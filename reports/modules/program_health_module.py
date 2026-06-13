"""
reports/modules/program_health_module.py — Program Health Overview module.

Computes 4 velocity signals (Open-Critical MoM, Net Velocity, SLA Posture,
MTTR) from the S1 severity-dimension trend snapshot substrate, derives the
OD-5 composite RAG, and provides an Owner velocity table.

Signal re-derivation design (D-17-02 — definition parity)
----------------------------------------------------------
All four signals read pre-computed snapshot fields so they NEVER disagree
with new_vs_remediated or mttr_trend:

  Signal 1 — Open-Critical MoM  : snap.get("critical")
  Signal 2 — Net Velocity       : snap.get("new_findings_count") - snap.get("fixed_findings_count")
  Signal 3 — SLA Posture        : snap.get("sla_rate_crit_high")         [Plan 17-01 field]
  Signal 4 — MTTR Overall       : snap.get("mttr_overall_days")

Net-velocity direction (RESEARCH Open Question 1): "delta of deltas" —
  curr_net_delta < prev_net_delta means the backlog is shrinking faster →
  improving. Binary; no flat band.

Cold-start MTTR tile (RESEARCH Open Question 2): always "—" because no
  fixed_vulns_df is threaded to this module (D-17-01: not in
  _MODULES_NEEDING_FIXED_VULNS). The snapshot field is used for MoM; the
  current-value tile requires fixed_vulns_df which is absent.

Render channels (Plan 17-03)
-----------------------------
Four render channels (PDF, Excel, email panel, analyst tabs) are NOT
implemented here — this plan delivers compute + ModuleData ONLY. The
no-op BaseModule defaults are inherited.

OD-5 composite RAG rule
------------------------
green  : all 4 signals green
amber  : 2–3 signals green
red    : 0–1 signals green
cap    : any missing signal → composite capped at amber (D-17-06);
         the cap is structural in _composite_rag_od5 and cannot be
         bypassed via module_options.

Threat mitigations
------------------
T-17-04 : validate_config() coerces module_options numerics; bad values
          log WARNING and fall back to default (Security V5).
T-17-05 : analyst_rows carry only owner-name + aggregate counts + MoM
          delta — no UUIDs, IPs, hostnames, or plugin IDs (QUAL-05).
T-17-06 : snap.get() throughout (never []); whole compute wrapped in
          try/except → _empty_result (fail-soft batch).
"""

from __future__ import annotations

import base64
import io
import logging
from typing import Any, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from config import SLA_DAYS
from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.board_report_utils import extract_owner
from reports.modules.format_utils import safe_format, safe_int, safe_pct
from reports.modules.rag_utils import (
    NO_DATA_DRIVER,
    NO_DATA_HEADLINE,
    STATUS_COLOR,
    STATUS_LABEL,
    build_rag_strip_entry,
)
from reports.modules.registry import register_module
from utils.open_count import open_findings_at

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level pure helper functions
# ---------------------------------------------------------------------------

def _composite_rag_od5(
    signal_statuses: list[str],
    green_min: int = 4,
    amber_min: int = 2,
) -> tuple[str, bool]:
    """
    Compute the OD-5 composite RAG status from a list of per-signal statuses.

    Parameters
    ----------
    signal_statuses : list[str]
        Each element is one of: "green", "amber", "red", "missing".
    green_min : int
        Minimum green-signal count for a Green composite. Default 4.
    amber_min : int
        Minimum green-signal count for an Amber composite. Default 2.

    Returns
    -------
    tuple[str, bool]
        (composite_status, data_incomplete) where composite_status is
        "green" / "amber" / "red" and data_incomplete is True when any
        signal is "missing".

    Notes
    -----
    D-17-06 structural cap: if any signal is "missing" AND the raw
    composite would be "green", it is capped to "amber" (data_incomplete=True).
    This cap is structural — it cannot be bypassed via module_options.
    """
    green_count = sum(1 for s in signal_statuses if s == "green")
    has_missing = any(s == "missing" for s in signal_statuses)

    # Raw composite by green-count thresholds (OD-5)
    if green_count >= green_min:
        raw = "green"
    elif green_count >= amber_min:
        raw = "amber"
    else:
        raw = "red"

    # D-17-06 structural cap: missing signal prevents Green
    if has_missing and raw == "green":
        return ("amber", True)

    return (raw, has_missing)


def _signal_direction(
    curr: Optional[float],
    prev: Optional[float],
    higher_is_better: bool,
    flat_band: float = 0.0,
) -> str:
    """
    Classify MoM signal direction as "green" / "amber" / "red" / "missing".

    Parameters
    ----------
    curr : float or None
        Current-period value.
    prev : float or None
        Previous-period value.
    higher_is_better : bool
        True for SLA Posture (higher rate = better);
        False for Open-Critical, Net Velocity, MTTR (lower = better).
    flat_band : float
        Absolute tolerance for "flat" (amber). Default 0.0.
        A delta within [-flat_band, +flat_band] inclusive is "flat".

    Returns
    -------
    str
        "missing" when either value is None.
        "amber"   when abs(delta) <= flat_band.
        "green"   when direction improved.
        "red"     when direction worsened.
    """
    if curr is None or prev is None:
        return "missing"
    delta = curr - prev
    if abs(delta) <= flat_band:
        return "amber"
    improved = (delta > 0) if higher_is_better else (delta < 0)
    return "green" if improved else "red"


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

@register_module
class ProgramHealthModule(BaseModule):
    """
    Program Health Overview — 4 velocity signals + composite RAG.

    Reads the S1 severity-dimension trend snapshot substrate to derive:
      1. Open-Critical MoM direction
      2. Net Velocity direction (inflow - outflow MoM delta)
      3. SLA Posture direction (% Crit+High within SLA, reopened-aware)
      4. MTTR Overall direction

    Composite RAG: Green = all 4 green; Amber = 2–3 green; Red = 0–1 green.
    Missing-signal Amber cap (D-17-06) is structural.

    Owner Velocity: current Crit+High open counts per owner with MoM delta
    and >20% rise outlier flag (D-17-09). Degrades gracefully when the
    owner-dimension snapshot has insufficient history.

    This module's compute() is the sole source of truth for the four-channel
    render contract (Plan 17-03). All metrics, table_data, analyst_rows,
    rag_strip, and driver_narrative are populated here; renderers are pure.
    """

    MODULE_ID         = "program_health"
    DISPLAY_NAME      = "Program Health Overview"
    DESCRIPTION       = (
        "Four-signal composite program health RAG — Open-Critical MoM, "
        "Net Velocity, SLA Posture, and MTTR — with Owner velocity table."
    )
    REQUIRED_DATA     = ["vulns", "assets", "trend_snapshots"]
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]
    VERSION           = "1.0.0"

    # ------------------------------------------------------------------
    # _build_cold_start_result
    # ------------------------------------------------------------------

    def _build_cold_start_result(
        self,
        vulns_df: pd.DataFrame,
        report_date: Any,
        config: ModuleConfig,
    ) -> ModuleData:
        """
        Return a coherent cold-start ModuleData for < 2 snapshots (D-17-08).

        Diverges from the mttr_trend analog at ONE point:
          rag_strip status = "yellow" (NOT "no_data") with
          headline_value_str = "Trend Being Established".

        Current-value Open-Critical and SLA posture are computed from the
        live vulns_df so cold-start tiles show real numbers (not "—").
        MTTR current tile is None ("—") — no fixed_vulns_df is provided
        (D-17-01 / RESEARCH Open Question 2).
        """
        # Current-value Open-Critical count (reopened-aware)
        curr_open_crit: Optional[int] = None
        curr_sla_rate: Optional[float] = None

        if not vulns_df.empty:
            try:
                open_df = open_findings_at(vulns_df, report_date)
                if not open_df.empty and "severity" in open_df.columns:
                    # Open-Critical count
                    curr_open_crit = int(
                        (open_df["severity"].str.lower() == "critical").sum()
                    )
                    # SLA posture: Crit+High within SLA
                    ch_df = open_df[
                        open_df["severity"].str.lower().isin(["critical", "high"])
                    ]
                    if not ch_df.empty and "first_found" in ch_df.columns:
                        # Coerce report_date to UTC-aware Timestamp (handles tz-naive + tz-aware)
                        snap_ts = (
                            pd.Timestamp(report_date).tz_convert("UTC")
                            if getattr(report_date, "tzinfo", None) is not None
                            else pd.Timestamp(report_date, tz="UTC")
                        )
                        days_open = (
                            snap_ts - pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
                        ).dt.days
                        # Vectorized within-SLA test using config.SLA_DAYS
                        sla_map = ch_df["severity"].str.lower().map(SLA_DAYS)
                        within = days_open <= sla_map
                        curr_sla_rate = round(
                            float(within.sum()) / len(ch_df) * 100, 1
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s cold-start current-value computation failed: %s",
                    self._log_prefix(), exc,
                )

        metrics = {
            "cold_start":        True,
            "composite_rag":     "amber",
            "data_incomplete":   True,
            "open_crit_current": curr_open_crit,
            "sla_rate_current":  curr_sla_rate,
            "mttr_current":      None,
            "net_delta_current": None,
            # Signal statuses all missing in cold-start
            "signal_open_crit_status":   "missing",
            "signal_net_velocity_status": "missing",
            "signal_sla_rate_status":    "missing",
            "signal_mttr_status":        "missing",
            "missing_signal_names":      [
                "Open Critical count", "Net Velocity",
                "SLA Posture", "MTTR",
            ],
        }

        driver_narrative = (
            "Program health trend being established — "
            "month-over-month direction available from next snapshot."
        )

        summary_text = (
            f"Program Health Overview — cold start. "
            f"Current Open Critical: {safe_int(curr_open_crit)}. "
            f"SLA Posture: {safe_pct(curr_sla_rate)}."
        )

        return ModuleData(
            module_id        = self.MODULE_ID,
            display_name     = self.DISPLAY_NAME,
            metrics          = metrics,
            table_data       = [],
            chart_data       = {},
            summary_text     = summary_text,
            metadata         = {"cold_start": True},
            driver_narrative = driver_narrative,
            analyst_rows     = [],
            rag_strip        = build_rag_strip_entry(
                display_name       = self.DISPLAY_NAME,
                headline_value_str = "Trend Being Established",
                status             = "yellow",   # D-17-08 — NOT "no_data"
            ),
            error            = None,
        )

    # ------------------------------------------------------------------
    # compute
    # ------------------------------------------------------------------

    def compute(
        self,
        vulns_df:    pd.DataFrame,
        assets_df:   pd.DataFrame,
        report_date: Any,
        config:      ModuleConfig,
        **kwargs:    Any,
    ) -> ModuleData:
        """
        Compute the 4-signal composite program health RAG.

        Parameters
        ----------
        vulns_df : pd.DataFrame
            Tag-filtered open vulnerability DataFrame.
        assets_df : pd.DataFrame
            Asset DataFrame for extract_owner() Owner velocity cut.
        report_date : datetime
            Report run timestamp (UTC-aware).
        config : ModuleConfig
            Options (all overridable via module_options YAML):
              green_count_min  (int, default 4)  — signals needed for Green.
              amber_count_min  (int, default 2)  — signals needed for Amber.
              open_crit_flat_abs (int, default 5) — ±N = flat for Open-Crit.
              sla_rate_flat_pct (float, default 2.0) — ±N% = flat for SLA.
              mttr_flat_days   (float, default 1.0) — ±N days = flat for MTTR.
              owner_outlier_pct (float, default 20.0) — % rise threshold.
              tag_category, tag_value — injected by composed_report.
        **kwargs
            ``trend_snapshots`` (dict) — severity-dimension read_trend() result:
            ``{"snapshots": [...], "insufficient_data": bool}``.
            Delivered via _MODULES_NEEDING_TREND_SNAPSHOTS. Absent /
            insufficient → cold-start (QUAL-01).
        """
        logger.debug(
            "%s compute() — vulns_df rows: %d",
            self._log_prefix(), len(vulns_df),
        )

        try:
            # ----------------------------------------------------------------
            # QUAL-03 — empty-data guard
            # ----------------------------------------------------------------
            if vulns_df.empty:
                logger.warning(
                    "%s vulns_df empty — returning _empty_result.", self._log_prefix()
                )
                return self._empty_result("vulns_df is empty", config)

            # ----------------------------------------------------------------
            # Read validated module_options
            # ----------------------------------------------------------------
            config = self.validate_config(config)  # coerces + falls back to defaults

            green_count_min   = int(config.options.get("green_count_min",   4))
            amber_count_min   = int(config.options.get("amber_count_min",   2))
            open_crit_flat    = int(config.options.get("open_crit_flat_abs", 5))
            sla_rate_flat     = float(config.options.get("sla_rate_flat_pct", 2.0))
            mttr_flat         = float(config.options.get("mttr_flat_days",    1.0))
            owner_outlier_pct = float(config.options.get("owner_outlier_pct", 20.0))
            tag_category      = config.options.get("tag_category")
            tag_value         = config.options.get("tag_value")

            # ----------------------------------------------------------------
            # QUAL-01 — cold-start guard
            # ----------------------------------------------------------------
            trend_snapshots = kwargs.get("trend_snapshots")
            cold_start = (
                trend_snapshots is None
                or trend_snapshots.get("insufficient_data", True)
            )
            if cold_start:
                logger.info(
                    "%s trend_snapshots absent or insufficient — cold start.",
                    self._log_prefix(),
                )
                return self._build_cold_start_result(vulns_df, report_date, config)

            snapshots: list[dict] = trend_snapshots.get("snapshots", [])
            if not snapshots:
                return self._build_cold_start_result(vulns_df, report_date, config)

            # ----------------------------------------------------------------
            # Deduplicate snapshots by calendar month (D-16-08 pattern)
            # VERBATIM from mttr_trend_module lines 646–651
            # ----------------------------------------------------------------
            by_month: dict[str, dict] = {}
            for snap in snapshots:
                m = snap.get("month", "")
                if m not in by_month or snap.get("generated_at", "") > by_month[m].get("generated_at", ""):
                    by_month[m] = snap
            snapshots_deduped = [by_month[m] for m in sorted(by_month)]

            if len(snapshots_deduped) < 2:
                logger.info(
                    "%s only %d deduped snapshot(s) — cold start.",
                    self._log_prefix(), len(snapshots_deduped),
                )
                return self._build_cold_start_result(vulns_df, report_date, config)

            curr = snapshots_deduped[-1]
            prev = snapshots_deduped[-2]

            # ----------------------------------------------------------------
            # Signal 1 — Open-Critical MoM (higher_is_better=False)
            # ----------------------------------------------------------------
            curr_crit = curr.get("critical")
            prev_crit = prev.get("critical")
            sig1_status = _signal_direction(
                curr_crit, prev_crit,
                higher_is_better=False,
                flat_band=float(open_crit_flat),
            )

            # ----------------------------------------------------------------
            # Signal 2 — Net Velocity MoM (higher_is_better=False)
            # Direction: "delta of deltas" — curr_net < prev_net → improving
            # Net velocity is binary; no flat band (flat_band=0.0)
            # ----------------------------------------------------------------
            curr_new = curr.get("new_findings_count")
            curr_fix = curr.get("fixed_findings_count")
            prev_new = prev.get("new_findings_count")
            prev_fix = prev.get("fixed_findings_count")

            curr_net_delta: Optional[float] = None
            prev_net_delta: Optional[float] = None
            if curr_new is not None and curr_fix is not None:
                curr_net_delta = float(curr_new) - float(curr_fix)
            if prev_new is not None and prev_fix is not None:
                prev_net_delta = float(prev_new) - float(prev_fix)

            sig2_status = _signal_direction(
                curr_net_delta, prev_net_delta,
                higher_is_better=False,
                flat_band=0.0,
            )

            # ----------------------------------------------------------------
            # Signal 3 — SLA Posture (higher_is_better=True)
            # Reads sla_rate_crit_high from snapshot (Plan 17-01 field)
            # ----------------------------------------------------------------
            curr_sla = curr.get("sla_rate_crit_high")
            prev_sla = prev.get("sla_rate_crit_high")
            sig3_status = _signal_direction(
                curr_sla, prev_sla,
                higher_is_better=True,
                flat_band=sla_rate_flat,
            )

            # ----------------------------------------------------------------
            # Signal 4 — MTTR Overall (higher_is_better=False)
            # ----------------------------------------------------------------
            curr_mttr = curr.get("mttr_overall_days")
            prev_mttr = prev.get("mttr_overall_days")
            sig4_status = _signal_direction(
                curr_mttr, prev_mttr,
                higher_is_better=False,
                flat_band=mttr_flat,
            )

            signal_statuses = [sig1_status, sig2_status, sig3_status, sig4_status]
            signal_names    = [
                "Open Critical count", "Net Velocity", "SLA Posture", "MTTR"
            ]

            # ----------------------------------------------------------------
            # Composite RAG (OD-5 + D-17-06 missing cap)
            # ----------------------------------------------------------------
            composite_rag, data_incomplete = _composite_rag_od5(
                signal_statuses,
                green_min=green_count_min,
                amber_min=amber_count_min,
            )

            missing_signal_names = [
                name for name, status in zip(signal_names, signal_statuses)
                if status == "missing"
            ]
            green_count = sum(1 for s in signal_statuses if s == "green")

            # ----------------------------------------------------------------
            # Current-value SLA posture (reopened-aware, D-17-03/QUAL-02)
            # For the current-value tile — uses live vulns_df, not snapshot
            # ----------------------------------------------------------------
            curr_sla_tile: Optional[float] = None
            try:
                open_df_live = open_findings_at(vulns_df, report_date)
                if not open_df_live.empty and "severity" in open_df_live.columns:
                    ch_live = open_df_live[
                        open_df_live["severity"].str.lower().isin(["critical", "high"])
                    ]
                    if not ch_live.empty and "first_found" in ch_live.columns:
                        snap_ts = (
                            pd.Timestamp(report_date).tz_convert("UTC")
                            if getattr(report_date, "tzinfo", None) is not None
                            else pd.Timestamp(report_date, tz="UTC")
                        )
                        days_open_live = (
                            snap_ts - pd.to_datetime(ch_live["first_found"], utc=True, errors="coerce")
                        ).dt.days
                        sla_map_live = ch_live["severity"].str.lower().map(SLA_DAYS)
                        within_live = days_open_live <= sla_map_live
                        curr_sla_tile = round(
                            float(within_live.sum()) / len(ch_live) * 100, 1
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s SLA tile computation failed: %s", self._log_prefix(), exc
                )

            # Current-value Open-Critical
            curr_open_crit_tile: Optional[int] = None
            if curr_crit is not None:
                curr_open_crit_tile = int(curr_crit)

            # ----------------------------------------------------------------
            # Sparkline series for Plan 03 renderers
            # ----------------------------------------------------------------
            open_crit_series = [
                s.get("critical") for s in snapshots_deduped
            ]
            sla_series = [
                s.get("sla_rate_crit_high") for s in snapshots_deduped
            ]
            mttr_series = [
                s.get("mttr_overall_days") for s in snapshots_deduped
            ]
            net_velocity_series = [
                (
                    (float(s.get("new_findings_count", 0)) - float(s.get("fixed_findings_count", 0)))
                    if s.get("new_findings_count") is not None and s.get("fixed_findings_count") is not None
                    else None
                )
                for s in snapshots_deduped
            ]
            month_labels = [s.get("month", "") for s in snapshots_deduped]

            # ----------------------------------------------------------------
            # Owner Velocity (D-17-09)
            # Read owner-dimension snapshot inside compute (Option A)
            # ----------------------------------------------------------------
            owner_rows:            list[dict] = []
            owner_mom_suppressed:  bool = True   # True = suppress MoM Delta column
            owner_insufficient_note: bool = False

            try:
                from data.trend_store import (  # noqa: PLC0415
                    read_trend, _sanitise_tag_for_filename,
                )
                _tag_filter = _sanitise_tag_for_filename(tag_category, tag_value)
                owner_trend = read_trend(
                    dimension  = "owner",
                    tag_filter = _tag_filter,
                    months     = 13,
                )
                owner_insufficient = owner_trend.get("insufficient_data", True)

                # Open Crit+High per owner from live vulns_df (QUAL-02)
                open_df_owner = open_findings_at(vulns_df, report_date)
                enriched = extract_owner(assets_df)
                uuid_to_owner = dict(
                    zip(enriched["asset_uuid"], enriched["owner"])
                )

                if not open_df_owner.empty and "severity" in open_df_owner.columns:
                    ch_owner = open_df_owner[
                        open_df_owner["severity"].str.lower().isin(["critical", "high"])
                    ]
                    if not ch_owner.empty:
                        # CoW-safe: assign to a local Series, never to a column
                        owner_series = ch_owner["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
                        curr_owner_counts: dict[str, int] = (
                            owner_series.value_counts().to_dict()
                        )
                    else:
                        curr_owner_counts = {}
                else:
                    curr_owner_counts = {}

                # Previous-month owner counts from snapshot
                prev_owner_counts: dict[str, int] = {}
                if not owner_insufficient:
                    owner_snaps = owner_trend.get("snapshots", [])
                    # Dedup owner snapshots by month
                    o_by_month: dict[str, dict] = {}
                    for osnap in owner_snaps:
                        m = osnap.get("month", "")
                        if m not in o_by_month or osnap.get("generated_at", "") > o_by_month[m].get("generated_at", ""):
                            o_by_month[m] = osnap
                    o_deduped = [o_by_month[m] for m in sorted(o_by_month)]
                    if len(o_deduped) >= 2:
                        prev_snap = o_deduped[-2]
                        # Owner snapshot stores owner-keyed counts at top level
                        for key, val in prev_snap.items():
                            if key not in ("month", "tag_filter", "asset_count",
                                           "on_time_asset_count", "reopened_count",
                                           "accepted_count", "recast_count",
                                           "new_findings_count", "fixed_findings_count",
                                           "mttr_overall_days", "mttr_by_severity",
                                           "mttr_by_owner", "sla_rate_crit_high",
                                           "generated_at") and isinstance(val, int):
                                prev_owner_counts[key] = val
                        owner_mom_suppressed = False
                    else:
                        owner_insufficient_note = True
                else:
                    owner_insufficient_note = True

                # Build owner_rows
                all_owners = sorted(
                    set(curr_owner_counts) | set(prev_owner_counts)
                )
                for owner_name in all_owners:
                    curr_cnt = curr_owner_counts.get(owner_name, 0)
                    prev_cnt = prev_owner_counts.get(owner_name, 0) if not owner_mom_suppressed else None
                    if prev_cnt is not None and prev_cnt > 0:
                        mom_delta = curr_cnt - prev_cnt
                        mom_delta_pct = (mom_delta / prev_cnt) * 100
                        outlier = mom_delta_pct > owner_outlier_pct
                    elif prev_cnt is not None and prev_cnt == 0 and curr_cnt > 0:
                        mom_delta = curr_cnt
                        mom_delta_pct = None
                        outlier = True
                    else:
                        mom_delta = None
                        mom_delta_pct = None
                        outlier = False

                    owner_rows.append({
                        "owner":            owner_name,
                        "open_crit_high":   curr_cnt,
                        "prev_open":        prev_cnt,
                        "mom_delta":        mom_delta,
                        "mom_delta_pct":    mom_delta_pct,
                        "outlier":          outlier,
                    })

                # Sort descending by current open count
                owner_rows.sort(key=lambda r: r["open_crit_high"], reverse=True)

            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s owner velocity computation failed: %s",
                    self._log_prefix(), exc,
                )
                owner_rows = []
                owner_mom_suppressed = True
                owner_insufficient_note = False

            # ----------------------------------------------------------------
            # RAG strip headline (UI-SPEC Copywriting Contract)
            # ----------------------------------------------------------------
            rag_strip_status = composite_rag  # "green" / "amber" / "red"
            # Map amber → "yellow" for build_rag_strip_entry API
            rag_key = "yellow" if rag_strip_status == "amber" else rag_strip_status
            headline_str = f"{green_count} / 4 On Track"
            if data_incomplete:
                headline_str += " (incomplete)"

            rag_strip = build_rag_strip_entry(
                display_name       = self.DISPLAY_NAME,
                headline_value_str = headline_str,
                status             = rag_key,
            )

            # ----------------------------------------------------------------
            # Driver narrative (UI-SPEC templates)
            # ----------------------------------------------------------------
            if composite_rag == "green":
                # Find best signal
                green_names = [
                    n for n, s in zip(signal_names, signal_statuses) if s == "green"
                ]
                top_signal = green_names[0] if green_names else "all signals"
                driver_narrative = (
                    f"The program improved on {green_count} of 4 indicators this month. "
                    f"{top_signal} shows improvement."
                )
            elif composite_rag == "amber":
                lag_names = [
                    n for n, s in zip(signal_names, signal_statuses)
                    if s in ("amber", "red")
                ]
                lag_str = lag_names[0] if lag_names else "one or more signals"
                driver_narrative = (
                    f"The program held steady on {green_count} of 4 indicators this month. "
                    f"{lag_str} warrants attention."
                )
            else:
                # Red
                bad_names = [
                    n for n, s in zip(signal_names, signal_statuses)
                    if s in ("amber", "red")
                ]
                bottom_str = ", ".join(bad_names[:2]) if bad_names else "multiple signals"
                driver_narrative = (
                    f"The program worsened on {4 - green_count} of 4 indicators this month. "
                    f"Immediate focus recommended on {bottom_str}."
                )

            if missing_signal_names:
                driver_narrative += (
                    f" Note: {', '.join(missing_signal_names)} data incomplete this period."
                )

            # ----------------------------------------------------------------
            # Summary text
            # ----------------------------------------------------------------
            composite_label = STATUS_LABEL.get(rag_key, rag_strip_status.title())
            summary_text = (
                f"Program Health Overview — {headline_str}. "
                f"Composite: {composite_label}. "
                f"SLA Posture: {safe_pct(curr_sla_tile)}. "
                f"Open Critical: {safe_int(curr_open_crit_tile)}."
            )

            # ----------------------------------------------------------------
            # Metrics dict (consumed by renderers)
            # ----------------------------------------------------------------
            metrics = {
                "composite_rag":     composite_rag,
                "data_incomplete":   data_incomplete,
                "cold_start":        False,
                "green_count":       green_count,
                "missing_signal_names": missing_signal_names,
                # Signal current values
                "open_crit_current":    curr_open_crit_tile,
                "net_delta_current":    curr_net_delta,
                "sla_rate_current":     curr_sla_tile,     # live, reopened-aware
                "mttr_current":         curr_mttr,          # from snapshot
                # Signal statuses
                "signal_open_crit_status":    sig1_status,
                "signal_net_velocity_status": sig2_status,
                "signal_sla_rate_status":     sig3_status,
                "signal_mttr_status":         sig4_status,
                # Previous-period values (for MoM arrows)
                "open_crit_prev":    prev_crit,
                "net_delta_prev":    prev_net_delta,
                "sla_rate_prev":     prev_sla,
                "mttr_prev":         prev_mttr,
                # Options passthrough for renderers
                "owner_mom_suppressed":    owner_mom_suppressed,
                "owner_insufficient_note": owner_insufficient_note,
                # Sparkline series
                "sparkline_months":        month_labels,
                "sparkline_open_crit":     open_crit_series,
                "sparkline_net_velocity":  net_velocity_series,
                "sparkline_sla_rate":      sla_series,
                "sparkline_mttr":          mttr_series,
            }

            # ----------------------------------------------------------------
            # Analyst rows (CONTRACT-02, QUAL-05)
            # Aggregate-only: owner tag name + counts + delta; no UUIDs/IPs
            # ----------------------------------------------------------------
            analyst_df = pd.DataFrame([
                {
                    "Owner":                r["owner"],
                    "Open Crit+High (curr)": r["open_crit_high"],
                    "Open Crit+High (prev)": r["prev_open"],
                    "MoM Delta":            r["mom_delta"],
                    "MoM Delta %":          (
                        round(r["mom_delta_pct"], 1)
                        if r["mom_delta_pct"] is not None else None
                    ),
                    "Outlier":              r["outlier"],
                }
                for r in owner_rows
            ]) if owner_rows else pd.DataFrame(
                columns=["Owner", "Open Crit+High (curr)", "Open Crit+High (prev)",
                         "MoM Delta", "MoM Delta %", "Outlier"]
            )
            analyst_rows_list: list[tuple[str, pd.DataFrame]] = [
                ("PH — Owner Detail", analyst_df),
            ]

            return ModuleData(
                module_id        = self.MODULE_ID,
                display_name     = self.DISPLAY_NAME,
                metrics          = metrics,
                table_data       = owner_rows,
                chart_data       = {
                    "months":          month_labels,
                    "open_crit":       open_crit_series,
                    "net_velocity":    net_velocity_series,
                    "sla_rate":        sla_series,
                    "mttr":            mttr_series,
                },
                summary_text     = summary_text,
                metadata         = {
                    "snapshots_used": len(snapshots_deduped),
                    "tag_filter": f"{tag_category}={tag_value}" if tag_category and tag_value else "all_assets",
                },
                driver_narrative = driver_narrative,
                analyst_rows     = analyst_rows_list,
                rag_strip        = rag_strip,
                error            = None,
            )

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "%s compute() failed: %s", self._log_prefix(), exc,
                exc_info=True,
            )
            return self._empty_result(str(exc), config)

    # ------------------------------------------------------------------
    # validate_config
    # ------------------------------------------------------------------

    def validate_config(self, config: ModuleConfig) -> ModuleConfig:
        """
        Coerce and validate all program_health module_options.

        Coercion rules (T-17-04 threshold-injection mitigation):
          green_count_min, amber_count_min, open_crit_flat_abs → int
          sla_rate_flat_pct, mttr_flat_days, owner_outlier_pct   → float

        On a bad value: log WARNING and fall back to the default.
        Returns a ModuleConfig with a clean options dict (defaults filled in).
        """
        _int_keys   = [
            ("green_count_min",   4),
            ("amber_count_min",   2),
            ("open_crit_flat_abs", 5),
        ]
        _float_keys = [
            ("sla_rate_flat_pct",  2.0),
            ("mttr_flat_days",     1.0),
            ("owner_outlier_pct", 20.0),
        ]

        clean = dict(config.options)

        for key, default in _int_keys:
            val = clean.get(key)
            if val is not None:
                try:
                    clean[key] = int(val)
                except (TypeError, ValueError):
                    logger.warning(
                        "%s validate_config: '%s' must be an integer, "
                        "got %r — falling back to default %d",
                        self._log_prefix(), key, val, default,
                    )
                    clean[key] = default
            else:
                clean[key] = default

        for key, default in _float_keys:
            val = clean.get(key)
            if val is not None:
                try:
                    clean[key] = float(val)
                except (TypeError, ValueError):
                    logger.warning(
                        "%s validate_config: '%s' must be a float, "
                        "got %r — falling back to default %s",
                        self._log_prefix(), key, val, default,
                    )
                    clean[key] = default
            else:
                clean[key] = default

        return ModuleConfig(module_id=config.module_id, options=clean)

    # ------------------------------------------------------------------
    # get_audit_info
    # ------------------------------------------------------------------

    def get_audit_info(self) -> dict:
        """Return calculation documentation for audit and runbook records."""
        return {
            **super().get_audit_info(),
            "calculations": {
                "Signal 1 — Open-Critical MoM": (
                    "snap.get('critical') curr vs prev. higher_is_better=False. "
                    "flat_band=open_crit_flat_abs (default 5). "
                    "Reads S1 severity snapshot; definition parity with trend_store (D-17-02)."
                ),
                "Signal 2 — Net Velocity MoM": (
                    "curr_net_delta = new_findings_count - fixed_findings_count. "
                    "Direction = 'delta of deltas': curr_net < prev_net → improving. "
                    "Binary; flat_band=0 (no flat zone per Net Velocity contract). "
                    "higher_is_better=False."
                ),
                "Signal 3 — SLA Posture MoM": (
                    "snap.get('sla_rate_crit_high') — % Crit+High within config.SLA_DAYS, "
                    "computed reopened-aware by capture_trend_snapshot.py (Plan 17-01). "
                    "higher_is_better=True. flat_band=sla_rate_flat_pct (default 2.0)."
                ),
                "Signal 4 — MTTR Overall MoM": (
                    "snap.get('mttr_overall_days') — sample-weighted MTTR from snapshot. "
                    "higher_is_better=False. flat_band=mttr_flat_days (default 1.0)."
                ),
                "OD-5 Composite RAG": (
                    "Green = green_count >= green_count_min (default 4). "
                    "Amber = green_count >= amber_count_min (default 2). "
                    "Red = green_count < amber_count_min."
                ),
                "D-17-06 Missing-Signal Amber Cap": (
                    "Structural in _composite_rag_od5: any 'missing' signal AND "
                    "raw composite == 'green' → capped to 'amber' (data_incomplete=True). "
                    "Cannot be bypassed via module_options."
                ),
                "Current SLA Posture tile": (
                    "Computed from live vulns_df via open_findings_at() (reopened-aware). "
                    "open_findings_at(vulns_df, report_date) → filter Crit+High → "
                    "vectorized days_open <= config.SLA_DAYS[severity] (D-17-03/QUAL-02)."
                ),
                "Owner Velocity (D-17-09)": (
                    "Current Crit+High open counts from live vulns_df via extract_owner. "
                    "Previous from owner-dimension snapshot (read_trend dimension='owner'). "
                    "Outlier flag: MoM rise > owner_outlier_pct% (default 20%). "
                    "Degrades gracefully when owner trend insufficient_data=True."
                ),
                "Cold-start (D-17-08)": (
                    "< 2 deduped snapshots → composite='amber', rag_strip status='yellow', "
                    "headline='Trend Being Established'. Current Open-Crit and SLA tiles "
                    "show live values from vulns_df. MTTR tile = '—' (no fixed_vulns_df, "
                    "per D-17-01 / RESEARCH Open Question 2)."
                ),
            },
        }


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    from reports.modules.registry import discover, get_module

    discover()
    m = get_module("program_health")
    assert m is not None, "program_health not found in registry"
    assert m.MODULE_ID == "program_health"

    # Pure function smoke
    assert _composite_rag_od5(["green"] * 4) == ("green", False), "4-green → green"
    assert _composite_rag_od5(["green", "green", "green", "missing"]) == ("amber", True), "3+missing → amber"
    assert _composite_rag_od5(["green", "red", "red", "red"]) == ("red", False), "1 green → red"
    assert _signal_direction(40.0, 50.0, False, 0.0) == "green", "lower = improved for False"
    assert _signal_direction(None, 50.0, False, 0.0) == "missing", "None → missing"
    assert _signal_direction(50.0, 48.0, False, 5.0) == "amber", "within flat band"
    assert _signal_direction(90.0, 80.0, True, 2.0) == "green", "higher = improved for True"

    print("program_health module smoke test PASSED")
    sys.exit(0)
