"""
reports/ops_remediation.py — Operations Remediation Report.

Audience: IT Operations and remediation teams responsible for patching
specific asset groups. Designed to provide a clear, prioritized, and
actionable list of vulnerabilities to remediate, scoped by Tenable tag.

This report is NOT a replacement for sla_remediation.py — it has a
different structure and audience focus:
  - Vulnerabilities grouped by plugin (not per-row) for large-group usability
  - Four-state SLA status: Overdue / Urgent / Warning / On Track
  - Unscanned asset identification and exclusion from vuln counts
  - No per-asset breakdown in output — plugin + asset count is sufficient

Outputs
-------
- Excel: ops_remediation.xlsx  (6 tabs: Summary, Critical & High,
         Medium & Low, Overdue — All Severities, Unscanned Assets, Metadata)
- PDF:   ops_remediation.pdf   (cover, exec summary, overdue, urgent,
         unscanned, notes)
- Charts: none — returns empty list for run_all.py interface compatibility

CLI
---
python reports/ops_remediation.py
python reports/ops_remediation.py \\
    --tag-category "Operations" --tag-value "Server Operations"
python reports/ops_remediation.py --output-dir output/test/ --no-email
python reports/ops_remediation.py --cache-dir data/cache/2026-03-26/
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Allow running as a top-level script from any working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    CACHE_DIR,
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    SEVERITY_ORDER,
    SLA_DAYS,
    vpr_to_severity,
)
from data.fetchers import (
    enrich_vulns_with_assets,
    fetch_all_assets,
    fetch_all_vulnerabilities,
    filter_by_tag,
)
from utils.formatters import report_timestamp, safe_filename
from utils.sla_calculator import apply_sla_to_df

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "Operations Remediation Report"
REPORT_SLUG = "ops_remediation"

# Four-state SLA labels — used as cell text and in PDF/email body
OPS_SLA_OVERDUE  = "Overdue"
OPS_SLA_URGENT   = "Urgent - <=25% SLA Remaining"
OPS_SLA_WARNING  = "Warning - <=50% SLA Remaining"
OPS_SLA_ON_TRACK = "On Track"

# Ordered list for consistent display (worst → best)
OPS_SLA_STATE_ORDER: list[str] = [
    OPS_SLA_OVERDUE,
    OPS_SLA_URGENT,
    OPS_SLA_WARNING,
    OPS_SLA_ON_TRACK,
]

# Excel conditional formatting colors per SLA state (no leading #)
OPS_SLA_FILL: dict[str, str] = {
    OPS_SLA_OVERDUE:  "FF0000",   # red
    OPS_SLA_URGENT:   "FF6600",   # orange
    OPS_SLA_WARNING:  "FFC000",   # amber
    OPS_SLA_ON_TRACK: "E2EFDA",   # light green
}
OPS_SLA_FONT_COLOR: dict[str, str] = {
    OPS_SLA_OVERDUE:  "FFFFFF",   # white
    OPS_SLA_URGENT:   "FFFFFF",   # white
    OPS_SLA_WARNING:  "000000",   # black
    OPS_SLA_ON_TRACK: "000000",   # black
}
OPS_SLA_FONT_BOLD: dict[str, bool] = {
    OPS_SLA_OVERDUE:  True,
    OPS_SLA_URGENT:   True,
    OPS_SLA_WARNING:  False,
    OPS_SLA_ON_TRACK: False,
}

# Severity rank map for sort ordering (Critical = 0, sorts first)
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Assets with no scan or scan older than this threshold are flagged as unscanned
UNSCANNED_THRESHOLD_DAYS: int = 30

# Note included at the top of every vulnerability tab and in the PDF
LARGE_GROUP_NOTE = (
    "Asset-level detail for each plugin is available in Tenable Vulnerability "
    "Management. Filter by Plugin ID to view all affected assets for your group."
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


# ===========================================================================
# Step 1 — Data preparation functions
# ===========================================================================


def _fetch_and_prepare(
    tio,
    cache_dir: Path,
    tag_category: Optional[str],
    tag_value: Optional[str],
    as_of: Optional[datetime] = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Fetch, enrich, tag-filter, and SLA-annotate the vulnerability dataset.

    Uses the single unscoped parquet cache introduced in the fetcher refactor.
    Tag scoping is performed in-memory after the cache load, so all delivery
    groups running in the same ``run_all.py`` invocation share one API call.

    Unscanned asset exclusion is NOT performed here — call
    ``_identify_unscanned_assets()`` on the returned ``assets_df`` and filter
    ``vulns_df`` by the scanned asset IDs before passing to ``_group_by_plugin()``.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped parquet cache directory (shared with other reports).
    tag_category : str or None
        Tenable tag category to scope the report (e.g. "Operations").
    tag_value : str or None
        Tenable tag value to scope the report (e.g. "Server Operations").
    as_of : datetime, optional
        Reference timestamp for SLA age calculations.  Defaults to UTC now.

    Returns
    -------
    tuple[pd.DataFrame, pd.DataFrame]
        ``(vulns_df, assets_df)`` where both are scoped to the tag filter.
        ``vulns_df`` has full SLA columns from ``apply_sla_to_df()`` plus
        the four-state ``ops_sla_status`` column from ``_compute_sla_status()``.
        ``assets_df`` contains all scoped assets including unscanned ones.
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    logger.info(
        "[%s] Fetching vulnerability data (tag=%s:%s)…",
        REPORT_NAME, tag_category, tag_value,
    )

    vulns_df  = fetch_all_vulnerabilities(tio, cache_dir)
    assets_df = fetch_all_assets(tio, cache_dir)

    if vulns_df.empty:
        logger.warning("[%s] No vulnerabilities returned — report will be empty.", REPORT_NAME)
        assets_df = filter_by_tag(assets_df, tag_category, tag_value)
        return vulns_df, assets_df

    logger.info("[%s] Enriching vulnerabilities with asset metadata…", REPORT_NAME)
    df = enrich_vulns_with_assets(vulns_df, assets_df)

    # Tag filtering happens after enrichment — the reliable tags column
    # comes from the asset export join, not the vuln export payload.
    df        = filter_by_tag(df, tag_category, tag_value)
    assets_df = filter_by_tag(assets_df, tag_category, tag_value)

    if df.empty:
        logger.warning(
            "[%s] No vulnerabilities match tag filter (%s=%s) — report will be empty.",
            REPORT_NAME, tag_category, tag_value,
        )
        return df, assets_df

    logger.info("[%s] Applying SLA calculations…", REPORT_NAME)
    df = apply_sla_to_df(df, as_of=as_of)
    df = _compute_sla_status(df)

    logger.info(
        "[%s] Prepared %d vulnerability records across %d unique assets.",
        REPORT_NAME, len(df), df["asset_id"].nunique(),
    )
    return df, assets_df


def _compute_sla_status(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add a four-state ``ops_sla_status`` column to a SLA-annotated vuln DataFrame.

    Requires the following columns produced by ``apply_sla_to_df()``:
        - ``is_overdue``     : bool
        - ``days_remaining`` : int  (negative when overdue)
        - ``sla_days``       : int  (None/NaN for info severity)
        - ``remediated``     : bool

    SLA state logic
    ---------------
    Overdue  : days_open > sla_days  (is_overdue == True)
    Urgent   : within SLA AND days_remaining ≤ 25% of sla_days
    Warning  : within SLA AND days_remaining ≤ 50% of sla_days (but > 25%)
    On Track : within SLA AND days_remaining > 50% of sla_days

    Rows with no applicable SLA (info severity, missing sla_days, or
    already remediated) receive ``OPS_SLA_ON_TRACK`` as a safe default.

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame with SLA columns already applied.

    Returns
    -------
    pd.DataFrame
        A copy of ``df`` with the ``ops_sla_status`` column added.
    """
    if df.empty:
        df = df.copy()
        df["ops_sla_status"] = pd.Series(dtype="object")
        return df

    # Guard: sla_days must exist (comes from apply_sla_to_df)
    if "is_overdue" not in df.columns or "days_remaining" not in df.columns:
        raise ValueError(
            "_compute_sla_status requires apply_sla_to_df() to be called first. "
            "Missing columns: is_overdue and/or days_remaining."
        )

    # Compute thresholds — NaN where sla_days is NaN (info severity)
    urgent_threshold  = df["sla_days"] * 0.25
    warning_threshold = df["sla_days"] * 0.50

    # Ordered conditions evaluated top-down by np.select (first match wins)
    conditions = [
        df["is_overdue"],
        ~df["is_overdue"] & (df["days_remaining"] <= urgent_threshold),
        ~df["is_overdue"] & (df["days_remaining"] <= warning_threshold),
    ]
    choices = [OPS_SLA_OVERDUE, OPS_SLA_URGENT, OPS_SLA_WARNING]

    ops_status = np.select(conditions, choices, default=OPS_SLA_ON_TRACK)

    return df.assign(ops_sla_status=ops_status)


def _identify_unscanned_assets(
    assets_df: pd.DataFrame,
    as_of: Optional[datetime] = None,
    threshold_days: int = UNSCANNED_THRESHOLD_DAYS,
) -> pd.DataFrame:
    """
    Identify assets that have not been scanned recently.

    An asset is considered unscanned when:
      - ``last_scan_time`` is null / NaT  (never scanned), OR
      - ``last_scan_time`` is more than ``threshold_days`` before ``as_of``

    Unscanned assets must be excluded from vulnerability counts and SLA
    calculations — their absence from scan data means we cannot make
    reliable vulnerability statements about them.

    Parameters
    ----------
    assets_df : pd.DataFrame
        Full scoped asset DataFrame from ``fetch_all_assets()`` after tag filter.
        Must contain ``asset_id``, ``hostname``, ``ipv4``, ``tags``,
        ``last_scan_time``, and optionally ``operating_system``.
    as_of : datetime, optional
        Reference timestamp for age calculation.  Defaults to UTC now.
    threshold_days : int
        Days since last scan to consider an asset unscanned.  Default: 30.

    Returns
    -------
    pd.DataFrame
        Subset of ``assets_df`` for unscanned assets with computed columns:
            - ``last_scan_date``   : formatted date string or "Never"
            - ``days_since_scan``  : int days since last scan, or None if never
        Sorted by ``days_since_scan`` descending (never-scanned first, then
        oldest scan first).
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    if assets_df.empty:
        return pd.DataFrame(columns=[
            "asset_id", "hostname", "ipv4", "tags",
            "last_scan_date", "days_since_scan", "operating_system",
        ])

    as_of_ts = pd.Timestamp(as_of)

    # Coerce last_scan_time to UTC-aware datetime
    if "last_scan_time" in assets_df.columns:
        last_scan = pd.to_datetime(assets_df["last_scan_time"], utc=True, errors="coerce")
    else:
        last_scan = pd.Series(pd.NaT, index=assets_df.index, dtype="datetime64[ns, UTC]")

    days_since = (as_of_ts - last_scan).dt.days
    df = assets_df.assign(last_scan_time=last_scan, days_since_scan=days_since)

    # Classify unscanned
    never_scanned  = df["last_scan_time"].isna()
    stale_scan     = df["days_since_scan"] > threshold_days
    unscanned_mask = never_scanned | stale_scan

    # Build result with computed columns
    result_base = df[unscanned_mask]
    last_scan_date = result_base["last_scan_time"].apply(
        lambda ts: "Never" if pd.isna(ts) else ts.strftime("%Y-%m-%d")
    )
    sort_key = result_base["days_since_scan"].fillna(999_999)
    result = (
        result_base.assign(last_scan_date=last_scan_date, _sort_key=sort_key)
        .sort_values("_sort_key", ascending=False)
        .drop(columns="_sort_key")
        .reset_index(drop=True)
    )

    # Select and order output columns for downstream use
    output_cols = [
        "asset_id",
        "hostname",
        "ipv4",
        "tags",
        "last_scan_date",
        "days_since_scan",
        "operating_system",
    ]
    # Only include columns that actually exist in the DataFrame
    output_cols = [c for c in output_cols if c in result.columns]
    result = result[output_cols]

    n_never  = int(never_scanned.sum())
    n_stale  = int(stale_scan.sum())
    logger.info(
        "[%s] Unscanned assets: %d total "
        "(never scanned: %d, last scan >%d days ago: %d)",
        REPORT_NAME, len(result), n_never, threshold_days, n_stale,
    )

    return result


def _format_cves(series: pd.Series) -> str:
    """
    Collapse a per-plugin group of comma-separated CVE strings into one string.

    Takes the union of all CVEs across all rows in the group, sorts them,
    and formats as "CVE-YYYY-NNNNN, CVE-... +N more" when the count exceeds 3.

    Parameters
    ----------
    series : pd.Series
        Series of comma-separated CVE strings (e.g. the ``cve_list`` column
        for all rows sharing one plugin_id).

    Returns
    -------
    str
        Formatted CVE string, e.g. "CVE-2021-44228, CVE-2022-0001 +3 more",
        or empty string if no CVEs are present.
    """
    all_cves: set[str] = set()
    for raw in series.fillna(""):
        for cve in raw.split(","):
            cve = cve.strip()
            if cve:
                all_cves.add(cve)

    cves = sorted(all_cves)
    if not cves:
        return ""
    if len(cves) <= 3:
        return ", ".join(cves)
    return ", ".join(cves[:3]) + f" +{len(cves) - 3} more"


def _group_by_plugin(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate the vulnerability DataFrame by plugin, producing one row per plugin.

    SLA status and days-remaining are taken from the **oldest instance** of
    each plugin (the row with the highest ``days_open``) — worst-case semantics
    that ensure the most urgent state for the group is surfaced.

    Sort order applied (as specified):
        1. Severity rank: Critical first → High → Medium → Low
        2. Within severity: highest VPR score first
        3. Within same VPR score: highest affected asset count first
        4. Within same asset count: most days open (oldest instance) first

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame scoped to scanned assets only, with
        ``ops_sla_status`` column present (call ``_compute_sla_status()`` first).

    Returns
    -------
    pd.DataFrame
        One row per plugin with these columns:
            plugin_id, plugin_name, plugin_family, severity, vpr_score,
            cvss_score, cves, affected_asset_count,
            days_open_oldest, days_open_newest,
            sla_status, days_remaining, exploit_available
    """
    if df.empty:
        return pd.DataFrame(columns=[
            "plugin_id", "plugin_name", "plugin_family", "severity",
            "vpr_score", "cvss_score", "cves", "affected_asset_count",
            "days_open_oldest", "days_open_newest",
            "sla_status", "days_remaining", "exploit_available",
        ])

    # ------------------------------------------------------------------
    # Step A: Identify worst-case (oldest) row per plugin for SLA state.
    # Sort descending on days_open so .first() within each plugin gives
    # the oldest instance.
    # ------------------------------------------------------------------
    worst_case_cols = ["ops_sla_status", "days_remaining"]
    worst_case = (
        df.sort_values("days_open", ascending=False, na_position="last")
        .groupby("plugin_id", sort=False)[worst_case_cols]
        .first()
        .reset_index()
        .rename(columns={"ops_sla_status": "sla_status"})
    )

    # ------------------------------------------------------------------
    # Step B: Standard per-plugin aggregations
    # ------------------------------------------------------------------
    agg = df.groupby("plugin_id").agg(
        plugin_name         = ("plugin_name",        "first"),
        plugin_family       = ("plugin_family",       "first"),
        vpr_score           = ("vpr_score",           "max"),
        cvss_score          = ("cvss_v3_base_score",  "max"),
        affected_asset_count= ("asset_id",            "nunique"),
        days_open_oldest    = ("days_open",           "max"),
        days_open_newest    = ("days_open",           "min"),
        exploit_available   = ("exploit_available",   "any"),
    ).reset_index()

    # ------------------------------------------------------------------
    # Step C: CVE aggregation — union of all CVEs per plugin
    # ------------------------------------------------------------------
    cve_agg = (
        df.groupby("plugin_id")["cve_list"]
        .apply(_format_cves)
        .reset_index()
        .rename(columns={"cve_list": "cves"})
    )

    # ------------------------------------------------------------------
    # Step D: Derive severity from max VPR score
    # (VPR is per-plugin; max handles edge cases from incremental updates)
    # ------------------------------------------------------------------
    agg["severity"] = agg["vpr_score"].apply(
        lambda v: vpr_to_severity(v, fallback="info")
    )

    # ------------------------------------------------------------------
    # Step E: Merge all aggregated components
    # ------------------------------------------------------------------
    result = (
        agg
        .merge(cve_agg,    on="plugin_id", how="left")
        .merge(worst_case, on="plugin_id", how="left")
    )

    # ------------------------------------------------------------------
    # Step F: Format exploit_available as a human-readable Yes/No string
    # Step G: Apply the four-level sort order
    # ------------------------------------------------------------------
    exploit_fmt = result["exploit_available"].map({True: "Yes", False: "No"}).fillna("No")
    sev_rank = result["severity"].str.lower().map(SEVERITY_RANK).fillna(99).astype(int)
    result = result.assign(exploit_available=exploit_fmt, _sev_rank=sev_rank)
    result = (
        result
        .sort_values(
            ["_sev_rank", "vpr_score", "affected_asset_count", "days_open_oldest"],
            ascending=[True, False, False, False],
            na_position="last",
        )
        .drop(columns="_sev_rank")
        .reset_index(drop=True)
    )

    # ------------------------------------------------------------------
    # Step H: Select and order final output columns
    # ------------------------------------------------------------------
    result = result[[
        "plugin_id",
        "plugin_name",
        "plugin_family",
        "severity",
        "vpr_score",
        "cvss_score",
        "cves",
        "affected_asset_count",
        "days_open_oldest",
        "days_open_newest",
        "sla_status",
        "days_remaining",
        "exploit_available",
    ]]

    logger.info(
        "[%s] Grouped into %d plugins | %d unique assets affected.",
        REPORT_NAME, len(result), df["asset_id"].nunique(),
    )
    return result


def _compute_summary_metrics(
    vulns_df: pd.DataFrame,
    plugin_df: pd.DataFrame,
    assets_df: pd.DataFrame,
    unscanned_df: pd.DataFrame,
    tag_category: Optional[str],
    tag_value: Optional[str],
    as_of: Optional[datetime] = None,
) -> dict:
    """
    Compute all summary metrics used in the Excel Summary tab, PDF executive
    summary, and email KPI strip.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Full scoped and SLA-annotated vuln DataFrame (scanned assets only).
    plugin_df : pd.DataFrame
        Output of ``_group_by_plugin()`` for derived counts.
    assets_df : pd.DataFrame
        All scoped assets (scanned + unscanned).
    unscanned_df : pd.DataFrame
        Output of ``_identify_unscanned_assets()``.
    tag_category, tag_value : str or None
        Tag filter applied to the report.
    as_of : datetime, optional
        Reference timestamp for the report.

    Returns
    -------
    dict
        Keys match the metric names used by the email template and Excel
        Summary tab builder.  All count values are Python ints; rates are
        floats (0.0–1.0).
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    tag_filter_str = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )

    total_assets_in_scope = len(assets_df)
    total_unscanned       = len(unscanned_df)
    total_scanned         = total_assets_in_scope - total_unscanned

    if vulns_df.empty:
        return {
            "generated_at":         as_of.strftime("%Y-%m-%d %H:%M UTC"),
            "tag_filter":           tag_filter_str,
            "total_assets":         total_scanned,
            "total_unscanned":      total_unscanned,
            "open_critical":        0,
            "open_high":            0,
            "open_medium":          0,
            "open_low":             0,
            "count_overdue":        0,
            "count_urgent":         0,
            "count_warning":        0,
            "count_on_track":       0,
            "plugins_with_overdue": 0,
            "exploitable_plugins":  0,
            "sla_compliance_rate":  1.0,
            "top5_plugins":         [],
        }

    # Open vuln counts by severity (per finding row, not per plugin)
    open_by_sev: dict[str, int] = {
        sev: int((vulns_df["severity"].str.lower() == sev).sum())
        for sev in ("critical", "high", "medium", "low")
    }

    # SLA state counts (per finding row)
    state_counts: dict[str, int] = {
        state: int((vulns_df["ops_sla_status"] == state).sum())
        for state in OPS_SLA_STATE_ORDER
    }

    # SLA compliance rate: fraction of rows that are On Track (not Overdue/Urgent/Warning)
    total_rows = len(vulns_df)
    on_track_rows = state_counts.get(OPS_SLA_ON_TRACK, 0)
    sla_compliance_rate = round(on_track_rows / total_rows, 4) if total_rows > 0 else 1.0

    # Plugin-level derived metrics
    plugins_with_overdue = int(
        (plugin_df["sla_status"] == OPS_SLA_OVERDUE).sum()
    ) if not plugin_df.empty else 0

    exploitable_plugins = int(
        (plugin_df["exploit_available"] == "Yes").sum()
    ) if not plugin_df.empty else 0

    # Top 5 plugins by affected asset count
    top5 = (
        plugin_df
        .nlargest(5, "affected_asset_count", keep="first")
        [["plugin_name", "affected_asset_count"]]
        .to_dict("records")
    ) if not plugin_df.empty else []

    return {
        "generated_at":         as_of.strftime("%Y-%m-%d %H:%M UTC"),
        "tag_filter":           tag_filter_str,
        "total_assets":         total_scanned,
        "total_unscanned":      total_unscanned,
        "open_critical":        open_by_sev["critical"],
        "open_high":            open_by_sev["high"],
        "open_medium":          open_by_sev["medium"],
        "open_low":             open_by_sev["low"],
        "count_overdue":        state_counts.get(OPS_SLA_OVERDUE,  0),
        "count_urgent":         state_counts.get(OPS_SLA_URGENT,   0),
        "count_warning":        state_counts.get(OPS_SLA_WARNING,  0),
        "count_on_track":       state_counts.get(OPS_SLA_ON_TRACK, 0),
        "plugins_with_overdue": plugins_with_overdue,
        "exploitable_plugins":  exploitable_plugins,
        "sla_compliance_rate":  sla_compliance_rate,
        "top5_plugins":         top5,
    }


# ===========================================================================
# Steps 2–5 placeholders — to be implemented after Step 1 review
# ===========================================================================

def _apply_ops_sla_formatting(ws) -> None:
    """
    Apply four-state SLA conditional formatting to the ``sla_status`` column
    in an ops_remediation worksheet.

    States and fills:
      Overdue                    → red   (#FFCDD2 / bold red text)
      Urgent - <=25% SLA Remaining  → orange (#FFE0B2 / bold orange text)
      Warning - <=50% SLA Remaining → yellow (#FFF9C4 / amber text)
      On Track                   → green (#C8E6C9 / dark-green text)
    """
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.styles import Font, PatternFill
    from exporters.excel_exporter import _col_letter_for  # reuse helper

    col = _col_letter_for(ws, "sla_status")
    if not col:
        return

    data_start = 2
    data_end   = ws.max_row
    rng        = f"{col}{data_start}:{col}{data_end}"

    rules = [
        (OPS_SLA_OVERDUE,  "FFCDD2", "B71C1C", True),
        (OPS_SLA_URGENT,   "FFE0B2", "E65100", True),
        (OPS_SLA_WARNING,  "FFF9C4", "F57F17", False),
        (OPS_SLA_ON_TRACK, "C8E6C9", "1B5E20", False),
    ]
    for label, bg, fg, bold in rules:
        ws.conditional_formatting.add(
            rng,
            CellIsRule(
                operator="equal",
                formula=[f'"{label}"'],
                fill=PatternFill("solid", fgColor=bg),
                font=Font(bold=bold, color=fg, size=10, name="Calibri"),
            ),
        )


def _build_summary_sheet(wb, summary: dict) -> None:
    """Write the Summary tab with KPI metrics from the summary dict."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment

    ws = wb.create_sheet(title="Summary", index=0)
    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 22

    _title_font   = Font(bold=True, size=14, color="1F3864", name="Calibri")
    _section_font = Font(bold=True, size=11, color="1F3864", name="Calibri")
    _label_font   = Font(bold=True, size=10, name="Calibri")
    _value_font   = Font(size=10, name="Calibri")
    _head_fill    = PatternFill("solid", fgColor="E8EAF6")
    _alt_fill     = PatternFill("solid", fgColor="F5F7FA")
    _red_fill     = PatternFill("solid", fgColor="FFCDD2")
    _orange_fill  = PatternFill("solid", fgColor="FFE0B2")
    _yellow_fill  = PatternFill("solid", fgColor="FFF9C4")
    _green_fill   = PatternFill("solid", fgColor="C8E6C9")

    sev_fills = {
        "critical": PatternFill("solid", fgColor="FFCDD2"),
        "high":     PatternFill("solid", fgColor="FFE0B2"),
        "medium":   PatternFill("solid", fgColor="FFF9C4"),
        "low":      PatternFill("solid", fgColor="C8E6C9"),
    }
    sla_fills = {
        OPS_SLA_OVERDUE:  _red_fill,
        OPS_SLA_URGENT:   _orange_fill,
        OPS_SLA_WARNING:  _yellow_fill,
        OPS_SLA_ON_TRACK: _green_fill,
    }

    def _w(row, col, val, font=None, fill=None, align=None):
        cell = ws.cell(row=row, column=col, value=val)
        if font:  cell.font  = font
        if fill:  cell.fill  = fill
        if align: cell.alignment = align
        return cell

    row = 1
    _w(row, 1, "Operations Remediation Report — Summary",
       font=_title_font)
    ws.row_dimensions[row].height = 26
    row += 2

    # --- Scope & timestamp ---
    _w(row, 1, "Report Metadata", font=_section_font)
    row += 1
    _w(row, 1, "Generated (UTC)", font=_label_font, fill=_head_fill)
    _w(row, 2, summary.get("generated_at", ""), font=_value_font)
    row += 1
    _w(row, 1, "Scope / Tag Filter", font=_label_font, fill=_alt_fill)
    _w(row, 2, summary.get("tag_filter", "All Assets"), font=_value_font)
    row += 1
    _w(row, 1, "Total Assets in Scope", font=_label_font, fill=_head_fill)
    _w(row, 2, summary.get("total_assets", 0), font=_value_font)
    row += 1
    _w(row, 1, "Unscanned / Stale Assets (>30d)", font=_label_font, fill=_alt_fill)
    _w(row, 2, summary.get("total_unscanned", 0), font=_value_font)
    row += 2

    # --- Open vuln counts by severity ---
    _w(row, 1, "Open Vulnerability Counts by Severity", font=_section_font)
    row += 1
    for i, sev in enumerate(("critical", "high", "medium", "low")):
        label = sev.title()
        count = summary.get(f"open_{sev}", 0)
        fill  = sev_fills.get(sev, _alt_fill)
        _w(row, 1, label, font=_label_font, fill=fill)
        _w(row, 2, count, font=_value_font)
        row += 1
    row += 1

    # --- SLA state breakdown ---
    _w(row, 1, "SLA State Breakdown (by finding)", font=_section_font)
    row += 1
    state_map = [
        ("count_overdue",   OPS_SLA_OVERDUE,  _red_fill),
        ("count_urgent",    OPS_SLA_URGENT,   _orange_fill),
        ("count_warning",   OPS_SLA_WARNING,  _yellow_fill),
        ("count_on_track",  OPS_SLA_ON_TRACK, _green_fill),
    ]
    for key, label, fill in state_map:
        _w(row, 1, label, font=_label_font, fill=fill)
        _w(row, 2, summary.get(key, 0), font=_value_font)
        row += 1
    row += 1

    # --- Plugin-level metrics ---
    _w(row, 1, "Plugin-Level Metrics", font=_section_font)
    row += 1
    _w(row, 1, "Unique Plugins with Overdue Findings", font=_label_font, fill=_head_fill)
    _w(row, 2, summary.get("plugins_with_overdue", 0), font=_value_font)
    row += 1
    _w(row, 1, "Exploitable Plugins", font=_label_font, fill=_alt_fill)
    _w(row, 2, summary.get("exploitable_plugins", 0), font=_value_font)
    row += 1
    compliance_pct = round(summary.get("sla_compliance_rate", 0) * 100, 1)
    _w(row, 1, "SLA Compliance Rate (On Track %)", font=_label_font, fill=_head_fill)
    _w(row, 2, f"{compliance_pct}%", font=_value_font)
    row += 2

    # --- Top 5 plugins ---
    top5 = summary.get("top5_plugins", [])
    if top5:
        _w(row, 1, "Top 5 Plugins by Affected Asset Count", font=_section_font)
        row += 1
        _w(row, 1, "Plugin Name", font=_label_font, fill=_head_fill)
        _w(row, 2, "Affected Assets", font=_label_font, fill=_head_fill)
        row += 1
        for i, p in enumerate(top5):
            fill = _alt_fill if i % 2 == 0 else PatternFill("solid", fgColor="FFFFFF")
            _w(row, 1, p.get("plugin_name", ""), font=_value_font, fill=fill)
            _w(row, 2, p.get("affected_asset_count", 0), font=_value_font, fill=fill)
            row += 1


def _build_excel(
    plugin_df: pd.DataFrame,
    overdue_df: pd.DataFrame,
    unscanned_df: pd.DataFrame,
    summary: dict,
    output_path: Path,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> Path:
    """
    Build ops_remediation.xlsx with five worksheets:

    1. Summary       — KPI metrics from the summary dict
    2. Plugins       — plugin_df with four-state SLA conditional formatting
    3. Overdue Detail — raw vuln rows that are Overdue, sorted severity → days_open desc
    4. Unscanned Assets — assets with no recent scan
    5. Report Info   — metadata tab (write_metadata_tab)

    Parameters
    ----------
    plugin_df : pd.DataFrame
        Output of ``_group_by_plugin()``.
    overdue_df : pd.DataFrame
        Vuln-level rows filtered to ``ops_sla_status == OPS_SLA_OVERDUE``,
        pre-sorted by severity then days_open descending.
    unscanned_df : pd.DataFrame
        Output of ``_identify_unscanned_assets()``.
    summary : dict
        Output of ``_compute_summary_metrics()``.
    output_path : Path
        Destination file path (must end in .xlsx).
    tag_category, tag_value : str or None
        Tag filter — forwarded to the Report Info tab.

    Returns
    -------
    Path
        The written file path (same as *output_path*).
    """
    from openpyxl import Workbook
    from exporters.excel_exporter import (
        write_dataframe_to_sheet,
        write_metadata_tab,
    )

    tag_filter_str = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )

    wb = Workbook()
    # Remove default sheet created by openpyxl
    if "Sheet" in wb.sheetnames:
        del wb["Sheet"]

    # --- Tab 1: Summary ---
    _build_summary_sheet(wb, summary)

    # --- Tab 2: Plugins ---
    plugin_display = plugin_df.copy()
    # Rename columns to title-case display names for readability
    plugin_display = plugin_display.rename(columns={
        "plugin_id":           "Plugin ID",
        "plugin_name":         "Plugin Name",
        "plugin_family":       "Plugin Family",
        "severity":            "Severity",
        "vpr_score":           "VPR Score",
        "cvss_score":          "CVSS Score",
        "cves":                "CVEs",
        "affected_asset_count":"Affected Assets",
        "days_open_oldest":    "Days Open (Oldest)",
        "days_open_newest":    "Days Open (Newest)",
        "sla_status":          "SLA Status",
        "days_remaining":      "Days Remaining",
        "exploit_available":   "Exploit Available",
    })
    write_dataframe_to_sheet(
        wb, plugin_display,
        sheet_name="Plugins",
        title_row=f"Plugin Summary — {tag_filter_str}",
        severity_col="Severity",
    )
    # Apply four-state SLA formatting — must rename col to match internal helper
    ws_plugins = wb["Plugins"]
    # Temporarily map display header back for helper lookup
    for cell in ws_plugins[2]:  # row 2 is header (row 1 is title)
        if cell.value == "SLA Status":
            cell.value = "sla_status"
            break
    _apply_ops_sla_formatting(ws_plugins)
    # Restore display header
    for cell in ws_plugins[2]:
        if cell.value == "sla_status":
            cell.value = "SLA Status"
            break

    # --- Tab 3: Overdue Detail ---
    if not overdue_df.empty:
        overdue_display = overdue_df[[
            c for c in [
                "asset_id", "hostname", "ipv4", "tags",
                "plugin_id", "plugin_name", "severity", "vpr_score",
                "cve", "days_open", "days_remaining", "ops_sla_status",
                "first_found",
            ] if c in overdue_df.columns
        ]].copy()
        overdue_display = overdue_display.rename(columns={
            "asset_id":       "Asset ID",
            "hostname":       "Hostname",
            "ipv4":           "IP Address",
            "tags":           "Tags",
            "plugin_id":      "Plugin ID",
            "plugin_name":    "Plugin Name",
            "severity":       "Severity",
            "vpr_score":      "VPR Score",
            "cve":            "CVE",
            "days_open":      "Days Open",
            "days_remaining": "Days Remaining",
            "ops_sla_status": "SLA Status",
            "first_found":    "First Found",
        })
        write_dataframe_to_sheet(
            wb, overdue_display,
            sheet_name="Overdue Detail",
            title_row=f"Overdue Findings — {tag_filter_str}",
            severity_col="Severity",
        )
        ws_overdue = wb["Overdue Detail"]
        for cell in ws_overdue[2]:
            if cell.value == "SLA Status":
                cell.value = "sla_status"
                break
        _apply_ops_sla_formatting(ws_overdue)
        for cell in ws_overdue[2]:
            if cell.value == "sla_status":
                cell.value = "SLA Status"
                break
    else:
        ws_empty = wb.create_sheet(title="Overdue Detail")
        ws_empty.cell(row=1, column=1, value="No overdue findings for this scope.")

    # --- Tab 4: Unscanned Assets ---
    if not unscanned_df.empty:
        write_dataframe_to_sheet(
            wb, unscanned_df,
            sheet_name="Unscanned Assets",
            title_row=f"Unscanned / Stale Assets (>30 days) — {tag_filter_str}",
            severity_col=None,
        )
    else:
        ws_empty2 = wb.create_sheet(title="Unscanned Assets")
        ws_empty2.cell(row=1, column=1, value="No unscanned assets for this scope.")

    # --- Tab 5: Report Info ---
    from datetime import datetime, timezone
    generated_at = datetime.now(tz=timezone.utc)
    write_metadata_tab(wb, REPORT_NAME, tag_filter_str, generated_at)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_path)
    logger.info("[%s] Excel workbook saved: %s", REPORT_NAME, output_path)
    return output_path


def _kpi_html(summary: dict) -> str:
    """
    Render the summary dict as an inline-CSS HTML block suitable for embedding
    in a PDF section.  Produces a two-column tile grid (label | value) followed
    by a top-5 plugins mini-table.
    """
    accent      = "#1F3864"
    text        = "#212121"
    muted       = "#757575"
    border      = "#DDDFE2"
    white       = "#FFFFFF"
    alt         = "#E8EAF6"

    sla_colors = {
        OPS_SLA_OVERDUE:  ("#FFCDD2", "#B71C1C"),
        OPS_SLA_URGENT:   ("#FFE0B2", "#E65100"),
        OPS_SLA_WARNING:  ("#FFF9C4", "#F57F17"),
        OPS_SLA_ON_TRACK: ("#C8E6C9", "#1B5E20"),
    }
    sev_bg = {"critical": "#FFCDD2", "high": "#FFE0B2", "medium": "#FFF9C4", "low": "#C8E6C9"}
    sev_fg = {"critical": "#B71C1C", "high": "#E65100", "medium": "#F57F17", "low": "#1B5E20"}

    td_l = (
        f"padding: 5px 10px; font-family: Arial, sans-serif; font-size: 9pt; "
        f"font-weight: bold; color: {muted}; border: 1px solid {border}; "
        f"background-color: {alt}; width: 60%;"
    )
    td_r = (
        f"padding: 5px 10px; font-family: Arial, sans-serif; font-size: 10pt; "
        f"font-weight: bold; color: {text}; border: 1px solid {border}; "
        f"background-color: {white}; width: 40%; text-align: right;"
    )

    compliance_pct = round(summary.get("sla_compliance_rate", 0) * 100, 1)

    # SLA state rows with per-state background colour
    def _state_row(label: str, key: str) -> str:
        bg, fg = sla_colors.get(label, (white, text))
        val = summary.get(key, 0)
        return (
            f"<tr>"
            f'<td style="{td_l} background-color: {bg}; color: {fg};">{label}</td>'
            f'<td style="{td_r} background-color: {bg}; color: {fg};">{val:,}</td>'
            f"</tr>\n"
        )

    # Severity count rows
    def _sev_row(sev: str) -> str:
        bg = sev_bg.get(sev, white)
        fg = sev_fg.get(sev, text)
        val = summary.get(f"open_{sev}", 0)
        return (
            f"<tr>"
            f'<td style="{td_l} background-color: {bg}; color: {fg};">'
            f"Open {sev.title()}</td>"
            f'<td style="{td_r} background-color: {bg}; color: {fg};">{val:,}</td>'
            f"</tr>\n"
        )

    rows = (
        f"<tr><td style='{td_l}'>Generated (UTC)</td>"
        f"<td style='{td_r}'>{summary.get('generated_at', '')}</td></tr>\n"
        f"<tr><td style='{td_l}'>Scope</td>"
        f"<td style='{td_r}'>{summary.get('tag_filter', 'All Assets')}</td></tr>\n"
        f"<tr><td style='{td_l}'>Total Assets in Scope</td>"
        f"<td style='{td_r}'>{summary.get('total_assets', 0):,}</td></tr>\n"
        f"<tr><td style='{td_l}'>Unscanned / Stale Assets (&gt;30d)</td>"
        f"<td style='{td_r}'>{summary.get('total_unscanned', 0):,}</td></tr>\n"
    )
    for sev in ("critical", "high", "medium", "low"):
        rows += _sev_row(sev)
    rows += _state_row(OPS_SLA_OVERDUE,  "count_overdue")
    rows += _state_row(OPS_SLA_URGENT,   "count_urgent")
    rows += _state_row(OPS_SLA_WARNING,  "count_warning")
    rows += _state_row(OPS_SLA_ON_TRACK, "count_on_track")
    rows += (
        f"<tr><td style='{td_l}'>Unique Plugins with Overdue Findings</td>"
        f"<td style='{td_r}'>{summary.get('plugins_with_overdue', 0):,}</td></tr>\n"
        f"<tr><td style='{td_l}'>Exploitable Plugins</td>"
        f"<td style='{td_r}'>{summary.get('exploitable_plugins', 0):,}</td></tr>\n"
        f"<tr><td style='{td_l}'>SLA Compliance Rate (On Track)</td>"
        f"<td style='{td_r}'>{compliance_pct}%</td></tr>\n"
    )

    kpi_table = (
        f'<table style="border-collapse: collapse; width: 100%; margin: 8px 0;">'
        f"{rows}</table>"
    )

    # Top-5 plugins mini-table
    top5 = summary.get("top5_plugins", [])
    top5_html = ""
    if top5:
        th = (
            f"font-family: Arial, sans-serif; font-size: 9pt; font-weight: bold; "
            f"color: {white}; background-color: {accent}; "
            f"border: 1px solid {border}; padding: 5px 8px; text-align: left;"
        )
        td = (
            f"font-family: Arial, sans-serif; font-size: 9pt; color: {text}; "
            f"border: 1px solid {border}; padding: 4px 8px;"
        )
        t_rows = ""
        for i, p in enumerate(top5):
            bg = alt if i % 2 == 0 else white
            t_rows += (
                f'<tr style="background-color: {bg};">'
                f'<td style="{td}">{p.get("plugin_name", "")}</td>'
                f'<td style="{td}; text-align: right;">'
                f'{p.get("affected_asset_count", 0):,}</td>'
                f"</tr>\n"
            )
        top5_html = (
            f'<p style="font-weight: bold; color: {accent}; margin: 14px 0 4px 0;">'
            f"Top 5 Plugins by Affected Asset Count</p>"
            f'<table style="border-collapse: collapse; width: 100%; margin: 4px 0;">'
            f"<thead><tr>"
            f'<th style="{th}">Plugin Name</th>'
            f'<th style="{th}; text-align: right;">Affected Assets</th>'
            f"</tr></thead>"
            f"<tbody>{t_rows}</tbody></table>"
        )

    return kpi_table + top5_html


def _truncate_for_pdf(df: pd.DataFrame) -> pd.DataFrame:
    """
    Truncate long text fields for PDF rendering only.

    Keeps plugin names and hostnames within the fixed column widths used by the
    WeasyPrint tables.  Never call this before build_excel() — Excel must always
    receive full untruncated values.
    """
    df = df.copy()
    if "Plugin Name" in df.columns:
        df["Plugin Name"] = df["Plugin Name"].apply(
            lambda x: (x[:57] + "...") if isinstance(x, str) and len(x) > 60 else (x or "")
        )
    if "Hostname" in df.columns:
        df["Hostname"] = df["Hostname"].apply(
            lambda x: (x[:47] + "...") if isinstance(x, str) and len(x) > 50 else (x or "")
        )
    return df


# Column width maps for WeasyPrint table-layout: fixed.
# Keys must match the renamed (display) column headers passed to build_pdf().
_PDF_COL_WIDTHS_VULN = {
    "Severity":        "8%",
    "Plugin Name":     "26%",
    "CVE":             "12%",
    "Hostname":        "14%",
    "IP Address":      "9%",
    "Days Open":       "8%",
    "Days Remaining":  "10%",
    "First Found":     "13%",
}

_PDF_COL_WIDTHS_PLUGIN = {
    "Severity":          "8%",
    "Plugin Name":       "26%",
    "Plugin Family":     "12%",
    "VPR Score":         "7%",
    "Affected Assets":   "9%",
    "Days Open (Oldest)":"10%",
    "SLA Status":        "20%",
    "Exploit Available": "8%",
}

_PDF_COL_WIDTHS_UNSCANNED = {
    "Hostname":        "22%",
    "IP Address":      "15%",
    "Tags":            "20%",
    "Last Scan Date":  "18%",
    "Days Since Scan": "12%",
    "Operating System":"13%",
}


def _build_pdf(
    plugin_df: pd.DataFrame,
    overdue_df: pd.DataFrame,
    urgent_df: pd.DataFrame,
    unscanned_df: pd.DataFrame,
    summary: dict,
    output_path: Path,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> Path:
    """
    Build ops_remediation.pdf via WeasyPrint with five sections:

    1. Executive Summary  — KPI tiles from the summary dict
    2. Overdue Findings   — overdue_df (top 200, sorted severity → days_open desc)
    3. Urgent Findings    — urgent_df (<=25% SLA remaining, sorted severity → days_remaining)
    4. Plugin Summary     — plugin_df (all plugins, same sort as _group_by_plugin)
    5. Unscanned Assets   — unscanned_df (only if non-empty)

    The cover page (generated by build_pdf) shows report title, scope banner,
    SLA definitions, and VPR score ranges.

    Parameters
    ----------
    plugin_df : pd.DataFrame
        Output of ``_group_by_plugin()``.
    overdue_df : pd.DataFrame
        Vuln-level rows with ``ops_sla_status == OPS_SLA_OVERDUE``.
    urgent_df : pd.DataFrame
        Vuln-level rows with ``ops_sla_status == OPS_SLA_URGENT``.
    unscanned_df : pd.DataFrame
        Output of ``_identify_unscanned_assets()``.
    summary : dict
        Output of ``_compute_summary_metrics()``.
    output_path : Path
        Destination .pdf file path.
    tag_category, tag_value : str or None
        Tag filter applied to the report.

    Returns
    -------
    Path
        Absolute path of the written PDF.
    """
    from exporters.pdf_exporter import build_pdf

    tag_filter_str = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )

    # ------------------------------------------------------------------
    # Section 1: Executive Summary KPIs (rendered as styled HTML, no table)
    # ------------------------------------------------------------------
    sections: list[dict] = [
        {
            "heading":  "Executive Summary",
            "text":     _kpi_html(summary),
        },
    ]

    # ------------------------------------------------------------------
    # Section 2: Overdue Findings (vuln-level, top 200)
    # ------------------------------------------------------------------
    overdue_count = len(overdue_df)
    overdue_cols  = [c for c in [
        "severity", "plugin_name", "cve", "hostname", "ipv4",
        "days_open", "days_remaining", "first_found",
    ] if c in overdue_df.columns]

    overdue_display = overdue_df[overdue_cols].head(200).copy()
    overdue_display = overdue_display.rename(columns={
        "severity":      "Severity",
        "plugin_name":   "Plugin Name",
        "cve":           "CVE",
        "hostname":      "Hostname",
        "ipv4":          "IP Address",
        "days_open":     "Days Open",
        "days_remaining":"Days Remaining",
        "first_found":   "First Found",
    })

    overdue_note = ""
    if overdue_count > 200:
        overdue_note = (
            f"Showing top 200 of {overdue_count:,} overdue findings. "
            f"Full detail available in the Excel attachment."
        )

    sections.append({
        "heading":      f"Overdue Findings ({overdue_count:,} total)",
        "text":         overdue_note or None,
        "dataframe":    _truncate_for_pdf(overdue_display) if not overdue_df.empty else None,
        "severity_col": "Severity",
        "col_widths":   _PDF_COL_WIDTHS_VULN,
    })

    # ------------------------------------------------------------------
    # Section 3: Urgent Findings (<=25% SLA remaining)
    # ------------------------------------------------------------------
    urgent_count = len(urgent_df)
    if not urgent_df.empty:
        urgent_cols = [c for c in [
            "severity", "plugin_name", "cve", "hostname", "ipv4",
            "days_open", "days_remaining", "first_found",
        ] if c in urgent_df.columns]

        urgent_display = urgent_df[urgent_cols].head(200).copy()
        urgent_display = urgent_display.rename(columns={
            "severity":      "Severity",
            "plugin_name":   "Plugin Name",
            "cve":           "CVE",
            "hostname":      "Hostname",
            "ipv4":          "IP Address",
            "days_open":     "Days Open",
            "days_remaining":"Days Remaining",
            "first_found":   "First Found",
        })
        sections.append({
            "heading":      f"Urgent Findings — <=25% SLA Remaining ({urgent_count:,} total)",
            "text":         (
                f"These {urgent_count:,} findings are not yet overdue but have fewer than "
                f"25% of their SLA window remaining. Prioritize alongside overdue items."
            ),
            "dataframe":    _truncate_for_pdf(urgent_display),
            "severity_col": "Severity",
            "col_widths":   _PDF_COL_WIDTHS_VULN,
        })

    # ------------------------------------------------------------------
    # Section 4: Plugin Summary
    # ------------------------------------------------------------------
    plugin_count = len(plugin_df)
    plugin_cols  = [c for c in [
        "severity", "plugin_name", "plugin_family",
        "vpr_score", "affected_asset_count",
        "days_open_oldest", "sla_status", "exploit_available",
    ] if c in plugin_df.columns]

    plugin_display = plugin_df[plugin_cols].head(200).copy()
    plugin_display = plugin_display.rename(columns={
        "severity":            "Severity",
        "plugin_name":         "Plugin Name",
        "plugin_family":       "Plugin Family",
        "vpr_score":           "VPR Score",
        "affected_asset_count":"Affected Assets",
        "days_open_oldest":    "Days Open (Oldest)",
        "sla_status":          "SLA Status",
        "exploit_available":   "Exploit Available",
    })

    plugin_note = ""
    if plugin_count > 200:
        plugin_note = (
            f"Showing top 200 of {plugin_count:,} plugins (sorted by severity, VPR score, "
            f"affected asset count). Full list in the Excel attachment."
        )

    sections.append({
        "heading":      f"Plugin Summary ({plugin_count:,} unique plugins)",
        "text":         plugin_note or None,
        "dataframe":    _truncate_for_pdf(plugin_display),
        "severity_col": "Severity",
        "col_widths":   _PDF_COL_WIDTHS_PLUGIN,
    })

    # ------------------------------------------------------------------
    # Section 5: Unscanned Assets (omit section if empty)
    # ------------------------------------------------------------------
    if not unscanned_df.empty:
        unscanned_cols = [c for c in [
            "hostname", "ipv4", "tags", "last_scan_date", "days_since_scan",
        ] if c in unscanned_df.columns]

        unscanned_display = unscanned_df[unscanned_cols].copy()
        unscanned_display = unscanned_display.rename(columns={
            "hostname":       "Hostname",
            "ipv4":           "IP Address",
            "tags":           "Tags",
            "last_scan_date": "Last Scan Date",
            "days_since_scan":"Days Since Scan",
        })

        sections.append({
            "heading":      f"Unscanned / Stale Assets ({len(unscanned_df):,} assets)",
            "text":         (
                "Assets below have not been scanned in the last 30 days. "
                "Vulnerability counts for these assets may be incomplete."
            ),
            "dataframe":    _truncate_for_pdf(unscanned_display),
            "severity_col": None,
            "col_widths":   _PDF_COL_WIDTHS_UNSCANNED,
        })

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------
    output_path = Path(output_path)
    result = build_pdf(
        report_title=REPORT_NAME,
        scope_str=tag_filter_str,
        sections=sections,
        output_path=output_path,
    )
    logger.info("[%s] PDF written: %s", REPORT_NAME, result)
    return result


def _build_email_summary(
    summary: dict,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> dict:
    """
    Build the ``metrics`` sub-dict that goes into the ``report_outputs`` entry
    for this report.  ``build_kpi_metrics()`` in ``delivery/email_template.py``
    reads this to construct the four KPI tiles shown in the email body.

    The returned dict has two top-level sections:

    ``kpi_tiles``
        Pre-built list of tile dicts ``{label, value, color, sub_label?}``
        consumed directly by the email template renderer.  Avoids duplicating
        the extraction logic that other reports embed in their own ``metrics``
        structures.

    ``raw``
        Flat copy of the summary dict for any downstream consumer that wants
        the underlying numbers (e.g. dashboards, audit scripts).

    Parameters
    ----------
    summary : dict
        Output of ``_compute_summary_metrics()``.
    tag_category, tag_value : str or None
        Tag filter — included in ``raw`` for context.

    Returns
    -------
    dict
        ``{kpi_tiles: list[dict], raw: dict}``
    """
    _RED    = "#d32f2f"
    _ORANGE = "#f57c00"
    _AMBER  = "#fbc02d"
    _GREEN  = "#388e3c"
    _GREY   = "#757575"

    # ------------------------------------------------------------------
    # Tile 1: Open Criticals
    # ------------------------------------------------------------------
    open_crit = summary.get("open_critical", 0)
    tile_crit = {
        "label": "Open Criticals",
        "value": f"{open_crit:,}",
        "color": _RED if open_crit > 0 else _GREEN,
    }

    # ------------------------------------------------------------------
    # Tile 2: Overdue Findings (all severities)
    # ------------------------------------------------------------------
    count_overdue = summary.get("count_overdue", 0)
    tile_overdue = {
        "label": "Overdue Findings",
        "value": f"{count_overdue:,}",
        "color": _RED if count_overdue > 0 else _GREEN,
        "sub_label": "across all severities",
    }

    # ------------------------------------------------------------------
    # Tile 3: SLA Compliance Rate
    # ------------------------------------------------------------------
    rate = summary.get("sla_compliance_rate", 0.0)
    rate_pct = round(rate * 100, 1)
    if rate >= 0.80:
        compliance_color = _GREEN
    elif rate >= 0.60:
        compliance_color = _AMBER
    else:
        compliance_color = _RED
    tile_sla = {
        "label":     "SLA Compliance",
        "value":     f"{rate_pct}%",
        "color":     compliance_color,
        "sub_label": "findings on track",
    }

    # ------------------------------------------------------------------
    # Tile 4: Exploitable Plugins
    # ------------------------------------------------------------------
    exploitable = summary.get("exploitable_plugins", 0)
    tile_exploit = {
        "label": "Exploitable Plugins",
        "value": f"{exploitable:,}",
        "color": _RED if exploitable > 0 else _GREEN,
        "sub_label": "with known exploit",
    }

    kpi_tiles = [tile_crit, tile_overdue, tile_sla, tile_exploit]

    return {
        "kpi_tiles": kpi_tiles,
        "raw": {
            "tag_filter":           summary.get("tag_filter", "All Assets"),
            "generated_at":         summary.get("generated_at", ""),
            "total_assets":         summary.get("total_assets", 0),
            "total_unscanned":      summary.get("total_unscanned", 0),
            "open_critical":        summary.get("open_critical", 0),
            "open_high":            summary.get("open_high", 0),
            "open_medium":          summary.get("open_medium", 0),
            "open_low":             summary.get("open_low", 0),
            "count_overdue":        summary.get("count_overdue", 0),
            "count_urgent":         summary.get("count_urgent", 0),
            "count_warning":        summary.get("count_warning", 0),
            "count_on_track":       summary.get("count_on_track", 0),
            "plugins_with_overdue": summary.get("plugins_with_overdue", 0),
            "exploitable_plugins":  summary.get("exploitable_plugins", 0),
            "sla_compliance_rate":  summary.get("sla_compliance_rate", 0.0),
        },
    }


def run_report(
    tio,
    run_id: str,
    tag_category: Optional[str] = None,
    tag_value: Optional[str] = None,
    output_dir: Optional[Path] = None,
    generated_at: Optional[datetime] = None,
    cache_dir: Optional[Path] = None,
) -> dict:
    """
    Main entry point called by ``run_all.py`` and ``scheduler.py``.

    Signature matches the convention used by all other report modules so
    ``run_all.py`` can call it uniformly.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Date string (``YYYY-MM-DD``) used to name the default output directory
        when *output_dir* is not provided.
    tag_category, tag_value : str, optional
        Tag filter for asset scoping.
    output_dir : Path, optional
        Where to write Excel and PDF files.  Created if it does not exist.
        Defaults to ``OUTPUT_DIR / run_id / "ops_remediation"``.
    generated_at : datetime, optional
        Report timestamp.  Defaults to UTC now.
    cache_dir : Path, optional
        Parquet cache directory shared across the batch run.
        Defaults to ``CACHE_DIR / run_id``.

    Returns
    -------
    dict
        ``{"pdf": Path, "excel": Path, "charts": [], "metrics": dict}``
        compatible with ``run_all.py`` / ``email_sender.py``.
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if cache_dir is None:
        cache_dir = CACHE_DIR / (run_id or generated_at.strftime("%Y-%m-%d"))
    if output_dir is None:
        output_dir = OUTPUT_DIR / (run_id or generated_at.strftime("%Y-%m-%d")) / REPORT_SLUG
    output_dir = Path(output_dir)
    cache_dir  = Path(cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    logger.info(
        "[%s] Starting | filter=%s=%s | output=%s",
        REPORT_NAME,
        tag_category or "*",
        tag_value    or "*",
        output_dir,
    )

    # ------------------------------------------------------------------
    # Step 1: Fetch and prepare data
    # ------------------------------------------------------------------
    vulns_df, assets_df = _fetch_and_prepare(
        tio          = tio,
        cache_dir    = cache_dir,
        tag_category = tag_category,
        tag_value    = tag_value,
        as_of        = generated_at,
    )

    unscanned_df = _identify_unscanned_assets(assets_df, as_of=generated_at)

    scanned_ids   = set(assets_df["asset_id"]) - set(unscanned_df["asset_id"])
    vulns_scanned = vulns_df[vulns_df["asset_id"].isin(scanned_ids)]

    plugin_df = _group_by_plugin(vulns_scanned)

    summary = _compute_summary_metrics(
        vulns_df     = vulns_scanned,
        plugin_df    = plugin_df,
        assets_df    = assets_df,
        unscanned_df = unscanned_df,
        tag_category = tag_category,
        tag_value    = tag_value,
        as_of        = generated_at,
    )

    # ------------------------------------------------------------------
    # Step 2: Build Excel
    # ------------------------------------------------------------------
    slug_str   = safe_filename(f"{tag_category or 'all'}_{tag_value or 'assets'}")
    excel_path = output_dir / f"ops_remediation_{slug_str}.xlsx"

    overdue_df = vulns_scanned[
        vulns_scanned["ops_sla_status"] == OPS_SLA_OVERDUE
    ].sort_values(
        ["severity", "days_open"],
        ascending=[True, False],
        na_position="last",
        key=lambda s: s.map(SEVERITY_RANK) if s.name == "severity" else s,
    )

    _build_excel(
        plugin_df    = plugin_df,
        overdue_df   = overdue_df,
        unscanned_df = unscanned_df,
        summary      = summary,
        output_path  = excel_path,
        tag_category = tag_category,
        tag_value    = tag_value,
    )

    # ------------------------------------------------------------------
    # Step 3: Build PDF
    # ------------------------------------------------------------------
    pdf_path = output_dir / f"ops_remediation_{slug_str}.pdf"

    urgent_df = vulns_scanned[
        vulns_scanned["ops_sla_status"] == OPS_SLA_URGENT
    ].sort_values(
        ["severity", "days_remaining"],
        ascending=[True, True],
        na_position="last",
        key=lambda s: s.map(SEVERITY_RANK) if s.name == "severity" else s,
    )

    _build_pdf(
        plugin_df    = plugin_df,
        overdue_df   = overdue_df,
        urgent_df    = urgent_df,
        unscanned_df = unscanned_df,
        summary      = summary,
        output_path  = pdf_path,
        tag_category = tag_category,
        tag_value    = tag_value,
    )

    # ------------------------------------------------------------------
    # Step 4: Build email metrics
    # ------------------------------------------------------------------
    email_metrics = _build_email_summary(
        summary      = summary,
        tag_category = tag_category,
        tag_value    = tag_value,
    )

    logger.info(
        "[%s] Complete | excel=%s | pdf=%s",
        REPORT_NAME, excel_path.name, pdf_path.name,
    )

    return {
        "pdf":     pdf_path,
        "excel":   excel_path,
        "charts":  [],
        "metrics": email_metrics,
    }


# ===========================================================================
# CLI entry point
# ===========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Operations Remediation Report — prioritized, tag-scoped vuln list for IT ops teams.",
    )
    parser.add_argument("--tag-category", default=None, help='Tenable tag category (e.g. "Operations")')
    parser.add_argument("--tag-value",    default=None, help='Tenable tag value    (e.g. "Server Operations")')
    parser.add_argument("--output-dir",   default=None, help="Output directory (default: output/)")
    parser.add_argument("--cache-dir",    default=None, help="Parquet cache directory (default: data/cache/<today>)")
    parser.add_argument("--no-email",     action="store_true", help="Generate reports but skip email delivery")
    args = parser.parse_args()

    _cache_dir = (
        Path(args.cache_dir)
        if args.cache_dir
        else CACHE_DIR / datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    )
    _output_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR

    from tenable_client import get_client
    _tio = get_client()

    _as_of = datetime.now(tz=timezone.utc)

    # -----------------------------------------------------------------------
    # Step 1 smoke-test — exercises all data prep functions and prints a
    # summary.  run_report() will replace this block once Steps 2-5 are done.
    # -----------------------------------------------------------------------

    # Pre-filter cache inspection: load raw parquets and show tag samples
    # so we can verify the tag column format before any filtering is applied.
    _raw_assets_cache = _cache_dir / "assets_all.parquet"
    _raw_vulns_cache  = _cache_dir / "vulns_all.parquet"
    print("\n=== Cache Inspection (pre-filter) ===")
    if _raw_assets_cache.exists():
        _raw_assets = pd.read_parquet(_raw_assets_cache, engine="fastparquet")
        _non_empty_asset_tags = _raw_assets["tags"].fillna("").loc[lambda s: s != ""]
        print(f"  assets_all rows        : {len(_raw_assets)}")
        print(f"  assets with tags       : {len(_non_empty_asset_tags)}/{len(_raw_assets)}")
        print(f"  sample tag values      : {_non_empty_asset_tags.head(5).tolist()}")
    else:
        print(f"  assets_all.parquet not found at {_raw_assets_cache}")
    if _raw_vulns_cache.exists():
        _raw_vulns = pd.read_parquet(_raw_vulns_cache, engine="fastparquet")
        _vulns_with_tags = _raw_vulns["tags"].fillna("").loc[lambda s: s != ""] if "tags" in _raw_vulns.columns else pd.Series(dtype=str)
        print(f"  vulns_all rows         : {len(_raw_vulns)}")
        print(f"  vulns with tags col    : {'yes' if 'tags' in _raw_vulns.columns else 'no (expected)'}")
        print(f"  vuln asset_id sample   : {_raw_vulns['asset_id'].dropna().head(3).tolist()}")
        print(f"  asset asset_id sample  : {_raw_assets['asset_id'].dropna().head(3).tolist() if _raw_assets_cache.exists() else 'N/A'}")
    else:
        print(f"  vulns_all.parquet not found at {_raw_vulns_cache}")
    print()

    _vulns_df, _assets_df = _fetch_and_prepare(
        tio          = _tio,
        cache_dir    = _cache_dir,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
        as_of        = _as_of,
    )

    _unscanned_df = _identify_unscanned_assets(_assets_df, as_of=_as_of)

    _scanned_ids   = set(_assets_df["asset_id"]) - set(_unscanned_df["asset_id"])
    _vulns_scanned = _vulns_df[_vulns_df["asset_id"].isin(_scanned_ids)]

    _plugin_df = _group_by_plugin(_vulns_scanned)

    _summary = _compute_summary_metrics(
        vulns_df     = _vulns_scanned,
        plugin_df    = _plugin_df,
        assets_df    = _assets_df,
        unscanned_df = _unscanned_df,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
        as_of        = _as_of,
    )

    print("\n=== Step 1 — Data Preparation Summary ===")
    for k, v in _summary.items():
        if k == "top5_plugins":
            print(f"  top5_plugins:")
            for p in v:
                print(f"    {p['plugin_name'][:60]:<60}  {p['affected_asset_count']} assets")
        else:
            print(f"  {k:<28}: {v}")

    print(f"\n  plugin_df rows       : {len(_plugin_df)}")
    print(f"  unscanned_df rows    : {len(_unscanned_df)}")
    if not _plugin_df.empty:
        print(f"\n  SLA state distribution (by plugin row):")
        for state in OPS_SLA_STATE_ORDER:
            n = int((_plugin_df["sla_status"] == state).sum())
            print(f"    {state:<35}: {n}")

    # --- Step 2: Build Excel ---
    _overdue_df = _vulns_scanned[
        _vulns_scanned["ops_sla_status"] == OPS_SLA_OVERDUE
    ].sort_values(
        ["severity", "days_open"],
        ascending=[True, False],
        na_position="last",
        key=lambda s: s.map(SEVERITY_RANK) if s.name == "severity" else s,
    )
    _output_dir.mkdir(parents=True, exist_ok=True)
    _slug = safe_filename(
        f"{args.tag_category or 'all'}_{args.tag_value or 'assets'}"
    )
    _excel_path = _output_dir / f"ops_remediation_{_slug}.xlsx"
    _build_excel(
        plugin_df    = _plugin_df,
        overdue_df   = _overdue_df,
        unscanned_df = _unscanned_df,
        summary      = _summary,
        output_path  = _excel_path,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
    )
    print(f"\n  Excel written: {_excel_path}")

    # --- Step 3: Build PDF ---
    _urgent_df = _vulns_scanned[
        _vulns_scanned["ops_sla_status"] == OPS_SLA_URGENT
    ].sort_values(
        ["severity", "days_remaining"],
        ascending=[True, True],
        na_position="last",
        key=lambda s: s.map(SEVERITY_RANK) if s.name == "severity" else s,
    )
    _pdf_path = _output_dir / f"ops_remediation_{_slug}.pdf"
    _build_pdf(
        plugin_df    = _plugin_df,
        overdue_df   = _overdue_df,
        urgent_df    = _urgent_df,
        unscanned_df = _unscanned_df,
        summary      = _summary,
        output_path  = _pdf_path,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
    )
    print(f"  PDF written:  {_pdf_path}")

    # --- Step 4: Build email summary ---
    _email_metrics = _build_email_summary(
        summary      = _summary,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
    )
    print(f"\n=== Step 4 - Email Summary ===")
    print(f"  kpi_tiles ({len(_email_metrics['kpi_tiles'])} tiles):")
    for tile in _email_metrics["kpi_tiles"]:
        sub = f"  ({tile['sub_label']})" if tile.get("sub_label") else ""
        print(f"    [{tile['label']}] {tile['value']}{sub}  color={tile['color']}")
    print(f"  raw keys: {list(_email_metrics['raw'].keys())}")
