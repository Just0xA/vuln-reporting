"""
tests/test_new_vs_remediated_module.py — Unit tests for NewVsRemediatedModule.

Tests cover:
  - Cold-start: trend_snapshots None or insufficient_data=True → coherent
    ModuleData with error=None and metrics["cold_start"]=True; no "NaN" in
    any rendered channel (QUAL-01)
  - Stacked inflow split: net_new and resurfaced are distinct counts in
    chart_data and table_data (D-15-02)
  - No double-count: finding with first_found and resurfaced_date in
    different months counts as net_new in first_found month AND resurfaced
    in resurfaced_date month (never both in the same month)
  - Outflow Option B: snapshot with fixed_findings_count=N → outflow bar=N
    and net_delta=(total_inflow - N); outflow comes from trend snapshot,
    NOT from fixed_vulns_df kwarg (D-15-06)
  - Cold-start outflow guard: snapshot with absent/None fixed_findings_count
    → "—" in table (not silent zero) (D-15-06)
  - Partial-month label: current month label contains "partial" (D-15-08)
  - Open-count context uses open_findings_at (QUAL-02 — REOPENED not dropped)
  - Zero-denominator MoM delta helper: prev=0 → "N/A" not ZeroDivisionError
  - fixed_vulns_df NOT consulted: module works with fixed_vulns_df=None
  - Empty vulns_df / zero-data → safe four-channel render (QUAL-03)

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id:  100001, 100002, ...
  - owner names: "Engineering", "Operations", "Unassigned"
  - No real hostnames, IPs, CVE IDs, or plugin names

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import datetime
from typing import Optional

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.base import ModuleConfig, ModuleData
from reports.modules.new_vs_remediated_module import (
    NewVsRemediatedModule,
    _safe_mom_delta,
    _month_label,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"
_REPORT_DATE = datetime.datetime(2026, 6, 11, 12, 0, 0, tzinfo=datetime.timezone.utc)
_CURRENT_PERIOD = pd.Period("2026-06", "M")


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _ts(year: int, month: int, day: int = 1) -> str:
    return f"{year:04d}-{month:02d}-{day:02d}T00:00:00Z"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns_df with all required columns."""
    defaults = {
        "state":            "open",
        "resurfaced_date":  None,
        "last_fixed":       None,
        "first_found":      _ts(2026, 1),
        "plugin_id":        100001,
        "asset_uuid":       _uuid(1),
        "severity":         "high",
        "severity_modification_type": "NONE",
        "recast_rule_uuid": "",
    }
    records = [{**defaults, **r} for r in rows]
    # columns= keeps the fetcher contract on empty input: zero rows but real
    # columns (a columnless frame breaks date coercion / extract_owner).
    df = pd.DataFrame(records, columns=list(defaults.keys()))
    # Normalise date columns to datetime64[ns, UTC] (as fetcher would do)
    for col in ("first_found", "last_fixed", "resurfaced_date"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df


def _make_assets(rows: Optional[list[dict]] = None) -> pd.DataFrame:
    """Build a minimal assets_df with asset_uuid and tags columns."""
    if rows is None:
        rows = [{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}]
    defaults = {"asset_uuid": _uuid(1), "tags": ""}
    records = [{**defaults, **r} for r in rows]
    # columns= keeps the fetcher contract on empty input (see _make_vulns).
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_snapshot(
    month: str,
    new_findings_count: Optional[int] = None,
    fixed_findings_count: Optional[int] = None,
    **extra,
) -> dict:
    """Build a minimal trend snapshot dict."""
    return {
        "month":               month,
        "tag_filter":          "all_assets",
        "critical":            0,
        "high":                0,
        "medium":              0,
        "low":                 0,
        "asset_count":         5,
        "on_time_asset_count": None,
        "reopened_count":      None,
        "accepted_count":      None,
        "recast_count":        None,
        "new_findings_count":  new_findings_count,
        "fixed_findings_count": fixed_findings_count,
        "generated_at":        "2026-06-01T00:00:00Z",
        **extra,
    }


def _config(**options) -> ModuleConfig:
    return ModuleConfig("new_vs_remediated", options=options)


def _run(
    vulns_rows: list[dict],
    snapshots: Optional[list[dict]] = None,
    insufficient_data: bool = False,
    asset_rows: Optional[list[dict]] = None,
    include_fixed_vulns_df: bool = False,
    **options,
) -> ModuleData:
    """Run compute() with synthetic fixtures."""
    mod       = NewVsRemediatedModule()
    vulns_df  = _make_vulns(vulns_rows)
    assets_df = _make_assets(asset_rows)
    cfg       = _config(**options)
    kwargs: dict = {}
    if snapshots is not None:
        kwargs["trend_snapshots"] = {
            "snapshots":        snapshots,
            "insufficient_data": insufficient_data,
        }
    if include_fixed_vulns_df:
        # fixed_vulns_df presence must NOT affect outflow (Option B test)
        kwargs["fixed_vulns_df"] = _make_vulns([
            {"state": "fixed", "first_found": _ts(2026, 5)}
        ])
    return mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg, **kwargs)


# ===========================================================================
# 1. MODULE REGISTRATION
# ===========================================================================

class TestRegistration:
    def test_module_id(self):
        assert NewVsRemediatedModule.MODULE_ID == "new_vs_remediated"

    def test_display_name(self):
        assert NewVsRemediatedModule.DISPLAY_NAME == "New vs Remediated"

    def test_auto_discovery(self):
        """Module is auto-discovered via @register_module on import."""
        import reports.modules  # triggers discover()
        import reports.modules.registry as registry
        assert "new_vs_remediated" in registry._modules

    def test_required_data_includes_trend(self):
        assert "trend_snapshots" in NewVsRemediatedModule.REQUIRED_DATA


# ===========================================================================
# 2. COLD-START GUARD (QUAL-01)
# ===========================================================================

class TestColdStart:
    def test_none_trend_snapshots_returns_cold_start(self):
        """trend_snapshots absent → cold-start ModuleData."""
        data = _run(vulns_rows=[{"state": "open"}])
        assert data.error is None
        assert data.metrics.get("cold_start") is True

    def test_insufficient_data_true_returns_cold_start(self):
        """insufficient_data=True → cold-start ModuleData."""
        data = _run(
            vulns_rows=[{"state": "open"}],
            snapshots=[_make_snapshot("2026-05")],
            insufficient_data=True,
        )
        assert data.error is None
        assert data.metrics.get("cold_start") is True

    def test_single_snapshot_returns_cold_start(self):
        """A single snapshot → insufficient_data=True from read_trend convention."""
        # Simulate what read_trend returns for a single snapshot
        data = _run(
            vulns_rows=[{"state": "open"}],
            snapshots=[_make_snapshot("2026-05")],
            insufficient_data=True,
        )
        assert data.error is None
        assert data.metrics.get("cold_start") is True

    def test_cold_start_summary_text_contains_notice(self):
        """Cold-start summary_text contains 'Trend data being established'."""
        data = _run(vulns_rows=[{"state": "open"}])
        assert "Trend data being established" in data.summary_text

    def test_cold_start_no_nan_in_summary(self):
        """Cold-start summary must not contain 'NaN' (QUAL-01)."""
        data = _run(vulns_rows=[{"state": "open"}])
        assert "NaN" not in data.summary_text
        assert "NaN" not in (data.driver_narrative or "")

    def test_cold_start_no_nan_in_pdf_render(self):
        """Cold-start PDF render must not contain 'NaN'."""
        data = _run(vulns_rows=[{"state": "open"}])
        mod = NewVsRemediatedModule()
        cfg = _config()
        html = mod.render_pdf_section(data, cfg)
        assert "NaN" not in html

    def test_cold_start_no_nan_in_email_panel(self):
        """Cold-start email panel must not contain 'NaN'."""
        data = _run(vulns_rows=[{"state": "open"}])
        mod = NewVsRemediatedModule()
        cfg = _config()
        html = mod.render_email_panel(data, cfg)
        assert "NaN" not in html

    def test_cold_start_rag_strip_is_no_data(self):
        """Cold-start RAG strip must be 'no_data' status."""
        data = _run(vulns_rows=[{"state": "open"}])
        assert data.rag_strip.get("rag_label") == "No Data"

    def test_cold_start_analyst_rows_empty(self):
        """Cold-start analyst tabs returns []."""
        data = _run(vulns_rows=[{"state": "open"}])
        mod = NewVsRemediatedModule()
        cfg = _config()
        assert mod.render_analyst_tabs(data, cfg) == []


# ===========================================================================
# 3. STACKED INFLOW SPLIT (D-15-01/02)
# ===========================================================================

class TestInflowSplit:
    def _two_month_snapshots(self) -> list[dict]:
        return [
            _make_snapshot("2026-04", fixed_findings_count=1),
            _make_snapshot("2026-05", fixed_findings_count=2),
        ]

    def test_net_new_counted_on_first_found_month(self):
        """first_found in May → net_new in May snapshot."""
        data = _run(
            vulns_rows=[
                {"state": "open", "first_found": _ts(2026, 5), "resurfaced_date": None},
                {"state": "open", "first_found": _ts(2026, 5), "resurfaced_date": None},
            ],
            snapshots=self._two_month_snapshots(),
            insufficient_data=False,
        )
        assert data.error is None
        # Find May row in table_data
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert may_rows[0]["net_new"] == 2
        assert may_rows[0]["resurfaced"] == 0

    def test_resurfaced_counted_on_resurfaced_date_month(self):
        """resurfaced_date in May (first_found in April) → resurfaced in May."""
        data = _run(
            vulns_rows=[
                {
                    "state":           "reopened",
                    "first_found":     _ts(2026, 4),
                    "resurfaced_date": _ts(2026, 5),
                },
            ],
            snapshots=self._two_month_snapshots(),
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert may_rows[0]["net_new"] == 0
        assert may_rows[0]["resurfaced"] == 1

    def test_net_new_and_resurfaced_are_distinct_in_chart_data(self):
        """chart_data["net_new"] and chart_data["resurfaced"] are separate lists."""
        data = _run(
            vulns_rows=[
                {"state": "open",     "first_found": _ts(2026, 5), "resurfaced_date": None},
                {"state": "reopened", "first_found": _ts(2026, 4), "resurfaced_date": _ts(2026, 5)},
            ],
            snapshots=self._two_month_snapshots(),
            insufficient_data=False,
        )
        assert data.error is None
        assert "net_new" in data.chart_data
        assert "resurfaced" in data.chart_data
        # May index is 1 (snapshots are April, May)
        assert data.chart_data["net_new"][1] == 1
        assert data.chart_data["resurfaced"][1] == 1

    def test_no_double_count_when_first_found_equals_resurfaced_date(self):
        """
        D-15-02: finding with first_found in same month as resurfaced_date
        counts as net_new only (resurfaced mask excludes net_new mask).
        """
        data = _run(
            vulns_rows=[
                {
                    "state":           "reopened",
                    "first_found":     _ts(2026, 5),
                    "resurfaced_date": _ts(2026, 5),  # same month as first_found
                },
            ],
            snapshots=self._two_month_snapshots(),
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        # Should count as net_new only, NOT both
        assert may_rows[0]["net_new"] == 1
        assert may_rows[0]["resurfaced"] == 0
        assert may_rows[0]["total_inflow"] == 1

    def test_finding_counted_in_correct_separate_months(self):
        """
        Finding with first_found in April and resurfaced_date in May:
        net_new in April, resurfaced in May — never double-counted in one month.
        """
        snapshots = [
            _make_snapshot("2026-04", fixed_findings_count=0),
            _make_snapshot("2026-05", fixed_findings_count=0),
        ]
        data = _run(
            vulns_rows=[
                {
                    "state":           "reopened",
                    "first_found":     _ts(2026, 4),
                    "resurfaced_date": _ts(2026, 5),
                },
            ],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        apr_rows = [r for r in data.table_data if "2026-04" in r["month"]]
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert apr_rows[0]["net_new"] == 1
        assert apr_rows[0]["resurfaced"] == 0
        assert may_rows[0]["net_new"] == 0
        assert may_rows[0]["resurfaced"] == 1


# ===========================================================================
# 4. OUTFLOW OPTION B — from snapshot fixed_findings_count (D-15-06)
# ===========================================================================

class TestOutflowOptionB:
    def _snapshots_with_fixed(self, fixed: int) -> list[dict]:
        return [
            _make_snapshot("2026-04", fixed_findings_count=1),
            _make_snapshot("2026-05", fixed_findings_count=fixed),
        ]

    def test_outflow_bar_sourced_from_snapshot_fixed_findings_count(self):
        """
        Snapshot with fixed_findings_count=7 → outflow=7 in May table row.
        Outflow comes from trend snapshot, NOT from fixed_vulns_df kwarg.
        """
        data = _run(
            vulns_rows=[
                {"state": "open", "first_found": _ts(2026, 5)},
            ],
            snapshots=self._snapshots_with_fixed(7),
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert may_rows[0]["outflow"] == "7"

    def test_net_delta_is_total_inflow_minus_outflow(self):
        """
        total_inflow=3, fixed_findings_count=7 → net_delta = 3 - 7 = -4.
        """
        snapshots = [
            _make_snapshot("2026-04", fixed_findings_count=1),
            _make_snapshot("2026-05", fixed_findings_count=7),
        ]
        data = _run(
            vulns_rows=[
                {"state": "open", "first_found": _ts(2026, 5)},
                {"state": "open", "first_found": _ts(2026, 5)},
                {"state": "open", "first_found": _ts(2026, 5)},
            ],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert may_rows[0]["total_inflow"] == 3
        # net_delta = 3 - 7 = -4
        assert may_rows[0]["net_delta"] == "-4"

    def test_fixed_vulns_df_kwarg_not_used_for_outflow(self):
        """
        Module produces the correct outflow when fixed_vulns_df is present:
        outflow must still come from snapshot fixed_findings_count, not
        fixed_vulns_df row count. Even with fixed_vulns_df present, if
        fixed_findings_count=5 in snapshot, outflow=5.
        """
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=self._snapshots_with_fixed(5),
            insufficient_data=False,
            include_fixed_vulns_df=True,  # fixed_vulns_df is present but must not override
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        # Outflow must equal snapshot fixed_findings_count (5), not len(fixed_vulns_df) (1)
        assert may_rows[0]["outflow"] == "5"

    def test_module_works_with_fixed_vulns_df_none(self):
        """
        fixed_vulns_df=None is the normal production path — no AttributeError/KeyError.
        """
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=self._snapshots_with_fixed(3),
            insufficient_data=False,
            # include_fixed_vulns_df=False (default) → fixed_vulns_df not in kwargs
        )
        assert data.error is None


# ===========================================================================
# 5. COLD-START OUTFLOW GUARD (D-15-06 — absent fixed_findings_count)
# ===========================================================================

class TestColdStartOutflow:
    def test_absent_fixed_findings_count_renders_dash_not_zero(self):
        """
        Snapshot with fixed_findings_count absent (None) → outflow="—" in
        table_data, NOT "0" (never treat absent as silent zero outflow).
        """
        snapshots = [
            _make_snapshot("2026-04", fixed_findings_count=2),
            # 2026-05 snapshot with NO fixed_findings_count field
            {
                "month":               "2026-05",
                "tag_filter":          "all_assets",
                "critical":            0,
                "high":                0,
                "medium":              0,
                "low":                 0,
                "asset_count":         5,
                "generated_at":        "2026-05-01T00:00:00Z",
                # fixed_findings_count deliberately absent
            },
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert may_rows[0]["outflow"] == "—", (
            f"Expected '—' for absent fixed_findings_count, got {may_rows[0]['outflow']!r}"
        )
        assert may_rows[0]["net_delta"] == "—"

    def test_none_fixed_findings_count_renders_dash_not_zero(self):
        """
        Snapshot with fixed_findings_count=None → outflow="—" (D-15-06).
        """
        snapshots = [
            _make_snapshot("2026-04", fixed_findings_count=1),
            _make_snapshot("2026-05", fixed_findings_count=None),  # explicit None
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert may_rows[0]["outflow"] == "—"

    def test_mixed_snapshots_some_with_some_without_fixed_count(self):
        """
        When some months have fixed_findings_count and some don't,
        only months with the field show numeric outflow.
        """
        snapshots = [
            _make_snapshot("2026-04", fixed_findings_count=3),  # has count
            {
                "month":       "2026-05",
                "tag_filter":  "all_assets",
                "generated_at": "2026-05-01T00:00:00Z",
                # no fixed_findings_count
            },
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        apr_rows = [r for r in data.table_data if "2026-04" in r["month"]]
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        # April should show numeric outflow
        assert apr_rows[0]["outflow"] != "—"
        # May should show dash
        assert may_rows[0]["outflow"] == "—"


# ===========================================================================
# 6. PARTIAL-MONTH LABEL (D-15-08)
# ===========================================================================

class TestPartialMonthLabel:
    def test_current_month_label_contains_partial(self):
        """Current month (2026-06) label must contain 'partial'."""
        # Report date is 2026-06-11 so current period is 2026-06
        snapshots = [
            _make_snapshot("2026-05", fixed_findings_count=2),
            _make_snapshot("2026-06", fixed_findings_count=1),  # current month
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 6)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        jun_rows = [r for r in data.table_data if "2026-06" in r["month"]]
        assert len(jun_rows) == 1
        assert "partial" in jun_rows[0]["month"].lower(), (
            f"Expected 'partial' in current month label, got {jun_rows[0]['month']!r}"
        )

    def test_current_month_label_in_chart_data(self):
        """Current month label in chart_data['months'] contains 'partial'."""
        snapshots = [
            _make_snapshot("2026-05", fixed_findings_count=2),
            _make_snapshot("2026-06", fixed_findings_count=1),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 6)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        jun_labels = [m for m in data.chart_data.get("months", []) if "2026-06" in m]
        assert len(jun_labels) == 1
        assert "partial" in jun_labels[0].lower()

    def test_prior_month_label_does_not_contain_partial(self):
        """Completed prior months must NOT have 'partial' in their label."""
        snapshots = [
            _make_snapshot("2026-05", fixed_findings_count=2),
            _make_snapshot("2026-06", fixed_findings_count=1),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        may_rows = [r for r in data.table_data if "2026-05" in r["month"]]
        assert len(may_rows) == 1
        assert "partial" not in may_rows[0]["month"].lower()

    def test_month_label_helper_current_period(self):
        """_month_label returns MTD label for the current period."""
        current = pd.Period("2026-06", "M")
        label = _month_label("2026-06", current)
        assert "partial" in label.lower()
        assert "MTD" in label

    def test_month_label_helper_prior_period(self):
        """_month_label returns plain month string for completed months."""
        current = pd.Period("2026-06", "M")
        label = _month_label("2026-05", current)
        assert label == "2026-05"
        assert "partial" not in label.lower()


# ===========================================================================
# 7. REOPENED-AWARE OPEN COUNT (QUAL-02)
# ===========================================================================

class TestReopenedAware:
    def test_reopened_findings_included_in_open_count_context(self):
        """
        QUAL-02: open_findings_at is used for open-count context;
        REOPENED state findings must not be dropped from the context.
        A vulns_df with 2 OPEN + 1 REOPENED → open_df has 3 rows,
        owner_counts total must reflect all 3.
        """
        snapshots = [
            _make_snapshot("2026-05", fixed_findings_count=0),
            _make_snapshot("2026-06", fixed_findings_count=0),
        ]
        data = _run(
            vulns_rows=[
                {"state": "open",     "first_found": _ts(2026, 6), "asset_uuid": _uuid(1)},
                {"state": "open",     "first_found": _ts(2026, 6), "asset_uuid": _uuid(1)},
                {"state": "reopened", "first_found": _ts(2026, 3), "resurfaced_date": _ts(2026, 6), "asset_uuid": _uuid(1)},
            ],
            snapshots=snapshots,
            insufficient_data=False,
            asset_rows=[{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}],
        )
        assert data.error is None
        # owner_counts should include the REOPENED finding
        owner_counts = data.metrics.get("owner_counts", {})
        total = sum(owner_counts.values())
        assert total == 3, (
            f"Expected 3 open findings (REOPENED included), got {total} via {owner_counts}"
        )


# ===========================================================================
# 8. SAFE MOM DELTA HELPER (Pitfall 5)
# ===========================================================================

class TestSafeMomDelta:
    def test_prev_zero_returns_na(self):
        """prev=0 → 'N/A' not ZeroDivisionError."""
        assert _safe_mom_delta(5, 0) == "N/A"

    def test_prev_none_returns_na(self):
        """prev=None → 'N/A'."""
        assert _safe_mom_delta(5, None) == "N/A"

    def test_curr_none_returns_na(self):
        """curr=None → 'N/A'."""
        assert _safe_mom_delta(None, 5) == "N/A"

    def test_both_none_returns_na(self):
        """Both None → 'N/A'."""
        assert _safe_mom_delta(None, None) == "N/A"

    def test_positive_delta(self):
        """curr > prev → positive percentage string."""
        result = _safe_mom_delta(12, 10)
        assert result == "+20.0%"

    def test_negative_delta(self):
        """curr < prev → negative percentage string."""
        result = _safe_mom_delta(8, 10)
        assert result == "-20.0%"

    def test_zero_delta(self):
        """curr == prev → '+0.0%'."""
        result = _safe_mom_delta(10, 10)
        assert result == "+0.0%"


# ===========================================================================
# 9. EMPTY VULNS_DF / ZERO-DATA GUARD (QUAL-03)
# ===========================================================================

class TestEmptyDataGuard:
    def test_empty_vulns_df_returns_cold_start_not_error(self):
        """
        Empty vulns_df with two valid snapshots → cold-start ModuleData
        (error=None; cold_start=True); not a hard error.
        """
        mod = NewVsRemediatedModule()
        vulns_df  = pd.DataFrame()  # completely empty
        assets_df = _make_assets()
        cfg       = _config()
        snapshots = {
            "snapshots": [
                _make_snapshot("2026-05", fixed_findings_count=2),
                _make_snapshot("2026-06", fixed_findings_count=1),
            ],
            "insufficient_data": False,
        }
        data = mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg, trend_snapshots=snapshots)
        assert data.error is None
        assert data.metrics.get("cold_start") is True

    def test_render_pdf_on_cold_start_does_not_crash(self):
        """render_pdf_section on cold-start data returns valid HTML without crashing."""
        data = _run(vulns_rows=[])
        mod = NewVsRemediatedModule()
        cfg = _config()
        html = mod.render_pdf_section(data, cfg)
        assert isinstance(html, str)
        assert "NaN" not in html

    def test_render_excel_on_cold_start_returns_tab_name(self):
        """render_excel_tabs on cold-start data returns a non-empty tab list."""
        import openpyxl
        data = _run(vulns_rows=[])
        mod  = NewVsRemediatedModule()
        cfg  = _config()
        wb   = openpyxl.Workbook()
        tabs = mod.render_excel_tabs(data, wb, cfg)
        assert len(tabs) > 0

    def test_render_email_panel_on_cold_start_does_not_crash(self):
        """render_email_panel on cold-start data returns valid HTML."""
        data = _run(vulns_rows=[])
        mod  = NewVsRemediatedModule()
        cfg  = _config()
        html = mod.render_email_panel(data, cfg)
        assert isinstance(html, str)
        assert "NaN" not in html

    def test_render_analyst_tabs_on_cold_start_returns_empty(self):
        """render_analyst_tabs on cold-start returns []."""
        data = _run(vulns_rows=[])
        mod  = NewVsRemediatedModule()
        cfg  = _config()
        assert mod.render_analyst_tabs(data, cfg) == []

    def test_render_rag_strip_on_cold_start_returns_no_data(self):
        """render_rag_strip_entry on cold-start returns a valid no_data dict."""
        data = _run(vulns_rows=[])
        mod  = NewVsRemediatedModule()
        cfg  = _config()
        strip = mod.render_rag_strip_entry(data, cfg)
        assert strip.get("rag_label") == "No Data"

    def test_zero_owner_data_does_not_crash(self):
        """
        vulns_df with findings but empty assets_df → Unassigned owner,
        no crash (QUAL-03 — filtered-to-zero Owner group).
        """
        snapshots = [
            _make_snapshot("2026-05", fixed_findings_count=1),
            _make_snapshot("2026-06", fixed_findings_count=1),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 6)}],
            snapshots=snapshots,
            insufficient_data=False,
            asset_rows=[],  # empty assets
        )
        assert data.error is None


# ===========================================================================
# 10. RAG STRIP LOGIC
# ===========================================================================

class TestRagStrip:
    def _run_with_fixed(self, inflow: int, outflow: int) -> ModuleData:
        snapshots = [
            _make_snapshot("2026-05", fixed_findings_count=1),
            _make_snapshot("2026-06", fixed_findings_count=outflow),
        ]
        vulns = [
            {"state": "open", "first_found": _ts(2026, 6)}
            for _ in range(inflow)
        ]
        return _run(
            vulns_rows=vulns,
            snapshots=snapshots,
            insufficient_data=False,
        )

    def test_rag_green_when_net_delta_negative(self):
        """inflow < outflow → net_delta < 0 → green RAG."""
        data = self._run_with_fixed(inflow=3, outflow=5)
        assert data.error is None
        assert data.metrics.get("rag_status") == "green"

    def test_rag_yellow_when_net_delta_zero(self):
        """inflow == outflow → net_delta == 0 → yellow RAG."""
        data = self._run_with_fixed(inflow=5, outflow=5)
        assert data.error is None
        assert data.metrics.get("rag_status") == "yellow"

    def test_rag_red_when_net_delta_positive(self):
        """inflow > outflow → net_delta > 0 → red RAG."""
        data = self._run_with_fixed(inflow=7, outflow=3)
        assert data.error is None
        assert data.metrics.get("rag_status") == "red"

    def test_rag_no_data_when_all_outflow_cold(self):
        """All months with absent fixed_findings_count → no_data RAG."""
        snapshots = [
            {
                "month": "2026-05",
                "tag_filter": "all_assets",
                "generated_at": "2026-05-01T00:00:00Z",
                # no fixed_findings_count
            },
            {
                "month": "2026-06",
                "tag_filter": "all_assets",
                "generated_at": "2026-06-01T00:00:00Z",
                # no fixed_findings_count
            },
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 6)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metrics.get("rag_status") == "no_data"
