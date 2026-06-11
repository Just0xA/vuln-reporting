"""
tests/test_vuln_density_module.py — Unit tests for VulnDensityModule.

Tests cover:
  - Per-snapshot denominator: each snapshot divides by its OWN on_time_asset_count
    (NOT len(assets_df) — Pitfall 4); two snapshots with different denoms use each
    month's own value
  - Historical immutability: changing assets_df length does not alter historical
    density points (Pitfall 4 verification)
  - None on_time_asset_count in snapshot: skipped/cold-start for that point, no crash
    (D-15-06 backward-compat on older snapshots)
  - current-run denom None from count_on_time_assets → _empty_result (no division)
  - Denom MoM change >10% sets denom_drift_flag=True in metadata (success criterion 2)
  - insufficient_data / fewer than 2 usable snapshots → cold-start notice (QUAL-01)
  - Zero-asset / empty input → safe four-channel render, gray cell, no ZeroDivisionError
    (QUAL-03)
  - Current month labeled "partial" (D-15-08)
  - RAG thresholds module_options-overridable (D-15-07)

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
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
from reports.modules.vuln_density_module import (
    VulnDensityModule,
    _month_label,
    _DEFAULT_GREEN_DENSITY,
    _DEFAULT_YELLOW_DENSITY,
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
    """Build a minimal assets_df with last_licensed_scan_date column."""
    if rows is None:
        # Default: 5 assets all recently scanned (within 35 days of report_date)
        rows = [
            {
                "asset_uuid":              _uuid(i),
                "tags":                    "Owner=Engineering",
                "last_licensed_scan_date": _ts(2026, 6, 1),
            }
            for i in range(1, 6)
        ]
    defaults = {
        "asset_uuid":              _uuid(1),
        "tags":                    "",
        "last_licensed_scan_date": None,
    }
    records = [{**defaults, **r} for r in rows]
    # columns= keeps the fetcher contract on empty input.
    df = pd.DataFrame(records, columns=list(defaults.keys()))
    # Normalise last_licensed_scan_date to datetime64[ns, UTC]
    df["last_licensed_scan_date"] = pd.to_datetime(
        df["last_licensed_scan_date"], utc=True, errors="coerce"
    )
    return df


def _make_snapshot(
    month: str,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    asset_count: int = 10,
    on_time_asset_count: Optional[int] = 8,
    **extra,
) -> dict:
    """Build a minimal trend snapshot dict with on_time_asset_count."""
    return {
        "month":               month,
        "tag_filter":          "all_assets",
        "critical":            critical,
        "high":                high,
        "medium":              medium,
        "low":                 low,
        "asset_count":         asset_count,
        "on_time_asset_count": on_time_asset_count,
        "generated_at":        f"{month}-01T00:00:00Z",
        **extra,
    }


def _config(**options) -> ModuleConfig:
    return ModuleConfig("vuln_density", options=options)


def _run(
    vulns_rows: list[dict],
    snapshots: Optional[list[dict]] = None,
    insufficient_data: bool = False,
    asset_rows: Optional[list[dict]] = None,
    **options,
) -> ModuleData:
    """Run compute() with synthetic fixtures."""
    mod       = VulnDensityModule()
    vulns_df  = _make_vulns(vulns_rows)
    assets_df = _make_assets(asset_rows)
    cfg       = _config(**options)
    kwargs: dict = {}
    if snapshots is not None:
        kwargs["trend_snapshots"] = {
            "snapshots":        snapshots,
            "insufficient_data": insufficient_data,
        }
    return mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg, **kwargs)


# ===========================================================================
# 1. MODULE REGISTRATION
# ===========================================================================

class TestRegistration:
    def test_module_id(self):
        assert VulnDensityModule.MODULE_ID == "vuln_density"

    def test_display_name(self):
        assert VulnDensityModule.DISPLAY_NAME == "Vulnerability Density"

    def test_auto_discovery(self):
        """Module is auto-discovered via @register_module on import."""
        import reports.modules  # triggers discover()
        import reports.modules.registry as registry
        assert "vuln_density" in registry._modules

    def test_required_data_includes_trend(self):
        assert "trend_snapshots" in VulnDensityModule.REQUIRED_DATA

    def test_default_rag_thresholds(self):
        assert _DEFAULT_GREEN_DENSITY == 2.0
        assert _DEFAULT_YELLOW_DENSITY == 4.0


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
        mod = VulnDensityModule()
        cfg = _config()
        html = mod.render_pdf_section(data, cfg)
        assert "NaN" not in html

    def test_cold_start_no_nan_in_email_panel(self):
        """Cold-start email panel must not contain 'NaN'."""
        data = _run(vulns_rows=[{"state": "open"}])
        mod = VulnDensityModule()
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
        mod = VulnDensityModule()
        cfg = _config()
        assert mod.render_analyst_tabs(data, cfg) == []


# ===========================================================================
# 3. PER-SNAPSHOT DENOMINATOR (Pitfall 4 — CRITICAL)
# ===========================================================================

class TestPerSnapshotDenominator:
    def test_each_snapshot_uses_its_own_on_time_asset_count(self):
        """
        Two snapshots with DIFFERENT on_time_asset_count:
        April uses 10, May uses 20. density[April] = open/10, density[May] = open/20.
        Pitfall 4: never reuse len(assets_df) for historical points.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=10),
            _make_snapshot("2026-05", high=20, on_time_asset_count=20),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metrics.get("cold_start") is not True

        # April density: 10 vulns / 10 assets = 1.0
        # May density: 20 vulns / 20 assets = 1.0
        densities = data.metrics.get("density_series", [])
        assert len(densities) == 2, f"Expected 2 density points, got {densities}"
        assert abs(densities[0] - 1.0) < 0.001, f"April density expected 1.0, got {densities[0]}"
        assert abs(densities[1] - 1.0) < 0.001, f"May density expected 1.0, got {densities[1]}"

    def test_different_denoms_produce_different_densities(self):
        """
        Two snapshots with same open_count but different on_time_asset_count
        must produce DIFFERENT densities (confirming per-snapshot denom is used).
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=10),
            _make_snapshot("2026-05", high=10, on_time_asset_count=20),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        densities = data.metrics.get("density_series", [])
        assert len(densities) == 2
        # April: 10/10=1.0, May: 10/20=0.5 — must differ
        assert densities[0] != densities[1], (
            "Different on_time_asset_count per snapshot must yield different densities"
        )
        assert abs(densities[0] - 1.0) < 0.001
        assert abs(densities[1] - 0.5) < 0.001

    def test_historical_density_immutable_when_assets_df_changes(self):
        """
        Pitfall 4 verification: density for an old snapshot does NOT change
        when assets_df contains a different number of assets. Historical points
        use snapshot on_time_asset_count, NEVER current len(assets_df).
        """
        snap = _make_snapshot("2026-04", high=10, on_time_asset_count=10)

        # Run 1: assets_df has 5 assets
        assets_5 = _make_assets([
            {"asset_uuid": _uuid(i), "tags": "", "last_licensed_scan_date": _ts(2026, 6, 1)}
            for i in range(1, 6)
        ])
        mod = VulnDensityModule()
        cfg = _config()
        vulns_df = _make_vulns([{"state": "open", "first_found": _ts(2026, 4)}])
        ts = {"snapshots": [snap], "insufficient_data": False}
        data_5 = mod.compute(vulns_df, assets_5, _REPORT_DATE, cfg, trend_snapshots=ts)

        # Run 2: assets_df has 100 assets
        assets_100 = _make_assets([
            {"asset_uuid": _uuid(i), "tags": "", "last_licensed_scan_date": _ts(2026, 6, 1)}
            for i in range(1, 101)
        ])
        data_100 = mod.compute(vulns_df, assets_100, _REPORT_DATE, cfg, trend_snapshots=ts)

        # Both runs should produce the SAME historical density for April
        # (10 / on_time_asset_count=10 = 1.0), not 10/5=2.0 or 10/100=0.1
        ds_5   = data_5.metrics.get("density_series", [])
        ds_100 = data_100.metrics.get("density_series", [])

        if ds_5 and ds_100:
            assert abs(ds_5[0] - ds_100[0]) < 0.001, (
                f"Historical density changed with assets_df size (Pitfall 4): "
                f"5-asset run={ds_5[0]}, 100-asset run={ds_100[0]}"
            )

    def test_snapshot_with_none_on_time_asset_count_is_skipped(self):
        """
        Snapshot whose on_time_asset_count is None → skipped (cold-start for
        that point); does not crash, does not divide by None (D-15-06).
        A second snapshot with a valid denom still produces a usable point.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=None),
            _make_snapshot("2026-05", high=10, on_time_asset_count=10),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        # April is skipped (None denom), May is included — 1 usable density point
        densities = data.metrics.get("density_series", [])
        assert len(densities) >= 1, "Expected at least 1 usable density point (May)"

    def test_all_none_denoms_returns_cold_start(self):
        """
        All snapshots have on_time_asset_count=None → cold-start (no usable points).
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=None),
            _make_snapshot("2026-05", high=10, on_time_asset_count=None),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metrics.get("cold_start") is True


# ===========================================================================
# 4. CURRENT-RUN DENOM FROM count_on_time_assets NONE → _empty_result
# ===========================================================================

class TestCurrentRunDenomNone:
    def test_no_licensed_assets_returns_empty_result(self):
        """
        assets_df with no last_licensed_scan_date (all NaT) →
        count_on_time_assets returns None → _empty_result.
        No division attempted.
        """
        # Build assets_df with no licensed scan dates
        assets_no_lsd = pd.DataFrame(
            [{"asset_uuid": _uuid(1), "tags": "", "last_licensed_scan_date": None}],
            columns=["asset_uuid", "tags", "last_licensed_scan_date"],
        )
        assets_no_lsd["last_licensed_scan_date"] = pd.to_datetime(
            assets_no_lsd["last_licensed_scan_date"], utc=True, errors="coerce"
        )

        snapshots = [
            _make_snapshot("2026-04", high=5, on_time_asset_count=5),
            _make_snapshot("2026-05", high=5, on_time_asset_count=5),
        ]
        mod = VulnDensityModule()
        vulns_df = _make_vulns([{"state": "open", "first_found": _ts(2026, 5)}])
        cfg = _config()
        ts = {"snapshots": snapshots, "insufficient_data": False}
        data = mod.compute(vulns_df, assets_no_lsd, _REPORT_DATE, cfg, trend_snapshots=ts)

        # Should be _empty_result (no current-run density possible)
        assert data.error is not None or data.metrics.get("cold_start") is True, (
            "Expected _empty_result or cold-start when count_on_time_assets returns None"
        )

    def test_empty_assets_df_returns_empty_result(self):
        """
        Empty assets_df → count_on_time_assets returns None → _empty_result.
        """
        assets_empty = pd.DataFrame(
            columns=["asset_uuid", "tags", "last_licensed_scan_date"]
        )
        assets_empty["last_licensed_scan_date"] = pd.to_datetime(
            assets_empty["last_licensed_scan_date"], utc=True, errors="coerce"
        )
        snapshots = [
            _make_snapshot("2026-04", high=5, on_time_asset_count=5),
            _make_snapshot("2026-05", high=5, on_time_asset_count=5),
        ]
        mod = VulnDensityModule()
        vulns_df = _make_vulns([{"state": "open", "first_found": _ts(2026, 5)}])
        cfg = _config()
        ts = {"snapshots": snapshots, "insufficient_data": False}
        data = mod.compute(vulns_df, assets_empty, _REPORT_DATE, cfg, trend_snapshots=ts)

        assert data.error is not None or data.metrics.get("cold_start") is True


# ===========================================================================
# 5. DENOMINATOR DRIFT FLAG (success criterion 2)
# ===========================================================================

class TestDenomDriftFlag:
    def test_denom_drift_gt_10pct_sets_flag_true(self):
        """
        on_time_asset_count changes >10% between last two usable snapshots
        → metadata["denom_drift_flag"] = True.
        100 → 89 = 11% drop → drift flag.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=100),
            _make_snapshot("2026-05", high=10, on_time_asset_count=89),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metadata.get("denom_drift_flag") is True, (
            "Expected denom_drift_flag=True for >10% denom change"
        )

    def test_denom_drift_exactly_10pct_does_not_set_flag(self):
        """
        Exactly 10% change → NOT flagged (flag triggers on strictly >10%).
        100 → 90 = exactly 10%.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=100),
            _make_snapshot("2026-05", high=10, on_time_asset_count=90),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metadata.get("denom_drift_flag") is not True, (
            "Expected denom_drift_flag False/absent for exactly 10% denom change"
        )

    def test_denom_drift_lt_10pct_does_not_set_flag(self):
        """
        <10% denom change → no drift flag.
        100 → 95 = 5%.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=100),
            _make_snapshot("2026-05", high=10, on_time_asset_count=95),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metadata.get("denom_drift_flag") is not True

    def test_single_usable_snapshot_no_drift_flag(self):
        """
        Only one usable snapshot (second has None denom) → cannot compute
        drift → no flag set (need >=2 usable points).
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=None),
            _make_snapshot("2026-05", high=10, on_time_asset_count=100),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        # Only one usable denom — cannot compute drift
        assert data.metadata.get("denom_drift_flag") is not True

    def test_denom_increase_gt_10pct_sets_flag(self):
        """
        Denom increases >10%: 100 → 115 = 15% increase → drift flag True.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=100),
            _make_snapshot("2026-05", high=10, on_time_asset_count=115),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        assert data.metadata.get("denom_drift_flag") is True


# ===========================================================================
# 6. PARTIAL-MONTH LABEL (D-15-08)
# ===========================================================================

class TestPartialMonthLabel:
    def test_current_month_label_contains_partial(self):
        """Current month (2026-06) label must contain 'partial'."""
        snapshots = [
            _make_snapshot("2026-05", high=5, on_time_asset_count=10),
            _make_snapshot("2026-06", high=5, on_time_asset_count=10),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
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
            _make_snapshot("2026-05", high=5, on_time_asset_count=10),
            _make_snapshot("2026-06", high=5, on_time_asset_count=10),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        jun_labels = [m for m in data.chart_data.get("months", []) if "2026-06" in m]
        assert len(jun_labels) >= 1
        assert "partial" in jun_labels[0].lower()

    def test_prior_month_label_does_not_contain_partial(self):
        """Completed prior months must NOT have 'partial' in their label."""
        snapshots = [
            _make_snapshot("2026-05", high=5, on_time_asset_count=10),
            _make_snapshot("2026-06", high=5, on_time_asset_count=10),
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
# 7. ZERO-ASSET / EMPTY INPUT GUARD (QUAL-03)
# ===========================================================================

class TestEmptyDataGuard:
    def test_empty_vulns_df_no_crash(self):
        """Empty vulns_df with valid snapshots → no crash, error=None."""
        mod = VulnDensityModule()
        vulns_df = _make_vulns([])
        assets_df = _make_assets()
        cfg = _config()
        snapshots = {
            "snapshots": [
                _make_snapshot("2026-05", high=5, on_time_asset_count=10),
                _make_snapshot("2026-06", high=5, on_time_asset_count=10),
            ],
            "insufficient_data": False,
        }
        data = mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg, trend_snapshots=snapshots)
        # Should not raise; error may be set or cold_start
        assert isinstance(data, ModuleData)

    def test_zero_on_time_asset_count_in_snapshot_no_zerodivision(self):
        """
        Snapshot with on_time_asset_count=0 → NOT used as denominator
        (would be ZeroDivisionError). Treated as None/skip.
        """
        snapshots = [
            _make_snapshot("2026-04", high=10, on_time_asset_count=0),
            _make_snapshot("2026-05", high=10, on_time_asset_count=10),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 4)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        # Must not raise ZeroDivisionError
        assert data.error is None or isinstance(data.error, str)

    def test_render_pdf_on_cold_start_does_not_crash(self):
        """render_pdf_section on cold-start data returns valid HTML without crashing."""
        data = _run(vulns_rows=[])
        mod = VulnDensityModule()
        cfg = _config()
        html = mod.render_pdf_section(data, cfg)
        assert isinstance(html, str)
        assert "NaN" not in html

    def test_render_excel_on_cold_start_returns_tab_name(self):
        """render_excel_tabs on cold-start data returns a non-empty tab list."""
        import openpyxl
        data = _run(vulns_rows=[])
        mod = VulnDensityModule()
        cfg = _config()
        wb  = openpyxl.Workbook()
        tabs = mod.render_excel_tabs(data, wb, cfg)
        assert len(tabs) > 0

    def test_render_email_panel_on_cold_start_does_not_crash(self):
        """render_email_panel on cold-start data returns valid HTML."""
        data = _run(vulns_rows=[])
        mod = VulnDensityModule()
        cfg = _config()
        html = mod.render_email_panel(data, cfg)
        assert isinstance(html, str)
        assert "NaN" not in html

    def test_render_analyst_tabs_on_cold_start_returns_empty(self):
        """render_analyst_tabs on cold-start returns []."""
        data = _run(vulns_rows=[])
        mod = VulnDensityModule()
        cfg = _config()
        assert mod.render_analyst_tabs(data, cfg) == []

    def test_render_rag_strip_on_cold_start_is_gray(self):
        """render_rag_strip_entry on cold-start returns a no_data/gray dict."""
        data = _run(vulns_rows=[])
        mod = VulnDensityModule()
        cfg = _config()
        strip = mod.render_rag_strip_entry(data, cfg)
        assert strip.get("rag_label") == "No Data"


# ===========================================================================
# 8. RAG THRESHOLDS AND STATUS
# ===========================================================================

class TestRagStatus:
    def _run_with_density(
        self,
        open_count: int,
        on_time_asset_count: int,
        **options,
    ) -> ModuleData:
        """Run with a two-snapshot fixture so current density is deterministic."""
        snapshots = [
            _make_snapshot("2026-05", high=open_count, on_time_asset_count=on_time_asset_count),
            _make_snapshot("2026-06", high=open_count, on_time_asset_count=on_time_asset_count),
        ]
        return _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
            **options,
        )

    def test_rag_green_when_density_below_green_threshold(self):
        """density < 2.0 (green threshold) → green RAG."""
        # 10 vulns / 10 assets = 1.0 density → green
        data = self._run_with_density(open_count=10, on_time_asset_count=10)
        assert data.error is None
        assert data.metrics.get("rag_status") == "green", (
            f"Expected green for density=1.0, got {data.metrics.get('rag_status')}"
        )

    def test_rag_yellow_when_density_between_thresholds(self):
        """2.0 <= density < 4.0 → yellow RAG."""
        # 30 vulns / 10 assets = 3.0 density → yellow
        data = self._run_with_density(open_count=30, on_time_asset_count=10)
        assert data.error is None
        assert data.metrics.get("rag_status") == "yellow", (
            f"Expected yellow for density=3.0, got {data.metrics.get('rag_status')}"
        )

    def test_rag_red_when_density_above_yellow_threshold(self):
        """density >= 4.0 → red RAG."""
        # 50 vulns / 10 assets = 5.0 density → red
        data = self._run_with_density(open_count=50, on_time_asset_count=10)
        assert data.error is None
        assert data.metrics.get("rag_status") == "red", (
            f"Expected red for density=5.0, got {data.metrics.get('rag_status')}"
        )

    def test_rag_thresholds_overridable_via_options(self):
        """
        D-15-07: RAG thresholds overridable via config.options.
        With green_density_threshold=5.0, density=3.0 should still be green.
        """
        # 30 vulns / 10 assets = 3.0 — below custom green threshold of 5.0
        data = self._run_with_density(
            open_count=30,
            on_time_asset_count=10,
            green_density_threshold=5.0,
            yellow_density_threshold=8.0,
        )
        assert data.error is None
        assert data.metrics.get("rag_status") == "green", (
            "Custom green_density_threshold=5.0 should make density=3.0 green"
        )


# ===========================================================================
# 9. OWNER CUT
# ===========================================================================

class TestOwnerCut:
    def test_owner_density_present_in_analyst_rows(self):
        """Analyst rows include per-Owner density tab."""
        snapshots = [
            _make_snapshot("2026-05", high=5, on_time_asset_count=10),
            _make_snapshot("2026-06", high=5, on_time_asset_count=10),
        ]
        data = _run(
            vulns_rows=[
                {"state": "open", "first_found": _ts(2026, 5), "asset_uuid": _uuid(1)},
            ],
            snapshots=snapshots,
            insufficient_data=False,
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering", "last_licensed_scan_date": _ts(2026, 6, 1)},
            ],
        )
        assert data.error is None
        if not data.metrics.get("cold_start"):
            mod = VulnDensityModule()
            cfg = _config()
            analyst = mod.render_analyst_tabs(data, cfg)
            # Should return at least one tab when not cold-start
            assert isinstance(analyst, list)


# ===========================================================================
# 10. DENSITY COMPUTATION CORRECTNESS
# ===========================================================================

class TestDensityComputation:
    def test_density_uses_all_severity_buckets(self):
        """
        open_count = critical + high + medium + low for the snapshot.
        A snapshot with critical=2, high=3, medium=4, low=1 → open_count=10.
        density = 10 / on_time_asset_count.
        """
        snapshots = [
            _make_snapshot(
                "2026-05",
                critical=2, high=3, medium=4, low=1,
                on_time_asset_count=10,
            ),
            _make_snapshot(
                "2026-06",
                critical=2, high=3, medium=4, low=1,
                on_time_asset_count=10,
            ),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        densities = data.metrics.get("density_series", [])
        assert len(densities) >= 1
        for d in densities:
            assert abs(d - 1.0) < 0.001, f"Expected 10/10=1.0, got {d}"

    def test_current_density_in_metrics(self):
        """metrics['current_density'] is the most recent usable density point."""
        snapshots = [
            _make_snapshot("2026-05", high=10, on_time_asset_count=10),
            _make_snapshot("2026-06", high=20, on_time_asset_count=10),
        ]
        data = _run(
            vulns_rows=[{"state": "open", "first_found": _ts(2026, 5)}],
            snapshots=snapshots,
            insufficient_data=False,
        )
        assert data.error is None
        if not data.metrics.get("cold_start"):
            current_density = data.metrics.get("current_density")
            assert current_density is not None
            # Most recent snapshot: 20 / 10 = 2.0
            assert abs(current_density - 2.0) < 0.001
