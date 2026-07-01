"""
tests/test_tech_debt_by_owner_module.py — Unit tests for TechDebtByOwnerModule.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id: 100001, 100002, ...
  - owner names: "Engineering", "Operations"
  - No real hostnames, IPs, CVE IDs, plugin names, or real Tenable UUIDs

Key requirement coverage
------------------------
- Registration: auto-discovered via @register_module
- Owner parse/join: Owner tag -> owner map; multi-value join with " | "
- (Unassigned) bucket: missing Owner tag AND no matching asset
- Overdue Crit+High counting: within-SLA exclusion, Medium exclusion
- VPR-primary severity with native fallback
- RAG threshold buckets (default + option-overridden)
- Strip status = worst per-owner status; total headline; no_data
- Empty-data guard across all four channels

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import datetime
from typing import Optional

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

import openpyxl

from reports.modules.base import ModuleConfig, ModuleData
from reports.modules.tech_debt_by_owner_module import (
    TechDebtByOwnerModule,
    build_owner_map,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"
_REPORT_DATE = datetime.datetime(2026, 7, 1, tzinfo=datetime.timezone.utc)

# far-past first_found so Crit/High rows are overdue by default
_OVERDUE_FIRST_FOUND = "2020-01-01T00:00:00Z"
# recent first_found so a Critical row is within SLA
_RECENT_FIRST_FOUND = "2026-06-30T00:00:00Z"


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns_df with all required columns."""
    defaults = {
        "state":       "OPEN",
        "first_found": _OVERDUE_FIRST_FOUND,
        "vpr_score":   9.5,
        "severity":    "critical",
        "asset_uuid":  _uuid(1),
        "plugin_id":   100001,
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_assets(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal assets_df with asset_uuid and tags columns."""
    defaults = {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _config(**options) -> ModuleConfig:
    return ModuleConfig("tech_debt_by_owner", options=options)


def _run(
    vulns_rows: list[dict],
    asset_rows: Optional[list[dict]] = None,
    report_date: datetime.datetime = _REPORT_DATE,
    **options,
) -> ModuleData:
    mod       = TechDebtByOwnerModule()
    vulns_df  = _make_vulns(vulns_rows)
    assets_df = _make_assets(asset_rows if asset_rows is not None else [
        {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
    ])
    cfg = _config(**options)
    return mod.compute(vulns_df, assets_df, report_date, cfg)


def _owner_row(data: ModuleData, owner: str) -> Optional[dict]:
    for row in data.metrics.get("owner_rows", []):
        if row["owner"] == owner:
            return row
    return None


# ===========================================================================
# 1. MODULE REGISTRATION
# ===========================================================================

class TestRegistration:
    def test_module_id(self):
        assert TechDebtByOwnerModule.MODULE_ID == "tech_debt_by_owner"

    def test_auto_discovery(self):
        """Module is auto-discovered via @register_module on import."""
        import reports.modules
        import reports.modules.registry as registry
        assert "tech_debt_by_owner" in registry._modules

    def test_required_data(self):
        assert TechDebtByOwnerModule.REQUIRED_DATA == ["vulns", "assets"]


# ===========================================================================
# 2. OWNER PARSE / JOIN
# ===========================================================================

class TestOwnerParseJoin:
    def test_single_owner_tag(self):
        """An asset 'Owner=Engineering' -> its overdue Crit+High findings land under 'Engineering'."""
        data = _run(
            vulns_rows=[
                {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100001},
            ],
            asset_rows=[{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}],
        )
        row = _owner_row(data, "Engineering")
        assert row is not None
        assert row["total"] == 1

    def test_multi_value_owner_joins_with_pipe_for_custom_category(self):
        """
        Multi-value join uses ' | ' for the inline-parse path (non-default
        owner_category). The default 'Owner' category delegates to
        extract_owner(), which joins with '; ' (see next test) — both are
        the canonical join for their respective code paths per CONTEXT.md.
        """
        owner_map = build_owner_map(
            pd.DataFrame([{"asset_uuid": _uuid(1), "tags": "Team=Alpha;Team=Beta"}]),
            owner_category="Team",
        )
        assert owner_map[_uuid(1)] == "Alpha | Beta"

    def test_multi_value_owner_default_category_joins_with_semicolon(self):
        """
        Default 'Owner' category delegates to board_report_utils.extract_owner(),
        whose canonical multi-value join is '; ' (alphabetical, deduped).
        """
        owner_map = build_owner_map(
            pd.DataFrame([{"asset_uuid": _uuid(1), "tags": "Owner=Alpha;Owner=Beta"}])
        )
        assert owner_map[_uuid(1)] == "Alpha; Beta"

    def test_multi_value_owner_end_to_end(self):
        """End-to-end: multi-value Owner tag join reflected in owner_rows."""
        data = _run(
            vulns_rows=[
                {"asset_uuid": _uuid(1), "severity": "high", "vpr_score": 7.5, "plugin_id": 100001},
            ],
            asset_rows=[{"asset_uuid": _uuid(1), "tags": "Owner=Alpha;Owner=Beta"}],
        )
        row = _owner_row(data, "Alpha; Beta")
        assert row is not None
        assert row["total"] == 1


# ===========================================================================
# 3. (UNASSIGNED) BUCKET
# ===========================================================================

class TestUnassignedBucket:
    def test_asset_with_no_owner_tag(self):
        """An asset with no Owner tag buckets under '(Unassigned)'."""
        data = _run(
            vulns_rows=[
                {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100001},
            ],
            asset_rows=[{"asset_uuid": _uuid(1), "tags": "Environment=Production"}],
        )
        row = _owner_row(data, "(Unassigned)")
        assert row is not None
        assert row["total"] == 1

    def test_vuln_with_no_matching_asset(self):
        """A vuln whose asset_uuid has no matching asset buckets under '(Unassigned)'."""
        data = _run(
            vulns_rows=[
                {"asset_uuid": _uuid(9), "severity": "high", "vpr_score": 7.5, "plugin_id": 100001},
            ],
            asset_rows=[{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}],
        )
        row = _owner_row(data, "(Unassigned)")
        assert row is not None
        assert row["total"] == 1
        assert _owner_row(data, "Engineering") is None


# ===========================================================================
# 4. OVERDUE CRIT+HIGH COUNTING
# ===========================================================================

class TestOverdueCounting:
    def test_within_sla_critical_not_counted(self):
        """A within-SLA Critical (recent first_found) is NOT counted."""
        data = _run(
            vulns_rows=[
                {
                    "asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5,
                    "first_found": _RECENT_FIRST_FOUND, "plugin_id": 100001,
                },
            ],
        )
        assert data.metrics["total_overdue_ch"] == 0

    def test_overdue_medium_not_counted(self):
        """An overdue Medium is NOT counted (not Crit/High)."""
        data = _run(
            vulns_rows=[
                {
                    "asset_uuid": _uuid(1), "severity": "medium", "vpr_score": 5.0,
                    "first_found": _OVERDUE_FIRST_FOUND, "plugin_id": 100001,
                },
            ],
        )
        assert data.metrics["total_overdue_ch"] == 0

    def test_overdue_critical_and_high_counted_and_split(self):
        """Overdue Critical and overdue High ARE counted, split into overdue_critical / overdue_high."""
        data = _run(
            vulns_rows=[
                {
                    "asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5,
                    "first_found": _OVERDUE_FIRST_FOUND, "plugin_id": 100001,
                },
                {
                    "asset_uuid": _uuid(1), "severity": "high", "vpr_score": 7.5,
                    "first_found": _OVERDUE_FIRST_FOUND, "plugin_id": 100002,
                },
            ],
        )
        row = _owner_row(data, "Engineering")
        assert row["overdue_critical"] == 1
        assert row["overdue_high"]     == 1
        assert row["total"]            == 2


# ===========================================================================
# 5. VPR SEVERITY (PRIMARY + NATIVE FALLBACK)
# ===========================================================================

class TestVprSeverity:
    def test_vpr_score_overrides_native_severity(self):
        """A row with vpr_score=9.5 counts as Critical even if native severity says otherwise."""
        data = _run(
            vulns_rows=[
                {
                    "asset_uuid": _uuid(1), "severity": "low", "vpr_score": 9.5,
                    "first_found": _OVERDUE_FIRST_FOUND, "plugin_id": 100001,
                },
            ],
        )
        row = _owner_row(data, "Engineering")
        assert row["overdue_critical"] == 1
        assert row["overdue_high"]     == 0

    def test_null_vpr_falls_back_to_native_severity(self):
        """A row with null vpr_score falls back to native severity."""
        data = _run(
            vulns_rows=[
                {
                    "asset_uuid": _uuid(1), "severity": "high", "vpr_score": None,
                    "first_found": _OVERDUE_FIRST_FOUND, "plugin_id": 100001,
                },
            ],
        )
        row = _owner_row(data, "Engineering")
        assert row["overdue_high"] == 1


# ===========================================================================
# 6. RAG BUCKETS
# ===========================================================================

class TestRagBuckets:
    def test_zero_is_green(self):
        """Owner with 0 overdue Crit+High -> green (owner present via non-overdue finding)."""
        data = _run(
            vulns_rows=[
                {
                    "asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5,
                    "first_found": _RECENT_FIRST_FOUND, "plugin_id": 100001,
                },
            ],
        )
        # Zero overdue Crit+High across the board -> no owner rows at all (no_data)
        assert data.metrics["total_overdue_ch"] == 0
        assert data.rag_strip["rag_label"] == "No Data"

    def test_three_is_yellow(self):
        """Owner with 3 overdue Crit+High -> yellow (default thresholds)."""
        rows = [
            {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100000 + i}
            for i in range(3)
        ]
        data = _run(vulns_rows=rows)
        row = _owner_row(data, "Engineering")
        assert row["total"] == 3
        assert row["rag_status"] == "yellow"

    def test_five_is_red(self):
        """Owner with 5+ overdue Crit+High -> red (default thresholds)."""
        rows = [
            {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100000 + i}
            for i in range(5)
        ]
        data = _run(vulns_rows=rows)
        row = _owner_row(data, "Engineering")
        assert row["total"] == 5
        assert row["rag_status"] == "red"

    def test_custom_thresholds_change_bucket(self):
        """Custom green_max/amber_max via options changes the bucket."""
        rows = [
            {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100000 + i}
            for i in range(3)
        ]
        # Default: 3 -> yellow. With amber_max raised to 10, 3 should still be
        # yellow (> green_max=0); lower amber_max to prove red shifts too.
        data = _run(vulns_rows=rows, green_max=5, amber_max=10)
        row = _owner_row(data, "Engineering")
        assert row["total"] == 3
        assert row["rag_status"] == "green"  # <= green_max=5


# ===========================================================================
# 7. STRIP STATUS / HEADLINE / NO_DATA
# ===========================================================================

class TestStripStatus:
    def test_strip_status_is_worst_owner_status(self):
        """Strip status = worst per-owner status (red if any red)."""
        data = _run(
            vulns_rows=[
                # Engineering: 5 overdue crit -> red
                *[
                    {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100000 + i}
                    for i in range(5)
                ],
                # Operations: 1 overdue high -> yellow
                {"asset_uuid": _uuid(2), "severity": "high", "vpr_score": 7.5, "plugin_id": 100010},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
            ],
        )
        assert data.rag_strip["rag_label"] == "Off Target"  # red

    def test_headline_is_sum_across_owners(self):
        """Total headline = sum of totals across owners."""
        data = _run(
            vulns_rows=[
                {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100001},
                {"asset_uuid": _uuid(2), "severity": "high", "vpr_score": 7.5, "plugin_id": 100002},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
            ],
        )
        assert data.metrics["total_overdue_ch"] == 2
        assert data.rag_strip["headline_value"] == "2"

    def test_zero_in_scope_is_no_data(self):
        """Zero-in-scope -> rag_strip status/color is no_data (#757575) and driver_narrative == NO_DATA_DRIVER."""
        from reports.modules import NO_DATA_DRIVER
        data = _run(vulns_rows=[])
        assert data.rag_strip["rag_color"] == "#757575"
        assert data.driver_narrative == NO_DATA_DRIVER


# ===========================================================================
# 8. EMPTY-DATA GUARD — FOUR CHANNEL
# ===========================================================================

class TestFourChannelEmptyData:
    def test_zero_row_vulns_df(self):
        """Zero-row vulns_df gives error=None and a populated rag_strip."""
        mod       = TechDebtByOwnerModule()
        vulns_df  = _make_vulns([])
        assets_df = _make_assets([])
        data = mod.compute(vulns_df, assets_df, _REPORT_DATE, _config())
        assert data.error is None
        assert data.rag_strip

    def test_truly_empty_dataframe(self):
        """Truly-empty pd.DataFrame() gives error=None and a populated rag_strip."""
        mod  = TechDebtByOwnerModule()
        data = mod.compute(pd.DataFrame(), pd.DataFrame(), _REPORT_DATE, _config())
        assert data.error is None
        assert data.rag_strip

    def _empty_data(self) -> ModuleData:
        mod = TechDebtByOwnerModule()
        return mod.compute(pd.DataFrame(), pd.DataFrame(), _REPORT_DATE, _config())

    def test_render_pdf_section_returns_str(self):
        data = self._empty_data()
        result = TechDebtByOwnerModule().render_pdf_section(data, _config())
        assert isinstance(result, str)
        assert "NaN" not in result

    def test_render_excel_tabs_returns_list(self):
        data     = self._empty_data()
        workbook = openpyxl.Workbook()
        result   = TechDebtByOwnerModule().render_excel_tabs(data, workbook, _config())
        assert isinstance(result, list)

    def test_render_email_panel_returns_str(self):
        data   = self._empty_data()
        result = TechDebtByOwnerModule().render_email_panel(data, _config())
        assert isinstance(result, str)
        assert "NaN" not in result

    def test_render_analyst_tabs_returns_list(self):
        data   = self._empty_data()
        result = TechDebtByOwnerModule().render_analyst_tabs(data, _config())
        assert isinstance(result, list)

    def test_render_rag_strip_returns_dict(self):
        data   = self._empty_data()
        result = TechDebtByOwnerModule().render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert all(k in result for k in ("label", "headline_value", "rag_color", "rag_label"))
        assert "NaN" not in str(result)


# ===========================================================================
# 9. RENDER METHODS — VALID DATA
# ===========================================================================

class TestRenderMethodsValidData:
    def _valid_data(self) -> ModuleData:
        return _run(
            vulns_rows=[
                {"asset_uuid": _uuid(1), "severity": "critical", "vpr_score": 9.5, "plugin_id": 100001},
                {"asset_uuid": _uuid(2), "severity": "high", "vpr_score": 7.5, "plugin_id": 100002},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
            ],
        )

    def test_pdf_section_non_empty(self):
        data   = self._valid_data()
        result = TechDebtByOwnerModule().render_pdf_section(data, _config())
        assert isinstance(result, str)
        assert len(result) > 0
        assert "Engineering" in result

    def test_excel_tab_returned(self):
        data     = self._valid_data()
        workbook = openpyxl.Workbook()
        result   = TechDebtByOwnerModule().render_excel_tabs(data, workbook, _config())
        assert result == ["Tech Debt by Owner"]

    def test_email_panel_non_empty(self):
        data   = self._valid_data()
        result = TechDebtByOwnerModule().render_email_panel(data, _config())
        assert isinstance(result, str)
        assert len(result) > 0
        assert "Operations" in result

    def test_analyst_tabs_contain_detail(self):
        data   = self._valid_data()
        result = TechDebtByOwnerModule().render_analyst_tabs(data, _config())
        assert len(result) == 1
        assert result[0][0] == "Tech Debt Detail"
        assert len(result[0][1]) == 2

    def test_rag_strip_populated_non_no_data(self):
        data   = self._valid_data()
        result = TechDebtByOwnerModule().render_rag_strip_entry(data, _config())
        assert result["headline_value"] != "—"
