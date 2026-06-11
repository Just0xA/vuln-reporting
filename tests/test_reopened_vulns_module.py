"""
tests/test_reopened_vulns_module.py — Unit tests for ReopenedVulnsModule.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id:  100001, 100002, ...
  - owner names: "Engineering", "Operations", "Unassigned"
  - No real hostnames, IPs, CVE IDs, or plugin names

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import warnings

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.base import ModuleConfig, ModuleData
from reports.modules.reopened_vulns_module import ReopenedVulnsModule

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns_df with all required columns."""
    defaults = {
        "state":            "OPEN",
        "resurfaced_date":  None,
        "last_fixed":       None,
        "first_found":      "2026-01-01T00:00:00Z",
        "plugin_id":        100001,
        "asset_uuid":       _uuid(1),
        "severity":         "high",
        "severity_modification_type": "NONE",
        "recast_rule_uuid": "",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records)


def _make_assets(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal assets_df with asset_uuid and tags columns."""
    defaults = {"asset_uuid": _uuid(1), "tags": ""}
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records)


def _config(**options) -> ModuleConfig:
    return ModuleConfig("reopened_vulns", options=options)


def _run(vulns_rows, asset_rows=None, fixed_rows=None, **options) -> ModuleData:
    mod        = ReopenedVulnsModule()
    vulns_df   = _make_vulns(vulns_rows)
    assets_df  = _make_assets(asset_rows or [{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}])
    cfg        = _config(**options)
    kwargs: dict = {}
    if fixed_rows is not None:
        kwargs["fixed_vulns_df"] = _make_vulns(fixed_rows)
    import datetime
    report_date = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)
    return mod.compute(vulns_df, assets_df, report_date, cfg, **kwargs)


# ===========================================================================
# 1. MODULE REGISTRATION
# ===========================================================================

class TestRegistration:
    def test_module_id(self):
        assert ReopenedVulnsModule.MODULE_ID == "reopened_vulns"

    def test_display_name(self):
        assert ReopenedVulnsModule.DISPLAY_NAME == "Reopened Vulnerabilities"

    def test_auto_discovery(self):
        """Module is auto-discovered via @register_module on import."""
        import reports.modules  # triggers discover()
        import reports.modules.registry as registry
        assert "reopened_vulns" in registry._modules

    def test_required_data(self):
        assert "vulns" in ReopenedVulnsModule.REQUIRED_DATA
        assert "assets" in ReopenedVulnsModule.REQUIRED_DATA


# ===========================================================================
# 2. REOPENED FILTER
# ===========================================================================

class TestReopenedFilter:
    def test_counts_only_reopened_rows(self):
        """3 REOPENED + 2 OPEN + 1 FIXED → reopened_count == 3."""
        data = _run([
            {"state": "REOPENED", "plugin_id": 100001, "asset_uuid": _uuid(1)},
            {"state": "REOPENED", "plugin_id": 100002, "asset_uuid": _uuid(1)},
            {"state": "REOPENED", "plugin_id": 100003, "asset_uuid": _uuid(1)},
            {"state": "OPEN",     "plugin_id": 100004, "asset_uuid": _uuid(1)},
            {"state": "OPEN",     "plugin_id": 100005, "asset_uuid": _uuid(1)},
            {"state": "FIXED",    "plugin_id": 100006, "asset_uuid": _uuid(1)},
        ])
        assert data.metrics["reopened_count"] == 3
        assert data.error is None

    def test_filter_is_case_insensitive(self):
        """Lower-case 'reopened' state value is matched correctly."""
        data = _run([
            {"state": "reopened", "plugin_id": 100001},
            {"state": "Reopened", "plugin_id": 100002},
            {"state": "OPEN",     "plugin_id": 100003},
        ])
        assert data.metrics["reopened_count"] == 2

    def test_zero_reopened_is_valid_not_error(self):
        """Zero REOPENED rows → reopened_count==0, error None (not _empty_result error)."""
        data = _run([
            {"state": "OPEN",  "plugin_id": 100001},
            {"state": "FIXED", "plugin_id": 100002},
        ])
        assert data.metrics["reopened_count"] == 0
        assert data.error is None
        assert data.rag_strip  # rag_strip is populated (green on zero rate with fixed_vulns_df)


# ===========================================================================
# 3. REOPEN-LAG COMPUTATION
# ===========================================================================

class TestReopenLag:
    def test_lag_days_computed_when_both_dates_present(self):
        """reopen_lag_days == (resurfaced_date - last_fixed).days when both present."""
        data = _run([
            {
                "state":           "REOPENED",
                "plugin_id":       100001,
                "resurfaced_date": "2026-05-15T00:00:00Z",
                "last_fixed":      "2026-05-10T00:00:00Z",
            }
        ])
        assert data.error is None
        # Check analyst drill-down
        detail_df = data.analyst_rows[0][1]
        assert len(detail_df) == 1
        lag = detail_df.iloc[0]["reopen_lag_days"]
        assert lag == 5

    def test_lag_days_none_when_resurfaced_date_absent(self):
        """reopen_lag_days is NaN/None when resurfaced_date is absent."""
        data = _run([
            {
                "state":           "REOPENED",
                "plugin_id":       100001,
                "resurfaced_date": None,
                "last_fixed":      "2026-05-10T00:00:00Z",
            }
        ])
        assert data.error is None
        detail_df = data.analyst_rows[0][1]
        lag = detail_df.iloc[0]["reopen_lag_days"]
        assert pd.isna(lag)

    def test_lag_days_none_when_last_fixed_absent(self):
        """reopen_lag_days is NaN when last_fixed is absent."""
        data = _run([
            {
                "state":           "REOPENED",
                "plugin_id":       100001,
                "resurfaced_date": "2026-05-15T00:00:00Z",
                "last_fixed":      None,
            }
        ])
        assert data.error is None
        detail_df = data.analyst_rows[0][1]
        lag = detail_df.iloc[0]["reopen_lag_days"]
        assert pd.isna(lag)


# ===========================================================================
# 4. OWNER CUT
# ===========================================================================

class TestOwnerCut:
    def test_owner_mapped_from_assets(self):
        """asset_uuid→owner mapping via extract_owner."""
        data = _run(
            vulns_rows=[
                {"state": "REOPENED", "plugin_id": 100001, "asset_uuid": _uuid(1)},
                {"state": "REOPENED", "plugin_id": 100002, "asset_uuid": _uuid(2)},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
            ],
        )
        assert data.error is None
        counts = data.metrics["owner_counts"]
        assert counts.get("Engineering", 0) == 1
        assert counts.get("Operations", 0) == 1

    def test_unassigned_when_no_matching_asset(self):
        """Rows with no matching asset uuid → 'Unassigned' owner."""
        data = _run(
            vulns_rows=[
                {"state": "REOPENED", "plugin_id": 100001, "asset_uuid": _uuid(9)},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
            ],
        )
        assert data.error is None
        counts = data.metrics["owner_counts"]
        assert counts.get("Unassigned", 0) == 1

    def test_unassigned_when_no_owner_tag(self):
        """Asset with no Owner tag → 'Unassigned'."""
        data = _run(
            vulns_rows=[
                {"state": "REOPENED", "plugin_id": 100001, "asset_uuid": _uuid(1)},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Environment=Production"},
            ],
        )
        counts = data.metrics["owner_counts"]
        assert counts.get("Unassigned", 0) == 1


# ===========================================================================
# 5. REOPEN RATE — OPTIONAL FIXED_VULNS_DF
# ===========================================================================

class TestReopenRate:
    def test_rate_computed_when_fixed_vulns_df_present(self):
        """Rate = reopened / (reopened + fixed) when fixed_vulns_df provided."""
        data = _run(
            vulns_rows=[
                {"state": "REOPENED", "plugin_id": 100001},
                {"state": "REOPENED", "plugin_id": 100002},
            ],
            fixed_rows=[
                {"state": "FIXED", "plugin_id": 100003},
                {"state": "FIXED", "plugin_id": 100004},
                {"state": "FIXED", "plugin_id": 100005},
                {"state": "FIXED", "plugin_id": 100006},
                {"state": "FIXED", "plugin_id": 100007},
                {"state": "FIXED", "plugin_id": 100008},
                {"state": "FIXED", "plugin_id": 100009},
                {"state": "FIXED", "plugin_id": 100010},
            ],
        )
        assert data.error is None
        assert data.metrics["has_rate"] is True
        # 2 / (2 + 8) * 100 = 20.0
        assert data.metrics["reopen_rate"] == pytest.approx(20.0, abs=0.01)

    def test_rate_none_when_no_fixed_vulns_df(self):
        """reopen_rate is None and has_rate False when fixed_vulns_df absent."""
        data = _run([
            {"state": "REOPENED", "plugin_id": 100001},
        ])
        assert data.metrics["has_rate"] is False
        assert data.metrics["reopen_rate"] is None
        assert data.metadata["rate_disclosure"] != ""

    def test_rate_disclosure_in_metadata(self):
        """When rate absent, metadata['rate_disclosure'] is set to a non-empty string."""
        data = _run([{"state": "REOPENED", "plugin_id": 100001}])
        assert "rate_disclosure" in data.metadata
        assert len(data.metadata["rate_disclosure"]) > 0

    def test_rate_zero_when_no_reopened_but_fixed_present(self):
        """Zero REOPENED, fixed_vulns_df present → rate = 0.0, has_rate = True."""
        data = _run(
            vulns_rows=[{"state": "OPEN", "plugin_id": 100001}],
            fixed_rows=[{"state": "FIXED", "plugin_id": 100002}],
        )
        assert data.metrics["has_rate"] is True
        assert data.metrics["reopen_rate"] == pytest.approx(0.0)


# ===========================================================================
# 6. EMPTY-DATA GUARD (QUAL-03)
# ===========================================================================

class TestEmptyDataGuard:
    def test_empty_vulns_df_returns_empty_result(self):
        """Empty vulns_df → _empty_result with error set (QUAL-03)."""
        import datetime
        mod        = ReopenedVulnsModule()
        vulns_df   = pd.DataFrame()
        assets_df  = _make_assets([{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}])
        report_date = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)
        data = mod.compute(vulns_df, assets_df, report_date, _config())
        assert data.error is not None
        assert data.rag_strip  # gray cell still present

    def test_missing_state_column_returns_empty_result(self):
        """vulns_df without 'state' column → _empty_result."""
        import datetime
        mod        = ReopenedVulnsModule()
        vulns_df   = pd.DataFrame({"plugin_id": [100001]})
        assets_df  = _make_assets([{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}])
        report_date = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)
        data = mod.compute(vulns_df, assets_df, report_date, _config())
        assert data.error is not None

    def test_rag_strip_gray_on_empty_result(self):
        """_empty_result produces a gray RAG strip cell."""
        import datetime
        mod        = ReopenedVulnsModule()
        vulns_df   = pd.DataFrame()
        assets_df  = _make_assets([])
        report_date = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)
        data = mod.compute(vulns_df, assets_df, report_date, _config())
        assert data.rag_strip.get("rag_color") == "#757575"


# ===========================================================================
# 7. FOUR-CHANNEL RETURN TYPES ON ZERO / ERROR DATA
# ===========================================================================

class TestFourChannelReturnTypes:
    def _empty_module_data(self) -> ModuleData:
        """Return an _empty_result ModuleData for channel tests."""
        import datetime
        mod         = ReopenedVulnsModule()
        vulns_df    = pd.DataFrame()
        assets_df   = _make_assets([])
        report_date = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)
        return mod.compute(vulns_df, assets_df, report_date, _config())

    def test_render_pdf_section_returns_str(self):
        data = self._empty_module_data()
        result = ReopenedVulnsModule().render_pdf_section(data, _config())
        assert isinstance(result, str)

    def test_render_excel_tabs_returns_list(self):
        import openpyxl
        data     = self._empty_module_data()
        workbook = openpyxl.Workbook()
        result   = ReopenedVulnsModule().render_excel_tabs(data, workbook, _config())
        assert isinstance(result, list)

    def test_render_email_panel_returns_empty_string_on_error(self):
        data   = self._empty_module_data()
        result = ReopenedVulnsModule().render_email_panel(data, _config())
        assert result == ""

    def test_render_analyst_tabs_returns_empty_list_on_error(self):
        data   = self._empty_module_data()
        result = ReopenedVulnsModule().render_analyst_tabs(data, _config())
        assert result == []

    def test_render_rag_strip_returns_dict_with_gray_on_error(self):
        data   = self._empty_module_data()
        result = ReopenedVulnsModule().render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert result.get("rag_color") == "#757575"


# ===========================================================================
# 8. RENDER METHODS — VALID DATA
# ===========================================================================

class TestRenderMethodsValidData:
    def _valid_data(self) -> ModuleData:
        return _run(
            vulns_rows=[
                {
                    "state":           "REOPENED",
                    "plugin_id":       100001,
                    "asset_uuid":      _uuid(1),
                    "resurfaced_date": "2026-05-15T00:00:00Z",
                    "last_fixed":      "2026-05-10T00:00:00Z",
                },
                {
                    "state":           "REOPENED",
                    "plugin_id":       100002,
                    "asset_uuid":      _uuid(2),
                    "resurfaced_date": "2026-05-20T00:00:00Z",
                    "last_fixed":      "2026-05-18T00:00:00Z",
                },
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
            ],
            fixed_rows=[
                {"state": "FIXED", "plugin_id": 100003},
                {"state": "FIXED", "plugin_id": 100004},
                {"state": "FIXED", "plugin_id": 100005},
            ],
        )

    def test_render_email_panel_non_empty_when_data_valid(self):
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_email_panel(data, _config())
        assert result != ""
        assert self.DISPLAY_NAME in result or "Reopened" in result

    def test_render_email_panel_contains_display_name(self):
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_email_panel(data, _config())
        assert "Reopened Vulnerabilities" in result

    def test_render_pdf_section_returns_non_empty_str(self):
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_pdf_section(data, _config())
        assert isinstance(result, str)
        assert len(result) > 0

    def test_render_excel_tabs_returns_tab_name(self):
        import openpyxl
        data     = self._valid_data()
        workbook = openpyxl.Workbook()
        result   = ReopenedVulnsModule().render_excel_tabs(data, workbook, _config())
        assert result == ["Reopened Vulns"]

    def test_render_analyst_tabs_returns_data_analyst_rows(self):
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_analyst_tabs(data, _config())
        assert result == data.analyst_rows
        assert len(result) == 2  # ("Reopened Detail", df), ("By Owner", df)

    def test_analyst_detail_columns_only_allowed(self):
        """Analyst detail tab MUST have only allowed columns (QUAL-05)."""
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_analyst_tabs(data, _config())
        detail_df = result[0][1]
        allowed   = {"plugin_id", "resurfaced_date", "reopen_lag_days", "owner"}
        assert set(detail_df.columns).issubset(allowed), (
            f"Unexpected columns: {set(detail_df.columns) - allowed}"
        )

    def test_analyst_detail_no_asset_uuid_or_hostnames(self):
        """Analyst drill-down must not contain asset_uuid (QUAL-05)."""
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_analyst_tabs(data, _config())
        detail_df = result[0][1]
        assert "asset_uuid" not in detail_df.columns

    def test_render_rag_strip_returns_populated_dict(self):
        data   = self._valid_data()
        result = ReopenedVulnsModule().render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert "rag_color"  in result
        assert "rag_label"  in result
        assert "label"      in result
        assert "headline_value" in result

    DISPLAY_NAME = "Reopened Vulnerabilities"


# ===========================================================================
# 9. RAG STATUS THRESHOLDS
# ===========================================================================

class TestRagThresholds:
    def test_green_when_rate_below_green_threshold(self):
        """Rate below 5.0% → green status."""
        data = _run(
            vulns_rows=[{"state": "REOPENED", "plugin_id": 100001}],
            fixed_rows=[
                {"state": "FIXED", "plugin_id": 100002},
                {"state": "FIXED", "plugin_id": 100003},
                {"state": "FIXED", "plugin_id": 100004},
                {"state": "FIXED", "plugin_id": 100005},
                {"state": "FIXED", "plugin_id": 100006},
                {"state": "FIXED", "plugin_id": 100007},
                {"state": "FIXED", "plugin_id": 100008},
                {"state": "FIXED", "plugin_id": 100009},
                {"state": "FIXED", "plugin_id": 100010},
                {"state": "FIXED", "plugin_id": 100011},
                {"state": "FIXED", "plugin_id": 100012},
                {"state": "FIXED", "plugin_id": 100013},
                {"state": "FIXED", "plugin_id": 100014},
                {"state": "FIXED", "plugin_id": 100015},
                {"state": "FIXED", "plugin_id": 100016},
                {"state": "FIXED", "plugin_id": 100017},
                {"state": "FIXED", "plugin_id": 100018},
                {"state": "FIXED", "plugin_id": 100019},
                {"state": "FIXED", "plugin_id": 100020},
                {"state": "FIXED", "plugin_id": 100021},
            ],  # 1 reopened / 21 total = 4.76% < 5.0% → green
        )
        assert data.metrics["rag_status"] == "green"

    def test_red_when_rate_above_yellow_threshold(self):
        """Rate above 10.0% → red status."""
        data = _run(
            vulns_rows=[
                {"state": "REOPENED", "plugin_id": 100001},
                {"state": "REOPENED", "plugin_id": 100002},
            ],
            fixed_rows=[
                {"state": "FIXED", "plugin_id": 100003},
                {"state": "FIXED", "plugin_id": 100004},
                {"state": "FIXED", "plugin_id": 100005},
                {"state": "FIXED", "plugin_id": 100006},
                {"state": "FIXED", "plugin_id": 100007},
                {"state": "FIXED", "plugin_id": 100008},
                {"state": "FIXED", "plugin_id": 100009},
                {"state": "FIXED", "plugin_id": 100010},
            ],  # 2 reopened / 10 total = 20.0% > 10.0% → red
        )
        assert data.metrics["rag_status"] == "red"

    def test_custom_thresholds_respected(self):
        """green_rate_threshold / yellow_rate_threshold override via module_options."""
        data = _run(
            vulns_rows=[{"state": "REOPENED", "plugin_id": 100001}],
            fixed_rows=[
                {"state": "FIXED", "plugin_id": 100002},
                {"state": "FIXED", "plugin_id": 100003},
                {"state": "FIXED", "plugin_id": 100004},
            ],
            # 1/4 = 25% — with default 10% yellow threshold this would be red,
            # but with a raised yellow threshold of 30% it should be yellow.
            green_rate_threshold=10.0,
            yellow_rate_threshold=30.0,
        )
        assert data.metrics["rag_status"] == "yellow"

    def test_no_data_rag_when_rate_absent(self):
        """No fixed_vulns_df → rate is None → RAG status is 'no_data'."""
        data = _run([{"state": "REOPENED", "plugin_id": 100001}])
        assert data.metrics["rag_status"] == "no_data"
        assert data.rag_strip.get("rag_color") == "#757575"


# ===========================================================================
# 10. COW STRICT-MODE: NO CHAINED ASSIGNMENT WARNINGS
# ===========================================================================

class TestCoWStrictMode:
    def test_no_future_warning_on_normal_compute(self):
        """No FutureWarning/ChainedAssignmentError raised during compute()."""
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=FutureWarning)
            _run(
                vulns_rows=[
                    {
                        "state":           "REOPENED",
                        "plugin_id":       100001,
                        "asset_uuid":      _uuid(1),
                        "resurfaced_date": "2026-05-15T00:00:00Z",
                        "last_fixed":      "2026-05-10T00:00:00Z",
                    },
                    {"state": "OPEN",  "plugin_id": 100002},
                    {"state": "FIXED", "plugin_id": 100003},
                ],
                asset_rows=[
                    {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                ],
            )

    def test_no_future_warning_on_empty_input(self):
        """No FutureWarning/ChainedAssignmentError on empty vulns_df."""
        import datetime
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=FutureWarning)
            mod         = ReopenedVulnsModule()
            vulns_df    = pd.DataFrame()
            assets_df   = _make_assets([])
            report_date = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)
            mod.compute(vulns_df, assets_df, report_date, _config())
