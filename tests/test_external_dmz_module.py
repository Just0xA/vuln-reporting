"""
tests/test_external_dmz_module.py — Unit tests for ExternalDmzModule.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - ip_address: "203.0.113.x" (RFC 5737 TEST-NET-3 — globally non-routable in
    the real internet but classified by ipaddress.is_global as True, which is
    the relevant classification for gap-detection tests)
  - No real hostnames, real IPs, CVE IDs, or plugin names in committed fixtures

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import datetime
import warnings

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.base import ModuleConfig, ModuleData
from reports.modules.external_dmz_module import ExternalDmzModule

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"

_REPORT_DATE = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_assets(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal assets_df with required columns for external_scope()."""
    defaults = {
        "asset_uuid": _uuid(1),
        "tags":       "",
        "ipv4":       "",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records)


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns_df with all required columns."""
    defaults = {
        "asset_uuid":  _uuid(1),
        "severity":    "high",
        "plugin_id":   100001,
        "state":       "OPEN",
        "first_found": "2026-01-01T00:00:00Z",
        "severity_modification_type": "NONE",
        "recast_rule_uuid": "",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records)


def _config(**options) -> ModuleConfig:
    return ModuleConfig("external_dmz", options=options)


def _run(asset_rows, vuln_rows=None, **options) -> ModuleData:
    mod        = ExternalDmzModule()
    assets_df  = _make_assets(asset_rows)
    vulns_df   = _make_vulns(vuln_rows or [])
    cfg        = _config(**options)
    return mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg)


# ===========================================================================
# 1. MODULE REGISTRATION
# ===========================================================================

class TestModuleRegistration:
    def test_module_id(self):
        assert ExternalDmzModule.MODULE_ID == "external_dmz"

    def test_display_name(self):
        assert ExternalDmzModule.DISPLAY_NAME  # non-empty

    def test_registered_in_registry(self):
        import reports.modules  # triggers auto-discovery
        from reports.modules import registry
        assert "external_dmz" in registry._modules

    def test_not_in_trend_snapshots_frozenset(self):
        """Phase-14 D-03: external_dmz must NOT be in _MODULES_NEEDING_TREND_SNAPSHOTS."""
        import reports.composed_report as cr
        assert "external_dmz" not in cr._MODULES_NEEDING_TREND_SNAPSHOTS

    def test_no_trend_snapshots_kwarg_in_module(self):
        """Phase-14 D-03: compute() must not use trend_snapshots or cold_start."""
        import inspect
        from reports.modules.external_dmz_module import ExternalDmzModule
        # Check compute() method source specifically (not docstring of the module)
        src = inspect.getsource(ExternalDmzModule.compute)
        # Only the body matters — strip out the docstring to avoid false positives
        # from documentation mentions of kwarg names.
        lines = src.split("\n")
        # Skip lines that are part of the docstring (between triple-quote delimiters)
        in_docstring = False
        code_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if not in_docstring:
                code_lines.append(line)
        code_body = "\n".join(code_lines)
        assert "trend_snapshots" not in code_body, (
            "compute() must not access trend_snapshots (Phase-14 D-03)"
        )
        assert "cold_start" not in code_body, (
            "compute() must not have a cold_start branch (Phase-14 D-03)"
        )


# ===========================================================================
# 2. EXTERNAL SCOPE COUNTS — happy path
# ===========================================================================

class TestExternalScopeCounts:
    """Assets with Location=External/DMZ tags are in scope; others are not."""

    def test_external_tagged_assets_scoped(self):
        """Vulns on Location=External assets are counted; internal assets are not."""
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Location=External", "ipv4": "10.0.0.1"},
            {"asset_uuid": _uuid(2), "tags": "Location=External", "ipv4": "10.0.0.2"},
            {"asset_uuid": _uuid(3), "tags": "Owner=Engineering",  "ipv4": "10.0.0.3"},  # internal
        ]
        vuln_rows = [
            {"asset_uuid": _uuid(1), "severity": "critical"},
            {"asset_uuid": _uuid(2), "severity": "high"},
            {"asset_uuid": _uuid(3), "severity": "critical"},  # internal — excluded
        ]
        data = _run(asset_rows, vuln_rows)
        assert data.error is None
        assert data.metrics["ext_critical"] == 1
        assert data.metrics["ext_high"] == 1
        assert data.metrics["ext_medium"] == 0

    def test_dmz_tagged_assets_scoped(self):
        """Location=DMZ assets are in scope."""
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Location=DMZ", "ipv4": "192.168.1.1"},
        ]
        vuln_rows = [
            {"asset_uuid": _uuid(1), "severity": "medium"},
        ]
        data = _run(asset_rows, vuln_rows)
        assert data.error is None
        assert data.metrics["ext_medium"] == 1
        assert data.metrics["ext_critical"] == 0

    def test_counts_across_critical_high_medium(self):
        """Critical/High/Medium all counted; 'low' not in primary metrics."""
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Location=External", "ipv4": "10.0.0.1"},
        ]
        vuln_rows = [
            {"asset_uuid": _uuid(1), "severity": "critical"},
            {"asset_uuid": _uuid(1), "severity": "critical"},
            {"asset_uuid": _uuid(1), "severity": "high"},
            {"asset_uuid": _uuid(1), "severity": "medium"},
            {"asset_uuid": _uuid(1), "severity": "low"},
        ]
        data = _run(asset_rows, vuln_rows)
        assert data.metrics["ext_critical"] == 2
        assert data.metrics["ext_high"] == 1
        assert data.metrics["ext_medium"] == 1

    def test_internal_only_assets_excluded(self):
        """No external-tagged or public-IP assets → zero counts."""
        # These IPs are RFC 1918 (private) and have no Location=External tag
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Owner=Engineering", "ipv4": "10.0.0.1"},
            {"asset_uuid": _uuid(2), "tags": "Owner=Operations",  "ipv4": "192.168.1.1"},
        ]
        vuln_rows = [
            {"asset_uuid": _uuid(1), "severity": "critical"},
        ]
        data = _run(asset_rows, vuln_rows)
        # No external scope → should return gray no-data result, not error
        assert data.error is None
        assert data.summary_text == "No external-scope assets in scope."


# ===========================================================================
# 3. ZERO-EXTERNAL-ASSET GROUP — gray cell, not error
# ===========================================================================

class TestZeroExternalAssets:
    """Internal-only groups must render a gray 'no_data' cell, not an error."""

    def test_empty_scoped_df_error_is_none(self):
        """error field must be None when external_scope returns empty scoped_df."""
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Owner=Engineering", "ipv4": "10.0.0.1"},
        ]
        data = _run(asset_rows)
        assert data.error is None

    def test_empty_scoped_df_summary_text(self):
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Owner=Engineering", "ipv4": "10.0.0.1"},
        ]
        data = _run(asset_rows)
        assert data.summary_text == "No external-scope assets in scope."

    def test_empty_scoped_df_rag_strip_is_no_data(self):
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Owner=Engineering", "ipv4": "10.0.0.1"},
        ]
        data = _run(asset_rows)
        from reports.modules.rag_utils import STATUS_COLOR
        assert data.rag_strip.get("rag_color") == STATUS_COLOR["no_data"]

    def test_empty_assets_df_returns_no_data(self):
        """Completely empty assets_df → no_data result, no exception."""
        mod = ExternalDmzModule()
        data = mod.compute(
            pd.DataFrame(),
            pd.DataFrame(),
            _REPORT_DATE,
            _config(),
        )
        assert data.error is None
        assert data.summary_text == "No external-scope assets in scope."


# ===========================================================================
# 4. MISMATCH ANALYST TAB — schema lock
# ===========================================================================

class TestMismatchAnalystSchema:
    """
    analyst_rows[0] for "External Scope Mismatches" must have EXACTLY the
    locked columns: asset_uuid, ip_address, owner_tag, untagged_reason,
    finding_count — no plugin/CVE/per-severity columns (Pitfall 11 / D-11).

    Synthetic IPs: 1.2.3.x are globally-routable addresses with no real
    operator association; used here as placeholder test values only.
    Python's ipaddress.is_global returns True for them, making them suitable
    for triggering the public-IP-untagged gap-detection path.
    """

    def _gap_asset_rows(self) -> list[dict]:
        """Public-IP-but-untagged gap assets (D-05/D-08)."""
        return [
            {"asset_uuid": _uuid(1), "tags": "", "ipv4": "1.2.3.1"},
            {"asset_uuid": _uuid(2), "tags": "", "ipv4": "1.2.3.2"},
        ]

    def test_mismatch_tab_exact_columns(self):
        """Mismatch DataFrame must have exactly the locked schema columns."""
        data = _run(
            self._gap_asset_rows(),
            [
                {"asset_uuid": _uuid(1), "severity": "critical"},
                {"asset_uuid": _uuid(2), "severity": "high"},
            ],
        )
        mismatch_tab = next(
            (df for name, df in data.analyst_rows if name == "External Scope Mismatches"),
            None,
        )
        assert mismatch_tab is not None, "Expected 'External Scope Mismatches' tab"
        expected_cols = {"asset_uuid", "ip_address", "owner_tag", "untagged_reason", "finding_count"}
        assert set(mismatch_tab.columns) == expected_cols

    def test_mismatch_tab_no_plugin_cve_columns(self):
        """No plugin_id, cve, severity columns in mismatch tab (Pitfall 11)."""
        data = _run(
            self._gap_asset_rows(),
            [{"asset_uuid": _uuid(1), "severity": "critical"}],
        )
        mismatch_tab = next(
            (df for name, df in data.analyst_rows if name == "External Scope Mismatches"),
            None,
        )
        assert mismatch_tab is not None
        forbidden = {"plugin_id", "cve", "severity", "plugin_name"}
        assert not (forbidden & set(mismatch_tab.columns))

    def test_finding_count_is_aggregate(self):
        """finding_count is groupby size (aggregate) — not per-finding rows."""
        data = _run(
            self._gap_asset_rows(),
            [
                {"asset_uuid": _uuid(1), "severity": "critical"},
                {"asset_uuid": _uuid(1), "severity": "high"},   # 2 findings on uuid(1)
                {"asset_uuid": _uuid(2), "severity": "medium"},  # 1 finding on uuid(2)
            ],
        )
        mismatch_tab = next(
            (df for name, df in data.analyst_rows if name == "External Scope Mismatches"),
            None,
        )
        assert mismatch_tab is not None
        row1 = mismatch_tab[mismatch_tab["asset_uuid"] == _uuid(1)]
        row2 = mismatch_tab[mismatch_tab["asset_uuid"] == _uuid(2)]
        assert len(row1) == 1, "One row per asset (aggregate, not per-finding)"
        assert len(row2) == 1
        assert row1.iloc[0]["finding_count"] == 2
        assert row2.iloc[0]["finding_count"] == 1

    def test_zero_mismatches_tab_still_present(self):
        """When no gap assets, mismatch tab exists but is empty."""
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Location=External", "ipv4": "10.0.0.1"},
        ]
        data = _run(asset_rows, [{"asset_uuid": _uuid(1), "severity": "high"}])
        mismatch_tab = next(
            (df for name, df in data.analyst_rows if name == "External Scope Mismatches"),
            None,
        )
        assert mismatch_tab is not None
        assert len(mismatch_tab) == 0
        # Columns still present (schema lock even on zero rows)
        expected_cols = {"asset_uuid", "ip_address", "owner_tag", "untagged_reason", "finding_count"}
        assert set(mismatch_tab.columns) == expected_cols


# ===========================================================================
# 5. RAG STATUS — critical count thresholds
# ===========================================================================

class TestRagStatus:
    """RAG from external Critical count: green=0, yellow=1-5, red=>5."""

    def _ext_asset(self, uid: int = 1) -> dict:
        return {"asset_uuid": _uuid(uid), "tags": "Location=External", "ipv4": "10.0.0.1"}

    def test_zero_critical_is_green(self):
        data = _run([self._ext_asset()], [])
        assert data.metrics["rag_status"] == "green"

    def test_one_critical_is_yellow(self):
        data = _run(
            [self._ext_asset()],
            [{"asset_uuid": _uuid(1), "severity": "critical"}],
        )
        assert data.metrics["rag_status"] == "yellow"

    def test_five_critical_is_yellow(self):
        vuln_rows = [{"asset_uuid": _uuid(1), "severity": "critical"} for _ in range(5)]
        data = _run([self._ext_asset()], vuln_rows)
        assert data.metrics["rag_status"] == "yellow"

    def test_six_critical_is_red(self):
        vuln_rows = [{"asset_uuid": _uuid(1), "severity": "critical"} for _ in range(6)]
        data = _run([self._ext_asset()], vuln_rows)
        assert data.metrics["rag_status"] == "red"

    def test_rag_thresholds_overridable_via_options(self):
        """green_ext_crit_threshold / yellow_ext_crit_threshold options work."""
        # With green=2, yellow=4: 3 critical → yellow
        vuln_rows = [{"asset_uuid": _uuid(1), "severity": "critical"} for _ in range(3)]
        data = _run(
            [self._ext_asset()],
            vuln_rows,
            green_ext_crit_threshold=2,
            yellow_ext_crit_threshold=4,
        )
        assert data.metrics["rag_status"] == "yellow"


# ===========================================================================
# 6. EMPTY-DATA GUARD — all four channels (QUAL-03)
# ===========================================================================

class TestEmptyDataGuard:
    """All four render channels must handle zero-row / error ModuleData safely."""

    def _empty_data(self) -> ModuleData:
        mod = ExternalDmzModule()
        return mod.compute(
            pd.DataFrame(),
            pd.DataFrame(),
            _REPORT_DATE,
            _config(),
        )

    def test_render_pdf_section_no_raise(self):
        data = self._empty_data()
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            result = ExternalDmzModule().render_pdf_section(data, _config())
        assert isinstance(result, str)

    def test_render_excel_tabs_no_raise(self):
        import openpyxl
        data   = self._empty_data()
        wb     = openpyxl.Workbook()
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            tabs = ExternalDmzModule().render_excel_tabs(data, wb, _config())
        assert isinstance(tabs, list)

    def test_render_email_panel_no_raise(self):
        data = self._empty_data()
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            result = ExternalDmzModule().render_email_panel(data, _config())
        assert isinstance(result, str)

    def test_render_analyst_tabs_no_raise(self):
        data = self._empty_data()
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            result = ExternalDmzModule().render_analyst_tabs(data, _config())
        assert isinstance(result, list)

    def test_render_rag_strip_no_raise(self):
        data = self._empty_data()
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            result = ExternalDmzModule().render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert "rag_color" in result

    def test_error_result_four_channels_safe(self):
        """_empty_result()-shaped data (error set) must not crash any renderer."""
        mod = ExternalDmzModule()
        # Force an error result
        data = mod._empty_result("Synthetic test error.", _config())
        wb = __import__("openpyxl").Workbook()
        assert isinstance(mod.render_pdf_section(data, _config()), str)
        assert isinstance(mod.render_excel_tabs(data, wb, _config()), list)
        assert isinstance(mod.render_email_panel(data, _config()), str)
        assert isinstance(mod.render_analyst_tabs(data, _config()), list)
        result = mod.render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert "rag_color" in result


# ===========================================================================
# 7. COW STRICT MODE — no FutureWarning on full happy path
# ===========================================================================

class TestCowStrictMode:
    """No FutureWarning (chained assignment) emitted during compute()."""

    def test_no_future_warning_on_compute(self):
        asset_rows = [
            {"asset_uuid": _uuid(1), "tags": "Location=External", "ipv4": "10.0.0.1"},
            {"asset_uuid": _uuid(2), "tags": "",                   "ipv4": "1.2.3.2"},  # gap
            {"asset_uuid": _uuid(3), "tags": "Owner=Engineering",  "ipv4": "10.0.0.3"},
        ]
        vuln_rows = [
            {"asset_uuid": _uuid(1), "severity": "critical"},
            {"asset_uuid": _uuid(2), "severity": "high"},
        ]
        mod = ExternalDmzModule()
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            data = mod.compute(
                _make_vulns(vuln_rows),
                _make_assets(asset_rows),
                _REPORT_DATE,
                _config(),
            )
        assert data.error is None
