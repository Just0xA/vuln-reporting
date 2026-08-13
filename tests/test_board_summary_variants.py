"""
tests/test_board_summary_variants.py — quick-260813-ga2 board_summary
excluded / included risk-managed variant coverage.

Covers slug registration (run_all._VALID_REPORTS / _REPORT_MODULE_MAP /
_CHROME_AWARE_SLUGS / the schema reports enum), title-suffix composition,
per-variant module options, distinct PDF/Excel filenames, the
run_full_pipeline slug kwarg, owner-supplemental skip on the inclusive
variant, empty email panels on the inclusive variant, and the
_board_module_configs() no-state-leak property (T-ga2-04).

These tests reuse the _invoke_and_capture_pdf_chrome patching pattern from
tests/test_phase6_board_summary_chrome.py — no Tenable call, no WeasyPrint
render.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd
import yaml

import reports.board_summary as bs
import run_all


# ===========================================================================
# Slug registration
# ===========================================================================

class TestSlugRegistration:
    def test_slug_present_in_valid_reports(self):
        assert "board_summary_incl_risk_managed" in run_all._VALID_REPORTS

    def test_slug_present_in_report_module_map(self):
        assert (
            run_all._REPORT_MODULE_MAP["board_summary_incl_risk_managed"]
            == "reports.board_summary"
        )

    def test_slug_present_in_chrome_aware_slugs(self):
        assert "board_summary_incl_risk_managed" in run_all._CHROME_AWARE_SLUGS

    def test_slug_present_in_board_summary_slugs(self):
        assert run_all._BOARD_SUMMARY_SLUGS == frozenset({
            "board_summary", "board_summary_incl_risk_managed",
        })

    def test_slug_present_in_schema_enum(self):
        with open("delivery_config.schema.yaml") as f:
            schema = yaml.safe_load(f)
        enum = schema["definitions"]["group"]["properties"]["reports"]["items"]["enum"]
        assert "board_summary_incl_risk_managed" in enum

    def test_schema_enum_reconciled_with_valid_reports(self):
        """Nothing enforces this reconciliation today — this test is the
        enforcement (quick-260813-ga2)."""
        with open("delivery_config.schema.yaml") as f:
            schema = yaml.safe_load(f)
        enum = set(schema["definitions"]["group"]["properties"]["reports"]["items"]["enum"])
        assert enum == set(run_all._VALID_REPORTS), (
            enum ^ set(run_all._VALID_REPORTS)
        )


# ===========================================================================
# _board_module_configs() — factory shape + no state leak
# ===========================================================================

class TestBoardModuleConfigsFactory:
    def test_preserves_literal_five_module_order(self):
        configs = bs._board_module_configs(False)
        assert [c.module_id for c in configs] == [
            "scan_coverage_sla",
            "critical_remediation_sla",
            "high_risk_assets",
            "aged_vulns_assets",
            "accepted_recast",
        ]

    def test_consuming_modules_carry_the_option(self):
        for include_risk_managed in (False, True):
            configs = {c.module_id: c for c in bs._board_module_configs(include_risk_managed)}
            for module_id in ("critical_remediation_sla", "high_risk_assets", "aged_vulns_assets"):
                assert configs[module_id].options.get("include_risk_managed") == include_risk_managed

    def test_variant_invariant_modules_carry_no_option(self):
        for include_risk_managed in (False, True):
            configs = {c.module_id: c for c in bs._board_module_configs(include_risk_managed)}
            assert "include_risk_managed" not in configs["scan_coverage_sla"].options
            assert "include_risk_managed" not in configs["accepted_recast"].options

    def test_fresh_objects_do_not_leak_between_calls(self):
        """T-ga2-04 — mutating one call's ModuleConfig objects must not
        affect a subsequent call's fresh objects."""
        included = bs._board_module_configs(True)
        for cfg in included:
            cfg.options["poisoned"] = True

        excluded = bs._board_module_configs(False)
        for cfg in excluded:
            assert "poisoned" not in cfg.options


# ===========================================================================
# run_report() variant wiring — shared invocation harness
# ===========================================================================

def _invoke(**run_kwargs) -> dict:
    """Call run_report with mocked deps; return everything captured about
    the composer construction, run_full_pipeline call, owner-supplemental
    call, and the final result dict."""
    captured: dict = {}

    class _Spy:
        def __init__(self, *args, **kwargs):
            captured["module_configs"] = kwargs.get("module_configs")
            captured["pdf_chrome"]     = kwargs.get("pdf_chrome")

        def run_all(self):
            return []

        def run_full_pipeline(self, *a, **kw):
            captured["run_full_pipeline_kwargs"] = kw
            return {
                "pdf_html":              "<html></html>",
                "excel_workbook":        MagicMock(save=MagicMock()),
                "analyst_workbook_path": None,
                "email_body_html":       "<div>panel</div>",
                "email_inline_images":   [{"cid": "gauge_1"}],
                "email_kpis":            {},
                "errors":                [],
            }

    # Stub frames carry the columns _filter_assets_by_tag / the vulns &
    # fixed-vulns filtering branches read so the (unused-here) tag-filter
    # path never raises. One dummy row, matching test_phase6_board_summary_
    # chrome.py's fixture.
    assets_df = pd.DataFrame({"asset_uuid": ["x"], "tags": [""]})
    vulns_df  = pd.DataFrame({"asset_uuid": ["x"]})
    fixed_df  = pd.DataFrame({"asset_uuid": ["x"]})

    supp_mock = MagicMock(
        return_value={"supplemental_excel": None, "supplemental_csv": None}
    )

    with patch.object(bs, "ReportComposer", _Spy), \
         patch.object(bs, "fetch_all_vulnerabilities", return_value=vulns_df), \
         patch.object(bs, "fetch_all_assets",          return_value=assets_df), \
         patch.object(bs, "fetch_fixed_vulnerabilities", return_value=fixed_df), \
         patch.object(bs, "read_trend", return_value={"snapshots": [], "insufficient_data": True}), \
         patch.object(bs, "_render_pdf",               return_value=None), \
         patch("reports.owner_supplemental.write_owner_supplemental", supp_mock):
        captured["result"] = bs.run_report(tio=MagicMock(), run_id="t", **run_kwargs)

    captured["write_owner_supplemental_mock"] = supp_mock
    return captured


# ===========================================================================
# Title suffixes
# ===========================================================================

class TestTitleSuffixes:
    def test_excluded_variant_default_title(self):
        cfg = _invoke()["pdf_chrome"]
        assert cfg.title == bs._REPORT_TITLE + bs._VARIANT_EXCLUDED.title_suffix

    def test_included_variant_default_title(self):
        cfg = _invoke(include_risk_managed=True)["pdf_chrome"]
        assert cfg.title == bs._REPORT_TITLE + bs._VARIANT_INCLUDED.title_suffix

    def test_excluded_variant_composes_with_report_title_override(self):
        cfg = _invoke(report_title="Executive Security Posture")["pdf_chrome"]
        assert cfg.title == "Executive Security Posture" + bs._VARIANT_EXCLUDED.title_suffix

    def test_included_variant_composes_with_report_title_override(self):
        cfg = _invoke(
            report_title="Executive Security Posture", include_risk_managed=True,
        )["pdf_chrome"]
        assert cfg.title == "Executive Security Posture" + bs._VARIANT_INCLUDED.title_suffix

    def test_variant_titles_are_distinct(self):
        assert bs._VARIANT_EXCLUDED.title_suffix != bs._VARIANT_INCLUDED.title_suffix


# ===========================================================================
# Per-variant module options reaching the composer
# ===========================================================================

class TestModuleOptionsReachComposer:
    def test_excluded_variant_passes_false(self):
        module_configs = _invoke()["module_configs"]
        cfg = {c.module_id: c for c in module_configs}["critical_remediation_sla"]
        assert cfg.options["include_risk_managed"] is False

    def test_included_variant_passes_true(self):
        module_configs = _invoke(include_risk_managed=True)["module_configs"]
        cfg = {c.module_id: c for c in module_configs}["critical_remediation_sla"]
        assert cfg.options["include_risk_managed"] is True


# ===========================================================================
# Filenames + run_full_pipeline slug kwarg
# ===========================================================================

class TestFilenamesAndSlug:
    def test_filenames_differ_between_variants(self):
        assert bs._VARIANT_EXCLUDED.pdf_filename != bs._VARIANT_INCLUDED.pdf_filename
        assert bs._VARIANT_EXCLUDED.excel_filename != bs._VARIANT_INCLUDED.excel_filename

    def test_run_full_pipeline_receives_excluded_slug(self):
        kw = _invoke()["run_full_pipeline_kwargs"]
        assert kw["slug"] == "board_summary"

    def test_run_full_pipeline_receives_included_slug(self):
        kw = _invoke(include_risk_managed=True)["run_full_pipeline_kwargs"]
        assert kw["slug"] == "board_summary_incl_risk_managed"


# ===========================================================================
# Owner supplemental — skipped for the inclusive variant
# ===========================================================================

class TestOwnerSupplementalSkip:
    def test_not_called_for_inclusive_variant(self):
        captured = _invoke(include_risk_managed=True)
        assert captured["write_owner_supplemental_mock"].call_count == 0

    def test_called_once_for_excluded_variant(self):
        captured = _invoke()
        assert captured["write_owner_supplemental_mock"].call_count == 1


# ===========================================================================
# Email panels — empty for the inclusive variant
# ===========================================================================

class TestEmailPanels:
    def test_inclusive_variant_returns_empty_body_and_images(self):
        result = _invoke(include_risk_managed=True)["result"]
        assert result["email_body_html"] == ""
        assert result["email_inline_images"] == []

    def test_excluded_variant_returns_nonempty_body_with_cross_reference(self):
        result = _invoke()["result"]
        assert result["email_body_html"] != ""
        assert "Including Risk-Accepted" in result["email_body_html"]

    def test_excluded_variant_keeps_inline_images(self):
        result = _invoke()["result"]
        assert result["email_inline_images"] == [{"cid": "gauge_1"}]


# ===========================================================================
# No state leak across successive run_report() calls in one process
# ===========================================================================

class TestNoLeakAcrossRuns:
    def test_included_then_excluded_run_do_not_cross_contaminate(self):
        first  = _invoke(include_risk_managed=True)
        second = _invoke(include_risk_managed=False)

        first_cfg  = {c.module_id: c for c in first["module_configs"]}["critical_remediation_sla"]
        second_cfg = {c.module_id: c for c in second["module_configs"]}["critical_remediation_sla"]

        assert first_cfg.options["include_risk_managed"] is True
        assert second_cfg.options["include_risk_managed"] is False
