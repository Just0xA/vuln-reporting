"""Phase 6 plan 03 — board_summary chrome wiring tests.

Covers CHROME-INT-01 + CHROME-INT-02 — the privacy_label and scope_subtitle
kwargs on board_summary.run_report() and the resulting PdfChromeConfig that
gets passed into ReportComposer(pdf_chrome=...).

These tests intentionally stub fetchers and ReportComposer so they exercise
ONLY the kwarg-to-PdfChromeConfig wiring path (no Tenable calls, no PDF/Excel
rendering).
"""
from __future__ import annotations

import inspect
from unittest.mock import patch, MagicMock

import pandas as pd

import reports.board_summary as bs


def test_run_report_signature_has_new_kwargs():
    """CHROME-INT-02 — signature exposes both kwargs with documented defaults."""
    sig = inspect.signature(bs.run_report)
    assert sig.parameters["privacy_label"].default == "Confidential"
    assert sig.parameters["scope_subtitle"].default is None
    # YAML-driven cover-title override (parity with composed_report);
    # None means board_summary falls back to its slug default.
    assert sig.parameters["report_title"].default is None


def _invoke_and_capture_pdf_chrome(**run_kwargs):
    """Call run_report with mocked deps and return the PdfChromeConfig
    handed to ReportComposer."""
    captured: dict = {}

    class _Spy:
        def __init__(self, *args, **kwargs):
            captured["pdf_chrome"] = kwargs.get("pdf_chrome")

        def run_all(self):
            return []

        def run_full_pipeline(self, *a, **kw):
            return {
                "pdf_html":              "<html></html>",
                "excel_workbook":        MagicMock(save=MagicMock()),
                "analyst_workbook_path": None,
                "email_body_html":       "",
                "email_inline_images":   [],
                "email_kpis":            {},
                "errors":                [],
            }

    # Stub frames carry the columns _filter_assets_by_tag / the vulns &
    # fixed-vulns filtering branches read so the tag-filter path is
    # exercisable without raising. One dummy row is needed because pandas
    # drops columns when boolean-masking a zero-row DataFrame (the asset
    # tag filter path goes filtered_assets["asset_uuid"] which then
    # KeyError's on the empty column index).
    assets_df = pd.DataFrame({"asset_uuid": ["x"], "tags": [""]})
    vulns_df  = pd.DataFrame({"asset_uuid": ["x"]})
    fixed_df  = pd.DataFrame({"asset_uuid": ["x"]})

    with patch.object(bs, "ReportComposer", _Spy), \
         patch.object(bs, "fetch_all_vulnerabilities", return_value=vulns_df), \
         patch.object(bs, "fetch_all_assets",          return_value=assets_df), \
         patch.object(bs, "fetch_fixed_vulnerabilities", return_value=fixed_df), \
         patch.object(bs, "read_trend", return_value={"snapshots": [], "insufficient_data": True}), \
         patch.object(bs, "_render_pdf",               return_value=None):
        bs.run_report(tio=MagicMock(), run_id="t", **run_kwargs)

    return captured["pdf_chrome"]


def test_subtitle_defaults_to_all_assets_when_no_filter():
    """D-02 — value-only formatter returns 'All assets' when no tag filter set."""
    cfg = _invoke_and_capture_pdf_chrome(tag_category=None, tag_value=None)
    assert cfg.subtitle == "All assets"


def test_subtitle_is_value_only_when_filter_set():
    """D-02 — value-only formatter: 'Production', not 'Environment = Production'."""
    cfg = _invoke_and_capture_pdf_chrome(
        tag_category="Environment", tag_value="Production",
    )
    assert cfg.subtitle == "Production"


def test_explicit_scope_subtitle_overrides_fallback():
    """Explicit scope_subtitle kwarg wins over the tag-derived fallback."""
    cfg = _invoke_and_capture_pdf_chrome(
        tag_category="Environment", tag_value="Production",
        scope_subtitle="Custom Slice",
    )
    assert cfg.subtitle == "Custom Slice"


def test_privacy_label_defaults_to_confidential():
    """CHROME-INT-02 — omitted privacy_label defaults to 'Confidential'."""
    cfg = _invoke_and_capture_pdf_chrome()
    assert cfg.privacy_label == "Confidential"


def test_report_title_defaults_to_slug_default():
    """Omitted report_title falls back to the board_summary slug default,
    with the excluded variant's title suffix appended (quick-260813-ga2)."""
    cfg = _invoke_and_capture_pdf_chrome()
    assert cfg.title == bs._REPORT_TITLE + bs._VARIANT_EXCLUDED.title_suffix


def test_report_title_override_propagates_to_chrome_title():
    """YAML-driven report_title flows into PdfChromeConfig.title, with the
    variant suffix still appended (quick-260813-ga2)."""
    cfg = _invoke_and_capture_pdf_chrome(
        report_title="Executive Security Posture",
    )
    assert cfg.title == "Executive Security Posture" + bs._VARIANT_EXCLUDED.title_suffix


def test_privacy_label_override_propagates():
    """CHROME-INT-02 — explicit privacy_label reaches PdfChromeConfig verbatim."""
    cfg = _invoke_and_capture_pdf_chrome(privacy_label="Internal Only")
    assert cfg.privacy_label == "Internal Only"
