"""Phase 6 plan 01 — ReportComposer chrome wiring unit tests.

Covers both code paths of the optional pdf_chrome wiring:

- Chrome-on (pdf_chrome=PdfChromeConfig(...)) emits the body-level
  ``chrome-header`` div AND chrome CSS markers (``@page :first`` /
  ``position: running(chrome-header)``).
- Chrome-off (pdf_chrome=None) emits NEITHER marker but preserves
  the legacy ``_PDF_CSS`` ``@bottom-center`` page-number rule.
- Cascade order: chrome ``<style>`` block must come AFTER ``_PDF_CSS``
  so ``@page :first`` wins on page-1 page-number suppression
  (RESEARCH.md Q1).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from reports.modules.composer import ReportComposer
from reports.modules.pdf_chrome import PdfChromeConfig


def _make_cfg() -> PdfChromeConfig:
    return PdfChromeConfig(
        title="Test Report",
        subtitle="Production",
        generated_at=datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc),
        header_bg="#1a2332",
        logo_path=None,
        privacy_label="Confidential",
    )


def _make_composer(pdf_chrome: PdfChromeConfig | None) -> ReportComposer:
    return ReportComposer(
        vulns_df=pd.DataFrame(),
        assets_df=pd.DataFrame(),
        report_date=datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc),
        module_configs=[],
        pdf_chrome=pdf_chrome,
    )


def test_assemble_pdf_chrome_on_contains_header_and_chrome_css() -> None:
    composer = _make_composer(_make_cfg())
    html = composer.assemble_pdf(results=[])

    assert "chrome-header" in html, "header div must appear at body-top"
    assert (
        "position: running(chrome-header)" in html
        or "@page :first" in html
    ), "chrome CSS markers must appear in <head>"


def test_assemble_pdf_chrome_off_omits_chrome_markers() -> None:
    composer = _make_composer(None)
    html = composer.assemble_pdf(results=[])

    assert "chrome-header" not in html
    assert "running(chrome-header)" not in html
    # Legacy _PDF_CSS still present
    assert "@bottom-center" in html


def test_assemble_pdf_chrome_css_appended_after_pdf_css() -> None:
    """Cascade order: chrome <style> must come AFTER _PDF_CSS so
    @page :first cascades over the base @bottom-center page-number
    declaration (RESEARCH.md Q1)."""
    composer = _make_composer(_make_cfg())
    html = composer.assemble_pdf(results=[])

    pdf_css_idx    = html.find("@bottom-center")
    chrome_css_idx = html.find("@page :first")
    assert pdf_css_idx >= 0,    "_PDF_CSS @bottom-center marker missing"
    assert chrome_css_idx >= 0, "chrome @page :first marker missing"
    assert chrome_css_idx > pdf_css_idx, (
        "chrome CSS must be appended AFTER _PDF_CSS per RESEARCH.md Q1"
    )
