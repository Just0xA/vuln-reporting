"""
tests/test_pdf_chrome.py — Layer-1 unit tests for the shared PDF chrome utility.

Fast string-assert tests on PdfChrome.build_css() / .build_header_html() /
.build_footer_runners() output. No WeasyPrint, no PDF rendering — those
assertions live in tests/test_pdf_chrome.py::test_real_render_chrome_2_pages
(plan 05-04 adds it to the same file).

Test surface (CONTEXT.md D-04 — Layer 1):
  1. build_css() suppresses cover page number via @page :first
  2. build_css() emits counter(page) / counter(pages) (Page N of M)
  3. build_css() interpolates cfg.header_bg into the header background
  4. build_css() interpolates cfg.privacy_label into the footer corner
  5. build_css() interpolates cfg.generated_at as 'YYYY-MM-DD HH:MM UTC'
  6. build_header_html() with logo_path=None returns title-only
  7. build_header_html() with a valid logo_path includes <img src="file://...">
  8. build_header_html() with a missing logo_path silently falls back
     (no exception, no log warning) — CHROME-CFG-03 acceptance
  9. build_footer_runners() returns '' in v1

Plus two PdfChromeConfig __post_init__ guard tests (defense-in-depth):
  10. naive datetime is rejected
  11. privacy_label containing " is rejected
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig


# Fixed UTC timestamp so the generated_at interpolation assertion is stable.
GEN = datetime(2026, 5, 13, 8, 52, tzinfo=timezone.utc)


def _cfg(**overrides) -> PdfChromeConfig:
    """Build a known-good PdfChromeConfig with per-test overrides."""
    base = dict(
        title         = "Vuln Report",
        subtitle      = "Production",
        generated_at  = GEN,
        header_bg     = "#1a2332",
        logo_path     = None,
        privacy_label = "Confidential",
    )
    base.update(overrides)
    return PdfChromeConfig(**base)


# ---------------------------------------------------------------------------
# build_css() — CSS string assertions
# ---------------------------------------------------------------------------

def test_css_suppresses_cover_page_number():
    """CHROME-FTR-03: cover page footer has no 'Page N of M'."""
    css = PdfChrome(_cfg()).build_css()
    assert "@page :first" in css
    # @page :first must override @bottom-center with an empty content
    # rule. The base @page block MUST come before @page :first (cascade
    # order) — assert by position.
    assert "@bottom-center" in css
    assert 'content: ""' in css
    assert css.index("@page :first") > css.index("@bottom-center")


def test_css_emits_page_n_of_m():
    """CHROME-FTR-02: non-cover pages get 'Page N of M' via counters."""
    css = PdfChrome(_cfg()).build_css()
    assert "counter(page)" in css
    assert "counter(pages)" in css


def test_css_interpolates_header_bg():
    """CHROME-CFG-01: header_bg flows into the background rule."""
    css = PdfChrome(_cfg(header_bg="#330033")).build_css()
    assert "background: #330033" in css


def test_css_interpolates_privacy_label():
    """CHROME-CFG-04: privacy_label flows into @bottom-left content."""
    css = PdfChrome(_cfg(privacy_label="Internal Only")).build_css()
    assert 'content: "Internal Only"' in css


def test_css_interpolates_generated_at_utc():
    """CHROME-FTR-01: generated_at is formatted 'YYYY-MM-DD HH:MM UTC'."""
    css = PdfChrome(_cfg()).build_css()
    assert "2026-05-13 08:52 UTC" in css


# ---------------------------------------------------------------------------
# build_header_html() — logo branches
# ---------------------------------------------------------------------------

def test_header_html_no_logo_is_title_only():
    """CHROME-HDR-01 logo-absent branch: no <img>, title visible."""
    html_out = PdfChrome(_cfg(logo_path=None)).build_header_html()
    assert "<img" not in html_out
    assert "Vuln Report" in html_out
    assert "chrome-header" in html_out


def test_header_html_with_valid_logo_includes_img(tmp_path: Path):
    """CHROME-HDR-01 logo-present branch: <img src='file://...'> + title."""
    logo = tmp_path / "logo.png"
    # PNG magic header bytes — content is irrelevant for HTML-string test.
    logo.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    html_out = PdfChrome(_cfg(logo_path=logo)).build_header_html()
    assert '<img src="file://' in html_out
    assert "logo.png" in html_out
    assert "Vuln Report" in html_out


def test_header_html_missing_logo_silent_fallback(tmp_path: Path, caplog):
    """CHROME-CFG-03: missing logo file → title-only, no exception, no warning."""
    nonexistent = tmp_path / "does-not-exist.png"
    assert not nonexistent.exists()
    with caplog.at_level("WARNING"):
        html_out = PdfChrome(_cfg(logo_path=nonexistent)).build_header_html()
    assert "<img" not in html_out
    assert "Vuln Report" in html_out
    # No log spam: filtered-to-zero recipient groups would otherwise drown
    # in identical warnings (this project hit that on 2026-05-04).
    assert caplog.records == []


# ---------------------------------------------------------------------------
# build_footer_runners() — empty-string contract in v1
# ---------------------------------------------------------------------------

def test_footer_runners_empty_in_v1():
    """Footer is CSS-only; the body-side helper returns ''."""
    assert PdfChrome(_cfg()).build_footer_runners() == ""


# ---------------------------------------------------------------------------
# PdfChromeConfig.__post_init__ — defense-in-depth guards
# ---------------------------------------------------------------------------

def test_config_rejects_naive_datetime():
    """generated_at MUST be tz-aware UTC — naive datetimes are rejected."""
    with pytest.raises(ValueError, match="timezone-aware"):
        PdfChromeConfig(
            title="T", subtitle="S",
            generated_at=datetime(2026, 5, 13, 8, 52),  # naive — no tzinfo
        )


def test_config_rejects_double_quote_in_privacy_label():
    """privacy_label MUST NOT contain " — would break CSS content string."""
    with pytest.raises(ValueError, match="double-quote"):
        PdfChromeConfig(
            title="T", subtitle="S", generated_at=GEN,
            privacy_label='Has a "quote" in it',
        )
