"""Phase 6 plan 02 — cover body redesign + scope subtitle formatter."""
from datetime import datetime, timezone

import pandas as pd

from run_all import _format_scope_subtitle


# ──────────────────────────────────────────────────────────────────────────
# Scope subtitle formatter (D-02)
# ──────────────────────────────────────────────────────────────────────────


def test_format_scope_subtitle_no_filter_returns_all_assets():
    assert _format_scope_subtitle(None, None) == "All assets"


def test_format_scope_subtitle_full_filter_returns_value_only():
    assert _format_scope_subtitle("Environment", "Production") == "Production"


def test_format_scope_subtitle_partial_filter_returns_all_assets():
    assert _format_scope_subtitle("Environment", None) == "All assets"
    assert _format_scope_subtitle(None, "Production") == "All assets"


# ──────────────────────────────────────────────────────────────────────────
# Trimmed _PDF_UNIFIED_COVER_TEMPLATE (CHROME-COV-01 / CHROME-COV-02)
# ──────────────────────────────────────────────────────────────────────────


def test_cover_template_removes_legacy_elements():
    """CHROME-COV-02 — cover body no longer carries title/divider/meta/Generated/Sections."""
    from reports.modules.composer import _PDF_UNIFIED_COVER_TEMPLATE as tmpl
    for needle in ("cover-title", "cover-divider", "cover-meta",
                   "Generated:", "Sections:"):
        assert needle not in tmpl, f"legacy element {needle!r} still in cover template"


def test_cover_template_preserves_rag_strip_marker():
    """CHROME-COV-01 + R1 — baseline extractor depends on this exact header text."""
    from reports.modules.composer import _PDF_UNIFIED_COVER_TEMPLATE as tmpl
    assert "Risk Status Summary" in tmpl
    assert "rag-strip" in tmpl


def test_built_cover_renders_scope_subtitle():
    """Rendered cover HTML contains the supplied scope subtitle verbatim
    and preserves the Risk Status Summary baseline marker."""
    from reports.modules.composer import ReportComposer

    composer = ReportComposer(
        vulns_df       = pd.DataFrame(),
        assets_df      = pd.DataFrame(),
        report_date    = datetime(2026, 5, 13, tzinfo=timezone.utc),
        module_configs = [],
    )
    # results=[] → no rag cells, but the wrapper + header marker + subtitle
    # interpolation are what we're asserting on.
    # Phase 6 plan 06-03 pruned title/generated_at_str/module_list_str —
    # only `subtitle` remains on _build_unified_cover_page.
    html = composer._build_unified_cover_page(
        [],
        subtitle = "Production",
    )
    assert "Production" in html
    assert "Risk Status Summary" in html
    # And the removed elements must NOT appear in rendered output either.
    for needle in ("cover-title", "cover-divider", "cover-meta",
                   "Generated:", "Sections:"):
        assert needle not in html, f"legacy element {needle!r} leaked into render"
