# Phase 5 — PDF Chrome Foundation — Research

**Researched:** 2026-05-13
**Domain:** WeasyPrint CSS3 paged-media (running elements + margin boxes), `pypdf` text extraction
**Confidence:** HIGH (all four open questions resolved by locally rendered PDFs + maintainer responses on GitHub)

---

## Summary

- **`@page :first` works in WeasyPrint 65.1**, and margin-box rules cascade — `@page :first { @bottom-center { content: "" } }` overrides ONLY the bottom-center box; bottom-left and bottom-right cascade automatically from the base `@page` rule. **[VERIFIED locally]** Cover page-number suppression needs exactly two lines of CSS.
- **`pypdf` 6.x extracts WeasyPrint output deterministically per page**, including margin-box content (header band, footer corners). The output is plain text with newlines between flow-content and margin-box content — perfect for `assert "Page 1 of" not in pages[0]` style assertions. **[VERIFIED locally]**
- **`position: running()` with `<img>` inside works cleanly in 65.1** — vertical-align: middle on inline-block image + span pairs renders without margin-box layout quirks. The known bug ([Issue #2013](https://github.com/Kozea/WeasyPrint/issues/2013)) affects `<table>` inside running elements, NOT `<img>`. **[VERIFIED locally]**
- **Footer three-corner layout is simpler than CONTEXT.md suggested** — three sibling margin boxes (`@bottom-left`, `@bottom-center`, `@bottom-right`) with literal `content: "..."` strings work without overlap at A4 landscape 15mm/12mm/18mm/12mm margins. **No need for CSS custom properties, no need for additional `position: running()` elements** for the footer corners. The header still needs one `position: running()` element because it carries an `<img>`; the footer is pure margin-box `content:` strings.
- **No dependency bumps needed beyond adding `pypdf~=6.0`** (latest 6.11.0, pin to 6.x range). WeasyPrint stays at 65.1; the patterns we need have been stable since 51.

**Primary recommendation:** Implement exactly as CONTEXT.md D-01..D-04 specify. Use the verified CSS template in §3 below verbatim. For the footer corners pick the **literal-string approach** (cleanest CSS, no Python side); for the header use the **`position: running(chrome-header)` + `<img>` inside** approach.

---

## Resolved Open Questions

### Q1 — `@page :first` margin-box override / cascade behavior

**Short answer:** `@page :first` reliably overrides individual margin boxes; the others cascade from the base `@page` rule. No need to redeclare all margin boxes inside `@page :first`. **[VERIFIED locally on WeasyPrint 65.1]**

**Evidence:** Maintainer `grewn0uille` confirms in [WeasyPrint Issue #2088](https://github.com/Kozea/WeasyPrint/issues/2088) (2024-03-05) that `:first` is fully supported — the bug report there was user confusion between `:first` (page selector) and `:first-child` (descendant selector). Documentation says: *"All the features of this draft are available, including: the @page rule and the :left, :right, :first and :blank selectors"* ([WeasyPrint Going Further docs](https://doc.courtbouillon.org/weasyprint/stable/going_further.html)).

**Minimal reproducer (verified):**

```css
@page {
  size: A4 landscape;
  margin: 15mm 12mm 18mm 12mm;
  @bottom-left   { content: "Confidential";                                      font-size: 8pt; }
  @bottom-center { content: "Page " counter(page) " of " counter(pages);         font-size: 8pt; }
  @bottom-right  { content: "2026-05-13 08:52 UTC";                              font-size: 8pt; }
}
@page :first {
  @bottom-center { content: ""; }   /* cover: ONLY this corner; the other two cascade */
}
```

**Verified output (3-page test render):**

| Page | bottom-left | bottom-center | bottom-right |
|------|-------------|---------------|--------------|
| 1 (cover) | Confidential | *(empty)* | 2026-05-13 08:52 UTC |
| 2 | Confidential | Page 2 of 3 | 2026-05-13 08:52 UTC |
| 3 | Confidential | Page 3 of 3 | 2026-05-13 08:52 UTC |

`pypdf` text extraction for Page 1 returned `'Cover Page\nConfidential 2026-05-13 08:52 UTC'` — no "Page 1 of" present. CHROME-FTR-03 acceptance trivially testable.

### Q2 — Three-corner footer at A4 landscape (15/12/18/12 mm margins)

**Short answer:** Use three sibling margin boxes (`@bottom-left`, `@bottom-center`, `@bottom-right`) with literal `content: "..."` strings. No overlap. **Do NOT use CSS custom properties (`var(--privacy)` etc.)** — they work but add unnecessary indirection. **Do NOT use additional `position: running()` elements** for the footer — the literal-string pattern is simpler and equivalent.

**Recommendation:** **Literal `content:` strings in margin boxes** (Python f-string interpolation into the CSS at `PdfChrome.build_css()` call time). This means `build_footer_runners()` actually returns an **empty string** — there's no body-side running element for the footer; everything is in the CSS. The method exists for API symmetry with `build_header_html()` and to future-proof for cases where the footer eventually needs HTML markup.

**Evidence:** The existing composer already uses `content: "Page " counter(page) " of " counter(pages)` in `@bottom-center` at A4 landscape with these exact margins (composer.py lines 73–80). Three corners at A4 landscape (297mm × 210mm content; ~273mm × 177mm printable inside margins) have ~90mm per corner — vastly more than the ~50mm any single string needs. **[VERIFIED locally]**

**CSS (exact, ready to drop in):**

```css
@bottom-left   { content: "{privacy_label}";                            font-size: 8pt; color: #666; }
@bottom-center { content: "Page " counter(page) " of " counter(pages);  font-size: 8pt; color: #666; }
@bottom-right  { content: "{generated_at_str}";                         font-size: 8pt; color: #666; }
```

Where `{privacy_label}` and `{generated_at_str}` are Python f-string interpolations from `PdfChromeConfig` — text only, no HTML, no Python-side escaping concerns beyond escaping `"` in the strings (the design system can document "no double-quotes in privacy_label").

**Rejected: CSS custom properties.** `@bottom-left { content: var(--privacy-label); }` works in WeasyPrint, but requires a `:root { --privacy-label: "Confidential"; }` declaration to be useful and adds a second site to touch when changing values. Literal f-string interpolation is one fewer indirection layer.

**Rejected: additional `position: running()` elements per corner.** Equivalent behaviorally but doubles the body markup and the test surface (must now assert running-element CSS *and* margin-box-element-call CSS).

### Q3 — `pypdf` text-extraction stability for per-page assertions

**Short answer:** Yes, `pypdf` 6.x is reliable enough. Recommended pin: **`pypdf~=6.0`** (latest 6.11.0 as of 2026-05-13). No need for PyMuPDF or pdfplumber.

**Evidence:** **[VERIFIED locally]** — `pypdf.PdfReader().pages[i].extract_text()` against the WeasyPrint-rendered test PDF produces stable, deterministic text per page. Margin-box content (footer corners, header band running element) ALL appear in the page text, separated from body content by `\n`. Latest pypdf is 6.11.0 [per PyPI](https://pypi.org/project/pypdf/); the API used (`PdfReader(path).pages[i].extract_text()`) is documented in [pypdf extract-text docs](https://pypdf.readthedocs.io/en/stable/user/extract-text.html) and has been stable since 3.x.

**Verified extraction for cover page of the test render:**

```
'Cover Page\nVulnerability Report\nConfidential 2026-05-13 08:52 UTC'
```

Both required CHROME-FTR-03 assertions pass deterministically:

- `"Page 1 of" not in pages[0]` ✓
- `"Page 2 of 2" in pages[1]` ✓
- `"Confidential" in pages[0] and "Confidential" in pages[1]` ✓ (CHROME-FTR-01)

**Pin justification:** `~=6.0` allows 6.x bugfix updates but pins major version, matching the rest of `requirements.txt`'s conservative pinning style (exact pins for runtime deps). If the project prefers exact pins, use `pypdf==6.11.0`. Either works; recommend `~=6.0` since pypdf is dev/test-only and a 6.x bump is unlikely to break extraction order.

**Note on whitespace fidelity:** pypdf docs do warn "*The representation used within PDF files makes it very hard to guarantee correct whitespaces*" — but Phase 5's assertions are existence checks on substrings like `"Page 2 of"`, not exact-whitespace matches. The locally verified output has predictable single-space separators between margin-box content items.

### Q4 — `position: running()` with `<img>` content

**Short answer:** Works without issues in WeasyPrint 65.1 (the version pinned in `requirements.txt`). The known running-element bug ([Issue #2013](https://github.com/Kozea/WeasyPrint/issues/2013) — "Margin is not applied to running tables") affects `<table>` *inside* a running element, not `<img>`. **[VERIFIED locally]**

**Evidence:** [WeasyPrint Issue #967](https://github.com/Kozea/WeasyPrint/issues/967) is about running tables specifically. Issue #2013 explicitly says "*works with images and text, but not with tables*" — confirming images-inside-running is the supported path. The `position: running()` feature has shipped since WeasyPrint 51 ([PR #882](https://github.com/Kozea/WeasyPrint/pull/882)) and the image-inside path has been stable through 65.1.

**Verified pattern (locally rendered, header band on every page):**

```html
<style>
  @page { @top-left { content: element(chrome-header); } /* ... */ }
  .chrome-header { position: running(chrome-header);
                   background: #1a2332; color: #fff;
                   padding: 3mm 4mm; }
  .chrome-header img  { height: 8mm; vertical-align: middle; margin-right: 4mm; }
  .chrome-header span { vertical-align: middle; font-weight: bold; font-size: 11pt; }
</style>
<body>
  <div class="chrome-header">
    <img src="file:///D:/.../logo.png" alt="">
    <span>Vulnerability Report</span>
  </div>
  ...
</body>
```

**Caveats discovered:**

- **`vertical-align: middle` is required** on both `<img>` and adjacent `<span>` to align them in the inline-block flow — without it the title text baselines below the image.
- **`height: 8mm` on `<img>`** is necessary to constrain the image; otherwise it renders at native pixel dimensions (a 200px logo will explode the header band).
- **Use `inline-block`/inline flow, NOT flexbox** inside the margin box per memory `[[feedback_layout_fixes]]` (WeasyPrint flex bugs are real in this project). The verified pattern uses inline flow (default), which is the recommended path.
- **`file:///` URI** must be absolute and forward-slashed even on Windows (`pathlib.Path.as_uri()` produces this correctly).

---

## Implementation Sketch — `reports/modules/pdf_chrome.py`

Starter shape for the planner. Verified CSS/HTML, not yet tested as a full module — but every CSS construct used here was rendered locally in Q1, Q2, Q4 verifications.

### `build_css()` — full output

```python
def build_css(self) -> str:
    return f"""
    @page {{
      size: A4 landscape;
      margin: 15mm 12mm 18mm 12mm;
      @top-left {{
        content: element(chrome-header);
      }}
      @bottom-left {{
        content: "{self.cfg.privacy_label}";
        font-size: 8pt;
        color: #666;
      }}
      @bottom-center {{
        content: "Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #666;
      }}
      @bottom-right {{
        content: "{self.cfg.generated_at.strftime('%Y-%m-%d %H:%M UTC')}";
        font-size: 8pt;
        color: #666;
      }}
    }}
    @page :first {{
      @bottom-center {{ content: ""; }}
    }}
    .chrome-header {{
      position: running(chrome-header);
      background: {self.cfg.header_bg};
      color: #ffffff;
      padding: 3mm 4mm;
    }}
    .chrome-header img {{
      height: 8mm;
      vertical-align: middle;
      margin-right: 4mm;
    }}
    .chrome-header .chrome-title {{
      vertical-align: middle;
      font-weight: bold;
      font-size: 12pt;
    }}
    .chrome-header .chrome-subtitle {{
      vertical-align: middle;
      font-weight: normal;
      font-size: 9pt;
      color: #cccccc;
      margin-left: 5mm;
    }}
    """
```

**Composer integration note (Phase 6 — not this phase's work):** the existing `_PDF_CSS` block (composer.py lines 70–230) already contains an `@page` block and a `@bottom-center` page-number rule. Phase 6 replaces the composer's hardcoded `@page` block with the result of `chrome.build_css()`; module-section / table / KPI / cover-body CSS stays in `_PDF_CSS`.

### `build_header_html()` — both branches

```python
def build_header_html(self) -> str:
    # Resolve logo at RENDER time per D-03 — missing file = silent title-only
    logo_html = ""
    if self.cfg.logo_path and Path(self.cfg.logo_path).exists():
        logo_uri = Path(self.cfg.logo_path).resolve().as_uri()  # file:///D:/.../logo.png
        logo_html = f'<img src="{logo_uri}" alt="">'

    title    = html.escape(self.cfg.title)
    subtitle = html.escape(self.cfg.subtitle) if self.cfg.subtitle else ""
    subtitle_html = f'<span class="chrome-subtitle">{subtitle}</span>' if subtitle else ""

    return (
        f'<div class="chrome-header">'
        f'{logo_html}'
        f'<span class="chrome-title">{title}</span>'
        f'{subtitle_html}'
        f'</div>'
    )
```

### `build_footer_runners()` — no-op (CSS-only footer)

```python
def build_footer_runners(self) -> str:
    """
    Footer corners are emitted as literal `content:` strings inside the
    margin boxes defined by build_css() — no body-side running elements
    needed for the footer.

    Method exists for API symmetry with build_header_html() and to
    future-proof for cases where the footer eventually needs HTML markup
    (e.g. clickable links, mixed-color text spans).
    """
    return ""
```

**Composer wiring (Phase 6):**

```python
# In ReportComposer.assemble_pdf() — Phase 6 work:
chrome = PdfChrome(chrome_config)
html_doc = f"""
{_PDF_DOCTYPE}
<html>
  <head>
    <style>{chrome.build_css()}</style>
    <style>{_PDF_CSS_BODY}</style>     # remaining body styles (module sections, tables, KPI tiles)
  </head>
  <body>
    {chrome.build_header_html()}      # carries position: running(chrome-header)
    {chrome.build_footer_runners()}   # empty string in v1; future-proofing
    {cover_html}
    {module_sections}
  </body>
</html>
"""
```

---

## Test Pattern — `tests/test_pdf_chrome.py`

### Layer 1 — Fast unit tests (no WeasyPrint)

```python
from datetime import datetime, timezone
from pathlib import Path
import pytest
from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig

GEN = datetime(2026, 5, 13, 8, 52, tzinfo=timezone.utc)


def _cfg(**kw):
    base = dict(title="Vuln Report", subtitle="Production",
                generated_at=GEN, header_bg="#1a2332",
                logo_path=None, privacy_label="Confidential")
    base.update(kw)
    return PdfChromeConfig(**base)


def test_css_suppresses_cover_page_number():
    css = PdfChrome(_cfg()).build_css()
    assert '@page :first' in css
    assert '@bottom-center' in css and 'content: ""' in css
    # The :first block appears AFTER the base @page block (cascade order matters)
    assert css.index('@page :first') > css.index('@bottom-center')


def test_css_emits_page_n_of_m():
    css = PdfChrome(_cfg()).build_css()
    assert 'counter(page)' in css
    assert 'counter(pages)' in css


def test_css_interpolates_header_bg():
    css = PdfChrome(_cfg(header_bg="#330033")).build_css()
    assert "background: #330033" in css


def test_css_interpolates_privacy_label():
    css = PdfChrome(_cfg(privacy_label="Internal Only")).build_css()
    assert 'content: "Internal Only"' in css


def test_css_interpolates_generated_at():
    css = PdfChrome(_cfg()).build_css()
    assert '2026-05-13 08:52 UTC' in css


def test_header_html_no_logo():
    html_out = PdfChrome(_cfg(logo_path=None)).build_header_html()
    assert '<img' not in html_out
    assert 'Vuln Report' in html_out
    assert 'chrome-header' in html_out


def test_header_html_with_valid_logo(tmp_path):
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)  # PNG magic, content irrelevant for HTML test
    html_out = PdfChrome(_cfg(logo_path=logo)).build_header_html()
    assert '<img src="file://' in html_out
    assert 'logo.png' in html_out
    assert 'Vuln Report' in html_out


def test_header_html_missing_logo_silent_fallback(tmp_path, caplog):
    """CHROME-CFG-03: missing logo file → title-only, no exception, no warning."""
    nonexistent = tmp_path / "does-not-exist.png"
    with caplog.at_level("WARNING"):
        html_out = PdfChrome(_cfg(logo_path=nonexistent)).build_header_html()
    assert '<img' not in html_out
    assert 'Vuln Report' in html_out
    assert caplog.records == []   # no warning spam


def test_footer_runners_empty_in_v1():
    """v1 emits footer via CSS margin boxes; build_footer_runners() returns ''."""
    assert PdfChrome(_cfg()).build_footer_runners() == ""
```

### Layer 2 — One real-render integration test (WeasyPrint + pypdf)

```python
import weasyprint
from pypdf import PdfReader
import io


def test_real_render_chrome_2_pages(tmp_path):
    """End-to-end: render a 2-page doc, extract per-page text, verify chrome behavior."""
    chrome = PdfChrome(_cfg())
    html_doc = f"""<!doctype html>
    <html>
      <head><style>{chrome.build_css()}</style></head>
      <body>
        {chrome.build_header_html()}
        <h1>Cover Page</h1>
        <div style="page-break-before: always;"><h1>Page Two</h1><p>body content</p></div>
      </body>
    </html>"""

    pdf_bytes = weasyprint.HTML(string=html_doc).write_pdf()
    assert pdf_bytes  # non-empty

    reader = PdfReader(io.BytesIO(pdf_bytes))
    assert len(reader.pages) == 2

    page1 = reader.pages[0].extract_text()
    page2 = reader.pages[1].extract_text()

    # CHROME-FTR-03: cover does NOT have page number
    assert "Page 1 of" not in page1
    # CHROME-FTR-02: page 2 DOES have "Page N of M"
    assert "Page 2 of 2" in page2
    # CHROME-FTR-01: privacy label on every page
    assert "Confidential" in page1
    assert "Confidential" in page2
    # CHROME-HDR-01: header title on every page (running element)
    assert "Vuln Report" in page1
    assert "Vuln Report" in page2
    # Generated-at timestamp on every page
    assert "2026-05-13 08:52 UTC" in page1
    assert "2026-05-13 08:52 UTC" in page2
```

**Why this exact shape:** every assertion above was empirically validated against the prototype renders during this research (see Q1, Q3, Q4 verification output). No theoretical guesses.

---

## Dependency Updates

**`requirements.txt`** — add one line in the test/dev section (currently no test dependencies are pinned; add a section header):

```diff
+ # Testing — PDF text extraction for chrome integration tests
+ pypdf~=6.0
```

- **Latest pypdf:** 6.11.0 (2026-05-13, [PyPI](https://pypi.org/project/pypdf/))
- **Pin rationale:** `~=6.0` per Q3 — pypdf is dev/test-only; allow 6.x bugfix updates; major-version pin protects against future breaking API changes. If project standardizes on exact pins, use `pypdf==6.11.0`.

**WeasyPrint pin:** **NO CHANGE.** Stays at `weasyprint==65.1`. All four open questions verified against 65.1 directly. Latest is 68.1 but bumping is out of scope for this phase per CONTEXT.md ("WeasyPrint version — already pinned by v1.0 work; do not bump in this phase").

---

## Risks / Gotchas

1. **`logo_path` strings vs `Path` objects.** `PdfChromeConfig.logo_path: Path | None` — the planner should make sure `config.py`'s `LOGO_PATH` constant is typed `Path | None` (not `str`), and that `run_group()` passes the constant through unchanged. Mixed `str` / `Path` causes the existence check to silently fail.

2. **`Path.as_uri()` requires absolute path.** Relative paths raise `ValueError`. `PdfChrome.build_header_html()` MUST call `.resolve()` first. Tests should cover both relative-input and absolute-input scenarios.

3. **HTML-escaping privacy_label and title.** `html.escape()` is needed on `cfg.title` and `cfg.subtitle` (they appear inside `<span>` markup). For `cfg.privacy_label` and `cfg.generated_at` — they go into CSS `content: "..."` strings, where the risk is a stray `"` breaking the CSS. Recommend: document that `privacy_label` must not contain `"`; alternatively, escape it as `\"` in the f-string. Planner choice.

4. **Generated-at timezone.** CHROME-FTR-01 requires "Date Generated (UTC)". `PdfChromeConfig.generated_at: datetime` should be UTC-aware (`tzinfo=timezone.utc`). The CSS interpolation uses `strftime('%Y-%m-%d %H:%M UTC')` — the literal "UTC" suffix is correct ONLY if the datetime is actually UTC. The planner should add a `__post_init__` validation: `assert cfg.generated_at.tzinfo is not None` or convert with `.astimezone(timezone.utc)`.

5. **No flexbox in margin boxes** (per memory `[[feedback_layout_fixes]]` and verified in Q4). The header-band layout uses inline-block / vertical-align: middle. If a future change adds a third element (e.g. logo + title + tagline + version-stamp), keep using inline flow, not flex.

6. **Two `<style>` blocks in the final HTML doc** (composer's existing `_PDF_CSS` plus chrome's `build_css()`). WeasyPrint resolves multiple style blocks fine, but Phase 6 must decide whether to keep them separate or merge. Researcher recommendation: keep separate — easier to test chrome CSS in isolation.

7. **`@page :first` selector cascading.** While Q1 verified the cascade works for margin-box content, watch out for the order: the base `@page` rule MUST come before `@page :first`. Reversing the order would have `:first`'s overrides clobbered by `@page` (CSS specificity). The `build_css()` template above gets this right.

---

## Cross-Cuts to Phase 6

Phase 6 inherits everything in this RESEARCH.md plus:

- **Composer wiring location:** `ReportComposer.assemble_pdf()` (composer.py, search for `_PDF_CSS` and the cover-page assembly).
- **CSS coexistence strategy:** keep `_PDF_CSS` (module sections, tables, KPI tiles, cover-body styling) and `chrome.build_css()` (page-level + header band) as separate `<style>` blocks.
- **Cover page changes (CHROME-COV-01/02):** remove the inline "Generated:" and "Data Protection Label" from `_build_unified_cover_page()` (composer.py ~line 730+); both are now in the chrome footer.
- **`run_group()` default-resolution:** `group.get("privacy_label", "Confidential")` per D-03 plumbing. Per-group YAML schema field added in Phase 5 (CHROME-CFG-04, CHROME-COMPAT-02).
- **`HEADER_BG_COLOR` and `LOGO_PATH` constants** added to `config.py` in Phase 5; Phase 6 imports them at `run_group()` call site to build the `PdfChromeConfig`.
- **Phase 6 cutover smoke baselines (CHROME-INT-03)** will need regeneration because the cover page no longer renders the inline "Generated:" + "Data Protection Label" HTML — structural drift expected on the first run after cutover. The baseline regen is in scope for Phase 6, not Phase 5.

---

## Sources

### Primary (HIGH confidence)
- [WeasyPrint Issue #2088](https://github.com/Kozea/WeasyPrint/issues/2088) — maintainer `grewn0uille` 2024-03-05 confirms `:first` is supported and works with `@page`.
- [WeasyPrint Going Further docs](https://doc.courtbouillon.org/weasyprint/stable/going_further.html) — paged-media feature list including `:first` selector.
- [WeasyPrint PR #882](https://github.com/Kozea/WeasyPrint/pull/882) — `position: running()` + `element()` introduction (shipped in 51).
- [pypdf extract-text docs](https://pypdf.readthedocs.io/en/stable/user/extract-text.html) — current per-page extraction API.
- **Local verification:** WeasyPrint 65.1 + pypdf 6.11.0 against test HTML documents (this session). Cover page-number suppression, three-corner footer, running-element with `<img>` all rendered and text-extracted successfully.

### Secondary (MEDIUM confidence)
- [WeasyPrint Issue #2013](https://github.com/Kozea/WeasyPrint/issues/2013) — running-element bug scoped to `<table>` content only; `<img>` and text confirmed working.
- [WeasyPrint Issue #1043](https://github.com/Kozea/WeasyPrint/issues/1043) — "different footer on cover vs other pages" use case; closed issue (no maintainer fix detail visible from outside, but the use case is exactly what `@page :first` solves).

### Tertiary
- [Aaron Saray: Deep Dive Into Print CSS Headers and Footers (2025)](https://aaronsaray.com/2025/a-deep-dive-into-print-css-headers-and-footers/) — community guide on @page margin boxes.
- [PrintCSS: Page Selectors and Page Breaks (Medium)](https://medium.com/printcss/printcss-page-selectors-and-page-breaks-c9eff43e2653) — page-selector usage examples.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| — | *(none)* | — | All claims in this research were either verified by local render (Q1–Q4) or cited from authoritative WeasyPrint/pypdf docs/issues. No `[ASSUMED]` claims. |

---

## Metadata

**Confidence breakdown:**
- `@page :first` behavior: **HIGH** — verified by local 3-page render with pypdf extraction.
- Three-corner footer CSS: **HIGH** — verified locally, no overlap at A4 landscape with composer's existing margins.
- pypdf reliability for assertions: **HIGH** — verified locally; output is deterministic and substring-assertable.
- `position: running()` with `<img>`: **HIGH** — verified locally on WeasyPrint 65.1.
- Implementation sketch: **MEDIUM** — CSS/HTML strings all verified, but the full `pdf_chrome.py` module integration not yet stress-tested with composer wiring (that's Phase 6's job).

**Research date:** 2026-05-13
**Valid until:** ~2026-06-13 (WeasyPrint and pypdf both stable; bumps unlikely in 30 days)
**Verified against:** WeasyPrint 65.1 (installed), pypdf 6.11.0 (latest as of research date).
