# Phase 05 — PDF Chrome Foundation — CONTEXT

**Phase:** 5 — PDF Chrome Foundation
**Milestone:** v1.1 — PDF Chrome Redesign
**Date:** 2026-05-13
**Status:** Context locked; ready for `/gsd-plan-phase 5`.

---

## Domain

Build a shared PDF chrome utility (header band + footer band CSS) plus its config surface, **provable in isolation before any report consumes it.** Phase 6 wires it into `board_summary`; future PDF reports (legacy migrations and net-new) inherit it without copying CSS.

The chrome utility is intended to be **the canonical PDF design system going forward** — not a one-off for board_summary. Every PDF report from v1.1 onward holds a `PdfChromeConfig` and renders through `PdfChrome`.

Requirements (locked in `.planning/REQUIREMENTS.md`): **CHROME-CFG-01, CHROME-CFG-02, CHROME-CFG-03, CHROME-CFG-04, CHROME-HDR-01, CHROME-HDR-02, CHROME-FTR-01, CHROME-FTR-02, CHROME-FTR-03.**

---

## Canonical Refs

Downstream agents (researcher, planner, executor) MUST read these in addition to ROADMAP.md and this CONTEXT.md:

- `.planning/REQUIREMENTS.md` — milestone v1.1 active requirements (CHROME-CFG / HDR / FTR rows are this phase; COV / INT / COMPAT rows are Phase 6).
- `.planning/ROADMAP.md` — phase 5 success criteria and v1.1 milestone scope.
- `CLAUDE.md` — Karpathy Guidelines, Project Structure, Code Quality Requirements.
- `docs/GLOSSARY.md` — definitions of *chrome*, *cover page*, *four-channel render contract*, *module*, *RAG strip*, *slug* (created 2026-05-13 as part of this discussion).
- `reports/modules/composer.py` — existing PDF assembler. Lines 70–230 hold the current `@page` block, `.report-header`/`.report-footer` body divs, and `.report-cover` block. Lines 378–387 hold the current inline "Generated:" timestamp + cover-meta that v1.1 retires. Lines 730+ hold `_build_unified_cover_page()`.
- `reports/modules/base.py` — `BaseModule` + `ModuleConfig` pattern; the `PdfChromeConfig` dataclass parallels this shape.
- `config.py` — target for `HEADER_BG_COLOR` and `LOGO_PATH` new constants.
- `delivery_config.schema.yaml` — target for optional `privacy_label` per-group field.
- `.planning/codebase/STRUCTURE.md` and `.planning/codebase/ARCHITECTURE.md` — composer/run_group flow context.

---

## Decisions (locked)

### D-01 — Chrome shape: `PdfChrome` class + `PdfChromeConfig` dataclass

The chrome utility is a typed design-system object, not loose functions.

```python
# reports/modules/pdf_chrome.py
@dataclass(frozen=True)
class PdfChromeConfig:
    title: str
    subtitle: str
    generated_at: datetime           # UTC
    header_bg: str = "#1a2332"       # default per CHROME-CFG-01
    logo_path: Path | None = None    # CHROME-CFG-02
    privacy_label: str = "Confidential"  # defensive default for tests; CHROME-CFG-04

class PdfChrome:
    def __init__(self, cfg: PdfChromeConfig): ...
    def build_css(self) -> str: ...                # @page rules + chrome class styles
    def build_header_html(self) -> str: ...        # running element for top margin box
    def build_footer_runners(self) -> str: ...     # running elements for bottom corners
```

**Why this shape over standalone functions:** the typed config object IS the design-system surface. Future global knobs (header height, footer font, etc.) are added as `PdfChromeConfig` fields with defaults — no signature churn for callers. Parallels existing `BaseModule` + `ModuleConfig` pattern.

**Why not composer-internal methods:** would tie chrome to one PDF assembler. The chrome must be reusable by future non-composer reports (per spirit of CHROME-INT-02).

**Composer integration:** `ReportComposer` holds a `PdfChrome` instance; calls `.build_css()` and injects the result into the existing `_PDF_CSS` block; replaces the inline-cover "Generated:" + data-protection-label HTML with running elements emitted by `.build_header_html()` and `.build_footer_runners()`. The actual composer wiring is Phase 6 work; Phase 5 only builds the utility.

### D-02 — Repeat mechanism: WeasyPrint `@page` margin boxes + CSS running elements

Header and footer repeat on every page via WeasyPrint's native CSS3 paged-media features:

```css
@page {
  @top-left   { content: element(chrome-header); }
  @bottom-left   { content: var(--privacy-label); }
  @bottom-center { content: "Page " counter(page) " of " counter(pages); }
  @bottom-right  { content: var(--generated-at); }
}
@page :first {
  @bottom-center { content: ""; }   /* cover hides page number — CHROME-FTR-03 */
}
body > .chrome-header { position: running(chrome-header); }
```

- Cover page number suppression uses `@page :first` (selector, not Python branching).
- `counter(page) / counter(pages)` handles "Page N of M" math automatically (CHROME-FTR-02).
- Body has one `<div class="chrome-header" style="position: running(chrome-header)">…</div>` that WeasyPrint pulls into the top-left margin box on every page.
- Privacy label and generated-at can be emitted as CSS custom-property values OR as additional running elements — planner picks; both equivalent.
- The composer already uses `counter(page) / counter(pages)` for its current bottom-center page number, so this pattern is consistent.

**Rejected:** per-page HTML blocks emitted by Python. Reimplements CSS counters; breaks when modules span multiple pages.

### D-03 — Logo + privacy-label plumbing

**Logo consumption:** `<img src="file:///abs/path/logo.png">` inside the `position: running(chrome-header)` element. WeasyPrint resolves `file://` natively. `<img>` (vs `content: url(...)` in the margin box) gives inline-block sizing without margin-box layout quirks.

**Logo missing-file fallback (CHROME-CFG-03):** detected **at render time inside `PdfChrome.build_header_html()`**:

```python
if self.cfg.logo_path and Path(self.cfg.logo_path).exists():
    # emit <img src="file://..."> + title
else:
    # title-only header; no <img>, no reserved width, no exception, no warning
```

No startup-time FS check — config can be set even when the file is added later. The design system owns its own defensive behavior.

**Privacy-label flow (CHROME-CFG-04, CHROME-COMPAT-02):**

```
delivery_config.yaml: groups[].privacy_label  (optional string)
    ↓
delivery_config.schema.yaml validates type=string  (does NOT inject default)
    ↓
run_group()  →  group.get("privacy_label", "Confidential")    ← default resolves here
    ↓
report function kwarg  →  composer  →  PdfChromeConfig(privacy_label=...)
```

The `"Confidential"` default resolves at the `run_group()` call site (operator-visible). `PdfChromeConfig` ALSO keeps `privacy_label: str = "Confidential"` as a defensive dataclass default for direct instantiation in tests.

### D-04 — Isolation test surface: two-layer pyramid

Phase 5 ships with both fast string-assert unit tests and one real-render integration test. This honors the existing project rule "verify CSS / layout fixes with real renders, not theoretical math" while keeping the bulk of the suite fast.

**Layer 1 — fast unit tests on `PdfChrome` output (no WeasyPrint):**

- `build_css()` contains `@page :first { @bottom-center { content: "" } }` (cover page-number suppression)
- `build_css()` contains `counter(page)` and `counter(pages)` (Page N of M wiring)
- `build_css()` interpolates `cfg.header_bg` into the header background rule
- `build_header_html()` with `logo_path=None` returns title-only output (no `<img>` tag)
- `build_header_html()` with a valid `logo_path` includes `<img src="file://..."` and the title text
- `build_header_html()` with `logo_path` pointing at a nonexistent file silently falls back to title-only (no exception, no log warning) — **CHROME-CFG-03 acceptance**
- `build_footer_runners()` emits the privacy label and the formatted UTC generated-at

**Layer 2 — one real-render integration test (WeasyPrint + `pypdf` text extraction):**

- Build minimal `PdfChromeConfig`; wrap in a tiny HTML doc with 2+ pages of content
- Render to PDF bytes via WeasyPrint
- Extract text per page with `pypdf`; assert:
  - Page 1 (cover) text does NOT contain `"Page 1 of"` (CHROME-FTR-03)
  - Page 2+ text DOES contain `"Page"` and `"of"` (CHROME-FTR-02)
  - Every page's text contains the privacy label (CHROME-FTR-01)
  - Page count matches expected

**Not in Phase 5:** Pixel/byte-diff snapshots. Those belong to Phase 6's cutover-baseline regen (CHROME-INT-03).

---

## Code Context

- **`reports/modules/composer.py`** — current PDF assembler. Owns `_PDF_CSS` (line 70+), `_build_unified_cover_page()` (line 730+). Phase 5 does NOT modify this file; it only adds the new `pdf_chrome.py` module. Phase 6 integrates.
- **`reports/modules/base.py`** — `BaseModule` + `ModuleConfig` is the design parallel for `PdfChrome` + `PdfChromeConfig`. Same shape, same import convention, same auto-discovery exemption (pdf_chrome is a utility, NOT a metric module — no `_module.py` suffix, no `@register_module`).
- **`config.py`** — add `HEADER_BG_COLOR = "#1a2332"` and `LOGO_PATH: Path | None = None` constants alongside `SLA_DAYS`.
- **`delivery_config.schema.yaml`** — add optional `privacy_label: string` field at the group level.
- **`tests/`** — new `tests/test_pdf_chrome.py` for both test layers. `pypdf` is **not currently in `requirements.txt`** — planner must add it (likely pin `pypdf~=4.0`).
- **WeasyPrint version** — already pinned by v1.0 work; do not bump in this phase. (Per memory [[feedback_layout_fixes]]: WeasyPrint flex bugs are real — stick to inline-block / table layout in the margin boxes; no flex.)

---

## Deferred Ideas

Captured during this discussion; out of scope for Phase 5 (and most for v1.1).

- **Header text autoshift for light backgrounds** — explicitly out of scope per `REQUIREMENTS.md` "Out of Scope" section. White-on-dark only; operator picks a dark color.
- **Pixel/byte-diff visual snapshots of chrome** — belongs in Phase 6's cutover-baseline regen, not Phase 5.
- **Legacy report migration (management_summary, ops_remediation)** — GEN-01/02, deferred to future milestone. Those reports keep their existing render paths in v1.1 (CHROME-COMPAT-01).
- **CSS custom properties vs additional running elements for footer corner content** — Planner-discretion implementation detail. Both produce equivalent output; pick whichever yields cleaner CSS in the prototype.

---

## Open Questions for Researcher

- Does WeasyPrint's `@page :first` selector reliably suppress the bottom-center margin box content, or does it require redeclaring the `@page` block with all margin boxes? Confirm minimal reproducer.
- What is the exact CSS for placing privacy label + page number + generated-at in three separate footer corners without overlap at A4 landscape (15mm 12mm 18mm 12mm margins per current composer)?
- Is `pypdf` text extraction order-stable enough for "Page 1 text does NOT contain 'Page 1 of'" assertions, or do we need PyMuPDF / pdfplumber for reliable per-page text?
- Are there WeasyPrint `position: running()` gotchas with images inside the running element (some versions had issues with image dimensions in margin boxes)?

---

## Success Criteria (from ROADMAP.md, restated)

1. `config.py` exposes `HEADER_BG_COLOR` (default `#1a2332`) and `LOGO_PATH` (default `None`).
2. `delivery_config.schema.yaml` accepts an optional `privacy_label: string` per group; defaults to `"Confidential"` when omitted (default resolved in `run_group()`).
3. Shared chrome utility renders header band (logo-or-no-logo branches) and footer band (cover-variant vs page-N-of-M variant) — covered by unit tests on generated HTML/CSS.
4. Logo-missing fallback test passes: no exception, no logo space reserved, title-only rendering.

---

## Next Step

```
/clear
/gsd-plan-phase 5
```
