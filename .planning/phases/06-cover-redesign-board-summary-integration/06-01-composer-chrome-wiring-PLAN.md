---
phase: 06-cover-redesign-board-summary-integration
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - reports/modules/composer.py
  - tests/test_phase6_composer_chrome.py
autonomous: true
requirements:
  - CHROME-INT-01
  - CHROME-INT-02
user_setup: []
must_haves:
  truths:
    - "ReportComposer.__init__ accepts an optional pdf_chrome=PdfChromeConfig kwarg."
    - "When pdf_chrome is None, assemble_pdf() output is byte-identical to pre-Phase-6 output (backward compatible)."
    - "When pdf_chrome is set, assemble_pdf() emits chrome CSS after _PDF_CSS and injects build_header_html() at body-top."
  artifacts:
    - path: "reports/modules/composer.py"
      provides: "ReportComposer wired to optionally consume PdfChrome utility"
      contains: "pdf_chrome"
    - path: "tests/test_phase6_composer_chrome.py"
      provides: "Unit tests for chrome-on and chrome-off assembly paths"
      contains: "test_assemble_pdf"
  key_links:
    - from: "reports/modules/composer.py"
      to: "reports/modules/pdf_chrome.py"
      via: "from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig"
      pattern: "PdfChromeConfig"
    - from: "ReportComposer.assemble_pdf"
      to: "PdfChrome.build_css / build_header_html"
      via: "second <style> block appended after _PDF_CSS; header div at body-top"
      pattern: "build_header_html"
---

<objective>
Wire the Phase 5 `PdfChrome` utility into `ReportComposer` as an optional constructor parameter. When supplied, the composer emits chrome CSS as a second `<style>` block AFTER existing `_PDF_CSS` (per RESEARCH.md Q1 cascade analysis), and injects `PdfChrome.build_header_html()` at body-top. When omitted, behavior is byte-identical to today.

Purpose: Phase 6 plans 02-04 cannot proceed without this wire point. D-06 locks the wire location as constructor-level (not per-call), so the same composer instance threads chrome through PDF + email + analyst Excel as a single source of truth.

Output: Backward-compatible constructor change; surgical injection in `assemble_pdf()`; paired unit tests asserting both code paths.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/06-cover-redesign-board-summary-integration/06-CONTEXT.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-RESEARCH.md
@.planning/REQUIREMENTS.md
@CLAUDE.md
@reports/modules/composer.py
@reports/modules/pdf_chrome.py

<interfaces>
<!-- The Phase 5 chrome utility contract that this plan consumes. -->

reports/modules/pdf_chrome.py (already on disk; CONSUME ONLY — Phase 5 contract):
```python
@dataclass(frozen=True)
class PdfChromeConfig:
    title: str
    subtitle: str | None
    generated_at: datetime   # MUST be tz-aware UTC; __post_init__ enforces
    header_bg: str
    logo_path: Path | None
    privacy_label: str = "Confidential"

class PdfChrome:
    def __init__(self, config: PdfChromeConfig) -> None: ...
    def build_css(self) -> str: ...               # returns @page + running() rules
    def build_header_html(self) -> str: ...       # body-level <div> with position: running(chrome-header)
    def build_footer_runners(self) -> str: ...    # v1 returns "" — corners are pure CSS content strings
```

reports/modules/composer.py constructor signature AFTER this plan:
```python
class ReportComposer:
    def __init__(
        self,
        modules: list[BaseModule],
        ...existing kwargs...,
        pdf_chrome: PdfChromeConfig | None = None,   # NEW — D-06
    ) -> None:
        ...
        self._pdf_chrome: PdfChrome | None = (
            PdfChrome(pdf_chrome) if pdf_chrome is not None else None
        )
```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add pdf_chrome constructor parameter to ReportComposer</name>
  <files>reports/modules/composer.py</files>
  <action>
1. Add the sibling import near the existing `from reports.modules.base import ...` / `from reports.modules.registry import ...` block (top of file):
   ```python
   from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig
   ```
   RESEARCH.md Q3 confirms zero circular-import risk.

2. In `ReportComposer.__init__` (composer.py lines ~430-446), add `pdf_chrome: PdfChromeConfig | None = None` as the LAST kwarg (after all existing kwargs, before the closing paren).

3. Store the wrapped instance on the composer:
   ```python
   self._pdf_chrome: PdfChrome | None = (
       PdfChrome(pdf_chrome) if pdf_chrome is not None else None
   )
   ```
   Place this assignment near the other `self._*` assignments inside `__init__`.

4. DO NOT change the order or default of any existing kwarg. DO NOT touch unrelated code. Karpathy §3 — surgical.
  </action>
  <verify>
    <automated>python -c "from reports.modules.composer import ReportComposer; from reports.modules.pdf_chrome import PdfChromeConfig; from datetime import datetime, timezone; cfg = PdfChromeConfig(title='T', subtitle='S', generated_at=datetime.now(tz=timezone.utc), header_bg='#1a2332', logo_path=None); rc = ReportComposer(modules=[], pdf_chrome=cfg); assert rc._pdf_chrome is not None; rc2 = ReportComposer(modules=[]); assert rc2._pdf_chrome is None; print('OK')"</automated>
  </verify>
  <done>`ReportComposer(modules=[])` still works (None default). `ReportComposer(modules=[], pdf_chrome=cfg)` stores a wrapped `PdfChrome` on `self._pdf_chrome`. No existing test regresses.</done>
</task>

<task type="auto">
  <name>Task 2: Inject chrome CSS + header HTML into assemble_pdf</name>
  <files>reports/modules/composer.py</files>
  <action>
In `assemble_pdf()` (composer.py lines ~710-724, the HTML scaffold area), make two guarded injections.

**Injection A — chrome CSS as second `<style>` block AFTER `_PDF_CSS`** (per RESEARCH.md Q1: source-order cascade required so `@page :first` suppresses page-1 counter):

Find the existing line that emits `<style>{_PDF_CSS}</style>` (or equivalent f-string composition). Immediately AFTER it (still inside `<head>`), insert:
```python
chrome_style = (
    f"<style>{self._pdf_chrome.build_css()}</style>"
    if self._pdf_chrome is not None
    else ""
)
```
and concatenate `chrome_style` into the head-section assembly.

**Injection B — chrome header HTML at body-top** (per RESEARCH.md Finding 4: must be body-level, NOT inside `<head>` or `.report-cover`, because WeasyPrint pulls it into `@top-left` via the running-element rule emitted by `build_css`):

Immediately AFTER `<body>` (before the existing cover/body content is interpolated), inject:
```python
chrome_header = (
    self._pdf_chrome.build_header_html()
    if self._pdf_chrome is not None
    else ""
)
```
and concatenate `chrome_header` into the body assembly.

Both injections are guarded by `if self._pdf_chrome is not None` — when absent, both strings are empty and the output is byte-identical to today (backward compatibility per D-06).

**DO NOT** call `build_footer_runners()` — RESEARCH.md Finding 4 confirms it returns `""` in v1 and footer corners are pure-CSS via `build_css()`. (Optional: a no-op `_ = self._pdf_chrome.build_footer_runners()` for API symmetry is acceptable but not required.)

**DO NOT** modify `_PDF_CSS` itself. DO NOT modify `_PDF_UNIFIED_COVER_TEMPLATE` (that's plan 06-02). DO NOT touch `_build_unified_cover_page()` substitution logic in this plan.
  </action>
  <verify>
    <automated>python -m pytest tests/test_phase6_composer_chrome.py -v</automated>
  </verify>
  <done>Both code paths exercised by Task 3 tests pass. Chrome-on path emits header HTML + chrome CSS markers. Chrome-off path is byte-identical to legacy assembly.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Add unit tests for chrome-on and chrome-off assembly paths</name>
  <files>tests/test_phase6_composer_chrome.py</files>
  <behavior>
    - Test 1 (chrome-on): `ReportComposer(modules=[], pdf_chrome=cfg).assemble_pdf(...)` HTML output contains the `chrome-header` div marker AND a chrome-CSS marker (e.g. `position: running(chrome-header)` or `@page :first`).
    - Test 2 (chrome-off): `ReportComposer(modules=[]).assemble_pdf(...)` HTML output does NOT contain any chrome marker. It still contains the legacy `_PDF_CSS` page-size/`@bottom-center` rule.
    - Test 3 (cascade order): in chrome-on output, the chrome `<style>` block index is strictly GREATER than the `_PDF_CSS` `<style>` block index (chrome appended AFTER) so `@page :first` wins on cascade (RESEARCH.md Q1).
  </behavior>
  <action>
Create `tests/test_phase6_composer_chrome.py`. Pattern mirrors `tests/test_pdf_chrome.py` (Phase 5 Layer-1 unit tests).

Skeleton:
```python
"""Phase 6 plan 01 — ReportComposer chrome wiring unit tests."""
from datetime import datetime, timezone

import pytest

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


def _assemble_html(composer: ReportComposer) -> str:
    # Use the public assemble_pdf path but capture the HTML pre-render.
    # Pattern: call the same internal HTML builder assemble_pdf uses, OR
    # patch WeasyPrint and capture the HTML string passed to it.
    # IMPLEMENTOR: pick the simpler of the two based on the actual
    # assemble_pdf surface — they should produce the same string.
    ...


def test_assemble_pdf_chrome_on_contains_header_and_chrome_css():
    cfg = _make_cfg()
    composer = ReportComposer(modules=[], pdf_chrome=cfg)
    html = _assemble_html(composer)
    assert "chrome-header" in html, "header div must appear at body-top"
    assert "position: running(chrome-header)" in html or "@page :first" in html, \
        "chrome CSS markers must appear in <head>"


def test_assemble_pdf_chrome_off_omits_chrome_markers():
    composer = ReportComposer(modules=[])
    html = _assemble_html(composer)
    assert "chrome-header" not in html
    assert "running(chrome-header)" not in html
    # Legacy _PDF_CSS still present
    assert "@bottom-center" in html


def test_assemble_pdf_chrome_css_appended_after_pdf_css():
    """Cascade order: chrome <style> must come AFTER _PDF_CSS for @page :first to win."""
    cfg = _make_cfg()
    composer = ReportComposer(modules=[], pdf_chrome=cfg)
    html = _assemble_html(composer)
    # _PDF_CSS contains @bottom-center; chrome CSS contains @page :first
    pdf_css_idx = html.find("@bottom-center")
    chrome_css_idx = html.find("@page :first")
    assert pdf_css_idx >= 0 and chrome_css_idx >= 0
    assert chrome_css_idx > pdf_css_idx, \
        "chrome CSS must be appended AFTER _PDF_CSS per RESEARCH.md Q1"
```

If `assemble_pdf` does not expose a pure-HTML accessor, the IMPLEMENTOR may extract the HTML-build step into a `_build_assembled_html(...)` helper inside `assemble_pdf()` and call it from both `assemble_pdf` and these tests. That refactor is in-scope for THIS plan (it's enabling the verify gate for THIS plan's behavior).

DO NOT mock `PdfChrome` itself — exercise the real Phase 5 utility against the real composer scaffold.
  </action>
  <verify>
    <automated>python -m pytest tests/test_phase6_composer_chrome.py -v</automated>
  </verify>
  <done>All 3 tests pass. Tests cover both code paths and cascade order. No existing test regresses (run full `pytest` to confirm).</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| composer caller → ReportComposer | Caller supplies PdfChromeConfig with operator-derived strings (title, subtitle, privacy_label). |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-06-01 | Tampering | `pdf_chrome` constructor kwarg | accept | `PdfChromeConfig.__post_init__` (Phase 5) already validates `privacy_label` regex + UTC tz; composer trusts the dataclass. Defense-in-depth handled upstream. |
| T-06-02 | Denial of Service | None vs PdfChromeConfig branching in assemble_pdf | mitigate | Both branches must be exercised by unit tests (Task 3) so a future refactor cannot silently break the None path that all non-Board-Summary callers rely on. |
</threat_model>

<verification>
```powershell
# 1. Constructor + storage smoke
python -c "from reports.modules.composer import ReportComposer; from reports.modules.pdf_chrome import PdfChromeConfig; from datetime import datetime, timezone; cfg = PdfChromeConfig(title='T', subtitle='S', generated_at=datetime.now(tz=timezone.utc), header_bg='#1a2332', logo_path=None); rc = ReportComposer(modules=[], pdf_chrome=cfg); assert rc._pdf_chrome is not None; print('OK')"

# 2. New unit tests
python -m pytest tests/test_phase6_composer_chrome.py -v

# 3. No regression in existing composer tests
python -m pytest tests/test_phase2_composer_pipeline.py -v
```
</verification>

<success_criteria>
- `ReportComposer.__init__` accepts `pdf_chrome: PdfChromeConfig | None = None` (CHROME-INT-01).
- `assemble_pdf()` injects chrome CSS as a second `<style>` block AFTER `_PDF_CSS`, and `build_header_html()` at body-top (CHROME-INT-01).
- Chrome-off path is byte-identical to today (backward compat per D-06).
- All Task 3 tests pass; existing composer/pipeline tests still pass.
</success_criteria>

<output>
After completion, create `.planning/phases/06-cover-redesign-board-summary-integration/06-01-SUMMARY.md` capturing:
- Exact lines added in `composer.py` (constructor + assemble_pdf injections)
- Test names + pass evidence
- Confirmation that `tests/test_phase2_composer_pipeline.py` still passes (no regression)
- Note: cover template trim is plan 06-02; this plan is wire-only.
</output>
