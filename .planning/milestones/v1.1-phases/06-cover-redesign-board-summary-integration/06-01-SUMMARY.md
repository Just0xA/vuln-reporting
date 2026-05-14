---
phase: 06-cover-redesign-board-summary-integration
plan: 01
subsystem: reports.modules.composer
tags: [chrome, pdf, composer, phase6, wire-only]
requires:
  - reports/modules/pdf_chrome.py  # Phase 5 contract (consumed, not modified)
provides:
  - "ReportComposer.__init__ optional pdf_chrome: PdfChromeConfig | None kwarg"
  - "assemble_pdf chrome CSS + header injection (guarded; byte-identical when None)"
affects:
  - reports/modules/composer.py
  - tests/test_phase6_composer_chrome.py
tech-stack:
  added: []
  patterns:
    - "Optional constructor wiring with None default for backward compatibility (D-06)"
    - "Second-style-block cascade-order pattern for @page :first override (RESEARCH.md Q1)"
key-files:
  created:
    - tests/test_phase6_composer_chrome.py
  modified:
    - reports/modules/composer.py
decisions:
  - "D-06 honored: pdf_chrome is a constructor kwarg, NOT a per-assemble_pdf-call param"
  - "Chrome CSS emitted as a second <style> block AFTER _PDF_CSS (RESEARCH.md Q1)"
  - "pdf_chrome placed before **kwargs so it stays a named keyword (not swallowed)"
metrics:
  completed: 2026-05-13
  tasks: 3
  commits: 3
requirements:
  - CHROME-INT-01
  - CHROME-INT-02
---

# Phase 6 Plan 01: ReportComposer Chrome Wiring Summary

Wire-only integration of the Phase 5 `PdfChrome` utility into `ReportComposer`. Constructor accepts an optional `pdf_chrome: PdfChromeConfig | None = None` kwarg; when supplied, `assemble_pdf()` emits a second `<style>` block after `_PDF_CSS` and injects `build_header_html()` at body-top. When omitted, output is byte-identical to pre-Phase-6 behavior. Plans 06-02 (cover trim) and 06-03 (board_summary opt-in) now have a stable wire point.

## Tasks Completed

| Task | Name                                            | Commit  | Files                                |
| ---- | ----------------------------------------------- | ------- | ------------------------------------ |
| 1    | Add pdf_chrome constructor kwarg                | 9cd42b6 | reports/modules/composer.py          |
| 2    | Inject chrome CSS + header into assemble_pdf    | 1d3c707 | reports/modules/composer.py          |
| 3    | Unit tests for chrome-on / chrome-off / cascade | fe32dd9 | tests/test_phase6_composer_chrome.py |

## Exact Changes — composer.py

### Constructor (added)

```python
from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig  # new import

def __init__(
    self,
    vulns_df:       pd.DataFrame,
    assets_df:      pd.DataFrame,
    report_date:    Any,
    module_configs: list[ModuleConfig],
    pdf_chrome:     PdfChromeConfig | None = None,   # NEW
    **kwargs:       Any,
) -> None:
    ...
    self._pdf_chrome: PdfChrome | None = (
        PdfChrome(pdf_chrome) if pdf_chrome is not None else None
    )
```

`pdf_chrome` is placed BEFORE `**kwargs` because named keyword parameters must precede the var-keyword. The plan example (`<interfaces>`) wrote `...existing kwargs..., pdf_chrome=…` which is ambiguous; placing it before `**kwargs` is the only valid Python signature. All tests construct via keyword, so call ergonomics are unchanged.

### assemble_pdf (added 2 guarded injections)

```python
chrome_style = (
    f"<style>{self._pdf_chrome.build_css()}</style>"
    if self._pdf_chrome is not None
    else ""
)
chrome_header = (
    self._pdf_chrome.build_header_html()
    if self._pdf_chrome is not None
    else ""
)

return "\n".join([
    _PDF_DOCTYPE,
    "<html>",
    "<head>",
    '<meta charset="utf-8">',
    f"<title>{title}</title>",
    _PDF_CSS,
    chrome_style,                                # NEW — after _PDF_CSS per Q1
    f"<style>{page_css}</style>" if page_css else "",
    "</head>",
    "<body>",
    chrome_header,                               # NEW — body-top per Finding 4
    cover,
    body,
    "</body>",
    "</html>",
])
```

Both injections collapse to empty strings when `self._pdf_chrome is None` → output is byte-identical to today (D-06).

`build_footer_runners()` is NOT called — RESEARCH.md Finding 4 confirms it returns `""` in v1 and footer corners are pure-CSS via `build_css()`.

## Tests Added

`tests/test_phase6_composer_chrome.py` — 3 tests, all PASS:

| Test                                                       | Asserts                                                                             |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `test_assemble_pdf_chrome_on_contains_header_and_chrome_css` | `chrome-header` div present AND chrome CSS marker (`@page :first` or `running()`) present |
| `test_assemble_pdf_chrome_off_omits_chrome_markers`        | No chrome markers; legacy `@bottom-center` from `_PDF_CSS` still present            |
| `test_assemble_pdf_chrome_css_appended_after_pdf_css`      | `find("@page :first") > find("@bottom-center")` — cascade order locked              |

Pass evidence:

```
tests/test_phase6_composer_chrome.py::test_assemble_pdf_chrome_on_contains_header_and_chrome_css PASSED [ 33%]
tests/test_phase6_composer_chrome.py::test_assemble_pdf_chrome_off_omits_chrome_markers          PASSED [ 66%]
tests/test_phase6_composer_chrome.py::test_assemble_pdf_chrome_css_appended_after_pdf_css        PASSED [100%]
============================== 3 passed in 0.77s ===============================
```

Tests construct against the actual `ReportComposer(vulns_df=…, assets_df=…, report_date=…, module_configs=[], pdf_chrome=…)` signature; the plan's skeleton `ReportComposer(modules=[], …)` was a stand-in shape and has been corrected in the implemented test.

`assemble_pdf` already returns an HTML string directly (WeasyPrint conversion happens in callers), so no `_build_assembled_html` helper extraction was needed.

## Regression Check

- `tests/test_pdf_chrome.py` (Phase 5 chrome contract): 12 tests pass.
- `tests/test_phase6_composer_chrome.py` (new): 3 tests pass.
- Combined: **15 passed in 1.14s**.
- `tests/test_phase2_composer_pipeline.py`: collected 0 items (file present but contains no `test_*` functions). No regression — file was never an executable gate.
- Pre-existing `tests/test_modules_level1.py` calls `sys.exit()` at import (out-of-scope per scope-boundary rule; logged here, not fixed).

Smoke verify command from plan passed:

```
python -c "from reports.modules.composer import ReportComposer; ... rc = ReportComposer(..., pdf_chrome=cfg); assert rc._pdf_chrome is not None; ..."
→ OK
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] `pdf_chrome` parameter position relative to `**kwargs`**
- **Found during:** Task 1.
- **Issue:** Plan said "add as the LAST kwarg." Existing signature ends with `**kwargs: Any` (var-keyword). Named kwargs must precede `**kwargs` in Python; "last" was ambiguous.
- **Fix:** Placed `pdf_chrome` immediately before `**kwargs`. All call sites are keyword-only, so ergonomics are unchanged.
- **Files modified:** `reports/modules/composer.py` (Task 1).
- **Commit:** 9cd42b6.

**2. [Rule 3 — Blocking] Test skeleton constructor signature mismatch**
- **Found during:** Task 3.
- **Issue:** Plan skeleton showed `ReportComposer(modules=[], pdf_chrome=cfg)`. Actual constructor requires `vulns_df`, `assets_df`, `report_date`, `module_configs`.
- **Fix:** Implemented tests against the real signature via a `_make_composer()` helper using empty `pd.DataFrame()` and a fixed UTC `report_date`. Behavior assertions unchanged.
- **Files modified:** `tests/test_phase6_composer_chrome.py` (Task 3).
- **Commit:** fe32dd9.

**3. [Rule 3 — Blocking] `tests/` is gitignored**
- **Found during:** Task 3 commit.
- **Issue:** `.gitignore` line 59 excludes `tests/`. First `git add` was rejected.
- **Fix:** Used `git add -f` (matches Phase 5 precedent — `tests/test_pdf_chrome.py` was force-added the same way at commits 25b39db and 040cae2). `.gitignore` itself was not modified (out of plan scope).
- **Commit:** fe32dd9.

### TDD Gate Note

Task 3 was marked `tdd="true"` but in plan order it executes AFTER Tasks 1 and 2, so tests pass green on first run rather than failing RED first. Behavior coverage of both branches is achieved either way — the cascade-order test (Test 3) is the load-bearing assertion regardless of execution order.

## Threat Mitigations Applied

| Threat ID | Mitigation                                                                                                                                                                |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-06-01   | Accepted upstream — `PdfChromeConfig.__post_init__` validates tz-awareness and privacy-label regex; composer trusts the frozen dataclass.                                |
| T-06-02   | Mitigated — `test_assemble_pdf_chrome_off_omits_chrome_markers` now locks the None branch against future refactors that might accidentally always emit chrome markup.    |

## Out-of-Scope / Deferred

- **Cover-page trim (drop title/Generated/Sections lines)** — Plan 06-02.
- **`board_summary.run_report()` opt-in to `pdf_chrome`** — Plan 06-03.
- **`run_all.run_group()` privacy-label + scope-subtitle threading** — Plan 06-04.
- **Baseline regen + visual UAT** — Plan 06-05.
- **`management_summary` / `ops_remediation`** — DO NOT TOUCH (CHROME-COMPAT-01); confirmed untouched in this plan.
- **`tests/test_modules_level1.py` `sys.exit()` at import** — pre-existing, unrelated to chrome wiring; not in scope of 06-01.

## Self-Check

- [x] `reports/modules/composer.py` — modified, committed (9cd42b6, 1d3c707).
- [x] `tests/test_phase6_composer_chrome.py` — created, committed (fe32dd9).
- [x] Commits 9cd42b6, 1d3c707, fe32dd9 present in `git log --oneline -5`.
- [x] `reports/modules/pdf_chrome.py` — UNTOUCHED (verified by git status).
- [x] `reports/management_summary.py`, `reports/ops_remediation.py` — UNTOUCHED.
- [x] All 3 new tests pass; Phase 5 chrome tests still pass (15 total).

## Self-Check: PASSED
