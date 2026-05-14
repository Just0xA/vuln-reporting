---
phase: 06-cover-redesign-board-summary-integration
plan: 02
subsystem: reports.modules.composer
tags: [chrome, pdf, cover, subtitle, phase6]
requires:
  - reports/modules/composer.py  # Phase 6 plan 01 — pdf_chrome wire already landed
provides:
  - "Trimmed _PDF_UNIFIED_COVER_TEMPLATE (subtitle + RAG strip only)"
  - "_format_scope_subtitle helper (run_all.py, module-level)"
affects:
  - reports/modules/composer.py
  - run_all.py
  - tests/test_phase6_cover_redesign.py
tech-stack:
  added: []
  patterns:
    - "Value-only scope subtitle; sentence-case 'All assets' default (D-02)"
    - "Risk Status Summary header baked as literal in template (preserves R1 marker)"
key-files:
  created:
    - tests/test_phase6_cover_redesign.py
  modified:
    - reports/modules/composer.py
    - run_all.py
decisions:
  - "D-01 honored: cover body trimmed to scope subtitle + RAG strip"
  - "D-02 honored: _format_scope_subtitle is module-level in run_all.py (RESEARCH Finding 5 recommendation)"
  - "Risk Status Summary header literal-ized in template (was {header} placeholder); R1 marker preserved verbatim"
  - "Optional CSS cleanup of .cover-title/.cover-divider/.cover-meta rules SKIPPED per Karpathy §3 (dead but harmless)"
metrics:
  completed: 2026-05-13
  tasks: 3
  commits: 3
requirements:
  - CHROME-COV-01
  - CHROME-COV-02
---

# Phase 6 Plan 02: Cover Body Redesign Summary

Strips the unified cover template to the scope-subtitle line + RAG strip block now that Phase 6 plan 01 wired the chrome header (title every page) and footer (Generated timestamp + privacy label every page). Adds the single-source-of-truth `_format_scope_subtitle` formatter that plan 06-04 will thread into both the cover-body subtitle and `PdfChromeConfig.subtitle`. Plan 06-03 (board_summary opt-in) is unblocked.

## Tasks Completed

| Task | Name                                                 | Commit  | Files                                |
| ---- | ---------------------------------------------------- | ------- | ------------------------------------ |
| 1    | Trim _PDF_UNIFIED_COVER_TEMPLATE + substitution dict | 23b0315 | reports/modules/composer.py          |
| 2    | Add _format_scope_subtitle helper                    | 9ed08b1 | run_all.py                           |
| 3    | Unit tests (cover trim + formatter)                  | 979d9bb | tests/test_phase6_cover_redesign.py  |

## Diff Summary — Trimmed Template

**Before** (composer.py:378-394, 17 lines):

```html
<div class="report-cover">
  <p class="cover-title">{title}</p>
  <p class="cover-subtitle">{subtitle}</p>
  <hr class="cover-divider">
  <div class="cover-meta">
    <p style="margin:0 0 2mm 0;">Generated: {generated_at}</p>
    <p style="margin:0 0 4mm 0;">Sections: {module_list}</p>
  </div>
  <div class="rag-strip">
    <h2 class="rag-strip-header">{header}</h2>
    <div class="rag-cell-row">
{cells_html}
    </div>
  </div>
</div>
```

**After** (composer.py:378-388, 11 lines):

```html
<div class="report-cover">
  <p class="cover-subtitle">{scope_subtitle}</p>
  <div class="rag-strip">
    <h2 class="rag-strip-header">Risk Status Summary</h2>
    <div class="rag-cell-row">
{cells_html}
    </div>
  </div>
</div>
```

**Lines removed (per CHROME-COV-02):**
- `<p class="cover-title">{title}</p>`
- `<hr class="cover-divider">`
- `<div class="cover-meta">` ... `</div>` wrapper (3 lines including inline `Generated:` and `Sections:` paragraphs)

**Lines preserved:**
- `<div class="report-cover">` wrapper
- `<p class="cover-subtitle">` (placeholder renamed `{subtitle}` → `{scope_subtitle}`)
- `<h2 class="rag-strip-header">Risk Status Summary</h2>` — R1 marker is now baked in as a literal (was `{header}` placeholder). The composer's substitution call already passed the literal `"Risk Status Summary"`, so behavior is identical.
- Full `.rag-strip` / `.rag-cell-row` / per-module rag cell block (CHROME-COV-01).

**Substitution dict change** (`_build_unified_cover_page`, composer.py:919-926):

Before — 6 kwargs into `.format(...)`: `title`, `subtitle`, `generated_at`, `module_list`, `header`, `cells_html`.

After — 2 kwargs: `scope_subtitle`, `cells_html`. (`title`/`generated_at`/`module_list` kept as method parameters because callers still pass them; they're now silently unused inside `_build_unified_cover_page` — full caller cleanup is plan 06-03's surgery.)

## R1 Verification — Risk Status Summary Marker

```
$ grep -n "Risk Status Summary" reports/modules/composer.py
382:    <h2 class="rag-strip-header">Risk Status Summary</h2>
```

Verbatim match with `tests/baseline_utils.py`'s `pdf_has_risk_status_summary_header` extractor expectation. Baseline shape unchanged.

## _format_scope_subtitle Helper

Placed module-level in `run_all.py` immediately above `run_group()` per RESEARCH Finding 5 (single source of truth; future `composed_report` inherits for free).

```python
def _format_scope_subtitle(tag_category: str | None, tag_value: str | None) -> str:
    return tag_value if (tag_category and tag_value) else "All assets"
```

NOT wired into `run_group()` in this plan — plan 06-04 owns the wiring into the `slug == "board_summary"` kwarg block.

## Tests Added — 6 PASS

| Test                                                          | Asserts                                                                              |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `test_format_scope_subtitle_no_filter_returns_all_assets`     | `f(None, None) == "All assets"`                                                      |
| `test_format_scope_subtitle_full_filter_returns_value_only`   | `f("Environment", "Production") == "Production"`                                     |
| `test_format_scope_subtitle_partial_filter_returns_all_assets`| `f("Environment", None)` and `f(None, "Production")` both `== "All assets"`          |
| `test_cover_template_removes_legacy_elements`                 | Template missing `cover-title`, `cover-divider`, `cover-meta`, `Generated:`, `Sections:` |
| `test_cover_template_preserves_rag_strip_marker`              | Template contains `"Risk Status Summary"` AND `"rag-strip"` (CHROME-COV-01, R1)      |
| `test_built_cover_renders_scope_subtitle`                     | Rendered HTML from `_build_unified_cover_page(...)` contains `"Production"` + `"Risk Status Summary"` AND no legacy markers |

Pass evidence:

```
tests/test_phase6_cover_redesign.py ......                               [100%]
======================= 6 passed, 14 warnings in 0.88s ========================
```

Regression sweep — `tests/test_phase6_composer_chrome.py` (3 passed). `tests/test_phase2_composer_pipeline.py` collected 0 items (no test functions, matches 06-01 SUMMARY observation).

## RESEARCH.md Finding 6 — Verified

Grep for the removed strings inside `tests/`:

```
$ Grep cover-title|cover-meta|cover-divider tests/
Found 1 file: tests/test_phase6_cover_redesign.py
```

Only hit is the new file from Task 3, which asserts the strings are ABSENT. Zero pre-existing tests assert on the removed cover-body strings. No regression risk from Finding 6.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Test skeleton called wrong signature**
- **Found during:** Task 3.
- **Issue:** Plan skeleton suggested `_build_unified_cover_page(scope_subtitle="Production", modules=[])`. Actual method signature is `(self, results: list[ModuleData], *, title, subtitle, generated_at_str, module_list_str)`.
- **Fix:** Constructed a real `ReportComposer` (mirroring 06-01's `_make_composer` pattern) and called `composer._build_unified_cover_page([], title=..., subtitle="Production", generated_at_str=..., module_list_str="")`. The plan's load-bearing intent — "scope subtitle ends up in rendered HTML" — is preserved.
- **Files:** `tests/test_phase6_cover_redesign.py`.
- **Commit:** 979d9bb.

**2. [Rule 1 — Minor] `{header}` placeholder in template**
- **Found during:** Task 1.
- **Issue:** The original template carried `<h2 class="rag-strip-header">{header}</h2>` with the caller passing the literal `"Risk Status Summary"` in the `.format()` call. The plan's `<interfaces>` block specifies the literal string be in the template itself.
- **Fix:** Baked `"Risk Status Summary"` directly into the template (matching the plan spec). Removed `header=...` from the substitution dict. Behavior identical — the rendered HTML is byte-equivalent.
- **Commit:** 23b0315.

**3. [Rule 3 — Blocking] `tests/` is gitignored**
- **Issue:** `.gitignore` line 59 excludes `tests/`. `git add` rejected the new file.
- **Fix:** Used `git add -f` (matches Phase 5 + 06-01 precedent).
- **Commit:** 979d9bb.

### Karpathy §3 Discretion

Optional CSS cleanup of `.cover-title`, `.cover-divider`, `.cover-meta` rules in `_PDF_CSS` (composer.py:70-374): **SKIPPED**. The plan allowed it ("you MAY trim now-dead CSS rules…If touching them is non-trivial or risks merge friction, LEAVE THEM"). Surgical-changes principle wins — dead-but-harmless CSS is out of scope for cover-body redesign.

### Caller Cleanup Deferred

`_build_unified_cover_page`'s `title`, `generated_at_str`, and `module_list_str` parameters are now unused inside the method body. The `assemble_pdf` caller (composer.py:707-713) still passes them. Both are harmless dead arguments; full signature pruning is plan 06-03's natural scope when `board_summary` re-wires the call site for chrome opt-in.

## Threat Mitigations Applied

| Threat ID | Mitigation                                                                                                                                                     |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-06-03   | `safe_scope_subtitle = html.escape(str(subtitle), quote=True)` — same escape pattern as the prior `safe_title` / `safe_subtitle` interpolations. No regression. |

## Out-of-Scope / Deferred

- **`board_summary.run_report()` opt-in to `pdf_chrome` / `scope_subtitle` kwarg** — Plan 06-03.
- **`run_all.run_group()` resolving `scope_subtitle` and threading into report_kwargs** — Plan 06-04.
- **Baseline regen + operator visual UAT** — Plan 06-05.
- **`reports/modules/pdf_chrome.py`, `reports/management_summary.py`, `reports/ops_remediation.py`** — UNTOUCHED, verified by `git status`.
- **`_PDF_RAG_STRIP_TEMPLATE` deprecated alias (composer.py:402)** — auto-tracks via Python name binding (R4); no action needed.
- **Pruning unused `title`/`generated_at_str`/`module_list_str` parameters from `_build_unified_cover_page`** — defer to plan 06-03's caller rewire.
- **Dead `.cover-title`/`.cover-divider`/`.cover-meta` CSS rules in `_PDF_CSS`** — Karpathy §3 discretion; harmless.

## Self-Check

- [x] `reports/modules/composer.py` — modified, committed (23b0315). `_PDF_UNIFIED_COVER_TEMPLATE` trimmed; substitution dict matches.
- [x] `run_all.py` — `_format_scope_subtitle` added, committed (9ed08b1).
- [x] `tests/test_phase6_cover_redesign.py` — created, 6 tests pass, committed (979d9bb).
- [x] Commits 23b0315, 9ed08b1, 979d9bb present in `git log --oneline -5`.
- [x] `reports/modules/pdf_chrome.py` — UNTOUCHED.
- [x] `reports/management_summary.py`, `reports/ops_remediation.py` — UNTOUCHED.
- [x] R1 marker `"Risk Status Summary"` present verbatim in trimmed template (composer.py:382).
- [x] RESEARCH Finding 6 re-verified: zero pre-existing tests assert on removed strings.

## Self-Check: PASSED
