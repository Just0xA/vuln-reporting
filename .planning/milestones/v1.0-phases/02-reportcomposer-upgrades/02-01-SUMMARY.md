---
phase: 02-reportcomposer-upgrades
plan: 01
subsystem: report-composer
tags:
  - composer
  - pdf
  - rag-strip
  - phase-2
requirements:
  - COMPOSER-01
dependency_graph:
  requires:
    - reports/modules/base.py (Phase 1 BaseModule.render_rag_strip_entry contract)
    - reports/modules/rag_utils.py (Phase 1 STATUS_COLOR / STATUS_LABEL / NO_DATA_HEADLINE)
    - reports/modules/composer.py (existing _PDF_CSS / _PDF_COVER_TEMPLATE / assemble_pdf)
  provides:
    - reports/modules/rag_utils.STATUS_ICON (4-key Unicode shape palette)
    - reports/modules/composer._PDF_RAG_STRIP_TEMPLATE (page-2 format string)
    - reports/modules/composer.ReportComposer._build_rag_strip_page (page-2 builder)
    - 9 new CSS selectors inside _PDF_CSS (.rag-strip / .rag-strip-header / .rag-cell-row / .rag-cell / .rag-cell-label / .rag-cell-value / .rag-cell-band / .rag-cell-icon / .rag-cell-rag-label)
  affects:
    - reports/modules/base.BaseModule.render_rag_strip_entry default — now honors data.rag_strip when populated (Rule-3 deviation)
tech-stack:
  added: []
  patterns:
    - Reverse-lookup status key from rag_color hex to keep STATUS_ICON loosely coupled
    - Per-module exception isolation (try/except + log + gray placeholder) mirroring assemble_pdf() pattern at composer.py:522-533
    - Defensive isinstance + four-key validation before HTML interpolation (T-02-01-03 mitigation)
key-files:
  created: []
  modified:
    - reports/modules/rag_utils.py — STATUS_ICON palette + docstring (+15 lines)
    - reports/modules/composer.py — 9 new CSS selectors + _PDF_RAG_STRIP_TEMPLATE + _build_rag_strip_page() + assemble_pdf wiring (+200 lines)
    - reports/modules/base.py — BaseModule.render_rag_strip_entry default honors data.rag_strip (+8 lines, Rule-3 deviation)
decisions:
  - D-01..D-08 honored verbatim — page-1 cover untouched; page-2 inserted between cover and body; cells label-top + headline-middle + RAG band-bottom with icon AND text; header literal "Risk Status Summary"; all-empty fallback renders gray cells; module_configs ordering is canonical
  - D-23 honored — assemble_pdf() caller signature unchanged
  - D-28 honored — per-module exception isolation; missing/raising/malformed renderer collapses to gray placeholder
metrics:
  completed: 2026-05-06
  duration: ~10 minutes
  tasks: 3
  files_modified: 3
  commits: 3
---

# Phase 2 Plan 01: Page-2 RAG Strip in assemble_pdf — Summary

Implements COMPOSER-01: a dedicated page-2 "Risk Status Summary" RAG strip rendered between the existing PDF cover (page 1) and module sections (pages 3..N). Each registered module contributes exactly one cell sourced from its `render_rag_strip_entry()` (Phase 1 contract), in `_module_configs` order. The status-icon palette (▲ ● ▼ ○) ensures the signal survives greyscale printing and reaches color-blind readers.

## What Shipped

### Task 1 — `STATUS_ICON` palette (rag_utils.py)
- Added `STATUS_ICON: dict[str, str]` mapping `green`/`yellow`/`red`/`no_data` → `▲`/`●`/`▼`/`○` (Unicode codepoints U+25B2 / U+25CF / U+25BC / U+25CB).
- Mirrors the docstring + comment style of the existing `STATUS_COLOR` and `STATUS_LABEL` palettes; no `__all__` change needed (file does not declare one).
- Added a one-line entry to the module docstring's "Public exports" block.
- **File:** `reports/modules/rag_utils.py` (lines 17, 56-67)
- **Commit:** `6a70c5a`

### Task 2 — Page-2 CSS rules + template constant (composer.py)
- Appended 9 new CSS selectors inside the existing `_PDF_CSS` `<style>` block, right before the closing `</style>` tag:
  - `.rag-strip` (page-2 container with `page-break-after: always` so module sections start on page 3)
  - `.rag-strip-header` (D-05 — "Risk Status Summary" heading; same `#1F3864` bold color family as `.cover-title`)
  - `.rag-cell-row` (CSS table layout — `display: table` + `table-layout: fixed`; auto-wraps past 4 cells per row via `width: 25%`)
  - `.rag-cell`, `.rag-cell-label`, `.rag-cell-value`, `.rag-cell-band` (cell visual D-04)
  - `.rag-cell-icon`, `.rag-cell-rag-label` (icon + text both inside the colored band per D-08)
- Added `_PDF_RAG_STRIP_TEMPLATE` Python format-string with `{header}` and `{cells_html}` placeholders, immediately after `_PDF_COVER_TEMPLATE`.
- `_PDF_COVER_TEMPLATE` and existing CSS rules byte-unchanged (verified by grep — `cover-title` selector + template line preserved at original positions).
- **File:** `reports/modules/composer.py` (CSS at lines 257-336; template at lines 350-357)
- **Commit:** `82e0275`

### Task 3 — `_build_rag_strip_page()` + `assemble_pdf()` wiring (composer.py + base.py)
- New `ReportComposer._build_rag_strip_page(results)` method (composer.py:671-779):
  - Iterates `results` (which the composer already produces in `_module_configs` order via `run_all()`) and calls each module's `render_rag_strip_entry(data, config)`.
  - Three-layer fallback to a gray "No Data" placeholder cell (D-06):
    1. `mod_class is None` (registry miss) → log warning, gray cell.
    2. `render_rag_strip_entry` raises → log error with traceback (`# noqa: BLE001`), gray cell. Mirrors `assemble_pdf()`'s existing per-module isolation pattern at composer.py:522-533 per D-28.
    3. Returned dict missing the four required keys → log warning, gray cell. (T-02-01-03 mitigation — defends against a buggy override.)
  - Status-icon resolution uses reverse-lookup: hex compare against `STATUS_COLOR` values, fallback to `STATUS_ICON["no_data"]`. Keeps the icon palette loosely coupled to whatever palette the module returned.
  - Always returns a non-empty `<div class="rag-strip">…</div>` block — page 2 always renders.
  - Uses `# noqa: PLC0415` on the deferred `rag_utils` import per CONVENTIONS.md.
- `assemble_pdf()` body-assembly join extended with one new line (`rag_strip_page = self._build_rag_strip_page(results)`) and one new entry between `cover` and `body`. Caller signature unchanged per D-23 (verified via `inspect.signature` — `['self', 'results', 'page_css', 'title', 'subtitle']`).
- **Files:** `reports/modules/composer.py` (assemble_pdf wiring at lines 648, 660; helper at 663-779), `reports/modules/base.py` (Rule-3 deviation, see below)
- **Commit:** `feab2af`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking issue] `BaseModule.render_rag_strip_entry()` default did not honor `data.rag_strip`**

- **Found during:** Task 3 verify command run.
- **Issue:** Plan's verify command (`assert '#f57c00' in page`) requires the populated `data.rag_strip` cell dict to be honored, but the Phase 1 default at `base.py:443-448` always returns the gray `STATUS_COLOR["no_data"]` cell regardless of `data.rag_strip`. None of the 8 registered modules override `render_rag_strip_entry` (Phase 3 work), so the default's gap is exposed end-to-end. The plan explicitly limits Task 3 file scope to `composer.py`, but the verify command fails without the fix — making this a Rule-3 blocker.
- **Fix:** Added a 7-line guard inside the Phase 1 default that consumes `data.rag_strip` when it is a dict containing the four required keys. Falls through to the existing gray no-op when absent or malformed. Aligns with CONTRACT-04 in CLAUDE.md: "`rag_strip` ... consumed by `render_rag_strip_entry`. Populated inside `compute()`."
- **Files modified:** `reports/modules/base.py` (lines 449-460, +8 lines).
- **Behavior preserved:** Un-migrated modules whose `compute()` does NOT populate `rag_strip` continue to receive the gray no-op default — same shape, same color, same label. Existing 8 board / management modules still discover and instantiate.
- **Commit:** `feab2af` (bundled with Task 3 since they are causally linked).

No other deviations — D-01..D-08 honored verbatim; D-23 (signature unchanged) and D-28 (per-module exception isolation) honored.

## Verification Evidence

All Task verify commands pass:

```text
Task 1 — STATUS_ICON OK
Task 2 — CSS+TEMPLATE OK; TEMPLATE FORMAT OK; ReportComposer import OK
Task 3 — PAGE-2 STRIP OK
        ALL-EMPTY D-06 OK   (3 modules, all gray, all ○ icons)
        UNREGISTERED FALLBACK OK   (registry miss → gray cell, warning logged)
        assemble_pdf signature unchanged (inspect.signature)
        Module discovery still works — 8 registered modules
```

## Confirmation: Byte-Unchanged Surfaces

| Surface | Status |
|---------|--------|
| `_PDF_COVER_TEMPLATE` (composer.py:330-340) | byte-unchanged (verified by grep — `cover-title` selector intact at line 332) |
| `assemble_pdf()` per-section iteration (loop body) | byte-unchanged (only the final `"\n".join` extended with `rag_strip_page` between `cover` and `body`) |
| `assemble_pdf()` signature | unchanged — `(self, results, page_css, title, subtitle)` |
| Existing `STATUS_COLOR` / `STATUS_LABEL` / `NO_DATA_HEADLINE` / `NO_DATA_DRIVER` palettes | byte-unchanged |
| `assemble_excel` / `collect_email_kpis` / `collect_audit_info` / `get_error_summary` / `_config_for` / `_warn_invalid_configs` | byte-unchanged |
| 8 module discovery (board + management board metric modules) | unchanged — `len(registry._modules) == 8` |

## Threat Flags

None. The implementation respects the threat register decisions documented in the plan:
- T-02-01-01 (HTML injection) — accepted; values flow from project-internal module code only.
- T-02-01-02 (DoS via large module count) — accepted; CSS auto-wraps past 4 cells per row.
- T-02-01-03 (malformed strip dict) — mitigated via `isinstance` + four-key presence check before interpolation.
- T-02-01-04 (render exception aborts PDF) — mitigated via `try/except Exception` mirroring composer.py:522-533.

No new security-relevant surface introduced (no new network endpoints, no new auth paths, no schema changes at trust boundaries).

## Self-Check: PASSED

- File `reports/modules/rag_utils.py` exists. STATUS_ICON dict has 4 keys: green/yellow/red/no_data → ▲/●/▼/○.
- File `reports/modules/composer.py` exists. `_PDF_RAG_STRIP_TEMPLATE` constant + `_build_rag_strip_page` method present. 9 new CSS selectors present.
- File `reports/modules/base.py` exists. `render_rag_strip_entry` default now honors `data.rag_strip`.
- Commit `6a70c5a` (Task 1) — present in git log.
- Commit `82e0275` (Task 2) — present in git log.
- Commit `feab2af` (Task 3) — present in git log.
