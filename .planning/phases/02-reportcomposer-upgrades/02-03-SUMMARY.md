---
phase: 02-reportcomposer-upgrades
plan: 03
subsystem: report-composer
tags:
  - composer
  - excel
  - analyst-workbook
  - phase-2
requirements:
  - COMPOSER-03
dependency_graph:
  requires:
    - reports/modules/base.py (Phase 1 BaseModule.render_analyst_tabs contract — no-op default returns [])
    - reports/modules/composer.py (existing assemble_excel iteration / try-except pattern; existing _write_metadata_tab two-column layout)
    - reports/modules/registry.py (registry.get for module class lookup)
  provides:
    - reports.modules.composer.ReportComposer.assemble_analyst_workbook — NEW public method
    - reports.modules.composer._unique_sheet_name — NEW module-level helper (Excel 31-char-aware)
    - reports.modules.composer._write_analyst_metadata_tab — NEW module-level helper (D-19 _Metadata)
  affects:
    - none — fully additive; no existing surface mutated
tech-stack:
  added: []
  patterns:
    - Deferred openpyxl import (`# noqa: PLC0415`) inside method body to keep module-level surface lean (CONVENTIONS.md)
    - Per-module exception isolation (try/except + log + record in failures list) mirroring assemble_excel() pattern at composer.py:822-833 (D-28)
    - Empty-contribution skip rule (D-20) before sheet-name allocation — empty DataFrames never inflate used_names
    - Two-pass write (collect-then-emit) so D-20 all-empty fallback can return None and write nothing to disk
    - Defensive shape validation — non-list returns and malformed (str, df) tuples are logged + skipped, never raised
key-files:
  created: []
  modified:
    - reports/modules/composer.py — assemble_analyst_workbook() public method + _unique_sheet_name() / _write_analyst_metadata_tab() module-level helpers (+327 lines net)
decisions:
  - D-16 honored — caller passes the output_path; composer does NOT compute the filename itself
  - D-17 honored — tabs appear in _module_configs order; per-module multi-tab returns concatenated sequentially
  - D-18 honored — sheet-name collisions auto-suffix _2/_3; Excel 31-char limit respected (defensive 100-attempt cap raises ValueError)
  - D-19 honored — _Metadata tab carries exactly Report / Generated / Scope / Modules; per-tab row counts and run duration deliberately OUT
  - D-20 honored — all-empty workbook (every module returned [] or empty DataFrames) → returns None and writes nothing to disk
  - D-21 honored — workbook lands in directory passed by caller; flat layout, no analyst/ subdirectory inside the composer
  - D-25 honored — Phase 4 opt-out hook in place: generate=True keyword-only param; generate=False returns None immediately without iterating modules or importing openpyxl
  - D-28 honored — per-module render_analyst_tabs() exception caught + logged + recorded in failures list; module's tabs skipped but workbook still renders for surviving modules
metrics:
  completed: 2026-05-06
  duration: ~10 minutes
  tasks: 2
  files_modified: 1
  commits: 2
---

# Phase 2 Plan 03: Analyst Workbook Assembly — Summary

Implements COMPOSER-03 — the analyst-detail companion workbook channel of the four-channel module render contract. The composer gains a public `assemble_analyst_workbook(results, output_path, *, slug, scope_label, generate)` that drives `render_analyst_tabs()` per module into a separate `.xlsx`. After Phase 2, board / management modules can be migrated (Phase 3) to override `render_analyst_tabs()` and produce drill-down rows for analysts; Phase 2 ships the composer machinery against Phase 1's no-op `[]` defaults so the all-empty path is exercised end-to-end before any module migration.

## What Shipped

### Task 1 — `_unique_sheet_name()` and `_write_analyst_metadata_tab()` helpers (composer.py)

- Added `_unique_sheet_name(name: str, used: set[str]) -> str` at module scope below `_write_metadata_tab`:
  - Returns `name[:31]` when not in `used` (Excel 31-char limit, D-18).
  - On collision, walks suffixes `_2`, `_3`, ... while truncating the base name to keep total length ≤ 31.
  - Raises `ValueError` after 99 attempts (T-02-03-05 — pathological-input defensive guard).
  - Includes the documented "Collision semantics note" in the docstring (acknowledges Excel's own limitation when two long names share their first 31 characters).
- Added `_write_analyst_metadata_tab(workbook, *, slug, generated_at, scope_label, module_ids, failures) -> str` at module scope:
  - Writes the four D-19 canonical key/value rows: Report (slug), Generated (UTC timestamp via `.strftime("%Y-%m-%d %H:%M UTC")` or `str()` fallback), Scope (`scope_label or "All Assets"`), Modules (comma-joined IDs).
  - When `failures` is non-empty, appends a "Failures" subsection at A6 with header row (Module ID / Error) and one row per failure (D-28 audit trail).
  - Returns the literal `"_Metadata"` tab name; mirrors the existing `_write_metadata_tab()` shape but emits Phase 2 D-19 fields instead of the audit summary fields.
- **File:** `reports/modules/composer.py` (helpers at lines 1192-1340)
- **Commit:** `c2b2909`

### Task 2 — `ReportComposer.assemble_analyst_workbook()` method (composer.py)

- Added new public method `assemble_analyst_workbook(self, results, output_path, *, slug='', scope_label='', generate=True) -> Optional[Path]` between `assemble_excel()` and the `# Email KPI collection` banner.
- Three keyword-only parameters: `slug`, `scope_label`, `generate` — all verified via `inspect.signature` in the verify command.
- `generate=False` short-circuits to `None` immediately — no module iteration, no openpyxl import (D-25 Phase 4 opt-out hook).
- Defers `import openpyxl  # noqa: PLC0415` to inside the method body so the composer's module-level imports surface stays lean (CONVENTIONS.md compliance).
- Iterates `results` in `_module_configs` order. For each module:
  - Registry miss → log warning, append `(module_id, "module not registered")` to failures, continue.
  - `render_analyst_tabs()` raises → log traceback, append `(module_id, "{ExcType}: {message}")` to failures, continue (D-28 exception isolation mirroring `assemble_excel()`'s pattern at composer.py:822-833).
  - Non-list return → log warning, append failure entry, continue (T-02-03-04 mitigation).
  - For each `(sheet_name, df)` entry: shape-check `(tuple, len 2, str sheet)`; skip when `df is None / not a DataFrame / df.empty` (D-20 contributing rule); allocate a unique sheet name via `_unique_sheet_name()` and queue.
- After iteration: if `collected` list is empty → return `None` and write nothing to disk (D-20 all-empty fallback).
- Otherwise: open `openpyxl.Workbook`, remove default blank sheet, write each `(sheet_name, df)` as one tab (header from `df.columns`, data rows from `df.itertuples(index=False)`), append `_Metadata` tab via `_write_analyst_metadata_tab()` with the failures list, save to `str(output_path)`, return `output_path`.
- **File:** `reports/modules/composer.py` (method at lines 856-1038)
- **Commit:** `f25cf85`

## Confirmation: Byte-Unchanged Surfaces

| Surface | Status |
|---------|--------|
| `reports/modules/composer.assemble_pdf` / `_build_rag_strip_page` / `assemble_excel` / `assemble_email_body` / `collect_email_kpis` / `collect_audit_info` / `get_error_summary` / `_config_for` / `_warn_invalid_configs` / `run_all` / `run_module` | byte-unchanged — Plan 02-03 is purely additive |
| `reports/modules/composer.py` module-level imports (`logging`, `traceback`, `datetime`, `typing`, `pandas`, `BaseModule`, `ModuleConfig`, `ModuleData`, `registry`) | byte-unchanged — assemble_analyst_workbook reuses existing `traceback`, `Optional`, `Any`, `logger`, `pd`, `registry` |
| `reports/modules/composer._error_data` / `_write_error_tab` / `_write_metadata_tab` | byte-unchanged — new helpers added at the END of the module after these |
| `reports/modules/base.BaseModule.render_analyst_tabs` (Phase 1 contract — no-op default returns `[]`) | byte-unchanged — Plan 02-03 only consumes the contract; doesn't extend it |
| `reports/modules/registry.py` | byte-unchanged |
| `delivery/email_template.py` and `templates/report_email.html` | byte-unchanged — Plan 02-03 is composer-internal only |
| 8 module discovery (board + management board metric modules) | unchanged — `len(registry._modules) == 8` after import |

## Verification Evidence

Both Task `<verify>` commands pass end-to-end:

```text
Task 1 — helpers OK
        _unique_sheet_name('Hello', set()) == 'Hello'                  ✓
        _unique_sheet_name('Hello', {'Hello'}) == 'Hello_2'            ✓
        _unique_sheet_name('Hello', {'Hello','Hello_2'}) == 'Hello_3'  ✓
        _unique_sheet_name('X'*50, set()) == 'X'*31                    ✓ (Excel 31-char clip)
        _unique_sheet_name('X'*50, {'X'*31}) == 'X'*29 + '_2'          ✓ (clip-with-suffix to fit 31)
        _write_analyst_metadata_tab — D-19 rows present, no Failures   ✓
        _write_analyst_metadata_tab — Failures subsection at A6/A7/A8  ✓

Task 2 — assemble_analyst_workbook OK
        signature: (self, results, output_path, *, slug, scope_label, generate)  ✓
        generate=False -> None, no file written                              ✓
        all-empty results -> None, no file written (D-20)                    ✓
        successful path: workbook written, 'Tab Alpha' + 'Tab Alpha_2' tabs  ✓ (collision auto-suffix)
        empty df contribution skipped ('Empty' not in sheetnames)            ✓
        _Metadata tab present with D-19 rows                                  ✓
        Failures subsection records the raising stub                          ✓
```

Acceptance-criteria grep counts:

| Pattern | File | Expected | Actual |
|---------|------|----------|--------|
| `def _unique_sheet_name` | reports/modules/composer.py | 1 | 1 ✓ |
| `def _write_analyst_metadata_tab` | reports/modules/composer.py | 1 | 1 ✓ |
| `def assemble_analyst_workbook` | reports/modules/composer.py | 1 | 1 ✓ |
| `Collision semantics note` | reports/modules/composer.py | ≥ 1 | 1 ✓ |
| `import openpyxl  # noqa: PLC0415` | reports/modules/composer.py | ≥ 1 | 1 ✓ |
| `openpyxl` as a module-level public binding | reports/modules/composer.py | absent | absent ✓ (deferred only) |
| `_write_analyst_metadata_tab` line > `_write_metadata_tab` line | reports/modules/composer.py | true | 1246 > 1137 ✓ |
| `_unique_sheet_name` line > `_write_metadata_tab` line | reports/modules/composer.py | true | 1192 > 1137 ✓ |

Module imports cleanly: `python -c "from reports.modules import ReportComposer; print('OK')"` prints `OK`.

## Deviations from Plan

None. D-16, D-17, D-18, D-19, D-20, D-21, D-25, D-28 honored verbatim. No Rule-1, Rule-2, or Rule-3 auto-fixes were required — every step matched the plan's exact code blocks. No new module-level imports were added (the `openpyxl` import is deferred inside the method body per CONVENTIONS.md).

## Threat Flags

None. The implementation respects the threat register decisions documented in the plan:

- **T-02-03-01** (path traversal via `output_path`) — accepted; composer is a library, sanitization happens at run_all.py / report-script level. v1 has no user-supplied path inputs flowing here.
- **T-02-03-02** (DoS via huge module DataFrame) — accepted; modules are project-internal, row counts bounded by Tenable export size (~180k findings max in observed practice). openpyxl handles up to 1M rows per sheet.
- **T-02-03-03** (render exception kills entire workbook) — mitigated via `try/except Exception` mirroring `assemble_excel()`'s pattern at composer.py:822-833. Logs traceback, records failure in `failures` list, continues to next module. Workbook still renders for the modules that succeeded.
- **T-02-03-04** (tampering — module returns malformed analyst-tab list) — mitigated via `isinstance(tabs, list)` guard plus per-entry `isinstance(entry, tuple) and len(entry) == 2 and isinstance(entry[0], str)` shape validation. Bad entries logged and skipped, not raised.
- **T-02-03-05** (resource exhaustion — pathological sheet-name collision) — mitigated via `_unique_sheet_name`'s `range(2, 100)` bound + ValueError. Helper terminates rather than spinning forever on degenerate inputs.

No new security-relevant surface introduced (no new network endpoints, no new auth paths, no schema changes at trust boundaries).

## Self-Check: PASSED

- File `reports/modules/composer.py` exists. `assemble_analyst_workbook` method present at line 856. `_unique_sheet_name` helper at line 1192. `_write_analyst_metadata_tab` helper at line 1246.
- Deferred `import openpyxl  # noqa: PLC0415` present once inside method body; no module-level openpyxl binding.
- Commit `c2b2909` (Task 1) — present in git log.
- Commit `f25cf85` (Task 2) — present in git log.
