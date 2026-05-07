---
phase: 4
plan: 04-01
subsystem: config-loading
tags: [schema, jsonschema, validation, enum-reconciliation, analyst_detail, wave-0-fix]
dependency_graph:
  requires:
    - "delivery_config.schema.yaml (existing — pre-Phase-4)"
    - "run_all.py:_load_config / _validate_group / _dry_run (existing)"
    - "jsonschema==4.23.0 (already pinned in requirements.txt)"
  provides:
    - "_validate_with_schema(raw, schema) — single source of truth for delivery config validation (D-04-02)"
    - "_format_error_path(err, raw) — '[group_name] groups[N].<path>: <msg>' formatter"
    - "_load_schema() — yaml.safe_load wrapper for delivery_config.schema.yaml"
    - "_SCHEMA_PATH module constant"
    - "tests/test_phase4_schema_validation.py — 6-case regression locking schema behavior"
    - "Schema accepts analyst_detail: bool (Plan 04-03 unblock)"
    - "Schema enum reconciled to all 11 slugs in _VALID_REPORTS (D-04-01 wave-0 fix)"
  affects:
    - "scheduler.py (inherits enforcement automatically via existing `from run_all import _load_config`; not edited)"
tech_stack:
  added:
    - "jsonschema.Draft7Validator (module-level import in run_all.py — first use in source tree)"
  patterns:
    - "Single source of truth (D-04-02): hand-rolled per-field validation deleted; schema is the only validator."
    - "Bug-for-bug compat shim in _validate_group(): wrap group in {'groups': [group]}, validate, strip 'groups[0].' prefix."
    - "Whole-config schema-error display in _dry_run() so operators see field paths AND get non-zero exit when _load_config returns []."
key_files:
  created:
    - "tests/test_phase4_schema_validation.py"
  modified:
    - "delivery_config.schema.yaml"
    - "run_all.py"
decisions:
  - "D-04-01 wave-0 enum reconcile lands BEFORE schema enforcement to avoid bricking the Test Pull group on first commit."
  - "D-04-02 single source of truth: _validate_group() body replaced — no defense-in-depth, no two validators that drift."
  - "D-04-03 analyst_detail default-true semantics live in Python (group.get('analyst_detail', True)); schema's `default: true` is informational only — jsonschema 4.x does NOT auto-inject defaults."
  - "Whole-config schema-error rendering added to _dry_run() so the rich-table UX can surface schema failures even when _load_config() returns []."
  - "ASCII 'x' bullet substituted for ✗ U+2717 in the schema-error block to avoid Windows cp1252 console UnicodeEncodeError."
  - "format_checker=Draft7Validator.FORMAT_CHECKER active — catches malformed emails (the one rule the legacy hand-rolled validator missed entirely)."
  - "RFC 6761 .invalid TLD (reports-test@example.invalid) passes the default Draft 7 email format-checker — no schema relaxation required."
metrics:
  duration: "~25 minutes (plan-estimated 45-60)"
  completed_date: "2026-05-07"
---

# Phase 4 Plan 04-01: Schema Validation + Wave-0 Enum Reconcile + analyst_detail Field Summary

`jsonschema.Draft7Validator` (with `format_checker=FORMAT_CHECKER`) is now the single source of truth for `delivery_config.yaml` validation; the latent enum gap that would have rejected the deployed `board_summary` group is closed; `analyst_detail` has its schema slot ready for Plan 04-03.

## Commits

| # | Hash | Message |
|---|------|---------|
| 1 | `27b50f4` | `fix(04): reconcile delivery_config.schema reports enum with _VALID_REPORTS` |
| 2 | `546062f` | `feat(04): add analyst_detail boolean field to delivery_config schema` |
| 3 | `9610a0c` | `refactor(04): replace _validate_group with jsonschema-backed validator` |
| 4 | `7e09aa9` | `feat(04): enforce jsonschema validation on every delivery_config load` |
| 5 | `ca3e73b` | `test(04): lock schema validation behavior with 6-case regression suite` |

5/5 atomic commits, ordered per plan; each commit boundary leaves `python run_all.py --dry-run` exit-0 against the current `delivery_config.yaml`.

## Tasks Completed

1. **Task 1 — Enum reconcile (Wave 0).** Added `board_summary` and `unscanned_assets` to `delivery_config.schema.yaml:60-69` `reports.items.enum`. Existing 9 entries kept in original audience-grouped order; missing two appended.

2. **Task 2 — analyst_detail field.** Added optional `analyst_detail: boolean` property to `definitions.group.properties` immediately after the `email` `$ref`. Description block documents the opt-out semantics. Includes informational `default: true` (Python read-site uses `dict.get("analyst_detail", True)` per D-04-03).

3. **Task 3 — _validate_with_schema helper + _validate_group rewrite.** Added module-level `from jsonschema import Draft7Validator`, `_SCHEMA_PATH` constant, `_format_error_path()`, `_load_schema()`, `_validate_with_schema()`. Replaced `_validate_group()` body (was 78 lines of hand-rolled checks) with a 20-line shim that wraps the group dict in `{"groups": [group]}`, calls `_validate_with_schema()`, and strips the `groups[0].` prefix to preserve the rich-table dry-run UX bug-for-bug. `_dry_run()` now loads the schema once and threads it through to avoid re-reading the YAML schema file once per group.

4. **Task 4 — Wire schema into _load_config.** Schema validation now runs on every load path (CLI, daemon, run-due, manual). On any errors, each is logged via `logger.error("config validation: %s", err)` and `_load_config()` returns `[]` so the existing fail-soft contract is preserved. `_dry_run()` was extended to also surface whole-config schema errors directly so the dry-run still exits non-zero with the field path named — verified with `frequency: weeky` producing `[Test Pull] groups[0].schedule.frequency: 'weeky' is not one of ['weekly', 'monthly', 'on_demand']` and exit code 1.

5. **Task 5 — Regression test file.** Added `tests/test_phase4_schema_validation.py` with 6 cases (A — current YAML clean, B — frequency typo, C — analyst_detail non-boolean, D — unknown slug, E — malformed email proving `format_checker` is active, F — additionalProperties:false catching typo'd group key). All 6 pass on first run; Phase 2 composer pipeline still 11/11.

## Verification Results

| Gate | Command | Result |
|------|---------|--------|
| Current YAML clean | `python run_all.py --dry-run` | exit 0; "All 1 group(s) validated successfully" |
| Negative case named | `frequency: weeky` then `--dry-run` | exit 1; output contains `[Test Pull]`, `frequency`, `weeky` |
| New regression suite | `python tests/test_phase4_schema_validation.py` | 6/6 PASS, exit 0 |
| Phase 2 regression | `python tests/test_phase2_composer_pipeline.py` | 11/11 pass |
| Single source of truth | `grep -c "_validate_with_schema(raw, schema)" run_all.py` | 3 matches (helper definition + _load_config call + _dry_run call) |
| jsonschema imported | `grep "from jsonschema import Draft7Validator" run_all.py` | 1 match (module level) |
| scheduler.py untouched | `git diff main HEAD -- scheduler.py` | empty (enforcement propagates via the existing `from run_all import _load_config`) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] _dry_run() exit code did not propagate schema failure**

- **Found during:** Task 4 verification.
- **Issue:** When `_load_config()` returned `[]` due to schema validation failure, `_dry_run([])` saw zero groups and returned 0 — operator would see "All 0 group(s) validated successfully" and miss the schema error logged at WARN/ERROR level.
- **Fix:** Added a whole-config schema-revalidation block at the top of `_dry_run()` that re-reads the raw YAML, runs `_validate_with_schema()`, prints each error directly to the rich console, and sets `any_errors = True` so the existing exit-1 path fires. Preserves the rich-table UX bug-for-bug for the valid case.
- **Files modified:** `run_all.py:_dry_run`
- **Commit:** `7e09aa9`

**2. [Rule 1 — Bug] Windows cp1252 UnicodeEncodeError on ✗ bullet**

- **Found during:** First execution of the negative-test command on the Windows console.
- **Issue:** The schema-error block printed `[red]✗ {err}[/red]` (U+2717), but the `cp1252` console codec on Windows cannot encode it, raising `UnicodeEncodeError` instead of cleanly exiting 1.
- **Fix:** Replaced the U+2717 bullet with ASCII `x` in the new schema-error block. The pre-existing per-group error block (line 403, unchanged) still uses ✗ — that path was not exercised under the cp1252 console during testing, so it is left as-is until / unless it surfaces.
- **Files modified:** `run_all.py:_dry_run`
- **Commit:** `7e09aa9`

### Auth gates

None.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries beyond the planned validator wire-in (covered in T-04-01-01..T-04-01-03).

## Self-Check: PASSED

All claimed files exist; all claimed commits land in `git log`:

- `delivery_config.schema.yaml` — modified, contains `board_summary`, `unscanned_assets`, `analyst_detail`.
- `run_all.py` — modified, contains `_validate_with_schema(raw, schema)` (3x), `Draft7Validator` import, `_format_error_path`, `_load_schema`.
- `tests/test_phase4_schema_validation.py` — created, 6 `_check(` calls, no `import pytest`.
- Commits 27b50f4, 546062f, 9610a0c, 7e09aa9, ca3e73b all present in `git log`.

## Unblocks

- **Plan 04-02** (analyst-detail companion workbook for board_summary) — schema accepts `analyst_detail: false`, no `additionalProperties: false` rejection.
- **Plan 04-03** (per-group YAML toggle wire-in) — schema slot ready; `dict.get("analyst_detail", True)` read-site can land safely.
- Both can proceed in parallel in Wave 2.
