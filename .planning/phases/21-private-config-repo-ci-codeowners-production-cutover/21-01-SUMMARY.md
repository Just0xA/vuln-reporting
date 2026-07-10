---
phase: 21-private-config-repo-ci-codeowners-production-cutover
plan: 01
subsystem: config-loader
tags: [config, dual-source-fallback, dry-run, cutover]
dependency-graph:
  requires: []
  provides:
    - "run_all._select_config_source (D-04/D-05 shared source-selection decision)"
    - "run_all._load_config dual-source fallback (D-04)"
    - "run_all._dry_run active-source echo (D-05)"
  affects:
    - "run_all.py:_load_config"
    - "run_all.py:_dry_run"
tech-stack:
  added: []
  patterns:
    - "Pure decision helper shared by two call sites (_load_config, _dry_run) to guarantee agreement"
key-files:
  created: []
  modified:
    - run_all.py
    - tests/test_config_loader.py
    - tests/test_dry_run_surfacing.py
decisions:
  - "_select_config_source re-runs resolve_config internally to decide, and _load_config re-runs it again on the directory/none paths to obtain groups — a small duplicated-call cost accepted to keep the decision helper pure/side-effect-free per the plan's idempotency guard (scheduler hot-reloads every cycle)."
metrics:
  duration_seconds: 780
  completed: 2026-07-10
---

# Phase 21 Plan 01: Dual-Source Config Fallback + Active-Source Logging Summary

One-liner: Added `_select_config_source` as the single source-of-truth decision helper, wired it into `_load_config` (directory-mode failure now falls through to the legacy single file instead of returning `[]`) and `_dry_run` (echoes the active source on every `--dry-run`), closing the D-04/D-05 gap the Phase 21 cutover depends on.

## What Was Built

**Task 1 — `_select_config_source` helper.** A new pure, side-effect-free function in `run_all.py` that encapsulates the "which config source wins" decision. Returns one of four tokens: `"directory"` (deliveries.d/ resolves clean and passes schema), `"legacy-fallback"` (deliveries.d/ present but resolution/schema failed, and a legacy `delivery_config.yaml` exists), `"legacy"` (no deliveries.d/ at all), or `"none"` (deliveries.d/ failed and no legacy file exists — the terminal dual-source-retired state). It reuses the existing `deliveries.d` presence check, `resolve_config`, and the existing `_load_schema`/`_validate_with_schema` gate. Five unit cases (`N` through `R`) cover all five behavior rows from the plan, using synthetic `example.invalid` fixtures built on the existing Task-3 fixture pattern.

**Task 2 — Wiring D-04 fallback + D-05 logging.** `_load_config`'s directory-mode branch now calls `_select_config_source` first and branches on the result:
- `"directory"` → returns the resolved groups (unchanged success path), now with an explicit `logger.debug` naming the active source.
- `"legacy-fallback"` → emits exactly one `logger.warning` naming the fallback and the legacy path, then falls through to the pre-existing legacy single-file branch (reached, not duplicated) instead of `return []`.
- `"none"` → re-derives the resolution/schema errors for logging (preserving all prior error messages byte-for-byte) and returns `[]` — the terminal dual-source-retired state, unchanged in intent.

The legacy single-file success path also now logs an explicit `active source=legacy` debug line for D-05 "every run" coverage.

`_dry_run` gained a single new `console.print` line after the existing directory-mode surfacing block: `"Active config source: {label}"`, driven by the same `_select_config_source(config_path)` call `_load_config` uses, so the two call sites can never disagree. The exit-code contract (0 all-valid / 1 any error) is unchanged — the new line is purely informational.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed as written; no bugs or blocking issues required Rule 1-3 fixes beyond normal fixture iteration (an initial test fixture was missing a required `email.subject` schema field, caught and fixed by the schema gate itself during test-writing, not a code defect).

## Test Coverage Added

- `tests/test_config_loader.py`: 5 new `_select_config_source` cases (N-R, one per behavior row) + 1 new `_load_config` fallback case (S: broken `deliveries.d/` duplicate-name + valid legacy sibling → returns the legacy groups, not `[]`).
- `tests/test_dry_run_surfacing.py`: 2 new cases — directory-mode success echoes `"Active config source: directory-mode"`; legacy-fallback echoes `"Active config source: legacy-fallback"`.

These files follow the pre-existing repo convention of script-style `main()`-driven checks (not pytest `test_*` functions — `pytest.ini`'s `testpaths` doesn't include top-level `tests/*.py` either), run directly via `.venv/bin/python3 tests/<file>.py`. All new checks pass.

## Pre-existing (out-of-scope) test failure

`M_load_config_legacy_single_file_still_works` in `tests/test_config_loader.py` fails in this environment because the repo's real `delivery_config.yaml` (gitignored, per Hard Rule/CONF-04 privacy discipline) does not exist on disk here. Verified this failure pre-exists on the plan's base commit (`a8b8422`) before any Task 1/2 changes — confirmed by running the original (pre-edit) file content directly. Out of scope per the deviation-rules scope boundary (pre-existing, unrelated to this plan's edited lines); not fixed.

## Self-Check: PASSED

- `run_all.py` — FOUND (modified, contains `_select_config_source` at line 157, called from `_load_config` line 230 and `_dry_run` line 567)
- `tests/test_config_loader.py` — FOUND (modified)
- `tests/test_dry_run_surfacing.py` — FOUND (modified)
- Commit `5be9926` (Task 1) — FOUND in `git log --oneline`
- Commit `275b14a` (Task 2) — FOUND in `git log --oneline`
- `grep -n "def _select_config_source" run_all.py` → exactly one match (line 157)
- `grep -n "return \[\]" run_all.py` → the two former directory-mode early-returns (~186/~197 pre-change) no longer exist; only the legacy-branch and "none"-terminal `return []`s remain
- Both test scripts (`tests/test_config_loader.py`, `tests/test_dry_run_surfacing.py`) run clean except the pre-existing, environment-caused `M` failure documented above
