---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "06"
subsystem: tests, data/fetchers, scripts/update_from_github.sh
tags: [test-rigor, cache-correctness, deploy-safety, coderabbit]
dependency_graph:
  requires: []
  provides:
    - CR-T1/T2/T6/T7 test-rigor fixes
    - CR-B5 window-keyed fixed-vuln cache
    - CR-U1/U2 updater symlink resolver + force guard
  affects:
    - tests/e2e/test_groups.py
    - tests/test_consumer_audit.py
    - tests/baselines/management_summary_structural_schema.py
    - tests/baselines/management_summary_value_golden.json
    - tests/conftest.py
    - data/fetchers.py
    - scripts/update_from_github.sh
tech_stack:
  added: []
  patterns:
    - pytest.skip(allow_module_level=True) for module-level import-time guards
    - file::function qualified identifiers for pass-through caller exemption sets
    - (int, bool) tuple return from page-count helper to surface heuristic flag
    - lookback_days-keyed parquet dataset names for cache correctness
    - _resolve_target() bash helper for symlink absolute/relative normalization
key_files:
  created: []
  modified:
    - tests/e2e/test_groups.py
    - tests/test_consumer_audit.py
    - tests/baselines/management_summary_structural_schema.py
    - tests/baselines/management_summary_value_golden.json
    - tests/conftest.py
    - data/fetchers.py
    - scripts/update_from_github.sh
decisions:
  - "IN-02: _first_str retained — fetch_vulnerabilities (deprecated) calls it at L977 and the __main__ CLI block calls fetch_vulnerabilities at L1385; removing _first_str would break the CLI; defer removal with the deprecated chain to a future cleanup task"
  - "CR-B5 fixture impact: seeded_cache and _cache_from fixtures updated to write vulns_fixed_{FIXED_LOOKBACK_DAYS}d.parquet, derived from config so future config changes propagate automatically"
  - "CR-U2 exit code: reuses exit 7 (release dir already exists) since --force on active release is a variant of the same pre-condition failure; no new exit code added"
metrics:
  duration_seconds: 1800
  completed_date: "2026-06-25"
  tasks_completed: 3
  files_changed: 7
---

# Phase 19 Plan 06: Work-stream E/F Test-Rigor + Cache Key + Updater Hardening Summary

One-liner: Close CR-T1/T2/T6/T7 test-correctness findings, fix the fixed-vuln cache collision (CR-B5), and harden the updater symlink resolver + force-on-active-release guard (CR-U1/U2).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Test-rigor CR-T1/T2/T6/T7 | 44eb920 | test_groups.py, test_consumer_audit.py, management_summary_structural_schema.py, management_summary_value_golden.json |
| 2 | CR-B5 cache key + IN-02 decision | ffc87c9 | data/fetchers.py |
| 2b | CR-B5 fixture fix (Rule 1) | 98fd3ae | tests/conftest.py, tests/e2e/test_groups.py |
| 3 | CR-U1/U2 updater hardening | 7619609 | scripts/update_from_github.sh |

## What Was Built

### Task 1 — Test-rigor fixes (CR-T1/T2/T6/T7)

**CR-T1** (`tests/e2e/test_groups.py`): Added `pytest.skip(allow_module_level=True)` guard when `_load_groups()` returns empty, preventing an `IndexError` during pytest collection on a fresh checkout. Moved `_FIRST_GROUP = _GROUPS[0]` before the parametrize decorator and removed the duplicate assignment that appeared after the SMTP section import.

**CR-T2** (`tests/test_consumer_audit.py`): Changed `_PASS_THROUGH_CALLERS` from bare function names (`"run_report"`) to module-qualified `"file::function"` identifiers (`"reports/management_summary.py::run_report"`, etc.). Updated the sweep loop to build `qualified = f"{rel_path}::{scope}"` and match against that, so a `run_report` in any unrelated file is not silently exempted.

**CR-T6** (`tests/baselines/management_summary_structural_schema.py`): Changed `_pdf_page_count_from_html` to return `(int, bool)` tuple where the bool is `is_heuristic` (True when WeasyPrint is unavailable). Updated `extract_structural_snapshot` to unpack the tuple and expose `pdf_page_count_is_heuristic` in the snapshot dict. Callers can now skip or soft-assert the page count when this flag is True.

**CR-T7** (`tests/baselines/management_summary_value_golden.json`): Replaced the hardcoded absolute Windows path `D:\Projects\vuln-reporting\tests\fixtures\management_summary_parity` in `_meta.fixture_dir` with the repo-relative value `tests/fixtures/management_summary_parity`.

### Task 2 — CR-B5 fixed-vuln cache key + IN-02 decision

**CR-B5** (`data/fetchers.py`): Changed the `_cache_path` call in `fetch_fixed_vulnerabilities` from `"vulns_fixed"` to `f"vulns_fixed_{lookback_days}d"`. Different lookback windows (e.g. 30d vs 365d) now write and read distinct parquet files, preventing silent cache reuse across window sizes. Updated the docstring to document the new filename pattern.

**IN-02 decision**: `_first_str` is retained. It is called by `fetch_vulnerabilities` (deprecated) at L977, and `fetch_vulnerabilities` itself is called in the `__main__` CLI block at L1385. Removing `_first_str` would break the CLI. Both functions remain until the deprecated chain is retired in a future cleanup task.

**CR-B5 fixture fix** (Rule 1 auto-fix): The `seeded_cache` fixture in `tests/conftest.py` and the `_cache_from` helper in `test_groups.py` were writing `vulns_fixed.parquet` — the old name. Updated both to write `vulns_fixed_{config.FIXED_LOOKBACK_DAYS}d.parquet` (365d by default), deriving the key from `config` so future changes propagate automatically.

### Task 3 — CR-U1/U2 updater hardening

**CR-U1** (`scripts/update_from_github.sh`): Added `_resolve_target()` helper function after `usage_error()`. The helper returns absolute targets unchanged and prepends `${INSTALL_ROOT}/` to relative targets, eliminating the double-prefix path `${INSTALL_ROOT}/releases/releases/vX/`. Updated `assert_layout` to use `_resolve_target "$(readlink ...)"` instead of the inline conditional block.

**CR-U2** (`scripts/update_from_github.sh`): Added active-release guard inside the `--force` + existing-dir branch of `cmd_install`. Before `rm -rf "$TARGET_DIR"`, the guard resolves `readlink -f "${INSTALL_ROOT}/current"` and refuses with exit 7 + clear error message when `TARGET_DIR` equals the active release. This prevents rollback breakage where `.last` would point at a partially-rebuilt tree.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] CR-B5 cache rename broke seeded_cache fixture**
- **Found during:** Task 2 verification (19/19 tests dropped to 10/19 after CR-B5)
- **Issue:** `seeded_cache` in `conftest.py` and `_cache_from` in `test_groups.py` wrote `vulns_fixed.parquet`; fetcher now reads `vulns_fixed_{lookback_days}d.parquet`; `DummyTio` raised on cache miss
- **Fix:** Both fixtures now derive the dataset name from `config.FIXED_LOOKBACK_DAYS` and write `vulns_fixed_365d.parquet`
- **Files modified:** `tests/conftest.py`, `tests/e2e/test_groups.py`
- **Commit:** 98fd3ae

### IN-02 Scope Decision

`_first_str` is NOT removed (plan permitted this outcome). `fetch_vulnerabilities` (the deprecated caller) is still exercised by the `__main__` CLI block — removing `_first_str` would be a breaking change to the CLI. Documented in decisions above and will be removed when the deprecated chain is retired.

## Verification Results

```
pytest tests/e2e/test_groups.py tests/test_consumer_audit.py tests/baselines/
  -k "groups or consumer or management_summary" -q -o "addopts="
→ 19 passed, 99 warnings

bash -n scripts/update_from_github.sh → syntax OK

grep -c "vulns_fixed_" data/fetchers.py → 2 (docstring + cache call)

grep -c "_resolve_target" scripts/update_from_github.sh → 4 (def + assert_layout call + 2 comments)
```

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries.

## Self-Check: PASSED

- tests/e2e/test_groups.py: modified, committed 44eb920, 98fd3ae
- tests/test_consumer_audit.py: modified, committed 44eb920
- tests/baselines/management_summary_structural_schema.py: modified, committed 44eb920
- tests/baselines/management_summary_value_golden.json: modified, committed 44eb920
- tests/conftest.py: modified, committed 98fd3ae
- data/fetchers.py: modified, committed ffc87c9
- scripts/update_from_github.sh: modified, committed 7619609
- All commits verified in git log
