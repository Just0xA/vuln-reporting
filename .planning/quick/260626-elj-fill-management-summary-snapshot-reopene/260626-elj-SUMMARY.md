---
phase: quick-260626-elj
plan: "01"
status: complete
subsystem: management_summary
tags: [bugfix, trend-snapshot, tdd, reaudit]
dependency_graph:
  requires: [reports/management_summary.py, tests/test_management_summary.py, utils/sla_calculator.py, utils/open_count.py]
  provides: [REAUDIT-WARN-1 fix — non-null reopened_count + sla_rate_crit_high in trend snapshot]
  affects: [data/trend/ snapshot store, management_summary trend persistence]
tech_stack:
  added: []
  patterns: [inline-import (# noqa: PLC0415), fail-soft None on exception, TDD RED/GREEN]
key_files:
  modified:
    - reports/management_summary.py
    - tests/test_management_summary.py
decisions:
  - "Compute reopened_count + sla_rate_crit_high inline in snapshot block rather than add modules to _MGMT_MODULE_CONFIGS — preserves rendered 7-module report byte-for-byte"
  - "Use inline imports (noqa: PLC0415) for sla_rate_crit_high path, mirroring capture_trend_snapshot.py style exactly"
metrics:
  duration_s: 600
  completed: 2026-06-26
  tasks: 2
  files_changed: 2
requirements: [REAUDIT-WARN-1]
---

# Quick Task 260626-elj: Fill management_summary Snapshot reopened_count + sla_rate_crit_high

**One-liner:** Inline-compute reopened_count (REOPENED state count) and sla_rate_crit_high (via compute_sla_rate_crit_high helper) directly from vulns_df in the snapshot block, replacing dead _safe_metric() calls that always resolved to None.

## Problem

REAUDIT-WARN-1: `reports/management_summary.py` forwarded `reopened_count` and `sla_rate_crit_high` to `capture_snapshot()` via `_safe_metric("reopened_vulns", ...)` and `_safe_metric("program_health", ...)` respectively. Both modules (`reopened_vulns`, `program_health`) are NOT in `_MGMT_MODULE_CONFIGS`, so `_safe_metric()` always returned `None`. The existing INT-WARN-1 regression test only checked kwarg KEY presence, so it stayed green over the nulls.

## Fix

Two surgical changes:

### Task 2 (RED): `tests/test_management_summary.py`

Added `test_reopened_and_sla_rate_forwarded_non_none` after `test_partial_write_regression_guard`. Reuses the existing `_run_report_capture_snapshot_kwargs` helper against the frozen parity fixture. Asserts:
- `captured["reopened_count"] is not None` AND `== 1` (fixture has exactly 1 REOPENED finding)
- `captured["sla_rate_crit_high"] is not None` AND `isinstance(..., float)`

**RED result:** FAILED — `assert None is not None` on `reopened_count` (pre-fix)

### Task 1 (GREEN): `reports/management_summary.py`

Replaced both dead `_safe_metric()` lines in the snapshot-write `try` block:

1. `reopened_count`: Inline count from `vulns_df["state"]`, guarded for missing column (fail-soft None). Mirrors `capture_trend_snapshot.py` L271-273.

2. `sla_rate_crit_high`: Inline imports (noqa: PLC0415) of `SLA_DAYS`, `open_findings_at`, `compute_sla_rate_crit_high`; wrapped in `try/except Exception` with `logger.warning` on failure (fail-soft None). Mirrors `capture_trend_snapshot.py` L387-407.

`_MGMT_MODULE_CONFIGS` (7 rendered modules) is unchanged. `capture_snapshot()` call signature unchanged. No module-level imports added.

## TDD Gate Compliance

- RED commit: `1276ccb` — test(quick-260626-elj): RED — assert non-None reopened_count + sla_rate_crit_high
- GREEN commit: `4407a6a` — fix(quick-260626-elj): REAUDIT-WARN-1 — inline reopened_count + sla_rate_crit_high

## Verification Results

### Step 1 — RED (pre-fix)
```
FAILED tests/test_management_summary.py::test_reopened_and_sla_rate_forwarded_non_none
AssertionError: REAUDIT-WARN-1: reopened_count must not be None
assert None is not None
```

### Step 2 — GREEN (post-fix)
```
1 passed, 14 warnings in 4.50s
```

### Step 3 — Full management_summary suite
```
17 passed, 197 warnings in 5.84s
```
All 17 tests pass (16 pre-existing + 1 new). Structural smoke, value-golden parity, INT-WARN-1 key-presence guards, and the new REAUDIT-WARN-1 value-non-null test all green.

### Step 4 — dry-run config validation
```
All 5 group(s) validated successfully.
```

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check: PASSED

- `reports/management_summary.py` — modified, committed at `4407a6a`
- `tests/test_management_summary.py` — modified, committed at `1276ccb`
- Both commits confirmed in `git log --oneline -5`
- Full test suite: 17 passed
- dry-run: 5 groups validated
