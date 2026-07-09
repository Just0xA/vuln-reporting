---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "03"
subsystem: management_summary
tags: [int-warn, correctness, trend-writer, recast, never-raises, test-idiom]
dependency_graph:
  requires: ["19-01", "19-02"]
  provides: ["complete-trend-writer", "recast-forward", "frozenset-gate-3", "cr-f3-never-raises", "cr-t5-zero-vs-absent"]
  affects: ["reports/management_summary.py", "tests/test_management_summary.py", "tests/test_composed_report_kwargs_gates.py"]
tech_stack:
  added: []
  patterns: ["fail-soft fetch", "try/except never-raises wrap", "key-existence check", "module result extraction"]
key_files:
  created: []
  modified:
    - reports/management_summary.py
    - tests/test_management_summary.py
    - tests/test_composed_report_kwargs_gates.py
decisions:
  - "INT-WARN-1/D-03: mttr_by_owner extracted from mttr_trend result.metadata['table_data_owner'] (not in metrics dict — stored as list of {label,mttr_days,...} rows)"
  - "INT-WARN-1/D-03: sla_rate_crit_high sourced from program_health result.metrics['sla_rate_current'] (live tile value, consistent with what the module computes)"
  - "CR-F3: safe default bundle dict initialised before try block so PDF/Excel/snapshot sections always have a valid dict; capture_snapshot guarded on vulns_df is not None"
  - "CR-T5: three or-chain sites fixed in _check_float_tolerance (scan_coverage_sla, mttr_trend, patch_compliance_rate) and one in _check_mixed (accepted_recast)"
metrics:
  duration_seconds: 2700
  completed_date: "2026-06-25"
  tasks: 3
  files: 3
---

# Phase 19 Plan 03: INT-WARN-1/2/3 + CR-F3 + CR-T5 Summary

**One-liner:** Closed five correctness gaps on the management_summary path — complete aggregate trend writer (INT-WARN-1), recast fetch/forward (INT-WARN-2), frozenset co-edit gate (INT-WARN-3), never-raises contract guard (CR-F3), and zero-vs-absent test idiom fix (CR-T5).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | INT-WARN-3: third frozenset membership gate | 0204e17 | tests/test_composed_report_kwargs_gates.py |
| 2 | INT-WARN-2 + CR-F3: recast fetch/forward + never-raises wrap | 0f766e1 | reports/management_summary.py, tests/test_management_summary.py |
| 3 RED | INT-WARN-1 + CR-T5 RED phase (failing tests) | 1520477 | tests/test_management_summary.py |
| 3 GREEN | INT-WARN-1 + CR-T5 GREEN phase (implementation) | 23ae2f0 | reports/management_summary.py, tests/test_management_summary.py |

## What Was Done

### Task 1 — INT-WARN-3: frozenset co-edit gate

Added `_MODULES_NEEDING_FIXED_VULNS` import and a third exact-membership assertion to `test_frozensets_membership` in `tests/test_composed_report_kwargs_gates.py`. Expected set: `{"critical_remediation_sla", "mttr_trend"}`. Citation format matches the two existing assertions: `"(INT-WARN-3 / Phase 19 / SUB-03)"`. A future edit that adds/removes a module from this frozenset without updating the test now fails immediately.

### Task 2 — INT-WARN-2 + CR-F3: recast fetch/forward + never-raises guard

**INT-WARN-2 (D-04):** Added fail-soft `fetch_recast_rules` call after the trend read. `accepted_recast` is always in `_MGMT_MODULE_CONFIGS` so the fetch is unconditional (no intersection check needed). Failure degrades to `recast_rules_df = None` with an ERROR log. Forwarded `recast_rules_df=recast_rules_df` to `ReportComposer(...)`. Previously the accepted_recast expiry cross-check was silently skipped (pending_reeval was always 0).

**CR-F3:** Wrapped the entire fetch/compose block (fetch → tag filter → recast fetch → composer → run_all → run_full_pipeline) in a try/except. Safe default `bundle` dict initialised before the try so PDF/Excel/email sections always have a valid dict to read from. `capture_snapshot` guarded with `if vulns_df is not None and assets_df is not None` so the fetch-failed path skips snapshot writing.

Two new tests: `test_recast_rules_fetched_and_forwarded_to_composer` (monkeypatches `fetch_recast_rules` and spies on `ReportComposer.__init__` to assert the kwarg arrives) and `test_run_report_never_raises_on_fetch_failure` (forces the first fetch to raise, asserts `run_report` returns a dict).

### Task 3 — INT-WARN-1 + CR-T5 (TDD)

**INT-WARN-1 (D-03):** Replaced the partial `capture_snapshot()` call with the full aggregate field set. Aggregate values extracted from the `results` list produced by `composer.run_all()` using `_safe_metric` / `_safe_metadata` helpers:

| capture_snapshot kwarg | Source module | Source key |
|------------------------|---------------|------------|
| `accepted_count` | `accepted_recast` | `metrics["accepted_count"]` |
| `recast_count` | `accepted_recast` | `metrics["recast_count"]` |
| `reopened_count` | `reopened_vulns` | `metrics["reopened_count"]` |
| `on_time_asset_count` | `scan_coverage_sla` | `metrics["scanned_on_time"]` |
| `mttr_overall_days` | `mttr_trend` | `metrics["overall_mttr"]` |
| `mttr_by_severity` | `mttr_trend` | `{sev}_mttr` metrics keys → dict |
| `mttr_by_owner` | `mttr_trend` | `metadata["table_data_owner"]` list → dict |
| `sla_rate_crit_high` | `program_health` | `metrics["sla_rate_current"]` |
| `fixed_vulns_df` | (already forwarded) | pass-through |

`None` is the safe default whenever a module result has `error is not None` (D-16-09).

**CR-T5:** Replaced three `val or default` or-chain sites in `_check_float_tolerance` (`scan_coverage_sla`, `mttr_trend`, `patch_compliance_rate`) and one in `_check_mixed` (`accepted_recast`) with explicit `key in dict` existence checks. A legitimate `0` / `0.0` is now correctly treated as PRESENT rather than as missing.

Three new INT-WARN-1 tests (full-field-set assertion, partial-write regression guard, None safe-default when module errored) and two CR-T5 tests (zero float not missing, zero int not missing).

## Verification

```
pytest tests/test_management_summary.py tests/test_composed_report_kwargs_gates.py -q -o addopts=""
# 26 passed

python -c "import reports.management_summary"
# (silent — import OK)

python run_all.py --dry-run
# All 5 group(s) validated successfully.
```

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Notes

- `mttr_by_owner` is stored in `result.metadata["table_data_owner"]` (not in `result.metrics`). The plan's `19-PATTERNS.md` said "read from `result.metrics`" as a general guideline; the actual extraction required reading from `metadata` for this specific field. This is correct — the metadata dict is part of `ModuleData` and the table_data_owner list maps cleanly to the `{owner: mttr_days}` dict shape capture_snapshot expects.
- `sla_rate_crit_high` maps from `program_health.metrics["sla_rate_current"]` (the live tile value), not from the trend snapshot field. This is consistent with how the cron writer computes it from live data.

## Self-Check

Verified commits exist and files are present:
- 0204e17 — test(19-03): INT-WARN-3 frozenset gate
- 0f766e1 — fix(19-03): INT-WARN-2 + CR-F3 recast/never-raises
- 1520477 — test(19-03): INT-WARN-1 + CR-T5 RED phase
- 23ae2f0 — feat(19-03): INT-WARN-1 complete trend writer + CR-T5 fix

## Self-Check: PASSED
