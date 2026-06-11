---
phase: 14-shared-substrates-composed-report-gates
plan: "01"
subsystem: utils
tags: [external-scope, classifier, stdlib, tdd, pure-compute]
dependency_graph:
  requires: []
  provides:
    - utils/external_scope.py — external_scope() + is_public_ipv4() substrate
  affects:
    - Phase 15 External/DMZ module (consumes external_scope() inline in compute())
tech_stack:
  added: []
  patterns:
    - stdlib ipaddress.ip_address().is_global for IP classification (D-05/D-07)
    - pd.DataFrame({...}) dict construction to avoid pandas 3.0 CoW assign() internal warning
    - monkeypatched is_global for positive external test fixture (D-18)
key_files:
  created:
    - utils/external_scope.py
    - tests/test_external_scope.py
  modified: []
decisions:
  - "D-05: is_public_ipv4 uses is_global (stdlib) not hand-rolled RFC1918 — covers CGNAT/loopback/link-local/doc-ranges in one call"
  - "D-06: Location=DMZ + private IP is not a mismatch; only public-IP-untagged gap is emitted"
  - "D-08: gap assets appear in BOTH scoped_df AND mismatches_df for analyst workbook consistency"
  - "D-18: monkeypatched is_global for the positive external test case; no real public IP literals committed"
  - "CoW fix: pd.DataFrame({col: series.to_numpy()}) dict construction bypasses pandas 3.0 assign() internal ChainedAssignmentError on filtered copies"
metrics:
  duration: ~15 min
  completed: "2026-06-11"
  tasks_completed: 2
  files_created: 2
---

# Phase 14 Plan 01: External Scope Classifier Summary

**One-liner:** Stdlib-only tag-authoritative `external_scope()` classifier with public-IP gap detection, tuple return, and monkeypatched positive-external TDD.

## What Was Built

`utils/external_scope.py` — pure-compute, stdlib-only external-scope classifier delivering ROADMAP Success Criterion #1 (SUB-01). The module:

- `is_public_ipv4(ip_str) -> bool` — wraps `ipaddress.ip_address().is_global`; returns `False` on any `ValueError`/`TypeError` (THREAT-14-01 defensive parse)
- `external_scope(assets_df) -> (scoped_df, mismatches_df)` — tag-authoritative classifier returning a 2-tuple mirroring `identify_on_time_assets`'s shape (D-08)

Key classification rules:
- `Location=External` or `Location=DMZ` tag → in `scoped_df`, NOT in `mismatches_df` (tags authoritative, D-04)
- `Location=DMZ` + private IP → scoped, NOT a mismatch (D-06: architecturally normal)
- Public IPv4 + no Location tag → in BOTH frames with `untagged_reason="public_ip_untagged"` (D-05/D-08)
- Private IP + no Location tag → in NEITHER frame
- Empty/missing-column input → two zero-row DataFrames, no exception (QUAL-03 fail-soft)

`tests/test_external_scope.py` — 36 pytest tests covering all branches:
- 20 parametrized `is_public_ipv4` negative cases (RFC1918, CGNAT, loopback, link-local, IPv6, malformed)
- 1 monkeypatched positive case (D-18: no real public IP literals committed)
- 9 `external_scope` classification tests
- 5 empty/missing-column fail-soft tests
- pandas CoW strict mode enabled at module level (`pd.options.mode.copy_on_write = True`)

## TDD Gate Compliance

- **RED commit:** `6119120` — `test(14-01): add failing tests for external_scope classifier (RED)` — tests collected but failed with `ModuleNotFoundError`
- **GREEN commit:** `d263b98` — `feat(14-01): implement utils/external_scope.py classifier (GREEN)` — all 36 tests pass, warnings-as-errors clean

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] pandas 3.0 CoW assign() internal ChainedAssignmentError**
- **Found during:** Task 1 GREEN implementation (TDD cycle)
- **Issue:** `gap_raw.assign(ip_address=gap_raw["ipv4"], ...)` — passing pre-extracted Series from the same filtered frame into `.assign()` triggers `ChainedAssignmentError` inside pandas 3.0's internal `data[k] = val` loop, even when using lambdas.
- **Fix:** Replaced `.assign()` with `pd.DataFrame({"col": series.to_numpy(), ...})` dict construction — reads from the filtered frame via `.to_numpy()` (numpy array, not a pandas view) then constructs a fresh DataFrame.  CoW-clean; confirmed via `-W error` run.
- **Files modified:** `utils/external_scope.py` (mismatches_df build block)
- **Commits:** `d263b98`

## Threat Surface Scan

T-14-01 (DoS — malformed IP into `is_public_ipv4`): mitigated via `try/except (ValueError, TypeError)` returning `False`.
T-14-02 (PII — `mismatches_df` asset-level fields): mitigated via module docstring D-11 boundary + synthetic-only test fixtures + no committed mismatches data.
T-14-03 (Tampering — package installs): accepted — zero new dependencies; stdlib `ipaddress` + existing pandas only.

No new threat surface beyond the plan's threat register.

## Self-Check: PASSED

- [x] `utils/external_scope.py` exists and is importable
- [x] `tests/test_external_scope.py` exists
- [x] RED commit `6119120` exists in git log
- [x] GREEN commit `d263b98` exists in git log
- [x] `pytest tests/test_external_scope.py -x -q` exits 0 (36 passed, 0 warnings with CoW strict mode)
- [x] No real public IP literals in test file (monkeypatched `is_global` for positive case)
- [x] No `df["col"] =` or `.loc[:, col] =` after a filter in `external_scope.py`
- [x] Module docstring documents D-11 PII boundary
- [x] No import from `reports.modules.*` in `utils/external_scope.py` (D-13)
