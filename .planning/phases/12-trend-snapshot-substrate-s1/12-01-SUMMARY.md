---
phase: 12-trend-snapshot-substrate-s1
plan: "01"
subsystem: utils
tags: [trend, open-count, predicate, unit-tests, TREND-01]
dependency_graph:
  requires: []
  provides: [utils/open_count.py, open_findings_at]
  affects: [data/trend_store.py (Plan 02), scripts/capture_trend_snapshot.py (Plan 03)]
tech_stack:
  added: []
  patterns: [two-interval-open-predicate, reopened-aware-filtering, pure-compute-utility]
key_files:
  created:
    - utils/open_count.py
    - tests/unit/test_open_count.py
  modified: []
decisions:
  - "D-01: State casing normalised via .str.upper() — API returns lowercase per _OPEN_STATES evidence; future-proof against any casing change"
  - "D-02: Smoke block _ts() uses pd.Timestamp(_REF - timedelta) without tz= kwarg since _REF is already tz-aware; avoids ValueError on Python 3.14 / pandas"
  - "D-03: Empty-DataFrame guard in test uses explicit typed zero-row construction (datetime64[ns, UTC] dtypes) instead of _df([]).reindex() which fails when _df tries to coerce nonexistent columns"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-08"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 0
---

# Phase 12 Plan 01: Open-Count Predicate Summary

**One-liner:** Reopened-aware two-interval `open_findings_at(df, date)` primitive with 10 labelled OPEN/REOPENED/FIXED unit tests proving TREND-01 correctness.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Implement open_findings_at predicate | 90b02bb | utils/open_count.py |
| 2 | Write labelled OPEN/REOPENED/FIXED unit tests | 913e589 | tests/unit/test_open_count.py |

## What Was Built

### `utils/open_count.py`

Pure-compute open-count primitive. No file I/O, no network I/O, no `config` import, no `_normalize_vuln_dates` call. Accepts an already-normalized DataFrame and a reference datetime.

The two-interval boolean predicate:
- FIXED: excluded when `state=FIXED AND last_fixed <= D`
- REOPENED (gap): excluded when `last_fixed <= D AND resurfaced_date IS NOT NULL AND D < resurfaced_date`
- REOPENED (no resurface): excluded when `last_fixed <= D AND resurfaced_date IS NULL`
- Born-after-D: excluded when `first_found > D`
- All others: included

Safety guards: empty-DataFrame fast-path returns `df.iloc[0:0].copy()`; tz-naive `date` argument coerced to UTC via `pd.Timestamp(date, tz="UTC")`.

### `tests/unit/test_open_count.py`

10 labelled unit tests, all marked `pytest.mark.unit`. Fixture helpers use lowercase state strings (`"open"`, `"fixed"`, `"reopened"`) to validate the `.str.upper()` decision. Fixed reference point `_REF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)` — no wall-clock dependency.

Test coverage:
- `test_open_state_included`
- `test_open_state_no_last_fixed_included`
- `test_fixed_state_excluded`
- `test_reopened_state_included` (D >= resurfaced_date)
- `test_reopened_in_gap_excluded` (last_fixed <= D < resurfaced_date)
- `test_reopened_null_resurfaced_excluded` (resurfaced_date = NaT)
- `test_born_after_D_excluded`
- `test_empty_dataframe_returns_empty`
- `test_mixed_population` (5-row composite, asserts 2 open)
- `test_tz_naive_date_does_not_raise`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed smoke block pd.Timestamp tz= kwarg crash**
- **Found during:** Task 1 smoke block execution
- **Issue:** `pd.Timestamp(_REF - timedelta(...), tz="UTC")` raises `ValueError: Cannot pass a datetime or Timestamp with tzinfo with the tz parameter` because `_REF` is already UTC-aware.
- **Fix:** Removed `tz="UTC"` kwarg from `_ts()` — the subtracted datetime inherits `_REF`'s tzinfo.
- **Files modified:** utils/open_count.py (smoke block only)
- **Commit:** 90b02bb

**2. [Rule 2 - Convention] Replaced chained-assignment in smoke block with .assign()**
- **Found during:** Task 1 smoke block execution
- **Issue:** `_df[col] = pd.to_datetime(...)` loop emitted pandas 3.0 ChainedAssignmentError FutureWarnings.
- **Fix:** Replaced with `.assign(**{col: ...})` pattern per CLAUDE.md pandas-3.0-safe convention.
- **Files modified:** utils/open_count.py (smoke block only)
- **Commit:** 90b02bb

**3. [Rule 1 - Bug] Fixed empty-DataFrame test construction**
- **Found during:** Task 2 test run (1 failure on first run)
- **Issue:** `_df([]).reindex(columns=[...])` failed because `_df()` tried to coerce date columns on an empty frame that had no columns yet.
- **Fix:** Replaced with explicit `pd.DataFrame({col: pd.Series([], dtype=...), ...})` construction with correct dtypes pre-set.
- **Files modified:** tests/unit/test_open_count.py
- **Commit:** 913e589

## Verification Results

```
$ python utils/open_count.py
Input rows  : 5
Open at REF : 3
Smoke test passed.

$ python -m pytest tests/unit/test_open_count.py -x -p no:xdist -o "addopts=" -q
..........
10 passed in 0.03s
```

## Known Stubs

None — this plan delivers pure computation with no UI rendering or data wiring.

## Threat Flags

None — pure in-process computation; no file, network, or user-input boundary introduced.

## Self-Check: PASSED

- [x] `utils/open_count.py` exists and contains `def open_findings_at`
- [x] `tests/unit/test_open_count.py` exists and contains `pytestmark = pytest.mark.unit`
- [x] Commit 90b02bb exists (Task 1)
- [x] Commit 913e589 exists (Task 2)
- [x] `python utils/open_count.py` exits 0
- [x] `python -m pytest tests/unit/test_open_count.py` — 10 passed
- [x] Source confirms `.str.upper()`, `df.iloc[0:0]` present; `_normalize_vuln_dates` and `import config` absent
