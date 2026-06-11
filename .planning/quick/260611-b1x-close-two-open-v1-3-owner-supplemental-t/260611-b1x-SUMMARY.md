---
phase: quick-260611-b1x
plan: 01
subsystem: owner-supplemental
tags: [fix, tdd, cow, dedup, pandas, asset-count, quick-260611-b1x, wr-13-01, wr-13-02, doc-audit-correct]
dependency_graph:
  requires: []
  provides: [deduped-asset-count, cow-clean-open-count, corrected-v1.3-audit]
  affects: [reports/owner_supplemental.py, tests/unit/test_owner_supplemental.py, .planning/v1.3-MILESTONE-AUDIT.md]
tech_stack:
  added: []
  patterns: [F-DTYPE .assign() convention, drop_duplicates keep-first, TDD RED-GREEN]
key_files:
  created: []
  modified:
    - reports/owner_supplemental.py
    - tests/unit/test_owner_supplemental.py
    - .planning/v1.3-MILESTONE-AUDIT.md
decisions:
  - "Fix lines 128/129 CoW warnings in addition to line 139 — plan claimed they don't warn but baseline proved they do; all three chained assignments replaced with .assign() as Rule 1 auto-fix"
  - "Fix test fixture _vulns_df_simple/_vulns_df_with_gap_reopened CoW pattern — needed to pass -W error::FutureWarning in the test itself"
metrics:
  duration: ~15 min
  completed: 2026-06-11
  tasks_completed: 3
  files_changed: 3
---

# Quick Task 260611-b1x: Close Two Open v1.3 owner_supplemental Tech-Debt Items — Summary

**One-liner:** TDD fixes for duplicate-uuid asset_count over-count and pandas CoW chained assignment in `_build_owner_app_df`, plus corrected v1.3 milestone audit marking all 3 items closed.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | TDD — fix Asset Count over-count on dup asset_uuid (WR-01) | b233ee3 | reports/owner_supplemental.py, tests/unit/test_owner_supplemental.py |
| 2 | TDD — fix pandas-3.0 CoW chained assignment on open_count cast (WR-02) | 3586026 | reports/owner_supplemental.py, tests/unit/test_owner_supplemental.py |
| 3 | Correct v1.3-MILESTONE-AUDIT.md tech-debt status | d175143 | .planning/v1.3-MILESTONE-AUDIT.md |

## What Was Done

### Task 1 — Asset Count dedup fix (Phase-13 WR-01)

`_build_owner_app_df` built `asset_counts` from the raw (un-deduped) `enriched` frame. A duplicate `asset_uuid` with two different Owner tags was counted once under each owner, producing a phantom row (`asset_count=1, open_count=0` for the second owner) and an inflated total. Fix: introduced `enriched_deduped` (`drop_duplicates("asset_uuid")`, keep-first) before the `asset_counts` groupby, mirroring the CR-01 keep-first pattern already used by the open-count path. The same `enriched_deduped` frame is now reused for `uuid_to_owner`, making both paths consistent.

**TDD:** `test_dup_uuid_asset_count_counts_once` — RED before fix (phantom "Second Owner" row), GREEN after.

### Task 2 — CoW chained assignment fix (Phase-13 WR-02)

Three chained assignment sites in `_build_owner_app_df` fired `ChainedAssignmentError FutureWarning`:
- `vuln_owner["owner"] = vuln_owner["owner"].fillna("Unassigned")` (line 128)
- `vuln_owner["application"] = vuln_owner["application"].fillna("")` (line 129)
- `result["open_count"] = result["open_count"].fillna(0).astype(int)` (line 139)

All three replaced with `vuln_owner = vuln_owner.assign(owner=..., application=...)` and `result = result.assign(open_count=...)` per CLAUDE.md F-DTYPE convention. The test fixture helpers `_vulns_df_simple` and `_vulns_df_with_gap_reopened` also used the same chained loop pattern and were fixed to `df.assign(**{...})` so the tests themselves pass under `-W error::FutureWarning`.

**TDD:** `test_open_count_no_chained_assignment_warning` — RED before fix (FutureWarning raised), GREEN after.

### Task 3 — Audit doc correction

Updated `.planning/v1.3-MILESTONE-AUDIT.md`:
- Phase-12 WR-01: rewritten as ALREADY-CLOSED; corrects stale line reference (82-88 → 108-112); cites commit 71207e6 and test `test_fixed_state_nat_last_fixed_excluded`.
- Phase-13 WR-01 and WR-02/CoW: marked RESOLVED by 260611-b1x with TDD test names.
- Frontmatter `status: tech_debt` → `status: passed`; prose status line updated; total summary updated to "all closed."

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed CoW warnings on lines 128/129 in addition to 139**
- **Found during:** Task 2 RED phase
- **Issue:** Plan stated lines 128/129 "do NOT warn (confirmed)" but the baseline run showed three FutureWarnings from owner_supplemental.py: lines 128, 129, and 139. Under `-W error::FutureWarning`, the test would fail if only line 139 was fixed.
- **Fix:** All three chained assignment sites replaced with `.assign()`.
- **Files modified:** reports/owner_supplemental.py
- **Commit:** 3586026

**2. [Rule 1 - Bug] Fixed test fixture CoW pattern in _vulns_df_simple/_vulns_df_with_gap_reopened**
- **Found during:** Task 2 GREEN phase
- **Issue:** Both fixture helpers used `df[col] = pd.to_datetime(...)` in a for-loop, which also fires FutureWarning — breaking the strict test from inside the test file itself.
- **Fix:** Loop replaced with `df.assign(**{col: pd.to_datetime(...) for col in ...})`.
- **Files modified:** tests/unit/test_owner_supplemental.py
- **Commit:** 3586026

## Verification Results

```
python -m pytest tests/unit/test_owner_supplemental.py -W error::FutureWarning
→ 5 passed

python -m pytest tests/unit/test_open_count.py -q
→ 13 passed (untouched, still green)

python -m pytest -q
→ 160 passed, 0 failed

git diff --stat HEAD~3 HEAD
→ ONLY reports/owner_supplemental.py, tests/unit/test_owner_supplemental.py,
  .planning/v1.3-MILESTONE-AUDIT.md modified
```

## Self-Check: PASSED

- `reports/owner_supplemental.py` — modified, committed b233ee3 + 3586026
- `tests/unit/test_owner_supplemental.py` — modified, committed b233ee3 + 3586026
- `.planning/v1.3-MILESTONE-AUDIT.md` — modified, committed d175143
- All 3 commits verified present in git log
- utils/open_count.py NOT modified (scope guard honored)
- 160/160 tests pass; 0 regressions
