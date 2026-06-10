---
phase: 13-owner-segmentation-composition-s2-doc
plan: "05"
subsystem: owner-segmentation
tags: [gap-closure, correctness, tdd, CR-01, WR-05, WR-02, SEG-03]
dependency_graph:
  requires: []
  provides: [SEG-03-verified, CR-01-closed, WR-05-closed, WR-02-closed]
  affects: [reports/owner_supplemental.py, data/trend_store.py, reports/board_summary.py]
tech_stack:
  added: []
  patterns: [drop_duplicates-before-set_index, open_findings_at-filter, report_date-threading]
key_files:
  created:
    - tests/unit/test_owner_supplemental.py
  modified:
    - reports/owner_supplemental.py
    - reports/board_summary.py
    - data/trend_store.py
    - tests/content/test_trend_store.py
    - docs/trend_and_segmentation_calculations.md
decisions:
  - "CR-01: drop_duplicates(\"asset_uuid\") before set_index in _build_owner_app_df — first-row wins, explicit, pandas-version-agnostic"
  - "WR-02: open_findings_at applied with Optional[datetime] report_date; None = back-compat raw-export count for callers without a date"
  - "WR-05: same drop_duplicates pattern in _count_by_owner, keeping data-layer free of any reports imports"
  - "Test for CR-01 written to assert deterministic first-row attribution (not just no-raise) since pandas 2.2.3 does not raise on non-unique join index"
metrics:
  duration_minutes: 20
  tasks_completed: 3
  files_modified: 5
  completed_date: "2026-06-10"
---

# Phase 13 Plan 05: CR-01/WR-05/WR-02 Correctness Cluster Summary

**One-liner:** Dedup-before-set_index (CR-01) + open_findings_at open-set filter with report_date threading (WR-02) + deterministic _count_by_owner dedup (WR-05) — supplemental now produces real Paths on duplicate-uuid assets and ties out to the owner trend snapshot.

## What Was Built

Three correctness defects sharing a duplicate-`asset_uuid` root cause were closed:

**CR-01 (BLOCKER → VERIFIED):** `reports/owner_supplemental.py:_build_owner_app_df` built the uuid→owner lookup with `enriched.set_index("asset_uuid")` without deduplicating first. In pandas 2.2.3 this doesn't raise but produces non-deterministic last-wins attribution when the same uuid appears under different owners (multi-network/multi-hostname assets from `fetch_all_assets()`). Fix: `enriched[["asset_uuid","owner","application"]].drop_duplicates("asset_uuid").set_index("asset_uuid")` — first-row wins, explicit and pandas-version-agnostic. This closes the invisible-failure path that was causing the board_summary fail-soft to silently swallow the supplemental.

**WR-02 (correctness/consistency):** The supplemental "Open Findings" column counted raw export rows via `groupby().size()` on the full `vulns_df`. A REOPENED finding in its `[last_fixed, resurfaced_date)` gap at the run date is in the export but not open at that date. Fix: apply `open_findings_at(vulns_df, report_date)` before aggregating. `report_date` is threaded as `Optional[datetime]` through `write_owner_supplemental` → `_build_owner_app_df`; `board_summary.py` passes `generated_at`. When `None`, raw-export counting is preserved for back-compat.

**WR-05 (correctness):** `data/trend_store.py:_count_by_owner` built `dict(zip(enriched_assets["asset_uuid"], enriched_assets["owner"]))` — silently last-wins on duplicate uuids. Fix: `ea = enriched_assets.drop_duplicates("asset_uuid")` then `dict(zip(ea["asset_uuid"], ea["owner"]))`. Data-layer isolation preserved (no `from reports` imports).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 0 | Write failing CR-01 + WR-02 regression tests (RED) | 487f0e2 | tests/unit/test_owner_supplemental.py |
| 1 | Fix CR-01 dedup + WR-02 open-set filter (GREEN) | 854e38a | reports/owner_supplemental.py, reports/board_summary.py |
| 2 | Fix WR-05 deterministic dedup + regression test + runbook | 1b6d1e7 | data/trend_store.py, tests/content/test_trend_store.py, docs/trend_and_segmentation_calculations.md |

## Verification Results

- `pytest tests/unit/test_owner_supplemental.py` — 3 passed (CR-01 deterministic attribution, WR-02 open-set, empty-guard)
- `pytest tests/content/test_trend_store.py` — 16 passed (WR-05 deterministic attribution + reconcile + all existing owner/severity cases)
- `pytest tests/unit tests/content` — 147 passed (no regression)
- `python -c "import reports.owner_supplemental, reports.board_summary"` — exit 0
- `grep "drop_duplicates" reports/owner_supplemental.py data/trend_store.py` — both match
- `grep -c "from reports" data/trend_store.py` — 0 (data-layer isolation preserved)
- `grep "report_date=generated_at" reports/board_summary.py` — line 324

## Deviations from Plan

**1. [Rule 1 - Bug] CR-01 test had to target determinism, not no-raise**

- **Found during:** Task 0 RED verification
- **Issue:** The plan spec said the CR-01 test "MUST raise ValueError" before the fix. But pandas 2.2.3 `DataFrame.join()` against a non-unique index does not raise — it silently uses last-wins matching. The test as originally conceived would have passed immediately (GREEN before the fix), making it useless as a regression test.
- **Fix:** Rewrote `test_duplicate_uuid_returns_paths_and_deterministic` to assert first-row attribution explicitly by using two rows with DIFFERENT owners on the same uuid, then checking the CSV shows "First Owner" (row 0), not "Second Owner" (row 1). This correctly fails RED (last-wins gives Second Owner before the fix) and passes GREEN (drop_duplicates gives First Owner after the fix).
- **Files modified:** tests/unit/test_owner_supplemental.py
- **Commit:** 487f0e2

## Known Stubs

None — all columns are computed from real data.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes. The changes stay in-memory (`_build_owner_app_df`, `_count_by_owner`). Output destinations and trend payload shape are unchanged.

## Self-Check: PASSED

- `tests/unit/test_owner_supplemental.py` exists: FOUND
- `tests/content/test_trend_store.py` contains `test_owner_attribution_deterministic_under_dup_uuid`: FOUND
- `reports/owner_supplemental.py` contains `drop_duplicates` and `open_findings_at`: FOUND
- `data/trend_store.py` contains `drop_duplicates` inside `_count_by_owner`: FOUND
- `reports/board_summary.py` line 324 `report_date=generated_at`: FOUND
- Commits 487f0e2, 854e38a, 1b6d1e7: VERIFIED in git log
