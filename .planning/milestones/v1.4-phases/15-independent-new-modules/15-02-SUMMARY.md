---
phase: 15-independent-new-modules
plan: "02"
subsystem: trend-substrate
tags: [trend-store, snapshot, backward-compat, aggregate-fields, cron, phase-15]
requirements: [RPT-02, RPT-03, RPT-04, QUAL-05]

dependency_graph:
  requires:
    - 14-02 (count_on_time_assets substrate — Phase-14 D-02)
  provides:
    - capture_snapshot() with six new optional aggregate params (on_time_asset_count,
      reopened_count, accepted_count, recast_count, new_findings_count,
      fixed_findings_count)
    - cron entry point wired to supply all four new counts + fixed_vulns_df
  affects:
    - 15-03, 15-04, 15-05 (Wave 3 trend-dependent modules consume new fields as MoM
      cold-start dimensions)
    - management_summary (existing callers unaffected — D-15-06 backward compat)

tech_stack:
  added: []
  patterns:
    - Backward-compatible extension: all new params use Optional[int]=None defaults
    - Paired derivation gate: new_findings_count / fixed_findings_count both None
      unless fixed_vulns_df is supplied (inflow/outflow pair)
    - Fail-soft fetch: fixed_vulns_df fetch wrapped try/except; proceeds with None
      on failure (cold-start, not abort)
    - CoW-compliant: pd.to_datetime(df["col"]) produces a new Series; no
      df["col"] = val after a filter

key_files:
  modified:
    - data/trend_store.py (capture_snapshot signature + new_entry extension)
    - tests/content/test_trend_store.py (6 new tests + meta_keys fix for owner tests)
    - scripts/capture_trend_snapshot.py (aggregate count wiring + new imports)

decisions:
  - new_findings_count and fixed_findings_count are a paired inflow/outflow metric
    gated on fixed_vulns_df not-None; when fixed_vulns_df=None both remain None
    (prevents a misleading "0 new" reading when the fixed export wasn't fetched)
  - owner-reconcile tests updated meta_keys to exclude Phase-15 aggregate fields
    (these tests sum per-owner int values and must skip the None-valued new keys)

metrics:
  duration: ~25 min
  completed: 2026-06-11
  tasks_completed: 2
  files_modified: 3
---

# Phase 15 Plan 02: Trend Store Backward-Compatible Extension Summary

Extended `data/trend_store.capture_snapshot()` with six new optional aggregate fields
(on_time_asset_count, reopened_count, accepted_count, recast_count, new_findings_count,
fixed_findings_count) and wired the cron entry point to supply them — all backward-compatible.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Failing tests for capture_snapshot() aggregate extension | e8c2d08 | tests/content/test_trend_store.py |
| 1 (GREEN) | Extend capture_snapshot() with backward-compatible aggregate fields | 2aaddc3 | data/trend_store.py, tests/content/test_trend_store.py |
| 2 | Wire aggregate counts into cron capture entry point | d6409a9 | scripts/capture_trend_snapshot.py |

## What Was Built

**`data/trend_store.py` — capture_snapshot() extended (D-15-04/05/06)**

Five new optional keyword parameters added with `None` defaults:
- `on_time_asset_count: Optional[int]` — Phase-14 D-02 density denominator
- `reopened_count: Optional[int]` — findings in REOPENED state
- `accepted_count: Optional[int]` — findings with severity_modification_type == ACCEPTED
- `recast_count: Optional[int]` — findings with severity_modification_type == RECASTED
- `fixed_vulns_df: Optional[pd.DataFrame]` — fixed findings for inflow/outflow derivation

Two derived fields added to `new_entry` (only when `fixed_vulns_df` is not-None):
- `new_findings_count` — count of df rows whose `first_found` month == snapshot month
- `fixed_findings_count` — count of fixed_vulns_df rows whose `last_fixed` month == snapshot month AND state == FIXED

All six new keys stored in `new_entry` after `asset_count` and before `generated_at`. All values are `int` or `None` — never DataFrames or lists (QUAL-05).

**`scripts/capture_trend_snapshot.py` — aggregate count wiring**

Before the severity `capture_snapshot()` call:
1. `count_on_time_assets(assets_df, snapshot_date)` provides `on_time_asset_count`
2. `df["state"].str.upper() == "REOPENED"` count provides `reopened_count`
3. `df["severity_modification_type"].str.upper().isin({"ACCEPTED", "RECASTED"})` counts
4. `fetch_fixed_vulnerabilities()` called fail-soft (warning + `None` on failure)

All four counts plus `fixed_vulns_df` passed as keyword args into the severity call only. Owner-dimension call is unchanged. INFO log emits scalar counts only — no row-level data (QUAL-05).

**Tests (`tests/content/test_trend_store.py`) — 6 new tests added (22 total)**

- `test_new_aggregate_fields_written` — new params accepted and written as ints
- `test_new_params_default_to_none` — omitting all new params writes None (backward compat)
- `test_old_snapshot_readable_without_new_fields` — pre-extension JSON readable, `.get()` returns None
- `test_new_fields_are_ints_or_none` — all six new keys are int or None, never complex objects
- `test_new_findings_count_derivation` — correct month-scoped derivation from df + fixed_vulns_df
- `test_existing_severity_fields_unchanged` — critical/high/medium/low/asset_count unchanged

Pre-existing owner-reconcile tests updated: `meta_keys` set now excludes Phase-15 aggregate field names (they're `None` in owner-dimension snapshots when not supplied; the sum loop previously crashed on `None + int`).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Owner-reconcile tests crashed on None values from new fields**
- **Found during:** Task 1 GREEN phase (test run)
- **Issue:** Pre-existing `test_owner_counts_reconcile` and `test_owner_attribution_deterministic_under_dup_uuid` summed all non-meta snapshot values; the new None-valued Phase-15 fields caused `TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'`
- **Fix:** Updated `meta_keys` in both tests to include all six Phase-15 field names; sum expression guards `v is not None`
- **Files modified:** `tests/content/test_trend_store.py`
- **Commit:** 2aaddc3

**2. [Rule 2 - Spec interpretation] new_findings_count / fixed_findings_count gated on fixed_vulns_df**
- **Found during:** Task 1 GREEN phase — `test_new_params_default_to_none` expected `new_findings_count is None` when no `fixed_vulns_df` was passed, but the first implementation derived it from `df` alone (which is always present)
- **Fix:** Changed derivation to require `fixed_vulns_df is not None` as the gate for both fields (inflow/outflow pair). This matches the spec intent "when the inputs are present, else None" — `new_findings_count` without `fixed_findings_count` would be misleading
- **Files modified:** `data/trend_store.py`
- **Commit:** 2aaddc3

## Backward Compatibility Verified

- Old snapshot JSON without Phase-15 fields: `read_trend()` returns it without error; `snap.get("on_time_asset_count")` returns `None` (cold-start, not crash)
- Existing `management_summary` callers: unaffected — `capture_snapshot()` signature extended with new optional-only params; no changes to `read_trend()`, `_load_trend_json()`, or `_atomic_write_json()`
- Severity + owner dimension dispatch: unchanged; new fields added to `new_entry` for both dimensions (None by default for owner calls)

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries beyond what the plan's threat model covers (T-15-02-PII verified: new keys store int/None only; T-15-02-COMPAT verified: backward-compat tests green; T-15-02-LOG verified: INFO logs only scalar counts).

## Known Stubs

None — no placeholder values or wired-but-empty data paths.

## Self-Check: PASSED
