---
phase: 16-mttr-rework
plan: "01"
subsystem: data-persistence
status: complete
tags: [trend-store, mttr, snapshot, backward-compat]
dependency_graph:
  requires: []
  provides: [mttr_overall_days, mttr_by_severity, mttr_by_owner in severity snapshots]
  affects: [data/trend_store.py, scripts/capture_trend_snapshot.py]
tech_stack:
  added: []
  patterns: [implicit-optional-field convention (D-16-09), fail-soft try/except around MTTR block, CoW .assign()]
key_files:
  modified:
    - data/trend_store.py
    - scripts/capture_trend_snapshot.py
decisions:
  - D-16-01: durably-fixed population — state==FIXED only, no last_fixed.notna() clause
  - D-16-02: COALESCE date clock — (last_fixed - COALESCE(resurfaced_date, first_found)).days clipped >=0
  - D-16-09: implicit-optional-field convention — explicit null written for all three fields, snap.get() returns None on old snapshots
metrics:
  duration: ~10 minutes
  completed: 2026-06-12
  tasks_completed: 3
  tasks_total: 3
  files_modified: 2
---

# Phase 16 Plan 01: MTTR Snapshot Schema Extension Summary

Three-field rolling-30-day MTTR aggregate (mttr_overall_days, mttr_by_severity, mttr_by_owner) persisted into every S1 severity snapshot, with reopened-aware date math and fail-soft computation.

## What Was Built

Two files were modified to extend the S1 snapshot store with MTTR persistence:

**`data/trend_store.py`** — `capture_snapshot()` extended with three optional kwargs:
- `mttr_overall_days: Optional[float]` — sample-weighted mean days_to_fix over durably-fixed findings in the rolling window
- `mttr_by_severity: Optional[dict]` — dict keyed critical/high/medium/low, each value float or None (None when sample < threshold)
- `mttr_by_owner: Optional[dict]` — dict keyed by internal Owner tag name, each value float or None

All three stored as explicit JSON values (null when not passed) in `new_entry` immediately before `generated_at`, following the Phase 15 implicit-optional-field convention (D-16-09). Docstring extended with parameter descriptions. No `schema_version` field. No conditional logic — caller computes, store stores.

Smoke block extended with a backward-compat cold-start assertion: a pre-Phase-16 snapshot lacking the MTTR fields reads back as `None` / `{}` via `snap.get()` / `(snap.get(...) or {})` access — never KeyError or TypeError (Pitfall B verified).

**`scripts/capture_trend_snapshot.py`** — Rolling-window MTTR aggregate computation block inserted between the `fixed_vulns_df` fetch and the `capture_snapshot()` call:
- D-16-01: durably-fixed filter (`state == "FIXED"` + `last_fixed >= window_cutoff`)
- D-16-02: COALESCE clock (`resurfaced_date.where(notna(), first_found)`), both sides coerced to `datetime64[ns, UTC]` before subtraction (Pitfall A)
- CoW-compliant: `.assign(days_to_fix=...)` only — no chained assignment after filter
- Flat mean for overall MTTR (sample-weighted per D-16-02 consequence); per-severity dict with `MIN_SAMPLE=5`
- Per-Owner dict via `extract_owner(assets_df)` with `MIN_SAMPLE=5` guard per owner
- Fail-soft `try/except` (T-16-03): computation failure logs warning, all three fields remain None; severity snapshot still written
- `Optional` import added to support type annotations

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Add three optional MTTR kwargs to capture_snapshot() | 5cc0691 | data/trend_store.py |
| 2 | Compute rolling-window MTTR aggregate in capture_trend_snapshot.py | 872204d | scripts/capture_trend_snapshot.py |
| 3 | Backward-compat smoke check — old snapshot reads back as cold-start | ed6435f | data/trend_store.py |

## Verification Results

- `python data/trend_store.py` exits 0; smoke block prints "Backward-compat cold-start: OK" and "Smoke test passed."
- `python -m scripts.capture_trend_snapshot --dry-run` exits 0
- `python -m pytest tests/unit tests/content` — 174 passed, 0 failed (no regression)
- Signature assertion: `{'mttr_overall_days','mttr_by_severity','mttr_by_owner'} <= set(parameters)` — OK
- No `schema_version` token in trend_store.py — OK
- CoW check: `python -W error::FutureWarning -c "import scripts.capture_trend_snapshot"` — no FutureWarning

## Deviations from Plan

None — plan executed exactly as written. The `Optional` import addition to `capture_trend_snapshot.py` was a Rule 2 auto-add (required for type annotations on the three new variables).

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns introduced. The three new snapshot fields carry aggregate floats and internal Owner tag name strings only — within the established PII boundary (T-16-01 mitigated). `data/trend/` remains gitignored.

## Self-Check: PASSED

- `data/trend_store.py` — modified, exists
- `scripts/capture_trend_snapshot.py` — modified, exists
- Commits 5cc0691, 872204d, ed6435f verified in git log
- 174 tests pass, 0 fail
