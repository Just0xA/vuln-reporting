---
phase: 17-program-health-overview
plan: "01"
subsystem: trend-substrate
status: complete
tags: [trend, snapshot, sla, program-health, sla_rate_crit_high]
requirements: [RPT-07]

dependency_graph:
  requires:
    - data/trend_store.py (capture_snapshot engine — Phase 12/13)
    - utils/open_count.py (open_findings_at reopened-aware predicate — Phase 12)
    - config.py (SLA_DAYS authoritative targets)
  provides:
    - sla_rate_crit_high optional field on severity snapshots (forward-accumulating)
    - backward-compat cold-start: old snapshots read back as None (no KeyError)
  affects:
    - scripts/capture_trend_snapshot.py (now computes + persists the field)
    - tests/content/test_trend_store.py (3 new round-trip/default/backward-compat tests)

tech_stack:
  added: []
  patterns:
    - Implicit-optional-field convention (D-16-09 pattern): absent key reads as None, no migration
    - Fail-soft aggregate block (T-17-02): try/except sets field None, severity snapshot still completes
    - Reopened-aware open population via open_findings_at() (QUAL-02)
    - CoW-safe vectorized SLA test: days_open as local variable, never ch_df column write (Pitfall 3)
    - tz-aware snap_ts via pd.Timestamp(snapshot_date, tz="UTC") (T-17-03, Pitfall 7)

key_files:
  modified:
    - data/trend_store.py
    - scripts/capture_trend_snapshot.py
    - tests/content/test_trend_store.py

decisions:
  - "D-17-04: sla_rate_crit_high is severity-dimension only; owner-dimension call does not receive it"
  - "D-17-03: SLA posture scoped to Critical+High only, using config.SLA_DAYS — never hardcoded day counts"
  - "QUAL-05: only the aggregate float crosses the trust boundary; no row-level fields persist"

metrics:
  duration_seconds: 900
  completed_date: "2026-06-12"
  tasks_completed: 3
  files_modified: 3
---

# Phase 17 Plan 01: SLA-Posture Aggregate Field (sla_rate_crit_high) Summary

**One-liner:** Forward-accumulating `sla_rate_crit_high` float (% Crit+High within SLA) added to S1 severity snapshots, computed reopened-aware via `open_findings_at()` + `config.SLA_DAYS`, with fail-soft computation and cold-start backward compatibility.

## What Was Built

The S1 trend substrate now persists a `sla_rate_crit_high` field — a float percentage (0–100) representing the fraction of open Critical+High findings within their VPR-derived SLA targets at snapshot date. This is the upstream contract the Phase 17 `program_health` module will consume for month-over-month SLA-rate delta.

### data/trend_store.py

- Added `sla_rate_crit_high: Optional[float] = None` parameter to `capture_snapshot()` immediately after `mttr_by_owner` (Phase 17 addition comment, matching Phase 16 style).
- Added docstring bullet mirroring `mttr_overall_days` pattern.
- Persisted field in `new_entry` dict as `"sla_rate_crit_high": sla_rate_crit_high` with Phase 17 comment (D-16-09 implicit-optional-field convention: explicit null, never absent).
- Added `__main__` backward-compat assertion: `_old_snap.get("sla_rate_crit_high") is None` with confirming print.

### scripts/capture_trend_snapshot.py

- Inserted fail-soft SLA-posture block immediately before the severity `capture_snapshot(...)` call, mirroring the Phase 16 MTTR block structure.
- Computation: `open_findings_at(df, snapshot_date)` → filter to Critical+High → vectorized within-SLA test using `pd.Timestamp(snapshot_date, tz="UTC")` and `config.SLA_DAYS` → `round(float(within.sum()) / len(ch_df) * 100, 1)`.
- Zero Crit+High open findings → field stays `None` (no divide-by-zero).
- `try/except Exception` fail-soft: logs `WARNING` and sets field `None` on any error; severity snapshot always completes.
- `sla_rate_crit_high=sla_rate_crit_high` passed to severity `capture_snapshot(...)` call only. Owner call is unchanged.

### tests/content/test_trend_store.py

Three tests appended, cloned from Phase 16 MTTR analogs (L874/L921/L952):

- `test_sla_rate_crit_high_roundtrip` — float 87.3 survives write/read cycle.
- `test_sla_rate_params_default_to_none` — omitted param writes JSON null (not a missing key).
- `test_sla_rate_backward_compat` — old snapshot lacking the key cold-starts to `None` via `snap.get()`.

## Verification

- `python data/trend_store.py` — smoke passes, prints `Backward-compat cold-start (sla_rate_crit_high): OK`, exits 0.
- `python -c "import ast; ast.parse(open('scripts/capture_trend_snapshot.py').read())"` — parse succeeds.
- `pytest tests/content/test_trend_store.py -k "sla_rate" -x -q` — 3 collected, 3 passed.
- `pytest tests/content/test_trend_store.py` — 29 passed, 0 failed (no regressions to prior 26 tests).
- `grep -c "sla_rate_crit_high=sla_rate_crit_high" scripts/capture_trend_snapshot.py` → 1 (severity call only).

## Commits

| Task | Commit | Files | Description |
|------|--------|-------|-------------|
| 1 | d92732e | data/trend_store.py | feat: add sla_rate_crit_high field to capture_snapshot() + backward-compat smoke |
| 2 | 35a1606 | scripts/capture_trend_snapshot.py | feat: compute reopened-aware sla_rate_crit_high in capture_trend_snapshot |
| 3 | 631d670 | tests/content/test_trend_store.py | test: append round-trip + default + backward-compat tests for sla_rate_crit_high |

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries beyond what the plan's threat model covers. The only new persisted value is `sla_rate_crit_high` — a single aggregate float. T-17-01 (information disclosure), T-17-02 (fail-soft), and T-17-03 (tz-aware computation) are all mitigated in the implementation as specified.

## Self-Check: PASSED

- `data/trend_store.py` — exists, contains `sla_rate_crit_high`
- `scripts/capture_trend_snapshot.py` — exists, parses, contains `sla_rate_crit_high=sla_rate_crit_high` once
- `tests/content/test_trend_store.py` — exists, 3 new tests collected and passing
- Commits d92732e, 35a1606, 631d670 — all present in git log
