---
phase: 18-management-summary-migration-docs
plan: "02"
subsystem: data-fetching
tags: [pytenable, pandas, parquet, fetchers, consumer-audit, tdd, D-18-05, D-18-06]

# Dependency graph
requires:
  - phase: 18-management-summary-migration-docs
    plan: "01"
    provides: structural baseline + smoke script confirming management_summary backward compat (GEN-01)
provides:
  - Bounded last_fixed fetch (config.FIXED_LOOKBACK_DAYS=365) in fetch_fixed_vulnerabilities()
  - Live-proven integer-epoch filter shape (not date-range dict — Task 0 disproved assumption A2)
  - Consumer-audit gate (D-18-06): narrow-vs-wide equality tests for all result-consuming modules
  - Precisely-scoped dynamic-discovery test for fetch_fixed_vulnerabilities callers
  - D-18-10 gate 1 GREEN: fetch widening verified safe before Plan 03 reconstruction
affects:
  - 18-03-PLAN (reconstruction backfill — consumes the widened fetch)
  - reports/modules/critical_remediation_sla_module.py
  - reports/modules/mttr_trend_module.py

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Consumer-audit gate pattern: narrow-vs-wide synthetic frame equality test before widening a shared fetch"
    - "Precisely-scoped AST sweep for result-consuming callers (excludes tests/scripts/docs/pass-throughs)"
    - "Plain int Unix epoch as proven Tenable last_fixed filter shape (not date-range dict)"

key-files:
  created:
    - scripts/probe_last_fixed_filter.py
    - tests/test_consumer_audit.py
  modified:
    - config.py
    - data/fetchers.py

key-decisions:
  - "D-18-05: Bounded FIXED_LOOKBACK_DAYS=365 in config.py; fetch uses int Unix epoch cutoff (not 2yr unbounded pull). Plain int epoch proven by Task 0 live probe — date-range dict shape (assumption A2) was REJECTED with 'Not a valid integer.' error."
  - "D-18-06: Every result-consuming module (CriticalRemediationSLAModule, MTTRTrendModule) applies its own explicit date window at compute() — fetch widening causes zero silent metric drift. MTTRTrendModule keeps deliberate rolling-30 (D-16-02)."
  - "fetch_all_vulnerabilities left unchanged: it fetches open/reopened state; no last_fixed time filter is applicable to open findings. Plan 03 reconstruction predicate sources open rows from current state."
  - "All direct callers of fetch_fixed_vulnerabilities in reports/ are pass-throughs (run_report fanning to composer); result-computing consumers receive fixed_vulns_df as **kwargs — dynamic discovery gate reflects this architecture correctly."

patterns-established:
  - "Consumer-audit-before-fetch-widen: proves D-18-10 gate 1 before reconstruction (Plan 03) widens the population it consumes"
  - "AST sweep with explicit exclusion sets: tests/, scripts/, docs/, import-only, pass-throughs — intentional co-edit gate (project_frozenset_gate_test_coupling)"

requirements-completed: [GEN-01]

# Metrics
duration: 45min
completed: 2026-06-20
---

# Phase 18 Plan 02: Bounded last_fixed Fetch + Consumer-Audit Gate (D-18-05 / D-18-06)

**Bounded 12-month last_fixed filter on fixed-vuln fetch via proven int-epoch shape, guarded by a TDD consumer-audit suite proving zero metric drift across all result-consuming modules.**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-06-19T10:46:00Z
- **Completed:** 2026-06-20T11:30:00Z
- **Tasks:** 4 (Task 0 checkpoint + Tasks 1, 2, 3 auto)
- **Files modified:** 4

## Accomplishments

- Live-API probe (Task 0) disproved assumption A2: the date-range dict `{"date": "YYYY-MM-DD", "modifier": "date-range"}` was rejected by Tenable with `{'last_fixed': ['Not a valid integer.']}`. The proven shape is a plain `int` Unix epoch seconds.
- Consumer-audit suite (Task 1 RED / Task 2 GREEN) confirmed that both CriticalRemediationSLAModule and MTTRTrendModule already apply their own explicit date windows at compute() time — no consumer drift was found; Task 2 was a "no fixes needed" GREEN.
- Bounded `last_fixed=_cutoff_epoch` filter added to `fetch_fixed_vulnerabilities()` (Task 3) using the live-proven int-epoch shape; `FIXED_LOOKBACK_DAYS=365` in `config.py` bounds it to 12 months.
- `fetch_all_vulnerabilities` confirmed unchanged: open/reopened findings have no `last_fixed` concept; Plan 03's reconstruction predicate sources open rows from current API state.
- D-18-10 gate 1 is GREEN: all 8 consumer-audit tests pass before Plan 03 widens the population.

## Task Commits

Each task was committed atomically:

1. **Task 0: Live-API probe** - `2ad8ed9` (chore: add live-API probe for last_fixed filter shape + direction)
2. **Task 1: Consumer-audit RED gate** - `ecc6f50` (test: add consumer-audit RED gate for fixed-vuln fetch widening)
3. **Task 2: Consumer-audit GREEN** - `0008255` (feat: verify consumer-audit GREEN — no explicit-window fixes needed)
4. **Task 3: Bounded fetch + config constant** - `ecf7788` (feat: widen fetch_fixed_vulnerabilities with bounded last_fixed filter)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `scripts/probe_last_fixed_filter.py` — Isolated live-API probe proving the last_fixed filter shape (plain int epoch, not date-range dict) and the 7-day < 90-day monotonic direction check
- `tests/test_consumer_audit.py` — 8 tests: narrow-vs-wide equality for CriticalRemediationSLAModule + MTTRTrendModule, fetch-filter shape/bound assertions, and a precisely-scoped AST-based caller-discovery gate
- `config.py` — Added `FIXED_LOOKBACK_DAYS: int = 365` constant (D-18-05; mirrors SLA_DAYS / ON_TIME_SCAN_WINDOW_DAYS placement)
- `data/fetchers.py` — Added `lookback_days` kwarg + `_cutoff_epoch` computation + `last_fixed=_cutoff_epoch` in export_filters; updated docstring documenting D-18-05 + D-18-06 audit results

## Decisions Made

**A2 assumption refuted:** The RESEARCH assumed `last_fixed` accepted a date-range dict `{"date": "...", "modifier": "date-range"}`. The Task 0 live probe showed this is rejected: `{'last_fixed': ['Not a valid integer.']}`. The proven shape is a plain `int` Unix epoch seconds value. The fetch rework was built on the live-proven shape, not the unverified ref-doc assumption.

**fetch_all_vulnerabilities left unchanged:** That function fetches `state=["open", "reopened"]` only. A `last_fixed` time filter is not applicable (open findings have not been fixed). Plan 03's reconstruction predicate uses the current-state open row population — no bounded window needed on the open-findings fetch.

**Consumer audit found no drift (Task 2 "no fixes needed"):** Both consumers already had their own explicit windows:
- `CriticalRemediationSLAModule`: filters to `last_fixed >= report_date - 30d` at compute step 4
- `MTTRTrendModule`: filters to `last_fixed >= report_date - window_days` (default 30) via D-16-02 rolling window

All three narrow-vs-wide equality assertions and both per-severity MTTR assertions passed GREEN without any consumer-side code changes.

## Deviations from Plan

None — plan executed exactly as written. Task 2 concluded "no explicit-window fixes needed" (the GREEN outcome when both consumers already had compliant windows), which is the correct TDD outcome when RED tests pass on the existing code.

The only factual correction from the plan's assumed A2 filter shape was surfaced by Task 0 (the checkpoint gate) and recorded before Task 3 was built on it — this is the plan's designed de-risking path, not a deviation.

## Issues Encountered

**Pre-existing CoW warnings in board_report_utils.py (lines 378, 383):** `df_local["_num"] = ...` and `df_local["_den"] = ...` emit `ChainedAssignmentError` under `pd.options.mode.copy_on_write = True`. These are pre-existing in `reports/modules/board_report_utils.py` and are out of scope for this plan (Task 3 touched only `config.py` and `data/fetchers.py`). Tests pass despite the warnings; no test assertions depend on the affected code path. Deferred per scope-boundary rule.

## Known Stubs

None — this plan delivers a data-fetch rework and test gate, not rendering logic.

## Threat Flags

No new network endpoints or auth paths introduced. The `last_fixed=_cutoff_epoch` filter value logged at `[API FETCH]` is a Unix epoch integer — no credential strings appear in the log line (T-18-03 mitigated).

## Next Phase Readiness

- Plan 03 (reconstruction backfill) may now proceed: the widened fetch is bounded, consumer-audit gate is GREEN, and D-18-10 gate 1 is satisfied.
- `fetch_fixed_vulnerabilities(tio, cache_dir)` now returns up to 12 months of fixed findings — the reconstruction predicate in Plan 03 will operate on this wider population.
- No blockers.

## Self-Check: PASSED

- `config.py` modified: FOUND
- `data/fetchers.py` modified: FOUND
- `tests/test_consumer_audit.py` exists: FOUND
- `scripts/probe_last_fixed_filter.py` exists: FOUND
- Commits 2ad8ed9, ecc6f50, 0008255, ecf7788: all in git log
- `python -m pytest tests/test_consumer_audit.py`: 8 passed, exit 0
- `python -W error::FutureWarning -m pytest tests/test_consumer_audit.py`: 8 passed, exit 0 (CoW warnings from pre-existing board_report_utils.py are out-of-scope)

---
*Phase: 18-management-summary-migration-docs*
*Completed: 2026-06-20*
