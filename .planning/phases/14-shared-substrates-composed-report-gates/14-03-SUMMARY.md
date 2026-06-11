---
phase: 14-shared-substrates-composed-report-gates
plan: "03"
subsystem: reporting
tags: [composed_report, kwargs-gates, trend_snapshots, recast_rules_df, module-registry, tdd]

# Dependency graph
requires:
  - phase: 14-shared-substrates-composed-report-gates-plan-01
    provides: external-scope frozenset pattern (_MODULES_NEEDING_ENV_TOTAL) that this plan mirrors
  - phase: 14-shared-substrates-composed-report-gates-plan-02
    provides: _MODULES_NEEDING_FIXED_VULNS pattern and ReportComposer **self._kwargs fan-out

provides:
  - _MODULES_NEEDING_TREND_SNAPSHOTS frozenset in composed_report.py (stub-seeded, D-17)
  - _MODULES_NEEDING_RECAST_RULES frozenset in composed_report.py (stub-seeded, D-17)
  - Conditional trend fetch block (read_trend → full dict under trend_snapshots kwarg, D-16)
  - Conditional recast fetch block (fetch_recast_rules → recast_rules_df kwarg, D-16)
  - sc4_kwargs_stub_module.py auto-discovered via @register_module (no run_all.py registration)
  - 9 tests proving D-15 (signature unchanged), D-16 (full dict forwarded), D-17 (frozenset seeding), SC#3 (no-regression intersection logic), SC#4 (both kwargs reach compute())

affects: [phase-15, phase-16, phase-17, phase-18, critical_remediation_sla, mttr_trend, program_health]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Kwargs-gate frozenset pattern: module self-describes membership by adding MODULE_ID to a frozenset; composed_report.py fetches on demand via .intersection(modules); fan-out via ReportComposer **self._kwargs → compute(**kwargs). No composer.py/base.py change required."
    - "D-16 full-dict forwarding: read_trend() result ({snapshots, insufficient_data}) forwarded whole under trend_snapshots kwarg — consumers branch on insufficient_data; no list-stripping at the gate."
    - "_sanitise_tag_for_filename convention: trend fetch passes the same tag_filter value used at capture time ('all_assets' underscore, not the _log_scope 'all assets' space form). This matches trend_store.py WR-05 filename lookup."

key-files:
  created:
    - reports/modules/sc4_kwargs_stub_module.py
    - tests/test_composed_report_kwargs_gates.py
  modified:
    - reports/composed_report.py

key-decisions:
  - "D-15 enforced: run_report() signature is unchanged — no new parameters; kwarg payload injected into ReportComposer(**composer_kwargs) fan-out only"
  - "D-16 enforced: trend gate forwards full read_trend() dict {snapshots, insufficient_data} under trend_snapshots (not just the snapshots list); recast gate forwards recast_rules_df DataFrame"
  - "D-17 enforced: both frozensets seeded with sc4_kwargs_stub only; real v1.4 module IDs added in the phase that builds them; stub is auto-discovered via *_module.py glob and not registered in run_all.py"
  - "SC#3 no-regression: _MODULES_NEEDING_TREND_SNAPSHOTS.intersection(['other_module']) is falsy, so no trend/recast fetch fires for groups not listing the stub — verified by intersection-logic tests and Task 4 --dry-run"
  - "Task 4 checkpoint approved by human after exit-0 --dry-run for all 5 delivery groups with zero regression on existing composed groups; composer.py and base.py confirmed byte-unchanged"

patterns-established:
  - "Kwargs-gate pattern: add MODULE_ID to a frozenset in composed_report.py → fetch fires lazily → kwarg arrives at compute(**kwargs) via self._kwargs fan-out — one change site, zero composer changes"
  - "SC#4 acceptance-test stub: a Phase-N gate gets a dedicated *_module.py stub that asserts the kwarg arrives and records metrics; stub is auto-discovered, not production-registered; provides living proof of gate correctness"

requirements-completed: [SUB-03]

# Metrics
duration: ~65min
completed: 2026-06-11
---

# Phase 14 Plan 03: Kwargs-Forwarding Gates (SC#3, SC#4) Summary

**Two kwargs-forwarding gates added to composed_report.py (_MODULES_NEEDING_TREND_SNAPSHOTS, _MODULES_NEEDING_RECAST_RULES) following the existing _MODULES_NEEDING_FIXED_VULNS pattern, with SC#4 stub module auto-discovered at compute() to prove full-dict forwarding via the ReportComposer **self._kwargs fan-out.**

## Performance

- **Duration:** ~65 min
- **Started:** 2026-06-11T18:00:00Z
- **Completed:** 2026-06-11T18:14:00Z (continuation close-out)
- **Tasks:** 4 (3 auto + 1 checkpoint, approved by human)
- **Files modified:** 3 (1 modified, 2 created)

## Accomplishments

- Added `_MODULES_NEEDING_TREND_SNAPSHOTS` and `_MODULES_NEEDING_RECAST_RULES` frozensets to `reports/composed_report.py` seeded with `sc4_kwargs_stub` only (D-17), mirroring the existing `_MODULES_NEEDING_FIXED_VULNS` pattern exactly
- Added conditional fetch blocks: `need_trend` → `read_trend(dimension="severity", months=13)` with correct `_sanitise_tag_for_filename` tag_filter convention (avoids WR-05 filename/field divergence); `need_recast` → `fetch_recast_rules(tio, cache_dir)`; both appended to `composer_kwargs` under guards
- Created `reports/modules/sc4_kwargs_stub_module.py` — auto-discovered Phase-14 acceptance-test stub (no `run_all.py`/schema registration needed); `compute()` asserts both kwargs present and records `trend_snapshot_count` + `recast_rules_row_count` metrics; fail-soft via `_empty_result` when either is missing
- 9-test TDD suite (RED→GREEN) proving D-15 (signature unchanged), D-16 (full dict forwarded), D-17 (stub-only seeding), SC#3 (intersection short-circuits for non-listed modules), SC#4 (both kwargs reach compute())
- Task 4 human checkpoint: `python run_all.py --dry-run` exited 0 for all 5 delivery groups; `composer.py` and `base.py` confirmed byte-unchanged

## Task Commits

Each task was committed atomically:

1. **Task 1: Add trend_snapshots and recast_rules_df kwargs gates to composed_report** - `e19c7b6` (feat)
2. **Task 2: Create SC#4 kwargs stub module** - `2f12eb3` (feat)
3. **Task 3: Gate-forwarding + no-regression tests (SC#3, SC#4)** - `55fcbf6` (test)
4. **Task 4: --dry-run no-regression check (SC#3)** — checkpoint, approved by human (no commit — verification only)

**Plan metadata:** (this SUMMARY commit)

## Files Created/Modified

- `reports/composed_report.py` — Two new frozensets + two conditional fetch blocks + two composer_kwargs appends; run_report() signature unchanged; 37 lines added
- `reports/modules/sc4_kwargs_stub_module.py` — Phase-14 SC#4 acceptance-test stub; auto-discovered via `*_module.py` glob; asserts trend_snapshots and recast_rules_df arrive at compute(); 95 lines
- `tests/test_composed_report_kwargs_gates.py` — 9 tests covering D-15/D-16/D-17/SC#3/SC#4 with synthetic-only data (QUAL-05); 245 lines

## Decisions Made

- **D-15 (signature freeze):** run_report() signature explicitly unchanged; kwargs injected downstream only through ReportComposer(**composer_kwargs) fan-out. Asserted by inspect-based test.
- **D-16 (full-dict forwarding):** trend gate forwards the complete `{snapshots, insufficient_data}` dict — not just the list. Phase-15 consumers branch on `insufficient_data` (QUAL-01 cold-start requirement); list-stripping at the gate would destroy that signal.
- **D-17 (stub-only seeding):** Both frozensets contain only `sc4_kwargs_stub` in Phase 14. Real module IDs are added by the phase that builds each module. The stub itself requires no `run_all.py` registration — `registry.discover()` picks it up via the `*_module.py` glob.
- **_sanitise_tag_for_filename convention:** trend fetch uses `"all_assets"` (underscore, capture-time form) for the no-filter case, not the `_log_scope` `"all assets"` (space). Diverging these would silently cause trend_store.py WR-05 filename/field mismatch and cold-start fallbacks on every run.

## Deviations from Plan

None — plan executed exactly as written. Task 4 checkpoint approved by human with confirmation that `python run_all.py --dry-run` passed for all 5 groups (exit 0) and that `composer.py` / `base.py` are byte-unchanged.

## Issues Encountered

None. The `_sanitise_tag_for_filename` convention was already documented in `14-PATTERNS.md` as a gotcha and was implemented correctly on the first pass.

## User Setup Required

None — no external service configuration required. Phase-15 modules that need trend history or recast rules self-register by adding their MODULE_ID to `_MODULES_NEEDING_TREND_SNAPSHOTS` or `_MODULES_NEEDING_RECAST_RULES` in `reports/composed_report.py`.

## Threat Surface Scan

No new network endpoints, auth paths, file-access patterns, or schema changes introduced. The recast DataFrame forwarding (T-14-08) is bounded to the stub's row-count metric only — no asset-level fields logged or emitted. Phase-15 consumers own the per-field PII boundary.

## Known Stubs

`reports/modules/sc4_kwargs_stub_module.py` is intentionally a Phase-14 acceptance-test stub, not a production module. It is seeded in both frozensets solely to prove kwargs forwarding works end-to-end. It will NOT appear in any delivery group's `modules:` list. It can be removed (or retained as a regression canary) once Phase-15 ships real modules using the gates.

## Next Phase Readiness

- **Phase 15 is unblocked.** Any new module needing trend snapshots adds its MODULE_ID to `_MODULES_NEEDING_TREND_SNAPSHOTS`; any module needing recast rules adds to `_MODULES_NEEDING_RECAST_RULES`. No changes to `composer.py`, `base.py`, or `run_report()` required.
- The QUAL-01 cold-start branch mandate is enforced from Phase 15 onward: every MoM module must branch on `trend_snapshots["insufficient_data"]` before computing deltas.
- QUAL-05 synthetic-data discipline established for this plan's test fixtures; carries forward.

## Self-Check

- `reports/composed_report.py` exists and carries both frozensets: confirmed via `e19c7b6`
- `reports/modules/sc4_kwargs_stub_module.py` exists: confirmed via `2f12eb3`
- `tests/test_composed_report_kwargs_gates.py` exists and passes (9/9): confirmed via `55fcbf6` + pytest run
- All commits present in git log: `e19c7b6`, `2f12eb3`, `55fcbf6`

## Self-Check: PASSED

---
*Phase: 14-shared-substrates-composed-report-gates*
*Plan: 03*
*Completed: 2026-06-11*
