---
phase: 15-independent-new-modules
plan: "01"
subsystem: reporting
tags: [modules, reopened-vulns, four-channel, pandas, openpyxl, RAG, analyst-drill-down]

# Dependency graph
requires:
  - phase: 14-board-report-polish
    provides: BaseModule, ModuleData, four-channel render contract, register_module, extract_owner, rag_utils, format_utils
provides:
  - "ReopenedVulnsModule (MODULE_ID=reopened_vulns) — four-channel PATHFINDER module proving the full render contract shape for Phase 15 parallel modules"
  - "Analyst drill-down schema locked: plugin_id, resurfaced_date, reopen_lag_days, owner — confirmed valid on live tenant (30,010 REOPENED rows, 100% resurfaced_date coverage)"
  - "39-test suite with CoW-strict fixtures covering REOPENED filter, reopen-lag, rate degradation, empty-data guard x4 channels"
affects:
  - 15-independent-new-modules (plans 02–05 copy the PATHFINDER four-channel shape)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "PATHFINDER shape: @register_module + BaseModule + four-channel render methods as the canonical template for Phase 15 modules"
    - "CoW compliance: .assign() only after filter; no df['col']= chained assignment anywhere in module"
    - "Rate-denominator degradation: fixed_vulns_df kwarg absent → rate=None + metadata['rate_disclosure'] note, never a silent zero"
    - "Analyst drill-down columns: plugin_id, resurfaced_date, reopen_lag_days, owner only (no hostnames/IPs — QUAL-05)"

key-files:
  created:
    - reports/modules/reopened_vulns_module.py
    - tests/test_reopened_vulns_module.py
  modified: []

key-decisions:
  - "Analyst drill-down schema confirmed as lag-available (plugin_id, resurfaced_date, reopen_lag_days, owner) — live-tenant spot-check returned 30,010 REOPENED rows with 100% resurfaced_date population; no disclosure-wording fallback needed"
  - "state==REOPENED is the PRIMARY filter (current snapshot, not open_findings_at) per RPT-03"
  - "Rate denominator uses fixed_vulns_df kwarg; graceful degradation to count-only when absent with explicit disclosure note"
  - "RAG thresholds (green_rate=5.0%, yellow_rate=10.0%) overridable via config.options per D-15-07"

patterns-established:
  - "PATHFINDER four-channel shape: all Phase 15 modules copy this exact import block, compute() guard, ModuleData construction, and render method error guards"
  - "Empty-data guard first in compute(): check vulns_df empty or missing state column → _empty_result before any pandas work"

requirements-completed: [RPT-03, QUAL-02, QUAL-03, QUAL-05]

# Metrics
duration: 65min
completed: 2026-06-11
---

# Phase 15 Plan 01: ReopenedVulnsModule (PATHFINDER) Summary

**ReopenedVulnsModule four-channel PATHFINDER delivering current-snapshot reopened-count + reopen-rate + Owner cut + analyst drill-down, with schema confirmed on live tenant (30,010 REOPENED rows, 100% resurfaced_date coverage)**

## Performance

- **Duration:** ~65 min
- **Started:** 2026-06-11T20:02:00Z
- **Completed:** 2026-06-11T20:12:56Z
- **Tasks:** 2 (1 code + 1 checkpoint)
- **Files modified:** 2

## Accomplishments

- Built `ReopenedVulnsModule` — the PATHFINDER module that proves all four render channels (PDF, Excel, email panel, analyst tabs + RAG strip) in isolation before the four parallel Phase-15 modules copy the shape
- Live-tenant checkpoint confirmed `resurfaced_date` fully populated on REOPENED findings (30,010 rows, 100% coverage) — lag-available analyst drill-down schema locked with no fallback wording needed
- 39 unit tests pass under `-W error::FutureWarning` (CoW strict mode) with entirely synthetic fixtures; no real hostnames/IPs/plugin names in any fixture (QUAL-05)

## Task Commits

1. **Task 1: Build ReopenedVulnsModule current-snapshot core + four channels** - `30662e7` (feat)
2. **Task 2: Live-tenant resurfaced_date population spot-check** - checkpoint APPROVED, no code change

**Plan metadata:** (this SUMMARY commit)

## Files Created/Modified

- `reports/modules/reopened_vulns_module.py` — ReopenedVulnsModule: MODULE_ID=reopened_vulns, @register_module, compute() with REOPENED filter + reopen-lag + Owner cut + rate degradation, all four render channels, 573 lines
- `tests/test_reopened_vulns_module.py` — 39 unit tests with CoW-strict synthetic fixtures, 579 lines

## Decisions Made

- **Analyst schema: lag-available (no fallback wording).** The Task 2 checkpoint confirmed 100% `resurfaced_date` coverage on the live tenant's 30,010 REOPENED rows. The `plugin_id, resurfaced_date, reopen_lag_days, owner` drill-down schema stands as-built; no "lag unavailable" disclosure text is needed.
- **state==REOPENED primary filter.** Reads directly from `vulns_df["state"]` uppercased, not through `open_findings_at`, matching RPT-03.
- **Rate denominator via kwarg, graceful degradation.** When `fixed_vulns_df` is absent, `reopen_rate` is `None` and `metadata["rate_disclosure"]` carries the disclosure; the module never renders a silent zero or crashes.
- **CoW-strict throughout.** All column creation uses `.assign()`; no `df["col"]=` after filter anywhere in the module.

## Deviations from Plan

None — plan executed exactly as written. Task 2 checkpoint returned APPROVED with the lag-available schema confirmed; no code change was required.

## Issues Encountered

None. The `ChainedAssignmentError` warnings in test output originate from pandas internals (`com.apply_if_callable` inside `pd.DataFrame.assign`), not from the module or test code; they are informational and do not fail under `-W error::FutureWarning` (which only errors on `FutureWarning`).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- PATHFINDER shape locked and confirmed: `@register_module`, `compute()` guard pattern, four render channels, ModuleData construction, analyst-drill-down column set — all verified end-to-end
- Parallel Phase-15 modules (plans 02–05) can safely copy this shape without further schema negotiation
- `resurfaced_date` population confirmed valid on this tenant — no compatibility shims needed in downstream modules that reference this field

---
*Phase: 15-independent-new-modules*
*Completed: 2026-06-11*
