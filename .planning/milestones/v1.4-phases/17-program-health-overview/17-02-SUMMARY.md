---
phase: 17-program-health-overview
plan: "02"
subsystem: program-health-module
status: complete
tags: [program-health, module, rag, cold-start, sla, owner, compute]
requirements: [RPT-07]

dependency_graph:
  requires:
    - reports/modules/base.py (BaseModule, ModuleData, ModuleConfig)
    - reports/modules/rag_utils.py (build_rag_strip_entry, STATUS_COLOR)
    - reports/modules/board_report_utils.py (extract_owner)
    - utils/open_count.py (open_findings_at reopened-aware predicate)
    - data/trend_store.py (read_trend, _sanitise_tag_for_filename)
    - config.py (SLA_DAYS)
    - reports/modules/registry.py (@register_module auto-discovery)
    - sla_rate_crit_high snapshot field (Plan 17-01)
  provides:
    - ProgramHealthModule.compute() — 4-signal OD-5 composite RAG + Owner velocity
    - _composite_rag_od5() / _signal_direction() — pure helpers (tested independently)
    - ModuleData fully populated (metrics, table_data, analyst_rows, rag_strip, driver_narrative)
    - program_health in _MODULES_NEEDING_TREND_SNAPSHOTS frozenset
  affects:
    - reports/composed_report.py (_MODULES_NEEDING_TREND_SNAPSHOTS frozenset)
    - tests/test_program_health_module.py (34 compute-layer tests)

tech_stack:
  added: []
  patterns:
    - OD-5 composite RAG rule with structural missing-signal Amber cap (D-17-06)
    - _signal_direction() with flat_band + higher_is_better (D-17-07)
    - Cold-start Amber path (D-17-08) — rag_strip status="yellow", NOT "no_data"
    - Owner velocity inside compute() (Option A — no second kwargs gate)
    - tz-aware Timestamp coercion: tz_convert("UTC") when tzinfo present, else Timestamp(tz="UTC")
    - validate_config() with WARNING + default fallback (T-17-04 threshold-injection mitigation)
    - D-16-08 snapshot dedup by calendar month (VERBATIM from mttr_trend_module)

key_files:
  created:
    - reports/modules/program_health_module.py
    - tests/test_program_health_module.py
  modified:
    - reports/composed_report.py

decisions:
  - "D-17-02 definition parity: signals read snapshot fields directly (critical, new/fixed_findings_count, sla_rate_crit_high, mttr_overall_days) — never re-derive from raw data"
  - "D-17-06 structural cap: _composite_rag_od5() enforces missing→amber before green_count check; cannot be bypassed via module_options"
  - "Net velocity direction: delta-of-deltas (curr_net_delta < prev_net_delta = improving), binary, flat_band=0.0 per RESEARCH Open Question 1"
  - "Cold-start MTTR tile = None ('—'); no fixed_vulns_df threaded per D-17-01 per RESEARCH Open Question 2"
  - "tz-aware Timestamp fix: pd.Timestamp(tz=) fails on already-tz-aware datetime; use .tz_convert('UTC') conditional on tzinfo presence"

metrics:
  duration_seconds: 2400
  completed_date: "2026-06-12"
  tasks_completed: 3
  files_modified: 3
---

# Phase 17 Plan 02: ProgramHealthModule Compute Layer Summary

**One-liner:** OD-5 four-signal composite RAG module (`program_health`) with structural missing-signal Amber cap, cold-start Amber path, reopened-aware SLA posture tile, and Owner velocity table — compute layer only (Plan 03 adds renderers).

## What Was Built

### reports/modules/program_health_module.py

The `program_health` auto-discovered module (@register_module, MODULE_ID=`program_health`) implementing:

**Module-level pure helpers:**
- `_composite_rag_od5(signal_statuses, green_min=4, amber_min=2)` — OD-5 composite with D-17-06 structural Amber cap when any signal is "missing" and raw would be "green"
- `_signal_direction(curr, prev, higher_is_better, flat_band=0.0)` — None→"missing"; abs(delta)<=flat_band→"amber"; green/red by direction

**compute() signals (D-17-02 — definition parity):**
- Signal 1 Open-Critical MoM: `snap.get("critical")` curr vs prev; higher_is_better=False; flat_band=open_crit_flat_abs
- Signal 2 Net Velocity: `new_findings_count - fixed_findings_count`; delta-of-deltas direction; flat_band=0.0 (binary)
- Signal 3 SLA Posture: `snap.get("sla_rate_crit_high")` from Plan 17-01; higher_is_better=True; flat_band=sla_rate_flat_pct
- Signal 4 MTTR Overall: `snap.get("mttr_overall_days")`; higher_is_better=False; flat_band=mttr_flat_days

**Cold-start path (D-17-08):** `< 2` deduped snapshots → composite="amber", rag_strip status="yellow" (NOT "no_data"), headline="Trend Being Established". Current Open-Critical and SLA posture tiles computed from live `vulns_df` via `open_findings_at()`. MTTR current tile = None ("—") — no `fixed_vulns_df` threaded (D-17-01).

**Owner velocity (D-17-09):** `open_findings_at()` Crit+High per owner, MoM delta from owner-dimension `read_trend()` snapshot, >20% outlier flag. Degrades gracefully when `owner_trend["insufficient_data"]=True`.

**Security:** `validate_config()` coerces all 6 `module_options` keys (int/float); bad values log WARNING and fall back to default (T-17-04). `get_audit_info()` documents OD-5 rule and D-17-06 cap.

### reports/composed_report.py

`"program_health"` added to `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset (one line, Phase 17 D-17-01 comment). NOT in `_MODULES_NEEDING_FIXED_VULNS`. Owner-dimension snapshot is read inside `compute()` (Option A). `run_all.py --dry-run` passes with no regression to all 5 existing groups.

### tests/test_program_health_module.py

34 tests across 5 test classes:

| Class | Tests | What's verified |
|-------|-------|----------------|
| TestColdStart | 3 | No-snapshot → amber; 1 snapshot → amber + current tiles; deduped=1 → cold-start |
| TestCompositeRAG | 3 | All-green; 2-green=amber; 1-green=red |
| TestMissingSignalCap | 3 | Missing caps amber (D-17-06); missing name in narrative; structural, not bypassable |
| TestSlaReopenedAware | 2 | REOPENED finding in SLA population; 50% rate with 2 open (1 within SLA) |
| TestEmptyDataGuard | 2 | Zero-row → no_data strip; works with snapshots too |
| TestOwnerOutlierFlagging | 3 | No trend = no flag; >20% → outlier; threshold option respected |
| TestPureFunctions | 18 | All _composite_rag_od5 and _signal_direction combinations |

All 8 acceptance-criteria test names present. CoW strict mode enforced. Synthetic data only (QUAL-05).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed tz-aware Timestamp coercion in SLA tile computation**

- **Found during:** Task 3 (tests revealed the failure)
- **Issue:** `pd.Timestamp(report_date, tz="UTC")` raises `TypeError: Cannot pass a datetime or Timestamp with tzinfo with the tz parameter` when `report_date` is already tz-aware (e.g. `datetime(2026, 6, 12, tzinfo=timezone.utc)`)
- **Fix:** Changed both SLA tile computation sites to use `pd.Timestamp(report_date).tz_convert("UTC") if getattr(report_date, "tzinfo", None) is not None else pd.Timestamp(report_date, tz="UTC")` — matches the pattern in `open_count.py` and `board_report_utils.py`
- **Files modified:** `reports/modules/program_health_module.py`
- **Commit:** 887ce7b (included with Task 3 commit)

**2. [Rule 1 - Bug] Fixed test fixture SLA clock semantics**

- **Found during:** Task 3 (test_reopened_finding_in_sla_denominator failing)
- **Issue:** Original test fixtures set REOPENED `first_found=20d ago` which is over the 15d critical SLA, so both findings were correctly marked overdue (SLA rate = 0%), but the assertion was `0 < sla_rate < 100`. The SLA clock starts at `first_found` (consistent with `capture_trend_snapshot.py`), not `resurfaced_date`.
- **Fix:** Changed fixture so REOPENED finding has `first_found=5d ago` (within 15d SLA) — now correctly tests that REOPENED findings are *included* in the open population and that their within-SLA status is computed correctly.
- **Files modified:** `tests/test_program_health_module.py`

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns. The only new persisted state is the module registration in `_MODULES_NEEDING_TREND_SNAPSHOTS`. T-17-04 (threshold injection) is mitigated via `validate_config()`. T-17-05 (analyst row PII) is mitigated — analyst tabs carry only owner tag names + aggregate counts + MoM delta. T-17-06 (fail-soft) is mitigated via `snap.get()` throughout and whole-compute `try/except`.

## Self-Check: PASSED

- `reports/modules/program_health_module.py` — exists, contains `@register_module`, `MODULE_ID = "program_health"`, `_composite_rag_od5`, `_signal_direction`, `validate_config`, `get_audit_info`
- `reports/composed_report.py` — `"program_health"` in `_MODULES_NEEDING_TREND_SNAPSHOTS`; not in `_MODULES_NEEDING_FIXED_VULNS`
- `tests/test_program_health_module.py` — exists, 34 tests collected, all pass
- `run_all.py --dry-run` — exits 0, 5 groups validated
- `run_all.py` does NOT contain `"program_health"` (it's a module, not a slug)
- Commits 1f1c9ff, bf6caa7, 887ce7b — all present in git log
