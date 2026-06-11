---
phase: 15-independent-new-modules
plan: "04"
subsystem: reports/modules
tags: [module, new-vs-remediated, mom, stacked-inflow, four-channel, rpt-01]
status: complete

dependency_graph:
  requires:
    - data/trend_store.py              # 15-02 aggregate fields (new_findings_count, fixed_findings_count, ...)
    - reports/modules/base.py          # BaseModule, ModuleConfig, ModuleData
    - reports/modules/registry.py      # @register_module auto-discovery
    - reports/modules/rag_utils.py     # rag_status_from_value, build_rag_strip_entry
    - reports/modules/format_utils.py  # safe_int, safe_pct, safe_format
    - reports/modules/board_report_utils.py  # extract_owner
    - utils/open_count.py              # open_findings_at (QUAL-02 open context)
  provides:
    - reports/modules/new_vs_remediated_module.py  # MODULE_ID=new_vs_remediated
  affects:
    - reports/modules/registry._modules  # adds new_vs_remediated at import time
    - reports/composed_report.py         # registers trend/recast gates for Phase-15 modules

tech_stack:
  added: []
  patterns:
    - stacked inflow split (net_new + resurfaced) per D-15-01/02
    - Option B outflow from fixed_findings_count snapshot field (D-15-06)
    - cold-start guards for insufficient trend history and absent fixed_findings_count (QUAL-01)
    - partial-month label helper (D-15-08)
    - ZeroDivision-safe MoM delta helper (Pitfall 5)
    - test fixtures build empty frames with columns (fetcher contract) for cold-start purity

key_files:
  created:
    - reports/modules/new_vs_remediated_module.py
    - tests/test_new_vs_remediated_module.py
  modified:
    - reports/composed_report.py

decisions:
  - "Stacked inflow = net_new + resurfaced (D-15-01/02): inflow is split so resurfaced findings are not double-counted as net-new"
  - "Outflow uses Option B — the fixed_findings_count snapshot field (D-15-06) — not a recomputed diff; absent field renders an em dash, never a misleading zero"
  - "composed_report.py pre-registers all three Phase-15 module IDs in _MODULES_NEEDING_TREND_SNAPSHOTS and _MODULES_NEEDING_RECAST_RULES (Phase-14 kwargs gates), with fail-soft conditional fetch blocks"
  - "Test fixtures (_make_vulns/_make_assets) construct empty DataFrames with columns=list(defaults) to mirror the fetcher's zero-row-with-columns contract; sibling modules (reopened_vulns, external_dmz) call extract_owner unguarded and rely on the same contract"

metrics:
  duration_minutes: 60
  completed_date: "2026-06-11"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 1
---

# Phase 15 Plan 04: New vs Remediated MoM Module Summary

**One-liner:** Four-channel `NewVsRemediatedModule` showing monthly inflow (net-new + resurfaced, stacked) vs remediation outflow from trend snapshots, plus the `composed_report` trend/recast gate registration for the Phase-15 module set (RPT-01).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Register trend/recast gates in composed_report | 5c243eb | reports/composed_report.py |
| 2 | Implement NewVsRemediatedModule + tests | 508b35a | reports/modules/new_vs_remediated_module.py, tests/test_new_vs_remediated_module.py |

## What Was Built

`NewVsRemediatedModule` (MODULE_ID=`new_vs_remediated`) is a MoM four-channel module that:

1. **Stacked inflow** — splits each month's inflow into **net-new** and **resurfaced** components (D-15-01/02) so resurfaced findings are not double-counted as new.
2. **Option B outflow** — reads remediation outflow from the `fixed_findings_count` snapshot field added in 15-02 (D-15-06), rather than recomputing a diff. A cold-start guard renders an em dash (not zero) when an older snapshot lacks the field, so "0 remediated" is never shown misleadingly.
3. **Cold-start handling** (QUAL-01) — `_build_cold_start_result` covers insufficient trend history; absent `fixed_findings_count` is handled separately for the outflow channel.
4. **Owner context + open count** — `extract_owner()` Owner cut plus `open_findings_at()` for open-count context (QUAL-02).
5. **Partial-month labels** (D-15-08) via `_month_label`, and a `_safe_mom_delta` helper guarding ZeroDivisionError (Pitfall 5).
6. **Four render channels** — `render_pdf_section`, `render_excel_tabs`, `render_email_panel` (CONTRACT-01), `render_analyst_tabs` (CONTRACT-02), `render_rag_strip_entry` (CONTRACT-03). RAG strip is driven by the last completed month's net_delta (D-15-07).
7. **composed_report gate registration** — `_MODULES_NEEDING_TREND_SNAPSHOTS` and `_MODULES_NEEDING_RECAST_RULES` pre-register the three Phase-15 module IDs, with conditional (fail-soft) trend-snapshot and recast fetch blocks forwarded via `composer_kwargs` (Phase-14 kwargs gates).

## Test Coverage

49 tests pass under both default and `-W error::FutureWarning` (pandas CoW strict mode):
- Module registration + registry presence
- Stacked inflow split (net-new vs resurfaced)
- Option B outflow from `fixed_findings_count`; cold-start em dash on absent field
- Insufficient-trend cold-start guard
- Owner cut + `open_findings_at` open context
- Partial-month labels, ZeroDivision-safe deltas
- Empty-data guard × all four render channels (cold start with empty vulns/assets)
- RAG strip logic on last completed month net_delta

## Deviations from Plan

### Rescue note (orchestrator)

The plan was executed by a background worktree executor that completed all implementation
(composed_report.py gate registration, the full module, and the test file) but could not
reach its commit step (Bash unavailable to background worktree agents in this session). The
orchestrator rescued the uncommitted files from the worktree onto `main`, ran the test +
dry-run gates, fixed the fixture bug below, and committed Tasks 1 and 2 atomically. No
implementation logic was changed during rescue — only the two test-fixture helpers.

### Auto-fixed Issues

**1. [Rule 1 - Bug] Cold-start test fixtures built columnless empty frames**
- **Found during:** Post-merge test gate (failures invisible to the executor, which had no Bash to run pytest)
- **Issue:** `_make_vulns([])` and `_make_assets([])` called `pd.DataFrame(records)` with empty `records`, producing a frame with no columns and no index. Cold-start tests (`vulns_rows=[]` / `asset_rows=[]`) then failed: date coercion raised `KeyError: 'first_found'`, and `extract_owner()` raised `ValueError: cannot set a frame with no defined index and a scalar` at `board_report_utils.py:304`.
- **Root cause:** The real fetchers return zero-*row* DataFrames *with columns*; the fixtures did not honor that contract. The module is correct — sibling modules `reopened_vulns` and `external_dmz` call `extract_owner()` unguarded and pass because their fixtures supply columns.
- **Fix:** `pd.DataFrame(records, columns=list(defaults.keys()))` in both helpers, so empty input yields zero rows with real columns.
- **Files modified:** `tests/test_new_vs_remediated_module.py`
- **Commit:** 508b35a

## Threat Surface Scan

No new network endpoints, auth paths, or trust-boundary schema changes. The analyst Owner cut passes through `extract_owner()` output (operator-local tag parsing) and aggregate counts only; trend snapshots remain aggregate-only (PII boundary D-04-08 / QUAL-05 maintained).

## Self-Check: PASSED

- `reports/modules/new_vs_remediated_module.py` exists: FOUND
- `tests/test_new_vs_remediated_module.py` exists: FOUND
- `reports/composed_report.py` gate registration present: FOUND
- Commit 5c243eb (Task 1): FOUND
- Commit 508b35a (Task 2): FOUND
- `pytest tests/test_new_vs_remediated_module.py -q -W error::FutureWarning` exits 0 (49 passed): VERIFIED
- `new_vs_remediated` in registry._modules: VERIFIED
- `python run_all.py --dry-run` exits 0 (all 5 groups validated): VERIFIED
