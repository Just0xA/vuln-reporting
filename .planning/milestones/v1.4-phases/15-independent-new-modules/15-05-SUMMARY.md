---
phase: 15-independent-new-modules
plan: "05"
status: complete
subsystem: reports/modules
tags: [vuln-density, mom-trend, per-snapshot-denominator, pitfall-4, drift-flag, cold-start, qual-01, qual-03, rpt-02]
requirements: [RPT-02, QUAL-01, QUAL-03, QUAL-05]

dependency_graph:
  requires:
    - 15-02  # on_time_asset_count field added to capture_snapshot()
    - 15-04  # vuln_density added to _MODULES_NEEDING_TREND_SNAPSHOTS in composed_report.py
  provides:
    - vuln_density MODULE_ID registered in reports.modules.registry
    - VulnDensityModule four-channel MoM density trend
  affects:
    - composed_report.py (consumes via trend_snapshots kwarg, no code change needed)

tech_stack:
  added: []
  patterns:
    - per-snapshot on_time_asset_count denominator (Pitfall 4 guard)
    - denom-drift >10% metadata flag (success criterion 2)
    - count_on_time_assets None-sentinel → _empty_result (D-14)
    - _build_cold_start_result QUAL-01 pattern (copied from new_vs_remediated_module)
    - .assign() CoW-safe in all production code and test fixtures

key_files:
  created:
    - reports/modules/vuln_density_module.py
    - tests/test_vuln_density_module.py
  modified: []

decisions:
  - "Per-snapshot denominator uses snap['on_time_asset_count']; snapshots with None or 0 denom are skipped (D-15-06 backward-compat) — not cold-started wholesale unless ALL snapshots lack usable denom"
  - "Drift flag compares last two USABLE denoms (those that contributed a density point), not last two raw snapshots — preserves accuracy when some snapshots have None denom"
  - "count_on_time_assets None → _empty_result (not cold-start) because the current-run denominator is required for the current-period density tile; cold-start is reserved for missing trend history"

metrics:
  duration_minutes: 25
  completed_date: "2026-06-11"
  tasks_completed: 1
  files_created: 2
  tests_added: 44
---

# Phase 15 Plan 05: Vulnerability Density Module Summary

**One-liner:** VulnDensityModule — fleet-size-normalized vulns/asset MoM trend using each snapshot's own on_time_asset_count denominator with >10% drift detection.

## What Was Built

`reports/modules/vuln_density_module.py` — a `@register_module` class implementing the full four-channel render contract:

- `compute()` — per-snapshot density from `on_time_asset_count` (never `len(assets_df)`), current-run denom from `count_on_time_assets()`, denom-drift flag, RAG via `rag_status_from_value(direction="lower_is_better")`
- `render_pdf_section` — density trend table with drift callout when flagged
- `render_excel_tabs` — "Vuln Density" tab with per-month open/asset/density columns
- `render_email_panel` — CONTRACT-01 panel with inline drift warning when `denom_drift_flag=True`
- `render_analyst_tabs` — CONTRACT-02: "Density by Month" + "Density by Owner" aggregate tabs
- `render_rag_strip_entry` — CONTRACT-03: pre-built strip cell

`tests/test_vuln_density_module.py` — 44 tests covering:

| Class | Tests | What's verified |
|---|---|---|
| `TestRegistration` | 5 | MODULE_ID, DISPLAY_NAME, registry auto-discovery, REQUIRED_DATA, default RAG thresholds |
| `TestColdStart` | 8 | cold-start on None/insufficient_data; no NaN in any channel; gray RAG strip |
| `TestPerSnapshotDenominator` | 5 | Pitfall 4: each snapshot uses its own denom; immutability across assets_df size changes; None-denom skip; all-None cold-start |
| `TestCurrentRunDenomNone` | 2 | count_on_time_assets None → _empty_result (no division) |
| `TestDenomDriftFlag` | 5 | >10% sets flag; =10% does not; <10% does not; 1 usable snapshot no flag; increase >10% sets flag |
| `TestPartialMonthLabel` | 5 | current month labeled "(MTD — partial)"; prior months plain; _month_label helper |
| `TestEmptyDataGuard` | 7 | all four channels on cold-start/zero inputs; zero on_time_asset_count not divided |
| `TestRagStatus` | 4 | green<2.0, yellow 2.0–4.0, red≥4.0; thresholds overridable via options |
| `TestOwnerCut` | 1 | analyst rows include per-Owner density tab |
| `TestDensityComputation` | 2 | all severity buckets summed; current_density in metrics |

## Key Decisions

1. **Pitfall 4 enforcement:** The per-snapshot loop uses `snap.get("on_time_asset_count")` exclusively. `len(assets_df)` appears only in a log message and docstring comment — verified by static check in test suite.

2. **None/0 denom skip vs. cold-start:** A snapshot with `on_time_asset_count=None` or `0` is silently skipped for density computation (backward-compat with pre-15-02 snapshots, D-15-06). The module only returns cold-start if ALL snapshots lack a usable denominator.

3. **Drift uses last two USABLE denoms:** `denom_series` accumulates only snapshots that contributed a density point. This ensures the drift check compares meaningful consecutive denominators, not a skipped snapshot vs. a valid one.

4. **current-run denom → _empty_result:** When `count_on_time_assets()` returns `None`, the module returns `_empty_result` (not cold-start) with an error message. Cold-start is reserved for "no trend history"; _empty_result is for "cannot compute any density today."

## Deviations from Plan

None — plan executed exactly as written. CoW fix (test fixtures used `df[col] = ...` instead of `.assign()`) was caught by `-W error::FutureWarning` in the first test run and corrected before the GREEN commit.

## Acceptance Criteria Verification

- [x] `reports/modules/vuln_density_module.py` contains `@register_module` and `MODULE_ID = "vuln_density"`
- [x] `vuln_density` present in registry on `import reports.modules`
- [x] Per-snapshot denominator test asserts each month divides by its own `on_time_asset_count` (NOT `len(assets_df)`)
- [x] Denom-drift test asserts the >10% flag is set on a fixture with a >10% denom change
- [x] Cold-start fixture (`insufficient_data`) renders notice; no "NaN" string in any channel (QUAL-01)
- [x] Zero-asset fixture returns `_empty_result` with gray cell; no `ZeroDivisionError` (QUAL-03)
- [x] `pytest tests/test_vuln_density_module.py` exits 0 under `-W error::FutureWarning`
- [x] `grep` confirms NO `len(assets_df)` used as a historical-point denominator

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Module is pure-compute with no I/O.

## Self-Check: PASSED

- `reports/modules/vuln_density_module.py` — FOUND
- `tests/test_vuln_density_module.py` — FOUND
- Commit `ba2e5f2` (RED — failing tests) — FOUND
- Commit `0cdac26` (GREEN — module implementation) — FOUND
- 44 tests pass, exit 0 under `-W error::FutureWarning`
