---
phase: 18-management-summary-migration-docs
plan: "01"
subsystem: management_summary
tags: [baseline, parity-gate, synthetic-fixture, QUAL-04, QUAL-02, D-18-10]
dependency_graph:
  requires: []
  provides:
    - tests/baselines/management_summary_structural_schema.py
    - tests/baselines/management_summary_structural_baseline.json
    - tests/baselines/management_summary_value_golden.json
    - tests/fixtures/management_summary_parity/*.parquet
    - tests/fixtures/management_summary_parity/trend_snapshots.json
    - scripts/smoke_management_summary_cutover.py
    - scripts/capture_management_summary_parity_golden.py
  affects:
    - .gitignore
tech_stack:
  added: []
  patterns:
    - shared structural-snapshot schema adapter (one adapter, two capture paths)
    - _NoLiveTenable sentinel (no live Tenable calls in smoke script)
    - bucketed golden (exact_match vs documented_difference per-metric policy)
    - frozen deterministic synthetic fixture (RFC-5737/6761, fixed seed + report_date)
key_files:
  created:
    - scripts/smoke_management_summary_cutover.py
    - tests/baselines/management_summary_structural_schema.py
    - tests/baselines/management_summary_structural_baseline.json
    - scripts/capture_management_summary_parity_golden.py
    - tests/fixtures/management_summary_parity/vulns_df.parquet
    - tests/fixtures/management_summary_parity/assets_df.parquet
    - tests/fixtures/management_summary_parity/fixed_vulns_df.parquet
    - tests/fixtures/management_summary_parity/trend_snapshots.json
    - tests/baselines/management_summary_value_golden.json
  modified:
    - .gitignore
decisions:
  - "Shared adapter path: extract_structural_snapshot() in management_summary_structural_schema.py is the single contract for both bespoke (Plan 01) and _bundle (Plan 04) captures — ensures apples-to-apples structural diff (review change #5)"
  - "Bucket assignments derived from 18-RESEARCH.md Seven Module Definitions + module docstrings: M1/M2/M3/M4/M6=exact_match, M5/M7=documented_difference — per-metric gate not blanket zero-drift (review HIGH change #1)"
  - "pdf_page_count=-1 for bespoke path: bespoke run_report() writes PDF to disk but returns no in-memory html; -1 means 'file exists but not counted' to distinguish from 0 (file absent). Plan 04 _bundle has a real WeasyPrint count."
  - "gitignore exception added for tests/fixtures/management_summary_parity/*.parquet so committed synthetic fixture parquets are tracked (Rule 3 auto-fix)"
metrics:
  duration: 600
  completed_date: "2026-06-19"
  tasks_completed: 3
  files_created: 9
  files_modified: 1
---

# Phase 18 Plan 01: Structural Baseline + Bucketed Bespoke Golden Summary

Captured the structural smoke baseline from the CURRENT bespoke management_summary path AND locked exact bespoke metric outputs into a per-metric BUCKETED golden against a frozen synthetic fixture — both committed before any migration code, satisfying QUAL-04 / D-18-10 gate 3.

## What Was Built

### Task 1: Shared structural-snapshot schema + smoke script
- `tests/baselines/management_summary_structural_schema.py`: ONE shared `extract_structural_snapshot(source)` adapter accepting both the bespoke `run_report()` result dict (Plan 01) and a composer `_bundle` (Plan 04). Produces identical 9-key structural snapshot in both cases so the pre/post-cutover diff is apples-to-apples (review change #5).
- `scripts/smoke_management_summary_cutover.py`: structural smoke baseline capture + diff script. `_NoLiveTenable` sentinel prevents live Tenable API calls. First run writes baseline and exits 0 with "BASELINE INITIALIZED"; subsequent runs diff and exit 1 on structural drift. `--cache-dir` and `--rebaseline` argparse flags. Plan 04 note in docstring.

### Task 2: Initial structural baseline
- `tests/baselines/management_summary_structural_baseline.json`: structural snapshot of the current bespoke path (source_path="bespoke") containing only: schema_version, source_path, pdf_page_count (-1 = file exists), pdf_section_count (7), metric_ids_present (7 sorted module IDs), pdf_rag_cell_count (0), email_panel_count (0), excel_tab_names_sorted ([]), analyst_excel_present (false), bundle_keys_present. No metric values, no PII.
- Second-run exit 0 verified (no drift against freshly written baseline).

### Task 3: Frozen synthetic fixture + bucketed bespoke golden
- `scripts/capture_management_summary_parity_golden.py`: one-shot capture script. Builds 71-row vulns_df (all 4 severities, ACCEPTED/RECASTED for M6, REOPENED row for QUAL-02) + 30-row assets_df + 29-row fixed_vulns_df (MTTR coverage, REOPENED D-16-02 row) + 3-month trend_snapshots.json. Runs bespoke `compute_all_metrics` and emits bucketed golden. `--rebuild-fixture --emit-golden` flags. Deterministic (fixed seed=12345, _REPORT_DATE=2026-06-01).
- Fixture set committed (vulns_df/assets_df/fixed_vulns_df.parquet + trend_snapshots.json).
- `tests/baselines/management_summary_value_golden.json`: bucketed golden with all 7 metrics classified:
  - **exact_match**: M1 (total_vulns_by_severity), M2 (scan_coverage_sla), M3 (mttr_trend), M4 (patch_compliance_rate), M6 (accepted_recast)
  - **documented_difference**: M5 (aged_vulns_assets — vuln histogram vs % aged assets, different unit+denominator, invariant:none), M7 (new_vs_remediated — simple delta vs inflow/outflow trend, invariant:none)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] .gitignore exception for parity fixture parquets**
- **Found during:** Task 3
- **Issue:** `.gitignore` line `tests/**/*.parquet` matched the synthetic fixture parquets in `tests/fixtures/management_summary_parity/`, preventing them from being staged/committed despite being required committed artifacts.
- **Fix:** Added `!tests/fixtures/management_summary_parity/*.parquet` negation exception to `.gitignore`.
- **Files modified:** `.gitignore`
- **Commit:** 861d022

**2. [Rule 1 - Structural] bespoke path returns no in-memory PDF HTML**
- **Found during:** Task 1 (schema design)
- **Issue:** `baseline_utils.extract_structural_snapshot` expects an in-memory `pdf_html` key (composer bundle shape), but the bespoke `run_report()` writes PDF to disk and returns a `Path`, not HTML. WeasyPrint page count therefore cannot be computed for the bespoke snapshot.
- **Fix:** Schema adapter returns `pdf_page_count=-1` when the PDF file exists but no in-memory HTML is available (distinguishes from 0=absent). Static bespoke structure inferred: `pdf_section_count=7` (one per metric), `pdf_rag_cell_count=0` (bespoke uses Matplotlib charts). Documented in adapter docstring and golden `_meta`.
- **Files modified:** `tests/baselines/management_summary_structural_schema.py`
- **Commit:** bd80ff3

## Threat Flags

None. Structural baseline contains only counts/IDs/booleans (T-18-01 mitigated). Fixture uses RFC-5737/6761 synthetic addresses only (T-18-01b mitigated). Golden includes fixed_vulns_df + trend_snapshots covering MoM metrics (T-18-01c mitigated).

## Self-Check: PASSED

- tests/baselines/management_summary_structural_schema.py: EXISTS
- scripts/smoke_management_summary_cutover.py: EXISTS
- tests/baselines/management_summary_structural_baseline.json: EXISTS (contains "source_path", "metric_ids_present", "schema_version")
- tests/fixtures/management_summary_parity/vulns_df.parquet: EXISTS
- tests/fixtures/management_summary_parity/assets_df.parquet: EXISTS
- tests/fixtures/management_summary_parity/fixed_vulns_df.parquet: EXISTS
- tests/fixtures/management_summary_parity/trend_snapshots.json: EXISTS
- tests/baselines/management_summary_value_golden.json: EXISTS (contains "bucket", both "exact_match" and "documented_difference" present)
- Commits bd80ff3, 6daa167, 861d022: FOUND in git log
- smoke script exits 0 on re-run (no drift): VERIFIED
- golden re-run is deterministic (value-stable): VERIFIED
- No live Tenable API calls in either script: VERIFIED (sentinel + grep)
- QUAL-04 constraint: all artifacts committed before any migration code: SATISFIED
