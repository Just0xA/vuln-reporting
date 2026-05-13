---
phase: 4
plan: 04-04
status: complete
started: 2026-05-07
completed: 2026-05-08
tasks: 5/5
commits: [6e2acf5, 1db6914, 6ec322e, b1e3c72, c964e05]
files_modified:
  - tests/baseline_utils.py
  - tests/test_baseline_extractor.py
  - tests/baselines/README.md
  - scripts/smoke_board_summary_cutover.py
operator_captured_files:
  - tests/baselines/board_summary_test_pull.json
  - tests/baselines/board_summary_test_pull_analyst_off.json
  - tests/baselines/board_summary_test_pull_zero_match.json
---

# Plan 04-04 SUMMARY — Cutover Smoke + Structural Baselines

## What shipped

Test-first PII-guarded structural snapshot extractor + cutover smoke
runner + 3 operator-captured baselines + README documenting the
"baselines change with CODE not DATA" convention.

## Commits

| SHA       | Type             | Subject                                                                |
|-----------|------------------|------------------------------------------------------------------------|
| `6e2acf5` | test (RED)       | Add `tests/test_baseline_extractor.py` — RED at HEAD                   |
| `1db6914` | feat (GREEN)     | Implement `tests/baseline_utils.py` — turns suite GREEN (18/18)        |
| `6ec322e` | feat             | `scripts/smoke_board_summary_cutover.py` — `_NoLiveTenable` sentinel   |
| `b1e3c72` | docs             | `tests/baselines/README.md` — structural-only convention               |
| `c964e05` | chore (operator) | 3 initial structural baselines captured against warm cache             |

## RED→GREEN structural negative control

Mirroring Plan 03-07's pattern, Task 1 committed the test RED at HEAD
(`ModuleNotFoundError: No module named 'tests.baseline_utils'`), Task 2
turned it GREEN by implementing the extractor. The diff between
commits `6e2acf5` and `1db6914` IS the automatic negative control —
bisecting that boundary observes the suite transition from RED to GREEN
PASS, proving the test exercises the implementation.

## Rule 1 deviations during Task 2 GREEN (auto-fixed)

Two real bugs that the plan's prose didn't catch but the executor found
during GREEN implementation. Both documented in commit `1db6914`'s body:

1. **WeasyPrint compresses PDF object headers via FlateDecode by
   default**, hiding `/Type /Page` regex matches. Fix: pass
   `uncompressed_pdf=True` to `HTML.write_pdf()`. The plan also
   prescribed a `-1` subtraction for the `/Pages` catalog object, but
   the regex's trailing `\b` already excludes the plural — removed the
   subtraction. Without these, Test H returned 0 instead of 5.

2. **Test fixture used hardcoded `#cccccc`** for the no-data RAG color,
   but `STATUS_COLOR['no_data']` in `reports/modules/rag_utils.py` is
   `#757575`. Fix: import the real color from `rag_utils`. Without
   this, Test D would false-pass without exercising the production path.

## Operator-captured baselines (Task 5)

Captured 2026-05-08 against the warm cache from
`python run_all.py --group "Test Pull" --no-email`. Re-run against the
same cache: exit 0, 3/3 OK, zero DRIFT.

### Sanity expectations vs actuals

| Group                      | Expected `analyst_excel_present` | Actual | Notes |
|----------------------------|----------------------------------|--------|-------|
| `test_pull`                | true                             | true   | Populated path; analyst workbook emitted |
| `test_pull_analyst_off`    | false                            | false  | D-04-03 opt-out toggle works |
| `test_pull_zero_match`     | (was guessed `true`; corrected to `false`) | false | When all 4 modules produce zero analyst rows, `assemble_analyst_workbook` returns None by design |

| Group                      | Expected `rag_cells_all_no_data` | Actual | Notes |
|----------------------------|----------------------------------|--------|-------|
| `test_pull`                | false                            | false  | Populated cells render normal RAG colors |
| `test_pull_analyst_off`    | false                            | false  | Same as test_pull (only analyst toggle differs) |
| `test_pull_zero_match`     | true                             | true   | All 4 cells gray no-data per empty-data path |

| Group                      | `panel_drivers_all_no_data_in_scope` | Notes |
|----------------------------|--------------------------------------|-------|
| `test_pull`                | false                                | Real driver narratives |
| `test_pull_analyst_off`    | false                                | Same as test_pull |
| `test_pull_zero_match`     | true                                 | All 4 panels say "No data in scope." |

Common to all three: `schema_version=1`, `pdf_rag_cell_count=4`,
`pdf_page_count=5`, `email_panel_count=4`,
`pdf_has_risk_status_summary_header=true`, `_Metadata` tab present in
`excel_tab_names_sorted`, 8 keys in `bundle_keys_present`.

`test_pull_zero_match` has `email_inline_image_cids_per_module=[]`
(empty list) — zero-data modules don't generate inline gauge images.
The other two groups have all 4 module gauge CIDs.

## PII guard verification

Spot-checked all 3 baseline JSONs:
- Zero `headline_metrics` keys
- Zero `*_pct` / `*_score` / `*_rate` keys
- Zero per-row data
- Zero hostnames, IPv4, IPv6, FQDN, plugin name, recast reason values
- Just counts, booleans, sorted name lists, and the static
  `schema_version` / `group_slug` strings

The defensive PII guard (exact-match list + narrow substring backstop
on `asset_name` / `host_name` / `ip_address`) passed unit tests and
doesn't false-positive on `tag_name` or `email_panel_count` (verified
by negative-control test in `tests/test_baseline_extractor.py`).

## Verification matrix

| Check                                                              | Result |
|--------------------------------------------------------------------|--------|
| `python tests/test_baseline_extractor.py`                          | 18/18 PASS |
| `python tests/test_phase2_composer_pipeline.py`                    | 11/11 PASS |
| `python tests/test_phase4_schema_validation.py`                    | 6/6 PASS |
| `python tests/test_phase4_analyst_detail_toggle.py`                | 3/3 PASS |
| `python scripts/smoke_board_summary_cutover.py --cache-date 1970-01-01` | exit 2, stderr contains "cache not found" + warm-cache command |
| `python scripts/smoke_board_summary_cutover.py` (first run)        | exit 0, 3 baselines INITIALIZED |
| `python scripts/smoke_board_summary_cutover.py` (re-run)           | exit 0, 3/3 OK, 0 DRIFT |

## What this enables

The Phase 4 cutover smoke is now a sub-5-second deterministic
regression bar that:

1. Catches structural regressions (lost tab, broken toggle, dropped
   panel, page-count drift) automatically without false-positive
   alerts on data churn.
2. Hard-guards against accidental live-API calls via `_NoLiveTenable`
   sentinel that raises `RuntimeError` on any method invocation.
3. Documents the structural-only convention in
   `tests/baselines/README.md` so future contributors don't try to
   add metric values back.

Visual operator confirmation against Tenable production remains the
human gate for value correctness — the smoke is the structural-shape
gate that complements it.

## Locked decisions honored

- **D-04-05 (REVISED)**: structural-only baseline. Zero metric values,
  zero row counts, zero row-level data. No `--update-baseline` flag —
  baselines change with CODE, not DATA.
- **D-04-06**: smoke runs against cached parquet only; aborts cleanly
  on cache-miss with helpful warm-cache hint.
- **D-04-08**: baselines store counts + booleans only; PII guard
  (exact + narrow substring) prevents leakage; new test recipients use
  RFC 6761 `example.invalid` domain.

## Next

- Phase 4 verification (orchestrator): all 4 plans complete, cutover
  smoke green, regression suites all green. Phase 4 closes when the
  orchestrator runs goal-backward verification + UAT.
- Phase 4 UAT: re-run UAT for the new YAML toggle paths (analyst-off
  delivery → no analyst workbook attached; zero-match → "No data in
  scope." panels).
