---
status: complete
phase: 04-yaml-config-and-regression-cutover
source: [04-01-SUMMARY.md, 04-02-SUMMARY.md, 04-03-SUMMARY.md, 04-04-SUMMARY.md]
started: 2026-05-08T10:50:00Z
updated: 2026-05-08T11:35:00Z
---

## Current Test

[testing complete — 7/7 passed]

## Tests

### 1. Cold start — fresh dry-run validates 3 groups and exits 0
expected: |
  `python run_all.py --dry-run` exits 0; rich-table shows 3 groups all
  validated; no traceback or schema error.
result: pass
notes: |
  Verified 2026-05-08T10:50Z. Exit 0; rich-table renders all 3 groups
  (Test Pull, Test Pull — Analyst Off, Test Pull — Zero Match); "All
  3 group(s) validated successfully." No traceback.

### 2. Schema validation catches misconfigured YAML at startup
expected: |
  Mutate one field to an invalid value (e.g. `frequency: weeky` typo) in
  delivery_config.yaml, run `python run_all.py --dry-run`. Expect exit 1
  with an error naming the offending group AND field path, e.g.
  `[Test Pull] groups[0].schedule.frequency: 'weeky' is not one of [...]`.
  Revert after testing.
result: pass
notes: |
  Verified 2026-05-08T10:50Z. Exit code 1; error message exactly:
  "[Test Pull] groups[0].schedule.frequency: 'weeky' is not one of
  ['weekly', 'monthly', 'on_demand']". File reverted cleanly via
  `git checkout`. Schema enforcement catches the typo at startup
  before any work runs — success criterion #2 met.

### 3. analyst_detail default (true) — Test Pull produces analyst workbook
expected: |
  `python run_all.py --group "Test Pull" --no-email` produces:
  - board_summary*.pdf (5-page unified cover + metric pages)
  - board_summary*.xlsx (standard Excel — 4 metric tabs + _Metadata)
  - board_summary*_analyst.xlsx (analyst companion — 4 named drill-down tabs)
  - email body in bundle (HTML)
  Status: success. Output folder under output/YYYY-MM-DD_HH-MM_Test-Pull/.
result: pass
notes: |
  Verified 2026-05-08 during cache-warm step (Phase 4 Plan 04-04
  Task 5). Status: success. Phase 03 UAT 6/6 also corroborates the
  populated-path delivery shape. Baseline
  test_pull.json captures: pdf_page_count=5, analyst_excel_present=true,
  email_panel_count=4, all 4 inline image CIDs present, _Metadata tab
  in excel_tab_names_sorted.

### 4. analyst_detail: false — Analyst Off group skips the analyst workbook
expected: |
  `python run_all.py --group "Test Pull — Analyst Off" --no-email` produces:
  - board_summary*.pdf
  - board_summary*.xlsx (standard)
  - email body in bundle
  - **NO** board_summary*_analyst.xlsx file in the output folder
  Status: success. The D-04-03 toggle is the only difference vs Test 3.
result: pass
notes: |
  Verified 2026-05-08T11:31Z. Status: success, exit 0. Output folder
  output/2026-05-08_11-31_test_pull_analyst_off/board_summary/ contains
  exactly 2 files: board_summary.pdf (114 KB), board_summary.xlsx
  (22 KB). NO *_analyst.xlsx file. D-04-03 toggle confirmed end-to-end.

### 5. Zero-match group produces graceful empty-data delivery
expected: |
  `python run_all.py --group "Test Pull — Zero Match" --no-email`
  (filter: tag_category=Application, tag_value=DoesNotExist — known no-match)
  produces a clean delivery (status: success, NOT failed) with:
  - PDF: 5 pages, all 4 RAG cells gray "No Data" / "—" headlines
  - Email body: 4 panels, each with "No data in scope." narrative
  - No analyst Excel (zero rows → no file)
  - No crash, no traceback, no ValueError
  - Zero ChainedAssignmentError / FutureWarning on stderr
result: pass
notes: |
  Verified 2026-05-08T11:32Z. Status: success, exit 0. Output folder
  output/2026-05-08_11-32_test_pull_zero_match/board_summary/ contains
  exactly 2 files: board_summary.pdf (104 KB), board_summary.xlsx
  (8 KB — smaller than populated; empty data tabs). NO *_analyst.xlsx
  (zero analyst rows → no file). Zero ChainedAssignmentError /
  FutureWarning / ValueError / Traceback hits on stderr. Module-level
  no-data warnings logged appropriately (scan_coverage_sla,
  high_risk_assets, aged_vulns_assets returned no_data ModuleData).
  Empty-data path is fully exercised + structurally locked by
  baseline test_pull_zero_match.json.
  Note: visual inspection of the PDF for "all 4 RAG cells gray + No
  data in scope." narrative is left to operator review (the structural
  smoke confirms via rag_cells_all_no_data=true and
  panel_drivers_all_no_data_in_scope=true).

### 6. Cutover smoke catches structural drift (regression bar)
expected: |
  Mutate one value in a committed baseline (e.g. change `pdf_page_count: 5`
  to `pdf_page_count: 4` in tests/baselines/board_summary_test_pull.json),
  run `python scripts/smoke_board_summary_cutover.py`. Expect exit 1 with a
  DRIFT line naming the field and the actual vs baseline values. Revert.
result: pass
notes: |
  Verified 2026-05-08T10:50Z. Mutated test_pull baseline pdf_page_count
  to 99; smoke exit 1; output:
    [smoke] Test Pull: DRIFT (1 field(s))
      pdf_page_count: actual=5 baseline=99
    [smoke] Test Pull — Analyst Off: OK
    [smoke] Test Pull — Zero Match: OK
  File reverted via `git checkout`. Drift detection works: catches the
  field, names actual vs baseline, isolates the affected group.

### 7. PII / sensitive-data redaction in baseline JSONs
expected: |
  Inspect the 3 committed baseline JSONs in tests/baselines/. Confirm:
  - No metric values (no `*_pct`, `*_score`, `*_rate`, `headline_metrics`)
  - No per-row data (no asset names, hostnames, IPs, FQDNs, plugin names)
  - Just counts, booleans, sorted name lists, and the static schema_version
    + group_slug strings
result: pass
notes: |
  Verified 2026-05-08T10:50Z. All 3 baselines: 12 keys (locked schema
  per D-04-05). Zero PII substring hits (hostname, ipv4, fqdn,
  plugin_name, etc.). Zero metric-value keys (*_pct, *_score, *_rate,
  headline_metrics). Zero IP-address regex matches. PII guard is
  structurally enforcing the no-row-level rule per D-04-08.

## Summary

total: 7
passed: 7
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none yet]
