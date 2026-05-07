---
status: complete
phase: 03-board-summary-module-migration
source: [03-01-SUMMARY.md, 03-02-SUMMARY.md, 03-03-SUMMARY.md, 03-04-SUMMARY.md, 03-05-SUMMARY.md, 03-06-SUMMARY.md, 03-07-SUMMARY.md]
started: 2026-05-06T21:55:00Z
updated: 2026-05-07T05:23:00Z
---

## Current Test

[testing complete — 5 passed, 1 issue (Test 3 RAG-strip layout)]

## Tests

### 1. Phase 2 + Phase 3 regression suite passes post-fix
expected: |
  `python tests/test_phase2_composer_pipeline.py` returns 10/10 passed
  (7 Phase 2 + 3 Phase 3 checks). Confirms the 9 code-review fixes (CR-01 + WR-01..08)
  didn't regress the composer pipeline contract.
result: pass
notes: |
  Verified 2026-05-06T22:00Z. All 10 checks PASS:
  D-22 bundle shape, D-27 module ordering, D-29 page-2 strip + cover stability,
  D-29 main-Excel content hash + mtime-normalized byte stability,
  D-28 email panel + analyst tabs exception isolation,
  Phase3 QUALITY-02 zero-row render methods, Phase3 populated render methods,
  Phase3 bundle email_inline_images key.
  Stderr tracebacks before final summary are the D-28 isolation-check fixtures
  (phase2-email-boom / phase2-analyst-boom) — expected, not failures.

### 2. Board Summary end-to-end run produces all four outputs
expected: |
  Run `python run_all.py --group "<your board group>" --no-email` produces a
  PDF, standard Excel, analyst Excel, and reports success in the CLI summary.
result: pass
notes: |
  Verified 2026-05-07T05:23Z (post Plan 03-07). Status: success. PDF +
  standard Excel + analyst Excel all written; zero ValueError; zero
  ChainedAssignmentError / FutureWarning on stderr.
prior_run:
  result: issue
  severity: blocker
  reported: |
    ValueError: Cannot convert <NA> to Excel at composer.py:1153 in
    assemble_analyst_workbook → ws.cell(value=val). Status: failed,
    Reports Generated: none, 1 group(s) failed. Plus 16 pre-existing pandas 3.0
    ChainedAssignmentError FutureWarnings across 6 files (scan_coverage_sla_module.py:395,
    board_report_utils.py:449/454/469, high_risk_assets_module.py:267/366/388,
    aged_vulns_assets_module.py:262/361/385).
  closed_by: |
    Plan 03-07 (commits 07357ec / 561647a / d17f2a6). pd.isna chokepoint +
    tzinfo strip in composer.py; .assign() at 3 risk_score sites; .loc[:,]
    at 7 text-column sites. Regression suite: 11/11 GREEN.

### 3. PDF page 1: unified RAG-strip cover
expected: |
  Page 1 unified cover with title + scope + generated + sections + 4 RAG cells.
result: issue
reported: |
  The RAG strip is still on a separate page. Also the RAG strip has 4 boxes
  which is expected, but it currently has 3 on 1 row and then a second row
  with 1 box. The boxes could be a little smaller to fit into a single row.
severity: major
prior_run:
  result: blocked
  blocked_by: prior-phase
  reason: Test 2 crash prevented PDF generation — unblocked by Plan 03-07.

### 4. Email body: four per-module panels with inline gauges
expected: |
  Email body has 4 per-module panels with CID-referenced inline gauges + driver
  narratives.
result: pass
notes: |
  Verified 2026-05-07T05:23Z. 4 per-module panels render with module display
  names, inline gauge CIDs, headline values, and driver narratives — the
  modular bundle path (D-22) is active.
prior_run:
  result: blocked
  blocked_by: prior-phase
  reason: Test 2 crash prevented email body assembly — unblocked by Plan 03-07.

### 5. Analyst workbook attachment with four named tabs
expected: |
  Analyst Excel companion has 4 named tabs with populated drill-down rows;
  accepted/recasted findings excluded from Critical Remediation Detail.
result: pass
notes: |
  Verified 2026-05-07T05:23Z. 4 named tabs populated with drill-down rows;
  empty cells (not literal NA/NaT strings) at previously-null positions —
  pd.isna chokepoint working as designed. BOARD-07 acceptance closed at high
  confidence (real Tenable data, not synthetic fixtures).
prior_run:
  result: blocked
  blocked_by: prior-phase
  reason: Test 2 crash WAS this artifact's assembly path — fix landed in 03-07.

### 6. Empty-data resilience: zero-row scenario produces graceful placeholders
expected: |
  Empty-tag-filter scenario produces gray no-data cells, em-dash headlines, and
  "No data in scope" placeholders. No crash.
result: pass
notes: |
  Verified 2026-05-07T05:23Z. Zero-row tag filter produced gray "No Data"
  cells, em-dash headlines, "No data in scope." placeholders. Status:
  success. QUALITY-02 empty-data hardening confirmed against real Tenable.
prior_run:
  result: blocked
  blocked_by: prior-phase
  reason: User re-ran the populated "Test Pull" group rather than a no-match filter
    in the prior pass — empty-data branch was never exercised. Now re-runnable.

## Summary

total: 6
passed: 5
issues: 1
pending: 0
skipped: 0
blocked: 0

## Gaps

- truth: "Board Summary PDF page 1 is a unified RAG-strip cover with all 4 cells in a single row"
  status: failed
  reason: "User reported: The RAG strip is still on a separate page. Also the RAG strip has 4 boxes which is expected, but it currently has 3 on 1 row and then a second row with 1 box. The boxes could be a little smaller to fit into a single row."
  severity: major
  test: 3
  root_cause: |
    Problem 1 (strip on separate page) is a DOWNSTREAM SYMPTOM of Problem 2.
    The cover template at composer.py:359-375 correctly nests .rag-strip
    inside .report-cover, but when the 4 cells wrap to 2 rows, the strip's
    vertical mass nearly doubles (~55mm → ~114mm) and overflows A4-landscape
    page 1 (177mm content area). page-break-after: always then forces a hard
    break, putting the strip alone on page 2.

    Problem 2 (3+1 row break): WeasyPrint flex implementation rounds aggressively.
    Geometry: 4 cells × 62mm + 3 gaps × 4mm = 260mm in a 273mm content row =
    only 13mm slack. Slack is consumed by border subpixel rounding (~2.8mm
    cumulative across 8 × 0.5pt borders) plus WeasyPrint's flex gap
    over-allocation. Result: computed row width edges past 273mm and the 4th
    cell drops to row 2. The 62mm width was pinned in Phase 2 commit 7be4355
    when the strip lived on standalone page 2 with generous headroom — the
    margin survived until the unified-cover collapse landed in commit a112a71
    and the cells now share vertical space with the cover metadata.
  artifacts:
    - path: "reports/modules/composer.py:281-291"
      issue: ".rag-cell-row flex container — flex-wrap: wrap, gap: 4mm — 13mm slack consumed by WeasyPrint flex rounding"
    - path: "reports/modules/composer.py:293-313"
      issue: ".rag-cell — flex: 0 0 62mm; width: 62mm — too wide; 4×62+3×4=260mm leaves only 13mm slack in a 273mm row"
    - path: "reports/modules/composer.py:233"
      issue: ".report-cover page-break-after: always — fires hard when strip overflows due to wrap, evicting strip to page 2"
  missing:
    - "Shrink .rag-cell width from 62mm to 58mm (composer.py:303 + flex-basis at composer.py:302). New row: 4×58 + 3×4 = 244mm in 273mm = 29mm slack — dwarfs WeasyPrint rounding."
    - "Do NOT change flex-wrap: wrap → nowrap. management_summary uses the same composer with 7 modules and intentionally wraps; nowrap would horizontally overflow on that report."
  debug_session: "in-memory (gsd-debugger agent a405bc3147e4d8c7d)"

- truth: "Board Summary delivery produces a populated analyst Excel without raising"
  status: failed
  reason: "User reported: ValueError: Cannot convert <NA> to Excel at composer.py:1153 in assemble_analyst_workbook → ws.cell(value=val). Status: failed, Reports Generated: none, 1 group(s) failed."
  severity: blocker
  test: 2
  root_cause: "composer.py:1151-1153 writes DataFrame cells directly to openpyxl without coercing pandas null sentinels. openpyxl's _bind_value accepts None and np.nan but explicitly raises on pd.NA (StringDtype null) and pd.NaT (datetime null). All four board modules coerce text columns through .astype('string') (StringDtype produces pd.NA, not np.nan); Int64 days-* columns also carry pd.NA; remediation due_date / last_licensed_scan_date carry pd.NaT. None reproduces in fixtures because regression suite uses synthetic non-null DataFrames."
  artifacts:
    - path: "reports/modules/composer.py"
      issue: "lines 1151-1153 write pd.NA / pd.NaT directly to openpyxl without coercion"
    - path: "reports/modules/scan_coverage_sla_module.py"
      issue: "lines 393-399 .astype('string') produces pd.NA on null hostname/ipv4/fqdn/business_unit"
    - path: "reports/modules/critical_remediation_sla_module.py"
      issue: "lines 353-359 .astype('string') on asset/plugin/owner_tag"
    - path: "reports/modules/high_risk_assets_module.py"
      issue: "lines 365-370 .astype('string') on hostname/business_unit/contributing_finding_ids"
    - path: "reports/modules/aged_vulns_assets_module.py"
      issue: "lines 360-365 .astype('string') on hostname/business_unit/contributing_plugins/worst_severity"
  missing:
    - "Coerce pd.isna(val) → None at composer.py:1151-1153 before ws.cell(value=val) (single chokepoint covers all 4 modules + future modules)"
    - "Add regression fixture in tests/test_phase2_composer_pipeline.py with pd.NA in StringDtype col + pd.NaT in datetime col + pd.NA in Int64 col; assert assemble_analyst_workbook returns a path without raising"
  debug_session: "in-memory (gsd-debugger agent a0cedc164009c042a)"

- truth: "Phase 3 modules use pandas-3.0-safe assignment patterns (no chained assignment)"
  status: failed
  reason: "User reported: 16 pre-existing pandas 3.0 ChainedAssignmentError FutureWarnings across 6 files: scan_coverage_sla_module.py:395, board_report_utils.py:449/454/469, high_risk_assets_module.py:267/366/388, aged_vulns_assets_module.py:262/361/385. Pattern: `df[col] = df[col].something(...)` after a slice — won't work under pandas 3.0 Copy-on-Write."
  severity: minor
  test: 2
  root_cause: "Pre-existing tech debt — chained assignment on slice copies that pandas 2.x tolerates but pandas 3.0 Copy-on-Write breaks. Not introduced by Phase 3 fixes; surfaces in Phase 3 modules because they're the most heavily exercised."
  artifacts:
    - path: "reports/modules/scan_coverage_sla_module.py:395"
    - path: "reports/modules/board_report_utils.py:449,454,469"
    - path: "reports/modules/high_risk_assets_module.py:267,366,388"
    - path: "reports/modules/aged_vulns_assets_module.py:262,361,385"
  missing:
    - "Replace chained assignment with .loc[:, col] = ... pattern at the 11 cited lines"
  debug_session: ""
