---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: 19-10
subsystem: reports/modules/program_health_module
tags: [program-health, pdf, excel, email, gap-closure, phase-19]
dependency_graph:
  requires: [phase-17-program-health-module, phase-19-19-09]
  provides: [program-health-polish-d1-d6]
  affects: [composed_report, board_summary, management_summary]
tech_stack:
  added: []
  patterns: [safe_pct/safe_int/safe_format, pandas-3.0-CoW-assign, page-break-div, E3F2FD-fill]
key_files:
  created: []
  modified:
    - reports/modules/program_health_module.py
    - tests/test_program_health_module.py
decisions:
  - D-17-01 preserved: program_health NOT added to _MODULES_NEEDING_FIXED_VULNS; no fixed_vulns_df threading
  - D-3 current-sign status separate from sig2_status delta-of-deltas sparkline trend (both coexist)
  - page-break via existing .page-break CSS class (page-break-before:always in composer CSS)
  - Net Velocity annotation in HTML annotation_html div (not PNG-only): makes intake/fixed/net accessible to text rendering
  - MTTR establishing caption: real-PDF render deferred to operator re-verification (WeasyPrint quirks cannot be tested via layout math)
metrics:
  duration_seconds: 2400
  completed_date: "2026-06-26"
  tasks_completed: 4
  files_modified: 2
  tests_added: 37
  tests_total: 107
---

# Phase 19 Plan 10: Program Health Overview PDF/Excel/Email Polish Summary

Gap-closure plan implementing D-1..D-6 from the approved spec (`docs/superpowers/specs/2026-06-26-program-health-pdf-excel-polish-design.md`). Turns operator UAT findings from the 19-08 human-verification checkpoint into executable code across four atomic commits.

## One-liner

Program Health Overview readability/correctness polish: two-page PDF split, verbatim chart captions, current-month Net Velocity intake/fixed/net annotation, MTTR establishing caption, six-column Owner table, readable Excel header fill, and definitions block — across all four render channels.

## Commits

| Hash | Type | Description |
|------|------|-------------|
| ece81f7 | feat | Compute layer — surface new/fixed_current, net_velocity_status_current, owner share_pct + asset_count |
| d38c8ac | feat | PDF render — two-page split, verbatim captions, intake/fixed/net annotation, MTTR caption |
| 7901d9e | feat | Email + Excel — intake/fixed/net tiles, definitions, readable header, Owner Velocity columns |
| 34215c1 | test | Sweep — cold-start + QUAL-03 empty-data guard assertions |

## Tasks Completed

| # | Task | Commit | Key changes |
|---|------|--------|-------------|
| 1 | Compute layer | ece81f7 | new_current/fixed_current in metrics; net_velocity_status_current from sign(curr_net_delta); share_pct + asset_count per owner row; cold-start metrics block updated |
| 2 | PDF render | d38c8ac | page-break div before Owner table; verbatim D-2 captions under each chart; Net Velocity annotation HTML; MTTR establishing caption; D-5 six-column Owner table |
| 3 | Email + Excel | 7901d9e | Email Net Velocity intake/fixed/net + current-sign arrow; MTTR establishing caption; per-tile definition divs; Excel header fill E3F2FD; definitions block; Owner Velocity Share%/Assets |
| 4 | Test sweep | 34215c1 | Cold-start key-presence guards; QUAL-03 empty-data channel guards; NaN% guard; full suite 107 passed |

## Spec Coverage

| Decision | Status |
|----------|--------|
| D-1: two-page PDF split (page-break before Owner table) | Implemented — `<div class="page-break"></div>` before Owner Velocity h3 |
| D-2: verbatim approved captions under each chart | Implemented — exact caption strings from spec copied as static literals |
| D-3: current-sign Net Velocity (email + PDF) | Implemented — `net_velocity_status_current` from sign(curr_net_delta); annotation "in {new} / fixed {fixed} · net {net} {arrow}" |
| D-4: MTTR establishing caption; no fixed_vulns_df | Implemented — appended when mttr_current is None; D-17-01 preserved |
| D-5: six Owner-table columns | Implemented — PDF + Excel: Owner | Open Crit+High | Share % | Assets | MoM Delta | MoM Delta % |
| D-6: readable Excel header + definitions + Owner Velocity Share%/Assets | Implemented — 1F3864→E3F2FD; definitions block (4 rows); Owner Velocity columns updated |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Outlier marker re-added to D-5 six-column table**
- **Found during:** Task 2 — existing `TestPdfOwnerOutlierMarker` test failed after replacing the old 4-column "Status" cell with the new 6-column D-5 layout
- **Issue:** D-5 redesign removed the dedicated outlier Status column; the outlier marker was lost
- **Fix:** Outlier marker (`&#9650; Outlier` in red) appended inline to the MoM Delta % cell — preserves the visual signal without adding a seventh column
- **Files modified:** reports/modules/program_health_module.py
- **Commit:** d38c8ac

**2. [Rule 2 - Auto] Net Velocity annotation added as HTML text (not PNG-only)**
- **Found during:** Task 2 — the `nv_curr_str` annotation was passed to `_render_sparkline_b64` as the PNG title, making it inaccessible to text-based assertions and potentially to accessibility tools
- **Fix:** Added an `annotation_html` div beneath the Net Velocity sparkline cell containing the formatted "in {new} / fixed {fixed} · net {net} {arrow}" string, visible in the HTML layer
- **Files modified:** reports/modules/program_health_module.py
- **Commit:** d38c8ac

**3. [Rule 1 - Bug] Test fixture `_make_normal_data()` and `_make_cold_data()` updated with new Task 1 fields**
- **Found during:** Task 2 — existing render-channel tests used the fixture without `share_pct`/`asset_count` in table_data rows and without the new metrics keys
- **Fix:** Added `share_pct`, `asset_count`, `new_current`, `fixed_current`, `net_velocity_status_current` to both fixtures
- **Files modified:** tests/test_program_health_module.py
- **Commit:** d38c8ac

### Human-Verification Deferred

**D-1 real-PDF render confirmation:** The PDF page-break implementation uses the project's established `.page-break` CSS class (`page-break-before: always` in composer.py). Automated tests confirm the `<div class="page-break"></div>` element is present before the Owner Velocity heading and that the element precedes the table in the HTML output. **WeasyPrint actual page-break behavior requires a real PDF render** — this is deferred to the operator re-verification step after this plan completes, per the plan spec's `<human-check>` note.

## Known Stubs

None — all spec decisions D-1..D-6 implemented. No placeholder text, hardcoded empty values, or deferred data sources introduced by this plan.

## Threat Flags

No new security-relevant surface introduced. The Share % and Assets columns carry aggregate-only owner counts (T-19-10-01 mitigated: no UUIDs/IPs/hostnames). HTML interpolation in all new code uses `html.escape()` on owner/tag strings (T-19-10-02). Safe helper guards prevent zero-denominator crashes (T-19-10-03).

## Self-Check: PASSED

- reports/modules/program_health_module.py — modified (confirmed via git log)
- tests/test_program_health_module.py — modified (confirmed via git log)
- Commits ece81f7, d38c8ac, 7901d9e, 34215c1 verified in git log
- Full test suite: 107 passed, 0 failed
- D-17-01 verified: program_health not in _MODULES_NEEDING_FIXED_VULNS
