---
phase: 13-owner-segmentation-composition-s2-doc
plan: "01"
subsystem: board-report-utils
tags: [owner-segmentation, tdd, helper-generalization, seg-01, seg-02, seg-04]
dependency_graph:
  requires: []
  provides:
    - reports/modules/board_report_utils.extract_owner
    - reports/modules/board_report_utils.OWNER_TAG_CATEGORY
    - reports/modules/board_report_utils.APPLICATION_TAG_CATEGORY
    - reports/modules/board_report_utils._DEFAULT_UNASSIGNED_LABEL
    - owner+application columns on assets_df
  affects:
    - reports/modules/board_report_utils.compute_per_bu_breakdown (owner output column)
    - reports/modules/board_report_utils.compute_bu_risk_scores (owner column refs)
tech_stack:
  added: []
  patterns:
    - dual-category single-pass tag parser (Owner + Application in one loop)
    - TDD RED/GREEN cycle for helper generalization
key_files:
  created:
    - tests/unit/test_owner_segmentation.py
  modified:
    - reports/modules/board_report_utils.py
decisions:
  - "Promoted _extract_owner_tag from critical_remediation_sla_module into shared helper (D-03); promoted version returns unassigned_label instead of '' (Pitfall 3)"
  - "extract_owner uses a single-pass dual-category loop rather than two separate apply() calls — one pass over semicolon-delimited tokens extracts both owner and application values"
  - "compute_per_bu_breakdown bu_column default changed from 'business_unit' to 'owner' — callers that pass the param explicitly are unaffected; callers relying on the default will consume the new name (Plan 02 caller repoint)"
metrics:
  duration: "~12 minutes"
  completed: "2026-06-10T17:55:00Z"
  tasks_completed: 2
  files_changed: 2
---

# Phase 13 Plan 01: Owner Segmentation Foundation Summary

Owner-primary generalization of `board_report_utils.py` — `extract_owner` replaces `extract_business_unit`, producing both `owner` (primary, from the `Owner` tag) and `application` (nested, from the `Application` tag) columns; `business_unit` column name and `Untagged` label fully eliminated; all 8 SEG-01/02/04 unit tests green, 111 unit tests total, zero regressions.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 0 | Write failing SEG-01/02/04 unit tests (RED state) | 148b338 | tests/unit/test_owner_segmentation.py (created) |
| 1 | Generalize board_report_utils.py to Owner-primary helper | d9b117c | reports/modules/board_report_utils.py (modified) |

## What Was Built

**`reports/modules/board_report_utils.py`** — generalized in place (D-03, blast-radius file 1 of 5 per D-08):

1. **Constants**: `BU_TAG_CATEGORY = "Application"` replaced with three new constants:
   - `OWNER_TAG_CATEGORY = "Owner"` — primary grouping dimension (D-01)
   - `APPLICATION_TAG_CATEGORY = "Application"` — nested analyst drill-down (D-05)
   - `_DEFAULT_UNASSIGNED_LABEL = "Unassigned"` — configurable catch-all (D-06)

2. **`extract_owner`** (renamed from `extract_business_unit`): dual-category single-pass parser. One loop over semicolon-delimited `Cat=Val` tokens extracts both `Owner` values (→ `owner` column) and `Application` values (→ `application` column). No-match owner → `unassigned_label`. Missing tags column → all-Unassigned, `application=""`, warning logged, no raise (SEG-04/D-07).

3. **`compute_per_bu_breakdown`**: output rename changed from `.rename(columns={bu_column: "business_unit"})` to `.rename(columns={bu_column: "owner"})` (D-04, Pitfall 2). `bu_column` default param updated to `"owner"`.

4. **`compute_bu_risk_scores`**: two `"business_unit"` column references changed to `"owner"` (slice at line 460, groupby at line 479).

5. **Module docstring**: updated to reflect Owner model and renamed function `extract_owner`.

**`tests/unit/test_owner_segmentation.py`** — 8 tests covering SEG-01/02/04:
- `test_owner_buckets_reconcile_to_whole` — value_counts sum equals row count
- `test_no_owner_tag_is_unassigned` — no-Owner assets get "Unassigned"; "Untagged" absent
- `test_application_column_populated` — dual-tagged asset has correct application value
- `test_missing_tags_column_fail_soft` — no raise on absent tags column; all-Unassigned
- `test_output_has_owner_not_business_unit` — owner present, business_unit absent
- `test_configurable_unassigned_label` — unassigned_label override honored
- `test_breakdown_output_column_is_owner` — compute_per_bu_breakdown output has owner, not business_unit
- `test_owner_tag_category_constant` — OWNER_TAG_CATEGORY == "Owner"

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — this plan is a pure helper/test layer with no rendering or data-source wiring.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Tag parser guards `isinstance(tags_val, str)` (T-13-01: arbitrary tag values flow only into in-memory columns). Missing-column path produces all-Unassigned without raising (T-13-02).

## Self-Check: PASSED

- `tests/unit/test_owner_segmentation.py` exists: FOUND
- `reports/modules/board_report_utils.py` contains `def extract_owner`: FOUND
- `reports/modules/board_report_utils.py` contains `OWNER_TAG_CATEGORY`: FOUND
- `reports/modules/board_report_utils.py` has 0 occurrences of `business_unit`: CONFIRMED
- `reports/modules/board_report_utils.py` has 0 occurrences of `Untagged`: CONFIRMED
- Commit 148b338 (RED test): FOUND
- Commit d9b117c (GREEN impl): FOUND
- 111 unit tests pass, 0 failures: CONFIRMED
