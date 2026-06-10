---
phase: 13-owner-segmentation-composition-s2-doc
plan: "02"
subsystem: board-consumer-modules
tags: [owner-segmentation, consumer-repoint, seg-01, seg-02, seg-04, d-02, d-06, d-08]
dependency_graph:
  requires:
    - reports/modules/board_report_utils.extract_owner
    - reports/modules/board_report_utils.OWNER_TAG_CATEGORY
    - owner+application columns on assets_df (Plan 01)
  provides:
    - 4 consumer modules fully repointed to owner column
    - _extract_owner_tag removed from critical_remediation_sla_module
    - D-08 blast radius files 2–5 of 5 complete
  affects:
    - reports/modules/aged_vulns_assets_module.py
    - reports/modules/high_risk_assets_module.py
    - reports/modules/scan_coverage_sla_module.py
    - reports/modules/critical_remediation_sla_module.py
tech_stack:
  added: []
  patterns:
    - owner-primary groupby/merge replaces business_unit at all compute/render sites
    - extract_owner defensive re-extract guard pattern (if "owner" not in columns)
    - .assign() for fillna catch-all (Pitfall 1 — Unassigned replaces Untagged)
    - _extract_owner_tag deleted; analyst detail uses extract_owner directly
key_files:
  created: []
  modified:
    - reports/modules/aged_vulns_assets_module.py
    - reports/modules/high_risk_assets_module.py
    - reports/modules/scan_coverage_sla_module.py
    - reports/modules/critical_remediation_sla_module.py
decisions:
  - "analyst detail owner_tag in critical_remediation_sla uses extract_owner on the findings DataFrame directly (findings carry tags in same Cat=Val;Cat=Val format) rather than replicating the single-field parse inline — keeps logic in one place"
  - "driver narrative 'worst BU' label updated to 'worst Owner' in both aged_vulns and high_risk modules — consistent with Owner model rename (D-02)"
metrics:
  duration: "~18 minutes"
  completed: "2026-06-10T18:15:00Z"
  tasks_completed: 2
  files_changed: 4
---

# Phase 13 Plan 02: Consumer Module Owner Repoint Summary

Completed the D-08 blast-radius repoint across all four board consumer modules — `aged_vulns_assets`, `high_risk_assets`, `scan_coverage_sla`, and `critical_remediation_sla` — from the interim `Application`/`business_unit` grouping to the generalized `Owner` helper from Plan 01. Private `_extract_owner_tag` deleted from `critical_remediation_sla_module`; its logic now lives exclusively in the shared `extract_owner` helper. All phase-wide grep gates pass: `business_unit=0`, `Untagged=0`, `Business Unit=0`, `_extract_owner_tag=0` across all four files. 125 unit/content tests green.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Repoint aged_vulns_assets_module + high_risk_assets_module | 7538c54 | reports/modules/aged_vulns_assets_module.py, reports/modules/high_risk_assets_module.py |
| 2 | Repoint scan_coverage_sla_module + critical_remediation_sla_module (remove _extract_owner_tag) | 37872d7 | reports/modules/scan_coverage_sla_module.py, reports/modules/critical_remediation_sla_module.py |

## What Was Built

### Task 1: aged_vulns_assets_module.py + high_risk_assets_module.py

Both modules follow an identical pattern (confirmed by PATTERNS.md). Changes applied to each:

1. **Import**: `extract_business_unit` → `extract_owner`
2. **compute() Step 5**: `extract_business_unit(on_time)` → `extract_owner(on_time)`; merge `on="business_unit"` → `on="owner"`
3. **Defensive re-extract guard**: `if "business_unit" not in asset_cols.columns` → `"owner"`; column slice `["asset_uuid", "hostname", "business_unit", "last_seen"]` → `["...", "owner", ...]`
4. **analyst_df reindex**: `"business_unit"` → `"owner"`; CSV injection guard loop updated to `"owner"`
5. **Driver narrative catch-all (Pitfall 1 — second site)**: `groupby("business_unit")` → `groupby("owner")`; `.fillna("Untagged").replace("", "Untagged")` → `.assign(owner=...fillna("Unassigned").replace("", "Unassigned"))` using `.assign()` per F-DTYPE pattern
6. **render_pdf_section**: `row.get("business_unit", "")` → `row.get("owner", "")`; `<th>Business Unit</th>` → `<th>Owner</th>`; section heading "Worst-Performing Business Units" → "Worst-Performing Owners"; fallback text updated; explanatory paragraph: "Application" tag → "Owner" tag
7. **render_excel_tabs**: header `"Business Unit"` → `"Owner"`; `row.get("business_unit", "")` → `row.get("owner", "")`
8. **Docstrings**: "business units" → "owners" narrative; `audit_info["BU_breakdown"]` key → `"owner_breakdown"`; Application tag reference → Owner tag

### Task 2: scan_coverage_sla_module.py

1. **Module docstring**: `per-business-unit breakdown` → `per-owner breakdown`; `Application tag category / extract_business_unit() / Untagged` → `Owner tag category / extract_owner() / Unassigned`
2. **Import**: `extract_business_unit` → `extract_owner`
3. **Empty-frame columns list**: `"business_unit"` → `"owner"`
4. **compute()**: `extract_owner(licensed)`; defensive re-extract: `if "owner" not in`; analyst reindex: `"owner"`; CSV injection guard: `"owner"`
5. **Driver narrative**: `bu_breakdown` sorted/accessed by `"owner"` key; "Best BU:" / "worst BU:" label → "Best Owner:" / "worst Owner:"
6. **render_pdf_section**: `row.get("owner", "")`; table heading/section → Owner; fallback text → Owner; explanatory paragraph → Owner/Unassigned
7. **render_excel_tabs**: headers `"Owner"`; `row.get("owner", "")`
8. **get_audit_info**: `BU_breakdown` → `owner_breakdown`; Application/Untagged → Owner/Unassigned

### Task 2: critical_remediation_sla_module.py

1. **Import**: `extract_business_unit` → `extract_owner`
2. **render_pdf_section**: `row.get("owner", "")`; table/section heading → Owner; fallback text → Owner tags
3. **render_excel_tabs**: headers `"Owner"`; `row.get("owner", "")`
4. **get_audit_info**: `BU_breakdown` → `owner_breakdown`; Application → Owner
5. **`_compute_bu_breakdown`**: empty-frame columns list `"owner"`; `extract_owner(on_time_assets)`; `uuid_to_owner` dict; `fw.assign(owner=...map(...).fillna("Unassigned"))` via `.assign()` — this is the **first catch-all site** (Pitfall 1)
6. **analyst detail `owner_tag` column**: replaced `.map(_extract_owner_tag)` with `extract_owner(missed)["owner"].values` — findings carry `tags` in the same `"Cat=Val;Cat=Val"` format so `extract_owner` applies directly
7. **DELETE `_extract_owner_tag`**: confirmed 0 remaining callers before deletion (D-03/Pitfall 3)

## Deviations from Plan

**1. [Rule 1 - Bug] analyst detail owner_tag replacement approach**
- **Found during:** Task 2 — `_extract_owner_tag` deletion
- **Issue:** The plan stated "DELETE `_extract_owner_tag`" but line 337 had a `.map(_extract_owner_tag)` call in the analyst detail builder that the plan's change site list at §976-991 did not enumerate
- **Fix:** Replaced `.map(_extract_owner_tag)` with `extract_owner(missed)["owner"].values` — assigns the extracted owner values before deleting the helper; the findings DataFrame has the same `tags` column format that `extract_owner` expects
- **Files modified:** reports/modules/critical_remediation_sla_module.py
- **Commit:** 37872d7

## Known Stubs

None — this plan is a pure repoint of existing compute/render paths with no new data-source wiring.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Tag parsing delegates to `extract_owner` (T-13-04: fail-soft on missing `tags` column; all-Unassigned, no raise). Secondary fillna guards now produce `"Unassigned"` not `NaN`/`"Untagged"` (T-13-05: consistent Owner display). `_extract_owner_tag` removal confirmed zero callers before delete (T-13-06).

## Self-Check: PASSED

- `reports/modules/aged_vulns_assets_module.py` exists and contains `extract_owner`: FOUND
- `reports/modules/high_risk_assets_module.py` exists and contains `extract_owner`: FOUND
- `reports/modules/scan_coverage_sla_module.py` exists and contains `extract_owner`: FOUND
- `reports/modules/critical_remediation_sla_module.py` exists and contains `extract_owner`: FOUND
- `business_unit` count across all 4 modules: 0 CONFIRMED
- `Untagged` count across all 4 modules: 0 CONFIRMED
- `Business Unit` count (case-insensitive) across all 4 modules: 0 CONFIRMED
- `_extract_owner_tag` count in critical_remediation_sla_module: 0 CONFIRMED
- Commit 7538c54 (Task 1): FOUND
- Commit 37872d7 (Task 2): FOUND
- 125 unit/content tests pass, 0 failures: CONFIRMED
