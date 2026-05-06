---
phase: 03-board-summary-module-migration
plan: 03-02
subsystem: reports/modules/scan_coverage_sla_module
tags: [module, board-metric, scan-coverage, render-email-panel, render-analyst-tabs, render-rag-strip-entry, contract-04, empty-data-guard]

# Dependency graph
requires:
  - phase: 03-board-summary-module-migration
    plan: 03-01
    provides: populate_rag_strip helper + email_inline_images bundle key + bundle-driven email_sender dispatch
  - phase: 02-reportcomposer-upgrades
    provides: assemble_email_body / assemble_analyst_workbook / collect_email_inline_images / build_email_body_modular
  - phase: 01-module-render-contract
    provides: BaseModule render_email_panel/render_analyst_tabs/render_rag_strip_entry, ModuleData.rag_strip/driver_narrative/analyst_rows, rag_utils + format_utils
provides:
  - "scan_coverage_sla_module — first board metric module migrated end-to-end to the four-channel render contract"
  - "Locked driver-narrative template ('Best BU: {good_bu_name} at {good_bu_pct}; worst BU: {worst_bu_name} at {worst_bu_pct} ({overdue_count} of {total_count} licensed assets overdue).') referencing the actual `bu_breakdown` DataFrame and `business_unit` column (W4)"
  - "Pure-construction (option 2) shape: rag_strip_payload built from build_rag_strip_entry inside compute(), passed directly into the ModuleData(...) constructor — locked for plans 03-03..05 to copy"
  - "Excel zero-row standardisation pattern (D-16): one-cell 'No data in scope' tab on empty modules, locked for plans 03-03..05"
  - "Email gauge base64 hand-off pattern: render_email_panel-time draw_gauge result stashed on data.metadata['email_gauge_b64'] inside compute(); composer.collect_email_inline_images aggregates"
affects: [03-03-critical-remediation-sla, 03-04-high-risk-assets, 03-05-aged-vulns-assets, 03-06-regression-extension]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Four-channel render contract for scan_coverage_sla_module — compute() populates rag_strip / driver_narrative / analyst_rows / metadata['email_gauge_b64']; render_email_panel + render_analyst_tabs override the new channels; render_rag_strip_entry inherits the BaseModule default that honors data.rag_strip"
    - "Empty-data hardening — all interpolations through safe_pct / safe_int; per-method try/except returns safe '' / [] / gray cell rather than raising; explicit assets-empty early return at the top of compute() so no zero-row DataFrame ever threads through dedup / extract_business_unit / compute_per_bu_breakdown"
    - "CSV-formula injection guard (T-03-02-02) on analyst Excel cells — string columns (hostname, ipv4, fqdn, business_unit) get a single-quote prefix when their first char is =, +, -, @"
    - "Pure-construction (option 2) for ModuleData — rag_strip cell built before the constructor and passed in directly; populate_rag_strip helper from 03-01 is available but plan 03-02 keeps the contract surgery local with build_rag_strip_entry directly"

key-files:
  created: []
  modified:
    - reports/modules/scan_coverage_sla_module.py — Phase 3 contract fields populated in compute(); render_email_panel + _render_empty_email_panel + render_analyst_tabs added; render_excel_tabs gains D-16 zero-row standardisation; render_rag_strip_entry NOT overridden (B5 inherits BaseModule default); two pre-existing pd.NaT / extract_business_unit empty-frame crashes patched as Rule 1 deviations; explicit assets-empty early return added (A4)

key-decisions:
  - "Pure-construction option 2 (build_rag_strip_entry called inside compute() and the result passed directly into ModuleData(...)) — locked at this plan and copied verbatim by plans 03-03..05. populate_rag_strip helper from 03-01 mutates data.rag_strip in place, which is fine for incremental migrations but Phase 3 modules build the dict pre-construction so compute() stays free of post-construction mutation."
  - "render_rag_strip_entry NOT overridden (B5). The BaseModule default at base.py:404-459 already honors data.rag_strip when populated and falls back to a gray no-data cell otherwise. Adding a duplicate override here would violate DRY — and plans 03-03..05 follow the same shape."
  - "Explicit assets-empty early return at compute() entry (Plan A4 spec) so the verify command's empty-input contract (driver=NO_DATA_DRIVER, analyst_rows=[], rag_strip gray cell, email_gauge_b64='') is satisfied without threading the empty frame through dedup / BU extraction / breakdown — each of which has its own zero-row crash on Python 3.14 + pandas 2.x."
  - "draw_gauge() error handling — the in-compute() gauge call is wrapped in its own try/except so a Matplotlib failure does not poison the rest of the module data. The metadata key falls back to '' which routes the email panel through the D-15 gray-placeholder branch."

patterns-established:
  - "Driver-narrative locked f-string template: f\"Best BU: {good_row['business_unit']} at {safe_pct(good_row['percentage'])}; worst BU: {worst_row['business_unit']} at {safe_pct(worst_row['percentage'])} ({safe_int(not_scanned_on_time)} of {safe_int(total_licensed)} licensed assets overdue).\" — references the bu_breakdown DataFrame produced by compute_per_bu_breakdown and its business_unit column (W4 — actual variable / column resolved in plan, not deferred to executor)."
  - "Tie-break pattern for narrative selection: bu_breakdown.sort_values(['percentage', 'business_unit'], ascending=[True, True]) for worst; ascending=[False, True] for best. Alphabetical business_unit secondary sort makes the narrative deterministic across runs."
  - "Excel zero-row standardisation (D-16) — emit a single 'No data in scope' cell at A1 with bold gray font when both data.metrics and data.table_data are empty AND no error is set. Behavior change from pre-Phase-3: empty modules previously skipped their tab entirely; post-Phase-3 they emit a placeholder tab so the workbook structure is uniform across runs."

requirements-completed: [BOARD-01, QUALITY-02]

# Metrics
duration: ~25min
completed: 2026-05-06
---

# Phase 3 Plan 03-02: scan_coverage_sla Module Migration Summary

**scan_coverage_sla_module is now end-to-end on the four-channel render contract: compute() populates rag_strip / driver_narrative / analyst_rows / metadata['email_gauge_b64']; render_email_panel + render_analyst_tabs override the new channels; render_excel_tabs emits a 1-row 'No data in scope' tab on empty input; render_rag_strip_entry inherits the BaseModule default. Plan locks the driver-narrative template (W4-resolved against the actual `bu_breakdown` variable + `business_unit` column) and the pure-construction option-2 ModuleData shape so plans 03-03..05 can copy them verbatim.**

## Performance

- **Duration:** ~25 minutes
- **Tasks:** 2 (T1 contract-field population in compute() + Rule 1 empty-frame fixes; T2 render method overrides + D-16 standardisation)
- **Files modified:** 1 (`reports/modules/scan_coverage_sla_module.py`)
- **Commits:** 2

## Accomplishments

- **compute() populates the three Phase 1 ModuleData fields + the metadata['email_gauge_b64'] hook on every return path.** Populated path: rag_strip via build_rag_strip_entry + rag_status_from_value with `_DIRECTION = "higher_is_better"`, threshold_green=95, threshold_yellow=90; driver_narrative via the locked f-string template using `bu_breakdown` sorted by percentage with alphabetical business_unit tiebreak; analyst_rows = [("Scan Coverage Detail", df)] with the 6 contracted columns sorted by days_since_licensed_scan desc and CSV-formula-injection-guarded; email_gauge_b64 from draw_gauge(figsize=(2.4,1.6)). Empty-data path (assets_df.empty): explicit early return populating NO_DATA_DRIVER + gray rag_strip + [] analyst_rows + "" gauge.
- **render_email_panel — 620px-wide horizontal-split table.** 150px gauge cell (cid:scan_coverage_sla_gauge) on the left + 430px text cell on the right (DISPLAY_NAME label, headline %, RAG color/icon/label, driver narrative). Inline CSS only; `<table>` shell with explicit `width=""` attributes per project convention. T-03-02-01 mitigation: every module-supplied string (DISPLAY_NAME, driver_narrative, rag_label) is `html.escape(..., quote=True)` before f-string interpolation. Empty-data delegates to `_render_empty_email_panel` (gray gauge cell, em-dash headline, gray no-data band). Per-method try/except returns "" on render exception per Phase 2 D-28 isolation.
- **render_analyst_tabs — single-tuple list passthrough (D-14).** Returns `list(data.analyst_rows)` when populated, `[]` when empty/error. Per-method try/except returns `[]` on render exception.
- **render_excel_tabs gains D-16 zero-row standardisation.** When both data.metrics and data.table_data are empty AND no error is set, emits a single "No data in scope" cell at A1 with bold gray (`#666666`) font and returns the tab name. Existing populated-path behavior preserved unchanged.
- **render_rag_strip_entry NOT overridden (B5).** Inherits the BaseModule default that honors `data.rag_strip` when populated and falls back to a gray no-data cell otherwise. Plans 03-03..05 follow the same shape.

## Task Commits

Each task was committed atomically:

1. **Task 1: Populate Phase 3 contract fields in compute() + Rule 1 empty-frame fixes** — `f785cae` (feat)
2. **Task 2: render_email_panel + render_analyst_tabs + render_excel_tabs D-16 standardisation** — `1b03874` (feat)

## Files Created/Modified

- `reports/modules/scan_coverage_sla_module.py` —
  - **Imports:** added `html`; added `populate_rag_strip` to the existing `board_report_utils` import (re-exported for the contract surface even though plan 03-02 uses `build_rag_strip_entry` directly); added `safe_int, safe_pct` from `format_utils`; added `STATUS_COLOR, STATUS_LABEL, STATUS_ICON, NO_DATA_DRIVER, NO_DATA_HEADLINE, build_rag_strip_entry, rag_status_from_value` from `rag_utils`.
  - **compute() head:** added explicit `if assets_df is None or assets_df.empty:` early-return path that populates all three Phase 3 contract fields (NO_DATA_DRIVER + gray rag_strip + [] analyst_rows + "" gauge) without threading the empty frame through dedup / BU enrichment / breakdown.
  - **compute() Step 1 (dedup):** Rule 1 fix — replaced `all_dedup.loc[:, _lsd] = pd.NaT` with `all_dedup[_lsd] = pd.Series(pd.NaT, index=all_dedup.index, dtype="datetime64[ns, UTC]")` to handle a zero-column DataFrame without crashing.
  - **compute() Step 4 (BU breakdown):** Rule 1 fix — wrapped `extract_business_unit(licensed)` and `compute_per_bu_breakdown(...)` in `if licensed.empty:` short-circuit returning an empty `bu_breakdown` DataFrame with the expected columns when `licensed` is zero-row. Also handles the all-unlicensed edge case.
  - **compute() Step 6 (Phase 3 contract fields):** new block before `return ModuleData(...)` building `analyst_rows_payload` (with reindex / sort / dedup / CSV-formula-injection guard), `driver` (locked f-string template with W4-verified variable / column references), `email_gauge_b64` (with try/except around draw_gauge), and `rag_strip_payload` (build_rag_strip_entry pre-construction).
  - **return ModuleData(...):** populated the three new keyword arguments (driver_narrative, analyst_rows, rag_strip) and added the `email_gauge_b64` key to metadata.
  - **render_excel_tabs:** added D-16 zero-row standardisation at the top of the method body (after the data.error check).
  - **render_email_panel + _render_empty_email_panel:** added new methods between `render_excel_tabs` and `render_email_kpis`. 620px horizontal-split layout per D-02 / D-15.
  - **render_analyst_tabs:** added new method immediately after `_render_empty_email_panel`. Single-tuple-list passthrough per D-14.

## Decisions Made

### Pure-construction option-2 (locked for 03-03..05)

PATTERNS.md offered two shapes for ModuleData rag_strip population:

1. Construct ModuleData first, call `populate_rag_strip(data, ...)` to mutate `data.rag_strip` in place, return.
2. Compute the cell dict before constructing ModuleData and pass `rag_strip=...` directly into the constructor.

Plan 03-02 locks **option 2**. Rationale: `compute()` stays a single pure construction expression; no post-construction mutation; matches the "pure compute, deferred render" anti-pattern check. The `populate_rag_strip` helper from Plan 03-01 is still imported (the import is preserved with `# noqa: F401` to acknowledge the contract surface) so plans 03-03..05 reading this module see the symbol available, but the actual call uses `rag_status_from_value` + `build_rag_strip_entry` directly.

### Driver-narrative template (W4 — locked)

```
Best BU: {good_row['business_unit']} at {safe_pct(good_row['percentage'])};
worst BU: {worst_row['business_unit']} at {safe_pct(worst_row['percentage'])}
({safe_int(not_scanned_on_time)} of {safe_int(total_licensed)} licensed assets overdue).
```

- Source DataFrame: `bu_breakdown` (the local variable produced earlier in `compute()` at the line where `compute_per_bu_breakdown(enriched, on_time_mask_bu, denom_mask, higher_is_better=True)` runs)
- Sort: `bu_breakdown.sort_values(["percentage", "business_unit"], ascending=[False, True])` for best-BU; `ascending=[True, True]` for worst-BU. Alphabetical secondary sort guarantees deterministic output across runs.
- Empty-data fallback: `NO_DATA_DRIVER` ("No data in scope.") when `total_licensed == 0` OR `bu_breakdown.empty`.

### Excel zero-row standardisation (D-16) regression diff

**Pre-Phase-3 behavior:** When `data.metrics` and `data.table_data` were both empty, `render_excel_tabs` would still create the "Scan Coverage Summary" tab and write the full KPI block with N/A and zero values into rows 1–10, plus an empty BU header row at row 12 with no data rows below. The tab was "live" but visually empty under the header.

**Post-Phase-3 behavior:** Empty modules emit a single "No data in scope" cell at A1 with bold gray (`#666666`) font and skip the KPI block + BU header entirely. The tab is structurally minimal but always present so workbook tab-count is consistent across runs.

This is a behavior change. **Plan 03-06's regression test (extension to `tests/test_phase2_composer_pipeline.py`) MUST capture the new shape and confirm against the live-Tenable Excel diff.** Plans 03-03..05 must surface the same diff in their SUMMARY (per CONTEXT risk-row line 206).

### Joined-cell columns / sort-order question — N/A this module

Plan 03-02's analyst tab is **asset-level** (D-10): hostname, ipv4, fqdn, last_licensed_scan_date, days_since_licensed_scan, business_unit. None of these are joined-cell columns — every row is one licensed asset, every cell is one scalar value. The sort-order question (worst-first by `days_since_licensed_scan` desc, NaN last) was resolved per D-11 and the column-type determinism question raised by CONTEXT line 238 does not apply.

Plans 03-04 (`high_risk_assets`) and 03-05 (`aged_vulns_assets`) DO produce joined-cell columns (`contributing_finding_ids`, `contributing_plugins`) — those plans own the determinism guard.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Pre-existing `pd.NaT` scalar assignment crashes on a zero-row DataFrame**

- **Found during:** Task 1 verify (empty-input compute() command)
- **Issue:** `compute()` Step 1 ran `all_dedup.loc[:, _lsd] = pd.NaT` when the dedup result lacked the `last_licensed_scan_date` column. On Python 3.14 + pandas 2.x this raises `ValueError: cannot set a frame with no defined index and a scalar` whenever `all_dedup` has zero rows.
- **Fix:** Replaced the scalar-loc assignment with an explicit Series construction: `all_dedup[_lsd] = pd.Series(pd.NaT, index=all_dedup.index, dtype="datetime64[ns, UTC]")`. Produces the same column on populated frames and works on the empty frame.
- **Files modified:** `reports/modules/scan_coverage_sla_module.py` (compute() Step 1)
- **Verification:** Empty-input verify command now passes; populated path unchanged.
- **Commit:** `f785cae`

**2. [Rule 1 - Bug] `extract_business_unit` and `compute_per_bu_breakdown` crash on a zero-row `licensed` frame**

- **Found during:** Task 1 verify (empty-input compute() command)
- **Issue:** `extract_business_unit(licensed)` (in `board_report_utils.py:278`) and `compute_per_bu_breakdown` both call `df.loc[:, col] = scalar` patterns that crash on a zero-row DataFrame for the same pandas 2.x reason.
- **Fix:** Wrapped Step 4 in `if licensed.empty:` short-circuit returning an explicit empty DataFrame with the expected columns (business_unit, numerator, denominator, percentage, affected). The fix stays inside `scan_coverage_sla_module.py` rather than touching `board_report_utils.py` (out of scope for plan 03-02; plans 03-03..05 will need their own short-circuits or the helper itself patched in a future plan).
- **Files modified:** `reports/modules/scan_coverage_sla_module.py` (compute() Step 4)
- **Verification:** Empty-input verify command now passes through the assets-empty early return AND through the all-unlicensed edge case.
- **Commit:** `f785cae`

**3. [Rule 3 - Plan ambiguity resolved] Plan A4 references an "existing empty-input early return" that didn't exist in the source**

- **Found during:** Task 1 implementation
- **Issue:** Plan A4 said "The existing compute() already has an empty-input early return (search for `if assets_df.empty:`). Update THAT existing early-return ModuleData(...) construction to also set the three new fields." But the source had no such early return — there was only one `return ModuleData(...)` (the populated path) and one `_empty_result(...)` exception fall-through.
- **Fix:** Added the explicit `if assets_df is None or assets_df.empty:` early-return path at the top of `compute()`'s try block, populating all three Phase 3 contract fields exactly as the plan specified. This matches the plan's intent (assets-empty must produce NO_DATA_DRIVER + gray rag_strip + [] analyst_rows + "" gauge without threading the empty frame through downstream computation) AND satisfies the acceptance criteria that require `>=2 matches` for `driver_narrative=`, `analyst_rows=`, `rag_strip=`.
- **Files modified:** `reports/modules/scan_coverage_sla_module.py` (compute() entry)
- **Verification:** Empty-input verify command passes; acceptance grep counts (`driver_narrative=`, `analyst_rows=`, `rag_strip=`) all = 2.
- **Commit:** `f785cae`

---

**Total deviations:** 3 auto-fixed (2 bug-class, 1 plan-ambiguity)
**Impact on plan:** Each fix was required for the plan's own verify commands and acceptance criteria to hold. No scope creep. The two pandas 2.x empty-frame bugs (#1 and #2) also exist in plans 03-03/04/05's source modules — those plan executors will hit them and should reuse the same Series-construction / short-circuit fixes (or a future utility plan can centralise the fix in `board_report_utils.py`).

## Issues Encountered

- The plan's verify command asserts `data.metadata.get('email_gauge_b64', '?') == ''` — i.e. the metadata key MUST be the empty-string sentinel. With the original compute() routing the empty input through `_empty_result()`, metadata was `{}` and the dict-default `'?' != ''` assertion failed. Adding the explicit early return that populates `metadata = {..., 'email_gauge_b64': ''}` was the correct fix.
- The acceptance grep counts (`driver_narrative=` `>= 2`, `analyst_rows=` `>= 2`, `rag_strip=` `>= 2`) require the file to have BOTH the populated-path return AND the empty-path return populating those fields. The `_empty_result()` exception fall-through doesn't count because that path is in `base.py`, not in this module's source.

## Threat Flags

None — plan 03-02 introduces no new security-relevant surface beyond what's already documented in the plan's `<threat_model>`. The two declared mitigations are both in place:

- **T-03-02-01** — Tampering / Injection on the email panel HTML fragment: `html.escape(..., quote=True)` is applied to `self.DISPLAY_NAME`, `data.driver_narrative`, and `STATUS_LABEL[status]` before f-string interpolation in both `render_email_panel` and `_render_empty_email_panel`. (`grep -c "html.escape" reports/modules/scan_coverage_sla_module.py` → 7.)
- **T-03-02-02** — Tampering / CSV-formula injection on analyst Excel cells: the `for _col in ("hostname", "ipv4", "fqdn", "business_unit"):` loop in `compute()` Step 6 prepends a single quote to any cell whose first char is `=`, `+`, `-`, or `@`. Applied uniformly to all four string columns even though `business_unit` values are Tenable-normalised — defence in depth.

## Next Plan Readiness

- The driver-narrative template + `bu_breakdown` / `business_unit` references are locked. Plans 03-03..05 follow the same compute()-time construction shape but use their own metric-specific templates (per CONTEXT lines 71-74).
- The pure-construction option-2 ModuleData shape is locked. Plans 03-03..05 build their `rag_strip_payload` before the `return ModuleData(...)` and pass it in as a kwarg.
- The Excel D-16 zero-row standardisation pattern is locked. Plans 03-03..05 add the same `empty_metrics and empty_tables and not data.error` block at the top of their `render_excel_tabs` body.
- The pandas 2.x empty-frame crashes (Deviations 1 & 2) WILL recur in plans 03-03/04/05 source modules. Each executor should expect to hit them and apply the same fix shape OR escalate to a future utility plan that patches `board_report_utils.py` centrally.
- Phase 2 regression test (`tests/test_phase2_composer_pipeline.py`) passes 7/7 against the new module shape.

---
*Phase: 03-board-summary-module-migration*
*Completed: 2026-05-06*

## Self-Check: PASSED

- File `03-02-SUMMARY.md` exists at `.planning/phases/03-board-summary-module-migration/`.
- Both task commits exist in the worktree branch's history (`f785cae`, `1b03874`).
- Modified file `reports/modules/scan_coverage_sla_module.py` exists and parses cleanly.
- Phase 2 regression test (`tests/test_phase2_composer_pipeline.py`) passes 7/7 against the new module shape.
- Plan verify commands all PASS:
  - Task 1 `empty-input compute OK`
  - Task 1 `W4 variable resolution OK`
  - Task 2 `empty render OK`
  - Task 2 `populated render OK`
  - Task 2 `no override OK`
