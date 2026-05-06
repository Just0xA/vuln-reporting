---
phase: 03-board-summary-module-migration
plan: 03-05
subsystem: modules/aged_vulns_assets
tags: [module, board-metric, aged-vulns, render-email-panel, render-analyst-tabs, lower-is-better, joined-cell, worst-severity]

# Dependency graph
requires:
  - plan: 03-01
    provides: rag_status_from_value(direction=...), build_rag_strip_entry, NO_DATA_DRIVER, NO_DATA_HEADLINE, STATUS_*, email_inline_images bundle key
  - plan: 03-04
    provides: lower_is_better module migration shape + W6 last_seen-merge sibling pattern
provides:
  - AgedVulnsAssetsModule with full Phase 3 four-channel contract (compute fields + render_email_panel + render_analyst_tabs + Excel zero-row)
  - Single-tab analyst rows with worst_severity column (D-12) and alphabetical-sorted contributing_plugins comma-joined cell
  - lower_is_better RAG-strip wiring (T-03-05-03 — direction explicitly passed, never defaulted)
affects:
  - reports/board_summary.py (no changes; the migrated module slots into the existing board pipeline)
  - .planning/phases/03-board-summary-module-migration/03-06-PLAN.md (regression-test extension owner)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Locked option-2 pure-construction shape (rag_strip dict + driver narrative + analyst_rows + email_gauge_b64 computed BEFORE ModuleData(...) and passed in directly — matches Plan 03-02..04 locked shape; no post-construction mutation)"
    - "Joined-cell alphabetical determinism: contributing_plugins built via ', '.join(sorted({str(v) for v in s.dropna() if str(v).strip()})) inside the _join_plugins agg closure — alphabetical sort chosen over descending-VPR because plugin names without VPR context are not directly orderable"
    - "Single-tab analyst output (D-12): the 'Aged Vulns Detail' sheet carries a worst_severity column (critical > high > medium ordering via _worst_severity helper) — analysts filter inside Excel rather than tabbing across three per-severity sub-tabs"
    - "W6 last_seen-merge resolution — real last_seen is projected from assets_df and joined onto the per-asset frame BEFORE deduplicate_assets_by_name; pd.NaT placeholder appears only inside a defensive logger.warning fallback (mirrors Plan 03-04 pattern)"
    - "T-03-05-03 mitigation in code — rag_status_from_value(direction=_DIRECTION) where _DIRECTION = 'lower_is_better' is hardcoded inline; the existing pre-Phase-3 sla_status_from_thresholds call in compute() step 4 already uses the same _DIRECTION constant. Two grep matches expected and present."

key-files:
  created: []
  modified:
    - reports/modules/aged_vulns_assets_module.py — added html, format_utils, rag_utils, deduplicate_assets_by_name imports; added _worst_severity module-private helper; extended _find_aged_assets to also return aged-findings frame (with attached days_open column); populated three new ModuleData contract fields (analyst_rows / driver_narrative / rag_strip) + email_gauge_b64 metadata key in both populated and no-data paths; added render_email_panel + _render_empty_email_panel + render_analyst_tabs methods; added D-16 Excel zero-row standardisation; defensive guard on on_time['asset_uuid'] lookup so empty assets_df routes through the no_data early-return

key-decisions:
  - "Locked driver-narrative template: f\"{count} assets carry at least one Med+ vuln open >{_AGED_DAYS_THRESHOLD} days; oldest finding: {oldest_age} days; worst BU: {worst_bu_name} with {worst_bu_count} assets.\" — verbatim per Plan 03-05 Step A3b. NO_DATA_DRIVER fallback when aged_assets_count == 0 OR analyst_rows is empty. worst_bu_name derived from the analyst DataFrame (groupby('business_unit').size()) so the BU shown is one of the in-scope BUs; empty BU values fall back to 'Untagged'."
  - "Single-tab decision (D-12) — worst_severity column. The plan explicitly chose a single 'Aged Vulns Detail' sheet with a worst_severity column over three per-severity sub-tabs (Aged - Critical / Aged - High / Aged - Medium). Rationale: reduces workbook tab count; analysts can still filter by severity inside Excel; preserves the single-tab shape decided across all four board modules in Plan 03-02..05. Verified — grep -c 'Aged - Critical|Aged - High|Aged - Medium' returns 0."
  - "Alphabetical sort for contributing_plugins (vs descending-VPR alternative). The cell joins unique plugin NAMES from the aged Med+ findings per asset; plugin names are free-text strings without intrinsic numeric ordering, so a deterministic alphabetical sort is the natural fit. Descending-VPR was considered but rejected because the analyst tab does not carry VPR per-row in the joined cell — adding VPR-per-plugin would require a parallel-array column that breaks the simple comma-join shape. Alphabetical also reads consistently across runs (deterministic regardless of fetcher row order)."
  - "Direction = lower_is_better (T-03-05-03 explicit-pass mitigation): rag_status_from_value(direction=_DIRECTION) is the single new call site; _DIRECTION is the module-level constant 'lower_is_better' (line 52). The acceptance grep direction\\s*=\\s*_DIRECTION returns 2 matches — the new compute() block + the pre-existing sla_status_from_thresholds call in step 4. Both are intentional; T-03-05-03 requires the new compute() block to never default — verified at the inline call site."
  - "_worst_severity helper definition. Pure-function module-private helper at file scope (alongside _find_aged_assets per the plan's intent). Takes set[str] and returns the worst tier from {critical, high, medium}; ignores anything outside that triad (e.g. 'low', 'info') and yields '' on an empty / all-unknown input. Used inside the per-asset agg closure: groupby('asset_uuid').agg(worst_severity=('severity', lambda s: _worst_severity(set(s))))."
  - "_find_aged_assets signature change: tuple[set, pd.DataFrame] rather than set. Returns the original aged_uuids set + the filtered aged_findings DataFrame (the relevant[aged_mask] subset) with a precomputed days_open column. compute() consumes the second return value to build the per-asset analyst tab without re-deriving the filter. No external imports of _find_aged_assets exist (it is module-private), so this signature change is internal only."
  - "W6 last_seen-merge resolution: assets_df already carries last_seen (verified via data/fetchers.py and confirmed by sibling Plan 03-04). compute() projects (asset_uuid, hostname, business_unit, last_seen) from assets_df, merges onto the per-asset grouped frame, then calls deduplicate_assets_by_name. The helper's signature is unchanged — only the caller is fixed. Defensive .assign(last_seen=pd.NaT) lives ONLY inside a logger.warning fallback path that fires when assets_df does not carry the column (which never happens in production today). Sibling pattern from Plan 03-04."
  - "Excel zero-row regression diff (D-16): pre-Phase-3 the empty Aged Vuln Assets module wrote a sheet with the KPI block populated by None values + an empty BU breakdown table — the sheet was structurally non-empty but content-empty. Post-Phase-3 the same input produces a single 'No data in scope' bold-gray cell at A1 with no other content. Live-Tenable Excel diff regression handed off to Plan 03-06."
  - "Pre-existing on_time['asset_uuid'] KeyError on empty assets_df is now defensively guarded (Rule 1 fix): when the column is absent, on_time_uuids = set() and total_on_time = len(on_time) is 0, which routes through the no-data early-return path. Required for the plan's own verify command to pass (which constructs pd.DataFrame() with no columns). Same fix as Plan 03-04."

patterns-established:
  - "Single-tab worst_severity pattern (Plan 03-05 unique among the four board modules): when a metric spans multiple severity tiers and the natural drill-down is per-severity, prefer a single tab with a worst_severity column over per-severity sub-tabs. Severity ordering helper (_worst_severity) is reusable for any future module needing critical>high>medium ranking from a set."
  - "Alphabetical comma-joined cell pattern: ', '.join(sorted({str(v) for v in s.dropna() if str(v).strip()})) — used for free-text-string joined cells (plugin names, owner tags, etc.) where no natural numeric ordering exists. Plan 03-04 used a numeric-first / lexical-fallback variant for plugin IDs; Plan 03-05 uses a single alphabetical path because plugin names are always strings."

requirements-completed: [BOARD-04, QUALITY-02]

# Metrics
duration: ~12min
completed: 2026-05-06
---

# Phase 3 Plan 03-05: Aged Vulnerability Assets Module Migration Summary

**AgedVulnsAssetsModule fully migrated to the Phase 3 four-channel contract — compute() populates rag_strip / driver_narrative / analyst_rows / email_gauge_b64 with the lower_is_better direction explicitly passed (T-03-05-03), the analyst tab is a single 'Aged Vulns Detail' sheet (D-12) with hostname / business_unit / oldest_finding_age_days / count_of_aged_findings / contributing_plugins / worst_severity columns, contributing_plugins is alphabetically sorted, render_email_panel emits the 620px horizontal-split panel with a CID gauge, and render_excel_tabs emits a 1-row 'No data in scope' sheet on empty input.**

## Performance

- **Duration:** ~12 minutes (covering both retry context-load and execution)
- **Started:** 2026-05-06T17:11:00Z (retry — sequential mode on main worktree)
- **Completed:** 2026-05-06T17:23:00Z (approx)
- **Tasks:** 2 (both autonomous; Task 2 was tdd="true")
- **Files modified:** 1 (`reports/modules/aged_vulns_assets_module.py`)

## Accomplishments

- **compute() populates the three Phase 3 ModuleData fields** (driver_narrative / analyst_rows / rag_strip) on both the populated path and the no-data early-return path. The `email_gauge_b64` metadata key is also set on both paths so `composer.collect_email_inline_images` picks the gauge up.
- **`_find_aged_assets` extended** to also return the aged-findings DataFrame (the `relevant[aged_mask]` subset) with a precomputed `days_open` column, so compute() can produce per-asset oldest_finding_age_days + count + plugin list + worst_severity without re-deriving the filter. Signature change is internal only — no other module imports this helper.
- **`_worst_severity` module-private helper** added at file scope. Pure function, takes `set[str]`, returns `"critical" | "high" | "medium" | ""` ordered critical > high > medium. Severities outside that triad (`"low"`, `"info"`, etc.) are ignored.
- **Single-tab analyst rows with worst_severity column (D-12)**:
  - Sheet name: `"Aged Vulns Detail"` (18 chars, ≤31)
  - Columns (per D-10): `hostname, business_unit, oldest_finding_age_days, count_of_aged_findings, contributing_plugins, worst_severity`
  - Sort: `oldest_finding_age_days` desc (D-11)
  - D-13 — apply asset-level dedup via `deduplicate_assets_by_name` AFTER projecting real `last_seen` from `assets_df` (W6 — duplicate-hostname tiebreak deterministic)
  - T-03-05-02 — CSV-formula injection guard on text columns (`hostname`, `business_unit`, `contributing_plugins`, `worst_severity`)
  - **contributing_plugins**: alphabetical-sorted unique plugin names comma-joined via `", ".join(sorted({str(v) for v in s.dropna() if str(v).strip()}))`. End-to-end smoke test confirms `"Plugin A, Plugin Z"` ordering even when fetcher returns plugins in `Z, A` insertion order.
  - **worst_severity**: per-asset critical > high > medium ordering. End-to-end smoke test confirms host-a (critical+high findings) → `"critical"`, host-b (medium only) → `"medium"`.
- **Locked driver-narrative template** (D-06) — verbatim per Plan 03-05 Step A3b:
  ```
  f"{count} assets carry at least one Med+ vuln open
   >{_AGED_DAYS_THRESHOLD} days; oldest finding: {oldest_age} days;
   worst BU: {worst_bu_name} with {worst_bu_count} assets."
  ```
  NO_DATA_DRIVER fallback when no aged assets are found.
- **lower_is_better direction is explicitly passed** (T-03-05-03) — `rag_status_from_value(direction=_DIRECTION)` where `_DIRECTION = "lower_is_better"`. Verified by both grep (`direction\s*=\s*_DIRECTION` returns 2 matches: pre-existing step-4 sla_status_from_thresholds + new Phase 3 rag_strip block) and runtime classifier check (1.0 → green, 3.0 → yellow, 7.0 → red against 2.0/5.0 thresholds).
- **render_email_panel** produces the 620px horizontal-split table with `cid:aged_vulns_assets_gauge` on populated input. Empty-data path delegates to `_render_empty_email_panel` which emits the gray "No data" placeholder (no `<img>`, em-dash headline, NO_DATA_DRIVER text). All interpolated strings are `html.escape`-d (T-03-05-01).
- **render_analyst_tabs** returns `data.analyst_rows` (single-element list `[("Aged Vulns Detail", df)]`) on populated input or `[]` on empty.
- **render_excel_tabs zero-row standardisation (D-16)** — emits a single bold-gray `"No data in scope"` cell at A1 when both `data.metrics` and `data.table_data` are empty AND `data.error` is None. Pre-existing populated path preserved.
- **render_rag_strip_entry NOT overridden** — inherits the BaseModule default which honors `data.rag_strip` populated by `compute()`. Verified by `grep -c "def render_rag_strip_entry"` returning 0.
- **[Rule 1] Defensive guard on `on_time['asset_uuid']`** — `pd.DataFrame()` with no columns now routes through the no_data early-return path instead of raising KeyError into `_empty_result`. Same fix as Plan 03-04.

## Task Commits

Each task was committed atomically:

1. **Task 1: Populate Phase 3 ModuleData fields in compute() + add _worst_severity helper + extend _find_aged_assets** — `8d4fdb9` (feat)
2. **Task 2: render_email_panel + render_analyst_tabs + Excel zero-row standardisation** — `ef049e2` (feat)

## Files Created/Modified

- `reports/modules/aged_vulns_assets_module.py`:
  - Added `import html`, plus imports from `format_utils` (`safe_int`, `safe_pct`), `rag_utils` (`NO_DATA_DRIVER`, `NO_DATA_HEADLINE`, `STATUS_COLOR as _RAG_STATUS_COLOR`, `STATUS_ICON`, `STATUS_LABEL as _RAG_STATUS_LABEL`, `build_rag_strip_entry`, `rag_status_from_value`), and `deduplicate_assets_by_name` from `board_report_utils`.
  - Added `_worst_severity(severities: set[str]) -> str` module-private helper (file scope, near `_find_aged_assets`).
  - Extended `_find_aged_assets` signature from `set` to `tuple[set, pd.DataFrame]`. The second return is the filtered aged-findings frame with a precomputed `days_open` Int64 column.
  - Updated the existing call site in compute() Step 3 to unpack the new tuple: `aged_uuids, aged_findings = _find_aged_assets(...)`.
  - Added defensive guard on `on_time['asset_uuid']` lookup in compute() Step 1 so empty assets_df → `on_time_uuids = set()` and the no_data early-return path wins (Rule 1 fix).
  - Updated the no-data early-return path (`total_on_time == 0`) to populate the three new contract fields and the empty `email_gauge_b64`.
  - Added the analyst rows / driver narrative / email gauge / rag_strip blocks BEFORE the existing populated-path `return ModuleData(...)`.
  - Updated the populated `return ModuleData(...)` to include the three new contract fields and the populated `email_gauge_b64` metadata key.
  - Inserted D-16 Excel zero-row standardisation at the TOP of `render_excel_tabs` body.
  - Added `render_email_panel` + `_render_empty_email_panel` + `render_analyst_tabs` methods AFTER `render_email_kpis` and BEFORE `get_audit_info`.
  - **Net diff:** +250 / -14 (Task 1) + +138 / -0 (Task 2) = +388 / -14 lines.

## Decisions Made

- **Driver narrative template.** Verbatim copy of the plan's locked Step A3b template. The `worst_bu_name` is derived from the analyst DataFrame (`groupby("business_unit").size()`) rather than from `bu_breakdown` because the analyst frame is already the aged-asset subset; reusing it avoids a second filter pass. Empty BU values fall back to `"Untagged"` (matching the Plan 03-04 sibling pattern).
- **Single-tab decision (D-12) — worst_severity column.** The plan explicitly chose this over per-severity sub-tabs (`"Aged - Critical"`, `"Aged - High"`, `"Aged - Medium"`). Rationale: reduces workbook tab count; analysts can still filter by severity inside Excel; preserves the single-tab shape decided across all four board modules in Plan 03-02..05. Verified — `grep -c "Aged - Critical\|Aged - High\|Aged - Medium"` returns 0.
- **Alphabetical sort for contributing_plugins.** Plugin names are free-text strings without intrinsic numeric ordering. Descending-VPR was considered but rejected because the joined-cell column does not carry per-plugin VPR; adding it would break the simple comma-join shape. Alphabetical also reads consistently across runs (deterministic regardless of fetcher row order). End-to-end smoke confirms `"Plugin A, Plugin Z"` even when input order is `Plugin Z, Plugin A`.
- **lower_is_better direction explicitly passed (T-03-05-03).** `rag_status_from_value(direction=_DIRECTION)` is hardcoded inline rather than relying on a default. The acceptance grep `direction\s*=\s*_DIRECTION` returns 2 matches: the pre-existing call in compute() step 4 (`sla_status_from_thresholds(..., direction=_DIRECTION)`) AND the new Phase 3 rag_strip block. Both are correct. The new call site explicitly passes the keyword so a future change to the helper's default can never silently regress aged-vulns RAG colors to higher-is-better.
- **D-13 asset-level dedup via `deduplicate_assets_by_name`.** The dedup is applied AFTER the per-asset groupby so each row is already one asset; the helper's hostname-tiebreak by most-recent `last_seen` resolves duplicates deterministically. **W6 resolution** — real `last_seen` is projected from `assets_df` and merged onto the per-asset frame BEFORE the dedup call so tiebreaks resolve deterministically. The defensive `.assign(last_seen=pd.NaT)` fallback lives ONLY inside a `logger.warning` path that fires when the upstream `fetch_all_assets()` contract is broken. Sibling pattern from Plan 03-04.
- **Excel zero-row standardisation (D-16) regression diff.** Pre-Phase-3: empty input wrote a structurally-populated sheet with the KPI block carrying None values and an empty BU breakdown table. Post-Phase-3: empty input writes a single bold-gray `"No data in scope"` cell at A1 and nothing else. Live-Tenable Excel diff regression handed off to Plan 03-06.
- **Pre-existing `on_time['asset_uuid']` KeyError fixed.** Required for the plan's own empty-input verify command (which constructs `pd.DataFrame()` with no columns). The bug was masked before because `_empty_result` returned a coherent failed-data shape; with the new contract fields the test asserts on `metadata.get('email_gauge_b64') == ''` (which `_empty_result` returns as `None`, breaking the assertion). Defensive `if "asset_uuid" in on_time.columns` guard added — same fix as Plan 03-04.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Defensive guard on `on_time["asset_uuid"]` lookup in compute() Step 1**
- **Found during:** Task 1 (running the empty-input verify command after the new contract fields were added)
- **Issue:** `identify_on_time_assets(empty, ...)` returns an empty DataFrame WITHOUT an `asset_uuid` column. The pre-existing line `on_time_uuids = set(on_time["asset_uuid"].dropna())` raised `KeyError: 'asset_uuid'`, falling through to `_empty_result` which returns `metadata={}`. The plan's verify command asserts `data.metadata.get('email_gauge_b64') == ''` — but `_empty_result` returns `None` for that key, breaking the assertion.
- **Fix:** Wrap the lookup in `if "asset_uuid" in on_time.columns: on_time_uuids = set(on_time["asset_uuid"].dropna()); else: on_time_uuids = set()`. Empty input now correctly routes through the `total_on_time == 0` no_data early-return path which populates the new contract fields per the plan.
- **Files modified:** `reports/modules/aged_vulns_assets_module.py`
- **Verification:** `python -c "...empty = pd.DataFrame(); ..."` now prints `empty-input compute OK`.
- **Committed in:** `8d4fdb9` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 bug-class)
**Impact on plan:** Required for the plan's own verify command to pass. No scope creep. Same defensive fix as Plan 03-04.

## Issues Encountered

- **Pandas FutureWarnings** (chained assignment) inside the new compute() block (lines 260, 359, 383) and inside pre-existing `board_report_utils.py:449/454/469` calls. These are forward-compatibility warnings about pandas 3.0 (the pinned version is 2.2.3). The behavior is correct in the pinned pandas version. The pre-existing pattern in `board_report_utils.py` produces the same warnings — no fix is in scope here. Per the scope-boundary rule, out-of-scope issues are not auto-fixed; the new instances I introduced match the codebase pattern (and match Plan 03-04's siblings) and don't change runtime behavior.
- **pytest 9 / Python 3.14 collected 0 tests** when invoked via `-m pytest tests/test_phase2_composer_pipeline.py`. The Phase 2 regression file uses a `if __name__ == "__main__":` runner pattern, not pytest test discovery. Ran the file directly via `python tests/test_phase2_composer_pipeline.py` — **7/7 passed** (D-22 bundle shape, D-27 module ordering, D-29 page-2 strip + cover stability, D-29 main-Excel content + mtime hash, D-28 email/analyst exception isolation).

## Threat Flags

None — Plan 03-05 introduces no new security-relevant surface beyond what's already documented in the plan's `<threat_model>`.
- T-03-05-01 (HTML injection in email panel) is mitigated by `html.escape(..., quote=True)` at every interpolation site (verified — `grep -c "html.escape"` returns 6).
- T-03-05-02 (CSV-formula injection in analyst Excel) is mitigated by the leading-quote escape on `hostname / business_unit / contributing_plugins / worst_severity`.
- T-03-05-03 (RAG misclassification by direction default) is mitigated by `direction=_DIRECTION` being explicitly passed at the new classifier call (verified — `grep -cE "direction\s*=\s*_DIRECTION"` returns 2; both call sites use the same `_DIRECTION = "lower_is_better"` constant).

## Next Phase Readiness

- AgedVulnsAssetsModule slots into the existing `board_summary` ReportComposer pipeline without any changes to `board_summary.py` or `composer.py` — the bundle-driven dispatch from Plan 03-01 picks up `email_gauge_b64`, `analyst_rows`, and `rag_strip` automatically.
- All four board modules (scan_coverage_sla, critical_remediation_sla, high_risk_assets, aged_vulns_assets) are now migrated to the Phase 3 four-channel contract. Wave 2 of Phase 3 is complete.
- Plan 03-06 (Wave 3) owns the regression-test extension to assert on the new contract fields and the joined-cell determinism (alphabetical for contributing_plugins; numeric-first/lexical-fallback for contributing_finding_ids in 03-04).
- The Phase 2 regression test (`tests/test_phase2_composer_pipeline.py`) still passes 7/7 against the migrated module.

---
*Phase: 03-board-summary-module-migration*
*Completed: 2026-05-06*

## Self-Check: PASSED

- File `reports/modules/aged_vulns_assets_module.py` exists and parses (`ast.parse` returns OK).
- File `.planning/phases/03-board-summary-module-migration/03-05-SUMMARY.md` exists.
- Both task commits exist on main (`8d4fdb9` Task 1, `ef049e2` Task 2). Verified via `git log --oneline -5` after each commit.
- Empty-input compute() verify prints `empty-input compute OK`.
- `_worst_severity` helper verify prints `worst_severity helper OK` (critical > high > medium ordering, empty/all-unknown returns "").
- Populated render_email_panel verify prints `populated render OK` (cid:aged_vulns_assets_gauge + 2.7% + driver text present).
- Empty render_email_panel verify prints `empty render OK` (no cid, em-dash headline, 620px shell).
- lower_is_better classifier verify prints `lower_is_better classifier OK` (1.0→green, 3.0→yellow, 7.0→red).
- W6 last_seen-merge wiring verify prints `W6 last_seen-merge wiring OK`.
- End-to-end populated compute() smoke test prints `END-TO-END populated compute OK` (verifies analyst tab with 6 columns; alphabetical contributing_plugins; correct worst_severity per asset; gauge base64 populated).
- Phase 2 regression test (`tests/test_phase2_composer_pipeline.py`) passes 7/7.
- All Task 1 and Task 2 acceptance grep counts match the plan's specification (Aged Vulns Detail=1, contributing_plugins=4, worst_severity=5, def _worst_severity=1, direction=_DIRECTION=2, email_gauge_b64=5, driver_narrative==2, analyst_rows==2, rag_strip==2, deduplicate_assets_by_name=5, sorted({=1, def render_email_panel=1, def _render_empty_email_panel=1, def render_analyst_tabs=1, def render_rag_strip_entry=0, width:620px=2, html.escape=6, "No data in scope"=1).
