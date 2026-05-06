---
phase: 03-board-summary-module-migration
plan: 03-04
subsystem: modules/high_risk_assets
tags: [module, board-metric, high-risk-assets, render-email-panel, render-analyst-tabs, lower-is-better, joined-cell]

# Dependency graph
requires:
  - plan: 03-01
    provides: populate_rag_strip helper, build_rag_strip_entry, rag_status_from_value, NO_DATA_DRIVER, NO_DATA_HEADLINE, STATUS_*, email_inline_images bundle key
provides:
  - HighRiskAssetsModule with full Phase 3 four-channel contract (compute fields + render_email_panel + render_analyst_tabs + Excel zero-row)
  - Asset-level analyst rows with deterministic comma-joined contributing_finding_ids cell
  - lower_is_better RAG-strip wiring (T-03-04-03 — direction explicitly passed, never defaulted)
affects:
  - reports/board_summary.py (no changes; the migrated module slots into the existing board pipeline)
  - .planning/phases/03-board-summary-module-migration/03-06-PLAN.md (regression-test extension owner)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Locked option-2 pure-construction shape (rag_strip dict + driver narrative + analyst_rows + email_gauge_b64 computed BEFORE ModuleData(...) and passed in directly — matches Plan 03-02's locked shape; no post-construction mutation)"
    - "Joined-cell determinism: contributing_finding_ids built via sorted(set(int_ids)) so ascending numeric order is guaranteed; lexical fallback via sorted(set(map(str, ...))) for non-int IDs"
    - "W6 last_seen-merge resolution — real last_seen is projected from assets_df and joined onto the per-asset frame BEFORE deduplicate_assets_by_name; pd.NaT placeholder appears only inside a defensive logger.warning fallback"
    - "T-03-04-03 mitigation in code — `rag_status_from_value(direction=_DIRECTION)` where _DIRECTION = 'lower_is_better' (the call site is explicit; no implicit default that could regress to higher_is_better)"

key-files:
  created: []
  modified:
    - reports/modules/high_risk_assets_module.py — added html, format_utils, rag_utils, deduplicate_assets_by_name imports; extended _find_high_risk_assets to also return aged-findings frame; populated three new ModuleData contract fields (analyst_rows / driver_narrative / rag_strip) + email_gauge_b64 metadata key in both populated and no-data paths; added render_email_panel + _render_empty_email_panel + render_analyst_tabs methods; added D-16 Excel zero-row standardisation; defensive guard on `on_time['asset_uuid']` lookup so empty assets_df routes through the no_data early-return

key-decisions:
  - "Locked driver-narrative template: `f\"{count} assets crossed the high-risk threshold (>={_HIGH_RISK_COUNT} Crit/High open >{_AGED_DAYS_THRESHOLD}d); worst BU: {worst_bu_name} with {worst_bu_count} assets.\"` — verbatim copy of the plan's Step A2b spec. NO_DATA_DRIVER fallback when high_risk_count == 0 OR analyst_rows is empty."
  - "Direction = lower_is_better (T-03-04-03 explicit-pass mitigation): `rag_status_from_value(direction=_DIRECTION)` is the single call site; _DIRECTION is the module-level constant 'lower_is_better' (line 53). The acceptance grep `direction\\s*=\\s*_DIRECTION` returns 2 matches (the new compute() block + a pre-existing call in step 4 of the existing compute()). Both are intentional; T-03-04-03 requires the new compute() block to never default — verified."
  - "contributing_finding_ids deterministic comma-join order: ascending numeric via `sorted(set(int_ids))` where int_ids is `[int(v) for v in unique_vals]`. The `sorted(set(...))` literal appears in the join helper (twice: numeric path + lexical fallback) so the deterministic-sort acceptance grep matches. Fallback path applies when plugin IDs cannot be coerced to int (defensive — Tenable plugin IDs are integers in observed data)."
  - "D-13 — explicit asset-level dedup decision via `deduplicate_assets_by_name`. Source data is finding-level (one row per Crit/High open >30d finding). compute() groups by asset_uuid first (producing crit_high_open_count + contributing_finding_ids per asset), then dedups by hostname using the helper. The dedup keeps the most-recent-`last_seen` row when duplicate hostnames exist."
  - "W6 last_seen-merge resolution: `assets_df` already carries `last_seen` (verified via `data/fetchers.py:525` and `1161/1202`). compute() projects `(asset_uuid, hostname, business_unit, last_seen)` from `assets_df`, merges onto the per-asset grouped frame, then calls `deduplicate_assets_by_name`. The helper's signature is unchanged — only the caller is fixed. Defensive `.assign(last_seen=pd.NaT)` lives ONLY inside a `logger.warning` fallback path that fires when assets_df does not carry the column (which never happens in production today)."
  - "Excel zero-row regression diff (D-16): pre-Phase-3 the empty High-Risk Assets module wrote a sheet with the KPI block populated by None values + an empty BU breakdown table — the sheet was structurally non-empty but content-empty. Post-Phase-3 the same input produces a single `'No data in scope'` cell at A1 with no other content. Live-Tenable Excel diff regression handed off to Plan 03-06."
  - "Pre-existing `on_time['asset_uuid']` KeyError on empty assets_df is now defensively guarded: when the column is absent, `on_time_uuids = set()` and `total_on_time = len(on_time)` is 0, which routes through the no-data early-return path. This was a Rule 1 bug fix required for the plan's own verify command to pass (which constructs `pd.DataFrame()` with no columns)."

patterns-established:
  - "Joined-cell builder pattern: a per-group _join_ids closure that (a) collects unique values via `set(s.dropna().tolist())`, (b) tries an ascending numeric sort via `sorted(set(int_ids))`, (c) falls back to lexical via `sorted(set(map(str, unique_vals)))`. Plan 03-05 (Aged Vulns Assets) will copy this pattern for its `contributing_plugins` cell."
  - "lower_is_better module migration shape (Plan 03-04 + 03-05 share this): every `rag_status_from_value` / `populate_rag_strip` / threshold helper call inside compute() passes `direction=_DIRECTION` explicitly so the lower-is-better classifier never defaults to higher_is_better."

requirements-completed: [BOARD-03, QUALITY-02]

# Metrics
duration: ~9min
completed: 2026-05-06
---

# Phase 3 Plan 03-04: High-Risk Assets Module Migration Summary

**HighRiskAssetsModule fully migrated to the Phase 3 four-channel contract — compute() populates rag_strip / driver_narrative / analyst_rows / email_gauge_b64 with the lower_is_better direction explicitly passed (T-03-04-03), the analyst tab carries asset-level rows with deterministic comma-joined contributing_finding_ids, render_email_panel emits the 620px horizontal-split panel with a CID gauge, and render_excel_tabs emits a 1-row "No data in scope" sheet on empty input.**

## Performance

- **Duration:** ~9 minutes (518s wall-clock)
- **Started:** 2026-05-06T16:36:14Z
- **Completed:** 2026-05-06T16:44:52Z (approx)
- **Tasks:** 2 (both autonomous; Task 2 was tdd="true")
- **Files modified:** 1 (`reports/modules/high_risk_assets_module.py`)

## Accomplishments

- **compute() populates the three Phase 3 ModuleData fields** (driver_narrative / analyst_rows / rag_strip) on both the populated path and the no-data early-return path. The `email_gauge_b64` metadata key is also set on both paths so `composer.collect_email_inline_images` picks the gauge up.
- **`_find_high_risk_assets` extended** to also return the aged-findings DataFrame (the `relevant[aged_mask]` slice) so compute() can produce per-asset contributing_finding_ids without re-deriving the filter. Signature change is internal only — no other module imports this helper.
- **Asset-level analyst rows with deterministic comma-joined `contributing_finding_ids`**:
  - Sheet name: `"High-Risk Assets Detail"` (24 chars, ≤31)
  - Columns (per D-10): `hostname, business_unit, crit_high_open_count, contributing_finding_ids`
  - Sort: `crit_high_open_count` desc (D-11)
  - D-13 — apply asset-level dedup via `deduplicate_assets_by_name` AFTER projecting real `last_seen` from `assets_df` (W6 — duplicate-hostname tiebreak deterministic)
  - T-03-04-02 — CSV-formula injection guard on text columns (`hostname`, `business_unit`, `contributing_finding_ids`)
- **Locked driver-narrative template** (D-06) — verbatim per the plan:
  ```
  f"{count} assets crossed the high-risk threshold (>={_HIGH_RISK_COUNT}
  Crit/High open >{_AGED_DAYS_THRESHOLD}d); worst BU: {worst_bu_name}
  with {worst_bu_count} assets."
  ```
  NO_DATA_DRIVER fallback when no high-risk assets are found.
- **lower_is_better direction is explicitly passed** (T-03-04-03) — `rag_status_from_value(direction=_DIRECTION)` where `_DIRECTION = "lower_is_better"`. Verified by both grep (`direction\\s*=\\s*_DIRECTION` returns 2 matches) and runtime classifier check (0.4 → green, 1.5 → red).
- **render_email_panel** produces the 620px horizontal-split table with `cid:high_risk_assets_gauge` on populated input. Empty-data path delegates to `_render_empty_email_panel` which emits the gray "No data" placeholder (no `<img>`, em-dash headline, NO_DATA_DRIVER text). All interpolated strings are `html.escape`-d (T-03-04-01).
- **render_analyst_tabs** returns `data.analyst_rows` (single-element list `[("High-Risk Assets Detail", df)]`) on populated input or `[]` on empty.
- **render_excel_tabs zero-row standardisation (D-16)** — emits a single bold-gray `"No data in scope"` cell at A1 when both `data.metrics` and `data.table_data` are empty AND `data.error` is None. Pre-existing populated path preserved.
- **render_rag_strip_entry NOT overridden** — inherits the BaseModule default which honors `data.rag_strip` populated by `compute()`. Verified by `grep -c "def render_rag_strip_entry"` returning 0.
- **[Rule 1] Defensive guard on `on_time['asset_uuid']`** — `pd.DataFrame()` with no columns now routes through the no_data early-return path instead of raising KeyError into `_empty_result`.

## Task Commits

Each task was committed atomically:

1. **Task 1: Populate Phase 3 ModuleData fields in compute()** — `24a9c63` (feat)
2. **Task 2: render_email_panel + render_analyst_tabs + Excel zero-row standardisation** — `5a89e4d` (feat)

## Files Created/Modified

- `reports/modules/high_risk_assets_module.py`:
  - Added `import html`, plus imports from `format_utils` (`safe_int`, `safe_pct`), `rag_utils` (`NO_DATA_DRIVER`, `NO_DATA_HEADLINE`, `STATUS_COLOR as _RAG_STATUS_COLOR`, `STATUS_ICON`, `STATUS_LABEL as _RAG_STATUS_LABEL`, `build_rag_strip_entry`, `rag_status_from_value`), and `deduplicate_assets_by_name` from `board_report_utils`.
  - Extended `_find_high_risk_assets` signature from `tuple[set, pd.Series]` to `tuple[set, pd.Series, pd.DataFrame]`. Returns the aged-findings frame as the third element so compute() can build the contributing_finding_ids cell without re-deriving the filter.
  - Updated the existing call site in compute() to unpack the new third return value.
  - Added defensive guard on `on_time['asset_uuid']` lookup so empty assets_df → `on_time_uuids = set()` and the no_data early-return path wins (Rule 1 fix).
  - Updated the no-data early-return path (`total_on_time == 0`) to populate the three new contract fields and the empty `email_gauge_b64`.
  - Added the analyst rows / driver narrative / email gauge / rag_strip blocks BEFORE the existing populated-path `return ModuleData(...)`.
  - Updated the populated `return ModuleData(...)` to include the three new contract fields and the populated `email_gauge_b64` metadata key.
  - Inserted D-16 Excel zero-row standardisation at the TOP of `render_excel_tabs` body.
  - Added `render_email_panel` + `_render_empty_email_panel` + `render_analyst_tabs` methods AFTER `render_email_kpis` and BEFORE `get_audit_info`.
  - **Net diff:** +210 / -14 (Task 1) + +138 / -0 (Task 2) = +348 / -14 lines.

## Decisions Made

- **Driver narrative template.** Verbatim copy of the plan's locked Step A2b template. The `worst_bu_name` is derived from the analyst DataFrame (`groupby("business_unit").size()`) rather than from `bu_breakdown` because the analyst frame is already the high-risk subset; reusing it avoids a second filter pass. Empty BU values fall back to `"Untagged"`.
- **lower_is_better direction explicitly passed.** `rag_status_from_value(direction=_DIRECTION)` is hardcoded inline rather than relying on a default. T-03-04-03 mitigation. The acceptance grep `direction\s*=\s*_DIRECTION` returns 2 matches: the pre-existing call in compute() step 4 (`sla_status_from_thresholds(..., direction=_DIRECTION)`) AND the new Phase 3 rag_strip block. Both are correct.
- **Joined-cell deterministic order.** `sorted(set(int_ids))` where `int_ids = [int(v) for v in unique_vals]`. The `sorted(set(...))` literal appears twice (numeric path + lexical fallback) so the determinism-sort acceptance grep matches. Lexical fallback via `sorted(set(map(str, unique_vals)))` is for the rare case where plugin IDs cannot be coerced to int (Tenable plugin IDs are always integers in observed data, so the fallback path is defensive only).
- **D-13 asset-level dedup via `deduplicate_assets_by_name`.** The dedup is applied AFTER the per-asset groupby so each row is already one asset; the helper's hostname-tiebreak by most-recent `last_seen` resolves duplicates deterministically. **W6 resolution** — real `last_seen` is projected from `assets_df` and merged onto the per-asset frame BEFORE the dedup call so tiebreaks resolve deterministically. The previous `pd.NaT` injection (suggested in pattern A2a Step 1 of the plan's draft template) was a planning-time risk; this plan resolves it at the source rather than passing the issue to the executor. The defensive `.assign(last_seen=pd.NaT)` fallback lives ONLY inside a `logger.warning` path that fires when the upstream `fetch_all_assets()` contract is broken.
- **Excel zero-row standardisation (D-16) regression diff.** Pre-Phase-3: empty input wrote a structurally-populated sheet with the KPI block carrying None values and an empty BU breakdown table. Post-Phase-3: empty input writes a single bold-gray `"No data in scope"` cell at A1 and nothing else. Live-Tenable Excel diff regression handed off to Plan 03-06.
- **Pre-existing `on_time['asset_uuid']` KeyError fixed.** Required for the plan's own empty-input verify command (which constructs `pd.DataFrame()` with no columns). The bug was masked before because `_empty_result` returned a coherent failed-data shape; with the new contract fields the test asserts on `metadata.get('email_gauge_b64') == ''` (which `_empty_result` returns as `None`, breaking the assertion). Defensive `if "asset_uuid" in on_time.columns` guard added.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Defensive guard on `on_time["asset_uuid"]` lookup in compute() Step 1**
- **Found during:** Task 1 (running the empty-input verify command after the new contract fields were added)
- **Issue:** `identify_on_time_assets(empty, ...)` returns an empty DataFrame WITHOUT an `asset_uuid` column. The pre-existing line `on_time_uuids = set(on_time["asset_uuid"].dropna())` raised `KeyError: 'asset_uuid'`, falling through to `_empty_result` which returns `metadata={}`. The plan's verify command asserts `data.metadata.get('email_gauge_b64') == ''` — but `_empty_result` returns `None` for that key, breaking the assertion.
- **Fix:** Wrap the lookup in `if "asset_uuid" in on_time.columns: on_time_uuids = set(on_time["asset_uuid"].dropna()); else: on_time_uuids = set()`. Empty input now correctly routes through the `total_on_time == 0` no_data early-return path which populates the new contract fields per the plan.
- **Files modified:** `reports/modules/high_risk_assets_module.py`
- **Verification:** `python -c "...empty = pd.DataFrame(); ..."` now prints `empty-input compute OK`.
- **Committed in:** `24a9c63` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 bug-class)
**Impact on plan:** Required for the plan's own verify command to pass. No scope creep.

## Issues Encountered

- **Pandas FutureWarnings** (chained assignment) on lines 265, 364, 386 (introduced) and inside `board_report_utils.py:449/454/469` (pre-existing). These are forward-compatibility warnings about pandas 3.0 (the pinned version is 2.2.3). The behavior is correct in the pinned pandas version. The pre-existing pattern in `board_report_utils.py` produces the same warnings — no fix is in scope here. Per the scope-boundary rule, out-of-scope issues are not auto-fixed; the new instances I introduced match the codebase pattern and don't change runtime behavior.
- **The `sorted(set(` literal acceptance grep** required a small refactor of the join helper (I initially wrote `sorted({int(v) for v in unique_vals})` which is logically equivalent but doesn't match the literal grep). Restructured to `sorted(set(int_ids))` to satisfy the acceptance criterion while preserving deterministic numeric order.
- **The `"No data in scope"` acceptance grep** required removing one occurrence of the phrase from a comment so the count matched exactly 1. The string is now in only the `ws["A1"] = "No data in scope"` line; the comment uses "placeholder cell" instead.

## Threat Flags

None — Plan 03-04 introduces no new security-relevant surface beyond what's already documented in the plan's `<threat_model>`. T-03-04-01 (HTML injection in email panel) is mitigated by `html.escape(..., quote=True)` at every interpolation site (verified — `grep -c "html.escape"` returns 7). T-03-04-02 (CSV-formula injection in analyst Excel) is mitigated by the leading-quote escape on `hostname / business_unit / contributing_finding_ids`. T-03-04-03 (RAG misclassification by direction default) is mitigated by `direction=_DIRECTION` being explicitly passed at every classifier call (verified — `grep -cE "direction\s*=\s*_DIRECTION"` returns 2).

## Next Phase Readiness

- HighRiskAssetsModule slots into the existing `board_summary` ReportComposer pipeline without any changes to `board_summary.py` or `composer.py` — the bundle-driven dispatch from Plan 03-01 picks up `email_gauge_b64`, `analyst_rows`, and `rag_strip` automatically.
- Sibling Plan 03-05 (Aged Vulns Assets) shares the lower_is_better module migration shape and the joined-cell helper pattern; this plan's `_join_ids` closure can be copied near-verbatim for `contributing_plugins`.
- Plan 03-06 owns regression-test extension to assert on the new contract fields and the joined-cell determinism. The current `tests/test_phase2_composer_pipeline.py` still passes 7/7 against the migrated module.

---
*Phase: 03-board-summary-module-migration*
*Completed: 2026-05-06*

## Self-Check: PASSED

- File `reports/modules/high_risk_assets_module.py` exists and parses (`ast.parse` returns OK).
- File `.planning/phases/03-board-summary-module-migration/03-04-SUMMARY.md` exists.
- Both task commits exist on the worktree branch (`24a9c63` Task 1, `5a89e4d` Task 2).
- Empty-input compute() verify prints `empty-input compute OK`.
- Populated render_email_panel verify prints `populated render OK`.
- Empty render_email_panel verify prints `empty render OK`.
- lower_is_better classifier verify prints `lower_is_better classifier OK`.
- W6 last_seen-merge wiring verify prints `W6 last_seen-merge wiring OK`.
- Phase 2 regression test (`tests/test_phase2_composer_pipeline.py`) passes 7/7.
- All Task 1 and Task 2 acceptance grep counts match the plan's specification.
