---
phase: quick-260722-lx9
plan: 01
status: complete
subsystem: reporting-modules
tags: [pandas, board-summary, management-summary, composed-report, kpi-modules, accepted-recast]
requires: []
provides: [QUICK-260722-lx9]
affects:
  - reports/modules/board_report_utils.py
  - reports/modules/__init__.py
  - reports/modules/high_risk_assets_module.py
  - reports/modules/aged_vulns_assets_module.py
  - reports/modules/critical_remediation_sla_module.py
  - reports/board_summary.py
  - docs/board_summary_calculations.md
  - CLAUDE.md
tech-stack:
  added: []
  patterns:
    - "exclude_risk_managed(df) shared helper in board_report_utils.py — the single point of exclusion for ACCEPTED/RECASTED findings, applied at the top of compute() (or right after a fixed_vulns_df kwarg fetch)"
key-files:
  created:
    - tests/test_board_report_utils.py
    - tests/test_kpi_risk_managed_exclusion.py
    - tests/test_board_accepted_recast.py
  modified:
    - reports/modules/board_report_utils.py
    - reports/modules/__init__.py
    - reports/modules/high_risk_assets_module.py
    - reports/modules/aged_vulns_assets_module.py
    - reports/modules/critical_remediation_sla_module.py
    - reports/board_summary.py
    - tests/test_phase6_board_summary_chrome.py
    - docs/board_summary_calculations.md
    - CLAUDE.md
decisions:
  - "exclude_risk_managed() applied unconditionally inside compute() (not gated by a module option) — approved by the operator as the intended correctness fix, per plan objective."
  - "accepted_recast module deliberately exempted from exclude_risk_managed() since risk-managed findings are exactly its subject matter."
  - "recast_rules_df is not tag-scoped in board_summary.py (mirrors management_summary) because fetch_recast_rules() returns no asset_uuid column."
  - "Board structural baselines (board_summary_test_pull*.json) captured from real Tenable data are NOT edited/regenerated in this task (Hard Rule 1) — flagged for operator regeneration below."
metrics:
  duration_seconds: 2118
  completed: 2026-07-22
requirements: [QUICK-260722-lx9]
---

# Phase quick-260722-lx9 Plan 01: Exclude accepted/recast findings from KPI modules + wire Accepted/Recast-by-Owner into board_summary Summary

Excludes risk-accepted and severity-recast open findings from three KPI modules' metrics (`high_risk_assets`, `aged_vulns_assets`, `critical_remediation_sla`), via a new shared `exclude_risk_managed()` helper, and wires the existing `accepted_recast` module into the `board_summary` bundle as its 5th board metric (previously `management_summary`-only), with its own local trend read and fail-soft recast-rules fetch.

## What Was Done

### Task 1 — `exclude_risk_managed()` shared helper + unit tests (commit e3fef65)
- Added `reports/modules/board_report_utils.py::exclude_risk_managed(df)`: drops rows whose `severity_modification_type` (case-insensitive) is `ACCEPTED` or `RECASTED`; empty-df and missing-column guarded (returns `df` unchanged, no error); otherwise returns a fresh `.copy()` (Hard Rule 5, no `ChainedAssignmentError` under pandas CoW strict mode).
- Re-exported from `reports/modules/__init__.py` alongside the existing `populate_rag_strip` re-export.
- `tests/test_board_report_utils.py`: covers empty input, missing-column, ACCEPTED/RECASTED exclusion, case-insensitivity, other-values-kept, and copy-semantics.

### Task 2 — Apply the filter in the three KPI modules + per-module tests (commit dbc50b9)
- `high_risk_assets_module.py`, `aged_vulns_assets_module.py`: `vulns_df = exclude_risk_managed(vulns_df)` as the first statement inside `compute()`'s `try` block, so the filtered frame flows through all downstream on-time/aged/high-risk logic.
- `critical_remediation_sla_module.py`: `fixed_vulns_df = exclude_risk_managed(fixed_vulns_df)` immediately after the `kwargs.get("fixed_vulns_df", ...)` fetch. Removed the now-redundant local WR-03 exclusion block on the "missed SLA" slice (three lines: `if "severity_modification_type" in missed.columns: ...`), replacing it with a one-line comment noting the exclusion now happens upstream. The WR-03 explanatory comment block above it was preserved.
- `tests/test_kpi_risk_managed_exclusion.py`: for each of the three modules, builds a synthetic fixture where a subset of qualifying findings carry ACCEPTED/RECASTED, and asserts the headline metric equals the value computed without those rows. Includes a sanity check that non-risk-managed rows still qualify, and a zero-qualifying-assets path (see Deviations).

### Task 3 — Wire `accepted_recast` into `board_summary` + integration test + chrome harness fix (commit 2ffe785)
- `reports/board_summary.py`:
  - Added `ModuleConfig("accepted_recast")` to `_BOARD_MODULE_CONFIGS` (5th board metric).
  - Added top import `from data.trend_store import read_trend`.
  - Derived `tag_filter_label` (`"all_assets"` or `f"{tag_category}_{tag_value}"`) inside the existing tag-filter branch, mirroring `management_summary`.
  - Added a local trend read (`read_trend("severity", tag_filter_label, months=13)`) after the fetch/tag-scoping block — reads the local trend store, not Tenable (Hard Rule 1 safe).
  - Added a deferred fail-soft recast-rules fetch mirroring `management_summary`'s INT-WARN-2 pattern (`recast_rules_df = None`; `try`/`except` around `fetch_recast_rules(tio, cache_dir)`; non-fatal on failure).
  - `recast_rules_df` is intentionally **not** tag-scoped (no `asset_uuid` column in its schema) — comment added at the fetch site, consistent with `management_summary`.
  - Forwarded `trend_snapshots=trend_snapshots` and `recast_rules_df=recast_rules_df` into the `ReportComposer(...)` construction.
  - Updated the file's own module docstring/comments from "four" to "five" board metrics (directly stale after this change, same file being edited).
- `tests/test_board_accepted_recast.py`: asserts `accepted_recast` is present in `_BOARD_MODULE_CONFIGS`, and that running its `compute()` with synthetic board-style fixtures (vulns/assets/recast_rules/trend) produces all four channels — non-empty `render_pdf_section`, at least one analyst/excel tab, and a populated (non "No Data") RAG strip entry.
- `tests/test_phase6_board_summary_chrome.py`: added `patch.object(bs, "read_trend", return_value={"snapshots": [], "insufficient_data": True})` to the hermetic chrome-wiring test harness so it doesn't touch the local trend store; all 8 pre-existing chrome assertions still pass. The deferred `fetch_recast_rules` needed no patch — no `TVM_ACCESS_KEY`/`TVM_SECRET_KEY` env vars are set in this environment, so it safely short-circuits to an empty DataFrame without any network call.

### Task 4 — Regression check (no code changes required)
- Ran the full suite (`python -m pytest tests/`) before and after Tasks 1–3; the only failures are 6 pre-existing, unrelated failures (confirmed identical on the pre-task baseline commit — see Deviations/Deferred below).
- Root-caused why no `management_summary`/`composed_report` golden values shifted:
  - `management_summary`'s 7 modules are `total_vulns_by_severity`, `scan_coverage_sla`, `mttr_trend`, `patch_compliance_rate`, `aged_vulns_assets`, `accepted_recast`, `new_vs_remediated` — `high_risk_assets` and `critical_remediation_sla` are **not** in that list, so their exclusion cannot affect `management_summary`'s golden values.
  - The one shared module, `aged_vulns_assets` (M5), is bucketed `documented_difference` in `tests/baselines/management_summary_value_golden.json` (different unit/denominator vs. the bespoke age-bucket histogram) — it has **no exact-match assertion**, so a metric-value shift there does not fail the parity gate.
  - The `management_summary_parity` fixture's `vulns_df.parquet` **does** contain 5 ACCEPTED + 5 RECASTED rows (of 71 total open), but its `fixed_vulns_df.parquet` has **no** `severity_modification_type` column at all, so `exclude_risk_managed(fixed_vulns_df)` is a no-op there (missing-column guard) — `critical_remediation_sla` isn't in `management_summary` anyway, so this is moot for that fixture but confirms the guard behaves correctly.
  - `test_composed_report_*.py` references `critical_remediation_sla`/`high_risk_assets`/`aged_vulns_assets` only by module ID for kwargs-gating assertions (e.g. "does this module trigger a fixed-vulns fetch"), not by asserted numeric value.
- **Board structural baselines** (`tests/baselines/board_summary_test_pull.json`, `board_summary_test_pull_analyst_off.json`, `board_summary_test_pull_zero_match.json`) were captured from real Tenable-exported parquet and were **not edited**. `test_board_summary_baseline.py` still passes because its zero-match synthetic rebuild (`_build_zero_match_bundle_synthetic()` in `tests/test_board_summary_baseline.py`) uses its own hardcoded 4-module list independent of `board_summary.py`'s live `_BOARD_MODULE_CONFIGS`, so it never exercises the new 5th module — see the **OPERATOR FLAG** below.

### Task 5 — Docs (commit c9764bf)
- `docs/board_summary_calculations.md`:
  - New "Metric 5 — Accepted/Recast by Owner" section (formula, expired-rule cross-check, Owner cut via `extract_owner()`, MoM cold-start behavior per Hard Rule 7, RAG thresholds, values reported, edge cases) at the same depth as the existing four metric sections.
  - New "Exclusion of risk-managed findings" subsection in Section 2 (Shared Baseline) explaining `scan_coverage_sla` is unaffected (assets-only), `high_risk_assets`/`aged_vulns_assets`/`critical_remediation_sla` now exclude ACCEPTED/RECASTED via `exclude_risk_managed()`, and `accepted_recast` intentionally does not apply that filter.
  - Updated the Data Sources table (added recast rules + local trend snapshots, Metric-5-only) and the Table of Contents; renumbered "Data-Quality Notes" from Section 10 to 11.
- `CLAUDE.md`: `board_summary` slug-index row Notes cell updated from "4 board KPIs; modules-based." to "5 board metrics; modules-based. Incl. Accepted/Recast-by-Owner." — single-cell surgical edit.

## OPERATOR FLAG — board_summary structural baseline regeneration required

`tests/baselines/board_summary_test_pull.json`, `board_summary_test_pull_analyst_off.json`, and `board_summary_test_pull_zero_match.json` were captured from a real, warmed-parquet Tenable pull of `board_summary` with the **prior 4-module bundle**. `board_summary` now produces a **5th module page/tab/RAG-strip entry** (`accepted_recast`). These JSON files were **not edited or regenerated** in this task (Hard Rule 1 — no live Tenable pulls from Claude Code). `test_board_summary_baseline.py` remains green because it is a self-consistency/tamper-evidence test whose synthetic zero-match rebuild uses its own fixed 4-module list, not `board_summary.py`'s live module list — it does not exercise the new module.

**Action required:** the operator must regenerate the three `board_summary` structural baselines via `scripts/smoke_board_summary_cutover.py` (or equivalent) against a warmed parquet cache, outside Claude Code, after this change lands. Until then, a live/manual `board_summary` run's structural snapshot will diff against the stale 4-module baselines.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `compute_bu_risk_scores()` empty-series index lacked an "owner" name, crashing on a zero-qualifying-assets result**
- **Found during:** Task 2 (writing `tests/test_kpi_risk_managed_exclusion.py`'s zero-qualifying-assets test cases).
- **Issue:** `reports/modules/board_report_utils.py::compute_bu_risk_scores()` had two early-return paths (`not qualifying_uuids or vulns_df.empty`, and `risk_vulns.empty`) that returned a bare `pd.Series(dtype=int)` with no index name. The caller (`high_risk_assets_module.py` / `aged_vulns_assets_module.py`) does `bu_breakdown.merge(bu_risk.rename("risk_score").reset_index(), on="owner", ...)` — `.reset_index()` on an unnamed-index empty series produces a column named `"index"`, not `"owner"`, so the merge raised `KeyError: 'owner'`. This was latent before this task (rarely hit — needs on-time assets present but zero qualifying high-risk/aged assets, a real but uncommon production shape); the new `exclude_risk_managed()` exclusion makes a "zero qualifying assets" result meaningfully more likely (a scenario that used to have >=1 qualifying asset can now correctly resolve to zero after excluding risk-managed findings), so it's directly reachable via this change.
- **Fix:** Named both empty-series indexes `pd.Index([], name="owner")` so the downstream `.rename("risk_score").reset_index()` always produces an `"owner"` column, matching the shape of the non-empty return path (`bu_asset.groupby("owner")["risk_score"].sum()`, which already has an `"owner"`-named index).
- **Files modified:** `reports/modules/board_report_utils.py`
- **Verification:** `tests/test_kpi_risk_managed_exclusion.py::TestHighRiskAssetsExclusion::test_accepted_recast_rows_do_not_count_toward_threshold` and `::test_non_risk_managed_rows_still_qualify` (and the `aged_vulns_assets` equivalents) exercise this exact zero/non-zero qualifying-assets path and pass. Full `pytest tests/` re-run shows no regression.
- **Committed in:** dbc50b9 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug).
**Impact on plan:** Necessary for correctness — without this fix, the new exclusion filter would make `high_risk_assets`/`aged_vulns_assets` crash (fall back to `_empty_result()`) on any board/management/composed-report run where excluding risk-managed findings drops the qualifying-asset count to zero. No scope creep — single-purpose fix scoped to the exact function the plan's Task 2 already required exercising.

## Issues Encountered

None beyond the auto-fixed bug above.

## Pre-existing test failures (out of scope, unrelated — Rule "Scope Boundary")

Confirmed identical on the pre-task baseline commit (`703c9fb`, before any of this task's changes) and after every task in this plan — not caused by, and not fixed by, this work:

- `tests/unit/test_modules.py::test_four_channel_types[stub_non_string_pdf_f1]`
- `tests/unit/test_modules.py::test_four_channel_types[stub_always_fails_f2]`
- `tests/unit/test_modules.py::test_four_channel_types[_phase2_test_panel_boom]`
- `tests/unit/test_modules.py::test_empty_data_guard[stub_always_fails_f2]`
- `tests/unit/test_modules.py::test_empty_data_guard[_phase2_test_panel_boom]`
- `tests/e2e/test_groups.py::test_group_runs_fail_soft_and_artifacts_valid[Remediation Team]`

The `test_modules.py` failures are test-registry pollution from `tests/test_phase2_composer_pipeline.py` (a script-style test file with `if __name__ == "__main__"`/argparse that also gets pytest-collected, registering stub modules with side effects that leak into `tests/unit/test_modules.py`'s dynamic module-registry iteration when the full suite runs together). The `test_groups.py` failure is a pre-existing `KeyError: 'asset_id'` in `reports/patch_compliance.py`/`reports/sla_remediation.py` (`df["asset_id"]` — unrelated bespoke-report code, not touched by this plan). Left unfixed per the deviation-rules scope boundary ("Only auto-fix issues DIRECTLY caused by the current task's changes").

## Verification

- Task 1: `python -m pytest tests/test_board_report_utils.py -x -q` → 6 passed. `python -c "from reports.modules import exclude_risk_managed"` → import OK.
- Task 2: `python -m pytest tests/test_kpi_risk_managed_exclusion.py -x -q` → 5 passed. `grep -l exclude_risk_managed` on all three modules → 3/3. No `isin(["accepted", "recasted"])` remains in `critical_remediation_sla_module.py`.
- Task 3: `python -m pytest tests/test_board_accepted_recast.py tests/test_phase6_board_summary_chrome.py -x -q` → 12 passed. `grep` confirms `ModuleConfig("accepted_recast")`, `recast_rules_df`, `trend_snapshots` all present in `reports/board_summary.py`.
- Task 4: `python -m pytest tests/ -q` (full suite) → same 6 pre-existing failures as the pre-task baseline, no new failures. `tests/test_management_summary.py` (17 tests) and `tests/test_composed_report_*.py` (10 tests) and `tests/test_board_summary_baseline.py` (part of 26 combined with `test_management_summary.py`) all green.
- Task 5: `grep -qi "accepted/recast\|accepted_recast" docs/board_summary_calculations.md`, `grep -qi "exclude_risk_managed\|risk-managed" docs/board_summary_calculations.md`, `grep -q "5 board" CLAUDE.md` → all pass.
- Hard Rule 1: no live Tenable pulls attempted anywhere — all tests use synthetic fixtures (`00000000-...` UUIDs); `read_trend()` reads the local `data/trend/` store; `fetch_recast_rules()` fail-soft short-circuits with no credentials set; `run_all.py --dry-run` runs clean (no delivery groups configured in this worktree, as expected — `delivery_config.yaml` is gitignored).
- Hard Rule 2: all new fixtures use synthetic `00000000-0000-0000-0000-00000000000N` UUIDs, `plugin_id` 100001+, and non-real owner names ("Engineering", "Operations").
- Hard Rule 5: `exclude_risk_managed()` and its callers use `.copy()`/`.assign()`; CoW strict mode enforced at every new test file's module level; no `ChainedAssignmentError` observed.
- Hard Rule 6: `exclude_risk_managed()` guards empty df and missing column.
- Hard Rule 8: zero new dependencies (checked `requirements.txt` untouched).

## Known Stubs

None.

## Threat Flags

None — this task filters existing rows and wires an already-registered, already-tested module into an existing bundle; no new network endpoints, auth paths, file-access patterns, or schema changes at a trust boundary were introduced.

## Self-Check: PASSED

- Files: all 12 created/modified files present on disk (`reports/modules/board_report_utils.py`, `reports/modules/__init__.py`, `tests/test_board_report_utils.py`, `reports/modules/high_risk_assets_module.py`, `reports/modules/aged_vulns_assets_module.py`, `reports/modules/critical_remediation_sla_module.py`, `tests/test_kpi_risk_managed_exclusion.py`, `reports/board_summary.py`, `tests/test_board_accepted_recast.py`, `tests/test_phase6_board_summary_chrome.py`, `docs/board_summary_calculations.md`, `CLAUDE.md`).
- Commits: `e3fef65` (Task 1), `dbc50b9` (Task 2), `2ffe785` (Task 3), `c9764bf` (Task 5) all present in `git log`.
