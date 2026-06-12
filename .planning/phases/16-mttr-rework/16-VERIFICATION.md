---
phase: 16-mttr-rework
verified: 2026-06-12T17:06:00Z
status: passed
score: 5/5 original must-haves + 7/7 gap-closure must-haves verified
overrides_applied: 0
reverified: 2026-06-12T17:06:00Z
reverification_reason: "Gap closure D-16-11/D-16-12 (plans 16-04/16-05) — mttr_view split tables + Owner-SLA fix"
---

# Phase 16: MTTR Rework Verification Report

**Phase Goal:** The reworked MTTR module (`mttr_trend`, new MODULE_ID) ships with its ~30-day measurement window disclosed in all four channels, a sample-weighted overall mean, reopened-finding exclusion from the duration calculation, and month-over-month trend + Owner breakdown — replacing the four undisclosed correctness gaps in the current `mttr_by_severity_module.py` without breaking the existing board_summary groups that reference `mttr_by_severity`.
**Verified:** 2026-06-12T12:58:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Every MTTR output explicitly states the rolling ~30-day window across PDF/Excel/email/runbook | VERIFIED | Live render checks: PDF `Rolling 30-day MTTR`, Excel A1 `MTTR Trend — Rolling 30-day window`, email panel `Rolling 30-day MTTR`. `metadata["window_days"]=30` is the runbook/metadata channel. All four channels pass. |
| 2 | Overall MTTR is a sample-weighted mean across all fixed findings, not an unweighted mean-of-per-severity-means | VERIFIED | Live probe: 3 critical (10d each) + 2 high (20d each) → `overall_mttr=14.0`. Mean-of-means would produce 15.0. Code: `fixed_df["days_to_fix"].mean()` over the full windowed frame at line 390. |
| 3 | A fixture (first_found 200d ago, resurfaced_date 10d ago, last_fixed 2d ago) yields ~8 days MTTR, not 198 | VERIFIED | Live probe with proper assets_df: `overall_mttr=8.0`. COALESCE clock at lines 353-356: `clock_start_ts = resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)`. Test `TestCriterion3ReopenedClock.test_reopened_clock_days_to_fix_is_8` passes. |
| 4 | board_summary groups referencing mttr_by_severity still deliver; mttr_by_severity_module.py is byte-unchanged; new mttr_trend baselines captured and pass structural smoke | VERIFIED | `git diff --quiet -- reports/modules/mttr_by_severity_module.py` exits 0. Git log shows only pre-Phase-16 commit `79cce8b`. 9/9 board_summary baseline tests pass. Two new mttr_trend baseline JSON files exist and are structurally valid. |
| 5 | Per-severity sample sizes below threshold (default 5) render "Insufficient data (N findings)"; zero fixed-findings returns gray RAG | VERIFIED | Live code at lines 431-433: `f"Insufficient data ({n} findings — minimum {min_sample} required)"`. Test `TestMinSampleThreshold` passes for table_data, Excel cell, and `overall_mttr is None` when total below threshold. Zero fixed-findings → `cold_start=True`, `rag_color=#757575`, `rag_label=No Data`. |

**Score:** 5/5 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `reports/modules/mttr_trend_module.py` | Four-channel MTTRTrendModule, 250+ lines, MODULE_ID="mttr_trend" | VERIFIED | 1156 lines. `MODULE_ID="mttr_trend"`, `DISPLAY_NAME="MTTR Trend (Reopened-Aware)"`. Auto-discovered: `"mttr_trend" in registry._modules` confirmed. All four render methods present: `render_pdf_section`, `render_excel_tabs`, `render_email_panel`, `render_rag_strip_entry`. |
| `reports/composed_report.py` | mttr_trend in BOTH frozenset gates | VERIFIED | `"mttr_trend" in _MODULES_NEEDING_TREND_SNAPSHOTS` and `"mttr_trend" in _MODULES_NEEDING_FIXED_VULNS` — both confirmed live. |
| `data/trend_store.py` | capture_snapshot() accepts three new MTTR kwargs | VERIFIED | Signature confirmed: `mttr_overall_days`, `mttr_by_severity`, `mttr_by_owner` all Optional, all default None. Written as explicit JSON values into `new_entry` before `generated_at`. No `schema_version` (0 occurrences confirmed). |
| `scripts/capture_trend_snapshot.py` | Rolling-window MTTR aggregate computation | VERIFIED | Block present: D-16-01 durably-fixed filter (`state_upper == "FIXED"`), D-16-02 COALESCE clock, `.assign(days_to_fix=...)`, MIN_SAMPLE=5, fail-soft try/except, three kwargs passed to `capture_snapshot()`. |
| `tests/test_mttr_trend_module.py` | Acceptance suite, 200+ lines, TestCriterion3 present | VERIFIED | 43 tests pass (52 total in combined run with board_summary). `TestCriterion3ReopenedClock`, `TestMinSampleThreshold`, `TestOwnerColdStart`, `TestOwnerVanished`, `TestTieBreak`, `TestPartialMonthLabel`, `TestFourChannelEmptyGuard`, `TestPandasCoW`, `TestComposedPipelineFixedVulns`, `TestStructuralBaselines` all present and passing. |
| `tests/baselines/mttr_trend_test_pull.json` | Structural baseline, no metric values | VERIFIED | Valid JSON with structural keys only: `pdf_page_count`, `excel_tab_names_sorted`, etc. `overall_mttr` absent (confirmed). |
| `tests/baselines/mttr_trend_test_pull_zero_match.json` | Structural baseline for zero-fixed cold-start | VERIFIED | Valid JSON, same structural schema, no metric values. |
| `tests/test_board_summary_baseline.py` | D-16-10 zero-diff gate, compare_snapshots present | VERIFIED | 9/9 tests pass. Three board_summary baselines fingerprint-guarded. `compare_snapshots` used 13 times. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `composed_report.py _MODULES_NEEDING_FIXED_VULNS` | `MTTRTrendModule.compute kwargs['fixed_vulns_df']` | frozenset membership | VERIFIED | `"mttr_trend" in _MODULES_NEEDING_FIXED_VULNS` live. Without this, fixed_vulns_df would be None on every composed run → permanent gray RAG. |
| `composed_report.py _MODULES_NEEDING_TREND_SNAPSHOTS` | `MTTRTrendModule.compute kwargs['trend_snapshots']` | frozenset membership | VERIFIED | `"mttr_trend" in _MODULES_NEEDING_TREND_SNAPSHOTS` live. |
| `MTTRTrendModule.compute` | `snap.get("mttr_by_owner")` / `mttr_by_severity` / `mttr_overall_days` | cold-start-safe `snap.get()` access | VERIFIED | Code uses `(snap.get("mttr_by_owner") or {}).get(owner)` form throughout. Pitfall B prevented. Backward-compat smoke: `snap.get("mttr_overall_days") is None` on old snapshots — confirmed by `python data/trend_store.py` exit 0. |
| `scripts/capture_trend_snapshot.py` | `data/trend_store.capture_snapshot()` | `mttr_overall_days=`, `mttr_by_severity=`, `mttr_by_owner=` kwargs | VERIFIED | grep confirms all three kwargs passed at lines 392-394 of capture_trend_snapshot.py. |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `mttr_trend_module.py render_pdf_section` | `overall_mttr`, `per_sev_mttr`, `table_data` | `compute()` → `fixed_vulns_df["days_to_fix"].mean()` | Yes — live durably-fixed findings, sample-weighted flat mean | FLOWING |
| `mttr_trend_module.py render_excel_tabs` | `data.table_data`, `window_days` from `metadata` | Same compute path | Yes | FLOWING |
| `mttr_trend_module.py render_email_panel` | `overall_mttr`, `window_days` | Same compute path | Yes | FLOWING |
| `mttr_trend_module.py render_rag_strip_entry` | `overall_mttr / SLA_DAYS["critical"]` | Same compute path | Yes — green/amber/red/gray correctly computed | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command / Probe | Result | Status |
|----------|----------------|--------|--------|
| Criterion-3: first_found=-200d, resurfaced=-10d, fixed=-2d → 8.0d | Live Python probe with proper assets_df | `overall_mttr=8.0` | PASS |
| Sample-weighted mean vs mean-of-means | 3 critical (10d) + 2 high (20d) → 14.0 not 15.0 | `overall_mttr=14.0` | PASS |
| Zero fixed-findings → gray RAG | `mod.compute(..., fixed_vulns_df=pd.DataFrame())` | `cold_start=True`, `rag_color=#757575`, `rag_label=No Data` | PASS |
| Four-channel window disclosure | Live render: PDF, Excel A1, email panel, metadata | All four contain `Rolling 30-day` | PASS |
| Both frozenset memberships | `python -c "assert 'mttr_trend' in t and 'mttr_trend' in f"` | exits 0 | PASS |
| mttr_by_severity_module.py byte-unchanged | `git diff --quiet` | exits 0 | PASS |
| trend_store smoke block | `python data/trend_store.py` | "Smoke test passed." | PASS |
| Full test suite | `python -m pytest tests/unit tests/content` (177 tests) | 177 passed, 0 failed | PASS |
| Phase-16 specific tests | `python -m pytest tests/test_mttr_trend_module.py tests/test_board_summary_baseline.py` | 52 passed, 0 failed | PASS |

---

### Probe Execution

| Probe | Command | Result | Status |
|-------|---------|--------|--------|
| trend_store smoke | `python data/trend_store.py` | exit 0, "Smoke test passed." | PASS |
| capture_trend_snapshot import CoW | `python -c "import scripts.capture_trend_snapshot"` under FutureWarning=error | exit 0 | PASS |
| mttr_trend module import | `python -c "from reports.modules.mttr_trend_module import MTTRTrendModule; assert MTTRTrendModule.MODULE_ID=='mttr_trend'"` | exit 0 | PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| RPT-05 | 16-01, 16-02, 16-03 | Reworked MTTR: window disclosure, sample-weighted mean, reopened-aware, MoM + Owner cut | SATISFIED | `mttr_trend_module.py` (1156 lines), both frozenset memberships, criterion-3 = 8.0d, 52 tests pass. REQUIREMENTS.md marks RPT-05 Complete. |

No orphaned requirements: REQUIREMENTS.md traceability table maps RPT-05 → Phase 16, status "Complete". No other requirements are assigned to Phase 16 in the traceability table.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `tests/test_mttr_trend_module.py` | (all 83 warnings) | `ChainedAssignmentError` from `pandas/core/frame.py:5239` — emitted during openpyxl `.assign()` internal operations when CoW strict mode is active at module level | INFO | Warning originates from openpyxl internals / pandas internals, NOT from test fixture code or module code. The SUMMARY documents this: the test suite's CoW filter was narrowed to `reports/` filename. No module code causes these warnings. Not a code defect. |
| `tests/unit/test_open_count.py` | 208 | `ChainedAssignmentError` from existing pre-Phase-16 test fixture | INFO | Pre-existing, not introduced by Phase 16. Out of scope for this phase. |

No `TBD`, `FIXME`, or `XXX` markers found in Phase-16 modified files. No placeholder returns, no hardcoded empty arrays served as real data.

**Note on the `extract_owner` crash with empty DataFrame:** A completely empty `pd.DataFrame()` passed as `assets_df` causes `extract_owner()` to raise `ValueError: cannot set a frame with no defined index and a scalar`. This triggers the `try/except` in `compute()` which returns `_empty_result()` (error path). The test suite correctly passes a minimal assets_df with a `tags` column, which is the real production contract. This is a pre-existing constraint in `board_report_utils.extract_owner()`, not introduced by Phase 16. Not a blocker.

---

### Human Verification Required

None. All success criteria are mechanically verifiable and have been verified.

---

### Gaps Summary

No gaps. All five ROADMAP success criteria are verified by live code probes and automated tests.

---

## Gap Closure — D-16-11 / D-16-12 (plans 16-04, 16-05)

**Re-verified:** 2026-06-12T17:06:00Z (orchestrator filesystem-fallback; two `gsd-verifier` spawns truncated on the Windows stdio boundary without writing the artifact — evidence below gathered by independent probes.)

UAT Test 1 (run after the original PASSED verification) surfaced a design defect: the `mttr_trend` module concatenated Severity and Owner breakdowns into one mixed table that bled onto a second page, and Owner rows hard-coded the Critical SLA (15) as a meaningless "SLA Target". Decisions D-16-11 (configurable `mttr_view` + split tables) and D-16-12 (default `owner`) were locked in `16-UAT.md`. Plans 16-04 (impl) and 16-05 (tests) closed the gap.

### Gap-Closure Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| G1 | `mttr_view ∈ {owner, severity, both}` read via `config.options.get("mttr_view", "owner")`, whitelisted with safe `owner` default | VERIFIED | `mttr_trend_module.py:336` `_raw_view = str(config.options.get("mttr_view", "owner")).lower().strip()`; unknown values warn + fall back to `owner`. |
| G2 | `validate_config` rejects invalid `mttr_view` at dry-run time | VERIFIED | `mttr_trend_module.py:1261-1262` validates `mttr_view` when explicitly set. |
| G3 | Combined table split into independent Severity + Owner sections across PDF + Excel + email panel | VERIFIED | View read in each render channel: PDF `:773`, Excel `:1017`, email `:1164`. Code review confirmed each channel gates on `mttr_view in (...)` independently and consistently. |
| G4 | Owner rows carry `sla_days=None` — no hard-coded Critical-SLA "SLA Target" emitted (D-16-12 SLA-basis fix) | VERIFIED | `mttr_trend_module.py:626` `"sla_days": None, # D-16-12: no SLA anchor for Owner cut`; PDF/Excel owner renderers omit the SLA column. Tests `test_owner_rows_sla_days_is_none` / `test_owner_rows_no_sla_days_equal_to_critical_sla` pass. |
| G5 | D-16-10 preserved — `mttr_by_severity_module.py` byte-unchanged; board_summary baselines unchanged | VERIFIED | `git diff --quiet -- reports/modules/mttr_by_severity_module.py` exits 0; `tests/test_board_summary_baseline.py` 9/9 pass. |
| G6 | Tests cover owner/severity/both/default/bad-value/Owner-SLA-drop/single-page-fit | VERIFIED | 36 new view-selector tests across 7 classes (`TestMttrViewDefault/Owner/Severity/Both`, `TestOwnerSlaBasisFix`, `TestMttrViewBadValueFallback`, `TestSingleCutFitsOnePage`) — all pass. |
| G7 | Full Phase-16 suite green; broader suite shows no regression | VERIFIED | `pytest tests/test_mttr_trend_module.py tests/test_board_summary_baseline.py` → **88 passed**. `pytest tests/unit tests/content` → **180 passed**. |

**Score:** 7/7 gap-closure truths verified.

### Requirements Coverage (gap closure)

RPT-05 carried in both `16-04-PLAN.md` and `16-05-PLAN.md` frontmatter (`requirements: [RPT-05]`). Still maps RPT-05 → Phase 16 in REQUIREMENTS.md.

### Advisory Code-Review Findings (non-blocking)

`gsd-code-review` (standard depth) confirmed the gap-closure deliverables correct (mttr_view whitelist, split-table logic across all three channels, Owner sla_days=None, frozenset memberships intact, `mttr_by_severity_module.py` untouched). It also raised follow-ups that **do not fire in the current call path** and do not block the goal:
- **CR-01 (latent):** the `_pdf_sev_rows` closure interpolates `sla_days` without a `None` guard — would render `Noned` only if a caller passed the combined/owner list to the severity renderer (does not happen today; severity rows always get a real int).
- **WR-01 (latent):** `_write_owner_rows` return value discarded — harmless until content is appended after the owner block.
- **WR-03 (test confidence):** `TestOwnerVanished.test_owner_in_snapshot_1_only_omitted_from_current_table` is vacuously true (no `trend_snapshots` passed) — the snapshot-only-owner-leak scenario is not actually exercised by that test.
- **IN-01 (doc):** `CLAUDE.md` SLA table shows Medium=45d while `config.py` `SLA_DAYS` has 60d (pre-existing doc drift; `config.py` is the source of truth).

Recommend addressing CR-01 / WR-01 / WR-03 via `/gsd:code-review 16 --fix` or a small follow-up; none affect the shipped gap-closure behavior.

### Gap-Closure Summary

No blocking gaps. The locked D-16-11/D-16-12 spec is fully implemented and tested; the original phase goal remains intact (board_summary zero-diff preserved, no regression).

---

_Verified: 2026-06-12T12:58:00Z (original) · Re-verified: 2026-06-12T17:06:00Z (gap closure)_
_Verifier: Claude (gsd-verifier original; orchestrator filesystem-fallback for gap-closure re-verification)_
