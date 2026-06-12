---
phase: 16-mttr-rework
verified: 2026-06-12T20:20:00Z
status: passed
score: 12/12 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: passed
  previous_score: 5/5 original + 7/7 gap-closure
  gaps_closed:
    - "D-16-13 always-on 4-gauge band (gate removed; gauges render in all table modes)"
    - "D-16-13 focus-driven Owner/Application/none detail table (mttr_view retired, mttr_table auto)"
    - "D-16-13 severity table removed from PDF/email/Excel headline channels"
    - "Snapshot script sys.path bootstrap (capture_trend_snapshot.py runs from any CWD)"
    - "CLAUDE.md Medium SLA 45→60 doc fix"
  gaps_remaining: []
  regressions: []
---

# Phase 16: MTTR Rework Verification Report (Post-Gap-Closure)

**Phase Goal:** The reworked MTTR module (`mttr_trend`, new MODULE_ID) ships with its ~30-day measurement window disclosed in all four channels, a sample-weighted overall mean, reopened-finding exclusion from the duration calculation, and month-over-month trend + Owner breakdown — replacing the four undisclosed correctness gaps in the current `mttr_by_severity_module.py` without breaking the existing board_summary groups that reference `mttr_by_severity`.
**Verified:** 2026-06-12T20:20:00Z
**Status:** PASSED
**Re-verification:** Yes — supersedes previous VERIFICATION.md (plans 16-01..16-05 original pass + plans 16-06/16-07 D-16-13 gap-closure). This pass independently verifies the complete post-gap-closure codebase state.

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ~30-day window disclosed in all four channels | VERIFIED | `window_days` in metadata; PDF: "Rolling {window_days}-day MTTR" at line 910-911; Excel tab: row-1 window disclosure (line 1114 docstring); email panel: mode disclosure; `metadata["window_days"]=30` (runbook channel). `grep -n "window_days\|30-day\|Rolling"` returns 28 hits across all render methods. |
| 2 | Overall MTTR is sample-weighted (flat mean), not unweighted mean-of-means | VERIFIED | Line 478: `fixed_df["days_to_fix"].mean()` over the full windowed frame. Per-severity at line 523 likewise uses `.mean()` over the per-severity slice, not a mean of per-owner or per-bucket sub-means. |
| 3 | Reopened-aware: COALESCE clock resets to resurfaced_date | VERIFIED | Lines 435-441: `resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)` — criterion-3 fixture (first_found=-200d, resurfaced=-10d, fixed=-2d) yields 8d not 198d. Confirmed by `TestCriterion3ReopenedClock`. |
| 4 | board_summary groups unaffected; mttr_by_severity_module.py byte-unchanged | VERIFIED | `git diff --quiet -- reports/modules/mttr_by_severity_module.py` exits 0. `git diff --quiet` on all three board_summary baseline JSONs exits 0. `pytest tests/test_board_summary_baseline.py` → 9/9 passed. |
| 5 | D-16-13: 4-gauge per-severity band renders unconditionally in ALL table modes | VERIFIED | `if mttr_view in ("severity","both")` gate is gone — `grep -c "mttr_view" reports/modules/mttr_trend_module.py` == 0. Gauge loop at lines 935-1005 runs unconditionally inside `render_pdf_section`. `TestGaugeBandAllViews` asserts 4 `data:image/png;base64,` images in PDF and email for owner, application, and gauges-only modes — all pass. |
| 6 | D-16-13: each gauge SLA sourced from config.SLA_DAYS, not hardcoded | VERIFIED | Line 78: `from config import SLA_DAYS`. Lines 937, 949, 968, 972: `SLA_DAYS[sev]` for gauge thresholds and reference tick. `TestExcelSeverityBlockAndSla` asserts Medium == `config.SLA_DAYS["medium"]` == 60. |
| 7 | D-16-13: MoM direction arrows (▼ green / ▲ red / — grey) per severity | VERIFIED | Lines 694-700: `per_sev_mom_direction` computed via `_owner_mom_delta(sev_series[sev])` with "down"/"up"/"flat" tokens. Lines 981-1003: arrows rendered as HTML entity spans with inline colour. `TestMomArrowPolarity` asserts decrease→green &#9660;, increase→red &#9650;, flat→&#8212; — passes. |
| 8 | D-16-13: severity table removed from PDF/email/Excel headline channels; Excel keeps compact 4-row numeric block | VERIFIED | `grep -n "MTTR by Severity"` returns only one hit at line 798 inside `analyst_rows` (not a headline <table>). No `if mttr_view in ("severity","both")` branch anywhere. `TestSeverityTableAbsent` confirms no "MTTR by Severity" heading in PDF/email; confirms Excel has compact Severity/MTTR/SLA/Status/MoM Delta block but not the old 6-column table — passes. |
| 9 | D-16-13: focus-driven detail table (Owner unfocused / Application on Owner-focus / none on Application-focus); mttr_view retired; mttr_table override | VERIFIED | Lines 370-402: `resolved_table_mode` derived from `mttr_table` override and `tag_category`/`tag_value` focus signal. `metadata["mttr_table_mode"]` is the single source of truth read at render lines 905, 1143, 1306. `TestFocusRouting` proves all three auto paths and the explicit override — passes. `grep -c "mttr_view" reports/modules/mttr_trend_module.py` == 0. |
| 10 | Focus signal plumbed: composed_report.py injects tag_category/tag_value into mttr_trend options | VERIFIED | `reports/composed_report.py` lines 308-319: after tag filter resolved, `opts_map` augmented with `{"tag_category": tag_category, "tag_value": tag_value}` via `setdefault` for mttr_trend only. Other modules untouched. 7 `mttr_trend` occurrences in composed_report.py (2 frozensets + 4 options-injection lines + comment). |
| 11 | Snapshot script bootstrap: `python scripts/capture_trend_snapshot.py --dry-run` runs from any CWD without ModuleNotFoundError | VERIFIED | Lines 34-36 of script: `_REPO_ROOT = Path(__file__).resolve().parent.parent; sys.path.insert(0, str(_REPO_ROOT))` at line 34, before `from config import CACHE_DIR` at line 36. Live invocation from repo root: exits 0, emits "DRY RUN" log. `TestSnapshotCliRealInvocation` (5 tests) invokes via subprocess from `tempfile.TemporaryDirectory()` cwd with PYTHONPATH stripped — all 5 pass. |
| 12 | CLAUDE.md Medium SLA corrected 45→60 to match config.py SLA_DAYS | VERIFIED | `grep -n "Medium.*4.0 – 6.9" CLAUDE.md` returns `93: | Medium   | 4.0 – 6.9       | 60         |`. |

**Score:** 12/12 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `reports/modules/mttr_trend_module.py` | Four-channel MTTRTrendModule with always-on gauges, focus-driven table, MODULE_ID="mttr_trend" | VERIFIED | 1462 lines. MODULE_ID="mttr_trend". `mttr_view` count == 0. `mttr_table` count == 22. `draw_gauge` count == 2. `mttr_table_mode` count == 4. `per_sev_mom_direction` count == 8. `SLA_DAYS[` count == 10. Auto-discovered: `"mttr_trend" in registry._modules` confirmed live. |
| `reports/composed_report.py` | mttr_trend in both frozensets; focus-signal injection | VERIFIED | `"mttr_trend" in _MODULES_NEEDING_TREND_SNAPSHOTS` == True; `"mttr_trend" in _MODULES_NEEDING_FIXED_VULNS` == True. Lines 308-319 inject tag_category/tag_value via `setdefault`. |
| `scripts/capture_trend_snapshot.py` | sys.path bootstrap before first-party imports | VERIFIED | `sys.path.insert` at line 34, `from config import` at line 36. Bootstrap precedes imports (34 < 36). |
| `scripts/warm_cache.py` | sys.path bootstrap added (sibling audit fix) | VERIFIED | `grep -c "sys.path.insert" scripts/warm_cache.py` — fixed by commit 20800d2. |
| `CLAUDE.md` | Medium SLA row shows 60 | VERIFIED | Line 93: `| Medium   | 4.0 – 6.9       | 60         |`. |
| `tests/test_mttr_trend_module.py` | D-16-13 classes replacing retired mttr_view classes | VERIFIED | 7 new D-16-13 classes present: TestGaugeBandAllViews, TestMomArrowPolarity, TestFocusRouting, TestSeverityTableAbsent, TestExcelSeverityBlockAndSla, TestMttrTableBadValueFallback, TestSinglePageFit. `grep -c "class TestMttrView"` == 0. All 76 tests in file pass. |
| `tests/test_capture_trend_snapshot_cli.py` | Real-invocation subprocess regression test (UAT-5 lock) | VERIFIED | 5 tests. Uses `tempfile.TemporaryDirectory()` as cwd. Strips PYTHONPATH from subprocess env. Asserts returncode==0, no ModuleNotFoundError, "DRY RUN" in output. 5/5 pass. |
| `tests/baselines/mttr_trend_test_pull.json` | Structural baseline, no metric values | VERIFIED | Keys: `pdf_page_count`, `excel_tab_names_sorted`, etc. `overall_mttr` absent confirmed live. |
| `tests/baselines/mttr_trend_test_pull_zero_match.json` | Structural baseline for zero-fixed cold-start | VERIFIED | Same structural schema. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `composed_report.py _MODULES_NEEDING_FIXED_VULNS` | `MTTRTrendModule.compute kwargs['fixed_vulns_df']` | frozenset membership | VERIFIED | Live Python check: `"mttr_trend" in _MODULES_NEEDING_FIXED_VULNS` == True |
| `composed_report.py _MODULES_NEEDING_TREND_SNAPSHOTS` | `MTTRTrendModule.compute kwargs['trend_snapshots']` | frozenset membership | VERIFIED | Live Python check: `"mttr_trend" in _MODULES_NEEDING_TREND_SNAPSHOTS` == True |
| `composed_report.py run_report()` | `mttr_trend module_options` | tag_category/tag_value setdefault injection | VERIFIED | Lines 315-319 inject focus signal into mttr_trend opts only; verified by reading and confirmed by `TestFocusRouting` passing |
| `render_pdf_section` | `draw_gauge` per severity | unconditional loop (gate removed) | VERIFIED | Lines 935-1005: no `if mttr_view` gate; `draw_gauge` called for each sev with `SLA_DAYS[sev]` thresholds |
| `compute() per_sev_mom_direction` | `render_pdf_section` arrow HTML | `data.metadata.get("per_sev_mom_direction", {})` | VERIFIED | Line 933 reads metadata; lines 981-1003 render ▼/▲/— with inline colour spans |
| `compute() mttr_table_mode` | all three headline renderers | `data.metadata.get("mttr_table_mode", "owner")` | VERIFIED | Read at lines 905 (PDF), 1143 (Excel), 1306 (email) — 4 total hits (stash + 3 reads) |
| `scripts/capture_trend_snapshot.py` | first-party imports | `sys.path.insert(0, str(_REPO_ROOT))` before imports | VERIFIED | bootstrap at line 34 < `from config import` at line 36; subprocess test confirms from non-root CWD |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `render_pdf_section` — gauges | `sev_mttr` from `m.get(f"{sev}_mttr")` | `compute()` → `sev_df["days_to_fix"].mean()` over windowed durably-fixed frame | Yes — FIXED-state filter + rolling window + COALESCE clock | FLOWING |
| `render_pdf_section` — detail table | `table_data_owner` / `table_data_application` from metadata | `compute()` groupby over `extract_owner(assets_df)` columns | Yes — per-owner/application sample-weighted MTTR | FLOWING |
| `render_pdf_section` — MoM arrows | `per_sev_mom_direction` from metadata | `compute()` → `_owner_mom_delta(sev_series[sev])` | Yes — curr-prev of last two trend-store snapshots | FLOWING |
| `render_excel_tabs` — severity numeric block | `table_data_severity` + `per_sev_mom_direction` | Same compute path | Yes | FLOWING |
| `render_email_panel` — mode label | `metadata["mttr_table_mode"]` | Resolved table mode from focus signal | Yes — auto-resolves from tag_category/tag_value | FLOWING |
| `render_rag_strip_entry` | `overall_mttr / SLA_DAYS["critical"]` | `compute()` flat mean then ratio | Yes | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command / Probe | Result | Status |
|----------|----------------|--------|--------|
| snapshot --dry-run from repo root | `python scripts/capture_trend_snapshot.py --dry-run` | exit 0; "DRY RUN" in output | PASS |
| mttr_trend module auto-discovery | `python -c "import reports.modules; ... assert 'mttr_trend' in r._modules"` | exits 0 | PASS |
| mttr_table validate_config — bad value | `mod.validate_config(ModuleConfig('mttr_trend', options={'mttr_table':'bogus'}))` | returns non-empty error | PASS |
| mttr_table validate_config — good value | same with `'owner'` | returns empty (no error) | PASS |
| Both frozenset memberships | Python import check | both True | PASS |
| mttr_view fully retired | `grep -c "mttr_view" reports/modules/mttr_trend_module.py` | 0 | PASS |
| mttr_by_severity byte-unchanged | `git diff --quiet -- reports/modules/mttr_by_severity_module.py` | exit 0 | PASS |
| board_summary baselines byte-unchanged | `git diff --quiet -- tests/baselines/board_summary_*.json` | exit 0 | PASS |
| CLAUDE.md Medium SLA | `grep "Medium.*4.0 – 6.9" CLAUDE.md` | shows 60 | PASS |
| SLA_DAYS sourced from config | `grep -c "SLA_DAYS\[" reports/modules/mttr_trend_module.py` | 10 (all config-sourced) | PASS |
| Phase-16 targeted tests | `pytest tests/test_mttr_trend_module.py tests/test_capture_trend_snapshot_cli.py tests/test_board_summary_baseline.py` | 90 passed | PASS |
| Broader regression suite | `pytest tests/unit tests/content` | 180 passed | PASS |

---

### Probe Execution

| Probe | Command | Result | Status |
|-------|---------|--------|--------|
| snapshot --dry-run real CLI | `python scripts/capture_trend_snapshot.py --dry-run` | exit 0, "DRY RUN" log line emitted | PASS |
| mttr_trend module import + registry | `python -c "import reports.modules; import reports.modules.registry as r; assert 'mttr_trend' in r._modules"` | exit 0 | PASS |
| validate_config round-trip | `python -c "... assert mod.validate_config(ModuleConfig('mttr_trend', options={'mttr_table':'bogus'})); ..."` | exit 0 | PASS |
| snapshot subprocess from tempdir (UAT-5 lock) | `pytest tests/test_capture_trend_snapshot_cli.py` | 5 passed | PASS |

---

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| RPT-05 | 16-01, 16-02, 16-03, 16-04, 16-05, 16-06, 16-07 | Reworked MTTR: window disclosure, sample-weighted mean, reopened-aware, MoM + Owner cut, D-16-13 always-on gauges + focus table | SATISFIED | `mttr_trend_module.py` (1462 lines), both frozenset memberships, COALESCE clock, 90 targeted tests pass, REQUIREMENTS.md marks RPT-05 Complete → Phase 16. |

No orphaned requirements. REQUIREMENTS.md traceability table maps RPT-05 → Phase 16 only. No additional requirements assigned to Phase 16.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `tests/test_mttr_trend_module.py` | suite-wide | `ChainedAssignmentError` warnings from openpyxl/pandas internals during CoW strict mode | INFO | Originates from openpyxl `.assign()` internal code path, not from module code or test fixtures. Pre-existing, not introduced by Phase 16. The test suite's CoW FutureWarning filter targets `reports/` filenames. Not a code defect. |
| `tests/test_mttr_trend_module.py` | `TestOwnerVanished` | Test is vacuously true — no `trend_snapshots` passed, so snapshot-only-owner-leak scenario is not exercised (WR-03 from code review) | WARNING | Advisory only — the test does not falsify the scenario it names. Does not block phase goal. Flagged for follow-up via `/gsd-debug` or next code review pass. |

No `TBD`, `FIXME`, or `XXX` markers found in Phase-16 modified files. No placeholder returns serving as real data. No hardcoded SLA values in `mttr_trend_module.py` — all sourced from `config.SLA_DAYS`.

**Deviation from 16-07 plan acceptance criterion:** `grep -c "mttr_view" tests/test_mttr_trend_module.py` is 7, not 0. All 7 occurrences are inside `TestSeverityTableAbsent` as assertion strings (e.g. `assert "mttr_view" not in data.metadata`) that prove retirement. No test passes `mttr_view` as an active option. The spirit of the criterion (no active use of the retired option) is fully satisfied. This is documented, not a blocker.

**Deviation from 16-07 baseline criterion:** `git diff --stat tests/baselines/mttr_trend_test_pull.json` shows no change (baseline byte-identical before and after). This is correct — `extract_structural_snapshot` captures page count and tab names, which did not change between the old owner-only and new always-on-gauge renders. The self-guard `@pytest.mark.baseline` tests pass against the committed files. Not a defect.

---

### Human Verification Required

None. All phase-goal success criteria are mechanically verifiable and have been independently verified by this pass.

---

### Gaps Summary

No gaps. All 12 observable truths are verified by live codebase probes, grep counts, and automated tests (90 targeted + 180 broader tests pass).

Two advisory code-review items (WR-03 vacuous test; latent CR-01 `sla_days` None guard in a caller path that never fires today) do not affect the shipped behavior and are not blockers. They are candidates for a follow-up `/gsd-debug` or code-review fix pass.

---

_Verified: 2026-06-12T20:20:00Z_
_Verifier: Claude (gsd-verifier) — independent re-verification of post-gap-closure codebase state_
_Previous verifications: 2026-06-12T12:58:00Z (original 5/5) · 2026-06-12T17:06:00Z (gap-closure 7/7 orchestrator fallback)_
