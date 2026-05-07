---
phase: 3
plan: 03-07
subsystem: reports/modules + tests/test_phase2_composer_pipeline.py
tags: [gap-closure, regression, openpyxl-coercion, pd-na, pandas-3-cow, tech-debt, uat, structural-negative-control]
dependency_graph:
  requires: [03-01, 03-02, 03-03, 03-04, 03-05, 03-06]
  provides: [unblocks UAT tests 3, 4, 5, 6 of 03-UAT.md; pandas-3.0-safe assignment in 4 board modules]
  affects: [reports/modules/composer.py, reports/modules/scan_coverage_sla_module.py, reports/modules/board_report_utils.py, reports/modules/high_risk_assets_module.py, reports/modules/aged_vulns_assets_module.py, tests/test_phase2_composer_pipeline.py]
tech_stack:
  added: []
  patterns:
    - "pd.isna(val) → None coercion + tzinfo strip at openpyxl cell-write chokepoint"
    - ".loc[:, col] = ... over chained df[col] = ... for non-dtype-replacing setters"
    - "df = df.assign(col=...) for setter lines that must replace dtype on a CoW-tracked frame"
key_files:
  created:
    - .planning/phases/03-board-summary-module-migration/03-07-SUMMARY.md
  modified:
    - tests/test_phase2_composer_pipeline.py            # +135 lines (check_11 + CHECKS tuple) + 22 lines (Windows tempfile cleanup pattern)
    - reports/modules/composer.py                       # +29 lines (pd.isna + tzinfo chokepoint)
    - reports/modules/scan_coverage_sla_module.py       # 1 line .loc swap
    - reports/modules/board_report_utils.py             # 2 .loc swaps + 1 .assign() swap
    - reports/modules/high_risk_assets_module.py        # 2 .loc swaps + 1 .assign() swap
    - reports/modules/aged_vulns_assets_module.py       # 2 .loc swaps + 1 .assign() swap
decisions:
  - "Test-first commit ordering: check_11 was committed RED in Task 1 (10/11 passed) BEFORE the composer fix. The Task 1 → Task 2 commit boundary IS the structural negative control — bisecting across it observes 10/11 RED → 11/11 GREEN, which proves check_11 actually exercises the BLOCKER class. No prose-only revert-and-retest cycle was relied on."
  - "Composer chokepoint extended beyond plan: in addition to the planned pd.isna(val) → None coercion, the cell-write loop now also strips tzinfo from tz-aware pd.Timestamp / datetime values. openpyxl rejects tz-aware datetimes with TypeError; Phase 3 modules emit datetime64[ns, UTC] columns directly. Without this extension the Task 2 fix would have only swapped the BLOCKER class from <NA> → tzinfo. Documented as Rule 1 deviation in the Task 2 commit body."
  - "F-DTYPE fallback resolved with .assign() rather than the plan's df = df.copy() + df[col]= recipe. Under .loc[:, col]= the existing float64 column dtype is PRESERVED, breaking int dtype acceptance. Under df[col]= the int64 dtype is restored BUT the CoW-tracked merge parent fires ChainedAssignmentError. Only df = df.assign(risk_score=...) achieves both int64 dtype AND zero CoW warning. Applied at all 3 risk_score swap sites; documented inline."
metrics:
  duration: ~70 minutes (3 atomic commits + smoke verifications + F-DTYPE iteration)
  completed: 2026-05-06
  tasks: 3
  files_modified: 6
  lines_changed: ~225 insertions / ~25 deletions
---

# Phase 3 Plan 03-07: Gap Closure for UAT Findings Summary

One-liner: Closed BLOCKER (openpyxl crash on pd.NA / tz-aware dt in analyst workbook) and pre-existing pandas-3.0 chained-assignment tech debt — surfaced when Plan 03-06 ran against real Tenable data — with 3 atomic commits whose mid-sequence RED→GREEN transition serves as a structural (not prose-only) negative control.

## Goal

After Plan 03-06 wired the four migrated board modules into `ReportComposer`, the first real-Tenable smoke run (UAT for 03-UAT.md) hit two issues:

1. **BLOCKER:** `ValueError: Cannot convert <NA> to Excel` at `composer.py:1153` (`assemble_analyst_workbook` cell-write loop). openpyxl's `_bind_value` raises on `pd.NA` (StringDtype null) and `pd.NaT` (datetime null) — exactly what the four migrated board modules emit via `.astype("string")` formula-injection guards, nullable `Int64` days columns, and `datetime64[ns, UTC]` date columns. Synthetic regression fixtures used non-null DataFrames so the suite was 10/10 GREEN — the bug only reproduced against real data.
2. **MINOR / pre-existing tech debt:** 10 cited `df[col] = df[col].something(...)` chained-setter lines across 4 module files emit `ChainedAssignmentError` `FutureWarning` under pandas 3.0 Copy-on-Write semantics, masking genuine warnings.

This plan closed both gaps with three atomic commits, where the structural diff between Task 1 and Task 2 (RED→GREEN for `check_11`) replaces the older prose-only "revert-and-retest" negative-control pattern.

## Result

- **Regression suite:** 10/10 → 10/11 RED (Task 1) → 11/11 GREEN (Task 2) → 11/11 GREEN (Task 3).
- **Real-Tenable smoke:** `python run_all.py --group "Test Pull" --no-email` exits 0; `board_summary` reports `Status: success`.
- **Pandas-3.0 noise:** zero `ChainedAssignmentError` / `FutureWarning` strings on stderr after Task 3 (confirmed via 175,312-vuln / 43,565-asset live run).
- **F-DTYPE acceptance:** all three `risk_score` columns confirmed `int64` after the `.assign()` resolution.
- **Existing 10 checks:** all stayed GREEN throughout — no Phase 2 / Phase 3 contract regression.

## Delivered

Three atomic commits, monotonically advancing the regression suite from RED to GREEN:

| Commit  | Type       | Description                                                              |
| ------- | ---------- | ------------------------------------------------------------------------ |
| 07357ec | `test`     | Add check_11 regression for analyst-workbook nullable dtypes (RED-first) |
| 561647a | `fix`      | Coerce pandas null sentinels to None at openpyxl cell-write              |
| d17f2a6 | `refactor` | Quiet pandas-3.0 ChainedAssignmentError on 10 setter lines               |

## Test-First Commit Ordering — Structural Negative Control

The most important workflow detail in this plan was committing the test FIRST, as RED, before the composer fix. The chronology:

1. **Commit 07357ec (Task 1) — RED.** Added `check_11_phase3_analyst_workbook_nullable_dtypes` to `tests/test_phase2_composer_pipeline.py` with a 2-row DataFrame mixing `pd.NA` in StringDtype, `pd.NaT` in `datetime64[ns, UTC]`, and `pd.NA` in `Int64`. Suite at HEAD: `Result: 10/11 passed, 0 skipped, 1 failed.` Failure label: `[ERROR] Gap 03-07 analyst workbook nullable dtypes: ValueError: Cannot convert <NA> to Excel`. **Intentional RED.**
2. **Commit 561647a (Task 2) — GREEN.** Applied `pd.isna(val) → None` coercion at the cell-write chokepoint (`composer.py:1163`) plus a tzinfo-stripping branch (Rule 1 deviation — see below). Suite at HEAD: `Result: 11/11 passed, 0 skipped, 0 failed.`
3. **Commit d17f2a6 (Task 3) — GREEN preserved.** Mechanical refactor; suite stayed `11/11 passed`.

**Why this matters:** the diff between commits 07357ec and 561647a IS the automatic, mechanical negative control. Anyone bisecting `python tests/test_phase2_composer_pipeline.py` across that boundary observes the suite transition from RED to GREEN exactly when the chokepoint coercion lands. There is no prose-only "revert the fix, run, confirm fail, re-apply" step that an executor or reviewer could skip — the bisect IS the evidence. This replaces the older negative-control pattern (review reports describing manual revert-and-retest cycles) with one that's git-traceable forever.

## BLOCKER fix mechanism (Task 2 — composer.py)

The `assemble_analyst_workbook` cell-write loop at `composer.py:1161-1175`:

```python
# Data rows
# Gap 03-UAT.md #1 — openpyxl's _bind_value accepts None and np.nan
# but raises on pd.NA (StringDtype null) and pd.NaT (datetime null).
# All four Phase 3 board modules coerce text columns through
# .astype("string") (StringDtype produces pd.NA, not np.nan) and have
# nullable Int64 / datetime64 columns. Coerce every pandas-null
# sentinel to None at this chokepoint so the analyst workbook renders
# empty cells rather than crashing the batch.
#
# Additionally: openpyxl rejects tz-aware datetimes with
# "TypeError: Excel does not support timezones in datetimes". The
# Phase 3 modules emit last_licensed_scan_date and last_seen as
# datetime64[ns, UTC] straight into the analyst_df. Strip tzinfo at
# this same chokepoint so openpyxl writes a naive datetime (Excel
# has no concept of timezone so the UTC instant is the only
# meaningful representation).
for row_idx, row in enumerate(df.itertuples(index=False), start=2):
    for col_idx, val in enumerate(row, start=1):
        if pd.isna(val):
            cell_value = None
        elif isinstance(val, pd.Timestamp) and val.tzinfo is not None:
            cell_value = val.tz_convert("UTC").tz_localize(None).to_pydatetime()
        elif hasattr(val, "tzinfo") and val.tzinfo is not None:
            cell_value = val.replace(tzinfo=None)
        else:
            cell_value = val
        ws.cell(row=row_idx, column=col_idx, value=cell_value)
```

Confirmation that the existing 10 checks stayed green throughout: the per-task `python tests/test_phase2_composer_pipeline.py` output before and after each commit shows checks 1-10 always pass and only check_11 transitions. The Phase 2 (D-22..D-29) and Phase 3 (QUALITY-02 zero-row, populated-row, email_inline_images) contracts stayed intact across all three commits.

## Deviations

### Rule 1 — extended Task 2 chokepoint to tz-aware datetimes

The plan called for `pd.isna(val) → None` coercion only. After applying that change, the regression suite revealed a second openpyxl rejection class: `TypeError: Excel does not support timezones in datetimes`. The Phase 3 modules emit `last_licensed_scan_date` and `last_seen` as `datetime64[ns, UTC]` directly into `analyst_df` (no tzinfo strip step exists). Without extending the chokepoint to also strip tzinfo, the Task 2 commit would have swapped the BLOCKER class from `<NA>` → `tzinfo` and the suite would have stayed at 10/11 RED — defeating the structural negative-control intent.

**Resolution:** added two `elif` branches before the default `cell_value = val` — one for `pd.Timestamp` with tzinfo (uses `tz_convert("UTC").tz_localize(None).to_pydatetime()`), one for stdlib `datetime` with tzinfo (uses `.replace(tzinfo=None)`). Excel has no timezone concept; the UTC instant is the only meaningful representation. Documented in the Task 2 commit body.

### Rule 1 — Windows tempfile cleanup race in check_11

The plan's check_11 used `tempfile.TemporaryDirectory() + openpyxl.load_workbook(path) + wb.close()`. On Windows, openpyxl's atexit shutdown (`_writer.py:32 _openpyxl_shutdown`) holds transient handles into the user temp dir that collide with `TemporaryDirectory.__exit__` → `PermissionError [WinError 32]`. The error masked the (now-passing) BLOCKER assertion outcome.

**Resolution:** switched to `tempfile.mkdtemp` + `openpyxl.load_workbook(io.BytesIO(read_bytes()))` + `shutil.rmtree(..., ignore_errors=True)` — the BytesIO load pattern (already used by check_4a/4b) bypasses the file-handle race, and the best-effort cleanup tolerates the openpyxl atexit transient. The BLOCKER assertion shape (header row, row count, per-cell None expectations) was preserved verbatim. Documented in the Task 2 commit body.

### Plan F-DTYPE fallback resolved via `.assign()` not `df[col]=`

The plan's F-DTYPE recipe said: if `.loc[:, col] = ...` drifts a `risk_score` column to float64, swap that one line back to `df[col] = ...` (preceded by `df = df.copy()` if needed). The dtype audit confirmed all 3 risk_score columns drifted to float64 under `.loc[:,]`, so the F-DTYPE fallback was triggered.

**Issue with the plan recipe:** `df = df.copy() + df[col] = ...` did NOT silence the `ChainedAssignmentError` warning, because the merge result's CoW parent tracking persists across the `.copy()`. Two CoW warnings appeared in the warning audit — at `board_report_utils.py:477` and `high_risk_assets_module.py:273`.

**Resolution:** used `df = df.assign(risk_score=df["risk_score"].fillna(0).astype(int))` instead. `.assign()` returns a new frame with the column REPLACED (preserving int64 dtype) and bypasses the CoW parent-tracking warning. Verified empirically with the warning audit. Applied at all 3 risk_score sites:

| File                                  | Line(s)  | Pattern                       |
| ------------------------------------- | -------- | ----------------------------- |
| `board_report_utils.py`               | ~469-477 | `bu_asset = bu_asset.assign(risk_score=...)` |
| `high_risk_assets_module.py`          | ~262-274 | `bu_breakdown = bu_breakdown.assign(risk_score=...)` |
| `aged_vulns_assets_module.py`         | ~257-269 | `bu_breakdown = bu_breakdown.assign(risk_score=...)` |

Documented inline at all three sites and in the Task 3 commit body.

### Plan F3 (`df = df.copy()`) was NOT triggered

The plan said: "Try `.loc[:, col] = ...` only. Re-run smoke. If a line still warns, prepend `df = df.copy()` immediately above it." For the 7 non-risk_score lines, the bare `.loc[:, col] = ...` swap was sufficient — zero residual warnings. F3's `.copy()` upgrade was not used on any of those 7 lines. The 3 risk_score lines required a different escape hatch (`.assign()`) — see the previous deviation.

## Gap 2 outcome (10 lines, 4 files, 0 warnings)

Task 3 edited exactly 10 cited setter lines across 4 files:

| File                                       | Line  | Original setter                                 | Final pattern                                              |
| ------------------------------------------ | ----- | ----------------------------------------------- | ---------------------------------------------------------- |
| `scan_coverage_sla_module.py`              | 395   | `analyst_df[_col] = ...`                        | `analyst_df.loc[:, _col] = ...`                            |
| `board_report_utils.py`                    | 449   | `risk_vulns["severity"] = ...`                  | `risk_vulns.loc[:, "severity"] = ...`                      |
| `board_report_utils.py`                    | 454   | `risk_vulns["weighted"] = ...`                  | `risk_vulns.loc[:, "weighted"] = ...`                      |
| `board_report_utils.py`                    | 469   | `bu_asset["risk_score"] = ...`                  | `bu_asset = bu_asset.assign(risk_score=...)` (F-DTYPE)     |
| `high_risk_assets_module.py`               | 267   | `bu_breakdown["risk_score"] = ...`              | `bu_breakdown = bu_breakdown.assign(risk_score=...)` (F-DTYPE) |
| `high_risk_assets_module.py`               | 366   | `analyst_df[_col] = ...`                        | `analyst_df.loc[:, _col] = ...`                            |
| `high_risk_assets_module.py`               | 388   | `bu_counts["business_unit"] = ...`              | `bu_counts.loc[:, "business_unit"] = ...`                  |
| `aged_vulns_assets_module.py`              | 262   | `bu_breakdown["risk_score"] = ...`              | `bu_breakdown = bu_breakdown.assign(risk_score=...)` (F-DTYPE) |
| `aged_vulns_assets_module.py`              | 361   | `analyst_df[_col] = ...`                        | `analyst_df.loc[:, _col] = ...`                            |
| `aged_vulns_assets_module.py`              | 385   | `bu_counts["business_unit"] = ...`              | `bu_counts.loc[:, "business_unit"] = ...`                  |

Real-Tenable run audit: `python run_all.py --group "Test Pull" --no-email 2>&1 | grep -cE "ChainedAssignmentError|FutureWarning"` → **0**.

`critical_remediation_sla_module.py` was intentionally NOT touched — not cited as a gap source and has no chained-setter pattern at the time of planning.

## F-DTYPE outcome (all 3 risk_score columns int64)

Verified post-edit on the live cache (`data/cache/2026-05-06`, 175312 vulns / 43565 assets):

| Module / column                                                  | dtype | `pd.api.types.is_integer_dtype` |
| ---------------------------------------------------------------- | ----- | ------------------------------- |
| `HighRiskAssetsModule.bu_breakdown.risk_score`                   | int64 | True                            |
| `AgedVulnsAssetsModule.bu_breakdown.risk_score`                  | int64 | True                            |
| `compute_bu_risk_scores(...)` returned `pd.Series.risk_score`    | int64 | True (verified via `.assign()` ensures int64 dtype enters the groupby) |

All three forced the F-DTYPE fallback (initial `.loc[:, col] = ...` preserved the merge's float64); all three were resolved with `.assign()` rather than the plan's recommended `df[col]= + .copy()` pattern. Documented inline at each site.

## Files Modified

- `tests/test_phase2_composer_pipeline.py` — added `check_11_phase3_analyst_workbook_nullable_dtypes` (135 lines) + appended `(label, fn)` tuple to `CHECKS`; switched check_11 from `TemporaryDirectory + load_workbook(path)` to `mkdtemp + load_workbook(BytesIO(...))` for Windows file-handle safety.
- `reports/modules/composer.py` — `assemble_analyst_workbook` cell-write loop now coerces `pd.NA / pd.NaT` to `None` and strips tzinfo from tz-aware datetimes before openpyxl receives the value.
- `reports/modules/scan_coverage_sla_module.py` — 1 chained-setter line swapped to `.loc[:, col] = ...`.
- `reports/modules/board_report_utils.py` — 2 chained-setter lines swapped to `.loc[:, col] = ...`; 1 risk_score line uses `.assign()` (F-DTYPE).
- `reports/modules/high_risk_assets_module.py` — 2 chained-setter lines swapped to `.loc[:, col] = ...`; 1 risk_score line uses `.assign()` (F-DTYPE).
- `reports/modules/aged_vulns_assets_module.py` — 2 chained-setter lines swapped to `.loc[:, col] = ...`; 1 risk_score line uses `.assign()` (F-DTYPE).

## Verification

| Check                                                                          | Status |
| ------------------------------------------------------------------------------ | ------ |
| `python tests/test_phase2_composer_pipeline.py` returns `Result: 11/11 passed, 0 skipped, 0 failed.` | ✅ PASS |
| `python run_all.py --group "Test Pull" --no-email` exits 0 with `Status: success` for `board_summary` | ✅ PASS |
| Real-Tenable run shows zero `ChainedAssignmentError|FutureWarning` strings on stderr | ✅ PASS (0) |
| `git log --oneline --grep="03-07"` shows exactly 3 commits in test → fix → refactor order | ✅ PASS (07357ec, 561647a, d17f2a6) |
| Bisect-style negative control: HEAD~2 → 10/11 RED; HEAD~1 → 11/11 GREEN; HEAD → 11/11 GREEN | ✅ PASS (Task 1 was RED, Task 2 turned it GREEN, Task 3 preserved GREEN) |
| `grep -nE "pd\.isna\(val\)" reports/modules/composer.py` returns exactly 1 match | ✅ PASS |
| F-DTYPE: all 3 risk_score columns confirmed `int64`                            | ✅ PASS |
| `python run_all.py --dry-run` exits 0 with all configured groups validated     | ✅ PASS |
| Backward-compat audit: `delivery_config.yaml` groups still listed/validated   | ✅ PASS |

## Next Steps — UAT Re-Run Unblocked

Plan 03-UAT.md flagged 4 tests as `blocked_by: prior-phase` while the BLOCKER was unfixed:

1. **Test 3** — PDF cover page renders RAG strip + 4 module pages
2. **Test 4** — Email body assembles per-module panels
3. **Test 5** — Analyst-detail companion workbook reaches users
4. **Test 6** — Zero-row recipient group renders gracefully

All four are now unblocked by the Task 2 chokepoint fix. **The user should re-invoke `/gsd-uat-phase 03`** to run the UAT pass and update `03-UAT.md` with the final results. BOARD-07 acceptance is now verifiable end-to-end against real Tenable data, not just synthetic fixtures.

## BOARD-07 Traceability

The Board Summary analyst-workbook companion is now provably emitted against real Tenable data — confirmed by:

- The real-Tenable smoke run (`run_all.py --group "Test Pull" --no-email`) produces a `board_summary_analyst_*.xlsx` artifact in the output folder (the analyst Excel companion was the BOARD-07 acceptance the BLOCKER prevented).
- `check_11_phase3_analyst_workbook_nullable_dtypes` in the regression suite locks the chokepoint behavior with true nullable dtypes (StringDtype + Int64 + datetime64[ns, UTC] populated and null), so a future refactor cannot regress it without breaking the suite.
- The structural RED→GREEN bisect at the Task 1 → Task 2 commit boundary is permanent evidence (in git history) that check_11 actually exercises the BLOCKER class.

This raises BOARD-07 confidence above what `03-06-SUMMARY.md` could achieve (which closed BOARD-07 against synthetic fixtures only).

## Self-Check: PASSED

- ✅ `tests/test_phase2_composer_pipeline.py` — confirmed: contains `check_11_phase3_analyst_workbook_nullable_dtypes` def + tuple in CHECKS list (`grep -nE "check_11_phase3_analyst_workbook_nullable_dtypes" tests/test_phase2_composer_pipeline.py` → 2 matches).
- ✅ `reports/modules/composer.py` — confirmed: `pd.isna(val)` chokepoint present (1 match), tzinfo strip present (`val.tz_convert("UTC").tz_localize(None)`).
- ✅ Commit 07357ec exists in `git log` — RED-first test, +135 lines on `tests/test_phase2_composer_pipeline.py`.
- ✅ Commit 561647a exists in `git log` — composer.py + tests deviation.
- ✅ Commit d17f2a6 exists in `git log` — refactor on 4 module files (10 + 22 lines net delta).
- ✅ Suite: 11/11 GREEN at HEAD.
- ✅ Real-Tenable smoke: status=success, zero pandas-3.0 warnings.
- ✅ F-DTYPE: all 3 risk_score columns int64.
