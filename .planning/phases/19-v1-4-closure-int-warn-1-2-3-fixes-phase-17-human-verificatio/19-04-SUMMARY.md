---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "04"
subsystem: trend-store
tags: [correctness, backfill, trend-store, testing]
dependency_graph:
  requires: ["19-01"]
  provides: ["CR-B1", "CR-B2", "CR-B3", "CR-B4", "CR-B6", "CR-B7", "CR-T3", "CR-T4", "WR-05", "WR-06", "WR-07"]
  affects: ["data/trend_store.py", "scripts/backfill_trend_reconstruction.py"]
tech_stack:
  added: []
  patterns:
    - "CoW boundary-local copy: _df_boundary = combined.copy() before state flip"
    - "argparse type= validator pattern: _month_arg() rejects non-YYYY-MM"
    - "Corrupt-file safety: isinstance validation + rename-to-*.corrupt before return []"
    - "Partial-month flag: read_trend() flags newest entry partial=True when month==local-now"
key_files:
  modified:
    - scripts/backfill_trend_reconstruction.py
    - tests/test_backfill_reconstruction.py
    - data/trend_store.py
    - tests/content/test_trend_store.py
decisions:
  - "CR-B3 confirmed no-change: _months_in_range_stdlib already uses datetime.now() (local-naive) consistent with CLAUDE.md month-key policy"
  - "WR-05 flag placed in read_trend return layer (not in capture_snapshot write layer) so callers get it without post-processing"
  - "WR-06 fix: date.astimezone() only when date.tzinfo is not None; naive dates left as-is (they are already local)"
metrics:
  duration: 900
  completed: "2026-06-25"
  tasks: 3
  files: 4
---

# Phase 19 Plan 04: Trend/Backfill Correctness (CR-B1/B2/B3/B4/B6/B7 + WR-05/06/07 + CR-T3/T4) Summary

**One-liner:** Fixed-after-boundary add-back state flip + cached open/reopened filter + argparse YYYY-MM validator + explicit-zero empty fixed count + shape-validated corrupt-file load + local-month key + partial-month flag in read_trend — all paired with exact-tolerance and set-membership tests.

## What Was Built

### Task 1 — CR-B1 add-back fix + CR-T3 exact-tolerance test

**Problem:** `open_findings_at()` treats `state=fixed` as terminal. Add-back rows (findings fixed AFTER the month boundary, which were still open AT the boundary) were silently dropped from historical open counts — causing undercounting for past months.

**Fix (scripts/backfill_trend_reconstruction.py `reconstruct_month`):** For the boundary check only, build `_df_boundary = combined.copy()` and flip add-back rows' state to `"open"` using `.loc[_add_back_in_combined, "state"] = "open"`. Never mutates the original `combined` or `fixed_df` frames (pandas CoW rule).

**Test tightening (tests/test_backfill_reconstruction.py):** Replaced the loose `abs_diff <= MAX_ABSOLUTE_ERROR or rel_diff <= MAX_RELATIVE_ERROR` tolerance band with an exact `got == expected` assertion citing CR-B1, so a dropped add-back row immediately fails the test.

**New test `TestAddBackMetadataPreserved`:** Verifies that `fixed_df["state"]` and `fixed_df["last_fixed"]` are unchanged after `reconstruct_month` returns — the state flip is local to the boundary frame only.

### Task 2 — CR-B2 cached filter + CR-B4 arg validator + CR-T4 taper-set assertion

**CR-B2 (cached branch):** After loading from the parquet cache, apply `state.str.lower().isin({"open", "reopened"})` filter so cached runs agree with live runs that go through `fetch_all_vulnerabilities()` (which applies the same filter before returning).

**CR-B4 (--window-start validation):** Added `_month_arg(value: str) -> str` argparse type validator that `re.fullmatch(r"\d{4}-\d{2}", value)` and raises `argparse.ArgumentTypeError` on malformed input. Wired `type=_month_arg` onto `--window-start`.

**CR-B3 (confirmed):** `_months_in_range_stdlib` already uses `datetime.now()` (local-naive) consistent with CLAUDE.md month-key convention. No code change needed.

**CR-T4 taper test:** Added `assert set(produced_months) >= expected_taper_months` before checking partial flags, so the test cannot silently pass when taper months were never produced. Prior `if taper_month in reconstructed:` guards allowed silent pass-through.

### Task 3 — CR-B6/B7 + WR-05/06/07 in data/trend_store.py + 8 new tests

**CR-B6:** When `fixed_vulns_df is not None` and `fixed_vulns_df.empty`, set `fixed_findings_count = 0` explicitly. Prior code left it `None`, conflating "looked, found nothing" with "caller did not supply fixed data".

**CR-B7 + WR-07 (`_load_trend_json`):** Extended the parse block with three shape validations that raise `ValueError` on failure: (1) `isinstance(data, dict)`, (2) `isinstance(snapshots, list)`, (3) all entries `isinstance(s, dict)`. On `(json.JSONDecodeError, ValueError, AttributeError)`, rename the file to `*.corrupt` (best-effort, log if rename fails) and return `[]` — data-loss-safe rename-before-overwrite pattern.

**WR-06 (`capture_snapshot`):** Derive `month_str` from `date.astimezone().strftime("%Y-%m")` when `date` is tz-aware, falling back to `date.strftime("%Y-%m")` for naive dates (already local). Fixes month-boundary misattribution on non-UTC servers receiving UTC-aware `generated_at` datetimes.

**WR-05 (`read_trend`):** Flag the newest returned snapshot as `partial=True` when its `month` field equals `datetime.now().strftime("%Y-%m")` (same local-time convention as `capture_snapshot`). MoM consumers can now exclude the partial current-month point from `latest − prior` delta math. Added ordering-contract docstring note to both `capture_snapshot` and `read_trend`.

## Tests Added

| Test | File | Covers |
|------|------|--------|
| `TestAddBackMetadataPreserved` | test_backfill_reconstruction.py | CR-B1: original fixed_df not mutated |
| CR-T4 set-membership assertion | test_backfill_reconstruction.py | CR-T4: taper months must exist before flag check |
| `test_fixed_findings_count_explicit_zero_when_empty_df` | test_trend_store.py | CR-B6 |
| `test_load_trend_json_bare_list_is_corrupt` | test_trend_store.py | CR-B7/WR-07 |
| `test_load_trend_json_non_list_snapshots_is_corrupt` | test_trend_store.py | CR-B7/WR-07 |
| `test_load_trend_json_non_dict_snapshot_entry_is_corrupt` | test_trend_store.py | CR-B7/WR-07 |
| `test_capture_snapshot_month_key_uses_local_time` | test_trend_store.py | WR-06 |
| `test_read_trend_flags_current_month_as_partial` | test_trend_store.py | WR-05 |

## Deviations from Plan

None — plan executed exactly as written. CR-B3 was confirmed as no-change (clock already consistent) as noted in the plan's action block.

## Verification

- `pytest tests/test_backfill_reconstruction.py tests/content/test_trend_store.py -q -o addopts=""` → 55 passed
- `python -c "import data.trend_store, scripts.backfill_trend_reconstruction"` → imports cleanly

## Self-Check: PASSED

Files confirmed present:
- `scripts/backfill_trend_reconstruction.py` — contains `_month_arg`, `_df_boundary = combined.copy()`, `isin({"open", "reopened"})` on cached path
- `tests/test_backfill_reconstruction.py` — contains exact `==` assertion + `TestAddBackMetadataPreserved` + CR-T4 set assertion
- `data/trend_store.py` — contains 3 new `isinstance` checks in `_load_trend_json`, `fixed_findings_count = 0` for empty df, `date.astimezone()` WR-06 fix, `entry["partial"] = True` WR-05 flag
- `tests/content/test_trend_store.py` — 8 new tests appended

Commits confirmed present:
- `2fb3742` — fix(19-04): CR-B1 add-back state flip + CR-T3 exact-tolerance test
- `53e11ec` — fix(19-04): CR-B2 cached filter + CR-B4 arg validator + CR-T4 taper-set assertion
- `8dfe44f` — fix(19-04): CR-B6/B7/WR-05/WR-06/WR-07 trend_store hardening + 8 tests
