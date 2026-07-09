---
phase: 14-shared-substrates-composed-report-gates
plan: "02"
subsystem: utils/asset_count + config constant
tags: [asset-count, on-time-scan, denominator, pure-function, tdd, SC#2, SUB-02]
requirements: [SUB-02]
dependency_graph:
  requires: []
  provides: [count_on_time_assets, ON_TIME_SCAN_WINDOW_DAYS]
  affects: [Phase 15 vulnerability density module]
tech_stack:
  added: []
  patterns: [injected-date pure function, None sentinel D-14, config-sourced window D-13, TDD RED/GREEN]
key_files:
  created:
    - utils/asset_count.py
    - tests/test_asset_count.py
  modified:
    - config.py
decisions:
  - "D-12: count_on_time_assets accepts injected report_date; no datetime.now() inside"
  - "D-13: ON_TIME_SCAN_WINDOW_DAYS = 30 in config.py is the single canonical window; board_report_utils.py line 59 migration deferred"
  - "D-14: None sentinel (not 0) when no on-time licensed assets; callers must None-check before dividing"
  - "TDD RED purity test: fixed-absolute-scan-date fixture (2026-05-20) + shifted report_date (2026-06-25) correctly proves injected-date purity; relative-days-ago was internally consistent but insufficient to distinguish report_date influence"
metrics:
  duration: "5m 15s"
  completed: "2026-06-11"
  tasks_completed: 2
  files_changed: 3
---

# Phase 14 Plan 02: Asset Count Substrate (SC#2) Summary

**One-liner:** Pure `count_on_time_assets()` utility returning on-time-scanned licensed asset count from `assets_df` via injected `report_date`, with `None` sentinel and `ON_TIME_SCAN_WINDOW_DAYS = 30` canonical config constant.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add ON_TIME_SCAN_WINDOW_DAYS to config.py | 5d3e2e7 | config.py |
| 2 (RED) | Failing tests for count_on_time_assets | 4ddb60d | tests/test_asset_count.py |
| 2 (GREEN) | Implement count_on_time_assets + test fix | 1744e99 | utils/asset_count.py, tests/test_asset_count.py |

## What Was Built

### `config.py` (+8 lines)

Added `ON_TIME_SCAN_WINDOW_DAYS: int = 30` in a labeled `# ===` comment block placed immediately after `SLA_DAYS`, before `SEVERITY_ORDER` (per D-13). Comment documents: single canonical source; consumed by `utils/asset_count.py` and `scan_coverage_sla_module.py`; no drift between substrate and board module. `board_report_utils.py` line 59 (`ON_TIME_WINDOW_DAYS = 30`) left untouched — migration deferred.

### `utils/asset_count.py` (new, 155 lines)

Pure-compute utility implementing `count_on_time_assets(assets_df, report_date, window_days=ON_TIME_SCAN_WINDOW_DAYS) -> int | None`:

- **No `datetime.now()` inside** (D-12): cutoff computed solely from injected `report_date`
- **Config-sourced default window** (D-13): imports `ON_TIME_SCAN_WINDOW_DAYS` from `config`; no `reports.modules` backward import
- **None sentinel** (D-14): returns `None` (not `0`) on empty df, missing column, all-NaT licensed dates, or zero on-time count
- **tz-normalization**: mirrors `scan_coverage_sla_module.py` lines 262–265 (tz-aware → `tz_convert("UTC")`; tz-naive → assign `tz="UTC"`)
- **Licensed filter**: `last_licensed_scan_date.notna()` isolates licensed rows before the on-time split
- **Inclusive boundary**: `licensed[_LSD] >= cutoff` (exactly-at-cutoff counted as on-time)
- **CoW-safe**: no `df["col"] = val` after filter; fail-soft on missing column (logs warning, returns None)
- `if __name__ == "__main__":` argparse stub per Code Quality requirements

### `tests/test_asset_count.py` (new, 220 lines, 15 tests)

All fixtures synthetic-only (QUAL-05). Covers every behavior-block case:

- On-time count (all within, partial stale, unlicensed exclusion)
- Window boundary: exactly-at-cutoff (inclusive), one-day-over (exclusive → None)
- None sentinel: all-stale, empty df, all-unlicensed, missing column + warning logged
- Injected-date purity (D-12): same df + different report_dates yield different counts
- tz-naive and tz-aware non-UTC report_date coercion
- Default window resolves to `config.ON_TIME_SCAN_WINDOW_DAYS` (D-13)
- Custom `window_days` overrides default

## Verification

```
python -c "import config; assert config.ON_TIME_SCAN_WINDOW_DAYS == 30"  → OK
python -c "from utils.asset_count import count_on_time_assets"            → OK
pytest tests/test_asset_count.py -v                                        → 15 passed
grep -n "datetime.now" utils/asset_count.py                               → (no executable matches)
grep -n "reports.modules" utils/asset_count.py                            → nothing
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed injected-date purity test fixture**

- **Found during:** TDD GREEN — test `test_different_report_dates_yield_different_counts` failed with `assert 1 is None`
- **Issue:** The test built an asset "20 days before `_REPORT_DATE`" (2026-06-01), giving scan date 2026-05-12. The second report_date was 2025-06-01 with cutoff 2025-05-02 — the scan date (2026-05-12) was still AFTER this old cutoff, so both report_dates saw the asset as on-time. The test premise was internally incorrect.
- **Fix:** Replaced relative-days-ago fixture with a fixed absolute scan date (2026-05-20 UTC). Used `date1 = 2026-06-01` (cutoff = 2026-05-02, asset on-time) and `date3 = 2026-06-25` (cutoff = 2026-05-26, asset stale → None). This correctly exercises injected-date purity (D-12).
- **Files modified:** `tests/test_asset_count.py`
- **Commit:** 1744e99 (included in GREEN commit)

## Known Stubs

None — `count_on_time_assets` is fully wired to `assets_df`; no mock data flows to callers.

## Forward Dependencies Created

- **OD-3 (Phase 15):** `capture_snapshot()` must be extended to record the on-time-scanned count per snapshot so MoM vulnerability density trend can cold-start. `count_on_time_assets` provides the current-run denominator; it does NOT read the S1 snapshot `asset_count` field (wrong basis per D-02).
- **Phase 15 density module:** Calls `count_on_time_assets(assets_df, report_date)` inside `compute()`, None-checks before dividing, and renders cold-start / No-Data via `_empty_result()` on `None` return.

## Threat Flags

None — `count_on_time_assets` returns an aggregate `int | None` scalar; no asset-level rows cross trust boundaries. T-14-04 (zero/empty/missing-column DoS) mitigated by the None sentinel guards; T-14-06 (test fixture PII) mitigated by synthetic-only data (QUAL-05).

## Self-Check: PASSED

- [x] `config.py` contains `ON_TIME_SCAN_WINDOW_DAYS` — FOUND
- [x] `utils/asset_count.py` exists — FOUND
- [x] `tests/test_asset_count.py` exists — FOUND
- [x] Commit 5d3e2e7 (Task 1) — FOUND
- [x] Commit 4ddb60d (TDD RED) — FOUND
- [x] Commit 1744e99 (TDD GREEN) — FOUND
- [x] All 15 tests pass — VERIFIED
