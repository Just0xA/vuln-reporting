---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "02"
subsystem: utils/sla_calculator + program_health_module
tags: [sla, program-health, robustness, nan-safety, d-05, wr-01, wr-02, wr-03, wr-04, wr-05]
dependency_graph:
  requires: []
  provides:
    - utils.sla_calculator.compute_sla_rate_crit_high
    - program_health_module NaN-safe _signal_direction
    - program_health_module sparkline gap semantics
    - program_health_module analyst_df NaN/int guard
    - _OWNER_SNAPSHOT_METADATA_KEYS frozenset constant
  affects:
    - scripts/capture_trend_snapshot.py (site 1 — snapshot persistence)
    - reports/modules/program_health_module.py (site 2 cold-start, site 3 live-tile)
tech_stack:
  added: []
  patterns:
    - shared helper pattern (D-05): single computation site, caller-injected SLA_DAYS dict
    - pd.isna() NaN guard in _signal_direction (WR-03)
    - sparkline gap semantics via explicit None (WR-04)
    - module-level frozenset constant for metadata-key blocklist (WR-05)
key_files:
  created:
    - utils/sla_calculator.py (new function compute_sla_rate_crit_high)
    - tests/test_sla_rate_crit_high.py (5 tests for the shared helper)
  modified:
    - scripts/capture_trend_snapshot.py (site 1 converted to shared helper)
    - reports/modules/program_health_module.py (sites 2+3, WR-03/04/05 fixes, constant)
    - tests/test_program_health_module.py (9 new WR-03/04/05 targeted tests)
decisions:
  - "tz-aware report_date handled via tz_convert/tz guard in helper (matches existing module pattern)"
  - "test_unmapped_severity_excluded: denominator is all valid-first_found rows; unmapped severity excluded from numerator only (sla_days_col.notna() in within mask)"
  - "WR-05 minimal fix: frozenset constant + dropna + int-cast on analyst_df; nested owner_counts sub-dict (the full structural fix) deferred to a future capture_snapshot refactor"
metrics:
  duration_seconds: 1800
  completed_date: "2026-06-24"
  tasks_completed: 3
  files_modified: 5
---

# Phase 19 Plan 02: SLA-Rate NaT-Denominator Fix + program_health_module Robustness Summary

Single shared `compute_sla_rate_crit_high()` helper in `utils/sla_calculator.py` eliminates the three-site NaT-denominator downward bias (D-05/WR-01); five WR-03/04/05 robustness guards added to `program_health_module`.

## What Was Built

### Task 1 — compute_sla_rate_crit_high shared helper + unit tests

Added `compute_sla_rate_crit_high(open_df, report_date, sla_days) -> Optional[float]` to `utils/sla_calculator.py`:

- Filters to critical+high, returns `None` when frame is empty or all-NaT (cold-start safe)
- Builds `valid_mask = ff_ts.notna()` and uses `ch_valid = ch_df[valid_mask]` as the denominator population — NaT rows excluded from **both** numerator and denominator (WR-01)
- Handles tz-aware `report_date` via `tz_convert("UTC")` / `tz="UTC"` guard (matched from existing module pattern)
- `sla_days_col.notna()` guard in `within` mask prevents unmapped severity rows from silently counting as within-SLA (WR-02)
- SLA day counts never hardcoded — callers pass `config.SLA_DAYS`

5 unit tests: NaT exclusion from denominator, all-NaT → None, empty → None, unmapped severity excluded from numerator, mixed within/overdue split.

### Task 2 — Convert all 3 SLA-rate sites to shared helper

Replaced the inline 10-line `days_open/sla_days_col/within/len(ch_df)` block at all three sites:

- **Site 1** (`scripts/capture_trend_snapshot.py` L390-418): inline block replaced with `compute_sla_rate_crit_high(open_df, snapshot_date, SLA_DAYS)` inside the existing fail-soft try/except
- **Site 2** (`program_health_module.py` cold-start ~L258): inline `ch_df/snap_ts/days_open/within` replaced with helper call
- **Site 3** (`program_health_module.py` live-tile ~L503): inline `ch_live/snap_ts/days_open_live/within_live` replaced with helper call
- Top-level import added to `program_health_module.py`; no local imports remain at call sites

### Task 3 — program_health_module WR-03/04/05 robustness

**WR-03**: `_signal_direction` guard broadened from `curr is None or prev is None` to also include `pd.isna(curr) or pd.isna(prev)`. A JSON-round-tripped `float('nan')` now returns `"missing"` instead of silently classifying as `"red"` and un-capping the composite RAG.

**WR-04**: Dropped `, 0` defaults from net-velocity sparkline builder (`s.get("new_findings_count")` / `s.get("fixed_findings_count")` with no default). The `is not None` gate already handles the absent-key case; the `, 0` defaults were dead code that diverged semantically from Signal 2's gap representation.

**WR-05**: 
- Extracted the metadata-key blocklist into module-level `_OWNER_SNAPSHOT_METADATA_KEYS: frozenset[str]` constant — reader and any future writers now reference the same set
- Added `dropna(subset=["Open Crit+High (curr)"])` guard on `analyst_df` after construction
- Added `.assign()` int-cast on `"Open Crit+High (curr)"` column to ensure Python `int` (not numpy int64) for clean JSON/Excel output

## Test Results

| Suite | Count | Status |
|-------|-------|--------|
| `tests/test_sla_rate_crit_high.py` | 5 | All pass |
| `tests/test_program_health_module.py` | 62 (53 pre-existing + 9 new) | All pass |
| `tests/content/test_trend_store.py` | 29 | All pass |
| **Total** | **96** | **All pass** |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] pd.Timestamp(tz_aware_dt, tz="UTC") raises ValueError**
- **Found during:** Task 1 — first test run
- **Issue:** `pd.Timestamp(report_date, tz="UTC")` raises `ValueError: Cannot pass a datetime or Timestamp with tzinfo with the tz parameter` when `report_date` is already tz-aware (as it is in all callers)
- **Fix:** Added the same tz-aware guard already present in `program_health_module.py` L260-263: `pd.Timestamp(dt).tz_convert("UTC") if dt.tzinfo is not None else pd.Timestamp(dt, tz="UTC")`
- **Files modified:** `utils/sla_calculator.py`
- **Commit:** 94ff76f

**2. [Rule 1 - Test] test_unmapped_severity_excluded expectation corrected**
- **Found during:** Task 1 — second test run
- **Issue:** The test initially expected `100.0%` (1 critical / 1 classifiable), but the authoritative helper body uses `len(ch_valid)` (all valid-first_found rows) as denominator, not just SLA-classifiable rows. With partial_sla = {"critical": 15} and 1 critical + 1 high (unmapped), result is `1/2 = 50.0%`. The test expectation was wrong.
- **Fix:** Corrected test expectation to `50.0` with updated docstring explaining the denominator semantics precisely
- **Files modified:** `tests/test_sla_rate_crit_high.py`
- **Commit:** 94ff76f

**3. [Rule 2 - Missing functionality] `import math` added to test file**
- **Found during:** Task 3 — adding WR-03 tests
- **Issue:** Needed `math` for potential `math.nan` usage in NaN tests; added to imports proactively
- **Note:** Not actually used in final tests (used `float("nan")` directly); left as harmless stdlib import

## Known Stubs

None. All three fixes are fully implemented and tested.

## Threat Flags

None. No new network endpoints, auth paths, file access, or schema changes introduced.

## Self-Check

### Files exist
- `utils/sla_calculator.py` — contains `compute_sla_rate_crit_high` (1 definition confirmed)
- `tests/test_sla_rate_crit_high.py` — 5 tests
- `scripts/capture_trend_snapshot.py` — contains `compute_sla_rate_crit_high` (2 occurrences: import + call)
- `reports/modules/program_health_module.py` — contains `compute_sla_rate_crit_high` (3 occurrences: import + 2 calls), `pd.isna` in `_signal_direction`, `_OWNER_SNAPSHOT_METADATA_KEYS`
- `tests/test_program_health_module.py` — 62 tests

### Commits exist
- 94ff76f — feat(19-02): add compute_sla_rate_crit_high shared helper + unit tests
- 3ca8a22 — feat(19-02): convert all 3 SLA-rate sites to shared helper
- 2dca148 — fix(19-02): WR-03/04/05 robustness fixes + 9 new tests

## Self-Check: PASSED
