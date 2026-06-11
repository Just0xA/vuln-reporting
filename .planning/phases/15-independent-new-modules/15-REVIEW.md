---
phase: 15-independent-new-modules
reviewed: 2026-06-11T22:00:00Z
depth: standard
files_reviewed: 8
files_reviewed_list:
  - reports/modules/reopened_vulns_module.py
  - reports/modules/external_dmz_module.py
  - reports/modules/new_vs_remediated_module.py
  - reports/modules/vuln_density_module.py
  - reports/modules/accepted_recast_module.py
  - data/trend_store.py
  - reports/composed_report.py
  - scripts/capture_trend_snapshot.py
findings:
  critical: 0
  warning: 5
  info: 5
  total: 10
status: resolved
resolution:
  warnings_fixed: [WR-01, WR-02, WR-03, WR-04, WR-05]
  fix_commit: 81d85c2
  info_deferred: [IN-01, IN-02, IN-03, IN-04, IN-05]
  note: "All 5 Warnings fixed with regression coverage (WR-01/02/04 added tests; WR-03/05 verified by inspection/existing excel test). 5 Info findings (unused imports/helpers, owner-dim aggregate-count parity) deferred as non-functional cleanup."
---

# Phase 15: Code Review Report

**Reviewed:** 2026-06-11T22:00:00Z
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found

---

## Summary

Eight files were reviewed spanning five new metric modules, the trend-store extension, the
composed-report outflow gate, and the cron snapshot script. The implementation is broadly
correct and well-disciplined: the four-channel render contract is consistently honoured,
the empty-data guard pattern is applied across all modules, the Pitfall-4 per-snapshot
denominator is enforced in `vuln_density_module.py`, accepted/recast counts remain
separate, and PII/aggregate-only boundaries are respected throughout.

Five findings at Warning severity and five at Info severity are reported. There are no
Blockers. The most consequential issues are:

1. A UTC/local timezone mismatch in `trend_store.capture_snapshot()` that causes
   `new_findings_count` and `fixed_findings_count` to be attributed to the wrong calendar
   month whenever the server runs in a non-UTC timezone and the snapshot is captured near a
   month boundary.
2. A pandas 3.x `UserWarning` on tz-aware `.dt.to_period("M")` calls in
   `new_vs_remediated_module.py` — the same class of issue that was explicitly fixed in
   `accepted_recast_module.py` but not propagated to the sibling module that also calls
   `.dt.to_period()` on tz-aware Series.
3. A misleading exit-code contract in `capture_trend_snapshot.py` where the owner-snapshot
   failure path is documented as "Non-fatal, log and continue" but actually exits with code
   3, preventing the severity snapshot completion from being signalled as a success to the
   calling scheduler.

---

## Warnings

### WR-01: UTC/local mismatch in `new_findings_count` / `fixed_findings_count` derivation

**File:** `data/trend_store.py:313,342,347`

**Issue:** `month_str` is derived from `date.strftime("%Y-%m")` using **server local time**
(documented as intentional — `# LOCAL — no tz conversion`). However, `ff` (line 341) and
`lf` (line 344) are both parsed with `utc=True`, making them UTC-aware. The month-match
comparisons on lines 342 and 347 use `ff.dt.strftime("%Y-%m")` and `lf.dt.strftime("%Y-%m")`,
which produce **UTC month strings**, not local-time month strings.

When the server runs in any timezone west of UTC (e.g. UTC-5), a finding first-found at
`2026-06-01T03:00:00 UTC` is server-local `2026-05-31` — correct month key is `2026-05` —
but `ff.dt.strftime("%Y-%m")` yields `"2026-06"`, so it is attributed to June instead of
May. The magnitude is small (only findings near midnight UTC at a month boundary are
misattributed), but the severity/open-set counts in the same snapshot already use the local
month key correctly via `open_findings_at`, making `new_findings_count` inconsistent with
the rest of the snapshot.

**Fix:** Strip the UTC timezone before strftime so the comparison uses local time, matching
`month_str`:

```python
# line 341-342 — new_findings_count derivation
ff = pd.to_datetime(df["first_found"], utc=True, errors="coerce")
ff_local = ff.dt.tz_convert(None)   # strip tz → local-equivalent naive
new_findings_count = int((ff_local.dt.strftime("%Y-%m") == month_str).sum())

# line 344-347 — fixed_findings_count derivation
lf = pd.to_datetime(fixed_vulns_df["last_fixed"], utc=True, errors="coerce")
lf_local = lf.dt.tz_convert(None)
fixed_findings_count = int(
    ((lf_local.dt.strftime("%Y-%m") == month_str) & (state_upper == "FIXED")).sum()
)
```

---

### WR-02: tz-aware `.dt.to_period("M")` produces `UserWarning` in pandas 3.x

**File:** `reports/modules/new_vs_remediated_module.py:313,318`

**Issue:** `ff_ts` (line 281) and `rs_ts` (line 282-285) are created with `utc=True` and
are therefore timezone-aware Series. Calling `.dt.to_period("M")` on a tz-aware Series
emits `UserWarning: Converting to Period representation will drop timezone information` in
pandas 3.x. This is exactly the warning that `accepted_recast_module.py` fixed (per
15-06-SUMMARY auto-fixed issue 1) by stripping timezone via `.tz_localize(None)` before
calling `.to_period()`. The fix was not propagated to this sibling module.

Under `-W error::FutureWarning` this specific warning class (`UserWarning`) is not caught,
so the tests currently pass. However, future pandas versions may promote this to a
`FutureWarning` or a hard error.

**Fix:** Strip tz before calling `.dt.to_period()`:

```python
# line 313
net_new_mask = ff_ts.dt.tz_localize(None).dt.to_period("M") == month_period

# line 318
rs_in_month = (
    rs_ts.notna()
    & (rs_ts.dt.tz_localize(None).dt.to_period("M") == month_period)
)
```

Note: `tz_localize(None)` on a tz-aware Series removes the timezone info without
converting the wall-clock values (equivalent to `tz_convert(None)` which also removes it),
matching the pattern used in `accepted_recast_module.py:330`.

---

### WR-03: Owner-snapshot failure exits code 3 despite comment saying "Non-fatal"

**File:** `scripts/capture_trend_snapshot.py:322-326`

**Issue:** The exception handler for the owner-dimension snapshot logs
`"Non-fatal: severity snapshot already succeeded; log and continue."` but then immediately
executes `return 3`. Exit code 3 is defined in the module docstring as
`"fetch or write failure"`. This means a transient owner-snapshot failure (e.g. a one-time
`extract_owner` crash) causes the entire cron job to report failure to the scheduler,
potentially suppressing the severity snapshot's success status, triggering alerts, and
causing the operator to believe the severity snapshot also failed.

If the intent is truly non-fatal, the handler should `continue` (not return). If the
intent is to signal partial success, code 3 is the wrong signal — it is indistinguishable
from a severity-snapshot failure.

**Fix:** Decide the intended contract and implement it consistently:

```python
# Option A — truly non-fatal (continue without exiting):
except Exception as exc:
    logger.exception("capture_snapshot (owner) failed: %s", exc)
    logger.warning("Owner snapshot failure is non-fatal; severity snapshot already succeeded.")
    _log_completed(logger, start, "partial", f"owner-snapshot: {exc}")
    # Fall through to return 0 below

# Option B — signal partial success with a distinct exit code:
# Change `return 3` to `return 1` and document code 1 = "partial success"
# (severity OK, owner failed). This distinguishes it from a severity failure.
```

---

### WR-04: `accepted_recast_module.py` crashes on vulns_df missing `severity_modification_type`

**File:** `reports/modules/accepted_recast_module.py:224`

**Issue:** The empty-data guard at line 216 checks `vulns_df.empty or "state" not in
vulns_df.columns`. If `vulns_df` is non-empty but is missing the
`severity_modification_type` column (e.g. an older fetcher schema or a filtered-down
DataFrame where the column was dropped), execution falls through to line 224:

```python
mod_type = vulns_df["severity_modification_type"].astype(str).str.upper()
```

This raises `KeyError: 'severity_modification_type'`, which is caught by the outer
`except Exception` (line 474) and returned as an `_empty_result` with an error. Fail-soft
means no crash, but an unexpected `KeyError` produces a confusing error message rather than
a clean "column missing" diagnosis.

The parallel module `reopened_vulns_module.py` guards `"state" not in vulns_df.columns`
explicitly. `accepted_recast_module.py` should guard its required column too.

**Fix:** Extend the empty-data guard:

```python
if (
    vulns_df.empty
    or "state" not in vulns_df.columns
    or "severity_modification_type" not in vulns_df.columns
):
    return self._build_zero_exception_result(config, green_threshold, yellow_threshold)
```

---

### WR-05: `render_excel_tabs` in `accepted_recast_module.py` sets column widths for 5 columns but only writes 4

**File:** `reports/modules/accepted_recast_module.py:824`

**Issue:** The `widths` list is `[28, 14, 14, 14, 20]` — five entries. The `for` loop
iterates `enumerate(widths, start=1)`, setting widths for columns A through E. However,
the per-owner table only writes data into columns 1–4 (Owner, Accepted, Recasted, Total).
Column E (index 5) is set to width 20 but receives no data. This is a minor inconsistency
that wastes a column slot but causes no crash.

**Fix:** Align `widths` with the four data columns:

```python
widths = [28, 14, 14, 14]
for col_idx, w in enumerate(widths, start=1):
    ws.column_dimensions[get_column_letter(col_idx)].width = w
```

---

## Info

### IN-01: `safe_format` imported but never used in four modules

**File:**
- `reports/modules/reopened_vulns_module.py:47`
- `reports/modules/external_dmz_module.py:47`
- `reports/modules/new_vs_remediated_module.py:46`
- `reports/modules/accepted_recast_module.py:62`

**Issue:** All four files import `safe_format` from `format_utils` but never call it in
the module body. (`vuln_density_module.py` does use it.) The import is harmless but is
flagged by linters and creates a misleading impression that the value is used.

**Fix:** Remove `safe_format` from the import line in each of the four files, or add a
`# noqa: F401` comment if the import is kept intentionally as a re-export.

---

### IN-02: `_rag_fill` defined in three modules that never call it

**File:**
- `reports/modules/reopened_vulns_module.py:76`
- `reports/modules/external_dmz_module.py:77`
- `reports/modules/new_vs_remediated_module.py:69`

**Issue:** `_rag_fill` is defined at module level in all five new modules (copied from the
PATHFINDER shape) but is only called in `vuln_density_module.py` (line 635) and
`accepted_recast_module.py` (line 820). The three other modules define the function and
never invoke it.

**Fix:** Remove the `_rag_fill` definition from the three modules that do not use it, or
move it to a shared Excel styling helper if row-level RAG fill is expected to be added to
those modules in future plans.

---

### IN-03: `_safe_mom_delta` defined but never called in `new_vs_remediated_module.py`

**File:** `reports/modules/new_vs_remediated_module.py:83`

**Issue:** `_safe_mom_delta` is defined at module level (lines 83–106) and is well
documented. However, it is never called anywhere in the file. The module uses inline string
formatting for its MoM display (e.g. `safe_int(nd)` in `table_data`) rather than going
through this helper. The function's docstring describes percentage formatting
(`"+12.5%"`, `"-3.2%"`) which does not match the current `table_data` representation
(raw integer delta, not a percentage string).

This is likely a leftover from an earlier design iteration that was superseded before the
function was used.

**Fix:** Remove `_safe_mom_delta` if it is not needed, or wire it into the MoM delta
display if percentage-format deltas are a future requirement.

---

### IN-04: `NO_DATA_DRIVER`, `STATUS_COLOR`, `STATUS_LABEL` imported but unused in `reopened_vulns_module.py`

**File:** `reports/modules/reopened_vulns_module.py:49,51,52`

**Issue:** The import block pulls in `NO_DATA_DRIVER`, `STATUS_COLOR`, and `STATUS_LABEL`
from `rag_utils`. None of these three names appear anywhere in the module body. (The module
uses `NO_DATA_HEADLINE`, `build_rag_strip_entry`, and `rag_status_from_value` — all of
which are used.)

**Fix:** Remove the three unused names from the import:

```python
from reports.modules.rag_utils import (
    NO_DATA_HEADLINE,
    build_rag_strip_entry,
    rag_status_from_value,
)
```

---

### IN-05: Owner-snapshot in `capture_trend_snapshot.py` does not pass Phase-15 aggregate counts

**File:** `scripts/capture_trend_snapshot.py:317-320`

**Issue:** The severity-dimension `capture_snapshot` call (lines 297-304) correctly passes
`on_time_asset_count`, `reopened_count`, `accepted_count`, `recast_count`, and
`fixed_vulns_df`. The owner-dimension call (lines 317-319) passes none of these. This is
not a bug per the current spec — `capture_snapshot` defaults all new params to `None`, and
the owner snapshots are not consumed by any Phase-15 module. However, the inconsistency
means the owner-dimension snapshots will never carry the Phase-15 aggregate fields even
when the data is available, which may become a gap if future modules read owner-dimension
trend snapshots and expect those fields.

**Fix:** No immediate action required. Document the gap in the owner-dimension call as a
known limitation, or pass the same Phase-15 kwargs to the owner call for completeness:

```python
owner_path = capture_snapshot(
    df, assets_df, snapshot_date, "owner", "all_assets",
    enriched_assets=enriched,
    on_time_asset_count=on_time_asset_count,
    reopened_count=reopened_count,
    accepted_count=accepted_count,
    recast_count=recast_count,
    fixed_vulns_df=fixed_vulns_df,
)
```

---

_Reviewed: 2026-06-11T22:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
