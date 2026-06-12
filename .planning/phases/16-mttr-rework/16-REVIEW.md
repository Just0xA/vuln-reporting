---
phase: 16-mttr-rework
reviewed: 2026-06-12T12:45:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - data/trend_store.py
  - scripts/capture_trend_snapshot.py
  - reports/modules/mttr_trend_module.py
  - reports/composed_report.py
  - tests/test_mttr_trend_module.py
  - tests/test_board_summary_baseline.py
  - pytest.ini
findings:
  critical: 0
  warning: 5
  info: 4
  total: 9
status: issues_found
---

# Phase 16: Code Review Report

**Reviewed:** 2026-06-12T12:45:00Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

Phase 16 reworks MTTR into a reopened-aware, rolling-window, sample-weighted metric
with a month-over-month (MoM) trend persisted through the snapshot engine. The code
is well-documented and clearly carries forward prior review discipline (CoW `.assign()`,
explicit-null cold-start convention, fail-soft batch semantics, aggregate-only PII
discipline). No BLOCKER-class defects were found: no injection, no credential leakage,
no data-loss path, no crash on the documented happy or cold-start paths.

The substantive concerns are **two correctness divergences that the test suite cannot
catch because they live in the cron script, not the module**:

1. The capture script (`capture_trend_snapshot.py`) hardcodes the MTTR window to 30
   days and `min_sample` to 5, while the module (`mttr_trend_module.py`) reads both
   from per-group YAML config. A group that overrides `mttr_window_days` will see its
   live gauge and its persisted MoM line computed over *different* windows — a silent
   apples-to-oranges trend.
2. The module's per-severity filter (`mttr_trend_module.py:411`) calls `.str.lower()`
   on the `severity` column without the defensive `.astype(str)` guard that the rest
   of the codebase (and even the sibling capture script at line 351) applies. This is
   a latent crash on a non-object severity column.

The remaining warnings are robustness gaps (duplicate MTTR computation across two
files, an unvalidated assumption that `fixed_df` carries `severity`/`asset_uuid`).
Info items are duplication and a test docstring that over-claims its guarantee.

## Warnings

### WR-01: Module reads `mttr_window_days`/`min_sample_size` from config, but the snapshot writer hardcodes both — live gauge and MoM line diverge

**File:** `scripts/capture_trend_snapshot.py:308,348` and `reports/modules/mttr_trend_module.py:313-314`
**Issue:**
`MTTRTrendModule.compute()` derives the window and sample threshold from the recipient
group's YAML options:

```python
window_days = int(config.options.get("mttr_window_days", 30))
min_sample  = int(config.options.get("min_sample_size", 5))
```

But the persisted MoM series comes from `capture_trend_snapshot.py`, which hardcodes
both:

```python
window_days = 30  # line 308 — configurable in future; default per D-16-04
MIN_SAMPLE = 5     # line 348
```

The module's PDF/email render and MoM line are both labelled "Rolling {window_days}-day
MTTR". If any group sets `module_options: { mttr_trend: { mttr_window_days: 14 } }`,
its live gauge will read a 14-day window while every persisted snapshot it plots was
computed over 30 days. The chart then overlays two metrics that are not comparable, with
a single window-days disclosure that is correct for only one of them. The discrepancy is
invisible to the test suite because every test drives `compute()` directly with synthetic
`trend_snapshots`; nothing exercises the capture→read round trip with a non-default window.

**Fix:** Make the capture script honor the same default constant and (ideally) record the
window it used in the snapshot entry so `read_trend` consumers can detect a mismatch.
At minimum, hoist `window_days`/`min_sample` to a shared `config.py` constant
(e.g. `MTTR_WINDOW_DAYS = 30`, `MTTR_MIN_SAMPLE = 5`) imported by both the module default
and the capture script, so the two cannot drift:

```python
# config.py
MTTR_WINDOW_DAYS = 30
MTTR_MIN_SAMPLE  = 5
# capture_trend_snapshot.py
from config import MTTR_WINDOW_DAYS, MTTR_MIN_SAMPLE
window_days = MTTR_WINDOW_DAYS
MIN_SAMPLE  = MTTR_MIN_SAMPLE
# mttr_trend_module.py
window_days = int(config.options.get("mttr_window_days", MTTR_WINDOW_DAYS))
```
If per-group window override is genuinely intended, persist `window_days` in each
snapshot entry and have the module skip/flag snapshots whose window differs from the
live window.

### WR-02: `.str.lower()` on `severity` without `.astype(str)` guard — latent crash, inconsistent with sibling code

**File:** `reports/modules/mttr_trend_module.py:411`
**Issue:**
```python
sev_df = fixed_df[fixed_df["severity"].str.lower() == sev]
```
This relies on `severity` always being an object/string column. The codebase deliberately
guards this everywhere else — `utils/open_count.py:93` uses `df["state"].astype(str).str.upper()`
with an explicit comment about non-object dtype raising `AttributeError`, and the *sibling*
capture script applies the guard at `capture_trend_snapshot.py:351`:
```python
sev_df = windowed[windowed["severity"].astype(str).str.lower() == sev]
```
If `fetch_fixed_vulnerabilities` ever returns a `fixed_vulns_df` whose `severity` column
is all-null (inferred `float64`) or categorical — e.g. an empty-after-filter frame that
still has a non-object `severity` dtype — `.str` raises `AttributeError`, which is caught
by the broad `except Exception` at line 704 and silently degrades the *entire* module to
`_empty_result`. The MTTR section then renders an error box instead of the per-severity
gauges, with no indication the cause was a dtype edge, not missing data.

**Fix:** Match the guard used elsewhere in the file's own ecosystem:
```python
sev_df = fixed_df[fixed_df["severity"].astype(str).str.lower() == sev]
```

### WR-03: Per-severity/owner MTTR computed twice with subtly different rounding — drift risk between persisted and live values

**File:** `scripts/capture_trend_snapshot.py:345-371` and `reports/modules/mttr_trend_module.py:389-482`
**Issue:**
The `days_to_fix` clock, windowing, per-severity mean, and per-owner mean are implemented
*independently* in two places: the capture script (which persists them) and the module
(which recomputes them live for the gauges). The two are meant to be the same calculation,
but they already differ in rounding precision — the capture script rounds to 2 decimals
(`round(..., 2)`, lines 345/353/369) while the module rounds to 1 (`round(..., 1)`,
lines 390/435/477). A reader comparing the current-month MoM point (persisted, 2dp) against
the live overall gauge (1dp) can see two different numbers for the same month. More
seriously, any future fix to the clock math must be made in both places or the MoM line
silently diverges from the gauge it sits next to.

**Fix:** Extract the windowed `days_to_fix` + per-bucket mean logic into a single shared
pure function (e.g. `utils/mttr.py: compute_mttr(fixed_df, report_date, window_days,
min_sample) -> {overall, by_severity, by_owner}`) and call it from both the capture script
and the module. Standardize the rounding precision in that one place.

### WR-04: `compute()` assumes `fixed_df` carries `asset_uuid` for the Owner cut but never guards the column the way it guards `severity`/date columns

**File:** `reports/modules/mttr_trend_module.py:451-452`
**Issue:**
The date and severity accesses are all column-guarded (`if "severity" in fixed_df.columns`,
the `_nat_series` fallbacks for `last_fixed`/`first_found`/`resurfaced_date`). The Owner cut
is guarded for `asset_uuid` presence at line 451 (`if "asset_uuid" in fixed_df.columns and
uuid_to_owner`), which is good — but `extract_owner(assets_df)` at line 446 assumes
`assets_df` produces an `owner` column and a usable `asset_uuid`. If `assets_df` lacks
`asset_uuid` entirely (not merely empty), `dict(zip(enriched_assets["asset_uuid"], ...))`
at line 448 raises `KeyError`, again swallowed into a full-module `_empty_result`. The
guard at 451 protects `fixed_df` but not `enriched_assets`.

**Fix:** Guard the `enriched_assets` access symmetrically:
```python
enriched_assets = extract_owner(assets_df)
uuid_to_owner = (
    dict(zip(enriched_assets["asset_uuid"], enriched_assets["owner"]))
    if {"asset_uuid", "owner"}.issubset(enriched_assets.columns) and not enriched_assets.empty
    else {}
)
```

### WR-05: `accepted_count`/`recast_count` fallback path builds an all-empty-string Series via `.where(False, "")` — obscure and fragile

**File:** `scripts/capture_trend_snapshot.py:274-278`
**Issue:**
```python
smt_upper = df["severity_modification_type"].astype(str).str.upper() \
    if "severity_modification_type" in df.columns \
    else df["state"].astype(str).str.upper().where(False, "")
accepted_count = int(smt_upper.isin({"ACCEPTED"}).sum())
recast_count = int(smt_upper.isin({"RECASTED"}).sum())
```
The `else` branch coerces `state` to upper, then `.where(False, "")` replaces *every*
element with `""` — an indirect way of producing an all-empty Series shaped like `df`.
This works, but it is non-obvious and depends on `state` being present (if both
`severity_modification_type` and `state` are absent the line raises `KeyError`). The intent
("zero accepted/recast when the column is missing") is better expressed directly.

**Fix:**
```python
if "severity_modification_type" in df.columns:
    smt_upper = df["severity_modification_type"].astype(str).str.upper()
    accepted_count = int((smt_upper == "ACCEPTED").sum())
    recast_count   = int((smt_upper == "RECASTED").sum())
else:
    accepted_count = recast_count = 0
```

## Info

### IN-01: `_format_scope_subtitle` and `_filter_assets_by_tag` duplicated verbatim from `board_summary.py`/`run_all.py`

**File:** `reports/composed_report.py:55-61,443-479`
**Issue:** Both helpers are copied verbatim with comments explaining the duplication is
intentional (to avoid a circular import / per a plan rule). This is acknowledged tech debt,
not a defect — flagging only so the divergence risk is on record: a future fix to tag
matching in `board_summary._filter_assets_by_tag` will not propagate here.
**Fix:** None required now. If the circular-import constraint is ever lifted, consolidate
into `utils/tag_helper.py`.

### IN-02: `registry._modules` accessed via private attribute in two places

**File:** `reports/composed_report.py:175` and `tests/test_mttr_trend_module.py:182`
**Issue:** `registry._modules.keys()` (and `registry._modules` in the test) reach into a
name-mangled private. The `# noqa: SLF001` on line 175 acknowledges it. A public accessor
(`registry.registered_ids()`) would decouple callers from the internal dict.
**Fix:** Add a thin public accessor on the registry and use it in both call sites.

### IN-03: Board-summary baseline test docstring claims "byte-identical" but the test never compares bytes

**File:** `tests/test_board_summary_baseline.py:2-4,22-24`
**Issue:** The module docstring states the baselines are proven "byte-identical" and
"Assert the three files are byte-identical to themselves (no re-write has occurred)."
The actual tests assert JSON self-consistency (`compare_snapshots(b, b) == []`) and a
hard-coded structural fingerprint — they do not hash or byte-compare the files. The
tamper-evidence the docstring promises is delivered by `git diff`, not by this test. The
docstring over-states the in-test guarantee.
**Fix:** Reword the docstring to "structural-fingerprint identical" / "git diff is the
byte-level tamper evidence; this test guards the structural fingerprint", or add an actual
`hashlib` digest comparison against a committed expected hash if byte-level is intended.

### IN-04: `read_trend` post-filter + warning is dead in the happy path and re-sorts already-sorted data

**File:** `data/trend_store.py:459-467`
**Issue:** The file is already tag-scoped by its filename, so the `relevant = [s for s in
all_snaps if s.get("tag_filter") == tag_filter]` filter is, by the code's own comment,
"redundant in the happy path." It is retained as a divergence detector (good), but the
subsequent `.sort()` runs unconditionally on every read even though `capture_snapshot`
appends in month order. This is correctness-neutral; noted only as minor dead-ish work.
**Fix:** None required — the guard's observability value justifies it. Optionally skip the
re-sort when `relevant is all_snaps`.

---

_Reviewed: 2026-06-12T12:45:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
