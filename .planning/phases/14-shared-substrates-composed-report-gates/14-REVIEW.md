---
phase: 14-shared-substrates-composed-report-gates
reviewed: 2026-06-11T18:24:00Z
depth: standard
files_reviewed: 8
files_reviewed_list:
  - config.py
  - utils/external_scope.py
  - utils/asset_count.py
  - reports/composed_report.py
  - reports/modules/sc4_kwargs_stub_module.py
  - tests/test_external_scope.py
  - tests/test_asset_count.py
  - tests/test_composed_report_kwargs_gates.py
findings:
  critical: 0
  warning: 3
  info: 4
  total: 7
status: issues_found
---

# Phase 14: Code Review Report

**Reviewed:** 2026-06-11T18:24:00Z
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found

## Summary

Reviewed the Phase 14 in-scope additions: the `ON_TIME_SCAN_WINDOW_DAYS`
constant (`config.py`), the new `external_scope` and `count_on_time_assets`
substrates, the two new kwargs-forwarding frozensets / fetch blocks /
`composer_kwargs` appends in `composed_report.py`, the SC#4 acceptance stub,
and the three test modules.

The kwargs-forwarding gate wiring is correct end-to-end: `composer_kwargs`
flows into `ReportComposer.__init__(**kwargs)` → `self._kwargs` →
`compute(**self._kwargs)`, and the stub reads `trend_snapshots` /
`recast_rules_df` via `kwargs.get()`. The frozenset `.intersection()`
short-circuit correctly leaves existing composed-report groups untouched
(SC#3). `run_report()`'s public signature is unchanged (D-15). Tag-authoritative
classification, the public-IP gap detector, the DMZ/External case-sensitivity
split, and the `None`-vs-`0` sentinel discipline are all implemented as
specified and well covered.

No Critical/Blocker defects. Three Warnings concern a latent tz-comparison
crash in `count_on_time_assets` that contradicts its own docstring contract and
is not exercised by any test, a fail-soft gap where the trend/recast gates make
unguarded network/IO calls that can abort the batch, and an `external_scope`
schema-assumption that crashes when expected mismatch columns are absent.

## Warnings

### WR-01: `count_on_time_assets` crashes on a tz-naive `last_licensed_scan_date` column — contradicts its own docstring contract

**File:** `utils/asset_count.py:121-130`
**Issue:** The function normalizes only `report_date` to a tz-aware UTC
`Timestamp` (lines 122-125), making `cutoff` tz-aware. It then compares the raw
column directly: `int((licensed[_LSD] >= cutoff).sum())`. If
`last_licensed_scan_date` is a **tz-naive** `datetime64[ns]` column, pandas
raises `TypeError: Cannot compare tz-naive and tz-aware timestamps`, which
propagates out of this pure-compute substrate and (per the empty-data hardening
mandate / fail-soft batch semantics) can abort a delivery group.

The docstring explicitly claims (lines 90-94) "The tz-normalization mirrors
`scan_coverage_sla_module.py` lines 262-265: tz-aware dates are
`tz_convert("UTC")`; tz-naive dates are assigned UTC directly." That mirroring
is applied to `report_date` only — the **column** receives no such
normalization, so the stated contract is not actually met. Every test fixture
builds the column with `pd.to_datetime(dates, utc=True)` (always tz-aware), so
the tz-naive-column path is never exercised and the latent crash is invisible to
the suite.
**Fix:** Normalize the column to UTC before comparing (mirroring how the
reference module's `_lsd` is handled), e.g.:
```python
lsd = licensed[_LSD]
if getattr(lsd.dt, "tz", None) is not None:
    lsd = lsd.dt.tz_convert("UTC")
else:
    lsd = lsd.dt.tz_localize("UTC")
on_time_count = int((lsd >= cutoff).sum())
```
And add a test fixture whose column is tz-naive (`pd.to_datetime(dates)` without
`utc=True`) to lock the path.

### WR-02: Trend/recast gate fetches run outside any try/except — a fetch failure aborts the whole composed report

**File:** `reports/composed_report.py:206-226`
**Issue:** The two new gate blocks call `read_trend(...)` (line 215, file IO +
JSON parse) and `fetch_recast_rules(tio, cache_dir)` (line 226, live HTTP +
parquet write) directly in `run_report()` with no surrounding error handling.
By contrast, the downstream PDF (lines 366-374) and Excel (lines 380-389)
generation are each individually wrapped in `try/except` so a single channel
failure does not sink the report. A raise from `read_trend`/`fetch_recast_rules`
(corrupt cache, transient API/network error after tenacity exhausts, parquet
write error) therefore propagates out of `run_report()` and, under fail-soft
batch semantics, takes down the entire group's bundle — even though the
modules' own `compute()` methods are designed to fail soft. This widens the
blast radius of an upstream IO error from "one module renders no-data" to "no
report at all."
**Fix:** Wrap each gate fetch so a failure degrades to "kwarg absent" (the stub
and any real module already handle a missing kwarg via `_empty_result`):
```python
if need_trend:
    try:
        from data.trend_store import read_trend, _sanitise_tag_for_filename
        ...
        trend_snapshots = read_trend(dimension="severity",
                                     tag_filter=_trend_tag_filter, months=13)
    except Exception as exc:
        logger.error("composed_report: trend read failed: %s", exc, exc_info=True)
        trend_snapshots = None
```
Same pattern for the recast block.

### WR-03: `external_scope` mismatch builder assumes `asset_uuid` exists — `KeyError` on a tags+ipv4 frame that lacks it

**File:** `utils/external_scope.py:203-210`
**Issue:** The guard at lines 141-149 only checks for `"tags"` and `"ipv4"`.
When a gap row exists (`gap_raw` non-empty) the mismatch builder unconditionally
reads `gap_raw["asset_uuid"]` (line 205). A DataFrame that has `tags` and `ipv4`
but no `asset_uuid` column (a plausible shape from a partial/renamed export)
passes the guard, produces a non-empty `gap_raw`, and then raises `KeyError:
'asset_uuid'` inside the classifier. Because this module is documented as pure /
fail-soft (QUAL-03, "Neither frame is ever None... fail-soft"), an unguarded
`KeyError` here violates the stated contract and can abort the batch. The
empty-`gap_raw` branch (lines 194-198) is safe; only the populated branch is
exposed.
**Fix:** Either add `asset_uuid` to the required-column guard at line 141, or
build the column defensively:
```python
"asset_uuid": gap_raw["asset_uuid"].to_numpy()
              if "asset_uuid" in gap_raw.columns
              else pd.Series([pd.NA] * len(gap_raw)).to_numpy(),
```
Given D-11 names `asset_uuid` as a required output column, adding it to the
guard is the cleaner fix.

## Info

### IN-01: `env_vuln_total` computed even when `tag_severity_share` is absent (wasted work, but harmless)

**File:** `reports/composed_report.py:240-244`
**Issue:** `env_vuln_total` is always computed from `vulns_df["state"]`
regardless of whether any module in the composition needs it (the gate is only
applied later, at line 325, when appending to `composer_kwargs`). This is
pre-existing (commit 4ad9694, out of strict scope) but is adjacent to the new
gate appends and worth noting: the trend/recast/fixed gates avoid their work
when not needed, while this one does not. No correctness impact —
`.str.lower().isin(...)` on an empty/absent column is guarded by the
`if "state" in vulns_df.columns` check.
**Fix:** Optional — gate the computation behind
`if _MODULES_NEEDING_ENV_TOTAL.intersection(modules):` to match the other gates'
do-work-only-when-needed pattern.

### IN-02: Recast gate triggers a full live HTTP export for a test-only stub module

**File:** `reports/composed_report.py:221-226` / `reports/modules/sc4_kwargs_stub_module.py`
**Issue:** Listing `sc4_kwargs_stub` in a real delivery group's `modules:` now
causes `fetch_recast_rules()` (a live `POST /v1/recast/rules/search` export +
parquet write) to run. The stub's own docstring says "NOT for production
delivery groups," so this is by design for acceptance testing, but it is a sharp
edge: an operator who pastes the stub into a production composition to "see what
it does" incurs a real API export job. Acceptable as designed; flagged so the
phase-15 real modules that replace the stub in these frozensets get a second
look at fetch cost.
**Fix:** None required for Phase 14. When the stub is removed from the
frozensets (D-17, future phase), confirm the replacement module genuinely needs
the recast export.

### IN-03: Window-boundary comment in `test_some_assets_stale` misstates the inclusive boundary

**File:** `tests/test_asset_count.py:58-62`
**Issue:** The docstring/comment says "Only assets within the window
(< window_days ago) are counted." The actual (and tested) boundary is **inclusive
at exactly `window_days`** (`>= cutoff`), as `test_boundary_exactly_at_cutoff_is_counted`
confirms. The `< window_days` phrasing is a minor doc inaccuracy that could
mislead a future reader into thinking the boundary is exclusive.
**Fix:** Reword to "(<= window_days ago / >= cutoff, inclusive)".

### IN-04: `registry._modules` private-member access in error path

**File:** `reports/composed_report.py:162`
**Issue:** `sorted(registry._modules.keys())` reaches into a private attribute
(already `# noqa: SLF001`-annotated). The composer uses the same pattern
(`composer.py:526`), so this is consistent with the codebase, but a public
accessor (e.g. `registry.registered_ids()`) would be more robust to internal
registry refactors. Pre-existing line, low priority.
**Fix:** Optional — expose a public read accessor on `registry` and use it here
and in `composer.run_module`.

---

_Reviewed: 2026-06-11T18:24:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
