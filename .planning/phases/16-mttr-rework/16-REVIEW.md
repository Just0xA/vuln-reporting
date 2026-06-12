---
phase: 16-mttr-rework
reviewed: 2026-06-12T20:10:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - reports/composed_report.py
  - reports/modules/mttr_trend_module.py
  - scripts/capture_trend_snapshot.py
  - scripts/warm_cache.py
  - tests/test_capture_trend_snapshot_cli.py
  - tests/test_composed_report_kwargs_gates.py
  - tests/test_mttr_trend_module.py
findings:
  critical: 0
  warning: 4
  info: 5
  total: 9
status: resolved
resolution: "WR-01..WR-04 fixed in commit fix(16): resolve code-review warnings (config mutation, safe_format, dead code). Info items left as advisory."
---

# Phase 16: Code Review Report (D-16-13 Gap-Closure)

**Reviewed:** 2026-06-12T20:10:00Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

This gap-closure review covers the D-16-13 change (always-on 4-severity gauge
band + focus-driven Owner/Application tables, superseding the prior `mttr_view`
table-toggle) and the `sys.path` bootstrap fix for two cron scripts. Reviewed
against `diff_base` 4eaf49a.

The diff touches `reports/composed_report.py` (+17, tag-scope injection into the
`mttr_trend` module options), a large rework of
`reports/modules/mttr_trend_module.py` (gauge band / focus routing / Excel
block), the 5-line bootstrap insertions in `scripts/capture_trend_snapshot.py`
and `scripts/warm_cache.py`, and substantial test additions.

The empty-data/cold-start hardening is solid: all four render channels were
exercised against zero-row `ModuleData`; SLA values are sourced from
`config.SLA_DAYS` (verified — no hardcoded `45`/`15` SLA literals in the new
code, only gauge-scale multipliers `*1.25`/`*2` which are legitimate chart
thresholds); and `mttr_by_severity_module.py` is NOT in the diff (board_summary
zero-diff per D-16-10, confirmed). The bootstrap fix is correct and locked by a
real-invocation subprocess regression test. No BLOCKER-class correctness or
security defect was found.

Four WARNING-level defects degrade robustness/correctness: (1) `run_report`
mutates the caller's YAML-loaded `module_options` dict in place; (2) a raw
f-string format spec on a MoM value in the Excel renderer that diverges from the
project's `safe_format` mandate and from the module's own PDF path; (3) a
redundant `module_configs` rebuild tied to the WR-01 mutate-then-rebuild
pattern; and (4) a dead `direction` variable in the Excel block. Five INFO items
follow.

## Warnings

### WR-01: `run_report` mutates the caller's `module_options` dict in place

**File:** `reports/composed_report.py:317-322`
**Issue:** The D-16-13 tag-scope injection block does:

```python
mt_opts = opts_map.setdefault("mttr_trend", {})
if "tag_category" not in mt_opts:
    mt_opts["tag_category"] = tag_category
if "tag_value" not in mt_opts:
    mt_opts["tag_value"] = tag_value
```

`opts_map` is `module_options or {}` (line 306), and `run_all.py:717` passes
`group_config.get("module_options")` — the live YAML-loaded group config dict —
directly as `module_options`. When the group declares a `module_options:` block,
`opts_map` *is* that dict, and `setdefault` + `mt_opts[...] = ...` mutate it in
place. The injected `tag_category` / `tag_value` are then persisted on the
shared config object. In daemon mode YAML hot-reloads every 5 min so blast
radius is bounded, but any path that reuses the loaded config dict across runs
with a *different* tag scope (e.g. a manual `--tag-category`/`--tag-value`
override on a group that already has `module_options.mttr_trend`) sees the
stale, first-run scope shadow the override, because `if "tag_category" not in
mt_opts` now finds the previously-injected key. It also writes `tag_value=None`
into the operator's config dict when no tag filter is active, which then masks
any later real value under the same guard.
**Fix:** Build the augmented options into a fresh dict; never mutate `opts_map`
or its nested entries:

```python
if "mttr_trend" in modules:
    base = dict(opts_map.get("mttr_trend", {}) or {})
    base.setdefault("tag_category", tag_category)
    base.setdefault("tag_value", tag_value)
    opts_map = {**opts_map, "mttr_trend": base}
    module_configs = [
        ModuleConfig(module_id=mid, options=dict(opts_map.get(mid, {}) or {}))
        for mid in modules
    ]
```

### WR-02: Raw f-string format spec on a MoM value in the Excel renderer

**File:** `reports/modules/mttr_trend_module.py:1196`
**Issue:** CLAUDE.md is explicit: "Inline f-string format specs on possibly-None
values are forbidden — use `safe_format`/`safe_int`/`safe_pct`." The Excel
severity block uses a bare spec:

```python
mom_str = f"{mom_delta:+.1f}d"
```

The guard `if mom_delta is not None` prevents the `None` crash, but the module's
own PDF path (line 1027) formats the identical value with
`safe_format(mom, "+.1f")`. This Excel line is an inconsistent,
convention-violating divergence that the project rule says to flag at review,
and it forgoes the helper's `pd.isna`/non-float defense. The numeric cell writes
(`mttr_val`, `sample_size`, raw `mom`) at lines 1200-1204 and 1219-1224 write
numpy scalars from `days_to_fix` straight into openpyxl; tolerated by current
openpyxl but fragile and untested.
**Fix:** Mirror the PDF path:

```python
mom_str = (safe_format(mom_delta, "+.1f") + "d") if mom_delta is not None else "—"
```

and cast numeric cell values to Python scalars (`float(...)` / `int(...)`)
before `ws.cell(..., value=...)`.

### WR-03: Redundant `module_configs` build immediately discarded

**File:** `reports/composed_report.py:307-310` then `324-327`
**Issue:** `module_configs` is built at 307-310, then — when `mttr_trend` is in
`modules` — rebuilt identically at 324-327 after the opts mutation. The first
list is always discarded whenever the injection block runs; the two
comprehensions are identical except for the (mutated) `opts_map`. This is wasted
work and signals the fragile mutate-then-rebuild pattern behind WR-01.
**Fix:** Construct `module_configs` exactly once, after the (non-mutating, per
WR-01) opts augmentation. Remove the first comprehension.

### WR-04: Dead `direction` variable in Excel severity block

**File:** `reports/modules/mttr_trend_module.py:1192-1193`
**Issue:** Inside `_write_sev_numeric_rows`:

```python
direction = per_sev_mom_direction.get(sev_name.lower(), "flat")
mom_delta = row.get("mom_delta")
```

`direction` is computed but never read — the Excel cell only writes the numeric
`mom_str`. The whole reason `per_sev_mom_direction` is threaded into
`render_excel_tabs` (line 1152) is dead for this block. Either the arrow glyph
was meant to be appended to the Excel cell (matching the PDF gauges) and was
dropped, or the lookup is vestigial.
**Fix:** Remove the unused `direction` line, or append the token if the Excel
cell is supposed to carry direction. Decide intent; do not leave a
computed-but-unused MoM direction in a numeric channel.

## Info

### IN-01: `validate_config` does not cover injected `tag_category` / `tag_value`

**File:** `reports/modules/mttr_trend_module.py:1389-1414`
**Issue:** `validate_config` covers `mttr_window_days`, `min_sample_size`, and
`mttr_table`, but not the new injected scope keys. They are framework-injected
so this is acceptable; however a stray operator-supplied `tag_value` without
`tag_category` silently resolves to `owner` mode with no warning.
**Fix:** Optional debug log when only one of the pair is present.

### IN-02: Per-severity MoM arrow can lag the live gauge value by up to one month

**File:** `reports/modules/mttr_trend_module.py:690-697`
**Issue:** Per-severity MoM direction reuses `_owner_mom_delta(sev_series[sev])`
(compares `series[-1]` vs `series[-2]` of deduped sorted snapshot months). When
the current partial month is absent from snapshots, the "MoM" is
prior-vs-prior-prior, not current-vs-prior, while the gauge VALUE is live
`fixed_df`. This matches the documented independent-cold-start design and the
tests, so it is intentional — flagged so the semantics are recorded.
**Fix:** None required; consider a one-line source comment.

### IN-03: `extract_owner` called twice in `capture_trend_snapshot.py`

**File:** `scripts/capture_trend_snapshot.py:361-366` and `409-410`
**Issue:** `extract_owner(assets_df)` runs once for the MTTR-by-owner aggregate
and again for the owner-dimension snapshot, each re-importing and re-enriching.
Performance is out of v1 scope and the calls sit in separate try-blocks, so this
is informational.
**Fix:** Optionally enrich once and reuse.

### IN-04: `smt_upper` fallback uses obscure `.where(False, "")` construction

**File:** `scripts/capture_trend_snapshot.py:277-279`
**Issue:** When `severity_modification_type` is absent, the fallback
`df["state"].astype(str).str.upper().where(False, "")` builds an all-`""` series
so `accepted_count`/`recast_count` correctly fall to 0. Correct but obscure.
**Fix:** Optional readability: `pd.Series("", index=df.index)`.

### IN-05: Several tests lock exact Unicode glyphs / wording (brittle by design)

**File:** `tests/test_mttr_trend_module.py:397, 1196-1268`
**Issue:** Assertions match exact `&#9660;` / `&#8212;` / `—` glyphs and the
literal "Insufficient data (3 findings — minimum 5 required)" string. Acceptable
as a regression lock but tightly coupled to cosmetic source details.
**Fix:** None required; noted for maintainers.

---

_Reviewed: 2026-06-12T20:10:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
