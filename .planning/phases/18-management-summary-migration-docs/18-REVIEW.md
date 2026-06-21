---
phase: 18-management-summary-migration-docs
reviewed: 2026-06-21T17:50:00Z
depth: standard
files_reviewed: 16
files_reviewed_list:
  - config.py
  - data/fetchers.py
  - data/trend_store.py
  - reports/management_summary.py
  - run_all.py
  - scripts/backfill_trend_reconstruction.py
  - scripts/capture_management_summary_parity_golden.py
  - scripts/probe_last_fixed_filter.py
  - scripts/smoke_management_summary_cutover.py
  - tests/baselines/management_summary_structural_schema.py
  - tests/test_backfill_reconstruction.py
  - tests/test_consumer_audit.py
  - tests/test_management_summary.py
  - tests/test_phase6_run_group_chrome.py
  - tests/test_trend_store.py
  - docs/management_summary_calculations.md
findings:
  critical: 1
  warning: 8
  info: 5
  total: 14
status: issues_found
---

# Phase 18: Code Review Report

**Reviewed:** 2026-06-21T17:50:00Z
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

Reviewed the Phase 18 management_summary migration: the bespoke ~2,200-line render
path was cut over to `ReportComposer`, the fixed-vuln fetch was widened with a
bounded `last_fixed` integer-epoch filter, and ~12 months of trend history were
reconstructed.

The core migration is largely sound: the consumer-audit gate (`test_consumer_audit.py`)
is a genuinely strong defense against silent metric drift, `open_findings_at` correctly
implements the reopened-aware two-interval predicate, pandas CoW discipline (`.assign()`
only) is honored throughout, and the empty-data/cold-start guards are present.

However, the review surfaced one BLOCKER: the tag-scoped path in
`management_summary.run_report()` is dead — it hardcodes `tio=None` into
`get_assets_by_tag`, guaranteeing an exception on every tag-scoped run and silently
falling back to a different (and weaker) filter. Several WARNINGs concern a
probe-vs-production filter-shape contradiction, a broken-on-import parity-capture
script, a month-boundary semantics contradiction between code and its own docs/docstrings,
and a duplicated dead helper.

## Critical Issues

### CR-01: Tag-scoped management_summary run always throws on the primary path and silently falls back

**File:** `reports/management_summary.py:250-260`
**Issue:** Inside the `if tag_category and tag_value:` block, the primary asset-scoping
call hardcodes `None` as the Tenable client:

```python
from utils.tag_helper import get_assets_by_tag
try:
    filtered_asset_uuids = set(
        get_assets_by_tag(None, tag_category, tag_value)   # tio=None
    )
except Exception:
    # Fallback: filter from in-memory tags_str column
    mask = assets_df["tags_str"].str.contains(...)
    ...
```

`get_assets_by_tag(tio, tag_category, tag_value)` (utils/tag_helper.py:61) calls
`fetch_assets_by_tag(tio, run_id, ...)` which calls `tio.exports.assets(...)`. With
`tio=None` this raises `AttributeError` **every time**. The primary path is therefore
unreachable dead code, and every tag-scoped run silently uses the `except` fallback.

This is a BLOCKER for two reasons:
1. **Correctness divergence:** the two paths do not produce the same scope. `get_assets_by_tag`
   resolves the tag server-side against the live Tenable export (the authoritative semantics
   used everywhere else in the suite). The fallback does an in-memory substring match on the
   `tags_str` display column (`"Category: Value"`), which is a *different* matching rule
   (substring, not exact token; depends on a display-formatted column that may differ from
   the canonical `tags` column used by `filter_by_tag`). Recipients of a tag-scoped report
   get a silently different asset set than the rest of the suite would produce.
2. **Silent failure:** the broad `except Exception` swallows the guaranteed `AttributeError`
   with no log line, violating the project "no silent failures" rule (CLAUDE.md Code Quality).
   An operator never learns the primary path is broken.

**Fix:** Pass the real client through. `run_report` already receives `tio`:

```python
filtered_asset_uuids = set(
    get_assets_by_tag(tio, tag_category, tag_value)
)
```

If an in-memory fallback is genuinely wanted, narrow the `except` to the specific
recoverable error and log a warning before falling back, and match on the canonical
`tags` column (exact `Category=Value` token) rather than `tags_str` substring, so the
two paths agree.

## Warnings

### WR-01: Probe proves a different filter shape than production uses

**File:** `scripts/probe_last_fixed_filter.py:68-111` vs `data/fetchers.py:449-453`
**Issue:** The probe's entire purpose is to de-risk the `last_fixed` filter shape before
the production fetch is built. The probe sends a **dict**:

```python
_FILTER_KEY:   {"date": cutoff_date, "modifier": _FILTER_MODIFIER},   # date-range dict
```

But `fetch_fixed_vulnerabilities` ships a **bare integer epoch**:

```python
"last_fixed": _cutoff_epoch,   # int Unix epoch seconds
```

These are two distinct API filter shapes. The probe never exercised the integer-epoch
shape that production actually uses, yet the docstrings of both the probe and
`fetch_fixed_vulnerabilities` assert the integer-epoch shape was "proven by the Task 0
live probe." The committed probe code contradicts that claim. Either the probe was edited
after the live run, or the shape was never probed as shipped. The production filter
direction/acceptance is effectively unverified by the committed artifact.

**Fix:** Update `_build_export_filters` to send the integer-epoch shape that production
uses (`{_FILTER_KEY: int(epoch_seconds)}`), so the committed probe matches the shipped
filter, and re-run it to re-confirm. At minimum, correct the docstrings so they do not
claim a shape the probe code does not test.

### WR-02: Parity-capture script imports a function the migration deleted — broken on import

**File:** `scripts/capture_management_summary_parity_golden.py:697`
**Issue:** The script does `from reports.management_summary import compute_all_metrics`,
but the atomic cutover removed `compute_all_metrics` (and all `_compute_metric_*`,
`_save_trend_snapshot`, etc.) from `management_summary.py`. `test_bespoke_functions_removed`
in `test_management_summary.py` explicitly asserts these are gone. Running
`capture_management_summary_parity_golden.py --emit-golden` now raises `ImportError`.

The docstring claims this is intentional one-time sequencing ("MUST run while the bespoke
compute path still exists ... atomically removed at cutover"), so the script is dead by
design. But leaving a permanently-broken script committed in `scripts/` with no guard or
archival is a maintenance hazard — a future operator following the documented
`python scripts/capture_..._golden.py --rebuild-fixture --emit-golden` workflow gets a
crash with no explanation. The golden it emits (`management_summary_value_golden.json`) is
still consumed by `test_value_golden_parity`, so the relationship is confusing: the test
depends on an artifact whose generator can no longer run.

**Fix:** Either move the script to a `legacy_archive/` / `_archived/` location (mirroring
the trend `legacy_archive` pattern used elsewhere this phase), or add a hard guard at the
top of `main()` that detects the missing bespoke path and exits with a clear message
("bespoke compute path removed at Phase 18 cutover; this one-time capture script is
retired — the golden is frozen"). Update the docstring's "Usage" block to stop advertising
a runnable workflow.

### WR-03: `month_end_utc` semantics contradict the reconstruction docs and inline comments

**File:** `data/trend_store.py:117-118` vs `scripts/backfill_trend_reconstruction.py:129` & `docs/management_summary_calculations.md:1218,1231`
**Issue:** `month_end_utc` returns the **last second of the month**:

```python
last_day = calendar.monthrange(year, mon)[1]
return datetime(year, mon, last_day, 23, 59, 59, tzinfo=timezone.utc)   # e.g. 2025-10-31 23:59:59
```

The trend_store docstring (lines 78-86) correctly documents this inclusive
`23:59:59` boundary. But the reconstruction documentation and an inline comment describe
the **opposite** semantics:

- `docs/management_summary_calculations.md:1218`: `boundary = month_end_utc(M)   # first instant of month M+1 in UTC`
- `docs/management_summary_calculations.md:1231`: "returns the last instant of month M in UTC (midnight of the first day of M+1)"

"23:59:59 on the last day of M" and "00:00:00 on the first day of M+1" are different
instants. A finding fixed in the one-second gap (e.g. `last_fixed = 2025-11-01 00:00:00`)
is classified differently depending on which definition is believed. The code is internally
consistent (the tests in `test_trend_store.py::TestMonthEndUtcBoundaries` pin `23:59:59`),
so this is a documentation defect — but it is load-bearing documentation an auditor uses to
reason about reconstructed counts, and it states the boundary wrong.

**Fix:** Correct `docs/management_summary_calculations.md` lines 1218 and 1231 (and any
mirrored comment) to state the actual boundary: "last instant of month M = `YYYY-MM-DD
23:59:59 UTC` on the last calendar day of M (inclusive)". Do not change the code.

### WR-04: Duplicated `_months_in_range` helper with an unused dead import

**File:** `scripts/backfill_trend_reconstruction.py:189-228`
**Issue:** `_months_in_range` (line 189) and `_months_in_range_stdlib` (line 211) have
**identical bodies**. The only difference is `_months_in_range` imports
`from dateutil.relativedelta import relativedelta` (line 194) — which it then never uses;
both functions compute months with the same manual `cur_mon += 1` loop. `run_reconstruction`
calls only `_months_in_range_stdlib` (line 380). So `_months_in_range` is dead code that
additionally introduces an unused (and per CLAUDE.md "no new SDK adoption / locked stack")
`dateutil` import that could `ImportError` on a minimal install if the dead function were
ever called.

**Fix:** Delete `_months_in_range` (lines 189-208) entirely and keep
`_months_in_range_stdlib`. The dead `dateutil` import goes with it.

### WR-05: `read_trend` `months` slice does not exclude partial / future months and may surface MTD as a completed point

**File:** `reports/management_summary.py:407-414` and `data/trend_store.py:483-496`
**Issue:** `run_report` calls `read_trend("severity", tag_filter_label, months=13)` to feed
the MoM modules, then unconditionally calls `capture_snapshot(...)` with
`date=generated_at` (the current run time). `capture_snapshot` writes/overwrites a snapshot
keyed to the **current** month. On the same run, the just-written current-month (MTD,
partial) snapshot is the newest entry `read_trend` returns. The MoM-consuming modules
(`new_vs_remediated`, `accepted_recast`, `mttr_trend`) then compute deltas where the latest
point is a partial month-to-date count compared against a complete prior month — which
systematically understates inflow/accepted/recast for the current month and can render a
misleading "improving" delta mid-month.

The docs note the current month is labeled "(MTD — partial)" in module output, which
mitigates display but not the delta math if a module computes `latest − prior` using the
partial point as `latest`. Because capture happens *after* read within the same run, the
first run of a month seeds a partial point that the *next* run then treats as a prior
"completed" month if the read ordering or month rollover interacts unexpectedly.

**Fix:** Confirm each MoM module excludes the current (partial) month from delta math, or
have `read_trend`/the module layer flag the newest entry as partial when its `month` equals
the current local month. At minimum, document the ordering contract (capture-after-read)
explicitly so a future change to read/write ordering does not silently corrupt deltas.

### WR-06: `capture_snapshot` month attribution mixes local-time month key with UTC-derived new/fixed buckets within the same entry

**File:** `data/trend_store.py:390,422-433`
**Issue:** The snapshot `month` key is computed in **server-local** time
(`date.strftime("%Y-%m")`, line 390), but `new_findings_count` / `fixed_findings_count`
are bucketed by converting UTC timestamps to local tz and comparing to that local
`month_str` (lines 422-433). The open-finding severity counts, however, come from
`open_findings_at(df, date)` where `date` is `generated_at` (UTC). So within one snapshot
entry, the severity counts are evaluated at a UTC instant while the inflow/outflow counts
are attributed by local-month membership. Near a month boundary on a non-UTC server, the
severity snapshot can belong to UTC month M while the `month` label and the new/fixed
buckets belong to local month M-1 (or M+1). The code comments acknowledge the local-vs-UTC
skew for new/fixed but do not reconcile it against the UTC `open_findings_at` evaluation
instant, leaving the entry internally inconsistent at the boundary.

**Fix:** Pick one clock for the whole entry. Given CLAUDE.md's timezone policy (report
timestamps UTC; only cache-folder/schedule use local), the cleanest fix is to derive
`month_str` from the UTC `generated_at` as well, so the `month` label, the
`open_findings_at` evaluation, and the new/fixed buckets all agree. If local-month
labeling is a hard requirement, also evaluate `open_findings_at` at the local month
boundary so the entry is coherent.

### WR-07: `_load_trend_json` corrupt-file rename can silently discard a non-dict-but-recoverable file, and the rename is not atomic across the read

**File:** `data/trend_store.py:172-192`
**Issue:** When the JSON root is not a dict (e.g. a bare list — the exact shape the legacy
`management_summary_*.json` files use), `data.get("snapshots", [])` raises `AttributeError`,
the file is renamed to `*.corrupt`, and `[]` is returned. `capture_snapshot` then does a
read-modify-**write** of `{"snapshots": []}` to the original path — so a legacy file that
happened to live at a `trend_*` path would be renamed away and replaced with an empty
snapshot set, permanently losing whatever data it held. The legacy-archive tests confirm
read_trend avoids `legacy_archive/`, but nothing prevents a mis-named legacy file directly
in `trend_dir` from triggering this destructive path. The rename is best-effort and logged,
but the net effect is data loss for any non-`{"snapshots":...}` JSON that lands at a
`trend_*` filename.

**Fix:** Distinguish "parse error / unexpected shape" from "valid but unknown schema."
For a successfully-parsed-but-non-dict root, do not treat it as corrupt-and-renameable;
instead refuse to write over it (raise or return a sentinel that aborts the capture for
that file) so a misplaced file is preserved rather than overwritten. Reserve the `*.corrupt`
rename for genuine `JSONDecodeError`.

### WR-08: `vpr_to_severity` boundary gap silently drops scores in (8.9, 9.0) and (6.9, 7.0) etc. to fallback

**File:** `config.py:95-100,152-157`
**Issue:** `VPR_SEVERITY_MAP` uses inclusive ranges with literal upper bounds `8.9`, `6.9`,
`3.9`:

```python
(9.0, 10.0, "critical"),
(7.0, 8.9, "high"),
(4.0, 6.9, "medium"),
(0.1, 3.9, "low"),
```

A VPR score in an open interval between bands — e.g. `8.95`, `6.95`, `3.95`, or `0.05` —
matches **no** band and falls through to `fallback` (the native severity). VPR scores are
floats and Tenable does emit one-decimal and occasionally finer values; `8.95` is a real
possible score. Per CLAUDE.md the whole point is that VPR severity is authoritative over
native; here a sliver of VPR-scored findings silently revert to native classification,
which can move a finding's tier (and thus its SLA). This is a latent mis-classification,
not a crash, so WARNING.

**Fix:** Make the bands contiguous using half-open lower bounds keyed off the next tier,
e.g. critical `>= 9.0`, high `>= 7.0 and < 9.0`, medium `>= 4.0 and < 7.0`, low
`>= 0.1 and < 4.0`. That removes the gaps and the `8.9/6.9/3.9` magic literals.

## Info

### IN-01: `import math` inside `vpr_to_severity` hot path

**File:** `config.py:147`
**Issue:** `import math` is performed inside the function body, so it re-runs on every call.
`vpr_to_severity` is called once per finding during fetch (potentially >1M rows per the
probe's own numbers). The import is cached by Python so the cost is small, but it is
idiomatic and marginally faster to hoist it to module top-level.
**Fix:** Move `import math` to the top of `config.py`.

### IN-02: `_first_str` defined but only used by the deprecated `fetch_vulnerabilities`

**File:** `data/fetchers.py:163-175,973`
**Issue:** `_first_str` is only referenced by `fetch_vulnerabilities` (line 973), which is
itself marked `.. deprecated::` and slated for removal once `tag_helper.py` is updated. Not
a defect, but flagging the dead-code chain so it is removed together in the follow-up cleanup.
**Fix:** Remove `_first_str` when `fetch_vulnerabilities` / `fetch_assets` are retired.

### IN-03: Docs runbook still describes the removed bespoke render path in several sections

**File:** `docs/management_summary_calculations.md:421-558,627-634`
**Issue:** Sections 12/14/15/17 and Troubleshooting still document the deleted bespoke
internals: `data/trend/management_summary_<tag>.json` filenames (the migration moved these
to `trend_*.json` + `legacy_archive/`), `build_email_body()`, `_build_pdf()`, `_email_preview_html()`,
the `Path.__deepcopy__` monkey-patch, and `--test-gauge/--test-pdf/--test-email` CLI flags
that the migrated `run_report` no longer exposes (the current CLI in `management_summary.py`
only has `--tag-category/--tag-value/--cache-dir/--output-dir/--no-email`). The new v1.4
section (lines 669+) is correct, but the earlier half of the doc describes a code path that
no longer exists, which will mislead an operator.
**Fix:** Reconcile the pre-v1.4 sections with the migrated reality, or clearly mark them as
"pre-v1.4 / historical" the way Group B disclosures are marked.

### IN-04: Stale `_OPEN_STATES` reference in `open_findings_at` docstring

**File:** `utils/open_count.py:49,84`
**Issue:** The docstring references `management_summary._OPEN_STATES` as the source of state
casing ("matching `management_summary._OPEN_STATES`"). `_OPEN_STATES` was removed from
`management_summary.py` in this migration (it is in the deleted-names list in
`test_management_summary.py`). The reference now points at a non-existent symbol.
**Fix:** Update the docstring to drop the `management_summary._OPEN_STATES` reference; the
fetcher's lowercase convention is the real contract.

### IN-05: `LOGO_PATH` defaults to a path that likely does not exist, relying on a render-time fallback

**File:** `config.py:261`
**Issue:** `LOGO_PATH` defaults to `<root>/assets/logo.png` (a concrete Path, not None),
with the comment noting the missing-file fallback lives in `PdfChrome.build_header_html()`.
This is by design per the comment, but it is worth flagging: every chrome-aware report
(now including `management_summary`) ships pointing at a file that may not exist, and the
correctness depends entirely on the render-time fallback being robust. If that fallback
regresses, every PDF header breaks. Not a defect in the reviewed scope; noting the coupling.
**Fix:** None required; consider defaulting to `None` (title-only) unless the asset is
known to ship, so the safe path is the default rather than the exception.

---

_Reviewed: 2026-06-21T17:50:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
