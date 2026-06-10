---
phase: 13-owner-segmentation-composition-s2-doc
reviewed: 2026-06-10T18:30:00Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - data/trend_store.py
  - reports/board_summary.py
  - reports/modules/aged_vulns_assets_module.py
  - reports/modules/board_report_utils.py
  - reports/modules/critical_remediation_sla_module.py
  - reports/modules/high_risk_assets_module.py
  - reports/modules/scan_coverage_sla_module.py
  - reports/owner_supplemental.py
  - scripts/capture_trend_snapshot.py
  - tests/content/test_trend_store.py
  - tests/unit/test_owner_segmentation.py
  - docs/trend_and_segmentation_calculations.md
findings:
  critical: 1
  warning: 6
  info: 4
  total: 11
status: issues_found
---

# Phase 13: Code Review Report

**Reviewed:** 2026-06-10T18:30:00Z
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

Phase 13 generalizes the board-report segmentation dimension from `Application` to
`Owner`, adds an owner-dimension trend snapshot to `data/trend_store.py`, introduces
the `reports/owner_supplemental.py` writer wired into `board_summary.py`, and ships an
auditor runbook (`docs/trend_and_segmentation_calculations.md`).

The module-level code is generally careful — empty-data guards, CSV-injection guards,
and `.assign()`-based dtype preservation are consistently applied. The most serious
issues are: (1) a `set_index("asset_uuid")` in the supplemental writer that will raise
when assets share a UUID after dedup-free enrichment, producing a silent fail-soft loss
of the supplemental; (2) a documentation/implementation contract break — the runbook and
the `capture_trend_snapshot.py` docstring both advertise `--tag-category` /
`--tag-value` flags that the script does not implement; and (3) a reconciliation
discrepancy where the supplemental's "Open Findings" column counts raw export rows rather
than the `open_findings_at` open set the trend store uses, so two artifacts from the same
run will disagree.

## Critical Issues

### CR-01: Supplemental writer raises on duplicate `asset_uuid` in enriched assets — silent loss via fail-soft wrapper

**File:** `reports/owner_supplemental.py:110`
**Issue:** `_build_owner_app_df` builds a lookup with
`uuid_to_owner = enriched.set_index("asset_uuid")[["owner", "application"]]` and then
`vuln_owner.join(uuid_to_owner, on="asset_uuid", how="left")`. `enriched` comes from
`extract_owner(assets_df)`, which does **not** deduplicate by `asset_uuid`
(`extract_owner` only appends columns; no dedup is applied anywhere in this path).
`fetch_all_assets()` can legitimately return more than one row for the same
`asset_uuid` (multi-network / multi-hostname assets), and the rest of the board pipeline
explicitly dedups (`deduplicate_assets_by_name`) precisely because duplicates exist.

`DataFrame.join(..., on=...)` against an index that contains duplicate keys raises:
`ValueError: cannot reindex on an axis with duplicate labels` (non-unique index on the
right side of a join). Because `write_owner_supplemental` is called inside the
fail-soft `try/except` in `board_summary.py:322-330`, the exception is swallowed and
both `supplemental_excel` and `supplemental_csv` come back `None` — the analyst
worklist silently disappears for exactly the asset populations (duplicated UUIDs) most
likely to need tag cleanup. The runbook (Section 5) advertises this worklist as the
mechanism for finding Unassigned assets, so the failure is invisible to operators.

Note the asymmetry: `asset_counts` on line 97-102 uses `groupby(...).nunique()` and is
safe; only the `set_index` join path (line 110) is exposed.

**Fix:**
```python
# Deduplicate the lookup before set_index so a non-unique asset_uuid
# cannot raise on join. Keep first owner/application per uuid.
uuid_to_owner = (
    enriched[["asset_uuid", "owner", "application"]]
    .drop_duplicates("asset_uuid")
    .set_index("asset_uuid")
)
```
Add a regression test feeding an `assets_df` with two rows sharing one `asset_uuid`
(different hostnames) and assert the supplemental writes without raising.

## Warnings

### WR-01: Runbook and script docstring advertise `--tag-category` / `--tag-value` flags that do not exist

**File:** `scripts/capture_trend_snapshot.py:133-160`, `docs/trend_and_segmentation_calculations.md:31-35`
**Issue:** The runbook Quick Start shows:
```bash
python scripts/capture_trend_snapshot.py \
    --tag-category "Environment" --tag-value "Production"
```
and the module docstring / file-per-dimension section frame tag-scoped snapshots as a
supported operation. But `_build_parser()` only registers `--month`, `--date`,
`--verbose`, and `--dry-run`. Running the documented command fails with
`error: unrecognized arguments: --tag-category Environment --tag-value Production`
(exit code 2). The `capture_snapshot` call on lines 260 and 273 hardcodes
`"all_assets"`. An operator following the runbook to capture a Production trend will get
a usage error, and there is no tag-scoped capture path at all despite the
`_sanitise_tag_for_filename` helper and the file-naming scheme being built for it.
**Fix:** Either (a) remove the `--tag-category`/`--tag-value` example and the
tag-scoped framing from both the script docstring and runbook Section 1/7 until the
flags are implemented, or (b) add the two `argparse` arguments, thread them through
`_sanitise_tag_for_filename` → `tag_filter`, and apply the same asset/vuln tag filter
`board_summary._filter_assets_by_tag` uses before calling `capture_snapshot`. Pick one;
do not leave the doc describing capability the CLI lacks.

### WR-02: Supplemental "Open Findings" counts raw export rows, not the `open_findings_at` open set — reconciles against nothing

**File:** `reports/owner_supplemental.py:108-120`, `docs/trend_and_segmentation_calculations.md:294-296`
**Issue:** The "Open Findings" column is computed as a plain `groupby(...).size()` over
every row in `vulns_df`. `vulns_df` from `fetch_all_vulnerabilities` is the open+reopened
**export**, which (per the runbook's own Section 3) over-counts the true open set unless
filtered through `open_findings_at` — a REOPENED finding sitting in its
`[last_fixed, resurfaced_date)` gap is in the export but is *not* open at date D. The
trend store (`_count_by_owner` → `open_findings_at` at `trend_store.py:277, 300`) and the
supplemental therefore produce different per-owner "open" counts from the same run. The
runbook labels the column "Open Findings" and bills the supplemental as drill-down into
the same Owner segmentation, but the numbers will not tie out to the owner trend
snapshot. This is a correctness/consistency defect, not styling.
**Fix:** Apply the same predicate the trend store uses before aggregating:
```python
from utils.open_count import open_findings_at
open_df = open_findings_at(vulns_df, report_date)  # thread report_date in
vuln_owner = open_df[["asset_uuid"]].copy()
```
This requires passing a reference date into `write_owner_supplemental`
(`board_summary` already has `generated_at`). If counting raw export rows is genuinely
intended, rename the column to "Export Rows (open+reopened)" and document the divergence
from the trend open count.

### WR-03: `capture_trend_snapshot.py` returns exit code 3 on owner-snapshot failure but logs `status="partial"` — contradicts documented contract

**File:** `scripts/capture_trend_snapshot.py:278-282`
**Issue:** The owner-snapshot `except` block logs
`_log_completed(logger, start, "partial", ...)` and then `return 3`. The module
docstring (lines 16-21) defines exit code `3` as "fetch or write failure" and the
runbook (line 38) says "exit code 3 = owner capture failed (severity was still
written)." Logging the run as `partial` while returning the hard-failure code `3` sends
two different signals to two different observers: the logfile says partial success, the
cron wrapper sees a total failure. A monitoring rule keyed on exit code will alert/page
as if nothing was captured, even though the severity snapshot persisted. Either the log
status or the exit code is wrong; they must agree.
**Fix:** Decide the contract. If a successful severity snapshot with a failed owner
snapshot is "partial success," return a distinct non-3 code (or 0 with a logged
warning) and document it. If it is a failure, log `status="failed"`. Do not pair
`"partial"` with `3`.

### WR-04: `_compute_days_to_fix` can produce negative `days_to_fix`, corrupting the "missed SLA" drill-down

**File:** `reports/modules/critical_remediation_sla_module.py:1020-1027`
**Issue:** The fallback branch computes `delta = lf - ff; return float(delta.days)`
with no guard that `last_fixed >= first_found`. Tenable export rows occasionally carry a
`last_fixed` earlier than `first_found` (re-import / clock-skew / merged-asset history).
A negative `days_to_fix` then flows into `within_sla_mask` (`<= _CRITICAL_SLA_DAYS` is
trivially True, inflating the within-SLA numerator) and is excluded from the "missed"
slice. The primary `time_taken_to_fix` branch (line 1016) has the same exposure — a
negative seconds value divides to a negative day count. The `.clip(lower=0)` on line 334
only protects the displayed "days overdue" column, not the SLA classification itself.
**Fix:** Clamp at the source so both the metric and the drill-down agree:
```python
days = float(delta.days)
return max(days, 0.0)
# and in the time_taken_to_fix branch:
return max(float(ttf) / 86400.0, 0.0)
```
or explicitly drop rows where `last_fixed < first_found` as data-quality outliers and
log them.

### WR-05: `_count_by_owner` reconciliation invariant is unguarded against duplicate `asset_uuid` in open findings vs. asset map

**File:** `data/trend_store.py:187-194`
**Issue:** `_count_by_owner` maps `open_df["asset_uuid"]` through a dict built from
`enriched_assets`. The runbook (Section 5, lines 237-239) promises per-owner totals
"reconcile to the whole" and `test_owner_counts_reconcile` asserts exactly that. The
invariant holds only because `dict(zip(...))` silently collapses duplicate `asset_uuid`
keys to the last value. If `enriched_assets` contains the same `asset_uuid` under two
different owners (possible when the caller passes raw multi-row assets — see CR-01), the
owner attribution becomes order-dependent and non-deterministic, while the *total* still
reconciles (so the test cannot catch it). The capture path in
`capture_trend_snapshot.py:272` passes `extract_owner(assets_df)` with no dedup, so this
is reachable in production even though the test fixtures are clean.
**Fix:** Deduplicate the map and assert uniqueness, or document that `enriched_assets`
must be pre-deduplicated by `asset_uuid`:
```python
ea = enriched_assets.drop_duplicates("asset_uuid")
uuid_to_owner = dict(zip(ea["asset_uuid"], ea["owner"]))
```
and have `capture_trend_snapshot.py` pass a deduplicated frame.

### WR-06: `read_trend` ignores `dimension` when validating, so a wrong-dimension file silently returns owner data as severity (or vice versa)

**File:** `data/trend_store.py:364-390`
**Issue:** `read_trend` builds the path from `dimension` and reads whatever
`{"snapshots": [...]}` it finds, with no check that the entries carry the expected keys
for that dimension. Because owner snapshots store arbitrary owner-name keys and severity
snapshots store `critical/high/...`, a caller that reads `read_trend("severity", ...)`
against a file that was accidentally written with owner data (e.g. a future bug in the
filename suffix, or a hand-edited recovery from a `.corrupt` rename) gets back rows with
no `critical` key and `insufficient_data=False`. Downstream severity-trend rendering
would then `KeyError` or silently show zeros. The function already added an observable
warning for the tag_filter-mismatch case (lines 378-383) but not for a
dimension/shape mismatch.
**Fix:** After loading, sanity-check the shape for severity reads (e.g. assert
`"critical" in snap` for `dimension == "severity"`) and log a warning + return
`insufficient_data=True` when the stored shape does not match the requested dimension.

## Info

### IN-01: Unused return value `aged_counts_per_asset` from `_find_high_risk_assets`

**File:** `reports/modules/high_risk_assets_module.py:231, 1042, 1047`
**Issue:** `compute()` unpacks `high_risk_uuids, aged_counts_per_asset, aged_findings`
but never references `aged_counts_per_asset` again. `_find_high_risk_assets` computes
`aged_counts = aged.groupby("asset_uuid").size()` solely to derive `high_risk_uuids` and
then also returns it. The dead middle element adds a documented-but-unused tuple slot
and a `pd.Series(dtype=int)` allocation on every early-return path.
**Fix:** Either consume it (the analyst tab re-derives `crit_high_open_count` via a
separate groupby on line 323, which `aged_counts` already holds) or drop it from the
return tuple and the three early returns to simplify the contract.

### IN-02: `populate_rag_strip` exported on the contract surface but unused by any board module

**File:** `reports/modules/board_report_utils.py:574-627`, `reports/modules/scan_coverage_sla_module.py:40`
**Issue:** All four board modules build their RAG strip inline via
`build_rag_strip_entry(...)` + `rag_status_from_value(...)`. `populate_rag_strip` (which
mutates `data.rag_strip` in place) is imported only in `scan_coverage_sla_module.py`
with a `# noqa: F401 # re-exported for plan 03-02 contract surface` and is never called.
It is effectively dead code carried for a contract that the migration to pure-construction
superseded.
**Fix:** Confirm no out-of-scope module consumes it; if none, remove the helper and the
re-export, or add a one-line comment in the helper docstring stating it is intentionally
retained as a public API for external module authors.

### IN-03: Smoke-block docstrings in `trend_store.py` no longer match owner-dimension reality

**File:** `data/trend_store.py:83-84`
**Issue:** `_sanitise_tag_for_filename` docstring says "Phase 12 only uses
`tag_filter='all_assets'` which bypasses this function, but the helper is provided here
for Phase 13's parameterised case." Phase 13 shipped without wiring the parameterised
case (see WR-01), so the helper remains entirely unexercised by any caller and the
docstring overstates current usage.
**Fix:** Update the docstring to note the parameterised path is not yet wired, or wire
it per WR-01.

### IN-04: Inconsistent log-status vocabulary across the snapshot script

**File:** `scripts/capture_trend_snapshot.py:211, 264, 281, 284`
**Issue:** `_log_completed` is called with status strings `"dry-run"`, `"failed"`,
`"partial"`, and `"success"`. The delivery-log schema in CLAUDE.md standardizes on
`success | partial | failed`; `"dry-run"` is an out-of-band value. This is a minor
observability inconsistency, not a bug, but it complicates any log-scraping that keys on
the documented status enum.
**Fix:** Map dry-run onto `success` with a `detail="dry-run"` suffix (the function
already supports `detail`), keeping the status vocabulary aligned with the project
schema.

---

_Reviewed: 2026-06-10T18:30:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
