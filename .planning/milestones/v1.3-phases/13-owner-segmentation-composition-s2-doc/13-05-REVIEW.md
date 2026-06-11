---
phase: 13-owner-segmentation-composition-s2-doc
plan: 13-05
reviewed: 2026-06-10T19:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - reports/owner_supplemental.py
  - data/trend_store.py
  - reports/board_summary.py
  - tests/unit/test_owner_supplemental.py
  - tests/content/test_trend_store.py
findings:
  critical: 0
  warning: 4
  info: 2
  total: 6
status: issues_found
---

# Phase 13 / Plan 13-05: Gap-Closure Code Review (CR-01, WR-05, WR-02 cluster)

**Reviewed:** 2026-06-10T19:00:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

> Scope note: this is the gap-closure review for plan 13-05 only (the duplicate-`asset_uuid`
> correctness cluster). The full-phase review is `13-REVIEW.md` and is intentionally left intact.

## Summary

I traced the three claimed fixes end to end against the diff (`6eb4abd^..HEAD`):

- **CR-01** (`owner_supplemental._build_owner_app_df`): `drop_duplicates("asset_uuid")` is now
  applied to the `uuid_to_owner` map before `set_index`/`join`. First-row-wins attribution for the
  **open_count** column is correct and deterministic. Verified by
  `test_duplicate_uuid_returns_paths_and_deterministic`.
- **WR-05** (`trend_store._count_by_owner`): `enriched_assets.drop_duplicates("asset_uuid")` before
  `dict(zip(...))` gives deterministic first-row-wins owner attribution. The reconcile-to-whole
  invariant (sum of per-owner counts == `len(open_findings_at(...))`) holds because every open row
  maps to exactly one owner via `.fillna("Unassigned")`. Verified by
  `test_owner_attribution_deterministic_under_dup_uuid` and `test_owner_counts_reconcile`.
- **WR-02** (open-set filter + `report_date` threading): `open_findings_at(vulns_df, report_date)`
  is applied before aggregation when `report_date` is provided; `board_summary` threads
  `generated_at`. Verified by `test_open_findings_uses_open_set`.

All 19 tests across the two test files pass (`19 passed in 3.43s`). The dedup fixes are correct for
the columns they target.

The defects below are real but none rise to BLOCKER: the CR-01 fix is **incomplete** (the
`asset_count` column in the same function still double-counts duplicate UUIDs and emits phantom
rows), a pandas chained-assignment in the new code violates the project's own F-DTYPE convention
and will silently break under pandas 3.0, the new `open_findings_at` dependency has no
column-presence guard, and the headline "ties out to the trend snapshot" invariant is asserted in
prose but not pinned by any test.

## Warnings

### WR-01: `asset_count` column still double-counts duplicate `asset_uuid` (CR-01 fix is partial)

**File:** `reports/owner_supplemental.py:99-109, 138-141`
**Issue:** The CR-01 fix deduplicated the **open-count** attribution map (lines 119-123) but left
the **asset_count** path (lines 100-105) unchanged:

```python
asset_counts = (
    enriched
    .groupby(["owner", "application"], dropna=False)["asset_uuid"]
    .nunique()
    .reset_index(name="asset_count")
)
```

`extract_owner` does not dedup, and the fix's own fixture docstring (`_assets_df_with_dup_uuid`)
states a single physical asset can appear under two different `owner`/`application` rows
(multi-network host). For duplicate uuid `"dup"` with row 0 = `(A, X)` and row 1 = `(B, Y)`:

- `asset_counts` emits **two** rows — `(A,X) → 1` and `(B,Y) → 1` — counting one physical asset
  twice, so the `Asset Count` total overstates distinct assets.
- The open-count path (correctly dedup'd) attributes the finding only to `(A,X)`.
- `asset_counts.merge(open_counts, how="left")` (line 138) then yields a **phantom `(B,Y)` row**
  with `asset_count=1, open_count=0` representing a non-existent owner/application split.

The same un-dedup'd `asset_counts` is also returned verbatim by the empty-vulns early return
(lines 107-109), so the defect exists even when `vulns_df` is empty. CR-01's root cause
("non-unique asset_uuid → wrong attribution") is therefore only half closed: open attribution is
fixed, asset attribution is not.

**Fix:** Dedup the asset frame on `asset_uuid` (first-row wins, matching the open path) before the
`asset_count` groupby, and reuse the same deduped frame for the owner map so the two columns cannot
diverge:

```python
enriched = extract_owner(assets_df)
enriched_unique = enriched.drop_duplicates("asset_uuid")

asset_counts = (
    enriched_unique
    .groupby(["owner", "application"], dropna=False)["asset_uuid"]
    .nunique()
    .reset_index(name="asset_count")
)
# ... and build uuid_to_owner from enriched_unique[["asset_uuid","owner","application"]]
```

### WR-02: Chained-assignment violates the project's F-DTYPE convention (breaks under pandas 3.0)

**File:** `reports/owner_supplemental.py:139`
**Issue:** `result["open_count"] = result["open_count"].fillna(0).astype(int)` triggers a
`ChainedAssignmentError` `FutureWarning` at test runtime (confirmed in the pytest output for
`test_open_findings_uses_open_set`). The project already forbids this exact pattern:
`reports/modules/board_report_utils.py:496-504` (the F-DTYPE note) mandates `.assign()` over
`df[col]=` / `.loc[:, col]=` setters because they "fire ChainedAssignmentError FutureWarning under
pandas 3.0 CoW." Under pandas 3.0 CoW the in-place mutation will silently no-op, leaving
`open_count` as float64-with-NaN instead of int — a future correctness regression in code added by
this very fix.

**Fix:** Use `.assign()` on the merge result, matching the established convention:

```python
result = (
    asset_counts.merge(open_counts, on=["owner", "application"], how="left")
    .assign(open_count=lambda d: d["open_count"].fillna(0).astype(int))
    .sort_values(["owner", "application"])
    .reset_index(drop=True)
)
return result[["owner", "application", "open_count", "asset_count"]]
```

### WR-03: New `open_findings_at` dependency has no column-presence guard

**File:** `reports/owner_supplemental.py:107-115`
**Issue:** The early-return guard only checks `vulns_df.empty or "asset_uuid" not in vulns_df.columns`.
When `report_date is not None` (the production path — `board_summary.py:324` always threads
`generated_at`), line 115 calls `open_findings_at(vulns_df, report_date)`, which directly indexes
`df["first_found"]`, `df["state"]`, `df["last_fixed"]`, `df["resurfaced_date"]`
(`utils/open_count.py:75, 82, 93-95`). If any column is absent, `open_findings_at` raises
`KeyError` instead of returning a coherent empty result. In the board pipeline that KeyError is
swallowed by the fail-soft `try/except` at `board_summary.py:327-330`, so the supplemental silently
produces **no output at all** (both return paths None) rather than a "no data" workbook — a quiet
loss of the tagging-cleanup worklist operators rely on. `fetch_all_vulnerabilities` guarantees the
columns today (`data/fetchers.py:350-370`), so this is a contract/robustness gap, not a live crash;
but the WR-02 change newly couples the public `write_owner_supplemental` API to four date/state
columns that the guard does not check.

**Fix:** Guard the columns before calling, and degrade to raw rows (with a warning) when missing:

```python
_OPEN_SET_COLS = {"first_found", "last_fixed", "resurfaced_date", "state"}
use_open_set = report_date is not None and _OPEN_SET_COLS.issubset(vulns_df.columns)
open_vulns = open_findings_at(vulns_df, report_date) if use_open_set else vulns_df
```

### WR-04: The "ties out to the owner trend snapshot" invariant is asserted in prose, not in a test

**File:** `reports/owner_supplemental.py:111-112`, `data/trend_store.py:171-197`
**Issue:** The WR-02 fix is justified by the comment "so the supplemental 'Open Findings' column
ties out to the owner trend snapshot" (owner_supplemental.py:111) — the stated correctness goal of
the cluster. No test asserts that cross-module tie-out. `test_open_findings_uses_open_set` checks
the supplemental against a hand-computed `1`; `test_owner_counts_reconcile` checks the trend
snapshot against `open_findings_at` — but nothing asserts that the **per-owner open totals from
`_build_owner_app_df` equal the per-owner counts from `_count_by_owner`** for the same
`(vulns_df, assets_df, report_date)`. Because the two paths use different aggregation keys
(supplemental groups by `(owner, application)`; trend by `owner`) and WR-01 leaves the supplemental
asset path un-deduped, a future change could silently break the tie-out with no failing test.

**Fix:** Add a reconciliation test building one `(vulns_df, assets_df)` pair (with a duplicate
`asset_uuid` and an Unassigned asset) that runs both `_build_owner_app_df` and `_count_by_owner`
(via `capture_snapshot(..., dimension="owner")`) and asserts the per-owner open-finding totals
match. This pins the cross-module invariant the cluster exists to guarantee.

## Info

### IN-01: `report_date=None` back-compat branch is dead in the only production caller

**File:** `reports/owner_supplemental.py:115`, `reports/board_summary.py:324`
**Issue:** The `report_date is None` branch (raw export rows) exists for "callers that do not thread
a date," but the only production caller (`board_summary.run_report`) now always passes
`report_date=generated_at`, and no other production call site exists. The back-compat branch is
exercised only by `test_duplicate_uuid_returns_paths_and_deterministic` and
`test_empty_assets_returns_paths` — so the CR-01 determinism test validates a path production never
takes. Consider threading `report_date` in at least one determinism test so the dedup is verified on
the live open-set path. (Acceptable as a public-API affordance; noted for test coverage, not a bug.)

### IN-02: `datetime` imported for annotation only

**File:** `reports/owner_supplemental.py:20`
**Issue:** `from datetime import datetime` was added solely for the `Optional[datetime]` annotations.
With `from __future__ import annotations` (line 16) in effect, annotations are strings and the
runtime import is not strictly required. Harmless; flagged only in case the project lints unused
runtime imports. No action required.

---

_Reviewed: 2026-06-10T19:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
