---
phase: 13-owner-segmentation-composition-s2-doc
verified: 2026-06-10T19:10:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 4/5
  gaps_closed:
    - "Truth 3 / SEG-03: write_owner_supplemental now returns real Excel/CSV Paths on duplicate-asset_uuid input (CR-01 closed by drop_duplicates before set_index in _build_owner_app_df; WR-05 closed by deterministic dedup in _count_by_owner; WR-02 closed by open_findings_at open-set filter threaded from board_summary.generated_at)"
  gaps_remaining: []
  regressions: []
---

# Phase 13: Owner Segmentation + Composition Verification Report (Re-verification)

**Phase Goal:** Findings and assets can be grouped by Owner tag with a lossless Unassigned catch-all, the combination with the trend primitive is proven end-to-end, and an auditor-facing runbook documents both substrates.
**Verified:** 2026-06-10T19:10:00Z
**Status:** passed
**Re-verification:** Yes — after gap closure plan 13-05 (commits 487f0e2, 854e38a, 1b6d1e7)

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Calling the segmentation helper on a real or synthetic findings DataFrame returns per-Owner buckets whose counts sum to the total, with all untagged assets collected under a single `Unassigned` bucket (label configurable). | VERIFIED | `extract_owner` at `reports/modules/board_report_utils.py:214`. 8 unit tests in `tests/unit/test_owner_segmentation.py` including `test_owner_buckets_reconcile_to_whole` and `test_no_owner_tag_is_unassigned`. 147 tests pass, 0 failures. |
| 2 | When the `Owner` tag category is entirely absent or zero assets carry it, the helper returns everything under `Unassigned` and does not raise — existing reports that call it continue to deliver. | VERIFIED | `extract_owner` missing-column path (lines 297-305): logs warning, sets all rows `unassigned_label`, `application=""`, no raise. `test_missing_tags_column_fail_soft` covers the path. Phase-wide grep gates: `business_unit`, `Untagged`, and `Business Unit` all 0 across five blast-radius files. |
| 3 | The analyst exception list of untagged assets is written as a local Excel/CSV file; it is not attached to any email or committed to the repository. | VERIFIED | CR-01 closed: `_build_owner_app_df` now calls `enriched[["asset_uuid","owner","application"]].drop_duplicates("asset_uuid").set_index("asset_uuid")` (line 119-123), eliminating the ValueError on non-unique index. `reports/board_summary.py:324` threads `report_date=generated_at` (WR-02). `data/trend_store.py:_count_by_owner` dedups enriched_assets before the zip map (WR-05). Tests: `test_duplicate_uuid_returns_paths_and_deterministic` and `test_open_findings_uses_open_set` both pass. File written to `output/` (gitignored); `delivery/email_sender.py` has 0 references to `supplemental_excel`/`supplemental_csv`. |
| 4 | `capture_snapshot` accepts an `owner` dimension argument and writes per-Owner open counts into the snapshot store; `read_trend` can retrieve a month-over-month series for a specific Owner — proving S1 and S2 compose end-to-end. | VERIFIED | `_count_by_owner` at `data/trend_store.py:171`; dimension dispatch at lines 295-302; `enriched_assets=None` raises ValueError (tested). `scripts/capture_trend_snapshot.py:271-276`: `extract_owner(assets_df)` then `capture_snapshot(..., "owner", "all_assets", enriched_assets=enriched)`. `grep -c "from reports" data/trend_store.py` = 0 (data-layer isolation). 6 owner content tests pass including round-trip, no-PII, reconcile-to-whole, cold-start. |
| 5 | `docs/trend_and_segmentation_calculations.md` exists, documents the two-interval open predicate, the ~29-day Tenable fixed-retention constraint and forward-accumulation model, and the Owner/Unassigned segmentation model in the established `docs/*_calculations.md` style. | VERIFIED | File exists. Contains: "two-interval" (Section 3), "resurfaced_date" (Section 3 snippet), "29" (Section 4), "forward" (Section 4), "Unassigned", `open_findings_at`, "trend_owner", tag_filter consistency requirement, PII rule framed as AI/repo exposure ("Internal email: permitted", "Repository commit: prohibited"). Eight-section structure with File/Audience/Outputs/Schedule header block. |

**Score:** 5/5 truths verified

---

## Re-verification Focus: Truth 3 / SEG-03 (was FAILED — gap-closure commits 487f0e2, 854e38a, 1b6d1e7)

### CR-01 (BLOCKER — now closed)

**Before:** `_build_owner_app_df` called `enriched.set_index("asset_uuid")` without deduplicating. In pandas 2.2.3 this produced non-deterministic last-wins attribution (rather than raising) when the same uuid appeared under different owners — and in older pandas versions would raise `ValueError`. The exception was swallowed by the fail-soft `try/except` in `board_summary.py`, silently returning `supplemental_excel=None`.

**After (854e38a):** Line 119-123 of `reports/owner_supplemental.py`:
```python
uuid_to_owner = (
    enriched[["asset_uuid", "owner", "application"]]
    .drop_duplicates("asset_uuid")
    .set_index("asset_uuid")
)
```
First-row-wins attribution; deterministic and pandas-version-agnostic.

**Test pinning:** `test_duplicate_uuid_returns_paths_and_deterministic` in `tests/unit/test_owner_supplemental.py` uses two rows with different owners on the same uuid and asserts first-row attribution in the output CSV. Passes.

### WR-02 (correctness — now closed)

`open_findings_at(vulns_df, report_date)` applied before aggregation when `report_date` is not None. `board_summary.py:324` threads `generated_at`. `test_open_findings_uses_open_set` passes.

### WR-05 (correctness — now closed)

`data/trend_store.py:_count_by_owner` (lines 190-192): `ea = enriched_assets.drop_duplicates("asset_uuid")` before `dict(zip(...))`. `test_owner_attribution_deterministic_under_dup_uuid` passes; reconcile-to-whole invariant preserved. `grep -c "from reports" data/trend_store.py` = 0.

---

## Assessment of 13-05-REVIEW.md Open Items

The code review flagged four warnings after gap closure. This section assesses whether any constitute blockers against the phase's must-have truths.

### WR-01 (asset_count double-counts duplicate UUIDs) — WARNING, not a blocker

`asset_counts` at `owner_supplemental.py:100-105` still groups the un-deduped `enriched` frame. For a physical asset appearing under two different (owner, application) combinations, `asset_count` will double-count that asset's contribution. This creates phantom rows in the output with `asset_count=1, open_count=0` for the secondary (owner, application) combination.

**Impact on must-have truths:** The must-have truth for SEG-03 is "write_owner_supplemental returns real Excel/CSV Paths (not None) when assets_df contains duplicate asset_uuid rows." WR-01 does not prevent Paths from being returned — the file is written. The defect affects the *accuracy* of the `Asset Count` column, not the production of the output. The phase goal ("analyst exception list is written as a local Excel/CSV file") is met.

**Classification:** WARNING — `Asset Count` column over-counts on multi-network assets. Should be addressed in a follow-up plan. Does not block this phase.

### WR-02 chained-assignment at line 139 — WARNING, not a blocker

`result["open_count"] = result["open_count"].fillna(0).astype(int)` violates the project's F-DTYPE `.assign()` convention and produces a `FutureWarning` in the test output. Under pandas 3.0 CoW this will silently no-op, leaving `open_count` as float64-with-NaN. Currently works correctly in pandas 2.x.

**Impact on must-have truths:** All 147 tests pass today. This is a forward-compatibility gap, not a current failure. Does not affect SEG-03 file production.

**Classification:** WARNING — violates CLAUDE.md F-DTYPE convention; will become a correctness regression under pandas 3.0. Should be fixed in a follow-up plan alongside WR-01.

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `reports/modules/board_report_utils.py` | Owner-primary helper with `extract_owner`, `OWNER_TAG_CATEGORY`, owner-column breakdown/risk | VERIFIED | `extract_owner` at line 214; `OWNER_TAG_CATEGORY = "Owner"` at line 50; `compute_per_bu_breakdown` renames to `"owner"`; `compute_bu_risk_scores` uses `"owner"` column. |
| `tests/unit/test_owner_segmentation.py` | 8 unit tests for SEG-01/02/04 | VERIFIED | All 8 tests confirmed present and passing. |
| `reports/modules/aged_vulns_assets_module.py` | Owner-repointed consumer | VERIFIED | Imports `extract_owner`; uses `owner` column; 0 occurrences of `business_unit`, `Untagged`, `Business Unit`. |
| `reports/modules/high_risk_assets_module.py` | Owner-repointed consumer | VERIFIED | Same pattern as aged_vulns confirmed. |
| `reports/modules/scan_coverage_sla_module.py` | Owner-repointed consumer | VERIFIED | Phase-wide grep gates pass. |
| `reports/modules/critical_remediation_sla_module.py` | Owner-repointed consumer with `_extract_owner_tag` removed | VERIFIED | `extract_owner` present; `_extract_owner_tag` count = 0. |
| `data/trend_store.py` | `_count_by_owner` + `dimension=owner` dispatch + deterministic dedup (WR-05) | VERIFIED | `_count_by_owner` at line 171; `drop_duplicates("asset_uuid")` at line 191; `from reports` count = 0. |
| `reports/owner_supplemental.py` | Combined supplemental Excel/CSV writer with CR-01 dedup fix | VERIFIED | `write_owner_supplemental` exists; `drop_duplicates("asset_uuid")` at line 121; `open_findings_at` imported and used at line 115; `report_date` param threaded. |
| `reports/board_summary.py` | Fail-soft wiring with WR-02 report_date threading | VERIFIED | `write_owner_supplemental(assets_df, vulns_df, output_dir, report_date=generated_at)` at line 324; additive `supplemental_excel`/`supplemental_csv` keys in result_dict. |
| `tests/unit/test_owner_supplemental.py` | CR-01 + WR-02 regression tests | VERIFIED | `test_duplicate_uuid_returns_paths_and_deterministic`, `test_open_findings_uses_open_set`, `test_empty_assets_returns_paths` — all pass. |
| `scripts/capture_trend_snapshot.py` | Owner-dimension snapshot capture | VERIFIED | `extract_owner` import and call at lines 271-276; both severity and owner captures present. |
| `docs/trend_and_segmentation_calculations.md` | DOC-01 auditor runbook | VERIFIED | Exists; all required content strings confirmed; 8 sections; correct header block. |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `extract_owner` | `owner` + `application` columns | single-pass tag parser | VERIFIED | Dual-category loop; missing-column path all-Unassigned; no raise. |
| `compute_per_bu_breakdown` | `owner` output column | `.rename(columns={bu_column: "owner"})` | VERIFIED | `bu_column` default is `"owner"`; rename confirmed. |
| 4 consumer modules | `board_report_utils.extract_owner` | `from ... import extract_owner` | VERIFIED | All four modules import `extract_owner`; use `owner` column; `Business Unit` heading = 0. |
| `scripts/capture_trend_snapshot.py` | `capture_snapshot(dimension="owner", ...)` | pre-enrich via `extract_owner`, pass `enriched_assets` | VERIFIED | Lines 271-276 confirmed. |
| `reports/board_summary.run_report` | `write_owner_supplemental` | fail-soft call at line 322-330 with `report_date=generated_at` | VERIFIED | CR-01 closed; file produced on duplicate-uuid input. Additive result keys 390-391 confirmed. |
| `_build_owner_app_df` | `open_findings_at` | filter vulns_df to open set at report_date before counting | VERIFIED | `open_findings_at` import at module level; used at line 115. |
| `docs/trend_and_segmentation_calculations.md` open-predicate section | `utils/open_count.py open_findings_at` | documents the predicate | VERIFIED | Section 3 references `open_findings_at` by name and path. |

---

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `capture_snapshot` owner path | `count_entry` | `_count_by_owner(open_df, enriched_assets)` with deterministic dedup | Yes — uses open predicate on real vuln data; deterministic first-row attribution | FLOWING |
| `write_owner_supplemental` | `df` (owner/app frame) | `_build_owner_app_df` → `extract_owner` + `open_findings_at` + dedup'd uuid map | Yes — real asset/vuln data; no longer hollow on duplicate UUIDs | FLOWING (WR-01: `asset_count` column over-counts on multi-network assets — WARNING only) |
| `read_trend("owner", ...)` | `snapshots` list | `_load_trend_json` from `data/trend/trend_owner_all_assets.json` | Yes — reads accumulated monthly captures | FLOWING |

---

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| All unit + content tests pass | `.venv/Scripts/python.exe -m pytest tests/unit tests/content` | `147 passed, 236 warnings in 3.75s` | PASS |
| Modules import cleanly | `python -c "import reports.owner_supplemental, reports.board_summary"` | `imports OK` | PASS |
| CR-01 fix present | `grep "drop_duplicates" reports/owner_supplemental.py` | Line 121: `.drop_duplicates("asset_uuid")` before `.set_index` | PASS |
| WR-05 fix present | `grep "drop_duplicates" data/trend_store.py` | Line 191: `ea = enriched_assets.drop_duplicates("asset_uuid")` | PASS |
| WR-02 wiring present | `grep "report_date=generated_at" reports/board_summary.py` | Line 324 confirmed | PASS |
| Data-layer isolation | `grep -c "from reports" data/trend_store.py` | 0 | PASS |
| `output/` gitignored | `git check-ignore output/` | `output/` | PASS |
| Phase-wide `business_unit` gate | grep across 5 blast-radius files | 0 for all five | PASS |
| Phase-wide `Untagged` gate | grep across 5 blast-radius files | 0 for all five | PASS |
| `Business Unit` heading gate | grep across 4 consumer modules | 0 matches | PASS |
| `_extract_owner_tag` removed | `grep -c "_extract_owner_tag" critical_remediation_sla_module.py` | 0 | PASS |
| Gap-closure commits | `git log --oneline` | 487f0e2, 854e38a, 1b6d1e7 present | PASS |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SEG-01 | 13-01 | Helper groups findings/assets by `Owner` tag, returns per-Owner buckets | SATISFIED | `extract_owner` + 8 tests; `test_owner_buckets_reconcile_to_whole` passes. |
| SEG-02 | 13-01 | Assets without Owner tag fall into `Unassigned` catch-all | SATISFIED | No-match → `unassigned_label`; `test_no_owner_tag_is_unassigned` passes; configurable. |
| SEG-03 | 13-03, 13-05 | Analyst exception list of Unassigned assets as operator-facing local output | SATISFIED | `write_owner_supplemental` writes real Paths on duplicate-uuid input (CR-01 closed). File under `output/` (gitignored); not wired to email. |
| SEG-04 | 13-01 | Segmentation is fail-soft when Owner category is absent or partially applied | SATISFIED | Missing-column path: warning logged, all-Unassigned, no raise. `test_missing_tags_column_fail_soft` passes. |
| SEG-05 | 13-03 | Owner segmentation composes with trend primitive end-to-end | SATISFIED | `capture_snapshot(dimension="owner")` + `read_trend("owner", "all_assets")` round-trip; 6 content tests pass. |
| DOC-01 | 13-04 | Substrate calculations runbook | SATISFIED | `docs/trend_and_segmentation_calculations.md` exists; all required content confirmed. |

---

## Anti-Patterns / Follow-up Items

The following items were identified in the 13-05-REVIEW.md. Neither blocks this phase's must-have truths. Both should be addressed in a follow-up plan.

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `reports/owner_supplemental.py` | 100-105 | `asset_counts` built from un-deduped `enriched` — `Asset Count` column over-counts physical assets that appear under multiple (owner, application) rows; creates phantom rows with `asset_count=1, open_count=0` in the output | WARNING | `Asset Count` total overstates distinct assets for multi-network hosts; does not prevent file production (WR-01) |
| `reports/owner_supplemental.py` | 139 | `result["open_count"] = result["open_count"].fillna(0).astype(int)` — chained-assignment violates F-DTYPE `.assign()` convention; pandas FutureWarning in tests; will silently no-op under pandas 3.0 CoW | WARNING | Forward-compatibility regression risk; `open_count` may remain float64-with-NaN under pandas 3.0 (WR-02 from review) |

---

## Human Verification Required

None — all success criteria are verifiable programmatically.

---

## Gaps Summary

None. All five must-have truths are VERIFIED. The prior BLOCKER (CR-01 — `write_owner_supplemental` silently returning None on duplicate-uuid assets) is closed by `drop_duplicates("asset_uuid")` before `set_index` in `_build_owner_app_df` (commit 854e38a). The two follow-up warnings (WR-01 asset_count over-counting, WR-02 review's chained-assignment) are real and should be closed in a future plan, but neither prevents the analyst exception list from being written nor affects any of this phase's five must-have truths.

---

_Verified: 2026-06-10T19:10:00Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification after gap-closure plan 13-05 (commits 487f0e2, 854e38a, 1b6d1e7)_
