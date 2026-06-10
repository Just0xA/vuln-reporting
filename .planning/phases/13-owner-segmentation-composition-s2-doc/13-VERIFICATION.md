---
phase: 13-owner-segmentation-composition-s2-doc
verified: 2026-06-10T18:35:00Z
status: gaps_found
score: 4/5 must-haves verified
overrides_applied: 0
gaps:
  - truth: "The analyst exception list of untagged assets is written as a local Excel/CSV file; it is not attached to any email or committed to the repository."
    status: partial
    reason: >
      The file is correctly written to output/ (gitignored), is not wired into
      email delivery, and is not committed. However, CR-01 from the code review
      identifies a reproducible ValueError that causes the supplemental to silently
      return None via the fail-soft wrapper when assets_df contains duplicate
      asset_uuid rows — a condition that fetch_all_assets() legitimately produces
      for multi-network/multi-hostname assets. The rest of the board run continues
      unaffected, but the analyst exception list (the stated SEG-03 deliverable)
      disappears with no operator-visible signal. The criterion says the file IS
      written; with duplicate UUIDs in production, it is NOT written.
    artifacts:
      - path: "reports/owner_supplemental.py"
        issue: >
          Line 110: enriched.set_index("asset_uuid")[["owner","application"]] raises
          ValueError("cannot reindex on an axis with duplicate labels") when enriched
          contains more than one row for the same asset_uuid. extract_owner() does not
          deduplicate; fetch_all_assets() legitimately returns duplicates. The call is
          inside the fail-soft try/except in board_summary.py:322-330, so the exception
          is swallowed and supplemental_excel/supplemental_csv come back None.
    missing:
      - "Add .drop_duplicates('asset_uuid') before .set_index('asset_uuid') in _build_owner_app_df (line ~109). Fix is one line; see CR-01 in 13-REVIEW.md."
      - "Add a regression test: write_owner_supplemental(assets_df_with_duplicate_uuids, ...) returns real paths without raising."
---

# Phase 13: Owner Segmentation + Composition Verification Report

**Phase Goal:** Findings and assets can be grouped by Owner tag with a lossless Unassigned catch-all, the combination with the trend primitive is proven end-to-end, and an auditor-facing runbook documents both substrates.
**Verified:** 2026-06-10T18:35:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Calling the segmentation helper on a real or synthetic findings DataFrame returns per-Owner buckets whose counts sum to the total, with all untagged assets collected under a single `Unassigned` bucket (label configurable). | VERIFIED | `extract_owner` implemented in `reports/modules/board_report_utils.py` lines 214-307. Single-pass dual-category parser; no-match → `unassigned_label`. 8 unit tests in `tests/unit/test_owner_segmentation.py` including `test_owner_buckets_reconcile_to_whole` and `test_no_owner_tag_is_unassigned`. All 143 tests pass. |
| 2 | When the `Owner` tag category is entirely absent or zero assets carry it, the helper returns everything under `Unassigned` and does not raise — existing reports that call it continue to deliver. | VERIFIED | `extract_owner` lines 297-305: missing tags column → logs warning, sets all rows `unassigned_label`, `application=""`, no raise. `test_missing_tags_column_fail_soft` test covers this path. All four consumer modules import `extract_owner`; `business_unit`, `Untagged`, and `Business Unit` confirmed at 0 occurrences across all five blast-radius files. |
| 3 | The analyst exception list of untagged assets is written as a local Excel/CSV file; it is not attached to any email or committed to the repository. | FAILED (BLOCKER) | File is written to `output/` (gitignored confirmed via `git check-ignore output/`). `delivery/email_sender.py` contains no reference to `supplemental_excel` or `supplemental_csv` — not wired to email. However, CR-01 (13-REVIEW.md): `_build_owner_app_df` line 110 does `enriched.set_index("asset_uuid")` without deduplicating first. `fetch_all_assets()` legitimately returns duplicate `asset_uuid` rows for multi-network/multi-hostname assets; this raises `ValueError: cannot reindex on an axis with duplicate labels`. The exception is swallowed by the `try/except` in `board_summary.py:322-330`; both paths return `None`. The supplemental is silently absent for exactly the asset populations most likely to need tagging cleanup. The file IS written in the test fixture (clean data), but is NOT reliably written in production. |
| 4 | `capture_snapshot` accepts an `owner` dimension argument and writes per-Owner open counts into the snapshot store; `read_trend` can retrieve a month-over-month series for a specific Owner — proving S1 and S2 compose end-to-end. | VERIFIED | `_count_by_owner` at `data/trend_store.py:171`; dimension dispatch at lines 295-300; `enriched_assets=None` raises `ValueError` (tested). `read_trend` requires no change and works via filename + tag_filter matching. `scripts/capture_trend_snapshot.py:271-276` calls `extract_owner(assets_df)` then `capture_snapshot(..., "owner", "all_assets", enriched_assets=enriched)`. 6 new content tests in `test_trend_store.py` including round-trip, no-PII, reconcile-to-whole, ValueError-on-None, cold-start — all pass. `grep -c "from reports" data/trend_store.py` returns 0 (data layer isolation maintained). |
| 5 | `docs/trend_and_segmentation_calculations.md` exists, documents the two-interval open predicate, the ~29-day Tenable fixed-retention constraint and forward-accumulation model, and the Owner/Unassigned segmentation model in the established `docs/*_calculations.md` style. | VERIFIED | File exists and was read in full. Contains: "two-interval" (Section 3), "resurfaced_date" (Section 3 Python snippet), "29" (Section 4 title and body), "forward" (Section 4), "Unassigned" (Sections 5, 6, 7, 8), `open_findings_at` (Section 3), "trend_owner" (Section 7), tag_filter consistency requirement (Section 7), PII rule framed as AI/repo exposure with "Internal email: permitted" and "Repository commit: prohibited" (Section 6). Header block has **File**, **Audience**, **Outputs**, **Schedule**. Eight numbered sections match the `docs/*_calculations.md` pattern. |

**Score:** 4/5 truths verified (truth 3 FAILED)

---

## CR-01 Impact Assessment (from 13-REVIEW.md)

The code review's Critical finding directly affects Success Criterion 3. The `ValueError` on duplicate `asset_uuid` is not a theoretical concern: `fetch_all_assets()` returns duplicates for multi-network assets, and `reports/board_summary.py` even calls `deduplicate_assets_by_name()` earlier in the pipeline specifically because duplicates exist. The deduplication step that protects the rest of the board pipeline is absent at the `write_owner_supplemental` call site.

The failure is invisible to operators: the board PDF and Excel deliver normally; the only symptom is `supplemental_excel: None` and `supplemental_csv: None` in the result dict, and a log line from the `except` block that an operator may not be monitoring.

Fix is one line in `_build_owner_app_df`:
```python
uuid_to_owner = (
    enriched[["asset_uuid", "owner", "application"]]
    .drop_duplicates("asset_uuid")
    .set_index("asset_uuid")
)
```

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `reports/modules/board_report_utils.py` | Owner-primary helper with `extract_owner`, `OWNER_TAG_CATEGORY`, owner-column breakdown/risk | VERIFIED | `extract_owner` at line 214; `OWNER_TAG_CATEGORY = "Owner"` at line 50; `APPLICATION_TAG_CATEGORY` at line 53; `_DEFAULT_UNASSIGNED_LABEL = "Unassigned"` at line 56; `compute_per_bu_breakdown` renames to `"owner"` at line 379; `compute_bu_risk_scores` uses `"owner"` column. |
| `tests/unit/test_owner_segmentation.py` | 8 unit tests for SEG-01/02/04 | VERIFIED | All 8 tests listed in 13-01-SUMMARY.md confirmed present; 23 tests in the targeted file pass. |
| `reports/modules/aged_vulns_assets_module.py` | Owner-repointed consumer | VERIFIED | Imports `extract_owner` at line 40; uses `owner` column at compute/render sites; 0 occurrences of `business_unit`, `Untagged`, `Business Unit`. |
| `reports/modules/high_risk_assets_module.py` | Owner-repointed consumer | VERIFIED | Same pattern as aged_vulns confirmed. |
| `reports/modules/scan_coverage_sla_module.py` | Owner-repointed consumer | VERIFIED | Phase-wide grep gates pass (0 occurrences of `business_unit`, `Untagged`, `Business Unit`). |
| `reports/modules/critical_remediation_sla_module.py` | Owner-repointed consumer with `_extract_owner_tag` removed | VERIFIED | `extract_owner` at lines 55, 325, 1051; `_extract_owner_tag` count = 0. |
| `data/trend_store.py` | `_count_by_owner` + `dimension=owner` dispatch | VERIFIED | `_count_by_owner` at line 171; `enriched_assets` param in `capture_snapshot` at line 226; dimension dispatch at lines 295-302; `from reports` count = 0. |
| `reports/owner_supplemental.py` | Combined supplemental Excel/CSV writer | PARTIAL — CR-01 blocker | `write_owner_supplemental` exists and implements the full writer pattern. Fails on duplicate `asset_uuid` via `set_index` at line 110 (see CR-01). |
| `scripts/capture_trend_snapshot.py` | Owner-dimension snapshot capture | VERIFIED | `extract_owner` import and call at lines 271-276; both severity and owner captures present; severity capture unregressed. |
| `docs/trend_and_segmentation_calculations.md` | DOC-01 auditor runbook | VERIFIED | Exists; all required strings confirmed present; 8 sections; correct header block. |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `extract_owner` | `owner` + `application` columns | single-pass tag parser (lines 263-291) | VERIFIED | Parser produces both columns; missing-column path sets all to `unassigned_label`/`""`. |
| `compute_per_bu_breakdown` | `owner` output column | `.rename(columns={bu_column: "owner"})` | VERIFIED | `bu_column` default is `"owner"`; rename confirmed at line 379. |
| 4 consumer modules | `board_report_utils.extract_owner` | `from ... import extract_owner` | VERIFIED | All four modules have the import; use `owner` column at groupby/merge/render sites; `Business Unit` heading count = 0 across all four. |
| `scripts/capture_trend_snapshot.py` | `capture_snapshot(dimension="owner", ...)` | pre-enrich via `extract_owner`, pass `enriched_assets` | VERIFIED | Lines 271-276; `extract_owner(assets_df)` then `capture_snapshot(..., "owner", "all_assets", enriched_assets=enriched)`. |
| `reports/board_summary.run_report` | `write_owner_supplemental` | post-pipeline call lines 322-330, additive result keys 390-391 | PARTIAL — CR-01 | Wiring is correct and fail-soft. But the callee raises on duplicate UUIDs, so the link produces `None` outputs in production. |
| `docs/trend_and_segmentation_calculations.md` open-predicate section | `utils/open_count.py open_findings_at` | documents the predicate | VERIFIED | Section 3 references `open_findings_at` by name and path; Python snippet matches the actual implementation. |

---

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `capture_snapshot` owner path | `count_entry` | `_count_by_owner(open_df, enriched_assets)` → `open_findings_at` | Yes — uses open predicate on real vuln data | FLOWING |
| `write_owner_supplemental` | `df` (owner/app frame) | `_build_owner_app_df` → `extract_owner(assets_df)` + vulns groupby | Yes — real asset/vuln data; HOLLOW on duplicate UUIDs in production (CR-01) | HOLLOW (CR-01) |
| `read_trend("owner", ...)` | `snapshots` list | `_load_trend_json` from `data/trend/trend_owner_all_assets.json` | Yes — reads accumulated monthly captures | FLOWING |

---

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Modules import cleanly | `python -c "import reports.owner_supplemental, reports.board_summary"` | `imports OK` | PASS |
| All unit + content tests pass | `.venv/Scripts/python.exe -m pytest tests/unit tests/content` | `143 passed, 224 warnings in 3.68s` | PASS |
| Phase-wide `business_unit` gate | `grep -c "business_unit" <5 blast-radius files>` | `0` for all five files | PASS |
| Phase-wide `Untagged` gate | `grep -c "Untagged" <5 blast-radius files>` | `0` for all five files | PASS |
| `Business Unit` display heading gate | `grep -n "Business Unit" <4 consumer modules>` | 0 matches | PASS |
| `_extract_owner_tag` removed | `grep -c "_extract_owner_tag" critical_remediation_sla_module.py` | `0` | PASS |
| `data/trend_store.py` layer isolation | `grep -c "from reports" data/trend_store.py` | `0` | PASS |
| `output/` gitignored | `git check-ignore output/` | `output/` | PASS |
| CR-01 vulnerable line present | `grep -n "set_index.*asset_uuid" reports/owner_supplemental.py` | Line 110 found — dedup missing | FAIL |
| WR-01: `--tag-category` flag absent | `grep -n "add_argument" scripts/capture_trend_snapshot.py` | Only `--month`, `--date`, `--verbose`, `--dry-run` registered | FAIL (WARNING) |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SEG-01 | 13-01 | Helper groups findings/assets by `Owner` tag, returns per-Owner buckets | SATISFIED | `extract_owner` + 8 tests; `test_owner_buckets_reconcile_to_whole` passes. |
| SEG-02 | 13-01 | Assets without Owner tag fall into `Unassigned` catch-all | SATISFIED | `extract_owner` returns `unassigned_label` on no-match; `test_no_owner_tag_is_unassigned` passes; configurable via `unassigned_label` param. |
| SEG-03 | 13-03 | Analyst exception list of Unassigned assets as operator-facing local output | BLOCKED — CR-01 | `write_owner_supplemental` produces the file correctly on clean data but raises `ValueError` on duplicate `asset_uuid` in production, silently returning `None` via fail-soft. The deliverable exists in code but is not reliably produced. |
| SEG-04 | 13-01 | Segmentation is fail-soft when Owner category is absent or partially applied | SATISFIED | `extract_owner` missing-column path: warning logged, all-Unassigned, no raise. Tested by `test_missing_tags_column_fail_soft`. |
| SEG-05 | 13-03 | Owner segmentation composes with trend primitive end-to-end | SATISFIED | `capture_snapshot(dimension="owner")` + `read_trend("owner", "all_assets")` round-trip tested by 6 content tests including `test_capture_owner_writes_owner_file`, `test_read_trend_owner_roundtrip`, `test_owner_counts_reconcile`. |
| DOC-01 | 13-04 | Substrate calculations runbook documenting open predicate, ~29-day retention, Owner/Unassigned model | SATISFIED | `docs/trend_and_segmentation_calculations.md` exists; all required content strings confirmed present; 8 sections; matches `docs/*_calculations.md` style. |

---

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `reports/owner_supplemental.py` | 110 | `enriched.set_index("asset_uuid")` without `.drop_duplicates("asset_uuid")` — raises `ValueError` on non-unique index when duplicate UUIDs present | BLOCKER | Supplemental silently returns `None` for asset populations with duplicate UUIDs; SEG-03 analyst worklist is absent without any operator-visible failure signal. |
| `scripts/capture_trend_snapshot.py` | 33-35 (runbook) / argparse | Runbook Quick Start documents `--tag-category` / `--tag-value` flags that are not registered in `_build_parser()`; running the documented command exits with `error: unrecognized arguments` | WARNING | Documentation/implementation contract break; operator following the runbook to capture a tag-scoped snapshot receives a usage error. |
| `scripts/capture_trend_snapshot.py` | 278-282 | `_log_completed(logger, start, "partial", ...)` followed by `return 3` — log status and exit code describe different severity levels | WARNING | Monitoring keyed on exit code 3 will alert as a hard failure; logfile shows partial success. Two observers see contradictory signals (WR-03). |

---

## Human Verification Required

None — all success criteria are verifiable programmatically.

---

## Gaps Summary

One gap blocks the phase goal:

**Truth 3 / SEG-03 — analyst exception list not reliably written.**

`write_owner_supplemental` in `reports/owner_supplemental.py` calls `enriched.set_index("asset_uuid")` at line 110 without first deduplicating by `asset_uuid`. The call site is inside the `try/except` fail-soft wrapper in `board_summary.py`, so the `ValueError` is swallowed and both supplemental paths return `None`. This is not a theoretical concern: `fetch_all_assets()` legitimately produces duplicate UUID rows for multi-network/multi-hostname assets, and the board pipeline itself calls `deduplicate_assets_by_name()` upstream for exactly this reason.

The fix is a single line:
```python
uuid_to_owner = (
    enriched[["asset_uuid", "owner", "application"]]
    .drop_duplicates("asset_uuid")
    .set_index("asset_uuid")
)
```

The two warnings (WR-01 doc/CLI mismatch, WR-03 exit-code/log-status contradiction) are not blockers against the phase goal but should be addressed before the script is handed to operators.

The four passing truths (SEG-01, SEG-02, SEG-04, SEG-05, DOC-01) are fully verified and represent solid, well-tested work.

---

_Verified: 2026-06-10T18:35:00Z_
_Verifier: Claude (gsd-verifier)_
