---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "07"
subsystem: config / modules / docs
tags: [cleanup, dead-code, VPR, import-hoist, docs]
dependency_graph:
  requires: ["19-02", "19-04"]
  provides: ["contiguous-VPR-bands", "dead-code-cleared", "docs-reconciled"]
  affects: ["config.py", "reports/modules/*", "scripts/backfill_trend_reconstruction.py", "utils/open_count.py", "data/trend_store.py", "docs/*", "run_all.py", "scripts/smoke_*.py"]
tech_stack:
  added: []
  patterns: ["TDD RED/GREEN for config correctness", "AST-based dead-import verification", "MIMEImage CID attach pattern"]
key_files:
  created:
    - tests/test_config.py
  modified:
    - config.py
    - reports/modules/reopened_vulns_module.py
    - reports/modules/external_dmz_module.py
    - reports/modules/new_vs_remediated_module.py
    - scripts/backfill_trend_reconstruction.py
    - utils/open_count.py
    - data/trend_store.py
    - docs/management_summary_calculations.md
    - docs/trend_and_segmentation_calculations.md
    - scripts/smoke_management_summary_cutover.py
    - run_all.py
    - scripts/smoke_email_phase2.py
    - tests/test_new_vs_remediated_module.py
    - .planning/phases/18-management-summary-migration-docs/18-VALIDATION.md
    - .planning/milestones/v1.3-phases/13-owner-segmentation-composition-s2-doc/13-03-SUMMARY.md
    - .planning/phases/15-independent-new-modules/15-02-SUMMARY.md
    - .planning/phases/14-shared-substrates-composed-report-gates/14-03-PLAN.md
decisions:
  - "WR-08: used 8.99/6.99/3.99 upper-bound form (not half-open < 9.0 logic) for minimal churn on the (lo, hi, label) tuple shape — gap-closed, existing callers unaffected"
  - "15-REVIEW IN-03: removed _safe_mom_delta AND its TestSafeMomDelta test class — the helper was dead (zero callers), so the tests were testing unreachable code"
  - "CR-G4: threaded email_inline_images through _build_synthetic_outputs return tuple and _smtp_send signature rather than a global — keeps the attach logic local to the send path"
  - "CR-G8: confirmed already resolved during triage (19-CONTEXT.md placeholder is now concrete reference to 19-CODERABBIT-TRIAGE.md); no code change needed"
metrics:
  duration_seconds: 2700
  completed_date: "2026-06-25"
  tasks: 3
  files: 17
---

# Phase 19 Plan 07: Cleanup Backlog Clearance Summary

Low-value cleanup wave (D-02 separation): dead code, unused imports, stale docs/comments cleared in isolation from correctness commits. Closes all remaining 18-REVIEW and 15-REVIEW items plus CodeRabbit G-bucket doc/comment findings.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | WR-08 VPR band gap + IN-01 math hoist (TDD) | 393859a | config.py, tests/test_config.py |
| 2 | Dead-code/import removals (15-REVIEW IN-01..04, 18-REVIEW WR-04/IN-04/IN-05) | 76041c3 | 7 files |
| 3 | Doc/comment staleness CR-G1..G5, G8..G12 + IN-03 runbook + CR-G4 functional CID attach | 17c1acc | 9 files |

## What Was Built

### Task 1 — WR-08 + IN-01 (TDD)

**VPR band contiguity (WR-08):** `VPR_SEVERITY_MAP` upper bounds corrected from `8.9/6.9/3.9` to `8.99/6.99/3.99`, closing the three gaps where scores like 8.95 / 6.95 / 3.95 fell through to the native-severity fallback instead of their correct tier. CLAUDE.md mandates VPR as authoritative; fallback for in-range scores was a silent correctness failure.

**Math import hoist (IN-01):** `import math` moved from inside `vpr_to_severity()` to module-level, removing a per-call import on the hot path.

**Tests:** 22 new tests in `tests/test_config.py` covering all six gap-boundary cases, band-edge cases, None/NaN/string fallback, and an AST-based structural check that confirms `import math` is at module level and NOT inside `vpr_to_severity`.

### Task 2 — Dead-code/import removals

**15-REVIEW IN-01:** Removed unused `safe_format` from `from ... format_utils import` in `reopened_vulns_module`, `external_dmz_module`, `new_vs_remediated_module`. (`vuln_density_module` retains it — it is used there.)

**15-REVIEW IN-02:** Removed dead `_rag_fill` function definition from the three modules above. Only `vuln_density_module` calls `_rag_fill` (confirmed by grep/AST); definitions in the other three modules were unreachable.

**15-REVIEW IN-03:** Removed dead `_safe_mom_delta` from `new_vs_remediated_module` (zero callers confirmed). Also removed the corresponding `TestSafeMomDelta` class from `test_new_vs_remediated_module.py` which directly tested the now-deleted symbol (Rule 1 auto-fix: test would have blocked collection).

**15-REVIEW IN-04:** Trimmed unused `NO_DATA_DRIVER`, `STATUS_COLOR`, `STATUS_LABEL` from `reopened_vulns_module` rag_utils import block. Trimmed `STATUS_COLOR` from `external_dmz_module` and `NO_DATA_DRIVER` from `new_vs_remediated_module` (per AST analysis of actual usage).

**18-REVIEW WR-04:** Deleted `_months_in_range` (lines 202-221) and its inline `from dateutil.relativedelta import relativedelta` from `backfill_trend_reconstruction.py`. All call sites already used `_months_in_range_stdlib`. `dateutil` is not in requirements (locked stack).

**18-REVIEW IN-04:** Updated `utils/open_count.py` docstring — removed stale `management_summary._OPEN_STATES` reference (symbol removed in GEN-01). Also updated an inline comment referencing `_OPEN_STATES`.

**18-REVIEW IN-05:** Extended `data/trend_store.py` `capture_snapshot` docstring with an "Owner-dimension scope (IN-05)" note clarifying that `dimension="owner"` does not populate aggregate count fields (`reopened_count`, `accepted_count`, etc.).

### Task 3 — Doc/comment staleness

**CR-G1:** `smoke_management_summary_cutover.py` module docstring rewritten to describe the current v1.4 `ReportComposer` / `result["_bundle"]` path; removed all "old bespoke path" framing from the description of current behavior.

**CR-G2:** `run_all.py` `_CHROME_AWARE_SLUGS` comment updated — replaced stale "CHROME-COMPAT-01: management_summary MUST NOT receive chrome kwargs" (no longer true post-GEN-01) with accurate note that `management_summary` accepts chrome kwargs and `ops_remediation` does not.

**CR-G3:** `smoke_email_phase2.py` `--no-stub-panels` help text corrected. Old text claimed the flag "lets the legacy KPI-tile fallback render" which was wrong; new text accurately states it disables the empty-panels stub fallback only.

**CR-G4 (functional):** `smoke_email_phase2.py` now attaches inline CID gauge images to the sent email. Added `from email.mime.image import MIMEImage` import; threaded `email_inline_images` out of `_build_synthetic_outputs` return tuple; added MIMEImage attach loop in `_smtp_send` (mirrors `delivery/email_sender.py`'s `email_inline_images` handling pattern). Previously the panel HTML referenced `cid:` URLs that were never resolved in the recipient's email client.

**CR-G5:** `docs/trend_and_segmentation_calculations.md` "No backfill" section rewritten as "Backfill": describes the sanctioned `backfill_trend_reconstruction.py` path first, then explicitly marks manual/ad-hoc backfill as unsupported.

**CR-G8:** Verified already resolved during triage — the `19-CONTEXT.md` placeholder ref now points to the concrete `19-CODERABBIT-TRIAGE.md` file. No code change needed.

**CR-G9:** `18-VALIDATION.md` frontmatter corrected: `wave_0_complete: false` → `true` (phase fully approved and signed off).

**CR-G10:** `13-03-SUMMARY.md` `_count_by_owner` description clarified: "Empty/missing `enriched_assets` guard produces all-Unassigned" was self-contradictory with the frontmatter truth that `enriched_assets=None` raises `ValueError`. Corrected to: empty DataFrame (zero rows) → all-Unassigned; None → rejected upstream by `capture_snapshot` with `ValueError` (T-13-12).

**CR-G11:** `15-02-SUMMARY.md` invalid Python set notation fixed: `{"ACCEPTED"/"RECASTED"}` → `{"ACCEPTED", "RECASTED"}`.

**CR-G12:** `14-03-PLAN.md` malformed acceptance-criteria shell check fixed: trailing space removed and assertion made concrete (`assert 'sc4_kwargs_stub' in registry._registry`).

**18-REVIEW IN-03:** `docs/management_summary_calculations.md` — added `HISTORICAL NOTE` banner at the top of sections 1-18 marking them as describing the removed pre-v1.4 bespoke path; updated the `compute_all_metrics()` reference in the SLA section to note both pre/post-v1.4 paths; the authoritative v1.4 runbook remains the "v1.4 Module Metrics" section at the bottom.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] test_new_vs_remediated_module.py imported deleted symbol**
- **Found during:** Task 2
- **Issue:** `test_new_vs_remediated_module.py` directly imported `_safe_mom_delta` from `new_vs_remediated_module`. After removing the dead function, the test file failed collection with `ImportError`.
- **Fix:** Removed `_safe_mom_delta` from the import and deleted the `TestSafeMomDelta` class (7 tests that covered now-deleted dead code).
- **Files modified:** `tests/test_new_vs_remediated_module.py`
- **Commit:** 76041c3

## Known Stubs

None — all plan goals produce real behavior changes. CR-G4 now functionally attaches CID images (not a stub).

## Threat Flags

None — this was a cleanup-only wave. No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check

- [x] `tests/test_config.py` exists: FOUND
- [x] `393859a` exists in git log: FOUND
- [x] `76041c3` exists in git log: FOUND
- [x] `17c1acc` exists in git log: FOUND
- [x] 197 tests pass (test_config + test_backfill_reconstruction + test_reopened_vulns + test_external_dmz + test_new_vs_remediated + test_vuln_density)
- [x] `grep -c "_months_in_range[^_]" scripts/backfill_trend_reconstruction.py` == 0
- [x] `grep -c "_OPEN_STATES" utils/open_count.py` == 0
- [x] `grep -qi "MIMEImage\|Content-ID" scripts/smoke_email_phase2.py` matches

## Self-Check: PASSED
