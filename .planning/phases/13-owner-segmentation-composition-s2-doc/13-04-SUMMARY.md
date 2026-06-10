---
phase: 13-owner-segmentation-composition-s2-doc
plan: "04"
subsystem: documentation
tags: [documentation, runbook, trend, open-predicate, owner-segmentation, doc-01]
dependency_graph:
  requires:
    - reports/modules/board_report_utils.extract_owner (plan 01)
    - data/trend_store.capture_snapshot + read_trend (phase 12)
    - reports/owner_supplemental.write_owner_supplemental (plan 03)
    - utils/open_count.open_findings_at (plan 01 predecessor)
  provides:
    - docs/trend_and_segmentation_calculations.md (DOC-01 auditor runbook)
  affects: []
tech_stack:
  added: []
  patterns:
    - docs/*_calculations.md runbook structure (header block, ToC, numbered sections)
key_files:
  created:
    - docs/trend_and_segmentation_calculations.md
  modified: []
decisions:
  - "PII rule documented as AI/repo exposure prohibition (D-10) — internal email explicitly permitted; this is the real rationale, not an email ban"
  - "Two-interval model documented with exact clause breakdown matching open_findings_at implementation; naive form and ~19% silent-drop explained explicitly"
  - "~29-day retention constraint documented as a hard architectural constraint, not a soft recommendation; backfill explicitly prohibited with rationale"
  - "Unassigned catch-all documented as a reconcile-to-whole guarantee (SEG-02), not just a UX label"
metrics:
  duration: "~10 minutes"
  completed: "2026-06-10T20:00:00Z"
  tasks_completed: 1
  files_changed: 1
---

# Phase 13 Plan 04: Trend and Segmentation Calculations Runbook Summary

Eight-section auditor runbook documenting the reopened-aware two-interval open predicate, ~29-day Tenable retention and forward-accumulation model, Owner/Unassigned segmentation, the PII rule as AI/repo exposure (internal email permitted), and the trend_owner file location and tag_filter consistency requirement — matching the established docs/*_calculations.md style.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Author docs/trend_and_segmentation_calculations.md | 5b4fc66 | docs/trend_and_segmentation_calculations.md (created) |

## What Was Built

**`docs/trend_and_segmentation_calculations.md`** — DOC-01 auditor runbook:

1. **Quick Start** — how to capture a monthly owner snapshot via `scripts/capture_trend_snapshot.py`, read it back via `read_trend("owner","all_assets")`, and run the board report to produce the supplemental.

2. **Data Sources** — open/reopened vulns parquet, assets parquet; VPR-first severity; note that `owner` column is derived at runtime by `extract_owner`, not stored in parquet.

3. **Open Predicate — Reopened-Aware Two-Interval Model** — documents the exact three fixed-state clauses from `utils/open_count.py open_findings_at`; explains why the naive `last_fixed IS NULL OR last_fixed > D` form silently drops ~19% of findings (the entire REOPENED population); documents NaT-first_found inclusion policy; lists required columns with their expected types.

4. **~29-Day Retention and Forward-Accumulation Model** — documents the Tenable fixed-finding retention limit; explains why multi-month reconstruction is not possible; cold-start behaviour; no-backfill rule; same-month idempotency.

5. **Owner / Unassigned Segmentation Model** — Owner tag = Application Support (patching-responsible); Business Unit and Technical Support are future/reference dimensions (not built); Application is nested analyst drill-down (D-05); Unassigned catch-all guarantees reconcile-to-whole (SEG-02); fail-soft path (SEG-04); tag format and single-pass parser description.

6. **Combined Supplemental** — `write_owner_supplemental` output shape (Owner | Application | Open Findings | Asset Count); Unassigned rows as tagging-cleanup worklist; PII rule documented as: internal email permitted, repo commit prohibited, AI/Claude context prohibited (D-10, the real rationale); fail-soft wiring in board_summary.

7. **Trend Composition and Data Store** — file-per-dimension naming convention; owner file at `data/trend/trend_owner_all_assets.json`; severity vs owner snapshot payload shapes (aggregate counts only, TREND-06/D-11); timezone policy (month=local, generated_at=UTC); tag_filter consistency requirement with diagnostic snippet; `capture_snapshot` call pattern with pre-enrichment.

8. **Troubleshooting** — `insufficient_data=True` causes (cold start, tag_filter mismatch, missing directory); all-Unassigned diagnosis (Owner tag not assigned, enriched_assets missing, tags column absent); corrupt file recovery; `ValueError` for missing enriched_assets.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. This is a documentation-only plan; no code, no rendering, no data wiring.

## Threat Flags

T-13-13 (Info Disclosure): All illustrative examples in the runbook use synthetic placeholder names (e.g., "Network Defense", "Finance Application Support") and no real hostnames, IPs, or asset UUIDs appear in the committed document. D-10 repo-commit ban applies to docs as noted in the threat register.

T-13-14 (Repudiation / doc drift): doc authored after Plans 01 and 03 landed (depends_on satisfied), describing the implemented behaviour. Future drift is handled by normal doc maintenance.

## Self-Check: PASSED

- `docs/trend_and_segmentation_calculations.md` exists: FOUND
- Contains "two-interval": CONFIRMED
- Contains "resurfaced_date": CONFIRMED
- Contains "29": CONFIRMED
- Contains "forward": CONFIRMED
- Contains "Unassigned": CONFIRMED
- Contains "open_findings_at": CONFIRMED
- Contains "trend_owner": CONFIRMED
- Contains "AI" (PII rule framing): CONFIRMED
- Contains "internal email: permitted" framing: CONFIRMED
- Contains "prohibited" (repo/AI ban): CONFIRMED
- Contains **File:**, **Audience:**, **Outputs:** header block: CONFIRMED
- Commit 5b4fc66: FOUND
