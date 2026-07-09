---
phase: 18-management-summary-migration-docs
plan: 05
subsystem: docs
tags: [management_summary, auditor-runbook, DOC-02, trend-reconstruction, module-metrics]

# Dependency graph
requires:
  - phase: 18-management-summary-migration-docs
    provides: "Plans 01-04: golden baselines, reconstruction script, and GEN-01 atomic cutover that this runbook documents"

provides:
  - "docs/management_summary_calculations.md extended with auditor-reproducible v1.4 Module Metrics section (seven rendered modules + related non-rendered disclosures + mandatory honesty disclosures)"
  - "DOC-02 satisfied: an auditor can recompute each of the seven rendered module metrics from the runbook alone"
  - "D-18-10 gate 5 GREEN — Phase 18 complete"

affects: [future-auditors, phase-18-review, v1.4-close]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-module runbook sections follow the docs/*_calculations.md convention (Calculation / Data Source / Edge Cases)"
    - "Rendered vs non-rendered separation: two clearly-labeled groups prevent auditor confusion about unrendered modules appearing in a composed-report runbook"
    - "Mandatory honesty-disclosure pattern: reconstruction predicate + temporal-paradox limitation + parity-bucket outcome as mandatory doc subsections"

key-files:
  created: []
  modified:
    - docs/management_summary_calculations.md

key-decisions:
  - "DOC-02 auditor-reproducibility is a human judgment — operator checkpoint (Task 2) confirmed the rendered/non-rendered separation and all mandatory disclosures are accurate"
  - "M5 (aged_vulns_assets) and M7 (new_vs_remediated) documented as intentional metric-design changes vs. bespoke path, NOT regressions — matching Plan 01 golden bucket assignment"
  - "Reopened temporal-paradox limitation explicitly stated as best-effort bounded by the D-18-09 overlap-test tolerance; captured months carry no such caveat"
  - "Rolling-30 MTTR window documented as a deliberate recent-velocity choice, not a data limit (D-18-06)"

patterns-established:
  - "Two-group separation in composed-report runbooks: 'Modules Rendered in report' vs 'Related Disclosures NOT Rendered' — prevents auditor confusion when modules are documented for completeness but absent from the composed PDF"
  - "Parity-bucket disclosure table: exact-match vs documented-difference, with intentional-change framing for any metric whose definition changed in the migration"

requirements-completed: [DOC-02]

# Metrics
duration: multi-session (Task 1 prior session; Task 2 operator checkpoint approved same session)
completed: 2026-06-21
---

# Phase 18 Plan 05: DOC-02 Auditor Runbooks Summary

**Auditor-reproducible v1.4 module-metrics runbook added to docs/management_summary_calculations.md: seven rendered module sections with formulas/fields/predicates, rendered-vs-non-rendered separation, and mandatory honesty disclosures (reconstruction predicate + reopened temporal-paradox + M5/M7 intentional-change parity-bucket)**

## Performance

- **Duration:** Multi-session (Task 1: prior session; Task 2 checkpoint: operator-approved)
- **Started:** Prior session
- **Completed:** 2026-06-21
- **Tasks:** 2 (1 auto + 1 checkpoint:human-verify)
- **Files modified:** 1

## Accomplishments

- Extended `docs/management_summary_calculations.md` with +742 lines covering the v1.4 Module Metrics section, enabling an auditor to recompute each of the seven rendered module metrics from the doc alone
- Clearly separated "Modules Rendered in management_summary (the seven)" from "Related v1.4 Disclosures NOT Rendered in management_summary" (external exposure, vulnerability density) — prevents auditor confusion about why non-rendered modules appear in the runbook
- Added all mandatory honesty disclosures: reconstruction predicate (open_findings_at + month_end_utc, ALL-ASSETS-ONLY scope, tag-scoped cold-start noted), reopened temporal-paradox limitation (best-effort, bounded by overlap tolerance, fix→reopen→fix intermediate months not perfectly reproducible), migration parity-bucket outcome (five exact-match metrics; M5/M7 as intentional design changes, not regressions), per-metric reconstructed-vs-cold-start split table, rolling-30 MTTR intent, and external-scope rule
- Operator checkpoint (Task 2) confirmed auditor reproducibility, disclosure accuracy, and honest-limitation framing — DOC-02 is an auditor-trust deliverable requiring human judgment

## Task Commits

1. **Task 1: Extend management_summary_calculations.md with v1.4 module metrics** - `1890351` (docs)
2. **Task 2: Operator auditor-reproducibility review** - APPROVED (no repo artifact — human checkpoint)

## Files Created/Modified

- `docs/management_summary_calculations.md` — Extended with v1.4 Module Metrics section: seven per-RENDERED-module subsections (total_vulns_by_severity, scan_coverage_sla, mttr_trend, patch_compliance_rate, aged_vulns_assets, accepted_recast, new_vs_remediated) + related-non-rendered disclosures + mandatory reconstruction/temporal-paradox/parity-bucket disclosures

## Decisions Made

- **DOC-02 requires operator sign-off:** Auditor reproducibility and honest-limitation framing are human judgments the executor cannot make; operator checkpoint (Task 2) confirmed the runbook meets the bar
- **M5/M7 framed as intentional metric-design changes:** aged_vulns_assets (bespoke age-bucket vuln histogram → % aged on-time-scanned assets) and new_vs_remediated (bespoke simple MoM total-open delta → inflow/outflow trend) are documented as deliberate improvements, not silent regressions — matching the Plan 01 golden bucket assignment
- **Temporal-paradox limitation stated honestly:** Tenable exports retain only most-recent state-transition timestamps; fix→reopen→fix intermediate months cannot be perfectly reconstructed; best-effort approximation is bounded by the D-18-09 overlap-test tolerance (spike +2-of-160,453 benchmark); captured months carry no such caveat

## Deviations from Plan

None — plan executed exactly as written. Task 1 completed in a prior session (commit `1890351`); Task 2 operator checkpoint was approved as written.

## Issues Encountered

None.

## User Setup Required

None — documentation-only change.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Docs-only change. T-18-14 (PII in runbook examples): verified — no real hostnames, IPs, plugin names, or asset-level examples appear in the extended section (aggregate formulas and field names only). T-18-15/15b/15c (misleading audit doc): mitigated — runbook written from AS-IMPLEMENTED Plan 03 script and Plan 04 cutover; operator confirmed disclosure accuracy at checkpoint.

## Self-Check

- [x] `docs/management_summary_calculations.md` modified — confirmed (commit `1890351`)
- [x] Task 1 commit `1890351` exists — confirmed via `git log`
- [x] Task 2 checkpoint APPROVED by operator — confirmed in execution context
- [x] DOC-02 requirement satisfied — all 15 disclosure tokens present, operator review passed
- [x] No PII examples in doc — verified against QUAL-05

## Self-Check: PASSED

## Next Phase Readiness

Phase 18 is complete. D-18-10 gate 5 is GREEN. All five plans executed and approved:
- Plan 01: golden baselines + smoke infrastructure
- Plan 02: reconstruction spike + backfill script
- Plan 03: reconstruction execution + overlap gate
- Plan 04: GEN-01 atomic cutover (management_summary → ReportComposer)
- Plan 05: DOC-02 auditor runbooks (this plan)

v1.4 milestone (Management Summary Reporting Improvement) is ready for close-out.

---
*Phase: 18-management-summary-migration-docs*
*Completed: 2026-06-21*
