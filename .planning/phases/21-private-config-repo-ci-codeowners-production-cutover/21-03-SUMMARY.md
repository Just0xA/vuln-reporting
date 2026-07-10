---
phase: 21-private-config-repo-ci-codeowners-production-cutover
plan: 03
subsystem: infra
tags: [codeowners, yaml, config-governance, private-repo-reference]

# Dependency graph
requires:
  - phase: 21-01
    provides: Phase 20 config language (contacts.yaml + deliveries.d/<team>.yaml shape, resolve_config resolver contract) this plan's reference artifacts mirror
provides:
  - deploy/config-repo/CODEOWNERS.example — 1:1 per-file governance reference mapped to deliveries.d/, VM-team central stewardship (D-08), default rule for shared files (D-09), D-10 placeholder handle
  - deploy/config-repo/contacts.example.yaml — reference contacts+defaults shape mirroring the app repo's contacts.example.yaml, example.invalid only
  - deploy/config-repo/deliveries.d/README.md — one-file-per-team layout guidance (owner field, contact: refs, global name uniqueness, resolver-contract errors)
affects: [21-04, private-config-repo-provisioning]

# Tech tracking
tech-stack:
  added: []
  patterns: ["CODEOWNERS 1:1-per-file-with-central-roster governance pattern", "reference-template-in-public-repo-for-private-repo-artifact pattern (*.example / README, never real config)"]

key-files:
  created:
    - deploy/config-repo/CODEOWNERS.example
    - deploy/config-repo/contacts.example.yaml
    - deploy/config-repo/deliveries.d/README.md
  modified: []

key-decisions:
  - "CODEOWNERS 1:1 structure locked now (per-file entries matching deliveries.d/exec.yaml, remediation.yaml, tag_profile.yaml) but every entry — including the default * rule — resolves to the same @ORG/vuln-management-team placeholder, per D-08 central stewardship"
  - "@ORG/vuln-management-team is documented in-file as a D-10 provisioning placeholder, not a real handle; real handles are a change-management input filled at private-repo creation"
  - "SC2 reconciliation documented inline in CODEOWNERS.example: the 1:1 structure enables future per-team delegation, but the roster is centralized to VM team now — intentional, not an unmet criterion"
  - "No real deliveries.d/*.yaml config committed anywhere under deploy/config-repo/ — deliveries.d/README.md + an inline snippet stand in for the real per-team files, which live only in the private repo (Hard Rule 2 / D-02)"

patterns-established:
  - "Public-repo *.example / README references for private-repo-only artifacts: shape and governance rules are documented and verifiable in the public repo without ever committing real config or real VCS handles"

requirements-completed: [CONF-04]

# Metrics
duration: 12min
completed: 2026-07-09
---

# Phase 21 Plan 03: Private Config Repo Governance + Config-Tree Reference Summary

**CODEOWNERS.example with 1:1 per-file VM-team governance (D-08/D-09/D-10) plus a contacts.example.yaml + deliveries.d/README.md reference pair documenting the exact config-tree shape the private repo holds — all synthetic `example.invalid` identifiers, no real handles or config.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-09T20:45:00-04:00
- **Completed:** 2026-07-09T20:46:07-04:00
- **Tasks:** 2 completed
- **Files modified:** 3 (all new)

## Accomplishments
- Authored `deploy/config-repo/CODEOWNERS.example`: a leading default `*` rule covering shared cross-cutting files (`contacts.yaml`, `defaults`, schema copy) plus one per-file entry per `deliveries.d/` team file (exec, remediation, tag_profile), all resolving to the `@ORG/vuln-management-team` placeholder — with an in-file header documenting the D-10 placeholder status and the SC2 reconciliation.
- Authored `deploy/config-repo/contacts.example.yaml`, mirroring the app repo's root `contacts.example.yaml` shape (`contacts:` map + `defaults.analyst_mailbox`), with a header stating the Nothing-Defined-Twice guardrail.
- Authored `deploy/config-repo/deliveries.d/README.md` documenting the one-file-per-team convention: `owner:` field, `contact:` refs (never inline `email:`), global delivery-name uniqueness, registered report/module slugs, and the resolver-contract errors the CI gate (Plan 02) surfaces — with an illustrative `example.invalid` snippet.

## Task Commits

Each task was committed atomically:

1. **Task 1: Author the CODEOWNERS reference (per-file VM-team ownership + default rule)** - `08b03aa` (feat)
2. **Task 2: Author the reference contacts.yaml + deliveries.d/ layout guidance** - `3c340a7` (feat)

**Plan metadata:** (this commit, pending) `docs(21-03): complete plan`

## Files Created/Modified
- `deploy/config-repo/CODEOWNERS.example` - Governance reference: default `*` rule + 1:1 per-file entries, all VM-team, D-10 placeholder handle documented
- `deploy/config-repo/contacts.example.yaml` - Reference contacts + defaults shape for the private repo, example.invalid only
- `deploy/config-repo/deliveries.d/README.md` - One-file-per-team layout guidance + owner/contact-ref/uniqueness conventions + illustrative snippet

## Decisions Made
- Followed the plan's D-08/D-09/D-10 spec exactly: 1:1 CODEOWNERS structure, central VM-team roster, and a clearly-marked `@ORG/vuln-management-team` placeholder rather than any invented real handle.
- Placed the reference tree under `deploy/config-repo/` (matching the plan's stated output paths) as clearly-labelled templates for the operator to copy into the private config repo — not live configuration for this public repo.
- Did not commit a real `deliveries.d/*.yaml` file; the README's inline snippet plus the three CODEOWNERS-referenced team filenames (exec/remediation/tag_profile) are sufficient to document the shape without duplicating the Phase 20 fixture files.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. The plan's verify command for Task 2 referenced `.venv/bin/python3`, which is not present in this worktree (no project virtualenv checked into the worktree); the system `python3` (3.14, with PyYAML available) was used instead to run the identical yaml-parsing assertion. This is a tooling-path substitution only — the assertion logic and result are unchanged, so it is not logged as a deviation under Rules 1-4.

## User Setup Required

None - no external service configuration required. These are reference templates; the operator copies them into the private config repo at provisioning time (D-10), per the Plan 04 runbook.

## Next Phase Readiness
- CODEOWNERS.example and the contacts/deliveries.d reference pair are ready for Plan 04 (production cutover runbook) to cite as the artifacts the operator copies into the newly-provisioned private repo.
- No blockers. This plan is independent of 21-02 (CI gate) and both feed into 21-04's cutover documentation.

---
*Phase: 21-private-config-repo-ci-codeowners-production-cutover*
*Completed: 2026-07-09*

## Self-Check: PASSED

All created files verified present; all task/summary commits verified in git log.
