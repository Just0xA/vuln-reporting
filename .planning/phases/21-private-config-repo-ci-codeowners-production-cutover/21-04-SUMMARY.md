---
phase: 21-private-config-repo-ci-codeowners-production-cutover
plan: 04
subsystem: infra
tags: [provenance, cutover, runbook, config-loader, dual-source]

# Dependency graph
requires:
  - phase: 21-private-config-repo-ci-codeowners-production-cutover
    provides: "Plan 21-01 _select_config_source / _load_config dual-source fallback (D-04) and _dry_run active-source echo (D-05)"
provides:
  - "scripts/stamp_config_provenance.py — D-03 provenance stamp/verify CLI tying live server config to a reviewed repo commit SHA"
  - "RUNBOOK.md \"Delivery Config — Reviewed-Repo Cutover\" section: documented private-repo -> PR -> CODEOWNERS -> CI -> merge -> copy -> stamp flow"
  - "RUNBOOK.md updated layout diagram (shared/config/ + .config-provenance.json sidecar) and safe-to-edit table (server SSH hand-edits no longer documented)"
  - "Operator sign-off: dual-source fallback echo, provenance round-trip, and runbook clarity verified on real/staging infra"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "sha256 + source-commit-SHA sidecar (.config-provenance.json) as the drift-detection mechanism for reviewed-config-to-server traceability (D-03)"

key-files:
  created:
    - scripts/stamp_config_provenance.py
    - tests/test_stamp_config_provenance.py
  modified:
    - RUNBOOK.md

key-decisions:
  - "D-03 provenance implemented as source-commit-SHA + sha256 stamp/verify sidecar (.config-provenance.json), per Task 1 acceptance criteria — not a checksum-only or git-tag scheme."
  - "Server directory-mode config location chosen as shared/config/ (contacts.yaml + deliveries.d/), documented alongside the pre-existing shared/ symlink layout; symlink_shared() decision stated explicitly in RUNBOOK.md rather than silently skipped."
  - "Operator approved the checkpoint after verifying all four staging/synthetic checks (directory-mode dry-run, legacy-fallback dry-run, provenance round-trip + drift, runbook read-through) — production cutover itself remains operator-only per Hard Rule 1/2 and D-10 change management."

requirements-completed: [QUAL-07, CONF-04]

# Metrics
duration: 15min
completed: 2026-07-10
---

# Phase 21 Plan 04: Production Cutover — Provenance + Runbook Summary

**D-03 provenance stamp/verify CLI plus a RUNBOOK "Reviewed-Repo Cutover" runbook, both operator-approved via dual-source dry-run verification — the live server config is now traceable to a reviewed commit and the documented edit path drops SSH hand-edits.**

## Performance

- **Duration:** ~15 min (Tasks 1-2 build; Task 3 operator checkpoint approved same session)
- **Started:** 2026-07-09T20:48:44-04:00 (previous phase-tracking commit)
- **Completed:** 2026-07-10 (checkpoint approval)
- **Tasks:** 3 (2 autonomous + 1 operator checkpoint)
- **Files modified:** 3 (2 created, 1 modified)

## Accomplishments
- D-03 provenance mechanism shipped: `stamp`/`verify` subcommands recording source commit SHA, UTC timestamp, and sha256 of the config tree in a `.config-provenance.json` sidecar, with round-trip + drift tests passing.
- RUNBOOK.md documents the full reviewed-repo cutover: layout diagram extended with `shared/config/` + sidecar + dual-source coexistence note; safe-to-edit table and SSH nano guidance replaced with the private-repo -> PR -> CODEOWNERS -> CI -> merge -> copy -> stamp flow; QUAL-07 SC4 zero-interruption cutover sequence and D-04 rollback note documented.
- Operator independently verified the dual-source fallback echo, the provenance round-trip/drift detection, and the runbook's clarity on their environment, and approved the checkpoint — closing out CONF-04 SC3 and QUAL-07 SC4 for Phase 21.

## Task Commits

Each task was committed atomically:

1. **Task 1: Build the D-03 config provenance stamp/verify script** - `3e276d2` (feat)
2. **Task 2: Write the RUNBOOK cutover runbook + update layout diagram and safe-to-edit table** - `b994b96` (docs)
3. **Task 3: Operator dual-source cutover dry-run verification** - checkpoint:human-verify (gate=blocking) — no file changes; operator responded "approved" after independently running the four verification steps below.

**Plan metadata:** this summary's commit (docs: complete plan)

## Files Created/Modified
- `scripts/stamp_config_provenance.py` - argparse CLI with `stamp` (writes `.config-provenance.json` sidecar: source commit SHA, ISO-8601 UTC timestamp, sha256 of the config tree) and `verify` (recomputes sha256, exits non-zero on drift or missing sidecar) subcommands; no recipient content, only SHAs/checksums/timestamps (Hard Rule 2)
- `tests/test_stamp_config_provenance.py` - round-trip, drift, missing-sidecar, and missing-config-dir cases using synthetic `example.invalid` fixtures only
- `RUNBOOK.md` - new "Delivery Config — Reviewed-Repo Cutover" section; layout diagram extended with `shared/config/` (contacts.yaml + deliveries.d/) and the provenance sidecar; safe-to-edit table row and SSH nano guidance replaced with the reviewed-repo flow; explicit `symlink_shared()` decision recorded; D-04 rollback note included

## Decisions Made
- D-03 realized as source-commit-SHA + sha256 sidecar stamp/verify (Claude's discretion per 21-CONTEXT.md), matching the plan's `stamp`/`verify` acceptance criteria exactly.
- `shared/config/` chosen as the server directory-mode location, consistent with the existing `shared/` symlink pattern; the `symlink_shared()` entry decision was made explicit in the runbook rather than deferred.
- Operator approval closes the checkpoint on the strength of staging/synthetic verification; the actual private-repo provisioning and first live cutover remain a separate, operator-only change-management action (D-10), unchanged by this plan.

## Deviations from Plan

None - plan executed exactly as written. Tasks 1 and 2 were built and committed in the prior execution session; Task 3 was a non-autonomous, no-file-change checkpoint that the operator ran and approved in this session.

## Issues Encountered

None blocking. One environment note surfaced during the operator's manual verification, worth capturing for future operators:

**Venv interpreter gotcha (not a defect in this plan's deliverables):** on the operator's WSL host, bare `python` is not on `PATH`. Commands from the how-to-verify steps (`run_all.py --dry-run`, `stamp_config_provenance.py stamp`/`verify`) must be run through the project venv — `source .venv/bin/activate` first, or invoke directly via `.venv/bin/python3`. This matches the plan's own automated-verify convention (`.venv/bin/python3 -m pytest ...`) but the checkpoint's `how-to-verify` steps used bare `python` for brevity; future runbook/checkpoint text should default to the venv-qualified interpreter to avoid this friction.

## Verification

- **Automated (Task 1):** `.venv/bin/python3 -m pytest tests/test_stamp_config_provenance.py -x -q` passes (round-trip + drift + missing-sidecar + missing-config-dir cases).
- **Automated (Task 2):** grep gates confirm RUNBOOK.md contains the reviewed/private-repo language, `dual-source`, `stamp_config_provenance`, and `CODEOWNERS` — all present (`OK`).
- **Operator sign-off (Task 3):** operator ran all four staging/synthetic checks and responded "approved":
  1. Directory-mode config placed beside legacy `delivery_config.yaml`; `run_all.py --dry-run` (via venv interpreter) reports the active-source line as directory-mode and all deliveries validate OK.
  2. Directory-mode config broken (renamed `contacts.yaml`); `--dry-run` re-run reports legacy-fallback as the active source and validation still passes off the legacy file (D-04 zero-interruption confirmed).
  3. `stamp_config_provenance.py stamp` then `verify` round-trip passes (exit 0); mutating a config byte then re-running `verify` correctly exits non-zero (drift detected).
  4. RUNBOOK.md "Delivery Config — Reviewed-Repo Cutover" section read correctly: private-repo -> PR -> CODEOWNERS -> CI -> merge -> copy -> stamp flow, and the one-full-dual-source-cycle-before-retiring-legacy sequence, both confirmed clear and correct for the operator's environment.

## User Setup Required

None - no external service configuration required. The actual production cutover (provisioning the private repo, first live PR/CODEOWNERS/CI cycle, first real dual-source window) remains a separate operator-only action under change management (D-10, Hard Rule 1/2) and is out of scope for this plan's deliverables.

## Next Phase Readiness

- CONF-04 SC3 and QUAL-07 SC4 are both satisfied: provenance mechanism ships, documented cutover path replaces SSH hand-edits, and the zero-interruption dual-source sequence is verified end to end (mechanism + operator sign-off).
- Phase 21 (private-config-repo-ci-codeowners-production-cutover) has no further plans pending in this wave; the production cutover itself is now unblocked for the operator to schedule under normal change management.
- Runbook follow-up: consider qualifying `python` invocations in checkpoint `how-to-verify` steps with the venv path/activation, consistent with the plan's own automated-verify commands, to avoid the PATH gotcha hit during this operator verification.

---
*Phase: 21-private-config-repo-ci-codeowners-production-cutover*
*Completed: 2026-07-10*

## Self-Check: PASSED

- `.planning/phases/21-private-config-repo-ci-codeowners-production-cutover/21-04-SUMMARY.md` — FOUND
- `scripts/stamp_config_provenance.py` — FOUND
- `tests/test_stamp_config_provenance.py` — FOUND
- `RUNBOOK.md` grep gates (reviewed/private-repo, dual-source, stamp_config_provenance, CODEOWNERS) — all present
- Commit `3e276d2` (Task 1) — FOUND in `git log --oneline`
- Commit `b994b96` (Task 2) — FOUND in `git log --oneline`
- Task 3 — no file artifacts expected (checkpoint:human-verify, no autonomous changes); operator approval recorded above
