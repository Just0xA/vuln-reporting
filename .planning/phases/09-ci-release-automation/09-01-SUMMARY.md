---
phase: 09-ci-release-automation
plan: 01
subsystem: infra
tags: [github-actions, git-archive, release-automation, semver, sha256]

requires: []
provides:
  - GitHub Actions workflow that builds and publishes slim release tarballs on v* tag push or workflow_dispatch
  - SHA256 sidecar uploaded alongside tarball on every release
  - Prerelease detection for -rc/-beta/-alpha tag suffixes
  - Insertion marker for Plan 09-02 tarball-content assertion step
affects:
  - 09-ci-release-automation/09-02 (inserts assertion step into this workflow)
  - Phase 10 (update_from_github.sh consumes sha256sum output format)

tech-stack:
  added: [github-actions, softprops/action-gh-release@v3, actions/checkout@v6]
  patterns:
    - "version resolution: single step outputs VERSION for all downstream steps"
    - "prerelease detection: grep -qE for -rc/-beta/-alpha substrings"
    - "git archive against resolved ref (not HEAD) for workflow_dispatch correctness"
    - "set -euo pipefail in every run: block"

key-files:
  created:
    - .github/workflows/release.yml
  modified: []

key-decisions:
  - "Use major-version pins (v6/v3) over SHA pins — Dependabot can auto-bump; SHA pins fail silently on security patches"
  - "git archive passes VERSION ref, not HEAD, so workflow_dispatch re-runs against historical tags produce correct tarballs"
  - "No exclusion list in workflow — rely entirely on .gitattributes export-ignore boundary (Plan 09-02 is the runtime safety net)"
  - "GH_TOKEN set at job env level as forward-looking convenience for future gh CLI steps (not load-bearing today)"

patterns-established:
  - "Insertion marker comment: Plan 09-02 expects the literal line '# Tarball-content assertion step inserted by Plan 09-02'"

requirements-completed: [CI-01, CI-02, CI-03, CI-04, CI-05, CI-07]

duration: 2min
completed: 2026-05-19
---

# Phase 09 Plan 01: Release Workflow Summary

**GitHub Actions workflow that builds vuln-reporting-vX.Y.Z-slim.tar.gz via git archive, computes SHA256 sidecar, detects -rc/-beta/-alpha prerelease suffixes, and publishes both assets to GitHub Releases on tag push or workflow_dispatch**

## Performance

- **Duration:** 2 min
- **Started:** 2026-05-19T20:55:25Z
- **Completed:** 2026-05-19T20:57:25Z
- **Tasks:** 1 of 1
- **Files modified:** 1

## Accomplishments

- Created `.github/workflows/release.yml` with triggers, permissions, version resolution, tarball build, SHA256 sidecar, and asset upload
- Hardened against shell injection via semver regex validation on `inputs.version` before it reaches `git archive`
- Placed Plan 09-02 insertion marker at the exact location between sha256 and upload steps

## Task Commits

1. **Task 1: Author .github/workflows/release.yml** — `fc5d7a9` (feat)

**Plan metadata:** (in final docs commit)

## Files Created/Modified

- `.github/workflows/release.yml` — 83-line GitHub Actions workflow: triggers, permissions, version resolution, prerelease detection, slim tarball build, SHA256 sidecar, softprops upload

## Decisions Made

- Multi-line `git archive` command (backslash continuation) used for YAML readability — functionally identical to single-line form; plan's verify grep pattern assumed single-line but the file is correct
- Prerelease input to `softprops/action-gh-release@v3` passed as `${{ steps.prerelease.outputs.prerelease == 'true' }}` expression — evaluates to `true`/`false` string at template expansion time, which the action accepts

## Deviations from Plan

None — plan executed exactly as written. One minor note: the plan's automated verify grep `grep -E "git archive --format=tar\.gz --prefix=vuln-reporting-"` fails because the git archive invocation is formatted across multiple lines in the YAML run block. The command itself is logically identical; this is a grep-script quirk, not a workflow deficiency. All other automated verifies pass cleanly.

## Issues Encountered

- PyYAML parses bare `on:` key as Python boolean `True` (YAML 1.1 behavior). The plan's shape-check script used `'on' in d`; the actual key is `True`. The workflow YAML is valid and GitHub Actions parses it correctly — this is a known PyYAML limitation that does not affect the real CI behavior.

## User Setup Required

**Human-check required post-merge (one-time smoke test):**

1. Push `v0.0.0-alpha1` tag: `git tag v0.0.0-alpha1 && git push origin v0.0.0-alpha1`
2. Observe the Actions tab — workflow should run to completion
3. Confirm the Release page shows two assets: `vuln-reporting-v0.0.0-alpha1-slim.tar.gz` and `vuln-reporting-v0.0.0-alpha1-slim.tar.gz.sha256`
4. Confirm release is marked as **Pre-release** (the `-alpha1` suffix triggers prerelease detection)
5. Delete the test release and tag: delete from GitHub UI then `git push --delete origin v0.0.0-alpha1`

**Local dry-run (optional, verifies .gitattributes boundary):**
```bash
git archive --format=tar.gz --prefix=vuln-reporting-vtest/ -o /tmp/test.tar.gz HEAD
tar -tzf /tmp/test.tar.gz | head -30
```
Confirm no `.planning/`, `docs/`, `tests/`, `CLAUDE.md`, `.github/`, or `data/trend/` paths appear.

## Next Phase Readiness

- `.github/workflows/release.yml` is in place; Plan 09-02 inserts the tarball-content assertion step between the sha256 and upload steps using the insertion marker
- The `-slim` suffix, SHA256 sidecar format (`sha256sum` GNU default), and version ref passing are all conventions Plan 09-02 and Phase 10 depend on — established here

---
*Phase: 09-ci-release-automation*
*Completed: 2026-05-19*
