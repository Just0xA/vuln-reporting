---
phase: 09-ci-release-automation
plan: "02"
subsystem: ci-release
tags: [ci, release, security, tarball-assertion]
dependency_graph:
  requires: ["09-01"]
  provides: ["tarball-content-assertion"]
  affects: [".github/workflows/release.yml"]
tech_stack:
  added: []
  patterns:
    - "bash accumulator pattern for fail-on-any-finding with set -euo pipefail"
    - "sed+cut bare-value extraction to avoid awk -F: VARNAME=value pitfall"
    - "find -print0 / read -d '' loop for NUL-safe file walking"
key_files:
  created: []
  modified:
    - .github/workflows/release.yml
decisions:
  - "Used sed -E 's/^[^:]+:[0-9]+://' + cut -d= -f2- for bare-value extraction; awk -F: '{print $3}' is incorrect because it yields VARNAME=value not just value"
  - "grep guarded with || true inside find loop; fail decision driven by LEAK accumulator, not grep exit code"
  - "No trap for EXTRACT_DIR cleanup — runner is ephemeral"
metrics:
  duration: "~5 minutes"
  completed: "2026-05-19"
  tasks_completed: 1
  tasks_total: 1
  files_modified: 1
---

# Phase 9 Plan 02: Tarball-Content Assertion Step Summary

One-liner: Tarball-content assertion step in release.yml that blocks forbidden paths and non-placeholder credentials before upload.

## What Was Built

Replaced the `# Tarball-content assertion step inserted by Plan 09-02` marker comment in `.github/workflows/release.yml` with a fully functional `Assert tarball contents` bash step, positioned between `Compute SHA256 sidecar` and `Upload to GitHub Release`.

The step:
1. Verifies the tarball file exists before proceeding
2. Extracts to `mktemp -d` and asserts the expected `vuln-reporting-${VERSION}` root is present
3. Checks 12 forbidden paths: `.planning`, `.env`, `.env.local`, `data/trend`, `.git`, `tests`, `docs`, `ref`, `CLAUDE.md`, `RUNBOOK.md`, `CONTRIBUTING.md`, `.github` — distinguishing file vs. directory in log output
4. Scans all files with `find -type f -print0` + NUL-safe `read` loop, greping for `^(TVM_ACCESS_KEY|TVM_SECRET_KEY|SMTP_PASSWORD)=`, extracting bare values via `sed+cut`, whitelisting the three `.env.example` placeholder strings
5. Accumulates findings into `FOUND` and `LEAK` arrays; exits 1 with a summary count if either is non-empty; otherwise prints the clean-pass message and exits 0

## Commits

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Insert Assert tarball contents step | 3bcf393 | `.github/workflows/release.yml` |

## Verification Results

All 8 automated checks passed:
- Step name `Assert tarball contents` present
- Plan 09-01 marker comment removed
- `set -euo pipefail` present
- All 12 forbidden paths listed (spot-checked `.planning`, `data/trend`, `CLAUDE.md`)
- All 3 credential variables scanned
- All 3 placeholder whitelist values present
- YAML step ordering: `Compute SHA256 sidecar` → `Assert tarball contents` → `Upload to GitHub Release`
- Local `git archive HEAD` sanity check: no forbidden paths in current HEAD tarball (Phase 7 boundary intact)
- Leak-detector smoke test: correctly flags `TVM_ACCESS_KEY=AAAAA-real-looking-key`

Two human-check items remain (require a live GitHub Actions run):
- Negative test: commit fake `.env` with real-looking key, run assertion locally, confirm non-zero exit + offending path logged
- Positive test: confirm `v0.0.0-alpha1` smoke-tag run (from Plan 09-01) shows `Tarball assertion passed: no forbidden paths, no credential leaks`

## Deviations from Plan

None — plan executed exactly as written. The awk extraction warning in the plan was heeded; sed+cut used throughout.

## Self-Check: PASSED

- `.github/workflows/release.yml` modified: confirmed present and YAML-valid (python yaml.safe_load passed)
- Commit 3bcf393 exists: confirmed via git log
- No unexpected file deletions (1 file changed, 80 insertions, 1 deletion — only the marker comment line removed)
- Phase 7 boundary intact: local archive sanity check passed
