---
phase: 09-ci-release-automation
verified: 2026-05-19T21:05:00Z
status: passed
score: 7/7 must-haves verified
gaps: []
human_verification:
  - test: "Push v0.0.0-alpha1 smoke tag"
    expected: |
      Workflow runs end-to-end; two assets (tarball + sha256) appear on the Release page;
      release is marked Pre-release; assertion step prints
      "Tarball assertion passed: no forbidden paths, no credential leaks"
    why_human: "Requires a live GitHub Actions runner and repo push access; cannot be exercised by static inspection"
---

# Phase 9: CI/Release Automation — Verification Report

**Phase Goal:** Pushing a `v*` tag publishes a slim, validated release tarball + SHA256 checksum to GitHub Releases automatically, with prerelease tags marked and forbidden paths blocked at build time
**Verified:** 2026-05-19T21:05:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Slim tarball + SHA256 built and published on `v*` tag push | VERIFIED | `release.yml` lines 56-70: `git archive` with `-slim.tar.gz` suffix; `sha256sum` sidecar; both uploaded via `softprops/action-gh-release@v3` lines 153-162 |
| 2 | `workflow_dispatch` re-run path with `version` input | VERIFIED | `release.yml` lines 7-12: `workflow_dispatch` trigger with required `version` input; Resolve version step lines 34-36 branches on `github.event_name == 'workflow_dispatch'` |
| 3 | `-rc`/`-beta`/`-alpha` tags produce `prerelease: true`; bare semver tags produce stable releases | VERIFIED | `release.yml` lines 45-54: `grep -qE '\-(rc\|beta\|alpha)'` sets `prerelease=true\|false`; passed to action line 158 as `${{ steps.prerelease.outputs.prerelease == 'true' }}` |
| 4 | Tarball-content assertion gates Upload; forbidden paths + credential scan present | VERIFIED | `release.yml` lines 72-151: full `Assert tarball contents` step checks 12 forbidden paths (`.planning`, `.env`, `data/trend`, `.git`, etc.) and scans all files for `TVM_ACCESS_KEY`, `TVM_SECRET_KEY`, `SMTP_PASSWORD`; accumulates failures before exiting 1 |
| 5 | `permissions: contents: write` declared; `actions/checkout@v6` + `softprops/action-gh-release@v3` pinned | VERIFIED | `release.yml` lines 14-15: top-level `permissions: contents: write`; line 26: `actions/checkout@v6`; line 154: `softprops/action-gh-release@v3` |
| 6 | Plan 09-01 marker comment replaced (no stale marker) | VERIFIED | Grep for `inserted by Plan 09-02` returns zero matches in `release.yml`; 09-02 SUMMARY confirms "marker comment removed" |
| 7 | Credential-scan extraction uses `sed+cut` pattern, not deprecated `awk -F: '{print $3}'` | VERIFIED | `release.yml` lines 124-125: `sed -E 's/^[^:]+:[0-9]+://'` then `cut -d= -f2-`; `awk` does not appear anywhere in the file |

**Score:** 7/7 truths verified

---

## Requirements Coverage

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| CI-01 | `v*` tag triggers workflow, builds slim tarball, uploads, publishes Release | PASS | `release.yml` lines 3-6 (push tag trigger), 56-64 (git archive), 153-162 (softprops upload) |
| CI-02 | `workflow_dispatch` with version input for re-runs | PASS | `release.yml` lines 7-12, 34-36 |
| CI-03 | Tarball named `vuln-reporting-vX.Y.Z-slim.tar.gz` | PASS | `release.yml` line 63: `-o "vuln-reporting-${VERSION}-slim.tar.gz"` |
| CI-04 | SHA256 checksum file uploaded as second asset | PASS | `release.yml` lines 66-70, 159-162 |
| CI-05 | `-rc`/`-beta`/`-alpha` tags marked prerelease | PASS | `release.yml` lines 45-54, 158 |
| CI-06 | Assertion step fails build on forbidden paths or non-placeholder credentials | PASS | `release.yml` lines 72-151 |
| CI-07 | `permissions: contents: write` declared explicitly | PASS | `release.yml` lines 14-15 |

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `.github/workflows/release.yml` | Complete release workflow | VERIFIED | 163 lines; all steps present and substantive; commits `fc5d7a9`, `728cd4c`, `3bcf393`, `7d7f73e` confirmed in git log |

---

## Additional Checks

### `fetch-depth: 0` on checkout

`release.yml` line 28: `fetch-depth: 0` — confirmed present. Required so `git archive <VERSION>` resolves tagged commits correctly when the shallow default would otherwise fail.

### `set -euo pipefail` in multi-line bash blocks

All four multi-line `run:` blocks include `set -euo pipefail` on the first line:
- Resolve version step: line 33
- Detect prerelease step: line 48
- Build slim tarball step: line 58
- Compute SHA256 sidecar step: line 68
- Assert tarball contents step: line 74

### Action pin strategy

Both actions use major-version tags (`@v6`, `@v3`) rather than SHA pins. This matches the documented decision in 09-01-SUMMARY.md: "Dependabot can auto-bump; SHA pins fail silently on security patches." Consistent with the ROADMAP success criterion specifying "pinned to verified majors current as of 2026-05-19."

### SUMMARY accuracy

- **09-01-SUMMARY.md**: Accurately reflects what shipped. The noted deviation (multi-line git archive command vs. plan's single-line grep assumption) is a grep-script quirk, not a workflow defect. The marker comment placement, all CI requirement completions, and action choices are correctly documented.
- **09-02-SUMMARY.md**: Accurately reflects what shipped. The `sed+cut` extraction pattern is correctly documented as the fix for the `awk -F:` pitfall. The 8 automated verification checks listed all have observable evidence in the final file.

---

## Anti-Patterns Found

None. No `TBD`, `FIXME`, `XXX`, `TODO`, placeholder text, or empty implementations found in `.github/workflows/release.yml`.

---

## Human Verification Required

### 1. Live smoke-tag run

**Test:** Push `v0.0.0-alpha1` tag: `git tag v0.0.0-alpha1 && git push origin v0.0.0-alpha1`

**Expected:**
- Workflow runs to completion in the Actions tab
- Release page shows two assets: `vuln-reporting-v0.0.0-alpha1-slim.tar.gz` and `vuln-reporting-v0.0.0-alpha1-slim.tar.gz.sha256`
- Release is marked Pre-release (the `-alpha1` suffix triggers prerelease detection)
- The `Assert tarball contents` step log shows: "Tarball assertion passed: no forbidden paths, no credential leaks"
- Clean up: delete from GitHub UI, then `git push --delete origin v0.0.0-alpha1`

**Why human:** Requires a live GitHub Actions runner and authenticated push access to the remote; static inspection cannot exercise the full workflow end-to-end.

This is an expected post-merge step, not a gap blocking Phase 9 closure.

---

## Gaps Summary

No gaps. All 7 requirements (CI-01 through CI-07) have verifiable implementation in `.github/workflows/release.yml`. The sole outstanding item is the live smoke-tag run, which is a documented human verification step by design.

---

## Conclusion

Phase 9 has achieved its goal. The single artifact (`.github/workflows/release.yml`) fully implements all seven CI requirements: tag-triggered slim tarball build with `-slim` suffix, SHA256 sidecar, `workflow_dispatch` re-run path, prerelease detection for `-rc`/`-beta`/`-alpha` suffixes, tarball-content assertion with forbidden-path and credential-scan logic gating the upload step, and explicit `permissions: contents: write` with verified action pins. The Plan 09-01 insertion marker was cleanly replaced by the Plan 09-02 assertion step with no residue. The deprecated `awk -F:` extraction pattern was correctly avoided in favor of `sed+cut`. Phase 9 is ready to close.

---

_Verified: 2026-05-19T21:05:00Z_
_Verifier: Claude (gsd-verifier)_
