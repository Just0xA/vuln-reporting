---
phase: 07-foundations
verified: 2026-05-19T13:27:00Z
status: passed
score: 4/4 must-haves verified
overrides_applied: 0
---

# Phase 7: Foundations Verification Report

**Phase Goal:** The repository correctly defines its release artifact boundary so no future tag can produce a tarball with dev-only content.
**Verified:** 2026-05-19T13:27:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `git archive` tarball contains NO `.planning/`, `docs/`, `ref/`, `tests/`, `.github/`, `CLAUDE.md`, `RUNBOOK.md`, `CONTRIBUTING.md` | VERIFIED | Ran `git archive --format=tar.gz HEAD \| tar -tz \| grep -E "^(\.planning/\|docs/\|ref/\|tests/\|\.github/\|CLAUDE\.md\|RUNBOOK\.md\|CONTRIBUTING\.md)"` → 0 matches. Tarball total = 62 entries; all dev paths excluded. |
| 2 | `scripts/setup_github_labels.py` and `scripts/smoke_*` are absent AND rule is forward-compatible | VERIFIED | Tarball preview shows only an empty `scripts/` directory entry; `git ls-tree HEAD scripts/` shows 3 tracked files (`setup_github_labels.py`, `smoke_board_summary_cutover.py`, `smoke_email_phase2.py`) — all 3 stripped from the tarball. `.gitattributes` uses explicit `scripts/setup_github_labels.py` + `scripts/smoke_*` patterns (NOT a `scripts/*` wildcard), so future scripts like `warm_cache.py` (Phase 8) and `update_from_github.sh` (Phase 10) will ship automatically. |
| 3 | `deploy/vuln-reports.service` uses `/opt/vuln-reporting/current/` as `WorkingDirectory`, `/opt/vuln-reporting/shared/.env` as `EnvironmentFile`; obsolete `Documentation=...` line is REMOVED | VERIFIED | Line 32: `WorkingDirectory=/opt/vuln-reporting/current/`. Line 37: `EnvironmentFile=/opt/vuln-reporting/shared/.env`. `grep Documentation=` returned **no matches** — line fully removed. Bonus: `ReadWritePaths` (line 81) correctly points to `/opt/vuln-reporting/shared/{output,logs,data/cache}`. |
| 4 | Gitignored runtime paths (`data/trend/`, `data/cache/`, `output/`, `logs/`) have `export-ignore` lines in `.gitattributes` | VERIFIED | `.gitattributes` lines 48–51 declare all four with `export-ignore`. Tarball grep for `^(data/trend\|data/cache\|output/\|logs/)` returned 0 matches. |

**Score:** 4/4 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `.gitattributes` | export-ignore rules for tarball boundary | VERIFIED | New file (66 lines). Contains all required `export-ignore` declarations; well-commented and intentional about scope (explicit names, not wildcards over `scripts/`). Self-excludes (line 60). |
| `deploy/vuln-reports.service` | Updated for symlink-based deploy layout | VERIFIED | `WorkingDirectory=/opt/vuln-reporting/current/`, `EnvironmentFile=/opt/vuln-reporting/shared/.env`, `ReadWritePaths` points at shared paths. Obsolete `Documentation=` line removed entirely. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `.gitattributes` | `git archive HEAD` tarball | `export-ignore` directive | WIRED | Live `git archive` run produced a tarball with all 11 export-ignore declarations honored (verified by grep). Note: `.gitattributes` must be **committed** for rules to apply to `git archive HEAD` — current verification implicitly confirms commit because `git archive` reads from HEAD. |
| `deploy/vuln-reports.service` | `/opt/vuln-reporting/shared/.env` | `EnvironmentFile=` directive | WIRED | Line 37 declares the directive with the correct path; matches plan key-link pattern `EnvironmentFile=/opt/vuln-reporting/shared/\.env`. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Tarball excludes all dev paths | `git archive --format=tar.gz HEAD \| tar -tz \| grep -E "^(\.planning/\|docs/\|ref/\|tests/\|\.github/\|CLAUDE\.md\|RUNBOOK\.md\|CONTRIBUTING\.md)"` | 0 matches | PASS |
| Named script exclusions removed | `... \| grep -E "setup_github_labels\|smoke_"` | 0 matches | PASS |
| Runtime dirs excluded | `... \| grep -E "^(data/trend\|data/cache\|output/\|logs/)"` | 0 matches | PASS |
| Repo-management excluded | `... \| grep -E "^\.(gitattributes\|gitignore\|claude\|cursor\|codex\|agents)"` | 0 matches | PASS |
| Documentation line removed | `grep Documentation= deploy/vuln-reports.service` | No matches | PASS |
| Forward-compat (no wildcard) | `grep -E "warm_cache\|update_from_github" .gitattributes` | Only matches in a comment line explaining intent | PASS — no exclusion rule would catch Phase 8/10 scripts |

### Anti-Patterns Found

None. No `TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER` markers in either modified file. The `scripts/` empty directory entry in the tarball is an unavoidable artifact of `tar` recording the directory itself when its contents are filtered out — this is correct behavior, not a stub.

### Gaps Summary

No gaps. All four roadmap success criteria are observably true against the live HEAD. The `.gitattributes` file is forward-compatible by design (explicit-name exclusions rather than a `scripts/*` wildcard), satisfying SC2's secondary requirement that future Phase 8 (`warm_cache.py`) and Phase 10 (`update_from_github.sh`) runtime scripts ship in the tarball automatically.

Bonus observation (informational, not a gap): The plan's must-haves include `ReadWritePaths` pointing at shared paths — this was also verified (line 81 of the service file) even though it is not part of the four roadmap SCs.

---

_Verified: 2026-05-19T13:27:00Z_
_Verifier: Claude (gsd-verifier)_
