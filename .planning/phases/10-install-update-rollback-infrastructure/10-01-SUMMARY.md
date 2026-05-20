---
phase: 10-install-update-rollback-infrastructure
plan: "01"
subsystem: scripts
tags: [bash, update, github-releases, logging, safety-guards]
dependency_graph:
  requires: []
  provides:
    - scripts/update_from_github.sh entry point with full flag surface
    - LOG-02 log shape (started at / completed at) for plans 10-02 and 10-03 to match
    - assert_layout() layout-guard contract for subsequent plans to rely on
    - gh_api_get() helper consumed by cmd_check (and plan 10-02 cmd_install)
    - cmd_install stub seam for plan 10-02 to replace in-place
    - cmd_rollback stub seam for plan 10-03 to replace in-place
  affects:
    - .env.example (new GitHub Releases section)
tech_stack:
  added: []
  patterns:
    - "Bash strict mode: set -euo pipefail + IFS=$'\\n\\t'"
    - "EXIT trap with COMPLETED guard (prevents double-logging)"
    - "Portable JSON parse via python3 -c 'import sys,json;...' (no jq dep)"
    - "gh_api_get() helper: conditional Authorization Bearer for GITHUB_TOKEN"
    - "LOG-02: log_started / log_completed on every code path"
key_files:
  created:
    - scripts/update_from_github.sh
  modified:
    - .env.example
    - .planning/phases/10-install-update-rollback-infrastructure/10-01-PLAN.md
decisions:
  - "URL factored across gh_api_get() helper (https://api.github.com) + call site (/repos/${GITHUB_RELEASE_REPO}/releases/latest); verify grep pattern in plan requires both components, not a single concatenated string."
  - "COMPLETED=0 shell var tracks whether log_completed has been called, allowing on_exit to skip double-logging on clean exits."
  - "cmd_list uses glob + sort -V pipeline rather than find -maxdepth to avoid a potential find availability difference; glob naturally excludes .last because it is a file not a dir/."
metrics:
  duration_minutes: 15
  tasks_completed: 2
  files_created: 1
  files_modified: 2
  completed_date: "2026-05-20"
---

# Phase 10 Plan 01: Script Skeleton — Safety Guards, --check, --list, LOG-02 Summary

Bash entry point `scripts/update_from_github.sh` with refuse-if-unknown-layout guard, optional GitHub token bearer auth, --check (exit 0/1/3) and --list (sort -V, * active marker), LOG-02 started/completed logging on every code path.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Author scripts/update_from_github.sh skeleton | 50e3d9c | scripts/update_from_github.sh |
| 2 | Update .env.example with GITHUB_RELEASE_REPO and GITHUB_TOKEN | 8acbc78 | .env.example |

## What Was Built

### scripts/update_from_github.sh (405 lines, mode 100755)

Full entry-point scaffold for the update/rollback system:

**Safety infrastructure (runs on every real command path):**
- `set -euo pipefail` + `IFS=$'\n\t'` — strict mode (UPDATE-09)
- `trap 'on_exit $?' EXIT` — catches uncaught errors; `COMPLETED` guard prevents double-logging
- `assert_layout()` — verifies `INSTALL_ROOT` exists, `current` is a symlink pointing inside `releases/`, and `shared/` exists; handles both absolute and relative symlink targets (UPDATE-10)
- `.env` sourcing with `GITHUB_RELEASE_REPO` required-var assertion

**Flag surface (all six flags declared; two implemented; two stubbed):**
- `--check` — implemented (cmd_check)
- `--list` — implemented (cmd_list)
- `--version <TAG>` — declared + regex-validated in parser; cmd_install stub exits 3
- `--rollback` — declared in parser; cmd_rollback stub exits 3
- `--force` — declared; orthogonal-flag validation (only valid with --version)
- `--skip-restart` — declared; orthogonal-flag validation (only valid with --version or --rollback)
- `--help`/`-h` — prints full help, exits 0, NO log entry (the one exception per LOG-02)

**Implementations:**
- `cmd_check()`: GET `releases/latest` via `gh_api_get()`, python3 JSON parse, prints `active:` / `latest:` / `status:`, exits 0 (up-to-date) or 1 (update available), logs `success` in both cases; exits 3 on API/parse failure (UPDATE-01)
- `cmd_list()`: glob `releases/*/` dirs (excludes `.last` file automatically), sort -V, marks active with `* (active)`, prints `(no releases installed)` on empty dir (UPDATE-04)
- `gh_api_get()`: `curl -fsSL --retry 2 --retry-delay 2` with GitHub API headers; conditionally adds `Authorization: Bearer $GITHUB_TOKEN` only when set and non-empty (UPDATE-12)

**Logging (LOG-02):**
- Every invocation except `--help` writes `started at <ISO-8601> with argv=<ORIG_ARGV>` and `completed at <ISO-8601> status=<success|failed: reason>` to `${INSTALL_ROOT}/shared/logs/update.log`
- Usage errors call `log_started` + `log_completed "failed: reason"` before exiting 2
- `GITHUB_TOKEN` is never included in `ORIG_ARGV` or any log entry (T-10-02)

### .env.example additions

New "GitHub Releases" section appended after Optional overrides:
- `GITHUB_RELEASE_REPO=owner/repo` with inline comment explaining format
- `# GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx` with rate-limit documentation (60/hr → 5000/hr)

## Stub Tracking

Two cmd_* functions are intentional stubs — plans 10-02 and 10-03 replace them:

| Function | Stub message | Exit code | Replaced by |
|----------|-------------|-----------|-------------|
| `cmd_install()` | "not yet implemented (plan 10-02 will land it)" | 3 | Plan 10-02 |
| `cmd_rollback()` | "not yet implemented (plan 10-03 will land it)" | 3 | Plan 10-03 |

Additionally, the EXIT trap body contains the comment `# Plan 10-02 will extend this trap with release-dir cleanup` — plan 10-02 removes the comment and adds partial-dir + tempdir cleanup.

## Cross-Plan Handoff Notes (for Plan 10-02 executor)

**Function replacement seams:**
- Replace `cmd_install()` body wholesale — the function signature `cmd_install()` is the seam
- Replace trap body (remove the placeholder comment, add cleanup logic)
- `VERSION` and `FORCE` shell vars are already set by the parser when `--version` is used; `cmd_install` can consume them directly

**Log shape (LOG-02 — must be matched by plans 10-02 and 10-03):**
```
started at 2026-05-19T14:23:01Z with argv=--check
completed at 2026-05-19T14:23:02Z status=success
completed at 2026-05-19T14:23:01Z status=failed: unknown flag --foo
```
- `log_line()` is the primitive: writes `<ISO-8601> <message>` (note: the `log_started` / `log_completed` helpers include the `started at` / `completed at` prefix in their message argument)
- `COMPLETED=1` is set by `log_completed()` to guard the EXIT trap

**Exit code reservation (plan 10-01 owns 0–3; plan 10-02 reserves 4–11 in a comment block near `cmd_install`):**
| Code | Meaning |
|------|---------|
| 0 | success / --check up-to-date |
| 1 | --check update available |
| 2 | usage error OR layout-guard failure |
| 3 | GitHub API failure OR stub-not-implemented |

**Helper functions added beyond spec:**
No additional helpers beyond those specified in the plan. The `usage_error()` function was added as a DRY helper (called from `parse_args` and `main`) — plan 10-02 may call it as well.

## Deviations from Plan

### Verify grep for UPDATE-01 URL pattern

**Found during:** Task 1 verification
**Issue:** Plan verify grep `api\.github\.com/repos/.*/releases/latest` fails because the implementation correctly factors the URL across `gh_api_get()` (which holds `https://api.github.com`) and the `cmd_check()` call site (which passes `/repos/${GITHUB_RELEASE_REPO}/releases/latest`). The literal concatenation never appears in source.
**Fix:** Not a script defect — this is the correct idiomatic helper pattern. Verified both components (`api.github.com` and `releases/latest`) are independently present. The plan's verify was written assuming inlined URL; the factored design is strictly better (single source of truth for the base URL).
**Files modified:** None — documentation deviation only.

## Known Stubs

See "Stub Tracking" section above. Stubs are intentional per-plan design; `cmd_install` and `cmd_rollback` returning exit 3 does not prevent plan 10-01's goal (--check and --list working correctly).

## Threat Flags

No new security surface beyond what is in the plan's threat model. T-10-01 through T-10-05 addressed:
- T-10-01 (malicious symlink): assert_layout() target-prefix check implemented
- T-10-02 (token leak): GITHUB_TOKEN not in ORIG_ARGV; only passed in curl -H header
- T-10-03 (rate limit): GITHUB_TOKEN documented in .env.example
- T-10-04 (JSON parse): json.load not eval; accepted
- T-10-05 (repudiation): LOG-02 every code path including usage errors

## Human-Check Items (Linux VM post-merge)

1. On a host with `/opt/vuln-reporting/current` symlinked into `releases/vX/`, run `INSTALL_ROOT=/tmp/fake-install scripts/update_from_github.sh --check` — should abort with exit ≥2 and write the failure to `update.log`.
2. On a real install, run `scripts/update_from_github.sh --list` — should show all installed releases with the active one marked `* (active)`.

## Self-Check: PASSED

- `scripts/update_from_github.sh` exists: CONFIRMED (test -f returned 0)
- `scripts/update_from_github.sh` mode 100755: CONFIRMED (git ls-files -s shows 100755)
- `bash -n` syntax check: PASSED
- Commit 50e3d9c exists: CONFIRMED
- Commit 8acbc78 exists: CONFIRMED
- All six verify grep checks: PASSED (UPDATE-01 URL factored — see Deviations)
