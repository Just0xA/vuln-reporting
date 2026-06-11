---
phase: 07-foundations
plan: 01
subsystem: build/deploy
tags: [release-tarball, systemd, foundations]
dependency-graph:
  requires: []
  provides:
    - "Release-tarball boundary (consumed by Phase 8 release scripts + Phase 10 update_from_github.sh)"
    - "Symlink-aware systemd unit (consumed by Phase 10 deploy layout)"
  affects:
    - "Any future `git archive HEAD` / GitHub Release source tarball"
    - "`/etc/systemd/system/vuln-reports.service` on the production box once redeployed"
tech-stack:
  added: []
  patterns:
    - "Per-path `export-ignore` (explicit names only, no wholesale `scripts/*`)"
    - "Symlink-based deploy layout (`current/` + `shared/`)"
key-files:
  created:
    - ".gitattributes"
  modified:
    - "deploy/vuln-reports.service"
decisions:
  - "Excluded `.gitattributes` itself from the release tarball — release consumers don't need export-ignore rules, they don't re-archive."
  - "Used `scripts/smoke_*` (no `.py` suffix) so future non-Python smoke scripts are covered automatically."
  - "Did NOT touch `ExecStart` or the venv path — Phase 10 owns the venv migration."
  - "Removed `Documentation=` entirely rather than re-pointing it — Phase 11 will decide doc hosting."
metrics:
  duration: "~10 min"
  completed: "2026-05-19"
---

# Phase 7 Plan 01: Foundations — Release Tarball Boundary + Systemd Unit Update

Define the release-artifact boundary (`.gitattributes` `export-ignore`) and align the systemd unit with the Phase 10 symlink-based deploy layout (`/opt/vuln-reporting/current/` + `/opt/vuln-reporting/shared/`).

## What Shipped

**Task 1 — `.gitattributes` (new, 65 lines):** Per-path `export-ignore` rules grouped by purpose (dev/planning dirs, dev-only root docs, named dev-only scripts, belt-and-suspenders for gitignored runtime paths, repo-management files). Two required inline comments included:

1. Above the scripts block: documents that exclusions are by explicit name (not wildcard) so Phase 8 `warm_cache.py` and Phase 10 `update_from_github.sh` will ship in the tarball automatically when they land.
2. Above the self-exclusion: explains why `.gitattributes` itself is `export-ignore`d.

Committed as `9f9739d` **before** running any `git archive HEAD` verify (critical — `git archive HEAD` reads the committed tree only).

**Task 2 — `deploy/vuln-reports.service`:** Surgical 4-line directive update + the adjacent inline comment. `ExecStart` and venv path left untouched per scope.

Committed as `1bd95a4`.

## Confirmation: `.gitattributes` Committed Before Verify

`.gitattributes` was committed in `9f9739d` (atomic commit, message references FOOT-01..04). All subsequent `git archive HEAD | tar -tz` invocations read the post-commit HEAD tree and honored the `export-ignore` rules — verified by:

```text
$ git ls-files --error-unmatch .gitattributes
.gitattributes              # exit 0 — tracked at HEAD
```

## Evidence — `git archive HEAD` Tarball Preview

### Forbidden paths grep (must be empty)

```text
$ git archive --format=tar.gz HEAD --prefix=vuln-reporting/ | tar -tz | sort > /tmp/release_preview.txt
$ grep -E 'vuln-reporting/(\.planning/|docs/|ref/|tests/|\.github/|CLAUDE\.md|RUNBOOK\.md|CONTRIBUTING\.md|scripts/setup_github_labels\.py|scripts/smoke_|data/trend/|data/cache/|output/|logs/)' /tmp/release_preview.txt
                            # (empty — all forbidden paths stripped)
```

Empty output confirms FOOT-01 (dev/planning dirs), FOOT-02 (named scripts), FOOT-03 (root dev docs), and FOOT-04 (belt-and-suspenders runtime paths).

### Required paths grep (must be present)

```text
$ grep 'vuln-reporting/deploy/vuln-reports\.service' /tmp/release_preview.txt
vuln-reporting/deploy/vuln-reports.service

$ git archive --format=tar.gz HEAD --prefix=vuln-reporting/ | tar -tz | sort | grep -E '^vuln-reporting/(scripts/|deploy/|\.gitattributes)'
vuln-reporting/deploy/
vuln-reporting/deploy/vuln-reports.service
vuln-reporting/scripts/
```

Notes on the `scripts/` evidence:

- The `scripts/` directory entry is present (so future Phase 8 `warm_cache.py` and Phase 10 `update_from_github.sh` will be carried automatically).
- All three currently-tracked `scripts/` files (`setup_github_labels.py`, `smoke_board_summary_cutover.py`, `smoke_email_phase2.py`) match the explicit exclusion rules and are stripped — confirmed by the forbidden-paths grep above being empty.
- Verified `git ls-tree -r HEAD --name-only` shows those files exist at HEAD, so the absence from the tarball is the result of `export-ignore` working, not the files being missing.

### `.gitattributes` self-exclusion

```text
$ grep -E '^vuln-reporting/\.gitattributes$' /tmp/release_preview.txt
                            # (empty — self-exclusion works)
```

### Tarball size sanity check

```text
$ wc -l /tmp/release_preview.txt
62 entries     # vs 1500+ files tracked at HEAD — confirms heavy exclusion
```

## Diff — `deploy/vuln-reports.service`

```diff
diff --git a/deploy/vuln-reports.service b/deploy/vuln-reports.service
index bea7691..ca43c19 100644
--- a/deploy/vuln-reports.service
+++ b/deploy/vuln-reports.service
@@ -16,7 +16,6 @@

 [Unit]
 Description=Vulnerability Management Report Scheduler
-Documentation=file:///opt/vuln-reporting/RUNBOOK.MD
 After=network.target
 Wants=network-online.target

@@ -30,12 +29,12 @@ Group=vuln-reports
 # -----------------------------------------------------------------------
 # Working directory and environment
 # -----------------------------------------------------------------------
-WorkingDirectory=/opt/vuln-reporting
+WorkingDirectory=/opt/vuln-reporting/current/

 # Load credentials from .env file.
 # All SMTP_* and TVM_* variables defined in .env are injected into the
 # process environment.  Never commit .env to version control.
-EnvironmentFile=/opt/vuln-reporting/.env
+EnvironmentFile=/opt/vuln-reporting/shared/.env

 # -----------------------------------------------------------------------
 # Execution
@@ -75,9 +74,11 @@ PrivateTmp=true
 # Allow network access (required for Tenable API and SMTP delivery)
 # PrivateNetwork is NOT set so that outbound connections work.

-# Restrict write access: only the project directory and logs are writable.
-# Adjust ReadWritePaths if you change OUTPUT_DIR or LOG_DIR in config.py.
-ReadWritePaths=/opt/vuln-reporting/output /opt/vuln-reporting/logs /opt/vuln-reporting/data/cache
+# Restrict write access: only the shared runtime paths are writable.
+# These are the persistent directories under /opt/vuln-reporting/shared/
+# (the release-agnostic side of the symlink-based deploy layout) — the
+# release tree under /opt/vuln-reporting/current/ is intentionally read-only.
+ReadWritePaths=/opt/vuln-reporting/shared/output /opt/vuln-reporting/shared/logs /opt/vuln-reporting/shared/data/cache

 [Install]
 WantedBy=multi-user.target
```

Confirming directive snapshot:

```text
$ grep -E '^(Documentation|WorkingDirectory|EnvironmentFile|ReadWritePaths|ExecStart)=' deploy/vuln-reports.service
WorkingDirectory=/opt/vuln-reporting/current/
EnvironmentFile=/opt/vuln-reporting/shared/.env
ExecStart=/opt/vuln-reporting/.venv/bin/python scheduler.py --mode daemon
ReadWritePaths=/opt/vuln-reporting/shared/output /opt/vuln-reporting/shared/logs /opt/vuln-reporting/shared/data/cache
```

`Documentation=` removed, `ExecStart=` unchanged.

## Requirement Traceability

| Req       | Satisfied by                                                                                                                            |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| FOOT-01   | `.gitattributes` lines for `.planning/`, `docs/`, `ref/`, `tests/`, `.github/`, `CLAUDE.md`, `RUNBOOK.md`, `CONTRIBUTING.md`             |
| FOOT-02   | `.gitattributes` lines `scripts/setup_github_labels.py` and `scripts/smoke_*` (explicit-name rule, not wildcard — forward-compatible)    |
| FOOT-03   | `.gitattributes` self-exclusion + `.gitignore` + `.claude/` / `.cursor/` / `.codex/` / `.agents/` repo-management exclusions             |
| FOOT-04   | `.gitattributes` belt-and-suspenders block (`data/trend/`, `data/cache/`, `output/`, `logs/`) layered over `.gitignore`                  |
| UPDATE-15 | `deploy/vuln-reports.service` directive edits: `WorkingDirectory`, `EnvironmentFile`, `ReadWritePaths` to `shared/` paths; `Documentation=` removed |

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- `.gitattributes` exists at repo root and tracked at HEAD (commit `9f9739d`): FOUND
- `deploy/vuln-reports.service` updated (commit `1bd95a4`): FOUND
- Commit `9f9739d` in `git log`: FOUND
- Commit `1bd95a4` in `git log`: FOUND
- `git archive HEAD` forbidden-paths grep: empty (verified)
- `git archive HEAD` `deploy/vuln-reports.service` present: verified
- `Documentation=` removed: verified
- `ExecStart=` unchanged: verified
