---
phase: 11-documentation
plan: "01"
subsystem: documentation
tags: [readme, deployment, docs, tarball-workflow, rollback]
dependency_graph:
  requires: [phase-7-foundations, phase-9-ci-release, phase-10-update-infrastructure]
  provides: [README.md, DEPLOYMENT.md]
  affects: []
tech_stack:
  added: []
  patterns: [release-tarball-workflow, symlink-layout, per-release-venv, shared-paths]
key_files:
  created:
    - README.md
    - DEPLOYMENT.md
  modified: []
decisions:
  - "DEPLOYMENT.md is the single authoritative install/upgrade/rollback source; RUNBOOK.md will be rescoped to operations-only in plan 11-02"
  - "git clone is explicitly documented as NOT a supported production install path"
  - "Rollback one-liner appears in both the top Rollback callout AND inside the Update Procedure section for redundancy"
  - "systemd venv path (current/.venv) matches the fixed deploy/vuln-reports.service (commit 884e415 resolved the pre-existing mismatch before this doc was written)"
metrics:
  duration_minutes: 25
  completed_date: "2026-05-20"
  tasks_completed: 2
  tasks_total: 3
  files_created: 2
  lines_written: 586
---

# Phase 11 Plan 01: Root README.md + Authoritative DEPLOYMENT.md — Summary

**One-liner:** Orientation README pointing newcomers to the right guides, plus a 539-line tarball install/upgrade/rollback reference covering all ten required sections with accurate Phase 7/9/10 detail.

## What Was Built

### Task 1: README.md (DOC-01)

`README.md` at the repo root — a concise 47-line orientation document:
- "What this is" with the core-value framing from CLAUDE.md
- "Who it's for" covering the three audiences (Operations, Management, Executive Leadership)
- Quickstart section: one pointer to DEPLOYMENT.md (install) and one to RUNBOOK.md (ops)
- Documentation map table: DEPLOYMENT.md, RUNBOOK.md, CLAUDE.md, docs/
- No install steps, no operations procedures

Commit: `9892793`

### Task 2: DEPLOYMENT.md (DOC-02)

`DEPLOYMENT.md` at the repo root — 539 lines, all ten required sections:

1. **Rollback** — prominent blockquote at the top with the one-liner; repeated inside Update Procedure
2. **System Requirements** — RHEL 9 / Ubuntu, Python 3.10+, WeasyPrint system packages (both dnf and apt variants), SELinux note
3. **Install from a Release Tarball** — 8-step manual install path; explicit "NOT a supported production install path" framing for git clone
4. **Configure Credentials** — `shared/.env` from `.env.example`; TVM keys, SMTP, `GITHUB_RELEASE_REPO` (required), `GITHUB_TOKEN` (optional, lifts rate limit 60→5000/hr)
5. **Verify** — `run_all.py --dry-run`, Tenable connectivity check, systemd unit install commands
6. **Update Procedure** — `--check` exit codes (0/1/≥2), `--version` 11-step flow, rollback one-liner repeated, additional flags (`--list`, `--force`, `--skip-restart`)
7. **Troubleshooting (Install / Upgrade)** — SHA256 mismatch, layout-guard refusal, venv build failure, health-check auto-rollback fired, GitHub API rate limit
8. **On-Disk Layout** — fenced tree diagram matching Phase 7/10 reality
9. **Schema Migration Note** — operator-managed `delivery_config.yaml` is symlinked and not overwritten
10. **Pre-Release Sensitive-Data Checklist (D-04-08)** — 9-item Markdown task list with `example.invalid` domain requirement

Commit: `4fc8bdd`

## Rollback One-Liner (as placed in DEPLOYMENT.md)

```
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
```

Appears in: (1) the `## Rollback` blockquote callout near the top, and (2) the "Roll back after an upgrade" subsection inside `## Update Procedure`.

## Deviations from Plan

None — plan executed exactly as written.

One contextual note: the plan's `<how-to-verify>` checkpoint note warned about a pre-existing `deploy/vuln-reports.service:42` venv-path mismatch (`/opt/vuln-reporting/.venv`). This was already resolved before plan execution by quick task `260520-a29-systemd-venv-path` (commit 884e415). The service file and DEPLOYMENT.md both correctly reference `/opt/vuln-reporting/current/.venv/bin/python`.

## Automated Verify Results

Task 1:
```
test -f README.md && grep -q "DEPLOYMENT.md" README.md && grep -q "RUNBOOK.md" README.md
  && grep -qi "right metric, right audience" README.md && echo PASS
→ PASS
```

Task 2 (all ten section headings + rollback one-liner + GITHUB_RELEASE_REPO + git clone + out-of-scope pattern):
```
→ PASS
```

## Status

Auto tasks (Tasks 1 and 2): COMPLETE — both committed.
Checkpoint (Task 3: human-verify): PENDING — awaiting human prose review.

## Self-Check: PASSED

- `README.md` exists: confirmed (47 lines, min 25)
- `DEPLOYMENT.md` exists: confirmed (539 lines, min 180)
- Commit `9892793` exists: confirmed
- Commit `4fc8bdd` exists: confirmed
- Cross-link README→DEPLOYMENT.md: `[DEPLOYMENT.md](DEPLOYMENT.md)` present
- `update_from_github.sh` referenced in DEPLOYMENT.md: confirmed
- `GITHUB_RELEASE_REPO` in DEPLOYMENT.md: confirmed
- Rollback one-liner in both locations: confirmed
