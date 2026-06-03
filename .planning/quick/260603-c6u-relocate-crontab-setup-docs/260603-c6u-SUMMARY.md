---
phase: quick-260603-c6u
plan: "01"
subsystem: docs
tags: [docs, cron, deployment, runbook, warm-cache]
dependency_graph:
  requires: []
  provides: [single-source-of-truth-timing-rules]
  affects: [DEPLOYMENT.md, RUNBOOK.md]
tech_stack:
  added: []
  patterns: []
key_files:
  created: []
  modified:
    - DEPLOYMENT.md
    - RUNBOOK.md
decisions:
  - "DEPLOYMENT.md owns the canonical cron-scheduling setup step and both timing rules (TIMING RULE A/B); RUNBOOK.md cross-references it"
  - "RUNBOOK.md warm-cache section restructured into operator day-to-day actions: timing adjustment, log checking, and cache-miss troubleshooting"
  - "Full logrotate block removed from RUNBOOK.md; operators pointed to deploy/crontab.example for the snippet (single source of truth)"
metrics:
  duration: 15m
  completed_date: "2026-06-03T12:52:18Z"
  tasks_completed: 2
  files_modified: 2
---

# Quick Task 260603-c6u: Relocate Crontab / Warm-Cache Setup Docs — Summary

**One-liner:** Moved canonical cron-scheduling setup and both timing rules (TIMING RULE A/B) into DEPLOYMENT.md; trimmed RUNBOOK.md to operator day-to-day actions with cross-references.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add canonical cron-scheduling setup step to DEPLOYMENT.md | 0df053e | DEPLOYMENT.md (+58 lines) |
| 2 | Trim RUNBOOK.md warm-cache section to operator actions + cross-reference | 0ee60f5 | RUNBOOK.md (+45/-43 lines) |

## What Was Done

### Task 1 — DEPLOYMENT.md

Added a new `### Schedule reports with cron (alternative to the systemd daemon)` subsection inside the "## Verify" flow, immediately after the "Allow the updater to restart the service" proxy guidance and before "## Update Procedure". The subsection covers:

1. Crontab.example install command with `sudo -u vuln-reports crontab - < ...`
2. Both timing rules in full (TIMING RULE A: ≥30 min before earliest group; TIMING RULE B: never near midnight / cache-folder date-rollover explanation)
3. The `cd` into project root requirement and per-release `current/.venv/bin/python` interpreter path
4. Non-default INSTALL_ROOT: all path occurrences in each cron line must change together, with cross-reference to [Relocating the install base](#relocating-the-install-base)
5. Cron-or-daemon-not-both note
6. Un-rotated `.cron.log` note pointing to `deploy/crontab.example` for the logrotate snippet

### Task 2 — RUNBOOK.md

Replaced the "## Operational Cron Schedule" section's inline setup prose + full timing-rule explanation + full logrotate block with:

- A callout at the top cross-referencing DEPLOYMENT.md for first-time setup
- "How cron-based scheduling works" kept (±10-minute window, every 5 min — operational explanation, not setup)
- "Adjusting cron timing when groups change" — new operator action with `crontab -e` + dry-run
- "Checking warm-cache and cron logs" — log file paths and `.cron.log` not-auto-rotated note with pointer to `crontab.example`
- "Troubleshooting cache misses" — explains date-rollover and warm-not-complete causes with pointer to DEPLOYMENT.md timing rules

## Verification

- `Cache folders are named by server local date` now appears only in DEPLOYMENT.md (not RUNBOOK.md)
- RUNBOOK.md links to DEPLOYMENT.md in 8 places (including the new cross-references)
- `deploy/crontab.example` is unchanged (git diff confirms no edits)
- Only DEPLOYMENT.md and RUNBOOK.md changed (docs-only diff)

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- DEPLOYMENT.md exists and contains TIMING RULE A, `crontab - <`, `server local`, `relocating-the-install-base`, `cron.log`
- RUNBOOK.md cross-references DEPLOYMENT.md; no longer contains `Cache folders are named by server local date`
- `deploy/crontab.example` unchanged
- Commits 0df053e and 0ee60f5 confirmed via `git log`
