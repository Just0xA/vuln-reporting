---
phase: 11-documentation
plan: "02"
subsystem: documentation
tags: [runbook, operations, cron, deployment, documentation]
dependency_graph:
  requires: [11-01]
  provides: [operations-runbook, crontab-example]
  affects: [RUNBOOK.MD, deploy/crontab.example]
tech_stack:
  added: []
  patterns: [v1.2-symlink-layout, shared-logs, cron-warm-cache-scheduling]
key_files:
  created:
    - deploy/crontab.example
  modified:
    - RUNBOOK.MD
decisions:
  - "Kept RUNBOOK.MD uppercase filename (tracked by git as RUNBOOK.MD) — not renamed to avoid case-collision on case-insensitive filesystems"
  - "Used 06:15 warm-cache cron time as the concrete example (>=30 min before 07:00 earliest group, well clear of midnight); operator is directed to adjust both"
  - "crontab.example uses -m scripts.warm_cache module invocation to match warm_cache.py's own design (not a direct path invocation)"
metrics:
  duration: "~20 min"
  completed: "2026-05-20"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 2
---

# Phase 11 Plan 02: Operations Runbook Rewrite + Drop-in Crontab Summary

**One-liner:** Rescoped RUNBOOK.MD to operations-only (removed 350+ lines of RHEL fresh-install), modernized all paths to the v1.2 shared/ layout, added Operational Cron Schedule section, and shipped `deploy/crontab.example` with warm-cache timing rules encoded as comments.

---

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | Rewrite RUNBOOK.MD (DOC-03, DOC-04) | e6d08e7 | RUNBOOK.MD |
| 2 | Write deploy/crontab.example (DOC-05) | 1f558b0 | deploy/crontab.example |

---

## What Was Built

### Task 1 — RUNBOOK.MD rewrite

The 1063-line monolith was rewritten from scratch as a ~430-line operations manual.

**Removed (moved to DEPLOYMENT.md in 11-01):**
- Section 1: RHEL 9 Server Deployment (Fresh Install) — Steps 1–15, including `dnf install`, `git clone`, SELinux setup, venv creation, systemd unit install
- Section 2: Cron Job Setup (as install framing)
- Section 7: Contact and Escalation (merged into Troubleshooting inline guidance)

**Kept and refreshed:**
- Day-to-Day Operations: add/remove recipients, add group, monthly delivery, change schedule, change SLA windows, manual trigger, `--no-email`, `--recipients` test address, delivery-log queries (`--recent`, `--failures`, `--group`, `--from/--to`)
- Scheduler Management: systemctl start/stop/restart/status, 5-min hot-reload mechanics, journald + file log locations, safe concurrent manual runs
- Troubleshooting (runtime only): Tenable auth, SMTP, email-not-received, oversized attachment, scheduler-not-firing, missing VPR, venv issues, delivery-log DB locked

**New section (DOC-04):**
- Operational Cron Schedule: explains warm-cache timing rules (≥30 min pre-group, not near midnight), references `deploy/crontab.example`, logrotate example for `.cron.log` files

**Path modernization (old flat → v1.2 shared/ layout):**

| Old path | New path |
| -------- | -------- |
| `/opt/vuln-reporting/delivery_config.yaml` | `/opt/vuln-reporting/shared/delivery_config.yaml` |
| `/opt/vuln-reporting/logs/scheduler.log` | `/opt/vuln-reporting/shared/logs/scheduler.log` |
| `/opt/vuln-reporting/logs/app.log` | `/opt/vuln-reporting/shared/logs/app.log` |
| `/opt/vuln-reporting/data/cache/` | `/opt/vuln-reporting/shared/data/cache/` |
| `.venv/bin/python` (flat) | `/opt/vuln-reporting/current/.venv/bin/python` (per-release) |
| All code invocations from flat `/opt/vuln-reporting/` | `cd /opt/vuln-reporting/current` |

### Task 2 — deploy/crontab.example

A 82-line drop-in crontab with:
- `warm_cache.py` at `15 6 * * *` (06:15 local) — ≥30 min before the 07:00 CLAUDE.md sample group, well clear of midnight
- `scheduler.py --mode run-due` at `*/5 * * * *` — every 5 minutes, replacing the systemd daemon
- Comments explaining both timing hazards: ≥30-min pre-group rule and the midnight date-rollover hazard (cache folders are local-date-named)
- Logs redirected to `shared/logs/warm_cache.cron.log` and `shared/logs/run-due.cron.log`
- Venv path note: per-release `current/.venv/bin/python`; one-line comment for older hand-built installs using flat `.venv/`

---

## Verification Results

### Task 1 automated greps (all PASS)

```
Section headers present: ## Installation & Upgrades, ## Day-to-Day Operations,
  ## Scheduler Management, ## Operational Cron Schedule, ## Troubleshooting, ## File Reference
Cross-links: DEPLOYMENT.md ✓, crontab.example ✓, shared/logs ✓
Negative greps:
  ! grep -qi "RHEL 9 Server Deployment (Fresh Install)" → PASS (not found)
  ! grep -qi "git clone"                                → PASS (not found)
  ! grep -qi "dnf install"                              → PASS (not found)
```

### Task 2 automated greps (all PASS)

```
File exists: deploy/crontab.example ✓
Content: warm_cache ✓, run-due ✓, midnight ✓, 30 min ✓, /opt/vuln-reporting/current ✓
```

---

## Deviations from Plan

None — plan executed exactly as written.

---

## Checkpoint Pending

Task 3 is a `checkpoint:human-verify`. The automated tasks are committed.
The human verifier should:
1. Open `RUNBOOK.MD` and confirm no install content remains; operations prose reads correctly
2. Open `deploy/crontab.example` and confirm the 06:15 warm-cache time and cron timing comments are clear
3. Verify cross-links: RUNBOOK.MD → DEPLOYMENT.md and RUNBOOK.MD → deploy/crontab.example both resolve
4. Signal approval with "approved" or describe corrections needed

---

## Known Stubs

None.

---

## Threat Flags

None — documentation files only; no new network endpoints, auth paths, or schema changes.

---

## Self-Check: PASSED

- RUNBOOK.MD exists and is 430+ lines: FOUND
- deploy/crontab.example exists: FOUND
- Commit e6d08e7 (RUNBOOK.MD): FOUND
- Commit 1f558b0 (crontab.example): FOUND
