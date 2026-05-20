---
quick_id: 260520-a29
slug: systemd-venv-path
date: 2026-05-20
status: complete
---

# Quick Task: Fix systemd venv path mismatch (v1.2 ship-blocker)

## Problem

`deploy/vuln-reports.service` launched the scheduler with
`ExecStart=/opt/vuln-reporting/.venv/bin/python`, a flat venv path that does
not exist under the v1.2 symlink-based deploy layout. Phase 10's
`update_from_github.sh` (`provision_venv`, line 408) builds the venv
**per-release** at `releases/vX.Y.Z/.venv`, reached via the `current` symlink
(`current/.venv`). After any tarball install the unit would fail to start, and
because the updater runs a post-swap `systemctl is-active` health check
(UPDATE-08), every upgrade would auto-rollback — making the Phase 10 install
flow non-functional end-to-end despite its isolated PASS.

## Fix

- `deploy/vuln-reports.service:42` — `ExecStart` → `/opt/vuln-reporting/current/.venv/bin/python scheduler.py --mode daemon` (matches `WorkingDirectory=/opt/vuln-reporting/current/`). The unit had only this one venv reference.
- `.planning/codebase/STACK.md:18` — updated the codebase-intel line that asserted the old path/line-number so the map stays accurate.

## Out of scope (handled elsewhere)

- `RUNBOOK.md` lines 349/358/1024 still reference the old flat path — Phase 11 plan 11-02 rewrites RUNBOOK and already specifies `current/.venv` cron lines with an older-install fallback note. Left for Phase 11.
- `.planning/research/*` and `.planning/phases/07-*` artifacts reference the old path as frozen historical record — not touched.

## Verification

- `grep -n "ExecStart" deploy/vuln-reports.service` shows the `current/.venv` path.
- `grep -rn "/opt/vuln-reporting/\.venv" deploy/` returns no matches.
- Functional confirmation (unit actually starts post-install) requires the Linux-VM smoke documented in the Phase 10 plan SUMMARYs.
