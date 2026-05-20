---
quick_id: 260520-mp4
slug: close-v12-audit-gaps
date: 2026-05-20
status: complete
---

# Quick Task: Close v1.2 milestone-audit gaps

Closes the three findings in `.planning/v1.2-MILESTONE-AUDIT.md` plus the
requirements bookkeeping sync.

## Changes

- **B-01 (blocker)** — `deploy/vuln-reports.service`: added
  `/opt/vuln-reporting/shared/data/trend` to `ReadWritePaths` (line 93).
  `management_summary` writes trend JSON there; systemd hardening was denying it.
- **Relocation** — added a header comment to the unit explaining the base path is
  hard-coded (systemd can't env-expand `WorkingDirectory`/`EnvironmentFile`/
  `ReadWritePaths`) with a `sed` relocation recipe; added a "Relocating the install
  base" section to `DEPLOYMENT.md` covering the `sed`-the-unit step AND the
  `INSTALL_ROOT` env var for `update_from_github.sh` (with the chicken-and-egg note:
  `INSTALL_ROOT` cannot live in `shared/.env` because it locates `.env`).
- **W-01 (warning)** — `DEPLOYMENT.md` update-procedure steps 7/8: corrected to
  swap-then-write-breadcrumb (matches code `update_from_github.sh:676→679`; crash-safe).
- **W-02 (warning)** — `DEPLOYMENT.md`: added "Allow the updater to restart the
  service" with the scoped sudoers entry (`vuln-reports ALL=(root) NOPASSWD:
  /bin/systemctl restart vuln-reports.service`) and the run-as-root alternative;
  referenced from `RUNBOOK.md`.
- **Bookkeeping** — `REQUIREMENTS.md`: traceability table 39× `Open → ✓ Verified`;
  ticked the 8 remaining `[ ]` requirement-definition boxes (CACHE-01..05, CI-06,
  LOG-01, LOG-03). All 39 v1.2 reqs phase-verified.

## Verification

- `grep ReadWritePaths deploy/vuln-reports.service` includes `data/trend`.
- `REQUIREMENTS.md`: 0 `| Open |`, 0 `- [ ]`, 39 `✓ Verified`.
- DEPLOYMENT.md: sudoers block, relocation section, swapped steps 7/8 all present.
- Functional confirmation (daemon actually writes trend under hardening; updater
  restart via sudoers; relocated install) requires the Linux+systemd VM smoke
  documented in the Phase 10/11 SUMMARYs.
