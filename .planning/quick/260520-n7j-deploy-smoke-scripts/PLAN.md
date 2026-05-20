---
quick_id: 260520-n7j
slug: deploy-smoke-scripts
date: 2026-05-20
status: complete
---

# Quick Task: Deploy smoke + bootstrap scripts

Closes the "post-merge Linux+systemd smoke" gap from `.planning/v1.2-MILESTONE-AUDIT.md`
by shipping reusable validation tooling that runs on a real Rocky/Alma 9 host.

## Files (commit 8a1b160)

- **`deploy/smoke_test.sh`** — network-free smoke. Builds a fake `/opt/vuln-reporting`
  layout from two `git archive` releases + per-release venvs, installs the systemd unit,
  and runs 5 checks: (1) POSITIVE B-01 trend write under the real `systemd-run` sandbox;
  (2) NEGATIVE control that asserts the write is blocked when `data/trend` is omitted from
  `ReadWritePaths` — loudly FAILs the whole smoke if the sandbox isn't enforcing; (3)
  `update_from_github.sh --list` active-marker; (4) `--rollback --skip-restart` symlink +
  `.last` mechanics; (5) tolerant auto-rollback signal (broken release → `systemctl
  is-active` not active). Placeholder creds only (D-04-08). `--clean` removes the layout.
- **`deploy/smoke_bootstrap.sh`** — Rocky/Alma 9 provisioner: `dnf install` Python 3.11 +
  the WeasyPrint deps copied verbatim from DEPLOYMENT.md (`gcc libffi-devel openssl-devel
  cairo-devel pango-devel`), then delegates to `smoke_test.sh`. Throwaway-host framing.
- **`.gitattributes`** — `deploy/smoke_*.sh export-ignore` (mirrors `scripts/smoke_*`);
  both confirmed excluded from the slim tarball.

## Verification

Dev-box (Windows) limited to: `bash -n` (both clean), `git check-attr export-ignore`
(both set), 0 smoke files in `git archive HEAD` tarball, mode 100755, and cross-read
correctness against `deploy/vuln-reports.service`, `scripts/update_from_github.sh`
(flags `--list`/`--rollback`/`--skip-restart`, `* (active)` marker, `write_breadcrumb`
all confirmed), and `reports/management_summary.py` (TREND_DIR write mirrored).

**Full functional validation happens ON the Rocky 9 host** — that is the point of the
script. The negative control (check 2) self-detects a non-enforcing sandbox (e.g. WSL2
or a container), so a green run on real RHEL-family systemd is meaningful. The
`--version` GitHub download path is NOT covered (needs a real published release — push
`v0.0.0-alpha1` per Phase 9).
