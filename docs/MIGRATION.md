# MIGRATION.md — git-pull install → v1.2 tarball workflow

This guide migrates an **older `git clone` + `git pull` deployment** to the v1.2
**release-tarball** install/update/rollback workflow (the `/opt/vuln-reporting/{current,releases,shared}`
layout driven by `scripts/update_from_github.sh`). See [`DEPLOYMENT.md`](../DEPLOYMENT.md)
for the underlying install reference; this document is the migration-specific overlay.

---

## Why migrate

The legacy `git pull` workflow mutates the live tree in place: no atomic swap, no
rollback, `pip` churn against the running venv, and dev-only files on the production box.
The v1.2 workflow gives you:

- **Atomic upgrades + instant rollback** — `--version` swaps a symlink; `--rollback` reverts in one command; a failed post-swap health check auto-rolls-back.
- **CI-published, SHA256-verified tarballs** — no git on prod, slim footprint (the `.gitattributes` `export-ignore` boundary).
- **Per-release venvs** — an upgrade can't half-break the running one; old releases are retained and auto-pruned (`--prune`, keep 3).
- **Hardened systemd unit** — `ProtectSystem=strict`, restart limits, runtime-cache env wiring.

For a production server, the rollback safety and hardening alone justify the one-time migration.

---

## What to preserve

| Preserve | Why | Destination |
|---|---|---|
| **`data/trend/*.json`** | **IRREPLACEABLE** — historical snapshots for `management_summary` / `trend_analysis`; cannot be regenerated retroactively. | `shared/data/trend/` |
| `delivery_config.yaml` | Recipient groups | `shared/delivery_config.yaml` |
| `.env` | Credentials — **reconcile, do not copy blindly** (see step 5) | `shared/.env` |
| `logs/delivery_log.db` | SQLite delivery-audit history (for audit continuity) | `shared/logs/` |
| `assets/logo.png` | Custom PDF-chrome logo (gitignored, operator-supplied) — only if you set one | `current/assets/` |

**Disposable — do not migrate:** `output/` (historical artifacts) and `data/cache/`
(date-named, regenerates).

---

## Approach: parallel cutover, not in-place reset

Keep the old install running until the new one is validated. The cutover is reversible
and effectively zero-downtime. On the **same box**, handle the path collision (step 3);
on a **different/fresh server** it is a true parallel run (skip step 3).

Placeholders below: `<OLD_PATH>` (current git-clone dir), `<EARLIEST_GROUP_TIME>`
(earliest `time:` in `delivery_config.yaml`), `<VERSION>` (latest release tag, e.g. `v1.2.4`),
`<old-service>` (existing scheduler unit name).

### 0. Pre-flight
```bash
python3 --version                            # MUST be >= 3.10 (wire `alternatives` if the host has only versioned interpreters)
systemctl list-units | grep -i vuln          # find the old service name
crontab -l -u vuln-reports 2>/dev/null; sudo crontab -l 2>/dev/null   # find any warm-cache / scheduler cron
id vuln-reports || echo "service account missing — create per DEPLOYMENT.md"
```

### 1. Back up old install + stage state
```bash
sudo tar czf /root/vuln-reporting-OLD-$(date +%F).tar.gz <OLD_PATH>
sudo mkdir -p /root/vuln-migrate
sudo cp    <OLD_PATH>/.env                   /root/vuln-migrate/
sudo cp    <OLD_PATH>/delivery_config.yaml   /root/vuln-migrate/
sudo cp -r <OLD_PATH>/data/trend             /root/vuln-migrate/trend          # IRREPLACEABLE
sudo cp    <OLD_PATH>/logs/delivery_log.db   /root/vuln-migrate/ 2>/dev/null || true
sudo cp    <OLD_PATH>/assets/logo.png        /root/vuln-migrate/ 2>/dev/null || true
```

### 2. Stop the old scheduler (begin cutover window)
```bash
sudo systemctl stop <old-service> && sudo systemctl disable <old-service>
# remove/comment any old warm-cache or scheduler cron (replaced in step 7)
```

### 3. Make room (same box only, when `<OLD_PATH>` == `/opt/vuln-reporting`)
```bash
sudo mv /opt/vuln-reporting /opt/vuln-reporting.old      # tarball already taken in step 1
```
*(If the old clone lives elsewhere, skip this — leave it in place as the fallback.)*

### 4. Build the new layout + install the release
Follow [`DEPLOYMENT.md`](../DEPLOYMENT.md) (or `deploy/smoke_bootstrap.sh` for prereqs):
create `/opt/vuln-reporting/{releases,shared/{logs,output,data/cache,data/trend,data/runtime-cache}}`,
then install `<VERSION>` per the documented steps, or seed `current` once and use
`update_from_github.sh --version <VERSION>` thereafter.

### 5. Reconcile `.env` + drop in preserved state
```bash
sudo -u vuln-reports cp /root/vuln-migrate/.env /opt/vuln-reporting/shared/.env
# Old installs predate GITHUB_RELEASE_REPO — diff against the example and add what's missing:
diff <(grep -oE '^[A-Z_]+' /opt/vuln-reporting/current/.env.example | sort) \
     <(grep -oE '^[A-Z_]+' /opt/vuln-reporting/shared/.env | sort)
#   → add GITHUB_RELEASE_REPO=<owner>/<repo>   (CHAR-CHECK the owner/repo — a one-char typo 404s the updater)
#   → optional GITHUB_TOKEN=...                (lifts the GitHub API rate limit from 60/hr to 5000/hr)
sudo chmod 600 /opt/vuln-reporting/shared/.env

sudo -u vuln-reports cp /root/vuln-migrate/delivery_config.yaml /opt/vuln-reporting/shared/delivery_config.yaml
sudo -u vuln-reports cp /root/vuln-migrate/trend/*.json         /opt/vuln-reporting/shared/data/trend/
sudo -u vuln-reports cp /root/vuln-migrate/delivery_log.db      /opt/vuln-reporting/shared/logs/ 2>/dev/null || true
sudo chown -R vuln-reports:vuln-reports /opt/vuln-reporting/shared
```

### 6. Validate before cutover
Use the env-matching form so the manual run mirrors the systemd environment (otherwise
matplotlib warns about the unwritable service-account `$HOME`):
```bash
sudo -u vuln-reports env HOME=/opt/vuln-reporting/shared/data/runtime-cache \
  XDG_CACHE_HOME=/opt/vuln-reporting/shared/data/runtime-cache \
  MPLCONFIGDIR=/opt/vuln-reporting/shared/data/runtime-cache/matplotlib \
  bash -c "cd /opt/vuln-reporting/current && .venv/bin/python run_all.py --dry-run"
# then a real render WITHOUT sending, against the migrated trend data:
#   ... run_all.py --group "<one group>" --no-email
```

### 7. Cut over — daemon **or** cron, not both
```bash
# Option A — systemd daemon (hot-reloads config, manages the process):
sudo cp /opt/vuln-reporting/current/deploy/vuln-reports.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vuln-reports

# Option B — cron run-due (the alternative to the daemon): install deploy/crontab.example.
```
Add the **cache pre-warm** cron (`deploy/crontab.example` entry #1) regardless of A/B —
but see the warm-cache note below for timing.

> ⚠️ If you chose the daemon (A), do **not** also add the `scheduler.py --mode run-due`
> cron (entry #2). Running both delivers every report twice.

### 8. Confirm + keep the fallback
```bash
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --check
systemctl status vuln-reports --no-pager | head
journalctl -u vuln-reports -f      # watch the next warm-cache + scheduled group
```
Keep `/opt/vuln-reporting.old` (and the tarball) until you've seen a clean warm-cache run
**and** a clean scheduled delivery. Rollback = stop the new scheduler, re-enable
`<old-service>`. Once confident: `sudo rm -rf /opt/vuln-reporting.old`.

---

## Three things that will bite if skipped

1. **Trend JSON is irreplaceable.** Without `data/trend/*.json`, trend/management reports restart from zero history.
2. **`GITHUB_RELEASE_REPO` is required and typo-prone.** It is absent from pre-v1.2 `.env` files; the updater is inert without it. Char-check the `owner/repo`.
3. **Retire any midnight warm-cache cron.** Cache folders are named by server **local date**; a job near midnight caches under one date while the report run reads another → guaranteed cache miss (or re-fetch). Schedule `warm_cache.py --prune-stale` **≥30 minutes before `<EARLIEST_GROUP_TIME>` and never near midnight** (see `deploy/crontab.example` entry #1).

---

## Warm-cache note (preferred future approach)

The cron-based pre-warm works but carries timing coupling, the midnight footgun, and a
second scheduler to keep in sync. The preferred end state for a daemon deployment is to
fold the warm step **into the daemon** (schedule-derived, run once before each batch),
which removes all three. That enhancement is tracked in
[`.planning/ROADMAP.md`](../.planning/ROADMAP.md) ("Backlog" → *Daemon-integrated warm-cache*).
Until it lands, use the corrected cron above.
