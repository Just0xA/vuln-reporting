# Deployment Guide — Vulnerability Management Reporting Suite v1.2

This document is the single authoritative guide for installing, upgrading, and rolling back
the suite on a Linux server using the v1.2 release-tarball workflow.

**Target audience:** A non-author operator deploying or maintaining the suite on a server.

> **For day-to-day operations** (recipients, schedules, manual triggers, troubleshooting
> runtime issues), see [RUNBOOK.md](RUNBOOK.md) after you complete this guide.

---

## Rollback

> **Emergency rollback — run this if an upgrade misbehaves:**
>
> ```bash
> sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
> ```
>
> This re-points `current` to the previous release and restarts the service.
> No other steps required.

The rollback one-liner is also printed to stdout at the end of every successful upgrade
so you always have a copy-paste-ready command immediately after the swap.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Install from a Release Tarball](#install-from-a-release-tarball)
3. [Configure Credentials](#configure-credentials)
4. [Verify](#verify)
5. [Update Procedure](#update-procedure)
6. [Troubleshooting (Install / Upgrade)](#troubleshooting-install--upgrade)
7. [On-Disk Layout](#on-disk-layout)
8. [Schema Migration Note](#schema-migration-note)
9. [Pre-Release Sensitive-Data Checklist (D-04-08)](#pre-release-sensitive-data-checklist-d-04-08)

---

## System Requirements

**Operating system:** Linux server — RHEL 9, Ubuntu 22.04+, or compatible derivatives.
A systemd-capable OS is required for the daemon mode.

**Python:** 3.10 or later.

```bash
# RHEL 9 ships Python 3.9; install 3.12 from AppStream:
sudo dnf install -y python3.12 python3.12-pip python3.12-devel

# Confirm:
python3.12 --version
```

`scripts/update_from_github.sh` auto-resolves a versioned interpreter (>= 3.10) when
no unversioned `python3` exists — it checks bare `python3` first, then falls back through
the highest available versioned name from `python3.13` down to `python3.10`. On a host with only `python3.12`
and no `/usr/bin/python3` symlink, the updater will resolve `python3.12` automatically.

Wiring up an unversioned `python3` is still recommended for clarity and compatibility with
other tooling:

```bash
sudo alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
```

If no python3 >= 3.10 is found, the updater exits 8 with a clear error in `update.log`.

`requirements.txt` (pip into a per-release `.venv`, as shown below) is the supported server install path; the `uv`/devcontainer workflow is a dev-only convenience and is not used for server deployment.

**WeasyPrint system packages** (required for PDF generation):

```bash
# RHEL 9 / Fedora / CentOS Stream
sudo dnf install -y gcc libffi-devel openssl-devel cairo-devel pango-devel

# Debian / Ubuntu equivalents
sudo apt-get install -y build-essential libffi-dev libssl-dev \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0
```

Without these libraries, `pip install weasyprint` will fail during venv provisioning.

**SELinux (RHEL 9):** Allow outbound HTTPS + SMTP connections for the service account:

```bash
sudo setsebool -P httpd_can_network_connect on
```

**Disk:** Allow ~500 MB for the install root (two release versions), growing over time as
reports accumulate in `shared/output/`.

---

## Install from a Release Tarball

> **Production installs MUST use a release tarball.**
> `git clone` is NOT a supported production install path — the repository contains
> `.planning/`, `.git/`, development artifacts, and test fixtures that the slim tarball
> excludes. Using a tarball gives you a clean, auditable install with a verified SHA256
> checksum.

### Step 1 — Create the install root and service account

```bash
sudo mkdir -p /opt/vuln-reporting/{releases,shared/{logs,output,data/cache,data/trend,data/runtime-cache}}
sudo useradd --system --no-create-home --shell /sbin/nologin vuln-reports
sudo chown -R vuln-reports:vuln-reports /opt/vuln-reporting
sudo chmod -R 750 /opt/vuln-reporting
```

### Step 2 — Download the release tarball and checksum

Navigate to **https://github.com/OWNER/REPO/releases** (replace `OWNER/REPO` with your
`GITHUB_RELEASE_REPO` value) and locate the target release.

Download `vuln-reporting-vX.Y.Z-slim.tar.gz` and its `.sha256` sidecar:

```bash
VERSION=v1.2.0   # replace with the target release tag
BASE_URL="https://github.com/OWNER/REPO/releases/download/${VERSION}"

curl -fsSL -o "/tmp/vuln-reporting-${VERSION}-slim.tar.gz" \
    "${BASE_URL}/vuln-reporting-${VERSION}-slim.tar.gz"
curl -fsSL -o "/tmp/vuln-reporting-${VERSION}-slim.tar.gz.sha256" \
    "${BASE_URL}/vuln-reporting-${VERSION}-slim.tar.gz.sha256"
```

### Step 3 — Verify the checksum

```bash
cd /tmp && sha256sum -c "vuln-reporting-${VERSION}-slim.tar.gz.sha256"
# Expected: vuln-reporting-vX.Y.Z-slim.tar.gz: OK
```

If the check fails, re-download. Never proceed with a checksum mismatch.

### Step 4 — Extract into the releases directory

```bash
RELEASE_DIR="/opt/vuln-reporting/releases/${VERSION}"
sudo -u vuln-reports mkdir -p "$RELEASE_DIR"
sudo -u vuln-reports tar -xzf "/tmp/vuln-reporting-${VERSION}-slim.tar.gz" \
    --strip-components=1 -C "$RELEASE_DIR"
```

### Step 5 — Create the per-release virtual environment

```bash
sudo -u vuln-reports python3.12 -m venv "${RELEASE_DIR}/.venv"
sudo -u vuln-reports "${RELEASE_DIR}/.venv/bin/pip" install --upgrade pip
sudo -u vuln-reports "${RELEASE_DIR}/.venv/bin/pip" install -r "${RELEASE_DIR}/requirements.txt"
```

### Step 6 — Symlink shared paths

```bash
# Credentials and config (operator-managed; survive upgrades)
sudo -u vuln-reports ln -sfn /opt/vuln-reporting/shared/.env               "${RELEASE_DIR}/.env"
sudo -u vuln-reports ln -sfn /opt/vuln-reporting/shared/delivery_config.yaml "${RELEASE_DIR}/delivery_config.yaml"

# Runtime data (logs, output, cache, trend snapshots)
sudo -u vuln-reports ln -sfn /opt/vuln-reporting/shared/logs               "${RELEASE_DIR}/logs"
sudo -u vuln-reports ln -sfn /opt/vuln-reporting/shared/output             "${RELEASE_DIR}/output"
sudo -u vuln-reports ln -sfn /opt/vuln-reporting/shared/data/cache         "${RELEASE_DIR}/data/cache"
sudo -u vuln-reports ln -sfn /opt/vuln-reporting/shared/data/trend         "${RELEASE_DIR}/data/trend"
```

### Step 7 — Point `current` at the new release

```bash
sudo -u vuln-reports ln -sfn "$RELEASE_DIR" /opt/vuln-reporting/current
```

### Step 8 — Configure credentials

See [Configure Credentials](#configure-credentials) below.

---

## Configure Credentials

Credentials live in `shared/.env` (operator-managed; never overwritten by upgrades).

```bash
# Copy the template from the new release:
sudo -u vuln-reports cp /opt/vuln-reporting/current/.env.example \
    /opt/vuln-reporting/shared/.env

# Edit with your real values:
sudo -u vuln-reports nano /opt/vuln-reporting/shared/.env

# Restrict permissions — the file contains passwords:
sudo chmod 600 /opt/vuln-reporting/shared/.env
```

Required variables:

```dotenv
# Tenable.io API keys — Settings > My Account > API Keys
TVM_ACCESS_KEY=your_access_key_here
TVM_SECRET_KEY=your_secret_key_here
TVM_URL=https://cloud.tenable.com

# SMTP (Office 365 defaults shown; adjust for other providers)
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=reports@yourcompany.com
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_ADDRESS=reports@yourcompany.com
SMTP_FROM_NAME=Vulnerability Management Reports

# GitHub Releases source — required by update_from_github.sh --check / --version
# Format: <github-org-or-user>/<repository-name>
```

Optional variables:

```dotenv
# Personal access token — lifts GitHub API rate limit from 60/hr to 5000/hr
# Recommended if --check runs on a cron schedule
# GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Override maximum total attachment size before Excel files are dropped (default 25)
# MAX_ATTACHMENT_SIZE_MB=25
```

`shared/.env` is symlinked into every release directory (Step 6 above), so it is
read at the same path (`/opt/vuln-reporting/current/.env`) regardless of which
release is active.

### Seed the delivery config

Like `.env`, `delivery_config.yaml` lives in `shared/` (operator-managed; survives
upgrades) and is symlinked into each release by Step 6. The symlink dangles until
you create the file — seed it from the shipped example, then edit your real groups:

```bash
# Copy the template from the new release:
sudo -u vuln-reports cp /opt/vuln-reporting/current/delivery_config.example.yaml /opt/vuln-reporting/shared/delivery_config.yaml

# Edit with your real recipient groups, schedules, and filters:
sudo -u vuln-reports nano /opt/vuln-reporting/shared/delivery_config.yaml
```

Until at least one group is defined, `run_all.py --dry-run` validates 0 groups.

---

## Verify

### Validate configuration (no API calls)

```bash
sudo -u vuln-reports env HOME=/opt/vuln-reporting/shared/data/runtime-cache XDG_CACHE_HOME=/opt/vuln-reporting/shared/data/runtime-cache MPLCONFIGDIR=/opt/vuln-reporting/shared/data/runtime-cache/matplotlib bash -c "cd /opt/vuln-reporting/current && .venv/bin/python run_all.py --dry-run"
```

This is a single-line, paste-safe command — the `&&` keeps it intact when a terminal
collapses a multi-line `cd`+command block onto one line.

The `env HOME=... XDG_CACHE_HOME=... MPLCONFIGDIR=...` prefix mirrors the systemd unit's
`Environment=` lines so matplotlib writes its config/font cache into the writable
`shared/data/runtime-cache` directory. A manual `sudo -u` invocation does **not** inherit
the service's `Environment=` settings, so without this prefix matplotlib probes the
`--no-create-home` service account's unwritable `/home/vuln-reports` and prints a harmless
`Permission denied: '/home/vuln-reports'` / `MPLCONFIGDIR` warning, then rebuilds its font
cache under `/tmp`. The simpler form below still validates correctly — it just emits that
warning:

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting/current && .venv/bin/python run_all.py --dry-run"
```

Expected output: a `rich` table listing all delivery groups with a green `OK` for each.
If any group shows `FAIL`, the error message identifies the misconfigured field.

### Verify Tenable connectivity

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting/current && .venv/bin/python tenable_client.py"
```

This is a single-line, paste-safe command (the `&&` survives a multi-line paste collapse).

Expected output:

```
Successfully authenticated to Tenable at https://cloud.tenable.com
Connection successful. Client is ready.
```

### Install and start the systemd service

```bash
sudo cp /opt/vuln-reporting/current/deploy/vuln-reports.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vuln-reports
sudo systemctl start vuln-reports
sudo systemctl status vuln-reports
```

The service uses `WorkingDirectory=/opt/vuln-reporting/current/` and reads credentials
from `EnvironmentFile=/opt/vuln-reporting/shared/.env`.

Check live logs:

```bash
sudo journalctl -u vuln-reports -f
```

### Allow the updater to restart the service

`update_from_github.sh` calls `sudo systemctl restart vuln-reports.service` after every
swap and rollback. Two invocation models are supported:

**Run as root (default — recommended for manual and interactive upgrades)**

Always invoke the updater with `sudo` (as shown throughout this guide):

```bash
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --version v1.2.1
```

The updater automatically restores service-account ownership on the new release directory
(and its `.venv`) after provisioning, using the owner of `${INSTALL_ROOT}/releases/` as the
reference. This means a root-run upgrade no longer leaves a `root:root`-owned tree that the
`ProtectSystem=strict` service cannot read, which previously caused the post-swap health check
to auto-rollback every clean upgrade.

**Run as the `vuln-reports` service account (for cron automation)**

Supported for flexibility — for example, if you want a cron job to run as the service account
rather than as root. In this mode the updater skips the ownership fix (the files are already
owned by the invoking account, which is the service account). This mode **requires** the scoped
sudoers entry below; without it the `systemctl restart` call fails for the non-interactive
account and the post-swap health check auto-rolls-back every upgrade regardless of release
health:

```bash
# /etc/sudoers.d/vuln-reports-restart  (validate with: sudo visudo -c)
vuln-reports ALL=(root) NOPASSWD: /bin/systemctl restart vuln-reports.service
```

Confirm the `systemctl` path with `command -v systemctl` — some distros use
`/usr/bin/systemctl`; the sudoers path must match exactly.

**Proxy variables for the service-account path**

When the updater is invoked as the `vuln-reports` service account (e.g. from a cron job or
wrapper script), `curl` (release download) and `pip` (venv provisioning) need outbound internet
access. The proxy environment variables that your AD user inherits automatically are **not**
inherited by the service account.

Set `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` (and their lower-case equivalents `http_proxy`,
`https_proxy`, `no_proxy`, which `curl` also honors) on the invocation line or in the wrapper
script — **not** in `shared/.env`. The updater reads only `GITHUB_RELEASE_REPO` and
`GITHUB_TOKEN` from `shared/.env`; it does not export those values to `curl` or `pip`, so
proxy settings there have no effect (same chicken-and-egg constraint as `INSTALL_ROOT` — see
[Relocating the install base](#relocating-the-install-base)).

Example cron/wrapper invocation as the service account:

```bash
HTTPS_PROXY=http://proxy.corp.example.com:8080 \
NO_PROXY=localhost,127.0.0.1,.corp.example.com \
http_proxy=http://proxy.corp.example.com:8080 \
https_proxy=http://proxy.corp.example.com:8080 \
no_proxy=localhost,127.0.0.1,.corp.example.com \
  /opt/vuln-reporting/current/scripts/update_from_github.sh --version v1.2.1
```

If no proxy is required on your network, ignore this subsection entirely.

### Schedule reports with cron (alternative to the systemd daemon)

The systemd service described in "Install and start the systemd service" above is the
recommended path for scheduled delivery. If you prefer a cron-based schedule instead,
this subsection covers the first-time setup. **Use cron OR the daemon — not both at the
same time for scheduled delivery.** Running both doubles every delivery and may produce
race conditions on the parquet cache.

The ready-to-use crontab file ships at [`deploy/crontab.example`](deploy/crontab.example).
Review and adjust the timing before installing (see comments inside the file), then install
it as the service account:

```bash
sudo -u vuln-reports crontab - < /opt/vuln-reporting/current/deploy/crontab.example
```

The example file contains two cron lines: a `warm_cache` pre-warmer that runs before any
report group fires, and a `scheduler.py --mode run-due` line invoked every 5 minutes to
fire any group whose schedule matches the current time within a ±10-minute window.

**TIMING RULE A — schedule `warm_cache` at least 30 minutes before your earliest report group.**
The fetch must complete before the report run starts. With a 07:00 earliest group, schedule
`warm_cache` at 06:15 or earlier. Adjust both times to match your actual earliest group. If
the dataset is large and the fetch takes longer than 30 minutes, push the warm-cache time
earlier accordingly.

**TIMING RULE B — never schedule `warm_cache` near midnight.**
Cache folders are named by server local date (`YYYY-MM-DD`), not UTC. If `warm_cache.py`
fires at 23:55 and the report run fires at 00:05, the date rolls over between the two runs
and the report run will not find the cached data — it re-fetches everything from Tenable,
defeating the point of pre-warming. Keep warm-cache well before midnight (e.g. 06:15
satisfies both rules with comfortable margins).

**`cd` into the project root — required.**
`warm_cache.py` imports project-root modules (`config`, `data`, `tenable_client`), and
`python -m` only adds the current working directory to `sys.path`. Cron's default CWD is
the service account's home directory, not the project root, so the `cd` at the start of
each cron line is not optional.

**Per-release `.venv` path.**
The updater builds a virtual environment at `current/.venv/` for each release. The cron
lines use `/opt/vuln-reporting/current/.venv/bin/python`. Operators on an older hand-built
install may need `/opt/vuln-reporting/.venv/bin/python` instead.

**Non-default `INSTALL_ROOT`.**
If the suite is installed somewhere other than `/opt/vuln-reporting` (see
[Relocating the install base](#relocating-the-install-base)), every path occurrence in each
cron line must change together: the `cd` target, the interpreter path, and the `>>` log-redirect
path. Changing only the `cd` target while leaving the interpreter or log path pointing at the
old base will silently break the pre-warmer or discard its output.

**Cron log files are NOT auto-rotated.**
The `>>` redirects in the cron lines capture cron-level stdout/stderr into
`warm_cache.cron.log` and `run-due.cron.log` under `shared/logs/`. These files are not
covered by the scripts' own rotating log handlers. See the logrotate snippet in
[`deploy/crontab.example`](deploy/crontab.example) (comments inside the file) to set up
rotation — or truncate them periodically.

---

## Update Procedure

The `scripts/update_from_github.sh` script automates the full download-verify-swap-health-check
cycle. It requires `GITHUB_RELEASE_REPO` to be set in `shared/.env`.

### Check whether an update is available

```bash
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --check
```

Exit codes:
- `0` — already on the latest release
- `1` — update available (safe to proceed)
- `>=2` — error (check `shared/logs/update.log`)

Output example:
```
active:  v1.2.0
latest:  v1.2.1
status: update available
```

### Install a specific version

```bash
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --version v1.2.1
```

The script performs this sequence automatically:

1. Downloads `vuln-reporting-v1.2.1-slim.tar.gz` and its `.sha256` sidecar
2. Verifies the SHA256 checksum — refuses to proceed on mismatch (exit 5)
3. Extracts the tarball into `releases/v1.2.1/`
4. Creates `releases/v1.2.1/.venv` and runs `pip install -r requirements.txt`
5. Symlinks shared paths (`.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/`, `data/trend/`) into the new release directory
6. Runs `run_all.py --dry-run` as a smoke test
7. Atomically swaps `current` to `releases/v1.2.1/` via `ln -sfn`
8. Writes the previous release as the `releases/.last` rollback breadcrumb — *after* the swap succeeds, so `.last` only ever points at a release that was actually displaced (crash-safe ordering)
9. Restarts `vuln-reports.service`
10. Waits 10 seconds, then checks `systemctl is-active` — auto-rolls back to the previous release and exits 12 if the service is not active
11. Prints the rollback one-liner on success:

```
Rollback: sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
```

### Roll back after an upgrade

If the new release misbehaves after a successful health check, run:

```bash
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
```

This re-points `current` to whatever the script displaced during the last upgrade
(stored in `releases/.last`) and restarts the service. No health check is run on
rollback — the rollback target is by definition the previously-trusted release.

Additional flags:

```bash
# List all installed releases; marks the active one with * (active)
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --list

# Re-extract over an existing release directory
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --version v1.2.0 --force

# Skip the systemctl restart (staged maintenance windows)
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --version v1.2.1 --skip-restart

# Prune old releases, keeping the 3 most recent (active + rollback target always kept)
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --prune

# Override the retention count
sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --prune --keep 5
```

Successful `--version` installs auto-prune to the default retention (keep 3). The active
release and the `.last` rollback target are never deleted even if they fall outside the
keep window. Prune is best-effort and never fails an install.

All invocations log a started and completed line to `shared/logs/update.log`.

---

## Troubleshooting (Install / Upgrade)

### SHA256 mismatch (exit code 5)

The script refuses to extract a tarball whose checksum does not match its sidecar.

**Resolution:** Re-download both the tarball and the `.sha256` file. Do not attempt
to install a tarball whose checksum cannot be verified — the file may be corrupted
or tampered with.

### Layout-guard refusal (exit code 2)

The script refuses to run if `current` is missing or does not point inside `releases/`.

**Symptom:** Error line in `update.log`:
`current is missing or not a symlink (refuse-if-unknown-layout)`
or `current points outside releases/`.

**Resolution:** This typically occurs on a hand-built install where `current` was not
created. Run the manual install steps (Steps 7 above) to create the `current` symlink
pointing inside `releases/`, then retry.

### Venv build failure (exit code 8)

Python package compilation fails during `pip install -r requirements.txt`.

**Most common cause:** Missing WeasyPrint system packages.

**Resolution:**

```bash
# RHEL 9
sudo dnf install -y gcc libffi-devel openssl-devel cairo-devel pango-devel

# Debian / Ubuntu
sudo apt-get install -y build-essential libffi-dev libssl-dev \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0
```

Then retry the `--version` install (use `--force` to re-extract if the partial
release directory was left in place).

### Health-check auto-rollback fired (exit code 12)

The service did not reach `active` within 10 seconds after the swap.

**Resolution:**

```bash
# Check the update log for the failure reason
tail -50 /opt/vuln-reporting/shared/logs/update.log

# Check the service's own startup errors
sudo systemctl status vuln-reports
sudo journalctl -u vuln-reports --since "5 minutes ago"
```

The broken release directory is preserved (not deleted) for inspection.
The previous release is already active again — the suite continues to run.
Fix the issue in the new release directory and retry `--version` with `--force`.

### GitHub API rate limit

`--check` calls the GitHub Releases API unauthenticated (60 requests/hour).
On a cron schedule this is easily exhausted.

**Resolution:** Set `GITHUB_TOKEN` in `shared/.env` to a personal access token
(classic or fine-grained with read access to releases). This raises the limit
to 5000 requests/hour:

```dotenv
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

No service restart needed — the script reads `.env` at each invocation.

---

## On-Disk Layout

```
/opt/vuln-reporting/
├── current -> releases/v1.2.1/          # symlink; atomically swapped on upgrade
├── releases/
│   ├── v1.2.0/                          # previous release (kept for rollback)
│   │   ├── .venv/                       # per-release Python virtual environment
│   │   ├── .env -> ../../shared/.env    # symlink (operator-managed)
│   │   ├── delivery_config.yaml -> ../../shared/delivery_config.yaml
│   │   ├── logs -> ../../shared/logs
│   │   ├── output -> ../../shared/output
│   │   ├── data/
│   │   │   ├── cache -> ../../../shared/data/cache
│   │   │   └── trend -> ../../../shared/data/trend
│   │   └── scripts/
│   │       └── update_from_github.sh
│   ├── v1.2.1/                          # active release (current points here)
│   │   └── ...                          # same structure as above
│   └── .last                            # rollback breadcrumb (previous current target)
└── shared/
    ├── .env                             # operator-managed credentials (survives upgrades)
    ├── delivery_config.yaml             # operator-managed; symlinked, NOT overwritten
    ├── logs/
    │   ├── app.log
    │   ├── scheduler.log
    │   ├── update.log
    │   ├── warm_cache.log
    │   └── delivery_log.db
    ├── output/                          # timestamped report folders
    └── data/
        ├── cache/                       # per-day parquet cache
        ├── trend/                       # trend snapshots (management_summary)
        └── runtime-cache/               # service HOME/XDG_CACHE_HOME/MPLCONFIGDIR
            └── matplotlib/              # auto-created by matplotlib at first render
```

The `current` symlink is the sole indirection point. Every path that the service,
cron jobs, and manual CLI invocations use goes through `current/` — so a rollback
(re-pointing `current`) takes effect for all callers simultaneously with no
configuration changes.

`shared/data/runtime-cache/` is not symlinked into the release tree — it is used
only by the systemd unit, which runs under `ProtectSystem=strict` (the whole OS
tree, including `/opt`, is read-only except the paths in `ReadWritePaths`). The
service account is created with `--no-create-home`, so the unit pins `HOME`,
`XDG_CACHE_HOME`, and `MPLCONFIGDIR` into this directory via `Environment=` lines
so matplotlib and WeasyPrint/fontconfig have a writable cache. This directory
**must exist before the service starts** — a missing `ReadWritePaths` path makes
systemd fail namespace setup under `strict`. Step 1's `mkdir -p` creates it. The
`matplotlib/` subdirectory is auto-created by matplotlib on first render because
its parent (`runtime-cache/`) is writable.

---

## Relocating the install base

The default install base is `/opt/vuln-reporting`. To install somewhere else
(e.g. `/opt/storage/vuln-reporting` on a host where `/opt` is small and a separate
volume is mounted at `/opt/storage`), two independent pieces must agree on the base:

**1. The updater script — set `INSTALL_ROOT`.**
`update_from_github.sh` derives every path from `INSTALL_ROOT` (default
`/opt/vuln-reporting`). Override it as an **environment variable** on each invocation:

```bash
sudo INSTALL_ROOT=/opt/storage/vuln-reporting \
  /opt/storage/vuln-reporting/current/scripts/update_from_github.sh --check
```

`INSTALL_ROOT` **must** be an environment variable — it cannot go in `shared/.env`,
because the script uses `INSTALL_ROOT` to *locate* `shared/.env` in the first place
(chicken-and-egg). For cron or automation, set it in the crontab line or a wrapper
script, not in the credential file.

**2. The systemd unit — rewrite the hard-coded paths.**
systemd cannot expand environment variables in `WorkingDirectory`, `EnvironmentFile`,
or `ReadWritePaths` (they are parsed before any environment loads), so the unit ships
with the base path hard-coded. Rewrite all of them consistently before installing:

```bash
sudo sed -i 's#/opt/vuln-reporting#/opt/storage/vuln-reporting#g' \
  /etc/systemd/system/vuln-reports.service
sudo systemctl daemon-reload
sudo systemctl restart vuln-reports
```

Both must point at the same base. After relocating, re-run the `--dry-run` verify
(see [Verify](#verify)) before enabling scheduled delivery.

---

## Schema Migration Note

`shared/delivery_config.yaml` is **operator-managed** and is **symlinked** into each
release directory — it is never overwritten by an upgrade.

After a **major version upgrade** (e.g., v1.x → v2.x), new configuration fields may
be added or required. Operators should diff their config against the new release's
example to pick up any new fields:

```bash
diff /opt/vuln-reporting/shared/delivery_config.yaml \
     /opt/vuln-reporting/current/delivery_config.example.yaml
```

If `delivery_config.schema.yaml` is present in the release, editors and CI can validate
the config against it automatically. A dry-run (`run_all.py --dry-run`) will also report
missing or unrecognised fields before the scheduler processes them.

Minor version upgrades (e.g., v1.2.0 → v1.2.1) do not change the schema.

---

## Pre-Release Sensitive-Data Checklist (D-04-08)

Run this checklist before tagging a release. Its purpose is to ensure that no
row-level Tenable data reaches the public repository via committed files, test
fixtures, or build artifacts.

### What is safe to commit

- Aggregate counts (e.g., "42 critical findings")
- Structural shape / schema examples with placeholder values
- Synthetic/fabricated data that does not originate from a real Tenable environment

### What must NOT be committed

Row-level Tenable data — asset names, IP addresses, FQDN values, plugin names,
vulnerability descriptions, CVE IDs tied to real assets, or any value that could
identify a real system or finding in your environment.

### Checklist

- [ ] **outputs/** — no report PDF, Excel, or CSV files in the working tree or committed.
  `output/` is in `.gitignore`; confirm with `git status --short | grep output/`.

- [ ] **logs/** — no `app.log`, `scheduler.log`, `delivery_log.db`, or `warm_cache.log`
  in the working tree or committed. `logs/` is in `.gitignore`; confirm with
  `git status --short | grep logs/`.

- [ ] **data/trend/** — no `*.json` trend snapshot files committed. `data/trend/` is in
  `.gitignore`; confirm with `git status --short | grep data/trend`.

- [ ] **data/cache/** — no `*.parquet` cache files committed. `data/cache/` is in
  `.gitignore`; confirm with `git status --short | grep data/cache`.

- [ ] **delivery_config.yaml** — the committed file (if any) uses only placeholder
  recipient addresses. Real recipient addresses must use the operator's live config
  in `shared/delivery_config.yaml`, which is never committed.

- [ ] **test fixtures / baselines** — any committed YAML, JSON, or CSV test data uses
  synthetic values only (no real asset names, IPs, or plugin output strings).

- [ ] **Test recipient addresses** use the `example.invalid` domain (RFC 6761 reserved;
  guaranteed never to deliver). Examples: `analyst@example.invalid`,
  `ciso@example.invalid`. Never use real addresses in committed test files.

- [ ] **No credentials in committed files** — `.env` is in `.gitignore`. Confirm:
  `git log --all --full-history -- .env` returns no commits.

- [ ] **Tarball content assertion passes** — the CI release workflow
  (`.github/workflows/release.yml`) includes a forbidden-path gate that rejects
  `.planning/`, `.env`, `data/trend/`, and `.git` from the slim tarball.
  Confirm the workflow completed successfully before publishing.

Run `git diff --name-only HEAD` and `git status --short` immediately before
`git tag vX.Y.Z` to catch any accidentally staged sensitive files.
