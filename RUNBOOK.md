# Vulnerability Management Reporting Suite — Runbook

**Audience:** Security Analysts with limited Python experience
**Platform:** Linux server with the v1.2 symlink layout (`/opt/vuln-reporting/current/`)
**Scope:** Day-to-day operations — how to run and use an already-deployed suite

> This runbook assumes the suite is already installed and running. For installation,
> upgrades, and rollback procedures, see **[DEPLOYMENT.md](DEPLOYMENT.md)**.

---

## Table of Contents

1. [Installation & Upgrades](#installation--upgrades)
2. [Day-to-Day Operations](#day-to-day-operations)
3. [Delivery Config — Reviewed-Repo Cutover](#delivery-config--reviewed-repo-cutover)
4. [Scheduler Management](#scheduler-management)
5. [Operational Cron Schedule](#operational-cron-schedule)
6. [Troubleshooting (Runtime)](#troubleshooting-runtime)
7. [File Reference](#file-reference)

---

## Installation & Upgrades

This runbook covers **running and operating** an already-installed suite.

To install the suite from scratch, upgrade to a new release, or roll back to a
previous release, see **[DEPLOYMENT.md](DEPLOYMENT.md)**. That document owns
all server setup, tarball install, venv build, systemd unit installation, and
update procedures — including the scoped **sudoers entry** the updater needs to
restart the service (see DEPLOYMENT.md → "Allow the updater to restart the
service") and how to **relocate the install base** off the `/opt/vuln-reporting`
default.

---

## Day-to-Day Operations

> **Delivery config edits no longer happen on the server.** As of the
> reviewed-repo cutover (see [Delivery Config — Reviewed-Repo
> Cutover](#delivery-config--reviewed-repo-cutover) below), the documented
> path for adding recipients, groups, or schedule changes is: edit in the
> private corporate config repo → PR → CODEOWNERS review → CI gate → merge
> → manual copy of the merged commit to the server → provenance stamp. The
> sections immediately below (recipient/group/schedule how-tos) describe the
> **legacy single-file** editing mechanics — still accurate for the
> mechanics of *what* to change, but the *where you edit it* has moved to
> the private repo. They remain here as reference for reading/understanding
> `delivery_config.yaml` shape, and for the pre-cutover legacy file during
> the dual-source window.

All day-to-day configuration changes are made in one file:

```
/opt/vuln-reporting/shared/delivery_config.yaml
```

After any edit, run a dry-run to validate before the next scheduled delivery:

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python run_all.py --dry-run
```

The daemon picks up changes to `delivery_config.yaml` within 5 minutes — no
restart needed. Changes to `config.py` (SLA values) require a service restart.

**Server-side hand-edits over SSH are no longer the documented path** —
see [Delivery Config — Reviewed-Repo Cutover](#delivery-config--reviewed-repo-cutover).

---

### How to add a recipient to an existing group

> **Legacy single-file mechanics.** Post-cutover, do this edit in the
> private repo's `contacts.yaml` (recipients are keyed by named contact,
> not per-group) and go through PR → CODEOWNERS → CI → merge → copy, per
> the cutover section below — do not hand-edit the server copy.

1. Open the delivery configuration:

   ```bash
   sudo -u vuln-reports nano /opt/vuln-reporting/shared/delivery_config.yaml
   ```

2. Find the group by its `name` field. Add the new address to `recipients`:

   ```yaml
   email:
     recipients:
       - existing@company.com
       - newperson@company.com   # ← add this line
   ```

3. Save the file. The scheduler hot-reloads within 5 minutes — no restart needed.

4. Validate:

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python run_all.py --dry-run
   ```

---

### How to remove a recipient

Delete or comment out the address from the `recipients` list. At least one
address must remain — the dry-run will warn you if `recipients` is empty.

---

### How to add a new delivery group

Add a new entry to the `groups` list in `delivery_config.yaml`. Copy an
existing group as a starting point and adjust the values:

```yaml
- name: "Finance Team — Weekly Report"
  description: "SLA and patch status for Finance business unit"
  schedule:
    frequency: weekly
    day_of_week: tuesday   # monday | tuesday | wednesday | thursday | friday | saturday | sunday
    time: "08:00"          # 24-hour, server local time
  filters:
    tag_category: "Business Unit"   # must match exact Tenable tag category name
    tag_value: "Finance"            # must match exact Tenable tag value
  reports:
    - sla_remediation
    - patch_compliance
    - asset_risk
  email:
    subject: "Finance BU — Weekly Vulnerability Report"
    recipients:
      - finance-it@company.com
    cc:
      - security@company.com
    reply_to: security@company.com
```

Valid report slugs: `executive_kpi`, `sla_remediation`, `asset_risk`,
`patch_compliance`, `trend_analysis`, `plugin_cve`, `ops_remediation`,
`management_summary`, `vuln_export`, `board_summary`,
`board_summary_incl_risk_managed`, `unscanned_assets`, `composed_report`.

Run `--dry-run` to validate before the next scheduled run.

---

### How to set up a monthly report delivery

Monthly groups run once per calendar month on a fixed day at a fixed time.

```yaml
- name: "Monthly Executive Summary"
  description: "First-of-month executive package for leadership"
  schedule:
    frequency: monthly
    day_of_month: 1      # integer 1–28; 28 max avoids February edge cases
    time: "07:00"        # 24-hour, server local time
  filters:
    tag_category: "Environment"
    tag_value: "Production"
  reports:
    - executive_kpi
    - trend_analysis
  email:
    subject: "Monthly Vulnerability Management Report — Production"
    recipients:
      - ciso@company.com
    cc:
      - security-team@company.com
    reply_to: security@company.com
```

**Why is the maximum day 28?** February has 28 or 29 days depending on the
year. Setting `day_of_month: 29`, `30`, or `31` would silently skip February
and any shorter month. Using 28 guarantees delivery every month.

After adding the group, validate:

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python run_all.py --dry-run
```

The dry-run summary will show the monthly group as: `monthly / day 1 07:00`

---

### How to change a report schedule

Edit the `schedule` block for the relevant group in `delivery_config.yaml`:

```yaml
schedule:
  frequency: weekly
  day_of_week: wednesday   # changed from monday
  time: "09:30"            # changed from 07:00
```

The scheduler picks up the change within 5 minutes (hot-reload).

---

### How to change SLA windows

SLA thresholds are defined in `config.py`. Edit the `SLA_DAYS` dictionary:

```bash
sudo -u vuln-reports nano /opt/vuln-reporting/current/config.py
```

```python
SLA_DAYS: dict[str, int] = {
    "critical": 15,    # days to remediate a Critical vulnerability
    "high":     30,
    "medium":   90,
    "low":      180,
}
```

> **Important:** Changing SLA windows affects all reports and all delivery
> groups immediately. This change requires a developer review if your
> organisation has a formally agreed SLA policy.

After editing `config.py`, restart the service to apply the new values:

```bash
sudo systemctl restart vuln-reports
```

---

### How to trigger a group right now

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python run_all.py --group "Finance Team — Weekly Report"
```

This generates reports and sends the email to the configured recipients,
regardless of the scheduled day and time.

---

### How to generate reports without sending email

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python run_all.py --group "Finance Team — Weekly Report" --no-email
```

Output files are saved to `/opt/vuln-reporting/shared/output/` as usual.
Nothing is sent.

---

### How to send to a test address before a live run

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python run_all.py \
  --group "Finance Team — Weekly Report" \
  --recipients your.name@company.com
```

The email goes to `your.name@company.com` instead of the configured recipients.
The configured `cc` list is also cleared. This is safe to run while the daemon
is running.

---

### How to check what ran and when

Use the delivery log inspector:

```bash
cd /opt/vuln-reporting/current

# Show the 20 most recent deliveries
sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --recent 20

# Show deliveries for a specific group
sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --group "Finance Team — Weekly Report"

# Show deliveries within a date range
sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --from 2026-03-01 --to 2026-03-31
```

---

### How to check for failures

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --failures
```

This lists every delivery attempt that resulted in `failed` or `partial`
status, with the error message included.

---

## Delivery Config — Reviewed-Repo Cutover

**CONF-04 SC3 / QUAL-07 SC4.** This section replaces server-side SSH
hand-edits of delivery config with a reviewed-repo flow: real recipient
addresses, groups, and schedules are edited in a **private corporate config
repository**, never on the server. The transport stays "like current" — a
manual copy of the merged, reviewed commit onto the server — the server
gains no outbound git or artifact-fetch machinery (D-01). What changes is
provenance and review, not transport.

### The documented edit path

1. **Edit in the private corporate repo.** Change `contacts.yaml` and/or a
   `deliveries.d/<team>.yaml` file (never `shared/delivery_config.yaml` on
   the server — that file is legacy-only, see below).
2. **Open a PR** against the private repo.
3. **CODEOWNERS review.** Every config file maps 1:1 to a
   `deliveries.d/<team>.yaml` owner entry; today all entries — including
   the default rule covering `contacts.yaml`/`defaults`/the schema copy —
   resolve to the Vulnerability Management team (central stewardship). See
   `deploy/config-repo/CODEOWNERS.example` for the reference mapping.
4. **CI gate passes.** The private repo's CI (`deploy/config-repo/ci.yml.example`
   is the reference workflow) fetches a pinned `vuln-reporting` slim
   release, runs schema validation + `run_all.py --dry-run` (pre-auth,
   Hard Rule 1) against the merged effective config, and publishes the
   delivery matrix (names + owner only, never addresses) as a PR artifact.
   A non-zero `--dry-run` exit blocks the merge.
5. **Merge.** The PR lands on the private repo's default branch.
6. **Manually copy the merged commit's config to the server** —
   `contacts.yaml` + `deliveries.d/` → `/opt/vuln-reporting/shared/config/`
   on the server (same manual SCP/SSH transport as today; the server does
   not pull).
7. **Stamp provenance:**

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python scripts/stamp_config_provenance.py \
     stamp --config-dir /opt/vuln-reporting/shared/config --commit <merge-sha>
   ```

   This writes `shared/config/.config-provenance.json`, recording the
   merge commit SHA, a UTC timestamp, and a sha256 of the copied config
   tree — the D-03 invariant that live config traces to a reviewed commit.
   Periodically re-run with `verify` (drop `--commit`) to confirm no
   untracked drift has occurred:

   ```bash
   sudo -u vuln-reports .venv/bin/python scripts/stamp_config_provenance.py \
     verify --config-dir /opt/vuln-reporting/shared/config
   ```

   `verify` exits 0 when the live config matches its recorded provenance,
   and non-zero (with a logged reason) on drift or a missing sidecar.

Server-side hand-edits (`sudo -u vuln-reports nano
.../delivery_config.yaml`) are **no longer the documented path**. The
legacy how-to sections above remain for reading `delivery_config.yaml`
shape and for operating the legacy file during the dual-source window
only.

### Cutover procedure (zero delivery interruption — QUAL-07 SC4)

Perform this sequence once, when first cutting a delivery group over from
the legacy file to the reviewed-repo path. **Do not retire the legacy file
until step 4 confirms one full clean cycle.**

1. **Place directory-mode config alongside the still-present legacy file.**
   Copy the reviewed commit's `contacts.yaml` + `deliveries.d/` into
   `shared/config/` per the edit path above, and stamp provenance. Leave
   `shared/delivery_config.yaml` in place — both sources now coexist.
2. **Confirm directory-mode is active:**

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python run_all.py --dry-run
   ```

   The active-source echo (D-05) must report the directory-mode source,
   and every delivery must validate OK. If it instead reports
   legacy-fallback, the directory-mode config failed to resolve — fix it
   in the private repo and repeat the copy (do not hand-edit the server
   copy).
3. **Let ONE full delivery cycle run repo-sourced.** Wait for every
   delivery in the group to fire at least once on its normal schedule
   (weekly groups: one week; monthly groups: one month).
4. **Confirm via the delivery audit log** that every pre-cutover delivery
   still delivered:

   ```bash
   sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --recent 20
   sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --failures
   ```

   Zero unexpected failures for the cutover group across the full cycle is
   the gate for step 5.
5. **Only THEN retire the legacy file** — remove (or archive)
   `shared/delivery_config.yaml`. Directory mode is now the sole source;
   `_select_config_source` will report `"legacy"` fallback is no longer
   possible for this deployment until a legacy file is reintroduced.

**Rollback note.** If directory-mode resolution ever fails after cutover
but before legacy retirement (step 5), the D-04 automatic fallback
transparently delivers off the still-present legacy file — the next
`run_all.py --dry-run` (or the next scheduled delivery) logs a WARNING
naming the fallback and the legacy path, with zero delivery interruption.
No manual rollback action is required; fix the directory-mode config in
the private repo and re-copy. If legacy has already been retired (step 5
completed) and directory-mode then fails, re-place a last-known-good
`shared/delivery_config.yaml` from the private repo's history to restore
the fallback safety net while the directory-mode issue is fixed.

**`symlink_shared()` decision (explicit, per-release symlink for
`shared/config/`): YES, add one.** `run_all.py` resolves the
directory-mode config as `config_path.parent / "deliveries.d"`, where
`config_path` is `ROOT_DIR / "delivery_config.yaml"` and `ROOT_DIR =
Path(__file__).resolve().parent` — i.e. `current/`'s own directory, not
the symlink target. Because `Path.parent` does not follow symlinks, this
check only ever sees a `deliveries.d/` that physically resolves inside
`current/` (via a symlink placed there), the same way the existing single
`delivery_config.yaml` symlink works today. Therefore `shared/config/`
needs its own per-release symlink alongside the existing six in
`scripts/update_from_github.sh`'s `symlink_shared()` — e.g.
`ln -sfn "${INSTALL_ROOT}/shared/config" "${target_dir}/config"` — so that
`deliveries.d/` (and `contacts.yaml`) resolve at
`current/config/deliveries.d/` and `current/delivery_config.yaml`'s
sibling check finds it correctly relative to `config_path.parent`. This is
a small transport touch (one new symlink line), not a change to the D-01
manual-copy model: the *contents* of `shared/config/` still arrive via
manual copy from the private repo; only the per-release *pointer* to that
persistent directory is automated, identical in kind to the existing
`delivery_config.yaml` symlink.

---

## Scheduler Management

The daemon runs as the `vuln-reports` service account under systemd.

---

### Start, stop, restart, and check status

```bash
# Start the service
sudo systemctl start vuln-reports

# Stop the service (waits for any running job to finish before exiting)
sudo systemctl stop vuln-reports

# Restart the service
sudo systemctl restart vuln-reports

# Check whether it is running
sudo systemctl status vuln-reports
```

---

### How changes to delivery_config.yaml take effect

The daemon checks for changes to `delivery_config.yaml` **every 5 minutes**.
When a change is detected:

1. All currently-scheduled group jobs are cleared.
2. The updated config is loaded and validated.
3. All weekly and monthly groups are rescheduled with the new settings.

You do **not** need to restart the service after editing `delivery_config.yaml`.
The only exception is if you change `config.py` (SLA values, paths) — those
require a service restart.

---

### Check scheduler logs

```bash
# Stream live log output
sudo journalctl -u vuln-reports -f

# Show the last 100 lines
sudo journalctl -u vuln-reports -n 100

# Show everything since a specific time
sudo journalctl -u vuln-reports --since "2026-03-23 06:00"

# Show only errors and warnings
sudo journalctl -u vuln-reports -p warning
```

The scheduler also writes to a rotating log file at:

```
/opt/vuln-reporting/shared/logs/scheduler.log
```

Application-level logs (report runs, fetcher output, email attempts) are at:

```
/opt/vuln-reporting/shared/logs/app.log
```

---

### Running a manual trigger while the daemon is also running

This is safe. The daemon and manual CLI runs are completely independent:

- The daemon uses APScheduler to fire jobs on a schedule.
- A manual run (`run_all.py --group "..."`) is a separate process.
- Both can run at the same time without interfering.

The only shared resource is the parquet cache
(`/opt/vuln-reporting/shared/data/cache/`). Two runs on the same calendar date
share cached data, which is intentional and reduces API load.

---

## Operational Cron Schedule

> **First-time cron setup** (installing `crontab.example`, the two timing rules, `INSTALL_ROOT`
> path adjustment, and the cron-or-daemon choice) is covered in [DEPLOYMENT.md](DEPLOYMENT.md)
> under "Schedule reports with cron (alternative to the systemd daemon)".

This section covers day-to-day cron operation for an already-configured install.

---

### How cron-based scheduling works

`scheduler.py --mode run-due` reads `delivery_config.yaml`, checks whether any
group's schedule matches the current time within a **±10-minute window**, runs
matching groups, and exits. It must be invoked **every 5–10 minutes** by cron
so it can catch any scheduled group within that window.

---

### Adjusting cron timing when delivery groups change

When you add a new delivery group or change an existing group's scheduled time, check
whether the warm-cache line still fires early enough. `warm_cache` must finish before
the earliest group fires — see [DEPLOYMENT.md](DEPLOYMENT.md) for the timing rules.

To edit the installed crontab:

```bash
sudo -u vuln-reports crontab -e
```

After adjusting, run a dry-run to confirm the config is still valid:

```bash
cd /opt/vuln-reporting/current
sudo -u vuln-reports .venv/bin/python run_all.py --dry-run
```

---

### Checking warm-cache and cron logs

The pre-warmer writes its own rotating log:

```
/opt/vuln-reporting/shared/logs/warm_cache.log
```

The `>>` redirect in the crontab also captures cron-level output:

```
/opt/vuln-reporting/shared/logs/warm_cache.cron.log
/opt/vuln-reporting/shared/logs/run-due.cron.log
```

The `.cron.log` files are NOT auto-rotated. See the logrotate snippet in
[`deploy/crontab.example`](deploy/crontab.example) to set up rotation, or
truncate them periodically.

---

### Troubleshooting cache misses (report re-fetches instead of `[CACHE HIT]`)

If a report run shows live fetches rather than `[CACHE HIT]` in the logs, the most
common causes are:

- **Date rollover:** `warm_cache` ran just before midnight and the report ran just
  after — cache folder names are by server local date, so they no longer match.
  See DEPLOYMENT.md's timing rules to keep both lines well away from midnight.
- **Warm run still in progress:** `warm_cache` had not finished before the report
  group fired. Push the warm-cache cron time earlier (or adjust the group's delivery
  time later) to guarantee the fetch completes first.

---

## Troubleshooting (Runtime)

This section covers issues that arise during normal operation of an installed
suite. For install, upgrade, and rollback troubleshooting, see
[DEPLOYMENT.md](DEPLOYMENT.md).

---

### Tenable authentication failure

**Symptom:** `Authentication failed` or `401 Unauthorized` when starting the
service or running reports.

**Check these things:**

1. Confirm the variable names are present in `.env` (never print values):

   ```bash
   grep -E "^TVM_" /opt/vuln-reporting/shared/.env | cut -d= -f1
   ```

2. Test the connection manually:

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python tenable_client.py
   ```

3. Verify the API keys are active in the Tenable console:
   **Settings → My Account → API Keys**

4. Confirm `TVM_URL` is set to `https://cloud.tenable.com` (or your
   on-premises URL if applicable).

---

### SMTP failure

**Symptom:** Reports are generated but email is not sent. The delivery log
shows `status: failed` with an SMTP error message.

**Check these things:**

1. Confirm reports generate without SMTP involved:

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python run_all.py --group "Your Group" --no-email
   ```

   If this succeeds, the problem is SMTP-specific.

2. Check the delivery log for the error:

   ```bash
   sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --failures
   ```

3. Common SMTP issues:
   - Wrong `SMTP_USERNAME` or `SMTP_PASSWORD` in `.env`
   - Port 587 blocked by a firewall — try `SMTP_PORT=465` and `SMTP_USE_SSL=true`
   - Office 365: ensure the account has SMTP AUTH enabled in the Microsoft
     365 admin centre

---

### Report generated but email not received

1. Check the delivery log to confirm the attempt succeeded:

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python delivery/delivery_log.py --recent 5
   ```

   If `status` shows `success`, the email was accepted by the SMTP server.

2. Ask the recipient to check their spam/junk folder.

3. If status shows `partial`, Excel attachments were omitted because the
   combined size exceeded the limit. The email was still sent — only the
   Excel files are missing (see next section).

---

### Oversized attachment warning

**Symptom:** Log message: `Attachment size X.X MB exceeds limit of 25 MB —
dropping Excel files.`

The combined PDF + Excel size exceeded `MAX_ATTACHMENT_SIZE_MB` (default 25 MB,
set in `.env`). The email was sent with PDFs only. The email body notes the
omission.

To increase the limit, add to `/opt/vuln-reporting/shared/.env`:

```
MAX_ATTACHMENT_SIZE_MB=40
```

Then restart the service:

```bash
sudo systemctl restart vuln-reports
```

---

### Scheduler not firing at expected time

**Symptom:** Reports are not sent at the scheduled time.

**Check these things:**

1. Confirm the server's local time and timezone:

   ```bash
   timedatectl
   date
   ```

   The scheduler uses server local time. If the server is in UTC but
   `delivery_config.yaml` uses local business hours, jobs will fire at the
   wrong wall-clock time.

2. Check the scheduler log for the job being scheduled:

   ```bash
   sudo journalctl -u vuln-reports | grep "Scheduled:"
   ```

3. Confirm the service is running:

   ```bash
   sudo systemctl status vuln-reports
   ```

4. Validate the configuration is correct:

   ```bash
   cd /opt/vuln-reporting/current
   sudo -u vuln-reports .venv/bin/python run_all.py --dry-run
   ```

5. **If using cron instead of the daemon:** confirm `scheduler.py --mode run-due`
   is running every 5–10 minutes and that the cron process runs as the
   `vuln-reports` user. Check the cron log:

   ```bash
   tail -f /opt/vuln-reporting/shared/logs/run-due.cron.log
   ```

---

### Missing VPR scores

**Symptom:** In report output or logs: `vpr_score is None for N vulnerabilities`.

Not all Tenable plugins have a VPR score. When `vpr_score` is absent, the
suite falls back to Tenable's native severity field (Critical/High/Medium/Low).
This is by design and does not indicate an error.

To identify which vulnerabilities lack VPR scores, open the Excel output and
filter the `vpr_score` column for blank cells.

---

### Python virtual environment issues

**Symptom:** `ModuleNotFoundError` or packages appear missing even after
`pip install`.

The most common cause is accidentally using the system Python instead of the
virtual environment Python. Under the v1.2 layout, the venv is inside the
release directory at `/opt/vuln-reporting/current/.venv/`. All service and cron
invocations must use:

```
/opt/vuln-reporting/current/.venv/bin/python
```

If you need to rebuild the venv for the current release:

```bash
sudo -u vuln-reports bash
cd /opt/vuln-reporting/current
rm -rf .venv
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
exit
```

Then restart the service:

```bash
sudo systemctl restart vuln-reports
```

---

### Delivery log database locked

**Symptom:** `sqlite3.OperationalError: database is locked`

This can happen if two processes try to write to `delivery_log.db`
simultaneously. The database uses WAL (Write-Ahead Log) mode which handles
concurrent reads well, but concurrent writes can briefly contend.

**Resolution:**

1. Check for any stuck Python processes:

   ```bash
   ps aux | grep python
   ```

2. If you see orphaned processes from a previous failed run, kill them:

   ```bash
   sudo kill <PID>
   ```

3. If the lock persists after all Python processes are stopped:

   ```bash
   ls -la /opt/vuln-reporting/shared/logs/delivery_log.db*
   ```

   Delete any `-wal` or `-shm` files (only when no Python processes are running):

   ```bash
   rm /opt/vuln-reporting/shared/logs/delivery_log.db-wal
   rm /opt/vuln-reporting/shared/logs/delivery_log.db-shm
   ```

---

## File Reference

### Project layout (v1.2 symlink structure)

```
/opt/vuln-reporting/
  current/                          # Symlink → active release (e.g. releases/v1.2.0/)
    run_all.py                      # Master report runner
    scheduler.py                    # Three-mode scheduler (daemon / run-due / manual)
    config.py                       # SLA windows, severity colours, shared constants
    tenable_client.py               # Authenticated Tenable API client factory
    .venv/                          # Per-release Python virtual environment
    data/fetchers.py                # All Tenable API fetch functions
    reports/                        # Per-slug report scripts
    exporters/                      # Excel, PDF, chart exporters
    delivery/                       # email_sender, delivery_log, email_template
    utils/                          # sla_calculator, tag_helper, formatters
    scripts/warm_cache.py           # Cache pre-warmer (run before report groups)
    deploy/
      vuln-reports.service          # systemd unit file
      crontab.example               # Drop-in crontab (cron alternative to daemon)
    templates/report_email.html     # Jinja2 email template
    requirements.txt                # Pinned Python dependency versions
  shared/                           # Persistent data that survives releases
    .env                            # Credentials and overrides (never commit)
    delivery_config.yaml            # LEGACY single-file config (dual-source cutover window only)
    delivery_config.schema.yaml     # JSON Schema for YAML validation
    config/                         # Directory-mode config, copied from a reviewed private-repo commit
      contacts.yaml                 # Named contact groups + defaults.analyst_mailbox
      deliveries.d/                 # Per-team delivery files (<team>.yaml), globbed + merged
        <team>.yaml
      .config-provenance.json       # D-03 sidecar: source commit SHA + UTC timestamp + sha256
                                     # (written by scripts/stamp_config_provenance.py stamp)
    logs/
      app.log                       # Application-level log (rotating)
      scheduler.log                 # Scheduler-level log (rotating)
      delivery_log.db               # SQLite delivery audit log
      warm_cache.log                # warm_cache.py rotating log
    data/cache/                     # Parquet cache files (reused within run date)
    output/                         # Generated reports (timestamped sub-folders)
  releases/                         # Versioned release directories
    v1.2.0/ → (current points here)
    v1.1.0/ → (previous release, kept for rollback)
```

**Dual-source coexistence during the cutover window (QUAL-07 SC4):** both
`shared/config/` (directory-mode, reviewed-repo-sourced) AND the legacy
`shared/delivery_config.yaml` are present on disk at the same time. The
loader prefers directory mode; on any directory-mode resolution/schema
failure it automatically falls back to the legacy file and logs a WARNING
naming the active source (D-04). `run_all.py --dry-run` echoes which source
is currently active (D-05) — see [Delivery Config — Reviewed-Repo
Cutover](#delivery-config--reviewed-repo-cutover) for the full procedure.
The `.config-provenance.json` sidecar lives inside `shared/config/` and is
never present for the legacy file (D-03 applies only to the reviewed
directory-mode config).

---

### Files safe to edit without developer involvement

| File | What you can change |
| ---- | ------------------- |
| `shared/.env` | Add or rotate credentials; adjust `MAX_ATTACHMENT_SIZE_MB` |
| `current/config.py` | `SLA_DAYS` values only (requires service restart) |
| `current/deploy/vuln-reports.service` | `WorkingDirectory`, `User`, `EnvironmentFile` if paths change |

**`shared/delivery_config.yaml` and `shared/config/` (contacts + deliveries)
are NOT server-side hand-edits.** Recipients, groups, and schedules are
changed in the private corporate config repo via PR → CODEOWNERS review →
CI gate → merge, then the merged commit is manually copied to the server
and stamped with `scripts/stamp_config_provenance.py`. See [Delivery
Config — Reviewed-Repo Cutover](#delivery-config--reviewed-repo-cutover).
This table intentionally no longer lists delivery config as a direct-edit
file — that is the change this cutover makes.

---

### Where outputs are saved

Every report run creates a timestamped sub-folder:

```
/opt/vuln-reporting/shared/output/
  2026-03-23_07-00_Finance-Team-Weekly-Report/
    sla_remediation/
      sla_remediation_report_2026-03-23.pdf
      sla_remediation_report_2026-03-23.xlsx
    patch_compliance/
      ...
```

**Suggested retention policy:**

| Folder age  | Action                                          |
| ----------- | ----------------------------------------------- |
| < 90 days   | Keep in place                                   |
| 90–180 days | Archive to cold storage (zip + move off server) |
| > 180 days  | Delete                                          |

Automate cleanup with a weekly cron job:

```bash
find /opt/vuln-reporting/shared/output -maxdepth 1 -type d -mtime +180 -exec rm -rf {} \;
```

---

### Key log files

| Log file | Written by | Contains |
| -------- | ---------- | -------- |
| `shared/logs/app.log` | `run_all.py`, report scripts | Fetcher progress, report generation, module errors |
| `shared/logs/scheduler.log` | `scheduler.py` | Job scheduling, hot-reload events, group run summaries |
| `shared/logs/warm_cache.log` | `scripts/warm_cache.py` | Cache pre-fetch progress and exit status |
| `shared/logs/delivery_log.db` | `delivery/delivery_log.py` | SQLite audit log: group, recipients, status, duration |
| `shared/logs/warm_cache.cron.log` | cron stdout redirect | cron-level output when using `deploy/crontab.example` |
| `shared/logs/run-due.cron.log` | cron stdout redirect | cron-level output when using `deploy/crontab.example` |

---

## Local E2E Test Suite

Offline pytest suite that validates reports before every commit (no Tenable, no VM).
Tests live in `tests/` and run fully offline: synthetic data is injected through a
seeded parquet cache, and outbound email is captured via a faked SMTP transport.

**One-time setup (per checkout):**

    .venv/Scripts/python -m pip install -r requirements-dev.txt   # Windows
    git config core.hooksPath .githooks

**Run manually:**

    python -m pytest             # whole suite, parallel (-n auto)
    python -m pytest -m unit     # Layer 1 only (per-module contract)
    python -m pytest -m content  # Layer 2 only (exact values)
    python -m pytest -m e2e      # Layer 3 only (run_group + SMTP capture)

**Pre-commit gate:** once `core.hooksPath` is set, `.githooks/pre-commit` runs the
full suite on every `git commit` (using the project `.venv` interpreter if present).
Emergency bypass (use sparingly — preferred over `--no-verify`, which skips all hooks):

    VULN_E2E_SKIP=1 git commit -m "..."

**Eyeball a delivered email:** captured messages are written to
`output/test-eml/message_NNN.eml` — open in Outlook / a browser.

**Before your first PR (future contributors):** run the one-time setup above, then
`python -m pytest` must be green before pushing. CI is intentionally not configured;
the maintainer/reviewer runs the suite locally.

---

_This document covers the operational aspects of the suite. For installation,
upgrades, and rollback see [DEPLOYMENT.md](DEPLOYMENT.md). For architecture
details, API integration notes, and development guidelines, see `CLAUDE.md`._
