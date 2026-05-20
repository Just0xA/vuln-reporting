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
3. [Scheduler Management](#scheduler-management)
4. [Operational Cron Schedule](#operational-cron-schedule)
5. [Troubleshooting (Runtime)](#troubleshooting-runtime)
6. [File Reference](#file-reference)

---

## Installation & Upgrades

This runbook covers **running and operating** an already-installed suite.

To install the suite from scratch, upgrade to a new release, or roll back to a
previous release, see **[DEPLOYMENT.md](DEPLOYMENT.md)**. That document owns
all server setup, tarball install, venv build, systemd unit installation, and
update procedures.

---

## Day-to-Day Operations

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

---

### How to add a recipient to an existing group

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
`management_summary`, `vuln_export`, `board_summary`, `unscanned_assets`,
`composed_report`.

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

If you prefer not to run the systemd daemon, you can use cron to invoke
`scheduler.py --mode run-due` on a regular cadence. **Use cron OR the daemon —
not both at the same time for scheduled delivery.**

The ready-to-use crontab file is at [`deploy/crontab.example`](deploy/crontab.example).
Install it as the `vuln-reports` user:

```bash
sudo -u vuln-reports crontab - < /opt/vuln-reporting/current/deploy/crontab.example
```

Review and adjust the timing before installing (see comments inside the file).

---

### How cron-based scheduling works

`scheduler.py --mode run-due` reads `delivery_config.yaml`, checks whether any
group's schedule matches the current time within a **±10-minute window**, runs
matching groups, and exits. It must be invoked **every 5–10 minutes** by cron
so it can catch any scheduled group within that window.

---

### Warm-cache cron line

`warm_cache.py` pre-fetches the four Tenable datasets
(vulnerabilities, fixed vulnerabilities, assets, recast rules) into parquet
files so that the report run hits `[CACHE HIT]` instead of fetching live.

Two timing rules govern when to schedule this line:

1. **≥30 minutes before the earliest report group.** The fetch must complete
   before the report run starts. With a 07:00 earliest group, schedule at
   06:15 or earlier.

2. **Never near midnight.** Cache folders are named by server local date
   (`YYYY-MM-DD`). If `warm_cache.py` fires at 23:55 and the report runs at
   00:05, the cache folder name changes between the two and the report run
   will not find the cached data — it will re-fetch everything.

The example file schedules warm-cache at **06:15** (15 minutes past 6 AM),
which satisfies both rules assuming a 07:00 earliest group. Adjust if your
earliest group is earlier or the fetch takes longer than 30 minutes on your
dataset.

---

### Log rotation guidance

`warm_cache.py` and `scheduler.py` write their own rotating logs to
`/opt/vuln-reporting/shared/logs/`. The cron lines in `deploy/crontab.example`
also redirect cron-level stdout/stderr to separate `.cron.log` files in that
directory. Those cron log files are NOT rotated automatically — configure them
in `logrotate` or truncate them periodically:

```bash
# /etc/logrotate.d/vuln-reports-cron
/opt/vuln-reporting/shared/logs/warm_cache.cron.log
/opt/vuln-reporting/shared/logs/run-due.cron.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

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
python3.11 -m venv .venv
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
    delivery_config.yaml            # Recipient groups, schedules, report selections
    delivery_config.schema.yaml     # JSON Schema for YAML validation
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

---

### Files safe to edit without developer involvement

| File | What you can change |
| ---- | ------------------- |
| `shared/.env` | Add or rotate credentials; adjust `MAX_ATTACHMENT_SIZE_MB` |
| `shared/delivery_config.yaml` | Add/remove groups, change recipients, adjust schedules |
| `current/config.py` | `SLA_DAYS` values only (requires service restart) |
| `current/deploy/vuln-reports.service` | `WorkingDirectory`, `User`, `EnvironmentFile` if paths change |

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

_This document covers the operational aspects of the suite. For installation,
upgrades, and rollback see [DEPLOYMENT.md](DEPLOYMENT.md). For architecture
details, API integration notes, and development guidelines, see `CLAUDE.md`._
