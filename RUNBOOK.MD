# Vulnerability Management Reporting Suite — Runbook

**Audience:** Security Analysts with limited Python experience
**Platform:** RHEL 9 (also applicable to other RHEL/CentOS derivatives)
**Project directory:** `/opt/vuln-reporting/`

---

## Table of Contents

1. [RHEL 9 Server Deployment (Fresh Install)](#section-1--rhel-9-server-deployment-fresh-install)
2. [Cron Job Setup (Alternative to systemd)](#section-2--cron-job-setup-alternative-to-systemd)
3. [Day-to-Day Operations](#section-3--day-to-day-operations)
4. [Scheduler Management](#section-4--scheduler-management)
5. [Troubleshooting](#section-5--troubleshooting)
6. [File Reference](#section-6--file-reference)
7. [Contact and Escalation](#section-7--contact-and-escalation)

---

## Section 1 — RHEL 9 Server Deployment (Fresh Install)

Follow these steps in order on a freshly provisioned RHEL 9 server.
Each step includes the exact commands to run.

---

### Step 1 — Install Python 3.10+

Check what Python version is already installed:

```bash
python3 --version
```

RHEL 9 ships with Python 3.9. Install Python 3.11 from the AppStream repository:

```bash
sudo dnf install -y python3.11 python3.11-pip python3.11-devel
```

Confirm the version:

```bash
python3.11 --version
```

---

### Step 2 — Install required system packages

The PDF generation library (WeasyPrint) needs C libraries to build:

```bash
sudo dnf install -y gcc libffi-devel openssl-devel cairo-devel pango-devel
```

> **Why these packages?** WeasyPrint renders HTML to PDF using the Cairo/Pango
> graphics stack. Without these libraries, `pip install weasyprint` will fail
> with a compilation error.

---

### Step 3 — Configure SELinux

RHEL 9 runs SELinux in enforcing mode by default. The scheduler needs to:
- Make outbound HTTPS connections to Tenable's cloud API
- Make outbound SMTP connections (port 587 or 465)
- Write files to `output/`, `logs/`, and `data/cache/`

Allow outbound network connections for the service account:

```bash
sudo setsebool -P httpd_can_network_connect on
```

If you see `Permission denied` errors for file writes in journald logs, restore
the SELinux context on the project directory:

```bash
sudo restorecon -Rv /opt/vuln-reporting/
```

If that does not resolve the issue, check what SELinux is blocking:

```bash
sudo ausearch -c python3.11 --raw | audit2allow -M vuln-reports-local
sudo semodule -i vuln-reports-local.pp
```

> **Note:** Run the `ausearch` command after the failure occurs so the audit
> log contains the relevant denial. This generates a minimal policy that
> allows only the specific operations the service needs.

---

### Step 4 — Create a dedicated service account

Never run the scheduler as root. Create a service account with no login shell:

```bash
sudo useradd --system --no-create-home --shell /sbin/nologin vuln-reports
```

---

### Step 5 — Deploy the project files

Copy or clone the project to `/opt/vuln-reporting/`:

```bash
# Option A — git clone (if you have a repository)
sudo git clone https://your-repo-url/vuln-reporting.git /opt/vuln-reporting

# Option B — copy from a local machine using scp
scp -r /local/path/to/vuln-reporting user@server:/opt/
```

Set correct ownership so the service account can read and write all files:

```bash
sudo chown -R vuln-reports:vuln-reports /opt/vuln-reporting
sudo chmod -R 750 /opt/vuln-reporting
```

---

### Step 6 — Create a Python virtual environment

Switch to the service account to create the virtual environment:

```bash
sudo -u vuln-reports bash
cd /opt/vuln-reporting
python3.11 -m venv .venv
source .venv/bin/activate
```

Install all Python dependencies:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Exit back to your own account when done:

```bash
exit
```

---

### Step 7 — Configure credentials

Copy the example `.env` file and fill in your real values:

```bash
sudo -u vuln-reports cp /opt/vuln-reporting/.env.example /opt/vuln-reporting/.env
sudo -u vuln-reports nano /opt/vuln-reporting/.env
```

The `.env` file must contain at minimum:

```
TVM_ACCESS_KEY=<your Tenable access key>
TVM_SECRET_KEY=<your Tenable secret key>
TVM_URL=https://cloud.tenable.com

SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=reports@yourcompany.com
SMTP_PASSWORD=<your SMTP password>
SMTP_FROM_ADDRESS=reports@yourcompany.com
SMTP_FROM_NAME=Vulnerability Management Reports
```

Restrict permissions on the `.env` file (it contains passwords):

```bash
sudo chmod 600 /opt/vuln-reporting/.env
```

---

### Step 8 — Verify Tenable connectivity

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting && source .venv/bin/activate && python tenable_client.py"
```

Expected output: `[INFO] Tenable connection verified.` (or similar). If you see
an authentication error, double-check `TVM_ACCESS_KEY` and `TVM_SECRET_KEY`
in your `.env` file.

---

### Step 9 — Discover available tags

Tags are the way you scope reports to a business unit, environment, or other
asset grouping. List all tags configured in your Tenable environment:

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting && source .venv/bin/activate && python utils/tag_helper.py --list-tags"
```

Note the exact category names and values — you will need them when configuring
`delivery_config.yaml` in the next step.

---

### Step 10 — Configure delivery groups

Edit `delivery_config.yaml` to define who gets what reports and when:

```bash
sudo -u vuln-reports nano /opt/vuln-reporting/delivery_config.yaml
```

A minimal working example:

```yaml
groups:
  - name: "Security Team — Weekly Full Report"
    description: "All reports, all assets, every Monday morning"
    schedule:
      frequency: weekly
      day_of_week: monday
      time: "07:00"
    filters: {}
    reports:
      - executive_kpi
      - sla_remediation
      - asset_risk
    email:
      subject: "Weekly Vulnerability Report"
      recipients:
        - analyst@yourcompany.com
      cc: []
      reply_to: security@yourcompany.com
```

See [Section 3](#section-3--day-to-day-operations) for detailed instructions on
adding and modifying groups.

---

### Step 11 — Validate the configuration

Run a dry-run to catch any mistakes before going live. This checks the YAML
structure and confirms all required `.env` variables are present. **No API
calls are made and no files are written.**

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting && source .venv/bin/activate && python run_all.py --dry-run"
```

Expected output: a table listing all groups with a green `OK` status for each.
If any show `FAIL`, the error message will tell you exactly what to fix.

---

### Step 12 — Run your first report manually (no email)

Before enabling automated delivery, verify that reports generate correctly:

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting && source .venv/bin/activate && python run_all.py --group 'Security Team — Weekly Full Report' --no-email"
```

This will:
1. Connect to Tenable and fetch vulnerability data
2. Generate PDF, Excel, and chart files
3. Save everything to `output/YYYY-MM-DD_HH-MM_<group-name>/`
4. Skip the email step

Review the output files in `output/` to confirm the data looks correct.

---

### Step 13 — Send a test email to yourself

Once the reports look good, do a test send to your own address:

```bash
sudo -u vuln-reports bash -c "cd /opt/vuln-reporting && source .venv/bin/activate && python run_all.py --group 'Security Team — Weekly Full Report' --recipients your.email@yourcompany.com"
```

Check your inbox (and spam folder). The email should contain:
- A formatted HTML body with KPI tiles
- PDF report(s) attached
- Excel report(s) attached

---

### Step 14 — Install and enable the systemd service

```bash
sudo cp /opt/vuln-reporting/deploy/vuln-reports.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vuln-reports
sudo systemctl start vuln-reports
sudo systemctl status vuln-reports
```

Expected output of `status`: `active (running)` with no errors.

---

### Step 15 — Verify the scheduler is running

Watch the live log output for 30 seconds:

```bash
sudo journalctl -u vuln-reports -f
```

You should see startup messages and the list of scheduled groups. Press
`Ctrl+C` to stop watching.

---

## Section 2 — Cron Job Setup (Alternative to systemd)

Use this approach if you prefer not to run a persistent daemon, or if your
server does not use systemd.

### How it works

Instead of an always-on process, cron calls `scheduler.py --mode run-due`
every 10 minutes. The script checks whether any group is due at that moment
and runs it, then exits.

### Add the cron job

Edit the crontab for the `vuln-reports` service account:

```bash
sudo -u vuln-reports crontab -e
```

Add this line (adjust the path if your project is not in `/opt/vuln-reporting/`):

```cron
*/10 * * * * cd /opt/vuln-reporting && /opt/vuln-reporting/.venv/bin/python scheduler.py --mode run-due >> /opt/vuln-reporting/logs/cron.log 2>&1
```

**What each part means:**

| Part | Meaning |
|------|---------|
| `*/10 * * * *` | Run every 10 minutes, every hour, every day |
| `cd /opt/vuln-reporting` | Switch to the project directory first |
| `/opt/vuln-reporting/.venv/bin/python` | Use the virtual environment's Python |
| `scheduler.py --mode run-due` | Check if any group is due and run it |
| `>> .../logs/cron.log 2>&1` | Append all output (stdout and stderr) to the cron log |

### Verify cron is working

After the cron job has had a chance to run at least once:

```bash
tail -f /opt/vuln-reporting/logs/cron.log
```

You should see entries like:
```
2026-03-23 07:00:07 [INFO] — No groups are due at Sunday 07:00 — exiting.
```

And when a group is actually due:
```
2026-03-23 07:00:07 [INFO] — 1 group(s) due at Monday 07:00: ['Security Team']
2026-03-23 07:01:34 [INFO] — Group 'Security Team' done in 87.2s (status=success)
```

---

## Section 3 — Day-to-Day Operations

---

### How to add a recipient to an existing group

1. Open `delivery_config.yaml` in a text editor:
   ```bash
   nano /opt/vuln-reporting/delivery_config.yaml
   ```

2. Find the group by its `name` field. Add the new address to the
   `recipients` list:
   ```yaml
   email:
     recipients:
       - existing@company.com
       - newperson@company.com    # ← add this line
   ```

3. Save the file. The scheduler's hot-reload picks up the change within
   5 minutes — no restart needed.

4. Verify the change is valid:
   ```bash
   python run_all.py --dry-run
   ```

---

### How to remove a recipient

Delete or comment out the address from the `recipients` list. Make sure at
least one address remains — the dry-run will warn you if `recipients` is empty.

---

### How to add a new delivery group

Add a new entry to the `groups` list in `delivery_config.yaml`. Copy an
existing group as a starting point and change the values:

```yaml
  - name: "Finance Team — Weekly Report"
    description: "SLA and patch status for Finance business unit"
    schedule:
      frequency: weekly
      day_of_week: tuesday    # monday | tuesday | wednesday | thursday | friday | saturday | sunday
      time: "08:00"           # 24-hour, server local time
    filters:
      tag_category: "Business Unit"   # must match exact Tenable tag category name
      tag_value: "Finance"            # must match exact Tenable tag value
    reports:
      - sla_remediation         # choose from: executive_kpi, sla_remediation,
      - patch_compliance        # asset_risk, patch_compliance, trend_analysis,
      - asset_risk              # plugin_cve
    email:
      subject: "Finance BU — Weekly Vulnerability Report"
      recipients:
        - finance-it@company.com
      cc:
        - security@company.com
      reply_to: security@company.com
```

Run `python run_all.py --dry-run` to validate before the next scheduled run.

---

### How to change a report schedule

Edit the `schedule` block for the relevant group:

```yaml
schedule:
  frequency: weekly
  day_of_week: wednesday    # changed from monday
  time: "09:30"             # changed from 07:00
```

The scheduler picks up the change within 5 minutes (hot-reload).

---

### How to change SLA windows

SLA thresholds are defined in `config.py`. Open it and edit the `SLA_DAYS`
dictionary:

```bash
nano /opt/vuln-reporting/config.py
```

```python
SLA_DAYS: dict[str, int] = {
    "critical": 15,     # days to remediate a Critical vulnerability
    "high":     30,
    "medium":   90,
    "low":      180,
}
```

> **Important:** Changing SLA windows affects all reports and all delivery
> groups immediately. This change requires a developer review if your
> organisation has a formally agreed SLA policy.

---

### How to trigger a report right now

```bash
cd /opt/vuln-reporting
source .venv/bin/activate
python run_all.py --group "Finance Team — Weekly Report"
```

This generates reports and sends the email to the configured recipients,
regardless of the scheduled day and time.

---

### How to generate reports without sending email

```bash
python run_all.py --group "Finance Team — Weekly Report" --no-email
```

Output files are saved to `output/` as usual. Nothing is sent.

---

### How to send to a test address before a live run

```bash
python run_all.py --group "Finance Team — Weekly Report" --recipients your.name@company.com
```

The email goes to `your.name@company.com` instead of the configured recipients.
The configured `cc` list is also cleared. This is safe to run while the daemon
is also running.

---

### How to check what ran and when

Use the delivery log inspector:

```bash
# Show the 20 most recent deliveries
python delivery/delivery_log.py --recent 20

# Show deliveries for a specific group
python delivery/delivery_log.py --group "Finance Team — Weekly Report"

# Show deliveries within a date range
python delivery/delivery_log.py --from 2026-03-01 --to 2026-03-31
```

---

### How to check for failures

```bash
python delivery/delivery_log.py --failures
```

This lists every delivery attempt that resulted in `failed` or `partial`
status, with the error message included.

---

## Section 4 — Scheduler Management

---

### Start, stop, restart, and check status

```bash
# Start the service
sudo systemctl start vuln-reports

# Stop the service (waits up to 120 seconds for any running job to finish)
sudo systemctl stop vuln-reports

# Restart the service
sudo systemctl restart vuln-reports

# Check whether it is running
sudo systemctl status vuln-reports
```

---

### How changes to delivery_config.yaml take effect

The daemon automatically checks for changes to `delivery_config.yaml`
**every 5 minutes**. When a change is detected:

1. All currently-scheduled group jobs are removed.
2. The updated config is loaded.
3. All weekly groups are rescheduled with the new settings.

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
/opt/vuln-reporting/logs/scheduler.log
```

---

### Running a manual trigger while the daemon is also running

This is safe. The daemon and manual CLI runs are completely independent:

- The daemon uses APScheduler to fire jobs on a schedule.
- A manual run (`python run_all.py --group "..."`) is a separate process.
- Both can run at the same time without interfering.

The only shared resource is the parquet cache (`data/cache/`). Two runs with
the same `run_id` (same calendar date) will share cached data, which is
intentional and reduces API load.

---

## Section 5 — Troubleshooting

---

### Tenable authentication failure

**Symptom:** Error message: `Authentication failed` or `401 Unauthorized`
when starting the service or running reports.

**Check these things:**

1. Confirm `TVM_ACCESS_KEY` and `TVM_SECRET_KEY` are correct in `.env`:
   ```bash
   # Print the variable names present (never prints values)
   grep -E "^TVM_" /opt/vuln-reporting/.env | cut -d= -f1
   ```

2. Test the connection manually:
   ```bash
   cd /opt/vuln-reporting && source .venv/bin/activate
   python tenable_client.py
   ```

3. Verify the API keys are active in the Tenable console:
   **Settings → My Account → API Keys**

4. Check that `TVM_URL` points to the correct endpoint
   (default: `https://cloud.tenable.com`).

---

### SMTP failure

**Symptom:** Reports are generated but email is not sent. The delivery log
shows `status: failed` with an SMTP error message.

**Check these things:**

1. Verify SMTP credentials:
   ```bash
   python run_all.py --group "Your Group" --no-email
   ```
   If this succeeds, the problem is SMTP-specific.

2. Check the delivery log for the error message:
   ```bash
   python delivery/delivery_log.py --failures
   ```

3. Common SMTP issues:
   - Wrong `SMTP_USERNAME` or `SMTP_PASSWORD` in `.env`
   - Port 587 blocked by a firewall — try `SMTP_PORT=465` and `SMTP_USE_SSL=true`
   - Office 365: ensure the account has SMTP AUTH enabled in the Microsoft
     365 admin centre

---

### Report generated but email not received

1. Check the delivery log to confirm delivery was attempted and succeeded:
   ```bash
   python delivery/delivery_log.py --recent 5
   ```
   If `status` shows `success`, the email was accepted by the SMTP server.

2. Ask the recipient to check their spam/junk folder.

3. If status shows `partial`, Excel files were omitted due to size. The email
   was still sent — only the Excel attachments are missing.

---

### Oversized attachment warning

**Symptom:** Log shows `Attachment size X.X MB exceeds limit of 25 MB —
dropping Excel files.`

This means the combined PDF + Excel size exceeded the configured limit
(`MAX_ATTACHMENT_SIZE_MB` in `.env`, default 25 MB). The email was still sent
with PDF attachments only. The email body contains a note explaining this.

**To increase the limit:**

```bash
# Add to .env:
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
   The scheduler uses server local time. If the server is in UTC but your
   `delivery_config.yaml` uses local business hours, the jobs will fire at
   the wrong wall-clock time.

2. To run on UTC, set `time: "07:00"` to the UTC equivalent of your intended
   local time.

3. Check the scheduler logs for the job being scheduled:
   ```bash
   sudo journalctl -u vuln-reports | grep "Scheduled:"
   ```

4. Verify the service is running:
   ```bash
   sudo systemctl status vuln-reports
   ```

5. Run a manual dry-run to confirm the config is valid:
   ```bash
   python run_all.py --dry-run
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

### SELinux blocking network or file writes

**Symptom:** `Permission denied` errors in the log despite correct file
permissions.

1. Check the SELinux audit log for denials:
   ```bash
   sudo ausearch -m avc -ts recent
   ```

2. If you see denials related to `python3.11` making network connections:
   ```bash
   sudo setsebool -P httpd_can_network_connect on
   ```

3. If you see denials for file writes to `output/` or `logs/`:
   ```bash
   sudo restorecon -Rv /opt/vuln-reporting/
   ```

4. For anything more specific, generate a targeted policy module:
   ```bash
   sudo ausearch -c python3.11 --raw | audit2allow -M vuln-reports-policy
   sudo semodule -i vuln-reports-policy.pp
   ```

---

### Python virtual environment issues

**Symptom:** `ModuleNotFoundError` or packages appear missing even after
`pip install`.

The most common cause is accidentally using the system Python instead of the
virtual environment Python.

Recreate the virtual environment from scratch:

```bash
sudo -u vuln-reports bash
cd /opt/vuln-reporting
rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
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

1. Check if there are any stuck Python processes:
   ```bash
   ps aux | grep python
   ```

2. If you see orphaned processes from a previous failed run, kill them:
   ```bash
   sudo kill <PID>
   ```

3. If the lock persists after all Python processes are stopped:
   ```bash
   ls -la /opt/vuln-reporting/logs/delivery_log.db*
   ```
   Delete any `-wal` or `-shm` files (only when no Python processes are running):
   ```bash
   rm /opt/vuln-reporting/logs/delivery_log.db-wal
   rm /opt/vuln-reporting/logs/delivery_log.db-shm
   ```

---

## Section 6 — File Reference

### Project structure

| File / Directory | Description | Safe to edit? |
|-----------------|-------------|---------------|
| `.env` | Credentials and overrides (never commit) | Yes — add/change values |
| `.env.example` | Template for onboarding new deployments | No |
| `config.py` | SLA windows, severity colours, shared constants | SLA values only |
| `tenable_client.py` | Authenticated Tenable API client factory | No |
| `delivery_config.yaml` | Recipient groups, schedules, report selections | **Yes — primary ops file** |
| `delivery_config.schema.yaml` | JSON Schema for YAML validation in editors/CI | No |
| `scheduler.py` | Three-mode scheduler (daemon / run-due / manual) | No |
| `run_all.py` | Master report runner; defines `run_group()` | No |
| `data/fetchers.py` | All Tenable API fetch functions with parquet caching | No |
| `utils/sla_calculator.py` | SLA status calculations applied to all reports | No |
| `utils/tag_helper.py` | Tag discovery and asset filtering helpers | No |
| `utils/formatters.py` | Formatting utilities (dates, labels, file names) | No |
| `exporters/chart_exporter.py` | Matplotlib and Plotly chart generation | No |
| `exporters/excel_exporter.py` | Excel file builder (openpyxl) | No |
| `exporters/pdf_exporter.py` | PDF builder (WeasyPrint HTML→PDF) | No |
| `reports/executive_kpi.py` | Executive KPI Dashboard report | No |
| `reports/sla_remediation.py` | SLA & Remediation Tracking report | No |
| `reports/asset_risk.py` | Asset Risk Scoring report | No |
| `reports/patch_compliance.py` | Patch Compliance & Vulnerability Age report | No |
| `reports/trend_analysis.py` | Trend Analysis over time report | No |
| `reports/plugin_cve.py` | Plugin / CVE Breakdown report | No |
| `delivery/email_sender.py` | SMTP delivery with attachments and inline charts | No |
| `delivery/email_template.py` | Jinja2 email body renderer | No |
| `delivery/delivery_log.py` | SQLite delivery audit log + CLI inspector | No |
| `templates/report_email.html` | Jinja2 HTML email template | No (design changes require developer) |
| `deploy/vuln-reports.service` | systemd unit file | Yes — update paths/account name |
| `requirements.txt` | Pinned Python dependency versions | No |
| `logs/` | Application logs, scheduler logs, delivery_log.db | Do not delete manually |
| `output/` | Generated reports (timestamped sub-folders per run) | Safe to archive/delete old folders |
| `data/cache/` | Parquet cache files (reused within the same run date) | Safe to delete — will be rebuilt |

---

### Files safe to edit without developer involvement

- **`.env`** — add or rotate credentials
- **`delivery_config.yaml`** — add/remove groups, change recipients, adjust schedules
- **`config.py`** — change `SLA_DAYS` values only (all other values require review)
- **`deploy/vuln-reports.service`** — update `WorkingDirectory`, `User`, `EnvironmentFile` if you change install paths

---

### Where outputs are saved

Every report run creates a timestamped sub-folder:

```
output/
  2026-03-23_07-00_Security-Team-Weekly-Full-Report/
    executive_kpi/
      executive_kpi_report_2026-03-23.pdf
      executive_kpi_report_2026-03-23.xlsx
      charts/
        bar_open_by_severity.png
        kpi_gauge_critical.png
    sla_remediation/
      ...
```

**Suggested retention policy:**

| Folder age | Action |
|-----------|--------|
| < 90 days | Keep in place |
| 90–180 days | Archive to cold storage (zip + move off server) |
| > 180 days | Delete |

Automate cleanup with a weekly cron job:

```bash
find /opt/vuln-reporting/output -maxdepth 1 -type d -mtime +180 -exec rm -rf {} \;
```

---

## Section 7 — Contact and Escalation

Before escalating to the development team or opening a support ticket,
collect the following information:

**1. Python version**
```bash
/opt/vuln-reporting/.venv/bin/python --version
```

**2. The error message**
```bash
sudo journalctl -u vuln-reports --since "1 hour ago" | grep -E "ERROR|CRITICAL|Exception|Traceback"
```

**3. The delivery log entry for the failed run**
```bash
cd /opt/vuln-reporting && source .venv/bin/activate
python delivery/delivery_log.py --failures
```
Copy the relevant row (group name, timestamp, error message).

**4. Which group failed**
Exact name as it appears in `delivery_config.yaml`.

**5. Which `.env` variable names are present** (never include values)
```bash
grep -E "^[A-Z_]+=." /opt/vuln-reporting/.env | cut -d= -f1
```

**6. Whether the issue is reproducible manually**
```bash
python run_all.py --group "Failing Group Name" --no-email
```
Note whether this succeeds or fails, and the full output.

---

*This document covers the operational aspects of the Vulnerability Management
Reporting Suite.  For architecture details, API integration notes, and
development guidelines, see `CLAUDE.md` in the project root.*
