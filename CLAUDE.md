# CLAUDE.MD — Vulnerability Management Reporting Suite (pyTenable)

## Project Overview

Build a modular Python reporting suite that connects to **Tenable.io / Tenable Vulnerability Management** via the `pyTenable` SDK and produces meaningful, audience-specific vulnerability management reports. Reports are segmented by **Tenable Tags/Labels**, support three distinct audience formats, and are exported as **CSV/Excel, PDF, and matplotlib/plotly charts**.

The suite supports **scheduled and on-demand execution**, with a YAML-driven delivery system that emails the right reports to the right recipients — each group with its own filters, report selection, frequency, and recipient list that can be updated without touching code.

---

## Technology Stack

- **Python 3.10+**
- **pyTenable** — primary SDK for all Tenable API calls
- **pandas** — data manipulation and aggregation
- **openpyxl** — Excel (.xlsx) output with formatting
- **matplotlib + plotly** — charts and visualizations
- **reportlab or weasyprint** — PDF generation
- **python-dotenv** — credential management via `.env`
- **PyYAML** — recipient group and schedule configuration
- **APScheduler** — embedded scheduler (also cron/Task Scheduler compatible)
- **smtplib + email.mime** — SMTP email delivery (Office 365, Gmail, etc.)
- **Jinja2** — HTML email body templating
- **tenacity** — API retry/backoff
- **rich** — CLI progress/status output

---

## Credential Management

All credentials must be loaded exclusively from a `.env` file using `python-dotenv`. Never hardcode credentials.

```
# .env
TVM_ACCESS_KEY=your_access_key_here
TVM_SECRET_KEY=your_secret_key_here
TVM_URL=https://cloud.tenable.com

# SMTP
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=reports@yourcompany.com
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_ADDRESS=reports@yourcompany.com
SMTP_FROM_NAME=Vulnerability Management Reports
```

Instantiate the Tenable client like this:

```python
from tenable.io import TenableIO
from dotenv import load_dotenv
import os

load_dotenv()
tio = TenableIO(
    access_key=os.getenv("TVM_ACCESS_KEY"),
    secret_key=os.getenv("TVM_SECRET_KEY")
)
```

Validate connection on startup and exit gracefully with a clear error message if authentication fails.

---

## SLA Definitions

Severity is determined by the **VPR (Vulnerability Priority Rating)** score provided by Tenable,
not the native CVSS-based severity field. Always derive severity from the `vpr_score` field.

| Severity | VPR Score Range | SLA (Days to Remediate) |
| -------- | --------------- | ----------------------- |
| Critical | 9.0 – 10.0      | 15 days                 |
| High     | 7.0 – 8.9       | 30 days                 |
| Medium   | 4.0 – 6.9       | 90 days                 |
| Low      | 0.1 – 3.9       | 180 days                |

A vulnerability with no VPR score should fall back to native Tenable severity.

A vulnerability is **overdue** when: `today - first_found_date > SLA_days` AND it has not been remediated.

Define these as constants in a shared `config.py`:

```python
SLA_DAYS = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180
}
```

---

## Asset Segmentation

All reports must support **filtering and grouping by Tenable Tags/Labels**. Tags should be:

- Fetched dynamically from the API at runtime (do not hardcode tag values)
- Usable as CLI `--tag-category` and `--tag-value` arguments to scope any report
- Defined per recipient group in `delivery_config.yaml` (see below)
- Included as a column/dimension in all aggregated outputs

Example CLI usage:

```bash
python report_sla.py --tag-category "Business Unit" --tag-value "Finance"
python report_executive.py --tag-category "Environment" --tag-value "Production"
```

If no tag filter is provided, reports run against **all assets**.

---

## Project Structure

```
vuln-reporting/
├── .env                          # Credentials (never commit)
├── .env.example                  # Template for onboarding
├── config.py                     # SLA constants, severity mappings, shared config
├── tenable_client.py             # Authenticated TenableIO client factory
├── delivery_config.yaml          # Recipient groups, schedules, report selections
├── scheduler.py                  # APScheduler daemon + cron/manual trigger support
├── data/
│   └── fetchers.py               # All pyTenable API fetch functions
├── reports/
│   ├── executive_kpi.py
│   ├── sla_remediation.py
│   ├── asset_risk.py
│   ├── patch_compliance.py
│   ├── trend_analysis.py
│   └── plugin_cve.py
├── exporters/
│   ├── excel_exporter.py
│   ├── pdf_exporter.py
│   └── chart_exporter.py
├── delivery/
│   ├── email_sender.py           # SMTP send logic with attachments + inline charts
│   ├── email_template.py         # Jinja2 HTML body builder
│   └── delivery_log.py           # Delivery audit log (SQLite)
├── utils/
│   ├── sla_calculator.py
│   ├── tag_helper.py
│   └── formatters.py
├── templates/
│   └── report_email.html         # Jinja2 email template
├── logs/                         # Rotating application logs + delivery_log.db
├── output/                       # Timestamped report output folders
├── run_all.py                    # Master runner
└── README.md
```

---

## Delivery Configuration — `delivery_config.yaml`

This is the **single file** that controls who gets what, with what filters, and how often. It must be fully editable without touching any Python code. Adding/removing recipients, changing filters, or adjusting schedules requires only editing this file.

```yaml
# delivery_config.yaml

groups:
  - name: "Executive Team"
    description: "Weekly KPI summary for leadership"
    schedule:
      frequency: weekly # Options: weekly | on_demand
      day_of_week: monday # monday–sunday (weekly only)
      time: "07:00" # 24hr, server local time
    filters:
      tag_category: "Environment"
      tag_value: "Production"
    reports:
      - executive_kpi
      - trend_analysis
    email:
      subject: "Weekly Vulnerability Management Summary — Production"
      recipients:
        - ciso@company.com
        - vp-it@company.com
      cc:
        - security-team@company.com
      reply_to: security@company.com

  - name: "Finance Remediation Team"
    description: "Weekly SLA and patch status scoped to Finance assets"
    schedule:
      frequency: weekly
      day_of_week: tuesday
      time: "08:00"
    filters:
      tag_category: "Business Unit"
      tag_value: "Finance"
    reports:
      - sla_remediation
      - patch_compliance
      - asset_risk
    email:
      subject: "Finance BU — Weekly Vulnerability Remediation Report"
      recipients:
        - finance-it-lead@company.com
        - patching-team@company.com
      cc: []
      reply_to: security@company.com

  - name: "Security Analysts — Full Detail"
    description: "Weekly full-suite delivery for the security team, all assets"
    schedule:
      frequency: weekly
      day_of_week: monday
      time: "06:00"
    filters: {} # Empty = all assets, no tag filter
    reports:
      - executive_kpi
      - sla_remediation
      - asset_risk
      - patch_compliance
      - trend_analysis
      - plugin_cve
    email:
      subject: "Weekly Full Vulnerability Report Suite"
      recipients:
        - analyst1@company.com
        - analyst2@company.com
      cc: []
      reply_to: security@company.com

  - name: "Ad-Hoc Production Snapshot"
    description: "On-demand only — triggered manually via CLI"
    schedule:
      frequency: on_demand
    filters:
      tag_category: "Environment"
      tag_value: "Production"
    reports:
      - executive_kpi
      - sla_remediation
    email:
      subject: "On-Demand Production Vulnerability Snapshot"
      recipients:
        - requestor@company.com
      cc: []
      reply_to: security@company.com
```

### YAML Schema Rules

- `frequency` must be `weekly` or `on_demand`
- `day_of_week` and `time` are required when `frequency: weekly`; ignored for `on_demand`
- `filters` may be empty `{}` to run against all assets
- `reports` must be a list from: `executive_kpi`, `sla_remediation`, `asset_risk`, `patch_compliance`, `trend_analysis`, `plugin_cve`
- `recipients` is a required list; `cc` may be empty
- Validate the YAML schema on startup and exit with a clear error if misconfigured
- Build a `delivery_config.schema.yaml` (JSON Schema format) so the config can be validated by editors and CI

---

## Scheduler — `scheduler.py`

Build a flexible scheduler supporting three execution modes so teams can adopt whatever fits their infrastructure.

### Mode 1: APScheduler Daemon (always-on process)

```bash
python scheduler.py --mode daemon
```

- Reads `delivery_config.yaml` on startup and schedules all `weekly` groups via APScheduler `CronTrigger`
- Hot-reloads `delivery_config.yaml` every 5 minutes — reschedules changed groups without restart
- Logs all scheduled jobs and executions to `logs/scheduler.log`
- Designed to run as a background process via `nohup` or a `systemd` service
- Include a sample `systemd` unit file in the repo: `deploy/vuln-reports.service`

### Mode 2: Single-Run (cron / Windows Task Scheduler compatible)

```bash
python scheduler.py --mode run-due
```

- Reads `delivery_config.yaml` and executes only groups whose `day_of_week` + `time` matches the current time within a ±10-minute window
- Designed to be called by an external scheduler every 5–10 minutes
- Example crontab:
  ```
  */10 * * * * /usr/bin/python3 /opt/vuln-reporting/scheduler.py --mode run-due >> /var/log/vuln-reports.log 2>&1
  ```
- Windows Task Scheduler: trigger every 10 minutes, action: `python scheduler.py --mode run-due`

### Mode 3: Manual / On-Demand

```bash
# Run a specific group by name
python scheduler.py --mode manual --group "Finance Remediation Team"

# Run all groups with frequency: on_demand
python scheduler.py --mode manual --all-on-demand

# Override recipients at runtime (useful for testing or ad-hoc requests)
python scheduler.py --mode manual --group "Ad-Hoc Production Snapshot" --recipients test@company.com,manager@company.com

# Generate reports but skip email delivery
python scheduler.py --mode manual --group "Executive Team" --no-email
```

All three modes call the same underlying `run_group(group_config)` function — behavior is identical regardless of how it is triggered.

---

## Email Delivery — `delivery/email_sender.py`

### Email Structure

Every delivery email must include all of the following:

1. **HTML body** (Jinja2 template) containing:
   - Report title, generation timestamp, and group name
   - Scope banner: tag filter applied (e.g., "Scope: Environment = Production") or "All Assets"
   - **KPI summary strip**: Total Criticals open, % Critical/High within SLA, count of overdue Critical+High, overall MTTR
   - **Inline charts**: top 2–3 charts embedded as base64 CID images (`<img src="cid:chart_1">`) so they render in Outlook and Gmail without downloading attachments
   - Bullet list of attached reports with one-line descriptions
   - SLA reference table (4 rows)
   - Footer: reply-to address, generation timestamp, instructions for updating recipients or filters

2. **PDF attachments** — one per report in the group's report list

3. **Excel attachments** — one per report in the group's report list

### SMTP Implementation

```python
def send_report_email(group_config: dict, report_outputs: dict) -> bool:
    """
    group_config: parsed group from delivery_config.yaml
    report_outputs: {report_name: {pdf: path, excel: path, charts: [path, ...]}}
    Returns True on success, False on failure — logs error, never raises
    """
```

- Use STARTTLS (port 587) by default; support SSL (port 465) via env var override
- Retry up to 3 times with exponential backoff on transient SMTP failures (`tenacity`)
- Validate all recipient email addresses before attempting send
- Enforce a configurable `MAX_ATTACHMENT_SIZE_MB` (default: 25MB total). If exceeded: log a warning, send PDF only, note in email body that Excel was omitted due to size
- Never send to an empty recipient list — log and skip if `recipients` resolves to zero valid addresses

---

## Email Template — `templates/report_email.html`

Build a Jinja2 HTML email template that is:

- Compatible with Outlook, Gmail, and Apple Mail — **inline CSS only**, no external stylesheets or `<style>` blocks
- Structured with these sections in order:
  1. **Header band**: Report title + date generated
  2. **Scope banner**: Filter applied or "All Assets"
  3. **KPI tiles** (4–5 metric boxes, table-based layout for email client compatibility): Total Criticals, % Within SLA, Overdue High+Critical, MTTR
  4. **Inline charts**: `<img src="cid:chart_N">` placeholders — up to 3 charts
  5. **Attached reports list**: bullet list with report name + one-line description
  6. **SLA reference table**: 4-row table
  7. **Footer**: reply-to, timestamp, "To update recipients or report filters, contact: [reply_to address]"

---

## Delivery Log — `delivery/delivery_log.py`

Maintain a **SQLite audit log** at `logs/delivery_log.db`.

### Schema

```sql
CREATE TABLE delivery_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           DATETIME NOT NULL,
    group_name          TEXT NOT NULL,
    trigger_mode        TEXT NOT NULL,      -- 'scheduled' | 'manual' | 'daemon'
    reports_run         TEXT NOT NULL,      -- JSON array
    tag_filter          TEXT,               -- "Category=Value" or "all_assets"
    recipients          TEXT NOT NULL,      -- JSON array
    status              TEXT NOT NULL,      -- 'success' | 'partial' | 'failed'
    error_message       TEXT,               -- NULL on success
    output_folder       TEXT NOT NULL,
    attachment_size_kb  INTEGER,
    duration_seconds    REAL
);
```

### CLI for log inspection

```bash
python delivery/delivery_log.py --recent 20
python delivery/delivery_log.py --failures
python delivery/delivery_log.py --group "Executive Team"
python delivery/delivery_log.py --from 2025-01-01 --to 2025-01-31
```

---

## `run_all.py` — Master Runner

```bash
# Run all groups that are due (scheduled mode)
python run_all.py

# Run a specific group with full delivery
python run_all.py --group "Finance Remediation Team"

# Generate reports only, no email
python run_all.py --group "Executive Team" --no-email

# Dry run: validate config and show what would be sent
python run_all.py --dry-run

# Override tag filter at runtime
python run_all.py --group "Ad-Hoc Production Snapshot" --tag-category "Environment" --tag-value "Staging"

# Override recipients at runtime
python run_all.py --group "Executive Team" --recipients test@company.com
```

Saves all outputs to: `output/YYYY-MM-DD_HH-MM_<group-name>/`

Prints a `rich` summary table on completion: group name, reports generated, delivery status, output path.

---

## Report Scripts

### 1. `reports/executive_kpi.py` — Executive / KPI Dashboard

**Audience:** Management / Executives

- Total open vulns by severity
- % Critical and High within SLA / overdue
- Mean Time to Remediate (MTTR) by severity
- Remediation Rate: closed this period / open at start of period
- Top 5 riskiest asset tags (Critical×10 + High×5 + Medium×2 + Low×1)
- Month-over-month change in open Critical/High counts

**Outputs:** PDF, Excel, Plotly bar chart (vulns by severity), Plotly KPI gauges (SLA compliance %)

---

### 2. `reports/sla_remediation.py` — SLA & Remediation Tracking

**Audience:** IT / Remediation Teams + Security Analysts

- Per-vuln SLA status: Within SLA / Overdue / Remediated
- Days remaining or days overdue per vulnerability
- Overdue breakdown by severity and tag group
- Remediation velocity: vulns closed last 7 / 30 / 90 days
- Per-asset overdue vuln list sorted by severity then days overdue
- SLA breach rate trend over last 6 months

**Outputs:** Excel (one tab per severity, red/yellow/green conditional formatting), PDF, Matplotlib bar (Overdue vs. Within SLA per severity)

---

### 3. `reports/asset_risk.py` — Asset Risk Scoring

**Audience:** Security Analysts + IT

- Per-asset score: `(Critical×10) + (High×5) + (Medium×2) + (Low×1)`
- Top 25 highest-risk assets with hostname, IP, tags, score, severity breakdown
- Risk score distribution histogram
- Clean assets (zero vulns)
- Average risk score grouped by tag category
- CVSS averages per asset and per tag group

**Outputs:** Excel (color-coded risk tiers), PDF, Plotly horizontal bar (Top 25 assets)

---

### 4. `reports/patch_compliance.py` — Patch Compliance & Vuln Age

**Audience:** IT / Remediation Teams + Security Analysts

- Age buckets: 0–15d, 16–30d, 31–60d, 61–90d, 91–180d, 180d+
- % open vulns beyond SLA per severity
- Top 20 oldest unpatched vulns with plugin name, CVE, asset, days open
- Per-tag patch compliance score
- Recurring vulnerability count
- Plugin family breakdown for aged vulns

**Outputs:** Excel, PDF, Matplotlib stacked bar (age buckets per severity)

---

### 5. `reports/trend_analysis.py` — Trend Analysis Over Time

**Audience:** Management / Executives + Security Analysts

- Weekly/monthly open vuln snapshots by severity
- MTTR trend per severity
- SLA compliance rate trend per month
- Net vuln delta: new introduced vs. remediated per period
- Per-tag-group trend (improving vs. degrading)
- Rolling 90-day remediation rate

**Outputs:** Excel (time-series), PDF, Plotly line charts (open vuln trend + SLA compliance trend)

---

### 6. `reports/plugin_cve.py` — Plugin / CVE Breakdown

**Audience:** Security Analysts

- Top 25 plugins by affected asset count
- Top 25 CVEs by CVSS score
- Plugin family distribution
- Exploitable vuln count (`exploit_available` field)
- CVSS ≥ 9.0 vulns that are SLA-overdue
- Per-plugin: asset count, severity, CVSS, CVE list, SLA status, oldest days open

**Outputs:** Excel (plugin tab + CVE tab), PDF, Plotly donut (plugin families), Matplotlib bar (Top 25 plugins)

---

## Shared Utilities

### `utils/sla_calculator.py`

```python
def get_sla_status(severity: str, first_found: datetime, remediated: bool) -> dict:
    """Returns status, days_open, days_remaining (negative = overdue), sla_days"""
```

### `utils/tag_helper.py`

```python
def get_all_tags(tio) -> pd.DataFrame
def get_assets_by_tag(tio, tag_category: str, tag_value: str) -> list[str]
def enrich_vulns_with_tags(vulns_df: pd.DataFrame, tio) -> pd.DataFrame
```

CLI: `python utils/tag_helper.py --list-tags` / `--list-tags --category "Business Unit"`

### `exporters/chart_exporter.py`

Consistent color palette across all charts:

- Critical = `#d32f2f` | High = `#f57c00` | Medium = `#fbc02d` | Low = `#388e3c` | Info = `#1976d2`

Matplotlib `.png` for PDF embedding and email CID inline images.
Plotly `.html` (interactive) + `.png` (static) for both attachment and inline use.

---

## Data Fetching Guidelines (`data/fetchers.py`)

- `tio.exports.vulns()` for bulk vulnerability data
- `tio.exports.assets()` for asset enrichment
- `tio.tags.list()` for tag discovery
- Cache fetched data to local `.parquet` during each run to avoid redundant API calls across reports in the same group execution
- `tenacity` exponential backoff for rate limiting
- All fetch functions return a normalized `pd.DataFrame`
- `rich` progress bars for all long-running fetches

---

## Code Quality Requirements

- `if __name__ == "__main__":` with `argparse` on every script
- Full docstrings and type hints throughout
- Timezone-aware datetime handling (UTC)
- `logging` module with rotating file handlers (`logs/app.log`)
- No silent failures — log all errors; on multi-group runs, failures in one group must not stop others
- `requirements.txt` with pinned versions
- `.env.example` with all variables and inline comments

---

## README.md Must Include

1. Prerequisites and install instructions
2. `.env` setup — Tenable credentials and SMTP config
3. `delivery_config.yaml` annotated walkthrough
4. Tag discovery: `python utils/tag_helper.py --list-tags`
5. Scheduling setup for all three modes:
   - APScheduler daemon with sample `systemd` unit (`deploy/vuln-reports.service`)
   - Cron job with example crontab entry
   - Windows Task Scheduler step-by-step
6. Manual trigger examples
7. How to add/remove recipients (YAML only — no code changes)
8. How to add a new delivery group
9. Delivery log inspection commands
10. Output folder structure
11. Troubleshooting: Tenable auth errors, SMTP failures, rate limiting, oversized attachments

---

## Deliverables Checklist

- [ ] `config.py`
- [ ] `tenable_client.py`
- [ ] `delivery_config.yaml` — annotated example with 4 sample groups
- [ ] `delivery_config.schema.yaml` — schema for validation
- [ ] `data/fetchers.py`
- [ ] `utils/sla_calculator.py`
- [ ] `utils/tag_helper.py` (with `--list-tags` CLI)
- [ ] `utils/formatters.py`
- [ ] `exporters/excel_exporter.py`
- [ ] `exporters/pdf_exporter.py`
- [ ] `exporters/chart_exporter.py`
- [ ] `reports/executive_kpi.py`
- [ ] `reports/sla_remediation.py`
- [ ] `reports/asset_risk.py`
- [ ] `reports/patch_compliance.py`
- [ ] `reports/trend_analysis.py`
- [ ] `reports/plugin_cve.py`
- [ ] `delivery/email_sender.py`
- [ ] `delivery/email_template.py`
- [ ] `templates/report_email.html`
- [ ] `delivery/delivery_log.py` (with inspection CLI)
- [ ] `scheduler.py` (daemon + run-due + manual modes)
- [ ] `deploy/vuln-reports.service` (systemd unit file)
- [ ] `run_all.py`
- [ ] `requirements.txt`
- [ ] `.env.example`
- [ ] `README.md`
