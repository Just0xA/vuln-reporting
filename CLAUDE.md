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
- **weasyprint** — PDF generation
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
├── delivery_config.schema.yaml   # JSON Schema for YAML validation
├── scheduler.py                  # APScheduler daemon + cron/manual trigger support
├── data/
│   ├── fetchers.py               # All pyTenable API fetch functions
│   └── trend/                    # Trend data store (JSON snapshots for management_summary)
├── reports/
│   ├── executive_kpi.py
│   ├── sla_remediation.py
│   ├── asset_risk.py
│   ├── patch_compliance.py
│   ├── trend_analysis.py
│   ├── plugin_cve.py
│   ├── ops_remediation.py
│   ├── vuln_export.py
│   ├── management_summary.py     # Management executive summary (module-based)
│   ├── board_summary.py          # Board-level KPI report (module-based)
│   └── modules/                  # Reusable metric module infrastructure
│       ├── __init__.py           # Auto-discovery + public exports
│       ├── base.py               # BaseModule ABC, ModuleConfig, ModuleData
│       ├── registry.py           # ModuleRegistry singleton + @register_module
│       ├── composer.py           # ReportComposer — PDF/Excel/email assembly
│       ├── chart_utils.py        # draw_gauge() and shared chart helpers
│       ├── board_report_utils.py # Shared utilities for board metric modules
│       ├── scan_coverage_sla_module.py
│       ├── critical_remediation_sla_module.py
│       ├── high_risk_assets_module.py
│       └── aged_vulns_assets_module.py
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
├── docs/
│   ├── management_summary_calculations.md
│   └── board_summary_calculations.md
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
      frequency: weekly # Options: weekly | monthly | on_demand
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

  - name: "Monthly Executive Summary"
    description: "First of the month full executive package"
    schedule:
      frequency: monthly
      day_of_month: 1       # integer 1–28 (use 28 max to avoid last-day-of-month issues in February)
      time: "07:00"         # 24hr, server local time
    filters:
      tag_category: "Environment"
      tag_value: "Production"
    reports:
      - executive_kpi
      - trend_analysis
      - patch_compliance
    email:
      subject: "Monthly Vulnerability Management Report — Production"
      recipients:
        - ciso@company.com
      cc:
        - security-team@company.com
      reply_to: security@company.com
```

### YAML Schema Rules

- `frequency` must be `weekly`, `monthly`, or `on_demand`
- `day_of_week` is required when `frequency: weekly`; must be one of `monday`–`sunday`; ignored otherwise
- `day_of_month` is required when `frequency: monthly`; must be an integer between 1 and 28 (28 max to avoid last-day-of-month issues in February); ignored otherwise
- `time` is required for `frequency: weekly` and `frequency: monthly`; format `HH:MM` (24-hour, server local time); ignored for `on_demand`
- `filters` may be empty `{}` to run against all assets
- `reports` must be a list from: `executive_kpi`, `sla_remediation`, `asset_risk`, `patch_compliance`, `trend_analysis`, `plugin_cve`, `ops_remediation`, `management_summary`, `vuln_export`, `board_summary`, `unscanned_assets`
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

- Reads `delivery_config.yaml` on startup and schedules all `weekly` and `monthly` groups via APScheduler `CronTrigger`
- Hot-reloads `delivery_config.yaml` every 5 minutes — reschedules changed groups without restart
- Logs all scheduled jobs and executions to `logs/scheduler.log`
- Designed to run as a background process via `nohup` or a `systemd` service
- Include a sample `systemd` unit file in the repo: `deploy/vuln-reports.service`

### Mode 2: Single-Run (cron / Windows Task Scheduler compatible)

```bash
python scheduler.py --mode run-due
```

- Reads `delivery_config.yaml` and executes only groups whose schedule (`day_of_week` + `time` for weekly; `day_of_month` + `time` for monthly) matches the current time within a ±10-minute window
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
  3. **KPI tiles** (4–5 metric boxes, table-based layout for email client compatibility): Total Criticals, % Within SLA, Overdue High+Critical, MTTR. If `ops_remediation` is in the run, its pre-built `kpi_tiles` from `metrics` are used directly and take priority over the generic tile logic.
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

## Board-Style Reports — Module Infrastructure

Reports that use the `reports/modules/` infrastructure are composed of independent,
testable metric modules assembled by `ReportComposer` into PDF, Excel, and email outputs.
This pattern is used by `board_summary` and `management_summary`.

### Module anatomy

Every metric module lives in `reports/modules/` and must:
1. Be named `*_module.py` (auto-discovered by `registry.discover()` on package import)
2. Decorate the class with `@register_module`
3. Extend `BaseModule` and implement `compute()`. Override any of the renderer methods (`render_pdf_section`, `render_excel_tabs`, `render_email_kpis`, `render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) whose channel the module contributes to. All renderers are concrete with no-op defaults — un-overridden methods produce empty contributions (gray "No Data" cell for the RAG strip; empty string for email panel; empty list for analyst tabs).

```python
from reports.modules import register_module
from reports.modules.base import BaseModule, ModuleConfig, ModuleData

@register_module
class MyMetricModule(BaseModule):
    MODULE_ID    = "my_metric"
    DISPLAY_NAME = "My Metric"
    ...
```

### Four-channel render contract

Every metric module can render itself into up to four channels via concrete methods on `BaseModule`. All are **concrete with no-op defaults** (NOT `@abstractmethod`) so existing modules continue to instantiate without changes.

| Method | Channel | Default | Override when |
|--------|---------|---------|---------------|
| `render_pdf_section(data, config) -> str` | PDF | `""` | `"pdf"` in `SUPPORTED_OUTPUTS` |
| `render_excel_tabs(data, workbook, config) -> list[str]` | Excel | `[]` | `"excel"` in `SUPPORTED_OUTPUTS` |
| `render_email_kpis(data, config) -> list[dict]` | Email KPI tiles (legacy) | `[]` | Module surfaces a KPI tile |
| `render_email_panel(data, config) -> str` | Email body panel (CONTRACT-01) | `""` | Module appears as a per-module panel in composed email body |
| `render_analyst_tabs(data, config) -> list[tuple[str, pd.DataFrame]]` | Analyst-detail companion workbook (CONTRACT-02) | `[]` | Module produces drill-down rows for analysts |
| `render_rag_strip_entry(data, config) -> dict` | Cover-page RAG strip (CONTRACT-03) | Gray "No Data" cell | Module appears in the cover-page strip |

The supporting fields on `ModuleData` (CONTRACT-04) carry the data each renderer needs:

| Field | Purpose |
|-------|---------|
| `driver_narrative: str` | 1-line "what's driving it" string consumed by `render_email_panel`. Populated inside `compute()`. |
| `analyst_rows: list[tuple[str, pd.DataFrame]]` | Pivot-friendly drill-down data consumed by `render_analyst_tabs`. Populated inside `compute()`. |
| `rag_strip: dict` | Pre-built cover-page strip cell `{label, headline_value, rag_color, rag_label}` consumed by `render_rag_strip_entry`. Populated inside `compute()`. |

### Empty-data guard pattern

Filtered-to-zero recipient groups are a regular occurrence (Owner=Configuration Mangement typo, etc.) — render methods MUST not crash on a zero-row `ModuleData`. Two rules:

1. **Use `safe_pct` / `safe_int` / `safe_format` from `reports.modules.format_utils`** when interpolating any metric value that could be `None` or `NaN`. Inline f-string format specs on possibly-`None` values are forbidden.

   ```python
   from reports.modules import safe_pct, safe_int, safe_format

   # Good
   panel_html = f"<p>Coverage: {safe_pct(cov_pct)}</p>"

   # Bad — crashes on cov_pct = None
   panel_html = f"<p>Coverage: {cov_pct:.1f}%</p>"
   ```

2. **Return safe defaults instead of raising** in every render method. The `BaseModule._empty_result()` helper produces a coherent failed-`ModuleData` with a gray "No Data" strip cell and "No data in scope." driver narrative — overrides can rely on it as a reference shape.

   ```python
   def render_rag_strip_entry(self, data, config):
       if data.error or not data.metrics:
           from reports.modules import build_rag_strip_entry
           return build_rag_strip_entry(self.DISPLAY_NAME, "—", "no_data")
       headline = safe_pct(data.metrics["scan_coverage_pct"])
       status = rag_status_from_value(data.metrics["scan_coverage_pct"], 95.0, 90.0)
       return build_rag_strip_entry(self.DISPLAY_NAME, headline, status)
   ```

The shared RAG palette + sentinels live in `reports/modules/rag_utils.py` (`STATUS_COLOR`, `STATUS_LABEL`, `NO_DATA_HEADLINE`, `NO_DATA_DRIVER`). The shared formatters live in `reports/modules/format_utils.py`. Both are also re-exported at the package level so modules can `from reports.modules import safe_pct, build_rag_strip_entry, rag_status_from_value`.

### Adding a new module to an existing composed report

1. Create `reports/modules/my_metric_module.py` following the pattern above.
2. Add `ModuleConfig("my_metric")` to the report's module config list (e.g. `_BOARD_MODULE_CONFIGS` in `board_summary.py`).
3. No registration in `run_all.py` or `CLAUDE.md` is needed for the module itself — only the top-level **report slug** (`board_summary`, `management_summary`) is registered there.

### Key files

| File | Purpose |
|------|---------|
| `reports/modules/base.py` | `BaseModule` ABC, `ModuleConfig`, `ModuleData` dataclasses |
| `reports/modules/registry.py` | `ModuleRegistry` singleton + `@register_module` decorator |
| `reports/modules/composer.py` | `ReportComposer` — runs modules, assembles PDF/Excel/email |
| `reports/modules/board_report_utils.py` | Shared utilities for the four board metric modules |
| `reports/modules/chart_utils.py` | `draw_gauge()` and other shared rendering helpers |
| `reports/modules/rag_utils.py` | Shared RAG palette (`STATUS_COLOR`, `STATUS_LABEL`), classifier wrapper (`rag_status_from_value`), strip-cell builder (`build_rag_strip_entry`), no-data sentinels |
| `reports/modules/format_utils.py` | None/NaN-safe formatters (`safe_pct`, `safe_int`, `safe_format`) for use in render methods |

### PDF assembly note

`ReportComposer.assemble_pdf()` produces a cover/title page (page 1) followed by one page
per module. The cover page carries the report title, scope, generated timestamp, and section
list. There is no separate trailing footer page — placing generated metadata there caused an
orphaned last page when the final module filled its page exactly.

---

## Adding a New Report — Required Steps

Every new report script **must** be registered in three places or `--dry-run` will reject it:

1. **`run_all.py` — `_VALID_REPORTS`**: add the slug to the `frozenset`.
2. **`run_all.py` — `_REPORT_MODULE_MAP`**: add `"slug": "reports.module_name"`.
3. **`CLAUDE.md` — YAML Schema Rules**: add the slug to the `reports` valid-values list above.

If the report needs group-config parameters beyond the standard set (`tag_category`, `tag_value`, `output_dir`, `generated_at`, `cache_dir`), add a slug-specific block inside `run_group()` in `run_all.py` (see the `vuln_export` / `csv_severities` pattern at the `run_report` call site).

Each report's `run_report()` must return a dict with at minimum these keys:
```python
{"pdf": path_or_none, "excel": path_or_none, "charts": list_of_paths}
```
CSV-only reports also include `"csv": path_or_none`. All other keys (e.g. `"metrics"`) are optional.

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

### 7. `reports/ops_remediation.py` — Operations Remediation

**Audience:** Operations / Remediation Teams

Operationally focused report that groups overdue findings by plugin to provide actionable remediation priorities, surfaces risk management posture (accepted/recast findings), and tracks recurring vulnerabilities.

**Excel Tabs (7 total):**
1. **Summary** — KPI snapshot: severity counts, overdue totals, SLA compliance %, exploitability breakdown (exploit available / functional exploit / high maturity), risk management counts (accepted, recast, expiring/expired rules, recurring findings)
2. **Overdue by Plugin** — Plugins with overdue findings grouped and ranked; columns: Plugin ID, Plugin Name, CVE(s), Exploit Available, Exploit Code Maturity, Severity, VPR Score, Overdue Critical/High/Medium/Low, Total Overdue, Oldest Days Overdue, Affected Assets, SLA Days
3. **Overdue Findings Detail** — Row-per-finding detail for all overdue vulns; columns: Asset, IP, Plugin ID, Plugin Name, Severity, VPR Score, Days Overdue, First Found, SLA Due Date, CVE(s), Exploit Available
4. **Unscanned Assets** — Assets not seen in the scan window; columns: Asset Name, IP Address, Last Seen, Days Since Last Scan, Tags
5. **Risk Acceptances & Recasts** — Active accepted/recast findings from the vuln export enriched with recast rules API; columns: Plugin ID, Plugin Name, Modification Type, Recast Reason, Original Severity, Current Severity, VPR Score, Date Opened, Expiration Date, Days Until Expiry, Affected Assets, Rule UUID
6. **Recurring Vulnerabilities** — Findings where `resurfaced_date` is populated (closed then reopened); columns: Plugin ID, Plugin Name, Asset Name, IP Address, Original First Found, Date Closed, Date Reopened, Last Seen, Current State, Severity, VPR Score, Exploit Available, Exploit Maturity
7. **Report Info** — Metadata: report parameters, run timestamp, tab reference guide, field availability notes

**PDF:** Executive summary with KPI tiles, SLA compliance table, overdue breakdown by severity, top 10 overdue plugins table (page-break forced before Top 5 Priority Plugins table), risk management summary

**Email KPI tiles (5):** Open Criticals, Overdue Critical+High, Critical+High Within SLA, Exploitable Overdue, Recurring Findings. Includes narrative sentences for elevated risk signals (recurring findings, expired/expiring rules, accepted/recast counts).

**Key data sources:**
- Primary: `tio.exports.vulns()` — `severity_modification_type` field (`"recasted"` / `"accepted"` / `"none"`) is the authoritative source for risk modifications
- Enrichment: `POST /v1/recast/rules/search` — provides expiration dates, original severity, and `created_at` for risk modification rows; only present when a rule exists
- `expires_at` is absent from the API response when no expiration has been set (treat as "Never")
- VPR score for accepted findings (which may have NaN `vpr_score` in a scoped export) is sourced from `vulns_all.parquet` by plugin ID

**Outputs:** Excel (7 tabs), PDF, no charts (chart list returned as `[]` in metrics dict)

---

### 8. `reports/vuln_export.py` — Raw Vulnerability Export (CSV)

**Audience:** Operations / Remediation Teams, Security Analysts

- One row per open finding scoped to the group's tag filter and severity filter
- Default severity filter: Critical, High, Medium (configurable via `csv_severities` in delivery_config.yaml)
- Joins `assets_df` on `asset_uuid` for Asset Name, IP Address, Operating System enrichment
- Four-state SLA status: Overdue / Urgent / Warning / On Track (same thresholds as ops_remediation)
- Sort order: severity rank → VPR score descending → Days Open descending

**Columns:** Plugin ID, Plugin Name, Application, Asset Name, IP Address, Operating System, CPE, Severity, VPR Score, First Found, Days Open, SLA Status, Exploit Available, Exploit Code Maturity

**Outputs:** CSV only (UTF-8 with BOM, `quoting=QUOTE_ALL`). No PDF, no Excel, no charts.

**Return dict:** `{"pdf": None, "excel": None, "csv": "<path>", "charts": [], "metrics": {...}}`

**Group-config extras:**
```yaml
csv_severities:   # optional — defaults to [critical, high, medium]
  - critical
  - high
  - medium
```

---

### 9. `reports/management_summary.py` — Management Executive Summary

**Audience:** Senior Management — Directors and Vice Presidents

Seven board-facing metrics, each with a gauge chart and RAG status (green/amber/red):

1. Total open vulnerabilities by severity
2. Asset scan coverage
3. Mean Time to Remediate (MTTR) by severity
4. SLA compliance rate
5. Vulnerability age distribution
6. Managed exception rate (accepted/recast findings)
7. Month-over-month trend

Monthly trend data is persisted to `data/trend/` as JSON snapshots so each run can show
a rolling historical view without re-querying the API.

Built on the `reports/modules/` infrastructure.

**Outputs:** PDF (5 pages), HTML email body. No Excel attachment.

**Calculations runbook:** `docs/management_summary_calculations.md`

---

### 10. `reports/board_summary.py` — Board Vulnerability Metrics Summary

**Audience:** Board of Directors / Executive Leadership

Four board-facing KPIs, each with a gauge chart, RAG status, and per-business-unit breakdown:

1. **Scan Coverage SLA** — % of licensed assets scanned in the last 30 days (target ≥ 95%)
2. **Critical Remediation SLA** — % of critical vulns fixed within their 15-day SLA in the last 30 days (target ≥ 95%)
3. **High-Risk Assets** — % of on-time assets with ≥ 10 Crit/High vulns open > 30 days (target ≤ 0.5%)
4. **Aged Vulnerability Assets** — % of on-time assets with ≥ 1 Med/High/Crit vuln open > 90 days (target ≤ 2%)

All four metrics share the same on-time scanned asset baseline (licensed assets, scanned within
30 days, deduplicated by hostname). Business-unit breakdown uses the Tenable `Application` tag
category. Unlicensed assets (null `last_licensed_scan_date`) are excluded from all metrics.

Built on the `reports/modules/` infrastructure — each metric is an independent registered
module; `ReportComposer` assembles the PDF, Excel, and email KPI tiles.

**Outputs:** PDF (cover page + 4 metric pages), Excel (4 tabs + `_Metadata`). No charts returned.

**Calculations runbook:** `docs/board_summary_calculations.md`

---

### 11. `reports/unscanned_assets.py` — Unscanned / Overdue Assets List

**Audience:** Security Analysts / IT Operations

Companion report to the Board Summary Scan Coverage SLA metric. Lists every asset that is **not** contributing to the "on time" numerator so analysts can investigate why assets are missing from coverage. Uses identical deduplication logic (`deduplicate_assets_by_name` from `board_report_utils`) so counts reconcile exactly with the board metric.

**Three-way asset split:**
- **On Time** — licensed asset with `last_licensed_scan_date` within `scan_window_days` (excluded from output, count shown in summary only)
- **Overdue Licensed** — licensed asset whose `last_licensed_scan_date` is older than `scan_window_days`; these inflate the denominator and hurt coverage %
- **No Licensed Scan** — asset with a null `last_licensed_scan_date`; excluded from both numerator and denominator of the board metric

**Group-config extras:**
```yaml
scan_window_days: 30   # optional — defaults to 30; must match board_summary setting
```

**Excel tabs:**
1. **Summary** — reconciliation counts (on time / overdue licensed / no licensed scan / total licensed / unlicensed excluded); formula showing how Scan Coverage SLA % is derived
2. **Overdue Licensed** — assets with stale scan dates; sorted by `days_since_licensed_scan` descending; columns: hostname, ipv4, fqdn, OS, last_licensed_scan_date, days_since_licensed_scan, last_seen, days_since_last_seen, last_scan_time, source_name, tags, asset_uuid
3. **No Licensed Scan** — assets never assigned a licensed scan; sorted by `days_since_last_seen` descending; columns: hostname, ipv4, fqdn, OS, last_seen, days_since_last_seen, first_seen, has_plugin_results, source_name, tags, asset_uuid

**CSV:** Flat export combining Overdue Licensed and No Licensed Scan rows with a `Category` column.

**Outputs:** Excel (.xlsx), CSV. No PDF, no charts.

**Return dict:** `{"pdf": None, "excel": path, "csv": path, "charts": [], "metrics": {...}}`

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

- `tio.exports.vulns()` for bulk vulnerability data — includes `severity_modification_type`, `recast_rule_uuid`, and `recast_reason` fields for risk management tracking
- `tio.exports.assets()` for asset enrichment
- `tio.tags.list()` for tag discovery
- `POST /v1/recast/rules/search` (`fetch_recast_rules()`) — returns active recast/accept rules with filter trees, expiration dates, original severity, and `created_at`; used as optional enrichment by `ops_remediation`
- Cache fetched data to local `.parquet` during each run to avoid redundant API calls across reports in the same group execution
- Cache folders are named by **local machine date** (`YYYY-MM-DD`), not UTC. At the start of each `run_all.py` batch, cache folders from prior days are automatically deleted — only the current day's cache is retained.
- `tenacity` exponential backoff for rate limiting
- All fetch functions return a normalized `pd.DataFrame`
- `rich` progress bars for all long-running fetches

### Recast rules filter structure

The recast rules API returns a `filter` field that can be an arbitrary AND/OR tree of conditions. Supported filter properties include: Plugin ID (`definition.id`), Asset ID, IPv4, IPv6, FQDN, Network, CVE, Plugin Output, Protocol, and Tags — in any combination. Use `_summarize_filter()` to convert the filter tree to a human-readable string. Plugin ID is only extractable when the filter is a flat `{"property": "definition.id", ...}` condition or a single-item `and/or` wrapping one.

---

## Code Quality Requirements

- `if __name__ == "__main__":` with `argparse` on every script
- Full docstrings and type hints throughout
- Timezone-aware datetime handling: report timestamps use UTC; cache folder names use local machine timezone
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

- [x] `config.py`
- [ ] `tenable_client.py`
- [x] `delivery_config.yaml` — annotated example with 4 sample groups
- [x] `delivery_config.schema.yaml` — schema for validation
- [x] `data/fetchers.py`
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
- [x] `reports/ops_remediation.py`
- [x] `reports/vuln_export.py`
- [x] `reports/management_summary.py`
- [x] `reports/board_summary.py`
- [x] `reports/unscanned_assets.py`
- [x] `reports/modules/` — BaseModule, ModuleRegistry, ReportComposer, chart_utils, board_report_utils, 4 board metric modules
- [ ] `delivery/email_sender.py`
- [ ] `delivery/email_template.py`
- [ ] `templates/report_email.html`
- [ ] `delivery/delivery_log.py` (with inspection CLI)
- [ ] `scheduler.py` (daemon + run-due + manual modes)
- [ ] `deploy/vuln-reports.service` (systemd unit file)
- [x] `run_all.py`
- [ ] `requirements.txt`
- [ ] `.env.example`
- [ ] `README.md`
- [x] `docs/management_summary_calculations.md`
- [x] `docs/board_summary_calculations.md`

<!-- GSD:project-start source:PROJECT.md -->
## Project

**Vulnerability Management Reporting Suite**

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + inline-chart email — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

The next direction is to make every report **modular and composable** rather than canned: individual KPI/KRI modules render themselves into PDF, Excel, email, and analyst drill-down detail, so each recipient group (Operations, Management, Executive Leadership) gets a tailored bundle assembled from the same shared metric library.

**Core Value:** **Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

### Constraints

- **Tech stack**: Python 3.10+, `pyTenable` SDK, pandas, openpyxl, WeasyPrint, matplotlib + plotly, Jinja2, APScheduler, tenacity — locked. No new SDK adoption in v1.
- **Email-client compatibility**: Outlook / Gmail / Apple Mail must render the per-module email panels. Inline CSS only; no `<style>` blocks; charts via base64 CID. Already established and must be preserved.
- **Backward compatibility**: Existing groups in `delivery_config.yaml` referencing `board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets` must continue to deliver during and after v1. Adding the analyst-detail companion to Board Summary cannot regress existing email/PDF for those recipients.
- **Credential handling**: All Tenable + SMTP credentials via `.env` only — never hardcoded, never logged, never committed. Existing pattern is locked.
- **Fail-soft batch semantics**: A module render error must not kill the batch. The empty-data hardening requirement is a hard correctness bar, not a nice-to-have, because filtered-to-zero recipient groups are a regular occurrence (we just hit two on 2026-05-04).
- **Reviewer-in-the-loop for Board Summary delivery**: Board Summary today goes Manager → CISO → IT Metrics team; it is never delivered directly. v1's `analyst_detail: true|false` toggle exists to future-proof this — when Board Summary delivery becomes more direct, recipient groups can opt out of the analyst companion without changing code.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Python 3.10+ — entire codebase. `from __future__ import annotations` used pervasively (e.g. `tenable_client.py:13`, `data/fetchers.py:18`) implying minimum 3.10 baseline; project documentation in `CLAUDE.md` declares "Python 3.10+".
- HTML/Jinja2 templates — `templates/report_email.html` and inline HTML built by `delivery/email_template.py:47-57` (Jinja2 `Environment` + `FileSystemLoader`).
- YAML — declarative delivery config (`delivery_config.yaml`) plus JSON-Schema-format validator at `delivery_config.schema.yaml`.
- SQL (SQLite dialect) — embedded delivery audit log; see `delivery/delivery_log.py:49-64` for the `delivery_log` `CREATE TABLE` statement.
## Runtime
- CPython, expected to be invoked from a project-local virtualenv. The systemd unit at `deploy/vuln-reports.service:43` hard-codes the interpreter path `ExecStart=/opt/vuln-reporting/.venv/bin/python scheduler.py --mode daemon`, and the dev workstation copy of `.venv/` lives at the repo root.
- pip with a flat, fully-pinned `requirements.txt` (no Poetry/PDM/uv lockfile present).
- No `pyproject.toml`, `setup.py`, `Pipfile`, or `Pipfile.lock` in the repo root. `requirements.txt` is the single source of truth for dependencies.
## Frameworks
- `pyTenable` 1.5.2 (`requirements.txt:2`) — Tenable Vulnerability Management SDK; instantiated in `tenable_client.py:80-84` (`TenableIO(access_key=..., secret_key=..., url=...)`); errors caught from the bundled `tenable.errors.APIError` (`tenable_client.py:21`) and from `restfly.errors.UnauthorizedError` re-aliased as `AuthenticationError` (`tenable_client.py:22`). `restfly` is a transitive dependency pulled in by pyTenable.
- `pandas` 2.2.3 (`requirements.txt:5`) + `numpy` 2.2.4 (`requirements.txt:6`) — every fetcher in `data/fetchers.py` returns a normalized `pd.DataFrame`; date normalization helpers `_parse_iso_utc` / `_normalize_vuln_dates` / `_normalize_asset_dates` at `data/fetchers.py:1132-1168`.
- `APScheduler` 3.11.0 (`requirements.txt:24`) — used in daemon mode only. `BlockingScheduler` and `IntervalTrigger` imported at `scheduler.py:300-301`; `CronTrigger` imported at `scheduler.py:155`. Misfire grace time set to 600s in `scheduler.py:254`.
- No test framework declared in `requirements.txt`. A `tests/` directory exists at the repo root but is not wired into a runner. Pytest, unittest, etc. are not installed by `requirements.txt` (verified via grep — `pytest`, `unittest`, `nose` absent).
- No linter, formatter, or pre-commit configuration committed. No `.flake8`, `pyproject.toml`, `ruff.toml`, `mypy.ini`, `.pre-commit-config.yaml` present at the repo root (only the files listed in the directory listing are tracked).
## Key Dependencies
- `pyTenable==1.5.2` — Tenable API SDK (`requirements.txt:2`). Used directly via `tio.exports.vulns()`, `tio.exports.assets()`, `tio.tags.list()`, `tio.server.status()`.
- `pandas==2.2.3` — DataFrame substrate for every report (`requirements.txt:5`).
- `numpy==2.2.4` — pandas dep, used directly in math/aggregations across reports (`requirements.txt:6`).
- `openpyxl==3.1.5` — Excel writer for all `.xlsx` outputs and conditional formatting (`requirements.txt:9`); imported in `exporters/excel_exporter.py` and per-module Excel renderers under `reports/modules/`.
- `matplotlib==3.10.1` — static PNG charts embedded in PDFs and emails (`requirements.txt:12`).
- `plotly==6.0.1` + `kaleido==0.2.1` — interactive `.html` charts plus static PNG export via Kaleido (`requirements.txt:13-14`). Kaleido is the static-image renderer required by Plotly's `write_image()`.
- `weasyprint==65.1` — HTML → PDF rendering (`requirements.txt:17`); imported lazily inside `exporters/pdf_exporter.py:515`, `reports/board_summary.py:350`, and `reports/management_summary.py:1236` to keep import-time cost down.
- `python-dotenv==1.1.0` — `.env` loader (`requirements.txt:20`); called in `tenable_client.py:53`, `config.py:16`, `delivery/email_sender.py:61`, `scheduler.py:49`, `run_all.py:48`.
- `PyYAML==6.0.2` — `delivery_config.yaml` parser (`requirements.txt:21`); used in `run_all.py:47` (`yaml.safe_load` at `run_all.py:153`).
- `Jinja2==3.1.6` — email body templating (`requirements.txt:27`); `Environment(loader=FileSystemLoader(...), autoescape=select_autoescape(...))` at `delivery/email_template.py:56-57`.
- `tenacity==9.1.2` — exponential backoff for both Tenable API fetches and SMTP sends (`requirements.txt:30`). Tenable retry policy: `data/fetchers.py:162-168` (`wait_exponential(multiplier=2, min=4, max=60)`, `stop_after_attempt(5)`). SMTP retry policy: `delivery/email_sender.py:91-97` (`wait_exponential(multiplier=2, min=4, max=30)`, `stop_after_attempt(3)`).
- `rich==14.0.0` — CLI tables and progress bars (`requirements.txt:33`); `Console`, `Table`, `box` used by `run_all.py`, `delivery/delivery_log.py`, `utils/tag_helper.py`; `Progress`/`SpinnerColumn` used during exports in `data/fetchers.py:245-251` and `data/fetchers.py:376-382`.
- `fastparquet` (unpinned, `requirements.txt:36`) — explicitly selected via `engine="fastparquet"` in `data/fetchers.py:184` (`pd.read_parquet`) and `data/fetchers.py:192` (`df.to_parquet`). pyarrow is intentionally not used.
- `jsonschema==4.23.0` — declared in `requirements.txt:39` for delivery-config schema validation (`delivery_config.schema.yaml`), but not actually imported anywhere in the project source. Validation is currently performed by hand-rolled checks in `run_all.py:241-318` (`_validate_group()`).
- `tzdata==2025.2` — timezone database (`requirements.txt:42`); required on Windows hosts where IANA tz data is otherwise unavailable. UTC handling in `data/fetchers.py:1142` (`pd.to_datetime(..., utc=True, errors="coerce", format="ISO8601")`).
- `requests` — pulled in transitively by pyTenable; imported lazily inside `data/fetchers.py:586` (`import requests as _requests`) for the direct `POST /v1/recast/rules/search` call that pyTenable does not wrap.
- `restfly` — transitive dep of pyTenable; `restfly.errors.UnauthorizedError` aliased to `AuthenticationError` at `tenable_client.py:22`.
- `smtplib` (stdlib) — SMTP transport in `delivery/email_sender.py:33`. Both `smtplib.SMTP` (STARTTLS) and `smtplib.SMTP_SSL` paths implemented at `delivery/email_sender.py:245-265`.
- `email.mime.*` (stdlib) — `MIMEMultipart`, `MIMEText`, `MIMEImage`, `MIMEBase`, `encoders` imported at `delivery/email_sender.py:38-42`.
- `sqlite3` (stdlib) — delivery audit log at `delivery/delivery_log.py:28`; WAL journal mode set at `delivery/delivery_log.py:84`.
## Configuration
- All secrets and connection settings are loaded from a single `.env` file at the repo root via `python-dotenv`. `.env.example` is committed as the onboarding template.
- Tenable creds (required): `TVM_ACCESS_KEY`, `TVM_SECRET_KEY` (`tenable_client.py:55-67`). Optional: `TVM_URL` (defaults to `https://cloud.tenable.com` at `tenable_client.py:57`).
- SMTP creds (required for delivery): `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, `SMTP_FROM_NAME` (read at `delivery/email_sender.py:75-85`). Optional: `SMTP_USE_SSL` (string `"true"` flips port-465 SSL path).
- Optional overrides: `MAX_ATTACHMENT_SIZE_MB` (`config.py:201`, default 25), `LOG_LEVEL` (`config.py:206`, default `INFO`).
- `--dry-run` enforces presence of `TVM_ACCESS_KEY`, `TVM_SECRET_KEY`, `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS` (`run_all.py:117-124`).
- No build step. The project ships as a directory of `.py` source files plus the `.venv/` virtualenv on the deploy host.
- `delivery_config.schema.yaml` is the JSON-Schema-format validator for `delivery_config.yaml` (intended for editor / CI use; not currently enforced at runtime — see `jsonschema` note above).
## Platform Requirements
- Python 3.10+.
- Local virtualenv (`.venv/`) populated by `pip install -r requirements.txt`.
- WeasyPrint requires GTK/Pango/Cairo native libs on Windows; on Linux/RHEL these are typically installed via `pango`, `cairo`, `gdk-pixbuf2` system packages.
- Linux host running systemd is the documented deployment target. Sample unit at `deploy/vuln-reports.service` expects:
- Cron / Windows Task Scheduler also supported via `python scheduler.py --mode run-due` invoked every 5–10 minutes (CLAUDE.md `Mode 2`).
- Outbound network access required to Tenable.io (`https://cloud.tenable.com`) and the configured SMTP relay.
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Module Header & Imports
## Naming Patterns
### Files & Modules
| Kind | Pattern | Example |
|------|---------|---------|
| Report scripts | `reports/<slug>.py` (snake_case slug) | `reports/board_summary.py`, `reports/ops_remediation.py` |
| Metric modules | `reports/modules/<name>_module.py` (auto-discovered by `*_module.py` glob) | `reports/modules/scan_coverage_sla_module.py` |
| Utilities | `utils/<area>.py` | `utils/sla_calculator.py`, `utils/formatters.py` |
| Data fetchers | `data/fetchers.py` (single module) | — |
### Identifiers
- **Functions, variables, parameters:** `snake_case` — `run_report`, `vulns_df`, `tag_category`.
- **Classes:** `PascalCase` — `BaseModule`, `ScanCoverageSLAModule`, `ReportComposer`, `ModuleRegistry`.
- **Constants:** `UPPER_SNAKE_CASE` at module top — `SLA_DAYS` (`config.py:28`), `_VALID_REPORTS` (`run_all.py:75`), `DEFAULT_SEVERITIES` (`reports/vuln_export.py:67`).
- **Module-private helpers/constants:** leading underscore — `_extract_plugin_id_from_filter` (`data/fetchers.py:46`), `_BOARD_MODULE_CONFIGS` (`reports/board_summary.py:66`), `_REPORT_MODULE_MAP` (`run_all.py:102`), `_PDF_CSS` (`reports/modules/composer.py:63`).
- **Class constants on `BaseModule` subclasses:** `MODULE_ID`, `DISPLAY_NAME`, `DESCRIPTION`, `REQUIRED_DATA`, `SUPPORTED_OUTPUTS`, `VERSION` — see `reports/modules/base.py:163-174` and `reports/modules/scan_coverage_sla_module.py:97-104`.
- **DataFrame variables:** suffix `_df` — `vulns_df`, `assets_df`, `fixed_vulns_df`. Booleans: prefix `is_` / `has_` — `is_overdue`, `has_plugin_results`.
### Report slugs
### `MODULE_ID` strings
## Type Hints
- `list[str]`, `dict[str, int]`, `tuple[int, str]` — never `List[str]`, `Dict[...]`.
- `Optional[X]` from `typing` is still used in function signatures (`utils/sla_calculator.py:19,32-37`, `run_all.py:45`); newer files freely mix `X | None` (`reports/modules/registry.py:136-148`).
- Class attribute annotations use the same modern syntax — `_VALID_REPORTS: frozenset[str]` (`run_all.py:75`), `MODULE_ID: str = ""` (`reports/modules/base.py:163`).
- Function return types are annotated wherever practical; `-> None` is explicit on side-effecting helpers (e.g. `_save_cache` at `data/fetchers.py:188`).
## Docstring Style
- One-line summary.
- Optional extended description.
- `Parameters` section with name, type, description.
- `Returns` section.
- `Examples` for utility functions where doctests are useful (`config.py:106-114`, `utils/formatters.py:44-49,206-213`).
## Logging
### Log message conventions
- **Group/Report-prefixed messages** use bracketed identifiers: `logger.info("[%s] Running report: %s", group_name, slug)` (`run_all.py:583`), `logger.warning("[%s] Pre-fetch failed (%s) — reports will attempt to fetch individually.", ...)` (`run_all.py:563`).
- **Phase markers** for cache and API events: `[CACHE HIT]` (`data/fetchers.py:183`), `[API FETCH]` (`data/fetchers.py:236, 368, 477`).
- **Section dividers** in logs use `===`: `"=== Starting group '%s' (trigger=%s, run_id=%s) ==="` (`run_all.py:502-504`).
- Use `%s` / `%d` lazy formatting — never `f"{...}"` — so the log level filter elides formatting work for suppressed records.
- `logger.exception` is rarely used; instead, `logger.error("[%s] %s\n%s", group_name, msg, traceback.format_exc())` is the prevailing pattern (`run_all.py:521, 605, 636`).
- Module-level helpers expose `_log_prefix(self) -> "[module:<id>]"` (`reports/modules/base.py:424-426`) for use inside metric modules.
### Log configuration
## Error Handling
## Datetime & Timezone Handling
| Purpose | Clock | Format / Constructor |
|---------|-------|----------------------|
| Report timestamps, SLA math, `generated_at`, `as_of` | UTC | `datetime.now(tz=timezone.utc)` |
| Schedule matching, cache folder names, output folder names | Server local | `datetime.now()` (no tzinfo) |
- UTC for report content: `run_all.py:485, 863`, `reports/board_summary.py:129`, `utils/sla_calculator.py:67`, `utils/formatters.py:319`.
- Local for cache folder names: `run_all.py:487, 489, 864-867`, `reports/board_summary.py:131`. CLAUDE.md explicitly mandates this (cache by local date).
- Local for schedule matching: `run_all.py:830` — `_is_due()` accepts a local `now`, see comment at `run_all.py:188-189`.
## Pandas Patterns
### `.assign()` chains, not in-place mutation
### `np.select` for multi-condition labels
### `filter_by_*` family
### Empty-DataFrame guards
### Categorical for ordered enums
### Caching layer
## Dataclasses
- `ModuleConfig` (`reports/modules/base.py:43-75`) — what the caller hands to a module: `module_id` and an `options: dict` for forward-compatible per-group customization.
- `ModuleData` (`reports/modules/base.py:78-126`) — what `compute()` returns: `module_id`, `display_name`, `metrics`, `table_data`, `chart_data`, `summary_text`, `metadata`, `error`. **Always populate every field on success; on failure, set `error` and leave data fields empty** (use `BaseModule._empty_result`).
## The `@register_module` Decorator Pattern
## The Slug → Module Triple-Registration Rule
## Function Design
- **Keyword-only arguments after `*` for optional/configuration kwargs** — see `run_group` (`run_all.py:424-437`) and `run_report` (`reports/board_summary.py:82-91`).
- **Helpers are module-private (`_leading_underscore`)** when not part of the public API — `_validate_group`, `_dry_run`, `_print_summary`, `_import_report`, `_load_config`, `_is_due`, `_first_str`, `_normalize_vuln_dates`.
- **Public entry points are short and orchestrate** rather than do work inline — `main()` at `run_all.py:742-905` parses args, loads config, dispatches; the heavy lifting lives in `run_group()`.
- **Pure helpers** (no I/O, no API calls) live in `utils/` and are explicitly noted as such — `utils/formatters.py:6` ("All functions are pure (no I/O, no API calls) and safe to import anywhere").
## CLI Convention
- `run_all.py:764-802`
- `utils/tag_helper.py:228-269`
- `utils/sla_calculator.py:305-328` (smoke-test entry point)
## Module-Level Constants Block
## Comments
- **Section banners** use `# ===` lines or `# ---` for nested subsections.
- **`# noqa: PLC0415`** marks intentional in-function imports done to break circular-import chains or defer heavy SDK loading — `run_all.py:515, 554, 631, 849`.
- **`# noqa: BLE001`** marks intentional broad-`Exception` catches.
- Inline TODOs/HACKs are absent from the analyzed sample — when present, prefer adding a `concerns` entry rather than leaving an unannotated comment.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## System Overview
```text
```
## Component Responsibilities
| Component | Responsibility | File |
|-----------|----------------|------|
| Master CLI runner | Parse args, load YAML, schedule-match, drive `run_group()` for each selected group | `run_all.py:742` |
| `run_group()` | Single shared per-group execution: pre-fetch → loop reports → email | `run_all.py:424` |
| Scheduler | APScheduler daemon, run-due trigger, manual mode — all delegate to `run_group()` | `scheduler.py:1` |
| Tenable client factory | Build authenticated `TenableIO` from `.env`, validate connection, exit on failure | `tenable_client.py:40` |
| Shared config | SLA constants, severity / VPR maps, color palette, paths (`ROOT_DIR`, `CACHE_DIR`, `OUTPUT_DIR`, `LOG_DIR`) | `config.py:1` |
| Data fetchers | All `tio.exports.*` calls + parquet caching + tenacity retry | `data/fetchers.py:203,339,451,554` |
| Report scripts | Per-slug `run_report(tio, run_id, **kwargs) -> dict` returning `{pdf, excel, csv, charts, metrics}` | `reports/*.py` |
| Module base / data contracts | `BaseModule` ABC + `ModuleConfig` / `ModuleData` dataclasses | `reports/modules/base.py:43,78,132` |
| Module registry | `@register_module` decorator + filename-based auto-discovery (`*_module.py`, `*_metrics.py`) | `reports/modules/registry.py:228,413` |
| Report composer | Drives `compute()` → `assemble_pdf()` / `assemble_excel()` / `collect_email_kpis()` | `reports/modules/composer.py:320,467,588,664` |
| Excel exporter | openpyxl workbook helpers and styling | `exporters/excel_exporter.py` |
| PDF exporter | WeasyPrint HTML→PDF wrappers (also embedded inside composer for board/management) | `exporters/pdf_exporter.py` |
| Chart exporter | Matplotlib + Plotly chart factories; consistent `SEVERITY_COLORS` palette | `exporters/chart_exporter.py` |
| Email sender | SMTP send (STARTTLS / SSL), tenacity retry, attachment size enforcement, inline CID charts | `delivery/email_sender.py:1` |
| Email template | Jinja2 HTML body builder | `delivery/email_template.py` |
| Delivery log | SQLite audit log of every send attempt + inspection CLI | `delivery/delivery_log.py` |
| SLA / tag / formatter utils | Severity SLA math, tag enrichment, filename / timestamp formatters | `utils/sla_calculator.py`, `utils/tag_helper.py`, `utils/formatters.py` |
## Pattern Overview
- **Single shared executor.** `run_group()` is the sole entry point for "run one delivery group" — all CLI modes converge there (`run_all.py:424`, `scheduler.py:54` imports it).
- **Fail-soft batches.** A failure in one report never aborts the rest of the group; a failure in one group never aborts other groups (`run_all.py:603`, `run_all.py:884`).
- **Run-scoped parquet cache.** Pre-fetch warms `data/cache/<YYYY-MM-DD>/` once per batch; every report in the batch hits `[CACHE HIT]` instead of re-calling Tenable (`run_all.py:553`, `data/fetchers.py:175`).
- **Standard report contract.** Every `reports/<slug>.py` exposes `run_report(tio, run_id, **kwargs) -> dict` returning at minimum `{pdf, excel, charts}`; CSV-only reports add `csv` (`run_all.py:585`).
- **Auto-discovery for modules.** Importing `reports.modules` triggers `registry.discover()`, which globs `*_module.py` / `*_metrics.py`, imports each, and lets `@register_module` self-register the class (`reports/modules/__init__.py:67`, `reports/modules/registry.py:228`).
- **Pure compute, deferred render.** `BaseModule.compute()` is contractually side-effect-free; `render_pdf_section()` / `render_excel_tabs()` / `render_email_kpis()` are called later by the composer (`reports/modules/base.py:180-225`).
## Layers
- Purpose: Resolve which groups run now, supply shared `tio`, `run_id`, `cache_dir`, `generated_at`, and dispatch `run_group()`.
- Depends on: `tenable_client`, `config`, `data.fetchers`, `reports.*`, `delivery.email_sender`.
- Used by: end users (CLI), cron / Task Scheduler (`--mode run-due`), systemd (`--mode daemon`).
- Purpose: Tunable constants and per-group routing — recipients, schedules, filters, report list.
- Depends on: nothing.
- Used by: every other layer.
- Purpose: Single source of truth for Tenable export jobs and their normalized DataFrame outputs.
- Pattern: function-per-dataset; read parquet if present, otherwise call `tio.exports.*`, normalize, write parquet, return DataFrame.
- Depends on: `pyTenable`, `tenacity`, `config.CACHE_DIR`.
- Used by: report scripts (and indirectly modules, via the composer's caller).
- Purpose: One slug per audience-specific report. Owns its own data assembly, formatting, and output writing.
- Depends on: `data.fetchers`, `exporters/*`, `utils/*`, optionally `reports.modules`.
- Used by: `run_all.run_group()` via dynamic import driven by `_REPORT_MODULE_MAP` (`run_all.py:102`).
- Purpose: Reusable, independently-testable metric modules + the composer that assembles them into PDFs/Excel/email KPIs. Used by `board_summary` and `management_summary`.
- Depends on: `pandas`, `openpyxl`, `WeasyPrint` (via PDF assembly), `chart_utils`, `board_report_utils`.
- Used by: composed reports (`reports/board_summary.py:57`, `reports/management_summary.py`).
- Purpose: Format-conversion helpers (HTML→PDF, dict/df→XLSX, df→PNG/HTML chart).
- Depends on: `weasyprint`, `openpyxl`, `matplotlib`, `plotly`.
- Used by: report scripts and module renderers.
- Purpose: Email assembly, SMTP send with retries, audit logging.
- Depends on: `smtplib`, `email.mime`, `tenacity`, `Jinja2`, `sqlite3`, `config.MAX_ATTACHMENT_SIZE_MB`.
- Used by: `run_group()` after report generation (`run_all.py:631`).
- Purpose: SLA calculation (`sla_calculator.py`), tag discovery / asset-by-tag fetch (`tag_helper.py`), filename + timestamp formatting (`formatters.py`).
- Used by: every layer above.
## Data Flow
### Primary "scheduled batch" path
### Composed-report sub-flow (e.g. `board_summary`)
- No long-lived state; the daemon mode keeps APScheduler in-process but each fired job calls the same stateless `run_group()`.
- Trend snapshots persist between runs in `data/trend/management_summary_<scope>.json` for `management_summary`'s month-over-month metric.
- Run-scoped state (`tio`, `run_id`, `cache_dir`, `generated_at`) is created once per batch and passed by argument — no globals are mutated between groups.
## Key Abstractions
- Purpose: One delivery group, end-to-end — the unit of execution shared by every entry point.
- File: `run_all.py:424`.
- Pattern: Function with rich keyword args; never raises, always returns a result dict (`{group_name, status, output_folder, duration_seconds, reports_generated, email_status, error}`).
- Purpose: Standard contract every report module must implement.
- Examples: `reports/board_summary.py:82`, `reports/vuln_export.py:357`, `reports/ops_remediation.py:2625`.
- Returns: `{"pdf": path|None, "excel": path|None, "charts": [paths], "csv": path|None (optional), "metrics": dict (optional)}`.
- Purpose: Contract for a single board/management metric — `compute()` (abstract, pure) plus default no-op `render_pdf_section()` / `render_excel_tabs()` / `render_email_kpis()` that subclasses override based on `SUPPORTED_OUTPUTS`.
- File: `reports/modules/base.py:132`.
- Purpose: Typed data contract between `compute()` and renderers — `metrics`, `table_data`, `chart_data`, `summary_text`, `metadata`, `error`.
- File: `reports/modules/base.py:43,78`.
- Purpose: Module discovery/lookup. Self-registration via `@register_module`, file-glob auto-discovery on package import.
- File: `reports/modules/registry.py:59,410,413`.
- Purpose: Orchestrate module execution and assemble outputs. Owns no metric logic.
- File: `reports/modules/composer.py:288`.
## Entry Points
- Location: `run_all.py:742`.
- Triggers: User runs `python run_all.py [--group | --dry-run | --no-email | --tag-category | --tag-value | --recipients]`.
- Responsibilities: Logging setup, arg parsing, `.env` load, config load + validate, group selection, shared `tio` + `cache_dir` setup, loop `run_group()`, print rich summary, set exit code.
- Location: `scheduler.py:1`.
- Triggers:
- Responsibilities: Mode-specific scheduling/argument handling; delegates execution to `run_group()`.
- Location: each report has `if __name__ == "__main__": argparse + run_report(get_client(), ...)`.
- Triggers: Standalone reproduction / debugging without the YAML config (e.g. `python reports/board_summary.py --tag-category "Environment" --tag-value "Production"`).
- Location: `tenable_client.py:140`.
- Triggers: `python tenable_client.py` — connectivity smoke test.
## Extension Points
- Add a new function in `data/fetchers.py` next to existing `fetch_*` functions; reuse `_cache_path` / `_load_cache` / `_save_cache` (`data/fetchers.py:175-200`) and `tenacity` retry decorators.
## Architectural Constraints
- **Threading:** Single-threaded by default. APScheduler daemon mode runs jobs serially in its own background thread; nothing in the report layer is thread-safe and `ModuleRegistry` is explicitly documented as not designed for concurrent mutation (`reports/modules/registry.py:71`).
- **Global state:**
- **Import-time side effects:** Importing `reports.modules` runs `registry.discover()`, which imports every `*_module.py` in the package. Module files must be importable without external resources.
- **Namespace collision avoidance:** `run_all.py:62-64` deletes any pre-existing `reports`, `data`, `utils` modules from `sys.modules` before adding the project root, so a pip-installed `reports` package on the host can't shadow project-local code. Each project package directory has its own `__init__.py` to guarantee non-namespace-package status.
- **Date / timezone policy:** Cache folder names use **local** machine date (`run_all.py:864`, `run_all.py:870`); report timestamps use **UTC** (`run_all.py:863`). Stale cache folders from prior local-days are pruned at the start of each batch (`run_all.py:870`).
## Anti-Patterns
### Hardcoding new reports outside the three registration sites
### Manual module imports in board/management reports
### Side effects in `BaseModule.compute()`
### Raising exceptions out of report code
## Error Handling
- **`run_group()`** — wraps the Tenable connection, every `run_report()` call, and the email send; returns a status dict instead of raising (`run_all.py:519`, `run_all.py:603`, `run_all.py:634`).
- **`ReportComposer.run_module()`** — catches `validate_config()` and `compute()` exceptions and returns a `ModuleData` with `error` set (`reports/modules/composer.py:355,429`).
- **`registry.discover()`** — broken module file logs a warning, other modules still load (`reports/modules/registry.py:391`).
- **`send_report_email()`** — never raises; tenacity retries SMTP-class errors up to 3 times with exponential backoff; final failure logged and recorded in `delivery_log.db` (`delivery/email_sender.py:91`).
- **`tenable_client.get_client()`** — fatal-only path: missing env vars or bad credentials → `sys.exit(1)` with a clear message; everything downstream assumes the client is valid.
## Cross-Cutting Concerns
- `run_all.py:742` configures root logging (`StreamHandler` + `FileHandler(LOG_DIR/'app.log')`) with a third-party noise filter for `fontTools` and `weasyprint.progress` (`run_all.py:724`).
- `scheduler.py` uses a `RotatingFileHandler` on `logs/scheduler.log` (`scheduler.py:60`).
- Each module emits via `logger = logging.getLogger(__name__)` so log lines are namespaced by file.
- `--dry-run` runs `_validate_group()` on every group, checks required `.env` vars, prints a rich validation table, and exits non-zero on any error (`run_all.py:321`).
- `delivery_config.schema.yaml` is a JSON Schema for editor / CI validation of the YAML.
- `BaseModule.validate_config()` is called by the composer before `compute()` (`reports/modules/composer.py:399`).
- Single chokepoint: `tenable_client.get_client()` (`tenable_client.py:40`). All keys come from `.env` via `python-dotenv`; never hardcoded.
- SMTP credentials are also `.env`-only (`delivery/email_sender.py:75`).
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
