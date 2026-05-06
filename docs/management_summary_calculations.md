# Management Executive Summary — Calculations Runbook

**File:** `reports/management_summary.py`
**Audience:** Senior Management — Directors and Vice Presidents
**Outputs:** PDF (5 pages) + HTML email body (no Excel)
**Schedule:** Monthly (first of the month recommended)

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [How to Activate Scheduled Delivery](#2-how-to-activate-scheduled-delivery)
3. [CLI Reference](#3-cli-reference)
4. [Data Sources](#4-data-sources)
5. [SLA Definitions](#5-sla-definitions)
6. [Metric 1 — Total Open Vulnerabilities by Severity](#6-metric-1--total-open-vulnerabilities-by-severity)
7. [Metric 2 — Asset Scan Coverage](#7-metric-2--asset-scan-coverage)
8. [Metric 3 — Mean Time to Remediate (MTTR)](#8-metric-3--mean-time-to-remediate-mttr)
9. [Metric 4 — SLA Compliance Rate](#9-metric-4--sla-compliance-rate)
10. [Metric 5 — Vulnerability Age Distribution](#10-metric-5--vulnerability-age-distribution)
11. [Metric 6 — Managed Exception Rate](#11-metric-6--managed-exception-rate)
12. [Metric 7 — Month-over-Month Trend](#12-metric-7--month-over-month-trend)
13. [Gauge Color Zones](#13-gauge-color-zones)
14. [PDF Structure](#14-pdf-structure)
15. [Email Structure](#15-email-structure)
16. [Output Files](#16-output-files)
17. [Trend Data Store](#17-trend-data-store)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Quick Start

```bash
# Test gauges (no Tenable connection)
python reports/management_summary.py --test-gauge

# Test PDF with synthetic data (no Tenable connection)
python reports/management_summary.py --test-pdf

# Test email preview with synthetic data (no Tenable connection)
python reports/management_summary.py --test-email

# Run against live data, all assets
python reports/management_summary.py --no-email

# Run scoped to a specific tag, skip email
python reports/management_summary.py \
    --tag-category "Environment" --tag-value "Production" \
    --no-email

# Run and send email (requires SMTP config in .env)
python reports/management_summary.py \
    --tag-category "Environment" --tag-value "Production"
```

---

## 2. How to Activate Scheduled Delivery

Edit `delivery_config.yaml` and uncomment the example group (search for
`Monthly Management Summary`).  Update recipients, tag filter, and
`day_of_month` as needed.  Validate before the next scheduled run:

```bash
python run_all.py --dry-run
```

Example config:

```yaml
- name: "Monthly Management Summary"
  description: "First-of-month management-level PDF report"
  schedule:
    frequency: monthly
    day_of_month: 1
    time: "07:00"
  filters:
    tag_category: "Environment"
    tag_value: "Production"
  reports:
    - management_summary
  email:
    subject: "Monthly Vulnerability Management Summary — Production"
    recipients:
      - ciso@company.com
      - vp-it@company.com
    cc:
      - security-team@company.com
    reply_to: security@company.com
```

`management_summary` may be combined with other report slugs in the same
group (e.g. alongside `ops_remediation`).  The PDF and email body are
generated independently; each report attaches its own PDF.

---

## 3. CLI Reference

| Flag | Description |
|---|---|
| `--tag-category CATEGORY` | Tenable tag category to scope the report (e.g. `"Environment"`) |
| `--tag-value VALUE` | Tenable tag value to scope the report (e.g. `"Production"`) |
| `--cache-dir PATH` | Path to an existing parquet cache directory (skips API fetch) |
| `--output-dir PATH` | Output directory for PDF and email preview files |
| `--no-email` | Generate PDF and preview but skip SMTP delivery |
| `--test-gauge` | Render 8 test gauge PNGs to `output/gauge_test/` and exit |
| `--test-pdf` | Render a 5-page test PDF from synthetic data and exit |
| `--test-email` | Render an email preview HTML from synthetic data and exit |

If no tag filter is supplied the report runs against **all assets** in the
Tenable tenant.

---

## 4. Data Sources

| Data | Source | Cached As |
|---|---|---|
| Open vulnerabilities | `tio.exports.vulns()` — states `open`, `reopened` | `vulns_all.parquet` |
| Fixed vulnerabilities | `tio.exports.vulns()` — state `fixed` | `vulns_fixed.parquet` |
| Asset inventory | `tio.exports.assets()` | `assets_all.parquet` |

All three parquet files are shared with other reports running in the same
`run_all.py` batch.  Cache files are named by local machine date
(`YYYY-MM-DD`); prior-day caches are automatically deleted at the start of
each batch run.

Severity is derived from the **VPR score** (`vpr_score` field), not the
native Tenable severity field.  When `vpr_score` is null the native severity
is used as a fallback.

---

## 5. SLA Definitions

| Severity | VPR Score Range | SLA (Days to Remediate) |
|---|---|---|
| Critical | 9.0 – 10.0 | 15 days |
| High | 7.0 – 8.9 | 30 days |
| Medium | 4.0 – 6.9 | 90 days |
| Low | 0.1 – 3.9 | 180 days |

A finding is **overdue** when `today − first_found_date > SLA_days` and the
finding is still open.  "Today" is the UTC report timestamp passed into
`compute_all_metrics()`.

---

## 6. Metric 1 — Total Open Vulnerabilities by Severity

**PDF location:** Page 2, KPI tile row
**Email location:** KPI tile strip (tiles 1 and 2)

### What it measures

A simple count of all currently open findings, broken down by severity.
"Open" means `state` is `open` or `reopened` in the Tenable export.

### Formula

```
open_df     = vulns WHERE state IN {"open", "reopened"}
critical    = count(open_df WHERE severity == "critical")
high        = count(open_df WHERE severity == "high")
medium      = count(open_df WHERE severity == "medium")
low         = count(open_df WHERE severity == "low")
total       = critical + high + medium + low
```

### Edge cases

- Findings with no VPR score fall back to the native Tenable severity label.
- The `info` severity is excluded from all counts throughout this report.
- If `vulns_df` is empty all counts return 0.

---

## 7. Metric 2 — Asset Scan Coverage

**PDF location:** Page 2, right column gauge
**Email location:** KPI tile 4 (Scan Coverage)

### What it measures

The percentage of Tenable-licensed assets that received at least one
authenticated scan within the past 30 days.  Assets outside this window have
an unknown risk posture.

### Formula

```
licensed        = assets WHERE last_licensed_scan_date IS NOT NULL
cutoff          = report_date − 30 days
scanned         = licensed WHERE last_licensed_scan_date >= cutoff
coverage_pct    = (len(scanned) / len(licensed)) × 100
not_scanned     = len(licensed) − len(scanned)
```

### Status thresholds

| Coverage | Status | Color |
|---|---|---|
| ≥ 95 % | Good | Green |
| 80 – 94 % | Needs Attention | Amber |
| < 80 % | At Risk | Red |

### Edge cases

- If `assets_df` is empty or `last_licensed_scan_date` is not present in the
  export, all fields return 0 and `error` is set to a descriptive message.
  The PDF and email display a "No data" placeholder instead of a gauge.
- The 30-day window is evaluated against the report's UTC timestamp, not the
  local machine clock.

---

## 8. Metric 3 — Mean Time to Remediate (MTTR)

**PDF location:** Page 3, four-gauge row
**Email location:** Not shown directly (context for Metric 4)

### What it measures

The average number of days between a vulnerability being first observed and
its confirmed remediation, grouped by severity.  Calculated from the
**fixed** vulnerability export (`vulns_fixed.parquet`), not open findings.

### Formula

```
For each fixed finding in fixed_vulns_df:
    IF time_taken_to_fix IS NOT NULL AND time_taken_to_fix > 0:
        days_to_fix = time_taken_to_fix / 86400          # seconds → days
    ELSE:
        days_to_fix = (last_fixed − first_found).days    # date fallback

MTTR[severity] = mean(days_to_fix) for findings of that severity
```

`time_taken_to_fix` is the authoritative field when populated (set by
Tenable at fix-time in seconds).  The date-arithmetic fallback is used when
the field is absent or zero.

### Status thresholds (per severity)

| MTTR vs SLA | Status | Color |
|---|---|---|
| ≤ 80 % of SLA | Within SLA | Green |
| 81 – 100 % of SLA | Approaching SLA | Amber |
| > 100 % of SLA | Exceeding SLA | Red |

Example for Critical (SLA = 15 days): green ≤ 12 d, amber 12–15 d, red > 15 d.

### Edge cases

- When no fixed vulnerabilities exist for a severity tier, MTTR returns
  `None` for that tier.  The PDF renders a "No data" placeholder instead of
  a gauge.
- MTTR is calculated across the entire fixed history in the export, not just
  the current month.  It reflects the programme's overall remediation
  performance, not just recent activity.
- The fixed vuln export does not support the same tag filtering as the open
  vuln export.  Tag filtering is applied post-export by matching `asset_uuid`
  values between the fixed vulns and the asset export.

---

## 9. Metric 4 — SLA Compliance Rate

**PDF location:** Page 3, compliance gauge + per-severity tiles
**Email location:** KPI tile 3 (SLA Compliance)

### What it measures

The percentage of **currently open** findings whose age has not yet exceeded
the SLA deadline for their severity.  A finding first seen today counts as
within SLA; a Critical finding open for 16 days is overdue.

### Formula

```
open_df         = vulns WHERE state IN {"open", "reopened"}
days_open       = (report_date − first_found_date).days
sla_for_sev     = SLA_DAYS[severity]          # 15 / 30 / 90 / 180
within_sla      = open_df WHERE days_open <= sla_for_sev
overall_rate    = (len(within_sla) / len(open_df)) × 100

per_severity[sev] = {
    rate:       (count within SLA for sev / count open for sev) × 100,
    within_sla: count within SLA for sev,
    total:      count open for sev,
}
```

### Status thresholds (overall rate)

| Compliance | Status | Color |
|---|---|---|
| ≥ 90 % | On Target | Green |
| 75 – 89 % | Below Target | Amber |
| < 75 % | At Risk | Red |

### Edge cases

- When `open_df` is empty `overall_rate` returns `None` and the gauge
  displays "No data".
- Findings with a null `first_found_date` are excluded from the calculation
  (cannot determine SLA status without an open date).
- The compliance rate counts all open findings regardless of whether they
  have a managed exception (accepted/recast).  Exception findings that are
  overdue still reduce the compliance rate.  See Metric 6 for exception
  counts.

---

## 10. Metric 5 — Vulnerability Age Distribution

**PDF location:** Page 4, horizontal bar chart
**Email location:** Inline CID chart (chart_1)

### What it measures

The number of currently open findings in each age band, showing how long
the existing backlog has been present.

### Age bands

| Band | Days Open | Bar Color |
|---|---|---|
| 0–30 days | 0 – 30 | Green |
| 31–60 days | 31 – 60 | Light green |
| 61–90 days | 61 – 90 | Yellow |
| 91–180 days | 91 – 180 | Orange |
| 181–365 days | 181 – 365 | Deep orange |
| 365+ days | 366+ | Red |

### Formula

```
open_df     = vulns WHERE state IN {"open", "reopened"}
days_open   = (report_date − first_found_date).days

For each band (min_days, max_days):
    count = count(open_df WHERE min_days <= days_open <= max_days)
    pct   = (count / len(open_df)) × 100
```

### Edge cases

- Findings with a null `first_found_date` are assigned `days_open = 0`
  and fall into the 0–30 band.
- When `open_df` is empty all counts are 0 and the chart renders with empty
  bars.
- Percentages are rounded to one decimal place.  Due to rounding, the sum of
  displayed percentages may occasionally be 99.9 % or 100.1 %.

---

## 11. Metric 6 — Managed Exception Rate

**PDF location:** Page 4, two large numbers
**Email location:** KPI tile 5 (Exception Rate)

### What it measures

The percentage of open findings that have been formally reviewed and approved
for handling outside the standard SLA.  Includes both:

- **Risk acceptances** — finding acknowledged as residual risk
  (`severity_modification_type == "ACCEPTED"`)
- **Severity recasts** — finding severity adjusted by a security analyst
  (`severity_modification_type == "RECASTED"`)

Both types represent active management decisions and are counted together.

### Formula

```
open_df          = vulns WHERE state IN {"open", "reopened"}
accepted_mask    = open_df WHERE severity_modification_type
                               .upper() IN {"ACCEPTED", "RECASTED"}
open_exceptions  = count(accepted_mask)
total_open       = len(open_df)
exception_rate   = (open_exceptions / total_open) × 100
```

### Status thresholds (exception rate)

| Rate | Status | Color |
|---|---|---|
| < 5 % | Low | Green |
| 5 – 15 % | Moderate | Amber |
| > 15 % | Elevated | Red |

### Edge cases

- When `total_open` is 0 the rate returns 0.0 and color is green.
- `severity_modification_type` defaults to `"none"` when null (via
  `.fillna("none")`), so missing values are never counted as exceptions.
- The exception rate is informational — a rising rate warrants review to
  confirm exceptions are justified and not masking remediation debt.

---

## 12. Metric 7 — Month-over-Month Trend

**PDF location:** Page 5, line chart + delta tiles
**Email location:** Delta row (month-over-month change numbers)

### What it measures

Change in open vulnerability counts over time, grouped into two lines:
Critical + High (highest-priority) and Medium + Low (broader hygiene).
Delta values compare the most recent two monthly snapshots.

### How trend data accumulates

Each time `run_report()` (or `__main__`) runs, a snapshot is appended to a
JSON file stored at:

```
data/trend/management_summary_<sanitised_tag>.json
```

Where `<sanitised_tag>` is derived from the tag filter, e.g.:
- All assets → `management_summary_all_assets.json`
- Environment=Production → `management_summary_environment_production.json`

The JSON file contains one entry per `(month, tag_filter)` pair.  Running
the report multiple times in the same month overwrites the existing entry for
that month — only the most recent run per month is stored.

### Formula

```
snapshots   = chronologically sorted entries from trend JSON
delta_crit_high = snapshots[-1].critical + snapshots[-1].high
              − snapshots[-2].critical − snapshots[-2].high
delta_med_low   = snapshots[-1].medium  + snapshots[-1].low
              − snapshots[-2].medium  − snapshots[-2].low
```

A **negative delta** means counts decreased (improving).
A **positive delta** means counts increased (worsening).

### Edge cases

- When fewer than 2 snapshots exist (first run for a given scope), the trend
  chart is replaced by a "Trend data is being established" notice and delta
  values display as "—".  The snapshot is still saved so the next run will
  have two data points.
- Up to 24 months of snapshots are retained per scope.  Older entries are
  pruned automatically when saving a new snapshot.
- Switching tag filters creates a separate trend file per scope; they do not
  share history.

---

## 13. Gauge Color Zones

All gauges use the same zone evaluation logic: the needle value is compared
against an ordered list of `(upper_bound, color)` thresholds.  The first
threshold whose upper bound is ≥ the value determines the color.

### Scan Coverage gauge (Metric 2)

| Zone | Range | Color |
|---|---|---|
| At Risk | 0 – 70 % | Red |
| Needs Attention | 70 – 85 % | Amber |
| Good | 85 – 100 % | Green |

### MTTR gauges (Metric 3, per severity)

The gauge range is 0 to `SLA × 2`.  Example for Critical (SLA = 15 d):

| Zone | Range | Color |
|---|---|---|
| Within SLA | 0 – 12 d | Green (80 % of SLA) |
| Approaching SLA | 12 – 15 d | Amber |
| Exceeding SLA | 15 – 30 d | Red |

The SLA value is shown as a reference tick mark on the gauge arc.

### SLA Compliance gauge (Metric 4)

| Zone | Range | Color |
|---|---|---|
| At Risk | 0 – 70 % | Red |
| Below Target | 70 – 85 % | Amber |
| Near Target | 85 – 95 % | Yellow |
| On Target | 95 – 100 % | Green |

---

## 14. PDF Structure

The PDF is rendered by WeasyPrint from an HTML string with inline CSS.
Output is letter size (8.5 × 11 in) with 0.65 in top/bottom and 0.75 in
left/right margins.

| Page | Content |
|---|---|
| 1 — Cover | Organisation name, report title, period, scope banner, generated timestamp, CONFIDENTIAL notice |
| 2 — Program Health Overview | Metric 1 KPI tiles + explanatory text; Metric 2 scan coverage gauge + asset counts |
| 3 — Remediation Performance | Metric 3 four MTTR gauges with SLA reference ticks; Metric 4 compliance gauge + per-severity tiles |
| 4 — Backlog and Risk | Metric 5 horizontal age bar chart; Metric 6 two large numbers + explanatory text |
| 5 — Trend | Metric 7 line chart (or first-run notice) + month-over-month delta tiles |

### "[Organisation Name]" placeholder

The cover page displays `[Organisation Name]` as a placeholder.  To replace
it with your organisation's name, update the string literal in `_build_pdf()`
(search for `[Organisation Name]` in `reports/management_summary.py`).

---

## 15. Email Structure

The email body is built by `build_email_body()` and uses inline CSS only
(no `<style>` blocks; compatible with Outlook, Gmail, Apple Mail).

| Section | Content |
|---|---|
| Header band | Navy background, report title, group name + timestamp |
| Scope banner | Tag filter applied or "All Assets" |
| KPI tiles | 5 tiles: Open Criticals, Open Highs, SLA Compliance %, Scan Coverage %, Exception Rate % |
| Age chart | Vulnerability age distribution bar chart embedded as `cid:chart_1` |
| Trend delta | Month-over-month change for Critical+High and Medium+Low |
| Attached report | Bullet referencing the PDF |
| SLA reference | 4-row table |
| Footer | Reply-to address, timestamp, update instructions |

The `{reply_to}` placeholder in the footer is substituted by
`email_sender.py` at send time using the `reply_to` value from
`delivery_config.yaml`.

The age chart uses a CID inline reference (`cid:chart_1`) in the email
HTML sent via SMTP.  The browser-viewable preview file replaces this with
an inline `data:image/png;base64,...` URI so it renders without an email
client.

---

## 16. Output Files

All files are written to `output/YYYY-MM-DD_HH-MM_<group-name>/management_summary/`
when run via `run_all.py`, or to `--output-dir` when run directly.

| File | Description |
|---|---|
| `management_summary_<tag>.pdf` | 5-page WeasyPrint PDF |
| `management_summary_email_preview.html` | Browser-viewable email preview (data URI charts) |

There is no Excel output — this report is PDF + email only.

---

## 17. Trend Data Store

Trend snapshots are stored as JSON files under `data/trend/`:

```
data/trend/
├── management_summary_all_assets.json
├── management_summary_environment_production.json
└── management_summary_businessunit_finance.json
```

Each file contains a list of snapshot dicts:

```json
[
  {
    "month": "2026-01",
    "tag_filter": "Environment=Production",
    "critical": 14,
    "high": 49,
    "medium": 190,
    "low": 67,
    "generated_at": "2026-01-01T07:04:22+00:00"
  },
  ...
]
```

### Manual snapshot management

To **delete trend history** for a scope (e.g. to reset after a data
migration), delete the corresponding JSON file:

```bash
del data\trend\management_summary_environment_production.json
```

The next run will create a new file and show the first-run notice.

To **backfill** a missing month, add a JSON entry manually with the
correct `month`, `tag_filter`, and severity counts.  The file is
append-safe — entries are keyed by `(month, tag_filter)` and duplicates
are overwritten, not appended.

---

## 18. Troubleshooting

### PDF renders but gauge images are missing

WeasyPrint must be able to process `data:image/png;base64,...` URIs.
Ensure WeasyPrint ≥ 53.0 is installed.  Run:

```bash
python reports/management_summary.py --test-pdf
```

and open the output PDF to confirm gauges render.

### Email preview shows broken chart image

This should not occur after the Step 4 fix.  The preview file uses inline
`data:` URIs, not CID references.  If you see a broken image, confirm
`_email_preview_html()` is being called before writing the preview file.

### RecursionError in matplotlib (Python 3.14)

The `Path.__deepcopy__` monkey-patch at the top of `management_summary.py`
fixes a known Python 3.14 / matplotlib incompatibility.  If the error
recurs after a matplotlib upgrade, check whether the upstream fix has been
applied by inspecting `matplotlib/path.py` line ~285.  The patch can be
removed once the installed matplotlib version no longer calls
`copy.deepcopy(super(), memo)` in `Path.__deepcopy__`.

### MTTR shows "No data" for all severities

`fetch_fixed_vulnerabilities()` returned an empty DataFrame.  This means
either:
- No vulnerabilities have been fixed in the Tenable tenant (unlikely in
  production).
- The Tenable export API returned no fixed-state findings.  Check the
  `vulns_fixed.parquet` cache file size; if it is near-empty, the export
  may have timed out or been rate-limited.
- The tag filter produced no fixed findings for the selected scope.

### Trend shows first-run notice every month

The trend JSON file is not persisting between runs.  Confirm that:
1. `data/trend/` directory exists and is writable.
2. The tag filter string is consistent between runs (case-sensitive).
   `Environment=Production` and `environment=production` produce different
   filenames.
3. The process has write access to the project directory.

### "No groups are due" when running via run_all.py

`management_summary` uses `frequency: monthly`.  Ensure `day_of_month` and
`time` match the current date/time within the ±10-minute window used by the
schedule matcher.  Use `--group "Monthly Management Summary"` to run
on-demand regardless of schedule:

```bash
python run_all.py --group "Monthly Management Summary" --no-email
```
