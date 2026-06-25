# Management Executive Summary — Calculations Runbook

> **HISTORICAL NOTE (18-REVIEW IN-03):** Sections 1–18 below describe the
> pre-v1.4 bespoke render path (`compute_all_metrics()` / `_compute_metric_1`…`_7`),
> which was **atomically removed in Phase 18 (GEN-01, Plan 18-04)**.
> The current authoritative runbook for the v1.4 `ReportComposer`-based pipeline
> is the **[v1.4 Module Metrics](#v14-module-metrics-post-cutover--gen-01-plan-18-04)**
> section at the bottom of this file.  The sections below are retained as
> historical context only.

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
finding is still open.  "Today" is the UTC report timestamp used by the
report composer (pre-v1.4: passed into `compute_all_metrics()`; v1.4+: the
`report_date` passed to each module's `compute()` method).

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

---

## v1.4 Module Metrics (post-cutover — GEN-01, Plan 18-04)

As of v1.4, `management_summary` is rendered by `ReportComposer` composing
seven registered metric modules.  The legacy ~2,200-line bespoke render path
was atomically removed.  This section is the authoritative auditor runbook for
the seven modules that are **actually rendered in the composed report**.

> **Scoping note:** This section is divided into two groups.  Group A documents
> the seven modules rendered in the PDF and email.  Group B documents two
> related v1.4 metric modules that are **not** rendered in `management_summary`
> but are documented here for cross-reference because they share the same
> module infrastructure and are mentioned elsewhere in phase documentation
> (external exposure and vulnerability density).  An auditor should not expect
> to see Group B metrics in the `management_summary` PDF or email.

---

### GROUP A — Modules Rendered in management_summary (the seven)

All seven modules share these common conventions:

- **Severity classification:** The `severity` column in `vulns_df` is
  VPR-derived: `vpr_to_severity()` maps `vpr_score` to Critical (9.0–10.0),
  High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9).  When `vpr_score` is
  null, the native Tenable severity field is used as a fallback.
- **SLA values** are read from `config.SLA_DAYS` (the single authoritative
  source): Critical = 15 d, High = 30 d, Medium = 60 d, Low = 120 d.
- **Open-finding predicate (QUAL-02):** Any module that counts open findings at
  a point in time uses `open_findings_at()` from `utils/open_count.py` — the
  reopened-aware two-interval predicate.  See the Reopened Temporal-Paradox
  Limitation section below for the honest bound on that approximation.
- **Empty-data guard:** All render methods use `safe_pct()`, `safe_int()`, and
  `safe_format()` from `reports.modules.format_utils` instead of inline
  f-string format specs on possibly-`None` values.  On a zero-row
  `ModuleData`, `BaseModule._empty_result()` returns a gray RAG strip cell and
  "No data in scope." driver rather than raising.
- **Data source:** `vulns_df` from `fetch_all_vulnerabilities()` (cached as
  `vulns_all.parquet`); `assets_df` from `fetch_all_assets()` (cached as
  `assets_all.parquet`).  Both are tag-filtered by the delivery group's
  `tag_category` / `tag_value` before being passed to modules.

---

#### M1 — Total Open Vulnerabilities by Severity (`total_vulns_by_severity`)

**Module ID:** `total_vulns_by_severity`
**Parity bucket:** Exact-match — zero drift vs the bespoke path on frozen fixture.

**Calculation**

```
open_df  = vulns_df WHERE state.lower() IN {"open", "reopened"}
critical = count(open_df WHERE severity == "critical")
high     = count(open_df WHERE severity == "high")
medium   = count(open_df WHERE severity == "medium")
low      = count(open_df WHERE severity == "low")
total    = critical + high + medium + low
```

The `severity` column is already VPR-derived by the fetcher upstream; this
module does not re-classify.  Informational findings are excluded upstream by
the fetcher and do not appear in `vulns_df`.

**Data Source**

- `vulns_df`: `tio.exports.vulns()` bulk export (states `open`, `reopened`),
  cached as `vulns_all.parquet`.
- Columns consumed: `state`, `severity`.

**Metrics emitted**

`metrics = {critical, high, medium, low, total, total_label}`

**Edge cases**

- `vulns_df` empty or missing `state` column: all counts return 0; no error.
- `severity` values are lowercased before comparison.
- Findings with null VPR fall back to native severity field (handled upstream
  by `vpr_to_severity()`; this module sees already-classified values).

---

#### M2 — Scan Coverage SLA (`scan_coverage_sla`)

**Module ID:** `scan_coverage_sla`
**Parity bucket:** Exact-match — zero drift vs the bespoke path on frozen fixture.

**Calculation**

```
ON_TIME_WINDOW_DAYS = 30   (from board_report_utils.ON_TIME_WINDOW_DAYS)

all_dedup      = deduplicate_assets_by_name(assets_df)
               # dedup by hostname: most-recent last_seen retained
licensed       = all_dedup WHERE last_licensed_scan_date IS NOT NULL
cutoff         = report_date − 30 days  (UTC-aware pd.Timestamp)
on_time        = licensed WHERE last_licensed_scan_date >= cutoff
not_on_time    = licensed WHERE last_licensed_scan_date < cutoff
total_licensed = len(on_time) + len(not_on_time)

scan_coverage_pct = round(len(on_time) / total_licensed × 100, 1)
```

Assets with no `last_licensed_scan_date` (unlicensed) are excluded from both
numerator and denominator.

**Status thresholds (board-defined)**

| Coverage | Status | RAG |
|---|---|---|
| ≥ 95 % | On Target | Green |
| ≥ 90 % and < 95 % | At Risk | Amber |
| < 90 % | Off Target | Red |

**Data Source**

- `assets_df`: `tio.exports.assets()`, cached as `assets_all.parquet`.
- Columns consumed: `hostname`, `last_seen`, `last_licensed_scan_date`,
  `asset_uuid`, `tags`.
- Owner breakdown uses the Tenable `"Owner"` tag category via
  `extract_owner()`; assets without an Owner tag are grouped under
  `"Unassigned"`.

**Metrics emitted**

`metrics = {scan_coverage_pct, scanned_on_time, not_scanned_on_time,
total_licensed, unlicensed_excluded, status}`

**Edge cases**

- `assets_df` empty or `last_licensed_scan_date` absent: returns `no_data`
  ModuleData; PDF and email display a "No data" placeholder.
- `total_licensed == 0`: `scan_coverage_pct` is `None`; status is `"no_data"`.
- Deduplication runs on all assets before the licensed split; a hostname whose
  most-recent record is unlicensed does not retain an older licensed duplicate.

---

#### M3 — MTTR Trend (rolling-30) (`mttr_trend`)

**Module ID:** `mttr_trend`
**Parity bucket:** Exact-match — zero drift vs the bespoke path on the rolling-30
value on the frozen fixture.

**Calculation**

```
# Population: durably-FIXED findings in rolling window (D-16-01)
# Never uses "state == fixed OR last_fixed.notna()" — that re-includes REOPENED.
fixed_df = fixed_vulns_df WHERE state.upper() == "FIXED"
         AND last_fixed >= report_date − mttr_window_days
         (default mttr_window_days = 30)

# Reopened-aware clock (D-16-02):
# COALESCE resurfaced_date when present, else first_found.
clock_start_ts = COALESCE(resurfaced_date, first_found)
days_to_fix    = (last_fixed − clock_start_ts).days  clipped >= 0

# Overall MTTR: flat sample-weighted mean across all in-window fixed findings
# NOT a mean of per-severity means (D-16-02 consequence).
overall_mttr = mean(days_to_fix)   when len(fixed_df) >= min_sample_size (default 5)

# Per-severity MTTR:
per_sev_mttr[sev] = mean(days_to_fix WHERE severity == sev)
```

The `time_taken_to_fix` Tenable field is **not used** — `days_to_fix` is
derived from date arithmetic only (D-16-02 fix).

**RAG anchor:** `overall_mttr / SLA_DAYS["critical"]` (15 d).
Green ≤ 1.0 × SLA, Amber ≤ 1.25 × SLA, Red > 1.25 × SLA.

**Rolling-30 window intent (D-16-06):** The 30-day window is a deliberate
"recent velocity" choice — it reflects the programme's current remediation
pace rather than a long-term average.  It is **not** a data availability
limit.  The window is configurable via `module_options.mttr_window_days`
in `delivery_config.yaml`.

**MoM trend line:** Read from `trend_snapshots` kwargs (persisted
`mttr_overall_days` and `mttr_by_severity` fields in the trend store written
by `capture_trend_snapshot()`).  The MoM trend line cold-starts independently
of the per-severity live gauges — if `trend_snapshots` is absent or
`insufficient_data=True`, the gauges still render from live `fixed_vulns_df`
while only the trend line shows "Month-over-month trend being established."

**Per-severity MoM direction arrows:** Derived from persisted `sev_series` via
`_owner_mom_delta()`.  MTTR is lower-is-better: delta < 0 → ▼ faster (green);
delta > 0 → ▲ slower (red); 0 or None → — flat.

**Data Source**

- `fixed_vulns_df` (kwargs, via `_MODULES_NEEDING_FIXED_VULNS` in
  `composed_report.py`): `tio.exports.vulns()` with state `fixed`, cached as
  `vulns_fixed.parquet`.
- Columns consumed: `state`, `last_fixed`, `first_found`, `resurfaced_date`,
  `severity`, `asset_uuid`.
- `trend_snapshots` (kwargs): persisted by `capture_trend_snapshot()` in the
  trend store.

**Edge cases**

- `fixed_vulns_df` absent or empty: full cold-start; gray RAG strip; `error=None`.
- No findings in the rolling window: full cold-start.
- Severity bucket with `n < min_sample_size` (default 5): renders
  "Insufficient data (N findings — minimum 5 required)".
- Current month labeled "(MTD — partial)" in all channels (D-16-08).

---

#### M4 — Patch Compliance Rate (`patch_compliance_rate`)

**Module ID:** `patch_compliance_rate`
**Parity bucket:** Exact-match — zero drift vs the bespoke path on frozen fixture.

**Calculation**

```
open_df    = vulns_df WHERE state.lower() IN {"open", "reopened"}
             AND severity IN active_severities  (default: all four)
total_open = len(open_df)

first_found = pd.to_datetime(open_df["first_found"], utc=True)
days_open   = (report_date − first_found).dt.days.fillna(0).astype(int)
sla_series  = open_df["severity"].map(config.SLA_DAYS)
within_mask = days_open <= sla_series

within_total = count(within_mask == True)
overall_rate = round(within_total / total_open × 100, 1)

per_sev_rate[sev] = (count within SLA for sev / count open for sev) × 100
```

`first_found` values that are `NaN` are treated as `days_open = 0` (always
within SLA) via `.fillna(0)`.

**Status thresholds**

| Rate | Status | RAG |
|---|---|---|
| ≥ 90 % | On Target | Green |
| ≥ 75 % and < 90 % | Below Target | Amber |
| < 75 % | At Risk | Red |

**Data Source**

- `vulns_df`: `tio.exports.vulns()`, states `open` and `reopened`.
- Columns consumed: `state`, `severity`, `first_found`.

**Metrics emitted**

`metrics = {overall_rate, critical_rate, high_rate, medium_rate, low_rate,
within_sla, overdue, total_open}`

**Edge cases**

- `vulns_df` empty or `total_open == 0`: `overall_rate` is `None`; gauge
  shows "N/A — No open vulnerabilities".
- Findings with null `first_found` are treated as `days_open = 0` (within
  SLA) — they are not excluded from the denominator.
- Optional `severity_filter` config option limits computation to named tiers;
  `overall_rate` covers only the filtered tiers when set.

---

#### M5 — Aged Vulnerability Assets (`aged_vulns_assets`)

**Module ID:** `aged_vulns_assets`
**Parity bucket:** Documented-difference — **intentional metric-design change**
from the pre-v1.4 bespoke path.  See migration parity-bucket disclosure below.

**What changed from pre-v1.4:** The bespoke `management_summary` computed a
vulnerability age-bucket histogram (count of open findings in 0–30 d, 31–60 d,
61–90 d, 91–180 d, 181–365 d, 365+ d bands).  The v1.4 module replaces this
with a percentage of *assets* carrying at least one aged finding — a more
actionable measure that surfaces assets with persistent remediation gaps rather
than raw finding counts that can be skewed by a small number of chronic hosts.

**Calculation**

```
ON_TIME_WINDOW_DAYS = 30
_AGED_DAYS_THRESHOLD = 90
_AGED_SEVERITIES = {"critical", "high", "medium"}

# Step 1: on-time asset set
on_time, _ = identify_on_time_assets(assets_df, report_date)
on_time_uuids = set(on_time["asset_uuid"].dropna())
total_on_time = len(on_time)
# identify_on_time_assets: licensed assets WHERE last_licensed_scan_date >= report_date − 30d

# Step 2: find assets with aged findings
aged_uuids = set of on_time_uuids that have >= 1 finding WHERE:
    severity IN {"critical", "high", "medium"}
    AND (report_date − first_found).days > 90
    AND asset_uuid IN on_time_uuids
# Findings with null first_found produce NaT → treated as 0 days (not aged).

aged_assets_count = len(aged_uuids)
aged_assets_pct   = round(aged_assets_count / total_on_time × 100, 1)
```

Lower is better.

**Status thresholds (board-defined)**

| Rate | Status | RAG |
|---|---|---|
| ≤ 2 % | On Target | Green |
| > 2 % and ≤ 5 % | At Risk | Amber |
| > 5 % | Off Target | Red |

**Risk Score (Owner table):** The risk score column counts
`sum(severity_weight × open_finding_count)` across **all** open
Critical/High/Medium findings on each aged-qualifying asset, not only the
findings that triggered the >90 d qualification.  This reflects the asset's
holistic risk posture.  Weights are from `config.RISK_WEIGHTS`.

**Data Source**

- `vulns_df`: open/reopened findings; columns `asset_uuid`, `severity`
  (VPR-derived), `first_found`.
- `assets_df`: `fetch_all_assets()`; columns `asset_uuid`, `hostname`,
  `last_seen`, `last_licensed_scan_date`, `tags`.
- Owner breakdown from Tenable `"Owner"` tag via `extract_owner()`.

**Edge cases**

- `total_on_time == 0`: returns `no_data` ModuleData; `aged_assets_pct` is
  `None`.
- `vulns_df` empty or missing required columns: returns `aged_assets_count = 0`.
- The M5 synthetic fixture used by the parity test is missing the `"owner"`
  column; in that fixture run M5 reaches the empty-data guard and returns a
  gray "No Data" RAG cell.  This is a fixture limitation only — real-data
  renders confirmed correct by operator visual UAT (Plan 18-04).

---

#### M6 — Accepted & Recast (`accepted_recast`)

**Module ID:** `accepted_recast`
**Parity bucket:** Exact-match — zero drift vs the bespoke path on frozen fixture
(current-period finding counts and exception rate).

**Calculation**

```
# Classification from severity_modification_type (uppercase-coerced):
mod_type = vulns_df["severity_modification_type"].astype(str).str.upper()
accepted_df = vulns_df WHERE mod_type.isin({"ACCEPTED"})
recasted_df = vulns_df WHERE mod_type.isin({"RECASTED"})
# "" / "NONE" / anything else → excluded from both counts (never silently aggregated)

# Expiry cross-check (Pitfall 6a — recast_rules_df kwarg):
# Exclude findings whose recast_rule_uuid maps to an expired rule
# (expires_at < report_date) from both accepted_df and recasted_df.
# Expired-rule findings are surfaced as "pending_reeval_count" instead.
# When recast_rules_df is absent: cross-check skipped with a WARNING log.

accepted_count   = len(accepted_df)   # after expiry exclusion
recast_count     = len(recasted_df)   # after expiry exclusion
total_exceptions = accepted_count + recast_count

# Rate denominator: total open findings (OPEN or REOPENED)
open_mask  = vulns_df["state"].astype(str).str.upper().isin({"OPEN", "REOPENED"})
total_open = count(open_mask)

exception_rate = round(total_exceptions / total_open × 100, 2)   when total_open > 0
```

ACCEPTED and RECASTED findings are tracked **separately** in all channels —
they are never silently summed.  The headline shows both counts independently.

**RAG thresholds (D-15-07, lower is better)**

| Exception rate | RAG |
|---|---|
| ≤ 5 % | Green |
| > 5 % and ≤ 15 % | Amber |
| > 15 % | Red |
| 0 exceptions | Green (regardless of denominator) |

Thresholds are overridable via `module_options.green_exception_rate` and
`module_options.yellow_exception_rate`.

**MoM delta (QUAL-01):** Prior-month `accepted_count` / `recast_count` read
from `trend_snapshots` kwargs (the `accepted_count` and `recast_count` fields
written by `capture_trend_snapshot()`).  When `trend_snapshots` is absent,
`insufficient_data=True`, or no prior completed month exists, MoM delta arrows
are **omitted entirely** — no "▲ 0%" or NaN% is shown.

**Data Source**

- `vulns_df`: columns `state`, `severity_modification_type`, `recast_rule_uuid`,
  `asset_uuid`.
- `recast_rules_df` (kwargs): from `fetch_recast_rules()` via
  `_MODULES_NEEDING_RECAST_RULES`; columns `rule_id`, `action`, `expires_at`.
- `trend_snapshots` (kwargs): for MoM delta; `accepted_count` / `recast_count`
  fields from the trend store.

**Analyst tab:** Per-rule detail (`rule_id`, `action`, `plugin_id`,
`original_severity`, `new_severity`, `expires_at`, `created_at`,
`finding_count`, `filter_summary`) — never per-finding rows.

**Edge cases**

- `vulns_df` empty or missing `severity_modification_type`: returns coherent
  zero-exception result (green RAG, `error=None`).
- `recast_rules_df` absent: cross-check skipped; headline counts still
  computed from the finding-level `severity_modification_type` field.

---

#### M7 — New vs Remediated (`new_vs_remediated`)

**Module ID:** `new_vs_remediated`
**Parity bucket:** Documented-difference — **intentional metric-design change**
from the pre-v1.4 bespoke path.  See migration parity-bucket disclosure below.

**What changed from pre-v1.4:** The bespoke `management_summary` computed a
simple month-over-month delta of total open vulnerability counts (snapshot[−1]
total − snapshot[−2] total).  The v1.4 module computes **inflow and outflow
separately**, giving management explicit visibility into whether the backlog
change is driven by new findings, re-emerging findings, or remediation velocity.

**Calculation**

```
# Inflow — two components (D-15-01/02):
# net_new:    first_found in month M (via ff_ts.dt.to_period("M") == month_period)
# resurfaced: resurfaced_date in month M AND NOT first_found in month M
#             (excludes double-count when both timestamps fall in the same month)
net_new    = count(first_found in month M)
resurfaced = count(resurfaced_date in month M AND NOT first_found in month M)
total_inflow = net_new + resurfaced

# Outflow (Option B / D-15-06):
# Sourced from aggregate snapshot field fixed_findings_count
# written by capture_trend_snapshot() — NOT from fixed_vulns_df.
outflow = trend_snapshots[month]["fixed_findings_count"]
# When absent in a snapshot → outflow displays as "—" for that month;
# no silent zero substitution.

net_delta = total_inflow − outflow   (when outflow is available)
```

**RAG (D-15-07, based on last completed month with a valid net_delta)**

| net_delta | RAG |
|---|---|
| < 0 | Green (backlog shrinking) |
| == 0 | Amber (stable) |
| > 0 | Red (backlog growing) |
| absent / None | no_data (gray) |

**Data Source**

- `vulns_df`: columns `first_found`, `resurfaced_date`, `asset_uuid`, `state`.
- `trend_snapshots` (kwargs): snapshot list with `fixed_findings_count` field
  (written by `capture_trend_snapshot()` in plan 15-02); **not** `fixed_vulns_df`.
- `assets_df`: for Owner cut via `extract_owner()`; `open_findings_at()` at
  `report_date` (QUAL-02) provides the current open count per Owner.

**Metrics emitted**

`metrics = {months, last_net_delta, rag_status, cold_start, owner_counts}`

`table_data` per month: `{month, net_new, resurfaced, total_inflow, outflow, net_delta}`

**Cold-start (QUAL-01):** When `trend_snapshots` is absent or
`insufficient_data=True`, returns a coherent "Trend data being established"
ModuleData with `error=None` and `cold_start=True`.

**Edge cases**

- Current month labeled "(MTD — partial)" in all channels (D-15-08).
- Snapshots without `fixed_findings_count` (older format) show "—" for outflow
  and net_delta — no silent zero.
- `vulns_df` empty: cold-start returned.

---

### GROUP B — Related v1.4 Disclosures NOT Rendered in management_summary

The following two modules are part of the v1.4 module library and share the
same `BaseModule` infrastructure, but they are **not included** in
`management_summary`'s `_MGMT_MODULE_CONFIGS` list and therefore do not appear
in the composed PDF or email.  They are documented here so auditors reviewing
v1.4 phase documentation are not confused by references to these module IDs in
research or planning artifacts.

**If you expect to see "External Exposure" or "Vulnerability Density" in a
`management_summary` PDF — you will not.  These are separate modules used by
other composed reports (e.g., `board_summary`) or not yet wired to any
delivery group.**

#### External Exposure (`external_dmz`)

Not rendered in `management_summary`.  Documented for cross-reference.

This module counts open findings on assets classified as externally facing.

**External-scope rule:** An asset is "external" when:
- It carries the Tenable tag `Location = External` or `Location = DMZ`, OR
- Its IPv4 address is non-RFC1918, non-CGNAT (100.64.0.0/10), non-loopback
  (127.0.0.0/8), and non-link-local (169.254.0.0/16) — i.e., a routable
  public IP.

The tag is authoritative when present.  IPv4 is a gap-detector for assets
lacking the tag.  CGNAT and DMZ nuance: the Tenable `Location=External` tag is
a dynamic rule based on "IP not in RFC1918"; `Location=DMZ` is a designated
private range (unpopulated in this tenant).  See `project_tenable_location_tag_semantics`
memory for detail.

#### Vulnerability Density (`vuln_density`)

Not rendered in `management_summary`.  Documented for cross-reference.

This module computes open finding count per on-time-scanned licensed asset
(density = total open / total on-time-scanned).  Its denominator uses the
`asset_count` field from the trend snapshot — which is `null` on reconstructed
months (see reconstruction disclosure below).  For this reason, Vulnerability
Density **cold-starts** on reconstructed months even when other modules have
12-month history.

---

### Mandatory Honesty Disclosures

#### Reconstruction Disclosure

**Reconstruction range:** 2025-06 through the current month (inclusive), for
the `all_assets` scope only.

**Script:** `scripts/backfill_trend_reconstruction.py` (Plan 18-03).
**Store file:** `data/trend/trend_severity_all_assets.json`.

**ALL-ASSETS-ONLY scope (review change #4):** Reconstruction was performed only
for `tag_filter = "all_assets"`.  No per-tag-scope reconstruction was
performed.  Tag-scoped delivery groups cold-start their MoM trend history —
this is the pre-existing behavior for `board_summary` and `composed_report`
(not a regression introduced by v1.4).  As of the v1.4 milestone, no active
delivery group in `delivery_config.yaml` is tag-scoped on `management_summary`
(only commented examples exist), so there are no active groups that cold-start.

**Reconstruction predicate (as implemented):**

For each month M to reconstruct, the script builds a combined DataFrame:

```
boundary    = month_end_utc(M)   # last instant of month M in UTC (YYYY-MM-DD 23:59:59 UTC, inclusive)

# current-open rows: open/reopened findings at script run time
# fixed-after-boundary rows: fixed findings where last_fixed > boundary
# (these findings were still open at month-end; they got fixed after M)
combined = current_open_df  UNION  fixed_df[last_fixed > boundary]

# Apply the reopened-aware two-interval predicate at the month boundary:
open_at_boundary = open_findings_at(combined, boundary)

counts = open_at_boundary.groupby("severity").size()
```

`month_end_utc(M)` returns the last instant of month M in UTC: `YYYY-MM-DD
23:59:59 UTC` on the last calendar day of M (inclusive upper bound). A finding
with `last_fixed == month_end_utc(M)` is counted as fixed at M (not open-at-M);
a finding fixed at `00:00:00 UTC` on the first day of M+1 is after the boundary
and counts as open-at-M.

**Provenance markers on reconstructed snapshots:**

| Field | Value |
|---|---|
| `source` | `"reconstructed"` |
| `asset_count` | `null` (not reconstructable — D-18-04) |
| `partial` | `true` for Jun, Jul, Aug 2025 (taper-edge months — D-18-02) |
| `generated_at` | UTC timestamp of the script run |

`source = "captured"` on snapshots written by `capture_trend_snapshot()` at
real report run time.

**Immutability (D-18-03):** Reconstructed months — including the current month
at the time of the script run — are written once and never overwritten.  A
second invocation of the backfill script writes 0 new months (idempotent).
`capture_trend_snapshot()` also honors this rule: it skips any month already
present with `source = "reconstructed"`.

**asset_count = null on reconstructed months:** The `asset_count` field records
the licensed asset count at capture time.  This is not derivable from
vulnerability exports alone, so reconstructed snapshots carry `asset_count: null`.
Modules that depend on `asset_count` from the trend store (e.g., Vulnerability
Density) cold-start on reconstructed months — they will not show historical
density values for the 2025-06 → 2026-05 window.

---

#### Reopened Temporal-Paradox Limitation

**Mandatory disclosure — this limitation applies to all reconstructed months.**

Tenable vulnerability exports retain only the **most-recent** state-transition
timestamps for each finding: `last_fixed`, `resurfaced_date`, and `first_found`
reflect the most recent occurrence of each event.  A finding that went through
a fix → reopen → fix cycle within the reconstructed window has only its final
`last_fixed` timestamp preserved; the intermediate fix event is not available
in the export.

Consequently, a finding that was:
- Fixed in month M (intermediate fix)
- Reopened in month M+1 (resurfaced)
- Fixed again in month M+2 (final fix)

...will appear in the export as `last_fixed = M+2`, `resurfaced_date = M+1`.
When the reconstruction predicate evaluates month M's boundary, it correctly
classifies the finding as open (the `last_fixed` of M+2 is after the boundary).
However, the intermediate M fix is invisible — the predicate cannot distinguish
whether the finding was open or closed in month M if multiple fix/reopen cycles
occurred.

**Reconstructed months are therefore a best-effort approximation**, not a
perfect historical record.  The residual error is **bounded** by:

- The overlap-test tolerance: ≤ 2% relative OR ≤ 5 absolute per severity.
- The Spike 002 benchmark: the two-interval predicate produced +2 of 160,453
  findings divergence vs a live ground-truth snapshot (0.001% error).
- The Phase 18-03 overlap-gate outcome: `live_open = 210,267`,
  `reconstructed_total = 210,267`, `abs_diff = 0`, `rel_diff = 0.0%` — PASS.

The validated two-interval `open_findings_at()` predicate minimizes (but cannot
fully eliminate) error from churned findings.  **Captured months carry no such
caveat** — they record the actual live open count at the time of the real
report run.

**Overlap-gate confidence:** The Plan 18-03 gate ran on the **weaker fallback
path** (no prior captured months existed when reconstruction ran; the primary
captured-month gate could not be exercised).  The weaker path compares a
reconstruction-of-today against the current live open count.  This is
explicitly weaker than the primary path (which validates against independently
captured monthly snapshots).  The gate passed at 0% divergence, but the absence
of captured-month anchors means the approximation quality across the 2025-06 →
2026-05 historical window has not been independently verified at each month.

**Do not treat reconstructed months as exact historical counts.**  Use them for
directional trend analysis.

---

#### Migration Parity-Bucket Outcome

The following table discloses the per-metric comparison result between the
legacy bespoke `management_summary` render path and the v1.4 module pipeline,
as validated by the Plan 18-04 bucketed parity gate against the Plan 18-01
frozen synthetic fixture.

| Metric | Module ID | Parity bucket | Outcome |
|---|---|---|---|
| M1 Total Open Vulns by Severity | `total_vulns_by_severity` | Exact-match | PASS — zero drift |
| M2 Scan Coverage SLA | `scan_coverage_sla` | Exact-match | PASS — zero drift |
| M3 MTTR Trend (rolling-30) | `mttr_trend` | Exact-match | PASS — zero drift |
| M4 Patch Compliance Rate | `patch_compliance_rate` | Exact-match | PASS — zero drift |
| M5 Aged Vulnerability Assets | `aged_vulns_assets` | Documented-difference | **Intentional design change** — see below |
| M6 Accepted & Recast | `accepted_recast` | Exact-match | PASS — zero drift |
| M7 New vs Remediated | `new_vs_remediated` | Documented-difference | **Intentional design change** — see below |

**M5 intentional design change:** The pre-v1.4 bespoke metric was a
vulnerability age-bucket histogram (count of open findings in six age bands:
0–30 d, 31–60 d, 61–90 d, 91–180 d, 181–365 d, 365+ d).  The v1.4
`aged_vulns_assets` module replaces this with the **percentage of
on-time-scanned assets** carrying at least one Medium/High/Critical finding
open more than 90 days.  This is a metric-design change, not a regression.
The new metric is more actionable: it surfaces chronic hosts with persistent
gaps rather than inflating counts with repeated findings on a few problem assets.

**M7 intentional design change:** The pre-v1.4 bespoke metric computed a
simple month-over-month total-open delta
(`snapshots[-1].total − snapshots[-2].total`).  The v1.4 `new_vs_remediated`
module computes **inflow** (stacked net-new + resurfaced) vs **outflow**
(snapshot `fixed_findings_count`) with an explicit net delta.  Historical
reports predating v1.4 that show the simple total-open delta are not
inconsistent with current reports showing inflow/outflow — they measure
different things by design.

The M5 and M7 changes were USER-APPROVED during Phase 18 planning and are
recorded in the Plan 18-01 golden file as `"comparison_policy":
"documented_difference"`.

---

#### Per-Metric Reconstructed-vs-Cold-Start Split

The following table states which metrics carry 12-month reconstructed all-assets
history vs which cold-start on reconstructed months.

| Metric | Module ID | Reconstructed history available? | Notes |
|---|---|---|---|
| Total Open Vulns by Severity | `total_vulns_by_severity` | Yes — 12 mo | Severity counts seeded by backfill |
| MTTR Trend MoM line | `mttr_trend` | Yes — 12 mo (snapshots) | `mttr_overall_days` / `mttr_by_severity` seeded |
| Accepted & Recast MoM delta | `accepted_recast` | Yes — 12 mo (snapshots) | `accepted_count` / `recast_count` seeded |
| New vs Remediated outflow | `new_vs_remediated` | Partial — `fixed_findings_count` absent on older snapshots | Outflow shows "—" for reconstructed months without this field |
| Scan Coverage SLA (live) | `scan_coverage_sla` | N/A — live asset metric, no trend history | Always computed from current `assets_df` |
| Patch Compliance Rate (live) | `patch_compliance_rate` | N/A — live finding metric, no trend history | Always computed from current `vulns_df` |
| Aged Vulnerability Assets (live) | `aged_vulns_assets` | N/A — live asset+finding metric, no trend history | Always computed from current `vulns_df` + `assets_df` |
| Vulnerability Density (not rendered) | `vuln_density` | Cold-start on reconstructed months | `asset_count = null` on reconstructed months; density not computable |

---

#### Rolling-30 MTTR Window Intent

The `mttr_trend` module defaults to a 30-day rolling window
(`mttr_window_days = 30`).  This window is a **deliberate recent-velocity
choice** (D-18-06): it reflects how fast the programme is currently fixing
vulnerabilities, not a long-term average.  A 30-day window responds quickly to
remediation sprints and slowdowns, making it more actionable for monthly
management reporting.

This is **not** a data-availability limit.  The Tenable fixed-vuln export
retains approximately 15–16 months of history (real retention, not the API
default 30-day floor).  The window can be widened via
`module_options.mttr_window_days` in `delivery_config.yaml` if a longer
view is desired.

---

#### External Exposure Scope Rule

Used by the `external_dmz` module (not rendered in `management_summary` — see
Group B above).  Documented here because the rule is referenced in v1.4 phase
planning documents and auditors may encounter it when reviewing cross-report
metric definitions.

An asset is classified as **externally exposed** when:

1. It carries the Tenable tag `Location = External` OR `Location = DMZ`, **or**
2. Its IPv4 address is a routable public address — not in RFC1918
   (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), not CGNAT
   (100.64.0.0/10), not loopback (127.0.0.0/8), and not link-local
   (169.254.0.0/16).

The tag is authoritative when present; IPv4 classification is a gap-detector
for assets that lack the Location tag.  The `Location=External` Tenable tag is
a dynamic rule based on "IP not RFC1918"; `Location=DMZ` is a designated
private range (unpopulated in this tenant).  No CGNAT or DMZ addresses appear
in Tenable data for this organisation.
