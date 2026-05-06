# Board Vulnerability Metrics Summary — Calculations Runbook

**File:** `reports/board_summary.py`
**Audience:** Board of Directors / Executive Leadership
**Outputs:** PDF (cover page + 4 metric pages) + Excel workbook (4 tabs + `_Metadata`)
**Schedule:** Monthly (first of the month recommended)

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [How to Activate Scheduled Delivery](#2-how-to-activate-scheduled-delivery)
3. [CLI Reference](#3-cli-reference)
4. [Data Sources](#4-data-sources)
5. [Shared Baseline — On-Time Scanned Assets](#5-shared-baseline--on-time-scanned-assets)
6. [Severity Classification (VPR)](#6-severity-classification-vpr)
7. [Business-Unit Breakdown](#7-business-unit-breakdown)
8. [RAG Status Logic](#8-rag-status-logic)
9. [Metric 1 — Scan Coverage SLA](#9-metric-1--scan-coverage-sla)
10. [Metric 2 — Critical Remediation SLA](#10-metric-2--critical-remediation-sla)
11. [Metric 3 — High-Risk Assets](#11-metric-3--high-risk-assets)
12. [Metric 4 — Aged Vulnerability Assets](#12-metric-4--aged-vulnerability-assets)
13. [PDF Structure](#13-pdf-structure)
14. [Excel Structure](#14-excel-structure)
15. [Output Files](#15-output-files)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Quick Start

```bash
# All assets, default output directory
python reports/board_summary.py

# Scoped to a specific tag
python reports/board_summary.py --tag-category "Environment" --tag-value "Production"

# Custom output directory, no email
python reports/board_summary.py --output-dir output/board_q1 --no-email
```

Or trigger via the delivery group:

```bash
python run_all.py --group "Monthly Board Security Metrics" --no-email
```

---

## 2. How to Activate Scheduled Delivery

The `Monthly Board Security Metrics` group in `delivery_config.yaml` controls this report.
Edit the group block and set the correct recipients:

```yaml
- name: "Monthly Board Security Metrics"
  description: "Monthly board-level vulnerability metrics — four RAG-status KPIs with BU breakdown"
  schedule:
    frequency: monthly
    day_of_month: 1
    time: "06:00"
  filters: {}              # empty = all assets; add tag_category/tag_value to scope
  reports:
    - board_summary
  email:
    subject: "Monthly Board Security Metrics — All Assets"
    recipients:
      - ciso@company.com
      - board-security@company.com
    cc:
      - security-team@company.com
    reply_to: security@company.com
```

No code changes required — the scheduler reads this file directly.
Run `python run_all.py --dry-run` after editing to validate before the next scheduled run.

---

## 3. CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--tag-category CATEGORY` | _(none)_ | Tenable tag category to scope the report (e.g. `"Environment"`) |
| `--tag-value VALUE` | _(none)_ | Tag value paired with `--tag-category` (e.g. `"Production"`) |
| `--output-dir PATH` | `output/board_summary/` | Directory to write PDF and Excel output |
| `--no-email` | _(flag)_ | Generate reports without sending email |
| `--run-id ID` | today's date (`YYYY-MM-DD`) | Parquet cache key |

Both `--tag-category` and `--tag-value` must be supplied together to apply a filter.
If only one is provided, or if neither is provided, the report runs against all assets.

---

## 4. Data Sources

| Data | API call | Cache file | Notes |
|------|----------|------------|-------|
| Open vulnerabilities | `tio.exports.vulns()` | `vulns_all.parquet` | State = open; all severities |
| Assets | `tio.exports.assets()` | `assets_all.parquet` | Full asset inventory |
| Fixed vulnerabilities | `tio.exports.vulns(state=["fixed"])` | `fixed_vulns.parquet` | Used only by Metric 2 |

Cache files are written to `cache/YYYY-MM-DD/` (local machine date) at the start of each run.
If a run starts before midnight and completes after midnight, both dates may have cache files.
Cache folders from prior days are deleted at the start of each `run_all.py` batch — only today's cache is retained.

---

## 5. Shared Baseline — On-Time Scanned Assets

All four board metrics share a single asset baseline to ensure the denominator is consistent across the report.

### Step 1 — Deduplicate by hostname

The raw asset export can contain multiple records for the same hostname (e.g. from different
scans or network interfaces). Before any metric is computed, assets are deduplicated:

- Assets with a non-blank `hostname` are grouped; the row with the most-recent `last_seen` is kept.
- Assets with a blank or null `hostname` are kept as-is (cannot be grouped reliably).

**Implementation:** `board_report_utils.deduplicate_assets_by_name()`

### Step 2 — Licensed assets only (Metrics 1, 3, 4)

After deduplication, assets without a `last_licensed_scan_date` (unlicensed assets) are
excluded from the population used by Metrics 1, 3, and 4. These assets have never received
a licensed Tenable scan and cannot be evaluated for scan coverage or vulnerability posture.

Deduplication runs on **all** assets first so that a hostname whose most-recent record is
unlicensed does not retain an older licensed duplicate. Only after deduplication is the
licensed/unlicensed split made.

### Step 3 — On-time scan window (Metrics 1, 3, 4)

Within the licensed population, an asset is classified as **on-time scanned** when:

```
last_licensed_scan_date IS NOT NULL
AND last_licensed_scan_date >= report_date − 30 days
```

| Set | Definition |
|-----|------------|
| On-time | Licensed AND scanned within the last 30 days |
| Not on-time | Licensed AND last_licensed_scan_date < 30-day cutoff |
| Excluded | Unlicensed (null last_licensed_scan_date) |

**Metrics 3 and 4** use the on-time asset set as their denominator — they only evaluate
assets that have been recently scanned, so unknown-state assets do not inflate or deflate
the metric.

**Metric 2** uses `fixed_vulns_df` (not the asset baseline) as its input population — see
[Metric 2](#10-metric-2--critical-remediation-sla) for details.

**Implementation:** `board_report_utils.identify_on_time_assets()`

---

## 6. Severity Classification (VPR)

Severity is derived from the **VPR (Vulnerability Priority Rating)** score, not the native
Tenable CVSS-based severity field.

| Severity | VPR Score Range | SLA (Days to Remediate) |
|----------|-----------------|-------------------------|
| Critical | 9.0 – 10.0 | 15 days |
| High | 7.0 – 8.9 | 30 days |
| Medium | 4.0 – 6.9 | 90 days |
| Low | 0.1 – 3.9 | 180 days |

A finding with no `vpr_score` falls back to the native Tenable `severity` field.

**Implementation:** `config.vpr_to_severity(vpr_score, fallback_severity)`

---

## 7. Business-Unit Breakdown

Every metric page includes a per-business-unit breakdown table showing which BUs are
performing best and worst on that metric.

**Business unit source:** The Tenable `Application` tag category.

Tags are stored in `assets_df` as a semicolon-delimited `"Category=Value"` string, for example:

```
"Application=Finance;Environment=Production;Owner=Network Defense"
```

Assignment rules:
- Asset has exactly one `Application` tag → that value (e.g. `"Finance"`)
- Asset has no `Application` tag → `"Untagged"`
- Asset has multiple distinct `Application` values → values joined alphabetically with `"; "`

**Sort order in PDF/Excel tables** (all four metrics use the same two-key logic):

1. **Primary — absolute affected count, descending.** "Affected" means the raw number of assets representing the problem:
   - Higher-is-better metrics (1 & 2): `denominator − numerator` (assets *not* meeting the goal, e.g. not scanned on time, criticals not fixed within SLA)
   - Lower-is-better metrics (3 & 4): `numerator` (assets *with* the problem, e.g. high-risk, aged-vuln)
2. **Secondary — percentage, worst-first** (ascending for higher-is-better, descending for lower-is-better). Tiebreaker when two BUs have the same affected count.

This ensures a large environment with many real problems ranks above a small environment that is 100% non-compliant, giving the board a view that reflects actual remediation workload rather than relative compliance rate alone.

**Implementation:** `board_report_utils.extract_business_unit()`, `board_report_utils.compute_per_bu_breakdown(higher_is_better=True|False)`

---

## 8. RAG Status Logic

Each metric is classified into one of four states:

| State | Display label | Colour |
|-------|---------------|--------|
| `green` | On Target | `#388e3c` |
| `yellow` | At Risk | `#f57c00` |
| `red` | Off Target | `#d32f2f` |
| `no_data` | No Data | `#757575` |

The thresholds differ per metric and direction (see each metric section below).

**Higher-is-better** (Metrics 1 and 2):
```
value >= green_threshold  → green
value >= yellow_threshold → yellow
value <  yellow_threshold → red
value is None             → no_data
```

**Lower-is-better** (Metrics 3 and 4):
```
value <= green_threshold  → green
value <= yellow_threshold → yellow
value >  yellow_threshold → red
value is None             → no_data
```

**Implementation:** `board_report_utils.sla_status_from_thresholds()`

---

## 9. Metric 1 — Scan Coverage SLA

**Module ID:** `scan_coverage_sla`  
**Direction:** Higher is better  
**Target:** ≥ 95% (green) / ≥ 90% (amber) / < 90% (red)

### What it measures

The percentage of **licensed** assets that received a licensed Tenable scan within the last
30 days. Assets without a `last_licensed_scan_date` (unlicensed) are excluded from both
numerator and denominator.

### Formula

```
Scan Coverage % = (scanned_on_time / total_licensed) × 100
```

Where:
- `total_licensed` = count of deduplicated licensed assets (denominator)
- `scanned_on_time` = licensed assets where `last_licensed_scan_date >= report_date − 30 days`

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | Scan Coverage ≥ 95% |
| Amber (At Risk) | Scan Coverage ≥ 90% and < 95% |
| Red (Off Target) | Scan Coverage < 90% |

### Metrics returned

| Key | Description |
|-----|-------------|
| `scan_coverage_pct` | Coverage percentage (1 decimal place), or `None` if no licensed assets |
| `scanned_on_time` | Count of licensed assets scanned within the 30-day window |
| `not_scanned_on_time` | Count of licensed assets NOT scanned within the window |
| `total_licensed` | Total deduplicated licensed assets (denominator) |
| `unlicensed_excluded` | Count of assets excluded because `last_licensed_scan_date` is null |
| `status` | RAG status string: `green`, `yellow`, `red`, or `no_data` |

### Edge cases

- If `total_licensed == 0` → status is `no_data`; metric value is `None`.
- Assets with unparseable `last_licensed_scan_date` values are treated as `null` (unlicensed).

---

## 10. Metric 2 — Critical Remediation SLA

**Module ID:** `critical_remediation_sla`  
**Direction:** Higher is better  
**Target:** ≥ 95% (green) / ≥ 85% (amber) / < 85% (red)

### What it measures

The percentage of Critical vulnerabilities (VPR 9.0–10.0) that were **fixed within their
15-day SLA** during the last 30 days. Only findings on assets that were scanned on time
(within the last 30 days) are included.

### Formula

```
Remediation SLA % = (fixed_within_sla / total_fixed_in_window) × 100
```

Where:
- `total_fixed_in_window` = Critical findings with `last_fixed >= report_date − 30 days`, on on-time assets
- `fixed_within_sla` = findings from above where `days_to_fix <= 15`

### Days-to-fix calculation

For each fixed finding, `days_to_fix` is computed as:

1. **Primary**: `time_taken_to_fix / 86400` (seconds → days) if the field is populated and numeric.
2. **Fallback**: `(last_fixed − first_found).days` if `time_taken_to_fix` is absent or unparseable.

Findings where `days_to_fix` cannot be computed are excluded from the SLA count entirely
(neither numerator nor denominator). This prevents division bias from incomplete data.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | Remediation SLA ≥ 95% |
| Amber (At Risk) | Remediation SLA ≥ 85% and < 95% |
| Red (Off Target) | Remediation SLA < 85% |

### Metrics returned

| Key | Description |
|-----|-------------|
| `remediation_sla_pct` | SLA compliance percentage (1 decimal place), or `None` if no data |
| `fixed_within_sla` | Count of Critical findings fixed within 15 days |
| `fixed_outside_sla` | Count of Critical findings fixed but outside the 15-day SLA |
| `total_fixed_last_month` | Total Critical findings fixed in the 30-day window |
| `status` | RAG status string |

### Edge cases

- If no Critical findings were fixed in the last 30 days → status is `no_data`.
- If `fixed_vulns_df` is not passed to `ReportComposer` → returns `no_data` with a logged warning.
- If `fixed_vulns_df` is empty → status is `no_data`.
- Findings where `days_to_fix` is negative (data error) are treated as within SLA (0-day fix).

---

## 11. Metric 3 — High-Risk Assets

**Module ID:** `high_risk_assets`  
**Direction:** Lower is better  
**Target:** ≤ 0.5% (green) / ≤ 1.0% (amber) / > 1.0% (red)

### What it measures

The percentage of on-time scanned assets that are **high-risk**: assets with **10 or more**
Critical or High open vulnerabilities (VPR ≥ 7.0) that have been open for **more than 30 days**.

### Formula

```
High-Risk Assets % = (high_risk_asset_count / total_on_time_assets) × 100
```

Where:
- `total_on_time_assets` = deduplicated licensed assets scanned within the last 30 days (shared baseline)
- `high_risk_asset_count` = on-time assets with ≥ 10 Critical/High findings open > 30 days

### High-risk asset classification

An asset is classified as **high-risk** when it meets **both** of the following conditions:

1. **Severity filter**: The finding has VPR-derived severity of `critical` or `high` (VPR ≥ 7.0).
2. **Age filter**: `days_open > 30` (strictly greater than 30; a finding open exactly 30 days is NOT counted).
3. **Count threshold**: The asset has **≥ 10** qualifying findings meeting both conditions above.

Only findings on on-time assets contribute to the count.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | High-Risk Assets % ≤ 0.5% |
| Amber (At Risk) | High-Risk Assets % ≤ 1.0% and > 0.5% |
| Red (Off Target) | High-Risk Assets % > 1.0% |

### Metrics returned

| Key | Description |
|-----|-------------|
| `high_risk_pct` | Percentage of on-time assets classified as high-risk (1 dp), or `None` |
| `high_risk_count` | Count of high-risk assets |
| `total_on_time_assets` | Denominator (on-time scanned assets) |
| `status` | RAG status string |

### Edge cases

- If `total_on_time_assets == 0` → status is `no_data`.
- Assets with no open vulnerabilities are not high-risk (count = 0 < 10 threshold).
- `days_open` is computed as `(report_date − first_found).days`. Findings where `first_found` cannot be parsed are excluded from the count.

---

## 12. Metric 4 — Aged Vulnerability Assets

**Module ID:** `aged_vulns_assets`  
**Direction:** Lower is better  
**Target:** ≤ 2% (green) / ≤ 5% (amber) / > 5% (red)

### What it measures

The percentage of on-time scanned assets that have **at least one** Medium, High, or Critical
open vulnerability that has been open for **more than 90 days**.

### Formula

```
Aged Assets % = (aged_asset_count / total_on_time_assets) × 100
```

Where:
- `total_on_time_assets` = deduplicated licensed assets scanned within the last 30 days (shared baseline)
- `aged_asset_count` = on-time assets with ≥ 1 Med/High/Crit finding open > 90 days

### Aged asset classification

An asset is classified as **aged** when it has **at least one** finding meeting **both** of the
following conditions:

1. **Severity filter**: VPR-derived severity is `medium`, `high`, or `critical` (VPR ≥ 4.0).
2. **Age filter**: `days_open > 90` (strictly greater than 90; a finding open exactly 90 days is NOT counted).

Only findings on on-time assets are evaluated.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | Aged Assets % ≤ 2% |
| Amber (At Risk) | Aged Assets % ≤ 5% and > 2% |
| Red (Off Target) | Aged Assets % > 5% |

### Metrics returned

| Key | Description |
|-----|-------------|
| `aged_pct` | Percentage of on-time assets with aged findings (1 dp), or `None` |
| `aged_count` | Count of aged assets |
| `total_on_time_assets` | Denominator (on-time scanned assets) |
| `status` | RAG status string |

### Edge cases

- If `total_on_time_assets == 0` → status is `no_data`.
- An asset is only counted once regardless of how many aged findings it has (set membership).
- Low severity findings (VPR < 4.0) are excluded — they have a 180-day SLA and are not tracked by this board metric.
- `days_open` is computed as `(report_date − first_found).days`. Findings where `first_found` cannot be parsed are excluded.

---

## 13. PDF Structure

The PDF is assembled by `ReportComposer.assemble_pdf()` in `reports/modules/composer.py`.

| Page | Content |
|------|---------|
| 1 | **Cover page** — report title, scope, generated timestamp, section list |
| 2 | **Metric 1**: Scan Coverage SLA — gauge, status badge, on-time/not-on-time counts, top-5 BU table, methodology note |
| 3 | **Metric 2**: Critical Remediation SLA — gauge, fixed/within-SLA counts, top-5 BU table, methodology note |
| 4 | **Metric 3**: High-Risk Assets — gauge, high-risk/on-time counts, top-5 BU table, methodology note |
| 5 | **Metric 4**: Aged Vulnerability Assets — gauge, aged/on-time counts, top-5 BU table, methodology note |

Page numbers appear in the footer of every page (`Page N of N`).

**Gauge colour zones (all metrics):**

| Zone | Colour |
|------|--------|
| Green (on-target) | `#388e3c` |
| Amber (at-risk) | `#fbc02d` |
| Red (off-target) | `#d32f2f` |

**BU tables in PDF** show the top 5 worst-performing business units for each metric, ranked by absolute affected count descending (see BU Sort Order in Section 7). This ensures the BUs with the most actual assets requiring remediation are always surfaced first, regardless of environment size.

---

## 14. Excel Structure

The workbook is assembled by `ReportComposer.assemble_excel()`.

| Tab | Content |
|-----|---------|
| `Scan Coverage Summary` | Overall KPI block + full BU breakdown table (all BUs, not just top 5) |
| `Critical Remediation Summary` | Overall KPI block + full BU breakdown |
| `High-Risk Assets Summary` | Overall KPI block + full BU breakdown |
| `Aged Vulns Summary` | Overall KPI block + full BU breakdown |
| `_Metadata` | Run timestamp, module list, per-module status, error messages |

**Coverage % column colour coding** (all tabs):
- Green fill: on-target (meets green threshold)
- Amber fill: at-risk (between green and amber thresholds)
- Red fill: off-target (worse than amber threshold)

---

## 15. Output Files

```
output/board_summary/
├── board_summary.pdf      # 5-page board-ready PDF
└── board_summary.xlsx     # 4-metric Excel workbook + metadata tab
```

When run via `run_all.py`, outputs are written to a timestamped folder:

```
output/YYYY-MM-DD_HH-MM_Monthly-Board-Security-Metrics/
├── board_summary.pdf
└── board_summary.xlsx
```

---

## 16. Troubleshooting

### All metrics show "No Data"

The report ran but found no licensed, on-time assets. Common causes:

1. **Tag filter too narrow** — the `tag_category` / `tag_value` filter matched zero assets.  
   Fix: run `python utils/tag_helper.py --list-tags` to discover valid tag values.  
   Fix: set `filters: {}` in `delivery_config.yaml` to run against all assets.

2. **No licensed assets in scope** — all matching assets have a null `last_licensed_scan_date`.  
   Check: query the parquet cache:
   ```python
   import pandas as pd
   df = pd.read_parquet("cache/YYYY-MM-DD/assets_all.parquet")
   print(df["last_licensed_scan_date"].notna().sum(), "licensed assets")
   ```

3. **Stale cache** — a previous run's cache contains no assets matching the new filter.  
   Fix: delete the cache folder and re-run.

### Metric 2 shows "No Data" but others have values

No Critical findings were fixed in the last 30 days in the scoped asset population.
This is a valid data state (no remediation activity). It may also occur if:

- `fixed_vulns.parquet` is missing or empty. Check that `fetch_fixed_vulnerabilities()` succeeded in the logs.
- The scope filter excluded all assets with fixed Critical findings.

### BU breakdown is entirely "Untagged"

Assets in scope have no `Application` tag in Tenable.
Add `Application` tags to assets in the Tenable console, or use a different tag category
for BU segmentation (requires a code change to `BU_TAG_CATEGORY` in `board_report_utils.py`).

### PDF generation fails (WeasyPrint ImportError)

WeasyPrint requires a separate install and OS-level dependencies:

```bash
pip install weasyprint
```

On Windows, WeasyPrint also requires GTK. See the WeasyPrint documentation for platform-specific setup.
The report will still produce the Excel output if PDF fails — check the logs for the error.

### Scan Coverage is unexpectedly low

Check how many assets are licensed:

```python
import pandas as pd
df = pd.read_parquet("cache/YYYY-MM-DD/assets_all.parquet")
total    = len(df)
licensed = df["last_licensed_scan_date"].notna().sum()
on_time  = (pd.to_datetime(df["last_licensed_scan_date"], utc=True, errors="coerce")
            >= pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=30)).sum()
print(f"Total: {total}, Licensed: {licensed}, On-time: {on_time}")
```

If `licensed` is much lower than `total`, many assets lack a Tenable license — this is expected
and intentional (unlicensed assets are excluded from the metric by design).
