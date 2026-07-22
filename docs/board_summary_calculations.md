# Board Vulnerability Metrics Summary — Calculations Runbook

**Audience:** Board of Directors / Executive Leadership
**Delivery cadence:** Monthly
**Report shape:** A cover page plus one page per metric (gauge, status, key counts, top business-unit breakdown) and a companion Excel workbook with the full BU detail for each metric.

This runbook documents **what each metric measures, which fields it draws from, and how the numbers are derived.** It is intended for the team responsible for collecting, validating, and consolidating the underlying data. Operational concerns (scheduling, file outputs, troubleshooting infrastructure) live elsewhere.

For field-by-field definitions of the underlying Tenable data, see [`tenable_vuln_api_reference.md`](tenable_vuln_api_reference.md). For project-specific terminology, see [`GLOSSARY.md`](GLOSSARY.md).

---

## Table of Contents

1. [Data Sources](#1-data-sources)
2. [Shared Baseline — On-Time Scanned Assets](#2-shared-baseline--on-time-scanned-assets)
3. [Severity Classification (VPR)](#3-severity-classification-vpr)
4. [Business-Unit Breakdown](#4-business-unit-breakdown)
5. [RAG Status Logic](#5-rag-status-logic)
6. [Metric 1 — Scan Coverage SLA](#6-metric-1--scan-coverage-sla)
7. [Metric 2 — Critical Remediation SLA](#7-metric-2--critical-remediation-sla)
8. [Metric 3 — High-Risk Assets](#8-metric-3--high-risk-assets)
9. [Metric 4 — Aged Vulnerability Assets](#9-metric-4--aged-vulnerability-assets)
10. [Metric 5 — Accepted/Recast by Owner](#10-metric-5--acceptedrecast-by-owner)
11. [Data-Quality Notes](#11-data-quality-notes)

---

## 1. Data Sources

The board summary draws from Tenable exports plus two local supplemental sources, pulled fresh on the day the report runs:

| Data | Source | Used by | Notes |
|------|--------|---------|-------|
| Open vulnerabilities | Tenable vulnerability export, state = open, all severities | All five metrics | Each row is one (plugin × asset) finding currently detected on the asset. |
| Asset inventory | Tenable asset export | All five metrics | Full asset inventory including licensing and last-scan timestamps. |
| Fixed vulnerabilities | Tenable vulnerability export, state = fixed | Metric 2 only | Findings that were detected previously but are no longer present on the asset, used to measure remediation time. |
| Recast/accept rules | Tenable `POST /v1/recast/rules/search`, fetched fail-soft | Metric 5 only | Active HOST recast/accept rules, used for the expired-rule cross-check. Absent (fetch failure or no credentials) → cross-check skipped, finding-level counts still computed. |
| Trend snapshots | Local trend store (`data/trend/`), not Tenable | Metric 5 only | Prior-month accepted/recast counts, used for the month-over-month delta. |

Each report run produces a point-in-time snapshot. The same input snapshot is reused across Metrics 1–4 so the counts on every metric page can be reconciled against the same population. Metric 5 additionally draws on the local trend store and recast rules.

---

## 2. Shared Baseline — On-Time Scanned Assets

All four board metrics share a single asset baseline so that the denominator stays consistent across the report.

### Step 1 — Deduplicate by hostname

The raw asset export can contain multiple records for the same hostname (for example, from different scans or network interfaces). Before any metric is computed, assets are deduplicated:

- Assets with a non-blank `hostname` are grouped, and the row with the most-recent `last_seen` is kept.
- Assets with a blank or null `hostname` are kept as-is (they cannot be grouped reliably).

### Step 2 — Licensed assets only (Metrics 1, 3, 4)

After deduplication, assets without a `last_licensed_scan_date` (unlicensed assets) are excluded from the population used by Metrics 1, 3, and 4. These assets have never received a licensed Tenable scan and cannot be evaluated for scan coverage or vulnerability posture.

Deduplication runs on **all** assets first so that a hostname whose most-recent record is unlicensed does not retain an older licensed duplicate. Only after deduplication is the licensed/unlicensed split made.

### Step 3 — On-time scan window (Metrics 1, 3, 4)

Within the licensed population, an asset is classified as **on-time scanned** when:

> `last_licensed_scan_date` is not null **AND** `last_licensed_scan_date` ≥ report date − 30 days.

| Set | Definition |
|-----|------------|
| On-time | Licensed AND scanned within the last 30 days |
| Not on-time | Licensed AND `last_licensed_scan_date` < the 30-day cutoff |
| Excluded | Unlicensed (`last_licensed_scan_date` is null) |

Metrics 3 and 4 use the **on-time** asset set as their denominator — they only evaluate assets that have been recently scanned, so unknown-state assets do not inflate or deflate the metric.

Metric 2 uses fixed vulnerabilities (not the asset baseline) as its input population — see [Metric 2](#7-metric-2--critical-remediation-sla).

### Exclusion of risk-managed findings (Metrics 3, 4, and 2's SLA population)

Risk-accepted and recast findings (`severity_modification_type` in `{ACCEPTED, RECASTED}`) remain `state = open` in Tenable, so they would otherwise inflate metrics that count "open" findings against a population the operator has already dispositioned.

- **Metric 3 (High-Risk Assets)** and **Metric 4 (Aged Vulnerability Assets)** exclude ACCEPTED/RECASTED open findings before evaluating the high-risk/aged classification.
- **Metric 2 (Critical Remediation SLA)** excludes ACCEPTED/RECASTED findings from the *fixed* population before computing the SLA percentage and the "missed SLA" analyst drill-down.
- **Metric 1 (Scan Coverage SLA)** is unaffected — it is assets-only and does not consume `vulns_df`.
- **Metric 5 (Accepted/Recast by Owner)** intentionally does **not** apply this exclusion — risk-managed findings are exactly what it reports on.

All three exclusions are applied via the shared `exclude_risk_managed()` helper (`reports/modules/board_report_utils.py`).

---

## 3. Severity Classification (VPR)

Severity is derived from the **VPR (Vulnerability Priority Rating)** score, not the native Tenable CVSS-based severity field.

| Severity | VPR Score Range | SLA (days to remediate) |
|----------|-----------------|-------------------------|
| Critical | 9.0 – 10.0 | 15 days |
| High | 7.0 – 8.9 | 30 days |
| Medium | 4.0 – 6.9 | 90 days |
| Low | 0.1 – 3.9 | 180 days |

A finding with no `vpr_score` falls back to the native Tenable `severity` field.

---

## 4. Business-Unit Breakdown

Every metric page includes a per-business-unit breakdown table showing which BUs are performing best and worst on that metric.

### Business unit source

The Tenable `Application` tag category is the business-unit dimension. Tags are stored on each asset as a semicolon-delimited `"Category=Value"` string, for example:

> `Application=Finance;Environment=Production;Owner=Network Defense`

Assignment rules:

- Asset has exactly one `Application` tag → that value (e.g. `"Finance"`)
- Asset has no `Application` tag → `"Untagged"`
- Asset has multiple distinct `Application` values → values joined alphabetically with `"; "`

### Sort order

All four metrics use the same two-key sort logic in PDF and Excel tables:

1. **Primary — absolute affected count, descending.** "Affected" means the raw number of assets representing the problem:
   - Higher-is-better metrics (1 & 2): assets **not** meeting the goal (e.g. not scanned on time, or criticals not fixed within SLA).
   - Lower-is-better metrics (3 & 4): assets **with** the problem (e.g. high-risk, aged-vuln).
2. **Secondary — percentage, worst-first.** Ascending for higher-is-better, descending for lower-is-better. Used as the tiebreaker when two BUs have the same affected count.

This ensures a large environment with many real problems ranks above a small environment that is 100% non-compliant, giving the board a view that reflects actual remediation workload rather than relative compliance rate alone.

### Risk Score broadening (Metrics 3 & 4)

The Risk Score column in the High-Risk Assets and Aged Vulnerability Assets BU tables is deliberately **broader** than the qualifying-finding subset:

- **High-Risk Assets:** the score sums severity-weighted open-finding counts across **all open Critical/High findings** on the asset, not only the >30-day findings that caused the asset to qualify as high-risk.
- **Aged Vulnerability Assets:** the score sums severity-weighted open-finding counts across **all open Critical/High/Medium findings** on the asset, not only the >90-day findings that caused the asset to qualify as aged.

This broadening is intentional. The Risk Score is meant to be a **holistic asset-risk indicator** — once an asset qualifies as high-risk or aged, the score communicates the total severity-weighted exposure on that asset so the board can see "BU Finance has 47 high-risk assets totalling 932 risk-score points" rather than "BU Finance has 47 high-risk assets totalling N points-from-only-the-qualifying-findings". The Aged% / High-Risk% gauges themselves remain narrow (qualifying findings only), so the headline metric is unaffected.

**Severity weights** for risk score:

| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 5 |
| Medium | 2 |
| Low | 1 |

---

## 5. RAG Status Logic

Each metric is classified into one of four states:

| State | Display label | Colour |
|-------|---------------|--------|
| Green | On Target | `#388e3c` |
| Amber/Yellow | At Risk | `#f57c00` |
| Red | Off Target | `#d32f2f` |
| No Data | No Data | `#757575` |

The thresholds differ per metric and direction. The rules:

**Higher-is-better** (Metrics 1 and 2):

| Value | Status |
|-------|--------|
| ≥ green threshold | Green |
| ≥ amber threshold and < green threshold | Amber |
| < amber threshold | Red |
| Not computable (no input data) | No Data |

**Lower-is-better** (Metrics 3 and 4):

| Value | Status |
|-------|--------|
| ≤ green threshold | Green |
| ≤ amber threshold and > green threshold | Amber |
| > amber threshold | Red |
| Not computable (no input data) | No Data |

---

## 6. Metric 1 — Scan Coverage SLA

**Direction:** Higher is better
**Target:** ≥ 95% green / ≥ 90% amber / < 90% red

### What it measures

The percentage of **licensed** assets that received a licensed Tenable scan within the last 30 days. Assets without a `last_licensed_scan_date` (unlicensed) are excluded from both numerator and denominator.

### Formula

> **Scan Coverage % = (assets scanned on time ÷ total licensed assets) × 100**

Where:

- **Total licensed assets** = count of deduplicated licensed assets (denominator).
- **Assets scanned on time** = licensed assets where `last_licensed_scan_date` ≥ report date − 30 days.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | Scan Coverage ≥ 95% |
| Amber (At Risk) | Scan Coverage ≥ 90% and < 95% |
| Red (Off Target) | Scan Coverage < 90% |

### Values reported

| Value | Description |
|-------|-------------|
| Scan Coverage % | Coverage percentage to one decimal place, or "No Data" when there are no licensed assets in scope. |
| Scanned on time | Count of licensed assets scanned within the 30-day window. |
| Not scanned on time | Count of licensed assets NOT scanned within the window. |
| Total licensed | Total deduplicated licensed assets (denominator). |
| Unlicensed (excluded) | Count of assets excluded because `last_licensed_scan_date` is null. |

### Edge cases

- If there are **zero** licensed assets in scope → status is "No Data"; the percentage is reported as "No Data" rather than 0%.
- Assets with an unparseable `last_licensed_scan_date` are treated as unlicensed and excluded.

---

## 7. Metric 2 — Critical Remediation SLA

**Direction:** Higher is better
**Target:** ≥ 95% green / ≥ 85% amber / < 85% red

### What it measures

The percentage of Critical vulnerabilities (VPR 9.0–10.0) that were **fixed within their 15-day SLA** during the last 30 days. Only findings on assets that were scanned on time (within the last 30 days) are included.

### Formula

> **Remediation SLA % = (fixed within SLA ÷ total Critical fixed in window) × 100**

Where:

- **Total Critical fixed in window** = Critical findings with `last_fixed` ≥ report date − 30 days, on on-time assets.
- **Fixed within SLA** = the subset of the above where days to fix ≤ 15.

### Days-to-fix derivation

For each fixed finding, days-to-fix is derived as follows:

1. **Primary source:** `time_taken_to_fix` (seconds) ÷ 86,400, when the field is populated and numeric. This is Tenable's authoritative remediation duration.
2. **Fallback:** `(last_fixed − first_found)` expressed in whole days, when `time_taken_to_fix` is missing or unparseable.

Findings where days-to-fix cannot be computed are **excluded from the SLA count entirely** (neither numerator nor denominator). This prevents division bias from incomplete data.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | Remediation SLA ≥ 95% |
| Amber (At Risk) | Remediation SLA ≥ 85% and < 95% |
| Red (Off Target) | Remediation SLA < 85% |

### Values reported

| Value | Description |
|-------|-------------|
| Remediation SLA % | SLA compliance percentage to one decimal place, or "No Data". |
| Fixed within SLA | Count of Critical findings fixed within 15 days. |
| Fixed outside SLA | Count of Critical findings fixed but outside the 15-day SLA. |
| Total fixed last month | Total Critical findings fixed in the 30-day window. |

### Edge cases

- If no Critical findings were fixed in the last 30 days in scope → status is "No Data". This is a legitimate state (no remediation activity), not an error.
- If the fixed-vulnerability data set is empty or unavailable → status is "No Data".
- Findings where days-to-fix is negative (a data error in the source feed) are treated as within SLA (effectively a same-day fix).

---

## 8. Metric 3 — High-Risk Assets

**Direction:** Lower is better
**Target:** ≤ 0.5% green / ≤ 1.0% amber / > 1.0% red

### What it measures

The percentage of **on-time scanned** assets that are high-risk: assets carrying **10 or more** Critical or High open vulnerabilities (VPR ≥ 7.0) that have been open for **more than 30 days**.

### Formula

> **High-Risk Assets % = (high-risk asset count ÷ total on-time assets) × 100**

Where:

- **Total on-time assets** = deduplicated licensed assets scanned within the last 30 days (shared baseline).
- **High-risk asset count** = on-time assets with ≥ 10 Critical/High findings open more than 30 days.

### High-risk classification rules

An asset qualifies as high-risk when it meets **all three** of the following conditions:

1. **Severity filter:** The finding has VPR-derived severity of `critical` or `high` (VPR ≥ 7.0).
2. **Age filter:** Days open is **strictly greater than 30** (a finding open exactly 30 days is **not** counted).
3. **Count threshold:** The asset has **≥ 10** qualifying findings meeting both conditions above.

Only findings on on-time assets contribute to the count.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | High-Risk Assets % ≤ 0.5% |
| Amber (At Risk) | High-Risk Assets % ≤ 1.0% and > 0.5% |
| Red (Off Target) | High-Risk Assets % > 1.0% |

### Values reported

| Value | Description |
|-------|-------------|
| High-Risk Assets % | Percentage of on-time assets classified as high-risk, to one decimal place. |
| High-risk count | Count of high-risk assets. |
| Total on-time assets | Denominator (on-time scanned assets). |

### Edge cases

- If total on-time assets is zero → status is "No Data".
- Assets with no open vulnerabilities cannot be high-risk (count = 0 < 10 threshold).
- Days open is computed as `report date − first_found` in whole days. Findings where `first_found` cannot be parsed are excluded from the count.

---

## 9. Metric 4 — Aged Vulnerability Assets

**Direction:** Lower is better
**Target:** ≤ 2% green / ≤ 5% amber / > 5% red

### What it measures

The percentage of **on-time scanned** assets that have **at least one** Medium, High, or Critical open vulnerability that has been open for **more than 90 days**.

### Formula

> **Aged Assets % = (aged asset count ÷ total on-time assets) × 100**

Where:

- **Total on-time assets** = deduplicated licensed assets scanned within the last 30 days (shared baseline).
- **Aged asset count** = on-time assets with ≥ 1 Medium/High/Critical finding open more than 90 days.

### Aged classification rules

An asset qualifies as aged when it has **at least one** finding meeting **both** of the following conditions:

1. **Severity filter:** VPR-derived severity is `medium`, `high`, or `critical` (VPR ≥ 4.0).
2. **Age filter:** Days open is **strictly greater than 90** (a finding open exactly 90 days is **not** counted).

Only findings on on-time assets are evaluated.

### Thresholds

| Status | Condition |
|--------|-----------|
| Green (On Target) | Aged Assets % ≤ 2% |
| Amber (At Risk) | Aged Assets % ≤ 5% and > 2% |
| Red (Off Target) | Aged Assets % > 5% |

### Values reported

| Value | Description |
|-------|-------------|
| Aged Assets % | Percentage of on-time assets with at least one qualifying aged finding, to one decimal place. |
| Aged count | Count of aged assets. |
| Total on-time assets | Denominator (on-time scanned assets). |

### Edge cases

- If total on-time assets is zero → status is "No Data".
- An asset is only counted once regardless of how many aged findings it has — this is asset-level membership, not finding-level.
- Low-severity findings (VPR < 4.0) are excluded; they have a 180-day SLA and are not tracked by this board metric.
- Days open is computed as `report date − first_found` in whole days. Findings where `first_found` cannot be parsed are excluded.

---

## 10. Metric 5 — Accepted/Recast by Owner

**Module:** `reports/modules/accepted_recast_module.py` (`accepted_recast`)
**Direction:** Lower exception rate is better
**Target:** ≤ 5% green / ≤ 15% amber / > 15% red (overridable via module options)

### What it measures

The count of open findings that have been formally risk-managed by an analyst — either accepted as residual risk or had their severity recast — cut by the asset's Owner tag. ACCEPTED and RECASTED findings are tracked **separately** (never aggregated into a single number), because they represent different operational decisions.

- **Accepted** — `severity_modification_type == "ACCEPTED"` (risk acknowledged, no further action expected)
- **Recasted** — `severity_modification_type == "RECASTED"` (severity adjusted by an analyst)

Unlike Metrics 2–4, this module intentionally reads the **full** `vulns_df` — it is **not** filtered by `exclude_risk_managed()` (see [Exclusion of risk-managed findings](#exclusion-of-risk-managed-findings-metrics-3-4-and-2s-sla-population) above), since risk-managed findings are exactly the population it exists to surface.

### Formula

```
open_df           = vulns WHERE state IN {"OPEN", "REOPENED"}
total_open        = len(open_df)
accepted_df       = open_df WHERE severity_modification_type.upper() == "ACCEPTED"
recasted_df       = open_df WHERE severity_modification_type.upper() == "RECASTED"
accepted_count    = len(accepted_df)   # after expiry cross-check, below
recast_count      = len(recasted_df)   # after expiry cross-check, below
total_exceptions  = accepted_count + recast_count
exception_rate    = (total_exceptions / total_open) × 100   (None when total_open == 0)
```

### Expired-rule cross-check

When `recast_rules_df` is available (fetched fail-soft from Tenable's recast/accept rules API), findings whose `recast_rule_uuid` maps to a rule with `expires_at` in the past are excluded from the current-period accepted/recast counts and flagged "pending re-evaluation" instead — an expired rule no longer represents an active risk decision. When `recast_rules_df` is absent (fetch failure or no credentials), the cross-check is skipped and finding-level counts are still computed from the raw classification.

### Owner cut

Counts are cut by the Owner tag category via `extract_owner()` — the same shared helper used by Metrics 3 and 4. Assets with no `Owner` tag are grouped under `Unassigned`.

### Month-over-month delta

The current-period accepted/recast counts are compared against the prior month's `accepted_count` / `recast_count` fields read from the local trend store (`read_trend("severity", tag_filter_label, months=13)`). Per the mandatory cold-start branch (Hard Rule 7): when the trend read reports `insufficient_data=True` or the prior month is absent, the delta arrow is omitted entirely — never rendered as "▲ 0%" or a NaN string.

### Thresholds (exception rate)

| Status | Condition |
|--------|-----------|
| Green | Exception rate ≤ 5% |
| Amber | Exception rate ≤ 15% and > 5% |
| Red | Exception rate > 15% |

Both thresholds are overridable per delivery group via `green_exception_rate` / `yellow_exception_rate` module options.

### Values reported

| Value | Description |
|-------|-------------|
| Accepted count | Open ACCEPTED findings (post expiry cross-check). |
| Recast count | Open RECASTED findings (post expiry cross-check). |
| Total exceptions | Accepted count + Recast count. |
| Exception rate | Total exceptions ÷ total open findings, as a percentage. |
| Pending re-evaluation | Count of findings excluded due to an expired recast/accept rule. |

### Edge cases

- When `total_open` is 0, exception rate is `None` and status is "No Data".
- `""`, `"NONE"`, and any value other than `ACCEPTED`/`RECASTED` are excluded from both counts (never silently aggregated).
- Rule-level detail (rule name, action, original/new severity) appears only in the analyst drill-down tab — the headline metric is always a **finding** count, never a rule count.

---

## 11. Data-Quality Notes

Common scenarios the team should recognise when reviewing the numbers:

### All metrics show "No Data"

The report ran but found no licensed, on-time assets. Typical causes:

- **Tag filter too narrow.** The configured tag scope matched zero assets. Confirm the tag category and value are spelled correctly and that assets carrying those tags exist in Tenable.
- **No licensed assets in scope.** Every matching asset has a null `last_licensed_scan_date`. Confirm with the licensing administrator that the scope contains assets covered by a Tenable license.

### Metric 2 shows "No Data" while others have values

No Critical findings were fixed in the last 30 days within the scoped asset population. This is a **valid** data state (no Critical remediation activity in the window). It may also occur if the fixed-vulnerability feed for the run was empty or the scope filter excluded all assets carrying fixed Critical findings.

### Business-unit breakdown is entirely "Untagged"

Assets in scope have no `Application` tag in Tenable. Either add `Application` tags to assets in the Tenable console, or coordinate with the platform team to use a different tag category for business-unit segmentation.

### Scan Coverage is unexpectedly low

Compare the total asset count against the licensed asset count. If a large share of assets lack a `last_licensed_scan_date`, those assets are licensed-unscanned (or unlicensed entirely) and will be excluded from the metric by design. A coverage drop usually signals one of:

- Recent additions to the asset inventory that have not yet been scanned.
- Loss of Tenable license coverage on a portion of the estate.
- A scanner or schedule failure that prevented the most recent monthly scan from running.

### A metric "feels wrong" against last month's number

Two factors most often explain shifts month-to-month:

- **Population change.** Assets added/removed from Tenable, license changes, or a tag-scope change will shift the denominator.
- **Threshold crossings.** The strict ">30 days" and ">90 days" age filters mean an asset can flip in or out of the metric on a single day. The counts are not a continuous distribution — they're a population that crossed a hard age boundary.

When investigating a swing, start with the on-time asset denominator and the qualifying-finding count for the affected BU; one of those two will usually explain the move.