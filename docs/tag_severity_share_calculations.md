# Tag Severity Share vs Environment — Calculations Runbook

**Module ID:** `tag_severity_share`
**Audience:** Auditors, metrics team, analysts verifying report numbers
**Delivery:** Via `composed_report` slug; any YAML delivery group with
`modules: [tag_severity_share]`

This runbook documents what the module measures, which fields it draws from,
and how the numbers are derived. It is intended for anyone validating or
auditing the output. Operational concerns (scheduling, file outputs) live in
`RUNBOOK.md`.

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Data Source and Scope](#2-data-source-and-scope)
3. [Denominator: Environment Grand Total (D1)](#3-denominator-environment-grand-total-d1)
4. [Severity Buckets — VPR-Pure with None Bucket (D2)](#4-severity-buckets--vpr-pure-with-none-bucket-d2)
5. [Intentional Divergence: No Native-Severity Fallback (D3)](#5-intentional-divergence-no-native-severity-fallback-d3)
6. [Per-Severity Percentage Formula](#6-per-severity-percentage-formula)
7. [Tag Share Percentage](#7-tag-share-percentage)
8. [Open States and Informational Exclusion (D6, D8)](#8-open-states-and-informational-exclusion-d6-d8)
9. [No-Tag Degenerate Case (D7)](#9-no-tag-degenerate-case-d7)
10. [RAG Strip Behaviour](#10-rag-strip-behaviour)
11. [Data-Quality Notes](#11-data-quality-notes)

---

## 1. Purpose

For a selected Tenable tag, this module shows the **VPR severity distribution
of the tag's open findings expressed as a share of the entire environment's
open-finding total**. Each severity row answers: "What fraction of all
environment findings are Critical / High / Medium / Low / None within this tag?"

The five rows therefore sum to the **tag's overall share of the environment**,
not to 100%.

---

## 2. Data Source and Scope

| Field | Source |
|-------|--------|
| `state` | `tio.exports.vulns()`, field `state` |
| `vpr_score` | `tio.exports.vulns()`, field `vpr_score` (raw float; `null` when Tenable has not assigned a VPR) |
| `asset_uuid` | Used by `composed_report.py` to apply the tag filter before passing `vulns_df` to this module |

`vulns_df` arrives **already tag-filtered** (the `composed_report` slug applies
the YAML group's `tag_category` / `tag_value` filter via `_filter_assets_by_tag`
before calling the module pipeline).

`env_vuln_total` is computed from the **unfiltered** `vulns_df` (all assets, all
severities) before the tag filter is applied. See
[Section 3](#3-denominator-environment-grand-total-d1) for details on how it is
forwarded to this module.

---

## 3. Denominator: Environment Grand Total (D1)

```
env_vuln_total = count of rows where state in {"open", "reopened"}
                 in the UNFILTERED vulns_df
                 (all assets, all severities, all tags)
```

`composed_report.py` computes this total **before** applying the tag filter,
then passes it to the module via `env_vuln_total` in `**kwargs`. The gating
mechanism mirrors `fixed_vulns_df` for `critical_remediation_sla` — see
`_MODULES_NEEDING_ENV_TOTAL` in `composed_report.py`.

**Why this denominator?** Decision D1 (locked): each severity percentage is the
tag's count at that severity divided by the total number of open findings across
the **entire environment**. This makes the rows directly comparable across
different tags and answers "how much of our overall exposure does this tag
represent at each severity tier?"

---

## 4. Severity Buckets — VPR-Pure with None Bucket (D2)

| Bucket | Rule |
|--------|------|
| Critical | `vpr_score` 9.0 – 10.0 |
| High | `vpr_score` 7.0 – 8.9 |
| Medium | `vpr_score` 4.0 – 6.9 |
| Low | `vpr_score` 0.1 – 3.9 |
| **None** | `vpr_score` is `null` / `NaN` / `0.0` |

The **None bucket** (D2) matches what the Tenable GUI displays as "None
severity" — findings that Tenable has not yet scored with a VPR, or that
scored exactly 0.0. These are real findings; they are not excluded.

---

## 5. Intentional Divergence: No Native-Severity Fallback (D3)

**This module does NOT fall back to Tenable's native (CVSS-derived) severity
when `vpr_score` is null.**

A finding with `vpr_score = null` lands in the **None** bucket unconditionally,
regardless of what Tenable's `severity` field contains.

### Why this is intentional — not a bug

This module's purpose is to measure VPR exposure. A finding without a VPR
score has unknown VPR-based priority. Promoting it to Critical or High via its
native severity would misstate the VPR picture and inflate the tiers that drive
SLA timers.

### Where this diverges from other parts of the suite

| Context | Behaviour |
|---------|-----------|
| **This module (`tag_severity_share`)** | `null`/`0.0` VPR → **None bucket**. No native fallback. |
| `config.vpr_to_severity()` used elsewhere | `null` VPR falls back to native severity. This is the default for most other reports. |
| Spike's `vpr_to_severity(fallback=native_severity)` | Same fallback behaviour as `config.vpr_to_severity`. |

An auditor seeing a count in the **None** bucket should read it as "findings
that Tenable has not yet VPR-scored (or scored as 0)." It is **not** an error
in the report.

The global change to apply None-bucket semantics everywhere (decoupling `vpr_to_severity`
from native fallback) is captured as a separate ROADMAP item (D9) and will be
coordinated across all consuming reports when it ships.

---

## 6. Per-Severity Percentage Formula

```
pct[sev] = tag_count[sev] / env_vuln_total * 100.0
```

- `tag_count[sev]` — number of the tag's open findings bucketed into `sev`.
- `env_vuln_total` — see [Section 3](#3-denominator-environment-grand-total-d1).
- **Divide-by-zero guard:** when `env_vuln_total == 0`, all pcts are `0.0`.

---

## 7. Tag Share Percentage

```
tag_share_pct = tag_total / env_vuln_total * 100.0
```

where `tag_total` is the sum of all five `tag_count[sev]` values (all open
findings for the tag regardless of severity).

`tag_share_pct` equals the sum of the five per-severity pcts (within floating-
point tolerance). This row-sum invariant is checked in the unit tests
(`test_pcts_sum_to_tag_share_pct`).

---

## 8. Open States and Informational Exclusion (D6, D8)

**Open states included:** `state in {"open", "reopened"}` only.
- `"fixed"`, `"resolved"`, and any other state are excluded.
- The reopened-aware historical predicate (spike 002) is intentionally **not**
  used here — D6 locks current-snapshot semantics: what is open right now.

**Informational findings:** Findings with `severity == "info"` (Tenable's
internally derived metadata noise) are excluded **upstream by the fetcher**
(`data/fetchers.py`) and never appear in `vulns_df`. No code change is needed
here to exclude them. The None bucket therefore contains only non-informational
findings that lack a VPR score.

---

## 9. No-Tag Degenerate Case (D7)

When no tag filter is configured (YAML `filters: {}`), the module receives the
full unfiltered `vulns_df` as both the tag-scoped frame and the denominator
frame. In this case:

- `tag_total == env_vuln_total`
- The five severity pcts sum to approximately 100% (representing the
  environment's own VPR severity distribution)

This is correct and expected behaviour, not an error. The report shows the
environment-wide distribution as if the entire environment were the "tag."

---

## 10. RAG Strip Behaviour

The cover-page RAG strip headline is the tag's share of the environment
(`tag_share_pct` formatted as a percentage).

| Condition | Status | Colour |
|-----------|--------|--------|
| `tag_total == 0` | `no_data` | Gray `#757575` |
| `tag_total > 0` | `yellow` (informational) | Amber `#f57c00` |

**Important:** The amber/yellow status does **not** indicate a threshold breach.
No SLA threshold or pass/fail boundary was locked for this metric in the design
spec. The colour is a neutral informational signal meaning "data present, no
automated verdict." An auditor should read it as equivalent to "informational"
rather than "at risk."

---

## 11. Data-Quality Notes

- **VPR lag:** Tenable assigns VPR scores asynchronously. Newly discovered
  findings may appear in the None bucket for 24–48 hours before Tenable
  computes their VPR. A spike in the None bucket immediately after a large scan
  is expected and will resolve as VPR scores are assigned.
- **Scan timing:** `env_vuln_total` and the tag-filtered count are drawn from
  the same cached export run at the start of the batch. Both are point-in-time
  consistent; no cross-day staleness.
- **Empty tag scope:** If a tag filter produces zero matched assets, `tag_total`
  will be 0 and the module renders a gray "No Data" RAG cell with the driver
  "No data in scope." This is the expected empty-data guard behaviour, not a
  calculation error.
