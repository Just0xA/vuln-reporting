# Vulnerability Type Distribution — Calculations Runbook

**Module ID:** `vuln_type_distribution`
**Audience:** Auditors, metrics team, analysts verifying report numbers
**Delivery:** Via `composed_report` slug; any YAML delivery group with
`modules: [vuln_type_distribution]`

This runbook documents what the module measures, which fields it draws from,
and how the numbers are derived. It is intended for anyone validating or
auditing the output. Operational concerns (scheduling, file outputs) live in
`RUNBOOK.md`.

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Data Source and Scope](#2-data-source-and-scope)
3. [The VTD-01 Family-Override Classifier (D4)](#3-the-vtd-01-family-override-classifier-d4)
4. [CPE Part-Letter Precedence](#4-cpe-part-letter-precedence)
5. [Denominator: Within-Tag (D5)](#5-denominator-within-tag-d5)
6. [Coverage Statistics](#6-coverage-statistics)
7. [Hardware Row Hidden When Zero](#7-hardware-row-hidden-when-zero)
8. [Open States (D6)](#8-open-states-d6)
9. [RAG Strip Behaviour](#9-rag-strip-behaviour)
10. [Data-Quality Notes](#10-data-quality-notes)

---

## 1. Purpose

For a selected Tenable tag, this module shows the **CPE type distribution** of
the tag's open findings, broken into four buckets:

| Bucket | Meaning |
|--------|---------|
| **Application** | Third-party / end-user software (browsers, Office, databases, middleware) |
| **OS** | Operating system and distro-level packages |
| **Hardware** | Network devices, firmware, embedded systems |
| **Other** | Findings that could not be classified by family or CPE |

Count and percentage are **within-tag only** (not vs the environment).

---

## 2. Data Source and Scope

| Field | Source |
|-------|--------|
| `state` | `tio.exports.vulns()`, field `state` |
| `plugin_family` | `tio.exports.vulns()`, field `plugin_family` |
| `cpe` | `tio.exports.vulns()`, comma-joined CPE string; see `data/fetchers.py:343` |
| `asset_uuid` | Used by `composed_report.py` to apply the tag filter before passing `vulns_df` to this module |

`vulns_df` arrives **already tag-filtered** (the `composed_report` slug applies
the YAML group's `tag_category` / `tag_value` filter before calling the module
pipeline).

---

## 3. The VTD-01 Family-Override Classifier (D4)

Classification follows a strict priority order. The first rule that matches wins.

```
classify(plugin_family, cpe):
  1. If plugin_family matches OS_FAMILY regex → "OS"
  2. Else if any CPE contains part 'a'          → "Application"
  3. Else if any CPE contains part 'o'          → "OS"
  4. Else if any CPE contains part 'h'          → "Hardware"
  5. Else                                       → "Other"
```

### Step 1 — Family override

The `OS_FAMILY` regex covers:

```
local security checks | red hat | centos | oracle linux | ubuntu |
debian | suse | amazon linux | rocky | alma | fedora | microsoft bulletin
```

**Why this override exists:** Linux distribution "Local Security Checks" plugins
carry CPEs in the form `cpe:/a:<package>` — the CPE part letter is `a`
(Application). Without the override, these OS patch findings would land on the
Application tile. On real Tenable data, this affects approximately **6% of
OS-volume findings** — a significant misclassification that would overstate the
Application bucket.

**Microsoft Bulletins** similarly carry `cpe:/a:microsoft:...` CPEs for OS-level
Windows patches. The override routes them to OS as OS-team remediation work.

**Deliberate non-override example:** Findings in the `"Windows"` plugin family
are third-party applications (Adobe Reader, Google Chrome, Java, Office). Their
`cpe:/a:...` CPE is correct — the override intentionally does not fire for the
generic `Windows` family name.

### Steps 2–4 — CPE part letter

The CPE standard encodes the type in the part letter:

| Part | CPE format (2.2) | CPE format (2.3) | Bucket |
|------|------------------|------------------|--------|
| `a` | `cpe:/a:...` | `cpe:2.3:a:...` | Application |
| `o` | `cpe:/o:...` | `cpe:2.3:o:...` | OS |
| `h` | `cpe:/h:...` | `cpe:2.3:h:...` | Hardware |

Both CPE format versions (2.2 and 2.3) are recognised via the regex:

```python
_CPE_PART = re.compile(r"cpe:(?:2\.3:|/)([aoh])[:/]", re.IGNORECASE)
```

### Step 5 — "Other" fallback

When neither the family override nor the CPE part letter applies (missing CPE,
unparseable CPE, or unrecognised family), the finding is classified as `"Other"`.

**Important:** The fallback label is `"Other"`, **not** `"Unclassified"` (spec D4).
This is a labelling decision, not an error bucket.

---

## 4. CPE Part-Letter Precedence

When a finding's CPE string contains **multiple CPE entries** (the `cpe` field
is comma-joined), precedence is applied: `a > o > h`.

Examples:

| CPE string | Result |
|------------|--------|
| `cpe:/a:openssl:openssl, cpe:/o:linux:kernel` | **Application** (a wins) |
| `cpe:/o:linux:kernel, cpe:/h:cisco:router` | **OS** (o wins over h) |
| `cpe:/h:cisco:router` | **Hardware** |

---

## 5. Denominator: Within-Tag (D5)

```
pct[bucket] = count[bucket] / tag_total * 100.0
```

where `tag_total` is the number of open findings in the tag scope (all buckets
combined).

- The percentages sum to 100% (within floating-point tolerance).
- **Divide-by-zero guard:** when `tag_total == 0`, all pcts are `0.0`.

This is **not** a share of the environment (cf. `tag_severity_share_module` which
uses `env_vuln_total` as its denominator). The type distribution is a within-tag
breakdown only.

---

## 6. Coverage Statistics

Based on spike 001 (`sources/001-cpe-coverage-crit-high/`) on real production
Tenable data:

| Outcome | Share of Critical + High findings |
|---------|-----------------------------------|
| Classified (Application / OS / Hardware) | ~99.2% |
| Other (unclassified) | ~0.8% |

The ~0.8% Other rate is considered negligible. Without the VTD-01 family
override, approximately **6% of OS-volume findings would misclassify as
Application**, overstating application exposure and understating OS exposure.

---

## 7. Hardware Row Hidden When Zero

When the Hardware bucket count is 0, the Hardware row is **omitted entirely**
from the PDF table, Excel tab, and email panel. This is expected behaviour —
Hardware findings are rare or absent in most production environments (confirmed
by spike data).

The `hide_hardware` flag is stored in `ModuleData.metadata` and checked by all
renderers. An auditor who does not see a Hardware row should not interpret it as
a data error; it means the count is 0.

---

## 8. Open States (D6)

**Included:** `state in {"open", "reopened"}` only.

The reopened-aware historical two-interval predicate (spike 002) is intentionally
**not** used. D6 locks current-snapshot semantics: the module shows the type
distribution of what is open **right now**, not as of a past date.

Informational findings are excluded upstream by the fetcher and never appear
in `vulns_df`.

---

## 9. RAG Strip Behaviour

The cover-page RAG strip headline is the Application bucket's within-tag
percentage.

| Condition | Status | Colour |
|-----------|--------|--------|
| `tag_total == 0` | `no_data` | Gray `#757575` |
| `tag_total > 0` | `yellow` (informational) | Amber `#f57c00` |

**Important:** The amber/yellow status does **not** indicate a threshold breach.
No pass/fail boundary was locked for this metric in the design spec. The colour
is a neutral informational signal meaning "data present, no automated verdict."

---

## 10. Data-Quality Notes

- **CPE lag:** Not all Tenable plugins ship with CPE data. Findings without a
  CPE and with a non-OS-family plugin will fall into `Other`. This is expected
  and reflected in the ~0.8% Other rate.
- **Multiple CPEs per finding:** The `cpe` field is a comma-joined string
  (fetchers.py:343). The classifier checks all CPEs and applies a>o>h
  precedence. A finding with both an application CPE and an OS CPE is
  classified as Application.
- **Empty tag scope:** If a tag filter produces zero matched assets, `tag_total`
  will be 0 and the module renders a gray "No Data" RAG cell. This is the
  expected empty-data guard behaviour, not a calculation error.
- **Scope at time of run:** Classification uses the current `plugin_family` and
  CPE values from the run-day export. Historical reclassifications (Tenable
  updating a plugin family or CPE) are not retroactively applied to past
  snapshots.
