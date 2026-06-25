# Trend and Segmentation Calculations Runbook

**File:** `data/trend_store.py`, `utils/open_count.py`, `reports/owner_supplemental.py`
**Audience:** Auditors and operators verifying open-count correctness, trend history integrity, and Owner/Unassigned segmentation behaviour
**Outputs:** `data/trend/trend_<dimension>_<tagsuffix>.json` (persisted aggregate trend); `output/<run>/owner_segmentation.xlsx` + `.csv` (analyst supplemental, run-scoped)
**Schedule:** Snapshot capture runs once per month via `scripts/capture_trend_snapshot.py` (or whenever `run_report()` triggers it). The supplemental is generated on each board run.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Data Sources](#2-data-sources)
3. [Open Predicate — Reopened-Aware Two-Interval Model](#3-open-predicate--reopened-aware-two-interval-model)
4. [~29-Day Retention and Forward-Accumulation Model](#4-29-day-retention-and-forward-accumulation-model)
5. [Owner / Unassigned Segmentation Model](#5-owner--unassigned-segmentation-model)
6. [Combined Supplemental (Owner/Application Excel + CSV)](#6-combined-supplemental-ownerapplication-excel--csv)
7. [Trend Composition and Data Store](#7-trend-composition-and-data-store)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Quick Start

### Capture a monthly owner snapshot

```bash
# Capture both severity and owner snapshots for the current month
# (requires .env credentials)
python scripts/capture_trend_snapshot.py

# With a tag filter
python scripts/capture_trend_snapshot.py \
    --tag-category "Environment" --tag-value "Production"
```

The script captures the severity-dimension snapshot first, then the owner-dimension snapshot.
Both write to `data/trend/`. Exit code 0 = both succeeded; exit code 3 = owner capture failed
(severity was still written).

### Read owner trend back in Python

```python
from data.trend_store import read_trend

result = read_trend("owner", "all_assets")
# Returns: {"snapshots": [...], "insufficient_data": bool}

if result["insufficient_data"]:
    print("Not enough history yet — accumulate more monthly snapshots.")
else:
    for snap in result["snapshots"]:
        print(snap["month"], snap)  # per-Owner open counts keyed by owner name
```

### Run the board report and produce the supplemental

```bash
python run_all.py --group "Board Summary" --no-email
# Outputs: output/<timestamp>-Board-Summary/
#   board_summary.pdf / .xlsx        (standard delivery artifacts)
#   owner_segmentation.xlsx / .csv   (analyst supplemental — see Section 6)
```

---

## 2. Data Sources

| Data | Source | Cached As |
|---|---|---|
| Open + reopened vulnerabilities | `tio.exports.vulns()` — states `open`, `reopened` | `vulns_all.parquet` |
| All asset inventory | `tio.exports.assets()` | `assets_all.parquet` |

Severity is derived from the **VPR score** (`vpr_score` field), not the native Tenable severity
label. When `vpr_score` is null the native severity is used as a fallback.

The `owner` column is derived at runtime from the `tags` column of `assets_all.parquet` by
`extract_owner()` in `reports/modules/board_report_utils.py`. It is not stored in the parquet
cache — tag enrichment runs in-memory on each report execution.

---

## 3. Open Predicate — Reopened-Aware Two-Interval Model

**Source file:** `utils/open_count.py` — `open_findings_at(df, date)`

### Why the naive predicate is insufficient

A simple "open-at-date-D" predicate might read:

```
last_fixed IS NULL OR last_fixed > D
```

This form silently drops the entire **REOPENED** population — approximately **19% of findings**
on real Tenable data. A REOPENED finding was fixed once and then reappeared; its `state` field
is `"reopened"` and both `last_fixed` and `resurfaced_date` are populated. The naive predicate
evaluates `last_fixed IS NULL` as False (because `last_fixed` exists) and `last_fixed > D` as
False (because the fix event is in the past), and therefore incorrectly classifies the finding
as fixed. This is a structural silent undercount, not an edge case.

### The two-interval model (implemented)

`open_findings_at` uses three terminal-state clauses. A finding is **fixed at date D** when
any of the following is true:

1. **`state == FIXED`** — the finding is in terminal-fixed state. State is authoritative;
   `last_fixed` presence is not required (Tenable occasionally exports FIXED rows with no
   `last_fixed` date).

2. **`state == REOPENED` and `last_fixed <= D` and `resurfaced_date` is known and `D < resurfaced_date`** —
   the finding is in the gap between its fix and its resurface. It was closed on `last_fixed`
   and had not yet reappeared by date D. Closed at D.

3. **`state == REOPENED` and `last_fixed <= D` and `resurfaced_date` is `NaT`** —
   the finding was fixed (`last_fixed` exists) but never resurfaced. Treated as closed.

A finding is **open at D** when it was born (first_found <= D, or first_found is NaT — see
NaT policy below) **and** none of the three fixed clauses above apply.

In Python (from `utils/open_count.py`):

```python
fixed = (
    (st == "FIXED")
    | ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.notna() & (D < rs))
    | ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.isna())
)
return df[born & ~fixed]
```

where `st = df["state"].astype(str).str.upper()`, `lf = df["last_fixed"]`,
`rs = df["resurfaced_date"]`, and `D` is the reference date as a UTC-aware `pd.Timestamp`.

### NaT-first_found policy

A finding with `first_found = NaT` cannot reliably be excluded on a "born after D" basis. The
predicate errs toward **inclusion** (counts the finding as present/born) and logs a warning so
the data-quality issue is observable rather than silently suppressing findings. This follows the
WR-01/WR-02 over-count-prevention vs silent-undercount tradeoff.

### Required columns

`open_findings_at` requires the DataFrame to have these columns, normalised to
`datetime64[ns, UTC]` by `data.fetchers._normalize_vuln_dates` **before** calling the predicate:

| Column | Type | Notes |
|---|---|---|
| `first_found` | `datetime64[ns, UTC]` | NaT-tolerant; see NaT policy above |
| `last_fixed` | `datetime64[ns, UTC]` | NaT = never fixed |
| `resurfaced_date` | `datetime64[ns, UTC]` | NaT = never resurfaced |
| `state` | `str` | `"open"`, `"reopened"`, or `"fixed"` (lowercased by fetcher; uppercased inside predicate) |

The `severity` column is VPR-classified upstream; `open_findings_at` does not inspect or
reclassify it.

---

## 4. ~29-Day Retention and Forward-Accumulation Model

### The hard constraint

Tenable Vulnerability Management retains fixed findings for approximately **29 days** after
the fix date. After that window the finding ages out of the export and is no longer returned by
`tio.exports.vulns(state=["fixed"])`. This means:

- **Multi-month open-count history cannot be reconstructed** from a current export. Applying
  `open_findings_at(df, date_three_months_ago)` on today's DataFrame will undercount because
  fixed-then-aged-out findings are absent from `df`.
- **The substrate is forward-accumulating snapshots only.** Each monthly run captures the
  current open count and appends it to the trend JSON file. History grows one snapshot per
  month as runs execute.

### Cold start

When a trend JSON file does not exist (first run for a given dimension + tag scope), there is
no historical data. `read_trend` returns `insufficient_data=True` and modules display a
"Trend data is being established" notice. **This is expected behaviour, not an error.** History
accumulates from the first captured snapshot forward; there is no mechanism to backfill prior
months.

### Backfill

**Sanctioned path — `scripts/backfill_trend_reconstruction.py`:** A one-time idempotent
reconstruction script seeds historical all-assets MoM severity history (~12 months) from
Tenable's fixed+open exports.  Use this script for the initial seed after a fresh install.
It applies an overlap-test gate before writing and marks reconstructed months with
`source: "reconstructed"` so they are distinguishable from live captures.  See the script's
module docstring for full usage, exit codes, and constraints.

**Unsupported ad-hoc backfill:** Do not attempt to add JSON entries by hand or write a
custom backfill outside the sanctioned script.  Manual entries bypass the overlap-test gate
and immutability checks, risking misleading trend data.  If a month's snapshot was missed
and the reconstruction window has passed, that month is simply absent — the next captured
snapshot becomes the new earliest data point.

### Same-month idempotency

Running the snapshot capture multiple times in the same calendar month overwrites the existing
entry for that `(month, tag_filter)` pair rather than appending a duplicate. The most recent
run per month is retained. This is by design.

---

## 5. Owner / Unassigned Segmentation Model

**Source file:** `reports/modules/board_report_utils.py` — `extract_owner(assets_df, ...)`

### Ownership model (D-01)

The `Owner` Tenable tag category identifies the **Application Support group** responsible for
maintaining and patching the application. This is the routing dimension for vulnerability
reporting: open findings are grouped and trended by Owner because that is where remediation
accountability sits.

The ownership model distinguishes three categories:

| Category | Tag / Source | Status |
|---|---|---|
| **Owner** (primary) | `Owner=<Application Support group>` Tenable tag | **Active** — Phase 13 target |
| Business Unit | Future `business_unit` tag (not yet populated in Tenable) | Reference-only; not built |
| Technical Support | Future category for OS/server engineering (MS Security Updates, OS vulns) | Reference-only; not built |

The column produced by `extract_owner` is named `owner` (D-04). The `business_unit` name is
reserved for the future real Business Unit tag and must not be reused.

### Application as nested drill-down (D-05)

The `Application` tag category is extracted alongside `Owner` by `extract_owner` and stored in
an `application` column. It is a **nested analyst drill-down** dimension, not the primary
grouping dimension. The combined supplemental (Section 6) surfaces both columns so analysts
can see which applications sit under each Owner and identify gaps.

### Unassigned catch-all (SEG-02, D-06)

Any asset that carries no `Owner` tag (or an empty `Owner` tag value) is labelled
**`"Unassigned"`** by `extract_owner`. The default label is the string constant
`_DEFAULT_UNASSIGNED_LABEL = "Unassigned"` in `board_report_utils.py`; callers can override
it via the `unassigned_label` parameter if the report requires a different display label.

The Unassigned bucket guarantees that per-Owner totals **reconcile to the whole**: summing
open findings across all Owner groups (including Unassigned) equals the total open count for
the scope. No findings are dropped or double-counted.

### Fail-soft behaviour (SEG-04, D-07)

If the `tags` column is absent from `assets_df` (data pipeline issue, schema change), or if no
`Owner` tokens are found in any tag string:

- `extract_owner` logs a warning but does **not raise**.
- All assets are labelled `Unassigned`; the `application` column is set to `""`.
- Downstream report rendering continues — an all-Unassigned result is a valid (if diagnostic)
  output rather than a crash.

This fail-soft behaviour applies to all four board metric modules that consume `extract_owner`
output.

### Tag format

The `tags` column in the asset DataFrame stores tags as a semicolon-delimited
`"Category=Value"` string produced by `fetch_all_assets()`:

```
"Application=Finance;Environment=Production;Owner=Network Defense"
```

`extract_owner` makes a single pass over each tag string, extracting `Owner` and `Application`
values. Category matching is case-insensitive (`casefold()`). When multiple distinct values
exist for the same category, they are joined with `"; "` in alphabetical order. The function
returns a copy of the input DataFrame with `owner` and `application` columns appended; the
original is not mutated.

---

## 6. Combined Supplemental (Owner/Application Excel + CSV)

**Source file:** `reports/owner_supplemental.py` — `write_owner_supplemental(assets_df, vulns_df, output_dir)`

### What it produces

The combined supplemental is a flat `Owner | Application | Open Findings | Asset Count`
workbook providing analyst drill-down into the Owner segmentation for a given run. It is
generated on each board report run by `reports/board_summary.py`.

**Files written per run:**

| File | Location | Description |
|---|---|---|
| `owner_segmentation.xlsx` | `output/<run>/` | Single `Owner Assignment` tab |
| `owner_segmentation.csv` | `output/<run>/` | Same data, CSV variant |

### Tab structure (Owner Assignment)

Each row represents one `(Owner, Application)` group:

| Column | Source |
|---|---|
| Owner | `extract_owner` → `owner` column |
| Application | `extract_owner` → `application` column |
| Open Findings | Count of findings open at the run's `report_date` via `open_findings_at(vulns_df, report_date)`, so this column ties out to the owner trend snapshot from the same run |
| Asset Count | Count of distinct assets in this group |

Rows with `Owner = "Unassigned"` double as a **tagging-cleanup worklist** — they identify
applications (and assets) that still need an Owner tag assigned in Tenable. Sorting by Owner
then Application surfaces these rows together.

### PII rule (D-10)

The supplemental contains application-group and asset-count data that is specific enough to be
considered sensitive operational detail. The rule governing its handling is:

- **Internal email: permitted.** The supplemental may be attached to a corporate email and
  sent to the relevant analyst or operations team. It is not a public document but it is not
  restricted from internal use.
- **Repository commit: prohibited.** The supplemental must not be committed to the Git
  repository. The `output/` directory is listed in `.gitignore` for this reason.
- **AI / Claude context: prohibited.** Row-level application and asset data from the
  supplemental must not be pasted into or fed to an AI assistant (Claude or otherwise). The
  prohibition is about **AI/repo exposure**, not about internal email.

This is the real rationale behind D-04-08 / SEG-03. The literal SEG-03 phrasing "not attached
to any email" is superseded by D-10's clarification. The output path (`output/`, gitignored) is
the enforcement mechanism for the repo constraint; the AI constraint relies on operator
discipline.

### Fail-soft wiring

The call to `write_owner_supplemental` in `reports/board_summary.py` is wrapped in a
`try/except` block. If the supplemental writer fails (e.g. openpyxl error, disk full), the
failure is logged and the board PDF/Excel delivery continues unaffected. The result dict will
carry `None` for `supplemental_excel` and `supplemental_csv` in that case.

---

## 7. Trend Composition and Data Store

**Source file:** `data/trend_store.py` — `capture_snapshot(...)`, `read_trend(...)`

### File-per-dimension shape (D-03)

Each dimension + tag scope combination has its own JSON file under `data/trend/`. The naming
convention is:

```
data/trend/trend_<dimension>_<tag_suffix>.json
```

Where `<tag_suffix>` is:
- `all_assets` when no tag filter is applied
- A sanitised `Category_Value` string when a tag filter is applied (spaces and special
  characters replaced with underscores)

**Examples:**

```
data/trend/
├── trend_severity_all_assets.json        # Phase 12 severity dimension, all assets
├── trend_severity_environment_production.json
├── trend_owner_all_assets.json           # Phase 13 owner dimension, all assets
└── trend_owner_environment_production.json
```

The owner-dimension file for all assets is `data/trend/trend_owner_all_assets.json`. This is
the canonical path produced by `capture_trend_snapshot.py` when run without a tag filter.

### Snapshot payload structure

Each snapshot entry in the JSON is a dict with these fields:

**Severity dimension (Phase 12):**
```json
{
  "month": "2026-06",
  "tag_filter": "all_assets",
  "critical": 12,
  "high": 47,
  "medium": 183,
  "low": 61,
  "asset_count": 245,
  "generated_at": "2026-06-01T07:04:22Z"
}
```

**Owner dimension (Phase 13):**
```json
{
  "month": "2026-06",
  "tag_filter": "all_assets",
  "Network Defense": 18,
  "Finance Application Support": 34,
  "Unassigned": 51,
  "asset_count": 245,
  "generated_at": "2026-06-01T07:04:27Z"
}
```

Owner-dimension payloads use **arbitrary Owner names as keys**. No row-level asset or
finding data appears in the snapshot — payloads are aggregate counts only (TREND-06, D-11).

### Timezone policy

- `month` key — server local time (`date.strftime("%Y-%m")`, no timezone conversion)
- `generated_at` — UTC (`datetime.now(tz=timezone.utc)`)

This matches the project-wide convention: schedule matching uses local time; audit timestamps
use UTC.

### tag_filter consistency requirement (Pitfall 6)

The `tag_filter` string passed to `read_trend` **must exactly match** the value stored at
capture time. `read_trend` builds the file path as
`trend_<dimension>_<tag_filter>.json` and then filters entries to `snap["tag_filter"] == tag_filter`.
A mismatch (e.g. `"all_assets"` vs `"All_Assets"`, or a differently sanitised tag string)
will produce an empty snapshot list and `insufficient_data=True` even when the file contains
months of valid history.

If `read_trend` returns `insufficient_data=True` on a file you know to be populated, confirm
that the `tag_filter` value used by the caller matches the stored value:

```python
import json
from pathlib import Path

path = Path("data/trend/trend_owner_all_assets.json")
data = json.loads(path.read_text())
print([s["tag_filter"] for s in data["snapshots"]])
# Compare against what your caller is passing
```

### Capturing a snapshot in code

```python
from datetime import datetime, timezone
from data.trend_store import capture_snapshot
from reports.modules.board_report_utils import extract_owner

# Caller enriches assets with extract_owner before passing to capture_snapshot.
# This keeps data/trend_store.py free of reports/modules/ imports.
enriched_assets = extract_owner(assets_df)

capture_snapshot(
    df=vulns_df,
    assets_df=assets_df,
    date=datetime.now(tz=timezone.utc),
    dimension="owner",
    tag_filter="all_assets",
    enriched_assets=enriched_assets,
)
```

The `enriched_assets` parameter is **required** when `dimension="owner"`. Passing
`enriched_assets=None` with `dimension="owner"` raises `ValueError` immediately (loud,
testable failure — T-13-12). For `dimension="severity"` the parameter is unused and may be
omitted.

---

## 8. Troubleshooting

### `insufficient_data=True` on every call

**Cause 1 — cold start:** No snapshot file exists for this `(dimension, tag_filter)` pair.
The first run after setup will always produce `insufficient_data=True`. Capture at least two
monthly snapshots before expecting trend data.

**Cause 2 — tag_filter mismatch:** The `tag_filter` string passed to `read_trend` does not
exactly match the value stored at capture time. See the tag_filter consistency requirement in
Section 7. Check stored values directly in the JSON file.

**Cause 3 — file path:** Verify `data/trend/` exists and is writable. If the directory is
missing, `capture_snapshot` will create it, but `read_trend` on a non-existent path returns
`[]` and `insufficient_data=True` immediately.

### All rows showing Owner = "Unassigned"

**Cause 1 — Owner tag not assigned in Tenable:** Assets in the scope have no `Owner` tag.
Open the Tenable console and verify that the `Owner` tag category and its values have been
assigned to assets. The Unassigned supplemental rows from Section 6 identify which assets need
tags.

**Cause 2 — `assets_df` not enriched before capture:** `capture_snapshot(dimension="owner")`
requires a pre-enriched DataFrame (with `owner` column) passed as `enriched_assets`. If the
caller passes the raw `assets_df` without first calling `extract_owner`, the uuid-to-owner map
will be empty and all findings will fall through to `Unassigned`. Confirm the
`scripts/capture_trend_snapshot.py` enrichment step is present and running without error.

**Cause 3 — tags column absent:** `fetch_all_assets()` returned a DataFrame without a `tags`
column. Check the parquet cache (`assets_all.parquet`) for the `tags` column. If the column is
missing, the API export may have changed shape or the normalisation step in `data/fetchers.py`
may need updating.

### Trend file renamed to `*.corrupt`

If `data/trend/trend_<dim>_<tag>.json` becomes unparseable (e.g. partial write, disk error
during a prior run), `_load_trend_json` renames it to `*.corrupt` before returning `[]`. This
preserves the original file for manual inspection. To recover:

1. Inspect the `.corrupt` file to determine how much history is intact.
2. If the JSON is partially valid, fix it manually (must be `{"snapshots": [...]}`).
3. Rename it back to the original `.json` filename.
4. If the file is unrecoverable, delete it and accept the cold-start loss.

The next `capture_snapshot` call will create a fresh file.

### `ValueError: capture_snapshot: enriched_assets is required for dimension='owner'`

The caller invoked `capture_snapshot` with `dimension="owner"` but omitted the
`enriched_assets` parameter (or passed `None` explicitly). Pre-enrich `assets_df` via
`extract_owner` and pass the result as `enriched_assets`. See Section 7 for the correct call
pattern.
