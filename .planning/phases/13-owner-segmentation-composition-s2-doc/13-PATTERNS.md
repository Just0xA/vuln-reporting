# Phase 13: Owner Segmentation + Composition (S2 + Doc) - Pattern Map

**Mapped:** 2026-06-10
**Files analyzed:** 8 (5 modified, 1 extended, 1 new writer, 1 new doc)
**Analogs found:** 8 / 8

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `reports/modules/board_report_utils.py` | utility (shared helper) | transform | itself — generalize in place | self |
| `reports/modules/aged_vulns_assets_module.py` | module (consumer) | CRUD | itself — repoint column references | self |
| `reports/modules/critical_remediation_sla_module.py` | module (consumer) | CRUD | itself — repoint + remove `_extract_owner_tag` | self |
| `reports/modules/high_risk_assets_module.py` | module (consumer) | CRUD | `aged_vulns_assets_module.py` — identical pattern | exact |
| `reports/modules/scan_coverage_sla_module.py` | module (consumer) | CRUD | `aged_vulns_assets_module.py` — same import/column pattern | exact |
| `data/trend_store.py` | service (snapshot engine) | batch | itself — add `_count_by_owner` dispatch | self |
| `reports/modules/board_report_utils.py` (supplemental writer) | utility (Excel writer) | file-I/O | `reports/unscanned_assets.py` `_write_data_tab` / `_write_csv` | exact |
| `docs/trend_and_segmentation_calculations.md` | doc (runbook) | — | `docs/management_summary_calculations.md` | exact |
| `tests/unit/test_owner_segmentation.py` | test | — | `tests/content/test_trend_store.py` fixture pattern | role-match |
| `tests/content/test_trend_store.py` (extend) | test | — | itself — add owner-dimension cases | self |

---

## Pattern Assignments

### `reports/modules/board_report_utils.py` — generalize BU helper to Owner-primary (SEG-01/02/04/05)

**Analog:** itself — the current `extract_business_unit` / `compute_per_bu_breakdown` / `compute_bu_risk_scores` block is the template; generalize it in place.

**Current module-level constants** (lines 47–48):
```python
#: Tenable tag category that identifies the business unit.
BU_TAG_CATEGORY: str = "Application"
```
Change to:
```python
OWNER_TAG_CATEGORY: str = "Owner"           # primary grouping dimension (D-01)
APPLICATION_TAG_CATEGORY: str = "Application"  # nested analyst drill-down (D-05)
_DEFAULT_UNASSIGNED_LABEL: str = "Unassigned"  # D-06; replaces "Untagged" everywhere
```

**Current `extract_business_unit` signature + body** (lines 206–280):
```python
def extract_business_unit(
    assets_df:       pd.DataFrame,
    tag_column_name: str = "tags",
) -> pd.DataFrame:
    df = assets_df.copy()

    def _bu_from_tags(tags_val) -> str:
        if not isinstance(tags_val, str) or not tags_val.strip():
            return "Untagged"
        tokens = [t.strip() for t in tags_val.split(";") if t.strip()]
        app_values: list[str] = []
        for token in tokens:
            if "=" not in token:
                continue
            cat, _, val = token.partition("=")
            if cat.strip().casefold() == BU_TAG_CATEGORY.casefold() and val.strip():
                app_values.append(val.strip())
        if not app_values:
            return "Untagged"
        if len(app_values) == 1:
            return app_values[0]
        return "; ".join(sorted(set(app_values)))

    if tag_column_name in df.columns:
        df.loc[:, "business_unit"] = df[tag_column_name].apply(_bu_from_tags)
    else:
        logger.warning(
            "extract_business_unit: column %r not present in DataFrame — "
            "all assets will be labelled 'Untagged'.",
            tag_column_name,
        )
        df.loc[:, "business_unit"] = "Untagged"
    return df
```
Rename to `extract_owner`; inner closure must extract BOTH `owner` (primary) AND `application` (nested, D-05); return `unassigned_label` (default `"Unassigned"`) instead of `"Untagged"`; set `df.loc[:, "owner"]` and `df.loc[:, "application"]` columns.

**Private tag parser to promote** — `_extract_owner_tag` from `critical_remediation_sla_module.py` lines 976–991:
```python
def _extract_owner_tag(tags_str: Any) -> str:
    """Parse the Owner tag value from a Tenable-style tags string."""
    if not isinstance(tags_str, str) or not tags_str.strip():
        return ""
    for piece in tags_str.split(";"):
        if "=" not in piece:
            continue
        cat, _, val = piece.partition("=")
        if cat.strip().lower() == "owner":
            return val.strip()
    return ""
```
This returns `""` on no-match. When promoted into `board_report_utils.py`, it must return `unassigned_label` instead — that is the only behavioral change needed. The dual-category loop (Owner + Application) replaces the single-category version.

**Critical rename in `compute_per_bu_breakdown`** (line 370):
```python
# CURRENT — always renames to "business_unit" regardless of bu_column param:
.rename(columns={bu_column: "business_unit"})

# AFTER D-04 — must rename to "owner":
.rename(columns={bu_column: "owner"})
```
This is the load-bearing rename: all four consumer modules read the output column by name, and ALL of those reads must change from `"business_unit"` to `"owner"` in lockstep.

**`compute_bu_risk_scores` column references** (lines 429–479):
```python
# CURRENT — enriched parameter docstring and groupby both reference "business_unit":
enriched : pd.DataFrame
    On-time assets with a ``business_unit`` column (from extract_business_unit).
...
bu_map = (
    enriched.loc[
        enriched["asset_uuid"].isin(qualifying_uuids),
        ["asset_uuid", "business_unit"],      # ← line 460
    ]
    .drop_duplicates("asset_uuid")
)
...
return bu_asset.groupby("business_unit")["risk_score"].sum()  # ← line 479
```
Change every `"business_unit"` reference here to `"owner"`.

**Module-level docstring** (lines 26–30) — update all listed function names and the `"business_unit"` / `"Application"` references.

---

### `reports/modules/aged_vulns_assets_module.py` — repoint consumer (D-04/D-06/D-08)

**Analog:** itself — the current compute() and render methods define the exact locations.

**Import block** (around line 55 — copy pattern from current file, change symbol names):
```python
from reports.modules.board_report_utils import (
    compute_bu_risk_scores,
    compute_per_bu_breakdown,
    extract_business_unit,          # ← rename to extract_owner
    identify_on_time_assets,
    sla_status_from_thresholds,
    ON_TIME_WINDOW_DAYS,
)
```

**compute() — per-BU breakdown block** (lines 241–274):
```python
# CURRENT:
enriched       = extract_business_unit(on_time)
numerator_mask = enriched["asset_uuid"].isin(aged_uuids)
denom_mask     = pd.Series(True, index=enriched.index)
bu_breakdown = compute_per_bu_breakdown(enriched, numerator_mask, denom_mask, ...)
bu_breakdown = bu_breakdown.merge(
    bu_risk.rename("risk_score").reset_index(),
    on="business_unit",             # ← merge key
    ...
)
bu_breakdown.sort_values("risk_score", ...)
table_data = bu_breakdown.to_dict("records")

# AFTER D-04:
enriched       = extract_owner(on_time)
...
on="owner",                         # ← merge key
```

**Secondary fillna catch-all** (lines 389–394 per RESEARCH.md §Pitfall 1):
```python
# CURRENT — groupby + fillna in consumer:
bu_counts["business_unit"].fillna("Untagged").replace("", "Untagged")

# AFTER D-06:
owner_counts["owner"].fillna("Unassigned").replace("", "Unassigned")
```

**render_email_panel / render_pdf_section row access** (lines 580, 728):
```python
# CURRENT:
bu_name = str(row.get("business_unit", ""))

# AFTER D-04:
bu_name = str(row.get("owner", ""))
```

**PDF/Excel heading strings** — grep for `"Business Unit"` (display string, not column name) in both HTML f-strings and openpyxl `ws.cell(value=...)` calls; change to `"Owner"` (D-02).

---

### `reports/modules/critical_remediation_sla_module.py` — repoint + remove `_extract_owner_tag` (D-04/D-06/D-08)

**Analog:** itself. All `business_unit` column references and the private `_extract_owner_tag` function are the change targets.

**Import block** (lines 53–59):
```python
from reports.modules.board_report_utils import (
    compute_per_bu_breakdown,
    extract_business_unit,          # ← rename to extract_owner
    identify_on_time_assets,
    sla_status_from_thresholds,
    ON_TIME_WINDOW_DAYS,
)
```

**`_compute_bu_breakdown` helper** (lines 1046–1091) — the densest change site:
```python
# CURRENT (lines 1059–1073):
if fixed_in_window.empty:
    return pd.DataFrame(
        columns=["business_unit", "numerator", "denominator", "percentage", "affected"]
    )

enriched_assets = extract_business_unit(on_time_assets)
uuid_to_bu      = dict(
    zip(enriched_assets["asset_uuid"], enriched_assets["business_unit"])
)

fw = fixed_in_window.copy()
fw.loc[:, "business_unit"] = (
    fw["asset_uuid"].map(uuid_to_bu).fillna("Untagged")
)

# AFTER D-04/D-06:
if fixed_in_window.empty:
    return pd.DataFrame(
        columns=["owner", "numerator", "denominator", "percentage", "affected"]
    )

enriched_assets = extract_owner(on_time_assets)
uuid_to_owner   = dict(
    zip(enriched_assets["asset_uuid"], enriched_assets["owner"])
)

fw = fixed_in_window.copy()
fw.loc[:, "owner"] = (
    fw["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
)
```

**Row access in render methods** (lines 588, 740):
```python
# CURRENT:
row.get("business_unit", "")
# AFTER:
row.get("owner", "")
```

**Remove `_extract_owner_tag`** (lines 976–991) entirely — replaced by `extract_owner` in the shared helper. Verify no other callers before deleting.

---

### `reports/modules/high_risk_assets_module.py` — repoint consumer (D-04/D-06/D-08)

**Analog:** `aged_vulns_assets_module.py` — RESEARCH.md §Consumer Module Reference Map confirms the pattern is identical at equivalent line numbers (§246, §265, §336-337, §348, §363, §373, §392–402, §584, §732).

Apply the exact same changes as `aged_vulns_assets_module.py`:
- `extract_business_unit` → `extract_owner` in import and call sites
- `"business_unit"` column name → `"owner"` everywhere (merge keys, row access, groupby, fillna)
- `"Untagged"` → `"Unassigned"` in all fillna/replace calls
- `"Business Unit"` display heading → `"Owner"` in HTML and openpyxl headers

---

### `reports/modules/scan_coverage_sla_module.py` — repoint consumer (D-04/D-06/D-08)

**Analog:** `aged_vulns_assets_module.py` for the compute/column-rename pattern; itself for the render heading locations.

**compute() block** (lines 315, 362–363, 381, 394, 414–433 per RESEARCH.md):
Same column rename pattern as aged_vulns — `extract_business_unit` → `extract_owner`, `"business_unit"` → `"owner"`.

**render_email_panel HTML table header** (line 648):
```python
# CURRENT:
<th>Business Unit</th>

# AFTER D-02:
<th>Owner</th>
```
Also line 675 explanatory paragraph: `"Application" tag category` → `"Owner" tag category`; `"Untagged"` → `"Unassigned"`.

**render_excel_tabs openpyxl header** (lines 762–777):
```python
# CURRENT (line 762):
headers = ["Business Unit", "Scanned On Time", "Licensed Assets", "Coverage %"]
...
value=str(row.get("business_unit", ""))   # line 777

# AFTER D-02/D-04:
headers = ["Owner", "Scanned On Time", "Licensed Assets", "Coverage %"]
...
value=str(row.get("owner", ""))
```

**Module docstring** (lines 19, 988 per RESEARCH.md §Pitfall 7): update `"Application"` tag references → `"Owner"`.

---

### `data/trend_store.py` — add `_count_by_owner` dispatch (SEG-05)

**Analog:** itself — `_count_by_severity` (lines 171–185) is the direct pattern template.

**Current `_count_by_severity`** (lines 171–185):
```python
def _count_by_severity(open_df: pd.DataFrame) -> dict[str, int]:
    """
    Return a dict of {critical, high, medium, low} open-finding counts.

    Uses .to_dict() BEFORE .get() to avoid calling .get() on a pandas Series
    (groupby returns a Series, not a dict — Pitfall 3).  Guarded against an
    empty DataFrame so groupby is never called on zero rows.
    """
    counts = open_df.groupby("severity").size().to_dict() if not open_df.empty else {}
    return {
        "critical": int(counts.get("critical", 0)),
        "high":     int(counts.get("high", 0)),
        "medium":   int(counts.get("medium", 0)),
        "low":      int(counts.get("low", 0)),
    }
```

New `_count_by_owner` follows the same defensive guard pattern but joins `open_df` to enriched assets via `asset_uuid`:
```python
def _count_by_owner(
    open_df: pd.DataFrame,
    enriched_assets: pd.DataFrame,
) -> dict[str, int]:
    """
    Return {owner_name: open_finding_count} for the open findings set.

    Joins open_df to enriched_assets on asset_uuid to derive owner labels.
    Findings for assets absent from enriched_assets count under "Unassigned".
    """
    if open_df.empty:
        return {}
    uuid_to_owner = (
        dict(zip(enriched_assets["asset_uuid"], enriched_assets["owner"]))
        if not enriched_assets.empty and "owner" in enriched_assets.columns
        else {}
    )
    owner_col = open_df["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
    counts = owner_col.value_counts().to_dict()
    return {str(k): int(v) for k, v in counts.items()}
```

**`capture_snapshot` dispatch** (lines 244–266) — current code calls `_count_by_severity(open_df)` unconditionally and builds the `new_entry` dict with fixed severity keys. After the extension:

```python
# CURRENT (lines 244–266):
open_df    = open_findings_at(df, date)
sev_counts = _count_by_severity(open_df)
asset_count = int(len(assets_df))
...
new_entry: dict = {
    "month":        month_str,
    "tag_filter":   tag_filter,
    "critical":     sev_counts["critical"],
    "high":         sev_counts["high"],
    "medium":       sev_counts["medium"],
    "low":          sev_counts["low"],
    "asset_count":  asset_count,
    "generated_at": generated_at_str,
}
```

After extension — `capture_snapshot` must accept an `enriched_assets` param (optional, None for severity dimension; caller pre-enriches for owner dimension per RESEARCH.md A1 / Pitfall 5):
```python
# New signature addition:
def capture_snapshot(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    date: datetime,
    dimension: str = "severity",
    tag_filter: str = "all_assets",
    trend_dir: Optional[Path] = None,
    enriched_assets: Optional[pd.DataFrame] = None,   # NEW — required when dimension="owner"
) -> Path:

# Dispatch:
if dimension == "severity":
    counts = _count_by_severity(open_df)
    count_entry = {
        "critical": counts["critical"],
        "high":     counts["high"],
        "medium":   counts["medium"],
        "low":      counts["low"],
    }
elif dimension == "owner":
    if enriched_assets is None:
        raise ValueError("capture_snapshot: enriched_assets is required for dimension='owner'")
    counts = _count_by_owner(open_df, enriched_assets)
    count_entry = counts   # arbitrary owner keys
else:
    raise ValueError(f"capture_snapshot: unknown dimension {dimension!r}")

new_entry: dict = {
    "month":        month_str,
    "tag_filter":   tag_filter,
    **count_entry,
    "asset_count":  asset_count,
    "generated_at": generated_at_str,
}
```

**`read_trend` requires no changes** (lines 291–346) — the `tag_filter` string match at line 333 works for any dimension string. Caller must pass identical `tag_filter` value used during `capture_snapshot`.

**`_atomic_write_json`** (lines 154–168) — use as-is for the owner JSON file; handles Windows fd-close-before-replace.

**`_sanitise_tag_for_filename`** (lines 73–~110) — use as-is; `"all_assets"` suffix for an unscoped owner snapshot.

---

### Combined supplemental Excel writer (new function in `board_report_utils.py`, SEG-03)

**Analog:** `reports/unscanned_assets.py` `_write_data_tab` (lines 518–563) and `_write_csv` (lines 570–603).

**Fill constants to copy** (lines 74–79):
```python
_FILL_HEADER = PatternFill("solid", fgColor="1F3864")   # dark navy
_FILL_ALT    = PatternFill("solid", fgColor="F5F5F5")   # zebra stripe
```
These constants already exist in `scan_coverage_sla_module.py` and other module files under the same names — confirm the target file's existing `_FILL_HEADER`/`_FILL_ALT` before adding.

**`_write_data_tab` core pattern** (lines 518–563):
```python
def _write_data_tab(
    wb:       openpyxl.Workbook,
    tab_name: str,
    df:       pd.DataFrame,
    col_spec: list[tuple[str, str]],   # (Header label, DataFrame column name)
) -> None:
    ws = wb.create_sheet(tab_name)

    if df.empty:
        ws["A1"] = f"No assets in this category for this run."
        ws["A1"].font = Font(italic=True, color="888888")
        return

    # Header row
    for col_idx, (header, _) in enumerate(col_spec, start=1):
        cell           = ws.cell(row=1, column=col_idx, value=header)
        cell.font      = Font(bold=True, color="FFFFFF")
        cell.fill      = _FILL_HEADER
        cell.alignment = Alignment(horizontal="center", wrap_text=False)

    # Data rows — zebra stripe
    for row_idx in range(len(df)):
        row_series = df.iloc[row_idx]
        alt = (row_idx % 2 == 1)
        for col_idx, (header, field) in enumerate(col_spec, start=1):
            raw = row_series.get(field) if field in df.columns else None
            val = _safe_cell_value(raw, field)   # handles pd.NA/NaT/None
            cell           = ws.cell(row=row_idx + 2, column=col_idx, value=val)
            cell.alignment = Alignment(horizontal="left")
            if alt:
                cell.fill = _FILL_ALT

    ws.freeze_panes = "A2"
```

**`_safe_cell_value` pattern** (lines 404–424) — copy into `board_report_utils.py` supplemental writer or call from `unscanned_assets` if it becomes a shared utility:
```python
def _safe_cell_value(val: object, field: str) -> object:
    if field in _DATE_FIELDS:
        return _fmt_date(val)
    if isinstance(val, (list, tuple)):
        return ", ".join(str(v) for v in val if v)
    try:
        if pd.isna(val):
            return ""
    except (TypeError, ValueError):
        pass
    if val is None:
        return ""
    return val
```

**`_write_csv` pattern** (lines 570–603):
```python
def _write_csv(csv_file, overdue_df, unlicensed_df) -> None:
    fieldnames = ["Category", "hostname", "ipv4", ...]
    with csv_file.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames,
                                extrasaction="ignore",
                                quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for _, row in overdue_df.iterrows():
            writer.writerow({"Category": "Overdue Licensed", **row.to_dict()})
```
For the combined supplemental, the flat CSV has no "Category" split — one writer loop over the single `owner_app_df`. Use `utf-8-sig` encoding (Excel-friendly BOM) and `QUOTE_ALL`.

**Column spec for combined supplemental** (D-09 / RESEARCH.md open question 3 — minimal v1):
```python
_SUPPLEMENTAL_COLS: list[tuple[str, str]] = [
    ("Owner",         "owner"),
    ("Application",   "application"),
    ("Open Findings", "open_count"),
    ("Asset Count",   "asset_count"),
]
```
`Unassigned` Owner rows double as the "needs Owner assignment" worklist. No SLA-computation columns in v1 (avoids re-implementing module logic).

**Output location:** `output/<run_folder>/owner_segmentation.xlsx` and `owner_segmentation.csv` — written by `board_summary.run_report()` after the four modules compute; returned in the run dict under `"supplemental_excel"` and `"supplemental_csv"` keys (parallel to how `unscanned_assets` returns `"excel"` and `"csv"`).

---

### `docs/trend_and_segmentation_calculations.md` — new DOC-01 runbook

**Analog:** `docs/management_summary_calculations.md` — copy the exact document structure.

**management_summary_calculations.md structure** (lines 1–29):
```markdown
# [Title] — Calculations Runbook

**File:** `<primary source file>`
**Audience:** <audience>
**Outputs:** <output types>
**Schedule:** <schedule>

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [How to Activate Scheduled Delivery](#...)
3. [CLI Reference](#...)
4. [Data Sources](#...)
5. [SLA Definitions](#...)
6–N. [Metric N — <name>](#...)
N+1. [Gauge Color Zones](#...)
N+2. [PDF Structure](#...)
N+3. [Output Files](#...)
N+4. [Trend Data Store](#...)
N+5. [Troubleshooting](#...)

---

## 1. Quick Start
```

DOC-01 required sections (from RESEARCH.md SEG requirements + CONTEXT.md D-10/D-11):
1. Quick Start — how to capture an owner snapshot, read it back
2. Open Predicate — the reopened-aware two-interval predicate (`utils/open_count.py` `open_findings_at`)
3. ~29-Day Retention — why snapshots, not reconstruction; forward-accumulation model
4. Owner/Unassigned Model — `Owner` tag = Application Support (patching-responsible); `Unassigned` catch-all; reconcile-to-whole guarantee
5. Combined Supplemental — what it contains, PII rule (AI/repo ban, NOT email ban), delivery path
6. Trend Composition — `dimension="owner"` file location, `tag_filter` consistency requirement, `read_trend` return shape
7. Troubleshooting — `insufficient_data=True` causes, `tag_filter` mismatch, all-Unassigned diagnosis

---

### `tests/unit/test_owner_segmentation.py` — new unit tests (SEG-01/02/04)

**Analog:** `tests/content/test_trend_store.py` — fixture helper pattern (hand-built DataFrames with known counts).

**Fixture pattern** (lines 40–60):
```python
def _assets_df(rows: list[dict]) -> pd.DataFrame:
    """Hand-built assets DataFrame with known tag strings."""
    return pd.DataFrame(rows)

# Example fixture:
_ASSETS = [
    {"asset_uuid": "a1", "tags": "Owner=Network Defense;Application=Finance"},
    {"asset_uuid": "a2", "tags": "Owner=Platform Eng;Application=HR"},
    {"asset_uuid": "a3", "tags": "Application=Finance"},          # no Owner → Unassigned
    {"asset_uuid": "a4", "tags": ""},                             # empty → Unassigned
    {"asset_uuid": "a5", "tags": None},                           # null → Unassigned
]
```

**Test assertions required** (RESEARCH.md Validation Architecture):
- `extract_owner(df)["owner"].value_counts()` sums to `len(df)` — reconcile-to-whole (SEG-01/02)
- assets with no Owner tag land in `"Unassigned"` bucket, not `"Untagged"` (SEG-02, D-06)
- `extract_owner(df)["application"]` populated from Application tag (D-05)
- `extract_owner` on DataFrame with missing `tags` column → all `"Unassigned"`, no raise (SEG-04)
- Output has `"owner"` column, NOT `"business_unit"` column (D-04, Pitfall 2)
- `compute_per_bu_breakdown` output has `"owner"` column, NOT `"business_unit"` column (D-04)

---

### `tests/content/test_trend_store.py` — extend with owner dimension (SEG-05)

**Analog:** itself — the existing `capture_snapshot` / `read_trend` test structure (lines 1–60+).

**New test cases to add** (RESEARCH.md SEG-05):
- `capture_snapshot(df, assets_df, date, dimension="owner", enriched_assets=enriched)` writes `trend_owner_all_assets.json`
- `read_trend("owner", "all_assets")` returns `{"snapshots": [...], "insufficient_data": ...}` with owner keys (not `critical`/`high`/etc.)
- `capture_snapshot` with `dimension="owner"` and `enriched_assets=None` raises `ValueError`
- Snapshot payload contains no PII fields (extend existing `_PII_FIELDS` check — TREND-06)
- `tag_filter` stored in JSON matches what is passed to `read_trend` (Pitfall 6)

---

## Shared Patterns

### Catch-all label — TWO sites, both must change

**Source:** `reports/modules/board_report_utils.py` lines 262–278 (primary) + consumer module groupby guards (secondary)

**Apply to:** All five blast-radius files

**Primary site** (inside `_bu_from_tags` closure / new `_parse_tags`):
```python
# Return on no-match — change from "Untagged" to configurable label (default "Unassigned")
if not app_values:
    return "Untagged"   # ← PRIMARY SITE; becomes: return unassigned_label
```

**Secondary site** (consumer module groupby guard — aged_vulns §393, high_risk §396, critical_remediation §1072):
```python
# Belt-and-suspenders fillna after groupby (NaN for genuinely-null group keys)
bu_counts["business_unit"].fillna("Untagged").replace("", "Untagged")
# ↓
owner_counts["owner"].fillna("Unassigned").replace("", "Unassigned")
```

**Verification gate:** After all changes, `grep -r "Untagged" reports/modules/` must return zero results across all five blast-radius files.

### Display heading rename

**Source:** `reports/modules/scan_coverage_sla_module.py` lines 648, 762 (representative of all four modules)

**Apply to:** All four consumer modules — both HTML render strings and openpyxl `ws.cell(value=...)` calls

```python
# HTML (all four render_email_panel / render_pdf_section methods):
"<th>Business Unit</th>"   →   "<th>Owner</th>"
"Top 5 Worst-Performing Business Units"   →   "Top 5 Worst-Performing Owners"

# openpyxl (all four render_excel_tabs methods):
headers = ["Business Unit", ...]   →   headers = ["Owner", ...]
row.get("business_unit", "")       →   row.get("owner", "")
```

**Verification gate:** `grep -rn "Business Unit" reports/modules/` must return zero results after all four modules are repointed.

### openpyxl fill constants

**Source:** `reports/unscanned_assets.py` lines 74–79

**Apply to:** Combined supplemental writer in `board_report_utils.py`

```python
_FILL_HEADER = PatternFill("solid", fgColor="1F3864")   # dark navy
_FILL_ALT    = PatternFill("solid", fgColor="F5F5F5")   # zebra stripe
```
Note: `scan_coverage_sla_module.py` and other module files already define identically-named constants locally — confirm the supplemental writer's file context before adding.

### Atomic JSON write

**Source:** `data/trend_store.py` `_atomic_write_json` (lines 154–168)

**Apply to:** `capture_snapshot` for `dimension="owner"` — no change needed, the same `_atomic_write_json` call at line 283 covers both dimensions once the `new_entry` dict is built.

### Empty-data guard

**Source:** `CLAUDE.md` + `reports/modules/format_utils.py` `safe_pct` / `safe_int` / `safe_format`

**Apply to:** Any new render paths in `board_report_utils.py` supplemental writer and `_count_by_owner`.

```python
# _count_by_owner already guards:
if open_df.empty:
    return {}

# Supplemental writer must guard:
if owner_app_df.empty:
    ws["A1"] = "No data for this run."
    return
```

### F-DTYPE / `.assign()` pattern

**Source:** `reports/modules/aged_vulns_assets_module.py` lines 268–270; `board_report_utils.py` lines 475–477

**Apply to:** Any DataFrame column assignment after a merge in the repointed modules.

```python
# Pattern: use .assign() instead of .loc[:, col]= after merge to avoid
# pandas 3.0 ChainedAssignmentError FutureWarning and float64 dtype drift
bu_breakdown = bu_breakdown.assign(
    risk_score=bu_breakdown["risk_score"].fillna(0).astype(int),
)
```

---

## No Analog Found

All files in this phase have strong analogs. No novel patterns are required.

| File | Note |
|------|------|
| `docs/trend_and_segmentation_calculations.md` | New doc; `docs/management_summary_calculations.md` is a complete structural template |
| `tests/unit/test_owner_segmentation.py` | New test file; `tests/content/test_trend_store.py` fixture pattern applies directly |

---

## Metadata

**Analog search scope:** `reports/modules/`, `data/`, `reports/`, `tests/content/`, `docs/`
**Files read:** `board_report_utils.py`, `trend_store.py`, `critical_remediation_sla_module.py`, `scan_coverage_sla_module.py`, `aged_vulns_assets_module.py` (partial), `unscanned_assets.py`, `management_summary_calculations.md`, `test_trend_store.py`
**Pattern extraction date:** 2026-06-10
