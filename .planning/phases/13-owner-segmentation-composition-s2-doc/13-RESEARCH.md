# Phase 13: Owner Segmentation + Composition (S2 + Doc) - Research

**Researched:** 2026-06-10
**Domain:** Python DataFrame segmentation, tag parsing, snapshot composition, technical runbook authoring
**Confidence:** HIGH — this is concrete rewiring of already-read code; all findings are from direct file inspection

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** `Owner` is the active stakeholder dimension (= Application Support group). Business Unit and Technical Support are future/reference — design generally but do not build them now.
- **D-02:** Report-facing heading reads `"Owner"` everywhere across PDF tables and Excel tabs.
- **D-03:** Generalize the existing shared helper in place — `board_report_utils.py` becomes Owner-primary and tag-category-parameterized. Do NOT build a parallel helper.
- **D-04:** Rename grouping column `business_unit` → `owner` in the helper and all consumers.
- **D-05:** Keep `Application` as a separate parsed column for nested analyst drill-down; helper must extract both `owner` (primary) and `application` (nested).
- **D-06:** `Unassigned` is the catch-all label (configurable). Standardize away from the existing `"Untagged"` fillna pattern.
- **D-07:** Fail-soft when `Owner` is absent/partial → everything `Unassigned`, no crash; empty-data guard per CLAUDE.md.
- **D-08:** Blast radius confirmed — repoint these five files and ONLY these five: `board_report_utils.py`, `aged_vulns_assets_module.py`, `critical_remediation_sla_module.py`, `high_risk_assets_module.py`, `scan_coverage_sla_module.py`.
- **D-09:** One combined supplemental Excel, single flat tab: `Owner | Application | <counts>`. Unassigned rows double as "needs Owner assignment" worklist. Follow `unscanned_assets.py` analyst-Excel precedent.
- **D-10:** PII discipline = no AI/repo transmission, NOT a ban on internal email. Combined supplemental may be emailed internally. DOC-01 must document the real rationale.
- **D-11:** Trend store stays aggregate-only (TREND-06 unchanged). D-10 applies to the analyst supplemental only, not persisted `data/trend/` payloads.
- **D-12:** `capture_snapshot(dimension="owner", ...)` writes `trend_owner_<tagsuffix>.json` with per-Owner open counts. `read_trend("owner", ...)` returns the month-over-month series. No signature change to existing Phase 12 API.

### Claude's Discretion

- Exact generalized function/parameter names and signatures in `board_report_utils.py` (beyond Owner-primary + parameterized shape and `owner` column rename).
- Exact filenames/paths for the combined supplemental and where in the run output it lands (within D-10's not-committed / not-AI constraint).
- Precise `trend_owner_*.json` count-key encoding and tag-suffix convention (follow Phase-12 `trend_<dimension>_<tagsuffix>.json` precedent).
- Whether the configurable `Owner` category name and `Unassigned` label are module constants vs config-driven (follow existing `BU_TAG_CATEGORY` precedent).

### Deferred Ideas (OUT OF SCOPE)

- `management_summary` and `composed_report` Owner wiring (GEN-01).
- Building the real Business Unit and Technical Support tags/dimensions.
- Performance-metric responsibility mapping to Owner + Business Unit.
- Per-Owner severity breakdown in trend (D-12 captures per-Owner counts only).
- All v1.4 report modules.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SEG-01 | Reusable helper groups findings/assets by `Owner` tag category, returning per-Owner buckets | Generalize `extract_business_unit` + `aggregate_by_business_unit` in `board_report_utils.py` — see §Standard Stack and §Architecture Patterns |
| SEG-02 | Assets without an `Owner` tag fall into a single `Unassigned` catch-all (label configurable) so per-Owner totals always reconcile | Replace existing `fillna("Untagged").replace("", "Untagged")` pattern with `fillna(unassigned_label).replace("", unassigned_label)` — see §Catch-all Pattern |
| SEG-03 | Analyst exception list of `Unassigned` assets as operator-facing local output (Excel/CSV) — not committed, not AI-transmitted; internal email permitted (D-10) | Follow `unscanned_assets.py` `_write_summary_tab` / `_write_data_tab` / `_write_csv` pattern — see §Supplemental Excel Precedent |
| SEG-04 | Fail-soft when `Owner` is absent/partial — everything `Unassigned`, no crash; empty-data guard per CLAUDE.md | Existing `extract_business_unit` missing-column guard is the pattern; `safe_pct`/`safe_int`/`safe_format` for all render paths |
| SEG-05 | Owner segmentation composes with trend primitive — per-Owner open counts can be snapshotted and trended | `capture_snapshot(df, assets_df, date, dimension="owner", tag_filter=<owner_tagsuffix>)` — no signature change; new count aggregation logic needed; see §Trend Composition |
| DOC-01 | `docs/trend_and_segmentation_calculations.md` — auditor runbook covering open predicate, ~29-day retention/forward-accumulation, Owner/Unassigned model | All content already implemented and documented in code; style from `docs/management_summary_calculations.md` |

</phase_requirements>

---

## Summary

Phase 13 is entirely concrete code rewiring with a confirmed blast radius of five files plus one new document. There is no speculative architecture — the Phase 12 substrate (`data/trend_store.py`) is already `dimension`+`tag_filter` parameterized and requires no signature changes. The segmentation helper (`board_report_utils.py`) already implements the exact group-by-tag + fillna catch-all pattern against the `Application` tag; this phase generalizes it to be Owner-primary. The four consumer modules each import `extract_business_unit` and reference the `business_unit` column name in well-understood, consistent patterns.

The key implementation specifics surfaced by reading the actual code: (1) there are two distinct catch-all patterns in the codebase — the helper returns `"Untagged"` on no-match, and the consumer modules additionally apply `.fillna("Untagged").replace("", "Untagged")` after groupby — both must change to `"Unassigned"` (D-06); (2) `critical_remediation_sla_module.py` has a private `_extract_owner_tag` at line 976 that already parses the `Owner` tag from the semicolon-delimited string — this logic must be promoted into the shared helper rather than duplicated; (3) `compute_per_bu_breakdown` already accepts a `bu_column` parameter (default `"business_unit"`) and renames it to `"business_unit"` in its output — this rename-to-fixed-name must change to rename to `"owner"` after D-04; (4) the trend composition for `dimension="owner"` needs a new `_count_by_owner` aggregation function alongside the existing `_count_by_severity` in `trend_store.py`.

**Primary recommendation:** Sequence as three plans — (1) generalize `board_report_utils.py` + repoint consumers, (2) combined supplemental Excel + trend composition, (3) DOC-01 runbook. The helper generalization is the load-bearing change that unblocks everything else.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Owner tag extraction from asset `tags` string | Shared helper (`board_report_utils.py`) | — | Single source of truth; currently split between helper (`Application`) and private function in `critical_remediation_sla_module.py` (`Owner`) — D-03 consolidates both here |
| `owner` column population on DataFrames | Shared helper → consumed by 4 modules | — | Extract-once pattern; modules call the helper, never re-parse tags themselves |
| `Unassigned` catch-all | Shared helper (primary) + consumer modules (secondary fillna guard) | — | Helper sets the label on extraction; modules' groupby fillna guards serve as defensive belt-and-suspenders |
| Combined analyst supplemental (Excel/CSV) | `board_summary.py` run path / new supplemental writer function | — | Follows `unscanned_assets.py` pattern; written to run output directory, not transmitted to AI or committed |
| Per-Owner trend snapshots | `data/trend_store.py` `capture_snapshot(dimension="owner")` | `scripts/capture_trend_snapshot.py` entry point | Phase 12 substrate already accepts `dimension` param; new aggregation logic added without signature change |
| DOC-01 runbook | `docs/trend_and_segmentation_calculations.md` (new file) | — | Auditor-facing; documents what is already implemented |

---

## Standard Stack

No new packages. This phase uses only the existing project stack. [VERIFIED: direct code inspection]

| Library | Current Use | Phase 13 Role |
|---------|-------------|---------------|
| `pandas` | All DataFrame operations | `groupby`, `fillna`, `merge` for Owner segmentation |
| `openpyxl` | Excel generation | Combined supplemental workbook (follow `unscanned_assets.py` pattern) |
| `data/trend_store.py` | `capture_snapshot` / `read_trend` | Called with `dimension="owner"` — no changes to public API |
| `utils/open_count.py` | `open_findings_at` | Used inside `capture_snapshot` — unchanged |

**Installation:** None required.

---

## Package Legitimacy Audit

> Not applicable — this phase installs no external packages.

---

## Architecture Patterns

### System Architecture Diagram

```
assets_df (tags column: "Application=X;Owner=Y;...")
    │
    ▼
extract_owner(assets_df)                          ← board_report_utils.py (generalized)
    │  adds columns: owner (primary), application (nested)
    │  missing Owner → "Unassigned"
    ▼
enriched_assets_df
    ├──► compute_per_owner_breakdown(...)          ← board_report_utils.py (renamed)
    │        groupby "owner" → numerator/denominator/pct table
    │        consumed by: aged_vulns, high_risk, scan_coverage, critical_remediation
    │
    ├──► combined_supplemental_writer(...)         ← new helper (D-09)
    │        flat tab: Owner | Application | counts
    │        written to run output dir (not committed, not AI-transmitted)
    │
    └──► capture_snapshot(df, assets_df,           ← data/trend_store.py (unchanged API)
             dimension="owner",
             tag_filter="all_assets")
              │  _count_by_owner(open_df, enriched) → {owner_name: int, ...}
              ▼
         data/trend/trend_owner_all_assets.json
              │
              ▼
         read_trend("owner", "all_assets", months=6)
              → {"snapshots": [...], "insufficient_data": bool}
```

### Recommended File Changes

```
reports/modules/
├── board_report_utils.py      ← GENERALIZE (BU_TAG_CATEGORY → OWNER_TAG_CATEGORY,
│                                 extract_business_unit → extract_owner,
│                                 business_unit col → owner col,
│                                 compute_per_bu_breakdown: output col owner,
│                                 compute_bu_risk_scores: owner col,
│                                 add Application extraction for D-05)
├── aged_vulns_assets_module.py        ← REPOINT (business_unit → owner, import renames)
├── critical_remediation_sla_module.py ← REPOINT + REMOVE _extract_owner_tag
├── high_risk_assets_module.py         ← REPOINT (business_unit → owner)
└── scan_coverage_sla_module.py        ← REPOINT (business_unit → owner)

data/
└── trend_store.py             ← ADD _count_by_owner() aggregation; extend
                                   capture_snapshot to dispatch on dimension

docs/
└── trend_and_segmentation_calculations.md  ← NEW (DOC-01)

tests/
├── unit/test_owner_segmentation.py    ← NEW (SEG-01..04 unit tests)
└── content/test_trend_store_owner.py  ← NEW or extend test_trend_store.py (SEG-05)
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Tag string parsing | New parser | Promote `_extract_owner_tag` from `critical_remediation_sla_module.py` §976 into `board_report_utils.py` | Already handles `"Cat=Val;Cat=Val"` format correctly, case-insensitive match |
| Excel workbook with header/data/freeze panes | Custom writer | Follow `_write_summary_tab` / `_write_data_tab` pattern from `unscanned_assets.py` §431/518 | Zebra stripe, freeze panes, header fill, column widths all handled |
| Atomic JSON write | Custom file write | Existing `_atomic_write_json` in `trend_store.py` | Already handles Windows fd-close-before-replace requirement |
| Tag-to-filename sanitization | Custom regex | Existing `_sanitise_tag_for_filename` in `trend_store.py` | Already used; `"all_assets"` for unscoped captures |
| Per-Owner percentage table | Custom groupby | Existing `compute_per_bu_breakdown` (renamed `compute_per_owner_breakdown`) | Already handles zero-denominator exclusion, sort, affected-count logic |

---

## Critical Code Surfaces (Verified by Direct Inspection)

### `board_report_utils.py` — Current Shape

**File:** `reports/modules/board_report_utils.py` [VERIFIED: direct read]

| Symbol | Current | Change Required |
|--------|---------|-----------------|
| `BU_TAG_CATEGORY` (§48) | `"Application"` | Rename to `OWNER_TAG_CATEGORY = "Owner"` (or parameterize) |
| `extract_business_unit(assets_df, tag_column_name="tags")` (§206) | Extracts `Application` tag → `business_unit` column; missing → `"Untagged"` | Rename to `extract_owner`; extract `Owner` tag → `owner` column; also extract `Application` → `application` column (D-05); missing → `"Unassigned"` (D-06) |
| Inner `_bu_from_tags` closure (§247) | Matches `BU_TAG_CATEGORY.casefold()` | Must match `OWNER_TAG_CATEGORY` (`"owner"`) AND separately extract `Application` for the `application` column |
| `compute_per_bu_breakdown(df, num_mask, den_mask, bu_column="business_unit", ...)` (§287) | `bu_column` param accepted but output always renamed to `"business_unit"` (§370: `.rename(columns={bu_column: "business_unit"})`) | Change output rename to `"owner"` — **this is the critical rename**: callers currently read `row["business_unit"]` which must become `row["owner"]` |
| `compute_bu_risk_scores(...)` (§407) | References `"business_unit"` column in `enriched` and `bu_map` (§460, §479) | Column references become `"owner"` |
| Docstring (§26-30) | Lists `extract_business_unit`, `compute_per_bu_breakdown`, etc. | Update to reflect new names |

**Catch-all pattern in `extract_business_unit` (§271, §278):**
```python
# Current:
df.loc[:, "business_unit"] = df[tag_column_name].apply(_bu_from_tags)
# _bu_from_tags returns "Untagged" on no-match

# After D-04 + D-06:
df.loc[:, "owner"] = df[tag_column_name].apply(_owner_from_tags)
# _owner_from_tags returns "Unassigned" on no-match
```

### `_extract_owner_tag` in `critical_remediation_sla_module.py` — Promote to Shared Helper

**Location:** `critical_remediation_sla_module.py` §976 [VERIFIED: direct read]

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

This returns `""` (empty string) rather than `"Unassigned"`. The new `extract_owner` in `board_report_utils.py` must return `"Unassigned"` on empty/no-match (D-06). After promoting, `_extract_owner_tag` in `critical_remediation_sla_module.py` should be removed; the module calls the shared helper instead.

**Where `_extract_owner_tag` is currently used in `critical_remediation_sla_module.py`:** Checking is needed during implementation — it appears in the BU breakdown helper `_compute_bu_breakdown` (§1050-1091), not in `compute()`. After D-03/D-04, that helper calls `extract_business_unit` (§1065) which is being generalized — so `_extract_owner_tag` becomes redundant once the shared helper handles `Owner`.

### Consumer Module `business_unit` Reference Map

All four consumer modules follow the same pattern [VERIFIED: grep of `reports/modules/*.py`]:

**`aged_vulns_assets_module.py`:**
- §241: `enriched = extract_business_unit(on_time)` → becomes `extract_owner(on_time)`
- §260: merge `on="business_unit"` → `on="owner"`
- §329-330: defensive re-extract `if "business_unit" not in asset_cols.columns` → `"owner"`
- §341: column slice `["asset_uuid", "hostname", "business_unit", "last_seen"]` → `"owner"`
- §356, §368: `"business_unit"` in column references → `"owner"`
- §389, §393-394: groupby `"business_unit"` + fillna `"Untagged"` → `"owner"` + fillna `"Unassigned"`
- §399, §402: sort and `worst_bu_name` → `"owner"`
- §580, §728: `row.get("business_unit", "")` in render methods → `"owner"`

**`high_risk_assets_module.py`:** Identical pattern to `aged_vulns_assets_module.py` at equivalent line numbers (§246, §265, §336-337, §348, §363, §373, §392-402, §584, §732).

**`scan_coverage_sla_module.py`:**
- §315: `enriched = extract_business_unit(licensed)` → `extract_owner`
- §362-363: defensive re-extract → `"owner"`
- §381, §394: column references → `"owner"`
- §414-433: sort + best/worst BU name references → `"owner"`
- §629, §777: `row.get("business_unit", "")` → `"owner"`
- §988: docstring reference

**`critical_remediation_sla_module.py`:**
- §55: import `extract_business_unit` → `extract_owner`
- §588, §740: `row.get("business_unit", "")` → `"owner"`
- §1061: empty DataFrame columns `["business_unit", ...]` → `["owner", ...]`
- §1065: `extract_business_unit(on_time_assets)` → `extract_owner`
- §1067: `enriched_assets["business_unit"]` → `enriched_assets["owner"]`
- §1071-1072: `fw["business_unit"]` assignment + `.fillna("Untagged")` → `"owner"` + `.fillna("Unassigned")`

### Consumer Render Strings Using "Business Unit" Heading

The PDF and Excel render methods in all four modules output the string `"Business Unit"` as a column header. These must change to `"Owner"` (D-02). Search pattern: `"Business Unit"` in HTML strings and openpyxl cell values.

**Confirming this is needed** — `scan_coverage_sla_module.py` §602 renders:
```html
<th>Business Unit</th>
```
And Excel tabs write column headers with "Business Unit". All four modules have equivalent header strings that must become `"Owner"`.

### `compute_per_bu_breakdown` Output Column Rename — The Key Gotcha

[VERIFIED: direct read of §370]

```python
.rename(columns={bu_column: "business_unit"})
```

This always renames the groupby column to `"business_unit"` regardless of the `bu_column` parameter. After D-04, it must rename to `"owner"`. The `bu_column` parameter can remain for future extensibility, but the output column name must match what consumers expect.

**Impact:** All four consumer modules read `row["business_unit"]` from the breakdown DataFrame. After this rename changes to `"owner"`, all those reads must also change — confirmed covered by the reference map above.

### `data/trend_store.py` — Owner Dimension Extension

**Current `capture_snapshot` dispatch** (§193-288) [VERIFIED: direct read]:
- `dimension="severity"` (default): calls `_count_by_severity(open_df)` which groups by `open_df["severity"]` and returns `{critical, high, medium, low}` counts.
- `dimension="owner"`: needs a new `_count_by_owner(open_df, enriched_assets)` that groups open findings by their asset's Owner tag and returns `{owner_name: int, ...}` dict.

**Key design point for `_count_by_owner`:** `open_df` does not have an `owner` column directly — it has `asset_uuid`. The enriched assets DataFrame (with `owner` column from the generalized helper) must be joined to `open_df` by `asset_uuid` to get per-Owner finding counts. The caller (`scripts/capture_trend_snapshot.py` or whoever drives the owner snapshot) must provide enriched assets, or `capture_snapshot` must accept enriched assets as an optional param.

**Preferred approach (follows Phase 12 D-08 df-injected pattern):** The caller enriches `assets_df` with Owner tags before passing to `capture_snapshot`, or `capture_snapshot` with `dimension="owner"` accepts the enriched assets. The snapshot payload becomes `{owner_name: count, ..., "asset_count": int}` — aggregate only (TREND-06/D-11).

**`read_trend` for owner dimension** (§291-346): Already handles arbitrary `dimension` and `tag_filter` strings. A call `read_trend("owner", "all_assets")` reads `data/trend/trend_owner_all_assets.json` without any code changes. The `tag_filter` matching guard at §333 (`relevant = [s for s in all_snaps if s.get("tag_filter") == tag_filter]`) will work correctly as long as the stored `tag_filter` field matches what is passed to `read_trend`.

### Combined Supplemental Excel — Precedent from `unscanned_assets.py`

**Pattern** [VERIFIED: direct read §431-603]:

```
unscanned_assets.xlsx:
  Tab 1: "Summary"     — _write_summary_tab(): metadata rows, counts table, reconciliation note
  Tab 2: "Overdue..."  — _write_data_tab(): header fill navy, zebra stripe, freeze_panes="A2"
  Tab 3: "No Lic..."   — _write_data_tab(): same pattern

CSV companion: _write_csv(): DictWriter, QUOTE_ALL, utf-8-sig encoding, Category column
```

**For Phase 13 combined supplemental (D-09):**
```
owner_segmentation.xlsx (or similar name):
  Tab 1: single flat tab — Owner | Application | <counts columns>
         Unassigned as Owner value; blank Application rows = "needs assignment" worklist
         Header: navy fill, freeze A2, zebra stripe, sortable/filterable
  
CSV companion: same columns as flat tab
```

The `_write_data_tab` function accepts a `col_spec: list[tuple[str, str]]` (header, field_name) and a DataFrame — this is exactly the pattern to follow. The `_safe_cell_value` helper handles openpyxl serialization of pd.NA/NaT (the root cause documented in prior observations §303).

**Output location:** Run output directory (same as other reports), gitignored by `output/` pattern; may be emailed internally (D-10).

---

## Common Pitfalls

### Pitfall 1: Two Catch-All Sites — Both Must Change

**What goes wrong:** Developer changes `extract_business_unit` to return `"Unassigned"` but misses the secondary `.fillna("Untagged").replace("", "Untagged")` calls in the consumer modules (aged_vulns at §393-394, high_risk at §396-397, critical_remediation at §1072, scan_coverage implicitly via `compute_per_bu_breakdown`).

**Why it happens:** The fillna in the helper normalizes the initial extraction; the fillna in the consumer is a defensive guard after groupby (which can produce NaN for genuinely-null group keys). Both sites must use `"Unassigned"`.

**How to avoid:** Grep for `"Untagged"` across all five blast-radius files before marking the task complete.

**Warning signs:** Tests pass but an asset with a null `owner` value (not just missing tag, but empty string from the parser) ends up in a mixed `"Untagged"`/`"Unassigned"` bucket.

### Pitfall 2: `compute_per_bu_breakdown` Renames Output Column to Hardcoded `"business_unit"`

**What goes wrong:** The helper is generalized and `extract_business_unit` is renamed to `extract_owner`, but the output of `compute_per_bu_breakdown` still has a `"business_unit"` column (§370 hardcodes the rename). Consumer code reading `row["business_unit"]` continues to work, masking that the column name was never updated.

**Why it happens:** The `bu_column` parameter controls the INPUT column name but the `.rename(columns={bu_column: "business_unit"})` always produces `"business_unit"` in output — easy to miss.

**How to avoid:** After D-04, change the rename to `.rename(columns={bu_column: "owner"})` AND update all consumer read sites. Test with an assertion that the output DataFrame has an `"owner"` column and NO `"business_unit"` column.

### Pitfall 3: `_extract_owner_tag` Returns `""` — Different from `"Unassigned"`

**What goes wrong:** The private `_extract_owner_tag` at §976 returns empty string `""` on no-match, while the new helper must return `"Unassigned"` (D-06). If the private function is reused without changing its return value, assets with no Owner tag get an empty string in the `owner` column rather than `"Unassigned"`, and groupby/fillna behavior diverges between callers.

**Why it happens:** The private function was designed to return a falsy sentinel for absence; the shared helper needs a display-safe label.

**How to avoid:** When promoting `_extract_owner_tag` into `board_report_utils.py`, change the no-match return from `""` to the configurable `unassigned_label` (default `"Unassigned"`). Then remove `_extract_owner_tag` from `critical_remediation_sla_module.py` entirely.

### Pitfall 4: PDF/Excel Headers Still Read "Business Unit"

**What goes wrong:** Column renames are complete but HTML table headers and openpyxl column headers in render methods still say `"Business Unit"` (D-02 requires `"Owner"`).

**Why it happens:** Header strings are not in the same locations as the column name variables — they are in f-string HTML or explicit `ws.cell(value="Business Unit")` calls, invisible to a grep for `"business_unit"`.

**How to avoid:** Grep for the display string `"Business Unit"` (case-insensitive) across all four consumer modules. Change to `"Owner"`.

### Pitfall 5: Trend Composition Needs Enriched Assets at Snapshot Time

**What goes wrong:** `capture_snapshot(df, assets_df, date, dimension="owner")` receives the raw `assets_df` without an `owner` column. Inside `_count_by_owner`, the join on `asset_uuid` fails or returns all-zero Owner counts because the column doesn't exist yet.

**Why it happens:** For `dimension="severity"`, `open_df` already has the `severity` column — no join needed. For `dimension="owner"`, the Owner tag must be extracted from `assets_df.tags` first.

**How to avoid:** Either (a) caller pre-enriches `assets_df` before passing to `capture_snapshot`, or (b) `capture_snapshot` enriches internally when `dimension="owner"` by calling `extract_owner`. Option (a) is consistent with Phase 12 D-08 ("df-injected, pure-ish"). Document the IN-06-equivalent scope coupling contract: `df` and `assets_df` must be the same scope, and `assets_df` must have an `owner` column when `dimension="owner"`.

### Pitfall 6: `read_trend` `tag_filter` Field Must Match Stored Value Exactly

**What goes wrong:** `capture_snapshot` writes `tag_filter="all_assets"` into the JSON entry, but `read_trend` is called with a slightly different string (e.g., `"Owner_all_assets"` or `"owner"`). The §333 filter finds no matching entries and returns `insufficient_data=True` on a populated file.

**Why it happens:** `read_trend` filters entries by `s.get("tag_filter") == tag_filter` and logs a warning but returns empty. The filename and stored field both encode `tag_filter`, so they must be consistent.

**How to avoid:** Use the same `tag_filter` string in both `capture_snapshot` and `read_trend` calls. For the all-assets Owner snapshot, `tag_filter="all_assets"` is the correct value (consistent with Phase 12 severity snapshot). The §334-338 warning log will surface any mismatch during testing.

### Pitfall 7: docstring/comment "Application tag" References in Four Modules

**What goes wrong:** Module docstrings and inline comments in all four consumer modules reference `"Application"` tag as the BU source (e.g., `scan_coverage_sla_module.py` §19: `"Derived from the Tenable tag category 'Application'"`, §988: `"deduplicated assets enriched with business_unit from Application tag"`). These are not functionally incorrect after the rename (they don't break tests) but they become wrong documentation.

**How to avoid:** Include a docstring/comment sweep in the repoint tasks. Update references from `Application` to `Owner` in the four module docstrings and the `board_report_utils.py` module-level docstring (§17, §26-30).

---

## Code Examples

### Pattern 1: Generalized `extract_owner` with dual-column extraction

```python
# Source: generalization of board_report_utils.py §206-280

OWNER_TAG_CATEGORY: str = "Owner"         # primary grouping dimension (D-01)
APPLICATION_TAG_CATEGORY: str = "Application"  # nested analyst drill-down (D-05)
_DEFAULT_UNASSIGNED_LABEL: str = "Unassigned"  # D-06

def extract_owner(
    assets_df: pd.DataFrame,
    tag_column_name: str = "tags",
    unassigned_label: str = _DEFAULT_UNASSIGNED_LABEL,
) -> pd.DataFrame:
    """
    Add ``owner`` and ``application`` columns from tag string.

    owner      — from "Owner" tag category (primary; D-01)
    application — from "Application" tag category (nested; D-05)
    Both default to unassigned_label / "" respectively when absent.
    """
    df = assets_df.copy()

    def _parse_tags(tags_val):
        owner_vals, app_vals = [], []
        if isinstance(tags_val, str) and tags_val.strip():
            for token in tags_val.split(";"):
                if "=" not in token:
                    continue
                cat, _, val = token.partition("=")
                cat_lower = cat.strip().casefold()
                val_clean = val.strip()
                if val_clean:
                    if cat_lower == OWNER_TAG_CATEGORY.casefold():
                        owner_vals.append(val_clean)
                    elif cat_lower == APPLICATION_TAG_CATEGORY.casefold():
                        app_vals.append(val_clean)
        owner = "; ".join(sorted(set(owner_vals))) if owner_vals else unassigned_label
        app   = "; ".join(sorted(set(app_vals)))   if app_vals   else ""
        return owner, app

    if tag_column_name in df.columns:
        parsed = df[tag_column_name].apply(_parse_tags)
        df.loc[:, "owner"]       = [p[0] for p in parsed]
        df.loc[:, "application"] = [p[1] for p in parsed]
    else:
        logger.warning("extract_owner: column %r not present — all assets Unassigned.", tag_column_name)
        df.loc[:, "owner"]       = unassigned_label
        df.loc[:, "application"] = ""
    return df
```

[Source: board_report_utils.py §206-280 generalized per D-03/D-04/D-05/D-06]

### Pattern 2: Consumer repoint — rename column references

```python
# Before (aged_vulns_assets_module.py §241, §260, §393-394):
enriched = extract_business_unit(on_time)
# ... merge on="business_unit"
bu_counts["business_unit"].fillna("Untagged").replace("", "Untagged")

# After (D-04, D-06):
enriched = extract_owner(on_time)
# ... merge on="owner"
owner_counts["owner"].fillna("Unassigned").replace("", "Unassigned")
```

[Source: aged_vulns_assets_module.py §241-399]

### Pattern 3: `_count_by_owner` for trend_store.py

```python
# New function alongside existing _count_by_severity in data/trend_store.py

def _count_by_owner(
    open_df: pd.DataFrame,
    enriched_assets: pd.DataFrame,
) -> dict[str, int]:
    """
    Return {owner_name: open_finding_count} for the open findings set.

    Joins open_df to enriched_assets on asset_uuid to get the owner label.
    Assets not found in enriched_assets are counted under "Unassigned".
    """
    if open_df.empty:
        return {}
    uuid_to_owner = dict(
        zip(enriched_assets["asset_uuid"], enriched_assets["owner"])
    ) if not enriched_assets.empty and "owner" in enriched_assets.columns else {}

    owner_col = open_df["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
    counts = owner_col.value_counts().to_dict()
    return {str(k): int(v) for k, v in counts.items()}
```

[Source: data/trend_store.py §171-185 pattern for _count_by_severity]

### Pattern 4: Combined supplemental Excel — single flat tab

```python
# New helper following unscanned_assets.py _write_data_tab pattern

def _write_owner_supplemental(
    wb: openpyxl.Workbook,
    owner_app_df: pd.DataFrame,  # columns: owner, application, <count cols>
) -> None:
    ws = wb.create_sheet("Owner Assignment")
    col_spec = [
        ("Owner",       "owner"),
        ("Application", "application"),
        ("Open Vulns",  "open_count"),
        # ... additional count columns as needed
    ]
    # Header row: navy fill, white bold text
    for col_idx, (header, _) in enumerate(col_spec, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = _FILL_HEADER   # PatternFill("solid", fgColor="1F3864")

    # Data rows: zebra stripe, left-aligned
    for row_idx, (_, row) in enumerate(owner_app_df.iterrows(), start=2):
        alt = (row_idx % 2 == 0)
        for col_idx, (_, field) in enumerate(col_spec, start=1):
            val = row.get(field, "")
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.alignment = Alignment(horizontal="left")
            if alt:
                cell.fill = _FILL_ALT

    ws.freeze_panes = "A2"
```

[Source: unscanned_assets.py §518-563 _write_data_tab]

---

## State of the Art

| Old Approach | Current Approach | Impact for Phase 13 |
|--------------|------------------|---------------------|
| `BU_TAG_CATEGORY = "Application"` (interim stand-in) | `OWNER_TAG_CATEGORY = "Owner"` (actual patching-responsible group) | Phase 13's primary change — repoints the board tables to the correct stakeholder |
| `"business_unit"` column name | `"owner"` column name (D-04) | Frees `"business_unit"` for the future real Business Unit tag |
| `"Untagged"` catch-all label | `"Unassigned"` (D-06) | Standardized display-safe label for the "no Owner tag" group |
| Private `_extract_owner_tag` in `critical_remediation_sla_module.py` | Promoted to shared `extract_owner` in `board_report_utils.py` | Single source of truth; removes duplication |
| Trend only supports `dimension="severity"` | `dimension="owner"` added via `_count_by_owner` dispatch | Proves S1×S2 composition (SEG-05) |

---

## Assumptions Log

> All claims in this research were verified by direct code inspection. The table below records the one design inference that requires discretion-exercise during planning.

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `capture_snapshot` caller (entry point script) will pre-enrich `assets_df` with the `owner` column before calling with `dimension="owner"`, keeping `capture_snapshot` pure-ish per Phase 12 D-08 | Trend Composition, Pitfall 5 | If instead `capture_snapshot` enriches internally, it must import from `board_report_utils` — creating a new cross-layer import (data/ → reports/modules/). Pre-enrichment by caller avoids this. [ASSUMED] |
| A2 | The combined supplemental filename will be `owner_segmentation.xlsx` / `owner_segmentation.csv` (following `unscanned_assets.xlsx` naming convention) | Combined Supplemental section | Cosmetic only — planner decides exact filename per Claude's Discretion |

---

## Open Questions

1. **Where does `_count_by_owner` get its enriched assets when called from `capture_snapshot`?**
   - What we know: `capture_snapshot(df, assets_df, ...)` receives raw `assets_df`; `_count_by_owner` needs an `owner`-enriched version.
   - What's unclear: Should the caller enrich before passing (cleaner separation), or should `capture_snapshot` enrich internally when `dimension="owner"` (one-stop API)?
   - Recommendation: Caller pre-enriches. `scripts/capture_trend_snapshot.py` calls `extract_owner(assets_df)` before calling `capture_snapshot`. This keeps `trend_store.py` (data layer) free of imports from `reports/modules/` (reports layer). The planner should make this explicit in the task.

2. **Combined supplemental: generated by `board_summary.py` run path or a standalone helper?**
   - What we know: `board_summary.py` drives the four board modules; D-09 wants the supplemental alongside board output.
   - What's unclear: Should the supplemental be written by `board_summary.run_report()` or by a standalone function in `board_report_utils.py` that `board_summary` calls?
   - Recommendation: New private function in `board_report_utils.py` called by `board_summary.run_report()` after the four modules compute — analogous to how `unscanned_assets.py` calls its private writers. Return path in the `run_report` dict under a new key (e.g., `"supplemental_excel"`).

3. **What count columns belong in the combined supplemental flat tab?**
   - What we know: D-09 specifies `Owner | Application | <counts columns>`; the "counts" are not specified.
   - What's unclear: Open vuln count only? Open by severity? Asset count? SLA breach count?
   - Recommendation: Keep it minimal for v1 — `Open Findings`, `Asset Count`, `Unassigned` boolean flag (True for Unassigned Owner rows). Analyst can sort/filter. Avoid metrics that require SLA computation, which would re-implement module logic.

---

## Environment Availability

> Step 2.6: No new external dependencies. All tools and runtimes are available.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python venv | All code | ✓ | pytest 9.0.3 confirmed | — |
| `openpyxl` | Combined supplemental Excel | ✓ | Already in requirements.txt | — |
| `pandas` | All DataFrame operations | ✓ | Already in requirements.txt | — |
| `data/trend/` directory | Trend composition | ✓ | Created by Phase 12 | — |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 9.0.3 |
| Config file | `pytest.ini` (testpaths: `tests/unit tests/content tests/e2e`) |
| Quick run command | `.venv/Scripts/python.exe -m pytest tests/unit tests/content -q -x` |
| Full suite command | `.venv/Scripts/python.exe -m pytest -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEG-01 | `extract_owner(df)` returns per-Owner buckets summing to total | unit | `.venv/Scripts/python.exe -m pytest tests/unit/test_owner_segmentation.py -x` | ❌ Wave 0 |
| SEG-02 | Assets with no Owner tag land in `"Unassigned"` bucket; totals reconcile | unit | same file | ❌ Wave 0 |
| SEG-03 | Supplemental Excel written to output dir, not committed, not AI-transmitted | manual/smoke | Verify file exists at output path; verify not in `.gitignore` exclusions | ❌ |
| SEG-04 | `extract_owner` on DataFrame with no tags column returns all-Unassigned, no raise | unit | `.venv/Scripts/python.exe -m pytest tests/unit/test_owner_segmentation.py::test_missing_tags_column -x` | ❌ Wave 0 |
| SEG-05 | `capture_snapshot(dimension="owner")` + `read_trend("owner")` round-trip | content | `.venv/Scripts/python.exe -m pytest tests/content/test_trend_store.py -x -k owner` | ❌ Wave 0 |
| DOC-01 | `docs/trend_and_segmentation_calculations.md` exists with required sections | manual | `Test-Path docs/trend_and_segmentation_calculations.md` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `.venv/Scripts/python.exe -m pytest tests/unit -q -x`
- **Per wave merge:** `.venv/Scripts/python.exe -m pytest tests/unit tests/content -q`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/unit/test_owner_segmentation.py` — covers SEG-01, SEG-02, SEG-04
- [ ] Extend `tests/content/test_trend_store.py` with owner-dimension cases — covers SEG-05
- [ ] `docs/trend_and_segmentation_calculations.md` (the deliverable itself is DOC-01)

*(The existing `tests/unit/test_modules.py`, `tests/content/test_trend_store.py`, and `tests/unit/test_open_count.py` infrastructure is in place — no new framework setup required)*

---

## Security Domain

> `security_enforcement` not explicitly set to false; applying standard check.

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | Yes (tag string parsing) | The `tags` column is Tenable-sourced and stored in parquet; the `_bu_from_tags`/`_owner_from_tags` parser already defensively checks `isinstance(tags_val, str)` and splits on `";"` — no injection surface. No change needed. |
| V6 Cryptography | No | No cryptographic operations |
| V2 Authentication | No | No new auth paths |
| V3 Session Management | No | No new session paths |
| V4 Access Control | No | Existing email/delivery access controls unchanged |

**Threat pattern:** The Owner tag values from Tenable could contain arbitrary strings. These are written into Excel cells (via openpyxl) and HTML (via `html.escape()` already used in render methods). The existing `html.escape()` calls in render methods cover XSS; openpyxl writes values as cell data (not formulas), so formula injection is not a risk unless a tag value starts with `=`, `+`, `-`, or `@`. The existing `_safe_cell_value` function in `unscanned_assets.py` does not explicitly guard against CSV injection; the combined supplemental should apply the same `_safe_cell_value` pattern.

---

## Sources

### Primary (HIGH confidence)

- `reports/modules/board_report_utils.py` — full file read; all function signatures, line numbers, constants verified
- `data/trend_store.py` — full file read; `capture_snapshot` and `read_trend` signatures verified
- `utils/open_count.py` — full file read; two-interval predicate implementation verified
- `reports/modules/aged_vulns_assets_module.py`, `high_risk_assets_module.py`, `scan_coverage_sla_module.py`, `critical_remediation_sla_module.py` — imports, compute(), render methods, all `business_unit` references verified via grep + targeted reads
- `reports/unscanned_assets.py` — `_write_summary_tab`, `_write_data_tab`, `_write_csv`, column specs verified
- `tests/content/test_trend_store.py` — test structure and fixture patterns verified
- `pytest.ini` — test framework config verified
- `.planning/phases/13-owner-segmentation-composition-s2-doc/13-CONTEXT.md` — all 12 decisions read

### Secondary (MEDIUM confidence)

- `.planning/REQUIREMENTS.md` — SEG-01..05, DOC-01 definitions
- `.planning/phases/12-trend-snapshot-substrate-s1/12-CONTEXT.md` — Phase 12 D-08/D-09 forward-compatibility decisions
- `.planning/notes/trend-reconstruction-engine.md` — Spike 002 findings (29-day retention constraint)

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new packages; all existing libraries verified in-repo
- Architecture: HIGH — all five blast-radius files read; exact line numbers for every change site documented
- Pitfalls: HIGH — all pitfalls derived from reading actual code, not inference

**Research date:** 2026-06-10
**Valid until:** 2026-07-10 (stable code; no external dependencies)
