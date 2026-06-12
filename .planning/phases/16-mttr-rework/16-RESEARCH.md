# Phase 16: MTTR Rework — Research

**Researched:** 2026-06-12
**Domain:** Four-channel metric module — rolling MTTR with reopened-aware duration clock, snapshot persistence, Owner MoM
**Confidence:** HIGH — all findings grounded in direct codebase inspection of the files named in CONTEXT.md

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-16-01:** Option B — durably-fixed only. Population = `state == "FIXED"`. Drop the `state=="fixed" OR last_fixed.notna()` clause from the existing module.
- **D-16-02:** Date-math only, reopened-aware. `days_to_fix = (last_fixed − COALESCE(resurfaced_date, first_found)).days`, clipped ≥ 0. Drop `time_taken_to_fix` preference entirely.
- **D-16-03:** Persist rolling-30-day MTTR aggregate into the S1 snapshot store (overall + per-severity + per-Owner). Extend `data/trend_store.py` `capture_snapshot()` and `scripts/capture_trend_snapshot.py`.
- **D-16-04:** Configurable window, default 30. `module_options` key `mttr_window_days`. Disclosure label reads the actual window value.
- **D-16-05:** Headline = sample-weighted overall MTTR + MoM trend line + per-severity breakdown + Owner table.
- **D-16-06:** Owner cut is MoM (not current-snapshot-only). Per-Owner cold-start valid; Owner-set drift defined at plan time.
- **D-16-07:** Sub-threshold rows render "Insufficient data (N findings)". Zero fixed-findings-in-scope → `_empty_result()`.
- **D-16-08:** Calendar-month X-axis. One trend point per calendar month. Current month flagged "Month-to-date (partial)". Multiple snapshots in one month → use the latest.
- **D-16-09:** Implicit optional-field convention (same as D-15-06). No `schema_version`. Absent field → cold-start.
- **D-16-10:** `board_summary` baseline re-capture is a zero-diff safety confirmation. Separately capture new structural smoke baseline for `mttr_trend`. `mttr_by_severity_module.py` byte-unchanged.
- **OD-7 confirmed:** `MODULE_ID = "mttr_trend"`. `mttr_by_severity_module.py` left byte-unchanged.

### Claude's Discretion
- Exact snapshot field names + JSON shape for the new MTTR aggregate
- Chart styling and gauge-vs-line choices
- Excel column order
- Precise Owner-drift join/missing-month mechanics
- Multiple-snapshots-in-one-month tie-break
- `min_sample_size` default (confirm 5 at plan time)
- Exact "as-of"/partial disclosure wording

### Deferred Ideas (OUT OF SCOPE)
- MTTR history backfill beyond ~29 days
- Sub-monthly reopen rate
- WAS MTTR (gated on SDK upgrade)
- Program Health (Phase 17)
- `management_summary` migration (Phase 18)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RPT-05 | Reworked MTTR (`mttr_trend`) disclosing window, sample-weighted mean, reopened-aware duration, MoM trend + Owner cut on four-channel contract | Open items 1–6 below resolve all implementation unknowns |
| QUAL-01 | Cold-start branching — `insufficient_data` checked before any MoM delta | Open item 2 (Owner-drift join) and open item 4 (min_sample) |
| QUAL-02 | Reopened-aware predicate for any open-count context | Open item 3 confirms `resurfaced_date` is fetched and normalised |
| QUAL-03 | Empty-data guard on all four channels | Open item 4 specifies the exact threshold and fallback path |
| QUAL-05 | Aggregate-only PII — no hostnames/IPs/plugin names in snapshots | Open item 1 (snapshot field names are floats/ints only) |
</phase_requirements>

---

## Summary

Phase 16 adds one new file (`reports/modules/mttr_trend_module.py`), extends two existing files (`data/trend_store.py` `capture_snapshot()` and `scripts/capture_trend_snapshot.py`), and adds `"mttr_trend"` to one frozenset (`composed_report._MODULES_NEEDING_TREND_SNAPSHOTS`). Everything else is untouched.

The implementation is a surgical rework of the existing `mttr_by_severity_module.py` logic — copied into the new file, then modified in three places: (a) the resolved-population filter (line ~173–177 becomes `state == "FIXED"` only), (b) the `days_to_fix` derivation (lines ~190–222 replace the `time_taken_to_fix` preference with the COALESCE date-math), and (c) the overall-mean aggregation (lines ~282–286 become a flat `mean()` across all in-scope findings instead of a mean-of-per-severity-means). New capabilities layered on top are the MoM trend read from snapshots, Owner table, and window disclosure.

The `capture_snapshot()` extension follows the exact pattern Phase 15 used for `reopened_count`, `accepted_count`, `recast_count`, and `fixed_findings_count` — new optional kwargs with `None` as the backward-compatible default.

**Primary recommendation:** Build in five sequential steps — snapshot schema extension → capture script wiring → new module → composed_report frozenset → tests + baselines. No parallel work required; each step is a prerequisite for the next.

---

## Open Item 1: Snapshot Schema Shape

### Current schema (from `data/trend_store.py` lines 358–370)

A severity-dimension snapshot entry today looks like:

```json
{
  "month": "2026-06",
  "tag_filter": "all_assets",
  "critical": 47,
  "high": 183,
  "medium": 412,
  "low": 91,
  "asset_count": 312,
  "on_time_asset_count": 298,
  "reopened_count": 14,
  "accepted_count": 6,
  "recast_count": 2,
  "new_findings_count": 38,
  "fixed_findings_count": 51,
  "generated_at": "2026-06-01T06:00:00Z"
}
```

Fields added in Phase 15 (`on_time_asset_count`, `reopened_count`, `accepted_count`, `recast_count`, `new_findings_count`, `fixed_findings_count`) are all optional kwargs with `None` defaults. An older snapshot lacking them is a valid cold start for those dimensions. This is the **implicit optional-field convention (D-16-09)** that Phase 16 repeats exactly.

### Proposed new fields (Phase 16 addition)

Add three new optional fields to the severity-dimension snapshot entry:

```json
{
  "...existing fields...",
  "mttr_overall_days": 14.3,
  "mttr_by_severity": {
    "critical": 8.1,
    "high": 12.4,
    "medium": 19.7,
    "low": null
  },
  "mttr_by_owner": {
    "Engineering": 11.2,
    "Operations": 17.8,
    "Unassigned": null
  }
}
```

**Field specification:**

| Field | Type | Semantics | PII safe? |
|-------|------|-----------|-----------|
| `mttr_overall_days` | `float \| null` | Sample-weighted mean `days_to_fix` over all durably-fixed findings in the rolling window. `null` when sample < `min_sample_size` overall. | Yes — float |
| `mttr_by_severity` | `dict[str, float \| null]` | Per-severity MTTR floats. Keys always present: `critical`, `high`, `medium`, `low`. `null` when that severity's sample < `min_sample_size`. | Yes — floats |
| `mttr_by_owner` | `dict[str, float \| null]` | Per-Owner MTTR floats. Keys are Owner tag names (internal strings per `[[project_pii_rule_is_ai_not_email]]`). `null` when that Owner's sample < `min_sample_size`. Empty dict `{}` when no fixed findings exist. | Yes — aggregate floats + internal tag names |

**Before/after snapshot record:**

```json
// BEFORE (current severity snapshot)
{
  "month": "2026-06",
  "tag_filter": "all_assets",
  "critical": 47,
  "fixed_findings_count": 51,
  "generated_at": "2026-06-01T06:00:00Z"
}

// AFTER (same snapshot with Phase 16 MTTR fields added)
{
  "month": "2026-06",
  "tag_filter": "all_assets",
  "critical": 47,
  "fixed_findings_count": 51,
  "mttr_overall_days": 14.3,
  "mttr_by_severity": {"critical": 8.1, "high": 12.4, "medium": 19.7, "low": null},
  "mttr_by_owner": {"Engineering": 11.2, "Operations": 17.8, "Unassigned": null},
  "generated_at": "2026-06-01T06:00:00Z"
}
```

**Cold-start rule:** A snapshot that has none of the three new fields is a valid cold start for the MTTR MoM series. `mttr_trend.compute()` treats `snap.get("mttr_overall_days")` returning `None` as "no MTTR captured for this month" — it does not crash.

**Backward-compat proof:** `capture_snapshot()` currently accepts `fixed_vulns_df: Optional[pd.DataFrame] = None` and skips `new_findings_count` / `fixed_findings_count` derivation when it is `None`. The three new MTTR kwargs (`mttr_overall_days`, `mttr_by_severity`, `mttr_by_owner`) follow the same pattern — keyword-only, `Optional`, defaulting to `None`. Existing callers (`capture_trend_snapshot.py`) that do not pass the new kwargs will write `None` for all three (or simply omit them from the entry dict — see implementation note below).

**Implementation note on omission vs. explicit null:** Phase 15 stores explicit `None` values as JSON `null` in the snapshot dict (visible in `new_entry` at `trend_store.py` line 363: `"on_time_asset_count": on_time_asset_count`). Phase 16 should follow the same pattern — include the keys with `null` rather than omitting them. This makes the schema self-documenting and ensures `snap.get("mttr_overall_days")` returns `None` rather than requiring a two-path check.

**`capture_snapshot()` signature extension (new kwargs only):**

```python
def capture_snapshot(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    date: datetime,
    dimension: str = "severity",
    tag_filter: str = "all_assets",
    trend_dir: Optional[Path] = None,
    enriched_assets: Optional[pd.DataFrame] = None,
    on_time_asset_count: Optional[int] = None,
    reopened_count: Optional[int] = None,
    accepted_count: Optional[int] = None,
    recast_count: Optional[int] = None,
    fixed_vulns_df: Optional[pd.DataFrame] = None,
    # ---- Phase 16 additions ----
    mttr_overall_days: Optional[float] = None,
    mttr_by_severity: Optional[dict] = None,
    mttr_by_owner: Optional[dict] = None,
) -> Path:
```

These are appended to the `new_entry` dict verbatim (the same `**{...}` spread pattern at lines 358–370). No conditional logic needed inside `trend_store.py` — the caller computes the values and passes them in.

---

## Open Item 2: Owner-Drift Join / Missing-Month Mechanics

### Reference implementation: `new_vs_remediated_module.py`

`new_vs_remediated_module.py` reads `trend_snapshots["snapshots"]` (a list of dicts sorted ascending by month) and iterates over them to build per-month arrays. It does NOT build a cross-snapshot join; each month is computed independently from that month's snapshot fields plus the live `vulns_df`. The Owner cut is computed from `open_findings_at()` against the current report's `vulns_df`, not from stored per-Owner snapshots.

`mttr_trend` differs: the Owner MTTR series is stored per snapshot (not derivable from the current export due to the ~29-day retention wall). The join across snapshots must be explicit.

### Recommended mechanics

**Data structure in `compute()`:** Build a dict `owner_series: dict[str, list[Optional[float]]]` keyed by Owner name, where the value is a list of MTTR values aligned to the months list. Build it in a single pass over snapshots:

```python
months: list[str] = []
overall_mttr_series: list[Optional[float]] = []
sev_series: dict[str, list[Optional[float]]] = {s: [] for s in _SEVERITIES}
owner_set: set[str] = set()

for snap in snapshots:
    months.append(snap.get("month", ""))
    overall_mttr_series.append(snap.get("mttr_overall_days"))
    for sev in _SEVERITIES:
        sev_series[sev].append(
            (snap.get("mttr_by_severity") or {}).get(sev)
        )
    for owner in (snap.get("mttr_by_owner") or {}):
        owner_set.add(owner)

# Build per-owner series with None back-fill for months before that Owner appeared
owner_series: dict[str, list[Optional[float]]] = {}
for snap_idx, snap in enumerate(snapshots):
    snap_owners = snap.get("mttr_by_owner") or {}
    for owner in owner_set:
        if owner not in owner_series:
            owner_series[owner] = [None] * snap_idx  # back-fill missing months
        owner_series[owner].append(snap_owners.get(owner))

# Forward-fill trailing None for owners who vanished
for owner in owner_set:
    series = owner_series[owner]
    while len(series) < len(months):
        series.append(None)
```

**New Owner (cold start for that Owner):** On first appearance its series starts with `None` back-fills for all prior months, then the actual MTTR value from the snapshot where it appears. No crash; no `NaN%`. Renders as "Trend data being established" for the MoM delta on that Owner's first month.

**Vanished Owner (dropped from scope):** After its last snapshot, the Owner's series is padded with trailing `None` values. In the Owner table render, show only Owners whose MOST RECENT snapshot month has a non-`None` value (i.e. filter to `owner_series[owner][-1] is not None`). A vanished Owner simply disappears from the table without error.

**Missing month for an existing Owner:** An Owner may have `null` in `mttr_by_owner` for a given month because its sample was below `min_sample_size` that month (not because it vanished). Render as "—" in the Owner MoM column, not as 0. In the MoM delta column, treat prior-month `None` identically to the zero-denominator case — show "N/A", not a computed percentage.

**Multiple snapshots in the same calendar month (D-16-08 tie-break):** Before the per-month loop, deduplicate to the latest snapshot per month:

```python
by_month: dict[str, dict] = {}
for snap in snapshots:
    m = snap.get("month", "")
    if m not in by_month or snap.get("generated_at", "") > by_month[m].get("generated_at", ""):
        by_month[m] = snap
snapshots_deduped = [by_month[m] for m in sorted(by_month)]
```

This uses `generated_at` (ISO UTC string — lexicographic sort is correct) to pick the latest. If `generated_at` is absent, last-encountered wins (acceptable for the degenerate case).

**MoM delta calculation:** Defined as `current_month_value − prior_month_value` in days (absolute delta, not percentage). A negative delta means MTTR improved. Use `safe_format` for rendering. Percentage change is NOT used for MTTR — the absolute day delta is more operationally meaningful for a remediation SLA audience.

```python
# Owner MoM delta for the last two months
def _owner_mom_delta(series: list[Optional[float]]) -> Optional[float]:
    if len(series) < 2:
        return None
    curr, prev = series[-1], series[-2]
    if curr is None or prev is None:
        return None
    return round(curr - prev, 1)
```

**Partial-month label:** Mirror `new_vs_remediated_module.py`'s `_month_label()` helper exactly. The current calendar month gets the "(Month-to-date — partial)" suffix per D-16-08. The wording "Month-to-date" is preferable to "MTD" in isolation because MTTR is expressed in days and "MTD" without expansion reads ambiguously.

---

## Open Item 3: Duration-Clock Validation

### Field availability in `data/fetchers.py`

Direct inspection of `fetch_all_vulnerabilities()` (lines 350–361) and `fetch_fixed_vulnerabilities()` (lines 465–475) confirms all four fields are fetched and normalised:

| Field | Fetched in `vulns` | Fetched in `vulns_fixed` | Normalised to `datetime64[ns, UTC]` |
|-------|-------------------|--------------------------|-------------------------------------|
| `first_found` | Yes (line 350) | Yes (line 465) | Yes (`_normalize_vuln_dates`, line 1173) |
| `last_fixed` | Yes (line 352) | Yes (line 467) | Yes |
| `resurfaced_date` | Yes (line 360) | Yes (line 473) | Yes |
| `time_taken_to_fix` | Yes (line 361) | Yes (line 474) | No — raw numeric (seconds) |

The D-16-02 formula `(last_fixed − COALESCE(resurfaced_date, first_found)).days` is fully implementable from existing fetched fields.

### Vectorised implementation pattern

```python
# All datetime columns are already tz-aware datetime64[ns, UTC] after fetcher normalisation.
# No additional pd.to_datetime() coercion needed — but defensively coerce with utc=True
# in case the module receives a partially-normalised DataFrame.

last_fixed_ts = pd.to_datetime(
    fixed_df["last_fixed"] if "last_fixed" in fixed_df.columns else _nat_series,
    utc=True, errors="coerce",
)
first_found_ts = pd.to_datetime(
    fixed_df["first_found"] if "first_found" in fixed_df.columns else _nat_series,
    utc=True, errors="coerce",
)
resurfaced_ts = pd.to_datetime(
    fixed_df["resurfaced_date"] if "resurfaced_date" in fixed_df.columns else _nat_series,
    utc=True, errors="coerce",
)

# COALESCE: use resurfaced_date when present, else first_found
clock_start_ts = resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)

# days_to_fix — both sides are tz-aware datetime64[ns, UTC]; subtraction is safe
date_diff_days = (last_fixed_ts - clock_start_ts).dt.days.clip(lower=0)

fixed_df = fixed_df.assign(days_to_fix=date_diff_days)

# Drop rows where we cannot compute a days_to_fix value
fixed_df = fixed_df[
    fixed_df["days_to_fix"].notna() & (fixed_df["days_to_fix"] >= 0)
]
```

### Dtype / tz pitfalls

1. **Both sides must be tz-aware before subtraction.** The fetcher normalises via `_normalize_vuln_dates` (line 1173) which calls `pd.to_datetime(df[col], utc=True, errors="coerce")`. If the module receives a pre-normalised DataFrame this is fine. If it receives a raw export (e.g. in tests), the defensive `utc=True` coerce above handles it. Subtracting a tz-naive from a tz-aware Series raises `TypeError` in pandas 2.2+.

2. **NaT handling.** `(NaT - timestamp).dt.days` returns `NaT` (not 0 or negative). The `.clip(lower=0)` call does not change `NaT` to 0 — it only clips numeric values. The subsequent `fixed_df["days_to_fix"].notna()` filter correctly drops NaT rows.

3. **`resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)` mixed-tz safety.** Both `resurfaced_ts` and `first_found_ts` are `datetime64[ns, UTC]` after the same coerce path. `.where()` with `other=` is safe when both sides share the same dtype.

4. **pandas CoW.** The `fixed_df.assign(days_to_fix=...)` pattern is compliant. Never `fixed_df["days_to_fix"] = date_diff_days` after a filter (QUAL-03, `260611-b1x`).

### Criterion-3 fixture validation

Fixture: `first_found` = −200d, `resurfaced_date` = −10d, `last_fixed` = −2d (all relative to report_date).

```
clock_start = resurfaced_date (−10d)  ← resurfaced_date is not NaT
days_to_fix = last_fixed − clock_start = (−2d) − (−10d) = 8 days
```

Result: **8 days**. The old module would compute `(last_fixed − first_found).days = (−2d) − (−200d) = 198 days`. The rework eliminates the inflation.

**Unit test fixture (synthetic, RFC 5737/6761):**

```python
REF = datetime(2026, 6, 12, tzinfo=timezone.utc)
fixture = pd.DataFrame({
    "state":           ["fixed"],
    "severity":        ["critical"],
    "asset_uuid":      ["00000000-0000-0000-0000-000000000001"],
    "first_found":     [REF - timedelta(days=200)],
    "resurfaced_date": [REF - timedelta(days=10)],
    "last_fixed":      [REF - timedelta(days=2)],
})
# Normalise to UTC-aware
for col in ("first_found", "resurfaced_date", "last_fixed"):
    fixture[col] = pd.to_datetime(fixture[col], utc=True)
# Expected: days_to_fix = 8, overall_mttr = 8.0
```

### Live-tenant `resurfaced_date` population

This was verified in Phase 15 (plan 15-01 PATHFINDER task). The live-tenant spot-check result is recorded in the Phase 15 execution history. Phase 16 does not need to re-verify — the field is confirmed populated for REOPENED findings. The build-time verification task is: run the criterion-3 unit test (above) against the synthetic fixture before claiming `days_to_fix` is correct.

---

## Open Item 4: `min_sample_size` Default and Render Paths

### Confirmed default: 5

The existing module (`mttr_by_severity_module.py` line 161) defaults to `1`:
```python
min_sample = int(config.options.get("min_sample_size", 1))
```

ROADMAP success criterion 5 explicitly states: "Per-severity sample sizes below the minimum threshold (default 5) render 'Insufficient data (N findings)'". The new module must default to `5`.

```python
min_sample = int(config.options.get("min_sample_size", 5))  # default raised to 5
```

### Render paths by scope

| Condition | Applies To | Render |
|-----------|-----------|--------|
| `len(fixed_df) == 0` overall | Module | `_empty_result()` with gray RAG strip, `error=None`, `metrics["cold_start"]=True` — identical to `new_vs_remediated._build_cold_start_result()` pattern |
| `len(sev_df) < min_sample` for one severity | That severity | `"Insufficient data (N findings)"` in all channels. `mttr_days = None` for that row. Status = gray "No Data". |
| `len(owner_df) < min_sample` for one Owner | That Owner row | `"Insufficient data (N findings)"` in Owner table. MTTR = `None`. |
| `len(owner_df) == 0` (zero fixed findings for an Owner) | That Owner | Omit row entirely from the Owner table (D-16-07: owners with zero fixed findings are omitted, not shown as "Insufficient data") |
| `len(fixed_df) >= 1` but overall < min_sample | Overall MTTR | `overall_mttr = None`. Sample-weighted formula still applies to individual severities that meet threshold. Show overall as "Insufficient data (N findings)". |
| `trend_snapshots` absent or `insufficient_data=True` | MoM trend | Cold-start notice on MoM trend line only; current-snapshot per-severity gauges still render (they come from `fixed_vulns_df` live, not from snapshots) |

**Key insight:** The per-severity gauges (from `fixed_vulns_df` live data) and the MoM trend line (from snapshots) are independent cold-start paths. A group on its first run has no snapshots but does have `fixed_vulns_df` — it should still show per-severity gauges and "Trend data being established" for the MoM panel.

**"Insufficient data" wording:** Standardise on:
```
"Insufficient data (3 findings — minimum 5 required)"
```
Include both the actual sample count and the threshold so the recipient understands why.

**`safe_pct` / `safe_int` / `safe_format` enforcement:** Every value path that can yield `None` must pass through `format_utils`. No inline `f"{mttr:.1f}d"` on a value that could be `None`. Use:
```python
from reports.modules.format_utils import safe_format
mttr_str = safe_format(mttr, "{:.1f}d") if mttr is not None else "Insufficient data"
```

---

## Open Item 5: Build Order and Untouched-Files Guard

### Recommended build sequence

```
Step 1 — trend_store.py extension
  File:  data/trend_store.py
  Change: Add 3 optional kwargs to capture_snapshot(); add them to new_entry dict.
  Test:   Smoke block (python data/trend_store.py) still passes; existing callers unaffected.

Step 2 — capture_trend_snapshot.py wiring
  File:  scripts/capture_trend_snapshot.py
  Change: Compute mttr_overall_days / mttr_by_severity / mttr_by_owner from fixed_vulns_df
          using D-16-02 formula; pass to capture_snapshot() severity call.
  Test:   --dry-run succeeds; --verbose log shows computed aggregate values.
  Note:   fixed_vulns_df is already fetched in this script (lines 287–294).
          Owner enrichment already present (extract_owner call at line 315).

Step 3 — new module file
  File:  reports/modules/mttr_trend_module.py  (NEW)
  Change: New @register_module class MTTRTrendModule; MODULE_ID = "mttr_trend".
          Copy structural shell from mttr_by_severity_module.py, then apply
          the three surgical replacements (population filter, days_to_fix, overall mean).
          Add: MoM trend read from kwargs["trend_snapshots"], Owner table,
          window disclosure, min_sample=5 default.
  Test:   Unit tests for criterion-3 fixture (8d result), zero-row guard,
          cold-start guard, min_sample threshold rendering.

Step 4 — composed_report frozenset
  File:  reports/composed_report.py
  Change: Add "mttr_trend" to _MODULES_NEEDING_TREND_SNAPSHOTS frozenset.
  Test:   Existing composed_report dry-run tests pass; no regression on current
          modules in the frozenset.

Step 5 — tests and baselines
  Files: tests/test_mttr_trend_module.py (NEW)
         tests/baselines/mttr_trend_*.json (NEW — captured after Step 3 passes)
         tests/baselines/board_summary_*.json (RE-CAPTURED — zero-diff confirmation)
  Test:   All tests green; board_summary baselines byte-identical.
```

### Untouched-files guarantee (D-16-10)

The following files MUST NOT be modified in any wave of Phase 16:

| File | Reason |
|------|--------|
| `reports/modules/mttr_by_severity_module.py` | Byte-unchanged per D-16-10; board_summary groups reference it |
| `reports/modules/board_report_utils.py` | `extract_owner()` is consumed, not modified |
| `reports/modules/composer.py` | `**self._kwargs` fan-out already handles new kwargs |
| `reports/modules/base.py` | No new abstract methods; `_empty_result()` reused as-is |
| `data/fetchers.py` | All required fields already fetched |
| `utils/open_count.py` | `open_findings_at()` consumed, not modified |
| `config.py` | `SLA_DAYS` consumed, not modified |
| `delivery_config.schema.yaml` | `mttr_trend` is a module ID, not a top-level report slug; no schema registration needed |
| `run_all.py` | `_VALID_REPORTS` / `_REPORT_MODULE_MAP` untouched; module auto-discovered |

**Why `run_all.py` is untouched:** `mttr_trend` is consumed via `composed_report` or `management_summary` (Phase 18), not as a standalone report slug. CLAUDE.md registration steps (adding to `_VALID_REPORTS`, `_REPORT_MODULE_MAP`, `CLAUDE.md` schema list) apply only to top-level report slugs. Module auto-discovery (`@register_module` + `reports.modules` import triggering `registry.discover()`) handles everything else.

---

## Open Item 6: board_summary Baseline Re-Capture (D-16-10)

### How board_summary structural smoke works

`tests/baseline_utils.py` defines `extract_structural_snapshot(bundle, group_slug)` which extracts 12 structural keys from a report bundle: `pdf_page_count`, `pdf_rag_cell_count`, `excel_tab_names_sorted`, `email_panel_count`, `email_inline_image_cids_per_module`, `bundle_keys_present`, `analyst_excel_present`, `rag_cells_all_no_data`, `panel_drivers_all_no_data_in_scope`, and three others. Metric values are never captured.

The three existing board_summary baselines are:
- `tests/baselines/board_summary_test_pull.json`
- `tests/baselines/board_summary_test_pull_analyst_off.json`
- `tests/baselines/board_summary_test_pull_zero_match.json`

These are compared against actual bundle output via `compare_snapshots(actual, baseline)` which returns a list of diff lines. An empty list = no regression.

### Zero-diff confirmation procedure (D-16-10)

After Phase 16 is fully implemented (Steps 1–4 above complete), the procedure is:

1. Run board_summary with its standard synthetic test fixtures (the same fixtures that produced the three existing baselines).
2. Call `extract_structural_snapshot(bundle, "board_summary_test_pull")`.
3. Call `compare_snapshots(actual_snap, load_baseline(...))`.
4. Assert `diffs == []` — **any diff means something broke**.

The three keys most likely to drift if something went wrong: `pdf_rag_cell_count` (would change if a new RAG cell was accidentally added to board_summary's cover), `excel_tab_names_sorted` (would change if a new tab appeared), `email_panel_count` (would change if an extra panel was injected).

Because `mttr_by_severity_module.py` is byte-unchanged and the new optional `capture_snapshot` params are not passed by the board_summary code path, this diff MUST be zero. A non-zero diff indicates a scope violation — something outside the allowed change list was modified.

### New mttr_trend baseline capture

Separately, after `tests/test_mttr_trend_module.py` passes, capture a new structural smoke baseline for `mttr_trend` by:

1. Building a synthetic composed-report bundle that includes `mttr_trend` (with synthetic `fixed_vulns_df` and 2-snapshot `trend_snapshots`).
2. Calling `extract_structural_snapshot(bundle, "mttr_trend_test_pull")`.
3. Writing to `tests/baselines/mttr_trend_test_pull.json` via `write_baseline()`.
4. Adding a zero-match variant: zero fixed findings → `_empty_result()` bundle → `tests/baselines/mttr_trend_test_pull_zero_match.json`.

These new baselines are committed as part of Phase 16's final plan.

---

## Architecture Patterns

### Four-channel render contract for `mttr_trend`

| Channel | Content | Notes |
|---------|---------|-------|
| `render_pdf_section` | Overall MTTR gauge (vs SLA) + window disclosure footer + per-severity gauges (4 small, same as existing module) + MoM trend line chart + Owner MTTR table | Window disclosure: `<p class="explanatory-text">Rolling {window_days}-day MTTR — findings remediated in the last {window_days} days.</p>` |
| `render_excel_tabs` | Single "MTTR Trend" tab: per-severity rows (MTTR, SLA, variance, status, sample, N-finding note if sub-threshold) + Owner table below | Column order: Severity/Owner, MTTR (Days), SLA Target, Variance, Status, Sample Size, MoM Delta |
| `render_email_panel` | CONTRACT-01 table; overall MTTR headline + RAG color + window disclosure in footer + MoM delta arrow | Never `render_email_kpis` — new v1.4 modules implement `render_email_panel` |
| `render_rag_strip_entry` | CONTRACT-03; headline = overall MTTR string (e.g. "14.3d"); RAG = Green/Amber/Red vs SLA | Use `build_rag_strip_entry` from `rag_utils.py` |

### RAG logic for overall MTTR

Mirror the existing module's `_status_from_ratio()`:
- `overall_mttr / SLA_DAYS["critical"]` — use Critical SLA as the overall RAG anchor (most stringent; consistent with the existing module)
- Green: ratio ≤ 1.0 | Amber: ratio ≤ 1.25 | Red: ratio > 1.25
- No overall MTTR (zero fixed findings or sub-threshold): gray "No Data" RAG

### Partial-month disclosure wording (recommended)

For the PDF explanatory text:
```
Rolling {window_days}-day MTTR — findings remediated in the last {window_days} days.
Current month ({month_str}) is month-to-date (partial).
```

For the email panel footer (inline CSS only):
```html
<span style="font-size:10px;color:#757575;">
  Rolling {window_days}-day MTTR.
  Current month is partial.
</span>
```

For the Excel header (row 1 of the MTTR Trend tab):
```
MTTR Trend — Rolling {window_days}-day window
```

The disclosure text reads the actual `window_days` value (from `config.options.get("mttr_window_days", 30)`), so it can never misstate the window.

---

## Common Pitfalls (Phase-Specific)

### Pitfall A: `resurfaced_ts.where()` dtype mismatch

If `resurfaced_date` is all-NaT for a given DataFrame (no reopened findings in scope), `pd.to_datetime(..., utc=True, errors="coerce")` returns a `datetime64[ns, UTC]` Series of all NaT. `.where(notna(), other=first_found_ts)` with two `datetime64[ns, UTC]` Series is safe. However if either side is `object` dtype (e.g. raw string column not yet normalised), the `.where()` result is also `object` dtype and subtraction fails. Prevention: always coerce both sides explicitly with `pd.to_datetime(..., utc=True, errors="coerce")` even if the fetcher already normalised them.

### Pitfall B: per-Owner `null` vs. absent dict key

`snap.get("mttr_by_owner")` returns `None` (not a dict) for old snapshots. The pattern `(snap.get("mttr_by_owner") or {}).get(owner)` handles both `None` and missing-key cases. Do NOT use `snap["mttr_by_owner"][owner]` — this raises `KeyError` on old snapshots and `TypeError` on `None`.

### Pitfall C: rolling window application

D-16-04 specifies a configurable rolling window (default 30 days). The window is applied to `fixed_vulns_df` in `capture_trend_snapshot.py` BEFORE computing the MTTR aggregate to pass to `capture_snapshot()`. The window predicate is: `last_fixed >= (snapshot_date - timedelta(days=window_days))`. This must be applied in the capture script, not inside the module (the module only reads pre-computed values from snapshots for MoM, though it applies the window to the live `fixed_vulns_df` for the current snapshot's gauges). Document this split clearly.

### Pitfall D: `days_to_fix` window mismatch between live gauges and snapshot MTTR

The current-run per-severity gauges derive MTTR from the live `fixed_vulns_df` (windowed). The MoM trend line reads MTTR from snapshots. These should agree for the current month if the capture script ran with the same window. If `mttr_window_days` was changed between runs, they may diverge. The module should note in `metadata` what window was used for the live computation.

### Pitfall E: board_summary baseline re-capture timing

Re-capture the board_summary baselines AFTER all Phase 16 code is merged, not before. Re-capturing before the merge leaves baselines that reflect a partially-changed codebase. The correct order: all changes merged → board_summary dry-run with test fixtures → `extract_structural_snapshot` → `compare_snapshots` asserts zero diff → baselines confirmed (no file update needed since they are unchanged).

---

## Validation Architecture

Nyquist validation is not the primary gate for this phase (no config.json flag checked — treated as not blocking). The following unit tests are implied by the success criteria and are plannable:

| Test | File | Fixture | Assertion |
|------|------|---------|-----------|
| Criterion-3 reopened-clock fixture | `tests/test_mttr_trend_module.py` | `first_found=−200d, resurfaced_date=−10d, last_fixed=−2d` (all UTC-aware) | `days_to_fix == 8`, `overall_mttr == 8.0` |
| Zero fixed findings → `_empty_result()` | same | Empty `fixed_vulns_df` | `data.error is None`, `metrics["cold_start"] is True`, RAG strip is gray |
| Cold-start MoM (1 snapshot) | same | Single snapshot in `trend_snapshots` | Module renders notice, no `NaN%`, no crash |
| min_sample=5 sub-threshold | same | 3 Critical findings, 0 others | Critical renders "Insufficient data (3 findings — minimum 5 required)", no MTTR value |
| Owner cold start (new Owner in latest snapshot) | same | 2 snapshots; Owner "Ops" appears only in snapshot 2 | Owner series = `[None, 12.3]`; MoM delta = `None`; renders "N/A" |
| Owner vanished (absent from latest snapshot) | same | 2 snapshots; Owner "Ops" in snapshot 1 only | Owner omitted from current Owner table (last value is None) |
| Multiple snapshots same month — tie-break | same | 2 snapshots with `month="2026-06"`; different `generated_at` | Only latest `generated_at` snapshot used |
| pandas CoW compliance | all module tests | Any fixture | `pd.options.mode.copy_on_write = True` — zero `ChainedAssignmentError` |
| board_summary zero-diff | `tests/test_board_summary_baseline.py` (existing) | Standard board_summary synthetic fixtures | `compare_snapshots(actual, baseline) == []` |
| PII-clean fixtures | All test files | Check committed fixture content | No real hostnames, IPs, or plugin names; all RFC 6761/5737 |

**Quick run command:** `python -m pytest tests/test_mttr_trend_module.py -x`
**Full suite command:** `python -m pytest tests/ -x`

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `resurfaced_date` is populated on the live tenant for REOPENED findings (verified in Phase 15 plan 15-01 spot-check) | Open Item 3 | If not populated, the D-16-02 formula degrades to `(last_fixed - first_found).days` for all findings — criterion-3 fixture still passes, but live MTTR is not corrected for reopened findings |
| A2 | `generated_at` is always present in snapshot dicts (set in `trend_store.py` line 314) | Open Item 2 (tie-break) | If absent on a snapshot, lexicographic sort falls back to "last-encountered wins" — acceptable degradation, no crash |
| A3 | Owner tag names stored in `mttr_by_owner` JSON keys are aggregate/internal strings that do not constitute PII under `[[project_pii_rule_is_ai_not_email]]` | Open Item 1 | Owner tag values are internal corporate team names (e.g. "Engineering"); if they contain employee names or other PII, the PII rule would require a different storage approach |

---

## Sources

### Primary (HIGH confidence — direct codebase inspection)
- `data/trend_store.py` lines 222–392 — `capture_snapshot()` full signature, `new_entry` dict shape (lines 358–370), `read_trend()` return contract (lines 395–450)
- `reports/modules/mttr_by_severity_module.py` lines 160–265 — existing population filter, `days_to_fix` derivation (lines 190–222), overall mean (lines 282–286), `min_sample` default (line 161)
- `reports/modules/new_vs_remediated_module.py` lines 108–136 — `_month_label()` partial-month pattern; lines 247–260 — cold-start guard; lines 302–343 — per-snapshot iteration pattern
- `scripts/capture_trend_snapshot.py` lines 261–329 — aggregate count computation pattern, `fixed_vulns_df` fail-soft fetch, owner snapshot call with WR-03 exit semantics
- `data/fetchers.py` lines 347–361, 460–475, 1171–1175 — field availability (`resurfaced_date`, `last_fixed`, `first_found`, `time_taken_to_fix`) and UTC normalisation
- `tests/baseline_utils.py` lines 132–197 — `extract_structural_snapshot()` 12-key schema, `compare_snapshots()` contract
- `tests/baselines/board_summary_test_pull.json` — the three existing board_summary baseline files confirmed present
- `reports/composed_report.py` lines 81–99 — `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset (current members: `sc4_kwargs_stub`, `new_vs_remediated`, `vuln_density`, `accepted_recast`)

### Secondary (HIGH confidence — milestone research documents)
- `.planning/research/PITFALLS.md` Pitfall 3 — MTTR reopened inflation; Pitfall 9 — pandas CoW; criterion-3 fixture spec
- `.planning/research/SUMMARY.md` — zero-new-dependency verdict; "no scipy/statsmodels — sample-weighted MTTR mean is plain pandas"

---

## RESEARCH COMPLETE

**Phase:** 16 — MTTR Rework
**Confidence:** HIGH

### Key Findings

1. **Snapshot schema is a clean 3-field addition.** `mttr_overall_days` (float|null), `mttr_by_severity` (dict), `mttr_by_owner` (dict) follow the exact Phase 15 implicit-optional-field pattern. No schema versioning. Absent → cold-start. `capture_snapshot()` needs three new optional kwargs appended to `new_entry`.

2. **Duration clock is fully implementable from existing fetched fields.** `resurfaced_date`, `last_fixed`, and `first_found` are all fetched and UTC-normalised. The COALESCE vectorised pattern is straightforward. Criterion-3 fixture math validates to exactly 8 days.

3. **Owner-drift join uses a single forward-fill pass.** New Owner → back-fill `None` for prior months + valid series start. Vanished Owner → trailing `None`; omit from current table. Missing-month (sub-threshold) → render "—". Tie-break on same-month snapshots by `generated_at` descending.

4. **`min_sample_size` default is 5.** "Insufficient data (N findings — minimum 5 required)" is the standard render for sub-threshold severities and Owners. Zero overall → `_empty_result()`.

5. **Build order is strictly sequential (5 steps).** No parallel work needed. `mttr_by_severity_module.py` is byte-unchanged throughout. `run_all.py` untouched. Only four files change: `trend_store.py`, `capture_trend_snapshot.py`, `composed_report.py`, and the new `mttr_trend_module.py`.

6. **board_summary baseline re-capture is a zero-diff assertion, not a re-baseline.** The three existing `.json` files are expected to survive unchanged. Any diff is a regression signal.

### File Created
`.planning/phases/16-mttr-rework/16-RESEARCH.md`

### Confidence Assessment

| Area | Level | Reason |
|------|-------|--------|
| Snapshot schema | HIGH | Directly modelled on Phase 15 extension; `trend_store.py` source inspected line-by-line |
| Duration clock | HIGH | All fields confirmed fetched + normalised; criterion-3 arithmetic verified |
| Owner-drift mechanics | HIGH | Pattern derived from `new_vs_remediated_module.py` reference; all edge cases enumerated |
| min_sample default | HIGH | Confirmed in ROADMAP success criterion 5; existing module default inspected |
| Build order | HIGH | Dependency graph is linear; untouched-files list verified against all files that reference `mttr_by_severity` |
| Baseline mechanics | HIGH | `baseline_utils.py` and three existing baseline files directly inspected |

### Open Questions

None requiring user input. All six "Claude's Discretion" items are resolved above. The only build-time verification task is running the criterion-3 unit test against the synthetic fixture once the module is implemented.

### Ready for Planning
Research complete. Planner can now create PLAN.md files.
