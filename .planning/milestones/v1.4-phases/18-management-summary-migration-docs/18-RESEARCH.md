# Phase 18: management_summary Migration + Docs — Research

**Researched:** 2026-06-18
**Domain:** Python module migration (bespoke → ReportComposer pipeline), Tenable fixed-vuln fetch rework, trend-store backfill mechanics, smoke-baseline tooling, PDF chrome, DOC-02 runbooks
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-18-01:** Reconstruct-backfill ~12mo of history from Tenable (not cold-start, not JSON migration). Decoupled from cutover — runs and verifies first, then cutover reads a pre-seeded store.
- **D-18-02:** Fixed 12-month window: 2025-06 → now. Jun–Aug 2025 months carry a partial/approximate flag (retention taper edge).
- **D-18-03:** Provenance-marked, immutable reconstructed snapshots. `source` field: `"reconstructed"` vs `"captured"`. Reconstructed months never overwritten by later capture runs. Follows D-15-06/D-16-09/D-17-04 implicit-optional-field convention (no `schema_version`).
- **D-18-04:** Faithful partial backfill. `asset_count` is null on all reconstructed months (Tenable does not retain historical asset population). Vulnerability Density cold-starts for reconstructed months. No fabricated denominators.
- **D-18-05:** Bounded `last_fixed` fetch rework lands in Phase 18, before the cutover. Sized to the 12-month window, not unbounded. `fetch_fixed_vulnerabilities` (`data/fetchers.py` ~L410); consider same for `fetch_all_vulnerabilities` (~L284).
- **D-18-06:** Hard consumer-audit gate before widening the fetch. Every fixed-data consumer must apply its own explicit date window. MTTR keeps deliberate rolling-30 definition. No silent metric drift.
- **D-18-07:** Per-module auditor-reproducible runbooks following `docs/*_calculations.md` convention. Disclose: reconstructed month range + predicate, per-metric reconstructed-vs-cold-start split, rolling-30 MTTR intent, external-scope rule.
- **D-18-08:** One-time operator-run seeding script (`scripts/backfill_trend_reconstruction.py`). Idempotent (skips months already present). Forward capture cron continues unchanged.
- **D-18-09:** Overlap-test verification gate. Reconstruct a month for which a real captured snapshot exists and assert finding-derived fields match within stated tolerance. Fallback: reconstruct "today" and compare to live numbers.
- **D-18-10:** Full gate chain. Order: (1) bounded `last_fixed` fetch rework + consumer audit → (2) reconstruction seeding script + overlap-test → (3) smoke baseline from bespoke path → (4) migration cutover (atomic bespoke-path removal) → (5) runbooks. Smoke baseline may be Plan 01 (read-only, independent of 1/2); gates 1–3 all green before cutover.
- **D-18-11:** Archive, don't delete. Move `management_summary_*.json` to `data/trend/legacy_archive/`. Remove `_save_trend_snapshot()` at cutover.

### Claude's Discretion

- Reconstruction predicate mechanics (reuse `utils/open_count.py` `open_findings_at()` at past month-boundaries with fixed-data add-back).
- Exact overlap-test tolerance (D-18-09).
- Provenance field name + JSON shape (D-18-03).
- Archive dir path (D-18-11).
- Partial-month flag mechanics for earliest reconstructed months (D-18-02).
- Runbook file grouping (strict per-module vs tightly-grouped) within the per-module-reproducible decision (D-18-07).
- Whether the consumer audit (D-18-06) extracts a shared explicit-window helper or fixes each consumer in place.

### Deferred Ideas (OUT OF SCOPE)

- Widening the MTTR metric window (90-day / all-time MTTR) — metric design change, future phase.
- Reconstructing the Feb–Aug 2025 tail / full ~16mo.
- Persistent finding-mirror + differential-export architecture.
- Per-Owner SLA posture in snapshots.
- CLOSED items from the folded todo: `include_unlicensed`, asset-export licensing.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| GEN-01 | `management_summary` migrated from bespoke render path onto four-channel module contract; chrome-aware; no regression to existing delivery. | Sections: Bespoke Path Removal Surface, Migration Pattern (board_summary analog), Chrome-Awareness, Smoke Baseline Mechanics |
| QUAL-04 | GEN-01 cutover guarded by structural smoke baseline (before rewrite) + visual operator UAT; legacy trend writer removed in same change that routes reads through `read_trend()`. | Sections: Smoke Baseline Mechanics, Dual-Writer Prevention Pattern |
| DOC-02 | Auditor-facing calculation runbooks for each of the seven v1.4 modules: metric definition, data source, edge-case handling, disclosed MTTR window, external-scope rule. | Sections: Runbook Convention, Seven Module Definitions |
</phase_requirements>

---

## Summary

Phase 18 is the final and highest-risk phase of v1.4. It has three technically independent sub-problems that must execute in strict gate order: (1) a bounded `last_fixed` fetch rework + consumer-audit gate, (2) a 12-month trend reconstruction backfill seeded into the S1 store before the cutover, and (3) the atomic migration of `management_summary` from its ~2,200-line bespoke render path onto `ReportComposer.run_full_pipeline()` — plus the DOC-02 runbooks.

The highest-risk unknown was OD-8 (trend disposition). It is now locked as reconstruct-backfill (D-18-01). The retention premise of Spike-002 was wrong: the "~30-day fixed-findings wall" was an API default, not a platform purge. Real retention is ~15–16 months, retrievable via a bounded `last_fixed` parameter. This both enables the backfill and introduces a regression vector: widening the fetch changes the effective population of every existing fixed-data consumer. The consumer-audit gate (D-18-06) is a hard correctness bar, not optional cleanup.

The migration analog is `board_summary.py`, which has already been fully migrated onto `ReportComposer` (Phases 1–6). The seven management_summary modules all exist as registered `@register_module` classes. The structural smoke baseline pattern is proven via `scripts/smoke_board_summary_cutover.py` + `tests/baseline_utils.py`. All the planner needs is exact removal surface, wiring patterns, and reconstruction mechanics.

**Primary recommendation:** Plan the phase in five sequential gates matching D-18-10. Each gate is a separate plan (or set of tasks) with a hard green check before the next gate opens. Never entangle the 2,200-line atomic removal with reconstruction or fetch-rework work.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Bounded `last_fixed` fetch rework | Data layer (`data/fetchers.py`) | None | Single fetch point; all reports share parquet cache hit |
| Fixed-data consumer audit | Module layer (`mttr_trend_module.py`, `new_vs_remediated_module.py`) | Data layer audit | Consumers own their own window predicates |
| Trend reconstruction backfill | Script layer (`scripts/backfill_trend_reconstruction.py`) | Data layer (`data/trend_store.py`) | One-time seeding; store owns the write |
| Overlap-test verification | Script layer (`scripts/backfill_trend_reconstruction.py`) | None | Inline self-check on first run |
| Smoke baseline capture | Script layer (`scripts/smoke_management_summary_cutover.py`) | Test layer (`tests/baseline_utils.py`) | Structural read-only; pattern from board_summary smoke |
| `management_summary` migration | Report layer (`reports/management_summary.py`) | Composer (`reports/modules/composer.py`) | board_summary is the verified analog |
| Chrome-awareness | `run_all.py` (`_CHROME_AWARE_SLUGS`) | `reports/management_summary.py` (accept new kwargs) | Existing allowlist gate; management_summary must opt in AND accept the new kwargs |
| Calculation runbooks | `docs/` layer | None | DOC-02; follows existing `*_calculations.md` pattern |

---

## Standard Stack

No new packages are introduced in this phase. All work uses the existing locked stack (Python 3.10+, pandas, WeasyPrint, openpyxl, matplotlib, pyTenable). [VERIFIED: CLAUDE.md — "Zero new dependencies" cross-cutting constraint]

The parquet cache format, trend store JSON shape, and module auto-discovery machinery are all unchanged.

---

## Architecture Patterns

### System Architecture Diagram

```
Tenable API (fixed export)
        |
        | bounded last_fixed param (D-18-05)
        v
data/fetchers.py::fetch_fixed_vulnerabilities()
        |
        |-- [CACHE HIT] vulns_fixed.parquet
        |
        +----> consumer-audit gate (D-18-06) ----> each module owns explicit window
        |
        +----> backfill_trend_reconstruction.py (D-18-08, one-time)
                |
                | open_findings_at() at each past month-boundary
                | + fixed-add-back predicate (Spike-002 two-interval form)
                |
                v
        data/trend/trend_severity_all_assets.json
                |  [source="reconstructed", asset_count=null, immutable]
                |
        data/trend_store.py::read_trend()
                |
                v
        reports/management_summary.py::run_report()   (POST-CUTOVER)
                |
                v
        ReportComposer.run_full_pipeline()
                |  module_configs = [7 modules]
                |  trend_snapshots = read_trend() result
                |
                +---> assemble_pdf()       -> management_summary.pdf  (chrome header/footer)
                +---> assemble_excel()     -> management_summary.xlsx
                +---> assemble_email_body()-> email_body_html (non-empty -> build_email_body_modular())
                +---> assemble_analyst()   -> analyst workbook (optional)
```

### Recommended Project Structure (Phase 18 additions)

```
scripts/
├── smoke_management_summary_cutover.py   # new — structural smoke baseline
├── backfill_trend_reconstruction.py      # new — one-time seeding script (D-18-08)
data/trend/
├── trend_severity_all_assets.json        # S1 store — receives reconstructed + forward snapshots
├── legacy_archive/                       # new dir (D-18-11)
│   └── management_summary_all_assets.json  # archived legacy JSON
docs/
├── management_summary_calculations.md    # existing — extend with seven module runbooks (D-18-07)
reports/
└── management_summary.py                 # ~2,200 lines → migrated to ReportComposer pipeline
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Structural snapshot comparison | Custom diff logic | `tests/baseline_utils.extract_structural_snapshot()` + `compare_snapshots()` | Already proven by board_summary smoke; PII guard built in |
| Trend JSON write atomicity | Direct file.write() | `data/trend_store._atomic_write_json()` | Windows fd-close-before-replace safety; corrupt-file guard already wired |
| Open-at-date predicate | Naive `last_fixed IS NULL OR last_fixed > D` | `utils/open_count.open_findings_at()` | Drops ~19% REOPENED population without the two-interval form |
| Module registration | Manual registry calls | `@register_module` decorator + `registry.discover()` auto-import | Modules self-register on import; no `run_all.py` re-registration needed for individual modules |
| PDF chrome rendering | Custom header/footer HTML | `reports/modules/pdf_chrome.PdfChromeConfig` + `_CHROME_AWARE_SLUGS` gate | Shared design system; already wired into ReportComposer |
| Email routing | Slug-allowlist check | Bundle-driven `email_body_html` non-empty predicate | `build_email_body_modular()` is triggered by non-empty `email_body_html` in the return dict — no slug list needed |
| Idempotent snapshot write | Custom month-match loop | `capture_snapshot()` existing (month, tag_filter) idempotent-overwrite | Already handles same-month re-runs cleanly |

**Key insight:** Every architectural primitive this phase needs already exists and is tested. The planner's job is sequencing and wiring, not invention.

---

## Bespoke Path Removal Surface

[VERIFIED: codebase read]

The following functions in `reports/management_summary.py` must be removed atomically in the cutover commit (the commit that routes reads through `read_trend()`):

| Function | Lines (approx) | What it does | Replacement |
|----------|---------------|--------------|-------------|
| `_sanitise_tag_for_filename()` | ~128–149 | Builds legacy JSON filename suffix | Not needed — S1 store uses its own path convention |
| `_trend_file_path()` | ~152–163 | Returns `management_summary_{suffix}.json` path | Not needed post-cutover |
| `_load_trend_history()` | ~166–181 | Loads legacy JSON snapshots | Replaced by `data/trend_store.read_trend()` |
| `_save_trend_snapshot()` | ~184–249 | Writes legacy JSON trend snapshot | Removed; `capture_snapshot()` handles forward writes |
| `_compute_metric_1()` through `_compute_metric_7()` | ~257–764 | Bespoke per-metric compute functions | Replaced by seven registered modules via `ReportComposer` |
| `compute_all_metrics()` | ~772–896 | Aggregates all seven metrics | Replaced by `composer.run_all()` |
| `_build_age_bar_chart()` | ~1105–1151 | Matplotlib bar chart for M5 | Module owns its own chart rendering |
| `_build_trend_line_chart()` | ~1154–1194 | Two-line trend chart for M7 | Module owns its own chart rendering |
| `_build_pdf()` | ~1205–1779 | Bespoke WeasyPrint PDF builder | Replaced by `composer.assemble_pdf()` |
| `build_email_kpi_tiles()` | ~1793–1881 | Legacy KPI tile builder | Replaced by module `render_email_kpis()` |
| `build_email_body()` | ~1934–2135 | Bespoke HTML email assembler | Replaced by `composer.assemble_email_body()` (→ `email_body_html`) |
| `_email_preview_html()` | ~2138–2152 | CID→data-URI swap for preview | Can be kept or removed — no functional dependency |

**What stays:** `run_report()` signature (callers must not change), `REPORT_NAME`, `REPORT_SLUG`, module-level imports, `if __name__ == "__main__"` block (update to call new pipeline). The `_PDF_CSS`, `_AGE_BUCKETS`, `_OPEN_STATES` constants are consumed only by the deleted functions and go away with them.

**Current `run_report()` gaps to fill:** The current `run_report()` does not accept `privacy_label`, `scope_subtitle`, or `report_title` kwargs — these must be added in the cutover so `_CHROME_AWARE_SLUGS` injection works. Currently management_summary is excluded from `_CHROME_AWARE_SLUGS` precisely because it doesn't accept those kwargs (comment at run_all.py L94: "CHROME-COMPAT-01 — management_summary and ops_remediation MUST NOT receive privacy_label / scope_subtitle"). The cutover removes this constraint.

---

## Migration Pattern: board_summary as the Analog

[VERIFIED: codebase read of `reports/board_summary.py`]

`board_summary.py` is the only fully-migrated report and is the direct analog. The management_summary cutover must replicate this exact structure:

```python
# Pattern from board_summary.py — replicate for management_summary

_MGMT_MODULE_CONFIGS: list[ModuleConfig] = [
    ModuleConfig("total_vulns_by_severity"),
    ModuleConfig("scan_coverage_sla"),
    ModuleConfig("mttr_trend"),
    ModuleConfig("patch_compliance_rate"),
    ModuleConfig("aged_vulns_assets"),
    ModuleConfig("accepted_recast"),
    ModuleConfig("new_vs_remediated"),
]

def run_report(tio, run_id, *, tag_category=None, tag_value=None,
               output_dir=None, generated_at=None, cache_dir=None,
               privacy_label="Confidential", scope_subtitle=None,
               report_title=None, analyst_detail=True) -> dict:
    ...
    # 1. Fetch (vulns, assets, fixed_vulns) — parquet cache shared
    # 2. Apply tag filter
    # 3. Read trend snapshots: trend_snapshots = read_trend("severity", tag_filter)
    # 4. Build PdfChromeConfig
    # 5. Instantiate ReportComposer with module_configs + fixed_vulns_df + trend_snapshots kwarg
    # 6. results = composer.run_all()
    # 7. bundle = composer.run_full_pipeline(results, output_dir, slug="management_summary", ...)
    # 8. Render PDF (bundle["pdf_html"]), save Excel (bundle["excel_workbook"])
    # 9. Return standard dict with email_body_html, analyst_excel, email_inline_images
```

Key difference from board_summary: management_summary's seven modules all need `trend_snapshots` forwarded. This follows the `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset pattern from `composed_report.py`. The planner must add `"management_summary"` to the frozenset in `composed_report.py` if that file controls the gate, OR wire `trend_snapshots` directly in the new `management_summary.run_report()` by passing it via `**kwargs` to `ReportComposer` (matching how `composed_report.py` handles the `critical_remediation_sla` fixed-vulns gate).

**Concrete board_summary wiring to copy:**

```python
# Source: reports/board_summary.py ~L278-305 [VERIFIED]
pdf_chrome_cfg = PdfChromeConfig(
    title=effective_title, subtitle=resolved_subtitle,
    generated_at=generated_at, header_bg=HEADER_BG_COLOR,
    logo_path=LOGO_PATH, privacy_label=privacy_label,
)
composer = ReportComposer(
    vulns_df=vulns_df, assets_df=assets_df,
    report_date=generated_at, module_configs=_MGMT_MODULE_CONFIGS,
    fixed_vulns_df=fixed_vulns_df, pdf_chrome=pdf_chrome_cfg,
)
results = composer.run_all()
bundle = composer.run_full_pipeline(
    results, output_dir,
    slug="management_summary", report_date=generated_at,
    generate_analyst=analyst_detail,
    pdf_title=effective_title, pdf_subtitle=resolved_subtitle,
    scope_label=scope_label,
)
```

---

## Chrome-Awareness Pattern

[VERIFIED: codebase read of `run_all.py` L91–95, L719–728]

`_CHROME_AWARE_SLUGS` is a `frozenset` at `run_all.py:95`. Currently: `{"board_summary", "composed_report"}`.

The chrome injection block at `run_all.py:L719–728`:
```python
if slug in _CHROME_AWARE_SLUGS:
    report_kwargs["privacy_label"]  = privacy_label
    report_kwargs["scope_subtitle"] = scope_subtitle
    report_kwargs["report_title"]   = group_config.get("report_title")
```

**To add management_summary:**
1. Add `"management_summary"` to `_CHROME_AWARE_SLUGS` frozenset.
2. Add `privacy_label`, `scope_subtitle`, `report_title` kwargs to `management_summary.run_report()` signature.
3. Wire them into `PdfChromeConfig` construction (same as board_summary).
4. Remove the CHROME-COMPAT-01 comment exclusion.

**Frozenset membership test:** The existing test in `tests/test_run_all.py` (frozenset gate test) checks `_CHROME_AWARE_SLUGS` membership. Per project memory (`project_frozenset_gate_test_coupling`), adding a slug to a frozenset breaks the corresponding test until its hardcoded expected set is updated. The planner must include a task to update the frozenset test's expected set.

---

## Smoke Baseline Mechanics

[VERIFIED: codebase read of `scripts/smoke_board_summary_cutover.py`, `tests/baseline_utils.py`]

The board_summary smoke script is the proven template. The management_summary version (`scripts/smoke_management_summary_cutover.py`) must follow the same pattern:

**What `extract_structural_snapshot()` captures (from `tests/baseline_utils.py`):**
- Section/page counts (structural counts, not metric values)
- Module presence (which module IDs appear in results)
- RAG cell count (number of RAG strip entries)
- Email panel count (number of `<table role="presentation">` tags)
- Excel tab names (sorted list)
- Boolean flags (analyst workbook present, errors list non-empty)
- No metric values (drift daily — excluded per D-04-05)
- No row-level data (D-04-08 PII guard)

**Workflow (per smoke_board_summary_cutover.py docstring):**
1. Warm the cache: `python run_all.py --group "Management Summary Test" --no-email`
2. Run smoke script against today's parquet (no live API calls — `_NoLiveTenable` sentinel)
3. First run: baseline JSON written automatically, exits 0 with "BASELINE INITIALIZED"
4. Post-cutover run: diffs against committed baseline; structural drift exits 1

**Key constraint:** The smoke script must be committed (with its initial baseline JSON) BEFORE any migration code is written — this is the QUAL-04 requirement. The baseline captures the structural shape of the CURRENT bespoke output. After migration, the same script runs again and must pass.

**The `_bundle` private key pattern:** `board_summary.run_report()` returns a `_bundle` key (private, leading underscore) carrying the in-memory composer pipeline output. The smoke script uses `result["_bundle"]` to call `extract_structural_snapshot()` without re-parsing on-disk PDF/Excel. Management_summary's migrated `run_report()` should follow the same pattern.

---

## Trend Reconstruction Backfill Mechanics

[VERIFIED: CONTEXT.md, todos/pending/2026-06-18-pass-bounded-last-fixed-lookback-in-fixed-vuln-fetch.md, data/trend_store.py, utils/open_count.py]

### Bounded `last_fixed` Fetch Rework (D-18-05)

`fetch_fixed_vulnerabilities()` at `data/fetchers.py:L410` currently passes only `state` and `severity` to `tio.exports.vulns()`. This triggers the Tenable API default 30-day window.

Fix: add `last_fixed` filter to the export call:

```python
# Proposed pattern (D-18-05) — sized to 12-month window [ASSUMED exact param name]
from datetime import timedelta
lookback_date = (datetime.now(tz=timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%d")
export_filters = {
    "state":      ["fixed"],
    "severity":   ["critical", "high", "medium", "low"],
    "last_fixed": {"date": lookback_date, "modifier": "date-range"},  # verify exact API param shape
}
```

The exact `last_fixed` filter parameter shape must be verified against `ref/Retrieve Vulnerability Data from Vulnerability Management.md` (line 42 "Time-based Filters"). The empirical proof used a 2-year window (returned 1,285,823 rows vs 187,775 without filter); Phase 18 sizes to 12 months to bound the parquet cache bloat.

### Reconstruction Predicate

The reconstruction predicate for "what was open at month-boundary D?" is already implemented in `utils/open_count.open_findings_at(df, D)` — the two-interval reopened-aware form. [VERIFIED: codebase read]

For reconstruction, the input `df` must be constructed as:
- **Open findings:** `fetch_all_vulnerabilities()` result (state = open/reopened at run time)
- **Fixed-findings add-back:** any finding in `fetch_fixed_vulnerabilities()` where `last_fixed > D` was open at D

The two-interval predicate handles this correctly: a REOPENED finding is open at D if `(first_found <= D OR resurfaced_date <= D) AND NOT (last_fixed <= D AND resurfaced_date > D)`. The spike validated this form produces results within +2/160,453 of the true live count.

### Provenance Field (D-18-03)

Each reconstructed snapshot entry in `data/trend/trend_severity_all_assets.json` carries:
```json
{
  "month": "2025-09",
  "tag_filter": "all_assets",
  "critical": 1234,
  "high": 5678,
  "medium": 9012,
  "low": 3456,
  "asset_count": null,
  "source": "reconstructed",
  "reconstruction_predicate": "open_findings_at(vulns_df_at_run_time + fixed_add_back, month_end_D)",
  "generated_at": "2026-06-18T...",
  ...
}
```

The `source` field name follows the D-16-09 implicit-optional-field convention: absent → defaults to `"captured"` (cold-start branches treat missing field as captured). No `schema_version` field needed.

**Immutability rule:** The seeding script must check for an existing entry with `"month": month_str` before writing. If one exists with `"source": "reconstructed"`, skip it. If one exists with `"source": "captured"`, also skip it (captured ground truth is never overwritten by reconstruction). [ASSUMED: exact skip logic to implement]

### Partial-Month Flag for Taper Edge Months (D-18-02)

Jun–Aug 2025 months (the taper edge) should carry an additional flag:
```json
{
  "month": "2025-07",
  "source": "reconstructed",
  "partial": true,
  "partial_reason": "fixed-findings retention taper (≤Aug 2025 data under-represents true fixed count)"
}
```

This allows consumers and runbooks to disclose which months are approximate. [ASSUMED: field name "partial" — planner may choose differently within discretion]

### Consumer Audit Gate (D-18-06)

Fixed-data consumers that use ALL returned rows without their own time window will silently change behavior when the fetch widens from 30 days to 12 months:

| Module | Fixed-data usage | Window currently explicit? | Action needed |
|--------|-----------------|---------------------------|---------------|
| `mttr_trend_module.py` | `fixed_vulns_df` → rolling 30-day MTTR | YES — `mttr_window_days` default 30d filter applied at compute time [VERIFIED: docstring D-16-02] | Verify the rolling-30 filter is applied BEFORE groupby, not as a post-filter on the full 12-month pull |
| `new_vs_remediated_module.py` | `fixed_vulns_df` → monthly fixed outflow count | NEEDS VERIFICATION | Must filter `last_fixed` month == snapshot month — already does this in `capture_snapshot()` but verify the module itself doesn't aggregate ALL rows |
| `critical_remediation_sla_module.py` | `fixed_vulns_df` → % critical fixed within 15d | NEEDS VERIFICATION | Was designed for 30-day implicit window; widening to 12 months changes the population |
| `scan_coverage_sla_module.py` | Does NOT use `fixed_vulns_df` | N/A | No action |
| `accepted_recast_module.py` | Does NOT use `fixed_vulns_df` | N/A | No action |

The audit must confirm each consumer's date-windowing before widening the fetch. Result: either each module already has an explicit window (no drift) or the module needs a bounded filter added.

---

## Overlap-Test Verification (D-18-09)

The overlap test is the integrity gate for the reconstruction predicate:

**Happy path (a captured snapshot exists):**
1. Identify months that already have a `"source": "captured"` entry in `trend_severity_all_assets.json`.
2. Reconstruct those same months using the backfill predicate (do not write — compare only).
3. Assert: for each severity in {critical, high, medium, low}, `|reconstructed - captured| <= tolerance`.
4. Recommended tolerance: ≤ 2% relative difference OR ≤ 5 absolute findings (whichever is larger), matching the spike's "+2/160,453" empirical result. [ASSUMED: exact tolerance — within Claude's discretion per D-18-09]

**Fallback (no captured snapshot yet):**
1. Run reconstruction for the current month using today's data.
2. Compare to live `fetch_all_vulnerabilities()` open count for the same month.
3. Assert within the same tolerance.

The overlap test must be embedded in the seeding script itself — it runs automatically before writing any reconstructed months and exits non-zero if the tolerance check fails. This ensures the predicate is validated before committing 12 months of history.

---

## Seven Module Definitions (for Runbook Planning)

[VERIFIED: codebase — modules exist in reports/modules/ as registered classes]

The seven modules that replace the bespoke `_compute_metric_*` functions:

| Bespoke Metric | Module ID | Module File | Key Inputs |
|----------------|-----------|-------------|------------|
| Metric 1 — Total Vulns by Severity | `total_vulns_by_severity` | `total_vulns_by_severity_module.py` | `vulns_df` (open/reopened) |
| Metric 2 — Scan Coverage | `scan_coverage_sla` | `scan_coverage_sla_module.py` | `assets_df` |
| Metric 3 — MTTR | `mttr_trend` | `mttr_trend_module.py` | `fixed_vulns_df`, `trend_snapshots` |
| Metric 4 — Patch Compliance Rate | `patch_compliance_rate` | `patch_compliance_rate_module.py` | `vulns_df` |
| Metric 5 — Backlog Age Distribution | `aged_vulns_assets` | `aged_vulns_assets_module.py` | `vulns_df`, `assets_df` |
| Metric 6 — Exception/Recast Rate | `accepted_recast` | `accepted_recast_module.py` | `vulns_df`, `trend_snapshots` |
| Metric 7 — MoM Trend | `new_vs_remediated` | `new_vs_remediated_module.py` | `vulns_df`, `fixed_vulns_df`, `trend_snapshots` |

**Note on metric-module mapping:** Metrics 5 and 7 are the most semantically shifted. The bespoke Metric 5 was an age-bucket histogram; `aged_vulns_assets` is the closest equivalent (assets with aged vulns). The bespoke Metric 7 was a simple MoM delta of total open counts; `new_vs_remediated` provides the richer inflow/outflow trend. The runbooks must document the formula changes, not pretend these are identical. [ASSUMED: exact metric-module mapping — planner may adjust if module semantics differ after code review]

All seven modules are auto-discovered — `registry.discover()` runs on `import reports.modules`. No `run_all.py` registration needed for the individual modules.

**Modules needing `trend_snapshots` kwarg forwarded:**
- `mttr_trend` (MoM trend line)
- `new_vs_remediated` (MoM inflow/outflow)
- `accepted_recast` (MoM delta)
- Possibly others — verify each module's `compute()` signature for `**kwargs` consumption of `trend_snapshots`

---

## Runbook Convention (DOC-02)

[VERIFIED: codebase read of `docs/management_summary_calculations.md`]

The existing `docs/management_summary_calculations.md` follows this structure:
- Header: file, audience, outputs, schedule
- Table of contents
- Per-metric sections with: Calculation (exact formula), Data Source, Thresholds/Colors, Edge Cases
- Reference tables (SLA, gauge color zones)
- PDF Structure and Email Structure sections
- Trend Data Store section
- Troubleshooting

**Phase 18 runbooks must extend this file (or create per-module files) to add:**
1. For each of the seven v1.4 modules: exact formula with real field names, data source (which fetcher, which columns), reopened-aware predicate disclosure, cold-start branch behavior, empty-data guard behavior.
2. Reconstruction disclosure section: which months are reconstructed, the predicate used, `asset_count=null` for reconstructed months, per-metric reconstructed-vs-cold-start split.
3. Rolling-30 MTTR intent disclosure (D-18-06/D-18-07): explicitly state this is a "recent velocity" window, not a data limit.
4. External-scope rule (if applicable to any module's calculations).

**Runbook grouping decision (Claude's discretion):** Given the existing `management_summary_calculations.md` is already a single-file doc, the simplest approach is to extend it with a new "v1.4 Module Metrics" section rather than creating seven separate files. This avoids doc fragmentation while staying within the D-18-07 "per-module reproducible" bar. [ASSUMED: grouping choice — planner should confirm]

---

## Dual-Writer Prevention Pattern (QUAL-04)

The QUAL-04 requirement that the legacy trend writer is removed in the SAME commit that routes reads through `read_trend()` is the no-dual-writer-window rule. This means:

**Forbidden intermediate state:**
- `_save_trend_snapshot()` still present AND `capture_snapshot()` also running → two stores grow simultaneously

**Required atomic commit contents:**
1. Delete `_save_trend_snapshot()`, `_load_trend_history()`, `_trend_file_path()`, `_sanitise_tag_for_filename()` (the private bespoke trend helpers)
2. Add `from data.trend_store import read_trend, capture_snapshot` import
3. Replace `_compute_metric_7(trend_file, ...)` with `read_trend("severity", tag_filter)` call
4. Replace `_save_trend_snapshot(...)` at end of `run_report()` with `capture_snapshot(...)` call
5. Remove the call to `_trend_file_path()` and `_load_trend_history()` in `run_report()`

After this commit, `management_summary_*.json` files are never written to again. Only `trend_severity_*.json` files (the S1 store) accumulate going forward.

**Legacy JSON archival (D-18-11):** Move `data/trend/management_summary_*.json` to `data/trend/legacy_archive/` in the same commit or a cleanup commit immediately after.

---

## Common Pitfalls

### Pitfall 1: Widening the Fixed Fetch Without the Consumer Audit Gate
**What goes wrong:** `fetch_fixed_vulnerabilities()` now returns 12 months of data instead of 30 days. `critical_remediation_sla_module` computes "% critical fixed within 15 days" over ALL returned fixed rows — suddenly the denominator includes 12 months of fixed findings and the SLA% changes silently.
**Why it happens:** The module was written when the fetch returned only ~30 days implicitly. No explicit window filter was needed because the fetcher provided an implicit one.
**How to avoid:** Run the consumer audit (D-18-06) before committing the fetch rework. Test each consumer with synthetic 12-month fixed data and verify the output matches expectations.
**Warning signs:** SLA% metrics change by >5% with no data-quality explanation after the fetch rework.

### Pitfall 2: Reconstructed Snapshots Overwriting Captured Ones
**What goes wrong:** The backfill script runs on a server that already has a few months of captured snapshots. The script overwrites them with reconstructed values.
**Why it happens:** Missing immutability check in the seeding script.
**How to avoid:** Before writing each month, check if an entry with `"source": "captured"` exists for that month. If so, skip unconditionally. If a `"source": "reconstructed"` entry exists, also skip (immutable per D-18-03).
**Warning signs:** Captured months change their critical/high counts after the backfill script runs.

### Pitfall 3: Chrome kwargs Injected Before `run_report()` Signature Updated
**What goes wrong:** `management_summary` is added to `_CHROME_AWARE_SLUGS` but `run_report()` doesn't yet accept `privacy_label`, `scope_subtitle`, `report_title` kwargs → `TypeError: run_report() got an unexpected keyword argument`.
**Why it happens:** The frozenset and the signature are in different files and edited in different tasks.
**How to avoid:** Add kwargs to `run_report()` signature in the SAME commit that adds `"management_summary"` to `_CHROME_AWARE_SLUGS`.
**Warning signs:** `TypeError` on delivery group runs that include `management_summary`.

### Pitfall 4: Trend Snapshots Not Forwarded to Modules That Need Them
**What goes wrong:** Modules that require `trend_snapshots` (mttr_trend, new_vs_remediated, accepted_recast) receive an empty dict or None → cold-start branch fires even when 12 months of reconstructed history is present.
**Why it happens:** The `**kwargs` forwarding in `ReportComposer` requires the caller to pass `trend_snapshots` at construction time, following the `_MODULES_NEEDING_TREND_SNAPSHOTS` gate pattern in `composed_report.py`.
**How to avoid:** Explicitly pass `trend_snapshots=read_trend(...)` to `ReportComposer` constructor or `run_all()` kwargs, following the exact pattern used in `composed_report.py`.
**Warning signs:** MoM trend panels show cold-start messages even after 12 months of backfill are present.

### Pitfall 5: Dual-Writer Window from Partial Cutover
**What goes wrong:** `_save_trend_snapshot()` is removed in commit A, but the `_load_trend_history()` / `_trend_file_path()` helpers (reading the legacy JSON) are removed in commit B — between A and B the trend metric silently cold-starts because neither the old nor the new reader is wired.
**Why it happens:** Piecemeal removal rather than atomic removal.
**How to avoid:** The atomic commit must simultaneously: remove all legacy helpers, add the `read_trend()` call, and add the `capture_snapshot()` call. No partial state.
**Warning signs:** Metric 7 (MoM trend) shows first-run notice on first delivery after partial cutover.

### Pitfall 6: Smoke Baseline Written After Migration Code Exists
**What goes wrong:** The smoke baseline captures the migrated output instead of the bespoke output → the baseline does not serve as a regression guard because it was never compared against the bespoke structural shape.
**Why it happens:** Smoke script written late or merged after migration code.
**How to avoid:** The smoke script + its initial baseline JSON must be committed as the first commit of the phase (or at minimum before any changes to `management_summary.py` computation). This is the QUAL-04 contract.
**Warning signs:** Baseline JSON file has a `generated_at` timestamp after the first migration commit.

### Pitfall 7: `validate_config()` Contract Violation in Any New Module
**What goes wrong:** A module's `validate_config()` returns a `ModuleConfig` instead of `list[str]` → `composer.py` tries to join it → `TypeError` crashes every composed run.
**Why it happens:** Misread the contract; `validate_config` must return `list[str]` (empty = valid). Per project memory `project_validate_config_returns_error_list`.
**How to avoid:** If any new module-level code for Phase 18 adds a `validate_config()` method, return `[]` for valid or `["error message"]` for invalid. Never return a `ModuleConfig`.

---

## Code Examples

### capture_snapshot() with provenance field

```python
# Proposed backfill script pattern — writing one reconstructed month
# Source: data/trend_store.py capture_snapshot() signature [VERIFIED] + D-18-03 provenance extension [ASSUMED field]
from data.trend_store import _atomic_write_json, _load_trend_json, TREND_DIR
from utils.open_count import open_findings_at

def write_reconstructed_snapshot(
    vulns_df, fixed_vulns_df, month_date, tag_filter="all_assets", trend_dir=TREND_DIR
):
    file_path = trend_dir / f"trend_severity_{tag_filter}.json"
    snapshots = _load_trend_json(file_path)

    month_str = month_date.strftime("%Y-%m")
    # Immutability check (D-18-03)
    existing = next((s for s in snapshots if s.get("month") == month_str), None)
    if existing is not None:
        return  # Skip — never overwrite (captured or reconstructed)

    # Build reconstructed open set: open at month_date
    # Add back fixed-after-D findings: last_fixed > month_end_D
    month_end = month_date.replace(day=28)  # approximate month-end
    fixed_after_D = fixed_vulns_df[
        pd.to_datetime(fixed_vulns_df["last_fixed"], utc=True) > pd.Timestamp(month_end, tz="UTC")
    ]
    combined = pd.concat([vulns_df, fixed_after_D], ignore_index=True)
    open_df = open_findings_at(combined, month_end)

    sev_counts = open_df.groupby("severity").size().to_dict()
    is_taper_month = month_date < datetime(2025, 9, 1)

    entry = {
        "month": month_str,
        "tag_filter": tag_filter,
        "critical": int(sev_counts.get("critical", 0)),
        "high": int(sev_counts.get("high", 0)),
        "medium": int(sev_counts.get("medium", 0)),
        "low": int(sev_counts.get("low", 0)),
        "asset_count": None,  # D-18-04: not reconstructable
        "source": "reconstructed",
        "partial": is_taper_month,  # D-18-02
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    snapshots.append(entry)
    _atomic_write_json(file_path, {"snapshots": snapshots})
```

### read_trend() call in migrated run_report()

```python
# Source: data/trend_store.read_trend() [VERIFIED]
from data.trend_store import read_trend

tag_filter_label = f"{tag_category}_{tag_value}" if tag_category and tag_value else "all_assets"
trend_snapshots = read_trend("severity", tag_filter=tag_filter_label, months=13)
# Pass to ReportComposer via kwargs so modules receive it
```

### Adding management_summary to _CHROME_AWARE_SLUGS

```python
# Source: run_all.py L95 [VERIFIED]
# Before:
_CHROME_AWARE_SLUGS: frozenset[str] = frozenset({"board_summary", "composed_report"})
# After:
_CHROME_AWARE_SLUGS: frozenset[str] = frozenset({"board_summary", "composed_report", "management_summary"})
# Also update the corresponding expected set in tests/test_run_all.py frozenset membership test
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-----------------|--------------|--------|
| ~29-day fixed-retention "wall" (Spike-002 premise) | 30-day = API default only; real retention ~15–16mo via bounded `last_fixed` | 2026-06-18 | Enables 12mo reconstruction backfill; regression gate needed for all fixed-data consumers |
| `management_summary_*.json` private trend store | S1 store: `trend_severity_all_assets.json` (shared, tagged) | Phase 12 (2026-06) | S1 store serves all composed reports; management_summary must migrate to it |
| Bespoke `_compute_metric_*` + `_build_pdf()` | `ReportComposer.run_full_pipeline()` | Phase 1–6 for board_summary (2026-05) | All four-channel render contract channels, chrome, email routing via bundle |
| Chrome excluded for management_summary (CHROME-COMPAT-01) | management_summary added to `_CHROME_AWARE_SLUGS` | Phase 18 (this phase) | Header/footer band + `PdfChromeConfig` injection |
| Email routed via legacy `build_email_body()` | Bundle-driven `build_email_body_modular()` when `email_body_html` non-empty | Phase 2 (2026-05) | Non-empty `email_body_html` in return dict is the routing predicate |

**Deprecated/outdated:**
- `management_summary._save_trend_snapshot()`: removed at cutover; never write management_summary_*.json again.
- `management_summary._compute_metric_1()` through `_compute_metric_7()`: already partially delegating to modules (comments say "DEPRECATED" at L804, L815, L847) — the cutover completes this delegation and removes the wrapper functions.
- `management_summary.build_email_body()`: replaced by `email_body_html` bundle key.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The seven module IDs listed (total_vulns_by_severity, scan_coverage_sla, mttr_trend, patch_compliance_rate, aged_vulns_assets, accepted_recast, new_vs_remediated) correctly map to the bespoke Metric 1–7 semantics | Seven Module Definitions | Planner assigns wrong module to a metric → runbook documents wrong formula |
| A2 | The exact `last_fixed` Tenable API filter parameter shape is `{"date": "YYYY-MM-DD", "modifier": "date-range"}` | Bounded last_fixed Fetch Rework | Wrong filter shape → API error or no-op; must verify against ref/Retrieve Vulnerability Data |
| A3 | The provenance field name "source" and "partial" flag names are appropriate for the D-18-03/D-18-02 snapshot contract | Provenance Field | Any name is fine — within Claude's discretion; just must be consistent across seeding script, reader modules, and runbooks |
| A4 | Runbooks should extend `docs/management_summary_calculations.md` rather than create per-module files | Runbook Convention | If per-module files are preferred, seven new docs/ files needed instead |
| A5 | The overlap-test tolerance of ≤2% relative OR ≤5 absolute matches the spike's "+2/160,453" benchmark | Overlap-Test Verification | Tolerance too tight → test fails on legitimate drift; too loose → bugs pass undetected |
| A6 | `accepted_recast` and `new_vs_remediated` are the correct modules for Metrics 6 and 7 respectively | Seven Module Definitions | If wrong, smoke structural comparison will catch the mismatch via module presence check |

**If this table is empty:** Not empty — A1–A6 are low-to-medium risk assumptions the planner should verify against actual module code before finalizing plan tasks.

---

## Open Questions

1. **Does `composed_report.py`'s `_MODULES_NEEDING_TREND_SNAPSHOTS` gate apply to `management_summary`, or does `management_summary.run_report()` wire trend_snapshots directly?**
   - What we know: `composed_report.py` has `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset; `board_summary.run_report()` passes `fixed_vulns_df` directly to `ReportComposer` (not via the frozenset). Management_summary is its own slug, not a composed_report group.
   - What's unclear: whether management_summary should use the same direct-wiring pattern as board_summary or the frozenset gate pattern from composed_report.
   - Recommendation: Follow the board_summary analog — wire `trend_snapshots` directly in `management_summary.run_report()` by passing it to `ReportComposer` constructor, since management_summary is a fixed slug with known module requirements.

2. **Which exact months have captured snapshots today (for the overlap test)?**
   - What we know: `scripts/capture_trend_snapshot.py` has been running forward; some months likely have entries in `trend_severity_all_assets.json`.
   - What's unclear: how many captured months exist, which ones to use for the overlap test.
   - Recommendation: The backfill script should auto-detect captured months from the existing JSON and use the most recent captured month as the overlap test subject.

3. **Does the `critical_remediation_sla_module` need an explicit date window after the fetch is widened?**
   - What we know: It was designed for the implicit 30-day window. It consumes `fixed_vulns_df`.
   - What's unclear: whether its compute logic applies its own date filter (e.g. last_fixed within last 30 days) or aggregates all fixed rows.
   - Recommendation: Inspect `critical_remediation_sla_module.py` compute() before widening the fetch. Add this to the consumer-audit gate task checklist.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `data/trend_store.py` | Backfill script, migrated run_report | Yes — shipped Phase 12 | Current | None needed |
| `utils/open_count.open_findings_at()` | Reconstruction predicate | Yes — shipped Phase 12 | Current | None needed |
| `tests/baseline_utils.py` | Smoke script | Yes — shipped Phase 4 | Current | None needed |
| `reports/modules/composer.py ReportComposer` | Migration cutover | Yes — shipped Phase 1–2 | Current | None needed |
| `reports/modules/pdf_chrome.PdfChromeConfig` | Chrome wiring | Yes — shipped Phase 6 | Current | None needed |
| Tenable API (fixed export with `last_fixed` filter) | Fetch rework + reconstruction | Yes — empirically verified 2026-06-18 | 15–16mo retention confirmed | None needed |

**Missing dependencies with no fallback:** None.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (existing, see pytest.ini) |
| Config file | `pytest.ini` |
| Quick run command | `pytest tests/test_management_summary.py -x` (file to be created) |
| Full suite command | `pytest tests/ -x --ignore=tests/diagnose_*.py` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| GEN-01 | migrated run_report() returns non-empty email_body_html | smoke | `python scripts/smoke_management_summary_cutover.py` | No — Wave 0 |
| GEN-01 | seven modules present in bundle module_results | structural | `pytest tests/test_management_summary.py::test_module_presence -x` | No — Wave 0 |
| QUAL-04 | smoke baseline matches post-cutover structure | smoke | `python scripts/smoke_management_summary_cutover.py` | No — Wave 0 |
| QUAL-04 | no dual-writer: _save_trend_snapshot removed | unit | `pytest tests/test_management_summary.py::test_bespoke_functions_removed -x` | No — Wave 0 |
| DOC-02 | runbook files exist and have required sections | manual | Operator review | N/A — manual |
| D-18-06 | consumer audit: each fixed-data module has explicit date window | unit | `pytest tests/test_consumer_audit.py -x` | No — Wave 0 |
| D-18-09 | overlap test: reconstructed matches captured within tolerance | unit | `pytest tests/test_backfill_reconstruction.py::test_overlap -x` | No — Wave 0 |

### Wave 0 Gaps

- [ ] `scripts/smoke_management_summary_cutover.py` — structural smoke baseline script + initial baseline JSON
- [ ] `tests/test_management_summary.py` — module presence, email_body_html non-empty, no bespoke functions
- [ ] `tests/test_backfill_reconstruction.py` — overlap test, immutability check, partial flag
- [ ] `tests/test_consumer_audit.py` — verify each fixed-data consumer has explicit date window

---

## Security Domain

No new authentication, credential handling, or external-facing surfaces are introduced in this phase. The PII discipline (QUAL-05 / D-04-08) constraint applies to all reconstructed snapshot payloads:

- Snapshots store aggregate counts only: `{critical: int, high: int, ...}`
- `asset_count: null` on reconstructed months (not fabricated)
- No hostnames, IPs, plugin names, asset-level fields in any `data/trend/` file
- Legacy archive (`data/trend/legacy_archive/`) stays gitignored (same `.gitignore` rule as `data/trend/`)

---

## Sources

### Primary (HIGH confidence)

- `reports/management_summary.py` — full bespoke path read; exact removal surface documented
- `reports/board_summary.py` — migration analog; full wiring pattern read
- `data/trend_store.py` — `capture_snapshot()` / `read_trend()` full implementation read
- `utils/open_count.py` — `open_findings_at()` two-interval predicate read
- `run_all.py` — `_CHROME_AWARE_SLUGS`, `run_group()` chrome injection, `_REPORT_MODULE_MAP`
- `tests/baseline_utils.py` — `extract_structural_snapshot()` pattern
- `scripts/smoke_board_summary_cutover.py` — proven smoke script pattern
- `.planning/phases/18-management-summary-migration-docs/18-CONTEXT.md` — all 11 locked decisions
- `.planning/todos/pending/2026-06-18-pass-bounded-last-fixed-lookback-in-fixed-vuln-fetch.md` — empirical retention evidence
- `data/fetchers.py` — `fetch_fixed_vulnerabilities()` current implementation (no time filter)
- `reports/modules/mttr_trend_module.py` — rolling-30 window confirmation
- `reports/composed_report.py` — `_MODULES_NEEDING_FIXED_VULNS` frozenset pattern
- `docs/management_summary_calculations.md` — existing runbook format

### Secondary (MEDIUM confidence)

- `.planning/STATE.md` — OD-8 lock, cross-cutting constraints, frozenset gate test coupling warning
- `.planning/REQUIREMENTS.md` — GEN-01, QUAL-04, DOC-02 requirement text
- CLAUDE.md — zero new dependencies, fail-soft semantics, validate_config contract

---

## Metadata

**Confidence breakdown:**
- Bespoke path removal surface: HIGH — read all ~2,450 lines of management_summary.py
- Migration pattern (board_summary analog): HIGH — read full board_summary.py wiring
- Chrome-awareness: HIGH — read _CHROME_AWARE_SLUGS gate in run_all.py
- Reconstruction mechanics: HIGH (predicate verified) / MEDIUM (exact API filter param shape needs ref doc verification)
- Consumer audit gap: MEDIUM — modules identified; individual compute() bodies need targeted review
- Smoke baseline pattern: HIGH — read baseline_utils.py and smoke_board_summary_cutover.py
- DOC-02 runbook convention: HIGH — read existing management_summary_calculations.md

**Research date:** 2026-06-18
**Valid until:** 2026-07-18 (stable codebase; 30-day window before trending data or API behavior may drift)
