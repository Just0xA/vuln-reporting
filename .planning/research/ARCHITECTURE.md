# Architecture Research

**Domain:** v1.4 Management Summary Reporting Improvement — module/composer/run_all integration
**Researched:** 2026-06-11
**Confidence:** HIGH (derived entirely from direct source inspection)

---

## Integration Question 1: New Shared Substrates

Two new shared substrates emerge from the v1.4 feature set. Neither belongs inside a module file. Both mirror existing substrate placement conventions.

### Substrate A: Asset-Count Denominator (`utils/asset_count.py`)

**What it does:** Returns total licensed asset count (and optionally per-scope count) for Vulnerability Density's vulns-per-asset MoM computation. Asset totals must be taken from `assets_df`, not re-fetched; the run-scoped parquet cache already holds `assets_df` by the time any module runs.

**Where it lives:** `utils/asset_count.py` — mirrors `utils/open_count.py` (pure compute, no I/O, no network). A single function `asset_count(assets_df) -> int` counting non-null licensed assets. This is the only safe placement: modules must not do I/O inside `compute()`, and the denominator logic is reusable across Density and Program Health.

**How modules consume it:** The module calls `asset_count(assets_df)` directly inside `compute()` — `assets_df` is already a parameter of `compute()`. No new kwargs forwarding is needed for this substrate.

**What stays untouched:** `data/fetchers.py`, `data/trend_store.py`, `composed_report.py`, `run_all.py`.

### Substrate B: External-Scope Helper (`utils/external_scope.py`)

**What it does:** Classifies assets as external-scope when they carry `Location=External` or `Location=DMZ` tag OR have a computed public IPv4 (non-RFC1918). Emits a mismatch list (public-IP-but-untagged / tagged-but-private) as analyst exceptions — the same shape as `extract_owner()`'s `Unassigned` catch-all in `utils/tag_helper.py`.

**Where it lives:** `utils/external_scope.py` — mirrors the S2 substrate (`extract_owner()` lives in `utils/tag_helper.py`). Pure compute; accepts `assets_df`, returns `(scoped_assets_df, mismatches_df)`.

**RFC1918 check:** A small pure helper `is_public_ipv4(ip_str) -> bool` using `ipaddress.ip_address()` with a try/except; no new dependency.

**How modules consume it:** Called directly inside the External/DMZ module's `compute(assets_df, ...)` — `assets_df` already arrives via the composer. No kwargs forwarding needed.

**Mismatch list routing:** The `mismatches_df` is returned in `ModuleData.analyst_rows` as a `("External Scope Mismatches", df)` tuple — exactly the pattern used by the Owner Supplemental analyst tab (`reports/owner_supplemental.py`).

**What stays untouched:** No changes to `composed_report.py`, `run_all.py`, or `ReportComposer`.

---

## Integration Question 2: Data Flows and kwargs Forwarding

The composer's `**kwargs` pass-through is the key seam. `ReportComposer.__init__` stores `self._kwargs = kwargs`, and `run_module` calls `instance.compute(..., **self._kwargs)`. `composed_report.py` gates conditional kwargs into `composer_kwargs` before constructing `ReportComposer`, using frozenset membership checks (`_MODULES_NEEDING_FIXED_VULNS`, `_MODULES_NEEDING_ENV_TOTAL`).

### Modules and their data requirements

| Module | Data beyond vulns_df / assets_df | New kwargs gate needed? |
|--------|----------------------------------|-------------------------|
| New vs Remediated | `read_trend()` result | YES — `trend_snapshots` kwarg |
| Vulnerability Density | `asset_count(assets_df)` inline + `read_trend()` | YES — `trend_snapshots` kwarg |
| Reopened Vulnerabilities | `vulns_df` state/resurfaced_date columns (already present) | NO |
| Accepted & Recast | `vulns_df` severity_modification_type (already present); `fetch_recast_rules()` for analyst tab | YES — `recast_rules_df` kwarg |
| Program Health Overview | `read_trend()` + `extract_owner()` inline from assets_df | YES — `trend_snapshots` kwarg |
| MTTR rework | `fixed_vulns_df` (existing gate) + `read_trend()` for trend | `fixed_vulns_df` already gated; YES for `trend_snapshots` |
| External/DMZ | `external_scope(assets_df)` inline | NO |
| GEN-01 modules | same as existing metrics — covered by existing gates | depends on metric (see below) |

### The `trend_snapshots` kwarg pattern

Three or more new modules need pre-read trend history. The clean implementation adds one new gate in `composed_report.py`, following the exact pattern of `_MODULES_NEEDING_FIXED_VULNS` (lines 73–79) and `_MODULES_NEEDING_ENV_TOTAL` (lines 79–80):

```python
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "new_vs_remediated",
    "vuln_density",
    "program_health_overview",
    "mttr_trend",       # reworked MTTR, new MODULE_ID
    # extend as modules are added
})

need_trend = bool(_MODULES_NEEDING_TREND_SNAPSHOTS.intersection(modules))
if need_trend:
    from data.trend_store import read_trend  # noqa: PLC0415
    composer_kwargs["trend_snapshots"] = read_trend(
        dimension="severity",
        tag_filter=_log_scope,
        months=13,
    )
```

`composed_report.py` is the only file that changes for this gate. `run_all.py` does not change — it already passes `modules` through to `composed_report.run_report()` via `report_kwargs`. `ReportComposer` does not change — `**self._kwargs` already fans out to every `compute()` call.

### The `recast_rules_df` kwarg pattern

Accepted & Recast's analyst drill-down needs `fetch_recast_rules()`. This follows the `fixed_vulns_df` gate exactly:

```python
_MODULES_NEEDING_RECAST_RULES = frozenset({"accepted_recast"})

need_recast = bool(_MODULES_NEEDING_RECAST_RULES.intersection(modules))
if need_recast:
    from data.fetchers import fetch_recast_rules  # noqa: PLC0415
    composer_kwargs["recast_rules_df"] = fetch_recast_rules(tio, cache_dir)
```

`fetch_recast_rules()` already exists in `data/fetchers.py` (POST `/v1/recast/rules/search`). No new fetcher needed.

### What does NOT need new forwarding

- **Reopened Vulnerabilities:** `state` and `resurfaced_date` are already present on `vulns_df` from `fetch_all_vulnerabilities`. The module filters `vulns_df[vulns_df["state"].str.upper() == "REOPENED"]` directly inside `compute()`.
- **Vulnerability Density asset count:** `assets_df` is already a `compute()` parameter; `asset_count(assets_df)` is an inline call with no I/O.
- **External/DMZ scope:** `assets_df` already carries tag and IP fields; `external_scope(assets_df)` is inline pure compute.

### Summary of composed_report.py changes

Two new frozensets and two new conditional fetch blocks (~25–30 lines total). The `run_report()` function signature does not change. All new kwargs arrive at modules via the existing `**self._kwargs` fan-out.

---

## Integration Question 3: GEN-01 Migration Shape

### What GEN-01 means in code

`management_summary.py` today owns a bespoke render path: `compute_all_metrics()` delegates metrics 1, 3, 4 to existing modules (via `_module_registry.get()`), computes metrics 2, 5, 6, 7 inline, then drives a private PDF builder and Jinja2 email body. The file is approximately 2,200 lines. GEN-01 replaces this with a `ReportComposer`-driven pipeline identical to `board_summary.py`.

### Module decomposition

| management_summary metric | Module | Status |
|---------------------------|--------|--------|
| Metric 1 — Total Vulns by Severity | `total_vulns_by_severity` | Already exists; already called via `_module_registry.get()` in `compute_all_metrics()`. No new module needed. |
| Metric 2 — Scan Coverage | `scan_coverage_sla` | Already exists (`scan_coverage_sla_module.py`). No new module needed. |
| Metric 3 — MTTR by Severity | `mttr_trend` (rework) | Existing `mttr_by_severity` replaced/extended with the v1.4 rework: disclose ~30d window, sample-weight, reopened-aware, trend + Owner. New `MODULE_ID = "mttr_trend"` avoids conflicting with existing board_summary references to `mttr_by_severity`. |
| Metric 4 — Patch Compliance Rate | `patch_compliance_rate` | Already exists. No new module needed. |
| Metric 5 — Backlog Age Distribution | `aged_vulns_assets` | Already exists (`aged_vulns_assets_module.py`). No new module needed. |
| Metric 6 — Exception & Risk Acceptance Rate | `accepted_recast` | New module. Supersedes `_compute_metric_6()` and extends it with prev-month delta and Owner cut. |
| Metric 7 — Vulnerability Reduction Trend | `new_vs_remediated` | New module. Supersedes `_compute_metric_7()` (private trend JSON reader) by consuming `trend_store.read_trend()` via the `trend_snapshots` kwarg gate. |

Five of the seven metrics already have modules. GEN-01 requires two new modules (`accepted_recast`, `new_vs_remediated`) plus the MTTR rework, then replaces `management_summary.py`'s bespoke path with a `ReportComposer` pipeline.

### What the migrated management_summary.py looks like

After GEN-01, `management_summary.py:run_report()` becomes structurally identical to `board_summary.py:run_report()`:

1. Fetch `vulns_df`, `assets_df`, `fixed_vulns_df` (already done today)
2. Apply tag filter (already done today)
3. Read trend snapshots via `read_trend()` — replaces `_load_trend_history()`
4. Construct `ReportComposer(vulns_df, assets_df, ..., module_configs=_MGMT_MODULE_CONFIGS, **composer_kwargs)` where `composer_kwargs` carries `fixed_vulns_df`, `trend_snapshots`, `recast_rules_df`
5. Call `composer.run_full_pipeline(...)` and return the standard board-shaped bundle

The bespoke `_build_pdf()`, `_compute_metric_*()` functions, and private Jinja2 path become dead code after cutover and are removed.

`management_summary` is added to `_CHROME_AWARE_SLUGS` in `run_all.py` (one-line change) so it inherits the chrome header/footer post-migration. CHROME-COMPAT-01 (the hard contract that `management_summary` MUST NOT receive chrome kwargs while on the legacy path) inverts after GEN-01: once migrated, it MUST be in `_CHROME_AWARE_SLUGS`.

### Backward-compat mechanism

This is the v1.0 board_summary cutover pattern verbatim:

1. Capture smoke baselines from the current bespoke output before migration — `scripts/smoke_management_summary_cutover.py` (new script, mirrors `scripts/smoke_board_summary_cutover.py`).
2. Execute the migration.
3. Run smoke against the new output: structural shape (section count, RAG cell count, metric presence) must match; metric values are NOT locked (they shift with live data — D-04-05 decision).
4. Visual operator UAT: open both PDFs side by side, confirm all seven metric sections present.
5. Existing `delivery_config.yaml` groups referencing `management_summary` continue to work unchanged — `run_all.py` slug registration (`_VALID_REPORTS`, `_REPORT_MODULE_MAP`) does not change.

The private trend JSON files (`data/trend/management_summary_*.json`) are read-only legacy after migration. New modules write to `data/trend/trend_*.json` via `data/trend_store.py`. No migration of the old JSON files is needed — `management_summary`'s Metric 7 trend history accumulates independently of the new S1 store, and `new_vs_remediated` starts its own forward-accumulating history from first execution.

---

## Integration Question 4: Build Order

Dependencies flow strictly in one direction: substrates must be stable before consuming modules; GEN-01 dependency modules must be stable before the cutover.

```
Stage 1 — New shared substrates (no module dependencies, ~1 hour each)
  utils/asset_count.py          pure asset-count denominator
  utils/external_scope.py       external-scope classifier + mismatch emitter

Stage 2a — composed_report.py gate additions (unblocks trend/recast modules)
  Add _MODULES_NEEDING_TREND_SNAPSHOTS frozenset + fetch block
  Add _MODULES_NEEDING_RECAST_RULES frozenset + fetch block
  ~25 lines; can land as single commit; dependency: data/trend_store.read_trend() (already shipped)

Stage 2b — New modules (each independent; can be phased or batched)
  reopened_vulns_module.py          no new deps; good first module to validate new data shapes
  external_dmz_module.py            depends on Stage 1 (external_scope)
  accepted_recast_module.py         depends on Stage 2a (recast_rules_df kwarg)
  new_vs_remediated_module.py       depends on Stage 2a (trend_snapshots kwarg); also GEN-01 dep
  vuln_density_module.py            depends on Stage 1 (asset_count) + Stage 2a (trend_snapshots)
  program_health_overview_module.py depends on Stage 2a (trend_snapshots)
  mttr_trend_module.py              depends on Stage 2a (trend_snapshots); also GEN-01 dep

Stage 3 — GEN-01 migration (depends on Stages 1-2; specifically needs
          new_vs_remediated, accepted_recast, mttr_trend from Stage 2b)
  scripts/smoke_management_summary_cutover.py  (baseline capture — MUST land before rewrite)
  reports/management_summary.py rewrite        (replace bespoke path with ReportComposer)
  run_all.py: add management_summary to _CHROME_AWARE_SLUGS
  Visual operator UAT

Stage 4 — Registration (only if new modules exposed as standalone slugs)
  run_all.py _VALID_REPORTS + _REPORT_MODULE_MAP (per slug)
  delivery_config.schema.yaml enum additions (per slug)
  CLAUDE.md YAML Schema Rules additions (per slug)
  NOTE: modules consumed only via composed_report or management_summary
        need NO registration changes — auto-discovery handles them
```

### Practical sequencing guidance

Stages 1 and 2a are small (a few hundred lines combined) and unblock everything else. Build them in a single phase. Stage 2b modules are independent of each other and can be distributed across phases. Stage 3 (GEN-01) is the riskiest delivery item — schedule it as its own phase with the smoke-baseline-capture commit as a mandatory pre-step before any rewrite begins.

Reopened Vulnerabilities has no trend or substrate dependency and is a good first Stage 2b module to validate the four-channel contract against new data shapes before trend-dependent modules land.

---

## Component Responsibility Table: New vs Modified vs Untouched

| Component | v1.4 Status | Change Description |
|-----------|-------------|--------------------|
| `utils/asset_count.py` | NEW | Pure asset-count denominator substrate |
| `utils/external_scope.py` | NEW | External-scope classifier + mismatch emitter |
| `reports/modules/new_vs_remediated_module.py` | NEW | Monthly new/remediated trend; consumes `trend_snapshots` kwarg |
| `reports/modules/vuln_density_module.py` | NEW | Vulns/asset MoM; consumes `asset_count()` + `trend_snapshots` |
| `reports/modules/reopened_vulns_module.py` | NEW | Reopened state / resurfaced_date tracker |
| `reports/modules/accepted_recast_module.py` | NEW | Exception posture + prev-month delta + Owner cut; consumes `recast_rules_df` |
| `reports/modules/program_health_overview_module.py` | NEW | MoM velocity across totals + Owner cut; consumes `trend_snapshots` |
| `reports/modules/mttr_trend_module.py` | NEW | MTTR rework (window disclosure, sample-weight, reopened-aware, trend, Owner) |
| `reports/modules/external_dmz_module.py` | NEW | External exposure cut; consumes `external_scope()` |
| `scripts/smoke_management_summary_cutover.py` | NEW | Baseline-capture + structural regression harness for GEN-01 UAT |
| `reports/composed_report.py` | MODIFIED (minor) | +2 frozensets + 2 conditional fetch blocks (~25 lines); function signature unchanged |
| `run_all.py` | MODIFIED (minor, GEN-01 only) | Add `management_summary` to `_CHROME_AWARE_SLUGS` post-GEN-01; no new slug registration needed for module-only additions |
| `reports/management_summary.py` | MODIFIED (GEN-01) | Replace bespoke `_compute_metric_*` + `_build_pdf()` + private Jinja2 path with `ReportComposer` pipeline |
| `reports/modules/mttr_by_severity_module.py` | UNTOUCHED | Existing module kept; rework ships as `mttr_trend` with new MODULE_ID to avoid breaking existing board_summary module lists |
| `reports/modules/total_vulns_by_severity_module.py` | UNTOUCHED | Consumed by GEN-01 without change |
| `reports/modules/scan_coverage_sla_module.py` | UNTOUCHED | Consumed by GEN-01 without change |
| `reports/modules/patch_compliance_rate_module.py` | UNTOUCHED | Consumed by GEN-01 without change |
| `reports/modules/aged_vulns_assets_module.py` | UNTOUCHED | Consumed by GEN-01 without change |
| `reports/modules/composer.py` | UNTOUCHED | `**self._kwargs` fan-out already handles new kwargs; no changes |
| `reports/modules/base.py` | UNTOUCHED | Contract is stable |
| `data/trend_store.py` | UNTOUCHED | `read_trend()` is the consumption API; no changes needed |
| `utils/open_count.py` | UNTOUCHED | Already used by `data/trend_store.capture_snapshot`; available to modules if needed |
| `utils/tag_helper.py` (`extract_owner`) | UNTOUCHED | Used inline by Owner-cut modules |
| `run_all.py` `_VALID_REPORTS` / `_REPORT_MODULE_MAP` | UNTOUCHED | New v1.4 features are modules, not new top-level slugs; no registration needed |
| `delivery_config.schema.yaml` | UNTOUCHED | No new slugs; schema enum unchanged |
| `data/fetchers.py` | UNTOUCHED | `fetch_recast_rules()` already present; no new fetchers needed |

---

## Data Flow: v1.4 composed_report execution path

```
run_all.py run_group()
  slug == "composed_report"
  report_kwargs["modules"] = ["new_vs_remediated", "vuln_density", ...]
        |
        v
composed_report.run_report(tio, run_id, modules=[...], ...)
        |
        +-- fetch_all_vulnerabilities(tio, cache_dir)    [CACHE HIT after pre-fetch]
        +-- fetch_all_assets(tio, cache_dir)             [CACHE HIT]
        +-- fetch_fixed_vulnerabilities(...)             [if mttr_trend or critical_remediation_sla]
        +-- fetch_recast_rules(...)                      [if accepted_recast in modules]  (NEW gate)
        +-- read_trend(dimension, tag_filter, months=13) [if trend-dependent modules]     (NEW gate)
        |
        +-- apply tag filter to vulns_df, assets_df, fixed_vulns_df
        |
        +-- ReportComposer(
        |       vulns_df, assets_df, report_date,
        |       module_configs=[ModuleConfig(mid) for mid in modules],
        |       fixed_vulns_df=...,         [existing gate]
        |       env_vuln_total=...,         [existing gate]
        |       trend_snapshots=...,        [NEW gate]
        |       recast_rules_df=...,        [NEW gate]
        |   )
        |
        +-- composer.run_all()
        |     for each module:
        |       instance.compute(
        |           vulns_df, assets_df, report_date, config,
        |           **self._kwargs   <- trend_snapshots / recast_rules_df arrive here
        |       )
        |
        +-- composer.run_full_pipeline(...)
              -> pdf_html, excel_workbook, analyst_workbook_path,
                 email_body_html, email_inline_images
```

---

## Key Architectural Constraints for v1.4 Modules

**Empty-data guard is mandatory.** Filtered-to-zero groups happen routinely. Every `compute()` must call `self._empty_result(msg, config)` on zero-row inputs. Never inline `f"{value:.1f}"` on metrics that can be None — use `safe_pct` / `safe_int` / `safe_format` from `reports.modules.format_utils`.

**compute() is pure.** No file writes, no API calls, no mutations of input DataFrames. `trend_snapshots` arrives as a pre-read dict via kwargs; the module does not call `read_trend()` itself. `asset_count()` and `external_scope()` are pure compute helpers — calling them inside `compute()` is correct.

**MODULE_ID namespace.** New MODULE_IDs must not collide with existing ones. The MTTR rework uses `mttr_trend` (not `mttr_by_severity`) so existing board_summary groups that list `mttr_by_severity` are unaffected.

**Chrome inheritance.** New modules delivered via `composed_report` inherit chrome automatically. GEN-01's migrated `management_summary` inherits chrome by being added to `_CHROME_AWARE_SLUGS` — no per-module chrome work needed.

**Analyst rows and PII (D-04-08).** Analyst tabs may contain asset-level data (IPs, hostnames for External/DMZ mismatch list, Owner assignments). This data must never appear in committed baselines, test fixtures, or AI conversation context. The mismatch list ships as `analyst_rows` only — it does not appear in `summary_text` or `driver_narrative`.

---

## Sources

All findings derived from direct code inspection (confidence HIGH):

- `reports/composed_report.py` — kwargs gate pattern, `_MODULES_NEEDING_FIXED_VULNS` / `_MODULES_NEEDING_ENV_TOTAL`
- `run_all.py:680-729` — slug-specific extras block, `_CHROME_AWARE_SLUGS` gate
- `reports/modules/composer.py:425-596` — `ReportComposer.__init__`, `run_module`, `**self._kwargs` fan-out
- `reports/modules/base.py` — four-channel contract, `_empty_result()`
- `reports/management_summary.py:772-896` — `compute_all_metrics()`, metrics 1-7 inline vs module-delegated
- `utils/open_count.py` — S1 substrate shape (pure compute, no I/O)
- `data/trend_store.py` — S1 snapshot engine, `read_trend()` API
- `.planning/notes/report-requests-batch-2026-06.md` — substrate analysis, GEN-01 entanglement note
- `.planning/PROJECT.md` — v1.4 scope, WAS deferral decision, constraint list

---

*Architecture research for: v1.4 Management Summary Reporting Improvement integration*
*Researched: 2026-06-11*
