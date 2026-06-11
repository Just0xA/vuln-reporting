# Phase 12: Trend Snapshot Substrate (S1) - Context

**Gathered:** 2026-06-06
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver the **canonical open-count primitive** (`open_findings_at`) and a **forward-accumulating monthly snapshot engine** (`capture_snapshot` / `read_trend`) that begins building trend history in the existing `data/trend/` store. This is the keystone substrate (S1) for the v1.4 report batch — it must be reusable, unit-tested, PII-safe, idempotent, and cron-driven.

**In scope:** TREND-01..07 — the reopened-aware predicate, the snapshot capture/read engine, atomic + idempotent writes, cold-start-safe reads, PII-aggregate-only payloads, and a cron-friendly entry point. Phase 12 captures the **severity dimension for `all_assets`** only.

**Out of scope (this phase):** Owner/BU segmentation (Phase 13 — SEG-01..05), the calculations runbook (Phase 13 — DOC-01), all v1.4 report modules, and any flow/remediation-rate metrics.

</domain>

<decisions>
## Implementation Decisions

### Module placement & `management_summary` refactor
- **D-01:** Build the substrate as a **new shared module; leave `management_summary.py`'s private trend helpers (`_save_trend_snapshot`, `_load_trend_history`) exactly as-is.** Zero regression risk to TREND-03's byte-for-byte bar. Minor duplication is accepted; full `management_summary` migration onto the substrate stays **GEN-01** (already a v1.4 backlog item).
- **D-02:** `open_findings_at()` lives in **`utils/`** (pure compute, no I/O — same layer convention as `utils/sla_calculator.py`). The snapshot capture/read engine lives in **`data/`** (does I/O, alongside `data/fetchers.py` and the `data/trend/` store). Planner picks exact filenames.

### Snapshot store shape
- **D-03:** **File-per-dimension, flat counts.** `data/trend/trend_{dimension}_{tagsuffix}.json`. Each snapshot entry keeps the **existing flat per-entry shape** (`month`, `tag_filter`, `<count keys>`, `generated_at`) so it stays in the same shape *family* as `management_summary` — satisfying TREND-03's "no parallel store, same shape" while the substrate **owns its own files** (consistent with D-01). The severity file uses `critical`/`high`/`medium`/`low` keys identical to MS. New dimensions (type/owner, Phase 13) get their own files and never touch existing ones.
- **D-04:** Each snapshot entry **also records in-scope `asset_count`** (aggregate, PII-safe). This makes asset-churn *visible* in the trend (open dropped but asset_count dropped → churn, not remediation) and captures the denominator the v1.4 Vuln Density report needs but cannot backfill. This is the one churn-motivated payload addition; it stays within "aggregate counts only" (TREND-06).
- **D-05:** **`read_trend()` reads only the substrate's own files** (derived consequence of D-01/D-04). Because the substrate shape carries `asset_count` that MS's files lack, merge-reading MS history would produce ragged rows. Cold-start therefore begins at the substrate's first snapshot — consistent with the locked snapshot-not-reconstruction constraint. (Revisit only if a longer day-one series is later required.)

### Asset churn / metric validity (raised during discussion)
- **D-06:** **Open-count stays the primitive; no substrate-level de-duplication.** A rebuilt asset's re-detected findings (new UUID) are genuinely open *right now*, so counting them in a point-in-time stock is correct. Cross-UUID / stable-asset-key normalization is a report-layer concern, deferred to v1.4.
- **D-07:** **Churn is an inherent property of all stock-based VM trend metrics**, not a flaw in the snapshot approach (and reconstruction would be *strictly worse* on churn due to survivorship). The "was this drop real remediation or did assets leave?" question is answered by **flow metrics** = the deferred v1.4 New-vs-Remediated report, which this substrate feeds. The stock-vs-flow churn caveat is documented in **DOC-01 (Phase 13)**.

### Data source & entry point
- **D-08:** **`capture_snapshot` is df-injected and pure-ish:** it receives `df` (open+reopened findings) and `assets_df`, computes counts, and writes atomically. Keeps the open-count primitive unit-testable against labelled fixtures (TREND-01 requirement). The **entry-point script does the fetching**, reusing existing fetchers + the date-named `data/cache/` parquet store (the `scripts/warm_cache.py` pattern). Clean compute/I-O split per project conventions.
- **D-09:** **Standalone cron entry point: `scripts/capture_trend_snapshot.py`**, mirroring `scripts/warm_cache.py` (cron-friendly exit codes, logged). Phase 12 captures the **`all_assets` severity snapshot** (canonical whole-environment trend). `capture_snapshot` stays **parameterized by `dimension` + `tag_filter`** so Phase 13 can iterate owners without reshaping it.

### Locked by spikes — carried forward, NOT re-litigated
- Reopened-aware **two-interval predicate is mandatory** (naive form drops ~19% / all REOPENED). Unit tests must cover OPEN / REOPENED / FIXED labelled cases (TREND-01).
- **Snapshot-capture, not reconstruction** (~29-day Tenable fixed-retention wall; cold start is real).
- **Extend `data/trend/`**, not a parallel store.
- **PII discipline (D-04-08):** aggregate counts only — no hostnames, IPs, plugin names, or row-level fields in persisted files.
- **Atomic writes** (temp-file + `os.replace`) and **per-calendar-month idempotency** (overwrite the month's cell, never duplicate).

### Claude's Discretion
- Exact new-module filenames, function signatures beyond the agreed shape, and the precise dimension-registration mechanism.
- Cron exit-code conventions (follow `scripts/warm_cache.py` precedent).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements & roadmap
- `.planning/REQUIREMENTS.md` — TREND-01..07 definitions and milestone scope/out-of-scope.
- `.planning/ROADMAP.md` — Phase 12 goal + 5 success criteria (byte-for-byte MS bar, idempotency, cold-start, PII inspection).

### Spike findings (settled constraints — do not re-decide)
- `.claude/skills/spike-findings-vuln-reporting/SKILL.md` — requirements summary + source index.
- `.claude/skills/spike-findings-vuln-reporting/references/vuln-metric-substrate.md` — **the implementation blueprint**: reopened-aware `open_at` predicate (lines 42–57), snapshot-not-reconstruction rationale (59–69), constraints (72–77).
- `.planning/notes/trend-reconstruction-engine.md` — design record for S1; ~29-day retention, forward-accumulation model.
- `.planning/notes/report-requests-batch-2026-06.md` — substrate-first sequencing; how v1.4 reports consume S1.

### Existing code the substrate must align with / reuse
- `reports/management_summary.py` §§89, 124–250, 700–766 — the **existing trend store**: `TREND_DIR`, `_trend_file_path`, `_load_trend_history`, `_save_trend_snapshot` (the JSON shape to match; note current write is **non-atomic** — substrate must use temp + `os.replace`), and `_compute_metric_7` (the reader contract that must not regress).
- `data/fetchers.py` §§285, 350–360 (open+reopened export with `first_found`/`last_fixed`/`state`/`resurfaced_date`), §§379–473 (fixed export, ~29-day retention), assets fetcher — lifecycle fields the predicate needs.
- `utils/sla_calculator.py` — placement precedent for the pure `open_findings_at` primitive (UTC, no I/O).
- `scripts/warm_cache.py` — entry-point precedent (atomic pre-fetch, date-named cache, cron-friendly).
- `config.py` — `vpr_to_severity()` / SLA constants; severity is **VPR-first**.

### Style precedents
- `docs/management_summary_calculations.md` — the `docs/*_calculations.md` runbook style DOC-01 (Phase 13) must match.
- `CLAUDE.md` — empty-data guard (`safe_pct`/`safe_int`/`safe_format`), timezone policy (UTC report timestamps; local-time cache/schedule), atomic-write + fail-soft conventions.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`management_summary.py` trend helpers** — reference implementation for the JSON shape and idempotent per-(month, tag_filter) overwrite. Substrate copies the *shape*, not the code (D-01), and adds atomic write + `asset_count`.
- **`scripts/warm_cache.py`** — template for the standalone cron entry point (D-09): atomic, logged, date-named `data/cache/` parquet reuse, clean exit codes.
- **`data/fetchers.py`** — open+reopened and fixed exports already project the four lifecycle fields the predicate requires; the entry point reuses these (D-08).
- **`config.vpr_to_severity()`** — VPR-first severity tiering for the severity dimension.

### Established Patterns
- **Pure compute, deferred I/O** — `open_findings_at` (utils/, pure) vs snapshot engine (data/, I/O); `capture_snapshot` takes injected DataFrames (D-08) so the predicate is unit-testable.
- **Atomic write convention** — temp-file + `os.replace` (the MS writer is currently non-atomic; substrate must improve on it without changing MS).
- **Date-named parquet cache** — `data/cache/<YYYY-MM-DD>/` (local date), warmed once per batch.

### Integration Points
- Writes to the existing `data/trend/` directory (gitignored; aggregate-only) using substrate-owned `trend_{dimension}_{tagsuffix}.json` files.
- New entry point `scripts/capture_trend_snapshot.py` slots alongside `scripts/warm_cache.py` for cron/Task Scheduler.
- `read_trend()` becomes the consumption API for v1.4 trend reports; `capture_snapshot(dimension, tag_filter)` signature is forward-compatible with Phase 13 owner iteration.

</code_context>

<specifics>
## Specific Ideas

- Snapshot payload per entry (severity dimension): `{month, tag_filter, critical, high, medium, low, asset_count, generated_at}` — flat, aggregate-only.
- File naming: `data/trend/trend_severity_all_assets.json` for the Phase 12 default capture.
- Predicate reference (from spike blueprint) — two-interval model keyed on `resurfaced_date`; must validate to the exact live open count.

</specifics>

<deferred>
## Deferred Ideas

- **Flow metrics (new-this-month / remediated-this-month)** — the churn-robust answer to "real remediation vs assets leaving." This is the v1.4 **New-vs-Remediated** report (uses the fixed export within the ~29-day window). Substrate enables it; does not compute it here.
- **Vuln Density (open ÷ asset_count)** — v1.4 report; the `asset_count` denominator is captured now (D-04) precisely because it can't be backfilled.
- **Cross-UUID / stable-asset-key de-duplication** — report-layer normalization for rebuilt-asset double-counting (D-06); v1.4.
- **Per-tag-filter / per-delivery-group snapshot iteration** — Phase 13 (owner dimension) and beyond; Phase 12 captures `all_assets` only.
- **Full `management_summary` migration onto the substrate** — GEN-01 (v1.4); deferred to protect TREND-03's byte-for-byte bar (D-01).
- **Merge-reading MS severity history into `read_trend`** — rejected for now due to ragged `asset_count` rows (D-05); revisit only if a longer day-one series is needed.

</deferred>

---

*Phase: 12-trend-snapshot-substrate-s1*
*Context gathered: 2026-06-06*
