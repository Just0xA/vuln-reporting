# Project Research Summary

**Project:** Vulnerability Management Reporting Suite — v1.4 Management Summary Reporting Improvement
**Domain:** Python vulnerability-reporting suite — management/exec trend-cut modules + GEN-01 migration
**Researched:** 2026-06-11
**Confidence:** HIGH

## Executive Summary

v1.4 is a **thin-consumer milestone**. The six new metric modules (New vs Remediated, Vulnerability Density, Reopened Vulnerabilities, Accepted & Recast, External/DMZ Exposure Cut, Program Health Overview), the MTTR rework, and the GEN-01 `management_summary` migration are all built on top of the already-shipped **S1 trend substrate** and **S2 owner segmentation** — they fetch no new data, introduce no new dependencies, and require no pyTenable upgrade. WAS findings are explicitly **deferred**, which keeps the SDK pinned at pyTenable 1.5.2 and eliminates the only scenario that would have required a breaking stack change.

The two new shared substrates (`utils/external_scope.py` dual-signal IP/tag classifier and `utils/asset_count.py` density denominator) are pure-compute, **stdlib-only** helpers — zero new pip packages.

The recommended build order flows strictly: **substrate availability → composed_report kwargs gates → independent modules → Program Health → GEN-01 last**. GEN-01 is the riskiest item because it replaces a ~2,200-line bespoke render path with a `ReportComposer` pipeline while existing `management_summary` delivery must continue uninterrupted. The board_summary cutover pattern is the proven playbook: structural smoke baselines captured **before** any rewrite, atomic bespoke-path removal only after structural + visual UAT pass, and explicit elimination of the dual-writer trap (`management_summary_*.json` and `trend_*.json` must never grow simultaneously).

The primary correctness risks are mandatory acceptance criteria, not polish: (1) cold-start mishandling — every new tag scope is a cold start, `insufficient_data` branch required on every MoM module; (2) MTTR reopened-finding inflation — resolved-population decision locked before any MTTR code; (3) Vulnerability Density denominator drift — historical density uses each snapshot's own `asset_count`, never live `assets_df` length; (4) GEN-01 regression — bespoke path not deleted until smoke baselines pass.

## Key Findings

### Recommended Stack

The locked stack is fully sufficient. `requirements.txt` is **unchanged**. Every v1.4 capability maps to an already-pinned package (pandas 2.2.3, matplotlib 3.10.1 + plotly 6.0.1 + kaleido, openpyxl, weasyprint 65.1, Jinja2, pyTenable 1.5.2). Python 3.10+ stdlib `ipaddress` handles public-IPv4 classification.

**Zero-new-dependency verdict — confirmed:**
- `pyTenable` stays at 1.5.2 — WAS deferral keeps the SDK-version constraint intact; no `fetch_was_findings()` / `was_findings.parquet`
- No new charting library — matplotlib + plotly cover all v1.4 chart types
- No geo/IP-geolocation library — RFC-range classification only
- No scipy/statsmodels — sample-weighted MTTR mean is plain pandas
- **Python 3.10 `ipaddress` note:** `is_private` in 3.10 does NOT cover CGNAT `100.64.0.0/10`; an explicit `addr in ip_network("100.64.0.0/10")` check is required for correctness on the 3.10 minimum

**Two new substrate files (stdlib-only):**
- `utils/external_scope.py` — dual-signal external-asset classifier (`Location=External/DMZ` tag OR `is_public_ipv4()`); emits `(scoped_df, mismatches_df)` following the S2 `extract_owner()` shape
- `utils/asset_count.py` — pure asset-count denominator; mirrors `utils/open_count.py` placement

**Asset-count denominator — already partly solved:** `data/trend_store.py` constraint D-04 already captures `asset_count` per snapshot since v1.3, so historical density denominators are free from the existing S1 store; only the current-run denominator needs the new helper.

### Expected Features

Five table stakes, two differentiators; all thin consumers of S1 + S2.

**Table stakes:** New vs Remediated, Reopened Vulnerabilities, Accepted & Recast (supersedes management_summary Metric 6; tracks ACCEPTED vs RECASTED separately), MTTR Rework (ships as new `mttr_trend` MODULE_ID to protect board_summary), Program Health Overview (composites Modules 1 + 6 + GEN-01 SLA module), GEN-01 migration.

**Differentiators:** Vulnerability Density (historical `asset_count` denominator already in S1 snapshots), External/DMZ Exposure Cut (dual-signal scope).

**Deferred (not v1.4):** WAS in External Exposure (needs SDK upgrade); External MoM trend via S1 parameterized dimension (current-snapshot-only acceptable); MTTR backfill beyond ~29 days; sub-monthly reopen rate.

### Open Decisions — lock at plan-time

| # | Decision | Module(s) | Recommended Resolution |
|---|----------|-----------|------------------------|
| OD-1 | "New" inflow: `first_found` only vs `OR resurfaced_date` | New vs Remediated | `first_found` only for v1.4; document limitation |
| OD-2 | Density denominator definition | Vulnerability Density | On-time-scanned licensed assets (consistent with board_summary baseline) |
| OD-3 | Reopened snapshot dimension in S1 | Reopened + Accepted & Recast | Extend `capture_snapshot` with new dimensions; avoid proliferating snapshot files |
| OD-4 | MTTR resolved-population | MTTR Rework | Exclude current-REOPENED population (Option B); durably-fixed findings only |
| OD-5 | Program Health composite RAG | Program Health Overview | Green = all 4 green; Amber = 2–3 green; Red = 0–1 green |
| OD-6 | External exposure MoM trend mechanism | External Exposure | Defer MoM trend to v1.5; current-snapshot-only in v1.4 |
| OD-7 | MTTR rework MODULE_ID | MTTR Rework | New `mttr_trend` MODULE_ID; `mttr_by_severity` untouched; re-capture board_summary baselines |
| OD-8 | management_summary legacy trend-JSON migration vs cold start | GEN-01 | Cold start; accumulate forward; document discontinuity in runbook |

### Architecture Approach

v1.4 adds two new kwargs gates in `composed_report.py` (~25 lines: two frozensets + two conditional fetch blocks), seven new module files, two new util substrates, one new smoke script, and the major `reports/management_summary.py` migration. The `**self._kwargs` fan-out in `ReportComposer.run_module()` already distributes new kwargs to every `compute()` — `composer.py` and `base.py` untouched. Auto-discovery means new modules consumed only via `composed_report`/`management_summary` need no `run_all.py` or schema registration.

**New/modified components:**
1. `utils/external_scope.py` (NEW) — pure compute; `(scoped_df, mismatches_df)` tuple
2. `utils/asset_count.py` (NEW) — pure denominator
3. `reports/composed_report.py` (MINOR) — `_MODULES_NEEDING_TREND_SNAPSHOTS` + `_MODULES_NEEDING_RECAST_RULES` gates
4. Seven new `reports/modules/*_module.py` (NEW) — full four-channel contract, no legacy `render_email_kpis`-only shortcuts
5. `scripts/smoke_management_summary_cutover.py` (NEW) — structural baseline; first commit of the GEN-01 phase
6. `reports/management_summary.py` (GEN-01) — bespoke path → ReportComposer pipeline; 5 of 7 metrics already have modules; 2 new (`accepted_recast`, `new_vs_remediated`) + MTTR rework required before cutover
7. `run_all.py` (MINOR, GEN-01) — add `management_summary` to `_CHROME_AWARE_SLUGS`

**Untouched:** `composer.py`, `base.py`, `data/trend_store.py`, `utils/open_count.py`, `utils/tag_helper.py`, `data/fetchers.py`, `delivery_config.schema.yaml`, `_VALID_REPORTS`/`_REPORT_MODULE_MAP`, all five existing constituent metric modules.

### Critical Pitfalls — mandatory acceptance bars

1. **Cold-start** — branch on `read_trend()` `insufficient_data` before any delta; every new tag scope is a cold start; unit-test single-snapshot fixture renders a message, not `NaN%`.
2. **MTTR reopened inflation** — `(last_fixed − first_found)` spans the reopen cycle; lock OD-4 first; fixture (found 200d ago, resurfaced 10d ago, fixed 2d ago) → ~8d not 198d.
3. **Density denominator drift** — use `snapshot["asset_count"]` per month; never divide history by `len(assets_df)`.
4. **GEN-01 dual-writer + smoke-before-cutover** — baseline before any migration code; remove `_save_trend_snapshot()` in the same plan that routes reads through `read_trend()`.
5. **Reopened-aware open predicate mandatory** — `open_findings_at()` two-interval; naive filter drops ~19%.
6. **pandas 3.0 CoW** — `.assign()` only; never `df["col"]=` after a filter (burned v1.3 in `260611-b1x`).
7. **Empty-data guard on all four channels** — `safe_pct`/`safe_int`/`safe_format`; `_empty_result()` on zero rows.
8. **Aggregate-only PII (D-04-08)** — synthetic fixtures/baselines only; External mismatch list is output-only.

## Implications for Roadmap

Suggested structure: **5 phases**

1. **Shared Substrates + composed_report Gates** — `utils/external_scope.py`, `utils/asset_count.py`, two kwargs gates. Small, independently verifiable, unblocks everything. Addresses OD-2, OD-6; avoids external false-positives + denominator drift at the substrate. Standard patterns.
2. **Independent New Modules** — `reopened_vulns`, `external_dmz`, `accepted_recast`, `new_vs_remediated`, `vuln_density` (Reopened first — no trend dep, validates contract against `state`/`resurfaced_date`). Mutually independent. Lock OD-1, OD-3 in plan. Standard patterns.
3. **MTTR Rework** — ships as `mttr_trend` (new MODULE_ID); window disclosure, sample-weighted mean, OD-4 denominator, trend + Owner, four-channel; re-capture board_summary baselines. Lock OD-4 before code.
4. **Program Health Overview** — composites Modules 1 (New vs Remediated) + 6 (MTTR) + GEN-01 SLA; OD-5 composite RAG; cold-start-safe sparklines. Sequenced after its inputs.
5. **GEN-01 — management_summary Migration** — smoke baseline as the mandatory **first commit**; atomic bespoke-path removal after structural smoke + visual UAT; `_CHROME_AWARE_SLUGS` inversion; OD-8. **Highest risk — elevated planning care.**

**Ordering rationale:** substrates before consumers; independent modules before the compositor; MTTR before Program Health (hard dependency); GEN-01 last (needs all seven constituent modules, highest regression risk).

**Research flags:** Phase 5 (GEN-01) needs deeper planning care — the baseline→build→UAT→remove sequence must be the literal plan structure. Phases 1–4 are standard patterns; their only blockers are the listed open decisions, which must be locked in each phase's plan context before coding.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Direct `requirements.txt` + fetcher/module inspection; WAS deferral removes the only speculative dependency question |
| Features | HIGH | All items traced to specific source files; substrate fields confirmed in `trend_store.py` D-04 |
| Architecture | HIGH | Integration derived from direct inspection of `composed_report.py`, `composer.py`, `management_summary.py`; all extension points already exercised by board_summary |
| Pitfalls | HIGH | Grounded in this codebase's own bugs/constraints: `260611-b1x` (CoW), Spike 002 (29-day retention), v1.0 board_summary cutover |

**Overall confidence:** HIGH

### Gaps to address during planning

- **OD-1 … OD-8** — lock each in the phase plan where the affected module begins.
- **`resurfaced_date` population** — verify against a live tenant sample before finalizing the Reopened module's analyst drill-down (Phase 2).
- **S1 `capture_snapshot` extension (OD-3)** — confirm the extension doesn't break existing callers; Phase 2 smoke check on the trend store warranted.

---
*Research completed: 2026-06-11 — Ready for roadmap: yes*
