# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1–4 (shipped 2026-05-08) — [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- ✅ **v1.1 PDF Chrome Redesign** — Phases 5–6 (shipped 2026-05-13) — [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- ✅ **v1.2 Deployment & Self-Update Infrastructure** — Phases 7–11 (shipped 2026-05-22) — [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)
- ✅ **v1.3 Trend & Segmentation Substrate** — Phases 12–13 (shipped 2026-06-11) — [`milestones/v1.3-ROADMAP.md`](milestones/v1.3-ROADMAP.md)
- 🔵 **v1.4 Management Summary Reporting Improvement** — Phases 14–18 (in progress)

## Phases

<details>
<summary>✅ v1.0 Modular Reporting Framework (Phases 1–4) — SHIPPED 2026-05-08</summary>

Full detail: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)

</details>

<details>
<summary>✅ v1.1 PDF Chrome Redesign (Phases 5–6) — SHIPPED 2026-05-13</summary>

Full detail: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)

</details>

<details>
<summary>✅ v1.2 Deployment & Self-Update Infrastructure (Phases 7–11) — SHIPPED 2026-05-22</summary>

- [x] Phase 7: Foundations (2/2 plans) — slim-tarball `.gitattributes` boundary + symlink-layout systemd unit
- [x] Phase 8: Warm Cache (2/2 plans) — `scripts/warm_cache.py` atomic pre-fetch
- [x] Phase 9: CI/Release Automation (2/2 plans) — `.github/workflows/release.yml` slim tarball + SHA256
- [x] Phase 10: Install / Update / Rollback (3/3 plans) — `scripts/update_from_github.sh`
- [x] Phase 11: Documentation (2/2 plans) — README, DEPLOYMENT.md, RUNBOOK.md, crontab.example

Full detail: [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)

</details>

<details>
<summary>✅ v1.3 Trend & Segmentation Substrate (Phases 12–13) — SHIPPED 2026-06-11</summary>

- [x] Phase 12: Trend Snapshot Substrate (S1) (3/3 plans) — reopened-aware open-count primitive + monthly snapshot capture/read, `data/trend/` continuity, idempotency, PII discipline, cron entry point (TREND-01..07)
- [x] Phase 13: Owner Segmentation + Composition (S2 + Doc) (5/5 plans, incl. 13-05 gap-closure) — Owner helper + Unassigned catch-all, analyst worklist, fail-soft guard, S1×S2 composition proof, auditor runbook (SEG-01..05, DOC-01)

Post-milestone: substrate tech debt closed via quick task `260611-b1x` (owner_supplemental asset-count dedup + pandas-3.0 CoW).

Full detail: [`milestones/v1.3-ROADMAP.md`](milestones/v1.3-ROADMAP.md)

</details>

### v1.4 Management Summary Reporting Improvement (Phases 14–18)

- [x] **Phase 14: Shared Substrates + composed_report Gates** — external-scope classifier, asset-count denominator, trend/recast kwargs gates
 (completed 2026-06-11)
- [x] **Phase 15: Independent New Modules** — New vs Remediated, Vulnerability Density, Reopened Vulns, Accepted & Recast, External/DMZ Exposure
 (completed 2026-06-11)
- [x] **Phase 16: MTTR Rework** — `mttr_trend` MODULE_ID, window disclosure, sample-weighted mean, reopened-aware denominator, trend + Owner
 (completed 2026-06-12)
- [ ] **Phase 17: Program Health Overview** — composite MoM velocity dashboard composing Modules 1 + 6 + SLA signals
- [ ] **Phase 18: management_summary Migration + Docs** — GEN-01 cutover onto module render contract; auditor runbooks for all v1.4 modules

## Phase Details

### Phase 14: Shared Substrates + composed_report Gates
**Goal**: The foundational pure-compute helpers and kwargs forwarding gates are in place so every v1.4 module can consume trend history, recast rules, and scope-computation results without I/O inside `compute()`.
**Depends on**: Phase 13 (S1 trend store + S2 extract_owner — both shipped)
**Requirements**: SUB-01, SUB-02, SUB-03
**Open decisions to lock in this phase's plan:**
- OD-2: Density denominator definition (all licensed vs on-time-scanned) — locked before `asset_count.py` is written
- OD-6: External exposure MoM trend mechanism — lock defer-to-v1.5 decision before `external_scope.py` is written

**Success Criteria** (what must be TRUE):
1. `utils/external_scope.py` classifies an asset as external when it carries `Location=External` OR `Location=DMZ` tag OR has a public IPv4 (using `ipaddress.ip_address().is_global`, covering CGNAT + loopback + link-local); emits `(scoped_df, mismatches_df)` matching the S2 `extract_owner()` tuple shape; unit-tested against CGNAT `100.64.x.x`, loopback, IPv6 link-local, and the untagged/mismatched cases.
2. `utils/asset_count.py` returns the current-run licensed asset count from `assets_df` via a pure function; unit-tested including zero-asset guard.
3. `composed_report.py` gains `_MODULES_NEEDING_TREND_SNAPSHOTS` and `_MODULES_NEEDING_RECAST_RULES` frozensets with conditional fetch blocks following the existing `_MODULES_NEEDING_FIXED_VULNS` pattern; `run_report()` signature is unchanged; existing composed-report groups pass `--dry-run` with no regression.
4. `read_trend()` result and `recast_rules_df` arrive at module `compute()` calls via `**self._kwargs` fan-out — verified by a composed group that includes a stub module asserting both kwargs are present when listed in the frozensets.
**Plans**: 3 plans
- [x] 14-01-PLAN.md — `utils/external_scope.py` external-scope classifier + mismatch list (SUB-01)
- [x] 14-02-PLAN.md — `config.ON_TIME_SCAN_WINDOW_DAYS` + `utils/asset_count.py` on-time-scanned denominator (SUB-02)
- [x] 14-03-PLAN.md — `composed_report.py` trend/recast kwargs gates + SC#4 stub module (SUB-03)

---

### Phase 15: Independent New Modules
**Goal**: Five new four-channel metric modules are live and verifiably correct: New vs Remediated, Vulnerability Density, Reopened Vulnerabilities, Accepted & Recast, and External/DMZ Exposure Cut — each consuming the S1/S2 substrates and Phase 14 gates without peer-module dependencies.
**Depends on**: Phase 14
**Requirements**: RPT-01, RPT-02, RPT-03, RPT-04, RPT-06, QUAL-01, QUAL-02, QUAL-03, QUAL-05

**Note on QUAL requirements:** QUAL-01 (cold-start branching), QUAL-02 (reopened-aware predicate), QUAL-03 (empty-data guard on all four channels), and QUAL-05 (aggregate-only PII) are first verified here and are enforced as acceptance bars in every subsequent phase as well.

**Open decisions to lock in this phase's plans:**
- OD-1: "New" inflow definition — `first_found` only vs `OR resurfaced_date` (RPT-01)
- OD-3: S1 snapshot dimension extension shape for reopened/exception counts — extend `capture_snapshot` vs module-local file (RPT-03, RPT-04)
- Phase-2 verification: confirm `resurfaced_date` is populated on the live tenant before finalizing the Reopened drill-down schema (RPT-03)

**Success Criteria** (what must be TRUE):
1. A reader can view a monthly New vs Remediated trend chart (inflow vs outflow bars, net delta line) with an Owner cut; cold-start renders a "Trend data being established" notice (not `NaN%` or a crash) when fewer than 2 S1 snapshots exist; REOPENED population is not silently dropped from open-count context (QUAL-02 verified).
2. A reader can view Vulnerability Density (vulns per asset) trended MoM where each historical point uses its own snapshot's `asset_count` field — never the current `len(assets_df)` — and the denominator MoM change is flagged when it exceeds 10%; cold-start safe.
3. A reader can see Reopened Vulnerabilities count and rate with an Owner cut; `state==REOPENED` is the primary filter; analyst drill-down includes `plugin_id`, `resurfaced_date`, reopen-lag days; rate denominator gracefully absent-fixed-export degrades to count-only.
4. A reader can see Accepted & Recast posture with ACCEPTED and RECASTED tracked separately (never silently aggregated), a current vs prior-month delta arrow, and an Owner cut; expired-rule findings are flagged as "pending re-evaluation" rather than counted as currently accepted; finding counts drive the headline, rule counts are in the analyst tab.
5. A reader can see External/DMZ Exposure counts (Critical/High/Medium) on externally-scoped assets; the analyst mismatch list (public-IP-but-untagged, tagged-but-private) follows the locked schema (asset_uuid, ip_address, owner_tag, untagged_reason, finding_count aggregate only — no per-finding CVE/plugin detail per D-04-08); zero-external-asset groups render a gray "No external assets in scope" cell, not an error.
6. Every new module survives a zero-row filtered input on all four channels without raising; all computed percentages use `safe_pct`/`safe_int`/`safe_format`; no `df["col"] = val` after a filter anywhere in new module code (QUAL-03, pandas CoW).
7. No committed test fixture or baseline contains real hostnames, IPs, or plugin names; all synthetic data uses RFC 6761/5737 addresses (QUAL-05).
**Plans**: 6 plans
- [x] 15-01-PLAN.md — reopened_vulns PATHFINDER module (RPT-03) + live-tenant resurfaced_date spot-check
- [x] 15-02-PLAN.md — backward-compatible capture_snapshot() aggregate-field extension + cron wiring (RPT-02/03/04)
- [x] 15-03-PLAN.md — external_dmz current-snapshot module + locked mismatch list (RPT-06)
- [x] 15-04-PLAN.md — new_vs_remediated stacked-inflow MoM module + composed_report gate registration (RPT-01)
- [x] 15-05-PLAN.md — vuln_density per-snapshot-denominator MoM module (RPT-02)
- [x] 15-06-PLAN.md — accepted_recast separate-counts + expiry-aware MoM module (RPT-04)
**UI hint**: yes

---

### Phase 16: MTTR Rework
**Goal**: The reworked MTTR module (`mttr_trend`, new MODULE_ID) ships with its ~30-day measurement window disclosed in all four channels, a sample-weighted overall mean, reopened-finding exclusion from the duration calculation, and month-over-month trend + Owner breakdown — replacing the four undisclosed correctness gaps in the current `mttr_by_severity_module.py` without breaking the existing board_summary groups that reference `mttr_by_severity`.
**Depends on**: Phase 14 (trend_snapshots kwarg gate)
**Requirements**: RPT-05

**Open decisions to lock in this phase's plan:**
- OD-4: MTTR resolved-population definition — Option A (all fixed), B (exclude current-REOPENED), or C (first-time fixes only). Must be locked before any MTTR code is written.
- OD-7: Confirm MODULE_ID = `mttr_trend`, leaving `mttr_by_severity_module.py` untouched. Board_summary smoke baselines re-captured after rework lands.

**Success Criteria** (what must be TRUE):
1. Every MTTR output (PDF gauge labels, Excel column headers, email panel footer, calculations runbook) explicitly states "Rolling ~30-day MTTR (findings remediated in the last ~30 days)" — the measurement window is never implicit.
2. The overall MTTR is a sample-weighted mean across all fixed findings, not an unweighted mean of per-severity means; a program remediating 500 Low and 2 Critical findings shows a result dominated by Low MTTR.
3. A fixture where a finding was first found 200 days ago, `resurfaced_date` is 10 days ago, and `last_fixed` is 2 days ago produces an MTTR of approximately 8 days, not 198 days — the reopened-cycle inflation is eliminated.
4. Board_summary groups that reference `mttr_by_severity` continue to deliver without change; `mttr_by_severity_module.py` is byte-unchanged; new `mttr_trend` baselines are re-captured and pass the structural smoke check.
5. Per-severity sample sizes below the minimum threshold (default 5) render "Insufficient data (N findings)" rather than a potentially misleading single-finding average; zero fixed-findings-in-scope returns `_empty_result()` with gray RAG.
**Plans**: 7 plans (3 original + 4 gap-closure)
- [x] 16-01-PLAN.md — Extend snapshot store + capture script with rolling-30-day MTTR aggregate (overall/per-severity/per-Owner; D-16-03/09)
- [x] 16-02-PLAN.md — New four-channel `mttr_trend` module (reopened-aware clock, sample-weighted mean, MoM + Owner cut) + composed_report frozenset
- [x] 16-03-PLAN.md — Acceptance suite (criterion-3 lodestar, cold-start, min_sample, Owner-drift) + `mttr_trend` baselines + board_summary zero-diff (D-16-10)
- [x] 16-04-PLAN.md — Gap closure (D-16-11/12): configurable `mttr_view` {owner,severity,both} with split Severity/Owner tables across PDF/Excel/email + Owner SLA-basis fix (default owner)
- [x] 16-05-PLAN.md — Gap closure tests: mttr_view owner/severity/both/default + Owner-SLA-drop + single-page fit; regenerate `mttr_trend` baselines; re-assert board_summary zero-diff (D-16-10)
- [x] 16-06-PLAN.md — Gap closure (D-16-13): always-on 4-gauge severity band (MoM down/up arrows) in all views + focus-driven Owner/Application table; retire mttr_view, add mttr_table override; plumb focus via composed_report; fix capture_trend_snapshot sys.path bootstrap; CLAUDE.md Medium SLA 45 to 60
- [x] 16-07-PLAN.md — Gap closure tests (D-16-13): 4-gauge presence all views, MoM arrow polarity, focus routing, severity-table absent, Excel severity block + config SLA, snapshot real-CLI subprocess regression; regenerate mttr_trend baselines; re-assert board_summary zero-diff (D-16-10)

---

### Phase 17: Program Health Overview
**Goal**: The Program Health Overview module is live — a single-page composite MoM velocity dashboard that stitches New vs Remediated, MTTR trend, and SLA posture into one composite RAG with an Owner velocity table, cold-start-safe.
**Depends on**: Phase 15 (RPT-01 new_vs_remediated), Phase 16 (RPT-05 mttr_trend)
**Requirements**: RPT-07

**Open decisions to lock in this phase's plan:**
- OD-5: Composite RAG threshold rule — Green = all 4 signals green; Amber = 2–3 green; Red = 0–1 green (or adjust). Must be locked before render code is written.

**Success Criteria** (what must be TRUE):
1. A reader can see a single-page Program Health Overview with a composite RAG status ("on track / at risk / off track") derived from the locked OD-5 rule applied to open-trend + SLA rate + MTTR + net velocity signals.
2. The email panel renders a 4-tile KPI row (Open Critical delta, Net velocity, SLA rate delta, MTTR trend) and a one-paragraph narrative with no `NaN%` values — each tile degrades gracefully when its upstream signal is unavailable (Amber "data incomplete" composite RAG, explicit missing-signal note).
3. When fewer than 2 S1 snapshots exist, the module renders current-values-only tiles with a cold-start notice on MoM delta fields, not a crash.
4. The Owner velocity table shows each Owner's MoM delta on open Critical+High and flags Owners whose open count increased >20% MoM as outliers.
**Plans**: 3 plans
- [x] 17-01-PLAN.md — S1 snapshot SLA-posture field (`sla_rate_crit_high`): trend_store + capture script + round-trip tests (D-17-03/04)
- [x] 17-02-PLAN.md — `program_health` module compute: 4-signal re-derivation, OD-5 composite + missing-cap, cold-start Amber, Owner velocity, composed_report gate (D-17-01/05/06/07/08/09)
- [ ] 17-03-PLAN.md — four-channel render: PDF sparklines + Owner table, email 4-tile + narrative, Excel/analyst tabs, RAG strip (D-17-06/09)
**UI hint**: yes

---

### Phase 18: management_summary Migration + Docs
**Goal**: `management_summary` is migrated from its ~2,200-line bespoke render path onto the `ReportComposer` pipeline (GEN-01), becomes chrome-aware, and the auditor calculation runbooks for all seven v1.4 modules are written — with zero regression to existing recipient-group delivery throughout.
**Depends on**: Phase 15 (accepted_recast, new_vs_remediated modules), Phase 16 (mttr_trend module), Phase 17 (program_health_overview module complete)
**Requirements**: GEN-01, QUAL-04, DOC-02

**Open decisions to lock in this phase's plan:**
- OD-8: management_summary legacy trend-JSON migration vs cold start — recommended: cold start, accumulate forward, document discontinuity. Must be decided before any migration code is written.

**Key constraint:** The smoke baseline script (`scripts/smoke_management_summary_cutover.py`) capturing structural shape from the current bespoke path MUST be committed as the first plan of this phase, before any migration code is written. The bespoke path (`_save_trend_snapshot`, `_load_trend_history`, `_compute_metric_*`, `_build_pdf`) is removed in the same commit that routes reads through `read_trend()` — no dual-writer window.

**Success Criteria** (what must be TRUE):
1. A structural smoke baseline is captured from the current `management_summary` bespoke path before any migration code exists; the same smoke script passes against the migrated output after cutover — section count, RAG cell count, and module presence all match (D-04-05: values not locked, structure locked).
2. `management_summary` delivers via `ReportComposer.run_full_pipeline()` with all seven metric modules (`total_vulns_by_severity`, `scan_coverage_sla`, `mttr_trend`, `patch_compliance_rate`, `aged_vulns_assets`, `accepted_recast`, `new_vs_remediated`); the bespoke `_compute_metric_*` functions and private Jinja2 path are deleted in the same commit.
3. Existing `delivery_config.yaml` groups referencing `management_summary` deliver without YAML changes; the email body routes through `build_email_body_modular()` (non-empty `email_body_html` predicate) and renders correctly in Outlook/Gmail/Apple Mail.
4. `management_summary` is added to `_CHROME_AWARE_SLUGS` and inherits the PDF chrome header/footer; operator visual UAT confirms all seven metric sections are present in the migrated PDF before the bespoke path is declared removed.
5. Both `management_summary_*.json` (legacy trend) and `trend_*.json` (S1 store) are never written simultaneously; `_save_trend_snapshot()` is removed in the same plan that routes reads through `read_trend()`; only one trend history grows going forward.
6. Auditor calculation runbooks in `docs/` document each of the seven v1.4 modules' metric definitions, data sources, edge-case handling, disclosed MTTR window, and external-scope rule (DOC-02).
**Plans**: TBD

---

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Module Render Contract | v1.0 | 3/3 | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades | v1.0 | 5/5 | Complete | 2026-05-06 |
| 3. Board Summary Migration | v1.0 | 7/7 | Complete | 2026-05-07 |
| 4. YAML Opt-out + Regression | v1.0 | 4/4 | Complete | 2026-05-08 |
| 5. PDF Chrome Foundation | v1.1 | 4/4 | Complete | 2026-05-13 |
| 6. Cover Redesign + Board Int. | v1.1 | 5/5 | Complete | 2026-05-13 |
| 7. Foundations | v1.2 | 2/2 | Complete | 2026-05-19 |
| 8. Warm Cache | v1.2 | 2/2 | Complete | 2026-05-19 |
| 9. CI/Release Automation | v1.2 | 2/2 | Complete | 2026-05-19 |
| 10. Install / Update / Rollback | v1.2 | 3/3 | Complete | 2026-05-19 |
| 11. Documentation | v1.2 | 2/2 | Complete | 2026-05-20 |
| 12. Trend Snapshot Substrate | v1.3 | 3/3 | Complete | 2026-06-08 |
| 13. Owner Segmentation + Comp. | v1.3 | 5/5 | Complete | 2026-06-10 |
| 14. Shared Substrates + composed_report Gates | v1.4 | 3/3 | Complete    | 2026-06-11 |
| 15. Independent New Modules | v1.4 | 6/6 | Complete    | 2026-06-11 |
| 16. MTTR Rework | v1.4 | 7/7 | Complete    | 2026-06-12 |
| 17. Program Health Overview | v1.4 | 2/3 | In Progress|  |
| 18. management_summary Migration + Docs | v1.4 | 0/TBD | Not started | - |

## Backlog

Cross-milestone backlog is tracked in [`PROJECT.md`](PROJECT.md) ("Backlog" / "Deferred to Future Milestones") and [`STATE.md`](STATE.md) ("Deferred Items"). Open items carried past v1.3:

- **GEN-02** — Migrate `ops_remediation` to the module render contract.
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04** — Performance pass (per-batch enrich cache, midnight cache crossover, log rotation, tag-value typo detection).
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **composed_report output filename disambiguation** — per-group basenames for groups using `reports: [composed_report]`.
- **Cosmetic janitorial** — `run_all.py:76,90` stale `_VALID_FREQUENCIES` / `_VALID_REPORTS` constants.
- **Daemon-integrated warm-cache** — fold `scripts/warm_cache.py` into the scheduler daemon as a schedule-derived job.
- **E2E harness — strengthen Layer 3 module-error detection** — assert no module-level errors / no ERROR-level logs for groups expected clean.
- **E2E harness — minor follow-ups** — Excel-omitted email note assertion; SMTP wording reconciliation; legacy test migration to pytest discovery.
- **VTD-01 — Vuln Type Distribution module (App / OS / Hardware)** — Spike 001 done (PARTIAL); CPE prefix + plugin_family override classifier. Design: [`notes/vuln-type-distribution-module.md`](notes/vuln-type-distribution-module.md).
- **SEV-NONE-01 — Global `vpr_to_severity` "None" tier** — `vpr_score` 0/null → None everywhere; cross-cutting change, sized as its own phase.
- **EXT-WAS-01** — WAS findings in External Exposure — gated on pyTenable upgrade decision.
- **EXT-TREND-01** — External Exposure MoM trend via S1 parameterized dimension.
- **P15-CLEANUP — Phase-15 code-review Info findings** (non-functional; see [`phases/15-independent-new-modules/15-REVIEW.md`](phases/15-independent-new-modules/15-REVIEW.md)):
  - IN-01 — `safe_format` imported but unused in 4 of 5 new modules (only `vuln_density` calls it).
  - IN-02 — `_rag_fill` defined but unused in `reopened_vulns`, `external_dmz`, `new_vs_remediated` modules.
  - IN-03 — `_safe_mom_delta` defined but never called in `new_vs_remediated_module.py` (superseded by inline `safe_int`).
  - IN-04 — `NO_DATA_DRIVER`, `STATUS_COLOR`, `STATUS_LABEL` imported but unused in `reopened_vulns_module.py`.
  - IN-05 — owner-dimension `capture_snapshot` call in `capture_trend_snapshot.py` omits the Phase-15 aggregate counts the severity call passes (no current consumer; documented inconsistency).
