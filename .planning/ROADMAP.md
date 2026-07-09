# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1–4 (shipped 2026-05-08) — [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- ✅ **v1.1 PDF Chrome Redesign** — Phases 5–6 (shipped 2026-05-13) — [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- ✅ **v1.2 Deployment & Self-Update Infrastructure** — Phases 7–11 (shipped 2026-05-22) — [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)
- ✅ **v1.3 Trend & Segmentation Substrate** — Phases 12–13 (shipped 2026-06-11) — [`milestones/v1.3-ROADMAP.md`](milestones/v1.3-ROADMAP.md)
- ✅ **v1.4 Management Summary Reporting Improvement** — Phases 14–19 (shipped 2026-06-26) — [`milestones/v1.4-ROADMAP.md`](milestones/v1.4-ROADMAP.md)
- 🔜 **v1.6 → v2.0 (forward plan)** — candidate Phases 20–41; not yet opened as milestones — [`roadmap-v1.6-v2.0.md`](roadmap-v1.6-v2.0.md) (v1.7 spec: [`specs/milestone-spec-validation-substrate.md`](specs/milestone-spec-validation-substrate.md))

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

<details>
<summary>✅ v1.4 Management Summary Reporting Improvement (Phases 14–19) — SHIPPED 2026-06-26</summary>

- [x] Phase 14: Shared Substrates + composed_report Gates (3/3 plans) — external-scope classifier, on-time asset-count denominator, trend/recast kwargs frozenset gates (SUB-01..03)
- [x] Phase 15: Independent New Modules (6/6 plans) — New vs Remediated, Vulnerability Density, Reopened Vulns, Accepted & Recast, External/DMZ Exposure (RPT-01..04/06, QUAL-01..03/05)
- [x] Phase 16: MTTR Rework (7/7 plans) — `mttr_trend` MODULE_ID, ~30-day window disclosure, sample-weighted mean, reopened-aware clock, 4-gauge band + focus table (RPT-05)
- [x] Phase 17: Program Health Overview (3/3 plans) — composite MoM velocity dashboard, OD-5 composite RAG, Owner velocity table (RPT-07)
- [x] Phase 18: management_summary Migration + Docs (5/5 plans) — GEN-01 cutover onto ReportComposer, chrome-aware, 12mo trend reconstruction, auditor runbooks (GEN-01, QUAL-04, DOC-02)
- [x] Phase 19: v1.4 Closure (11/11 plans) — INT-WARN-1/2/3, 39 CodeRabbit findings, deferred 15/17/18-REVIEW findings, Phase 16 UAT + Phase 17 human verification

Post-milestone: re-audit finding REAUDIT-WARN-1 closed via quick task `260626-elj` (inline management_summary snapshot compute; report output unchanged).

Full detail: [`milestones/v1.4-ROADMAP.md`](milestones/v1.4-ROADMAP.md)

</details>

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
| 17. Program Health Overview | v1.4 | 3/3 | Complete   | 2026-06-13 |
| 18. management_summary Migration + Docs | v1.4 | 5/5 | Complete    | 2026-06-21 |
| 19. v1.4 Closure | v1.4 | 11/11 | Complete    | 2026-06-26 |

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
- **MTTR window widening** — 90-day / all-time MTTR metric-design change now that 12mo of fixed data is retrievable (Phase 18 keeps deliberate rolling-30, D-18-06); its own future phase.
- **Reconstruct the Feb–Aug 2025 taper tail / full ~16mo** — Phase 18 ships a fixed 12mo window (D-18-02); revisit if a longer horizon is wanted and the taper can be characterized.
- **Persistent finding-mirror + differential-export architecture** — `indexed_at` differential cursor + stateful local mirror; a v2 strategic trend-sourcing option (out of v1.4 scope).
- **P15-CLEANUP — Phase-15 code-review Info findings** (non-functional; see [`phases/15-independent-new-modules/15-REVIEW.md`](phases/15-independent-new-modules/15-REVIEW.md)):
  - IN-01 — `safe_format` imported but unused in 4 of 5 new modules (only `vuln_density` calls it).
  - IN-02 — `_rag_fill` defined but unused in `reopened_vulns`, `external_dmz`, `new_vs_remediated` modules.
  - IN-03 — `_safe_mom_delta` defined but never called in `new_vs_remediated_module.py` (superseded by inline `safe_int`).
  - IN-04 — `NO_DATA_DRIVER`, `STATUS_COLOR`, `STATUS_LABEL` imported but unused in `reopened_vulns_module.py`.
  - IN-05 — owner-dimension `capture_snapshot` call in `capture_trend_snapshot.py` omits the Phase-15 aggregate counts the severity call passes (no current consumer; documented inconsistency).
