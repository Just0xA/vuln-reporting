# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1-4 (shipped 2026-05-08) — see [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- ✅ **v1.1 PDF Chrome Redesign** — Phases 5-6 (shipped 2026-05-13) — see [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)

## Phases

<details>
<summary>✅ v1.0 Modular Reporting Framework (Phases 1-4) — SHIPPED 2026-05-08</summary>

- [x] Phase 1: Module Render Contract (3/3 plans) — completed 2026-05-05
- [x] Phase 2: ReportComposer Upgrades (5/5 plans) — completed 2026-05-06
- [x] Phase 3: Board Summary Module Migration (7/7 plans, incl. gap closure 03-07) — completed 2026-05-07
- [x] Phase 4: YAML Config and Regression Cutover (4/4 plans) — completed 2026-05-08

Quick tasks: `rag-cell-width-shrink` (2 iterations) — Phase 03 UAT cover-layout fix.

Full archive: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md). Requirements traceability: [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md). Retrospective: [`RETROSPECTIVE.md`](RETROSPECTIVE.md).

</details>

<details>
<summary>✅ v1.1 PDF Chrome Redesign (Phases 5-6) — SHIPPED 2026-05-13</summary>

- [x] Phase 5: PDF Chrome Foundation (4/4 plans) — completed 2026-05-13
- [x] Phase 6: Cover Redesign + Board Summary Integration (5/5 plans + UAT cycle) — completed 2026-05-13

UAT cycle extended chrome to `composed_report` so any future metric module inherits the chrome with zero per-slug Python.

Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md). Requirements traceability: [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md). Audit: [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md).

</details>

### Next Milestone

Next milestone not yet defined. Start with `/gsd-new-milestone` to capture goals, requirements, and roadmap.

### 📋 Deferred to future milestones

From the accumulated backlog (v1.0 + v1.1):

- **GEN-01/02** — Migrate `management_summary` and `ops_remediation` to the module render contract (they would inherit chrome for free once migrated, since chrome is wired through `ReportComposer`).
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04** — Per-batch `enrich_vulns_with_assets` cache, midnight cache crossover, log rotation, tag-typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **composed_report output filename disambiguation** — per-group basenames (slugified `report_title`, `output_basename:` YAML field, or slugified group name). Captured during v1.1 once multiple composed groups became plausible.
- **Cosmetic janitorial** — `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants (`run_all.py:76,90`); Phase 3 deprecated aliases `_PDF_RAG_STRIP_TEMPLATE` / `_build_rag_strip_page`.

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Module Render Contract | v1.0 | 3/3 | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades | v1.0 | 5/5 | Complete | 2026-05-06 |
| 3. Board Summary Module Migration | v1.0 | 7/7 | Complete | 2026-05-07 |
| 4. YAML Config and Regression Cutover | v1.0 | 4/4 | Complete | 2026-05-08 |
| 5. PDF Chrome Foundation | v1.1 | 4/4 | Complete | 2026-05-13 |
| 6. Cover Redesign + Board Summary Integration | v1.1 | 5/5 | Complete | 2026-05-13 |

## Backlog

(Backlog section preserved across milestone closes — accumulates 999.x items if any.)

*(empty)*
