# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1-4 (shipped 2026-05-08) — see [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- 📋 **v1.1 / v2 (planned)** — TBD via `/gsd-new-milestone`

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

### 📋 Next milestone (planned)

The next milestone is not yet defined. Run `/gsd-new-milestone` to start v1.1 / v2 questioning → research → requirements → roadmap.

Likely candidates from the v1.0 acknowledged backlog (see `milestones/v1.0-REQUIREMENTS.md` v2 section):
- **GEN-01/02** — Migrate `management_summary` and `ops_remediation` to the new module render contract.
- **GEN-03/04** — YAML-driven module composition (inline `modules: [...]` lists; named bundles defined as YAML maps rather than hardcoded).
- **PERF-01..04** — Per-batch `enrich_vulns_with_assets` cache, midnight cache crossover, log rotation, tag-typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **Cosmetic janitorial** — `_VALID_FREQUENCIES` / `_VALID_REPORTS` cleanup (`run_all.py:76,90` after Phase 4 jsonschema replacement); cover-page redesign (template-based; "Generated" + Data Protection Label to footer).

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Module Render Contract | v1.0 | 3/3 | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades | v1.0 | 5/5 | Complete | 2026-05-06 |
| 3. Board Summary Module Migration | v1.0 | 7/7 | Complete | 2026-05-07 |
| 4. YAML Config and Regression Cutover | v1.0 | 4/4 | Complete | 2026-05-08 |

## Backlog

(Backlog section preserved across milestone closes — accumulates 999.x items if any.)

*(empty)*
