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

**Candidate phase (awaiting milestone assignment):**

- **Phase: Operator Remediation Report v2 — Modular, Priority-Driven**
  Successor to (or replacement for) the current `ops_remediation` slug. Realized as a `composed_report`-style bundle of operator-focused metric modules driven by the priority model captured in [`notes/operator-remediation-priority-model.md`](notes/operator-remediation-priority-model.md). Each module renders into the four-channel contract (PDF section, Excel tab, email panel, analyst drill-down).
  - **External-Facing Priority Queue** — findings on assets where `Location ∈ {External, DMZ}` OR `ipv4` is outside RFC 1918 private space; ranked by VPR × asset count.
  - **Risk-Flag Hot List** — findings where VPR = 10, `vpr_v2.on_cisa_kev = true`, or CVE matches the Threat Intel watchlist (sourced from `config/threat_intel_priority_cves.yaml`; see seed [`threat-intel-tag-migration.md`](seeds/threat-intel-tag-migration.md) for the future Tenable-tag source).
  - **Aged Critical / High** — operator cut of the existing aged-vulns logic, scoped to Critical + High open > 90 days.
  - **Remediation Action Grouping** — group open findings by `plugin.id` (or by patch reference where applicable) so a single fix action shows the full finding-and-host footprint it would resolve.
  - **Fix-Type Breakdown** — counts by patch / configuration change / workaround / disable-service / no-fix-available / vendor-unpatched (Pillar 2 of the operator info model). Depends on research question Q-001 (fix-type reliability) before final classifier shape.
  - **Per-Environment Routing** — operator groups receive only the rows scoped to the environments they own (`Environment ∈ {Dev, Non-Prod, Prod}`), driven by YAML `filters:` and `modules:` per group.
  - **Backlog item this consumes:** GEN-01/02 — migrating `ops_remediation` onto the module contract (would inherit chrome for free).
  - **Cross-references:** `notes/operator-remediation-priority-model.md`, `seeds/threat-intel-tag-migration.md`, `research/questions.md` Q-001.

### 📋 Deferred to future milestones

From the accumulated backlog (v1.0 + v1.1):

- **GEN-01/02** — Migrate `management_summary` and `ops_remediation` to the module render contract (they would inherit chrome for free once migrated, since chrome is wired through `ReportComposer`).
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04** — Per-batch `enrich_vulns_with_assets` cache, midnight cache crossover, log rotation, tag-typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **composed_report output filename disambiguation** — per-group basenames (slugified `report_title`, `output_basename:` YAML field, or slugified group name). Captured during v1.1 once multiple composed groups became plausible.
- **Cosmetic janitorial** — `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants (`run_all.py:76,90`); Phase 3 deprecated aliases `_PDF_RAG_STRIP_TEMPLATE` / `_build_rag_strip_page`.
- **pyTenable upgrade + `assets_v2()` migration** — pin is `pyTenable==1.5.2`; latest is `1.9.1` (2026-04-09). Recommend splitting into two units of work to separate platform-stability risk from new-feature risk. See [Backlog → pyTenable upgrade + asset export v2](#backlog) below for the detail and recommended sequencing.

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

### pyTenable upgrade + asset export v2 migration

**Captured:** 2026-05-14 (research pass; see `feedback_gsd_artifact_reuse` memory for the explore conversation)
**Status:** Deferred — slot before or as part of the Operator Remediation Report v2 phase, or whenever we need a v2-only asset attribute.

**Context.** Project pins `pyTenable==1.5.2` (`requirements.txt:2`). Asset exports go through `tio.exports.assets()` → v1 endpoint `POST /assets/export`. Tenable shipped a v2 endpoint at `POST /assets/v2/export`, and pyTenable now exposes it as `tio.exports.assets_v2()`. Latest pyTenable is **1.9.1** (released 2026-04-09) — four minor releases ahead of our pin. Both v1 and v2 methods coexist in 1.9.x, so adoption is additive (no forced migration, no Tenable deprecation pressure today).

**Why upgrade.** The v2 endpoint unlocks fields directly relevant to the Operator Remediation Report v2 work (see [`notes/operator-remediation-priority-model.md`](notes/operator-remediation-priority-model.md)):

- `types` filter — first-class include/exclude of Tenable WAS (Web App Scanning) assets in operator reports.
- ACR (Asset Criticality Rating) and AES (Asset Exposure Score) attributes — could replace or supplement the RFC-1918 heuristic for "externally-facing" detection.
- `since` filter — returns assets updated/deleted/terminated since a timestamp regardless of state; enables incremental fetches instead of full exports each run.
- `include_resource_tags` — explicit toggle, cleaner than v1's implicit behavior.

Secondary benefits: Python 3.13 / 3.14 compatibility, Marshmallow → Pydantic refactor of the Exports API (1.7.0 + finalized in 1.9.0), and T1 Export APIs added in 1.8.2 if Tenable One ever scopes in.

**Risk to test.** The upgrade itself is the bigger risk than the v2 swap. The Marshmallow → Pydantic refactor in 1.7.0 / 1.9.0 could shift:

- Parameter validation error shape (low impact — our code doesn't catch SDK validation errors specifically).
- Response-iterator behavior — pyTenable historically yields dicts; verify Pydantic v2 doesn't return model instances that would break the DataFrame construction in `data/fetchers.py` (≈ lines 488, 949, 984, 1113) or anywhere downstream.
- Schema field renames from the 1.8.2 / 1.8.3 schema-correction commits.

Both `tio.exports.vulns()` and `tio.exports.assets()` call sites need end-to-end re-testing on the upgrade, not just assets.

**Recommended sequencing (do not couple).**

1. **Platform upgrade, no behavior change.** Bump `pyTenable` to latest 1.9.x; keep calling `assets()` and `vulns()` as today. Re-run full report suite against real Tenable; confirm no drift. Independently valuable (security, Python compat).
2. **`assets_v2()` adoption.** Swap asset-export call sites in `data/fetchers.py` to `assets_v2()`, surface the new fields into the assets parquet, and update the Operator Remediation priority model to consume ACR/AES where they beat the RFC-1918 heuristic. Add `since`-based incremental fetches if/when the warm-cache story justifies it.

Coupling the platform upgrade with the new-feature adoption couples two distinct risk profiles into one debug surface.

**Sources.**
- [pyTenable on PyPI](https://pypi.org/pypi/pytenable/json)
- [pyTenable Exports API docs (1.9.1)](https://pytenable.readthedocs.io/en/stable/api/io/exports.html) — `assets_v2()` method reference
- [Tenable Export Assets v2 API reference](https://developer.tenable.com/reference/export-assets-v2)
- [pyTenable CHANGELOG.md](https://github.com/tenable/pyTenable/blob/main/CHANGELOG.md)
