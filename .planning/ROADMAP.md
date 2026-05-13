# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1-4 (shipped 2026-05-08) — see [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- 🚧 **v1.1 PDF Chrome Redesign** — Phases 5-6 (started 2026-05-13)

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

### 🚧 v1.1 PDF Chrome Redesign (Phases 5-6) — IN PROGRESS

**Goal:** Redesign the PDF cover and apply a consistent, configurable header/footer to every page of every PDF report.

#### Phase 5: PDF Chrome Foundation

- [ ] Build shared PDF chrome utility (header band + footer band CSS) plus config surface; provable in isolation before any report consumes it.

**Requirements covered:** CHROME-CFG-01, CHROME-CFG-02, CHROME-CFG-03, CHROME-CFG-04, CHROME-HDR-01, CHROME-HDR-02, CHROME-FTR-01, CHROME-FTR-02, CHROME-FTR-03

**Success criteria:**
1. `config.py` exposes `HEADER_BG_COLOR` (default `#1a2332`) and `LOGO_PATH` (default `None`).
2. `delivery_config.schema.yaml` accepts an optional `privacy_label: string` per group; defaults to "Confidential" when omitted.
3. Shared chrome utility renders header band (logo-or-no-logo branches) and footer band (cover-variant vs page-N-of-M variant) — covered by unit tests on generated HTML/CSS.
4. Logo-missing fallback test passes: no exception, no logo space reserved, title-only rendering.

#### Phase 6: Cover Redesign + Board Summary Integration

- [ ] Wire chrome into `board_summary`, redesign cover body to use the RAG strip with the new chrome, and confirm end-to-end via real-Tenable smoke + operator UAT.

**Requirements covered:** CHROME-COV-01, CHROME-COV-02, CHROME-INT-01, CHROME-INT-02, CHROME-INT-03, CHROME-COMPAT-01, CHROME-COMPAT-02

**Success criteria:**
1. `board_summary` PDF renders with new cover (RAG strip + header + footer-without-page-number) and metric pages (header + footer-with-page-number).
2. Cutover smoke baselines regenerated; 0 structural drift after re-baseline.
3. `management_summary` and `ops_remediation` PDFs deliver unchanged (their existing renderers untouched; regression suites pass).
4. Operator visual UAT: cover looks professional, header color/logo correct, footer page numbering correct on non-cover pages.

### 📋 Deferred to future milestones

From the v1.0 acknowledged backlog (see `milestones/v1.0-REQUIREMENTS.md` v2 section):
- **GEN-01/02** — Migrate `management_summary` and `ops_remediation` to the module render contract.
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug already landed 2026-05-13.
- **PERF-01..04** — Per-batch `enrich_vulns_with_assets` cache, midnight cache crossover, log rotation, tag-typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **Cosmetic janitorial** — `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants (`run_all.py:76,90`).

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Module Render Contract | v1.0 | 3/3 | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades | v1.0 | 5/5 | Complete | 2026-05-06 |
| 3. Board Summary Module Migration | v1.0 | 7/7 | Complete | 2026-05-07 |
| 4. YAML Config and Regression Cutover | v1.0 | 4/4 | Complete | 2026-05-08 |
| 5. PDF Chrome Foundation | v1.1 | 0/0 | Not started | — |
| 6. Cover Redesign + Board Summary Integration | v1.1 | 0/0 | Not started | — |

## Backlog

(Backlog section preserved across milestone closes — accumulates 999.x items if any.)

*(empty)*
