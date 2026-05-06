# Roadmap: Vulnerability Management Reporting Suite — v1 Modular Reporting Framework

## Overview

v1 establishes the modular pattern as the durable unit of report composition. Today the `BaseModule` / `ReportComposer` infrastructure exists and is exercised by `board_summary` and `management_summary`, but it only renders to PDF and basic Excel — the email body is bare, the PDF cover is thin, and analysts have no drill-down path. v1 extends the contract with three new render hooks (email panel, analyst tabs, RAG strip entry), upgrades the composer to assemble email bodies, RAG-strip cover pages, and a paired analyst-detail companion workbook, and then proves the pattern end-to-end by migrating Board Summary's four metric modules to the new contract — without regressing the recipient groups that already consume Board Summary today.

The journey: define the contract → upgrade the composer → migrate Board Summary against both → wire YAML opt-out and confirm zero regression.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Module Render Contract** - Extend `BaseModule` with three new render hooks and bake in the empty-data guard pattern (completed 2026-05-05)
- [x] **Phase 2: ReportComposer Upgrades** - Assemble RAG-strip cover pages, per-module email bodies, and the paired analyst-detail workbook (completed 2026-05-06)
- [x] **Phase 3: Board Summary Module Migration** - Migrate the four board metric modules to the new contract and wire `board_summary.py` to the upgraded composer (completed 2026-05-06)
- [ ] **Phase 4: YAML Config and Regression Cutover** - Wire `jsonschema` runtime validation, ship the `analyst_detail` opt-out, and confirm zero regression for existing Board Summary recipient groups

## Parallelization Notes

Granularity is **coarse**; parallelization is **on**.

| Phase | Depends on | Can run in parallel with |
|-------|------------|---------------------------|
| 1 | Nothing | — |
| 2 | Phase 1 (consumes new abstract methods) | Phase 3 (modules implement against the same contract; the two converge in Phase 4) |
| 3 | Phase 1 (must implement the new abstract methods); soft-dep on Phase 2 for end-to-end smoke | Phase 2 |
| 4 | Phases 2 AND 3 (regression check + opt-out plumbing need both done) | — |

**Key opportunity:** After Phase 1 ships, Phases 2 and 3 are independently developable. Phase 3 module authors implement against the abstract methods from Phase 1; Phase 2 composer authors invoke those methods on a stub or example module. Final wiring (Phase 3's `board_summary.py` integration steps BOARD-05/06/07) merges the two streams. Phase 4 then gates the cutover.

## Phase Details

### Phase 1: Module Render Contract
**Goal**: Every metric module can describe how it renders into four channels (PDF section, Excel tabs, email panel, RAG strip), and the contract codifies the empty-data guard pattern so filtered-to-zero recipient groups never crash a render.
**Depends on**: Nothing (first phase)
**Requirements**: CONTRACT-01, CONTRACT-02, CONTRACT-03, CONTRACT-04, CONTRACT-05, QUALITY-01, QUALITY-03
**Success Criteria** (what must be TRUE):
  1. A test module subclass implementing `render_email_panel`, `render_analyst_tabs`, and `render_rag_strip_entry` instantiates and the abstract method signatures match the spec (HTML fragment string, list of `(sheet_name, DataFrame)` tuples, RAG cell dict)
  2. `ModuleData` carries the new render-output fields (driver narrative, analyst row data, RAG cell payload) and existing modules continue to compute without changes
  3. `reports/modules/base.py` docstrings and the `CLAUDE.md` "Adding a new module" section document the contract end-to-end including the empty-data guard pattern
  4. `management_summary.py:1853` `cov_pct` formats safely on `None` (no `TypeError` on a zero-licensed-asset run) — sibling fix to the 2026-05-04 `exception_rate` guard
  5. A grep audit of `reports/` finds no remaining `f"{...:.Xf}%"` or similar format spec interpolating an unguarded possibly-`None` metric value
**Plans**: 3 plans
- [ ] 01-01-PLAN.md — Helper modules: rag_utils.py + format_utils.py (Wave 1)
- [ ] 01-02-PLAN.md — BaseModule contract extension + package re-exports (Wave 2)
- [ ] 01-03-PLAN.md — QUALITY-01 cov_pct fix + QUALITY-03 audit + CLAUDE.md update (Wave 2)
**UI hint**: no

### Phase 2: ReportComposer Upgrades
**Goal**: `ReportComposer` drives all four render channels from the registered module list — emitting a RAG-strip cover, a per-module email body, and a paired analyst-detail companion workbook alongside the existing PDF and Excel.
**Depends on**: Phase 1
**Requirements**: COMPOSER-01, COMPOSER-02, COMPOSER-03, COMPOSER-04
**Success Criteria** (what must be TRUE):
  1. Running `ReportComposer.assemble_pdf()` against a module list produces a cover page with a RAG strip showing one cell per module (label + headline value + RAG color)
  2. `ReportComposer.assemble_email_body()` returns an HTML body composed of per-module panels in registration order, suitable as the Jinja2 template body for module-based reports, and renders correctly in Outlook / Gmail / Apple Mail with inline CSS only
  3. `ReportComposer.assemble_analyst_workbook()` writes a separate `.xlsx` with one tab per module (sourced from `render_analyst_tabs()`) plus a `_Metadata` tab containing scope, generated timestamp, and source module IDs
  4. `ReportComposer.run_all()` returns a dict with keys `pdf`, `excel`, `charts`, `metrics`, AND `analyst_excel`; existing keys are byte-for-byte unchanged on a regression baseline
**Plans**: 5 plans
- [x] 02-01-PLAN.md — Page-2 RAG strip insertion in assemble_pdf() + STATUS_ICON palette (COMPOSER-01) (Wave 1)
- [x] 02-02-PLAN.md — assemble_email_body() + build_email_body_modular() + template conditional (COMPOSER-02) (Wave 1)
- [x] 02-03-PLAN.md — assemble_analyst_workbook() with sheet-collision suffix and D-25 opt-out (COMPOSER-03) (Wave 1)
- [x] 02-04-PLAN.md — run_full_pipeline() orchestrator + board_summary/management_summary run_report() return-dict extension (COMPOSER-04) (Wave 2)
- [x] 02-05-PLAN.md — Phase 2 regression-snapshot + per-module exception-isolation test (D-28, D-29) (Wave 3)
**UI hint**: no

### Phase 3: Board Summary Module Migration
**Goal**: The four existing board metric modules implement the new contract end-to-end, `board_summary.py` integrates the upgraded composer outputs (RAG strip cover, per-module email panels, paired analyst workbook), and the empty-data guard discipline is enforced at every render entry point.
**Depends on**: Phase 1 (modules need the abstract methods); soft-dep on Phase 2 for end-to-end smoke wiring of BOARD-05/06/07
**Requirements**: BOARD-01, BOARD-02, BOARD-03, BOARD-04, BOARD-05, BOARD-06, BOARD-07, QUALITY-02
**Success Criteria** (what must be TRUE):
  1. Each of the four board modules (`scan_coverage_sla_module`, `critical_remediation_sla_module`, `high_risk_assets_module`, `aged_vulns_assets_module`) implements all three new render methods and produces an analyst tab populated with the contract-specified columns (hostname/IPv4/FQDN/scan-date for scan coverage; asset/plugin/days-overdue/owner/due-date for critical remediation; etc.)
  2. The Board Summary PDF cover page renders the RAG strip from `COMPOSER-01` instead of the previous thin cover
  3. The Board Summary email body renders four per-module panels from `COMPOSER-02` (gauge image, headline %, RAG color/label, "what's driving it" line) in place of today's bare delivery
  4. Every Board Summary delivery emits the analyst companion workbook from `COMPOSER-03` as an additional attachment alongside the existing PDF and Excel
  5. Each render method called against a zero-row `ModuleData` returns a sensible empty/N-A representation (dash placeholder, gray RAG, "No data in scope" driver line) instead of raising
**Plans**: 6 plans
- [x] 03-01-PLAN.md — Foundation: populate_rag_strip helper, unified RAG-strip PDF cover, email_inline_images bundle key, bundle-driven email_sender body+analyst routing, CLAUDE.md doc paragraph (Wave 1)
- [x] 03-02-PLAN.md — scan_coverage_sla_module migration end-to-end (higher_is_better) (Wave 2)
- [x] 03-03-PLAN.md — critical_remediation_sla_module migration end-to-end (higher_is_better, finding-level analyst rows) (Wave 2)
- [x] 03-04-PLAN.md — high_risk_assets_module migration end-to-end (lower_is_better, contributing_finding_ids join) (Wave 2)
- [x] 03-05-PLAN.md — aged_vulns_assets_module migration end-to-end (lower_is_better, single tab + worst_severity column) (Wave 2)
- [x] 03-06-PLAN.md — Phase 3 regression snapshot extension (QUALITY-02 zero-row coverage) + smoke script real-panel update (Wave 3)
**UI hint**: no

### Phase 4: YAML Config and Regression Cutover
**Goal**: `delivery_config.yaml` supports the `analyst_detail: false` opt-out, every config load runs `jsonschema` validation and exits loud on misconfigured groups, and all currently-configured Board Summary recipient groups receive non-regressing PDFs and Excel — with the only intentional delta being the added analyst Excel attachment and the upgraded email body / cover page.
**Depends on**: Phases 2 and 3 (regression check + opt-out plumbing both required)
**Requirements**: CONFIG-01, CONFIG-02, CONFIG-03, CONFIG-04, BOARD-08
**Success Criteria** (what must be TRUE):
  1. `delivery_config.schema.yaml` defines an optional per-group `analyst_detail` boolean field that defaults to `true` when omitted, and a sample group in `delivery_config.yaml` demonstrates the opt-out
  2. `run_all.py` and `scheduler.py` both invoke `jsonschema.validate()` on `delivery_config.yaml` at startup; a misconfigured group exits non-zero with an error naming the offending group and field (e.g. `frequency: weeky` is caught at startup, not at run time)
  3. A recipient group with `analyst_detail: false` receives the standard PDF, standard Excel, and email panels but no analyst companion workbook
  4. Re-running each currently-configured Board Summary recipient group (`UC Engineering`, `Workstation`, `Enterprise Virtualization`, etc.) produces a delivery whose PDF metrics, Excel rows, and recipient list match the pre-v1 baseline, with the only deltas being: (a) added analyst Excel attachment, (b) upgraded email body, (c) RAG-strip cover page
**Plans**: TBD
**UI hint**: no

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 (with Phases 2 and 3 parallelizable after Phase 1 ships).

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Module Render Contract | 3/3 | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades | 5/5 | Complete | 2026-05-06 |
| 3. Board Summary Module Migration | 6/6 | Complete | 2026-05-06 |
| 4. YAML Config and Regression Cutover | 0/TBD | Not started | - |
