# Requirements: Vulnerability Management Reporting Suite

**Defined:** 2026-05-05
**Core Value:** Right metric, right audience, right channel — without writing a new report each time.
**Milestone:** v1 — Modular Reporting Framework (pattern-establishing; Board Summary as exemplar)

## v1 Requirements

Each requirement maps to exactly one phase of the v1 roadmap.

### Module Render Contract (CONTRACT)

Extends `BaseModule` so every metric module can render itself to four channels.

- [ ] **CONTRACT-01**: `BaseModule` defines an abstract `render_email_panel(data: ModuleData) -> str` method returning an HTML fragment that contains a base64-CID gauge image, headline percentage, RAG color/label, and a 1-line "what's driving it" string
- [ ] **CONTRACT-02**: `BaseModule` defines an abstract `render_analyst_tabs(data: ModuleData) -> list[tuple[str, pd.DataFrame]]` method returning one or more (sheet_name, DataFrame) tuples of pivot-friendly drill-down rows for analysts
- [ ] **CONTRACT-03**: `BaseModule` defines an abstract `render_rag_strip_entry(data: ModuleData) -> dict` method returning the cover-page strip cell (`{label, headline_value, rag_color, rag_label}`)
- [ ] **CONTRACT-04**: `ModuleData` dataclass carries the additional render outputs needed by the new hooks (driver-narrative string, analyst row data, RAG cell payload) without forcing existing modules to recompute
- [ ] **CONTRACT-05**: The contract is documented in `reports/modules/base.py` docstrings and a new entry in `CLAUDE.md` "Adding a new module" section, including the empty-data guard pattern that all four render methods MUST follow

### Report Composer Upgrades (COMPOSER)

Drives all four render channels from the registered module list.

- [ ] **COMPOSER-01**: `ReportComposer.assemble_pdf()` emits a cover page that includes title, scope banner, generated timestamp, and a RAG strip showing every module at a glance (one cell per module: label + headline value + RAG color)
- [ ] **COMPOSER-02**: `ReportComposer.assemble_email_body()` (new method) builds an HTML email body composed of per-module panels in registration order, suitable for inlining as the Jinja2 template body for groups using module-based reports
- [ ] **COMPOSER-03**: `ReportComposer.assemble_analyst_workbook()` (new method) emits a separate `.xlsx` file containing one tab per module (sourced from each module's `render_analyst_tabs()` output) plus a `_Metadata` tab with run scope, generated timestamp, and the source module IDs
- [ ] **COMPOSER-04**: `ReportComposer.run_all()` return dict gains an `analyst_excel` path entry alongside the existing `pdf`, `excel`, `charts`, and `metrics` keys; existing keys remain unchanged for backward compatibility

### Board Summary Module Migration (BOARD)

Each of the four existing board metric modules implements the new contract; the Board Summary report integrates the new render channels.

- [ ] **BOARD-01**: `scan_coverage_sla_module` implements `render_email_panel`, `render_analyst_tabs`, and `render_rag_strip_entry`; the analyst tab lists every overdue licensed asset with hostname, IPv4, FQDN, last_licensed_scan_date, days_since_licensed_scan, and Application/BU tag
- [ ] **BOARD-02**: `critical_remediation_sla_module` implements all three contract methods; the analyst tab lists every overdue critical finding with asset, plugin, days overdue, first found, owner tag, and remediation due date
- [ ] **BOARD-03**: `high_risk_assets_module` implements all three contract methods; the analyst tab lists every asset that crossed the high-risk threshold with hostname, BU, count of Crit/High open >30d, and the contributing finding IDs
- [ ] **BOARD-04**: `aged_vulns_assets_module` implements all three contract methods; the analyst tab lists every asset with at least one Med/High/Crit vuln open >90d with hostname, BU, oldest finding age, count of aged findings, and contributing plugins
- [ ] **BOARD-05**: `board_summary.py` PDF output uses the new RAG-strip cover from `COMPOSER-01` (replacing the current thin cover page)
- [ ] **BOARD-06**: `board_summary.py` email body uses the new per-module panel composition from `COMPOSER-02` (replacing today's bare delivery)
- [ ] **BOARD-07**: `board_summary.py` always emits the analyst companion workbook from `COMPOSER-03` and includes it as an additional attachment alongside the existing PDF and Excel
- [ ] **BOARD-08**: All currently-configured Board Summary recipient groups (`UC Engineering`, `Workstation`, `Enterprise Virtualization`, etc.) continue to receive non-regressing PDFs and Excel; the only delta to existing delivery is the added analyst Excel attachment and the upgraded email body / cover page

### YAML Configuration & Validation (CONFIG)

Recipient groups can opt out of the analyst companion; misconfigured YAML fails loud on startup.

- [ ] **CONFIG-01**: `delivery_config.schema.yaml` extended with an optional per-group `analyst_detail: boolean` field that defaults to `true` when omitted
- [ ] **CONFIG-02**: `run_all.py` and `scheduler.py` startup paths parse `delivery_config.yaml` against the JSON schema using the `jsonschema` library; misconfigured YAML exits with a clear error message naming the offending group and field
- [ ] **CONFIG-03**: When `analyst_detail: false` is set on a recipient group, that group's `board_summary` delivery omits the analyst companion workbook (PDF + standard Excel + email panels still ship)
- [ ] **CONFIG-04**: A documented example group in `delivery_config.yaml` shows the `analyst_detail: false` opt-out so future groups can copy-paste

### Empty-Data Hardening (QUALITY)

Folded in because the same code paths are being touched by the modular work.

- [ ] **QUALITY-01**: `management_summary.py:1853` `cov_pct` format string is guarded against `None` using the same pattern used to fix `exception_rate` on 2026-05-04 (sibling fix)
- [ ] **QUALITY-02**: Every new module render method (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) returns a sensible empty/N-A representation rather than raising when invoked on a zero-row `ModuleData` (e.g., dash placeholder, gray RAG, "No data in scope" driver line)
- [ ] **QUALITY-03**: A grep-style audit of `reports/` confirms no other `f"{...:.Xf}%"` format spec interpolates a possibly-`None` metric value; any survivors are guarded with the same pattern (audit findings are added as commits to the relevant phase)

## v2 Requirements

Acknowledged and tracked. Re-evaluated after v1 ships.

### Pattern Generalization (GEN)

- **GEN-01**: Migrate `management_summary` to the new module render contract (replacing its bespoke email/PDF rendering)
- **GEN-02**: Migrate `ops_remediation` to the new module render contract (the 7-tab Excel becomes a composition of analyst-detail tabs)
- **GEN-03**: `delivery_config.yaml` supports inline `modules: [scan_coverage_sla, critical_remediation_sla]` lists per group, in addition to named report bundles, so analysts can compose ad-hoc reports without code changes
- **GEN-04**: Named report bundles are themselves YAML-defined (a `reports.<slug>.modules` map) rather than hardcoded in `board_summary.py` / `management_summary.py`

### New KPI/KRI Catalog (CATALOG)

- **CATALOG-01**: Per-analyst-request, build the next set of KPI/KRI modules (specific list TBD post-v1, driven by the analyst → developer → YAML workflow)

### Performance & Operational (PERF)

- **PERF-01**: `enrich_vulns_with_assets` per-batch caching so it runs once per group rather than once per report (~9× current cost on a 180k-row frame)
- **PERF-02**: Per-day cache wipe handles local-midnight crossover so long-running batches don't lose pre-fetched data partway through
- **PERF-03**: Log rotation hardening — observed log directory has no rotation enforcement on long-running daemon mode
- **PERF-04**: Tag value typo detection — currently `Owner=Configuration Mangement` typo silently filters to zero rows; surface a warning when a configured tag value is not present in the asset tag set

### Reports Listed-but-Not-Built (LEGACY)

- **LEGACY-01**: Re-evaluate the 6 reports in `CLAUDE.md` deliverables checklist (`executive_kpi`, `sla_remediation`, `asset_risk`, `patch_compliance`, `trend_analysis`, `plugin_cve`) — several may be expressible as module bundles rather than fresh report scripts once the v1 framework is in place

## Out of Scope

Explicitly excluded from v1. Recorded so they don't drift back in mid-milestone.

| Feature | Reason |
|---------|--------|
| Migrating `ops_remediation` / `management_summary` to the new contract | Prove the pattern with Board Summary first; pattern is still being defined in v1 |
| YAML-driven module composition (inline `modules:` lists) | v1 keeps module lists hardcoded in `board_summary.py` so the contract is exercised before adding the user-facing config surface; lands in v2 (GEN-03/04) |
| Adding new KPI/KRI modules beyond the four existing board metrics | The framework is what's being built in v1, not the catalog; new modules per analyst request post-v1 |
| `enrich_vulns_with_assets` performance pass | Real fix is per-batch enriched-frame caching; deferred until module pattern stabilizes (v2 PERF-01) |
| Per-day cache wipe across midnight boundaries | Operational impact is small; deferred (v2 PERF-02) |
| Building any of the 6 unbuilt reports listed in CLAUDE.md | Several may not be needed once the v1 framework lets analysts assemble equivalents from modules |
| Replacing WeasyPrint, switching SMTP libs, or any tech-stack swap | Stack is locked per PROJECT.md Constraints |
| New Tenable API integrations beyond the existing exports + recast rules | Out of scope for a framework milestone |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CONTRACT-01 | Phase 1 | Pending |
| CONTRACT-02 | Phase 1 | Pending |
| CONTRACT-03 | Phase 1 | Pending |
| CONTRACT-04 | Phase 1 | Pending |
| CONTRACT-05 | Phase 1 | Pending |
| COMPOSER-01 | Phase 2 | Pending |
| COMPOSER-02 | Phase 2 | Pending |
| COMPOSER-03 | Phase 2 | Pending |
| COMPOSER-04 | Phase 2 | Pending |
| BOARD-01 | Phase 3 | Pending |
| BOARD-02 | Phase 3 | Pending |
| BOARD-03 | Phase 3 | Pending |
| BOARD-04 | Phase 3 | Pending |
| BOARD-05 | Phase 3 | Pending |
| BOARD-06 | Phase 3 | Pending |
| BOARD-07 | Phase 3 | Pending |
| BOARD-08 | Phase 4 | Pending |
| CONFIG-01 | Phase 4 | Pending |
| CONFIG-02 | Phase 4 | Pending |
| CONFIG-03 | Phase 4 | Pending |
| CONFIG-04 | Phase 4 | Pending |
| QUALITY-01 | Phase 1 | Pending |
| QUALITY-02 | Phase 3 | Pending |
| QUALITY-03 | Phase 1 | Pending |

**Coverage:**
- v1 requirements: 24 total
- Mapped to phases: 24 ✓
- Unmapped: 0

---
*Requirements defined: 2026-05-05*
*Last updated: 2026-05-05 after roadmap creation (Traceability populated)*
