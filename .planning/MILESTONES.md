# Milestones

Living record of shipped versions. Each entry summarizes scope, accomplishments, and key outcomes. Full milestone details live in `.planning/milestones/v[X.Y]-ROADMAP.md` and `.planning/milestones/v[X.Y]-REQUIREMENTS.md`.

---

## v1.0 — Modular Reporting Framework

**Shipped:** 2026-05-08
**Phases:** 4 | **Plans:** 19 | **Quick tasks:** 1
**Timeline:** 4 days (2026-05-05 → 2026-05-08)
**Git range:** `ea709a1` (Phase 1 first feat) → `028f188` (Phase 4 UAT close)
**Files changed:** 96 | **LOC delta:** +27,072 / −390

**Delivered:** A modular metric-rendering framework where each `BaseModule` subclass renders itself into 4 channels (PDF section, Excel tabs, email panel, analyst drill-down) — proven end-to-end against the Board Summary report's 4 metric modules with backward-compatible delivery to existing recipient groups.

**Key accomplishments:**
- **Module render contract** extended `BaseModule` with three new abstract methods (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) plus three new `ModuleData` fields (`driver_narrative`, `analyst_rows`, `rag_strip`). Empty-data guard pattern codified in CLAUDE.md and exercised by every render method.
- **`ReportComposer` upgrades** added `assemble_email_body()` (per-module HTML panels), `assemble_analyst_workbook()` (per-module Excel tabs + `_Metadata`), unified RAG-strip cover page, and `run_full_pipeline()` orchestrator that emits a typed bundle. D-22 bundle-driven email/analyst routing — no slug allowlists.
- **Board Summary migration** ported all 4 metric modules (`scan_coverage_sla`, `critical_remediation_sla`, `high_risk_assets`, `aged_vulns_assets`) to the new contract. Real-Tenable UAT-confirmed: PDF + standard Excel + analyst Excel + email panels all render correctly; populated and zero-data paths both clean.
- **YAML schema validation** wired `jsonschema` enforcement into every config load (`run_all.py:_load_config`). `_validate_group()` body REPLACED with a thin schema shim (single source of truth). Misconfigured YAML exits non-zero with offending group + field named.
- **`analyst_detail: false` opt-out** plumbed through `run_all.py:run_group()` → `board_summary.run_report()` → `composer.run_full_pipeline(generate_analyst=)`. No new abstractions; existing kwargs only.
- **Cutover smoke** (`scripts/smoke_board_summary_cutover.py`) is a sub-5-second deterministic structural-shape regression bar against 3 committed baselines. `_NoLiveTenable` sentinel hard-guards against accidental live API calls. Baselines store counts + booleans only — no metric values, no row-level data — per D-04-08 PII guard.

**Verification:**
- 4/4 phase verifications PASSED
- 3/3 phase UATs CLOSED (Phase 1 verifier-only; 2/3/4 with explicit UATs at 6/6 and 7/7)
- 38 tests green across 4 suites at milestone close
- 0 DRIFT against committed structural baselines

**Notable surprises:**
- WeasyPrint flex implementation consumes ~33-37mm of phantom space beyond the visible cell-width math in 65.1 — discovered via empirical bisect during a UAT-driven cover-layout fix. Pinned cells at 55mm with documented inline comment.
- Headline metric values drift daily with vulnerability churn — locking them in baselines would create false-positive alerts. D-04-05 was REVISED before Phase 4 planning to structural-only snapshots; visual operator confirmation remains the value-correctness gate.
- pandas 3.0 Copy-on-Write shifted the dtype-replacement semantics for chained-setter patterns. `.loc[:, col]=` preserved float64 where `df[col]=` had replaced it with int64. `.assign()` was the only pattern preserving int64 dtype AND zero ChainedAssignmentError warnings — documented at 3 risk_score sites.

**Carried to v2 (acknowledged backlog):**
- GEN-01/02: Migrate `management_summary` and `ops_remediation` to the new module contract.
- GEN-03/04: YAML-driven module composition (`modules: [...]` lists; `reports.<slug>.modules` map).
- PERF-01..04: per-batch `enrich_vulns_with_assets` cache, per-day cache midnight handling, log rotation, tag-typo detection.
- LEGACY-01: re-evaluate the 6 unbuilt reports listed in CLAUDE.md as candidate module bundles.
- Cosmetic janitorial: `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants in `run_all.py:76,90`.
- Deferred design: cover-page redesign (template-based on Report Title; "Generated" + Data Protection Label to footer).

**Archive:**
- [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md) — full phase + plan details
- [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md) — all 24 requirements traceability
