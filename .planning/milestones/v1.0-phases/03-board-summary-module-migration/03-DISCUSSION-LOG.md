---
phase: 03-board-summary-module-migration
gathered: 2026-05-06T08:30:00Z
mode: discuss
gray_areas_total: 9
gray_areas_discussed: 9
---

# Phase 3 — Discussion Log

User chose to discuss all 9 gray areas. Sequence: architecture (Q1, Q9) → output design (Q2, Q4, Q6) → implementation (Q3, Q5, Q7) → process (Q8).

## Q1 — PDF cover architecture

**Question:** How should the new RAG strip relate to the existing thin cover (which Phase 2 inserted as page 2 between the existing cover and module sections)?

**Answer:** A) Strict replacement. Page 1 IS the RAG strip with title + scope as a header band above the cells. Module sections start on page 2.

**Captured as:** D-01.

## Q9 — Email-body modular-vs-legacy selector

**Initial framing:** Where should the legacy-vs-modular email body selector live? (slug allowlist / caller flag / bundle self-describing / YAML opt-in)

**User clarification:** *"We want to eventually move away from using 'board_summary' as a slug and define the modules to use. What work can we do now that would facilitate that move? Can we maintain the current workflow using the slugs in delivery_config.yaml until all base modules are designed and created?"*

**Discussion:** The user's directional intent matches the design `composer.run_full_pipeline()` was already shaped for. The right answer is option C (bundle self-describes) because it requires no slug allowlists and lets v2's planned YAML-driven module-list groups light up automatically. Slug-based YAML stays unchanged in Phase 3; v2 adds a `modules: [...]` shape additively.

**Answer:** C) Bundle self-describes via non-empty `email_body_html`. Same self-describing pattern for analyst workbook attachment. No slug allowlists anywhere. Document the v2 alignment guard in CLAUDE.md.

**Captured as:** D-18, D-19, D-20, D-21, D-22, D-23, D-24.

## Q2 — Email panel HTML structure

### Q2a — Layout & content density

**Question:** Vertical stack vs horizontal split, with or without per-BU breakdown?

**Answer:** C) Horizontal split, headline only. Gauge ~150px left, headline + RAG band + driver text ~430px right. No per-BU breakdown in email panels.

**Captured as:** D-02, D-03.

### Q2b — Gauge embed strategy

**Question:** CID-attached MIME parts vs inline base64 data URIs vs both?

**Answer:** A) CID attachments. Composer adds `email_inline_images` bundle key; `delivery/email_sender.py` extends `_collect_chart_pngs` to consume it. Required for Outlook desktop on Windows.

**Captured as:** D-04.

## Q4 — Driver narrative format

**Question:** Hand-coded per module / shared templated formatter / LLM-generated / hybrid?

**Answer:** A) Hand-coded per module. Each module's `compute()` builds its own narrative. Plans 03-02..05 spell out the exact template per module. Empty-data fallback uses `NO_DATA_DRIVER`.

**Captured as:** D-06, D-07.

## Q6 — RAG strip headline_value format

**Question:** Pure % / pure count / hybrid % above count below / context-driven mix?

**Answer:** A) Pure percentage. Each cell shows `safe_pct(metric_value)`. Empty data uses `NO_DATA_HEADLINE = "—"`.

**Captured as:** D-08, D-09.

## Q3 — Where the new ModuleData fields get populated

**Question:** Fully inside compute() / shared post-processor for all three / hybrid (helper for RAG, per-module for the rest) / decorator?

**Answer:** C) Hybrid. Helper in `board_report_utils.py` handles `rag_strip` only; `driver_narrative` and `analyst_rows` stay per-module. Note for planner: `rag_status_from_value()` may need a `direction` arg.

**Captured as:** D-05.

## Q5 — Analyst tab specifics

**Question:** Granularity (asset vs finding) / sort order / sub-tab splits / dedup strategy.

**Answer:** A) Per-module granularity, severity-desc sort, single tab per module (Aged Vulns gets a `worst_severity` column rather than sub-tabs), dedup via `deduplicate_assets_by_name` on asset-level tabs only.

**Captured as:** D-10, D-11, D-12, D-13, D-14.

## Q7 — Empty-data behavior (QUALITY-02)

### Q7a — Email panel zero-row visual

**Question:** Render a placeholder panel vs skip the panel?

**Answer:** A) Render placeholder panel. Same horizontal-split structure with greyed gauge box, "—" headline, gray "No Data" RAG band, "No data in scope." driver. Keeps four-panel rhythm consistent.

**Captured as:** D-15.

### Q7b — Excel tab zero-row behavior

**Question:** Keep existing per-module Excel empty behavior vs standardise?

**Answer:** B) Standardise. All four modules emit a single "No data in scope" row when empty. Behavior change with regression-baseline visibility — flagged for the planner.

**Captured as:** D-16.

## Q8 — Plan structure & parallelisation

**Question:** End-to-end per module / render-method-per-wave / per-(module, method) bundles / single plan?

**Answer:** A) End-to-end per module. 6 plans (foundation + 4 module migrations + regression). Sequential by intent for ease of demo; executor may wave-parallelize 03-02..05 if file-overlap allows.

**Captured as:** D-17.

## Decisions Index (D-01 through D-24)

| ID | Source | Summary |
|----|--------|---------|
| D-01 | Q1 | Strict cover replacement — page 1 IS the RAG strip with header band |
| D-02 | Q2a | Horizontal-split email panels (gauge left, text right) |
| D-03 | Q2a | No per-BU breakdown in email panels |
| D-04 | Q2b | CID-attached gauge images via `email_inline_images` bundle key |
| D-05 | Q3 | Hybrid field-population — helper for rag_strip, per-module for the rest |
| D-06 | Q4 | Hand-coded driver narratives per module |
| D-07 | Q4 | Empty-data driver fallback uses NO_DATA_DRIVER |
| D-08 | Q6 | RAG strip headline = pure percentage |
| D-09 | Q6 | Empty-data headline fallback uses NO_DATA_HEADLINE ("—") |
| D-10 | Q5 | Analyst tab granularity per-module (asset for SC/HRA/AVA, finding for CRSLA) |
| D-11 | Q5 | Worst-first sort on metric-relevant column |
| D-12 | Q5 | Single tab per module — Aged Vulns gets worst_severity column |
| D-13 | Q5 | Dedup via deduplicate_assets_by_name on asset-level tabs only |
| D-14 | Q5 | analyst_rows = list[tuple[str, df]] (single-element in v1) |
| D-15 | Q7a | Empty-row email panel renders placeholder, not skip |
| D-16 | Q7b | Excel tabs uniformly emit "No data in scope" row when empty |
| D-17 | Q8 | 6 plans, end-to-end per module, sequential by intent |
| D-18 | Q9 | Bundle self-describes email-body path; no slug allowlists |
| D-19 | Q9 | Bundle self-describes analyst attachment |
| D-20 | Q9 | composer.run_full_pipeline() stays slug-agnostic |
| D-21 | Q9 | board_summary.py minimal touch |
| D-22 | Q9 | Document bundle-driven dispatch in CLAUDE.md (plan 03-01) |
| D-23 | Q9 | No slug allowlists allowed (code-review gate) |
| D-24 | Q9 | delivery_config.yaml schema unchanged in Phase 3 |

## Deferred Ideas (raised during discussion, NOT acted on)

- v2 YAML-driven module composition (`groups[].modules: [...]`) — explicitly deferred per D-24
- Per-BU breakdown in email panels — D-03 defers; future email-template review
- Wider email card — Phase 2 UAT clarification; future review
- LLM-generated driver narratives — D-06 explicitly rejects in v1
- ops_remediation.py migration to module pattern — v2
- management_summary.py module migration — Phase 2 Option-2 deferral; v2
