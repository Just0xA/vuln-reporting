---
phase: 03-board-summary-module-migration
phase_number: 3
phase_name: Board Summary Module Migration
gathered: 2026-05-06T08:30:00Z
mode: discuss
gray_areas_total: 9
gray_areas_discussed: 9
decisions_total: 17
status: ready_for_planning
---

# Phase 3 Context — Board Summary Module Migration

## Phase Goal (from ROADMAP.md)

The four existing board metric modules implement the new contract end-to-end, `board_summary.py` integrates the upgraded composer outputs (RAG strip cover, per-module email panels, paired analyst workbook), and the empty-data guard discipline is enforced at every render entry point.

## Requirements In Scope

- **BOARD-01..04** — each of the four board modules (`scan_coverage_sla`, `critical_remediation_sla`, `high_risk_assets`, `aged_vulns_assets`) implements all three new render methods (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) and produces an analyst tab populated with the contract-specified columns.
- **BOARD-05** — `board_summary.py` PDF output uses the new RAG-strip cover from `COMPOSER-01` (replacing the current thin cover page).
- **BOARD-06** — `board_summary.py` email body uses the new per-module panel composition from `COMPOSER-02` (replacing today's bare delivery).
- **BOARD-07** — `board_summary.py` always emits the analyst companion workbook from `COMPOSER-03` and includes it as an additional attachment alongside the existing PDF and Excel.
- **QUALITY-02** — every new module render method returns a sensible empty/N-A representation rather than raising when invoked on a zero-row `ModuleData`.

## What's Already Locked from Phase 1 + 2 (no re-discussion)

| Layer | Surface | Where |
|-------|---------|-------|
| Phase 1 | `BaseModule.render_email_panel(data, config) -> str` (concrete no-op default) | `reports/modules/base.py` |
| Phase 1 | `BaseModule.render_analyst_tabs(data, config) -> list[tuple[str, pd.DataFrame]]` | `reports/modules/base.py` |
| Phase 1 | `BaseModule.render_rag_strip_entry(data, config) -> dict` (gray default; honors `data.rag_strip` when populated) | `reports/modules/base.py` |
| Phase 1 | `ModuleData.driver_narrative: str`, `ModuleData.analyst_rows: list[tuple[str, DataFrame]]`, `ModuleData.rag_strip: dict` | `reports/modules/base.py` |
| Phase 1 | `rag_utils.STATUS_COLOR / STATUS_LABEL / STATUS_ICON / NO_DATA_HEADLINE / NO_DATA_DRIVER / build_rag_strip_entry / rag_status_from_value` | `reports/modules/rag_utils.py` |
| Phase 1 | `format_utils.safe_pct / safe_int / safe_format` | `reports/modules/format_utils.py` |
| Phase 2 | `ReportComposer.assemble_email_body(results) -> str` (panels-only fragment) | `reports/modules/composer.py:1108` |
| Phase 2 | `ReportComposer.assemble_analyst_workbook(results, output_path)` | `reports/modules/composer.py:856` |
| Phase 2 | `ReportComposer._build_rag_strip_page(results) -> str` (page-2 RAG strip) | `reports/modules/composer.py:690` |
| Phase 2 | `ReportComposer.run_full_pipeline(results, output_dir, *, slug, ...)` (4-channel orchestrator returning `email_body_html`, `analyst_workbook_path`, etc.) | `reports/modules/composer.py:1276` |
| Phase 2 | `delivery.email_template.build_email_body_modular(group_config, report_outputs, module_panels_html, ...)` (sibling renderer) | `delivery/email_template.py:425` |
| Phase 2 | `templates/report_email.html` SECTION 3 carries `{% if module_panels_html %}{% else %}<KPI tiles>{% endif %}` | `templates/report_email.html:98-155` |
| Phase 2 | `reports/board_summary.py:run_report()` already calls `composer.run_full_pipeline()` and returns the six-key bundle (`pdf, excel, charts, metrics, analyst_excel, email_body_html`) | `reports/board_summary.py:289-302` |

These artifacts are STABLE. Phase 3 plans MUST NOT re-design them.

## Decisions

### Area 1 — PDF cover architecture (Q1)

- **D-01: Strict replacement of the existing thin cover.** Page 1 of board_summary's PDF IS the RAG strip with a header band above the cells (title + scope + generated timestamp). Module sections start on page 2. The Phase 2 separate "cover page 1 + RAG strip page 2" structure collapses into one unified cover.
  - The Phase 2 invariant D-01 ("Page 1 cover stays unchanged — `_PDF_COVER_TEMPLATE` is not edited") is **superseded for board_summary** by this Phase 3 decision. `_PDF_COVER_TEMPLATE` either gets merged into `_PDF_RAG_STRIP_TEMPLATE` or one of them is deleted; the planner picks the cleanest surgery.
  - `assemble_pdf()` either gains a `cover_mode` parameter or hardcodes the new unified layout. The planner picks based on whether `management_summary` (which uses its own bespoke `_build_pdf` flow, not `assemble_pdf`) needs to retain the legacy cover; default expectation is that the unified cover becomes the only mode and `_PDF_COVER_TEMPLATE` goes away.

### Area 2 — Email panel HTML structure (Q2)

- **D-02: Horizontal split layout.** Each panel is a `<table>`-based two-cell row: gauge image left at ~150px, headline + RAG band + driver-sentence text right at ~430px. Inline CSS only; `width=""` attributes on `<td>` per the project's existing email-template convention. 4 panels stack vertically inside the existing 620px outer card.
- **D-03: No per-BU breakdown in email panels.** The panel keeps the four BOARD-06 ingredients (gauge, headline %, RAG color/label, driver line) and nothing else. Per-BU detail stays in the PDF section page and the analyst workbook only — recipients drill into those for the breakdown.
- **D-04: CID-attached gauge images.** Composer adds a new bundle key `email_inline_images: list[dict]` with `{"cid": str, "path": Path}` entries. `delivery/email_sender.py` extends its existing `_collect_chart_pngs` MIME-attachment path to also consume `email_inline_images`. Each panel's `<img>` references its gauge by `cid:{module_id}_gauge`. Outlook desktop on Windows (Word render engine) requires CID — base64 data URIs are stripped — so this is a hard requirement, not a preference.

### Area 3 — Where the new ModuleData fields get populated (Q3)

- **D-05: Hybrid — shared helper for `rag_strip` only; per-module for `driver_narrative` and `analyst_rows`.** A new helper in `reports/modules/board_report_utils.py` (e.g. `populate_rag_strip(data, *, display_name, metric_value, headline_value, threshold_green, threshold_yellow, direction)`) classifies the metric against thresholds and writes `data.rag_strip = build_rag_strip_entry(...)`. `driver_narrative` and `analyst_rows` are hand-built inside each module's `compute()`.
  - Note for the planner: `rag_status_from_value()` may need a `direction` argument added if not already present — `scan_coverage_sla` and `critical_remediation_sla` are higher-is-better; `high_risk_assets` and `aged_vulns_assets` are lower-is-better. Verify before plan-writing.

### Area 4 — Driver narrative format (Q4)

- **D-06: Hand-coded per module.** Each module's `compute()` builds its own narrative from its specific metrics. Different modules can emphasize different angles (Scan Coverage talks about overdue counts + worst BU; Critical Remediation talks about specific overdue findings + window; Aged Vulns talks about oldest finding + count).
- **D-07: Empty-data driver fallback.** When the module's compute() sees zero in-scope rows, set `data.driver_narrative = NO_DATA_DRIVER` ("No data in scope.") from `reports/modules/rag_utils.py`.
- The Phase 3 plans MUST specify the exact narrative template per module so authors don't drift. Sample shapes (illustrative — planner refines):
  - Scan Coverage SLA: *"{good_bu} at {good_bu_pct}; {worst_bu} dragging the average down ({overdue_count} of {total_count} licensed assets overdue)."*
  - Critical Remediation SLA: *"{fixed_in_window} of {opened_in_window} fixed within 15-day window; {overdue_count} critical findings still open past SLA."*
  - High-Risk Assets: *"{count} assets crossed the high-risk threshold (≥10 Crit/High open >30d); worst contributor: {worst_bu} with {worst_bu_count} assets."*
  - Aged Vuln Assets: *"{count} assets carry at least one Med+ vuln open >90 days; oldest finding: {oldest_age} days; worst BU: {worst_bu}."*

### Area 5 — RAG strip headline_value format (Q5)

- **D-08: Pure percentage.** Every cell shows the metric percentage and nothing else.
  - Scan Coverage SLA: `safe_pct(scan_coverage_pct)` → e.g. `97.3%`
  - Critical Remediation SLA: `safe_pct(remediation_sla_pct)` → e.g. `92.4%`
  - High-Risk Assets: `safe_pct(high_risk_pct)` → e.g. `0.4%`
  - Aged Vuln Assets: `safe_pct(aged_assets_pct)` → e.g. `2.7%`
- **D-09: Empty-data headline fallback.** When the metric value is `None` / `NaN`, `safe_pct(None) → "—"` (NO_DATA_HEADLINE) is the displayed headline; RAG band falls through to `STATUS_LABEL["no_data"]` gray.

### Area 6 — Analyst tab specifics (Q5)

- **D-10: Per-module granularity.**
  - Scan Coverage SLA — **asset-level** rows; columns: hostname, IPv4, FQDN, last_licensed_scan_date, days_since_licensed_scan, Application BU.
  - Critical Remediation SLA — **finding-level** rows; columns: asset, plugin, days overdue, first_found, owner_tag, remediation due_date.
  - High-Risk Assets — **asset-level** rows; columns: hostname, BU, count of Crit/High open >30d, contributing finding IDs (comma-joined cell).
  - Aged Vuln Assets — **asset-level** rows; columns: hostname, BU, oldest finding age, count of aged findings, contributing plugins (comma-joined cell), worst_severity.
- **D-11: Worst-first sort on the metric-relevant column.** Scan Coverage by `days_since_licensed_scan` desc; Critical Remediation by `days overdue` desc; High-Risk Assets by `crit_high_open_count` desc; Aged Vulns by `oldest finding age` desc.
- **D-12: Single tab per module.** Aged Vulns gets a `worst_severity` column rather than splitting into 3 sub-tabs (`Aged - Critical / High / Medium`). Reduces workbook tab count; analyst can still filter in Excel.
- **D-13: Asset-level dedup via `deduplicate_assets_by_name`.** Apply to the three asset-level tabs (Scan Coverage, High-Risk Assets, Aged Vuln Assets). Critical Remediation finding-level tab does NOT dedup (each finding row is distinct).
- **D-14: Output shape.** Each module's `compute()` populates `data.analyst_rows = [(sheet_name, df)]` (single-element list). `render_analyst_tabs(data, config)` returns `data.analyst_rows`. List-of-tuples leaves the door open for any future module that legitimately needs sub-tabs.

### Area 7 — Empty-data behavior (Q7) — QUALITY-02

- **D-15: Email panel placeholder.** Empty-row modules render the same horizontal-split panel structure with: gauge cell replaced by a gray "No data" box (no gauge PNG generated for empty modules), headline `—`, gray `STATUS_LABEL["no_data"]` ("No Data") RAG band, driver = `NO_DATA_DRIVER`. Keeps the four-panel rhythm consistent across runs.
- **D-16: Excel zero-row standardisation.** Every module's `render_excel_tabs()` uniformly emits one row reading `"No data in scope"` when its analyst data is empty.
  - Behavior change with regression-baseline visibility: any module that today skips its tab on empty will start emitting a 1-row tab instead. Planner MUST flag this in the corresponding plan's SUMMARY and confirm against the live Tenable Excel diff.

### Area 8 — Plan structure & parallelisation (Q8)

- **D-17: Six plans, end-to-end per module.**
  - **03-01** — Foundation: `populate_rag_strip` helper + `rag_status_from_value` direction arg + `assemble_pdf` cover rework (D-01) + `email_inline_images` bundle key + `delivery/email_sender.py` bundle-driven email-body selector (per Area 9 below).
  - **03-02** — `scan_coverage_sla_module` migrated end-to-end: populate rag_strip / driver_narrative / analyst_rows in compute(); implement render_email_panel / render_analyst_tabs / render_rag_strip_entry; standardise Excel empty row.
  - **03-03** — `critical_remediation_sla_module` migrated end-to-end (same shape).
  - **03-04** — `high_risk_assets_module` migrated end-to-end (same shape).
  - **03-05** — `aged_vulns_assets_module` migrated end-to-end (same shape).
  - **03-06** — Phase 3 regression snapshot extension: extend `tests/test_phase2_composer_pipeline.py` (or sibling) to cover the populated-rag_strip / populated-panels paths; add zero-row `ModuleData` integration coverage for QUALITY-02.
- Sequential by intent (one module at a time = easier to demo and back out). Plans 03-02..03-05 each touch only their own module file plus shared helpers, so the executor MAY wave-parallelize them if file-overlap analysis allows it; that's an optimization, not a structural requirement.

### Area 9 — board_summary.py & email_sender.py wiring (Q9)

- **D-18: Bundle self-describes the email-body path.** `delivery/email_sender.py:send_report_email()` decides between legacy `build_email_body()` and `build_email_body_modular()` by checking whether ANY report's `email_body_html` in `report_outputs` is a non-empty string. No slug allowlists. No `MODULAR_REPORTS = {"board_summary"}` registry.
  ```python
  modular_panels = next(
      (
          outputs.get("email_body_html", "")
          for outputs in report_outputs.values()
          if isinstance(outputs.get("email_body_html"), str)
          and outputs["email_body_html"].strip()
      ),
      "",
  )
  if modular_panels:
      html_body = build_email_body_modular(group_config, report_outputs,
                                           module_panels_html=modular_panels, ...)
  else:
      html_body = build_email_body(group_config, report_outputs, ...)
  ```
- **D-19: Same self-describing pattern for analyst attachment.** `email_sender.py` attaches the analyst workbook whenever a report's `analyst_excel` is a real `Path` object, not slug-gated.
- **D-20: `composer.run_full_pipeline()` stays slug-agnostic.** The `slug` parameter remains a filename token (used for the analyst filename and the `_Metadata` Scope/Slug rows). No new slug-based behavior switches inside the composer or any module.
- **D-21: `reports/board_summary.py:run_report()` minimal touch.** It already calls `run_full_pipeline()` and returns the right bundle shape. Phase 3 should only adjust it if `_BOARD_MODULE_CONFIGS` needs new ModuleConfig options — and even those should land in the ModuleConfig.options dict, not as new positional args.

### Area 10 — v2-forward-compatibility guards

These are not gray areas the user picked but they fall out of D-18/D-19/D-20 and are load-bearing for the project's stated v2 direction (PROJECT.md: "Right metric, right audience, right channel — without writing a new report each time"):

- **D-22: Document the bundle-driven dispatch decision in CLAUDE.md.** One paragraph in the "Modular reports" / "Adding a new report" section saying the email-body and analyst-workbook routing decisions are bundle-driven, not slug-driven; this is intentional so v2's planned YAML-driven module composition (`groups[].modules: [m1, m2, ...]` schema) needs no `email_sender.py` or `composer.py` changes. Belongs in plan 03-01 alongside the wiring change.
- **D-23: No slug allowlists allowed in `delivery/email_sender.py`, `composer.py`, `run_all.py:run_group()`.** This is a code-review gate item for Phase 3 and beyond — any reviewer rejecting a registry-shaped change should cite this decision.
- **D-24: `delivery_config.yaml` schema is unchanged in Phase 3.** Existing `reports: [board_summary]` group entries continue to work. The v2 `modules: [...]` shape is added in a future phase, additively, without breaking the slug shape.

## Code Reuse / Patterns To Follow

- **`board_report_utils.py` already exposes** `compute_per_bu_breakdown`, `deduplicate_assets_by_name`, `extract_business_unit`, `sla_status_from_thresholds`, `ON_TIME_WINDOW_DAYS`. The four modules already use these. Phase 3 adds `populate_rag_strip` alongside.
- **`chart_utils.draw_gauge()` already exists** and is what the modules call to render their PDF gauges. Phase 3 reuses it for email gauges; the planner decides whether each module's compute() OR a composer-side helper writes the email gauge PNG to disk and emits the `email_inline_images` entry. (Recommendation: each module emits its own gauge during compute(), composer accumulates entries into the bundle — keeps modules self-contained.)
- **`assemble_pdf()` per-module exception isolation pattern** (Phase 2 `composer.py:522-533`) — mirror it for `render_email_panel` exception isolation in `assemble_email_body()` (already applied via Phase 2 D-28; nothing new for Phase 3 here, but plans should not regress it).

## Empty-Data Sentinels (already in `rag_utils.py`)

| Sentinel | Use |
|----------|-----|
| `NO_DATA_HEADLINE = "—"` | RAG strip cell headline; email panel headline; PDF section "headline" |
| `NO_DATA_DRIVER = "No data in scope."` | Email panel driver line; PDF section description on zero-row data |
| `STATUS_COLOR["no_data"] = "#757575"` | Gray RAG band |
| `STATUS_LABEL["no_data"] = "No Data"` | RAG band text |
| `STATUS_ICON["no_data"] = "○"` | RAG band icon (greyscale-print fallback) |

## Bundle Surface After Phase 3

`composer.run_full_pipeline()` returns:

```python
{
  "pdf_path":              Path,             # PDF with unified RAG-strip cover (D-01)
  "main_excel_path":       Path,             # existing Excel (untouched)
  "analyst_workbook_path": Path | None,      # populated when at least one module's analyst_rows is non-empty
  "email_body_html":       str,              # panels-only fragment when at least one render_email_panel returned non-empty
  "email_inline_images":   list[dict],       # NEW (D-04) — [{"cid": "scan_coverage_sla_gauge", "path": Path}, ...]
  "results":               list[ModuleData], # passthrough
  "audit":                 dict,             # passthrough (composer.collect_audit_info)
}
```

`reports/board_summary.py:run_report()` unpacks into:

```python
{
  "pdf":              Path,
  "excel":            Path,
  "charts":           list[Path],
  "metrics":          dict,
  "analyst_excel":    Path | None,           # was None on Phase 2; populated on Phase 3 when modules emit analyst_rows
  "email_body_html":  str,                   # was "" on Phase 2; populated on Phase 3 when modules implement render_email_panel
  # NEW key for D-04 (planner: confirm naming with the run_all.py / email_sender.py consumers):
  "email_inline_images": list[dict],
}
```

## Out-Of-Scope (deferred to v2 or later)

- **YAML-driven module composition** (`groups[].modules: [...]` schema) — D-24 explicitly defers; v2.
- **`delivery_config.yaml` schema additions** — none in Phase 3.
- **`management_summary.py` module migration** — its bespoke `_build_pdf` / `build_email_body` flow stays untouched; v2.
- **Per-BU breakdown in email panels** — D-03 defers; future email-template review can reopen.
- **Wider email card** — deferred per the Phase 2 UAT clarification (industry standard 600±40 px).
- **LLM-generated driver narratives** — D-06 explicitly rejects in v1; future scope.
- **`ops_remediation.py` migration to module pattern** — v2.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Excel zero-row standardisation (D-16) regresses live Tenable Excel content | Plan 03-06 regression test compares pre-Phase-3 vs post-Phase-3 Excel content with explicit acceptance for the new uniform "No data in scope" row. SUMMARY.md for plans 03-02..05 must call out the diff explicitly. |
| Cover-page rework (D-01) breaks existing PDF for ad-hoc `python reports/board_summary.py` callers | Plan 03-01 confirms: `assemble_pdf()` callers are board_summary's `run_full_pipeline()` only; `management_summary` uses its own `_build_pdf`. No external callers of `assemble_pdf()` exist outside the composer-driven board path. |
| CID gauge images don't render in some email client (D-04) | UAT test 2 in Phase 2 already validated Outlook / Gmail / Apple Mail rendering with CID-style infrastructure. Plan 03-06 SUMMARY must document a re-run of the off-network smoke (`scripts/smoke_email_phase2.py`) with real `render_email_panel` output, not stub panels. |
| `rag_status_from_value()` lacks `direction` arg → high_risk_assets / aged_vulns_assets get inverted RAG colors | Plan 03-01 adds the `direction` parameter (default `"higher_is_better"` for backward-compat) before any module uses it. |
| `populate_rag_strip()` helper drift between plans 03-02..05 | All four module plans reference the same plan 03-01-defined helper signature; helper signature is locked at plan 03-01 commit. |

## Anti-Patterns (do not do)

- ❌ Add `MODULAR_REPORTS = {"board_summary"}` or any slug allowlist to `delivery/email_sender.py` (violates D-18 / D-23).
- ❌ Add a slug-based behavior switch inside `composer.run_full_pipeline()` (violates D-20).
- ❌ Touch `management_summary.py:run_report()`'s bespoke `_build_pdf` / `build_email_body` flow (out of scope per "Phase 2 Option-2 deferral" — that work belongs to v2 alongside the management_summary module migration).
- ❌ Skip the per-module exception isolation pattern in `render_email_panel` / `render_analyst_tabs` / `render_rag_strip_entry` (Phase 2 D-28 invariant).
- ❌ Put driver narratives in a single shared formatter (violates D-06 — we explicitly chose hand-coded per module).
- ❌ Hardcode the email gauge PNG paths into `delivery/email_sender.py` (violates D-04 / D-19 — they flow through the bundle's `email_inline_images` key).

## Cross-Phase References

- Phase 1 verification: `.planning/phases/01-module-render-contract/01-VERIFICATION.md`
- Phase 2 verification: `.planning/phases/02-reportcomposer-upgrades/02-VERIFICATION.md`
- Phase 2 context (decisions D-01 through D-29 — Phase 2's): `.planning/phases/02-reportcomposer-upgrades/02-CONTEXT.md`
- Phase 2 patterns: `.planning/phases/02-reportcomposer-upgrades/02-PATTERNS.md`
- Project value statement + constraints: `.planning/PROJECT.md`
- Requirements traceability: `.planning/REQUIREMENTS.md` (BOARD-01..07, QUALITY-02 currently `Phase 3 / Pending`)
- Empty-data guard pattern: `CLAUDE.md` "Empty-data guard pattern" section
- Four-channel render contract: `CLAUDE.md` "Four-channel render contract" section

## Next Steps

1. `/gsd-plan-phase 3` — produces 6 plans (03-01..03-06) with full task breakdown, commit-by-commit. The planner MUST:
   - Resolve the `assemble_pdf()` cover-mode question (parameter vs hardcoded) inside plan 03-01 with a small ADR-style note.
   - Confirm `rag_status_from_value()` current signature and decide whether the `direction` arg is added in plan 03-01 or already present.
   - Spell out the exact driver-narrative template per module in plan 03-02..05 so executors don't ad-lib.
   - Capture the analyst-tab dataframe column types (especially the joined-cell columns: `contributing finding IDs`, `contributing plugins`) so Excel output is deterministic.
2. After Phase 3 ships: run UAT against a live Tenable export (matches the Phase 2 UAT test 3 protocol) to confirm RAG strip cells now show real values, email panels render, analyst workbook lands.
