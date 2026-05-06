# Phase 2: ReportComposer Upgrades - Context

**Gathered:** 2026-05-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Upgrade `ReportComposer` so that for any registered module list it can drive all four render channels — emitting a **dedicated page-2 RAG strip** in the PDF, **per-module email body panels**, and a **paired analyst-detail companion workbook** — alongside the existing PDF body and Excel that it already produces. The composer becomes the single orchestration entry point; the report scripts (`board_summary.py`, `management_summary.py`) keep their `run_report()` shape and just delegate to a new `run_full_pipeline()` bundle method.

**Concretely, Phase 2 ships:**
1. **PDF cover update** — `assemble_pdf()` is extended to insert a NEW dedicated page 2 between the existing cover (page 1, unchanged) and the existing module sections (pages 3..N, unchanged in this phase). Page 2 carries a "Risk Status Summary" header and a single horizontal row of cells (auto-flex layout for 1–12 modules, wrapping past 4 per row). Each cell sources from `render_rag_strip_entry()` (Phase 1 contract): label-top + big headline value + RAG-colored band-bottom containing both the rag_label text AND a status icon shape (▲ green / ● yellow / ▼ red / ○ no_data) for greyscale-print resilience.
2. **NEW `assemble_email_body(results)` method** — returns a panels-only HTML fragment (not a full standalone body) composed of per-module panels in `module_configs` order. Each panel is a single-row inline-styled `<table>` with gauge image (left) + label/value/RAG (middle) + driver_narrative line (right), ~150px tall, Outlook/Gmail/Apple Mail safe.
3. **NEW `assemble_analyst_workbook(results, output_path, *, generate=True)` method** — writes a separate `{report_slug}_{date}_analyst.xlsx` containing one tab per `(sheet_name, df)` tuple from each module's `render_analyst_tabs()` (sequential in `module_configs` order, sheet-name collisions auto-suffixed `_2`/`_3` with Excel 31-char-aware truncation), plus a `_Metadata` tab carrying scope + generated_at + source module IDs. Returns `Path` on success, `None` if every module returned `[]` or if `generate=False` (the Phase 4 opt-out hook is reserved on this method now).
4. **NEW `run_full_pipeline(results, output_dir, *, slug, date, generate_analyst=True)` method** — convenience entry point that orchestrates the four channels and returns a typed bundle dict.
5. **NEW `delivery/email_template.py:build_email_body_modular()`** — sibling to existing `build_email_body()`, accepts `module_panels_html` and renders against the SAME `templates/report_email.html` via a new `{% if module_panels_html %}` conditional that swaps the KPI-tiles section for the panels fragment while preserving scope banner, SLA reference table, attached-reports list, and footer.
6. **`board_summary.py` and `management_summary.py` `run_report()` extensions** — ~3 new lines each: call `composer.run_full_pipeline(...)`, unpack into the existing `{pdf, excel, charts, metrics}` return dict, plus add new keys `analyst_excel: Path | None` and `email_body_html: str`. Existing keys remain byte-for-byte unchanged on equivalent input (ROADMAP success criterion 4).
7. **Regression baseline snapshot in Phase 2 verifier** — capture sha256 of the main PDF and main xlsx for a frozen test scope BEFORE the composer changes; verify the same hashes match AFTER the changes. Only the new page-2 RAG strip is a controlled difference. The existing per-channel methods (`assemble_pdf`, `assemble_excel`, `collect_email_kpis`) stay public as building blocks; `run_full_pipeline()` calls them internally.

**Phase 2 does NOT touch:**
- The four-channel render contract on `BaseModule` / `ModuleData` — that shipped in Phase 1 and is locked.
- Any of the 4 board metric modules' implementations (Phase 3 migrates them to override `render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`). Phase 2 verifies the new composer machinery against the Phase-1 no-op defaults plus a temporary stub override or a single migrated module if convenient — but the BOARD-01..04 work proper is Phase 3.
- The 3 management_summary metric modules (v2 / GEN-01).
- `delivery_config.yaml` / `delivery_config.schema.yaml` / `jsonschema` runtime validation (Phase 4 / CONFIG-01..04).
- The `analyst_detail` opt-out wiring at the YAML / `run_all.py` level (Phase 4). The `generate=` kwarg on `assemble_analyst_workbook()` and the `generate_analyst=` kwarg on `run_full_pipeline()` are present in Phase 2 but always called with `True`. Phase 4 wires them from `group_config`.
- The QUALITY-02 board-module zero-row guard work (Phase 3, sibling to module migration).

</domain>

<decisions>
## Implementation Decisions

### PDF Cover RAG Strip Page (Area 1)
- **D-01: Page 1 cover stays unchanged.** Today's `_PDF_COVER_TEMPLATE` (title + scope/subtitle + generated_at + sections list) ships unmodified through Phase 2. Preserves all existing cover-page invariants and avoids risking regression on the cover page itself.
- **D-02: NEW dedicated page 2 = full-page RAG strip.** Phase 2 inserts a new HTML page between the cover and the first module section. Page-break CSS forces it onto its own page. The page is just the strip; pages 3..N are the existing per-module sections (unchanged in Phase 2 — Phase 3 will refresh them as part of board module migration).
- **D-03: Single horizontal row of cells, auto-flex 1–12 modules.** CSS handles 1–4 cells in a single row; >4 wraps to a second/third row of up to 4 each. Targets WeasyPrint flex/grid behavior — verify in research that this prints cleanly on A4 landscape.
- **D-04: Cell visual = label-top + big-value + RAG-colored band-bottom.** Module display name at top (small), `headline_value` as a big bold number/percent in the middle, ~10mm RAG-colored band at the bottom. Inside the colored band: BOTH the `rag_label` text AND a status icon shape (▲ green / ● yellow / ▼ red / ○ no_data) per D-08 — the icon survives greyscale printing while the colored band gives the at-a-glance signal.
- **D-05: Page 2 has a small header "Risk Status Summary" above the cell row.** Same typographic style as the report title on page 1; vertically centered above the cells with margin. Self-describing if the page is printed in isolation.
- **D-06: All-empty fallback = render the page anyway with all-gray "No Data" cells.** When every module's `render_rag_strip_entry()` returns the no-op default (Phase 1 D-04), page 2 still renders with the gray cells. Reader can tell at-a-glance that nothing matched the filter; aligns with Phase 1's empty-data guard pattern (better than silently skipping a page).
- **D-07: Module ordering on page 2 follows the `module_configs` list passed to `ReportComposer.__init__`.** No re-sorting, no severity-based reordering, no alphabetical. Whatever order the report script's `_BOARD_MODULE_CONFIGS` (or equivalent) declares is the canonical source of truth across all three new channels (strip, email panels, analyst tabs). Same as today's behavior for `assemble_pdf` / `assemble_excel` / `collect_email_kpis`.
- **D-08: Status icon set is ▲ (green) / ● (yellow) / ▼ (red) / ○ (no_data).** Unicode shapes; render alongside the rag_label text inside the colored band. Provides print-greyscale fallback AND helps color-blind readers (the shape carries the signal independent of color).

### Email Body Integration (Area 2)
- **D-09: `ReportComposer.assemble_email_body(results)` returns a panels-only HTML fragment.** Just the concatenated `<table>...</table>` blocks; no `<html>`, no `<head>`, no scope banner, no SLA table, no footer. The wrapping shell stays in `templates/report_email.html`. This keeps the composer focused on module rendering and lets the template own headers/footers.
- **D-10: `templates/report_email.html` gains a new `{{ module_panels_html }}` slot guarded by `{% if module_panels_html %}`.** When present, the template renders the module panels in place of the existing KPI tiles. When absent, the legacy KPI tiles render (preserving backward compatibility for ops_remediation, vuln_export, etc.).
- **D-11: Replace KPI tiles with module panels; KEEP the SLA reference table, scope banner, attached-reports list, footer.** Module panels carry richer info than today's tiles (gauge + value + RAG + driver line), so the tiles section is supplanted. The SLA reference table is a static lookup useful to non-security recipients and stays. Scope banner, attached-reports list, and footer are unchanged.
- **D-12: Per-module email panel = single-row HTML `<table>` with three columns.** Left = base64-encoded gauge image (~120×120px, no MIME CID indirection — embedded directly via `<img src="data:image/png;base64,...">`). Middle = module display name (top, small) + headline value (big) + RAG label (colored). Right = `driver_narrative` line. Total panel height ~150px. Inline `<style>` attributes only (NO `<style>` blocks); table-layout-fixed; widths in absolute px. Outlook/Gmail/Apple Mail compatible.
- **D-13: Each module renders its own gauge inside `render_email_panel()`.** `chart_utils.draw_gauge()` (returns base64 PNG) is called from inside `render_email_panel(data, config)`; the panel HTML embeds the base64 directly. No three-arg signature change to the contract; no MIME-CID leak into the composer. Stays consistent with Phase 1's `render_email_panel(data, config) -> str` shape.
- **D-14: Empty panel handling — silently skip when `render_email_panel()` returns `""`.** Mirrors `assemble_pdf()`'s existing skip-empty behavior at `composer.py:535`. Un-migrated modules contribute their RAG strip cell on page 2 (gray "No Data" default) but no email panel. The four channels are independent — a module can be migrated for one channel before another.
- **D-15: NEW `delivery/email_template.py:build_email_body_modular(group_config, module_panels_html, ...)` function.** Sibling to existing `build_email_body()`. Module-based reports (board_summary, management_summary in v2) call the new one; legacy reports keep using `build_email_body()`. Both render against the SAME `templates/report_email.html` — the conditional in D-10 selects which body section runs. Keeps the legacy reports' rendering path frozen (no risk of regression).

### Analyst Workbook Structure (Area 3)
- **D-16: Filename = `{report_slug}_{date}_analyst.xlsx`** (e.g., `board_summary_2026-05-05_analyst.xlsx`). Sorts alphabetically next to today's main `board_summary_2026-05-05.xlsx`. No scope token in the filename — keeps it short; scope is on the `_Metadata` tab.
- **D-17: Tabs are sequential in `module_configs` order; no auto-prefix.** A module returning `[(sheet1, df1), (sheet2, df2)]` gets two consecutive tabs; a subsequent module's tabs follow. Modules own their sheet names; the composer just preserves order.
- **D-18: Sheet-name collisions auto-suffix the duplicate with `_2`, `_3`, ...** Same approach openpyxl uses internally. Excel's 31-char limit handled by truncating the base name to leave room for the suffix (e.g., `Long_Sheet_Name_That_Almost_Fits_2`).
- **D-19: `_Metadata` tab carries Scope + generated_at + source module IDs.** Two-column key/value layout matching today's `assemble_excel()` `_Metadata` shape (`composer.py:_write_metadata_tab` at line 857). Specifically: `Report` (slug), `Generated` (UTC timestamp), `Scope` ("Application = UC Engineering" or "All Assets"), `Modules` (comma-joined module IDs in `module_configs` order). Per-tab row counts and run duration are deliberately OUT (those bleed runtime concerns).
- **D-20: All-empty workbook → skip the file entirely.** If the cumulative tab list is empty (every module returned `[]` from `render_analyst_tabs()`), `assemble_analyst_workbook()` returns `None` and writes nothing to disk. The report script's `run_report()` sets `analyst_excel: None`. `delivery/email_sender.py` only attaches non-None paths. Aligns with PROJECT.md fail-soft batch semantics: no work done = no artifact.
- **D-21: Workbook lands in the same `output/{date}_{HH-MM}_{group-name}/` directory as the main outputs.** No `analyst/` subdirectory. The filename suffix (`_analyst`) is the only disambiguation. Matches today's flat-directory output convention.

### Composer Return Contract (Area 4)
- **D-22: NEW `ReportComposer.run_full_pipeline(results, output_dir, *, slug, date, generate_analyst=True) -> dict` method.** Orchestrates the four channels by calling the per-channel methods internally. Returns a typed bundle dict: `{'pdf_html': str, 'excel_workbook': openpyxl.Workbook, 'analyst_workbook_path': Path | None, 'email_body_html': str, 'email_kpis': dict, 'metrics': dict, 'errors': list}`. Single high-level entry point for module-based report scripts.
- **D-23: Existing per-channel methods stay public as building blocks.** `assemble_pdf()`, `assemble_excel()`, `collect_email_kpis()` remain unchanged at the API surface (`assemble_pdf` gains the page-2 RAG strip insertion internally — caller signature unchanged). NEW per-channel methods `assemble_email_body()` and `assemble_analyst_workbook()` are also public. Tests, debug scripts, and à-la-carte callers can use them directly. `run_full_pipeline()` is the convenience layer.
- **D-24: Report-script `run_report()` return dict gains `analyst_excel: Path | None` AND `email_body_html: str`.** Existing `pdf`, `excel`, `charts`, `metrics` keys remain UNCHANGED (ROADMAP success criterion 4: byte-for-byte unchanged on equivalent input). New keys are additive only. `run_all.py` consumers and `delivery/email_sender.py` learn about the new keys; existing key handling stays the same.
- **D-25: Phase 4 opt-out hook = `generate=` kwarg on `assemble_analyst_workbook()` and `generate_analyst=` kwarg on `run_full_pipeline()`.** When false, the analyst workbook is not generated and `analyst_workbook_path` is `None`. Phase 2 always calls with `True`. Phase 4 wires `generate_analyst = group_config.get('analyst_detail', True)` at the report-script level. The signature is in place from Phase 2; Phase 4 just flips the value.
- **D-26: `board_summary.py` and `management_summary.py` `run_report()` are extended in-place with ~3 new lines.** Pseudo: `bundle = composer.run_full_pipeline(results, output_dir, slug=..., date=...)`; pdf is written from `bundle['pdf_html']` (existing flow); excel is written from `bundle['excel_workbook']` (existing flow); `analyst_excel` and `email_body_html` keys are added to the existing return dict from `bundle['analyst_workbook_path']` and `bundle['email_body_html']`. No new helpers, no extracted module-runner. Phase 3 will refresh the modules; the wiring stays.
- **D-27: Module ordering across all three new channels is driven by the `module_configs` list passed to `ReportComposer.__init__`.** Reaffirms D-07 explicitly across the strip, email panels, and analyst tabs. No per-channel reordering; no `PRIORITY` class constant; the report script's config is the single source of truth.

### Error Isolation & Robustness (Extra)
- **D-28: One module's `render_email_panel()` or `render_analyst_tabs()` exception is caught + logged + replaced with an error placeholder.** Email body inserts `<div class="error-box">Module {display_name}: email panel failed — {exc}</div>` in the panel position. Analyst workbook skips the module's tabs and adds a `_Metadata` row noting the failure. Mirrors the existing `assemble_pdf()` behavior at `composer.py:522-533`. Aligns with PROJECT.md fail-soft batch semantics: one module bug never kills a multi-group nightly run. The placeholder is visible (so failures aren't silently hidden) but does not propagate the exception.

### Phase 2 Verification (Extra)
- **D-29: Phase 2's `gsd-verifier` runs a regression-baseline snapshot test.** BEFORE the composer changes (or against a known-good cached parquet), generate a board_summary run for a frozen test scope and capture sha256 of the main PDF and main xlsx. AFTER the Phase 2 work lands, run the same scope; verify the main PDF and main xlsx hashes match. The new page-2 RAG strip is the ONLY controlled difference (the verifier asserts page 1 cover hash is unchanged; the body sections after page 2 are unchanged on equivalent module data). Catches regression early — before Phase 4's BOARD-08 gate has to.

### Claude's Discretion
- Exact CSS shape for the page-2 strip cells (CSS grid vs flexbox vs nested tables for WeasyPrint compat) — research/planner decides; D-04 only locks the visual shape, not the markup.
- Whether `assemble_email_body()` uses Jinja2 internally (e.g., a per-panel sub-template) or hand-built HTML strings. Lean toward hand-built for inline-CSS predictability, but if a research-uncovered Jinja2 idiom keeps the panels readable, accept that.
- Whether `_PDF_COVER_TEMPLATE` is left as-is and a new `_PDF_RAG_STRIP_TEMPLATE` is added, or both are restructured into a shared cover-block helper. Either is fine; pattern-mapper finding may steer the choice.
- The exact run-time API for the regression snapshot test (D-29) — whether it's a pytest fixture, a smoke script in `tests/`, or just gsd-verifier-driven smoke. Planner picks based on what fits.
- The placeholder error-box HTML/CSS for D-28 — keep it simple (single `<div>` with red border) but exact wording is the executor's call.
- Whether `board_summary.py:_BOARD_MODULE_CONFIGS` is renamed/reordered in Phase 2. Per D-27 the order is canonical, so changes here are strictly forbidden in Phase 2; Phase 3 may revisit.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project Planning
- `.planning/PROJECT.md` — v1 milestone scope, Constraints (tech stack lock, email-client compat, backward-compat, fail-soft batch semantics), Key Decisions table.
- `.planning/REQUIREMENTS.md` §"Report Composer Upgrades" — COMPOSER-01..04; §"Empty-Data Hardening" — QUALITY-02 belongs to Phase 3 (NOT this phase).
- `.planning/ROADMAP.md` §"Phase 2: ReportComposer Upgrades" — goal statement, dependencies (Phase 1), parallelization with Phase 3, success criteria 1–4.
- `.planning/phases/01-module-render-contract/01-CONTEXT.md` — Phase 1's locked decisions (D-01..D-17); Phase 2 must respect them all.
- `.planning/phases/01-module-render-contract/01-VERIFICATION.md` — Phase 1's verification report; lists every Phase 1 commitment that's now in the codebase.

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` §"Module Infrastructure", §"Key Abstractions", §"Anti-Patterns" — `ReportComposer` shape, `BaseModule` / `ModuleData` extended in Phase 1, "Side effects in compute()" / "Raising exceptions out of report code" anti-patterns.
- `.planning/codebase/STACK.md` — pinned dependencies (WeasyPrint 65.1, openpyxl 3.1.5, Jinja2 3.1.6, matplotlib 3.10.1, plotly 6.0.1 + kaleido 0.2.1). No new SDKs in v1.
- `.planning/codebase/CONVENTIONS.md` — naming patterns (snake_case modules / files / functions; PascalCase classes; UPPER_SNAKE constants; `_leading_underscore` for module-private), type-hint style, Numpydoc docstrings, dataclass `field(default_factory=...)` for mutable defaults, no-op renderer defaults shape, `# noqa: PLC0415` for deferred imports.

### Project Documentation
- `CLAUDE.md` (project root) §"Board-Style Reports — Module Infrastructure" — extended in Phase 1 with the four-channel render contract and empty-data guard pattern. Phase 2 may extend this section further with composer pipeline documentation.
- `CLAUDE.md` (project root) §"Adding a New Report — Required Steps" — three-place registration rule for new report slugs.
- `CLAUDE.md` (project root) §"Email Delivery — `delivery/email_sender.py`" — describes today's email body, attachment, and CID handling. Phase 2's `build_email_body_modular()` plugs into this pipeline.

### Phase 1 Helper Modules (consumed by Phase 2 internals)
- `reports/modules/rag_utils.py` — `STATUS_COLOR`, `STATUS_LABEL`, `rag_status_from_value()`, `build_rag_strip_entry()`, `NO_DATA_HEADLINE`, `NO_DATA_DRIVER`. Phase 2's page-2 cell rendering MAY use these constants directly to format the RAG band styling and "No Data" fallback colors.
- `reports/modules/format_utils.py` — `safe_pct`, `safe_int`, `safe_format`. Per Phase 1 D-15, every renderer that interpolates a metric value MUST use these.

### Source Files Phase 2 Touches Directly
- `reports/modules/composer.py` — primary edit target. Adds page-2 strip insertion inside `assemble_pdf()`; adds two new methods (`assemble_email_body`, `assemble_analyst_workbook`); adds `run_full_pipeline()`.
- `reports/board_summary.py:_BOARD_MODULE_CONFIGS` and `run_report()` (around lines 60–260) — extends `run_report()` in-place with the new bundle call.
- `reports/management_summary.py:run_report()` (around lines 1235–1260) — same in-place extension.
- `delivery/email_template.py:347 build_email_body()` — sibling addition `build_email_body_modular()`.
- `templates/report_email.html` — adds `{% if module_panels_html %}` conditional swapping KPI tiles for module panels block.

### Source Files Phase 2 Reads For Context (does NOT edit)
- `reports/modules/base.py` — `BaseModule` ABC + `ModuleData` dataclass extended in Phase 1; the four-channel render method signatures (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) are stable contracts.
- `reports/modules/registry.py` — `discover()` and `_registry`; Phase 2 uses `registry.get(module_id)` to instantiate modules in the new methods, same pattern as today's `assemble_pdf()` at `composer.py:509`.
- `reports/modules/chart_utils.py` — `draw_gauge()` returns base64 PNG; consumed by `render_email_panel()` in Phase 3 (Phase 2 just makes the contract permit embedding base64 inside the HTML fragment per D-13).
- `reports/modules/board_report_utils.py` — board-module-specific helpers (deduplication, BU breakdown). NOT touched by Phase 2.
- `reports/modules/scan_coverage_sla_module.py` (and the other 3 board modules) — analog of how a metric module is structured; useful for understanding what Phase 2's stub-module integration test (D-29) instantiates against.
- `delivery/email_sender.py` — consumes `build_email_body()` today (line ~280); Phase 2 lays groundwork so Phase 3 can wire `build_email_body_modular()` from `board_summary.py` runs.
- `templates/report_email.html` — the existing inline-CSS template that the new conditional plugs into.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`composer.py:_PDF_CSS`** — base stylesheet for PDF assembly; Phase 2's page-2 strip CSS extends this (or appends via `page_css` kwarg).
- **`composer.py:_PDF_COVER_TEMPLATE`** — today's cover-page format string at top of file; Phase 2 ADDS a new `_PDF_RAG_STRIP_TEMPLATE` (or equivalent) and inserts it AFTER the cover.
- **`composer.py:assemble_pdf()` skip-empty-section pattern at line 535** — `if not html or not html.strip(): continue`. Phase 2's `assemble_email_body()` mirrors this for empty panels (D-14).
- **`composer.py:assemble_pdf()` exception-isolation at line 522-533** — try/except around each module's render call, logs traceback, inserts visible error-box. Phase 2's `assemble_email_body()` and `assemble_analyst_workbook()` mirror this exactly (D-28).
- **`composer.py:_write_metadata_tab()` at line 857** — today's `_Metadata` tab writer; Phase 2's `assemble_analyst_workbook()` reuses this pattern (D-19).
- **`reports/modules/rag_utils.py:STATUS_COLOR`** — Phase 1 hex palette. Page-2 cells consume `STATUS_COLOR[rag_color_key]` directly OR use the rag_color hex string returned in the strip-cell dict.
- **`reports/modules/rag_utils.py:NO_DATA_HEADLINE` / `NO_DATA_DRIVER`** — used in the all-empty fallback (D-06) so the gray cells say "—" / "No data in scope." consistently.
- **`delivery/email_template.py:build_email_body()` at line 347** — today's Jinja2 renderer; Phase 2's `build_email_body_modular()` is a sibling that reuses the same Jinja2 environment, same template file, same `_safe_get` / `build_attached_reports` / `build_chart_cids` helpers — just adds `module_panels_html` to the context dict.

### Established Patterns
- **Pure compute, deferred render.** `BaseModule.compute()` is contractually side-effect-free (`reports/modules/base.py:191-200`). Phase 2's NEW render methods (`assemble_email_body`, `assemble_analyst_workbook`) call existing `render_email_panel()` / `render_analyst_tabs()` on already-computed `ModuleData` — they don't call `compute()` themselves. Same pattern.
- **Catch-all per module.** Composer's existing pattern is "iterate results, try each module's render, catch + log + insert placeholder, continue to next." Phase 2's two new methods follow this exactly (D-28).
- **No-op renderer defaults.** Phase 1 D-02..D-04 establish the no-op defaults: email panel `""`, analyst tabs `[]`, RAG strip dict gray "No Data" cell. Phase 2's composer methods MUST handle these no-op values without crashing.
- **`module_configs` is the canonical order.** `ReportComposer.__init__` accepts `module_configs: list[ModuleConfig]` and `run_all()` iterates in that exact order. Phase 2 reaffirms this is the source of truth across all three new channels (D-07, D-27).
- **`_register_module` decorator + `discover()` at import time.** Adding a new module is a 3-step registration (`run_all.py` `_VALID_REPORTS`, `_REPORT_MODULE_MAP`, `CLAUDE.md` YAML schema). Phase 2 doesn't add new metric modules — it only edits the composer. Three-place registration is irrelevant for Phase 2.
- **Numpydoc docstrings + `# ===` section banners + `from __future__ import annotations`.** New methods on `ReportComposer` and the new `build_email_body_modular()` follow this style.
- **Inline-CSS only for emails.** Per CLAUDE.md "Email Template" rules, the email body uses inline `<style>` attributes, no `<style>` blocks, no flexbox. Phase 2's per-module panel HTML in D-12 follows this.

### Integration Points
- **`reports/modules/composer.py:assemble_pdf()`** — internal change at the cover/section seam. The page-2 RAG strip block is inserted between the cover HTML and the first section's HTML. Caller signature unchanged.
- **`reports/board_summary.py:run_report()` and `reports/management_summary.py:run_report()`** — both add ~3 new lines to call `composer.run_full_pipeline()` and unpack into the existing return dict (D-26). Existing dict keys preserved (D-24).
- **`delivery/email_template.py`** — new `build_email_body_modular()` function alongside `build_email_body()`. Both render against the same `templates/report_email.html`; the template's `{% if module_panels_html %}` conditional decides which body section runs.
- **`templates/report_email.html`** — gains a new `{% if module_panels_html %}{{ module_panels_html | safe }}{% else %}{% raw KPI tiles block %}{% endif %}` conditional. The legacy KPI-tiles block stays in the `{% else %}` branch so legacy reports (ops_remediation, vuln_export) render unchanged.
- **`delivery/email_sender.py`** — Phase 2 lays the groundwork; Phase 3 (or Phase 4) wires the new `email_body_html` from the report-script return dict into the email sender's body argument. Phase 2 does NOT edit email_sender.py.
- **`run_all.py`** — Phase 2 does NOT edit `run_all.py`. Existing report-output dict consumers continue to work because new keys are additive (D-24).

### Anti-Patterns to Re-Read
- **"Side effects in `BaseModule.compute()`"** (`.planning/codebase/ARCHITECTURE.md`) — Phase 2's new render methods consume `ModuleData` only; they don't call `compute()` again or touch shared state.
- **"Raising exceptions out of report code"** — applies to the new composer methods. `assemble_email_body()` and `assemble_analyst_workbook()` MUST catch internally (per D-28) and never raise.
- **Mutable default args.** Bundle dict in D-22 must be constructed fresh per call (no `def run_full_pipeline(... bundle: dict = {})`); use `field(default_factory=dict)` if a dataclass is chosen for the bundle, or just construct a new dict literal inside the method.

</code_context>

<specifics>
## Specific Ideas

- **Page-2 cell HTML reference shape:**
  ```html
  <div class="rag-strip">
    <h2 class="rag-strip-header">Risk Status Summary</h2>
    <div class="rag-cell-row">
      <div class="rag-cell">
        <div class="rag-cell-label">Scan Coverage SLA</div>
        <div class="rag-cell-value">87.4%</div>
        <div class="rag-cell-band" style="background-color: #fbc02d;">
          <span class="rag-cell-icon">●</span>
          <span class="rag-cell-rag-label">At Risk</span>
        </div>
      </div>
      <!-- ... more cells ... -->
    </div>
  </div>
  ```

- **Per-module email panel reference shape:**
  ```html
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="width:100%; max-width:600px; margin:8px 0;">
    <tr>
      <td style="width:140px; padding:12px; vertical-align:middle;">
        <img src="data:image/png;base64,..." alt="" style="width:120px; height:120px; display:block;" />
      </td>
      <td style="padding:12px; vertical-align:middle;">
        <div style="font-size:11pt; color:#666;">Scan Coverage SLA</div>
        <div style="font-size:24pt; font-weight:bold; color:#1a1a1a;">87.4%</div>
        <div style="font-size:10pt; color:#fbc02d; font-weight:bold;">● At Risk</div>
      </td>
      <td style="padding:12px; vertical-align:middle; font-size:10pt; color:#444;">
        Coverage dipped 2.1% from last week — 14 production hosts overdue for licensed scan.
      </td>
    </tr>
  </table>
  ```

- **`run_full_pipeline()` reference signature:**
  ```python
  def run_full_pipeline(
      self,
      results: list[ModuleData],
      output_dir: Path,
      *,
      slug: str,
      report_date: date,
      generate_analyst: bool = True,
  ) -> dict[str, Any]:
      """Returns: {'pdf_html', 'excel_workbook', 'analyst_workbook_path', 'email_body_html', 'email_kpis', 'metrics', 'errors'}."""
  ```

- **`build_email_body_modular()` reference signature:**
  ```python
  def build_email_body_modular(
      group_config: dict,
      report_outputs: dict,
      module_panels_html: str,
      generated_at: datetime,
      group_name: str,
  ) -> str:
      """Renders templates/report_email.html with module_panels_html injected. Same Jinja2 env / template / helpers as build_email_body()."""
  ```

- **Status icon mapping (D-08):** `▲` (`U+25B2 BLACK UP-POINTING TRIANGLE`) for green / `●` (`U+25CF BLACK CIRCLE`) for yellow / `▼` (`U+25BC BLACK DOWN-POINTING TRIANGLE`) for red / `○` (`U+25CB WHITE CIRCLE`) for no_data. Add to `rag_utils.py` as a new `STATUS_ICON: dict[str, str]` palette (or reserve as Claude's discretion; D-04 only mandates the icons appear in the band, not where they live in code).

</specifics>

<deferred>
## Deferred Ideas

- **Migrating board metric modules to override `render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`.** This is BOARD-01..04 / Phase 3, NOT Phase 2. Phase 2 verifies the new composer machinery against Phase 1's no-op defaults plus a temporary stub override (or a single migrated module if convenient). The four board modules' migrations land in Phase 3.
- **Migrating `management_summary` modules to the new contract** — explicitly v2 (GEN-01).
- **`delivery_config.yaml` `analyst_detail: false` opt-out plumbing** — Phase 4 / CONFIG-03. Phase 2 ships the `generate=` kwarg on `assemble_analyst_workbook()` and `generate_analyst=` on `run_full_pipeline()`; Phase 4 wires them.
- **`jsonschema` runtime validation of `delivery_config.yaml`** — Phase 4 / CONFIG-02.
- **Visual-diff regression test (PIL/imagehash)** — D-29 picks bytewise sha256 for v1; visual diff is overkill for Phase 2 verification. Reconsider in v2 if false positives become a problem.
- **`STATUS_ICON` palette in `rag_utils.py`** — small surface area; planner may add it as part of the page-2 cell rendering or inline the four icons. Either is fine.
- **PDF cover page restructure (replacing `_PDF_COVER_TEMPLATE` with a more flexible component model)** — out of scope for v1; D-01 explicitly preserves today's cover. Revisit in v2 if multiple new report types need different cover variants.
- **Per-tab row counts and run duration on the analyst `_Metadata` tab** — D-19 explicitly excludes these. Re-evaluate if analyst feedback says they want it; small addition if so.
- **`analyst/` subdirectory for output organization** — D-21 picks flat. If analyst feedback finds the flat layout cluttered, revisit.
- **Sheet-name collision warning logs** — D-18 picks silent auto-suffix. If collisions become a real Phase 3 concern (board modules accidentally choosing the same sheet name), upgrade to a WARN-level log.
- **MIME CID gauge attachment instead of base64 inline (D-13 alternative)** — kept as alternative if base64 panel HTML balloons email size beyond practical limits; Phase 2 commits to base64 inline.

</deferred>

---

*Phase: 2-ReportComposer Upgrades*
*Context gathered: 2026-05-05*
