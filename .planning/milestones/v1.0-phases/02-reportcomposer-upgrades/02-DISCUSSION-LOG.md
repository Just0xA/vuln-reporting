# Phase 2: ReportComposer Upgrades — Discussion Log

**Date:** 2026-05-05
**Mode:** discuss-phase (default mode, single session)
**Areas selected:** All 4 primary + all 4 extras

---

## Initial gray-area selection

User was presented with 4 phase-specific gray areas and selected ALL of them via multiSelect:

1. PDF cover RAG strip layout
2. Email body integration
3. Analyst workbook structure
4. Composer return contract

---

## Area 1: PDF cover RAG strip layout

### Q1.1: How should the RAG strip be laid out on the cover page?

**Options presented:**
- Single horizontal row — one row of cells across page, ~25% wide each, label-top + big-value + colored-band-bottom; wraps for >4 modules.
- Vertical stack — one cell per row top-to-bottom; more dashboard-like; better for many modules.
- 2×2 grid — fixed 2-column wrapping for >4 modules.
- Auto/flex (CSS auto-fit minmax(200px, 1fr)) — most flexible, harder WeasyPrint margins.

**User selected:** Single horizontal row.

### User clarification (interrupted Q1.2/Q1.3/Q1.4):

User raised a structural question I hadn't framed: **"What about keeping the title page, and page 2 is the rag strip, with the subsequent pages being supporting tables or graphs for the RAG strip. So Title, Scope, Generated on, Sections/Modules list on page 1, page 2 would be the rag strip, and page 3-n would be the supporting data."**

This re-framed the entire layout question. Original framing had the strip living inside the existing cover page (alongside title/subtitle/timestamp). User's clarification: cover page is preserved unchanged, RAG strip gets its OWN dedicated page 2, module sections become pages 3..N.

**Locked from clarification:**
- Page 1 = existing cover (unchanged in Phase 2)
- Page 2 = full-page RAG strip (NEW)
- Pages 3..N = existing module sections (unchanged in Phase 2; Phase 3 refreshes when migrating board modules)

### Q1.2 (re-asked after clarification): What should each cell on the page-2 RAG strip look like?

**Options presented:**
- Label top + big value + colored band bottom (Recommended) — module display name on top, big bold headline_value in middle, ~10mm RAG-colored band at bottom with rag_label text inside.
- Full cell colored background — entire cell uses rag_color at low opacity.
- Color stripe on the left edge — 6–8mm colored stripe, rest white.

**User selected:** Label top + big value + colored band bottom.

### Q1.3 (re-asked): What module count should the page-2 RAG strip cleanly support?

**Options presented:**
- Optimize for 4 (Recommended) — hardcode the layout for board's 4 modules.
- Design for 1–6 — flex 1–6 cleanly; covers board + likely v2.
- Design for 1–12 (full flex) — auto-flex any count from 1 to 12; covers management_summary's 7 modules in v2.

**User selected:** Design for 1–12 (full flex).

### Q1.4: More questions about the RAG strip page, or move to next area?

**User selected:** More questions.

### Q1.5: What if every module's RAG cell is "No Data" (zero-row dataset, total filter miss)?

**Options:** Show page anyway with all-gray cells / Skip page 2 entirely / Replace cells with single "No data in scope" message.

**User selected:** Show the page anyway with all-gray cells.

### Q1.6: Does page 2 have a small header above the cell row?

**Options:** No header / Small header "Risk Status Summary" / Header + scope reminder.

**User selected:** Small header "Risk Status Summary".

---

## Area 2: Email body integration

### Q2.1: What does ReportComposer.assemble_email_body() return?

**Options:** HTML fragment (panels only) / Full standalone HTML body / Dict of named slots.

**User selected:** HTML fragment (panels only).

### Q2.2: What happens to today's KPI tiles + SLA reference table inside the email?

**Options:** Replace KPI tiles with module panels; keep SLA table / Add panels in addition / Replace everything except scope banner and footer.

**User selected:** Replace KPI tiles with module panels; keep SLA table.

### Q2.3: What's a per-module email panel's exact shape?

**Options:** Gauge + label + value + RAG band + driver line / Full-width banner / 2-column compact grid.

**User selected:** Gauge + label + value + RAG band + driver line.

### Q2.4: Where do the inline-CID gauge images come from?

**Options:** Each module renders its own gauge inside render_email_panel() / Composer pre-renders gauges and passes them in / Composer returns panels + a separate gauge dict.

**User selected:** Each module renders its own gauge inside render_email_panel().

### Q2.5: More questions about Email body integration, or move to next?

**User selected:** More questions.

### Q2.6: What happens when a module returns "" from render_email_panel() (un-migrated module — Phase 1 D-02 no-op default)?

**Options:** Skip silently / Render gray placeholder / Composer raises a warning, still skips.

**User selected:** Skip silently.

### Q2.7: How should delivery/email_template.py integrate the panels?

**Options:** New build_email_body_modular() function / Extend existing build_email_body() with optional kwarg / Extend the template with a new slot, no new function.

**User selected:** New build_email_body_modular() function.

---

## Area 3: Analyst workbook structure

### Q3.1: What's the analyst workbook filename convention?

**Options:** {report_slug}_{date}_analyst.xlsx / {report_slug}_{date}_{scope}_analyst.xlsx / analyst_{report_slug}_{date}.xlsx.

**User selected:** {report_slug}_{date}_analyst.xlsx.

### Q3.2: How should multi-tab module output be laid out?

**Options:** Sequential in module-config order / Sequential with module_id prefix / Group with section breaks.

**User selected:** Sequential, in module-config order.

### Q3.3: What goes on the _Metadata tab?

**Options:** Scope + generated_at + source module IDs / Above + per-module row counts / Above + run duration + tag filter detail.

**User selected:** Scope + generated_at + source module IDs.

### Q3.4: What if every module returns [] from render_analyst_tabs() (un-migrated modules)?

**Options:** Skip the workbook entirely / Create xlsx with only _Metadata tab / Raise/log warning, then skip.

**User selected:** Skip the workbook entirely — don't create the file.

### Q3.5: More questions about Analyst workbook structure, or move to next?

**User selected:** More questions.

### Q3.6: How are sheet name collisions handled when two modules return tabs with the same sheet_name?

**Options:** Auto-suffix with _2, _3 / Auto-prefix with module_id / Log warning + use module_id-prefixed name unconditionally.

**User selected:** Auto-suffix the duplicate with _2, _3.

### Q3.7: Where does the analyst workbook file land on disk?

**Options:** Same dir as main outputs / analyst/ subdirectory.

**User selected:** Same dir as main outputs.

---

## Area 4: Composer return contract

### Q4.1: How is the new composer surface organized?

**Options:** Two new methods + extend assemble_pdf / One new run_full_pipeline() that returns a bundle dict / Extend run_all() to return an enriched bundle.

**User selected:** One new run_full_pipeline() that returns a bundle dict.

### Q4.2: What's the report-script-level run_report() return dict shape?

**Options:** Add analyst_excel key alongside existing keys / Add analyst_excel and email_body_html keys / Add an attachments dict to consolidate.

**User selected:** Add analyst_excel key alongside existing keys.

### Q4.3: Phase 4 will need an opt-out hook — what's Phase 2's contract for that?

**Options:** assemble_analyst_workbook accepts a skip flag / Report scripts gate the call themselves / Phase 2 doesn't worry about it; Phase 4 figures it out.

**User selected:** assemble_analyst_workbook accepts a skip flag.

### Q4.4: Where does board_summary.py wire all this together?

**Options:** Extend run_report() in-place / Extract a new run_modular_report() helper in composer.py.

**User selected:** Extend run_report() in-place.

(Reconciled with Q4.1 in CONTEXT.md as: composer exposes both `run_full_pipeline()` AND the per-channel methods; report scripts extend their existing `run_report()` in-place to call `run_full_pipeline()` and unpack into the existing return dict.)

### Q4.5: More questions about Composer return contract, or wrap up?

**User selected:** More questions.

### Q4.6: What happens to existing per-channel methods once run_full_pipeline() exists?

**Options:** Keep as public building blocks / Make per-channel methods private / Keep public, but mark as 'advanced' in docstrings.

**User selected:** Keep as public building blocks.

### Q4.7: What's the run_full_pipeline() bundle dict shape?

**Options:** Match the report-script return dict + intermediates / Match the report-script return dict exactly / Return a typed dataclass (PipelineBundle).

**User selected:** Match the report-script return dict + intermediates.

---

## Final readiness check

User chose **Explore more gray areas** when asked if ready for context.

### Extras selected (multiSelect):
1. Error isolation in assemble_email_body / assemble_analyst_workbook
2. Page-2 strip greyscale / print rules
3. Module ordering / source of truth
4. Phase 2 testing / regression strategy

### Q-Extra.1: When ONE module's render_email_panel() or render_analyst_tabs() raises an exception, what should the composer do?

**Options:** Catch + log + insert error placeholder / Catch + log silently + skip module / Re-raise to crash the batch.

**User selected:** Catch + log + insert error placeholder.

### Q-Extra.2: Should the page-2 RAG strip include a print-greyscale fallback?

**Options:** Yes — small text badge alongside the colored band / No — rely on color only / Yes — add a status icon shape (▲/●/▼) alongside text.

**User selected:** Yes — add a status icon shape (▲/●/▼) alongside text.

### Q-Extra.3: What's the canonical source of truth for module ordering across all three channels?

**Options:** module_configs list passed to ReportComposer.__init__ / Module-defined PRIORITY constant / Channel-specific ordering.

**User selected:** module_configs list passed to ReportComposer.__init__.

### Q-Extra.4: How does Phase 2 verify the regression baseline?

**Options:** Snapshot before/after smoke test in Phase 2 / Defer to Phase 4's regression cutover gate / Visual diff (PIL/imagehash) instead of bytewise.

**User selected:** Snapshot before/after smoke test in Phase 2.

### Final readiness re-check

**User selected:** Lock it — write CONTEXT.md.

---

## Decision Coverage

29 explicit decisions captured across 4 primary areas + 4 extras:
- D-01..D-08: PDF cover RAG strip page (8 decisions)
- D-09..D-15: Email body integration (7 decisions)
- D-16..D-21: Analyst workbook structure (6 decisions)
- D-22..D-27: Composer return contract (6 decisions)
- D-28: Error isolation extra
- D-29: Phase 2 verification extra

All map to one or more of the 4 phase REQ-IDs (COMPOSER-01..04).

## Scope Creep Redirected

None during this session. User stayed within the composer / pipeline domain consistently.

## Claude's Discretion Notes

- Exact CSS shape (CSS grid vs flexbox vs nested tables for WeasyPrint compat) for the page-2 strip cells
- Whether `assemble_email_body()` uses Jinja2 internally or hand-built HTML strings (lean toward hand-built for inline-CSS predictability)
- Whether `_PDF_COVER_TEMPLATE` is left as-is and a new `_PDF_RAG_STRIP_TEMPLATE` is added, or both restructured into a shared cover-block helper
- Exact run-time API for D-29's regression snapshot test (pytest fixture / smoke script / gsd-verifier-driven smoke)
- Exact placeholder HTML/CSS wording for the D-28 error placeholder
- Whether the `STATUS_ICON` palette lives in `rag_utils.py` or is inlined at the page-2 cell rendering site

---

*Discussion log generated 2026-05-05*
