---
status: resolved
trigger: "When the Board Metric PDF prints using the modules, the PDF page for the metric bleeds onto a second page due to the length of the measurement explanation. Anytime it is longer than 2 lines a second page with just those 2 lines is created. My thought was to move the Explanation inline with the Metric graphic. The Metric graphic and numbers would be on the left hand side, and the explanation would be on the right hand side. The Measurement explanation text would be left aligned."
created: 2026-06-02
updated: 2026-06-02
---

# Debug Session: board-metric-pdf-page-bleed

## Symptoms

- **Expected behavior:** Each board metric module renders within a single PDF page.
- **Actual behavior:** When a metric's measurement explanation text exceeds 2 lines, the module overflows onto a second PDF page that contains only those overflowing ~2 lines of explanation text.
- **Error messages:** None — visual/layout defect in WeasyPrint PDF render.
- **Timeline:** Observed in the modules-based Board Metric PDF (board_summary / composed_report on reports/modules/ infrastructure).
- **Reproduction:** Render a board metric PDF where a module's measurement explanation is longer than 2 lines.
- **User-proposed fix:** Move the explanation inline with the metric graphic — graphic + numbers on the left, explanation on the right (left-aligned text) — so the per-module PDF section stays on one page.

## Current Focus

- hypothesis: CONFIRMED — Each board module's render_pdf_section() stacked content vertically (heading -> gauge -> status -> support numbers -> BU table -> explanation paragraph). The trailing explanation is the last block; when its lines pushed the section's total height past the page content area (reduced by PDF chrome header/footer margins), the trailing lines bled onto a second page.
- next_action: (done) two-column layout implemented and verified via real render.
- test: tests/verify_board_page_bleed.py (real WeasyPrint render, pypdf page count, worst-case explanation padding)
- expecting: worstcase page count drops from 3 to 2 for all board modules — ACHIEVED
- reasoning_checkpoint:
- tdd_checkpoint:

## Evidence

- timestamp: 2026-06-02T10:25Z
  observation: Board modules (scan_coverage_sla, critical_remediation_sla, high_risk_assets, aged_vulns_assets) each built their PDF section as a vertical stack in render_pdf_section(): h2 heading, centered gauge image (width:46%), centered status badge, centered support-numbers table (52% width), full-width "Top 5 Worst-Performing Business Units" data-table, then a multi-line `.explanatory-text` paragraph last. composer.py assemble_pdf inserts `<div class="page-break">` between sections (one page per module).
  source: reports/modules/scan_coverage_sla_module.py:676-684 (pre-fix), aged_vulns_assets_module.py:629-637, critical_remediation_sla_module.py:640-648, high_risk_assets_module.py:633-641, composer.py:678-681

- timestamp: 2026-06-02T10:26Z
  observation: Real-render harness with nominal synthetic data (full sections: gauge + 5-row BU table + ~10-line explanation) produced cover+1 page per module (no bleed). The nominal explanations alone do not exceed the content area with this data.
  source: tests/verify_board_page_bleed.py (nominal pass)

- timestamp: 2026-06-02T10:27Z
  observation: board_summary applies PDF chrome (PdfChromeConfig) which overrides @page with margin 18mm top/bottom plus a 15mm running header band, reducing usable content height vs the base _PDF_CSS @page. This is the production render path.
  source: reports/board_summary.py:278-285, reports/modules/pdf_chrome.py:169-227

- timestamp: 2026-06-02T10:28Z
  observation: REPRODUCED via real render. Padding the explanation paragraph with ~4 extra sentences (production worst case) pushed every board module from 2 pages (cover+1) to 3 pages (cover+2 = bleed). Confirms the explanation is the overflow block and the bug is height-driven, exactly as reported.
  source: tests/verify_board_page_bleed.py worst-case pass — scan_coverage_sla/critical_remediation_sla/aged_vulns_assets all nominal=2 worstcase=3

- timestamp: 2026-06-02T10:55Z
  observation: FOLLOW-UP (review-render). Two-column layout worked but the right-column explanation text bled ~5mm past the section-heading underline / BU-table right edge. Cause: left cell padding-right:5mm under WeasyPrint's default box-sizing:content-box adds to the 50% column width, so the table rendered wider than its 100% container. Fix: box-sizing:border-box on both table-cells so padding sits inside the 50%. Verified via rasterized PDF crop (PyMuPDF) — text right edge now aligns to the underline; page-bleed gate still PASS (all board modules nominal=2 worstcase=2).
  source: reports/modules/board_pdf_layout.py (box-sizing:border-box on cells); tests/render_board_review_pdf.py review render

- timestamp: 2026-06-02T10:40Z
  observation: FIX VERIFIED via real render. After moving the gauge+status+support to a left table-cell and the explanation to a right table-cell (BU table full-width below), worst-case page count dropped 3 -> 2 for all board modules; nominal stays 2. Structural check confirms gauge precedes explanation in the right cell and the BU table renders below both. Existing composer/board/module test suites pass (11 composer/chrome tests, 56 level-1 module tests, 8 composed_report smoke checks). WeasyPrint 65.1; CSS display:table used (not flex) per repo's documented flex quirks.
  source: tests/verify_board_page_bleed.py GREEN pass; pytest test_phase2/6 + composed_report_smoke + test_modules_level1

## Eliminated

- Not a page-break logic bug in composer.assemble_pdf — the page-break div placement is correct; the section content itself exceeded one page.
- Not specific to one module — all four board modules shared the identical vertical-stack pattern and all reproduced; all four received the identical fix.

## Resolution

- root_cause: Board metric PDF sections stacked the measurement-explanation paragraph as the LAST block below an already-tall vertical column (gauge image + status badge + support numbers + 5-row BU table). Under the production PDF chrome's reduced content height, a measurement explanation longer than ~2 lines pushed the section's total height past the single-page content area, so the trailing explanation lines bled onto a second page.
- fix: Restructured each board module's render_pdf_section to a two-column row — metric graphic + numbers on the LEFT, measurement explanation (left-aligned) on the RIGHT — via a new shared helper reports/modules/board_pdf_layout.two_column_metric_section(). The Top-5 BU table remains full width below the two-column row. The explanation now shares vertical space with the gauge column instead of stacking below it, shrinking section height. CSS display:table layout (not flex) per the repo's documented WeasyPrint flex quirks.
- verification: tests/verify_board_page_bleed.py — real WeasyPrint render + pypdf page count. Worst-case explanation dropped from 3 pages to 2 (cover+1) for all board modules; nominal stays at 2. Existing test suites pass (no regression).
- files_changed:
  - reports/modules/board_pdf_layout.py (new — shared two-column section helper)
  - reports/modules/scan_coverage_sla_module.py (render_pdf_section return + import)
  - reports/modules/critical_remediation_sla_module.py (render_pdf_section return + import)
  - reports/modules/high_risk_assets_module.py (render_pdf_section return + import)
  - reports/modules/aged_vulns_assets_module.py (render_pdf_section return + import)
  - tests/verify_board_page_bleed.py (new — real-render page-bleed verification harness)
