---
status: complete
phase: 02-reportcomposer-upgrades
source: [02-VERIFICATION.md]
started: 2026-05-06T05:11:00Z
updated: 2026-05-06T07:05:00Z
approved_by: monroe.justin@gmail.com
---

## Current Test

[all complete]

## Tests

### 1. Render the Phase 2 PDF for a real recipient group through WeasyPrint
expected: Page 1 cover (existing) renders unchanged; new page 2 carries the literal heading "Risk Status Summary" with one cell per registered module; each cell shows label, headline value, and a colored band with a Unicode shape icon (▲/●/▼/○) plus rag_label text; module sections start on page 3+.
result: pass
notes: |
  Validated via WeasyPrint render (`output/_phase2_smoke.pdf`) and live
  Tenable run of `board_summary` end-to-end. Two visual defects surfaced
  during UAT and were fixed in follow-up commits to plan 02-01:

  - `4f51df8 fix(02-01): center page-2 RAG strip and equalize cell heights`
    — switched the row from `display: table` to flexbox so cells stay
    uniform height regardless of label wrapping and don't overflow the
    page.
  - `7be4355 fix(02-01): pin RAG cell widths in mm to defeat WeasyPrint
    flex shrink` — switched cell `flex-basis` from
    `calc(25% - 3mm)` to fixed `62mm` because WeasyPrint cannot
    consistently resolve mixed `%` / `mm` calc() and was falling back
    to shrink-to-content sizing. With A4 landscape @page margins, 4 ×
    62mm cells + 3 × 4mm gaps = 260mm leaving 6.5mm gutter each side,
    visually centered.
  - `93840fb refactor: shorten Critical Remediation SLA module
    DISPLAY_NAME` — dropped "(30-day window)" from the cell label;
    the qualifier remains in the Excel tab heading and runbook docs.

  Final visual: page 1 cover unchanged; page 2 "Risk Status Summary"
  with 4 uniform-width centered cells; module sections on page 3+.
  Strip cells show gray "No Data" placeholders today because no Phase
  1 module yet populates `data.rag_strip` in `compute()` — Phase 3
  (BOARD-01..04) closes that gap.

### 2. Send a Phase 2 email body through Outlook, Gmail, and Apple Mail
expected: When `module_panels_html` is non-empty, panels render in place of KPI tiles with inline-CSS only; scope banner, attached-reports list, SLA reference table, and footer all render unchanged; no `<style>` blocks present; panels render correctly across all three clients.
result: pass
notes: |
  Validated via `scripts/smoke_email_phase2.py` (committed in
  `31453c6 test(02-02): add Phase 2 email smoke script for off-network
  UAT`). Smoke uses Gmail SMTP App Password from a home dev system,
  builds the panels-only fragment via
  `composer.assemble_email_body()`, wraps via
  `build_email_body_modular()`, sends with `smtplib` directly (the
  production `send_report_email()` is hard-wired to legacy
  `build_email_body()` until Phase 3 reroutes it). Stub panels (4
  boxes — label / headline / RAG band / driver narrative) inject
  Phase-3-style content so the `{% if module_panels_html %}` branch
  renders end-to-end.

  Email body width (620px) clarified during UAT — preserved per
  industry email-design convention (Outlook clip threshold, Mailchimp
  / Litmus / Email on Acid published guidance). Wider card deferred
  to a future email-template review.

### 3. Confirm board_summary end-to-end against a live Tenable export
expected: `run_report()` returns the six-key dict `{pdf, excel, charts, metrics, analyst_excel, email_body_html}`; pdf and excel files land in `output_dir` with correct content; `analyst_excel` is None on Phase 2 (no module migrated) per D-20 all-empty fallback; existing PDF + Excel content is byte-equivalent to pre-Phase-2 baseline.
result: pass
notes: |
  Validated via `python run_all.py --group "Board Summary" --no-email`
  against live Tenable export. Page 3+ module sections rendered real
  metric data, Excel rendered real data — both unchanged from
  pre-Phase-2 behavior. Page 2 RAG strip rendered 4 gray "No Data"
  cells per the documented Phase-2 baseline (no Phase 1 module yet
  populates `data.rag_strip`; the empty-data guard pattern in
  CLAUDE.md prescribes the gray placeholder). Phase 3 will populate
  the strip when modules migrate.

  Six-key return dict shape confirmed:
  `{pdf, excel, charts, metrics, analyst_excel, email_body_html}`
  with `analyst_excel = None` and `email_body_html = ""` per D-20
  all-empty fallback (no module yet populates the panels-only or
  analyst-tab surfaces).

## Summary

total: 3
passed: 3
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

None.
