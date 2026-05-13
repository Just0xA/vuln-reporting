---
phase: 02-reportcomposer-upgrades
plan: 02
subsystem: report-composer
tags:
  - composer
  - email
  - panels
  - phase-2
requirements:
  - COMPOSER-02
dependency_graph:
  requires:
    - reports/modules/base.py (Phase 1 BaseModule.render_email_panel contract — no-op default returns "")
    - reports/modules/composer.py (existing assemble_pdf iteration + skip-empty + try/except patterns)
    - delivery/email_template.py (existing _jinja_env + helper functions reused unchanged)
    - templates/report_email.html (existing SECTION 3 KPI tiles wrapped in conditional)
  provides:
    - reports.modules.composer.ReportComposer.assemble_email_body — NEW public method
    - delivery.email_template.build_email_body_modular — NEW sibling renderer function
    - templates/report_email.html — {% if module_panels_html %}...{% else %}<KPI tiles>{% endif %} conditional
  affects:
    - templates/report_email.html SECTION 3 — now branches between modular panels and legacy KPI tiles
tech-stack:
  added: []
  patterns:
    - Per-module exception isolation (try/except + log + visible inline-CSS error <div>) mirroring assemble_pdf() at composer.py:602-613 (D-28)
    - Skip-empty contribution rule (D-14) mirroring assemble_pdf()'s line 615 idiom
    - Sibling-function pattern for additive renderers — same Jinja2 env, same template, same helpers; only context-dict differs (D-15)
    - Backward-compat conditional swap in templates — keep the legacy block in {% else %} branch byte-unchanged (D-10, D-11)
key-files:
  created: []
  modified:
    - reports/modules/composer.py — assemble_email_body() public method (+88 lines, between collect_email_kpis and collect_audit_info)
    - delivery/email_template.py — build_email_body_modular() sibling function (+112 lines, appended after build_email_body)
    - templates/report_email.html — variables comment doc + SECTION 3 conditional wrapping (+14 lines net)
decisions:
  - D-09..D-15 honored verbatim — panels-only fragment, no scope banner / SLA / footer; template owns the wrapping shell; legacy build_email_body() byte-unchanged; build_email_body_modular() reuses _jinja_env, template, and helpers; KPI tiles stay in the {% else %} branch
  - D-28 honored — per-module render_email_panel() exception is caught + logged + replaced with an inline-CSS error placeholder <div>; never aborts assembly
metrics:
  completed: 2026-05-06
  duration: ~15 minutes
  tasks: 3
  files_modified: 3
  commits: 3
---

# Phase 2 Plan 02: assemble_email_body + build_email_body_modular + Template Conditional — Summary

Implements COMPOSER-02 — the email-body channel of the new four-channel module render contract. The composer gains a public `assemble_email_body(results) -> str` that concatenates per-module panels in `_module_configs` order. A sibling Jinja2 renderer `build_email_body_modular()` is added next to the unchanged `build_email_body()`. The shared email template grows a `{% if module_panels_html %}{% else %}{% endif %}` conditional that swaps the SECTION 3 KPI tiles for the panels fragment when present, and falls through to the legacy block when absent.

After Phase 2, board / management modules can be migrated (Phase 3) to override `render_email_panel()` and produce per-module panels (gauge + headline + RAG label + driver narrative); legacy reports (`ops_remediation`, `vuln_export`) keep rendering today's KPI tiles unchanged because the template falls through to the `{% else %}` branch when `module_panels_html` is not provided.

## What Shipped

### Task 1 — `ReportComposer.assemble_email_body()` (composer.py)

- Added new public method `assemble_email_body(self, results: list[ModuleData]) -> str` between `collect_email_kpis()` and `collect_audit_info()`.
- Iterates `results` in `_module_configs` order; for each module:
  - Registry miss: logs warning, silently skips (mirrors `collect_email_kpis()` at composer.py:691-692).
  - Renders via `instance.render_email_panel(data, config)` inside `try/except` per D-28.
  - On exception: logs traceback (`# noqa: BLE001`), substitutes a visible inline-CSS error `<div>` containing the module's display name and the exception message — uses `border:1px solid #d32f2f` per acceptance criterion.
  - Empty / whitespace-only HTML: silently skipped per D-14 (mirrors `assemble_pdf()` line 615).
- Returns the concatenated panel HTML joined by `"\n"`. Returns `""` when every panel is empty.
- Composer never calls `draw_gauge()` itself (D-13) — modules embed gauges as `data:image/png;base64,...` inside the returned HTML fragment in Phase 3.
- **File:** `reports/modules/composer.py` (lines 902-993)
- **Commit:** `f07c66c`

### Task 2 — `build_email_body_modular()` (delivery/email_template.py)

- Added sibling function `build_email_body_modular(group_config, report_outputs, module_panels_html, *, excel_omitted=False, generated_at=None) -> str` at the end of the module.
- Reuses the SAME `_jinja_env`, the SAME `templates/report_email.html`, and the SAME helper functions (`build_kpi_metrics`, `build_chart_cids`, `build_attached_reports`, `build_sla_table`, `_safe_get`) as `build_email_body()`.
- Context dict adds `module_panels_html` while STILL passing `kpi_metrics` so the template's `{% else %}` branch renders the legacy tiles when `module_panels_html` is empty (D-10, D-11).
- On render failure: returns the same minimal plain-HTML fallback shape as `build_email_body()` (`<p>...HTML template render failed...</p>`).
- **`build_email_body()` is byte-unchanged.** Its docstring, signature, log line `Email body rendered for group`, and code body are all preserved verbatim — verified by grep counts (`def build_email_body`: 2 matches total; original log line: still 1 occurrence).
- **File:** `delivery/email_template.py` (lines 421-532)
- **Commit:** `da58793`

### Task 3 — `{% if module_panels_html %}` template conditional (templates/report_email.html)

- **Edit 1:** Variables comment block at the top of the template gains a 3-line entry for `module_panels_html (str)` documenting the new context variable.
- **Edit 2:** SECTION 3 KPI TILES `<tr>...</tr>` wrapped in `{% if module_panels_html %}{% else %}{% endif %}`:
  - **`{% if %}` branch** — emits a single `<tr>` whose `<td>` carries `{{ module_panels_html | safe }}`. The `| safe` filter is required so the panel HTML's inline `<style>` attributes and `<table>` markup survive Jinja2 autoescape.
  - **`{% else %}` branch** — emits the EXISTING KPI tiles `<tr>` byte-for-byte unchanged from before this plan (preserves backward-compat for `ops_remediation`, `vuln_export`).
- The existing SECTION 3 banner comment (`<!-- ===== SECTION 3 — KPI TILES ===== -->`) is kept above the conditional. SECTION 1 (header band), SECTION 2 (scope banner), SECTION 4 (inline charts), SECTION 5 (attached reports), SECTION 6 (SLA reference), SECTION 7 (footer), and the OUTER WRAPPER / INNER CARD are all untouched (D-11).
- **Exact line range edited:** lines 25 (variables comment) and 92-141 (SECTION 3 wrapping). Net diff: +14 lines.
- **File:** `templates/report_email.html`
- **Commit:** `7bcc4ff`

## Confirmation: Byte-Unchanged Surfaces

| Surface | Status |
|---------|--------|
| `delivery/email_template.build_email_body()` | byte-unchanged — signature, docstring, body, and log line `Email body rendered for group` all preserved verbatim (verified by grep count = 1) |
| `delivery/email_template._jinja_env` | byte-unchanged — both renderers share the same singleton (`is` check passes in verify) |
| `delivery/email_template.build_kpi_metrics` / `build_attached_reports` / `build_chart_cids` / `build_sla_table` / `_safe_get` / `_REPORT_DESCRIPTIONS` / `_SEV_COLOR` / `_SEV_BG` | byte-unchanged — reused unmodified |
| `reports/modules/composer.assemble_pdf` / `_build_rag_strip_page` / `assemble_excel` / `collect_email_kpis` / `collect_audit_info` / `get_error_summary` / `_config_for` / `_warn_invalid_configs` / `run_all` / `run_module` | byte-unchanged — Plan 02-02 is purely additive on the composer |
| `reports/modules/composer.py` module-level imports (`logging`, `traceback`, `datetime`, `typing`, `pandas`, `BaseModule`, `ModuleConfig`, `ModuleData`, `registry`) | byte-unchanged — `assemble_email_body` reuses the existing `traceback` and `logger` |
| `templates/report_email.html` SECTION 1 / SECTION 2 / SECTION 4 / SECTION 5 / SECTION 6 / SECTION 7 / OUTER WRAPPER / INNER CARD | byte-unchanged |
| Inside `{% else %}` branch — every line of the existing KPI tiles `<tr>` (Key Metrics header, KPI tile grid, `kpi_metrics` for-loop, fallback `Metrics not available` cell) | byte-unchanged |
| 8 module discovery (board + management board metric modules) | unchanged — `len(registry._modules) == 8` after import |

## Verification Evidence

All three Task `<verify>` commands pass end-to-end:

```text
Task 1 — assemble_email_body OK
        signature: (self, results) — confirmed via inspect.signature
        registered stub returns its panel HTML (data-stub="A" present)
        raising stub gets the placeholder div with both the marker phrase
          ("email panel render failed") and the original exception text
          ("explode")
        un-migrated module silently skipped (no module ID in body)
        ordering preserved (PANEL_A appears before the error div)
        border:1px solid #d32f2f appears once in composer.py
        composer module imports cleanly

Task 2 — build_email_body_modular OK
        signature: (group_config, report_outputs, module_panels_html, *,
                    excel_omitted=False, generated_at=None) — confirmed
        et._jinja_env is _jinja_env (same singleton)
        non-empty panels render (P1, P2, data-test="OK" all present)
        empty panels fall back to legacy KPI tiles (Key Metrics present)
        new function appears AFTER original build_email_body() in source
        original build_email_body() byte-unchanged (log line count = 1)

Task 3 — Template conditional OK — all 3 paths verified
        Path A (legacy build_email_body) → KPI tiles render; no
          data-modular="YES" leak
        Path B (modular w/ panels) → injected HTML present; no
          legacy "Key Metrics" header
        Path C (modular w/ empty panels) → falls back to KPI tiles
        D-11: scope banner, attached reports, SLA reference, footer
          all rendered in every path

Global checks:
        grep -c draw_gauge reports/modules/composer.py == 0   (D-13)
        registered modules after import: 8 (unchanged from baseline)
        ReportComposer.assemble_email_body present
```

Acceptance-criteria grep counts:

| Pattern | File | Expected | Actual |
|---------|------|----------|--------|
| `def assemble_email_body` | reports/modules/composer.py | 1 | 1 ✓ |
| `border:1px solid #d32f2f` | reports/modules/composer.py | >= 1 | 1 ✓ |
| `draw_gauge` | reports/modules/composer.py | 0 | 0 ✓ |
| `def build_email_body_modular` | delivery/email_template.py | 1 | 1 ✓ |
| `def build_email_body` | delivery/email_template.py | 2 | 2 ✓ |
| `Email body rendered for group` (original log line) | delivery/email_template.py | 1 | 1 ✓ |
| `{% if module_panels_html %}` | templates/report_email.html | 1 | 1 ✓ |
| `{% else %}` | templates/report_email.html | >= 1 | 3 ✓ |
| `{% endif %}` | templates/report_email.html | >= 2 | 5 ✓ |
| `module_panels_html (str)` | templates/report_email.html | 1 | 1 ✓ |
| `module_panels_html | safe` | templates/report_email.html | 1 | 1 ✓ |

## Deviations from Plan

None. D-09..D-15 and D-28 honored verbatim. No Rule-1, Rule-2, or Rule-3 auto-fixes were required — every step matched the plan's exact code blocks.

The Task 2 `<verify>` block is logically dependent on Task 3 (the rendered-output assertions for `data-test="OK"` injection require the template conditional to be in place). This is not a deviation — the plan's `<verify>` blocks are intentionally written to verify the end-state behavior; running them in the listed order means Task 2's verify formally passes after Task 3 wires the template. Both Tasks 2 and 3 verifies were re-run after Task 3 committed and both pass cleanly. The structural assertions inside Task 2's verify (signature parameters, `_jinja_env` reuse, function exists and is callable) all passed standalone before Task 3.

## Threat Flags

None. The implementation respects the threat register decisions documented in the plan:
- T-02-02-01 (HTML injection via `{{ module_panels_html | safe }}`) — accepted; same trust level as existing `_PDF_COVER_TEMPLATE` interpolation and the legacy KPI-tile branch's `metric.value` / `metric.color` interpolations. Modules are project Python code reviewed during PR.
- T-02-02-02 (panel render exception kills body) — mitigated by `try/except Exception` mirroring assemble_pdf() pattern; logs traceback, substitutes visible error `<div>` per D-28.
- T-02-02-03 (base64 gauge resource exhaustion) — accepted; Phase 3 work to size gauges (~120×120 px) and stay under SMTP/Outlook limits. Not relevant in Phase 2 because no module overrides `render_email_panel` yet.
- T-02-02-04 (non-string `module_panels_html`) — accepted; type hint declares `str` and the only producer is `assemble_email_body()` which always returns `str`.

No new security-relevant surface introduced (no new network endpoints, no new auth paths, no schema changes at trust boundaries).

## Self-Check: PASSED

- File `reports/modules/composer.py` exists. `assemble_email_body` method present at line 906. Per-module exception placeholder uses `border:1px solid #d32f2f`. `draw_gauge` not referenced anywhere in the file.
- File `delivery/email_template.py` exists. `build_email_body_modular` function present after the unchanged `build_email_body`. Both functions share `_jinja_env` (verified by `is` check).
- File `templates/report_email.html` exists. `{% if module_panels_html %}` conditional wraps SECTION 3 KPI tiles; `module_panels_html (str)` doc line in variables comment block; `module_panels_html | safe` rendering in the `{% if %}` branch.
- Commit `f07c66c` (Task 1) — present in git log.
- Commit `da58793` (Task 2) — present in git log.
- Commit `7bcc4ff` (Task 3) — present in git log.
