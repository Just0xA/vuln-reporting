# Phase 2: ReportComposer Upgrades - Pattern Map

**Mapped:** 2026-05-06
**Files analyzed:** 5 (3 edits to existing, 2 template/Jinja edits) plus 3 NEW methods on `ReportComposer`
**Analogs found:** 5 / 5 (every new surface has an exact in-repo analog — Phase 2 is purely additive in the same idioms)

---

## File Classification

| Phase 2 Surface | Role | Data Flow | Closest Analog | Match Quality |
|-----------------|------|-----------|----------------|---------------|
| `reports/modules/composer.py:assemble_pdf()` (edit — page-2 strip insertion) | composer / HTML assembler | transform (results → HTML string) | self — `assemble_pdf()` cover/section seam at composer.py:557-582 | exact (in-place extension) |
| `reports/modules/composer.py:assemble_email_body()` (NEW) | composer / HTML assembler | transform (results → HTML fragment) | `composer.assemble_pdf()` (composer.py:467-582) — iteration + skip-empty + try/except | exact (sibling method) |
| `reports/modules/composer.py:assemble_analyst_workbook()` (NEW) | composer / Excel writer | file-I/O (results → .xlsx) | `composer.assemble_excel()` (composer.py:588-658) + `_write_metadata_tab()` (composer.py:857-905) | exact (sibling method + reused metadata helper) |
| `reports/modules/composer.py:run_full_pipeline()` (NEW) | composer / orchestration | request-response (results → bundle dict) | `composer.run_all()` (composer.py:320-353) — orchestrator that calls per-channel methods | role-match (existing orchestrator delegates `compute()`; new orchestrator delegates render channels) |
| `reports/board_summary.py:run_report()` (edit — ~3 lines) | report script entry point | request-response | self — current call sites at board_summary.py:228-261 | exact (in-place extension) |
| `reports/management_summary.py:run_report()` (edit — ~3 lines) | report script entry point | request-response | `reports/board_summary.py:run_report()` (board_summary.py:82-272) | exact (sibling pattern) |
| `delivery/email_template.py:build_email_body_modular()` (NEW) | email body renderer | transform (group_config + html → rendered HTML) | `delivery/email_template.py:build_email_body()` (email_template.py:347-418) | exact (sibling function, same Jinja env) |
| `templates/report_email.html` (edit — `{% if module_panels_html %}`) | Jinja2 email template | transform | self — existing KPI tiles block at template.html:92-141 | exact (conditional swap) |

---

## Pattern Assignments

### `reports/modules/composer.py:assemble_pdf()` — page-2 RAG strip insertion (EDIT)

**Analog:** self — the existing cover/section seam at `composer.py:557-582`.

**Existing cover-template + body assembly** (composer.py:557-582):
```python
cover = _PDF_COVER_TEMPLATE.format(
    title        = title,
    subtitle     = subtitle,
    generated_at = generated_at_str,
    module_list  = module_list_str,
)

body = "\n".join(sections) if sections else (
    '<p class="explanatory-text">No module output to display.</p>'
)

return "\n".join([
    _PDF_DOCTYPE,
    "<html>",
    "<head>",
    '<meta charset="utf-8">',
    f"<title>{title}</title>",
    _PDF_CSS,
    f"<style>{page_css}</style>" if page_css else "",
    "</head>",
    "<body>",
    cover,
    body,                                     # ← Phase 2 inserts rag_strip_page BEFORE this
    "</body>",
    "</html>",
])
```

**Existing per-section iteration + skip-empty + try/except** (composer.py:506-541) — Phase 2's new RAG-strip cell loop mirrors this:
```python
for i, data in enumerate(results):
    mod_class = registry.get(data.module_id)
    if mod_class is None:
        logger.warning(...)
        continue

    try:
        config   = self._config_for(data.module_id)
        instance = mod_class()
        html     = instance.render_pdf_section(data, config)         # ← swap to render_rag_strip_entry()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "ReportComposer.assemble_pdf [%s]: render_pdf_section() raised: %s\n%s",
            data.module_id, exc, traceback.format_exc(),
        )
        html = (
            f'<div class="error-box">'
            f"<strong>{data.display_name}</strong>: PDF render failed — {exc}"
            f"</div>"
        )

    if not html or not html.strip():
        continue                                                       # ← D-06: NOT skipped here; render gray cell
    if sections:
        sections.append('<div class="page-break"></div>')
    sections.append(html)
```

**Existing `_PDF_COVER_TEMPLATE`** (composer.py:259-269) — Phase 2's new `_PDF_RAG_STRIP_TEMPLATE` (or inline construction) mirrors this format-string idiom:
```python
_PDF_COVER_TEMPLATE = """
<div class="report-cover">
  <p class="cover-title">{title}</p>
  <p class="cover-subtitle">{subtitle}</p>
  <hr class="cover-divider">
  <div class="cover-meta">
    <p style="margin:0 0 2mm 0;">Generated: {generated_at}</p>
    <p style="margin:0;">Sections: {module_list}</p>
  </div>
</div>
"""
```

**Existing `_PDF_CSS`** (composer.py:63-257) — Phase 2's new strip CSS (`.rag-strip`, `.rag-cell-row`, `.rag-cell`, `.rag-cell-label`, `.rag-cell-value`, `.rag-cell-band`) extends the same `<style>` block. The cover-page `page-break-after` idiom is at composer.py:226 — page 2 needs the same `page-break-after: always` to push module sections onto page 3+:
```css
.report-cover {
    page-break-after: always;
    text-align: center;
    padding-top: 48mm;
}
```

**RAG cell color/label sourcing** — read directly from each module's `data.rag_strip` dict (already populated in Phase 1, defaults to gray "No Data" via `_empty_result`). Concrete shape from base.py:443-448:
```python
{
    "label":          self.DISPLAY_NAME,
    "headline_value": NO_DATA_HEADLINE,    # "—"
    "rag_color":      STATUS_COLOR["no_data"],   # "#757575"
    "rag_label":      STATUS_LABEL["no_data"],   # "No Data"
}
```

**D-08 status-icon mapping (Phase 2 may add to `rag_utils.py` OR inline a four-key dict in composer.py):**
```python
STATUS_ICON = {
    "green":   "▲",   # U+25B2
    "yellow":  "●",   # U+25CF
    "red":     "▼",   # U+25BC
    "no_data": "○",   # U+25CB
}
```

---

### `reports/modules/composer.py:assemble_email_body()` (NEW)

**Analog:** `composer.assemble_pdf()` at composer.py:467-582 — same iteration shape, same skip-empty rule, same try/except placeholder.

**Iteration template to mirror exactly** (composer.py:506-541):
```python
def assemble_email_body(self, results: list[ModuleData]) -> str:
    """
    Assemble per-module email panels into a panels-only HTML fragment.
    Mirrors assemble_pdf() iteration + skip-empty + per-module exception
    isolation (D-09, D-14, D-28).
    """
    panels: list[str] = []

    for data in results:
        mod_class = registry.get(data.module_id)
        if mod_class is None:
            logger.warning(
                "ReportComposer.assemble_email_body: module '%s' not in "
                "registry — skipping panel.",
                data.module_id,
            )
            continue

        try:
            config   = self._config_for(data.module_id)
            instance = mod_class()
            html     = instance.render_email_panel(data, config)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "ReportComposer.assemble_email_body [%s]: render_email_panel() "
                "raised: %s\n%s",
                data.module_id, exc, traceback.format_exc(),
            )
            html = (
                f'<div style="border:1px solid #d32f2f; padding:8px; '
                f'margin:6px 0; color:#5D4037; background:#FFF3CD;">'
                f"<strong>{data.display_name}</strong>: "
                f"email panel failed — {exc}"
                f"</div>"
            )

        if not html or not html.strip():
            continue                                  # D-14: silent skip on no-op default ""

        panels.append(html)

    return "\n".join(panels)
```

**Reference panel HTML shape** (D-12, from CONTEXT.md `<specifics>`):
```html
<table role="presentation" cellpadding="0" cellspacing="0" border="0"
       style="width:100%; max-width:600px; margin:8px 0;">
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

Note: per D-13, `render_email_panel()` (Phase 3) is the panel-html-builder — `assemble_email_body()` only concatenates. The composer never calls `draw_gauge()` itself.

---

### `reports/modules/composer.py:assemble_analyst_workbook()` (NEW)

**Analog:** `composer.assemble_excel()` at composer.py:588-658 (iteration + skip-empty + try/except) + `_write_metadata_tab()` at composer.py:857-905 (the metadata-tab writer pattern).

**Iteration + sheet-name handling** (mirrors composer.py:616-643):
```python
def assemble_analyst_workbook(
    self,
    results:     list[ModuleData],
    output_path: Path,
    *,
    generate:    bool = True,                  # D-25 Phase 4 opt-out hook (always True in Phase 2)
) -> Optional[Path]:
    """
    Write a separate {report_slug}_{date}_analyst.xlsx via openpyxl.
    Returns Path on success; None when generate=False or every module
    returned [] (D-20: all-empty workbook → skip file entirely).
    """
    if not generate:
        return None

    import openpyxl  # noqa: PLC0415  (deferred import — keeps composer light)

    # Collect all (sheet_name, df) tuples first so we can decide to skip
    collected: list[tuple[str, str, pd.DataFrame]] = []      # (module_id, sheet_name, df)
    used_names: set[str] = set()
    failures:   list[tuple[str, str]] = []                   # (module_id, error_msg)

    for data in results:
        mod_class = registry.get(data.module_id)
        if mod_class is None:
            logger.warning(...)
            continue

        try:
            config   = self._config_for(data.module_id)
            instance = mod_class()
            tabs     = instance.render_analyst_tabs(data, config)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "ReportComposer.assemble_analyst_workbook [%s]: "
                "render_analyst_tabs() raised: %s\n%s",
                data.module_id, exc, traceback.format_exc(),
            )
            failures.append((data.module_id, str(exc)))
            continue

        for sheet_name, df in tabs:
            if df is None or df.empty:
                continue                                      # D-20 contributing rule
            unique = _unique_sheet_name(sheet_name, used_names)   # D-18: auto-suffix _2/_3, 31-char clip
            used_names.add(unique)
            collected.append((data.module_id, unique, df))

    # D-20: all-empty workbook → no file
    if not collected:
        logger.info(
            "ReportComposer.assemble_analyst_workbook: every module returned "
            "[] from render_analyst_tabs() — skipping analyst workbook."
        )
        return None

    wb = openpyxl.Workbook()
    if wb.worksheets:
        wb.remove(wb.worksheets[0])    # mirrors board_summary.py:248-250

    for _module_id, sheet_name, df in collected:
        ws = wb.create_sheet(sheet_name)
        # Write header
        for col_idx, col in enumerate(df.columns, start=1):
            ws.cell(row=1, column=col_idx, value=str(col))
        # Write rows
        for row_idx, row in enumerate(df.itertuples(index=False), start=2):
            for col_idx, val in enumerate(row, start=1):
                ws.cell(row=row_idx, column=col_idx, value=val)

    # _Metadata tab — mirror _write_metadata_tab() shape (D-19)
    _write_analyst_metadata_tab(
        workbook        = wb,
        results         = results,
        report_date     = self._report_date,
        module_configs  = self._module_configs,
        failures        = failures,
        scope_label     = ...,                        # D-19: "Application = UC Engineering" or "All Assets"
    )

    wb.save(str(output_path))
    return output_path
```

**Sheet-name uniqueness helper** (D-18 — Excel 31-char limit aware):
```python
def _unique_sheet_name(name: str, used: set[str]) -> str:
    base = name[:31]
    if base not in used:
        return base
    for i in range(2, 100):
        suffix = f"_{i}"
        clipped = (name[: 31 - len(suffix)]) + suffix
        if clipped not in used:
            return clipped
    raise ValueError(f"Could not generate unique sheet name from {name!r}")
```

**`_Metadata` tab analog — `_write_metadata_tab()` at composer.py:857-905**, especially the two-column key/value layout (lines 875-885):
```python
ws["A1"] = "Report Metadata"
ws["A2"] = "Generated At"
ws["B2"] = (
    report_date.strftime("%Y-%m-%d %H:%M UTC")
    if hasattr(report_date, "strftime")
    else str(report_date)
)
ws["A3"] = "Modules Run"
ws["B3"] = len(results)
ws["A4"] = "Modules Failed"
ws["B4"] = sum(1 for r in results if r.error)
```

D-19 Phase 2 fields:
- `Report` (slug)
- `Generated` (UTC timestamp)
- `Scope` (`"Application = UC Engineering"` or `"All Assets"`)
- `Modules` (comma-joined module IDs in `module_configs` order)

---

### `reports/modules/composer.py:run_full_pipeline()` (NEW)

**Analog:** `composer.run_all()` at composer.py:320-353 — existing orchestrator that iterates `module_configs` and delegates per-module work, returning a typed result.

**Existing run_all shape** (composer.py:320-353) sets the precedent for the orchestration style:
```python
def run_all(self) -> list[ModuleData]:
    results: list[ModuleData] = []
    for config in self._module_configs:
        data = self.run_module(config.module_id, config)
        results.append(data)
    success_count = sum(1 for r in results if r.error is None)
    fail_count    = len(results) - success_count
    logger.info(
        "ReportComposer.run_all: %d/%d modules succeeded.",
        success_count, len(results),
    )
    if fail_count:
        logger.warning(
            "ReportComposer.run_all: %d module(s) failed: %s",
            fail_count,
            [r.module_id for r in results if r.error],
        )
    return results
```

**`run_full_pipeline()` reference signature (D-22)** — orchestrates the four channels by calling existing per-channel methods internally:
```python
def run_full_pipeline(
    self,
    results:          list[ModuleData],
    output_dir:       Path,
    *,
    slug:             str,
    report_date:      Any,                  # date-like (matches self._report_date type)
    generate_analyst: bool = True,
    pdf_title:        str  = "",
    pdf_subtitle:     str  = "",
) -> dict[str, Any]:
    """
    Drive the four render channels and return a typed bundle dict
    (D-22). Existing per-channel methods stay public as building
    blocks (D-23); this is the convenience layer.
    """
    import openpyxl  # noqa: PLC0415

    bundle: dict[str, Any] = {
        "pdf_html":              "",
        "excel_workbook":        None,
        "analyst_workbook_path": None,
        "email_body_html":       "",
        "email_kpis":            {},
        "metrics":               {},
        "errors":                [],
    }

    # PDF (already wraps page-2 strip insertion internally per D-23)
    bundle["pdf_html"] = self.assemble_pdf(
        results, title=pdf_title, subtitle=pdf_subtitle,
    )

    # Main Excel
    wb = openpyxl.Workbook()
    if wb.worksheets:
        wb.remove(wb.worksheets[0])
    self.assemble_excel(results, wb)
    bundle["excel_workbook"] = wb

    # Analyst workbook (separate file)
    date_str = (
        report_date.strftime("%Y-%m-%d")
        if hasattr(report_date, "strftime")
        else str(report_date)
    )
    analyst_filename = f"{slug}_{date_str}_analyst.xlsx"   # D-16
    bundle["analyst_workbook_path"] = self.assemble_analyst_workbook(
        results,
        output_dir / analyst_filename,
        generate=generate_analyst,
    )

    # Email body fragment (panels-only, per D-09)
    bundle["email_body_html"] = self.assemble_email_body(results)

    # Email KPIs (existing legacy channel, kept for un-migrated callers)
    bundle["email_kpis"] = self.collect_email_kpis(results)

    # Per-module metrics dict for downstream consumers
    bundle["metrics"] = {r.module_id: r.metrics for r in results}

    # Aggregated error list (existing helper)
    bundle["errors"] = self.get_error_summary(results)

    return bundle
```

---

### `reports/board_summary.py:run_report()` (EDIT — ~3 new lines)

**Analog:** self — current PDF/Excel write block at board_summary.py:226-272.

**Current PDF + Excel write pattern** (board_summary.py:226-261):
```python
pdf_path: Optional[Path] = None
try:
    pdf_html = composer.assemble_pdf(
        results,
        title    = _REPORT_TITLE,
        subtitle = subtitle,
    )
    pdf_file = output_dir / _PDF_FILENAME
    _render_pdf(pdf_html, pdf_file)
    pdf_path = pdf_file
    logger.info("board_summary: PDF written → %s", pdf_file)
except Exception as exc:
    logger.error(
        "board_summary: PDF generation failed: %s", exc, exc_info=True
    )

excel_path: Optional[Path] = None
try:
    wb = openpyxl.Workbook()
    if wb.worksheets:
        wb.remove(wb.worksheets[0])

    composer.assemble_excel(results, wb)

    excel_file = output_dir / _EXCEL_FILENAME
    wb.save(str(excel_file))
    excel_path = excel_file
    logger.info("board_summary: Excel written → %s", excel_file)
except Exception as exc:
    logger.error(
        "board_summary: Excel generation failed: %s", exc, exc_info=True
    )
```

**Current return dict** (board_summary.py:263-272) — Phase 2 adds two keys; existing keys are byte-for-byte unchanged (D-24):
```python
return {
    "pdf":    pdf_path,
    "excel":  excel_path,
    "charts": [],
    "metrics": {
        "kpis":           kpis,
        "errors":         errors,
        "module_results": {r.module_id: r.metrics for r in results},
    },
    # NEW (D-24):
    # "analyst_excel":    bundle["analyst_workbook_path"],
    # "email_body_html":  bundle["email_body_html"],
}
```

**Phase 2 extension shape (D-26 — ~3 added lines):**
```python
bundle = composer.run_full_pipeline(
    results, output_dir,
    slug         = "board_summary",
    report_date  = generated_at,
    pdf_title    = _REPORT_TITLE,
    pdf_subtitle = subtitle,
)
# pdf_path, excel_path still come from existing try/except blocks (writes the bytes
# to disk via _render_pdf and wb.save). Bundle is the source of the new keys.
return {
    ...,
    "analyst_excel":   bundle["analyst_workbook_path"],
    "email_body_html": bundle["email_body_html"],
}
```

(Or — Claude's Discretion per CONTEXT.md — replace the per-channel writes with `bundle["pdf_html"]`/`bundle["excel_workbook"]` writes; either preserves byte-for-byte equivalence on equivalent input per ROADMAP success criterion 4.)

---

### `reports/management_summary.py:run_report()` (EDIT — ~3 new lines)

**Analog:** `reports/board_summary.py:run_report()` — exact sibling pattern.

**Current return dict** (management_summary.py:2437-2442):
```python
return {
    "pdf":     pdf_path,
    "excel":   None,   # management_summary is PDF + email only
    "charts":  [],
    "metrics": email_metrics,
}
```

**Phase 2 extension** — same shape as board_summary above. NOTE: management_summary today does NOT use `ReportComposer` directly (it has its own `_build_pdf` and `build_email_body` flow — see management_summary.py:1237 + :2390). Phase 2 must wire a `ReportComposer` instance on the management_summary side (or — per CONTEXT.md `<deferred>` — leave management_summary on its existing flow until the v2 / GEN-01 module migration). Current Phase 2 commitment per CONTEXT.md D-26 is "extended in-place with ~3 new lines" — that implies the composer is already (or becomes) instantiated. Planner decides between two options:

1. **Instantiate `ReportComposer` for management_summary in Phase 2** — symmetrical with board_summary; gets the full bundle.
2. **Defer to Phase 3 / v2** — Phase 2 only wires the new keys with `None` / `""` values for management_summary so the return-dict shape matures even before the composer move.

Either is consistent with D-24 (additive keys only). Lean toward option 2 if the composer instantiation drags in module-list churn that Phase 3 (board) will redo anyway.

---

### `delivery/email_template.py:build_email_body_modular()` (NEW)

**Analog:** `delivery/email_template.py:build_email_body()` at email_template.py:347-418 — exact sibling.

**Existing function shape** (email_template.py:347-418, especially the context dict at :389-400 and the render block at :402-418):
```python
def build_email_body(
    group_config:   dict,
    report_outputs: dict,
    excel_omitted:  bool = False,
    generated_at:   Optional[datetime] = None,
) -> str:
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)

    email_cfg = group_config.get("email", {})
    filters   = group_config.get("filters", {}) or {}

    tag_category = filters.get("tag_category")
    tag_value    = filters.get("tag_value")
    tag_label    = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )

    context = {
        "group_name":       group_config.get("name", "Unknown Group"),
        "report_title":     email_cfg.get("subject", "Vulnerability Management Report"),
        "generated_at":     generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "tag_filter_label": tag_label,
        "kpi_metrics":      build_kpi_metrics(report_outputs, group_config),
        "charts":           build_chart_cids(report_outputs),
        "attached_reports": build_attached_reports(report_outputs),
        "sla_table":        build_sla_table(),
        "reply_to":         email_cfg.get("reply_to", ""),
        "excel_omitted":    excel_omitted,
    }

    try:
        template = _jinja_env.get_template("report_email.html")
        rendered = template.render(**context)
        ...
        return rendered
    except Exception as exc:
        logger.error("Email template render failed: %s", exc, exc_info=True)
        return (
            f"<p>Vulnerability Management Report — {context['group_name']}</p>"
            f"<p>Generated: {context['generated_at']}</p>"
            f"<p><em>HTML template render failed: {exc}</em></p>"
        )
```

**Phase 2 sibling reference signature (D-15, from CONTEXT.md `<specifics>`):**
```python
def build_email_body_modular(
    group_config:        dict,
    report_outputs:      dict,
    module_panels_html:  str,
    excel_omitted:       bool = False,
    generated_at:        Optional[datetime] = None,
) -> str:
    """
    Sibling to build_email_body() that injects module_panels_html into
    the {% if module_panels_html %} branch of templates/report_email.html.
    Same Jinja2 env / template / helpers; only the context dict differs.
    """
    # Reuse identical group_config / filters / tag_label extraction as
    # build_email_body() above — same scope banner, attached reports,
    # SLA table, footer, reply_to behavior.
    ...
    context = {
        ...,
        "module_panels_html": module_panels_html,    # NEW slot — KPI tiles
                                                     # block keyed off this.
        # kpi_metrics still computed for backward fallback path
        # in case template wants to render legacy tiles when
        # module_panels_html is empty.
        "kpi_metrics":        build_kpi_metrics(report_outputs, group_config),
    }

    try:
        template = _jinja_env.get_template("report_email.html")
        return template.render(**context)
    except Exception as exc:
        logger.error("Modular email template render failed: %s", exc, exc_info=True)
        return (
            f"<p>Vulnerability Management Report — {context['group_name']}</p>"
            f"<p>Generated: {context['generated_at']}</p>"
            f"<p><em>HTML template render failed: {exc}</em></p>"
        )
```

**Reused helpers from email_template.py (no edits required):**
- `_safe_get` (email_template.py:220-232)
- `build_attached_reports` (email_template.py:270-304)
- `build_chart_cids` (email_template.py:311-340)
- `build_sla_table` (email_template.py:239-263)
- `_jinja_env` (email_template.py:56-61) — single shared `Environment` instance

---

### `templates/report_email.html` — `{% if module_panels_html %}` conditional (EDIT)

**Analog:** self — existing KPI tiles block at template.html:92-141.

**Current KPI tiles block boundary (lines 92-141)** — the entire `<tr>...</tr>` for SECTION 3:
```html
<!-- =====================================================
     SECTION 3 — KPI TILES
     ===================================================== -->
<tr>
  <td style="padding: 20px 20px 10px 20px; background-color: #FFFFFF;">
    <p style="margin: 0 0 12px 0; font-family: Arial, Helvetica, sans-serif;
               font-size: 11pt; font-weight: bold; color: #1F3864;
               border-bottom: 2px solid #E8EAF6; padding-bottom: 6px;">
      Key Metrics
    </p>
    <!-- KPI tile grid — one row, up to 5 cells -->
    <table border="0" cellpadding="0" cellspacing="6" width="100%">
      <tr>
        {% set ns = namespace(count=kpi_metrics | length) %}
        {% for metric in kpi_metrics %}
        <td align="center" valign="top" bgcolor="#F5F7FA"
            style="background-color: #F5F7FA; border: 1px solid #DDDFE2;
                   padding: 14px 8px; vertical-align: top;">
          <p style="margin: 0 0 6px 0; font-family: Arial, Helvetica, sans-serif;
                     font-size: 8pt; color: #757575; text-transform: uppercase;
                     letter-spacing: 0.5px;">
            {{ metric.label | default("Metric") }}
          </p>
          <p style="margin: 0; font-family: Arial, Helvetica, sans-serif;
                     font-size: 18pt; font-weight: bold;
                     color: {{ metric.color | default('#1F3864') }};">
            {{ metric.value | default("N/A") }}
          </p>
          ...
        </td>
        {% else %}
        <td align="center" bgcolor="#F5F7FA" ...>
          <p ...>Metrics not available for this group.</p>
        </td>
        {% endfor %}
      </tr>
    </table>
  </td>
</tr>
```

**Phase 2 wrapping pattern (D-10):**
```html
{% if module_panels_html %}
<tr>
  <td style="padding: 20px 20px 10px 20px; background-color: #FFFFFF;">
    {{ module_panels_html | safe }}
  </td>
</tr>
{% else %}
<!-- existing SECTION 3 KPI tiles block, unchanged -->
<tr>
  <td style="padding: 20px 20px 10px 20px; ...">
    ...the entire current block...
  </td>
</tr>
{% endif %}
```

Variables comment header at template.html:15-26 also gains a one-liner: `module_panels_html (str)  — concatenated per-module panel fragment; when set, replaces KPI tiles section.`

---

## Shared Patterns

### Per-module exception isolation (`# noqa: BLE001` + log + placeholder)

**Source:** `composer.py:assemble_pdf()` lines 522-533; `composer.py:assemble_excel()` lines 630-641.
**Apply to:** Every new render-channel iteration in `assemble_email_body()` and `assemble_analyst_workbook()` (D-28).
```python
except Exception as exc:  # noqa: BLE001
    logger.error(
        "ReportComposer.<method> [%s]: <renderer>() raised: %s\n%s",
        data.module_id, exc, traceback.format_exc(),
    )
    # ...emit visible placeholder, never re-raise...
```

### Skip-empty contribution rule

**Source:** `composer.py:assemble_pdf()` line 535 (`if not html or not html.strip(): continue`); `composer.py:assemble_excel()` implicit via no-`tab_names` accumulation.
**Apply to:** `assemble_email_body()` (D-14 silent skip on `""`) and `assemble_analyst_workbook()` (D-20 skip on empty df + skip whole file when `collected == []`).

### `module_configs` is the canonical order

**Source:** `composer.py:336` (`for config in self._module_configs:`) and `composer.py:506` (`for i, data in enumerate(results):` where `results` comes from `run_all()` which iterates `_module_configs`).
**Apply to:** All three new channels (D-07, D-27). Strip cells, email panels, analyst tabs are emitted in `_module_configs` order; no per-channel reordering.

### `# noqa: PLC0415` for deferred imports

**Source:** `base.py:440` (`from reports.modules.rag_utils import (...)`); `board_summary.py:350` (`from weasyprint import HTML`); `board_summary.py:418` (CLI deferred imports).
**Apply to:** Any deferred `import openpyxl` inside `assemble_analyst_workbook()` to keep composer module-level imports lean. Also any deferred `STATUS_ICON`/`STATUS_COLOR` import inside the new strip-rendering helper if it lives at composer module level.

### Numpydoc docstrings + `from __future__ import annotations`

**Source:** Every file in `reports/modules/`; see `composer.py:1-41`, `base.py:1-25`, `rag_utils.py:1-21`, `format_utils.py:1-23`.
**Apply to:** All new methods on `ReportComposer` and the new `build_email_body_modular()` function. Use `# ===` for top-level section banners; `# ---` for nested.

### None/NaN-safe formatters in any HTML interpolation

**Source:** `reports/modules/format_utils.py:safe_pct/safe_int/safe_format`; re-exported at `reports/modules/__init__.py:61-67`.
**Apply to:** Any new interpolation of metric values inside the page-2 strip rendering or the email panel concatenation. Phase 2's composer methods consume the already-pre-formatted strings from `data.rag_strip["headline_value"]` (per Phase 1 D-08) so this should rarely matter in composer code itself, but any Phase 2 fallback string composition that touches a `data.metrics[...]` value MUST go through `safe_*`.

### Logging convention

**Source:** Every composer method (`composer.py:342-351, :511-515, :654-657`).
**Apply to:** New methods. Use `logger.info` for one-line success summaries; `logger.warning` for skipped modules / partial degradation; `logger.error` with `traceback.format_exc()` for caught exceptions. Use `%s`/`%d` lazy formatting per CONVENTIONS.md.

---

## No Analog Found

None. Every Phase 2 surface has a precise in-repo analog. The work is strictly additive — new methods on an existing class, a new sibling function in an existing module, a new conditional in an existing template. No greenfield invention.

---

## Metadata

**Analog search scope:**
- `reports/modules/` (composer.py, base.py, rag_utils.py, format_utils.py, __init__.py, scan_coverage_sla_module.py for sibling reference)
- `reports/board_summary.py`
- `reports/management_summary.py` (run_report tail at :2270-2442)
- `delivery/email_template.py`
- `templates/report_email.html`
- `.planning/phases/01-module-render-contract/01-CONTEXT.md` + `01-VERIFICATION.md` (locked Phase 1 contracts)
- `.planning/phases/02-reportcomposer-upgrades/02-CONTEXT.md` (Phase 2 decisions D-01..D-29)

**Files scanned:** 11
**Pattern extraction date:** 2026-05-06
