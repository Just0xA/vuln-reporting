"""
reports/modules/composer.py — Report composition utilities.

ReportComposer orchestrates module execution and assembles their
outputs into complete PDF HTML, Excel workbooks, and email KPI dicts.

Typical usage inside a report script
-------------------------------------
::

    from reports.modules import ReportComposer
    from reports.modules.base import ModuleConfig

    composer = ReportComposer(
        vulns_df=vulns_df,
        assets_df=assets_df,
        report_date=generated_at,
        module_configs=[
            ModuleConfig("sla_summary"),
            ModuleConfig("asset_risk", options={"top_n": 25}),
        ],
    )

    results       = composer.run_all()
    pdf_html      = composer.assemble_pdf(results)
    tab_names     = composer.assemble_excel(results, workbook)
    kpis          = composer.collect_email_kpis(results)
    errors        = composer.get_error_summary(results)

Design principles
-----------------
- Module failures are isolated: one module raising or returning an
  error does not prevent other modules from running.
- Order is preserved: modules execute and appear in output in the
  exact order given in ``module_configs``.
- The composer owns no metric logic — it is purely an orchestrator.
- ``assemble_pdf()`` wraps HTML fragments in a minimal but complete
  WeasyPrint-ready document including page CSS and a metadata footer.
- ``assemble_excel()`` appends a ``_Metadata`` tab after all module
  tabs to record run parameters and module audit info.
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Optional

import pandas as pd

from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.registry import registry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PDF document scaffolding
# ---------------------------------------------------------------------------

_PDF_DOCTYPE = "<!DOCTYPE html>"

_PDF_CSS = """
<style>
  /* ── Page setup ─────────────────────────────────────────────────── */
  @page {
    size: A4 landscape;
    margin: 15mm 12mm 18mm 12mm;
    @bottom-center {
      content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt;
      color: #666;
    }
  }

  /* ── Base typography ─────────────────────────────────────────────── */
  body {
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 9pt;
    color: #1a1a1a;
    margin: 0;
    padding: 0;
  }

  /* ── Module sections ─────────────────────────────────────────────── */
  .module-section {
    margin-bottom: 12mm;
  }

  .module-section + .module-section {
    page-break-before: auto;
  }

  .page-break {
    page-break-before: always;
  }

  /* ── Headings ────────────────────────────────────────────────────── */
  .section-heading {
    font-size: 13pt;
    font-weight: bold;
    color: #1F3864;
    border-bottom: 1.5pt solid #1F3864;
    padding-bottom: 2mm;
    margin-top: 0;
    margin-bottom: 4mm;
  }

  .subsection-heading {
    font-size: 10pt;
    font-weight: bold;
    color: #2e4a7a;
    margin-top: 4mm;
    margin-bottom: 2mm;
  }

  /* ── Narrative text ──────────────────────────────────────────────── */
  .explanatory-text {
    font-size: 8.5pt;
    color: #444;
    margin-bottom: 3mm;
    line-height: 1.4;
  }

  /* ── Error callout ───────────────────────────────────────────────── */
  .error-box {
    background: #fff3cd;
    border: 1pt solid #ffc107;
    border-left: 4pt solid #e65100;
    padding: 3mm 4mm;
    margin: 3mm 0;
    font-size: 8.5pt;
    color: #333;
    border-radius: 2pt;
  }

  /* ── Data tables ─────────────────────────────────────────────────── */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 8pt;
    margin-bottom: 4mm;
  }

  .data-table th {
    background: #1F3864;
    color: #ffffff;
    padding: 2mm 3mm;
    text-align: left;
    font-weight: bold;
  }

  .data-table td {
    padding: 1.5mm 3mm;
    border-bottom: 0.5pt solid #ddd;
    vertical-align: top;
  }

  .data-table tr:nth-child(even) td {
    background: #f5f7fa;
  }

  /* ── KPI tiles (inline use in modules) ───────────────────────────── */
  .kpi-row {
    display: table;
    width: 100%;
    margin-bottom: 5mm;
    border-spacing: 3mm;
  }

  .kpi-tile {
    display: table-cell;
    background: #f0f4ff;
    border: 0.5pt solid #c5cfe8;
    border-radius: 3pt;
    padding: 3mm 4mm;
    text-align: center;
    vertical-align: middle;
    min-width: 30mm;
  }

  .kpi-value {
    font-size: 16pt;
    font-weight: bold;
    color: #1F3864;
    display: block;
  }

  .kpi-label {
    font-size: 7.5pt;
    color: #555;
    display: block;
    margin-top: 1mm;
  }

  /* ── Report header/footer ────────────────────────────────────────── */
  .report-header {
    border-bottom: 2pt solid #1F3864;
    padding-bottom: 3mm;
    margin-bottom: 6mm;
  }

  .report-title {
    font-size: 16pt;
    font-weight: bold;
    color: #1F3864;
    margin: 0;
  }

  .report-subtitle {
    font-size: 9pt;
    color: #555;
    margin: 1mm 0 0 0;
  }

  .report-footer {
    border-top: 0.5pt solid #ccc;
    padding-top: 2mm;
    margin-top: 8mm;
    font-size: 7.5pt;
    color: #777;
  }

  /* ── Cover / title page ──────────────────────────────────────────── */
  .report-cover {
    page-break-after: always;
    text-align: center;
    padding-top: 48mm;
  }

  .cover-title {
    font-size: 22pt;
    font-weight: bold;
    color: #1F3864;
    margin: 0 0 5mm 0;
  }

  .cover-subtitle {
    font-size: 11pt;
    color: #555;
    margin: 0 0 10mm 0;
  }

  .cover-divider {
    border: none;
    border-top: 2pt solid #1F3864;
    width: 50%;
    margin: 0 auto 10mm auto;
  }

  .cover-meta {
    font-size: 9pt;
    color: #666;
    line-height: 2.2;
  }

  /* ── Page-2 RAG strip (D-02..D-08) ─────────────────────────────── */
  .rag-strip {
    page-break-after: always;
    padding: 18mm 6mm 0 6mm;
  }

  .rag-strip-header {
    font-size: 18pt;
    font-weight: bold;
    color: #1F3864;
    text-align: center;
    margin: 0 0 12mm 0;
  }

  .rag-cell-row {
    display: table;
    width: 100%;
    border-collapse: separate;
    border-spacing: 4mm 4mm;
    table-layout: fixed;
  }

  .rag-cell {
    display: table-cell;
    width: 25%;                  /* 4 cells per row max; auto-wraps */
    background: #ffffff;
    border: 0.5pt solid #c5cfe8;
    border-radius: 3pt;
    text-align: center;
    vertical-align: middle;
    padding: 6mm 4mm 0 4mm;
    height: 38mm;
  }

  .rag-cell-label {
    font-size: 9pt;
    color: #555;
    margin: 0 0 2mm 0;
    line-height: 1.2;
  }

  .rag-cell-value {
    font-size: 22pt;
    font-weight: bold;
    color: #1a1a1a;
    margin: 0 0 4mm 0;
    line-height: 1.0;
  }

  .rag-cell-band {
    margin: 4mm -4mm 0 -4mm;     /* extend band to cell edges */
    padding: 3mm 2mm;
    color: #ffffff;
    font-size: 10pt;
    font-weight: bold;
    text-align: center;
    border-radius: 0 0 3pt 3pt;
  }

  .rag-cell-icon {
    display: inline-block;
    margin-right: 2mm;
    font-size: 11pt;
    line-height: 1.0;
  }

  .rag-cell-rag-label {
    display: inline-block;
    vertical-align: middle;
  }
</style>
"""

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

_PDF_RAG_STRIP_TEMPLATE = """
<div class="rag-strip">
  <h2 class="rag-strip-header">{header}</h2>
  <div class="rag-cell-row">
{cells_html}
  </div>
</div>
"""


# ===========================================================================
# ReportComposer
# ===========================================================================

class ReportComposer:
    """
    Orchestrates module execution and output assembly for composed reports.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Normalized, tag-filtered vulnerability DataFrame.  Passed
        unchanged to every module's ``compute()`` call.
    assets_df : pd.DataFrame
        Normalized, tag-filtered asset DataFrame.
    report_date : datetime
        UTC-aware datetime for the report run.  Used for age calculations
        and display timestamps.
    module_configs : list[ModuleConfig]
        Ordered list of module configurations.  Modules execute and
        appear in output in this order.
    **kwargs
        Additional context forwarded to every module's ``compute()``
        call (e.g. ``trend_history=df`` for time-series modules).
    """

    def __init__(
        self,
        vulns_df:       pd.DataFrame,
        assets_df:      pd.DataFrame,
        report_date:    Any,
        module_configs: list[ModuleConfig],
        **kwargs:       Any,
    ) -> None:
        self._vulns_df       = vulns_df
        self._assets_df      = assets_df
        self._report_date    = report_date
        self._module_configs = module_configs
        self._kwargs         = kwargs

        # Validate configs up front — log warnings for unknown/misconfigured
        # modules but do not abort; run_all() will surface per-module errors.
        self._warn_invalid_configs()

    # ------------------------------------------------------------------
    # Module execution
    # ------------------------------------------------------------------

    def run_all(self) -> list[ModuleData]:
        """
        Execute ``compute()`` on all configured modules in order.

        A failure in one module (exception or returned error) does not
        stop subsequent modules.  Each failure is logged and represented
        in the results list as a ``ModuleData`` with ``error`` set.

        Returns
        -------
        list[ModuleData]
            One entry per ``ModuleConfig``, in the same order.
            Entries with ``error`` set indicate failed modules.
        """
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

    def run_module(
        self,
        module_id: str,
        config:    Optional[ModuleConfig] = None,
    ) -> ModuleData:
        """
        Execute a single module by ID and return its ``ModuleData``.

        If ``config`` is ``None``, a default ``ModuleConfig`` is created
        for the module with no options.

        Any unhandled exception from the module's ``compute()`` call is
        caught here so the composer never propagates module failures to
        the caller.

        Parameters
        ----------
        module_id : str
            The ``MODULE_ID`` to look up in the registry.
        config : ModuleConfig, optional
            Configuration for this run.  Defaults to
            ``ModuleConfig(module_id)``.

        Returns
        -------
        ModuleData
            Populated on success; ``error`` field set on any failure.
        """
        if config is None:
            config = ModuleConfig(module_id=module_id)

        # --- Resolve module class from registry ---
        mod_class = registry.get(module_id)
        if mod_class is None:
            err = (
                f"Module '{module_id}' is not registered. "
                f"Registered modules: {sorted(registry._modules.keys())}"
            )
            logger.error("ReportComposer.run_module: %s", err)
            return _error_data(module_id, err)

        # --- Validate config options ---
        try:
            instance      = mod_class()
            config_errors = instance.validate_config(config)
        except Exception as exc:  # noqa: BLE001
            err = f"validate_config() raised: {exc}"
            logger.error(
                "ReportComposer.run_module [%s]: %s\n%s",
                module_id, err, traceback.format_exc(),
            )
            return _error_data(module_id, err)

        if config_errors:
            err = (
                f"Module '{module_id}' config validation failed: "
                + "; ".join(config_errors)
            )
            logger.error("ReportComposer.run_module: %s", err)
            return _error_data(module_id, err)

        # --- Execute compute() ---
        logger.debug(
            "ReportComposer.run_module: calling compute() on '%s'.",
            module_id,
        )
        try:
            data = instance.compute(
                vulns_df    = self._vulns_df,
                assets_df   = self._assets_df,
                report_date = self._report_date,
                config      = config,
                **self._kwargs,
            )
        except Exception as exc:  # noqa: BLE001
            err = (
                f"compute() raised an unhandled exception: "
                f"{type(exc).__name__}: {exc}"
            )
            logger.error(
                "ReportComposer.run_module [%s]: %s\n%s",
                module_id, err, traceback.format_exc(),
            )
            return _error_data(module_id, err)

        # --- Sanity-check return type ---
        if not isinstance(data, ModuleData):
            err = (
                f"compute() returned {type(data).__name__!r} "
                f"instead of ModuleData."
            )
            logger.error("ReportComposer.run_module [%s]: %s", module_id, err)
            return _error_data(module_id, err)

        if data.error:
            logger.warning(
                "ReportComposer.run_module [%s]: module reported error: %s",
                module_id, data.error,
            )
        else:
            logger.debug(
                "ReportComposer.run_module [%s]: compute() succeeded. "
                "metrics=%s",
                module_id, list(data.metrics.keys()),
            )

        return data

    # ------------------------------------------------------------------
    # PDF assembly
    # ------------------------------------------------------------------

    def assemble_pdf(
        self,
        results:  list[ModuleData],
        page_css: str = "",
        title:    str = "Vulnerability Management Report",
        subtitle: str = "",
    ) -> str:
        """
        Assemble module HTML sections into a complete WeasyPrint-ready
        HTML document.

        Each module's ``render_pdf_section()`` is called in results
        order.  Empty strings (modules that don't support PDF output)
        are silently skipped.  A page-break ``<div>`` is inserted
        between sections.

        The document includes:
        - Base stylesheet (``_PDF_CSS``) plus any caller-supplied CSS
        - Report header (title + subtitle)
        - Module sections separated by page-break hints
        - Report footer with generation timestamp and module list

        Parameters
        ----------
        results : list[ModuleData]
            Output of ``run_all()``.
        page_css : str
            Additional CSS to append after the base stylesheet.
            Useful for report-specific overrides.
        title : str
            Report title shown in the header band.
        subtitle : str
            Subtitle line (scope, date range, tag filter, etc.).

        Returns
        -------
        str
            Complete HTML string ready for ``weasyprint.HTML(string=...)``.
        """
        sections: list[str] = []

        for i, data in enumerate(results):
            mod_class = registry.get(data.module_id)
            if mod_class is None:
                logger.warning(
                    "ReportComposer.assemble_pdf: module '%s' not in registry "
                    "— skipping PDF section.",
                    data.module_id,
                )
                continue

            try:
                config   = self._config_for(data.module_id)
                instance = mod_class()
                html     = instance.render_pdf_section(data, config)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "ReportComposer.assemble_pdf [%s]: render_pdf_section() "
                    "raised: %s\n%s",
                    data.module_id, exc, traceback.format_exc(),
                )
                html = (
                    f'<div class="error-box">'
                    f"<strong>{data.display_name}</strong>: "
                    f"PDF render failed — {exc}"
                    f"</div>"
                )

            if not html or not html.strip():
                continue  # Module doesn't support PDF output

            # Insert page break before all sections except the first
            if sections:
                sections.append('<div class="page-break"></div>')
            sections.append(html)

        # Build generated_at string
        generated_at_str = (
            self._report_date.strftime("%Y-%m-%d %H:%M UTC")
            if hasattr(self._report_date, "strftime")
            else str(self._report_date)
        )

        # Subtitle fallback (scope only — generated_at appears on the cover separately)
        if not subtitle:
            subtitle = f"Scope: All Assets  |  Generated {generated_at_str}"

        # Human-readable section list for the cover page
        module_list_str = ", ".join(d.display_name for d in results)

        cover = _PDF_COVER_TEMPLATE.format(
            title        = title,
            subtitle     = subtitle,
            generated_at = generated_at_str,
            module_list  = module_list_str,
        )

        body = "\n".join(sections) if sections else (
            '<p class="explanatory-text">No module output to display.</p>'
        )

        rag_strip_page = self._build_rag_strip_page(results)

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
            rag_strip_page,    # NEW — Phase 2 D-02
            body,
            "</body>",
            "</html>",
        ])

    # ------------------------------------------------------------------
    # Page-2 RAG strip (Phase 2 D-02..D-08, COMPOSER-01)
    # ------------------------------------------------------------------

    def _build_rag_strip_page(self, results: list[ModuleData]) -> str:
        """
        Build the dedicated page-2 ``<div class="rag-strip">`` HTML.

        Iterates results in ``_module_configs`` order, calls each
        module's ``render_rag_strip_entry()`` (Phase 1 contract), and
        renders one cell per module: label-top + headline-value-middle
        + RAG-colored band-bottom containing the status-icon shape AND
        the rag_label text (D-04 / D-08).

        Per-module exception isolation mirrors ``assemble_pdf()``'s
        existing pattern at composer.py:522-533 (D-28). Modules whose
        class is missing from the registry, whose render method raises,
        or whose entry returns an empty dict all collapse to a gray
        "No Data" placeholder cell — never skipped, so the strip always
        shows one cell per configured module (D-06).

        Returns
        -------
        str
            Complete ``<div class="rag-strip">...</div>`` block produced
            from ``_PDF_RAG_STRIP_TEMPLATE``. Always non-empty so the
            page is rendered even when every module returned no data.
        """
        from reports.modules.rag_utils import (  # noqa: PLC0415
            STATUS_COLOR, STATUS_LABEL, STATUS_ICON, NO_DATA_HEADLINE,
        )

        def _gray_placeholder(label: str) -> dict:
            return {
                "label":          label,
                "headline_value": NO_DATA_HEADLINE,
                "rag_color":      STATUS_COLOR["no_data"],
                "rag_label":      STATUS_LABEL["no_data"],
            }

        def _icon_for(rag_color_hex: str) -> str:
            # Reverse-lookup the status key from the rag_color hex so the
            # icon palette stays loosely coupled to whatever palette the
            # module returned. Fallback to no_data if the color is unknown.
            for key, hex_str in STATUS_COLOR.items():
                if str(hex_str).lower() == str(rag_color_hex).lower():
                    return STATUS_ICON.get(key, STATUS_ICON["no_data"])
            return STATUS_ICON["no_data"]

        cells: list[str] = []

        for data in results:
            mod_class = registry.get(data.module_id)
            if mod_class is None:
                logger.warning(
                    "ReportComposer._build_rag_strip_page: module '%s' not "
                    "in registry — emitting gray placeholder cell.",
                    data.module_id,
                )
                cell_dict = _gray_placeholder(data.display_name or data.module_id)
            else:
                try:
                    config   = self._config_for(data.module_id)
                    instance = mod_class()
                    cell_dict = instance.render_rag_strip_entry(data, config)
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "ReportComposer._build_rag_strip_page [%s]: "
                        "render_rag_strip_entry() raised: %s\n%s",
                        data.module_id, exc, traceback.format_exc(),
                    )
                    cell_dict = _gray_placeholder(data.display_name or data.module_id)

            # Defensive: if a module returned a malformed dict, fall back to gray.
            if not isinstance(cell_dict, dict) or not all(
                k in cell_dict for k in ("label", "headline_value", "rag_color", "rag_label")
            ):
                logger.warning(
                    "ReportComposer._build_rag_strip_page [%s]: "
                    "render_rag_strip_entry returned malformed dict %r — "
                    "using gray placeholder.",
                    data.module_id, cell_dict,
                )
                cell_dict = _gray_placeholder(data.display_name or data.module_id)

            label          = str(cell_dict["label"])
            headline_value = str(cell_dict["headline_value"])
            rag_color      = str(cell_dict["rag_color"])
            rag_label      = str(cell_dict["rag_label"])
            icon           = _icon_for(rag_color)

            cells.append(
                '    <div class="rag-cell">\n'
                f'      <div class="rag-cell-label">{label}</div>\n'
                f'      <div class="rag-cell-value">{headline_value}</div>\n'
                f'      <div class="rag-cell-band" '
                f'style="background-color: {rag_color};">\n'
                f'        <span class="rag-cell-icon">{icon}</span>'
                f'<span class="rag-cell-rag-label">{rag_label}</span>\n'
                '      </div>\n'
                '    </div>'
            )

        cells_html = "\n".join(cells)
        return _PDF_RAG_STRIP_TEMPLATE.format(
            header     = "Risk Status Summary",
            cells_html = cells_html,
        )

    # ------------------------------------------------------------------
    # Excel assembly
    # ------------------------------------------------------------------

    def assemble_excel(
        self,
        results:  list[ModuleData],
        workbook: Any,
    ) -> list[str]:
        """
        Call ``render_excel_tabs()`` on all modules and collect tab names.

        Modules that return an empty list (no Excel support) are silently
        skipped.  A ``_Metadata`` tab is appended as the final tab
        containing run parameters and per-module audit info.

        Parameters
        ----------
        results : list[ModuleData]
            Output of ``run_all()``.
        workbook : openpyxl.Workbook
            The workbook to write into.  The caller owns the workbook
            lifecycle — this method does not save or close it.

        Returns
        -------
        list[str]
            All worksheet names added across all modules, including
            ``_Metadata``.
        """
        all_tab_names: list[str] = []

        for data in results:
            mod_class = registry.get(data.module_id)
            if mod_class is None:
                logger.warning(
                    "ReportComposer.assemble_excel: module '%s' not in "
                    "registry — skipping.",
                    data.module_id,
                )
                continue

            try:
                config    = self._config_for(data.module_id)
                instance  = mod_class()
                tab_names = instance.render_excel_tabs(data, workbook, config)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "ReportComposer.assemble_excel [%s]: render_excel_tabs() "
                    "raised: %s\n%s",
                    data.module_id, exc, traceback.format_exc(),
                )
                tab_names = _write_error_tab(
                    workbook,
                    tab_name  = f"{data.display_name[:25]} Err",
                    module_id = data.module_id,
                    error     = str(exc),
                )

            all_tab_names.extend(tab_names)

        # Append metadata tab
        meta_tab = _write_metadata_tab(
            workbook     = workbook,
            results      = results,
            report_date  = self._report_date,
            module_configs = self._module_configs,
        )
        all_tab_names.append(meta_tab)

        logger.info(
            "ReportComposer.assemble_excel: wrote %d tab(s): %s",
            len(all_tab_names), all_tab_names,
        )
        return all_tab_names

    # ------------------------------------------------------------------
    # Email KPI collection
    # ------------------------------------------------------------------

    def collect_email_kpis(
        self,
        results: list[ModuleData],
    ) -> dict[str, str]:
        """
        Collect KPI tiles from all modules for the email body.

        Calls ``render_email_kpis()`` on each module and merges the
        results into a single flat dict.  On key collision, later modules
        overwrite earlier ones — put higher-priority modules last in
        ``module_configs`` if ordering matters.

        Modules that returned errors contribute no KPI tiles.

        Parameters
        ----------
        results : list[ModuleData]

        Returns
        -------
        dict[str, str]
            Merged ``{label: value}`` dict for email KPI tile rendering.
        """
        merged: dict[str, str] = {}

        for data in results:
            mod_class = registry.get(data.module_id)
            if mod_class is None:
                continue

            try:
                config   = self._config_for(data.module_id)
                instance = mod_class()
                kpis     = instance.render_email_kpis(data, config)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ReportComposer.collect_email_kpis [%s]: "
                    "render_email_kpis() raised: %s",
                    data.module_id, exc,
                )
                continue

            merged.update(kpis)

        return merged

    # ------------------------------------------------------------------
    # Email body assembly (Phase 2 D-09..D-14, COMPOSER-02)
    # ------------------------------------------------------------------

    def assemble_email_body(
        self,
        results: list[ModuleData],
    ) -> str:
        """
        Assemble per-module email panels into a panels-only HTML fragment.

        Iterates ``results`` in ``_module_configs`` order, calls each
        module's ``render_email_panel()`` (Phase 1 contract), and
        concatenates the non-empty HTML fragments. The returned string
        is a fragment — no ``<html>``, ``<head>``, ``<body>``, scope
        banner, SLA table, or footer (D-09); the wrapping shell stays
        in ``templates/report_email.html``.

        Per-module exception isolation mirrors ``assemble_pdf()``'s
        existing pattern at composer.py:522-533 (D-28). One module's
        render failure inserts a visible error placeholder ``<div>``
        in the panel position but never aborts assembly.

        Modules that return ``""`` or whitespace are silently skipped
        (D-14) — mirrors ``assemble_pdf()``'s skip-empty rule at
        composer.py:535. Un-migrated modules whose ``render_email_panel``
        is the no-op ``""`` default contribute nothing to the body (their
        cover-page strip cell still renders separately as gray "No Data").

        Modules absent from the registry are silently skipped (mirrors
        ``collect_email_kpis()``'s behavior at composer.py:691-692).

        Per D-13 the composer never calls ``draw_gauge()`` itself —
        ``render_email_panel()`` (Phase 3) embeds gauges as
        ``data:image/png;base64,...`` inside the returned HTML fragment.

        Parameters
        ----------
        results : list[ModuleData]
            Output of ``run_all()``.

        Returns
        -------
        str
            Concatenated panel HTML fragments joined by ``"\\n"``.
            Empty string when every panel is empty (the email template's
            ``{% if module_panels_html %}`` conditional then falls through
            to the legacy KPI tiles section).
        """
        panels: list[str] = []

        for data in results:
            mod_class = registry.get(data.module_id)
            if mod_class is None:
                logger.warning(
                    "ReportComposer.assemble_email_body: module '%s' not "
                    "in registry — skipping panel.",
                    data.module_id,
                )
                continue

            try:
                config   = self._config_for(data.module_id)
                instance = mod_class()
                html     = instance.render_email_panel(data, config)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "ReportComposer.assemble_email_body [%s]: "
                    "render_email_panel() raised: %s\n%s",
                    data.module_id, exc, traceback.format_exc(),
                )
                html = (
                    '<div style="border:1px solid #d32f2f; '
                    'background:#FFF3CD; color:#5D4037; '
                    'padding:8px 12px; margin:6px 0; '
                    'font-family:Arial,Helvetica,sans-serif; font-size:10pt;">'
                    f'<strong>{data.display_name}</strong>: '
                    f'email panel render failed — {exc}'
                    '</div>'
                )

            if not html or not html.strip():
                continue   # D-14 — skip empty / whitespace-only panels

            panels.append(html)

        return "\n".join(panels)

    # ------------------------------------------------------------------
    # Audit info collection
    # ------------------------------------------------------------------

    def collect_audit_info(
        self,
        results: list[ModuleData],
    ) -> list[dict]:
        """
        Collect audit/calculation metadata from all modules.

        Merges ``get_audit_info()`` from the module class with
        ``ModuleData.metadata`` from the compute run so the audit record
        contains both the static calculation description and the dynamic
        run-time values (row counts, filter parameters, etc.).

        Parameters
        ----------
        results : list[ModuleData]

        Returns
        -------
        list[dict]
            One audit dict per module, in results order.
        """
        audit_records: list[dict] = []

        for data in results:
            mod_class = registry.get(data.module_id)

            static_info: dict = {}
            if mod_class is not None:
                try:
                    static_info = mod_class().get_audit_info()
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "ReportComposer.collect_audit_info [%s]: "
                        "get_audit_info() raised: %s",
                        data.module_id, exc,
                    )

            record = {
                **static_info,
                "run_metadata": data.metadata,
                "run_error":    data.error,
            }
            audit_records.append(record)

        return audit_records

    # ------------------------------------------------------------------
    # Error summary
    # ------------------------------------------------------------------

    def get_error_summary(
        self,
        results: list[ModuleData],
    ) -> list[str]:
        """
        Return error messages from all failed modules.

        Parameters
        ----------
        results : list[ModuleData]

        Returns
        -------
        list[str]
            One entry per failed module: ``"module_id: error message"``.
            Empty list if all modules succeeded.
        """
        return [
            f"{r.module_id}: {r.error}"
            for r in results
            if r.error
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _config_for(self, module_id: str) -> ModuleConfig:
        """Return the ModuleConfig for ``module_id``, or a default."""
        for cfg in self._module_configs:
            if cfg.module_id == module_id:
                return cfg
        return ModuleConfig(module_id=module_id)

    def _warn_invalid_configs(self) -> None:
        """Log warnings for any module IDs not found in the registry."""
        ids = [c.module_id for c in self._module_configs]
        _, invalid = registry.validate_module_list(ids)
        for mid in invalid:
            logger.warning(
                "ReportComposer: module '%s' is configured but not "
                "registered. It will produce an error result when run.",
                mid,
            )


# ===========================================================================
# Module-level helpers (not part of the public API)
# ===========================================================================

def _error_data(module_id: str, error: str) -> ModuleData:
    """Return a failed ModuleData for a module that could not be run."""
    return ModuleData(
        module_id    = module_id,
        display_name = module_id,
        metrics      = {},
        table_data   = [],
        chart_data   = {},
        summary_text = "",
        metadata     = {},
        error        = error,
    )


def _write_error_tab(
    workbook:  Any,
    tab_name:  str,
    module_id: str,
    error:     str,
) -> list[str]:
    """
    Write a minimal error tab to ``workbook`` when render_excel_tabs()
    raises an unhandled exception.

    Returns the list ``[tab_name]`` so callers can extend their tab list.
    """
    try:
        ws      = workbook.create_sheet(tab_name[:31])   # Excel 31-char limit
        ws["A1"] = "Module"
        ws["B1"] = module_id
        ws["A2"] = "Error"
        ws["B2"] = error
        ws["A3"] = "Action"
        ws["B3"] = "Check application logs for details."
        return [tab_name[:31]]
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "_write_error_tab: could not write error tab for '%s': %s",
            module_id, exc,
        )
        return []


def _write_metadata_tab(
    workbook:       Any,
    results:        list[ModuleData],
    report_date:    Any,
    module_configs: list[ModuleConfig],
) -> str:
    """
    Append a ``_Metadata`` tab to ``workbook`` with run parameters and
    per-module audit info.

    Returns the name of the tab that was written (``"_Metadata"``).
    """
    TAB_NAME = "_Metadata"

    try:
        ws = workbook.create_sheet(TAB_NAME)

        # ── Run summary ──────────────────────────────────────────────
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

        # ── Per-module summary ───────────────────────────────────────
        ws["A6"] = "Module ID"
        ws["B6"] = "Display Name"
        ws["C6"] = "Status"
        ws["D6"] = "Error"

        for row_idx, data in enumerate(results, start=7):
            ws.cell(row=row_idx, column=1, value=data.module_id)
            ws.cell(row=row_idx, column=2, value=data.display_name)
            ws.cell(row=row_idx, column=3,
                    value="OK" if data.error is None else "FAILED")
            ws.cell(row=row_idx, column=4, value=data.error or "")

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "_write_metadata_tab: could not write metadata tab: %s", exc
        )

    return TAB_NAME


# ===========================================================================
# Phase 2 analyst workbook helpers (COMPOSER-03)
# ===========================================================================

def _unique_sheet_name(name: str, used: set[str]) -> str:
    """
    Return a unique Excel-31-char-safe sheet name for ``name``.

    If ``name[:31]`` is not in ``used``, return it. Otherwise append
    ``_2``, ``_3``, ... while keeping the total length <= 31 by
    truncating the base name to leave room for the suffix
    (Phase 2 D-18).

    Collision semantics note (acknowledged for v1):
    When two long sheet names share their first 31 characters but
    differ later, only the auto-suffix counter (``_2``, ``_3``, ...)
    discriminates them — exactly Excel's own behavior. Acceptable for
    v1 since board modules use short, distinct sheet names. v2 may
    revisit if module-supplied sheet names start colliding past index
    30 in practice.

    Parameters
    ----------
    name : str
        Desired sheet name. Will be truncated to fit Excel's 31-char
        worksheet name limit.
    used : set[str]
        Set of sheet names already taken in the target workbook.
        The returned name will not be in this set.

    Returns
    -------
    str
        A unique sheet name <= 31 characters. The caller is expected
        to add the returned name to ``used`` before requesting another
        unique name.

    Raises
    ------
    ValueError
        If a unique name cannot be generated within 100 suffix
        attempts (defensive guard against pathological inputs).
    """
    base = name[:31]
    if base not in used:
        return base
    for i in range(2, 100):
        suffix    = f"_{i}"
        max_base  = 31 - len(suffix)
        candidate = name[:max_base] + suffix
        if candidate not in used:
            return candidate
    raise ValueError(
        f"_unique_sheet_name: could not generate unique sheet name "
        f"from {name!r} after 99 attempts."
    )


def _write_analyst_metadata_tab(
    workbook,
    *,
    slug:         str,
    generated_at: Any,
    scope_label:  str,
    module_ids:   list[str],
    failures:     list[tuple[str, str]],
) -> str:
    """
    Append the analyst workbook ``_Metadata`` tab.

    Per Phase 2 D-19, the tab carries exactly four canonical rows
    (Report / Generated / Scope / Modules) in a two-column key/value
    layout that mirrors :func:`_write_metadata_tab`. Per-tab row counts
    and run duration are deliberately excluded — those bleed runtime
    concerns the analyst workbook is not the right surface for.

    When ``failures`` is non-empty, a "Failures" subsection is appended
    listing ``module_id : error_message`` rows (Phase 2 D-28). Failed
    modules are still listed in the canonical Modules row so the
    audit trail is complete.

    Parameters
    ----------
    workbook : openpyxl.Workbook
    slug : str
        Report slug (e.g. ``"board_summary"``).
    generated_at : Any
        Datetime-like with ``.strftime`` or any value that ``str()``
        will format sensibly.
    scope_label : str
        Pre-formatted scope string (e.g. ``"Application = UC Engineering"``
        or ``"All Assets"``). Computed by the caller — composer does
        not assemble scope strings itself.
    module_ids : list[str]
        Module IDs in ``_module_configs`` order. Comma-joined into
        the Modules row.
    failures : list[tuple[str, str]]
        Per-module render failures. Empty list when all modules
        succeeded.

    Returns
    -------
    str
        The tab name written (always ``"_Metadata"``).
    """
    TAB_NAME = "_Metadata"

    try:
        ws = workbook.create_sheet(TAB_NAME)

        gen_str = (
            generated_at.strftime("%Y-%m-%d %H:%M UTC")
            if hasattr(generated_at, "strftime")
            else str(generated_at)
        )

        # ── D-19 canonical rows (key/value, two columns) ─────────────
        ws["A1"] = "Report"
        ws["B1"] = slug
        ws["A2"] = "Generated"
        ws["B2"] = gen_str
        ws["A3"] = "Scope"
        ws["B3"] = scope_label or "All Assets"
        ws["A4"] = "Modules"
        ws["B4"] = ", ".join(module_ids)

        # ── Failures subsection (D-28 audit trail) ───────────────────
        if failures:
            ws["A6"] = "Failures"
            ws["A7"] = "Module ID"
            ws["B7"] = "Error"
            for row_idx, (module_id, err) in enumerate(failures, start=8):
                ws.cell(row=row_idx, column=1, value=module_id)
                ws.cell(row=row_idx, column=2, value=err)

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "_write_analyst_metadata_tab: could not write metadata tab: %s",
            exc,
        )

    return TAB_NAME
