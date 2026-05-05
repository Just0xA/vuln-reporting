"""
reports/modules/base.py — Abstract base class and data contracts for report modules.

Every report module in the suite inherits from BaseModule and implements its
three required abstract methods:
    - compute()             — pure metric calculation, no side effects
    - render_pdf_section()  — HTML fragment for WeasyPrint
    - render_excel_tabs()   — writes tabs into an openpyxl Workbook

Two dataclasses define the data contract between the caller and each module:
    - ModuleConfig  — configuration sourced from delivery_config.yaml
    - ModuleData    — structured output returned by compute()

Conventions
-----------
- MODULE_ID must be globally unique across the entire modules/ directory.
  Use snake_case with a domain prefix if needed (e.g. "sla_summary",
  "asset_risk_top25").
- Modules must never raise unhandled exceptions out of compute().
  On failure, catch the error, populate ModuleData.error, and return.
- render_pdf_section() and render_excel_tabs() must handle
  ModuleData.error gracefully (render an error notice, not a traceback).
- All compute() calls must be side-effect free: no file writes, no
  API calls, no mutations of the input DataFrames.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

import pandas as pd

logger = logging.getLogger(__name__)


# ===========================================================================
# Data contracts
# ===========================================================================

@dataclass
class ModuleConfig:
    """
    Configuration passed to a module at render time.

    Sourced from the delivery group's entry in delivery_config.yaml.
    The ``options`` dict allows per-group module customization without
    requiring code changes — every configurable behaviour should be
    exposed as an option key.

    Examples
    --------
    ::

        ModuleConfig("sla_summary")
        ModuleConfig("asset_risk", options={"top_n": 25})
        ModuleConfig("patch_compliance",
                     options={"severity_filter": ["critical", "high"]})
        ModuleConfig("trend_chart", options={"show_chart": True,
                                             "window_days": 90})

    Attributes
    ----------
    module_id : str
        Must match the ``MODULE_ID`` class attribute of the target module.
    options : dict
        Arbitrary key-value configuration forwarded to the module.
        Modules document their supported option keys in their class
        docstring and in ``get_audit_info()``.
    """

    module_id: str
    options:   dict = field(default_factory=dict)


@dataclass
class ModuleData:
    """
    Structured output returned by ``BaseModule.compute()``.

    Every field must be populated on success.  On failure, set
    ``error`` to a message string and leave the data fields as
    empty defaults — callers and renderers check ``error`` first.

    Attributes
    ----------
    module_id : str
        Matches ``ModuleConfig.module_id`` so output can be traced
        back to its source.
    display_name : str
        Human-readable module name used in PDF headings and email
        subject lines.
    metrics : dict
        Key-value pairs for KPI tile display.
        Example: ``{"Overdue Critical": 12, "SLA Compliance": "87%"}``
    table_data : list[dict]
        List of row dicts for tabular output in PDF and Excel.
        Each dict is one row; keys are column headers.
        Empty list if the module has no tabular output.
    chart_data : dict
        Raw data for chart rendering (not a rendered chart).
        Structure is module-defined.  Empty dict if no chart.
    summary_text : str
        Plain-language narrative sentence(s) describing the metrics.
        Used in email body and PDF executive summary sections.
    metadata : dict
        Audit and calculation metadata — timestamps, row counts,
        filter parameters, data sources.  Written to the Report Info
        tab in Excel and used by ``collect_audit_info()``.
    driver_narrative : str
        Plain-language "what's driving it" line consumed by
        ``render_email_panel()``.  Empty string default; modules
        populate inside ``compute()`` so renderers don't get
        DataFrames (D-07).
    analyst_rows : list[tuple[str, pd.DataFrame]]
        Pivot-friendly drill-down rows used by
        ``render_analyst_tabs()``.  Each tuple is
        ``(sheet_name, DataFrame)``.  Empty list default.
    rag_strip : dict
        Pre-built cover-page strip cell with keys ``label``,
        ``headline_value``, ``rag_color``, ``rag_label`` per
        CONTRACT-03.  Empty dict default; populated inside
        ``compute()`` so renderers stay pure.
    error : str or None
        ``None`` on success.  On failure, a human-readable error
        message.  Renderers must check this before accessing other
        fields.
    """

    module_id:        str
    display_name:     str
    metrics:          dict
    table_data:       list[dict]
    chart_data:       dict
    summary_text:     str
    metadata:         dict
    # --- New in Phase 1 (CONTRACT-04) ---
    driver_narrative: str                            = ""
    analyst_rows:     list[tuple[str, pd.DataFrame]] = field(default_factory=list)
    rag_strip:        dict                           = field(default_factory=dict)
    # ------------------------------------
    error:            Optional[str]                  = None


# ===========================================================================
# Abstract base class
# ===========================================================================

class BaseModule(ABC):
    """
    Abstract base class for all report modules.

    Subclass this, set the class-level constants, and implement the
    three abstract methods.  Register with the ``@register_module``
    decorator from ``reports.modules.registry`` so the module is
    auto-discovered at runtime.

    Class constants
    ---------------
    MODULE_ID : str
        Unique identifier used in delivery_config.yaml and the registry.
        Convention: ``snake_case``.  Must be non-empty.
    DISPLAY_NAME : str
        Human-readable name for headings, logs, and error messages.
    DESCRIPTION : str
        One-sentence description of what the module measures.
    REQUIRED_DATA : list[str]
        Keys the module needs from the data context.  Currently
        informational — used for audit documentation.
        Typical values: ``["vulns"]``, ``["vulns", "assets"]``.
    SUPPORTED_OUTPUTS : list[str]
        Output formats this module can render.  Renderers check this
        before calling format-specific methods.
        Valid values: ``"pdf"``, ``"excel"``, ``"email"``.
    VERSION : str
        Semantic version string.  Increment when the calculation
        logic changes so audit logs can detect formula changes.
    """

    MODULE_ID:         str       = ""
    DISPLAY_NAME:      str       = ""
    DESCRIPTION:       str       = ""
    REQUIRED_DATA:     list[str] = []
    SUPPORTED_OUTPUTS: list[str] = ["pdf", "excel", "email"]
    # Valid values: "pdf", "excel", "email", "csv"
    # Set to a subset to opt out of formats this module does not produce.
    # Examples:
    #   SUPPORTED_OUTPUTS = ["csv"]               # data export only
    #   SUPPORTED_OUTPUTS = ["pdf", "email"]      # no Excel tab
    #   SUPPORTED_OUTPUTS = ["excel"]             # no PDF, no email KPIs
    VERSION:           str       = "1.0.0"

    # ------------------------------------------------------------------
    # Abstract method — must be implemented by every module
    # ------------------------------------------------------------------

    @abstractmethod
    def compute(
        self,
        vulns_df:    pd.DataFrame,
        assets_df:   pd.DataFrame,
        report_date: Any,
        config:      ModuleConfig,
        **kwargs:    Any,
    ) -> ModuleData:
        """
        Compute module metrics from input DataFrames.

        Contract
        --------
        - **Pure function**: no file writes, no API calls, no mutation
          of input DataFrames.
        - **Always returns**: catch all exceptions internally; set
          ``ModuleData.error`` and return safe empty defaults rather
          than raising.
        - **Idempotent**: calling with the same inputs always produces
          the same result.
        - Log computation steps at ``DEBUG`` level.
        - Log data quality issues (missing columns, unexpected nulls,
          empty subsets) at ``WARNING`` level.

        Parameters
        ----------
        vulns_df : pd.DataFrame
            Normalized, tag-filtered vulnerability DataFrame.
            Already scoped to the delivery group's tag filter.
        assets_df : pd.DataFrame
            Normalized, tag-filtered asset DataFrame.
        report_date : datetime
            UTC-aware datetime representing the report run time.
            Used for age calculations and display timestamps.
        config : ModuleConfig
            Module configuration including ``options`` dict.
        **kwargs
            Additional context passed by the composer, e.g.
            ``trend_history`` for time-series modules.

        Returns
        -------
        ModuleData
            Populated on success; ``error`` field set on failure.
        """
        ...

    # ------------------------------------------------------------------
    # Renderer methods — concrete no-op defaults, override as needed
    # ------------------------------------------------------------------
    # Only compute() is abstract. Renderers default to no-op so that
    # output-limited modules (e.g. CSV-only) only implement what they
    # actually produce. Override any renderer whose format appears in
    # SUPPORTED_OUTPUTS.
    # ------------------------------------------------------------------

    def render_pdf_section(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> str:
        """
        Render module output as an HTML fragment for WeasyPrint.

        **Default:** returns ``""`` (no PDF output).  Override when
        ``"pdf"`` is in ``self.SUPPORTED_OUTPUTS``.

        Contract for overrides
        ----------------------
        - Return a **self-contained HTML fragment** — no ``<html>``,
          ``<head>``, or ``<body>`` tags.
        - Use **inline CSS only** or CSS class names defined in the
          global report stylesheet.  No ``<link>`` tags, no external
          URLs.
        - Embed charts as ``data:image/png;base64,...`` URIs.
        - If ``data.error`` is set, render an error callout ``<div>``
          with class ``error-box`` — do **not** raise an exception.

        Returns
        -------
        str
            HTML fragment, or ``""`` to produce no PDF section.
        """
        return ""

    def render_excel_tabs(
        self,
        data:     ModuleData,
        workbook: Any,
        config:   ModuleConfig,
    ) -> list[str]:
        """
        Write one or more tabs into an openpyxl Workbook.

        **Default:** writes nothing and returns ``[]``.  Override when
        ``"excel"`` is in ``self.SUPPORTED_OUTPUTS``.

        Contract for overrides
        ----------------------
        - **Add tabs to the provided workbook** — do not create a new
          Workbook instance.
        - Return a list of the worksheet names that were added.
        - If ``data.error`` is set, write the error message to a single
          tab rather than raising.
        - Use shared styling helpers from ``exporters/excel_exporter.py``
          for consistent formatting across all modules.

        Parameters
        ----------
        workbook : openpyxl.Workbook
            The workbook to write into.  Do not save or close it —
            the caller owns the workbook lifecycle.

        Returns
        -------
        list[str]
            Names of worksheets added.  ``[]`` if no tabs written.
        """
        return []

    # ------------------------------------------------------------------
    # Phase 1 renderer methods — concrete with no-op defaults
    # ------------------------------------------------------------------
    # render_email_panel, render_analyst_tabs, render_rag_strip_entry
    # extend the four-channel render contract added in Phase 1
    # (CONTRACT-01..03). All are concrete with no-op defaults so
    # un-migrated modules continue to instantiate (D-01); subclasses
    # override the channels they contribute to per SUPPORTED_OUTPUTS.
    # ------------------------------------------------------------------

    def render_email_panel(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> str:
        """
        Render module output as an inline-CSS HTML fragment for the
        composed email body.

        **Default:** returns ``""`` (no contribution to the email body).
        Override when ``"email"`` is in ``self.SUPPORTED_OUTPUTS`` and
        the module wants to appear as a per-module panel in the
        assembled email body.

        Contract for overrides
        ----------------------
        - Return a **self-contained inline-CSS HTML fragment** — no
          ``<html>``, ``<head>``, ``<body>``, or ``<style>`` blocks.
          Outlook / Gmail / Apple Mail compatibility requires inline
          style attributes only.
        - Embed gauge images as ``cid:`` references (the composer
          provides the CID image map) OR as ``data:image/png;base64,...``
          URIs. Both are tolerated; ``cid:`` is preferred for size.
        - Include a 1-line "what's driving it" string sourced from
          ``data.driver_narrative`` so the panel matches the
          cover-page strip.
        - On ``data.error`` or empty driver narrative, return ``""``
          (the composer concatenates non-empty fragments only).
        - Use ``safe_pct`` / ``safe_int`` / ``safe_format`` from
          ``reports.modules.format_utils`` for any numeric
          interpolation.  Inline f-string format specs on
          possibly-``None`` metric values are forbidden.

        Returns
        -------
        str
            HTML fragment, or ``""`` to omit this module from the
            panel section.
        """
        return ""

    def render_analyst_tabs(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> list[tuple[str, pd.DataFrame]]:
        """
        Return one or more (sheet_name, DataFrame) tuples of
        pivot-friendly drill-down rows for the analyst-detail
        companion workbook.

        **Default:** returns ``[]``.  Un-migrated modules don't
        appear as tabs in the analyst workbook (no empty-tab noise).

        Contract for overrides
        ----------------------
        - Each tuple is one worksheet.  ``sheet_name`` must be unique
          within the module's contribution and ``<= 31`` chars
          (Excel limit).
        - The DataFrame should be **flat and pivot-table-friendly** —
          one row per finding/asset, no aggregation.  Analysts pivot
          themselves.
        - On ``data.error`` or zero-row data, return ``[]``.  The
          composer produces no tab for an empty contribution.
        - Source data MUST come from ``data.analyst_rows`` (populated
          inside ``compute()``); this method is a pure render path.

        Returns
        -------
        list[tuple[str, pd.DataFrame]]
            ``[]`` if the module emits no analyst detail.
        """
        return []

    def render_rag_strip_entry(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> dict:
        """
        Return the cover-page RAG-strip cell for this module.

        **Default:** returns a gray "No Data" cell shaped like
        ``{"label": self.DISPLAY_NAME, "headline_value": "—",
        "rag_color": "#757575", "rag_label": "No Data"}``.
        The strip ALWAYS shows one cell per module so missed
        overrides are visually obvious instead of silently
        disappearing.

        Contract for overrides
        ----------------------
        - Return a dict with exactly four keys: ``label``,
          ``headline_value``, ``rag_color``, ``rag_label``.
          No additional keys in v1 (per CONTRACT-03).
        - ``headline_value`` is a pre-formatted string
          (e.g. ``"87.4%"``, ``"12 assets"``, ``"—"``);
          the composer does not reformat.
        - On ``data.error`` or no-data conditions, return the
          gray default (use ``rag_utils.build_rag_strip_entry``
          with status ``"no_data"`` for consistency).
        - Use ``safe_pct`` / ``safe_int`` / ``safe_format`` for
          the headline value when sourcing from possibly-``None``
          metrics.

        Returns
        -------
        dict
            Strip cell dict.  Always non-empty so the cover strip
            is structurally consistent.
        """
        from reports.modules.rag_utils import (  # noqa: PLC0415
            STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE,
        )
        return {
            "label":          self.DISPLAY_NAME,
            "headline_value": NO_DATA_HEADLINE,
            "rag_color":      STATUS_COLOR["no_data"],
            "rag_label":      STATUS_LABEL["no_data"],
        }

    # ------------------------------------------------------------------
    # Optional methods — concrete implementations with sensible defaults
    # ------------------------------------------------------------------

    def render_email_kpis(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> dict[str, str]:
        """
        Return key-value pairs for email KPI tiles.

        Default implementation returns all ``data.metrics`` entries
        as strings.  Override to select a subset or reformat values
        for email display (e.g. adding units, percentage signs).

        Returns empty dict if ``"email"`` is not in
        ``self.SUPPORTED_OUTPUTS`` or if ``data.error`` is set.

        Returns
        -------
        dict[str, str]
            ``{label: formatted_value}`` for email KPI tile rendering.
        """
        if "email" not in self.SUPPORTED_OUTPUTS:
            return {}
        if data.error:
            return {}
        return {k: str(v) for k, v in data.metrics.items()}

    def validate_config(
        self,
        config: ModuleConfig,
    ) -> list[str]:
        """
        Validate module configuration options.

        Override in subclasses to add module-specific validation of
        ``config.options``.  Called by the composer before ``compute()``.

        Default implementation returns an empty list (no errors).

        Returns
        -------
        list[str]
            List of error message strings.  Empty list means valid.
        """
        return []

    def get_audit_info(self) -> dict:
        """
        Return module metadata for audit and runbook documentation.

        Override in subclasses to document calculation formulas and
        data field sources.  The base implementation returns only
        identity metadata.

        The ``calculations`` key should be a dict mapping each output
        metric to a plain-English description of how it is computed
        and which source fields it uses.

        Example override::

            def get_audit_info(self):
                return {
                    **super().get_audit_info(),
                    "calculations": {
                        "Overdue Count": (
                            "Rows where days_open > SLA_DAYS[severity] "
                            "and state not in ('fixed', 'remediated'). "
                            "Source: vulns_df.is_overdue."
                        ),
                    }
                }

        Returns
        -------
        dict
            Audit metadata dict.
        """
        return {
            "module_id":    self.MODULE_ID,
            "display_name": self.DISPLAY_NAME,
            "description":  self.DESCRIPTION,
            "version":      self.VERSION,
            "required_data": self.REQUIRED_DATA,
            "supported_outputs": self.SUPPORTED_OUTPUTS,
            "calculations": (
                "Not documented — override get_audit_info() "
                "in the module class."
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers available to all modules
    # ------------------------------------------------------------------

    def _empty_result(
        self,
        error_message: str,
        config: ModuleConfig,
    ) -> ModuleData:
        """
        Convenience method for returning a failed ModuleData from
        inside a caught exception handler.

        Populates the three Phase 1 render fields
        (``driver_narrative``, ``analyst_rows``, ``rag_strip``) with
        safe defaults so the cover strip shows a gray "No Data" cell
        and the email panel / analyst tabs contribute nothing instead
        of crashing the assembler.

        Usage::

            except Exception as exc:
                logger.error(...)
                return self._empty_result(str(exc), config)
        """
        from reports.modules.rag_utils import (  # noqa: PLC0415
            STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE, NO_DATA_DRIVER,
        )
        return ModuleData(
            module_id        = self.MODULE_ID,
            display_name     = self.DISPLAY_NAME,
            metrics          = {},
            table_data       = [],
            chart_data       = {},
            summary_text     = "",
            metadata         = {},
            driver_narrative = NO_DATA_DRIVER,
            analyst_rows     = [],
            rag_strip        = {
                "label":          self.DISPLAY_NAME,
                "headline_value": NO_DATA_HEADLINE,
                "rag_color":      STATUS_COLOR["no_data"],
                "rag_label":      STATUS_LABEL["no_data"],
            },
            error            = error_message,
        )

    def _log_prefix(self) -> str:
        """Return a consistent log prefix for this module."""
        return f"[module:{self.MODULE_ID}]"
