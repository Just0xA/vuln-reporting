"""
reports/modules/scan_coverage_sla_module.py — Scan Coverage SLA metric module.

Computes the percentage of managed assets that received a licensed Tenable scan
within the last 30 days, with a per-business-unit breakdown.

Module ID:    scan_coverage_sla
Display Name: Scan Coverage SLA

SLA thresholds (board-defined):
    Green:  scan_coverage_pct >= 95%
    Yellow: scan_coverage_pct >= 90%  and < 95%
    Red:    scan_coverage_pct <  90%

Data source:  assets_df.last_licensed_scan_date  (fetch_all_assets cache)

Business-unit dimension:
    Derived from the Tenable tag category "Application" via
    board_report_utils.extract_business_unit().  Assets without an
    Application tag are grouped under "Untagged".
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.registry import register_module
from reports.modules.board_report_utils import (
    compute_per_bu_breakdown,
    deduplicate_assets_by_name,
    extract_business_unit,
    sla_status_from_thresholds,
    ON_TIME_WINDOW_DAYS,
)
from reports.modules.chart_utils import draw_gauge

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_GREEN_THRESHOLD  = 95.0   # >= green
_YELLOW_THRESHOLD = 90.0   # >= yellow; < green
_DIRECTION        = "higher_is_better"

# draw_gauge threshold list: each tuple = (upper_bound, colour)
# Zones: 0–90 red | 90–95 amber | 95–100 green
_GAUGE_THRESHOLDS = [
    (_YELLOW_THRESHOLD, "#d32f2f"),
    (_GREEN_THRESHOLD,  "#fbc02d"),
    (100.0,             "#388e3c"),
]

# Status display properties
_STATUS_COLOR: dict[str, str] = {
    "green":   "#388e3c",
    "yellow":  "#f57c00",
    "red":     "#d32f2f",
    "no_data": "#757575",
}

_STATUS_LABEL: dict[str, str] = {
    "green":   "On Target",
    "yellow":  "At Risk",
    "red":     "Off Target",
    "no_data": "No Data",
}

# Excel fill colours (no leading #, openpyxl RGB format)
_FILL_GREEN  = PatternFill("solid", fgColor="C8E6C9")  # light green
_FILL_YELLOW = PatternFill("solid", fgColor="FFF9C4")  # light amber
_FILL_RED    = PatternFill("solid", fgColor="FFCDD2")  # light red
_FILL_HEADER = PatternFill("solid", fgColor="1F3864")  # dark navy


# ===========================================================================
# Module class
# ===========================================================================

@register_module
class ScanCoverageSLAModule(BaseModule):
    """
    Percentage of assets scanned within the last 30 days, with per-BU breakdown.

    Supported options
    -----------------
    None — this module accepts no configurable options.
    """

    MODULE_ID         = "scan_coverage_sla"
    DISPLAY_NAME      = "Scan Coverage SLA"
    DESCRIPTION       = (
        "Percentage of licensed assets scanned within the last 30 days, "
        "with per-business-unit breakdown. "
        "Assets with no last_licensed_scan_date are excluded from both "
        "numerator and denominator."
    )
    REQUIRED_DATA     = ["assets"]
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]
    VERSION           = "1.0.0"

    # ------------------------------------------------------------------
    # compute()
    # ------------------------------------------------------------------

    def compute(
        self,
        vulns_df:    pd.DataFrame,
        assets_df:   pd.DataFrame,
        report_date: Any,
        config:      ModuleConfig,
        **kwargs:    Any,
    ) -> ModuleData:
        """
        Compute scan coverage percentage and per-BU breakdown.

        Parameters
        ----------
        vulns_df : pd.DataFrame
            Not used by this module; accepted for interface compatibility.
        assets_df : pd.DataFrame
            Full (unfiltered) asset DataFrame from fetch_all_assets().
            Required columns: hostname, last_seen, last_licensed_scan_date,
            asset_uuid, tags.
        report_date : datetime
            UTC-aware datetime for the report run.  Used to compute the
            30-day recency cutoff.
        config : ModuleConfig
            Module configuration (no options consumed).

        Returns
        -------
        ModuleData
            ``error`` is None on success; set to an error string on failure.
        """
        logger.debug(
            "%s compute() — assets_df rows: %d",
            self._log_prefix(), len(assets_df),
        )

        try:
            # ---- Step 1: deduplicate; separate licensed vs unlicensed ----
            # Deduplication runs on ALL assets first so that a hostname whose
            # most-recent record is unlicensed does not retain an older licensed
            # duplicate.  After deduplication the licensed split is clean.
            _lsd      = "last_licensed_scan_date"
            all_dedup = deduplicate_assets_by_name(assets_df).copy()
            if _lsd in all_dedup.columns:
                all_dedup.loc[:, _lsd] = pd.to_datetime(
                    all_dedup[_lsd], utc=True, errors="coerce"
                )
            else:
                all_dedup.loc[:, _lsd] = pd.NaT

            licensed_mask    = all_dedup[_lsd].notna()
            licensed         = all_dedup[licensed_mask].copy().reset_index(drop=True)
            unlicensed_count = int((~licensed_mask).sum())

            logger.debug(
                "%s dedup total=%d, licensed=%d, unlicensed=%d",
                self._log_prefix(), len(all_dedup), len(licensed), unlicensed_count,
            )

            # ---- Step 2: split licensed into on-time vs not-on-time ----
            if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
                rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
            else:
                rd_ts = pd.Timestamp(report_date, tz="UTC")
            cutoff = rd_ts - pd.Timedelta(days=ON_TIME_WINDOW_DAYS)

            if not licensed.empty:
                on_time_flag = licensed[_lsd] >= cutoff
                on_time      = licensed[on_time_flag].copy().reset_index(drop=True)
                not_on_time  = licensed[~on_time_flag].copy().reset_index(drop=True)
            else:
                on_time     = licensed.copy()
                not_on_time = licensed.copy()

            scanned_on_time     = len(on_time)
            not_scanned_on_time = len(not_on_time)
            total_licensed      = scanned_on_time + not_scanned_on_time

            # ---- Step 3: overall percentage + status ----
            if total_licensed == 0:
                scan_coverage_pct = None
                status = "no_data"
                logger.warning(
                    "%s no licensed assets found — returning no_data.",
                    self._log_prefix(),
                )
            else:
                scan_coverage_pct = round(
                    scanned_on_time / total_licensed * 100, 1
                )
                status = sla_status_from_thresholds(
                    scan_coverage_pct,
                    green_threshold  = _GREEN_THRESHOLD,
                    yellow_threshold = _YELLOW_THRESHOLD,
                    direction        = _DIRECTION,
                )

            # ---- Step 4: per-BU breakdown (licensed assets only) ----
            # Unlicensed assets are excluded from the denominator entirely.
            enriched = extract_business_unit(licensed)

            on_time_uuids   = set(on_time["asset_uuid"].dropna())
            on_time_mask_bu = enriched["asset_uuid"].isin(on_time_uuids)
            denom_mask      = pd.Series(True, index=enriched.index)

            bu_breakdown = compute_per_bu_breakdown(
                enriched, on_time_mask_bu, denom_mask,
                higher_is_better=True,
            )
            table_data = bu_breakdown.to_dict("records")

            # ---- Step 5: narrative summary ----
            if scan_coverage_pct is None:
                summary_text = (
                    "Scan coverage could not be computed — "
                    "no licensed assets were found in the asset inventory."
                )
            else:
                summary_text = (
                    f"Scan coverage is {scan_coverage_pct:.1f}% — "
                    f"{scanned_on_time:,} of {total_licensed:,} licensed assets "
                    f"were scanned within the last {ON_TIME_WINDOW_DAYS} days "
                    f"({unlicensed_count:,} unlicensed assets excluded). "
                    f"Status: {_STATUS_LABEL.get(status, status)}."
                )

            computed_at = (
                report_date.isoformat()
                if hasattr(report_date, "isoformat")
                else str(report_date)
            )

            return ModuleData(
                module_id    = self.MODULE_ID,
                display_name = self.DISPLAY_NAME,
                metrics      = {
                    "scan_coverage_pct":   scan_coverage_pct,
                    "scanned_on_time":     scanned_on_time,
                    "not_scanned_on_time": not_scanned_on_time,
                    "total_licensed":      total_licensed,
                    "unlicensed_excluded": unlicensed_count,
                    "status":              status,
                },
                table_data   = table_data,
                chart_data   = {
                    "value":      scan_coverage_pct,
                    "thresholds": {
                        "green":  _GREEN_THRESHOLD,
                        "yellow": _YELLOW_THRESHOLD,
                    },
                    "direction":  _DIRECTION,
                    # Pre-sliced top 5 for PDF render (worst performers first)
                    "top_5":      bu_breakdown.head(5).to_dict("records"),
                },
                summary_text = summary_text,
                metadata     = {
                    "filter":               (
                        "Deduplicated by hostname (most-recent last_seen retained); "
                        "unlicensed assets (null last_licensed_scan_date) excluded "
                        "from both numerator and denominator"
                    ),
                    "window":               f"Last {ON_TIME_WINDOW_DAYS} days from report_date",
                    "sla_source":           "Board-defined thresholds (Green ≥95%, Amber ≥90%, Red <90%)",
                    "computed_at":          computed_at,
                    "unlicensed_excluded":  unlicensed_count,
                },
                error        = None,
            )

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "%s compute() failed: %s", self._log_prefix(), exc,
                exc_info=True,
            )
            return self._empty_result(str(exc), config)

    # ------------------------------------------------------------------
    # render_pdf_section()
    # ------------------------------------------------------------------

    def render_pdf_section(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> str:
        """
        Render a full-page PDF section for WeasyPrint.

        Layout (top to bottom):
        1. Section heading
        2. Gauge (centred) with 95 / 90 colour zones
        3. Status badge showing coverage % and on-target label
        4. Two bold support numbers: Scanned On Time | Not On Time
        5. Top-5 worst-performing BUs table (row-coloured by threshold band)
        6. Explanatory paragraph

        Returns an error callout div if ``data.error`` is set.
        """
        if data.error:
            return (
                f'<div class="error-box">'
                f"<strong>{self.DISPLAY_NAME}</strong>: {data.error}"
                f"</div>"
            )

        m                   = data.metrics
        scan_coverage_pct   = m.get("scan_coverage_pct")
        scanned_on_time     = m.get("scanned_on_time", 0)
        not_scanned_on_time = m.get("not_scanned_on_time", 0)
        status              = m.get("status", "no_data")

        # ---- Gauge ----
        gauge_value = scan_coverage_pct if scan_coverage_pct is not None else 0.0
        try:
            gauge_b64  = draw_gauge(
                value      = gauge_value,
                min_val    = 0,
                max_val    = 100,
                thresholds = _GAUGE_THRESHOLDS,
                title      = "Scan Coverage %",
                unit       = "%",
                figsize    = (5, 3),
            )
            gauge_html = (
                f'<div style="text-align:center; margin-bottom:4mm;">'
                f'<img src="data:image/png;base64,{gauge_b64}" '
                f'style="width:46%; max-width:320px;" alt="Scan Coverage gauge">'
                f'</div>'
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s PDF gauge render failed: %s", self._log_prefix(), exc)
            pct_display = f"{gauge_value:.1f}%"
            gauge_html = (
                f'<p style="text-align:center; font-size:20pt; font-weight:bold; '
                f'color:{_STATUS_COLOR.get(status, "#333")};">{pct_display}</p>'
            )

        # ---- Status badge ----
        status_color = _STATUS_COLOR.get(status, "#757575")
        status_label = _STATUS_LABEL.get(status, status)
        pct_display  = (
            f"{scan_coverage_pct:.1f}%" if scan_coverage_pct is not None else "N/A"
        )
        status_html = (
            f'<p style="text-align:center; font-size:10pt; font-weight:bold; '
            f'color:{status_color}; margin:0 0 5mm 0;">'
            f'Coverage: {pct_display} &nbsp;&middot;&nbsp; {status_label}'
            f'</p>'
        )

        # ---- Supporting numbers ----
        not_scanned_color = "#d32f2f" if not_scanned_on_time > 0 else "#388e3c"
        support_html = f"""
<table style="width:52%; margin:0 auto 6mm auto; border-collapse:collapse;">
  <tr>
    <td style="text-align:center; padding:2mm 8mm;
               border-right:0.5pt solid #ddd; vertical-align:middle;">
      <span style="font-size:14pt; font-weight:bold; color:#1F3864;">{scanned_on_time:,}</span>
      <br><span style="font-size:7.5pt; color:#555;">Scanned On Time</span>
    </td>
    <td style="text-align:center; padding:2mm 8mm; vertical-align:middle;">
      <span style="font-size:14pt; font-weight:bold;
             color:{not_scanned_color};">{not_scanned_on_time:,}</span>
      <br><span style="font-size:7.5pt; color:#555;">Not On Time</span>
    </td>
  </tr>
</table>"""

        # ---- Top 5 BU table ----
        top5 = data.chart_data.get("top_5", [])
        if top5:
            rows_html = ""
            for row in top5:
                bu_pct  = float(row.get("percentage", 0.0))
                bu_name = str(row.get("business_unit", ""))
                bu_num  = int(row.get("numerator",    0))
                bu_den  = int(row.get("denominator",  0))
                row_bg  = _row_bg(bu_pct, _GREEN_THRESHOLD, _YELLOW_THRESHOLD,
                                  direction="higher_is_better")
                rows_html += (
                    f'<tr style="background:{row_bg};">'
                    f'<td style="padding:1.5mm 3mm;">{bu_name}</td>'
                    f'<td style="text-align:right; padding:1.5mm 3mm;">{bu_num:,}</td>'
                    f'<td style="text-align:right; padding:1.5mm 3mm;">{bu_den:,}</td>'
                    f'<td style="text-align:right; padding:1.5mm 3mm; '
                    f'font-weight:bold;">{bu_pct:.1f}%</td>'
                    f'</tr>'
                )
            bu_table_html = f"""
<h3 class="subsection-heading">Top 5 Worst-Performing Business Units</h3>
<table class="data-table">
  <thead>
    <tr>
      <th>Business Unit</th>
      <th style="text-align:right;">Scanned On Time</th>
      <th style="text-align:right;">Licensed Assets</th>
      <th style="text-align:right;">Coverage %</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>"""
        else:
            bu_table_html = (
                '<p class="explanatory-text" style="color:#888; font-style:italic;">'
                'No business-unit breakdown available — '
                'assets may lack Application tags.'
                '</p>'
            )

        # ---- Explanatory paragraph ----
        explain_html = f"""
<p class="explanatory-text">
  <strong>What this measures:</strong> The percentage of <em>licensed</em> assets
  that received a licensed Tenable scan within the past {ON_TIME_WINDOW_DAYS} days.
  Assets without a <em>last_licensed_scan_date</em> (unlicensed) are excluded from
  both the numerator and denominator.  Assets that go unscanned have unknown
  vulnerability posture &mdash; new or worsening findings cannot be detected until a
  scan completes.  Denominator is the deduplicated licensed asset inventory (one row
  per hostname; most-recent <em>last_seen</em> retained).  Board target is &ge;95%
  (green).  &ge;90% is at-risk (amber).  Below 90% is off-target (red).
  Business-unit breakdown uses the Tenable &ldquo;Application&rdquo; tag category.
  Assets without an Application tag are grouped under &ldquo;Untagged&rdquo;.
</p>"""

        return f"""
<div class="module-section">
  <h2 class="section-heading">{self.DISPLAY_NAME}</h2>
  {gauge_html}
  {status_html}
  {support_html}
  {bu_table_html}
  {explain_html}
</div>"""

    # ------------------------------------------------------------------
    # render_excel_tabs()
    # ------------------------------------------------------------------

    def render_excel_tabs(
        self,
        data:     ModuleData,
        workbook: Any,
        config:   ModuleConfig,
    ) -> list[str]:
        """
        Write the "Scan Coverage Summary" tab into ``workbook``.

        Tab contents:
        - Overall KPI block (coverage %, status, supporting numbers)
        - Full business-unit breakdown table with colour-coded Coverage % column

        Returns
        -------
        list[str]
            ``["Scan Coverage Summary"]`` on success, ``[]`` on error.
        """
        tab_name = "Scan Coverage Summary"
        try:
            ws = workbook.create_sheet(tab_name)

            if data.error:
                ws["A1"] = "Error"
                ws["B1"] = data.error
                return [tab_name]

            m                   = data.metrics
            scan_coverage_pct   = m.get("scan_coverage_pct")
            scanned_on_time     = m.get("scanned_on_time", 0)
            not_scanned_on_time = m.get("not_scanned_on_time", 0)
            total_licensed      = m.get("total_licensed", 0)
            unlicensed_excluded = m.get("unlicensed_excluded", 0)
            status              = m.get("status", "no_data")

            # ---- Overall KPI block (rows 1–9) ----
            _xl_title(ws, "A1", "Scan Coverage SLA — Overall Summary")

            status_color_hex = _STATUS_COLOR.get(status, "#757575").lstrip("#")
            pct_str = (
                f"{scan_coverage_pct:.1f}%" if scan_coverage_pct is not None else "N/A"
            )

            _xl_kv(ws, 3, "Overall Coverage:", pct_str,
                   value_font=Font(bold=True, size=12, color=status_color_hex))
            _xl_kv(ws, 4, "Status:",
                   _STATUS_LABEL.get(status, status),
                   value_font=Font(bold=True, color=status_color_hex))
            _xl_kv(ws, 5, "Scanned On Time:",       f"{scanned_on_time:,}")
            _xl_kv(ws, 6, "Not On Time:",            f"{not_scanned_on_time:,}")
            _xl_kv(ws, 7, "Total Licensed Assets:",  f"{total_licensed:,}")
            _xl_kv(ws, 8, "Unlicensed Excluded:",    f"{unlicensed_excluded:,}")
            _xl_kv(ws, 9, "Window:",                 "Last 30 days (last_licensed_scan_date)")
            _xl_kv(ws, 10, "SLA Thresholds:",        "Green ≥95%  |  Amber ≥90%  |  Red <90%")

            # ---- BU breakdown table (starts at row 12) ----
            header_row = 12
            headers    = ["Business Unit", "Scanned On Time", "Licensed Assets", "Coverage %"]

            for col_idx, header in enumerate(headers, start=1):
                cell             = ws.cell(row=header_row, column=col_idx, value=header)
                cell.font        = Font(bold=True, color="FFFFFF")
                cell.fill        = _FILL_HEADER
                cell.alignment   = Alignment(horizontal="center")

            for row_offset, row in enumerate(data.table_data or [], start=1):
                data_row = header_row + row_offset
                bu_pct   = float(row.get("percentage",  0.0))
                bu_fill  = _xl_fill(bu_pct, _GREEN_THRESHOLD, _YELLOW_THRESHOLD,
                                    direction="higher_is_better")

                ws.cell(row=data_row, column=1,
                        value=str(row.get("business_unit", ""))).alignment = (
                    Alignment(horizontal="left")
                )
                ws.cell(row=data_row, column=2,
                        value=int(row.get("numerator",   0))).alignment = (
                    Alignment(horizontal="right")
                )
                ws.cell(row=data_row, column=3,
                        value=int(row.get("denominator", 0))).alignment = (
                    Alignment(horizontal="right")
                )
                pct_cell           = ws.cell(row=data_row, column=4,
                                             value=f"{bu_pct:.1f}%")
                pct_cell.fill      = bu_fill
                pct_cell.font      = Font(bold=True)
                pct_cell.alignment = Alignment(horizontal="center")

            # ---- Column widths ----
            ws.column_dimensions[get_column_letter(1)].width = 32
            ws.column_dimensions[get_column_letter(2)].width = 18
            ws.column_dimensions[get_column_letter(3)].width = 14
            ws.column_dimensions[get_column_letter(4)].width = 14

            return [tab_name]

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "%s render_excel_tabs() failed: %s",
                self._log_prefix(), exc, exc_info=True,
            )
            return []

    # ------------------------------------------------------------------
    # render_email_kpis()
    # ------------------------------------------------------------------

    def render_email_kpis(
        self,
        data:   ModuleData,
        config: ModuleConfig,
    ) -> dict[str, str]:
        """
        Return three KPI tiles for the HTML email body.

        Returns
        -------
        dict[str, str]
            Keys: "Scan Coverage", "Scanned On Time", "Not On Time".
            Returns empty dict if ``data.error`` is set.
        """
        if "email" not in self.SUPPORTED_OUTPUTS or data.error:
            return {}
        m   = data.metrics
        pct = m.get("scan_coverage_pct")
        return {
            "Scan Coverage":   f"{pct:.1f}%" if pct is not None else "N/A",
            "Scanned On Time": f"{m.get('scanned_on_time', 0):,}",
            "Not On Time":     f"{m.get('not_scanned_on_time', 0):,}",
        }

    # ------------------------------------------------------------------
    # get_audit_info()
    # ------------------------------------------------------------------

    def get_audit_info(self) -> dict:
        """Return calculation documentation for audit and runbook records."""
        return {
            **super().get_audit_info(),
            "calculations": {
                "scan_coverage_pct": (
                    "scanned_on_time / total_licensed × 100, rounded to 1 decimal. "
                    f"Numerator: licensed assets where last_licensed_scan_date "
                    f">= report_date − {ON_TIME_WINDOW_DAYS} days. "
                    "Denominator: licensed deduplicated assets "
                    "(last_licensed_scan_date IS NOT NULL after hostname dedup — "
                    "most-recent last_seen retained; unlicensed assets excluded entirely)."
                ),
                "status": (
                    "sla_status_from_thresholds(scan_coverage_pct, "
                    f"green_threshold={_GREEN_THRESHOLD}, "
                    f"yellow_threshold={_YELLOW_THRESHOLD}, "
                    "direction='higher_is_better'). "
                    "None → 'no_data'."
                ),
                "BU_breakdown": (
                    "compute_per_bu_breakdown(higher_is_better=True) applied to licensed "
                    "deduplicated assets enriched with business_unit from Application tag. "
                    "Per-BU numerator = count of on-time assets in that BU; "
                    "denominator = licensed asset count in that BU. "
                    "Unlicensed assets are excluded from all BU buckets. "
                    "affected = denominator − numerator (assets NOT scanned on time). "
                    "Primary sort: affected DESC (most un-scanned assets first). "
                    "Secondary sort: percentage ASC (worst coverage % among ties). "
                    "Assets with no Application tag → 'Untagged' bucket."
                ),
                "deduplication": (
                    "deduplicate_assets_by_name() removes duplicate hostnames, "
                    "retaining the row with the most-recent last_seen. "
                    "Rows with empty/blank hostname are kept as-is."
                ),
            },
        }


# ===========================================================================
# Module-private rendering helpers
# ===========================================================================

def _row_bg(
    pct: float,
    green_threshold: float,
    yellow_threshold: float,
    direction: str = "higher_is_better",
) -> str:
    """Return a light HTML background-color for a BU table row."""
    if direction == "higher_is_better":
        if pct >= green_threshold:
            return "#E8F5E9"   # light green
        if pct >= yellow_threshold:
            return "#FFF8E1"   # light amber
        return "#FFEBEE"       # light red
    else:  # lower_is_better
        if pct <= green_threshold:
            return "#E8F5E9"
        if pct <= yellow_threshold:
            return "#FFF8E1"
        return "#FFEBEE"


def _xl_fill(
    pct: float,
    green_threshold: float,
    yellow_threshold: float,
    direction: str = "higher_is_better",
) -> PatternFill:
    """Return an openpyxl PatternFill for a coverage-% cell."""
    if direction == "higher_is_better":
        if pct >= green_threshold:
            return _FILL_GREEN
        if pct >= yellow_threshold:
            return _FILL_YELLOW
        return _FILL_RED
    else:  # lower_is_better
        if pct <= green_threshold:
            return _FILL_GREEN
        if pct <= yellow_threshold:
            return _FILL_YELLOW
        return _FILL_RED


def _xl_title(ws, cell_ref: str, value: str) -> None:
    """Write a bold, size-12 title cell."""
    ws[cell_ref]       = value
    ws[cell_ref].font  = Font(bold=True, size=12)


def _xl_kv(
    ws,
    row:         int,
    label:       str,
    value:       str,
    value_font:  Font | None = None,
) -> None:
    """Write a label in column A and its value in column B for the given row."""
    label_cell       = ws.cell(row=row, column=1, value=label)
    label_cell.font  = Font(bold=True)

    value_cell       = ws.cell(row=row, column=2, value=value)
    if value_font is not None:
        value_cell.font = value_font
