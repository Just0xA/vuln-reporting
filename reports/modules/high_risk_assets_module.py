"""
reports/modules/high_risk_assets_module.py — High-Risk Assets metric module.

Measures the percentage of on-time-scanned assets that carry 10 or more
Critical or High vulnerabilities that have been open for more than 30 days.
A high concentration of such assets signals a systemic remediation backlog
that exposes the organisation to sustained elevated risk.

Module ID:    high_risk_assets
Display Name: High-Risk Assets

SLA thresholds (board-defined, lower is better):
    Green:  high_risk_pct <= 0.5%
    Yellow: high_risk_pct <= 1.0%  (and > 0.5%)
    Red:    high_risk_pct >  1.0%

Denominator: all deduplicated on-time-scanned assets (last_licensed_scan_date
             within the last 30 days).
Numerator:   subset where the count of Critical/High open findings with
             days_open > 30 is >= 10.
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
    extract_business_unit,
    identify_on_time_assets,
    sla_status_from_thresholds,
    ON_TIME_WINDOW_DAYS,
)
from reports.modules.chart_utils import draw_gauge

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_GREEN_THRESHOLD  = 0.5    # <= green (lower is better)
_YELLOW_THRESHOLD = 1.0    # <= yellow; > green
_DIRECTION        = "lower_is_better"

#: Minimum number of aged Critical/High findings required for an asset to be
#: classified as "high-risk".
_HIGH_RISK_COUNT: int = 10

#: Findings open longer than this many days qualify as "aged".
_AGED_DAYS_THRESHOLD: int = 30

# draw_gauge threshold list: each tuple = (upper_bound, colour)
# For lower_is_better the gauge reads left=green, right=red:
#   0–0.5  green | 0.5–1.0 amber | 1.0–100 red
_GAUGE_THRESHOLDS = [
    (_GREEN_THRESHOLD,  "#388e3c"),   # 0 – 0.5  green
    (_YELLOW_THRESHOLD, "#fbc02d"),   # 0.5 – 1.0 amber
    (100.0,             "#d32f2f"),   # 1.0 – 100 red
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
class HighRiskAssetsModule(BaseModule):
    """
    Percentage of on-time-scanned assets with >= 10 Critical/High vulns open > 30 days.

    Lower is better.  The per-BU breakdown table shows worst performers first
    (highest percentage of high-risk assets at the top) so the PDF and Excel
    surfaces the business units with the most acute remediation backlog.

    Supported options
    -----------------
    None — this module accepts no configurable options.
    """

    MODULE_ID         = "high_risk_assets"
    DISPLAY_NAME      = "High-Risk Assets"
    DESCRIPTION       = (
        f"Percentage of on-time-scanned assets carrying "
        f">={_HIGH_RISK_COUNT} Critical/High vulnerabilities open >{_AGED_DAYS_THRESHOLD} days."
    )
    REQUIRED_DATA     = ["vulns", "assets"]
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
        Compute the high-risk asset percentage and per-BU breakdown.

        Parameters
        ----------
        vulns_df : pd.DataFrame
            Open / reopened findings from fetch_all_vulnerabilities().
            Expected columns: asset_uuid, severity (VPR-derived), first_found.
        assets_df : pd.DataFrame
            Full asset inventory from fetch_all_assets().
            Required columns: asset_uuid, hostname, last_seen,
            last_licensed_scan_date, tags.
        report_date : datetime
            UTC-aware report run timestamp.
        config : ModuleConfig
            Module configuration (no options consumed).
        **kwargs
            Accepted but not used.

        Returns
        -------
        ModuleData
            ``error`` is None on success; set on failure.
        """
        logger.debug(
            "%s compute() — vulns_df=%d rows, assets_df=%d rows",
            self._log_prefix(), len(vulns_df), len(assets_df),
        )

        try:
            # ---- Step 1: derive on-time asset set ----
            on_time, _ = identify_on_time_assets(assets_df, report_date)
            on_time_uuids = set(on_time["asset_uuid"].dropna())
            total_on_time = len(on_time)

            if total_on_time == 0:
                logger.warning(
                    "%s no on-time assets found — returning no_data.",
                    self._log_prefix(),
                )
                return ModuleData(
                    module_id    = self.MODULE_ID,
                    display_name = self.DISPLAY_NAME,
                    metrics      = {
                        "high_risk_pct":   None,
                        "high_risk_count": 0,
                        "total_on_time":   0,
                        "status":          "no_data",
                    },
                    table_data   = [],
                    chart_data   = {"value": None, "top_5": []},
                    summary_text = (
                        "No on-time-scanned assets were found — "
                        "high-risk asset percentage cannot be computed."
                    ),
                    metadata     = _build_metadata(report_date),
                    error        = None,
                )

            # ---- Step 2: build UTC-aware report timestamp ----
            if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
                rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
            else:
                rd_ts = pd.Timestamp(report_date, tz="UTC")

            # ---- Step 3: filter vulns to on-time assets + Critical/High ----
            high_risk_uuids, aged_counts_per_asset = _find_high_risk_assets(
                vulns_df, on_time_uuids, rd_ts,
            )
            high_risk_count = len(high_risk_uuids)

            # ---- Step 4: overall metric ----
            high_risk_pct = round(high_risk_count / total_on_time * 100, 1)
            status = sla_status_from_thresholds(
                high_risk_pct,
                green_threshold  = _GREEN_THRESHOLD,
                yellow_threshold = _YELLOW_THRESHOLD,
                direction        = _DIRECTION,
            )

            # ---- Step 5: per-BU breakdown ----
            enriched       = extract_business_unit(on_time)
            numerator_mask = enriched["asset_uuid"].isin(high_risk_uuids)
            denom_mask     = pd.Series(True, index=enriched.index)

            bu_breakdown = compute_per_bu_breakdown(
                enriched, numerator_mask, denom_mask,
                higher_is_better=False,
            )
            table_data = bu_breakdown.to_dict("records")

            # ---- Step 6: narrative summary ----
            summary_text = _build_summary(
                high_risk_pct, high_risk_count, total_on_time, status,
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
                    "high_risk_pct":   high_risk_pct,
                    "high_risk_count": high_risk_count,
                    "total_on_time":   total_on_time,
                    "status":          status,
                },
                table_data   = table_data,
                chart_data   = {
                    "value":      high_risk_pct,
                    "thresholds": {
                        "green":  _GREEN_THRESHOLD,
                        "yellow": _YELLOW_THRESHOLD,
                    },
                    "direction":  _DIRECTION,
                    # Top 5 BUs by affected asset count (most high-risk assets first)
                    "top_5":      bu_breakdown.head(5).to_dict("records"),
                },
                summary_text = summary_text,
                metadata     = {**_build_metadata(report_date), "computed_at": computed_at},
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
        2. Gauge (centred) — green near 0%, red near 100%
        3. Status badge showing high-risk % and on-target label
        4. Two bold support numbers: High-Risk Assets | Total On-Time Assets
        5. Top-5 worst-performing BUs table (highest % first)
        6. Explanatory paragraph

        Returns an error callout div if ``data.error`` is set.
        """
        if data.error:
            return (
                f'<div class="error-box">'
                f"<strong>{self.DISPLAY_NAME}</strong>: {data.error}"
                f"</div>"
            )

        m               = data.metrics
        high_risk_pct   = m.get("high_risk_pct")
        high_risk_count = m.get("high_risk_count", 0)
        total_on_time   = m.get("total_on_time", 0)
        status          = m.get("status", "no_data")

        # ---- Gauge ----
        gauge_value = high_risk_pct if high_risk_pct is not None else 0.0
        try:
            gauge_b64  = draw_gauge(
                value      = gauge_value,
                min_val    = 0,
                max_val    = 100,
                thresholds = _GAUGE_THRESHOLDS,
                title      = "High-Risk Assets %",
                unit       = "%",
                figsize    = (5, 3),
            )
            gauge_html = (
                f'<div style="text-align:center; margin-bottom:4mm;">'
                f'<img src="data:image/png;base64,{gauge_b64}" '
                f'style="width:46%; max-width:320px;" '
                f'alt="High-Risk Assets gauge">'
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
            f"{high_risk_pct:.1f}%" if high_risk_pct is not None else "N/A"
        )
        status_html = (
            f'<p style="text-align:center; font-size:10pt; font-weight:bold; '
            f'color:{status_color}; margin:0 0 5mm 0;">'
            f'High-Risk Assets: {pct_display} &nbsp;&middot;&nbsp; {status_label}'
            f'</p>'
        )

        # ---- Supporting numbers ----
        risk_color  = _STATUS_COLOR.get(status, "#555")
        support_html = f"""
<table style="width:52%; margin:0 auto 6mm auto; border-collapse:collapse;">
  <tr>
    <td style="text-align:center; padding:2mm 8mm;
               border-right:0.5pt solid #ddd; vertical-align:middle;">
      <span style="font-size:14pt; font-weight:bold;
             color:{risk_color};">{high_risk_count:,}</span>
      <br><span style="font-size:7.5pt; color:#555;">High-Risk Assets</span>
    </td>
    <td style="text-align:center; padding:2mm 8mm; vertical-align:middle;">
      <span style="font-size:14pt; font-weight:bold;
             color:#1F3864;">{total_on_time:,}</span>
      <br><span style="font-size:7.5pt; color:#555;">Total On-Time Assets</span>
    </td>
  </tr>
</table>"""

        # ---- Top 5 BU table (worst performers = highest %) ----
        top5 = data.chart_data.get("top_5", [])
        if top5:
            rows_html = ""
            for row in top5:
                bu_pct  = float(row.get("percentage", 0.0))
                bu_name = str(row.get("business_unit", ""))
                bu_num  = int(row.get("numerator",    0))
                bu_den  = int(row.get("denominator",  0))
                row_bg  = _row_bg(bu_pct)
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
      <th style="text-align:right;">High-Risk Assets</th>
      <th style="text-align:right;">On-Time Assets</th>
      <th style="text-align:right;">High-Risk %</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>"""
        else:
            bu_table_html = (
                '<p class="explanatory-text" style="color:#888; font-style:italic;">'
                'No business-unit breakdown available — '
                'assets may lack Application tags or no high-risk assets were found.'
                '</p>'
            )

        # ---- Explanatory paragraph ----
        explain_html = f"""
<p class="explanatory-text">
  <strong>What this measures:</strong> The percentage of assets scanned on time
  (licensed scan within the last {ON_TIME_WINDOW_DAYS} days) that carry
  &ge;{_HIGH_RISK_COUNT} Critical or High vulnerabilities (VPR&nbsp;7.0&ndash;10.0) that
  have been open for more than {_AGED_DAYS_THRESHOLD} days.  These assets represent
  the highest sustained risk exposure — they are actively managed yet have significant
  unresolved findings well past normal triage timelines.  Board target is
  &le;{_GREEN_THRESHOLD:.1f}% (green).  &le;{_YELLOW_THRESHOLD:.1f}% is at-risk (amber).
  Above {_YELLOW_THRESHOLD:.1f}% is off-target (red).  Business-unit breakdown uses
  the Tenable &ldquo;Application&rdquo; tag category.
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
        Write the "High-Risk Assets" tab into ``workbook``.

        Tab contents:
        - Overall KPI block (high-risk %, status, supporting numbers, thresholds)
        - Full per-BU breakdown table sorted worst-first (highest % at top)

        Returns
        -------
        list[str]
            ``["High-Risk Assets"]`` on success, ``[]`` on error.
        """
        tab_name = "High-Risk Assets"
        try:
            ws = workbook.create_sheet(tab_name)

            if data.error:
                ws["A1"] = "Error"
                ws["B1"] = data.error
                return [tab_name]

            m               = data.metrics
            high_risk_pct   = m.get("high_risk_pct")
            high_risk_count = m.get("high_risk_count", 0)
            total_on_time   = m.get("total_on_time", 0)
            status          = m.get("status", "no_data")

            # ---- Overall KPI block ----
            _xl_title(ws, "A1", "High-Risk Assets — Overall Summary")

            status_color_hex = _STATUS_COLOR.get(status, "#757575").lstrip("#")
            pct_str = (
                f"{high_risk_pct:.1f}%" if high_risk_pct is not None else "N/A"
            )

            _xl_kv(ws, 3, "High-Risk Asset %:", pct_str,
                   value_font=Font(bold=True, size=12, color=status_color_hex))
            _xl_kv(ws, 4, "Status:",
                   _STATUS_LABEL.get(status, status),
                   value_font=Font(bold=True, color=status_color_hex))
            _xl_kv(ws, 5, "High-Risk Assets:", f"{high_risk_count:,}")
            _xl_kv(ws, 6, "Total On-Time Assets:", f"{total_on_time:,}")
            _xl_kv(ws, 7, "High-Risk Definition:",
                   f">={_HIGH_RISK_COUNT} Critical/High vulns open >{_AGED_DAYS_THRESHOLD} days")
            _xl_kv(ws, 8, "Scope:",
                   "On-time-scanned assets only (last_licensed_scan_date within last 30 days)")
            _xl_kv(ws, 9, "SLA Thresholds (lower is better):",
                   f"Green <={_GREEN_THRESHOLD:.1f}%  |  "
                   f"Amber <={_YELLOW_THRESHOLD:.1f}%  |  "
                   f"Red >{_YELLOW_THRESHOLD:.1f}%")

            # ---- BU breakdown table (starts at row 11, worst first) ----
            header_row = 11
            headers = [
                "Business Unit", "High-Risk Assets", "On-Time Assets", "High-Risk %"
            ]
            for col_idx, header in enumerate(headers, start=1):
                cell           = ws.cell(row=header_row, column=col_idx, value=header)
                cell.font      = Font(bold=True, color="FFFFFF")
                cell.fill      = _FILL_HEADER
                cell.alignment = Alignment(horizontal="center")

            for row_offset, row in enumerate(data.table_data or [], start=1):
                data_row = header_row + row_offset
                bu_pct   = float(row.get("percentage",  0.0))
                bu_fill  = _xl_fill(bu_pct)

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
            ws.column_dimensions[get_column_letter(3)].width = 18
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
            Keys: "High-Risk Assets %", "High-Risk Assets", "On-Time Assets".
            Returns empty dict if ``data.error`` is set.
        """
        if "email" not in self.SUPPORTED_OUTPUTS or data.error:
            return {}
        m   = data.metrics
        pct = m.get("high_risk_pct")
        return {
            "High-Risk Assets %": f"{pct:.1f}%" if pct is not None else "N/A",
            "High-Risk Assets":   f"{m.get('high_risk_count', 0):,}",
            "On-Time Assets":     f"{m.get('total_on_time', 0):,}",
        }

    # ------------------------------------------------------------------
    # get_audit_info()
    # ------------------------------------------------------------------

    def get_audit_info(self) -> dict:
        """Return calculation documentation for audit and runbook records."""
        return {
            **super().get_audit_info(),
            "calculations": {
                "high_risk_pct": (
                    "high_risk_count / total_on_time × 100, rounded to 1 decimal. "
                    "None → 'no_data' when total_on_time == 0."
                ),
                "high_risk_count": (
                    f"Count of on-time assets where the number of open Critical or High "
                    f"findings with days_open > {_AGED_DAYS_THRESHOLD} is "
                    f">= {_HIGH_RISK_COUNT}."
                ),
                "total_on_time": (
                    "Count of deduplicated assets where last_licensed_scan_date IS NOT NULL "
                    f"AND >= report_date − {ON_TIME_WINDOW_DAYS} days."
                ),
                "days_open": (
                    "(report_date − first_found).days.  Findings with null first_found "
                    "produce NaT/NaN and are treated as 0 days (not counted as aged)."
                ),
                "severity_filter": (
                    "severity IN ('critical', 'high').  Severity is VPR-derived "
                    "(vpr_to_severity from config.py) as produced by fetch_all_vulnerabilities()."
                ),
                "BU_breakdown": (
                    "compute_per_bu_breakdown(higher_is_better=False) on on-time assets "
                    "enriched with Application tag. "
                    "Numerator = high-risk assets per BU; denominator = all on-time assets per BU. "
                    "affected = numerator (raw high-risk count). "
                    "Primary sort: affected DESC (largest absolute problem first). "
                    "Secondary sort: percentage DESC (worst % among ties)."
                ),
            },
        }


# ===========================================================================
# Module-private helpers
# ===========================================================================

def _find_high_risk_assets(
    vulns_df:      pd.DataFrame,
    on_time_uuids: set,
    rd_ts:         pd.Timestamp,
) -> tuple[set, pd.Series]:
    """
    Identify on-time assets that qualify as "high-risk".

    An asset is high-risk when it has >= ``_HIGH_RISK_COUNT`` Critical or High
    findings that have been open for more than ``_AGED_DAYS_THRESHOLD`` days.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Open / reopened findings.
    on_time_uuids : set
        UUIDs of on-time-scanned assets.
    rd_ts : pd.Timestamp
        UTC-aware report timestamp used to compute days_open.

    Returns
    -------
    tuple[set, pd.Series]
        ``(high_risk_uuids, aged_counts_per_asset)``
        - ``high_risk_uuids``: set of asset_uuids classified as high-risk.
        - ``aged_counts_per_asset``: pd.Series indexed by asset_uuid with the
          count of aged Critical/High findings per asset (all on-time assets,
          not just high-risk ones).
    """
    if vulns_df.empty:
        return set(), pd.Series(dtype=int)

    required = {"asset_uuid", "severity", "first_found"}
    if not required.issubset(vulns_df.columns):
        missing = required - set(vulns_df.columns)
        logger.warning(
            "_find_high_risk_assets: missing columns %s — returning empty set.", missing
        )
        return set(), pd.Series(dtype=int)

    # Filter to on-time assets + Critical/High severity
    on_time_mask  = vulns_df["asset_uuid"].isin(on_time_uuids)
    severity_mask = vulns_df["severity"].str.lower().isin(["critical", "high"])
    relevant      = vulns_df[on_time_mask & severity_mask].copy()

    if relevant.empty:
        return set(), pd.Series(dtype=int)

    # Compute days_open; NaT first_found → NaN days → treated as 0 (not aged)
    days_open = (rd_ts - relevant["first_found"]).dt.days
    aged_mask = days_open > _AGED_DAYS_THRESHOLD

    aged = relevant[aged_mask]

    if aged.empty:
        return set(), pd.Series(dtype=int)

    # Count aged Critical/High findings per asset
    aged_counts = aged.groupby("asset_uuid").size()

    # Assets that meet or exceed the high-risk threshold
    high_risk_uuids = set(aged_counts[aged_counts >= _HIGH_RISK_COUNT].index)

    return high_risk_uuids, aged_counts


def _build_metadata(report_date: Any) -> dict:
    """Return the standard metadata block for this module."""
    return {
        "high_risk_definition":  (
            f">={_HIGH_RISK_COUNT} Critical/High findings open "
            f">{_AGED_DAYS_THRESHOLD} days on an on-time-scanned asset."
        ),
        "severity_scope":        "Critical (VPR 9.0–10.0) and High (VPR 7.0–8.9)",
        "denominator_scope":     (
            f"On-time-scanned assets: last_licensed_scan_date IS NOT NULL "
            f"AND >= report_date − {ON_TIME_WINDOW_DAYS} days."
        ),
        "sla_source":            (
            f"Board-defined thresholds "
            f"(Green <={_GREEN_THRESHOLD}%, "
            f"Amber <={_YELLOW_THRESHOLD}%, Red >{_YELLOW_THRESHOLD}%, "
            f"direction=lower_is_better)"
        ),
        "window":                f"Last {ON_TIME_WINDOW_DAYS} days from report_date",
    }


def _build_summary(
    high_risk_pct:   float | None,
    high_risk_count: int,
    total_on_time:   int,
    status:          str,
) -> str:
    """Build a plain-language narrative sentence for the email body."""
    if high_risk_pct is None:
        return (
            "No on-time-scanned assets were found — "
            "high-risk asset percentage cannot be computed."
        )
    status_label = _STATUS_LABEL.get(status, status)
    return (
        f"{high_risk_pct:.1f}% of on-time-scanned assets are high-risk — "
        f"{high_risk_count:,} of {total_on_time:,} assets have "
        f">={_HIGH_RISK_COUNT} Critical/High vulnerabilities open "
        f">{_AGED_DAYS_THRESHOLD} days. "
        f"Status: {status_label}."
    )


def _row_bg(pct: float) -> str:
    """Light HTML background-color for a BU table row (lower-is-better)."""
    if pct <= _GREEN_THRESHOLD:
        return "#E8F5E9"   # light green
    if pct <= _YELLOW_THRESHOLD:
        return "#FFF8E1"   # light amber
    return "#FFEBEE"       # light red


def _xl_fill(pct: float) -> PatternFill:
    """openpyxl PatternFill for a high-risk-% cell (lower-is-better)."""
    if pct <= _GREEN_THRESHOLD:
        return _FILL_GREEN
    if pct <= _YELLOW_THRESHOLD:
        return _FILL_YELLOW
    return _FILL_RED


def _xl_title(ws, cell_ref: str, value: str) -> None:
    ws[cell_ref]      = value
    ws[cell_ref].font = Font(bold=True, size=12)


def _xl_kv(ws, row: int, label: str, value: str,
            value_font: Font | None = None) -> None:
    lc      = ws.cell(row=row, column=1, value=label)
    lc.font = Font(bold=True)
    vc      = ws.cell(row=row, column=2, value=value)
    if value_font is not None:
        vc.font = value_font
