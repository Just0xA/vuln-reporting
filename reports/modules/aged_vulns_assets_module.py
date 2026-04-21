"""
reports/modules/aged_vulns_assets_module.py — Aged Vulnerability Assets metric module.

Measures the percentage of on-time-scanned assets that carry at least one
Medium, High, or Critical vulnerability open for more than 90 days.  Assets
with long-standing unresolved findings indicate a persistent remediation gap
and represent enduring exposure even at lower severities.

Module ID:    aged_vulns_assets
Display Name: Aged Vulnerability Assets

SLA thresholds (board-defined, lower is better):
    Green:  aged_assets_pct <= 2%
    Yellow: aged_assets_pct <= 5%  (and > 2%)
    Red:    aged_assets_pct >  5%

Denominator: all deduplicated on-time-scanned assets (last_licensed_scan_date
             within the last 30 days).
Numerator:   subset with >= 1 Medium/High/Critical finding open > 90 days.
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

_GREEN_THRESHOLD  = 2.0    # <= green (lower is better)
_YELLOW_THRESHOLD = 5.0    # <= yellow; > green
_DIRECTION        = "lower_is_better"

#: Findings open longer than this many days qualify as "aged".
_AGED_DAYS_THRESHOLD: int = 90

#: Minimum aged findings required for an asset to be included in the numerator.
_MIN_AGED_COUNT: int = 1

#: Severity tiers included in the aged-vuln scan.
_AGED_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium"})

# draw_gauge threshold list: (upper_bound, colour)
# 0–2 green | 2–5 amber | 5–100 red
_GAUGE_THRESHOLDS = [
    (_GREEN_THRESHOLD,  "#388e3c"),
    (_YELLOW_THRESHOLD, "#fbc02d"),
    (100.0,             "#d32f2f"),
]

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

_FILL_GREEN  = PatternFill("solid", fgColor="C8E6C9")
_FILL_YELLOW = PatternFill("solid", fgColor="FFF9C4")
_FILL_RED    = PatternFill("solid", fgColor="FFCDD2")
_FILL_HEADER = PatternFill("solid", fgColor="1F3864")


# ===========================================================================
# Module class
# ===========================================================================

@register_module
class AgedVulnsAssetsModule(BaseModule):
    """
    Percentage of on-time-scanned assets with >= 1 Med/High/Crit vuln open > 90 days.

    Lower is better.  Per-BU breakdown sorted worst-first (highest percentage
    at the top) to surface business units with the deepest aging backlog.

    Supported options
    -----------------
    None — this module accepts no configurable options.
    """

    MODULE_ID         = "aged_vulns_assets"
    DISPLAY_NAME      = "Aged Vulnerability Assets"
    DESCRIPTION       = (
        f"Percentage of on-time-scanned assets with >={_MIN_AGED_COUNT} "
        f"Medium/High/Critical vulnerability open >{_AGED_DAYS_THRESHOLD} days."
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
        Compute aged-vulnerability asset percentage and per-BU breakdown.

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
                        "aged_assets_pct":   None,
                        "aged_assets_count": 0,
                        "total_on_time":     0,
                        "status":            "no_data",
                    },
                    table_data   = [],
                    chart_data   = {"value": None, "top_5": []},
                    summary_text = (
                        "No on-time-scanned assets were found — "
                        "aged vulnerability asset percentage cannot be computed."
                    ),
                    metadata     = _build_metadata(report_date),
                    error        = None,
                )

            # ---- Step 2: build UTC-aware report timestamp ----
            if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
                rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
            else:
                rd_ts = pd.Timestamp(report_date, tz="UTC")

            # ---- Step 3: identify assets with aged Med/High/Crit findings ----
            aged_uuids = _find_aged_assets(vulns_df, on_time_uuids, rd_ts)
            aged_assets_count = len(aged_uuids)

            # ---- Step 4: overall metric ----
            aged_assets_pct = round(aged_assets_count / total_on_time * 100, 1)
            status = sla_status_from_thresholds(
                aged_assets_pct,
                green_threshold  = _GREEN_THRESHOLD,
                yellow_threshold = _YELLOW_THRESHOLD,
                direction        = _DIRECTION,
            )

            # ---- Step 5: per-BU breakdown ----
            enriched       = extract_business_unit(on_time)
            numerator_mask = enriched["asset_uuid"].isin(aged_uuids)
            denom_mask     = pd.Series(True, index=enriched.index)

            bu_breakdown = compute_per_bu_breakdown(
                enriched, numerator_mask, denom_mask,
            )

            # Sort descending: worst performers (highest %) first
            bu_breakdown_desc = (
                bu_breakdown
                .sort_values("percentage", ascending=False)
                .reset_index(drop=True)
            )
            table_data = bu_breakdown_desc.to_dict("records")

            # ---- Step 6: narrative summary ----
            summary_text = _build_summary(
                aged_assets_pct, aged_assets_count, total_on_time, status,
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
                    "aged_assets_pct":   aged_assets_pct,
                    "aged_assets_count": aged_assets_count,
                    "total_on_time":     total_on_time,
                    "status":            status,
                },
                table_data   = table_data,
                chart_data   = {
                    "value":      aged_assets_pct,
                    "thresholds": {
                        "green":  _GREEN_THRESHOLD,
                        "yellow": _YELLOW_THRESHOLD,
                    },
                    "direction":  _DIRECTION,
                    "top_5":      bu_breakdown_desc.head(5).to_dict("records"),
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
        3. Status badge showing aged-assets % and on-target label
        4. Two bold support numbers: Aged Assets | Total On-Time Assets
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

        m                 = data.metrics
        aged_assets_pct   = m.get("aged_assets_pct")
        aged_assets_count = m.get("aged_assets_count", 0)
        total_on_time     = m.get("total_on_time", 0)
        status            = m.get("status", "no_data")

        # ---- Gauge ----
        gauge_value = aged_assets_pct if aged_assets_pct is not None else 0.0
        try:
            gauge_b64  = draw_gauge(
                value      = gauge_value,
                min_val    = 0,
                max_val    = 100,
                thresholds = _GAUGE_THRESHOLDS,
                title      = "Aged Vuln Assets %",
                unit       = "%",
                figsize    = (5, 3),
            )
            gauge_html = (
                f'<div style="text-align:center; margin-bottom:4mm;">'
                f'<img src="data:image/png;base64,{gauge_b64}" '
                f'style="width:46%; max-width:320px;" '
                f'alt="Aged Vulnerability Assets gauge">'
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
            f"{aged_assets_pct:.1f}%" if aged_assets_pct is not None else "N/A"
        )
        status_html = (
            f'<p style="text-align:center; font-size:10pt; font-weight:bold; '
            f'color:{status_color}; margin:0 0 5mm 0;">'
            f'Aged Assets: {pct_display} &nbsp;&middot;&nbsp; {status_label}'
            f'</p>'
        )

        # ---- Supporting numbers ----
        aged_color   = _STATUS_COLOR.get(status, "#555")
        support_html = f"""
<table style="width:52%; margin:0 auto 6mm auto; border-collapse:collapse;">
  <tr>
    <td style="text-align:center; padding:2mm 8mm;
               border-right:0.5pt solid #ddd; vertical-align:middle;">
      <span style="font-size:14pt; font-weight:bold;
             color:{aged_color};">{aged_assets_count:,}</span>
      <br><span style="font-size:7.5pt; color:#555;">Assets with Aged Vulns</span>
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
      <th style="text-align:right;">Assets with Aged Vulns</th>
      <th style="text-align:right;">On-Time Assets</th>
      <th style="text-align:right;">Aged %</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>"""
        else:
            bu_table_html = (
                '<p class="explanatory-text" style="color:#888; font-style:italic;">'
                'No business-unit breakdown available — '
                'assets may lack Application tags or no aged findings were found.'
                '</p>'
            )

        # ---- Explanatory paragraph ----
        explain_html = f"""
<p class="explanatory-text">
  <strong>What this measures:</strong> The percentage of assets scanned on time
  (licensed scan within the last {ON_TIME_WINDOW_DAYS} days) that carry at least one
  Medium, High, or Critical vulnerability (VPR&nbsp;&ge;4.0) open for more than
  {_AGED_DAYS_THRESHOLD} days.  Long-standing unresolved findings — even at medium
  severity — represent persistent, accepted risk exposure and can indicate systemic
  remediation gaps.  Board target is &le;{_GREEN_THRESHOLD:.0f}% (green).
  &le;{_YELLOW_THRESHOLD:.0f}% is at-risk (amber).  Above {_YELLOW_THRESHOLD:.0f}%
  is off-target (red).  Business-unit breakdown uses the Tenable
  &ldquo;Application&rdquo; tag category.
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
        Write the "Aged Vuln Assets" tab into ``workbook``.

        Tab contents:
        - Overall KPI block (aged %, status, supporting numbers, thresholds)
        - Full per-BU breakdown table sorted worst-first (highest % at top)

        Returns
        -------
        list[str]
            ``["Aged Vuln Assets"]`` on success, ``[]`` on error.
        """
        tab_name = "Aged Vuln Assets"
        try:
            ws = workbook.create_sheet(tab_name)

            if data.error:
                ws["A1"] = "Error"
                ws["B1"] = data.error
                return [tab_name]

            m                 = data.metrics
            aged_assets_pct   = m.get("aged_assets_pct")
            aged_assets_count = m.get("aged_assets_count", 0)
            total_on_time     = m.get("total_on_time", 0)
            status            = m.get("status", "no_data")

            # ---- Overall KPI block ----
            _xl_title(ws, "A1", "Aged Vulnerability Assets — Overall Summary")

            status_color_hex = _STATUS_COLOR.get(status, "#757575").lstrip("#")
            pct_str = (
                f"{aged_assets_pct:.1f}%" if aged_assets_pct is not None else "N/A"
            )

            _xl_kv(ws, 3, "Aged Assets %:", pct_str,
                   value_font=Font(bold=True, size=12, color=status_color_hex))
            _xl_kv(ws, 4, "Status:",
                   _STATUS_LABEL.get(status, status),
                   value_font=Font(bold=True, color=status_color_hex))
            _xl_kv(ws, 5, "Assets with Aged Vulns:", f"{aged_assets_count:,}")
            _xl_kv(ws, 6, "Total On-Time Assets:", f"{total_on_time:,}")
            _xl_kv(ws, 7, "Aged Definition:",
                   f">={_MIN_AGED_COUNT} Medium/High/Critical vuln open >{_AGED_DAYS_THRESHOLD} days")
            _xl_kv(ws, 8, "Scope:",
                   "On-time-scanned assets only (last_licensed_scan_date within last 30 days)")
            _xl_kv(ws, 9, "SLA Thresholds (lower is better):",
                   f"Green <={_GREEN_THRESHOLD:.0f}%  |  "
                   f"Amber <={_YELLOW_THRESHOLD:.0f}%  |  "
                   f"Red >{_YELLOW_THRESHOLD:.0f}%")

            # ---- BU breakdown table (starts at row 11, worst first) ----
            header_row = 11
            headers = [
                "Business Unit", "Assets with Aged Vulns", "On-Time Assets", "Aged %"
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
            ws.column_dimensions[get_column_letter(2)].width = 22
            ws.column_dimensions[get_column_letter(3)].width = 18
            ws.column_dimensions[get_column_letter(4)].width = 12

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
            Keys: "Aged Assets %", "Assets w/ Aged Vulns", "On-Time Assets".
            Returns empty dict if ``data.error`` is set.
        """
        if "email" not in self.SUPPORTED_OUTPUTS or data.error:
            return {}
        m   = data.metrics
        pct = m.get("aged_assets_pct")
        return {
            "Aged Assets %":       f"{pct:.1f}%" if pct is not None else "N/A",
            "Assets w/ Aged Vulns": f"{m.get('aged_assets_count', 0):,}",
            "On-Time Assets":       f"{m.get('total_on_time', 0):,}",
        }

    # ------------------------------------------------------------------
    # get_audit_info()
    # ------------------------------------------------------------------

    def get_audit_info(self) -> dict:
        """Return calculation documentation for audit and runbook records."""
        return {
            **super().get_audit_info(),
            "calculations": {
                "aged_assets_pct": (
                    "aged_assets_count / total_on_time × 100, rounded to 1 decimal. "
                    "None → 'no_data' when total_on_time == 0."
                ),
                "aged_assets_count": (
                    f"Count of on-time assets that have >= {_MIN_AGED_COUNT} "
                    f"Medium/High/Critical finding with days_open > {_AGED_DAYS_THRESHOLD}."
                ),
                "total_on_time": (
                    "Count of deduplicated assets where last_licensed_scan_date IS NOT NULL "
                    f"AND >= report_date − {ON_TIME_WINDOW_DAYS} days."
                ),
                "days_open": (
                    "(report_date − first_found).days.  Findings with null first_found "
                    "produce NaT/NaN and are treated as not aged."
                ),
                "severity_filter": (
                    "severity IN ('critical', 'high', 'medium').  Severity is VPR-derived "
                    "as produced by fetch_all_vulnerabilities()."
                ),
                "BU_breakdown": (
                    "compute_per_bu_breakdown() on on-time assets enriched with Application tag. "
                    "Numerator = assets with aged finding(s) per BU; "
                    "denominator = all on-time assets per BU. "
                    "Sorted DESCENDING by percentage (worst performers first)."
                ),
            },
        }


# ===========================================================================
# Module-private helpers
# ===========================================================================

def _find_aged_assets(
    vulns_df:      pd.DataFrame,
    on_time_uuids: set,
    rd_ts:         pd.Timestamp,
) -> set:
    """
    Return the set of on-time asset UUIDs with >= 1 aged Med/High/Crit finding.

    A finding is aged when (report_date − first_found).days > _AGED_DAYS_THRESHOLD.
    Findings with null first_found are treated as 0 days old (not aged).

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Open / reopened findings.
    on_time_uuids : set
        UUIDs of on-time-scanned assets.
    rd_ts : pd.Timestamp
        UTC-aware report timestamp.

    Returns
    -------
    set
        UUIDs of on-time assets with at least one qualifying aged finding.
    """
    if vulns_df.empty:
        return set()

    required = {"asset_uuid", "severity", "first_found"}
    if not required.issubset(vulns_df.columns):
        missing = required - set(vulns_df.columns)
        logger.warning(
            "_find_aged_assets: missing columns %s — returning empty set.", missing
        )
        return set()

    # Filter to on-time assets + qualifying severities
    on_time_mask  = vulns_df["asset_uuid"].isin(on_time_uuids)
    severity_mask = vulns_df["severity"].str.lower().isin(_AGED_SEVERITIES)
    relevant      = vulns_df[on_time_mask & severity_mask]

    if relevant.empty:
        return set()

    # Compute days_open; NaT → NaN → aged_mask = False (not aged)
    days_open = (rd_ts - relevant["first_found"]).dt.days
    aged_mask = days_open > _AGED_DAYS_THRESHOLD

    return set(relevant.loc[aged_mask, "asset_uuid"].dropna().unique())


def _build_metadata(report_date: Any) -> dict:
    """Return the standard metadata block for this module."""
    return {
        "aged_definition":   (
            f">={_MIN_AGED_COUNT} Medium/High/Critical finding open "
            f">{_AGED_DAYS_THRESHOLD} days on an on-time-scanned asset."
        ),
        "severity_scope":    "Medium (VPR 4.0–6.9), High (VPR 7.0–8.9), Critical (VPR 9.0–10.0)",
        "denominator_scope": (
            f"On-time-scanned assets: last_licensed_scan_date IS NOT NULL "
            f"AND >= report_date − {ON_TIME_WINDOW_DAYS} days."
        ),
        "sla_source":        (
            f"Board-defined thresholds "
            f"(Green <={_GREEN_THRESHOLD}%, "
            f"Amber <={_YELLOW_THRESHOLD}%, Red >{_YELLOW_THRESHOLD}%, "
            f"direction=lower_is_better)"
        ),
        "window":            f"Last {ON_TIME_WINDOW_DAYS} days from report_date",
    }


def _build_summary(
    aged_assets_pct:   float | None,
    aged_assets_count: int,
    total_on_time:     int,
    status:            str,
) -> str:
    """Build a plain-language narrative sentence for the email body."""
    if aged_assets_pct is None:
        return (
            "No on-time-scanned assets were found — "
            "aged vulnerability asset percentage cannot be computed."
        )
    status_label = _STATUS_LABEL.get(status, status)
    return (
        f"{aged_assets_pct:.1f}% of on-time-scanned assets have aged vulnerabilities — "
        f"{aged_assets_count:,} of {total_on_time:,} assets carry at least one "
        f"Medium/High/Critical finding open >{_AGED_DAYS_THRESHOLD} days. "
        f"Status: {status_label}."
    )


def _row_bg(pct: float) -> str:
    """Light HTML background-color for a BU table row (lower-is-better)."""
    if pct <= _GREEN_THRESHOLD:
        return "#E8F5E9"
    if pct <= _YELLOW_THRESHOLD:
        return "#FFF8E1"
    return "#FFEBEE"


def _xl_fill(pct: float) -> PatternFill:
    """openpyxl PatternFill for an aged-% cell (lower-is-better)."""
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
