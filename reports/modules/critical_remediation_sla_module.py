"""
reports/modules/critical_remediation_sla_module.py — Critical Vulnerability Remediation SLA.

Measures the percentage of Critical vulnerabilities that were fixed within
their 15-day SLA during the last 30 days, scoped to assets that have been
scanned on time.

Module ID:    critical_remediation_sla
Display Name: Critical Vulnerability Remediation SLA (30-day window)

SLA thresholds (board-defined):
    Green:  remediation_sla_pct >= 95%
    Yellow: remediation_sla_pct >= 85%  and < 95%
    Red:    remediation_sla_pct <  85%

Data sources:
    vulns_df         — open / reopened findings (from fetch_all_vulnerabilities)
    fixed_vulns_df   — fixed findings (from fetch_fixed_vulnerabilities),
                       passed via **kwargs["fixed_vulns_df"] by the caller
    assets_df        — full asset inventory (from fetch_all_assets)

Fixed-vuln dependency
---------------------
This module needs BOTH open AND fixed vulnerability data.  The standard
``vulns_df`` parameter contains only open/reopened findings.  Fixed findings
must be supplied by the caller (board_summary.py) as a kwarg::

    composer = ReportComposer(
        vulns_df=open_vulns_df,
        assets_df=assets_df,
        report_date=report_date,
        module_configs=module_configs,
        fixed_vulns_df=fetch_fixed_vulnerabilities(tio, cache_dir),
    )

When ``fixed_vulns_df`` is absent or empty the metric returns ``"no_data"``.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from config import SLA_DAYS
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

_GREEN_THRESHOLD  = 95.0   # >= green
_YELLOW_THRESHOLD = 85.0   # >= yellow; < green
_DIRECTION        = "higher_is_better"

# Gauge colour zones: 0–85 red | 85–95 amber | 95–100 green
_GAUGE_THRESHOLDS = [
    (_YELLOW_THRESHOLD, "#d32f2f"),
    (_GREEN_THRESHOLD,  "#fbc02d"),
    (100.0,             "#388e3c"),
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

# Excel fills (openpyxl RGB, no leading #)
_FILL_GREEN  = PatternFill("solid", fgColor="C8E6C9")
_FILL_YELLOW = PatternFill("solid", fgColor="FFF9C4")
_FILL_RED    = PatternFill("solid", fgColor="FFCDD2")
_FILL_HEADER = PatternFill("solid", fgColor="1F3864")

# SLA for critical findings (days) — sourced from config.SLA_DAYS
_CRITICAL_SLA_DAYS: int = SLA_DAYS["critical"]   # 15


# ===========================================================================
# Module class
# ===========================================================================

@register_module
class CriticalRemediationSLAModule(BaseModule):
    """
    Percentage of Critical vulns fixed within their 15-day SLA in the last 30 days.

    Only findings on assets that were scanned on time (within the last 30 days)
    are included.  This ensures the denominator reflects a recently-validated
    asset population, not stale or decommissioned systems.

    Supported options
    -----------------
    None — this module accepts no configurable options.
    """

    MODULE_ID         = "critical_remediation_sla"
    DISPLAY_NAME      = "Critical Vulnerability Remediation SLA (30-day window)"
    DESCRIPTION       = (
        "Percentage of Critical vulnerabilities fixed within their 15-day SLA "
        "during the last 30 days, scoped to assets scanned on time."
    )
    REQUIRED_DATA     = ["vulns", "assets", "fixed_vulns"]
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
        Compute Critical remediation SLA compliance for the last 30 days.

        Parameters
        ----------
        vulns_df : pd.DataFrame
            Open / reopened findings from fetch_all_vulnerabilities().
            Used to compute ``total_open_last_month``.
        assets_df : pd.DataFrame
            Full asset inventory from fetch_all_assets().
            Used to derive the on-time asset set and BU labels.
        report_date : datetime
            UTC-aware report run timestamp.
        config : ModuleConfig
            Module configuration (no options consumed).
        **kwargs
            ``fixed_vulns_df`` (pd.DataFrame, optional): fixed findings from
            fetch_fixed_vulnerabilities().  Required for the primary metric.
            Returns ``"no_data"`` when absent or empty.

        Returns
        -------
        ModuleData
            ``error`` is None on success; set to an error string on failure.
        """
        logger.debug(
            "%s compute() — vulns_df=%d rows, assets_df=%d rows",
            self._log_prefix(), len(vulns_df), len(assets_df),
        )

        try:
            fixed_vulns_df: pd.DataFrame = kwargs.get(
                "fixed_vulns_df", pd.DataFrame()
            )

            # ---- Step 1: derive on-time asset set ----
            on_time, _ = identify_on_time_assets(assets_df, report_date)
            on_time_uuids = set(on_time["asset_uuid"].dropna())

            # ---- Step 2: build UTC-aware 30-day window ----
            if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
                rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
            else:
                rd_ts = pd.Timestamp(report_date, tz="UTC")
            thirty_days_ago = rd_ts - pd.Timedelta(days=ON_TIME_WINDOW_DAYS)

            # ---- Step 3: open critical findings on on-time assets ----
            open_crit = _filter_critical(vulns_df, on_time_uuids)
            total_open_last_month = len(open_crit)

            # ---- Step 4: fixed critical findings in the 30-day window ----
            fixed_crit_all = _filter_critical(fixed_vulns_df, on_time_uuids)

            if fixed_crit_all.empty:
                fixed_in_window = pd.DataFrame()
            else:
                state_upper = fixed_crit_all["state"].str.upper()
                lf_col      = fixed_crit_all["last_fixed"]
                fixed_mask  = (
                    (state_upper == "FIXED")
                    & lf_col.notna()
                    & (lf_col >= thirty_days_ago)
                )
                fixed_in_window = fixed_crit_all[fixed_mask].copy()

            total_fixed_last_month = len(fixed_in_window)

            # ---- Step 5: compute days_to_fix and count within-SLA ----
            if total_fixed_last_month == 0:
                remediation_sla_pct = None
                fixed_within_sla    = 0
                status              = "no_data"
                logger.debug(
                    "%s no critical findings fixed in the last 30 days "
                    "— returning no_data.",
                    self._log_prefix(),
                )
            else:
                fixed_in_window = fixed_in_window.copy()
                fixed_in_window.loc[:, "days_to_fix"] = fixed_in_window.apply(
                    _compute_days_to_fix, axis=1
                )

                within_sla_mask = (
                    fixed_in_window["days_to_fix"].notna()
                    & (fixed_in_window["days_to_fix"] <= _CRITICAL_SLA_DAYS)
                )
                fixed_within_sla    = int(within_sla_mask.sum())
                remediation_sla_pct = round(
                    fixed_within_sla / total_fixed_last_month * 100, 1
                )
                status = sla_status_from_thresholds(
                    remediation_sla_pct,
                    green_threshold  = _GREEN_THRESHOLD,
                    yellow_threshold = _YELLOW_THRESHOLD,
                    direction        = _DIRECTION,
                )

            # ---- Step 6: per-BU breakdown ----
            # Scope: fixed critical findings in last 30 days, per on-time-asset BU
            bu_breakdown = _compute_bu_breakdown(
                fixed_in_window, on_time, within_sla_mask
                if total_fixed_last_month > 0 else None
            )
            table_data = bu_breakdown.to_dict("records")

            # ---- Step 7: narrative summary ----
            summary_text = _build_summary(
                remediation_sla_pct, total_fixed_last_month,
                fixed_within_sla, total_open_last_month, status,
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
                    "remediation_sla_pct":    remediation_sla_pct,
                    "total_open_last_month":  total_open_last_month,
                    "total_fixed_last_month": total_fixed_last_month,
                    "fixed_within_sla":       fixed_within_sla,
                    "status":                 status,
                },
                table_data   = table_data,
                chart_data   = {
                    "value":      remediation_sla_pct,
                    "thresholds": {
                        "green":  _GREEN_THRESHOLD,
                        "yellow": _YELLOW_THRESHOLD,
                    },
                    "direction":  _DIRECTION,
                    "top_5":      bu_breakdown.head(5).to_dict("records"),
                },
                summary_text = summary_text,
                metadata     = {
                    "window":            f"Last {ON_TIME_WINDOW_DAYS} days from report_date",
                    "critical_sla_days": _CRITICAL_SLA_DAYS,
                    "sla_source":        (
                        "Board-defined thresholds "
                        f"(Green ≥{_GREEN_THRESHOLD}%, "
                        f"Amber ≥{_YELLOW_THRESHOLD}%, Red <{_YELLOW_THRESHOLD}%)"
                    ),
                    "on_time_scope": (
                        "Only findings on assets with last_licensed_scan_date "
                        f">= report_date − {ON_TIME_WINDOW_DAYS} days are included."
                    ),
                    "days_to_fix_source": (
                        "time_taken_to_fix / 86400 when available; "
                        "fallback: (last_fixed − first_found).days"
                    ),
                    "computed_at": computed_at,
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

        Layout:
        1. Section heading
        2. Gauge (centred) with 95 / 85 colour zones
        3. Status badge
        4. Three bold support numbers: Open Last Month | Fixed Last Month | Fixed in SLA
        5. Top-5 worst-performing BUs table
        6. Explanatory paragraph
        """
        if data.error:
            return (
                f'<div class="error-box">'
                f"<strong>{self.DISPLAY_NAME}</strong>: {data.error}"
                f"</div>"
            )

        m                    = data.metrics
        sla_pct              = m.get("remediation_sla_pct")
        total_open           = m.get("total_open_last_month", 0)
        total_fixed          = m.get("total_fixed_last_month", 0)
        fixed_within_sla     = m.get("fixed_within_sla", 0)
        status               = m.get("status", "no_data")

        # ---- Gauge ----
        gauge_value = sla_pct if sla_pct is not None else 0.0
        try:
            gauge_b64  = draw_gauge(
                value      = gauge_value,
                min_val    = 0,
                max_val    = 100,
                thresholds = _GAUGE_THRESHOLDS,
                title      = "Critical Remediation SLA %",
                unit       = "%",
                figsize    = (5, 3),
            )
            gauge_html = (
                f'<div style="text-align:center; margin-bottom:4mm;">'
                f'<img src="data:image/png;base64,{gauge_b64}" '
                f'style="width:46%; max-width:320px;" '
                f'alt="Critical Remediation SLA gauge">'
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
            f"{sla_pct:.1f}%" if sla_pct is not None else "N/A"
        )
        status_html = (
            f'<p style="text-align:center; font-size:10pt; font-weight:bold; '
            f'color:{status_color}; margin:0 0 5mm 0;">'
            f'SLA Compliance: {pct_display} &nbsp;&middot;&nbsp; {status_label}'
            f'</p>'
        )

        # ---- Three support numbers ----
        support_html = f"""
<table style="width:65%; margin:0 auto 6mm auto; border-collapse:collapse;">
  <tr>
    <td style="text-align:center; padding:2mm 5mm;
               border-right:0.5pt solid #ddd; vertical-align:middle;">
      <span style="font-size:13pt; font-weight:bold; color:#555;">{total_open:,}</span>
      <br><span style="font-size:7pt; color:#777;">Open Last Month</span>
    </td>
    <td style="text-align:center; padding:2mm 5mm;
               border-right:0.5pt solid #ddd; vertical-align:middle;">
      <span style="font-size:13pt; font-weight:bold; color:#1F3864;">{total_fixed:,}</span>
      <br><span style="font-size:7pt; color:#777;">Fixed Last Month</span>
    </td>
    <td style="text-align:center; padding:2mm 5mm; vertical-align:middle;">
      <span style="font-size:13pt; font-weight:bold;
             color:{status_color};">{fixed_within_sla:,}</span>
      <br><span style="font-size:7pt; color:#777;">Fixed within SLA (≤{_CRITICAL_SLA_DAYS}d)</span>
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
                row_bg  = _row_bg(bu_pct, _GREEN_THRESHOLD, _YELLOW_THRESHOLD)
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
      <th style="text-align:right;">Fixed in SLA</th>
      <th style="text-align:right;">Fixed (30d)</th>
      <th style="text-align:right;">SLA Compliance %</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>"""
        else:
            bu_table_html = (
                '<p class="explanatory-text" style="color:#888; font-style:italic;">'
                'No business-unit breakdown available '
                '(no critical findings fixed in the last 30 days, or '
                'assets lack Application tags).'
                '</p>'
            )

        # ---- Explanatory paragraph ----
        explain_html = f"""
<p class="explanatory-text">
  <strong>What this measures:</strong> Of Critical vulnerabilities (VPR 9.0&ndash;10.0)
  that were fixed in the last 30 days on assets scanned on time, what percentage were
  remediated within the {_CRITICAL_SLA_DAYS}-day SLA?  Only assets with a licensed scan
  in the last {ON_TIME_WINDOW_DAYS} days are in scope — this prevents stale assets from
  inflating the denominator.  Board target is &ge;{_GREEN_THRESHOLD:.0f}% (green).
  &ge;{_YELLOW_THRESHOLD:.0f}% is at-risk (amber).  Below {_YELLOW_THRESHOLD:.0f}% is
  off-target (red).
  <em>Note: this metric approximates "open during the window" using fixed-finding data
  combined with still-open findings; see the calculations document for detail.</em>
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
        Write the "Critical Remediation SLA" tab into ``workbook``.

        Returns
        -------
        list[str]
            ``["Critical Remediation SLA"]`` on success, ``[]`` on error.
        """
        tab_name = "Critical Remediation SLA"
        try:
            ws = workbook.create_sheet(tab_name)

            if data.error:
                ws["A1"] = "Error"
                ws["B1"] = data.error
                return [tab_name]

            m                = data.metrics
            sla_pct          = m.get("remediation_sla_pct")
            total_open       = m.get("total_open_last_month", 0)
            total_fixed      = m.get("total_fixed_last_month", 0)
            fixed_within_sla = m.get("fixed_within_sla", 0)
            status           = m.get("status", "no_data")

            # ---- Overall KPI block ----
            _xl_title(ws, "A1", "Critical Vulnerability Remediation SLA — 30-Day Window")

            status_color_hex = _STATUS_COLOR.get(status, "#757575").lstrip("#")
            pct_str = (
                f"{sla_pct:.1f}%" if sla_pct is not None else "N/A"
            )

            _xl_kv(ws, 3, "SLA Compliance (30d):", pct_str,
                   value_font=Font(bold=True, size=12, color=status_color_hex))
            _xl_kv(ws, 4, "Status:",
                   _STATUS_LABEL.get(status, status),
                   value_font=Font(bold=True, color=status_color_hex))
            _xl_kv(ws, 5, "Open Last Month (Critical):", f"{total_open:,}")
            _xl_kv(ws, 6, "Fixed Last Month (Critical):", f"{total_fixed:,}")
            _xl_kv(ws, 7, f"Fixed within SLA (≤{_CRITICAL_SLA_DAYS}d):",
                   f"{fixed_within_sla:,}")
            _xl_kv(ws, 8, "Window:",
                   f"Last {ON_TIME_WINDOW_DAYS} days (last_fixed >= report_date − 30d)")
            _xl_kv(ws, 9, "SLA Thresholds:",
                   f"Green ≥{_GREEN_THRESHOLD:.0f}%  |  "
                   f"Amber ≥{_YELLOW_THRESHOLD:.0f}%  |  "
                   f"Red <{_YELLOW_THRESHOLD:.0f}%")
            _xl_kv(ws, 10, "Scope:",
                   "Assets with last_licensed_scan_date within last 30 days only")

            # ---- BU breakdown table ----
            header_row = 12
            headers = [
                "Business Unit", "Fixed in SLA", "Fixed (30d)", "SLA Compliance %"
            ]
            for col_idx, header in enumerate(headers, start=1):
                cell           = ws.cell(row=header_row, column=col_idx, value=header)
                cell.font      = Font(bold=True, color="FFFFFF")
                cell.fill      = _FILL_HEADER
                cell.alignment = Alignment(horizontal="center")

            for row_offset, row in enumerate(data.table_data or [], start=1):
                data_row = header_row + row_offset
                bu_pct   = float(row.get("percentage",  0.0))
                bu_fill  = _xl_fill(bu_pct, _GREEN_THRESHOLD, _YELLOW_THRESHOLD)

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
            ws.column_dimensions[get_column_letter(2)].width = 16
            ws.column_dimensions[get_column_letter(3)].width = 14
            ws.column_dimensions[get_column_letter(4)].width = 20

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
            Keys: "Crit Remediation SLA", "Crit Fixed (30d)", "Crit Fixed in SLA".
        """
        if "email" not in self.SUPPORTED_OUTPUTS or data.error:
            return {}
        m   = data.metrics
        pct = m.get("remediation_sla_pct")
        return {
            "Crit Remediation SLA": f"{pct:.1f}%" if pct is not None else "N/A",
            "Crit Fixed (30d)":     f"{m.get('total_fixed_last_month', 0):,}",
            "Crit Fixed in SLA":    f"{m.get('fixed_within_sla', 0):,}",
        }

    # ------------------------------------------------------------------
    # get_audit_info()
    # ------------------------------------------------------------------

    def get_audit_info(self) -> dict:
        """Return calculation documentation for audit and runbook records."""
        return {
            **super().get_audit_info(),
            "calculations": {
                "remediation_sla_pct": (
                    "fixed_within_sla / total_fixed_last_month × 100, "
                    "rounded to 1 decimal. "
                    "None when total_fixed_last_month == 0 (status → 'no_data')."
                ),
                "total_open_last_month": (
                    "Count of critical open/reopened findings on on-time assets. "
                    "Represents findings that were open at the start of the window."
                ),
                "total_fixed_last_month": (
                    f"Count of critical findings where state == 'FIXED' AND "
                    f"last_fixed >= report_date − {ON_TIME_WINDOW_DAYS} days, "
                    "on on-time assets."
                ),
                "fixed_within_sla": (
                    f"Subset of total_fixed_last_month where "
                    f"days_to_fix <= {_CRITICAL_SLA_DAYS} (Critical SLA). "
                    "days_to_fix = time_taken_to_fix / 86400 when available; "
                    "fallback: (last_fixed − first_found).days."
                ),
                "on_time_scope": (
                    f"last_licensed_scan_date IS NOT NULL AND "
                    f">= report_date − {ON_TIME_WINDOW_DAYS} days. "
                    "Applied to assets_df BEFORE filtering findings."
                ),
                "BU_breakdown": (
                    "compute_per_bu_breakdown(higher_is_better=True) via _compute_bu_breakdown(). "
                    "Per-BU: numerator = fixed within SLA; denominator = total fixed in last 30 days. "
                    "BU derived from Application tag on on-time assets. "
                    "affected = denominator − numerator (criticals NOT fixed within SLA). "
                    "Primary sort: affected DESC (most missed-SLA criticals first). "
                    "Secondary sort: percentage ASC (worst compliance % among ties)."
                ),
            },
        }


# ===========================================================================
# Module-private helpers
# ===========================================================================

def _filter_critical(
    df: pd.DataFrame,
    on_time_uuids: set,
) -> pd.DataFrame:
    """
    Return rows from ``df`` that are on an on-time asset and are Critical severity.

    Assumes ``df.severity`` is already VPR-derived (as produced by fetchers.py).
    Returns an empty DataFrame if ``df`` is empty or lacks required columns.
    """
    if df.empty:
        return df.copy()

    if "asset_uuid" not in df.columns or "severity" not in df.columns:
        return pd.DataFrame()

    mask = (
        df["asset_uuid"].isin(on_time_uuids)
        & (df["severity"].str.lower() == "critical")
    )
    return df[mask].copy()


def _compute_days_to_fix(row: pd.Series) -> float | None:
    """
    Compute the number of days between first_found and last_fixed for a finding.

    Strategy:
    1. Use ``time_taken_to_fix`` (seconds) ÷ 86400 when the field is available
       and non-null (this is Tenable's own calculated field — most accurate).
    2. Fallback: ``(last_fixed − first_found).days`` when both dates are present.
    3. Return None when neither source is available.
    """
    ttf = row.get("time_taken_to_fix")
    if ttf is not None and not pd.isna(ttf):
        try:
            return float(ttf) / 86400.0
        except (TypeError, ValueError):
            pass

    lf = row.get("last_fixed")
    ff = row.get("first_found")
    if pd.notna(lf) and pd.notna(ff):
        try:
            delta = lf - ff
            return float(delta.days)
        except (TypeError, AttributeError):
            pass

    return None


def _compute_bu_breakdown(
    fixed_in_window:  pd.DataFrame,
    on_time_assets:   pd.DataFrame,
    within_sla_mask:  "pd.Series[bool] | None",
) -> pd.DataFrame:
    """
    Build per-BU breakdown for the remediation SLA metric.

    Maps each finding in ``fixed_in_window`` to its asset's business unit
    using the on_time_assets enriched with the Application tag.

    Returns an empty DataFrame if ``fixed_in_window`` is empty.
    """
    if fixed_in_window.empty:
        return pd.DataFrame(
            columns=["business_unit", "numerator", "denominator", "percentage", "affected"]
        )

    # Enrich on-time assets with BU labels
    enriched_assets = extract_business_unit(on_time_assets)
    uuid_to_bu      = dict(
        zip(enriched_assets["asset_uuid"], enriched_assets["business_unit"])
    )

    fw = fixed_in_window.copy()
    fw.loc[:, "business_unit"] = (
        fw["asset_uuid"].map(uuid_to_bu).fillna("Untagged")
    )

    # within_sla_mask is aligned with fixed_in_window.index
    if within_sla_mask is None:
        within_sla_mask = pd.Series(False, index=fw.index)

    denom_mask = pd.Series(True, index=fw.index)

    return compute_per_bu_breakdown(fw, within_sla_mask, denom_mask, higher_is_better=True)


def _build_summary(
    sla_pct:             float | None,
    total_fixed:         int,
    fixed_within_sla:    int,
    total_open:          int,
    status:              str,
) -> str:
    """Build a plain-language narrative sentence for the email body."""
    if sla_pct is None:
        if total_open == 0:
            return (
                "No Critical vulnerabilities were found on on-time-scanned assets — "
                "remediation SLA compliance cannot be computed."
            )
        return (
            f"There are {total_open:,} open Critical findings on assets scanned on time, "
            "but none were fixed in the last 30 days — "
            "remediation SLA compliance cannot be computed."
        )

    status_label = _STATUS_LABEL.get(status, status)
    return (
        f"Critical remediation SLA compliance is {sla_pct:.1f}% — "
        f"{fixed_within_sla:,} of {total_fixed:,} Critical vulnerabilities fixed "
        f"in the last 30 days were remediated within the {_CRITICAL_SLA_DAYS}-day SLA. "
        f"Status: {status_label}."
    )


def _row_bg(pct: float, green_threshold: float, yellow_threshold: float) -> str:
    """Light HTML background colour for a BU table row (higher-is-better)."""
    if pct >= green_threshold:
        return "#E8F5E9"
    if pct >= yellow_threshold:
        return "#FFF8E1"
    return "#FFEBEE"


def _xl_fill(
    pct: float,
    green_threshold: float,
    yellow_threshold: float,
) -> PatternFill:
    """openpyxl PatternFill for a SLA-% cell (higher-is-better)."""
    if pct >= green_threshold:
        return _FILL_GREEN
    if pct >= yellow_threshold:
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
