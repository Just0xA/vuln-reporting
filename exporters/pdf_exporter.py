"""
exporters/pdf_exporter.py — PDF report generation via WeasyPrint.

Produces a professional, print-ready PDF with:
  - Cover page (report title, scope, generation timestamp, SLA reference table)
  - Consistent page header (title + scope) and footer (page number + timestamp)
  - Inline Matplotlib .png chart embedding (base64 data URI)
  - Sections built from a list of dicts: {heading, dataframe, text, chart_png_path}
  - Clean styling: no heavy backgrounds in body; color used only for accents and severity

Exported API
------------
build_pdf()                — assemble and render a complete report PDF
render_sla_reference_table() — HTML snippet for the SLA table (used in emails too)
render_vpr_reference_table() — HTML snippet for the VPR score ranges table
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from config import (
    SLA_DAYS,
    SEVERITY_LABELS,
    SEVERITY_FILL_COLORS,
    VPR_SEVERITY_MAP,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Color constants mirrored for inline CSS (no imports at template render time)
# ---------------------------------------------------------------------------
_ACCENT       = "#1F3864"   # dark navy — headers, accents
_ACCENT_LIGHT = "#E8EAF6"   # very light indigo — alternate table rows
_TEXT         = "#212121"   # near-black body text
_MUTED        = "#757575"   # secondary text / footer
_BORDER       = "#DDDFE2"   # table borders
_WHITE        = "#FFFFFF"

_SEV_COLORS: dict[str, str] = {
    "critical": "#d32f2f",
    "high":     "#f57c00",
    "medium":   "#fbc02d",
    "low":      "#388e3c",
    "info":     "#1976d2",
}
_SEV_BG: dict[str, str] = {
    "critical": "#FFCDD2",
    "high":     "#FFE0B2",
    "medium":   "#FFF9C4",
    "low":      "#C8E6C9",
    "info":     "#BBDEFB",
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _encode_image(png_path: str | Path) -> str:
    """Return a base64 data URI for a PNG file."""
    with open(png_path, "rb") as fh:
        encoded = base64.b64encode(fh.read()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _html_escape(text: str) -> str:
    """Minimal HTML escaping for user-supplied strings."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _df_to_html_table(df: pd.DataFrame, severity_col: Optional[str] = "severity") -> str:
    """
    Convert a DataFrame to a styled HTML table string.

    Applies severity-based background colors to the *severity_col* column
    and alternating row fills for readability.
    """
    col_style = (
        f"font-family: Arial, sans-serif; font-size: 9pt; color: {_TEXT}; "
        f"border: 1px solid {_BORDER}; padding: 4px 6px; "
        "vertical-align: middle; white-space: nowrap;"
    )
    header_style = (
        f"font-family: Arial, sans-serif; font-size: 9pt; font-weight: bold; "
        f"color: {_WHITE}; background-color: {_ACCENT}; "
        f"border: 1px solid {_BORDER}; padding: 5px 7px; text-align: left;"
    )
    alt_fill = _ACCENT_LIGHT

    # Coerce datetimes to strings
    df = df.copy()
    for col in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            df[col] = df[col].dt.strftime("%Y-%m-%d").fillna("")

    lines: list[str] = [
        f'<table style="border-collapse: collapse; width: 100%; margin: 8px 0;">'
    ]
    # Header row
    lines.append("<thead><tr>")
    for col in df.columns:
        lines.append(f'<th style="{header_style}">{_html_escape(col)}</th>')
    lines.append("</tr></thead>")

    # Data rows
    lines.append("<tbody>")
    for i, (_, row) in enumerate(df.iterrows()):
        row_bg = alt_fill if i % 2 == 0 else _WHITE
        lines.append(f'<tr style="background-color: {row_bg};">')
        for col in df.columns:
            val = row[col]
            cell_style = col_style
            # Severity-colored cell
            if severity_col and col.lower() == severity_col.lower():
                sev_key = str(val).lower()
                bg = _SEV_BG.get(sev_key, row_bg)
                fg = _SEV_COLORS.get(sev_key, _TEXT)
                cell_style = (
                    f"font-family: Arial, sans-serif; font-size: 9pt; "
                    f"font-weight: bold; color: {fg}; background-color: {bg}; "
                    f"border: 1px solid {_BORDER}; padding: 4px 6px; "
                    "vertical-align: middle; white-space: nowrap;"
                )
            display_val = _html_escape("" if pd.isna(val) else val)
            lines.append(f'<td style="{cell_style}">{display_val}</td>')
        lines.append("</tr>")
    lines.append("</tbody></table>")

    return "\n".join(lines)


# ===========================================================================
# Public reference table helpers (also consumed by email_template.py)
# ===========================================================================

def render_sla_reference_table(inline_css: bool = True) -> str:
    """
    Return an HTML table of SLA definitions (Severity → SLA days).

    Parameters
    ----------
    inline_css : bool
        Always True for email/PDF use.  Kept as a parameter for future
        templating flexibility.

    Returns
    -------
    str
        Self-contained HTML table string, safe to embed in any HTML document.
    """
    header_style = (
        f"font-family: Arial, sans-serif; font-size: 9pt; font-weight: bold; "
        f"color: {_WHITE}; background-color: {_ACCENT}; "
        f"border: 1px solid {_BORDER}; padding: 5px 10px; text-align: left;"
    )
    cell_style = (
        f"font-family: Arial, sans-serif; font-size: 9pt; color: {_TEXT}; "
        f"border: 1px solid {_BORDER}; padding: 4px 10px; vertical-align: middle;"
    )

    rows = ""
    for i, (sev, days) in enumerate(SLA_DAYS.items()):
        row_bg = _ACCENT_LIGHT if i % 2 == 0 else _WHITE
        sev_bg  = _SEV_BG.get(sev, row_bg)
        sev_fg  = _SEV_COLORS.get(sev, _TEXT)
        label   = SEVERITY_LABELS.get(sev, sev.title())
        rows += (
            f'<tr style="background-color: {row_bg};">'
            f'<td style="{cell_style} font-weight: bold; color: {sev_fg}; '
            f'background-color: {sev_bg};">{label}</td>'
            f'<td style="{cell_style}">{days} days</td>'
            f"</tr>\n"
        )

    return (
        f'<table style="border-collapse: collapse; width: 100%; margin: 8px 0;">'
        f"<thead><tr>"
        f'<th style="{header_style}">Severity</th>'
        f'<th style="{header_style}">SLA (Days to Remediate)</th>'
        f"</tr></thead>"
        f"<tbody>{rows}</tbody>"
        f"</table>"
    )


def render_vpr_reference_table() -> str:
    """
    Return an HTML table of VPR score → severity tier mappings.

    Returns
    -------
    str
        Self-contained HTML table string.
    """
    header_style = (
        f"font-family: Arial, sans-serif; font-size: 9pt; font-weight: bold; "
        f"color: {_WHITE}; background-color: {_ACCENT}; "
        f"border: 1px solid {_BORDER}; padding: 5px 10px; text-align: left;"
    )
    cell_style = (
        f"font-family: Arial, sans-serif; font-size: 9pt; color: {_TEXT}; "
        f"border: 1px solid {_BORDER}; padding: 4px 10px; vertical-align: middle;"
    )

    rows = ""
    for i, (lo, hi, label) in enumerate(VPR_SEVERITY_MAP):
        row_bg = _ACCENT_LIGHT if i % 2 == 0 else _WHITE
        sev_bg = _SEV_BG.get(label, row_bg)
        sev_fg = _SEV_COLORS.get(label, _TEXT)
        lbl    = SEVERITY_LABELS.get(label, label.title())
        rows += (
            f'<tr style="background-color: {row_bg};">'
            f'<td style="{cell_style} font-weight: bold; color: {sev_fg}; '
            f'background-color: {sev_bg};">{lbl}</td>'
            f'<td style="{cell_style}">{lo} – {hi}</td>'
            f"</tr>\n"
        )

    return (
        f'<table style="border-collapse: collapse; width: 100%; margin: 8px 0;">'
        f"<thead><tr>"
        f'<th style="{header_style}">Severity</th>'
        f'<th style="{header_style}">VPR Score Range</th>'
        f"</tr></thead>"
        f"<tbody>{rows}</tbody>"
        f"</table>"
    )


# ===========================================================================
# Core HTML builder
# ===========================================================================

def _build_html(
    report_title: str,
    scope_str: str,
    sections: list[dict],
    generated_at: datetime,
) -> str:
    """
    Render the full report as an HTML string ready for WeasyPrint.

    Each section dict may contain:
        heading         : str           — section heading (required)
        dataframe       : pd.DataFrame  — rendered as HTML table
        text            : str           — paragraph text (raw HTML allowed)
        chart_png_path  : str | Path    — embedded as base64 PNG image
        severity_col    : str           — column to apply severity coloring
                                          (default "severity")
    """
    ts = generated_at.strftime("%Y-%m-%d %H:%M UTC")

    # ------------------------------------------------------------------
    # Page CSS (WeasyPrint supports @page, which Outlook cannot — safe here)
    # ------------------------------------------------------------------
    css = f"""
    @page {{
        size: A4;
        margin: 18mm 15mm 20mm 15mm;
        @top-center {{
            content: "{_html_escape(report_title)} — {_html_escape(scope_str)}";
            font-family: Arial, sans-serif;
            font-size: 8pt;
            color: {_MUTED};
            border-bottom: 1px solid {_BORDER};
            padding-bottom: 3px;
        }}
        @bottom-center {{
            content: "Page " counter(page) " of " counter(pages)
                     "  |  Generated: {ts}";
            font-family: Arial, sans-serif;
            font-size: 8pt;
            color: {_MUTED};
            border-top: 1px solid {_BORDER};
            padding-top: 3px;
        }}
    }}
    @page :first {{
        @top-center {{ content: ""; border: none; }}
        @bottom-center {{ content: ""; border: none; }}
    }}
    body {{
        font-family: Arial, sans-serif;
        font-size: 10pt;
        color: {_TEXT};
        margin: 0;
        padding: 0;
        line-height: 1.5;
    }}
    h1 {{ font-size: 22pt; color: {_ACCENT}; margin: 0 0 8px 0; }}
    h2 {{ font-size: 16pt; color: {_ACCENT}; margin: 18px 0 6px 0;
          border-bottom: 2px solid {_ACCENT}; padding-bottom: 4px; }}
    h3 {{ font-size: 12pt; color: {_ACCENT}; margin: 14px 0 4px 0; }}
    p  {{ margin: 4px 0 10px 0; }}
    img {{ max-width: 100%; height: auto; display: block; margin: 10px auto; }}
    .cover-page {{
        min-height: 240mm;
        display: flex;
        flex-direction: column;
        justify-content: center;
        page-break-after: always;
    }}
    .scope-banner {{
        background-color: {_ACCENT_LIGHT};
        border-left: 4px solid {_ACCENT};
        padding: 8px 12px;
        font-size: 10pt;
        color: {_ACCENT};
        margin: 12px 0;
        font-weight: bold;
    }}
    .section {{ page-break-inside: avoid; margin-bottom: 18px; }}
    .chart-container {{ text-align: center; margin: 12px 0; }}
    .meta-label {{ font-weight: bold; color: {_MUTED}; font-size: 9pt; }}
    .meta-value {{ font-size: 10pt; }}
    .ref-heading {{
        font-size: 11pt;
        font-weight: bold;
        color: {_ACCENT};
        margin: 14px 0 4px 0;
    }}
    """

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------
    cover = f"""
    <div class="cover-page">
        <h1>{_html_escape(report_title)}</h1>
        <div class="scope-banner">&#128269; Scope: {_html_escape(scope_str)}</div>
        <table style="margin: 12px 0; border-collapse: collapse;">
            <tr>
                <td style="width: 160px;" class="meta-label">Generated (UTC)</td>
                <td class="meta-value">{ts}</td>
            </tr>
        </table>

        <p class="ref-heading">SLA Definitions</p>
        {render_sla_reference_table()}

        <p class="ref-heading">VPR Severity Score Ranges</p>
        {render_vpr_reference_table()}
    </div>
    """

    # ------------------------------------------------------------------
    # Body sections
    # ------------------------------------------------------------------
    body_parts: list[str] = []
    for section in sections:
        heading         = section.get("heading", "")
        df              = section.get("dataframe")
        text            = section.get("text")
        chart_png_path  = section.get("chart_png_path")
        sev_col         = section.get("severity_col", "severity")

        parts: list[str] = [f'<div class="section">']
        if heading:
            parts.append(f"<h2>{_html_escape(heading)}</h2>")

        if text:
            # text may already contain HTML markup — pass through
            parts.append(f"<p>{text}</p>")

        if chart_png_path:
            try:
                img_uri = _encode_image(chart_png_path)
                parts.append(
                    f'<div class="chart-container">'
                    f'<img src="{img_uri}" alt="{_html_escape(heading)} chart" />'
                    f"</div>"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not embed chart %s: %s", chart_png_path, exc)

        if df is not None and not df.empty:
            max_rows_inline = 500  # avoid multi-thousand row tables in PDF
            if len(df) > max_rows_inline:
                parts.append(
                    f"<p><em>Table truncated to {max_rows_inline} rows. "
                    f"Full data available in the Excel attachment.</em></p>"
                )
                df = df.head(max_rows_inline)
            parts.append(_df_to_html_table(df, severity_col=sev_col))

        parts.append("</div>")
        body_parts.append("\n".join(parts))

    body_html = "\n".join(body_parts)

    # ------------------------------------------------------------------
    # Full document
    # ------------------------------------------------------------------
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
{css}
</style>
</head>
<body>
{cover}
{body_html}
</body>
</html>"""


# ===========================================================================
# Public entry point
# ===========================================================================

def build_pdf(
    report_title: str,
    scope_str: str,
    sections: list[dict],
    output_path: str | Path,
    generated_at: Optional[datetime] = None,
) -> Path:
    """
    Render a complete report PDF from a list of section descriptors.

    Parameters
    ----------
    report_title : str
        Appears on the cover page, page headers, and filename.
    scope_str : str
        Tag filter description shown in the cover scope banner and page header,
        e.g. "Environment = Production" or "All Assets".
    sections : list[dict]
        Ordered list of report sections.  Each dict may contain:

        .. code-block:: python

            {
                "heading": "SLA Summary",          # section heading (str)
                "dataframe": df,                   # pd.DataFrame or None
                "text": "<p>Some context.</p>",    # HTML-safe text or None
                "chart_png_path": "/path/chart.png",  # or None
                "severity_col": "severity",        # col to color (default "severity")
            }

    output_path : str or Path
        Destination .pdf file path.
    generated_at : datetime, optional
        Defaults to UTC now.

    Returns
    -------
    Path
        Absolute path of the written PDF.

    Raises
    ------
    RuntimeError
        If WeasyPrint fails to render the document.
    """
    try:
        from weasyprint import HTML, CSS
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint is not installed.  Run: pip install weasyprint"
        ) from exc

    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Building PDF: %s (%d section(s))", output_path.name, len(sections))

    html_str = _build_html(report_title, scope_str, sections, generated_at)

    try:
        HTML(string=html_str, base_url=str(output_path.parent)).write_pdf(str(output_path))
    except Exception as exc:
        logger.error("WeasyPrint render failed for %s: %s", output_path, exc)
        raise RuntimeError(f"PDF generation failed: {exc}") from exc

    logger.info("PDF written: %s", output_path)
    return output_path.resolve()


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from config import OUTPUT_DIR

    out = OUTPUT_DIR / "pdf_test"
    out.mkdir(parents=True, exist_ok=True)

    sample_df = pd.DataFrame({
        "asset_hostname": ["web-01.corp", "db-02.corp", "app-03.corp"],
        "severity":       ["critical",    "high",       "medium"],
        "plugin_name":    ["OpenSSL RCE", "Log4j",      "PHP XSS"],
        "days_open":      [20,            35,           60],
        "sla_status":     ["Overdue",     "Overdue",    "Within SLA"],
    })

    path = build_pdf(
        report_title="SLA Remediation Report",
        scope_str="Environment = Production",
        sections=[
            {
                "heading": "Open Vulnerability SLA Status",
                "text": "The table below lists all open vulnerabilities with their current SLA status.",
                "dataframe": sample_df,
            },
        ],
        output_path=out / "test_report.pdf",
    )
    print(f"Written: {path}")

    # Also verify standalone reference tables
    print("\n--- SLA Reference Table (HTML) ---")
    print(render_sla_reference_table()[:300], "…")
    print("\n--- VPR Reference Table (HTML) ---")
    print(render_vpr_reference_table()[:300], "…")
