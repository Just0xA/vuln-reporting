"""
delivery/email_template.py — Jinja2 email body renderer.

Loads templates/report_email.html and renders it with the data produced by
a group delivery run.  All metric extraction has safe fallbacks so the email
is always renderable even when a specific report was not run for the group.

Public API
----------
build_email_body()    Render the full HTML email body string.
build_kpi_metrics()   Extract 4–5 KPI tiles from report_outputs.
build_sla_table()     Build SLA / VPR reference rows from config.py constants.

Report outputs dict schema (as returned by each run_report()):
    {
        "report_slug": {
            "pdf":     Path,
            "excel":   Path,
            "charts":  [Path, ...],
            "metrics": {...}   # optional — injected by run_all.py if available
        },
        ...
    }
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys_path_patched = False
try:
    from config import ROOT_DIR, SLA_DAYS, SEVERITY_LABELS, VPR_SEVERITY_MAP
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from config import ROOT_DIR, SLA_DAYS, SEVERITY_LABELS, VPR_SEVERITY_MAP
    sys_path_patched = True

if not sys_path_patched:
    import sys
    if str(Path(__file__).resolve().parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Jinja2 environment — points to the project's templates/ directory
# ---------------------------------------------------------------------------
_TEMPLATES_DIR = ROOT_DIR / "templates"

_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

# ---------------------------------------------------------------------------
# Severity color map for KPI tile values and SLA table cells
# ---------------------------------------------------------------------------
_SEV_COLOR: dict[str, str] = {
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

# Report slug → human description (used in the attached reports list)
_REPORT_DESCRIPTIONS: dict[str, str] = {
    "executive_kpi":    "Executive KPI dashboard — severity counts, SLA compliance, top riskiest assets",
    "sla_remediation":  "SLA & remediation tracking — per-vulnerability status, overdue detail, breach trend",
    "asset_risk":       "Asset risk scoring — risk score rankings, distribution histogram, tag group averages",
    "patch_compliance": "Patch compliance — vulnerability age buckets, oldest unpatched vulns, per-tag compliance",
    "trend_analysis":   "Trend analysis — monthly open vuln trend, MTTR trend, SLA compliance over time",
    "plugin_cve":       "Plugin / CVE breakdown — top plugins, top CVEs, exploitable vulns, CVSS distribution",
}


# ===========================================================================
# KPI metric extraction
# ===========================================================================

def build_kpi_metrics(
    report_outputs: dict,
    group_config: dict,
) -> list[dict]:
    """
    Build the list of KPI tile dicts for the email template.

    Attempts to extract four key metrics from whichever reports were run:
        1. Total Criticals open
        2. % Critical / High within SLA (combined)
        3. Count of overdue Critical + High
        4. Overall MTTR (or avg age of open critical vulns as proxy)

    All metrics degrade gracefully to ``"N/A"`` if the relevant report was
    not run for this group or did not return a ``"metrics"`` payload.

    Parameters
    ----------
    report_outputs : dict
        ``{report_slug: {pdf, excel, charts, metrics?}}``
    group_config : dict
        The group's entry from delivery_config.yaml (used for context only).

    Returns
    -------
    list[dict]
        Each dict: ``{label, value, color, sub_label?}``
    """

    def _metrics_from(slug: str) -> dict:
        """Return the metrics sub-dict for a slug, or empty dict."""
        output = report_outputs.get(slug, {})
        return output.get("metrics", {}) if isinstance(output, dict) else {}

    # Prefer executive_kpi metrics; fall back to sla_remediation for SLA fields
    exec_m = _metrics_from("executive_kpi")
    sla_m  = _metrics_from("sla_remediation")

    # ------------------------------------------------------------------
    # Metric 1: Total Criticals open
    # ------------------------------------------------------------------
    total_crit = _safe_get(exec_m, "sev_counts", "critical") or \
                 _safe_get(sla_m,  "sev_summary_by_sev", "critical", "Open")
    tile_crit = {
        "label": "Open Criticals",
        "value": f"{int(total_crit):,}" if total_crit is not None else "N/A",
        "color": _SEV_COLOR["critical"],
    }

    # ------------------------------------------------------------------
    # Metric 2: % Critical + High within SLA (average of the two rates)
    # ------------------------------------------------------------------
    comp_crit = _safe_get(exec_m, "compliance", "critical")
    comp_high = _safe_get(exec_m, "compliance", "high")
    if comp_crit is not None and comp_high is not None:
        combined_sla = (comp_crit + comp_high) / 2
        sla_str      = f"{combined_sla * 100:.1f}%"
        sla_color    = _SEV_COLOR["low"] if combined_sla >= 0.8 else \
                       _SEV_COLOR["medium"] if combined_sla >= 0.6 else \
                       _SEV_COLOR["critical"]
    else:
        sla_str   = "N/A"
        sla_color = "#757575"

    tile_sla = {
        "label":     "Critical + High Within SLA",
        "value":     sla_str,
        "color":     sla_color,
        "sub_label": "combined average",
    }

    # ------------------------------------------------------------------
    # Metric 3: Overdue Critical + High combined count
    # ------------------------------------------------------------------
    od_crit = _safe_get(exec_m, "overdue", "critical") or 0
    od_high = _safe_get(exec_m, "overdue", "high")     or 0
    if od_crit is not None and od_high is not None:
        od_total   = int(od_crit) + int(od_high)
        od_str     = f"{od_total:,}"
        od_color   = _SEV_COLOR["critical"] if od_total > 0 else _SEV_COLOR["low"]
    else:
        od_str   = "N/A"
        od_color = "#757575"

    tile_overdue = {
        "label": "Overdue Critical + High",
        "value": od_str,
        "color": od_color,
    }

    # ------------------------------------------------------------------
    # Metric 4: MTTR / avg age of open critical vulns
    # ------------------------------------------------------------------
    mttr_crit = _safe_get(exec_m, "avg_age", "critical")
    if mttr_crit is not None:
        mttr_str   = f"{int(round(mttr_crit))}d"
        mttr_color = _SEV_COLOR["critical"] if mttr_crit > 15 else _SEV_COLOR["low"]
        mttr_sub   = "avg age of open criticals"
    else:
        mttr_str   = "N/A"
        mttr_color = "#757575"
        mttr_sub   = "avg age of open criticals"

    tile_mttr = {
        "label":     "Avg Age — Criticals",
        "value":     mttr_str,
        "color":     mttr_color,
        "sub_label": mttr_sub,
    }

    return [tile_crit, tile_sla, tile_overdue, tile_mttr]


def _safe_get(d: dict, *keys):
    """
    Safely traverse a nested dict without raising KeyError.
    Returns None if any key is missing or the structure is wrong.
    """
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(k)
        if current is None:
            return None
    return current


# ===========================================================================
# SLA / VPR reference table builder
# ===========================================================================

def build_sla_table() -> list[dict]:
    """
    Build the SLA reference table rows from config.py constants.

    Returns
    -------
    list[dict]
        Each dict: ``{severity, days, vpr_range, color, bg_color}``
    """
    # Build a lookup from severity → VPR range string
    vpr_ranges: dict[str, str] = {
        label: f"{lo} – {hi}"
        for lo, hi, label in VPR_SEVERITY_MAP
    }

    rows = []
    for sev, days in SLA_DAYS.items():
        rows.append({
            "severity":  SEVERITY_LABELS.get(sev, sev.title()),
            "days":      days,
            "vpr_range": vpr_ranges.get(sev, "N/A"),
            "color":     _SEV_COLOR.get(sev, "#212121"),
            "bg_color":  _SEV_BG.get(sev, "#FFFFFF"),
        })
    return rows


# ===========================================================================
# Attached reports list builder
# ===========================================================================

def build_attached_reports(report_outputs: dict) -> list[dict]:
    """
    Build the list of report dicts for the attached-reports section.

    Parameters
    ----------
    report_outputs : dict
        ``{report_slug: {pdf, excel, charts, ...}}``

    Returns
    -------
    list[dict]
        Each dict: ``{name, description}``
    """
    items = []
    for slug, output in report_outputs.items():
        if not isinstance(output, dict):
            continue
        pdf  = output.get("pdf")
        xlsx = output.get("excel")

        name_parts = []
        if pdf:
            name_parts.append(Path(pdf).name)
        if xlsx:
            name_parts.append(Path(xlsx).name)

        if not name_parts:
            continue

        items.append({
            "name":        ", ".join(name_parts),
            "description": _REPORT_DESCRIPTIONS.get(slug, slug.replace("_", " ").title()),
        })
    return items


# ===========================================================================
# Chart CID list builder
# ===========================================================================

def build_chart_cids(report_outputs: dict, max_charts: int = 3) -> list[str]:
    """
    Return the CID strings (e.g. ``["chart_1", "chart_2"]``) that will be
    referenced as ``cid:chart_N`` in the template.

    Collects the first *max_charts* PNG paths across all reports in order,
    then returns the CID names that email_sender.py will use when attaching
    the inline images.

    Parameters
    ----------
    report_outputs : dict
    max_charts : int

    Returns
    -------
    list[str]
        CID name strings without angle brackets or ``cid:`` prefix.
    """
    cids = []
    for slug, output in report_outputs.items():
        if not isinstance(output, dict):
            continue
        for chart_path in (output.get("charts") or []):
            if len(cids) >= max_charts:
                break
            cids.append(f"chart_{len(cids) + 1}")
        if len(cids) >= max_charts:
            break
    return cids


# ===========================================================================
# Main renderer
# ===========================================================================

def build_email_body(
    group_config: dict,
    report_outputs: dict,
    excel_omitted: bool = False,
    generated_at: Optional[datetime] = None,
) -> str:
    """
    Render the Jinja2 HTML email body and return it as a string.

    Parameters
    ----------
    group_config : dict
        Group entry from delivery_config.yaml.
        Expected keys: ``name``, ``email.subject``, ``email.reply_to``,
        ``filters.tag_category``, ``filters.tag_value``.
    report_outputs : dict
        ``{report_slug: {pdf, excel, charts, metrics?}}``
    excel_omitted : bool
        Set True when Excel files were dropped due to attachment size.
        Renders a warning banner in the email body.
    generated_at : datetime, optional
        Defaults to UTC now.

    Returns
    -------
    str
        Fully rendered HTML string ready for use as a MIME text/html part.
    """
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
        logger.debug(
            "Email body rendered for group '%s' (%d chars)",
            context["group_name"],
            len(rendered),
        )
        return rendered
    except Exception as exc:
        logger.error("Email template render failed: %s", exc, exc_info=True)
        # Return a minimal plain fallback so the send attempt is not blocked
        return (
            f"<p>Vulnerability Management Report — {context['group_name']}</p>"
            f"<p>Generated: {context['generated_at']}</p>"
            f"<p><em>HTML template render failed: {exc}</em></p>"
        )
