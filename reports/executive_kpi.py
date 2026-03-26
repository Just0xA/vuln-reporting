"""
reports/executive_kpi.py — Executive / KPI Dashboard report.

Audience: Management / Executives

Metrics produced
----------------
- Total open vulnerabilities by severity (VPR-derived)
- % Critical and High within SLA / overdue
- Average age of open vulnerabilities by severity (proxy for MTTR on open vulns)
- Top 5 riskiest assets (risk score = Critical×10 + High×5 + Medium×2 + Low×1)
- New vulnerabilities this month vs last month (month-over-month delta)
- Open Critical / High counts with SLA compliance context

Outputs
-------
- Excel: KPI Summary sheet + Open by Severity + Top Riskiest Assets
- PDF:   Cover page + KPI section + SLA compliance section + asset section
- Charts: Plotly bar (open by severity) + Plotly KPI gauges (Critical & High SLA %)

CLI
---
python reports/executive_kpi.py [options]
  --tag-category CATEGORY   Tag category to filter by (e.g. "Environment")
  --tag-value    VALUE       Tag value to filter by   (e.g. "Production")
  --output-dir   DIR         Base output directory    (default: output/)
  --run-id       ID          Cache key / run identifier (default: today's date)
  --no-cache                 Ignore existing parquet cache and re-fetch
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Allow running as a top-level script from any working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    RISK_WEIGHTS,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    SLA_DAYS,
)
from data.fetchers import (
    enrich_vulns_with_assets,
    fetch_all_assets,
    fetch_all_vulnerabilities,
    filter_by_tag,
)
from exporters.chart_exporter import bar_chart_by_severity, kpi_gauge
from exporters.excel_exporter import export_to_excel
from exporters.pdf_exporter import build_pdf
from utils.formatters import (
    fmt_days,
    fmt_int,
    fmt_pct,
    ordered_severities,
    report_timestamp,
    safe_filename,
    severity_label,
    sort_by_severity,
)
from utils.sla_calculator import apply_sla_to_df, compute_mttr, overdue_summary, sla_compliance_rate

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "Executive KPI Dashboard"
REPORT_SLUG = "executive_kpi"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


# ===========================================================================
# Phase 1 — Data fetching and preparation
# ===========================================================================

def _fetch_and_prepare(
    tio,
    cache_dir: Path,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> pd.DataFrame:
    """
    Fetch vulnerabilities and assets, enrich, and apply SLA calculations.

    Returns the fully-prepared DataFrame used by all downstream phases.
    Severity is always the VPR-derived ``severity`` column from fetchers.py —
    never ``severity_native`` or ``severity_level``.
    """
    logger.info("[%s] Fetching vulnerability data…", REPORT_NAME)
    vulns_df = fetch_all_vulnerabilities(tio, cache_dir)

    if vulns_df.empty:
        logger.warning("[%s] No vulnerabilities returned — report will be empty.", REPORT_NAME)
        return vulns_df

    logger.info("[%s] Fetching asset data…", REPORT_NAME)
    assets_df = fetch_all_assets(tio, cache_dir)

    df = enrich_vulns_with_assets(vulns_df, assets_df)
    df = filter_by_tag(df, tag_category, tag_value)

    if df.empty:
        logger.warning("[%s] No vulnerabilities match tag filter — report will be empty.", REPORT_NAME)
        return df

    df = apply_sla_to_df(df)

    logger.info(
        "[%s] Prepared %d vulnerability records (%d unique assets).",
        REPORT_NAME, len(df), df["asset_id"].nunique(),
    )
    return df


# ===========================================================================
# Phase 2 — KPI calculations
# ===========================================================================

def _compute_kpis(df: pd.DataFrame, as_of: Optional[datetime] = None) -> dict:
    """
    Derive all executive KPI values from the prepared vulnerability DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Output of _fetch_and_prepare() — must have sla_status and remediated columns.
    as_of : datetime, optional
        Reference timestamp (defaults to UTC now).

    Returns
    -------
    dict
        Flat key → value mapping consumed by _build_charts(), _build_excel(),
        and _build_pdf().
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    if df.empty:
        return {"empty": True}

    open_df = df[~df["remediated"]].copy()

    # ------------------------------------------------------------------
    # Severity-level open counts
    # ------------------------------------------------------------------
    sev_counts: dict[str, int] = {}
    for sev in ordered_severities(include_info=True):
        sev_counts[sev] = int((open_df["severity"] == sev).sum())

    total_open = len(open_df)

    # ------------------------------------------------------------------
    # SLA compliance rates per severity
    # ------------------------------------------------------------------
    compliance: dict[str, float] = {}
    for sev in ordered_severities():   # critical, high, medium, low
        compliance[sev] = sla_compliance_rate(df, sev)

    # ------------------------------------------------------------------
    # Overdue counts per severity (open only)
    # ------------------------------------------------------------------
    overdue_df = overdue_summary(open_df)
    overdue: dict[str, int] = dict(
        zip(overdue_df["severity"], overdue_df["overdue_count"].astype(int))
    )

    # ------------------------------------------------------------------
    # Average age of open vulnerabilities by severity (proxy for open-vuln MTTR)
    # ------------------------------------------------------------------
    avg_age: dict[str, Optional[float]] = {}
    for sev in ordered_severities():
        subset = open_df[open_df["severity"] == sev]
        if subset.empty or "days_open" not in subset.columns:
            avg_age[sev] = None
        else:
            avg_age[sev] = round(float(subset["days_open"].mean()), 1)

    # ------------------------------------------------------------------
    # Month-over-month new vuln delta (based on first_found)
    # ------------------------------------------------------------------
    this_month_start = as_of.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_month_start = (this_month_start - timedelta(days=1)).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    first_found_col = df["first_found"]
    this_month_new = int((first_found_col >= this_month_start).sum())
    last_month_new = int(
        ((first_found_col >= last_month_start) & (first_found_col < this_month_start)).sum()
    )
    mom_delta = this_month_new - last_month_new

    # ------------------------------------------------------------------
    # Top 5 riskiest assets by VPR-weighted severity score
    # ------------------------------------------------------------------
    asset_risk = _compute_asset_risk(open_df)

    return {
        "empty": False,
        "total_open": total_open,
        "sev_counts": sev_counts,
        "compliance": compliance,
        "overdue": overdue,
        "avg_age": avg_age,
        "this_month_new": this_month_new,
        "last_month_new": last_month_new,
        "mom_delta": mom_delta,
        "asset_risk_top5": asset_risk.head(5),
        "asset_risk_all": asset_risk,
        "as_of": as_of,
    }


def _compute_asset_risk(open_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute a risk score per asset and return a DataFrame sorted descending.

    Score = (Critical×10) + (High×5) + (Medium×2) + (Low×1)
    Uses the VPR-derived ``severity`` column exclusively.
    """
    if open_df.empty:
        return pd.DataFrame(columns=[
            "asset_hostname", "asset_ipv4", "risk_score",
            "critical", "high", "medium", "low", "total_vulns",
        ])

    df = open_df.copy()
    df["_risk_pts"] = df["severity"].str.lower().map(RISK_WEIGHTS).fillna(0)

    asset_risk = (
        df.groupby(["asset_id", "asset_hostname", "asset_ipv4"])
        .agg(
            risk_score=("_risk_pts", "sum"),
            critical=("severity", lambda s: int((s == "critical").sum())),
            high=("severity", lambda s: int((s == "high").sum())),
            medium=("severity", lambda s: int((s == "medium").sum())),
            low=("severity", lambda s: int((s == "low").sum())),
            total_vulns=("severity", "count"),
        )
        .reset_index()
        .sort_values("risk_score", ascending=False)
        .reset_index(drop=True)
    )

    asset_risk["rank"] = asset_risk.index + 1
    asset_risk["risk_score"] = asset_risk["risk_score"].astype(int)

    return asset_risk[[
        "rank", "asset_hostname", "asset_ipv4", "risk_score",
        "critical", "high", "medium", "low", "total_vulns",
    ]]


# ===========================================================================
# Phase 3 — Chart generation
# ===========================================================================

def _build_charts(
    open_df: pd.DataFrame,
    kpis: dict,
    charts_dir: Path,
) -> list[dict]:
    """
    Generate all charts for this report.

    Returns
    -------
    list[dict]
        Each dict: {name, png, html}  (html may be None for gauge charts)
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    if kpis.get("empty"):
        return results

    # ------------------------------------------------------------------
    # Chart 1: Open vulnerabilities by severity (Plotly bar)
    # ------------------------------------------------------------------
    sev_counts = kpis["sev_counts"]
    sev_df = pd.DataFrame([
        {"severity": sev, "open_count": sev_counts.get(sev, 0)}
        for sev in ordered_severities()
        if sev_counts.get(sev, 0) > 0
    ])

    if not sev_df.empty:
        png, html = bar_chart_by_severity(
            sev_df,
            "Open Vulnerabilities by Severity (VPR-Derived)",
            charts_dir / "open_by_severity",
            value_col="open_count",
            ylabel="Open Vulnerabilities",
        )
        results.append({"name": "open_by_severity", "png": png, "html": html})
        logger.debug("Chart written: %s", png)

    # ------------------------------------------------------------------
    # Chart 2: Critical SLA compliance gauge
    # ------------------------------------------------------------------
    critical_pct = round(kpis["compliance"].get("critical", 1.0) * 100, 1)
    png, html = kpi_gauge(
        critical_pct,
        "Critical — SLA Compliance %",
        charts_dir / "gauge_critical",
        thresholds={"red": 50, "yellow": 80},
    )
    results.append({"name": "gauge_critical", "png": png, "html": html})

    # ------------------------------------------------------------------
    # Chart 3: High SLA compliance gauge
    # ------------------------------------------------------------------
    high_pct = round(kpis["compliance"].get("high", 1.0) * 100, 1)
    png, html = kpi_gauge(
        high_pct,
        "High — SLA Compliance %",
        charts_dir / "gauge_high",
        thresholds={"red": 60, "yellow": 85},
    )
    results.append({"name": "gauge_high", "png": png, "html": html})

    return results


# ===========================================================================
# Phase 4 — Excel workbook
# ===========================================================================

def _build_excel(
    df: pd.DataFrame,
    kpis: dict,
    output_dir: Path,
    tag_filter: str,
    generated_at: datetime,
) -> Path:
    """Assemble the Excel workbook and return its path."""
    sheets: list[dict] = []

    # ------------------------------------------------------------------
    # Sheet 1: KPI Summary (key-value table)
    # ------------------------------------------------------------------
    if kpis.get("empty"):
        kpi_rows = [{"Metric": "No data returned for the selected scope.", "Value": "—"}]
    else:
        sev_counts = kpis["sev_counts"]
        compliance = kpis["compliance"]
        overdue    = kpis["overdue"]
        avg_age    = kpis["avg_age"]

        kpi_rows = [
            {"Metric": "Report Generated (UTC)", "Value": generated_at.strftime("%Y-%m-%d %H:%M")},
            {"Metric": "Scope / Tag Filter",     "Value": tag_filter},
            {"Metric": "",                        "Value": ""},
            {"Metric": "── Open Vulnerability Counts ──", "Value": ""},
            {"Metric": "Total Open Vulnerabilities", "Value": fmt_int(kpis["total_open"])},
        ]
        for sev in ordered_severities():
            lbl = severity_label(sev)
            kpi_rows.append({"Metric": f"  Open {lbl}", "Value": fmt_int(sev_counts.get(sev, 0))})

        kpi_rows += [
            {"Metric": "", "Value": ""},
            {"Metric": "── SLA Compliance ──", "Value": ""},
        ]
        for sev in ("critical", "high"):
            lbl = severity_label(sev)
            sla = fmt_pct(compliance.get(sev, 1.0))
            od  = fmt_int(overdue.get(sev, 0))
            kpi_rows.append({"Metric": f"  {lbl} — Within SLA", "Value": sla})
            kpi_rows.append({"Metric": f"  {lbl} — Overdue",    "Value": od})

        kpi_rows += [
            {"Metric": "", "Value": ""},
            {"Metric": "── Average Age of Open Vulnerabilities ──", "Value": ""},
        ]
        for sev in ordered_severities():
            lbl = severity_label(sev)
            kpi_rows.append({
                "Metric": f"  {lbl} — Avg Age",
                "Value": fmt_days(avg_age.get(sev)),
            })

        kpi_rows += [
            {"Metric": "", "Value": ""},
            {"Metric": "── Month-over-Month ──", "Value": ""},
            {"Metric": "  New Vulns This Month",  "Value": fmt_int(kpis["this_month_new"])},
            {"Metric": "  New Vulns Last Month",  "Value": fmt_int(kpis["last_month_new"])},
            {"Metric": "  Delta",                 "Value": f"{kpis['mom_delta']:+,}"},
        ]

    sheets.append({
        "name": "KPI Summary",
        "df": pd.DataFrame(kpi_rows),
        "title": f"{REPORT_NAME} — KPI Summary",
        "severity_col": None,
    })

    # ------------------------------------------------------------------
    # Sheet 2: Open by Severity (one row per severity tier)
    # ------------------------------------------------------------------
    if not kpis.get("empty"):
        sev_rows = []
        for sev in ordered_severities():
            lbl        = severity_label(sev)
            count      = kpis["sev_counts"].get(sev, 0)
            total      = kpis["total_open"] or 1
            comp_rate  = kpis["compliance"].get(sev, 1.0)
            od_count   = kpis["overdue"].get(sev, 0)
            sev_rows.append({
                "Severity":       lbl,
                "Open Count":     count,
                "% of Total":     fmt_pct(count / total),
                "Within SLA":     fmt_int(count - od_count),
                "Within SLA %":   fmt_pct(comp_rate),
                "Overdue":        fmt_int(od_count),
                "Overdue %":      fmt_pct(1 - comp_rate),
                "Avg Age (days)": fmt_days(kpis["avg_age"].get(sev)),
                "SLA Window":     f"{SLA_DAYS.get(sev, 'N/A')} days",
            })
        sheets.append({
            "name": "Open by Severity",
            "df": pd.DataFrame(sev_rows),
            "title": "Open Vulnerabilities by Severity Tier",
            "severity_col": "Severity",
        })

    # ------------------------------------------------------------------
    # Sheet 3: Top Riskiest Assets
    # ------------------------------------------------------------------
    if not kpis.get("empty") and not kpis["asset_risk_all"].empty:
        risk_df = kpis["asset_risk_all"].rename(columns={
            "asset_hostname": "Hostname",
            "asset_ipv4":     "IPv4",
            "risk_score":     "Risk Score",
            "critical":       "Critical",
            "high":           "High",
            "medium":         "Medium",
            "low":            "Low",
            "total_vulns":    "Total Open Vulns",
            "rank":           "Rank",
        })
        sheets.append({
            "name": "Riskiest Assets",
            "df": risk_df,
            "title": "Asset Risk Scores (VPR-Derived Severity Weights)",
            "severity_col": None,
        })

    output_path = output_dir / f"{REPORT_SLUG}.xlsx"
    return export_to_excel(
        sheets=sheets,
        output_path=output_path,
        report_name=REPORT_NAME,
        tag_filter=tag_filter,
        generated_at=generated_at,
    )


# ===========================================================================
# Phase 5 — PDF report
# ===========================================================================

def _build_pdf(
    df: pd.DataFrame,
    kpis: dict,
    charts: list[dict],
    output_dir: Path,
    scope_str: str,
    generated_at: datetime,
) -> Path:
    """Assemble the PDF report and return its path."""
    sections: list[dict] = []

    # Helper: look up a chart's PNG path by name
    def _chart_png(name: str) -> Optional[Path]:
        for c in charts:
            if c["name"] == name:
                return c["png"]
        return None

    # ------------------------------------------------------------------
    # Section 1: KPI overview
    # ------------------------------------------------------------------
    if kpis.get("empty"):
        kpi_text = "No vulnerability data was returned for the selected scope."
    else:
        sev_counts = kpis["sev_counts"]
        total      = kpis["total_open"]
        mom        = kpis["mom_delta"]
        mom_str    = f"+{mom}" if mom > 0 else str(mom)
        lines = [
            f"<strong>Total Open Vulnerabilities:</strong> {fmt_int(total)}",
            f"<strong>Critical:</strong> {fmt_int(sev_counts.get('critical', 0))} &nbsp;|&nbsp; "
            f"<strong>High:</strong> {fmt_int(sev_counts.get('high', 0))} &nbsp;|&nbsp; "
            f"<strong>Medium:</strong> {fmt_int(sev_counts.get('medium', 0))} &nbsp;|&nbsp; "
            f"<strong>Low:</strong> {fmt_int(sev_counts.get('low', 0))}",
            f"<strong>New This Month:</strong> {fmt_int(kpis['this_month_new'])} "
            f"({mom_str} vs last month)",
        ]
        kpi_text = "<br/>".join(lines)

    sections.append({
        "heading": "Vulnerability Overview",
        "text": kpi_text,
        "chart_png_path": _chart_png("open_by_severity"),
    })

    # ------------------------------------------------------------------
    # Section 2: SLA compliance
    # ------------------------------------------------------------------
    if not kpis.get("empty"):
        compliance = kpis["compliance"]
        overdue    = kpis["overdue"]
        sla_lines  = []
        for sev in ordered_severities():
            lbl  = severity_label(sev)
            comp = fmt_pct(compliance.get(sev, 1.0))
            od   = fmt_int(overdue.get(sev, 0))
            age  = fmt_days(kpis["avg_age"].get(sev))
            sla_lines.append(
                f"<strong>{lbl}:</strong> {comp} within SLA &mdash; "
                f"{od} overdue &mdash; avg age {age}"
            )

        sections.append({
            "heading": "SLA Compliance by Severity",
            "text": "<br/>".join(sla_lines),
            "chart_png_path": _chart_png("gauge_critical"),
        })

        # Gauge for High on its own sub-section
        sections.append({
            "heading": "",
            "chart_png_path": _chart_png("gauge_high"),
        })

    # ------------------------------------------------------------------
    # Section 3: Top riskiest assets
    # ------------------------------------------------------------------
    if not kpis.get("empty") and not kpis["asset_risk_top5"].empty:
        top5 = kpis["asset_risk_top5"].rename(columns={
            "asset_hostname": "Hostname",
            "asset_ipv4":     "IPv4",
            "risk_score":     "Risk Score",
            "critical":       "Critical",
            "high":           "High",
            "medium":         "Medium",
            "low":            "Low",
            "total_vulns":    "Total Vulns",
            "rank":           "Rank",
        })
        sections.append({
            "heading": "Top 5 Riskiest Assets",
            "text": (
                "Risk score = (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1). "
                "Severity derived from VPR score."
            ),
            "dataframe": top5,
            "severity_col": None,
        })

    output_path = output_dir / f"{REPORT_SLUG}.pdf"
    return build_pdf(
        report_title=REPORT_NAME,
        scope_str=scope_str,
        sections=sections,
        output_path=output_path,
        generated_at=generated_at,
    )


# ===========================================================================
# Orchestrator — callable by run_all.py
# ===========================================================================

def run_report(
    tio,
    run_id: str,
    tag_category: Optional[str] = None,
    tag_value: Optional[str] = None,
    output_dir: Optional[Path] = None,
    generated_at: Optional[datetime] = None,
    cache_dir: Optional[Path] = None,
) -> dict:
    """
    Run the Executive KPI report end-to-end.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Used for naming the default output directory.
    tag_category, tag_value : str, optional
        Tag filter for asset scoping.
    output_dir : Path, optional
        Directory for all output files.  Defaults to OUTPUT_DIR/<run_id>/<slug>/.
    generated_at : datetime, optional
        Override the report timestamp (defaults to UTC now).
    cache_dir : Path, optional
        Run-scoped parquet cache directory.  Pass the same path to all reports
        in one group execution so they share cached API data.  Defaults to
        data/cache/<today>/ when not provided.

    Returns
    -------
    dict
        {
            "pdf":    Path,
            "excel":  Path,
            "charts": [Path, ...],   # PNG paths only — for email CID embedding
        }
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if cache_dir is None:
        from config import CACHE_DIR  # noqa: PLC0415
        cache_dir = CACHE_DIR / generated_at.strftime("%Y-%m-%d_%H-%M")
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    if output_dir is None:
        output_dir = OUTPUT_DIR / safe_filename(run_id) / REPORT_SLUG
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    charts_dir = output_dir / "charts"
    scope_str  = f"{tag_category} = {tag_value}" if tag_category and tag_value else "All Assets"

    logger.info(
        "=== %s | scope=%s | run_id=%s | cache=%s ===",
        REPORT_NAME, scope_str, run_id, cache_dir,
    )

    # Phase 1: data
    df = _fetch_and_prepare(tio, cache_dir, tag_category, tag_value)

    # Phase 2: metrics
    kpis = _compute_kpis(df, as_of=generated_at)

    # Phase 3: charts — pass only open vulns
    open_df = df[~df["remediated"]].copy() if not df.empty else df
    charts  = _build_charts(open_df, kpis, charts_dir)

    # Phase 4: Excel
    excel_path = _build_excel(df, kpis, output_dir, scope_str, generated_at)
    logger.info("Excel written: %s", excel_path)

    # Phase 5: PDF
    pdf_path = _build_pdf(df, kpis, charts, output_dir, scope_str, generated_at)
    logger.info("PDF written: %s", pdf_path)

    chart_pngs = [c["png"] for c in charts if c.get("png")]
    logger.info(
        "=== %s complete — pdf=%s excel=%s charts=%d ===",
        REPORT_NAME, pdf_path.name, excel_path.name, len(chart_pngs),
    )

    return {
        "pdf":    pdf_path,
        "excel":  excel_path,
        "charts": chart_pngs,
    }


# ===========================================================================
# CLI entry point
# ===========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{REPORT_NAME} — standalone CLI runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reports/executive_kpi.py
  python reports/executive_kpi.py --tag-category "Environment" --tag-value "Production"
  python reports/executive_kpi.py --output-dir output/test/ --run-id 2026-03-20
        """,
    )
    parser.add_argument("--tag-category", default=None, metavar="CATEGORY",
                        help="Tenable tag category for asset scoping")
    parser.add_argument("--tag-value", default=None, metavar="VALUE",
                        help="Tenable tag value for asset scoping")
    parser.add_argument("--output-dir", default=None, metavar="DIR",
                        help="Output directory (default: output/<run-id>/executive_kpi/)")
    parser.add_argument("--run-id", default=None, metavar="ID",
                        help="Run identifier used for output directory naming (default: today YYYY-MM-DD)")
    parser.add_argument("--cache-dir", default=None, metavar="DIR",
                        help="Parquet cache directory (default: data/cache/<today>/)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Purge existing parquet cache before fetching")

    args = parser.parse_args()

    run_id    = args.run_id or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    out       = Path(args.output_dir) if args.output_dir else None
    from config import CACHE_DIR
    cache_dir = Path(args.cache_dir) if args.cache_dir else CACHE_DIR / run_id

    if args.no_cache:
        for f in cache_dir.glob("vulns_*.parquet"):
            f.unlink()
            logger.info("Purged cache: %s", f)

    from tenable_client import get_client
    tio = get_client()

    result = run_report(
        tio=tio,
        run_id=run_id,
        tag_category=args.tag_category,
        tag_value=args.tag_value,
        output_dir=out,
        cache_dir=cache_dir,
    )

    print(f"\nReport complete:")
    print(f"  PDF:    {result['pdf']}")
    print(f"  Excel:  {result['excel']}")
    print(f"  Charts: {len(result['charts'])} file(s)")
    for p in result["charts"]:
        print(f"    {p}")
