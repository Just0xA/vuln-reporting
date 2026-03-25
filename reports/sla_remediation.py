"""
reports/sla_remediation.py — SLA & Remediation Tracking report.

Audience: IT / Remediation Teams + Security Analysts

Metrics produced
----------------
- Per-vulnerability SLA status: Within SLA / Overdue (VPR-derived severity)
- Days remaining or days overdue per vulnerability
- Overdue breakdown by severity
- Remediation velocity: new vulns introduced last 7 / 30 / 90 days
- Per-asset overdue vulnerability list sorted by severity then days overdue
- Approximated SLA breach rate trend over last 6 months

Outputs
-------
- Excel: one tab per severity (Critical / High / Medium / Low) with SLA
         conditional formatting, plus a Summary tab and an Asset Overdue tab
- PDF:   Cover page + SLA Status summary + overdue detail + trend section
- Charts: Stacked bar (Overdue vs Within SLA per severity)
          Line chart  (SLA breach rate trend — last 6 months)

CLI
---
python reports/sla_remediation.py [options]
  --tag-category CATEGORY
  --tag-value    VALUE
  --output-dir   DIR
  --run-id       ID
  --no-cache
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    SLA_DAYS,
)
from data.fetchers import fetch_assets, fetch_vulnerabilities, enrich_vulns_with_assets
from exporters.chart_exporter import line_chart, stacked_bar_chart
from exporters.excel_exporter import export_to_excel
from exporters.pdf_exporter import build_pdf
from utils.formatters import (
    fmt_date_utc,
    fmt_days,
    fmt_int,
    fmt_pct,
    ordered_severities,
    report_timestamp,
    safe_filename,
    severity_label,
    sort_by_severity,
)
from utils.sla_calculator import apply_sla_to_df, overdue_summary, sla_compliance_rate

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "SLA & Remediation Tracking"
REPORT_SLUG = "sla_remediation"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# Columns included in per-severity detail sheets
_DETAIL_COLS = [
    "asset_hostname",
    "asset_ipv4",
    "plugin_name",
    "plugin_id",
    "cve_list",
    "vpr_score",
    "first_found",
    "days_open",
    "sla_days",
    "days_remaining",
    "sla_status",
]

_DETAIL_RENAME = {
    "asset_hostname":  "Hostname",
    "asset_ipv4":      "IPv4",
    "plugin_name":     "Plugin Name",
    "plugin_id":       "Plugin ID",
    "cve_list":        "CVEs",
    "vpr_score":       "VPR Score",
    "first_found":     "First Found",
    "days_open":       "Days Open",
    "sla_days":        "SLA Window",
    "days_remaining":  "Days Remaining",
    "sla_status":      "SLA Status",
}


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
    Fetch, enrich, and apply SLA calculations to the vulnerability dataset.

    All severity values are taken from the VPR-derived ``severity`` column.
    ``severity_native`` is never used as the primary severity source.
    """
    logger.info("[%s] Fetching vulnerability data…", REPORT_NAME)
    vulns_df = fetch_vulnerabilities(
        tio, cache_dir, tag_category=tag_category, tag_value=tag_value
    )

    if vulns_df.empty:
        logger.warning("[%s] No vulnerabilities returned.", REPORT_NAME)
        return vulns_df

    logger.info("[%s] Fetching asset data…", REPORT_NAME)
    assets_df = fetch_assets(tio, cache_dir)

    df = enrich_vulns_with_assets(vulns_df, assets_df)
    df = apply_sla_to_df(df)

    logger.info(
        "[%s] Prepared %d records (%d assets, %d overdue).",
        REPORT_NAME,
        len(df),
        df["asset_id"].nunique(),
        int(df["is_overdue"].sum()),
    )
    return df


# ===========================================================================
# Phase 2 — Metric calculations
# ===========================================================================

def _compute_metrics(df: pd.DataFrame, as_of: Optional[datetime] = None) -> dict:
    """
    Compute all SLA and remediation metrics.

    Returns a flat metrics dict consumed by all downstream phases.
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    if df.empty:
        return {"empty": True}

    open_df = df[~df["remediated"]].copy()

    # ------------------------------------------------------------------
    # Per-severity SLA summary
    # ------------------------------------------------------------------
    sev_summary_rows = []
    for sev in ordered_severities():
        lbl       = severity_label(sev)
        sev_open  = open_df[open_df["severity"] == sev]
        count     = len(sev_open)
        od_count  = int(sev_open["is_overdue"].sum())
        ok_count  = count - od_count
        comp_rate = sla_compliance_rate(df, sev)
        sla_win   = SLA_DAYS.get(sev, "N/A")
        avg_age   = round(float(sev_open["days_open"].mean()), 1) if not sev_open.empty else None
        sev_summary_rows.append({
            "Severity":       lbl,
            "severity":       sev,              # lowercase key for chart grouping
            "Open":           count,
            "Within SLA":     ok_count,
            "Overdue":        od_count,
            "Compliance %":   fmt_pct(comp_rate),
            "Avg Age (days)": fmt_days(avg_age),
            "SLA Window":     f"{sla_win} days",
        })
    sev_summary_df = pd.DataFrame(sev_summary_rows)

    # ------------------------------------------------------------------
    # Overdue vuln detail (all severities, sorted by severity then days overdue)
    # ------------------------------------------------------------------
    overdue_df = (
        open_df[open_df["is_overdue"]]
        .copy()
        .assign(
            _sev_order=lambda d: d["severity"].str.lower().map(
                {s: i for i, s in enumerate(SEVERITY_ORDER)}
            ).fillna(99)
        )
        .sort_values(["_sev_order", "days_remaining"])  # most overdue (most negative) first
        .drop(columns=["_sev_order"])
        .reset_index(drop=True)
    )

    # ------------------------------------------------------------------
    # Per-asset overdue summary
    # ------------------------------------------------------------------
    asset_overdue_df = _compute_asset_overdue(overdue_df)

    # ------------------------------------------------------------------
    # Remediation velocity: new vulns in last 7 / 30 / 90 days
    # ------------------------------------------------------------------
    velocity: dict[str, int] = {}
    for window in (7, 30, 90):
        cutoff = as_of - timedelta(days=window)
        velocity[f"new_last_{window}d"] = int(
            (df["first_found"] >= cutoff).sum()
        )

    # ------------------------------------------------------------------
    # SLA breach rate trend — last 6 months (approximated from first_found)
    # ------------------------------------------------------------------
    trend_df = _compute_breach_trend(open_df, n_months=6, as_of=as_of)

    return {
        "empty":           False,
        "total_open":      len(open_df),
        "total_overdue":   int(open_df["is_overdue"].sum()),
        "sev_summary":     sev_summary_df,
        "overdue_detail":  overdue_df,
        "asset_overdue":   asset_overdue_df,
        "velocity":        velocity,
        "trend":           trend_df,
        "as_of":           as_of,
    }


def _compute_asset_overdue(overdue_df: pd.DataFrame) -> pd.DataFrame:
    """
    Group overdue vulns by asset and return a ranked summary DataFrame.
    """
    if overdue_df.empty:
        return pd.DataFrame(columns=[
            "Hostname", "IPv4", "Overdue Vulns",
            "Critical", "High", "Medium", "Low", "Most Overdue (days)",
        ])

    asset_grp = (
        overdue_df.groupby(["asset_id", "asset_hostname", "asset_ipv4"])
        .agg(
            overdue_count=("is_overdue", "count"),
            critical=("severity", lambda s: int((s == "critical").sum())),
            high=("severity", lambda s: int((s == "high").sum())),
            medium=("severity", lambda s: int((s == "medium").sum())),
            low=("severity", lambda s: int((s == "low").sum())),
            # days_remaining is negative for overdue — most negative = worst
            most_overdue_days=("days_remaining", "min"),
        )
        .reset_index()
        .sort_values("overdue_count", ascending=False)
        .reset_index(drop=True)
    )

    # Convert most_overdue_days to positive "days overdue" for readability
    asset_grp["most_overdue_days"] = asset_grp["most_overdue_days"].abs()

    return asset_grp.rename(columns={
        "asset_hostname":    "Hostname",
        "asset_ipv4":        "IPv4",
        "overdue_count":     "Overdue Vulns",
        "critical":          "Critical",
        "high":              "High",
        "medium":            "Medium",
        "low":               "Low",
        "most_overdue_days": "Most Overdue (days)",
    })[["Hostname", "IPv4", "Overdue Vulns", "Critical", "High", "Medium", "Low",
        "Most Overdue (days)"]]


def _compute_breach_trend(
    open_df: pd.DataFrame,
    n_months: int = 6,
    as_of: Optional[datetime] = None,
) -> pd.DataFrame:
    """
    Approximate monthly SLA breach rate over the past *n_months*.

    Methodology: for each month end, count vulns whose first_found is on or
    before that month end (they existed then) and compute what % were already
    overdue at that point using their VPR-derived SLA window.

    Note: this is an under-estimate since fixed vulns are not included in
    the open-only export.  It reflects the current open cohort's history.

    Returns
    -------
    pd.DataFrame
        Columns: month, critical_breach_pct, high_breach_pct, overall_breach_pct
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    if open_df.empty or "first_found" not in open_df.columns:
        return pd.DataFrame(columns=["month", "critical_breach_pct", "high_breach_pct", "overall_breach_pct"])

    rows = []
    for i in range(n_months - 1, -1, -1):
        # Last moment of the month that was i months ago
        month_anchor = (as_of.replace(day=1) - pd.DateOffset(months=i))
        month_end = (
            pd.Timestamp(month_anchor).to_period("M").to_timestamp("M")
            .tz_localize("UTC")
        )
        label = month_end.strftime("%b %Y")

        # Vulns that had first_found on or before this month end
        cohort = open_df[open_df["first_found"] <= month_end].copy()

        if cohort.empty:
            rows.append({
                "month": label,
                "critical_breach_pct": 0.0,
                "high_breach_pct": 0.0,
                "overall_breach_pct": 0.0,
            })
            continue

        # Days open at month_end and whether overdue at that point
        cohort["_days_at"] = (month_end - cohort["first_found"]).dt.days.clip(lower=0)
        cohort["_sla_at"]  = cohort["severity"].str.lower().map(SLA_DAYS)
        cohort["_od_at"]   = (
            cohort["_sla_at"].notna()
            & (cohort["_days_at"] > cohort["_sla_at"])
        )

        def _breach_pct(sev_filter=None):
            sub = cohort if sev_filter is None else cohort[cohort["severity"] == sev_filter]
            if sub.empty or not sub["_sla_at"].notna().any():
                return 0.0
            return round(float(sub["_od_at"].mean()) * 100, 1)

        rows.append({
            "month":                label,
            "critical_breach_pct":  _breach_pct("critical"),
            "high_breach_pct":      _breach_pct("high"),
            "overall_breach_pct":   _breach_pct(),
        })

    return pd.DataFrame(rows)


# ===========================================================================
# Phase 3 — Chart generation
# ===========================================================================

def _build_charts(
    metrics: dict,
    charts_dir: Path,
) -> list[dict]:
    """
    Generate all charts for this report.

    Returns
    -------
    list[dict]
        Each dict: {name, png, html}
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    if metrics.get("empty"):
        return results

    sev_summary = metrics["sev_summary"]

    # ------------------------------------------------------------------
    # Chart 1: Stacked bar — Overdue vs Within SLA per severity
    # ------------------------------------------------------------------
    # Build a DataFrame ordered Critical → Low with open-only severities
    sev_order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    status_df = (
        sev_summary[sev_summary["Open"] > 0]
        .copy()
        .assign(_order=lambda d: d["severity"].map(sev_order_map).fillna(99))
        .sort_values("_order")
        .drop(columns=["_order"])
        .reset_index(drop=True)
    )

    if not status_df.empty:
        # x-axis labels: "Critical", "High", etc. (title-cased)
        status_df["Severity Label"] = status_df["severity"].map(SEVERITY_LABELS)

        png, html = stacked_bar_chart(
            status_df,
            "Overdue vs Within SLA by Severity",
            charts_dir / "sla_status_bar",
            x_col="Severity Label",
            stack_cols=["Within SLA", "Overdue"],
            colors=["#388e3c", "#d32f2f"],
            ylabel="Open Vulnerabilities",
        )
        results.append({"name": "sla_status_bar", "png": png, "html": html})
        logger.debug("Chart written: %s", png)

    # ------------------------------------------------------------------
    # Chart 2: Line chart — SLA breach rate trend (last 6 months)
    # ------------------------------------------------------------------
    trend_df = metrics["trend"]
    if not trend_df.empty and trend_df["overall_breach_pct"].sum() > 0:
        png, html = line_chart(
            trend_df,
            "SLA Breach Rate Trend — Last 6 Months",
            charts_dir / "sla_breach_trend",
            x_col="month",
            y_cols=["critical_breach_pct", "high_breach_pct", "overall_breach_pct"],
            colors=[
                SEVERITY_COLORS["critical"],
                SEVERITY_COLORS["high"],
                "#607d8b",  # blue-grey for overall
            ],
            xlabel="Month",
            ylabel="Breach Rate",
            y_pct=False,
        )
        results.append({"name": "sla_breach_trend", "png": png, "html": html})

    return results


# ===========================================================================
# Phase 4 — Excel workbook
# ===========================================================================

def _build_excel(
    df: pd.DataFrame,
    metrics: dict,
    output_dir: Path,
    tag_filter: str,
    generated_at: datetime,
) -> Path:
    """
    Assemble the Excel workbook:
    - Report Info tab (from metadata helper)
    - Summary tab
    - One tab per severity (Critical / High / Medium / Low) with SLA formatting
    - Asset Overdue tab
    """
    sheets: list[dict] = []

    if metrics.get("empty"):
        sheets.append({
            "name": "Summary",
            "df": pd.DataFrame({"Message": ["No data returned for the selected scope."]}),
            "severity_col": None,
        })
        return export_to_excel(
            sheets=sheets,
            output_path=output_dir / f"{REPORT_SLUG}.xlsx",
            report_name=REPORT_NAME,
            tag_filter=tag_filter,
            generated_at=generated_at,
        )

    # ------------------------------------------------------------------
    # Summary sheet
    # ------------------------------------------------------------------
    sev_summary_display = metrics["sev_summary"][[
        "Severity", "Open", "Within SLA", "Overdue",
        "Compliance %", "Avg Age (days)", "SLA Window",
    ]].copy()

    # Add velocity block below the severity table via separate rows
    velocity = metrics["velocity"]
    vel_rows = pd.DataFrame([
        {"Severity": "── Remediation Velocity ──", "Open": "", "Within SLA": "",
         "Overdue": "", "Compliance %": "", "Avg Age (days)": "", "SLA Window": ""},
        {"Severity": "New vulns — last 7 days",   "Open": fmt_int(velocity["new_last_7d"]),
         "Within SLA": "", "Overdue": "", "Compliance %": "", "Avg Age (days)": "", "SLA Window": ""},
        {"Severity": "New vulns — last 30 days",  "Open": fmt_int(velocity["new_last_30d"]),
         "Within SLA": "", "Overdue": "", "Compliance %": "", "Avg Age (days)": "", "SLA Window": ""},
        {"Severity": "New vulns — last 90 days",  "Open": fmt_int(velocity["new_last_90d"]),
         "Within SLA": "", "Overdue": "", "Compliance %": "", "Avg Age (days)": "", "SLA Window": ""},
    ])
    summary_df = pd.concat([sev_summary_display, vel_rows], ignore_index=True)

    sheets.append({
        "name": "Summary",
        "df": summary_df,
        "title": f"{REPORT_NAME} — Summary",
        "severity_col": "Severity",
    })

    # ------------------------------------------------------------------
    # Per-severity detail sheets
    # ------------------------------------------------------------------
    open_df = df[~df["remediated"]].copy()

    for sev in ordered_severities():
        lbl    = severity_label(sev)
        sev_df = (
            open_df[open_df["severity"] == sev]
            .copy()
            # Sort: most overdue first (days_remaining most negative), then alpha by host
            .assign(
                _od=lambda d: d["is_overdue"].astype(int),
                _dr=lambda d: d["days_remaining"].fillna(9999),
            )
            .sort_values(["_od", "_dr"], ascending=[False, True])
            .drop(columns=["_od", "_dr"])
            .reset_index(drop=True)
        )

        # Select and rename display columns (only include cols that exist)
        available = [c for c in _DETAIL_COLS if c in sev_df.columns]
        sev_display = sev_df[available].rename(columns=_DETAIL_RENAME)

        sheets.append({
            "name": lbl,
            "df": sev_display,
            "title": f"{lbl} Vulnerabilities — SLA Status",
            "severity_col": None,        # whole sheet is one severity
            "sla_formatting": True,
            "sla_status_col": "SLA Status",
        })

    # ------------------------------------------------------------------
    # Asset Overdue sheet
    # ------------------------------------------------------------------
    asset_od = metrics["asset_overdue"]
    if not asset_od.empty:
        sheets.append({
            "name": "Asset Overdue",
            "df": asset_od,
            "title": "Assets with Overdue Vulnerabilities",
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Trend sheet
    # ------------------------------------------------------------------
    trend_df = metrics["trend"]
    if not trend_df.empty:
        trend_display = trend_df.rename(columns={
            "month":                "Month",
            "critical_breach_pct":  "Critical Breach %",
            "high_breach_pct":      "High Breach %",
            "overall_breach_pct":   "Overall Breach %",
        })
        sheets.append({
            "name": "Breach Trend",
            "df": trend_display,
            "title": "SLA Breach Rate Trend (approximated from open vuln first_found dates)",
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
    metrics: dict,
    charts: list[dict],
    output_dir: Path,
    scope_str: str,
    generated_at: datetime,
) -> Path:
    """Assemble the PDF report and return its path."""
    sections: list[dict] = []

    def _chart_png(name: str) -> Optional[Path]:
        for c in charts:
            if c["name"] == name:
                return c["png"]
        return None

    # ------------------------------------------------------------------
    # Section 1: SLA status summary
    # ------------------------------------------------------------------
    if metrics.get("empty"):
        sections.append({
            "heading": "SLA Status Summary",
            "text": "No vulnerability data was returned for the selected scope.",
        })
    else:
        total     = metrics["total_open"]
        total_od  = metrics["total_overdue"]
        velocity  = metrics["velocity"]

        intro = (
            f"<strong>Total Open Vulnerabilities:</strong> {fmt_int(total)} &nbsp;|&nbsp; "
            f"<strong>Overdue:</strong> {fmt_int(total_od)} "
            f"({fmt_pct(total_od / total if total else 0)})<br/>"
            f"<strong>New last 7d:</strong> {fmt_int(velocity['new_last_7d'])} &nbsp;|&nbsp; "
            f"<strong>New last 30d:</strong> {fmt_int(velocity['new_last_30d'])} &nbsp;|&nbsp; "
            f"<strong>New last 90d:</strong> {fmt_int(velocity['new_last_90d'])}"
        )
        sections.append({
            "heading": "SLA Status Summary",
            "text": intro,
            "chart_png_path": _chart_png("sla_status_bar"),
            "dataframe": metrics["sev_summary"][[
                "Severity", "Open", "Within SLA", "Overdue",
                "Compliance %", "Avg Age (days)", "SLA Window",
            ]],
            "severity_col": "Severity",
        })

    # ------------------------------------------------------------------
    # Section 2: Overdue vulnerability detail (top 100 — most critical first)
    # ------------------------------------------------------------------
    if not metrics.get("empty") and not metrics["overdue_detail"].empty:
        od_df = metrics["overdue_detail"]
        available = [c for c in _DETAIL_COLS if c in od_df.columns]
        od_display = od_df[available].rename(columns=_DETAIL_RENAME).head(100)
        sections.append({
            "heading": "Overdue Vulnerabilities — Detail",
            "text": (
                f"Showing top {min(100, len(od_df))} of {len(od_df)} overdue vulnerabilities "
                f"sorted by severity then days overdue. Full data is in the Excel attachment."
            ),
            "dataframe": od_display,
            "severity_col": None,   # whole table is overdue — no per-cell severity color needed
        })

    # ------------------------------------------------------------------
    # Section 3: Per-asset overdue summary
    # ------------------------------------------------------------------
    if not metrics.get("empty") and not metrics["asset_overdue"].empty:
        sections.append({
            "heading": "Assets with Overdue Vulnerabilities",
            "dataframe": metrics["asset_overdue"].head(50),
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Section 4: SLA breach rate trend
    # ------------------------------------------------------------------
    if not metrics.get("empty") and not metrics["trend"].empty:
        sections.append({
            "heading": "SLA Breach Rate Trend — Last 6 Months",
            "text": (
                "Approximated from currently-open vulnerability first_found dates. "
                "Shows the estimated % of open vulnerabilities that were overdue "
                "at the end of each calendar month."
            ),
            "chart_png_path": _chart_png("sla_breach_trend"),
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
    Run the SLA & Remediation Tracking report end-to-end.

    Parameters
    ----------
    tio : TenableIO
    run_id : str
        Used for naming the default output directory.
    tag_category, tag_value : str, optional
    output_dir : Path, optional
    generated_at : datetime, optional
    cache_dir : Path, optional
        Run-scoped parquet cache directory.  Pass the same path to all reports
        in one group execution so they share cached API data.

    Returns
    -------
    dict
        {"pdf": Path, "excel": Path, "charts": [Path, ...]}
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
    metrics = _compute_metrics(df, as_of=generated_at)

    # Phase 3: charts
    charts = _build_charts(metrics, charts_dir)

    # Phase 4: Excel
    excel_path = _build_excel(df, metrics, output_dir, scope_str, generated_at)
    logger.info("Excel written: %s", excel_path)

    # Phase 5: PDF
    pdf_path = _build_pdf(df, metrics, charts, output_dir, scope_str, generated_at)
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
  python reports/sla_remediation.py
  python reports/sla_remediation.py --tag-category "Business Unit" --tag-value "Finance"
  python reports/sla_remediation.py --output-dir output/test/ --run-id 2026-03-20
        """,
    )
    parser.add_argument("--tag-category", default=None, metavar="CATEGORY")
    parser.add_argument("--tag-value",    default=None, metavar="VALUE")
    parser.add_argument("--output-dir",   default=None, metavar="DIR")
    parser.add_argument("--run-id",       default=None, metavar="ID")
    parser.add_argument("--cache-dir",    default=None, metavar="DIR",
                        help="Parquet cache directory (default: data/cache/<today>/)")
    parser.add_argument("--no-cache",     action="store_true",
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
