"""
reports/patch_compliance.py — Patch Compliance & Vulnerability Age report.

Audience: IT / Remediation Teams + Security Analysts

Metrics produced
----------------
- Vulnerability age distribution across six fixed buckets:
    0–15d, 16–30d, 31–60d, 61–90d, 91–180d, 180d+
- % of open vulnerabilities beyond their SLA window per severity
  (higher overdue % = lower patch compliance)
- Top 20 oldest unpatched vulnerabilities:
    plugin name, CVE(s), hostname, IP, days open, severity, SLA status
- Per-tag-group patch compliance score: % within SLA, grouped by the
  tag category/value active at runtime (requires assets export for tag data)
- Recurring vulnerability count (state == "reopened")
- Plugin family breakdown for overdue vulnerabilities

Severity is always derived from vpr_score via config.vpr_to_severity().
``severity_native`` is never used as the primary severity source.

Outputs
-------
- Excel:
    Tab "Age Distribution"    — age bucket counts per severity, row-color coded
    Tab "Oldest Vulns"        — top 20 oldest open vulns, sorted by days_open desc
    Tab "Per-Tag Compliance"  — % within SLA per tag group (if tag data available)
    Tab "Plugin Families"     — overdue vuln counts per plugin family
    Metadata tab via export_to_excel()
- PDF:   Patch compliance scorecard + age distribution chart embedded
- Chart: Matplotlib stacked bar — age buckets (x-axis) per severity (stacked),
         saved as .png and also via chart_exporter helpers

CLI
---
python reports/patch_compliance.py [options]
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    AGE_BUCKETS,
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    SLA_DAYS,
)
from data.fetchers import enrich_vulns_with_assets, fetch_assets, fetch_vulnerabilities
from exporters.chart_exporter import save_matplotlib_figure, stacked_bar_chart
from exporters.excel_exporter import export_to_excel
from exporters.pdf_exporter import build_pdf
from utils.formatters import (
    age_bucket,
    age_bucket_order,
    fmt_int,
    fmt_pct,
    ordered_severities,
    safe_filename,
    severity_label,
)
from utils.sla_calculator import apply_sla_to_df, sla_compliance_rate

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "Patch Compliance & Vulnerability Age"
REPORT_SLUG = "patch_compliance"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# Map age buckets to color-tier labels for Excel row coloring
# (reuses severity fill palette: freshest = green/low, oldest = red/critical)
_AGE_BUCKET_TIERS: dict[str, str] = {
    "0–15d":    "low",       # green  — well within any SLA window
    "16–30d":   "low",       # green  — still healthy for medium/low
    "31–60d":   "medium",    # yellow — starting to age
    "61–90d":   "medium",    # yellow
    "91–180d":  "high",      # orange — overdue for critical/high
    "180d+":    "critical",  # red    — overdue for all severities
}


# ===========================================================================
# Phase 1 — Fetch and prepare
# ===========================================================================

def _fetch_and_prepare(
    tio,
    run_id: str,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Fetch vulnerabilities and assets, enrich, and apply SLA calculations.

    Returns
    -------
    (enriched_vulns_df, raw_assets_df)
    raw_assets_df is kept separately for per-tag-group compliance calculations
    that require the full tag string for each asset.
    """
    logger.info("[%s] Fetching vulnerability data (run_id=%s)…", REPORT_NAME, run_id)
    vulns_df = fetch_vulnerabilities(
        tio, run_id, tag_category=tag_category, tag_value=tag_value
    )

    logger.info("[%s] Fetching asset data…", REPORT_NAME)
    assets_df = fetch_assets(tio, run_id)

    if vulns_df.empty:
        logger.warning("[%s] No vulnerabilities returned.", REPORT_NAME)
        return vulns_df, assets_df

    df = enrich_vulns_with_assets(vulns_df, assets_df)
    df = apply_sla_to_df(df)

    logger.info(
        "[%s] Prepared %d records (%d assets, %d overdue).",
        REPORT_NAME,
        len(df),
        df["asset_id"].nunique(),
        int(df["is_overdue"].sum()),
    )
    return df, assets_df


# ===========================================================================
# Phase 2 — Metric calculations
# ===========================================================================

def _compute_metrics(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    tag_category: Optional[str],
) -> dict:
    """
    Compute all patch compliance and age metrics.

    Returns a flat metrics dict consumed by all downstream phases.
    """
    if df.empty:
        return {"empty": True}

    open_df = df[~df["remediated"]].copy()

    age_dist       = _compute_age_distribution(open_df)
    compliance_tbl = _compute_compliance_table(df)
    top20_oldest   = _compute_oldest_vulns(open_df, n=20)
    tag_compliance = _compute_tag_compliance(df, assets_df, tag_category)
    recurring_cnt  = _compute_recurring_count(df)
    family_overdue = _compute_plugin_family_overdue(open_df)

    return {
        "empty":           False,
        "total_open":      len(open_df),
        "total_overdue":   int(open_df["is_overdue"].sum()),
        "age_dist":        age_dist,
        "compliance_tbl":  compliance_tbl,
        "top20_oldest":    top20_oldest,
        "tag_compliance":  tag_compliance,
        "recurring_count": recurring_cnt,
        "family_overdue":  family_overdue,
        "tag_category":    tag_category,
    }


def _compute_age_distribution(open_df: pd.DataFrame) -> pd.DataFrame:
    """
    Count open vulnerabilities per age bucket per severity.

    Returns
    -------
    pd.DataFrame
        Columns: age_bucket, critical, high, medium, low, total, color_tier
        Rows are ordered by ascending age (freshest → oldest).
    """
    if open_df.empty:
        empty = pd.DataFrame(
            columns=["age_bucket", "critical", "high", "medium", "low", "total", "color_tier"]
        )
        return empty

    open_df = open_df.copy()
    open_df["_bucket"] = open_df["days_open"].apply(age_bucket)

    bucket_order = age_bucket_order()
    rows = []
    for label in bucket_order:
        bucket_df = open_df[open_df["_bucket"] == label]
        row = {"age_bucket": label}
        for sev in ordered_severities():
            row[sev] = int((bucket_df["severity"] == sev).sum())
        row["total"] = int(len(bucket_df))
        row["color_tier"] = _AGE_BUCKET_TIERS.get(label, "info")
        rows.append(row)

    return pd.DataFrame(rows)


def _compute_compliance_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Per-severity patch compliance scorecard: open count, overdue count, SLA %.

    Returns
    -------
    pd.DataFrame
        One row per severity tier (Critical → Low).
    """
    open_df = df[~df["remediated"]]
    rows = []
    for sev in ordered_severities():
        lbl       = severity_label(sev)
        sev_open  = open_df[open_df["severity"] == sev]
        count     = len(sev_open)
        od_count  = int(sev_open["is_overdue"].sum())
        ok_count  = count - od_count
        comp_rate = sla_compliance_rate(df, sev)
        sla_win   = SLA_DAYS.get(sev, "N/A")
        rows.append({
            "Severity":         lbl,
            "severity":         sev,
            "Open":             count,
            "Within SLA":       ok_count,
            "Overdue":          od_count,
            "% Within SLA":     fmt_pct(comp_rate),
            "% Overdue":        fmt_pct(1.0 - comp_rate),
            "SLA Window (days)": sla_win,
        })
    return pd.DataFrame(rows)


def _compute_oldest_vulns(open_df: pd.DataFrame, n: int = 20) -> pd.DataFrame:
    """
    Return the top-N oldest unpatched vulnerabilities sorted by days open descending.
    """
    if open_df.empty:
        return pd.DataFrame()

    display_cols = [c for c in [
        "asset_hostname", "asset_ipv4", "plugin_name", "plugin_id",
        "plugin_family", "cve_list", "vpr_score", "severity",
        "first_found", "days_open", "sla_status", "days_remaining",
    ] if c in open_df.columns]

    return (
        open_df[display_cols]
        .sort_values("days_open", ascending=False)
        .head(n)
        .reset_index(drop=True)
    )


def _compute_tag_compliance(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    tag_category: Optional[str],
) -> pd.DataFrame:
    """
    Compute % within SLA grouped by tag category/value.

    Expands the semicolon-delimited 'tags' column from assets_df
    (format: "Category=Value;Category=Value…") and joins to vulns via asset_id.
    If tag_category is supplied, only that category is shown; otherwise all.

    Returns
    -------
    pd.DataFrame
        Columns: Tag Category, Tag Value, Open Vulns, Within SLA, % Within SLA
    """
    if df.empty or assets_df.empty or "tags" not in assets_df.columns:
        return pd.DataFrame()

    # Build a long-form asset → tag mapping
    tag_rows: list[dict] = []
    for _, row in assets_df.iterrows():
        raw = row.get("tags", "")
        if not isinstance(raw, str) or not raw.strip():
            continue
        for tag_str in raw.split(";"):
            if "=" not in tag_str:
                continue
            cat, val = tag_str.split("=", 1)
            cat, val = cat.strip(), val.strip()
            if not cat or not val:
                continue
            tag_rows.append({
                "asset_id": row["asset_id"],
                "tag_cat":  cat,
                "tag_val":  val,
            })

    if not tag_rows:
        return pd.DataFrame()

    tag_long = pd.DataFrame(tag_rows)

    if tag_category:
        tag_long = tag_long[tag_long["tag_cat"].str.lower() == tag_category.lower()]

    if tag_long.empty:
        return pd.DataFrame()

    # Join with open vulns
    open_df = df[~df["remediated"]].copy()
    merged = open_df.merge(tag_long, on="asset_id", how="inner")

    if merged.empty:
        return pd.DataFrame()

    result_rows = []
    for (cat, val), grp in merged.groupby(["tag_cat", "tag_val"]):
        open_cnt = len(grp)
        within = int((grp["sla_status"] == "Within SLA").sum())
        overdue = int(grp["is_overdue"].sum())
        pct = within / open_cnt if open_cnt else 1.0
        result_rows.append({
            "Tag Category":  cat,
            "Tag Value":     val,
            "Open Vulns":    open_cnt,
            "Within SLA":    within,
            "Overdue":       overdue,
            "% Within SLA":  fmt_pct(pct),
        })

    return (
        pd.DataFrame(result_rows)
        .sort_values("% Within SLA", ascending=True)  # worst compliance first
        .reset_index(drop=True)
    )


def _compute_recurring_count(df: pd.DataFrame) -> int:
    """
    Count vulnerabilities that are in state 'reopened' — previously fixed
    but re-discovered.
    """
    if df.empty or "state" not in df.columns:
        return 0
    return int((df["state"].str.lower() == "reopened").sum())


def _compute_plugin_family_overdue(open_df: pd.DataFrame) -> pd.DataFrame:
    """
    Rank plugin families by overdue vulnerability instance count.

    Returns
    -------
    pd.DataFrame
        Columns: Plugin Family, Overdue Vulns, Total Open, Overdue %
        Sorted by Overdue Vulns descending.
    """
    if open_df.empty or "plugin_family" not in open_df.columns:
        return pd.DataFrame()

    rows = []
    for family, grp in open_df.groupby("plugin_family"):
        total    = len(grp)
        overdue  = int(grp["is_overdue"].sum())
        pct      = overdue / total if total else 0.0
        rows.append({
            "Plugin Family": family,
            "Overdue Vulns": overdue,
            "Total Open":    total,
            "Overdue %":     fmt_pct(pct),
        })

    if not rows:
        return pd.DataFrame()

    return (
        pd.DataFrame(rows)
        .sort_values("Overdue Vulns", ascending=False)
        .reset_index(drop=True)
    )


# ===========================================================================
# Phase 3 — Chart generation
# ===========================================================================

def _build_charts(metrics: dict, charts_dir: Path) -> list[dict]:
    """
    Generate the age distribution stacked bar chart.

    The stacked bar has age buckets on the X axis and severity counts stacked
    per bucket.  Colors map to the severity palette from config.py.

    Returns
    -------
    list[dict]
        Each entry: {name, png, html}
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    if metrics.get("empty"):
        return results

    age_dist = metrics["age_dist"]
    if age_dist.empty:
        return results

    # Build chart DataFrame: x = age bucket, stacked series = severities
    # Only include severity columns that have at least one non-zero value
    sev_cols_present = [
        sev for sev in ordered_severities()
        if sev in age_dist.columns and age_dist[sev].sum() > 0
    ]

    if not sev_cols_present:
        return results

    chart_df = age_dist[["age_bucket"] + sev_cols_present].copy()

    # Use stacked_bar_chart from chart_exporter — stack_cols = severity names
    # triggers automatic severity palette coloring inside the exporter.
    sev_colors = [SEVERITY_COLORS[s] for s in sev_cols_present]

    png, html = stacked_bar_chart(
        chart_df,
        "Vulnerability Age Distribution by Severity",
        charts_dir / "age_distribution",
        x_col="age_bucket",
        stack_cols=sev_cols_present,
        colors=sev_colors,
        xlabel="Age Bucket",
        ylabel="Open Vulnerabilities",
    )
    results.append({"name": "age_distribution", "png": png, "html": html})
    logger.debug("Chart written: %s", png)

    return results


# ===========================================================================
# Phase 4 — Excel workbook
# ===========================================================================

def _build_excel(
    metrics: dict,
    output_dir: Path,
    tag_filter: str,
    generated_at: datetime,
) -> Path:
    """
    Assemble the Excel workbook:
    - Age Distribution   — bucket counts per severity, row-color coded by age tier
    - Oldest Vulns       — top 20 oldest open vulns
    - Per-Tag Compliance — % within SLA by tag group (if available)
    - Plugin Families    — overdue count by plugin family
    - Metadata tab via export_to_excel()
    """
    sheets: list[dict] = []
    output_path = output_dir / f"{REPORT_SLUG}.xlsx"

    if metrics.get("empty"):
        sheets.append({
            "name": "Patch Compliance",
            "df": pd.DataFrame({"Message": ["No data returned for the selected scope."]}),
            "severity_col": None,
        })
        return export_to_excel(
            sheets=sheets, output_path=output_path,
            report_name=REPORT_NAME, tag_filter=tag_filter, generated_at=generated_at,
        )

    # ------------------------------------------------------------------
    # Tab 1: Age Distribution
    # ------------------------------------------------------------------
    age_dist = metrics["age_dist"].copy()

    # Build display DataFrame with renamed columns
    display_cols = ["age_bucket"] + ordered_severities() + ["total"]
    available    = [c for c in display_cols if c in age_dist.columns]
    age_display  = age_dist[available + ["color_tier"]].rename(columns={
        "age_bucket": "Age Bucket",
        "critical":   "Critical",
        "high":       "High",
        "medium":     "Medium",
        "low":        "Low",
        "total":      "Total",
        "color_tier": "_color",  # used for row coloring; hidden via exporter
    })

    sheets.append({
        "name":         "Age Distribution",
        "df":           age_display,
        "title":        "Vulnerability Age Distribution by Severity",
        "severity_col": "_color",   # maps bucket rows to severity fill colors
    })

    # ------------------------------------------------------------------
    # Tab 2: Oldest Vulnerabilities
    # ------------------------------------------------------------------
    top20 = metrics["top20_oldest"]
    if not top20.empty:
        rename_map = {
            "asset_hostname": "Hostname",
            "asset_ipv4":     "IPv4",
            "plugin_name":    "Plugin Name",
            "plugin_id":      "Plugin ID",
            "plugin_family":  "Plugin Family",
            "cve_list":       "CVEs",
            "vpr_score":      "VPR Score",
            "severity":       "Severity",
            "first_found":    "First Found",
            "days_open":      "Days Open",
            "sla_status":     "SLA Status",
            "days_remaining": "Days Remaining",
        }
        top20_display = top20.rename(columns={k: v for k, v in rename_map.items() if k in top20.columns})
        sheets.append({
            "name":             "Oldest Vulnerabilities",
            "df":               top20_display,
            "title":            "Top 20 Oldest Unpatched Vulnerabilities",
            "severity_col":     "Severity" if "Severity" in top20_display.columns else None,
            "sla_formatting":   True,
            "sla_status_col":   "SLA Status",
        })

    # ------------------------------------------------------------------
    # Tab 3: Per-Tag Compliance
    # ------------------------------------------------------------------
    tag_comp = metrics["tag_compliance"]
    if not tag_comp.empty:
        sheets.append({
            "name":         "Per-Tag Compliance",
            "df":           tag_comp,
            "title":        "Patch Compliance Score by Tag Group (% Within SLA)",
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Tab 4: Plugin Family Overdue Breakdown
    # ------------------------------------------------------------------
    family_od = metrics["family_overdue"]
    if not family_od.empty:
        sheets.append({
            "name":         "Plugin Families",
            "df":           family_od,
            "title":        "Overdue Vulnerabilities by Plugin Family",
            "severity_col": None,
        })

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

    if metrics.get("empty"):
        sections.append({
            "heading": "Patch Compliance Summary",
            "text": "No vulnerability data was returned for the selected scope.",
        })
    else:
        total       = metrics["total_open"]
        total_od    = metrics["total_overdue"]
        recurring   = metrics["recurring_count"]
        od_pct      = total_od / total if total else 0.0

        # ------------------------------------------------------------------
        # Section 1: Compliance scorecard + age chart
        # ------------------------------------------------------------------
        intro_lines = [
            f"<strong>Total Open Vulnerabilities:</strong> {fmt_int(total)} &nbsp;|&nbsp; "
            f"<strong>Overdue:</strong> {fmt_int(total_od)} ({fmt_pct(od_pct)})",
            f"<strong>Recurring Vulnerabilities (re-opened):</strong> {fmt_int(recurring)}",
        ]
        sections.append({
            "heading":         "Patch Compliance Scorecard",
            "text":            "<br/>".join(intro_lines),
            "dataframe":       metrics["compliance_tbl"][[
                "Severity", "Open", "Within SLA", "Overdue",
                "% Within SLA", "% Overdue", "SLA Window (days)",
            ]],
            "severity_col":    "Severity",
            "chart_png_path":  _chart_png("age_distribution"),
        })

        # ------------------------------------------------------------------
        # Section 2: Age distribution table
        # ------------------------------------------------------------------
        age_dist = metrics["age_dist"]
        if not age_dist.empty:
            display_cols = ["age_bucket"] + [
                s for s in ordered_severities() if s in age_dist.columns
            ] + (["total"] if "total" in age_dist.columns else [])
            age_display = age_dist[display_cols].rename(columns={
                "age_bucket": "Age Bucket",
                "critical": "Critical", "high": "High",
                "medium": "Medium", "low": "Low", "total": "Total",
            })
            sections.append({
                "heading":  "Vulnerability Age Distribution",
                "text":     (
                    "Open vulnerabilities bucketed by days since first discovery. "
                    "Counts exceeding the SLA window for each severity tier indicate "
                    "patch compliance gaps."
                ),
                "dataframe": age_display,
                "severity_col": None,
            })

        # ------------------------------------------------------------------
        # Section 3: Top 20 oldest
        # ------------------------------------------------------------------
        top20 = metrics["top20_oldest"]
        if not top20.empty:
            rename_map = {
                "asset_hostname": "Hostname",
                "asset_ipv4":     "IPv4",
                "plugin_name":    "Plugin Name",
                "cve_list":       "CVEs",
                "severity":       "Severity",
                "days_open":      "Days Open",
                "sla_status":     "SLA Status",
            }
            top20_pdf = top20.rename(columns={
                k: v for k, v in rename_map.items() if k in top20.columns
            })[[v for v in rename_map.values() if v in top20.rename(columns=rename_map).columns]]
            sections.append({
                "heading":  "Top 20 Oldest Unpatched Vulnerabilities",
                "text":     (
                    "Sorted by days open descending. Full detail including CVEs, "
                    "plugin family, and SLA dates is in the Excel attachment."
                ),
                "dataframe":     top20_pdf,
                "severity_col":  "Severity" if "Severity" in top20_pdf.columns else None,
            })

        # ------------------------------------------------------------------
        # Section 4: Plugin family overdue summary
        # ------------------------------------------------------------------
        family_od = metrics["family_overdue"]
        if not family_od.empty:
            sections.append({
                "heading":   "Overdue Vulnerabilities by Plugin Family",
                "text":      (
                    "Plugin families contributing most to overdue vulnerability count. "
                    "Use this to target patch efforts by technology area."
                ),
                "dataframe":     family_od,
                "severity_col":  None,
            })

        # ------------------------------------------------------------------
        # Section 5: Per-tag compliance (if populated)
        # ------------------------------------------------------------------
        tag_comp = metrics["tag_compliance"]
        if not tag_comp.empty:
            sections.append({
                "heading":   "Patch Compliance by Tag Group",
                "dataframe": tag_comp,
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
) -> dict:
    """
    Run the Patch Compliance & Vulnerability Age report end-to-end.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Cache key — share this value across all reports in one group execution.
    tag_category, tag_value : str, optional
        Tag filter for asset scoping.
    output_dir : Path, optional
        Directory for all output files.  Defaults to OUTPUT_DIR/<run_id>/<slug>/.
    generated_at : datetime, optional
        Override the report timestamp (defaults to UTC now).

    Returns
    -------
    dict
        {"pdf": Path, "excel": Path, "charts": [Path, ...]}
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if output_dir is None:
        output_dir = OUTPUT_DIR / safe_filename(run_id) / REPORT_SLUG
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    charts_dir = output_dir / "charts"
    scope_str  = f"{tag_category} = {tag_value}" if tag_category and tag_value else "All Assets"

    logger.info("=== %s | scope=%s | run_id=%s ===", REPORT_NAME, scope_str, run_id)

    # Phase 1: data
    df, assets_df = _fetch_and_prepare(tio, run_id, tag_category, tag_value)

    # Phase 2: metrics
    metrics = _compute_metrics(df, assets_df, tag_category)

    # Phase 3: charts
    charts = _build_charts(metrics, charts_dir)

    # Phase 4: Excel
    excel_path = _build_excel(metrics, output_dir, scope_str, generated_at)
    logger.info("Excel written: %s", excel_path)

    # Phase 5: PDF
    pdf_path = _build_pdf(metrics, charts, output_dir, scope_str, generated_at)
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
  python reports/patch_compliance.py
  python reports/patch_compliance.py --tag-category "Business Unit" --tag-value "Finance"
  python reports/patch_compliance.py --output-dir output/test/ --run-id 2026-03-20
        """,
    )
    parser.add_argument("--tag-category", default=None, metavar="CATEGORY",
                        help="Tenable tag category for asset scoping")
    parser.add_argument("--tag-value",    default=None, metavar="VALUE",
                        help="Tenable tag value for asset scoping")
    parser.add_argument("--output-dir",   default=None, metavar="DIR",
                        help="Output directory (default: output/<run-id>/patch_compliance/)")
    parser.add_argument("--run-id",       default=None, metavar="ID",
                        help="Cache key / run identifier (default: today YYYY-MM-DD)")
    parser.add_argument("--no-cache",     action="store_true",
                        help="Purge existing parquet cache before fetching")

    args = parser.parse_args()

    run_id = args.run_id or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    out    = Path(args.output_dir) if args.output_dir else None

    if args.no_cache:
        from config import CACHE_DIR
        for f in CACHE_DIR.glob(f"{run_id}_vulns_*.parquet"):
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
    )

    print(f"\nReport complete:")
    print(f"  PDF:    {result['pdf']}")
    print(f"  Excel:  {result['excel']}")
    print(f"  Charts: {len(result['charts'])} file(s)")
    for p in result["charts"]:
        print(f"    {p}")
