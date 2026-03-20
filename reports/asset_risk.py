"""
reports/asset_risk.py — Asset Risk Scoring report.

Audience: Security Analysts + IT

Metrics produced
----------------
- Per-asset risk score: (Critical×10) + (High×5) + (Medium×2) + (Low×1)
  Severity derived exclusively from VPR score via config.vpr_to_severity().
- Top 25 highest-risk assets: hostname, IPv4, tags, score, severity breakdown,
  CVSS v3 average
- Risk score distribution histogram (bucketed)
- Clean assets (zero open vulnerabilities)
- Average risk score grouped by tag category/value
- CVSS averages per asset and per tag group

Outputs
-------
- Excel: Risk Summary tab + Top 25 Riskiest tab (risk-tier colored) +
         All Assets tab + Tag Group Averages tab + Clean Assets tab
- PDF:   Cover page + top-asset bar chart + histogram + tag group table +
         clean assets note
- Charts: Plotly horizontal bar (Top 25 by risk score)
          Matplotlib PNG histogram (risk score distribution)

CLI
---
python reports/asset_risk.py [options]
  --tag-category  CATEGORY  Tag category for asset scoping (e.g. "Environment")
  --tag-value     VALUE     Tag value for asset scoping   (e.g. "Production")
  --output-dir    DIR       Base output directory
  --run-id        ID        Cache key (default: today YYYY-MM-DD)
  --no-cache                Purge parquet cache before fetching
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
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    RISK_TIER_THRESHOLDS,
    RISK_WEIGHTS,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
)
from data.fetchers import enrich_vulns_with_assets, fetch_assets, fetch_vulnerabilities
from exporters.chart_exporter import horizontal_bar_chart, save_matplotlib_figure
from exporters.excel_exporter import export_to_excel
from exporters.pdf_exporter import build_pdf
from utils.formatters import (
    fmt_int,
    fmt_pct,
    ordered_severities,
    risk_tier,
    risk_tier_fill_color,
    safe_filename,
    severity_label,
)
from utils.sla_calculator import apply_sla_to_df

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "Asset Risk Scoring"
REPORT_SLUG = "asset_risk"

# Risk score histogram buckets: (label, lo_inclusive, hi_inclusive)
_RISK_BUCKETS: list[tuple[str, int, int]] = [
    ("0 (Clean)",   0,   0),
    ("1–10",        1,   10),
    ("11–50",       11,  50),
    ("51–100",      51,  100),
    ("101–200",     101, 200),
    ("201+",        201, 999_999),
]

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
# Phase 1 — Fetch and prepare
# ===========================================================================

def _fetch_and_prepare(
    tio,
    run_id: str,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Fetch vulnerabilities and the full asset list, enrich, and apply SLA.

    Returns
    -------
    (enriched_vulns_df, raw_assets_df)
    The raw assets_df is kept separately so we can identify clean assets
    (those absent from the vuln export).
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
        "[%s] Prepared %d records across %d assets.",
        REPORT_NAME, len(df), df["asset_id"].nunique(),
    )
    return df, assets_df


# ===========================================================================
# Phase 2 — Risk score computation
# ===========================================================================

def _compute_asset_scores(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Compute a risk score for every asset and return a ranked DataFrame.

    Open vulnerabilities only (remediated rows excluded).
    Severity is the VPR-derived ``severity`` column — never ``severity_native``.

    Returns
    -------
    pd.DataFrame
        One row per asset_id.  Columns:
        rank, asset_id, asset_hostname, asset_ipv4, asset_fqdn,
        risk_score, risk_tier, critical, high, medium, low,
        total_vulns, avg_cvss_v3, avg_cvss, tags
    """
    if df.empty:
        return pd.DataFrame()

    open_df = df[~df["remediated"]].copy()
    open_df["_risk_pts"] = open_df["severity"].str.lower().map(RISK_WEIGHTS).fillna(0)

    agg = (
        open_df.groupby(["asset_id", "asset_hostname", "asset_ipv4", "asset_fqdn"])
        .agg(
            risk_score    = ("_risk_pts",        "sum"),
            critical      = ("severity",         lambda s: int((s == "critical").sum())),
            high          = ("severity",         lambda s: int((s == "high").sum())),
            medium        = ("severity",         lambda s: int((s == "medium").sum())),
            low           = ("severity",         lambda s: int((s == "low").sum())),
            total_vulns   = ("severity",         "count"),
            avg_cvss_v3   = ("cvss_v3_base_score", lambda s: round(s.dropna().mean(), 2) if s.notna().any() else None),
            avg_cvss      = ("cvss_base_score",    lambda s: round(s.dropna().mean(), 2) if s.notna().any() else None),
        )
        .reset_index()
    )

    agg["risk_score"] = agg["risk_score"].astype(int)
    agg["risk_tier"]  = agg["risk_score"].apply(risk_tier)

    # Attach tags from assets_df (join on asset_id)
    if not assets_df.empty and "tags" in assets_df.columns:
        agg = agg.merge(
            assets_df[["asset_id", "tags"]].rename(columns={"asset_id": "asset_id"}),
            on="asset_id",
            how="left",
        )
    else:
        agg["tags"] = ""

    agg = agg.sort_values("risk_score", ascending=False).reset_index(drop=True)
    agg["rank"] = agg.index + 1

    return agg[[
        "rank", "asset_id", "asset_hostname", "asset_ipv4", "asset_fqdn",
        "risk_score", "risk_tier", "critical", "high", "medium", "low",
        "total_vulns", "avg_cvss_v3", "avg_cvss", "tags",
    ]]


def _identify_clean_assets(
    asset_scores: pd.DataFrame,
    assets_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Return assets from assets_df that have no open vulnerabilities.

    Parameters
    ----------
    asset_scores : pd.DataFrame
        Output of _compute_asset_scores() — only assets WITH vulns.
    assets_df : pd.DataFrame
        Full asset export from fetch_assets().
    """
    if assets_df.empty:
        return pd.DataFrame()

    scored_ids = set(asset_scores["asset_id"]) if not asset_scores.empty else set()
    clean = assets_df[~assets_df["asset_id"].isin(scored_ids)].copy()

    display_cols = [c for c in ["asset_id", "hostname", "ipv4", "fqdn",
                                "operating_system", "last_seen", "tags"]
                   if c in clean.columns]
    return clean[display_cols].reset_index(drop=True)


def _compute_tag_group_averages(
    asset_scores: pd.DataFrame,
    tag_category: Optional[str] = None,
) -> pd.DataFrame:
    """
    Parse the tags column and compute average + total risk score by tag group.

    If *tag_category* is provided, only show groups for that category.
    Otherwise, show groups for all categories found in the data.

    Returns
    -------
    pd.DataFrame
        Columns: tag_category, tag_value, asset_count, avg_risk_score,
                 total_risk_score, avg_cvss_v3
    """
    if asset_scores.empty or "tags" not in asset_scores.columns:
        return pd.DataFrame()

    # Expand semicolon-delimited tag strings to long format
    rows: list[dict] = []
    for _, row in asset_scores.iterrows():
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
            rows.append({
                "asset_id":    row["asset_id"],
                "risk_score":  row["risk_score"],
                "avg_cvss_v3": row["avg_cvss_v3"],
                "tag_cat":     cat,
                "tag_val":     val,
            })

    if not rows:
        return pd.DataFrame()

    long_df = pd.DataFrame(rows)

    if tag_category:
        long_df = long_df[long_df["tag_cat"].str.lower() == tag_category.lower()]

    if long_df.empty:
        return pd.DataFrame()

    grouped = (
        long_df.groupby(["tag_cat", "tag_val"])
        .agg(
            asset_count      = ("asset_id",    "nunique"),
            avg_risk_score   = ("risk_score",  lambda s: round(s.mean(), 1)),
            total_risk_score = ("risk_score",  "sum"),
            avg_cvss_v3      = ("avg_cvss_v3", lambda s: round(s.dropna().mean(), 2)
                                               if s.notna().any() else None),
        )
        .reset_index()
        .sort_values("avg_risk_score", ascending=False)
        .rename(columns={"tag_cat": "Tag Category", "tag_val": "Tag Value",
                         "asset_count": "Assets", "avg_risk_score": "Avg Risk Score",
                         "total_risk_score": "Total Risk Score",
                         "avg_cvss_v3": "Avg CVSS v3"})
        .reset_index(drop=True)
    )

    return grouped


def _compute_risk_histogram(asset_scores: pd.DataFrame) -> pd.DataFrame:
    """
    Count assets in each risk score bucket.

    Returns
    -------
    pd.DataFrame
        Columns: bucket, asset_count, pct
    """
    if asset_scores.empty:
        return pd.DataFrame(columns=["bucket", "asset_count", "pct"])

    total = len(asset_scores)
    rows = []
    for label, lo, hi in _RISK_BUCKETS:
        count = int(((asset_scores["risk_score"] >= lo) &
                     (asset_scores["risk_score"] <= hi)).sum())
        rows.append({"bucket": label, "asset_count": count,
                     "pct": round(count / total * 100, 1) if total else 0.0})
    return pd.DataFrame(rows)


# ===========================================================================
# Phase 3 — Metrics dict
# ===========================================================================

def _compute_metrics(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    tag_category: Optional[str],
) -> dict:
    """Aggregate all outputs needed by downstream phases."""
    if df.empty and assets_df.empty:
        return {"empty": True}

    asset_scores = _compute_asset_scores(df, assets_df)
    clean_assets = _identify_clean_assets(asset_scores, assets_df)
    tag_groups   = _compute_tag_group_averages(asset_scores, tag_category)
    histogram    = _compute_risk_histogram(asset_scores)

    total_assets  = len(asset_scores) + len(clean_assets)
    avg_risk      = round(asset_scores["risk_score"].mean(), 1) if not asset_scores.empty else 0.0
    max_risk      = int(asset_scores["risk_score"].max()) if not asset_scores.empty else 0
    tier_counts   = asset_scores["risk_tier"].value_counts().to_dict() if not asset_scores.empty else {}

    return {
        "empty":        df.empty,
        "asset_scores": asset_scores,
        "top25":        asset_scores.head(25),
        "clean_assets": clean_assets,
        "tag_groups":   tag_groups,
        "histogram":    histogram,
        "total_assets": total_assets,
        "scored_count": len(asset_scores),
        "clean_count":  len(clean_assets),
        "avg_risk":     avg_risk,
        "max_risk":     max_risk,
        "tier_counts":  tier_counts,
    }


# ===========================================================================
# Phase 4 — Charts
# ===========================================================================

def _build_charts(metrics: dict, charts_dir: Path) -> list[dict]:
    """
    Generate:
    1. Plotly horizontal bar — Top 25 assets by risk score
    2. Matplotlib PNG — risk score distribution histogram
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    if metrics["empty"] or metrics["asset_scores"].empty:
        return results

    top25 = metrics["top25"].copy()

    # ------------------------------------------------------------------
    # Chart 1: Horizontal bar — Top 25 by risk score
    # ------------------------------------------------------------------
    # Label = "hostname (IPv4)" truncated to 40 chars
    top25["label"] = (
        top25["asset_hostname"].fillna(top25["asset_ipv4"])
        .str[:35]
        + top25["asset_ipv4"].apply(lambda ip: f" ({ip})" if pd.notna(ip) and ip else "")
    ).str[:45]

    # Color each bar by its risk tier (maps to severity colors)
    top25["_color_key"] = top25["risk_tier"].replace({"none": "info"})

    png, html = horizontal_bar_chart(
        top25,
        "Top 25 Highest-Risk Assets (VPR-Derived Score)",
        charts_dir / "top25_assets",
        label_col="label",
        value_col="risk_score",
        color_col="_color_key",
        xlabel="Risk Score",
        max_rows=25,
    )
    results.append({"name": "top25_bar", "png": png, "html": html})

    # ------------------------------------------------------------------
    # Chart 2: Risk score distribution histogram (Matplotlib)
    # ------------------------------------------------------------------
    hist_df = metrics["histogram"]
    if not hist_df.empty:
        fig, ax = plt.subplots(figsize=(9, 4))
        bucket_colors = [
            "#388e3c",   # 0 Clean
            "#8bc34a",   # 1-10
            "#fbc02d",   # 11-50
            "#f57c00",   # 51-100
            "#d32f2f",   # 101-200
            "#7b1fa2",   # 201+
        ]
        bars = ax.bar(
            hist_df["bucket"],
            hist_df["asset_count"],
            color=bucket_colors[: len(hist_df)],
            width=0.6,
            zorder=2,
        )
        ax.set_title("Asset Risk Score Distribution", fontweight="bold")
        ax.set_xlabel("Risk Score Bucket")
        ax.set_ylabel("Number of Assets")
        ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=1)
        for bar, pct in zip(bars, hist_df["pct"]):
            h = bar.get_height()
            if h > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    h + max(hist_df["asset_count"].max() * 0.01, 0.3),
                    f"{int(h):,}\n({pct:.0f}%)",
                    ha="center", va="bottom", fontsize=9,
                )
        hist_png = save_matplotlib_figure(fig, charts_dir / "risk_histogram")
        results.append({"name": "risk_histogram", "png": hist_png, "html": None})

    return results


# ===========================================================================
# Phase 5 — Excel workbook
# ===========================================================================

def _build_excel(
    metrics: dict,
    output_dir: Path,
    tag_filter: str,
    generated_at: datetime,
) -> Path:
    """
    Sheets:
    - Risk Summary   : overall stats + histogram table
    - Top 25 Riskiest: top 25 with risk-tier color coding
    - All Assets     : full scored list
    - Tag Group Avgs : average risk by tag category/value
    - Clean Assets   : zero-vuln assets
    """
    sheets: list[dict] = []

    if metrics["empty"]:
        sheets.append({
            "name": "Risk Summary",
            "df": pd.DataFrame({"Message": ["No data returned for the selected scope."]}),
            "severity_col": None,
        })
        return export_to_excel(
            sheets=sheets, output_path=output_dir / f"{REPORT_SLUG}.xlsx",
            report_name=REPORT_NAME, tag_filter=tag_filter, generated_at=generated_at,
        )

    # ------------------------------------------------------------------
    # Sheet 1: Risk Summary
    # ------------------------------------------------------------------
    tier_counts = metrics["tier_counts"]
    hist_df     = metrics["histogram"]
    summary_rows = [
        {"Metric": "Total Assets in Scope",  "Value": fmt_int(metrics["total_assets"])},
        {"Metric": "Assets with Open Vulns", "Value": fmt_int(metrics["scored_count"])},
        {"Metric": "Clean Assets (0 vulns)", "Value": fmt_int(metrics["clean_count"])},
        {"Metric": "Avg Risk Score",         "Value": str(metrics["avg_risk"])},
        {"Metric": "Max Risk Score",         "Value": fmt_int(metrics["max_risk"])},
        {"Metric": "", "Value": ""},
        {"Metric": "── Risk Tier Breakdown ──", "Value": ""},
        {"Metric": "Critical Tier (score ≥50)", "Value": fmt_int(tier_counts.get("critical", 0))},
        {"Metric": "High Tier (20–49)",         "Value": fmt_int(tier_counts.get("high", 0))},
        {"Metric": "Medium Tier (5–19)",         "Value": fmt_int(tier_counts.get("medium", 0))},
        {"Metric": "Low Tier (1–4)",             "Value": fmt_int(tier_counts.get("low", 0))},
        {"Metric": "None (score = 0)",           "Value": fmt_int(tier_counts.get("none", 0))},
    ]
    sheets.append({
        "name": "Risk Summary",
        "df": pd.DataFrame(summary_rows),
        "title": f"{REPORT_NAME} — Summary",
        "severity_col": None,
    })

    # ------------------------------------------------------------------
    # Sheet 2: Top 25 Riskiest (risk-tier color via risk_tier column)
    # ------------------------------------------------------------------
    top25_display = metrics["top25"].rename(columns={
        "rank": "Rank", "asset_hostname": "Hostname", "asset_ipv4": "IPv4",
        "asset_fqdn": "FQDN", "risk_score": "Risk Score", "risk_tier": "Risk Tier",
        "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
        "total_vulns": "Total Vulns", "avg_cvss_v3": "Avg CVSS v3",
        "avg_cvss": "Avg CVSS v2", "tags": "Tags",
    })
    sheets.append({
        "name": "Top 25 Riskiest",
        "df": top25_display,
        "title": "Top 25 Highest-Risk Assets",
        "severity_col": "Risk Tier",   # risk_tier values match severity fill color keys
    })

    # ------------------------------------------------------------------
    # Sheet 3: All Assets (full scored list)
    # ------------------------------------------------------------------
    all_display = metrics["asset_scores"].rename(columns={
        "rank": "Rank", "asset_hostname": "Hostname", "asset_ipv4": "IPv4",
        "asset_fqdn": "FQDN", "risk_score": "Risk Score", "risk_tier": "Risk Tier",
        "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
        "total_vulns": "Total Vulns", "avg_cvss_v3": "Avg CVSS v3",
        "avg_cvss": "Avg CVSS v2", "tags": "Tags",
    })
    sheets.append({
        "name": "All Assets",
        "df": all_display,
        "title": "All Assets with Open Vulnerabilities — Risk Scores",
        "severity_col": "Risk Tier",
    })

    # ------------------------------------------------------------------
    # Sheet 4: Tag Group Averages
    # ------------------------------------------------------------------
    tag_groups = metrics["tag_groups"]
    if not tag_groups.empty:
        sheets.append({
            "name": "Tag Group Avgs",
            "df": tag_groups,
            "title": "Average Risk Score by Tag Category / Value",
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Sheet 5: Clean Assets
    # ------------------------------------------------------------------
    clean = metrics["clean_assets"]
    if not clean.empty:
        clean_display = clean.rename(columns={
            "hostname": "Hostname", "ipv4": "IPv4", "fqdn": "FQDN",
            "operating_system": "OS", "last_seen": "Last Seen", "tags": "Tags",
        })
        sheets.append({
            "name": "Clean Assets",
            "df": clean_display,
            "title": "Clean Assets — No Open Vulnerabilities",
            "severity_col": None,
        })

    return export_to_excel(
        sheets=sheets,
        output_path=output_dir / f"{REPORT_SLUG}.xlsx",
        report_name=REPORT_NAME,
        tag_filter=tag_filter,
        generated_at=generated_at,
    )


# ===========================================================================
# Phase 6 — PDF report
# ===========================================================================

def _build_pdf(
    metrics: dict,
    charts: list[dict],
    output_dir: Path,
    scope_str: str,
    generated_at: datetime,
) -> Path:
    sections: list[dict] = []

    def _chart_png(name: str) -> Optional[Path]:
        for c in charts:
            if c["name"] == name:
                return c["png"]
        return None

    if metrics["empty"]:
        sections.append({
            "heading": "Asset Risk Scoring",
            "text": "No data returned for the selected scope.",
        })
    else:
        # Section 1: summary + top25 bar
        intro = (
            f"<strong>Total Assets in Scope:</strong> {fmt_int(metrics['total_assets'])} &nbsp;|&nbsp; "
            f"<strong>With Open Vulns:</strong> {fmt_int(metrics['scored_count'])} &nbsp;|&nbsp; "
            f"<strong>Clean:</strong> {fmt_int(metrics['clean_count'])}<br/>"
            f"<strong>Average Risk Score:</strong> {metrics['avg_risk']} &nbsp;|&nbsp; "
            f"<strong>Maximum Risk Score:</strong> {fmt_int(metrics['max_risk'])}"
        )
        sections.append({
            "heading": "Top 25 Highest-Risk Assets",
            "text": intro,
            "chart_png_path": _chart_png("top25_bar"),
        })

        # Section 2: top25 table
        top25_display = metrics["top25"][[
            "rank", "asset_hostname", "asset_ipv4", "risk_score", "risk_tier",
            "critical", "high", "medium", "low", "avg_cvss_v3",
        ]].rename(columns={
            "rank": "Rank", "asset_hostname": "Hostname", "asset_ipv4": "IPv4",
            "risk_score": "Score", "risk_tier": "Tier",
            "critical": "Crit", "high": "High", "medium": "Med", "low": "Low",
            "avg_cvss_v3": "Avg CVSSv3",
        })
        sections.append({
            "heading": "",
            "dataframe": top25_display,
            "severity_col": "Tier",
        })

        # Section 3: histogram
        sections.append({
            "heading": "Risk Score Distribution",
            "text": "Number of assets in each risk score tier.",
            "chart_png_path": _chart_png("risk_histogram"),
        })

        # Section 4: tag group averages
        if not metrics["tag_groups"].empty:
            sections.append({
                "heading": "Average Risk Score by Tag Group",
                "dataframe": metrics["tag_groups"],
                "severity_col": None,
            })

        # Section 5: clean assets count
        clean_count = metrics["clean_count"]
        sections.append({
            "heading": "Clean Assets",
            "text": (
                f"{fmt_int(clean_count)} asset(s) in scope have no open vulnerabilities. "
                f"Full list is available in the Excel attachment (Clean Assets tab)."
            ),
        })

    return build_pdf(
        report_title=REPORT_NAME,
        scope_str=scope_str,
        sections=sections,
        output_path=output_dir / f"{REPORT_SLUG}.pdf",
        generated_at=generated_at,
    )


# ===========================================================================
# Orchestrator
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
    Run the Asset Risk Scoring report end-to-end.

    Returns
    -------
    dict  {"pdf": Path, "excel": Path, "charts": [Path, ...]}
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

    df, assets_df = _fetch_and_prepare(tio, run_id, tag_category, tag_value)
    metrics       = _compute_metrics(df, assets_df, tag_category)
    charts        = _build_charts(metrics, charts_dir)
    excel_path    = _build_excel(metrics, output_dir, scope_str, generated_at)
    pdf_path      = _build_pdf(metrics, charts, output_dir, scope_str, generated_at)

    chart_pngs = [c["png"] for c in charts if c.get("png")]
    logger.info(
        "=== %s complete — pdf=%s excel=%s charts=%d ===",
        REPORT_NAME, pdf_path.name, excel_path.name, len(chart_pngs),
    )
    return {"pdf": pdf_path, "excel": excel_path, "charts": chart_pngs}


# ===========================================================================
# CLI entry point
# ===========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{REPORT_NAME} — standalone CLI runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reports/asset_risk.py
  python reports/asset_risk.py --tag-category "Environment" --tag-value "Production"
  python reports/asset_risk.py --output-dir output/test/ --run-id 2026-03-20
        """,
    )
    parser.add_argument("--tag-category", default=None, metavar="CATEGORY")
    parser.add_argument("--tag-value",    default=None, metavar="VALUE")
    parser.add_argument("--output-dir",   default=None, metavar="DIR")
    parser.add_argument("--run-id",       default=None, metavar="ID")
    parser.add_argument("--no-cache",     action="store_true")
    args = parser.parse_args()

    run_id = args.run_id or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    out    = Path(args.output_dir) if args.output_dir else None

    if args.no_cache:
        from config import CACHE_DIR
        for f in CACHE_DIR.glob(f"{run_id}_*.parquet"):
            f.unlink(); logger.info("Purged: %s", f)

    from tenable_client import get_client
    tio = get_client()

    result = run_report(tio=tio, run_id=run_id,
                        tag_category=args.tag_category, tag_value=args.tag_value,
                        output_dir=out)
    print(f"\nReport complete:")
    print(f"  PDF:    {result['pdf']}")
    print(f"  Excel:  {result['excel']}")
    for p in result["charts"]:
        print(f"  Chart:  {p}")
