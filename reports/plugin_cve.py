"""
reports/plugin_cve.py — Plugin / CVE Breakdown report.

Audience: Security Analysts

Metrics produced
----------------
- Top 25 plugins by affected asset count: plugin_id, name, family, severity,
  CVSS, CVE list, asset count, exploit_available, days oldest open, SLA status
- Top 25 CVEs by CVSS score: CVE ID, CVSS, affected plugin count, asset count,
  severity, exploit_available, SLA status
- Plugin family distribution: unique plugin count + total instances per family
- Exploitability summary: exploit_available=True count by severity
- CVSS >= 9.0 overdue items as highest-priority remediation targets
- Per-plugin asset detail for top 25 plugins (hostname, IP, tags, days_open,
  SLA status)

Outputs
-------
- Excel: Plugin Breakdown tab + CVE Detail tab + Family Distribution tab +
         Exploitable tab + High Priority (CVSS≥9 Overdue) tab
- PDF:   Narrative + top-plugin bar chart + plugin family donut chart
- Charts: Plotly donut (plugin families by instance count)
          Matplotlib horizontal bar (Top 25 plugins by asset count, colored
          by dominant severity)

Note on data availability
--------------------------
The vulnerability export uses ``state: ["open", "reopened"]`` — remediated
vulnerabilities are excluded.  SLA status is therefore based on days since
first_found relative to today's date; "Remediated" status does not appear.

CLI
---
python reports/plugin_cve.py [options]
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
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
)
from data.fetchers import (
    enrich_vulns_with_assets,
    fetch_all_assets,
    fetch_all_vulnerabilities,
    filter_by_tag,
)
from exporters.chart_exporter import donut_chart, horizontal_bar_chart, save_matplotlib_figure
from exporters.excel_exporter import export_to_excel
from exporters.pdf_exporter import build_pdf
from utils.formatters import (
    fmt_int,
    fmt_pct,
    ordered_severities,
    safe_filename,
    severity_label,
)
from utils.sla_calculator import apply_sla_to_df

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "Plugin / CVE Breakdown"
REPORT_SLUG = "plugin_cve"

_TOP_N = 25          # plugins and CVEs shown in top-N tables
_CVSS_HIGH_RISK = 9.0  # threshold for high-priority CVSS section

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
    cache_dir: Path,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Fetch vulnerabilities and the full asset list, enrich, and apply SLA.

    Returns
    -------
    (enriched_vulns_df, raw_assets_df)
    """
    logger.info("[%s] Fetching vulnerability data…", REPORT_NAME)
    vulns_df = fetch_all_vulnerabilities(tio, cache_dir)

    logger.info("[%s] Fetching asset data…", REPORT_NAME)
    assets_df = fetch_all_assets(tio, cache_dir)

    if vulns_df.empty:
        logger.warning("[%s] No vulnerabilities returned.", REPORT_NAME)
        assets_df = filter_by_tag(assets_df, tag_category, tag_value)
        return vulns_df, assets_df

    df = enrich_vulns_with_assets(vulns_df, assets_df)
    df = filter_by_tag(df, tag_category, tag_value)
    assets_df = filter_by_tag(assets_df, tag_category, tag_value)

    if df.empty:
        logger.warning("[%s] No vulnerabilities match tag filter.", REPORT_NAME)
        return df, assets_df

    df = apply_sla_to_df(df)

    logger.info(
        "[%s] Prepared %d records | %d unique plugins | %d assets.",
        REPORT_NAME,
        len(df),
        df["plugin_id"].nunique(),
        df["asset_uuid"].nunique(),
    )
    return df, assets_df


# ===========================================================================
# Phase 2 — Compute metrics
# ===========================================================================

def _compute_top_plugins(df: pd.DataFrame) -> pd.DataFrame:
    """
    Top N plugins by unique asset count.

    Columns returned: plugin_id, plugin_name, plugin_family, severity,
    cvss_base_score, cvss3_score, cve_list, asset_count,
    exploit_available, oldest_days_open, oldest_sla_status.
    """
    if df.empty:
        return pd.DataFrame()

    # Prefer CVSS v3; fall back to v2
    def _cvss(sub: pd.DataFrame) -> float:
        v3 = sub["cvss3_score"].dropna()
        if not v3.empty:
            return round(float(v3.max()), 1)
        v2 = sub["cvss_base_score"].dropna()
        return round(float(v2.max()), 1) if not v2.empty else 0.0

    def _cve_list(sub: pd.DataFrame) -> str:
        cves: set[str] = set()
        for raw in sub["cve_list"].dropna():
            for cve in str(raw).split(","):
                cve = cve.strip()
                if cve:
                    cves.add(cve)
        return "; ".join(sorted(cves))

    rows = []
    for (pid, pname, pfam), grp in df.groupby(
        ["plugin_id", "plugin_name", "plugin_family"], sort=False
    ):
        asset_count = grp["asset_uuid"].nunique()
        exploit = bool(grp["exploit_available"].any())
        oldest_idx = grp["days_open"].idxmax() if "days_open" in grp.columns else None
        oldest_days = int(grp.loc[oldest_idx, "days_open"]) if oldest_idx is not None else 0
        oldest_sla = grp.loc[oldest_idx, "sla_status"] if oldest_idx is not None else ""
        # Dominant severity: most common in this plugin group
        dom_sev = grp["severity"].mode().iloc[0] if not grp["severity"].empty else "info"

        rows.append({
            "plugin_id": pid,
            "plugin_name": pname,
            "plugin_family": pfam,
            "severity": dom_sev,
            "cvss_score": _cvss(grp),
            "cve_list": _cve_list(grp),
            "asset_count": asset_count,
            "instance_count": len(grp),
            "exploit_available": "Yes" if exploit else "No",
            "oldest_days_open": oldest_days,
            "oldest_sla_status": oldest_sla,
        })

    result = (
        pd.DataFrame(rows)
        .sort_values("asset_count", ascending=False)
        .head(_TOP_N)
        .reset_index(drop=True)
    )
    result.insert(0, "rank", range(1, len(result) + 1))
    return result


def _compute_top_cves(df: pd.DataFrame) -> pd.DataFrame:
    """
    Top N CVEs by CVSS score.

    Explodes the cve_list column and groups by CVE ID.
    Columns: cve_id, cvss_score, plugin_count, asset_count, severity,
    exploit_available, oldest_sla_status.
    """
    if df.empty:
        return pd.DataFrame()

    exploded = df.copy()
    exploded["cve_id"] = exploded["cve_list"].fillna("").str.split(",")
    exploded = exploded.explode("cve_id")
    exploded["cve_id"] = exploded["cve_id"].str.strip()
    exploded = exploded[exploded["cve_id"] != ""]

    if exploded.empty:
        return pd.DataFrame()

    # Prefer CVSS v3 per row, fall back to v2
    exploded["_cvss"] = exploded["cvss3_score"].fillna(
        exploded["cvss_base_score"]
    ).fillna(0.0)

    rows = []
    for cve_id, grp in exploded.groupby("cve_id", sort=False):
        cvss = round(float(grp["_cvss"].max()), 1)
        plugin_count = grp["plugin_id"].nunique()
        asset_count = grp["asset_uuid"].nunique()
        dom_sev = grp["severity"].mode().iloc[0] if not grp["severity"].empty else "info"
        exploit = bool(grp["exploit_available"].any())
        oldest_idx = grp["days_open"].idxmax() if "days_open" in grp.columns else None
        oldest_sla = grp.loc[oldest_idx, "sla_status"] if oldest_idx is not None else ""

        rows.append({
            "cve_id": cve_id,
            "cvss_score": cvss,
            "plugin_count": plugin_count,
            "asset_count": asset_count,
            "severity": dom_sev,
            "exploit_available": "Yes" if exploit else "No",
            "oldest_sla_status": oldest_sla,
        })

    result = (
        pd.DataFrame(rows)
        .sort_values("cvss_score", ascending=False)
        .head(_TOP_N)
        .reset_index(drop=True)
    )
    result.insert(0, "rank", range(1, len(result) + 1))
    return result


def _compute_family_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """
    Plugin family breakdown: unique plugin count + total instance count per family.
    """
    if df.empty:
        return pd.DataFrame()

    result = (
        df.groupby("plugin_family")
        .agg(
            unique_plugins=("plugin_id", "nunique"),
            total_instances=("plugin_id", "count"),
        )
        .sort_values("total_instances", ascending=False)
        .reset_index()
        .rename(columns={"plugin_family": "Plugin Family"})
    )
    result.columns = ["Plugin Family", "Unique Plugins", "Total Instances"]
    return result


def _compute_exploitability(df: pd.DataFrame) -> pd.DataFrame:
    """
    Count of exploit_available=True findings, grouped by severity.
    """
    if df.empty:
        return pd.DataFrame()

    exploit_df = df[df["exploit_available"] == True].copy()  # noqa: E712
    if exploit_df.empty:
        return pd.DataFrame(
            {"Severity": [], "Exploitable Findings": [], "Unique Plugins": [], "Affected Assets": []}
        )

    sev_order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows = []
    for sev in ordered_severities(include_info=True):
        grp = exploit_df[exploit_df["severity"] == sev]
        if grp.empty:
            continue
        rows.append({
            "Severity": severity_label(sev),
            "_severity_key": sev,
            "Exploitable Findings": len(grp),
            "Unique Plugins": grp["plugin_id"].nunique(),
            "Affected Assets": grp["asset_uuid"].nunique(),
        })
    return pd.DataFrame(rows)


def _compute_high_priority(df: pd.DataFrame) -> pd.DataFrame:
    """
    CVSS >= 9.0 items that are SLA-overdue — highest-priority remediation targets.
    """
    if df.empty:
        return pd.DataFrame()

    # Use the best available CVSS score
    df = df.copy()
    df["_cvss"] = df["cvss3_score"].fillna(df["cvss_base_score"]).fillna(0.0)

    high_risk = df[
        (df["_cvss"] >= _CVSS_HIGH_RISK) & (df["sla_status"] == "Overdue")
    ].copy()

    if high_risk.empty:
        return pd.DataFrame()

    result = (
        high_risk[[
            "plugin_id", "plugin_name", "plugin_family", "severity",
            "_cvss", "cve_list", "hostname", "ipv4",
            "exploit_available", "days_open", "sla_status",
        ]]
        .sort_values(["_cvss", "days_open"], ascending=[False, False])
        .rename(columns={
            "plugin_id": "Plugin ID",
            "plugin_name": "Plugin Name",
            "plugin_family": "Family",
            "severity": "_severity_key",
            "_cvss": "CVSS",
            "cve_list": "CVEs",
            "hostname": "Hostname",
            "ipv4": "IPv4",
            "exploit_available": "Exploitable",
            "days_open": "Days Open",
            "sla_status": "SLA Status",
        })
        .reset_index(drop=True)
    )
    result["Exploitable"] = result["Exploitable"].map(
        lambda x: "Yes" if x is True or x == "Yes" else "No"
    )
    return result


def _compute_metrics(df: pd.DataFrame) -> dict:
    """
    Orchestrate all metric computations and return a single metrics dict.
    """
    if df.empty:
        return {
            "empty": True,
            "total_findings": 0,
            "total_plugins": 0,
            "total_assets": 0,
            "top_plugins": pd.DataFrame(),
            "top_cves": pd.DataFrame(),
            "family_dist": pd.DataFrame(),
            "exploitability": pd.DataFrame(),
            "high_priority": pd.DataFrame(),
        }

    return {
        "empty": False,
        "total_findings": len(df),
        "total_plugins": df["plugin_id"].nunique(),
        "total_assets": df["asset_uuid"].nunique(),
        "top_plugins": _compute_top_plugins(df),
        "top_cves": _compute_top_cves(df),
        "family_dist": _compute_family_distribution(df),
        "exploitability": _compute_exploitability(df),
        "high_priority": _compute_high_priority(df),
    }


# ===========================================================================
# Phase 3 — Build charts
# ===========================================================================

def _build_charts(metrics: dict, charts_dir: Path) -> list[dict]:
    """
    Charts
    ------
    1. Plotly donut  — plugin family distribution by instance count
    2. Matplotlib horizontal bar — Top 25 plugins by asset count (severity color)
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    if metrics["empty"]:
        return results

    # ------------------------------------------------------------------
    # Chart 1: Plugin family donut (Plotly)
    # ------------------------------------------------------------------
    family_df = metrics["family_dist"]
    if not family_df.empty:
        png, html = donut_chart(
            family_df,
            "Plugin Family Distribution (by Instance Count)",
            charts_dir / "plugin_family_donut",
            labels_col="Plugin Family",
            values_col="Total Instances",
        )
        results.append({"name": "family_donut", "png": png, "html": html})

    # ------------------------------------------------------------------
    # Chart 2: Top 25 plugins horizontal bar (Matplotlib)
    # ------------------------------------------------------------------
    top_plugins = metrics["top_plugins"]
    if not top_plugins.empty:
        # Build display label: truncate long names
        top_plugins = top_plugins.copy()
        top_plugins["_label"] = top_plugins["plugin_name"].str[:50].str.strip()
        # Color by dominant severity
        top_plugins["_color_key"] = top_plugins["severity"]

        png, html = horizontal_bar_chart(
            top_plugins,
            f"Top {_TOP_N} Plugins by Affected Asset Count",
            charts_dir / "top_plugins_bar",
            label_col="_label",
            value_col="asset_count",
            color_col="_color_key",
            xlabel="Unique Assets Affected",
            max_rows=_TOP_N,
        )
        results.append({"name": "top_plugins_bar", "png": png, "html": html})

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
    Sheets
    ------
    1. Plugin Breakdown      — Top 25 plugins; exploit rows highlighted
    2. CVE Detail            — Top 25 CVEs; CVSS >= 9 rows highlighted
    3. Family Distribution   — unique plugins + instances per family
    4. Exploitable           — exploit_available=True findings by severity
    5. High Priority         — CVSS >= 9.0 overdue items
    """
    sheets: list[dict] = []

    if metrics["empty"]:
        sheets.append({
            "name": "Plugin Breakdown",
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
    # Sheet 1: Plugin Breakdown
    # ------------------------------------------------------------------
    top_plugins = metrics["top_plugins"].copy()
    if not top_plugins.empty:
        # severity_col drives row fill; exploit rows will also be critical-colored
        # Use severity for coloring — exploitable plugins naturally bubble up
        plugin_display = top_plugins.rename(columns={
            "rank": "Rank",
            "plugin_id": "Plugin ID",
            "plugin_name": "Plugin Name",
            "plugin_family": "Family",
            "severity": "Severity",
            "cvss_score": "CVSS",
            "cve_list": "CVEs",
            "asset_count": "Assets Affected",
            "instance_count": "Total Findings",
            "exploit_available": "Exploitable",
            "oldest_days_open": "Oldest Days Open",
            "oldest_sla_status": "SLA Status",
        })
        sheets.append({
            "name": "Plugin Breakdown",
            "df": plugin_display,
            "title": f"Top {_TOP_N} Plugins by Affected Asset Count",
            "severity_col": "Severity",
            "sla_formatting": True,
            "sla_status_col": "SLA Status",
        })
    else:
        sheets.append({
            "name": "Plugin Breakdown",
            "df": pd.DataFrame({"Message": ["No plugin data available."]}),
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Sheet 2: CVE Detail
    # ------------------------------------------------------------------
    top_cves = metrics["top_cves"].copy()
    if not top_cves.empty:
        cve_display = top_cves.rename(columns={
            "rank": "Rank",
            "cve_id": "CVE ID",
            "cvss_score": "CVSS",
            "plugin_count": "Plugins Affected",
            "asset_count": "Assets Affected",
            "severity": "Severity",
            "exploit_available": "Exploitable",
            "oldest_sla_status": "SLA Status",
        })
        sheets.append({
            "name": "CVE Detail",
            "df": cve_display,
            "title": f"Top {_TOP_N} CVEs by CVSS Score",
            "severity_col": "Severity",
            "sla_formatting": True,
            "sla_status_col": "SLA Status",
        })
    else:
        sheets.append({
            "name": "CVE Detail",
            "df": pd.DataFrame({"Message": ["No CVE data available."]}),
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Sheet 3: Family Distribution
    # ------------------------------------------------------------------
    family_df = metrics["family_dist"]
    if not family_df.empty:
        sheets.append({
            "name": "Family Distribution",
            "df": family_df,
            "title": "Plugin Family Distribution",
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Sheet 4: Exploitable
    # ------------------------------------------------------------------
    exploit_df = metrics["exploitability"]
    if not exploit_df.empty:
        exploit_display = exploit_df.drop(columns=["_severity_key"], errors="ignore")
        sheets.append({
            "name": "Exploitable",
            "df": exploit_display,
            "title": "Exploitable Vulnerabilities by Severity",
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Sheet 5: High Priority (CVSS >= 9 Overdue)
    # ------------------------------------------------------------------
    high_df = metrics["high_priority"]
    if not high_df.empty:
        hp_display = high_df.drop(columns=["_severity_key"], errors="ignore")
        sheets.append({
            "name": "High Priority",
            "df": hp_display,
            "title": f"High Priority: CVSS ≥ {_CVSS_HIGH_RISK} and Overdue",
            "severity_col": None,
            "sla_formatting": True,
            "sla_status_col": "SLA Status",
        })

    return export_to_excel(
        sheets=sheets,
        output_path=output_dir / f"{REPORT_SLUG}.xlsx",
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
    sections: list[dict] = []

    def _chart_png(name: str) -> Optional[Path]:
        for c in charts:
            if c["name"] == name:
                return c["png"]
        return None

    if metrics["empty"]:
        sections.append({
            "heading": REPORT_NAME,
            "text": "No data returned for the selected scope.",
        })
    else:
        total = metrics["total_findings"]
        n_plugins = metrics["total_plugins"]
        n_assets = metrics["total_assets"]

        # Section 1: Summary + top-plugins bar
        intro = (
            f"<strong>Total Open Findings:</strong> {fmt_int(total)} &nbsp;|&nbsp; "
            f"<strong>Unique Plugins:</strong> {fmt_int(n_plugins)} &nbsp;|&nbsp; "
            f"<strong>Affected Assets:</strong> {fmt_int(n_assets)}<br/>"
            f"The table below lists the top {_TOP_N} plugins ordered by the number of "
            f"unique assets they affect.  A single plugin can produce multiple findings "
            f"on the same asset; <em>Total Findings</em> reflects the raw instance count."
        )
        sections.append({
            "heading": f"Top {_TOP_N} Plugins by Affected Asset Count",
            "text": intro,
            "chart_png_path": _chart_png("top_plugins_bar"),
        })

        # Top plugin table (condensed)
        top_plugins = metrics["top_plugins"]
        if not top_plugins.empty:
            plugin_pdf = top_plugins[[
                "rank", "plugin_name", "plugin_family", "severity",
                "cvss_score", "asset_count", "exploit_available", "oldest_sla_status",
            ]].rename(columns={
                "rank": "#",
                "plugin_name": "Plugin",
                "plugin_family": "Family",
                "severity": "Sev",
                "cvss_score": "CVSS",
                "asset_count": "Assets",
                "exploit_available": "Exploit",
                "oldest_sla_status": "Oldest SLA",
            })
            sections.append({
                "heading": "",
                "dataframe": plugin_pdf,
                "severity_col": "Sev",
            })

        # Section 2: Plugin family donut
        sections.append({
            "heading": "Plugin Family Distribution",
            "text": (
                "The donut chart below shows the proportion of vulnerability findings "
                "by plugin family.  Families with a high instance count may indicate "
                "systemic patching gaps."
            ),
            "chart_png_path": _chart_png("family_donut"),
        })

        # Family table
        family_df = metrics["family_dist"]
        if not family_df.empty:
            sections.append({
                "heading": "",
                "dataframe": family_df.head(15),
                "severity_col": None,
            })

        # Section 3: Exploitability
        exploit_df = metrics["exploitability"]
        if not exploit_df.empty:
            exploit_count = exploit_df["Exploitable Findings"].sum()
            sections.append({
                "heading": "Exploitable Vulnerabilities",
                "text": (
                    f"<strong>{fmt_int(exploit_count)}</strong> open findings have a known "
                    f"exploit available.  These represent an elevated risk of active "
                    f"exploitation and should be prioritized regardless of SLA window."
                ),
                "dataframe": exploit_df.drop(columns=["_severity_key"], errors="ignore"),
                "severity_col": None,
            })

        # Section 4: High-priority (CVSS >= 9 overdue)
        high_df = metrics["high_priority"]
        if not high_df.empty:
            hp_count = len(high_df)
            sections.append({
                "heading": f"Immediate Action Required — CVSS ≥ {_CVSS_HIGH_RISK} and Overdue",
                "text": (
                    f"<strong>{fmt_int(hp_count)}</strong> finding(s) have a CVSS score of "
                    f"{_CVSS_HIGH_RISK} or higher <em>and</em> have breached their SLA "
                    f"remediation window.  These are the highest-priority remediation "
                    f"targets.  Full detail is available in the Excel attachment "
                    f"(High Priority tab)."
                ),
            })
        else:
            sections.append({
                "heading": f"CVSS ≥ {_CVSS_HIGH_RISK} Overdue Items",
                "text": (
                    f"No findings with CVSS ≥ {_CVSS_HIGH_RISK} are currently past their "
                    f"SLA remediation window.  Excellent."
                ),
            })

        # Section 5: Top CVEs
        top_cves = metrics["top_cves"]
        if not top_cves.empty:
            cve_pdf = top_cves[[
                "rank", "cve_id", "cvss_score", "asset_count",
                "plugin_count", "severity", "exploit_available",
            ]].rename(columns={
                "rank": "#",
                "cve_id": "CVE",
                "cvss_score": "CVSS",
                "asset_count": "Assets",
                "plugin_count": "Plugins",
                "severity": "Sev",
                "exploit_available": "Exploit",
            })
            sections.append({
                "heading": f"Top {_TOP_N} CVEs by CVSS Score",
                "text": (
                    "CVEs ranked by maximum CVSS score observed across all open findings.  "
                    f"Full CVE detail is in the Excel attachment (CVE Detail tab)."
                ),
                "dataframe": cve_pdf,
                "severity_col": "Sev",
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
    cache_dir: Optional[Path] = None,
) -> dict:
    """
    Run the Plugin / CVE Breakdown report end-to-end.

    Returns
    -------
    dict  {"pdf": Path, "excel": Path, "charts": [Path, ...]}
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

    df, assets_df  = _fetch_and_prepare(tio, cache_dir, tag_category, tag_value)
    metrics        = _compute_metrics(df)
    charts         = _build_charts(metrics, charts_dir)
    excel_path     = _build_excel(metrics, output_dir, scope_str, generated_at)
    pdf_path       = _build_pdf(metrics, charts, output_dir, scope_str, generated_at)

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
  python reports/plugin_cve.py
  python reports/plugin_cve.py --tag-category "Environment" --tag-value "Production"
  python reports/plugin_cve.py --output-dir output/test/ --run-id 2026-03-20
        """,
    )
    parser.add_argument("--tag-category", default=None, metavar="CATEGORY")
    parser.add_argument("--tag-value",    default=None, metavar="VALUE")
    parser.add_argument("--output-dir",   default=None, metavar="DIR")
    parser.add_argument("--run-id",       default=None, metavar="ID")
    parser.add_argument("--cache-dir",    default=None, metavar="DIR",
                        help="Parquet cache directory (default: data/cache/<today>/)")
    parser.add_argument("--no-cache",     action="store_true")
    args = parser.parse_args()

    run_id    = args.run_id or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    out       = Path(args.output_dir) if args.output_dir else None
    from config import CACHE_DIR
    cache_dir = Path(args.cache_dir) if args.cache_dir else CACHE_DIR / run_id

    if args.no_cache:
        for f in cache_dir.glob("*.parquet"):
            f.unlink(); logger.info("Purged: %s", f)

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

    print(f"\nPDF   : {result['pdf']}")
    print(f"Excel : {result['excel']}")
    print(f"Charts: {len(result['charts'])} file(s)")
    for p in result["charts"]:
        print(f"  {p}")
