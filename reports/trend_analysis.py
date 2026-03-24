"""
reports/trend_analysis.py — Trend Analysis Over Time report.

Audience: Management / Executives + Security Analysts

Methodology note
----------------
This report derives all trend data from the current open-vulnerability export
(state: open | reopened).  Historical snapshots are reconstructed by applying
time-window filters to the ``first_found`` and ``last_fixed`` date fields:

- Open count trend   : vulns in today's open export whose first_found ≤ month-end.
                       Underestimates actual historical open counts (excludes vulns
                       that were opened and fully remediated within the period).
- SLA compliance     : for each month's cohort, simulates what % would have been
                       overdue at that point given their first_found dates and SLA
                       windows.  Same methodology as the SLA Remediation report.
- MTTR proxy         : average days_open for vulns first_found in each month.
                       Actual MTTR requires the fixed-state export; this shows how
                       long the current unresolved cohort has been aging.
- Net new per month  : count of vulns whose first_found falls within each month.
- Per-tag trend      : net-new counts per tag group for the trailing 3 months;
                       groups are classified improving or degrading based on
                       direction of change.
- 90-day age profile : % of currently-open vulns first found > 90 days ago
                       (inverse proxy for the rolling remediation rate).

Outputs
-------
- Excel:
    Tab "Open Counts Trend"    — severity rows × month columns (open count)
    Tab "Avg Age Trend"        — severity rows × month columns (avg days open)
    Tab "SLA Compliance Trend" — severity rows × month columns (% within SLA)
    Tab "Net New Trend"        — month rows, one column per severity + total
    Tab "Tag Group Trend"      — per-tag net-new for trailing 3 months (if tags available)
    Metadata tab via export_to_excel()
- PDF:   Narrative summary + two embedded Plotly line charts
- Chart 1 (Plotly):  Open vulnerability count by severity over trailing 6 months
- Chart 2 (Plotly):  SLA compliance % by severity over trailing 6 months

CLI
---
python reports/trend_analysis.py [options]
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

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    SEVERITY_COLORS,
    SLA_DAYS,
)
from data.fetchers import enrich_vulns_with_assets, fetch_assets, fetch_vulnerabilities
from exporters.chart_exporter import line_chart
from exporters.excel_exporter import export_to_excel
from exporters.pdf_exporter import build_pdf
from utils.formatters import (
    fmt_days,
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
REPORT_NAME = "Trend Analysis Over Time"
REPORT_SLUG = "trend_analysis"

_N_MONTHS     = 6   # trailing months for main trend charts
_N_MONTHS_TAG = 3   # trailing months for per-tag-group trend

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
# Shared time-window builder
# ===========================================================================

def _build_month_windows(n_months: int, as_of: datetime) -> list[tuple]:
    """
    Return a list of (period_end, label) for the trailing *n_months* calendar
    months, oldest first.

    ``period_end`` is the last instant of the month (23:59:59 UTC of the last
    calendar day), represented as a tz-aware UTC Timestamp.

    Parameters
    ----------
    n_months : int
    as_of : datetime
        Reference point (UTC).

    Returns
    -------
    list of (period_end: pd.Timestamp, label: str)
    """
    windows: list[tuple] = []
    for i in range(n_months - 1, -1, -1):  # oldest first
        anchor = as_of.replace(day=1) - pd.DateOffset(months=i)
        period_end = (
            pd.Timestamp(anchor)
            .to_period("M")
            .to_timestamp("M")          # last day of the month, midnight
            .tz_localize("UTC")
        )
        period_start = (
            pd.Timestamp(anchor)
            .to_period("M")
            .to_timestamp("MS")         # first day of the month
            .tz_localize("UTC")
        )
        label = period_end.strftime("%b %Y")
        windows.append((period_start, period_end, label))
    return windows


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

    Returns (enriched_vulns_df, raw_assets_df).
    raw_assets_df is retained for per-tag-group trend calculations.
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

    # Ensure last_fixed is UTC-aware (may be NaT for open vulns)
    if "last_fixed" in df.columns:
        df["last_fixed"] = pd.to_datetime(df["last_fixed"], utc=True, errors="coerce")

    logger.info(
        "[%s] Prepared %d records (%d unique assets).",
        REPORT_NAME, len(df), df["asset_id"].nunique(),
    )
    return df, assets_df


# ===========================================================================
# Phase 2 — Metric calculations
# ===========================================================================

def _compute_metrics(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    tag_category: Optional[str],
    as_of: Optional[datetime] = None,
) -> dict:
    """Compute all trend metrics and return as a flat dict."""
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    if df.empty:
        return {"empty": True}

    open_df  = df[~df["remediated"]].copy()
    windows  = _build_month_windows(_N_MONTHS, as_of)
    windows3 = windows[-_N_MONTHS_TAG:]  # last 3 months for tag trend

    open_trend   = _compute_open_trend(open_df, windows)
    avg_age_trend = _compute_avg_age_trend(open_df, windows)
    sla_trend    = _compute_sla_trend(open_df, windows)
    net_new      = _compute_net_new_trend(df, windows)
    tag_trend    = _compute_tag_trend(df, assets_df, tag_category, windows3)
    summary      = _compute_summary_stats(df, open_df, as_of)

    return {
        "empty":        False,
        "windows":      windows,
        "open_trend":   open_trend,
        "avg_age_trend": avg_age_trend,
        "sla_trend":    sla_trend,
        "net_new":      net_new,
        "tag_trend":    tag_trend,
        "summary":      summary,
        "as_of":        as_of,
    }


def _compute_open_trend(
    open_df: pd.DataFrame,
    windows: list[tuple],
) -> pd.DataFrame:
    """
    For each month-end, count currently-open vulns whose first_found
    is on or before that month-end, broken down by severity.

    This represents the portion of today's open backlog that was already
    present at the end of each past month.

    Returns
    -------
    pd.DataFrame
        Columns: month, critical, high, medium, low, total
        Rows are ordered oldest → most recent.
    """
    rows: list[dict] = []
    for _start, period_end, label in windows:
        row: dict = {"month": label}
        cohort = open_df[open_df["first_found"] <= period_end]
        for sev in ordered_severities():
            row[sev] = int((cohort["severity"] == sev).sum())
        row["total"] = len(cohort)
        rows.append(row)
    return pd.DataFrame(rows)


def _compute_avg_age_trend(
    open_df: pd.DataFrame,
    windows: list[tuple],
) -> pd.DataFrame:
    """
    For each month, compute the average ``days_open`` for vulns whose
    ``first_found`` falls within that month (proxy for MTTR).

    Returns
    -------
    pd.DataFrame
        Columns: month, critical, high, medium, low
        None values indicate no vulns first_found in that month.
    """
    rows: list[dict] = []
    for period_start, period_end, label in windows:
        cohort = open_df[
            (open_df["first_found"] >= period_start) &
            (open_df["first_found"] <= period_end)
        ]
        row: dict = {"month": label}
        for sev in ordered_severities():
            sev_cohort = cohort[cohort["severity"] == sev]
            if sev_cohort.empty or "days_open" not in sev_cohort.columns:
                row[sev] = None
            else:
                val = sev_cohort["days_open"].mean()
                row[sev] = round(float(val), 1) if pd.notna(val) else None
        rows.append(row)
    return pd.DataFrame(rows)


def _compute_sla_trend(
    open_df: pd.DataFrame,
    windows: list[tuple],
) -> pd.DataFrame:
    """
    Estimate SLA compliance rate per severity for each trailing month.

    Methodology: for each month-end M, take the cohort of currently-open
    vulns with first_found ≤ M.  Compute how many days each would have been
    open at M and whether that exceeds the SLA window.

    Returns
    -------
    pd.DataFrame
        Columns: month, critical, high, medium, low  (values = % within SLA, 0–100)
    """
    rows: list[dict] = []
    for _start, period_end, label in windows:
        cohort = open_df[open_df["first_found"] <= period_end].copy()
        row: dict = {"month": label}

        if cohort.empty:
            for sev in ordered_severities():
                row[sev] = 100.0
            rows.append(row)
            continue

        cohort["_days_at"] = (period_end - cohort["first_found"]).dt.days.clip(lower=0)
        cohort["_sla_at"]  = cohort["severity"].str.lower().map(SLA_DAYS)
        cohort["_within"]  = (
            cohort["_sla_at"].notna() &
            (cohort["_days_at"] <= cohort["_sla_at"])
        )

        for sev in ordered_severities():
            sev_sub = cohort[cohort["severity"] == sev]
            if sev_sub.empty or not sev_sub["_sla_at"].notna().any():
                row[sev] = 100.0
            else:
                row[sev] = round(float(sev_sub["_within"].mean()) * 100, 1)

        rows.append(row)
    return pd.DataFrame(rows)


def _compute_net_new_trend(
    df: pd.DataFrame,
    windows: list[tuple],
) -> pd.DataFrame:
    """
    Count newly-discovered vulnerabilities per month, broken down by severity.

    Uses ``first_found`` to assign each vulnerability to its discovery month.
    Note: vulns opened-and-closed in a past month are absent from the export;
    these counts reflect the persisting-open cohort only.

    Returns
    -------
    pd.DataFrame
        Columns: month, critical, high, medium, low, total_new
    """
    rows: list[dict] = []
    for period_start, period_end, label in windows:
        cohort = df[
            (df["first_found"] >= period_start) &
            (df["first_found"] <= period_end)
        ]
        row: dict = {"month": label}
        for sev in ordered_severities():
            row[sev] = int((cohort["severity"] == sev).sum())
        row["total_new"] = len(cohort)
        rows.append(row)
    return pd.DataFrame(rows)


def _compute_tag_trend(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    tag_category: Optional[str],
    windows3: list[tuple],
) -> pd.DataFrame:
    """
    Compute net-new vulnerability count per tag group for each of the trailing
    3 months, and classify each group as improving, degrading, or stable.

    Joins assets_df tags to vulns by asset_id.  If tag_category is supplied,
    only groups within that category are shown.

    Returns
    -------
    pd.DataFrame
        Columns: Tag Category, Tag Value, <month1>, <month2>, <month3>,
                 Change, Direction
        Sorted by Direction (degrading first) then latest-month count desc.
    """
    if df.empty or assets_df.empty or "tags" not in assets_df.columns:
        return pd.DataFrame()

    # Build asset → tag mapping
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
            tag_rows.append({"asset_id": row["asset_id"], "tag_cat": cat, "tag_val": val})

    if not tag_rows:
        return pd.DataFrame()

    tag_long = pd.DataFrame(tag_rows)
    if tag_category:
        tag_long = tag_long[tag_long["tag_cat"].str.lower() == tag_category.lower()]

    if tag_long.empty:
        return pd.DataFrame()

    merged = df.merge(tag_long, on="asset_id", how="inner")
    if merged.empty:
        return pd.DataFrame()

    month_labels = [lbl for _, _, lbl in windows3]
    result_rows: list[dict] = []

    for (cat, val), grp in merged.groupby(["tag_cat", "tag_val"]):
        row_data: dict = {"Tag Category": cat, "Tag Value": val}
        counts: list[int] = []
        for period_start, period_end, lbl in windows3:
            new_count = int(
                ((grp["first_found"] >= period_start) & (grp["first_found"] <= period_end)).sum()
            )
            row_data[lbl] = new_count
            counts.append(new_count)

        # Classify direction using first vs last month count
        if len(counts) >= 2 and counts[0] != 0:
            change = counts[-1] - counts[0]
            row_data["Change"] = f"{change:+d}"
            if counts[-1] < counts[0]:
                row_data["Direction"] = "Improving"
            elif counts[-1] > counts[0]:
                row_data["Direction"] = "Degrading"
            else:
                row_data["Direction"] = "Stable"
        else:
            row_data["Change"] = "—"
            row_data["Direction"] = "Stable"

        result_rows.append(row_data)

    if not result_rows:
        return pd.DataFrame()

    result_df = pd.DataFrame(result_rows)

    # Sort: degrading first, then by latest month count descending
    direction_order = {"Degrading": 0, "Stable": 1, "Improving": 2}
    result_df["_sort_dir"] = result_df["Direction"].map(direction_order).fillna(1)
    latest_col = month_labels[-1] if month_labels else None
    if latest_col and latest_col in result_df.columns:
        result_df = result_df.sort_values(
            ["_sort_dir", latest_col], ascending=[True, False]
        )
    else:
        result_df = result_df.sort_values("_sort_dir")

    return result_df.drop(columns=["_sort_dir"]).reset_index(drop=True)


def _compute_summary_stats(
    df: pd.DataFrame,
    open_df: pd.DataFrame,
    as_of: datetime,
) -> dict:
    """
    Compute high-level summary statistics for the narrative section.

    Returns
    -------
    dict
        total_open, total_in_scope, sev_counts, age_profile_pct_old,
        avg_age_per_sev, rolling_90d_persistence_rate
    """
    total_open   = len(open_df)
    total_scope  = len(df)

    sev_counts: dict[str, int] = {}
    for sev in ordered_severities():
        sev_counts[sev] = int((open_df["severity"] == sev).sum())

    # 90-day age profile: % of open vulns first found > 90 days ago
    ninety_days_ago = pd.Timestamp(as_of) - pd.DateOffset(days=90)
    if total_open:
        old_count = int((open_df["first_found"] < ninety_days_ago).sum())
        age_profile_pct_old = round(old_count / total_open * 100, 1)
    else:
        age_profile_pct_old = 0.0

    # Average days_open per severity
    avg_age: dict[str, Optional[float]] = {}
    for sev in ordered_severities():
        sev_df = open_df[open_df["severity"] == sev]
        if sev_df.empty or "days_open" not in sev_df.columns:
            avg_age[sev] = None
        else:
            val = sev_df["days_open"].mean()
            avg_age[sev] = round(float(val), 1) if pd.notna(val) else None

    return {
        "total_open":              total_open,
        "total_in_scope":          total_scope,
        "sev_counts":              sev_counts,
        "age_profile_pct_old":     age_profile_pct_old,
        "avg_age":                 avg_age,
    }


# ===========================================================================
# Phase 3 — Chart generation
# ===========================================================================

def _build_charts(metrics: dict, charts_dir: Path) -> list[dict]:
    """
    Generate two Plotly line charts:
    1. Open vulnerability count by severity over trailing 6 months
    2. SLA compliance % by severity over trailing 6 months

    Returns
    -------
    list[dict]  — each entry: {name, png, html}
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    if metrics.get("empty"):
        return results

    sev_colors = [SEVERITY_COLORS[s] for s in ordered_severities()]

    # ------------------------------------------------------------------
    # Chart 1: Open vulnerability count trend
    # ------------------------------------------------------------------
    open_trend = metrics["open_trend"]
    sev_cols_present = [
        s for s in ordered_severities()
        if s in open_trend.columns and open_trend[s].sum() > 0
    ]
    if not open_trend.empty and sev_cols_present:
        colors1 = [SEVERITY_COLORS[s] for s in sev_cols_present]
        png1, html1 = line_chart(
            open_trend,
            "Open Vulnerability Count by Severity — Trailing 6 Months",
            charts_dir / "open_count_trend",
            x_col="month",
            y_cols=sev_cols_present,
            colors=colors1,
            xlabel="Month",
            ylabel="Open Vulnerabilities",
            y_pct=False,
        )
        results.append({"name": "open_count_trend", "png": png1, "html": html1})
        logger.debug("Chart written: %s", png1)

    # ------------------------------------------------------------------
    # Chart 2: SLA compliance % trend
    # ------------------------------------------------------------------
    sla_trend = metrics["sla_trend"]
    sla_cols_present = [
        s for s in ordered_severities()
        if s in sla_trend.columns
    ]
    if not sla_trend.empty and sla_cols_present:
        colors2 = [SEVERITY_COLORS[s] for s in sla_cols_present]
        png2, html2 = line_chart(
            sla_trend,
            "SLA Compliance % by Severity — Trailing 6 Months",
            charts_dir / "sla_compliance_trend",
            x_col="month",
            y_cols=sla_cols_present,
            colors=colors2,
            xlabel="Month",
            ylabel="Within SLA",
            y_pct=True,
        )
        results.append({"name": "sla_compliance_trend", "png": png2, "html": html2})
        logger.debug("Chart written: %s", png2)

    return results


# ===========================================================================
# Phase 4 — Excel workbook
# ===========================================================================

def _pivot_to_severity_rows(trend_df: pd.DataFrame) -> pd.DataFrame:
    """
    Transpose a month×severity DataFrame to severity×month layout for Excel.

    Input columns: month, critical, high, medium, low, [total, ...]
    Output columns: Severity, <month1>, <month2>, ...
    """
    sev_cols = [s for s in ordered_severities() if s in trend_df.columns]
    if trend_df.empty or not sev_cols:
        return pd.DataFrame()

    rows: list[dict] = []
    for sev in sev_cols:
        row: dict = {"Severity": severity_label(sev)}
        for _, month_row in trend_df.iterrows():
            row[month_row["month"]] = month_row.get(sev)
        rows.append(row)
    return pd.DataFrame(rows)


def _build_excel(
    metrics: dict,
    output_dir: Path,
    tag_filter: str,
    generated_at: datetime,
) -> Path:
    """
    Assemble the Excel workbook with five time-series tabs.

    Tabs:
    - Open Counts Trend    : severity rows × month columns
    - Avg Age Trend        : severity rows × month columns (avg days open)
    - SLA Compliance Trend : severity rows × month columns (% within SLA)
    - Net New Trend        : month rows, severity columns + total
    - Tag Group Trend      : per-tag net-new for last 3 months (if available)
    - Metadata tab via export_to_excel()
    """
    sheets: list[dict] = []
    output_path = output_dir / f"{REPORT_SLUG}.xlsx"

    if metrics.get("empty"):
        sheets.append({
            "name": "Trend Analysis",
            "df": pd.DataFrame({"Message": ["No data returned for the selected scope."]}),
            "severity_col": None,
        })
        return export_to_excel(
            sheets=sheets, output_path=output_path,
            report_name=REPORT_NAME, tag_filter=tag_filter, generated_at=generated_at,
        )

    # ------------------------------------------------------------------
    # Tab 1: Open Counts Trend (severity rows × month columns)
    # ------------------------------------------------------------------
    open_pivot = _pivot_to_severity_rows(metrics["open_trend"])
    if not open_pivot.empty:
        sheets.append({
            "name":         "Open Counts Trend",
            "df":           open_pivot,
            "title":        "Open Vulnerability Count by Severity — Trailing 6 Months",
            "severity_col": "Severity",
        })

    # ------------------------------------------------------------------
    # Tab 2: Avg Age Trend (severity rows × month columns, values = avg days)
    # ------------------------------------------------------------------
    age_pivot = _pivot_to_severity_rows(metrics["avg_age_trend"])
    if not age_pivot.empty:
        sheets.append({
            "name":         "Avg Age Trend",
            "df":           age_pivot,
            "title":        "Average Days Open per Severity by Month (MTTR Proxy)",
            "severity_col": "Severity",
        })

    # ------------------------------------------------------------------
    # Tab 3: SLA Compliance Trend (severity rows × month columns, values = %)
    # ------------------------------------------------------------------
    sla_pivot = _pivot_to_severity_rows(metrics["sla_trend"])
    if not sla_pivot.empty:
        sheets.append({
            "name":         "SLA Compliance Trend",
            "df":           sla_pivot,
            "title":        "SLA Compliance % by Severity — Trailing 6 Months",
            "severity_col": "Severity",
        })

    # ------------------------------------------------------------------
    # Tab 4: Net New Trend (month rows × severity columns + total)
    # ------------------------------------------------------------------
    net_new = metrics["net_new"].copy()
    if not net_new.empty:
        rename_map: dict[str, str] = {"month": "Month", "total_new": "Total New"}
        for sev in ordered_severities():
            if sev in net_new.columns:
                rename_map[sev] = severity_label(sev)
        sheets.append({
            "name":         "Net New Trend",
            "df":           net_new.rename(columns=rename_map),
            "title":        "New Vulnerabilities Introduced per Month (from open export)",
            "severity_col": None,
        })

    # ------------------------------------------------------------------
    # Tab 5: Per-Tag Trend (if available)
    # ------------------------------------------------------------------
    tag_trend = metrics["tag_trend"]
    if not tag_trend.empty:
        sheets.append({
            "name":         "Tag Group Trend",
            "df":           tag_trend,
            "title":        "Net New Vulnerabilities per Tag Group — Trailing 3 Months",
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
            "heading": "Trend Analysis",
            "text": "No vulnerability data was returned for the selected scope.",
        })
    else:
        summary   = metrics["summary"]
        total     = summary["total_open"]
        sev_counts = summary["sev_counts"]
        pct_old   = summary["age_profile_pct_old"]

        # ------------------------------------------------------------------
        # Section 1: Narrative summary + open count chart
        # ------------------------------------------------------------------
        lines = [
            f"<strong>Total Open Vulnerabilities:</strong> {fmt_int(total)}",
            f"<strong>Critical:</strong> {fmt_int(sev_counts.get('critical', 0))} &nbsp;|&nbsp; "
            f"<strong>High:</strong> {fmt_int(sev_counts.get('high', 0))} &nbsp;|&nbsp; "
            f"<strong>Medium:</strong> {fmt_int(sev_counts.get('medium', 0))} &nbsp;|&nbsp; "
            f"<strong>Low:</strong> {fmt_int(sev_counts.get('low', 0))}",
            f"<strong>Vulnerabilities open &gt; 90 days:</strong> {pct_old:.1f}% of current backlog",
            "",
            "<em>Methodology: trend data is reconstructed from first_found dates in "
            "the current open-vulnerability export.  Vulns opened and fully remediated "
            "in a past month are not present in this dataset.</em>",
        ]
        sections.append({
            "heading":        "Executive Trend Summary",
            "text":           "<br/>".join(lines),
            "chart_png_path": _chart_png("open_count_trend"),
        })

        # ------------------------------------------------------------------
        # Section 2: Open counts trend table
        # ------------------------------------------------------------------
        open_pivot = _pivot_to_severity_rows(metrics["open_trend"])
        if not open_pivot.empty:
            sections.append({
                "heading":  "Open Vulnerability Count — Trailing 6 Months",
                "text":     "Count of currently-unresolved vulns whose first_found date falls "
                            "on or before each month end.",
                "dataframe":    open_pivot,
                "severity_col": "Severity",
            })

        # ------------------------------------------------------------------
        # Section 3: SLA compliance trend + chart
        # ------------------------------------------------------------------
        sla_pivot = _pivot_to_severity_rows(metrics["sla_trend"])
        if not sla_pivot.empty:
            sections.append({
                "heading":        "SLA Compliance Trend — Trailing 6 Months",
                "text":           "Estimated % of open vulns within their SLA window at each month end.",
                "dataframe":      sla_pivot,
                "severity_col":   "Severity",
                "chart_png_path": _chart_png("sla_compliance_trend"),
            })

        # ------------------------------------------------------------------
        # Section 4: Net new per month
        # ------------------------------------------------------------------
        net_new = metrics["net_new"].copy()
        if not net_new.empty:
            rename_map = {"month": "Month", "total_new": "Total New"}
            for sev in ordered_severities():
                if sev in net_new.columns:
                    rename_map[sev] = severity_label(sev)
            sections.append({
                "heading":  "New Vulnerabilities Introduced per Month",
                "text":     "Count of open vulns first_found within each calendar month.",
                "dataframe":    net_new.rename(columns=rename_map),
                "severity_col": None,
            })

        # ------------------------------------------------------------------
        # Section 5: MTTR proxy table
        # ------------------------------------------------------------------
        age_pivot = _pivot_to_severity_rows(metrics["avg_age_trend"])
        if not age_pivot.empty:
            sections.append({
                "heading":  "Average Vulnerability Age by Month (MTTR Proxy)",
                "text":     "Average days_open for vulns first discovered in each month. "
                            "Full MTTR calculation requires the fixed-state vulnerability export.",
                "dataframe":    age_pivot,
                "severity_col": "Severity",
            })

        # ------------------------------------------------------------------
        # Section 6: Per-tag trend (if available)
        # ------------------------------------------------------------------
        tag_trend = metrics["tag_trend"]
        if not tag_trend.empty:
            sections.append({
                "heading":  "Per-Tag-Group Trend — Trailing 3 Months",
                "text":     "New vulnerabilities introduced per tag group. "
                            "Direction: Improving = net-new count decreasing, "
                            "Degrading = increasing.",
                "dataframe":    tag_trend,
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
    Run the Trend Analysis Over Time report end-to-end.

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
    metrics = _compute_metrics(df, assets_df, tag_category, as_of=generated_at)

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
  python reports/trend_analysis.py
  python reports/trend_analysis.py --tag-category "Environment" --tag-value "Production"
  python reports/trend_analysis.py --output-dir output/test/ --run-id 2026-03-20
        """,
    )
    parser.add_argument("--tag-category", default=None, metavar="CATEGORY",
                        help="Tenable tag category for asset scoping")
    parser.add_argument("--tag-value",    default=None, metavar="VALUE",
                        help="Tenable tag value for asset scoping")
    parser.add_argument("--output-dir",   default=None, metavar="DIR",
                        help="Output directory (default: output/<run-id>/trend_analysis/)")
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
