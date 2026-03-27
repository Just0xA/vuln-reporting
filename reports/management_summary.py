"""
reports/management_summary.py — Monthly Management Executive Summary Report.

Audience: Senior Management — Directors and Vice Presidents.
Language: Clear, jargon-free, action-oriented.  No plugin-level or
vulnerability-level detail.  Program health through seven high-level
metrics, each with a plain-language explanation.

Outputs
-------
- PDF:   management_summary_YYYY-MM.pdf   (WeasyPrint, inline Matplotlib charts)
- Email: HTML body via standard Jinja2 template  (no Excel attachment)
- Charts: none as separate files — all charts embedded as base64 PNG in the PDF

CLI
---
python reports/management_summary.py
python reports/management_summary.py \\
    --tag-category "Environment" --tag-value "Production"
python reports/management_summary.py --no-email --output-dir output/test/
python reports/management_summary.py --cache-dir data/cache/2026-03-01/

Build Order (this file)
-----------------------
Step 1 (this build): Data computation — _compute_metric_1 through _compute_metric_7,
                     trend helpers.  __main__ prints computed values for review.
Step 2: _draw_gauge() Matplotlib function.
Step 3: _build_pdf() — WeasyPrint HTML builder, page by page.
Step 4: Email builder.
Step 5: run_report() entry point, CLI wiring, run_all.py integration.
Step 6: docs/management_summary_calculations.md
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import logging
import math
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")   # Non-interactive backend — must precede pyplot import
import matplotlib.pyplot as plt
from matplotlib.patches import Wedge

# ---- Python 3.14 / matplotlib compatibility patch -------------------------
# matplotlib.path.Path.__deepcopy__ calls copy.deepcopy(super(), memo) which
# recurses infinitely in Python 3.14.  Replace it with a direct constructor
# copy that only copies the data arrays — no deepcopy chain involved.
import matplotlib.path as _mpath


def _safe_path_deepcopy(self, memo):  # type: ignore[override]
    return _mpath.Path(
        self.vertices.copy(),
        self.codes.copy() if self.codes is not None else None,
        self._interpolation_steps,
        self.should_simplify,
        self.simplify_threshold,
    )


_mpath.Path.__deepcopy__ = _safe_path_deepcopy  # type: ignore[method-assign]
# ---------------------------------------------------------------------------
import pandas as pd
from rich import box
from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Allow running as a top-level script from any working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    CACHE_DIR,
    LOG_DIR,
    LOG_LEVEL,
    OUTPUT_DIR,
    ROOT_DIR,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    SLA_DAYS,
    vpr_to_severity,
)
from data.fetchers import (
    enrich_vulns_with_assets,
    fetch_all_assets,
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
    filter_by_tag,
)
from utils.formatters import report_timestamp, safe_filename

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
REPORT_NAME = "Management Executive Summary"
REPORT_SLUG = "management_summary"
TREND_DIR: Path = ROOT_DIR / "data" / "trend"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

_console = Console()

# ---------------------------------------------------------------------------
# Age bucket definitions for Metric 5 — Backlog Age Distribution
# (label, min_days_inclusive, max_days_inclusive, bar_color)
# ---------------------------------------------------------------------------
_AGE_BUCKETS: list[tuple[str, int, int, str]] = [
    ("0–30 days",    0,   30,    "#388e3c"),   # green
    ("31–60 days",   31,  60,    "#7cb342"),   # light green
    ("61–90 days",   61,  90,    "#fbc02d"),   # yellow
    ("91–180 days",  91,  180,   "#f57c00"),   # orange
    ("181–365 days", 181, 365,   "#e64a19"),   # deep orange
    ("365+ days",    366, 99999, "#d32f2f"),   # red
]

# Open states as reported by the Tenable vuln export
_OPEN_STATES: frozenset[str] = frozenset({"open", "reopened"})


# ===========================================================================
# Trend data helpers
# ===========================================================================


def _sanitise_tag_for_filename(
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> str:
    """
    Return a filesystem-safe suffix for the trend JSON filename.

    Spaces are replaced with underscores; any character outside
    ``[A-Za-z0-9_]`` is removed.

    Examples
    --------
    >>> _sanitise_tag_for_filename("Environment", "Production")
    'Environment_Production'
    >>> _sanitise_tag_for_filename(None, None)
    'all_assets'
    """
    if not tag_category or not tag_value:
        return "all_assets"
    combined = f"{tag_category}_{tag_value}"
    sanitised = re.sub(r"[^A-Za-z0-9_]", "_", combined).strip("_")
    return sanitised or "all_assets"


def _trend_file_path(
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> Path:
    """
    Return the Path to the trend JSON file for this tag filter.

    Creates ``data/trend/`` automatically if it does not exist.
    """
    TREND_DIR.mkdir(parents=True, exist_ok=True)
    suffix = _sanitise_tag_for_filename(tag_category, tag_value)
    return TREND_DIR / f"management_summary_{suffix}.json"


def _load_trend_history(trend_file: Path) -> list[dict]:
    """
    Load all snapshot entries from the trend JSON file.

    Returns an empty list if the file does not exist or cannot be parsed.
    Never raises.
    """
    if not trend_file.exists():
        return []
    try:
        with trend_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("snapshots", [])
    except Exception as exc:
        logger.warning("Could not load trend file %s: %s", trend_file, exc)
        return []


def _save_trend_snapshot(
    trend_file: Path,
    month_str: str,
    tag_filter_label: str,
    sev_counts: dict,
    generated_at: datetime,
) -> None:
    """
    Append or update the current month's snapshot in the trend JSON file.

    If an entry already exists for this (month, tag_filter) pair, it is
    overwritten — handles re-runs within the same month cleanly.  The file
    is never overwritten entirely; only the matching entry is replaced.

    Parameters
    ----------
    trend_file : Path
        Output JSON path (from ``_trend_file_path()``).
    month_str : str
        ISO year-month string, e.g. ``"2026-03"``.
    tag_filter_label : str
        Human-readable filter label, e.g. ``"Environment=Production"``
        or ``"all_assets"``.
    sev_counts : dict
        Severity count dict with keys: critical, high, medium, low.
    generated_at : datetime
        UTC-aware run timestamp.
    """
    if trend_file.exists():
        try:
            with trend_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            logger.warning("Trend file unreadable, reinitialising: %s", exc)
            data = {"snapshots": []}
    else:
        data = {"snapshots": []}

    new_entry: dict = {
        "month":        month_str,
        "tag_filter":   tag_filter_label,
        "critical":     int(sev_counts.get("critical", 0)),
        "high":         int(sev_counts.get("high", 0)),
        "medium":       int(sev_counts.get("medium", 0)),
        "low":          int(sev_counts.get("low", 0)),
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    snapshots: list[dict] = data.get("snapshots", [])
    updated = False
    for idx, snap in enumerate(snapshots):
        if snap.get("month") == month_str and snap.get("tag_filter") == tag_filter_label:
            snapshots[idx] = new_entry
            updated = True
            break
    if not updated:
        snapshots.append(new_entry)

    data["snapshots"] = snapshots
    TREND_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with trend_file.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Trend snapshot saved: month=%s filter=%s", month_str, tag_filter_label)
    except Exception as exc:
        logger.error("Failed to write trend file %s: %s", trend_file, exc)


# ===========================================================================
# Metric compute functions
# ===========================================================================


def _compute_metric_1(vulns_df: pd.DataFrame) -> dict:
    """
    Metric 1 — Total Vulnerabilities by Severity.

    Counts open (state = open / reopened) findings grouped by VPR-derived
    severity tier.  Informational findings are already excluded by the fetcher
    and do not appear in vulns_df.

    Calculation
    -----------
    For each severity in {Critical, High, Medium, Low}:
        count = number of rows where severity == <tier>
                AND state in {open, reopened}
    total = sum of all four counts

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Tag-filtered vulnerability DataFrame (open/reopened only).

    Returns
    -------
    dict
        Keys: ``critical``, ``high``, ``medium``, ``low`` (int each),
        ``total`` (int).
    """
    if vulns_df.empty:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    open_df = vulns_df[vulns_df["state"].str.lower().isin(_OPEN_STATES)]
    sev_lower = open_df["severity"].str.lower()

    counts: dict[str, int] = {
        sev: int((sev_lower == sev).sum())
        for sev in ("critical", "high", "medium", "low")
    }
    counts["total"] = sum(counts.values())
    return counts


def _compute_metric_2(
    assets_df: pd.DataFrame,
    report_date: datetime,
) -> dict:
    """
    Metric 2 — Scan Coverage.

    Measures the percentage of licensed assets scanned within the last 30 days.

    Calculation
    -----------
    licensed  = assets where last_licensed_scan_date IS NOT NULL
    cutoff    = report_date - 30 days
    scanned   = licensed WHERE last_licensed_scan_date >= cutoff
    coverage  = (len(scanned) / len(licensed)) × 100, rounded to 1dp

    Thresholds:
        >= 95%  → "Good"            green  (#388e3c)
        >= 80%  → "Needs Attention" amber  (#fbc02d)
        <  80%  → "At Risk"         red    (#d32f2f)

    Parameters
    ----------
    assets_df : pd.DataFrame
        Tag-filtered asset DataFrame.
    report_date : datetime
        UTC-aware reference date (usually run timestamp).

    Returns
    -------
    dict
        coverage_pct (float|None), scanned (int), not_scanned (int),
        total_licensed (int), status (str), color (str), error (str|None).
    """
    _grey = "#9E9E9E"

    if assets_df.empty or "last_licensed_scan_date" not in assets_df.columns:
        return {
            "coverage_pct":   None,
            "scanned":        0,
            "not_scanned":    0,
            "total_licensed": 0,
            "status":         "No data",
            "color":          _grey,
            "error":          "No asset data available",
        }

    licensed     = assets_df[assets_df["last_licensed_scan_date"].notna()]
    total_licensed = len(licensed)

    if total_licensed == 0:
        return {
            "coverage_pct":   None,
            "scanned":        0,
            "not_scanned":    0,
            "total_licensed": 0,
            "status":         "No licensed assets found",
            "color":          _grey,
            "error":          "No licensed assets found",
        }

    cutoff  = pd.Timestamp(report_date) - pd.Timedelta(days=30)
    scanned = int((licensed["last_licensed_scan_date"] >= cutoff).sum())
    not_scanned  = total_licensed - scanned
    coverage_pct = round(scanned / total_licensed * 100, 1)

    if coverage_pct >= 95:
        status, color = "Good",             "#388e3c"
    elif coverage_pct >= 80:
        status, color = "Needs Attention",  "#fbc02d"
    else:
        status, color = "At Risk",          "#d32f2f"

    return {
        "coverage_pct":   coverage_pct,
        "scanned":        scanned,
        "not_scanned":    not_scanned,
        "total_licensed": total_licensed,
        "status":         status,
        "color":          color,
        "error":          None,
    }


def _compute_metric_3(fixed_vulns_df: pd.DataFrame) -> dict:
    """
    Metric 3 — Mean Time to Remediate (MTTR) by Severity.

    Calculated from FIXED vulnerabilities only.

    Calculation (per finding)
    -------------------------
    Preferred:  days_to_fix = time_taken_to_fix / 86400
                (when time_taken_to_fix IS NOT NULL AND > 0)
    Fallback:   days_to_fix = (last_fixed - first_found).days

    MTTR per severity = mean(days_to_fix) for that severity tier,
                        rounded to 1 decimal place.

    Gauge thresholds (compare MTTR to SLA target):
        MTTR <= SLA target          → "Within SLA"    green  (#388e3c)
        MTTR <= SLA target × 1.25   → "Near SLA Limit" amber  (#fbc02d)
        MTTR >  SLA target × 1.25   → "Exceeding SLA"  red    (#d32f2f)

    Parameters
    ----------
    fixed_vulns_df : pd.DataFrame
        Tag-filtered FIXED vulnerability DataFrame.

    Returns
    -------
    dict
        mttr:   {severity: float|None}   days, 1dp, or None if no data
        status: {severity: str|None}     threshold label or None
        color:  {severity: str}          hex color
        total_fixed: int                 total fixed findings in scope
    """
    _grey   = "#9E9E9E"
    _sevs   = list(SLA_DAYS.keys())
    _empty  = {sev: None for sev in _sevs}
    _empty_color = {sev: _grey for sev in _sevs}

    if fixed_vulns_df.empty:
        return {
            "mttr":        _empty.copy(),
            "status":      _empty.copy(),
            "color":       _empty_color.copy(),
            "total_fixed": 0,
        }

    df = fixed_vulns_df.copy()

    # ---- Compute days_to_fix vectorised ----
    ttf_valid = df["time_taken_to_fix"].notna() & (df["time_taken_to_fix"] > 0)
    ttf_days  = df["time_taken_to_fix"].div(86400)

    last_fixed_ts  = pd.to_datetime(df.get("last_fixed"),  utc=True, errors="coerce")
    first_found_ts = pd.to_datetime(df.get("first_found"), utc=True, errors="coerce")
    date_diff_days = (last_fixed_ts - first_found_ts).dt.days.clip(lower=0)

    df = df.assign(
        days_to_fix=ttf_days.where(ttf_valid, other=date_diff_days)
    )
    # Drop rows where we cannot compute a days_to_fix value
    df = df[df["days_to_fix"].notna() & (df["days_to_fix"] >= 0)]

    result: dict = {"mttr": {}, "status": {}, "color": {}, "total_fixed": len(df)}

    for sev, sla in SLA_DAYS.items():
        sev_df = df[df["severity"].str.lower() == sev]
        if sev_df.empty:
            result["mttr"][sev]   = None
            result["status"][sev] = None
            result["color"][sev]  = _grey
        else:
            mttr = round(float(sev_df["days_to_fix"].mean()), 1)
            result["mttr"][sev] = mttr

            if mttr <= sla:
                result["status"][sev] = "Within SLA"
                result["color"][sev]  = "#388e3c"
            elif mttr <= sla * 1.25:
                result["status"][sev] = "Near SLA Limit"
                result["color"][sev]  = "#fbc02d"
            else:
                result["status"][sev] = "Exceeding SLA"
                result["color"][sev]  = "#d32f2f"

    return result


def _compute_metric_4(
    vulns_df: pd.DataFrame,
    report_date: datetime,
) -> dict:
    """
    Metric 4 — Patch Compliance Rate.

    Fraction of open vulnerabilities still within their SLA remediation window.

    Calculation
    -----------
    For each open finding:
        days_open  = (report_date - first_found).days
        within_sla = days_open <= sla_days[severity]

    overall_rate = (count within_sla / total_open) × 100, rounded to 1dp

    Per-severity rates use the same formula scoped to each tier.

    Thresholds:
        >= 90%  → "Compliant"        green  (#388e3c)
        >= 75%  → "Needs Attention"  amber  (#fbc02d)
        <  75%  → "Non-Compliant"    red    (#d32f2f)

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Tag-filtered open vulnerability DataFrame.
    report_date : datetime
        UTC-aware reference date.

    Returns
    -------
    dict
        overall_rate (float), per_severity {sev: {"rate": float,
        "within_sla": int, "total": int}}, within_sla (int),
        total_open (int), status (str), color (str).
    """
    open_df    = vulns_df[vulns_df["state"].str.lower().isin(_OPEN_STATES)].copy()
    total_open = len(open_df)
    per_sev: dict = {sev: {"rate": 0.0, "within_sla": 0, "total": 0} for sev in SLA_DAYS}

    if total_open == 0:
        return {
            "overall_rate": 100.0,
            "per_severity": per_sev,
            "within_sla":   0,
            "total_open":   0,
            "status":       "Compliant",
            "color":        "#388e3c",
        }

    report_ts   = pd.Timestamp(report_date)
    first_found = pd.to_datetime(open_df["first_found"], utc=True, errors="coerce")
    days_open   = (report_ts - first_found).dt.days.fillna(0).astype(int)
    sla_series  = open_df["severity"].str.lower().map(SLA_DAYS)
    within_mask = days_open <= sla_series

    within_total = int(within_mask.sum())
    overall_rate = round(within_total / total_open * 100, 1)

    for sev, sla in SLA_DAYS.items():
        sev_mask    = open_df["severity"].str.lower() == sev
        sev_total   = int(sev_mask.sum())
        sev_within  = int((within_mask & sev_mask).sum())
        per_sev[sev] = {
            "rate":       round(sev_within / sev_total * 100, 1) if sev_total > 0 else 0.0,
            "within_sla": sev_within,
            "total":      sev_total,
        }

    if overall_rate >= 90:
        status, color = "Compliant",        "#388e3c"
    elif overall_rate >= 75:
        status, color = "Needs Attention",  "#fbc02d"
    else:
        status, color = "Non-Compliant",    "#d32f2f"

    return {
        "overall_rate": overall_rate,
        "per_severity": per_sev,
        "within_sla":   within_total,
        "total_open":   total_open,
        "status":       status,
        "color":        color,
    }


def _compute_metric_5(
    vulns_df: pd.DataFrame,
    report_date: datetime,
) -> list[dict]:
    """
    Metric 5 — Vulnerability Backlog Age Distribution.

    Buckets all open vulnerabilities by days_open into six ranges.

    Calculation
    -----------
    For each open finding:
        days_open = (report_date - first_found).days

    Buckets:
        0–30, 31–60, 61–90, 91–180, 181–365, 365+

    Each bucket: count + percentage of total open.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Tag-filtered open vulnerability DataFrame.
    report_date : datetime
        UTC-aware reference date.

    Returns
    -------
    list[dict]
        One dict per bucket:
        {label, min_days, max_days, count (int), pct (float), color (str)}.
    """
    open_df = vulns_df[vulns_df["state"].str.lower().isin(_OPEN_STATES)].copy()
    total   = len(open_df)

    if total == 0:
        return [
            {
                "label":    label,
                "min_days": lo,
                "max_days": hi,
                "count":    0,
                "pct":      0.0,
                "color":    color,
            }
            for label, lo, hi, color in _AGE_BUCKETS
        ]

    report_ts   = pd.Timestamp(report_date)
    first_found = pd.to_datetime(open_df["first_found"], utc=True, errors="coerce")
    days_open   = (report_ts - first_found).dt.days.fillna(0).astype(int)

    results: list[dict] = []
    for label, lo, hi, color in _AGE_BUCKETS:
        if hi >= 99999:
            mask = days_open >= lo
        else:
            mask = (days_open >= lo) & (days_open <= hi)
        count = int(mask.sum())
        pct   = round(count / total * 100, 1)
        results.append({
            "label":    label,
            "min_days": lo,
            "max_days": hi,
            "count":    count,
            "pct":      pct,
            "color":    color,
        })

    return results


def _compute_metric_6(vulns_df: pd.DataFrame) -> dict:
    """
    Metric 6 — Exception and Risk Acceptance Rate.

    Counts open findings where severity_modification_type is "ACCEPTED"
    (risk acceptance) or "RECASTED" (severity recast).  Both represent a
    management decision to handle a finding outside the normal remediation SLA.

    Calculation
    -----------
    open_exceptions = count of open findings WHERE
                      severity_modification_type.upper() IN {"ACCEPTED", "RECASTED"}
    total_open      = count of all open findings
    exception_rate  = (open_exceptions / total_open) × 100, rounded to 2dp
    If total_open == 0: rate = None / "N/A"

    Color thresholds:
        rate > 5%  → red    (#d32f2f)  "High"
        rate > 2%  → amber  (#fbc02d)  "Elevated"
        rate <= 2% → green  (#388e3c)  "Normal"

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Tag-filtered vulnerability DataFrame (open/reopened).

    Returns
    -------
    dict
        open_exceptions (int), total_open (int), exception_rate (float|None),
        rate_color (str), rate_label (str).
    """
    open_df    = vulns_df[vulns_df["state"].str.lower().isin(_OPEN_STATES)]
    total_open = len(open_df)

    if total_open == 0:
        return {
            "open_exceptions": 0,
            "total_open":      0,
            "exception_rate":  None,
            "rate_color":      "#9E9E9E",
            "rate_label":      "N/A",
        }

    # Both ACCEPTED (risk acceptance) and RECASTED (severity recast) represent
    # management decisions to handle a finding outside normal remediation SLA.
    _EXCEPTION_TYPES = {"ACCEPTED", "RECASTED"}
    accepted_mask = (
        open_df["severity_modification_type"]
        .fillna("none")
        .str.upper()
        .isin(_EXCEPTION_TYPES)
    )
    open_exceptions = int(accepted_mask.sum())
    exception_rate  = round(open_exceptions / total_open * 100, 2)

    if exception_rate > 5:
        rate_color, rate_label = "#d32f2f", "High"
    elif exception_rate > 2:
        rate_color, rate_label = "#fbc02d", "Elevated"
    else:
        rate_color, rate_label = "#388e3c", "Normal"

    return {
        "open_exceptions": open_exceptions,
        "total_open":      total_open,
        "exception_rate":  exception_rate,
        "rate_color":      rate_color,
        "rate_label":      rate_label,
    }


def _compute_metric_7(
    trend_file: Path,
    tag_filter_label: str,
) -> dict:
    """
    Metric 7 — Vulnerability Reduction Trend (Month-over-Month).

    Reads historical snapshots and computes period-over-period deltas.

    Calculation
    -----------
    1. Load all snapshots from the trend JSON file.
    2. Filter to entries matching tag_filter_label.
    3. Sort chronologically; keep the most recent 6.
    4. If >= 2 snapshots:
           delta_critical_high = (curr.critical + curr.high)
                               - (prev.critical + prev.high)
           delta_medium_low    = (curr.medium + curr.low)
                               - (prev.medium + prev.low)
    5. If < 2 snapshots: first_run_notice = True, deltas = None.

    Parameters
    ----------
    trend_file : Path
        Path to the JSON trend store (from ``_trend_file_path()``).
    tag_filter_label : str
        Filter label used when the snapshot was stored.

    Returns
    -------
    dict
        snapshots (list, up to 6), delta_critical_high (int|None),
        delta_medium_low (int|None), has_trend (bool),
        first_run_notice (bool).
    """
    all_snaps = _load_trend_history(trend_file)
    relevant  = [s for s in all_snaps if s.get("tag_filter") == tag_filter_label]
    relevant.sort(key=lambda s: s.get("month", ""))
    recent = relevant[-6:]

    has_trend        = len(recent) >= 2
    first_run_notice = len(recent) < 2

    delta_critical_high: Optional[int] = None
    delta_medium_low:    Optional[int] = None

    if has_trend:
        prev = recent[-2]
        curr = recent[-1]
        delta_critical_high = (
            (curr.get("critical", 0) + curr.get("high", 0)) -
            (prev.get("critical", 0) + prev.get("high", 0))
        )
        delta_medium_low = (
            (curr.get("medium", 0) + curr.get("low", 0)) -
            (prev.get("medium", 0) + prev.get("low", 0))
        )

    return {
        "snapshots":           recent,
        "delta_critical_high": delta_critical_high,
        "delta_medium_low":    delta_medium_low,
        "has_trend":           has_trend,
        "first_run_notice":    first_run_notice,
    }


# ===========================================================================
# Convenience — compute all metrics in one call
# ===========================================================================


def compute_all_metrics(
    vulns_df: pd.DataFrame,
    assets_df: pd.DataFrame,
    fixed_vulns_df: pd.DataFrame,
    trend_file: Path,
    tag_filter_label: str,
    report_date: datetime,
) -> dict:
    """
    Compute all seven metrics and return them in a single dict.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Tag-filtered open vulnerability DataFrame.
    assets_df : pd.DataFrame
        Tag-filtered asset DataFrame.
    fixed_vulns_df : pd.DataFrame
        Tag-filtered fixed vulnerability DataFrame (for MTTR).
    trend_file : Path
        Trend JSON path for this tag filter.
    tag_filter_label : str
        Human-readable filter label, e.g. "Environment=Production".
    report_date : datetime
        UTC-aware reference timestamp.

    Returns
    -------
    dict
        Keys: metric_1 ... metric_7
    """
    logger.info("[%s] Computing metric 1 — Total Vulnerabilities by Severity", REPORT_SLUG)
    m1 = _compute_metric_1(vulns_df)

    logger.info("[%s] Computing metric 2 — Scan Coverage", REPORT_SLUG)
    m2 = _compute_metric_2(assets_df, report_date)

    logger.info("[%s] Computing metric 3 — MTTR by Severity", REPORT_SLUG)
    m3 = _compute_metric_3(fixed_vulns_df)

    logger.info("[%s] Computing metric 4 — Patch Compliance Rate", REPORT_SLUG)
    m4 = _compute_metric_4(vulns_df, report_date)

    logger.info("[%s] Computing metric 5 — Backlog Age Distribution", REPORT_SLUG)
    m5 = _compute_metric_5(vulns_df, report_date)

    logger.info("[%s] Computing metric 6 — Exception Rate", REPORT_SLUG)
    m6 = _compute_metric_6(vulns_df)

    logger.info("[%s] Computing metric 7 — Trend (loading history)", REPORT_SLUG)
    m7 = _compute_metric_7(trend_file, tag_filter_label)

    return {
        "metric_1": m1,
        "metric_2": m2,
        "metric_3": m3,
        "metric_4": m4,
        "metric_5": m5,
        "metric_6": m6,
        "metric_7": m7,
    }


# ===========================================================================
# Step 2 — Matplotlib gauge (semicircular dial)
# ===========================================================================


def _val_to_angle(v: float, min_val: float, max_val: float) -> float:
    """
    Map a gauge value to a matplotlib angle in degrees.

    The gauge arc spans the upper semicircle:
        180°  = left  = min_val
         90°  = top   = midpoint
          0°  = right = max_val

    The returned angle is clamped so the needle never escapes the arc.
    """
    if max_val == min_val:
        return 90.0
    fraction = max(0.0, min(1.0, (v - min_val) / (max_val - min_val)))
    return 180.0 - fraction * 180.0


def _fmt_gauge_label(v: float) -> str:
    """Format a gauge range-end label (e.g. 0 → '0', 100 → '100', 37.5 → '37.5')."""
    return str(int(v)) if v == int(v) else f"{v:.1f}"


def _draw_gauge(
    value: float,
    min_val: float = 0,
    max_val: float = 100,
    thresholds: Optional[list[tuple[float, str]]] = None,
    title: str = "",
    unit: str = "%",
    reference_line: Optional[float] = None,
    reference_label: Optional[str] = None,
    figsize: tuple = (3, 2),
) -> str:
    """
    Draw a semicircular gauge using Matplotlib and return a base64 PNG string.

    Parameters
    ----------
    value : float
        Current value to display.  Clamped to [min_val, max_val].
    min_val, max_val : float
        Gauge range.  Defaults 0–100.
    thresholds : list of (threshold_value, hex_color), optional
        Defines colour zones from min to max.  Each tuple means
        "from the previous threshold up to threshold_value, use this colour."
        Example: [(75, '#d32f2f'), (90, '#fbc02d'), (100, '#388e3c')]
        → 0–75 red, 75–90 amber, 90–100 green.
        If None, the arc is drawn in a neutral grey.
    title : str
        Label displayed below the gauge value.
    unit : str
        Suffix appended to the displayed value (default ``"%"``).
        Pass ``"d"`` for day-based MTTR gauges.
    reference_line : float, optional
        Draw a prominent tick mark at this value on the arc.
        Used to show the SLA target on MTTR gauges.
    reference_label : str, optional
        Short label for the reference tick (e.g. ``"SLA"``).
    figsize : tuple
        Matplotlib figure size in inches.  Default ``(3, 2)``.

    Returns
    -------
    str
        Base64-encoded PNG for inline embedding::

            <img src="data:image/png;base64,{result}"
                 style="width:100%; max-width:500px;">

    Notes
    -----
    - White background (``facecolor='white'``).
    - Rendered at 150 dpi for PDF clarity.
    - Figure is closed with ``plt.close(fig)`` immediately after encoding
      to prevent memory accumulation during batch runs.
    """
    value_clamped = max(float(min_val), min(float(max_val), float(value)))

    # ---- Determine the zone colour the current value falls in ---------------
    value_color = "#2E75B6"   # default: project navy
    if thresholds:
        lo = float(min_val)
        for thresh_val, color in thresholds:
            if lo <= value_clamped <= float(thresh_val):
                value_color = color
                break
            lo = float(thresh_val)
        else:
            # value is above all defined threshold upper-bounds — use last color
            value_color = thresholds[-1][1]

    # ---- Figure setup -------------------------------------------------------
    fig, ax = plt.subplots(figsize=figsize, facecolor="white")
    ax.set_aspect("equal")
    # Data coordinates chosen so the semicircle fits cleanly with room for
    # value text (below center) and title text (bottom).
    ax.set_xlim(-0.62, 0.62)
    ax.set_ylim(-0.30, 0.60)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    center  = (0.0, 0.0)
    r_outer = 0.50
    r_inner = 0.32
    arc_w   = r_outer - r_inner
    arc_mid = (r_inner + r_outer) / 2.0   # midpoint radius for needle length

    # ---- Background (full grey arc) -----------------------------------------
    ax.add_patch(
        Wedge(center, r_outer, 0, 180, width=arc_w,
              facecolor="#E0E0E0", edgecolor="none")
    )

    # ---- Coloured zone arcs -------------------------------------------------
    if thresholds:
        lo_val = float(min_val)
        zones: list[tuple[float, float, str]] = []
        for thresh_val, color in thresholds:
            hi_val = min(float(thresh_val), float(max_val))
            if hi_val > lo_val:
                zones.append((lo_val, hi_val, color))
            lo_val = float(thresh_val)
        # Any gap between last threshold and max_val gets the last color
        if lo_val < float(max_val):
            zones.append((lo_val, float(max_val), thresholds[-1][1]))

        for lo_v, hi_v, color in zones:
            # Angles: higher angle (left) corresponds to lower value
            a_left  = _val_to_angle(lo_v, min_val, max_val)
            a_right = _val_to_angle(hi_v, min_val, max_val)
            if a_left > a_right:          # always true for a left-to-right gauge
                ax.add_patch(
                    Wedge(center, r_outer, a_right, a_left,
                          width=arc_w, facecolor=color,
                          edgecolor="none", linewidth=0)
                )

    # ---- Thin boundary rings (visual polish) --------------------------------
    for r, w in ((r_outer, 0.007), (r_inner, 0.007)):
        ax.add_patch(
            Wedge(center, r, 0, 180, width=w,
                  facecolor="#BDBDBD", edgecolor="none")
        )

    # ---- Reference line (e.g. SLA target tick) ------------------------------
    if reference_line is not None and min_val <= reference_line <= max_val:
        ref_rad = math.radians(_val_to_angle(reference_line, min_val, max_val))
        # Draw tick that extends slightly inside and outside the arc band
        rx1 = center[0] + (r_inner - 0.03) * math.cos(ref_rad)
        ry1 = center[1] + (r_inner - 0.03) * math.sin(ref_rad)
        rx2 = center[0] + (r_outer + 0.03) * math.cos(ref_rad)
        ry2 = center[1] + (r_outer + 0.03) * math.sin(ref_rad)
        ax.plot([rx1, rx2], [ry1, ry2],
                color="#212121", linewidth=2.5,
                solid_capstyle="round", zorder=7)
        if reference_label:
            lx = center[0] + (r_outer + 0.12) * math.cos(ref_rad)
            ly = center[1] + (r_outer + 0.12) * math.sin(ref_rad)
            ax.text(lx, ly, reference_label,
                    ha="center", va="center",
                    fontsize=6, color="#212121", fontweight="bold")

    # ---- Needle -------------------------------------------------------------
    needle_rad = math.radians(_val_to_angle(value_clamped, min_val, max_val))
    nx = center[0] + arc_mid * math.cos(needle_rad)
    ny = center[1] + arc_mid * math.sin(needle_rad)
    ax.plot([center[0], nx], [center[1], ny],
            color="#212121", linewidth=2.0,
            solid_capstyle="round", zorder=8)

    # Pivot: dark ring + light centre dot for a clean rivet look
    ax.add_patch(plt.Circle(center, 0.032, color="#212121", zorder=9))
    ax.add_patch(plt.Circle(center, 0.018, color="#F5F5F5", zorder=10))

    # ---- Arc endpoint labels (min / max) ------------------------------------
    ax.text(center[0] - r_outer - 0.07, center[1] - 0.04,
            _fmt_gauge_label(min_val),
            ha="center", va="center", fontsize=6.5, color="#757575")
    ax.text(center[0] + r_outer + 0.07, center[1] - 0.04,
            _fmt_gauge_label(max_val),
            ha="center", va="center", fontsize=6.5, color="#757575")

    # ---- Value text (large, bold, zone-coloured) ----------------------------
    val_rounded = round(value, 1)
    if unit:
        disp_val = (
            f"{int(round(value))}{unit}"
            if val_rounded == int(val_rounded)
            else f"{val_rounded:.1f}{unit}"
        )
    else:
        disp_val = (
            str(int(round(value)))
            if val_rounded == int(val_rounded)
            else f"{val_rounded:.1f}"
        )
    ax.text(center[0], center[1] - 0.11,
            disp_val,
            ha="center", va="center",
            fontsize=13, fontweight="bold", color=value_color, zorder=11)

    # ---- Title label --------------------------------------------------------
    if title:
        ax.text(center[0], -0.25,
                title,
                ha="center", va="center",
                fontsize=6.5, color="#1A1A1A")

    # ---- Encode to base64 PNG -----------------------------------------------
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150,
                bbox_inches="tight", facecolor="white", edgecolor="none")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("utf-8")
    fig.clf()
    plt.close(fig)
    return b64


def _run_gauge_test(output_dir: Optional[Path] = None) -> None:
    """
    Render a representative set of test gauges and save them as PNG files.

    Outputs to ``output/gauge_test/`` (or *output_dir* if provided) so the
    user can open them and verify rendering before the PDF builder is wired up.

    Gauges rendered:
        coverage_good.png      — Scan coverage 97%  (green)
        coverage_attention.png — Scan coverage 85%  (amber)
        coverage_risk.png      — Scan coverage 68%  (red)
        mttr_within_sla.png    — Critical MTTR 10d  (green, SLA=15d reference)
        mttr_near_sla.png      — Critical MTTR 17d  (amber, SLA=15d reference)
        mttr_exceeding_sla.png — Critical MTTR 25d  (red,   SLA=15d reference)
        compliance_good.png    — Patch compliance 94% (green)
        compliance_poor.png    — Patch compliance 68% (red)
    """
    out = Path(output_dir) if output_dir else OUTPUT_DIR / "gauge_test"
    out.mkdir(parents=True, exist_ok=True)

    _console.print(f"\n[bold]Rendering test gauges -> {out}[/bold]\n")

    # Scan coverage thresholds: 0–80 red, 80–95 amber, 95–100 green
    coverage_thresholds = [
        (80,  "#d32f2f"),
        (95,  "#fbc02d"),
        (100, "#388e3c"),
    ]

    # Patch compliance thresholds: 0–75 red, 75–90 amber, 90–100 green
    compliance_thresholds = [
        (75,  "#d32f2f"),
        (90,  "#fbc02d"),
        (100, "#388e3c"),
    ]

    # Critical MTTR: SLA=15, max on dial=30 (SLA×2)
    # Zones: 0–15 green, 15–18.75 amber (SLA×1.25), 18.75–30 red
    sla_crit = SLA_DAYS["critical"]   # 15
    mttr_thresholds_crit = [
        (sla_crit,        "#388e3c"),
        (sla_crit * 1.25, "#fbc02d"),
        (sla_crit * 2,    "#d32f2f"),
    ]

    test_cases = [
        ("coverage_good.png",      97.0, 0, 100, coverage_thresholds,    "%",  None,       None,    "Scan Coverage"),
        ("coverage_attention.png", 85.0, 0, 100, coverage_thresholds,    "%",  None,       None,    "Scan Coverage"),
        ("coverage_risk.png",      68.0, 0, 100, coverage_thresholds,    "%",  None,       None,    "Scan Coverage"),
        ("mttr_within_sla.png",    10.0, 0, sla_crit * 2, mttr_thresholds_crit, "d", sla_crit, "SLA", "MTTR — Critical"),
        ("mttr_near_sla.png",      17.0, 0, sla_crit * 2, mttr_thresholds_crit, "d", sla_crit, "SLA", "MTTR — Critical"),
        ("mttr_exceeding_sla.png", 25.0, 0, sla_crit * 2, mttr_thresholds_crit, "d", sla_crit, "SLA", "MTTR — Critical"),
        ("compliance_good.png",    94.0, 0, 100, compliance_thresholds,  "%",  None,       None,    "Patch Compliance"),
        ("compliance_poor.png",    68.0, 0, 100, compliance_thresholds,  "%",  None,       None,    "Patch Compliance"),
    ]

    for filename, val, lo, hi, thresholds, unit, ref, ref_lbl, title in test_cases:
        b64 = _draw_gauge(
            value=val,
            min_val=lo,
            max_val=hi,
            thresholds=thresholds,
            title=title,
            unit=unit,
            reference_line=ref,
            reference_label=ref_lbl,
        )
        png_bytes = base64.b64decode(b64)
        out_path  = out / filename
        out_path.write_bytes(png_bytes)
        _console.print(f"  [green]OK[/green] {filename}  (value={val}{unit})")

    _console.print(f"\n[bold]All test gauges written to: {out}[/bold]")


# ===========================================================================
# Step 3 — PDF builder
# ===========================================================================

_PDF_CSS = """
<style>
  @page { size: letter; margin: 0.65in 0.75in; }

  /* ---- reset ---- */
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
         font-size: 10pt; color: #212121; background: #ffffff; }

  /* ---- page break ---- */
  .page-break { page-break-after: always; }

  /* ---- cover page ---- */
  .cover-header {
    background: #0d2b55; color: #ffffff;
    padding: 36pt 0 28pt 0; text-align: center;
  }
  .cover-org { font-size: 13pt; font-weight: 400; letter-spacing: 2pt;
               text-transform: uppercase; color: #90caf9; margin-bottom: 6pt; }
  .cover-title { font-size: 22pt; font-weight: 700; line-height: 1.2;
                 color: #ffffff; margin-bottom: 4pt; }
  .cover-subtitle { font-size: 11pt; color: #bbdefb; }
  .cover-body { padding: 28pt 0 0 0; text-align: center; }
  .cover-detail { font-size: 10pt; color: #546e7a; margin-bottom: 6pt; }
  .cover-scope { display: inline-block; background: #e3f2fd;
                 border-left: 4pt solid #1976d2;
                 padding: 6pt 14pt; margin: 16pt 0 20pt 0;
                 font-size: 10pt; color: #0d47a1; }
  .cover-confidential { margin-top: 22pt; font-size: 8.5pt;
                         color: #b71c1c; letter-spacing: 1pt;
                         text-transform: uppercase; font-weight: 700; }

  /* ---- section heading ---- */
  .section-heading {
    background: #0d2b55; color: #ffffff;
    padding: 5pt 10pt; font-size: 12pt; font-weight: 700;
    margin-bottom: 14pt; letter-spacing: 0.5pt;
  }

  /* ---- KPI tiles (Metric 1) ---- */
  .kpi-row { width: 100%; border-collapse: collapse; margin-bottom: 12pt; }
  .kpi-cell {
    width: 20%; text-align: center; padding: 10pt 4pt;
    border-radius: 4pt;
  }
  .kpi-label { font-size: 8pt; text-transform: uppercase;
               letter-spacing: 0.8pt; color: #546e7a; margin-bottom: 4pt; }
  .kpi-value { font-size: 22pt; font-weight: 700; line-height: 1; }
  .kpi-total { background: #eceff1; }
  .kpi-critical { background: #ffebee; }
  .kpi-high { background: #fff3e0; }
  .kpi-medium { background: #fffde7; }
  .kpi-low { background: #e8f5e9; }
  .color-critical { color: #d32f2f; }
  .color-high { color: #f57c00; }
  .color-medium { color: #f9a825; }
  .color-low { color: #388e3c; }
  .color-total { color: #37474f; }

  /* ---- two-column layout ---- */
  .two-col { width: 100%; border-collapse: collapse; }
  .two-col td { vertical-align: top; }
  .col-left { width: 55%; padding-right: 12pt; }
  .col-right { width: 45%; }

  /* ---- gauge block ---- */
  .gauge-block { text-align: center; margin-bottom: 10pt; }
  .gauge-img { max-width: 200pt; }
  .gauge-caption { font-size: 8pt; color: #546e7a; margin-top: 2pt; }
  .gauge-na { background: #f5f5f5; border: 1pt solid #e0e0e0;
              padding: 8pt; text-align: center; color: #9e9e9e;
              font-size: 9pt; border-radius: 3pt; }

  /* ---- scan coverage detail ---- */
  .coverage-detail { font-size: 9pt; color: #37474f; margin-top: 6pt; }
  .coverage-detail td { padding: 2pt 6pt; }
  .coverage-label { color: #546e7a; }

  /* ---- four-gauge row (MTTR) ---- */
  .mttr-row { width: 100%; border-collapse: collapse; margin-bottom: 12pt; }
  .mttr-cell { width: 25%; text-align: center; padding: 4pt; }
  .mttr-sev-label { font-size: 8pt; font-weight: 700;
                    text-transform: uppercase; margin-bottom: 3pt; }

  /* ---- compliance severity tiles ---- */
  .comp-tile-row { width: 100%; border-collapse: collapse; margin-top: 8pt; }
  .comp-tile { width: 25%; text-align: center; padding: 6pt 2pt; }
  .comp-tile-inner { border-radius: 3pt; padding: 6pt 2pt; }
  .comp-rate { font-size: 16pt; font-weight: 700; }
  .comp-sublabel { font-size: 7.5pt; color: #546e7a; margin-top: 2pt; }

  /* ---- age bar chart section ---- */
  .chart-section { margin-bottom: 16pt; }
  .chart-img { max-width: 100%; }

  /* ---- metric 6 big numbers ---- */
  .m6-row { width: 100%; border-collapse: collapse; margin-top: 14pt; }
  .m6-cell { width: 50%; text-align: center; padding: 14pt 8pt; }
  .m6-big { font-size: 36pt; font-weight: 700; line-height: 1; }
  .m6-sublabel { font-size: 9pt; color: #546e7a; margin-top: 6pt; }
  .m6-explainer { font-size: 8.5pt; color: #546e7a; margin-top: 18pt;
                  border-top: 1pt solid #e0e0e0; padding-top: 10pt;
                  line-height: 1.55; }

  /* ---- trend section ---- */
  .trend-first-run { background: #e8f5e9; border-left: 4pt solid #388e3c;
                     padding: 10pt 14pt; font-size: 9.5pt; color: #2e7d32;
                     margin-bottom: 14pt; }
  .trend-delta-row { width: 100%; border-collapse: collapse; margin-top: 14pt; }
  .trend-delta-cell { width: 50%; text-align: center; padding: 10pt 8pt; }
  .trend-delta-val { font-size: 20pt; font-weight: 700; }
  .trend-delta-label { font-size: 8.5pt; color: #546e7a; margin-top: 4pt; }
  .delta-up { color: #d32f2f; }
  .delta-down { color: #388e3c; }
  .delta-flat { color: #546e7a; }
</style>
"""


def _build_age_bar_chart(m5_data: list) -> str:
    """Horizontal bar chart for Metric 5 (vulnerability age buckets).

    Each bar is coloured from ``_AGE_BUCKETS`` and annotated with
    count + percentage.  Returns a base64-encoded PNG string.
    """
    labels = [b["label"] for b in m5_data]
    counts = [b["count"] for b in m5_data]
    colors = [b["color"] for b in m5_data]
    total  = sum(counts)

    fig, ax = plt.subplots(figsize=(6.5, 2.8))
    fig.patch.set_facecolor("white")

    y_pos = range(len(labels))
    bars  = ax.barh(list(y_pos), counts, color=colors, height=0.55, zorder=2)

    # Annotate each bar
    for bar, b in zip(bars, m5_data):
        w = bar.get_width()
        pct_str = f"{b['pct']:.1f}%"
        label_str = f"{w:,}  ({pct_str})" if w > 0 else "0"
        ax.text(
            w + (total * 0.01 if total > 0 else 1),
            bar.get_y() + bar.get_height() / 2,
            label_str,
            va="center", ha="left", fontsize=8, color="#37474f",
        )

    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlabel("Open Vulnerabilities", fontsize=8.5)
    ax.xaxis.set_tick_params(labelsize=8)
    ax.set_xlim(0, (total or 1) * 1.22)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(left=False)
    ax.grid(axis="x", color="#e0e0e0", linewidth=0.5, zorder=1)
    ax.set_title("Vulnerability Age Distribution (Open)", fontsize=9.5, pad=6)

    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight")
    fig.clf()
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def _build_trend_line_chart(m7_data: dict) -> Optional[str]:
    """Two-line trend chart for Metric 7.

    Lines:
      - Critical + High (red)
      - Medium + Low (amber)

    Returns a base64-encoded PNG string, or ``None`` if fewer than 2
    monthly snapshots are available.
    """
    snapshots = m7_data.get("snapshots", [])
    if len(snapshots) < 2:
        return None

    months     = [s["month"] for s in snapshots]
    crit_high  = [s["critical"] + s["high"] for s in snapshots]
    med_low    = [s["medium"]   + s["low"]  for s in snapshots]

    fig, ax = plt.subplots(figsize=(6.5, 3.0))
    fig.patch.set_facecolor("white")

    ax.plot(months, crit_high, color="#d32f2f", linewidth=2.0,
            marker="o", markersize=5, label="Critical + High", zorder=3)
    ax.plot(months, med_low, color="#f57c00", linewidth=2.0,
            marker="s", markersize=5, label="Medium + Low", zorder=3)

    ax.set_ylabel("Open Vulnerabilities", fontsize=8.5)
    ax.tick_params(axis="x", labelsize=7.5, rotation=30)
    ax.tick_params(axis="y", labelsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#e0e0e0", linewidth=0.5, zorder=1)
    ax.legend(fontsize=8, loc="upper right", frameon=False)
    ax.set_title("Open Vulnerability Trend by Severity Group", fontsize=9.5, pad=6)

    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight")
    fig.clf()
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def _img_tag(b64: str, max_width: str = "100%") -> str:
    """Return an ``<img>`` tag with an inline base64 PNG data URI."""
    return (
        f'<img src="data:image/png;base64,{b64}" '
        f'style="max-width:{max_width}; display:block;" />'
    )


def _build_pdf(
    metrics: dict,
    report_date: datetime,
    tag_filter_label: str,
    output_path: Path,
) -> Path:
    """Render the management summary PDF via WeasyPrint.

    Produces a 5-page letter-size PDF:

    1. Cover
    2. Program Health Overview (Metrics 1 & 2)
    3. Remediation Performance (Metrics 3 & 4)
    4. Backlog and Risk (Metrics 5 & 6)
    5. Trend (Metric 7)

    Parameters
    ----------
    metrics:
        Output of :func:`compute_all_metrics`.
    report_date:
        UTC datetime used for timestamps.
    tag_filter_label:
        Human-readable scope string, e.g. ``"Environment=Production"``.
    output_path:
        Destination ``.pdf`` file path.

    Returns
    -------
    Path
        The resolved path to the written PDF file.
    """
    from weasyprint import HTML as WeasyHTML  # type: ignore  # optional dep

    m1 = metrics["metric_1"]
    m2 = metrics["metric_2"]
    m3 = metrics["metric_3"]
    m4 = metrics["metric_4"]
    m5 = metrics["metric_5"]
    m6 = metrics["metric_6"]
    m7 = metrics["metric_7"]

    period_str = report_date.strftime("%B %Y")
    ts_str     = report_date.strftime("%d %b %Y %H:%M UTC")
    scope_str  = (
        tag_filter_label.replace("=", " = ")
        if tag_filter_label != "all_assets"
        else "All Assets (no tag filter)"
    )

    # ------------------------------------------------------------------
    # Helper: coloured delta arrow text
    # ------------------------------------------------------------------
    def _delta_html(val: Optional[int], label: str) -> str:
        if val is None:
            return (
                f'<div class="trend-delta-val delta-flat">—</div>'
                f'<div class="trend-delta-label">{label}</div>'
            )
        sign  = "+" if val > 0 else ""
        cls   = "delta-up" if val > 0 else ("delta-down" if val < 0 else "delta-flat")
        return (
            f'<div class="trend-delta-val {cls}">{sign}{val:,}</div>'
            f'<div class="trend-delta-label">{label}</div>'
        )

    # ------------------------------------------------------------------
    # Helper: gauge image or N/A placeholder
    # ------------------------------------------------------------------
    def _gauge_or_na(
        value: Optional[float],
        min_val: float,
        max_val: float,
        thresholds: list,
        title: str,
        unit: str,
        reference_line: Optional[float] = None,
        reference_label: Optional[str] = None,
        max_width: str = "170pt",
    ) -> str:
        if value is None:
            return f'<div class="gauge-na">No data</div>'
        b64 = _draw_gauge(
            value=value,
            min_val=min_val,
            max_val=max_val,
            thresholds=thresholds,
            title=title,
            unit=unit,
            reference_line=reference_line,
            reference_label=reference_label,
        )
        return _img_tag(b64, max_width)

    # ------------------------------------------------------------------
    # SLA constants for gauge thresholds
    # ------------------------------------------------------------------
    from config import SLA_DAYS  # type: ignore

    sla_crit = float(SLA_DAYS["critical"])
    sla_high = float(SLA_DAYS["high"])
    sla_med  = float(SLA_DAYS["medium"])
    sla_low  = float(SLA_DAYS["low"])

    mttr_thresholds = {
        "critical": [(sla_crit * 0.8, "#388e3c"), (sla_crit, "#fbc02d"), (sla_crit * 2, "#d32f2f")],
        "high":     [(sla_high * 0.8, "#388e3c"), (sla_high, "#fbc02d"), (sla_high * 2, "#d32f2f")],
        "medium":   [(sla_med  * 0.8, "#388e3c"), (sla_med,  "#fbc02d"), (sla_med  * 2, "#d32f2f")],
        "low":      [(sla_low  * 0.8, "#388e3c"), (sla_low,  "#fbc02d"), (sla_low  * 2, "#d32f2f")],
    }
    compliance_thresholds = [
        (70.0,  "#d32f2f"),
        (85.0,  "#f57c00"),
        (95.0,  "#fbc02d"),
        (100.0, "#388e3c"),
    ]
    coverage_thresholds = [
        (70.0,  "#d32f2f"),
        (85.0,  "#fbc02d"),
        (100.0, "#388e3c"),
    ]

    # ------------------------------------------------------------------
    # PAGE 1 — Cover
    # ------------------------------------------------------------------
    page1 = f"""
<div class="page-break">
  <div class="cover-header">
    <div class="cover-org">[Organisation Name]</div>
    <div class="cover-title">Vulnerability Management<br/>Executive Summary</div>
    <div class="cover-subtitle">Monthly Report — {period_str}</div>
  </div>
  <div class="cover-body">
    <div class="cover-detail">Generated: {ts_str}</div>
    <div class="cover-scope">Scope: {scope_str}</div>
    <div class="cover-detail" style="color:#37474f;">
      This report provides senior leadership with a high-level view of the organisation's
      vulnerability management program performance, remediation compliance, and risk posture.
    </div>
    <div class="cover-confidential">Confidential — For Authorised Recipients Only</div>
  </div>
</div>
"""

    # ------------------------------------------------------------------
    # PAGE 2 — Program Health Overview (Metrics 1 & 2)
    # ------------------------------------------------------------------

    # Metric 2 — scan coverage
    if m2["error"]:
        m2_gauge_html = f'<div class="gauge-na">{m2["error"]}</div>'
        m2_detail_html = ""
    else:
        m2_gauge_html = _gauge_or_na(
            m2["coverage_pct"], 0, 100,
            coverage_thresholds,
            "Scan Coverage", "%",
            max_width="200pt",
        )
        m2_detail_html = f"""
<table class="coverage-detail">
  <tr>
    <td class="coverage-label">Scanned assets:</td>
    <td><strong>{m2['scanned']:,}</strong></td>
  </tr>
  <tr>
    <td class="coverage-label">Not scanned:</td>
    <td><strong>{m2['not_scanned']:,}</strong></td>
  </tr>
  <tr>
    <td class="coverage-label">Total licensed:</td>
    <td><strong>{m2['total_licensed']:,}</strong></td>
  </tr>
  <tr>
    <td class="coverage-label">Status:</td>
    <td style="color:{m2['color']};font-weight:700;">{m2['status']}</td>
  </tr>
</table>"""

    page2 = f"""
<div class="page-break">
  <div class="section-heading">Program Health Overview</div>

  <!-- Metric 1: KPI tiles -->
  <table class="kpi-row">
    <tr>
      <td class="kpi-cell kpi-total">
        <div class="kpi-label">Total Open</div>
        <div class="kpi-value color-total">{m1['total']:,}</div>
      </td>
      <td class="kpi-cell kpi-critical">
        <div class="kpi-label">Critical</div>
        <div class="kpi-value color-critical">{m1['critical']:,}</div>
      </td>
      <td class="kpi-cell kpi-high">
        <div class="kpi-label">High</div>
        <div class="kpi-value color-high">{m1['high']:,}</div>
      </td>
      <td class="kpi-cell kpi-medium">
        <div class="kpi-label">Medium</div>
        <div class="kpi-value color-medium">{m1['medium']:,}</div>
      </td>
      <td class="kpi-cell kpi-low">
        <div class="kpi-label">Low</div>
        <div class="kpi-value color-low">{m1['low']:,}</div>
      </td>
    </tr>
  </table>

  <p style="font-size:8.5pt;color:#546e7a;margin-bottom:14pt;">
    Severity is derived from the Tenable VPR score (Critical ≥ 9.0 · High 7.0–8.9 ·
    Medium 4.0–6.9 · Low &lt; 4.0).  Counts reflect open and re-opened findings only.
  </p>

  <!-- Metric 2: Scan coverage gauge -->
  <table class="two-col">
    <tr>
      <td class="col-left">
        <p style="font-size:10pt;font-weight:700;margin-bottom:6pt;">
          Asset Scan Coverage
        </p>
        <p style="font-size:8.5pt;color:#546e7a;margin-bottom:10pt;">
          Scan coverage measures the percentage of Tenable-licensed assets that received
          at least one authenticated scan within the past 30 days.  Assets outside this
          window have unknown risk posture and represent blind spots in the program.
        </p>
        {m2_detail_html}
      </td>
      <td class="col-right">
        <div class="gauge-block">
          {m2_gauge_html}
        </div>
      </td>
    </tr>
  </table>
</div>
"""

    # ------------------------------------------------------------------
    # PAGE 3 — Remediation Performance (Metrics 3 & 4)
    # ------------------------------------------------------------------

    mttr_vals = m3.get("mttr", {})

    def _mttr_cell(sev: str, label: str, sla: float) -> str:
        v = mttr_vals.get(sev)
        img = _gauge_or_na(
            v, 0, sla * 2,
            mttr_thresholds[sev],
            f"MTTR – {label}", "d",
            reference_line=sla,
            reference_label="SLA",
            max_width="130pt",
        )
        color_map = {"critical": "#d32f2f", "high": "#f57c00",
                     "medium": "#f9a825", "low": "#388e3c"}
        return (
            f'<td class="mttr-cell">'
            f'<div class="mttr-sev-label" style="color:{color_map[sev]};">{label}</div>'
            f'{img}'
            f'</td>'
        )

    # Overall compliance gauge
    comp_gauge_html = _gauge_or_na(
        m4["overall_rate"], 0, 100,
        compliance_thresholds,
        "SLA Compliance", "%",
        max_width="190pt",
    )

    # Per-severity compliance tiles
    def _comp_tile(sev: str, label: str) -> str:
        ps  = m4.get("per_severity", {}).get(sev, {})
        rate = ps.get("rate")
        bg_map  = {"critical": "#ffebee", "high": "#fff3e0",
                   "medium": "#fffde7",   "low": "#e8f5e9"}
        col_map = {"critical": "#d32f2f", "high": "#f57c00",
                   "medium": "#f9a825",   "low": "#388e3c"}
        val_str  = f"{rate:.0f}%" if rate is not None else "N/A"
        wi_str   = f"{ps.get('within_sla', 0):,} within SLA"
        return (
            f'<td class="comp-tile">'
            f'<div class="comp-tile-inner" style="background:{bg_map[sev]};">'
            f'<div class="comp-rate" style="color:{col_map[sev]};">{val_str}</div>'
            f'<div style="font-size:8pt;font-weight:700;color:{col_map[sev]};">{label}</div>'
            f'<div class="comp-sublabel">{wi_str}</div>'
            f'</div></td>'
        )

    page3 = f"""
<div class="page-break">
  <div class="section-heading">Remediation Performance</div>

  <!-- Metric 3: MTTR gauges -->
  <p style="font-size:10pt;font-weight:700;margin-bottom:4pt;">
    Mean Time to Remediate (MTTR) by Severity
  </p>
  <p style="font-size:8.5pt;color:#546e7a;margin-bottom:10pt;">
    MTTR measures the average number of days between a vulnerability being first
    observed and its confirmed fix.  Reference tick marks indicate the program's SLA
    target for each severity tier (Critical 15 d · High 30 d · Medium 90 d · Low 180 d).
    A needle inside the green zone indicates the team is resolving findings within SLA on
    average.  "No data" gauges indicate no fixed vulnerabilities were found in this
    reporting period for that severity tier.
  </p>
  <table class="mttr-row">
    <tr>
      {_mttr_cell("critical", "Critical", sla_crit)}
      {_mttr_cell("high",     "High",     sla_high)}
      {_mttr_cell("medium",   "Medium",   sla_med)}
      {_mttr_cell("low",      "Low",      sla_low)}
    </tr>
  </table>

  <!-- Metric 4: SLA compliance -->
  <p style="font-size:10pt;font-weight:700;margin-bottom:4pt;margin-top:8pt;">
    SLA Compliance Rate
  </p>
  <p style="font-size:8.5pt;color:#546e7a;margin-bottom:10pt;">
    Compliance rate is the percentage of <em>currently open</em> vulnerabilities whose
    age has not yet exceeded the SLA deadline for their severity.  A finding first seen
    today counts as within SLA; a Critical finding open for 16 days is overdue.
    The program target is ≥ 90 % compliance across all severity tiers.
  </p>
  <table class="two-col">
    <tr>
      <td class="col-left">
        <table class="comp-tile-row">
          <tr>
            {_comp_tile("critical", "Critical")}
            {_comp_tile("high",     "High")}
            {_comp_tile("medium",   "Medium")}
            {_comp_tile("low",      "Low")}
          </tr>
        </table>
        <p style="font-size:8.5pt;color:#37474f;margin-top:10pt;">
          Overall: <strong style="font-size:13pt;color:{m4['color']};">
          {f"{m4['overall_rate']:.1f}%" if m4['overall_rate'] is not None else "N/A"}
          </strong>
          &nbsp;({m4['within_sla']:,} of {m4['total_open']:,} open findings within SLA)
          &nbsp;&nbsp;<span style="color:{m4['color']};font-weight:700;">{m4['status']}</span>
        </p>
      </td>
      <td class="col-right">
        <div class="gauge-block">
          {comp_gauge_html}
        </div>
      </td>
    </tr>
  </table>
</div>
"""

    # ------------------------------------------------------------------
    # PAGE 4 — Backlog and Risk (Metrics 5 & 6)
    # ------------------------------------------------------------------

    age_chart_b64 = _build_age_bar_chart(m5)
    age_chart_html = _img_tag(age_chart_b64, "100%")

    # Metric 6 values
    exc_count = m6["open_exceptions"]
    exc_rate  = m6["exception_rate"]
    exc_rate_str = f"{exc_rate:.1f}%"

    page4 = f"""
<div class="page-break">
  <div class="section-heading">Backlog and Risk</div>

  <!-- Metric 5: Age distribution bar chart -->
  <p style="font-size:10pt;font-weight:700;margin-bottom:4pt;">
    Vulnerability Age Distribution
  </p>
  <p style="font-size:8.5pt;color:#546e7a;margin-bottom:10pt;">
    This chart shows how long current open vulnerabilities have been present in the
    environment, grouped into age bands.  A healthy program concentrates volume in the
    shorter bands (0–60 days).  Significant bars in the 91+ day ranges indicate a
    remediation backlog that may require prioritised attention or resourcing.
  </p>
  <div class="chart-section">
    {age_chart_html}
  </div>

  <!-- Metric 6: Exception rate -->
  <p style="font-size:10pt;font-weight:700;margin-bottom:4pt;margin-top:4pt;">
    Managed Exception Rate
  </p>
  <table class="m6-row">
    <tr>
      <td class="m6-cell">
        <div class="m6-big" style="color:{m6['rate_color']};">{exc_rate_str}</div>
        <div class="m6-sublabel">of open findings are managed exceptions</div>
      </td>
      <td class="m6-cell">
        <div class="m6-big" style="color:#37474f;">{exc_count:,}</div>
        <div class="m6-sublabel">open managed exception findings<br/>
          (out of {m6['total_open']:,} total open)</div>
      </td>
    </tr>
  </table>
  <div class="m6-explainer">
    <strong>What are managed exceptions?</strong>&nbsp; A managed exception is an open
    vulnerability that has been formally reviewed and approved for handling outside the
    standard SLA.  This includes <em>risk acceptances</em> — where the finding is
    acknowledged and accepted as a residual risk — and <em>severity recasts</em> — where
    the assigned severity has been adjusted by a security analyst based on compensating
    controls or environmental context.  Both types are captured here because they
    represent active management decisions rather than unaddressed gaps.  A low exception
    rate indicates the program is resolving most findings through standard remediation.
    A rising rate warrants review to ensure exceptions are justified and not masking
    remediation debt.
  </div>
</div>
"""

    # ------------------------------------------------------------------
    # PAGE 5 — Trend (Metric 7)
    # ------------------------------------------------------------------

    trend_chart_b64  = _build_trend_line_chart(m7)
    trend_chart_html = (
        _img_tag(trend_chart_b64, "100%") if trend_chart_b64 else ""
    )

    if m7["first_run_notice"]:
        trend_notice_html = """
<div class="trend-first-run">
  <strong>Trend data is being established.</strong><br/>
  This is the first time the Management Executive Summary has been generated for this
  scope.  Monthly snapshots will accumulate automatically each time the report runs.
  A trend chart will appear once at least two months of data are available.
</div>"""
    else:
        trend_notice_html = ""

    delta_crit_high = m7.get("delta_critical_high")
    delta_med_low   = m7.get("delta_medium_low")

    page5 = f"""
<div>
  <div class="section-heading">Vulnerability Trend</div>

  <p style="font-size:8.5pt;color:#546e7a;margin-bottom:10pt;">
    Trend data reflects end-of-month open vulnerability counts saved each time this
    report is generated.  The Critical + High line represents the highest-priority
    backlog requiring executive attention; the Medium + Low line indicates broader
    program hygiene.  Downward movement on both lines over consecutive months
    indicates a maturing, effective program.
  </p>

  {trend_notice_html}
  {trend_chart_html}

  <!-- Month-over-month delta summary -->
  <table class="trend-delta-row" style="margin-top:{'8pt' if trend_chart_b64 else '0'};">
    <tr>
      <td class="trend-delta-cell">
        {_delta_html(delta_crit_high, "month-over-month change · Critical + High")}
      </td>
      <td class="trend-delta-cell">
        {_delta_html(delta_med_low, "month-over-month change · Medium + Low")}
      </td>
    </tr>
  </table>

  <p style="font-size:8pt;color:#9e9e9e;margin-top:20pt;text-align:center;">
    {REPORT_NAME} · Generated {ts_str} · Scope: {scope_str}
  </p>
</div>
"""

    # ------------------------------------------------------------------
    # Assemble and render
    # ------------------------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{REPORT_NAME} — {period_str}</title>
  {_PDF_CSS}
</head>
<body>
{page1}
{page2}
{page3}
{page4}
{page5}
</body>
</html>"""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    WeasyHTML(string=html).write_pdf(str(output_path))
    logger.info("PDF written: %s", output_path)
    return output_path


def _run_pdf_test(
    output_dir: Optional[Path] = None,
    tag_category: Optional[str] = None,
    tag_value: Optional[str] = None,
) -> None:
    """Render a test PDF using synthetic metric data — no Tenable connection needed."""
    out = Path(output_dir) if output_dir else ROOT_DIR / "output" / "pdf_test"
    out.mkdir(parents=True, exist_ok=True)
    _console.print(f"[bold]Generating test PDF -> {out}[/bold]")

    report_date      = datetime.now(tz=timezone.utc)
    tag_filter_label = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all_assets"
    )

    # ---- synthetic metrics ----
    synthetic_metrics = {
        "metric_1": {
            "critical": 12, "high": 47, "medium": 183, "low": 64, "total": 306
        },
        "metric_2": {
            "coverage_pct": 87.3, "scanned": 218, "not_scanned": 32,
            "total_licensed": 250, "status": "Attention", "color": "#f57c00",
            "error": None,
        },
        "metric_3": {
            "mttr": {"critical": 11.2, "high": 22.4, "medium": 68.0, "low": None},
            "status": "Within SLA", "color": "#388e3c", "total_fixed": 94,
        },
        "metric_4": {
            "overall_rate": 81.7,
            "per_severity": {
                "critical": {"rate": 75.0, "within_sla": 9,  "total": 12},
                "high":     {"rate": 85.1, "within_sla": 40, "total": 47},
                "medium":   {"rate": 80.3, "within_sla": 147,"total": 183},
                "low":      {"rate": 90.6, "within_sla": 58, "total": 64},
            },
            "within_sla": 254, "total_open": 306,
            "status": "Below Target", "color": "#f57c00",
        },
        "metric_5": [
            {"label": "0–30 days",    "min_days": 0,   "max_days": 30,
             "count": 78,  "pct": 25.5, "color": "#388e3c"},
            {"label": "31–60 days",   "min_days": 31,  "max_days": 60,
             "count": 62,  "pct": 20.3, "color": "#7cb342"},
            {"label": "61–90 days",   "min_days": 61,  "max_days": 90,
             "count": 55,  "pct": 18.0, "color": "#fbc02d"},
            {"label": "91–180 days",  "min_days": 91,  "max_days": 180,
             "count": 73,  "pct": 23.9, "color": "#f57c00"},
            {"label": "181–365 days", "min_days": 181, "max_days": 365,
             "count": 28,  "pct": 9.2,  "color": "#e64a19"},
            {"label": "365+ days",    "min_days": 366, "max_days": 99999,
             "count": 10,  "pct": 3.3,  "color": "#d32f2f"},
        ],
        "metric_6": {
            "open_exceptions": 7, "total_open": 306,
            "exception_rate": 2.3, "rate_color": "#388e3c",
            "rate_label": "Low",
        },
        "metric_7": {
            "snapshots": [
                {"month": "2025-09", "critical": 18, "high": 52, "medium": 201, "low": 70},
                {"month": "2025-10", "critical": 16, "high": 50, "medium": 196, "low": 68},
                {"month": "2025-11", "critical": 14, "high": 49, "medium": 190, "low": 67},
                {"month": "2025-12", "critical": 13, "high": 48, "medium": 185, "low": 65},
                {"month": "2026-01", "critical": 12, "high": 47, "medium": 183, "low": 64},
            ],
            "delta_critical_high": -2,
            "delta_medium_low":    -2,
            "has_trend":          True,
            "first_run_notice":   False,
        },
    }

    pdf_path = out / f"management_summary_test_{report_date.strftime('%Y%m%d_%H%M')}.pdf"
    _build_pdf(synthetic_metrics, report_date, tag_filter_label, pdf_path)
    _console.print(f"[green]OK[/green] PDF written: {pdf_path}")


# ===========================================================================
# Step 4 — Email builder
# ===========================================================================

_RED    = "#d32f2f"
_ORANGE = "#f57c00"
_AMBER  = "#fbc02d"
_GREEN  = "#388e3c"
_GREY   = "#757575"


def build_email_kpi_tiles(metrics: dict) -> list[dict]:
    """Return five KPI tile dicts for the email template renderer.

    Each dict has keys ``label``, ``value``, ``color``, and optionally
    ``sub_label``.  The same format is used by ``ops_remediation`` so the
    email template can render them identically.

    Tiles
    -----
    1. Open Criticals        — Metric 1
    2. Open Highs            — Metric 1
    3. SLA Compliance Rate   — Metric 4
    4. Scan Coverage         — Metric 2
    5. Exception Rate        — Metric 6
    """
    m1 = metrics["metric_1"]
    m2 = metrics["metric_2"]
    m4 = metrics["metric_4"]
    m6 = metrics["metric_6"]

    # Tile 1 — Open Criticals
    crit = m1["critical"]
    tile_crit = {
        "label": "Open Criticals",
        "value": f"{crit:,}",
        "color": _RED if crit > 0 else _GREEN,
    }

    # Tile 2 — Open Highs
    high = m1["high"]
    tile_high = {
        "label": "Open Highs",
        "value": f"{high:,}",
        "color": _ORANGE if high > 0 else _GREEN,
    }

    # Tile 3 — SLA Compliance Rate
    comp_rate = m4.get("overall_rate")
    comp_str  = f"{comp_rate:.1f}%" if comp_rate is not None else "N/A"
    if comp_rate is None:
        comp_color = _GREY
    elif comp_rate >= 90:
        comp_color = _GREEN
    elif comp_rate >= 75:
        comp_color = _AMBER
    else:
        comp_color = _RED
    tile_sla = {
        "label":     "SLA Compliance",
        "value":     comp_str,
        "color":     comp_color,
        "sub_label": f"{m4.get('within_sla', 0):,} of {m4.get('total_open', 0):,} findings on track",
    }

    # Tile 4 — Scan Coverage
    if m2.get("error"):
        cov_str   = "N/A"
        cov_color = _GREY
        cov_sub   = "data unavailable"
    else:
        cov_pct   = m2["coverage_pct"]
        cov_str   = f"{cov_pct:.1f}%"
        cov_color = _GREEN if cov_pct >= 90 else (_AMBER if cov_pct >= 75 else _RED)
        cov_sub   = f"{m2['scanned']:,} of {m2['total_licensed']:,} assets scanned"
    tile_coverage = {
        "label":     "Scan Coverage",
        "value":     cov_str,
        "color":     cov_color,
        "sub_label": cov_sub,
    }

    # Tile 5 — Exception Rate
    exc_rate = m6["exception_rate"]
    exc_str  = f"{exc_rate:.1f}%"
    tile_exc = {
        "label":     "Exception Rate",
        "value":     exc_str,
        "color":     m6["rate_color"],
        "sub_label": f"{m6['open_exceptions']:,} accepted or recast findings",
    }

    return [tile_crit, tile_high, tile_sla, tile_coverage, tile_exc]


# ---------------------------------------------------------------------------
# Inline-CSS email body
# ---------------------------------------------------------------------------

_EMAIL_CSS = """
  body{margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#212121;}
  .wrapper{max-width:680px;margin:0 auto;background:#ffffff;}
  /* header */
  .hdr{background:#0d2b55;padding:24px 32px;}
  .hdr-title{color:#ffffff;font-size:20px;font-weight:700;margin:0 0 2px 0;}
  .hdr-sub{color:#90caf9;font-size:12px;margin:0;}
  /* scope banner */
  .scope{background:#e3f2fd;border-left:4px solid #1976d2;padding:10px 32px;
         font-size:12px;color:#0d47a1;}
  /* section label */
  .sec-label{padding:14px 32px 4px 32px;font-size:11px;font-weight:700;
              text-transform:uppercase;letter-spacing:0.8px;color:#546e7a;}
  /* KPI tiles — table-based for Outlook compatibility */
  .kpi-wrap{padding:4px 24px 16px 24px;}
  .kpi-tbl{border-collapse:separate;border-spacing:8px 0;width:100%;}
  .kpi-td{width:20%;text-align:center;padding:12px 4px;border-radius:4px;}
  .kpi-val{font-size:22px;font-weight:700;line-height:1.1;display:block;}
  .kpi-lbl{font-size:9px;text-transform:uppercase;letter-spacing:0.7px;
            color:#546e7a;display:block;margin-top:3px;}
  .kpi-sub{font-size:8.5px;color:#9e9e9e;display:block;margin-top:2px;}
  /* chart */
  .chart-wrap{padding:0 32px 16px 32px;text-align:center;}
  .chart-wrap img{max-width:100%;height:auto;display:block;margin:0 auto;}
  /* trend delta row */
  .delta-wrap{padding:0 24px 16px 24px;}
  .delta-tbl{border-collapse:collapse;width:100%;}
  .delta-td{width:50%;text-align:center;padding:10px 8px;
             border:1px solid #e0e0e0;border-radius:3px;}
  .delta-val{font-size:20px;font-weight:700;}
  .delta-lbl{font-size:9px;color:#546e7a;margin-top:3px;}
  .d-up{color:#d32f2f;} .d-dn{color:#388e3c;} .d-flat{color:#546e7a;}
  /* attachments */
  .attach-wrap{padding:0 32px 16px 32px;}
  .attach-wrap ul{margin:4px 0 0 16px;padding:0;color:#37474f;font-size:12px;line-height:1.8;}
  /* SLA table */
  .sla-wrap{padding:0 32px 16px 32px;}
  .sla-tbl{border-collapse:collapse;width:100%;font-size:11px;}
  .sla-tbl th{background:#0d2b55;color:#ffffff;padding:6px 10px;text-align:left;}
  .sla-tbl td{padding:5px 10px;border-bottom:1px solid #e0e0e0;}
  .sla-tbl tr:last-child td{border-bottom:none;}
  /* footer */
  .footer{background:#eceff1;padding:14px 32px;font-size:10px;color:#78909c;line-height:1.6;}
"""


def build_email_body(
    metrics: dict,
    report_date: datetime,
    tag_filter_label: str,
    group_name: str = "",
) -> tuple[str, dict[str, str]]:
    """Build the HTML email body for the Management Executive Summary.

    Embeds the age distribution chart as a CID inline image so it renders
    in Outlook and Gmail without requiring attachment downloads.

    Parameters
    ----------
    metrics:
        Output of :func:`compute_all_metrics`.
    report_date:
        UTC datetime of the report run.
    tag_filter_label:
        Human-readable scope string, e.g. ``"Environment=Production"``.
    group_name:
        Delivery group name from ``delivery_config.yaml``; used in the header.

    Returns
    -------
    tuple[str, dict[str, str]]
        ``(html_body, inline_charts)`` where ``inline_charts`` maps CID names
        (e.g. ``"chart_1"``) to base64-encoded PNG strings for attachment by
        the email sender.
    """
    m7 = metrics["metric_7"]

    period_str = report_date.strftime("%B %Y")
    ts_str     = report_date.strftime("%d %b %Y %H:%M UTC")
    scope_str  = (
        tag_filter_label.replace("=", " = ")
        if tag_filter_label != "all_assets"
        else "All Assets"
    )
    header_sub = f"{group_name} &nbsp;·&nbsp; {ts_str}" if group_name else ts_str

    # ------------------------------------------------------------------
    # KPI tiles HTML
    # ------------------------------------------------------------------
    tiles = build_email_kpi_tiles(metrics)
    bg_map = {
        _RED:    "#ffebee",
        _ORANGE: "#fff3e0",
        _AMBER:  "#fffde7",
        _GREEN:  "#e8f5e9",
        _GREY:   "#f5f5f5",
    }

    def _tile_td(tile: dict) -> str:
        bg  = bg_map.get(tile["color"], "#f5f5f5")
        sub = (f'<span class="kpi-sub">{tile["sub_label"]}</span>'
               if tile.get("sub_label") else "")
        return (
            f'<td class="kpi-td" style="background:{bg};">'
            f'<span class="kpi-val" style="color:{tile["color"]};">{tile["value"]}</span>'
            f'<span class="kpi-lbl">{tile["label"]}</span>'
            f'{sub}'
            f'</td>'
        )

    tiles_html = (
        '<table class="kpi-tbl" role="presentation">'
        "<tr>" + "".join(_tile_td(t) for t in tiles) + "</tr>"
        "</table>"
    )

    # ------------------------------------------------------------------
    # Inline chart — age distribution bar chart (CID: chart_1)
    # ------------------------------------------------------------------
    inline_charts: dict[str, str] = {}
    age_b64 = _build_age_bar_chart(metrics["metric_5"])
    inline_charts["chart_1"] = age_b64
    chart_html = (
        '<img src="cid:chart_1" alt="Vulnerability Age Distribution" '
        'style="max-width:600px;width:100%;height:auto;display:block;margin:0 auto;" />'
    )

    # ------------------------------------------------------------------
    # Month-over-month trend delta
    # ------------------------------------------------------------------
    def _delta_td(val: Optional[int], label: str) -> str:
        if val is None:
            cls, sign = "d-flat", ""
        elif val > 0:
            cls, sign = "d-up", "+"
        elif val < 0:
            cls, sign = "d-dn", ""
        else:
            cls, sign = "d-flat", ""
        val_str = f"{sign}{val:,}" if val is not None else "—"
        return (
            f'<td class="delta-td">'
            f'<div class="delta-val {cls}">{val_str}</div>'
            f'<div class="delta-lbl">{label}</div>'
            f'</td>'
        )

    if m7["has_trend"]:
        delta_html = (
            '<table class="delta-tbl" role="presentation"><tr>'
            + _delta_td(m7.get("delta_critical_high"), "month-over-month · Critical + High")
            + _delta_td(m7.get("delta_medium_low"),    "month-over-month · Medium + Low")
            + "</tr></table>"
        )
    elif m7["first_run_notice"]:
        delta_html = (
            '<p style="font-size:11px;color:#2e7d32;background:#e8f5e9;'
            'border-left:3px solid #388e3c;padding:8px 12px;margin:0;">'
            "<strong>Trend data is being established.</strong> Month-over-month "
            "comparisons will appear once a second monthly snapshot is available."
            "</p>"
        )
    else:
        delta_html = ""

    # ------------------------------------------------------------------
    # SLA reference table
    # ------------------------------------------------------------------
    sla_rows = [
        ("Critical", "9.0 – 10.0", "15 days", "#d32f2f"),
        ("High",     "7.0 – 8.9",  "30 days", "#f57c00"),
        ("Medium",   "4.0 – 6.9",  "90 days", "#f9a825"),
        ("Low",      "0.1 – 3.9",  "180 days","#388e3c"),
    ]
    sla_row_html = "".join(
        f'<tr><td style="color:{c};font-weight:700;">{s}</td>'
        f'<td>{vpr}</td><td>{sla}</td></tr>'
        for s, vpr, sla, c in sla_rows
    )

    # ------------------------------------------------------------------
    # Assemble
    # ------------------------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{REPORT_NAME} — {period_str}</title>
  <style>{_EMAIL_CSS}</style>
</head>
<body>
<div class="wrapper">

  <!-- Header -->
  <div class="hdr">
    <p class="hdr-title">{REPORT_NAME}</p>
    <p class="hdr-sub">{header_sub}</p>
  </div>

  <!-- Scope banner -->
  <div class="scope">Scope: <strong>{scope_str}</strong></div>

  <!-- KPI tiles -->
  <div class="sec-label">Key Metrics — {period_str}</div>
  <div class="kpi-wrap">{tiles_html}</div>

  <!-- Age distribution chart -->
  <div class="sec-label">Vulnerability Age Distribution</div>
  <div class="chart-wrap">{chart_html}</div>

  <!-- Trend delta -->
  {'<div class="sec-label">Month-over-Month Change</div><div class="delta-wrap">' + delta_html + '</div>' if delta_html else ''}

  <!-- Attached reports -->
  <div class="sec-label">Attached Report</div>
  <div class="attach-wrap">
    <ul>
      <li><strong>Management Executive Summary (PDF)</strong> — seven high-level metrics
          covering open vulnerability counts, scan coverage, MTTR, SLA compliance,
          backlog age, exception rate, and trend.</li>
    </ul>
  </div>

  <!-- SLA reference -->
  <div class="sec-label">SLA Reference</div>
  <div class="sla-wrap">
    <table class="sla-tbl" role="presentation">
      <tr>
        <th>Severity</th><th>VPR Score</th><th>SLA (Days to Remediate)</th>
      </tr>
      {sla_row_html}
    </table>
  </div>

  <!-- Footer -->
  <div class="footer">
    Generated: {ts_str} &nbsp;·&nbsp; Scope: {scope_str}<br />
    To update recipients or report filters, contact:
    <a href="mailto:{{reply_to}}" style="color:#1976d2;">{{reply_to}}</a><br />
    This report is generated automatically by the Vulnerability Management Reporting Suite.
  </div>

</div>
</body>
</html>"""

    return html, inline_charts


def _email_preview_html(html: str, inline_charts: dict[str, str]) -> str:
    """Return a browser-viewable copy of the email HTML.

    Replaces ``cid:<name>`` image references with inline ``data:image/png;base64,``
    URIs so the preview renders correctly when opened in a browser.
    The original *html* string (with CID references) is unchanged and should
    be used for the actual SMTP send.
    """
    preview = html
    for cid, b64 in inline_charts.items():
        preview = preview.replace(
            f"cid:{cid}",
            f"data:image/png;base64,{b64}",
        )
    return preview


# ===========================================================================
# __main__ — Step 1 + 2 test runner
# ===========================================================================


def _print_metrics(metrics: dict, report_date: datetime, tag_label: str) -> None:
    """Print a rich summary of all computed metrics to the console."""
    _console.rule(f"[bold blue]{REPORT_NAME} — Step 1 Metric Review[/bold blue]")
    _console.print(
        f"  [dim]Report date:[/dim] {report_date.strftime('%Y-%m-%d %H:%M UTC')}  "
        f"  [dim]Scope:[/dim] {tag_label}\n"
    )

    # --- Metric 1 ---
    m1 = metrics["metric_1"]
    t = Table(title="Metric 1 — Total Vulnerabilities by Severity",
              box=box.SIMPLE_HEAD, show_header=True)
    for col in ("Critical", "High", "Medium", "Low", "Total"):
        t.add_column(col, justify="right")
    t.add_row(
        f"[red]{m1['critical']:,}[/red]",
        f"[yellow]{m1['high']:,}[/yellow]",
        f"[cyan]{m1['medium']:,}[/cyan]",
        f"[green]{m1['low']:,}[/green]",
        f"[bold]{m1['total']:,}[/bold]",
    )
    _console.print(t)

    # --- Metric 2 ---
    m2 = metrics["metric_2"]
    if m2["error"]:
        _console.print(f"[bold]Metric 2 — Scan Coverage:[/bold] {m2['error']}\n")
    else:
        _console.print(
            f"[bold]Metric 2 — Scan Coverage:[/bold]  "
            f"{m2['coverage_pct']}%  [{m2['status']}]  "
            f"(Scanned: {m2['scanned']:,}  Not scanned: {m2['not_scanned']:,} "
            f"of {m2['total_licensed']:,} licensed)\n"
        )

    # --- Metric 3 ---
    m3 = metrics["metric_3"]
    t3 = Table(title=f"Metric 3 — MTTR by Severity  (total fixed in scope: {m3['total_fixed']:,})",
               box=box.SIMPLE_HEAD, show_header=True)
    for col in ("Severity", "MTTR (days)", "SLA Target", "Status"):
        t3.add_column(col)
    for sev in ("critical", "high", "medium", "low"):
        mttr_val  = f"{m3['mttr'][sev]:.1f}" if m3["mttr"][sev] is not None else "N/A"
        stat_val  = m3["status"][sev] or "N/A"
        t3.add_row(sev.title(), mttr_val, f"{SLA_DAYS[sev]}d", stat_val)
    _console.print(t3)

    # --- Metric 4 ---
    m4 = metrics["metric_4"]
    _console.print(
        f"[bold]Metric 4 — Patch Compliance Rate:[/bold]  "
        f"{m4['overall_rate']}%  [{m4['status']}]  "
        f"({m4['within_sla']:,} of {m4['total_open']:,} open within SLA)"
    )
    per_sev_str = "  ".join(
        f"{s.title()}: {m4['per_severity'][s]['rate']}%"
        for s in ("critical", "high", "medium", "low")
    )
    _console.print(f"  Per-severity: {per_sev_str}\n")

    # --- Metric 5 ---
    t5 = Table(title="Metric 5 — Backlog Age Distribution",
               box=box.SIMPLE_HEAD, show_header=True)
    for col in ("Age Bucket", "Count", "% of Open"):
        t5.add_column(col, justify="right" if col != "Age Bucket" else "left")
    for bucket in metrics["metric_5"]:
        t5.add_row(bucket["label"], f"{bucket['count']:,}", f"{bucket['pct']}%")
    _console.print(t5)

    # --- Metric 6 ---
    m6 = metrics["metric_6"]
    rate_str = f"{m6['exception_rate']}%" if m6["exception_rate"] is not None else "N/A"
    _console.print(
        f"[bold]Metric 6 — Exception Rate:[/bold]  "
        f"{m6['open_exceptions']:,} open exceptions  |  {rate_str} of total open  "
        f"[{m6['rate_label']}]\n"
    )

    # --- Metric 7 ---
    m7 = metrics["metric_7"]
    _console.print(
        f"[bold]Metric 7 — Trend:[/bold]  "
        f"{len(m7['snapshots'])} snapshot(s) on record  |  "
        f"Has trend: {m7['has_trend']}  |  First-run notice: {m7['first_run_notice']}"
    )
    if m7["has_trend"]:
        dch = m7["delta_critical_high"]
        dml = m7["delta_medium_low"]
        arrow_ch = "v" if dch < 0 else ("^" if dch > 0 else "—")
        arrow_ml = "v" if dml < 0 else ("^" if dml > 0 else "—")
        color_ch = "green" if dch < 0 else ("red" if dch > 0 else "white")
        color_ml = "green" if dml < 0 else ("red" if dml > 0 else "white")
        _console.print(
            f"  [{color_ch}]Critical+High: {arrow_ch} {abs(dch)} from last month[/{color_ch}]  "
            f"  [{color_ml}]Medium+Low: {arrow_ml} {abs(dml)} from last month[/{color_ml}]"
        )
    if m7["first_run_notice"]:
        _console.print(
            "  [dim]First-run notice: trend will display from the next "
            "monthly snapshot onward.[/dim]"
        )
    _console.print()
    _console.rule()


# ===========================================================================
# Step 5 — run_report() entry point (called by run_all.py / scheduler.py)
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
    """Main entry point called by ``run_all.py`` and ``scheduler.py``.

    Signature matches the convention used by all other report modules so
    ``run_all.py`` can call it uniformly.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Date string (``YYYY-MM-DD``) used to name the default output
        directory when *output_dir* is not provided.
    tag_category, tag_value : str, optional
        Tag filter for asset scoping.
    output_dir : Path, optional
        Where to write the PDF.  Created if it does not exist.
        Defaults to ``OUTPUT_DIR / run_id / "management_summary"``.
    generated_at : datetime, optional
        Report timestamp.  Defaults to UTC now.
    cache_dir : Path, optional
        Parquet cache directory shared across the batch run.
        Defaults to ``CACHE_DIR / run_id``.

    Returns
    -------
    dict
        ``{"pdf": Path, "excel": None, "charts": [], "metrics": dict}``
        where ``metrics`` contains ``kpi_tiles`` (list of tile dicts consumed
        by the email template renderer) and ``raw`` (flat summary numbers),
        plus ``email_html`` and ``inline_charts`` for direct use by
        ``email_sender.py``.
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if cache_dir is None:
        cache_dir = CACHE_DIR / (run_id or generated_at.strftime("%Y-%m-%d"))
    if output_dir is None:
        output_dir = OUTPUT_DIR / (run_id or generated_at.strftime("%Y-%m-%d")) / REPORT_SLUG
    output_dir = Path(output_dir)
    cache_dir  = Path(cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    tag_filter_label = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all_assets"
    )

    logger.info(
        "[%s] Starting | filter=%s=%s | output=%s",
        REPORT_NAME,
        tag_category or "*",
        tag_value    or "*",
        output_dir,
    )

    # ------------------------------------------------------------------
    # Fetch data (uses shared parquet cache)
    # ------------------------------------------------------------------
    vulns_raw  = fetch_all_vulnerabilities(tio, cache_dir)
    assets_raw = fetch_all_assets(tio, cache_dir)
    fixed_raw  = fetch_fixed_vulnerabilities(tio, cache_dir)

    # ------------------------------------------------------------------
    # Enrich and filter by tag
    # ------------------------------------------------------------------
    vulns_enriched = enrich_vulns_with_assets(vulns_raw, assets_raw)
    vulns_df       = filter_by_tag(vulns_enriched, tag_category, tag_value)
    assets_df      = filter_by_tag(assets_raw, tag_category, tag_value)

    fixed_enriched = enrich_vulns_with_assets(fixed_raw, assets_raw)
    fixed_vulns_df = filter_by_tag(fixed_enriched, tag_category, tag_value)

    logger.info(
        "[%s] In-scope: %d open vulns, %d assets, %d fixed vulns",
        REPORT_NAME, len(vulns_df), len(assets_df), len(fixed_vulns_df),
    )

    # ------------------------------------------------------------------
    # Trend file + compute metrics
    # ------------------------------------------------------------------
    trend_file       = _trend_file_path(tag_category, tag_value)
    month_str        = generated_at.strftime("%Y-%m")

    metrics = compute_all_metrics(
        vulns_df         = vulns_df,
        assets_df        = assets_df,
        fixed_vulns_df   = fixed_vulns_df,
        trend_file       = trend_file,
        tag_filter_label = tag_filter_label,
        report_date      = generated_at,
    )

    _save_trend_snapshot(
        trend_file       = trend_file,
        month_str        = month_str,
        tag_filter_label = tag_filter_label,
        sev_counts       = metrics["metric_1"],
        generated_at     = generated_at,
    )

    # ------------------------------------------------------------------
    # Build PDF
    # ------------------------------------------------------------------
    slug_str = safe_filename(f"{tag_category or 'all'}_{tag_value or 'assets'}")
    pdf_path = output_dir / f"{REPORT_SLUG}_{slug_str}.pdf"
    _build_pdf(metrics, generated_at, tag_filter_label, pdf_path)
    logger.info("[%s] PDF written: %s", REPORT_NAME, pdf_path.name)

    # ------------------------------------------------------------------
    # Build email body (pre-built HTML + inline charts dict)
    # ------------------------------------------------------------------
    email_html, inline_charts = build_email_body(
        metrics          = metrics,
        report_date      = generated_at,
        tag_filter_label = tag_filter_label,
    )

    # Write browser-viewable preview alongside the PDF
    preview_path = output_dir / f"{REPORT_SLUG}_email_preview.html"
    preview_path.write_text(_email_preview_html(email_html, inline_charts), encoding="utf-8")
    logger.info("[%s] Email preview written: %s", REPORT_NAME, preview_path.name)

    # ------------------------------------------------------------------
    # Package return value
    # ------------------------------------------------------------------
    kpi_tiles = build_email_kpi_tiles(metrics)
    m1 = metrics["metric_1"]
    m2 = metrics["metric_2"]
    m4 = metrics["metric_4"]
    m6 = metrics["metric_6"]

    email_metrics = {
        "kpi_tiles": kpi_tiles,
        # Pre-built HTML body — email_sender.py uses this directly when present,
        # bypassing generic template rendering.
        "email_html":    email_html,
        "inline_charts": inline_charts,
        "raw": {
            "tag_filter":       tag_filter_label,
            "generated_at":     generated_at.isoformat(),
            "open_critical":    m1["critical"],
            "open_high":        m1["high"],
            "open_medium":      m1["medium"],
            "open_low":         m1["low"],
            "open_total":       m1["total"],
            "coverage_pct":     m2.get("coverage_pct"),
            "scanned":          m2.get("scanned"),
            "total_licensed":   m2.get("total_licensed"),
            "sla_compliance":   m4.get("overall_rate"),
            "within_sla":       m4.get("within_sla"),
            "total_open":       m4.get("total_open"),
            "exception_rate":   m6["exception_rate"],
            "open_exceptions":  m6["open_exceptions"],
        },
    }

    logger.info("[%s] Complete | pdf=%s", REPORT_NAME, pdf_path.name)

    return {
        "pdf":     pdf_path,
        "excel":   None,   # management_summary is PDF + email only
        "charts":  [],
        "metrics": email_metrics,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{REPORT_NAME} — Step 1 + 2 test runner",
    )
    parser.add_argument("--tag-category", default=None,
                        help="Tenable tag category to filter by, e.g. 'Environment'")
    parser.add_argument("--tag-value", default=None,
                        help="Tenable tag value to filter by, e.g. 'Production'")
    parser.add_argument("--cache-dir", default=None,
                        help="Path to an existing parquet cache directory")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (also used as gauge test root)")
    parser.add_argument("--no-email", action="store_true",
                        help="Generate reports but skip email delivery")
    parser.add_argument("--test-gauge", action="store_true",
                        help="Render test gauge PNGs to output/gauge_test/ and exit "
                             "(no Tenable connection required)")
    parser.add_argument("--test-pdf", action="store_true",
                        help="Render a test PDF using synthetic data and exit "
                             "(no Tenable connection required)")
    parser.add_argument("--test-email", action="store_true",
                        help="Render a test email HTML preview using synthetic data and exit "
                             "(no Tenable connection required)")
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Step 2 test: render gauges and exit — no Tenable connection needed
    # ------------------------------------------------------------------
    if args.test_gauge:
        gauge_out = Path(args.output_dir) / "gauge_test" if args.output_dir else None
        _run_gauge_test(gauge_out)
        sys.exit(0)

    # ------------------------------------------------------------------
    # Step 3 test: render PDF from synthetic data and exit
    # ------------------------------------------------------------------
    if args.test_pdf:
        pdf_out = Path(args.output_dir) if args.output_dir else None
        _run_pdf_test(pdf_out, args.tag_category, args.tag_value)
        sys.exit(0)

    # ------------------------------------------------------------------
    # Step 4 test: render email preview from synthetic data and exit
    # ------------------------------------------------------------------
    if args.test_email:
        _tag_label = (
            f"{args.tag_category}={args.tag_value}"
            if args.tag_category and args.tag_value
            else "all_assets"
        )
        _rd = datetime.now(tz=timezone.utc)
        # Reuse the same synthetic metrics as _run_pdf_test
        from io import StringIO as _SIO  # noqa: F401 — just for clarity
        _synthetic = {
            "metric_1": {"critical": 12, "high": 47, "medium": 183, "low": 64, "total": 306},
            "metric_2": {
                "coverage_pct": 87.3, "scanned": 218, "not_scanned": 32,
                "total_licensed": 250, "status": "Attention", "color": "#f57c00",
                "error": None,
            },
            "metric_3": {
                "mttr": {"critical": 11.2, "high": 22.4, "medium": 68.0, "low": None},
                "status": "Within SLA", "color": "#388e3c", "total_fixed": 94,
            },
            "metric_4": {
                "overall_rate": 81.7,
                "per_severity": {
                    "critical": {"rate": 75.0, "within_sla": 9,   "total": 12},
                    "high":     {"rate": 85.1, "within_sla": 40,  "total": 47},
                    "medium":   {"rate": 80.3, "within_sla": 147, "total": 183},
                    "low":      {"rate": 90.6, "within_sla": 58,  "total": 64},
                },
                "within_sla": 254, "total_open": 306,
                "status": "Below Target", "color": "#f57c00",
            },
            "metric_5": [
                {"label": "0–30 days",    "min_days": 0,   "max_days": 30,    "count": 78,  "pct": 25.5, "color": "#388e3c"},
                {"label": "31–60 days",   "min_days": 31,  "max_days": 60,    "count": 62,  "pct": 20.3, "color": "#7cb342"},
                {"label": "61–90 days",   "min_days": 61,  "max_days": 90,    "count": 55,  "pct": 18.0, "color": "#fbc02d"},
                {"label": "91–180 days",  "min_days": 91,  "max_days": 180,   "count": 73,  "pct": 23.9, "color": "#f57c00"},
                {"label": "181–365 days", "min_days": 181, "max_days": 365,   "count": 28,  "pct": 9.2,  "color": "#e64a19"},
                {"label": "365+ days",    "min_days": 366, "max_days": 99999, "count": 10,  "pct": 3.3,  "color": "#d32f2f"},
            ],
            "metric_6": {
                "open_exceptions": 7, "total_open": 306,
                "exception_rate": 2.3, "rate_color": "#388e3c", "rate_label": "Low",
            },
            "metric_7": {
                "snapshots": [
                    {"month": "2025-09", "critical": 18, "high": 52, "medium": 201, "low": 70},
                    {"month": "2026-01", "critical": 12, "high": 47, "medium": 183, "low": 64},
                ],
                "delta_critical_high": -2, "delta_medium_low": -2,
                "has_trend": True, "first_run_notice": False,
            },
        }
        _html, _charts = build_email_body(_synthetic, _rd, _tag_label, "Test Group")
        _out = Path(args.output_dir) if args.output_dir else ROOT_DIR / "output" / "email_test"
        _out.mkdir(parents=True, exist_ok=True)
        _preview = _out / f"management_summary_email_preview_{_rd.strftime('%Y%m%d_%H%M')}.html"
        _preview.write_text(_email_preview_html(_html, _charts), encoding="utf-8")
        _console.print(f"[green]OK[/green] Email preview: {_preview}")
        _console.print(f"  Inline charts: {list(_charts.keys())}")
        sys.exit(0)

    # ------------------------------------------------------------------
    # Resolve cache directory (local date, matching run_all.py convention)
    # ------------------------------------------------------------------
    cache_dir = (
        Path(args.cache_dir)
        if args.cache_dir
        else CACHE_DIR / datetime.now().strftime("%Y-%m-%d")
    )
    cache_dir.mkdir(parents=True, exist_ok=True)

    report_date = datetime.now(tz=timezone.utc)
    month_str   = report_date.strftime("%Y-%m")

    tag_category: Optional[str] = args.tag_category
    tag_value:    Optional[str] = args.tag_value
    tag_filter_label = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all_assets"
    )

    # ------------------------------------------------------------------
    # Connect + fetch
    # ------------------------------------------------------------------
    from tenable_client import get_client
    tio = get_client()

    _console.print(f"\n[bold]Fetching vulnerability data...[/bold]  cache: {cache_dir}")
    vulns_raw  = fetch_all_vulnerabilities(tio, cache_dir)
    assets_raw = fetch_all_assets(tio, cache_dir)

    _console.print("[bold]Fetching fixed vulnerability data (for MTTR)...[/bold]")
    fixed_raw = fetch_fixed_vulnerabilities(tio, cache_dir)

    # ------------------------------------------------------------------
    # Enrich with tags + filter
    # ------------------------------------------------------------------
    _console.print("[bold]Enriching and filtering...[/bold]")
    vulns_enriched = enrich_vulns_with_assets(vulns_raw, assets_raw)
    vulns_df       = filter_by_tag(vulns_enriched, tag_category, tag_value)
    assets_df      = filter_by_tag(assets_raw, tag_category, tag_value)

    fixed_enriched = enrich_vulns_with_assets(fixed_raw, assets_raw)
    fixed_vulns_df = filter_by_tag(fixed_enriched, tag_category, tag_value)

    _console.print(
        f"  Open/reopened vulns in scope: [bold]{len(vulns_df):,}[/bold]\n"
        f"  Assets in scope:              [bold]{len(assets_df):,}[/bold]\n"
        f"  Fixed vulns in scope:         [bold]{len(fixed_vulns_df):,}[/bold]\n"
    )

    # ------------------------------------------------------------------
    # Trend file
    # ------------------------------------------------------------------
    trend_file = _trend_file_path(tag_category, tag_value)

    # ------------------------------------------------------------------
    # Compute all metrics
    # ------------------------------------------------------------------
    metrics = compute_all_metrics(
        vulns_df        = vulns_df,
        assets_df       = assets_df,
        fixed_vulns_df  = fixed_vulns_df,
        trend_file      = trend_file,
        tag_filter_label= tag_filter_label,
        report_date     = report_date,
    )

    # ------------------------------------------------------------------
    # Save trend snapshot (uses Metric 1 severity counts)
    # ------------------------------------------------------------------
    _save_trend_snapshot(
        trend_file       = trend_file,
        month_str        = month_str,
        tag_filter_label = tag_filter_label,
        sev_counts       = metrics["metric_1"],
        generated_at     = report_date,
    )

    # ------------------------------------------------------------------
    # Print results
    # ------------------------------------------------------------------
    _print_metrics(metrics, report_date, tag_filter_label)

    # ------------------------------------------------------------------
    # Generate PDF (Step 3)
    # ------------------------------------------------------------------
    output_dir = Path(args.output_dir) if args.output_dir else (
        ROOT_DIR / "output" / f"{datetime.now().strftime('%Y-%m-%d_%H-%M')}_{REPORT_SLUG}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    pdf_filename = (
        f"{REPORT_SLUG}_{tag_filter_label.replace('=','_').replace(' ','_')}"
        f"_{report_date.strftime('%Y%m%d_%H%M')}.pdf"
    )
    pdf_path = output_dir / pdf_filename

    _console.print(f"\n[bold]Building PDF...[/bold]  {pdf_path}")
    _build_pdf(metrics, report_date, tag_filter_label, pdf_path)
    _console.print(f"[green]OK[/green] PDF complete: {pdf_path}")

    # ------------------------------------------------------------------
    # Build email body (Step 4)
    # ------------------------------------------------------------------
    _console.print("\n[bold]Building email body...[/bold]")
    email_html, inline_charts = build_email_body(
        metrics          = metrics,
        report_date      = report_date,
        tag_filter_label = tag_filter_label,
    )
    email_preview_path = output_dir / f"{REPORT_SLUG}_email_preview.html"
    email_preview_path.write_text(_email_preview_html(email_html, inline_charts), encoding="utf-8")
    _console.print(f"[green]OK[/green] Email body preview: {email_preview_path}")
    _console.print(f"  Inline charts: {list(inline_charts.keys())}")

    if args.no_email:
        _console.print("\n[dim]--no-email set — skipping delivery.[/dim]")
    else:
        _console.print(
            "\n[dim]Email delivery will run via run_all.py (Step 5). "
            "Pass --no-email to suppress this message.[/dim]"
        )
