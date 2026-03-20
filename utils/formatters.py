"""
utils/formatters.py — Severity label helpers, color map utilities, and
general display formatting used across all report scripts and exporters.

All functions are pure (no I/O, no API calls) and safe to import anywhere.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from config import (
    SEVERITY_COLORS,
    SEVERITY_FILL_COLORS,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    RISK_TIER_THRESHOLDS,
    RISK_TIER_COLORS,
    AGE_BUCKETS,
    SLA_DAYS,
)


# ===========================================================================
# Severity label helpers
# ===========================================================================

def severity_label(severity: str) -> str:
    """
    Return the display-formatted severity label for a severity key.

    Parameters
    ----------
    severity : str
        Raw severity string (case-insensitive), e.g. "critical", "HIGH".

    Returns
    -------
    str
        Title-cased label, e.g. "Critical".  Returns "Unknown" if not found.

    Examples
    --------
    >>> severity_label("critical")
    'Critical'
    >>> severity_label("HIGH")
    'High'
    """
    return SEVERITY_LABELS.get(severity.lower(), "Unknown")


def ordered_severities(include_info: bool = False) -> list[str]:
    """
    Return the canonical severity list in descending order.

    Parameters
    ----------
    include_info : bool
        Whether to include "info" in the returned list (default False).

    Returns
    -------
    list[str]
        e.g. ["critical", "high", "medium", "low"] or with "info".
    """
    if include_info:
        return list(SEVERITY_ORDER)
    return [s for s in SEVERITY_ORDER if s != "info"]


def sort_by_severity(df, severity_col: str = "severity"):
    """
    Return a DataFrame sorted by severity in Critical → Low order.

    Parameters
    ----------
    df : pd.DataFrame
    severity_col : str
        Column name containing severity strings.

    Returns
    -------
    pd.DataFrame
        Sorted copy of the input DataFrame.
    """
    order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    df = df.copy()
    df["_sev_order"] = df[severity_col].str.lower().map(order_map).fillna(99)
    return df.sort_values("_sev_order").drop(columns="_sev_order").reset_index(drop=True)


# ===========================================================================
# Color map utilities
# ===========================================================================

def severity_hex_color(severity: str) -> str:
    """
    Return the hex chart color for a severity tier.

    Parameters
    ----------
    severity : str
        e.g. "critical", "high", "medium", "low", "info"

    Returns
    -------
    str
        Hex color string with leading #, e.g. "#d32f2f".
        Falls back to "#9e9e9e" (grey) for unknown severities.
    """
    return SEVERITY_COLORS.get(severity.lower(), "#9e9e9e")


def severity_fill_color(severity: str) -> str:
    """
    Return the Excel cell fill hex color (no leading #) for a severity tier.

    Used with openpyxl PatternFill.

    Parameters
    ----------
    severity : str

    Returns
    -------
    str
        6-char hex string without #, e.g. "FFCDD2".
    """
    return SEVERITY_FILL_COLORS.get(severity.lower(), "F5F5F5")


def chart_color_sequence(severities: list[str]) -> list[str]:
    """
    Return a list of hex colors corresponding to a list of severity names.

    Useful for building Plotly color_discrete_sequence or Matplotlib color lists.

    Parameters
    ----------
    severities : list[str]
        e.g. ["critical", "high", "medium"]

    Returns
    -------
    list[str]
        Matching hex color strings.
    """
    return [severity_hex_color(s) for s in severities]


def risk_tier(score: int) -> str:
    """
    Map a numeric risk score to a tier label.

    Parameters
    ----------
    score : int
        Risk score (Critical×10 + High×5 + Medium×2 + Low×1).

    Returns
    -------
    str
        One of "critical", "high", "medium", "low", "none".
    """
    for threshold, tier in RISK_TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "none"


def risk_tier_fill_color(score: int) -> str:
    """Return the Excel fill color for a given risk score."""
    tier = risk_tier(score)
    return RISK_TIER_COLORS.get(tier, "F5F5F5")


# ===========================================================================
# SLA display helpers
# ===========================================================================

def sla_days_label(severity: str) -> str:
    """
    Return a human-readable SLA window label.

    Examples
    --------
    >>> sla_days_label("critical")
    '15 days'
    >>> sla_days_label("high")
    '30 days'
    """
    days = SLA_DAYS.get(severity.lower())
    if days is None:
        return "N/A"
    return f"{days} days"


def format_days_remaining(days_remaining: Optional[int]) -> str:
    """
    Format days_remaining as a human-readable string.

    Positive → "X days left", negative → "X days overdue", None → "N/A".

    Examples
    --------
    >>> format_days_remaining(5)
    '5 days left'
    >>> format_days_remaining(-3)
    '3 days overdue'
    >>> format_days_remaining(None)
    'N/A'
    """
    if days_remaining is None:
        return "N/A"
    if days_remaining >= 0:
        return f"{days_remaining} days left"
    return f"{abs(days_remaining)} days overdue"


# ===========================================================================
# Age bucket helpers
# ===========================================================================

def age_bucket(days_open: Optional[int]) -> str:
    """
    Return the age bucket label for a given number of days open.

    Parameters
    ----------
    days_open : int or None

    Returns
    -------
    str
        One of the AGE_BUCKETS labels, e.g. "0–15d", "180d+", or "Unknown".
    """
    if days_open is None or days_open < 0:
        return "Unknown"
    for label, lo, hi in AGE_BUCKETS:
        if lo <= days_open <= hi:
            return label
    return "180d+"


def age_bucket_order() -> list[str]:
    """Return age bucket labels in ascending age order."""
    return [label for label, _, _ in AGE_BUCKETS]


# ===========================================================================
# General number / date formatters
# ===========================================================================

def fmt_int(value) -> str:
    """Format an integer with thousands separator, or '—' for None/NaN."""
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "—"


def fmt_pct(value: Optional[float], decimals: int = 1) -> str:
    """
    Format a float fraction (0.0–1.0) as a percentage string.

    Examples
    --------
    >>> fmt_pct(0.857)
    '85.7%'
    >>> fmt_pct(None)
    'N/A'
    """
    if value is None:
        return "N/A"
    try:
        return f"{value * 100:.{decimals}f}%"
    except (TypeError, ValueError):
        return "N/A"


def fmt_days(value: Optional[float]) -> str:
    """Format a day count as an integer with 'd' suffix, or '—' for None."""
    if value is None:
        return "—"
    try:
        return f"{int(round(value))}d"
    except (TypeError, ValueError):
        return "—"


def fmt_date_utc(dt: Optional[datetime], fmt: str = "%Y-%m-%d") -> str:
    """
    Format a datetime as a UTC date string.

    Parameters
    ----------
    dt : datetime or None
    fmt : str
        strftime format string (default: ISO date).

    Returns
    -------
    str
        Formatted date string, or "N/A" if dt is None or not parseable.
    """
    if dt is None:
        return "N/A"
    try:
        if hasattr(dt, "tzinfo") and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime(fmt)
    except (AttributeError, ValueError):
        return "N/A"


def report_timestamp() -> str:
    """Return a current UTC timestamp string suitable for filenames and headers."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def safe_filename(name: str) -> str:
    """
    Convert a group name or report title to a filesystem-safe string.

    Strips characters that are illegal on Windows/macOS/Linux, replaces
    spaces with underscores, and lowercases the result.

    Examples
    --------
    >>> safe_filename("Finance Remediation Team")
    'finance_remediation_team'
    >>> safe_filename("Exec / KPI Report (2025)")
    'exec_kpi_report_2025'
    """
    import re
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"[\s]+", "_", name.strip())
    return name.lower()


# ===========================================================================
# Plotly / Matplotlib layout helpers
# ===========================================================================

def standard_chart_layout() -> dict:
    """
    Return a base Plotly layout dict with font, background, and margin settings
    consistent across all reports.
    """
    return {
        "font": {"family": "Arial, sans-serif", "size": 13, "color": "#212121"},
        "paper_bgcolor": "#ffffff",
        "plot_bgcolor": "#ffffff",
        "margin": {"l": 60, "r": 40, "t": 60, "b": 60},
        "legend": {"orientation": "h", "yanchor": "bottom", "y": -0.25},
    }


def severity_bar_colors(severities: list[str]) -> list[str]:
    """
    Convenience alias for chart_color_sequence, for use in bar chart builders.

    Parameters
    ----------
    severities : list[str]

    Returns
    -------
    list[str]
    """
    return chart_color_sequence(severities)
