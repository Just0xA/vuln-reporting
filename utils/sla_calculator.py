"""
utils/sla_calculator.py — SLA status calculation for vulnerability findings.

All SLA logic lives here so every report uses the same definitions.
Import get_sla_status() for per-row calculations, or apply_sla_to_df()
to vectorize across a full vulnerability DataFrame.

SLA Definitions (from config.py):
    Critical : 15 days
    High     : 30 days
    Medium   : 90 days
    Low      : 180 days
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import pandas as pd

from config import SLA_DAYS, SEVERITY_ORDER

logger = logging.getLogger(__name__)


# ===========================================================================
# Core per-vulnerability function
# ===========================================================================

def get_sla_status(
    severity: str,
    first_found: datetime,
    remediated: bool,
    as_of: Optional[datetime] = None,
) -> dict:
    """
    Compute the SLA status for a single vulnerability finding.

    Parameters
    ----------
    severity : str
        One of "critical", "high", "medium", "low", "info".
        Case-insensitive.
    first_found : datetime
        When the vulnerability was first observed.  Must be timezone-aware
        (UTC strongly preferred).
    remediated : bool
        True if the vulnerability has been fixed (state == "fixed").
    as_of : datetime, optional
        Reference point for age calculation.  Defaults to now (UTC).

    Returns
    -------
    dict with keys:
        status          : "Within SLA" | "Overdue" | "Remediated" | "N/A"
        days_open       : int  — calendar days since first_found (or until fix)
        sla_days        : int  — allowed remediation window
        days_remaining  : int  — positive = days left, negative = days overdue
                                 None for info-severity or remediated vulns
        is_overdue      : bool
    """
    severity_key = severity.lower() if severity else "info"

    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    # Ensure first_found is timezone-aware
    if first_found is not None and hasattr(first_found, "tzinfo") and first_found.tzinfo is None:
        first_found = first_found.replace(tzinfo=timezone.utc)

    # Info severity — no SLA applies
    if severity_key not in SLA_DAYS:
        return {
            "status": "N/A",
            "days_open": _days_between(first_found, as_of),
            "sla_days": None,
            "days_remaining": None,
            "is_overdue": False,
        }

    sla_days = SLA_DAYS[severity_key]

    if first_found is None or pd.isnull(first_found):
        return {
            "status": "Unknown",
            "days_open": None,
            "sla_days": sla_days,
            "days_remaining": None,
            "is_overdue": False,
        }

    days_open = _days_between(first_found, as_of)
    days_remaining = sla_days - days_open

    if remediated:
        return {
            "status": "Remediated",
            "days_open": days_open,
            "sla_days": sla_days,
            "days_remaining": days_remaining,
            "is_overdue": False,
        }

    if days_open > sla_days:
        return {
            "status": "Overdue",
            "days_open": days_open,
            "sla_days": sla_days,
            "days_remaining": days_remaining,   # negative value
            "is_overdue": True,
        }

    return {
        "status": "Within SLA",
        "days_open": days_open,
        "sla_days": sla_days,
        "days_remaining": days_remaining,
        "is_overdue": False,
    }


# ===========================================================================
# Vectorized helper for full DataFrames
# ===========================================================================

def apply_sla_to_df(
    df: pd.DataFrame,
    as_of: Optional[datetime] = None,
) -> pd.DataFrame:
    """
    Add SLA-derived columns to a vulnerability DataFrame in-place.

    Expects the DataFrame to have at minimum:
        severity      : str column ("critical", "high", etc.)
        first_found   : datetime column (UTC-aware)
        state         : str column ("open" | "reopened" | "fixed")

    Adds columns:
        remediated      : bool
        days_open       : int
        sla_days        : int
        days_remaining  : int (negative = overdue)
        sla_status      : "Within SLA" | "Overdue" | "Remediated" | "N/A"
        is_overdue      : bool

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame (from data/fetchers.py).
    as_of : datetime, optional
        Reference timestamp.  Defaults to UTC now.

    Returns
    -------
    pd.DataFrame
        The same DataFrame with SLA columns appended.
    """
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    if df.empty:
        for col in ("remediated", "days_open", "sla_days", "days_remaining", "sla_status", "is_overdue"):
            df[col] = None
        return df

    # Coerce first_found to UTC-aware datetime if not already
    if not pd.api.types.is_datetime64_any_dtype(df["first_found"]):
        first_found = pd.to_datetime(df["first_found"], utc=True, errors="coerce")
    elif df["first_found"].dt.tz is None:
        first_found = df["first_found"].dt.tz_localize("UTC")
    else:
        first_found = df["first_found"]

    as_of_ts = pd.Timestamp(as_of)
    remediated = df["state"].str.lower().isin(["fixed", "remediated"])
    days_open = (as_of_ts - first_found).dt.days.fillna(-1).astype(int)
    sla_days = df["severity"].str.lower().map(SLA_DAYS)
    days_remaining = sla_days - days_open
    is_overdue = ~remediated & sla_days.notna() & (days_open > sla_days)

    df = df.assign(
        first_found=first_found,
        remediated=remediated,
        days_open=days_open,
        sla_days=sla_days,
        days_remaining=days_remaining,
        is_overdue=is_overdue,
    )

    # sla_status string label
    import numpy as np
    conditions = [
        df["remediated"],
        df["severity"].str.lower() == "info",
        df["is_overdue"],
    ]
    choices = ["Remediated", "N/A", "Overdue"]
    sla_status = pd.Categorical(
        np.select(conditions, choices, default="Within SLA"),
        categories=["Within SLA", "Overdue", "Remediated", "N/A"],
    )
    df = df.assign(sla_status=pd.Series(sla_status, index=df.index))

    return df


# ===========================================================================
# Aggregate helpers
# ===========================================================================

def sla_compliance_rate(df: pd.DataFrame, severity: Optional[str] = None) -> float:
    """
    Return the fraction of open vulnerabilities that are within SLA.

    Parameters
    ----------
    df : pd.DataFrame
        Must have sla_status column (apply apply_sla_to_df first).
    severity : str, optional
        If provided, filter to this severity tier only.

    Returns
    -------
    float
        Value between 0.0 and 1.0.  Returns 1.0 if no open vulns exist.
    """
    if df.empty:
        return 1.0

    subset = df[~df["remediated"]]
    if severity:
        subset = subset[subset["severity"].str.lower() == severity.lower()]

    if subset.empty:
        return 1.0

    within = (subset["sla_status"] == "Within SLA").sum()
    return round(within / len(subset), 4)


def compute_mttr(df: pd.DataFrame, severity: Optional[str] = None) -> Optional[float]:
    """
    Compute Mean Time To Remediate (MTTR) in days for resolved vulns.

    Parameters
    ----------
    df : pd.DataFrame
        Must have days_open and remediated columns.
    severity : str, optional
        Filter to a specific severity tier.

    Returns
    -------
    float or None
        Average days to remediate, or None if no remediated vulns.
    """
    subset = df[df["remediated"]]
    if severity:
        subset = subset[subset["severity"].str.lower() == severity.lower()]
    if subset.empty or "days_open" not in subset.columns:
        return None
    return round(float(subset["days_open"].mean()), 1)


def overdue_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return a summary DataFrame of overdue counts grouped by severity.

    Parameters
    ----------
    df : pd.DataFrame
        Must have is_overdue and severity columns.

    Returns
    -------
    pd.DataFrame
        Columns: severity, overdue_count, ordered Critical → Low.
    """
    if df.empty or "is_overdue" not in df.columns:
        return pd.DataFrame(columns=["severity", "overdue_count"])

    overdue = df[df["is_overdue"]].groupby("severity").size().reset_index(name="overdue_count")

    # Enforce severity order
    overdue["_order"] = overdue["severity"].str.lower().map(
        {s: i for i, s in enumerate(SEVERITY_ORDER)}
    )
    return overdue.sort_values("_order").drop(columns="_order").reset_index(drop=True)


# ===========================================================================
# Utility
# ===========================================================================

def _days_between(start: Optional[datetime], end: datetime) -> Optional[int]:
    """Return calendar days between two datetimes, or None if start is None."""
    if start is None:
        return None
    delta = end - start
    return max(0, delta.days)


if __name__ == "__main__":
    # Quick smoke test
    from datetime import timedelta

    now = datetime.now(tz=timezone.utc)

    test_cases = [
        ("critical", now - timedelta(days=20), False),   # Overdue (20 > 15)
        ("critical", now - timedelta(days=10), False),   # Within SLA
        ("high",     now - timedelta(days=25), True),    # Remediated
        ("medium",   now - timedelta(days=100), False),  # Overdue (100 > 90)
        ("low",      now - timedelta(days=90), False),   # Within SLA (90 <= 180)
        ("info",     now - timedelta(days=500), False),  # N/A
    ]

    print(f"{'Severity':<12} {'Days':>6} {'Remediated':>12} {'Status':<14} {'Days Remaining':>15}")
    print("-" * 65)
    for sev, ff, rem in test_cases:
        result = get_sla_status(sev, ff, rem)
        days = (now - ff).days
        print(
            f"{sev:<12} {days:>6} {str(rem):>12} "
            f"{result['status']:<14} {str(result['days_remaining']):>15}"
        )
