"""
config.py — Shared constants and configuration for the vulnerability reporting suite.

All report scripts, utilities, and exporters import from here so that SLA
definitions, severity ordering, and color palettes remain consistent across
the entire suite.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# Repository root — absolute path regardless of working directory
# =============================================================================
ROOT_DIR: Path = Path(__file__).resolve().parent

# =============================================================================
# SLA Definitions (days to remediate per severity)
# A vulnerability is OVERDUE when:
#   today - first_found_date > SLA_DAYS[severity]  AND  not yet remediated
# =============================================================================
SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 60,
    "low": 120,
}

# =============================================================================
# Severity ordering — used for consistent sorting and display
# =============================================================================
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

SEVERITY_LABELS: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# Numeric severity levels as returned by Tenable API
# 4 = Critical, 3 = High, 2 = Medium, 1 = Low, 0 = Info
# Used ONLY as a fallback when vpr_score is absent.
SEVERITY_LEVEL_MAP: dict[int, str] = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
}

SEVERITY_NAME_TO_LEVEL: dict[str, int] = {v: k for k, v in SEVERITY_LEVEL_MAP.items()}

# =============================================================================
# VPR (Vulnerability Priority Rating) — primary severity source
#
# Tenable exposes vpr_score on each vulnerability finding (plugin.vpr.score).
# We use this score to derive the severity tier that all downstream code
# consumes.  When vpr_score is None or missing the native Tenable severity
# field (SEVERITY_LEVEL_MAP above) is used as a fallback.
#
# Ranges are inclusive on both ends; evaluated top-down (highest first).
# =============================================================================
VPR_SEVERITY_MAP: list[tuple[float, float, str]] = [
    (9.0, 10.0, "critical"),
    (7.0, 8.9, "high"),
    (4.0, 6.9, "medium"),
    (0.1, 3.9, "low"),
]


def vpr_to_severity(score: float | None, fallback: str = "info") -> str:
    """
    Map a VPR score to a severity tier label.

    Evaluates ``VPR_SEVERITY_MAP`` top-down (critical first) and returns the
    label whose range contains *score*.  When *score* is ``None``, ``NaN``,
    or outside all defined ranges (i.e. exactly 0.0), *fallback* is returned
    so the caller can supply the native Tenable severity string instead of
    silently dropping to "info".

    Parameters
    ----------
    score : float or None
        The ``vpr_score`` value from the Tenable vulnerability export.
    fallback : str
        Severity label to return when *score* is absent or unclassifiable.
        Defaults to ``"info"``; callers should pass the native Tenable
        severity string (e.g. ``SEVERITY_LEVEL_MAP[severity_id]``) so that
        unscored findings are still classified correctly.

    Returns
    -------
    str
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
        ``"info"``, or whatever *fallback* resolves to.

    Examples
    --------
    >>> vpr_to_severity(9.5)
    'critical'
    >>> vpr_to_severity(7.0)
    'high'
    >>> vpr_to_severity(0.0, fallback="low")
    'low'
    >>> vpr_to_severity(None, fallback="medium")
    'medium'
    """
    try:
        if score is None:
            return fallback
        score = float(score)
    except (TypeError, ValueError):
        return fallback

    import math

    if math.isnan(score):
        return fallback

    for lo, hi, label in VPR_SEVERITY_MAP:
        if lo <= score <= hi:
            return label

    # score == 0.0 or any value outside all ranges
    return fallback


# =============================================================================
# Risk scoring weights (used in asset risk and executive KPI reports)
# Score = (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1)
# =============================================================================
RISK_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# =============================================================================
# Color palette — consistent across all matplotlib and plotly charts
# Also used for Excel conditional formatting
# =============================================================================
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#fbc02d",
    "low": "#388e3c",
    "info": "#1976d2",
}

# Excel fill colors (openpyxl PatternFill hex, no leading #)
SEVERITY_FILL_COLORS: dict[str, str] = {
    "critical": "FFCDD2",  # light red
    "high": "FFE0B2",  # light orange
    "medium": "FFF9C4",  # light yellow
    "low": "C8E6C9",  # light green
    "info": "BBDEFB",  # light blue
}

# Risk tier thresholds for asset risk report color coding
RISK_TIER_COLORS: dict[str, str] = {
    "critical": "FFCDD2",  # score >= 50
    "high": "FFE0B2",  # score 20-49
    "medium": "FFF9C4",  # score 5-19
    "low": "C8E6C9",  # score 1-4
    "none": "F5F5F5",  # score 0
}

RISK_TIER_THRESHOLDS: list[tuple[int, str]] = [
    (50, "critical"),
    (20, "high"),
    (5, "medium"),
    (1, "low"),
    (0, "none"),
]

# =============================================================================
# Patch age buckets (used in patch_compliance report)
# =============================================================================
AGE_BUCKETS: list[tuple[str, int, int]] = [
    ("0–15d", 0, 15),
    ("16–30d", 16, 30),
    ("31–60d", 31, 60),
    ("61–90d", 61, 90),
    ("91–180d", 91, 180),
    ("180d+", 181, 99999),
]

# =============================================================================
# Delivery / attachment limits
# =============================================================================
MAX_ATTACHMENT_SIZE_MB: int = int(os.getenv("MAX_ATTACHMENT_SIZE_MB", "25"))

# =============================================================================
# Logging
# =============================================================================
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_DIR: Path = ROOT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)


# =============================================================================
# Output directory
# =============================================================================
OUTPUT_DIR: Path = ROOT_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# =============================================================================
# Data cache directory (parquet files per run)
# =============================================================================
CACHE_DIR: Path = ROOT_DIR / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
