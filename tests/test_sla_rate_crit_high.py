"""
tests/test_sla_rate_crit_high.py — Unit tests for compute_sla_rate_crit_high().

Covers D-05 / 17-REVIEW WR-01 (NaT-denominator bias fix) and WR-02
(unmapped severity exclusion).

All fixtures use synthetic aggregate-safe data only (QUAL-05 / D-04-08):
  - No real hostnames, IPs, asset UUIDs, or plugin names.
  - asset_uuid values use RFC-compliant nil-UUID form.
"""

from __future__ import annotations

import datetime
from datetime import timezone

import pandas as pd
import pytest

from utils.sla_calculator import compute_sla_rate_crit_high

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

REF = datetime.datetime(2026, 6, 12, 0, 0, 0, tzinfo=timezone.utc)

# Minimal SLA_DAYS dict matching config.py (callers always pass this explicitly)
SLA = {"critical": 15, "high": 30, "medium": 60, "low": 120}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_open_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal open-findings frame with severity + first_found columns."""
    defaults: dict = {"severity": "high", "first_found": REF - datetime.timedelta(days=5)}
    records = [{**defaults, **r} for r in rows]
    df = pd.DataFrame(records, columns=["severity", "first_found"])
    df = df.assign(
        first_found=pd.to_datetime(df["first_found"], utc=True, errors="coerce")
    )
    return df


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_nat_excluded_from_denominator():
    """
    WR-01: NaT rows must NOT count in the denominator.

    3 high findings within SLA + 2 NaT first_found → rate should be 100.0%
    (3 in-SLA / 3 valid), not 60.0% (3/5 if NaT were counted).
    """
    in_sla_days = 5  # within high SLA of 30 days
    rows = [
        {"severity": "high", "first_found": REF - datetime.timedelta(days=in_sla_days)},
        {"severity": "high", "first_found": REF - datetime.timedelta(days=in_sla_days)},
        {"severity": "high", "first_found": REF - datetime.timedelta(days=in_sla_days)},
        {"severity": "high", "first_found": None},   # NaT
        {"severity": "critical", "first_found": None},  # NaT
    ]
    df = _make_open_df(rows)
    result = compute_sla_rate_crit_high(df, REF, SLA)
    assert result == 100.0, f"Expected 100.0, got {result}"


def test_all_nat_returns_none():
    """
    WR-01 cold-start: when every Crit+High row has first_found=NaT, return None
    (not 0.0 — there are no SLA-classifiable rows to divide over).
    """
    rows = [
        {"severity": "critical", "first_found": None},
        {"severity": "high",     "first_found": None},
    ]
    df = _make_open_df(rows)
    result = compute_sla_rate_crit_high(df, REF, SLA)
    assert result is None, f"Expected None for all-NaT frame, got {result}"


def test_empty_crit_high_returns_none():
    """
    When the open frame contains no Critical or High rows, return None.
    """
    rows = [
        {"severity": "medium", "first_found": REF - datetime.timedelta(days=10)},
        {"severity": "low",    "first_found": REF - datetime.timedelta(days=50)},
    ]
    df = _make_open_df(rows)
    result = compute_sla_rate_crit_high(df, REF, SLA)
    assert result is None, f"Expected None for no-crit/high frame, got {result}"


def test_unmapped_severity_excluded():
    """
    WR-02: A row whose severity maps to NaN in sla_days does not count toward
    the numerator (within-SLA count), guarded by sla_days_col.notna() in the
    within mask.

    Use a partial SLA dict that maps only "critical" (not "high") to test the
    guard. With 1 critical (in SLA, 5 days < 15) and 1 high (unmapped → NaN
    sla_days → excluded from within count but stays in denominator):
      - within.sum() = 1  (only critical qualifies)
      - len(ch_valid) = 2 (both rows have valid first_found)
      - result = 50.0%, NOT 100.0%

    This confirms unmapped rows cannot be silently counted as "within SLA"
    (they do not inflate the within.sum() numerator).
    """
    partial_sla = {"critical": 15}  # "high" unmapped → sla_days_col NaN for high rows
    rows = [
        {"severity": "critical", "first_found": REF - datetime.timedelta(days=5)},  # in SLA
        {"severity": "high",     "first_found": REF - datetime.timedelta(days=5)},  # unmapped → not in within
    ]
    df = _make_open_df(rows)
    result = compute_sla_rate_crit_high(df, REF, partial_sla)
    # 1 within / 2 valid = 50.0% — unmapped high is NOT silently counted as within-SLA
    assert result == 50.0, f"Expected 50.0, got {result}"


def test_in_sla_vs_overdue_split():
    """
    Mixed within-SLA and overdue Crit+High (all valid first_found) yields
    the correct percentage.

    2 critical within SLA (5 days < 15) + 2 high overdue (35 days > 30) = 50.0%.
    """
    rows = [
        {"severity": "critical", "first_found": REF - datetime.timedelta(days=5)},   # in SLA
        {"severity": "critical", "first_found": REF - datetime.timedelta(days=5)},   # in SLA
        {"severity": "high",     "first_found": REF - datetime.timedelta(days=35)},  # overdue
        {"severity": "high",     "first_found": REF - datetime.timedelta(days=35)},  # overdue
    ]
    df = _make_open_df(rows)
    result = compute_sla_rate_crit_high(df, REF, SLA)
    assert result == 50.0, f"Expected 50.0, got {result}"
