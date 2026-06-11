"""
tests/test_asset_count.py — Unit tests for utils/asset_count.count_on_time_assets.

All fixtures are SYNTHETIC-ONLY (QUAL-05): no real hostnames, IPs, or asset fields.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import pytest

import config
from utils.asset_count import count_on_time_assets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Fixed injected report_date for all tests unless overridden.
_REPORT_DATE = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(days_ago: int) -> pd.Timestamp:
    """Return a UTC Timestamp *days_ago* days before _REPORT_DATE."""
    return pd.Timestamp(_REPORT_DATE) - pd.Timedelta(days=days_ago)


def _make_assets(scan_days_ago: list[int | None]) -> pd.DataFrame:
    """
    Build a minimal assets_df with a last_licensed_scan_date column.

    Parameters
    ----------
    scan_days_ago : list of int or None
        Each entry becomes one row. int = days before _REPORT_DATE when
        last licensed scan occurred; None = NaT (unlicensed / no scan date).
    """
    dates = [_ts(d) if d is not None else pd.NaT for d in scan_days_ago]
    return pd.DataFrame({"last_licensed_scan_date": pd.to_datetime(dates, utc=True)})


# ---------------------------------------------------------------------------
# Basic on-time counting
# ---------------------------------------------------------------------------


def test_all_assets_within_window() -> None:
    """Assets scanned within the window should all be counted."""
    df = _make_assets([5, 10, 29])
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result == 3


def test_some_assets_stale() -> None:
    """Only assets within the window (< window_days ago) are counted."""
    # 10d ago = on time, 40d ago = stale (> 30d window)
    df = _make_assets([10, 40])
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result == 1


def test_unlicensed_assets_excluded() -> None:
    """Assets with NaT last_licensed_scan_date are not licensed and excluded."""
    df = _make_assets([5, None, None])
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result == 1


# ---------------------------------------------------------------------------
# Window boundary — inclusive cutoff
# ---------------------------------------------------------------------------


def test_boundary_exactly_at_cutoff_is_counted() -> None:
    """An asset scanned exactly window_days days ago is on-time (>= cutoff)."""
    window = 30
    df = _make_assets([window])  # scanned exactly 30 days ago
    result = count_on_time_assets(df, _REPORT_DATE, window_days=window)
    assert result == 1


def test_boundary_one_day_past_cutoff_is_excluded() -> None:
    """An asset scanned window_days+1 days ago is NOT on-time (< cutoff)."""
    window = 30
    df = _make_assets([window + 1])  # scanned 31 days ago
    result = count_on_time_assets(df, _REPORT_DATE, window_days=window)
    assert result is None


# ---------------------------------------------------------------------------
# None sentinel — D-14
# ---------------------------------------------------------------------------


def test_all_stale_returns_none() -> None:
    """All licensed assets outside the window → None sentinel (not 0)."""
    df = _make_assets([40, 60, 90])  # all stale
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result is None


def test_empty_dataframe_returns_none() -> None:
    """Empty assets_df → None sentinel."""
    df = pd.DataFrame({"last_licensed_scan_date": pd.Series([], dtype="datetime64[ns, UTC]")})
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result is None


def test_all_unlicensed_returns_none() -> None:
    """Assets with all-NaT last_licensed_scan_date → None sentinel."""
    df = _make_assets([None, None, None])
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result is None


def test_missing_column_returns_none(caplog: pytest.LogCaptureFixture) -> None:
    """Missing last_licensed_scan_date column → None sentinel + warning logged."""
    df = pd.DataFrame({"asset_id": [1, 2, 3]})
    result = count_on_time_assets(df, _REPORT_DATE)
    assert result is None
    # A warning should have been logged about the missing column.
    assert any("last_licensed_scan_date" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Injected-date purity — D-12
# ---------------------------------------------------------------------------


def test_different_report_dates_yield_different_counts() -> None:
    """
    Same assets_df, two different injected report_dates → different counts.
    Proves no datetime.now() inside — the cutoff is purely report_date-driven.

    The asset is scanned at a fixed absolute date (2026-05-20).
    - date1 = 2026-06-01: cutoff = 2026-05-02; asset (2026-05-20) >= cutoff → on-time
    - date2 = 2026-05-25: cutoff = 2026-04-25; asset (2026-05-20) >= cutoff → on-time
    - date3 = 2026-06-25: cutoff = 2026-05-26; asset (2026-05-20) < cutoff → stale → None
    """
    # Build asset with an absolute scan date of 2026-05-20 UTC.
    # _REPORT_DATE is 2026-06-01, so "20 days ago" = 2026-05-12 — use 12 days instead.
    # Actually build a fixed-date asset directly.
    fixed_scan = pd.Timestamp("2026-05-20", tz="UTC")
    df = pd.DataFrame({"last_licensed_scan_date": [fixed_scan]})

    date1 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)   # cutoff = 2026-05-02 → on-time
    date3 = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)  # cutoff = 2026-05-26 → stale

    count1 = count_on_time_assets(df, date1)
    count3 = count_on_time_assets(df, date3)

    # For date1 (recent): asset scanned 2026-05-20 is within 30d of 2026-06-01 → count = 1
    assert count1 == 1
    # For date3 (later): cutoff = 2026-05-26 > 2026-05-20 → stale → None
    assert count3 is None


def test_tz_naive_report_date_accepted() -> None:
    """A tz-naive report_date should be coerced to UTC without raising."""
    df = _make_assets([5])
    naive_date = datetime(2026, 6, 1, 12, 0, 0)  # no tzinfo
    result = count_on_time_assets(df, naive_date)
    assert result == 1


def test_tz_aware_non_utc_report_date_accepted() -> None:
    """A tz-aware non-UTC report_date should be converted to UTC correctly."""
    from datetime import timezone as tz
    import datetime as dt
    eastern = tz(dt.timedelta(hours=-4))  # EDT = UTC-4
    # 2026-06-01 12:00 EDT = 2026-06-01 16:00 UTC
    eastern_date = datetime(2026, 6, 1, 12, 0, 0, tzinfo=eastern)
    df = _make_assets([5])  # asset scanned 5 days before _REPORT_DATE (which is 16:00 UTC)
    result = count_on_time_assets(df, eastern_date)
    assert result == 1


# ---------------------------------------------------------------------------
# Default window comes from config — D-13
# ---------------------------------------------------------------------------


def test_default_window_matches_config() -> None:
    """
    When window_days is not passed, the function uses config.ON_TIME_SCAN_WINDOW_DAYS.
    Verified by placing one asset exactly at config.ON_TIME_SCAN_WINDOW_DAYS days ago —
    it must be counted (boundary inclusive) under the default window.
    """
    window = config.ON_TIME_SCAN_WINDOW_DAYS
    df = _make_assets([window])  # scanned exactly at the boundary
    result = count_on_time_assets(df, _REPORT_DATE)  # no window_days arg
    assert result == 1


def test_default_window_constant_value() -> None:
    """config.ON_TIME_SCAN_WINDOW_DAYS must be 30 (D-13 single-source)."""
    assert config.ON_TIME_SCAN_WINDOW_DAYS == 30


# ---------------------------------------------------------------------------
# No datetime.now() + no reports.modules import (verified by acceptance criteria)
# These are tested via grep in the CI acceptance gate; here we verify the
# function accepts a caller-supplied date for cutoff purity.
# ---------------------------------------------------------------------------


def test_custom_window_days_respected() -> None:
    """Passing a custom window_days overrides the default without changing config."""
    # Asset scanned 10 days ago — on-time for window=15, stale for window=5
    df = _make_assets([10])
    assert count_on_time_assets(df, _REPORT_DATE, window_days=15) == 1
    assert count_on_time_assets(df, _REPORT_DATE, window_days=5) is None


if __name__ == "__main__":
    import sys
    import subprocess
    sys.exit(subprocess.call(["pytest", __file__, "-v"]))
