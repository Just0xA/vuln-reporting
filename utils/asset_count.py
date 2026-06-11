"""
utils/asset_count.py — On-time-scanned licensed asset count substrate.

Pure compute: no file I/O, no network I/O.  Import count_on_time_assets()
to get the current-run on-time-scanned licensed asset count — the
Vulnerability Density denominator (D-01, OD-2).

Caller contract
---------------
- Pass ``assets_df`` from the pre-fetched / cached asset export.
- Pass ``report_date`` as the run's ``generated_at`` (UTC datetime).
  Do NOT call datetime.now() inside this function (D-12).
- Call None-check the return value before dividing:
    count = count_on_time_assets(assets_df, report_date)
    if count is None:
        # no on-time licensed assets in scope — render cold-start / no-data
        ...
    density = open_count / count

Forward dependency
------------------
Phase 15 (OD-3) must extend ``capture_snapshot()`` to record the
on-time-scanned count per snapshot so MoM density trend can cold-start.
This function provides the current-run denominator; it does NOT read
or reuse the S1 snapshot ``asset_count`` field (which is the all-asset
count — the wrong basis per D-02).
"""

from __future__ import annotations

import argparse
import logging
from datetime import datetime

import pandas as pd

from config import ON_TIME_SCAN_WINDOW_DAYS

logger = logging.getLogger(__name__)

# Column name for licensed scan date in the assets export.
_LSD = "last_licensed_scan_date"


def count_on_time_assets(
    assets_df: pd.DataFrame,
    report_date: datetime,
    window_days: int = ON_TIME_SCAN_WINDOW_DAYS,
) -> int | None:
    """
    Return the count of licensed assets scanned on time as of ``report_date``.

    "On time" means the asset's ``last_licensed_scan_date`` is within
    ``window_days`` days of ``report_date`` (i.e. >= cutoff, inclusive).

    This is the Vulnerability Density denominator: on-time-scanned licensed
    assets (D-01 / OD-2) — consistent with the board_summary managed-asset
    baseline.  It is NOT the all-licensed count.

    Parameters
    ----------
    assets_df : pd.DataFrame
        Asset DataFrame from the Tenable asset export (or the run-scoped
        parquet cache).  Must contain a ``last_licensed_scan_date`` column
        of UTC datetime64 values; NaT = unlicensed or never-scanned.
    report_date : datetime
        The run's reference date (the ``generated_at`` UTC timestamp).
        The cutoff is derived entirely from this parameter:
            cutoff = report_date - window_days
        No ``datetime.now()`` call is made inside this function (D-12).
    window_days : int, optional
        Number of days defining "on time".  Defaults to
        ``config.ON_TIME_SCAN_WINDOW_DAYS`` (D-13 single canonical source).

    Returns
    -------
    int or None
        Count of on-time-scanned licensed assets, or ``None`` when:
        - ``assets_df`` is empty,
        - ``last_licensed_scan_date`` column is absent (fail-soft),
        - no licensed assets exist (all NaT),
        - no licensed assets fall within the on-time window.

        ``None`` (not ``0``) is the sentinel so callers can distinguish
        "no assets in scope" from "no open vulnerabilities" (D-14).
        Callers MUST None-check before dividing.

    Notes
    -----
    - CoW: no ``df["col"] = val`` after a filter.  Intermediate columns
      are added via ``.assign()`` to avoid pandas 3.0 ChainedAssignmentError.
    - The tz-normalization mirrors ``scan_coverage_sla_module.py`` lines
      262-265: tz-aware dates are tz_convert("UTC"); tz-naive dates are
      assigned UTC directly.
    """
    # ---- Guard: empty input ----
    if assets_df.empty:
        logger.debug("count_on_time_assets: empty assets_df — returning None.")
        return None

    # ---- Guard: missing column ----
    if _LSD not in assets_df.columns:
        logger.warning(
            "count_on_time_assets: column %r not present in assets_df — "
            "cannot compute on-time count; returning None.",
            _LSD,
        )
        return None

    # ---- Filter to licensed assets (last_licensed_scan_date not NaT) ----
    licensed_mask = assets_df[_LSD].notna()
    licensed = assets_df[licensed_mask]

    if licensed.empty:
        logger.debug(
            "count_on_time_assets: no licensed assets (all NaT %r) — returning None.",
            _LSD,
        )
        return None

    # ---- Normalise report_date to a UTC pd.Timestamp (mirrors scan_coverage_sla_module) ----
    if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
        rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
    else:
        rd_ts = pd.Timestamp(report_date, tz="UTC")

    cutoff = rd_ts - pd.Timedelta(days=window_days)

    # ---- Count on-time rows (last_licensed_scan_date >= cutoff, inclusive) ----
    on_time_count = int((licensed[_LSD] >= cutoff).sum())

    if on_time_count == 0:
        logger.debug(
            "count_on_time_assets: %d licensed assets found but none scanned "
            "within %d-day window (cutoff=%s) — returning None sentinel (D-14).",
            len(licensed),
            window_days,
            cutoff,
        )
        return None

    logger.debug(
        "count_on_time_assets: %d / %d licensed assets on-time (window=%dd, cutoff=%s).",
        on_time_count,
        len(licensed),
        window_days,
        cutoff,
    )
    return on_time_count


if __name__ == "__main__":
    # Library-only utility — no standalone operation.  Provides a --help stub
    # consistent with Code Quality requirements (if __name__ == "__main__").
    parser = argparse.ArgumentParser(
        description=(
            "utils/asset_count — pure-compute on-time licensed asset count substrate.\n"
            "This is a library module; import count_on_time_assets() in your code.\n"
            "Run via: python -c \"from utils.asset_count import count_on_time_assets\""
        )
    )
    parser.parse_args()
    print(
        "utils/asset_count is a library module.\n"
        f"Default window: ON_TIME_SCAN_WINDOW_DAYS = {ON_TIME_SCAN_WINDOW_DAYS} days\n"
        "Import count_on_time_assets() to use."
    )
