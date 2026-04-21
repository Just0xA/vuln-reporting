"""
reports/modules/board_report_utils.py — Shared utilities for board-level metric modules.

The board report defines an "on-time scanned" asset set that is used as the
baseline for three of four board metrics.  This module implements that filter
once and exposes it for reuse — it is intentionally NOT registered as a module
itself; these are pure calculation helpers imported directly by the four board
metric modules.

Asset tag format
----------------
``assets_df`` from ``fetch_all_assets()`` stores tags in the ``tags`` column as
a semicolon-delimited ``"Category=Value"`` string::

    "Application=Finance;Environment=Production;Owner=Network Defense"

``extract_business_unit()`` parses this format to derive the business-unit label.
This is an important distinction from the spec's ``tags_raw`` design — there is
no list-of-dicts column in the normalised asset DataFrame; only the string form
is stored in parquet.

Shared utilities
----------------
- ``deduplicate_assets_by_name``  — remove duplicate hostnames, keep most-recent
- ``identify_on_time_assets``     — split into on-time / not-on-time subsets
- ``extract_business_unit``       — add ``business_unit`` column from Application tag
- ``compute_per_bu_breakdown``    — per-BU numerator/denominator/percentage table
- ``sla_status_from_thresholds``  — classify a value as green/yellow/red/no_data
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

#: Tenable tag category that identifies the business unit.
BU_TAG_CATEGORY: str = "Application"

#: Default scan-recency window in days for the on-time filter.
ON_TIME_WINDOW_DAYS: int = 30


# ===========================================================================
# Asset deduplication
# ===========================================================================

def deduplicate_assets_by_name(assets_df: pd.DataFrame) -> pd.DataFrame:
    """
    Deduplicate assets by hostname, keeping the most recent entry by last_seen.

    Assets with an empty or whitespace-only ``hostname`` value cannot be
    grouped reliably, so they are kept as-is (all rows retained).

    Parameters
    ----------
    assets_df : pd.DataFrame
        Asset DataFrame from ``fetch_all_assets()``.  Expected columns:
        ``hostname`` (str) and ``last_seen`` (datetime-like or str).

    Returns
    -------
    pd.DataFrame
        New DataFrame with the same columns.  For assets that share a non-empty
        hostname, only the row with the most recent ``last_seen`` is retained.
        Rows with empty/blank hostnames are all retained.
        Result is reset-indexed (0, 1, 2, …) — original index is not preserved.

    Notes
    -----
    ``last_seen`` is coerced to UTC-aware ``pd.Timestamp`` before sorting so
    mixed tz-aware / tz-naive or string dates are handled consistently.  Rows
    where ``last_seen`` cannot be parsed (coercion → NaT) sort last and are
    effectively treated as "oldest".
    """
    if assets_df.empty:
        return assets_df.copy()

    df = assets_df.copy()

    # Coerce last_seen to UTC-aware datetime for reliable sorting.
    # pd.to_datetime(..., utc=True) both localises tz-naive values and
    # converts tz-aware values to UTC, so it is safe to call even when the
    # column is already in UTC (e.g. loaded from parquet).
    df.loc[:, "last_seen"] = pd.to_datetime(df["last_seen"], utc=True, errors="coerce")

    # Partition into "has a hostname" vs "no hostname"
    hostname_series = df["hostname"].fillna("").str.strip()
    with_hostname    = df[hostname_series != ""].copy()
    without_hostname = df[hostname_series == ""].copy()

    if not with_hostname.empty:
        # Sort descending by last_seen so keep="first" retains the most recent
        with_hostname = (
            with_hostname
            .sort_values("last_seen", ascending=False, na_position="last")
            .drop_duplicates(subset=["hostname"], keep="first")
        )

    result = pd.concat([with_hostname, without_hostname], ignore_index=True)

    removed = len(df) - len(result)
    if removed:
        logger.debug(
            "deduplicate_assets_by_name: %d → %d rows (%d duplicate hostname "
            "entries removed).",
            len(df), len(result), removed,
        )

    return result


# ===========================================================================
# On-time scan filter
# ===========================================================================

def identify_on_time_assets(
    assets_df:   pd.DataFrame,
    report_date: datetime,
    window_days: int = ON_TIME_WINDOW_DAYS,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split assets into on-time-scanned and not-on-time-scanned subsets.

    An asset is classified as **on-time** when:

    1. ``last_licensed_scan_date`` is not null / NaT, **and**
    2. ``last_licensed_scan_date >= report_date − window_days``

    Deduplication (by hostname, keeping the most-recent ``last_seen``) is
    applied before the split so no hostname appears in both sets.

    Parameters
    ----------
    assets_df : pd.DataFrame
        Asset DataFrame from ``fetch_all_assets()``.
    report_date : datetime
        Reference point for the recency window.  UTC-aware datetimes are
        handled correctly; naive datetimes are treated as UTC.
    window_days : int
        Number of days in the recency window.  Default: 30.

    Returns
    -------
    tuple[pd.DataFrame, pd.DataFrame]
        ``(on_time_df, not_on_time_df)`` — mutually exclusive subsets of
        the deduplicated asset DataFrame.  Both share the same columns.
        Both are reset-indexed.

    Notes
    -----
    Assets where ``last_licensed_scan_date`` is null are placed in
    ``not_on_time_df`` (they have never been licensed-scanned, or the date
    is unknown — both cases are operationally "not on time").
    """
    if assets_df.empty:
        empty = assets_df.copy()
        return empty, empty

    df = deduplicate_assets_by_name(assets_df)

    # Coerce scan date column to UTC-aware datetime
    df.loc[:, "last_licensed_scan_date"] = pd.to_datetime(
        df["last_licensed_scan_date"], utc=True, errors="coerce"
    )

    # Build UTC-aware cutoff timestamp
    if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
        rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
    else:
        rd_ts = pd.Timestamp(report_date, tz="UTC")

    cutoff = rd_ts - pd.Timedelta(days=window_days)

    on_time_mask = (
        df["last_licensed_scan_date"].notna()
        & (df["last_licensed_scan_date"] >= cutoff)
    )

    on_time     = df[on_time_mask].copy().reset_index(drop=True)
    not_on_time = df[~on_time_mask].copy().reset_index(drop=True)

    logger.debug(
        "identify_on_time_assets: total_dedup=%d, on_time=%d, not_on_time=%d "
        "(window=%dd, cutoff=%s).",
        len(df), len(on_time), len(not_on_time), window_days, cutoff.date(),
    )

    return on_time, not_on_time


# ===========================================================================
# Business-unit extraction
# ===========================================================================

def extract_business_unit(
    assets_df:       pd.DataFrame,
    tag_column_name: str = "tags",
) -> pd.DataFrame:
    """
    Add a ``business_unit`` column derived from the ``Application`` tag category.

    The ``tags`` column in ``assets_df`` (as produced by ``fetch_all_assets()``)
    stores tags as a semicolon-delimited ``"Category=Value"`` string, for example::

        "Application=Finance;Environment=Production;Owner=Network Defense"

    This function scans each ``"Category=Value"`` token, identifies any where the
    category (case-insensitively) matches ``BU_TAG_CATEGORY`` (``"Application"``),
    and extracts the value as the business-unit label.

    Assignment rules:

    - No ``Application`` tag → ``"Untagged"``
    - Exactly one ``Application`` tag value → that value (e.g. ``"Finance"``)
    - Multiple distinct ``Application`` tag values (unusual but possible) →
      values joined with ``"; "`` in alphabetical order

    Parameters
    ----------
    assets_df : pd.DataFrame
        Asset DataFrame.  The column named ``tag_column_name`` must hold the
        semicolon-delimited tag string.
    tag_column_name : str
        Name of the tags column.  Default ``"tags"`` matches ``fetch_all_assets()``
        output.  The design spec refers to this as ``tags_raw``, but the
        normalised DataFrame stores it as a string under ``"tags"``.

    Returns
    -------
    pd.DataFrame
        Copy of ``assets_df`` with a ``business_unit`` column appended.
        The original DataFrame is not modified.
    """
    df = assets_df.copy()

    def _bu_from_tags(tags_val) -> str:
        """Extract Application tag value(s) from a semicolon-delimited tag string."""
        if not isinstance(tags_val, str) or not tags_val.strip():
            return "Untagged"

        tokens = [t.strip() for t in tags_val.split(";") if t.strip()]
        app_values: list[str] = []

        for token in tokens:
            if "=" not in token:
                continue
            cat, _, val = token.partition("=")
            if cat.strip().casefold() == BU_TAG_CATEGORY.casefold() and val.strip():
                app_values.append(val.strip())

        if not app_values:
            return "Untagged"
        if len(app_values) == 1:
            return app_values[0]
        # Multiple values — sort and join (rare; flagged via "; " separator so
        # downstream callers can detect and handle if needed)
        return "; ".join(sorted(set(app_values)))

    if tag_column_name in df.columns:
        df.loc[:, "business_unit"] = df[tag_column_name].apply(_bu_from_tags)
    else:
        logger.warning(
            "extract_business_unit: column %r not present in DataFrame — "
            "all assets will be labelled 'Untagged'.",
            tag_column_name,
        )
        df.loc[:, "business_unit"] = "Untagged"

    return df


# ===========================================================================
# Per-BU percentage breakdown
# ===========================================================================

def compute_per_bu_breakdown(
    df:               pd.DataFrame,
    numerator_mask:   "pd.Series[bool]",
    denominator_mask: "pd.Series[bool]",
    bu_column:        str = "business_unit",
) -> pd.DataFrame:
    """
    Compute per-business-unit numerator/denominator/percentage for a metric.

    Both masks must be boolean ``pd.Series`` aligned with ``df`` by index.
    The easiest way to guarantee alignment is to derive them from ``df``
    directly (e.g. ``df["asset_uuid"].isin(on_time_set)``).

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame containing the ``bu_column`` column.  Each row represents
        one asset (or finding, depending on the metric).
    numerator_mask : pd.Series[bool]
        ``True`` for rows that contribute to the numerator
        (e.g. "scanned on time", "fixed within SLA").
    denominator_mask : pd.Series[bool]
        ``True`` for rows that contribute to the denominator total.
    bu_column : str
        Column name holding the business-unit label.  Default: ``"business_unit"``.

    Returns
    -------
    pd.DataFrame
        Columns: ``business_unit``, ``numerator`` (int), ``denominator`` (int),
        ``percentage`` (float, 1 decimal place).

        Sorted by ``percentage`` **ascending** (worst performers first) so the
        PDF top-5 table surfaces the BUs most in need of attention.

        BUs with ``denominator == 0`` are excluded (prevents divide-by-zero and
        avoids misleading 0% rows where the BU has no applicable assets).

    Notes
    -----
    Masks are re-indexed to ``df.index`` before grouping so any accidental
    index misalignment is handled gracefully (fills with ``False``).
    """
    df_local = df.copy()

    # Re-index masks defensively to df_local's index
    df_local["_num"] = (
        numerator_mask
        .reindex(df_local.index, fill_value=False)
        .astype(int)
    )
    df_local["_den"] = (
        denominator_mask
        .reindex(df_local.index, fill_value=False)
        .astype(int)
    )

    grouped = (
        df_local
        .groupby(bu_column, dropna=False)
        .agg(
            numerator  =("_num", "sum"),
            denominator=("_den", "sum"),
        )
        .reset_index()
        .rename(columns={bu_column: "business_unit"})
    )

    # Exclude BUs with zero denominator
    grouped = grouped[grouped["denominator"] > 0].copy()

    grouped.loc[:, "percentage"] = (
        (grouped["numerator"] / grouped["denominator"] * 100)
        .round(1)
    )

    # Worst performers first so PDF top-5 highlights the most critical BUs
    return grouped.sort_values("percentage", ascending=True).reset_index(drop=True)


# ===========================================================================
# SLA status classifier
# ===========================================================================

def sla_status_from_thresholds(
    value:            Optional[float],
    green_threshold:  float,
    yellow_threshold: float,
    direction:        str = "higher_is_better",
) -> str:
    """
    Classify a metric value as green / yellow / red / no_data.

    Parameters
    ----------
    value : float or None
        The metric value to classify.  ``None`` → ``"no_data"``.
    green_threshold : float
        Boundary between green and yellow.
    yellow_threshold : float
        Boundary between yellow and red.
    direction : str
        ``"higher_is_better"`` (default) — green when ``value >= green_threshold``.
        ``"lower_is_better"``            — green when ``value <= green_threshold``.

    Returns
    -------
    str
        One of ``"green"``, ``"yellow"``, ``"red"``, ``"no_data"``.

    Examples
    --------
    Scan Coverage SLA (higher is better, green ≥ 95 %, yellow ≥ 90 %)::

        sla_status_from_thresholds(97.2, 95.0, 90.0)           → "green"
        sla_status_from_thresholds(92.1, 95.0, 90.0)           → "yellow"
        sla_status_from_thresholds(88.0, 95.0, 90.0)           → "red"

    High-Risk Assets (lower is better, green ≤ 0.5 %, yellow ≤ 1.0 %)::

        sla_status_from_thresholds(0.3, 0.5, 1.0, "lower_is_better")  → "green"
        sla_status_from_thresholds(0.7, 0.5, 1.0, "lower_is_better")  → "yellow"
        sla_status_from_thresholds(1.5, 0.5, 1.0, "lower_is_better")  → "red"
    """
    if value is None:
        return "no_data"

    if direction == "higher_is_better":
        if value >= green_threshold:
            return "green"
        if value >= yellow_threshold:
            return "yellow"
        return "red"
    else:  # lower_is_better
        if value <= green_threshold:
            return "green"
        if value <= yellow_threshold:
            return "yellow"
        return "red"
