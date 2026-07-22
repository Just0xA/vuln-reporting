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

``extract_owner()`` parses this format to derive the primary grouping label from
the ``Owner`` tag category (the Application Support team / patching-responsible
party, per D-01) and the nested ``Application`` value for analyst drill-down
(D-05).  This is an important distinction from the spec's ``tags_raw`` design —
there is no list-of-dicts column in the normalised asset DataFrame; only the
string form is stored in parquet.

Shared utilities
----------------
- ``deduplicate_assets_by_name``  — remove duplicate hostnames, keep most-recent
- ``identify_on_time_assets``     — split into on-time / not-on-time subsets
- ``extract_owner``               — add ``owner`` + ``application`` columns from Owner/Application tags
- ``exclude_risk_managed``        — drop ACCEPTED/RECASTED rows from a findings DataFrame
- ``compute_per_bu_breakdown``    — per-owner numerator/denominator/percentage table
- ``compute_bu_risk_scores``      — weighted Risk Score per owner for qualifying assets
- ``sla_status_from_thresholds``  — classify a value as green/yellow/red/no_data
- ``populate_rag_strip``           — populate ModuleData.rag_strip via shared classifier
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

#: Tenable tag category for the primary Owner grouping dimension (D-01).
OWNER_TAG_CATEGORY: str = "Owner"

#: Tenable tag category for the nested Application drill-down column (D-05).
APPLICATION_TAG_CATEGORY: str = "Application"

#: Default label for assets that carry no Owner tag (D-06).
_DEFAULT_UNASSIGNED_LABEL: str = "Unassigned"

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
# Owner extraction
# ===========================================================================

def extract_owner(
    assets_df:        pd.DataFrame,
    tag_column_name:  str = "tags",
    unassigned_label: str = _DEFAULT_UNASSIGNED_LABEL,
) -> pd.DataFrame:
    """
    Add an ``owner`` column (primary) and an ``application`` column (nested) from
    the ``Owner`` and ``Application`` tag categories respectively.

    The ``tags`` column in ``assets_df`` (as produced by ``fetch_all_assets()``)
    stores tags as a semicolon-delimited ``"Category=Value"`` string, for example::

        "Application=Finance;Environment=Production;Owner=Network Defense"

    This function makes a single pass over each tag string, extracting:

    - **owner** — value(s) of any ``Owner=…`` tokens (case-insensitive category
      match).  No match → ``unassigned_label`` (default ``"Unassigned"``).
    - **application** — value(s) of any ``Application=…`` tokens.  No match →
      ``""`` (empty string; callers may use this for nested drill-down).

    When multiple distinct values exist for the same category (unusual but
    possible), they are joined with ``"; "`` in alphabetical order.

    Fail-soft behaviour (SEG-04 / D-07): if the column named ``tag_column_name``
    is absent from ``assets_df``, a warning is logged, ``owner`` is set to
    ``unassigned_label`` for all rows, and ``application`` to ``""``.  No
    exception is raised.

    Parameters
    ----------
    assets_df : pd.DataFrame
        Asset DataFrame.  The column named ``tag_column_name`` should hold the
        semicolon-delimited tag string.
    tag_column_name : str
        Name of the tags column.  Default ``"tags"`` matches ``fetch_all_assets()``
        output.
    unassigned_label : str
        Label for assets that carry no ``Owner`` tag.  Default ``"Unassigned"``
        (D-06).  Pass a custom string to override (e.g. ``"No Owner"``).

    Returns
    -------
    pd.DataFrame
        Copy of ``assets_df`` with ``owner`` and ``application`` columns appended.
        The original DataFrame is not modified.
    """
    df = assets_df.copy()

    def _parse_tags(tags_val) -> tuple[str, str]:
        """Return (owner_label, application_label) from a semicolon-delimited tag string."""
        if not isinstance(tags_val, str) or not tags_val.strip():
            return unassigned_label, ""

        owner_values: list[str] = []
        app_values:   list[str] = []

        for token in tags_val.split(";"):
            token = token.strip()
            if not token or "=" not in token:
                continue
            cat, _, val = token.partition("=")
            cat_cf = cat.strip().casefold()
            val_s  = val.strip()
            if not val_s:
                continue
            if cat_cf == OWNER_TAG_CATEGORY.casefold():
                owner_values.append(val_s)
            elif cat_cf == APPLICATION_TAG_CATEGORY.casefold():
                app_values.append(val_s)

        owner_label = (
            "; ".join(sorted(set(owner_values)))
            if owner_values
            else unassigned_label
        )
        app_label = "; ".join(sorted(set(app_values))) if app_values else ""
        return owner_label, app_label

    if tag_column_name in df.columns:
        parsed = df[tag_column_name].apply(_parse_tags)
        df.loc[:, "owner"]       = [p[0] for p in parsed]
        df.loc[:, "application"] = [p[1] for p in parsed]
    else:
        logger.warning(
            "extract_owner: column %r not present in DataFrame — "
            "all assets will be labelled %r.",
            tag_column_name,
            unassigned_label,
        )
        df.loc[:, "owner"]       = unassigned_label
        df.loc[:, "application"] = ""

    return df


# ===========================================================================
# Risk-managed finding exclusion
# ===========================================================================

def exclude_risk_managed(df: pd.DataFrame) -> pd.DataFrame:
    """
    Drop rows whose ``severity_modification_type`` is ACCEPTED or RECASTED.

    Risk-accepted and recast findings remain ``state=open`` in Tenable, so
    KPI modules that count "open" findings would otherwise be inflated by a
    population the operator has already dispositioned. This helper is the
    single point of exclusion applied at the top of a module's ``compute()``.

    Parameters
    ----------
    df : pd.DataFrame
        Findings DataFrame. May or may not contain a
        ``severity_modification_type`` column.

    Returns
    -------
    pd.DataFrame
        A fresh ``.copy()`` of ``df`` with ACCEPTED/RECASTED rows removed.
        Empty input or a missing ``severity_modification_type`` column is
        returned unchanged (still a ``.copy()`` where empty; original frame
        when the column is absent — no error is raised in either case).

    Notes
    -----
    Matching is case-insensitive (``"accepted"``, ``"Recasted"``, ``"ACCEPTED"``
    all match). Values other than ACCEPTED/RECASTED (``"NONE"``, ``""``,
    ``None``, or anything else) are kept. Returns a ``.copy()`` so callers can
    safely ``.assign()`` onto the result without chaining through the caller's
    frame (Hard Rule 5).
    """
    if df.empty or "severity_modification_type" not in df.columns:
        return df

    mod = df["severity_modification_type"].astype(str).str.upper()
    return df[~mod.isin(["ACCEPTED", "RECASTED"])].copy()


# ===========================================================================
# Per-BU percentage breakdown
# ===========================================================================

def compute_per_bu_breakdown(
    df:               pd.DataFrame,
    numerator_mask:   "pd.Series[bool]",
    denominator_mask: "pd.Series[bool]",
    bu_column:        str  = "owner",
    higher_is_better: bool = True,
) -> pd.DataFrame:
    """
    Compute per-owner numerator/denominator/percentage for a metric.

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
        Column name holding the owner label.  Default: ``"owner"``.
    higher_is_better : bool
        Ranking direction for the metric.

        * ``True``  (default) — a higher percentage is the goal (e.g. Scan
          Coverage, Critical Remediation SLA).  The "affected" count that drives
          sort order is ``denominator − numerator`` (assets *not* meeting the
          goal).
        * ``False`` — a lower percentage is the goal (e.g. High-Risk Assets,
          Aged Vulnerability Assets).  The "affected" count is ``numerator``
          (assets *with* the problem).

        In both cases BUs are ranked by **absolute affected count descending**
        so that a large environment with many real problems ranks above a small
        environment that is 100 % non-compliant.  Percentage is used as the
        tiebreaker (worst percentage first within the same affected count).

    Returns
    -------
    pd.DataFrame
        Columns: ``owner``, ``numerator`` (int), ``denominator`` (int),
        ``percentage`` (float, 1 decimal place), ``affected`` (int — sort key,
        see *higher_is_better* above).

        Primary sort: ``affected`` descending.
        Secondary sort: ``percentage`` worst-first (ascending for
        higher-is-better, descending for lower-is-better).

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
        .rename(columns={bu_column: "owner"})
    )

    # Exclude BUs with zero denominator
    grouped = grouped[grouped["denominator"] > 0].copy()

    grouped.loc[:, "percentage"] = (
        (grouped["numerator"] / grouped["denominator"] * 100)
        .round(1)
    )

    # affected = raw count of assets that represent the problem for this metric.
    # For higher-is-better: assets NOT meeting the goal (denominator - numerator).
    # For lower-is-better: assets WITH the problem (numerator).
    if higher_is_better:
        grouped.loc[:, "affected"] = grouped["denominator"] - grouped["numerator"]
        pct_ascending = True   # lower % = worse for higher-is-better
    else:
        grouped.loc[:, "affected"] = grouped["numerator"]
        pct_ascending = False  # higher % = worse for lower-is-better

    # Primary: most affected assets first (absolute impact).
    # Secondary: worst percentage first within the same affected count.
    return (
        grouped
        .sort_values(
            ["affected", "percentage"],
            ascending=[False, pct_ascending],
        )
        .reset_index(drop=True)
    )


# ===========================================================================
# BU risk score computation
# ===========================================================================

def compute_bu_risk_scores(
    vulns_df:         pd.DataFrame,
    qualifying_uuids: set,
    enriched:         pd.DataFrame,
    severities:       "frozenset[str]",
    weights:          "dict[str, int]",
) -> pd.Series:
    """
    Compute a weighted Risk Score per business unit for the qualifying asset set.

    For each qualifying asset, sums (weight × open finding count) across the
    specified severity tiers using all open findings on that asset (not only the
    aged/filtered findings that caused the asset to qualify).  Returns the per-BU
    total of those per-asset scores.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Open / reopened findings from fetch_all_vulnerabilities().
    qualifying_uuids : set
        UUIDs of assets that met the module threshold (high-risk or aged).
    enriched : pd.DataFrame
        On-time assets with an ``owner`` column (from extract_owner).
    severities : frozenset[str]
        Lower-cased severity labels to include (e.g. frozenset({"critical", "high"})).
    weights : dict[str, int]
        Severity → point value mapping (RISK_WEIGHTS from config).

    Returns
    -------
    pd.Series
        Indexed by ``owner``, values are integer Risk Scores.
        BUs with no qualifying assets are absent from the result.
    """
    if not qualifying_uuids or vulns_df.empty:
        return pd.Series(dtype=int, index=pd.Index([], name="owner"))

    mask = (
        vulns_df["asset_uuid"].isin(qualifying_uuids)
        & vulns_df["severity"].str.lower().isin(severities)
    )
    risk_vulns = vulns_df.loc[mask, ["asset_uuid", "severity"]].copy()
    risk_vulns.loc[:, "severity"] = risk_vulns["severity"].str.lower()

    if risk_vulns.empty:
        return pd.Series(dtype=int, index=pd.Index([], name="owner"))

    risk_vulns.loc[:, "weighted"] = risk_vulns["severity"].map(weights).fillna(0)
    asset_scores = risk_vulns.groupby("asset_uuid")["weighted"].sum().astype(int)

    bu_map = (
        enriched.loc[
            enriched["asset_uuid"].isin(qualifying_uuids),
            ["asset_uuid", "owner"],
        ]
        .drop_duplicates("asset_uuid")
    )
    bu_asset = bu_map.merge(
        asset_scores.rename("risk_score").reset_index(),
        on="asset_uuid",
        how="left",
    )
    # F-DTYPE (Plan 03-07 Task 3): use .assign() rather than chained
    # df[col]= or .loc[:, col]= setters — both alternatives either drop
    # int dtype (.loc[:, col]= preserves the merge's float64) or fire
    # ChainedAssignmentError FutureWarning under pandas 3.0 CoW
    # (df[col]= chains through the merge's tracked parent frame).
    # .assign() replaces the column on a fresh frame and bypasses both.
    bu_asset = bu_asset.assign(
        risk_score=bu_asset["risk_score"].fillna(0).astype(int),
    )

    return bu_asset.groupby("owner")["risk_score"].sum()


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


# ===========================================================================
# RAG strip population
# ===========================================================================

def populate_rag_strip(
    data:             "ModuleData",  # forward-ref string — avoid circular import
    *,
    display_name:     str,
    metric_value:     Optional[float],
    threshold_green:  float,
    threshold_yellow: float,
    direction:        str = "higher_is_better",
) -> None:
    """
    Populate ``data.rag_strip`` in place with a pre-built RAG cell dict.

    Headline value is rendered via :func:`safe_pct` (so ``None`` / ``NaN``
    becomes the ``NO_DATA_HEADLINE`` em-dash). Status is computed via
    :func:`rag_status_from_value` honoring the supplied direction. The
    resulting cell dict is built by :func:`build_rag_strip_entry`.

    Parameters
    ----------
    data : ModuleData
        The module's ModuleData — the helper mutates ``data.rag_strip`` in place.
    display_name : str
        Cell label (typically ``self.DISPLAY_NAME``).
    metric_value : float or None
        The metric's headline percentage. ``None`` / ``NaN`` -> no_data gray cell.
    threshold_green, threshold_yellow : float
        Classification thresholds matching the module's existing constants.
    direction : str
        ``"higher_is_better"`` (default) or ``"lower_is_better"``.

    Returns
    -------
    None
        Mutates ``data.rag_strip`` in place.
    """
    # Deferred imports — these modules import each other transitively, so
    # we resolve the symbols at call time rather than at module-load time.
    from reports.modules.rag_utils import (    # noqa: PLC0415
        build_rag_strip_entry,
        rag_status_from_value,
    )
    from reports.modules.format_utils import safe_pct   # noqa: PLC0415

    status = rag_status_from_value(
        metric_value,
        green_threshold  = threshold_green,
        yellow_threshold = threshold_yellow,
        direction        = direction,
    )
    data.rag_strip = build_rag_strip_entry(
        display_name       = display_name,
        headline_value_str = safe_pct(metric_value),
        status             = status,
    )
