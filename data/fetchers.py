"""
data/fetchers.py — All pyTenable API fetch functions.

Every public function in this module:
  - Accepts an authenticated TenableIO client as its first argument
  - Returns a normalized pandas DataFrame
  - Caches results to a run-scoped .parquet file in data/cache/ to avoid
    redundant API calls when multiple reports run in the same group execution
  - Uses tenacity for exponential backoff on rate-limit and transient errors
  - Shows a rich progress bar for long-running export jobs

Cache key convention:
    data/cache/<run_id>_<dataset>.parquet
    run_id is passed in by the caller (e.g. "2025-03-19T07-00_finance")
    or defaults to "latest" when called standalone.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from config import CACHE_DIR, SEVERITY_LEVEL_MAP, vpr_to_severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tenacity retry policy — applied to all API calls
# Retries on connection errors and Tenable 429 / 5xx responses
# ---------------------------------------------------------------------------
try:
    from tenable.errors import APIError
    _RETRY_EXCEPTIONS = (APIError, ConnectionError, TimeoutError)
except ImportError:
    _RETRY_EXCEPTIONS = (ConnectionError, TimeoutError)

_retry_policy = dict(
    retry=retry_if_exception_type(_RETRY_EXCEPTIONS),
    wait=wait_exponential(multiplier=2, min=4, max=60),
    stop=stop_after_attempt(5),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)


# ===========================================================================
# Internal helpers
# ===========================================================================

def _cache_path(run_id: str, dataset: str) -> Path:
    """Return the parquet cache path for a given run and dataset name."""
    return CACHE_DIR / f"{run_id}_{dataset}.parquet"


def _load_cache(path: Path) -> Optional[pd.DataFrame]:
    """Return cached DataFrame if the file exists, else None."""
    if path.exists():
        logger.info("Loading cached data from %s", path)
        return pd.read_parquet(path)
    return None


def _save_cache(df: pd.DataFrame, path: Path) -> None:
    """Persist DataFrame to parquet, logging any write errors non-fatally."""
    try:
        df.to_parquet(path, index=False)
        logger.debug("Cached %d rows to %s", len(df), path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not write cache file %s: %s", path, exc)


# ===========================================================================
# Public fetch functions
# ===========================================================================

@retry(**_retry_policy)
def fetch_vulnerabilities(
    tio,
    run_id: str = "latest",
    *,
    tag_category: Optional[str] = None,
    tag_value: Optional[str] = None,
) -> pd.DataFrame:
    """
    Export all vulnerability findings via tio.exports.vulns().

    Optionally scoped to assets matching a specific tag category/value pair.
    Results are cached per run_id so subsequent calls within the same run
    return the cached DataFrame instantly.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Unique identifier for this run (used as the cache key prefix).
    tag_category : str, optional
        Tenable tag category to filter by (e.g. "Business Unit").
    tag_value : str, optional
        Tenable tag value to filter by (e.g. "Finance").

    Returns
    -------
    pd.DataFrame
        Normalized vulnerability DataFrame. Key columns:
        asset_id, asset_hostname, asset_ipv4, asset_fqdn,
        plugin_id, plugin_name, plugin_family,
        vpr_score        — raw VPR score from Tenable (float, may be NaN),
        severity         — VPR-derived tier ("critical"/"high"/"medium"/"low"/"info");
                           falls back to severity_native when vpr_score is absent,
        severity_native  — original Tenable integer-mapped severity (preserved for
                           reference and fallback only; do not use as primary source),
        severity_level   — raw Tenable integer severity_id (0–4),
        cve_list, cvss_base_score, cvss_v3_base_score,
        first_found, last_found, last_fixed,
        state, exploit_available,
        tag_category, tag_value
    """
    dataset = f"vulns_{tag_category or 'all'}_{tag_value or 'all'}"
    cache = _cache_path(run_id, dataset)
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info(
        "Fetching vulnerabilities from Tenable (tag=%s:%s) …",
        tag_category,
        tag_value,
    )

    export_filters: dict = {"state": ["open", "reopened"]}

    # Build tag filter if both category and value are provided
    if tag_category and tag_value:
        asset_ids = fetch_assets_by_tag(tio, run_id, tag_category=tag_category, tag_value=tag_value)
        if asset_ids.empty:
            logger.warning("No assets found for tag %s=%s; returning empty DataFrame.", tag_category, tag_value)
            return pd.DataFrame()
        export_filters["asset_id"] = asset_ids["asset_id"].tolist()

    rows: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Streaming vulnerability export…", total=None)

        for vuln in tio.exports.vulns(**export_filters):
            asset = vuln.get("asset", {})
            plugin = vuln.get("plugin", {})
            severity_id = vuln.get("severity_id", 0)

            # Native Tenable severity string — used ONLY as a fallback when
            # vpr_score is absent; not the primary severity source.
            severity_native = SEVERITY_LEVEL_MAP.get(severity_id, "info")

            # VPR score lives at plugin.vpr.score in the vuln export payload.
            vpr_score = (plugin.get("vpr") or {}).get("score")

            # Primary severity — VPR-derived; falls back to native if absent.
            severity = vpr_to_severity(vpr_score, fallback=severity_native)

            rows.append({
                # Asset identifiers
                "asset_id": asset.get("uuid", ""),
                "asset_hostname": asset.get("hostname", ""),
                "asset_ipv4": asset.get("ipv4", ""),
                "asset_fqdn": asset.get("fqdn", ""),
                "asset_netbios": asset.get("netbios", ""),
                "operating_system": asset.get("operating_system", ""),
                # Plugin / finding info
                "plugin_id": plugin.get("id", ""),
                "plugin_name": plugin.get("name", ""),
                "plugin_family": plugin.get("family", ""),
                "plugin_publication_date": plugin.get("publication_date", ""),
                "plugin_modification_date": plugin.get("modification_date", ""),
                # Severity — VPR-derived is the canonical field for all reports
                "vpr_score": vpr_score,          # raw float from API, may be None
                "severity": severity,            # primary: use this everywhere
                "severity_native": severity_native,  # fallback reference only
                "severity_level": severity_id,   # raw Tenable integer (0–4)
                # CVE / CVSS
                "cve_list": ",".join(plugin.get("cve", []) or []),
                "cvss_base_score": plugin.get("cvss_base_score"),
                "cvss_v3_base_score": plugin.get("cvss3_base_score"),
                "cvss_temporal_score": plugin.get("cvss_temporal_score"),
                # Exploit
                "exploit_available": plugin.get("exploit_available", False),
                "exploitability_ease": plugin.get("exploitability_ease", ""),
                # Dates
                "first_found": vuln.get("first_found", ""),
                "last_found": vuln.get("last_found", ""),
                "last_fixed": vuln.get("last_fixed", ""),
                # State
                "state": vuln.get("state", ""),
                # Tag context (populated post-filter)
                "tag_category": tag_category or "",
                "tag_value": tag_value or "",
            })
            progress.advance(task)

    df = pd.DataFrame(rows)
    df = _normalize_vuln_dates(df)
    logger.info("Fetched %d vulnerability records.", len(df))
    _save_cache(df, cache)
    return df


@retry(**_retry_policy)
def fetch_assets(
    tio,
    run_id: str = "latest",
) -> pd.DataFrame:
    """
    Export all asset records via tio.exports.assets().

    Results are cached per run_id.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Unique identifier for this run.

    Returns
    -------
    pd.DataFrame
        Normalized asset DataFrame. Key columns:
        asset_id, hostname, ipv4, fqdn, operating_system,
        first_seen, last_seen, last_scan_time,
        tags (list serialized as JSON string), network_name
    """
    cache = _cache_path(run_id, "assets")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("Fetching assets from Tenable …")
    rows: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Streaming asset export…", total=None)

        for asset in tio.exports.assets():
            ipv4_list = asset.get("ipv4s") or asset.get("ipv4", []) or []
            fqdn_list = asset.get("fqdns") or asset.get("fqdn", []) or []
            hostname_list = asset.get("hostnames") or asset.get("hostname", []) or []
            os_list = asset.get("operating_systems") or []

            # Serialize tags as a list of "category=value" strings
            raw_tags = asset.get("tags") or []
            tag_strings = [
                f"{t.get('category_name', '')}={t.get('value', '')}"
                for t in raw_tags
                if isinstance(t, dict)
            ]

            rows.append({
                "asset_id": asset.get("id", ""),
                "hostname": (hostname_list[0] if hostname_list else ""),
                "ipv4": (ipv4_list[0] if ipv4_list else ""),
                "fqdn": (fqdn_list[0] if fqdn_list else ""),
                "operating_system": (os_list[0] if os_list else ""),
                "network_name": asset.get("network_name", ""),
                "first_seen": asset.get("first_seen", ""),
                "last_seen": asset.get("last_seen", ""),
                "last_scan_time": asset.get("last_scan_time", ""),
                "tags": ";".join(tag_strings),   # semi-colon delimited for parquet compat
                "agent_uuid": asset.get("agent_uuid", ""),
            })
            progress.advance(task)

    df = pd.DataFrame(rows)
    df = _normalize_asset_dates(df)
    logger.info("Fetched %d asset records.", len(df))
    _save_cache(df, cache)
    return df


@retry(**_retry_policy)
def fetch_tags(tio, run_id: str = "latest") -> pd.DataFrame:
    """
    Retrieve all tag categories and values via tio.tags.list().

    Caches results per run_id.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Unique identifier for this run.

    Returns
    -------
    pd.DataFrame
        Columns: tag_uuid, category_name, value, description, asset_count
    """
    cache = _cache_path(run_id, "tags")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("Fetching tag definitions from Tenable …")
    rows: list[dict] = []

    for tag in tio.tags.list():
        rows.append({
            "tag_uuid": tag.get("uuid", ""),
            "category_name": tag.get("category_name", ""),
            "value": tag.get("value", ""),
            "description": tag.get("description", ""),
            "asset_count": tag.get("counts", {}).get("assigned_assets", 0),
        })

    df = pd.DataFrame(rows)
    logger.info("Fetched %d tag records.", len(df))
    _save_cache(df, cache)
    return df


@retry(**_retry_policy)
def fetch_assets_by_tag(
    tio,
    run_id: str = "latest",
    *,
    tag_category: str,
    tag_value: str,
) -> pd.DataFrame:
    """
    Return a DataFrame of asset IDs that carry a specific tag category/value.

    Used internally by fetch_vulnerabilities() to scope exports.

    Parameters
    ----------
    tio : TenableIO
    run_id : str
    tag_category : str
    tag_value : str

    Returns
    -------
    pd.DataFrame
        Columns: asset_id, hostname, ipv4
    """
    dataset = f"tagged_assets_{tag_category}_{tag_value}"
    cache = _cache_path(run_id, dataset)
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("Fetching assets tagged %s=%s …", tag_category, tag_value)

    # Find matching tag UUID
    tags_df = fetch_tags(tio, run_id)
    match = tags_df[
        (tags_df["category_name"].str.lower() == tag_category.lower())
        & (tags_df["value"].str.lower() == tag_value.lower())
    ]

    if match.empty:
        logger.warning("Tag '%s=%s' not found in Tenable.", tag_category, tag_value)
        return pd.DataFrame(columns=["asset_id", "hostname", "ipv4"])

    tag_uuid = match.iloc[0]["tag_uuid"]

    # Export assets filtered by this tag
    rows: list[dict] = []
    for asset in tio.exports.assets(tag_uuids=[tag_uuid]):
        ipv4_list = asset.get("ipv4s") or asset.get("ipv4", []) or []
        hostname_list = asset.get("hostnames") or asset.get("hostname", []) or []
        rows.append({
            "asset_id": asset.get("id", ""),
            "hostname": (hostname_list[0] if hostname_list else ""),
            "ipv4": (ipv4_list[0] if ipv4_list else ""),
        })

    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["asset_id", "hostname", "ipv4"])
    logger.info("Found %d assets for tag %s=%s.", len(df), tag_category, tag_value)
    _save_cache(df, cache)
    return df


# ===========================================================================
# Date normalization helpers
# ===========================================================================

def _parse_iso_utc(series: pd.Series) -> pd.Series:
    """
    Parse an ISO-8601 string column into timezone-aware UTC datetimes.
    Invalid or empty values become NaT.
    """
    return pd.to_datetime(series, utc=True, errors="coerce")


def _normalize_vuln_dates(df: pd.DataFrame) -> pd.DataFrame:
    """Cast date columns in the vulnerability DataFrame to UTC datetimes."""
    for col in ("first_found", "last_found", "last_fixed"):
        if col in df.columns:
            df[col] = _parse_iso_utc(df[col])
    return df


def _normalize_asset_dates(df: pd.DataFrame) -> pd.DataFrame:
    """Cast date columns in the asset DataFrame to UTC datetimes."""
    for col in ("first_seen", "last_seen", "last_scan_time"):
        if col in df.columns:
            df[col] = _parse_iso_utc(df[col])
    return df


# ===========================================================================
# Convenience — enrich vulnerabilities with full asset detail
# ===========================================================================

def enrich_vulns_with_assets(
    vulns_df: pd.DataFrame,
    assets_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Left-join the vulnerability DataFrame with the asset DataFrame on asset_id.

    This adds OS, full tag list, network name, and first/last seen dates
    to every vulnerability row.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Output of fetch_vulnerabilities().
    assets_df : pd.DataFrame
        Output of fetch_assets().

    Returns
    -------
    pd.DataFrame
        Enriched vulnerability DataFrame.
    """
    asset_cols = [
        "asset_id",
        "operating_system",
        "network_name",
        "first_seen",
        "last_seen",
        "tags",
    ]
    available = [c for c in asset_cols if c in assets_df.columns]
    enriched = vulns_df.merge(assets_df[available], on="asset_id", how="left")
    return enriched


if __name__ == "__main__":
    import argparse
    from tenable_client import get_client

    parser = argparse.ArgumentParser(description="Standalone data fetch test")
    parser.add_argument("--dataset", choices=["vulns", "assets", "tags"], default="tags")
    parser.add_argument("--tag-category", default=None)
    parser.add_argument("--tag-value", default=None)
    parser.add_argument("--run-id", default="test")
    args = parser.parse_args()

    tio = get_client()

    if args.dataset == "vulns":
        df = fetch_vulnerabilities(
            tio,
            args.run_id,
            tag_category=args.tag_category,
            tag_value=args.tag_value,
        )
    elif args.dataset == "assets":
        df = fetch_assets(tio, args.run_id)
    else:
        df = fetch_tags(tio, args.run_id)

    print(df.head(10).to_string())
    print(f"\nTotal rows: {len(df)}")
