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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Allow running as a top-level script from any working directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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

# ---------------------------------------------------------------------------
# Type-coercion helper
# ---------------------------------------------------------------------------

def _extract_plugin_id_from_filter(filter_dict: dict) -> Optional[str]:
    """
    Recursively search a Tenable recast rule ``filter`` structure for the
    ``definition.id`` condition that carries the plugin_id.

    The filter can be nested arbitrarily (e.g. ``{and: [{or: [...]}, {property:
    "definition.id", ...}]}``) so we recurse through every ``and`` / ``or``
    level until we find the plugin id condition.

    Returns the plugin_id as a string, or None if not found.
    """
    if not isinstance(filter_dict, dict):
        return None
    # Flat filter: {"property": "definition.id", "operator": "eq", "value": "123"}
    if filter_dict.get("property") == "definition.id" and filter_dict.get("operator") == "eq":
        return str(filter_dict.get("value", ""))
    # Nested filter under "and" / "or" keys — recurse
    for key in ("and", "or"):
        for cond in (filter_dict.get(key) or []):
            if not isinstance(cond, dict):
                continue
            if cond.get("property") == "definition.id" and cond.get("operator") == "eq":
                return str(cond.get("value", ""))
            result = _extract_plugin_id_from_filter(cond)
            if result:
                return result
    return None


# Human-readable property labels for filter conditions
_FILTER_PROP_LABELS: dict[str, str] = {
    "definition.id":   "Plugin ID",
    "asset.ipv4":      "IPv4",
    "asset.ipv6":      "IPv6",
    "asset.fqdn":      "FQDN",
    "asset.id":        "Asset ID",
    "asset.tags":      "Tag",
    "asset.network":   "Network",
    "cve":             "CVE",
    "plugin.output":   "Plugin Output",
    "protocol":        "Protocol",
}


def _summarize_filter(filter_dict: dict, _depth: int = 0) -> str:
    """
    Convert a Tenable recast rule filter tree into a compact human-readable string.

    Examples:
        {"and": [{"property": "definition.id", "operator": "eq", "value": "57582"}]}
        → "Plugin ID: 57582"

        {"and": [{"property": "asset.ipv4", ...}, {"property": "definition.id", ...}]}
        → "IPv4: 10.0.0.1 AND Plugin ID: 57582"

    Truncates to 120 chars for display. Returns "No filter" for empty input.
    """
    if not isinstance(filter_dict, dict) or not filter_dict:
        return "No filter"

    # Flat leaf condition
    if "property" in filter_dict and "operator" in filter_dict:
        prop  = filter_dict.get("property", "")
        op    = filter_dict.get("operator", "eq")
        value = filter_dict.get("value", "")
        label = _FILTER_PROP_LABELS.get(prop, prop)
        op_str = "" if op == "eq" else f" ({op})"
        return f"{label}{op_str}: {value}"

    parts: list[str] = []
    for junction in ("and", "or"):
        conditions = filter_dict.get(junction) or []
        if not conditions:
            continue
        sep = f" {junction.upper()} "
        sub_parts = [
            _summarize_filter(c, _depth + 1)
            for c in conditions
            if isinstance(c, dict)
        ]
        joined = sep.join(p for p in sub_parts if p and p != "No filter")
        if joined:
            parts.append(f"({joined})" if _depth > 0 and len(sub_parts) > 1 else joined)

    result = " AND ".join(parts) if parts else "No filter"
    if len(result) > 120:
        result = result[:117] + "..."
    return result


def _first_str(val) -> str:
    """
    Return a plain string regardless of whether the Tenable API returned a
    single string, a list of strings, or None / falsy.

    The vulnerability export wraps some asset fields (e.g. operating_system)
    in a list on certain asset types while returning a bare string on others.
    Passing the raw value directly to pandas produces an object-dtype column
    with mixed list / str values that pyarrow refuses to serialise.
    """
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""

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

def _cache_path(cache_dir: Path, dataset: str) -> Path:
    """Return the parquet cache path for a given cache directory and dataset name."""
    return cache_dir / f"{dataset}.parquet"


def _load_cache(path: Path) -> Optional[pd.DataFrame]:
    """Return cached DataFrame if the file exists, else None."""
    if path.exists():
        logger.info("[CACHE HIT] Loading %s from cache", path.name)
        return pd.read_parquet(path, engine="fastparquet")
    return None


def _save_cache(df: pd.DataFrame, path: Path) -> None:
    """Persist DataFrame to parquet, logging any write errors non-fatally."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(path, index=False, engine="fastparquet")
        logger.debug("Cached %d rows to %s", len(df), path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not write cache file %s: %s", path, exc)


# ===========================================================================
# Unscoped fetch functions — fetch ALL data; call filter_by_tag() to scope
# ===========================================================================

@retry(**_retry_policy)
def fetch_all_vulnerabilities(tio, cache_dir: Path) -> pd.DataFrame:
    """
    Fetch ALL open/reopened vulnerability findings from Tenable, excluding
    Informational severity findings (VPR-derived severity == 'info').

    No tag filter is applied at the API level.  Tag scoping is performed
    in-memory after loading this dataset using ``filter_by_tag()``.

    Caches to ``<cache_dir>/vulns_all.parquet``.  All delivery groups in one
    run_all.py execution share this single parquet file — only the first group
    triggers an API call; every subsequent group gets a [CACHE HIT].

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped directory for parquet cache files.

    Returns
    -------
    pd.DataFrame
        Same column structure as fetch_vulnerabilities().  The ``tags`` column
        is intentionally absent — the Tenable vuln export does not populate
        ``asset.tags`` reliably.  Call ``enrich_vulns_with_assets()`` then
        ``filter_by_tag()`` to apply tag-based scoping after fetching.
    """
    cache = _cache_path(cache_dir, "vulns_all")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info(
        "[API FETCH] Fetching all vulnerabilities from Tenable API (unscoped, no tag filter)"
    )

    export_filters: dict = {
        "state":    ["open", "reopened"],
        "severity": ["critical", "high", "medium", "low"],
    }
    rows: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Streaming full vulnerability export…", total=None)

        for vuln in tio.exports.vulns(**export_filters):
            asset       = vuln.get("asset", {})
            plugin      = vuln.get("plugin", {})
            severity_id = vuln.get("severity_id", 0)

            severity_native = SEVERITY_LEVEL_MAP.get(severity_id, "info")
            vpr_data        = plugin.get("vpr") or {}
            vpr_score       = vpr_data.get("score")
            severity        = vpr_to_severity(vpr_score, fallback=severity_native)

            # Exclude Informational — no SLA obligation; reduces export size.
            if severity == "info":
                progress.advance(task)
                continue

            # Exploit code maturity — prefer vpr_v2 if present, fall back to
            # vpr.drivers.exploit_code_maturity.  Normalize to uppercase.
            vpr_v2       = plugin.get("vpr_v2") or {}
            vpr_drivers  = vpr_data.get("drivers") or {}
            exploit_maturity = (
                vpr_v2.get("exploit_code_maturity")
                or vpr_drivers.get("exploit_code_maturity")
                or ""
            )

            # Operating system — vuln export returns a list on some asset types
            os_raw = asset.get("operating_system", [])
            if isinstance(os_raw, list):
                operating_system = ", ".join(str(v) for v in os_raw if v)
            else:
                operating_system = str(os_raw) if os_raw else ""

            rows.append({
                # Asset identifiers — asset_uuid matches assets_df.asset_uuid
                "asset_uuid":      asset.get("uuid", ""),
                "hostname":        asset.get("hostname", ""),
                "ipv4":            asset.get("ipv4", ""),
                "mac_address":     asset.get("mac_address", ""),
                "operating_system": operating_system,
                # Plugin / finding info
                "plugin_id":       plugin.get("id", ""),
                "plugin_name":     plugin.get("name", ""),
                "plugin_family":   plugin.get("family", ""),
                # Severity — VPR-derived is the canonical field
                "vpr_score":       vpr_score,
                "severity":        severity,
                "severity_native": severity_native,
                "severity_level":  severity_id,
                # CVE / CVSS / CPE
                "cve_list":        ", ".join(plugin.get("cve", []) or []),
                "cpe":             ", ".join(plugin.get("cpe", []) or []),
                "cvss_base_score": plugin.get("cvss_base_score"),
                "cvss3_score":     plugin.get("cvss3_base_score"),
                # Exploit
                "exploit_available":    plugin.get("exploit_available", False),
                "exploit_code_maturity": str(exploit_maturity).upper(),
                # Dates
                "first_found":  vuln.get("first_found", ""),
                "last_found":   vuln.get("last_found", ""),
                "last_fixed":   vuln.get("last_fixed", ""),
                # State / identity
                "state":        vuln.get("state", ""),
                "finding_id":   vuln.get("finding_id", ""),
                # Risk management
                "severity_modification_type": vuln.get("severity_modification_type", "NONE"),
                "recast_rule_uuid":           vuln.get("recast_rule_uuid", ""),
                "recast_reason":              vuln.get("recast_reason", ""),
                "resurfaced_date":            vuln.get("resurfaced_date", ""),
                "time_taken_to_fix":          vuln.get("time_taken_to_fix"),
                # NOTE: tags are NOT included here — the vuln export asset
                # sub-object does not populate asset.tags reliably.  Tag data
                # is joined from the asset export by enrich_vulns_with_assets().
            })
            progress.advance(task)

    df = pd.DataFrame(rows)
    df = _normalize_vuln_dates(df)
    logger.info(
        "Fetched %d vulnerability records (Informational excluded).", len(df)
    )
    _save_cache(df, cache)
    return df


@retry(**_retry_policy)
def fetch_fixed_vulnerabilities(tio, cache_dir: Path) -> pd.DataFrame:
    """
    Fetch ALL fixed/remediated vulnerability findings from Tenable.

    Used by ``reports/management_summary.py`` to compute MTTR metrics.
    The ``time_taken_to_fix`` field (seconds) is the primary MTTR source;
    ``(last_fixed - first_found)`` is the fallback.

    Caches to ``<cache_dir>/vulns_fixed.parquet``.  Informational findings
    are excluded (no SLA; MTTR is meaningless for them).

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped directory for parquet cache files.

    Returns
    -------
    pd.DataFrame
        Same column schema as ``fetch_all_vulnerabilities()`` but containing
        only state=fixed findings.
    """
    cache = _cache_path(cache_dir, "vulns_fixed")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("[API FETCH] Fetching fixed vulnerabilities from Tenable API")

    export_filters: dict = {
        "state":    ["fixed"],
        "severity": ["critical", "high", "medium", "low"],
    }
    rows: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Streaming fixed vulnerability export…", total=None)

        for vuln in tio.exports.vulns(**export_filters):
            asset       = vuln.get("asset", {})
            plugin      = vuln.get("plugin", {})
            severity_id = vuln.get("severity_id", 0)

            severity_native = SEVERITY_LEVEL_MAP.get(severity_id, "info")
            vpr_data        = plugin.get("vpr") or {}
            vpr_score       = vpr_data.get("score")
            severity        = vpr_to_severity(vpr_score, fallback=severity_native)

            if severity == "info":
                progress.advance(task)
                continue

            vpr_v2          = plugin.get("vpr_v2") or {}
            vpr_drivers     = vpr_data.get("drivers") or {}
            exploit_maturity = (
                vpr_v2.get("exploit_code_maturity")
                or vpr_drivers.get("exploit_code_maturity")
                or ""
            )

            os_raw = asset.get("operating_system", [])
            if isinstance(os_raw, list):
                operating_system = ", ".join(str(v) for v in os_raw if v)
            else:
                operating_system = str(os_raw) if os_raw else ""

            rows.append({
                "asset_uuid":      asset.get("uuid", ""),
                "hostname":        asset.get("hostname", ""),
                "ipv4":            asset.get("ipv4", ""),
                "mac_address":     asset.get("mac_address", ""),
                "operating_system": operating_system,
                "plugin_id":       plugin.get("id", ""),
                "plugin_name":     plugin.get("name", ""),
                "plugin_family":   plugin.get("family", ""),
                "vpr_score":       vpr_score,
                "severity":        severity,
                "severity_native": severity_native,
                "severity_level":  severity_id,
                "cve_list":        ", ".join(plugin.get("cve", []) or []),
                "cvss_base_score": plugin.get("cvss_base_score"),
                "cvss3_score":     plugin.get("cvss3_base_score"),
                "exploit_available":     plugin.get("exploit_available", False),
                "exploit_code_maturity": str(exploit_maturity).upper(),
                "first_found":  vuln.get("first_found", ""),
                "last_found":   vuln.get("last_found", ""),
                "last_fixed":   vuln.get("last_fixed", ""),
                "state":        vuln.get("state", ""),
                "finding_id":   vuln.get("finding_id", ""),
                "severity_modification_type": vuln.get("severity_modification_type", "NONE"),
                "recast_rule_uuid":           vuln.get("recast_rule_uuid", ""),
                "recast_reason":              vuln.get("recast_reason", ""),
                "resurfaced_date":            vuln.get("resurfaced_date", ""),
                "time_taken_to_fix":          vuln.get("time_taken_to_fix"),
            })
            progress.advance(task)

    df = pd.DataFrame(rows)
    df = _normalize_vuln_dates(df)
    logger.info("Fetched %d fixed vulnerability records (Informational excluded).", len(df))
    _save_cache(df, cache)
    return df


@retry(**_retry_policy)
def fetch_all_assets(tio, cache_dir: Path) -> pd.DataFrame:
    """
    Fetch ALL asset records from Tenable.

    No tag filter is applied.  Use ``filter_by_tag()`` on the returned
    DataFrame to scope to a specific tag category/value in-memory.

    Caches to ``<cache_dir>/assets_all.parquet``.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped directory for parquet cache files.

    Returns
    -------
    pd.DataFrame
        Same column structure as fetch_assets().
    """
    cache = _cache_path(cache_dir, "assets_all")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("[API FETCH] Fetching all assets from Tenable API (unscoped)")
    rows: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Streaming full asset export…", total=None)

        for asset in tio.exports.assets():
            ipv4_list     = asset.get("ipv4s")          or []
            fqdn_list     = asset.get("fqdns")          or []
            hostname_list = asset.get("hostnames")      or []
            mac_list      = asset.get("mac_addresses")  or []
            os_list       = asset.get("operating_systems") or []
            sources       = asset.get("sources")        or []

            # Tags — build two representations:
            #   tags     : "Category=Value;Category=Value" (used by filter_by_tag)
            #   tags_str : "Key: Value, Key: Value"        (display in Excel/PDF)
            raw_tags    = asset.get("tags") or []
            tag_filter_parts  = []   # for filter_by_tag() compat
            tag_display_parts = []   # for human display
            for t in raw_tags:
                if not isinstance(t, dict):
                    continue
                # API uses "key" for category name in the asset export
                category = t.get("key") or t.get("category_name") or t.get("tag_key") or ""
                value    = t.get("value") or t.get("tag_value") or ""
                if category and value:
                    tag_filter_parts.append(f"{category}={value}")
                    tag_display_parts.append(f"{category}: {value}")

            source_name = sources[0].get("name", "") if sources else ""

            rows.append({
                # UUID — asset export uses "id", not "uuid"
                "asset_uuid":        asset.get("id", ""),
                # Identity
                "hostname":          hostname_list[0] if hostname_list else (fqdn_list[0] if fqdn_list else ""),
                "ipv4":              ipv4_list[0]    if ipv4_list    else "",
                "mac_address":       mac_list[0]     if mac_list     else "",
                "fqdn":              fqdn_list[0]    if fqdn_list    else "",
                "operating_system":  os_list[0]      if os_list      else "",
                "network_name":      asset.get("network_name", ""),
                # Scan dates
                "last_seen":                    asset.get("last_seen"),
                "last_scan_time":               asset.get("last_scan_time"),
                "last_licensed_scan_date":      asset.get("last_licensed_scan_date"),
                "last_authenticated_scan_date": asset.get("last_authenticated_scan_date"),
                "first_seen":                   asset.get("first_seen", ""),
                "has_plugin_results":           asset.get("has_plugin_results"),
                # Source
                "source_name":       source_name,
                "is_connector_asset": any("Connector" in (s.get("name") or "") for s in sources),
                # Tags
                "tags":              ";".join(tag_filter_parts),   # filter_by_tag compat
                "tags_str":          ", ".join(tag_display_parts), # display
                # Agent identity (list — one asset may have multiple agent names)
                "agent_names":       asset.get("agent_names") or [],
                "agent_uuid":        asset.get("agent_uuid", ""),
            })
            progress.advance(task)

    df = pd.DataFrame(rows)
    df = _normalize_asset_dates(df)
    logger.info("Fetched %d asset records.", len(df))
    _save_cache(df, cache)
    return df


# ===========================================================================
# Recast / Accept rules — direct REST call (not wrapped by pyTenable for IO)
# ===========================================================================

def fetch_recast_rules(tio, cache_dir: Path) -> pd.DataFrame:
    """
    Fetch all active HOST recast and accept rules from the Tenable
    ``POST /v1/recast/rules/search`` endpoint.

    pyTenable does not wrap this endpoint for Tenable.io.  Authentication
    uses the same ``TVM_ACCESS_KEY`` / ``TVM_SECRET_KEY`` / ``TVM_URL``
    environment variables as the rest of the project.

    Only ``resource_type == "HOST"`` rules with ``action`` of ``RECAST`` or
    ``ACCEPT`` are returned.  ``CHANGE_RESULT`` / ``ACCEPT_RESULT`` rules
    (Host Audit / compliance scans) are silently dropped.  Disabled rules
    are also excluded.

    Caches to ``<cache_dir>/recast_rules.parquet``.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client (used only to confirm connectivity;
        the direct HTTP call uses env-var credentials).
    cache_dir : Path
        Run-scoped directory for parquet cache files.

    Returns
    -------
    pd.DataFrame
        Columns: rule_id, rule_name, plugin_id (int, nullable),
        action, new_severity, original_severity, expires_at, created_at.
        Empty DataFrame on error or when no rules exist.
    """
    import os
    import requests as _requests

    cache = _cache_path(cache_dir, "recast_rules")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    base_url   = os.getenv("TVM_URL", "https://cloud.tenable.com").rstrip("/")
    access_key = os.getenv("TVM_ACCESS_KEY", "")
    secret_key = os.getenv("TVM_SECRET_KEY", "")

    if not access_key or not secret_key:
        logger.warning(
            "fetch_recast_rules: TVM_ACCESS_KEY / TVM_SECRET_KEY not set "
            "— returning empty DataFrame"
        )
        return pd.DataFrame(columns=[
            "rule_id", "rule_name", "plugin_id", "action",
            "new_severity", "original_severity", "expires_at", "created_at",
        ])

    headers = {
        "accept":       "application/json",
        "content-type": "application/json",
        "X-ApiKeys":    f"accessKey={access_key};secretKey={secret_key}",
    }

    all_rules: list[dict] = []
    payload: dict = {"resource_type": ["HOST"]}

    logger.info("[API FETCH] Fetching recast/accept rules from Tenable API")

    while True:
        try:
            resp = _requests.post(
                f"{base_url}/v1/recast/rules/search",
                json=payload,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.error("fetch_recast_rules: API call failed: %s", exc)
            break

        data       = resp.json()
        all_rules.extend(data.get("rules") or [])
        next_cursor = (data.get("pagination") or {}).get("next")
        if not next_cursor:
            break
        payload["next"] = next_cursor

    rows: list[dict] = []
    for rule in all_rules:
        rule_value = rule.get("rule_value") or {}
        action     = rule_value.get("action", "")

        # Only vulnerability recasts / acceptances — skip compliance audit actions
        if action not in ("RECAST", "ACCEPT"):
            continue

        # Skip disabled rules
        if (rule.get("disabled_details") or {}).get("disabled", False):
            continue

        raw_pid   = _extract_plugin_id_from_filter(rule.get("filter") or {})
        plugin_id = int(raw_pid) if raw_pid and str(raw_pid).isdigit() else None

        filter_summary = _summarize_filter(rule.get("filter") or {})

        # expires_at is only present in the response when an expiry has been set.
        # Absence means "Never expires".
        expires_at_val = rule.get("expires_at") or "Never"

        rows.append({
            "rule_id":           rule.get("rule_id", ""),
            "rule_name":         rule.get("rule_name", ""),
            "plugin_id":         plugin_id,
            "filter_summary":    filter_summary,
            "action":            action,
            "new_severity":      rule_value.get("severity", ""),        # current severity after rule
            "original_severity": rule_value.get("original_severity"),   # original severity before rule (None for ACCEPT)
            "expires_at":        expires_at_val,
            "created_at":        rule.get("created_at", ""),
        })

    _EMPTY_COLS = [
        "rule_id", "rule_name", "plugin_id", "action",
        "new_severity", "original_severity", "expires_at", "created_at",
    ]
    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=_EMPTY_COLS)

    if not df.empty:
        for col in ("expires_at", "created_at"):
            if col in df.columns:
                df[col] = _parse_iso_utc(df[col])

    logger.info(
        "fetch_recast_rules: %d active HOST RECAST/ACCEPT rules loaded.", len(df)
    )
    _save_cache(df, cache)
    return df


# ===========================================================================
# In-memory filter helpers
# ===========================================================================

def filter_by_tag(
    df: pd.DataFrame,
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> pd.DataFrame:
    """
    Filter a vulnerability or asset DataFrame to rows that carry a specific tag.

    Searches the ``tags`` column for an exact ``"Category=Value"`` token within
    the semicolon-delimited string produced by ``fetch_all_vulnerabilities()``,
    ``fetch_all_assets()``, and ``enrich_vulns_with_assets()``.  The match is
    case-insensitive.

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability or asset DataFrame to filter.
    tag_category : str or None
        Tag category to match, e.g. ``"Environment"``.
    tag_value : str or None
        Tag value to match, e.g. ``"Production"``.

    Returns
    -------
    pd.DataFrame
        Filtered copy of df, or df unmodified when no filter is specified or
        when the ``tags`` column is absent.
    """
    if not tag_category or not tag_value:
        return df

    if "tags" not in df.columns:
        logger.warning(
            "filter_by_tag: 'tags' column not present in DataFrame — returning "
            "unfiltered.  Call fetch_all_vulnerabilities() or "
            "enrich_vulns_with_assets() before filter_by_tag()."
        )
        return df

    # Diagnostic: log how many rows have populated tags and show a sample.
    non_empty_tags = df["tags"].fillna("").loc[lambda s: s != ""]
    logger.info(
        "filter_by_tag diagnostic: %d/%d rows have non-empty tags. "
        "Sample values: %s",
        len(non_empty_tags),
        len(df),
        non_empty_tags.head(5).tolist(),
    )

    target = re.escape(f"{tag_category}={tag_value}")
    mask = df["tags"].fillna("").str.contains(target, case=False, regex=True)
    filtered = df[mask].copy()
    logger.info(
        "filter_by_tag(%r=%r): %d → %d rows",
        tag_category, tag_value, len(df), len(filtered),
    )
    return filtered


def filter_by_severity(
    df: pd.DataFrame,
    severities: list[str],
) -> pd.DataFrame:
    """
    Filter a vulnerability DataFrame to rows whose VPR-derived severity
    matches one of the supplied values.

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame — must contain a ``severity`` column.
    severities : list[str]
        Severity labels to retain, e.g. ``["critical", "high"]``.
        Values are compared case-insensitively.

    Returns
    -------
    pd.DataFrame
        Filtered copy, or df unmodified when ``severities`` is empty/None or
        when the ``severity`` column is absent.
    """
    if not severities:
        return df
    if "severity" not in df.columns:
        return df

    targets = [s.lower().strip() for s in severities if s]
    if not targets:
        return df

    filtered = df[df["severity"].str.lower().isin(targets)].copy()
    logger.info(
        "filter_by_severity(%r): %d → %d rows",
        severities, len(df), len(filtered),
    )
    return filtered


# ===========================================================================
# Tag-scoped fetch functions — DEPRECATED
# Use fetch_all_vulnerabilities() + filter_by_tag() for all new code.
# These functions are retained because utils/tag_helper.py imports them
# directly (fetch_tags, fetch_assets_by_tag).  They will be removed in a
# follow-up cleanup task once tag_helper.py is updated.
# ===========================================================================

@retry(**_retry_policy)
def fetch_vulnerabilities(
    tio,
    cache_dir: Path,
    *,
    tag_category: Optional[str] = None,
    tag_value: Optional[str] = None,
) -> pd.DataFrame:
    """
    .. deprecated::
        Use ``fetch_all_vulnerabilities(tio, cache_dir)`` followed by
        ``filter_by_tag(df, tag_category, tag_value)`` instead.  This function
        issues a separate Tenable export API call per unique tag filter, which
        prevents cross-group cache sharing.

    Export all vulnerability findings via tio.exports.vulns().

    Optionally scoped to assets matching a specific tag category/value pair.
    Results are cached in cache_dir so subsequent calls within the same run
    return the cached DataFrame instantly.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped directory for parquet cache files.  All reports in the
        same group execution must pass the same path so they share the cache.
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
    cache = _cache_path(cache_dir, dataset)
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info(
        "[API FETCH] Fetching vulns from Tenable API (tag=%s:%s)",
        tag_category,
        tag_value,
    )

    export_filters: dict = {
        "state":    ["open", "reopened"],
        "severity": ["critical", "high", "medium", "low"],
    }

    # Scope to tag if both category and value are provided.
    # tio.exports.vulns() accepts tags as a list of (category, value) tuples.
    if tag_category and tag_value:
        export_filters["tags"] = [(tag_category, tag_value)]

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
                "operating_system": _first_str(asset.get("operating_system")),
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
    cache_dir: Path,
) -> pd.DataFrame:
    """
    Export all asset records via tio.exports.assets().

    Results are cached in cache_dir.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped directory for parquet cache files.

    Returns
    -------
    pd.DataFrame
        Normalized asset DataFrame. Key columns:
        asset_id, hostname, ipv4, fqdn, operating_system,
        first_seen, last_seen, last_scan_time,
        tags (list serialized as JSON string), network_name
    """
    cache = _cache_path(cache_dir, "assets")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("[API FETCH] Fetching assets from Tenable API")
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
            tag_strings = []
            for t in raw_tags:
                if not isinstance(t, dict):
                    continue
                category = (
                    t.get("category_name")
                    or t.get("tag_key")
                    or t.get("key")
                    or ""
                )
                value = (
                    t.get("value")
                    or t.get("tag_value")
                    or ""
                )
                if category and value:
                    tag_strings.append(f"{category}={value}")

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
def fetch_tags(tio, cache_dir: Path) -> pd.DataFrame:
    """
    Retrieve all tag categories and values via tio.tags.list().

    Caches results in cache_dir.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    cache_dir : Path
        Run-scoped directory for parquet cache files.

    Returns
    -------
    pd.DataFrame
        Columns: tag_uuid, category_name, value, description, asset_count
    """
    cache = _cache_path(cache_dir, "tags")
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("[API FETCH] Fetching tag definitions from Tenable API")
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
    cache_dir: Path,
    *,
    tag_category: str,
    tag_value: str,
) -> pd.DataFrame:
    """
    .. deprecated::
        Use ``fetch_all_assets(tio, cache_dir)`` followed by
        ``filter_by_tag(df, tag_category, tag_value)`` instead.

    Return a DataFrame of asset IDs that carry a specific tag category/value.

    Parameters
    ----------
    tio : TenableIO
    cache_dir : Path
        Run-scoped directory for parquet cache files.
    tag_category : str
    tag_value : str

    Returns
    -------
    pd.DataFrame
        Columns: asset_id, hostname, ipv4
    """
    dataset = f"tagged_assets_{tag_category}_{tag_value}"
    cache = _cache_path(cache_dir, dataset)
    cached = _load_cache(cache)
    if cached is not None:
        return cached

    logger.info("[API FETCH] Fetching assets tagged %s=%s from Tenable API", tag_category, tag_value)

    # tio.exports.assets() accepts tags as a list of (category, value) tuples.
    # No UUID lookup is required — the API resolves the tag internally.
    rows: list[dict] = []
    for asset in tio.exports.assets(tags=[(tag_category, tag_value)]):
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
    updates = {
        col: _parse_iso_utc(df[col])
        for col in ("first_found", "last_found", "last_fixed", "resurfaced_date")
        if col in df.columns
    }
    return df.assign(**updates) if updates else df


def _normalize_asset_dates(df: pd.DataFrame) -> pd.DataFrame:
    """Cast date columns in the asset DataFrame to UTC datetimes."""
    updates = {
        col: _parse_iso_utc(df[col])
        for col in (
            "first_seen",
            "last_seen",
            "last_scan_time",
            "last_licensed_scan_date",
            "last_authenticated_scan_date",
        )
        if col in df.columns
    }
    return df.assign(**updates) if updates else df


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
        "asset_uuid",
        "operating_system",
        "network_name",
        "first_seen",
        "last_seen",
        "last_licensed_scan_date",
        "last_authenticated_scan_date",
        "mac_address",
        "tags",
        "tags_str",
        "source_name",
        "is_connector_asset",
    ]
    available = [c for c in asset_cols if c in assets_df.columns]

    # Drop columns that exist in vulns_df and would be overwritten by the join
    # (operating_system and mac_address can appear in both — prefer the richer
    # asset-export version which normalises list fields cleanly).
    drop_from_vulns = [c for c in ("operating_system", "mac_address") if c in vulns_df.columns and c in available]
    vulns_base = vulns_df.drop(columns=drop_from_vulns) if drop_from_vulns else vulns_df

    enriched = vulns_base.merge(assets_df[available], on="asset_uuid", how="left")

    # Diagnostic: report join success rate so key mismatches are visible.
    if "tags" in enriched.columns:
        matched = enriched["tags"].notna().sum()
        logger.info(
            "enrich_vulns_with_assets: %d/%d vuln rows matched an asset "
            "(tags populated). vuln asset_uuid sample: %s | asset asset_uuid sample: %s",
            matched,
            len(enriched),
            vulns_df["asset_uuid"].dropna().head(3).tolist(),
            assets_df["asset_uuid"].dropna().head(3).tolist(),
        )

    return enriched


if __name__ == "__main__":
    import argparse
    from datetime import datetime, timezone
    from tenable_client import get_client

    parser = argparse.ArgumentParser(
        description=(
            "Standalone data fetcher. Pulls data from Tenable and caches to parquet.\n\n"
            "Examples:\n"
            "  python data/fetchers.py --all                  # fetch everything\n"
            "  python data/fetchers.py --dataset vulns_fixed  # fixed vulns only\n"
            "  python data/fetchers.py --dataset vulns_all    # open/reopened vulns only\n"
            "  python data/fetchers.py --dataset assets_all   # assets only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dataset",
        choices=["vulns_all", "vulns_fixed", "assets_all", "vulns", "assets", "tags"],
        default=None,
        help=(
            "Single dataset to fetch. "
            "vulns_all=open+reopened, vulns_fixed=fixed/remediated, "
            "assets_all=all assets. Ignored when --all is set."
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Fetch all three datasets: vulns_all, vulns_fixed, and assets_all.",
    )
    parser.add_argument("--tag-category", default=None,
                        help="Apply in-memory tag filter after fetching (vulns_all / assets_all)")
    parser.add_argument("--tag-value", default=None)
    parser.add_argument("--cache-dir", default=None,
                        help="Cache directory path (default: data/cache/<today>)")
    args = parser.parse_args()

    if not args.all and args.dataset is None:
        parser.error("Specify --all to fetch everything, or --dataset <name> for a single dataset.")

    _cache_dir = (
        Path(args.cache_dir)
        if args.cache_dir
        else CACHE_DIR / datetime.now().strftime("%Y-%m-%d")
    )

    tio = get_client()

    if args.all:
        print(f"Fetching all datasets → {_cache_dir}\n")

        print("--- vulns_all (open + reopened) ---")
        df = fetch_all_vulnerabilities(tio, _cache_dir)
        print(f"  {len(df):,} rows\n")

        print("--- vulns_fixed (fixed / remediated) ---")
        df = fetch_fixed_vulnerabilities(tio, _cache_dir)
        print(f"  {len(df):,} rows\n")

        print("--- assets_all ---")
        df = fetch_all_assets(tio, _cache_dir)
        print(f"  {len(df):,} rows\n")

        print(f"All fetches complete. Cache: {_cache_dir}")

    elif args.dataset == "vulns_all":
        df = fetch_all_vulnerabilities(tio, _cache_dir)
        df = filter_by_tag(df, args.tag_category, args.tag_value)
        print(df.head(10).to_string())
        print(f"\nTotal rows: {len(df):,}")
    elif args.dataset == "vulns_fixed":
        df = fetch_fixed_vulnerabilities(tio, _cache_dir)
        print(df.head(10).to_string())
        print(f"\nTotal rows: {len(df):,}")
    elif args.dataset == "assets_all":
        df = fetch_all_assets(tio, _cache_dir)
        df = filter_by_tag(df, args.tag_category, args.tag_value)
        print(df.head(10).to_string())
        print(f"\nTotal rows: {len(df):,}")
    elif args.dataset == "vulns":
        df = fetch_vulnerabilities(
            tio,
            _cache_dir,
            tag_category=args.tag_category,
            tag_value=args.tag_value,
        )
        print(df.head(10).to_string())
        print(f"\nTotal rows: {len(df):,}")
    elif args.dataset == "assets":
        df = fetch_assets(tio, _cache_dir)
        print(df.head(10).to_string())
        print(f"\nTotal rows: {len(df):,}")
    else:
        df = fetch_tags(tio, _cache_dir)
        print(df.head(10).to_string())
        print(f"\nTotal rows: {len(df):,}")
