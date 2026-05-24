"""
tests/fixtures/builders.py — hand-built DataFrames with EXACT known contents.

These power Layer 2 value assertions. Every value is deliberate so the
expected KPI numbers are hand-verifiable. Columns mirror the normalized
output of data/fetchers.py (vuln rows at fetchers.py:325, asset rows at :544).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

# Fixed reference point so "days_open" is deterministic regardless of wall clock.
AS_OF = datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc)

# Full vuln column set the suite relies on.
_VULN_COLUMNS = [
    "asset_uuid", "hostname", "ipv4", "plugin_id", "plugin_name",
    "plugin_family", "vpr_score", "severity", "severity_native",
    "cve_list", "cvss_base_score", "exploit_available",
    "first_found", "last_found", "last_fixed", "state", "finding_id",
]

_ASSET_COLUMNS = [
    "asset_uuid", "hostname", "ipv4", "fqdn", "operating_system",
    "network_name", "last_seen", "last_licensed_scan_date",
    "tags", "tags_str", "source_name",
]


def _vuln(asset_uuid, severity, vpr, days_ago, state="open", **over):
    """One vuln row; first_found is `days_ago` before AS_OF."""
    ff = AS_OF - timedelta(days=days_ago) if days_ago is not None else None
    row = {
        "asset_uuid": asset_uuid,
        "hostname": f"host-{asset_uuid}",
        "ipv4": "10.0.0.1",
        "plugin_id": 19506,
        "plugin_name": "Test Plugin",
        "plugin_family": "General",
        "vpr_score": vpr,
        "severity": severity,
        "severity_native": severity,
        "cve_list": "CVE-2024-0001",
        "cvss_base_score": 7.5,
        "exploit_available": False,
        "first_found": ff,
        "last_found": AS_OF,
        "last_fixed": None,
        "state": state,
        "finding_id": f"f-{asset_uuid}-{severity}",
    }
    row.update(over)
    return row


def build_vulns_df(rows: list[dict]) -> pd.DataFrame:
    # .assign() returns a new frame — avoids the pandas CoW chained-assignment
    # FutureWarning that in-place df[col]=... triggers.
    df = pd.DataFrame(rows, columns=_VULN_COLUMNS)
    return df.assign(
        first_found=pd.to_datetime(df["first_found"], utc=True, errors="coerce"),
    )


def build_assets_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=_ASSET_COLUMNS)
    return df.assign(
        last_seen=pd.to_datetime(df["last_seen"], utc=True, errors="coerce"),
        last_licensed_scan_date=pd.to_datetime(
            df["last_licensed_scan_date"], utc=True, errors="coerce"
        ),
    )


def three_overdue_crit() -> pd.DataFrame:
    """
    5 open vulns: exactly 3 critical past the 15-day SLA, 2 critical within it.
    Expected: is_overdue.sum() == 3.
    """
    return build_vulns_df([
        _vuln("a1", "critical", 9.5, days_ago=20),  # overdue (20 > 15)
        _vuln("a2", "critical", 9.1, days_ago=30),  # overdue
        _vuln("a3", "critical", 9.8, days_ago=16),  # overdue
        _vuln("a4", "critical", 9.2, days_ago=10),  # within SLA
        _vuln("a5", "critical", 9.0, days_ago=5),   # within SLA
    ])


def one_asset() -> pd.DataFrame:
    return build_assets_df([{
        "asset_uuid": "a1", "hostname": "host-a1", "ipv4": "10.0.0.1",
        "fqdn": "host-a1.test", "operating_system": "Linux",
        "network_name": "Default", "last_seen": AS_OF,
        "last_licensed_scan_date": AS_OF, "tags": "Environment=Production",
        "tags_str": "Environment: Production", "source_name": "NESSUS_SCAN",
    }])
