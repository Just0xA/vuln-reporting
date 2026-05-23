"""
tests/fixtures/scenarios.py — named scenarios, including failure modes.

Each scenario returns (vulns_df, assets_df). Used by Layer 3 to exercise
empty-data, null-VPR, and null-date code paths deterministically.
"""
from __future__ import annotations

import pandas as pd

from tests.fixtures.builders import (
    AS_OF, build_assets_df, build_vulns_df, one_asset, three_overdue_crit, _vuln,
)


def zero_match() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Assets exist but carry a tag no group filters on → filtered-to-zero."""
    assets = build_assets_df([{
        "asset_uuid": "z1", "hostname": "z-host", "ipv4": "10.9.9.9",
        "fqdn": "z.test", "operating_system": "Linux", "network_name": "Default",
        "last_seen": AS_OF, "last_licensed_scan_date": AS_OF,
        "tags": "Environment=NoSuchValue", "tags_str": "Environment: NoSuchValue",
        "source_name": "NESSUS_SCAN",
    }])
    return three_overdue_crit(), assets


def null_vpr() -> tuple[pd.DataFrame, pd.DataFrame]:
    """VPR null → severity must come from native fallback."""
    df = build_vulns_df([
        _vuln("n1", "high", vpr=None, days_ago=40, severity_native="high"),
        _vuln("n2", "medium", vpr=None, days_ago=10, severity_native="medium"),
    ])
    return df, one_asset()


def null_first_found() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Null first_found must not crash SLA math."""
    df = build_vulns_df([_vuln("nf1", "critical", 9.5, days_ago=None)])
    return df, one_asset()
