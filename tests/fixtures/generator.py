"""
tests/fixtures/generator.py — seeded synthetic data generator.

make_scenario() returns (vulns_df, assets_df, expected) where `expected`
is derived from the SAME params so value assertions stay in sync with the
generated data. Deterministic for a fixed seed.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pandas as pd

from config import SLA_DAYS as _SLA  # source of truth — avoid drift
from tests.fixtures.builders import build_assets_df, build_vulns_df

_SEVERITIES = ["critical", "high", "medium", "low"]
_VPR = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.0}


def make_scenario(
    seed: int = 42,
    n_assets: int = 50,
    vulns_per_asset: int = 4,
    overdue_ratio: float = 0.3,
    as_of: datetime | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Generate vulns + assets and the expected overdue count."""
    if as_of is None:
        as_of = datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc)
    rng = random.Random(seed)

    asset_rows, vuln_rows = [], []
    expected_overdue = 0

    for i in range(n_assets):
        uuid = f"gen-{i:04d}"
        asset_rows.append({
            "asset_uuid": uuid, "hostname": f"gen-host-{i}",
            "ipv4": f"10.1.{i // 256}.{i % 256}", "fqdn": f"gen-host-{i}.test",
            "operating_system": "Linux", "network_name": "Default",
            "last_seen": as_of, "last_licensed_scan_date": as_of,
            "tags": "Environment=Staging", "tags_str": "Environment: Staging",
            "source_name": "NESSUS_SCAN",
        })
        for j in range(vulns_per_asset):
            sev = rng.choice(_SEVERITIES)
            is_overdue = rng.random() < overdue_ratio
            days_ago = _SLA[sev] + 5 if is_overdue else max(1, _SLA[sev] - 5)
            if is_overdue:
                expected_overdue += 1
            vuln_rows.append({
                "asset_uuid": uuid, "hostname": f"gen-host-{i}", "ipv4": "10.1.0.1",
                "plugin_id": 10000 + j, "plugin_name": f"Gen Plugin {j}",
                "plugin_family": "General", "vpr_score": _VPR[sev],
                "severity": sev, "severity_native": sev,
                "cve_list": "CVE-2024-9999", "cvss_base_score": 7.0,
                "exploit_available": False,
                "first_found": as_of - timedelta(days=days_ago),
                "last_found": as_of, "last_fixed": None, "state": "open",
                "finding_id": f"gen-{i}-{j}",
            })

    return (
        build_vulns_df(vuln_rows),
        build_assets_df(asset_rows),
        {"overdue_count": expected_overdue, "n_assets": n_assets},
    )
