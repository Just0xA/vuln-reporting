"""
tests/test_kpi_risk_managed_exclusion.py — Risk-managed (ACCEPTED/RECASTED)
exclusion regression for the three shared board KPI modules.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id: 100001, 100002, ...
  - owner names: "Engineering", "Unassigned"
  - No real hostnames, IPs, CVE IDs, plugin names, or real Tenable UUIDs

Key requirement coverage
-------------------------
- high_risk_assets: ACCEPTED/RECASTED aged Crit/High findings do not push an
  asset over the high-risk threshold
- aged_vulns_assets: ACCEPTED/RECASTED aged findings do not qualify an asset
  as an aged-vulnerability asset
- critical_remediation_sla: ACCEPTED/RECASTED rows in the FIXED population are
  excluded from the SLA percentage and from the "missed SLA" analyst rows

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import datetime

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.base import ModuleConfig
from reports.modules.high_risk_assets_module import HighRiskAssetsModule
from reports.modules.aged_vulns_assets_module import AgedVulnsAssetsModule
from reports.modules.critical_remediation_sla_module import CriticalRemediationSLAModule

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"
_REPORT_DATE = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)

# far-past first_found so findings are "aged" (>30d and >90d both satisfied)
_AGED_FIRST_FOUND = "2020-01-01T00:00:00Z"
# recent scan date so assets are "on-time" (within 30d of report date)
_ON_TIME_SCAN_DATE = "2026-06-01T00:00:00Z"
# recent last_found so open findings clear the quick-260805-ezo finding-level
# staleness guard (last_found >= report_date - 30d)
_RECENT_LAST_FOUND = "2026-06-05T00:00:00Z"


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    # quick-260805-ezo — board modules now tier from vpr_score (VPR-only),
    # so every fixture row carries an explicit vpr_score. 9.5 = critical.
    defaults = {
        "asset_uuid":                  _uuid(1),
        "plugin_id":                   100001,
        "plugin_name":                 "Test Plugin",
        "severity":                    "critical",
        "vpr_score":                   9.5,
        "first_found":                 _AGED_FIRST_FOUND,
        "last_found":                  _RECENT_LAST_FOUND,
        "state":                       "OPEN",
        "severity_modification_type":  "NONE",
    }
    records = [{**defaults, **r} for r in rows]
    df = pd.DataFrame(records, columns=list(defaults.keys()))
    df["first_found"] = pd.to_datetime(df["first_found"], utc=True)
    df["last_found"]  = pd.to_datetime(df["last_found"],  utc=True)
    return df


def _make_assets(rows: list[dict]) -> pd.DataFrame:
    defaults = {
        "asset_uuid":               _uuid(1),
        "hostname":                 "host-1",
        "last_seen":                "2026-06-10T00:00:00Z",
        "last_licensed_scan_date":  _ON_TIME_SCAN_DATE,
        "tags":                     "Owner=Engineering",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_fixed_vulns(rows: list[dict]) -> pd.DataFrame:
    defaults = {
        "asset_uuid":                  _uuid(1),
        "plugin_id":                   100001,
        "plugin_name":                 "Test Plugin",
        "severity":                    "critical",
        "state":                       "FIXED",
        "first_found":                 "2026-05-20T00:00:00Z",
        "last_fixed":                  "2026-05-25T00:00:00Z",
        "severity_modification_type":  "NONE",
        "tags":                        "Owner=Engineering",
    }
    records = [{**defaults, **r} for r in rows]
    df = pd.DataFrame(records, columns=list(defaults.keys()))
    df["first_found"] = pd.to_datetime(df["first_found"], utc=True)
    df["last_fixed"]  = pd.to_datetime(df["last_fixed"],  utc=True)
    return df


# ===========================================================================
# high_risk_assets — >= 10 aged Crit/High findings qualifies an asset
# ===========================================================================

class TestHighRiskAssetsExclusion:
    def test_accepted_recast_rows_do_not_count_toward_threshold(self):
        # Asset carries 8 NONE-modification aged Crit/High findings — below
        # the >=10 high-risk threshold — plus 3 ACCEPTED/RECASTED aged
        # findings that would push it to 11 (over threshold) if wrongly
        # counted.
        vulns_rows = (
            [{"plugin_id": 100000 + i, "severity_modification_type": "NONE"} for i in range(8)]
            + [
                {"plugin_id": 100100, "severity_modification_type": "ACCEPTED"},
                {"plugin_id": 100101, "severity_modification_type": "RECASTED"},
                {"plugin_id": 100102, "severity_modification_type": "accepted"},
            ]
        )
        vulns_df  = _make_vulns(vulns_rows)
        assets_df = _make_assets([{}])
        mod       = HighRiskAssetsModule()
        cfg       = ModuleConfig("high_risk_assets")

        result = mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg)

        assert result.error is None
        assert result.metrics["high_risk_count"] == 0
        assert result.metrics["high_risk_pct"] == 0.0

    def test_non_risk_managed_rows_still_qualify(self):
        # Sanity check: 10 NONE-modification aged findings DO qualify.
        vulns_rows = [
            {"plugin_id": 100000 + i, "severity_modification_type": "NONE"}
            for i in range(10)
        ]
        vulns_df  = _make_vulns(vulns_rows)
        assets_df = _make_assets([{}])
        mod       = HighRiskAssetsModule()
        cfg       = ModuleConfig("high_risk_assets")

        result = mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg)

        assert result.error is None
        assert result.metrics["high_risk_count"] == 1


# ===========================================================================
# aged_vulns_assets — >= 1 aged Med/High/Crit finding qualifies an asset
# ===========================================================================

class TestAgedVulnsAssetsExclusion:
    def test_accepted_recast_only_finding_does_not_qualify(self):
        # Asset's ONLY aged finding is ACCEPTED — must not qualify the asset.
        vulns_df  = _make_vulns([
            {"plugin_id": 100001, "severity_modification_type": "ACCEPTED"},
        ])
        assets_df = _make_assets([{}])
        mod       = AgedVulnsAssetsModule()
        cfg       = ModuleConfig("aged_vulns_assets")

        result = mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg)

        assert result.error is None
        assert result.metrics["aged_assets_count"] == 0
        assert result.metrics["aged_assets_pct"] == 0.0

    def test_non_risk_managed_finding_still_qualifies(self):
        vulns_df  = _make_vulns([
            {"plugin_id": 100001, "severity_modification_type": "NONE"},
        ])
        assets_df = _make_assets([{}])
        mod       = AgedVulnsAssetsModule()
        cfg       = ModuleConfig("aged_vulns_assets")

        result = mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg)

        assert result.error is None
        assert result.metrics["aged_assets_count"] == 1


# ===========================================================================
# quick-260805-ezo — VPR-only severity tiering in the two asset-count modules
# ===========================================================================

class TestVprOnlySeverityTiering:
    """
    D-03 — high_risk_assets and aged_vulns_assets tier findings from the
    board-local ``vpr_severity`` column, never from the native ``severity``
    string. A null VPR is "none", NOT the native CVSS tier.
    """

    def test_high_risk_native_critical_without_vpr_not_counted(self):
        # 12 findings that the NATIVE severity string calls "critical" but
        # which carry no VPR score at all. Under VPR-only tiering they are
        # "none" and must not push the asset over the >=10 high-risk bar.
        vulns_df = _make_vulns([
            {"plugin_id": 100000 + i, "severity": "critical", "vpr_score": None}
            for i in range(12)
        ])
        result = HighRiskAssetsModule().compute(
            vulns_df, _make_assets([{}]), _REPORT_DATE,
            ModuleConfig("high_risk_assets"),
        )

        assert result.error is None
        assert result.metrics["high_risk_count"] == 0

    def test_high_risk_native_medium_with_critical_vpr_is_counted(self):
        # Native severity says "medium" but VPR 9.5 is Critical — VPR wins.
        vulns_df = _make_vulns([
            {"plugin_id": 100000 + i, "severity": "medium", "vpr_score": 9.5}
            for i in range(10)
        ])
        result = HighRiskAssetsModule().compute(
            vulns_df, _make_assets([{}]), _REPORT_DATE,
            ModuleConfig("high_risk_assets"),
        )

        assert result.error is None
        assert result.metrics["high_risk_count"] == 1

    def test_aged_vulns_native_critical_without_vpr_not_counted(self):
        vulns_df = _make_vulns([
            {"plugin_id": 100001, "severity": "critical", "vpr_score": None},
        ])
        result = AgedVulnsAssetsModule().compute(
            vulns_df, _make_assets([{}]), _REPORT_DATE,
            ModuleConfig("aged_vulns_assets"),
        )

        assert result.error is None
        assert result.metrics["aged_assets_count"] == 0

    def test_aged_vulns_native_low_with_critical_vpr_is_counted(self):
        vulns_df = _make_vulns([
            {"plugin_id": 100001, "severity": "low", "vpr_score": 9.5},
        ])
        result = AgedVulnsAssetsModule().compute(
            vulns_df, _make_assets([{}]), _REPORT_DATE,
            ModuleConfig("aged_vulns_assets"),
        )

        assert result.error is None
        assert result.metrics["aged_assets_count"] == 1


# ===========================================================================
# critical_remediation_sla — FIXED population exclusion
# ===========================================================================

class TestCriticalRemediationSLAExclusion:
    def test_accepted_recast_rows_excluded_from_sla_and_missed_rows(self):
        # 2 NONE-modification findings fixed within the 15-day SLA (5 days),
        # plus 2 ACCEPTED/RECASTED findings fixed WAY outside SLA (40 days)
        # that must not count toward total_fixed_last_month, must not drag
        # down remediation_sla_pct, and must not appear in the "missed SLA"
        # analyst rows.
        fixed_rows = [
            {
                "plugin_id":                  100001,
                "first_found":                "2026-05-20T00:00:00Z",
                "last_fixed":                 "2026-05-25T00:00:00Z",  # 5 days
                "severity_modification_type": "NONE",
            },
            {
                "plugin_id":                  100002,
                "first_found":                "2026-05-20T00:00:00Z",
                "last_fixed":                 "2026-05-25T00:00:00Z",  # 5 days
                "severity_modification_type": "NONE",
            },
            {
                "plugin_id":                  100003,
                "first_found":                "2026-04-15T00:00:00Z",
                "last_fixed":                 "2026-05-25T00:00:00Z",  # 40 days
                "severity_modification_type": "ACCEPTED",
            },
            {
                "plugin_id":                  100004,
                "first_found":                "2026-04-15T00:00:00Z",
                "last_fixed":                 "2026-05-25T00:00:00Z",  # 40 days
                "severity_modification_type": "RECASTED",
            },
        ]
        fixed_vulns_df = _make_fixed_vulns(fixed_rows)
        vulns_df       = pd.DataFrame(columns=["asset_uuid", "severity", "first_found"])
        assets_df      = _make_assets([{}])
        mod            = CriticalRemediationSLAModule()
        cfg            = ModuleConfig("critical_remediation_sla")

        result = mod.compute(
            vulns_df, assets_df, _REPORT_DATE, cfg, fixed_vulns_df=fixed_vulns_df,
        )

        assert result.error is None
        assert result.metrics["total_fixed_last_month"] == 2
        assert result.metrics["fixed_within_sla"] == 2
        assert result.metrics["remediation_sla_pct"] == 100.0
        # No "missed SLA" analyst rows — the two ACCEPTED/RECASTED 40-day
        # findings are excluded before the missed-SLA slice is computed.
        assert result.analyst_rows == []
