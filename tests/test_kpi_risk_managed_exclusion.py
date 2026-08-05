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
    # quick-260805-ezo — vpr_score drives the cohort; resurfaced_date drives
    # the reopened-aware clock; time_taken_to_fix is present but deliberately
    # NOT consulted by the module any more.
    defaults = {
        "asset_uuid":                  _uuid(1),
        "plugin_id":                   100001,
        "plugin_name":                 "Test Plugin",
        "severity":                    "critical",
        "vpr_score":                   9.5,
        "state":                       "FIXED",
        "first_found":                 "2026-05-20T00:00:00Z",
        "last_fixed":                  "2026-05-25T00:00:00Z",
        "resurfaced_date":             None,
        "time_taken_to_fix":           None,
        "severity_modification_type":  "NONE",
        "tags":                        "Owner=Engineering",
    }
    records = [{**defaults, **r} for r in rows]
    df = pd.DataFrame(records, columns=list(defaults.keys()))
    for _col in ("first_found", "last_fixed", "resurfaced_date"):
        df[_col] = pd.to_datetime(df[_col], utc=True)
    return df


def _days_before(n: float) -> str:
    """ISO-8601 UTC timestamp ``n`` days before the fixed report date."""
    return (_REPORT_DATE - datetime.timedelta(days=n)).isoformat()


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
        # quick-260805-ezo — QT-01 metrics contract replaces
        # total_fixed_last_month / fixed_within_sla with denominator / compliant.
        assert result.metrics["denominator"] == 2
        assert result.metrics["compliant"] == 2
        assert result.metrics["fixed_late"] == 0
        assert result.metrics["remediation_sla_pct"] == 100.0
        # No "missed SLA" analyst rows — the two ACCEPTED/RECASTED 40-day
        # findings are excluded before the missed-SLA slice is computed —
        # so only the always-present VPR distribution tab is returned.
        assert [name for name, _ in result.analyst_rows] == [
            "VPR Severity Distribution"
        ]


# ===========================================================================
# quick-260805-ezo — critical_remediation_sla reformulation
# ===========================================================================

_CRIT_CFG = ModuleConfig("critical_remediation_sla")


def _run_sla(vulns_df, assets_df, fixed_vulns_df):
    return CriticalRemediationSLAModule().compute(
        vulns_df, assets_df, _REPORT_DATE, _CRIT_CFG,
        fixed_vulns_df=fixed_vulns_df,
    )


def _empty_open_df() -> pd.DataFrame:
    return _make_vulns([]).iloc[0:0]


def _empty_fixed_df() -> pd.DataFrame:
    return _make_fixed_vulns([]).iloc[0:0]


class TestCriticalRemediationSLACohortAndScoping:
    """D-04 / D-06 — cohort membership and the asymmetric scoping rules."""

    def test_fixed_finding_on_stale_asset_is_counted(self):
        # D-06: the asset-level on-time gate is REMOVED from the FIXED side.
        # This asset was last licensed-scanned 200 days ago.
        assets_df = _make_assets([
            {"last_licensed_scan_date": _days_before(200)},
        ])
        fixed_df = _make_fixed_vulns([
            {"first_found": _days_before(20), "last_fixed": _days_before(10)},
        ])

        result = _run_sla(_empty_open_df(), assets_df, fixed_df)

        assert result.error is None
        assert result.metrics["compliant"] == 1
        assert result.metrics["denominator"] == 1

    def test_open_finding_with_stale_last_found_is_not_counted(self):
        # D-06: finding-level staleness guard — last_found 45 days ago.
        vulns_df = _make_vulns([
            {"last_found": _days_before(45), "first_found": _days_before(400)},
        ])

        result = _run_sla(vulns_df, _make_assets([{}]), _empty_fixed_df())

        assert result.error is None
        assert result.metrics["open_past_due"] == 0
        assert result.metrics["open_not_due"] == 0
        assert result.metrics["total_critical_open"] == 0

    def test_open_finding_on_not_on_time_asset_is_not_counted(self):
        # The asset-level on-time gate is KEPT on the OPEN side.
        assets_df = _make_assets([
            {"last_licensed_scan_date": _days_before(200)},
        ])
        vulns_df = _make_vulns([
            {"last_found": _days_before(2), "first_found": _days_before(400)},
        ])

        result = _run_sla(vulns_df, assets_df, _empty_fixed_df())

        assert result.error is None
        assert result.metrics["total_critical_open"] == 0

    def test_accepted_excluded_from_both_populations(self):
        vulns_df = _make_vulns([
            {"plugin_id": 100001, "severity_modification_type": "ACCEPTED",
             "last_found": _days_before(2), "first_found": _days_before(400)},
        ])
        fixed_df = _make_fixed_vulns([
            {"plugin_id": 100002, "severity_modification_type": "ACCEPTED",
             "first_found": _days_before(20), "last_fixed": _days_before(10)},
        ])

        result = _run_sla(vulns_df, _make_assets([{}]), fixed_df)

        assert result.error is None
        assert result.metrics["total_critical_open"] == 0
        assert result.metrics["denominator"] == 0

    def test_native_critical_with_non_critical_vpr_not_in_cohort(self):
        # severity string says critical, VPR 6.0 says medium — VPR wins.
        vulns_df = _make_vulns([
            {"severity": "critical", "vpr_score": 6.0,
             "last_found": _days_before(2), "first_found": _days_before(400)},
        ])
        fixed_df = _make_fixed_vulns([
            {"severity": "critical", "vpr_score": 6.0,
             "first_found": _days_before(20), "last_fixed": _days_before(10)},
        ])

        result = _run_sla(vulns_df, _make_assets([{}]), fixed_df)

        assert result.error is None
        assert result.metrics["total_critical_open"] == 0
        assert result.metrics["denominator"] == 0


class TestCriticalRemediationSLAClock:
    """D-05 — COALESCE(resurfaced_date, first_found); no time_taken_to_fix."""

    def test_reopened_clock_uses_resurfaced_date(self):
        fixed_df = _make_fixed_vulns([
            {
                "first_found":     _days_before(100),
                "resurfaced_date": _days_before(10),
                "last_fixed":      _days_before(2),
            },
        ])

        result = _run_sla(_empty_open_df(), _make_assets([{}]), fixed_df)

        assert result.error is None
        # 8 days from the resurface date, NOT 98 from first_found.
        assert result.metrics["compliant"] == 1
        assert result.metrics["fixed_late"] == 0

    def test_time_taken_to_fix_is_ignored_when_it_contradicts_date_math(self):
        fixed_df = _make_fixed_vulns([
            {
                "first_found":       _days_before(20),
                "last_fixed":        _days_before(10),   # date math -> 10 days
                # Tenable's own field claims 90 days. Date math must win.
                "time_taken_to_fix": 90 * 86400.0,
            },
        ])

        result = _run_sla(_empty_open_df(), _make_assets([{}]), fixed_df)

        assert result.error is None
        assert result.metrics["compliant"] == 1
        assert result.metrics["fixed_late"] == 0

    def test_last_fixed_before_clock_start_clips_to_zero(self):
        fixed_df = _make_fixed_vulns([
            {
                "first_found": _days_before(5),
                "last_fixed":  _days_before(10),   # negative delta
            },
        ])

        result = _run_sla(_empty_open_df(), _make_assets([{}]), fixed_df)

        assert result.error is None
        assert result.metrics["compliant"] == 1
        assert result.metrics["fixed_late"] == 0


class TestCriticalRemediationSLAMetric:
    """D-07 / D-08 — four-component formula and the excluded-C denominator."""

    def test_four_component_arithmetic(self):
        # A = 10 fixed (7 within 15d, 3 late), B = 5 open past due,
        # C = 40 open not yet due.
        fixed_rows = (
            [{"plugin_id": 200000 + i,
              "first_found": _days_before(20), "last_fixed": _days_before(10)}
             for i in range(7)]
            + [{"plugin_id": 210000 + i,
                "first_found": _days_before(60), "last_fixed": _days_before(10)}
               for i in range(3)]
        )
        open_rows = (
            [{"plugin_id": 300000 + i,
              "first_found": _days_before(100), "last_found": _days_before(1)}
             for i in range(5)]
            + [{"plugin_id": 310000 + i,
                "first_found": _days_before(3), "last_found": _days_before(1)}
               for i in range(40)]
        )

        result = _run_sla(
            _make_vulns(open_rows), _make_assets([{}]),
            _make_fixed_vulns(fixed_rows),
        )

        assert result.error is None
        m = result.metrics
        assert m["compliant"] == 7
        assert m["fixed_late"] == 3
        assert m["open_past_due"] == 5
        assert m["open_not_due"] == 40
        assert m["breached"] == 8
        assert m["denominator"] == 15
        assert m["remediation_sla_pct"] == 46.7
        assert m["total_critical_open"] == 45
        assert m["status"] == "red"

    def test_removed_metric_keys_are_gone(self):
        result = _run_sla(
            _make_vulns([{"first_found": _days_before(3),
                          "last_found": _days_before(1)}]),
            _make_assets([{}]),
            _make_fixed_vulns([{"first_found": _days_before(20),
                                "last_fixed": _days_before(10)}]),
        )
        for removed in (
            "total_open_last_month", "total_fixed_last_month", "fixed_within_sla",
        ):
            assert removed not in result.metrics, (
                f"{removed} must be removed from the metrics contract (QT-01)"
            )

    def test_zero_denominator_is_no_data_even_with_open_not_due(self):
        # C = 3 findings still inside their 15-day clock; nothing fixed,
        # nothing overdue -> denominator 0 -> No Data.
        open_rows = [
            {"plugin_id": 300000 + i,
             "first_found": _days_before(3), "last_found": _days_before(1)}
            for i in range(3)
        ]

        result = _run_sla(
            _make_vulns(open_rows), _make_assets([{}]), _empty_fixed_df(),
        )

        assert result.error is None
        assert result.metrics["open_not_due"] == 3
        assert result.metrics["denominator"] == 0
        assert result.metrics["remediation_sla_pct"] is None
        assert result.metrics["status"] == "no_data"

    def test_open_past_due_alone_drives_the_metric_red(self):
        open_rows = [
            {"plugin_id": 300000 + i,
             "first_found": _days_before(100), "last_found": _days_before(1)}
            for i in range(4)
        ]

        result = _run_sla(
            _make_vulns(open_rows), _make_assets([{}]), _empty_fixed_df(),
        )

        assert result.error is None
        assert result.metrics["open_past_due"] == 4
        assert result.metrics["breached"] == 4
        assert result.metrics["denominator"] == 4
        assert result.metrics["remediation_sla_pct"] == 0.0
        assert result.metrics["status"] == "red"


class TestCriticalRemediationSLAAnalystTabs:
    """D-10 — analyst workbook tabs."""

    def _tabs(self, result):
        return CriticalRemediationSLAModule().render_analyst_tabs(
            result, _CRIT_CFG,
        )

    def test_two_tabs_when_missed_rows_exist(self):
        result = _run_sla(
            _make_vulns([{"first_found": _days_before(100),
                          "last_found": _days_before(1)}]),
            _make_assets([{}]),
            _make_fixed_vulns([{"first_found": _days_before(60),
                                "last_fixed": _days_before(10)}]),
        )
        tabs = self._tabs(result)

        assert [name for name, _ in tabs] == [
            "Critical Remediation Detail", "VPR Severity Distribution",
        ]
        # Both the late-fixed row and the still-overdue open row appear.
        assert len(tabs[0][1]) == 2

    def test_one_tab_when_no_missed_rows(self):
        result = _run_sla(
            _empty_open_df(), _make_assets([{}]),
            _make_fixed_vulns([{"first_found": _days_before(20),
                                "last_fixed": _days_before(10)}]),
        )
        tabs = self._tabs(result)

        assert [name for name, _ in tabs] == ["VPR Severity Distribution"]

    def test_no_tabs_on_error(self):
        result = _run_sla(
            _empty_open_df(), _make_assets([{}]), _empty_fixed_df(),
        )
        result.error = "boom"

        assert self._tabs(result) == []

    def test_distribution_tab_shape_and_total(self):
        open_rows = [
            {"plugin_id": 400001, "vpr_score": 9.5,
             "last_found": _days_before(1), "first_found": _days_before(3)},
            {"plugin_id": 400002, "vpr_score": 7.5,
             "last_found": _days_before(1), "first_found": _days_before(3)},
            {"plugin_id": 400003, "vpr_score": 5.0,
             "last_found": _days_before(1), "first_found": _days_before(3)},
            {"plugin_id": 400004, "vpr_score": 1.0,
             "last_found": _days_before(1), "first_found": _days_before(3)},
            {"plugin_id": 400005, "vpr_score": None,
             "last_found": _days_before(1), "first_found": _days_before(3)},
        ]
        result = _run_sla(
            _make_vulns(open_rows), _make_assets([{}]), _empty_fixed_df(),
        )
        tabs   = dict(self._tabs(result))
        dist   = tabs["VPR Severity Distribution"]

        assert list(dist.columns) == ["VPR Severity", "Open Findings"]
        assert list(dist["VPR Severity"]) == [
            "critical", "high", "medium", "low", "none", "TOTAL",
        ]
        assert len(dist) == 6
        assert list(dist["Open Findings"]) == [1, 1, 1, 1, 1, 5]
        assert int(dist["Open Findings"].iloc[-1]) == int(
            dist["Open Findings"].iloc[:-1].sum()
        )

    def test_distribution_tab_ignores_the_30_day_staleness_guard(self):
        # The distribution tab scope is on-time assets + risk-managed excluded
        # ONLY — the finding-level last_found guard is deliberately NOT applied.
        open_rows = [
            {"plugin_id": 400001, "vpr_score": 9.5,
             "last_found": _days_before(200), "first_found": _days_before(400)},
        ]
        result = _run_sla(
            _make_vulns(open_rows), _make_assets([{}]), _empty_fixed_df(),
        )
        dist = dict(self._tabs(result))["VPR Severity Distribution"]

        assert int(dist["Open Findings"].iloc[-1]) == 1
        # ...but the stale finding stays out of the SLA populations.
        assert result.metrics["total_critical_open"] == 0
