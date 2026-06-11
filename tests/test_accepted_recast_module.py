"""
tests/test_accepted_recast_module.py — Unit tests for AcceptedRecastModule.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - recast_rule_uuid: "00000000-0000-0000-0000-00000000000N"  (Pitfall 6a — synthetic)
  - plugin_id: 100001, 100002, ...
  - owner names: "Engineering", "Operations", "Unassigned"
  - No real hostnames, IPs, CVE IDs, plugin names, or real Tenable UUIDs

Key requirement coverage
------------------------
- RPT-04: ACCEPTED and RECASTED tracked SEPARATELY (Pitfall 6b)
- RPT-04: expired-rule findings flagged "pending re-evaluation" (Pitfall 6a)
- RPT-04: finding counts drive headline; rule counts in analyst tab only (Pitfall 6c)
- QUAL-01: MoM delta cold-starts safe; prior-month absent omits arrow, never NaN%
- QUAL-03: zero-exception / empty-data renders safe four-channel output
- QUAL-05: fixtures synthetic; no real recast_rule_uuid

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import datetime
import warnings
from typing import Optional

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.base import ModuleConfig, ModuleData
from reports.modules.accepted_recast_module import AcceptedRecastModule

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_UUID_PREFIX  = "00000000-0000-0000-0000-00000000000"
_REPORT_DATE  = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns_df with all required columns."""
    defaults = {
        "state":                       "OPEN",
        "first_found":                 "2026-01-01T00:00:00Z",
        "plugin_id":                   100001,
        "asset_uuid":                  _uuid(1),
        "severity":                    "high",
        "severity_modification_type":  "NONE",
        "recast_rule_uuid":            "",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_assets(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal assets_df with asset_uuid and tags columns."""
    defaults = {"asset_uuid": _uuid(1), "tags": ""}
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_recast_rules(rows: list[dict]) -> pd.DataFrame:
    """Build a recast_rules_df with all fetch_recast_rules columns."""
    defaults = {
        "rule_id":           _uuid(1),
        "rule_name":         "Test Rule",
        "plugin_id":         None,
        "action":            "ACCEPT",
        "new_severity":      None,
        "original_severity": "high",
        "expires_at":        None,
        "created_at":        "2026-01-01T00:00:00Z",
        "filter":            {},
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _config(**options) -> ModuleConfig:
    return ModuleConfig("accepted_recast", options=options)


def _run(
    vulns_rows:  list[dict],
    asset_rows:  Optional[list[dict]] = None,
    rules_rows:  Optional[list[dict]] = None,
    trend:       Optional[dict]       = None,
    **options,
) -> ModuleData:
    mod       = AcceptedRecastModule()
    vulns_df  = _make_vulns(vulns_rows)
    assets_df = _make_assets(asset_rows or [{"asset_uuid": _uuid(1), "tags": "Owner=Engineering"}])
    cfg       = _config(**options)
    kwargs: dict = {}
    if rules_rows is not None:
        kwargs["recast_rules_df"] = _make_recast_rules(rules_rows)
    if trend is not None:
        kwargs["trend_snapshots"] = trend
    return mod.compute(vulns_df, assets_df, _REPORT_DATE, cfg, **kwargs)


# ===========================================================================
# 1. MODULE REGISTRATION
# ===========================================================================

class TestRegistration:
    def test_module_id(self):
        assert AcceptedRecastModule.MODULE_ID == "accepted_recast"

    def test_display_name(self):
        assert "Accepted" in AcceptedRecastModule.DISPLAY_NAME
        assert "Recast"   in AcceptedRecastModule.DISPLAY_NAME

    def test_auto_discovery(self):
        """Module is auto-discovered via @register_module on import."""
        import reports.modules
        import reports.modules.registry as registry
        assert "accepted_recast" in registry._modules

    def test_required_data_includes_recast(self):
        assert "recast_rules" in AcceptedRecastModule.REQUIRED_DATA

    def test_required_data_includes_trend(self):
        assert "trend_snapshots" in AcceptedRecastModule.REQUIRED_DATA


# ===========================================================================
# 2. SEPARATE ACCEPTED / RECASTED COUNTS (Pitfall 6b — RPT-04)
# ===========================================================================

class TestSeparateCounts:
    def test_accepted_and_recast_are_distinct_metrics(self):
        """
        RPT-04 / Pitfall 6b: accepted_count and recast_count MUST be separate
        metrics — NEVER silently aggregated into one "exceptions" headline.
        """
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "OPEN",   "plugin_id": 100001},
            {"severity_modification_type": "ACCEPTED", "state": "OPEN",   "plugin_id": 100002},
            {"severity_modification_type": "RECASTED", "state": "OPEN",   "plugin_id": 100003},
            {"severity_modification_type": "NONE",     "state": "OPEN",   "plugin_id": 100004},
            {"severity_modification_type": "",         "state": "OPEN",   "plugin_id": 100005},
        ])
        assert data.error is None
        assert data.metrics["accepted_count"] == 2
        assert data.metrics["recast_count"]   == 1
        # Confirm they are separate keys — both present
        assert "accepted_count" in data.metrics
        assert "recast_count"   in data.metrics

    def test_empty_string_excluded_from_both(self):
        """Pitfall 6b: severity_modification_type='' excluded from both accepted and recasted."""
        data = _run([
            {"severity_modification_type": "",     "state": "OPEN", "plugin_id": 100001},
            {"severity_modification_type": "NONE", "state": "OPEN", "plugin_id": 100002},
        ])
        assert data.metrics["accepted_count"] == 0
        assert data.metrics["recast_count"]   == 0

    def test_none_string_excluded_from_both(self):
        """Pitfall 6b: severity_modification_type='NONE' excluded from both."""
        data = _run([
            {"severity_modification_type": "NONE", "state": "OPEN", "plugin_id": 100001},
        ])
        assert data.metrics["accepted_count"] == 0
        assert data.metrics["recast_count"]   == 0

    def test_isin_filter_case_insensitive(self):
        """Classification filter coerces to uppercase before .isin() check."""
        data = _run([
            {"severity_modification_type": "accepted", "state": "OPEN", "plugin_id": 100001},
            {"severity_modification_type": "Recasted", "state": "OPEN", "plugin_id": 100002},
        ])
        assert data.metrics["accepted_count"] == 1
        assert data.metrics["recast_count"]   == 1

    def test_total_exceptions_is_sum_of_separate(self):
        """total_exceptions == accepted_count + recast_count."""
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001},
            {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100002},
            {"severity_modification_type": "RECASTED", "state": "OPEN", "plugin_id": 100003},
        ])
        assert data.metrics["total_exceptions"] == data.metrics["accepted_count"] + data.metrics["recast_count"]
        assert data.metrics["total_exceptions"] == 3


# ===========================================================================
# 3. EXPIRY CROSS-CHECK (Pitfall 6a — RPT-04)
# ===========================================================================

class TestExpiryCrossCheck:
    def test_expired_rule_finding_excluded_from_accepted_count(self):
        """
        RPT-04 / Pitfall 6a: a finding linked to an expired rule is excluded
        from accepted_count and surfaced as pending_reeval.
        """
        data = _run(
            vulns_rows=[
                # Finding linked to expired rule — should be excluded
                {
                    "severity_modification_type": "ACCEPTED",
                    "state":            "OPEN",
                    "plugin_id":        100001,
                    "recast_rule_uuid": _uuid(1),
                },
                # Finding linked to valid (non-expired) rule
                {
                    "severity_modification_type": "ACCEPTED",
                    "state":            "OPEN",
                    "plugin_id":        100002,
                    "recast_rule_uuid": _uuid(2),
                },
            ],
            rules_rows=[
                {
                    "rule_id":   _uuid(1),
                    "action":    "ACCEPT",
                    "expires_at": "2026-01-01T00:00:00Z",  # expired before report_date
                },
                {
                    "rule_id":   _uuid(2),
                    "action":    "ACCEPT",
                    "expires_at": None,  # no expiry
                },
            ],
        )
        assert data.error is None
        # Expired finding excluded from current count
        assert data.metrics["accepted_count"] == 1
        # Surfaced as pending re-evaluation
        assert data.metrics["pending_reeval"] == 1

    def test_non_expired_rule_finding_counted(self):
        """A finding whose rule has not expired is counted normally."""
        data = _run(
            vulns_rows=[
                {
                    "severity_modification_type": "ACCEPTED",
                    "state":            "OPEN",
                    "plugin_id":        100001,
                    "recast_rule_uuid": _uuid(1),
                },
            ],
            rules_rows=[
                {
                    "rule_id":   _uuid(1),
                    "action":    "ACCEPT",
                    "expires_at": "2030-01-01T00:00:00Z",  # future — not expired
                },
            ],
        )
        assert data.metrics["accepted_count"] == 1
        assert data.metrics["pending_reeval"] == 0

    def test_recast_rules_df_none_skips_cross_check(self):
        """
        Pitfall 6a graceful degradation: recast_rules_df=None → cross-check
        skipped, warning logged, finding-level counts still computed.
        """
        data = _run(
            vulns_rows=[
                {
                    "severity_modification_type": "ACCEPTED",
                    "state":            "OPEN",
                    "plugin_id":        100001,
                    "recast_rule_uuid": _uuid(1),
                },
            ],
            # rules_rows=None → recast_rules_df not passed
        )
        assert data.error is None
        # Count still computed without cross-check
        assert data.metrics["accepted_count"] == 1
        # No expiry checked — pending_reeval stays 0
        assert data.metrics["pending_reeval"] == 0

    def test_empty_recast_rules_df_skips_cross_check(self):
        """recast_rules_df present but empty → skip cross-check gracefully."""
        mod      = AcceptedRecastModule()
        vulns_df = _make_vulns([
            {
                "severity_modification_type": "RECASTED",
                "state":            "OPEN",
                "plugin_id":        100001,
                "recast_rule_uuid": _uuid(1),
            }
        ])
        assets_df = _make_assets([])
        empty_rules = pd.DataFrame(columns=[
            "rule_id", "rule_name", "plugin_id", "action",
            "new_severity", "original_severity", "expires_at", "created_at",
        ])
        data = mod.compute(
            vulns_df, assets_df, _REPORT_DATE, _config(),
            recast_rules_df=empty_rules,
        )
        assert data.error is None
        assert data.metrics["recast_count"] == 1

    def test_expiry_metadata_recorded(self):
        """metadata['expiry_checked'] reflects whether recast_rules_df was provided."""
        data_with    = _run(
            vulns_rows=[{"state": "OPEN", "plugin_id": 100001}],
            rules_rows=[{"rule_id": _uuid(1)}],
        )
        data_without = _run(
            vulns_rows=[{"state": "OPEN", "plugin_id": 100001}],
        )
        assert data_with.metadata["expiry_checked"]    is True
        assert data_without.metadata["expiry_checked"] is False


# ===========================================================================
# 4. FINDING-COUNT HEADLINE / RULE COUNTS IN ANALYST TAB (Pitfall 6c — RPT-04)
# ===========================================================================

class TestFindingVsRuleCount:
    def test_headline_metric_is_finding_count(self):
        """
        RPT-04 / Pitfall 6c: headline metrics (accepted_count, recast_count)
        are FINDING counts, not rule counts.
        """
        # 3 findings linked to 1 rule → headline = 3, not 1
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001, "recast_rule_uuid": _uuid(1)},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100002, "recast_rule_uuid": _uuid(1)},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100003, "recast_rule_uuid": _uuid(1)},
            ],
            rules_rows=[
                {"rule_id": _uuid(1), "action": "ACCEPT"},
            ],
        )
        # 3 findings (not 1 rule) drive the headline
        assert data.metrics["accepted_count"] == 3

    def test_rule_detail_in_analyst_rows_only(self):
        """
        Pitfall 6c: rule-level detail (rule_id, action, etc.) lives ONLY in
        analyst_rows — NOT in the headline metrics.
        """
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001, "recast_rule_uuid": _uuid(1)},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100002, "recast_rule_uuid": _uuid(1)},
            ],
            rules_rows=[
                {"rule_id": _uuid(1), "action": "ACCEPT"},
            ],
        )
        # Headline = finding count
        assert data.metrics["accepted_count"] == 2
        # Rule detail in analyst tab
        rule_detail_df = data.analyst_rows[0][1]
        assert "rule_id"        in rule_detail_df.columns
        assert "finding_count"  in rule_detail_df.columns
        # Rule finding_count in analyst tab matches headline
        assert rule_detail_df["finding_count"].sum() == 2

    def test_analyst_tab_has_rule_detail_columns(self):
        """Rule Detail analyst tab contains expected columns (Pitfall 6c)."""
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001, "recast_rule_uuid": _uuid(1)},
            ],
            rules_rows=[
                {"rule_id": _uuid(1), "action": "ACCEPT", "plugin_id": None},
            ],
        )
        rule_df = data.analyst_rows[0][1]
        expected_cols = {"rule_id", "action", "plugin_id", "original_severity",
                         "new_severity", "expires_at", "created_at",
                         "finding_count", "filter_summary"}
        assert expected_cols.issubset(set(rule_df.columns))

    def test_analyst_tab_uses_summarize_filter_not_inline_parse(self):
        """
        Pitfall 6c: filter_summary column uses _summarize_filter, not an inline
        parse. Verify filter_summary is a string (not a dict).
        """
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                 "plugin_id": 100001, "recast_rule_uuid": _uuid(1)},
            ],
            rules_rows=[
                {
                    "rule_id": _uuid(1),
                    "action":  "ACCEPT",
                    "filter":  {"property": "definition.id", "operator": "eq", "value": "57582"},
                },
            ],
        )
        rule_df = data.analyst_rows[0][1]
        # filter_summary must be a non-empty string
        assert rule_df["filter_summary"].dtype == object
        assert len(rule_df) > 0
        filter_val = rule_df.iloc[0]["filter_summary"]
        assert isinstance(filter_val, str)
        assert len(filter_val) > 0

    def test_analyst_tab_accepts_none_plugin_id(self):
        """Rule with plugin_id=None (nullable int) must not crash analyst tab."""
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                 "plugin_id": 100001, "recast_rule_uuid": _uuid(1)},
            ],
            rules_rows=[
                {"rule_id": _uuid(1), "action": "ACCEPT", "plugin_id": None},
            ],
        )
        assert data.error is None
        rule_df = data.analyst_rows[0][1]
        # plugin_id None accepted without error
        assert len(rule_df) == 1


# ===========================================================================
# 5. MoM DELTA COLD-START (QUAL-01 — Pitfall 5)
# ===========================================================================

class TestMomDeltaColdStart:
    def test_no_delta_when_trend_snapshots_absent(self):
        """
        QUAL-01: when trend_snapshots is absent, accepted_delta and
        recast_delta are None — no '▲ 0%' or NaN% emitted.
        """
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001},
        ])
        # delta absent → None (not a string)
        assert data.metrics["accepted_delta"] is None
        assert data.metrics["recast_delta"]   is None

    def test_no_delta_when_insufficient_data_true(self):
        """
        QUAL-01: trend_snapshots with insufficient_data=True → omit delta.
        """
        trend = {"insufficient_data": True, "snapshots": []}
        data = _run(
            vulns_rows=[{"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001}],
            trend=trend,
        )
        assert data.metrics["accepted_delta"] is None
        assert data.metrics["recast_delta"]   is None

    def test_no_delta_when_prior_month_absent(self):
        """
        QUAL-01: trend_snapshots has snapshots but no prior completed month
        (all snapshots are current-month or future) → omit delta arrow.
        """
        trend = {
            "insufficient_data": False,
            "snapshots": [
                {"month": "2026-06", "accepted_count": 5, "recast_count": 2},
            ],
        }
        data = _run(
            vulns_rows=[{"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001}],
            trend=trend,
        )
        # 2026-06 IS the current month for report_date 2026-06-11 → no prior month
        assert data.metrics["accepted_delta"] is None
        assert data.metrics["recast_delta"]   is None

    def test_delta_arrow_present_when_prior_month_available(self):
        """
        When a prior completed month is present in trend_snapshots, delta arrow
        is computed and is a non-None string.
        """
        trend = {
            "insufficient_data": False,
            "snapshots": [
                {"month": "2026-05", "accepted_count": 3, "recast_count": 1},
            ],
        }
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100002},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100003},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100004},
                {"severity_modification_type": "RECASTED", "state": "OPEN", "plugin_id": 100005},
            ],
            trend=trend,
        )
        # curr=4 vs prev=3 → ▲ +1
        assert data.metrics["accepted_delta"] == "▲ +1"
        # curr=1 vs prev=1 → → 0
        assert data.metrics["recast_delta"]   == "→ 0"

    def test_no_nan_string_in_any_rendered_output(self):
        """
        QUAL-01: NaN% must never appear in PDF, email panel, or driver narrative.
        """
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001},
        ])
        mod = AcceptedRecastModule()
        cfg = _config()
        pdf   = mod.render_pdf_section(data, cfg)
        email = mod.render_email_panel(data, cfg)
        strip = mod.render_rag_strip_entry(data, cfg)

        assert "NaN" not in pdf
        assert "NaN" not in email
        assert "NaN" not in str(strip)
        assert "NaN" not in (data.driver_narrative or "")

    def test_no_delta_arrow_zero_string_when_prior_absent(self):
        """
        QUAL-01 / Pitfall 5: '▲ 0%' or '▲ 0' must not appear when prior month
        is absent — the delta must be fully omitted.
        """
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001},
        ])
        mod = AcceptedRecastModule()
        cfg = _config()
        pdf   = mod.render_pdf_section(data, cfg)
        email = mod.render_email_panel(data, cfg)

        assert "▲ 0" not in pdf
        assert "▲ 0" not in email


# ===========================================================================
# 6. ZERO-EXCEPTION SAFE RENDER (QUAL-03)
# ===========================================================================

class TestZeroExceptionSafeRender:
    def test_zero_exception_input_green_rag(self):
        """
        QUAL-03: zero exceptions → green RAG "0 managed exceptions in scope."
        error=None.
        """
        data = _run([
            {"severity_modification_type": "NONE", "state": "OPEN", "plugin_id": 100001},
            {"severity_modification_type": "",     "state": "OPEN", "plugin_id": 100002},
        ])
        assert data.error is None
        assert data.metrics["accepted_count"] == 0
        assert data.metrics["recast_count"]   == 0
        assert data.metrics["rag_status"]     == "green"
        assert data.rag_strip.get("rag_color") == "#388e3c"

    def test_zero_exception_driver_narrative(self):
        """Zero exceptions → driver_narrative contains '0 managed exceptions'."""
        data = _run([
            {"severity_modification_type": "NONE", "state": "OPEN", "plugin_id": 100001},
        ])
        assert "0 managed exceptions" in data.driver_narrative

    def test_empty_vulns_df_returns_safe_zero_result(self):
        """
        QUAL-03: empty vulns_df → zero-exception result, error=None,
        all four channels render without crash.
        """
        mod       = AcceptedRecastModule()
        vulns_df  = _make_vulns([])  # zero rows but with columns
        assets_df = _make_assets([])
        data = mod.compute(vulns_df, assets_df, _REPORT_DATE, _config())

        assert data.error is None
        assert data.metrics["accepted_count"] == 0
        assert data.metrics["recast_count"]   == 0
        assert data.rag_strip  # strip populated

    def test_truly_empty_df_returns_safe_result(self):
        """
        QUAL-03: pd.DataFrame() (no columns) → safe result, error=None.
        """
        mod       = AcceptedRecastModule()
        vulns_df  = pd.DataFrame()
        assets_df = pd.DataFrame()
        data = mod.compute(vulns_df, assets_df, _REPORT_DATE, _config())
        # Must not crash; error is None (zero-exception is a valid state)
        assert data.error is None
        assert data.rag_strip

    def test_nonempty_df_missing_smt_column_returns_safe_result(self):
        """
        WR-04: a NON-empty vulns_df that lacks the severity_modification_type
        column must guard into the zero-exception result, not KeyError into the
        outer error handler. The classification step requires that column.
        """
        mod       = AcceptedRecastModule()
        vulns_df  = pd.DataFrame({
            "asset_uuid": [_uuid(1), _uuid(2)],
            "state":      ["OPEN", "OPEN"],
            # severity_modification_type intentionally absent
        })
        assets_df = _make_assets([])
        data = mod.compute(vulns_df, assets_df, _REPORT_DATE, _config())

        assert data.error is None
        assert data.metrics["accepted_count"] == 0
        assert data.metrics["recast_count"]   == 0
        assert data.rag_strip


# ===========================================================================
# 7. RATE DENOMINATOR
# ===========================================================================

class TestRateDenominator:
    def test_denominator_is_open_plus_reopened(self):
        """
        Rate denominator = total OPEN + REOPENED findings, not total rows.
        FIXED rows excluded.
        """
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "OPEN",     "plugin_id": 100001},
            {"severity_modification_type": "NONE",     "state": "OPEN",     "plugin_id": 100002},
            {"severity_modification_type": "NONE",     "state": "REOPENED", "plugin_id": 100003},
            {"severity_modification_type": "NONE",     "state": "FIXED",    "plugin_id": 100004},
        ])
        # total_open = 3 (OPEN + REOPENED, not FIXED)
        assert data.metrics["total_open"]      == 3
        # exception_rate = 1 accepted / 3 open * 100 ≈ 33.3%
        assert data.metrics["exception_rate"] == pytest.approx(33.33, abs=0.1)

    def test_exception_rate_none_when_total_open_zero(self):
        """exception_rate is None when total_open == 0 (no division by zero)."""
        data = _run([
            {"severity_modification_type": "FIXED", "state": "FIXED", "plugin_id": 100001},
        ])
        assert data.metrics["exception_rate"] is None


# ===========================================================================
# 8. OWNER CUT
# ===========================================================================

class TestOwnerCut:
    def test_accepted_and_recasted_owner_counts_separate(self):
        """owner_accepted and owner_recasted are separate dicts in metrics."""
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                 "plugin_id": 100001, "asset_uuid": _uuid(1)},
                {"severity_modification_type": "RECASTED",  "state": "OPEN",
                 "plugin_id": 100002, "asset_uuid": _uuid(1)},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
            ],
        )
        assert "owner_accepted" in data.metrics
        assert "owner_recasted" in data.metrics
        assert data.metrics["owner_accepted"].get("Engineering", 0) == 1
        assert data.metrics["owner_recasted"].get("Engineering", 0) == 1

    def test_unassigned_when_no_matching_asset(self):
        """Findings with no matching asset uuid → 'Unassigned' owner."""
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                 "plugin_id": 100001, "asset_uuid": _uuid(9)},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
            ],
        )
        assert data.metrics["owner_accepted"].get("Unassigned", 0) == 1


# ===========================================================================
# 9. RAG STATUS
# ===========================================================================

class TestRagStatus:
    def test_green_below_green_threshold(self):
        """Exception rate < 5% → green."""
        # 1 accepted out of 21 open = 4.76% < 5% → green
        rows = [{"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001}]
        rows += [{"severity_modification_type": "NONE",     "state": "OPEN", "plugin_id": 100000 + i}
                 for i in range(2, 22)]
        data = _run(rows)
        assert data.metrics["rag_status"] == "green"

    def test_red_above_yellow_threshold(self):
        """Exception rate > 15% → red."""
        # 2 accepted out of 10 total open = 20% > 15% → red
        rows = [{"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100000 + i}
                for i in range(1, 3)]
        rows += [{"severity_modification_type": "NONE",     "state": "OPEN", "plugin_id": 100010 + i}
                 for i in range(1, 9)]
        data = _run(rows)
        assert data.metrics["rag_status"] == "red"

    def test_custom_thresholds_via_options(self):
        """green_exception_rate / yellow_exception_rate override via module_options."""
        # 1 accepted out of 4 open = 25% — with yellow raised to 30% → yellow not red
        data = _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN", "plugin_id": 100001},
                {"severity_modification_type": "NONE",     "state": "OPEN", "plugin_id": 100002},
                {"severity_modification_type": "NONE",     "state": "OPEN", "plugin_id": 100003},
                {"severity_modification_type": "NONE",     "state": "OPEN", "plugin_id": 100004},
            ],
            green_exception_rate=10.0,
            yellow_exception_rate=30.0,
        )
        assert data.metrics["rag_status"] == "yellow"

    def test_no_data_rag_when_rate_none(self):
        """exception_rate=None (total_open==0) → rag_status 'no_data', gray strip."""
        data = _run([
            {"severity_modification_type": "ACCEPTED", "state": "FIXED", "plugin_id": 100001},
        ])
        # accepted_count > 0 but total_open=0 → exception_rate=None → rag 'no_data'
        assert data.metrics["exception_rate"] is None
        # RAG = 'no_data' when rate unavailable
        rag = data.metrics.get("rag_status")
        assert rag == "no_data"


# ===========================================================================
# 10. EMPTY-DATA GUARD — FOUR-CHANNEL (QUAL-03)
# ===========================================================================

class TestFourChannelEmptyData:
    def _empty_data(self) -> ModuleData:
        mod      = AcceptedRecastModule()
        vulns_df = pd.DataFrame()
        assets_df = pd.DataFrame()
        return mod.compute(vulns_df, assets_df, _REPORT_DATE, _config())

    def test_render_pdf_section_returns_str(self):
        data = self._empty_data()
        result = AcceptedRecastModule().render_pdf_section(data, _config())
        assert isinstance(result, str)

    def test_render_excel_tabs_returns_list(self):
        import openpyxl
        data     = self._empty_data()
        workbook = openpyxl.Workbook()
        result   = AcceptedRecastModule().render_excel_tabs(data, workbook, _config())
        assert isinstance(result, list)

    def test_render_email_panel_returns_str(self):
        data   = self._empty_data()
        result = AcceptedRecastModule().render_email_panel(data, _config())
        assert isinstance(result, str)

    def test_render_analyst_tabs_returns_list(self):
        data   = self._empty_data()
        result = AcceptedRecastModule().render_analyst_tabs(data, _config())
        assert isinstance(result, list)

    def test_render_rag_strip_returns_dict(self):
        data   = self._empty_data()
        result = AcceptedRecastModule().render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert all(k in result for k in ("label", "headline_value", "rag_color", "rag_label"))


# ===========================================================================
# 11. FOUR-CHANNEL RENDER METHODS — VALID DATA
# ===========================================================================

class TestRenderMethodsValidData:
    def _valid_data(self) -> ModuleData:
        return _run(
            vulns_rows=[
                {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                 "plugin_id": 100001, "asset_uuid": _uuid(1), "recast_rule_uuid": _uuid(1)},
                {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                 "plugin_id": 100002, "asset_uuid": _uuid(1), "recast_rule_uuid": _uuid(1)},
                {"severity_modification_type": "RECASTED",  "state": "OPEN",
                 "plugin_id": 100003, "asset_uuid": _uuid(2), "recast_rule_uuid": _uuid(2)},
                {"severity_modification_type": "NONE",     "state": "OPEN",
                 "plugin_id": 100004, "asset_uuid": _uuid(1)},
            ],
            asset_rows=[
                {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
            ],
            rules_rows=[
                {"rule_id": _uuid(1), "action": "ACCEPT"},
                {"rule_id": _uuid(2), "action": "RECAST"},
            ],
        )

    def test_pdf_section_non_empty(self):
        data   = self._valid_data()
        result = AcceptedRecastModule().render_pdf_section(data, _config())
        assert isinstance(result, str)
        assert len(result) > 0

    def test_pdf_section_contains_accepted_and_recasted(self):
        """PDF section distinguishes Accepted vs Recasted (different operational meaning)."""
        data   = self._valid_data()
        result = AcceptedRecastModule().render_pdf_section(data, _config())
        assert "Accepted" in result
        assert "Recasted" in result

    def test_excel_tab_returned(self):
        import openpyxl
        data     = self._valid_data()
        workbook = openpyxl.Workbook()
        result   = AcceptedRecastModule().render_excel_tabs(data, workbook, _config())
        assert isinstance(result, list)
        assert len(result) == 1

    def test_email_panel_non_empty(self):
        data   = self._valid_data()
        result = AcceptedRecastModule().render_email_panel(data, _config())
        assert isinstance(result, str)
        assert len(result) > 0

    def test_email_panel_contains_display_name(self):
        data   = self._valid_data()
        result = AcceptedRecastModule().render_email_panel(data, _config())
        assert "Accepted" in result

    def test_email_panel_distinguishes_accepted_recasted(self):
        """Email panel shows Accepted and Recasted as separate values (Pitfall 6b)."""
        data   = self._valid_data()
        result = AcceptedRecastModule().render_email_panel(data, _config())
        assert "Accepted" in result
        assert "Recasted" in result

    def test_analyst_tabs_contain_rule_detail_and_by_owner(self):
        data   = self._valid_data()
        result = AcceptedRecastModule().render_analyst_tabs(data, _config())
        assert len(result) == 2
        tab_names = [t[0] for t in result]
        assert "Rule Detail" in tab_names
        assert "By Owner"    in tab_names

    def test_rag_strip_populated(self):
        data   = self._valid_data()
        result = AcceptedRecastModule().render_rag_strip_entry(data, _config())
        assert isinstance(result, dict)
        assert all(k in result for k in ("label", "headline_value", "rag_color", "rag_label"))
        assert result["headline_value"] != "—"  # not a no-data cell


# ===========================================================================
# 12. COW STRICT MODE — NO CHAINED ASSIGNMENT WARNINGS
# ===========================================================================

class TestCoWStrictMode:
    def test_no_future_warning_normal_compute(self):
        """No FutureWarning raised during compute() with valid data."""
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=FutureWarning)
            _run(
                vulns_rows=[
                    {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                     "plugin_id": 100001, "asset_uuid": _uuid(1), "recast_rule_uuid": _uuid(1)},
                    {"severity_modification_type": "RECASTED",  "state": "OPEN",
                     "plugin_id": 100002, "asset_uuid": _uuid(2), "recast_rule_uuid": _uuid(2)},
                    {"severity_modification_type": "NONE",      "state": "OPEN",
                     "plugin_id": 100003, "asset_uuid": _uuid(1)},
                ],
                asset_rows=[
                    {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
                    {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
                ],
                rules_rows=[
                    {"rule_id": _uuid(1), "action": "ACCEPT"},
                    {"rule_id": _uuid(2), "action": "RECAST"},
                ],
            )

    def test_no_future_warning_empty_input(self):
        """No FutureWarning on empty vulns_df."""
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=FutureWarning)
            mod       = AcceptedRecastModule()
            vulns_df  = pd.DataFrame()
            assets_df = pd.DataFrame()
            mod.compute(vulns_df, assets_df, _REPORT_DATE, _config())

    def test_no_future_warning_zero_exceptions(self):
        """No FutureWarning when all rows have NONE modification type."""
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=FutureWarning)
            _run([
                {"severity_modification_type": "NONE", "state": "OPEN", "plugin_id": 100001},
                {"severity_modification_type": "",     "state": "OPEN", "plugin_id": 100002},
            ])

    def test_no_future_warning_with_expiry_check(self):
        """No FutureWarning when expiry cross-check runs with rules."""
        with warnings.catch_warnings():
            warnings.filterwarnings("error", category=FutureWarning)
            _run(
                vulns_rows=[
                    {"severity_modification_type": "ACCEPTED", "state": "OPEN",
                     "plugin_id": 100001, "recast_rule_uuid": _uuid(1)},
                ],
                rules_rows=[
                    {"rule_id": _uuid(1), "action": "ACCEPT", "expires_at": "2026-01-01T00:00:00Z"},
                ],
            )
