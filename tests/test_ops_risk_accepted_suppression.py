"""
tests/test_ops_risk_accepted_suppression.py — _suppress_risk_accepted() behavior
suite for reports/ops_remediation.py (quick-260813-jaz).

Verifies:
  - ACCEPTED findings are suppressed from the actionable worklist
  - RECASTED findings are KEPT (D-01 — a recast is still open work Operations
    owns, only the severity tier changed; this deliberately diverges from
    the board's both-types risk-managed exclusion convention, i.e. it does
    NOT reuse the board's shared exclusion helper)
  - Expired acceptances (recast rule's expires_at in the past) return to the
    actionable population (D-02)
  - Unexpired / never-expiring acceptances stay suppressed
  - Graceful degradation when recast_rules_df or required columns are
    missing (Hard Rule 6) — never raises, always logs a warning
  - Behavior 8: _extract_risk_modifications (Tab 5) keeps reading the FULL
    unfiltered population, and run_report()'s source-level wiring routes
    the suppressed frame to exactly the actionable-metric call sites.

All fixtures use synthetic-only data (Hard Rule 2 / CLAUDE.md D-04-08):
  - asset_uuid  : "00000000-0000-0000-0000-00000000000N"
  - rule_id     : "11111111-0000-0000-0000-00000000000N"
  - plugin_id   : 100001, 100002, ...
  - plugin_name : "Synthetic Plugin A", "Synthetic Plugin B", ...
No real hostnames, IPs, CVE IDs, plugin names, or Tenable UUIDs.

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import inspect
import logging
import warnings
from datetime import datetime, timezone

import pandas as pd
import pytest

# Enforce pandas CoW strict mode BEFORE importing report modules.
pd.options.mode.copy_on_write = True

import reports.ops_remediation as ops_remediation
from reports.ops_remediation import _suppress_risk_accepted

_ASSET_PREFIX = "00000000-0000-0000-0000-00000000000"
_RULE_PREFIX = "11111111-0000-0000-0000-00000000000"
_AS_OF = datetime(2026, 8, 13, tzinfo=timezone.utc)
_PAST = "2026-01-01T00:00:00Z"
_FUTURE = "2027-01-01T00:00:00Z"


def _findings(rows: list[dict]) -> pd.DataFrame:
    """Build a synthetic findings frame with the columns _suppress_risk_accepted needs."""
    base_cols = [
        "asset_uuid", "plugin_id", "plugin_name", "severity",
        "severity_modification_type", "recast_rule_uuid", "state", "first_found",
    ]
    df = pd.DataFrame(rows)
    for col in base_cols:
        if col not in df.columns:
            df[col] = None
    return df


def _rules(rows: list[dict]) -> pd.DataFrame:
    """Build a synthetic recast-rules frame with rule_id / expires_at."""
    return pd.DataFrame(rows)


def _call_no_cow_warning(func, *args, **kwargs):
    """Call *func* and assert it emits no CoW / ChainedAssignment warning
    originating from reports/ops_remediation.py."""
    ops_path = inspect.getsourcefile(ops_remediation)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = func(*args, **kwargs)
    cow_warnings = [w for w in caught if getattr(w, "filename", "") == ops_path]
    assert not cow_warnings, f"Unexpected warning(s) from ops_remediation: {cow_warnings}"
    return result


# ---------------------------------------------------------------------------
# Behaviors 1-2: ACCEPTED dropped, RECASTED kept (D-01)
# ---------------------------------------------------------------------------


class TestAcceptedVsRecasted:
    def test_accepted_rows_dropped(self):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED", "recast_rule_uuid": None,
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        result = _call_no_cow_warning(_suppress_risk_accepted, df, None, _AS_OF)
        assert result.empty

    def test_recasted_rows_kept(self):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "High",
             "severity_modification_type": "RECASTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        result = _call_no_cow_warning(_suppress_risk_accepted, df, None, _AS_OF)
        assert len(result) == 1
        assert result.iloc[0]["severity_modification_type"] == "RECASTED"

    def test_mixed_accepted_and_recasted(self):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED", "recast_rule_uuid": None,
             "state": "OPEN", "first_found": "2026-01-01"},
            {"asset_uuid": _ASSET_PREFIX + "2", "plugin_id": 100002,
             "plugin_name": "Synthetic Plugin B", "severity": "High",
             "severity_modification_type": "RECASTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        result = _suppress_risk_accepted(df, None, _AS_OF)
        assert len(result) == 1
        assert result.iloc[0]["plugin_id"] == 100002


# ---------------------------------------------------------------------------
# Behaviors 3-5: expiry carve-out (D-02)
# ---------------------------------------------------------------------------


class TestExpiryCarveOut:
    def test_accepted_with_expired_rule_is_kept(self):
        vulns = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        rules = _rules([{"rule_id": _RULE_PREFIX + "1", "expires_at": _PAST}])
        result = _suppress_risk_accepted(vulns, rules, _AS_OF)
        assert len(result) == 1

    def test_accepted_with_future_expiry_is_dropped(self):
        vulns = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        rules = _rules([{"rule_id": _RULE_PREFIX + "1", "expires_at": _FUTURE}])
        result = _suppress_risk_accepted(vulns, rules, _AS_OF)
        assert result.empty

    @pytest.mark.parametrize("expires_at", [None, pd.NaT, "", "Never", "not-a-date"])
    def test_accepted_with_non_expiring_rule_stays_suppressed(self, expires_at):
        vulns = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        rules = _rules([{"rule_id": _RULE_PREFIX + "1", "expires_at": expires_at}])
        result = _suppress_risk_accepted(vulns, rules, _AS_OF)
        assert result.empty


# ---------------------------------------------------------------------------
# Behavior 6: empty / missing-column guards on the findings frame
# ---------------------------------------------------------------------------


class TestFindingsFrameGuards:
    def test_empty_frame_returned_unchanged(self):
        df = pd.DataFrame(columns=[
            "asset_uuid", "plugin_id", "severity_modification_type", "recast_rule_uuid",
        ])
        result = _suppress_risk_accepted(df, None, _AS_OF)
        assert result is df

    def test_missing_modification_type_column_returned_unchanged(self):
        df = pd.DataFrame([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001},
        ])
        result = _suppress_risk_accepted(df, None, _AS_OF)
        assert result is df

    def test_missing_recast_rule_uuid_suppresses_all_accepted_and_warns(self, caplog):
        df = pd.DataFrame([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "severity_modification_type": "ACCEPTED"},
            {"asset_uuid": _ASSET_PREFIX + "2", "plugin_id": 100002,
             "severity_modification_type": "RECASTED"},
        ])
        rules = _rules([{"rule_id": _RULE_PREFIX + "1", "expires_at": _PAST}])
        with caplog.at_level(logging.WARNING, logger="reports.ops_remediation"):
            result = _suppress_risk_accepted(df, rules, _AS_OF)
        assert len(result) == 1
        assert result.iloc[0]["severity_modification_type"] == "RECASTED"
        assert any("recast_rule_uuid" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Behavior 7: recast_rules_df None / empty / malformed
# ---------------------------------------------------------------------------


class TestRecastRulesDegradation:
    def test_none_recast_rules_suppresses_all_accepted_and_warns(self, caplog):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        with caplog.at_level(logging.WARNING, logger="reports.ops_remediation"):
            result = _suppress_risk_accepted(df, None, _AS_OF)
        assert result.empty
        assert any("Recast rules unavailable" in rec.message for rec in caplog.records)

    def test_empty_recast_rules_suppresses_all_accepted_and_warns(self, caplog):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        with caplog.at_level(logging.WARNING, logger="reports.ops_remediation"):
            result = _suppress_risk_accepted(df, pd.DataFrame(), _AS_OF)
        assert result.empty
        assert any("Recast rules unavailable" in rec.message for rec in caplog.records)

    def test_malformed_recast_rules_missing_expires_at_suppresses_all_and_warns(self, caplog):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        malformed_rules = pd.DataFrame([{"rule_id": _RULE_PREFIX + "1"}])  # no expires_at
        with caplog.at_level(logging.WARNING, logger="reports.ops_remediation"):
            result = _suppress_risk_accepted(df, malformed_rules, _AS_OF)
        assert result.empty
        assert any("Recast rules unavailable" in rec.message for rec in caplog.records)

    def test_malformed_recast_rules_missing_rule_id_suppresses_all_and_warns(self, caplog):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": "ACCEPTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        malformed_rules = pd.DataFrame([{"expires_at": _PAST}])  # no rule_id
        with caplog.at_level(logging.WARNING, logger="reports.ops_remediation"):
            result = _suppress_risk_accepted(df, malformed_rules, _AS_OF)
        assert result.empty
        assert any("Recast rules unavailable" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Plus: other modification values kept, case-insensitivity, fresh .copy()
# ---------------------------------------------------------------------------


class TestAdditionalGuarantees:
    @pytest.mark.parametrize("mod_value", ["NONE", "", None, "SOMETHING_ELSE"])
    def test_other_modification_values_are_kept(self, mod_value):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": mod_value, "recast_rule_uuid": None,
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        result = _suppress_risk_accepted(df, None, _AS_OF)
        assert len(result) == 1

    @pytest.mark.parametrize("mod_value", ["accepted", "Accepted", "ACCEPTED"])
    def test_case_insensitive_accepted_matching(self, mod_value):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "Medium",
             "severity_modification_type": mod_value, "recast_rule_uuid": None,
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        result = _suppress_risk_accepted(df, None, _AS_OF)
        assert result.empty

    def test_returned_frame_is_fresh_copy(self):
        df = _findings([
            {"asset_uuid": _ASSET_PREFIX + "1", "plugin_id": 100001,
             "plugin_name": "Synthetic Plugin A", "severity": "High",
             "severity_modification_type": "RECASTED",
             "recast_rule_uuid": _RULE_PREFIX + "1",
             "state": "OPEN", "first_found": "2026-01-01"},
            {"asset_uuid": _ASSET_PREFIX + "2", "plugin_id": 100002,
             "plugin_name": "Synthetic Plugin B", "severity": "Medium",
             "severity_modification_type": "ACCEPTED", "recast_rule_uuid": None,
             "state": "OPEN", "first_found": "2026-01-01"},
        ])
        result = _suppress_risk_accepted(df, None, _AS_OF)
        assert result is not df
        result = result.assign(severity="MUTATED")
        assert df.iloc[0]["severity"] == "High"
