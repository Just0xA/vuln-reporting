"""
tests/content/test_values.py — Layer 2 exact-value assertions on known fixtures.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from config import vpr_to_severity
from tests.fixtures.builders import AS_OF, three_overdue_crit
from tests.fixtures.generator import make_scenario
from utils.sla_calculator import apply_sla_to_df, get_sla_status

pytestmark = pytest.mark.content


def test_three_overdue_criticals_counts_exactly_three():
    df = apply_sla_to_df(three_overdue_crit(), as_of=AS_OF)
    assert int(df["is_overdue"].sum()) == 3


def test_null_vpr_falls_back_to_native_severity():
    """vpr_to_severity (config.py:79): None score → fallback; real score → VPR band."""
    assert vpr_to_severity(None, fallback="high") == "high"
    assert vpr_to_severity(9.5, fallback="low") == "critical"


def test_overdue_boundary_is_strict_greater_than():
    """days_open == sla_days is Within SLA; days_open > sla_days is Overdue."""
    at_limit = get_sla_status("critical", AS_OF - timedelta(days=15), False, as_of=AS_OF)
    over = get_sla_status("critical", AS_OF - timedelta(days=16), False, as_of=AS_OF)
    assert at_limit["status"] == "Within SLA"
    assert at_limit["is_overdue"] is False
    assert over["status"] == "Overdue"
    assert over["is_overdue"] is True


def test_generator_overdue_matches_expected():
    vulns, _, expected = make_scenario(seed=42, as_of=AS_OF)
    df = apply_sla_to_df(vulns, as_of=AS_OF)
    assert int(df["is_overdue"].sum()) == expected["overdue_count"]


def test_remediated_is_never_overdue():
    res = get_sla_status("critical", AS_OF - timedelta(days=99), True, as_of=AS_OF)
    assert res["status"] == "Remediated"
    assert res["is_overdue"] is False
