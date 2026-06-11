"""
tests/test_composed_report_kwargs_gates.py — Gate-forwarding + no-regression tests.

Covers SC#3 and SC#4 from the Phase 14 ROADMAP:

  SC#3: existing composed-report groups are unaffected by the new gates
        (frozenset .intersection() short-circuits for non-listed modules).
  SC#4: trend_snapshots and recast_rules_df kwargs reach compute() via the
        **self._kwargs fan-out when the module ID is in the frozensets.

Tests:
  - test_frozensets_seeded_with_stub_only (D-17)
  - test_run_report_signature_unchanged (D-15)
  - test_stub_compute_receives_both_kwargs (SC#4 unit-level)
  - test_stub_compute_missing_kwarg_failsoft (fail-soft contract)
  - test_gate_intersection_logic (SC#3 no-regression mechanism)

Synthetic data only (QUAL-05): no real hostnames, IPs, plugin names,
or asset-level fields in any fixture.

Run: pytest tests/test_composed_report_kwargs_gates.py -x -q
"""
from __future__ import annotations

import inspect
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

# Enable pandas CoW strict mode to catch chained-assignment regressions.
pd.options.mode.copy_on_write = True

# Make the project root importable.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Importing composed_report triggers registry.discover() transitively.
import reports.composed_report as _cr  # noqa: E402
from reports.composed_report import (  # noqa: E402
    _MODULES_NEEDING_TREND_SNAPSHOTS,
    _MODULES_NEEDING_RECAST_RULES,
    run_report,
)
from reports.modules.sc4_kwargs_stub_module import Sc4KwargsStubModule  # noqa: E402
from reports.modules.base import ModuleConfig  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_REPORT_DATE = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

_FAKE_TREND_SNAPSHOTS = {
    "snapshots": [
        {"month": "2026-04", "critical": 10, "high": 20, "medium": 30, "low": 5},
        {"month": "2026-05", "critical": 8,  "high": 18, "medium": 28, "low": 4},
    ],
    "insufficient_data": False,
}

_FAKE_RECAST_RULES_DF = pd.DataFrame({
    "rule_uuid":       ["aaaaaaaa-0000-0000-0000-000000000001",
                        "aaaaaaaa-0000-0000-0000-000000000002"],
    "plugin_id":       [12345, 67890],
    "original_sev":    ["critical", "high"],
    "new_sev":         ["high", "medium"],
    "expires_at":      [None, None],
})

_EMPTY_VULNS_DF = pd.DataFrame({
    "asset_uuid": pd.Series([], dtype="string"),
    "severity":   pd.Series([], dtype="string"),
})

_EMPTY_ASSETS_DF = pd.DataFrame({
    "asset_uuid": pd.Series([], dtype="string"),
})


def _make_module_config() -> ModuleConfig:
    return ModuleConfig(module_id="sc4_kwargs_stub")


# ---------------------------------------------------------------------------
# SC#3 / D-17: frozenset seeding
# ---------------------------------------------------------------------------

def test_frozensets_seeded_with_stub_only():
    """D-17: both frozensets contain exactly the SC#4 stub ID and nothing else."""
    assert _MODULES_NEEDING_TREND_SNAPSHOTS == frozenset({"sc4_kwargs_stub"}), (
        "_MODULES_NEEDING_TREND_SNAPSHOTS must be seeded with 'sc4_kwargs_stub' only (D-17)"
    )
    assert _MODULES_NEEDING_RECAST_RULES == frozenset({"sc4_kwargs_stub"}), (
        "_MODULES_NEEDING_RECAST_RULES must be seeded with 'sc4_kwargs_stub' only (D-17)"
    )


# ---------------------------------------------------------------------------
# D-15: run_report() signature unchanged
# ---------------------------------------------------------------------------

def test_run_report_signature_unchanged():
    """D-15: run_report() must not acquire trend_snapshots or recast_rules_df parameters."""
    sig = inspect.signature(run_report)
    assert "trend_snapshots" not in sig.parameters, (
        "run_report() must not expose trend_snapshots as a parameter (D-15)"
    )
    assert "recast_rules_df" not in sig.parameters, (
        "run_report() must not expose recast_rules_df as a parameter (D-15)"
    )
    # Confirm the existing required parameters are still present (no regression).
    assert "tio" in sig.parameters
    assert "run_id" in sig.parameters
    assert "modules" in sig.parameters


# ---------------------------------------------------------------------------
# SC#4: stub compute() receives both kwargs
# ---------------------------------------------------------------------------

def test_stub_compute_receives_both_kwargs():
    """SC#4: compute() returns a non-error ModuleData when both kwargs are present."""
    stub = Sc4KwargsStubModule()
    config = _make_module_config()

    result = stub.compute(
        vulns_df    = _EMPTY_VULNS_DF,
        assets_df   = _EMPTY_ASSETS_DF,
        report_date = _REPORT_DATE,
        config      = config,
        trend_snapshots = _FAKE_TREND_SNAPSHOTS,
        recast_rules_df = _FAKE_RECAST_RULES_DF,
    )

    assert result.error is None, (
        f"ModuleData.error must be None when both kwargs present; got: {result.error}"
    )
    assert result.metrics.get("trend_snapshots_present") is True
    assert result.metrics.get("recast_rules_df_present") is True
    assert result.metrics.get("trend_snapshot_count") == 2, (
        "trend_snapshot_count must equal len(snapshots) == 2"
    )
    assert result.metrics.get("recast_rules_row_count") == 2, (
        "recast_rules_row_count must equal len(recast_rules_df) == 2"
    )


# ---------------------------------------------------------------------------
# Fail-soft: missing kwarg returns _empty_result, does not raise
# ---------------------------------------------------------------------------

def test_stub_compute_missing_trend_snapshots_failsoft():
    """Fail-soft: missing trend_snapshots -> _empty_result, no exception raised."""
    stub = Sc4KwargsStubModule()
    config = _make_module_config()

    result = stub.compute(
        vulns_df    = _EMPTY_VULNS_DF,
        assets_df   = _EMPTY_ASSETS_DF,
        report_date = _REPORT_DATE,
        config      = config,
        # trend_snapshots intentionally omitted
        recast_rules_df = _FAKE_RECAST_RULES_DF,
    )

    assert result.error is not None, (
        "ModuleData.error must be set when trend_snapshots is missing"
    )
    assert "trend_snapshots" in result.error


def test_stub_compute_missing_recast_rules_df_failsoft():
    """Fail-soft: missing recast_rules_df -> _empty_result, no exception raised."""
    stub = Sc4KwargsStubModule()
    config = _make_module_config()

    result = stub.compute(
        vulns_df    = _EMPTY_VULNS_DF,
        assets_df   = _EMPTY_ASSETS_DF,
        report_date = _REPORT_DATE,
        config      = config,
        trend_snapshots = _FAKE_TREND_SNAPSHOTS,
        # recast_rules_df intentionally omitted
    )

    assert result.error is not None, (
        "ModuleData.error must be set when recast_rules_df is missing"
    )
    assert "recast_rules_df" in result.error


def test_stub_compute_missing_both_kwargs_failsoft():
    """Fail-soft: both kwargs missing -> _empty_result, no exception raised."""
    stub = Sc4KwargsStubModule()
    config = _make_module_config()

    result = stub.compute(
        vulns_df    = _EMPTY_VULNS_DF,
        assets_df   = _EMPTY_ASSETS_DF,
        report_date = _REPORT_DATE,
        config      = config,
        # both kwargs intentionally omitted
    )

    assert result.error is not None, (
        "ModuleData.error must be set when both kwargs are missing"
    )


# ---------------------------------------------------------------------------
# SC#3 no-regression: intersection logic gates fetches correctly
# ---------------------------------------------------------------------------

def test_gate_intersection_logic_stub_listed():
    """SC#3: intersection is truthy when sc4_kwargs_stub is in the module list."""
    assert _MODULES_NEEDING_TREND_SNAPSHOTS.intersection(["sc4_kwargs_stub"]), (
        "intersection must be truthy for sc4_kwargs_stub (gates should fire)"
    )
    assert _MODULES_NEEDING_RECAST_RULES.intersection(["sc4_kwargs_stub"]), (
        "intersection must be truthy for sc4_kwargs_stub (gates should fire)"
    )


def test_gate_intersection_logic_other_module_excluded():
    """SC#3: intersection is falsy for a module NOT in the frozensets (no fetch triggered)."""
    assert not _MODULES_NEEDING_TREND_SNAPSHOTS.intersection(["some_other_module"]), (
        "intersection must be falsy for an unlisted module (no trend fetch)"
    )
    assert not _MODULES_NEEDING_RECAST_RULES.intersection(["some_other_module"]), (
        "intersection must be falsy for an unlisted module (no recast fetch)"
    )


def test_gate_intersection_logic_empty_modules():
    """SC#3: empty module list triggers no fetches (existing groups with no stub)."""
    assert not _MODULES_NEEDING_TREND_SNAPSHOTS.intersection([]), (
        "empty module list must yield falsy intersection (no trend fetch)"
    )
    assert not _MODULES_NEEDING_RECAST_RULES.intersection([]), (
        "empty module list must yield falsy intersection (no recast fetch)"
    )
