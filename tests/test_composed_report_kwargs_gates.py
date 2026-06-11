"""
tests/test_composed_report_kwargs_gates.py — Gate-forwarding + no-regression tests.

Covers SC#3 and SC#4 from the Phase 14 ROADMAP:

  SC#3: existing composed-report groups are unaffected by the new gates
        (frozenset .intersection() short-circuits for non-listed modules).
  SC#4: trend_snapshots and recast_rules_df kwargs reach compute() via the
        **self._kwargs fan-out when the module ID is in the frozensets.

Tests:
  - test_frozensets_membership (D-17 + Phase 15 module registration)
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

def test_frozensets_membership():
    """D-17 + Phase 15: the gate frozensets hold the SC#4 stub plus exactly the
    Phase-15 modules that legitimately need each fetch. Current-snapshot modules
    (reopened_vulns, external_dmz) are MoM-free per D-03 and must NOT appear in
    either set."""
    assert _MODULES_NEEDING_TREND_SNAPSHOTS == frozenset(
        {"sc4_kwargs_stub", "new_vs_remediated", "vuln_density", "accepted_recast"}
    ), "_MODULES_NEEDING_TREND_SNAPSHOTS membership drifted (D-17 / Phase 15)"
    assert _MODULES_NEEDING_RECAST_RULES == frozenset(
        {"sc4_kwargs_stub", "accepted_recast"}
    ), "_MODULES_NEEDING_RECAST_RULES membership drifted (D-17 / Phase 15)"
    # D-03 negative guard: current-snapshot modules never trigger a trend fetch.
    assert "reopened_vulns" not in _MODULES_NEEDING_TREND_SNAPSHOTS
    assert "external_dmz" not in _MODULES_NEEDING_TREND_SNAPSHOTS


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


# ---------------------------------------------------------------------------
# WR-02: gate fetch failures must fail soft (not propagate out of run_report)
# ---------------------------------------------------------------------------

def test_gate_fetch_failure_does_not_propagate(monkeypatch, tmp_path):
    """
    WR-02 regression: a raise from read_trend / fetch_recast_rules must degrade
    to "kwarg absent" — run_report() still returns a bundle dict rather than
    letting the exception abort the whole group (fail-soft batch semantics).

    The eager fetchers are stubbed to return empty synthetic frames (no network);
    the two gate fetches are monkeypatched to raise. The sc4_kwargs_stub module
    (in both frozensets) then fail-softs on the absent kwargs via _empty_result.
    """
    # Stub the eager fetchers so no Tenable/network call happens (synthetic only).
    monkeypatch.setattr(_cr, "fetch_all_vulnerabilities",
                        lambda tio, cache_dir: _EMPTY_VULNS_DF.copy())
    monkeypatch.setattr(_cr, "fetch_all_assets",
                        lambda tio, cache_dir: _EMPTY_ASSETS_DF.copy())

    # Make BOTH gate fetches raise at their source-module call sites
    # (run_report imports them lazily from these modules).
    import data.trend_store as _trend_store
    import data.fetchers as _fetchers

    def _boom_trend(*args, **kwargs):
        raise RuntimeError("synthetic trend read failure")

    def _boom_recast(*args, **kwargs):
        raise RuntimeError("synthetic recast fetch failure")

    monkeypatch.setattr(_trend_store, "read_trend", _boom_trend)
    monkeypatch.setattr(_fetchers, "fetch_recast_rules", _boom_recast)

    result = run_report(
        tio          = object(),          # never used — fetchers are stubbed
        run_id       = "2026-06-01",
        modules      = ["sc4_kwargs_stub"],
        generated_at = _REPORT_DATE,
        output_dir   = tmp_path,
        cache_dir    = tmp_path,
    )

    # The bundle must come back as a dict despite both gate fetches raising.
    assert isinstance(result, dict)
    assert "pdf" in result and "excel" in result and "charts" in result
