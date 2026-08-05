"""
tests/test_consumer_audit.py — Consumer-audit gate for fetch_fixed_vulnerabilities.

Plan 18-02, D-18-05 / D-18-06 / D-18-10 gate 1.

Purpose
-------
Widening fetch_fixed_vulnerabilities from the implicit ~30-day Tenable API
default to a configurable 12-month window (config.FIXED_LOOKBACK_DAYS) would
silently change the effective population of every fixed-data consumer that
previously relied on that default.

This suite is the HARD GATE (D-18-06) that proves each result-consuming module
applies its OWN explicit date-window filter at compute() time, so the module's
output is IDENTICAL whether the fetcher returns a narrow 30-day frame or a wide
12-month frame.  Consumers that aggregate ALL returned rows would produce
different output on the wide frame — those tests fail, surfacing the regression
(RESEARCH Pitfall 1).

Test inventory
--------------
Consumer narrow-vs-wide equality tests (the no-drift assertions):
  test_critical_remediation_sla_no_drift        — PRIMARY CONSUMER; highest risk
  test_mttr_trend_no_drift                      — rolling-30 window; deliberate window

Fetch-filter test (RED until Task 3):
  test_fetch_fixed_vulnerabilities_has_last_fixed_filter

Precisely-scoped dynamic caller-discovery test:
  test_all_fixed_consumers_discovered

All fixtures use synthetic-only data (RFC-5737 / RFC-6761 per QUAL-05):
  IPs    : 198.51.100.x / 203.0.113.x
  Hosts  : asset-N.invalid / asset-N.example.invalid
  No real hostnames, IPs, CVE IDs, plugin names, or asset-level PII.

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import ast
import datetime
import textwrap
from datetime import timedelta, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignment / FutureWarning
pd.options.mode.copy_on_write = True

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from reports.modules.base import ModuleConfig
from reports.modules.critical_remediation_sla_module import CriticalRemediationSLAModule
from reports.modules.mttr_trend_module import MTTRTrendModule


# ===========================================================================
# Shared constants
# ===========================================================================

# All tests anchor to this report_date so narrow-vs-wide comparisons are stable.
_REPORT_DATE = datetime.datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc)

# Synthetic asset UUIDs (no real data — QUAL-05)
_UUID_PREFIX = "00000000-0000-0000-0000-0000000000"

# Narrow window: last 30 days — matches critical_remediation_sla's deliberate 30-day filter
_NARROW_DAYS = 30

# Wide window: 365 days — matches config.FIXED_LOOKBACK_DAYS (the widened fetch)
_WIDE_DAYS = 365


# ===========================================================================
# Synthetic data helpers
# ===========================================================================

def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n:02d}"


def _ts(days_ago: float) -> datetime.datetime:
    """UTC-aware timestamp N days before the report date."""
    return _REPORT_DATE - timedelta(days=days_ago)


def _make_assets_df(n: int = 3) -> pd.DataFrame:
    """
    Build a minimal assets_df with n on-time-scanned synthetic assets.

    last_licensed_scan_date within last 30 days so all assets are "on time"
    for identify_on_time_assets().  Tags use Owner= so extract_owner() returns
    a real owner label.

    Includes last_seen required by deduplicate_assets_by_name().

    IPs: 198.51.100.x (RFC-5737 TEST-NET-2)
    Hosts: asset-N.invalid (RFC-6761)
    """
    rows = []
    for i in range(n):
        rows.append({
            "asset_uuid":               _uuid(i),
            "hostname":                 f"asset-{i}.invalid",
            "ipv4":                     f"198.51.100.{i + 1}",
            "last_licensed_scan_date":  _ts(5),   # 5 days ago — well within 30-day window
            "last_seen":                _ts(1),   # required by deduplicate_assets_by_name
            "tags":                     "Owner=TeamAlpha",
        })
    return pd.DataFrame(rows)


def _make_fixed_row(
    uuid_n: int,
    last_fixed_days_ago: float,
    first_found_days_ago: float = 10.0,
    severity: str = "critical",
    state: str = "fixed",
) -> dict:
    """
    Build a single fixed-vuln row using synthetic data only.

    Hostname: asset-N.example.invalid (RFC-6761 .example.invalid)
    IP: 203.0.113.x (RFC-5737 TEST-NET-3)
    """
    lf = _ts(last_fixed_days_ago)
    ff = _ts(first_found_days_ago)
    return {
        "asset_uuid":      _uuid(uuid_n),
        "hostname":        f"asset-{uuid_n}.example.invalid",
        "ipv4":            f"203.0.113.{uuid_n + 1}",
        "plugin_id":       f"SYNTH-{uuid_n:04d}",
        "plugin_name":     f"Synthetic Plugin {uuid_n}",
        "plugin_family":   "General",
        "vpr_score":       9.5,                  # Critical VPR
        "severity":        severity,
        "severity_native": severity,
        "severity_level":  4,
        "cve_list":        "",
        "cvss_base_score": None,
        "cvss3_score":     None,
        "exploit_available":     False,
        "exploit_code_maturity": "UNPROVEN",
        "first_found":     ff,
        "last_found":      lf,
        "last_fixed":      lf,
        "state":           state,
        "finding_id":      f"synth-{uuid_n:04d}-{int(last_fixed_days_ago)}d",
        "severity_modification_type": "NONE",
        "recast_rule_uuid": "",
        "recast_reason":   "",
        "resurfaced_date": None,
        "time_taken_to_fix": float((lf - ff).total_seconds()),
        "tags":            "Owner=TeamAlpha",
        "mac_address":     "",
        "operating_system": "",
    }


def _make_fixed_df(rows: list[dict]) -> pd.DataFrame:
    """Build a fixed_vulns_df from a list of row dicts and coerce date columns."""
    df = pd.DataFrame(rows)
    for col in ("first_found", "last_found", "last_fixed"):
        if col in df.columns:
            df = df.assign(**{col: pd.to_datetime(df[col], utc=True, errors="coerce")})
    return df


def _narrow_fixed_df() -> pd.DataFrame:
    """
    Narrow frame: 5 critical findings all fixed within the last 30 days.

    These are the ONLY rows a consumer with a 30-day window would act on.
    All 5 fixed within the 15-day Critical SLA (last_fixed 1-7 days ago,
    first_found 8-12 days before that).
    """
    rows = [
        _make_fixed_row(uuid_n=i, last_fixed_days_ago=float(i + 1), first_found_days_ago=float(i + 10))
        for i in range(5)
    ]
    return _make_fixed_df(rows)


def _wide_fixed_df() -> pd.DataFrame:
    """
    Wide frame: narrow frame PLUS 10 older critical findings fixed 60-360 days ago.

    The older rows are OUTSIDE the 30-day consumer window.  A consumer that
    applies its own explicit 30-day window at compute time should produce
    IDENTICAL output to the narrow frame — the extra rows are filtered away.
    A consumer that aggregates ALL returned rows would show different results.
    """
    narrow_rows = [
        _make_fixed_row(uuid_n=i, last_fixed_days_ago=float(i + 1), first_found_days_ago=float(i + 10))
        for i in range(5)
    ]
    old_rows = [
        _make_fixed_row(uuid_n=10 + i, last_fixed_days_ago=float(60 + i * 30), first_found_days_ago=float(75 + i * 30))
        for i in range(10)
    ]
    return _make_fixed_df(narrow_rows + old_rows)


def _default_module_config(**extra_options) -> ModuleConfig:
    return ModuleConfig(module_id="test", options=extra_options)


# ===========================================================================
# Task 1 — Consumer narrow-vs-wide equality tests (no-drift assertions)
# ===========================================================================

class TestCriticalRemediationSLANoDrift:
    """
    D-18-06 — CriticalRemediationSLAModule must apply its own 30-day window
    at compute() time so widening the fetch produces identical output.

    This is the PRIMARY CONSUMER / highest-risk assertion (RESEARCH Pitfall 1:
    "% critical fixed within 15d").  If the module aggregates ALL returned
    fixed rows instead of filtering to last_fixed >= report_date - 30d, the
    test will FAIL on the wide frame — surfacing the drift.
    """

    def _run(self, fixed_df: pd.DataFrame):
        assets_df = _make_assets_df(n=5)
        # open vulns_df — deliberately empty. quick-260805-ezo:
        # critical_remediation_sla derives the open_past_due / open_not_due
        # components from this frame; keeping it empty isolates the assertion
        # to the FIXED side, which is what the narrow-vs-wide gate tests.
        vulns_df = pd.DataFrame(columns=[
            "asset_uuid", "vpr_severity", "state", "last_found", "first_found",
        ])
        module = CriticalRemediationSLAModule()
        config = _default_module_config()
        return module.compute(
            vulns_df=vulns_df,
            assets_df=assets_df,
            report_date=_REPORT_DATE,
            config=config,
            fixed_vulns_df=fixed_df,
        )

    def test_narrow_vs_wide_denominator_identical(self):
        """
        denominator must be the same on narrow and wide frames.

        The narrow frame has 5 findings fixed within last 30 days.
        The wide frame adds 10 OLD findings (60-360 days ago) that should
        be excluded by the module's own last_fixed >= report_date - 30d filter.

        quick-260805-ezo — repointed from total_fixed_last_month (removed by
        QT-01) to denominator. The intent is unchanged: widening the fixed
        fetch must not change the module's output.
        """
        narrow_data = self._run(_narrow_fixed_df())
        wide_data   = self._run(_wide_fixed_df())

        assert narrow_data.error is None, f"Narrow run errored: {narrow_data.error}"
        assert wide_data.error is None,   f"Wide run errored: {wide_data.error}"

        narrow_denom = narrow_data.metrics.get("denominator")
        wide_denom   = wide_data.metrics.get("denominator")

        assert narrow_denom == wide_denom, (
            f"DRIFT DETECTED: denominator differs between narrow "
            f"({narrow_denom}) and wide ({wide_denom}) frames.  "
            f"CriticalRemediationSLAModule is aggregating all returned fixed "
            f"rows instead of filtering to its own 30-day window (D-18-06 / "
            f"RESEARCH Pitfall 1)."
        )

    def test_narrow_vs_wide_remediation_sla_pct_identical(self):
        """remediation_sla_pct must be identical — the key headline metric."""
        narrow_data = self._run(_narrow_fixed_df())
        wide_data   = self._run(_wide_fixed_df())

        narrow_pct = narrow_data.metrics.get("remediation_sla_pct")
        wide_pct   = wide_data.metrics.get("remediation_sla_pct")

        assert narrow_pct == wide_pct, (
            f"DRIFT DETECTED: remediation_sla_pct differs between narrow "
            f"({narrow_pct}%) and wide ({wide_pct}%) frames (D-18-06)."
        )

    def test_narrow_vs_wide_compliant_identical(self):
        """
        compliant count must be identical on both frames.

        quick-260805-ezo — repointed from fixed_within_sla (removed by QT-01)
        to compliant; same intent.
        """
        narrow_data = self._run(_narrow_fixed_df())
        wide_data   = self._run(_wide_fixed_df())

        narrow_ws = narrow_data.metrics.get("compliant")
        wide_ws   = wide_data.metrics.get("compliant")

        assert narrow_ws == wide_ws, (
            f"DRIFT DETECTED: compliant differs between narrow ({narrow_ws}) "
            f"and wide ({wide_ws}) frames (D-18-06)."
        )


class TestMTTRTrendNoDrift:
    """
    D-18-06 / D-16-02 — MTTRTrendModule applies a rolling-window filter
    at compute() time (default 30 days).  Adding older rows to the fixed
    frame must NOT change the rolling-30 overall_mttr.

    MTTR must keep deliberate rolling-30 (D-16-02 docstring):
      "Window: report_date - window_days"
    """

    def _run(self, fixed_df: pd.DataFrame, window_days: int = 30):
        assets_df = _make_assets_df(n=5)
        vulns_df  = pd.DataFrame(columns=[
            "asset_uuid", "severity", "state", "last_fixed", "first_found",
        ])
        module = MTTRTrendModule()
        cfg    = _default_module_config(
            mttr_window_days=window_days,
            min_sample_size=1,      # lower threshold so 5 rows are sufficient
        )
        # trend_snapshots absent → MoM cold-start; live gauges still render
        return module.compute(
            vulns_df=vulns_df,
            assets_df=assets_df,
            report_date=_REPORT_DATE,
            config=cfg,
            fixed_vulns_df=fixed_df,
            trend_snapshots=None,
        )

    def test_rolling_30_overall_mttr_identical_on_narrow_vs_wide(self):
        """
        overall_mttr with window_days=30 must be identical on narrow and wide frames.

        The deliberate rolling-window filter (last_fixed >= report_date - 30d)
        inside MTTRTrendModule.compute() must exclude the 10 old rows added
        by the wide frame.  If the module aggregates all rows, the mean shifts.
        """
        narrow_data = self._run(_narrow_fixed_df())
        wide_data   = self._run(_wide_fixed_df())

        # Both should succeed (not cold-start) — we have 5 recent findings
        assert not narrow_data.metrics.get("cold_start"), (
            "Unexpected cold-start on narrow frame — check fixture has "
            "min_sample_size=1 and >=1 finding within 30 days."
        )
        assert not wide_data.metrics.get("cold_start"), (
            "Unexpected cold-start on wide frame."
        )

        narrow_mttr = narrow_data.metrics.get("overall_mttr")
        wide_mttr   = wide_data.metrics.get("overall_mttr")

        assert narrow_mttr is not None, "overall_mttr is None on narrow frame"
        assert wide_mttr   is not None, "overall_mttr is None on wide frame"

        assert narrow_mttr == wide_mttr, (
            f"DRIFT DETECTED: overall_mttr differs between narrow ({narrow_mttr}d) "
            f"and wide ({wide_mttr}d) frames.  "
            f"MTTRTrendModule is not correctly filtering to its rolling "
            f"{30}-day window (D-18-06 / D-16-02)."
        )

    def test_rolling_30_preserved_when_older_rows_present(self):
        """
        Per-severity MTTR values must also be identical on narrow vs wide,
        confirming the window filter applies before the groupby.
        """
        narrow_data = self._run(_narrow_fixed_df())
        wide_data   = self._run(_wide_fixed_df())

        for sev in ("critical", "high", "medium", "low"):
            narrow_sev = narrow_data.metrics.get(f"{sev}_mttr")
            wide_sev   = wide_data.metrics.get(f"{sev}_mttr")
            assert narrow_sev == wide_sev, (
                f"DRIFT DETECTED: {sev}_mttr differs (narrow={narrow_sev}, "
                f"wide={wide_sev}) — per-severity window not applied correctly."
            )


# ===========================================================================
# Task 1 (RED) — Fetch-filter test
# Stays RED until Task 3 adds last_fixed to fetch_fixed_vulnerabilities.
# ===========================================================================

class TestFetchFixedVulnerabilitiesHasLastFixedFilter:
    """
    Task 3 gate (RED until Task 3): fetch_fixed_vulnerabilities must build
    export_filters containing a last_fixed key sized to config.FIXED_LOOKBACK_DAYS.

    Implementation note: this test inspects the export_filters that the
    function would pass to tio.exports.vulns() by patching out the actual
    export call and capturing the kwargs.

    The PROVEN filter shape (from Task 0 live probe) is:
        last_fixed=<int epoch seconds>
    NOT a date-range dict.
    """

    def test_export_filters_contain_last_fixed(self):
        """
        fetch_fixed_vulnerabilities must pass last_fixed=<int epoch> to
        tio.exports.vulns() — the shape confirmed by the Task 0 live probe.

        This test is RED until Task 3 adds the bounded lookback filter.
        """
        import data.fetchers as fetchers_mod

        captured_kwargs: list[dict] = []

        def fake_vulns(**kwargs):
            captured_kwargs.append(kwargs)
            return iter([])   # no rows — we only check the filter shape

        class FakeTIO:
            class exports:
                @staticmethod
                def vulns(**kwargs):
                    return fake_vulns(**kwargs)

        # Use a temp dir so the cache-miss path runs the actual filter-building code
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            # Patch the rich Progress to avoid TTY issues in CI
            with patch("data.fetchers._make_fetch_progress") as mock_progress:
                mock_progress.return_value.__enter__ = lambda s: mock_progress.return_value
                mock_progress.return_value.__exit__  = lambda s, *a: False
                mock_progress.return_value.add_task  = lambda *a, **kw: 0
                mock_progress.return_value.advance   = lambda *a: None

                fetchers_mod.fetch_fixed_vulnerabilities(FakeTIO(), cache_dir)

        assert captured_kwargs, (
            "fetch_fixed_vulnerabilities did not call tio.exports.vulns() — "
            "check that the cache-miss path ran (use a fresh temp cache_dir)."
        )
        kwargs = captured_kwargs[0]

        # The proven shape: last_fixed is a plain integer (Unix epoch seconds)
        assert "last_fixed" in kwargs, (
            "fetch_fixed_vulnerabilities does NOT pass last_fixed to "
            "tio.exports.vulns(). This is the RED gate — Task 3 must add it."
        )
        last_fixed_val = kwargs["last_fixed"]
        assert isinstance(last_fixed_val, int), (
            f"last_fixed must be a plain int (Unix epoch seconds, proven by "
            f"Task 0 live probe), got {type(last_fixed_val).__name__}: {last_fixed_val!r}"
        )

    def test_lookback_bounded_to_fixed_lookback_days(self):
        """
        The last_fixed epoch value must correspond to approximately
        now - config.FIXED_LOOKBACK_DAYS (within a 60-second tolerance to
        account for test execution time).

        Bounded = NOT a 2-year/unbounded pull (D-18-05).
        """
        import data.fetchers as fetchers_mod

        captured_kwargs: list[dict] = []

        def fake_vulns(**kwargs):
            captured_kwargs.append(kwargs)
            return iter([])

        class FakeTIO:
            class exports:
                @staticmethod
                def vulns(**kwargs):
                    return fake_vulns(**kwargs)

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            with patch("data.fetchers._make_fetch_progress") as mock_progress:
                mock_progress.return_value.__enter__ = lambda s: mock_progress.return_value
                mock_progress.return_value.__exit__  = lambda s, *a: False
                mock_progress.return_value.add_task  = lambda *a, **kw: 0
                mock_progress.return_value.advance   = lambda *a: None

                call_ts = datetime.datetime.now(tz=timezone.utc)
                fetchers_mod.fetch_fixed_vulnerabilities(FakeTIO(), cache_dir)

        assert captured_kwargs, "tio.exports.vulns() was not called"
        last_fixed_epoch = captured_kwargs[0].get("last_fixed")
        assert last_fixed_epoch is not None, "last_fixed not in export kwargs"

        # Compute the expected cutoff: call_ts - config.FIXED_LOOKBACK_DAYS
        expected_cutoff = call_ts - timedelta(days=config.FIXED_LOOKBACK_DAYS)
        expected_epoch  = int(expected_cutoff.timestamp())

        # Allow ±120 seconds of tolerance for test execution overhead
        tolerance = 120
        assert abs(last_fixed_epoch - expected_epoch) <= tolerance, (
            f"last_fixed epoch {last_fixed_epoch} is not within {tolerance}s of "
            f"expected cutoff (now - {config.FIXED_LOOKBACK_DAYS}d = {expected_epoch}). "
            f"Difference: {abs(last_fixed_epoch - expected_epoch)}s.  "
            f"Check that config.FIXED_LOOKBACK_DAYS is used for the lookback "
            f"(D-18-05 bounded fetch, not a 2-year unbounded pull)."
        )


# ===========================================================================
# Task 1 — Precisely-scoped caller-discovery sweep (dynamic completeness gate)
# ===========================================================================

# ---------------------------------------------------------------------------
# COVERED_FIXED_CONSUMERS
# ---------------------------------------------------------------------------
# The static sweep (test_all_fixed_consumers_discovered) finds CALLERS of
# fetch_fixed_vulnerabilities in reports/ and data/.  ALL of those callers
# are pass-through wrappers (run_report functions that fan the df out to
# modules via the composer).  The actual result-COMPUTING consumers
# (CriticalRemediationSLAModule, MTTRTrendModule) receive fixed_vulns_df
# as a **kwargs injection — they never call fetch_fixed_vulnerabilities
# directly.
#
# COVERED_FIXED_CONSUMERS documents the audited result-computing modules.
# The sweep asserts that every DIRECT CALLER of fetch_fixed_vulnerabilities
# is either in _PASS_THROUGH_CALLERS or has an entry here.  Since all
# direct callers today are pass-throughs, the sweep primarily guards against
# a future addition of a direct-calling aggregator that bypasses the
# composer fan-out (and thus might escape the explicit-window requirement).
#
# This set is an INTENTIONAL co-edit gate (project_frozenset_gate_test_coupling):
# if someone adds a direct-calling result-aggregator (not a pass-through),
# the sweep will fail until they add it here and verify it has its own window.
#
# Audited result-computing consumers (receive fixed_vulns_df via kwargs):
#   - CriticalRemediationSLAModule: applies last_fixed >= report_date - 30d (Step 3)
#   - MTTRTrendModule:              applies last_fixed >= report_date - window_days (D-16-02)
#
# EXCLUSION SCOPE for the static sweep (callers NOT flagged as violations):
#   tests/              — excluded directory: test files are not production consumers
#   scripts/            — excluded directory: probe + backfill scripts annotated below
#     probe_last_fixed_filter.py         — one-time operator probe (Task 0), not production
#     backfill_trend_reconstruction.py   — Plan 03 migration script (not yet built)
#   docs/               — excluded directory: documentation examples only
#   import-only refs    — no call site in the module: excluded automatically by sweep
#   management_summary.run_report — pass-through: hands frame to composer → covered modules
#   composed_report.run_report    — pass-through: fan-out via _MODULES_NEEDING_FIXED_VULNS
#   board_summary.run_report      — pass-through: hands frame to composer → covered modules
# ---------------------------------------------------------------------------
COVERED_FIXED_CONSUMERS: frozenset[str] = frozenset({
    "CriticalRemediationSLAModule.compute",
    "MTTRTrendModule.compute",
})

# Pure pass-through callers — they call fetch_fixed_vulnerabilities and hand the
# result to an already-covered consumer (fan-out) without aggregating it themselves.
# Excluded from the discovery gate so the gate is not brittle on harmless callers.
#
# CR-T2: Use module-qualified "file::function" identifiers so the exemption only
# matches the specific run_report functions in named files, not any run_report
# anywhere in the codebase.
_PASS_THROUGH_CALLERS: frozenset[str] = frozenset({
    "reports/management_summary.py::run_report",
    "reports/board_summary.py::run_report",
    "reports/composed_report.py::run_report",
})

# Known scripts excluded from the result-consuming sweep.
_EXCLUDED_SCRIPTS: frozenset[str] = frozenset({
    "probe_last_fixed_filter.py",
    "backfill_trend_reconstruction.py",   # Plan 03 migration script (not yet built)
})

# Directories to exclude from the sweep entirely.
_EXCLUDED_DIRS: frozenset[str] = frozenset({
    "tests",
    "docs",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "output",
    "logs",
    "data/cache",
    "data/trend",
    "migrations",
    "scripts",  # probe scripts excluded above; backfill is future work
})


class TestAllFixedConsumersDiscovered:
    """
    Precisely-scoped dynamic-completeness gate (review changes #3 & #6, D-18-06).

    Statically sweeps reports/, data/, run_all.py for Python files and parses
    them with ast to discover RESULT-CONSUMING callers of
    fetch_fixed_vulnerabilities.

    Exclusions are EXPLICIT and documented so the gate is not brittle on
    harmless references:
      - tests/ tree (test files are not production consumers)
      - scripts/ tree (probe and backfill scripts are annotated as excluded)
      - docs/ tree (documentation examples)
      - import-only references (no call site in the same module)
      - pure pass-through wrappers (hand the frame to an already-covered module)

    If the scoped sweep finds a result-consuming caller NOT in
    COVERED_FIXED_CONSUMERS, the test FAILS — surfacing the unlisted consumer
    for the author to audit and add to the covered set.

    See project_frozenset_gate_test_coupling memory: updating COVERED_FIXED_CONSUMERS
    above is the required co-edit when adding a new real consumer.
    """

    @staticmethod
    def _collect_python_files(root: Path) -> list[Path]:
        """
        Walk root recursively and return .py files, respecting _EXCLUDED_DIRS.
        """
        results = []
        for path in root.rglob("*.py"):
            # Skip any path that contains an excluded directory segment
            parts = set(path.parts)
            if any(excl in parts for excl in _EXCLUDED_DIRS):
                continue
            # Also exclude by resolved relative segment check for robustness
            rel = path.relative_to(root)
            if any(part in _EXCLUDED_DIRS for part in rel.parts):
                continue
            # Exclude known scripts by filename
            if path.name in _EXCLUDED_SCRIPTS:
                continue
            results.append(path)
        return results

    @staticmethod
    def _find_call_sites(tree: ast.AST, func_name: str) -> list[str]:
        """
        Return a list of enclosing function/method names where func_name is called.

        Walks the AST looking for Call nodes whose func is a Name or Attribute
        matching func_name.  Returns the qualified name of the enclosing
        function/class (e.g. "MyClass.my_method" or "run_report").
        """
        call_sites: list[str] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self):
                self._scope_stack: list[str] = []

            def visit_ClassDef(self, node: ast.ClassDef):
                self._scope_stack.append(node.name)
                self.generic_visit(node)
                self._scope_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._scope_stack.append(node.name)
                self.generic_visit(node)
                self._scope_stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node: ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name == func_name:
                    scope = ".".join(self._scope_stack) if self._scope_stack else "<module>"
                    call_sites.append(scope)
                self.generic_visit(node)

        Visitor().visit(tree)
        return call_sites

    @staticmethod
    def _has_import_only(tree: ast.AST, func_name: str) -> bool:
        """
        Return True if func_name is imported but has no call site in the module
        (import-only reference — excluded from the result-consuming sweep).
        """
        imported = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.ImportFrom, ast.Import)):
                # Check if func_name appears in the import names
                names = getattr(node, "names", [])
                if any(alias.name == func_name or alias.asname == func_name for alias in names):
                    imported = True
        return imported   # call sites checked separately

    def test_all_fixed_consumers_discovered(self):
        """
        The scoped sweep must find ONLY callers that are in COVERED_FIXED_CONSUMERS
        or are documented pass-throughs.

        If a new result-consuming caller exists that is NOT in the covered set,
        this test FAILs — co-edit COVERED_FIXED_CONSUMERS above to add it (and
        verify it applies its own explicit date window per D-18-06).
        """
        project_root = Path(__file__).resolve().parent.parent
        func_name = "fetch_fixed_vulnerabilities"

        # Directories to sweep (reports/, data/, and run_all.py)
        sweep_roots = [
            project_root / "reports",
            project_root / "data",
        ]
        sweep_files = []
        for root in sweep_roots:
            if root.exists():
                sweep_files.extend(self._collect_python_files(root))
        # Also include run_all.py directly (not in reports/ or data/)
        run_all_py = project_root / "run_all.py"
        if run_all_py.exists():
            sweep_files.append(run_all_py)

        assert sweep_files, (
            f"No Python files found under {sweep_roots} — check project structure."
        )

        discovered_result_consumers: set[str] = set()
        uncovered_callers: list[str] = []

        for py_file in sweep_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree   = ast.parse(source, filename=str(py_file))
            except (SyntaxError, UnicodeDecodeError):
                continue   # skip unparsable files

            call_sites = self._find_call_sites(tree, func_name)
            if not call_sites:
                continue

            # CR-T2: build the repo-relative file path for qualified matching.
            rel_path = py_file.relative_to(project_root).as_posix()

            for scope in call_sites:
                # CR-T2: Exclude pass-through callers by module-qualified
                # "file::function" identifier so a bare "run_report" function
                # in an unrelated file is not silently exempted.
                qualified = f"{rel_path}::{scope}"
                if qualified in _PASS_THROUGH_CALLERS:
                    continue
                # Exclude module-level calls (scope == "<module>") — these are
                # typically documentation examples or ad-hoc scripts
                if scope == "<module>":
                    continue

                # This is a result-consuming call site
                discovered_result_consumers.add(scope)

                if scope not in COVERED_FIXED_CONSUMERS:
                    rel = py_file.relative_to(project_root)
                    uncovered_callers.append(f"{rel}::{scope}")

        # If uncovered callers are found, fail with a clear message.
        # Note: all current direct callers are pass-throughs (run_report in
        # composed_report/board_summary/management_summary) — they fan the df
        # out to result-computing modules (CriticalRemediationSLAModule,
        # MTTRTrendModule) which receive it as **kwargs and apply their own
        # explicit date windows (D-18-06).  A failure here means a new
        # direct-calling aggregator was added outside the pass-through pattern.
        assert not uncovered_callers, (
            f"DISCOVERY GATE: The following direct callers of "
            f"fetch_fixed_vulnerabilities in reports/ or data/ were found "
            f"that are NOT in _PASS_THROUGH_CALLERS and NOT in "
            f"COVERED_FIXED_CONSUMERS:\n"
            + "\n".join(f"  - {c}" for c in sorted(uncovered_callers))
            + "\n\nFor each caller, either:\n"
            + "  a) If it aggregates fixed rows itself: verify it applies its\n"
            + "     own explicit date window (D-18-06) and add it to\n"
            + "     COVERED_FIXED_CONSUMERS in this file, OR\n"
            + "  b) If it passes the frame to an already-covered consumer:\n"
            + "     add the function name to _PASS_THROUGH_CALLERS."
        )
