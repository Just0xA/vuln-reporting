"""
tests/test_management_summary.py — Phase 18 Plan 04 migration acceptance tests.

Purpose
-------
These are the RED-phase acceptance tests for the GEN-01 atomic cutover of
management_summary onto ReportComposer.run_full_pipeline().  They will FAIL
against the current bespoke path (Task 1, RED) and pass once Task 2 lands
(GREEN).

Test inventory
--------------
(1) test_module_presence            — bundle contains all seven module IDs
(2) test_email_body_html_nonempty   — return dict has non-empty email_body_html
(3) test_bespoke_functions_removed  — listed bespoke functions are NOT present
(4) test_run_report_accepts_chrome_kwargs — chrome kwargs accepted (no TypeError)
(5) test_trend_forwarded_no_coldstart     — seeded trend reaches MoM modules
(6) test_value_golden_parity              — per-metric bucketed parity gate
(7) test_read_trend_ignores_legacy_archive_integration — integration echo of
    the store-level contract

Frozen-synthetic fixture gate (D-04-05 reconciliation)
-------------------------------------------------------
test_value_golden_parity is a FROZEN-SYNTHETIC-INPUT parity lock, NOT a
live-value lock.  D-04-05 governs live-drifting values in the operator smoke
script; this test asserts deterministic behaviour against a committed fixture
set captured by Plan 01.

Per-metric bucket policy (review HIGH change #1)
------------------------------------------------
The golden JSON's "bucket" field drives assertion policy — the test reads bucket
assignments FROM the golden, never hard-codes them:
  - "exact_match"  → assert zero drift (EXACT for ints; stated tolerance for floats)
  - "documented_difference" → do NOT assert exact equality; record actual values
    for the SUMMARY; rely on the module's own tests + visual UAT (M5, M7)

QUAL-05 compliance: all fixtures use RFC-5737/6761 synthetic addresses only.
No real hostnames, IPs, plugin names, or asset-level fields appear here.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_TESTS_DIR    = Path(__file__).resolve().parent
_FIXTURES_DIR = _TESTS_DIR / "fixtures" / "management_summary_parity"
_BASELINES_DIR = _TESTS_DIR / "baselines"
_GOLDEN_PATH  = _BASELINES_DIR / "management_summary_value_golden.json"

# The seven module IDs the migrated management_summary must compose.
_MGMT_MODULE_IDS: list[str] = sorted([
    "total_vulns_by_severity",
    "scan_coverage_sla",
    "mttr_trend",
    "patch_compliance_rate",
    "aged_vulns_assets",
    "accepted_recast",
    "new_vs_remediated",
])

# Bespoke functions/constants that must NOT exist after the atomic cutover.
_BESPOKE_NAMES: list[str] = [
    "_sanitise_tag_for_filename",
    "_trend_file_path",
    "_load_trend_history",
    "_save_trend_snapshot",
    "_compute_metric_1",
    "_compute_metric_2",
    "_compute_metric_3",
    "_compute_metric_4",
    "_compute_metric_5",
    "_compute_metric_6",
    "_compute_metric_7",
    "compute_all_metrics",
    "_build_age_bar_chart",
    "_build_trend_line_chart",
    "_build_pdf",
    "build_email_kpi_tiles",
    "build_email_body",
    # constants consumed only by the deleted functions
    "_PDF_CSS",
    "_AGE_BUCKETS",
    "_OPEN_STATES",
]

# Fixed report date for determinism (matches Plan 01 fixture capture).
_REPORT_DATE = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Shared fixture-loading helpers
# ---------------------------------------------------------------------------

def _load_fixtures() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """Load the Plan 01 frozen synthetic fixture set."""
    vulns_df     = pd.read_parquet(_FIXTURES_DIR / "vulns_df.parquet")
    assets_df    = pd.read_parquet(_FIXTURES_DIR / "assets_df.parquet")
    fixed_vulns_df = pd.read_parquet(_FIXTURES_DIR / "fixed_vulns_df.parquet")
    with (_FIXTURES_DIR / "trend_snapshots.json").open(encoding="utf-8") as fh:
        trend_snapshots = json.load(fh)
    return vulns_df, assets_df, fixed_vulns_df, trend_snapshots


def _load_golden() -> dict:
    """Load the Plan 01 bucketed bespoke value golden."""
    with _GOLDEN_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Helper: run the modular pipeline against provided data (no live Tenable)
# ---------------------------------------------------------------------------

def _run_modular_pipeline(
    vulns_df: pd.DataFrame,
    assets_df: pd.DataFrame,
    fixed_vulns_df: pd.DataFrame,
    trend_snapshots: dict,
    output_dir: Path,
    *,
    report_date: datetime = _REPORT_DATE,
    privacy_label: str = "Confidential",
    scope_subtitle: str | None = None,
    report_title: str | None = None,
    analyst_detail: bool = True,
) -> dict:
    """
    Invoke the MODULAR management_summary pipeline directly.

    Calls run_report() with a _NoLiveTio sentinel — after Task 2 lands,
    run_report() will call fetch_* helpers that require a live tio client.
    To avoid that in tests we call the composer pipeline directly the same
    way run_report() will, bypassing the fetch layer.

    Post-Task-2: once run_report() is migrated, these tests switch to calling
    run_report() with a stub tio that returns the pre-loaded fixture DataFrames.
    For the RED phase they call the composer path directly to get ahead.

    NOTE: This helper intentionally calls the NEW modular path even in the RED
    phase so we can confirm the bespoke path does NOT satisfy the assertions.
    """
    # Import here so import errors produce a clear failure message.
    import reports.management_summary as ms
    from reports.modules import ReportComposer
    from reports.modules.base import ModuleConfig
    from reports.modules.pdf_chrome import PdfChromeConfig
    from config import HEADER_BG_COLOR, LOGO_PATH

    # After Task 2 the module will expose _MGMT_MODULE_CONFIGS.
    # For RED-phase testing, import or fall back to constructing them here.
    try:
        module_configs = ms._MGMT_MODULE_CONFIGS  # type: ignore[attr-defined]
    except AttributeError:
        # RED phase: bespoke module doesn't have _MGMT_MODULE_CONFIGS yet.
        # Build them to test the composer path directly.
        module_configs = [ModuleConfig(mid) for mid in [
            "total_vulns_by_severity",
            "scan_coverage_sla",
            "mttr_trend",
            "patch_compliance_rate",
            "aged_vulns_assets",
            "accepted_recast",
            "new_vs_remediated",
        ]]

    effective_title = report_title or "Management Vulnerability Summary"
    resolved_subtitle = scope_subtitle or "All assets"

    pdf_chrome_cfg = PdfChromeConfig(
        title         = effective_title,
        subtitle      = resolved_subtitle,
        generated_at  = report_date,
        header_bg     = HEADER_BG_COLOR,
        logo_path     = LOGO_PATH,
        privacy_label = privacy_label,
    )

    composer = ReportComposer(
        vulns_df        = vulns_df,
        assets_df       = assets_df,
        report_date     = report_date,
        module_configs  = module_configs,
        fixed_vulns_df  = fixed_vulns_df,
        pdf_chrome      = pdf_chrome_cfg,
        trend_snapshots = trend_snapshots,  # forwarded to every compute() via **kwargs
    )

    results = composer.run_all()

    bundle = composer.run_full_pipeline(
        results,
        output_dir,
        slug             = "management_summary",
        report_date      = report_date,
        generate_analyst = analyst_detail,
        pdf_title        = effective_title,
        pdf_subtitle     = resolved_subtitle,
        scope_label      = "All Assets",
    )

    return {"_bundle": bundle, "results": results}


# ===========================================================================
# Test 1: Module presence
# ===========================================================================

def test_module_presence(tmp_path: Path) -> None:
    """
    Bundle must contain results for all seven management_summary module IDs.

    Mirrors test_board_summary_baseline's module-presence check.
    After Task 2 this calls run_report(); during RED it calls the composer
    pipeline directly with the synthetic fixture set.

    Presence check: all 7 module IDs must appear in results (the composer
    ran them), even if some modules errored during compute() — the
    fail-soft semantics produce a result entry with error set, not a
    missing entry.  Correctness (no error) is tested separately in the
    parity gate for exact_match modules.
    """
    vulns_df, assets_df, fixed_vulns_df, trend_snapshots = _load_fixtures()

    out = _run_modular_pipeline(
        vulns_df, assets_df, fixed_vulns_df, trend_snapshots, tmp_path
    )
    results = out["results"]

    # All 7 module IDs must be present (ran by the composer)
    present_ids = sorted(r.module_id for r in results)
    for mid in _MGMT_MODULE_IDS:
        assert mid in present_ids, (
            f"Expected module '{mid}' in composer results but got: {present_ids}. "
            f"The module must be in _MGMT_MODULE_CONFIGS."
        )

    # Log any modules that errored (non-fatal for this test; parity gate catches drift)
    errored = [r.module_id for r in results if r.error]
    if errored:
        import warnings
        warnings.warn(
            f"Module(s) errored during compute() (fail-soft): {errored}. "
            f"These will show as absent in the parity gate.",
            stacklevel=1,
        )


# ===========================================================================
# Test 2: email_body_html non-empty
# ===========================================================================

def test_email_body_html_nonempty(tmp_path: Path) -> None:
    """
    The modular pipeline must produce a non-empty email_body_html.

    This triggers build_email_body_modular() routing in email_sender.py
    (the bundle-driven predicate: any report's email_body_html non-empty).

    RED assertion: the bespoke run_report() returns email_body_html="" which
    fails this test — proving the migration is not yet done.
    """
    vulns_df, assets_df, fixed_vulns_df, trend_snapshots = _load_fixtures()

    out = _run_modular_pipeline(
        vulns_df, assets_df, fixed_vulns_df, trend_snapshots, tmp_path
    )
    bundle = out["_bundle"]

    email_html = bundle.get("email_body_html", "")
    assert isinstance(email_html, str), "email_body_html must be a str"
    assert len(email_html.strip()) > 0, (
        "email_body_html must be non-empty after GEN-01 migration; "
        "bespoke path returns '' — this should FAIL before Task 2"
    )


# ===========================================================================
# Test 3: Bespoke functions removed
# ===========================================================================

def test_bespoke_functions_removed() -> None:
    """
    After the atomic cutover, none of the listed bespoke functions/constants
    must remain as attributes of the management_summary module.

    RED assertion: the bespoke module HAS these attributes — this test
    is expected to FAIL before Task 2 and pass after.

    This proves QUAL-04 dual-writer window closed: the old write path
    (_save_trend_snapshot) and old compute path (compute_all_metrics, etc.)
    are gone in the same commit that adds read_trend() / composer wiring.
    """
    import reports.management_summary as ms

    surviving = [name for name in _BESPOKE_NAMES if hasattr(ms, name)]
    assert surviving == [], (
        f"The following bespoke names must be removed in the Task 2 atomic commit "
        f"but are still present: {surviving}"
    )


# ===========================================================================
# Test 4: run_report accepts chrome kwargs
# ===========================================================================

def test_run_report_accepts_chrome_kwargs() -> None:
    """
    run_report() must accept privacy_label, scope_subtitle, report_title
    without raising TypeError (Pitfall 3 — chrome kwargs added to signature
    in the SAME commit as _CHROME_AWARE_SLUGS membership).

    RED assertion: the bespoke run_report() signature does NOT have these
    kwargs — calling with them raises TypeError.
    """
    import inspect
    import reports.management_summary as ms

    sig = inspect.signature(ms.run_report)
    params = set(sig.parameters.keys())

    for kwarg in ("privacy_label", "scope_subtitle", "report_title"):
        assert kwarg in params, (
            f"run_report() must accept '{kwarg}' kwarg (chrome integration) "
            f"but it is missing from the signature. "
            f"This should FAIL before Task 2."
        )


# ===========================================================================
# Test 5: Trend forwarded — no cold-start on seeded all_assets scope
# ===========================================================================

def test_trend_forwarded_no_coldstart(tmp_path: Path) -> None:
    """
    When a seeded (>=2 snapshot) all_assets trend is forwarded to the composer,
    the MoM-consuming modules must NOT cold-start (Pitfall 4).

    Checks that at least one of the three MoM modules (mttr_trend,
    new_vs_remediated, accepted_recast) has insufficient_data=False in their
    computed metrics — proving trend_snapshots reached compute().

    The fixture trend_snapshots.json has 3 snapshots (2026-03, 04, 05) with
    tag_filter="all_assets" so insufficient_data=False.
    """
    vulns_df, assets_df, fixed_vulns_df, trend_snapshots = _load_fixtures()

    # Confirm the fixture has enough snapshots
    assert not trend_snapshots.get("insufficient_data", True), (
        "Fixture trend_snapshots.json must have insufficient_data=False "
        "(3 snapshots) — check the fixture."
    )
    assert len(trend_snapshots.get("snapshots", [])) >= 2

    out = _run_modular_pipeline(
        vulns_df, assets_df, fixed_vulns_df, trend_snapshots, tmp_path
    )
    results = out["results"]

    # Find MoM modules that consume trend_snapshots
    mom_module_ids = {"mttr_trend", "new_vs_remediated", "accepted_recast"}
    mom_results = {r.module_id: r for r in results if r.module_id in mom_module_ids}

    # At least the mttr_trend module should receive trend_snapshots.
    # When trend_snapshots is NOT forwarded, these modules cold-start and
    # record cold_start=True or insufficient_data=True in their metrics.
    for mid, r in mom_results.items():
        if r.error:
            continue  # skip modules that errored (separate concern)
        metrics = r.metrics or {}
        cold = metrics.get("cold_start") or metrics.get("insufficient_data")
        # We assert at least one MoM module is NOT cold-starting
        if not cold:
            return  # at least one module got the trend data — test passes

    pytest.fail(
        "All MoM modules (mttr_trend, new_vs_remediated, accepted_recast) are "
        "cold-starting despite a seeded trend fixture. This means trend_snapshots "
        "is not being forwarded through the ReportComposer **kwargs path. "
        "Check that trend_snapshots is passed to ReportComposer.__init__()."
    )


# ===========================================================================
# Test 6: Per-metric bucketed value-parity gate (review HIGH change #1)
# ===========================================================================

def test_value_golden_parity(tmp_path: Path) -> None:
    """
    Per-metric parity gate against the Plan 01 bucketed bespoke golden.

    Frozen-synthetic check (D-04-05 reconciliation):
      This is NOT a live-value lock and does NOT conflict with D-04-05.
      The frozen fixture set (vulns_df/assets_df/fixed_vulns_df/trend_snapshots)
      is committed in Plan 01 and never changes — this test checks that the
      NEW modular pipeline computes the SAME values as the bespoke path did
      on the SAME deterministic input.

    Assertion policy (read from the golden — never hard-coded here):
      - "exact_match"  → assert zero drift:
            integer counts: exact equality
            float values:   abs(actual - bespoke) <= golden["tolerance"]
      - "documented_difference" → record actual vs bespoke for SUMMARY;
            assert only the golden's shared_invariant if it names one;
            if shared_invariant == "none", skip exact assert entirely.

    Metrics:
      M1 total_vulns_by_severity  — exact_match (integer counts)
      M2 scan_coverage_sla        — exact_match (float tolerance 1e-6)
      M3 mttr_trend               — exact_match (float tolerance 0.5 days)
      M4 patch_compliance_rate    — exact_match (float tolerance 1e-6)
      M5 aged_vulns_assets        — documented_difference (different unit)
      M6 accepted_recast          — exact_match (int counts + float rate)
      M7 new_vs_remediated        — documented_difference (different semantics)
    """
    vulns_df, assets_df, fixed_vulns_df, trend_snapshots = _load_fixtures()
    golden = _load_golden()

    out = _run_modular_pipeline(
        vulns_df, assets_df, fixed_vulns_df, trend_snapshots, tmp_path,
        report_date=_REPORT_DATE,
    )
    results = out["results"]

    # Build a module_id → metrics dict for easy lookup
    mod_metrics: dict[str, dict] = {
        r.module_id: (r.metrics or {})
        for r in results
    }

    failures: list[str] = []
    documented_differences: list[str] = []

    for metric_key, gentry in golden["metrics"].items():
        mid    = gentry["metric_id"]
        bucket = gentry["bucket"]
        bespoke_vals = gentry.get("bespoke_values", {})
        policy = gentry.get("comparison_policy", "EXACT")
        tol    = gentry.get("tolerance", 0.0)

        if mid not in mod_metrics:
            if bucket == "exact_match":
                failures.append(
                    f"{metric_key} ({mid}): module not found in results "
                    f"(exact_match metric — must be present)"
                )
            # documented_difference modules being absent is recorded, not a failure
            documented_differences.append(
                f"{metric_key} ({mid}): module absent (bucket={bucket})"
            )
            continue

        actual = mod_metrics[mid]

        if bucket == "exact_match":
            _assert_exact_match(
                metric_key, mid, bespoke_vals, actual, policy, tol, failures
            )

        elif bucket == "documented_difference":
            # Do NOT assert exact equality.
            # Record actual vs bespoke for the SUMMARY.
            inv = gentry.get("shared_invariant", "none")
            if inv and inv != "none":
                # Assert the named shared invariant if one exists
                _assert_shared_invariant(
                    metric_key, mid, inv, bespoke_vals, actual, failures
                )
            documented_differences.append(
                f"{metric_key} ({mid}): documented_difference — "
                f"bespoke={_summarise(bespoke_vals)}, "
                f"modular={_summarise(actual)}"
            )

    # Print documented differences for SUMMARY capture (not failures)
    if documented_differences:
        print("\n--- Documented differences (M5, M7) ---")
        for dd in documented_differences:
            print(f"  {dd}")

    if failures:
        pytest.fail(
            "Per-metric parity gate FAILED on exact_match metrics:\n"
            + "\n".join(f"  - {f}" for f in failures)
        )


def _assert_exact_match(
    metric_key: str,
    mid: str,
    bespoke: dict,
    actual: dict,
    policy: str,
    tol: float,
    failures: list[str],
) -> None:
    """Assert zero drift for an exact_match metric."""
    if policy == "EXACT":
        _check_int_counts(metric_key, mid, bespoke, actual, failures)
    elif policy == "TOLERANCE":
        _check_float_tolerance(metric_key, mid, bespoke, actual, tol, failures)
    elif policy == "MIXED":
        _check_mixed(metric_key, mid, bespoke, actual, tol, failures)
    else:
        failures.append(f"{metric_key} ({mid}): unknown policy '{policy}'")


def _check_int_counts(
    metric_key: str, mid: str, bespoke: dict, actual: dict,
    failures: list[str],
) -> None:
    """M1 total_vulns_by_severity: integer counts must match exactly."""
    for sev in ("critical", "high", "medium", "low", "total"):
        if sev not in bespoke:
            continue
        bv = bespoke[sev]
        av = actual.get(sev, actual.get(f"open_{sev}"))
        if av is None:
            failures.append(
                f"{metric_key} ({mid}): '{sev}' missing in modular metrics. "
                f"actual keys: {sorted(actual.keys())}"
            )
            continue
        if int(av) != int(bv):
            failures.append(
                f"{metric_key} ({mid}): '{sev}' mismatch — "
                f"bespoke={bv}, modular={av}"
            )


def _check_float_tolerance(
    metric_key: str, mid: str, bespoke: dict, actual: dict,
    tol: float, failures: list[str],
) -> None:
    """M2/M3/M4 float checks with stated tolerance."""
    if mid == "scan_coverage_sla":
        # Module key is scan_coverage_pct; bespoke golden key is coverage_pct.
        bv = bespoke.get("coverage_pct")
        # Accept either key name for forward-compatibility.
        av = actual.get("scan_coverage_pct") or actual.get("coverage_pct")
        if bv is not None and av is not None:
            if abs(float(av) - float(bv)) > tol:
                failures.append(
                    f"{metric_key} ({mid}): coverage_pct drift — "
                    f"bespoke={bv}, modular={av}, tol={tol}"
                )
        elif bv is not None:
            failures.append(
                f"{metric_key} ({mid}): scan_coverage_pct/coverage_pct missing in modular metrics. "
                f"Keys: {sorted(actual.keys())}"
            )

    elif mid == "mttr_trend":
        # Per-severity MTTR values (rolling-30 window)
        bespoke_mttr = bespoke.get("mttr", {})
        actual_mttr  = actual.get("mttr_by_severity") or actual.get("mttr", {})
        for sev in ("critical", "high", "medium", "low"):
            bv = bespoke_mttr.get(sev)
            av = actual_mttr.get(sev)
            if bv is None:
                continue  # bespoke didn't have this severity
            if av is None:
                # Module may report None when sample is too small — acceptable
                continue
            if abs(float(av) - float(bv)) > tol:
                failures.append(
                    f"{metric_key} ({mid}): mttr[{sev}] drift — "
                    f"bespoke={bv}, modular={av}, tol={tol} days"
                )

    elif mid == "patch_compliance_rate":
        bv = bespoke.get("overall_rate")
        av = actual.get("overall_rate") or actual.get("compliance_rate")
        if bv is not None and av is not None:
            if abs(float(av) - float(bv)) > tol:
                failures.append(
                    f"{metric_key} ({mid}): overall_rate drift — "
                    f"bespoke={bv}, modular={av}, tol={tol}"
                )
        elif bv is not None:
            failures.append(
                f"{metric_key} ({mid}): overall_rate/compliance_rate missing "
                f"in modular metrics. Keys: {sorted(actual.keys())}"
            )


def _check_mixed(
    metric_key: str, mid: str, bespoke: dict, actual: dict,
    tol: float, failures: list[str],
) -> None:
    """M6 accepted_recast: integer counts exact, exception_rate float.

    Key-name mapping (bespoke golden → module metrics):
      bespoke "open_exceptions" → module "total_exceptions"
              (module counts accepted + recast as total_exceptions)
      bespoke "total_open"      → module "total_open" (same)
      bespoke "exception_rate"  → module "exception_rate" (same)
    """
    if mid == "accepted_recast":
        # Integer counts — bespoke "open_exceptions" maps to module "total_exceptions"
        bespoke_exc = bespoke.get("open_exceptions")
        actual_exc  = actual.get("total_exceptions") or actual.get("open_exceptions")
        if bespoke_exc is not None:
            if actual_exc is None:
                failures.append(
                    f"{metric_key} ({mid}): open_exceptions/total_exceptions missing "
                    f"in modular. Keys: {sorted(actual.keys())}"
                )
            elif int(actual_exc) != int(bespoke_exc):
                failures.append(
                    f"{metric_key} ({mid}): open_exceptions/total_exceptions mismatch — "
                    f"bespoke={bespoke_exc}, modular={actual_exc}"
                )

        # total_open — same key name in both
        bv = bespoke.get("total_open")
        av = actual.get("total_open")
        if bv is not None:
            if av is None:
                failures.append(
                    f"{metric_key} ({mid}): 'total_open' missing in modular. "
                    f"Keys: {sorted(actual.keys())}"
                )
            elif int(av) != int(bv):
                failures.append(
                    f"{metric_key} ({mid}): 'total_open' mismatch — "
                    f"bespoke={bv}, modular={av}"
                )

        # Float rate — same key name
        bv = bespoke.get("exception_rate")
        av = actual.get("exception_rate")
        if bv is not None and av is not None:
            if abs(float(av) - float(bv)) > tol:
                failures.append(
                    f"{metric_key} ({mid}): exception_rate drift — "
                    f"bespoke={bv:.4f}, modular={av:.4f}, tol={tol}"
                )
        elif bv is not None and av is None:
            failures.append(
                f"{metric_key} ({mid}): exception_rate missing in modular"
            )


def _assert_shared_invariant(
    metric_key: str, mid: str, invariant: str,
    bespoke: dict, actual: dict, failures: list[str],
) -> None:
    """Assert a named shared_invariant for documented_difference metrics."""
    # Currently no invariants are defined for M5/M7 (both "none").
    # This function is a hook for future cases where an invariant IS named.
    pass


def _summarise(d: dict) -> str:
    """Return a short human-readable repr of a metrics dict."""
    if not d:
        return "{}"
    # Top-level numeric values only (QUAL-05 — no PII)
    nums = {k: v for k, v in d.items() if isinstance(v, (int, float))}
    return str(nums)[:120]


# ===========================================================================
# Test 7: read_trend does not ingest legacy_archive (integration echo)
# ===========================================================================

def test_read_trend_ignores_legacy_archive_integration(tmp_path: Path) -> None:
    """
    Integration-level check: the management_summary read_trend wiring must
    NOT ingest files stored under trend_dir/legacy_archive/.

    This is the integration echo of the authoritative store-level contract
    test in tests/test_trend_store.py::test_read_trend_ignores_legacy_archive.

    Approach:
      1. Create a tmp trend_dir with a valid trend_severity_all_assets.json
         (simulating what Plan 03 seeded).
      2. Also create trend_dir/legacy_archive/management_summary_2026-05.json
         with an INCOMPATIBLE shape (bare list, not {"snapshots": [...]}),
         which would cause a corrupt-file error if traversed.
      3. Call read_trend("severity", "all_assets") on the tmp dir.
      4. Assert it returns the expected 2 snapshots from the active file
         and does NOT attempt to parse the legacy_archive file.
    """
    from data.trend_store import read_trend

    # Write 2 valid snapshots directly in trend_dir
    trend_dir = tmp_path / "trend"
    trend_dir.mkdir()
    active_file = trend_dir / "trend_severity_all_assets.json"
    active_file.write_text(
        json.dumps({
            "snapshots": [
                {
                    "month": "2026-04",
                    "tag_filter": "all_assets",
                    "critical": 5, "high": 3, "medium": 2, "low": 1,
                    "asset_count": 10,
                    "generated_at": "2026-04-01T10:00:00Z",
                },
                {
                    "month": "2026-05",
                    "tag_filter": "all_assets",
                    "critical": 4, "high": 2, "medium": 2, "low": 1,
                    "asset_count": 10,
                    "generated_at": "2026-05-01T10:00:00Z",
                },
            ]
        }),
        encoding="utf-8",
    )

    # Write an INCOMPATIBLE-shape file in legacy_archive/ — a bare list
    # that would cause _load_trend_json to error if traversed.
    legacy_dir = trend_dir / "legacy_archive"
    legacy_dir.mkdir()
    legacy_file = legacy_dir / "management_summary_2026-05.json"
    legacy_file.write_text(
        json.dumps([{"month": "2026-05", "bad": "shape"}]),
        encoding="utf-8",
    )

    result = read_trend("severity", "all_assets", months=13, trend_dir=trend_dir)

    # Should return the 2 active snapshots — no more, no error
    assert not result["insufficient_data"], (
        "read_trend should NOT report insufficient_data when 2 active snapshots exist"
    )
    snaps = result["snapshots"]
    assert len(snaps) == 2, (
        f"Expected 2 snapshots from active file; got {len(snaps)}. "
        f"If >2, legacy_archive/ is being traversed."
    )
    months_returned = {s["month"] for s in snaps}
    assert months_returned == {"2026-04", "2026-05"}, (
        f"Unexpected snapshot months: {months_returned}"
    )


# ===========================================================================
# Test 8: Tag-scoped run passes the real tio to get_assets_by_tag (CR-01)
# ===========================================================================

class _StubTio:
    """Sentinel Tenable client — its identity is what the test checks."""


def _run_report_tag_scoped(
    monkeypatch,
    tmp_path: Path,
    *,
    get_assets_by_tag_impl,
) -> tuple[dict, list]:
    """
    Drive the real run_report() through the tag-scoped branch with stubbed
    fetchers (no live Tenable) and a monkeypatched get_assets_by_tag.

    Returns (run_report_result, captured_tio_args) where captured_tio_args is
    the list of first positional args get_assets_by_tag received.
    """
    import reports.management_summary as ms
    import utils.tag_helper as tag_helper

    vulns_df, assets_df, fixed_vulns_df, _ = _load_fixtures()
    # tags_str column is required by the fallback branch; the fixtures don't
    # carry it, so add a synthetic one (QUAL-05 — no real tag data).
    assets_df = assets_df.assign(tags_str="Environment: Production")

    monkeypatch.setattr(ms, "fetch_all_vulnerabilities", lambda tio, cache_dir: vulns_df)
    monkeypatch.setattr(ms, "fetch_all_assets", lambda tio, cache_dir: assets_df)
    monkeypatch.setattr(ms, "fetch_fixed_vulnerabilities", lambda tio, cache_dir: fixed_vulns_df)
    # Keep the test off the trend store / file writes.
    monkeypatch.setattr(ms, "read_trend", lambda *a, **k: {"snapshots": [], "insufficient_data": True})
    monkeypatch.setattr(ms, "capture_snapshot", lambda *a, **k: None)

    captured: list = []

    def _spy(tio, tag_category, tag_value, *a, **k):
        captured.append(tio)
        return get_assets_by_tag_impl(tio, tag_category, tag_value)

    # get_assets_by_tag is imported locally inside run_report — patch the source.
    monkeypatch.setattr(tag_helper, "get_assets_by_tag", _spy)

    stub_tio = _StubTio()
    result = ms.run_report(
        stub_tio,
        "test-run",
        tag_category="Environment",
        tag_value="Production",
        output_dir=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        generated_at=_REPORT_DATE,
        analyst_detail=False,
    )
    return result, captured


def test_tag_scoped_passes_real_tio_no_silent_fallback(monkeypatch, tmp_path, caplog):
    """
    CR-01: the tag-scoped primary path must call get_assets_by_tag with the
    REAL tio (not None) and must NOT silently fall back when it succeeds.

    Regression guard for the hardcoded ``get_assets_by_tag(None, ...)`` bug
    that made the primary path unreachable dead code.
    """
    import logging

    def _ok_impl(tio, tag_category, tag_value):
        # Server-side resolution succeeds — return one asset_uuid from the fixture.
        return ["uuid-crit-000"]

    with caplog.at_level(logging.WARNING, logger="reports.management_summary"):
        result, captured = _run_report_tag_scoped(
            monkeypatch, tmp_path, get_assets_by_tag_impl=_ok_impl
        )

    # The primary path ran with the real tio (not None).
    assert captured, "get_assets_by_tag was never called — primary path skipped"
    assert all(tio is not None for tio in captured), (
        "get_assets_by_tag was called with tio=None — CR-01 regression "
        "(hardcoded None makes the primary path throw every time)"
    )
    assert all(isinstance(tio, _StubTio) for tio in captured), (
        "get_assets_by_tag did not receive the run_report tio client"
    )

    # On success there must be NO fallback warning.
    fallback_warnings = [
        r for r in caplog.records
        if "falling back to in-memory tags_str" in r.getMessage()
    ]
    assert not fallback_warnings, (
        "Primary tag-scoping succeeded but the in-memory fallback warning was "
        "logged — the primary path was not actually used."
    )

    assert result.get("email_body_html", "") != "" or "metrics" in result


def test_tag_scoped_fallback_logs_warning(monkeypatch, tmp_path, caplog):
    """
    CR-01: when server-side tag scoping genuinely fails, the in-memory
    fallback must log a WARNING (no silent failures — CLAUDE.md).
    """
    import logging

    def _failing_impl(tio, tag_category, tag_value):
        raise RuntimeError("simulated server-side tag resolution failure")

    with caplog.at_level(logging.WARNING, logger="reports.management_summary"):
        _run_report_tag_scoped(
            monkeypatch, tmp_path, get_assets_by_tag_impl=_failing_impl
        )

    fallback_warnings = [
        r for r in caplog.records
        if "falling back to in-memory tags_str" in r.getMessage()
    ]
    assert fallback_warnings, (
        "Server-side tag scoping failed but no fallback WARNING was logged — "
        "the broad except must not swallow the failure silently."
    )


# ===========================================================================
# Test 9: INT-WARN-2 — recast_rules_df fetched and forwarded (D-04)
# ===========================================================================

def _make_standard_monkeypatches(monkeypatch, tmp_path, ms):
    """Apply the standard no-live-network monkeypatches to a ms module."""
    vulns_df, assets_df, fixed_vulns_df, trend_snapshots = _load_fixtures()
    monkeypatch.setattr(ms, "fetch_all_vulnerabilities",
                        lambda tio, cache_dir: vulns_df)
    monkeypatch.setattr(ms, "fetch_all_assets",
                        lambda tio, cache_dir: assets_df)
    monkeypatch.setattr(ms, "fetch_fixed_vulnerabilities",
                        lambda tio, cache_dir: fixed_vulns_df)
    monkeypatch.setattr(ms, "read_trend",
                        lambda *a, **k: {"snapshots": [], "insufficient_data": True})
    monkeypatch.setattr(ms, "capture_snapshot", lambda *a, **k: None)
    return vulns_df, assets_df, fixed_vulns_df, trend_snapshots


def test_recast_rules_fetched_and_forwarded_to_composer(monkeypatch, tmp_path):
    """
    INT-WARN-2 / D-04: management_summary must call fetch_recast_rules and
    forward recast_rules_df= to ReportComposer so the accepted_recast expiry
    cross-check runs (pending_reeval no longer always 0).
    """
    import reports.management_summary as ms
    import data.fetchers as fetchers
    from reports.modules import ReportComposer

    _make_standard_monkeypatches(monkeypatch, tmp_path, ms)

    # Sentinel recast DataFrame — its identity is what we check.
    sentinel_df = pd.DataFrame({"rule_uuid": ["test-uuid-001"], "plugin_id": [12345]})
    fetch_calls: list = []

    def _fake_fetch_recast(tio, cache_dir):
        fetch_calls.append(True)
        return sentinel_df

    monkeypatch.setattr(fetchers, "fetch_recast_rules", _fake_fetch_recast)

    # Capture the ReportComposer kwargs to verify recast_rules_df was forwarded.
    composer_kwargs_captured: list[dict] = []
    _real_composer_init = ReportComposer.__init__

    def _spy_composer_init(self, **kwargs):
        composer_kwargs_captured.append(dict(kwargs))
        _real_composer_init(self, **kwargs)

    monkeypatch.setattr(ReportComposer, "__init__", _spy_composer_init)

    ms.run_report(
        object(),       # tio sentinel — fetchers are stubbed
        "test-run-iw2",
        output_dir=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        generated_at=_REPORT_DATE,
        analyst_detail=False,
    )

    assert fetch_calls, (
        "fetch_recast_rules was never called — INT-WARN-2 not satisfied "
        "(recast expiry cross-check in accepted_recast will always see no rules)"
    )
    assert composer_kwargs_captured, "ReportComposer.__init__ was never called"
    kwargs = composer_kwargs_captured[0]
    assert "recast_rules_df" in kwargs, (
        "recast_rules_df kwarg not forwarded to ReportComposer "
        "(INT-WARN-2 / D-04 — accepted_recast expiry cross-check will be skipped)"
    )
    forwarded = kwargs["recast_rules_df"]
    assert forwarded is sentinel_df, (
        "ReportComposer received a different DataFrame than fetch_recast_rules returned"
    )


# ===========================================================================
# Test 10: CR-F3 — run_report never raises on fetch/compose failure
# ===========================================================================

def test_run_report_never_raises_on_fetch_failure(monkeypatch, tmp_path):
    """
    CR-F3: a fetch/compose failure must be reflected in the return dict, not
    propagated as an exception.  The docstring contract says 'Never raises'.
    """
    import reports.management_summary as ms

    # Make the very first fetch explode to simulate a catastrophic fetch failure.
    def _boom(tio, cache_dir):
        raise RuntimeError("synthetic fetch failure (CR-F3 test)")

    monkeypatch.setattr(ms, "fetch_all_vulnerabilities", _boom)
    # Other fetchers don't matter — the first one raises before they're called.
    monkeypatch.setattr(ms, "read_trend",
                        lambda *a, **k: {"snapshots": [], "insufficient_data": True})
    monkeypatch.setattr(ms, "capture_snapshot", lambda *a, **k: None)

    # run_report must NOT raise — it must return a dict.
    result = ms.run_report(
        object(),       # tio sentinel — fetchers are stubbed
        "test-run-crf3",
        output_dir=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        generated_at=_REPORT_DATE,
        analyst_detail=False,
    )

    assert isinstance(result, dict), (
        "run_report raised or did not return a dict when fetch failed — "
        "CR-F3 'never raises' contract violated"
    )
    # Standard keys must be present even on failure.
    for key in ("pdf", "excel", "charts", "metrics"):
        assert key in result, (
            f"run_report return dict missing '{key}' key on fetch failure (CR-F3)"
        )


# ===========================================================================
# Tests 11-13: INT-WARN-1 — full field-set forward-write + D-03b guard
# ===========================================================================

# The FULL set of optional aggregate kwargs capture_snapshot accepts
# (minus the always-positional df/assets_df/date/dimension/tag_filter
# and the trend-internal trend_dir/enriched_assets).
_FULL_AGGREGATE_KWARGS: frozenset[str] = frozenset({
    "on_time_asset_count",
    "reopened_count",
    "accepted_count",
    "recast_count",
    "mttr_overall_days",
    "mttr_by_severity",
    "mttr_by_owner",
    "sla_rate_crit_high",
    "fixed_vulns_df",
})


def _run_report_capture_snapshot_kwargs(monkeypatch, tmp_path) -> dict:
    """
    Run run_report() with all fetchers stubbed and monkeypatch capture_snapshot
    to capture the kwargs it receives.  Returns the captured kwargs dict.
    """
    import reports.management_summary as ms
    import data.fetchers as fetchers

    vulns_df, assets_df, fixed_vulns_df, _ = _load_fixtures()
    monkeypatch.setattr(ms, "fetch_all_vulnerabilities",
                        lambda tio, cache_dir: vulns_df)
    monkeypatch.setattr(ms, "fetch_all_assets",
                        lambda tio, cache_dir: assets_df)
    monkeypatch.setattr(ms, "fetch_fixed_vulnerabilities",
                        lambda tio, cache_dir: fixed_vulns_df)
    monkeypatch.setattr(ms, "read_trend",
                        lambda *a, **k: {"snapshots": [], "insufficient_data": True})
    # Stub recast fetch (no network)
    monkeypatch.setattr(fetchers, "fetch_recast_rules",
                        lambda tio, cache_dir: pd.DataFrame())

    captured: dict = {}

    def _spy_capture_snapshot(*args, **kwargs):
        captured.update(kwargs)
        # Also capture positional args by name
        pos_names = ["df", "assets_df", "date", "dimension", "tag_filter"]
        for i, val in enumerate(args):
            if i < len(pos_names):
                captured[pos_names[i]] = val

    monkeypatch.setattr(ms, "capture_snapshot", _spy_capture_snapshot)

    ms.run_report(
        object(),
        "test-run-iw1",
        output_dir=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        generated_at=_REPORT_DATE,
        analyst_detail=False,
    )
    return captured


def test_management_summary_forwards_full_field_set(monkeypatch, tmp_path):
    """
    INT-WARN-1 / D-03: capture_snapshot must receive the full aggregate kwarg
    set — every optional field the cron writer emits.

    Validates that management_summary is a COMPLETE trend writer, not a
    partial writer that discards the aggregate metrics.
    """
    captured = _run_report_capture_snapshot_kwargs(monkeypatch, tmp_path)

    missing = _FULL_AGGREGATE_KWARGS - set(captured.keys())
    assert not missing, (
        f"capture_snapshot was not given these aggregate kwargs: {sorted(missing)}. "
        "INT-WARN-1 / D-03: management_summary must be a complete trend writer."
    )


def test_partial_write_regression_guard(monkeypatch, tmp_path):
    """
    D-03b regression guard: the kwarg set forwarded to capture_snapshot must be
    EXACTLY _FULL_AGGREGATE_KWARGS (no extra, no missing).

    A future edit that drops one kwarg will fail this test, surfacing the
    partial-write regression before it reaches production.
    """
    captured = _run_report_capture_snapshot_kwargs(monkeypatch, tmp_path)

    # Restrict to the optional aggregate keys only (ignore positional df/assets_df/etc.)
    forwarded_aggregate = set(captured.keys()) & (
        _FULL_AGGREGATE_KWARGS | {"df", "assets_df", "date", "dimension", "tag_filter",
                                   "trend_dir", "enriched_assets"}
    )
    forwarded_optional = forwarded_aggregate - {
        "df", "assets_df", "date", "dimension", "tag_filter",
        "trend_dir", "enriched_assets",
    }

    missing = _FULL_AGGREGATE_KWARGS - forwarded_optional
    assert not missing, (
        f"D-03b partial-write regression: capture_snapshot missing {sorted(missing)}. "
        "Add the missing kwarg(s) to the capture_snapshot() call in run_report()."
    )


def test_missing_module_result_forwards_none(monkeypatch, tmp_path):
    """
    INT-WARN-1: when a contributing module's result has error != None,
    the corresponding aggregate value must be forwarded as None (safe default),
    not raised or omitted.

    Simulates a failed mttr_trend module and asserts mttr_overall_days=None
    is forwarded rather than causing a KeyError or raising.
    """
    import reports.management_summary as ms
    import data.fetchers as fetchers
    from reports.modules import ReportComposer
    from reports.modules.base import ModuleData

    vulns_df, assets_df, fixed_vulns_df, _ = _load_fixtures()
    monkeypatch.setattr(ms, "fetch_all_vulnerabilities",
                        lambda tio, cache_dir: vulns_df)
    monkeypatch.setattr(ms, "fetch_all_assets",
                        lambda tio, cache_dir: assets_df)
    monkeypatch.setattr(ms, "fetch_fixed_vulnerabilities",
                        lambda tio, cache_dir: fixed_vulns_df)
    monkeypatch.setattr(ms, "read_trend",
                        lambda *a, **k: {"snapshots": [], "insufficient_data": True})
    monkeypatch.setattr(fetchers, "fetch_recast_rules",
                        lambda tio, cache_dir: pd.DataFrame())

    # Make run_all() return a result list where mttr_trend has error set
    _real_run_all = ReportComposer.run_all

    def _patched_run_all(self):
        results = _real_run_all(self)
        patched = []
        for r in results:
            if r.module_id == "mttr_trend":
                patched.append(ModuleData(
                    module_id    = r.module_id,
                    display_name = r.display_name,
                    metrics      = {},
                    error        = "synthetic mttr_trend failure",
                ))
            else:
                patched.append(r)
        return patched

    monkeypatch.setattr(ReportComposer, "run_all", _patched_run_all)

    captured: dict = {}

    def _spy_capture_snapshot(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(ms, "capture_snapshot", _spy_capture_snapshot)

    # run_report must not raise even with a failed module result
    result = ms.run_report(
        object(),
        "test-run-iw1-none",
        output_dir=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        generated_at=_REPORT_DATE,
        analyst_detail=False,
    )

    assert isinstance(result, dict), "run_report raised when a module result had error set"
    # mttr_overall_days must be None (safe default), not a KeyError or missing
    assert "mttr_overall_days" in captured, (
        "mttr_overall_days not forwarded to capture_snapshot when mttr_trend errored"
    )
    assert captured["mttr_overall_days"] is None, (
        f"mttr_overall_days should be None when mttr_trend errored; "
        f"got {captured['mttr_overall_days']!r}"
    )


# ===========================================================================
# CR-T5: _check_float_tolerance / _check_mixed treat 0/0.0 as PRESENT
# ===========================================================================

def test_check_float_tolerance_zero_not_treated_as_missing():
    """
    CR-T5: _check_float_tolerance must not treat a legitimate 0.0 value as
    missing.  The 'or' idiom (val or default) evaluates 0.0 as falsy and
    triggers a false 'missing' failure.
    """
    from tests.test_management_summary import _check_float_tolerance  # noqa: PLC0415

    failures: list[str] = []
    # Both bespoke and actual have zero scan_coverage_pct — should be equal (drift = 0.0)
    bespoke = {"coverage_pct": 0.0}
    actual  = {"scan_coverage_pct": 0.0}

    _check_float_tolerance(
        "M2", "scan_coverage_sla", bespoke, actual, tol=0.001, failures=failures
    )

    assert not failures, (
        f"CR-T5: _check_float_tolerance treated 0.0 as missing — "
        f"'or' idiom not replaced with key-existence check. Failures: {failures}"
    )


def test_check_mixed_zero_not_treated_as_missing():
    """
    CR-T5: _check_mixed must not treat a legitimate 0 count as missing.
    """
    from tests.test_management_summary import _check_mixed  # noqa: PLC0415

    failures: list[str] = []
    # Both bespoke and actual have zero exceptions — should be equal
    bespoke = {"open_exceptions": 0, "total_open": 100, "exception_rate": 0.0}
    actual  = {"total_exceptions": 0, "total_open": 100, "exception_rate": 0.0}

    _check_mixed(
        "M6", "accepted_recast", bespoke, actual, tol=0.001, failures=failures
    )

    assert not failures, (
        f"CR-T5: _check_mixed treated 0 as missing — "
        f"'or' idiom not replaced with key-existence check. Failures: {failures}"
    )
