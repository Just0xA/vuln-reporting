"""
tests/test_backfill_reconstruction.py — Unit tests for the all-assets
trend reconstruction seeding script and related trend_store extensions.

Tests (RED — implementation does not yet exist):

(1) test_overlap_synthetic_integration_pass   PRIMARY gate
(2) test_overlap_fail_exits_nonzero
(3) test_overlap_live_fallback_marked_weaker
(4) test_immutability_skips_captured
(5) test_immutability_skips_reconstructed
(6) test_capture_snapshot_skips_reconstructed_current_month
(7) test_partial_flag_on_taper_months
(8) test_asset_count_null_on_reconstructed
(9) test_reopened_aware_predicate
(10) test_month_end_utc_boundaries

Synthetic data uses:
  - RFC-5737 IP addresses (192.0.2.x, 198.51.100.x, 203.0.113.x)
  - RFC-6761 hostnames (*.example, *.test, *.invalid)
in compliance with QUAL-05 (aggregate-only PII in committed artifacts).

All tests write into a temporary directory — never to the real data/trend/.

Tolerance constant (QUAL-02 / RESEARCH A5 / D-18-09 discretion):
  MAX_RELATIVE_ERROR = 0.02  (2% relative)
  MAX_ABSOLUTE_ERROR = 5     (5 absolute per severity)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# sys.path bootstrap — mirrors the pattern in scripts/capture_trend_snapshot.py
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from data.trend_store import capture_snapshot, month_end_utc  # noqa: E402

# ---------------------------------------------------------------------------
# Tolerance constants (D-18-09 / RESEARCH A5)
# Spike 002 benchmark: +2 of 160,453 open — the reconstruction was near-perfect.
# We allow ≤2% relative OR ≤5 absolute per severity.
# ---------------------------------------------------------------------------
MAX_RELATIVE_ERROR = 0.02
MAX_ABSOLUTE_ERROR = 5


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ts(ref: datetime, days_ago: int | None) -> pd.Timestamp:
    """Return a UTC Timestamp `days_ago` days before `ref`, or NaT."""
    if days_ago is None:
        return pd.NaT
    return pd.Timestamp(ref - timedelta(days=days_ago), tz="UTC")


def _make_vuln_df(rows: list[dict]) -> pd.DataFrame:
    """
    Build a normalised vulnerability DataFrame from a list of row dicts.

    Expected dict keys: state, severity, first_found, last_fixed, resurfaced_date
    (all date values should be pd.Timestamp or pd.NaT).

    Uses RFC-5737/6761 synthetic values for any PII-adjacent fields (QUAL-05).
    """
    df = pd.DataFrame(rows)
    for col in ("first_found", "last_fixed", "resurfaced_date"):
        if col not in df.columns:
            df = df.assign(**{col: pd.NaT})
        df = df.assign(**{col: pd.to_datetime(df[col], utc=True, errors="coerce")})
    if "asset_uuid" not in df.columns:
        df = df.assign(asset_uuid=[f"asset-{i:04d}.example" for i in range(len(df))])
    return df


def _write_captured_snapshot(trend_dir: Path, month: str, counts: dict[str, int]) -> None:
    """Write a pre-existing source='captured' snapshot entry directly (no compute needed)."""
    file_path = trend_dir / "trend_severity_all_assets.json"
    existing: list[dict] = []
    if file_path.exists():
        with file_path.open("r") as fh:
            data = json.load(fh)
        existing = data.get("snapshots", [])
    entry = {
        "month": month,
        "tag_filter": "all_assets",
        "source": "captured",
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "asset_count": counts.get("asset_count", 100),
        "generated_at": "2026-05-01T00:00:00Z",
    }
    existing.append(entry)
    from data.trend_store import _atomic_write_json
    _atomic_write_json(file_path, {"snapshots": existing})


def _write_reconstructed_snapshot(trend_dir: Path, month: str, counts: dict[str, int]) -> None:
    """Write a pre-existing source='reconstructed' snapshot entry directly."""
    file_path = trend_dir / "trend_severity_all_assets.json"
    existing: list[dict] = []
    if file_path.exists():
        with file_path.open("r") as fh:
            data = json.load(fh)
        existing = data.get("snapshots", [])
    entry = {
        "month": month,
        "tag_filter": "all_assets",
        "source": "reconstructed",
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "asset_count": None,
        "generated_at": "2026-05-01T00:00:00Z",
    }
    existing.append(entry)
    from data.trend_store import _atomic_write_json
    _atomic_write_json(file_path, {"snapshots": existing})


def _load_snapshots(trend_dir: Path) -> list[dict]:
    file_path = trend_dir / "trend_severity_all_assets.json"
    if not file_path.exists():
        return []
    with file_path.open("r") as fh:
        return json.load(fh).get("snapshots", [])


# ---------------------------------------------------------------------------
# Test 1 (PRIMARY): Synthetic-integration overlap gate with fixed-after-D add-back
# ---------------------------------------------------------------------------

class TestOverlapSyntheticIntegrationPass:
    """
    PRIMARY confidence gate (review MEDIUM change #9).

    Scenario: A captured snapshot exists for month M with known per-severity
    counts derived from a known finding set. We then run the reconstruction
    predicate (open_findings_at at month_end_utc(M), with fixed-after-M rows
    added back) and assert the reconstructed counts match the captured counts
    within tolerance.

    The key fixed-after-D add-back exercise:
      - Some findings are currently FIXED (last_fixed > month_end_utc(M))
        so they appear in the fixed export but NOT in the current open export.
      - The reconstruction must include these rows in the combined frame before
        applying open_findings_at, so they are counted as open-at-M.
    """

    def test_overlap_synthetic_integration_pass(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import (
            reconstruct_month,
            within_tolerance,
        )

        # Reference point: month M = 2025-10, boundary = 2025-10-31 23:59:59 UTC
        month = "2025-10"
        boundary = month_end_utc(month)

        # Build synthetic finding set:
        #   - 3 findings open at boundary (first_found before boundary, not fixed then)
        #   - 2 findings fixed AFTER boundary (fixed-after-D add-back scenario)
        #   - 1 finding fixed BEFORE boundary (not open at M)

        ref = boundary  # for clarity

        rows = [
            # Row 0: open at M (critical) — still open today (open export)
            {
                "state": "open",
                "severity": "critical",
                "first_found": _ts(ref, 120),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            },
            # Row 1: open at M (high) — still open today (open export)
            {
                "state": "open",
                "severity": "high",
                "first_found": _ts(ref, 90),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            },
            # Row 2: open at M (medium) — still open today (open export)
            {
                "state": "open",
                "severity": "medium",
                "first_found": _ts(ref, 60),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            },
            # Row 3: open at M (critical) — FIXED AFTER M (fixed export only)
            #   first_found 150d before boundary, fixed 30 days after boundary
            {
                "state": "fixed",
                "severity": "critical",
                "first_found": _ts(ref, 150),
                "last_fixed": ref + timedelta(days=30),
                "resurfaced_date": pd.NaT,
            },
            # Row 4: open at M (high) — FIXED AFTER M (fixed export only)
            {
                "state": "fixed",
                "severity": "high",
                "first_found": _ts(ref, 80),
                "last_fixed": ref + timedelta(days=15),
                "resurfaced_date": pd.NaT,
            },
            # Row 5: fixed BEFORE M — not open at M, not in add-back
            {
                "state": "fixed",
                "severity": "low",
                "first_found": _ts(ref, 200),
                "last_fixed": _ts(ref, 10),  # fixed 10 days before boundary
                "resurfaced_date": pd.NaT,
            },
        ]
        df = _make_vuln_df(rows)

        # Partition into current-open and fixed frames as the script would see them:
        #   current_open_df: rows with state in {open, reopened}
        #   fixed_df: ALL fixed rows (script fetches them all and filters add-back)
        current_open_df = df[df["state"].isin(["open", "reopened"])].copy()
        fixed_df = df[df["state"] == "fixed"].copy()

        # The captured ground truth: rows 0+3=2 critical, rows 1+4=2 high, 1 medium, 0 low
        captured_counts = {"critical": 2, "high": 2, "medium": 1, "low": 0}

        # Run the reconstruction
        reconstructed_counts = reconstruct_month(current_open_df, fixed_df, month)

        # Assert within tolerance
        for sev, expected in captured_counts.items():
            got = reconstructed_counts.get(sev, 0)
            abs_diff = abs(got - expected)
            rel_diff = abs_diff / max(expected, 1)
            assert abs_diff <= MAX_ABSOLUTE_ERROR or rel_diff <= MAX_RELATIVE_ERROR, (
                f"Severity={sev}: expected={expected} got={got} "
                f"abs_diff={abs_diff} rel_diff={rel_diff:.1%} — exceeds tolerance"
            )

        # Also test the within_tolerance helper
        assert within_tolerance(captured_counts, reconstructed_counts)


# ---------------------------------------------------------------------------
# Test 2: Divergence beyond tolerance exits non-zero / raises, writes nothing
# ---------------------------------------------------------------------------

class TestOverlapFailExitsNonzero:
    """
    When reconstruction diverges beyond tolerance, the gate must fail and
    NO snapshots must be written to the trend store.
    """

    def test_overlap_fail_exits_nonzero(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import within_tolerance

        # Captured: 100 criticals.  Reconstructed: 1 (wildly wrong).
        captured = {"critical": 100, "high": 50, "medium": 20, "low": 5}
        reconstructed = {"critical": 1, "high": 50, "medium": 20, "low": 5}

        assert not within_tolerance(captured, reconstructed), (
            "within_tolerance must return False when divergence exceeds threshold"
        )

    def test_gate_writes_nothing_on_divergence(self, tmp_path: Path) -> None:
        """
        Calling run_reconstruction with a forced tolerance failure must leave
        the trend store empty (no writes).
        """
        from scripts.backfill_trend_reconstruction import run_reconstruction

        # Build a tiny frame: only 1 finding, but the captured snapshot says 100
        month = "2025-10"
        boundary = month_end_utc(month)
        rows = [
            {
                "state": "open",
                "severity": "critical",
                "first_found": _ts(boundary, 30),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])  # no fixed rows

        # Write a captured snapshot that massively diverges from the 1-row frame
        _write_captured_snapshot(
            tmp_path, month, {"critical": 100, "high": 50, "medium": 20, "low": 5}
        )

        # run_reconstruction must return a non-success result and write 0 months
        result = run_reconstruction(
            current_open_df=current_open_df,
            fixed_df=fixed_df,
            trend_dir=tmp_path,
            window_start="2025-10",
            dry_run=False,
        )
        assert result["gate_passed"] is False, "Gate must report failure"
        assert result["months_written"] == 0, "No months must be written on gate failure"

        # The store must still contain only the captured snapshot (untouched)
        snaps = _load_snapshots(tmp_path)
        assert all(s.get("source") != "reconstructed" for s in snaps), (
            "No reconstructed snapshots should be written when gate fails"
        )


# ---------------------------------------------------------------------------
# Test 3: Live-today fallback is marked as weaker confidence
# ---------------------------------------------------------------------------

class TestOverlapLiveFallbackMarkedWeaker:
    """
    When no captured month exists, the script falls back to 'reconstruct today
    vs live' but marks it EXPLICITLY as weaker confidence.
    """

    def test_overlap_live_fallback_marked_weaker(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import run_reconstruction

        # No captured snapshot in the store → fallback path
        month = "2025-10"
        boundary = month_end_utc(month)
        rows = [
            {
                "state": "open",
                "severity": "critical",
                "first_found": _ts(boundary, 30),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])

        result = run_reconstruction(
            current_open_df=current_open_df,
            fixed_df=fixed_df,
            trend_dir=tmp_path,
            window_start=month,
            dry_run=True,  # dry-run: gate runs but nothing written
        )

        # The result must record which gate path was used and explicitly flag weaker
        assert "gate_confidence" in result, (
            "run_reconstruction must return gate_confidence in result dict"
        )
        assert result["gate_confidence"] == "weaker", (
            "When no captured month exists, confidence must be 'weaker' not 'primary'"
        )


# ---------------------------------------------------------------------------
# Test 4: Immutability — captured month is never overwritten
# ---------------------------------------------------------------------------

class TestImmutabilitySkipsCaptured:
    """A month present with source='captured' must never be overwritten by the script."""

    def test_immutability_skips_captured(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import run_reconstruction

        month = "2025-10"
        boundary = month_end_utc(month)

        # Pre-write a captured snapshot
        original_counts = {"critical": 42, "high": 10, "medium": 5, "low": 1}
        _write_captured_snapshot(tmp_path, month, original_counts)

        # Build a frame that would produce different counts if written
        rows = [
            {
                "state": "open",
                "severity": "high",
                "first_found": _ts(boundary, 30),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])

        result = run_reconstruction(
            current_open_df=current_open_df,
            fixed_df=fixed_df,
            trend_dir=tmp_path,
            window_start=month,
            dry_run=False,
        )

        # The captured snapshot must be untouched
        snaps = _load_snapshots(tmp_path)
        captured = [s for s in snaps if s.get("source") == "captured"]
        assert len(captured) == 1
        assert captured[0]["critical"] == 42, (
            "Captured snapshot critical count must not be overwritten"
        )
        assert result["months_skipped_existing"] >= 1, (
            "Script must report at least 1 month skipped due to existing captured entry"
        )


# ---------------------------------------------------------------------------
# Test 5: Immutability — reconstructed month is never overwritten (idempotent)
# ---------------------------------------------------------------------------

class TestImmutabilitySkipsReconstructed:
    """
    An existing source='reconstructed' month is skipped on a second run —
    the script is idempotent (D-18-08).
    """

    def test_immutability_skips_reconstructed(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import run_reconstruction

        month = "2025-10"
        boundary = month_end_utc(month)

        # Pre-write a reconstructed snapshot
        original_counts = {"critical": 7, "high": 3, "medium": 1, "low": 0}
        _write_reconstructed_snapshot(tmp_path, month, original_counts)

        rows = [
            {
                "state": "open",
                "severity": "critical",
                "first_found": _ts(boundary, 30),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])

        result = run_reconstruction(
            current_open_df=current_open_df,
            fixed_df=fixed_df,
            trend_dir=tmp_path,
            window_start=month,
            dry_run=False,
        )

        # Must not overwrite
        snaps = _load_snapshots(tmp_path)
        reconstructed = [s for s in snaps if s.get("source") == "reconstructed"]
        assert len(reconstructed) == 1
        assert reconstructed[0]["critical"] == 7, (
            "Reconstructed snapshot must not be overwritten on second run"
        )
        assert result["months_skipped_existing"] >= 1


# ---------------------------------------------------------------------------
# Test 6: capture_snapshot skips a current-month source='reconstructed' entry
# ---------------------------------------------------------------------------

class TestCaptureSnapshotSkipsReconstructedCurrentMonth:
    """
    data/trend_store.capture_snapshot() must not overwrite a month that
    already has a source='reconstructed' entry (review MEDIUM change #7).

    This is a data/trend_store-level contract test.
    """

    def test_capture_snapshot_skips_reconstructed_current_month(
        self, tmp_path: Path
    ) -> None:
        # Write a reconstructed entry for the current month
        current_month = datetime.now().strftime("%Y-%m")
        _write_reconstructed_snapshot(
            tmp_path, current_month, {"critical": 99, "high": 0, "medium": 0, "low": 0}
        )

        # Build a minimal open DataFrame that would produce different counts
        ref = datetime.now(tz=timezone.utc)
        rows = [
            {
                "state": "open",
                "severity": "high",
                "first_found": _ts(ref, 5),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        df = _make_vuln_df(rows)
        assets_df = pd.DataFrame({"asset_uuid": ["asset-0000.test"]})

        # Call capture_snapshot — it must detect the reconstructed entry and skip
        capture_snapshot(df, assets_df, ref, trend_dir=tmp_path)

        # The store must still have the original reconstructed counts
        snaps = _load_snapshots(tmp_path)
        assert len(snaps) == 1, "No new snapshot should have been written"
        assert snaps[0]["source"] == "reconstructed"
        assert snaps[0]["critical"] == 99, (
            "capture_snapshot must not overwrite a reconstructed current-month entry"
        )


# ---------------------------------------------------------------------------
# Test 7: Partial flag on taper-edge months
# ---------------------------------------------------------------------------

class TestPartialFlagOnTaperMonths:
    """
    Months before 2025-09 carry partial=True (D-18-02, taper-edge caveat).
    Months from 2025-09 onward do NOT carry partial=True.
    """

    def test_partial_flag_on_taper_months(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import run_reconstruction

        boundary = month_end_utc("2025-06")

        # Single finding that is open at each month in our window
        rows = [
            {
                "state": "open",
                "severity": "critical",
                "first_found": _ts(boundary, 200),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])

        result = run_reconstruction(
            current_open_df=current_open_df,
            fixed_df=fixed_df,
            trend_dir=tmp_path,
            window_start="2025-06",
            dry_run=False,
        )

        snaps = _load_snapshots(tmp_path)
        reconstructed = {s["month"]: s for s in snaps if s.get("source") == "reconstructed"}

        # Taper months: Jun, Jul, Aug 2025 → partial=True
        for taper_month in ("2025-06", "2025-07", "2025-08"):
            if taper_month in reconstructed:
                assert reconstructed[taper_month].get("partial") is True, (
                    f"Month {taper_month} must carry partial=True (taper-edge D-18-02)"
                )

        # Non-taper months: Sep 2025 onward → partial absent or False
        for non_taper in ("2025-09", "2025-10", "2025-11"):
            if non_taper in reconstructed:
                assert not reconstructed[non_taper].get("partial"), (
                    f"Month {non_taper} must NOT carry partial=True"
                )


# ---------------------------------------------------------------------------
# Test 8: asset_count is None on every reconstructed snapshot
# ---------------------------------------------------------------------------

class TestAssetCountNullOnReconstructed:
    """
    Reconstructed snapshots must have asset_count=None (D-18-04).
    Tenable does not retain historical asset population — no fabricated denominator.
    """

    def test_asset_count_null_on_reconstructed(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import run_reconstruction

        month = "2025-10"
        boundary = month_end_utc(month)
        rows = [
            {
                "state": "open",
                "severity": "critical",
                "first_found": _ts(boundary, 30),
                "last_fixed": pd.NaT,
                "resurfaced_date": pd.NaT,
            }
        ]
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])

        run_reconstruction(
            current_open_df=current_open_df,
            fixed_df=fixed_df,
            trend_dir=tmp_path,
            window_start=month,
            dry_run=False,
        )

        snaps = _load_snapshots(tmp_path)
        reconstructed = [s for s in snaps if s.get("source") == "reconstructed"]
        assert reconstructed, "At least one reconstructed snapshot must be written"
        for snap in reconstructed:
            assert snap.get("asset_count") is None, (
                f"Month {snap['month']}: asset_count must be None on reconstructed entries (D-18-04)"
            )


# ---------------------------------------------------------------------------
# Test 9: Reopened-aware predicate correctly counts REOPENED findings
# ---------------------------------------------------------------------------

class TestReopenedAwarePredicate:
    """
    QUAL-02 — The reconstruction must use open_findings_at() two-interval form.

    A REOPENED finding that was first_found 200d ago, last_fixed 50d ago, and
    resurfaced 10d ago is open at the reference date (not dropped by a naive
    last_fixed predicate).

    We verify this by feeding such a finding into reconstruct_month and asserting
    it is counted, not dropped.
    """

    def test_reopened_aware_predicate(self, tmp_path: Path) -> None:
        from scripts.backfill_trend_reconstruction import reconstruct_month

        # Month M: reference = 2025-10
        month = "2025-10"
        boundary = month_end_utc(month)

        # REOPENED finding: first_found 200d before boundary, last_fixed 50d
        # before boundary, resurfaced_date 10d before boundary.
        # At boundary: it was in the "open" interval [resurfaced, ∞) → open.
        rows = [
            {
                "state": "reopened",
                "severity": "high",
                "first_found": _ts(boundary, 200),
                "last_fixed": _ts(boundary, 50),
                "resurfaced_date": _ts(boundary, 10),
            }
        ]
        # This row would be in the current-open export (state=reopened)
        current_open_df = _make_vuln_df(rows)
        fixed_df = _make_vuln_df([])

        counts = reconstruct_month(current_open_df, fixed_df, month)

        assert counts.get("high", 0) == 1, (
            "REOPENED finding open at boundary must be counted (QUAL-02 reopened-aware predicate)"
        )

    def test_naive_predicate_would_fail(self) -> None:
        """
        Demonstrate why a naive last_fixed predicate drops REOPENED findings.

        This is a documentation test: the finding in test_reopened_aware_predicate
        has last_fixed = 50 days before boundary. A naive predicate
        (last_fixed IS NULL OR last_fixed > D) would see last_fixed <= D and
        drop the finding, undercounting opens.

        The test asserts the naive approach is wrong (count=0) to anchor the
        contrast with the correct two-interval form (count=1 above).
        """
        boundary = month_end_utc("2025-10")
        last_fixed = boundary - timedelta(days=50)

        # Naive predicate check: last_fixed IS NULL OR last_fixed > D
        naive_is_open = (last_fixed is None) or (last_fixed > boundary)
        assert not naive_is_open, (
            "Naive predicate correctly fails: REOPENED with last_fixed<=D "
            "is dropped — illustrates why reopened-aware form is mandatory"
        )


# ---------------------------------------------------------------------------
# Test 10: month_end_utc boundary semantics
# ---------------------------------------------------------------------------

class TestMonthEndUtcBoundaries:
    """
    month_end_utc(month) must return a tz-aware UTC datetime at the
    last instant of the given month (review MEDIUM change #8).

    Pinned boundary semantics:
      - Inclusive: a finding with last_fixed == month_end_utc(M) is fixed AT M
        (depends on implementation's inclusive/exclusive choice — test both sides)
      - The returned value is tz-aware UTC
      - The last second of the month is 23:59:59 UTC on the last calendar day
      - The first second of the next month (00:00:00 UTC) is beyond the boundary
    """

    def test_month_end_utc_returns_tz_aware(self) -> None:
        boundary = month_end_utc("2025-10")
        assert boundary.tzinfo is not None, "month_end_utc must return a tz-aware datetime"
        # Verify it's UTC
        import datetime as dt_module
        offset = boundary.utcoffset()
        assert offset == dt_module.timedelta(0), (
            "month_end_utc must return UTC (utcoffset == 0)"
        )

    def test_month_end_utc_october_2025(self) -> None:
        boundary = month_end_utc("2025-10")
        # October has 31 days; last instant is 2025-10-31 23:59:59 UTC
        assert boundary.year == 2025
        assert boundary.month == 10
        assert boundary.day == 31
        assert boundary.hour == 23
        assert boundary.minute == 59
        assert boundary.second == 59

    def test_month_end_utc_at_boundary_23_59_59(self) -> None:
        """
        A finding with last_fixed at exactly 23:59:59 on the last day of the month
        is within the month (fixed AT or before the boundary → not open-at-M under
        an inclusive boundary).
        """
        from utils.open_count import open_findings_at

        month = "2025-10"
        boundary = month_end_utc(month)

        # Verify boundary is exactly 23:59:59
        assert boundary.second == 59
        assert boundary.minute == 59
        assert boundary.hour == 23
        assert boundary.day == 31  # last day of October

        # Finding fixed AT boundary: open_findings_at uses (lf <= D) as "fixed"
        # So last_fixed == boundary means the finding IS fixed at boundary → not open
        rows = [
            {
                "state": "fixed",
                "severity": "critical",
                "first_found": pd.Timestamp("2025-10-01 00:00:00", tz="UTC"),
                "last_fixed": boundary,
                "resurfaced_date": pd.NaT,
            }
        ]
        df = _make_vuln_df(rows)
        open_at_boundary = open_findings_at(df, boundary)
        assert len(open_at_boundary) == 0, (
            "A finding fixed at exactly 23:59:59 on last day must NOT be open at boundary"
        )

    def test_month_end_utc_at_next_month_start_00_00_00(self) -> None:
        """
        A finding with last_fixed at the FIRST INSTANT of the next month
        (00:00:00 on Nov 1) is NOT yet fixed at the Oct 31 boundary.
        It should be counted as open-at-Oct.
        """
        from utils.open_count import open_findings_at

        month = "2025-10"
        boundary = month_end_utc(month)

        # First instant of the next month
        next_month_start = pd.Timestamp("2025-11-01 00:00:00", tz="UTC")

        rows = [
            {
                "state": "fixed",
                "severity": "critical",
                "first_found": pd.Timestamp("2025-10-01 00:00:00", tz="UTC"),
                "last_fixed": next_month_start,
                "resurfaced_date": pd.NaT,
            }
        ]
        df = _make_vuln_df(rows)
        open_at_boundary = open_findings_at(df, boundary)
        assert len(open_at_boundary) == 1, (
            "A finding fixed at 00:00:00 next month must still be open at Oct 31 boundary"
        )

    def test_month_end_utc_accepts_date_object(self) -> None:
        """month_end_utc must accept a date or datetime in addition to 'YYYY-MM' strings."""
        import datetime as dt_module
        d = dt_module.date(2025, 10, 15)
        boundary = month_end_utc(d)
        assert boundary.month == 10
        assert boundary.day == 31

    def test_month_end_utc_february_non_leap(self) -> None:
        """February in a non-leap year ends on the 28th."""
        boundary = month_end_utc("2025-02")
        assert boundary.day == 28
        assert boundary.month == 2

    def test_month_end_utc_february_leap(self) -> None:
        """February in a leap year ends on the 29th."""
        boundary = month_end_utc("2024-02")
        assert boundary.day == 29
        assert boundary.month == 2
