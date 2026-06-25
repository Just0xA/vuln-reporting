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

def _ts(ref: datetime | pd.Timestamp, days_ago: int | None) -> pd.Timestamp:
    """Return a UTC Timestamp `days_ago` days before `ref`, or NaT."""
    if days_ago is None:
        return pd.NaT
    dt = ref - timedelta(days=days_ago)
    # If `ref` is already tz-aware (datetime or pd.Timestamp), use tz_convert
    # rather than passing tz= to pd.Timestamp (which raises on tz-aware inputs).
    ts = pd.Timestamp(dt)
    if ts.tzinfo is None:
        return ts.tz_localize("UTC")
    return ts.tz_convert("UTC")


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

        # CR-T3: exact/zero-tolerance assertion — a dropped add-back row fails this.
        # (Previously used a loose tolerance band; tightened to == per CR-T3 so that
        # dropping rows 3 or 4 — the fixed-after-M add-backs — is immediately caught.)
        for sev, expected in captured_counts.items():
            got = reconstructed_counts.get(sev, 0)
            assert got == expected, (
                f"open_findings_at add-back: severity={sev}: expected {expected} rows, "
                f"got {got}. CR-B1: add-back rows (fixed after boundary) must not be "
                f"dropped from the boundary open count."
            )

        # Confirm within_tolerance still passes (it must, given exact match above)
        assert within_tolerance(captured_counts, reconstructed_counts)


# ---------------------------------------------------------------------------
# CR-T3 companion: add-back rows preserve original fixed metadata
# ---------------------------------------------------------------------------

class TestAddBackMetadataPreserved:
    """
    CR-B1 / CR-T3: The state flip that makes add-back rows visible to
    open_findings_at is LOCAL to the boundary check only.  The original fixed
    state and last_fixed metadata on the fixed_df rows must be unchanged after
    reconstruct_month returns (no in-place mutation of the caller's DataFrames).
    """

    def test_addback_original_metadata_preserved(self) -> None:
        from datetime import timedelta

        from scripts.backfill_trend_reconstruction import reconstruct_month

        month = "2025-10"
        boundary = month_end_utc(month)

        fixed_rows = [
            {
                "state": "fixed",
                "severity": "critical",
                "first_found": boundary - timedelta(days=60),
                "last_fixed": boundary + timedelta(days=5),  # fixed AFTER boundary → add-back
                "resurfaced_date": pd.NaT,
            }
        ]
        fixed_df = _make_vuln_df(fixed_rows)
        # Capture state before call
        state_before = fixed_df["state"].iloc[0]
        last_fixed_before = fixed_df["last_fixed"].iloc[0]

        current_open_df = _make_vuln_df([])
        reconstruct_month(current_open_df, fixed_df, month)

        # Original fixed_df must be unchanged (no in-place mutation)
        assert fixed_df["state"].iloc[0] == state_before, (
            "CR-B1: reconstruct_month must not mutate fixed_df state column"
        )
        assert fixed_df["last_fixed"].iloc[0] == last_fixed_before, (
            "CR-B1: reconstruct_month must not mutate fixed_df last_fixed column"
        )


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

        # Pre-write a captured snapshot for this month.
        # The overlap gate compares the captured month against reconstruction, so we need
        # the finding frame to match the captured counts within tolerance — otherwise the
        # gate fails (correctly!) before we can test the skip behavior.
        # Use 1 critical finding and a captured snapshot of {critical: 1}.
        original_counts = {"critical": 1, "high": 0, "medium": 0, "low": 0}
        _write_captured_snapshot(tmp_path, month, original_counts)

        # Frame that matches the captured counts: 1 critical open at boundary
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

        # The captured snapshot must still be present and untouched
        snaps = _load_snapshots(tmp_path)
        captured_snaps = [s for s in snaps if s.get("source") == "captured"]
        assert len(captured_snaps) >= 1, "Captured snapshot must still exist"
        oct_captured = [s for s in captured_snaps if s.get("month") == month]
        assert len(oct_captured) == 1
        assert oct_captured[0]["critical"] == 1, (
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

        # The original 2025-10 reconstructed snapshot must not be overwritten.
        # The script may write OTHER months (2025-11 onward); only 2025-10 must be skipped.
        snaps = _load_snapshots(tmp_path)
        oct_reconstructed = [
            s for s in snaps
            if s.get("source") == "reconstructed" and s.get("month") == month
        ]
        assert len(oct_reconstructed) == 1, (
            "Exactly one reconstructed entry for 2025-10 must exist"
        )
        assert oct_reconstructed[0]["critical"] == 7, (
            "Reconstructed snapshot for 2025-10 must not be overwritten on second run"
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
        produced_months = set(reconstructed.keys())

        # CR-T4: assert the expected taper/non-taper month set EXISTS before checking flags.
        # Without this pre-check the flag assertions silently pass when the months were
        # never written (the `if month in reconstructed` guards would skip everything).
        expected_taper_months = {"2025-06", "2025-07", "2025-08"}
        assert produced_months >= expected_taper_months, (
            f"CR-T4: expected taper months not produced: "
            f"{expected_taper_months - produced_months}. "
            f"Produced: {produced_months}"
        )

        # Taper months: Jun, Jul, Aug 2025 → partial=True
        for taper_month in ("2025-06", "2025-07", "2025-08"):
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
        A REOPENED finding whose last_fixed is at 00:00:00 Nov 1 (the first instant
        of the next month) and resurfaced even later is NOT closed at Oct 31 23:59:59
        boundary — because last_fixed (Nov 1 00:00:00) > boundary (Oct 31 23:59:59),
        so the REOPENED fixed-gap clause does not apply, and the finding is open.

        Note: state="fixed" is terminal in open_findings_at (clause 1 always excludes
        it regardless of last_fixed). The boundary test for "fixed after D still open"
        must use state="reopened" which is only fixed during [last_fixed, resurfaced_date).
        """
        from utils.open_count import open_findings_at

        month = "2025-10"
        boundary = month_end_utc(month)

        # First instant of the next month — AFTER the Oct 31 23:59:59 boundary
        next_month_start = pd.Timestamp("2025-11-01 00:00:00", tz="UTC")
        # Resurfaced even later (confirming it's in the open interval at boundary)
        resurfaced = pd.Timestamp("2025-11-15 00:00:00", tz="UTC")

        # REOPENED finding: last_fixed at Nov 1 00:00:00, resurfaced Nov 15.
        # At Oct 31 23:59:59: last_fixed (Nov 1) > boundary → NOT in the fixed gap
        # → the finding is open at boundary.
        rows = [
            {
                "state": "reopened",
                "severity": "critical",
                "first_found": pd.Timestamp("2025-10-01 00:00:00", tz="UTC"),
                "last_fixed": next_month_start,
                "resurfaced_date": resurfaced,
            }
        ]
        df = _make_vuln_df(rows)
        open_at_boundary = open_findings_at(df, boundary)
        assert len(open_at_boundary) == 1, (
            "REOPENED finding with last_fixed at 00:00:00 next month must be open at Oct 31 boundary "
            "(last_fixed > boundary, so REOPENED fixed-gap clause does not apply)"
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


# ---------------------------------------------------------------------------
# Test 11: Live-fetch branch passes cache_dir to both fetchers (regression)
# ---------------------------------------------------------------------------

class TestLoadDataframesPassesCacheDir:
    """
    Regression guard: _load_dataframes() live-fetch branch must pass cache_dir
    as the second positional argument to both fetch_all_vulnerabilities and
    fetch_fixed_vulnerabilities.

    Stubs are defined with the real required signature (tio, cache_dir, ...) so
    that a missing-arg call raises TypeError immediately — no live API needed.
    """

    def test_live_fetch_passes_cache_dir_to_both_fetchers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pathlib import Path as _Path

        received: dict[str, list] = {"open": [], "fixed": []}

        def stub_fetch_all_vulnerabilities(tio, cache_dir: _Path) -> pd.DataFrame:
            """Stub with the real required signature — missing cache_dir raises TypeError."""
            received["open"].append(cache_dir)
            return _make_vuln_df([])

        def stub_fetch_fixed_vulnerabilities(
            tio, cache_dir: _Path, lookback_days: int = 365
        ) -> pd.DataFrame:
            """Stub with the real required signature — missing cache_dir raises TypeError."""
            received["fixed"].append(cache_dir)
            return _make_vuln_df([])

        # Patch the fetchers at the location _load_dataframes imports them from
        monkeypatch.setattr(
            "data.fetchers.fetch_all_vulnerabilities",
            stub_fetch_all_vulnerabilities,
        )
        monkeypatch.setattr(
            "data.fetchers.fetch_fixed_vulnerabilities",
            stub_fetch_fixed_vulnerabilities,
        )

        # Patch get_client to avoid a real Tenable connection
        monkeypatch.setattr(
            "tenable_client.get_client",
            lambda: object(),
        )

        # Patch config.CACHE_DIR to a tmp dir so mkdir succeeds without touching the repo
        import config as _config
        monkeypatch.setattr(_config, "CACHE_DIR", tmp_path)

        from scripts.backfill_trend_reconstruction import _load_dataframes

        # Call without cache_dir → triggers live-fetch branch
        open_df, fixed_df = _load_dataframes(cache_dir=None)

        # Both fetchers must have been called with a Path (cache_dir was passed)
        assert len(received["open"]) == 1, (
            "fetch_all_vulnerabilities must be called exactly once"
        )
        assert isinstance(received["open"][0], _Path), (
            "fetch_all_vulnerabilities must receive a Path as cache_dir"
        )
        assert len(received["fixed"]) == 1, (
            "fetch_fixed_vulnerabilities must be called exactly once"
        )
        assert isinstance(received["fixed"][0], _Path), (
            "fetch_fixed_vulnerabilities must receive a Path as cache_dir"
        )
