#!/usr/bin/env python
"""One-time idempotent all-assets trend reconstruction seeding script.

Reconstructs ~12 months (2025-06 → now) of real MoM severity history for the
ALL-ASSETS scope (severity/all_assets) from Tenable's fixed+open exports and
seeds ``data/trend/trend_severity_all_assets.json`` with provenance-marked,
immutable, partial-flagged, null-asset_count snapshots.

SCOPE (review HIGH change #4 — D-18-08):
  Reconstruction is ALL-ASSETS-ONLY (tag_filter='all_assets').
  No per-tag-scope iteration is performed.  Tag-scoped delivery groups cold-start
  their MoM history, which is the pre-existing behavior for board_summary /
  composed_report (not a regression).

CURRENT-MONTH IMMUTABILITY (review MEDIUM change #7 — D-18-03):
  Reconstructed months — including the current month — are written once and
  never overwritten.  capture_snapshot() also honors this rule.  A second
  invocation of this script writes 0 new months (idempotent).

OVERLAP-TEST GATE (D-18-09):
  Before writing any reconstructed history the script validates the predicate
  against captured ground truth (PRIMARY gate) or against the live current-state
  open count (WEAKER fallback).  The script exits non-zero on divergence without
  writing anything.

Exit codes
----------
0   Success (or dry-run)
1   Overlap-test gate failed — divergence exceeds tolerance; nothing written
2   Usage error / argument error
3   Unexpected runtime error

Usage
-----
  python scripts/backfill_trend_reconstruction.py [--cache-dir PATH]
                                                   [--window-start YYYY-MM]
                                                   [--dry-run]

  --cache-dir PATH        Directory containing pre-fetched ``vulns_all.parquet``
                          and ``vulns_fixed.parquet`` (avoids a live API fetch).
  --window-start YYYY-MM  Earliest month to reconstruct (default: 2025-06).
  --dry-run               Run the overlap-test gate and print the plan but write
                          nothing to the trend store.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from data.trend_store import (  # noqa: E402
    TREND_DIR,
    _atomic_write_json,
    _load_trend_json,
    month_end_utc,
)
from utils.open_count import open_findings_at  # noqa: E402

import pandas as pd  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WINDOW_START = "2025-06"

# Months whose fixed-findings counts are at the taper-edge of Tenable retention
# (Jun–Aug 2025 sit in the noisy transition zone; see D-18-02, 18-CONTEXT.md).
_TAPER_MONTHS_BEFORE = "2025-09"  # exclusive upper bound for partial=True

# Tolerance for the overlap-test gate (RESEARCH A5 / D-18-09 discretion).
# Spike 002 benchmark: +2 of 160,453 — near-perfect reconstruction.
# Allow ≤2% relative OR ≤5 absolute per severity.
_MAX_RELATIVE_ERROR = 0.02
_MAX_ABSOLUTE_ERROR = 5


# ---------------------------------------------------------------------------
# Core helpers (importable from tests)
# ---------------------------------------------------------------------------


def month_end_utc_of_month_str(month: str) -> pd.Timestamp:
    """Convenience wrapper: return month_end_utc as a pd.Timestamp (UTC)."""
    return pd.Timestamp(month_end_utc(month))


def reconstruct_month(
    current_open_df: pd.DataFrame,
    fixed_df: pd.DataFrame,
    month: str,
) -> dict[str, int]:
    """
    Reconstruct per-severity open counts at the end of *month*.

    Uses the reopened-aware two-interval predicate via ``open_findings_at``
    (QUAL-02).  The reconstruction input is built as:

        combined = current-open rows  UNION  fixed rows where last_fixed > month_end_utc(month)

    The fixed-after-D rows are included because they were still open at the
    month-boundary (they got fixed AFTER M).  This is the "fixed-after-D add-back"
    that makes the reconstruction faithful for past months.

    Parameters
    ----------
    current_open_df : pd.DataFrame
        Open/reopened findings at the time the script runs.
    fixed_df : pd.DataFrame
        ALL fixed findings in the lookback window (from fetch_fixed_vulnerabilities).
    month : str
        ``"YYYY-MM"`` month key to reconstruct.

    Returns
    -------
    dict[str, int]
        ``{critical, high, medium, low}`` counts at month-end boundary.
    """
    boundary = pd.Timestamp(month_end_utc(month))

    # Fixed-after-D add-back: fixed rows where last_fixed > boundary
    # (these were still open at the month-end; they only got fixed after M).
    if not fixed_df.empty and "last_fixed" in fixed_df.columns:
        lf = pd.to_datetime(fixed_df["last_fixed"], utc=True, errors="coerce")
        add_back_mask = lf > boundary
        add_back_df = fixed_df[add_back_mask].copy()
    else:
        add_back_df = pd.DataFrame(columns=current_open_df.columns)

    # Build combined frame: current opens + fixed-after-D (which were open at M)
    if add_back_df.empty:
        combined = current_open_df.copy()
    elif current_open_df.empty:
        combined = add_back_df.copy()
    else:
        combined = pd.concat([current_open_df, add_back_df], ignore_index=True)

    # Apply the reopened-aware two-interval predicate at the month boundary
    open_at_boundary = open_findings_at(combined, boundary)

    # Count by severity
    if open_at_boundary.empty:
        counts: dict = {}
    else:
        counts = open_at_boundary.groupby("severity").size().to_dict()

    return {
        "critical": int(counts.get("critical", 0)),
        "high":     int(counts.get("high", 0)),
        "medium":   int(counts.get("medium", 0)),
        "low":      int(counts.get("low", 0)),
    }


def within_tolerance(
    captured: dict[str, int],
    reconstructed: dict[str, int],
) -> bool:
    """
    Return True if every severity in *captured* is within tolerance of *reconstructed*.

    Tolerance (RESEARCH A5 / D-18-09): ≤2% relative OR ≤5 absolute per severity.
    """
    for sev in ("critical", "high", "medium", "low"):
        expected = captured.get(sev, 0)
        got = reconstructed.get(sev, 0)
        abs_diff = abs(got - expected)
        rel_diff = abs_diff / max(expected, 1)
        if abs_diff > _MAX_ABSOLUTE_ERROR and rel_diff > _MAX_RELATIVE_ERROR:
            return False
    return True


def _is_taper_month(month: str) -> bool:
    """Return True if *month* is in the Jun–Aug 2025 taper-edge window (D-18-02)."""
    return month < _TAPER_MONTHS_BEFORE


def _months_in_range(window_start: str) -> list[str]:
    """
    Return all ``"YYYY-MM"`` month strings from *window_start* through the
    current month (inclusive), in ascending order.
    """
    from dateutil.relativedelta import relativedelta  # type: ignore[import]

    start_year, start_mon = int(window_start[:4]), int(window_start[5:7])
    now = datetime.now()
    end_year, end_mon = now.year, now.month

    months = []
    cur_year, cur_mon = start_year, start_mon
    while (cur_year, cur_mon) <= (end_year, end_mon):
        months.append(f"{cur_year:04d}-{cur_mon:02d}")
        cur_mon += 1
        if cur_mon > 12:
            cur_mon = 1
            cur_year += 1
    return months


def _months_in_range_stdlib(window_start: str) -> list[str]:
    """
    Return all ``"YYYY-MM"`` month strings from *window_start* through the
    current month (inclusive), using only stdlib (no dateutil dependency).
    """
    start_year, start_mon = int(window_start[:4]), int(window_start[5:7])
    now = datetime.now()
    end_year, end_mon = now.year, now.month

    months = []
    cur_year, cur_mon = start_year, start_mon
    while (cur_year, cur_mon) <= (end_year, end_mon):
        months.append(f"{cur_year:04d}-{cur_mon:02d}")
        cur_mon += 1
        if cur_mon > 12:
            cur_mon = 1
            cur_year += 1
    return months


def run_reconstruction(
    current_open_df: pd.DataFrame,
    fixed_df: pd.DataFrame,
    trend_dir: Path,
    window_start: str = DEFAULT_WINDOW_START,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Core reconstruction logic — importable by tests.

    Parameters
    ----------
    current_open_df : pd.DataFrame
        All open/reopened findings.
    fixed_df : pd.DataFrame
        All fixed findings in the lookback window.
    trend_dir : Path
        Trend store directory (default: TREND_DIR; tests pass a tmp_path).
    window_start : str
        Earliest month to reconstruct ("YYYY-MM").
    dry_run : bool
        If True, run the overlap gate and compute the plan but write nothing.

    Returns
    -------
    dict with keys:
      gate_passed : bool
      gate_confidence : str   "primary" | "weaker"
      months_written : int
      months_skipped_existing : int
      months_dry_run : int
      divergences : list[dict]   populated when gate fails
    """
    file_path = trend_dir / "trend_severity_all_assets.json"
    existing_snapshots = _load_trend_json(file_path)

    # Build a lookup of already-present months
    existing_by_month = {
        s.get("month"): s for s in existing_snapshots if s.get("tag_filter") == "all_assets"
    }

    # ------------------------------------------------------------------
    # Overlap-test gate (D-18-09)
    # ------------------------------------------------------------------
    # PRIMARY gate: find captured months and validate reconstruction against them
    captured_months = {
        month: snap
        for month, snap in existing_by_month.items()
        if snap.get("source") == "captured"
    }

    gate_confidence: str
    gate_passed: bool
    divergences: list[dict] = []

    if captured_months:
        # PRIMARY path: reconstruct captured months and compare
        gate_confidence = "primary"
        logger.info(
            "Overlap-test gate: PRIMARY path — comparing against %d captured month(s): %s",
            len(captured_months),
            ", ".join(sorted(captured_months.keys())),
        )
        for month, captured_snap in sorted(captured_months.items()):
            captured_counts = {
                "critical": captured_snap.get("critical", 0),
                "high":     captured_snap.get("high", 0),
                "medium":   captured_snap.get("medium", 0),
                "low":      captured_snap.get("low", 0),
            }
            reconstructed_counts = reconstruct_month(current_open_df, fixed_df, month)
            if not within_tolerance(captured_counts, reconstructed_counts):
                divergences.append({
                    "month": month,
                    "captured": captured_counts,
                    "reconstructed": reconstructed_counts,
                })
                logger.error(
                    "Overlap gate FAIL for month=%s: captured=%s reconstructed=%s",
                    month, captured_counts, reconstructed_counts,
                )
            else:
                logger.info(
                    "Overlap gate PASS for month=%s: captured=%s reconstructed=%s",
                    month, captured_counts, reconstructed_counts,
                )
        gate_passed = len(divergences) == 0

    else:
        # WEAKER fallback: reconstruct "today" and compare to live open count.
        # The live count is the len of the current_open_df filtered to open-now
        # via open_findings_at at datetime.now().
        gate_confidence = "weaker"
        logger.warning(
            "Overlap-test gate: WEAKER fallback path — no captured months exist. "
            "Comparing reconstruction-of-today against current open count. "
            "This is EXPLICITLY WEAKER confidence than the primary captured-month gate. "
            "Consider running after capture_trend_snapshot.py has built at least 1 captured month."
        )
        now_ts = pd.Timestamp(datetime.now(tz=timezone.utc))
        live_open = open_findings_at(current_open_df, now_ts)
        live_count = len(live_open)

        # Reconstruct current month
        current_month = datetime.now().strftime("%Y-%m")
        reconstructed_counts = reconstruct_month(current_open_df, fixed_df, current_month)
        reconstructed_total = sum(reconstructed_counts.values())

        abs_diff = abs(reconstructed_total - live_count)
        rel_diff = abs_diff / max(live_count, 1)

        if abs_diff <= _MAX_ABSOLUTE_ERROR or rel_diff <= _MAX_RELATIVE_ERROR:
            gate_passed = True
            logger.info(
                "Overlap gate (weaker) PASS: live_open=%d reconstructed_total=%d "
                "abs_diff=%d rel_diff=%.1f%%",
                live_count, reconstructed_total, abs_diff, rel_diff * 100,
            )
        else:
            gate_passed = False
            logger.error(
                "Overlap gate (weaker) FAIL: live_open=%d reconstructed_total=%d "
                "abs_diff=%d rel_diff=%.1f%% — exceeds tolerance",
                live_count, reconstructed_total, abs_diff, rel_diff * 100,
            )
            divergences.append({
                "month": current_month,
                "live_count": live_count,
                "reconstructed_total": reconstructed_total,
            })

    if not gate_passed:
        logger.error(
            "RECONSTRUCTION ABORTED: overlap-test gate failed. "
            "No snapshots written. Divergences: %s",
            divergences,
        )
        return {
            "gate_passed": False,
            "gate_confidence": gate_confidence,
            "months_written": 0,
            "months_skipped_existing": 0,
            "months_dry_run": 0,
            "divergences": divergences,
        }

    # ------------------------------------------------------------------
    # Reconstruct all months in window
    # ------------------------------------------------------------------
    months = _months_in_range_stdlib(window_start)
    months_written = 0
    months_skipped = 0
    months_dry_run = 0
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    new_snapshots = list(existing_snapshots)  # copy; we'll mutate below

    for month in months:
        # Skip months already present (captured OR reconstructed — immutability D-18-03)
        if month in existing_by_month:
            logger.info("Skipping month=%s — already present (source=%s)", month,
                        existing_by_month[month].get("source", "unknown"))
            months_skipped += 1
            continue

        counts = reconstruct_month(current_open_df, fixed_df, month)
        entry: dict[str, Any] = {
            "month":       month,
            "tag_filter":  "all_assets",
            "source":      "reconstructed",
            "critical":    counts["critical"],
            "high":        counts["high"],
            "medium":      counts["medium"],
            "low":         counts["low"],
            "asset_count": None,           # D-18-04: not reconstructable
            "generated_at": generated_at,
        }
        # D-18-02: partial flag on taper-edge months
        if _is_taper_month(month):
            entry["partial"] = True

        if dry_run:
            logger.info(
                "[DRY-RUN] Would write month=%s source=reconstructed partial=%s counts=%s",
                month, entry.get("partial", False), counts,
            )
            months_dry_run += 1
        else:
            new_snapshots.append(entry)
            months_written += 1
            logger.info(
                "Reconstructed month=%s partial=%s counts=%s",
                month, entry.get("partial", False), counts,
            )

    if not dry_run and months_written > 0:
        _atomic_write_json(file_path, {"snapshots": new_snapshots})
        logger.info(
            "Reconstruction complete: %d months written, %d skipped (existing)",
            months_written, months_skipped,
        )
    elif dry_run:
        logger.info(
            "[DRY-RUN] Would write %d months; %d already exist (skipped)",
            months_dry_run, months_skipped,
        )
    else:
        logger.info(
            "Reconstruction complete: 0 months written (all %d already present)",
            months_skipped,
        )

    return {
        "gate_passed": True,
        "gate_confidence": gate_confidence,
        "months_written": months_written,
        "months_skipped_existing": months_skipped,
        "months_dry_run": months_dry_run,
        "divergences": [],
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="One-time all-assets trend reconstruction seeding script (D-18-08).",
    )
    parser.add_argument(
        "--cache-dir",
        metavar="PATH",
        help="Directory with pre-fetched vulns_all.parquet / vulns_fixed.parquet "
             "(skips live API fetch; use for the one-time operator run).",
    )
    parser.add_argument(
        "--window-start",
        default=DEFAULT_WINDOW_START,
        metavar="YYYY-MM",
        help=f"Earliest month to reconstruct (default: {DEFAULT_WINDOW_START}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the overlap gate and print plan but write no files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return parser.parse_args(argv)


def _load_dataframes(cache_dir: Optional[str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load current-open and fixed vulnerability DataFrames.

    If ``cache_dir`` is given and the parquet files exist there, load from disk.
    Otherwise fetch live from the Tenable API.
    """
    if cache_dir:
        cache_path = Path(cache_dir)
        open_path = cache_path / "vulns_all.parquet"
        fixed_path = cache_path / "vulns_fixed.parquet"
        if open_path.exists() and fixed_path.exists():
            logger.info("Loading from cache: %s", cache_path)
            current_open_df = pd.read_parquet(open_path)
            fixed_df = pd.read_parquet(fixed_path)
            return current_open_df, fixed_df
        else:
            logger.warning(
                "Cache dir provided but parquet files not found at %s — "
                "falling back to live fetch",
                cache_path,
            )

    # Live fetch
    from tenable_client import get_client  # noqa: E402
    from data.fetchers import fetch_all_vulnerabilities, fetch_fixed_vulnerabilities  # noqa: E402
    import config  # noqa: E402

    logger.info("Fetching open/reopened findings from Tenable API...")
    tio = get_client()
    current_open_df = fetch_all_vulnerabilities(tio)
    # Filter to open + reopened states only (drop fixed rows from the open export)
    if not current_open_df.empty and "state" in current_open_df.columns:
        state_upper = current_open_df["state"].astype(str).str.upper()
        current_open_df = current_open_df[state_upper.isin(["OPEN", "REOPENED"])].copy()

    logger.info("Fetching fixed findings from Tenable API (bounded lookback)...")
    fixed_df = fetch_fixed_vulnerabilities(tio)
    return current_open_df, fixed_df


def main(argv: list[str] | None = None) -> int:
    """Main entry point. Returns an exit code."""
    args = _parse_args(argv)
    _configure_logging(args.verbose)

    logger.info(
        "backfill_trend_reconstruction starting — window_start=%s dry_run=%s",
        args.window_start, args.dry_run,
    )

    try:
        current_open_df, fixed_df = _load_dataframes(args.cache_dir)
    except SystemExit as exc:
        logger.error("Authentication failure: %s", exc)
        return 2
    except Exception as exc:
        logger.error("Failed to load data: %s", exc)
        return 3

    result = run_reconstruction(
        current_open_df=current_open_df,
        fixed_df=fixed_df,
        trend_dir=TREND_DIR,
        window_start=args.window_start,
        dry_run=args.dry_run,
    )

    if not result["gate_passed"]:
        logger.error(
            "Exiting with code 1 — overlap-test gate FAILED (confidence=%s). "
            "No snapshots were written.",
            result["gate_confidence"],
        )
        return 1

    if args.dry_run:
        logger.info(
            "[DRY-RUN] Gate PASSED (confidence=%s). "
            "Would write %d months; %d already present.",
            result["gate_confidence"],
            result["months_dry_run"],
            result["months_skipped_existing"],
        )
    else:
        logger.info(
            "Done. Gate PASSED (confidence=%s). "
            "Months written: %d. Months skipped (already present): %d.",
            result["gate_confidence"],
            result["months_written"],
            result["months_skipped_existing"],
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
