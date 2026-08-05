#!/usr/bin/env python
"""Cache-backed sanity check for the quick-260805-ezo VPR-only board reformulation.

Reads the run-scoped parquet cache DIRECTLY and reproduces the reference values
the operator measured when the board Critical Remediation SLA reformulation was
specified.  Its job is to prove that the shipped helpers
(``identify_on_time_assets`` -> ``exclude_risk_managed`` -> ``add_vpr_severity``)
still produce those exact counts.

Hard Rule 1 — NO live Tenable pull
----------------------------------
This script never imports ``data.fetchers`` or ``tenable_client``.  It only
reads ``vulns_all.parquet`` / ``assets_all.parquet`` out of an existing warm
cache directory.  If the cache is missing, the script exits non-zero and tells
the operator to warm it OUTSIDE Claude Code.

Hard Rule 2 — aggregate-only output
-----------------------------------
Every line this script prints is an aggregate count.  No hostname, IP, MAC,
plugin name, or asset UUID is ever emitted (D-04-08 / T-ezo-03).

Coverage limitation
-------------------
The cache holds the OPEN/REOPENED population only — there is no fixed-vulns
parquet.  The FIXED half of the metric (``compliant`` / ``fixed_late``, and the
reopened-aware ``days_to_fix`` clock applied to fixed rows) therefore has NO
cache coverage and is verified by the synthetic unit fixtures in
``tests/test_kpi_risk_managed_exclusion.py`` only.

Flags
-----
--cache-dir PATH        Cache directory to read.  Default: data/cache/2026-07-01
--report-date YYYY-MM-DD  Reference date for the on-time / SLA windows.
                        Default: 2026-07-01
--verbose               Console handler at DEBUG.

Exit codes
----------
0   every reference value matched
1   at least one reference value mismatched (a per-row diff is printed)
2   cache directory or a required parquet file is missing
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from config import SLA_DAYS  # noqa: E402
from reports.modules.board_report_utils import (  # noqa: E402
    ON_TIME_WINDOW_DAYS,
    VPR_NONE_LABEL,
    add_vpr_severity,
    exclude_risk_managed,
    identify_on_time_assets,
)

logger = logging.getLogger("sanity_vpr_severity_cache")

_DEFAULT_CACHE_DIR   = _REPO_ROOT / "data" / "cache" / "2026-07-01"
_DEFAULT_REPORT_DATE = "2026-07-01"

_CRITICAL_SLA_DAYS: int = SLA_DAYS["critical"]

#: Reference values measured by the operator from data/cache/2026-07-01 at
#: report_date = 2026-07-01T00:00:00Z.  Keys are stable identifiers; values are
#: the expected aggregate counts.
_REFERENCE_VALUES: dict[str, int] = {
    "on_time_assets":            36_358,
    "open_findings_in_scope":   166_392,
    "vpr_critical":               5_723,
    "vpr_high":                  12_423,
    "vpr_medium":                57_196,
    "vpr_low":                   47_622,
    "vpr_none":                  43_428,
    "critical_open_in_window":    5_723,
    "open_past_due":              3_210,
    "open_not_due":               2_513,
}


def _configure_logging(verbose: bool) -> None:
    """Attach a console handler at INFO (or DEBUG when ``verbose``)."""
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def _parse_report_date(value: str) -> datetime:
    """Parse a ``YYYY-MM-DD`` string into a UTC-aware midnight datetime."""
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def _load_cache(cache_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load ``vulns_all.parquet`` and ``assets_all.parquet`` from ``cache_dir``.

    Parameters
    ----------
    cache_dir : Path
        Warm cache directory (``data/cache/<YYYY-MM-DD>/``).

    Returns
    -------
    tuple[pd.DataFrame, pd.DataFrame]
        ``(vulns_df, assets_df)``.

    Raises
    ------
    SystemExit
        Exit code 2 when the directory or either parquet file is absent.
        Hard Rule 1 forbids fetching the missing data from here.
    """
    vulns_path  = cache_dir / "vulns_all.parquet"
    assets_path = cache_dir / "assets_all.parquet"

    for path in (vulns_path, assets_path):
        if not path.is_file():
            logger.error(
                "Missing cache file: %s. Warm the parquet cache OUTSIDE Claude "
                "Code (scripts/warm_cache.py) — Hard Rule 1 forbids a live pull "
                "from here.",
                path,
            )
            raise SystemExit(2)

    vulns_df  = pd.read_parquet(vulns_path)
    assets_df = pd.read_parquet(assets_path)
    logger.debug(
        "Loaded cache: vulns=%d rows, assets=%d rows.",
        len(vulns_df), len(assets_df),
    )
    return vulns_df, assets_df


def compute_observed(
    vulns_df:    pd.DataFrame,
    assets_df:   pd.DataFrame,
    report_date: datetime,
) -> dict[str, int]:
    """
    Reproduce the reference aggregate counts from the cached frames.

    Applies the shipped board pipeline in order:
    ``identify_on_time_assets`` -> ``exclude_risk_managed`` ->
    ``add_vpr_severity``, then derives the VPR tier distribution and the
    open-side SLA populations.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Open / reopened findings from the parquet cache.
    assets_df : pd.DataFrame
        Full asset inventory from the parquet cache.
    report_date : datetime
        UTC-aware reference date for the on-time and SLA windows.

    Returns
    -------
    dict[str, int]
        Aggregate counts keyed the same way as ``_REFERENCE_VALUES``.
    """
    on_time, _    = identify_on_time_assets(assets_df, report_date)
    on_time_uuids = set(on_time["asset_uuid"].dropna())

    scoped = exclude_risk_managed(vulns_df)
    scoped = add_vpr_severity(scoped)
    scoped = scoped[scoped["asset_uuid"].isin(on_time_uuids)]

    tier_counts = scoped["vpr_severity"].value_counts()

    rd_ts    = pd.Timestamp(report_date).tz_convert("UTC")
    window   = rd_ts - pd.Timedelta(days=ON_TIME_WINDOW_DAYS)

    critical = scoped[scoped["vpr_severity"] == "critical"]

    last_found_ts = pd.to_datetime(
        critical["last_found"], utc=True, errors="coerce"
    )
    in_window = critical[last_found_ts.notna() & (last_found_ts >= window)]

    resurfaced_ts  = pd.to_datetime(
        in_window["resurfaced_date"], utc=True, errors="coerce"
    )
    first_found_ts = pd.to_datetime(
        in_window["first_found"], utc=True, errors="coerce"
    )
    clock_start = resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)
    age_days    = (rd_ts - clock_start).dt.days

    past_due = int((age_days.notna() & (age_days > _CRITICAL_SLA_DAYS)).sum())

    return {
        "on_time_assets":           int(len(on_time)),
        "open_findings_in_scope":   int(len(scoped)),
        "vpr_critical":             int(tier_counts.get("critical", 0)),
        "vpr_high":                 int(tier_counts.get("high", 0)),
        "vpr_medium":               int(tier_counts.get("medium", 0)),
        "vpr_low":                  int(tier_counts.get("low", 0)),
        "vpr_none":                 int(tier_counts.get(VPR_NONE_LABEL, 0)),
        "critical_open_in_window":  int(len(in_window)),
        "open_past_due":            past_due,
        "open_not_due":             int(len(in_window) - past_due),
    }


def report(observed: dict[str, int], expected: dict[str, int]) -> bool:
    """
    Print an aggregate-only comparison table and return whether all rows match.

    Parameters
    ----------
    observed : dict[str, int]
        Counts derived from the cache by :func:`compute_observed`.
    expected : dict[str, int]
        Reference counts (:data:`_REFERENCE_VALUES`).

    Returns
    -------
    bool
        ``True`` when every key matches.
    """
    print(f"{'quantity':<26} {'expected':>10} {'observed':>10} {'diff':>10}")
    print("-" * 60)

    all_match = True
    for key, want in expected.items():
        got  = observed.get(key, 0)
        diff = got - want
        if diff:
            all_match = False
        print(f"{key:<26} {want:>10,} {got:>10,} {diff:>+10,}")

    print("-" * 60)
    print("RESULT: PASS" if all_match else "RESULT: FAIL")
    if not all_match:
        print(
            "One or more aggregate counts drifted from the reference values "
            "measured for quick-260805-ezo. Confirm the cache directory and "
            "report date match the reference run before treating this as a "
            "code regression."
        )
    return all_match


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = argparse.ArgumentParser(
        description=(
            "Cache-backed sanity check for the board VPR-only severity tiering "
            "and the open-side Critical Remediation SLA populations. Never "
            "performs a live Tenable pull (Hard Rule 1)."
        ),
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=_DEFAULT_CACHE_DIR,
        help=f"Warm cache directory to read (default: {_DEFAULT_CACHE_DIR}).",
    )
    parser.add_argument(
        "--report-date", type=str, default=_DEFAULT_REPORT_DATE,
        help=(
            "Reference date YYYY-MM-DD for the on-time and SLA windows "
            f"(default: {_DEFAULT_REPORT_DATE})."
        ),
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Console handler at DEBUG.",
    )
    args = parser.parse_args(argv)

    _configure_logging(args.verbose)

    report_date = _parse_report_date(args.report_date)
    logger.info(
        "Reading cache %s at report_date=%s (aggregate counts only).",
        args.cache_dir, report_date.date(),
    )

    vulns_df, assets_df = _load_cache(args.cache_dir)
    observed = compute_observed(vulns_df, assets_df, report_date)

    return 0 if report(observed, _REFERENCE_VALUES) else 1


if __name__ == "__main__":
    sys.exit(main())
