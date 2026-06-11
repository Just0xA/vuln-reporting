#!/usr/bin/env python
"""Capture a monthly trend snapshot of open vulnerability counts into data/trend/.

Designed to be invoked on a cron/Task-Scheduler schedule (e.g., first day of each
month).  Fetches the open+reopened vulnerability export and the asset list into
``data/cache/<YYYY-MM-DD>/*.parquet`` (reusing an existing warm cache if present),
then calls ``capture_snapshot`` to accrue the all_assets severity dimension entry.

Flags
-----
--month YYYY-MM     Snapshot target month (server local). Defaults to current month.
--date YYYY-MM-DD   Cache folder date (server local). Defaults to today.
--verbose           Console handler at DEBUG (file handler stays at INFO).
--dry-run           Log what would happen; perform no fetch and write no files.

Exit codes
----------
0   success or dry-run
2   auth failure (``get_client`` raised ``SystemExit``) or argparse usage error
3   fetch or write failure
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import CACHE_DIR
from data.fetchers import (
    fetch_all_assets,
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
)
from data.trend_store import capture_snapshot
from tenable_client import get_client
from utils.asset_count import count_on_time_assets

_LOG_PATH = Path("logs") / "capture_trend_snapshot.log"
_LOGGER_NAME = "capture_trend_snapshot"


def _ensure_log_dir() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _configure_logging(verbose: bool) -> logging.Logger:
    """Build (or reconfigure) the ``capture_trend_snapshot`` logger with a rotating file handler.

    File handler always at INFO; console handler at DEBUG when verbose else INFO.
    Idempotent: clears prior handlers so repeated calls in tests do not stack.
    """
    _ensure_log_dir()
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = RotatingFileHandler(
        _LOG_PATH, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # Capture fetcher log lines too.
    root = logging.getLogger()
    if root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)

    logger.propagate = False
    return logger


def _log_to_file_only(message: str, level: int = logging.ERROR) -> None:
    """Write directly to the capture_trend_snapshot logfile without going through the configured logger.

    Used for the argparse-error path (LOG-01) where we have not yet configured the
    main logger because ``parse_args`` raised SystemExit before we knew --verbose.
    """
    _ensure_log_dir()
    fallback = logging.getLogger(f"{_LOGGER_NAME}._argparse")
    if not fallback.handlers:
        h = RotatingFileHandler(
            _LOG_PATH, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
        )
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        fallback.addHandler(h)
        fallback.setLevel(logging.INFO)
        fallback.propagate = False
    fallback.log(level, message)


class _SnapshotArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that logs usage errors to ``logs/capture_trend_snapshot.log`` before exiting (LOG-01)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        started = datetime.now(tz=timezone.utc).isoformat()
        _log_to_file_only(
            f"Started at {started} UTC; argv={sys.argv}; "
            f"failed because argparse usage error: {message}"
        )
        super().error(message)


def _date_type(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--date must be YYYY-MM-DD, got {value!r}: {exc}"
        ) from exc
    return value


def _month_type(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--month must be YYYY-MM, got {value!r}: {exc}"
        ) from exc
    return value


def _build_parser() -> _SnapshotArgumentParser:
    parser = _SnapshotArgumentParser(
        prog="python -m scripts.capture_trend_snapshot",
        description="Capture a monthly open-vuln severity snapshot into data/trend/.",
    )
    parser.add_argument(
        "--month",
        type=_month_type,
        default=None,
        help="Snapshot target month (YYYY-MM, server local). Defaults to current month.",
    )
    parser.add_argument(
        "--date",
        type=_date_type,
        default=None,
        help="Cache folder date (YYYY-MM-DD, server local). Defaults to today.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Raise console handler to DEBUG.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log planned actions; perform no fetch and write no files.",
    )
    return parser


def _log_started(logger: logging.Logger, argv: list[str]) -> datetime:
    start = datetime.now(tz=timezone.utc)
    logger.info("Started at %s UTC; argv=%s", start.isoformat(), argv)
    return start


def _log_completed(
    logger: logging.Logger,
    start: datetime,
    status: str,
    detail: str = "",
) -> None:
    end = datetime.now(tz=timezone.utc)
    duration = (end - start).total_seconds()
    suffix = f"; detail={detail}" if detail else ""
    logger.info(
        "Completed at %s UTC; duration=%.2fs; status=%s%s",
        end.isoformat(),
        duration,
        status,
        suffix,
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point — returns cron-friendly exit code (0/2/3)."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse already logged the real reason via _SnapshotArgumentParser.error
        # (or this is a --help exit, code 0, which we pass through).
        # SystemExit.code is an int for usage/help exits and None when raised
        # bare; map the non-int case to 2 (usage error) and pass ints through.
        return e.code if isinstance(e.code, int) else 2

    logger = _configure_logging(args.verbose)
    start = _log_started(logger, sys.argv)

    # Timezone policy: month/date keys use server LOCAL time (CLAUDE.md).
    target_date_str = args.date or datetime.now().strftime("%Y-%m-%d")
    month_str = args.month or datetime.now().strftime("%Y-%m")  # LOCAL — Pitfall 6
    cache_dir = CACHE_DIR / target_date_str

    if args.dry_run:
        logger.info(
            "DRY RUN: would capture snapshot month=%s cache=%s", month_str, cache_dir
        )
        _log_completed(logger, start, "dry-run")
        return 0

    cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        tio = get_client()
    except SystemExit as exc:
        logger.error("Auth failure from get_client(): %s", exc)
        _log_completed(logger, start, "failed", f"auth: {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error from get_client(): %s", exc)
        _log_completed(logger, start, "failed", f"auth: {exc}")
        return 2

    try:
        logger.info("Fetching vulnerabilities into %s", cache_dir)
        df = fetch_all_vulnerabilities(tio, cache_dir)
        logger.info("Fetching assets into %s", cache_dir)
        assets_df = fetch_all_assets(tio, cache_dir)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Fetcher failed: %s", exc)
        _log_completed(logger, start, "failed", f"fetch: {exc}")
        return 3

    # Build the snapshot reference date so capture_snapshot derives the correct
    # month key.  When --month is given, construct a datetime whose %Y-%m matches
    # month_str; otherwise pass datetime.now() (LOCAL, matching the default month_str).
    #
    # WR-04 — local-vs-UTC cutoff is deliberately mixed and documented here:
    #   * The month KEY is derived local (date.strftime("%Y-%m") in capture_snapshot).
    #   * The open-set CUTOFF D is derived in open_findings_at, which coerces a
    #     tz-naive datetime to UTC.  So for a `--month 2026-06` run the cutoff is
    #     2026-06-01T00:00:00Z (UTC midnight on day 01), NOT local midnight.
    # This is acceptable for monthly snapshots (a few hours of UTC offset does not
    # move a once-per-month count meaningfully), but it must be auditable — hence
    # the resolved snapshot_date is logged below.
    if args.month:
        snapshot_date = datetime.strptime(month_str + "-01", "%Y-%m-%d")
    else:
        snapshot_date = datetime.now()
    logger.info(
        "Snapshot reference date=%s (tz-naive; open-set cutoff coerced to UTC "
        "midnight in open_findings_at); month key=%s",
        snapshot_date.isoformat(), month_str,
    )

    # Compute new aggregate counts for Phase-15 snapshot extension (D-15-05).
    # All values are aggregate counts only — no row-level data logged (QUAL-05).

    # on_time_asset_count: Phase-14 D-02 density denominator
    on_time_asset_count = count_on_time_assets(assets_df, snapshot_date)

    # reopened_count: findings in REOPENED state
    reopened_count = int(
        (df["state"].astype(str).str.upper() == "REOPENED").sum()
    )

    # accepted_count / recast_count: from severity_modification_type
    smt_upper = df["severity_modification_type"].astype(str).str.upper() \
        if "severity_modification_type" in df.columns \
        else df["state"].astype(str).str.upper().where(False, "")
    accepted_count = int(smt_upper.isin({"ACCEPTED"}).sum())
    recast_count = int(smt_upper.isin({"RECASTED"}).sum())

    logger.info(
        "Aggregate counts — on_time_assets=%s reopened=%d accepted=%d recast=%d",
        on_time_asset_count, reopened_count, accepted_count, recast_count,
    )

    # fixed_vulns_df: fetch fail-soft so a fixed-export failure doesn't abort the
    # severity snapshot (the new/fixed pair cold-starts when fixed_vulns_df=None)
    fixed_vulns_df = None
    try:
        fixed_vulns_df = fetch_fixed_vulnerabilities(tio, cache_dir)
        logger.info("Fixed vulnerabilities fetched: %d rows", len(fixed_vulns_df))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "fetch_fixed_vulnerabilities failed — fixed_findings_count / "
            "new_findings_count will cold-start for this snapshot: %s", exc,
        )

    try:
        path = capture_snapshot(
            df, assets_df, snapshot_date, "severity", "all_assets",
            on_time_asset_count=on_time_asset_count,
            reopened_count=reopened_count,
            accepted_count=accepted_count,
            recast_count=recast_count,
            fixed_vulns_df=fixed_vulns_df,
        )
        logger.info("Severity snapshot written: %s", path)
    except Exception as exc:  # noqa: BLE001
        logger.exception("capture_snapshot (severity) failed: %s", exc)
        _log_completed(logger, start, "failed", f"snapshot: {exc}")
        return 3

    # Owner-dimension snapshot (SEG-05, D-12).
    # Caller pre-enriches assets so data/trend_store.py stays free of
    # reports/modules/ imports (RESEARCH A1 / Pitfall 5).
    try:
        from reports.modules.board_report_utils import extract_owner  # noqa: PLC0415
        enriched = extract_owner(assets_df)
        owner_path = capture_snapshot(
            df, assets_df, snapshot_date, "owner", "all_assets",
            enriched_assets=enriched,
        )
        logger.info("Owner snapshot written: %s", owner_path)
    except Exception as exc:  # noqa: BLE001
        logger.exception("capture_snapshot (owner) failed: %s", exc)
        # WR-03: Non-fatal — the severity snapshot (the primary deliverable)
        # already succeeded, so the run is a success for cron purposes. Record
        # the partial status for observability but exit 0; returning 3 here would
        # make the scheduler treat the whole run as a fetch/write failure.
        _log_completed(logger, start, "partial", f"owner-snapshot: {exc}")
        return 0

    _log_completed(logger, start, "success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
