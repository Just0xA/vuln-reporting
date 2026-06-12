#!/usr/bin/env python
"""Warm the Tenable parquet cache for the day so scheduled report runs short-circuit on [CACHE HIT].

Designed to be invoked on a cron schedule (e.g., 03:00 nightly). Fetches the four
datasets that ``run_all.py`` pre-warms — vulnerabilities, fixed vulnerabilities,
assets, and recast rules — into ``data/cache/<YYYY-MM-DD>/*.parquet`` using the
same dataset filenames so downstream reports see the cache.

Flags
-----
--date YYYY-MM-DD   Target the named date folder instead of today (server local).
--prune-stale       Remove ``data/cache/<other-date>/`` folders before fetching.
--verbose           Console handler at DEBUG (file handler stays at INFO).
--dry-run           Log what would happen; write no files.

Exit codes
----------
0   success or dry-run
2   auth failure (``get_client`` raised ``SystemExit``) or argparse usage error
3   fetcher failed after retries
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from config import CACHE_DIR  # noqa: E402
from data.fetchers import (
    fetch_all_assets,
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
    fetch_recast_rules,
)
from tenable_client import get_client

_LOG_PATH = Path("logs") / "warm_cache.log"
_LOGGER_NAME = "warm_cache"

_FETCHERS = (
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
    fetch_all_assets,
    fetch_recast_rules,
)

# Dataset filenames mirror data/fetchers.py's _cache_path(cache_dir, "<dataset>") calls.
_DATASET_FILENAMES = (
    "vulns_all.parquet",
    "vulns_fixed.parquet",
    "assets_all.parquet",
    "recast_rules.parquet",
)


def _ensure_log_dir() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _configure_logging(verbose: bool) -> logging.Logger:
    """Build (or reconfigure) the ``warm_cache`` logger with a rotating file handler.

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
    """Write directly to the warm_cache logfile without going through the configured logger.

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


class _WarmCacheArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that logs usage errors to ``logs/warm_cache.log`` before exiting (LOG-01)."""

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


def _build_parser() -> _WarmCacheArgumentParser:
    parser = _WarmCacheArgumentParser(
        prog="python -m scripts.warm_cache",
        description="Pre-fetch Tenable parquet caches for the day.",
    )
    parser.add_argument(
        "--date",
        type=_date_type,
        default=None,
        help="Target date folder (YYYY-MM-DD, server local). Defaults to today.",
    )
    parser.add_argument(
        "--prune-stale",
        action="store_true",
        help="Remove data/cache/<other-date>/ folders before fetching.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Raise console handler to DEBUG.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log planned actions; write no files.",
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


def _prune_stale(
    cache_root: Path,
    target_date_str: str,
    logger: logging.Logger,
    dry_run: bool,
) -> None:
    if not cache_root.exists():
        logger.debug("Prune skipped: %s does not exist yet.", cache_root)
        return
    for entry in cache_root.iterdir():
        if not entry.is_dir():
            continue
        if entry.name == target_date_str:
            continue
        if dry_run:
            logger.info("WOULD remove stale cache folder %s", entry)
        else:
            logger.info("Removing stale cache folder %s", entry)
            shutil.rmtree(entry, ignore_errors=False)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse already logged the real reason via _WarmCacheArgumentParser.error
        # (or this is a --help exit, code 0, which we pass through).
        code = e.code if isinstance(e.code, int) else 2
        return code if code != 0 else 0

    logger = _configure_logging(args.verbose)
    start = _log_started(logger, sys.argv)

    target_date_str = args.date or datetime.now().strftime("%Y-%m-%d")
    cache_dir = CACHE_DIR / target_date_str

    if args.prune_stale:
        try:
            _prune_stale(CACHE_DIR, target_date_str, logger, args.dry_run)
        except Exception as exc:  # noqa: BLE001 - log and fail-soft for prune
            logger.exception("Prune failed: %s", exc)
            _log_completed(logger, start, "failed", f"prune: {exc}")
            return 3

    if args.dry_run:
        logger.info("DRY RUN: target cache dir = %s", cache_dir)
        for fname in _DATASET_FILENAMES:
            logger.info("DRY RUN: WOULD write %s", cache_dir / fname)
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

    for fn in _FETCHERS:
        try:
            logger.info("Fetching %s into %s", fn.__name__, cache_dir)
            fn(tio, cache_dir)
        except Exception as exc:  # noqa: BLE001 - top-level fetch barrier
            logger.exception("Fetcher %s failed: %s", fn.__name__, exc)
            _log_completed(logger, start, "failed", f"{fn.__name__}: {exc}")
            return 3

    _log_completed(logger, start, "success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
