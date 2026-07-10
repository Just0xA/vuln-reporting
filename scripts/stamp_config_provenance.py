#!/usr/bin/env python
"""Stamp and verify the D-03 provenance of the live server delivery config.

Implements the source-commit-SHA stamp mechanism (Phase 21 D-03): the
invariant that whatever delivery config is live on the server equals a
merged, CODEOWNERS-reviewed, CI-passed commit from the private config repo,
and that this is verifiable on the server without any git access (the
server stays dumb — no git-pull, no artifact fetch; D-01).

Two subcommands:

``stamp``
    Given the reviewed source commit SHA (from the private-repo merge that
    produced the config) and the directory-mode config location on the
    server, write a sidecar provenance file (``.config-provenance.json``)
    next to the placed config recording the source commit SHA, a UTC
    timestamp, and a sha256 of every file under the config directory.

``verify``
    Recompute the sha256 of the live config files and compare against the
    recorded sidecar. Exits 0 when the live config matches its recorded
    provenance; exits non-zero (with a clear logged message) on drift or a
    missing sidecar. This is what proves "live == a reviewed commit" (D-03).

The script reads/writes only commit SHAs, checksums, and timestamps — it
never contains or touches recipient content (Hard Rule 2).

Flags
-----
stamp --config-dir PATH --commit SHA
    Write ``<config-dir>/.config-provenance.json``.
verify --config-dir PATH
    Compare the live config directory's sha256 against the recorded sidecar.

Exit codes
----------
0   success (stamp written / verify matched)
1   verify drift or missing sidecar
2   argparse usage error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_PATH = Path("logs") / "stamp_config_provenance.log"
_LOGGER_NAME = "stamp_config_provenance"
_SIDECAR_NAME = ".config-provenance.json"


def _ensure_log_dir() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _configure_logging(verbose: bool) -> logging.Logger:
    """Build (or reconfigure) the ``stamp_config_provenance`` logger with a
    rotating file handler. File handler always at INFO; console handler at
    DEBUG when verbose else INFO. Idempotent: clears prior handlers.
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

    logger.propagate = False
    return logger


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python scripts/stamp_config_provenance.py",
        description=(
            "Stamp or verify the D-03 provenance of the live delivery config "
            "against a reviewed private-repo commit SHA."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Raise console handler to DEBUG.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    stamp_parser = subparsers.add_parser(
        "stamp", help="Write a provenance sidecar next to the placed config."
    )
    stamp_parser.add_argument(
        "--config-dir",
        type=Path,
        required=True,
        help="Directory holding the placed config (e.g. shared/config/).",
    )
    stamp_parser.add_argument(
        "--commit",
        required=True,
        help="The reviewed source commit SHA from the private-repo merge.",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify the live config matches its recorded provenance."
    )
    verify_parser.add_argument(
        "--config-dir",
        type=Path,
        required=True,
        help="Directory holding the placed config (e.g. shared/config/).",
    )

    return parser


def _config_files(config_dir: Path) -> list[Path]:
    """Return every file under `config_dir`, sorted, excluding the sidecar
    itself so the sidecar's own bytes never factor into its checksum.
    """
    return sorted(
        p
        for p in config_dir.rglob("*")
        if p.is_file() and p.name != _SIDECAR_NAME
    )


def compute_config_sha256(config_dir: Path) -> str:
    """Compute a single sha256 digest over every file under `config_dir`.

    Parameters
    ----------
    config_dir : Path
        Directory holding the placed directory-mode config
        (``contacts.yaml`` + ``deliveries.d/``).

    Returns
    -------
    str
        Hex sha256 digest of the concatenated (relative-path, file-bytes)
        stream, in sorted-path order for a deterministic result.
    """
    digest = hashlib.sha256()
    for file_path in _config_files(config_dir):
        digest.update(str(file_path.relative_to(config_dir)).encode("utf-8"))
        digest.update(file_path.read_bytes())
    return digest.hexdigest()


def stamp(config_dir: Path, commit_sha: str, logger: logging.Logger) -> int:
    """Write the provenance sidecar recording `commit_sha` + current sha256.

    Parameters
    ----------
    config_dir : Path
        Directory holding the placed directory-mode config.
    commit_sha : str
        The reviewed source commit SHA from the private-repo merge.
    logger : logging.Logger
        Logger for status/error messages.

    Returns
    -------
    int
        0 on success, 1 if `config_dir` does not exist or has no files.
    """
    if not config_dir.is_dir():
        logger.error("Config directory not found: %s", config_dir)
        return 1

    files = _config_files(config_dir)
    if not files:
        logger.error("Config directory has no files to stamp: %s", config_dir)
        return 1

    checksum = compute_config_sha256(config_dir)
    stamped_at = datetime.now(tz=timezone.utc).isoformat()
    record = {
        "commit_sha": commit_sha,
        "stamped_at": stamped_at,
        "sha256": checksum,
    }

    sidecar_path = config_dir / _SIDECAR_NAME
    sidecar_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    logger.info(
        "Stamped %s: commit=%s sha256=%s at %s",
        sidecar_path,
        commit_sha,
        checksum,
        stamped_at,
    )
    return 0


def verify(config_dir: Path, logger: logging.Logger) -> int:
    """Verify the live config under `config_dir` matches its recorded sidecar.

    Parameters
    ----------
    config_dir : Path
        Directory holding the placed directory-mode config.
    logger : logging.Logger
        Logger for status/error messages.

    Returns
    -------
    int
        0 when the live sha256 matches the recorded provenance; 1 on drift
        or a missing sidecar/config directory.
    """
    if not config_dir.is_dir():
        logger.error("Config directory not found: %s", config_dir)
        return 1

    sidecar_path = config_dir / _SIDECAR_NAME
    if not sidecar_path.is_file():
        logger.error(
            "Provenance sidecar missing: %s — live config is not traceable "
            "to a reviewed commit (D-03 violated)",
            sidecar_path,
        )
        return 1

    try:
        record = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Provenance sidecar unreadable: %s (%s)", sidecar_path, exc)
        return 1

    recorded_sha256 = record.get("sha256")
    if not recorded_sha256:
        logger.error("Provenance sidecar missing 'sha256' field: %s", sidecar_path)
        return 1

    live_sha256 = compute_config_sha256(config_dir)
    if live_sha256 != recorded_sha256:
        logger.error(
            "Provenance DRIFT detected in %s: recorded sha256=%s live sha256=%s "
            "— live config no longer matches commit %s (untracked hand-edit?)",
            config_dir,
            recorded_sha256,
            live_sha256,
            record.get("commit_sha", "?"),
        )
        return 1

    logger.info(
        "Provenance verified OK: %s matches commit %s (sha256=%s, stamped %s)",
        config_dir,
        record.get("commit_sha", "?"),
        live_sha256,
        record.get("stamped_at", "?"),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
        return code if code != 0 else 0

    logger = _configure_logging(args.verbose)
    started = datetime.now(tz=timezone.utc)
    logger.info("Started at %s UTC; argv=%s", started.isoformat(), sys.argv)

    if args.subcommand == "stamp":
        return stamp(args.config_dir, args.commit, logger)
    if args.subcommand == "verify":
        return verify(args.config_dir, logger)

    logger.error("Unknown subcommand: %s", args.subcommand)
    return 2


if __name__ == "__main__":
    sys.exit(main())
