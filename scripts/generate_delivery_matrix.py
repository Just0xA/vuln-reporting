#!/usr/bin/env python
"""Render the delivery matrix (deliveries x reports x schedule x filters x owner)
from the resolved delivery config.

Standalone script reusing `delivery.config_loader.resolve_config` (D-04) so
"who gets what, when" is answerable in one command, without opening any YAML.
The matrix shows contact/group NAMES + owner only — never expanded recipient
addresses (D-05, Hard Rule 2) — sourced from the resolver's
`metadata_by_delivery_name` side channel, never from the schema-gated group
dict (which carries no owner/contact key). Safe to publish as a CI artifact.

Flags
-----
--config PATH       Path to delivery_config.yaml (directory-mode siblings
                     `deliveries.d/` + `contacts.yaml` are resolved relative
                     to its parent). Defaults to ROOT_DIR/delivery_config.yaml.
--format {markdown,html}   Output format. Default: markdown (D-06).
--output PATH       Write to this path instead of stdout.
--verbose           Console handler at DEBUG (file handler stays at INFO).

Exit codes
----------
0   success
2   argparse usage error
3   loader returned errors (config failed to resolve)
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from delivery.config_loader import resolve_config  # noqa: E402

_LOG_PATH = Path("logs") / "generate_delivery_matrix.log"
_LOGGER_NAME = "generate_delivery_matrix"

_MATRIX_COLUMNS = ("Delivery", "Owner", "Reports", "Schedule", "Filters", "Contact")


def _ensure_log_dir() -> None:
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _configure_logging(verbose: bool) -> logging.Logger:
    """Build (or reconfigure) the ``generate_delivery_matrix`` logger with a
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


def _log_to_file_only(message: str, level: int = logging.ERROR) -> None:
    """Write directly to the logfile without the configured logger.

    Used for the argparse-error path (LOG-01) where the main logger has not
    yet been configured because ``parse_args`` raised ``SystemExit`` before
    ``--verbose`` was known.
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


class _MatrixArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that logs usage errors to the logfile before exiting (LOG-01)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        started = datetime.now(tz=timezone.utc).isoformat()
        _log_to_file_only(
            f"Started at {started} UTC; argv={sys.argv}; "
            f"failed because argparse usage error: {message}"
        )
        super().error(message)


def _build_parser() -> _MatrixArgumentParser:
    parser = _MatrixArgumentParser(
        prog="python scripts/generate_delivery_matrix.py",
        description="Render the delivery matrix from the resolved config.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to delivery_config.yaml. Defaults to ROOT_DIR/delivery_config.yaml.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write to this path instead of stdout.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Raise console handler to DEBUG.",
    )
    return parser


def _format_schedule(schedule: dict) -> str:
    """Render a resolved group's `schedule` block as a short display string."""
    frequency = schedule.get("frequency")
    if frequency == "weekly":
        return f"weekly / {schedule.get('day_of_week', '?')} {schedule.get('time', '?')}"
    if frequency == "monthly":
        return f"monthly / day {schedule.get('day_of_month', '?')} {schedule.get('time', '?')}"
    return frequency or "?"


def _format_filters(filters: dict) -> str:
    """Render a resolved group's `filters` block; empty dict = All Assets."""
    if not filters:
        return "All Assets"
    tag_category = filters.get("tag_category", "?")
    tag_value = filters.get("tag_value", "?")
    return f"{tag_category} = {tag_value}"


def _matrix_rows(groups: list[dict], metadata_by_delivery_name: dict[str, dict]) -> list[tuple[str, ...]]:
    """Build the shared (name, owner, reports, schedule, filters, contact) rows.

    PII invariant (D-05 / Hard Rule 2): owner + contact NAME come ONLY from
    `metadata_by_delivery_name`, never from `email.recipients`/`email.cc`.
    """
    rows: list[tuple[str, ...]] = []
    for group in groups:
        name = group.get("name", "?")
        meta = metadata_by_delivery_name.get(name, {})
        owner = meta.get("owner") or "—"
        contact = meta.get("contact") or "—"
        reports = ", ".join(group.get("reports") or [])
        schedule = _format_schedule(group.get("schedule") or {})
        filters = _format_filters(group.get("filters") or {})
        rows.append((name, owner, reports, schedule, filters, contact))
    return rows


def render_markdown(groups: list[dict], metadata_by_delivery_name: dict[str, dict]) -> str:
    """Render the delivery matrix as a Markdown table (D-06 default format)."""
    rows = _matrix_rows(groups, metadata_by_delivery_name)

    lines = [
        "# Delivery Matrix",
        "",
        "| " + " | ".join(_MATRIX_COLUMNS) + " |",
        "| " + " | ".join(["---"] * len(_MATRIX_COLUMNS)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return "\n".join(lines)


def render_html(groups: list[dict], metadata_by_delivery_name: dict[str, dict]) -> str:
    """Render the delivery matrix as a styled standalone HTML page (D-06 opt-in).

    This is a published artifact, not an email panel, so a `<style>` block is
    fine here — the inline-CSS-only rule (Constraints) governs email panels,
    not this page.
    """
    rows = _matrix_rows(groups, metadata_by_delivery_name)

    header_html = "".join(f"<th>{col}</th>" for col in _MATRIX_COLUMNS)
    body_html = "\n".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Delivery Matrix</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 2rem; }}
  h1 {{ font-size: 1.4rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
  th {{ background-color: #f2f2f2; }}
  tr:nth-child(even) {{ background-color: #fafafa; }}
</style>
</head>
<body>
<h1>Delivery Matrix</h1>
<table>
<thead><tr>{header_html}</tr></thead>
<tbody>
{body_html}
</tbody>
</table>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
        return code if code != 0 else 0

    logger = _configure_logging(args.verbose)
    start = datetime.now(tz=timezone.utc)
    logger.info("Started at %s UTC; argv=%s", start.isoformat(), sys.argv)

    config_path = args.config or (_REPO_ROOT / "delivery_config.yaml")

    groups, errors, warnings, metadata_by_delivery_name = resolve_config(config_path)

    for warning in warnings:
        logger.warning(warning)

    if errors:
        for error in errors:
            logger.error(error)
        logger.error("Config resolution failed with %d error(s); aborting.", len(errors))
        return 3

    if args.format == "html":
        output = render_html(groups, metadata_by_delivery_name)
    else:
        output = render_markdown(groups, metadata_by_delivery_name)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        logger.info("Wrote %s matrix to %s", args.format, args.output)
    else:
        print(output)

    end = datetime.now(tz=timezone.utc)
    logger.info(
        "Completed at %s UTC; duration=%.2fs; status=success",
        end.isoformat(),
        (end - start).total_seconds(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
