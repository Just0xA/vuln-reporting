"""
delivery/delivery_log.py — SQLite audit log for all report delivery attempts.

The database is created automatically on first use at logs/delivery_log.db.
Every send attempt — success, partial, or failed — writes one row.

Public API
----------
log_delivery()     Write a delivery record; returns the new row id.
get_recent()       Return the N most recent records.
get_failures()     Return all records with status != 'success'.
get_by_group()     Return all records for a named group.
get_by_date_range() Return records between two UTC date strings.

CLI
---
python delivery/delivery_log.py --recent 20
python delivery/delivery_log.py --failures
python delivery/delivery_log.py --group "Executive Team"
python delivery/delivery_log.py --from 2025-01-01 --to 2025-01-31
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import LOG_DIR, LOG_LEVEL
from rich.console import Console
from rich.table import Table
from rich import box

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Database location
# ---------------------------------------------------------------------------
DB_PATH: Path = LOG_DIR / "delivery_log.db"

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS delivery_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           DATETIME NOT NULL,
    group_name          TEXT NOT NULL,
    trigger_mode        TEXT NOT NULL,
    reports_run         TEXT NOT NULL,
    tag_filter          TEXT,
    recipients          TEXT NOT NULL,
    status              TEXT NOT NULL,
    error_message       TEXT,
    output_folder       TEXT NOT NULL,
    attachment_size_kb  INTEGER,
    duration_seconds    REAL
);
"""

# ---------------------------------------------------------------------------
# Status color mapping for terminal output
# ---------------------------------------------------------------------------
_STATUS_STYLE: dict[str, str] = {
    "success": "bold green",
    "partial": "bold yellow",
    "failed":  "bold red",
}


# ===========================================================================
# Internal helpers
# ===========================================================================

def _connect() -> sqlite3.Connection:
    """Return a connection with Row factory and WAL mode for concurrency."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db() -> None:
    """Create the delivery_log table if it does not already exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.execute(_CREATE_SQL)
        conn.commit()
    logger.debug("Delivery log DB initialised at %s", DB_PATH)


# ===========================================================================
# Public write API
# ===========================================================================

def log_delivery(
    *,
    group_name: str,
    trigger_mode: str,
    reports_run: list[str],
    tag_filter: Optional[str],
    recipients: list[str],
    status: str,
    output_folder: str,
    error_message: Optional[str] = None,
    attachment_size_kb: Optional[int] = None,
    duration_seconds: Optional[float] = None,
) -> int:
    """
    Write one delivery record to the audit log.

    Parameters
    ----------
    group_name : str
        Name of the delivery group (from delivery_config.yaml).
    trigger_mode : str
        One of ``'scheduled'``, ``'manual'``, ``'daemon'``.
    reports_run : list[str]
        Report slugs that were executed, e.g. ``["executive_kpi", "trend_analysis"]``.
    tag_filter : str or None
        Scope string such as ``"Environment=Production"`` or ``"all_assets"``.
    recipients : list[str]
        Email addresses the delivery was attempted to.
    status : str
        One of ``'success'``, ``'partial'``, ``'failed'``.
    output_folder : str
        Absolute path of the output directory for this run.
    error_message : str, optional
        Human-readable error detail — ``None`` on success.
    attachment_size_kb : int, optional
        Total size of all attachments in kilobytes.
    duration_seconds : float, optional
        Wall-clock seconds from report generation start to send completion.

    Returns
    -------
    int
        The ``id`` of the newly inserted row.
    """
    _init_db()

    timestamp = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    row = (
        timestamp,
        group_name,
        trigger_mode,
        json.dumps(reports_run),
        tag_filter or "all_assets",
        json.dumps(recipients),
        status,
        error_message,
        output_folder,
        attachment_size_kb,
        duration_seconds,
    )

    with _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO delivery_log
               (timestamp, group_name, trigger_mode, reports_run, tag_filter,
                recipients, status, error_message, output_folder,
                attachment_size_kb, duration_seconds)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            row,
        )
        conn.commit()
        row_id = cursor.lastrowid

    logger.debug(
        "Delivery log: id=%d group='%s' status=%s", row_id, group_name, status
    )
    return row_id


# ===========================================================================
# Public read API
# ===========================================================================

def get_recent(n: int = 20) -> list[sqlite3.Row]:
    """Return the *n* most recent delivery records, newest first."""
    _init_db()
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM delivery_log ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()


def get_failures() -> list[sqlite3.Row]:
    """Return all records where status is not 'success', newest first."""
    _init_db()
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM delivery_log WHERE status != 'success' ORDER BY id DESC"
        ).fetchall()


def get_by_group(group_name: str) -> list[sqlite3.Row]:
    """Return all records for a specific group name, newest first."""
    _init_db()
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM delivery_log WHERE group_name = ? ORDER BY id DESC",
            (group_name,),
        ).fetchall()


def get_by_date_range(from_date: str, to_date: str) -> list[sqlite3.Row]:
    """
    Return records whose timestamp falls within [from_date, to_date] UTC.

    Parameters
    ----------
    from_date : str
        ISO date string, e.g. ``"2025-01-01"``.  Inclusive start.
    to_date : str
        ISO date string, e.g. ``"2025-01-31"``.  Inclusive end (extended to
        23:59:59 so the full final day is included).
    """
    _init_db()
    # Extend to_date to cover the full final day
    to_ts = f"{to_date}T23:59:59"
    from_ts = f"{from_date}T00:00:00"
    with _connect() as conn:
        return conn.execute(
            """SELECT * FROM delivery_log
               WHERE timestamp >= ? AND timestamp <= ?
               ORDER BY id DESC""",
            (from_ts, to_ts),
        ).fetchall()


# ===========================================================================
# Terminal rendering
# ===========================================================================

def _render_table(rows: list[sqlite3.Row], title: str) -> None:
    """Render a list of delivery log rows as a rich table."""
    if not rows:
        console.print(f"[yellow]{title} — no records found.[/yellow]")
        return

    tbl = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on #1F3864",
        expand=True,
    )
    tbl.add_column("ID",         style="dim",           no_wrap=True, width=5)
    tbl.add_column("Timestamp",  style="cyan",          no_wrap=True, width=20)
    tbl.add_column("Group",      style="bold",          no_wrap=False, width=24)
    tbl.add_column("Trigger",    style="dim",           no_wrap=True, width=10)
    tbl.add_column("Reports",    no_wrap=False,          width=28)
    tbl.add_column("Scope",      style="dim",           no_wrap=False, width=22)
    tbl.add_column("Recipients", no_wrap=False,          width=26)
    tbl.add_column("Status",     no_wrap=True,           width=10)
    tbl.add_column("Size (KB)",  justify="right",        width=9)
    tbl.add_column("Duration",   justify="right",        width=9)
    tbl.add_column("Error",      style="red",           no_wrap=False, width=30)

    for row in rows:
        status_style = _STATUS_STYLE.get(row["status"], "")
        try:
            reports = ", ".join(json.loads(row["reports_run"]))
        except (json.JSONDecodeError, TypeError):
            reports = str(row["reports_run"])
        try:
            recips = ", ".join(json.loads(row["recipients"]))
        except (json.JSONDecodeError, TypeError):
            recips = str(row["recipients"])

        dur = f"{row['duration_seconds']:.1f}s" if row["duration_seconds"] else "—"
        kb  = str(row["attachment_size_kb"]) if row["attachment_size_kb"] else "—"
        err = str(row["error_message"] or "")[:120]

        tbl.add_row(
            str(row["id"]),
            str(row["timestamp"])[:19],
            row["group_name"],
            row["trigger_mode"],
            reports,
            row["tag_filter"] or "all_assets",
            recips,
            f"[{status_style}]{row['status']}[/{status_style}]",
            kb,
            dur,
            err,
        )

    console.print(tbl)
    console.print(f"[dim]{len(rows)} record(s) shown.[/dim]")


# ===========================================================================
# CLI entry point
# ===========================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    parser = argparse.ArgumentParser(
        description="Delivery audit log inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python delivery/delivery_log.py --recent 20
  python delivery/delivery_log.py --failures
  python delivery/delivery_log.py --group "Executive Team"
  python delivery/delivery_log.py --from 2025-01-01 --to 2025-01-31
        """,
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--recent", metavar="N", type=int, nargs="?", const=20,
        help="Show the N most recent records (default 20)",
    )
    mode.add_argument(
        "--failures", action="store_true",
        help="Show all failed or partial delivery records",
    )
    mode.add_argument(
        "--group", metavar="NAME",
        help="Show all records for a specific group name",
    )
    mode.add_argument(
        "--from", dest="from_date", metavar="YYYY-MM-DD",
        help="Show records from this UTC date (use with --to)",
    )

    parser.add_argument(
        "--to", dest="to_date", metavar="YYYY-MM-DD",
        help="End date for --from range (inclusive)",
    )

    args = parser.parse_args()

    if args.recent is not None:
        rows = get_recent(args.recent)
        _render_table(rows, f"Recent Deliveries (last {args.recent})")

    elif args.failures:
        rows = get_failures()
        _render_table(rows, "Failed / Partial Deliveries")

    elif args.group:
        rows = get_by_group(args.group)
        _render_table(rows, f"Deliveries — Group: {args.group}")

    elif args.from_date:
        if not args.to_date:
            console.print("[red]--from requires --to[/red]")
            sys.exit(1)
        rows = get_by_date_range(args.from_date, args.to_date)
        _render_table(rows, f"Deliveries {args.from_date} → {args.to_date}")
