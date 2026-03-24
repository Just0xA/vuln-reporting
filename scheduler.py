"""
scheduler.py — Flexible report scheduler supporting three execution modes.

MODE 1: APScheduler daemon (always-on process)
    python scheduler.py --mode daemon

    Reads delivery_config.yaml on startup and schedules all 'weekly' and
    'monthly' groups using APScheduler CronTrigger (server local time).
    Hot-reloads the config every 5 minutes — reschedules changed groups
    without a restart.  Handles SIGTERM/SIGINT gracefully: waits for any
    in-progress job to finish before exiting.

MODE 2: Single-run for cron / Windows Task Scheduler
    python scheduler.py --mode run-due

    Reads delivery_config.yaml, runs all groups whose schedule matches the
    current time within a ±10-minute window (day_of_week + time for weekly
    groups; day_of_month + time for monthly groups), then exits cleanly.
    Designed to be called every 5–10 minutes by an external scheduler.

MODE 3: Manual / on-demand
    python scheduler.py --mode manual --group "Finance Remediation Team"
    python scheduler.py --mode manual --all-on-demand
    python scheduler.py --mode manual --group "Executive Team" --no-email
    python scheduler.py --mode manual --group "Group" --recipients a@b.com,c@d.com

    Runs a specific named group or all on-demand groups immediately.
    Supports --no-email and --recipients override for safe test runs.

All three modes call run_group() from run_all.py — behaviour is identical
regardless of how execution is triggered.

Failures in one group never stop processing of remaining groups.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import LOG_DIR, LOG_LEVEL, ROOT_DIR
from run_all import _is_due, _load_config, run_group
from utils.formatters import safe_filename

# ---------------------------------------------------------------------------
# Logging — rotating scheduler log + stdout
# ---------------------------------------------------------------------------
_LOG_FILE = LOG_DIR / "scheduler.log"


def _setup_logging() -> None:
    """Configure root logger: rotating file + stdout handler."""
    root = logging.getLogger()
    if root.handlers:
        return  # Already configured (e.g. if imported then run directly)

    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s")

    fh = RotatingFileHandler(
        _LOG_FILE,
        maxBytes=10 * 1024 * 1024,   # 10 MB per file
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)

    root.addHandler(fh)
    root.addHandler(ch)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Day name → APScheduler CronTrigger abbreviation
# ---------------------------------------------------------------------------
_DAY_ABBR: dict[str, str] = {
    "monday":    "mon",
    "tuesday":   "tue",
    "wednesday": "wed",
    "thursday":  "thu",
    "friday":    "fri",
    "saturday":  "sat",
    "sunday":    "sun",
}


# ===========================================================================
# Shared job wrapper
# ===========================================================================

def _run_group_safe(group_config: dict, trigger_mode: str = "daemon") -> None:
    """
    APScheduler job wrapper — calls run_group() and catches all exceptions.

    Prevents a single group failure from crashing the scheduler or interfering
    with other pending jobs.
    """
    group_name = group_config.get("name", "Unknown Group")
    try:
        run_group(group_config, trigger_mode=trigger_mode)
    except Exception:
        logger.exception(
            "Unhandled exception while running group '%s'", group_name
        )


# ===========================================================================
# MODE 1 — Daemon
# ===========================================================================

#: Tracks the last-seen mtime of delivery_config.yaml for hot-reload detection.
_config_mtime: float = 0.0


def _schedule_groups(scheduler, groups: list[dict]) -> None:
    """
    (Re)schedule all weekly and monthly groups on *scheduler*.

    Removes all previously-scheduled group jobs first (identified by the
    ``group_`` prefix in their job ID), then adds fresh jobs for every group
    with ``frequency: weekly`` or ``frequency: monthly``.  The
    ``_reload_check`` meta-job is preserved.  Groups with ``frequency:
    on_demand`` are skipped — they only run when triggered manually.

    Safe to call repeatedly — used by both initial setup and hot-reload.
    """
    from apscheduler.triggers.cron import CronTrigger  # noqa: PLC0415

    # Remove all group jobs while leaving the reload-check job intact
    for job in scheduler.get_jobs():
        if job.id != "_reload_check":
            try:
                job.remove()
            except Exception:
                pass

    scheduled_count = 0

    for group in groups:
        schedule   = group.get("schedule") or {}
        group_name = group.get("name", "Unknown Group")
        frequency  = schedule.get("frequency")
        time_str   = schedule.get("time", "")

        if frequency == "weekly":
            day_name = str(schedule.get("day_of_week", "")).lower().strip()

            if day_name not in _DAY_ABBR:
                logger.warning(
                    "Group '%s': unknown day_of_week '%s' — not scheduled.",
                    group_name, day_name,
                )
                continue

            try:
                hour, minute = (int(x) for x in str(time_str).split(":"))
            except (ValueError, AttributeError):
                logger.warning(
                    "Group '%s': invalid time '%s' — not scheduled.",
                    group_name, time_str,
                )
                continue

            trigger = CronTrigger(
                day_of_week=_DAY_ABBR[day_name],
                hour=hour,
                minute=minute,
            )
            logger.info(
                "Scheduled: '%s' — every %s at %s (server local time)",
                group_name, day_name, time_str,
            )

        elif frequency == "monthly":
            dom_raw = schedule.get("day_of_month")

            if dom_raw is None:
                logger.warning(
                    "Group '%s': day_of_month missing — not scheduled.",
                    group_name,
                )
                continue

            try:
                dom = int(dom_raw)
                if not (1 <= dom <= 28):
                    raise ValueError(f"day_of_month {dom} is outside the allowed range 1–28")
            except (ValueError, TypeError):
                logger.warning(
                    "Group '%s': invalid day_of_month '%s' — not scheduled.",
                    group_name, dom_raw,
                )
                continue

            try:
                hour, minute = (int(x) for x in str(time_str).split(":"))
            except (ValueError, AttributeError):
                logger.warning(
                    "Group '%s': invalid time '%s' — not scheduled.",
                    group_name, time_str,
                )
                continue

            trigger = CronTrigger(
                day=dom,
                hour=hour,
                minute=minute,
            )
            logger.info(
                "Scheduled: '%s' — day %d of each month at %s (server local time)",
                group_name, dom, time_str,
            )

        else:
            # on_demand and unrecognised frequencies are not scheduled in daemon mode
            continue

        job_id = f"group_{safe_filename(group_name)}"

        scheduler.add_job(
            _run_group_safe,
            trigger=trigger,
            id=job_id,
            name=group_name,
            replace_existing=True,
            misfire_grace_time=600,           # allow up to 10 minutes late
            kwargs={"group_config": group, "trigger_mode": "daemon"},
        )
        scheduled_count += 1

    logger.info("Groups scheduled (weekly + monthly): %d", scheduled_count)


def _make_reload_check(scheduler) -> callable:
    """
    Return a closure that checks whether delivery_config.yaml has been
    modified and, if so, reloads it and reschedules all jobs.

    The closure is registered as the ``_reload_check`` APScheduler job.
    """
    def _reload_check() -> None:
        global _config_mtime
        config_path = ROOT_DIR / "delivery_config.yaml"

        try:
            current_mtime = config_path.stat().st_mtime
        except FileNotFoundError:
            logger.warning("delivery_config.yaml not found during reload check.")
            return

        if current_mtime == _config_mtime:
            return  # No change — nothing to do

        logger.info("delivery_config.yaml changed — reloading and rescheduling...")
        _config_mtime = current_mtime
        groups = _load_config()
        _schedule_groups(scheduler, groups)

    return _reload_check


def daemon_mode() -> None:
    """
    Start the APScheduler blocking daemon.

    Schedules all weekly and monthly delivery groups and adds a 5-minute
    hot-reload job.
    SIGTERM and SIGINT are caught; the main thread waits for the signal, then
    calls scheduler.shutdown(wait=True) to let any running jobs finish before
    the process exits.
    """
    from apscheduler.schedulers.blocking import BlockingScheduler   # noqa: PLC0415
    from apscheduler.triggers.interval import IntervalTrigger       # noqa: PLC0415

    global _config_mtime

    _setup_logging()
    load_dotenv()

    logger.info("=== Vulnerability Report Scheduler — DAEMON mode starting ===")
    logger.info("Log file: %s", _LOG_FILE)

    scheduler = BlockingScheduler()

    # Record initial mtime so the first reload check knows the baseline
    config_path = ROOT_DIR / "delivery_config.yaml"
    try:
        _config_mtime = config_path.stat().st_mtime
    except FileNotFoundError:
        logger.error("delivery_config.yaml not found at %s", config_path)

    # Schedule all weekly and monthly groups
    groups = _load_config()
    _schedule_groups(scheduler, groups)

    # Add hot-reload check job (runs every 5 minutes)
    scheduler.add_job(
        _make_reload_check(scheduler),
        trigger=IntervalTrigger(minutes=5),
        id="_reload_check",
        name="Config hot-reload",
        replace_existing=True,
    )
    logger.info(
        "Hot-reload check active — delivery_config.yaml polled every 5 minutes."
    )

    # ------------------------------------------------------------------
    # Signal handling: set an event from the signal handler, then shut
    # down cleanly from the main thread (not from within the handler).
    # ------------------------------------------------------------------
    _stop_event = threading.Event()

    def _on_signal(signum, _frame):
        sig_name = signal.Signals(signum).name
        logger.info(
            "Signal %s received — waiting for running jobs to finish before exit...",
            sig_name,
        )
        _stop_event.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    # Run the blocking scheduler in a background daemon thread
    sched_thread = threading.Thread(
        target=scheduler.start,
        name="apscheduler-main",
        daemon=True,
    )
    sched_thread.start()
    logger.info(
        "Scheduler running.  Waiting for jobs or shutdown signal (SIGTERM/SIGINT)..."
    )

    # Block main thread here — woken by the signal handler
    _stop_event.wait()

    logger.info("Shutting down scheduler...")
    scheduler.shutdown(wait=True)
    logger.info("=== Scheduler exited cleanly. ===")


# ===========================================================================
# MODE 2 — Run-due
# ===========================================================================

def run_due_mode() -> int:
    """
    Identify and run all groups whose schedule matches the current time.

    Groups are considered "due" if their configured day_of_week and time are
    within ±10 minutes of the current server local time.

    Returns
    -------
    int
        Exit code: 0 if all due groups succeeded, 1 if any failed.
    """
    _setup_logging()
    load_dotenv()

    logger.info("=== Vulnerability Report Scheduler — RUN-DUE mode ===")

    groups = _load_config()
    now    = datetime.now()     # server local time for schedule matching

    due = [g for g in groups if _is_due(g, now)]

    if not due:
        logger.info(
            "No groups are due at %s (%s) — exiting.",
            now.strftime("%A %H:%M"),
            now.strftime("%Y-%m-%d"),
        )
        return 0

    logger.info(
        "%d group(s) due at %s: %s",
        len(due),
        now.strftime("%A %H:%M"),
        [g.get("name") for g in due],
    )

    any_failed = False
    for group in due:
        result = run_group(group, trigger_mode="scheduled")
        if result.get("status") == "failed":
            any_failed = True

    return 1 if any_failed else 0


# ===========================================================================
# MODE 3 — Manual / on-demand
# ===========================================================================

def manual_mode(
    group_name: Optional[str],
    all_on_demand: bool,
    no_email: bool,
    recipients: Optional[list[str]],
) -> int:
    """
    Run a specific named group, or all groups with ``frequency: on_demand``.

    Parameters
    ----------
    group_name : str or None
        Exact group name to run.  Mutually exclusive with *all_on_demand*.
    all_on_demand : bool
        If True, run all groups with ``schedule.frequency: on_demand``.
    no_email : bool
        Pass through to run_group — suppresses email delivery.
    recipients : list[str] or None
        If provided, overrides the configured recipients for all groups run.

    Returns
    -------
    int
        Exit code: 0 on full success, 1 if any group failed or was not found.
    """
    _setup_logging()
    load_dotenv()

    logger.info("=== Vulnerability Report Scheduler — MANUAL mode ===")

    groups = _load_config()

    if group_name:
        targets = [g for g in groups if g.get("name") == group_name]
        if not targets:
            logger.error(
                "Group '%s' not found in delivery_config.yaml.  "
                "Available: %s",
                group_name,
                [g.get("name") for g in groups],
            )
            return 1

    elif all_on_demand:
        targets = [
            g for g in groups
            if (g.get("schedule") or {}).get("frequency") == "on_demand"
        ]
        if not targets:
            logger.info(
                "No groups with frequency: on_demand found in delivery_config.yaml."
            )
            return 0

    else:
        logger.error(
            "Manual mode requires --group <name> or --all-on-demand."
        )
        return 1

    logger.info(
        "Running %d group(s): %s",
        len(targets),
        [g.get("name") for g in targets],
    )

    any_failed = False
    for group in targets:
        result = run_group(
            group,
            no_email=no_email,
            recipient_override=recipients,
            trigger_mode="manual",
        )
        if result.get("status") == "failed":
            any_failed = True

    return 1 if any_failed else 0


# ===========================================================================
# CLI entry point
# ===========================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vulnerability Management Report Scheduler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  daemon       Always-on APScheduler process (run as a systemd service).
  run-due      Single-run: execute groups due now, then exit (use with cron).
  manual       Run a named group or all on-demand groups immediately.

Examples:
  # Mode 1 — daemon
  python scheduler.py --mode daemon

  # Mode 2 — cron / Windows Task Scheduler (call every 5–10 minutes)
  python scheduler.py --mode run-due

  # Mode 3 — manual triggers
  python scheduler.py --mode manual --group "Finance Remediation Team"
  python scheduler.py --mode manual --all-on-demand
  python scheduler.py --mode manual --group "Executive Team" --no-email
  python scheduler.py --mode manual --group "Executive Team" --recipients test@co.com
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["daemon", "run-due", "manual"],
        required=True,
        help="Execution mode",
    )
    parser.add_argument(
        "--group",        metavar="NAME",
        help="(manual) Run this specific group by name",
    )
    parser.add_argument(
        "--all-on-demand", action="store_true",
        help="(manual) Run all groups with frequency: on_demand",
    )
    parser.add_argument(
        "--no-email",     action="store_true",
        help="Generate reports but skip email delivery",
    )
    parser.add_argument(
        "--recipients",   metavar="EMAIL[,EMAIL...]",
        help="Override recipient list (comma-separated); clears CC",
    )

    args = parser.parse_args()

    if args.mode == "daemon":
        daemon_mode()
        return 0

    if args.mode == "run-due":
        return run_due_mode()

    if args.mode == "manual":
        recipient_list: Optional[list[str]] = None
        if args.recipients:
            recipient_list = [
                r.strip() for r in args.recipients.split(",") if r.strip()
            ]
        return manual_mode(
            group_name=args.group,
            all_on_demand=args.all_on_demand,
            no_email=args.no_email,
            recipients=recipient_list,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
