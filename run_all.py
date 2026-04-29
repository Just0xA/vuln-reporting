"""
run_all.py — Master CLI runner for the Vulnerability Management Reporting Suite.

This script is the single entry point for generating reports and sending delivery
emails.  It is called directly by users, by scheduler.py (which imports run_group),
and optionally by cron / Windows Task Scheduler via scheduler.py --mode run-due.

Usage
-----
  python run_all.py                                               # run all groups due now
  python run_all.py --group "Finance Remediation Team"           # run one specific group
  python run_all.py --group "Executive Team" --no-email          # reports only, skip email
  python run_all.py --dry-run                                     # validate config, no API calls
  python run_all.py --tag-category "Environment" --tag-value "Staging"  # override tag filter
  python run_all.py --group "Executive Team" --recipients test@company.com  # override recipients

Exit codes
----------
  0  All selected groups completed (success or partial).
  1  One or more groups failed, or config is invalid (--dry-run).

Public API (imported by scheduler.py)
--------------------------------------
  run_group(group_config, *, tio=None, run_id=None, base_output_dir=None,
            no_email=False, recipient_override=None, tag_category_override=None,
            tag_value_override=None, trigger_mode="scheduled",
            generated_at=None) -> dict

  _load_config() -> list[dict]
  _is_due(group_config, now) -> bool
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import shutil
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.table import Table

_PROJECT_ROOT = str(Path(__file__).resolve().parent)
sys.path.insert(0, _PROJECT_ROOT)

# Remove any stale entries for project-local packages that may have been
# pre-loaded from an installed pip package (e.g. a PyPI 'reports' package)
# before this sys.path manipulation ran.  This happens when run_all is
# imported by scheduler.py or another process that already resolved 'reports'
# from site-packages.  Clearing the cache forces Python to re-resolve from
# _PROJECT_ROOT on the next import.
for _k in [k for k in sys.modules if k in ("reports", "data", "utils")
           or k.startswith(("reports.", "data.", "utils."))]:
    del sys.modules[_k]

from config import CACHE_DIR, LOG_DIR, LOG_LEVEL, OUTPUT_DIR, ROOT_DIR
from utils.formatters import report_timestamp, safe_filename

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Valid report slugs and frequencies
# ---------------------------------------------------------------------------
_VALID_REPORTS: frozenset[str] = frozenset({
    "executive_kpi",
    "sla_remediation",
    "asset_risk",
    "patch_compliance",
    "trend_analysis",
    "plugin_cve",
    "ops_remediation",
    "management_summary",
    "vuln_export",
    "board_summary",
    "unscanned_assets",
})

_VALID_FREQUENCIES: frozenset[str] = frozenset({"weekly", "monthly", "on_demand"})

_VALID_DAYS: frozenset[str] = frozenset({
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
})

# Map config day names to Python weekday() integers (0=Monday)
_DAY_TO_WEEKDAY: dict[str, int] = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
}

# Map report slug -> importable module path
_REPORT_MODULE_MAP: dict[str, str] = {
    "executive_kpi":       "reports.executive_kpi",
    "sla_remediation":     "reports.sla_remediation",
    "asset_risk":          "reports.asset_risk",
    "patch_compliance":    "reports.patch_compliance",
    "trend_analysis":      "reports.trend_analysis",
    "plugin_cve":          "reports.plugin_cve",
    "ops_remediation":     "reports.ops_remediation",
    "management_summary":  "reports.management_summary",
    "vuln_export":         "reports.vuln_export",
    "board_summary":       "reports.board_summary",
    "unscanned_assets":    "reports.unscanned_assets",
}

# Required .env variables checked during --dry-run
_REQUIRED_ENV_VARS: list[str] = [
    "TVM_ACCESS_KEY",
    "TVM_SECRET_KEY",
    "SMTP_HOST",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM_ADDRESS",
]

_STATUS_STYLE: dict[str, str] = {
    "success": "bold green",
    "partial": "bold yellow",
    "failed":  "bold red",
}


# ===========================================================================
# Config loading
# ===========================================================================

def _load_config(config_path: Optional[Path] = None) -> list[dict]:
    """
    Load and return the groups list from delivery_config.yaml.

    Returns an empty list (with a logged error) if the file is missing or
    malformed, so callers can handle the empty-list case gracefully.
    """
    if config_path is None:
        config_path = ROOT_DIR / "delivery_config.yaml"

    if not config_path.exists():
        logger.error("delivery_config.yaml not found at %s", config_path)
        return []

    try:
        with open(config_path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("delivery_config.yaml parse error: %s", exc)
        return []

    if not isinstance(raw, dict):
        logger.error("delivery_config.yaml: root must be a mapping")
        return []

    groups = raw.get("groups")
    if not isinstance(groups, list):
        logger.error("delivery_config.yaml: 'groups' key must be a list")
        return []

    logger.debug("Loaded %d group(s) from delivery_config.yaml", len(groups))
    return groups


# ===========================================================================
# Schedule matching (used by run-due mode in scheduler.py)
# ===========================================================================

def _is_due(group_config: dict, now: datetime, window_minutes: int = 10) -> bool:
    """
    Return True if *group_config* is scheduled to run within ±*window_minutes*
    of *now* (server local time).

    Supports ``frequency: weekly`` (matched by day-of-week + time) and
    ``frequency: monthly`` (matched by day-of-month + time).
    ``on_demand`` groups are never considered due by this function.

    Parameters
    ----------
    group_config : dict
        A single group entry from delivery_config.yaml.
    now : datetime
        The reference time (should be server local, NOT UTC) for comparison.
    window_minutes : int
        How many minutes either side of the configured time to consider a match.
    """
    schedule  = group_config.get("schedule") or {}
    frequency = schedule.get("frequency")
    time_str  = schedule.get("time", "")

    if frequency == "weekly":
        day_name = str(schedule.get("day_of_week", "")).lower().strip()
        target_weekday = _DAY_TO_WEEKDAY.get(day_name)
        if target_weekday is None:
            return False
        if now.weekday() != target_weekday:
            return False

        try:
            h, m = (int(x) for x in str(time_str).split(":"))
        except (ValueError, AttributeError):
            return False

        target_minutes  = h * 60 + m
        current_minutes = now.hour * 60 + now.minute
        return abs(current_minutes - target_minutes) <= window_minutes

    if frequency == "monthly":
        dom_raw = schedule.get("day_of_month")
        if dom_raw is None:
            return False
        try:
            dom = int(dom_raw)
        except (ValueError, TypeError):
            return False
        if now.day != dom:
            return False

        try:
            h, m = (int(x) for x in str(time_str).split(":"))
        except (ValueError, AttributeError):
            return False

        target_minutes  = h * 60 + m
        current_minutes = now.hour * 60 + now.minute
        return abs(current_minutes - target_minutes) <= window_minutes

    return False


# ===========================================================================
# Config validation (used by --dry-run)
# ===========================================================================

def _validate_group(group: dict) -> list[str]:
    """
    Validate a single group config entry.

    Returns a list of human-readable error strings.  An empty list means the
    group is valid.
    """
    errors: list[str] = []

    if not group.get("name"):
        errors.append("Missing required field: 'name'")

    schedule = group.get("schedule") or {}
    frequency = schedule.get("frequency")
    if frequency not in _VALID_FREQUENCIES:
        errors.append(
            f"schedule.frequency must be one of {sorted(_VALID_FREQUENCIES)}, "
            f"got: {frequency!r}"
        )
    elif frequency == "weekly":
        day = str(schedule.get("day_of_week", "")).lower().strip()
        if day not in _VALID_DAYS:
            errors.append(f"schedule.day_of_week invalid: {day!r}")
        if not schedule.get("time"):
            errors.append("schedule.time is required when frequency is 'weekly'")
        else:
            try:
                parts = str(schedule["time"]).split(":")
                if len(parts) != 2:
                    raise ValueError
                int(parts[0]); int(parts[1])
            except (ValueError, AttributeError):
                errors.append(
                    f"schedule.time must be HH:MM format, got: {schedule['time']!r}"
                )
    elif frequency == "monthly":
        dom_raw = schedule.get("day_of_month")
        if dom_raw is None:
            errors.append(
                "schedule.day_of_month is required when frequency is 'monthly'"
            )
        else:
            try:
                dom = int(dom_raw)
                if not (1 <= dom <= 28):
                    raise ValueError(f"value {dom} is outside the allowed range 1–28")
            except (ValueError, TypeError):
                errors.append(
                    f"schedule.day_of_month must be an integer between 1 and 28, "
                    f"got: {dom_raw!r}"
                )
        if not schedule.get("time"):
            errors.append("schedule.time is required when frequency is 'monthly'")
        else:
            try:
                parts = str(schedule["time"]).split(":")
                if len(parts) != 2:
                    raise ValueError
                int(parts[0]); int(parts[1])
            except (ValueError, AttributeError):
                errors.append(
                    f"schedule.time must be HH:MM format, got: {schedule['time']!r}"
                )

    reports = group.get("reports")
    if not isinstance(reports, list) or not reports:
        errors.append("'reports' must be a non-empty list")
    else:
        for r in reports:
            if r not in _VALID_REPORTS:
                errors.append(f"Unknown report slug: {r!r}")

    email = group.get("email") or {}
    recipients = email.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        errors.append("email.recipients must be a non-empty list")

    return errors


def _dry_run(groups: list[dict]) -> int:
    """
    Validate all groups and print a rich summary table.

    Returns exit code: 0 if all valid, 1 if any group has an error or if any
    required .env variables are missing.
    """
    load_dotenv()

    missing_env = [v for v in _REQUIRED_ENV_VARS if not os.getenv(v)]
    any_errors = bool(missing_env)

    if missing_env:
        console.print(
            f"\n[bold red]Missing .env variables:[/bold red] {', '.join(missing_env)}\n"
        )

    tbl = Table(
        title="Delivery Config — Dry Run Validation",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on #1F3864",
        expand=True,
    )
    tbl.add_column("Group",      style="bold",     no_wrap=False, width=26)
    tbl.add_column("Schedule",                     no_wrap=True,  width=22)
    tbl.add_column("Filter",                       no_wrap=True,  width=24)
    tbl.add_column("Reports",                      no_wrap=False, width=36)
    tbl.add_column("Recipients",                   no_wrap=False, width=28)
    tbl.add_column("Status",                       no_wrap=True,  width=8)

    for group in groups:
        errs      = _validate_group(group)
        name      = group.get("name", "[unnamed]")

        schedule  = group.get("schedule") or {}
        freq      = schedule.get("frequency", "?")
        if freq == "weekly":
            sched_str = f"weekly / {schedule.get('day_of_week','?')} {schedule.get('time','?')}"
        elif freq == "monthly":
            sched_str = f"monthly / day {schedule.get('day_of_month','?')} {schedule.get('time','?')}"
        else:
            sched_str = freq

        filters    = group.get("filters") or {}
        cat, val   = filters.get("tag_category"), filters.get("tag_value")
        filter_str = f"{cat} = {val}" if cat and val else "All Assets"

        reports_str = ", ".join(group.get("reports") or [])

        email       = group.get("email") or {}
        recips      = email.get("recipients") or []
        cc_list     = email.get("cc") or []
        recip_str   = ", ".join(recips)
        if cc_list:
            recip_str += f"\nCC: {', '.join(cc_list)}"

        if errs:
            any_errors = True
            status = "[bold red]FAIL[/bold red]"
            for e in errs:
                console.print(f"  [red]✗ {name}: {e}[/red]")
        else:
            status = "[bold green]OK[/bold green]"

        tbl.add_row(name, sched_str, filter_str, reports_str, recip_str, status)

    console.print(tbl)

    if any_errors:
        console.print("\n[bold red]Validation FAILED — fix errors above before running.[/bold red]")
        return 1

    console.print(f"\n[bold green]All {len(groups)} group(s) validated successfully.[/bold green]")
    return 0


# ===========================================================================
# Report module loader
# ===========================================================================

def _import_report(slug: str):
    """
    Dynamically import a report module by slug.

    Returns the module object, or None if the module is not yet built or
    cannot be imported (logs a warning in that case).
    """
    module_path = _REPORT_MODULE_MAP.get(slug)
    if not module_path:
        logger.warning("No module mapping for report slug: %r", slug)
        return None
    try:
        return importlib.import_module(module_path)
    except ImportError as exc:
        logger.warning("Report module '%s' not available (%s) — skipping.", slug, exc)
        return None


# ===========================================================================
# Core execution — shared across all scheduler modes
# ===========================================================================

def run_group(
    group_config: dict,
    *,
    tio=None,
    run_id: Optional[str] = None,
    cache_dir: Optional[Path] = None,
    base_output_dir: Optional[Path] = None,
    no_email: bool = False,
    recipient_override: Optional[list[str]] = None,
    tag_category_override: Optional[str] = None,
    tag_value_override: Optional[str] = None,
    trigger_mode: str = "scheduled",
    generated_at: Optional[datetime] = None,
) -> dict:
    """
    Run all reports for one delivery group and optionally deliver via email.

    This is the single shared execution function called by all three scheduler
    modes (daemon, run-due, manual) and by run_all.py's main loop.

    Parameters
    ----------
    group_config : dict
        A single group entry from delivery_config.yaml.
    tio : TenableIO, optional
        Authenticated Tenable client.  If not provided, one is created via
        ``tenable_client.get_client()``.  Pass a pre-created instance when
        running multiple groups in sequence to reuse the connection.
    run_id : str, optional
        Cache key for parquet files.  Defaults to today's date (YYYY-MM-DD).
        Use the same run_id across all groups in one batch to share the cache.
    base_output_dir : Path, optional
        Parent directory under which the group's timestamped output folder is
        created.  Defaults to ``OUTPUT_DIR`` from config.
    no_email : bool
        If True, reports are generated but the email is not sent.
    recipient_override : list[str], optional
        Replace the configured recipients with this list.  CC is cleared.
        Useful for test runs and ad-hoc delivery.
    tag_category_override : str, optional
        Override the group's ``filters.tag_category``.
    tag_value_override : str, optional
        Override the group's ``filters.tag_value``.
    trigger_mode : str
        One of ``"scheduled"``, ``"manual"``, ``"daemon"``.  Written to the
        delivery audit log.
    generated_at : datetime, optional
        Override the report timestamp.  Defaults to UTC now.

    Returns
    -------
    dict
        Always returns — never raises.  Keys:
        ``group_name``, ``status``, ``output_folder``, ``duration_seconds``,
        ``reports_generated``, ``email_status``, ``error``.
        ``status`` is one of ``"success"``, ``"partial"``, ``"failed"``.
    """
    start_time  = time.monotonic()
    group_name  = group_config.get("name", "Unknown Group")

    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if run_id is None:
        run_id = datetime.now().strftime("%Y-%m-%d")
    if cache_dir is None:
        cache_dir = CACHE_DIR / datetime.now().strftime("%Y-%m-%d")
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if base_output_dir is None:
        base_output_dir = OUTPUT_DIR

    # Build timestamped output directory
    ts_str         = generated_at.strftime("%Y-%m-%d_%H-%M")
    group_dir_name = safe_filename(f"{ts_str}_{group_name}")
    group_output_dir = Path(base_output_dir) / group_dir_name
    group_output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(
        "=== Starting group '%s' (trigger=%s, run_id=%s) ===",
        group_name, trigger_mode, run_id,
    )
    logger.info("Output directory: %s", group_output_dir)

    # Resolve tag filter (CLI override takes precedence over group config)
    filters      = group_config.get("filters") or {}
    tag_category = tag_category_override or filters.get("tag_category")
    tag_value    = tag_value_override    or filters.get("tag_value")

    # Ensure Tenable client is available
    if tio is None:
        try:
            from tenable_client import get_client  # noqa: PLC0415
            tio = get_client()
        except SystemExit:
            raise  # propagate — tenable_client already logged the error
        except Exception as exc:
            err_msg = f"Tenable connection failed: {exc}"
            logger.error("[%s] %s\n%s", group_name, err_msg, traceback.format_exc())
            return {
                "group_name":        group_name,
                "status":            "failed",
                "output_folder":     str(group_output_dir),
                "duration_seconds":  round(time.monotonic() - start_time, 2),
                "reports_generated": [],
                "email_status":      "not_attempted",
                "error":             err_msg,
            }

    # ------------------------------------------------------------------
    # Structured group-start log (3c)
    # ------------------------------------------------------------------
    filter_str = (
        f"{tag_category}={tag_value}"
        if tag_category and tag_value
        else "all assets"
    )
    logger.info(
        "[INFO] Starting group: %s | Filter: %s | Cache: %s",
        group_name, filter_str, cache_dir,
    )

    # ------------------------------------------------------------------
    # Pre-fetch: warm the run-scoped parquet cache before any report runs.
    # All reports in this group — and all other groups in the same
    # run_all.py invocation that share cache_dir — will load from
    # [CACHE HIT] instead of triggering their own Tenable export API call.
    # A failure here is non-fatal: each report will fall back to fetching
    # individually, which is the existing behaviour.
    # ------------------------------------------------------------------
    try:
        from data.fetchers import (  # noqa: PLC0415
            fetch_all_assets,
            fetch_all_vulnerabilities,
        )
        logger.info("[%s] Pre-fetching: vulns_all + assets_all…", group_name)
        fetch_all_vulnerabilities(tio, cache_dir)
        fetch_all_assets(tio, cache_dir)
        logger.info("[%s] Pre-fetch complete.", group_name)
    except Exception as exc:
        logger.warning(
            "[%s] Pre-fetch failed (%s) — reports will attempt to fetch individually.",
            group_name, exc,
        )

    # ------------------------------------------------------------------
    # Run each configured report
    # ------------------------------------------------------------------
    report_slugs: list[str]      = group_config.get("reports", [])
    report_outputs: dict[str, dict] = {}
    reports_generated: list[str] = []

    for slug in report_slugs:
        report_module = _import_report(slug)
        if report_module is None:
            continue  # warning already logged inside _import_report

        report_output_dir = group_output_dir / slug

        try:
            logger.info("[%s] Running report: %s", group_name, slug)
            # Build kwargs — add slug-specific extras where applicable
            report_kwargs: dict = dict(
                tag_category=tag_category,
                tag_value=tag_value,
                output_dir=report_output_dir,
                generated_at=generated_at,
                cache_dir=cache_dir,
            )
            if slug == "vuln_export":
                csv_severities = group_config.get("csv_severities")
                if csv_severities is not None:
                    report_kwargs["csv_severities"] = csv_severities
            if slug == "unscanned_assets":
                report_kwargs["scan_window_days"] = group_config.get("scan_window_days", 30)
            result = report_module.run_report(tio, run_id, **report_kwargs)
            report_outputs[slug]  = result
            reports_generated.append(slug)
            logger.info("[%s] Report '%s' complete.", group_name, slug)

        except Exception as exc:
            logger.error(
                "[%s] Report '%s' failed: %s\n%s",
                group_name, slug, exc, traceback.format_exc(),
            )
            # Continue with remaining reports

    # ------------------------------------------------------------------
    # Email delivery
    # ------------------------------------------------------------------
    email_status = "skipped"

    if no_email:
        logger.info("[%s] Email delivery skipped (--no-email).", group_name)
    elif not report_outputs:
        logger.warning("[%s] No reports generated — skipping email.", group_name)
        email_status = "no_reports"
    else:
        # Build effective group config (apply recipient override if provided)
        if recipient_override:
            effective_cfg = dict(group_config)
            effective_cfg["email"] = dict(group_config.get("email") or {})
            effective_cfg["email"]["recipients"] = recipient_override
            effective_cfg["email"]["cc"] = []
        else:
            effective_cfg = group_config

        try:
            from delivery.email_sender import send_report_email  # noqa: PLC0415
            success      = send_report_email(effective_cfg, report_outputs, trigger_mode)
            email_status = "sent" if success else "failed"
        except Exception as exc:
            logger.error(
                "[%s] Email send raised an unexpected exception: %s\n%s",
                group_name, exc, traceback.format_exc(),
            )
            email_status = "error"

    # ------------------------------------------------------------------
    # Summarise result
    # ------------------------------------------------------------------
    duration = round(time.monotonic() - start_time, 2)

    if not reports_generated:
        status = "failed"
    elif email_status in ("sent", "skipped"):
        status = "success"
    elif email_status in ("failed", "error"):
        status = "partial"
    else:
        status = "success"

    logger.info(
        "=== Group '%s' done in %.1fs (status=%s, email=%s, reports=%s) ===",
        group_name, duration, status, email_status, reports_generated,
    )

    return {
        "group_name":        group_name,
        "status":            status,
        "output_folder":     str(group_output_dir),
        "duration_seconds":  duration,
        "reports_generated": reports_generated,
        "email_status":      email_status,
        "error":             None,
    }


# ===========================================================================
# Rich summary table
# ===========================================================================

def _print_summary(results: list[dict]) -> None:
    """Print a rich table summarising one or more group run results."""
    tbl = Table(
        title="Report Run Summary",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on #1F3864",
        expand=True,
    )
    tbl.add_column("Group",              style="bold", no_wrap=False, width=26)
    tbl.add_column("Reports Generated",               no_wrap=False, width=36)
    tbl.add_column("Email",                           no_wrap=True,  width=10)
    tbl.add_column("Status",                          no_wrap=True,  width=10)
    tbl.add_column("Duration",           justify="right", width=9)
    tbl.add_column("Output Folder",                   no_wrap=False, width=42)

    for r in results:
        status    = r.get("status", "unknown")
        style     = _STATUS_STYLE.get(status, "")
        dur_str   = f"{r['duration_seconds']:.1f}s" if r.get("duration_seconds") is not None else "?"
        rep_str   = ", ".join(r.get("reports_generated") or []) or "[dim]none[/dim]"
        email_str = r.get("email_status", "?")

        tbl.add_row(
            r.get("group_name", "?"),
            rep_str,
            email_str,
            f"[{style}]{status}[/{style}]",
            dur_str,
            r.get("output_folder", "?"),
        )

    console.print(tbl)

    failed_count  = sum(1 for r in results if r.get("status") == "failed")
    partial_count = sum(1 for r in results if r.get("status") == "partial")

    if failed_count:
        console.print(f"[bold red]{failed_count} group(s) failed.[/bold red]")
    if partial_count:
        console.print(f"[bold yellow]{partial_count} group(s) partial (email not sent).[/bold yellow]")
    if not failed_count and not partial_count:
        console.print(f"[bold green]All {len(results)} group(s) completed successfully.[/bold green]")


# ===========================================================================
# CLI entry point
# ===========================================================================

class _ThirdPartyFilter(logging.Filter):
    """Drop sub-WARNING records from libraries that reset their own log levels at runtime.

    fontTools.subset explicitly calls logger.setLevel(DEBUG) on child loggers
    during font subsetting, which overrides any parent-level WARNING we set.
    A handler-level filter is the only reliable way to suppress these because
    it intercepts the record after propagation, regardless of per-logger levels.
    """
    _NOISY = ("fontTools", "weasyprint.progress")

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno < logging.WARNING:
            for prefix in self._NOISY:
                if record.name == prefix or record.name.startswith(prefix + "."):
                    return False
        return True


def main() -> int:
    _log_level = getattr(logging, LOG_LEVEL, logging.INFO)
    _handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ]
    # When not in DEBUG mode attach a filter to every handler so that
    # libraries which explicitly reset child-logger levels at runtime
    # (fontTools.subset does this during font subsetting) cannot sneak
    # DEBUG/INFO records through propagation.
    if _log_level > logging.DEBUG:
        _f = _ThirdPartyFilter()
        for _h in _handlers:
            _h.addFilter(_f)

    logging.basicConfig(
        level=_log_level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        handlers=_handlers,
        force=True,  # replace any handlers added by third-party imports before main()
    )

    parser = argparse.ArgumentParser(
        description="Vulnerability Management Reporting Suite — master runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_all.py                                                # run all groups due now
  python run_all.py --group "Finance Remediation Team"            # run one group
  python run_all.py --group "Executive Team" --no-email           # generate only
  python run_all.py --dry-run                                      # validate config
  python run_all.py --tag-category "Environment" --tag-value "Staging"
  python run_all.py --group "Executive Team" --recipients test@company.com
        """,
    )
    parser.add_argument(
        "--group",        metavar="NAME",
        help="Run a specific group by name (bypasses schedule check)",
    )
    parser.add_argument(
        "--no-email",     action="store_true",
        help="Generate reports but skip email delivery",
    )
    parser.add_argument(
        "--dry-run",      action="store_true",
        help="Validate delivery_config.yaml and .env — no API calls, no files written",
    )
    parser.add_argument(
        "--tag-category", metavar="CATEGORY",
        help="Override tag category filter for all selected groups",
    )
    parser.add_argument(
        "--tag-value",    metavar="VALUE",
        help="Override tag value filter for all selected groups",
    )
    parser.add_argument(
        "--recipients",   metavar="EMAIL[,EMAIL...]",
        help="Override recipient list (comma-separated); clears CC",
    )

    args = parser.parse_args()

    load_dotenv()

    groups = _load_config()
    if not groups and not args.dry_run:
        console.print("[red]No groups found in delivery_config.yaml — nothing to run.[/red]")
        return 1

    # ------------------------------------------------------------------
    # Dry-run: validate only
    # ------------------------------------------------------------------
    if args.dry_run:
        return _dry_run(groups)

    # ------------------------------------------------------------------
    # Select groups to run
    # ------------------------------------------------------------------
    if args.group:
        selected = [g for g in groups if g.get("name") == args.group]
        if not selected:
            console.print(
                f"[red]Group '{args.group}' not found in delivery_config.yaml.[/red]\n"
                f"Available groups: {', '.join(g.get('name','?') for g in groups)}"
            )
            return 1
        trigger_mode = "manual"
    else:
        now      = datetime.now()  # server local time for schedule matching
        selected = [g for g in groups if _is_due(g, now)]
        if not selected:
            console.print(
                f"[yellow]No groups are due at {now.strftime('%A %H:%M')} "
                f"— nothing to run.[/yellow]"
            )
            return 0
        trigger_mode = "scheduled"

    console.print(
        f"\n[bold]Running {len(selected)} group(s): "
        f"{', '.join(g.get('name','?') for g in selected)}[/bold]\n"
    )

    # ------------------------------------------------------------------
    # Create a single Tenable client shared across all groups
    # ------------------------------------------------------------------
    try:
        from tenable_client import get_client  # noqa: PLC0415
        tio = get_client()
    except SystemExit:
        raise  # tenable_client already printed the error; propagate exit
    except Exception as exc:
        console.print(f"[red]Tenable connection failed: {exc}[/red]")
        return 1

    # Parse recipient override
    recipient_override: Optional[list[str]] = None
    if args.recipients:
        recipient_override = [r.strip() for r in args.recipients.split(",") if r.strip()]

    # Shared run_id and cache_dir so all groups in this batch share the parquet cache
    generated_at  = datetime.now(tz=timezone.utc)
    _today_local  = datetime.now().strftime("%Y-%m-%d")
    run_id        = _today_local
    cache_dir     = CACHE_DIR / _today_local
    cache_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Run cache directory: %s", cache_dir)

    # Remove cache folders from previous days, keep only today's
    for _old in CACHE_DIR.iterdir():
        if _old.is_dir() and _old.name != _today_local:
            try:
                shutil.rmtree(_old)
                logger.info("Removed stale cache folder: %s", _old)
            except Exception as _e:
                logger.warning("Could not remove stale cache folder %s: %s", _old, _e)

    # ------------------------------------------------------------------
    # Execute each group (failures in one group never stop the others)
    # ------------------------------------------------------------------
    results: list[dict] = []

    for group in selected:
        result = run_group(
            group,
            tio=tio,
            run_id=run_id,
            cache_dir=cache_dir,
            no_email=args.no_email,
            recipient_override=recipient_override,
            tag_category_override=args.tag_category,
            tag_value_override=args.tag_value,
            trigger_mode=trigger_mode,
            generated_at=generated_at,
        )
        results.append(result)

    # ------------------------------------------------------------------
    # Print summary and exit
    # ------------------------------------------------------------------
    console.print()
    _print_summary(results)

    return 1 if any(r["status"] == "failed" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
