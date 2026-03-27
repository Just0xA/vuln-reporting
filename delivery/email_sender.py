"""
delivery/email_sender.py — SMTP email delivery with attachments and inline charts.

All SMTP configuration is loaded from .env via python-dotenv.  No credentials
are hardcoded.

Protocol:
  - STARTTLS on port 587 (default)
  - SSL on port 465 when SMTP_USE_SSL=true in .env

Attachment handling:
  - PDFs and Excel files attached as MIME application/octet-stream
  - Top 2–3 chart PNGs embedded as inline CID images (MIMEImage)
  - If total attachment size exceeds MAX_ATTACHMENT_SIZE_MB, Excel files are
    dropped and a note is added to the email body

Reliability:
  - Tenacity retries (up to 3) with exponential backoff on SMTP errors
  - All exceptions caught; failures logged with full traceback
  - Delivery result written to delivery_log.db regardless of outcome
  - Returns True on success, False on any failure — never raises

Public API
----------
send_report_email(group_config, report_outputs, trigger_mode) -> bool
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
import sys
import time
import traceback
from datetime import datetime, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import LOG_DIR, LOG_LEVEL, MAX_ATTACHMENT_SIZE_MB
from delivery.delivery_log import log_delivery
from delivery.email_template import build_email_body

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Email address validation
# ---------------------------------------------------------------------------
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# ---------------------------------------------------------------------------
# SMTP configuration — read once at module load time
# ---------------------------------------------------------------------------
def _smtp_cfg() -> dict:
    """Read SMTP settings from environment variables."""
    return {
        "host":         os.getenv("SMTP_HOST", "smtp.office365.com"),
        "port":         int(os.getenv("SMTP_PORT", "587")),
        "username":     os.getenv("SMTP_USERNAME", ""),
        "password":     os.getenv("SMTP_PASSWORD", ""),
        "from_address": os.getenv("SMTP_FROM_ADDRESS", ""),
        "from_name":    os.getenv("SMTP_FROM_NAME", "Vulnerability Management Reports"),
        "use_ssl":      os.getenv("SMTP_USE_SSL", "false").lower() == "true",
    }


# ---------------------------------------------------------------------------
# Retry policy — applied to the SMTP send call only
# ---------------------------------------------------------------------------
_SMTP_RETRY = dict(
    retry=retry_if_exception_type((smtplib.SMTPException, ConnectionError, TimeoutError, OSError)),
    wait=wait_exponential(multiplier=2, min=4, max=30),
    stop=stop_after_attempt(3),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)


# ===========================================================================
# Internal helpers
# ===========================================================================

def _validate_addresses(addresses: list[str]) -> list[str]:
    """
    Filter *addresses* to only valid RFC-ish email strings.

    Logs a warning for each address that fails validation.
    Returns a list of valid addresses (may be shorter than input).
    """
    valid = []
    for addr in addresses:
        addr = addr.strip()
        if _EMAIL_RE.match(addr):
            valid.append(addr)
        else:
            logger.warning("Skipping invalid email address: %r", addr)
    return valid


def _collect_attachments(report_outputs: dict) -> tuple[list[Path], list[Path]]:
    """
    Collect all PDF and Excel file paths from report_outputs.

    Returns
    -------
    (pdf_paths, excel_paths)
        Both lists contain only paths that exist on disk.
    """
    pdfs:   list[Path] = []
    excels: list[Path] = []

    for slug, output in report_outputs.items():
        if not isinstance(output, dict):
            continue
        pdf  = output.get("pdf")
        xlsx = output.get("excel")
        if pdf and Path(pdf).exists():
            pdfs.append(Path(pdf))
        if xlsx and Path(xlsx).exists():
            excels.append(Path(xlsx))

    return pdfs, excels


def _collect_chart_pngs(report_outputs: dict, max_charts: int = 3) -> list[Path]:
    """
    Return the first *max_charts* chart PNG paths across all reports, in
    the order reports appear in report_outputs.
    """
    charts: list[Path] = []
    for slug, output in report_outputs.items():
        if not isinstance(output, dict):
            continue
        for p in (output.get("charts") or []):
            path = Path(p)
            if path.exists() and path.suffix.lower() == ".png":
                charts.append(path)
            if len(charts) >= max_charts:
                return charts
    return charts


def _total_size_bytes(paths: list[Path]) -> int:
    """Return the combined file size in bytes for a list of paths."""
    return sum(p.stat().st_size for p in paths if p.exists())


def _format_address(name: str, addr: str) -> str:
    """Return ``"Display Name <addr>"`` or just ``"addr"``."""
    name = name.strip()
    if name:
        # Escape any quotes in the display name
        name = name.replace('"', '\\"')
        return f'"{name}" <{addr}>'
    return addr


def _attach_file(msg: MIMEMultipart, path: Path) -> None:
    """Attach *path* to *msg* as a generic binary attachment."""
    with open(path, "rb") as fh:
        data = fh.read()
    part = MIMEBase("application", "octet-stream")
    part.set_payload(data)
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        "attachment",
        filename=path.name,
    )
    msg.attach(part)
    logger.debug("Attached file: %s (%d KB)", path.name, len(data) // 1024)


def _attach_inline_chart(msg: MIMEMultipart, path: Path, cid_index: int) -> None:
    """
    Embed a PNG as an inline CID image.

    The Content-ID header is set to ``<chart_N>`` (angle-bracket format as
    required by RFC 2045).  The template references it as ``cid:chart_N``
    (without brackets), which is the correct usage in HTML src attributes.
    """
    with open(path, "rb") as fh:
        img_data = fh.read()
    img = MIMEImage(img_data, _subtype="png")
    img.add_header("Content-ID", f"<chart_{cid_index}>")
    img.add_header("Content-Disposition", "inline", filename=path.name)
    msg.attach(img)
    logger.debug("Embedded chart_%d: %s", cid_index, path.name)


@retry(**_SMTP_RETRY)
def _smtp_send(
    cfg: dict,
    from_addr: str,
    to_addrs: list[str],
    raw_message: bytes,
) -> None:
    """
    Open an SMTP connection and deliver the message.

    Wrapped by tenacity — retried up to 3 times on transient failures.
    Raises on permanent failure (reraise=True).
    """
    if cfg["use_ssl"]:
        # Direct SSL — typically port 465
        with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=30) as smtp:
            smtp.login(cfg["username"], cfg["password"])
            smtp.sendmail(from_addr, to_addrs, raw_message)
            logger.debug(
                "Sent via SMTP_SSL to %d recipient(s) via %s:%d",
                len(to_addrs), cfg["host"], cfg["port"],
            )
    else:
        # STARTTLS — typically port 587
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(cfg["username"], cfg["password"])
            smtp.sendmail(from_addr, to_addrs, raw_message)
            logger.debug(
                "Sent via STARTTLS to %d recipient(s) via %s:%d",
                len(to_addrs), cfg["host"], cfg["port"],
            )


def _output_folder(report_outputs: dict) -> str:
    """Extract the output directory from report_outputs for the audit log."""
    for slug, output in report_outputs.items():
        if not isinstance(output, dict):
            continue
        pdf = output.get("pdf")
        if pdf:
            return str(Path(pdf).parent)
    return "unknown"


# ===========================================================================
# Public send function
# ===========================================================================

def send_report_email(
    group_config: dict,
    report_outputs: dict,
    trigger_mode: str = "scheduled",
) -> bool:
    """
    Build and send the report email for one delivery group.

    Parameters
    ----------
    group_config : dict
        Group entry from delivery_config.yaml.  Required keys::

            name
            email.recipients        (list[str])
            email.cc                (list[str], optional)
            email.subject           (str)
            email.reply_to          (str)
            filters.tag_category    (str, optional)
            filters.tag_value       (str, optional)
            reports                 (list[str])

    report_outputs : dict
        ``{report_slug: {pdf: Path, excel: Path, charts: [Path, ...]}}``
        as returned by each ``run_report()`` function.

    trigger_mode : str
        One of ``'scheduled'``, ``'manual'``, ``'daemon'``.  Written to the
        audit log.

    Returns
    -------
    bool
        ``True`` on successful delivery, ``False`` on any failure.
        Never raises.
    """
    start_time  = time.monotonic()
    group_name  = group_config.get("name", "Unknown Group")
    email_cfg   = group_config.get("email", {})
    filters     = group_config.get("filters") or {}
    reports_run = group_config.get("reports", list(report_outputs.keys()))

    tag_category = filters.get("tag_category")
    tag_value    = filters.get("tag_value")
    tag_filter   = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all_assets"
    )

    output_folder = _output_folder(report_outputs)

    logger.info(
        "=== Sending email for group '%s' (trigger=%s) ===",
        group_name, trigger_mode,
    )

    # ------------------------------------------------------------------
    # Validate recipients
    # ------------------------------------------------------------------
    raw_recipients = email_cfg.get("recipients") or []
    raw_cc         = email_cfg.get("cc") or []

    valid_recipients = _validate_addresses(raw_recipients)
    valid_cc         = _validate_addresses(raw_cc)
    all_to           = valid_recipients + valid_cc

    if not valid_recipients:
        msg = "No valid recipient addresses — aborting send."
        logger.error("[%s] %s", group_name, msg)
        log_delivery(
            group_name=group_name,
            trigger_mode=trigger_mode,
            reports_run=reports_run,
            tag_filter=tag_filter,
            recipients=[],
            status="failed",
            output_folder=output_folder,
            error_message=msg,
            duration_seconds=round(time.monotonic() - start_time, 2),
        )
        return False

    # ------------------------------------------------------------------
    # Collect attachments and enforce size limit
    # ------------------------------------------------------------------
    pdf_paths, excel_paths = _collect_attachments(report_outputs)
    chart_paths             = _collect_chart_pngs(report_outputs, max_charts=3)

    limit_bytes  = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024
    all_paths    = pdf_paths + excel_paths
    total_bytes  = _total_size_bytes(all_paths)
    excel_omitted = False

    if total_bytes > limit_bytes:
        logger.warning(
            "[%s] Attachment size %.1f MB exceeds limit of %d MB — dropping Excel files.",
            group_name, total_bytes / 1024 / 1024, MAX_ATTACHMENT_SIZE_MB,
        )
        excel_omitted = True
        excel_paths   = []
        all_paths     = pdf_paths
        total_bytes   = _total_size_bytes(all_paths)

    attachment_size_kb = total_bytes // 1024

    # ------------------------------------------------------------------
    # Build email body
    # ------------------------------------------------------------------
    # Some reports (management_summary) pre-build their own HTML body and
    # embed inline charts as base64 strings rather than file paths.
    # When a pre-built body is present it is used directly; the generic
    # Jinja2 template is bypassed for that report's content.
    # Pre-built inline charts are also attached as CID MIME parts here.
    # ------------------------------------------------------------------
    prebuilt_html:    str | None       = None
    prebuilt_charts:  dict[str, str]   = {}  # {cid_name: base64_str}

    for _slug, _output in report_outputs.items():
        if not isinstance(_output, dict):
            continue
        _m = _output.get("metrics") or {}
        if isinstance(_m, dict) and _m.get("email_html"):
            prebuilt_html   = _m["email_html"]
            prebuilt_charts = _m.get("inline_charts") or {}
            logger.debug(
                "[%s] Using pre-built email body from report '%s'.",
                group_name, _slug,
            )
            break  # first pre-built body wins; only one expected per group

    try:
        if prebuilt_html is not None:
            # Substitute the reply_to placeholder that build_email_body() would
            # normally fill via the Jinja2 template.
            reply_to_addr = (group_config.get("email") or {}).get("reply_to", "")
            html_body = prebuilt_html.replace("{reply_to}", reply_to_addr)
        else:
            html_body = build_email_body(
                group_config=group_config,
                report_outputs=report_outputs,
                excel_omitted=excel_omitted,
            )
    except Exception as exc:
        logger.error(
            "[%s] build_email_body() failed: %s\n%s",
            group_name, exc, traceback.format_exc(),
        )
        html_body = (
            f"<p><strong>{group_name}</strong> — Vulnerability Management Report</p>"
            f"<p>HTML body could not be rendered: {exc}</p>"
        )

    # ------------------------------------------------------------------
    # Assemble MIME message
    # ------------------------------------------------------------------
    cfg        = _smtp_cfg()
    from_addr  = cfg["from_address"]
    from_field = _format_address(cfg["from_name"], from_addr)
    subject    = email_cfg.get("subject", f"Vulnerability Report — {group_name}")
    reply_to   = email_cfg.get("reply_to", from_addr)

    msg = MIMEMultipart("mixed")
    msg["From"]     = from_field
    msg["To"]       = ", ".join(valid_recipients)
    if valid_cc:
        msg["Cc"]   = ", ".join(valid_cc)
    msg["Subject"]  = subject
    msg["Reply-To"] = reply_to

    # HTML body + inline charts go inside a related part
    related = MIMEMultipart("related")
    related.attach(MIMEText(html_body, "html", "utf-8"))

    # Attach pre-built base64 inline charts (e.g. from management_summary)
    import base64 as _base64
    for cid_name, b64_str in prebuilt_charts.items():
        try:
            img_data = _base64.b64decode(b64_str)
            img = MIMEImage(img_data, _subtype="png")
            img.add_header("Content-ID", f"<{cid_name}>")
            img.add_header("Content-Disposition", "inline", filename=f"{cid_name}.png")
            related.attach(img)
            logger.debug("[%s] Embedded pre-built inline chart: %s", group_name, cid_name)
        except Exception as exc:
            logger.warning(
                "[%s] Failed to embed pre-built chart '%s': %s",
                group_name, cid_name, exc,
            )

    # Attach file-based chart PNGs from standard reports
    for i, chart_path in enumerate(chart_paths, start=1):
        try:
            _attach_inline_chart(related, chart_path, i)
        except Exception as exc:
            logger.warning(
                "[%s] Failed to embed chart_%d (%s): %s",
                group_name, i, chart_path.name, exc,
            )

    msg.attach(related)

    # PDF attachments
    for pdf_path in pdf_paths:
        try:
            _attach_file(msg, pdf_path)
        except Exception as exc:
            logger.warning(
                "[%s] Failed to attach PDF %s: %s", group_name, pdf_path.name, exc
            )

    # Excel attachments (skipped if excel_omitted)
    for xlsx_path in excel_paths:
        try:
            _attach_file(msg, xlsx_path)
        except Exception as exc:
            logger.warning(
                "[%s] Failed to attach Excel %s: %s", group_name, xlsx_path.name, exc
            )

    # ------------------------------------------------------------------
    # Validate SMTP credentials before attempting send
    # ------------------------------------------------------------------
    if not cfg["username"] or not cfg["from_address"]:
        err_msg = (
            "SMTP_USERNAME or SMTP_FROM_ADDRESS not configured in .env. "
            "Cannot send email."
        )
        logger.error("[%s] %s", group_name, err_msg)
        log_delivery(
            group_name=group_name,
            trigger_mode=trigger_mode,
            reports_run=reports_run,
            tag_filter=tag_filter,
            recipients=valid_recipients,
            status="failed",
            output_folder=output_folder,
            error_message=err_msg,
            attachment_size_kb=attachment_size_kb,
            duration_seconds=round(time.monotonic() - start_time, 2),
        )
        return False

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------
    try:
        raw_bytes = msg.as_bytes()
        _smtp_send(cfg, from_addr, all_to, raw_bytes)
    except Exception as exc:
        err_msg = f"{type(exc).__name__}: {exc}"
        logger.error(
            "[%s] SMTP delivery failed after retries: %s\n%s",
            group_name, err_msg, traceback.format_exc(),
        )
        log_delivery(
            group_name=group_name,
            trigger_mode=trigger_mode,
            reports_run=reports_run,
            tag_filter=tag_filter,
            recipients=valid_recipients,
            status="failed",
            output_folder=output_folder,
            error_message=err_msg,
            attachment_size_kb=attachment_size_kb,
            duration_seconds=round(time.monotonic() - start_time, 2),
        )
        return False

    # ------------------------------------------------------------------
    # Success
    # ------------------------------------------------------------------
    duration = round(time.monotonic() - start_time, 2)
    status   = "partial" if excel_omitted else "success"

    logger.info(
        "[%s] Email delivered to %d recipient(s) in %.1fs (status=%s, %d KB).",
        group_name, len(all_to), duration, status, attachment_size_kb,
    )

    log_delivery(
        group_name=group_name,
        trigger_mode=trigger_mode,
        reports_run=reports_run,
        tag_filter=tag_filter,
        recipients=valid_recipients,
        status=status,
        output_folder=output_folder,
        error_message="Excel omitted: attachment size exceeded limit."
                      if excel_omitted else None,
        attachment_size_kb=attachment_size_kb,
        duration_seconds=duration,
    )
    return True
