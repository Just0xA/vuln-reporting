"""
scripts/smoke_email_phase2.py — Phase 2 email smoke test.

Sends one rendered Phase 2 email to a recipient of your choice using
synthetic ModuleData (no Tenable creds needed). Exercises the new
panels-only path:

    ReportComposer.assemble_email_body()  →  panels-only HTML fragment
    delivery.email_template.build_email_body_modular()  →  full HTML body

A synthetic 2-page PDF (cover + page-2 RAG strip + module sections)
is rendered and attached so the email has a realistic payload.

Usage from the project root::

    .venv\\Scripts\\python.exe scripts\\smoke_email_phase2.py recipient@example.com

Required env vars (override your normal corp SMTP for the smoke run)::

    SMTP_HOST            smtp.gmail.com
    SMTP_PORT            587
    SMTP_USERNAME        your.account@gmail.com
    SMTP_PASSWORD        16-char Google App Password
    SMTP_FROM_ADDRESS    your.account@gmail.com
    SMTP_FROM_NAME       Phase 2 Smoke

Gmail App Password setup (one-time):
    1. Enable 2-Step Verification on the Google account
       (https://myaccount.google.com/security)
    2. Visit https://myaccount.google.com/apppasswords
    3. Generate an App Password for "Mail" / "Windows Computer"
    4. Paste the 16-char value (spaces stripped) into SMTP_PASSWORD
"""

from __future__ import annotations

import argparse
import logging
import os
import smtplib
import ssl
import sys
import tempfile
from datetime import datetime, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Allow `from reports... import ...` when invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phase2_smoke")


_STUB_PANEL_TEMPLATE = (
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
    'width="100%" style="margin:0 0 18px 0;border:1px solid #c5cfe8;'
    'border-radius:6px;padding:14px 16px;font-family:Arial,Helvetica,sans-serif;">'
    '<tr><td style="font-size:13px;color:#555;line-height:1.4;">'
    '<div style="font-weight:bold;color:#1F3864;font-size:14px;'
    'margin:0 0 6px 0;">{label}</div>'
    '<div style="font-size:22px;font-weight:bold;color:#1a1a1a;'
    'margin:0 0 6px 0;">{headline}</div>'
    '<div style="display:inline-block;padding:4px 10px;border-radius:3px;'
    'background:{rag_color};color:#ffffff;font-size:11px;font-weight:bold;">'
    '{rag_label}</div>'
    '<div style="margin:8px 0 0 0;color:#444;font-size:12px;">'
    '<em>{driver}</em></div>'
    '</td></tr></table>'
)

_STUB_PANEL_DATA = [
    ("Scan Coverage SLA",                   "97.3%",  "#388e3c", "On Target",
     "Production assets at 99.1%; lab tier dragging average down."),
    ("Critical Vulnerability Remediation SLA", "92.4%", "#f57c00", "At Risk",
     "Three Windows servers missed 15-day window — patch backlog from last cycle."),
    ("High-Risk Assets",                    "0.4%",   "#388e3c", "On Target",
     "Two assets ≥ 10 Crit/High open > 30 days; both scheduled for retirement."),
    ("Aged Vulnerability Assets",           "2.7%",   "#d32f2f", "Off Target",
     "Aged Med+ population growing — recommend a clean-up sprint this month."),
]


def _stub_panels_html() -> str:
    """Stand-in panels for Phase 2 smoke — Phase 3 modules will replace this."""
    return "\n".join(
        _STUB_PANEL_TEMPLATE.format(
            label    = label,
            headline = headline,
            rag_color = rag_color,
            rag_label = rag_label,
            driver    = driver,
        )
        for label, headline, rag_color, rag_label, driver in _STUB_PANEL_DATA
    )


def _build_synthetic_outputs(*, stub_panels: bool) -> tuple[str, Path]:
    """Render the panels-only email fragment + a synthetic PDF on disk."""
    # Re-use the regression test fixtures so the email reflects the
    # exact ModuleData shape the production composer consumes.
    from test_phase2_composer_pipeline import _make_composer, _make_results  # noqa: PLC0415

    module_ids = (
        "scan_coverage_sla",
        "critical_remediation_sla",
        "high_risk_assets",
        "aged_vulns_assets",
    )
    composer = _make_composer(*module_ids)
    results  = _make_results(*module_ids)

    panels_html = composer.assemble_email_body(results)
    if not panels_html.strip() and stub_panels:
        # Phase 1 modules don't override render_email_panel() yet; inject
        # a stub so the panels-on email path renders end-to-end.
        panels_html = _stub_panels_html()

    pdf_html = composer.assemble_pdf(
        results,
        page_css="",
        title="Phase 2 Smoke",
        subtitle="Email body smoke test",
    )
    import weasyprint  # noqa: PLC0415
    pdf_path = Path(tempfile.gettempdir()) / "phase2_smoke.pdf"
    weasyprint.HTML(string=pdf_html).write_pdf(pdf_path)

    return panels_html, pdf_path


def _build_html_body(panels_html: str, pdf_path: Path, recipient: str) -> str:
    """Wrap the panels fragment in the full Jinja2 email template."""
    from delivery.email_template import build_email_body_modular  # noqa: PLC0415

    group_config = {
        "name":   "Phase 2 Smoke Group",
        "filters": {},  # All Assets banner
        "reports": ["board_summary"],
        "email": {
            "subject":  "Phase 2 Smoke — RAG-strip cover + per-module panels",
            "reply_to": os.getenv("SMTP_FROM_ADDRESS", ""),
            "recipients": [recipient],
        },
    }

    report_outputs = {
        "board_summary": {
            "pdf":     pdf_path,
            "excel":   None,   # smoke skips Excel
            "charts":  [],
            "metrics": {},
        },
    }

    return build_email_body_modular(
        group_config       = group_config,
        report_outputs     = report_outputs,
        module_panels_html = panels_html,
        excel_omitted      = True,    # surface the Excel-omitted banner
        generated_at       = datetime.now(tz=timezone.utc),
    )


def _attach_pdf(msg: MIMEMultipart, pdf_path: Path) -> None:
    with open(pdf_path, "rb") as fp:
        part = MIMEBase("application", "pdf")
        part.set_payload(fp.read())
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f'attachment; filename="{pdf_path.name}"',
    )
    msg.attach(part)


def _smtp_send(html_body: str, pdf_path: Path, recipient: str) -> None:
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USERNAME")
    pwd  = os.getenv("SMTP_PASSWORD")
    from_addr = os.getenv("SMTP_FROM_ADDRESS")
    from_name = os.getenv("SMTP_FROM_NAME", "Phase 2 Smoke")
    use_ssl   = os.getenv("SMTP_USE_SSL", "false").lower() == "true"

    missing = [
        name for name, val in {
            "SMTP_HOST": host, "SMTP_USERNAME": user,
            "SMTP_PASSWORD": pwd, "SMTP_FROM_ADDRESS": from_addr,
        }.items() if not val
    ]
    if missing:
        raise SystemExit(
            f"Missing required env var(s): {', '.join(missing)}. "
            "Either export them in this shell or add them to .env."
        )

    msg = MIMEMultipart("mixed")
    msg["From"]    = f"{from_name} <{from_addr}>"
    msg["To"]      = recipient
    msg["Subject"] = "Phase 2 Smoke — RAG-strip cover + per-module panels"
    msg["Reply-To"] = from_addr
    msg.attach(MIMEText(html_body, "html"))
    _attach_pdf(msg, pdf_path)

    logger.info("Connecting to %s:%d (use_ssl=%s)", host, port, use_ssl)
    if use_ssl:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as smtp:
            smtp.login(user, pwd)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(user, pwd)
            smtp.send_message(msg)
    logger.info("Sent Phase 2 smoke email to %s", recipient)


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 2 email smoke test.")
    parser.add_argument(
        "recipient",
        help="Destination email address (e.g. yourname@gmail.com).",
    )
    parser.add_argument(
        "--save-html",
        metavar="PATH",
        help="Also write the rendered HTML body to PATH for browser inspection.",
    )
    parser.add_argument(
        "--no-stub-panels",
        action="store_true",
        help="Skip the synthetic Phase 3-style panels and let the legacy "
             "KPI-tile fallback render (use to confirm the {%% else %%} path).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render everything but skip the SMTP send.",
    )
    args = parser.parse_args()

    panels_html, pdf_path = _build_synthetic_outputs(
        stub_panels=not args.no_stub_panels,
    )
    logger.info("Rendered panels-only fragment (%d chars)", len(panels_html))
    logger.info("Rendered synthetic PDF at %s", pdf_path)

    html_body = _build_html_body(panels_html, pdf_path, args.recipient)
    logger.info("Rendered full email body (%d chars)", len(html_body))

    if args.save_html:
        Path(args.save_html).write_text(html_body, encoding="utf-8")
        logger.info("Wrote HTML preview to %s", args.save_html)

    if args.dry_run:
        logger.info("--dry-run set; skipping SMTP send.")
        return 0

    _smtp_send(html_body, pdf_path, args.recipient)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
