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
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Allow `from reports... import ...` when invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from dotenv import load_dotenv  # noqa: E402

# Phase 3 D-01 + Plan 03-06 — drive real render_email_panel output
# from the four migrated board modules instead of stub HTML, so the
# smoke script verifies actual Phase 3 panel rendering off-network.
from reports.modules.scan_coverage_sla_module       import ScanCoverageSLAModule  # noqa: E402
from reports.modules.critical_remediation_sla_module import CriticalRemediationSLAModule  # noqa: E402
from reports.modules.high_risk_assets_module        import HighRiskAssetsModule  # noqa: E402
from reports.modules.aged_vulns_assets_module       import AgedVulnsAssetsModule  # noqa: E402
from reports.modules.base                           import ModuleData, ModuleConfig  # noqa: E402
from reports.modules.rag_utils                      import build_rag_strip_entry  # noqa: E402
# W7 — None/NaN-safe formatter (CLAUDE.md Empty-data guard pattern rule 1).
# Even though `pct` is a known float in this fixture, smoke-script code is
# what new contributors copy when wiring a new module; modeling the wrong
# pattern (an inline percent-precision f-string spec) would propagate the
# bug.
from reports.modules.format_utils                   import safe_pct  # noqa: E402

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


def _build_smoke_module_data(
    cls,
    metric_key: str,
    pct:        float,
    status:     str,
) -> ModuleData:
    """Build a populated ModuleData fixture for smoke rendering.

    Phase 3 D-04 requires ``metadata['email_gauge_b64']`` to be a
    non-empty base64 PNG so each module's ``render_email_panel`` emits
    a populated panel that references ``cid:{module_id}_gauge``.

    W7 — headline_value_str uses ``safe_pct(pct)`` (CLAUDE.md
    Empty-data guard pattern rule 1).
    """
    instance = cls()
    return ModuleData(
        module_id        = instance.MODULE_ID,
        display_name     = instance.DISPLAY_NAME,
        metrics          = {metric_key: pct, "status": status},
        table_data       = [],
        chart_data       = {},
        summary_text     = "",
        # 1×1 transparent PNG — minimal valid base64 PNG payload.
        metadata         = {
            "email_gauge_b64": (
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lE"
                "QVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII="
            ),
        },
        error            = None,
        driver_narrative = f"Phase 3 smoke driver for {instance.MODULE_ID}.",
        analyst_rows     = [],
        rag_strip        = build_rag_strip_entry(
            display_name       = instance.DISPLAY_NAME,
            # W7 — safe_pct(pct), NEVER an inline percent-precision
            # spec. See CLAUDE.md Empty-data guard pattern rule 1.
            headline_value_str = safe_pct(pct),
            status             = status,
        ),
    )


def _build_synthetic_outputs(*, stub_panels: bool) -> tuple[str, Path]:
    """Render the panels-only email fragment + a synthetic PDF on disk.

    Phase 3 D-01 + Plan 03-06: drives the four migrated board modules
    through their real ``render_email_panel`` paths instead of injecting
    stub HTML, so the smoke script proves the production panel-rendering
    code path off-network.
    """
    # Re-use the regression test composer factory so the smoke composer
    # mirrors the production composer constructor shape.
    from test_phase2_composer_pipeline import _make_composer  # noqa: PLC0415

    module_ids = (
        "scan_coverage_sla",
        "critical_remediation_sla",
        "high_risk_assets",
        "aged_vulns_assets",
    )
    composer = _make_composer(*module_ids)

    # Phase 3 D-04 / Plan 03-06 — drive real render_email_panel output
    # from populated ModuleData fixtures (replaces stub-panel injection
    # per CONTEXT risks line 208).
    smoke_results = [
        _build_smoke_module_data(ScanCoverageSLAModule,        "scan_coverage_pct",   97.3, "green"),
        _build_smoke_module_data(CriticalRemediationSLAModule, "remediation_sla_pct", 92.4, "yellow"),
        _build_smoke_module_data(HighRiskAssetsModule,         "high_risk_pct",       0.4,  "green"),
        _build_smoke_module_data(AgedVulnsAssetsModule,        "aged_assets_pct",     2.7,  "yellow"),
    ]

    # Drive the composer's email body assembly with real panels.
    panels_html         = composer.assemble_email_body(smoke_results)
    email_inline_images = composer.collect_email_inline_images(smoke_results)
    logger.info(
        "Collected %d real CID inline-gauge entries from migrated modules",
        len(email_inline_images),
    )

    if not panels_html.strip() and stub_panels:
        # Defensive fallback only — should not trigger now that the four
        # migrated modules implement render_email_panel.
        logger.warning(
            "Real-render panels_html was empty; falling back to stub panels"
        )
        panels_html = _stub_panels_html()

    # Phase 3 D-01: assemble_pdf now emits a unified RAG-strip cover on page 1.
    # The smoke script renders this PDF for visual confirmation of the
    # unified cover composition.
    pdf_html = composer.assemble_pdf(
        smoke_results,
        page_css="",
        title="Phase 2 Smoke",
        subtitle="Email body smoke test",
    )
    import weasyprint  # noqa: PLC0415
    pdf_path = Path(tempfile.gettempdir()) / "phase2_smoke.pdf"
    weasyprint.HTML(string=pdf_html).write_pdf(pdf_path)

    return panels_html, pdf_path, email_inline_images


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


def _smtp_send(
    html_body: str,
    pdf_path: Path,
    recipient: str,
    email_inline_images: list[dict] | None = None,
) -> None:
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

    # CR-G4: attach the inline CID gauge images so <img src="cid:..."> refs
    # in the panel HTML resolve in the recipient's email client.
    # Mirrors delivery/email_sender.py's email_inline_images attach pattern.
    import base64  # noqa: PLC0415
    for entry in (email_inline_images or []):
        cid = entry.get("cid", "")
        b64_png = entry.get("b64_png", "")
        if not cid or not b64_png:
            continue
        img_data = base64.b64decode(b64_png)
        img_part = MIMEImage(img_data, _subtype="png")
        img_part.add_header("Content-ID", f"<{cid}>")
        img_part.add_header("Content-Disposition", "inline")
        msg.attach(img_part)

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
        help="Disables the empty-panels stub fallback only — the real "
             "render_email_panel() output is always attempted first. "
             "Has no effect on the legacy KPI-tile path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render everything but skip the SMTP send.",
    )
    args = parser.parse_args()

    panels_html, pdf_path, email_inline_images = _build_synthetic_outputs(
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

    _smtp_send(html_body, pdf_path, args.recipient, email_inline_images)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
