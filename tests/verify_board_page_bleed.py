"""
tests/verify_board_page_bleed.py — REAL-render verification for board metric
PDF page bleed (debug session board-metric-pdf-page-bleed).

Renders each board module on ITS OWN single-section document WITH the same
PDF chrome (header/footer band) that board_summary applies in production, then
counts the resulting PDF pages. A module whose section fits on one page yields
a 2-page PDF (cover + 1). A bleeding module yields 3+. This is the REAL-render
gate required by the project preference: NO theoretical geometry.

Two passes:
  - nominal   : module's own explanation text.
  - worstcase : explanation padded with extra sentences to simulate the
                production worst case the user reported (>2 trailing lines
                bleeding onto a 2nd page). On the UNFIXED vertical-stack
                layout this bleeds; the two-column fix must keep it on
                one page.

Run: .venv/Scripts/python.exe tests/verify_board_page_bleed.py
"""
from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import weasyprint  # noqa: E402
from pypdf import PdfReader  # noqa: E402

from config import SLA_DAYS as _SLA  # noqa: E402
from reports.modules import registry  # noqa: E402
from reports.modules.base import ModuleConfig  # noqa: E402
from reports.modules.composer import ReportComposer  # noqa: E402
from reports.modules.pdf_chrome import PdfChromeConfig  # noqa: E402
from tests.fixtures.builders import build_assets_df, build_vulns_df  # noqa: E402

_BOARD_MODULES = [
    "scan_coverage_sla",
    "critical_remediation_sla",
    "aged_vulns_assets",
]

_SEVERITIES = ["critical", "high", "medium", "low"]
_VPR = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.0}
_APPS = ["Payments Platform", "Customer Portal", "Internal HR", "Data Lake", "Edge Gateway"]

# Padding appended just before the explanation's closing </p> to simulate the
# production worst case (a measurement explanation longer than ~2 lines past
# what nominal data produces).
_WORST_PAD = (
    " Additional remediation context follows for the worst-case render: "
    "long-standing exposure across business units compounds program risk, "
    "and trailing explanatory sentences like this one are exactly what "
    "previously bled onto a second page."
) * 2


def _make_data(as_of: datetime, seed: int = 7):
    rng = random.Random(seed)
    asset_rows, vuln_rows, fixed_rows = [], [], []
    n_assets = 40
    for i in range(n_assets):
        uuid = f"gen-{i:04d}"
        app = _APPS[i % len(_APPS)]
        asset_rows.append({
            "asset_uuid": uuid, "hostname": f"gen-host-{i}",
            "ipv4": f"10.1.{i // 256}.{i % 256}", "fqdn": f"gen-host-{i}.test",
            "operating_system": "Linux", "network_name": "Default",
            "last_seen": as_of, "last_licensed_scan_date": as_of - timedelta(days=i % 25),
            "tags": f"Application={app}", "tags_str": f"Application: {app}",
            "source_name": "NESSUS_SCAN",
        })
        for j in range(4):
            sev = rng.choice(_SEVERITIES)
            days_ago = rng.choice([5, 40, 120, 200])
            vuln_rows.append({
                "asset_uuid": uuid, "hostname": f"gen-host-{i}", "ipv4": "10.1.0.1",
                "plugin_id": 10000 + j, "plugin_name": f"Gen Plugin {j}",
                "plugin_family": "General", "vpr_score": _VPR[sev],
                "severity": sev, "severity_native": sev,
                "cve_list": "CVE-2024-9999", "cvss_base_score": 7.0,
                "exploit_available": False,
                "first_found": as_of - timedelta(days=days_ago),
                "last_found": as_of, "last_fixed": None, "state": "open",
                "finding_id": f"gen-{i}-{j}",
            })
        for k in range(2):
            in_sla = rng.random() < 0.6
            first = as_of - timedelta(days=(_SLA["critical"] - 5) if in_sla else (_SLA["critical"] + 40))
            fixed_rows.append({
                "asset_uuid": uuid, "hostname": f"gen-host-{i}", "ipv4": "10.1.0.1",
                "plugin_id": 20000 + k, "plugin_name": f"Fixed Plugin {k}",
                "plugin_family": "General", "vpr_score": 9.5,
                "severity": "critical", "severity_native": "critical",
                "cve_list": "CVE-2024-1111", "cvss_base_score": 9.0,
                "exploit_available": True,
                "first_found": first, "last_found": as_of - timedelta(days=2),
                "last_fixed": as_of - timedelta(days=rng.randint(1, 25)),
                "state": "fixed", "finding_id": f"fix-{i}-{k}",
            })
    return (
        build_vulns_df(vuln_rows),
        build_assets_df(asset_rows),
        build_vulns_df(fixed_rows),
    )


def _pad_explanation(section_html: str) -> str:
    """Inject worst-case padding into the last explanatory-text paragraph."""
    marker = "</p>"
    idx = section_html.rfind(marker)
    if idx == -1:
        return section_html
    return section_html[:idx] + _WORST_PAD + section_html[idx:]


def _render_pages(composer, data, mid, pad: bool) -> int:
    inst = registry.get(mid)()
    section = inst.render_pdf_section(data, ModuleConfig(mid))
    full = composer.assemble_pdf([data], title=f"Board — {mid}", subtitle="Scope: All Assets")
    if pad:
        full = full.replace(section, _pad_explanation(section), 1)
    doc = weasyprint.HTML(string=full).render()
    return len(doc.pages)


def main() -> int:
    as_of = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
    vulns_df, assets_df, fixed_df = _make_data(as_of)

    any_bleed = False
    for mid in _BOARD_MODULES:
        chrome = PdfChromeConfig(
            title="Board Summary (page-bleed verification)",
            subtitle="Scope: All Assets",
            generated_at=as_of,
        )
        composer = ReportComposer(
            vulns_df=vulns_df,
            assets_df=assets_df,
            report_date=as_of,
            module_configs=[ModuleConfig(mid)],
            fixed_vulns_df=fixed_df,
            pdf_chrome=chrome,
        )
        data = composer.run_all()[0]
        nominal = _render_pages(composer, data, mid, pad=False)
        worst = _render_pages(composer, data, mid, pad=True)
        bleed = nominal > 2 or worst > 2
        any_bleed = any_bleed or bleed
        flag = "BLEED" if bleed else "ok"
        print(f"  {mid:28s} nominal={nominal}  worstcase={worst}  error={data.error!r:6} -> {flag}")

    print("")
    if any_bleed:
        print("RESULT: FAIL — at least one module section bleeds to a 2nd page.")
        return 1
    print("RESULT: PASS — every module section fits on one page (cover + 1), "
          "nominal AND worst-case explanation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
