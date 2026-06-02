"""
tests/render_board_review_pdf.py — REVIEW render for the board-metric two-column
PDF layout (debug session board-metric-pdf-page-bleed).

Unlike verify_board_page_bleed.py (which counts pages per module for a pass/fail
gate), this writes actual PDF files to output/ so a human can open them and
visually confirm the two-column layout: metric graphic + numbers on the LEFT,
measurement explanation (left-aligned) on the RIGHT, Top-5 BU table full width
below — with no page bleed.

Produces two files, both with the production PDF chrome:
  - board_review_nominal.pdf    : all board modules, their own explanation text.
  - board_review_worstcase.pdf  : explanations padded to the reported worst case.

Run: .venv/Scripts/python.exe tests/render_board_review_pdf.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import weasyprint  # noqa: E402
from pypdf import PdfReader  # noqa: E402

from reports.modules.base import ModuleConfig  # noqa: E402
from reports.modules.composer import ReportComposer  # noqa: E402
from reports.modules.pdf_chrome import PdfChromeConfig  # noqa: E402

from tests.verify_board_page_bleed import (  # noqa: E402
    _BOARD_MODULES,
    _make_data,
    _pad_explanation,
)


def _render(out_path: Path, pad: bool) -> int:
    from datetime import datetime, timezone

    as_of = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
    vulns_df, assets_df, fixed_df = _make_data(as_of)

    module_configs = [ModuleConfig(mid) for mid in _BOARD_MODULES]
    chrome = PdfChromeConfig(
        title="Board Summary (layout review)",
        subtitle="Scope: All Assets",
        generated_at=as_of,
    )
    composer = ReportComposer(
        vulns_df=vulns_df,
        assets_df=assets_df,
        report_date=as_of,
        module_configs=module_configs,
        fixed_vulns_df=fixed_df,
        pdf_chrome=chrome,
    )
    data_list = composer.run_all()
    full = composer.assemble_pdf(
        data_list, title="Board Summary (layout review)", subtitle="Scope: All Assets"
    )

    if pad:
        # Pad each module's measurement explanation to the reported worst case.
        for inst_data, mid in zip(data_list, _BOARD_MODULES):
            from reports.modules import registry

            section = registry.get(mid)().render_pdf_section(inst_data, ModuleConfig(mid))
            full = full.replace(section, _pad_explanation(section), 1)

    weasyprint.HTML(string=full).write_pdf(str(out_path))
    return len(PdfReader(str(out_path)).pages)


def main() -> int:
    out_dir = Path(__file__).resolve().parent.parent / "output"
    out_dir.mkdir(exist_ok=True)

    for label, pad in (("nominal", False), ("worstcase", True)):
        out_path = out_dir / f"board_review_{label}.pdf"
        pages = _render(out_path, pad)
        print(f"  {label:10s} -> {out_path}  ({pages} pages)")

    print("\nOpen the two PDFs to review the two-column layout and confirm no page bleed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
