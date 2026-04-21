"""
reports/board_summary.py — Board-Level Vulnerability Metrics Summary.

Computes four board-level security metrics using the module infrastructure
and assembles them into a PDF and Excel workbook.

Metrics (in PDF/Excel order):
    1. Scan Coverage SLA          — % of assets scanned on time (>= 95% target)
    2. Critical Remediation SLA   — % of critical vulns fixed within 15-day SLA
                                    during the last 30 days (>= 95% target)
    3. High-Risk Assets           — % of on-time assets with >= 10 Crit/High vulns
                                    open > 30 days (<= 0.5% target)
    4. Aged Vulnerability Assets  — % of on-time assets with >= 1 Med/High/Crit
                                    vuln open > 90 days (<= 2% target)

All four metrics share a single "on-time scanned" asset baseline (assets with
last_licensed_scan_date within the last 30 days, deduplicated by hostname) so
the denominator is consistent across the board report.

Usage
-----
Standalone:
    python reports/board_summary.py
    python reports/board_summary.py --tag-category "Environment" --tag-value "Production"
    python reports/board_summary.py --output-dir output/board_q1 --no-email

Via run_all.py (delivery group):
    Registered as slug "board_summary" in _VALID_REPORTS and _REPORT_MODULE_MAP.
    Called via run_report(tio, run_id, **kwargs) — standard report contract.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd
import openpyxl

# Ensure the project root is on sys.path when this script is run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import CACHE_DIR, OUTPUT_DIR
from data.fetchers import (
    fetch_all_assets,
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
)

# Importing reports.modules triggers registry.discover() (see __init__.py),
# which auto-imports every *_module.py file in reports/modules/ and executes
# each file's @register_module decorator — including all four board modules.
from reports.modules import ReportComposer
from reports.modules.base import ModuleConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Report-level constants
# ---------------------------------------------------------------------------

_BOARD_MODULE_CONFIGS: list[ModuleConfig] = [
    ModuleConfig("scan_coverage_sla"),
    ModuleConfig("critical_remediation_sla"),
    ModuleConfig("high_risk_assets"),
    ModuleConfig("aged_vulns_assets"),
]

_REPORT_TITLE   = "Board Vulnerability Metrics Summary"
_PDF_FILENAME   = "board_summary.pdf"
_EXCEL_FILENAME = "board_summary.xlsx"


# ===========================================================================
# Public API — called by run_all.py
# ===========================================================================

def run_report(
    tio,
    run_id: str,
    *,
    tag_category: Optional[str] = None,
    tag_value:    Optional[str] = None,
    output_dir:   Optional[Path] = None,
    generated_at: Optional[datetime] = None,
    cache_dir:    Optional[Path] = None,
) -> dict:
    """
    Generate the Board Vulnerability Metrics Summary.

    Fetches vulnerability and asset data (with parquet caching), optionally
    scopes to a Tenable tag filter, runs the four board metric modules via
    ReportComposer, and writes PDF and Excel outputs.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Cache key (typically YYYY-MM-DD) — used to name parquet cache files.
    tag_category : str, optional
        Tenable tag category to scope the report (e.g. ``"Environment"``).
    tag_value : str, optional
        Tag value paired with ``tag_category`` (e.g. ``"Production"``).
        Both must be non-empty to apply the filter; otherwise all assets
        are included.
    output_dir : Path, optional
        Directory to write report files into.  Created if missing.
        Defaults to ``OUTPUT_DIR / "board_summary"``.
    generated_at : datetime, optional
        UTC-aware report timestamp.  Defaults to UTC now.
    cache_dir : Path, optional
        Parquet cache directory.  Defaults to today's ``CACHE_DIR`` subfolder.

    Returns
    -------
    dict
        Standard report output dict:
        ``{"pdf": path_or_none, "excel": path_or_none, "charts": [],
           "metrics": {"kpis": dict, "errors": list, "module_results": dict}}``.
        Never raises — all exceptions are caught and reflected in the return
        dict and application log.
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if cache_dir is None:
        cache_dir = CACHE_DIR / datetime.now().strftime("%Y-%m-%d")
    if output_dir is None:
        output_dir = OUTPUT_DIR / "board_summary"

    output_dir = Path(output_dir)
    cache_dir  = Path(cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    _log_scope = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all assets"
    )
    logger.info(
        "board_summary: starting run (scope=%s, run_id=%s, output=%s)",
        _log_scope, run_id, output_dir,
    )

    # ------------------------------------------------------------------
    # Fetch data (parquet cache shared with other reports in the same run)
    # ------------------------------------------------------------------
    logger.info("board_summary: fetching open vulnerabilities …")
    vulns_df = fetch_all_vulnerabilities(tio, cache_dir)

    logger.info("board_summary: fetching assets …")
    assets_df = fetch_all_assets(tio, cache_dir)

    logger.info("board_summary: fetching fixed vulnerabilities (for Metric 2) …")
    fixed_vulns_df = fetch_fixed_vulnerabilities(tio, cache_dir)

    logger.info(
        "board_summary: data loaded — vulns=%d, assets=%d, fixed=%d",
        len(vulns_df), len(assets_df), len(fixed_vulns_df),
    )

    # ------------------------------------------------------------------
    # Apply tag filter (exact token match on the tags string column)
    # ------------------------------------------------------------------
    if tag_category and tag_value:
        filtered_assets = _filter_assets_by_tag(assets_df, tag_category, tag_value)
        scoped_uuids    = set(filtered_assets["asset_uuid"].dropna())

        logger.info(
            "board_summary: tag filter '%s=%s' — %d / %d assets in scope.",
            tag_category, tag_value, len(filtered_assets), len(assets_df),
        )

        assets_df = filtered_assets
        vulns_df  = (
            vulns_df[vulns_df["asset_uuid"].isin(scoped_uuids)]
            .copy()
            .reset_index(drop=True)
        )
        fixed_vulns_df = (
            fixed_vulns_df[fixed_vulns_df["asset_uuid"].isin(scoped_uuids)]
            .copy()
            .reset_index(drop=True)
        )

    # ------------------------------------------------------------------
    # Run all four board modules via ReportComposer
    #
    # fixed_vulns_df is forwarded via **kwargs to every module's compute().
    # Only CriticalRemediationSLAModule consumes it; the other three ignore
    # the kwarg silently (their compute() signature accepts **kwargs).
    # ------------------------------------------------------------------
    composer = ReportComposer(
        vulns_df       = vulns_df,
        assets_df      = assets_df,
        report_date    = generated_at,
        module_configs = _BOARD_MODULE_CONFIGS,
        fixed_vulns_df = fixed_vulns_df,
    )

    results = composer.run_all()
    errors  = composer.get_error_summary(results)
    kpis    = composer.collect_email_kpis(results)

    if errors:
        logger.warning(
            "board_summary: %d module error(s) — %s", len(errors), errors
        )

    # ------------------------------------------------------------------
    # Build PDF subtitle
    # ------------------------------------------------------------------
    scope_str = (
        f"Scope: {tag_category} = {tag_value}"
        if tag_category and tag_value
        else "Scope: All Assets"
    )
    subtitle = scope_str

    # ------------------------------------------------------------------
    # PDF — assembled by composer, rendered by WeasyPrint
    # ------------------------------------------------------------------
    pdf_path: Optional[Path] = None
    try:
        pdf_html = composer.assemble_pdf(
            results,
            title    = _REPORT_TITLE,
            subtitle = subtitle,
        )
        pdf_file = output_dir / _PDF_FILENAME
        _render_pdf(pdf_html, pdf_file)
        pdf_path = pdf_file
        logger.info("board_summary: PDF written → %s", pdf_file)
    except Exception as exc:
        logger.error(
            "board_summary: PDF generation failed: %s", exc, exc_info=True
        )

    # ------------------------------------------------------------------
    # Excel — assembled by composer, saved via openpyxl
    # ------------------------------------------------------------------
    excel_path: Optional[Path] = None
    try:
        wb = openpyxl.Workbook()
        # Remove the default blank sheet openpyxl creates on Workbook()
        if wb.worksheets:
            wb.remove(wb.worksheets[0])

        composer.assemble_excel(results, wb)

        excel_file = output_dir / _EXCEL_FILENAME
        wb.save(str(excel_file))
        excel_path = excel_file
        logger.info("board_summary: Excel written → %s", excel_file)
    except Exception as exc:
        logger.error(
            "board_summary: Excel generation failed: %s", exc, exc_info=True
        )

    return {
        "pdf":    pdf_path,
        "excel":  excel_path,
        "charts": [],
        "metrics": {
            "kpis":           kpis,
            "errors":         errors,
            "module_results": {r.module_id: r.metrics for r in results},
        },
    }


# ===========================================================================
# Private helpers
# ===========================================================================

def _filter_assets_by_tag(
    assets_df:    pd.DataFrame,
    tag_category: str,
    tag_value:    str,
    col:          str = "tags",
) -> pd.DataFrame:
    """
    Return rows whose ``tags`` column contains an exact token match for
    ``"tag_category=tag_value"``.

    Tags are stored as semicolon-delimited ``"Category=Value"`` strings, e.g.::

        "Application=Finance;Environment=Production;Owner=Network Defense"

    Each token is compared exactly after stripping whitespace, so
    ``"Application=Finance"`` will not match ``"Application=FinancePlus"``.

    Returns the full (unfiltered) DataFrame if ``col`` is absent, with a
    warning logged so callers can detect unexpected schema drift.

    Parameters
    ----------
    assets_df : pd.DataFrame
    tag_category : str
    tag_value : str
    col : str
        Name of the tags column (default: ``"tags"``).

    Returns
    -------
    pd.DataFrame
        Filtered copy, reset-indexed.
    """
    if col not in assets_df.columns:
        logger.warning(
            "_filter_assets_by_tag: column %r absent from assets_df — "
            "returning unfiltered DataFrame.",
            col,
        )
        return assets_df

    target = f"{tag_category}={tag_value}"

    def _has_tag(tags_str: object) -> bool:
        if not isinstance(tags_str, str) or not tags_str.strip():
            return False
        return any(token.strip() == target for token in tags_str.split(";"))

    mask = assets_df[col].apply(_has_tag)
    return assets_df[mask].copy().reset_index(drop=True)


def _render_pdf(html: str, output_path: Path) -> None:
    """
    Render an HTML string to a PDF file using WeasyPrint.

    Parameters
    ----------
    html : str
        Complete HTML document (as produced by ReportComposer.assemble_pdf).
    output_path : Path
        Destination file path (.pdf).

    Raises
    ------
    ImportError
        If WeasyPrint is not installed.
    Any WeasyPrint or OS error
        Propagated to the caller so it can be caught and logged.
    """
    try:
        from weasyprint import HTML  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "WeasyPrint is required for PDF generation. "
            "Install it with: pip install weasyprint"
        ) from exc

    HTML(string=html).write_pdf(str(output_path))


# ===========================================================================
# CLI entry point — for standalone / manual runs
# ===========================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Board Vulnerability Metrics Summary — "
            "generates a board-level PDF and Excel report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # All assets, default output directory
  python reports/board_summary.py

  # Scoped to Production environment
  python reports/board_summary.py --tag-category "Environment" --tag-value "Production"

  # Custom output directory, no email (reports-only)
  python reports/board_summary.py --output-dir output/board_q1 --no-email
        """,
    )
    parser.add_argument(
        "--tag-category", metavar="CATEGORY",
        help="Tenable tag category to scope report (e.g. 'Environment')",
    )
    parser.add_argument(
        "--tag-value", metavar="VALUE",
        help="Tag value paired with --tag-category (e.g. 'Production')",
    )
    parser.add_argument(
        "--output-dir", metavar="PATH",
        help=(
            "Directory to write PDF and Excel output "
            "(default: output/board_summary/)"
        ),
    )
    parser.add_argument(
        "--no-email", action="store_true",
        help=(
            "Generate reports without sending email.  Note: email delivery for "
            "board_summary is managed by run_all.py / scheduler.py, not by "
            "this script — this flag is informational for standalone runs."
        ),
    )
    parser.add_argument(
        "--run-id", metavar="ID",
        default=None,
        help="Parquet cache key (default: today's local date, YYYY-MM-DD)",
    )
    return parser


def main() -> int:
    """CLI entry point."""
    import os  # noqa: PLC0415

    from dotenv import load_dotenv  # noqa: PLC0415
    from config import LOG_DIR, LOG_LEVEL  # noqa: PLC0415

    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
        ],
    )

    load_dotenv()

    args   = _build_arg_parser().parse_args()
    run_id = args.run_id or datetime.now().strftime("%Y-%m-%d")
    output = Path(args.output_dir) if args.output_dir else None

    try:
        from tenable_client import get_client  # noqa: PLC0415
        tio = get_client()
    except SystemExit:
        raise  # tenable_client already logged and called sys.exit
    except Exception as exc:
        logger.error("Tenable connection failed: %s", exc, exc_info=True)
        return 1

    result = run_report(
        tio          = tio,
        run_id       = run_id,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
        output_dir   = output,
    )

    pdf   = result.get("pdf")
    excel = result.get("excel")
    errs  = result.get("metrics", {}).get("errors", [])

    print(f"PDF:   {pdf or '(not generated — see logs)'}")
    print(f"Excel: {excel or '(not generated — see logs)'}")

    if errs:
        print(f"Module errors ({len(errs)}):")
        for e in errs:
            print(f"  - {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
