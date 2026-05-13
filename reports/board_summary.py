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

from config import CACHE_DIR, HEADER_BG_COLOR, LOGO_PATH, OUTPUT_DIR
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
from reports.modules.pdf_chrome import PdfChromeConfig


# Phase 6 plan 06-03: scope subtitle helper.
# Originally we attempted `from run_all import _format_scope_subtitle` to keep
# a single source of truth (D-02). That triggers a circular import because
# run_all.py top-level imports (config, data.fetchers, etc.) drag the project
# into a partially-initialized state before reports/* can pull from it. The
# plan explicitly authorized inlining as the fallback — kept here verbatim
# to match run_all.py:_format_scope_subtitle (D-02 single behavior, two call
# sites). If/when run_all's top-level imports get slimmed, swap back to the
# import.
def _format_scope_subtitle(tc: str | None, tv: str | None) -> str:
    """Value-only scope subtitle per D-02. Returns ``tag_value`` when both
    category and value are non-empty, else ``"All assets"`` (sentence case)."""
    return tv if (tc and tv) else "All assets"

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
    analyst_detail: bool = True,
    privacy_label: str = "Confidential",
    scope_subtitle: Optional[str] = None,
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
    analyst_detail : bool, default True
        When True (default), the analyst-detail companion workbook is
        generated and returned in the bundle as ``analyst_workbook_path``,
        and exposed in this report's return dict as ``analyst_excel``.
        When False (Phase 4 CONFIG-03 / D-04-03 opt-out), the composer
        short-circuits the analyst workbook entirely — the file is not
        written to disk, ``analyst_workbook_path`` is ``None``, and the
        return dict's ``analyst_excel`` is ``None``. The bundle-driven
        attach in ``delivery/email_sender.py`` then silently skips the
        attachment.

    Returns
    -------
    dict
        Standard report output dict::

            {
                "pdf":             path_or_none,
                "excel":           path_or_none,
                "charts":          [],
                "metrics":         {"kpis": dict, "errors": list,
                                    "module_results": dict},
                # New in Phase 2 (COMPOSER-04, D-24):
                "analyst_excel":   Path | None,   # analyst-detail workbook
                "email_body_html": str,           # panels-only fragment
                # New in Phase 3 (D-04):
                "email_inline_images": list,      # CID gauge entries
                "email_kpis":      list,          # legacy KPI tiles (D-23)
            }

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
    # ------------------------------------------------------------------
    # Resolve subtitle (D-02 single source of truth): explicit
    # scope_subtitle kwarg wins; otherwise derive from tag filter via
    # _format_scope_subtitle. The same string feeds BOTH the cover-body
    # subtitle line AND PdfChromeConfig.subtitle (chrome header band).
    # ------------------------------------------------------------------
    resolved_subtitle = (
        scope_subtitle
        if scope_subtitle is not None
        else _format_scope_subtitle(tag_category, tag_value)
    )

    # scope_label is the analyst workbook _Metadata Scope row (D-19) —
    # UNCHANGED. RESEARCH.md "Files Touched" line 234-244 calls this out:
    # the analyst metadata row uses the "Category = Value" / "All Assets"
    # formatting and must not be conflated with the chrome subtitle.
    scope_label = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )

    # ------------------------------------------------------------------
    # Build PdfChromeConfig (CHROME-INT-02) — wired into ReportComposer
    # via the optional pdf_chrome= kwarg landed in plan 06-01.
    # ------------------------------------------------------------------
    pdf_chrome_cfg = PdfChromeConfig(
        title         = _REPORT_TITLE,
        subtitle      = resolved_subtitle,
        generated_at  = generated_at,
        header_bg     = HEADER_BG_COLOR,
        logo_path     = LOGO_PATH,
        privacy_label = privacy_label,
    )

    composer = ReportComposer(
        vulns_df       = vulns_df,
        assets_df      = assets_df,
        report_date    = generated_at,
        module_configs = _BOARD_MODULE_CONFIGS,
        fixed_vulns_df = fixed_vulns_df,
        pdf_chrome     = pdf_chrome_cfg,
    )

    results = composer.run_all()

    # ------------------------------------------------------------------
    # Drive all four render channels through the bundle orchestrator
    # (Phase 2 D-22, D-26, COMPOSER-04). assemble_pdf inserts the new
    # page-2 RAG strip internally (Plan 02-01); assemble_analyst_workbook
    # writes the analyst .xlsx to output_dir and returns its path or
    # None when no module produced rows (D-20).
    # ------------------------------------------------------------------
    bundle = composer.run_full_pipeline(
        results,
        output_dir,
        slug             = "board_summary",
        report_date      = generated_at,
        generate_analyst = analyst_detail,    # Phase 4 (CONFIG-03 / D-04-03): YAML-driven opt-out
        pdf_title        = _REPORT_TITLE,
        pdf_subtitle     = resolved_subtitle,
        scope_label      = scope_label,
    )

    errors = bundle["errors"]
    kpis   = bundle["email_kpis"]

    if errors:
        logger.warning(
            "board_summary: %d module error(s) — %s", len(errors), errors
        )

    # ------------------------------------------------------------------
    # PDF — bytes come from bundle["pdf_html"]; WeasyPrint render path
    # unchanged
    # ------------------------------------------------------------------
    pdf_path: Optional[Path] = None
    try:
        pdf_file = output_dir / _PDF_FILENAME
        _render_pdf(bundle["pdf_html"], pdf_file)
        pdf_path = pdf_file
        logger.info("board_summary: PDF written → %s", pdf_file)
    except Exception as exc:
        logger.error(
            "board_summary: PDF generation failed: %s", exc, exc_info=True
        )

    # ------------------------------------------------------------------
    # Excel — workbook comes from bundle["excel_workbook"]; openpyxl
    # save path unchanged
    # ------------------------------------------------------------------
    excel_path: Optional[Path] = None
    try:
        wb         = bundle["excel_workbook"]
        excel_file = output_dir / _EXCEL_FILENAME
        wb.save(str(excel_file))
        excel_path = excel_file
        logger.info("board_summary: Excel written → %s", excel_file)
    except Exception as exc:
        logger.error(
            "board_summary: Excel generation failed: %s", exc, exc_info=True
        )

    result_dict: dict = {
        "pdf":    pdf_path,
        "excel":  excel_path,
        "charts": [],
        "metrics": {
            "kpis":           kpis,
            "errors":         errors,
            "module_results": {r.module_id: r.metrics for r in results},
        },
        # NEW in Phase 2 (D-24, COMPOSER-04) — additive keys, do not
        # mutate any existing key shape:
        "analyst_excel":    bundle["analyst_workbook_path"],   # Path | None
        "email_body_html":  bundle["email_body_html"],         # str (panels fragment)
        # NEW in Phase 3 (D-04, Plan 03-01) — CID gauge entries for
        # email_sender.py to decode into MIMEImage parts:
        "email_inline_images": bundle.get("email_inline_images", []),
        # WR-01 fix — surface the legacy KPI dict at the bundle top level
        # so the email template's generic KPI-tile fallback path
        # (collect_email_kpis() → report_outputs[*]["email_kpis"]) can
        # find it. Phase 2 D-23 specified that the legacy KPI channel must
        # be preserved; without this key, board_summary's KPI tiles never
        # show up in any consumer that doesn't explicitly look at
        # metrics["kpis"].
        "email_kpis":       kpis,
    }
    # _bundle: private key for tests/baseline_utils + smoke_board_summary_cutover.py (Plan 04-04). NOT part of the public contract.
    # Carries the in-memory composer pipeline output (pdf_html string,
    # openpyxl Workbook, analyst_workbook_path, email_body_html,
    # email_inline_images, errors, module_results) so the smoke script
    # can compute the structural snapshot without re-invoking the
    # composer or parsing on-disk PDF/Excel back. Leading underscore
    # signals "internal/diagnostic only"; downstream consumers
    # (run_all.py, scheduler.py, delivery/email_sender.py) ignore
    # unknown keys per CLAUDE.md's bundle-driven D-22 routing pattern.
    result_dict["_bundle"] = bundle
    return result_dict


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

    WR-08 fix — when the tags column is absent from the assets DataFrame,
    return an EMPTY DataFrame rather than the full (unfiltered) frame.
    The previous behavior (returning the unfiltered frame with a warning)
    silently widened scope: a board scoped to ``Environment=Production``
    that hit a fixture with no tags column would render the entire fleet
    as if it were Production. This is incompatible with CLAUDE.md's
    fail-soft semantics, which is about not crashing the batch — NOT
    about silently mis-scoping a single report. The empty frame causes
    each module to render a coherent "no data in scope" panel
    (driver_narrative = "No data in scope.", RAG strip = "—", etc.) so
    consumers see the correct signal instead of a misleading total.

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
        Filtered copy, reset-indexed. Empty if ``col`` is absent.
    """
    if col not in assets_df.columns:
        logger.error(
            "_filter_assets_by_tag: tags column %r absent from assets_df — "
            "returning EMPTY DataFrame so the report renders 'no data in "
            "scope' rather than silently widening to all assets. (Tag scope "
            "requested: %s=%s)",
            col, tag_category, tag_value,
        )
        return assets_df.iloc[0:0].copy().reset_index(drop=True)

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
