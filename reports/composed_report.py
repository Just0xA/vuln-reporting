"""
reports/composed_report.py — YAML-driven composed vulnerability report.

A generic report slug that builds its module list from the recipient
group's ``modules:`` YAML key rather than a hardcoded list. Lets
operators compose any combination of registered metric modules into a
single PDF / Excel / email / analyst bundle without authoring a new
per-report Python file.

Wiring is bundle-driven — the standard four-channel render contract
(see CLAUDE.md "Modular reports — bundle-driven routing") routes the
return dict through ``delivery/email_sender.py`` without any sender
changes. ``board_summary`` and ``management_summary`` are unaffected.

Usage
-----
Via run_all.py (delivery group):

    reports: [composed_report]
    modules:
      - scan_coverage_sla
      - critical_remediation_sla

Standalone:
    python reports/composed_report.py --modules scan_coverage_sla,critical_remediation_sla
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

# Ensure the project root is on sys.path when this script is run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import CACHE_DIR, HEADER_BG_COLOR, LOGO_PATH, OUTPUT_DIR
from data.fetchers import (
    fetch_all_assets,
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
)

# Importing reports.modules triggers registry.discover().
from reports.modules import ReportComposer, registry
from reports.modules.base import ModuleConfig
from reports.modules.pdf_chrome import PdfChromeConfig


def _format_scope_subtitle(
    tag_category: Optional[str], tag_value: Optional[str]
) -> str:
    """Value-only scope formatter (Phase 6 D-02). Duplicated from
    run_all.py to avoid the circular import board_summary already hit
    (run_all imports composed_report via importlib)."""
    return tag_value if (tag_category and tag_value) else "All assets"

logger = logging.getLogger(__name__)

_DEFAULT_REPORT_TITLE = "Composed Vulnerability Report"
_PDF_FILENAME         = "composed_report.pdf"
_EXCEL_FILENAME       = "composed_report.xlsx"

# Modules that need the fixed-vulnerabilities export forwarded via **kwargs.
# CriticalRemediationSLAModule is the only consumer today; conditionally
# fetching avoids an unnecessary export job when this module is not in the
# composition.
_MODULES_NEEDING_FIXED_VULNS = frozenset({"critical_remediation_sla"})

# Modules that need the environment-wide open-finding total (pre-tag-filter)
# forwarded via **kwargs.  TagSeverityShareModule is the only consumer today;
# the total is computed from the unfiltered vulns_df before the tag filter
# narrows it, mirroring the fixed_vulns_df gating pattern.
_MODULES_NEEDING_ENV_TOTAL = frozenset({"tag_severity_share"})

# Modules that need pre-read trend snapshots forwarded via **kwargs.
# trend_snapshots = read_trend() result dict {"snapshots": [...], "insufficient_data": bool}.
# Phase 14 seeds with the SC#4 stub only; Phase 15 registers all three
# trend-dependent module IDs here (D-17) so plans 15-05 and 15-06 need
# not touch this file.
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "sc4_kwargs_stub",
    "new_vs_remediated",   # D-17 (15-04)
    "vuln_density",        # D-17 (15-05)
    "accepted_recast",     # D-17 (15-06 — for MoM delta)
})

# Modules that need the recast-rules DataFrame forwarded via **kwargs.
# recast_rules_df = fetch_recast_rules() result DataFrame.
# Phase 14 seeds with the SC#4 stub only (D-17); Phase 15 adds accepted_recast.
_MODULES_NEEDING_RECAST_RULES = frozenset({
    "sc4_kwargs_stub",
    "accepted_recast",     # D-17 (15-06)
})


# ===========================================================================
# Public API — called by run_all.py
# ===========================================================================

def run_report(
    tio,
    run_id: str,
    *,
    tag_category:   Optional[str] = None,
    tag_value:      Optional[str] = None,
    output_dir:     Optional[Path] = None,
    generated_at:   Optional[datetime] = None,
    cache_dir:      Optional[Path] = None,
    modules:        Optional[list[str]] = None,
    module_options: Optional[dict[str, dict]] = None,
    analyst_detail: bool = True,
    report_title:   Optional[str] = None,
    privacy_label:  str = "Confidential",
    scope_subtitle: Optional[str] = None,
) -> dict:
    """
    Generate a YAML-composed vulnerability report.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Cache key (typically YYYY-MM-DD).
    tag_category, tag_value : str, optional
        Optional Tenable tag scope; both required to apply the filter.
    output_dir : Path, optional
        Output directory. Defaults to ``OUTPUT_DIR / "composed_report"``.
    generated_at : datetime, optional
        UTC-aware report timestamp. Defaults to UTC now.
    cache_dir : Path, optional
        Parquet cache directory. Defaults to today's CACHE_DIR subfolder.
    modules : list[str]
        Ordered list of registered module IDs to compose. Required and
        non-empty — raises ValueError when missing or empty.
    module_options : dict[str, dict], optional
        Per-module option dicts, keyed by module ID. Permissive
        pass-through to each module's ``ModuleConfig.options``.
    analyst_detail : bool, default True
        Opt-out for the analyst-detail companion workbook (mirrors
        ``board_summary``).
    report_title : str, optional
        Cover-page title override. Defaults to "Composed Vulnerability
        Report" when None.

    Returns
    -------
    dict
        Standard board-shaped output dict (see board_summary.run_report
        for the exact key list).
    """
    # ------------------------------------------------------------------
    # Defense-in-depth — dry-run catches these via registry validation,
    # but --group execution skips dry-run.
    # ------------------------------------------------------------------
    if not modules:
        raise ValueError(
            "composed_report: 'modules' must be a non-empty list. "
            "Add a `modules:` key with at least one registered module ID "
            "to the delivery group config."
        )

    _, invalid = registry.validate_module_list(list(modules))
    if invalid:
        registered = sorted(registry._modules.keys())  # noqa: SLF001
        raise ValueError(
            f"composed_report: unknown module ID(s) {invalid}. "
            f"Registered: {registered}"
        )

    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if cache_dir is None:
        cache_dir = CACHE_DIR / datetime.now().strftime("%Y-%m-%d")
    if output_dir is None:
        output_dir = OUTPUT_DIR / "composed_report"

    output_dir = Path(output_dir)
    cache_dir  = Path(cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    _log_scope = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all assets"
    )
    logger.info(
        "composed_report: starting run (scope=%s, run_id=%s, modules=%s, output=%s)",
        _log_scope, run_id, list(modules), output_dir,
    )

    # ------------------------------------------------------------------
    # Fetch data
    # ------------------------------------------------------------------
    logger.info("composed_report: fetching open vulnerabilities …")
    vulns_df = fetch_all_vulnerabilities(tio, cache_dir)

    logger.info("composed_report: fetching assets …")
    assets_df = fetch_all_assets(tio, cache_dir)

    need_fixed = bool(_MODULES_NEEDING_FIXED_VULNS.intersection(modules))
    fixed_vulns_df: Optional[pd.DataFrame] = None
    if need_fixed:
        logger.info(
            "composed_report: fetching fixed vulnerabilities "
            "(critical_remediation_sla in modules) …"
        )
        fixed_vulns_df = fetch_fixed_vulnerabilities(tio, cache_dir)

    need_trend = bool(_MODULES_NEEDING_TREND_SNAPSHOTS.intersection(modules))
    trend_snapshots: Optional[dict] = None
    if need_trend:
        # Fail-soft (WR-02): a trend read failure (corrupt cache, parse error)
        # must degrade to "kwarg absent" — the consuming module then fail-softs
        # on the missing kwarg via _empty_result — rather than propagate out of
        # run_report() and sink the whole group's bundle.
        try:
            from data.trend_store import read_trend, _sanitise_tag_for_filename  # noqa: PLC0415
            _trend_tag_filter = _sanitise_tag_for_filename(tag_category, tag_value)
            logger.info(
                "composed_report: reading trend snapshots (scope=%s) …",
                _trend_tag_filter,
            )
            trend_snapshots = read_trend(
                dimension  = "severity",
                tag_filter = _trend_tag_filter,
                months     = 13,
            )
        except Exception as exc:
            logger.error(
                "composed_report: trend snapshot read failed: %s", exc, exc_info=True
            )
            trend_snapshots = None

    need_recast = bool(_MODULES_NEEDING_RECAST_RULES.intersection(modules))
    recast_rules_df: Optional[pd.DataFrame] = None
    if need_recast:
        # Fail-soft (WR-02): a recast fetch failure (transient API/network error
        # after tenacity exhausts, parquet write error) degrades to "kwarg
        # absent" rather than aborting the batch.
        try:
            from data.fetchers import fetch_recast_rules  # noqa: PLC0415
            logger.info("composed_report: fetching recast rules …")
            recast_rules_df = fetch_recast_rules(tio, cache_dir)
        except Exception as exc:
            logger.error(
                "composed_report: recast rules fetch failed: %s", exc, exc_info=True
            )
            recast_rules_df = None

    logger.info(
        "composed_report: data loaded — vulns=%d, assets=%d, fixed=%s",
        len(vulns_df),
        len(assets_df),
        len(fixed_vulns_df) if fixed_vulns_df is not None else "n/a",
    )

    # ------------------------------------------------------------------
    # Compute environment grand total (pre-tag-filter) for tag_severity_share.
    # Must be computed from the UNFILTERED vulns_df before the tag filter
    # narrows the DataFrame, mirroring the fixed_vulns_df gating pattern.
    # ------------------------------------------------------------------
    if "state" in vulns_df.columns:
        _open_mask    = vulns_df["state"].str.lower().isin({"open", "reopened"})
        env_vuln_total = int(_open_mask.sum())
    else:
        env_vuln_total = 0

    # ------------------------------------------------------------------
    # Apply tag filter (verbatim from board_summary._filter_assets_by_tag)
    # ------------------------------------------------------------------
    if tag_category and tag_value:
        filtered_assets = _filter_assets_by_tag(assets_df, tag_category, tag_value)
        scoped_uuids    = set(filtered_assets["asset_uuid"].dropna())

        logger.info(
            "composed_report: tag filter '%s=%s' — %d / %d assets in scope.",
            tag_category, tag_value, len(filtered_assets), len(assets_df),
        )

        assets_df = filtered_assets
        vulns_df  = (
            vulns_df[vulns_df["asset_uuid"].isin(scoped_uuids)]
            .copy()
            .reset_index(drop=True)
        )
        if fixed_vulns_df is not None:
            fixed_vulns_df = (
                fixed_vulns_df[fixed_vulns_df["asset_uuid"].isin(scoped_uuids)]
                .copy()
                .reset_index(drop=True)
            )

    # ------------------------------------------------------------------
    # Build ModuleConfigs from YAML
    # ------------------------------------------------------------------
    opts_map: dict[str, dict] = module_options or {}
    module_configs: list[ModuleConfig] = [
        ModuleConfig(module_id=mid, options=dict(opts_map.get(mid, {}) or {}))
        for mid in modules
    ]

    # Warn about stray module_options keys not referenced in modules
    # (Q4: permissive pass-through — logger.warning only, not an error).
    stray_keys = set(opts_map.keys()) - set(modules)
    for k in sorted(stray_keys):
        logger.warning(
            "composed_report: module_options key '%s' is not in modules "
            "list — ignored.", k,
        )

    # ------------------------------------------------------------------
    # Resolve cover subtitle / scope label / chrome config (Phase 6).
    #
    # `resolved_subtitle` is the value-only scope string (D-02): caller's
    # explicit scope_subtitle wins, otherwise it's derived from the tag
    # filter. The cover template prefixes "Scope: " itself, so the value
    # passed as pdf_subtitle must be the bare token ("Production",
    # "All assets") — NOT "Scope: Production".
    # ------------------------------------------------------------------
    resolved_subtitle = (
        scope_subtitle
        if scope_subtitle is not None
        else _format_scope_subtitle(tag_category, tag_value)
    )
    scope_label = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )
    pdf_title = report_title or _DEFAULT_REPORT_TITLE

    pdf_chrome_cfg = PdfChromeConfig(
        title         = pdf_title,
        subtitle      = resolved_subtitle,
        generated_at  = generated_at,
        header_bg     = HEADER_BG_COLOR,
        logo_path     = LOGO_PATH,
        privacy_label = privacy_label,
    )

    # ------------------------------------------------------------------
    # Run composer pipeline
    # ------------------------------------------------------------------
    composer_kwargs: dict = {}
    if fixed_vulns_df is not None:
        composer_kwargs["fixed_vulns_df"] = fixed_vulns_df
    if _MODULES_NEEDING_ENV_TOTAL.intersection(modules):
        composer_kwargs["env_vuln_total"] = env_vuln_total
    if trend_snapshots is not None:
        composer_kwargs["trend_snapshots"] = trend_snapshots
    if recast_rules_df is not None:
        composer_kwargs["recast_rules_df"] = recast_rules_df

    composer = ReportComposer(
        vulns_df       = vulns_df,
        assets_df      = assets_df,
        report_date    = generated_at,
        module_configs = module_configs,
        pdf_chrome     = pdf_chrome_cfg,
        **composer_kwargs,
    )

    results = composer.run_all()

    bundle = composer.run_full_pipeline(
        results,
        output_dir,
        slug             = "composed_report",
        report_date      = generated_at,
        generate_analyst = analyst_detail,
        pdf_title        = pdf_title,
        pdf_subtitle     = resolved_subtitle,
        scope_label      = scope_label,
    )

    errors = bundle["errors"]
    kpis   = bundle["email_kpis"]

    if errors:
        logger.warning(
            "composed_report: %d module error(s) — %s", len(errors), errors
        )

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------
    pdf_path: Optional[Path] = None
    try:
        pdf_file = output_dir / _PDF_FILENAME
        _render_pdf(bundle["pdf_html"], pdf_file)
        pdf_path = pdf_file
        logger.info("composed_report: PDF written → %s", pdf_file)
    except Exception as exc:
        logger.error(
            "composed_report: PDF generation failed: %s", exc, exc_info=True
        )

    # ------------------------------------------------------------------
    # Excel
    # ------------------------------------------------------------------
    excel_path: Optional[Path] = None
    try:
        wb         = bundle["excel_workbook"]
        excel_file = output_dir / _EXCEL_FILENAME
        wb.save(str(excel_file))
        excel_path = excel_file
        logger.info("composed_report: Excel written → %s", excel_file)
    except Exception as exc:
        logger.error(
            "composed_report: Excel generation failed: %s", exc, exc_info=True
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
        "analyst_excel":       bundle["analyst_workbook_path"],
        "email_body_html":     bundle["email_body_html"],
        "email_inline_images": bundle.get("email_inline_images", []),
        "email_kpis":          kpis,
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

    Duplicated verbatim from ``reports/board_summary.py`` per the plan's
    "Do NOT factor _filter_assets_by_tag into a shared utility" rule.
    Tags are stored as semicolon-delimited "Category=Value" strings.

    When ``col`` is absent from the DataFrame, returns an empty frame so
    the report renders "no data in scope" rather than silently widening
    to all assets (WR-08 contract from board_summary).
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
    """Render an HTML string to PDF via WeasyPrint."""
    try:
        from weasyprint import HTML  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "WeasyPrint is required for PDF generation. "
            "Install it with: pip install weasyprint"
        ) from exc

    HTML(string=html).write_pdf(str(output_path))


# ===========================================================================
# CLI entry point — standalone runs
# ===========================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Composed Vulnerability Report — YAML-driven module composition."
        ),
    )
    parser.add_argument(
        "--modules", required=True, metavar="ID[,ID...]",
        help="Comma-separated list of registered module IDs to compose.",
    )
    parser.add_argument(
        "--tag-category", metavar="CATEGORY",
        help="Tenable tag category to scope report.",
    )
    parser.add_argument(
        "--tag-value", metavar="VALUE",
        help="Tag value paired with --tag-category.",
    )
    parser.add_argument(
        "--report-title", metavar="TITLE",
        help="Override the cover-page title.",
    )
    parser.add_argument(
        "--output-dir", metavar="PATH",
        help="Output directory (default: output/composed_report/).",
    )
    parser.add_argument(
        "--run-id", metavar="ID", default=None,
        help="Parquet cache key (default: today's local date, YYYY-MM-DD).",
    )
    return parser


def main() -> int:
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

    mod_ids = [m.strip() for m in args.modules.split(",") if m.strip()]

    try:
        from tenable_client import get_client  # noqa: PLC0415
        tio = get_client()
    except SystemExit:
        raise
    except Exception as exc:
        logger.error("Tenable connection failed: %s", exc, exc_info=True)
        return 1

    result = run_report(
        tio          = tio,
        run_id       = run_id,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
        output_dir   = output,
        modules      = mod_ids,
        report_title = args.report_title,
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
