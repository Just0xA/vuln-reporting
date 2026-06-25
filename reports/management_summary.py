"""
reports/management_summary.py — Management Vulnerability Summary Report (GEN-01).

Audience: Senior Management — Directors and Vice Presidents.
Language: Clear, jargon-free, action-oriented.  No plugin-level or
vulnerability-level detail.  Program health through seven high-level
metrics, each with a plain-language explanation.

GEN-01 migration (Phase 18 Plan 04):
    This file was migrated from a ~2,200-line bespoke render path onto
    ``ReportComposer.run_full_pipeline()`` composing all seven registered
    metric modules.  The bespoke functions (_save_trend_snapshot,
    _load_trend_history, _trend_file_path, _sanitise_tag_for_filename,
    _compute_metric_1.._7, compute_all_metrics, _build_age_bar_chart,
    _build_trend_line_chart, _build_pdf, build_email_kpi_tiles,
    build_email_body) and their private constants (_PDF_CSS, _AGE_BUCKETS,
    _OPEN_STATES) are removed in this commit — atomic, no dual-writer window
    (QUAL-04, D-18-10 gate 4).

    Trend writes use ``capture_snapshot()`` (forward-write to the S1 store).
    Trend reads use ``read_trend()`` with the all_assets scope seeded by
    Plan 03's backfill.

Outputs (composed, four-channel contract):
    - PDF:           management_summary.pdf      (chrome header/footer, WeasyPrint)
    - Excel:         management_summary.xlsx     (per-module tabs)
    - Analyst XLSX:  management_summary_*_analyst.xlsx (when analyst_detail=True)
    - Email:         modular panel HTML via build_email_body_modular()
    - Charts:        embedded in PDF/email as base64 CID

CLI
---
python reports/management_summary.py
python reports/management_summary.py \\
    --tag-category "Environment" --tag-value "Production"
python reports/management_summary.py --no-email --output-dir output/test/
python reports/management_summary.py --cache-dir data/cache/2026-03-01/
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Allow running as a top-level script from any working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    CACHE_DIR,
    HEADER_BG_COLOR,
    LOG_DIR,
    LOG_LEVEL,
    LOGO_PATH,
    OUTPUT_DIR,
)
from data.fetchers import (
    fetch_all_assets,
    fetch_all_vulnerabilities,
    fetch_fixed_vulnerabilities,
)
from data.trend_store import capture_snapshot, read_trend
from reports.modules import ReportComposer
from reports.modules.base import ModuleConfig
from reports.modules.pdf_chrome import PdfChromeConfig

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

REPORT_NAME = "Management Vulnerability Summary"
REPORT_SLUG = "management_summary"

_PDF_FILENAME   = "management_summary.pdf"
_EXCEL_FILENAME = "management_summary.xlsx"
_REPORT_TITLE   = "Management Vulnerability Summary"

# Phase 18 GEN-01: seven metric modules composing the migrated report.
# Auto-discovery via @register_module means no run_all.py re-registration
# of the modules themselves is needed — only this list.
_MGMT_MODULE_CONFIGS: list[ModuleConfig] = [
    ModuleConfig("total_vulns_by_severity"),
    ModuleConfig("scan_coverage_sla"),
    ModuleConfig("mttr_trend"),
    ModuleConfig("patch_compliance_rate"),
    ModuleConfig("aged_vulns_assets"),
    ModuleConfig("accepted_recast"),
    ModuleConfig("new_vs_remediated"),
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scope-subtitle helper (D-02 — matches board_summary inline copy to avoid
# circular import; single behaviour, two call sites per CLAUDE.md)
# ---------------------------------------------------------------------------

def _format_scope_subtitle(tc: str | None, tv: str | None) -> str:
    """Value-only scope subtitle. Returns ``tag_value`` when both
    category and value are non-empty, else ``"All assets"``."""
    return tv if (tc and tv) else "All assets"


# ---------------------------------------------------------------------------
# PDF render helper
# ---------------------------------------------------------------------------

def _render_pdf(html: str, output_path: Path) -> None:
    """Render an HTML string to a PDF file using WeasyPrint."""
    from weasyprint import HTML as _WP_HTML  # noqa: PLC0415
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _WP_HTML(string=html).write_pdf(str(output_path))


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
    # Phase 18 GEN-01 / Phase 6 chrome kwargs (CHROME-INT-02):
    privacy_label:  str = "Confidential",
    scope_subtitle: Optional[str] = None,
    report_title:   Optional[str] = None,
) -> dict:
    """
    Generate the Management Vulnerability Summary.

    GEN-01 (Phase 18): migrated from a bespoke 2,200-line render path onto
    ``ReportComposer.run_full_pipeline()`` composing seven metric modules.
    Trend reads via ``read_trend()`` (all_assets scope seeded by Plan 03).
    Trend writes via ``capture_snapshot()`` (forward-only, immutable past).

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Cache key (typically YYYY-MM-DD).
    tag_category, tag_value : str, optional
        Tenable tag filter.  Both must be non-empty to apply.
    output_dir : Path, optional
        Directory to write report files into.  Created if missing.
    generated_at : datetime, optional
        UTC-aware report timestamp.  Defaults to UTC now.
    cache_dir : Path, optional
        Parquet cache directory.  Defaults to today's ``CACHE_DIR`` subfolder.
    analyst_detail : bool, default True
        When True, generate and attach the analyst-detail companion workbook.
    privacy_label : str, default "Confidential"
        Chrome header privacy label (injected by run_all.py via
        _CHROME_AWARE_SLUGS gate).
    scope_subtitle : str, optional
        Override the scope subtitle shown in the chrome header.  When None,
        derived from tag_category/tag_value (``_format_scope_subtitle``).
    report_title : str, optional
        YAML-driven cover-page title override.  Defaults to REPORT_NAME.

    Returns
    -------
    dict
        Standard report output dict::

            {
                "pdf":                  Path | None,
                "excel":                Path | None,
                "charts":               [],
                "metrics":              {"kpis": list, "errors": list,
                                         "module_results": dict},
                "analyst_excel":        Path | None,
                "email_body_html":      str,          # non-empty (modular panels)
                "email_inline_images":  list[dict],   # CID gauge entries
                "email_kpis":           list,         # legacy KPI tiles
                "_bundle":              dict,         # composer bundle (internal)
            }

        Never raises — all exceptions are caught and reflected in the return
        dict and application log.
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if cache_dir is None:
        cache_dir = CACHE_DIR / datetime.now().strftime("%Y-%m-%d")
    if output_dir is None:
        output_dir = OUTPUT_DIR / "management_summary"

    output_dir = Path(output_dir)
    cache_dir  = Path(cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    _log_scope = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all assets"
    )
    logger.info(
        "management_summary: starting run (scope=%s, run_id=%s, output=%s)",
        _log_scope, run_id, output_dir,
    )

    # ------------------------------------------------------------------
    # CR-F3: initialise safe defaults so the return dict is always valid
    # even when the fetch/compose block raises (never-raises contract).
    # ------------------------------------------------------------------
    bundle:          dict           = {"errors": [], "email_kpis": [], "pdf_html": "",
                                       "excel_workbook": None, "email_body_html": "",
                                       "email_inline_images": [], "analyst_workbook_path": None}
    errors:          list           = []
    kpis:            list           = []
    results:         list           = []
    vulns_df        = None          # assigned inside try; used by capture_snapshot
    assets_df       = None
    fixed_vulns_df  = None
    tag_filter_label: str           = "all_assets"

    try:
        # ------------------------------------------------------------------
        # Fetch data (parquet cache shared with other reports in the same run)
        # ------------------------------------------------------------------
        logger.info("management_summary: fetching open vulnerabilities …")
        vulns_df = fetch_all_vulnerabilities(tio, cache_dir)

        logger.info("management_summary: fetching assets …")
        assets_df = fetch_all_assets(tio, cache_dir)

        logger.info("management_summary: fetching fixed vulnerabilities …")
        fixed_vulns_df = fetch_fixed_vulnerabilities(tio, cache_dir)

        logger.info(
            "management_summary: data loaded — vulns=%d, assets=%d, fixed=%d",
            len(vulns_df), len(assets_df), len(fixed_vulns_df),
        )

        # ------------------------------------------------------------------
        # Tag filter (exact token match on the tags string column)
        # ------------------------------------------------------------------
        if tag_category and tag_value:
            tag_filter_label = f"{tag_category}_{tag_value}"

            # Filter assets by tag using set membership on asset UUIDs.
            # Resolve the tag server-side against the live Tenable export — the
            # authoritative scoping rule used everywhere else in the suite — by
            # passing the real client (CR-01).
            from utils.tag_helper import get_assets_by_tag  # noqa: PLC0415
            try:
                filtered_asset_uuids = set(
                    get_assets_by_tag(tio, tag_category, tag_value)
                )
            except Exception:
                # Fallback: filter from the in-memory tags_str column. This is a
                # weaker (substring) match and must never fail silently — log the
                # primary-path failure so an operator can see the scope diverged
                # (CLAUDE.md: no silent failures).
                logger.warning(
                    "management_summary: server-side tag scoping via get_assets_by_tag "
                    "failed for '%s=%s'; falling back to in-memory tags_str substring "
                    "match (scope may differ from the rest of the suite).",
                    tag_category, tag_value,
                    exc_info=True,
                )
                mask = assets_df["tags_str"].str.contains(
                    f"{tag_category}: {tag_value}", na=False
                )
                filtered_asset_uuids = set(assets_df.loc[mask, "asset_uuid"].dropna())

            scoped_uuids = filtered_asset_uuids

            assets_df = (
                assets_df[assets_df["asset_uuid"].isin(scoped_uuids)]
                .copy()
                .reset_index(drop=True)
            )
            vulns_df = (
                vulns_df[vulns_df["asset_uuid"].isin(scoped_uuids)]
                .copy()
                .reset_index(drop=True)
            )
            fixed_vulns_df = (
                fixed_vulns_df[fixed_vulns_df["asset_uuid"].isin(scoped_uuids)]
                .copy()
                .reset_index(drop=True)
            )
            logger.info(
                "management_summary: tag filter '%s=%s' — %d assets, %d vulns in scope.",
                tag_category, tag_value, len(assets_df), len(vulns_df),
            )
        else:
            tag_filter_label = "all_assets"

        # ------------------------------------------------------------------
        # Trend read (read_trend feeds all seven modules; all_assets seeded by
        # Plan 03; tag-scoped groups cold-start MoM — pre-existing, not a
        # regression — D-18-10 scope note)
        # ------------------------------------------------------------------
        trend_snapshots = read_trend(
            "severity",
            tag_filter_label,
            months=13,
        )
        logger.info(
            "management_summary: trend read (filter=%s) — %d snapshots, insufficient=%s",
            tag_filter_label,
            len(trend_snapshots.get("snapshots", [])),
            trend_snapshots.get("insufficient_data", True),
        )

        # ------------------------------------------------------------------
        # INT-WARN-2 (D-04): fail-soft recast rules fetch.
        # accepted_recast is always in _MGMT_MODULE_CONFIGS, so fetch
        # unconditionally — but still fail-soft (mirrors composed_report.py
        # L245-259 gated recast fetch pattern).
        # ------------------------------------------------------------------
        recast_rules_df = None
        try:
            from data.fetchers import fetch_recast_rules  # noqa: PLC0415
            logger.info("management_summary: fetching recast rules …")
            recast_rules_df = fetch_recast_rules(tio, cache_dir)
        except Exception as _recast_exc:
            logger.error(
                "management_summary: recast rules fetch failed (non-fatal): %s",
                _recast_exc, exc_info=True,
            )
            recast_rules_df = None

        # ------------------------------------------------------------------
        # Subtitle / scope label resolution (D-02)
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

        # ------------------------------------------------------------------
        # Chrome config (CHROME-INT-02, Phase 18 GEN-01)
        # ------------------------------------------------------------------
        effective_title = report_title or _REPORT_TITLE

        pdf_chrome_cfg = PdfChromeConfig(
            title         = effective_title,
            subtitle      = resolved_subtitle,
            generated_at  = generated_at,
            header_bg     = HEADER_BG_COLOR,
            logo_path     = LOGO_PATH,
            privacy_label = privacy_label,
        )

        # ------------------------------------------------------------------
        # Compose via ReportComposer (mirrors board_summary wiring exactly)
        #
        # trend_snapshots forwarded via **kwargs fans out to every module's
        # compute() — mttr_trend, new_vs_remediated, accepted_recast consume
        # it; others ignore it silently (Pitfall 4 guard, D-14 kwargs gate).
        # fixed_vulns_df forwarded similarly — mttr_trend + other modules
        # that need it consume it; non-consumers ignore via **kwargs.
        # recast_rules_df forwarded so accepted_recast expiry cross-check
        # runs (INT-WARN-2/D-04).
        # ------------------------------------------------------------------
        composer = ReportComposer(
            vulns_df        = vulns_df,
            assets_df       = assets_df,
            report_date     = generated_at,
            module_configs  = _MGMT_MODULE_CONFIGS,
            fixed_vulns_df  = fixed_vulns_df,
            pdf_chrome      = pdf_chrome_cfg,
            trend_snapshots = trend_snapshots,    # D-14 kwargs fan-out
            recast_rules_df = recast_rules_df,    # D-04 / INT-WARN-2
        )

        results = composer.run_all()

        bundle = composer.run_full_pipeline(
            results,
            output_dir,
            slug             = REPORT_SLUG,
            report_date      = generated_at,
            generate_analyst = analyst_detail,
            pdf_title        = effective_title,
            pdf_subtitle     = resolved_subtitle,
            scope_label      = scope_label,
        )

        errors = bundle["errors"]
        kpis   = bundle["email_kpis"]

        if errors:
            logger.warning(
                "management_summary: %d module error(s) — %s", len(errors), errors
            )

    except Exception as _compose_exc:
        logger.error(
            "management_summary: fetch/compose failed (non-fatal): %s",
            _compose_exc, exc_info=True,
        )

    # ------------------------------------------------------------------
    # PDF — bytes come from bundle["pdf_html"]; WeasyPrint render
    # ------------------------------------------------------------------
    pdf_path: Optional[Path] = None
    try:
        pdf_file = output_dir / _PDF_FILENAME
        _render_pdf(bundle["pdf_html"], pdf_file)
        pdf_path = pdf_file
        logger.info("management_summary: PDF written → %s", pdf_file)
    except Exception as exc:
        logger.error(
            "management_summary: PDF generation failed: %s", exc, exc_info=True
        )

    # ------------------------------------------------------------------
    # Excel — workbook from bundle["excel_workbook"]
    # ------------------------------------------------------------------
    excel_path: Optional[Path] = None
    try:
        wb         = bundle["excel_workbook"]
        excel_file = output_dir / _EXCEL_FILENAME
        wb.save(str(excel_file))
        excel_path = excel_file
        logger.info("management_summary: Excel written → %s", excel_file)
    except Exception as exc:
        logger.error(
            "management_summary: Excel generation failed: %s", exc, exc_info=True
        )

    # ------------------------------------------------------------------
    # Forward-write trend snapshot (capture_snapshot — D-18-03/D-18-08)
    # Replaces the bespoke _save_trend_snapshot.  capture_snapshot() is
    # idempotent and skips reconstructed months (immutability preserved).
    # Fail-soft: a snapshot write failure must not abort the batch.
    # Guard: skip when fetch failed (vulns_df is None — CR-F3 path).
    # ------------------------------------------------------------------
    if vulns_df is not None and assets_df is not None:
        try:
            # ------------------------------------------------------------------
            # INT-WARN-1 (D-03): extract aggregate counts from the module
            # results computed by composer.run_all() so capture_snapshot()
            # receives the FULL field set (matching the cron writer in
            # scripts/capture_trend_snapshot.py).  Use None as the safe
            # default whenever a module result has error is not None (D-16-09).
            # ------------------------------------------------------------------
            _results_by_id: dict = {r.module_id: r for r in results}

            def _safe_metric(module_id: str, key: str):
                """Return metric value or None when module errored or key absent."""
                r = _results_by_id.get(module_id)
                if r is None or r.error is not None:
                    return None
                return r.metrics.get(key)

            def _safe_metadata(module_id: str, key: str):
                """Return metadata value or None when module errored or key absent."""
                r = _results_by_id.get(module_id)
                if r is None or r.error is not None:
                    return None
                return (r.metadata or {}).get(key)

            # accepted_recast → accepted_count, recast_count
            _snap_accepted_count = _safe_metric("accepted_recast", "accepted_count")
            _snap_recast_count   = _safe_metric("accepted_recast", "recast_count")

            # reopened_vulns → reopened_count
            _snap_reopened_count = _safe_metric("reopened_vulns", "reopened_count")

            # scan_coverage_sla → on_time_asset_count (stored as "scanned_on_time")
            _snap_on_time_asset_count = _safe_metric("scan_coverage_sla", "scanned_on_time")

            # mttr_trend → mttr_overall_days (stored as "overall_mttr")
            _snap_mttr_overall = _safe_metric("mttr_trend", "overall_mttr")

            # mttr_trend → mttr_by_severity dict (from per-sev _mttr metrics keys)
            _mttr_r = _results_by_id.get("mttr_trend")
            if _mttr_r is not None and _mttr_r.error is None and _mttr_r.metrics:
                _snap_mttr_by_severity: dict | None = {
                    sev: _mttr_r.metrics.get(f"{sev}_mttr")
                    for sev in ("critical", "high", "medium", "low")
                }
            else:
                _snap_mttr_by_severity = None

            # mttr_trend → mttr_by_owner dict (from metadata["table_data_owner"])
            _owner_rows = _safe_metadata("mttr_trend", "table_data_owner")
            if _owner_rows:
                _snap_mttr_by_owner: dict | None = {
                    row["label"]: row["mttr_days"]
                    for row in _owner_rows
                    if row.get("label") is not None
                }
            else:
                _snap_mttr_by_owner = None

            # program_health → sla_rate_crit_high (stored as "sla_rate_current")
            _snap_sla_rate_crit_high = _safe_metric("program_health", "sla_rate_current")

            capture_snapshot(
                df                  = vulns_df,
                assets_df           = assets_df,
                date                = generated_at,
                dimension           = "severity",
                tag_filter          = tag_filter_label,
                fixed_vulns_df      = fixed_vulns_df,
                on_time_asset_count = _snap_on_time_asset_count,
                reopened_count      = _snap_reopened_count,
                accepted_count      = _snap_accepted_count,
                recast_count        = _snap_recast_count,
                mttr_overall_days   = _snap_mttr_overall,
                mttr_by_severity    = _snap_mttr_by_severity,
                mttr_by_owner       = _snap_mttr_by_owner,
                sla_rate_crit_high  = _snap_sla_rate_crit_high,
            )
            logger.info(
                "management_summary: trend snapshot captured (filter=%s)", tag_filter_label
            )
        except Exception as exc:
            logger.error(
                "management_summary: trend snapshot write failed (non-fatal): %s",
                exc, exc_info=True,
            )
    else:
        logger.warning(
            "management_summary: skipping trend snapshot — data fetch failed (CR-F3 path)."
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
        # Bundle-driven routing keys (CLAUDE.md "Modular reports"):
        "analyst_excel":       bundle["analyst_workbook_path"],
        "email_body_html":     bundle["email_body_html"],        # non-empty → modular routing
        "email_inline_images": bundle.get("email_inline_images", []),
        "email_kpis":          kpis,
        # Private diagnostic key (mirrors board_summary pattern):
        # Used by smoke_management_summary_cutover.py and tests via
        # extract_structural_snapshot(result["_bundle"]).  NOT part of
        # the public delivery contract.
        "_bundle": bundle,
    }

    logger.info("management_summary: run complete | pdf=%s", pdf_path)
    return result_dict


# ===========================================================================
# CLI — standalone execution
# ===========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{REPORT_NAME} — Phase 18 GEN-01 migrated pipeline",
    )
    parser.add_argument("--tag-category", default=None,
                        help="Tenable tag category to filter by, e.g. 'Environment'")
    parser.add_argument("--tag-value", default=None,
                        help="Tenable tag value to filter by, e.g. 'Production'")
    parser.add_argument("--cache-dir", default=None,
                        help="Path to an existing parquet cache directory")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory for report files")
    parser.add_argument("--no-email", action="store_true",
                        help="Generate reports but skip email delivery")
    args = parser.parse_args()

    from dotenv import load_dotenv  # noqa: PLC0415
    load_dotenv()

    from tenable_client import get_client  # noqa: PLC0415
    _tio = get_client()

    _run_id  = datetime.now().strftime("%Y-%m-%d")
    _out_dir = Path(args.output_dir) if args.output_dir else None
    _cdir    = Path(args.cache_dir) if args.cache_dir else None

    _result = run_report(
        _tio,
        _run_id,
        tag_category = args.tag_category,
        tag_value    = args.tag_value,
        output_dir   = _out_dir,
        cache_dir    = _cdir,
    )
    print(f"PDF:   {_result['pdf']}")
    print(f"Excel: {_result['excel']}")
    errs = _result["metrics"]["errors"]
    if errs:
        print(f"Errors: {errs}")
