"""
reports/vuln_export.py — Raw Vulnerability Export (CSV)

Produces a single CSV file containing one row per open vulnerability finding,
scoped to the delivery group's tag filter and severity filter.  No PDF, no
Excel workbook, no charts.  The CSV is attached to the email as a data file
for downstream use (ticketing, import, ad-hoc analysis).

This is intentionally the simplest report in the suite.

Audience : Operations / Remediation Teams, Security Analysts
Output   : CSV only
Charts   : None
PDF      : None
Excel    : None

CLI usage
---------
  python reports/vuln_export.py
  python reports/vuln_export.py \\
      --tag-category "Operations" --tag-value "Server Operations"
  python reports/vuln_export.py \\
      --severities critical high medium
  python reports/vuln_export.py \\
      --no-email --output-dir output/test_csv/
  python reports/vuln_export.py \\
      --cache-dir data/cache/2026-03-25/

run_all.py integration
-----------------------
  Return dict: {"pdf": None, "excel": None, "csv": "<path>", "charts": []}
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Allow running as a standalone script from any working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import CACHE_DIR, LOG_DIR, LOG_LEVEL, OUTPUT_DIR, SEVERITY_ORDER, SLA_DAYS
from data.fetchers import (
    enrich_vulns_with_assets,
    fetch_all_assets,
    fetch_all_vulnerabilities,
    filter_by_severity,
    filter_by_tag,
)
from utils.sla_calculator import apply_sla_to_df

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SEVERITIES: list[str] = ["critical", "high", "medium"]
VALID_SEVERITIES:   frozenset[str] = frozenset({"critical", "high", "medium", "low"})

# Severity sort order (lower index = higher priority)
_SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Four-state SLA labels (shorter than ops_remediation.py's long strings)
SLA_OVERDUE  = "Overdue"
SLA_URGENT   = "Urgent"
SLA_WARNING  = "Warning"
SLA_ON_TRACK = "On Track"


# ===========================================================================
# Internal helpers
# ===========================================================================

def _compute_csv_sla_status(df: pd.DataFrame) -> pd.Series:
    """
    Compute four-state SLA status labels for each row.

    Requires apply_sla_to_df() to have been called first so that
    ``is_overdue``, ``days_remaining``, and ``sla_days`` columns exist.

    States
    ------
    Overdue  : days_open > sla_days
    Urgent   : within SLA AND days_remaining ≤ 25% of sla_days
    Warning  : within SLA AND days_remaining ≤ 50% of sla_days (> 25%)
    On Track : within SLA AND days_remaining > 50% of sla_days

    Rows with no applicable SLA (info severity or missing sla_days) default
    to On Track.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain is_overdue, days_remaining, sla_days columns.

    Returns
    -------
    pd.Series
        String labels aligned to df.index.
    """
    urgent_threshold  = df["sla_days"] * 0.25
    warning_threshold = df["sla_days"] * 0.50

    conditions = [
        df["is_overdue"],
        ~df["is_overdue"] & (df["days_remaining"] <= urgent_threshold),
        ~df["is_overdue"] & (df["days_remaining"] <= warning_threshold),
    ]
    choices = [SLA_OVERDUE, SLA_URGENT, SLA_WARNING]

    return pd.Series(
        np.select(conditions, choices, default=SLA_ON_TRACK),
        index=df.index,
        dtype="object",
    )


def _resolve_severities(
    raw: Optional[list[str]],
) -> list[str]:
    """
    Validate and normalise a list of severity filter strings.

    Invalid values are logged as warnings and dropped.  If all values are
    invalid (or raw is None / empty), the DEFAULT_SEVERITIES list is returned.

    Parameters
    ----------
    raw : list[str] or None

    Returns
    -------
    list[str]
        Lower-cased severity strings, ordered by SEVERITY_ORDER rank.
    """
    if not raw:
        return list(DEFAULT_SEVERITIES)

    valid: list[str] = []
    for item in raw:
        normalised = str(item).strip().lower()
        if normalised in VALID_SEVERITIES:
            valid.append(normalised)
        else:
            logger.warning(
                "vuln_export: ignoring invalid csv_severities value: %r "
                "(valid: %s)",
                item,
                ", ".join(sorted(VALID_SEVERITIES)),
            )

    if not valid:
        logger.warning(
            "vuln_export: no valid severities after validation — "
            "falling back to default: %s",
            DEFAULT_SEVERITIES,
        )
        return list(DEFAULT_SEVERITIES)

    # Return in canonical severity order
    return sorted(valid, key=lambda s: _SEVERITY_RANK.get(s, 99))


def _build_csv_dataframe(
    vulns_df: pd.DataFrame,
    report_date: datetime,
) -> pd.DataFrame:
    """
    Apply SLA status, select/rename columns, and sort.

    ``vulns_df`` must already be enriched via ``enrich_vulns_with_assets()``
    before being passed here — hostname, ipv4, and operating_system are sourced
    directly from the enriched DataFrame rather than joined again.

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Enriched, tag-filtered, state-filtered, severity-filtered vulnerability
        DataFrame (output of enrich_vulns_with_assets → filter_by_tag).
    report_date : datetime
        UTC timestamp used as the "as of" date for SLA and days-open
        calculations.

    Returns
    -------
    pd.DataFrame
        Ready-to-write DataFrame with the final column headers.
    """
    if vulns_df.empty:
        logger.warning("vuln_export: no open findings after filtering — CSV will be empty.")
        return pd.DataFrame(columns=[
            "Plugin ID", "Plugin Name", "Application", "Asset Name", "IP Address",
            "Operating System", "CPE", "Severity", "VPR Score", "First Found",
            "Days Open", "SLA Status", "Exploit Available", "Exploit Code Maturity",
        ])

    df = vulns_df.copy()

    # ------------------------------------------------------------------
    # SLA calculations
    # ------------------------------------------------------------------
    df = apply_sla_to_df(df, as_of=report_date)

    # ------------------------------------------------------------------
    # Derived columns — build all at once via assign() to avoid
    # chained-assignment warnings under pandas Copy-on-Write mode.
    # ------------------------------------------------------------------
    def _fmt_vpr(v) -> str:
        try:
            if v is None or (isinstance(v, float) and np.isnan(v)):
                return "N/A"
            return f"{float(v):.1f}"
        except (TypeError, ValueError):
            return "N/A"

    def _extract_tag_value(tags_str: str, category: str) -> str:
        prefix = f"{category}="
        for part in str(tags_str).split(";"):
            if part.strip().startswith(prefix):
                return part.strip()[len(prefix):]
        return ""

    first_found_dt  = pd.to_datetime(df["first_found"], utc=True, errors="coerce")
    # days_open from apply_sla_to_df uses fillna(-1) for missing first_found;
    # convert -1 sentinel back to pd.NA so it writes as blank in the CSV.
    raw_days_open   = pd.to_numeric(df["days_open"], errors="coerce")
    nullable_days   = raw_days_open.where(raw_days_open >= 0, other=pd.NA).astype("Int64")

    tags_col = df.get("tags", pd.Series("", index=df.index)).fillna("")

    df = df.assign(
        sla_status_csv         = _compute_csv_sla_status(df),
        days_open_display      = nullable_days,
        vpr_score_fmt          = df["vpr_score"].apply(_fmt_vpr),
        first_found_date       = first_found_dt.dt.strftime("%Y-%m-%d").fillna(""),
        severity_display       = df["severity"].str.title().fillna(""),
        exploit_available_disp = df["exploit_available"].apply(
                                     lambda v: "Yes" if v is True else "No"
                                 ),
        exploit_maturity_disp  = (
                                     df["exploit_code_maturity"]
                                     .fillna("")
                                     .str.strip()
                                     .str.replace("_", " ", regex=False)
                                     .apply(lambda v: v.title() if v else "Unknown")
                                 ),
        application_tag        = tags_col.apply(lambda t: _extract_tag_value(t, "Application")),
        _sev_rank              = df["severity"].str.lower().map(_SEVERITY_RANK).fillna(99),
        _vpr_sort              = pd.to_numeric(df["vpr_score"], errors="coerce").fillna(-1.0),
        _days_sort             = raw_days_open.fillna(-1),
    )

    # ------------------------------------------------------------------
    # Sort: Critical → High → Medium → Low, then VPR desc, then Days Open desc
    # ------------------------------------------------------------------
    df = (
        df.sort_values(
            by=["_sev_rank", "_vpr_sort", "_days_sort"],
            ascending=[True, False, False],
        )
        .drop(columns=["_sev_rank", "_vpr_sort", "_days_sort"])
        .reset_index(drop=True)
    )

    # ------------------------------------------------------------------
    # Select and rename to final output columns
    # ------------------------------------------------------------------
    output_df = pd.DataFrame({
        "Plugin ID":             df["plugin_id"].fillna("").astype(str).str.replace(r"\.0$", "", regex=True),
        "Plugin Name":           df["plugin_name"].fillna(""),
        "Application":           df["application_tag"],
        "Asset Name":            df.get("hostname", pd.Series("", index=df.index)).fillna(""),
        "IP Address":            df.get("ipv4", pd.Series("", index=df.index)).fillna(""),
        "Operating System":      df.get("operating_system", pd.Series("", index=df.index)).fillna(""),
        "CPE":                   df.get("cpe", pd.Series("", index=df.index)).fillna(""),
        "Severity":              df["severity_display"],
        "VPR Score":             df["vpr_score_fmt"],
        "First Found":           df["first_found_date"],
        "Days Open":             df["days_open_display"],
        "SLA Status":            df["sla_status_csv"],
        "Exploit Available":     df["exploit_available_disp"],
        "Exploit Code Maturity": df["exploit_maturity_disp"],
    })

    return output_df


def _build_kpi_metrics(
    output_df: pd.DataFrame,
    tag_category: Optional[str],
    tag_value: Optional[str],
    severities: list[str],
) -> dict:
    """
    Build the kpi_metrics dict for email_template rendering.

    Parameters
    ----------
    output_df : pd.DataFrame
        The final CSV DataFrame (already filtered and sorted).
    tag_category, tag_value : str or None
        Tag filter applied.
    severities : list[str]
        Severity filter applied (lower-cased).

    Returns
    -------
    dict
        Suitable for passing to build_email_body() via the metrics key.
    """
    total   = len(output_df)
    n_crit  = int((output_df["Severity"] == "Critical").sum())
    n_high  = int((output_df["Severity"] == "High").sum())
    n_med   = int((output_df["Severity"] == "Medium").sum())

    scope_label = (
        f"{tag_category} = {tag_value}"
        if tag_category and tag_value
        else "All Assets"
    )
    sev_label = ", ".join(s.title() for s in severities)

    summary_text = (
        f"This report contains {total:,} open vulnerability findings for "
        f"{scope_label} filtered to {sev_label} severity. The attached CSV "
        f"file includes one row per finding and can be opened directly in "
        f"Excel or imported into your ticketing system."
    )

    return {
        "kpi_metrics": {
            "Total Findings (CSV)": total,
            "Critical":             n_crit,
            "High":                 n_high,
            "Medium":               n_med,
            "Scope":                scope_label,
            "Severity Filter":      sev_label,
        },
        "summary_text": summary_text,
    }


# ===========================================================================
# Public run_report entry point
# ===========================================================================

def run_report(
    tio,
    run_id: str,
    *,
    tag_category: Optional[str] = None,
    tag_value: Optional[str] = None,
    output_dir: Optional[Path] = None,
    generated_at: Optional[datetime] = None,
    cache_dir: Optional[Path] = None,
    csv_severities: Optional[list[str]] = None,
) -> dict:
    """
    Generate the raw vulnerability export CSV for one delivery group.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Cache key for parquet files (e.g. "2026-04-08").
    tag_category : str, optional
        Tenable tag category to scope findings (e.g. "Operations").
    tag_value : str, optional
        Tenable tag value to scope findings (e.g. "Server Operations").
    output_dir : Path, optional
        Directory to save the CSV file.  Created if absent.
        Defaults to OUTPUT_DIR / "vuln_export".
    generated_at : datetime, optional
        Report timestamp (UTC).  Defaults to now.
    cache_dir : Path, optional
        Run-scoped parquet cache directory.  Defaults to today's CACHE_DIR.
    csv_severities : list[str], optional
        Severities to include.  Defaults to ["critical", "high", "medium"].
        Values are case-insensitive; invalid values are warned and dropped.

    Returns
    -------
    dict
        {"pdf": None, "excel": None, "csv": str | None, "charts": [],
         "metrics": {...}}
        ``csv`` is the absolute path to the generated CSV, or None if
        generation failed.
    """
    if generated_at is None:
        generated_at = datetime.now(tz=timezone.utc)
    if output_dir is None:
        output_dir = OUTPUT_DIR / "vuln_export"
    if cache_dir is None:
        cache_dir = CACHE_DIR / datetime.now().strftime("%Y-%m-%d")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir  = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    severities = _resolve_severities(csv_severities)
    logger.info(
        "vuln_export: tag=%s=%s | severities=%s | output=%s",
        tag_category, tag_value, severities, output_dir,
    )

    # ------------------------------------------------------------------
    # Fetch data (shared parquet cache)
    # ------------------------------------------------------------------
    try:
        vulns_raw  = fetch_all_vulnerabilities(tio, cache_dir)
        assets_raw = fetch_all_assets(tio, cache_dir)
    except Exception as exc:
        logger.error("vuln_export: data fetch failed: %s", exc, exc_info=True)
        return {"pdf": None, "excel": None, "csv": None, "charts": [], "metrics": {}}

    # ------------------------------------------------------------------
    # Enrich vulns with asset tags BEFORE tag filtering.
    # fetch_all_vulnerabilities() intentionally omits the 'tags' column
    # because the vuln export does not populate asset.tags reliably.
    # enrich_vulns_with_assets() performs a left join against the asset
    # export (which does carry tags), adding the 'tags' column so that
    # filter_by_tag() can scope the result correctly.
    # ------------------------------------------------------------------
    try:
        vulns_enriched = enrich_vulns_with_assets(vulns_raw, assets_raw)
    except Exception as exc:
        logger.error("vuln_export: enrich_vulns_with_assets failed: %s", exc, exc_info=True)
        return {"pdf": None, "excel": None, "csv": None, "charts": [], "metrics": {}}

    # ------------------------------------------------------------------
    # Filter: tag scope (on enriched df — now has 'tags' column)
    # ------------------------------------------------------------------
    vulns_df = filter_by_tag(vulns_enriched, tag_category, tag_value)

    # ------------------------------------------------------------------
    # Filter: open findings only
    # ------------------------------------------------------------------
    if "state" in vulns_df.columns:
        open_mask = vulns_df["state"].str.upper().isin(["OPEN", "REOPENED"])
        vulns_df  = vulns_df[open_mask].copy()
        logger.info("vuln_export: %d open findings after state filter", len(vulns_df))

    # ------------------------------------------------------------------
    # Filter: severity
    # ------------------------------------------------------------------
    vulns_df = filter_by_severity(vulns_df, severities)
    logger.info("vuln_export: %d findings after severity filter", len(vulns_df))

    # ------------------------------------------------------------------
    # Build CSV DataFrame
    # ------------------------------------------------------------------
    try:
        output_df = _build_csv_dataframe(vulns_df, generated_at)
    except Exception as exc:
        logger.error("vuln_export: _build_csv_dataframe failed: %s", exc, exc_info=True)
        return {"pdf": None, "excel": None, "csv": None, "charts": [], "metrics": {}}

    # ------------------------------------------------------------------
    # Write CSV — UTF-8 with BOM so Excel opens cleanly
    # ------------------------------------------------------------------
    date_str  = generated_at.strftime("%Y-%m-%d")
    csv_name  = f"vuln_export_{date_str}.csv"
    csv_path  = output_dir / csv_name

    try:
        output_df.to_csv(
            csv_path,
            index=False,
            encoding="utf-8-sig",    # BOM for Excel compatibility
            quoting=1,               # csv.QUOTE_ALL — quote all fields
        )
        logger.info(
            "vuln_export: wrote %d rows to %s (%d KB)",
            len(output_df),
            csv_path,
            csv_path.stat().st_size // 1024,
        )
    except Exception as exc:
        logger.error("vuln_export: CSV write failed: %s", exc, exc_info=True)
        return {"pdf": None, "excel": None, "csv": None, "charts": [], "metrics": {}}

    # ------------------------------------------------------------------
    # KPI metrics for email body
    # ------------------------------------------------------------------
    metrics = _build_kpi_metrics(output_df, tag_category, tag_value, severities)
    metrics["csv_row_count"] = len(output_df)
    metrics["csv_filename"]  = csv_name

    return {
        "pdf":     None,
        "excel":   None,
        "csv":     str(csv_path),
        "charts":  [],
        "metrics": metrics,
    }


# ===========================================================================
# CLI entry point
# ===========================================================================

def _configure_logging(level: str = "INFO") -> None:
    """Set up rotating file + stream logging."""
    from logging.handlers import RotatingFileHandler

    LOG_DIR.mkdir(exist_ok=True)
    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))

    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s")

    fh = RotatingFileHandler(LOG_DIR / "app.log", maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    root.addHandler(fh)
    root.addHandler(sh)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a raw vulnerability export CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tag-category",
        metavar="CATEGORY",
        help="Tenable tag category to scope findings (e.g. 'Operations')",
    )
    parser.add_argument(
        "--tag-value",
        metavar="VALUE",
        help="Tenable tag value to scope findings (e.g. 'Server Operations')",
    )
    parser.add_argument(
        "--severities",
        nargs="+",
        metavar="SEV",
        default=None,
        help=(
            "Severity levels to include. Valid: critical high medium low. "
            f"Default: {' '.join(DEFAULT_SEVERITIES)}"
        ),
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default=None,
        help="Directory to save the CSV file (created if absent)",
    )
    parser.add_argument(
        "--cache-dir",
        metavar="DIR",
        default=None,
        help="Run-scoped parquet cache directory",
    )
    parser.add_argument(
        "--no-email",
        action="store_true",
        help="Generate the CSV but do not send an email",
    )
    parser.add_argument(
        "--log-level",
        default=LOG_LEVEL,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: %(default)s)",
    )

    args = parser.parse_args()
    _configure_logging(args.log_level)

    output_dir = Path(args.output_dir) if args.output_dir else None
    cache_dir  = Path(args.cache_dir)  if args.cache_dir  else None

    try:
        from tenable_client import get_client  # noqa: PLC0415
        tio = get_client()
    except SystemExit:
        sys.exit(1)
    except Exception as e:
        logger.error("Tenable connection failed: %s", e)
        sys.exit(1)

    run_id = datetime.now().strftime("%Y-%m-%d")

    result = run_report(
        tio,
        run_id,
        tag_category=args.tag_category,
        tag_value=args.tag_value,
        output_dir=output_dir,
        cache_dir=cache_dir,
        csv_severities=args.severities,
    )

    csv_path = result.get("csv")
    if csv_path:
        import csv as _csv

        path = Path(csv_path)
        metrics = result.get("metrics", {})
        kpi     = metrics.get("kpi_metrics", {})

        print(f"\n--- vuln_export complete ---")
        print(f"File   : {path}")
        print(f"Size   : {path.stat().st_size // 1024} KB")
        print(f"Rows   : {kpi.get('Total Findings (CSV)', 0):,}")
        print(f"Critical: {kpi.get('Critical', 0):,}")
        print(f"High    : {kpi.get('High', 0):,}")
        print(f"Medium  : {kpi.get('Medium', 0):,}")
        print()

        # Print column headers and first 5 rows
        try:
            preview = pd.read_csv(path, encoding="utf-8-sig", nrows=5)
            print("Column headers:")
            for col in preview.columns:
                print(f"  {col}")
            print()
            print("First 5 rows:")
            print(preview.to_string(index=False, max_colwidth=40))
        except Exception as ex:
            print(f"Could not preview CSV: {ex}")

        if not args.no_email:
            print("\n--no-email not specified; email delivery requires run_all.py.")
    else:
        print("vuln_export: generation failed — check logs for details.")
        sys.exit(1)
