"""
data/trend_store.py — Forward-accumulating trend snapshot engine.

Provides two public functions:

  capture_snapshot(df, assets_df, date, ...) -> Path
      Write an atomic monthly snapshot of open-finding counts to
      ``data/trend/trend_{dimension}_{tag_suffix}.json``.

  read_trend(dimension, tag_filter, months, ...) -> dict
      Cold-start-safe reader; returns {"snapshots": [...], "insufficient_data": bool}.

Design constraints
------------------
D-01: This module is a NEW shared module.  ``reports/management_summary.py`` and
      its private helpers are left exactly as-is; this substrate does NOT edit them.
D-02: Snapshot engine lives in data/ (I/O layer); pure-compute predicate stays in
      utils/open_count.py (Plan 01).
D-03: Snapshots are file-per-dimension: trend_{dimension}_{tagsuffix}.json.
D-04: Each snapshot entry records aggregate in-scope asset_count alongside counts.
D-05: read_trend reads only trend_*.json files, never management_summary_*.json.
D-08: capture_snapshot is df-injected — receives already-fetched df + assets_df;
      calls open_findings_at; does no fetching itself.

Timezone policy (CLAUDE.md):
  - month key   → server-LOCAL time  (date.strftime("%Y-%m"), no tzinfo)
  - generated_at → UTC               (datetime.now(tz=timezone.utc))

Windows atomic-write safety (Gemini MEDIUM review):
  _atomic_write_json closes the temp-file fd via a ``with os.fdopen(...)`` block
  BEFORE calling os.replace.  On Windows an open fd held over the destination
  raises PermissionError on os.replace.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Allow running as a top-level script from any working directory
# (mirrors reports/management_summary.py line 58)
# ---------------------------------------------------------------------------
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.open_count import open_findings_at

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

# ROOT_DIR: two levels up from this file (data/trend_store.py → data/ → repo root)
ROOT_DIR: Path = Path(__file__).resolve().parent.parent
TREND_DIR: Path = ROOT_DIR / "data" / "trend"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _sanitise_tag_for_filename(
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> str:
    """
    Return a filesystem-safe suffix for the trend JSON filename.

    Spaces, slashes, and any character outside ``[A-Za-z0-9_]`` are replaced
    with underscores.  Leading/trailing underscores are stripped.

    Phase 12 only uses ``tag_filter="all_assets"`` which bypasses this function,
    but the helper is provided here for Phase 13's parameterised case.

    Examples
    --------
    >>> _sanitise_tag_for_filename("Environment", "Production")
    'Environment_Production'
    >>> _sanitise_tag_for_filename(None, None)
    'all_assets'
    """
    if not tag_category or not tag_value:
        return "all_assets"
    combined = f"{tag_category}_{tag_value}"
    sanitised = re.sub(r"[^A-Za-z0-9_]", "_", combined).strip("_")
    return sanitised or "all_assets"


def _load_trend_json(path: Path) -> list[dict]:
    """
    Load snapshot entries from a trend JSON file.

    Returns an empty list if the file does not exist or cannot be parsed.
    Never raises.  Named differently from the MS private helper
    ``_load_trend_history`` to avoid any collision.

    Contract (IN-05): the file root must be a JSON object of the shape
    ``{"snapshots": [...]}``.  Any other shape (a bare list, a scalar, etc.)
    causes ``.get`` to fail and is treated as unparseable — see the corrupt-file
    handling below.

    Corrupt-file handling (IN-02): the caller (``capture_snapshot``) does
    read-modify-write, so returning ``[]`` on a parse failure would let the next
    write OVERWRITE the corrupt file and permanently discard recoverable
    history.  To avoid silent destruction we rename the bad file to
    ``*.corrupt`` (best-effort) before returning ``[]`` and log at ERROR.
    """
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Root must be {"snapshots": [...]}.  A non-dict root (e.g. a bare list)
        # raises AttributeError on .get and is handled as a parse failure below.
        return data.get("snapshots", [])
    except Exception as exc:
        logger.error(
            "Could not parse trend file %s: %s — preserving it as *.corrupt so "
            "accumulated history is not overwritten on the next write",
            path, exc,
        )
        try:
            path.replace(path.with_suffix(path.suffix + ".corrupt"))
        except OSError as rename_exc:
            logger.error(
                "Could not preserve corrupt trend file %s: %s", path, rename_exc
            )
        return []


def _atomic_write_json(path: Path, data: dict) -> None:
    """
    Write *data* to *path* atomically via a temp file + os.replace.

    The temp-file fd is CLOSED by the ``with os.fdopen(...)`` context manager
    BEFORE ``os.replace`` runs.  This ordering is mandatory on Windows:
    an open fd over the destination raises PermissionError on os.replace
    (Gemini MEDIUM review — Windows file-locking concern).

    On any exception the temp file is unlinked (best-effort) and the
    original file is left untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        # Step 1: write + CLOSE the temp fd inside the with-block.
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        # Step 2: atomic rename — OUTSIDE the with-block so fd is already closed.
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup; ignore if temp file is already gone.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _count_by_owner(
    open_df: pd.DataFrame,
    enriched_assets: pd.DataFrame,
) -> dict[str, int]:
    """
    Return {owner_name: open_finding_count} for the open findings set.

    Joins open_df to enriched_assets on asset_uuid to derive owner labels.
    Findings for assets absent from enriched_assets count under "Unassigned".
    Empty open_df returns {}.

    Uses .to_dict() BEFORE any .get() call to avoid calling .get() on a
    pandas Series (Pitfall 3 carried from _count_by_severity).
    """
    if open_df.empty:
        return {}
    # WR-05: dedup before building the map so duplicate asset_uuid rows in
    # enriched_assets do not produce order-dependent (last-wins) attribution.
    # Keep the first row per uuid for deterministic first-row-wins semantics.
    if not enriched_assets.empty and "owner" in enriched_assets.columns:
        ea = enriched_assets.drop_duplicates("asset_uuid")
        uuid_to_owner = dict(zip(ea["asset_uuid"], ea["owner"]))
    else:
        uuid_to_owner = {}
    owner_col = open_df["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
    counts = owner_col.value_counts().to_dict()
    return {str(k): int(v) for k, v in counts.items()}


def _count_by_severity(open_df: pd.DataFrame) -> dict[str, int]:
    """
    Return a dict of {critical, high, medium, low} open-finding counts.

    Uses .to_dict() BEFORE .get() to avoid calling .get() on a pandas Series
    (groupby returns a Series, not a dict — Pitfall 3).  Guarded against an
    empty DataFrame so groupby is never called on zero rows.
    """
    counts = open_df.groupby("severity").size().to_dict() if not open_df.empty else {}
    return {
        "critical": int(counts.get("critical", 0)),
        "high":     int(counts.get("high", 0)),
        "medium":   int(counts.get("medium", 0)),
        "low":      int(counts.get("low", 0)),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def capture_snapshot(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    date: datetime,
    dimension: str = "severity",
    tag_filter: str = "all_assets",
    trend_dir: Optional[Path] = None,
    enriched_assets: Optional[pd.DataFrame] = None,
    on_time_asset_count: Optional[int] = None,
    reopened_count: Optional[int] = None,
    accepted_count: Optional[int] = None,
    recast_count: Optional[int] = None,
    fixed_vulns_df: Optional[pd.DataFrame] = None,
) -> Path:
    """
    Write an atomic monthly snapshot of open-finding counts.

    Parameters
    ----------
    df : pd.DataFrame
        Open+reopened findings (already fetched and date-normalised).
        Must have columns: first_found, last_fixed, resurfaced_date, state, severity.
        IN-06: ``df`` and ``assets_df`` MUST already be filtered to the same tag
        scope by the caller.  This function does no scoping of its own — it
        records open counts from ``df`` and an asset count from ``assets_df``
        verbatim, so a caller that filters one but not the other would silently
        record counts for mismatched scopes with no error.
    assets_df : pd.DataFrame
        In-scope assets (already fetched AND filtered to the same scope as
        ``df`` — see IN-06 above).  Used only for asset_count (D-04).
    date : datetime
        Snapshot reference date.  Month key uses SERVER-LOCAL time
        (``date.strftime("%Y-%m")``); ``generated_at`` uses UTC.

    Concurrency (IN-01)
    -------------------
    SINGLE-WRITER assumption: this function does read-modify-write (load the
    existing snapshot list, mutate, atomic-write) with no lock.  The ``os.replace``
    is atomic but the read-modify-write around it is not, so two concurrent
    captures for the same ``(dimension, tag_filter)`` could lose one update.
    This is safe under the intended once-per-month cron invocation; if concurrent
    invocation ever becomes possible, add a sidecar lockfile.
    dimension : str
        Grouping dimension — ``"severity"`` (default) or ``"owner"``.
    tag_filter : str
        Tag scope label — ``"all_assets"`` for Phase 12; a sanitised
        ``Category_Value`` string for Phase 13.
    trend_dir : Path, optional
        Override the default ``TREND_DIR`` (useful in tests without monkeypatching).
    enriched_assets : pd.DataFrame, optional
        Pre-enriched assets DataFrame with an ``owner`` column (from
        ``extract_owner``).  Required when ``dimension="owner"``; ignored for
        ``dimension="severity"``.  The caller is responsible for pre-enriching
        so this module stays free of ``reports/modules/`` imports (RESEARCH A1).
    on_time_asset_count : int or None, optional
        Count of on-time-scanned licensed assets (Phase-14 D-02 denominator).
        Supplied by the caller from ``count_on_time_assets()``; None when the
        caller does not provide it (backward-compat cold-start, D-15-06).
    reopened_count : int or None, optional
        Count of findings whose state == REOPENED in ``df``. None if not supplied.
    accepted_count : int or None, optional
        Count of findings with severity_modification_type == ACCEPTED. None if not
        supplied.
    recast_count : int or None, optional
        Count of findings with severity_modification_type == RECASTED. None if not
        supplied.
    fixed_vulns_df : pd.DataFrame or None, optional
        Fixed/remediated findings for this snapshot period. Used to derive
        ``fixed_findings_count`` (count where last_fixed month == snapshot month
        AND state == FIXED). None when not available.

    Notes
    -----
    New aggregate fields (D-15-05 / QUAL-05): all six new keys store int or None
    only — never DataFrames, lists, or row-level data.  Existing snapshots that
    lack these keys are valid cold-starts for the new dimensions (D-15-06).

    Returns
    -------
    Path
        The path of the written JSON file.
    """
    trend_dir = trend_dir or TREND_DIR

    # Compute the open subset via the Plan 01 predicate.
    open_df = open_findings_at(df, date)

    # D-04: record the in-scope asset count alongside severity counts.
    asset_count = int(len(assets_df))

    # Timezone policy: month key = local, generated_at = UTC.
    month_str = date.strftime("%Y-%m")  # LOCAL — no tz conversion
    generated_at_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Dimension dispatch — build count_entry dict with appropriate keys.
    if dimension == "severity":
        sev_counts = _count_by_severity(open_df)
        count_entry: dict = {
            "critical": sev_counts["critical"],
            "high":     sev_counts["high"],
            "medium":   sev_counts["medium"],
            "low":      sev_counts["low"],
        }
    elif dimension == "owner":
        if enriched_assets is None:
            raise ValueError(
                "capture_snapshot: enriched_assets is required for dimension='owner'"
            )
        count_entry = _count_by_owner(open_df, enriched_assets)
    else:
        raise ValueError(f"capture_snapshot: unknown dimension {dimension!r}")

    # D-15-05: derive new_findings_count / fixed_findings_count only when
    # fixed_vulns_df is supplied (they form a paired inflow/outflow metric).
    # Both derivations store aggregate ints (or None) — never DataFrames (QUAL-05).
    new_findings_count: Optional[int] = None
    fixed_findings_count: Optional[int] = None
    if fixed_vulns_df is not None:
        if "first_found" in df.columns:
            ff = pd.to_datetime(df["first_found"], utc=True, errors="coerce")
            new_findings_count = int((ff.dt.strftime("%Y-%m") == month_str).sum())
        if not fixed_vulns_df.empty:
            lf = pd.to_datetime(fixed_vulns_df["last_fixed"], utc=True, errors="coerce")
            state_upper = fixed_vulns_df["state"].astype(str).str.upper()
            fixed_findings_count = int(
                ((lf.dt.strftime("%Y-%m") == month_str) & (state_upper == "FIXED")).sum()
            )

    new_entry: dict = {
        "month":               month_str,
        "tag_filter":          tag_filter,
        **count_entry,
        "asset_count":         asset_count,
        "on_time_asset_count": on_time_asset_count,
        "reopened_count":      reopened_count,
        "accepted_count":      accepted_count,
        "recast_count":        recast_count,
        "new_findings_count":  new_findings_count,
        "fixed_findings_count": fixed_findings_count,
        "generated_at":        generated_at_str,
    }

    # Build substrate file path — trend_ prefix distinguishes from management_summary_*.json
    tag_suffix = tag_filter  # Phase 12 passes "all_assets" directly; Phase 13 sanitises upstream
    file_path = trend_dir / f"trend_{dimension}_{tag_suffix}.json"

    # Load existing snapshots, apply (month, tag_filter) idempotent-overwrite.
    snapshots = _load_trend_json(file_path)
    updated = False
    for idx, snap in enumerate(snapshots):
        if snap.get("month") == month_str and snap.get("tag_filter") == tag_filter:
            snapshots[idx] = new_entry
            updated = True
            break
    if not updated:
        snapshots.append(new_entry)

    _atomic_write_json(file_path, {"snapshots": snapshots})
    logger.info(
        "Trend snapshot saved: dimension=%s filter=%s month=%s path=%s",
        dimension, tag_filter, month_str, file_path,
    )
    return file_path


def read_trend(
    dimension: str,
    tag_filter: str = "all_assets",
    months: int = 6,
    trend_dir: Optional[Path] = None,
) -> dict:
    """
    Read the most recent trend snapshots for a given dimension + tag scope.

    Cold-start safe: if the file is missing or has fewer than 2 entries,
    returns ``insufficient_data=True`` without raising.

    Parameters
    ----------
    dimension : str
        Grouping dimension — ``"severity"`` for Phase 12.
    tag_filter : str
        Tag scope label matching what was passed to ``capture_snapshot``.
    months : int
        Maximum number of months to return (most recent, sorted ascending).
    trend_dir : Path, optional
        Override the default ``TREND_DIR`` (useful in tests).

    Returns
    -------
    dict
        ``{"snapshots": list[dict], "insufficient_data": bool}``
        ``insufficient_data`` is ``True`` when fewer than 2 snapshots exist.
    """
    trend_dir = trend_dir or TREND_DIR
    file_path = trend_dir / f"trend_{dimension}_{tag_filter}.json"

    all_snaps = _load_trend_json(file_path)

    # Filter to matching tag_filter, sort ascending by month, take last N.
    # The file is already tag-scoped via its filename (trend_{dim}_{tag_filter}.json),
    # so this filter is redundant in the happy path.  It is retained as a guard
    # but made observable: if entries exist yet none match tag_filter, the
    # filename suffix and the stored tag_filter field have diverged (e.g. a
    # Phase-13 sanitised filename suffix vs. a raw stored value).  Without this
    # log line read_trend would silently report insufficient_data on a fully
    # populated file (WR-05).
    relevant = [s for s in all_snaps if s.get("tag_filter") == tag_filter]
    if all_snaps and not relevant:
        logger.warning(
            "read_trend: %d entries in %s but none match tag_filter=%r "
            "(filename/field mismatch?)",
            len(all_snaps), file_path, tag_filter,
        )
    relevant.sort(key=lambda s: s.get("month", ""))
    recent = relevant[-months:]

    return {
        "snapshots":        recent,
        "insufficient_data": len(recent) < 2,
    }


# ---------------------------------------------------------------------------
# Smoke block — python data/trend_store.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile as _tempfile
    from datetime import timedelta

    _REF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def _ts(days_ago: int | None) -> "pd.Timestamp | type(pd.NaT)":
        if days_ago is None:
            return pd.NaT
        return pd.Timestamp(_REF - timedelta(days=days_ago))

    _data = {
        "state":           ["open",     "fixed",  "reopened", "open"],
        "first_found":     [_ts(30),    _ts(60),  _ts(90),    _ts(1)],
        "last_fixed":      [pd.NaT,     _ts(5),   _ts(20),    pd.NaT],
        "resurfaced_date": [pd.NaT,     pd.NaT,   _ts(10),    pd.NaT],
        "severity":        ["critical", "high",   "medium",   "critical"],
    }
    _df = pd.DataFrame(_data)
    _df = _df.assign(**{
        col: pd.to_datetime(_df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })

    _assets = pd.DataFrame({"asset_uuid": [f"a{i}" for i in range(5)]})

    with _tempfile.TemporaryDirectory() as _tmp:
        _tmp_path = Path(_tmp)

        # First capture
        _path = capture_snapshot(_df, _assets, _REF, trend_dir=_tmp_path)
        print(f"Written to: {_path}")

        _result = read_trend("severity", trend_dir=_tmp_path)
        print(f"Snapshots  : {len(_result['snapshots'])}")
        print(f"insufficient_data: {_result['insufficient_data']}")
        assert _path.exists(), "Snapshot file must exist"
        assert len(_result["snapshots"]) == 1

        # Second capture — same month (idempotent overwrite)
        capture_snapshot(_df, _assets, _REF, trend_dir=_tmp_path)
        _result2 = read_trend("severity", trend_dir=_tmp_path)
        assert len(_result2["snapshots"]) == 1, "Same-month re-run must overwrite, not append"
        print("Idempotent overwrite: OK")

        # Third capture — different month (append)
        _may = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
        capture_snapshot(_df, _assets, _may, trend_dir=_tmp_path)
        _result3 = read_trend("severity", trend_dir=_tmp_path)
        assert len(_result3["snapshots"]) == 2, "Different month must append"
        print("Month append: OK")

        print("Smoke test passed.")
