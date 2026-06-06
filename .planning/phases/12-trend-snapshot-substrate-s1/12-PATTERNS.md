# Phase 12: Trend Snapshot Substrate (S1) - Pattern Map

**Mapped:** 2026-06-06
**Files analyzed:** 5 new files
**Analogs found:** 5 / 5

---

## File Classification

| New File | Role | Data Flow | Closest Analog | Match Quality |
|----------|------|-----------|----------------|---------------|
| `utils/open_count.py` | utility (pure compute) | transform | `utils/sla_calculator.py` | exact — pure compute, UTC datetime, no I/O, `from __future__ import annotations` header |
| `data/trend_store.py` | service (I/O engine) | file-I/O + transform | `reports/management_summary.py` §§166–250 (`_load_trend_history`, `_save_trend_snapshot`) | role-match — copies JSON shape + idempotent overwrite logic; adds atomic write + `asset_count` |
| `scripts/capture_trend_snapshot.py` | entry point (cron) | request-response | `scripts/warm_cache.py` | exact — same structure, exit codes, logging skeleton, argparse subclass |
| `tests/unit/test_open_count.py` | test (unit) | transform | `tests/content/test_values.py` + `tests/fixtures/builders.py` | role-match — labelled-fixture pattern, `pytestmark = pytest.mark.unit`, hand-built DataFrames |
| `tests/content/test_trend_store.py` | test (content) | file-I/O | `tests/content/test_values.py` | exact — `pytestmark = pytest.mark.content`, `tmp_path` fixture for disk writes |

---

## Pattern Assignments

### `utils/open_count.py` (utility, transform)

**Analog:** `utils/sla_calculator.py`

**Imports pattern** (`utils/sla_calculator.py` lines 1–24):
```python
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import pandas as pd

from config import SLA_DAYS, SEVERITY_ORDER

logger = logging.getLogger(__name__)
```
For `open_count.py`, drop `SLA_DAYS`/`SEVERITY_ORDER`; no `config` import needed. `Optional` not required if using `datetime` directly.

**Module docstring pattern** (`utils/sla_calculator.py` lines 1–13):
```python
"""
utils/sla_calculator.py — SLA status calculation for vulnerability findings.

All SLA logic lives here so every report uses the same definitions.
Import get_sla_status() for per-row calculations, or apply_sla_to_df()
to vectorize across a full vulnerability DataFrame.
...
"""
```
Mirror this docstring style: one-line summary, blank line, usage note.

**Empty-DataFrame guard pattern** (`utils/sla_calculator.py` lines 162–166):
```python
    if df.empty:
        for col in ("remediated", "days_open", ...):
            df[col] = None
        return df
```
`open_findings_at` must return `df.iloc[0:0]` (zero-row copy with same columns) when `df.empty` — never crash on empty input.

**UTC datetime handling pattern** (`utils/sla_calculator.py` lines 66–71, 176):
```python
    if as_of is None:
        as_of = datetime.now(tz=timezone.utc)

    # Ensure first_found is timezone-aware
    if first_found is not None and hasattr(first_found, "tzinfo") and first_found.tzinfo is None:
        first_found = first_found.replace(tzinfo=timezone.utc)
    ...
    as_of_ts = pd.Timestamp(as_of)
```
For `open_findings_at`, the equivalent is:
```python
    D = pd.Timestamp(date, tz="UTC") if getattr(date, "tzinfo", None) is None else pd.Timestamp(date)
```

**Core function — complete predicate** (from RESEARCH.md Code Examples, cross-validated against `management_summary.py` line 120 `_OPEN_STATES = frozenset({"open", "reopened"})`):
```python
def open_findings_at(df: pd.DataFrame, date: datetime) -> pd.DataFrame:
    """
    Return the subset of findings that were open at point-in-time `date`.

    Uses the reopened-aware two-interval model: a REOPENED finding is
    considered fixed only during [last_fixed, resurfaced_date).

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame from fetch_all_vulnerabilities().
        Must have columns: first_found, last_fixed, resurfaced_date, state
        (all date columns normalized to datetime64[ns, UTC] by _normalize_vuln_dates).
    date : datetime
        Point-in-time reference (tz-aware UTC datetime).

    Returns
    -------
    pd.DataFrame
        Filtered to rows that were open at `date`.
    """
    if df.empty:
        return df.iloc[0:0].copy()
    D = pd.Timestamp(date, tz="UTC") if getattr(date, "tzinfo", None) is None else pd.Timestamp(date)
    born = df["first_found"] <= D
    st = df["state"].str.upper()    # normalize casing — API returns lowercase per _OPEN_STATES evidence
    lf = df["last_fixed"]
    rs = df["resurfaced_date"]
    fixed = (
        ((st == "FIXED")    & lf.notna() & (lf <= D)) |
        ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.notna() & (D < rs)) |
        ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.isna())
    )
    return df[born & ~fixed]
```

**`if __name__ == "__main__":` pattern** (`utils/sla_calculator.py` lines 305–328):
```python
if __name__ == "__main__":
    # Quick smoke test
    from datetime import timedelta
    now = datetime.now(tz=timezone.utc)
    ...
```
`open_count.py` must include a `__main__` block per CLAUDE.md convention. A minimal smoke test printing a count against a small synthetic DataFrame is sufficient.

---

### `data/trend_store.py` (service, file-I/O + transform)

**Analog:** `reports/management_summary.py` lines 85–250, 700–764

**TREND_DIR constant** (`management_summary.py` line 89):
```python
TREND_DIR: Path = ROOT_DIR / "data" / "trend"
```
`trend_store.py` must define the same constant. `ROOT_DIR` is derived from `Path(__file__).resolve().parent.parent` (one level up from `data/`).

**Tag sanitiser** (`management_summary.py` lines 128–149) — copy or import for Phase 13 compatibility:
```python
def _sanitise_tag_for_filename(
    tag_category: Optional[str],
    tag_value: Optional[str],
) -> str:
    if not tag_category or not tag_value:
        return "all_assets"
    combined = f"{tag_category}_{tag_value}"
    sanitised = re.sub(r"[^A-Za-z0-9_]", "_", combined).strip("_")
    return sanitised or "all_assets"
```
Substrate file naming: `TREND_DIR / f"trend_{dimension}_{tag_suffix}.json"` — the `trend_` prefix distinguishes substrate files from `management_summary_*.json` files in the same directory.

**Load helper pattern** (`management_summary.py` lines 166–181) — copy this error-handling shape verbatim:
```python
def _load_trend_history(trend_file: Path) -> list[dict]:
    if not trend_file.exists():
        return []
    try:
        with trend_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("snapshots", [])
    except Exception as exc:
        logger.warning("Could not load trend file %s: %s", trend_file, exc)
        return []
```
In `trend_store.py`, name this `_load_trend_json(path)` — same shape, different name to avoid collision with the MS private helper.

**MS write pattern (NON-atomic — DO NOT copy)** (`management_summary.py` lines 244–248):
```python
    # THIS IS THE PATTERN TO IMPROVE UPON — do not replicate:
    with trend_file.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
```

**Atomic write pattern to use instead** (from RESEARCH.md Pattern 3):
```python
import os
import tempfile

def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
```

**Idempotent overwrite pattern** (`management_summary.py` lines 232–240) — copy this logic exactly:
```python
    snapshots: list[dict] = data.get("snapshots", [])
    updated = False
    for idx, snap in enumerate(snapshots):
        if snap.get("month") == month_str and snap.get("tag_filter") == tag_filter_label:
            snapshots[idx] = new_entry
            updated = True
            break
    if not updated:
        snapshots.append(new_entry)
```
Key is the `(month, tag_filter)` tuple. `month_str` uses local time (`datetime.now().strftime("%Y-%m")`); `generated_at` uses UTC (`datetime.now(tz=timezone.utc)`).

**New entry shape** (`management_summary.py` lines 222–230, extended per D-04):
```python
    new_entry: dict = {
        "month":        month_str,           # local calendar month "YYYY-MM"
        "tag_filter":   tag_filter_label,    # "all_assets" for Phase 12
        "critical":     int(sev_counts.get("critical", 0)),
        "high":         int(sev_counts.get("high", 0)),
        "medium":       int(sev_counts.get("medium", 0)),
        "low":          int(sev_counts.get("low", 0)),
        "asset_count":  int(asset_count),    # D-04 addition — absent from MS shape
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),  # UTC
    }
```

**Empty-safe severity count extraction** (from RESEARCH.md Code Examples):
```python
def _count_by_severity(open_df: pd.DataFrame) -> dict[str, int]:
    counts = open_df.groupby("severity").size().to_dict() if not open_df.empty else {}
    return {
        "critical": int(counts.get("critical", 0)),
        "high":     int(counts.get("high", 0)),
        "medium":   int(counts.get("medium", 0)),
        "low":      int(counts.get("low", 0)),
    }
```
Never call `.get()` directly on a Series (groupby returns Series, not dict — `.to_dict()` first).

**Cold-start-safe reader** (`management_summary.py` lines 735–764 — `_compute_metric_7` pattern):
```python
    all_snaps = _load_trend_history(trend_file)
    relevant  = [s for s in all_snaps if s.get("tag_filter") == tag_filter_label]
    relevant.sort(key=lambda s: s.get("month", ""))
    recent = relevant[-6:]

    has_trend        = len(recent) >= 2
    first_run_notice = len(recent) < 2
```
`read_trend()` returns `{"snapshots": recent, "insufficient_data": len(recent) < 2}`. Never raises; returns empty list with `insufficient_data: True` when file missing or < 2 entries.

**`capture_snapshot` function signature** (per D-08/D-09 — parameterized for Phase 13):
```python
def capture_snapshot(
    df: pd.DataFrame,           # open+reopened findings (already fetched)
    assets_df: pd.DataFrame,    # all assets (already fetched)
    date: datetime,             # snapshot reference date (server local for month key)
    dimension: str = "severity",
    tag_filter: str = "all_assets",
) -> Path:
    """Write atomic monthly snapshot. Returns path written."""
```

**`read_trend` function signature**:
```python
def read_trend(
    dimension: str,
    tag_filter: str = "all_assets",
    months: int = 6,
) -> dict:
    """
    Returns:
        snapshots: list[dict]    — up to `months` most recent, sorted ascending
        insufficient_data: bool  — True when fewer than 2 snapshots exist
    """
```

---

### `scripts/capture_trend_snapshot.py` (entry point, request-response)

**Analog:** `scripts/warm_cache.py` — copy structure verbatim, substituting values per the table below.

**Module docstring pattern** (`warm_cache.py` lines 1–21):
```python
#!/usr/bin/env python
"""Warm the Tenable parquet cache for the day so scheduled report runs short-circuit on [CACHE HIT].

Designed to be invoked on a cron schedule...

Flags
-----
--date YYYY-MM-DD   ...
--verbose           ...
--dry-run           ...

Exit codes
----------
0   success or dry-run
2   auth failure (``get_client`` raised ``SystemExit``) or argparse usage error
3   fetcher failed after retries
"""
```
Mirror exactly; substitute script-specific description, flags, and log path.

**Imports pattern** (`warm_cache.py` lines 23–40):
```python
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import CACHE_DIR
from data.fetchers import (
    fetch_all_assets,
    fetch_all_vulnerabilities,
)
from tenable_client import get_client
```
`capture_trend_snapshot.py` adds `from data.trend_store import capture_snapshot`. Drops `fetch_fixed_vulnerabilities` and `fetch_recast_rules` (not needed for Phase 12 per RESEARCH.md Pattern 6).

**Constants pattern** (`warm_cache.py` lines 42–58):
```python
_LOG_PATH = Path("logs") / "warm_cache.log"
_LOGGER_NAME = "warm_cache"
```
Substitute:
```python
_LOG_PATH = Path("logs") / "capture_trend_snapshot.log"
_LOGGER_NAME = "capture_trend_snapshot"
```

**Logging configuration** (`warm_cache.py` lines 65–96) — copy verbatim:
```python
def _configure_logging(verbose: bool) -> logging.Logger:
    _ensure_log_dir()
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = RotatingFileHandler(
        _LOG_PATH, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    root = logging.getLogger()
    if root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)

    logger.propagate = False
    return logger
```

**`_log_to_file_only` / argparse subclass pattern** (`warm_cache.py` lines 99–127) — copy verbatim, substitute `_LOGGER_NAME`:
```python
class _WarmCacheArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        started = datetime.now(tz=timezone.utc).isoformat()
        _log_to_file_only(
            f"Started at {started} UTC; argv={sys.argv}; "
            f"failed because argparse usage error: {message}"
        )
        super().error(message)
```
Rename class to `_SnapshotArgumentParser`.

**Argument type validators** (`warm_cache.py` lines 130–137):
```python
def _date_type(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--date must be YYYY-MM-DD, got {value!r}: {exc}"
        ) from exc
    return value
```
Add a parallel `_month_type` validator for `--month YYYY-MM`:
```python
def _month_type(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--month must be YYYY-MM, got {value!r}: {exc}"
        ) from exc
    return value
```

**Parser builder** (`warm_cache.py` lines 140–166) — add `--month` flag, keep `--date`, `--verbose`, `--dry-run`:
```python
    parser.add_argument(
        "--month",
        type=_month_type,
        default=None,
        help="Snapshot target month (YYYY-MM, server local). Defaults to current month.",
    )
    parser.add_argument(
        "--date",
        type=_date_type,
        default=None,
        help="Cache folder date (YYYY-MM-DD, server local). Defaults to today.",
    )
```

**`_log_started` / `_log_completed`** (`warm_cache.py` lines 169–190) — copy verbatim:
```python
def _log_started(logger: logging.Logger, argv: list[str]) -> datetime:
    start = datetime.now(tz=timezone.utc)
    logger.info("Started at %s UTC; argv=%s", start.isoformat(), argv)
    return start

def _log_completed(logger, start, status, detail=""):
    end = datetime.now(tz=timezone.utc)
    duration = (end - start).total_seconds()
    suffix = f"; detail={detail}" if detail else ""
    logger.info("Completed at %s UTC; duration=%.2fs; status=%s%s",
                end.isoformat(), duration, status, suffix)
```

**`main()` structure** (`warm_cache.py` lines 214–268) — copy the try/except scaffold:
```python
def main(argv=None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
        return code if code != 0 else 0

    logger = _configure_logging(args.verbose)
    start = _log_started(logger, sys.argv)

    target_date_str = args.date or datetime.now().strftime("%Y-%m-%d")
    month_str = args.month or datetime.now().strftime("%Y-%m")
    cache_dir = CACHE_DIR / target_date_str

    if args.dry_run:
        logger.info("DRY RUN: would capture snapshot month=%s cache=%s", month_str, cache_dir)
        _log_completed(logger, start, "dry-run")
        return 0

    cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        tio = get_client()
    except SystemExit as exc:
        logger.error("Auth failure: %s", exc)
        _log_completed(logger, start, "failed", f"auth: {exc}")
        return 2
    except Exception as exc:
        logger.exception("Unexpected error from get_client(): %s", exc)
        _log_completed(logger, start, "failed", f"auth: {exc}")
        return 2

    try:
        df = fetch_all_vulnerabilities(tio, cache_dir)
        assets_df = fetch_all_assets(tio, cache_dir)
    except Exception as exc:
        logger.exception("Fetcher failed: %s", exc)
        _log_completed(logger, start, "failed", f"fetch: {exc}")
        return 3

    try:
        path = capture_snapshot(df, assets_df, datetime.now(), "severity", "all_assets")
        logger.info("Snapshot written: %s", path)
    except Exception as exc:
        logger.exception("capture_snapshot failed: %s", exc)
        _log_completed(logger, start, "failed", f"snapshot: {exc}")
        return 3

    _log_completed(logger, start, "success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

### `tests/unit/test_open_count.py` (test, unit)

**Analog:** `tests/content/test_values.py` + `tests/fixtures/builders.py`

**File header and marker** (`tests/unit/test_modules.py` lines 1–14, `tests/content/test_values.py` lines 1–15):
```python
"""
tests/unit/test_open_count.py — Layer 1 predicate correctness for open_findings_at.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from utils.open_count import open_findings_at

pytestmark = pytest.mark.unit
```

**Labelled-fixture builder pattern** (`tests/fixtures/builders.py` lines 32–64):
```python
# Fixed reference point — deterministic regardless of wall clock
_REF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

def _finding(state: str, first_found_days_ago: int,
             last_fixed_days_ago=None, resurfaced_days_ago=None) -> dict:
    """One finding row with normalized datetime64[ns, UTC] columns."""
    ff = _REF - timedelta(days=first_found_days_ago)
    lf = (_REF - timedelta(days=last_fixed_days_ago)) if last_fixed_days_ago is not None else None
    rs = (_REF - timedelta(days=resurfaced_days_ago)) if resurfaced_days_ago is not None else None
    return {
        "first_found":     ff,
        "last_fixed":      lf,
        "resurfaced_date": rs,
        "state":           state,
        "severity":        "critical",
    }

def _df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for col in ("first_found", "last_fixed", "resurfaced_date"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df
```

**Test cases to cover** (TREND-01 requirement — OPEN / REOPENED / FIXED labelled cases):
```python
def test_open_state_included():
    """A plain OPEN finding born before D is open at D."""
    df = _df([_finding("open", first_found_days_ago=10)])
    result = open_findings_at(df, _REF)
    assert len(result) == 1

def test_fixed_state_excluded():
    """A FIXED finding (last_fixed <= D) is not open at D."""
    df = _df([_finding("fixed", first_found_days_ago=10, last_fixed_days_ago=5)])
    result = open_findings_at(df, _REF)
    assert len(result) == 0

def test_reopened_state_included():
    """REOPENED finding is open at D when D >= resurfaced_date."""
    df = _df([_finding("reopened", first_found_days_ago=20,
                        last_fixed_days_ago=10, resurfaced_days_ago=3)])
    result = open_findings_at(df, _REF)
    assert len(result) == 1

def test_reopened_in_gap_excluded():
    """REOPENED finding is closed (in gap) when last_fixed <= D < resurfaced_date."""
    # last_fixed 5 days ago, resurfaced 2 days in the future
    df = _df([_finding("reopened", first_found_days_ago=20,
                        last_fixed_days_ago=5, resurfaced_days_ago=-2)])
    result = open_findings_at(df, _REF)
    assert len(result) == 0

def test_empty_dataframe_returns_empty():
    """Empty input must not raise."""
    df = _df([]).reindex(columns=["first_found","last_fixed","resurfaced_date","state","severity"])
    result = open_findings_at(df, _REF)
    assert result.empty
```

---

### `tests/content/test_trend_store.py` (test, file-I/O)

**Analog:** `tests/content/test_values.py`

**File header and marker**:
```python
"""
tests/content/test_trend_store.py — Layer 2 snapshot write/read/idempotency/PII/cold-start.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from data.trend_store import capture_snapshot, read_trend

pytestmark = pytest.mark.content
```

**`tmp_path` fixture for disk tests** — use pytest's built-in `tmp_path`; monkeypatch `TREND_DIR` or pass the path directly via a `trend_dir` parameter on `capture_snapshot`. The cleanest approach (avoids monkeypatching a module-level constant) is to make `capture_snapshot` accept an optional `trend_dir: Path = None` parameter that defaults to the module constant but can be overridden in tests:
```python
def test_capture_writes_file(tmp_path):
    df = _open_df(n=5)
    assets_df = _assets_df(n=10)
    path = capture_snapshot(df, assets_df, datetime(2026, 6, 1), "severity",
                            "all_assets", trend_dir=tmp_path)
    assert path.exists()
    import json
    data = json.loads(path.read_text())
    assert "snapshots" in data
    assert len(data["snapshots"]) == 1
```

**PII absence check** (TREND-06):
```python
_PII_FIELDS = {"hostname", "ipv4", "fqdn", "asset_uuid", "plugin_name", "plugin_id"}

def test_no_pii_in_snapshot(tmp_path):
    df = _open_df(n=5)
    assets_df = _assets_df(n=10)
    path = capture_snapshot(df, assets_df, datetime(2026, 6, 1), "severity",
                            "all_assets", trend_dir=tmp_path)
    import json
    text = path.read_text()
    for field in _PII_FIELDS:
        assert field not in text, f"PII field {field!r} found in snapshot file"
```

**Idempotency test** (TREND-05):
```python
def test_idempotent_overwrite(tmp_path):
    df = _open_df(n=5)
    assets_df = _assets_df(n=3)
    ref = datetime(2026, 6, 1)
    capture_snapshot(df, assets_df, ref, "severity", "all_assets", trend_dir=tmp_path)
    capture_snapshot(df, assets_df, ref, "severity", "all_assets", trend_dir=tmp_path)
    import json
    data = json.loads((tmp_path / "trend_severity_all_assets.json").read_text())
    assert len(data["snapshots"]) == 1   # second run overwrites, not appends
```

**Cold-start test** (TREND-04):
```python
def test_cold_start_read(tmp_path):
    result = read_trend("severity", "all_assets", trend_dir=tmp_path)
    assert result["snapshots"] == []
    assert result["insufficient_data"] is True
```

**MS file untouched test** (TREND-03):
```python
def test_ms_file_untouched(tmp_path):
    import json
    ms_file = tmp_path / "management_summary_all_assets.json"
    ms_file.write_text(json.dumps({"snapshots": [{"month": "2026-05", "tag_filter": "all_assets",
                                                   "critical": 10, "high": 5, "medium": 2, "low": 1,
                                                   "generated_at": "2026-05-01T00:00:00Z"}]}))
    original_mtime = ms_file.stat().st_mtime

    df = _open_df(n=3)
    assets_df = _assets_df(n=2)
    capture_snapshot(df, assets_df, datetime(2026, 6, 1), "severity",
                     "all_assets", trend_dir=tmp_path)
    assert ms_file.stat().st_mtime == original_mtime, "MS file must not be modified"
```

**Minimal fixture helpers for content tests**:
```python
# Mirror builders.py pattern — hand-built rows, known counts
def _open_df(n: int = 5) -> pd.DataFrame:
    """n open findings, all severity='critical', state='open'."""
    rows = [{"first_found": datetime(2026, 5, 1, tzinfo=timezone.utc),
             "last_fixed": None, "resurfaced_date": None,
             "state": "open", "severity": "critical"} for _ in range(n)]
    df = pd.DataFrame(rows)
    for col in ("first_found", "last_fixed", "resurfaced_date"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df

def _assets_df(n: int = 10) -> pd.DataFrame:
    return pd.DataFrame({"asset_uuid": [f"a{i}" for i in range(n)]})
```

---

## Shared Patterns

### UTC vs. Local Time (timezone policy)

**Source:** `utils/sla_calculator.py` lines 66–67, `scripts/warm_cache.py` line 227, `management_summary.py` line 229
**Apply to:** All five new files

Two distinct uses — apply the right one per use:
```python
# UTC — for generated_at (report timestamp)
generated_at = datetime.now(tz=timezone.utc)
entry["generated_at"] = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")

# Local — for month key and cache folder (schedule-matching keys)
month_str = datetime.now().strftime("%Y-%m")           # no tz=timezone.utc
target_date_str = args.date or datetime.now().strftime("%Y-%m-%d")  # no tz=timezone.utc
```

### `from __future__ import annotations`

**Source:** Every existing module in `utils/`, `scripts/`, `tests/`
**Apply to:** All five new files — first line after the module docstring.

### `logger = logging.getLogger(__name__)`

**Source:** `utils/sla_calculator.py` line 25, `reports/management_summary.py` line 102
**Apply to:** `utils/open_count.py`, `data/trend_store.py`

Module-level logger; no `logging.basicConfig` in library modules (only in entry points and `management_summary.py` which is a script-level module).

### `if __name__ == "__main__":` block

**Source:** `utils/sla_calculator.py` lines 305–328, `scripts/warm_cache.py` line 271
**Apply to:** `utils/open_count.py` (smoke test), `scripts/capture_trend_snapshot.py` (`sys.exit(main())`)
**Required by CLAUDE.md** — every script must include this.

### Empty-DataFrame guard

**Source:** `utils/sla_calculator.py` lines 162–166
**Apply to:** `utils/open_count.py` (`return df.iloc[0:0].copy()`), `data/trend_store.py` (`_count_by_severity` uses `.empty` check before `groupby`)
```python
# In capture_snapshot — graceful on zero-row df
if df.empty:
    open_df = df.iloc[0:0].copy()
else:
    open_df = open_findings_at(df, date)
```

### `pytestmark` per test layer

**Source:** `tests/unit/test_modules.py` line 14, `tests/content/test_values.py` line 15
**Apply to:** Both test files
```python
pytestmark = pytest.mark.unit     # for tests/unit/test_open_count.py
pytestmark = pytest.mark.content  # for tests/content/test_trend_store.py
```

### `.to_dict()` before `.get()` on groupby result

**Source:** RESEARCH.md Pitfall 3 + Code Examples
**Apply to:** `data/trend_store.py` `_count_by_severity`
```python
counts = open_df.groupby("severity").size().to_dict() if not open_df.empty else {}
int(counts.get("critical", 0))   # safe; Series.get() raises AttributeError
```

---

## No Analog Found

None — all five files have clear analogs in the codebase.

---

## Planner Decision Points Flagged

| # | File | Decision Needed | Recommendation |
|---|------|----------------|----------------|
| P1 | `utils/open_count.py` | State column casing: `st == "FIXED"` or `st.str.upper() == "FIXED"`? | Use `.str.upper()` — MS `_OPEN_STATES` uses lowercase, suggesting API returns lowercase; `.str.upper()` is casing-safe |
| P2 | `data/trend_store.py` | Should `capture_snapshot` and `read_trend` accept `trend_dir: Path = None` for testability? | Yes — avoids monkeypatching module constant in content tests; defaults to module-level `TREND_DIR` |
| P3 | `scripts/capture_trend_snapshot.py` | Single `--date YYYY-MM-DD` (infer month) or separate `--month YYYY-MM` + `--date`? | Two flags — `--month` for snapshot target, `--date` for cache folder; mirrors `warm_cache.py` `--date` vocabulary |

---

## Metadata

**Analog search scope:** `utils/`, `scripts/`, `tests/unit/`, `tests/content/`, `tests/fixtures/`, `reports/management_summary.py`
**Files read:** `utils/sla_calculator.py`, `scripts/warm_cache.py`, `reports/management_summary.py` (lines 85–250, 695–764), `tests/unit/test_modules.py`, `tests/content/test_values.py`, `tests/conftest.py`, `tests/fixtures/builders.py`, `pytest.ini`
**Pattern extraction date:** 2026-06-06
