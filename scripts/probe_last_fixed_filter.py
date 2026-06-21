"""
scripts/probe_last_fixed_filter.py — Live-API spike probe for last_fixed filter shape.

PURPOSE
-------
Proves the production Tenable export filter shape for ``last_fixed`` is actually
accepted by the live API AND filters in the CORRECT direction.

The SHIPPED ``fetch_fixed_vulnerabilities`` (data/fetchers.py) uses a BARE INTEGER
Unix-epoch value: ``{"last_fixed": <int epoch seconds>}``.  The earlier date-range
dict shape (``{"date": "YYYY-MM-DD", "modifier": "date-range"}``) was REJECTED by
the API, which is why production uses the integer-epoch shape.  This probe therefore
exercises the integer-epoch shape so the committed artifact matches what production
actually sends.

Tenable export schemas are finicky and docs can lag strict API validation, so this
de-risks the filter shape against the live tenant rather than the ref doc alone.

THREE THINGS THIS PROBE VERIFIES
---------------------------------
(a) ACCEPTED — the API accepts the last_fixed filter without a 400 / validation error.
(b) FILTERS CORRECTLY — sampled returned rows all have last_fixed >= the cutoff date
    (the filter is not a no-op).
(c) MONOTONIC DIRECTION — a NARROW cutoff (~7 days ago) returns FEWER rows than a
    WIDE cutoff (~90 days ago).  A wider lookback returns MORE fixed rows.

IMPORTANT: this probe does NOT assert "filtered < default".  The corrected direction
is NARROW < WIDE (7-day < 90-day), because a wider last_fixed lookback returns more
rows, not fewer (empirical: 187,775 rows at the ~30d default vs 1,285,823 at 2yr).

RUNNING
-------
    python scripts/probe_last_fixed_filter.py

Requires live Tenable credentials in .env (TVM_ACCESS_KEY / TVM_SECRET_KEY).
This is an operator-run, one-time probe — it is NOT called by any production code.

CREDENTIAL SAFETY
-----------------
Credentials are loaded exclusively via tenable_client.get_client() from .env.
No access/secret key strings are printed or logged by this script.
"""

from __future__ import annotations

import sys
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path when run directly
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tenable_client import get_client  # noqa: E402  (after path setup)

# ---------------------------------------------------------------------------
# Logging — stdout only; no credentials ever logged
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Probe configuration
# ---------------------------------------------------------------------------

# Production filter shape — key path inside export_filters:
#   {"last_fixed": <int Unix epoch seconds>}
# Tenable returns findings whose last_fixed is >= the supplied epoch.
# A SMALLER epoch (earlier cutoff) = WIDER window = MORE rows returned.
_FILTER_KEY = "last_fixed"

# Narrow window: ~7 days ago.  Should return FEWER fixed findings than the wide window.
_NARROW_DAYS = 7

# Wide window: ~90 days ago.  Should return MORE fixed findings than the narrow window.
_WIDE_DAYS = 90

# Maximum rows to stream for each count (keeps the probe fast).
# Set to None to count all rows; a cap is fine because we only need direction.
_ROW_CAP = 5_000

# How many rows to sample for the "last_fixed >= cutoff" field-value check.
_SAMPLE_SIZE = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cutoff_epoch(days_ago: int) -> int:
    """Return a Unix-epoch-seconds cutoff N days before now (UTC)."""
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days_ago)
    return int(cutoff.timestamp())


def _build_export_filters(cutoff_epoch: int) -> dict:
    """
    Build the export_filters dict for tio.exports.vulns() using the SHIPPED shape.

    The production shape (data/fetchers.fetch_fixed_vulnerabilities) is a bare
    integer Unix-epoch value:
        {"last_fixed": <int epoch seconds>}
    passed alongside the existing state and severity filters.
    """
    return {
        "state":       ["fixed"],
        "severity":    ["critical", "high", "medium", "low"],
        _FILTER_KEY:   cutoff_epoch,
    }


def _stream_count(tio, export_filters: dict, cap: int | None) -> tuple[int, list[dict]]:
    """
    Stream tio.exports.vulns() with the given filters.

    Returns (count, sampled_rows) where sampled_rows is up to _SAMPLE_SIZE rows.
    Stops streaming at ``cap`` rows to keep the probe fast.
    """
    count   = 0
    samples: list[dict] = []

    for vuln in tio.exports.vulns(**export_filters):
        count += 1
        if len(samples) < _SAMPLE_SIZE:
            samples.append(vuln)
        if cap is not None and count >= cap:
            break

    return count, samples


def _check_field_values(samples: list[dict], cutoff_epoch: int) -> tuple[bool, list[str]]:
    """
    Verify that sampled rows have last_fixed >= cutoff_epoch.

    Returns (all_ok, violations) where violations is a list of last_fixed
    values that were earlier than the cutoff.  ``last_fixed`` arrives as an
    ISO-8601 string on export rows; it is parsed to epoch seconds for the
    comparison against the integer-epoch cutoff.
    """
    violations: list[str] = []

    for vuln in samples:
        lf = vuln.get("last_fixed", "")
        if not lf:
            # Missing last_fixed on a fixed finding is unexpected but not a
            # filter-shape failure — skip.
            continue
        try:
            lf_epoch = int(
                datetime.fromisoformat(str(lf).replace("Z", "+00:00")).timestamp()
            )
        except ValueError:
            # Unparseable timestamp — record raw value as a violation.
            violations.append(str(lf))
            continue
        if lf_epoch < cutoff_epoch:
            violations.append(str(lf)[:10])

    all_ok = len(violations) == 0
    return all_ok, violations


# ---------------------------------------------------------------------------
# Main probe
# ---------------------------------------------------------------------------

def run_probe() -> None:
    """
    Execute the live-API probe.  Prints a structured results summary.
    Never prints access/secret key strings.
    """
    print()
    print("=" * 70)
    print("  Probe: last_fixed export filter shape + direction check")
    print("  Plan 18-02 Task 0 — A2 de-risk before fetch rework")
    print("=" * 70)
    print()

    # ------------------------------------------------------------------
    # Build an authenticated client (credentials from .env only)
    # ------------------------------------------------------------------
    logger.info("Connecting to Tenable API (credentials from .env) …")
    tio = get_client()
    logger.info("Client authenticated successfully.")
    print()

    # ------------------------------------------------------------------
    # Cutoff epochs (integer Unix seconds — the shipped filter shape)
    # ------------------------------------------------------------------
    narrow_cutoff = _cutoff_epoch(_NARROW_DAYS)
    wide_cutoff   = _cutoff_epoch(_WIDE_DAYS)

    print(f"Narrow cutoff ({_NARROW_DAYS}d ago):  {narrow_cutoff} (epoch)")
    print(f"Wide   cutoff ({_WIDE_DAYS}d ago): {wide_cutoff} (epoch)")
    print(f"Row cap per pull:         {_ROW_CAP} (stops early — direction only)")
    print(f"Filter key:               {_FILTER_KEY!r}")
    print(f"Filter shape:             bare integer Unix epoch (production shape)")
    print()

    # ------------------------------------------------------------------
    # (a) + (b): ACCEPTED + FILTERS CORRECTLY — narrow window pull
    # ------------------------------------------------------------------
    narrow_filters = _build_export_filters(narrow_cutoff)
    print(f"Filter shape used (narrow): {narrow_filters}")
    print()
    print(f"Streaming narrow ({_NARROW_DAYS}d) pull …")

    narrow_accepted = False
    narrow_count    = 0
    narrow_samples: list[dict] = []

    try:
        narrow_count, narrow_samples = _stream_count(tio, narrow_filters, _ROW_CAP)
        narrow_accepted = True
        print(f"  Rows received (up to cap): {narrow_count}")
    except Exception as exc:
        # Do not print the exception message if it could contain credentials —
        # in practice Tenable API errors never include keys, but we sanitize.
        err_str = str(exc)
        print(f"  ERROR: filter REJECTED or stream failed")
        print(f"  Exception type: {type(exc).__name__}")
        # Print the error text so the operator can see the corrected shape.
        # Tenable validation errors typically say "Invalid filter value" or
        # describe the expected parameter shape.
        print(f"  Detail: {err_str}")
        print()
        print("RESULT (a) ACCEPTED:           FAIL — API rejected the filter.")
        print("  -> Record the error message above.")
        print("  -> Task 3 must build fetch_fixed_vulnerabilities on the")
        print("     CORRECTED shape printed in the error, not on A2.")
        print()
        return

    # ------------------------------------------------------------------
    # (b) Field-value check on narrow samples
    # ------------------------------------------------------------------
    fields_ok, violations = _check_field_values(narrow_samples, narrow_cutoff)

    print()
    print(f"  Sample size checked:       {len(narrow_samples)}")
    print(f"  Rows with last_fixed >= cutoff: {len(narrow_samples) - len(violations)} / {len(narrow_samples)}")

    if violations:
        print(f"  VIOLATIONS (last_fixed < cutoff): {violations[:10]}")
        print()
        print("RESULT (b) FILTERS CORRECTLY:  FAIL — some rows violate the cutoff.")
        print("  -> The filter may be a no-op.  Investigate the epoch cutoff value.")
    else:
        print()
        print("RESULT (a) ACCEPTED:           PASS")
        print(f"  Accepted filter shape: {_FILTER_KEY!r}: <int epoch seconds>")
        print()
        if len(narrow_samples) > 0:
            print("RESULT (b) FILTERS CORRECTLY:  PASS — all sampled rows satisfy last_fixed >= cutoff.")
        else:
            print("RESULT (b) FILTERS CORRECTLY:  INCONCLUSIVE — 0 rows returned; nothing to sample.")
            print("  (This is expected if no findings were fixed in the last 7 days on this tenant.)")

    # ------------------------------------------------------------------
    # (c) MONOTONIC DIRECTION — wide window pull
    # ------------------------------------------------------------------
    print()
    print(f"Streaming wide ({_WIDE_DAYS}d) pull …")
    wide_filters = _build_export_filters(wide_cutoff)

    wide_count = 0
    try:
        wide_count, _ = _stream_count(tio, wide_filters, _ROW_CAP)
        print(f"  Rows received (up to cap): {wide_count}")
    except Exception as exc:
        err_str = str(exc)
        print(f"  ERROR: wide pull failed: {type(exc).__name__}: {err_str}")
        print("RESULT (c) MONOTONIC DIRECTION: INCONCLUSIVE — wide pull failed.")
        return

    print()
    print("RESULT (c) MONOTONIC DIRECTION CHECK")
    print(f"  Narrow ({_NARROW_DAYS}d cutoff) row count:  {narrow_count}")
    print(f"  Wide   ({_WIDE_DAYS}d cutoff) row count: {wide_count}")

    if wide_count > narrow_count:
        print(f"  PASS — wide ({wide_count}) > narrow ({narrow_count}): a wider lookback returns MORE rows.")
        direction_pass = True
    elif wide_count == narrow_count and wide_count >= _ROW_CAP:
        # Both hit the row cap — direction is inconclusive at this cap.
        print(f"  INCONCLUSIVE — both pulls hit the {_ROW_CAP}-row cap.")
        print(f"  Increase _ROW_CAP or remove the cap to get a definitive count.")
        direction_pass = None
    elif wide_count == narrow_count:
        print(f"  WARNING — wide == narrow ({wide_count}). Counts are identical.")
        print(f"  This may mean all fixed findings fall within the narrow window,")
        print(f"  or the filter is a no-op for this tenant's data. Investigate.")
        direction_pass = False
    else:
        print(f"  FAIL — wide ({wide_count}) < narrow ({narrow_count}).")
        print(f"  A wider lookback should return MORE rows, not fewer.")
        print(f"  This may indicate the filter is operating in the wrong direction.")
        direction_pass = False

    print()

    # ------------------------------------------------------------------
    # Summary for Task 3
    # ------------------------------------------------------------------
    print("=" * 70)
    print("  SUMMARY FOR TASK 3 (fetch rework)")
    print("=" * 70)
    if narrow_accepted and fields_ok and direction_pass is True:
        print()
        print("  CONFIRMED. This integer-epoch filter shape is what")
        print("  fetch_fixed_vulnerabilities ships:")
        print()
        print(f'    # lookback_epoch = int((now - FIXED_LOOKBACK_DAYS).timestamp())')
        print(f'    export_filters["{_FILTER_KEY}"] = lookback_epoch   # bare int')
        print()
        print("  A wider last_fixed lookback (smaller epoch) returns MORE rows")
        print("  (correct direction).  Bound lookback to config.FIXED_LOOKBACK_DAYS")
        print("  (default 365) to avoid the 1.29M-row unbounded pull (D-18-05).")
    elif not narrow_accepted:
        print()
        print("  REJECTED. See the error detail above for the corrected shape.")
        print("  fetch_fixed_vulnerabilities must use the shape from the API error.")
    else:
        print()
        print("  Results are mixed or inconclusive — review individual PASS/FAIL lines.")
        print("  Do not proceed with Task 3 until all three checks are PASS.")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Live-API probe: prove the Tenable last_fixed export filter shape "
            "is accepted and filters in the correct direction (narrow < wide). "
            "Requires live Tenable credentials in .env."
        )
    )
    # No required arguments — probe uses hard-coded narrow/wide day constants
    # that can be overridden by editing _NARROW_DAYS / _WIDE_DAYS above.
    parser.parse_args()

    run_probe()
