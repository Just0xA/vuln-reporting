"""
scripts/smoke_management_summary_cutover.py — Phase 18 management_summary cutover smoke.

Captures a STRUCTURAL-ONLY snapshot of the current bespoke management_summary
render path and compares it against a committed baseline JSON.  No live Tenable
API calls are made — the script runs against today's parquet cache only, enforced
via the ``_NoLiveTenable`` sentinel (D-04-06 equivalent for Phase 18).

QUAL-04 constraint:
    This script and the baseline JSON it writes MUST be committed BEFORE any
    migration code is written.  A baseline captured after migration code exists
    is worthless as a regression guard (RESEARCH Pitfall 6, D-18-10 gate 3).

QUAL-05 / D-04-08:
    The snapshot contains ONLY aggregate structural counts, sorted identifier
    lists, and boolean flags.  It NEVER contains metric values, hostnames,
    IPv4/IPv6 addresses, plugin names, or any row-level field.  The
    ``management_summary_structural_schema.extract_structural_snapshot`` adapter
    enforces this invariant.

Shared adapter (review change #5):
    Both this pre-cutover capture (Plan 01) and the post-cutover capture
    (Plan 04) use the SAME shared adapter:
        ``tests.baselines.management_summary_structural_schema.extract_structural_snapshot``
    Plan 04 switches the SOURCE to ``result["_bundle"]`` (the composer bundle)
    but passes it through the SAME adapter, so the snapshot keys are IDENTICAL
    and the diff is apples-to-apples.

Workflow:
    1. Warm the parquet cache (once per dev session):
           python run_all.py --group "<group referencing management_summary>" --no-email
       (writes data/cache/<YYYY-MM-DD>/*.parquet)

    2. Run this script:
           python scripts/smoke_management_summary_cutover.py

    3. First run writes tests/baselines/management_summary_structural_baseline.json
       and exits 0 with "BASELINE INITIALIZED".  Inspect the JSON, commit it.

    4. Subsequent runs diff against the committed baseline:
       - Exit 0: no structural drift — the migration is safe to proceed
       - Exit 1: structural drift detected — investigate before proceeding
       - Exit 2: no parquet cache found for today — warm the cache first
       - Exit 3: internal error — investigate the traceback

    --rebaseline:
       Overwrites the committed baseline with the current snapshot.  Use ONLY
       when an intentional structural change has been reviewed and approved.
       This is a code-review event — document the reason in the commit message.

Plan 04 cutover note:
    After the atomic bespoke-path removal, Plan 04 adapts this script to call
    ``reports.management_summary.run_report()`` and extract
    ``result["_bundle"]`` instead of the bespoke result dict, then passes it
    through the SAME shared adapter.  The baseline JSON is re-initialized once
    post-cutover (--rebaseline) and checked in to mark the new structural norm.
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import sys
import traceback
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.baselines.management_summary_structural_schema import (  # noqa: E402
    extract_structural_snapshot,
)

logger = logging.getLogger(__name__)

BASELINE_FILE = REPO_ROOT / "tests" / "baselines" / "management_summary_structural_baseline.json"


# ---------------------------------------------------------------------------
# _NoLiveTenable sentinel — no live Tenable API calls in this script
# ---------------------------------------------------------------------------

class _NoLiveTenable:
    """Sentinel that raises RuntimeError on any attribute access.

    Passed wherever a TenableIO client is expected.  Per D-04-06 (adapted for
    Phase 18), the smoke script runs against the cached parquet only.  If any
    code path in ``management_summary.run_report`` attempts a live Tenable
    call (``tio.exports``, ``tio.tags``, etc.) the sentinel fires immediately
    with a clear error rather than silently making a network call.
    """

    def __getattr__(self, name: str):
        raise RuntimeError(
            f"_NoLiveTenable: refusing live Tenable call ({name!r}). "
            f"The smoke script must read from data/cache/<today>/ only. "
            f"Warm the cache first:\n"
            f"    python run_all.py --group \"<management_summary group>\" --no-email"
        )


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_today(override: str | None = None) -> Path:
    date_str = override or datetime.now().strftime("%Y-%m-%d")
    return REPO_ROOT / "data" / "cache" / date_str


def _abort_no_cache(cache_dir: Path) -> int:
    msg = (
        f"\n[smoke] Cache not found at {cache_dir}\n"
        f"[smoke] Warm the cache first:\n"
        f"        python run_all.py --group \"<management_summary group>\" --no-email\n"
        f"[smoke] Then re-run this script.\n"
    )
    print(msg, file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------

def _load_baseline(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_baseline(path: Path, snapshot: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _compare_snapshots(actual: dict, baseline: dict) -> list[str]:
    """Return a list of diff lines (empty = no drift)."""
    diffs: list[str] = []
    for k in sorted(baseline.keys()):
        a, b = actual.get(k), baseline[k]
        if a != b:
            diffs.append(f"  {k}: actual={a!r}  baseline={b!r}")
    for k in sorted(set(actual.keys()) - set(baseline.keys())):
        diffs.append(
            f"  {k}: present in actual, missing from baseline "
            f"(schema updated? Update baseline with --rebaseline after review)"
        )
    return diffs


# ---------------------------------------------------------------------------
# Dispatch: call bespoke run_report in-process against cached parquet
# ---------------------------------------------------------------------------

def _dispatch_management_summary(cache_dir: Path) -> dict:
    """Call reports.management_summary.run_report() with the sentinel.

    Mirrors run_all.run_group()'s kwarg shape but never imports run_all
    (which sets up a live Tenable client).  The cache is pre-warmed per
    D-04-06; management_summary.run_report reads the parquet via
    data.fetchers, which honors cache-hits without touching tio.

    Returns the full bespoke run_report() result dict.  The structural
    snapshot adapter (extract_structural_snapshot) accepts this dict
    directly (source_path="bespoke").

    Post-cutover (Plan 04): this function switches to extracting
    ``result["_bundle"]`` and passing it through the SAME adapter.
    The adapter's source_path will then be "_bundle" and the baseline
    must be re-initialized via --rebaseline after the cutover commit.
    """
    ms = importlib.import_module("reports.management_summary")
    result = ms.run_report(
        _NoLiveTenable(),
        run_id=datetime.now().strftime("%Y-%m-%d"),
        tag_category=None,
        tag_value=None,
        cache_dir=cache_dir,
    )
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cache-dir", default=None,
        help="Override today's cache directory (absolute path). "
             "Useful for testing with a known-good cache snapshot.",
    )
    parser.add_argument(
        "--rebaseline", action="store_true",
        help="Overwrite the committed baseline with the current snapshot. "
             "CODE-REVIEW EVENT — document the reason in the commit message.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    # Resolve cache directory
    if args.cache_dir:
        cache_dir = Path(args.cache_dir)
    else:
        cache_dir = _cache_today()

    if not cache_dir.exists() or not any(cache_dir.glob("*.parquet")):
        return _abort_no_cache(cache_dir)

    # Run bespoke management_summary against cached parquet
    print(f"\n=== management_summary smoke ===")
    print(f"[smoke] cache: {cache_dir}")
    try:
        result = _dispatch_management_summary(cache_dir)
    except RuntimeError as exc:
        # Sentinel fired — live API call attempted
        print(f"[smoke] BLOCKED live Tenable call: {exc}", file=sys.stderr)
        return 3
    except Exception:
        print(traceback.format_exc(), file=sys.stderr)
        return 3

    # Extract structural snapshot via the SHARED adapter
    # (Plan 04 calls the SAME adapter on result["_bundle"] instead)
    snapshot = extract_structural_snapshot(result)

    # First-run: write baseline and exit 0
    if not BASELINE_FILE.exists() or args.rebaseline:
        _write_baseline(BASELINE_FILE, snapshot)
        label = "REBASELINED" if args.rebaseline else "BASELINE INITIALIZED"
        print(
            f"[smoke] {label}: {BASELINE_FILE}\n"
            f"[smoke] Review the JSON, then commit it as the pre-migration "
            f"structural baseline (QUAL-04 / D-18-10 gate 3).",
            file=sys.stderr,
        )
        return 0

    # Subsequent run: diff against committed baseline
    baseline = _load_baseline(BASELINE_FILE)
    diffs = _compare_snapshots(snapshot, baseline)

    if not diffs:
        print("[smoke] management_summary: OK (no structural drift)")
        return 0
    else:
        print(
            f"[smoke] management_summary: DRIFT ({len(diffs)} field(s))\n"
            + "\n".join(diffs),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
