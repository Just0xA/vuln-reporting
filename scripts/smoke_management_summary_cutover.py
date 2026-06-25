"""
scripts/smoke_management_summary_cutover.py — management_summary structural smoke.

Captures a STRUCTURAL-ONLY snapshot of the v1.4 ``management_summary`` render
path (``ReportComposer`` composing 7 modules, GEN-01 complete) and compares it
against a committed baseline JSON.  No live Tenable API calls are made — the
script runs against today's parquet cache only, enforced via the
``_NoLiveTenable`` sentinel (D-04-06 equivalent for Phase 18).

Current operation (post-cutover, GEN-01 / Plan 18-04):
    Calls ``reports.management_summary.run_report()`` and extracts
    ``result["_bundle"]`` (the ``ReportComposer`` bundle returned by the
    v1.4 modular path).  The bespoke ``compute_all_metrics()`` path no longer
    exists.

QUAL-05 / D-04-08:
    The snapshot contains ONLY aggregate structural counts, sorted identifier
    lists, and boolean flags.  It NEVER contains metric values, hostnames,
    IPv4/IPv6 addresses, plugin names, or any row-level field.  The
    ``management_summary_structural_schema.extract_structural_snapshot`` adapter
    enforces this invariant.

Shared adapter:
    ``tests.baselines.management_summary_structural_schema.extract_structural_snapshot``
    is the sole extraction path so the baseline key schema is stable across
    re-baselines.

Workflow:
    1. Warm the parquet cache (once per dev session):
           python run_all.py --group "<group referencing management_summary>" --no-email
       (writes data/cache/<YYYY-MM-DD>/*.parquet)

    2. Run this script:
           python scripts/smoke_management_summary_cutover.py

    3. First run writes tests/baselines/management_summary_structural_baseline.json
       and exits 0 with "BASELINE INITIALIZED".  Inspect the JSON, commit it.

    4. Subsequent runs diff against the committed baseline:
       - Exit 0: no structural drift
       - Exit 1: structural drift detected — investigate before proceeding
       - Exit 2: no parquet cache found for today — warm the cache first
       - Exit 3: internal error — investigate the traceback

    --rebaseline:
       Overwrites the committed baseline with the current snapshot.  Use ONLY
       when an intentional structural change has been reviewed and approved.
       This is a code-review event — document the reason in the commit message.
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
# Dispatch: call run_report in-process against cached parquet
# ---------------------------------------------------------------------------

def _dispatch_management_summary(cache_dir: Path) -> dict:
    """Call reports.management_summary.run_report() with the sentinel.

    Mirrors run_all.run_group()'s kwarg shape but never imports run_all
    (which sets up a live Tenable client).  The cache is pre-warmed per
    D-04-06; management_summary.run_report reads the parquet via
    data.fetchers, which honors cache-hits without touching tio.

    Plan 04 (post-cutover): returns result["_bundle"] — the ReportComposer
    bundle — so the shared adapter (extract_structural_snapshot) receives the
    composer dict (source_path="_bundle").  The baseline was re-initialized
    via --rebaseline after the cutover commit (review change #5, D-04-05).
    """
    ms = importlib.import_module("reports.management_summary")
    result = ms.run_report(
        _NoLiveTenable(),
        run_id=datetime.now().strftime("%Y-%m-%d"),
        tag_category=None,
        tag_value=None,
        cache_dir=cache_dir,
    )
    # Post-cutover (GEN-01): extract the composer bundle and pass it through
    # the shared adapter so snapshot keys are stable across re-baselines.
    return result["_bundle"]


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

    # Run management_summary (v1.4 ReportComposer path) against cached parquet
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

    # Extract structural snapshot via the SHARED adapter.
    # Plan 04 (post-cutover): _dispatch_management_summary now returns
    # result["_bundle"] (the composer bundle) so source_path="_bundle"
    # and the same adapter keys are used for an apples-to-apples diff.
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
