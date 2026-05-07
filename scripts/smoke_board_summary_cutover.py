"""
scripts/smoke_board_summary_cutover.py — Phase 4 BOARD-08 cutover smoke.

Runs all three Phase-4 test groups (per Plan 04-03) against today's parquet
cache (per D-04-06 — never live API; enforced via _NoLiveTenable sentinel),
extracts STRUCTURAL-ONLY snapshots via tests/baseline_utils, and diffs
against tests/baselines/<group_slug>.json.

REVISED D-04-05 (2026-05-07): snapshots contain NO metric values (which
drift daily with vulnerability churn) and NO row-level data. There is NO
--update-baseline flag — baselines change ONLY when CODE intentionally
changes the structure (rare, code-review event, documented in commit
message). Initial capture is implicit on first run: if a baseline file
does not exist, the script writes it AND exits 0 with a 'BASELINE
INITIALIZED' banner.

D-04-08: --unredacted controls error-output redaction in DIFF lines, NOT
the snapshot itself (the snapshot is structural and contains no row-level
data either way). LOCAL-ONLY: do not paste --unredacted output into a PR
description, chat, or shared document.

Workflow:
  1. Once per dev session, warm the cache:
       python run_all.py --group "Test Pull" --no-email
     (writes data/cache/<YYYY-MM-DD>/*.parquet)

  2. Run this script (subsequent runs are <5s, no Tenable API calls):
       python scripts/smoke_board_summary_cutover.py

  3. First run for a new group writes the baseline JSON automatically
     and exits 0 with 'BASELINE INITIALIZED for <group>: <file>'.
     Inspect the JSON, commit it.

Exit codes:
  0  All groups match their baselines (or first-run capture wrote a new one).
  1  At least one group drifted (structural change since baseline was committed).
  2  No cache exists for today. Cache-warm message printed.
  3  Internal error (uncaught exception) — investigate.
"""
from __future__ import annotations

import argparse
import importlib
import logging
import re
import sys
import traceback
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from tests.baseline_utils import (              # noqa: E402
    extract_structural_snapshot,
    compare_snapshots,
    load_baseline,
    write_baseline,
)

logger = logging.getLogger(__name__)

GROUP_SLUGS: dict[str, str] = {
    "Test Pull":               "test_pull",
    "Test Pull — Analyst Off": "test_pull_analyst_off",
    "Test Pull — Zero Match":  "test_pull_zero_match",
}

BASELINE_DIR = REPO_ROOT / "tests" / "baselines"


# --- D-04-06 hard guard: no live Tenable calls --------------------------

class _NoLiveTenable:
    """Sentinel passed wherever a TenableIO client is expected.

    Per D-04-06 the smoke script runs against the cached parquet only.
    Any attempt to call into the live API raises RuntimeError. This is
    BELT-AND-BRACES protection: if a future code path under board_summary
    tries to fall back to a live fetch when the cache is "stale", the
    sentinel will surface that immediately rather than silently making
    a network call.

    Cache-edge case: if the cache file path doesn't match the fetcher's
    expected pattern (e.g. cache-date mismatch, partial parquet write),
    the sentinel will fire mid-run with a clear traceback rather than
    silently making a live API call. This is intentional — fail-loud
    beats fail-silent — but operators should warm the cache via
    `python run_all.py --group 'Test Pull' --no-email` BEFORE running
    the smoke script.
    """

    def __getattr__(self, name: str):
        raise RuntimeError(
            f"_NoLiveTenable: refusing live Tenable call ({name!r}). "
            f"The smoke script must read from data/cache/<today>/ only."
        )


# --- Cache check (D-04-06) ---------------------------------------------

def _cache_today(override: str | None = None) -> Path:
    date_str = override or datetime.now().strftime("%Y-%m-%d")
    return REPO_ROOT / "data" / "cache" / date_str


def _abort_no_cache(cache_dir: Path) -> int:
    msg = (
        f"\n[smoke] cache not found at {cache_dir}\n"
        f"[smoke] warm the cache once:\n"
        f"        python run_all.py --group \"Test Pull\" --no-email\n"
        f"[smoke] then re-run this script.\n"
    )
    print(msg, file=sys.stderr)
    return 2


# --- Config load (minimal; never imports run_all.run_group) -------------

def _load_groups() -> list[dict]:
    cfg_path = REPO_ROOT / "delivery_config.yaml"
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    return raw.get("groups", []) if isinstance(raw, dict) else []


# --- Dispatcher: re-runs board_summary against cache only --------------

def _dispatch_board_summary(group_config: dict, *, cache_dir: Path) -> dict:
    """Call reports.board_summary.run_report directly with the sentinel.

    Mirrors run_all.run_group()'s slug-specific kwarg shape but never
    imports run_all (which sets up a live Tenable client). The cache is
    pre-warmed per D-04-06; board_summary.run_report reads the parquet
    via data.fetchers, which honors cache-hits without touching tio.

    Returns the bundle dict (result['_bundle']) — guaranteed present
    after Plan 04-02 Task 4 ships the private '_bundle' return-dict key.
    Raises RuntimeError if the key is missing (regression detector —
    points operator at Plan 04-02 Task 4).
    """
    bs = importlib.import_module("reports.board_summary")
    filters = group_config.get("filters") or {}
    result = bs.run_report(
        _NoLiveTenable(),
        run_id=datetime.now().strftime("%Y-%m-%d"),
        tag_category=filters.get("tag_category"),
        tag_value=filters.get("tag_value"),
        cache_dir=cache_dir,
        analyst_detail=group_config.get("analyst_detail", True),
    )
    bundle = result.get("_bundle")
    if bundle is None:
        raise RuntimeError(
            "board_summary.run_report did not return a '_bundle' key. "
            "Did Plan 04-02 Task 4 (composer bundle forward) ship? "
            "Re-run with the latest main; if the key is intentionally "
            "removed, update scripts/smoke_board_summary_cutover.py "
            "AND tests/baseline_utils.py to use a different path to "
            "the in-memory composer bundle."
        )
    return bundle


# --- Diff redaction (error-output only — snapshot is metrics-free) -----

_REDACT_PATTERNS = (
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),                  # IPv4
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
)


def _redact_line(line: str, *, mode: str) -> str:
    if mode == "unredacted":
        return line
    out = line
    for pat in _REDACT_PATTERNS:
        out = pat.sub("<redacted>", out)
    return out


# --- Main ---------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--group", default=None,
        help="Run only one group (by name).",
    )
    parser.add_argument(
        "--cache-date", default=None,
        help="Override today's cache date (YYYY-MM-DD). For local debugging.",
    )
    parser.add_argument(
        "--unredacted", action="store_true",
        help="Show raw values in error/diagnostic output. LOCAL-ONLY — "
             "the snapshot itself is structural and contains no row-level "
             "data either way; this flag controls only error-output verbosity.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    if args.unredacted:
        print(
            "WARNING: --unredacted is for local terminal use only. Do not "
            "paste, screenshot, or commit any output of this run.",
            file=sys.stderr,
        )

    cache_dir = _cache_today(args.cache_date)
    if not cache_dir.exists() or not any(cache_dir.glob("*.parquet")):
        return _abort_no_cache(cache_dir)

    groups = _load_groups()
    if not groups:
        print(
            "[smoke] _load_groups returned empty — config validation failed. "
            "Run `python run_all.py --dry-run` for details.",
            file=sys.stderr,
        )
        return 3

    overall_drift = False
    redact_mode = "unredacted" if args.unredacted else "default"

    for group in groups:
        name = group.get("name")
        if args.group and name != args.group:
            continue
        slug = GROUP_SLUGS.get(name)
        if slug is None:
            continue   # group not part of Phase-4 cutover

        baseline_file = BASELINE_DIR / f"board_summary_{slug}.json"
        print(f"\n=== {name} -> {baseline_file.name} ===")

        try:
            bundle = _dispatch_board_summary(group, cache_dir=cache_dir)
        except Exception:
            redacted_tb = _redact_line(traceback.format_exc(), mode=redact_mode)
            print(redacted_tb, file=sys.stderr)
            return 3

        snapshot = extract_structural_snapshot(bundle, slug)

        if not baseline_file.exists():
            write_baseline(baseline_file, snapshot)
            print(
                f"[smoke] BASELINE INITIALIZED for {name}: "
                f"{baseline_file} — review and commit.",
                file=sys.stderr,
            )
            continue

        baseline = load_baseline(baseline_file)
        diffs = compare_snapshots(snapshot, baseline)
        if not diffs:
            print(f"[smoke] {name}: OK")
        else:
            overall_drift = True
            print(f"[smoke] {name}: DRIFT ({len(diffs)} field(s))")
            for line in diffs:
                print(f"  {_redact_line(line, mode=redact_mode)}")

    return 1 if overall_drift else 0


if __name__ == "__main__":
    sys.exit(main())
