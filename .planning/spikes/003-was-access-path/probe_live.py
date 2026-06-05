"""
Spike 003 — LIVE tenant probe for WAS (pyTenable 1.5.2, tio.was).

NOTE: pyTenable 1.5.2 does NOT have tio.exports.was(); WAS is reached via
tio.was.export(), which is scan-config driven (searches WAS scan configs,
downloads per-target-scan reports, yields nested finding records). Filters are
scan-level only — severity/state/VPR filtering is client-side.

This probe closes the tenant-dependent gaps docs/source can't answer:
  - Is the tenant WAS-licensed (does tio.was.export() return data / 403)?
  - Is VPR populated on WAS findings? (codebase severity is VPR-first)
  - What is the real finding field schema (key union over a sample)?

REQUIRES live Tenable credentials in .env. Read-only; pulls at most SAMPLE_LIMIT
findings then stops. Writes nothing.

Run:  python .planning/spikes/003-was-access-path/probe_live.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

SAMPLE_LIMIT = 50


def _find_vpr(finding: dict):
    """WAS finding records vary; look for VPR in a few plausible spots."""
    if not isinstance(finding, dict):
        return None
    if finding.get("vpr_score") is not None:
        return finding["vpr_score"]
    vpr = finding.get("vpr")
    if isinstance(vpr, dict):
        return vpr.get("score")
    return vpr


def main() -> None:
    try:
        from tenable_client import get_client
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] could not import tenable_client.get_client: {exc}")
        return
    try:
        tio = get_client()
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] client auth failed (check .env): {exc}")
        return

    if not hasattr(tio, "was"):
        print("[FAIL] tio.was missing — unexpected pyTenable build.")
        return

    keys: Counter = Counter()
    finding_keys: Counter = Counter()
    vpr_present = 0
    sampled = 0
    sample_finding: dict | None = None

    try:
        # WAS configs/search requires an AND/OR group of >=2 conditions
        # ("Expecting an array of 2 or more"). Broad date floor + completed status.
        it = tio.was.export(
            and_filter=[
                ("scans_started_at", "gte", "2000/01/01"),
                ("scans_status", "contains", ["completed"]),
            ]
        )
        for rec in it:
            sampled += 1
            if isinstance(rec, dict):
                keys.update(rec.keys())                       # top-level: finding/config/scan/parent_scan
                finding = rec.get("finding", rec)
                if isinstance(finding, dict):
                    finding_keys.update(finding.keys())
                    if _find_vpr(finding) is not None:
                        vpr_present += 1
                    if sample_finding is None:
                        sample_finding = finding
            if sampled >= SAMPLE_LIMIT:
                break
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "403" in msg or "forbidden" in msg or "license" in msg or "not entitled" in msg:
            print(f"[RESULT] WAS appears NOT licensed/permitted in this tenant: {exc}")
        else:
            print(f"[FAIL] tio.was.export() error: {exc}")
        return

    print(f"sampled WAS findings    : {sampled}")
    if sampled == 0:
        print("[RESULT] tio.was.export() returned 0 findings — WAS unlicensed, no completed scans, or empty scope.")
        return

    print(f"vpr populated on finding: {vpr_present}/{sampled}  "
          f"({'OK for VPR-first SLA' if vpr_present else 'ABSENT — severity falls back to native'})")
    print(f"top-level record keys   : {sorted(keys)}")
    web = [k for k in ("uri", "url", "http_method", "method", "payload", "input_type",
                       "input_name", "output", "owasp", "cwe", "cve", "request", "response",
                       "name", "severity", "family") if k in finding_keys]
    print(f"web fields on finding   : {web}")
    print(f"\nall finding keys (union over sample):\n  {sorted(finding_keys)}")
    if sample_finding is not None:
        # Trim large payloads for readability
        trimmed = {k: (str(v)[:120] + "…" if isinstance(v, str) and len(str(v)) > 120 else v)
                   for k, v in sample_finding.items()}
        print(f"\none sample finding (trimmed):\n  {trimmed}")


if __name__ == "__main__":
    main()
