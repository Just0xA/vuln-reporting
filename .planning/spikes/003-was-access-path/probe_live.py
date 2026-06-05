"""
Spike 003 — LIVE tenant probe for WAS access path.

Doc research (see README) established WAS needs a SEPARATE export (tio.exports.was),
not tio.exports.vulns(). This script closes the tenant-dependent gaps that docs
can't answer:
  - Is the tenant WAS-licensed (does exports.was() return anything / 403)?
  - Is vpr_score populated on WAS findings? (codebase severity is VPR-first)
  - What is the actual chunk field schema (key union over a sample)?

REQUIRES live Tenable credentials in .env (TVM_ACCESS_KEY / TVM_SECRET_KEY / TVM_URL).
Read-only: it pulls at most SAMPLE_LIMIT findings and writes nothing.

Run:  python .planning/spikes/003-was-access-path/probe_live.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

SAMPLE_LIMIT = 200


def main() -> None:
    try:
        from tenable_client import get_client  # project's single chokepoint
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] could not import tenable_client.get_client: {exc}")
        return

    try:
        tio = get_client()
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] client auth failed (check .env): {exc}")
        return

    # Confirm the WAS export interface exists in this pyTenable version.
    has_exports_was = hasattr(getattr(tio, "exports", None), "was")
    has_was_iface = hasattr(tio, "was")
    print(f"tio.exports.was present : {has_exports_was}")
    print(f"tio.was present         : {has_was_iface}")
    if not has_exports_was:
        print("[WARN] tio.exports.was missing — upgrade pyTenable or use tio.was.export().")

    keys: Counter = Counter()
    vpr_present = 0
    vpr_v2_present = 0
    sampled = 0
    sample_record: dict | None = None

    try:
        it = tio.exports.was(state=["open", "reopened"])
        for finding in it:
            sampled += 1
            if isinstance(finding, dict):
                keys.update(finding.keys())
                if finding.get("vpr_score") is not None or (finding.get("vpr") or {}).get("score") is not None:
                    vpr_present += 1
                if finding.get("vpr_v2_score") is not None or (finding.get("vpr_v2") or {}).get("score") is not None:
                    vpr_v2_present += 1
                if sample_record is None:
                    sample_record = finding
            if sampled >= SAMPLE_LIMIT:
                break
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "403" in msg or "forbidden" in msg.lower() or "license" in msg.lower():
            print(f"[RESULT] WAS appears NOT licensed/permitted in this tenant: {exc}")
        else:
            print(f"[FAIL] exports.was() error: {exc}")
        return

    print(f"\nsampled WAS findings    : {sampled}")
    if sampled == 0:
        print("[RESULT] exports.was() returned 0 findings — WAS unlicensed, no scans, or empty scope.")
        return

    print(f"vpr_score populated     : {vpr_present}/{sampled}  "
          f"({'OK for VPR-first SLA' if vpr_present else 'ABSENT — severity will fall back to native'})")
    print(f"vpr_v2 populated        : {vpr_v2_present}/{sampled}")
    web = [k for k in ("url", "http_method", "input_type", "input_name", "output",
                       "owasp", "cwe", "cve", "request", "response") if k in keys]
    print(f"web fields seen         : {web}")
    print(f"\nall keys (union over sample):\n  {sorted(keys)}")
    if sample_record is not None:
        print(f"\none sample record:\n  {sample_record}")


if __name__ == "__main__":
    main()
