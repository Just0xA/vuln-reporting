"""
Spike 001 — Measure CPE coverage of VPR Critical+High open findings.

Question: can a CPE-prefix classifier (cpe:/a, cpe:/o, cpe:/h) reliably bucket
serious findings into Application / OS / Hardware, or is a plugin_family fallback
(or visible "Unclassified" bucket) required?

Runs against the most recent real cached vulns export. Mirrors production severity
logic via config.vpr_to_severity (VPR-first, native-severity fallback).

Usage: python measure.py [path-to-vulns.parquet]
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

# Reuse production severity derivation so Crit+High matches what the module will see.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from config import vpr_to_severity  # noqa: E402

PARQUET = sys.argv[1] if len(sys.argv) > 1 else "data/cache/2026-06-02/vulns_all.parquet"

# CPE part letter: matches both CPE 2.2 (cpe:/a:...) and 2.3 (cpe:2.3:a:...) forms.
_CPE_PART = re.compile(r"cpe:(?:2\.3:|/)([aoh])[:/]", re.IGNORECASE)
PART_TO_BUCKET = {"a": "Application", "o": "OS", "h": "Hardware"}
# Precedence for mixed-type findings: a > o > h (application risk owns the finding).
PRECEDENCE = ["a", "o", "h"]


def cpe_parts(cpe_field: str | None) -> set[str]:
    """Return the set of distinct part letters {a,o,h} found in a comma-joined CPE string."""
    if not cpe_field or not isinstance(cpe_field, str):
        return set()
    return {m.lower() for m in _CPE_PART.findall(cpe_field)}


def classify(parts: set[str]) -> str:
    """Apply a>o>h precedence to a set of part letters; '' if none."""
    for p in PRECEDENCE:
        if p in parts:
            return PART_TO_BUCKET[p]
    return ""


def derive_severity(row) -> str:
    native = str(row.get("severity") or "").strip().lower()
    return vpr_to_severity(row.get("vpr_score"), fallback=native or "info")


def main() -> None:
    df = pd.read_parquet(PARQUET)
    total_rows = len(df)

    df["derived_sev"] = df.apply(derive_severity, axis=1)
    ch = df[df["derived_sev"].isin(["critical", "high"])].copy()
    n = len(ch)

    ch["parts"] = ch["cpe"].apply(cpe_parts)
    ch["bucket"] = ch["parts"].apply(classify)
    ch["n_types"] = ch["parts"].apply(len)

    classified = ch[ch["bucket"] != ""]
    residual = ch[ch["bucket"] == ""]
    n_class = len(classified)
    n_resid = len(residual)

    def pct(x: int) -> str:
        return f"{100*x/n:.1f}%" if n else "n/a"

    print("=" * 64)
    print("SPIKE 001 — CPE coverage of VPR Critical+High findings")
    print(f"source: {PARQUET}")
    print("=" * 64)
    print(f"total findings in export : {total_rows:,}")
    print(f"VPR Critical+High        : {n:,}  ({100*n/total_rows:.1f}% of export)")
    print(f"  derived Critical       : {(ch['derived_sev']=='critical').sum():,}")
    print(f"  derived High           : {(ch['derived_sev']=='high').sum():,}")
    print()
    print("--- (1) clean CPE-prefix coverage of Crit+High ---")
    print(f"classified by CPE prefix : {n_class:,}  ({pct(n_class)})")
    print(f"residual (no a/o/h CPE)  : {n_resid:,}  ({pct(n_resid)})")
    print()
    print("--- (2) a/o/h split among classified (after a>o>h precedence) ---")
    for bucket, c in classified["bucket"].value_counts().items():
        print(f"  {bucket:<12}: {c:,}  ({100*c/n_class:.1f}% of classified, {pct(c)} of Crit+High)")
    print()
    print("--- (3) residual size ---")
    n_empty = (ch["parts"].apply(len) == 0).sum()
    print(f"truly empty CPE          : {n_empty:,}  ({pct(int(n_empty))})")
    print(f"non-empty but no a/o/h    : {n_resid - n_empty:,}")
    print()
    print("--- (4) plugin_family domination of residual (top 15) ---")
    fam = residual["plugin_family"].fillna("(none)").value_counts().head(15)
    cum = 0
    for f, c in fam.items():
        cum += c
        print(f"  {c:>6,}  ({100*c/n_resid:4.1f}%, cum {100*cum/n_resid:4.1f}%)  {f}")
    print()
    print("--- (5) mixed-type CPE frequency among Crit+High ---")
    nt = ch["n_types"].value_counts().sort_index()
    for k, c in nt.items():
        label = {0: "0 (empty)", 1: "1 (clean)"}.get(k, f"{k} (mixed)")
        print(f"  {label:<12}: {c:,}  ({pct(c)})")
    mixed = ch[ch["n_types"] >= 2]
    print(f"  mixed total            : {len(mixed):,}  ({pct(len(mixed))})")
    if len(mixed):
        combos = Counter(frozenset(p) for p in mixed["parts"])
        print("  top mixed combos:")
        for combo, c in combos.most_common(6):
            print(f"    {{{','.join(sorted(combo))}}}: {c:,}")

    # --- verdict heuristic ---
    cov = 100 * n_class / n if n else 0
    print()
    print("=" * 64)
    print(f"HEADLINE: CPE prefix alone classifies {cov:.1f}% of Crit+High findings.")
    if cov >= 90:
        print("VERDICT signal: CPE-only is viable; tiny Unclassified bucket acceptable.")
    elif cov >= 75:
        print("VERDICT signal: CPE-only workable; plugin_family fallback recommended for residual.")
    else:
        print("VERDICT signal: CPE-only INSUFFICIENT; plugin_family fallback REQUIRED.")
    print("=" * 64)


if __name__ == "__main__":
    main()
