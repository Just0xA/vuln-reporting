"""
Spike 002 — Trend-reconstruction lookback window + predicate validation.

Question: can we reconstruct month-over-month vuln history from the CURRENT finding
set (first_found/last_fixed/state/resurfaced_date) instead of accumulating snapshots,
and if so, HOW FAR BACK before retention purges make it lie?

Datasets (real cached export, 2026-06-02):
  vulns_all.parquet   = open/reopened population (160,453)
  vulns_fixed.parquet = remediated population (201,272)

Usage: python measure.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from config import vpr_to_severity  # noqa: E402  (kept for parity; severity slice optional)

CACHE = Path("data/cache/2026-06-02")
EXPORT_DATE: pd.Timestamp = None  # set in main() to the true max last_found = "now"


def load() -> pd.DataFrame:
    a = pd.read_parquet(CACHE / "vulns_all.parquet")
    f = pd.read_parquet(CACHE / "vulns_fixed.parquet")
    df = pd.concat([a, f], ignore_index=True)
    for c in ["first_found", "last_fixed", "resurfaced_date"]:
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    return df


def open_at_naive(df: pd.DataFrame, D: pd.Timestamp) -> int:
    """Single-interval predicate from the design note: first_found<=D AND (last_fixed null OR last_fixed>D)."""
    return int(((df["first_found"] <= D) & (df["last_fixed"].isna() | (df["last_fixed"] > D))).sum())


def open_at_improved(df: pd.DataFrame, D: pd.Timestamp) -> int:
    """
    Two-interval model that respects reopened findings.
    fixed_as_of_D:
      OPEN     -> never fixed
      REOPENED -> fixed only during [last_fixed, resurfaced_date)
      FIXED    -> fixed for D >= last_fixed
    open_at = first_found<=D AND NOT fixed_as_of_D
    """
    born = df["first_found"] <= D
    st = df["state"]
    lf, rs = df["last_fixed"], df["resurfaced_date"]
    fixed_open_state = (st == "FIXED") & lf.notna() & (lf <= D)
    fixed_reopen_gap = (st == "REOPENED") & lf.notna() & (lf <= D) & (rs.notna()) & (D < rs)
    # REOPENED with no resurfaced_date: treat last_fixed as a closed-then-? -> fall back to single interval
    fixed_reopen_nors = (st == "REOPENED") & lf.notna() & (lf <= D) & (rs.isna())
    fixed_as_of_D = fixed_open_state | fixed_reopen_gap | fixed_reopen_nors
    return int((born & ~fixed_as_of_D).sum())


def main() -> None:
    global EXPORT_DATE
    df = load()
    df["last_found"] = pd.to_datetime(df["last_found"], utc=True, errors="coerce")
    EXPORT_DATE = df["last_found"].max()  # the export's "now"
    n_all = (df["state"].isin(["OPEN", "REOPENED"])).sum()
    n_fixed = (df["state"] == "FIXED").sum()
    print("=" * 70)
    print("SPIKE 002 — trend-reconstruction lookback + predicate validation")
    print(f"universe: {len(df):,}  (open/reopened {n_all:,} + fixed {n_fixed:,})")
    print(f"export 'today' = {EXPORT_DATE.date()}")
    print("=" * 70)

    # --- (2) RETENTION HORIZON ---
    fixed = df[df["state"] == "FIXED"]
    lf_min = fixed["last_fixed"].min()
    retention_days = (EXPORT_DATE - lf_min).days
    print("\n--- (2) RETENTION HORIZON (the make-or-break) ---")
    print(f"fixed-export last_fixed range: {lf_min.date()} .. {fixed['last_fixed'].max().date()}")
    print(f"==> fixed findings are retained only ~{retention_days} days.")
    print("    Any remediation older than that is INVISIBLE (not in open set, purged from fixed set).")

    # --- (1) PREDICATE VALIDATION at D=today ---
    print("\n--- (1) PREDICATE VALIDATION at D=today ---")
    actual_open = int(n_all)
    naive_today = open_at_naive(df, EXPORT_DATE)
    impr_today = open_at_improved(df, EXPORT_DATE)
    print(f"actual current open (state OPEN+REOPENED) : {actual_open:,}")
    print(f"naive single-interval predicate           : {naive_today:,}  (delta {naive_today-actual_open:+,})")
    print(f"improved two-interval predicate           : {impr_today:,}  (delta {impr_today-actual_open:+,})")

    # --- (4) REOPENED WRINKLE ---
    reopened = df[df["state"] == "REOPENED"]
    rs_present = reopened["resurfaced_date"].notna().sum()
    print("\n--- (4) REOPENED WRINKLE ---")
    print(f"REOPENED findings: {len(reopened):,}  (resurfaced_date present: {rs_present:,})")
    print(f"naive predicate undercounts current open by exactly the reopened set: {actual_open-naive_today:,}")

    # --- monthly reconstruction back 18 months ---
    print("\n--- (3) MONTHLY RECONSTRUCTION (improved predicate) ---")
    print(f"{'month':<9} {'recon_open':>11} {'new(first_found)':>17} {'remediated(last_fixed)':>23}")
    months = pd.date_range("2024-12-01", "2026-06-01", freq="MS", tz="UTC")
    ff = df["first_found"]
    lf = df["last_fixed"]
    for m in months:
        nxt = m + pd.offsets.MonthBegin(1)
        recon = open_at_improved(df, m)
        new_in = int(((ff >= m) & (ff < nxt)).sum())
        rem_in = int(((lf >= m) & (lf < nxt)).sum())
        flag = "  <-- before retention floor (remediated~blind)" if m < lf_min.normalize() else ""
        print(f"{m.strftime('%Y-%m'):<9} {recon:>11,} {new_in:>17,} {rem_in:>23,}{flag}")

    # --- reliable window verdict ---
    print("\n" + "=" * 70)
    print("RELIABLE WINDOW")
    print(f"  - Remediated/month (outflow): only the last ~{retention_days} days have data.")
    print(f"  - Net-open reconstruction: complete only for D >= {lf_min.date()} "
          f"(~{retention_days}d); older D undercounts by everything fixed-then-purged.")
    print(f"  - New/month (inflow, first_found): extends years back BUT undercounts older")
    print(f"    months (short-lived findings already purged). Survivorship bias grows with age.")
    print("=" * 70)


if __name__ == "__main__":
    main()
