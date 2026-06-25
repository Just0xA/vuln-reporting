"""
utils/open_count.py — Point-in-time open-finding predicate.

Pure compute: no file I/O, no network I/O.  Import open_findings_at()
to filter a vulnerability DataFrame to the subset that was open at a
given reference date, using the reopened-aware two-interval model.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pandas as pd

logger = logging.getLogger(__name__)


def open_findings_at(df: pd.DataFrame, date: datetime) -> pd.DataFrame:
    """
    Return the subset of findings that were open at point-in-time ``date``.

    Uses the reopened-aware two-interval model: a REOPENED finding is
    considered fixed only during [last_fixed, resurfaced_date).  The
    naive single-interval form (last_fixed IS NULL OR last_fixed > D)
    drops the entire REOPENED population (~19% of findings on real data).

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame from fetch_all_vulnerabilities().
        Must have columns: first_found, last_fixed, resurfaced_date, state.
        All date columns must already be normalized to datetime64[ns, UTC]
        by ``data.fetchers._normalize_vuln_dates`` before calling this
        function — do NOT call _normalize_vuln_dates inside this predicate.
    date : datetime
        Point-in-time reference (UTC datetime preferred; tz-naive input is
        coerced to UTC).

    Returns
    -------
    pd.DataFrame
        Filtered to rows that were open at ``date``.  Zero-row DataFrames
        are returned as a zero-row copy; never raises on empty input.

    Notes
    -----
    State casing: the Tenable API returns lowercase values ("open",
    "reopened", "fixed").  This function normalises via ``.str.upper()``
    so it is safe against any future casing variation.

    Columns used: first_found, last_fixed, resurfaced_date, state.
    The severity column is already VPR-classified upstream; this predicate
    does not inspect or reclassify severity.
    """
    if df.empty:
        return df.iloc[0:0].copy()

    # Coerce tz-naive date to UTC so comparisons against datetime64[ns, UTC]
    # columns do not raise TypeError.
    D = (
        pd.Timestamp(date, tz="UTC")
        if getattr(date, "tzinfo", None) is None
        else pd.Timestamp(date)
    )

    # Born before or on the reference date.  A row with first_found=NaT would
    # evaluate (NaT <= D) as False and be dropped unconditionally, silently
    # undercounting opens (WR-02).  Policy decision: a missing first_found is not
    # grounds to drop an otherwise-open finding — we treat NaT-first_found as
    # born (present) and log a warning so the data-quality issue is observable
    # rather than silent.  Errs toward inclusion, consistent with WR-01's
    # over-count-prevention intent.
    missing_first_found = int(df["first_found"].isna().sum())
    if missing_first_found:
        logger.warning(
            "open_findings_at: %d row(s) have first_found=NaT; counting them as "
            "born/present rather than dropping them",
            missing_first_found,
        )
    born = df["first_found"].isna() | (df["first_found"] <= D)

    # Normalise state to uppercase once (fetcher stores lowercase: "open", "reopened", "fixed").
    # Coerce via .astype(str) first so a non-object state column (e.g. all-NaN
    # float or categorical inferred by pandas) does not raise AttributeError on
    # .str.upper() (WR-03).  .astype(str) keeps regular Python-str comparisons:
    # a genuine NaN state stringifies to "NAN", which matches no terminal-state
    # clause and therefore falls through to "open" — the safe default for an
    # unknown state.  We deliberately avoid .astype("string"), whose nullable-NA
    # semantics would propagate <NA> through the == comparisons and complicate
    # the boolean masks.
    st = df["state"].astype(str).str.upper()
    lf = df["last_fixed"]
    rs = df["resurfaced_date"]

    # A finding is "fixed at D" under any of three clauses:
    #   1. state=FIXED — terminal-fixed; state is authoritative regardless of
    #      last_fixed presence.  Tenable occasionally exports a FIXED row with an
    #      empty/missing last_fixed (fetcher stores vuln.get("last_fixed", "") →
    #      NaT).  Gating clause 1 on lf.notna() would let such a row fall through
    #      to "open", silently over-counting the exact direction of error this
    #      phase exists to prevent (WR-01).  A terminal FIXED state means closed.
    #   2. state=REOPENED, last_fixed <= D, resurfaced_date is known, and D < resurfaced_date
    #      (finding is in the gap between fix and resurface — closed at D)
    #   3. state=REOPENED, last_fixed <= D, resurfaced_date is NaT
    #      (was fixed, never resurfaced — treat as closed)
    fixed = (
        (st == "FIXED")
        | ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.notna() & (D < rs))
        | ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.isna())
    )

    return df[born & ~fixed]


if __name__ == "__main__":
    # Quick smoke test — builds a tiny synthetic DataFrame and prints the
    # open count at two reference dates. Mirrors the style of
    # utils/sla_calculator.py lines 305-328.
    from datetime import timedelta

    _REF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def _ts(days_ago: int | None) -> pd.Timestamp | None:
        if days_ago is None:
            return pd.NaT
        # _REF is already tz-aware; pd.Timestamp honours its tzinfo directly.
        return pd.Timestamp(_REF - timedelta(days=days_ago))

    _data = {
        "state":           ["open",     "fixed",    "reopened", "reopened",   "open"],
        "first_found":     [_ts(30),    _ts(60),    _ts(90),    _ts(90),      _ts(1)],
        "last_fixed":      [pd.NaT,     _ts(5),     _ts(20),    _ts(20),      pd.NaT],
        "resurfaced_date": [pd.NaT,     pd.NaT,     _ts(10),    pd.NaT,       pd.NaT],
        "severity":        ["critical", "high",     "medium",   "low",        "critical"],
    }
    _df = pd.DataFrame(_data)
    _df = _df.assign(**{
        col: pd.to_datetime(_df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })

    _result = open_findings_at(_df, _REF)
    print(f"Input rows  : {len(_df)}")
    print(f"Open at REF : {len(_result)}")
    # Expected: row 0 (open, born 30d ago) — included
    #           row 1 (fixed 5d ago)       — excluded
    #           row 2 (reopened, resurfaced 10d ago, so open at REF) — included
    #           row 3 (reopened, last_fixed 20d ago, no resurface)  — excluded
    #           row 4 (open, born 1d ago)   — included
    # => 3 open
    assert len(_result) == 3, f"Expected 3, got {len(_result)}"

    _empty_result = open_findings_at(_df.iloc[0:0], _REF)
    assert _empty_result.empty, "Empty input should return empty result"
    print("Smoke test passed.")
