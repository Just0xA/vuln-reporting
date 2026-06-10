"""
tests/unit/test_open_count.py — Labelled OPEN/REOPENED/FIXED cases for TREND-01.

Tests the reopened-aware two-interval predicate in utils/open_count.py.
Each test case is named for the finding lifecycle scenario it exercises so
failures are immediately actionable without reading the predicate code.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from utils.open_count import open_findings_at

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixed reference date — no wall-clock dependency
# ---------------------------------------------------------------------------

_REF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _finding(
    state: str,
    first_found_days_ago: int,
    last_fixed_days_ago: int | None = None,
    resurfaced_days_ago: int | None = None,
) -> dict:
    """
    Build one finding row dict relative to _REF.

    Positive ``days_ago`` values produce dates in the past; negative values
    produce future dates (used to test born-after-D exclusion).
    """
    def _ts(days_ago: int | None) -> pd.Timestamp | None:
        if days_ago is None:
            return None
        return _REF - timedelta(days=days_ago)

    return {
        "state": state,                           # lowercase — matches fetcher output
        "first_found": _ts(first_found_days_ago),
        "last_fixed": _ts(last_fixed_days_ago),
        "resurfaced_date": _ts(resurfaced_days_ago),
        "severity": "high",
    }


def _df(rows: list[dict]) -> pd.DataFrame:
    """
    Assemble rows into a DataFrame with datetime64[ns, UTC] date columns,
    matching the types that _normalize_vuln_dates() produces in the real pipeline.
    """
    df = pd.DataFrame(rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })
    return df


# ---------------------------------------------------------------------------
# OPEN state
# ---------------------------------------------------------------------------

def test_open_state_included() -> None:
    """A plain OPEN finding born before D must be counted open at D."""
    df = _df([_finding("open", first_found_days_ago=30)])
    result = open_findings_at(df, _REF)
    assert len(result) == 1


def test_open_state_no_last_fixed_included() -> None:
    """OPEN finding with last_fixed=NaT (never fixed) is open at D."""
    row = _finding("open", first_found_days_ago=10)
    assert row["last_fixed"] is None  # confirm fixture
    df = _df([row])
    result = open_findings_at(df, _REF)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# FIXED state
# ---------------------------------------------------------------------------

def test_fixed_state_excluded() -> None:
    """A FIXED finding with last_fixed <= D must be excluded at D."""
    df = _df([_finding("fixed", first_found_days_ago=60, last_fixed_days_ago=5)])
    result = open_findings_at(df, _REF)
    assert len(result) == 0


def test_fixed_state_nat_last_fixed_excluded() -> None:
    """A FIXED finding with last_fixed=NaT must STILL be excluded at D (WR-01).

    Tenable occasionally exports a terminal FIXED row with an empty/missing
    last_fixed.  State is authoritative for terminal-fixed: such a row must not
    fall through to "open" (which would silently over-count opens).
    """
    row = _finding("fixed", first_found_days_ago=60, last_fixed_days_ago=None)
    assert row["last_fixed"] is None  # confirm fixture
    df = _df([row])
    result = open_findings_at(df, _REF)
    assert len(result) == 0


# ---------------------------------------------------------------------------
# REOPENED state — three sub-cases
# ---------------------------------------------------------------------------

def test_reopened_state_included() -> None:
    """REOPENED finding with D >= resurfaced_date must be counted open at D."""
    # resurfaced 10 days ago => D is after resurfaced_date => open
    df = _df([_finding(
        "reopened",
        first_found_days_ago=90,
        last_fixed_days_ago=20,
        resurfaced_days_ago=10,
    )])
    result = open_findings_at(df, _REF)
    assert len(result) == 1


def test_reopened_in_gap_excluded() -> None:
    """REOPENED finding where last_fixed <= D < resurfaced_date is closed at D.

    The finding was fixed before D and has not yet resurfaced — it is in the
    gap [last_fixed, resurfaced_date) so must be excluded.
    """
    # last_fixed 20 days ago, resurfaced 5 days *in the future* (days_ago=-5)
    df = _df([_finding(
        "reopened",
        first_found_days_ago=90,
        last_fixed_days_ago=20,
        resurfaced_days_ago=-5,   # negative => future date
    )])
    result = open_findings_at(df, _REF)
    assert len(result) == 0


def test_reopened_null_resurfaced_excluded() -> None:
    """REOPENED finding with last_fixed <= D and resurfaced_date=NaT is excluded.

    Was fixed and never resurfaced according to the data — treat as closed.
    """
    df = _df([_finding(
        "reopened",
        first_found_days_ago=90,
        last_fixed_days_ago=20,
        resurfaced_days_ago=None,   # NaT
    )])
    result = open_findings_at(df, _REF)
    assert len(result) == 0


# ---------------------------------------------------------------------------
# Born-after-D exclusion
# ---------------------------------------------------------------------------

def test_born_after_D_excluded() -> None:
    """A finding whose first_found > D must not appear in the open set."""
    # first_found_days_ago=-1 => first_found is 1 day in the future
    df = _df([_finding("open", first_found_days_ago=-1)])
    result = open_findings_at(df, _REF)
    assert len(result) == 0


# ---------------------------------------------------------------------------
# first_found=NaT — counted as present, not silently dropped (WR-02)
# ---------------------------------------------------------------------------

def test_nat_first_found_open_included() -> None:
    """An OPEN finding with first_found=NaT must be counted, not dropped (WR-02).

    Policy: a missing first_found is not grounds to drop an otherwise-open
    finding.  NaT-first_found rows are treated as born/present (a warning is
    logged) rather than silently undercounting opens.
    """
    row = _finding("open", first_found_days_ago=None)
    assert row["first_found"] is None  # confirm fixture
    df = _df([row])
    result = open_findings_at(df, _REF)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# Defensive state dtype coercion (WR-03)
# ---------------------------------------------------------------------------

def test_non_string_state_dtype_does_not_raise() -> None:
    """A non-object state column (all-NaN float) must not raise on .str.upper() (WR-03).

    .astype(str) coerces defensively: a NaN state stringifies to "NAN", matches
    no terminal-state clause, and falls through to "open" (the safe default).
    """
    row = _finding("open", first_found_days_ago=10)
    df = _df([row])
    # Force the state column to a non-object (float) dtype, as pandas would infer
    # for an all-NaN column — this is the dtype that breaks a naive .str.upper().
    df["state"] = pd.Series([float("nan")], dtype="float64")
    result = open_findings_at(df, _REF)
    # NaN state stringifies to "NAN" → no fixed clause matches → counted open.
    assert len(result) == 1


# ---------------------------------------------------------------------------
# Empty-DataFrame guard
# ---------------------------------------------------------------------------

def test_empty_dataframe_returns_empty() -> None:
    """open_findings_at must return an empty DataFrame without raising."""
    # Build a properly-typed zero-row DataFrame that matches the live schema
    # (same column dtypes that _normalize_vuln_dates produces).
    empty = pd.DataFrame({
        "state": pd.Series([], dtype="object"),
        "first_found": pd.Series([], dtype="datetime64[ns, UTC]"),
        "last_fixed": pd.Series([], dtype="datetime64[ns, UTC]"),
        "resurfaced_date": pd.Series([], dtype="datetime64[ns, UTC]"),
        "severity": pd.Series([], dtype="object"),
    })
    result = open_findings_at(empty, _REF)
    assert result.empty


# ---------------------------------------------------------------------------
# Composite scenario — mixed population
# ---------------------------------------------------------------------------

def test_mixed_population() -> None:
    """Composite: 5 rows spanning all states; only correct rows are returned."""
    rows = [
        _finding("open",     first_found_days_ago=30),                            # included
        _finding("fixed",    first_found_days_ago=60, last_fixed_days_ago=5),     # excluded
        _finding("reopened", first_found_days_ago=90, last_fixed_days_ago=20,
                 resurfaced_days_ago=10),                                          # included
        _finding("reopened", first_found_days_ago=90, last_fixed_days_ago=20,
                 resurfaced_days_ago=-5),                                          # excluded (gap)
        _finding("reopened", first_found_days_ago=90, last_fixed_days_ago=20,
                 resurfaced_days_ago=None),                                        # excluded (NaT)
    ]
    df = _df(rows)
    result = open_findings_at(df, _REF)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Timezone coercion — tz-naive date argument
# ---------------------------------------------------------------------------

def test_tz_naive_date_does_not_raise() -> None:
    """Passing a tz-naive datetime must not raise TypeError."""
    naive_ref = _REF.replace(tzinfo=None)
    df = _df([_finding("open", first_found_days_ago=10)])
    result = open_findings_at(df, naive_ref)
    assert len(result) == 1
