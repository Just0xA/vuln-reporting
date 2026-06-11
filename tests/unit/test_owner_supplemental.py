"""
tests/unit/test_owner_supplemental.py — Regression tests for owner_supplemental.py.

Covers CR-01 (duplicate asset_uuid non-deterministic attribution via set_index),
WR-02 (Open Findings counts raw export rows instead of open_findings_at set),
and the empty-data guard (CLAUDE.md empty-data guard preserved).

These tests are written BEFORE the implementation fixes (TDD RED state):
  - test_duplicate_uuid_returns_paths_and_deterministic: FAILS before Task 1 —
    the open count is non-deterministic (last-wins from dict(zip)) or the returned
    Paths may be None; after the fix, attribution is deterministic (first-row wins)
    and real Paths are always returned.
  - test_open_findings_uses_open_set: FAILS before Task 1 (TypeError: unexpected kwarg
    or too-high count if kwarg accepted but unused)
  - test_empty_assets_returns_paths: passes in all states (guard already present)
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from reports.owner_supplemental import write_owner_supplemental
from utils.open_count import open_findings_at

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_REF = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(days_ago: int | None) -> pd.Timestamp | None:
    """Return a UTC Timestamp offset from _REF, or NaT for None."""
    if days_ago is None:
        return pd.NaT
    return pd.Timestamp(_REF - timedelta(days=days_ago))


def _assets_df_with_dup_uuid() -> pd.DataFrame:
    """
    Assets frame where two rows share the same asset_uuid but have DIFFERENT owners.

    This mirrors the multi-network / multi-hostname case that fetch_all_assets()
    can produce in production (same logical host, two network records).
    extract_owner does NOT dedup, so the duplicate flows into _build_owner_app_df.

    Row 0 and Row 1 share "dup-uuid"; row 0 is the FIRST row (owner="First Owner")
    and row 1 is the SECOND row (owner="Second Owner").

    After the CR-01 fix, drop_duplicates("asset_uuid") keeps row 0 (first-row wins),
    so the open count must appear under "First Owner", not "Second Owner".
    """
    return pd.DataFrame(
        {
            "asset_uuid": ["dup-uuid", "dup-uuid", "unique-uuid"],
            "hostname":   ["host-a",   "host-b",   "host-c"],
            "tags": [
                "Owner=First Owner;Application=Finance",   # row 0 — FIRST row
                "Owner=Second Owner;Application=Finance",  # row 1 — dup, diff owner
                "Owner=Infra;Application=Ops",
            ],
        }
    )


def _vulns_df_simple(asset_uuids: list[str]) -> pd.DataFrame:
    """
    Open-findings frame for the given asset UUIDs (all genuinely open).

    All findings are state='open', born before _REF, never fixed.
    """
    rows = []
    for uid in asset_uuids:
        rows.append(
            {
                "asset_uuid":      uid,
                "state":           "open",
                "first_found":     _ts(30),
                "last_fixed":      pd.NaT,
                "resurfaced_date": pd.NaT,
                "severity":        "critical",
            }
        )
    df = pd.DataFrame(rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })
    return df


def _vulns_df_with_gap_reopened(owner_asset: str, gap_asset: str) -> pd.DataFrame:
    """
    Build a vulns_df that contains:
      - one genuinely-open finding for owner_asset (born 30d ago, never fixed)
      - one REOPENED finding for gap_asset that is in its [last_fixed, resurfaced_date)
        gap at _REF — i.e. the finding IS in the open+reopened export but is NOT open
        at _REF.

    Both assets map to the same owner tag so we can check the per-owner count.
    """
    rows = [
        # Genuinely open
        {
            "asset_uuid":      owner_asset,
            "state":           "open",
            "first_found":     _ts(30),
            "last_fixed":      pd.NaT,
            "resurfaced_date": pd.NaT,
            "severity":        "high",
        },
        # REOPENED but currently in the [last_fixed, resurfaced_date) gap at _REF:
        # last_fixed = 5d ago (before _REF), resurfaced_date = 3d from now (after _REF)
        # → open_findings_at will exclude this row at _REF.
        {
            "asset_uuid":      gap_asset,
            "state":           "reopened",
            "first_found":     _ts(60),
            "last_fixed":      _ts(5),          # 5d before _REF
            "resurfaced_date": pd.Timestamp(_REF + timedelta(days=3)),  # after _REF
            "severity":        "high",
        },
    ]
    df = pd.DataFrame(rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })
    return df


def _assets_df_for_open_set() -> pd.DataFrame:
    """Assets for both asset_uuids used in the open-set test, same owner."""
    return pd.DataFrame(
        {
            "asset_uuid": ["open-asset", "gap-asset"],
            "hostname":   ["host1",      "host2"],
            "tags": [
                "Owner=TestOwner;Application=TestApp",
                "Owner=TestOwner;Application=TestApp",
            ],
        }
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_duplicate_uuid_returns_paths_and_deterministic(tmp_path: Path) -> None:
    """
    CR-01: write_owner_supplemental on assets_df with duplicate asset_uuid rows
    must (a) return real Paths and (b) attribute the finding to the FIRST row's
    owner — not the last (non-deterministic last-wins via set_index without dedup).

    BEFORE Task 1 fix: enriched.set_index("asset_uuid") on a non-unique index
    keeps duplicate rows.  DataFrame.join() against a non-unique right-hand index
    in pandas 2.2+ returns the LAST matching row's values (non-deterministic).
    The finding for "dup-uuid" therefore lands under "Second Owner" (last row)
    rather than "First Owner" (first row).

    AFTER fix: drop_duplicates("asset_uuid") before set_index pins first-row wins,
    so "dup-uuid" is attributed to "First Owner".
    """
    assets_df = _assets_df_with_dup_uuid()
    vulns_df  = _vulns_df_simple(["dup-uuid"])

    result = write_owner_supplemental(assets_df, vulns_df, tmp_path)

    assert result.get("supplemental_excel") is not None, (
        "supplemental_excel must be a real Path, not None"
    )
    assert result.get("supplemental_csv") is not None, (
        "supplemental_csv must be a real Path, not None"
    )
    assert Path(result["supplemental_excel"]).exists(), (
        f"Excel file not found: {result['supplemental_excel']}"
    )
    assert Path(result["supplemental_csv"]).exists(), (
        f"CSV file not found: {result['supplemental_csv']}"
    )

    # Determinism check: the finding must be under "First Owner", not "Second Owner".
    csv_path = Path(result["supplemental_csv"])
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    owners_with_findings = [r for r in rows if int(r.get("open_count", 0)) > 0]
    assert owners_with_findings, f"Expected at least one row with open_count > 0; got: {rows}"

    attributed_owners = {r["owner"] for r in owners_with_findings}
    assert "First Owner" in attributed_owners, (
        f"Finding must be attributed to 'First Owner' (first-row wins); "
        f"got attributed to: {attributed_owners}"
    )
    assert "Second Owner" not in attributed_owners, (
        f"Finding must NOT be attributed to 'Second Owner' (that is last-wins); "
        f"got: {attributed_owners}"
    )


def test_open_findings_uses_open_set(tmp_path: Path) -> None:
    """
    WR-02: the 'Open Findings' column in the supplemental must count only the
    open_findings_at(vulns_df, report_date) set, not raw export rows.

    A REOPENED finding in its [last_fixed, resurfaced_date) gap at report_date
    appears in the vulns_df export but is NOT open at that date.  If the
    supplemental counts raw rows, the gap-REOPENED row inflates the count.

    BEFORE Task 1 fix: write_owner_supplemental has no report_date param,
    so calling it with report_date=<date> raises TypeError on the unknown kwarg
    (or, if the kwarg is silently accepted but unused, the count is too high).

    AFTER fix: the owner row shows Open Findings == 1 (only the genuinely-open
    finding), not 2.
    """
    assets_df = _assets_df_for_open_set()
    vulns_df  = _vulns_df_with_gap_reopened("open-asset", "gap-asset")

    # Sanity: the export has 2 rows; open_findings_at should return only 1.
    open_set = open_findings_at(vulns_df, _REF)
    assert len(open_set) == 1, (
        f"Test fixture sanity: expected 1 open finding at _REF, got {len(open_set)}"
    )

    result = write_owner_supplemental(assets_df, vulns_df, tmp_path, report_date=_REF)

    csv_path = Path(result["supplemental_csv"])
    assert csv_path.exists(), "CSV was not written"

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    # Find the TestOwner row(s) — all rows belong to TestOwner in this fixture.
    # The open_count field name in the CSV matches the _SUPPLEMENTAL_COLS tuple.
    owner_rows = [r for r in rows if "TestOwner" in r.get("owner", "")]
    assert owner_rows, f"Expected TestOwner row in CSV; got rows: {rows}"

    # Sum open_count across all TestOwner rows (there may be one row since both
    # assets share the same owner/application).
    total_open = sum(int(r["open_count"]) for r in owner_rows)
    assert total_open == 1, (
        f"Expected Open Findings=1 (gap-REOPENED excluded), got {total_open}. "
        f"CSV rows: {rows}"
    )


def test_open_count_no_chained_assignment_warning(tmp_path: Path) -> None:
    """
    Phase-13 WR-02/CoW regression: _build_owner_app_df must not emit a
    ChainedAssignmentError FutureWarning from reports/owner_supplemental.py.

    BEFORE fix: result["open_count"] = result["open_count"].fillna(0).astype(int)
    at line ~139 chains through the merge's tracked parent frame and emits a
    FutureWarning; under pandas 3.0 CoW this will silently no-op, leaving
    open_count as float64-with-NaN.

    AFTER fix: converted to .assign(open_count=...) per CLAUDE.md F-DTYPE
    convention, which returns a new frame and bypasses CoW tracking.

    The test also asserts open_count is integer dtype (not float64) with no NaN.
    """
    import warnings

    assets_df = _assets_df_for_open_set()
    vulns_df  = _vulns_df_simple(["open-asset", "gap-asset"])

    with warnings.catch_warnings():
        warnings.simplefilter("error", FutureWarning)
        result = write_owner_supplemental(assets_df, vulns_df, tmp_path)

    csv_path = Path(result["supplemental_csv"])
    assert csv_path.exists()

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    # open_count must be integer-valued (no NaN represented as float)
    for r in rows:
        val = r.get("open_count", "")
        assert val != "", f"open_count must not be empty/NaN; row: {r}"
        assert val.isdigit() or (val.lstrip("-").isdigit()), (
            f"open_count must be an integer string, got: {val!r}"
        )


def test_dup_uuid_asset_count_counts_once(tmp_path: Path) -> None:
    """
    Phase-13 WR-01 regression: a duplicate asset_uuid carrying two different
    Owner/Application tags must be counted as exactly ONE physical asset in
    the Asset Count column.

    Fixture: "dup-uuid" appears in two rows (First Owner / Second Owner) and
    "unique-uuid" appears once (Infra / Ops).  Distinct physical assets = 2.

    BEFORE fix: asset_counts is built from the un-deduped enriched frame.
    nunique("asset_uuid") per group counts "dup-uuid" once under First Owner
    AND once under Second Owner → sum = 3 (phantom over-count), AND a phantom
    row (Second Owner, asset_count=1, open_count=0) is created.

    AFTER fix: enriched is deduped on asset_uuid (keep-first) BEFORE the
    asset_counts groupby, so "dup-uuid" is attributed only to First Owner
    and the sum of Asset Count = 2 = distinct physical assets.
    """
    assets_df = _assets_df_with_dup_uuid()
    vulns_df  = _vulns_df_simple(["unique-uuid"])  # no vulns for dup-uuid

    result = write_owner_supplemental(assets_df, vulns_df, tmp_path)

    csv_path = Path(result["supplemental_csv"])
    assert csv_path.exists()

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    # (a) No phantom row: "Second Owner" must NOT appear at all (deduped away)
    second_owner_rows = [r for r in rows if r.get("owner") == "Second Owner"]
    assert not second_owner_rows, (
        f"Phantom 'Second Owner' row must not exist after dedup; got: {second_owner_rows}"
    )

    # (b) Total Asset Count == count of distinct physical asset_uuids (2)
    total_asset_count = sum(int(r["asset_count"]) for r in rows)
    assert total_asset_count == 2, (
        f"Sum of Asset Count must equal distinct physical asset_uuids (2); "
        f"got {total_asset_count}. Rows: {rows}"
    )


def test_empty_assets_returns_paths(tmp_path: Path) -> None:
    """
    CLAUDE.md empty-data guard: write_owner_supplemental on empty assets_df and
    empty vulns_df must return real Paths (not None, not raise).

    This invariant must hold before AND after Task 1.
    """
    assets_df = pd.DataFrame(columns=["asset_uuid", "hostname", "tags"])
    vulns_df  = pd.DataFrame(
        columns=["asset_uuid", "state", "first_found", "last_fixed", "resurfaced_date"]
    )

    result = write_owner_supplemental(assets_df, vulns_df, tmp_path)

    assert result.get("supplemental_excel") is not None, (
        "supplemental_excel must be a real Path on empty input"
    )
    assert result.get("supplemental_csv") is not None, (
        "supplemental_csv must be a real Path on empty input"
    )
    assert Path(result["supplemental_excel"]).exists()
    assert Path(result["supplemental_csv"]).exists()
