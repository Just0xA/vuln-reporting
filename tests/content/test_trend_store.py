"""
tests/content/test_trend_store.py — Layer 2 snapshot write/read/idempotency/PII/cold-start.

Covers TREND-02..06 requirements:
  TREND-02: capture_snapshot writes a file (atomic write succeeds on current OS)
  TREND-03: existing management_summary_*.json is byte-for-byte unchanged
  TREND-04: read_trend is cold-start safe (no exception, insufficient_data=True)
  TREND-05: idempotent per (month, tag_filter); appends for new months
  TREND-06: snapshot payloads contain only aggregate counts, no PII fields

All capture/read calls pass trend_dir=tmp_path so no real data/trend/ files are
touched (P2 — testability without monkeypatching the module-level constant).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd
import pytest

from data.trend_store import capture_snapshot, read_trend
from utils.open_count import open_findings_at

pytestmark = pytest.mark.content


# ---------------------------------------------------------------------------
# PII field set — none of these must appear in snapshot files (TREND-06)
# ---------------------------------------------------------------------------

_PII_FIELDS = {"hostname", "ipv4", "fqdn", "asset_uuid", "plugin_name", "plugin_id"}


# ---------------------------------------------------------------------------
# Minimal fixture helpers — hand-built, known counts
# ---------------------------------------------------------------------------


def _open_df(n: int = 5) -> pd.DataFrame:
    """
    Return n open findings, all severity='critical', state='open'.

    Date columns are coerced to datetime64[ns, UTC] so the predicate
    open_findings_at() can compare them against a tz-aware reference date.
    """
    rows = [
        {
            "first_found":     datetime(2026, 5, 1, tzinfo=timezone.utc),
            "last_fixed":      None,
            "resurfaced_date": None,
            "state":           "open",
            "severity":        "critical",
        }
        for _ in range(n)
    ]
    df = pd.DataFrame(rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })
    return df


def _assets_df(n: int = 10) -> pd.DataFrame:
    """Return a minimal assets DataFrame with n rows."""
    return pd.DataFrame({"asset_uuid": [f"a{i}" for i in range(n)]})


# ---------------------------------------------------------------------------
# TREND-02: capture writes a file; atomic write succeeds on the current OS
# ---------------------------------------------------------------------------


def test_capture_writes_file(tmp_path):
    """
    capture_snapshot returns a path that exists and contains a single snapshot.

    Running to completion without PermissionError confirms the fd-close-before-
    os.replace ordering is correct on the current OS (Windows file-locking
    concern — Gemini MEDIUM review).
    """
    df = _open_df(n=5)
    assets_df = _assets_df(n=10)
    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )
    assert path.exists(), "capture_snapshot must return an existing path"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "snapshots" in data
    assert len(data["snapshots"]) == 1


# ---------------------------------------------------------------------------
# TREND-01 content: live count matches open_findings_at oracle
# ---------------------------------------------------------------------------


def test_live_count_match(tmp_path):
    """
    Written critical count equals the count from open_findings_at for severity='critical'.

    DO NOT assert against len(df[df.state != 'fixed']) — that naive predicate is
    the ~19% undercount bug this phase exists to fix.  open_findings_at is the oracle.
    """
    df = _open_df(n=7)  # 7 open criticals; first_found=2026-05-01
    assets_df = _assets_df(n=3)
    ref = datetime(2026, 6, 1, tzinfo=timezone.utc)

    path = capture_snapshot(df, assets_df, ref, "severity", "all_assets", trend_dir=tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    written_critical = data["snapshots"][0]["critical"]

    # Oracle: run the same predicate the engine calls
    open_df = open_findings_at(df, ref)
    oracle_critical = int((open_df["severity"] == "critical").sum())

    assert written_critical == oracle_critical, (
        f"Written critical count {written_critical} must match "
        f"open_findings_at oracle {oracle_critical}"
    )


# ---------------------------------------------------------------------------
# TREND-05a: idempotent same-month overwrite
# ---------------------------------------------------------------------------


def test_idempotent_overwrite(tmp_path):
    """Two captures for the same month produce exactly one snapshot entry."""
    df = _open_df(n=5)
    assets_df = _assets_df(n=3)
    ref = datetime(2026, 6, 1)

    capture_snapshot(df, assets_df, ref, "severity", "all_assets", trend_dir=tmp_path)
    capture_snapshot(df, assets_df, ref, "severity", "all_assets", trend_dir=tmp_path)

    data = json.loads(
        (tmp_path / "trend_severity_all_assets.json").read_text(encoding="utf-8")
    )
    assert len(data["snapshots"]) == 1, "Same-month re-run must overwrite, not append"


# ---------------------------------------------------------------------------
# TREND-05b: different month appends without touching the prior entry
# ---------------------------------------------------------------------------


def test_second_month_appends(tmp_path):
    """Capture month A then month B → two entries; month A entry unchanged."""
    df = _open_df(n=4)
    assets_df = _assets_df(n=2)

    ref_june = datetime(2026, 6, 1)
    ref_may = datetime(2026, 5, 1)

    capture_snapshot(df, assets_df, ref_may, "severity", "all_assets", trend_dir=tmp_path)
    # Record the May entry before June capture
    pre_data = json.loads(
        (tmp_path / "trend_severity_all_assets.json").read_text(encoding="utf-8")
    )
    may_entry_before = pre_data["snapshots"][0].copy()

    capture_snapshot(df, assets_df, ref_june, "severity", "all_assets", trend_dir=tmp_path)

    post_data = json.loads(
        (tmp_path / "trend_severity_all_assets.json").read_text(encoding="utf-8")
    )
    assert len(post_data["snapshots"]) == 2, "Different month must append a second entry"

    may_entry_after = next(
        s for s in post_data["snapshots"] if s["month"] == "2026-05"
    )
    # generated_at may differ (wall clock), compare all other keys
    comparable_keys = {"month", "tag_filter", "critical", "high", "medium", "low", "asset_count"}
    for k in comparable_keys:
        assert may_entry_after[k] == may_entry_before[k], (
            f"Month A entry key {k!r} changed after month B capture"
        )


# ---------------------------------------------------------------------------
# TREND-04: cold-start read safety
# ---------------------------------------------------------------------------


def test_cold_start_read(tmp_path):
    """read_trend on a missing file returns empty snapshots and insufficient_data=True."""
    result = read_trend("severity", "all_assets", trend_dir=tmp_path)
    assert result["snapshots"] == []
    assert result["insufficient_data"] is True


def test_single_snapshot_insufficient_data(tmp_path):
    """One snapshot is not enough for a trend — insufficient_data must still be True."""
    df = _open_df(n=2)
    assets_df = _assets_df(n=1)
    capture_snapshot(df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
                     trend_dir=tmp_path)

    result = read_trend("severity", "all_assets", trend_dir=tmp_path)
    assert len(result["snapshots"]) == 1
    assert result["insufficient_data"] is True


# ---------------------------------------------------------------------------
# TREND-06: no PII in snapshot file
# ---------------------------------------------------------------------------


def test_no_pii_in_snapshot(tmp_path):
    """
    Snapshot JSON must contain only aggregate counts — no hostname, ipv4, fqdn,
    asset_uuid, plugin_name, or plugin_id fields (D-04 PII discipline).
    """
    df = _open_df(n=5)
    assets_df = _assets_df(n=10)
    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )
    text = path.read_text(encoding="utf-8")
    for field in _PII_FIELDS:
        assert field not in text, f"PII field {field!r} found in snapshot file"


# ---------------------------------------------------------------------------
# TREND-03: management_summary_*.json is byte-for-byte unchanged
# ---------------------------------------------------------------------------


def test_ms_file_untouched(tmp_path):
    """
    A pre-existing management_summary_all_assets.json in the same directory must
    not be modified by capture_snapshot (D-01, D-05: substrate writes a different
    filename; it calls none of the MS private helpers).
    """
    ms_file = tmp_path / "management_summary_all_assets.json"
    ms_file.write_text(
        json.dumps({
            "snapshots": [{
                "month":        "2026-05",
                "tag_filter":   "all_assets",
                "critical":     10,
                "high":         5,
                "medium":       2,
                "low":          1,
                "generated_at": "2026-05-01T00:00:00Z",
            }]
        }),
        encoding="utf-8",
    )
    original_mtime = ms_file.stat().st_mtime

    df = _open_df(n=3)
    assets_df = _assets_df(n=2)
    capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )

    assert ms_file.stat().st_mtime == original_mtime, (
        "MS file mtime changed — substrate must not touch management_summary_*.json"
    )


# ---------------------------------------------------------------------------
# Empty-df safety: capture must not crash and must write all-zero counts
# ---------------------------------------------------------------------------


def test_empty_df_writes_zero_counts(tmp_path):
    """
    An empty open-findings DataFrame produces an entry with all severity counts 0.
    No exception is raised (empty-data guard in _count_by_severity).
    """
    empty_df = pd.DataFrame({
        "first_found":     pd.Series([], dtype="datetime64[ns, UTC]"),
        "last_fixed":      pd.Series([], dtype="datetime64[ns, UTC]"),
        "resurfaced_date": pd.Series([], dtype="datetime64[ns, UTC]"),
        "state":           pd.Series([], dtype="object"),
        "severity":        pd.Series([], dtype="object"),
    })
    assets_df = _assets_df(n=3)

    path = capture_snapshot(
        empty_df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    entry = data["snapshots"][0]
    assert entry["critical"] == 0
    assert entry["high"] == 0
    assert entry["medium"] == 0
    assert entry["low"] == 0
    assert entry["asset_count"] == 3


# ---------------------------------------------------------------------------
# Owner-dimension tests (SEG-05) — require Task 1 implementation
# ---------------------------------------------------------------------------


def _open_df_with_uuids(rows: list[dict]) -> pd.DataFrame:
    """
    Return an open-findings DataFrame with known asset_uuid values.

    Each row dict must include: asset_uuid, severity.
    Date columns are coerced to datetime64[ns, UTC].
    """
    base_rows = []
    for r in rows:
        base_rows.append({
            "asset_uuid":    r["asset_uuid"],
            "first_found":   datetime(2026, 5, 1, tzinfo=timezone.utc),
            "last_fixed":    None,
            "resurfaced_date": None,
            "state":         "open",
            "severity":      r.get("severity", "critical"),
        })
    df = pd.DataFrame(base_rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })
    return df


def _enriched_assets(uuid_owner_pairs: list[tuple[str, str]]) -> pd.DataFrame:
    """Return a minimal enriched assets DataFrame with asset_uuid + owner columns."""
    return pd.DataFrame(
        [{"asset_uuid": u, "owner": o} for u, o in uuid_owner_pairs]
    )


def test_capture_owner_writes_owner_file(tmp_path):
    """
    capture_snapshot with dimension='owner' writes trend_owner_all_assets.json
    and the file exists (SEG-05, D-12).
    """
    vulns_df = _open_df_with_uuids([
        {"asset_uuid": "a1", "severity": "critical"},
        {"asset_uuid": "a2", "severity": "high"},
    ])
    assets_df = _assets_df(n=5)
    enriched = _enriched_assets([("a1", "Team A"), ("a2", "Team B")])

    path = capture_snapshot(
        vulns_df, assets_df, datetime(2026, 6, 1), "owner", "all_assets",
        trend_dir=tmp_path, enriched_assets=enriched,
    )

    assert path.name == "trend_owner_all_assets.json", (
        f"Expected trend_owner_all_assets.json, got {path.name}"
    )
    assert path.exists(), "capture_snapshot must return an existing path"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "snapshots" in data
    assert len(data["snapshots"]) == 1


def test_read_trend_owner_roundtrip(tmp_path):
    """
    After an owner-dimension capture, read_trend('owner', 'all_assets')
    returns a dict with snapshot count keys that are owner names — NOT
    critical/high/medium/low (SEG-05, D-12).
    """
    vulns_df = _open_df_with_uuids([
        {"asset_uuid": "a1", "severity": "critical"},
        {"asset_uuid": "a2", "severity": "high"},
    ])
    assets_df = _assets_df(n=5)
    enriched = _enriched_assets([("a1", "Team Alpha"), ("a2", "Team Beta")])

    capture_snapshot(
        vulns_df, assets_df, datetime(2026, 6, 1), "owner", "all_assets",
        trend_dir=tmp_path, enriched_assets=enriched,
    )

    result = read_trend("owner", "all_assets", months=6, trend_dir=tmp_path)
    assert "snapshots" in result
    assert len(result["snapshots"]) >= 1

    snap = result["snapshots"][0]
    # Owner keys must be present; standard severity keys must NOT
    assert "Team Alpha" in snap or "Team Beta" in snap, (
        f"Expected owner keys in snapshot, got: {list(snap.keys())}"
    )
    assert "critical" not in snap, "Owner snapshot must not have severity key 'critical'"
    assert "high" not in snap, "Owner snapshot must not have severity key 'high'"


def test_owner_requires_enriched_assets(tmp_path):
    """
    capture_snapshot with dimension='owner' and enriched_assets=None
    must raise ValueError (D-12, T-13-12).
    """
    vulns_df = _open_df_with_uuids([{"asset_uuid": "a1"}])
    assets_df = _assets_df(n=2)

    with pytest.raises(ValueError, match="enriched_assets"):
        capture_snapshot(
            vulns_df, assets_df, datetime(2026, 6, 1), "owner", "all_assets",
            trend_dir=tmp_path, enriched_assets=None,
        )


def test_owner_counts_reconcile(tmp_path):
    """
    Sum of per-owner counts in the written snapshot equals the open-finding
    count from open_findings_at for the same df/date.

    Findings for assets absent from enriched count under 'Unassigned'.
    (SEG-05, TREND-06)
    """
    ref = datetime(2026, 6, 1, tzinfo=timezone.utc)

    vulns_df = _open_df_with_uuids([
        {"asset_uuid": "a1"},
        {"asset_uuid": "a2"},
        {"asset_uuid": "a3"},   # no owner in enriched → Unassigned
    ])
    assets_df = _assets_df(n=5)
    enriched = _enriched_assets([("a1", "Team A"), ("a2", "Team A")])

    path = capture_snapshot(
        vulns_df, assets_df, ref, "owner", "all_assets",
        trend_dir=tmp_path, enriched_assets=enriched,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    snap = data["snapshots"][0]

    # Sum all owner counts (excludes metadata keys — including Phase-15 aggregate fields
    # which are None in owner-dimension snapshots when not explicitly supplied)
    meta_keys = {
        "month", "tag_filter", "asset_count", "generated_at",
        "on_time_asset_count", "reopened_count", "accepted_count",
        "recast_count", "new_findings_count", "fixed_findings_count",
    }
    owner_total = sum(v for k, v in snap.items() if k not in meta_keys and v is not None)

    # Oracle: open_findings_at on the same df/date
    open_df = open_findings_at(vulns_df, ref)
    oracle_total = len(open_df)

    assert owner_total == oracle_total, (
        f"Owner count sum {owner_total} must equal open_findings_at oracle {oracle_total}"
    )


def test_owner_attribution_deterministic_under_dup_uuid(tmp_path):
    """
    WR-05: per-owner attribution is deterministic (first-row wins) when
    enriched_assets contains the same asset_uuid under two different owners.

    BEFORE the WR-05 fix: dict(zip(...)) with a non-unique asset_uuid is
    last-wins — the finding for a1 lands under "Team B" (second row).

    AFTER fix: drop_duplicates("asset_uuid") keeps row 0 ("Team A"), so a1's
    finding is attributed to "Team A".

    Also asserts that the owner-count sum still reconciles to the open-finding
    total (reconcile-to-whole invariant preserved).
    """
    ref = datetime(2026, 6, 1, tzinfo=timezone.utc)

    # a1 appears twice under different owners; a2 under a single owner.
    enriched = _enriched_assets([
        ("a1", "Team A"),   # row 0 — first row for a1
        ("a1", "Team B"),   # row 1 — dup uuid, different owner
        ("a2", "Team C"),
    ])

    vulns_df = _open_df_with_uuids([
        {"asset_uuid": "a1"},
        {"asset_uuid": "a2"},
    ])
    assets_df = _assets_df(n=3)

    path = capture_snapshot(
        vulns_df, assets_df, ref, "owner", "all_assets",
        trend_dir=tmp_path, enriched_assets=enriched,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    snap = data["snapshots"][0]

    meta_keys = {
        "month", "tag_filter", "asset_count", "generated_at",
        "on_time_asset_count", "reopened_count", "accepted_count",
        "recast_count", "new_findings_count", "fixed_findings_count",
    }

    # (a) a1's finding must be attributed to "Team A" (first-row), not "Team B".
    assert snap.get("Team A", 0) >= 1, (
        f"Expected a1's finding under 'Team A' (first-row wins); snap={snap}"
    )
    assert snap.get("Team B", 0) == 0, (
        f"Expected 0 under 'Team B' (last-row must NOT win); snap={snap}"
    )

    # (b) reconcile-to-whole invariant preserved.
    owner_total = sum(v for k, v in snap.items() if k not in meta_keys and v is not None)
    open_df = open_findings_at(vulns_df, ref)
    oracle_total = len(open_df)
    assert owner_total == oracle_total, (
        f"Owner count sum {owner_total} must equal open_findings_at oracle {oracle_total}"
    )


def test_owner_snapshot_no_pii(tmp_path):
    """
    Written owner snapshot JSON must contain no PII fields (TREND-06, D-11).

    Allowed keys in each entry: owner names + month + tag_filter + asset_count
    + generated_at. Disallowed: hostname, ipv4, fqdn, asset_uuid, plugin_name,
    plugin_id.
    """
    vulns_df = _open_df_with_uuids([
        {"asset_uuid": "a1"},
        {"asset_uuid": "a2"},
    ])
    assets_df = _assets_df(n=5)
    enriched = _enriched_assets([("a1", "Team A"), ("a2", "Team B")])

    path = capture_snapshot(
        vulns_df, assets_df, datetime(2026, 6, 1), "owner", "all_assets",
        trend_dir=tmp_path, enriched_assets=enriched,
    )

    text = path.read_text(encoding="utf-8")
    for field in _PII_FIELDS:
        assert field not in text, (
            f"PII field {field!r} found in owner snapshot file (TREND-06/D-11)"
        )


def test_owner_cold_start_safe(tmp_path):
    """
    read_trend('owner', 'all_assets') with <=1 snapshot returns available
    history with insufficient_data=True — does not raise (TREND-04 carried).
    """
    # Zero snapshots: file does not exist
    result = read_trend("owner", "all_assets", months=6, trend_dir=tmp_path)
    assert result["snapshots"] == []
    assert result["insufficient_data"] is True

    # One snapshot: insufficient_data still True
    vulns_df = _open_df_with_uuids([{"asset_uuid": "a1"}])
    assets_df = _assets_df(n=2)
    enriched = _enriched_assets([("a1", "Team A")])

    capture_snapshot(
        vulns_df, assets_df, datetime(2026, 6, 1), "owner", "all_assets",
        trend_dir=tmp_path, enriched_assets=enriched,
    )

    result2 = read_trend("owner", "all_assets", months=6, trend_dir=tmp_path)
    assert len(result2["snapshots"]) == 1
    assert result2["insufficient_data"] is True


# ---------------------------------------------------------------------------
# Phase 15 Plan 02 — new aggregate fields (D-15-04/05/06, QUAL-05)
# ---------------------------------------------------------------------------

pd.options.mode.copy_on_write = True


def _open_df_with_states(rows: list[dict]) -> pd.DataFrame:
    """
    Build an open-findings DataFrame with explicit state and
    severity_modification_type columns for aggregate field tests.

    Each row dict must include: state, severity, optional smt
    (severity_modification_type).  first_found defaults to 2026-06-01 UTC.
    """
    base_rows = []
    for r in rows:
        base_rows.append({
            "first_found":               r.get("first_found",
                                               datetime(2026, 6, 1, tzinfo=timezone.utc)),
            "last_fixed":                None,
            "resurfaced_date":           None,
            "state":                     r.get("state", "open"),
            "severity":                  r.get("severity", "critical"),
            "severity_modification_type": r.get("smt", ""),
        })
    df = pd.DataFrame(base_rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("first_found", "last_fixed", "resurfaced_date")
    })
    return df


def _fixed_df(n: int, month: str = "2026-06") -> pd.DataFrame:
    """
    Build a minimal fixed-vulns DataFrame with n rows whose last_fixed is in
    the given month and state=FIXED (for fixed_findings_count derivation).
    """
    rows = [
        {
            "last_fixed": datetime(int(month[:4]), int(month[5:7]), 15,
                                   tzinfo=timezone.utc),
            "state": "FIXED",
            "severity": "high",
            "first_found": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "resurfaced_date": None,
            "severity_modification_type": "",
        }
        for _ in range(n)
    ]
    df = pd.DataFrame(rows)
    df = df.assign(**{
        col: pd.to_datetime(df[col], utc=True, errors="coerce")
        for col in ("last_fixed", "first_found", "resurfaced_date")
    })
    return df


# --- D-15-05: new params accepted and written to new_entry ---


def test_new_aggregate_fields_written(tmp_path):
    """
    capture_snapshot called WITH all new params writes new_entry containing
    those aggregate fields as ints (D-15-05, QUAL-05 aggregate-only).
    """
    df = _open_df_with_states([
        {"state": "open"},
        {"state": "open"},
    ])
    assets_df = _assets_df(n=5)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
        on_time_asset_count=4,
        reopened_count=1,
        accepted_count=2,
        recast_count=3,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert entry["on_time_asset_count"] == 4
    assert entry["reopened_count"] == 1
    assert entry["accepted_count"] == 2
    assert entry["recast_count"] == 3


# --- D-15-06: backward compat — missing new params write None, no crash ---


def test_new_params_default_to_none(tmp_path):
    """
    capture_snapshot called WITHOUT new params writes new_entry with new
    fields as None (D-15-06 backward-compat).
    """
    df = _open_df(n=3)
    assets_df = _assets_df(n=5)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert entry["on_time_asset_count"] is None
    assert entry["reopened_count"] is None
    assert entry["accepted_count"] is None
    assert entry["recast_count"] is None
    assert entry["new_findings_count"] is None
    assert entry["fixed_findings_count"] is None


# --- D-15-06: old snapshot dict without new fields readable without crash ---


def test_old_snapshot_readable_without_new_fields(tmp_path):
    """
    A pre-extension snapshot dict (no new fields) loaded by read_trend is
    readable without error, and snap.get("on_time_asset_count") returns None
    — valid cold-start, no KeyError (D-15-06).
    """
    # Write a hand-built "old" snapshot file that lacks the new Phase-15 keys.
    old_snap = {
        "snapshots": [{
            "month":        "2026-05",
            "tag_filter":   "all_assets",
            "critical":     3,
            "high":         1,
            "medium":       0,
            "low":          0,
            "asset_count":  10,
            "generated_at": "2026-05-01T00:00:00Z",
        }]
    }
    snap_file = tmp_path / "trend_severity_all_assets.json"
    snap_file.write_text(json.dumps(old_snap), encoding="utf-8")

    # read_trend must not raise
    result = read_trend("severity", "all_assets", trend_dir=tmp_path)
    assert len(result["snapshots"]) == 1

    snap = result["snapshots"][0]
    # New-field access via .get() returns None — cold-start safe
    assert snap.get("on_time_asset_count") is None
    assert snap.get("reopened_count") is None


# --- QUAL-05: new fields are ints/None, never DataFrames or lists ---


def test_new_fields_are_ints_or_none(tmp_path):
    """
    New aggregate keys in the written JSON are either Python ints or None —
    never DataFrames, lists, or other complex objects (QUAL-05 / T-15-02-PII).
    """
    df = _open_df_with_states([
        {"state": "REOPENED"},
        {"smt": "ACCEPTED"},
        {"smt": "RECASTED"},
    ])
    fixed = _fixed_df(n=2)
    assets_df = _assets_df(n=7)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 15), "severity", "all_assets",
        trend_dir=tmp_path,
        on_time_asset_count=6,
        reopened_count=1,
        accepted_count=1,
        recast_count=1,
        fixed_vulns_df=fixed,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    new_keys = [
        "on_time_asset_count", "reopened_count", "accepted_count",
        "recast_count", "new_findings_count", "fixed_findings_count",
    ]
    for key in new_keys:
        val = entry[key]
        assert val is None or isinstance(val, int), (
            f"Key {key!r} must be int or None; got {type(val).__name__!r}: {val!r}"
        )


# --- D-15-05: new_findings_count + fixed_findings_count derived correctly ---


def test_new_findings_count_derivation(tmp_path):
    """
    new_findings_count = count of df rows whose first_found month == snapshot month.
    fixed_findings_count = count of fixed_vulns_df rows whose last_fixed month
    == snapshot month AND state == FIXED (case-insensitive).
    """
    snapshot_date = datetime(2026, 6, 15)  # month = 2026-06

    # 3 rows first-found mid-June 2026 (mid-month → same calendar month in any tz,
    # so this asserts intent without sitting on the UTC/local boundary — WR-01).
    june = datetime(2026, 6, 15, tzinfo=timezone.utc)
    df_rows = [
        {"state": "open", "severity": "critical", "first_found": june},
        {"state": "open", "severity": "high",     "first_found": june},
        {"state": "open", "severity": "medium",   "first_found": june},
    ]
    df = _open_df_with_states(df_rows)
    assets_df = _assets_df(n=4)

    fixed = _fixed_df(n=3, month="2026-06")  # 3 fixed in June
    # Add 1 row fixed in May — should NOT count
    may_row = pd.DataFrame([{
        "last_fixed":                datetime(2026, 5, 10, tzinfo=timezone.utc),
        "state":                     "FIXED",
        "severity":                  "low",
        "first_found":               datetime(2026, 1, 1, tzinfo=timezone.utc),
        "resurfaced_date":           None,
        "severity_modification_type": "",
    }])
    may_row = may_row.assign(**{
        col: pd.to_datetime(may_row[col], utc=True, errors="coerce")
        for col in ("last_fixed", "first_found", "resurfaced_date")
    })
    fixed = pd.concat([fixed, may_row], ignore_index=True)

    path = capture_snapshot(
        df, assets_df, snapshot_date, "severity", "all_assets",
        trend_dir=tmp_path,
        fixed_vulns_df=fixed,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert entry["new_findings_count"] == 3, (
        f"Expected 3 new findings in June, got {entry['new_findings_count']}"
    )
    assert entry["fixed_findings_count"] == 3, (
        f"Expected 3 fixed findings in June, got {entry['fixed_findings_count']}"
    )


def test_new_findings_count_buckets_by_local_month(tmp_path):
    """WR-01: a finding first-found late on the last LOCAL day of the month must
    be attributed to that LOCAL month (matching the local month_str label), even
    though its UTC instant falls in the next month on behind-UTC servers.

    The finding is built in the system's local tz at 23:30 on Jun 30, so it is
    June locally on every machine; on a behind-UTC server (e.g. US/Eastern) its
    UTC instant is Jul 1, which the pre-fix code mis-bucketed into July.
    """
    local_tz = datetime.now().astimezone().tzinfo
    snapshot_date = datetime(2026, 6, 30)  # local month = 2026-06

    boundary = datetime(2026, 6, 30, 23, 30, tzinfo=local_tz)
    df = _open_df_with_states([
        {"state": "open", "severity": "critical", "first_found": boundary},
    ])
    assets_df = _assets_df(n=1)
    # fixed_vulns_df must be non-None to trigger new_findings_count derivation;
    # its single June row is irrelevant to the new-count assertion below.
    fixed = _fixed_df(n=1)

    path = capture_snapshot(
        df, assets_df, snapshot_date, "severity", "all_assets",
        trend_dir=tmp_path,
        fixed_vulns_df=fixed,
    )
    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert entry["new_findings_count"] == 1, (
        "boundary finding must bucket into its LOCAL month (2026-06), "
        f"got {entry['new_findings_count']}"
    )


# --- No regression: existing severity+owner dimension snapshots unchanged ---


def test_existing_severity_fields_unchanged(tmp_path):
    """
    Existing severity counts and asset_count are NOT changed by the extension
    (no regression to count_entry / asset_count fields, D-15-06).
    """
    df = _open_df(n=5)
    assets_df = _assets_df(n=10)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
        on_time_asset_count=8,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    # Original fields still present and correct
    assert "critical" in entry
    assert "high" in entry
    assert "medium" in entry
    assert "low" in entry
    assert entry["asset_count"] == 10
    assert "month" in entry
    assert "tag_filter" in entry
    assert "generated_at" in entry


# ---------------------------------------------------------------------------
# Phase 16 Plan 01 — MTTR aggregate persistence (D-16-09, RPT-05)
# ---------------------------------------------------------------------------


def test_mttr_aggregate_fields_written(tmp_path):
    """
    capture_snapshot called WITH mttr_overall_days, mttr_by_severity, and
    mttr_by_owner writes all three keys into the snapshot entry with the
    exact float/dict values supplied (D-16-09, RPT-05).

    Mirrors test_new_aggregate_fields_written (Phase 15 analog).
    MTTR values are floats — the round-trip asserts float identity, not int.
    """
    df = _open_df_with_states([
        {"state": "open"},
        {"state": "open"},
    ])
    assets_df = _assets_df(n=5)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
        mttr_overall_days=14.3,
        mttr_by_severity={"critical": 8.5, "high": 18.0, "medium": 35.2, "low": None},
        mttr_by_owner={"Team Alpha": 12.7, "Team Beta": 22.1},
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]

    # mttr_overall_days: float round-trip
    assert entry["mttr_overall_days"] == 14.3, (
        f"Expected mttr_overall_days=14.3, got {entry['mttr_overall_days']!r}"
    )

    # mttr_by_severity: dict round-trip (includes a None-value key)
    assert isinstance(entry["mttr_by_severity"], dict), (
        f"Expected dict for mttr_by_severity, got {type(entry['mttr_by_severity'])}"
    )
    assert entry["mttr_by_severity"]["critical"] == 8.5
    assert entry["mttr_by_severity"]["high"] == 18.0
    assert entry["mttr_by_severity"]["medium"] == 35.2
    assert entry["mttr_by_severity"]["low"] is None

    # mttr_by_owner: dict round-trip
    assert isinstance(entry["mttr_by_owner"], dict), (
        f"Expected dict for mttr_by_owner, got {type(entry['mttr_by_owner'])}"
    )
    assert entry["mttr_by_owner"]["Team Alpha"] == 12.7
    assert entry["mttr_by_owner"]["Team Beta"] == 22.1


def test_mttr_params_default_to_none(tmp_path):
    """
    capture_snapshot called WITHOUT the three MTTR kwargs writes all three
    keys as explicit None (JSON null) — never missing (D-16-09 implicit-
    optional-field convention so snap.get() returns None, never KeyError).

    Mirrors test_new_params_default_to_none (Phase 15 analog).
    """
    df = _open_df(n=3)
    assets_df = _assets_df(n=5)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert entry["mttr_overall_days"] is None, (
        f"Expected mttr_overall_days=None when not supplied, got {entry['mttr_overall_days']!r}"
    )
    assert entry["mttr_by_severity"] is None, (
        f"Expected mttr_by_severity=None when not supplied, got {entry['mttr_by_severity']!r}"
    )
    assert entry["mttr_by_owner"] is None, (
        f"Expected mttr_by_owner=None when not supplied, got {entry['mttr_by_owner']!r}"
    )


# --- D-16-09: old snapshot without MTTR fields is cold-start-safe ---


def test_old_snapshot_readable_without_mttr_fields(tmp_path):
    """
    A hand-built "old" snapshot dict lacking mttr_overall_days/mttr_by_severity/
    mttr_by_owner, written to disk and loaded via read_trend, reads back cold-
    start-safe: snap.get("mttr_overall_days") is None, and the dict-typed fields
    degrade to empty dict via (snap.get(...) or {}) — never KeyError or TypeError.

    This promotes the D-16-09 contract from the __main__ smoke block into a
    collected pytest test.  Mirrors test_old_snapshot_readable_without_new_fields
    (Phase 15 analog).
    """
    old_snap = {
        "snapshots": [{
            "month":        "2026-05",
            "tag_filter":   "all_assets",
            "critical":     3,
            "high":         1,
            "medium":       0,
            "low":          0,
            "asset_count":  10,
            "generated_at": "2026-05-01T00:00:00Z",
            # NOTE: no mttr_overall_days, mttr_by_severity, mttr_by_owner keys
        }]
    }
    snap_file = tmp_path / "trend_severity_all_assets.json"
    snap_file.write_text(json.dumps(old_snap), encoding="utf-8")

    # read_trend must not raise
    result = read_trend("severity", "all_assets", trend_dir=tmp_path)
    assert len(result["snapshots"]) == 1

    snap = result["snapshots"][0]

    # D-16-09 cold-start access form — never snap["mttr_by_owner"] (KeyError)
    assert snap.get("mttr_overall_days") is None, (
        "Old snapshot must cold-start mttr_overall_days to None (no KeyError)"
    )
    assert (snap.get("mttr_by_severity") or {}) == {}, (
        "Old snapshot must cold-start mttr_by_severity to empty dict (no TypeError)"
    )
    assert (snap.get("mttr_by_owner") or {}) == {}, (
        "Old snapshot must cold-start mttr_by_owner to empty dict (no TypeError)"
    )


# ---------------------------------------------------------------------------
# Phase 17 Plan 01 — SLA-posture aggregate persistence (D-17-04, RPT-07)
# ---------------------------------------------------------------------------


def test_sla_rate_crit_high_roundtrip(tmp_path):
    """
    capture_snapshot called WITH sla_rate_crit_high writes the float into the
    snapshot entry and reads it back with the exact value supplied (D-17-04,
    RPT-07).

    Mirrors test_mttr_aggregate_fields_written (Phase 16 analog).
    sla_rate_crit_high is a float percentage 0–100 — round-trip asserts float
    identity, not int.
    """
    df = _open_df_with_states([
        {"state": "open"},
        {"state": "open"},
    ])
    assets_df = _assets_df(n=5)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
        sla_rate_crit_high=87.3,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]

    assert entry["sla_rate_crit_high"] == 87.3, (
        f"Expected sla_rate_crit_high=87.3, got {entry['sla_rate_crit_high']!r}"
    )


def test_sla_rate_params_default_to_none(tmp_path):
    """
    capture_snapshot called WITHOUT sla_rate_crit_high writes the key as
    explicit None (JSON null) — never missing (D-17-04 implicit-optional-field
    convention so snap.get() returns None, never KeyError).

    Mirrors test_mttr_params_default_to_none (Phase 16 analog).
    """
    df = _open_df(n=3)
    assets_df = _assets_df(n=5)

    path = capture_snapshot(
        df, assets_df, datetime(2026, 6, 1), "severity", "all_assets",
        trend_dir=tmp_path,
    )

    entry = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert entry["sla_rate_crit_high"] is None, (
        f"Expected sla_rate_crit_high=None when not supplied, got {entry['sla_rate_crit_high']!r}"
    )


def test_sla_rate_backward_compat(tmp_path):
    """
    A hand-built "old" snapshot dict lacking sla_rate_crit_high, written to disk
    and loaded via read_trend, reads back cold-start-safe: snap.get(
    "sla_rate_crit_high") is None — never KeyError.

    This promotes the D-17-04 backward-compat contract from the __main__ smoke
    block into a collected pytest test.  Mirrors
    test_old_snapshot_readable_without_mttr_fields (Phase 16 analog).
    """
    old_snap = {
        "snapshots": [{
            "month":        "2026-05",
            "tag_filter":   "all_assets",
            "critical":     3,
            "high":         1,
            "medium":       0,
            "low":          0,
            "asset_count":  10,
            "generated_at": "2026-05-01T00:00:00Z",
            # NOTE: no sla_rate_crit_high key — simulates a pre-Phase-17 snapshot
        }]
    }
    snap_file = tmp_path / "trend_severity_all_assets.json"
    snap_file.write_text(json.dumps(old_snap), encoding="utf-8")

    # read_trend must not raise
    result = read_trend("severity", "all_assets", trend_dir=tmp_path)
    assert len(result["snapshots"]) == 1

    snap = result["snapshots"][0]

    # D-17-04 cold-start access form — never snap["sla_rate_crit_high"] (KeyError)
    assert snap.get("sla_rate_crit_high") is None, (
        "Old snapshot must cold-start sla_rate_crit_high to None (no KeyError)"
    )


# ---------------------------------------------------------------------------
# CR-B6: present-but-empty fixed_vulns_df writes fixed_findings_count == 0
# ---------------------------------------------------------------------------


def test_fixed_findings_count_explicit_zero_when_empty_df(tmp_path):
    """
    CR-B6: capture_snapshot with a present-but-empty fixed_vulns_df must write
    fixed_findings_count == 0 (explicit int), not None.

    Empty != missing: a caller that passes an empty DataFrame is signalling
    "we looked, nothing was fixed this month".  Leaving the field as None
    would conflate "empty" with "caller did not supply fixed data at all".
    """
    df = _open_df(n=3)
    assets_df = _assets_df(n=2)
    empty_fixed_df = pd.DataFrame(
        columns=["last_fixed", "first_found", "state", "severity",
                 "resurfaced_date"]
    )

    path = capture_snapshot(
        df, assets_df,
        datetime(2026, 6, 1, tzinfo=timezone.utc),
        "severity", "all_assets",
        fixed_vulns_df=empty_fixed_df,
        trend_dir=tmp_path,
    )
    snap = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]

    assert snap["fixed_findings_count"] == 0, (
        "CR-B6: present-but-empty fixed_vulns_df must write fixed_findings_count=0, not None"
    )
    assert isinstance(snap["fixed_findings_count"], int), (
        "CR-B6: fixed_findings_count must be int (0), not None"
    )


# ---------------------------------------------------------------------------
# CR-B7 + WR-07: _load_trend_json validates shape and renames corrupt files
# ---------------------------------------------------------------------------


def test_load_trend_json_bare_list_is_corrupt(tmp_path):
    """
    CR-B7/WR-07: a JSON file whose root is a bare list (not a dict) must be
    renamed to *.corrupt and _load_trend_json must return [].
    """
    from data.trend_store import _load_trend_json

    bad_file = tmp_path / "trend_severity_all_assets.json"
    bad_file.write_text(json.dumps([{"month": "2026-01"}]), encoding="utf-8")

    result = _load_trend_json(bad_file)

    assert result == [], "CR-B7: bare-list root must return []"
    assert not bad_file.exists(), "CR-B7: corrupt file must be renamed away"
    corrupt = bad_file.with_suffix(bad_file.suffix + ".corrupt")
    assert corrupt.exists(), "CR-B7: *.corrupt rename must exist"


def test_load_trend_json_non_list_snapshots_is_corrupt(tmp_path):
    """
    CR-B7/WR-07: a JSON file with a dict root but non-list 'snapshots' value
    must be renamed to *.corrupt and return [].
    """
    from data.trend_store import _load_trend_json

    bad_file = tmp_path / "trend_severity_all_assets.json"
    bad_file.write_text(
        json.dumps({"snapshots": "not-a-list"}), encoding="utf-8"
    )

    result = _load_trend_json(bad_file)

    assert result == [], "CR-B7: non-list snapshots must return []"
    assert not bad_file.exists(), "CR-B7: corrupt file must be renamed away"


def test_load_trend_json_non_dict_snapshot_entry_is_corrupt(tmp_path):
    """
    CR-B7/WR-07: a JSON file whose 'snapshots' list contains a non-dict entry
    (e.g. a bare string or int) must be renamed to *.corrupt and return [].
    """
    from data.trend_store import _load_trend_json

    bad_file = tmp_path / "trend_severity_all_assets.json"
    bad_file.write_text(
        json.dumps({"snapshots": [{"month": "2026-01"}, "oops", 42]}),
        encoding="utf-8",
    )

    result = _load_trend_json(bad_file)

    assert result == [], "CR-B7: non-dict entry in snapshots must return []"
    assert not bad_file.exists(), "CR-B7: corrupt file must be renamed away"


# ---------------------------------------------------------------------------
# WR-06: month key uses local time (not UTC) even for UTC-aware input date
# ---------------------------------------------------------------------------


def test_capture_snapshot_month_key_uses_local_time(tmp_path):
    """
    WR-06: capture_snapshot must derive month_str from local time so a
    UTC-aware datetime near a month boundary on a non-UTC server is attributed
    to the correct local month.

    We use 2026-05-31T23:30:00Z.  On a UTC+1 server this is 2026-06-01 00:30
    local → month key "2026-06".  On UTC it stays "2026-05".  The test asserts
    that the written month_str matches what date.astimezone().strftime('%Y-%m')
    produces — i.e. the same local-time derivation capture_snapshot now uses.
    """
    import datetime as _dt

    utc_date = _dt.datetime(2026, 5, 31, 23, 30, 0, tzinfo=_dt.timezone.utc)
    expected_month = utc_date.astimezone().strftime("%Y-%m")

    df = _open_df(n=2)
    assets_df = _assets_df(n=1)

    path = capture_snapshot(
        df, assets_df, utc_date, "severity", "all_assets",
        trend_dir=tmp_path,
    )
    snap = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]

    assert snap["month"] == expected_month, (
        f"WR-06: month key must be local-time {expected_month!r}, "
        f"got {snap['month']!r}"
    )


# ---------------------------------------------------------------------------
# WR-05: read_trend flags the current-local-month newest entry as partial
# ---------------------------------------------------------------------------


def test_read_trend_flags_current_month_as_partial(tmp_path):
    """
    WR-05: when the newest snapshot's 'month' equals the current server-local
    month, read_trend must set partial=True on that entry so MoM delta math
    can exclude the partial month-to-date point instead of treating it as a
    completed latest point.

    The current-month detection uses datetime.now().strftime('%Y-%m') — the
    same local-time convention capture_snapshot uses (WR-06 / CLAUDE.md).
    """
    current_month = datetime.now().strftime("%Y-%m")
    prior_month = "2025-01"  # always in the past

    snap_data = {
        "snapshots": [
            {
                "month": prior_month,
                "tag_filter": "all_assets",
                "critical": 5, "high": 3, "medium": 2, "low": 1,
                "asset_count": 10,
                "generated_at": "2025-01-01T00:00:00Z",
            },
            {
                "month": current_month,
                "tag_filter": "all_assets",
                "critical": 6, "high": 4, "medium": 2, "low": 1,
                "asset_count": 10,
                "generated_at": "2026-01-01T00:00:00Z",
            },
        ]
    }
    snap_file = tmp_path / "trend_severity_all_assets.json"
    snap_file.write_text(json.dumps(snap_data), encoding="utf-8")

    result = read_trend("severity", "all_assets", months=12, trend_dir=tmp_path)
    snaps = result["snapshots"]

    # Newest entry (current month) must be flagged partial
    newest = snaps[-1]
    assert newest["month"] == current_month, "Newest entry must be the current month"
    assert newest.get("partial") is True, (
        "WR-05: current-local-month newest entry must carry partial=True"
    )

    # Prior entry must NOT be flagged partial
    prior = snaps[0]
    assert prior["month"] == prior_month
    assert not prior.get("partial"), (
        "WR-05: prior completed month must not carry partial=True"
    )
