"""
tests/test_trend_store.py — Store-level contract tests for data/trend_store.py.

Phase 18 Plan 04 (review change #11, D-18-11):
    test_read_trend_ignores_legacy_archive — the authoritative store-level
    contract test asserting that read_trend() does NOT traverse or ingest
    files stored under TREND_DIR/legacy_archive/.

    When the management_summary atomic cutover (Task 2) archives legacy
    management_summary_*.json files to data/trend/legacy_archive/, read_trend()
    must ignore them so the incompatible legacy JSON shape (flat dict with
    per-metric keys, not the {"snapshots": [...]} envelope) does not corrupt
    the active pipeline or trigger cold-start failures (T-18-13c).

    This is the authoritative store-level contract.
    tests/test_management_summary.py::test_read_trend_ignores_legacy_archive_integration
    is an integration echo that verifies the same property from the
    management_summary wiring layer.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from data.trend_store import read_trend


# ---------------------------------------------------------------------------
# Store-level contract: legacy_archive/ non-traversal
# ---------------------------------------------------------------------------

def test_read_trend_ignores_legacy_archive() -> None:
    """
    read_trend() must NOT traverse into TREND_DIR/legacy_archive/ (D-18-11).

    Setup:
      1. A valid ``trend_severity_all_assets.json`` is placed directly in
         trend_dir (the active file with 2 properly-shaped snapshots).
      2. An INCOMPATIBLE-shape file is placed in trend_dir/legacy_archive/.
         The legacy shape is a flat JSON dict (not ``{"snapshots": [...]}``)
         matching the pre-migration management_summary_*.json format.
         If read_trend() traverses the subdir, _load_trend_json() would parse
         it differently from a corrupt-file or return empty, and the result
         would either error or differ from what the active file alone provides.

    Assertions:
      - ``insufficient_data`` is False (2 active snapshots ≥ threshold).
      - Exactly 2 snapshots are returned (the active-file ones only).
      - The returned months match the active-file months exactly.
      - No error is raised during the call (legacy file does not blow up the read).

    This test is the complement to test_management_summary.py's
    test_read_trend_ignores_legacy_archive_integration.
    """
    with tempfile.TemporaryDirectory() as tmp:
        trend_dir = Path(tmp)

        # -- Active snapshot file (valid shape) --
        active_file = trend_dir / "trend_severity_all_assets.json"
        active_snapshots = [
            {
                "month": "2026-04",
                "tag_filter": "all_assets",
                "critical": 10,
                "high": 7,
                "medium": 5,
                "low": 2,
                "asset_count": 20,
                "generated_at": "2026-04-01T10:00:00Z",
            },
            {
                "month": "2026-05",
                "tag_filter": "all_assets",
                "critical": 8,
                "high": 6,
                "medium": 4,
                "low": 2,
                "asset_count": 20,
                "generated_at": "2026-05-01T10:00:00Z",
            },
        ]
        active_file.write_text(
            json.dumps({"snapshots": active_snapshots}),
            encoding="utf-8",
        )

        # -- Legacy-archive file (INCOMPATIBLE shape) --
        # Simulates a pre-migration management_summary_*.json that was a flat
        # dict with per-metric keys, not the {"snapshots":[...]} envelope.
        # If read_trend() tried to read this as a trend file, it would either
        # mis-parse it or trigger the corrupt-file rename branch.
        legacy_dir = trend_dir / "legacy_archive"
        legacy_dir.mkdir()
        legacy_file = legacy_dir / "management_summary_2026-05.json"
        # A bare list is the most disruptive shape: _load_trend_json() calls
        # data.get("snapshots", []) which raises AttributeError on a list,
        # triggering the corrupt-file rename + returning [] — but ONLY if
        # the file is traversed in the first place.
        legacy_file.write_text(
            json.dumps([
                {"metric_1": {"critical": 99, "high": 50}},
                {"metric_2": {"coverage_pct": 100.0}},
            ]),
            encoding="utf-8",
        )

        # -- Call read_trend with the tmp dir --
        result = read_trend(
            dimension="severity",
            tag_filter="all_assets",
            months=13,
            trend_dir=trend_dir,
        )

        # -- Assertions --
        assert not result["insufficient_data"], (
            "read_trend() reported insufficient_data=True despite 2 active "
            "snapshots in the active file. Either the active file was not read "
            "correctly, or legacy_archive/ interference caused an error."
        )

        snaps = result["snapshots"]
        assert len(snaps) == 2, (
            f"Expected exactly 2 snapshots (from the active file only); "
            f"got {len(snaps)}. "
            f"If >2: legacy_archive/ content is being ingested. "
            f"If 0: the active file was not read (possible subdir traversal side-effect). "
            f"Snapshots: {snaps}"
        )

        returned_months = {s["month"] for s in snaps}
        assert returned_months == {"2026-04", "2026-05"}, (
            f"Unexpected snapshot months: {returned_months}. "
            f"Expected only the active-file months {{2026-04, 2026-05}}."
        )

        # Confirm no legacy-archive data leaked into the snapshots
        for snap in snaps:
            assert "metric_1" not in snap, (
                f"Legacy-archive data leaked into snapshot: {snap}"
            )
            assert snap.get("asset_count") == 20, (
                f"Snapshot has unexpected asset_count (may be from legacy file): {snap}"
            )


def test_read_trend_legacy_archive_does_not_raise() -> None:
    """
    read_trend() must not raise even when legacy_archive/ contains a
    malformed file with an incompatible JSON structure.

    Regression guard: if read_trend() ever starts traversing subdirectories,
    the incompatible shape would cause _load_trend_json() to trigger the
    corrupt-file rename branch (which calls path.replace(...)) — a side effect
    observable as the legacy file being renamed to *.corrupt. This test confirms
    the side effect does NOT occur (the legacy file is unmolested).
    """
    with tempfile.TemporaryDirectory() as tmp:
        trend_dir = Path(tmp)

        # Create active file with 1 snapshot (insufficient_data=True — ok for this test)
        active_file = trend_dir / "trend_severity_all_assets.json"
        active_file.write_text(
            json.dumps({"snapshots": [
                {
                    "month": "2026-05",
                    "tag_filter": "all_assets",
                    "critical": 3, "high": 2, "medium": 1, "low": 0,
                    "asset_count": 5,
                    "generated_at": "2026-05-01T00:00:00Z",
                }
            ]}),
            encoding="utf-8",
        )

        # Malformed legacy file
        legacy_dir = trend_dir / "legacy_archive"
        legacy_dir.mkdir()
        legacy_file = legacy_dir / "management_summary_2026-05.json"
        legacy_file.write_text(
            json.dumps([{"bad": "shape"}]),
            encoding="utf-8",
        )

        # Must not raise
        result = read_trend(
            "severity", "all_assets", months=13, trend_dir=trend_dir
        )

        # The legacy file must be UNMOLESTED — not renamed to *.corrupt
        assert legacy_file.exists(), (
            "Legacy archive file was renamed/corrupted — this means read_trend() "
            "traversed into legacy_archive/ and triggered the corrupt-file handler. "
            "Fix: scope read_trend() to files directly in trend_dir, not subdirs."
        )

        # Exactly 1 snapshot (from the active file)
        assert len(result["snapshots"]) == 1
        assert result["insufficient_data"] is True  # only 1 snap < 2 threshold
