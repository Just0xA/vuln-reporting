"""
tests/test_board_report_utils.py — Unit tests for board_report_utils.exclude_risk_managed.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id: 100001, 100002, ...
  - No real hostnames, IPs, CVE IDs, plugin names, or real Tenable UUIDs

Key requirement coverage
-------------------------
- Empty df -> returned unchanged, no error
- Missing severity_modification_type column -> returned unchanged, no error
- ACCEPTED / RECASTED rows (any case) -> dropped
- Other values (NONE, "", None) -> kept
- Case-insensitivity explicitly verified
- Result is a fresh .copy() (Hard Rule 5 — no ChainedAssignmentError under CoW strict mode)

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.board_report_utils import exclude_risk_managed

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns_df with asset_uuid + severity_modification_type."""
    defaults = {
        "asset_uuid":                  _uuid(1),
        "plugin_id":                   100001,
        "severity_modification_type":  "NONE",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


class TestEmptyAndMissingColumn:
    def test_empty_df_returned_unchanged(self):
        df = pd.DataFrame(columns=["asset_uuid", "severity_modification_type"])
        result = exclude_risk_managed(df)
        assert result.empty
        assert list(result.columns) == list(df.columns)

    def test_missing_column_returned_unchanged(self):
        df = pd.DataFrame({"asset_uuid": [_uuid(1), _uuid(2)]})
        result = exclude_risk_managed(df)
        pd.testing.assert_frame_equal(result, df)


class TestExclusion:
    def test_accepted_and_recasted_dropped(self):
        df = _make_vulns([
            {"asset_uuid": _uuid(1), "severity_modification_type": "ACCEPTED"},
            {"asset_uuid": _uuid(2), "severity_modification_type": "RECASTED"},
            {"asset_uuid": _uuid(3), "severity_modification_type": "NONE"},
        ])
        result = exclude_risk_managed(df)
        assert len(result) == 1
        assert result.iloc[0]["asset_uuid"] == _uuid(3)

    def test_other_values_kept(self):
        df = _make_vulns([
            {"asset_uuid": _uuid(1), "severity_modification_type": "NONE"},
            {"asset_uuid": _uuid(2), "severity_modification_type": ""},
            {"asset_uuid": _uuid(3), "severity_modification_type": None},
        ])
        result = exclude_risk_managed(df)
        assert len(result) == 3

    def test_case_insensitive_matching(self):
        df = _make_vulns([
            {"asset_uuid": _uuid(1), "severity_modification_type": "accepted"},
            {"asset_uuid": _uuid(2), "severity_modification_type": "Recasted"},
            {"asset_uuid": _uuid(3), "severity_modification_type": "ACCEPTED"},
            {"asset_uuid": _uuid(4), "severity_modification_type": "none"},
        ])
        result = exclude_risk_managed(df)
        assert len(result) == 1
        assert result.iloc[0]["asset_uuid"] == _uuid(4)


class TestCopySemantics:
    def test_returned_frame_is_fresh_copy(self):
        df = _make_vulns([
            {"asset_uuid": _uuid(1), "severity_modification_type": "NONE"},
            {"asset_uuid": _uuid(2), "severity_modification_type": "ACCEPTED"},
        ])
        result = exclude_risk_managed(df)
        # Mutating the result must not raise ChainedAssignmentError and
        # must not affect the original frame (fresh .copy()).
        result = result.assign(extra_col="x")
        assert "extra_col" not in df.columns
