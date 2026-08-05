"""
tests/test_board_report_utils.py — Unit tests for board_report_utils helpers.

Covers ``exclude_risk_managed`` (quick-260722-lx9) and the VPR-only severity
tiering helpers ``vpr_severity_tier`` / ``add_vpr_severity`` (quick-260805-ezo).

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id: 100001, 100002, ...
  - No real hostnames, IPs, CVE IDs, plugin names, or real Tenable UUIDs

Key requirement coverage
-------------------------
exclude_risk_managed:
- Empty df -> returned unchanged, no error
- Missing severity_modification_type column -> returned unchanged, no error
- ACCEPTED / RECASTED rows (any case) -> dropped
- Other values (NONE, "", None) -> kept
- Case-insensitivity explicitly verified
- Result is a fresh .copy() (Hard Rule 5 — no ChainedAssignmentError under CoW strict mode)

vpr_severity_tier / add_vpr_severity (quick-260805-ezo):
- Tier boundaries 9.0 / 7.0 / 4.0 / 0.1 exactly as specified
- 0.0 / None / NaN / "" / "abc" / negative -> VPR_NONE_LABEL ("none")
- Numeric strings parse (object-dtype parquet round-trip tolerance)
- add_vpr_severity returns a NEW frame; the caller's frame is unmodified
- Missing vpr_score column -> every row "none", no exception
- Empty frame -> empty frame that still carries the vpr_severity column
- The vectorised add_vpr_severity path agrees with the scalar
  vpr_severity_tier path on every probed value
- CoW regression: calling add_vpr_severity on a filtered slice emits no
  ChainedAssignmentError / FutureWarning originating from reports/

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import warnings

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

from reports.modules.board_report_utils import (
    VPR_NONE_LABEL,
    add_vpr_severity,
    exclude_risk_managed,
    vpr_severity_tier,
)

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


# ===========================================================================
# quick-260805-ezo — VPR-only severity tiering
# ===========================================================================

#: Probe grid used by both the scalar-boundary tests and the
#: vectorised-vs-scalar agreement test.
_TIER_CASES: list[tuple[object, str]] = [
    # critical
    (10.0, "critical"),
    (9.5, "critical"),
    (9.0, "critical"),
    # high
    (8.9, "high"),
    (7.5, "high"),
    (7.0, "high"),
    # medium
    (6.9, "medium"),
    (5.0, "medium"),
    (4.0, "medium"),
    # low
    (3.9, "low"),
    (1.0, "low"),
    (0.1, "low"),
    # none
    (0.0, VPR_NONE_LABEL),
    (-1.0, VPR_NONE_LABEL),
    (None, VPR_NONE_LABEL),
    (float("nan"), VPR_NONE_LABEL),
    ("", VPR_NONE_LABEL),
    ("abc", VPR_NONE_LABEL),
    # numeric strings — parquet round-trips can yield object dtype
    ("9.5", "critical"),
    ("7.0", "high"),
    ("4.0", "medium"),
    ("0.1", "low"),
    ("0.0", VPR_NONE_LABEL),
]


class TestVprSeverityTier:
    @pytest.mark.parametrize("score,expected", _TIER_CASES)
    def test_tier_boundaries(self, score, expected):
        assert vpr_severity_tier(score) == expected, (
            f"vpr_severity_tier({score!r}) should be {expected!r}"
        )

    def test_none_label_constant_value(self):
        # VPR "none" is a distinct concept from native-CVSS "info" (D-02).
        assert VPR_NONE_LABEL == "none"


def _vpr_frame(scores: list) -> pd.DataFrame:
    """Build a minimal findings frame carrying only asset_uuid + vpr_score."""
    return pd.DataFrame({
        "asset_uuid": [_uuid(i % 10) for i in range(len(scores))],
        "vpr_score":  scores,
    })


class TestAddVprSeverity:
    def test_adds_column_without_mutating_input(self):
        df     = _vpr_frame([9.5, 7.0, 4.0, 0.1, 0.0])
        result = add_vpr_severity(df)

        assert "vpr_severity" not in df.columns, (
            "add_vpr_severity must not add a column to the caller's frame"
        )
        assert list(result["vpr_severity"]) == [
            "critical", "high", "medium", "low", VPR_NONE_LABEL,
        ]

    def test_missing_vpr_score_column_all_none(self):
        df = pd.DataFrame({
            "asset_uuid": [_uuid(1), _uuid(2)],
            "severity":   ["critical", "high"],
        })
        result = add_vpr_severity(df)

        assert list(result["vpr_severity"]) == [VPR_NONE_LABEL, VPR_NONE_LABEL]
        assert "vpr_severity" not in df.columns

    def test_empty_frame_still_carries_column(self):
        df     = pd.DataFrame(columns=["asset_uuid", "vpr_score"])
        result = add_vpr_severity(df)

        assert result.empty
        assert "vpr_severity" in result.columns

    def test_empty_frame_missing_column_still_carries_column(self):
        df     = pd.DataFrame(columns=["asset_uuid"])
        result = add_vpr_severity(df)

        assert result.empty
        assert "vpr_severity" in result.columns

    def test_vectorised_path_agrees_with_scalar_path(self):
        # The vectorised implementation must agree with vpr_severity_tier()
        # on every probed value — the plan requires the two paths be provably
        # identical when add_vpr_severity is vectorised.
        scores   = [case[0] for case in _TIER_CASES]
        expected = [case[1] for case in _TIER_CASES]

        result = add_vpr_severity(_vpr_frame(scores))

        assert list(result["vpr_severity"]) == expected
        assert list(result["vpr_severity"]) == [
            vpr_severity_tier(s) for s in scores
        ]

    def test_object_dtype_column_handled(self):
        # Mixed object dtype (string + float + None) — the shape parquet
        # round-trips can produce.
        df     = _vpr_frame(["9.5", 7.0, None, "abc"])
        result = add_vpr_severity(df)

        assert list(result["vpr_severity"]) == [
            "critical", "high", VPR_NONE_LABEL, VPR_NONE_LABEL,
        ]


class TestAddVprSeverityCoW:
    """
    Hard Rule 5 regression — add_vpr_severity must use .assign() so calling
    it on a filtered/sliced frame never raises ChainedAssignmentError nor
    emits a CoW FutureWarning from reports/.

    Warning filtering follows the Phase 16-03 fixture-isolation pattern:
    only warnings whose originating file lives under reports/ are treated
    as failures, so fixture-side pandas noise cannot produce a false positive.
    """

    def test_no_cow_warning_on_sliced_frame(self):
        df    = _vpr_frame([9.5, 7.0, 4.0, 0.1, 0.0, None])
        # Deliberately operate on a filtered SLICE (the CoW trap).
        slice_ = df[df["vpr_score"].notna()]

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = add_vpr_severity(slice_)

        reports_warnings = [
            w for w in caught
            if "reports/" in str(w.filename).replace("\\", "/")
        ]
        assert not reports_warnings, (
            "add_vpr_severity emitted CoW/Chained-assignment warnings from "
            f"reports/: {[str(w.message) for w in reports_warnings]}"
        )
        assert list(result["vpr_severity"]) == [
            "critical", "high", "medium", "low", VPR_NONE_LABEL,
        ]
        assert "vpr_severity" not in slice_.columns
