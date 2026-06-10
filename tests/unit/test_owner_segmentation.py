"""
tests/unit/test_owner_segmentation.py — Unit tests for Owner-primary segmentation.

Covers SEG-01, SEG-02, SEG-04 from Phase 13 requirements:
  SEG-01: extract_owner returns per-Owner buckets whose counts sum to total row count
          (reconcile-to-whole invariant; D-01, D-03)
  SEG-02: Assets with no Owner tag land in a single Unassigned bucket (D-06);
          "Untagged" is eliminated
  SEG-04: extract_owner does not raise when the tags column is absent — all rows
          fall into the Unassigned bucket (D-07)

Also asserts D-04 (owner column, not business_unit), D-05 (application nested column).

These tests are written BEFORE the implementation (TDD RED state) and will fail
with ImportError / AttributeError until board_report_utils.py is generalised.
"""

from __future__ import annotations

import pandas as pd
import pytest

from reports.modules.board_report_utils import (
    OWNER_TAG_CATEGORY,
    compute_per_bu_breakdown,
    extract_owner,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_assets_df() -> pd.DataFrame:
    """
    Hand-built assets DataFrame with known tag combinations.

    Row 0: dual-tagged — has both Owner and Application tags
    Row 1: Owner only (no Application tag)
    Row 2: Application only (no Owner tag) — must become "Unassigned"
    Row 3: empty tags string "" — must become "Unassigned"
    Row 4: tags is None — must become "Unassigned"
    """
    return pd.DataFrame(
        {
            "asset_uuid": ["a1", "a2", "a3", "a4", "a5"],
            "hostname": ["host1", "host2", "host3", "host4", "host5"],
            "tags": [
                "Owner=Network Defense;Application=Finance",  # row 0: both
                "Owner=Infra",                                # row 1: owner only
                "Application=Finance",                        # row 2: app only -> Unassigned
                "",                                           # row 3: empty string -> Unassigned
                None,                                         # row 4: None -> Unassigned
            ],
        }
    )


# ---------------------------------------------------------------------------
# Tests — SEG-01/02/04 core invariants
# ---------------------------------------------------------------------------


def test_owner_buckets_reconcile_to_whole():
    """SEG-01/02: owner value_counts() sum equals total row count."""
    df = _make_assets_df()
    result = extract_owner(df)
    assert "owner" in result.columns
    assert result["owner"].value_counts().sum() == len(df)


def test_no_owner_tag_is_unassigned():
    """SEG-02/D-06: assets with no Owner tag have owner == 'Unassigned'; 'Untagged' absent."""
    df = _make_assets_df()
    result = extract_owner(df)

    # Rows 2, 3, 4 have no Owner tag — all must be "Unassigned"
    no_owner_rows = result.iloc[[2, 3, 4]]
    assert (no_owner_rows["owner"] == "Unassigned").all(), (
        "Expected all no-Owner rows to be 'Unassigned'; "
        f"got: {no_owner_rows['owner'].tolist()}"
    )

    # "Untagged" must be completely absent
    assert "Untagged" not in result["owner"].values, (
        "Found 'Untagged' in owner column — must be 'Unassigned' everywhere"
    )


def test_application_column_populated():
    """D-05: extract_owner also populates the 'application' column from the Application tag."""
    df = _make_assets_df()
    result = extract_owner(df)

    assert "application" in result.columns, "expected 'application' column in output"

    # Row 0: dual-tagged — application should be "Finance"
    assert result.iloc[0]["application"] == "Finance", (
        f"expected 'Finance' for dual-tagged asset, got {result.iloc[0]['application']!r}"
    )

    # Row 1: owner-only — application should be empty string
    assert result.iloc[1]["application"] == "", (
        f"expected '' for owner-only asset, got {result.iloc[1]['application']!r}"
    )


def test_missing_tags_column_fail_soft():
    """SEG-04/D-07: extract_owner does not raise when the tags column is absent."""
    df_no_tags = pd.DataFrame({"asset_uuid": ["x", "y"]})

    # Must NOT raise
    result = extract_owner(df_no_tags)

    assert "owner" in result.columns
    assert (result["owner"] == "Unassigned").all(), (
        f"expected all-Unassigned owner on missing-column frame, got: {result['owner'].tolist()}"
    )
    assert "application" in result.columns
    assert (result["application"] == "").all()


def test_output_has_owner_not_business_unit():
    """D-04/Pitfall 2: extract_owner output has 'owner' column and no 'business_unit' column."""
    df = _make_assets_df()
    result = extract_owner(df)

    assert "owner" in result.columns, "missing 'owner' column in extract_owner output"
    assert "business_unit" not in result.columns, (
        "'business_unit' column must be absent from extract_owner output (D-04)"
    )


def test_configurable_unassigned_label():
    """D-06: extract_owner honors unassigned_label override."""
    df = _make_assets_df()
    result = extract_owner(df, unassigned_label="No Owner")

    # Rows 2, 3, 4 have no Owner tag — must use the custom label
    no_owner_rows = result.iloc[[2, 3, 4]]
    assert (no_owner_rows["owner"] == "No Owner").all(), (
        f"expected 'No Owner' label; got: {no_owner_rows['owner'].tolist()}"
    )

    # The default "Unassigned" must NOT appear when an override is set
    assert "Unassigned" not in result["owner"].values


# ---------------------------------------------------------------------------
# Tests — compute_per_bu_breakdown output column (D-04)
# ---------------------------------------------------------------------------


def test_breakdown_output_column_is_owner():
    """D-04/Pitfall 2: compute_per_bu_breakdown returns 'owner' column, not 'business_unit'."""
    # Build a small frame that already has an owner column
    df = pd.DataFrame(
        {
            "asset_uuid": ["a1", "a2", "a3", "a4"],
            "owner": ["TeamA", "TeamA", "TeamB", "Unassigned"],
        }
    )
    numerator_mask = pd.Series([True, False, True, False], index=df.index)
    denominator_mask = pd.Series([True, True, True, True], index=df.index)

    result = compute_per_bu_breakdown(df, numerator_mask, denominator_mask, bu_column="owner")

    assert "owner" in result.columns, (
        "compute_per_bu_breakdown must return 'owner' column (D-04)"
    )
    assert "business_unit" not in result.columns, (
        "'business_unit' must be absent from compute_per_bu_breakdown output (D-04)"
    )


# ---------------------------------------------------------------------------
# Constant sanity check
# ---------------------------------------------------------------------------


def test_owner_tag_category_constant():
    """OWNER_TAG_CATEGORY must be 'Owner' (D-01)."""
    assert OWNER_TAG_CATEGORY == "Owner"
