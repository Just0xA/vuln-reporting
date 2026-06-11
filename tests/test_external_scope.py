"""
tests/test_external_scope.py — Unit tests for utils/external_scope.py classifier.

Covers:
  - is_public_ipv4: RFC1918, CGNAT, loopback, link-local, IPv6 link-local,
    malformed, and (via monkeypatch) positive external case (D-18).
  - external_scope: tag-authoritative classification (Location=External/DMZ),
    public-IP gap detection (D-05/D-08), DMZ+private not-a-mismatch (D-06),
    empty-input guard (QUAL-03), missing-column fail-soft.

Synthetic data only (QUAL-05 / D-11):
  - Hostnames: *.example.invalid (RFC 6761)
  - Asset UUIDs: 00000000-0000-0000-0000-00000000000N form
  - Positive external case uses monkeypatched is_global (D-18) — RFC 5737
    doc ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) return is_global=False
    and CANNOT serve as positive external fixtures.

Run: pytest tests/test_external_scope.py -x -q
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pandas as pd
import pytest

# Enable pandas CoW strict mode to catch chained-assignment regressions
# in external_scope.py during test execution.
pd.options.mode.copy_on_write = True

# Make the project root importable.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utils.external_scope import external_scope, is_public_ipv4  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID = "00000000-0000-0000-0000-{:012d}".format


def _make_assets(*rows: dict) -> pd.DataFrame:
    """Build a minimal assets DataFrame from row dicts with 'tags' and 'ipv4'."""
    records = []
    for i, row in enumerate(rows):
        records.append({
            "asset_uuid": _UUID(i + 1),
            "hostname":   f"host{i + 1}.example.invalid",
            "ipv4":       row.get("ipv4", ""),
            "tags":       row.get("tags", ""),
        })
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# is_public_ipv4 — negative cases (no monkeypatching needed)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip_str, expected", [
    # RFC 1918 private ranges
    ("10.0.0.1",        False),
    ("10.255.255.255",  False),
    ("172.16.0.1",      False),
    ("172.31.255.255",  False),
    ("192.168.0.1",     False),
    ("192.168.1.1",     False),
    # CGNAT — 100.64.0.0/10 (RFC 6598); is_global=False per Python stdlib
    ("100.64.0.1",      False),
    ("100.127.255.255", False),
    # Loopback
    ("127.0.0.1",       False),
    ("127.255.255.255", False),
    # Link-local (IPv4)
    ("169.254.0.1",     False),
    ("169.254.255.255", False),
    # IPv6 link-local — version != 4, so always False
    ("fe80::1",         False),
    ("fe80::dead:beef", False),
    # Malformed / empty / None
    ("not-an-ip",       False),
    ("",                False),
    (None,              False),
    ("999.999.999.999", False),
    ("0.0.0.0",         False),
])
def test_is_public_ipv4_negatives(ip_str, expected):
    """is_public_ipv4 returns False for all non-globally-routable inputs."""
    assert is_public_ipv4(ip_str) is expected


def test_is_public_ipv4_positive_monkeypatched(monkeypatch):
    """
    is_public_ipv4 returns True when is_global reports True.

    D-18: RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
    return is_global=False and CANNOT serve as a positive fixture. We monkeypatch
    ipaddress.ip_address so the classifier sees is_global=True without embedding
    any real public IP literal in the test suite.
    """
    class _FakeAddr:
        version = 4
        is_global = True

    # Monkeypatch at the module level where is_public_ipv4 calls ipaddress.ip_address
    monkeypatch.setattr("utils.external_scope.ipaddress.ip_address", lambda _: _FakeAddr())
    # Use a synthetic address — the monkeypatch makes the actual value irrelevant
    assert is_public_ipv4("192.0.2.1") is True  # doc range, normally False; returns True via patch


# ---------------------------------------------------------------------------
# external_scope — tag-authoritative classification
# ---------------------------------------------------------------------------

def test_external_tag_scoped():
    """Asset with Location=External tag is in scoped_df, not in mismatches_df."""
    assets = _make_assets(
        {"tags": "Location=External", "ipv4": "10.0.0.1"},  # private IP + external tag
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 1, "Location=External asset must be in scoped_df"
    assert len(mismatches_df) == 0, "Location=External asset must NOT be in mismatches_df"


def test_dmz_tag_private_ip_not_mismatch():
    """
    Asset with Location=DMZ + private IP is in scoped_df but NOT in mismatches_df.

    D-06: DMZ-tagged + private IP is the NORMAL state.  The External-on-private-IP
    case is the anomaly; DMZ-on-private-IP is architecturally correct and must not
    be flagged as a gap.
    """
    assets = _make_assets(
        {"tags": "Location=DMZ", "ipv4": "10.0.0.5"},
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 1, "Location=DMZ asset must be in scoped_df"
    assert len(mismatches_df) == 0, "DMZ+private IP must NOT be in mismatches_df (D-06)"


def test_external_and_dmz_both_scoped():
    """Both Location=External and Location=DMZ assets land in scoped_df."""
    assets = _make_assets(
        {"tags": "Location=External", "ipv4": "10.0.0.1"},
        {"tags": "Location=DMZ",      "ipv4": "10.0.0.2"},
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 2
    assert len(mismatches_df) == 0


def test_private_untagged_excluded():
    """Asset with private IP and no Location tag is in NEITHER frame."""
    assets = _make_assets(
        {"tags": "Owner=NetOps", "ipv4": "10.0.0.1"},
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 0, "Private-untagged asset must not be in scoped_df"
    assert len(mismatches_df) == 0, "Private-untagged asset must not be in mismatches_df"


def test_public_ip_untagged_gap_in_both_frames(monkeypatch):
    """
    Asset with public IPv4 but no Location tag appears in BOTH scoped_df and
    mismatches_df with untagged_reason=='public_ip_untagged'.

    D-05 / D-08: IP signal is demoted to gap detection; gap assets are in both
    frames so the analyst workbook and the scoped population remain consistent.
    """
    class _FakeAddr:
        version = 4
        is_global = True

    monkeypatch.setattr("utils.external_scope.ipaddress.ip_address", lambda _: _FakeAddr())

    assets = _make_assets(
        {"tags": "Owner=NetOps", "ipv4": "192.0.2.1"},  # doc range; monkeypatched to is_global=True
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 1, "Gap asset (public-IP-untagged) must be in scoped_df (D-08)"
    assert len(mismatches_df) == 1, "Gap asset must be in mismatches_df"
    assert mismatches_df.iloc[0]["untagged_reason"] == "public_ip_untagged"


def test_public_ip_untagged_mismatch_columns(monkeypatch):
    """mismatches_df carries the required D-11 schema columns."""
    class _FakeAddr:
        version = 4
        is_global = True

    monkeypatch.setattr("utils.external_scope.ipaddress.ip_address", lambda _: _FakeAddr())

    assets = _make_assets(
        {"tags": "", "ipv4": "192.0.2.1"},
    )
    _, mismatches_df = external_scope(assets)

    required = {"asset_uuid", "ip_address", "owner_tag", "untagged_reason"}
    assert required.issubset(mismatches_df.columns), (
        f"mismatches_df missing columns: {required - set(mismatches_df.columns)}"
    )


def test_gap_asset_not_duplicated_when_also_has_other_tags(monkeypatch):
    """
    A public-IP-untagged asset with OTHER non-Location tags is still in both frames
    (the IP gap rule fires regardless of other tag categories).
    """
    class _FakeAddr:
        version = 4
        is_global = True

    monkeypatch.setattr("utils.external_scope.ipaddress.ip_address", lambda _: _FakeAddr())

    assets = _make_assets(
        {"tags": "Owner=NetOps;Environment=Production", "ipv4": "192.0.2.2"},
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 1
    assert len(mismatches_df) == 1
    assert mismatches_df.iloc[0]["untagged_reason"] == "public_ip_untagged"


def test_location_category_case_insensitive():
    """
    Tag category match is case-insensitive (D-10): 'location=External' (lowercase
    category) must classify the asset as external.
    """
    assets = _make_assets(
        {"tags": "location=External", "ipv4": "10.0.0.3"},
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 1, "lowercase 'location' category must match (D-10)"
    assert len(mismatches_df) == 0


def test_location_value_case_sensitive():
    """
    Tag VALUE match is exact / case-sensitive (D-10): 'Location=external' (lowercase
    value) must NOT classify as external.
    """
    assets = _make_assets(
        {"tags": "Location=external", "ipv4": "10.0.0.4"},  # lowercase value — not a match
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 0, "lowercase value 'external' must NOT match (D-10 exact value)"


def test_mixed_assets_classification(monkeypatch):
    """
    Multiple assets — each classified independently.

    Row 0: Location=External tag           → in scoped_df only
    Row 1: Location=DMZ + private IP       → in scoped_df only (D-06)
    Row 2: monkeypatched public IP, no tag → in BOTH frames (D-05/D-08)
    Row 3: private IP + no Location tag    → in NEITHER frame
    """
    call_count = 0
    original_ip_address = ipaddress.ip_address

    def _selective_ip(ip_str):
        # Only row 2 has "192.0.2.3" — make it appear public
        try:
            addr = original_ip_address(ip_str)
            if ip_str == "192.0.2.3":
                # Return a fake with is_global=True
                class _Pub:
                    version = 4
                    is_global = True
                return _Pub()
            return addr
        except (ValueError, TypeError):
            raise

    monkeypatch.setattr("utils.external_scope.ipaddress.ip_address", _selective_ip)

    assets = _make_assets(
        {"tags": "Location=External",  "ipv4": "10.0.0.1"},   # row 0
        {"tags": "Location=DMZ",       "ipv4": "10.0.0.2"},   # row 1
        {"tags": "Owner=Ops",          "ipv4": "192.0.2.3"},   # row 2 (patched public)
        {"tags": "Owner=Ops",          "ipv4": "10.0.0.4"},   # row 3
    )
    scoped_df, mismatches_df = external_scope(assets)

    assert len(scoped_df) == 3, f"Expected 3 in scoped_df, got {len(scoped_df)}"
    assert len(mismatches_df) == 1, f"Expected 1 mismatch, got {len(mismatches_df)}"
    assert mismatches_df.iloc[0]["untagged_reason"] == "public_ip_untagged"


# ---------------------------------------------------------------------------
# Empty-input and fail-soft guards (QUAL-03)
# ---------------------------------------------------------------------------

def test_empty_input_guard():
    """external_scope(empty DataFrame) returns two zero-row frames without raising."""
    result = external_scope(pd.DataFrame())
    assert isinstance(result, tuple) and len(result) == 2
    scoped_df, mismatches_df = result
    assert len(scoped_df) == 0
    assert len(mismatches_df) == 0


def test_empty_assets_with_columns_guard():
    """external_scope with zero-row but column-bearing DataFrame returns two zero-row frames."""
    assets = _make_assets()  # zero rows
    scoped_df, mismatches_df = external_scope(assets)
    assert len(scoped_df) == 0
    assert len(mismatches_df) == 0


def test_missing_tags_column_failsoft():
    """DataFrame without 'tags' column → two zero-row frames, no exception (fail-soft)."""
    assets = pd.DataFrame({
        "asset_uuid": ["00000000-0000-0000-0000-000000000001"],
        "ipv4":       ["10.0.0.1"],
    })
    scoped_df, mismatches_df = external_scope(assets)
    assert len(scoped_df) == 0
    assert len(mismatches_df) == 0


def test_missing_ipv4_column_failsoft():
    """DataFrame without 'ipv4' column → two zero-row frames, no exception (fail-soft)."""
    assets = pd.DataFrame({
        "asset_uuid": ["00000000-0000-0000-0000-000000000001"],
        "tags":       ["Location=External"],
    })
    scoped_df, mismatches_df = external_scope(assets)
    assert len(scoped_df) == 0
    assert len(mismatches_df) == 0


def test_missing_both_columns_failsoft():
    """DataFrame without 'tags' OR 'ipv4' columns → two zero-row frames, no exception."""
    assets = pd.DataFrame({"asset_uuid": ["00000000-0000-0000-0000-000000000001"]})
    scoped_df, mismatches_df = external_scope(assets)
    assert len(scoped_df) == 0
    assert len(mismatches_df) == 0


def test_missing_asset_uuid_column_failsoft(monkeypatch):
    """
    WR-03 regression: a frame with tags+ipv4 but no 'asset_uuid' column must
    fail soft, not raise KeyError.

    Pre-fix the guard only checked tags/ipv4, so this frame passed the guard and
    then — because the public-IP-untagged gap branch reads gap_raw['asset_uuid']
    unconditionally — raised KeyError inside the mismatch builder. The public IP
    is monkeypatched to is_global=True so the populated-gap branch is exercised
    (the empty-gap branch was already safe).
    """
    class _FakeAddr:
        version = 4
        is_global = True

    monkeypatch.setattr("utils.external_scope.ipaddress.ip_address", lambda _: _FakeAddr())

    # tags + ipv4 present, asset_uuid ABSENT — synthetic doc-range IP (QUAL-05).
    assets = pd.DataFrame({
        "tags": ["Owner=NetOps"],      # public IP but no Location tag -> gap row
        "ipv4": ["192.0.2.1"],
    })
    assert "asset_uuid" not in assets.columns

    scoped_df, mismatches_df = external_scope(assets)  # must not raise

    # Documented safe return: two zero-row DataFrames.
    assert len(scoped_df) == 0
    assert len(mismatches_df) == 0


# ---------------------------------------------------------------------------
# Return-type contract
# ---------------------------------------------------------------------------

def test_returns_two_dataframes():
    """external_scope always returns a 2-tuple of DataFrames."""
    assets = _make_assets({"tags": "Location=External", "ipv4": "10.0.0.1"})
    result = external_scope(assets)
    assert isinstance(result, tuple) and len(result) == 2
    assert isinstance(result[0], pd.DataFrame)
    assert isinstance(result[1], pd.DataFrame)
