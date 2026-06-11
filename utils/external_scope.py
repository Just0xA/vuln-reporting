"""
utils/external_scope.py — External-scope asset classifier.

Pure compute: no file I/O, no network I/O.  Call ``external_scope()`` to
classify a Tenable asset DataFrame into external-scope assets and an analyst
mismatch list of public-IP-but-untagged gap assets.

**Tags are authoritative (D-04).**  The IPv4 signal is demoted to a gap
detector only (D-05) — it never promotes a tagged-internal asset and never
overrides a tag.

Design decisions implemented here
----------------------------------
D-04  Tags are authoritative; Location=External/DMZ is the primary classifier.
D-05  ``is_public_ipv4`` output is demoted to the ``public_ip_untagged`` gap
      reason.  IP classification NEVER overrides a tag.
D-06  ``Location=DMZ`` + private IP is the NORMAL network state (DMZ hosts
      often carry RFC 1918 addresses behind NAT).  This is not a mismatch.
      Only ``Location=External`` on a private IP is an anomalous/advisory case.
D-08  Gap (public-IP-untagged) assets appear in BOTH ``scoped_df`` AND
      ``mismatches_df`` so the analyst workbook and the scoped population are
      consistent.
D-09  Classification reads the single primary ``ipv4`` column already present
      in ``assets_df`` (fetcher collapses ``ipv4s → ipv4[0]``).  No fetcher
      change needed.
D-10  ``_has_location_tag()`` matches the Location category case-insensitively
      (``casefold()``); value membership ``{"External", "DMZ"}`` is
      case-sensitive exact match.
D-11  **PII boundary:** ``mismatches_df`` contains asset-level fields
      (``asset_uuid``, ``ip_address``) that identify individual hosts.
      This frame is **operator-local / internal-email only** — it must NEVER
      be committed to the repository, sent to an AI/LLM service, or included in
      test fixtures.  Test fixtures use synthetic RFC 6761 ``*.example.invalid``
      hostnames and monkeypatched ``is_global`` (D-18) to avoid committing real
      IP addresses.
D-13  No import from ``reports.modules.*`` — ``utils/`` is dependency-free of
      the module layer.
"""
from __future__ import annotations

import ipaddress
import logging

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Location tag constants (D-10)
# ---------------------------------------------------------------------------

_LOCATION_CATEGORY = "location"          # case-insensitive match target
_EXTERNAL_VALUES   = frozenset({"External", "DMZ"})  # exact case-sensitive values


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def is_public_ipv4(ip_str: object) -> bool:
    """Return ``True`` if *ip_str* is a globally routable IPv4 address.

    Uses ``ipaddress.ip_address().is_global`` which covers RFC 1918, CGNAT
    (100.64.0.0/10, RFC 6598), loopback (127.0.0.0/8), link-local
    (169.254.0.0/16), documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24), and IPv6 addresses (version ≠ 4).

    Never raises — returns ``False`` on unparseable, empty, or ``None`` input
    (THREAT-14-01: defensive parse guard so malformed strings from untrusted
    Tenable export data never raise into the fail-soft batch).

    Parameters
    ----------
    ip_str:
        Value to classify.  Must be a string; ``None`` and non-string types
        are accepted and return ``False``.

    Returns
    -------
    bool
        ``True`` only for a globally routable IPv4 address.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4 and addr.is_global
    except (ValueError, TypeError):
        return False


def external_scope(
    assets_df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Classify assets into external-scope and public-IP-untagged gap subsets.

    Tags are authoritative (D-04).  ``is_public_ipv4`` is a gap detector only
    (D-05) — it never overrides a tag.

    Parameters
    ----------
    assets_df : pd.DataFrame
        Asset DataFrame from ``fetch_all_assets()``.  Expected columns:
        ``tags`` (semicolon-delimited ``"Category=Value"`` string) and
        ``ipv4`` (primary IPv4 address string, may be ``""`` or ``None``).

    Returns
    -------
    tuple[pd.DataFrame, pd.DataFrame]
        ``(scoped_df, mismatches_df)``

        ``scoped_df``
            All external-scope assets — those with a ``Location=External`` or
            ``Location=DMZ`` tag **plus** public-IP-but-untagged gap assets
            (D-08: gap assets appear in both frames).

        ``mismatches_df``
            Gap subset: assets whose ``ipv4`` is publicly routable but carry
            no ``Location`` tag.  Contains columns: ``asset_uuid``,
            ``ip_address`` (from ``ipv4``), ``owner_tag``,
            ``untagged_reason="public_ip_untagged"``.

        Both DataFrames are copies with reset indices.  Neither frame is ever
        ``None``.  Empty input or missing required columns returns two
        zero-row DataFrames (fail-soft; QUAL-03).

    Notes
    -----
    - ``Location=DMZ`` + private IP is **not** a mismatch (D-06).
    - ``Location=External`` + private IP is an advisory anomaly (defensive
      coverage) but is NOT emitted as a ``mismatches_df`` row in v1.4.
      The ``public_ip_untagged`` reason is the only gap reason today.
    - ``mismatches_df`` is **operator-local / internal-email only** (D-11).
      See module docstring for the PII boundary.
    """
    # ------------------------------------------------------------------
    # Empty / missing-column guard (QUAL-03 / fail-soft)
    # ------------------------------------------------------------------
    if assets_df.empty:
        empty = assets_df.iloc[0:0].copy()
        return empty, empty

    # ``asset_uuid`` is included because the populated-gap branch below reads
    # ``gap_raw["asset_uuid"]`` unconditionally (D-11 required output column);
    # a frame with tags+ipv4 but no asset_uuid would otherwise pass this guard
    # and raise KeyError inside the mismatch builder (WR-03).
    _required = ("tags", "ipv4", "asset_uuid")
    if any(c not in assets_df.columns for c in _required):
        missing = [c for c in _required if c not in assets_df.columns]
        logger.warning(
            "external_scope: required column(s) %r not present in DataFrame — "
            "returning two zero-row frames (fail-soft).",
            missing,
        )
        empty = assets_df.iloc[0:0].copy()
        return empty, empty

    # ------------------------------------------------------------------
    # Tag classification (D-10)
    # Adapt _parse_tags from board_report_utils.py:
    #   - casefold category match against "location"
    #   - exact value membership in {"External", "DMZ"}
    # ------------------------------------------------------------------
    def _has_location_tag(tags_val: object) -> bool:
        """Return True if any Location=External or Location=DMZ token is present."""
        if not isinstance(tags_val, str) or not tags_val.strip():
            return False
        for token in tags_val.split(";"):
            token = token.strip()
            if not token or "=" not in token:
                continue
            cat, _, val = token.partition("=")
            if cat.strip().casefold() == _LOCATION_CATEGORY:
                if val.strip() in _EXTERNAL_VALUES:
                    return True
        return False

    # ------------------------------------------------------------------
    # Build boolean masks (CoW-safe — masks only, no column assignment yet)
    # ------------------------------------------------------------------
    has_location_tag = assets_df["tags"].apply(_has_location_tag)
    has_public_ip    = assets_df["ipv4"].apply(is_public_ipv4)

    # Gap: public IP but no Location=External/DMZ tag (D-05)
    is_gap = has_public_ip & ~has_location_tag

    # Scope: tagged external/DMZ OR gap (D-08: gap appears in both frames)
    in_scope = has_location_tag | is_gap

    # ------------------------------------------------------------------
    # scoped_df — all in-scope assets (copy + reset index, CoW-safe)
    # ------------------------------------------------------------------
    scoped_df = assets_df[in_scope].copy().reset_index(drop=True)

    # ------------------------------------------------------------------
    # mismatches_df — gap subset with D-11 schema columns
    # Uses .assign() to add columns on a fresh frame (Pitfall 9 / CoW)
    # ------------------------------------------------------------------
    gap_raw = assets_df[is_gap].copy().reset_index(drop=True)

    if gap_raw.empty:
        # Return a zero-row mismatches_df with the D-11 schema columns present
        mismatches_df = pd.DataFrame(
            columns=["asset_uuid", "ip_address", "owner_tag", "untagged_reason"]
        )
    else:
        # Build mismatches_df from a plain dict to avoid pandas 3.0 CoW
        # ChainedAssignmentError that fires when .assign() internally does
        # `data[k] = val` on a copy (pandas 3.0+ CoW strict mode).
        mismatches_df = pd.DataFrame(
            {
                "asset_uuid":       gap_raw["asset_uuid"].to_numpy(),
                "ip_address":       gap_raw["ipv4"].to_numpy(),
                "owner_tag":        gap_raw["tags"].to_numpy(),
                "untagged_reason":  "public_ip_untagged",
            }
        ).reset_index(drop=True)

    logger.debug(
        "external_scope: total=%d, scoped=%d (tagged=%d, gap=%d), mismatches=%d.",
        len(assets_df),
        len(scoped_df),
        int(has_location_tag.sum()),
        int(is_gap.sum()),
        len(mismatches_df),
    )

    return scoped_df, mismatches_df


# ---------------------------------------------------------------------------
# CLI stub (project Code Quality requirement — every script has __main__)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "utils/external_scope.py — External-scope asset classifier.\n\n"
            "Library module; not intended for direct CLI use.\n\n"
            "Exported symbols:\n"
            "  is_public_ipv4(ip_str) -> bool\n"
            "  external_scope(assets_df) -> tuple[pd.DataFrame, pd.DataFrame]"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.parse_args()
    print("utils.external_scope — library module.  Import external_scope() and is_public_ipv4().")
