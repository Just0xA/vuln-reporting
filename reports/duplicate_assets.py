"""
reports/duplicate_assets.py — Duplicate Asset Detection

Scans the Tenable asset inventory for records that likely represent the same
physical or virtual machine using a pairwise field-scoring model.

Scoring model
-------------
For each candidate pair, up to four identity fields are compared.  IP
addresses are only treated as meaningful identifiers when they fall inside
corporate RFC 1918 space (10.0.0.0/8 or 172.16.0.0/12).  Addresses in
192.168.0.0/16 are excluded because they originate from home wireless
networks via the ZScaler zero-trust connection and carry no corporate
identity value.  Public IPs are also excluded.

  Fields matching                         Confidence
  --------------------------------------  ----------
  Hostname + MAC + IP (corporate)         High
  Hostname + MAC                          High
  Hostname + IP (corporate)               High
  MAC + IP (corporate)                    High
  Agent Name + any other field            High
  Hostname only                           Medium
  MAC only                                Medium
  Agent Name only                         Medium
  IP only (corporate RFC 1918, non-/16)   Medium
  IP only (192.168.x.x or public)         No match — excluded

Two or more fields matching always yields High confidence.  IP contributes
to the field count only when the address is in 10/8 or 172.16/12.

Group confidence uses the weakest-link rule: a group is only "High" if
every pairwise link within the connected component is High.  A single
Medium link anywhere in the chain pulls the whole group to Medium.

Candidate generation stays O(n) via groupby — assets are never compared
exhaustively against the full 40k+ inventory.

Output
------
CSV  — one row per asset that belongs to at least one duplicate group.
       Sorted by confidence (High first), then group_id, then hostname.

Columns
-------
  group_id          Integer (1-based), groups sorted High-first then by size.
  confidence        "High" or "Medium"
  matched_fields    Comma-separated fields that contributed matches within
                    the group, e.g. "Hostname, MAC Address"
  asset_uuid
  hostname
  ipv4
  mac_address
  agent_names       Semicolon-joined list
  fqdn
  operating_system
  last_seen
  source_name
  tags_str

CLI usage
---------
  # Dry run — counts only, no CSV written
  python reports/duplicate_assets.py --dry-run

  # Full run with default output directory
  python reports/duplicate_assets.py

  # Custom output and cache directory
  python reports/duplicate_assets.py \\
      --output-dir output/test_dupes/ \\
      --cache-dir data/cache/2026-04-09/

  # Reuse cached parquet, skip API fetch
  python reports/duplicate_assets.py \\
      --cache-dir data/cache/2026-04-09/ --no-fetch
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import logging
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Allow running directly from any working directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd


# ---------------------------------------------------------------------------
# IP range helpers
# ---------------------------------------------------------------------------

_CORPORATE_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
]


def _is_corporate_rfc1918(ip_str: str) -> bool:
    """
    Return True if *ip_str* falls inside 10.0.0.0/8 or 172.16.0.0/12.

    192.168.0.0/16 is intentionally excluded — those addresses originate
    from home wireless networks (ZScaler zero-trust) and are not meaningful
    corporate identifiers.  Public IPs are also excluded.
    """
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _CORPORATE_RFC1918)
    except ValueError:
        return False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Union-Find with weakest-link confidence tracking
# ---------------------------------------------------------------------------

class _UnionFind:
    """
    Disjoint-set (union-find) with path compression and union by rank.

    Each component tracks the minimum (weakest) confidence level of all
    edges that were unioned into it.  "High" > "Medium" in the ordering
    used here (High = 0, Medium = 1 for comparison purposes).
    """

    _CONF_RANK = {"High": 0, "Medium": 1}

    def __init__(self, elements: list[str]) -> None:
        self._parent: dict[str, str] = {e: e for e in elements}
        self._rank:   dict[str, int] = {e: 0 for e in elements}
        # Initialise to High; first real union will set the true minimum.
        self._min_conf: dict[str, str] = {e: "High" for e in elements}

    def find(self, x: str) -> str:
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])   # path compression
        return self._parent[x]

    def union(self, x: str, y: str, confidence: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            # Already in the same component — new edge may lower min confidence.
            if self._CONF_RANK[confidence] > self._CONF_RANK[self._min_conf[rx]]:
                self._min_conf[rx] = confidence
            return
        # Merge smaller tree into larger (by rank).
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1
        # New root inherits the weakest confidence across both components + new edge.
        candidates = [self._min_conf[rx], self._min_conf[ry], confidence]
        self._min_conf[rx] = max(candidates, key=lambda c: self._CONF_RANK[c])

    def get_confidence(self, x: str) -> str:
        return self._min_conf[self.find(x)]

    def groups(self) -> dict[str, list[str]]:
        """Return {root: [member, …]} for every component with 2+ members."""
        buckets: dict[str, list[str]] = defaultdict(list)
        for elem in self._parent:
            buckets[self.find(elem)].append(elem)
        return {r: mbs for r, mbs in buckets.items() if len(mbs) >= 2}


# ---------------------------------------------------------------------------
# Candidate pair generation  (O(n) via groupby)
# ---------------------------------------------------------------------------

def _candidate_pairs(df: pd.DataFrame) -> set[tuple[str, str]]:
    """
    Return all (uuid_a, uuid_b) pairs (uuid_a < uuid_b) that share at least
    one of: hostname, MAC address, or agent name.

    IP is deliberately excluded from candidate generation — two assets that
    share only an IP are never scored and never appear in output.
    """
    pairs: set[tuple[str, str]] = set()

    def _add_group(uuids: list[str]) -> None:
        uuids = list(dict.fromkeys(uuids))   # deduplicate, preserve order
        for i in range(len(uuids)):
            for j in range(i + 1, len(uuids)):
                a, b = uuids[i], uuids[j]
                pairs.add((a, b) if a < b else (b, a))

    # ── Hostname ─────────────────────────────────────────────────────────────
    hn_mask = df["hostname"].notna() & (df["hostname"].str.strip() != "")
    for _, grp in df[hn_mask].groupby("hostname", sort=False):
        uuids = grp["asset_uuid"].tolist()
        if len(uuids) >= 2:
            _add_group(uuids)

    # ── MAC address ──────────────────────────────────────────────────────────
    if "mac_address" in df.columns:
        mac_mask = df["mac_address"].notna() & (df["mac_address"].str.strip() != "")
        _mac_uuids = df.loc[mac_mask, "asset_uuid"].values
        _mac_norm  = df.loc[mac_mask, "mac_address"].str.lower().str.strip().values
        mac_df = pd.DataFrame({"asset_uuid": _mac_uuids, "mac_norm": _mac_norm})
        for _, grp in mac_df.groupby("mac_norm", sort=False):
            uuids = grp["asset_uuid"].tolist()
            if len(uuids) >= 2:
                _add_group(uuids)

    # ── Agent name ───────────────────────────────────────────────────────────
    if "agent_names" in df.columns:
        exploded = (
            df[["asset_uuid", "agent_names"]]
            .explode("agent_names")
            .rename(columns={"agent_names": "agent_name"})
        )
        exploded = exploded[
            exploded["agent_name"].notna()
            & (exploded["agent_name"].astype(str).str.strip() != "")
        ]
        for _, grp in exploded.groupby("agent_name", sort=False):
            uuids = grp["asset_uuid"].unique().tolist()
            if len(uuids) >= 2:
                _add_group(uuids)

    # ── IP address (corporate RFC 1918 only — 10/8 and 172.16/12) ───────────
    # 192.168.0.0/16 is excluded: home wireless via ZScaler, not a meaningful
    # corporate identifier.  Public IPs are also excluded.
    if "ipv4" in df.columns:
        ip_mask = df["ipv4"].notna() & (df["ipv4"].str.strip() != "")
        if ip_mask.any():
            _ip_uuids = df.loc[ip_mask, "asset_uuid"].values
            _ip_vals  = df.loc[ip_mask, "ipv4"].values
            corp_flags = [_is_corporate_rfc1918(ip) for ip in _ip_vals]
            corp_ip_df = pd.DataFrame({
                "asset_uuid": [u for u, f in zip(_ip_uuids, corp_flags) if f],
                "ipv4":       [ip for ip, f in zip(_ip_vals, corp_flags) if f],
            })
            for _, grp in corp_ip_df.groupby("ipv4", sort=False):
                uuids = grp["asset_uuid"].tolist()
                if len(uuids) >= 2:
                    _add_group(uuids)

    return pairs


# ---------------------------------------------------------------------------
# Pairwise field scorer
# ---------------------------------------------------------------------------

def _score_pair(
    row_a: dict,
    row_b: dict,
) -> tuple[str | None, list[str]]:
    """
    Compare two asset rows and return (confidence, matched_fields).

    Returns (None, []) if the pair does not meet the minimum match threshold
    (i.e. IP-only match, or no match at all).

    Parameters
    ----------
    row_a, row_b : dict
        Asset attribute dicts with keys: hostname, mac_address, ipv4,
        agent_names (list).

    Returns
    -------
    confidence : "High" | "Medium" | None
    matched_fields : list of field names that matched
    """
    def _nonempty(v: object) -> bool:
        return bool(v) and str(v).strip() != ""

    hostname_match = (
        _nonempty(row_a.get("hostname"))
        and row_a["hostname"] == row_b["hostname"]
    )
    mac_match = (
        _nonempty(row_a.get("mac_address"))
        and _nonempty(row_b.get("mac_address"))
        and row_a["mac_address"].lower().strip() == row_b["mac_address"].lower().strip()
    )
    # IP only counts when the address is in corporate RFC 1918 space
    # (10/8 or 172.16/12).  192.168.0.0/16 and public IPs are excluded.
    ip_val_a = row_a.get("ipv4", "") or ""
    ip_corporate_match = (
        _nonempty(ip_val_a)
        and ip_val_a == (row_b.get("ipv4", "") or "")
        and _is_corporate_rfc1918(ip_val_a)
    )

    # Agent name: any name in common
    names_a = set(row_a.get("agent_names") or [])
    names_b = set(row_b.get("agent_names") or [])
    agent_match = bool(names_a & names_b)

    matched: list[str] = []
    if hostname_match:      matched.append("Hostname")
    if mac_match:           matched.append("MAC Address")
    if agent_match:         matched.append("Agent Name")
    if ip_corporate_match:  matched.append("IP")

    n = len(matched)

    if n == 0:
        return None, []

    confidence = "High" if n >= 2 else "Medium"
    return confidence, matched


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def detect_duplicates(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, dict]:
    """
    Detect duplicate asset records using pairwise field scoring.

    Parameters
    ----------
    df : pd.DataFrame
        Full asset inventory from ``fetch_all_assets()``.

    Returns
    -------
    result_df : pd.DataFrame
        One row per asset in a duplicate group.  Empty if none found.
    summary : dict
        Counts for the dry-run / summary printout.
    """
    all_uuids = df["asset_uuid"].unique().tolist()
    uf = _UnionFind(all_uuids)

    # Build fast lookup: uuid → attribute dict
    lookup_cols = [c for c in ["hostname", "mac_address", "ipv4", "agent_names"]
                   if c in df.columns]
    lookup: dict[str, dict] = df.set_index("asset_uuid")[lookup_cols].to_dict("index")

    # Generate candidate pairs (shares hostname, MAC, or agent name)
    candidates = _candidate_pairs(df)

    # Score and union
    high_pairs = medium_pairs = excluded_pairs = 0
    # Track which fields contributed matches per uuid for the matched_fields column
    uuid_fields: dict[str, set[str]] = defaultdict(set)

    for (uuid_a, uuid_b) in candidates:
        confidence, matched_fields = _score_pair(
            lookup.get(uuid_a, {}),
            lookup.get(uuid_b, {}),
        )
        if confidence is None:
            excluded_pairs += 1
            continue

        uf.union(uuid_a, uuid_b, confidence)

        if confidence == "High":
            high_pairs += 1
        else:
            medium_pairs += 1

        for uuid in (uuid_a, uuid_b):
            uuid_fields[uuid].update(matched_fields)

    summary = {
        "candidate_pairs":  len(candidates),
        "high_pairs":       high_pairs,
        "medium_pairs":     medium_pairs,
        "excluded_pairs":   excluded_pairs,
    }

    # Collect connected components (2+ members)
    raw_groups = uf.groups()

    if not raw_groups:
        return pd.DataFrame(), summary

    # Build per-group metadata rows
    # Field order for matched_fields label (IP last since it's weakest)
    _FIELD_ORDER = ["Hostname", "MAC Address", "Agent Name", "IP"]

    group_meta: list[dict] = []
    for root, members in raw_groups.items():
        confidence = uf.get_confidence(root)

        # Union of all fields that matched any member in this group
        group_fields: set[str] = set()
        for m in members:
            group_fields.update(uuid_fields.get(m, set()))
        # Remove IP from label if it's not the only field (it never is alone here,
        # but keep it when it contributed alongside others)
        field_label = ", ".join(f for f in _FIELD_ORDER if f in group_fields)

        group_meta.append({
            "_root":          root,
            "_members":       members,
            "_size":          len(members),
            "confidence":     confidence,
            "matched_fields": field_label,
        })

    # Sort: High first, then by size desc
    group_meta.sort(key=lambda r: (0 if r["confidence"] == "High" else 1, -r["_size"]))

    # Assign group_id (1-based)
    for i, row in enumerate(group_meta, start=1):
        row["group_id"] = i

    summary["high_groups"]   = sum(1 for g in group_meta if g["confidence"] == "High")
    summary["medium_groups"] = sum(1 for g in group_meta if g["confidence"] == "Medium")
    summary["total_groups"]  = len(group_meta)

    # Expand to one row per asset — build output DataFrame
    out_cols = [c for c in
                ["hostname", "ipv4", "mac_address", "fqdn",
                 "operating_system", "last_seen", "source_name", "tags_str"]
                if c in df.columns]
    uuid_to_info: dict[str, dict] = df.set_index("asset_uuid")[out_cols].to_dict("index")

    # Pre-build agent_names string lookup to avoid repeated boolean indexing
    if "agent_names" in df.columns:
        agent_names_lookup: dict[str, str] = {}
        for row in df[["asset_uuid", "agent_names"]].itertuples(index=False):
            raw = row.agent_names
            if isinstance(raw, list):
                agent_names_lookup[row.asset_uuid] = "; ".join(
                    str(n) for n in raw if n
                )
            else:
                agent_names_lookup[row.asset_uuid] = (
                    str(raw) if pd.notna(raw) else ""
                )
    else:
        agent_names_lookup = {}

    final_rows: list[dict] = []
    for grp in group_meta:
        for uuid in grp["_members"]:
            final_rows.append({
                "group_id":       grp["group_id"],
                "confidence":     grp["confidence"],
                "matched_fields": grp["matched_fields"],
                "asset_uuid":     uuid,
                **uuid_to_info.get(uuid, {}),
                "agent_names":    agent_names_lookup.get(uuid, ""),
            })

    result_df = pd.DataFrame(final_rows)

    # Column order
    front = ["group_id", "confidence", "matched_fields", "asset_uuid",
             "hostname", "ipv4", "mac_address", "agent_names"]
    back  = [c for c in result_df.columns if c not in front]
    result_df = result_df[[c for c in front if c in result_df.columns] + back]

    return result_df, summary


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def write_csv(df: pd.DataFrame, output_dir: Path, generated_at: datetime) -> Path:
    """Write duplicate asset rows to a UTF-8 CSV and return the path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = generated_at.strftime("%Y%m%d_%H%M")
    path = output_dir / f"duplicate_assets_{ts}.csv"
    df.to_csv(path, index=False, encoding="utf-8-sig", quoting=csv.QUOTE_ALL)
    logger.info("Wrote %d rows to %s", len(df), path)
    return path


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(
    summary: dict,
    result_df: pd.DataFrame,
    dry_run: bool,
) -> None:
    dry_tag = " (DRY RUN)" if dry_run else ""
    print(f"\n=== Duplicate Asset Detection{dry_tag} ===\n")

    print("Candidate pair scoring:")
    print(f"  Total candidate pairs        : {summary.get('candidate_pairs', 0):>6,}")
    print(f"  High confidence pairs        : {summary.get('high_pairs', 0):>6,}")
    print(f"  Medium confidence pairs      : {summary.get('medium_pairs', 0):>6,}")
    print(f"  No-match pairs excluded      : {summary.get('excluded_pairs', 0):>6,}")
    print(f"  (IP ignored: 192.168/16 or public address)")

    if result_df is None or len(result_df) == 0:
        print("\n  No duplicate groups found.")
        if dry_run:
            print("\nNo CSV written (--dry-run).")
        return

    n_high   = summary.get("high_groups", 0)
    n_medium = summary.get("medium_groups", 0)
    n_total  = summary.get("total_groups", 0)
    n_high_assets   = len(result_df[result_df["confidence"] == "High"])
    n_medium_assets = len(result_df[result_df["confidence"] == "Medium"])

    print(f"\nAfter union-find grouping (weakest-link confidence):")
    print(f"  High confidence groups   : {n_high:>4}  ({n_high_assets:>5} assets)")
    print(f"  Medium confidence groups : {n_medium:>4}  ({n_medium_assets:>5} assets)")
    print(f"  Total duplicate groups   : {n_total:>4}  ({len(result_df):>5} assets)")

    if dry_run:
        print("\nNo CSV written (--dry-run).")


# ---------------------------------------------------------------------------
# Public run() function
# ---------------------------------------------------------------------------

def run(
    assets_df: pd.DataFrame,
    output_dir: Path | None = None,
    dry_run: bool = False,
    generated_at: datetime | None = None,
) -> dict:
    """
    Detect duplicate assets and optionally write a CSV.

    Parameters
    ----------
    assets_df : pd.DataFrame
        Full asset inventory from ``fetch_all_assets()``.
    output_dir : Path, optional
        Directory for CSV output.  Required unless ``dry_run=True``.
    dry_run : bool
        If True, compute and print results but do not write the CSV.
    generated_at : datetime, optional
        Timestamp used for the CSV file name.  Defaults to now.

    Returns
    -------
    dict
        {csv, total_groups, high_groups, medium_groups, total_assets_flagged}
    """
    if generated_at is None:
        generated_at = datetime.now()

    result_df, summary = detect_duplicates(assets_df)
    _print_summary(summary, result_df, dry_run=dry_run)

    if result_df is None or len(result_df) == 0:
        return {
            "csv": None,
            "total_groups": 0,
            "high_groups": 0,
            "medium_groups": 0,
            "total_assets_flagged": 0,
        }

    csv_path = None
    if not dry_run:
        if output_dir is None:
            output_dir = (
                Path("output")
                / generated_at.strftime("%Y-%m-%d_%H-%M_duplicate_assets")
            )
        csv_path = write_csv(result_df, output_dir, generated_at)
        print(f"\nCSV written : {csv_path}")
        print(f"Total rows  : {len(result_df):,}")

        # Preview — first 10 rows
        print("\nFirst 10 rows:")
        preview_cols = [c for c in
                        ["group_id", "confidence", "matched_fields",
                         "asset_uuid", "hostname", "ipv4"]
                        if c in result_df.columns]
        print(result_df.head(10)[preview_cols].to_string(index=False))

        # Example High confidence group
        high_ids = result_df[result_df["confidence"] == "High"]["group_id"].unique()
        if len(high_ids) > 0:
            ex = result_df[result_df["group_id"] == high_ids[0]]
            fields = ex["matched_fields"].iloc[0]
            print(f"\nExample High group (group_id={high_ids[0]}, fields: {fields}):")
            show = [c for c in
                    ["asset_uuid", "hostname", "ipv4", "mac_address",
                     "agent_names", "last_seen"]
                    if c in ex.columns]
            print(ex[show].to_string(index=False))

    return {
        "csv":                  str(csv_path) if csv_path else None,
        "total_groups":         summary.get("total_groups", 0),
        "high_groups":          summary.get("high_groups", 0),
        "medium_groups":        summary.get("medium_groups", 0),
        "total_assets_flagged": len(result_df),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect potential duplicate asset records in the Tenable inventory."
    )
    parser.add_argument(
        "--output-dir", metavar="PATH",
        help="Directory for CSV output (created if absent). "
             "Defaults to output/YYYY-MM-DD_HH-MM_duplicate_assets/",
    )
    parser.add_argument(
        "--cache-dir", metavar="PATH",
        help="Path to an existing cache directory to reuse cached parquet files.",
    )
    parser.add_argument(
        "--no-fetch", action="store_true",
        help="Read assets_all.parquet from --cache-dir without calling the API.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Compute and print duplicate counts but do not write any CSV.",
    )
    parser.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING).",
    )
    args = parser.parse_args()

    _configure_logging(args.log_level)

    output_dir = Path(args.output_dir) if args.output_dir else None
    cache_dir  = Path(args.cache_dir)  if args.cache_dir  else None
    generated_at = datetime.now()

    # ── Load assets ──────────────────────────────────────────────────────────
    if args.no_fetch:
        if cache_dir is None:
            print("ERROR: --no-fetch requires --cache-dir.")
            sys.exit(1)
        parquet = cache_dir / "assets_all.parquet"
        if not parquet.exists():
            print(f"ERROR: Cache file not found: {parquet}")
            sys.exit(1)
        print(f"Loading assets from cache: {parquet}")
        assets_df = pd.read_parquet(parquet)
        print(f"  {len(assets_df):,} asset records loaded.")
    else:
        try:
            from tenable_client import get_client       # noqa: PLC0415
            tio = get_client()
        except SystemExit:
            sys.exit(1)
        except Exception as exc:
            print(f"ERROR: Tenable connection failed: {exc}")
            sys.exit(1)

        from data.fetchers import fetch_all_assets      # noqa: PLC0415
        from config import CACHE_DIR                    # noqa: PLC0415

        if cache_dir is None:
            cache_dir = CACHE_DIR / generated_at.strftime("%Y-%m-%d")

        print(f"Fetching assets (cache: {cache_dir}) …")
        assets_df = fetch_all_assets(tio, cache_dir)
        print(f"  {len(assets_df):,} asset records loaded.")

    # ── Run detection ─────────────────────────────────────────────────────────
    result = run(
        assets_df,
        output_dir=output_dir,
        dry_run=args.dry_run,
        generated_at=generated_at,
    )

    if not args.dry_run and result["total_groups"] == 0:
        print("No duplicate groups found — no CSV written.")

    sys.exit(0)
