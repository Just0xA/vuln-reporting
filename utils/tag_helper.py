"""
utils/tag_helper.py — Tag discovery and asset-tag enrichment utilities.

Provides:
  - get_all_tags()          : fetch all tag categories and values from Tenable
  - get_assets_by_tag()     : return asset ID list for a category/value pair
  - enrich_vulns_with_tags(): join tag data onto a vulnerability DataFrame

CLI usage:
  python utils/tag_helper.py --list-tags
  python utils/tag_helper.py --list-tags --category "Business Unit"
  python utils/tag_helper.py --list-values --category "Environment"
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd
from rich.console import Console
from rich.table import Table

# Allow running as a standalone script from any directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from data.fetchers import fetch_tags, fetch_assets_by_tag

logger = logging.getLogger(__name__)
console = Console()


# ===========================================================================
# Public API
# ===========================================================================

def get_all_tags(tio, run_id: str = "latest") -> pd.DataFrame:
    """
    Retrieve all Tenable tag categories and values.

    Thin wrapper around data.fetchers.fetch_tags() provided here so report
    scripts and utilities can import from a single, named location.

    Parameters
    ----------
    tio : TenableIO
        Authenticated Tenable client.
    run_id : str
        Run-scoped cache key.

    Returns
    -------
    pd.DataFrame
        Columns: tag_uuid, category_name, value, description, asset_count
    """
    return fetch_tags(tio, run_id)


def get_assets_by_tag(
    tio,
    tag_category: str,
    tag_value: str,
    run_id: str = "latest",
) -> list[str]:
    """
    Return a list of asset UUIDs that carry the specified tag category/value.

    Parameters
    ----------
    tio : TenableIO
    tag_category : str
        e.g. "Business Unit"
    tag_value : str
        e.g. "Finance"
    run_id : str

    Returns
    -------
    list[str]
        List of asset UUID strings.  Empty list if no match.
    """
    df = fetch_assets_by_tag(tio, run_id, tag_category=tag_category, tag_value=tag_value)
    if df.empty:
        return []
    return df["asset_id"].tolist()


def enrich_vulns_with_tags(
    vulns_df: pd.DataFrame,
    tio,
    run_id: str = "latest",
) -> pd.DataFrame:
    """
    Attach per-asset tag data to a vulnerability DataFrame.

    Fetches the full asset list (cached), parses the tag strings, and joins
    all tag categories as individual columns onto the vulnerability rows.

    The resulting DataFrame gains one column per unique tag category found
    in the data, with the category name normalized to a safe column name
    (spaces → underscores, lowercased, prefixed with "tag_").

    For assets with multiple values in the same category, values are joined
    with " | ".

    Parameters
    ----------
    vulns_df : pd.DataFrame
        Output of data.fetchers.fetch_vulnerabilities().
    tio : TenableIO
        Authenticated Tenable client (used to fetch assets if not cached).
    run_id : str

    Returns
    -------
    pd.DataFrame
        Enriched DataFrame with tag_ columns appended.
    """
    from data.fetchers import fetch_assets

    if vulns_df.empty:
        return vulns_df

    assets_df = fetch_assets(tio, run_id)
    if assets_df.empty or "tags" not in assets_df.columns:
        return vulns_df

    # Expand the semicolon-delimited tag strings into a pivot table
    # Each row: asset_id, category, value
    expanded_rows: list[dict] = []
    for _, row in assets_df[["asset_id", "tags"]].iterrows():
        raw = row["tags"]
        if not raw or not isinstance(raw, str):
            continue
        for tag_str in raw.split(";"):
            if "=" not in tag_str:
                continue
            cat, val = tag_str.split("=", 1)
            expanded_rows.append({
                "asset_id": row["asset_id"],
                "category": cat.strip(),
                "value": val.strip(),
            })

    if not expanded_rows:
        return vulns_df

    tag_long = pd.DataFrame(expanded_rows)

    # Pivot: one row per asset, one column per tag category
    tag_wide = (
        tag_long.groupby(["asset_id", "category"])["value"]
        .apply(lambda vals: " | ".join(sorted(set(vals))))
        .unstack(level="category")
        .reset_index()
    )

    # Rename columns to safe Python identifiers
    rename_map = {
        col: "tag_" + col.lower().replace(" ", "_").replace("-", "_")
        for col in tag_wide.columns
        if col != "asset_id"
    }
    tag_wide = tag_wide.rename(columns=rename_map)

    enriched = vulns_df.merge(tag_wide, on="asset_id", how="left")
    logger.debug(
        "Enriched %d vuln rows with %d tag columns.",
        len(enriched),
        len(rename_map),
    )
    return enriched


# ===========================================================================
# CLI helpers
# ===========================================================================

def _print_tags_table(tags_df: pd.DataFrame, category_filter: str | None = None) -> None:
    """Render tag data as a rich table on stdout."""
    if category_filter:
        tags_df = tags_df[
            tags_df["category_name"].str.lower() == category_filter.lower()
        ]

    if tags_df.empty:
        console.print("[yellow]No tags found matching the specified criteria.[/yellow]")
        return

    table = Table(title="Tenable Tags", show_lines=True)
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Asset Count", justify="right", style="magenta")
    table.add_column("Description")

    for _, row in tags_df.sort_values(["category_name", "value"]).iterrows():
        table.add_row(
            str(row.get("category_name", "")),
            str(row.get("value", "")),
            str(row.get("asset_count", "")),
            str(row.get("description", "") or ""),
        )

    console.print(table)
    console.print(f"\n[bold]Total: {len(tags_df)} tag(s)[/bold]")


def _print_categories(tags_df: pd.DataFrame) -> None:
    """Print a deduplicated list of tag category names."""
    categories = sorted(tags_df["category_name"].dropna().unique().tolist())
    table = Table(title="Tag Categories", show_lines=True)
    table.add_column("Category Name", style="cyan")
    table.add_column("Unique Values", justify="right", style="magenta")

    counts = tags_df.groupby("category_name")["value"].nunique()
    for cat in categories:
        table.add_row(cat, str(counts.get(cat, 0)))

    console.print(table)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tenable tag discovery tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python utils/tag_helper.py --list-tags
  python utils/tag_helper.py --list-tags --category "Business Unit"
  python utils/tag_helper.py --list-categories
  python utils/tag_helper.py --list-values --category "Environment"
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--list-tags",
        action="store_true",
        help="List all tag categories and values",
    )
    group.add_argument(
        "--list-categories",
        action="store_true",
        help="List unique tag category names only",
    )
    group.add_argument(
        "--list-values",
        action="store_true",
        help="List values for a specific category (requires --category)",
    )

    parser.add_argument(
        "--category",
        metavar="CATEGORY",
        help="Filter output to this tag category",
    )
    parser.add_argument(
        "--run-id",
        default="latest",
        help="Cache key for this run (default: latest)",
    )

    args = parser.parse_args()

    # Import here to avoid circular import when used as a library
    from tenable_client import get_client

    tio = get_client()
    tags_df = get_all_tags(tio, run_id=args.run_id)

    if args.list_tags:
        _print_tags_table(tags_df, category_filter=args.category)

    elif args.list_categories:
        _print_categories(tags_df)

    elif args.list_values:
        if not args.category:
            console.print("[red]--list-values requires --category[/red]")
            sys.exit(1)
        _print_tags_table(tags_df, category_filter=args.category)
