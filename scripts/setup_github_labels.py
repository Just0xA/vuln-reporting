"""Create / sync the GitHub labels referenced by CONTRIBUTING.md.

Idempotent — safe to run repeatedly. Existing labels with the same name are
updated in place (color + description); missing labels are created; labels
already correct are left alone.

Usage:
    # PowerShell
    $env:GH_TOKEN = "ghp_yourTokenHere"
    python scripts/setup_github_labels.py

    # bash / zsh
    GH_TOKEN=ghp_yourTokenHere python scripts/setup_github_labels.py

The token needs `repo` scope (or `public_repo` if the repo is public-only).
Create one at: https://github.com/settings/tokens

Override the target repo with --repo OWNER/NAME (default: Just0xA/vuln-reporting).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_REPO = "Just0xA/vuln-reporting"

LABELS: list[dict[str, str]] = [
    # Classification — what kind of work is this?
    {
        "name": "feature-request",
        "color": "a2eeef",
        "description": "Proposes net-new capability (new report, module, channel, or fetcher).",
    },
    {
        "name": "enhancement",
        "color": "7057ff",
        "description": "Modifies existing behavior (not net-new).",
    },
    {
        "name": "bug",
        "color": "d73a4a",
        "description": "Defect, crash, incorrect output, or unexpected behavior.",
    },
    {
        "name": "type: chore",
        "color": "c5def5",
        "description": "Maintenance task with no user-facing change.",
    },
    # Pending operator attention
    {
        "name": "needs-review",
        "color": "fbca04",
        "description": "Awaiting maintainer triage / approval (features and enhancements).",
    },
    {
        "name": "needs-triage",
        "color": "e99695",
        "description": "Awaiting maintainer triage / confirmation (bugs and chores).",
    },
    # Approval gates — required on linked issue before a PR can be opened
    {
        "name": "approved-feature",
        "color": "0e8a16",
        "description": "Feature request approved — PR may now be opened against this issue.",
    },
    {
        "name": "approved-enhancement",
        "color": "1d76db",
        "description": "Enhancement approved — PR may now be opened against this issue.",
    },
    {
        "name": "confirmed-bug",
        "color": "b60205",
        "description": "Bug reproduced and confirmed — fix PR may now be opened against this issue.",
    },
    # Auto-flag from /gsd-inbox triage
    {
        "name": "gate-violation",
        "color": "e11d21",
        "description": "PR opened without the required approval gate label on its linked issue. Auto-applied by /gsd-inbox.",
    },
]


def _api_request(method: str, url: str, token: str, payload: dict | None = None) -> tuple[int, dict | None]:
    body = None
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vuln-reporting-label-setup",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            err = json.loads(raw)
        except json.JSONDecodeError:
            err = {"message": raw}
        return e.code, err


def _list_existing_labels(repo: str, token: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/labels?per_page=100&page={page}"
        status, data = _api_request("GET", url, token)
        if status != 200 or not isinstance(data, list):
            raise SystemExit(f"Failed to list labels (HTTP {status}): {data!r}")
        if not data:
            break
        for label in data:
            out[label["name"]] = label
        if len(data) < 100:
            break
        page += 1
    return out


def _create_label(repo: str, token: str, label: dict[str, str]) -> None:
    url = f"https://api.github.com/repos/{repo}/labels"
    status, data = _api_request("POST", url, token, label)
    if status not in (200, 201):
        raise SystemExit(f"Create failed for {label['name']!r}: HTTP {status} — {data!r}")


def _update_label(repo: str, token: str, label: dict[str, str]) -> None:
    # URL-encode the label name to handle "type: chore" and similar.
    encoded = urllib.request.quote(label["name"], safe="")
    url = f"https://api.github.com/repos/{repo}/labels/{encoded}"
    status, data = _api_request("PATCH", url, token, label)
    if status != 200:
        raise SystemExit(f"Update failed for {label['name']!r}: HTTP {status} — {data!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help=f"GitHub repository in OWNER/NAME form (default: {DEFAULT_REPO}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without making any API calls beyond listing.",
    )
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print(
            "ERROR: Set GH_TOKEN (or GITHUB_TOKEN) to a GitHub personal access token "
            "with `repo` (or `public_repo`) scope. Create one at "
            "https://github.com/settings/tokens",
            file=sys.stderr,
        )
        return 2

    print(f"Target repo: {args.repo}")
    existing = _list_existing_labels(args.repo, token)
    print(f"Existing labels on repo: {len(existing)}\n")

    created = updated = unchanged = 0
    for label in LABELS:
        name = label["name"]
        if name in existing:
            cur = existing[name]
            if cur.get("color") == label["color"] and (cur.get("description") or "") == label["description"]:
                print(f"  [=] {name:<24} already correct")
                unchanged += 1
                continue
            if args.dry_run:
                print(f"  [~] {name:<24} would update (color/description differs)")
            else:
                _update_label(args.repo, token, label)
                print(f"  [~] {name:<24} updated")
            updated += 1
        else:
            if args.dry_run:
                print(f"  [+] {name:<24} would create")
            else:
                _create_label(args.repo, token, label)
                print(f"  [+] {name:<24} created")
            created += 1

    print(f"\nSummary: {created} created, {updated} updated, {unchanged} unchanged.")
    if args.dry_run:
        print("Dry-run only — no changes made.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
