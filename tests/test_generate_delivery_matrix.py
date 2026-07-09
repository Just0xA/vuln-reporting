"""
tests/test_generate_delivery_matrix.py — Phase 20 CONF-05 delivery-matrix
generator regression.

Locks in the behavior of ``scripts/generate_delivery_matrix.py`` added in
Plan 20-03:
  * ``render_markdown`` covers every delivery name, owner, report slug,
    schedule, filters cell, and contact NAME from the resolved config.
  * Owner + contact NAME are sourced from ``metadata_by_delivery_name``
    (joined by delivery name), never from the schema-gated group dict,
    which carries no owner/contact key (D-09).
  * PII invariant (D-05 / Hard Rule 2): neither markdown nor html output
    contains any recipient address — names + owner only.
  * ``render_html`` produces a `<table` containing every delivery name.
  * A delivery with ``filters: {}`` renders "All Assets".

All addresses use the RFC 6761 reserved example.invalid domain (Hard
Rule 2 / D-04-08) — no real recipient addresses anywhere in this file.

Run: python -m pytest tests/test_generate_delivery_matrix.py -q
     (or) python tests/test_generate_delivery_matrix.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from delivery.config_loader import resolve_config  # noqa: E402
from scripts.generate_delivery_matrix import render_html, render_markdown  # noqa: E402

FAILED: list[str] = []


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


_CONTACTS_YAML = """
contacts:
  exec_team:
    recipients:
      - ciso@example.invalid
      - vp-it@example.invalid
    cc:
      - board-liaison@example.invalid
  remediation_team:
    recipients:
      - remediation@example.invalid
defaults:
  analyst_mailbox: analyst-team@example.invalid
"""

_FIXTURE_RECIPIENT_ADDRESSES = (
    "ciso@example.invalid",
    "vp-it@example.invalid",
    "board-liaison@example.invalid",
    "remediation@example.invalid",
    "analyst-team@example.invalid",
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _make_twin(base_dir: Path) -> Path:
    """Write a synthetic directory-mode twin covering both a tag-scoped and
    an all-assets ("filters: {}") delivery.
    """
    config_path = base_dir / "delivery_config.yaml"
    _write(base_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        base_dir / "deliveries.d" / "exec.yaml",
        """
owner: "IT Metrics Team"
deliveries:
  - name: "Executive Team"
    contact: exec_team
    subject: "Weekly Vuln Management Summary"
    schedule:
      frequency: weekly
      day_of_week: monday
      time: "07:00"
    filters:
      tag_category: "Environment"
      tag_value: "Production"
    reports:
      - executive_kpi
""",
    )
    _write(
        base_dir / "deliveries.d" / "remediation.yaml",
        """
owner: "Remediation Team"
deliveries:
  - name: "Remediation Team Delivery"
    contact: remediation_team
    subject: "Remediation Worklist"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - sla_remediation
      - patch_compliance
""",
    )
    return config_path


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        base_dir = Path(tmp)
        config_path = _make_twin(base_dir)
        groups, errors, _warnings, metadata = resolve_config(config_path)

        _check(
            "setup_twin_resolves_no_errors",
            errors == [] and len(groups) == 2,
            hint=str((errors, groups)),
        )

        markdown = render_markdown(groups, metadata)
        html = render_html(groups, metadata)

        # 1 — markdown contains every delivery name, owner, report slug,
        # and contact NAME from the fixture.
        _check(
            "markdown_contains_delivery_names",
            "Executive Team" in markdown and "Remediation Team Delivery" in markdown,
            hint=markdown,
        )
        _check(
            "markdown_contains_owners",
            "IT Metrics Team" in markdown and "Remediation Team" in markdown,
            hint=markdown,
        )
        _check(
            "markdown_contains_report_slugs",
            "executive_kpi" in markdown
            and "sla_remediation" in markdown
            and "patch_compliance" in markdown,
            hint=markdown,
        )
        _check(
            "markdown_contains_contact_names",
            "exec_team" in markdown and "remediation_team" in markdown,
            hint=markdown,
        )

        # 2 — PII invariant (D-05): no recipient address in markdown or html.
        markdown_leaks = [addr for addr in _FIXTURE_RECIPIENT_ADDRESSES if addr in markdown]
        html_leaks = [addr for addr in _FIXTURE_RECIPIENT_ADDRESSES if addr in html]
        _check(
            "PII_no_recipient_address_in_markdown",
            markdown_leaks == [],
            hint=str(markdown_leaks),
        )
        _check(
            "PII_no_recipient_address_in_html",
            html_leaks == [],
            hint=str(html_leaks),
        )
        _check(
            "PII_no_example_invalid_at_sign_in_markdown",
            "@example.invalid" not in markdown,
            hint=markdown,
        )
        _check(
            "PII_no_example_invalid_at_sign_in_html",
            "@example.invalid" not in html,
            hint=html,
        )

        # 3 — owner + contact come from the metadata side channel, not the
        # group dict (which carries no owner/contact key).
        _check(
            "side_channel_groups_carry_no_owner_contact_keys",
            all("owner" not in g and "contact" not in g for g in groups),
            hint=str(groups),
        )
        _check(
            "side_channel_metadata_populated",
            metadata.get("Executive Team", {}).get("owner") == "IT Metrics Team"
            and metadata.get("Executive Team", {}).get("contact") == "exec_team",
            hint=str(metadata),
        )

        # 4 — --format html produces <table containing the same delivery names.
        _check(
            "html_contains_table_tag",
            "<table" in html,
            hint=html,
        )
        _check(
            "html_contains_delivery_names",
            "Executive Team" in html and "Remediation Team Delivery" in html,
            hint=html,
        )

        # 5 — filters: {} renders "All Assets".
        _check(
            "filters_empty_renders_all_assets",
            "All Assets" in markdown and "All Assets" in html,
            hint=markdown,
        )

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
