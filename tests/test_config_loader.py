"""
tests/test_config_loader.py — Phase 20 CONF-01/02/03 loader regression.

Locks in the resolve-before-validate config loader behavior added in
Plan 20-01:
  * Task 1: contacts.yaml resolution (`resolve_contacts`) and per-delivery
    `contact:` ref + `defaults.analyst_mailbox` + `extra_recipients:`
    resolution (`resolve_delivery_email`).
  * Task 2: directory-mode discovery, glob+merge of deliveries.d/,
    global delivery-name uniqueness, inline-email rejection, deprecated
    `groups:` alias, and the owner/contact `metadata_by_delivery_name`
    side channel (`resolve_config`).
  * Task 3: `run_all._load_config` directory-mode delegation preserving
    the `list[dict]` return contract.

All addresses use the RFC 6761 reserved example.invalid domain (Hard
Rule 2 / D-04-08) — no real recipient addresses anywhere in this file.

Run: python -m pytest tests/test_config_loader.py -q
     (or) python tests/test_config_loader.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from delivery.config_loader import (  # noqa: E402
    resolve_config,
    resolve_contacts,
    resolve_delivery_email,
)
from run_all import (  # noqa: E402
    _load_config,
    _load_schema,
    _select_config_source,
    _validate_with_schema,
)

FAILED: list[str] = []


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


# ---------------------------------------------------------------------------
# Task 1 fixtures — resolve_contacts / resolve_delivery_email
# ---------------------------------------------------------------------------

def _contacts_doc() -> dict:
    return {
        "contacts": {
            "exec_team": {
                "recipients": ["ciso@example.invalid", "vp-it@example.invalid"],
                "cc": ["board-liaison@example.invalid"],
            },
            "custom_reply_team": {
                "recipients": ["custom@example.invalid"],
                "reply_to": "custom-reply@example.invalid",
            },
        },
        "defaults": {
            "analyst_mailbox": "analyst-team@example.invalid",
        },
    }


def _task1_checks() -> None:
    contacts_by_name, defaults = resolve_contacts(_contacts_doc())

    _check(
        "T1_resolve_contacts_shape",
        set(contacts_by_name.keys()) == {"exec_team", "custom_reply_team"}
        and defaults == {"analyst_mailbox": "analyst-team@example.invalid"},
        hint=str((contacts_by_name, defaults)),
    )

    # A — contact: ref resolves recipients/cc/reply_to
    delivery = {"contact": "exec_team", "subject": "Weekly Exec Summary"}
    email, errs = resolve_delivery_email(delivery, contacts_by_name, defaults)
    _check(
        "A_contact_ref_resolves_recipients",
        errs == []
        and email is not None
        and email["recipients"] == ["ciso@example.invalid", "vp-it@example.invalid"],
        hint=str((email, errs)),
    )

    # B — defaults.analyst_mailbox standing Cc + default reply_to
    _check(
        "B_analyst_mailbox_standing_cc",
        email is not None and "analyst-team@example.invalid" in email["cc"],
        hint=str(email),
    )
    _check(
        "B_analyst_mailbox_default_reply_to",
        email is not None and email.get("reply_to") == "analyst-team@example.invalid",
        hint=str(email),
    )
    # analyst_mailbox deduped against contact's own cc (board-liaison stays too)
    _check(
        "B_cc_dedup_preserves_contact_cc",
        email is not None and "board-liaison@example.invalid" in email["cc"],
        hint=str(email),
    )

    # C — contact's own reply_to overrides analyst_mailbox reply_to,
    # but analyst_mailbox still appears as standing Cc.
    delivery_c = {"contact": "custom_reply_team", "subject": "Custom Reply Test"}
    email_c, errs_c = resolve_delivery_email(delivery_c, contacts_by_name, defaults)
    _check(
        "C_contact_reply_to_overrides_default",
        errs_c == []
        and email_c is not None
        and email_c.get("reply_to") == "custom-reply@example.invalid",
        hint=str((email_c, errs_c)),
    )
    _check(
        "C_analyst_mailbox_still_standing_cc",
        email_c is not None and "analyst-team@example.invalid" in email_c["cc"],
        hint=str(email_c),
    )

    # D — extra_recipients merge+dedupe; contact's own address never
    # overridden/removed.
    delivery_d = {
        "contact": "exec_team",
        "subject": "Extra Recipients Test",
        "extra_recipients": ["ciso@example.invalid", "extra@example.invalid"],
    }
    email_d, errs_d = resolve_delivery_email(delivery_d, contacts_by_name, defaults)
    _check(
        "D_extra_recipients_merge_dedupe",
        errs_d == []
        and email_d is not None
        and email_d["recipients"] == [
            "ciso@example.invalid",
            "vp-it@example.invalid",
            "extra@example.invalid",
        ],
        hint=str((email_d, errs_d)),
    )

    # E — undefined contact ref collected as a permissive-check error
    # (not a raise).
    delivery_e = {"contact": "nonexistent", "subject": "Broken"}
    email_e, errs_e = resolve_delivery_email(delivery_e, contacts_by_name, defaults)
    _check(
        "E_undefined_contact_ref_error",
        email_e is None and len(errs_e) == 1 and "nonexistent" in errs_e[0],
        hint=str((email_e, errs_e)),
    )


# ---------------------------------------------------------------------------
# Task 2 fixtures — resolve_config (directory-mode discovery)
# ---------------------------------------------------------------------------

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


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _make_well_formed_twin(base_dir: Path) -> Path:
    """Write a well-formed contacts.yaml + deliveries.d/ twin under base_dir."""
    config_path = base_dir / "delivery_config.yaml"
    _write(base_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        base_dir / "deliveries.d" / "exec.yaml",
        """
owner: "IT Metrics Team"
deliveries:
  - name: "Executive Team"
    contact: exec_team
    subject: "Weekly Vuln Management Summary — Production"
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
    return config_path


def _task2_checks(tmp_root: Path) -> None:
    # F — well-formed twin resolves and PASSES the existing schema.
    twin_dir = tmp_root / "well_formed"
    config_path = _make_well_formed_twin(twin_dir)
    groups, errors, warnings, metadata = resolve_config(config_path)
    _check(
        "F_well_formed_twin_resolves_no_errors",
        errors == [] and len(groups) == 1,
        hint=str((errors, groups)),
    )
    schema = _load_schema()
    schema_errs = _validate_with_schema({"groups": groups}, schema)
    _check(
        "F_well_formed_twin_passes_schema",
        schema_errs == [],
        hint=str(schema_errs),
    )

    # Side channel — metadata_by_delivery_name populated; no owner/contact
    # keys on the group dicts themselves.
    _check(
        "SideChannel_metadata_populated",
        metadata.get("Executive Team") == {"owner": "IT Metrics Team", "contact": "exec_team"},
        hint=str(metadata),
    )
    _check(
        "SideChannel_groups_carry_no_owner_contact_keys",
        all("owner" not in g and "contact" not in g for g in groups),
        hint=str(groups),
    )

    # G — duplicate delivery name across two team files -> error, empty groups.
    dup_dir = tmp_root / "duplicate_name"
    _write(dup_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        dup_dir / "deliveries.d" / "team_a.yaml",
        """
owner: "Team A"
deliveries:
  - name: "Shared Name"
    contact: exec_team
    subject: "A"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    _write(
        dup_dir / "deliveries.d" / "team_b.yaml",
        """
owner: "Team B"
deliveries:
  - name: "Shared Name"
    contact: remediation_team
    subject: "B"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    dup_groups, dup_errors, _dup_warnings, _dup_metadata = resolve_config(
        dup_dir / "delivery_config.yaml"
    )
    _check(
        "G_duplicate_delivery_name_error",
        dup_groups == [] and any("duplicate delivery name" in e for e in dup_errors),
        hint=str(dup_errors),
    )

    # H — inline email.recipients in directory mode is rejected.
    inline_dir = tmp_root / "inline_email"
    _write(inline_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        inline_dir / "deliveries.d" / "team.yaml",
        """
owner: "Team Inline"
deliveries:
  - name: "Inline Email Delivery"
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
    email:
      recipients:
        - inline@example.invalid
""",
    )
    inline_groups, inline_errors, _inline_warnings, _inline_metadata = resolve_config(
        inline_dir / "delivery_config.yaml"
    )
    _check(
        "H_inline_email_rejected",
        inline_groups == [] and any(
            "inline" in e.lower() and "email" in e.lower() for e in inline_errors
        ),
        hint=str(inline_errors),
    )

    # I — missing contacts.yaml while deliveries.d/ exists -> clear error.
    missing_contacts_dir = tmp_root / "missing_contacts"
    _write(
        missing_contacts_dir / "deliveries.d" / "team.yaml",
        """
owner: "Team X"
deliveries:
  - name: "Some Delivery"
    contact: exec_team
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    mc_groups, mc_errors, _mc_warnings, _mc_metadata = resolve_config(
        missing_contacts_dir / "delivery_config.yaml"
    )
    _check(
        "I_missing_contacts_yaml_error",
        mc_groups == [] and any("contacts.yaml" in e for e in mc_errors),
        hint=str(mc_errors),
    )

    # J — deprecated top-level `groups:` alias in a team file is accepted
    # with a warning, still loads.
    alias_dir = tmp_root / "deprecated_alias"
    _write(alias_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        alias_dir / "deliveries.d" / "team.yaml",
        """
owner: "Team Alias"
groups:
  - name: "Alias Delivery"
    contact: exec_team
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    alias_groups, alias_errors, alias_warnings, _alias_metadata = resolve_config(
        alias_dir / "delivery_config.yaml"
    )
    _check(
        "J_deprecated_groups_alias_warns_and_loads",
        alias_errors == []
        and len(alias_groups) == 1
        and any("groups" in w and "deliveries" in w for w in alias_warnings),
        hint=str((alias_errors, alias_groups, alias_warnings)),
    )


# ---------------------------------------------------------------------------
# Task 3 fixtures — run_all._load_config directory-mode delegation
# ---------------------------------------------------------------------------

def _task3_checks(tmp_root: Path) -> None:
    twin_dir = tmp_root / "load_config_well_formed"
    config_path = _make_well_formed_twin(twin_dir)
    groups = _load_config(config_path=config_path)
    _check(
        "K_load_config_directory_mode_returns_list_of_dicts",
        isinstance(groups, list) and len(groups) == 1 and isinstance(groups[0], dict),
        hint=str(groups),
    )

    dup_dir = tmp_root / "load_config_duplicate"
    _write(dup_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        dup_dir / "deliveries.d" / "team_a.yaml",
        """
owner: "Team A"
deliveries:
  - name: "Dup"
    contact: exec_team
    subject: "A"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    _write(
        dup_dir / "deliveries.d" / "team_b.yaml",
        """
owner: "Team B"
deliveries:
  - name: "Dup"
    contact: remediation_team
    subject: "B"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    dup_groups = _load_config(config_path=dup_dir / "delivery_config.yaml")
    _check(
        "L_load_config_duplicate_name_returns_empty_list",
        dup_groups == [],
        hint=str(dup_groups),
    )

    # Legacy single-file path still works via _load_config.
    legacy_groups = _load_config(
        config_path=Path(__file__).resolve().parent.parent / "delivery_config.yaml"
    )
    _check(
        "M_load_config_legacy_single_file_still_works",
        isinstance(legacy_groups, list) and len(legacy_groups) > 0,
        hint=str(legacy_groups),
    )


# ---------------------------------------------------------------------------
# Task 1 (21-01) fixtures — _select_config_source
# ---------------------------------------------------------------------------

def _task_select_source_checks(tmp_root: Path) -> None:
    # Row 1 — deliveries.d/ present, resolves clean, passes schema -> "directory".
    clean_dir = tmp_root / "select_source_directory_ok"
    config_path = _make_well_formed_twin(clean_dir)
    _check(
        "N_select_source_directory_ok",
        _select_config_source(config_path) == "directory",
        hint=_select_config_source(config_path),
    )

    # Row 2 — deliveries.d/ present with a load_error (duplicate name) AND a
    # legacy delivery_config.yaml sibling present -> "legacy-fallback".
    fallback_dir = tmp_root / "select_source_legacy_fallback"
    _write(fallback_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        fallback_dir / "deliveries.d" / "team_a.yaml",
        """
owner: "Team A"
deliveries:
  - name: "Dup"
    contact: exec_team
    subject: "A"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    _write(
        fallback_dir / "deliveries.d" / "team_b.yaml",
        """
owner: "Team B"
deliveries:
  - name: "Dup"
    contact: remediation_team
    subject: "B"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    _write(
        fallback_dir / "delivery_config.yaml",
        """
groups:
  - name: "Legacy Group"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
    email:
      recipients:
        - legacy@example.invalid
""",
    )
    fallback_config_path = fallback_dir / "delivery_config.yaml"
    _check(
        "O_select_source_resolution_failure_legacy_fallback",
        _select_config_source(fallback_config_path) == "legacy-fallback",
        hint=_select_config_source(fallback_config_path),
    )

    # Row 3 — deliveries.d/ present, resolves clean but FAILS the schema
    # gate (missing required 'reports' key) AND a legacy file exists ->
    # "legacy-fallback".
    schema_fail_dir = tmp_root / "select_source_schema_fail_fallback"
    _write(schema_fail_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        schema_fail_dir / "deliveries.d" / "team.yaml",
        """
owner: "Team Schema Fail"
deliveries:
  - name: "No Reports Delivery"
    contact: exec_team
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports: []
""",
    )
    _write(
        schema_fail_dir / "delivery_config.yaml",
        """
groups:
  - name: "Legacy Group"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
    email:
      recipients:
        - legacy@example.invalid
""",
    )
    schema_fail_config_path = schema_fail_dir / "delivery_config.yaml"
    _check(
        "P_select_source_schema_failure_legacy_fallback",
        _select_config_source(schema_fail_config_path) == "legacy-fallback",
        hint=_select_config_source(schema_fail_config_path),
    )

    # Row 4 — deliveries.d/ present, resolution fails, AND legacy file
    # absent -> "none" (terminal dual-source-retired state).
    none_dir = tmp_root / "select_source_none"
    _write(none_dir / "contacts.yaml", _CONTACTS_YAML)
    _write(
        none_dir / "deliveries.d" / "team_a.yaml",
        """
owner: "Team A"
deliveries:
  - name: "Dup"
    contact: exec_team
    subject: "A"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    _write(
        none_dir / "deliveries.d" / "team_b.yaml",
        """
owner: "Team B"
deliveries:
  - name: "Dup"
    contact: remediation_team
    subject: "B"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    none_config_path = none_dir / "delivery_config.yaml"
    _check(
        "Q_select_source_no_fallback_available_none",
        _select_config_source(none_config_path) == "none",
        hint=_select_config_source(none_config_path),
    )

    # Row 5 — no deliveries.d/ at all; legacy delivery_config.yaml present
    # -> "legacy".
    legacy_only_dir = tmp_root / "select_source_legacy_only"
    _write(
        legacy_only_dir / "delivery_config.yaml",
        """
groups:
  - name: "Legacy Only Group"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
    email:
      recipients:
        - legacy@example.invalid
""",
    )
    legacy_only_config_path = legacy_only_dir / "delivery_config.yaml"
    _check(
        "R_select_source_no_deliveries_d_legacy",
        _select_config_source(legacy_only_config_path) == "legacy",
        hint=_select_config_source(legacy_only_config_path),
    )


def main() -> int:
    import tempfile

    _task1_checks()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        _task2_checks(tmp_root)
        _task3_checks(tmp_root)
        _task_select_source_checks(tmp_root)

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
