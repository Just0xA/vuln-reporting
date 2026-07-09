"""
delivery/config_loader.py — resolve-before-validate loader for the v1.6
config language (contacts.yaml + deliveries.d/*.yaml).

This module resolves the new source language — a shared `contacts.yaml`
(named contact groups + a top-level `defaults:` block) and per-team
`deliveries.d/<team>.yaml` files — into today's concrete group/`email:`
shape. The resolved effective config is handed to the *existing*
`delivery_config.schema.yaml` gate (via `run_all._validate_with_schema`)
unchanged; this module never defines a second schema.

Directory-mode discovery, glob+merge, and the `metadata_by_delivery_name`
side channel are implemented in `resolve_config` (Task 2). This module
never raises out of the resolution path — failures are collected as
error/warning strings for the caller to log (fail-loud-never-raise,
matching `run_all._load_config`).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml


def resolve_contacts(contacts_doc: dict) -> tuple[dict, dict]:
    """
    Parse a contacts.yaml document into a name -> contact-group mapping
    plus a defaults block.

    Parameters
    ----------
    contacts_doc : dict
        Parsed contacts.yaml content (already loaded via ``yaml.safe_load``
        by the caller — this function never parses YAML itself).
        Expected shape::

            contacts:
              exec_team:
                recipients: [ciso@example.invalid]
                cc: [board-liaison@example.invalid]
                reply_to: security@example.invalid
            defaults:
              analyst_mailbox: analyst-team@example.invalid

    Returns
    -------
    tuple[dict, dict]
        ``(contacts_by_name, defaults)`` where ``contacts_by_name`` maps
        each contact key to ``{"recipients": [...], "cc": [...],
        "reply_to": str | None}`` and ``defaults`` is the raw
        ``defaults:`` block (``{}`` if absent).
    """
    contacts_by_name: dict = {}
    raw_contacts = contacts_doc.get("contacts") or {}
    for name, entry in raw_contacts.items():
        entry = entry or {}
        contacts_by_name[name] = {
            "recipients": list(entry.get("recipients") or []),
            "cc": list(entry.get("cc") or []),
            "reply_to": entry.get("reply_to"),
        }

    defaults = contacts_doc.get("defaults") or {}
    return contacts_by_name, defaults


def resolve_delivery_email(
    delivery: dict,
    contacts_by_name: dict,
    defaults: dict,
) -> tuple[Optional[dict], list[str]]:
    """
    Resolve a single delivery's ``contact:`` ref + ``extra_recipients:``
    + ``defaults.analyst_mailbox`` into a concrete ``email:`` block.

    Parameters
    ----------
    delivery : dict
        A single delivery entry from a ``deliveries.d/*.yaml`` team file.
        Expected to carry ``contact: <key>``, an optional
        ``extra_recipients: [...]`` list, and a ``subject`` (either at
        the delivery's top level or nested under an ``email:`` stub —
        the delivery's own ``subject:`` key takes precedence).
    contacts_by_name : dict
        Output of :func:`resolve_contacts`.
    defaults : dict
        Output of :func:`resolve_contacts` (the ``defaults`` block).

    Returns
    -------
    tuple[dict | None, list[str]]
        ``(email_block, errors)``. On an undefined ``contact:`` ref,
        ``email_block`` is ``None`` and ``errors`` contains a single
        human-readable error string. On success, ``errors`` is ``[]``
        and ``email_block`` has ``subject``, ``recipients``, ``cc``,
        ``reply_to`` (schema shape — ``delivery_config.schema.yaml``
        lines 230-264).
    """
    contact_key = delivery.get("contact")
    if contact_key is None or contact_key not in contacts_by_name:
        return None, [f"undefined contact ref: {contact_key}"]

    contact = contacts_by_name[contact_key]

    # Order-preserving dedupe via a seen-set.
    recipients: list[str] = []
    seen_recipients: set[str] = set()
    for addr in contact["recipients"]:
        if addr not in seen_recipients:
            recipients.append(addr)
            seen_recipients.add(addr)

    # extra_recipients: additive, deduped, never overriding the contact's
    # own addresses (contact addresses were added first above).
    for addr in delivery.get("extra_recipients") or []:
        if addr not in seen_recipients:
            recipients.append(addr)
            seen_recipients.add(addr)

    cc: list[str] = []
    seen_cc: set[str] = set()
    for addr in contact["cc"]:
        if addr not in seen_cc:
            cc.append(addr)
            seen_cc.add(addr)

    # defaults.analyst_mailbox: standing Cc (deduped), no opt-out (D-02).
    analyst_mailbox = defaults.get("analyst_mailbox")
    if analyst_mailbox and analyst_mailbox not in seen_cc:
        cc.append(analyst_mailbox)
        seen_cc.add(analyst_mailbox)

    # reply_to: contact's own override wins; otherwise analyst_mailbox
    # is the default reply_to.
    reply_to = contact.get("reply_to") or analyst_mailbox

    # subject: delivery's own `subject:` key, or a nested `email.subject`
    # stub if present.
    subject = delivery.get("subject")
    if subject is None:
        email_stub = delivery.get("email") or {}
        subject = email_stub.get("subject")

    email_block: dict = {
        "subject": subject,
        "recipients": recipients,
    }
    if cc:
        email_block["cc"] = cc
    if reply_to:
        email_block["reply_to"] = reply_to

    return email_block, []


# Group-level keys copied verbatim from a directory-mode delivery entry into
# the resolved effective group dict (today's schema shape — everything
# except `contact` / `extra_recipients` / `subject` / `email`, which are
# consumed by resolve_delivery_email above, and `owner`, which is metadata
# routed through the metadata_by_delivery_name side channel).
_PASSTHROUGH_GROUP_KEYS: tuple[str, ...] = (
    "schedule",
    "filters",
    "reports",
    "csv_severities",
    "modules",
    "module_options",
    "analyst_detail",
    "report_title",
    "privacy_label",
    "description",
)


def resolve_config(config_path: Path) -> tuple[list[dict], list[str], list[str], dict[str, dict]]:
    """
    Resolve directory-mode config (``contacts.yaml`` + ``deliveries.d/*.yaml``)
    into today's effective ``groups`` shape.

    Directory presence is the mode switch (D-01): if ``deliveries_dir =
    config_path.parent / "deliveries.d"`` is not a directory, this function
    returns ``([], [], [], {})`` immediately so the caller falls back to the
    legacy single-file path.

    Parameters
    ----------
    config_path : Path
        Path to the (possibly nonexistent) single-file ``delivery_config.yaml``.
        ``deliveries.d/`` and ``contacts.yaml`` are resolved relative to
        ``config_path.parent`` (honors the prod ``shared/`` symlink layout).

    Returns
    -------
    tuple[list[dict], list[str], list[str], dict[str, dict]]
        ``(groups, errors, warnings, metadata_by_delivery_name)``.
        ``groups`` is the list of schema-shaped effective group dicts (never
        carrying ``owner``/``contact`` keys — D-09, schema
        ``additionalProperties: false`` at the group level). ``errors``/
        ``warnings`` are human-readable strings for the caller to log.
        ``metadata_by_delivery_name`` maps each delivery name to
        ``{"owner": str | None, "contact": str | None}``.

        On any error (duplicate name, undefined contact ref, inline email
        in directory mode, missing contacts.yaml), ``groups`` is ``[]``.
    """
    config_dir = config_path.parent
    deliveries_dir = config_dir / "deliveries.d"

    if not deliveries_dir.is_dir():
        return [], [], [], {}

    errors: list[str] = []
    warnings: list[str] = []
    metadata_by_delivery_name: dict[str, dict] = {}

    contacts_path = config_dir / "contacts.yaml"
    if not contacts_path.exists():
        errors.append(
            f"directory mode: contacts.yaml missing next to deliveries.d/ (expected {contacts_path})"
        )
        return [], errors, warnings, {}

    try:
        with open(contacts_path, encoding="utf-8") as fh:
            contacts_doc = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        errors.append(f"contacts.yaml parse error: {exc}")
        return [], errors, warnings, {}

    if not isinstance(contacts_doc, dict):
        errors.append("contacts.yaml: root must be a mapping")
        return [], errors, warnings, {}

    contacts_by_name, defaults = resolve_contacts(contacts_doc)

    groups: list[dict] = []
    seen_names: dict[str, str] = {}  # delivery name -> source file (for the collision message)

    for team_file in sorted(deliveries_dir.glob("*.yaml")):
        try:
            with open(team_file, encoding="utf-8") as fh:
                team_doc = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            errors.append(f"{team_file.name}: parse error: {exc}")
            continue

        if not isinstance(team_doc, dict):
            errors.append(f"{team_file.name}: root must be a mapping")
            continue

        owner = team_doc.get("owner")

        # Canonical `deliveries:` key; deprecated `groups:` alias accepted
        # with a warning (CONF-03/D-10).
        deliveries = team_doc.get("deliveries")
        if deliveries is None and "groups" in team_doc:
            deliveries = team_doc.get("groups")
            warnings.append(
                f"{team_file.name}: uses deprecated 'groups:' key — rename to 'deliveries:'"
            )

        if not isinstance(deliveries, list):
            errors.append(f"{team_file.name}: 'deliveries' key must be a list")
            continue

        for delivery in deliveries:
            if not isinstance(delivery, dict):
                errors.append(f"{team_file.name}: delivery entries must be mappings")
                continue

            name = delivery.get("name")

            # D-03: inline email.recipients is rejected in directory mode —
            # all "who" must flow through contact:.
            inline_email = delivery.get("email")
            if isinstance(inline_email, dict) and inline_email.get("recipients"):
                errors.append(
                    f"{team_file.name}: delivery '{name}' uses inline email.recipients — "
                    "directory mode requires a contact: ref (inline email is rejected)"
                )
                continue

            if name in seen_names:
                errors.append(
                    f"duplicate delivery name: {name} (in {team_file.name}, "
                    f"already defined in {seen_names[name]})"
                )
                continue
            seen_names[name] = team_file.name

            email_block, email_errors = resolve_delivery_email(delivery, contacts_by_name, defaults)
            if email_errors:
                errors.extend(f"{team_file.name}: delivery '{name}': {e}" for e in email_errors)
                continue

            group: dict = {"name": name}
            for key in _PASSTHROUGH_GROUP_KEYS:
                if key in delivery:
                    group[key] = delivery[key]
            group["email"] = email_block

            groups.append(group)
            metadata_by_delivery_name[name] = {
                "owner": owner,
                "contact": delivery.get("contact"),
            }

    if errors:
        return [], errors, warnings, metadata_by_delivery_name

    return groups, errors, warnings, metadata_by_delivery_name
