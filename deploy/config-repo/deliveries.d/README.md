# deliveries.d/ — private config repo layout reference

This directory documents the one-file-per-team convention the PRIVATE
config repo holds under `deliveries.d/`. It is a reference for the
private repo, not a live config directory — no real `deliveries.d/*.yaml`
config file is committed here (Hard Rule 2 / D-02); real team files live
only in the private repo.

## Layout

One file per team: `deliveries.d/<team>.yaml`. Each file carries:

- `owner:` — a team-slug string. Feeds the delivery matrix (owner column)
  and the 1:1 `CODEOWNERS` entry for this file (`../CODEOWNERS.example`).
- `deliveries:` — a list of delivery definitions for that team.

Every delivery in the list references a contact by name via `contact:
<key>` — **never** an inline `email:`/`recipients:` block. The referenced
key must exist in the sibling `contacts.yaml` (`../contacts.example.yaml`);
the loader rejects an undefined `contact:` ref.

Delivery `name:` must be **globally unique across all `deliveries.d/*.yaml`
files**, not just within one team's file — the loader rejects a duplicate
name anywhere in the merged set.

`reports:` (or `modules:` for a `composed_report` delivery) must reference
report slugs / module IDs already registered in the app (see the app
repo's `run_all.py` → `_VALID_REPORTS` and `reports/modules/`).

## Example team file

```yaml
# deliveries.d/exec.yaml
owner: exec-reporting-team

deliveries:
  - name: "Executive Team"
    subject: "Weekly Vuln Management Summary — Production"
    contact: exec_team              # references contacts.yaml by name
    schedule:
      frequency: weekly
      day_of_week: monday
      time: "07:00"
    filters:
      tag_category: "Environment"
      tag_value: "Production"
    reports:
      - executive_kpi
      - trend_analysis
```

## Resolver contract

The config loader (`resolve_config`) errors on:

- a missing `contacts.yaml` sibling next to `deliveries.d/`
- a duplicate delivery `name` across any two files in `deliveries.d/`
- an undefined `contact:` reference
- an inline `email:` block anywhere in directory mode

The private repo's CI gate runs schema validation + `run_all.py
--dry-run` against the merged effective config on every PR, so a tree
that violates any of the above fails the gate before merge.
