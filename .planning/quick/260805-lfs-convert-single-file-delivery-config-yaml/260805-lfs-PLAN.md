---
id: 260805-lfs
title: Convert single-file delivery_config.yaml to directory-mode config
date: 2026-08-05
mode: quick
status: planned
---

# Quick Task 260805-lfs — Single-file → directory-mode delivery config

## Context

The operator's live `delivery_config.yaml` holds 23 delivery groups in the legacy
single-file shape. Phase 20 shipped the v1.6 directory-mode config language
(`contacts.yaml` + `deliveries.d/*.yaml`, resolved by
`delivery/config_loader.py::resolve_config`), and **directory mode is already
active on this host** — `resolve_config` switches on the mere presence of
`deliveries.d/` (`config_loader.py:210`), so the single file is currently being
ignored in its entirety.

Convert the 23 groups to the new language so the operator's real schedule loads
again.

> **PII constraint (CLAUDE.md Hard Rule 2).** The source config carries real
> corporate mailboxes. `contacts.yaml` and `deliveries.d/` are gitignored
> (`.gitignore:14-19`) so the output never enters version control. No address,
> recipient name, or internal mailbox appears in this plan, the summary, the
> commit message, or any other `.planning/` artifact. Counts and abstract
> labels only.

## Decisions

**D-1 — No `defaults.analyst_mailbox`; explicit per-contact `cc`/`reply_to`.**
The shared analyst mailbox is a standing Cc with *no opt-out* (`config_loader.py:128-132`,
D-02) and is also the fallback `reply_to`. 14 of the 23 groups already Cc that
mailbox, so the knob is tempting — but the other 9 do not, and 5 of those send
*to* it directly. `email_sender.py:353` builds the envelope as
`all_to = valid_recipients + valid_cc` with **no dedupe**, so a self-Cc emits a
duplicate RCPT TO. This is a format migration, not a delivery-behavior change,
so every contact carries explicit `cc`/`reply_to` and resolved To/Cc/Reply-To
match the legacy file byte-for-byte. The knob remains available later.

**D-2 — Shard by owning team.** Matches the existing starter layout
(`exec.yaml`, `remediation.yaml`, `tag_profile.yaml`). 11 team files.

**D-3 — Contacts deduped by exact (recipients, cc, reply_to) triple.** Groups
with an identical audience share one contact block; near-identical audiences
stay separate. 15 contact blocks for 23 deliveries.

**D-4 — Retire the three starter example files.** `exec.yaml`,
`remediation.yaml`, and `tag_profile.yaml` ship `example.invalid` addresses on
*weekly* schedules. Directory mode merges every `deliveries.d/*.yaml`, so left
in place they would resolve into the effective config and the scheduler would
attempt real sends against reserved-domain addresses. Move them to
`deliveries.d/examples/` — `resolve_config` globs non-recursively
(`config_loader.py:240`), so a subdirectory is excluded while the reference
shapes are preserved on disk. `board_test.yaml` is a current on_demand test and
stays active, so its contact block is carried into the new `contacts.yaml`.

## Tasks

### Task 1 — Write `contacts.yaml`
- **files:** `contacts.yaml` (gitignored)
- **action:** 15 contact blocks, each with explicit `recipients`, `cc` (where the
  legacy group had one), and `reply_to`. Carry the existing `board_test` contact
  forward. No `defaults:` block (D-1). Preserve address capitalization exactly as
  written in the source — two mailboxes differ only by case across groups.
- **verify:** every `contact:` ref in `deliveries.d/*.yaml` resolves
- **done:** file parses; no undefined-ref errors from `--dry-run`

### Task 2 — Write 11 `deliveries.d/<team>.yaml` files
- **files:** `deliveries.d/{ciso,network_defense,atm,network_engineering,uc_engineering,workstation,enterprise_virtualization,server,citrix_vdi,board,adhoc}.yaml`
- **action:** one `deliveries:` entry per legacy group (23 total), `owner:` at
  file top, `subject:` at delivery top level, all of
  `schedule`/`filters`/`reports`/`description`/`report_title`/`analyst_detail`
  copied verbatim (`_PASSTHROUGH_GROUP_KEYS`, `config_loader.py:162`). No inline
  `email:` blocks — rejected in directory mode (D-03, `config_loader.py:276`).
- **verify:** 23 delivery names, all unique
- **done:** `--dry-run` lists 23 groups

### Task 3 — Retire starter examples
- **files:** `deliveries.d/examples/` (moved, gitignored)
- **action:** `git mv`-free plain move of the three `example.invalid` starter files
- **done:** effective config contains no `example.invalid` recipient

### Task 4 — Verify
- **action:** `python run_all.py --dry-run` (no API call, no credentials —
  permitted by `.claude/hooks/block_tenable_fetch.py`)
- **verify:** exit 0; source echoed as directory mode; 23 groups; zero errors
- **done:** clean dry-run

## must_haves

**truths**
- Resolved To/Cc/Reply-To for all 23 deliveries are identical to the legacy
  single-file config — the migration changes format, not recipients
- No real address appears in any committed artifact
- No repo source file is modified

**artifacts**
- `contacts.yaml` — 15 contact blocks
- `deliveries.d/*.yaml` — 11 team files, 23 deliveries
- `deliveries.d/examples/` — 3 retired starters

**key_links**
- `delivery/config_loader.py:176` — `resolve_config`
- `delivery/config_loader.py:162` — `_PASSTHROUGH_GROUP_KEYS`
- `delivery/email_sender.py:353` — `all_to = recipients + cc`, no dedupe
- `delivery_config.schema.yaml:29-35` — group required keys
