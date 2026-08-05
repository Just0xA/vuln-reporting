---
id: 260805-lfs
title: Convert single-file delivery_config.yaml to directory-mode config
date: 2026-08-05
status: complete
---

# Quick Task 260805-lfs — Summary

Converted the operator's 23-group single-file `delivery_config.yaml` into the
v1.6 directory-mode language (`contacts.yaml` + `deliveries.d/*.yaml`).

**No repo source file was modified.** Every artifact this task produced is
gitignored local operator config; the only committed files are this summary,
the plan, and the STATE.md row.

> PII: the source config carries real corporate mailboxes. Per CLAUDE.md Hard
> Rule 2 no address or recipient name appears here or in any other committed
> artifact — counts and abstract labels only.

## Why this was needed

`resolve_config` switches to directory mode on the mere *presence* of
`deliveries.d/` (`delivery/config_loader.py:210`). That directory already
existed on this host holding starter examples, so the operator's real
single-file config was being ignored in its entirety — none of the 23
deliveries were loading.

## What shipped

| Artifact | Contents |
|---|---|
| `contacts.yaml` | 18 contact blocks — 15 for the converted deliveries, 3 retained for the parked examples |
| `deliveries.d/*.yaml` | 11 team files, 23 deliveries, sharded by owning team |
| `deliveries.d/examples/` | 3 retired starter files + README |

23 deliveries collapse to 15 contacts because two audiences are reused: one
engineering team receives the same ops and management cut, and four deliveries
go to the operator's own mailbox.

## Decisions

**No `defaults.analyst_mailbox`; explicit per-contact `cc`/`reply_to`.**
The shared analyst mailbox is a standing Cc with no opt-out
(`config_loader.py:128-132`, D-02). 14 of 23 deliveries already Cc it, but 9 do
not — and 5 of those send *to* it. Since `email_sender.py:353` builds the
envelope as `all_to = valid_recipients + valid_cc` with **no dedupe**, the knob
would have produced a duplicate RCPT TO on those 5 and a brand-new Cc copy on 4
more. This was a format migration, so behavior was held fixed and the knob left
unused. It remains available if the self-Cc is later judged harmless; the
`contacts.yaml` header documents the exact edit.

**Starter examples retired to `deliveries.d/examples/`.** Three shipped
`example.invalid` addresses on *weekly* schedules. Directory mode merges every
`deliveries.d/*.yaml`, so in place they resolved as live deliveries the
scheduler would have tried to send. The glob is non-recursive
(`config_loader.py:240`), so a subdirectory parks them safely. Their contact
blocks stay in `contacts.yaml` so restoring one is a plain `mv`.

## Verification

- `python run_all.py --dry-run` → exit 0, `Active config source: directory-mode`,
  **24 groups validated** (23 converted + the pre-existing on-demand board test),
  zero errors, zero warnings.
- Field-by-field fidelity check (scratchpad script, not committed): parsed the
  legacy file, ran `resolve_config`, compared all 23 groups across
  `description`, `schedule`, `filters`, `reports`, `csv_severities`, `modules`,
  `module_options`, `analyst_detail`, `report_title`, and every email field —
  plus the reconstructed order-sensitive SMTP envelope. **Result: identical, 0
  differences.**
- `pytest tests/test_config_loader.py tests/test_effective_config_golden.py
  tests/test_dry_run_surfacing.py tests/test_config.py
  tests/test_stamp_config_provenance.py` → 26 passed.

## Pre-existing issues surfaced, not fixed

Carried over verbatim and flagged in file-level comments:

1. **One "Management" delivery runs the ops report.** A delivery whose name and
   subject both say "Management Summary" has `reports: [ops_remediation,
   vuln_export]`. Its recipient gets the operations worklist under a
   management-summary subject. Noted at the top of
   `deliveries.d/enterprise_virtualization.yaml` with the one-line correction.
2. **ATM scopes on two different tag categories.** The weekly ATM pair filters
   on `Application = ATM`; the monthly board cut filters on `Function = ATM`.
   Possibly different asset populations.
3. **Three deliveries share one monday 08:15 slot.** Harmless (±10-minute
   run-due window, fail-soft batches) but worth staggering.
4. **Two mailboxes appear in more than one capitalization** across groups.
   Preserved as-written so the migration changes nothing.

## Left for the operator

- `delivery_config.yaml` is now inert (directory mode wins) but still on disk —
  delete or rename once the new layout is trusted.
- Its local-only test group from quick-260805-ezo was **not** carried over; it
  was absent from the config supplied for conversion.
- Real config belongs in the private CODEOWNERS-reviewed config repo per CONF-04;
  `deploy/config-repo/` holds the reference shapes.
