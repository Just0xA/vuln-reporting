---
phase: quick-260522-kyy
plan: 01
subsystem: deploy
tags: [deployment, systemd, docs]
requires: []
provides:
  - "delivery_config.example.yaml (tracked, shippable, placeholder-only template)"
  - "deploy/vuln-reports.service with StartLimit keys in [Unit] (rate limit enforced)"
affects:
  - DEPLOYMENT.md
tech-stack:
  added: []
  patterns: [systemd-unit, release-tarball-export-boundary]
key-files:
  created:
    - delivery_config.example.yaml
  modified:
    - deploy/vuln-reports.service
    - DEPLOYMENT.md
decisions:
  - "Replaced the multi-line cd+command Verify blocks with paste-safe && one-liners rather than keeping both, to remove the paste-collapse footgun outright."
metrics:
  duration: ~10m
  completed: 2026-05-22
---

# Quick Task 260522-kyy: Apply 5 v1.2.0 Deployment Fixes Summary

Five clean-machine deployment fixes from the v1.2.0 Rocky 9 walkthrough: a misplaced
systemd StartLimit rate limit, a missing tracked example config, and four DEPLOYMENT.md
gaps (missing sudo prefixes, paste-collapse footguns, a dangling config symlink with no
seeding step, and stale Tenable verify expected-output). No release tagged.

## What Was Done

### Task 1 — systemd unit fix (#5) + tracked example config (#3a) — commit `ccee1c5`
- Moved `StartLimitIntervalSec=300` / `StartLimitBurst=5` out of `[Service]` (where
  systemd silently ignores them) into `[Unit]`, with a comment noting they bound the
  `Restart=on-failure` policy. `Restart`/`RestartSec` left untouched in `[Service]`.
- Created `delivery_config.example.yaml` at repo root: two example groups (a weekly
  tag-filtered executive group and a weekly all-assets remediation group), all using
  `example.invalid` recipients. Validates against `delivery_config.schema.yaml`.
- Confirmed not gitignored (only `delivery_config.yaml` is ignored), not export-ignored,
  and ships in `git archive HEAD` (tarball check returned 1).

### Task 2 — DEPLOYMENT.md doc fixes (#1, #2, #3b, #4) — commit `8a1555a`
- **#1:** Prefixed all six Step 6 symlink commands plus the Step 7 `current` symlink with
  `sudo -u vuln-reports` (7 total), matching Steps 4-5.
- **#2:** Replaced both Verify multi-line `cd`+command blocks with paste-safe `&&`
  one-liners, each annotated as paste-safe.
- **#3b:** Added a "Seed the delivery config" subsection after the `.env` block, mirroring
  the `.env` copy/edit pattern (`cp` from `delivery_config.example.yaml` then `nano`).
- **#4:** Replaced the stale `[INFO] Tenable connection verified.` with the real
  `tenable_client.py` output (the auth log line + "Connection successful. Client is ready.").
- Schema Migration diff already referenced `delivery_config.example.yaml` exactly — left as-is.

## Deviations from Plan

None - plan executed exactly as written.

## Verification

All automated gates from both tasks passed:
- `delivery_config.example.yaml` validates against the schema (`SCHEMA OK`).
- File not gitignored; ships in `git archive HEAD`.
- `[Unit]` StartLimit count = 2; `[Service]` StartLimit count = 0; `Restart`/`RestartSec` intact.
- DEPLOYMENT.md: 7 `sudo -u vuln-reports ln -sfn`; 2 paste-safe one-liners; 1 seed `cp`;
  real expected-output present; stale "Tenable connection verified" count = 0.

## Self-Check: PASSED

- FOUND: delivery_config.example.yaml
- FOUND: commit ccee1c5
- FOUND: commit 8a1555a
