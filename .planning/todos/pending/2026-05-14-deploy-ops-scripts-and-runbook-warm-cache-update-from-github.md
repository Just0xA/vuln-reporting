---
created: 2026-05-14T13:49:26.447Z
title: Deploy/ops scripts + RUNBOOK — warm cache, update from GitHub
area: tooling
files:
  - scripts/warm_cache.py
  - scripts/update_from_github.sh
  - RUNBOOK.MD
  - deploy/vuln-reports.service
related:
  - .planning/todos/pending/2026-05-14-shrink-server-footprint-exclude-dev-only-files.md
---

## Problem

Once the server runs a slim release tarball (see related footprint todo), two operational gaps remain:

1. **Cache warming.** `run_all.py` warms `data/cache/<YYYY-MM-DD>/` in-process at the start of every batch, which couples API fetch latency to report-run wall time. For a server with multiple recipient groups firing on different cron lines, the first group of the day pays the fetch cost while the later groups hit `[CACHE HIT]`. Decoupling the warm into its own scheduled job means every report run starts hot.

2. **Updating the install.** With versioned release tarballs in play, the operator needs a documented, deterministic way to roll forward (and back) without hand-extracting files or risking config loss.

Both deliverables need to live in `RUNBOOK.MD` so a non-author operator can follow them.

## Decisions captured (from /gsd-explore on 2026-05-14)

- Warm cache is a **separate scheduled job**, not just documentation of existing in-process behavior.
- Update mechanism is **versioned directories with symlink swap** (`/opt/vuln-reporting/releases/vX.Y.Z/` + `/opt/vuln-reporting/current` symlink). Rollback = one symlink flip.
- Updates are **operator-run on demand**, not auto-scheduled. A `--check` mode automates *discovery* of new releases; the *decision* to deploy stays human.
- **Single server** target. No multi-host orchestration needed.

## Solution — deliverables

### 1. `scripts/warm_cache.py`

- Standalone entry point: `python -m scripts.warm_cache` (or `scripts/warm_cache.py`).
- Reuses `tenable_client.get_client()` and the fetch functions in `data/fetchers.py`.
- Writes the same `data/cache/<YYYY-MM-DD>/*.parquet` shape that `run_all.py` expects, so the report batch finds `[CACHE HIT]` immediately.
- CLI flags: `--date YYYY-MM-DD` (default: today, server-local), `--prune-stale` (remove prior-day folders, matching current `run_all.py` behavior), `--verbose`.
- Exit code 0 on success, non-zero on Tenable auth or API failure (so cron can email on failure).
- Logs to `logs/warm_cache.log` via the existing rotating-handler pattern.
- Idempotent: re-running for the same date should re-fetch and overwrite cleanly.

### 2. `scripts/update_from_github.sh`

POSIX shell (server is Linux per `deploy/vuln-reports.service`). Layout assumed:

```
/opt/vuln-reporting/
├── current → releases/v1.2.0/        # symlink
├── releases/
│   ├── v1.1.0/
│   └── v1.2.0/
└── shared/                            # operator-managed, never overwritten
    ├── .env
    ├── delivery_config.yaml
    ├── logs/
    ├── output/
    └── data/cache/
```

Each release directory contains the extracted slim tarball; `shared/` is symlinked into the active release after extraction (so `.env`, configs, logs, output, and cache survive upgrades).

Modes:

- `update_from_github.sh --check` — hit GitHub Releases API, print latest vs currently-symlinked version, exit 0. No download, no changes.
- `update_from_github.sh --version vX.Y.Z` — download that release tarball, extract to `releases/vX.Y.Z/`, symlink `shared/` entries into it, validate (`python run_all.py --dry-run`), atomically swap the `current` symlink, restart the systemd unit. Refuses to overwrite an existing release dir without `--force`.
- `update_from_github.sh --rollback` — re-point `current` to the previous release dir (read from a `releases/.last` breadcrumb the script writes on each successful swap), restart the unit.
- `update_from_github.sh --list` — show installed releases and which is active.

Safety rails:
- Validates the tarball SHA against the release's published checksum if available.
- Requires `current` to exist and point inside `releases/` before any swap (refuses to operate on a hand-built install).
- Prints the rollback command on every successful upgrade so the operator sees it in their terminal scrollback.

### 3. `RUNBOOK.MD` additions

Add two new sections:

- **"Operational cron schedule"** — table of cron lines: warm cache (e.g. `15 6 * * *`), `scheduler.py --mode run-due` (every 5–10 min), log-rotation if not handled by systemd. Each line references the script and the log file to check on failure.
- **"Updating from GitHub"** — operator workflow: `--check` weekly (or when notified of a release), review release notes, `--version vX.Y.Z` to deploy, verify with a manual `run_all.py --dry-run` + a smoke `--group` run with `--no-email`, document the rollback one-liner. Include the on-disk layout diagram from §2 so operators understand what survives upgrades and what doesn't.

Cross-reference the footprint todo (`shrink-server-footprint-exclude-dev-only-files.md`) so a reader understands why the tarball is slim in the first place.

## Apply checklist (when ready to execute)

- [ ] Confirm `deploy/vuln-reports.service` reflects the `/opt/vuln-reporting/current` symlink path (or update it).
- [ ] Build `scripts/warm_cache.py`; verify a `run_all.py` batch immediately after shows `[CACHE HIT]` for every fetch.
- [ ] Build `scripts/update_from_github.sh`; dry-run against a throwaway `v0.0.1-rc1` release on a scratch directory before touching `/opt/`.
- [ ] Write RUNBOOK sections; have a non-author run the update flow end-to-end on a staging box to confirm the docs are sufficient.
- [ ] Add example crontab lines to `deploy/` (e.g. `deploy/crontab.example`).
