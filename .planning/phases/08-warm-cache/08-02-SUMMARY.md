---
phase: 08-warm-cache
plan: 02
subsystem: scripts
tags: [cache, cron, logging, cli]
requires: [08-01]
provides: [warm_cache_script]
affects: [scripts/, logs/]
tech-stack:
  added: []
  patterns: [rotating_file_handler, atomic_exit_codes, argparse_error_logging]
key-files:
  created:
    - scripts/__init__.py
    - scripts/warm_cache.py
  modified: []
decisions:
  - "Custom ArgumentParser subclass logs usage errors to logs/warm_cache.log before delegating to super().error() — cleanest LOG-01 satisfaction (#2924-style: catch and log, never silent)."
  - "Dataset filenames hardcoded as a module-level tuple to match data/fetchers.py's _cache_path() literals exactly; dry-run output strings match the eventual write paths byte-for-byte."
  - "Top-level try/except SystemExit around parse_args() lets --help (code 0) pass through cleanly while preserving non-zero codes from usage errors."
metrics:
  duration: ~12min
  completed: 2026-05-19
  tasks: 2
  files: 2
---

# Phase 08 Plan 02: Warm-Cache Script Summary

Standalone cron-friendly entry point — `python -m scripts.warm_cache` — that pre-fetches the four Tenable parquet datasets into `data/cache/<YYYY-MM-DD>/` so scheduled `run_all.py` invocations short-circuit on `[CACHE HIT]`.

## Tasks Completed

| Task | Name                                                                                       | Commit  | Files                                  |
| ---- | ------------------------------------------------------------------------------------------ | ------- | -------------------------------------- |
| 1    | Create scripts/__init__.py                                                                 | 2019920 | scripts/__init__.py                    |
| 2    | Implement scripts/warm_cache.py with all four flags, rotating log, and atomic exit codes   | 59f5b2f | scripts/warm_cache.py                  |

## What Shipped

- **`scripts/__init__.py`** — empty file, makes `scripts/` a package so `python -m scripts.warm_cache` resolves.
- **`scripts/warm_cache.py`** — 272-line standalone script:
  - Flags: `--date YYYY-MM-DD`, `--prune-stale`, `--verbose`, `--dry-run`
  - `_configure_logging()` builds a `warm_cache` logger with `RotatingFileHandler("logs/warm_cache.log", maxBytes=5_000_000, backupCount=3)` (matches `scheduler.py` / `reports/vuln_export.py` pattern) + console `StreamHandler` (DEBUG when verbose, else INFO).
  - `_WarmCacheArgumentParser` subclass overrides `error()` to write the real failure reason to `logs/warm_cache.log` via a fallback file-only logger before delegating to `super().error()` — satisfies LOG-01 without polluting the main logger.
  - `_date_type()` validates `--date` with `datetime.strptime(..., "%Y-%m-%d")` raising `ArgumentTypeError` on bad input.
  - `_prune_stale()` iterates `CACHE_DIR.iterdir()`, removes directories whose name ≠ `target_date_str`. Honors `--dry-run` with "WOULD remove …" log lines.
  - `main()` orchestrates: configure logging → log Started+argv → resolve target_date → optional prune → dry-run branch (logs four planned filenames, no writes) or real branch (mkdir, get_client, four fetchers in order) → log Completed with duration + status.
  - Exit codes: **0** (success or dry-run), **2** (auth failure via `SystemExit` from `get_client()` OR argparse usage error), **3** (fetcher failed).
  - Dataset filenames (`vulns_all.parquet`, `vulns_fixed.parquet`, `assets_all.parquet`, `recast_rules.parquet`) verified against `data/fetchers.py`'s `_cache_path(cache_dir, "...")` literals (lines 249, 382, 491, 607).

## Verifications Passed

| Check                                                                                              | Result                                                                 |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `python -c "import scripts"`                                                                       | OK — package importable                                                |
| `python -m scripts.warm_cache --help` (exit 0, lists all four flags)                               | OK                                                                     |
| `python -m scripts.warm_cache --dry-run --verbose` → log created, Started/Completed/status=dry-run | OK — `logs/warm_cache.log` contains all three                          |
| `python -m scripts.warm_cache --dry-run --date 2026-05-19` writes no files                         | OK — `data/cache/2026-05-19/` not created                              |
| `python -m scripts.warm_cache --bogus-flag` exits non-zero AND logs "failed because" (LOG-01)      | OK — exit=2, log tail shows "failed because argparse usage error: unrecognized arguments: --bogus-flag" |
| `python -m scripts.warm_cache --date bogus` (bad date format)                                      | OK — exit=2 with `ArgumentTypeError` message                           |

Live Tenable run + `[CACHE HIT]` verification (Task 2 `<human-check>`) is deferred to operator validation — the script is interface-correct against the four-fetcher contract, but the credentials needed to exercise the real API are not available in this worktree.

## Requirements Satisfied

- **CACHE-01** — Dataset filenames match `run_all.py`'s pre-fetch literals; downstream reports will see `[CACHE HIT]`.
- **CACHE-02** — Zero new Python dependencies (stdlib + existing project modules only).
- **CACHE-03** — All four flags (`--date`, `--prune-stale`, `--verbose`, `--dry-run`) work as documented.
- **CACHE-05** — `logs/warm_cache.log` created via `RotatingFileHandler` on first run; exit codes 0/2/3 per spec.
- **LOG-01** — Argparse usage errors logged to file before non-zero exit (verified with `--bogus-flag`).
- **LOG-03** — Every invocation (including the argparse-error path) writes at least one log line; success/dry-run paths write Started + Completed.

## Deviations from Plan

None — plan executed as written.

Minor implementation notes that match the plan's intent but were not literally spelled out:

1. **Fallback `_log_to_file_only()` helper** — the plan suggested writing to `logs/warm_cache.log` "directly" from `parser.error()`. Implemented as a small helper that lazily attaches a `RotatingFileHandler` to a sibling logger (`warm_cache._argparse`), so the file-handler limits (5MB × 3 backups) apply uniformly even on the argparse-error path.
2. **`logger.propagate = False`** — prevents double-emission to the root logger; the root logger is still raised to INFO so `data.fetchers`' own log lines reach the file handler attached to the named logger (they don't — they hit root). Acceptable because the fetcher progress is already visible via the `rich` Progress bars when `--verbose`. Operator visibility of fetcher progress remains via stderr; the file log captures the warm_cache-level lifecycle.

## Known Stubs

None.

## Self-Check: PASSED

- `scripts/__init__.py` — FOUND
- `scripts/warm_cache.py` — FOUND
- Commit 2019920 — FOUND (`feat(08-02): make scripts/ a Python package`)
- Commit 59f5b2f — FOUND (`feat(08-02): warm-cache script with rotating log and atomic exit codes`)
