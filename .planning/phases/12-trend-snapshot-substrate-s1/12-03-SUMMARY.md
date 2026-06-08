---
phase: 12-trend-snapshot-substrate-s1
plan: "03"
subsystem: scripts
tags: [trend, snapshot, cron, entry-point, warm_cache-mirror, TREND-07]
dependency_graph:
  requires: [data/trend_store.py (Plan 02), data/fetchers.py (existing), tenable_client.py (existing)]
  provides: [scripts/capture_trend_snapshot.py]
  affects: [data/trend/ (accrues trend_severity_all_assets.json monthly)]
tech_stack:
  added: []
  patterns: [warm_cache-mirror, argparse-LOG-01-logging, rotating-file-handler, cron-exit-codes]
key_files:
  created:
    - scripts/capture_trend_snapshot.py
  modified: []
decisions:
  - "D-08: entry point does the fetching (fetch_all_vulnerabilities + fetch_all_assets), then hands in-memory df + assets_df to capture_snapshot — no fetching inside trend_store"
  - "D-09: standalone cron entry point mirroring warm_cache.py exactly — same logging skeleton, argparse subclass, exit codes; captures all_assets severity dimension; capture_snapshot called with (dimension, tag_filter) params so Phase 13 per-owner snapshots need no changes here"
  - "Pitfall-6 compliance: month_str and snapshot_date both derived from server LOCAL time (datetime.now().strftime / datetime.strptime), matching CLAUDE.md timezone policy for month keys"
metrics:
  duration: "~20 minutes"
  completed: "2026-06-08"
  tasks_completed: 1
  tasks_total: 1
  files_created: 1
  files_modified: 0
---

# Phase 12 Plan 03: Capture Trend Snapshot Entry Point Summary

**One-liner:** Cron/Task-Scheduler entry point mirroring warm_cache.py — fetches open+reopened findings + assets into date-named cache, calls capture_snapshot for the all_assets severity dimension, logs to RotatingFileHandler, returns exit codes 0/2/3.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Build scripts/capture_trend_snapshot.py mirroring warm_cache.py | e69f4b5 | scripts/capture_trend_snapshot.py |

## What Was Built

### `scripts/capture_trend_snapshot.py`

Cron/Task-Scheduler-friendly entry point that closes TREND-07. Mirrors `scripts/warm_cache.py` verbatim for all shared infrastructure:

**Logging skeleton:** `_configure_logging(verbose)` builds a `RotatingFileHandler` (5 MB, 3 backups) to `logs/capture_trend_snapshot.log` at INFO; console handler at DEBUG when `--verbose`. `_log_to_file_only` handles the LOG-01 argparse-error path before the main logger exists.

**Argparse subclass (`_SnapshotArgumentParser`):** `error()` override logs to file before calling `super().error()` — usage errors always land in the log even when stderr is redirected.

**Validators:** `_date_type` (YYYY-MM-DD, from warm_cache) + `_month_type` (YYYY-MM, new) — both raise `argparse.ArgumentTypeError` on invalid input, producing exit 2.

**Flags:** `--month YYYY-MM` (snapshot target, server local, defaults to current month), `--date YYYY-MM-DD` (cache folder, server local, defaults to today), `--verbose`, `--dry-run`.

**`main()` scaffold:**
1. Parse args; translate argparse `SystemExit` to exit code (default 2).
2. `_configure_logging`; `_log_started`.
3. Derive `target_date_str` (local) and `month_str` (local) — Pitfall 6 compliance.
4. `--dry-run`: log DRY RUN line + `_log_completed("dry-run")`, return 0 with no fetch and no write.
5. `cache_dir.mkdir(parents=True, exist_ok=True)`.
6. `get_client()` in try/except → exit 2 on auth failure.
7. `fetch_all_vulnerabilities(tio, cache_dir)` + `fetch_all_assets(tio, cache_dir)` in try/except → exit 3 on fetch failure. Does NOT call `fetch_fixed_vulnerabilities` — open-count predicate operates only on the open+reopened export.
8. Build `snapshot_date`: `datetime.strptime(month_str + "-01", "%Y-%m-%d")` when `--month` given, else `datetime.now()` — ensures `capture_snapshot`'s `date.strftime("%Y-%m")` yields the correct local month key.
9. `capture_snapshot(df, assets_df, snapshot_date, "severity", "all_assets")` in try/except → exit 3 on failure; log "Snapshot written: {path}" on success.
10. `_log_completed("success")`; return 0.

**`if __name__ == "__main__": sys.exit(main())`** — required by CLAUDE.md.

**Parameterisation:** `capture_snapshot` called with explicit `dimension` and `tag_filter` args (not hardcoded string splices) so Phase 13 per-owner snapshots can drive this entry point or create a sibling without modifying this file.

## Deviations from Plan

None — plan executed exactly as written.

## Verification Results

```
$ PYTHONPATH=/d/Projects/vuln-reporting python scripts/capture_trend_snapshot.py --dry-run
2026-06-08 17:01:43,800 [INFO] Started at 2026-06-08T21:01:43.800916+00:00 UTC; argv=[...]
2026-06-08 17:01:43,801 [INFO] DRY RUN: would capture snapshot month=2026-06 cache=...\data\cache\2026-06-08
2026-06-08 17:01:43,801 [INFO] Completed at 2026-06-08T21:01:43.801185+00:00 UTC; duration=0.00s; status=dry-run
exit=0

$ PYTHONPATH=/d/Projects/vuln-reporting python scripts/capture_trend_snapshot.py --month not-a-month
error: argument --month: --month must be YYYY-MM, got 'not-a-month': ...
exit=2

$ PYTHONPATH=/d/Projects/vuln-reporting python -m pytest
137 passed, 224 warnings in 6.50s
```

Log file written: `logs/capture_trend_snapshot.log` shows DRY RUN entry + argparse error entry; no snapshot file written to `data/trend/`.

## Known Stubs

None — this plan delivers a pure infrastructure entry point with no UI rendering.

## Threat Flags

None — all STRIDE threats addressed:
- T-12-07 (input validation): `_month_type`/`_date_type` reject malformed values (exit 2)
- T-12-08 (information disclosure): log lines record argv, month, cache path, status only — no row-level finding fields
- T-12-09 (DoS/cron crash): auth failure → exit 2; fetch failure → exit 3; no uncaught exception stack traces

## Self-Check: PASSED

- [x] `scripts/capture_trend_snapshot.py` exists (257 lines, >120 required)
- [x] Contains `from data.trend_store import capture_snapshot`
- [x] Contains `fetch_all_vulnerabilities` and `fetch_all_assets`
- [x] Does NOT contain `fetch_fixed_vulnerabilities`
- [x] Contains `--month`, `--date`, `--dry-run`, `--verbose` flags
- [x] Contains `RotatingFileHandler` to `logs/capture_trend_snapshot.log`
- [x] month key derived from server-local `datetime.now().strftime("%Y-%m")`
- [x] Ends with `if __name__ == "__main__": sys.exit(main())`
- [x] `--dry-run` exits 0, writes DRY RUN log line, performs no fetch or file write
- [x] `--month not-a-month` exits 2 via `_month_type` argparse validation
- [x] Commit e69f4b5 exists
- [x] Full pytest suite: 137 passed, 0 failures
