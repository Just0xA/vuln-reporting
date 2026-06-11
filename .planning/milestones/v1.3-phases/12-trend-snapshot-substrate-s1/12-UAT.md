---
status: complete
phase: 12-trend-snapshot-substrate-s1
source: [12-01-SUMMARY.md, 12-02-SUMMARY.md, 12-03-SUMMARY.md]
started: 2026-06-10T11:57:00Z
updated: 2026-06-10T12:12:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Open-Count Predicate Tests
expected: `python -m pytest tests/unit/test_open_count.py -q` → 10 passed, 0 failed. Proves open_findings_at() correctly includes OPEN/REOPENED and excludes FIXED, reopened-gap, and born-after-date findings.
result: pass
note: 13 passed (10 original + 3 code-review-fix edge-case tests for WR-01). xdist -q suppresses the summary line; -p no:xdist confirmed "13 passed in 0.04s".

### 2. Trend Snapshot Engine Tests
expected: `python -m pytest tests/content/test_trend_store.py -q` → 9 passed, 0 failed. Proves atomic write, same-month idempotent overwrite, new-month append, cold-start read (missing file → insufficient_data), no-PII in snapshot, and management_summary file left untouched.
result: pass

### 3. Snapshot Capture Dry-Run
expected: `python -m scripts.capture_trend_snapshot --dry-run` (module form, from repo root — matches DEPLOYMENT.md cron convention; the bare `python scripts/...py` form intentionally requires project root on sys.path, same as warm_cache.py) → exits 0, logs a "DRY RUN: would capture snapshot month=YYYY-MM cache=..." line, and writes NO file into data/trend/. No Tenable fetch occurs.
result: pass
note: First attempt with bare `python scripts/capture_trend_snapshot.py` raised ModuleNotFoundError(config) — this is the documented project convention (DEPLOYMENT.md:409 "cd into project root required"), identical to warm_cache.py, NOT a Phase 12 defect. Corrected to `python -m scripts.capture_trend_snapshot --dry-run`: logged Started / DRY RUN month=2026-06 / Completed status=dry-run, exit 0, no file written.

### 4. Input Validation (bad --month)
expected: `python -m scripts.capture_trend_snapshot --month not-a-month` → exits 2 with a clear "--month must be YYYY-MM" error message (logged, not a stack trace).
result: pass

### 5. Full Regression Suite
expected: `python -m pytest -q` → all tests pass (137+ passed, 0 failed). Confirms Phase 12 additions broke nothing else in the suite.
result: pass
note: 140 passed, 14 warnings in 6.02s (-p no:xdist -o "addopts="). xdist -q suppresses the summary line — re-run without xdist to confirm count.

### 6. Live Snapshot Capture (needs Tenable creds)
expected: `python -m scripts.capture_trend_snapshot` (no flags) → fetches open+reopened findings, writes data/trend/trend_severity_all_assets.json with severity counts + generated_at. Re-running for the same month keeps exactly 1 entry for that month (idempotent overwrite). Skip/mark blocked if no live Tenable access.
result: pass

## Summary

total: 6
passed: 6
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none yet]
