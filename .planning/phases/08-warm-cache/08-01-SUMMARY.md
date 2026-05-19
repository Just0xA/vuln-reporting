---
phase: 08-warm-cache
plan: 01
subsystem: data-fetchers
tags: [cache, atomic-write, concurrency, CACHE-04]
requires: []
provides:
  - "data/fetchers.py::_atomic_write_parquet"
  - "Atomic parquet writes for all _save_cache call sites"
affects:
  - "data/fetchers.py::_save_cache (rerouted through helper)"
tech-stack:
  added: []
  patterns:
    - "Atomic file replace via sibling .tmp.<pid> + os.replace"
key-files:
  created: []
  modified:
    - data/fetchers.py
decisions:
  - "Option A (helper inside data/fetchers.py) over Option B (atomic only in warm_cache.py) — daemon path needs atomicity too"
  - "Sibling .tmp.<pid> in same dir, not tempfile module — guarantees same-filesystem rename"
  - "Helper does not log; _save_cache owns the WARNING surface to keep public behavior identical"
metrics:
  duration: "~6 minutes"
  completed: 2026-05-19
---

# Phase 08 Plan 01: Atomic Parquet Writes Summary

One-liner: Introduces `_atomic_write_parquet` in `data/fetchers.py` and reroutes `_save_cache` through it so the eight existing cache-write call sites inherit torn-write protection for free, satisfying CACHE-04.

## What Changed

- Added `import os` to `data/fetchers.py`.
- Added `_atomic_write_parquet(df, path)` helper (sibling `.tmp.<pid>` → `os.replace`, with best-effort `unlink(missing_ok=True)` on failure before re-raise).
- `_save_cache` now delegates its parquet write to the helper; its outer `try/except` + `logger.warning` + `logger.debug` shape is preserved so caller-visible behavior is identical.
- Eight `_save_cache(df, cache)` call sites in fetcher bodies (lines 334, 446, 546, 686, 939, 1028, 1070, 1124) unchanged — they inherit atomicity by construction.

## Verification Results

| Check                                                                        | Result    |
| ---------------------------------------------------------------------------- | --------- |
| Helper round-trip (`_atomic_write_parquet` writes, no tmp residue, reads back) | PASS      |
| `_save_cache` delegates to helper, no direct `.to_parquet`                  | PASS      |
| Exactly one `.to_parquet(` call in `data/fetchers.py`                       | PASS (1)  |
| Eight `_save_cache` call sites preserved                                    | PASS (8)  |
| 8-process concurrent-write stress: no `.tmp.*` residue, parquet reads cleanly | PASS      |
| `python run_all.py --dry-run` regression check                              | PASS      |

## Deviations from Plan

None — plan executed exactly as written.

## TDD Gate Compliance

The project gitignores `tests/`, so test files are not committed. RED was demonstrated locally before implementation (`ImportError: cannot import name '_atomic_write_parquet'`) and the same tests pass GREEN after the implementation commit. Single feat commit per the plan's `success_criteria` (`feat(08-01): atomic parquet writes in data/fetchers.py for CACHE-04`).

## Commits

- `819080d` — feat(08-01): atomic parquet writes in data/fetchers.py for CACHE-04

## Self-Check: PASSED

- `data/fetchers.py` modified (committed in `819080d`).
- `_atomic_write_parquet` exists in module; `_save_cache` delegates to it.
- 8-process concurrent stress verified no torn writes, no tmp residue.
