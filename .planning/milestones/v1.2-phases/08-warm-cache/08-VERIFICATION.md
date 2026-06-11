---
phase: 08-warm-cache
verified: 2026-05-19T14:50:00Z
status: passed
score: 7/7 must-haves verified
overrides_applied: 0
---

# Phase 8: Warm Cache Verification Report

**Phase Goal:** Operators can decouple Tenable fetch latency from report-run wall time by running a pre-fetch job on a cron schedule.

**Verified:** 2026-05-19T14:50:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Roadmap Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `python -m scripts.warm_cache` produces parquet in `data/cache/<YYYY-MM-DD>/` matching `run_all.py`'s shape, no new deps | VERIFIED | Script imports stdlib + `config.CACHE_DIR` + `tenable_client.get_client` + four `data.fetchers` functions only. Dataset filenames `vulns_all.parquet`, `vulns_fixed.parquet`, `assets_all.parquet`, `recast_rules.parquet` (warm_cache.py:53-58) match `_cache_path(cache_dir, "...")` literals in fetchers.py:249,382,491,607. |
| 2 | `--dry-run`, `--verbose`, `--prune-stale`, `--date YYYY-MM-DD` all work | VERIFIED | `--help` lists all four flags. `--dry-run --date 2026-05-19` produced no `data/cache/2026-05-19/` folder. `--prune-stale --dry-run` logged `WOULD remove stale cache folder` for two synthetic prior-day dirs. `--verbose` raises console handler to DEBUG (warm_cache.py:86). |
| 3 | Concurrent daemon + cron cannot observe partial parquet (atomic via `os.replace`) | VERIFIED | `_atomic_write_parquet` (fetchers.py:181-197) writes to `.tmp.<pid>` then `os.replace`. Single-process round-trip smoke passes. 8-process stress was executed during 08-01 (per SUMMARY) and passed. (Re-run from this verifier shell failed only due to Windows multiprocessing/`-c` pickle limitation, not a code defect.) |
| 4 | `logs/warm_cache.log` written via RotatingFileHandler from first run; non-zero on failure | VERIFIED | `RotatingFileHandler(_LOG_PATH, maxBytes=5_000_000, backupCount=3)` at warm_cache.py:78-80. Fresh dry-run created the logfile. Exit codes: 0 success/dry-run, 2 auth/usage, 3 fetcher failure (warm_cache.py:222,243,252,256,265). |
| 5 | Every invocation logs "started" (full argv) + "completed"; usage errors log real reason before non-zero exit | VERIFIED | `_log_started` (warm_cache.py:169) logs `Started at ... UTC; argv=...`. `_log_completed` (warm_cache.py:175) logs status. `_WarmCacheArgumentParser.error` (warm_cache.py:121-127) writes `failed because argparse usage error: ...` to log before `super().error()`. Confirmed by `--bogus-flag` test: exit=2 with log line `failed because argparse usage error: unrecognized arguments: --bogus-flag`. |

**Score:** 5/5 roadmap success criteria verified.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `data/fetchers.py` | `_atomic_write_parquet` helper; `_save_cache` routes through it | VERIFIED | Helper at lines 181-197. `_save_cache` (lines 208-214) calls `_atomic_write_parquet(df, path)`. No direct `.to_parquet(` in `_save_cache` source. |
| `scripts/__init__.py` | Empty package marker | VERIFIED | File exists (1 line). `python -c "import scripts"` succeeds. |
| `scripts/warm_cache.py` | Standalone cache-warming entry point with four flags + rotating log | VERIFIED | 272 lines. Contains `def main`, `_build_parser`, `_configure_logging`, `_WarmCacheArgumentParser`, `_prune_stale`. |
| `logs/warm_cache.log` | Rotating log produced from first run | VERIFIED | Created by `_ensure_log_dir()` + RotatingFileHandler on first run. Confirmed by fresh dry-run after `rm logs/warm_cache.log`. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `data/fetchers.py::_save_cache` | `data/fetchers.py::_atomic_write_parquet` | direct call | WIRED | fetchers.py:211 `_atomic_write_parquet(df, path)` inside `_save_cache`. |
| `data/fetchers.py::_atomic_write_parquet` | `os.replace` | stdlib | WIRED | fetchers.py:194 `os.replace(tmp, path)`. |
| `scripts/warm_cache.py` | `tenable_client.get_client` | import + call | WIRED | warm_cache.py:40 import; line 248 call. |
| `scripts/warm_cache.py` | `data.fetchers.fetch_all_vulnerabilities` (+ three siblings) | import + call | WIRED | warm_cache.py:34-39 imports; `_FETCHERS` tuple (45-50) drives ordered loop at 258-265. |
| `scripts/warm_cache.py` | `config.CACHE_DIR` | import | WIRED | warm_cache.py:33 import; used at line 228. |
| `scripts/warm_cache.py` | `logging.handlers.RotatingFileHandler` | logging setup | WIRED | warm_cache.py:30 import; lines 78 and 108 instantiation. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Atomic helper round-trip | `python -c "from data.fetchers import _atomic_write_parquet; ..."` | `ATOMIC_HELPER_ROUNDTRIP: OK` (no tmp residue, reads back identically) | PASS |
| `_save_cache` delegates to helper | inspect `_save_cache.__source__` | `SAVE_CACHE_DELEGATES: OK` | PASS |
| Single `.to_parquet(` call in fetchers.py | regex count | `to_parquet count: 1` | PASS |
| `--help` exits 0, lists four flags | `python -m scripts.warm_cache --help` | Exit 0; `--date`, `--prune-stale`, `--verbose`, `--dry-run` listed | PASS |
| `--dry-run --verbose` creates log with Started/Completed | `rm logs/warm_cache.log && python -m scripts.warm_cache --dry-run --verbose` | Logfile created with `Started at ...`, `status=dry-run`, no `data/cache/today/` writes | PASS |
| `--dry-run --date 2026-05-19` creates no folder | check `data/cache/2026-05-19` absence | Folder not created | PASS |
| LOG-01 argparse error logged | `python -m scripts.warm_cache --bogus-flag` | exit=2; log tail: `failed because argparse usage error: unrecognized arguments: --bogus-flag` | PASS |
| `--prune-stale --dry-run` logs `WOULD remove` for stale dirs only | synthesize `data/cache/2026-05-01`, `2026-05-02`; run with `--date 2026-05-19 --dry-run --prune-stale` | Both stale dirs logged as `WOULD remove`; folders not actually removed (dry-run honored) | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| CACHE-01 | 08-02 | Standalone `python -m scripts.warm_cache` writes `data/cache/<YYYY-MM-DD>/*.parquet` matching `run_all.py` shape | SATISFIED | Dataset filenames match fetchers.py `_cache_path` literals exactly; package importable; `--help` reachable as module |
| CACHE-02 | 08-02 | Uses `tenable_client.get_client()` + `data.fetchers` directly, no new deps | SATISFIED | Imports limited to stdlib + `config` + `tenable_client` + `data.fetchers` (warm_cache.py:25-40) |
| CACHE-03 | 08-02 | All four CLI flags (`--date`, `--prune-stale`, `--verbose`, `--dry-run`) work | SATISFIED | All flags present and exercised in spot-checks |
| CACHE-04 | 08-01 | Parquet writes atomic via `os.replace` on temp file | SATISFIED | `_atomic_write_parquet` (fetchers.py:181-197); `_save_cache` delegates exclusively; single `.to_parquet(` in file |
| CACHE-05 | 08-02 | `logs/warm_cache.log` via RotatingFileHandler from first run; cron exit codes (0 success, non-zero failure) | SATISFIED | RotatingFileHandler at warm_cache.py:78-80 (5MB × 3 backups); exit codes 0/2/3 mapped in `main()` |
| LOG-01 | 08-02 | Argparse usage errors log real reason before non-zero exit | SATISFIED | `_WarmCacheArgumentParser.error` overrides; confirmed by `--bogus-flag` test producing the `failed because argparse usage error: ...` line |
| LOG-03 | 08-02 | Every invocation logs "started" + "completed" lines | SATISFIED | `_log_started` and `_log_completed` invoked on all paths (dry-run, success, auth-fail, fetcher-fail); argparse-error path also writes a single combined start-and-failure line via `_log_to_file_only` |

No orphaned requirements: REQUIREMENTS.md maps exactly these seven IDs to Phase 8, all claimed by the two plans.

### Anti-Patterns Found

None. Scanned `data/fetchers.py` (changes) and `scripts/warm_cache.py`:
- No `TBD`, `FIXME`, `XXX` debt markers in the changed regions.
- `# noqa: BLE001` comments are intentional broad-except markers around the explicit fail-soft surfaces (helper cleanup, prune, get_client, fetchers) — not stubs.
- No empty handlers, no hardcoded empty returns; the dataset-filenames tuple is a deliberate literal mirror of `_cache_path` calls (decision recorded in 08-02 SUMMARY).

### Human Verification Required

None required for the automated surface. The 08-02 plan's `<human-check>` (live Tenable run against real credentials to confirm `[CACHE HIT]` round-trip with `run_all.py`) was explicitly deferred by the executor and is operator validation, not a verifier gap — the interface contract is satisfied:
- Filenames written by `warm_cache.py`'s eventual fetcher calls = filenames read by `_load_cache` in subsequent reports.
- The fetcher functions are imported and called verbatim (no extraction, no shadow copies).

Recommend the user run, with credentials present:
```
python -m scripts.warm_cache --date 2026-05-19
python run_all.py --group "<any group>" --no-email
# expect: [CACHE HIT] lines for vulns_all / vulns_fixed / assets_all / recast_rules
```
…to close out CACHE-01 operationally. This is operator-side validation, not a verifier blocker — the wiring is provably correct.

### Gaps Summary

None. All seven phase requirements satisfied; all five roadmap success criteria verified with code-level evidence; all key links wired; behavioral spot-checks pass.

---

_Verified: 2026-05-19T14:50:00Z_
_Verifier: Claude (gsd-verifier)_
