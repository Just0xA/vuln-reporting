### Phase 8: Warm Cache
**Goal**: Operators can decouple Tenable fetch latency from report-run wall time by running a pre-fetch job on a cron schedule
**Depends on**: Nothing (independent of release infrastructure; can run against existing live install)
**Requirements**: CACHE-01, CACHE-02, CACHE-03, CACHE-04, CACHE-05, LOG-01, LOG-03
**Success Criteria** (what must be TRUE):
  1. Operator runs `python -m scripts.warm_cache` and finds `data/cache/<YYYY-MM-DD>/*.parquet` files in the same shape `run_all.py` consumes, with no new Python dependencies required
  2. Operator passes `--dry-run` and sees what would be written without any files being created; passes `--verbose` and sees fetch progress; passes `--prune-stale` and prior-day cache folders are removed; passes `--date YYYY-MM-DD` and the target date folder is written
  3. A concurrent daemon + cron invocation cannot observe a partial parquet file (writes go to a temp file and are promoted via `os.replace`)
  4. `logs/warm_cache.log` is written from the first run and rotates automatically; exit code is 0 on success and non-zero on auth or API failure
  5. Every invocation produces at minimum a "started" line (with full argv) and a "completed" line (success or failure) in `logs/warm_cache.log`; usage errors log the real failure reason before exiting non-zero
**Plans**: 2 plans
Plans:
- [x] 08-01-PLAN.md — Atomic parquet-write helper in data/fetchers.py (CACHE-04)
- [x] 08-02-PLAN.md — scripts/warm_cache.py with rotating log, dry-run/verbose/prune-stale/date flags (CACHE-01, CACHE-02, CACHE-03, CACHE-05, LOG-01, LOG-03)