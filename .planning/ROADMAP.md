### Phase 9: CI/Release Automation
**Goal**: Pushing a `v*` tag publishes a slim, validated release tarball + SHA256 checksum to GitHub Releases automatically, with prerelease tags marked and forbidden paths blocked at build time
**Depends on**: Phase 7 (Foundations — `.gitattributes` defines the slim-tarball boundary that this workflow packages)
**Requirements**: CI-01, CI-02, CI-03, CI-04, CI-05, CI-06, CI-07
**Success Criteria** (what must be TRUE):
  1. Maintainer pushes a `vX.Y.Z` tag and `.github/workflows/release.yml` runs end-to-end: builds `vuln-reporting-vX.Y.Z-slim.tar.gz`, computes a `.sha256` sidecar, uploads both as assets, and creates a published GitHub Release named for the tag
  2. Maintainer can re-run the workflow against an existing tag via the GitHub UI (`workflow_dispatch` with a version input)
  3. Tags suffixed `-rc`, `-beta`, or `-alpha` produce releases marked `prerelease: true`; bare semver tags produce stable releases
  4. A tarball-content assertion step inspects the built archive and fails the build if `.planning/`, `.env`, `data/trend/`, `.git`, or non-placeholder credentials appear in the contents
  5. Workflow declares `permissions: contents: write` explicitly (no reliance on default repo settings); action versions are pinned to verified majors current as of 2026-05-19 (`actions/checkout@v6`, `softprops/action-gh-release@v3`)
**Plans**: 2 plans
Plans:
- [ ] 09-01-PLAN.md — Core release workflow `.github/workflows/release.yml` (checkout, build slim tarball, SHA256 sidecar, publish release, prerelease detection) (CI-01, CI-02, CI-03, CI-04, CI-05, CI-07)
- [ ] 09-02-PLAN.md — Tarball-content assertion step: forbidden-path + credential-scan gate (CI-06)

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