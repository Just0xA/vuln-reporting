### Phase 10: Install / Update / Rollback Infrastructure
**Goal**: A non-author operator can install, upgrade, and roll back the suite on a single Linux server using only `scripts/update_from_github.sh` — release tarball download is validated against its SHA256 sidecar, swaps are atomic, every upgrade leaves a one-liner rollback path, and a failed restart auto-reverts
**Depends on**: Phase 7 (`/opt/vuln-reporting/current` + `/opt/vuln-reporting/shared/` symlink layout in `deploy/vuln-reports.service`), Phase 9 (release tarball + `.sha256` sidecar on GitHub Releases)
**Requirements**: UPDATE-01, UPDATE-02, UPDATE-03, UPDATE-04, UPDATE-05, UPDATE-06, UPDATE-07, UPDATE-08, UPDATE-09, UPDATE-10, UPDATE-11, UPDATE-12, UPDATE-13, UPDATE-14, LOG-02
**Success Criteria** (what must be TRUE):
  1. Operator runs `scripts/update_from_github.sh --check` and sees current-vs-latest version comparison with distinct exit codes (0 up-to-date, 1 update-available, ≥2 error); operator runs `--list` and sees installed releases with the active one marked. Both honor `GITHUB_TOKEN` env var when set to lift the GitHub API rate limit from 60/hr to 5000/hr.
  2. Operator runs `--version vX.Y.Z`: script downloads the slim tarball + `.sha256`, validates the checksum (refuses to proceed on mismatch), extracts to `releases/vX.Y.Z/`, creates a per-release `.venv` and runs `pip install -r requirements.txt`, symlinks shared paths (`.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/`, `data/trend/`) from `/opt/vuln-reporting/shared/` into the release dir, runs `python run_all.py --dry-run` for smoke validation, captures the previous `current` target as a `.last` breadcrumb, atomically swaps via `ln -sfn`, restarts `vuln-reports.service`, and after a 10-second settle confirms `systemctl is-active` returns `active` — auto-rolling-back if not. The operator sees a printed rollback one-liner on success.
  3. Operator runs `--rollback`: script reads `releases/.last`, atomically re-points `current` to that previous release directory, and restarts the unit. The `.last` breadcrumb is captured BEFORE every forward swap and rewritten AFTER it succeeds (never both updated in a single mutation that could be interrupted).
  4. Script uses `set -euo pipefail` + `trap`-on-exit cleanup so a failed download, checksum mismatch, dry-run failure, or partial extraction never leaves a half-built release directory. Script refuses to operate if `current` is missing or does not point inside `releases/` (refuse-if-unknown-layout safety on hand-built installs).
  5. `--force` re-extracts over an existing release dir; `--skip-restart` skips the systemd restart with a warning logged. Every invocation logs a "started" line with full argv and a "completed" line (success or failure) to `logs/update.log`; usage errors log the real failure reason before exiting non-zero.
  6. GitHub Releases API URL is sourced from `GITHUB_RELEASE_REPO` in `.env` (e.g., `GITHUB_RELEASE_REPO=owner/repo`) — operators forking into their own org point the updater at their fork without code changes.
**Plans**: 3 plans
Plans:
- [x] 10-01-PLAN.md — Skeleton + safety guards + `--check` / `--list` discovery (UPDATE-09, UPDATE-10, UPDATE-04, UPDATE-01, UPDATE-12, LOG-02) — also adds `GITHUB_RELEASE_REPO` to `.env.example`
- [x] 10-02-PLAN.md — `--version vX.Y.Z` install flow: download + SHA256 verify + extract + per-release venv + shared-path symlinks + dry-run + atomic swap + breadcrumb (UPDATE-02, UPDATE-06, UPDATE-07, UPDATE-13, UPDATE-14)
- [ ] 10-03-PLAN.md — `--rollback`, `--force`, `--skip-restart`, post-swap health check with auto-rollback, rollback one-liner print on success (UPDATE-03, UPDATE-05, UPDATE-08, UPDATE-11)

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
- [x] 09-01-PLAN.md — Core release workflow `.github/workflows/release.yml` (checkout, build slim tarball, SHA256 sidecar, publish release, prerelease detection) (CI-01, CI-02, CI-03, CI-04, CI-05, CI-07)
- [x] 09-02-PLAN.md — Tarball-content assertion step: forbidden-path + credential-scan gate (CI-06)

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