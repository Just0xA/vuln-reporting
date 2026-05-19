# Milestone v1.2 Requirements — Server Update and Install

**Milestone goal:** Make the suite cleanly server-deployable — slim release tarballs, scripted install/update/rollback, an operator runbook, an auto-release workflow, and a user-friendly README — so a non-author operator can deploy + upgrade without hand-curating files.

**REQ-ID conventions:**
- `FOOT-NN` — Slim-release / footprint
- `CACHE-NN` — Warm-cache job (`scripts/warm_cache.py`)
- `CI-NN` — Release automation (`.github/workflows/release.yml`)
- `UPDATE-NN` — Install / update / rollback script + symlink layout
- `LOG-NN` — Cron-friendly logging guards (shared)
- `DOC-NN` — Documentation deliverables

---

## v1.2 Requirements

### Footprint / Release Artifacts

- [x] **FOOT-01**: Maintainer can produce a slim release tarball via `git archive` that excludes `.planning/`, `docs/`, `ref/`, `tests/`, `.github/`, `CLAUDE.md`, `RUNBOOK.md`, `CONTRIBUTING.md`.
- [x] **FOOT-02**: Dev-only scripts (`scripts/setup_github_labels.py`, `scripts/smoke_*` if applicable) are excluded individually; runtime scripts (`warm_cache.py`, `update_from_github.sh`) remain in the tarball.
- [x] **FOOT-03**: Belt-and-suspenders `export-ignore` lines for gitignored runtime paths (`data/trend/`, `data/cache/`, `output/`, `logs/`) prevent accidentally-staged files from leaking into a release tarball.
- [x] **FOOT-04**: Maintainer can preview tarball contents locally (`git archive --format=tar.gz HEAD | tar -tz`) before tagging a release.

### Warm-Cache Job

- [ ] **CACHE-01**: Operator can run `python -m scripts.warm_cache` (or `scripts/warm_cache.py`) as a standalone entry point that writes `data/cache/<YYYY-MM-DD>/*.parquet` in the same shape `run_all.py` consumes.
- [ ] **CACHE-02**: Warm-cache run uses `tenable_client.get_client()` + `data.fetchers` directly — no new Python dependencies, no extraction from `run_all.py`.
- [ ] **CACHE-03**: Operator can invoke `warm_cache.py` with `--date YYYY-MM-DD`, `--prune-stale`, `--verbose`, and `--dry-run` flags.
- [ ] **CACHE-04**: Parquet writes are atomic (via `os.replace` on a temp file) so concurrent daemon + cron runs cannot observe partial files.
- [ ] **CACHE-05**: All warm-cache output is captured to `logs/warm_cache.log` via `RotatingFileHandler` from the first run; cron-friendly exit codes (0 success, non-zero on auth/API failure).

### Release Automation

- [x] **CI-01**: Pushing a `v*` tag triggers `.github/workflows/release.yml`, which builds the slim tarball, uploads it as a release asset, and publishes the GitHub Release.
- [x] **CI-02**: Maintainer can manually trigger the release workflow via `workflow_dispatch` with a version input (for re-runs against an existing tag).
- [x] **CI-03**: Released tarball is named `vuln-reporting-vX.Y.Z-slim.tar.gz` (suffix avoids collision with GitHub's auto-generated source tarball).
- [x] **CI-04**: A SHA256 checksum file (`*.sha256`) is uploaded as a second asset on every release.
- [x] **CI-05**: Tags matching `-rc`, `-beta`, or `-alpha` suffixes are marked as prerelease on GitHub.
- [ ] **CI-06**: Release workflow runs a tarball-content assertion step that fails the build if forbidden paths (`.planning/`, `.env`, `data/trend/`, etc.) or non-placeholder credential values are present.
- [x] **CI-07**: Workflow declares `permissions: contents: write` explicitly (default `GITHUB_TOKEN` is read-only).

### Install / Update / Rollback

- [ ] **UPDATE-01**: Operator can run `scripts/update_from_github.sh --check` to compare the latest GitHub release against the currently-active version without downloading or changing anything (exit codes signal up-to-date vs update-available vs error).
- [ ] **UPDATE-02**: Operator can run `scripts/update_from_github.sh --version vX.Y.Z` to download, validate (SHA256), extract, validate via `python run_all.py --dry-run`, atomically swap the `current` symlink, and restart the systemd unit.
- [ ] **UPDATE-03**: Operator can run `scripts/update_from_github.sh --rollback` to re-point `current` to the previous release directory (read from `releases/.last` breadcrumb) and restart the unit.
- [ ] **UPDATE-04**: Operator can run `scripts/update_from_github.sh --list` to see installed releases and which is active.
- [ ] **UPDATE-05**: Operator can pass `--force` to re-extract over an existing release directory and `--skip-restart` to skip the systemd restart (with a warning in the log).
- [ ] **UPDATE-06**: Symlink swap is atomic (`ln -sfn` only; `rm` + `ln` is forbidden in the script).
- [ ] **UPDATE-07**: `.last` rollback breadcrumb is captured BEFORE the swap (`PREV=$(readlink current)`) and written AFTER the swap succeeds.
- [ ] **UPDATE-08**: Post-swap, the script runs `systemctl is-active vuln-reports` after a 10-second settle and auto-rolls-back if the unit is not active.
- [ ] **UPDATE-09**: Script uses `set -euo pipefail` and `trap`-on-exit cleanup so a failed download or partial extraction never leaves a half-built release directory.
- [ ] **UPDATE-10**: Script refuses to operate when `current` is missing or does not point inside `releases/` (refuse-if-unknown-layout safety on hand-built installs).
- [ ] **UPDATE-11**: On every successful upgrade, the script prints the exact rollback one-liner the operator can paste into their next prompt.
- [ ] **UPDATE-12**: Script supports an optional `GITHUB_TOKEN` env var for authenticated GitHub API calls (raises the rate limit from 60/hr to 5000/hr).
- [ ] **UPDATE-13**: Each release directory contains its own `.venv` (per-release dependency isolation); the script runs `pip install -r requirements.txt` after extraction.
- [ ] **UPDATE-14**: `/opt/vuln-reporting/shared/` paths (`.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/`, `data/trend/`) are symlinked into each release directory so configuration and runtime state survive upgrades.
- [x] **UPDATE-15**: `deploy/vuln-reports.service` is updated to reference `/opt/vuln-reporting/current/` and `/opt/vuln-reporting/shared/` paths; the obsolete `Documentation=` directive pointing to RUNBOOK.md is removed.

### Cron-Friendly Logging

- [ ] **LOG-01**: `scripts/warm_cache.py` catches argparse usage errors (unknown args, missing `--`) and logs `"Started at <T> with argv=<X>; failed because <Y>"` to `logs/warm_cache.log` before exiting non-zero — so the cron log records the real reason, not just `"type -h for help"`.
- [ ] **LOG-02**: `scripts/update_from_github.sh` writes the same shape of "started + failed-because" line to its log (e.g. `logs/update.log`) on usage errors, mid-run failures, and successful completions.
- [ ] **LOG-03**: Both scripts log a single "started" line at process start (with full argv) and a single "completed" line at process end (success or failure) — minimum two log lines per invocation.

### Documentation

- [ ] **DOC-01**: Repo has a new root `README.md` covering what the suite does, who it's for, a quickstart pointer, and a link to `DEPLOYMENT.md`.
- [ ] **DOC-02**: Repo has a new `DEPLOYMENT.md` covering: system requirements, install from release tarball, configure credentials, verify (`run_all.py --dry-run`), update procedure, rollback one-liner (prominently placed), troubleshooting, on-disk layout diagram, schema-migration note, and the D-04-08 sensitive-data pre-release checklist.
- [ ] **DOC-03**: `RUNBOOK.md` is rewritten from scratch and scoped narrowly to "how to run and use the tool" (day-to-day operations, scheduler management, log locations, troubleshooting common runtime errors). All install/deployment content moves out to `DEPLOYMENT.md`.
- [ ] **DOC-04**: `RUNBOOK.md` includes an "Operational cron schedule" section with `warm_cache.py` and `scheduler.py --mode run-due` cron lines and rotation guidance.
- [ ] **DOC-05**: `deploy/crontab.example` ships a working cron schedule the operator can drop in (warm-cache job placed ≥30 min before the earliest report group, never near midnight).

---

## Future Requirements (deferred)

Carried from prior milestones; not in scope for v1.2.

- **GEN-01/02** — Migrate `management_summary` / `ops_remediation` to the module render contract.
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04** — Per-batch `enrich_vulns_with_assets` cache, per-day cache midnight crossover, log rotation, tag-value typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **composed_report output filename disambiguation** — per-group basenames for groups using `reports: [composed_report]`.

---

## Out of Scope (explicit exclusions)

- **Multi-host / fleet deployment** — single-server target; no orchestration layer.
- **Auto-applied updates** — security tool; the *decision* to deploy stays a human action. Only discovery (`--check`) automates.
- **PyPI / Docker / container packaging** — release tarball is the only supported distribution channel for v1.2.
- **Self-hosted runner / SHA-pinning policy** — GitHub-hosted runners + major-tag action pins are acceptable for v1.2.
- **Markdown linting / docs CI** — no enforcement point exists; defer to a future dev-tooling milestone.
- **Threat-intel tag migration** — seed `threat-intel-tag-migration.md` trigger condition (Vuln Team's Teams/Tenable-tag rollout) is not met. Seed remains untouched in `.planning/seeds/`.
- **`composed_report` output filename disambiguation** — unrelated to deploy; stays on backlog.
- **`git clone` as a server-supported install path** — DEPLOYMENT.md will document that production installs MUST use a release tarball.
- **Auto venv recreation when `requirements.txt` is unchanged** — per-release `.venv` always runs `pip install` for simplicity and rollback isolation; optimizing for unchanged-deps is a future polish.

---

## Traceability

| REQ-ID | Phase | Plan | Status |
|--------|-------|------|--------|
| FOOT-01 | Phase 7 | — | Open |
| FOOT-02 | Phase 7 | — | Open |
| FOOT-03 | Phase 7 | — | Open |
| FOOT-04 | Phase 7 | — | Open |
| UPDATE-15 | Phase 7 | — | Open |
| CACHE-01 | Phase 8 | — | Open |
| CACHE-02 | Phase 8 | — | Open |
| CACHE-03 | Phase 8 | — | Open |
| CACHE-04 | Phase 8 | — | Open |
| CACHE-05 | Phase 8 | — | Open |
| LOG-01 | Phase 8 | — | Open |
| LOG-03 | Phase 8 | — | Open |
| CI-01 | Phase 9 | — | Open |
| CI-02 | Phase 9 | — | Open |
| CI-03 | Phase 9 | — | Open |
| CI-04 | Phase 9 | — | Open |
| CI-05 | Phase 9 | — | Open |
| CI-06 | Phase 9 | — | Open |
| CI-07 | Phase 9 | — | Open |
| UPDATE-01 | Phase 10 | — | Open |
| UPDATE-02 | Phase 10 | — | Open |
| UPDATE-03 | Phase 10 | — | Open |
| UPDATE-04 | Phase 10 | — | Open |
| UPDATE-05 | Phase 10 | — | Open |
| UPDATE-06 | Phase 10 | — | Open |
| UPDATE-07 | Phase 10 | — | Open |
| UPDATE-08 | Phase 10 | — | Open |
| UPDATE-09 | Phase 10 | — | Open |
| UPDATE-10 | Phase 10 | — | Open |
| UPDATE-11 | Phase 10 | — | Open |
| UPDATE-12 | Phase 10 | — | Open |
| UPDATE-13 | Phase 10 | — | Open |
| UPDATE-14 | Phase 10 | — | Open |
| LOG-02 | Phase 10 | — | Open |
| DOC-01 | Phase 11 | — | Open |
| DOC-02 | Phase 11 | — | Open |
| DOC-03 | Phase 11 | — | Open |
| DOC-04 | Phase 11 | — | Open |
| DOC-05 | Phase 11 | — | Open |
