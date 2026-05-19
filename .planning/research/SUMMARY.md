# Project Research Summary

**Project:** Vulnerability Management Reporting Suite — v1.2 Server Update and Install
**Domain:** Deployment infrastructure for a single-server Python systemd daemon
**Researched:** 2026-05-19
**Confidence:** HIGH

## Executive Summary

v1.2 adds no new application logic — every deliverable is infrastructure. The goal is a clean, operator-reproducible deployment path: slim release tarballs produced by a GitHub Actions workflow, a shell update script that downloads, validates, extracts, and atomically swaps releases, and documentation that lets a non-author operator deploy, upgrade, and roll back without touching the author. The core pattern is industry-standard (Capistrano/Mina-style symlink layout: `current → releases/vX.Y.Z`, with `shared/` carrying config and runtime-generated state across upgrades), applied to a Python + systemd daemon on a single Linux host.

The recommended build order is strictly sequential for the first three phases and then opens up. `.gitattributes` must land before any tag is pushed — a wrong tarball is immutable on GitHub. The release workflow depends on `.gitattributes` being correct. The update script depends on a real release tarball existing. Only `scripts/warm_cache.py` is independent of this chain and can be developed and tested against the existing live install in parallel with Phase 1 or Phase 3. Documentation is the final gate — written last so it describes final, not provisional, behavior.

The dominant risk category for this milestone is silent failure at the seams: partial tarball extraction leaving broken release directories, non-atomic symlink swaps creating a window where `scheduler.py` starts with no working directory, rollback breadcrumbs written before the swap they record, and `Restart=on-failure` masking a bad deploy by repeatedly restarting against broken code. All five critical pitfalls are implementation requirements in the update script, not nice-to-haves. The secondary risk is credential and sensitive data leakage into the public release tarball via `.env.example` or accidentally-staged `data/trend/` snapshots — the D-04-08 pre-release checklist must be enforced at every tag push.

---

## Key Findings

### Recommended Stack

v1.2 adds no Python dependencies. `scripts/warm_cache.py` reuses `tenable_client.get_client()`, `data.fetchers.fetch_all_vulnerabilities()`, `data.fetchers.fetch_all_assets()`, `rich`, and `python-dotenv` — all already in `requirements.txt`. The release workflow uses two GitHub Actions (`actions/checkout@v4`, `softprops/action-gh-release@v2`) and `git archive` for tarball construction. The update script uses only POSIX shell utilities (`curl`, `tar`, `ln`, `mv`, `systemctl`) plus Python's stdlib `json` module for GitHub API parsing — `jq` must not be required.

**Core technologies:**
- `actions/checkout@v4`: repo checkout in release workflow — current stable major (v3 deprecated; verify at commit time with `gh release list -R actions/checkout`)
- `softprops/action-gh-release@v2`: single-step release creation + tarball asset upload — preferred over archived `actions/create-release`; verify at commit time
- `git archive` + `.gitattributes export-ignore`: slim tarball construction — idiomatic; no separate exclude-list maintenance
- `python3 -c` (stdlib json): GitHub API parsing in `--check` mode — avoids `jq` dependency on minimal RHEL/Debian servers
- `ln -sfn` (atomic symlink swap): POSIX `rename(2)` syscall is atomic on Linux filesystems

**Version verification required before committing `release.yml`:**
```bash
gh release list -R actions/checkout --limit 5
gh release list -R softprops/action-gh-release --limit 5
```

See `.planning/research/STACK.md` for full version-pinning rationale and operator verification checklist.

---

### Expected Features

**Must have (table stakes):**
- `.gitattributes export-ignore` for dev paths — gate for release workflow; must land first
- `update_from_github.sh --version vX.Y.Z` — the core deploy action
- Atomic `current` symlink swap — `ln -sfn` only; `rm` + `ln` is forbidden
- `--rollback` mode — reads `.last` breadcrumb; breadcrumb written after swap, not before
- `--check` mode — exits 0/1/2 for up-to-date/update-available/error
- `--list` mode — shows installed releases with active marker
- Pre-swap `--dry-run` validation (`python run_all.py --dry-run`) — abort swap on failure
- `shared/` symlink wiring (`.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/`, `data/trend/`)
- systemd service restart after swap — default on; `--skip-restart` must warn
- `scripts/warm_cache.py` standalone entry point
- Cron-friendly exit codes on `warm_cache.py` — exit 0/non-zero; `RotatingFileHandler` from day one
- GitHub Actions `release.yml` on `v*` push + `workflow_dispatch`
- SHA256 checksum asset alongside tarball
- `DEPLOYMENT.md` — tarball-only install path; operator-focused
- RUNBOOK additions — "Operational cron schedule" + "Updating from GitHub"
- Root `README.md` — currently absent

**Should have (differentiators):**
- Print rollback one-liner on every successful upgrade
- `--force` flag on `--version` to re-extract over existing release dir
- Tarball SHA256 validation in update script
- Prerelease detection from tag suffix (`-rc1`, `-beta`)
- `deploy/crontab.example`
- `workflow_dispatch` input for manual release trigger
- `systemd ReadWritePaths` update for `current` symlink layout (required for SELinux correctness)

**Defer to post-v1.2:**
- `warm_cache.py --date` and `--prune-stale` flags
- Auto-generated release notes
- README badges
- Multi-host / fleet deployment
- PyPI packaging, Docker/container packaging

See `.planning/research/FEATURES.md` for full feature dependency graph (~2–3 days table stakes; ~4–6 days with differentiators).

---

### Architecture Approach

The symlink layout is transparent to all existing Python code. `config.CACHE_DIR` and `config.LOG_DIR` resolve correctly through symlinks — no changes to `config.py`, `run_all.py`, `scheduler.py`, or any report script are required. The seam for `warm_cache.py` is `data/fetchers.py` directly; no helper extraction from `run_all.py` needed.

**Major components:**

1. **`.gitattributes`** — defines tarball content; per-file exclusion for dev-only scripts; do NOT blanket-exclude `scripts/`
2. **`deploy/vuln-reports.service` (modified)** — `WorkingDirectory=/opt/vuln-reporting/current`, `EnvironmentFile=/opt/vuln-reporting/shared/.env`, `ExecStart=/opt/vuln-reporting/current/.venv/bin/python scheduler.py --mode daemon`, `ReadWritePaths` pointing at `shared/` subtrees
3. **`scripts/warm_cache.py`** — imports `fetch_all_vulnerabilities` + `fetch_all_assets` directly from `data.fetchers`; uses `config.CACHE_DIR` (local time, not UTC); atomic parquet write via `os.replace`; `RotatingFileHandler` on `logs/warm_cache.log`
4. **`.github/workflows/release.yml`** — `permissions: contents: write`; `git archive` tarball named `vuln-reporting-vX.Y.Z-slim.tar.gz`; SHA256 as second asset; tarball content assertion step before upload
5. **`scripts/update_from_github.sh`** — POSIX shell; `set -euo pipefail`; extract to `.tmp` dir with `trap` cleanup; `ln -sfn` atomic swap; `.last` breadcrumb written after swap; pre-swap `--dry-run`; post-swap `systemctl is-active` check with 10-second settle; optional `GITHUB_TOKEN` for API auth
6. **Documentation** — written last against final behavior

**Paths that do NOT change:** `run_all.py`, `data/fetchers.py`, `config.py`, `scheduler.py`, all report scripts.

See `.planning/research/ARCHITECTURE.md` for complete new/modified file list and post-v1.2 operational sequence diagram.

---

### Critical Pitfalls

1. **Non-atomic symlink swap (CRITICAL-03)** — `rm` + `ln` leaves a broken-symlink window. Use only `ln -sfn TARGET LINK`; comment in script forbids `rm` form.
2. **`Restart=on-failure` masks a bad deploy (CRITICAL-04)** — systemd repeatedly restarts against broken code. Prevention: pre-swap `--dry-run` (abort swap on failure) + post-swap `systemctl is-active` with 10-second settle; auto-rollback if not active.
3. **`.env.example` with non-placeholder values in tarball (CRITICAL-01)** — `.env` is gitignored and safe; `.env.example` IS tracked. A developer who filled in real values exposes credentials on the GitHub Release page permanently. Prevention: D-04-08 pre-release checklist + CI `grep` check in `release.yml`.
4. **`data/trend/` sneaks into tarball via accidental staging (CRITICAL-02)** — gitignored paths bypass `export-ignore` if accidentally staged. Prevention: belt-and-suspenders `export-ignore` lines for `data/trend/`, `output/`, `logs/`, `data/cache/` + tarball content assertion in `release.yml`.
5. **Rollback breadcrumb written before swap completes (CRITICAL-05)** — `.last` must be written after `ln -sfn` succeeds. Read `PREV=$(readlink current)` before the swap; write it after.
6. **`scripts/` blanket exclusion removes runtime tools (MOD-05)** — per-file exclusion for `setup_github_labels.py`, `smoke_board_summary_cutover.py`, `smoke_email_phase2.py` only.
7. **`contents: write` permission missing from `release.yml` (MOD-09)** — GitHub's default `GITHUB_TOKEN` is read-only since 2023; explicit `permissions: contents: write` is required.

See `.planning/research/PITFALLS.md` for all pitfalls with detection methods and the phase-specific warnings table.

---

## Implications for Roadmap

### Phase 1: Foundations — `.gitattributes` + Service Unit

**Rationale:** Everything downstream depends on the tarball being correct. A tag pushed without correct `export-ignore` rules bakes the wrong file list into an immutable release artifact. The service unit must also be updated before the first real deployment using the symlink layout — it ships in the tarball and must be correct from release one.

**Delivers:** Correct slim tarball definition; updated systemd unit targeting `current/` paths; resolution of the `scripts/` per-file exclusion question.

**Open decision to resolve:** `RUNBOOK.MD` export-ignore vs. `Documentation=` directive — research recommendation is to remove the `Documentation=` line.

**Avoids:** CRITICAL-02, MOD-03, MOD-05.

---

### Phase 2: `scripts/warm_cache.py`

**Rationale:** Independent of the release/symlink infrastructure — can be built and tested against the existing live install right now. Highest-value deliverable for reducing report latency.

**Delivers:** `scripts/warm_cache.py` with `--prune-stale`, `--date`, `--verbose`, `--dry-run` flags; `scripts/__init__.py`; `logs/warm_cache.log` with rotation.

**Avoids:** MOD-01 (schedule away from midnight), MOD-02 (atomic write via `os.replace`).

---

### Phase 3: Release Workflow

**Rationale:** Depends on Phase 1. Once a test tag is pushed, a real release tarball exists on GitHub — which Phase 4 requires to test the update script end-to-end.

**Delivers:** `.github/workflows/release.yml`; `vuln-reporting-vX.Y.Z-slim.tar.gz`; SHA256 `.sha256` second asset; tarball content assertion step; prerelease detection.

**Avoids:** MOD-09 (`permissions: contents: write`), MOD-04, MINOR-02 (`-slim` suffix), CRITICAL-01 (`.env.example` grep check).

**Open decision before tagging:** Confirm GitHub org/repo path for the Releases API URL used by Phase 4.

---

### Phase 4: `update_from_github.sh` + Symlink Layout

**Rationale:** Requires a real release tarball from Phase 3. Most complex phase — all five critical pitfalls live here.

**Delivers:** `scripts/update_from_github.sh` with `--check`, `--version`, `--rollback`, `--list`, `--force`, `--skip-restart`; `deploy/crontab.example`; on-disk layout instantiated.

**Avoids:** CRITICAL-03, CRITICAL-04, CRITICAL-05, MOD-08 (`set -euo pipefail` + trap), MOD-06.

**Open decision:** `.venv` per-release vs. shared. Recommendation: per-release.

---

### Phase 5: Documentation

**Rationale:** Written last so it describes final, not provisional, behavior.

**Delivers:** `README.md`; `DEPLOYMENT.md`; RUNBOOK additions ("Operational cron schedule" + "Updating from GitHub").

**Avoids:** MINOR-01 (tarball-only install), MINOR-03 (rollback one-liner placement), MINOR-05 (schema migration step), MOD-07 (`shared/` content contract).

---

### Phase Ordering Rationale

- `.gitattributes` before any tag is a hard prerequisite enforced by `git archive` immutability.
- `warm_cache.py` can run in parallel; no external dependency.
- Release workflow before update script — script's download path requires a real tarball.
- Documentation last — describes final behavior.

### Research Flags

No phases need a full research-phase invocation. Phase 4 warrants a pre-implementation PITFALLS.md review checklist (CRITICAL-03, 04, 05, MOD-08) before writing the shell script.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Action version pins drawn from Aug 2025 training data cutoff; verify with `gh release list` before committing `release.yml`. |
| Features | HIGH | Every table-stakes feature explicitly captured by the operator in prior todo exploration. |
| Architecture | HIGH | Integration analysis grounded in actual code line numbers; `ln -sfn` atomicity and systemd behavior are documented facts. |
| Pitfalls | HIGH | All critical pitfalls grounded in project files and git history. |

**Overall confidence:** HIGH

### Open Decisions (must be resolved during phasing)

1. `scripts/` per-file exclusion list — which smoke test files to exclude individually (Phase 1)
2. `Documentation=` line in service unit — remove vs. update path (Phase 1)
3. GitHub org/repo slug for Releases API URL (Phase 3 gate before Phase 4)
4. `.venv` per-release vs. shared (Phase 4 design decision)

---

## Sources

**Primary (HIGH):** `deploy/vuln-reports.service`, both pending todos, `.planning/PROJECT.md`, `data/fetchers.py:175-200`, `run_all.py:658-671`, POSIX `rename(2)`, systemd documentation, git `export-ignore` documentation.

**Secondary (MEDIUM):** `actions/checkout@v4` and `softprops/action-gh-release@v2` current majors; GitHub default `GITHUB_TOKEN` permissions; auto-tarball naming pattern; unauthenticated API rate limit.

**Tertiary (LOW):** Complexity estimates (S/M/L) — inferred, not measured.

---
*Research completed: 2026-05-19*
*Ready for roadmap: yes*
