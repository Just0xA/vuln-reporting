# Feature Landscape — v1.2 Server Update and Install

**Domain:** Deployment/install infrastructure for a single-server Python daemon
**Researched:** 2026-05-19
**Milestone scope:** NEW features only — report generation pipeline, module framework, YAML delivery, scheduler, delivery log already ship

---

## Table Stakes

Features operators expect. Missing = the install story breaks or the operator cannot safely update.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| `.gitattributes export-ignore` for dev paths | GitHub source tarballs are the deploy artifact; without this, operators get `.planning/`, `docs/`, `tests/` in production | S | Already drafted in todo; gate for release workflow — must land first |
| `update_from_github.sh --version vX.Y.Z` | The core deploy action: download a specific release, extract, wire shared/, swap symlink | M | Depends on versioned release layout existing |
| Atomic `current` symlink swap | Industry-standard rollout pattern (Capistrano, Fabric, Ansible all use it); rollback without extraction | S | `ln -sfn` is atomic on Linux; write `releases/.last` breadcrumb before swap |
| `--rollback` mode | Operators need a one-liner to undo a bad deploy; anything harder and they'll hand-edit | S | Reads `.last` breadcrumb, re-points symlink, restarts unit |
| `--check` mode | Operators need to know if an update exists without committing to it; cron-friendly discovery | S | Hits GitHub Releases API (`/repos/:owner/:repo/releases/latest`), prints version comparison, exits 0 |
| `--list` mode | Operators need to see what's installed and which is active | S | Reads `releases/` directories, marks active with `*` |
| Refuse if unknown layout | Script must refuse if `current` symlink doesn't exist or points outside `releases/`; prevents nuking hand-built installs | S | Guard at top of script, clear error message |
| Refuse if `shared/` missing | `shared/.env`, `shared/delivery_config.yaml` must pre-exist before any swap; operator must have run initial setup | S | Explicit pre-flight check with actionable error |
| `--dry-run` post-install validation | `python run_all.py --dry-run` after extraction, before symlink swap; if it fails, abort and do not touch `current` | S | Depends on venv existing in the new release dir |
| `shared/` symlink wiring | After extraction, link `.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/` into the new release dir | S | These survive upgrades; hardcoded list in script |
| systemd restart after swap | Service must reload from new code; `systemctl restart vuln-reports` after successful symlink swap | S | Operator needs to be told what unit name to expect |
| `warm_cache.py` standalone entry point | Decouples Tenable fetch from report wall time; first group of the day should not pay the fetch penalty | M | Reuses `tenable_client.get_client()` and `data/fetchers.py`; writes same parquet shape `run_all.py` expects |
| `warm_cache.py` cron-friendly exit codes | Exit 0 on success, non-zero on Tenable auth/API failure; cron's `MAILTO` then sends failure alerts | S | `sys.exit(1)` on any unrecoverable error |
| `warm_cache.py` rotating log | `logs/warm_cache.log`; same rotating-handler pattern as rest of suite | S | Already established pattern |
| GitHub Actions release workflow on `v*` tag | Automates tarball build and release creation; removes manual "build + upload" step from release process | M | Trigger: `push` with `tags: ['v*']` + `workflow_dispatch` |
| Slim tarball as release asset | Server pulls a clean runtime-only bundle; not manually curated per release | S | Depends on `.gitattributes` export-ignore being correct |
| SHA256 checksum published alongside tarball | `update_from_github.sh` validates download integrity before extraction; standard ops hygiene | S | `sha256sum` in workflow, upload `.sha256` file as second asset |
| DEPLOYMENT.md for operators | New operators need a single authoritative install guide; RUNBOOK.MD covers day-2 ops but not initial setup from a release tarball | M | Currently RUNBOOK.MD Section 1 covers git-clone install, not tarball install |
| RUNBOOK additions: "Operational cron schedule" | Operators need a canonical cron table to copy-paste; currently absent | S | Table format: schedule, script, log to check on failure |
| RUNBOOK additions: "Updating from GitHub" | Full operator workflow for `--check` → review → `--version` → verify; layout diagram | S | Includes on-disk layout diagram explaining what survives upgrade |
| Root `README.md` | No README exists; GitHub shows empty repo landing; operators and contributors have no entry point | M | What + who + quickstart + pointer to DEPLOYMENT.md |

---

## Differentiators

Features that make the deployment story noticeably better. Not strictly required, but significantly improve operator confidence.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Print rollback one-liner on every successful upgrade | Operator sees it in terminal scrollback; doesn't have to remember the command under pressure | S | `echo "Rollback: $0 --rollback"` after swap |
| `--force` flag on `--version` to re-extract over existing release dir | Without it, re-deploying same version to fix a bad deploy requires manual cleanup | S | Default: refuse to overwrite existing `releases/vX.Y.Z/` |
| Tarball SHA256 validation in `update_from_github.sh` | Integrity check on download; catches partial downloads and tampering | S | Fetch `.sha256` asset from release, compare with `sha256sum` |
| `--verbose` flag on `warm_cache.py` | Rich progress output for interactive runs; silent by default for cron | S | Toggle between `rich` progress bars and `logging` only |
| `--prune-stale` flag on `warm_cache.py` | Matches `run_all.py` stale-cache pruning behavior; keeps `data/cache/` clean if run before `run_all.py` | S | Remove prior-day folders |
| `--date YYYY-MM-DD` flag on `warm_cache.py` | Manual backfill for specific dates; useful for debugging or pre-warming before a scheduled run | S | Default: today (server-local) |
| Workflow `workflow_dispatch` input for manual release trigger | Lets maintainer cut a release from the GitHub Actions UI without pushing a tag locally | S | Second trigger alongside `push tags: ['v*']` |
| Prerelease detection from tag suffix | `v1.2.0-rc1`, `v1.2.0-beta` auto-marked as prerelease in GitHub Releases; stable tags publish as full release | S | Check if tag contains `-` after semver; set `prerelease: true` in release step |
| Auto-generated release notes from merged PRs | GitHub's `generate-release-notes` action pulls merged PR titles between tags; saves maintainer writing effort | S | `uses: actions/github-script` or `generate_release_notes: true` in `gh release create` |
| `deploy/crontab.example` | Copy-paste cron lines for warm cache + run-due + output cleanup; self-documenting | S | Companion to RUNBOOK cron table |
| Upgrade instructions in DEPLOYMENT.md cross-reference to RUNBOOK | Operator navigates naturally: DEPLOYMENT.md for first install, RUNBOOK for subsequent updates | S | Single sentence with section reference |
| systemd unit `ReadWritePaths` update for `current` symlink layout | Existing `vuln-reports.service` hardcodes `/opt/vuln-reporting/output` etc.; after symlink layout, those paths must resolve through `current/` or `shared/` | S | Required for SELinux + systemd sandboxing to keep working |

---

## Anti-Features

Features to explicitly NOT build in this milestone.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Auto-apply updates (unattended upgrade) | This is a security tool delivering to executives and CISOs; silent code changes are inappropriate; operator decision must stay in the loop | `--check` for discovery; `--version` requires explicit operator invocation |
| Multi-host or fleet deployment | Single-server target; adding host inventory, SSH orchestration, or Ansible playbooks is premature complexity for v1.2 | Document as future scope note in DEPLOYMENT.md |
| PyPI packaging / `pip install` | Biggest refactor (entry points, package layout, console_scripts); deferred per PROJECT.md constraints | `.gitattributes` + tarball is the right v1 mechanism |
| Git-on-server deploy path | `git clone` / `git pull` ships dev artifacts; adds git to server dependency surface; removes pinned-version discipline | Release tarball only |
| Automatic venv creation during update | Risk: wrong Python version, missing system deps (WeasyPrint C libs), silent failure mid-upgrade | Document venv creation in DEPLOYMENT.md; operator runs it once at initial install; `pip install -r requirements.txt` on each upgrade is explicit |
| Docker / container packaging | Different operational model; out of scope for a scheduler-daemon deployment | Note in DEPLOYMENT.md as a future option |
| Changelog auto-commit back to repo | Release workflow writing to `main` creates chicken-and-egg tagging problem and complicates history | Use GitHub's auto-release-notes from PR titles instead |
| README badges that require external services | CI status badges need a green workflow to exist; coverage badges need coverage tooling; don't add badges that will show broken/unknown on day one | Add only static shields (license, python version) or skip until CI is established |

---

## Feature Dependencies

```
.gitattributes export-ignore
  └── GitHub Actions release workflow
        └── slim tarball asset in release
              └── update_from_github.sh --version (downloads from release)
                    └── SHA256 validation (needs .sha256 asset from workflow)
                    └── --dry-run post-install (needs venv + requirements.txt in release)
                    └── --rollback (needs .last breadcrumb from a prior --version run)
                    └── --list (needs releases/ dir structure from prior installs)

shared/ layout decision (PROJECT.md)
  └── update_from_github.sh shared/ wiring
  └── systemd unit ReadWritePaths update (shared/ paths must be whitelisted)
  └── DEPLOYMENT.md initial install instructions (operator creates shared/ manually)

warm_cache.py
  └── data/fetchers.py (reused, no new dependency)
  └── tenable_client.get_client() (reused)
  └── deploy/crontab.example (references warm_cache.py cron line)
  └── RUNBOOK "Operational cron schedule" (references warm_cache.py)

DEPLOYMENT.md
  └── RUNBOOK "Updating from GitHub" (cross-reference between docs)
  └── update_from_github.sh (documents its modes)
  └── GitHub Actions workflow (references release tarball URL pattern)

README.md
  └── DEPLOYMENT.md (quickstart points to it)
  └── RUNBOOK.MD (operator ops reference)
```

---

## MVP Recommendation

**Phase ordering:**

1. `.gitattributes` + GitHub Actions workflow (S+M) — gate for everything else; without a real release tarball to test against, the update script cannot be validated end-to-end
2. `warm_cache.py` (M) — independent of deploy infrastructure; can ship in parallel with or immediately after phase 1
3. `update_from_github.sh` (M) — depends on phase 1 having cut at least one test release tarball; SHA256 validation depends on workflow uploading the `.sha256` asset
4. DEPLOYMENT.md + RUNBOOK additions (M) — depends on all scripts existing to document; write against the final behavior
5. `README.md` (M) — can be drafted early but finalized last once the install story is stable

**Minimum viable for "operator can deploy without author help":**
- `.gitattributes` ✓
- Release workflow ✓
- `update_from_github.sh` with `--version`, `--check`, `--rollback`, `--list` ✓
- `shared/` layout + symlink wiring ✓
- Post-install `--dry-run` validation ✓
- systemd restart after swap ✓
- DEPLOYMENT.md initial install section ✓
- RUNBOOK "Updating from GitHub" section ✓

**Defer to post-v1.2 if scope is tight:**
- `warm_cache.py --date` and `--prune-stale` flags (core warm behavior is the value; flags are polish)
- Auto-generated release notes (maintainer can write a one-liner manually for v1.2)
- `deploy/crontab.example` (RUNBOOK table covers the same ground in prose)
- README badges

---

## Complexity Notes

**S = Small:** < half day; mostly mechanical or formula-following (shell conditionals, cron line, doc section).
**M = Medium:** half to full day; requires design decisions, integration with existing code, or cross-cutting behavior (update script orchestration, Actions workflow, warm_cache.py integration with fetchers).
**L = Large:** multi-day; not present in this milestone's feature set.

**Feature count by complexity:**
- S: 19 features
- M: 5 features
- L: 0 features

Total estimated scope: ~4–6 engineering days if all differentiators are included; ~2–3 days for table stakes + most-valued differentiators only.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Table stakes (what must exist) | HIGH | Drawn directly from todo files + PROJECT.md; all items explicitly captured by the operator in prior exploration |
| Shell script safety rails | HIGH | Atomic symlink swap, `.last` breadcrumb, refuse-if-unknown-layout, SHA256 validation are universal patterns in mature deploy tooling (Capistrano, Fabric, Mina all use them) |
| GitHub Actions release workflow | HIGH | `v*` tag trigger + `workflow_dispatch` + asset upload is the standard pattern; prerelease detection from tag suffix is documented GitHub behavior |
| README sections | HIGH | Standard GitHub open-source README structure; operator-internal vs public distinction affects badge/contributing sections only |
| DEPLOYMENT.md sections | HIGH | Directly derived from existing RUNBOOK.MD structure + gaps identified in todo files |
| RUNBOOK conventions | HIGH | Existing RUNBOOK.MD establishes the project's conventions; additions follow that style |
| Complexity estimates | MEDIUM | No implementation has started; estimates based on scope of each feature, not measured velocity |
