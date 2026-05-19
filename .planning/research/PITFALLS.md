# Deployment Infrastructure Pitfalls

**Domain:** Adding deployment infrastructure to a Python + systemd reporting suite
**Milestone:** v1.2 Server Update and Install
**Researched:** 2026-05-19
**Confidence:** HIGH — grounded in project files, systemd unit, existing gitignore/gitattributes draft, and validated deployment patterns

---

## Critical Pitfalls

Mistakes that cause security incidents, data loss, silent rollback failures, or midnight report misses.

---

### CRITICAL-01: `.env` or `data/trend/` leaks into the release tarball

**What goes wrong:** `.gitattributes export-ignore` only suppresses paths that are **tracked by git**. `.env` is already `.gitignore`d and therefore untracked — it will NOT appear in a `git archive` tarball regardless of `.gitattributes`. However, `.env.example` IS tracked and WILL appear in the tarball. If `.env.example` contains filled-in placeholder values (real hostnames, real API key prefixes, real SMTP passwords copied from a prior session), those values are now public in the GitHub Release asset.

**Why it happens:** Developer fills in `.env.example` as a "living template" to remember field names, then forgets to scrub before tagging. The `.gitignore` on `.env` provides false confidence that secrets are safe.

**Consequences:** Tenable API credentials, SMTP credentials, or internal hostnames published on a public GitHub release page. Permanent — tarball assets on GitHub are crawled.

**Prevention:**
- Audit `.env.example` in the pre-release checklist: every value must be a clearly fake placeholder (e.g., `your_access_key_here`, `smtp.yourcompany.com`).
- Add a CI check in `release.yml`: `grep -E '^(TVM_ACCESS_KEY|TVM_SECRET_KEY|SMTP_PASSWORD)=.+[^_here]$' .env.example && exit 1` to catch non-placeholder values.
- The sensitive data discipline from D-04-08 applies to the tarball, not just committed code.

**Detection:** Download the release tarball from GitHub after tagging; extract and inspect `.env.example` before announcing the release.

**Phase:** Addresses in the phase that builds `.github/workflows/release.yml` and writes `DEPLOYMENT.md`. The `.env.example` audit step belongs in the release checklist section of `DEPLOYMENT.md`.

---

### CRITICAL-02: `data/trend/` sneaks into the tarball because it is selectively gitignored

**What goes wrong:** `.gitignore` excludes `data/trend/` globally. But if any snapshot file was ever committed before the gitignore rule was added (see git history: `5bdb866 chore(security): untrack data/trend snapshots; add to .gitignore` and `1315c64 docs(quick-260514-mlk): scrub data/trend from history`), the path may still exist in the git object store as a tracked file. `git archive HEAD` includes tracked files regardless of `.gitignore`. If a future developer accidentally `git add data/trend/` before `.gitignore` catches it, the snapshot lands in the next release tarball.

**Why it happens:** `.gitattributes export-ignore` was not added for `data/trend/` because it is already gitignored. The assumption "gitignored = safe" breaks when the file is accidentally staged.

**Consequences:** Real Tenable vulnerability data (asset counts, plugin IDs, trend metrics) published in a release asset. Violates D-04-08 sensitive data discipline.

**Prevention:**
- Add `data/trend/    export-ignore` to `.gitattributes` as a belt-and-suspenders rule — it costs nothing and guards against accidental staging.
- Also add `output/    export-ignore`, `logs/    export-ignore`, `data/cache/    export-ignore` for the same reason.
- In `release.yml`, add a step that runs `git archive` locally and uses `tar -tzf` to assert these paths are absent before uploading the artifact.

**Detection:** `git archive --format=tar.gz HEAD -o /tmp/preview.tar.gz && tar -tzf /tmp/preview.tar.gz | grep -E '^(data/trend|output|logs)'` must return nothing.

**Phase:** Phase that creates `.gitattributes`. Add the tarball content assertion to the release workflow phase.

---

### CRITICAL-03: Non-atomic symlink swap leaves the scheduler pointing at a partial extraction

**What goes wrong:** The naive update sequence is:
```
rm /opt/vuln-reporting/current
ln -s releases/v1.2.0 /opt/vuln-reporting/current
```
Between the `rm` and the `ln`, any `scheduler.py --mode run-due` invocation (fired by cron every 5 minutes) resolves `WorkingDirectory=/opt/vuln-reporting` from the systemd unit — but `current` does not exist. The process either fails to start or starts with no working directory. Even if the window is small, this is a real risk at 07:00 when `run-due` fires for the morning delivery groups.

The atomic form is `ln -sfn releases/v1.2.0 /opt/vuln-reporting/current` — `ln -sfn` on Linux is atomic at the filesystem level because it calls `rename(2)` on a temporary symlink. The non-atomic form using `rm` + `ln` must not appear in `update_from_github.sh`.

**Why it happens:** `rm` + `ln` is the intuitive sequence. `ln -sfn` behavior (atomic replace) is non-obvious.

**Consequences:** Cron-fired scheduler invocation during the swap window hits a missing working directory; the systemd unit may enter a failed state requiring manual restart. The swap appears to have succeeded but the service is down.

**Prevention:** Use only `ln -sfn TARGET LINK` in `update_from_github.sh`. Add a comment explaining why `rm` + `ln` is forbidden. Verify atomicity in the apply checklist by running the swap twice in rapid succession from two terminals.

**Detection:** `systemctl status vuln-reports` immediately after swap; any state other than `active (running)` is a failure.

**Phase:** Phase that builds `update_from_github.sh`. The `ln -sfn` form must be in the code; the `rm` form must not appear.

---

### CRITICAL-04: `Restart=on-failure` masks a failed symlink swap

**What goes wrong:** `deploy/vuln-reports.service` sets `Restart=on-failure`. If `update_from_github.sh` swaps the symlink to a broken release (missing `scheduler.py`, bad `requirements.txt`, Python syntax error in new code), systemd will:
1. Detect the process exit with non-zero code.
2. Wait `RestartSec=30`.
3. Restart the process — but now pointing at the broken release.
4. Repeat up to `StartLimitBurst=5` within `StartLimitIntervalSec=300`.

The operator sees "service restarted" in the restart log and may not notice the release is broken. The service enters `failed` state only after 5 attempts. Morning report deliveries miss.

**Why it happens:** `Restart=on-failure` is correct for normal crash recovery. The failure mode here is not a crash — it is a bad deploy that the restart policy cannot distinguish from a transient crash.

**Prevention:**
- `update_from_github.sh` must run `python run_all.py --dry-run` against the new release dir **before** the symlink swap, not after. If `--dry-run` fails, abort the swap, leave `current` pointing at the prior release, print the rollback hint.
- After swap, `update_from_github.sh` must restart the service and then run `systemctl is-active vuln-reports` with a 10-second settle wait. If not active, immediately roll back the symlink and restart.
- Document this sequence explicitly in DEPLOYMENT.md: "the script validates before swapping, not after."

**Detection:** `journalctl -u vuln-reports -n 50` showing repeated `Started → Exited` cycles is the warning sign.

**Phase:** Phase that builds `update_from_github.sh` — the pre-swap `--dry-run` and post-swap active-check are implementation requirements, not nice-to-haves.

---

### CRITICAL-05: `rollback` breadcrumb (`releases/.last`) not updated atomically — silent broken rollback

**What goes wrong:** `update_from_github.sh --rollback` reads `releases/.last` to know which version to roll back to. If the script writes `.last` before the symlink swap completes (or after a partial failure), the breadcrumb points at the wrong version. Worse: if the script crashes between writing `.last` and completing the swap, the next `--rollback` invocation rolls back to a version that was never actually active.

**Why it happens:** The breadcrumb write and the symlink swap are two separate filesystem operations. `set -euo pipefail` stops the script on error but does not make the two-step atomic.

**Consequences:** `--rollback` after a failed upgrade installs the wrong release. The operator believes they rolled back but the service is still running broken code.

**Prevention:**
- Write `.last` only after `ln -sfn` succeeds (not before). Sequence: (1) validate new release, (2) `ln -sfn` new, (3) write `.last` = old version, (4) restart service. If step 4 fails, the symlink still points at the new release — the operator must re-run `--rollback` manually, which at this point reads the now-correct `.last`.
- Alternatively, store the previous symlink target by reading it before the swap: `PREV=$(readlink /opt/vuln-reporting/current)`. Then `.last` is written from the in-memory value, not from a prior file state.
- Print the explicit rollback command (`update_from_github.sh --rollback`) on every successful swap so the operator has it in terminal scrollback.

**Detection:** After any upgrade, run `cat /opt/vuln-reporting/releases/.last` and verify it matches the previously active release.

**Phase:** Phase that builds `update_from_github.sh`. The breadcrumb write order is a correctness requirement.

---

## Moderate Pitfalls

Mistakes that cause report misses, operator confusion, or silent data drift without immediate failures.

---

### MOD-01: Midnight cache crossover — warm at 23:59, batch runs 00:01

**What goes wrong:** `scripts/warm_cache.py` uses server-local date for the cache folder name (`data/cache/YYYY-MM-DD/`), matching the behavior of `run_all.py`. If `warm_cache.py` is scheduled at, say, `23:45` and completes at `23:59`, the cache is written to `data/cache/2026-05-19/`. If the first report group fires at `00:01` (e.g., a `weekly` group scheduled for `Monday 00:01`), `run_all.py` computes today's date as `2026-05-20` and finds no cache — falls back to live fetch, paying full API latency, and the cache folder from warm_cache is now stale and will be pruned.

**Why it happens:** Cache naming is date-based (by design, from the existing `run_all.py` stale-folder-pruning logic). A warm job that straddles midnight creates a date mismatch.

**Prevention:**
- Schedule `warm_cache.py` far enough before the earliest report group that there is no midnight crossover risk. A 06:15 warm job for a 07:00 first delivery group is safe.
- `DEPLOYMENT.md` cron schedule section must show the warm job running at least 30 minutes before the earliest scheduled delivery group, with an explicit note: "do not schedule the warm job within 30 minutes of midnight if any report group fires shortly after midnight."
- This is already flagged in `.planning/PROJECT.md` backlog as PERF-02 (per-day cache midnight crossover). The v1.2 cron schedule doc must address it concretely.

**Detection:** `logs/warm_cache.log` shows a completion timestamp; `logs/app.log` shows `[CACHE MISS]` on the first batch run of the day despite warm job having run. Compare the dates in the folder names.

**Phase:** Phase that writes `scripts/warm_cache.py` and the RUNBOOK/DEPLOYMENT cron schedule section. The cron schedule example must not accidentally place the warm job near midnight.

---

### MOD-02: Double-warming — `scheduler.py` daemon fires during `warm_cache.py` run

**What goes wrong:** If `scheduler.py --mode daemon` is running alongside a cron-fired `warm_cache.py`, both may attempt to write `.parquet` files to the same `data/cache/YYYY-MM-DD/` folder simultaneously. The daemon's in-process warm (triggered by the first group of the day) and the standalone warm script race on file writes. Partial parquet files are silently corrupt. Pandas reads a partial parquet and produces wrong aggregations without raising an exception.

**Why it happens:** The existing `run_all.py` caches per-batch inside the process. `warm_cache.py` writes the same paths. No file locking exists.

**Prevention:**
- `warm_cache.py` should write to a `.tmp` file and rename atomically (`os.replace`) when complete. The final parquet is either complete or absent — never partial.
- `DEPLOYMENT.md` cron schedule section should note: if the daemon mode is used (not `run-due`), the daemon's internal warm makes `warm_cache.py` redundant for the first group. `warm_cache.py` is primarily useful in `run-due` / cron mode. Document the two deployment models separately.
- Alternatively, `warm_cache.py` can check for an existing cache folder and skip re-fetching if `--no-overwrite` is passed — useful for idempotent cron invocations.

**Detection:** `logs/warm_cache.log` and `logs/app.log` both show fetch activity at the same timestamp. Pandas errors reading a parquet file mid-batch.

**Phase:** Phase that builds `scripts/warm_cache.py` — atomic write is an implementation requirement.

---

### MOD-03: `.gitattributes` itself excluded from the tarball — operator cannot verify export rules

**What goes wrong:** The `.gitattributes` draft (from the footprint todo) includes `.gitattributes    export-ignore`. This means the file that defines the export rules is not present in the tarball. An operator who downloads the tarball and wants to understand what was excluded cannot inspect the rules. This is technically fine for the server install but creates confusion in audits.

More practically: if `.gitattributes` is excluded, then on a fresh server install the operator has no artifact telling them what was stripped. If they later try to `git clone` (fallback install) and apply tarball-style exclusions manually, they have nothing to reference.

**Why it happens:** Common advice to exclude `.gitattributes` from release tarballs, applied without considering audit use case.

**Prevention:** Do not add `.gitattributes    export-ignore` to `.gitattributes`. The file is small, contains no secrets, and its presence in the tarball is informative. The footprint todo draft includes this line — remove it before applying.

**Detection:** Download a preview tarball: `git archive --format=tar.gz HEAD -o /tmp/preview.tar.gz && tar -tzf /tmp/preview.tar.gz | grep gitattributes`. It should appear.

**Phase:** Phase that creates `.gitattributes`.

---

### MOD-04: GitHub Actions `release.yml` on tag re-push overwrites the existing release asset

**What goes wrong:** If `git push --force origin v1.2.0` (or a `git tag -d v1.2.0 && git tag v1.2.0 && git push --force --tags`) is used to correct a tagging mistake, the `release.yml` workflow fires again. The second run attempts to upload a tarball with the same asset name. GitHub's `gh release upload` (or `actions/upload-release-asset`) will fail if the asset already exists unless `--clobber` is used. If `--clobber` IS used, operators who downloaded the original tarball have a different artifact than operators who download after the re-push — silent version skew.

**Why it happens:** Tag re-push is a common developer reflex when a tag points at the wrong commit.

**Prevention:**
- Treat `v*` tags as immutable. Document in `DEPLOYMENT.md`: "Never force-push a version tag. If a tag points at the wrong commit, create a new patch version."
- In `release.yml`, do NOT use `--clobber`. Let the upload fail loudly — a failed CI job is visible; a silently replaced asset is not.
- Add `if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')` guard to the release job to prevent `workflow_dispatch` re-runs from uploading to an existing release.

**Detection:** GitHub Actions run history shows two successful runs for the same tag. Check the release asset's upload timestamp against the tag creation timestamp.

**Phase:** Phase that creates `.github/workflows/release.yml`.

---

### MOD-05: `scripts/` directory not fully excluded from the tarball — `setup_github_labels.py` ships to server

**What goes wrong:** The footprint todo notes `scripts/` is "mixed — `setup_github_labels.py` is dev-only; audit before excluding wholesale." The current `scripts/` contains:
- `warm_cache.py` — runtime (needed on server)
- `update_from_github.sh` — runtime (needed on server)
- `smoke_board_summary_cutover.py` — dev-only (test harness, not needed on server)
- `smoke_email_phase2.py` — dev-only
- `setup_github_labels.py` — dev-only (GitHub API, no server relevance)

If `scripts/    export-ignore` is applied as a blanket rule, `warm_cache.py` and `update_from_github.sh` are also stripped — the server install is missing its operational tools. If `scripts/` is not excluded, dev-only scripts ship unnecessarily.

**Why it happens:** The scripts directory serves two masters (dev tooling + runtime ops). Blanket exclusion removes everything.

**Prevention:** Use per-file `export-ignore` for the dev-only scripts rather than a directory-level exclusion:
```
scripts/setup_github_labels.py          export-ignore
scripts/smoke_board_summary_cutover.py  export-ignore
scripts/smoke_email_phase2.py           export-ignore
```
This keeps `warm_cache.py` and `update_from_github.sh` in the tarball while stripping dev smoke tests.

**Detection:** `git archive` preview — `tar -tzf /tmp/preview.tar.gz | grep scripts/` should show only `warm_cache.py` and `update_from_github.sh`.

**Phase:** Phase that creates `.gitattributes`. The per-file exclusion strategy must be explicit in the implementation plan.

---

### MOD-06: `WorkingDirectory=/opt/vuln-reporting` in the systemd unit resolves the symlink at start — not per-job

**What goes wrong:** The current unit file sets `WorkingDirectory=/opt/vuln-reporting`. On Linux, systemd resolves `WorkingDirectory` at process start time. If `WorkingDirectory` points at a symlink, systemd follows the symlink once and sets the working directory to the resolved path. After a symlink swap, the already-running daemon still has its working directory set to the OLD release path (`/opt/vuln-reporting/releases/v1.1.0/`). It will not pick up new code until the service is restarted.

This is expected and correct — the symlink swap + service restart sequence is the intended deploy mechanism. The pitfall is if `update_from_github.sh` swaps the symlink but does NOT restart the service (e.g., the restart step is skipped due to `--no-restart` flag or a bug in the script).

**Why it happens:** Operators may skip the restart to avoid interrupting an in-progress report. The daemon continues running old code silently.

**Prevention:**
- `update_from_github.sh` must always restart the service after swap unless explicitly passed `--skip-restart` (document that `--skip-restart` means "new code is NOT active until the next restart").
- The default behavior with no flags must include the restart.
- Print a prominent warning if `--skip-restart` is used: "WARNING: symlink swapped but service still running v1.1.0. Run 'systemctl restart vuln-reports' when ready."

**Detection:** After upgrade, `systemctl status vuln-reports` shows the process PID and start time. The start time should be after the upgrade timestamp. If it predates the upgrade, the service was not restarted.

**Phase:** Phase that builds `update_from_github.sh`.

---

### MOD-07: Stale `.pyc` files from prior release survive in `shared/` or `__pycache__/` after symlink swap

**What goes wrong:** Python's bytecode cache (`__pycache__/*.pyc`) is written alongside source files. In the symlink layout, each release directory has its own `__pycache__` trees — these are not in `shared/`. After a symlink swap, the new release has no pre-compiled `.pyc` files and Python compiles them on first import (harmless). The risk is if `shared/` accidentally contains `.pyc` files (e.g., if a previous deploy wrote cache alongside `shared/.env`) or if a symlink inside the release directory points into `shared/` for a directory that then accumulates `.pyc` files.

More concretely: if `data/fetchers.py` lives in the release dir but `data/cache/` is symlinked from `shared/`, Python will not write `.pyc` into `shared/data/cache/` — `.pyc` files go next to the `.py` source. This is safe. The risk is theoretical but real if the `shared/` layout is not clean.

**Prevention:**
- `shared/` should contain only non-code artifacts: `.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/`. Never symlink a directory that contains `.py` files into `shared/`.
- `update_from_github.sh` should not symlink `scripts/` or `reports/` into `shared/`.
- Document the `shared/` content contract in `DEPLOYMENT.md`: "shared contains only config and runtime-generated data, never Python source."

**Phase:** Phase that writes `DEPLOYMENT.md` and `update_from_github.sh`. Document the `shared/` contract explicitly.

---

### MOD-08: `set -euo pipefail` missing from `update_from_github.sh` — partial extraction left on disk

**What goes wrong:** Without `set -euo pipefail`, a failed `tar` extraction (e.g., disk full mid-extract, network interruption during download) leaves a partially-extracted release directory at `releases/v1.2.0/`. The script continues, runs `--dry-run` against the partial directory (which may pass if the missing files are not in the validation path), swaps the symlink, and the service starts against incomplete code.

**Why it happens:** Shell scripts default to continuing on error. `set -e` is frequently omitted.

**Prevention:**
- First line of `update_from_github.sh` (after shebang): `set -euo pipefail`.
- Extract to a temp directory first (`releases/v1.2.0.tmp/`), then `mv` to final name only after successful extraction. On any failure, `trap` removes the `.tmp` directory.
- Pattern:
  ```sh
  set -euo pipefail
  TMPDIR="releases/${VERSION}.tmp"
  trap 'rm -rf "$TMPDIR"' EXIT
  mkdir -p "$TMPDIR"
  tar -xzf "$TARBALL" -C "$TMPDIR" --strip-components=1
  mv "$TMPDIR" "releases/${VERSION}"
  trap - EXIT
  ```

**Detection:** Check for `releases/*.tmp` directories after any interrupted update — their presence indicates a failed extraction.

**Phase:** Phase that builds `update_from_github.sh`. `set -euo pipefail` and the trap-on-extract pattern are implementation requirements.

---

### MOD-09: GitHub Actions `contents: write` permission missing — release upload silently skipped or fails

**What goes wrong:** `release.yml` requires `permissions: contents: write` to create a GitHub Release and upload assets. The default `GITHUB_TOKEN` in a repository does NOT have `contents: write` unless explicitly declared in the workflow or granted in repository settings. Without it, `gh release create` or `actions/create-release` returns a 403. If the error is not surfaced clearly (e.g., swallowed by `|| true`), the workflow appears to succeed but no release asset is uploaded.

**Why it happens:** GitHub's default token permissions changed (restricted defaults are now common). Permission declarations are easy to forget.

**Prevention:**
- Declare explicitly in `release.yml`:
  ```yaml
  permissions:
    contents: write
  ```
- Do not use `|| true` on the release upload step — let it fail loudly.
- In the release workflow, add a step that verifies the asset was uploaded by checking the release page before the job completes.

**Detection:** GitHub Actions run shows green but the Release page has no `.tar.gz` asset attached. Check the upload step's output for HTTP 403.

**Phase:** Phase that creates `.github/workflows/release.yml`.

---

## Minor Pitfalls

Small friction points that cause operator confusion or documentation drift without breaking functionality.

---

### MINOR-01: `export-ignore` only applies to `git archive` — `git clone` on the server bypasses all rules

**What goes wrong:** `.gitattributes export-ignore` is not a security control. It only affects `git archive` (and GitHub's release source tarball generation, which uses `git archive` internally). A `git clone` of the repository pulls everything. If `DEPLOYMENT.md` mentions both "install from tarball" and "clone the repo" as valid options, operators who clone get `.planning/`, `docs/`, `tests/`, and all dev artifacts on the server.

**Why it happens:** The footprint todo already identifies this limitation but it is easy to forget when writing documentation.

**Prevention:**
- `DEPLOYMENT.md` must present only the tarball install as the supported server path. Remove any mention of `git clone` for server deployment.
- If a fallback clone method is documented (e.g., for development installs), label it explicitly: "Development only — not for production server deployment."
- The `.gitattributes` limitation note from the footprint todo ("only applies to git archive/release tarballs, not to git clone") should appear as a callout in `DEPLOYMENT.md`.

**Phase:** Phase that writes `DEPLOYMENT.md`.

---

### MINOR-02: GitHub auto-generated source tarball name collides with CI-built artifact name

**What goes wrong:** When a GitHub Release is published, GitHub auto-generates two source archives: `Source code (zip)` and `Source code (tar.gz)`, named `{repo}-{tag}.tar.gz` (e.g., `vuln-reporting-v1.2.0.tar.gz`). If `release.yml` uploads a CI-built artifact with the same name, the upload fails or the page shows duplicate assets with confusing identical names.

**Why it happens:** GitHub does not prevent asset name collisions between auto-generated and manually uploaded assets in all cases, but the upload step may error.

**Prevention:**
- Name the CI-built artifact distinctly: `vuln-reporting-v1.2.0-slim.tar.gz` or `vuln-reporting-v1.2.0-server.tar.gz`. This also communicates to operators which asset to download ("slim" = dev paths excluded).
- Document in `DEPLOYMENT.md` and `README.md`: "Download the `-slim.tar.gz` asset, not the auto-generated Source code archive."

**Detection:** GitHub Release page shows two assets with the same name. The CI-built upload step exits with an error about duplicate asset names.

**Phase:** Phase that creates `.github/workflows/release.yml` — the asset name in the upload step must use the `-slim` suffix.

---

### MINOR-03: `RUNBOOK.MD` and `DEPLOYMENT.md` drift — rollback one-liner absent from most visible place

**What goes wrong:** The update script prints the rollback command in terminal scrollback. But if an operator is following `DEPLOYMENT.md` for a routine upgrade, they may not read `RUNBOOK.MD` (which has the detailed troubleshooting section). If `DEPLOYMENT.md` does not include the rollback one-liner prominently, the operator who needs it quickly during an incident cannot find it.

**Prevention:**
- `DEPLOYMENT.md` "Updating from GitHub" section must include the rollback one-liner as a prominent block (not buried in a sub-sub-section):
  ```bash
  # Roll back to the previous release immediately:
  sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
  ```
- `RUNBOOK.MD` "Updating from GitHub" section is the detailed version; `DEPLOYMENT.md` is the quick-reference version. They should cross-reference each other, not duplicate.
- At milestone close, do a one-pass review: open both files side by side and verify the rollback one-liner appears in `DEPLOYMENT.md` within the first 30 lines of the update section.

**Phase:** Phase that writes `DEPLOYMENT.md` and `RUNBOOK.MD`. The rollback one-liner placement is a content requirement for `DEPLOYMENT.md`.

---

### MINOR-04: `warm_cache.py` log rotation not configured — `logs/warm_cache.log` grows unbounded

**What goes wrong:** The existing `run_all.py` uses rotating file handlers (`logs/app.log`). If `warm_cache.py` opens a plain `FileHandler` (the simplest path) instead of a `RotatingFileHandler`, the log file grows without bound. On a server that runs warm_cache daily, this is a slow disk fill — visible only after weeks or months.

**Prevention:**
- `warm_cache.py` must use `RotatingFileHandler` with the same parameters as the rest of the suite (match the `maxBytes` and `backupCount` from `run_all.py`/`scheduler.py`).
- This is already on the backlog as PERF-04 (log rotation). v1.2 is the right time to establish the pattern for the new warm_cache log, not defer it.

**Detection:** `ls -lh logs/warm_cache.log` after 30+ days of operation — file should be capped at the rotation size.

**Phase:** Phase that builds `scripts/warm_cache.py` — use `RotatingFileHandler` from day one.

---

### MINOR-05: `delivery_config.yaml` is `.gitignore`d — the server's live config is invisible to version control

**What goes wrong:** `.gitignore` excludes `delivery_config.yaml`. On the server, `shared/delivery_config.yaml` is the live config. After an upgrade, a new `delivery_config.schema.yaml` may add new required fields or tighten enum values. If the server's live config was not updated to match the new schema, `run_all.py --dry-run` (called by `update_from_github.sh` before the symlink swap) will fail schema validation and block the upgrade.

This is actually the CORRECT behavior — the pre-swap `--dry-run` catches the schema mismatch before it reaches production. The pitfall is that the operator may be surprised and not understand why the upgrade is blocked.

**Prevention:**
- `DEPLOYMENT.md` "Updating from GitHub" section must include a step: "Before updating, check the release notes for any `delivery_config.yaml` schema changes. If the new version adds required fields or changes enum values, update `shared/delivery_config.yaml` first, then run `--dry-run`, then proceed with `--version`."
- In `release.yml`, include a `CHANGELOG` entry (or release notes template) that always calls out schema changes explicitly.

**Detection:** `update_from_github.sh --version` aborts at the `--dry-run` step with a jsonschema validation error. The error message names the field — edit `shared/delivery_config.yaml` to add it.

**Phase:** Phase that writes `DEPLOYMENT.md` — the schema-migration step belongs in the upgrade procedure.

---

### MINOR-06: `update_from_github.sh` uses GitHub API without authentication — rate-limited on `--check`

**What goes wrong:** The `--check` mode hits the GitHub Releases API (`https://api.github.com/repos/{owner}/{repo}/releases/latest`) to compare versions. GitHub's unauthenticated API rate limit is 60 requests/hour per IP. On a shared server or CI environment, this can be exhausted. The failure mode is a `403` or `429` response that the script may interpret as "no new release" rather than "rate limited."

**Prevention:**
- Accept an optional `GITHUB_TOKEN` environment variable in the script. If set, pass it as `Authorization: Bearer $GITHUB_TOKEN`. If not set, proceed unauthenticated with a warning logged.
- The `--check` response must distinguish between "up to date", "new version available", and "API error / rate limited". Exit codes: 0 = up to date, 1 = new version available, 2 = error. This lets cron email on exit code 2.

**Phase:** Phase that builds `update_from_github.sh`.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Creating `.gitattributes` | `scripts/` blanket exclusion removes `warm_cache.py` and `update_from_github.sh` | Per-file exclusion for dev-only scripts only (MOD-05) |
| Creating `.gitattributes` | `.gitattributes` itself excluded — audit artifact missing | Do not add `.gitattributes export-ignore` (MOD-03) |
| Creating `.gitattributes` | `data/trend/`, `output/`, `logs/` not covered because they're gitignored — accidental staging sneaks them in | Add belt-and-suspenders `export-ignore` lines (CRITICAL-02) |
| Building `release.yml` | Auto-generated source tarball name collides with CI artifact | Use `-slim` suffix in asset name (MINOR-02) |
| Building `release.yml` | `contents: write` permission missing | Declare explicitly in workflow (MOD-09) |
| Building `release.yml` | `.env.example` with non-placeholder values in tarball | Pre-release audit step + CI grep check (CRITICAL-01) |
| Building `release.yml` | Tag re-push re-runs the workflow and overwrites the asset | Do not use `--clobber`; treat tags as immutable (MOD-04) |
| Building `update_from_github.sh` | `rm` + `ln` non-atomic swap | Use `ln -sfn` only (CRITICAL-03) |
| Building `update_from_github.sh` | `set -euo pipefail` missing, partial extraction left | First line + trap-on-extract pattern (MOD-08) |
| Building `update_from_github.sh` | Rollback breadcrumb written before swap completes | Write `.last` after `ln -sfn` succeeds (CRITICAL-05) |
| Building `update_from_github.sh` | `Restart=on-failure` masks a bad deploy | Pre-swap `--dry-run` + post-swap active-check required (CRITICAL-04) |
| Building `update_from_github.sh` | Service not restarted after swap | Default behavior must restart; `--skip-restart` must warn (MOD-06) |
| Building `update_from_github.sh` | GitHub API rate limit on `--check` | Accept optional `GITHUB_TOKEN`; distinguish error vs "up to date" (MINOR-06) |
| Building `scripts/warm_cache.py` | Midnight crossover — warm at 23:59, batch at 00:01 | Schedule warm job ≥30 min before earliest report group; document in DEPLOYMENT.md cron table (MOD-01) |
| Building `scripts/warm_cache.py` | Concurrent warm + daemon write races on parquet files | Atomic write via `os.replace`; document daemon vs run-due interaction (MOD-02) |
| Building `scripts/warm_cache.py` | Log rotation not configured | Use `RotatingFileHandler` from day one (MINOR-04) |
| Writing `DEPLOYMENT.md` | `git clone` mentioned as install option — bypasses export-ignore | Tarball-only as the supported server path (MINOR-01) |
| Writing `DEPLOYMENT.md` | `delivery_config.yaml` schema migration not covered | Add schema-migration step to upgrade procedure (MINOR-05) |
| Writing `DEPLOYMENT.md` | Rollback one-liner buried or missing | Must appear prominently in the update section (MINOR-03) |
| Writing `DEPLOYMENT.md` | `shared/` contract undocumented — `.pyc` or source files added | Explicit "shared contains config and runtime data only" statement (MOD-07) |

---

## Sensitive Data Discipline Checklist (D-04-08 applied to release artifacts)

The following must be verified before every tag push. Include this as a pre-release checklist in `DEPLOYMENT.md`:

- [ ] `.env` is not tracked by git (`git ls-files .env` returns nothing)
- [ ] `data/trend/` is not tracked by git (`git ls-files data/trend/` returns nothing)
- [ ] `output/` is not tracked by git
- [ ] `logs/` is not tracked by git
- [ ] `.env.example` contains only placeholder values — no real hostnames, key prefixes, or passwords
- [ ] Preview tarball passes content assertion: `git archive --format=tar.gz HEAD -o /tmp/preview.tar.gz && tar -tzf /tmp/preview.tar.gz | grep -E '(\.env$|data/trend|output/|logs/)' | wc -l` outputs `0`
- [ ] Release notes do not contain Tenable asset names, IPs, or plugin names
- [ ] `delivery_config.yaml` is gitignored and absent from the tarball (`git ls-files delivery_config.yaml` returns nothing)

---

## Sources

- Project files: `deploy/vuln-reports.service`, `.gitignore`, `.planning/todos/pending/2026-05-14-shrink-server-footprint-exclude-dev-only-files.md`, `.planning/todos/pending/2026-05-14-deploy-ops-scripts-and-runbook-warm-cache-update-from-github.md`, `.planning/PROJECT.md`
- `ln -sfn` atomicity: uses `rename(2)` syscall, which is atomic on POSIX filesystems — HIGH confidence (standard POSIX behavior)
- systemd `WorkingDirectory` symlink resolution: resolved at process start, not re-evaluated per-job — HIGH confidence (systemd documentation behavior)
- GitHub Actions default token permissions: `contents: read` by default since 2023 — MEDIUM confidence (GitHub documentation, verified against common workflow patterns)
- `git archive` + `.gitattributes export-ignore` scope: only applies to `git archive`, not `git clone` — HIGH confidence (git documentation)
- GitHub auto-generated release tarball naming: `{repo}-{tag}.tar.gz` format — HIGH confidence (GitHub documentation)
