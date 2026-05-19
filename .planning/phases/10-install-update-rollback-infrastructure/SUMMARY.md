# Phase 10 — Install / Update / Rollback Infrastructure

**Status**: Planned (3 plans pending)
**Depends on**: Phase 7 (Foundations — `/opt/vuln-reporting/{current,releases,shared}/` layout), Phase 9 (CI/Release Automation — slim tarball + `.sha256` sidecar published to GitHub Releases)
**Requirements**: UPDATE-01..14, LOG-02 (15 total; UPDATE-15 already shipped in Phase 7)

---

## Wave structure

| Wave | Plan | Title | Reqs covered | Est. LOC | Depends on |
|------|------|-------|--------------|----------|------------|
| 1 | [10-01-PLAN.md](10-01-PLAN.md) | Skeleton + safety guards + `--check` / `--list` | UPDATE-09, UPDATE-10, UPDATE-04, UPDATE-01, UPDATE-12, LOG-02 | ~220 | — |
| 2 | [10-02-PLAN.md](10-02-PLAN.md) | `--version vX.Y.Z` install flow (download, SHA256, extract, venv, symlinks, dry-run, atomic swap, breadcrumb) | UPDATE-02, UPDATE-06, UPDATE-07, UPDATE-13, UPDATE-14 | ~220 | 10-01 |
| 3 | [10-03-PLAN.md](10-03-PLAN.md) | `--rollback`, `--force`, `--skip-restart`, post-swap health check w/ auto-rollback, rollback one-liner | UPDATE-03, UPDATE-05, UPDATE-08, UPDATE-11 | ~150 | 10-01, 10-02 |

**Total estimated LOC**: ~590 across one Bash file (`scripts/update_from_github.sh`, ~580 lines) plus ~10 lines added to `.env.example`.

Plans are strictly sequential because they all edit the same Bash file — Plan 10-02 replaces the `cmd_install` stub from 10-01, and Plan 10-03 inserts logic INSIDE the `cmd_install` body that 10-02 builds. No parallelism is possible.

---

## Requirement → Plan → Verification matrix

| Req | Plan | Implementation | Verification |
|-----|------|----------------|--------------|
| UPDATE-01 | 10-01 | `cmd_check`: GET `releases/latest`, parse `tag_name` via python3, compare to `basename(readlink current)`. Exit 0/1/≥2. | Grep on script + manual `--check` smoke on Linux VM. |
| UPDATE-02 | 10-02 | `cmd_install`: download → `sha256sum -c` → `tar --strip-components=1` → venv → symlinks → dry-run → atomic swap → restart. | Grep on each pipeline step + end-to-end Linux VM smoke. |
| UPDATE-03 | 10-03 | `cmd_rollback`: read `.last`, reuse `atomic_swap` + `write_breadcrumb`, restart. Refuse on missing/empty/out-of-bounds `.last`. | Grep on `cmd_rollback` body + manual rollback smoke + no-history refusal smoke. |
| UPDATE-04 | 10-01 | `cmd_list`: enumerate `releases/*/`, mark active with `* (active)`, sort -V, exclude `.last`. | Grep + manual smoke. |
| UPDATE-05 | 10-03 | `--force` → `FORCE=1`; parser rejects outside `--version`. `--skip-restart` → skips restart AND health check with WARNING log. | Grep on SKIP_RESTART branch + flag-combo parser test. |
| UPDATE-06 | 10-02 | Atomic swap via `ln -sfn` only (`atomic_swap` helper); negative grep ensures no `rm` + `ln` on `current`. 10-03 reuses the helper. | Positive `ln -sfn .*current` grep + negative `rm .*current` grep excluding comments. |
| UPDATE-07 | 10-02 | `PREV=$(readlink current)` captured BEFORE swap; `.last.tmp` + `mv` written AFTER swap (`write_breadcrumb` helper). 10-03 reuses for rollback. | Greps on `readlink .*current` + `.last.tmp` + `mv .*.last`. |
| UPDATE-08 | 10-03 | Post-restart `sleep 10 && systemctl is-active --quiet`; failure → `auto_rollback` reusing 10-02 helpers; recursion guard via `IN_AUTO_ROLLBACK=1`. | Greps on `systemctl is-active`, `sleep 10`, `IN_AUTO_ROLLBACK` + Linux VM smoke forcing a failing release. |
| UPDATE-09 | 10-01 | `set -euo pipefail`, EXIT trap; 10-02 extends with partial-release-dir + tempdir cleanup. | Grep `set -euo pipefail` + `trap .* EXIT` + `PARTIAL_RELEASE_DIR`. |
| UPDATE-10 | 10-01 | `assert_layout()`: INSTALL_ROOT exists; `current` is a symlink; target inside `releases/`; `shared/` exists. Runs before env sourcing. | Grep + manual smoke with `INSTALL_ROOT=/tmp/fake-install` aborting cleanly. |
| UPDATE-11 | 10-03 | `echo "Rollback: sudo ${INSTALL_ROOT}/current/scripts/update_from_github.sh --rollback"` before `log_completed success`. | Grep on the literal string + visual check on smoke run. |
| UPDATE-12 | 10-01 | `gh_api_get()` conditionally adds `Authorization: Bearer $GITHUB_TOKEN`; `.env.example` documents the 60→5000/hr lift. | Grep on `GITHUB_TOKEN` in both files. |
| UPDATE-13 | 10-02 | `provision_venv()`: `python3 -m venv .venv` + `pip install -r requirements.txt` on every install. | Grep on both commands. |
| UPDATE-14 | 10-02 | `symlink_shared()`: six `ln -sfn` for `.env`, `delivery_config.yaml`, `logs`, `output`, `data/cache`, `data/trend`. | Loop-grep on all six target names. |
| LOG-02 | 10-01 | `log_started` / `log_completed` write `started at <ISO> with argv=<X>` and `completed at <ISO> status=<success|failed: reason>` to `${INSTALL_ROOT}/shared/logs/update.log` on every code path including usage errors. | Grep on `started at`, `completed at`, `update\.log` + cron-style bad-flag smoke. |

**Coverage**: 15 of 15 requirements mapped. UPDATE-15 already shipped in Phase 7.

---

## Cross-plan handoffs (executor notes)

### From 10-01 → 10-02
- `cmd_install` stub in 10-01 prints "not yet implemented in plan 10-02" and exits 3. Plan 10-02 replaces the whole function body.
- The EXIT trap in 10-01 has a placeholder comment `# Plan 10-02 will extend this trap with release-dir cleanup`. Plan 10-02 removes the comment and adds the partial-dir + tempdir cleanup branches.
- The flag parser in 10-01 already declares `--version`, `--force`, `--skip-restart`, `--rollback`. Plan 10-02 does NOT modify the parser — it only consumes the parsed shell vars.
- 10-02 reserves exit codes 4–11 in a comment block near `cmd_install`; 10-03 reserves 12–15.

### From 10-02 → 10-03
- 10-02 leaves a simple `systemctl restart` at the tail of `cmd_install` (no health check). Plan 10-03 replaces this block with restart-or-skip + health-check + auto-rollback structure.
- 10-02's helpers `atomic_swap` and `write_breadcrumb` are CONTRACT — 10-03 reuses them inside both `cmd_rollback` and `auto_rollback`. Do not duplicate swap logic.
- The relative-vs-absolute symlink target handling (`case "$PREV" in /*) ;; *) PREV="$INSTALL_ROOT/$PREV";; esac`) is established in 10-02; 10-03 repeats it in `cmd_rollback`.

### Style invariants across all three plans
- 2-space indent; `lower_snake` function names; `UPPER_SNAKE` shell vars.
- Structured records → `update.log` via `log_line` / `log_completed`. Operator-facing messages → stderr.
- `--help` alone is the ONE path that does not write to `update.log` — every other path, including usage errors, does.
- `ln -sfn` is the ONLY way to mutate `current` or any shared-path symlink. `rm -f X && ln -s …` is forbidden — UPDATE-06 enforced via negative grep in all three plans.

### Testing limitations
- The dev box is Windows; the script runs on Linux. Per-plan automated verification relies on `bash -n` and `grep`.
- End-to-end functional verification requires the post-merge Linux VM smoke documented in each plan's `<human-check>` blocks.
- 10-03's auto-rollback path requires deliberately publishing a broken release; the smoke documents how (temporarily stub `smoke_dry_run` to `return 0`).

---

## Out of scope (deferred from REQUIREMENTS.md)

Multi-host upgrades; auto-applied/unattended updates; PyPI/Docker distribution; SHA-pinning of GitHub Actions; skip-if-unchanged venv (UPDATE-13 explicitly says "always run pip"); sudoers configuration for passwordless `systemctl restart` (Phase 11 runbook); runtime path-traversal scrubbing of tarball contents (Phase 9 `.gitattributes` + SHA256 is the integrity story).

---

## Exit code reservation table (final, for Phase 11 runbook)

| Code | Plan | Meaning |
|------|------|---------|
| 0 | 10-01 | success (or `--check` up-to-date) |
| 1 | 10-01 | `--check` reports update available |
| 2 | 10-01 | usage error OR layout-guard failure |
| 3 | 10-01 | upstream GitHub API failure |
| 4 | 10-02 | release-asset download failure |
| 5 | 10-02 | SHA256 mismatch |
| 6 | 10-02 | tarball extraction failure |
| 7 | 10-02 | release dir already exists (without `--force`) |
| 8 | 10-02 | venv provisioning failure |
| 9 | 10-02 | post-extraction `data/` dir missing |
| 10 | 10-02 | dry-run smoke test failed |
| 11 | 10-02 | atomic swap post-condition failed |
| 12 | 10-03 | health check failed, auto-rollback SUCCEEDED |
| 13 | 10-03 | health check failed, auto-rollback ALSO failed (critical) |
| 14 | 10-03 | `--rollback` invoked but `.last` missing/empty/out of bounds |
| 15 | 10-03 | `--rollback` swap or restart failed |
