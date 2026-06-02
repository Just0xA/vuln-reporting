---
phase: quick-260602-jqg
plan: 01
status: complete
verification: UNVERIFIED-ON-WINDOWS (operator must confirm on RHEL/Rocky VM)
commits:
  - 2179eb5  # fix(updater): restore service-account ownership after root-run install
  - 9ff0249  # docs(deployment): document two invocation models + proxy guidance for updater
files_modified:
  - scripts/update_from_github.sh
  - DEPLOYMENT.md
---

# Quick Task 260602-jqg — Updater chown release dir + invocation/proxy docs

## Problem

`scripts/update_from_github.sh` never set ownership on anything it created. Run as
root (the documented default — it needs `sudo systemctl restart`), `extract_release`
(`mkdir -p` + `tar`) and `provision_venv` (`python -m venv` + `pip`) left the new
release dir and its `.venv` owned by **`root:root`**. The systemd service runs as
`User=vuln-reports` under `ProtectSystem=strict` against a `chmod 750` install tree,
so it is neither owner nor in the `root` group and cannot read its own release/venv.
Result: the post-swap health check fails and the updater auto-rolls-back (exit 12)
on every clean root-run upgrade.

The user surfaced it on an alternate install root (`/opt/storage/vuln-reporting`),
but the trigger is **running the updater as root**, not the path — the derived-owner
fix handles any `INSTALL_ROOT` with zero special-casing.

## What changed

### Task 1 — `scripts/update_from_github.sh`
- New helper `fix_release_ownership TARGET_DIR` added after `symlink_shared`.
- Called from `cmd_install` after `provision_venv "$TARGET_DIR"` + `symlink_shared
  "$TARGET_DIR"` and **before** the `PARTIAL_RELEASE_DIR=""` disarm — so a chown
  failure still triggers the EXIT-trap partial-release-dir cleanup.
- Behavior:
  - Non-root (`[ "$(id -u)" -ne 0 ]`) → log one line, `return 0`, no chown (files
    already owned by the invoking account).
  - Intended owner derived from `${INSTALL_ROOT}/releases` via GNU `stat -c '%U:%G'`
    (RHEL/Rocky coreutils; **not** hardcoded, **not** BSD `-f`). `stat` failure →
    fail-loud `log_completed "failed: ..."` + `exit 16`.
  - Skips the recursive walk when the release dir already matches the intended owner.
  - Otherwise `chown -R "$intended_owner" "$target_dir"`; failure → `exit 16`.
  - Code comment warns a future maintainer NOT to add `-L`/`-H`: default `chown -R`
    changes the `shared/` symlinks themselves, not their targets — intended, so
    `shared/` stays service-account-owned.
- Exit code **16** documented in the header block (lines 9–25).

### Task 2 — `DEPLOYMENT.md`
- "Allow the updater to restart the service" section rewritten into two explicit
  invocation models:
  - **Run as root (default)** — notes the updater now auto-restores service-account
    ownership of the new release dir + `.venv`, so a root-run upgrade no longer leaves
    a `root:root` tree the `ProtectSystem=strict` service can't read.
  - **Run as the `vuln-reports` service account** — supported for cron automation;
    updater skips the chown; **requires** the scoped sudoers `systemctl restart` entry
    (already documented) or the health check auto-rolls-back every upgrade.
- New "Proxy variables for the service-account path" subsection: `curl` (download) and
  `pip` (venv) need outbound internet; the AD user's proxy env is NOT inherited by the
  service account. Set `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` (+ lower-case variants) on
  the invocation/wrapper line — NOT in `shared/.env` (same chicken-and-egg constraint
  as `INSTALL_ROOT`; the updater reads only `GITHUB_RELEASE_REPO`/`GITHUB_TOKEN` from it
  and doesn't export them to curl/pip). Includes an example cron/wrapper line.
- No new `##` heading → table of contents unchanged.

## Verification

**Static only (this is a Windows dev box):**
- `bash -n scripts/update_from_github.sh` — clean.
- Project E2E suite (`pytest -n auto`, the `.githooks/pre-commit` gate) — 40 passed,
  green at base and after the change (the change is bash + markdown; the Python suite
  is unaffected).
- Manual review of the diff confirmed the placement, the `id -u` guard, the derived
  GNU `stat` owner, the fail-loud `exit 16`, and the no-`-L`/`-H` comment.

**⚠ UNVERIFIED — requires operator confirmation on the RHEL/Rocky VM.**
The ownership outcome cannot reproduce on Windows. On the VM, after a root-run
`--version` upgrade, confirm:
1. The new release dir and its `.venv` are owned by the service account (`vuln-reports`),
   matching `${INSTALL_ROOT}/releases`.
2. The post-swap health check passes (no auto-rollback / exit 12) on a healthy release.
3. Re-test on the alternate install root (`/opt/storage/vuln-reporting`) that originally
   surfaced the bug.
4. (Optional) Confirm the non-root / service-account invocation path still works with the
   sudoers entry and proxy variables set.

## Notes
- No new dependencies. Surgical — only the two files touched.
- The SUMMARY was reconstructed by the orchestrator after worktree cleanup (the
  executor's in-worktree copy was uncommitted by design and removed with the worktree).
