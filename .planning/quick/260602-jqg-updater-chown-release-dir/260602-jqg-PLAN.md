---
phase: quick-260602-jqg
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/update_from_github.sh
  - DEPLOYMENT.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "When run as root, a freshly installed release dir + its .venv end up owned by the service account (same owner as releases/), so the ProtectSystem=strict service can read them and the health check no longer auto-rolls-back on a clean upgrade."
    - "When run as the non-root service account, no chown is attempted (files already correctly owned)."
    - "chown runs after provision_venv and before smoke_dry_run; a chown failure is fail-loud with a dedicated nonzero exit (16) and the EXIT trap still cleans the partial release dir."
    - "chown -R does NOT dereference the shared/ symlinks (no -L/-H), so shared/ stays owned by the service account."
    - "DEPLOYMENT.md documents the two invocation models (run as root vs run as service account) and proxy-variable guidance for the service-account path."
  artifacts:
    - path: scripts/update_from_github.sh
      provides: "fix_release_ownership() helper + cmd_install call site + exit-16 header doc"
      contains: "fix_release_ownership"
    - path: DEPLOYMENT.md
      provides: "Two invocation models + proxy guidance + sudoers reminder"
  key_links:
    - from: "cmd_install"
      to: "fix_release_ownership"
      via: "call after provision_venv/symlink_shared, before smoke_dry_run"
      pattern: "fix_release_ownership"
---

<objective>
Fix `scripts/update_from_github.sh` leaving new release directories owned by `root:root` when the updater runs as root (the documented default). Because the service runs as `User=vuln-reports` under `ProtectSystem=strict` with the install tree `chmod 750`, it cannot read a root-owned release dir/venv — so the post-swap health check fails and auto-rolls-back every clean upgrade.

Fix approach (locked): after the release dir is created and the venv provisioned, `chown -R` the new release dir back to the correct owner, but ONLY when running as root and only when the current owner differs from the intended owner. The intended `owner:group` is derived (not hardcoded) from `${INSTALL_ROOT}/releases` via GNU `stat -c '%U:%G'`, so the alternate-install-root case keeps working with zero special-casing.

Plus DEPLOYMENT.md updates: make the two invocation models explicit and add proxy-variable guidance for the service-account path.

Purpose: A clean upgrade run as root must survive the post-swap health check.
Output: Patched updater script (new exit code 16) + DEPLOYMENT.md docs.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@scripts/update_from_github.sh
@DEPLOYMENT.md
@deploy/vuln-reports.service

<interfaces>
<!-- Key structures the executor needs from scripts/update_from_github.sh. -->

Exit-code header block: lines 9-25. Codes 0-15 are used; 16 is the next free code.

EXIT trap globals (lines 116-147):
- `PARTIAL_RELEASE_DIR` — set by extract_release() to the target dir; the on_exit trap
  rm -rf's it on any non-zero exit while it is still set. cmd_install clears it to ""
  immediately BEFORE smoke_dry_run (line 877). So a chown failure placed AFTER
  provision_venv but BEFORE that clear will still trigger partial-dir cleanup. Good.

Failure idiom used throughout (e.g. provision_venv lines 498-514):
    if ! <cmd>; then
      log_completed "failed: <reason>"
      exit N
    fi

log_line(msg) — timestamped line to update.log.
log_completed(status) — final status line; sets COMPLETED=1.

cmd_install pipeline (lines 845-935), relevant ordering:
    extract_release ...        # sets PARTIAL_RELEASE_DIR=$TARGET_DIR
    provision_venv "$TARGET_DIR"
    symlink_shared "$TARGET_DIR"
    PARTIAL_RELEASE_DIR=""      # line 877 — disarm partial-dir trap
    smoke_dry_run "$TARGET_DIR"
    ...

INSTALL_ROOT constant: line 33, `${INSTALL_ROOT:-/opt/vuln-reporting}`.
releases/ dir: `${INSTALL_ROOT}/releases` (created at install time, owned by service acct).

NOTE: the script runs under `set -euo pipefail` + `IFS=$'\n\t'`. Match the existing
helper-function structure and the `if ! cmd; then ...; exit N; fi` idiom exactly.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add fix_release_ownership() helper + cmd_install call site + exit-16 header</name>
  <files>scripts/update_from_github.sh</files>
  <action>
Add a new helper `fix_release_ownership TARGET_DIR` and call it from `cmd_install` after `symlink_shared "$TARGET_DIR"` and BEFORE the `PARTIAL_RELEASE_DIR=""` disarm line (so a chown failure still triggers the EXIT-trap partial-dir cleanup). Per locked decisions 1-4.

Helper behavior:
- If not running as root (`[ "$(id -u)" -ne 0 ]`): log a single line noting chown is skipped (non-root invocation — files already correctly owned), then `return 0`. Do NOT attempt chown.
- Derive the intended owner from the trusted `${INSTALL_ROOT}/releases` path using GNU coreutils `stat -c '%U:%G'`. This is RHEL/Rocky — use the GNU `-c` form, NOT the BSD `stat -f` form. If `stat` on releases/ fails, treat it as fail-loud: `log_completed "failed: could not determine intended owner from ${INSTALL_ROOT}/releases (stat)"` then `exit 16`.
- Determine the new release dir's current owner the same way (`stat -c '%U:%G' "$target_dir"`).
- Only chown when the current owner differs from the intended owner (skip the recursive walk when already correct; log a "already owned by <owner>; skipping chown" line).
- When they differ: `log_line "chowning ${target_dir} → <owner> (running as root)"`, then run `chown -R "<owner>" "$target_dir"` guarded by the existing failure idiom — on failure `log_completed "failed: chown -R of ${target_dir} to <owner> returned non-zero"` then `exit 16`.
- Add a comment on the chown line per locked decision 4: default `chown -R` (no `-L`/`-H`) changes the symlinks themselves, not their targets — that is intended so shared/ stays owned by the service account; a future maintainer must NOT add `-L`.

Header block (lines 9-25): add `  16  chown of new release dir failed (could not restore service-account ownership; run as root)` after the existing `15` line.

Place the helper after `provision_venv` and before/near `symlink_shared` (decision 3: it must execute after provision_venv so .venv contents are covered). The call site in cmd_install goes after symlink_shared and before the `PARTIAL_RELEASE_DIR=""` line.

Surgical: do not touch any other helper or reorder existing pipeline steps. Match the existing `local` var style, the `${INSTALL_ROOT}/...` quoting, and the helper docstring-comment style used by the neighbours (e.g. provision_venv at line 495).
  </action>
  <verify>
    <automated>bash -n scripts/update_from_github.sh; command -v shellcheck >/dev/null 2>&1 && shellcheck -S warning scripts/update_from_github.sh || echo "shellcheck not available (static syntax check only)"; grep -n "fix_release_ownership" scripts/update_from_github.sh; grep -n "stat -c '%U:%G'" scripts/update_from_github.sh; grep -n "exit 16" scripts/update_from_github.sh; grep -n "^#   16 " scripts/update_from_github.sh</automated>
  </verify>
  <done>
`bash -n` passes (no syntax errors); shellcheck (if installed) reports no new warnings on the added block. `fix_release_ownership` is defined and called from cmd_install after symlink_shared and before the `PARTIAL_RELEASE_DIR=""` disarm. The non-root path returns 0 without chowning. The chown uses GNU `stat -c '%U:%G'` against `${INSTALL_ROOT}/releases`, only chowns when owner differs, fails loud with `exit 16` on stat/chown failure, and carries the no-`-L` comment. Header block documents exit 16.

NOTE: actual ownership outcome CANNOT be verified on this Windows dev box — it only reproduces on the RHEL/Rocky VM. This task's verification is limited to static checks (bash -n, shellcheck, grep, manual logic review). Runtime ownership behavior is OPERATOR-VERIFIED ON THE VM only.
  </done>
</task>

<task type="auto">
  <name>Task 2: DEPLOYMENT.md — two invocation models + proxy guidance</name>
  <files>DEPLOYMENT.md</files>
  <action>
Update DEPLOYMENT.md per locked decision 5. Two doc changes, both in/near the "Allow the updater to restart the service" section (~line 313) and the "Update Procedure" section:

(a) Make the two invocation models explicit:
- **Run as root (default)** — the documented path throughout this guide (`sudo .../update_from_github.sh ...`). Note that the updater now auto-restores service-account ownership of the new release dir (and its `.venv`) after provisioning, derived from the owner of `${INSTALL_ROOT}/releases` — so a root-run upgrade no longer leaves a root-owned tree that the `ProtectSystem=strict` service cannot read. (Briefly: prior to this, a root-run upgrade left the release dir `root:root`, the service could not read it, and the post-swap health check auto-rolled-back.)
- **Run as the `vuln-reports` service account** — supported for flexibility (e.g. cron automation as the service account). In this mode the updater skips the chown (files are already owned correctly). Remind the operator that this mode REQUIRES the scoped sudoers entry already documented in this section (~line 326) for `systemctl restart` — without it the restart fails for the non-interactive account and the post-swap health check auto-rolls-back every upgrade.

(b) Add proxy-variable guidance for the service-account path: `curl` (release download) and `pip` (venv provisioning) need outbound internet, and the proxy is only inherited automatically when the updater is invoked as the company AD user. When running as the `vuln-reports` service account (cron/wrapper), set `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` (and the lower-case `http_proxy` / `https_proxy` / `no_proxy` variants, which curl honors) on the invocation. Explain WHERE: in the sudoers/cron/wrapper invocation line or wrapper script — NOT in `shared/.env` (mirror the existing INSTALL_ROOT chicken-and-egg note at ~line 569: the updater reads only a couple of keys from `shared/.env` and would not export these to curl/pip anyway). A short example wrapper/cron line showing `HTTPS_PROXY=... NO_PROXY=... <path>/update_from_github.sh --version vX.Y.Z` is appropriate.

Surgical: extend the existing "Allow the updater to restart the service" section and add a short proxy subsection; do not restructure unrelated sections or the Table of Contents unless a new ## heading is added (if you add a proxy ## heading, add it to the ToC too — otherwise keep it as a subsection under the existing one and leave the ToC alone). Match the existing prose tone and the fenced-bash example style.
  </action>
  <verify>
    <automated>grep -niE "run as root|service account|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|sudoers" DEPLOYMENT.md | head -40</automated>
  </verify>
  <done>
DEPLOYMENT.md explicitly describes both invocation models (run as root / run as service account), states that root-run upgrades now auto-restore service-account ownership, reminds the service-account path of the scoped sudoers `systemctl restart` entry, and documents `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` (plus lower-case variants) WHERE to set them (invocation/wrapper, not shared/.env) with a short example. Prose and fenced-bash style match the surrounding doc.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| root → service account | Updater (root) creates files the lower-privilege service must read under ProtectSystem=strict + chmod 750. Ownership is the boundary control. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-jqg-01 | Elevation/Tampering | `chown -R` target path | mitigate | Owner is derived from the trusted in-tree `${INSTALL_ROOT}/releases` (not from untrusted input); chown target is `$TARGET_DIR` which is always `${INSTALL_ROOT}/releases/${VERSION}` built from a regex-validated version tag (parse_args line 250). No external path crosses into the chown. |
| T-jqg-02 | Tampering | `chown -R` symlink dereference | accept (by design) | Default `chown -R` (no `-L`/`-H`) changes the symlinks, not their shared/ targets — intended; shared/ stays service-account-owned. Documented in a code comment so it is not "fixed" later. |
| T-jqg-03 | Denial of Service | chown failure mid-upgrade | mitigate | Fail-loud `exit 16`; PARTIAL_RELEASE_DIR still set at the call site so the EXIT trap rm -rf's the partial release dir. No new active release is swapped in. |

No package-manager installs introduced by this change — Package Legitimacy Gate N/A.
</threat_model>

<verification>
- `bash -n scripts/update_from_github.sh` passes.
- shellcheck (if installed) reports no new warnings.
- `fix_release_ownership` defined and called in cmd_install at the correct position (after provision_venv/symlink_shared, before `PARTIAL_RELEASE_DIR=""`).
- Non-root invocation skips chown (`id -u` guard).
- Exit code 16 documented in the header block and used on both stat and chown failure.
- chown comment warns against adding `-L`/`-H`.
- DEPLOYMENT.md documents both invocation models + proxy guidance + sudoers reminder.
- Runtime ownership/health-check behavior is OPERATOR-VERIFIED ON THE VM — NOT verifiable on this Windows dev box.
</verification>

<success_criteria>
- Script passes static checks; the chown block matches the existing bash idioms.
- A root-run clean upgrade will (on the VM) leave the release dir + .venv owned by the service account so the post-swap health check passes — to be confirmed by the operator on RHEL/Rocky.
- DEPLOYMENT.md clearly explains the two invocation models and the proxy requirement for the service-account path.
- The SUMMARY explicitly states the fix is UNVERIFIED until the user confirms on the RHEL/Rocky VM.
</success_criteria>

<output>
Create `.planning/quick/260602-jqg-updater-chown-release-dir/260602-jqg-SUMMARY.md` when done.
The SUMMARY MUST state that the ownership fix is UNVERIFIED on this host and requires operator confirmation on the RHEL/Rocky VM (the behavior cannot reproduce on the Windows dev box).
</output>
