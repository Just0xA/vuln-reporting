#!/usr/bin/env bash
# scripts/update_from_github.sh — Vuln Reporting Suite update / rollback helper
#
# Plans:
#   10-01  skeleton: --check, --list, safety guards, LOG-02 logging
#   10-02  --version vX.Y.Z install flow  (this plan)
#   10-03  --rollback, --force, --skip-restart, post-swap health check
#
# Exit codes:
#   0   success (or --check: already up-to-date)
#   1   --check: update available
#   2   usage error OR layout-guard failure
#   3   upstream GitHub API failure
#   4   release-asset download failure
#   5   SHA256 mismatch
#   6   tarball extraction failure
#   7   release dir already exists (without --force)
#   8   venv provisioning failure
#   9   post-extraction data/ dir missing
#   10  dry-run smoke test failed
#   11  atomic swap post-condition failed
#   (12–15 reserved for plan 10-03)

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INSTALL_ROOT="${INSTALL_ROOT:-/opt/vuln-reporting}"
LOG_FILE="${INSTALL_ROOT}/shared/logs/update.log"
SCRIPT_NAME="$(basename "$0")"

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
log_line() {
  # Write a timestamped line to $LOG_FILE.
  # Creates the logs/ directory if absent (shared/ is guaranteed by assert_layout,
  # but logs/ beneath it may not exist on a fresh install).
  # A write failure is surfaced to stderr but never propagates.
  local msg="$1"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    mkdir -p "$(dirname "$LOG_FILE")"
    printf '%s %s\n' "$ts" "$msg" >> "$LOG_FILE"
  } || {
    printf '%s: WARNING: could not write to %s\n' "$SCRIPT_NAME" "$LOG_FILE" >&2
  }
}

# Track whether log_completed has been called to prevent double-logging from
# the EXIT trap.
COMPLETED=0

log_started() {
  log_line "started at $(date -u +%Y-%m-%dT%H:%M:%SZ) with argv=${ORIG_ARGV}"
}

log_completed() {
  local status="$1"
  log_line "completed at $(date -u +%Y-%m-%dT%H:%M:%SZ) status=${status}"
  COMPLETED=1
}

# Trap-tracked globals for release-dir and tempdir cleanup (set by cmd_install).
# Initialized empty so the trap is a no-op when cmd_install hasn't run.
PARTIAL_RELEASE_DIR=""
TMPDIR_TO_CLEAN=""

# ---------------------------------------------------------------------------
# EXIT trap (UPDATE-09)
# Catches uncaught errors (set -e exits, unexpected signals, etc.).
# Does NOT double-log if log_completed was already called by a handler.
# Cleans up partial release dirs and tempdirs on pre-swap failures.
# ---------------------------------------------------------------------------
on_exit() {
  local rc="$1"

  # Remove a partial release dir only when the exit is a failure AND before the
  # atomic swap (after swap, PARTIAL_RELEASE_DIR is cleared so this branch is
  # inert — the now-active release dir is intentionally left alone).
  if [[ "$rc" -ne 0 && -n "$PARTIAL_RELEASE_DIR" && -d "$PARTIAL_RELEASE_DIR" ]]; then
    rm -rf "$PARTIAL_RELEASE_DIR" || true
    log_line "cleaned up partial release dir ${PARTIAL_RELEASE_DIR}"
  fi

  # Always clean up the download tempdir if it is still set.
  if [[ -n "$TMPDIR_TO_CLEAN" && -d "$TMPDIR_TO_CLEAN" ]]; then
    rm -rf "$TMPDIR_TO_CLEAN" || true
  fi

  if [[ "$COMPLETED" -eq 0 ]]; then
    log_line "completed at $(date -u +%Y-%m-%dT%H:%M:%SZ) status=failed: trap-on-exit (rc=${rc})"
  fi
}
trap 'on_exit $?' EXIT

# ---------------------------------------------------------------------------
# Usage / help
# --help is the ONE path that does NOT write to update.log; see LOG-02 note
# in plan 10-01.  Help should be usable on a host that is not yet installed.
# ---------------------------------------------------------------------------
print_usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [--check | --list | --version <TAG> | --rollback] [--force] [--skip-restart]

  Update and rollback helper for the Vulnerability Reporting Suite.
  Operates on the install layout at: ${INSTALL_ROOT}
  Logs every invocation to: ${LOG_FILE}

Flags:
  --check            Query GitHub for the latest release; print active vs latest
                     and exit 0 (up-to-date) or 1 (update available).
  --list             List all installed releases; mark the active one with * (active).
  --version <TAG>    Download and install release TAG (e.g. v1.2.0).
                     [not yet implemented — plan 10-02]
  --rollback         Roll back to the previous release recorded in .last.
                     [not yet implemented — plan 10-03]
  --force            (With --version) overwrite an already-installed release dir.
  --skip-restart     (With --version or --rollback) skip systemctl restart and
                     post-swap health check.
  --help, -h         Print this help and exit (no log entry written).

Examples:
  ${SCRIPT_NAME} --check
  ${SCRIPT_NAME} --list
  ${SCRIPT_NAME} --version v1.2.0

Log: ${LOG_FILE}
EOF
}

# ---------------------------------------------------------------------------
# Flag parser
# ---------------------------------------------------------------------------
parse_args() {
  CMD=""
  VERSION=""
  FORCE=0
  SKIP_RESTART=0

  if [[ $# -eq 0 ]]; then
    # No arguments — treat as usage error (handled in main after capture).
    return 0
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
        # Print help and exit 0 WITHOUT logging — this is the one exception.
        print_usage
        exit 0
        ;;
      --check)
        if [[ -n "$CMD" && "$CMD" != "check" ]]; then
          usage_error "conflicting command flags (--check cannot be combined with another command)"
        fi
        CMD="check"
        shift
        ;;
      --list)
        if [[ -n "$CMD" && "$CMD" != "list" ]]; then
          usage_error "conflicting command flags (--list cannot be combined with another command)"
        fi
        CMD="list"
        shift
        ;;
      --version)
        if [[ -n "$CMD" && "$CMD" != "install" ]]; then
          usage_error "conflicting command flags (--version cannot be combined with another command)"
        fi
        if [[ $# -lt 2 ]]; then
          usage_error "missing value after --version (expected a tag like v1.2.0)"
        fi
        local ver="$2"
        if ! [[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(rc|beta|alpha)[0-9.]*)?$ ]]; then
          usage_error "invalid version tag '${ver}' (expected format: v1.2.0 or v1.2.0-rc1)"
        fi
        CMD="install"
        VERSION="$ver"
        shift 2
        ;;
      --rollback)
        if [[ -n "$CMD" && "$CMD" != "rollback" ]]; then
          usage_error "conflicting command flags (--rollback cannot be combined with another command)"
        fi
        CMD="rollback"
        shift
        ;;
      --force)
        FORCE=1
        shift
        ;;
      --skip-restart)
        SKIP_RESTART=1
        shift
        ;;
      *)
        usage_error "unknown flag '$1' (try --help)"
        ;;
    esac
  done
}

# Call log_started + log_completed then exit 2 for usage errors.
# Note: ORIG_ARGV must be set before parse_args() for this to work correctly.
usage_error() {
  local reason="$1"
  printf 'error: %s\n' "$reason" >&2
  log_started
  log_completed "failed: ${reason}"
  exit 2
}

# ---------------------------------------------------------------------------
# Layout guard (UPDATE-10, T-10-01)
# Runs before env sourcing on all commands except --help.
# ---------------------------------------------------------------------------
assert_layout() {
  if [[ ! -d "$INSTALL_ROOT" ]]; then
    log_completed "failed: INSTALL_ROOT ${INSTALL_ROOT} does not exist"
    exit 2
  fi

  if [[ ! -L "${INSTALL_ROOT}/current" ]]; then
    log_completed "failed: ${INSTALL_ROOT}/current is missing or not a symlink (refuse-if-unknown-layout)"
    exit 2
  fi

  # Resolve the symlink target for prefix validation.
  # readlink (without -f) returns the raw link value, which may be absolute
  # (/opt/vuln-reporting/releases/vX/) or relative (releases/vX/).
  # Tolerate both by prepending INSTALL_ROOT/ when the target is not absolute.
  local target
  target="$(readlink "${INSTALL_ROOT}/current")"
  if [[ "$target" != /* ]]; then
    # Relative target — anchor it to INSTALL_ROOT.
    target="${INSTALL_ROOT}/${target}"
  fi

  if [[ "$target" != "${INSTALL_ROOT}/releases/"* ]]; then
    log_completed "failed: ${INSTALL_ROOT}/current points outside releases/ — refuse-if-unknown-layout"
    exit 2
  fi

  if [[ ! -d "${INSTALL_ROOT}/shared" ]]; then
    log_completed "failed: ${INSTALL_ROOT}/shared/ missing — refuse-if-unknown-layout"
    exit 2
  fi
}

# ---------------------------------------------------------------------------
# Env sourcing
# ---------------------------------------------------------------------------
source_env() {
  # shellcheck source=/dev/null
  . "${INSTALL_ROOT}/shared/.env"

  if [[ -z "${GITHUB_RELEASE_REPO:-}" ]]; then
    log_completed "failed: GITHUB_RELEASE_REPO not set in ${INSTALL_ROOT}/shared/.env"
    exit 2
  fi
  # GITHUB_TOKEN is optional; absence is not an error (just lower rate limits).
}

# ---------------------------------------------------------------------------
# GitHub API helper (UPDATE-12)
# Usage: gh_api_get /repos/owner/repo/releases/latest
# Emits response body to stdout; non-zero curl propagates via set -e.
# GITHUB_TOKEN is NEVER echoed to update.log (T-10-02 mitigated here).
# ---------------------------------------------------------------------------
gh_api_get() {
  local path="$1"
  local url="https://api.github.com${path}"
  local -a curl_args=(
    -fsSL
    --retry 2
    --retry-delay 2
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
  )
  # Conditionally add Authorization header only when GITHUB_TOKEN is set and
  # non-empty — avoids sending an empty bearer token (UPDATE-12).
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  curl "${curl_args[@]}" "$url"
}

# ---------------------------------------------------------------------------
# Release asset download (plan 10-02, UPDATE-02)
# ---------------------------------------------------------------------------

# download_release_assets VERSION TMPDIR
# Downloads the slim tarball and its .sha256 sidecar to TMPDIR.
# Uses the gh_api_get bearer-auth pattern — delegates to curl directly with the
# same conditional-header logic rather than going through gh_api_get (which
# targets api.github.com paths, not the release CDN).
download_release_assets() {
  local ver="$1"
  local tmpdir="$2"
  local base="vuln-reporting-${ver}-slim.tar.gz"
  local base_url="https://github.com/${GITHUB_RELEASE_REPO}/releases/download/${ver}"

  local -a curl_args=(
    -fsSL
    --retry 2
    --retry-delay 2
  )
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi

  log_line "downloading ${base} from ${base_url}"
  if ! curl "${curl_args[@]}" -o "${tmpdir}/${base}" "${base_url}/${base}"; then
    log_completed "failed: download of ${base_url}/${base} returned non-zero"
    exit 4
  fi

  log_line "downloading ${base}.sha256"
  if ! curl "${curl_args[@]}" -o "${tmpdir}/${base}.sha256" "${base_url}/${base}.sha256"; then
    log_completed "failed: download of ${base_url}/${base}.sha256 returned non-zero"
    exit 4
  fi
}

# verify_sha256 TMPDIR VERSION
# Verifies the downloaded tarball against the GNU-format sidecar.
# The cd is mandatory: the sidecar contains a bare filename (no path prefix),
# so sha256sum -c must run with the tarball in the working directory.
verify_sha256() {
  local tmpdir="$1"
  local ver="$2"
  local sidecar="vuln-reporting-${ver}-slim.tar.gz.sha256"

  log_line "verifying SHA256 for ${ver}"
  if ! (cd "$tmpdir" && sha256sum -c "$sidecar"); then
    log_completed "failed: SHA256 mismatch for ${ver}"
    exit 5
  fi
}

# extract_release TMPDIR VERSION TARGET_DIR
# Creates TARGET_DIR and extracts the tarball into it, stripping the top-level
# vuln-reporting-${VERSION}/ prefix that git archive inserts (Phase 9).
# Sets PARTIAL_RELEASE_DIR so the EXIT trap knows to clean up on failure.
extract_release() {
  local tmpdir="$1"
  local ver="$2"
  local target_dir="$3"
  local tarball="${tmpdir}/vuln-reporting-${ver}-slim.tar.gz"

  mkdir -p "$target_dir"
  # Record for the EXIT trap — cleared after atomic_swap succeeds.
  PARTIAL_RELEASE_DIR="$target_dir"

  log_line "extracting ${tarball} to ${target_dir}"
  if ! tar -xzf "$tarball" --strip-components=1 -C "$target_dir"; then
    log_completed "failed: extraction of ${tarball} into ${target_dir} failed"
    exit 6
  fi
}

# mktemp_cleanup TMPDIR
# Removes a tempdir; wrapped in || true so a cleanup failure does not mask
# the real exit code.
mktemp_cleanup() {
  local tmpdir="$1"
  rm -rf "$tmpdir" || true
}

# ---------------------------------------------------------------------------
# Venv provisioning (plan 10-02, UPDATE-13)
# ---------------------------------------------------------------------------

# provision_venv TARGET_DIR
# Creates a per-release venv and installs requirements.txt.
# Always runs in full — no skip-if-unchanged optimisation (UPDATE-13).
provision_venv() {
  local target_dir="$1"

  log_line "provisioning venv in ${target_dir}/.venv"
  if ! python3 -m venv "${target_dir}/.venv"; then
    log_completed "failed: venv provisioning for ${VERSION} (python3 -m venv returned non-zero)"
    exit 8
  fi
  if ! "${target_dir}/.venv/bin/pip" install --upgrade pip; then
    log_completed "failed: venv provisioning for ${VERSION} (pip upgrade returned non-zero)"
    exit 8
  fi
  if ! "${target_dir}/.venv/bin/pip" install -r "${target_dir}/requirements.txt"; then
    log_completed "failed: venv provisioning for ${VERSION} (pip install -r requirements.txt returned non-zero)"
    exit 8
  fi
}

# ---------------------------------------------------------------------------
# Shared-path symlinks (plan 10-02, UPDATE-14)
# ---------------------------------------------------------------------------

# symlink_shared TARGET_DIR
# Places the six shared-path symlinks inside the new release dir.
# Uses ln -sfn throughout: the -n flag prevents the "follow-then-nest" trap
# when the target is itself a symlink to a directory (re-extract with --force).
symlink_shared() {
  local target_dir="$1"

  # data/cache and data/trend are nested; assert data/ was extracted.
  if [[ ! -d "${target_dir}/data" ]]; then
    log_completed "failed: ${target_dir}/data/ missing; cannot place data/cache + data/trend symlinks"
    exit 9
  fi

  ln -sfn "${INSTALL_ROOT}/shared/.env"                 "${target_dir}/.env"
  ln -sfn "${INSTALL_ROOT}/shared/delivery_config.yaml" "${target_dir}/delivery_config.yaml"
  ln -sfn "${INSTALL_ROOT}/shared/logs"                 "${target_dir}/logs"
  ln -sfn "${INSTALL_ROOT}/shared/output"               "${target_dir}/output"
  ln -sfn "${INSTALL_ROOT}/shared/data/cache"           "${target_dir}/data/cache"
  ln -sfn "${INSTALL_ROOT}/shared/data/trend"           "${target_dir}/data/trend"

  log_line "shared-path symlinks placed in ${target_dir}"
}

# ---------------------------------------------------------------------------
# Smoke dry-run (plan 10-02, UPDATE-02)
# ---------------------------------------------------------------------------

# smoke_dry_run TARGET_DIR
# Runs run_all.py --dry-run inside the new release dir.
# Called AFTER PARTIAL_RELEASE_DIR is cleared so that a dry-run failure
# leaves the release dir intact for operator inspection (intentional: the
# operator needs to inspect a failing dir, so the trap must not delete it).
smoke_dry_run() {
  local target_dir="$1"

  log_line "running smoke dry-run in ${target_dir}"
  if ! (cd "$target_dir" && "${target_dir}/.venv/bin/python" run_all.py --dry-run); then
    log_completed "failed: dry-run smoke test failed for ${VERSION}; leaving ${target_dir} intact for inspection"
    exit 10
  fi
}

# ---------------------------------------------------------------------------
# Atomic swap + breadcrumb (plan 10-02, UPDATE-06, UPDATE-07)
# These helpers are CONTRACT for plan 10-03, which reuses them in
# cmd_rollback and auto_rollback.  Do not inline the logic.
# ---------------------------------------------------------------------------

# atomic_swap TARGET_DIR
# Atomically points ${INSTALL_ROOT}/current at TARGET_DIR via ln -sfn.
# rm + ln sequences on 'current' are FORBIDDEN (UPDATE-06).
atomic_swap() {
  local target_dir="$1"

  ln -sfn "$target_dir" "${INSTALL_ROOT}/current"

  # Post-condition check — ln -sfn is atomic on POSIX; a failure here indicates
  # a permissions or filesystem problem rather than a half-written symlink.
  if [[ "$(readlink "${INSTALL_ROOT}/current")" != "$target_dir" ]]; then
    log_completed "failed: atomic swap post-condition check failed for ${VERSION}"
    exit 11
  fi

  log_line "current swapped to ${target_dir}"
}

# write_breadcrumb PREV
# Atomically writes the previous release path to ${INSTALL_ROOT}/releases/.last.
# Temp-file + mv makes the write atomic across a crash mid-write (UPDATE-07 step 2).
write_breadcrumb() {
  local prev="$1"
  local last_tmp="${INSTALL_ROOT}/releases/.last.tmp"
  local last="${INSTALL_ROOT}/releases/.last"

  printf '%s\n' "$prev" > "$last_tmp"
  mv "$last_tmp" "$last"
  log_line "breadcrumb written: ${prev}"
}

# ---------------------------------------------------------------------------
# --check (UPDATE-01)
# ---------------------------------------------------------------------------
cmd_check() {
  local active latest api_response

  active="$(basename "$(readlink "${INSTALL_ROOT}/current")")"

  # Fetch latest release tag; portable JSON parse — no jq dependency.
  if ! api_response="$(gh_api_get "/repos/${GITHUB_RELEASE_REPO}/releases/latest" 2>&1)"; then
    log_completed "failed: could not fetch latest release tag from ${GITHUB_RELEASE_REPO}"
    exit 3
  fi

  if ! latest="$(printf '%s\n' "$api_response" | python3 -c 'import sys,json;print(json.load(sys.stdin)["tag_name"])' 2>/dev/null)"; then
    log_completed "failed: could not parse tag_name from GitHub API response for ${GITHUB_RELEASE_REPO}"
    exit 3
  fi

  printf 'active:  %s\n' "$active"
  printf 'latest:  %s\n' "$latest"

  if [[ "$active" == "$latest" ]]; then
    printf 'status: up-to-date\n'
    log_completed "success"
    exit 0
  else
    printf 'status: update available\n'
    log_completed "success"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# --list (UPDATE-04)
# ---------------------------------------------------------------------------
cmd_list() {
  local active releases_dir
  active="$(basename "$(readlink "${INSTALL_ROOT}/current")")"
  releases_dir="${INSTALL_ROOT}/releases"

  # Collect only directories (exclude .last breadcrumb file and other non-dirs).
  local -a entries=()
  if [[ -d "$releases_dir" ]]; then
    for d in "${releases_dir}"/*/; do
      # The glob expands to the literal pattern when the dir is empty; guard.
      [[ -d "$d" ]] || continue
      entries+=("$(basename "$d")")
    done
  fi

  if [[ ${#entries[@]} -eq 0 ]]; then
    printf '(no releases installed)\n'
    log_completed "success"
    exit 0
  fi

  # Sort by version (sort -V handles v1.10.0 > v1.2.0 correctly).
  local sorted
  sorted="$(printf '%s\n' "${entries[@]}" | sort -V)"

  while IFS= read -r name; do
    if [[ "$name" == "$active" ]]; then
      printf '%s * (active)\n' "$name"
    else
      printf '%s\n' "$name"
    fi
  done <<< "$sorted"

  log_completed "success"
}

# ---------------------------------------------------------------------------
# --version (plan 10-02)
# Full pipeline: download → SHA256 verify → extract → venv → symlinks →
# dry-run → breadcrumb-before → atomic swap → breadcrumb-after → restart.
# ---------------------------------------------------------------------------
cmd_install() {
  local TARGET_DIR="${INSTALL_ROOT}/releases/${VERSION}"

  # Set up download tempdir; EXIT trap will clean it unconditionally.
  TMPDIR_TO_CLEAN="$(mktemp -d)"

  # Refuse if target release dir already exists, unless FORCE is set.
  if [[ -d "$TARGET_DIR" && "${FORCE:-0}" != "1" ]]; then
    log_completed "failed: release dir ${TARGET_DIR} already exists (pass --force to overwrite)"
    printf 'error: release dir already exists; use --force to overwrite\n' >&2
    exit 7
  fi

  # FORCE + existing dir: remove before extraction so --strip-components=1 does
  # not merge into a dirty tree.
  if [[ -d "$TARGET_DIR" && "${FORCE:-0}" == "1" ]]; then
    log_line "FORCE: removing existing ${TARGET_DIR} before re-extraction"
    rm -rf "$TARGET_DIR"
  fi

  download_release_assets "$VERSION" "$TMPDIR_TO_CLEAN"
  verify_sha256 "$TMPDIR_TO_CLEAN" "$VERSION"
  extract_release "$TMPDIR_TO_CLEAN" "$VERSION" "$TARGET_DIR"
  # PARTIAL_RELEASE_DIR is now set to $TARGET_DIR; EXIT trap will rm -rf it on
  # any failure until atomic_swap() clears it below.

  provision_venv "$TARGET_DIR"
  symlink_shared "$TARGET_DIR"

  # Disarm partial-dir trap BEFORE the smoke test so that a dry-run failure
  # leaves the release dir intact for operator inspection.  The operator needs
  # to look at the dir; the trap must not destroy it on a smoke failure.
  PARTIAL_RELEASE_DIR=""
  smoke_dry_run "$TARGET_DIR"

  # Capture current symlink target BEFORE the swap (UPDATE-07 step 1).
  # Normalize to an absolute path so .last is always absolute — Plan 10-03's
  # cmd_rollback can feed it directly to ln -sfn without re-resolving.
  local PREV
  PREV="$(readlink "${INSTALL_ROOT}/current")"
  case "$PREV" in
    /*)  ;;                                        # already absolute
    *)   PREV="${INSTALL_ROOT}/releases/${PREV}";;  # bare basename → absolute
  esac

  atomic_swap "$TARGET_DIR"

  # Write breadcrumb AFTER swap succeeds (UPDATE-07 step 2).
  write_breadcrumb "$PREV"

  # -------------------------------------------------------------------------
  # Restart service (Plan 10-03 will wrap this block with the health-check
  # + auto-rollback; for now we invoke restart directly).
  # PARTIAL_RELEASE_DIR is already "" so a restart failure will NOT delete the
  # now-active release dir.
  # -------------------------------------------------------------------------
  if [[ "${SKIP_RESTART:-0}" != "1" ]]; then
    log_line "restarting vuln-reports.service"
    sudo systemctl restart vuln-reports.service
  else
    log_line "SKIP_RESTART=1: not restarting vuln-reports.service"
  fi

  # Clean up download tempdir on the happy path (the EXIT trap covers failures).
  mktemp_cleanup "$TMPDIR_TO_CLEAN"
  TMPDIR_TO_CLEAN=""

  log_completed "success"
}

# ---------------------------------------------------------------------------
# --rollback stub (plan 10-03 will replace this function body)
# ---------------------------------------------------------------------------
cmd_rollback() {
  printf 'error: --rollback flow not yet implemented (plan 10-03 will land it)\n' >&2
  log_completed "failed: cmd_rollback not implemented in plan 10-01"
  exit 3
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  # (a) Capture the original argv string immediately — BEFORE any processing.
  # Flag names are captured; env var values (like GITHUB_TOKEN) are never
  # echoed here, satisfying T-10-02.
  ORIG_ARGV="$*"

  # (b) Parse flags.  usage_error() (called inside parse_args for bad flags)
  # handles its own log_started/log_completed pair and exits 2 — so we only
  # reach the checks below on clean parses.
  parse_args "$@"

  # (c) No command flag given.
  if [[ -z "$CMD" ]]; then
    usage_error "no command flag given (try --help)"
  fi

  # Reject orthogonal-flag misuse: --force / --skip-restart without a real command.
  if [[ "$FORCE" -eq 1 && "$CMD" != "install" ]]; then
    usage_error "--force is only meaningful with --version"
  fi
  if [[ "$SKIP_RESTART" -eq 1 && "$CMD" != "install" && "$CMD" != "rollback" ]]; then
    usage_error "--skip-restart is only meaningful with --version or --rollback"
  fi

  # (d) --help was already handled inside parse_args (exits 0, no logging).

  # (e) Log that we've started.
  log_started

  # (f) Layout guard — runs before env sourcing for all real commands.
  assert_layout

  # (g) Source env and validate required vars.
  source_env

  # (h) Dispatch.
  case "$CMD" in
    check)    cmd_check    ;;
    list)     cmd_list     ;;
    install)  cmd_install  ;;
    rollback) cmd_rollback ;;
    *)
      log_completed "failed: internal error — unknown CMD '${CMD}'"
      exit 2
      ;;
  esac
}

main "$@"
