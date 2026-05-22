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
#   12  post-swap health check failed AND auto-rollback succeeded (investigate new release)
#   13  post-swap health check failed AND auto-rollback ALSO failed (critical; manual recovery)
#   14  --rollback: .last missing/empty/invalid (no rollback history; use --list + --version)
#   15  --rollback: atomic swap or systemctl restart failed

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INSTALL_ROOT="${INSTALL_ROOT:-/opt/vuln-reporting}"
LOG_FILE="${INSTALL_ROOT}/shared/logs/update.log"
SCRIPT_NAME="$(basename "$0")"

# Resolved at startup by resolve_python_bin(); used at every python3 call site.
PYTHON_BIN=""

# Recursion guard for auto_rollback — set to 1 on entry to auto_rollback so
# health_check short-circuits instead of triggering another rollback cycle
# (UPDATE-08, T-10-13: infinite-loop DoS mitigation).
IN_AUTO_ROLLBACK=0

# Default number of releases --prune and auto-prune keep.
RELEASE_RETENTION="${RELEASE_RETENTION:-3}"

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

# ---------------------------------------------------------------------------
# Python interpreter resolution (UPDATE-15)
# Sets PYTHON_BIN to the first python3 >= 3.10 found on PATH.
# Prefer bare python3 (distro-wired); fall back through versioned names in
# descending order.  On failure: log a clear message and exit 8.
# Must NOT use set +e regions — all probe failures are guarded with if/||.
# ---------------------------------------------------------------------------
resolve_python_bin() {
  local candidate version_ok

  # Prefer bare python3 if present and >= 3.10.
  if candidate="$(command -v python3 2>/dev/null)"; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PYTHON_BIN="$candidate"
      log_line "resolved python interpreter: ${PYTHON_BIN}"
      return 0
    fi
  fi

  # Fall back through versioned names in descending order.
  local name
  for name in python3.13 python3.12 python3.11 python3.10; do
    if candidate="$(command -v "$name" 2>/dev/null)"; then
      if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
        PYTHON_BIN="$candidate"
        log_line "resolved python interpreter: ${PYTHON_BIN}"
        return 0
      fi
    fi
  done

  log_completed "failed: no python3 >= 3.10 found on PATH; wire up python3 via 'alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1' or install python3.10+"
  exit 8
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
Usage: ${SCRIPT_NAME} [--check | --list | --version <TAG> | --rollback | --prune] [--force] [--skip-restart] [--keep <N>]

  Update and rollback helper for the Vulnerability Reporting Suite.
  Operates on the install layout at: ${INSTALL_ROOT}
  Logs every invocation to: ${LOG_FILE}

Flags:
  --check            Query GitHub for the latest release; print active vs latest
                     and exit 0 (up-to-date) or 1 (update available).
  --list             List all installed releases; mark the active one with * (active).
  --version <TAG>    Download and install release TAG (e.g. v1.2.0).
                     After install, performs a post-swap health check (10-second settle
                     then systemctl is-active). On failure, auto-rolls back to the
                     previous release and exits 12 (or 13 if rollback also fails).
                     Prints a Rollback one-liner to stdout on every successful upgrade.
  --rollback         Re-points current to whatever the script previously displaced
                     (read from \${INSTALL_ROOT}/releases/.last). Refuses with exit 14
                     if no breadcrumb exists — use --list and --version to recover by
                     hand. Does NOT run the post-swap health check (the rollback target
                     is by definition the previously-trusted release).
  --force            (Only meaningful with --version) overwrite an already-installed
                     release dir. Passing --force without --version is a usage error.
  --skip-restart     (With --version or --rollback) skip both the systemctl restart and
                     the post-swap health check; logs a WARNING line to update.log.
                     The next invocation still runs the health check normally.
  --prune            Delete old release dirs, keeping the ${RELEASE_RETENTION} most recent
                     (default). The active release and the rollback (.last) target are always
                     preserved. Successful --version installs auto-prune.
  --keep <N>         (Only with --prune) keep the N most recent releases instead of the
                     default. N must be a positive integer.
  --help, -h         Print this help and exit (no log entry written).

Notes:
  On every successful --version upgrade, the script prints a single Rollback: line
  to stdout showing exactly how to revert. You can also run --rollback at any time;
  the rollback target is whatever current pointed at before the most recent successful
  upgrade (forward or backward).

Examples:
  ${SCRIPT_NAME} --check
  ${SCRIPT_NAME} --list
  ${SCRIPT_NAME} --version v1.2.0
  ${SCRIPT_NAME} --rollback
  ${SCRIPT_NAME} --prune
  ${SCRIPT_NAME} --prune --keep 5

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
  KEEP=""

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
      --prune)
        if [[ -n "$CMD" && "$CMD" != "prune" ]]; then
          usage_error "conflicting command flags (--prune cannot be combined with another command)"
        fi
        CMD="prune"
        shift
        ;;
      --keep)
        if [[ $# -lt 2 ]]; then
          usage_error "missing value after --keep (expected a positive integer)"
        fi
        if ! [[ "$2" =~ ^[1-9][0-9]*$ ]]; then
          usage_error "invalid --keep value '$2' (expected a positive integer)"
        fi
        KEEP="$2"
        shift 2
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
  # Parse ONLY the keys this script needs from shared/.env. We deliberately do
  # NOT shell-source the file: systemd EnvironmentFile= tolerates unquoted
  # values containing spaces (e.g. SMTP_FROM_NAME=Vulnerability Management
  # Reports), but bash `.`/`source` parses such a line as `VAR=word command...`
  # and aborts under `set -e` ("command not found"). A safe KEY=VALUE reader
  # avoids any shell evaluation of the file contents.
  local env_file="${INSTALL_ROOT}/shared/.env"
  local line key value

  if [[ -f "$env_file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip blank lines and comments.
      [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
      # Require a KEY=VALUE shape; ignore anything else.
      [[ "$line" != *=* ]] && continue
      key="${line%%=*}"
      value="${line#*=}"
      # Trim surrounding whitespace from the key.
      key="${key#"${key%%[![:space:]]*}"}"
      key="${key%"${key##*[![:space:]]}"}"
      # Strip one layer of optional surrounding single or double quotes.
      if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
        value="${value:1:${#value}-2}"
      fi
      case "$key" in
        GITHUB_RELEASE_REPO) GITHUB_RELEASE_REPO="$value" ;;
        GITHUB_TOKEN)        GITHUB_TOKEN="$value" ;;
      esac
    done < "$env_file"
  fi

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
  if ! "$PYTHON_BIN" -m venv "${target_dir}/.venv"; then
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
# Release retention pruning (UPDATE-16)
# prune_releases <keep_n>
# Deletes old release dirs under ${INSTALL_ROOT}/releases/, keeping the
# keep_n most recent (by semver order).  The active release (current symlink
# target) and the .last rollback breadcrumb target are ALWAYS preserved even
# if they fall outside the keep-N window.  All deletions are best-effort and
# non-fatal; a prune failure must never abort an otherwise-successful install.
# ---------------------------------------------------------------------------
prune_releases() {
  local keep_n="$1"
  local releases_dir="${INSTALL_ROOT}/releases"

  # Resolve the active release basename.
  local active_abs active_base
  active_abs="$(readlink "${INSTALL_ROOT}/current" 2>/dev/null || true)"
  case "$active_abs" in
    /*) ;;
    *)  active_abs="${INSTALL_ROOT}/releases/${active_abs}" ;;
  esac
  active_base="$(basename "$active_abs")"

  # Resolve the .last rollback target basename (may not exist).
  local last_base=""
  local last_file="${releases_dir}/.last"
  if [[ -f "$last_file" ]]; then
    local last_raw
    last_raw="$(cat "$last_file" 2>/dev/null || true)"
    if [[ -n "$last_raw" ]]; then
      case "$last_raw" in
        /*) ;;
        *)  last_raw="${INSTALL_ROOT}/releases/${last_raw}" ;;
      esac
      last_base="$(basename "$last_raw")"
    fi
  fi

  # Enumerate release directories only (mirrors cmd_list — excludes .last file).
  local -a entries=()
  if [[ -d "$releases_dir" ]]; then
    for d in "${releases_dir}"/*/; do
      [[ -d "$d" ]] || continue
      entries+=("$(basename "$d")")
    done
  fi

  local total="${#entries[@]}"
  if [[ "$total" -le "$keep_n" ]]; then
    log_line "prune: ${total} release(s) <= keep ${keep_n}; nothing to remove"
    printf 'prune: %d release(s) present, keep=%d; nothing to remove\n' "$total" "$keep_n"
    return 0
  fi

  # Sort ascending by semver; the newest keep_n form the keep set.
  local sorted
  sorted="$(printf '%s\n' "${entries[@]}" | sort -V)"

  local -a all_sorted=()
  while IFS= read -r name; do
    all_sorted+=("$name")
  done <<< "$sorted"

  local num_sorted="${#all_sorted[@]}"
  local keep_start=$(( num_sorted - keep_n ))

  # Partition: candidates are the oldest entries (indices 0..keep_start-1).
  local -a kept_tags=() removed_tags=()

  local i
  for (( i = 0; i < num_sorted; i++ )); do
    local tag="${all_sorted[$i]}"

    if [[ "$i" -ge "$keep_start" ]]; then
      # Inside the keep window.
      kept_tags+=("$tag")
      continue
    fi

    # Outside the keep window — but always preserve active and rollback targets.
    if [[ "$tag" == "$active_base" ]]; then
      log_line "prune: preserving ${tag} (active release)"
      kept_tags+=("$tag")
      continue
    fi
    if [[ -n "$last_base" && "$tag" == "$last_base" ]]; then
      log_line "prune: preserving ${tag} (rollback target)"
      kept_tags+=("$tag")
      continue
    fi

    # Safety guard: path must be inside releases/ before any rm -rf.
    local abs_path="${releases_dir}/${tag}"
    case "$abs_path" in
      "${INSTALL_ROOT}/releases/"*) ;;
      *)
        log_line "WARNING: prune skipping ${abs_path} — path is outside ${INSTALL_ROOT}/releases/"
        kept_tags+=("$tag")
        continue
        ;;
    esac

    # Best-effort delete — a failure is logged and skipped, never fatal.
    if rm -rf "$abs_path" || { log_line "WARNING: prune failed to remove ${abs_path}"; false; }; then
      log_line "prune: removed ${abs_path}"
      removed_tags+=("$tag")
    else
      kept_tags+=("$tag")
    fi
  done

  # Join tag lists with spaces for the summary — the script's global
  # IFS=$'\n\t' would otherwise expand "${array[*]}" with newlines.
  local IFS=' '
  printf 'pruned: kept %d (%s), removed %d (%s)\n' \
    "${#kept_tags[@]}" "${kept_tags[*]:-none}" \
    "${#removed_tags[@]}" "${removed_tags[*]:-none}"

  return 0
}

# ---------------------------------------------------------------------------
# Post-swap health check (plan 10-03, UPDATE-08)
# ---------------------------------------------------------------------------

# health_check
# Returns 0 if the service is active, non-zero otherwise.
# Short-circuits to return 0 when called inside auto_rollback (IN_AUTO_ROLLBACK=1)
# to prevent infinite rollback recursion on a permanently-broken host (T-10-13).
health_check() {
  if [[ "${IN_AUTO_ROLLBACK:-0}" == "1" ]]; then
    # Recursion guard: trust that the rollback target is known-good; do not
    # trigger another rollback if the rollback's own restart also looks unhealthy.
    return 0
  fi
  sleep 10
  systemctl is-active --quiet vuln-reports.service
}

# auto_rollback PREV_TARGET
# Reuses atomic_swap + write_breadcrumb to swap back to PREV_TARGET, then
# restarts the service.  Never returns to its caller — always exits 12 or 13.
# PREV_TARGET must be an absolute path captured before the forward swap.
auto_rollback() {
  local prev="$1"
  IN_AUTO_ROLLBACK=1  # Recursion guard — health_check will short-circuit if called again.
  log_line "AUTO-ROLLBACK: health check failed; reverting current → $prev"

  if ! atomic_swap "$prev"; then
    log_completed "failed: post-swap health check failed AND auto-rollback swap failed (manual recovery required; current may be in an inconsistent state)"
    exit 13
  fi

  # Rewrite .last to the broken release dir so the operator can inspect or
  # manually re-attempt it later.  We deliberately do NOT abort if this fails —
  # the service recovery (restart below) is more important than the breadcrumb.
  write_breadcrumb "$TARGET_DIR"

  if ! sudo systemctl restart vuln-reports.service; then
    log_completed "failed: post-swap health check failed AND auto-rollback restart failed (service may be down; manual recovery required)"
    exit 13
  fi

  log_completed "failed: post-swap health check failed; auto-rolled-back to $prev (service restarted on previous release)"
  echo "warning: new release failed health check; auto-rolled-back to $prev" >&2
  echo "         the broken release dir is preserved at $TARGET_DIR for inspection" >&2
  exit 12
  # auto_rollback never returns to its caller — the exit above is reached on all paths.
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

  if ! latest="$(printf '%s\n' "$api_response" | "$PYTHON_BIN" -c 'import sys,json;print(json.load(sys.stdin)["tag_name"])')"; then
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
  # Restart, health check, and auto-rollback (plan 10-03, UPDATE-05, UPDATE-08).
  # PARTIAL_RELEASE_DIR is already "" so neither a restart failure nor a health
  # check failure will delete the now-active (or just-rolled-back) release dir.
  # -------------------------------------------------------------------------
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    log_line "WARNING: SKIP_RESTART=1 — skipping systemctl restart AND post-swap health check"
    echo "warning: --skip-restart was passed; service has NOT been restarted." >&2
    echo "         the next invocation of this script will run a health check normally." >&2
  else
    log_line "restarting vuln-reports.service"
    if ! sudo systemctl restart vuln-reports.service; then
      log_line "ERROR: systemctl restart returned non-zero; running auto-rollback"
      auto_rollback "$PREV"
      # auto_rollback never returns — exits 12 or 13.
    fi

    if ! health_check; then
      log_line "ERROR: post-swap health check failed (service not active after 10s settle); running auto-rollback"
      auto_rollback "$PREV"
      # auto_rollback never returns — exits 12 or 13.
    fi
  fi

  # Rollback one-liner (UPDATE-11) — printed on every successful upgrade so the
  # operator has a copy-paste-ready command immediately after the upgrade.
  # Uses ${INSTALL_ROOT}/current/ (the symlink) so it always points at the
  # just-installed version's script without needing to know the version tag.
  echo
  echo "Rollback: sudo ${INSTALL_ROOT}/current/scripts/update_from_github.sh --rollback"

  # Clean up download tempdir on the happy path (the EXIT trap covers failures).
  rm -rf "$TMPDIR_TO_CLEAN"
  TMPDIR_TO_CLEAN=""

  # Auto-prune old releases — best-effort, only on full success. Failure paths
  # exit via auto_rollback (exits 12/13) or earlier; they never reach this point.
  prune_releases "$RELEASE_RETENTION"

  log_completed "success"
}

# ---------------------------------------------------------------------------
# --rollback (plan 10-03, UPDATE-03)
# Reads .last breadcrumb, validates the target, swaps current back, rewrites
# .last, and restarts the service.  Deliberately does NOT run health_check —
# the rollback target is by definition a previously-trusted release; if it is
# also broken, the operator escalates by hand (exit 15 on restart failure).
# Reuses atomic_swap + write_breadcrumb from Plan 10-02 (same swap semantics).
# ---------------------------------------------------------------------------
cmd_rollback() {
  local last_file="${INSTALL_ROOT}/releases/.last"

  # UPDATE-03: refuse cleanly if no breadcrumb history exists.
  if [[ ! -f "$last_file" ]]; then
    log_completed "failed: $last_file does not exist (no rollback history — use --list and --version to recover by hand)"
    echo "error: no rollback history; nothing to roll back to" >&2
    echo "       run --list to see installed releases and --version vX.Y.Z to switch to one" >&2
    exit 14
  fi

  local target
  target="$(cat "$last_file" 2>/dev/null || true)"
  if [[ -z "$target" ]]; then
    log_completed "failed: $last_file is empty"
    echo "error: rollback breadcrumb is empty; nothing to roll back to" >&2
    exit 14
  fi

  # Promote a bare basename to an absolute path (readlink may produce either).
  case "$target" in
    /*) ;;
    *)  target="${INSTALL_ROOT}/releases/${target}" ;;
  esac

  if [[ ! -d "$target" ]]; then
    log_completed "failed: $last_file points to $target which does not exist"
    echo "error: rollback target $target no longer exists" >&2
    echo "       run --list to see available releases and --version vX.Y.Z to switch manually" >&2
    exit 14
  fi

  # T-10-12: sanity check — target must be inside releases/ to prevent a
  # tampered .last from pointing current at /etc/ or another sensitive path.
  case "$target" in
    "${INSTALL_ROOT}/releases/"*) ;;
    *)
      log_completed "failed: $last_file points to $target which is outside ${INSTALL_ROOT}/releases/"
      echo "error: rollback target outside expected releases/ directory; refusing" >&2
      exit 14
      ;;
  esac

  # Capture current symlink target BEFORE the swap so we can write it as the
  # new breadcrumb — enabling a "roll forward again" after this rollback.
  local prev_current
  prev_current="$(readlink "${INSTALL_ROOT}/current")"
  case "$prev_current" in
    /*) ;;
    *)  prev_current="${INSTALL_ROOT}/releases/${prev_current}" ;;
  esac

  log_line "rolling back: current → $target (displaced: $prev_current)"

  # Reuse Plan 10-02's atomic swap — same ln -sfn semantics, same post-condition check.
  if ! atomic_swap "$target"; then
    log_completed "failed: atomic swap to $target during --rollback"
    exit 15
  fi

  # Rewrite .last with the displaced target so "roll forward again" is possible
  # and audit trail is maintained (T-10-14 repudiation mitigation).
  write_breadcrumb "$prev_current"

  # Honor --skip-restart symmetrically with --version (staged maintenance windows).
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    log_line "WARNING: SKIP_RESTART=1 during --rollback — skipping systemctl restart"
    echo "warning: --skip-restart passed; service has NOT been restarted." >&2
  else
    if ! sudo systemctl restart vuln-reports.service; then
      log_completed "failed: systemctl restart after --rollback swap (current is now $target; service may be down)"
      exit 15
    fi
  fi

  echo "rolled back: current → $target"
  log_completed "success"
}

# ---------------------------------------------------------------------------
# --prune (UPDATE-16)
# ---------------------------------------------------------------------------
cmd_prune() {
  local keep_n="${KEEP:-$RELEASE_RETENTION}"
  log_line "prune requested (keep=${keep_n})"
  prune_releases "$keep_n"
  log_completed "success"
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
  if [[ -n "$KEEP" && "$CMD" != "prune" ]]; then
    usage_error "--keep is only meaningful with --prune"
  fi

  # (d) --help was already handled inside parse_args (exits 0, no logging).

  # (e) Log that we've started.
  log_started

  # (f) Layout guard — runs before env sourcing for all real commands.
  assert_layout

  # (f2) Resolve the Python interpreter once; both venv and cmd_check use it.
  resolve_python_bin

  # (g) Source env and validate required vars.
  source_env

  # (h) Dispatch.
  case "$CMD" in
    check)    cmd_check    ;;
    list)     cmd_list     ;;
    install)  cmd_install  ;;
    rollback) cmd_rollback ;;
    prune)    cmd_prune    ;;
    *)
      log_completed "failed: internal error — unknown CMD '${CMD}'"
      exit 2
      ;;
  esac
}

main "$@"
