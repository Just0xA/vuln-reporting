#!/usr/bin/env bash
# scripts/update_from_github.sh — Vuln Reporting Suite update / rollback helper
#
# Plans:
#   10-01  skeleton: --check, --list, safety guards, LOG-02 logging  (this plan)
#   10-02  --version vX.Y.Z install flow
#   10-03  --rollback, --force, --skip-restart, post-swap health check
#
# Exit codes (10-01 owns 0–3; see SUMMARY.md for full table):
#   0  success (or --check: already up-to-date)
#   1  --check: update available
#   2  usage error OR layout-guard failure
#   3  upstream GitHub API failure OR stubbed-not-yet-implemented command

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

# ---------------------------------------------------------------------------
# EXIT trap (UPDATE-09)
# Catches uncaught errors (set -e exits, unexpected signals, etc.).
# Does NOT double-log if log_completed was already called by a handler.
# Plan 10-02 will extend this trap with release-dir cleanup.
# ---------------------------------------------------------------------------
on_exit() {
  local rc="$1"
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
# --version stub (plan 10-02 will replace this function body)
# ---------------------------------------------------------------------------
cmd_install() {
  printf 'error: --version flow not yet implemented (plan 10-02 will land it)\n' >&2
  log_completed "failed: cmd_install not implemented in plan 10-01"
  exit 3
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
