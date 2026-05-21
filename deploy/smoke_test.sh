#!/usr/bin/env bash
# deploy/smoke_test.sh — Network-free systemd/layout smoke test
#
# PURPOSE
#   Validates the systemd unit + install layout + ReadWritePaths sandbox mechanics
#   (the B-01 class of bug: sandbox silently not enforcing write restrictions).
#   Creates a full fake two-release layout from the current repo checkout using
#   `git archive`, installs the unit, and runs five structured checks.
#
# WHAT IS NOT COVERED HERE (requires a real published release + network)
#   - The --version DOWNLOAD path (download, SHA256 verify, extraction from GitHub CDN)
#     needs a real published release.  Push v0.0.0-alpha1 per Phase 9 and run:
#       INSTALL_ROOT=/tmp/smoke-net bash deploy/smoke_bootstrap.sh
#     (or run update_from_github.sh --check against a real GITHUB_RELEASE_REPO with
#     network access).
#   - A real report render (matplotlib/WeasyPrint writing into runtime-cache under
#     ProtectSystem=strict). CHECK 1's trivial json.dump exercises the sandbox path
#     enforcement but not the library cache writes — confirm those on a real VM run.
#
# PLACEHOLDER CREDENTIALS (D-04-08)
#   shared/.env is populated with PLACEHOLDER values only — never real credentials.
#   Passing real TVM_ACCESS_KEY/TVM_SECRET_KEY/SMTP_PASSWORD values here would
#   violate D-04-08 (no credentials in committed or ephemeral smoke files).
#
# USAGE
#   sudo bash deploy/smoke_test.sh [--clean]
#   --clean : rm -rf the SMOKE_ROOT layout on EXIT in addition to the unit cleanup.
#             Without --clean the layout is left for post-failure inspection.
#
# ENVIRONMENT
#   SMOKE_ROOT  Override install base (default /opt/vuln-reporting).
#               Must not exist or must be the layout from a prior smoke run.

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "error: smoke_test.sh must run as root (it installs a systemd unit and starts services)" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
CLEAN=0
for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=1 ;;
    *) echo "error: unknown flag '$arg' (supported: --clean)" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SMOKE_ROOT="${SMOKE_ROOT:-/opt/vuln-reporting}"
# Repo root is the parent of the directory that contains this script.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DEST="/etc/systemd/system/vuln-reports.service"

REL1="v0.0.0-smoke1"
REL2="v0.0.0-smoke2"
DIR1="${SMOKE_ROOT}/releases/${REL1}"
DIR2="${SMOKE_ROOT}/releases/${REL2}"

# ---------------------------------------------------------------------------
# Test-result tracking
# ---------------------------------------------------------------------------
declare -a RESULTS=()   # "PASS|FAIL|SKIP: <label>"
OVERALL=0               # non-zero if any real check fails

record() {
  local verdict="$1"  # PASS / FAIL / SKIP
  local label="$2"
  RESULTS+=("${verdict}: ${label}")
  if [[ "$verdict" == "FAIL" ]]; then
    OVERALL=1
  fi
}

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
  echo ""
  echo "=== cleanup ==="

  # Stop and reset the transient/installed service if it was ever started
  systemctl stop vuln-reports.service 2>/dev/null || true
  systemctl reset-failed vuln-reports.service 2>/dev/null || true

  # Remove the installed unit if we placed it
  if [[ -f "$UNIT_DEST" ]]; then
    rm -f "$UNIT_DEST"
    systemctl daemon-reload 2>/dev/null || true
    echo "  removed ${UNIT_DEST} and reloaded daemon"
  fi

  if [[ "$CLEAN" -eq 1 ]]; then
    if [[ -d "$SMOKE_ROOT" ]]; then
      rm -rf "$SMOKE_ROOT"
      echo "  --clean: removed ${SMOKE_ROOT}"
    fi
  else
    echo "  layout preserved at ${SMOKE_ROOT} (pass --clean to remove)"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1 — Build install layout
# ---------------------------------------------------------------------------
echo "=== building smoke layout under ${SMOKE_ROOT} ==="

mkdir -p \
  "${SMOKE_ROOT}/releases" \
  "${SMOKE_ROOT}/shared/logs" \
  "${SMOKE_ROOT}/shared/output" \
  "${SMOKE_ROOT}/shared/data/cache" \
  "${SMOKE_ROOT}/shared/data/trend" \
  "${SMOKE_ROOT}/shared/data/runtime-cache"

# Write shared/.env with PLACEHOLDER values only (D-04-08 — no real creds).
cat > "${SMOKE_ROOT}/shared/.env" <<'ENVEOF'
# SMOKE TEST PLACEHOLDER CREDENTIALS — NOT REAL (D-04-08)
TVM_ACCESS_KEY=PLACEHOLDER_ACCESS_KEY
TVM_SECRET_KEY=PLACEHOLDER_SECRET_KEY
TVM_URL=https://cloud.tenable.com
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=smoke@example.invalid
SMTP_PASSWORD=PLACEHOLDER_SMTP_PASSWORD
SMTP_FROM_ADDRESS=smoke@example.invalid
SMTP_FROM_NAME=Smoke Test
GITHUB_RELEASE_REPO=owner/repo
ENVEOF
chmod 600 "${SMOKE_ROOT}/shared/.env"

# Write a minimal delivery_config.yaml so run_all.py --dry-run (used by
# update_from_github.sh smoke_dry_run) doesn't fail on a missing config.
cat > "${SMOKE_ROOT}/shared/delivery_config.yaml" <<'YAMLEOF'
# Smoke test placeholder — minimal valid config
groups:
  - name: "Smoke Group"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - vuln_export
    email:
      subject: "Smoke"
      recipients: [smoke@example.invalid]
      cc: []
YAMLEOF

# ---------------------------------------------------------------------------
# Step 2 — Fake two releases from git archive (network-free)
# ---------------------------------------------------------------------------
echo "=== creating fake releases from git archive ==="

for rel in "$REL1" "$REL2"; do
  rel_dir="${SMOKE_ROOT}/releases/${rel}"
  mkdir -p "$rel_dir"

  echo "  extracting ${rel} ..."
  git -C "$REPO" archive --format=tar.gz --prefix=ignored/ HEAD \
    | tar -xz --strip-components=1 -C "$rel_dir"

  # Create the data/ subdirectory that symlink_shared expects to exist.
  mkdir -p "${rel_dir}/data"

  # --- Provision venv (required so the ExecStart binary exists) ---
  echo "  provisioning venv for ${rel} ..."
  python3 -m venv "${rel_dir}/.venv"
  "${rel_dir}/.venv/bin/pip" install --upgrade pip --quiet
  "${rel_dir}/.venv/bin/pip" install -r "${rel_dir}/requirements.txt" --quiet

  # --- Place shared-path symlinks (mirrors symlink_shared in update_from_github.sh) ---
  ln -sfn "${SMOKE_ROOT}/shared/.env"                 "${rel_dir}/.env"
  ln -sfn "${SMOKE_ROOT}/shared/delivery_config.yaml" "${rel_dir}/delivery_config.yaml"
  ln -sfn "${SMOKE_ROOT}/shared/logs"                 "${rel_dir}/logs"
  ln -sfn "${SMOKE_ROOT}/shared/output"               "${rel_dir}/output"
  ln -sfn "${SMOKE_ROOT}/shared/data/cache"           "${rel_dir}/data/cache"
  ln -sfn "${SMOKE_ROOT}/shared/data/trend"           "${rel_dir}/data/trend"

  echo "  ${rel} ready"
done

# ---------------------------------------------------------------------------
# Step 3 — Service account
# ---------------------------------------------------------------------------
echo "=== ensuring vuln-reports user/group ==="

if ! getent group vuln-reports > /dev/null 2>&1; then
  groupadd vuln-reports
  echo "  created group vuln-reports"
fi
if ! id -u vuln-reports > /dev/null 2>&1; then
  useradd -r -g vuln-reports -s /sbin/nologin -M vuln-reports
  echo "  created user vuln-reports"
fi

chown -R vuln-reports:vuln-reports "${SMOKE_ROOT}"
chmod -R 750 "${SMOKE_ROOT}"
# .env must be 600 — restore after chmod -R
chmod 600 "${SMOKE_ROOT}/shared/.env"

# ---------------------------------------------------------------------------
# Step 4 — Point current at smoke1, write .last breadcrumb for smoke1
# ---------------------------------------------------------------------------
echo "=== setting up symlinks and breadcrumb ==="

ln -sfn "$DIR1" "${SMOKE_ROOT}/current"
# .last will be written to point at smoke1 after we swap to smoke2 in check 4.
# For now write it as smoke1 so the rollback test (check 4) can use it.
printf '%s\n' "$DIR1" > "${SMOKE_ROOT}/releases/.last"

# ---------------------------------------------------------------------------
# Step 5 — Install systemd unit
# ---------------------------------------------------------------------------
echo "=== installing systemd unit ==="

cp "${REPO}/deploy/vuln-reports.service" "$UNIT_DEST"

# If SMOKE_ROOT differs from the default, rewrite all hard-coded paths
# (mirrors the documented relocation sed recipe).
if [[ "$SMOKE_ROOT" != "/opt/vuln-reporting" ]]; then
  sed -i "s#/opt/vuln-reporting#${SMOKE_ROOT}#g" "$UNIT_DEST"
  echo "  patched unit paths: /opt/vuln-reporting -> ${SMOKE_ROOT}"
fi

systemctl daemon-reload
echo "  unit installed and daemon reloaded"

# ===========================================================================
# CHECKS
# ===========================================================================
echo ""
echo "=== running checks ==="
echo ""

# ---------------------------------------------------------------------------
# CHECK 1 — POSITIVE: B-01 trend write under the real sandbox
# ---------------------------------------------------------------------------
# Use systemd-run with the SAME identity and hardening as the live unit.
# ReadWritePaths and ProtectSystem=strict match the real unit exactly
# (output, logs, data/cache, data/trend, data/runtime-cache). The HOME/
# XDG_CACHE_HOME/MPLCONFIGDIR Environment lines mirror the unit so that the
# positive control behaves like a real render (library cache writes land in
# runtime-cache). Asserts that data/trend IS writable.
#
# The python one-liner mirrors management_summary's actual write pattern:
#   TREND_DIR.mkdir(parents=True, exist_ok=True)
#   json.dump(data, open(trend_file, "w"))
# ---------------------------------------------------------------------------
TREND_SENTINEL="${SMOKE_ROOT}/shared/data/trend/smoke_check1.json"
rm -f "$TREND_SENTINEL"

CHECK1_LABEL="POSITIVE — trend write under real ReadWritePaths sandbox"

if systemd-run \
    --wait \
    --pipe \
    --uid=vuln-reports \
    --property="ReadWritePaths=${SMOKE_ROOT}/shared/output ${SMOKE_ROOT}/shared/logs ${SMOKE_ROOT}/shared/data/cache ${SMOKE_ROOT}/shared/data/trend ${SMOKE_ROOT}/shared/data/runtime-cache" \
    --property="NoNewPrivileges=yes" \
    --property="PrivateTmp=yes" \
    --property="ProtectSystem=strict" \
    --property="Environment=HOME=${SMOKE_ROOT}/shared/data/runtime-cache" \
    --property="Environment=XDG_CACHE_HOME=${SMOKE_ROOT}/shared/data/runtime-cache" \
    --property="Environment=MPLCONFIGDIR=${SMOKE_ROOT}/shared/data/runtime-cache/matplotlib" \
    --property="WorkingDirectory=${SMOKE_ROOT}/current" \
    python3 -c "
import json, os
d = '${SMOKE_ROOT}/shared/data/trend'
os.makedirs(d, exist_ok=True)
json.dump({'smoke': 1}, open(os.path.join(d, 'smoke_check1.json'), 'w'))
" 2>/dev/null; then
  if [[ -f "$TREND_SENTINEL" ]]; then
    record PASS "$CHECK1_LABEL"
    echo "  CHECK 1 PASS: file created at ${TREND_SENTINEL}"
  else
    record FAIL "$CHECK1_LABEL"
    echo "  CHECK 1 FAIL: systemd-run exited 0 but file was NOT created"
  fi
else
  record FAIL "$CHECK1_LABEL"
  echo "  CHECK 1 FAIL: systemd-run exited non-zero — write was blocked (sandbox too strict?)"
fi

# ---------------------------------------------------------------------------
# CHECK 2 — NEGATIVE control: sandbox WITH data/trend REMOVED from RWP
# ---------------------------------------------------------------------------
# If this check UNEXPECTEDLY PASSES (file created), the sandbox is not
# enforcing. That makes check 1's PASS meaningless, and the entire smoke
# is worthless. Treat an unexpected pass as a hard FAIL.
#
# IMPORTANT: this control keeps runtime-cache in ReadWritePaths and supplies
# the same HOME/XDG_CACHE_HOME/MPLCONFIGDIR Environment as the real unit, so
# the ONLY thing being denied is the data/trend write. If we omitted those,
# a failure could be misattributed to a cache-dir denial rather than the
# data/trend path being absent from RWP.
# ---------------------------------------------------------------------------
TREND_SENTINEL2="${SMOKE_ROOT}/shared/data/trend/smoke_check2.json"
rm -f "$TREND_SENTINEL2"

CHECK2_LABEL="NEGATIVE control — sandbox without data/trend in ReadWritePaths"

# Intentionally omit data/trend from ReadWritePaths (runtime-cache stays in).
SANDBOX_EXIT=0
systemd-run \
    --wait \
    --pipe \
    --uid=vuln-reports \
    --property="ReadWritePaths=${SMOKE_ROOT}/shared/output ${SMOKE_ROOT}/shared/logs ${SMOKE_ROOT}/shared/data/cache ${SMOKE_ROOT}/shared/data/runtime-cache" \
    --property="NoNewPrivileges=yes" \
    --property="PrivateTmp=yes" \
    --property="ProtectSystem=strict" \
    --property="Environment=HOME=${SMOKE_ROOT}/shared/data/runtime-cache" \
    --property="Environment=XDG_CACHE_HOME=${SMOKE_ROOT}/shared/data/runtime-cache" \
    --property="Environment=MPLCONFIGDIR=${SMOKE_ROOT}/shared/data/runtime-cache/matplotlib" \
    --property="WorkingDirectory=${SMOKE_ROOT}/current" \
    python3 -c "
import json, os
d = '${SMOKE_ROOT}/shared/data/trend'
os.makedirs(d, exist_ok=True)
json.dump({'smoke': 2}, open(os.path.join(d, 'smoke_check2.json'), 'w'))
" 2>/dev/null || SANDBOX_EXIT=$?

if [[ "$SANDBOX_EXIT" -ne 0 ]] && [[ ! -f "$TREND_SENTINEL2" ]]; then
  record PASS "$CHECK2_LABEL"
  echo "  CHECK 2 PASS: write correctly blocked (exit ${SANDBOX_EXIT}, file absent) — sandbox is enforcing"
elif [[ -f "$TREND_SENTINEL2" ]]; then
  # Unexpected success — sandbox is NOT enforcing.  Check 1's PASS is meaningless.
  record FAIL "$CHECK2_LABEL"
  echo "  CHECK 2 FAIL: *** SANDBOX IS NOT ENFORCING ***"
  echo "               Write SUCCEEDED even without data/trend in ReadWritePaths."
  echo "               Check 1's PASS is meaningless — ReadWritePaths is not restricting writes."
  echo "               This host's systemd may not support ProtectSystem=strict or ReadWritePaths."
  OVERALL=1
elif [[ "$SANDBOX_EXIT" -ne 0 ]] && [[ -f "$TREND_SENTINEL2" ]]; then
  record FAIL "$CHECK2_LABEL"
  echo "  CHECK 2 FAIL: exit non-zero but file EXISTS — indeterminate sandbox state"
else
  record FAIL "$CHECK2_LABEL"
  echo "  CHECK 2 FAIL: unexpected state (exit=${SANDBOX_EXIT}, file_exists=$(test -f "$TREND_SENTINEL2" && echo yes || echo no))"
fi

# ---------------------------------------------------------------------------
# CHECK 3 — --list shows both releases, marks smoke1 as active
# ---------------------------------------------------------------------------
CHECK3_LABEL="--list shows both releases with active marker"

LIST_OUT="$(INSTALL_ROOT="${SMOKE_ROOT}" bash "${REPO}/scripts/update_from_github.sh" --list 2>/dev/null || true)"

FOUND_REL1=0
FOUND_REL2=0
FOUND_ACTIVE=0

while IFS= read -r line; do
  if echo "$line" | grep -q "^${REL1}"; then
    FOUND_REL1=1
  fi
  if echo "$line" | grep -q "^${REL2}"; then
    FOUND_REL2=1
  fi
  # The script prints the active one as: "<name> * (active)"
  if echo "$line" | grep -q "${REL1}.*\* (active)"; then
    FOUND_ACTIVE=1
  fi
done <<< "$LIST_OUT"

if [[ "$FOUND_REL1" -eq 1 && "$FOUND_REL2" -eq 1 && "$FOUND_ACTIVE" -eq 1 ]]; then
  record PASS "$CHECK3_LABEL"
  echo "  CHECK 3 PASS: both releases listed; ${REL1} marked * (active)"
else
  record FAIL "$CHECK3_LABEL"
  echo "  CHECK 3 FAIL: list output was:"
  echo "$LIST_OUT" | sed 's/^/    /'
  if [[ "$FOUND_REL1" -eq 0 ]]; then echo "    missing: ${REL1}"; fi
  if [[ "$FOUND_REL2" -eq 0 ]]; then echo "    missing: ${REL2}"; fi
  if [[ "$FOUND_ACTIVE" -eq 0 ]]; then echo "    active marker not found for ${REL1}"; fi
fi

# ---------------------------------------------------------------------------
# CHECK 4 — --rollback mechanics
# ---------------------------------------------------------------------------
# Setup: point current at smoke2, write .last -> smoke1.
# Run: --rollback --skip-restart (avoids needing sudoers for the transient smoke)
# Assert: current -> smoke1, .last rewritten to smoke2.
# ---------------------------------------------------------------------------
CHECK4_LABEL="--rollback swaps current back and rewrites .last"

echo "  setting up for rollback test: current -> smoke2, .last -> smoke1"
ln -sfn "$DIR2" "${SMOKE_ROOT}/current"
printf '%s\n' "$DIR1" > "${SMOKE_ROOT}/releases/.last"

ROLLBACK_EXIT=0
ROLLBACK_OUT="$(INSTALL_ROOT="${SMOKE_ROOT}" bash "${REPO}/scripts/update_from_github.sh" --rollback --skip-restart 2>&1)" || ROLLBACK_EXIT=$?

CURRENT_AFTER="$(readlink "${SMOKE_ROOT}/current" 2>/dev/null || echo "(missing)")"
LAST_AFTER="$(cat "${SMOKE_ROOT}/releases/.last" 2>/dev/null || echo "(missing)")"

# Normalize to absolute for comparison (update_from_github.sh promotes relative
# targets to absolute when writing breadcrumbs, matching our setup).
if [[ "$ROLLBACK_EXIT" -eq 0 ]] \
   && [[ "$CURRENT_AFTER" == "$DIR1" ]] \
   && [[ "$LAST_AFTER" == "$DIR2" ]]; then
  record PASS "$CHECK4_LABEL"
  echo "  CHECK 4 PASS: current -> ${REL1}, .last -> ${REL2}"
else
  record FAIL "$CHECK4_LABEL"
  echo "  CHECK 4 FAIL:"
  echo "    --rollback exit code: ${ROLLBACK_EXIT}"
  echo "    current after:        ${CURRENT_AFTER} (expected ${DIR1})"
  echo "    .last after:          ${LAST_AFTER} (expected ${DIR2})"
  if [[ -n "$ROLLBACK_OUT" ]]; then
    echo "    output:"
    echo "$ROLLBACK_OUT" | sed 's/^/      /'
  fi
fi

# Restore current to smoke1 for check 5
ln -sfn "$DIR1" "${SMOKE_ROOT}/current"

# ---------------------------------------------------------------------------
# CHECK 5 — Auto-rollback signal (tolerant: SKIP if systemd-run transient
#           unit support is unavailable or PrivateTmp is unsupported)
# ---------------------------------------------------------------------------
CHECK5_LABEL="Auto-rollback signal: broken release is not active after start"

# Break smoke2's venv so ExecStart fails
BROKEN_PYTHON="${DIR2}/.venv/bin/python"
if [[ -f "$BROKEN_PYTHON" ]]; then
  rm -f "$BROKEN_PYTHON"
  echo "  broke ${BROKEN_PYTHON} for check 5"
fi

# Point current at the broken release
ln -sfn "$DIR2" "${SMOKE_ROOT}/current"

# Try to start the service via systemctl (unit is installed).
# The service may fail immediately (ExecStart binary missing).
# We use start + brief sleep + is-active to confirm it is NOT running.
# If systemctl start itself is not usable (no D-Bus, container, etc.), SKIP.
DBUS_OK=0
if systemctl list-units --no-legend > /dev/null 2>&1; then
  DBUS_OK=1
fi

if [[ "$DBUS_OK" -eq 0 ]]; then
  record SKIP "$CHECK5_LABEL"
  echo "  CHECK 5 SKIP: D-Bus/systemctl not functional in this environment (container/minimal host)"
else
  # Start the service; it is expected to fail quickly because .venv/bin/python is gone.
  systemctl start vuln-reports.service 2>/dev/null || true
  sleep 3

  SVC_STATE="$(systemctl is-active vuln-reports.service 2>/dev/null || echo "unknown")"

  if [[ "$SVC_STATE" != "active" ]]; then
    record PASS "$CHECK5_LABEL"
    echo "  CHECK 5 PASS: service state is '${SVC_STATE}' (not active) after starting broken release"
    echo "               the real updater's post-swap health check would see this and auto-roll-back (exit 12)"
  else
    record FAIL "$CHECK5_LABEL"
    echo "  CHECK 5 FAIL: service is 'active' with a broken venv (broken ExecStart not detected)"
  fi

  # Clean up the failed service state
  systemctl stop vuln-reports.service 2>/dev/null || true
  systemctl reset-failed vuln-reports.service 2>/dev/null || true
fi

# Restore current to smoke1 after check 5
ln -sfn "$DIR1" "${SMOKE_ROOT}/current"

# ===========================================================================
# Results table
# ===========================================================================
echo ""
echo "=== results ==="
echo ""
printf "%-8s %s\n" "VERDICT" "CHECK"
printf "%-8s %s\n" "-------" "-----"
for r in "${RESULTS[@]}"; do
  verdict="${r%%:*}"
  label="${r#*: }"
  printf "%-8s %s\n" "$verdict" "$label"
done
echo ""

if [[ "$OVERALL" -eq 0 ]]; then
  echo "ALL CHECKS PASSED (or skipped)"
else
  echo "ONE OR MORE CHECKS FAILED — see details above"
fi
echo ""

exit "$OVERALL"
