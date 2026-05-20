#!/usr/bin/env bash
# deploy/smoke_bootstrap.sh — Provision a fresh Rocky/Alma 9 host and run smoke_test.sh
#
# PURPOSE
#   Installs all system prerequisites on a RHEL 9-compatible host (Rocky Linux 9,
#   AlmaLinux 9, CentOS Stream 9, or RHEL 9) and then delegates to smoke_test.sh.
#   Designed for a THROWAWAY VirtualBox VM or disposable cloud instance.
#
# WARNING — THROWAWAY HOST ONLY
#   This script installs system packages and creates a service account.
#   Run it on a VM or cloud instance that you will destroy afterward.
#   Do NOT run on a production server or a shared dev machine.
#   PLACEHOLDER credentials only — never pass real TVM_ACCESS_KEY or SMTP_PASSWORD
#   through this script (D-04-08).
#
# USAGE (two options)
#
#   Option A — Run from inside a repo checkout on the VM (default):
#     git clone https://github.com/OWNER/REPO /srv/vuln-reporting
#     cd /srv/vuln-reporting
#     sudo bash deploy/smoke_bootstrap.sh [--clean]
#
#   Option B — Copy the two smoke scripts to a VM that doesn't have git:
#     scp deploy/smoke_bootstrap.sh deploy/smoke_test.sh user@vm:/tmp/
#     # On the VM as root:
#     # (smoke_bootstrap.sh needs access to the full repo for git archive;
#     #  if you only copied the scripts, use Option A instead.)
#     sudo SMOKE_ROOT=/tmp/vuln-smoke bash /tmp/smoke_bootstrap.sh --clean
#
#   All flags are forwarded to smoke_test.sh:
#     --clean   remove SMOKE_ROOT layout on exit (passed through to smoke_test.sh)
#
# DESTROYING THE VM AFTERWARD
#   VirtualBox:  VBoxManage unregistervm <name> --delete
#   AWS:         aws ec2 terminate-instances --instance-ids <id>
#   GCP:         gcloud compute instances delete <name>

set -euo pipefail
IFS=$'\n\t'

# Must run as root
if [[ $EUID -ne 0 ]]; then
  echo "error: smoke_bootstrap.sh must run as root" >&2
  exit 1
fi

echo "=== smoke_bootstrap: provisioning RHEL 9 prerequisites ==="
echo ""

# ---------------------------------------------------------------------------
# Step 1 — Python 3.11
# ---------------------------------------------------------------------------
# RHEL 9 ships Python 3.9 from the base repos. Python 3.11 is available in
# the AppStream module stream. This matches DEPLOYMENT.md "System Requirements".
# ---------------------------------------------------------------------------
echo "--- installing Python 3.11 ---"
dnf install -y python3.11 python3.11-pip python3.11-devel

# Make python3 and python3.11 available on PATH if not already linked
# (dnf installs /usr/bin/python3.11; smoke_test.sh calls 'python3 -m venv').
if ! command -v python3 &>/dev/null || [[ "$(python3 --version 2>&1)" != *"3.11"* ]]; then
  # Use alternatives to set python3 to 3.11, or create a fallback symlink.
  if command -v alternatives &>/dev/null; then
    alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 2>/dev/null || true
    alternatives --set python3 /usr/bin/python3.11 2>/dev/null || true
    echo "  set python3 -> python3.11 via alternatives"
  else
    ln -sf /usr/bin/python3.11 /usr/local/bin/python3 2>/dev/null || true
    echo "  symlinked /usr/local/bin/python3 -> python3.11"
  fi
fi
echo "  python3: $(python3 --version)"

# ---------------------------------------------------------------------------
# Step 2 — git (required for git archive in smoke_test.sh)
# ---------------------------------------------------------------------------
echo "--- installing git ---"
dnf install -y git

# ---------------------------------------------------------------------------
# Step 3 — WeasyPrint system packages (RHEL 9 / Fedora / CentOS Stream)
# ---------------------------------------------------------------------------
# Package list taken verbatim from DEPLOYMENT.md "System Requirements":
#   gcc libffi-devel openssl-devel cairo-devel pango-devel
# Without these, pip install weasyprint fails during venv provisioning (exit 8).
# ---------------------------------------------------------------------------
echo "--- installing WeasyPrint system dependencies ---"
dnf install -y gcc libffi-devel openssl-devel cairo-devel pango-devel

# ---------------------------------------------------------------------------
# Step 4 — SELinux: allow outbound HTTPS + SMTP for the service account
# ---------------------------------------------------------------------------
# From DEPLOYMENT.md "SELinux (RHEL 9)":
#   sudo setsebool -P httpd_can_network_connect on
# This is idempotent.  If SELinux is disabled (Permissive/disabled), the
# command still succeeds (returns 0) without doing anything harmful.
# ---------------------------------------------------------------------------
echo "--- configuring SELinux outbound-connect boolean ---"
if command -v setsebool &>/dev/null; then
  setsebool -P httpd_can_network_connect on && echo "  httpd_can_network_connect=on" \
    || echo "  WARNING: setsebool returned non-zero (SELinux may be disabled — this is OK for smoke testing)"
else
  echo "  setsebool not found — skipping (SELinux tooling not installed)"
fi

# ---------------------------------------------------------------------------
# Step 5 — Delegate to smoke_test.sh
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE_TEST="${SCRIPT_DIR}/smoke_test.sh"

if [[ ! -f "$SMOKE_TEST" ]]; then
  echo "error: smoke_test.sh not found at ${SMOKE_TEST}" >&2
  echo "       Ensure you are running smoke_bootstrap.sh from inside the repo checkout." >&2
  exit 1
fi

echo ""
echo "=== prerequisites installed; delegating to smoke_test.sh ==="
echo ""

# exec replaces this process so smoke_test.sh's exit code becomes our exit code.
exec bash "$SMOKE_TEST" "$@"
