---
phase: quick-260522-mf3
plan: "01"
subsystem: scripts/updater
tags: [python-resolution, update-script, deployment, hardening]
dependency_graph:
  requires: []
  provides: [UPDATE-PY-RESOLVE]
  affects: [scripts/update_from_github.sh, DEPLOYMENT.md]
tech_stack:
  added: []
  patterns: [bash-set-euo-pipefail, command-v-probe, alternatives-install]
key_files:
  created: []
  modified:
    - scripts/update_from_github.sh
    - DEPLOYMENT.md
decisions:
  - "Prefer bare python3 first (distro-wired path); fall through versioned names descending"
  - "All interpreter probes use command -v + version check guarded with if/|| — no set +e regions"
  - "resolve_python_bin called in main() after assert_layout so LOG_FILE is writable before any log_line"
  - "Removed 2>/dev/null from cmd_check tag parse so interpreter/JSON errors surface in update.log"
metrics:
  duration: "12 minutes"
  completed: "2026-05-22"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 2
---

# Phase quick-260522-mf3 Plan 01: Harden update_from_github.sh Python Resolution Summary

**One-liner:** Added `resolve_python_bin()` to resolve a single `PYTHON_BIN` (>= 3.10) at startup — preferring bare `python3`, falling through `python3.13/3.12/3.11/3.10` — and wired it at both call sites; removed the `2>/dev/null` error swallow from `cmd_check`.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add resolve_python_bin and wire both call sites | 63938d1 | scripts/update_from_github.sh |
| 2 | Document python3 >= 3.10 prerequisite in DEPLOYMENT.md | b3ab105 | DEPLOYMENT.md |

---

## What Changed

### Task 1 — `scripts/update_from_github.sh`

**Constants block:** Added `PYTHON_BIN=""` declaration with a comment that it is resolved at startup.

**New function `resolve_python_bin()`** (placed before the EXIT trap section, after the Logger block):
- Probes bare `python3` first via `command -v`; if present, version-checks it with `"$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'`.
- On bare `python3` miss, iterates `python3.13 python3.12 python3.11 python3.10` in a `for` loop; picks the first that resolves AND passes the version check.
- On success: sets `PYTHON_BIN="$candidate"` and logs `resolved python interpreter: ${PYTHON_BIN}`.
- On failure: `log_completed "failed: no python3 >= 3.10 found on PATH; wire up python3 via 'alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1' or install python3.10+"` then `exit 8`.
- All probes use `if ... 2>/dev/null` guards — no `set +e` regions; `set -euo pipefail` is never relaxed.

**`main()` call order:** `resolve_python_bin` is called after `assert_layout` (step f2) and before `source_env` (step g), ensuring:
- `LOG_FILE` is writable (assert_layout guarantees `shared/` exists) before any `log_line` in the resolver.
- `PYTHON_BIN` is set for both the `check` path (`cmd_check`) and the `install` path (`provision_venv`).

**Call site 1 — `provision_venv()` line ~468:** `python3 -m venv` → `"$PYTHON_BIN" -m venv`

**Call site 2 — `cmd_check()` line ~628:** `python3 -c '...' 2>/dev/null` → `"$PYTHON_BIN" -c '...'` (no `2>/dev/null`). Interpreter and JSON parse errors now flow through the normal stderr path and land in `update.log` via the EXIT trap.

### Task 2 — `DEPLOYMENT.md`

Appended to the System Requirements > Python block (after the existing `python3.11 --version` code fence, before the WeasyPrint section):
- Explains that `update_from_github.sh` auto-resolves `python3.11` (or any >= 3.10) when no bare `python3` exists.
- States that wiring an unversioned `python3` is still recommended.
- Includes the RHEL alternatives one-liner verbatim.
- Notes exit 8 behavior on no qualifying interpreter.

---

## Resolution Logic Verification

The plan notes that end-to-end validation was already done on a Rocky 9 VM today, and that a live Linux run is not required on the Windows dev box. The logic is verified by reasoning through the three cases:

**Case A — bare `python3` present and >= 3.10:**
`command -v python3` succeeds → candidate set → version check passes → `PYTHON_BIN=python3` → returns 0. (Typical Ubuntu/Debian host.)

**Case B — no bare `python3`, but `python3.11` on PATH:**
`command -v python3` fails or version check fails → loop starts at `python3.13` (miss), `python3.12` (miss), `python3.11` (`command -v` succeeds, version check passes) → `PYTHON_BIN=python3.11` → returns 0. (Typical stock RHEL 9 host after `dnf install python3.11`.)

**Case C — only `python3.9` on PATH (no >= 3.10 anywhere):**
Bare `python3` miss or version check fails (3.9 < 3.10) → all four versioned names miss → `log_completed "failed: no python3 >= 3.10..."` → `exit 8`.

All three paths correctly avoid tripping `set -e` on the expected-miss branches because every `command -v` call is wrapped in `if ... 2>/dev/null` and every version check is wrapped in `if "$candidate" -c '...' 2>/dev/null`.

---

## Deviations from Plan

None — plan executed exactly as written.

---

## Self-Check: PASSED

- `bash -n scripts/update_from_github.sh` → SYNTAX OK (verified before Task 1 commit)
- `grep -q "alternatives --install /usr/bin/python3 python3" DEPLOYMENT.md` → OK (verified before Task 2 commit)
- `PYTHON_BIN` declared in Constants block: present
- `resolve_python_bin` defined: present
- `main()` calls `resolve_python_bin` after `assert_layout`: present
- Both former bare `python3` call sites use `"$PYTHON_BIN"`: present
- `2>/dev/null` removed from cmd_check tag parse: present
- Commits 63938d1 and b3ab105 exist in git log: confirmed
