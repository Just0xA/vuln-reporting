---
phase: 10-install-update-rollback-infrastructure
plan: "03"
subsystem: scripts
tags: [bash, install, rollback, health-check, systemd]
dependency_graph:
  requires: [10-01, 10-02]
  provides: [cmd_rollback, health_check, auto_rollback, UPDATE-03, UPDATE-05, UPDATE-08, UPDATE-11]
  affects: [scripts/update_from_github.sh]
tech_stack:
  added: []
  patterns:
    - "IN_AUTO_ROLLBACK recursion guard for health-check short-circuit"
    - "auto_rollback never-returns pattern (exits 12 or 13; callers annotate with no-return comment)"
    - "Symmetrical SKIP_RESTART handling in both cmd_install and cmd_rollback"
key_files:
  modified:
    - scripts/update_from_github.sh
decisions:
  - "cmd_rollback does NOT run health_check — rollback target is by definition previously-trusted; if also broken, operator escalates manually rather than risking recursion"
  - "auto_rollback writes TARGET_DIR (the broken new release) into .last after rolling back, so the operator can manually re-attempt or inspect without losing audit trail"
  - "Both tasks implemented in one commit (same file; edits were staged together before first commit ran); commit message covers both deliverables"
metrics:
  duration: "~3 minutes"
  completed: "2026-05-19"
  tasks_completed: 2
  files_modified: 1
---

# Phase 10 Plan 03: Post-Swap Health Check + Auto-Rollback + cmd_rollback Summary

**One-liner:** Post-swap health check with `IN_AUTO_ROLLBACK` recursion guard, full `cmd_rollback` reading `.last` breadcrumb, and operator-facing rollback one-liner printed on every successful upgrade.

---

## What Was Built

### Task 1 — Post-swap health check, auto-rollback, SKIP_RESTART gate, rollback one-liner

**`health_check()`** (new helper, ~8 lines):
- `sleep 10` settle period followed by `systemctl is-active --quiet vuln-reports.service`
- Short-circuits to `return 0` when `IN_AUTO_ROLLBACK=1` — prevents infinite rollback loops on permanently-broken hosts (T-10-13)

**`auto_rollback(PREV_TARGET)`** (new helper, ~25 lines):
- Sets `IN_AUTO_ROLLBACK=1` on entry
- Reuses `atomic_swap` to swap back to `PREV_TARGET`
- Calls `write_breadcrumb "$TARGET_DIR"` — writes the broken release into `.last` for operator inspection
- Restarts `vuln-reports.service`
- Exits 12 on success (health check failed, rollback OK); exits 13 on any step failure (critical)
- Never returns to its caller — all paths exit

**`cmd_install` restart block** (replaced the 10-02 bare restart):
- `SKIP_RESTART=1`: logs `WARNING: SKIP_RESTART=1 — skipping systemctl restart AND post-swap health check` and skips both
- Else: `systemctl restart` → `health_check` → on any failure, calls `auto_rollback "$PREV"` (which exits)
- Rollback one-liner printed to stdout immediately before `log_completed success`:
  ```
  Rollback: sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
  ```

**`IN_AUTO_ROLLBACK=0`** declared at file top alongside `PARTIAL_RELEASE_DIR` / `TMPDIR_TO_CLEAN`.

**Exit codes 12–15** documented in the header comment block.

**`--help` text** updated: `--force` "(only meaningful with --version)" note; `--skip-restart` "(skips both restart and health check; logs WARNING)" note; `--rollback` described with no-health-check rationale; Notes section added explaining the Rollback one-liner.

### Task 2 — Full `cmd_rollback` implementation

Replaced the stub from Plan 10-01 with a ~75-line implementation:

1. Read `${INSTALL_ROOT}/releases/.last` — exit 14 if missing, empty, or target dir absent
2. Promote bare basename to absolute path (`case "$target" in /*) ;; *) target="${INSTALL_ROOT}/releases/${target}" ;; esac`)
3. T-10-12 sanity check: refuse if target is outside `${INSTALL_ROOT}/releases/`
4. Capture `prev_current` (current symlink target before swap) — normalize to absolute path
5. `atomic_swap "$target"` — reuses Plan 10-02 helper; exit 15 on failure
6. `write_breadcrumb "$prev_current"` — enables a "roll forward again" after rollback; maintains audit trail
7. Honor `SKIP_RESTART` symmetrically — skips restart with WARNING, same as `cmd_install`
8. `systemctl restart vuln-reports.service` — bare restart; exit 15 on failure
9. Print `rolled back: current → $target` to stdout
10. `log_completed "success"`

**No health check in `cmd_rollback`** — by design. The rollback target was previously trusted. Running health check would expose a recursion risk if the previously-trusted release is also broken.

**`--force --rollback` rejection**: The existing Plan 10-01 check `"$FORCE" -eq 1 && "$CMD" != "install"` already covers this combination (rollback != install). No code change needed.

---

## Exit Code Table (Final — Phase 10 complete)

| Code | Meaning |
|------|---------|
| 0 | Success (or `--check`: up-to-date) |
| 1 | `--check`: update available |
| 2 | Usage error OR layout-guard failure |
| 3 | GitHub API failure |
| 4 | Release asset download failure |
| 5 | SHA256 mismatch |
| 6 | Tarball extraction failure |
| 7 | Release dir already exists (without `--force`) |
| 8 | Venv provisioning failure |
| 9 | Post-extraction `data/` dir missing |
| 10 | Dry-run smoke test failed |
| 11 | Atomic swap post-condition failed |
| 12 | Post-swap health check failed AND auto-rollback succeeded — investigate new release |
| 13 | Post-swap health check failed AND auto-rollback ALSO failed — critical; manual recovery |
| 14 | `--rollback`: `.last` missing/empty/invalid — no rollback history; use `--list` + `--version` |
| 15 | `--rollback`: atomic swap or `systemctl restart` failed |

---

## Rollback One-Liner (UPDATE-11 — verbatim)

```
Rollback: sudo /opt/vuln-reporting/current/scripts/update_from_github.sh --rollback
```

This line is printed to stdout at the end of every successful `--version` upgrade. The path uses `/current/` (the symlink) so it always points at the just-installed script without the operator needing to remember the version tag.

---

## Deviations from Plan

**1. [Deviation - Single Commit] Both tasks committed atomically**

- **Found during:** Implementation
- **Issue:** Both tasks modify the same file (`scripts/update_from_github.sh`). The edits for Task 1 and Task 2 were implemented together in the same edit session before the first commit was made, so staging captured both task deliverables in one shot.
- **Resolution:** One commit with a message covering both task deliverables. The plan called for two commits; a no-op second commit would add noise without value. All content is present and verified.
- **Commit:** `e91a665`

**2. [Plan Note] `auto_rollback` writes TARGET_DIR (not PREV) into `.last`**

- The plan spec said `write_breadcrumb "$TARGET_DIR"` in `auto_rollback` (the broken release), which is what was implemented. This allows the operator to find the broken release dir and inspect it (its path is now in `.last`). The plan's language was consistent with this.

---

## Human-Check Items (Deferred to Linux VM Smoke)

Per the plan's `<human-check>` element in Task 2, these require a Linux VM with a real systemd unit:

1. **Happy-path rollback**: `sudo .../update_from_github.sh --rollback` → verify `current` points at prior release, `.last` updated, service active, stdout shows `rolled back: current → /opt/...`, `update.log` shows started + success.
2. **No-history refusal**: `rm .last` then `--rollback` → verify exit code 14 and clear error directing operator to `--list` + `--version`.
3. **Auto-rollback smoke**: Install a broken release (stub out dry-run to return 0, break `run_all.py` imports) → verify auto-rollback fires, exit 12, service back on prior release, broken dir preserved.

---

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns introduced beyond those already documented in the plan's threat model:

| Flag | File | Description |
|------|------|-------------|
| threat_flag: path-traversal | scripts/update_from_github.sh | `.last` content used as symlink target — mitigated by `releases/`-prefix check in `cmd_rollback` (T-10-12) |

---

## Self-Check

- [x] `scripts/update_from_github.sh` exists and contains all required patterns
- [x] Commit `e91a665` exists in git log
- [x] All automated verify greps pass (Task 1 + Task 2)
- [x] `bash -n` syntax check passes

## Self-Check: PASSED
