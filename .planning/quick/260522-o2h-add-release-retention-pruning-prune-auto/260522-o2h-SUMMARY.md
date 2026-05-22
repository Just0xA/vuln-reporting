---
phase: quick-260522-o2h
plan: "01"
subsystem: scripts/updater
tags: [pruning, release-retention, ops, disk-management]
dependency_graph:
  requires: []
  provides: [release-retention-pruning]
  affects: [scripts/update_from_github.sh, DEPLOYMENT.md]
tech_stack:
  added: []
  patterns: [best-effort-nonfatal-guard, inside-releases-case-guard, sort-V-semver]
key_files:
  created: []
  modified:
    - scripts/update_from_github.sh
    - DEPLOYMENT.md
decisions:
  - "Single prune_releases helper called by both cmd_prune and the auto-prune hook; no duplicate deletion logic"
  - "Active and .last targets always preserved unconditionally, even outside the keep-N window"
  - "Auto-prune placed immediately before log_completed success in cmd_install; auto_rollback always exits so failure paths cannot reach it by construction"
  - "prune_releases always return 0 — guarded via || log_line not set +e"
  - "inside-releases case guard re-asserted before every rm -rf (mirrors cmd_rollback T-10-12 pattern)"
metrics:
  duration: "~25 minutes"
  completed: "2026-05-22"
  tasks_completed: 2
  files_modified: 2
---

# Phase quick-260522-o2h Plan 01: Release Retention Pruning Summary

**One-liner:** `prune_releases` helper keeps the N newest release dirs (default 3), always preserving the active and .last rollback target, called by `--prune` command and auto-wired into the cmd_install happy path.

## What Was Built

### Task 1 — prune_releases helper, cmd_prune, and flag parsing

**`scripts/update_from_github.sh`:**

- Added `RELEASE_RETENTION="${RELEASE_RETENTION:-3}"` constant after `IN_AUTO_ROLLBACK` in the constants block.
- Added `KEEP=""` initializer to `parse_args`.
- Added `--prune` case arm with the existing conflicting-command guard pattern.
- Added `--keep N` case arm: requires a following value (exits 2 via `usage_error` if missing), validates positive integer regex `^[1-9][0-9]*$` (exits 2 if invalid).
- Added `prune_releases <keep_n>` helper after `write_breadcrumb`:
  - Resolves active release basename from `readlink current` (normalizes relative to absolute with the bare-basename `case` pattern).
  - Resolves `.last` rollback target basename from `releases/.last` if present.
  - Enumerates directories only with `for d in "${releases_dir}"/*/; do [[ -d "$d" ]] || continue` (mirrors `cmd_list`, naturally excludes the `.last` file).
  - Short-circuits with a log and stdout message when total <= keep_n.
  - Sorts entries with `sort -V` (semver-aware).
  - For each deletion candidate (outside the newest-N window): skips unconditionally if basename matches active or .last target, with `log_line` for each preservation.
  - Before every `rm -rf`: re-asserts inside-releases `case` guard (mirrors `cmd_rollback` T-10-12 pattern); skips with WARNING if path is outside.
  - Deletes best-effort: `rm -rf "$abs_path" || { log_line "WARNING: prune failed to remove ${abs_path}"; false; }` — failure is logged and loop continues.
  - Prints concise stdout summary: `pruned: kept N (tags...), removed M (tags...)`.
  - `return 0` on all paths — never propagates failure.
- Added `cmd_prune`: `keep_n="${KEEP:-$RELEASE_RETENTION}"`, calls `prune_releases`, then `log_completed "success"`.
- Added `--keep` orthogonal-flag guard in `main()`: if `KEEP` is non-empty and `CMD != "prune"`, exits 2 via `usage_error`.
- Added `prune)    cmd_prune    ;;` to the `main()` dispatch case.
- Updated `print_usage`: synopsis line, two flag entries (`--prune`, `--keep <N>`), two examples (`--prune`, `--prune --keep 5`).

### Task 2 — Auto-prune hook and documentation

**`scripts/update_from_github.sh`:**

- Inserted `prune_releases "$RELEASE_RETENTION"` in `cmd_install` immediately before `log_completed "success"`, with a one-line comment explaining it is best-effort and only on full success.
- Confirmed by code inspection that `auto_rollback` always exits 12 or 13 and never returns, and all pre-swap failure paths exit earlier — so the auto-prune call is unreachable on failure paths by construction.

**`DEPLOYMENT.md`:**

- Added to the "Additional flags" block: `--prune` and `--prune --keep 5` bash examples with a prose note covering auto-prune behavior, active/.last preservation, and best-effort semantics.

## Commits

| Hash | Task | Description |
|------|------|-------------|
| b644860 | Task 1 | feat(quick-260522-o2h-01): add prune_releases helper, cmd_prune, and flag parsing |
| a0be4a1 | Task 2 | feat(quick-260522-o2h-02): wire auto-prune into cmd_install; document --prune in help and DEPLOYMENT.md |

## Prune Harness Verification Output

The prune logic was validated with a local bash harness (Git Bash on Windows cannot create real symlinks, so `active_base` and `last_base` were injected directly to simulate the Linux `readlink` results — the actual production path uses `readlink` which works correctly on Linux):

```
=== TEST 1: 5 releases, keep=3, active=v1.2.2, .last=v1.2.1 ===
[LOG] prune: removed /tmp/tmp.qiAFUHbA98/releases/v1.0.0
[LOG] prune: removed /tmp/tmp.qiAFUHbA98/releases/v1.1.0
pruned: kept 3 (v1.2.0 v1.2.1 v1.2.2), removed 2 (v1.0.0 v1.1.0)
--- remaining ---
v1.2.0
v1.2.1
v1.2.2
PASS: v1.2.2 (active) preserved
PASS: v1.2.1 (.last) preserved
PASS: v1.2.0 (3rd newest) preserved
PASS: v1.1.0 removed
PASS: v1.0.0 removed

=== TEST 2: 4 releases, keep=2, active=v1.1.0, .last=v1.0.0 (both outside newest-2) ===
[LOG] prune: preserving v1.0.0 (rollback target)
[LOG] prune: preserving v1.1.0 (active release)
pruned: kept 4 (v1.0.0 v1.1.0 v1.2.0 v1.2.1), removed 0 (none)
--- remaining ---
v1.0.0
v1.1.0
v1.2.0
v1.2.1
PASS: v1.1.0 (active, outside window) preserved
PASS: v1.0.0 (.last, outside window) preserved
PASS: v1.2.1 (newest) preserved
PASS: v1.2.0 (2nd newest) preserved

=== TEST 3: 2 releases, keep=3 -> nothing to remove ===
prune: 2 release(s) present, keep=3; nothing to remove

=== All harness tests complete ===
```

**Test 2 is the critical safety proof:** with `active=v1.1.0` and `.last=v1.0.0` both outside the newest-2 window, neither is deleted. All 4 releases survive (the 2 protected + the 2 in-window), and removed count is 0.

## Automated Verification

```
bash -n scripts/update_from_github.sh  →  SYNTAX OK
grep RELEASE_RETENTION                 →  found
grep prune_releases                    →  found
grep cmd_prune                         →  found
grep 'prune)'                          →  found
grep 'prune_releases "\$RELEASE_RETENTION"'  →  found (auto-prune hook)
grep -- '--prune' DEPLOYMENT.md        →  found
grep -c -- '--prune' scripts/...       →  10 occurrences
```

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- `scripts/update_from_github.sh` — modified, `bash -n` passes, all greps confirmed.
- `DEPLOYMENT.md` — modified, `--prune` present.
- Commits b644860 and a0be4a1 exist in git log.
- No files inadvertently deleted (post-commit deletion check clean).
