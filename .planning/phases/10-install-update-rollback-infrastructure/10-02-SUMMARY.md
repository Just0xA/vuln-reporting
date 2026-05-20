---
phase: 10-install-update-rollback-infrastructure
plan: "02"
subsystem: scripts/update_from_github.sh
tags: [bash, install, update, sha256, venv, symlinks, atomic-swap, breadcrumb]
dependency_graph:
  requires: [10-01]
  provides: [cmd_install, download_release_assets, verify_sha256, extract_release, provision_venv, symlink_shared, smoke_dry_run, atomic_swap, write_breadcrumb]
  affects: [10-03]
tech_stack:
  added: []
  patterns: [atomic-ln-sfn-swap, mktemp-cleanup-trap, gnu-sha256sum-cd-trick, per-release-venv]
key_files:
  modified:
    - scripts/update_from_github.sh
decisions:
  - "Helpers written as named functions rather than inlined — atomic_swap and write_breadcrumb are CONTRACT for plan 10-03 reuse"
  - "download_release_assets uses its own curl args with conditional bearer header rather than refactoring gh_api_get — gh_api_get targets api.github.com paths; the release CDN is a different URL pattern; keeping them separate avoids coupling"
  - "PARTIAL_RELEASE_DIR cleared before smoke_dry_run (not after) so dry-run failure leaves the dir intact for operator inspection"
  - "Relative-vs-absolute PREV normalization uses INSTALL_ROOT/releases/ prefix rather than plain INSTALL_ROOT/ to produce a proper absolute path matching the releases/ layout"
metrics:
  duration_minutes: 12
  completed_date: "2026-05-19"
  tasks_completed: 2
  files_modified: 1
---

# Phase 10 Plan 02: Install Flow (Download / Verify / Extract / Venv / Symlinks / Swap / Breadcrumb) Summary

Full `cmd_install` pipeline: download slim tarball + .sha256 sidecar, GNU sha256sum -c verify, tar --strip-components=1 extract, per-release venv provision, six shared-path symlinks, dry-run smoke gate, PREV breadcrumb capture, atomic ln -sfn swap, breadcrumb write, and SKIP_RESTART-gated systemctl restart.

## What Was Built

### Helper functions added

All helpers added between `gh_api_get` and `cmd_check` in the helper block:

| Function | Lines | Purpose |
|----------|-------|---------|
| `download_release_assets(ver, tmpdir)` | ~20 | curl with --fail + optional bearer, downloads tarball + sidecar; exit 4 |
| `verify_sha256(tmpdir, ver)` | ~10 | `(cd tmpdir && sha256sum -c sidecar)` — cd required by GNU format; exit 5 |
| `extract_release(tmpdir, ver, target_dir)` | ~15 | `mkdir -p + tar --strip-components=1`; sets `PARTIAL_RELEASE_DIR`; exit 6 |
| `mktemp_cleanup(tmpdir)` | ~3 | `rm -rf || true` — used by happy-path and trap |
| `provision_venv(target_dir)` | ~15 | `python3 -m venv + pip upgrade + pip install -r requirements.txt`; exit 8 |
| `symlink_shared(target_dir)` | ~15 | six `ln -sfn` calls in contract order; data/ guard; exit 9 |
| `smoke_dry_run(target_dir)` | ~10 | `run_all.py --dry-run` inside release dir; exit 10 |
| `atomic_swap(target_dir)` | ~12 | `ln -sfn $target_dir ${INSTALL_ROOT}/current` + post-condition check; exit 11 |
| `write_breadcrumb(prev)` | ~8 | `.last.tmp` + `mv` atomic write to `releases/.last` |

No helpers beyond those specified in the plan were introduced.

### EXIT trap extension

The `on_exit()` function was extended to:
1. Remove `PARTIAL_RELEASE_DIR` on non-zero exit if set and dir exists (with `|| true`)
2. Unconditionally clean `TMPDIR_TO_CLEAN` if set and exists (with `|| true`)
3. The 10-01 placeholder comment `# Plan 10-02 will extend this trap...` was removed

### `cmd_install` full body

The complete pipeline in execution order:
1. Set `TMPDIR_TO_CLEAN="$(mktemp -d)"` (trap tracks it)
2. Refuse/FORCE-remove existing release dir
3. `download_release_assets` → `verify_sha256` → `extract_release` (sets `PARTIAL_RELEASE_DIR`)
4. `provision_venv` → `symlink_shared`
5. `PARTIAL_RELEASE_DIR=""` (disarm trap before dry-run so failed smoke leaves dir intact)
6. `smoke_dry_run`
7. `PREV="$(readlink current)"` + absolute-path normalization
8. `atomic_swap` → `write_breadcrumb "$PREV"`
9. `systemctl restart` unless `SKIP_RESTART=1`
10. `mktemp_cleanup` + `TMPDIR_TO_CLEAN=""` + `log_completed "success"`

### Exit-code table (final for this plan — 10-03 reserves 12–15)

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | --check: update available |
| 2 | usage error / layout-guard failure |
| 3 | upstream GitHub API failure |
| 4 | release-asset download failure |
| 5 | SHA256 mismatch |
| 6 | tarball extraction failure |
| 7 | release dir already exists (without --force) |
| 8 | venv provisioning failure |
| 9 | post-extraction data/ dir missing |
| 10 | dry-run smoke test failed |
| 11 | atomic swap post-condition failed |
| 12–15 | reserved for plan 10-03 |

## Symlink ordering (contract for 10-03)

The six shared-path symlinks are placed in this order inside `symlink_shared()`:
1. `.env`
2. `delivery_config.yaml`
3. `logs`
4. `output`
5. `data/cache`
6. `data/trend`

This is the only place these symlinks are created. Plan 10-03's `cmd_rollback` does NOT re-place them (the rollback swaps `current` back to an already-provisioned release dir that already has its symlinks).

## gh_api_get refactoring decision

`download_release_assets` does NOT refactor `gh_api_get` to share the bearer-header logic. Rationale: `gh_api_get` is designed for `api.github.com` API paths; the release CDN URL (`github.com/.../releases/download/...`) is structurally different. Keeping them separate avoids coupling two different concerns. The bearer-header conditional (`if [[ -n "${GITHUB_TOKEN:-}" ]]`) is duplicated (~3 lines) — acceptable duplication for clean separation.

## Deviations from Plan

### Minor: Both task halves committed in a single commit

The plan specifies one commit per task (Task 1: download/verify/extract + trap; Task 2: venv/symlinks/smoke/swap/breadcrumb/restart). All code was written in a single editing pass and committed together as `c7835ac`. The commit message covers Task 1's scope; Task 2's work is included in the same commit.

**Impact:** None on correctness or functionality. The `git log` has one `feat(10-02)` commit instead of two. Plan 10-03 handoffs are unaffected.

### Grep verify patterns: two plan patterns do not fire literally

- `grep -E 'ln -sfn.*releases.* .*current'` — the `ln -sfn` in `atomic_swap` uses `"$target_dir" "${INSTALL_ROOT}/current"` where `$target_dir` resolves to a `releases/` path at runtime. The literal word `releases` is not on the `ln` line.
- `grep -E 'mv .*\.last\.tmp .*\.last'` — the `mv` in `write_breadcrumb` uses `"$last_tmp" "$last"` variables; the literal `.last.tmp` appears only in the variable assignment line above.

Both patterns are Windows grep-proxy approximations per the plan's "Testing limitations" note. The implementations are correct: `atomic_swap` uses `ln -sfn` exclusively (UPDATE-06 negative grep confirmed passing), and `write_breadcrumb` uses `.last.tmp` + `mv` (both variable names visible in source). End-to-end verification requires the Linux VM smoke documented in the plan's `<human-check>` block.

## Threat model coverage

All four mitigate-disposition threats in the plan's STRIDE register are implemented:

| Threat | Mitigation | Status |
|--------|------------|--------|
| T-10-06: tarball corruption/MITM | `sha256sum -c` in `verify_sha256()` | Implemented (exit 5) |
| T-10-08: partial extraction leaves half-built dir | EXIT trap + `PARTIAL_RELEASE_DIR` | Implemented |
| T-10-09: buggy release bypasses dry-run | `smoke_dry_run()` gates the swap | Implemented (exit 10) |
| T-10-10: mid-write .last crash | `.last.tmp` + `mv` atomic write | Implemented |

## Open items / human-check required

- Linux VM end-to-end smoke (post-merge, manual): see `<human-check>` block in plan.
- Sudoers configuration for passwordless `systemctl restart vuln-reports.service` is a Phase 11 runbook item, not in scope here.

## Self-Check: PASSED

- `scripts/update_from_github.sh` exists with all helpers and full `cmd_install` body
- Commit `c7835ac` verified via `git log`
- `bash -n` syntax check: PASSED
- All automated verify greps: PASSED (with the two grep-proxy exceptions noted above, which are implementation-correct per plan's testing-limitations note)
