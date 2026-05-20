---
phase: 10-install-update-rollback-infrastructure
verified: 2026-05-19T20:25:00Z
status: passed
score: 15/15
overrides_applied: 0
---

# Phase 10: Install / Update / Rollback Infrastructure — Verification Report

**Phase Goal:** A non-author operator can install, upgrade, and roll back the suite on a
single Linux server using only `scripts/update_from_github.sh` — release tarball download
is validated against its SHA256 sidecar, swaps are atomic, every upgrade leaves a one-liner
rollback path, and a failed restart auto-reverts.

**Verified:** 2026-05-19T20:25:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Scope Note

UPDATE-15 (`deploy/vuln-reports.service` path references) is assigned to Phase 7 in
REQUIREMENTS.md and is NOT in Phase 10's requirements list (ROADMAP.md is explicit:
UPDATE-01..14 + LOG-02). UPDATE-15 is out of scope here and not assessed.

---

## Syntax Check

`bash -n scripts/update_from_github.sh` — **EXIT 0** (no syntax errors).
Script is 857 lines, mode `100755` (confirmed via `git ls-files -s`).

---

## Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| SC-1 | `--check` and `--list` with distinct exit codes; GITHUB_TOKEN lifts rate limit | VERIFIED | See SC-1 below |
| SC-2 | `--version` end-to-end pipeline (download → SHA256 → extract → venv → 6 symlinks → dry-run → breadcrumb-before → atomic swap → breadcrumb-after → restart → health-check); rollback one-liner printed on success | VERIFIED | See SC-2 below |
| SC-3 | `--rollback` reads `.last`, atomically re-points `current`, restarts unit; `.last` captured BEFORE swap, written AFTER | VERIFIED | See SC-3 below |
| SC-4 | `set -euo pipefail` + EXIT trap cleanup; refuse-if-unknown-layout | VERIFIED | See SC-4 below |
| SC-5 | `--force` + `--skip-restart` behavior; LOG-02 started+completed on every code path including usage errors | VERIFIED | See SC-5 below |
| SC-6 | `GITHUB_RELEASE_REPO` sourced from `.env`; `.env.example` documents it | VERIFIED | See SC-6 below |

**Score: 6/6 success criteria verified**

---

## Detailed Requirement Evidence

### UPDATE-01 — `--check` command

**PASS**

`cmd_check()` (lines 557–585):
- Calls `gh_api_get "/repos/${GITHUB_RELEASE_REPO}/releases/latest"` (line 563)
- Parses `tag_name` via `python3 -c 'import sys,json;...'` (line 568) — no jq dependency
- Prints `active:` / `latest:` / `status:` to stdout
- Exit 0 when up-to-date (line 579), exit 1 when update available (line 583), exit 3 on API/parse failure (lines 565, 570)
- `log_completed "success"` on both the 0 and 1 paths (lines 578, 582)

### UPDATE-02 — SHA256 sidecar validation

**PASS**

`verify_sha256()` (lines 356–366):
```
if ! (cd "$tmpdir" && sha256sum -c "$sidecar"); then
```
- Subshell `cd` into tempdir before `sha256sum -c` — GNU format requires bare filename context; correctly implemented
- Exit 5 on mismatch (line 364)

Download pipeline in `download_release_assets()` (lines 324–350): downloads both
`vuln-reporting-${ver}-slim.tar.gz` and `vuln-reporting-${ver}-slim.tar.gz.sha256` to tmpdir.

### UPDATE-03 — `--rollback` command

**PASS**

`cmd_rollback()` (lines 727–804):
- Reads `${INSTALL_ROOT}/releases/.last` (line 731); exits 14 if missing (line 735), empty (line 743), target absent (line 756), or target outside `releases/` (line 766) — T-10-12 path-traversal guard
- Promotes bare basename to absolute path (lines 747–750)
- `atomic_swap "$target"` (line 782); exit 15 on failure
- `write_breadcrumb "$prev_current"` (line 789) — enables "roll forward again"
- `systemctl restart` (line 796); exit 15 on failure
- Prints `rolled back: current → $target` (line 802)
- `log_completed "success"` (line 803)

### UPDATE-04 — `--list` command

**PASS**

`cmd_list()` (lines 590–624):
- Globs `${INSTALL_ROOT}/releases/*/` — excludes `.last` file automatically (file, not dir)
- `sort -V` handles semantic versioning correctly (v1.10.0 > v1.2.0)
- Marks active release with `* (active)` (line 618)
- Prints `(no releases installed)` on empty dir (line 606)
- `log_completed "success"` (line 623)

### UPDATE-05 — `--force` and `--skip-restart`

**PASS**

`--force` behavior (lines 638–649 in `cmd_install`):
- Exit 7 if release dir exists without `--force` (line 641)
- With `--force`: `rm -rf "$TARGET_DIR"` then re-extracts (line 648)
- Rejection guard: `main()` line 826: `if [[ "$FORCE" -eq 1 && "$CMD" != "install" ]]` — usage error

`--skip-restart` behavior:
- `cmd_install` lines 686–690: logs `WARNING: SKIP_RESTART=1 — skipping systemctl restart AND post-swap health check`
- `cmd_rollback` lines 792–794: logs `WARNING: SKIP_RESTART=1 during --rollback — skipping systemctl restart`
- Symmetrical in both commands
- Rejection guard: `main()` line 829: `if [[ "$SKIP_RESTART" -eq 1 && "$CMD" != "install" && "$CMD" != "rollback" ]]`

### UPDATE-06 — Atomic swap (ln -sfn only; rm + ln forbidden)

**PASS**

`atomic_swap()` (lines 477–490):
```
ln -sfn "$target_dir" "${INSTALL_ROOT}/current"
```
Negative check: `grep -n "rm.*current"` returns **no matches**. The `rm` + `ln` sequence on `current` does not appear anywhere in the script. The only mutation of `current` is via `ln -sfn` in `atomic_swap()`. Post-condition check at line 483 confirms the symlink points to the expected target.

### UPDATE-07 — Breadcrumb ordering (BEFORE swap, AFTER swap)

**PASS**

In `cmd_install()` (lines 669–679):
- Line 670: `PREV="$(readlink "${INSTALL_ROOT}/current")"` — captured BEFORE `atomic_swap`
- Line 676: `atomic_swap "$TARGET_DIR"` — swap executes
- Line 679: `write_breadcrumb "$PREV"` — written AFTER swap succeeds

In `cmd_rollback()` (lines 772–789):
- Line 773: `prev_current="$(readlink "${INSTALL_ROOT}/current")"` — captured BEFORE swap
- Line 782: `atomic_swap "$target"` — swap executes
- Line 789: `write_breadcrumb "$prev_current"` — written AFTER swap succeeds

`write_breadcrumb()` (lines 495–503) uses `.last.tmp` + `mv` for atomic crash-safe write.

### UPDATE-08 — Post-swap health check with auto-rollback + recursion guard

**PASS**

`health_check()` (lines 513–521):
- `IN_AUTO_ROLLBACK` guard at line 514: `if [[ "${IN_AUTO_ROLLBACK:-0}" == "1" ]]; then return 0; fi`
- `sleep 10` settle (line 519)
- `systemctl is-active --quiet vuln-reports.service` (line 520)

`auto_rollback()` (lines 527–552):
- Sets `IN_AUTO_ROLLBACK=1` on entry (line 529) — prevents recursion
- Reuses `atomic_swap` to swap back (line 532)
- Calls `write_breadcrumb "$TARGET_DIR"` (line 540) — broken release preserved in `.last` for inspection
- Restarts service (line 542)
- Exit 12 on success (line 550), exit 13 on any failure (lines 534, 544)
- Never returns to caller — all paths exit

`IN_AUTO_ROLLBACK=0` initialized at file top (line 40).

`cmd_install` health-check invocation (lines 698–701):
```
if ! health_check; then
    auto_rollback "$PREV"
fi
```

### UPDATE-09 — `set -euo pipefail` + EXIT trap cleanup

**PASS**

- Line 27: `set -euo pipefail`
- Line 28: `IFS=$'\n\t'`
- Line 106: `trap 'on_exit $?' EXIT`

`on_exit()` (lines 86–105):
- Removes `PARTIAL_RELEASE_DIR` on non-zero exit if set and dir exists (lines 92–95) — with `|| true` so cleanup failure does not mask exit code
- Removes `TMPDIR_TO_CLEAN` unconditionally (lines 97–99)
- `COMPLETED` guard at line 102 prevents double-logging from the trap when `log_completed` was already called

### UPDATE-10 — Refuse-if-unknown-layout

**PASS**

`assert_layout()` (lines 244–275):
- Checks `$INSTALL_ROOT` exists (line 245)
- Checks `${INSTALL_ROOT}/current` is a symlink (line 250)
- Resolves relative symlink targets and validates the target is inside `${INSTALL_ROOT}/releases/` (lines 259–269)
- Checks `${INSTALL_ROOT}/shared/` exists (line 271)

`assert_layout` called at `main()` line 839 — BEFORE `source_env` (line 842) and BEFORE any command dispatch. All four commands (check, list, install, rollback) go through `main()`, so the guard fires unconditionally on all real invocations.

### UPDATE-11 — Rollback one-liner printed on successful `--version` upgrade

**PASS**

`cmd_install()` lines 709–710:
```
echo
echo "Rollback: sudo ${INSTALL_ROOT}/current/scripts/update_from_github.sh --rollback"
```

This appears ONLY in `cmd_install` (line 710). Confirmed absent from `cmd_rollback` (lines 727–804 produce no "Rollback:" line). One-liner uses `${INSTALL_ROOT}/current/` so it always references the just-installed script without requiring the operator to know the version tag.

### UPDATE-12 — Optional `GITHUB_TOKEN` for authenticated API calls

**PASS**

`gh_api_get()` (lines 297–313):
```
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi
```

`download_release_assets()` (lines 334–337): same conditional pattern for CDN downloads.

`source_env()` (line 288): comment confirms `GITHUB_TOKEN is optional; absence is not an error`.
`GITHUB_TOKEN` is never echoed to `ORIG_ARGV` or `update.log` (T-10-02 mitigation; `ORIG_ARGV="$*"` captures flag names only, not env var values).

### UPDATE-13 — Per-release venv

**PASS**

`provision_venv()` (lines 404–420):
- `python3 -m venv "${target_dir}/.venv"` (line 408) — per-release, inside release dir
- `pip upgrade` (line 412)
- `"${target_dir}/.venv/bin/pip" install -r "${target_dir}/requirements.txt"` (line 416)
- Always runs in full (no skip-if-unchanged logic)
- Exit 8 on any provisioning failure

### UPDATE-14 — Six shared-path symlinks

**PASS**

`symlink_shared()` (lines 425–447) places exactly six symlinks via `ln -sfn`:
1. `${INSTALL_ROOT}/shared/.env` → `${target_dir}/.env` (line 439)
2. `${INSTALL_ROOT}/shared/delivery_config.yaml` → `${target_dir}/delivery_config.yaml` (line 440)
3. `${INSTALL_ROOT}/shared/logs` → `${target_dir}/logs` (line 441)
4. `${INSTALL_ROOT}/shared/output` → `${target_dir}/output` (line 442)
5. `${INSTALL_ROOT}/shared/data/cache` → `${target_dir}/data/cache` (line 443)
6. `${INSTALL_ROOT}/shared/data/trend` → `${target_dir}/data/trend` (line 444)

Guard at line 432 confirms `${target_dir}/data/` exists before attempting nested symlinks; exit 9 if missing.

### LOG-02 — Started + completed lines on every code path

**PASS**

`log_started()` (lines 65–67): writes `started at <ISO-8601> with argv=<ORIG_ARGV>`
`log_completed()` (lines 69–73): writes `completed at <ISO-8601> status=<value>`; sets `COMPLETED=1`

Coverage confirmed by grep — `log_completed` appears on 36 lines covering:
- Usage errors (`usage_error()` calls `log_started` + `log_completed` at lines 235–236)
- Layout-guard failures (lines 246, 251, 267, 272)
- Env-sourcing failure (line 285)
- All download, SHA256, extract, venv, symlink, dry-run, swap failures (lines 341–486)
- Auto-rollback paths (lines 533, 543, 547)
- `cmd_check` success paths (lines 578, 582)
- `cmd_list` success (line 623) — note: `log_completed "success"` also at line 607 (empty dir path)
- `cmd_install` success (line 716)
- All `cmd_rollback` failure and success paths (lines 732–803)
- EXIT trap on_exit (line 103): writes `completed ... status=failed: trap-on-exit (rc=X)` when `COMPLETED=0`

`--help` is the ONE documented exception — prints usage and exits 0 with no log entry (correct per LOG-02 spec).

---

## SC-1 Detailed (ROADMAP Success Criterion 1)

`--check` (UPDATE-01 above) and `--list` (UPDATE-04 above): exit codes 0/1/3 for check;
0 for list. Both commands honor `GITHUB_TOKEN` via `gh_api_get()` and
`download_release_assets()` conditional bearer headers (UPDATE-12). VERIFIED.

## SC-2 Detailed (ROADMAP Success Criterion 2)

Full `cmd_install` pipeline order (lines 632–717):
1. `mktemp -d` → `TMPDIR_TO_CLEAN` (line 635)
2. Force-check / rm existing dir (lines 638–649)
3. `download_release_assets` (line 651) → `verify_sha256` (line 652) → `extract_release` (line 653)
4. `provision_venv` (line 657) → `symlink_shared` (line 658)
5. `PARTIAL_RELEASE_DIR=""` disarm (line 663) → `smoke_dry_run` (line 664)
6. `PREV` capture via `readlink` (line 670) — BEFORE swap
7. `atomic_swap "$TARGET_DIR"` (line 676)
8. `write_breadcrumb "$PREV"` (line 679) — AFTER swap
9. Restart + health check + auto-rollback (lines 686–702)
10. Rollback one-liner printed (line 710)
11. `log_completed "success"` (line 716)

All 11 steps confirmed present in sequence. VERIFIED.

## SC-3 Detailed (ROADMAP Success Criterion 3)

`cmd_rollback` reads `.last`, validates target, captures `prev_current` BEFORE swap,
`atomic_swap` then `write_breadcrumb "$prev_current"` AFTER — same ordering discipline
as `cmd_install`. VERIFIED (UPDATE-03 + UPDATE-07 above).

## SC-4 Detailed (ROADMAP Success Criterion 4)

`set -euo pipefail` (line 27), EXIT trap (line 106), `assert_layout()` (lines 244–275)
covering all four failure modes. VERIFIED (UPDATE-09 + UPDATE-10 above).

## SC-5 Detailed (ROADMAP Success Criterion 5)

`--force` and `--skip-restart` both implemented with symmetrical handling in `cmd_install`
and `cmd_rollback`. LOG-02 coverage comprehensive — 36 `log_completed` call sites plus
EXIT trap fallback. VERIFIED (UPDATE-05 + LOG-02 above).

## SC-6 Detailed (ROADMAP Success Criterion 6)

`source_env()` (lines 280–289) sources `${INSTALL_ROOT}/shared/.env` and validates
`GITHUB_RELEASE_REPO` is non-empty (exit 2 if missing). `.env.example` lines 39–49 document
`GITHUB_RELEASE_REPO=owner/repo` (required) and `# GITHUB_TOKEN=ghp_...` (optional,
commented, with rate-limit explanation). VERIFIED.

---

## Atomic Swap Audit (UPDATE-06)

Positive evidence: `ln -sfn "$target_dir" "${INSTALL_ROOT}/current"` at line 480 (only occurrence of a mutation to `current`).

Negative evidence: `grep "rm.*current"` returns zero matches. No `rm` + `ln` sequence exists anywhere in the script. The comment at line 476 explicitly states: `# rm + ln sequences on 'current' are FORBIDDEN (UPDATE-06)`.

---

## Exit Code Table Verification

| Code | Meaning | Verified |
|------|---------|---------|
| 0 | success / --check up-to-date | Line 579 (check), 608 (list), 716 (install) |
| 1 | --check: update available | Line 583 |
| 2 | usage error / layout-guard failure | Lines 237, 247, 252, 268, 273, 286, 852 |
| 3 | GitHub API failure | Lines 565, 570 |
| 4 | download failure | Lines 342, 348 |
| 5 | SHA256 mismatch | Line 364 |
| 6 | extraction failure | Line 385 |
| 7 | release dir exists without --force | Line 641 |
| 8 | venv provisioning failure | Lines 410, 414, 418 |
| 9 | data/ missing post-extract | Line 436 |
| 10 | dry-run smoke failed | Line 464 |
| 11 | atomic swap post-condition failed | Line 486 |
| 12 | health check failed, auto-rollback OK | Line 550 |
| 13 | health check AND auto-rollback failed | Lines 534, 544 |
| 14 | .last missing/empty/invalid | Lines 735, 743, 756, 766 |
| 15 | rollback atomic swap or restart failed | Lines 784, 798 |

All 16 exit codes (0–15) present; no overlaps; no gaps in the 0–15 range.

---

## Anti-Pattern Scan

`grep -nE "TBD|FIXME|XXX" scripts/update_from_github.sh` — **zero matches**. No debt markers.

No stub implementations: `cmd_install`, `cmd_rollback`, `cmd_check`, `cmd_list` are all
fully implemented (the 10-01 stubs for `cmd_install` and `cmd_rollback` were replaced by
plans 10-02 and 10-03 respectively). No `return null`, `return {}`, or placeholder patterns
in any function.

---

## SUMMARY.md Accuracy Check

| Plan | Claim | Accurate? |
|------|-------|-----------|
| 10-01-SUMMARY | Script created 405 lines, mode 100755; cmd_check + cmd_list implemented; LOG-02 on every path; assert_layout; GITHUB_RELEASE_REPO in .env.example | Yes — all confirmed in final 857-line script (plans 10-02 and 10-03 extended it) |
| 10-01-SUMMARY | cmd_install and cmd_rollback were intentional stubs in plan 10-01 | Yes — both replaced by subsequent plans |
| 10-02-SUMMARY | 9 helper functions added; cmd_install full pipeline; EXIT trap extended with PARTIAL_RELEASE_DIR + TMPDIR_TO_CLEAN cleanup | Yes — all functions present at their documented line ranges |
| 10-02-SUMMARY | PREV captured before swap; write_breadcrumb after swap | Yes — lines 670 vs 676 vs 679 |
| 10-03-SUMMARY | health_check with IN_AUTO_ROLLBACK short-circuit; auto_rollback sets it on entry; never returns | Yes — lines 514, 529, 550 |
| 10-03-SUMMARY | cmd_rollback full 75-line implementation with T-10-12 path-traversal guard | Yes — lines 727–804 (~78 lines) |
| 10-03-SUMMARY | Rollback one-liner printed in cmd_install only, not cmd_rollback | Yes — line 710 only |
| 10-03-SUMMARY | Both tasks committed in one commit (e91a665) | Yes — confirmed in git log |

One minor discrepancy: 10-02-SUMMARY states the commit message covers "Task 1's scope" with Task 2 included. This is an internal dev-process note; correctness of the implementation is unaffected.

All SUMMARY claims are **substantively accurate**.

---

## Requirements Coverage

| Requirement | Status | Evidence |
|-------------|--------|---------|
| UPDATE-01 | PASS | `cmd_check()` — exit 0/1/3, GitHub API, stdout comparison |
| UPDATE-02 | PASS | `verify_sha256()` with `cd + sha256sum -c`; full install pipeline |
| UPDATE-03 | PASS | `cmd_rollback()` — reads .last, validates, atomic swap, restart |
| UPDATE-04 | PASS | `cmd_list()` — sort -V, active marker, empty-dir message |
| UPDATE-05 | PASS | `--force` and `--skip-restart` in both install and rollback |
| UPDATE-06 | PASS | `atomic_swap()` uses `ln -sfn` only; no `rm + ln` on `current` |
| UPDATE-07 | PASS | PREV/prev_current captured before swap; breadcrumb written after |
| UPDATE-08 | PASS | `health_check()` + `auto_rollback()` + `IN_AUTO_ROLLBACK` guard |
| UPDATE-09 | PASS | `set -euo pipefail` + EXIT trap + PARTIAL_RELEASE_DIR cleanup |
| UPDATE-10 | PASS | `assert_layout()` — INSTALL_ROOT, current symlink, releases/ prefix, shared/ |
| UPDATE-11 | PASS | Rollback one-liner at line 710 in `cmd_install` only |
| UPDATE-12 | PASS | Conditional `Authorization: Bearer $GITHUB_TOKEN` in two curl callers |
| UPDATE-13 | PASS | `provision_venv()` — python3 -m venv + pip install -r requirements.txt |
| UPDATE-14 | PASS | `symlink_shared()` — exactly 6 shared-path symlinks via ln -sfn |
| LOG-02 | PASS | log_started + log_completed on all 36+ code paths; EXIT trap fallback |

**15/15 requirements PASSED**

---

## Gaps

None. All 15 requirements verified against actual code.

---

## Post-Merge Human-Action Items (Not Gaps)

These items require a Linux VM with a real systemd unit. They are documented as
`<human-check>` blocks in plans 10-01, 10-02, and 10-03 — they are expected post-merge
operator steps, not verification failures.

1. **End-to-end install smoke**: On a host with the layout at `/opt/vuln-reporting/`, run
   `scripts/update_from_github.sh --version vX.Y.Z` against a real GitHub release.
   Expected: tarball downloaded, SHA256 verified, venv provisioned, service restarted,
   rollback one-liner printed, `update.log` shows started + success.

2. **Health-check auto-rollback smoke**: Install a release with a broken `run_all.py`
   (bypassing dry-run or making it fail post-swap). Expected: service fails `is-active`
   after 10s settle, auto-rollback fires, exit 12, previous release active.

3. **Rollback command smoke**: After a successful `--version` upgrade, run `--rollback`.
   Expected: `current` re-points to prior release, `.last` updated with forward target,
   service restarted, stdout shows `rolled back: current → /opt/...`.

4. **No-history refusal**: `rm releases/.last` then `--rollback`. Expected: exit 14,
   error message directing operator to `--list` + `--version`.

5. **`--list` output**: On a host with multiple installed releases. Expected: sorted by
   version, active marked `* (active)`.

6. **Sudoers setup**: Passwordless `sudo systemctl restart vuln-reports.service` for the
   operator account. (Phase 11 runbook item — out of scope for Phase 10.)

---

## Conclusion

**Phase 10 goal is ACHIEVED.**

All 15 requirements (UPDATE-01..14 + LOG-02) are satisfied in `scripts/update_from_github.sh`
(857 lines, syntax-clean). The six ROADMAP success criteria are met by implemented, wired,
non-stub code. No debt markers, no stubs, no orphaned logic. The sole remaining items are
Linux-VM smoke runs that are correctly categorized as post-merge operator steps, not
verification gaps.

---

_Verified: 2026-05-19T20:25:00Z_
_Verifier: Claude (gsd-verifier)_
