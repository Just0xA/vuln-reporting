---
phase: 21-private-config-repo-ci-codeowners-production-cutover
verified: 2026-07-10T07:10:00Z
status: passed
score: 9/9 must-haves verified
has_blocking_gaps: false
overrides_applied: 0
---

# Phase 21: Private Config Repo + CI + CODEOWNERS + Production Cutover — Verification Report

**Phase Goal:** Delivery configuration lives in a private, reviewed repository — each team's file is protected by its own CODEOWNERS entry, CI blocks a bad merge before it reaches production, and production cuts over from hand-edited SSH files to the reviewed repo without a single delivery interruption.

**Verified:** 2026-07-10T07:10:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria, reconciled per 21-CONTEXT.md decisions)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | SC1 — Private repo exists, provisioned via change management, separate from public repo | VERIFIED (structural/reference level, per D-10) | Repo boundary is honored: no real private repo is created by this phase (correctly out of scope — D-10 change management). `deploy/config-repo/` ships the complete reference/template set (`ci.yml.example`, `CODEOWNERS.example`, `contacts.example.yaml`, `deliveries.d/README.md`, `README.md`) an operator copies into the private repo at provisioning. This is the documented, intentional scope boundary — not a gap. |
| 2 | SC2 — PR touching one team's file requires that team's owner via CODEOWNERS 1:1; CI blocks bad merges | VERIFIED | `deploy/config-repo/CODEOWNERS.example`: leading `* @ORG/vuln-management-team` default rule + one 1:1 entry per `deliveries.d/<team>.yaml` (exec, remediation, tag_profile — matching `tests/fixtures/phase20_config_twin/deliveries.d/`). Reconciled to central VM-team stewardship now (D-08) with 1:1 structure enabling later per-team delegation — documented inline. `deploy/config-repo/ci.yml.example` triggers on `pull_request`, fetches pinned+sha256-verified tarball, runs `run_all.py --dry-run` (config-only, placeholder env for all 6 `_REQUIRED_ENV_VARS`), non-zero exit blocks merge; publishes names+owner matrix artifact. |
| 3 | SC3 — Production reads reviewed-repo config instead of untracked SSH hand-edits | VERIFIED | `scripts/stamp_config_provenance.py` (`stamp`/`verify` subcommands, argparse) ties live server config to a reviewed commit SHA + sha256 + UTC timestamp sidecar. RUNBOOK.md "Delivery Config — Reviewed-Repo Cutover" section documents the edit path (private repo → PR → CODEOWNERS → CI → merge → manual copy → stamp) and replaces the `shared/delivery_config.yaml` safe-to-edit row / SSH nano guidance. Reconciled to manual-copy transport per D-01 (server stays dumb) rather than literal pull/artifact-fetch — documented and intentional. |
| 4 | SC4 — Every pre-cutover delivery continues through one full dual-source fallback cycle, zero interruption, before legacy retirement | VERIFIED | Live-tested: `_select_config_source`/`_load_config` fall through to the legacy branch (not `return []`) on directory-mode failure, logging a WARNING; `--dry-run` echoes the active source. Confirmed by direct execution (see Behavioral Spot-Checks) — removing `contacts.yaml` causes `--dry-run` to log the fallback WARNING and report `Active config source: legacy-fallback`. RUNBOOK.md prescribes the exact one-full-cycle-before-retirement sequence with a rollback note citing the D-04 auto-fallback. |

**Score:** 4/4 roadmap Success Criteria verified (all reconciled per the documented, locked 21-CONTEXT.md decisions D-01/D-03/D-04/D-05/D-08/D-09/D-10 — none are unmet requirements).

### Plan-Level Must-Haves (from PLAN frontmatter, cross-checked against code)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 5 | 21-01: Directory-mode clean resolution returns directory-mode groups, logs directory-mode source | VERIFIED | `run_all.py:230-244`; live `--dry-run` run shows `Active config source: directory-mode` with 3 groups validated. |
| 6 | 21-01: Directory-mode resolution/schema failure falls back to legacy instead of `[]`, logs WARNING naming active source | VERIFIED | `run_all.py:246-253` falls through (no `return []` between `"legacy-fallback"` and the legacy branch at line 259+). Live-tested: removing `contacts.yaml` produced `WARNING — delivery config: directory-mode config failed to resolve or validate; falling back to legacy single file ...` and `--dry-run` printed `Active config source: legacy-fallback`. |
| 7 | 21-01: Both dual-source paths absent → `[]` with logged error (terminal state) | VERIFIED | `run_all.py:254-267`, `grep -n "return \[\]" run_all.py` shows only the terminal `"none"` path and legacy-file-absent/parse-failure paths return `[]`; the two former directory-mode early-returns no longer exist. |
| 8 | 21-01: `--dry-run` echoes the active source; single shared `_select_config_source` decision | VERIFIED | `run_all.py:567-573` calls the same `_select_config_source` helper `_load_config` uses; `tests/test_dry_run_surfacing.py` passes with `active_source_directory_line` / `active_source_legacy_fallback_line` cases. |
| 9 | 21-02: Reference CI gate — pinned+sha256-verified tarball, config-only `--dry-run`, matrix artifact, non-zero blocks merge | VERIFIED | `deploy/config-repo/ci.yml.example` triggers on `pull_request`, `contents: read`, `sha256sum -c` before extraction, placeholder env for all 6 `_REQUIRED_ENV_VARS` (confirmed via grep — matches `run_all.py:135-142` exactly), invokes `run_all.py --dry-run` and `scripts/generate_delivery_matrix.py --format markdown`, uploads via `actions/upload-artifact`. `PINNED_VERSION` is a variable, not a literal real tag pretending to be current. |
| 10 | 21-03: CODEOWNERS 1:1 with `deliveries.d/`, default rule covers shared files, D-10 placeholder handles only | VERIFIED | `deploy/config-repo/CODEOWNERS.example` — default `*` rule + 3 per-file entries matching the fixture team files; only placeholder `@ORG/vuln-management-team` handle used; SC2 reconciliation documented inline. |
| 11 | 21-03: Reference `contacts.yaml` + `deliveries.d/` layout resolves cleanly through the Phase 20 loader shape | VERIFIED | `deploy/config-repo/contacts.example.yaml` parses, has `contacts:` + `defaults.analyst_mailbox`, `example.invalid` only; `deploy/config-repo/deliveries.d/README.md` documents owner/contact-ref/uniqueness with a matching illustrative snippet; no real `deliveries.d/*.yaml` committed. |
| 12 | 21-04: D-03 provenance — live config traceable to a reviewed commit | VERIFIED | `scripts/stamp_config_provenance.py` `stamp`/`verify` subcommands under argparse; `stamp` writes `.config-provenance.json` with `commit_sha`, `stamped_at` (UTC ISO), `sha256`; `verify` exits non-zero on drift or missing sidecar. `tests/test_stamp_config_provenance.py` (4 cases) all pass. |
| 13 | 21-04: RUNBOOK documents the full cutover flow + updated safe-to-edit table + one-full-cycle-before-retirement sequence | VERIFIED | RUNBOOK.md "Delivery Config — Reviewed-Repo Cutover" section (lines 306-436): edit path, cutover procedure, rollback note, explicit `symlink_shared()` decision. Safe-to-edit table (lines 895-910) no longer lists `shared/delivery_config.yaml`/`shared/config/` as a direct-edit row; states explicitly these are NOT server-side hand-edits. Layout diagram (lines 840-891) shows `shared/config/` + `.config-provenance.json` + dual-source coexistence note. |

**Score:** 9/9 plan-level must-haves verified (all four plans).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `run_all.py` | `_select_config_source` + fallback wiring | VERIFIED | Function exists (line 157), called from `_load_config` (line 230) and `_dry_run` (line 567); only one match for `def _select_config_source`. |
| `tests/test_config_loader.py` | Fallback-path unit tests | VERIFIED | 26/26 script-style checks pass, including 5 new `_select_config_source` cases (N-R) + fallback case S. |
| `tests/test_dry_run_surfacing.py` | Active-source echo assertion | VERIFIED | 11/11 checks pass, including the 2 new active-source-line cases. |
| `deploy/config-repo/ci.yml.example` | Private-repo CI gate reference | VERIFIED | Valid YAML, `pull_request` trigger, `contents: read`, sha256 verify, `run_all.py --dry-run`, matrix publish — all present. |
| `deploy/config-repo/README.md` | CI gate operator instructions | VERIFIED | States private/reference status, `PINNED_VERSION` bump policy, pre-auth rationale, gate scope, artifact contract. |
| `deploy/config-repo/CODEOWNERS.example` | Governance reference | VERIFIED | Default rule + 1:1 per-file entries, D-10/SC2 notes, placeholder-only handles. |
| `deploy/config-repo/contacts.example.yaml` | Reference contacts+defaults shape | VERIFIED | Parses cleanly; `contacts:` + `defaults.analyst_mailbox`; `example.invalid` only. |
| `deploy/config-repo/deliveries.d/README.md` | One-file-per-team layout guidance | VERIFIED | Documents owner/contact-ref/uniqueness with illustrative snippet; no real config committed. |
| `scripts/stamp_config_provenance.py` | D-03 provenance stamp/verify CLI | VERIFIED | `stamp` + `verify` subcommands, argparse, `if __name__ == "__main__":`; sidecar has commit SHA + sha256 + UTC timestamp. |
| `tests/test_stamp_config_provenance.py` | Provenance round-trip test | VERIFIED | 4/4 pytest cases pass (round-trip, drift, missing-sidecar, missing-config-dir). |
| `RUNBOOK.md` | Cutover runbook + updated layout/safe-to-edit | VERIFIED | New section present; layout diagram and safe-to-edit table both updated; grep gates for `dual-source`, `stamp_config_provenance`, `CODEOWNERS` all pass. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `run_all.py:_load_config` | `run_all.py:_dry_run` | shared `_select_config_source` helper | WIRED | Both call sites invoke the identical helper; confirmed by grep and by matching live output (`--dry-run` echo matched the actual `_load_config` fallback behavior in the live test). |
| `ci.yml.example` fetch step | `release.yml` slim tarball asset | pinned VERSION + `.sha256` verification | WIRED | `sha256sum -c` step present before extraction; `PINNED_VERSION` referenced as a variable. |
| `ci.yml.example` validate step | `run_all.py --dry-run` | config-only invocation with placeholder env | WIRED | All 6 `_REQUIRED_ENV_VARS` exported as placeholders before the dry-run step; matches `run_all.py`'s actual required-var list exactly. |
| `CODEOWNERS.example deliveries.d/` entries | `deliveries.d/<team>.yaml` files | 1:1 per-file mapping | WIRED | Three entries (exec, remediation, tag_profile) match the Phase 20 fixture team files exactly. |
| `RUNBOOK.md` cutover section | `scripts/stamp_config_provenance.py` | provenance stamp/verify step | WIRED | RUNBOOK cites exact CLI invocation with `--config-dir` and `--commit`. |
| `RUNBOOK.md` cutover section | `run_all.py --dry-run` active-source echo | dual-source-cycle verification step | WIRED | RUNBOOK step 2 of the cutover procedure explicitly checks the active-source echo before proceeding. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Directory-mode success echoes active source | `.venv/bin/python3 run_all.py --dry-run` (with real gitignored `deliveries.d/`+`contacts.yaml` present) | `Active config source: directory-mode`; 3 groups validated | PASS |
| D-04 fallback triggers on directory-mode failure | Temporarily moved `contacts.yaml` aside, re-ran `--dry-run`, restored file | `WARNING — ...falling back to legacy single file...` + `Active config source: legacy-fallback` | PASS |
| Loader/dry-run test suites pass | `tests/test_config_loader.py`, `tests/test_dry_run_surfacing.py` (script-style) | 26/26 and 11/11 checks pass | PASS |
| Provenance stamp/verify round-trip | `.venv/bin/python3 -m pytest tests/test_stamp_config_provenance.py -q` | 4/4 pass | PASS |
| CI YAML structurally valid | `yaml.safe_load` + content assertions on `ci.yml.example` | `OK` — pull_request trigger, sha256/dry-run/matrix/contents:read all present | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| CONF-04 | 21-01 (loader touch), 21-02, 21-03, 21-04 | Private repo + CODEOWNERS + CI gate + reviewed-repo production consumption | SATISFIED | All four SC (private repo boundary reference, CODEOWNERS+CI gate, provenance-based production consumption) verified above. REQUIREMENTS.md checkbox/table still show CONF-04 as `[ ]`/"Pending" — doc-freshness lag, not a code gap (see Anti-Patterns note). |
| QUAL-07 | 21-01, 21-04 | Legacy config keeps delivering unchanged through cutover; dual-source fallback cycle before retirement | SATISFIED | D-04/D-05 fallback live-verified; RUNBOOK cutover procedure enforces one full verified cycle before retirement with a rollback note. REQUIREMENTS.md checkbox/table still show QUAL-07 as `[ ]`/"Pending" — doc-freshness lag, not a code gap. |

No orphaned requirements: only CONF-04 and QUAL-07 map to Phase 21 in REQUIREMENTS.md, and both are declared in plan frontmatter (`requirements: [QUAL-07, CONF-04]` on 21-01 and 21-04; `requirements: [CONF-04]` on 21-02/21-03).

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `.planning/REQUIREMENTS.md` | 30, 36, 94-95 | CONF-04/QUAL-07 still marked `[ ]` and "Pending" in the traceability table | ℹ️ Info | Bookkeeping lag only — the code and tests for both requirements are complete and verified above. Does not block the phase goal; should be updated as part of phase closure (checkbox flip + traceability table + `[x] 21-04-PLAN.md` in ROADMAP.md, currently showing "3/4" plans complete despite plan 4 being done and committed). |

No debt markers (TBD/FIXME/XXX), no stub returns, no hardcoded-empty renders, no console.log-only implementations found in any file modified by this phase.

### Human Verification Required

None. The phase's one `checkpoint:human-verify` task (21-04 Task 3 — operator dual-source cutover dry-run verification) was already run and approved by the operator per the 21-04-SUMMARY.md record: all four staging/synthetic checks (directory-mode echo, legacy-fallback echo, provenance round-trip/drift, runbook read-through) were independently confirmed and the checkpoint resolved with "approved" before this verification pass began. No further human action is required to close Phase 21 itself; the actual production cutover (real private-repo provisioning + first live PR cycle) remains a separate operator-only change-management action, explicitly out of scope per D-10 and correctly not claimed as delivered by this phase.

### Gaps Summary

None. All four plans' must-haves are verified against the live codebase — not just SUMMARY claims. The dual-source fallback (the highest-risk mechanism in this phase, since a defect there would risk real delivery interruption) was independently exercised end-to-end in this verification session (not merely re-reading the SUMMARY's claim), confirming the WARNING log line and the `--dry-run` active-source echo both fire correctly on induced failure. The three ROADMAP SC wording gaps flagged in 21-CONTEXT.md (SC1's "private repo exists," SC2's "that team's owner," SC3's "pull or published artifact") are all deliberate, documented reconciliations (D-10, D-08, D-01 respectively) — not unmet criteria — and are treated as such per the phase's explicit "important context" instructions.

The only finding is an informational doc-freshness item: REQUIREMENTS.md's traceability table and checkboxes, and ROADMAP.md's phase progress line/plan checkbox, have not yet been updated to reflect Plan 21-04's completion (commits `3e276d2`, `b994b96`, `76b77b1` all exist and are clean in `git log`). This does not block the phase goal and is expected to be closed during normal phase-completion bookkeeping.

---

*Verified: 2026-07-10T07:10:00Z*
*Verifier: Claude (gsd-verifier)*
