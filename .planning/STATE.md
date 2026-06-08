---
gsd_state_version: 1.0
milestone: v1.3
milestone_name: Trend & Segmentation Substrate
status: verifying
stopped_at: Phase 12 context gathered
last_updated: "2026-06-08T21:03:51.855Z"
last_activity: 2026-06-08
progress:
  total_phases: 2
  completed_phases: 1
  total_plans: 3
  completed_plans: 3
  percent: 50
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-06-05)

**Core value:** Right metric, right audience, right channel — without writing a new report each time.
**Current focus:** Phase 12 — trend-snapshot-substrate-s1

## Current Position

Phase: 12 (trend-snapshot-substrate-s1) — EXECUTING
Plan: 3 of 3
Status: Phase complete — ready for verification
Last activity: 2026-06-08

## Shipped Milestones

- ✅ **v1.2 Deployment & Self-Update Infrastructure** (2026-05-22) — see [`MILESTONES.md`](MILESTONES.md). 5 phases (7–11), 10 plans, 65 files / +11,667 LOC. 39/39 requirements satisfied; audit passed. Tarball install/update/rollback via `scripts/update_from_github.sh`, CI release pipeline, hardened systemd unit; released v1.2.0–v1.2.4 (incl. python3 resolution, release pruning, daemon `LiveError` fix), all VM-validated. Full archive: [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md), [`milestones/v1.2-REQUIREMENTS.md`](milestones/v1.2-REQUIREMENTS.md). Audit: [`v1.2-MILESTONE-AUDIT.md`](v1.2-MILESTONE-AUDIT.md).
- ✅ **v1.1 PDF Chrome Redesign** (2026-05-13) — see [`MILESTONES.md`](MILESTONES.md). 2 phases, 9 plans, 49 files / +7305 LOC across 1 day. All 16 v1.1 requirements satisfied. Shared `PdfChrome` utility wired into `board_summary` + `composed_report` via `_CHROME_AWARE_SLUGS` allowlist; legacy renderers byte-unchanged. Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md), [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md). Audit: [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md).
- ✅ **v1.0 Modular Reporting Framework** (2026-05-08) — see [`MILESTONES.md`](MILESTONES.md). 4 phases, 19 plans, 1 quick task, 140 commits across 4 days. All 24 v1 requirements Validated. Full archive: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md), [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md), [`milestones/v1.0-phases/`](milestones/v1.0-phases/). Retrospective: [`RETROSPECTIVE.md`](RETROSPECTIVE.md).

## Performance Metrics

(Reset at milestone boundary; accumulates as v1.3 phases ship.)

## Accumulated Context

### Decisions

Decisions logged in PROJECT.md "Key Decisions" table. Prior milestone decision logs archived at `milestones/v1.0-ROADMAP.md`, `milestones/v1.1-ROADMAP.md`, and `milestones/v1.2-ROADMAP.md`.

### v1.3 Settled Constraints (from spikes — not open questions)

- **S1 is snapshot-capture, NOT reconstruction.** Spike 002: ~29-day Tenable fixed-retention wall forbids backfill. Cold start is real. Multi-month history must accumulate forward from first snapshot.
- **Reopened-aware predicate is mandatory.** The naive `last_fixed null OR last_fixed>D` form drops ~19% of all findings (the entire REOPENED population, ~30,500 of 160,453 in the spiked dataset). The two-interval model using `resurfaced_date` resolves it exactly (+2 of 160,453). TREND-01 requires unit tests proving this.
- **Snapshots extend `data/trend/`, not a parallel store.** Must not regress `management_summary` or any other existing trend consumer.
- **PII discipline (D-04-08) applies to snapshot payloads.** Aggregate counts only; no hostnames, IPs, plugin names, or asset-level fields in persisted files.
- **SEG-03 exception list is operator-facing local output only.** Never committed, never emailed.

### Pending Todos

None at roadmap creation.

### Blockers/Concerns

- ~~**Open decision (Phase 9 gate):** GitHub org/repo slug for the Releases API URL.~~ **Resolved 2026-05-19** — slug is not a Phase 9 concern. `release.yml` runs inside GitHub Actions and uses `$GITHUB_REPOSITORY` automatically. The configurable slug belongs to Phase 10 via `GITHUB_RELEASE_REPO` in `.env`, consumed by `update_from_github.sh --check`.
- ~~**Action version pins (Phase 9):** `actions/checkout@v4`, `softprops/action-gh-release@v2`.~~ **Verified 2026-05-19** via GitHub REST API (`/repos/{org}/{repo}/releases`): current stable majors are `actions/checkout@v6` (latest v6.0.2) and `softprops/action-gh-release@v3` (latest v3.0.0). Phase 9 plans pin to v6 / v3.
- ~~**`scripts/` per-file exclusion list (Phase 7):** Confirm exact list of smoke test files to exclude individually.~~ **Resolved 2026-05-19** — `.gitattributes` uses `scripts/setup_github_labels.py` + `scripts/smoke_*` (forward-compatible pattern); verified by `git archive HEAD` preview that all three current smoke files are excluded.
- ~~**🔴 v1.2 ship-blocker — systemd venv path mismatch (found 2026-05-20 during Phase 11 planning):** `deploy/vuln-reports.service:42` pointed `ExecStart` at the flat `/opt/vuln-reporting/.venv` path, but the updater builds a per-release `current/.venv` — unit would fail to start and trigger auto-rollback on every upgrade.~~ **Resolved 2026-05-20** (quick task `260520-a29-systemd-venv-path`) — `ExecStart` now uses `/opt/vuln-reporting/current/.venv/bin/python`; `deploy/` is clean of the old path. RUNBOOK references left to Phase 11's rewrite (11-02 already specifies `current/.venv` cron lines).

## Quick Tasks Completed

| Date | Slug | Subject | Commits |
|------|------|---------|---------|
| 2026-05-07 | rag-cell-width-shrink | Shrink Board Summary RAG cell width 62mm→55mm (empirical bisect after iter-1's 58mm proved insufficient) — closes Phase 03 UAT Test 3 | a1584b2, 9b47419, d7ea6d5 |
| 2026-05-13 | composed-report-slug (260513-9cf) | New `composed_report` slug for YAML-driven module composition — schema enum + conditional, registry-aware dry-run validation, generic `reports/composed_report.py`, two new test files; backward compatible (status: complete, 8 commits) | 917e1cb, 8e2f1f3, cf8a272, 1307560, 9049d46, 6e982d1, 56334bd, 9510566 |
| 2026-05-14 | tenable-assets-compliance-reference-docs | Two field reference docs in `docs/`: `tenable_assets_api_reference.md` (v1+v2 with per-field version indicators and migration summary) and `tenable_compliance_api_reference.md` (single-version reference). Mirrors style of existing `tenable_vuln_api_reference.md`. No code changes. | 73510eb |
| 2026-05-14 | github-contribution-templates | Scaffolded `.github/ISSUE_TEMPLATE/{config,feature_request,enhancement,bug_report,chore}.yml` + `.github/PULL_REQUEST_TEMPLATE/{feature,enhancement,fix}.md` + `CONTRIBUTING.md`. Tailored to project stack (Python + pyTenable + WeasyPrint); PII checklist enforced as required on bug reports; PR templates include issue-first gate notice. Required by `/gsd-inbox` triage. | 8ad2828 |
| 2026-05-14 | stop-syncing-data-trend-to-github-and-sc (260514-mlk) | Untracked `data/trend/*.json` (3 files w/ aggregate severity counts + internal Owner tag names), added `data/trend/` to `.gitignore`, scrubbed all history via `git filter-repo` (230 commits rewritten), force-pushed `main` (29fddd0→5bdb866) + tags v1.0/v1.1. Backup at `origin/backup/pre-trend-scrub-2026-05-14`. **Outstanding:** backup branch still contains the sensitive data — delete after confidence window to complete scrub. | 5bdb866 |
| 2026-05-20 | systemd-venv-path (260520-a29) | Fixed v1.2 ship-blocker: `deploy/vuln-reports.service` `ExecStart` pointed at flat `/opt/vuln-reporting/.venv` but updater builds per-release `current/.venv` — unit would fail to start and auto-rollback every upgrade. Repointed to `current/.venv`; synced `STACK.md` intel. RUNBOOK refs left to Phase 11. | 884e415 |
| 2026-05-20 | close-v12-audit-gaps (260520-mp4) | Closed all 3 v1.2 milestone-audit findings: B-01 (added `shared/data/trend` to systemd `ReadWritePaths` — `management_summary` was being denied the trend-JSON write under hardening), W-01 (fixed DEPLOYMENT.md breadcrumb/swap step order to match code), W-02 (documented the updater's sudoers requirement + run-as-root alternative). Added install-base relocation guidance (unit `sed` recipe + `INSTALL_ROOT` env var, with the chicken-and-egg note). Synced REQUIREMENTS.md traceability (39× Open→Verified) + ticked 8 requirement boxes. | 7b32a18 |
| 2026-05-20 | deploy-smoke-scripts (260520-n7j) | Added `deploy/smoke_test.sh` (network-free RHEL-9 systemd smoke: B-01 trend-write positive test + negative control that fails loudly if the sandbox isn't enforcing, plus `--list`/`--rollback`/auto-rollback mechanics against a fake `git archive` layout) and `deploy/smoke_bootstrap.sh` (Rocky/Alma 9 dnf provisioner). Both `export-ignore`'d from the slim tarball. Closes the documented post-merge-smoke gap; full run happens on a real RHEL-family host. | 8a1b160 |
| 2026-05-22 | apply-5-deployment-fixes (260522-kyy) | 5 fixes surfaced by the v1.2.0 clean-machine deployment walkthrough on a Rocky 9 VM: DEPLOYMENT.md Steps 6-7 missing `sudo -u vuln-reports` prefix (operator hit Permission denied) (#1), paste-fragile multi-line Verify commands → added `&&` one-liners (#2), no step created `shared/delivery_config.yaml` + broken Schema-Migration ref → added tracked `delivery_config.example.yaml` (placeholder/example.invalid) + a seed step (#3), stale Tenable verify expected-output corrected to real `tenable_client.py` strings (#4); systemd `StartLimitIntervalSec`/`StartLimitBurst` moved `[Service]`→`[Unit]` (were silently ignored — restart-storm cap was inert) (#5, ships in v1.2.1). Code/docs commit split. | ccee1c5, 8a1555a |
| 2026-05-22 | harden-update-from-github-sh-python3-res (260522-mf3) | v1.2.2 fix: `update_from_github.sh` hardcoded bare `python3` at two sudo call sites (venv provisioning + `--check` tag parse), failing with `command not found` on a normal RHEL/Rocky 9 host that has `python3.11`/`python3.9` but no `/usr/bin/python3` — and `2>/dev/null` masked it as a misleading "could not parse tag_name". Added `resolve_python_bin()` (prefer bare `python3` ≥3.10, else highest `python3.13→3.10`, else exit 8 with an `alternatives` hint), called once in `main()` after `assert_layout`; wired `$PYTHON_BIN` into both call sites; removed the parse `2>/dev/null`. DEPLOYMENT.md documents the prereq + `alternatives --install` one-liner. Validated end-to-end (upgrade/rollback/force) on vuln-dev Rocky 9 VM before the fix. Shipped in v1.2.2. | 63938d1, b3ab105, 6071d5f |
| 2026-05-22 | add-release-retention-pruning-prune-auto (260522-o2h) | Release GC for the updater (no retention previously existed — every release dir + its heavy `.venv` persisted forever). Added `RELEASE_RETENTION=3` constant, single `prune_releases <keep_n>` helper (semver `sort -V`, keep N newest), `--prune` command + `--keep N` override (validated via `usage_error`/exit 2, no new exit code), and auto-prune on the cmd_install happy path (after health check, before `log_completed success`; unreachable on failure since `auto_rollback` always exits 12/13). Safety: active (`current` target) + `.last` rollback target always preserved even outside keep-N; inside-`releases/` guard re-asserted before every `rm -rf`; deletes best-effort/non-fatal. Validated end-to-end on the Rocky 9 VM with dummy releases: `--keep 2` and `--keep 1` both removed only the dummies and preserved active + `.last` (incl. `.last` outside the keep window). DEPLOYMENT.md documents `--prune`/`--keep`/auto-prune. | b644860, a0be4a1, 9aab6bb |
| 2026-05-22 | fast: prune-summary IFS fix | Follow-up to 260522-o2h found during VM validation: global `IFS=$'\n\t'` made the `prune_releases` summary print tag lists newline-joined (`kept 2 (v1.2.1\nv1.2.2)`); scoped `local IFS=' '` to the summary printf. Cosmetic only. | fda6070 |
| 2026-05-22 | fast: dry-run env-form doc | DEPLOYMENT.md Verify step: made the env-prefixed (`HOME`/`XDG_CACHE_HOME`/`MPLCONFIGDIR` → `runtime-cache`) dry-run the recommended command. Manual `sudo -u` doesn't inherit the systemd `Environment=`, so matplotlib warned about the unwritable `/home/vuln-reports` (account is `--no-create-home`). Kept the simpler form documented as still-valid. Found on the Rocky 9 VM. | 7f1d6fb |
| 2026-06-02 | updater-chown-release-dir (260602-jqg) | Updater left new release dirs `root:root` when run as root (the documented default); the service (`User=vuln-reports`, `ProtectSystem=strict`, install tree `chmod 750`) can't read a root-owned release dir/`.venv`, so the post-swap health check auto-rolled-back every clean root-run upgrade. Added `fix_release_ownership()` (called after `provision_venv`/`symlink_shared`, before the `PARTIAL_RELEASE_DIR=""` disarm so the EXIT trap still cleans a partial dir on failure): when running as root, `chown -R` the new release dir back to the owner of `${INSTALL_ROOT}/releases` (GNU `stat -c '%U:%G'`, **derived not hardcoded** → alternate `INSTALL_ROOT` like `/opt/storage/vuln-reporting` needs no special-casing); non-root invocations skip (files already owned correctly); skips when already correct; fail-loud new **exit 16** on stat/chown failure; no `-L`/`-H` (with maintainer comment) so `shared/` symlinks aren't dereferenced. DEPLOYMENT.md now documents both invocation models (run-as-root default vs. service-account) + `HTTP(S)_PROXY`/`NO_PROXY` proxy guidance for the service-account path (set on the invocation/wrapper, not `shared/.env`). **UNVERIFIED on the Windows dev box — operator must confirm on the RHEL/Rocky VM that a root-run upgrade leaves the release dir + `.venv` service-account-owned and the health check passes.** Static checks only here (`bash -n` clean, E2E suite green). | 2179eb5, 9ff0249 |
| 2026-06-03 | relocate-crontab-setup-docs (260603-c6u) | Documentation-architecture fix: cron-scheduling setup (a first-time server task) lived only in RUNBOOK.md + `crontab.example`, while DEPLOYMENT.md (the setup guide) referenced `warm_cache` only in passing. Moved the canonical cron setup + the two `warm_cache` timing rules into DEPLOYMENT.md as a new "Schedule reports with cron (alternative to the systemd daemon)" subsection under Verify — now the single source of truth (crontab.example install cmd, TIMING RULE A/B in full, `cd`+per-release `.venv` gotcha, all-paths-together `INSTALL_ROOT` note linking "Relocating the install base", cron-or-daemon-not-both, un-rotated `.cron.log` pointer). Trimmed RUNBOOK.md's "Operational Cron Schedule" to day-to-day operator actions (adjust timing when groups change, check `warm_cache.log`/`.cron.log`, troubleshoot `[CACHE HIT]` misses) cross-referencing DEPLOYMENT.md (8 refs) with zero timing-rule duplication. `deploy/crontab.example` left untouched (its inline TIMING RULE A/B comments are correctly placed for an operator editing the crontab). Docs-only, no code. | 0df053e, 0ee60f5 |
| 2026-06-03 | fast: gitignore test scratch + remove data dump | Deleted `tests/debug_fetch2.txt` (raw Tenable export dump — real hostnames/IPs/MACs/asset UUIDs, same leak class as the prior `data/trend` scrub) and added `.gitignore` rules for local-only diagnostic/analysis scratch (`tests/diagnose_*.py`, `analyze_*.py`, `validate_*.py`, `test_modules_level*.py`, `tests/**/debug_*.txt`) so the 8 hand-run scripts stop showing as untracked. Verified patterns match zero tracked files (real pytest suite unaffected). Docs/hygiene only. | 7e64321 |
| 2026-06-05 | fast: release-trigger 3-part semver glob | Hardened `.github/workflows/release.yml` push-tags trigger from `'v*'` to `'v[0-9]*.[0-9]*.[0-9]*'` so a bare 2-part milestone tag (e.g. `v1.3`) can't start a release run that would then fail the strict SemVer regex at the Resolve-version step. Milestone label = `vX.Y` (planning only, never tagged); ship/patch releases = `vX.Y.Z`. Verified glob: matches `v1.2.0`/`v1.2.0-rc1`/`v10.20.30`, rejects `v1.3`/`v1.0`/legacy `pre-trend-scrub`. Strict regex retained as defense-in-depth. CI-config only. | ddd94fd |
| 2026-06-04 | fix-recast-rules-parquet-cache-write-fai (260604-bxa) | `warm_cache --prune-stale` logged a non-fatal `WARNING: Could not write cache file recast_rules.parquet: Can't infer object conversion type` whenever a recast/accept rule carried a real `expires_at` (e.g. `2027-05-31`). Root cause: `fetch_recast_rules()` (data/fetchers.py) normalized its date columns with an **in-place** `df.loc[:, col] = _parse_iso_utc(df[col])`, which preserves the column's existing `object` dtype and stuffs `Timestamp` objects into it — fastparquet then can't serialize the object column. It had been written that way (obs 827) to silence a false-positive pandas-2.2 ChainedAssignment warning that plain `df[col] =` emits. Dormant until now because every rule was `expires_at="Never"` → all-NaT object column (serializes fine). Fix: replaced the loop with the `df.assign(**updates)` pattern already used by `_normalize_vuln_dates`/`_normalize_asset_dates` in the same file — yields true `datetime64[ns, UTC]`, writes parquet cleanly, AND is warning-free. Verified via local repro (recast-shaped frame with one real `expires_at` + one `"Never"`): correct dtype + fastparquet round-trip. Surgical 1-block change; `_parse_iso_utc`/`_normalize_*` untouched. | ecfcdef |
| 2026-06-08 | tag-vs-env-severity-share-and-vuln-type (260608-cma) | New tag-vs-environment report via two auto-discovered composed modules. `tag_severity_share`: VPR-pure severity (Critical/High/Medium/Low/**None** where None=`vpr_score` null/0, **no native fallback** — deliberate divergence from `vpr_to_severity`, see spec D3); each severity % = tag count ÷ **environment grand total** (forwarded as `env_vuln_total` via gated `**kwargs` in `composed_report.py`, mirroring `_MODULES_NEEDING_FIXED_VULNS`). `vuln_type_distribution`: VTD-01 family-override CPE classifier (Linux distro/MS-Bulletin→OS, then `a/o/h`, else Other), within-tag %, Hardware hidden at 0. Four-channel render contract on both. 102 unit tests pass (VPR boundary/None edges, classifier labelled samples, env-share /0 guard, empty-data guard ×4 channels); `run_all.py --dry-run` validates all 5 groups. Two auditor runbooks added. Spec: `docs/superpowers/specs/2026-06-08-tag-severity-env-share-and-vuln-type-design.md`. **Outstanding:** example YAML group is written to disk + dry-run-validated but NOT committed (`delivery_config.yaml` is gitignored per commit `fb94c60`); operator must add the group to their live config. **Decoupled follow-up:** ROADMAP backlog **SEV-NONE-01** (global `vpr_to_severity` 0/null→None) captured, not yet built. | 3a13011, 8d04320, 4ad9694, fde8b60, 1edd9bc |
| Phase 12 P01 | 25 | 2 tasks | 2 files |
| Phase 12 P02 | 35 | 2 tasks | 2 files |
| Phase 12 P03 | 20 | 1 tasks | 1 files |

## Deferred Items

Carried forward from v1.0 + v1.1; not in scope for v1.2 or v1.3.

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| backlog | GEN-01/02: migrate `management_summary` + `ops_remediation` to module render contract | deferred | 2026-05-08 |
| backlog | GEN-03/04: YAML-driven module composition (partially landed via `composed_report` slug 2026-05-13) | partially deferred | 2026-05-08 |
| backlog | PERF-01..04: per-batch enrich cache, midnight cache crossover, log rotation, tag-value typo detection | deferred | 2026-05-08 |
| backlog | LEGACY-01: re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles | deferred | 2026-05-08 |
| janitorial | `run_all.py:76,90` stale `_VALID_FREQUENCIES` / `_VALID_REPORTS` constants | deferred (cosmetic) | 2026-05-08 |
| cleanup | Phase 3 W3 deprecated aliases (`_PDF_RAG_STRIP_TEMPLATE`, `_build_rag_strip_page`) | deferred (cosmetic) | 2026-05-08 |
| backlog | composed_report output filenames are hardcoded to `composed_report.{pdf,xlsx}` — every group with `reports: [composed_report]` writes the same basenames in its run folder. Need per-group disambiguation (slugified `report_title`, explicit `output_basename:` YAML field, or slugified group name). Captured during Phase 6 chrome rollout once multiple composed groups became plausible. | deferred | 2026-05-13 |

## Session Continuity

Last session: 2026-06-08T21:03:51.850Z
Stopped at: Phase 12 context gathered
Resume file: None
Next command: `/gsd:plan-phase 12`
