---
gsd_state_version: 1.0
milestone: v1.2
milestone_name: milestone
status: verifying
stopped_at: v1.2 roadmap defined; 5 phases mapped to 39 requirements.
last_updated: "2026-05-20T12:27:43.182Z"
last_activity: 2026-05-20
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 9
  completed_plans: 9
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-19)

**Core value:** Right metric, right audience, right channel — without writing a new report each time.
**Current focus:** Phase 08 — warm-cache

## Current Position

Phase: 11 — COMPLETE (final phase of v1.2)
Plan: 2 of 2
Status: Verified — 11-VERIFICATION.md status: passed (5/5 DOC reqs). All v1.2 phases (7,8,9,10,11) complete; milestone ready for audit/close.
Last activity: 2026-05-22 — Completed quick task 260522-o2h: added release retention/pruning (--prune + auto-prune) to the updater. Pending v1.2.3 release + real-symlink --prune validation on the Rocky 9 VM. (Prior: 260522-mf3 python3 hardening shipped in v1.2.2.)

## Shipped Milestones

- ✅ **v1.1 PDF Chrome Redesign** (2026-05-13) — see [`MILESTONES.md`](MILESTONES.md). 2 phases, 9 plans, 49 files / +7305 LOC across 1 day. All 16 v1.1 requirements satisfied. Shared `PdfChrome` utility wired into `board_summary` + `composed_report` via `_CHROME_AWARE_SLUGS` allowlist; legacy renderers byte-unchanged. Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md), [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md). Audit: [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md).
- ✅ **v1.0 Modular Reporting Framework** (2026-05-08) — see [`MILESTONES.md`](MILESTONES.md). 4 phases, 19 plans, 1 quick task, 140 commits across 4 days. All 24 v1 requirements Validated. Full archive: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md), [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md), [`milestones/v1.0-phases/`](milestones/v1.0-phases/). Retrospective: [`RETROSPECTIVE.md`](RETROSPECTIVE.md).

## Performance Metrics

(Reset at milestone boundary; accumulates as v1.2 phases ship.)

## Accumulated Context

### Decisions

Decisions logged in PROJECT.md "Key Decisions" table. Prior milestone decision logs archived at `milestones/v1.0-ROADMAP.md` and `milestones/v1.1-ROADMAP.md`.

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
| 2026-05-22 | add-release-retention-pruning-prune-auto (260522-o2h) | Release GC for the updater (no retention previously existed — every release dir + its heavy `.venv` persisted forever). Added `RELEASE_RETENTION=3` constant, single `prune_releases <keep_n>` helper (semver `sort -V`, keep N newest), `--prune` command + `--keep N` override (validated via `usage_error`/exit 2, no new exit code), and auto-prune on the cmd_install happy path (after health check, before `log_completed success`; unreachable on failure since `auto_rollback` always exits 12/13). Safety: active (`current` target) + `.last` rollback target always preserved even outside keep-N; inside-`releases/` guard re-asserted before every `rm -rf`; deletes best-effort/non-fatal. Harness validated keep/preserve math incl. targets outside keep window. Real-symlink `readlink` resolution still to be confirmed on a Linux VM. DEPLOYMENT.md documents `--prune`/`--keep`/auto-prune. | b644860, a0be4a1, 9aab6bb |

## Deferred Items

Carried forward from v1.0 + v1.1; not in scope for v1.2.

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

Last session: 2026-05-20T12:27:43.175Z
Stopped at: v1.2 roadmap defined; 5 phases mapped to 39 requirements.
Resume file: None
Next command: `/gsd:plan-phase 7`
