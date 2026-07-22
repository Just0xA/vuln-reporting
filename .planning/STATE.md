---
gsd_state_version: 1.0
milestone: v1.6
milestone_name: Delivery Config at Scale
status: Awaiting next milestone
stopped_at: Phase 21 context gathered
last_updated: "2026-07-10T11:22:29.408Z"
last_activity: 2026-07-10 — Milestone v1.6 completed and archived
progress:
  total_phases: 2
  completed_phases: 2
  total_plans: 8
  completed_plans: 8
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-10)

**Core value:** Right metric, right audience, right channel — without writing a new report each time.
**Current focus:** Planning next milestone (v1.6 shipped 2026-07-10)

## Current Position

Phase: Milestone v1.6 complete
Plan: —
Status: Awaiting next milestone
Last activity: 2026-07-22 — Completed quick task 260722-lx9: exclude accepted/recast from KPI modules + add accepted_recast board metric

## Shipped Milestones

- ✅ **v1.3 Trend & Segmentation Substrate** (2026-06-11) — see [`MILESTONES.md`](MILESTONES.md). 2 phases (12–13), 8 plans, 52 files / +8,811 LOC. 13/13 requirements satisfied; audit passed. Reopened-aware `open_findings_at()` + `data/trend_store.py` forward-accumulating snapshots + `extract_owner()` S2 segmentation + S1×S2 composition. Full archive: [`milestones/v1.3-ROADMAP.md`](milestones/v1.3-ROADMAP.md), [`milestones/v1.3-REQUIREMENTS.md`](milestones/v1.3-REQUIREMENTS.md).
- ✅ **v1.2 Deployment & Self-Update Infrastructure** (2026-05-22) — see [`MILESTONES.md`](MILESTONES.md). 5 phases (7–11), 10 plans, 65 files / +11,667 LOC. 39/39 requirements satisfied; audit passed. Tarball install/update/rollback via `scripts/update_from_github.sh`, CI release pipeline, hardened systemd unit; released v1.2.0–v1.2.4 (incl. python3 resolution, release pruning, daemon `LiveError` fix), all VM-validated. Full archive: [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md), [`milestones/v1.2-REQUIREMENTS.md`](milestones/v1.2-REQUIREMENTS.md). Audit: [`v1.2-MILESTONE-AUDIT.md`](v1.2-MILESTONE-AUDIT.md).
- ✅ **v1.1 PDF Chrome Redesign** (2026-05-13) — see [`MILESTONES.md`](MILESTONES.md). 2 phases, 9 plans, 49 files / +7305 LOC across 1 day. All 16 v1.1 requirements satisfied. Shared `PdfChrome` utility wired into `board_summary` + `composed_report` via `_CHROME_AWARE_SLUGS` allowlist; legacy renderers byte-unchanged. Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md), [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md). Audit: [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md).
- ✅ **v1.0 Modular Reporting Framework** (2026-05-08) — see [`MILESTONES.md`](MILESTONES.md). 4 phases, 19 plans, 1 quick task, 140 commits across 4 days. All 24 v1 requirements Validated. Full archive: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md), [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md), [`milestones/v1.0-phases/`](milestones/v1.0-phases/). Retrospective: [`RETROSPECTIVE.md`](RETROSPECTIVE.md).

## Performance Metrics

(Reset at milestone boundary; accumulates as v1.4 phases ship.)

| Phase | Plan | Duration (s) | Tasks | Files |
|-------|------|-------------|-------|-------|
| 16-mttr-rework | 03 | 540 | 3 | 5 |
| Phase 16-mttr-rework P04 | 900 | 3 tasks | 2 files |
| Phase 16-mttr-rework P05 | 600 | 3 tasks | 1 files |
| Phase 16-mttr-rework P06 | 540 | 3 tasks | 5 files |
| Phase 17-program-health-overview P03 | 1800 | 3 tasks | 2 files |
| Phase 18-management-summary-migration-docs P01 | 600 | 3 tasks | 10 files |
| Phase 18-management-summary-migration-docs P02 | 2700 | 4 tasks | 4 files |
| 18-management-summary-migration-docs | 03 | 2700 | 3 | 4 |
| 18-management-summary-migration-docs | 04 | multi-session | 4 | 7 |
| 18-management-summary-migration-docs | 05 | multi-session | 2 | 1 |
| Phase 19 P01 | 900 | 3 tasks | 5 files |
| Phase 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio P02 | 1800 | 3 tasks | 5 files |
| Phase 19 P05 | 900 | 3 tasks | 5 files |
| Phase 19 P07 | 2700 | 3 tasks | 17 files |
| Phase 19 P19-10 | 2400 | 4 tasks | 2 files |
| Phase 20-config-language-loader-matrix P01 | 1080 | 3 tasks | 3 files |
| Phase 20-config-language-loader-matrix P02 | 13min | 2 tasks | 2 files |
| Phase 20-config-language-loader-matrix P03 | 3min | 2 tasks | 2 files |
| Phase 20-config-language-loader-matrix P04 | 300 | 2 tasks | 7 files |

## Accumulated Context

### Roadmap Evolution

- v1.4 roadmap created 2026-06-11: 5 phases (14–18), 17 requirements, 100% coverage.
- Phase numbering continues from v1.3 (ended Phase 13); v1.4 starts at Phase 14.
- Phase 19 added: v1.4 Closure: INT-WARN-1/2/3 fixes, Phase 17 human verification, Phase 16 UAT, CodeRabbit findings
- v1.6 roadmap created 2026-07-09: 2 phases (20–21), 7 requirements (CONF-01/02/03/04/05, QUAL-06/07), 100% coverage. Phase numbering continues from v1.4 (ended Phase 19; v1.5 label consumed by a release tag, not a milestone); v1.6 starts at Phase 20. Phase 20 = config language + resolve-before-validate loader + deliveries.d/ split + delivery matrix + effective-config golden test. Phase 21 = private config repo + CODEOWNERS + CI gate + production cutover with one dual-source fallback cycle.

### Decisions

Decisions logged in PROJECT.md "Key Decisions" table. Prior milestone decision logs archived at `milestones/v1.0-ROADMAP.md`, `milestones/v1.1-ROADMAP.md`, `milestones/v1.2-ROADMAP.md`, and `milestones/v1.3-ROADMAP.md`.

- [Phase ?]: D-15 enforced: run_report() signature frozen — kwargs injected via ReportComposer fan-out only
- [Phase ?]: D-16: trend gate forwards full read_trend() dict {snapshots,insufficient_data} under trend_snapshots; recast gate forwards recast_rules_df
- [Phase ?]: D-17: frozensets seeded with sc4_kwargs_stub only in Phase 14; real v1.4 module IDs added by the phase that builds them
- [Phase 16-03]: Fingerprint-guard approach for board_summary baselines — live-data-origin baselines cannot be reproduced synthetically; hard-coded expected constants detect structural drift; zero-match cold-start path reproduced via _make_composer
- [Phase 16-03]: pytest.mark.baseline registered in pytest.ini for --strict-markers compliance (structural self-guard tests require committed baseline JSON files)
- [Phase 16-03]: CoW test fixture isolation — warnings from fixture code filtered to reports/ source path only to avoid false positives from fixture helpers
- [Phase 18-03]: D-18-08 LOCKED — one-time idempotent all-assets reconstruction script seeds ~12mo MoM history from Tenable fixed+open exports before Plan 04 cutover; tag-scoped scopes intentionally cold-start (pre-existing, no active group is tag-scoped on management_summary)
- [Phase 18-03]: D-18-03/change-7 LOCKED — reconstructed months (incl. current month) are immutable; capture_snapshot() skips any month already present with source='reconstructed'
- [Phase 18-03]: Overlap gate outcome (weaker-confidence path, by design) — live_open=210267 == reconstructed_total=210267, abs_diff=0, rel_diff=0.0% PASS; no prior captured months existed so primary captured-month gate ran as live-today fallback; synthetic-integration primary gate verified via unit tests
- [Phase 18-03]: 2026-06 pre-existing snapshot left intact (source=unknown; immutability respected regardless of source field)
- [Phase 18-04]: GEN-01 COMPLETE — management_summary atomically migrated from ~2,200-line bespoke path to ReportComposer pipeline composing 7 modules; chrome-aware PDF; modular email; 12mo all-assets trend wired via read_trend(); bespoke path removed in single commit (QUAL-04, D-18-10 gate 4 GREEN); per-metric parity gate passes (5 exact-match zero drift, M5/M7 documented-difference confirmed by operator visual UAT APPROVED); legacy JSON archived to data/trend/legacy_archive/
- [Phase 18-04]: Bucketed parity gate (USER-APPROVED) — comparison_policy per metric read from golden JSON; exact-match asserts zero drift; documented-difference metrics (M5 aged_vulns_assets, M7 new_vs_remediated) excluded from exact assert; M5 fixture gap (missing 'owner' column in synthetic fixture) is a known fixture limitation, not a production bug — real-data render confirmed correct by operator UAT
- [Phase 20-config-language-loader-matrix P01]: Directory-presence (deliveries.d/ next to config_path) is the sole mode switch for the config loader — no new CLI flag (D-01)
- [Phase 20-config-language-loader-matrix P01]: owner + contact-name travel via a metadata_by_delivery_name side channel returned by resolve_config, kept off the schema-gated group dicts since delivery_config.schema.yaml has additionalProperties:false at the group level (D-09)
- [Phase 20-config-language-loader-matrix P02]: contacts.example.yaml holds contacts + defaults only (no deliveries:), mirroring delivery_config.example.yaml's header-comment + example.invalid convention; one contact overrides reply_to, one does not, to document both paths
- [Phase 20-config-language-loader-matrix P02]: dry-run directory-mode surfacing block gated on the deliveries.d presence check, same mode switch (D-01) used by _load_config; warnings keep exit 0, errors flip exit 1
- [Phase 20-config-language-loader-matrix P03]: scripts/generate_delivery_matrix.py renders owner+contact NAME exclusively from resolve_config's metadata_by_delivery_name side channel, never email.recipients/cc (D-05 PII invariant) — Markdown default, --format html opt-in
- [Phase 20-config-language-loader-matrix P04]: Legacy fixture inline email: blocks hand-computed to pre-bake analyst-team@example.invalid into cc/reply_to per resolve_delivery_email's logic, so legacy and migrated-twin fixtures resolve to byte-identical effective configs (D-07 two-way equality)
- [Phase 20-config-language-loader-matrix P04]: Added scoped .gitignore exception for tests/fixtures/phase20_config_legacy/delivery_config.yaml — the bare delivery_config.yaml ignore rule (real production config exclusion) collided with the required synthetic fixture filename

### v1.4 Plan-Time Open Decisions (lock per phase)

These are NOT milestone-scoping decisions — each must be locked in the plan context of the phase that implements the affected module. Recommended resolutions are in `research/SUMMARY.md`.

| # | Decision | Phase | Recommended Resolution |
|---|----------|-------|------------------------|
| OD-1 | "New" inflow: `first_found` only vs `OR resurfaced_date` | Phase 15 | `first_found` only; document limitation |
| OD-2 | Density denominator definition | Phase 14 | On-time-scanned licensed assets (board_summary consistency) |
| OD-3 | S1 snapshot dimension extension shape (reopened/exception/new-fixed) | Phase 15 | Extend `capture_snapshot`; avoid proliferating snapshot files |
| OD-4 | MTTR resolved-population (exclude reopened? recast? first-fix only?) | Phase 16 | Option B: exclude current-REOPENED population |
| OD-5 | Program Health composite-RAG threshold rule | Phase 17 | Green = all 4 green; Amber = 2–3 green; Red = 0–1 green |
| OD-6 | External exposure MoM trend mechanism | Phase 14 | Defer MoM trend to v1.5; current-snapshot-only in v1.4 |
| OD-7 | MTTR rework MODULE_ID | Phase 16 | New `mttr_trend` MODULE_ID; `mttr_by_severity` untouched |
| OD-8 | management_summary legacy trend-JSON migration vs cold start | Phase 18 | **LOCKED 2026-06-18 → reconstruct-backfill ~12mo from Tenable (D-18-01); cold-start recommendation SUPERSEDED. See `phases/18-management-summary-migration-docs/18-CONTEXT.md`** |
| Phase 14 P01 | 15 | 2 tasks | 2 files |
| Phase 14 P02 | 315 | 2 tasks | 3 files |
| Phase 14-shared-substrates-composed-report-gates P03 | 65 | 4 tasks | 3 files |

### v1.4 Cross-Cutting Constraints (enforced every phase)

- **Cold-start branch mandatory (QUAL-01):** Every MoM module branches on `read_trend()` `insufficient_data` flag before computing deltas. First verified Phase 15; enforced in Phases 16, 17, 18.
- **Reopened-aware predicate mandatory (QUAL-02):** `open_findings_at()` two-interval form for all open-count logic. No naive `last_fixed null OR last_fixed>D` form.
- **Empty-data guard on all four channels (QUAL-03):** `safe_pct`/`safe_int`/`safe_format` + `_empty_result()` on zero-row inputs. First verified Phase 15; enforced in all subsequent phases.
- **Aggregate-only PII (QUAL-05, D-04-08):** Test fixtures and baselines use synthetic data only. No real hostnames, IPs, plugin names, or asset-level fields in committed artifacts. First verified Phase 15; enforced in all phases.
- **pandas 3.0 CoW: `.assign()` only** — never `df["col"] = val` after a filter or slice. Every module phase.
- **Zero new dependencies** — requirements.txt unchanged; stdlib `ipaddress` for IP classification; no new pip packages.
- **GEN-01 backward compat (QUAL-04):** Existing `management_summary` delivery must work throughout the milestone. Smoke baseline script committed as the first commit of Phase 18, before any migration code.

### v1.3 Settled Constraints (carried forward)

- **S1 is snapshot-capture; reconstruction is now ALSO viable (REVISED 2026-06-18).** ~~Spike 002: ~29-day Tenable fixed-retention wall forbids backfill.~~ **The "~29-day wall" was an API default (no time filter), NOT platform retention — real fixed retention is ~15–16mo, retrievable via a bounded `last_fixed`.** Phase 18 reconstructs ~12mo (OD-8/D-18-01). Forward snapshots still mandatory beyond the retrievable window. See `project_tenable_fixed_retention_trend` memory.
- **Reopened-aware predicate is mandatory.** The naive `last_fixed null OR last_fixed>D` form drops ~19% of all findings (the entire REOPENED population). The two-interval model using `resurfaced_date` resolves it exactly.
- **Snapshots extend `data/trend/`, not a parallel store.** Must not regress `management_summary` or any other existing trend consumer.
- **PII discipline (D-04-08) applies to snapshot payloads.** Aggregate counts only; no hostnames, IPs, plugin names, or asset-level fields in persisted files.
- **SEG-03 exception list is operator-facing local output only.** Never committed, never emailed.

### Pending Todos

- **Pass bounded last_fixed lookback in fixed-vuln fetch (Phase 18)** — `2026-06-18-pass-bounded-last-fixed-lookback-in-fixed-vuln-fetch.md`. The 30-day fixed floor is a Tenable API default (no time filter), not retention; real retention ~15-16mo. Fetch rework + revisit OD-8 cold-start & Phase-16 MTTR window. (`include_unlicensed`/asset-licensing investigated & ruled out.)

### Blockers/Concerns

None at roadmap creation.

## Quick Tasks Completed

Quick tasks completed through v1.4 are archived in [`MILESTONES.md`](MILESTONES.md) ("Quick Tasks Archive") — moved 2026-07-02 to keep STATE.md session-load lean. Append new quick tasks below; archive them at milestone close.

| Date | Slug | Subject | Commits |
|------|------|---------|---------|
| 2026-07-09 | fix-lingering-pre-v1-5-0-doc-defects-sta (260709-dux) | Final cleanup sweep before shipping v1.5.0 (internal `.planning/` docs only, no code). Fixed the stale codebase map `.planning/codebase/STACK.md` (×2 "Python 3.10+"→"3.12+"; line 8 now cites the real floor source `pyproject requires-python >=3.12` / `.python-version` instead of the old "CLAUDE.md declares 3.10+"), and filled two commit-hash placeholders left by task 260709-ar2 (STATE row `(docs commit)` and SUMMARY frontmatter `<docs-commit>` → `f4f8b4c, 11e71f5`). Frozen `.planning/research/*` / `phases/18-*` / STATE history rows mentioning 3.10+ left as historical records. Intel system is disabled (no `.planning/intel/`); STACK.md is a `/gsd:map-codebase` doc, hand-fixed. | f9e71a6 |
| 2026-07-09 | make-declared-python-floor-consistently- (260709-buj) | Final pre-v1.5.0 doc-consistency fix: made the declared Python floor consistently **3.12** (decision "3.12 everywhere"), resolving the split where pyproject/CONTRIBUTING said 3.12 but CLAUDE.md/PR-templates said 3.10+. Changed CLAUDE.md + `.planning/PROJECT.md` tech-stack line "Python 3.10+"→"3.12+" (PROJECT.md synced so a GSD regen won't revert CLAUDE.md), and dropped the "- [ ] 3.10" checkbox from the 3 PR templates. pyproject `>=3.12` / `.python-version` / CONTRIBUTING already correct — untouched. Frozen `.planning/research/*`, `phases/18-*`, and STATE history rows left as historical records; `.planning/codebase/STACK.md` still cites 3.10+ (stale intel, internal/export-ignored — refresh via `/gsd:intel`). All authoritative sources now agree on 3.12. | b538e09 |
| 2026-07-09 | land-v1-6-v2-0-roadmap-v1-7-validation-s (260709-ar2) | Reference-only intake of the externally-authored (other-chat) forward roadmap: landed `.planning/roadmap-v1.6-v2.0.md` (v1.4.x→v2.0 milestones, candidate Phases 20–41, dependency graph, kill-switches — verbatim + a 2026-07-09 intake-reconciliation blockquote: HK-01 already done via 260709-983, v1.5→v1.6 numbering pending the held v1.5.0 release, compliance seeds already in-repo) and `.planning/specs/milestone-spec-validation-substrate.md` (v1.7 VAL-01…10 spec). Added a forward pointer to ROADMAP.md Milestones ("🔜 v1.6 → v2.0"). NO milestone opened, no requirement-tracker/phase artifacts, no PROJECT.md edit; sibling Downloads artifacts (CLAUDE.md/SKILL.md/STATE.md) deliberately not imported (already applied). Next: ship held v1.5.0, then clear HK-02…07 and open v1.6 via `/gsd:new-milestone`. | f4f8b4c, 11e71f5 |
| 2026-07-09 | apply-2026-07-02-harness-optimization-pa (260709-983) | Selectively applied the drifted 2026-07-02 `harness-optimization.patch` after blob-level reconciliation. **Applied (6 clean hunks):** activated + hardened the `block_tenable_fetch.py` PreToolUse hook by adding the previously-missing `.claude/settings.json` that wires it (Hard Rule 1 enforcement was inactive without it), plus `tests/test_block_tenable_fetch.py` (26 tests green) and minor `SKILL.md`/`vuln-metric-substrate.md`/`CONVENTIONS.md` edits. **CLAUDE.md:** patch target blob `289de1d` was byte-identical to the working-tree rewrite already present — committed it (Hard-Rules invariants + restructure; restores SLA-table Medium=60 to match `config.py`, correcting the stray 45 left in HEAD by 260709-7ww). **Archive move (rebased):** applied the MILESTONES.md "Quick Tasks Archive" (+21 pre-v1.4 rows) and pruned exactly those rows from the current STATE.md with a pointer note, keeping the two post-v1.4 rows — avoided the stale patch's STATE.md hunk (would have dropped newer rows/duplicated). CLAUDE.md + STATE.md excluded from `git apply`; handled deliberately. | 6862d4d, 3dfa847, ddc0b8d |
| 2026-07-09 | migrate-deploy-docs-scripts-ci-from-pyth (260709-7ww) | Made deploy docs/scripts/CI consistent with the Python 3.12 baseline the uv migration already set (`pyproject requires-python>=3.12`, `.python-version 3.12`, local `.venv` 3.12) — docs/config only, no app logic. Bumped `python3.11`→`3.12` in DEPLOYMENT.md (RHEL AppStream install, `--version`, `alternatives`, `python -m venv`), RUNBOOK.md, `deploy/smoke_bootstrap.sh` (dnf + alternatives/symlink), and the failure-message example in `scripts/update_from_github.sh` (resolver `for name in python3.13..3.10` loop **preserved** — back-compat probing is fine). "Python 3.10+"→"3.12+" in CLAUDE.md (×2) + CONTRIBUTING.md; dropped the `3.11` checkbox from 3 PR templates + `feature_request.yml` (`3.12` box already present). Added a DEPLOYMENT.md note that `requirements.txt` is the supported server install path and uv/devcontainer is dev-only. `pyproject.toml`/`.python-version` untouched; `apscheduler==3.11.0` pin untouched. `.github/workflows/release.yml` pins no Python (uses no `setup-python`) so left unchanged. Folded in two pre-existing uncommitted edits (CLAUDE.md SLA-table Medium 60→45; DEPLOYMENT.md stray `GITHUB_RELEASE_REPO=owner/repo` removal). Whole-repo 3.11 gate clean. **Operational follow-up:** servers need Python 3.12 installed and per-release `.venv`s rebuilt on 3.12 before deploying the next release. | c8bf9fc, 81cd13b |
| 2026-07-22 | exclude-accepted-recast-findings-from-kp (260722-lx9) | Two coordinated modular-reporting changes. **(A)** New shared helper `board_report_utils.exclude_risk_managed(df)` (empty/missing-column safe, case-insensitive, returns `.copy()` per Hard Rule 5; re-exported at `reports.modules` package level) that drops findings whose `severity_modification_type` ∈ {ACCEPTED, RECASTED}. Applied **unconditionally** at the top of `compute()` in `high_risk_assets` + `aged_vulns_assets` (filters `vulns_df`) and `critical_remediation_sla` (filters the `fixed_vulns_df` FIXED population; removed the now-redundant WR-03 local exclusion block). Risk-accepted/recast findings stay `state=open` and previously inflated these KPIs — a correctness defect — so this intentionally shifts board_summary **and** management_summary **and** composed_report numbers. `scan_coverage_sla` untouched (assets-only); `accepted_recast` deliberately NOT filtered (it surfaces that population). **(B)** Wired the existing `accepted_recast` module in as the **5th** board_summary metric (Accepted/Recast-by-Owner) — added `ModuleConfig("accepted_recast")` to `_BOARD_MODULE_CONFIGS`, plus a local `read_trend` + fail-soft `fetch_recast_rules` fetch forwarded to `ReportComposer` (mirrors management_summary; Part-B3 tag scoping correctly skipped — `fetch_recast_rules` has no `asset_uuid`). New tests: `test_board_report_utils.py`, `test_kpi_risk_managed_exclusion.py`, `test_board_accepted_recast.py` (+ `read_trend` stub added to `test_phase6_board_summary_chrome.py` to keep it hermetic). 23 new tests green; full suite 894 passed / 5 pre-existing unrelated failures (stub-registry pollution in `test_modules.py`), zero new regressions vs baseline. Docs: `board_summary_calculations.md` + CLAUDE.md slug row (4→5 metrics). **1 auto-fixed deviation** (Rule 1): empty-series index `"owner"` name in `compute_bu_risk_scores()` to avoid `KeyError:'owner'` on zero-qualifying-asset results. **Operator follow-up:** regenerate the 3 `tests/baselines/board_summary_test_pull*.json` structural baselines via `smoke_board_summary_cutover.py` against warmed parquet (Hard Rule 1 — cannot be done in Claude Code; not touched here). | e3fef65, dbc50b9, 2ffe785, c9764bf |
| 2026-07-01 | add-tech-debt-by-owner-metric-module-per (260701-da9) | New auto-discovered `tech_debt_by_owner` composed module: ranks each **Owner** tag value by its count of **overdue open Critical+High** findings and RAG-rates them (green=0 / amber 1–4 / red≥5, thresholds option-overridable via `green_max`/`amber_max`) across all four channels + the cover RAG strip (strip status = worst per-owner status). v1 scope = per-owner overdue Crit/High **count** only — the fuller multi-dimensional framing (missing-patch / legacy-EOL / misconfiguration) is captured as **explicit future work**, not built. Owner derived in-module from `assets_df` tags joined on `asset_uuid` (default `Owner` category via `board_report_utils.extract_owner`; custom `owner_category` option via inline `Cat=Val` parser; missing/unmatched → `(Unassigned)`) — **ZERO edits** to `composed_report.py` / composer / `run_all.py` / CLAUDE.md slug list (pure auto-discovery via `*_module.py` + `@register_module`). Severity VPR-primary with native fallback; overdue per `sla_calculator` (open states, `today - first_found > SLA_DAYS[sev]`). Hard empty-data guard (`safe_*` + `_empty_result`; filtered-to-zero must not crash). 33 unit tests (owner parse/join, Crit/High counting, RAG buckets, `(Unassigned)`, 4-channel empty-data guard) all green; module registered (19 total discovered). Becomes usable when a group lists `tech_debt_by_owner` under a `composed_report` `modules:` array in `delivery_config.yaml`. | 5e38346, 654e042 |

## Deferred Items

Carried forward from prior milestones; not in scope for v1.4 (except GEN-01 which is v1.4 scope).

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| v1.4 scope | GEN-01: migrate `management_summary` to module render contract | **In scope — Phase 18** | 2026-05-08 |
| backlog | GEN-02: migrate `ops_remediation` to module render contract | deferred | 2026-05-08 |
| backlog | GEN-03/04: YAML-driven module composition (partially landed via `composed_report` slug 2026-05-13) | partially deferred | 2026-05-08 |
| backlog | PERF-01..04: per-batch enrich cache, midnight cache crossover, log rotation, tag-value typo detection | deferred | 2026-05-08 |
| backlog | LEGACY-01: re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles | deferred | 2026-05-08 |
| janitorial | `run_all.py:76,90` stale `_VALID_FREQUENCIES` / `_VALID_REPORTS` constants | deferred (cosmetic) | 2026-05-08 |
| cleanup | Phase 3 W3 deprecated aliases (`_PDF_RAG_STRIP_TEMPLATE`, `_build_rag_strip_page`) | deferred (cosmetic) | 2026-05-08 |
| backlog | composed_report output filenames are hardcoded to `composed_report.{pdf,xlsx}` — every group with `reports: [composed_report]` writes the same basenames in its run folder. Need per-group disambiguation (slugified `report_title`, explicit `output_basename:` YAML field, or slugified group name). Captured during Phase 6 chrome rollout once multiple composed groups became plausible. | deferred | 2026-05-13 |

### Acknowledged at v1.6 close (2026-07-10)

`gsd-sdk query audit-open` flagged 18 quick_tasks as `missing` at the v1.6 close — the **same detector false positive** documented under the v1.3-close root-cause note below (audit resolves `<quick-dir>/SUMMARY.md`, but gsd-quick writes the prefixed `<quick-dir>/<quick-id>-SUMMARY.md`). All 18 are completed tasks from prior milestones (v1.2–v1.4) with commits logged in MILESTONES.md; 17 carry a prefixed `SUMMARY.md`, one (`260520-a29-systemd-venv-path`) predates the summary convention. None are v1.6 work. The v1.6 milestone audit is `passed` (7/7 requirements, 5/5 integration, 1/1 flow). Acknowledged and proceeded.

| Category | Count | Disposition |
|----------|-------|-------------|
| quick_tasks | 18 | Detector false positive (unprefixed-`SUMMARY.md` path quirk); all complete, all prior-milestone work. Slugs: 260514-mlk, 260520-a29/mp4/n7j, 260522-kyy/mf3/o2h, 260602-jqg, 260603-c6u, 260604-bxa, 260608-cma, 260611-b1x, 260701-da9, 260709-7ww/983/ar2/buj/dux. |

### Acknowledged at v1.4 close (2026-06-26)

`gsd-sdk query audit-open` flagged 14 items at the v1.4 close — all verified **non-blocking** (the v1.4 milestone audit is `passed`, 17/17 requirements, 0 broken flows). Acknowledged and proceeded.

| Category | Count | Disposition |
|----------|-------|-------------|
| quick_tasks | 12 | Detector false positive (filename quirk — see note below; all complete with commits, mostly v1.2/v1.3 work). The v1.4 task `260626-elj` was cleared by adding an unprefixed `SUMMARY.md`. |
| uat_gaps | 1 | `16-UAT.md` is `status: passed` with 0 open scenarios — false positive (Phase 16 UAT confirmed 2026-06-26). |
| todos | 1 | `2026-06-18-run-coderabbit-on-phase-18` — work resolved in Phase 19 (39 CodeRabbit findings cleared, D-06); the reminder file is an untracked `.planning/todos/pending/` leftover. |

### Acknowledged at v1.3 close (2026-06-11)

`gsd-sdk query audit-open` flags 12 quick tasks as "missing summary" — a **detector false positive**, not open work. All are complete, logged above in "Quick Tasks Completed" with commits. Acknowledged and proceeded with the v1.3 close.

**Accurate root cause (corrected at v1.4 close 2026-06-26):** the earlier "omits a `status:` field" explanation was wrong. `audit-open` resolves the SUMMARY at `<quick-dir>/SUMMARY.md` (unprefixed), but gsd-quick writes `<quick-dir>/<quick-id>-SUMMARY.md` (prefixed). The unprefixed path isn't found → "missing". The prefixed file already carries `status: complete` (the executor writes it). Go-forward clean-up: drop an unprefixed copy (`cp <id>-SUMMARY.md SUMMARY.md`) in the quick dir — verified to clear the detector. `uat_gaps` with `status: passed`/0 open scenarios and resolved-but-uncommitted `.planning/todos/pending/` files are similar false positives.

## Session Continuity

Last session: 2026-07-10 — Milestone v1.6 completed and archived
Stopped at: v1.6 milestone close (archived + tagged)
Resume file: —
Next command: `/gsd:new-milestone`

## Operator Next Steps

- Start the next milestone with /gsd-new-milestone
