# Milestones

Living record of shipped versions. Each entry summarizes scope, accomplishments, and key outcomes. Full milestone details live in `.planning/milestones/v[X.Y]-ROADMAP.md` and `.planning/milestones/v[X.Y]-REQUIREMENTS.md`.

---

## v1.4 — Management Summary Reporting Improvement

**Shipped:** 2026-06-26
**Phases:** 6 (14–19) | **Plans:** 35 | **Tasks:** 62
**Timeline:** 2026-06-11 → 2026-06-26
**Git range:** `6119120` (Phase 14 start) → `bf661aa`
**Files changed:** 194 | **LOC delta:** +50,434 / −2,777
**Requirements:** 17/17 satisfied (SUB-01..03, RPT-01..07, QUAL-01..05, GEN-01, DOC-02); milestone audit passed
**Known deferred at close:** 14 `audit-open` items, all verified non-blocking false positives (see STATE.md "Deferred Items")

**Delivered:** The June-2026 management/exec trend-cut report batch built as thin four-channel modules on the shipped S1 (trend) + S2 (Owner) substrates, plus the GEN-01 `management_summary` migration onto the `ReportComposer` module pipeline — so each audience's report is assembled from a shared metric library rather than a bespoke render path.

**Key accomplishments:**

- **Shared substrates + composed_report gates (SUB-01/02/03, Phase 14):** `utils/external_scope.py` (tag/public-IPv4 external classifier + mismatch list, stdlib `ipaddress`), `utils/asset_count.py` (`count_on_time_assets` denominator + `config.ON_TIME_SCAN_WINDOW_DAYS`), and two new `composed_report.py` frozenset gates (`_MODULES_NEEDING_TREND_SNAPSHOTS`, `_MODULES_NEEDING_RECAST_RULES`) fanning `read_trend()` + `recast_rules_df` through `ReportComposer` to module `compute()` — proven by an auto-discovered SC#4 stub.
- **Five new four-channel metric modules (RPT-01/02/03/04/06, Phase 15):** New vs Remediated, Vulnerability Density (per-snapshot denominator + >10% drift flag), Reopened Vulnerabilities (live-tenant schema confirmed — 30,010 REOPENED rows, 100% `resurfaced_date`), Accepted & Recast (separate counts, expiry-aware), and External/DMZ Exposure (locked mismatch schema) — all cold-start-safe and zero-row-safe across PDF/Excel/email/analyst channels.
- **MTTR rework (RPT-05, Phase 16):** new `mttr_trend` module with a disclosed rolling-~30-day window, sample-weighted overall mean, reopened-aware COALESCE clock (kills reopen-cycle inflation — 198d→8d on the lodestar fixture), and an always-on 4-gauge severity band + focus-driven Owner/Application table; legacy `mttr_by_severity` left byte-unchanged so board_summary groups don't regress.
- **Program Health Overview (RPT-07, Phase 17):** single-page composite MoM velocity dashboard — OD-5 composite RAG with a structural missing-signal Amber cap, 4-tile KPI row, sparklines, and an Owner velocity table with >20% outlier flagging; cold-start renders "Trend Being Established" instead of NaN.
- **management_summary migration + docs (GEN-01/QUAL-04/DOC-02, Phase 18):** atomic cutover from the ~2,200-line bespoke path to `ReportComposer` (7 modules, chrome-aware, modular email), ~12mo all-assets trend reconstruction (overlap-gate PASS: live_open=210267 == reconstructed, 0 diff) behind a bounded `last_fixed` fetch + zero-drift consumer audit, and auditor calculation runbooks; per-metric parity gate green (5 exact-match, 2 documented-difference confirmed by operator UAT).
- **v1.4 closure (Phase 19):** INT-WARN-1/2/3 fixed, 39 CodeRabbit findings cleared, all deferred 15/17/18-REVIEW findings resolved, shared `compute_sla_rate_crit_high` helper across 3 sites; Phase 16 UAT + Phase 17 human checks operator-confirmed — milestone audit flipped `tech_debt` → `passed`.

**Post-close:** re-audit finding **REAUDIT-WARN-1** (management_summary snapshot persisted `reopened_count`/`sla_rate_crit_high` as `None`) fixed via quick task `260626-elj` — inline compute mirroring the cron writer, report output unchanged.

---

## v1.3 — Trend & Segmentation Substrate

**Shipped:** 2026-06-11
**Phases:** 2 (12–13) | **Plans:** 8
**Timeline:** 2026-06-08 → 2026-06-11
**Git range:** `90b02bb` (Phase 12 start) → `966a2da`
**Files changed:** 52 | **LOC delta:** +8,811 / −373
**Requirements:** 13/13 satisfied (TREND-01..07, SEG-01..05, DOC-01); milestone audit passed

**Delivered:** The two shared substrates under the June-2026 report batch — a forward-accumulating trend-snapshot mechanism (S1) and an Owner/Application segmentation helper (S2) — so v1.4 report modules become thin consumers instead of re-inventing trend and segmentation each time.

**Key accomplishments:**

- **Forward-accumulating trend substrate (TREND-01..07):** reopened-aware two-interval `open_findings_at()` predicate (`utils/open_count.py`) — the naive single-interval form silently dropped ~19% of findings (the entire REOPENED population); `data/trend_store.py` capture/read with `scripts/capture_trend_snapshot.py`. Cold-start-safe, idempotent, aggregate-counts-only (D-04-08 PII), extends `data/trend/` without regressing `management_summary`'s private path.
- **Owner segmentation helper (SEG-01/02/04):** `extract_owner(assets_df)` parses `Owner=`/`Application=` tags (one row per asset, fail-soft); migrated all board/management modules from "Business Unit" → Owner terminology.
- **Owner/Application analyst worklist (SEG-03):** combined `reports/owner_supplemental.py` Excel+CSV writer (gitignored `output/` only, never emailed/committed), wired fail-soft into `board_summary`; `Unassigned` rows double as the tagging-cleanup worklist.
- **S1×S2 composition (SEG-05):** owner-dimension snapshots via `capture_snapshot(dimension="owner", …)` with deterministic dedup; `read_trend` round-trip verified.
- **Calculation runbooks (DOC-01):** auditor-facing docs for the trend and owner-segmentation substrates.

**Post-milestone tech debt closed:** quick task `260611-b1x` deduped the owner_supplemental asset-count path (phantom-row over-count) and removed the pandas-3.0 CoW chained-assignment on the open-count column; the third audit item (`open_findings_at` NaT-FIXED over-count) was verified already-fixed (`71207e6`) and regression-tested, not re-touched.

**Key design constraints (settled by spikes):**

- S1 is snapshot-capture only — Tenable's ~29-day fixed-retention wall forbids backfill (Spike 002). Cold start is real.
- The open-count primitive must use the reopened-aware two-interval predicate; the naive form silently drops ~19% of findings (all REOPENED).
- Snapshots extend the existing `data/trend/` store; no parallel store; `management_summary` must not regress.
- Snapshot payloads are aggregate counts only (D-04-08 PII discipline).
- SEG-03 analyst exception list is operator-facing local output; never committed or emailed.

**Known deferred items at close:** 12 (see STATE.md Deferred Items) — all are completed quick tasks whose SUMMARY frontmatter omits a `status:` field, so `audit-open` reports them as "missing"; acknowledged as a detector false positive, not open work.

**Founding analysis:** [`notes/report-requests-batch-2026-06.md`](notes/report-requests-batch-2026-06.md), [`notes/trend-reconstruction-engine.md`](notes/trend-reconstruction-engine.md), [`spikes/MANIFEST.md`](spikes/MANIFEST.md) (Spikes 001–003).

---

## v1.2 — Deployment & Self-Update Infrastructure

**Shipped:** 2026-05-22 (v1.2.0)
**Phases:** 5 (7–11) | **Plans:** 10
**Timeline:** built 2026-05-19 → 2026-05-20; released and field-hardened 2026-05-22 on a Rocky 9 VM
**Git range:** `5c90d9c` (milestone start) → `v1.2.4` (`ce0bcf3`)
**Files changed:** 65 | **LOC delta:** +11,667 / −1,245
**Requirements:** 39/39 phase-verified satisfied

**Delivered:** A production deployment and self-update story for the suite. A non-author operator can install, upgrade, and roll back on a single Linux server from a signed release tarball — no git clone — driven by `scripts/update_from_github.sh`, with a CI pipeline that publishes those tarballs automatically and authoritative deployment docs.

**Key accomplishments (by phase):**

- **Phase 7 — Foundations:** `/opt/vuln-reporting/{current,releases,shared}` symlink layout; `.gitattributes` `export-ignore` boundary defining the slim release tarball; hardened `deploy/vuln-reports.service` systemd unit (`ProtectSystem=strict` + explicit `ReadWritePaths`, runtime-cache `HOME`/`XDG_CACHE_HOME`/`MPLCONFIGDIR`).
- **Phase 8 — Warm Cache:** `scripts/warm_cache.py` pre-fetch so scheduled batches hit `[CACHE HIT]` instead of redundant Tenable exports.
- **Phase 9 — CI / Release Automation:** `.github/workflows/release.yml` — pushing a `v*` tag builds `vuln-reporting-vX.Y.Z-slim.tar.gz` + `.sha256`, blocks forbidden paths, marks `-rc/-beta/-alpha` as prereleases, and publishes a GitHub Release.
- **Phase 10 — Install / Update / Rollback:** `scripts/update_from_github.sh` with `--check`/`--list`/`--version`/`--rollback`/`--force`/`--skip-restart` — SHA256-verified download, per-release venv, shared-path symlinks, atomic `ln -sfn` swap, `.last` breadcrumb, post-swap health check with auto-rollback, and a printed rollback one-liner.
- **Phase 11 — Documentation:** root `README.md`, authoritative `DEPLOYMENT.md` (tarball install/upgrade/rollback), operations-scoped `RUNBOOK.md`, and `deploy/crontab.example`.

**Releases:**
| Tag | Date | Summary |
|-----|------|---------|
| `v1.2.0` | 2026-05-22 | Initial deployment-infrastructure release (milestone ship). |
| `v1.2.1` | 2026-05-22 | Clean-machine deployment-walkthrough fixes: systemd `StartLimit*` moved `[Service]`→`[Unit]` (restart cap was inert), tracked `delivery_config.example.yaml`, `sudo -u vuln-reports` prefixes + paste-safe one-liners, stale Tenable verify text. |
| `v1.2.2` | 2026-05-22 | Updater resolves a versioned `python3` (≥3.10) on RHEL hosts that ship `python3.9`/`python3.11` but no `/usr/bin/python3`; removed the error-masking `2>/dev/null`. |
| `v1.2.3` | 2026-05-22 | Release retention: `--prune` command + `--keep N` and auto-prune on successful install (keep 3); active + `.last` rollback target always preserved. |
| `v1.2.4` | 2026-05-22 | Fixes `rich.errors.LiveError` when concurrent scheduled groups run in daemon mode — per-call `Console` + disable live display on non-TTY. |

**Verification:**

- 5/5 phase verifications passed (Phases 7–11); 39/39 requirements satisfied.
- Milestone audit `v1.2-MILESTONE-AUDIT.md` status: passed (original `gaps_found` closed by quick task `260520-mp4`).
- v1.2.0 → v1.2.4 each validated end-to-end on a real Rocky 9 VM: install, upgrade, rollback, force-overwrite, real-symlink prune (incl. rollback-target preservation), daemon-mode concurrency (no `LiveError`), and live email delivery.

**Notable surprises (all caught on the real RHEL VM, not the Windows dev box):**

- systemd `ExecStart` pointed at a flat `.venv` while the updater builds per-release `current/.venv` (ship-blocker; quick task `260520-a29`).
- `ProtectSystem=strict` made `ReadWritePaths` load-bearing — `management_summary`'s trend-JSON write was denied until `shared/data/trend` was added (`260520-mp4`).
- A normal RHEL host can have versioned Python only, no `python3` command → updater `command not found` under `sudo` (v1.2.2).
- Per-release venvs accumulate unbounded with no GC → `--prune` (v1.2.3).
- APScheduler runs same-time groups in concurrent threads sharing rich's process-global live-display lock → `LiveError` (v1.2.4).
- Two hand-edited `shared/.env` typos (`GITHUB_RELEASE_REPO`, SMTP) caused a 404 and a connection-refused; reinforced "check the VM's `.env` first."

**Archive:**

- [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md) — full phase + plan detail
- [`milestones/v1.2-REQUIREMENTS.md`](milestones/v1.2-REQUIREMENTS.md) — 39-requirement traceability
- [`v1.2-MILESTONE-AUDIT.md`](v1.2-MILESTONE-AUDIT.md) — milestone audit (status: passed)
- Post-release patches (v1.2.1–v1.2.4) tracked in [`STATE.md`](STATE.md) "Quick Tasks Completed".

---

## v1.1 — PDF Chrome Redesign

**Shipped:** 2026-05-13
**Phases:** 2 | **Plans:** 9
**Timeline:** 1 day (same-day discuss → plan → execute → UAT → close)
**Git range:** `0cda7bc` (Phase 5 context capture) → `c8f521d` (Phase 6 closeout)
**Files changed:** 49 | **LOC delta:** +7,305 / −166

**Delivered:** A shared PDF chrome design system applied to every page of every chrome-aware PDF report. The chrome lives in `reports/modules/pdf_chrome.py` and is wired through `ReportComposer` via an optional `pdf_chrome=` constructor kwarg. Two slugs (`board_summary` and `composed_report`) opt into chrome via the `_CHROME_AWARE_SLUGS` allowlist — meaning every future metric module added to a `composed_report` group inherits chrome with **zero per-slug Python**.

**Key accomplishments:**

- **`PdfChrome` utility** ships a single design-system surface: frozen `PdfChromeConfig` dataclass (`title`, `subtitle`, `generated_at`, `header_bg`, `logo_path`, `privacy_label`) feeds a `PdfChrome` class that emits CSS + header HTML + footer-separator HTML. Silent fallback to title-only when `LOGO_PATH` is unset/missing (CHROME-CFG-03, no log spam).
- **`position: fixed` chrome overlays** paint a full-width 15mm header band and a 1px footer separator edge-to-edge on every page. Replaced the initial margin-box approach after UAT revealed empty `@top-*` margin boxes collapse to zero width in WeasyPrint.
- **Cover body trimmed** to `Scope: <value>` subtitle + RAG strip (now headed "Key Performance Metrics"). Inline title, divider, `.cover-meta`, "Generated:" line, "Sections:" line all removed — those moved to chrome.
- **`_CHROME_AWARE_SLUGS` allowlist** is the single source of truth for chrome-kwarg injection. Legacy `management_summary` + `ops_remediation` byte-unchanged across the milestone — `git diff` returns 0 bytes for both.
- **Modular-framework parity:** `composed_report` inherits chrome on the same seam. Dropping a new `*_module.py` into a `reports: [composed_report]` group + `modules:` list gives it full chrome.
- **YAML knobs:** optional `privacy_label:` and `report_title:` per group; both default-safe (`"Confidential"` and the slug's built-in title respectively).
- **Operator-supplied logo** lives at `assets/logo.png` (`.gitignore`'d); `config.LOGO_PATH` resolves to it; silent-fallback if missing.

**Verification:**

- 2/2 phase verifications PASSED (Phase 5 PASS, Phase 6 PASS WITH NOTES)
- 16/16 requirements satisfied (3-source cross-reference clean)
- 37/37 tests green on the v1.1 surface
- Operator visual UAT approved both `board_summary` and `composed_report` renders
- 0-byte diff on `reports/management_summary.py` + `reports/ops_remediation.py` across the milestone

**Notable surprises:**

- **Empty margin boxes collapse in WeasyPrint.** Initial header design painted backgrounds on `@top-left/-center/-right`; empty boxes rendered zero-width, leaving visible gaps. Pivoted to `position: fixed` overlays with negative side offsets — predictable, pixel-perfect.
- **Latent `pdf_subtitle` double-prefix bug in composed_report.** When the cover template was changed to bake "Scope: " into itself, `composed_report` would have rendered "Scope: Scope: Production". Caught during the chrome-parity extension.
- **`_format_scope_subtitle` circular import.** Both consumers are imported via `importlib` from `run_all`, so they can't import the helper back. Inlined the 3-line helper in both. Defer factoring until > 2 consumers.
- **Same-day end-to-end delivery.** Milestone setup → close in 1 day. v1.0 was 4 days; v1.1 was 1 day because the milestone was scoped tight (chrome + one consumer + framework parity) and the v1.0 module contract did most of the heavy lifting.

**Carried to next milestone (acknowledged backlog):**

- composed_report output filename disambiguation (every group writes `composed_report.{pdf,xlsx}` today; needs per-group basenames).
- All v1.0 backlog still open: GEN-01/02, GEN-03/04, PERF-01..04, LEGACY-01, cosmetic janitorial.

**Archive:**

- [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md) — full phase + plan + UAT-cycle details
- [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md) — all 16 requirements traceability
- [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md) — aggregated milestone audit (status: passed)

---

## v1.0 — Modular Reporting Framework

**Shipped:** 2026-05-08
**Phases:** 4 | **Plans:** 19 | **Quick tasks:** 1
**Timeline:** 4 days (2026-05-05 → 2026-05-08)
**Git range:** `ea709a1` (Phase 1 first feat) → `028f188` (Phase 4 UAT close)
**Files changed:** 96 | **LOC delta:** +27,072 / −390

**Delivered:** A modular metric-rendering framework where each `BaseModule` subclass renders itself into 4 channels (PDF section, Excel tabs, email panel, analyst drill-down) — proven end-to-end against the Board Summary report's 4 metric modules with backward-compatible delivery to existing recipient groups.

**Key accomplishments:**

- **Module render contract** extended `BaseModule` with three new abstract methods (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) plus three new `ModuleData` fields (`driver_narrative`, `analyst_rows`, `rag_strip`). Empty-data guard pattern codified in CLAUDE.md and exercised by every render method.
- **`ReportComposer` upgrades** added `assemble_email_body()` (per-module HTML panels), `assemble_analyst_workbook()` (per-module Excel tabs + `_Metadata`), unified RAG-strip cover page, and `run_full_pipeline()` orchestrator that emits a typed bundle. D-22 bundle-driven email/analyst routing — no slug allowlists.
- **Board Summary migration** ported all 4 metric modules (`scan_coverage_sla`, `critical_remediation_sla`, `high_risk_assets`, `aged_vulns_assets`) to the new contract. Real-Tenable UAT-confirmed: PDF + standard Excel + analyst Excel + email panels all render correctly; populated and zero-data paths both clean.
- **YAML schema validation** wired `jsonschema` enforcement into every config load (`run_all.py:_load_config`). `_validate_group()` body REPLACED with a thin schema shim (single source of truth). Misconfigured YAML exits non-zero with offending group + field named.
- **`analyst_detail: false` opt-out** plumbed through `run_all.py:run_group()` → `board_summary.run_report()` → `composer.run_full_pipeline(generate_analyst=)`. No new abstractions; existing kwargs only.
- **Cutover smoke** (`scripts/smoke_board_summary_cutover.py`) is a sub-5-second deterministic structural-shape regression bar against 3 committed baselines. `_NoLiveTenable` sentinel hard-guards against accidental live API calls. Baselines store counts + booleans only — no metric values, no row-level data — per D-04-08 PII guard.

**Verification:**

- 4/4 phase verifications PASSED
- 3/3 phase UATs CLOSED (Phase 1 verifier-only; 2/3/4 with explicit UATs at 6/6 and 7/7)
- 38 tests green across 4 suites at milestone close
- 0 DRIFT against committed structural baselines

**Notable surprises:**

- WeasyPrint flex implementation consumes ~33-37mm of phantom space beyond the visible cell-width math in 65.1 — discovered via empirical bisect during a UAT-driven cover-layout fix. Pinned cells at 55mm with documented inline comment.
- Headline metric values drift daily with vulnerability churn — locking them in baselines would create false-positive alerts. D-04-05 was REVISED before Phase 4 planning to structural-only snapshots; visual operator confirmation remains the value-correctness gate.
- pandas 3.0 Copy-on-Write shifted the dtype-replacement semantics for chained-setter patterns. `.loc[:, col]=` preserved float64 where `df[col]=` had replaced it with int64. `.assign()` was the only pattern preserving int64 dtype AND zero ChainedAssignmentError warnings — documented at 3 risk_score sites.

**Carried to v2 (acknowledged backlog):**

- GEN-01/02: Migrate `management_summary` and `ops_remediation` to the new module contract.
- GEN-03/04: YAML-driven module composition (`modules: [...]` lists; `reports.<slug>.modules` map).
- PERF-01..04: per-batch `enrich_vulns_with_assets` cache, per-day cache midnight handling, log rotation, tag-typo detection.
- LEGACY-01: re-evaluate the 6 unbuilt reports listed in CLAUDE.md as candidate module bundles.
- Cosmetic janitorial: `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants in `run_all.py:76,90`.
- Deferred design: cover-page redesign (template-based on Report Title; "Generated" + Data Protection Label to footer).

**Archive:**

- [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md) — full phase + plan details
- [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md) — all 24 requirements traceability


---

## Quick Tasks Archive (moved from STATE.md 2026-07-02)

Detailed quick-task log through v1.4. New quick tasks append to STATE.md and are moved here at each milestone close.

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
| 2026-06-11 | close-two-open-v1-3-owner-supplemental-t (260611-b1x) | Closed the 2 genuinely-open v1.3 owner_supplemental tech-debt items the milestone audit deferred (the 3rd, P12 `open_findings_at` NaT-FIXED WR-01, was already fixed+tested in `71207e6` — verified, not re-touched). **WR-01 asset-count over-count:** `_build_owner_app_df` built `asset_counts` from the raw `enriched` frame, so a duplicate `asset_uuid` carrying differing Owner/Application tags was counted under multiple (owner,app) rows (phantom `asset_count=1/open_count=0`); fixed by deduping `enriched` on `asset_uuid` (keep-first) before the groupby, reusing that deduped frame for the open-count path too so the two columns stay consistent — mirrors the CR-01 keep-first pattern already in the file. **WR-02/CoW:** line ~139 `result["open_count"] = …fillna(0).astype(int)` was the one production line emitting a real pandas-3.0 `ChainedAssignmentError` FutureWarning (confirmed via `-W error::FutureWarning`; the audit-cited lines 128/129 did not warn — the warning fixtures did); converted all chained-assignment sites in the fn to `.assign()` per F-DTYPE. TDD: 2 new regression tests (`test_dup_uuid_asset_count_counts_once`, `test_open_count_no_chained_assignment_warning`). Also corrected the stale `v1.3-MILESTONE-AUDIT.md` (P12 WR-01 marked already-closed w/ corrected line ref 82-88→108-112; both P13 items marked resolved; frontmatter `tech_debt`→`passed`). Full suite green (exit 0); `utils/open_count.py` untouched. | b233ee3, 3586026, d175143 |
| 2026-06-26 | fill-management-summary-snapshot-reopene (260626-elj) | Closed v1.4 re-audit finding **REAUDIT-WARN-1**: `reports/management_summary.py` forwarded `reopened_count` + `sla_rate_crit_high` to `capture_snapshot()` but both resolved to `None` on every run — they were sourced via `_safe_metric()` from modules (`reopened_vulns`, `program_health`) NOT in `_MGMT_MODULE_CONFIGS`, and the INT-WARN-1 regression test only asserted kwarg KEY presence so it stayed green over the nulls. Fix: compute both INLINE in the snapshot block from `vulns_df`, mirroring the canonical cron writer (`scripts/capture_trend_snapshot.py`) — `reopened_count` via the REOPENED-state count (fail-soft None on missing `state` col), `sla_rate_crit_high` via `open_findings_at` + the shared D-05 `compute_sla_rate_crit_high(open_df, generated_at, SLA_DAYS)` helper (fail-soft None). `_MGMT_MODULE_CONFIGS` (the 7 rendered modules) left untouched so the audience-facing report is byte-identical (chosen over adding the 2 modules, which would have changed report content + broken the structural baseline). Strengthened the INT-WARN-1 guard with `test_reopened_and_sla_rate_forwarded_non_none` asserting NON-None values (fixture yields `reopened_count=1`, `sla_rate_crit_high=27.8`) — RED pre-fix, GREEN post-fix. Full `tests/test_management_summary.py` 17/17 (structural smoke + value-golden parity unchanged); `run_all.py --dry-run` validates all 5 groups. | 1276ccb, 4407a6a |
| 2026-06-08 | tag-vs-env-severity-share-and-vuln-type (260608-cma) | New tag-vs-environment report via two auto-discovered composed modules. `tag_severity_share`: VPR-pure severity (Critical/High/Medium/Low/**None** where None=`vpr_score` null/0, **no native fallback** — deliberate divergence from `vpr_to_severity`, see spec D3); each severity % = tag count ÷ **environment grand total** (forwarded as `env_vuln_total` via gated `**kwargs` in `composed_report.py`, mirroring `_MODULES_NEEDING_FIXED_VULNS`). `vuln_type_distribution`: VTD-01 family-override CPE classifier (Linux distro/MS-Bulletin→OS, then `a/o/h`, else Other), within-tag %, Hardware hidden at 0. Four-channel render contract on both. 102 unit tests pass (VPR boundary/None edges, classifier labelled samples, env-share /0 guard, empty-data guard ×4 channels); `run_all.py --dry-run` validates all 5 groups. Two auditor runbooks added. Spec: `docs/superpowers/specs/2026-06-08-tag-severity-env-share-and-vuln-type-design.md`. **Outstanding:** example YAML group is written to disk + dry-run-validated but NOT committed (`delivery_config.yaml` is gitignored per commit `fb94c60`); operator must add the group to their live config. **Decoupled follow-up:** ROADMAP backlog **SEV-NONE-01** (global `vpr_to_severity` 0/null→None) captured, not yet built. | 3a13011, 8d04320, 4ad9694, fde8b60, 1edd9bc |
