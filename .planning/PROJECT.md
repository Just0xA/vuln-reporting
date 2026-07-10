# Vulnerability Management Reporting Suite

## What This Is

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + paired analyst-detail companion workbook + per-module HTML email body — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

**As of v1.0:** every metric is a **module** that renders itself into 4 channels (PDF section, Excel tabs, email panel, analyst drill-down). Each named report (`board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets`) is a bundle of modules; recipient groups consume the bundle. The pattern is proven against Board Summary; v1's job was to establish the pattern, not to migrate every report.

## Core Value

**Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

## Current State

**All phases complete — v1.6 Delivery Config at Scale ready to close (2026-07-10):**
- **Phase 20 (2026-07-09):** resolve-before-validate config loader (`delivery/config_loader.py`), shared `contacts.yaml` + `defaults:` resolution, per-team `deliveries.d/` glob+merge with global delivery-name uniqueness, `--dry-run` error/warning surfacing, delivery-matrix generator (`scripts/generate_delivery_matrix.py`), and an effective-config golden test proving legacy and migrated twins resolve byte-identical (CONF-01/02/03/05, QUAL-06; 5/5 verified).
- **Phase 21 (2026-07-10):** D-04 automatic dual-source fallback loader + D-05 active-source surfacing (`run_all.py` `_select_config_source`/`_load_config`/`_dry_run` — directory-mode failure falls through to legacy instead of returning `[]`, logging the active source); private-repo CI gate, CODEOWNERS, and config-tree reference twins (`deploy/config-repo/*.example` — example.invalid/@ORG placeholders only, real config stays in the private corporate repo per Hard Rule 2); D-03 provenance stamp/verify script (`scripts/stamp_config_provenance.py`) and RUNBOOK reviewed-repo cutover runbook with the dual-source zero-interruption sequence (CONF-04, QUAL-07; 9/9 verified, operator cutover checkpoint approved).

**7/7 v1.6 requirements satisfied (CONF-01..05, QUAL-06, QUAL-07).** Milestone ready to archive via `/gsd:complete-milestone`.

**Shipped:** v1.4 Management Summary Reporting Improvement (2026-06-26) — see [`MILESTONES.md`](MILESTONES.md).

**Released 2026-07-09:** `v1.5.0` — a release tag cut to reconcile a dev-machine sync issue; it consumed the `v1.5` label, which is why the next *milestone* is **v1.6** (see [`roadmap-v1.6-v2.0.md`](roadmap-v1.6-v2.0.md)).

- 6 phases (14–19), 35 plans, 62 tasks across 2026-06-11 → 2026-06-26; 17/17 requirements satisfied (SUB-01..03, RPT-01..07, QUAL-01..05, GEN-01, DOC-02); milestone audit status: passed
- **Seven v1.4 metric modules on the four-channel contract:** New vs Remediated, Vulnerability Density, Reopened Vulnerabilities, Accepted & Recast, External/DMZ Exposure (Phase 15), reworked `mttr_trend` (Phase 16), and the Program Health Overview composite dashboard (Phase 17) — all consuming the S1 trend + S2 Owner substrates, cold-start-safe and zero-row-safe.
- **Shared substrates + gates (Phase 14):** `utils/external_scope.py` external classifier, `utils/asset_count.py` on-time-scanned denominator, and `composed_report.py` trend/recast kwargs frozenset gates fanning out through `ReportComposer`.
- **GEN-01 — `management_summary` migrated (Phase 18):** atomic cutover from the ~2,200-line bespoke path to `ReportComposer` (7 modules, chrome-aware, modular email), ~12mo all-assets trend reconstruction (overlap-gate 0-diff) behind a bounded `last_fixed` fetch + zero-drift consumer audit; auditor runbooks (DOC-02).
- **Closure (Phase 19):** INT-WARN-1/2/3 fixed, 39 CodeRabbit findings cleared, all deferred 15/17/18-REVIEW findings resolved, Phase 16 UAT + Phase 17 human checks operator-confirmed — audit flipped `tech_debt` → `passed`.
- Post-milestone: re-audit finding REAUDIT-WARN-1 (management_summary snapshot persisted `reopened_count`/`sla_rate_crit_high` as `None`) closed via quick task `260626-elj` — inline compute mirroring the cron writer; report output unchanged.

<details>
<summary>Previous shipped: v1.3 Trend & Segmentation Substrate (2026-06-11)</summary>

- 2 phases (12–13), 8 plans, 52 files / +8,811 / −373 across 2026-06-08 → 2026-06-11; 13/13 requirements satisfied (TREND-01..07, SEG-01..05, DOC-01); milestone audit status: passed
- **S1 — Trend snapshot substrate:** reopened-aware two-interval `open_findings_at()` open-count primitive (`utils/open_count.py`) — the naive single-interval form silently dropped ~19% of findings (all REOPENED); `data/trend_store.py` atomic capture/read with idempotent monthly overwrite, cold-start safety, and aggregate-only PII discipline; `scripts/capture_trend_snapshot.py` cron entry point.
- **S2 — Owner segmentation:** `extract_owner()` Owner/Application tag helper with a lossless `Unassigned` catch-all; combined analyst worklist (`reports/owner_supplemental.py`) wired fail-soft into `board_summary`; owner-dimension trend composition (S1×S2) proven end-to-end.
- Auditor runbook `docs/trend_and_segmentation_calculations.md` (DOC-01); post-milestone tech debt closed via quick task `260611-b1x`.

</details>

<details>
<summary>Previous shipped: v1.2 Deployment & Self-Update Infrastructure (2026-05-22)</summary>

- 5 phases (7–11), 10 plans, 65 files / +11,667 / −1,245 across 2026-05-19 → 2026-05-22 (released and field-hardened on a Rocky 9 VM)
- 39/39 requirements satisfied; milestone audit status: passed
- The suite installs, updates, and rolls back from signed release tarballs via `scripts/update_from_github.sh` — no git clone; SHA256-verified download, per-release `.venv`, shared-path symlinks, atomic `ln -sfn` swap, `.last` breadcrumb, post-swap health check with auto-rollback, retention (`--prune`/`--keep N`)
- `.github/workflows/release.yml` publishes `vuln-reporting-vX.Y.Z-slim.tar.gz` + `.sha256` on every `v*` tag; `scripts/warm_cache.py` decouples Tenable fetch latency from report-run wall time
- `/opt/vuln-reporting/{current,releases,shared}` symlink layout; hardened `deploy/vuln-reports.service`; authoritative `DEPLOYMENT.md` / `RUNBOOK.md` / `README.md` / `deploy/crontab.example`
- Released as v1.2.0 – v1.2.4 (post-ship fixes: inert systemd `StartLimit*`, versioned-`python3` resolution, release pruning, daemon-mode `LiveError`)

</details>

<details>
<summary>Previous shipped: v1.1 PDF Chrome Redesign (2026-05-13)</summary>

- 2 phases, 9 plans, 49 files changed across 1 day (2026-05-13 same-day discuss → plan → execute → UAT → close)
- 37 tests green on the v1.1 surface at milestone close
- Shared PDF chrome utility in `reports/modules/pdf_chrome.py` wired through `ReportComposer`; both `board_summary` and `composed_report` opt in via the `_CHROME_AWARE_SLUGS` allowlist
- Every page of every chrome-aware PDF renders a full-width header band (configurable bg + optional operator logo + report title) and a footer (privacy label / page number / "Generated On:" UTC timestamp) with a full-width separator line
- Cover body trimmed to `Scope: <value>` subtitle + RAG strip ("Key Performance Metrics" header)
- Modular-framework parity: adding a new `*_module.py` and listing it under `reports: [composed_report]` with `modules: [...]` gives it full chrome with **zero per-slug Python**
- Legacy `management_summary` + `ops_remediation` byte-unchanged across the milestone (CHROME-COMPAT-01 hard contract)

</details>

<details>
<summary>Previous shipped: v1.0 Modular Reporting Framework (2026-05-08)</summary>

- 4 phases, 19 plans, 1 quick task, 140 commits across 4 days
- 38 tests green at milestone close (composer regression 11/11, schema validation 6/6, analyst_detail toggle 3/3, baseline extractor 18/18)
- Board Summary delivers end-to-end: PDF (unified RAG-strip cover + 4 metric pages), standard Excel (4 tabs + `_Metadata`), analyst Excel (4 drill-down tabs), modular email body (4 per-module panels with inline gauges)
- `delivery_config.yaml` is jsonschema-enforced at startup; misconfigured groups fail loud
- `analyst_detail: false` per-group opt-out validated end-to-end
- Cutover smoke (`scripts/smoke_board_summary_cutover.py`) provides a sub-5-second structural-shape regression bar against PII-redacted committed baselines
- Codebase state: Module infrastructure exercised by `board_summary` (fully migrated). `management_summary` still on bespoke render path. `ops_remediation`, `vuln_export`, `unscanned_assets` use direct render code without the module contract.

</details>

**Codebase state (post-v1.2):** Five reports work end-to-end plus the YAML-driven `composed_report` slug. `board_summary` and `composed_report` are chrome-aware. `management_summary` + `ops_remediation` remain on legacy render paths (untouched); they will inherit chrome only after migration to the module contract (GEN-01/02 deferred). The suite is now server-deployable from signed release tarballs with scripted install/update/rollback (`scripts/update_from_github.sh`), CI-published artifacts (`.github/workflows/release.yml`), a standalone warm-cache job, and authoritative `DEPLOYMENT.md` / `RUNBOOK.md` / `README.md`.

## Current Milestone: v1.6 Delivery Config at Scale

**Goal:** Stop `delivery_config.yaml` from degrading as a shared cross-team surface. Separate the "who" (recipients) from the "what/when" (deliveries), split deliveries into per-team files with clear ownership, put the config under real version control with review, and make "who gets what, when" answerable without reading YAML.

**Why now:** Live production pain — one team receiving several reports means several stanzas, each duplicating the same recipients; updating a contact means editing every stanza; the file grows as (teams × reports). v1.6 has no downstream code dependents (see [`roadmap-v1.6-v2.0.md`](roadmap-v1.6-v2.0.md)), so it is sequenced first.

**Target capabilities (CONF-01…05):**

- **CONF-01** — Contacts extracted to a shared `contacts.yaml` (named contact groups + Exchange DL addresses); deliveries reference a contact by name, so recipient churn leaves the delivery files entirely.
- **CONF-02** — A `defaults:` block whose `analyst_mailbox` is the default Reply-To *and* a standing Cc on every delivery (analysts keep a record; any reply reaches them) — defined once, never repeated.
- **CONF-03** — Per-team `deliveries.d/<team>.yaml` split with `owner:` metadata; loader globs/merges and enforces global delivery-name uniqueness (fixes a latent missing-check bug). YAML key `groups:` → `deliveries:` (legacy `groups:` accepted as a deprecated alias during transition).
- **CONF-04** — Private internal config repo: CODEOWNERS per team file + a CI gate (schema validation + `run_all.py --dry-run` on the merged result); production consumes the repo instead of hand-edits over SSH.
- **CONF-05** — Delivery-matrix generator: deliveries × reports × schedule × filters × owner emitted as a published table.

**Phases:** continues from Phase 19 → **Phase 20** (config language + loader + matrix; CONF-01/02/03/05) and **Phase 21** (private repo + CI + CODEOWNERS + production cutover; CONF-04). **Long-lead:** private-repo provisioning goes through change management — start that request at milestone open, not at Phase 21.

Full requirement text + design decisions: [`REQUIREMENTS.md`](REQUIREMENTS.md). Forward roadmap (v1.6 → v2.0): [`roadmap-v1.6-v2.0.md`](roadmap-v1.6-v2.0.md).

**After v1.6 (leading candidates):** **GEN-02** (migrate `ops_remediation` to the module contract), **GEN-03/04** (broader YAML-driven module composition), the **MTTR window-widening** change (90-day/all-time), and **EXT-WAS-01 / EXT-TREND-01** (gated on a pyTenable-upgrade decision). The full forward plan is `roadmap-v1.6-v2.0.md`.

## Backlog (deferred from prior milestones)

- **GEN-01/02** — Migrate `management_summary` / `ops_remediation` to the module render contract (would automatically inherit chrome once added to `_CHROME_AWARE_SLUGS`).
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **composed_report output filename disambiguation** — captured during v1.1 once multiple composed groups became plausible.
- **PERF-01..04** — Performance pass.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.

## Deferred to Future Milestones

Carried from the v1.0 backlog (see `milestones/v1.0-REQUIREMENTS.md` v2 section):

- **GEN-01/02** — Migrate `management_summary` and `ops_remediation` to the module render contract.
- **GEN-03/04** — YAML-driven module composition (partially landed 2026-05-13 via the `composed_report` slug; remaining work is broader bundle definition in YAML).
- **PERF-01..04** — `enrich_vulns_with_assets` per-batch caching, per-day cache midnight crossover, log rotation, tag-value typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md (`executive_kpi`, `sla_remediation`, `asset_risk`, `patch_compliance`, `trend_analysis`, `plugin_cve`) as candidate module bundles.
- **Cosmetic janitorial** — `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants in `run_all.py:76,90`.

## Constraints

- **Tech stack**: Python 3.12+, `pyTenable` SDK, pandas (3.0-safe), openpyxl, WeasyPrint, matplotlib + plotly, Jinja2, APScheduler, tenacity, jsonschema — locked. No new SDK adoption without an explicit decision.
- **Email-client compatibility**: Outlook / Gmail / Apple Mail must render the per-module email panels. Inline CSS only; no `<style>` blocks; charts via base64 CID. Established and locked.
- **Backward compatibility**: Existing groups in `delivery_config.yaml` referencing `board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets` must continue to deliver. The v1 cutover protected this for `board_summary` (smoke baselines + visual operator UAT); v2 migrations of `management_summary` / `ops_remediation` will need similar regression protection.
- **Credential handling**: All Tenable + SMTP credentials via `.env` only — never hardcoded, never logged, never committed.
- **Fail-soft batch semantics**: A module render error must not kill the batch. Empty-data hardening (QUALITY-02) is a hard correctness bar; filtered-to-zero recipient groups are routine.
- **Sensitive data discipline (D-04-08)**: Test outputs, smoke logs, baseline files, and committed YAML must NOT contain row-level Tenable data (asset names, IPs, plugin names, etc.). Aggregate counts, structural shape, and synthetic test data are safe. Test recipient addresses use the RFC 6761 `example.invalid` domain.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| v1 = establish the modular pattern (not a polish pass) | User wants modules to be the durable unit of composition; eventually replace canned reports. Polishing Board Summary in isolation would build on a contract that wasn't finalized. | ✓ Good — pattern proven against Board Summary; v2 migration of `management_summary` and `ops_remediation` is now a clean job |
| Named report = bundle of modules | Keeps `delivery_config.yaml` recipient-readable (`reports: [board_summary]`) while letting the named bundle be defined as a module list internally. Direct module-list-in-YAML deferred to v2 (GEN-03/04). | ✓ Good — D-22 bundle-driven email/analyst routing landed without slug allowlists |
| Analyst companion always-paired with toggle | Today Board Summary always needs the drill-down (Manager + CISO review require it). Future delivery patterns may not. Toggle (`analyst_detail: true|false`) preserves both paths. | ✓ Good — toggle exercised end-to-end in Phase 4 (Plan 04-02) |
| Build the per-module email contract fresh, don't copy `management_summary` | `management_summary` did the module → existing-canned-report transform but didn't build customizable per-module email rendering. v1 built fresh against the contract; `management_summary` migrates in v2 against this contract. | ✓ Good — fresh bundle-driven path is cleaner than the legacy KPI-tile shell |
| Fold empty-data formatting hardening into v1 | Same code paths as the new render hooks; cheaper to bake the guard pattern in once. | ✓ Good — UAT Test 5 confirmed zero-match group renders gray no-data cells + "No data in scope." panels without crashing |
| Defer YAML-driven module composition to v2 | Lets v1 prove the render contract with hardcoded module lists before adding the user-facing config surface. | ✓ Good — v1 stayed tight; v2 GEN-03/04 is now a clean follow-on |
| D-01: Collapse PDF cover into unified RAG-strip cover | Phase 2 had separate cover (page 1) + RAG strip (page 2). Phase 3 unified them. | ✓ Good — single cover page replaces page-1+page-2 |
| D-04-01: Wave-0 enum reconcile MUST land before schema enforcement | `delivery_config.schema.yaml:60-69` `reports.items.enum` was missing `board_summary` and `unscanned_assets`. Turning on jsonschema before fixing the enum would brick the deployed Test Pull group on commit. | ✓ Good — preserved deployed group from being rejected on first commit |
| D-04-02: Replace `_validate_group()` body, no defense-in-depth | Two validators inevitably drift; the hand-rolled checks already missed format/dependencies/additionalProperties that the schema can express. Single source of truth wins. | ✓ Good — richer error messages from `jsonschema.Draft7Validator` |
| D-04-05 (REVISED): Structural-only baseline — no metric values | Operator clarified that headline % drift daily with vulnerability churn. Locking values would create false-positive alerts. Structural shape catches refactor regressions; visual operator confirmation remains the value-correctness gate. | ✓ Good — zero false-positive alerts on data churn; smoke is a deterministic <5s regression bar |
| D-04-08: Sensitive data MUST NOT enter conversation context | PII-class fields (hostnames, IPs, plugin names, etc.) belong only on the operator's machine. Default-redact with exact-match list + narrow substring backstop. Test recipients use `example.invalid` (RFC 6761). | ✓ Good — baselines store counts + booleans only; PII guard exercised in 18/18 baseline-extractor tests |
| v1.3: Substrates before report modules | Building any single June-2026 report first means inventing the trend engine inside it, then refactoring it out from under the others. Build S1/S2 as shared substrates so v1.4 reports are thin consumers. | ✓ Good — S1×S2 compose end-to-end (SEG-05); v1.4 reports consume `open_findings_at` + `extract_owner` directly |
| v1.3: Trend is snapshot-capture, NOT reconstruction | Spike 002: Tenable's ~29-day fixed-retention wall forbids backfill. History accumulates forward from the first snapshot; cold start is real. | ✓ Good — `data/trend_store.py` forward-accumulating + cold-start safe |
| v1.3: Reopened-aware two-interval open-count predicate is mandatory | The naive `last_fixed null OR last_fixed>D` form drops the entire REOPENED population (~19% of findings). The two-interval model using `resurfaced_date` resolves it exactly. | ✓ Good — `open_findings_at` unit-tested on OPEN/REOPENED/FIXED edges incl. NaT-FIXED (WR-01) |
| v1.3: Phase 14 created then removed — tech-debt premise was stale | A milestone-close audit deferred 3 substrate items into a new Phase 14. The headline item (`open_findings_at` NaT-FIXED over-count) was already fixed + regression-tested (`71207e6`); the other 2 were ~15 lines in one file. Phase removed; closed via quick task `260611-b1x`. | ✓ Good — verified before building; avoided a full phase for a trivial fix |
| v1.4 (D-18-01): Trend reconstruction overturns the v1.3 cold-start premise | Spike 002's "~29-day fixed-retention wall" assumed the API default; passing `last_fixed` reaches ~12–16mo of fixed history. v1.4 reconstructs ~12mo all-assets MoM history before the GEN-01 cutover instead of cold-starting `management_summary`. | ✓ Good — overlap gate PASS (live_open == reconstructed, 0 diff); provenance-marked immutable reconstructed months |
| v1.4 (OD-7): MTTR rework ships as new `mttr_trend` MODULE_ID, `mttr_by_severity` byte-unchanged | Reworking the existing module in place would have regressed board_summary groups that reference `mttr_by_severity`. A new MODULE_ID lets the corrected metric ship without touching the legacy one. | ✓ Good — board_summary baselines byte-identical; `mttr_trend` carries window disclosure + reopened-aware clock |
| v1.4: GEN-01 cutover guarded by structural smoke + bucketed parity, no dual-writer window | The ~2,200-line bespoke path was removed in the same commit that routed reads through `read_trend()`. Structural baseline (pre-cutover) + per-metric parity buckets (5 exact-match, 2 documented-difference) caught regressions without locking churning values. | ✓ Good — operator UAT APPROVED; existing groups deliver with zero YAML changes |
| v1.4: REAUDIT-WARN-1 fixed by inline compute, not by composing more modules | The post-close re-audit found 2 of 8 snapshot fields persisted as `None` because they were sourced from modules absent from `_MGMT_MODULE_CONFIGS`. Adding the modules would have changed the audience-facing report; computing the fields inline (cron-writer style) fixes the data with byte-identical report output. | ✓ Good — quick task `260626-elj`; report unchanged, snapshot fields now populated |
| v1.6: Resolve-before-validate loader | The loader resolves contacts/`defaults`/refs into a concrete `email:` block *before* schema validation, so the existing schema validates the *effective* config and every migrated file must resolve to today's group shape. Backward compat falls out for free; the current schema stays the single gate. | — Pending |
| v1.6: Nothing defined twice | Contacts + `defaults` live only in the shared `contacts.yaml`; per-team `deliveries.d/*.yaml` hold deliveries only. This is the guardrail that stops per-team splitting from re-duplicating the shared "who" one level up (the failure mode that would make the split worse than today). | — Pending |
| v1.6: Rename YAML key `groups:`→`deliveries:`; internal `group` identifiers untouched | User-facing clarity (a *delivery* = one schedule+filter+reports+contact) without a risky churn through `run_group()`, `output/<date>_<group-name>/` naming, and the `delivery_log.db` audit schema. Legacy `groups:` accepted as a deprecated alias during the transition. | — Pending |
| v1.6: Analyst mailbox = default Reply-To + standing Cc (one knob), universal, no opt-out | Satisfies "analysts keep a record and any reply reaches them" with one `defaults.analyst_mailbox` line driving both headers. All reporting is internal, so no per-delivery opt-out — deletes a config knob and a code branch. | — Pending |
| v1.6: No per-delivery SLA override (scope decision) | A stricter-turnaround team self-selects operationally; the org SLA stays universal, so their report is just a narrower per-delivery `filters:` (already supported) with unchanged SLA math. Keeps v1.6 pure config-plumbing and the "config resolves identically" parity gate clean. | ✓ Good — confirmed with operator 2026-07-09 |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition:**
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone:**
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-07-10 — Phase 21 (private config repo + CI + CODEOWNERS + production cutover; CONF-04, QUAL-07) complete and verified 9/9, operator cutover checkpoint approved. v1.6 Delivery Config at Scale fully executed (Phases 20–21; 7/7 requirements CONF-01…05, QUAL-06/07) — ready to archive via `/gsd:complete-milestone`. `v1.5.0` released 2026-07-09 (release tag; consumed the v1.5 label). v1.4 phase dirs archived to `milestones/v1.4-phases/`.*
