# Vulnerability Management Reporting Suite

## What This Is

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + paired analyst-detail companion workbook + per-module HTML email body — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

**As of v1.0:** every metric is a **module** that renders itself into 4 channels (PDF section, Excel tabs, email panel, analyst drill-down). Each named report (`board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets`) is a bundle of modules; recipient groups consume the bundle. The pattern is proven against Board Summary; v1's job was to establish the pattern, not to migrate every report.

## Core Value

**Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

## Current State

**Shipped:** v1.3 Trend & Segmentation Substrate (2026-06-11) — see [`MILESTONES.md`](MILESTONES.md).

- 2 phases (12–13), 8 plans, 52 files / +8,811 / −373 across 2026-06-08 → 2026-06-11; 13/13 requirements satisfied (TREND-01..07, SEG-01..05, DOC-01); milestone audit status: passed
- **S1 — Trend snapshot substrate:** reopened-aware two-interval `open_findings_at()` open-count primitive (`utils/open_count.py`) — the naive single-interval form silently dropped ~19% of findings (all REOPENED); `data/trend_store.py` atomic capture/read with idempotent monthly overwrite, cold-start safety, and aggregate-only PII discipline; `scripts/capture_trend_snapshot.py` cron entry point. Extends `data/trend/` without regressing `management_summary`'s private path.
- **S2 — Owner segmentation:** `extract_owner()` Owner/Application tag helper with a lossless `Unassigned` catch-all; combined analyst worklist (`reports/owner_supplemental.py`) wired fail-soft into `board_summary`; owner-dimension trend composition (S1×S2) proven end-to-end. Migrated board/management modules from "Business Unit" → Owner terminology.
- Auditor runbook `docs/trend_and_segmentation_calculations.md` (DOC-01).
- Post-milestone: substrate tech debt closed via quick task `260611-b1x` (owner_supplemental asset-count dedup + pandas-3.0 CoW chained-assignment). The third audited item — `open_findings_at` NaT-FIXED over-count — was found already-fixed (commit `71207e6`) and regression-tested, so the Phase 14 created to address it was removed as unnecessary.

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

## Current Milestone: v1.4 Management Summary Reporting Improvement

**Goal:** Build the June-2026 management/exec trend-cut report batch as modular four-channel reports consuming the shipped S1 (trend) + S2 (Owner) substrates, and migrate `management_summary` onto the module render contract (GEN-01).

**Target features:**
- **New vs Remediated** — monthly incoming vs remediated trend (most direct S1 consumer)
- **Vulnerability Density** — vulns/asset MoM; introduces an asset-count denominator substrate
- **Reopened Vulnerabilities** — build/config regression tracking (`state==REOPENED` / `resurfaced_date`)
- **Accepted & Recast** — current posture + prev-month ▲▼%, by Owner (recast rules already in codebase)
- **Program Health Overview** — MoM velocity across totals, Owner cut
- **MTTR rework** — disclose ~30d window, sample-weight, reopened-aware, add trend + Owner, four-channel contract
- **External / DMZ exposure cut** — scope = tagged `Location=External/DMZ` OR computed public IPv4 (non-RFC1918); analyst mismatch/exception list (mirrors S2 `Unassigned`). **WAS deferred** — no pyTenable upgrade this milestone
- **GEN-01** — migrate `management_summary` to the module render contract (folded in)

**Key context:** WAS deferral keeps the locked pyTenable-version constraint intact (External report is a host-vuln exposure cut, not a new data source). Two new substrates emerge — an asset-count denominator (Density) and an external-scope helper. GEN-01 migration must not regress existing `management_summary` delivery (smoke baselines + visual UAT, same pattern as the v1.0 `board_summary` cutover). All new modules use the four-channel render contract + empty-data hardening; aggregate-only PII discipline (D-04-08) on any new trend snapshots.

**Founding analysis:** [`notes/report-requests-batch-2026-06.md`](notes/report-requests-batch-2026-06.md), [`notes/trend-reconstruction-engine.md`](notes/trend-reconstruction-engine.md), spikes 001–003 ([`spikes/MANIFEST.md`](spikes/MANIFEST.md)), and the `spike-findings-vuln-reporting` skill.

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

- **Tech stack**: Python 3.10+, `pyTenable` SDK, pandas (3.0-safe), openpyxl, WeasyPrint, matplotlib + plotly, Jinja2, APScheduler, tenacity, jsonschema — locked. No new SDK adoption without an explicit decision.
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
*Last updated: 2026-06-26 — v1.4 complete (Phases 14–19, all verified passed; Phase 19 closure milestone audit status: passed). Ready for milestone archival via /gsd-complete-milestone.*
