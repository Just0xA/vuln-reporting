# Vulnerability Management Reporting Suite

## What This Is

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + paired analyst-detail companion workbook + per-module HTML email body — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

**As of v1.0:** every metric is a **module** that renders itself into 4 channels (PDF section, Excel tabs, email panel, analyst drill-down). Each named report (`board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets`) is a bundle of modules; recipient groups consume the bundle. The pattern is proven against Board Summary; v1's job was to establish the pattern, not to migrate every report.

## Core Value

**Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

## Current State

**Shipped:** v1.0 Modular Reporting Framework (2026-05-08) — see [`MILESTONES.md`](MILESTONES.md).

- 4 phases, 19 plans, 1 quick task, 140 commits across 4 days
- 38 tests green at milestone close (composer regression 11/11, schema validation 6/6, analyst_detail toggle 3/3, baseline extractor 18/18)
- Board Summary delivers end-to-end: PDF (unified RAG-strip cover + 4 metric pages), standard Excel (4 tabs + `_Metadata`), analyst Excel (4 drill-down tabs), modular email body (4 per-module panels with inline gauges)
- `delivery_config.yaml` is jsonschema-enforced at startup; misconfigured groups fail loud
- `analyst_detail: false` per-group opt-out validated end-to-end
- Cutover smoke (`scripts/smoke_board_summary_cutover.py`) provides a sub-5-second structural-shape regression bar against PII-redacted committed baselines

**Codebase state (post-v1.0):** Five reports work end-to-end. Module infrastructure is exercised by `board_summary` (fully migrated). `management_summary` still uses its bespoke render path (not yet migrated). `ops_remediation`, `vuln_export`, `unscanned_assets` use direct render code without the module contract.

## Next Milestone Goals

The next milestone is not yet defined. Run `/gsd-new-milestone` to start questioning → research → requirements → roadmap.

Likely v1.1 / v2 candidates from the acknowledged backlog (see `milestones/v1.0-REQUIREMENTS.md` v2 section):

- **Migrate `management_summary` and `ops_remediation`** to the new module render contract (GEN-01/02). The contract is now field-tested against Board Summary; bringing the other two reports onto the same path is a clean migration rather than a rewrite.
- **YAML-driven module composition** (GEN-03/04). Per-group inline `modules: [...]` lists and named report bundles defined in YAML rather than hardcoded in Python. The framework already routes via D-22 bundle-driven predicates with no slug allowlists, so the v2 wiring is a near-zero-cost change to `delivery/email_sender.py`.
- **Performance pass** (PERF-01..04). `enrich_vulns_with_assets` per-batch caching (~9× current cost on a 180k-row frame), per-day cache midnight crossover, log rotation, tag-value typo detection.
- **Re-evaluate the 6 unbuilt reports** in CLAUDE.md (`executive_kpi`, `sla_remediation`, `asset_risk`, `patch_compliance`, `trend_analysis`, `plugin_cve`) as candidate module bundles rather than fresh report scripts (LEGACY-01).
- **Cosmetic janitorial:** `_VALID_FREQUENCIES` / `_VALID_REPORTS` constants in `run_all.py:76,90` are unreferenced after Phase 4 jsonschema replacement; cover-page redesign deferred from Phase 03 UAT (template-based; relocate "Generated" + Data Protection Label to a page footer).

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
*Last updated: 2026-05-08 after v1.0 milestone (Modular Reporting Framework shipped)*
