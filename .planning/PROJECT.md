# Vulnerability Management Reporting Suite

## What This Is

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + inline-chart email — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

The next direction is to make every report **modular and composable** rather than canned: individual KPI/KRI modules render themselves into PDF, Excel, email, and analyst drill-down detail, so each recipient group (Operations, Management, Executive Leadership) gets a tailored bundle assembled from the same shared metric library.

## Core Value

**Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

## Requirements

### Validated

<!-- Inferred from the existing brownfield codebase via .planning/codebase/ map (2026-05-05). -->

- ✓ **Tenable.io connectivity** — authenticated `TenableIO` factory with `.env` credential loading, startup connection validation, and tenacity retry/backoff (`tenable_client.py`, `data/fetchers.py`)
- ✓ **Per-day parquet cache** shared across all reports in a batch run; batch-scoped pre-fetch of `vulns_all` + `assets_all` (`data/fetchers.py`, `run_all.py`)
- ✓ **YAML-driven delivery configuration** with JSON-schema file (validation gap noted), tag-filtered asset segmentation, weekly / monthly / on-demand schedules (`delivery_config.yaml`, `delivery_config.schema.yaml`)
- ✓ **Three-mode scheduler** — APScheduler daemon, ±10-min `run-due` for cron / Task Scheduler, manual on-demand for individual or all-on-demand groups (`scheduler.py`)
- ✓ **Single-entry-point batch executor** — `run_group()` is the sole per-group runner; CLI, scheduler, and on-demand modes all converge there with fail-soft semantics (one report failing doesn't kill the batch) (`run_all.py:424`)
- ✓ **SMTP delivery** with STARTTLS/SSL, retry with exponential backoff, attachment-size enforcement, inline CID charts, recipient validation (`delivery/email_sender.py`)
- ✓ **SQLite delivery audit log** with inspection CLI (`delivery/delivery_log.py`)
- ✓ **Module infrastructure foundation** — `BaseModule` ABC, `ModuleConfig` / `ModuleData` dataclasses, `@register_module` decorator with auto-discovery, `ReportComposer` driving compute → PDF/Excel/email-KPI assembly (`reports/modules/`)
- ✓ **Five working report slugs** built end-to-end: `board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets`
- ✓ **Excel / PDF / chart exporters** with consistent severity color palette (`exporters/`)

### Active

<!-- v1 milestone — Modular Reporting Framework. The pattern itself is the deliverable. -->

- [ ] **Module render contract extension** — extend `BaseModule` with three new render hooks every module must implement: `render_email_panel()` (gauge + headline % + RAG label + 1-line "what's driving it"), `render_analyst_tabs()` (pivot-friendly Excel detail rows), `render_rag_strip_entry()` (cover-page strip data)
- [ ] **`ReportComposer` upgrades** — produce a cover page with a RAG strip showing all modules at a glance; assemble email body from per-module panels; emit an always-paired analyst-detail companion Excel workbook (one tab per module) with a `analyst_detail: true|false` toggle in YAML for future flexibility
- [ ] **Board Summary as exemplar** — finish each of the four board metric modules against the new contract: per-module email panel, per-module analyst-detail tab. Email no longer ships bare; analysts can pinpoint which finding/risk drives a metric without opening a separate ticket
- [ ] **YAML schema + runtime validation** — extend `delivery_config.yaml` and `delivery_config.schema.yaml` to support the `analyst_detail` toggle; wire `jsonschema` validation on startup so misconfigured groups fail loud (currently the schema file exists but is never enforced)
- [ ] **Empty-data hardening** — apply the formatting-guard pattern (the fix shipped 2026-05-04 for `ops_remediation` `ops_sla_status` and `management_summary` `exception_rate`) to the sibling site at `management_summary.py:1853` (`cov_pct`), and bake the pattern into all new module render methods so empty-filter recipient groups never crash the batch

### Out of Scope

<!-- v2 / backlog. Recorded so v1 stays shippable. -->

- **Migrating `ops_remediation`, `management_summary` to the new module contract** — proves the pattern with Board Summary first; migration is a v2 beat once the contract is field-tested
- **Migrating `board_summary.py`'s hardcoded `_BOARD_MODULE_CONFIGS` to be YAML-driven** — v1 keeps the module list in code so we exercise the contract before adding configurability; YAML-driven module composition lands in v2
- **Adding new KPI/KRI modules beyond the four existing board metrics** — new modules are built per analyst-submitted requirement after v1 ships; the framework is what's being built in v1, not the catalog
- **`enrich_vulns_with_assets` performance pass** — currently runs once per report on a 180k-row frame (~9× per group); real fix is a per-batch enriched-frame cache. Deferred until the modular pattern stabilizes
- **Per-day cache wipe across midnight boundaries** — current code purges yesterday's cache at run start, which can lose data when a long-running batch straddles local midnight. Deferred — operational impact is small in practice
- **`ops_remediation`'s 7-tab Excel layout reimagined as modules** — large refactor, no user-visible benefit until the module pattern is proven elsewhere
- **The `executive_kpi` / `sla_remediation` / `asset_risk` / `patch_compliance` / `trend_analysis` / `plugin_cve` reports listed in CLAUDE.md** — described in the spec but not built; will be re-evaluated post-v1 since several may be expressible as module bundles rather than fresh report scripts

## Context

**Codebase state.** Brownfield. Five reports work end-to-end. Module infrastructure exists and is exercised by `board_summary` and `management_summary`. The five new render hooks needed for v1 are extensions of the existing `BaseModule` ABC, not a rewrite. See `.planning/codebase/` for the full map.

**The in-progress milestone before GSD onboarding.** Board Summary is the first attempt at the modular pattern. Metrics compute correctly and the report file generates, but: the email is bare delivery (no per-module panels), the PDF cover is too thin (no RAG strip), and analysts have no drill-down to identify which findings drive a metric. v1 finishes Board Summary as the proving ground for the broader pattern.

**Audience differentiation is the motivating use case.** Operations, Management, and Executive Leadership consume the same vulnerability data through different lenses. Today, each audience would mean a new bespoke report file. The modular pattern collapses this — same modules, different bundles per group.

**Operational workflow for new modules.** Analyst → Developer → YAML. An analyst working with their delivery group identifies a needed KPI/KRI and submits the requirement to a developer. The developer builds the module against the contract. Once registered, any group can opt in via `delivery_config.yaml` without code changes.

**Concerns map context.** `.planning/codebase/CONCERNS.md` cataloged 0 high / 9 med / 24 low concerns on 2026-05-05. The empty-data formatting bugs and missing `jsonschema` validation are folded into v1 because they touch the same code paths as the modular work. Performance and per-day-cache concerns are explicitly deferred (Out of Scope above).

## Constraints

- **Tech stack**: Python 3.10+, `pyTenable` SDK, pandas, openpyxl, WeasyPrint, matplotlib + plotly, Jinja2, APScheduler, tenacity — locked. No new SDK adoption in v1.
- **Email-client compatibility**: Outlook / Gmail / Apple Mail must render the per-module email panels. Inline CSS only; no `<style>` blocks; charts via base64 CID. Already established and must be preserved.
- **Backward compatibility**: Existing groups in `delivery_config.yaml` referencing `board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets` must continue to deliver during and after v1. Adding the analyst-detail companion to Board Summary cannot regress existing email/PDF for those recipients.
- **Credential handling**: All Tenable + SMTP credentials via `.env` only — never hardcoded, never logged, never committed. Existing pattern is locked.
- **Fail-soft batch semantics**: A module render error must not kill the batch. The empty-data hardening requirement is a hard correctness bar, not a nice-to-have, because filtered-to-zero recipient groups are a regular occurrence (we just hit two on 2026-05-04).
- **Reviewer-in-the-loop for Board Summary delivery**: Board Summary today goes Manager → CISO → IT Metrics team; it is never delivered directly. v1's `analyst_detail: true|false` toggle exists to future-proof this — when Board Summary delivery becomes more direct, recipient groups can opt out of the analyst companion without changing code.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| v1 = establish the modular pattern (not a polish pass) | User wants modules to be the durable unit of composition; eventually replace canned reports. Polishing Board Summary in isolation would build on a contract that's not finalized. | — Pending |
| Named report = bundle of modules (Q1 option B) | Keeps `delivery_config.yaml` recipient-readable (`reports: [board_summary]`) while still letting the named bundle be defined as a module list internally. Direct module-list-in-YAML is a v2 generalization. | — Pending |
| Analyst companion always-paired with toggle (Q2 option a + c) | Today Board Summary always needs the drill-down (Manager + CISO review require it). Future delivery patterns may not. Toggle preserves both paths. | — Pending |
| Build the module email contract fresh, don't copy `management_summary` (Q3 option b) | `management_summary` did the module → existing-canned-report transform but didn't build the customizable per-module email rendering. v1 builds the pattern fresh against the contract; `management_summary` migrates in v2. | — Pending |
| Fold empty-data formatting hardening into v1 | Same code paths as the new render hooks; cheaper to bake the guard pattern in once than to revisit each module after the fact. | — Pending |
| Defer YAML-driven module composition to v2 | Lets v1 prove the render contract with hardcoded module lists before adding the user-facing config surface. | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-05 after initialization (brownfield onboarding, GSD installed mid-milestone)*
