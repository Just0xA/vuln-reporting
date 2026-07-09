# CLAUDE.MD — Vulnerability Management Reporting Suite (pyTenable)

Modular Python reporting suite for Tenable Vulnerability Management: self-registering metric modules on a four-channel render contract (PDF / Excel / email panel / analyst drill-down), composed into audience bundles via `delivery_config.yaml`, delivered on schedule from a hardened RHEL 9 host.

**Core value:** Right metric, right audience, right channel — without writing a new report each time.

**Vocabulary:** Project-specific terms (chrome, RAG strip, VPR, four-channel render contract, slug, etc.) are defined in [`docs/GLOSSARY.md`](docs/GLOSSARY.md). Read it when a term is unfamiliar; add an entry when introducing a new one.

---

## Hard Rules — Invariants (never violate; each has already caused or prevented a real incident)

1. **No live Tenable pulls from Claude Code — ever.** A PreToolUse hook (`.claude/hooks/block_tenable_fetch.py`, wired via `.claude/settings.json`) denies every live-pull entry point: `data/fetchers.py`, `tenable_client.py`, all `reports/*.py` standalone invocations, `utils/tag_helper.py`, and the live-pull scripts. Only verified pre-auth dry-runs are permitted: `run_all.py --dry-run`, `scripts/warm_cache.py --dry-run`, `scripts/capture_trend_snapshot.py --dry-run`. A human runs live pulls manually, outside Claude Code. Do not attempt workarounds; if a task seems to need live data, stop and ask the operator to warm the parquet cache.
2. **Aggregate-only PII in anything committed (D-04-08).** No real hostnames, IPs, MACs, plugin names, or asset UUIDs in test fixtures, baselines, snapshots, debug dumps, or docs. Two git-history scrubs have already been required (`data/trend` 2026-05-14, `tests/debug_fetch2.txt` 2026-06-03). Synthetic data only.
3. **All "currently open" logic MUST use the reopened-aware two-interval predicate** — `utils/open_count.open_findings_at()`. The naive `last_fixed null OR last_fixed > D` form silently drops ~19% of findings (the entire REOPENED population).
4. **Severity is VPR-first** via `config.vpr_to_severity(vpr_score, fallback=native)` (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9). Never tier from the raw CVSS severity string.
5. **pandas CoW: `.assign()` only.** Never `df["col"] = val` after a filter or slice — it raises `ChainedAssignmentError` under pandas 3.0 semantics and has produced real parquet-serialization bugs (`fix-recast-rules` 2026-06-04).
6. **Empty-data guard on all four channels.** Filtered-to-zero recipient groups are routine. Use `safe_pct` / `safe_int` / `safe_format` for any possibly-`None`/`NaN` value; return `BaseModule._empty_result()` instead of raising. Inline f-string format specs on possibly-`None` values are forbidden.
7. **Cold-start branch mandatory for MoM modules:** branch on `read_trend()`'s `insufficient_data` flag before computing deltas.
8. **Zero new dependencies** without explicit operator approval — `requirements.txt` is locked.
9. **Credentials via `.env` only** (see `.env.example`) — never hardcoded, never logged, never committed. Single chokepoint: `tenable_client.get_client()`; validate on startup, exit with a clear error on auth failure.

---

# Karpathy Guidelines

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.
- Remove imports/variables/functions that YOUR changes made unused.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

---

## Planning Systems — Boundary

Two systems coexist by design:

- **Superpowers** = design exploration only. Brainstorm/spec sessions write to `docs/superpowers/specs/` (and `plans/`). No repo code edits from a Superpowers session.
- **GSD** = all execution. Every code change goes through a GSD entry point (see GSD Workflow Enforcement below). A GSD plan that implements a Superpowers spec must link the spec in its `PLAN.md` context.

---

## SLA Definitions

| Severity | VPR Score Range | SLA (Days) |
| -------- | --------------- | ---------- |
| Critical | 9.0 – 10.0      | 15         |
| High     | 7.0 – 8.9       | 30         |
| Medium   | 4.0 – 6.9       | 60         |
| Low      | 0.1 – 3.9       | 120        |

A vulnerability is **overdue** when `today - first_found_date > SLA_days` AND not remediated. Constants in `config.py` → `SLA_DAYS`.

---

## Asset Segmentation

All reports must support filtering and grouping by Tenable Tags/Labels: fetched dynamically at runtime (never hardcoded), CLI `--tag-category` / `--tag-value` on any report, defined per recipient group in `delivery_config.yaml`, included as a dimension in aggregated outputs. No tag filter = all assets.

---

## Project Structure

```
vuln-reporting/
├── config.py                     # SLA constants, severity maps, vpr_to_severity
├── tenable_client.py             # Authenticated TenableIO client factory
├── delivery_config.yaml          # Recipient groups (gitignored; see delivery_config.example.yaml)
├── delivery_config.schema.yaml   # JSON Schema validator for the YAML
├── scheduler.py                  # APScheduler daemon + run-due + manual modes
├── run_all.py                    # Master runner; run_group() is the single executor
├── data/fetchers.py              # All pyTenable fetch functions + parquet cache
├── data/trend_store.py           # Forward-accumulating trend snapshots
├── reports/                      # Per-slug report scripts
│   └── modules/                  # Metric module infrastructure (auto-discovered)
├── exporters/                    # excel / pdf / chart
├── delivery/                     # email_sender / email_template / delivery_log (SQLite audit)
├── utils/                        # sla_calculator / tag_helper / open_count / formatters
├── scripts/                      # warm_cache, capture_trend_snapshot, updater, smokes
├── deploy/                       # systemd unit, crontab.example, smoke scripts
├── docs/                         # Calculation runbooks + API field references + GLOSSARY
└── templates/report_email.html   # Jinja2 email body (inline CSS only)
```

Deeper file-by-file notes: `.planning/codebase/STRUCTURE.md` and `ARCHITECTURE.md`. Operations (scheduling, cron, install/update/rollback): `DEPLOYMENT.md` and `RUNBOOK.md`.

---

## Delivery Configuration — `delivery_config.yaml`

Single YAML controlling who gets what, with what filters, and how often — editable without touching Python. `delivery_config.schema.yaml` is the authoritative validator; `delivery_config.example.yaml` is the committed reference shape. Key rules:

- `frequency` ∈ {weekly, monthly, on_demand}; `day_of_week` (weekly) / `day_of_month` (monthly, 1–28) / `time` (`HH:MM` server-local) as applicable
- `filters` may be `{}` (all assets); `recipients` required
- Valid report slugs are defined in **`run_all.py` → `_VALID_REPORTS`** and mirrored in the schema enum — those two are the only registration points (this file is not a registry)
- Groups using `composed_report` must declare a non-empty `modules:` array of registered module IDs; optional `module_options:` per-module dict and `report_title:` cover override
- Config is validated on startup and by `run_all.py --dry-run` — exit with a clear error if misconfigured

---

## Execution Model

`run_group(group_config)` in `run_all.py` is the sole "run one delivery group" entry point; all modes converge there:

- **Daemon:** `python scheduler.py --mode daemon` (APScheduler; hot-reloads YAML; systemd unit at `deploy/vuln-reports.service`)
- **Run-due:** `python scheduler.py --mode run-due` (cron every 5–10 min; ±10-minute schedule window)
- **Manual:** `python run_all.py --group "<name>"` with `--no-email`, `--dry-run`, `--recipients`, `--tag-category/--tag-value` overrides

Outputs land in `output/YYYY-MM-DD_HH-MM_<group-name>/`. Fail-soft batch semantics: one report failing never aborts the group; one group failing never aborts the batch.

---

## Email Delivery — key rules

`delivery/email_sender.py` sends HTML body (Jinja2, **inline CSS only** — Outlook/Gmail/Apple Mail compatible) + PDF and Excel attachments per report. STARTTLS 587 default; `tenacity` retry ×3; `MAX_ATTACHMENT_SIZE_MB` (25) enforced — over limit sends PDF-only with a body note; never send to an empty recipient list. `send_report_email()` returns bool, logs errors, never raises. Delivery audit: SQLite at `logs/delivery_log.db` (`delivery/delivery_log.py`, CLI: `--recent N`, `--failures`, `--group`, date range).

---
## Board-Style Reports — Module Infrastructure

Reports built on `reports/modules/` are composed of independent, testable metric modules assembled by `ReportComposer` into PDF, Excel, and email outputs. Used by `board_summary`, `management_summary`, and `composed_report`.

### Module anatomy

Every metric module lives in `reports/modules/` and must:

1. Be named `*_module.py` (auto-discovered by `registry.discover()` on package import — the suffix is load-bearing)
2. Decorate the class with `@register_module`
3. Extend `BaseModule` and implement `compute()` (contractually side-effect-free). Override any renderer methods whose channel the module contributes to.

```python
from reports.modules import register_module
from reports.modules.base import BaseModule, ModuleConfig, ModuleData

@register_module
class MyMetricModule(BaseModule):
    MODULE_ID    = "my_metric"
    DISPLAY_NAME = "My Metric"
    ...
```

### Four-channel render contract

All renderer methods are **concrete with no-op defaults** (not `@abstractmethod`).

| Method                                                                 | Channel                               | Default             |
| ---------------------------------------------------------------------- | ------------------------------------- | ------------------- |
| `render_pdf_section(data, config) -> str`                              | PDF                                   | `""`                |
| `render_excel_tabs(data, workbook, config) -> list[str]`               | Excel                                 | `[]`                |
| `render_email_kpis(data, config) -> list[dict]`                        | Email KPI tiles (legacy)              | `[]`                |
| `render_email_panel(data, config) -> str`                              | Email body panel (CONTRACT-01)        | `""`                |
| `render_analyst_tabs(data, config) -> list[tuple[str, pd.DataFrame]]`  | Analyst-detail workbook (CONTRACT-02) | `[]`                |
| `render_rag_strip_entry(data, config) -> dict`                         | Cover-page RAG strip (CONTRACT-03)    | Gray "No Data" cell |

`ModuleData` (CONTRACT-04) carries `driver_narrative: str` (1-line "what's driving it"), `analyst_rows`, and `rag_strip` (`{label, headline_value, rag_color, rag_label}`).

Shared utilities: `reports/modules/rag_utils.py` and `reports/modules/format_utils.py`, both re-exported at the package level. Empty-data handling is Hard Rule 6.

### Adding a new module to an existing composed report

1. Create `reports/modules/my_metric_module.py` following the pattern above.
2. Add `ModuleConfig("my_metric")` to the report's module-config list (e.g. `_BOARD_MODULE_CONFIGS` in `board_summary.py`) — or, for `composed_report`, just list the MODULE_ID in the group's `modules:` YAML. Auto-discovery handles registration.

### PDF assembly note

`ReportComposer.assemble_pdf()` produces a cover/title page followed by one page per module. No trailing footer page (metadata there caused an orphaned last page when the final module filled its page exactly).

---

## Adding a New Report Slug — Required Steps

Register in exactly **two** places or `--dry-run` will reject it:

1. **`run_all.py` — `_VALID_REPORTS`**: add the slug to the frozenset, and add `"slug": "reports.module_name"` to `_REPORT_MODULE_MAP`.
2. **`delivery_config.schema.yaml`**: add the slug to the reports enum.

If the report needs group-config parameters beyond the standard set, add a slug-specific block inside `run_group()` (see `vuln_export` / `csv_severities` pattern). Every `run_report()` must return at minimum `{"pdf": path_or_none, "excel": path_or_none, "charts": list_of_paths}`; modular reports opt into the upgraded email/analyst pipeline by populating `email_body_html`, `analyst_excel`, and `email_inline_images` bundle keys — routing is by bundle self-description, never by slug allowlist.

### Composed Reports — YAML-driven module composition

`reports/composed_report.py` is the generic slug realizing the composition pattern: a group opts in with `reports: [composed_report]` plus a `modules:` list. The slug fetches `vulns_df` + `assets_df` (plus gated extras via the kwargs frozensets, e.g. `fixed_vulns_df`, `trend_snapshots`, `recast_rules_df`), applies the tag filter, and drives `ReportComposer.run_full_pipeline`. Adding a new metric module needs **zero** changes to `composed_report.py`.

---

## Report Scripts — Slug Index

| Slug                 | Audience                          | Outputs                          | Notes                                                                        |
| -------------------- | --------------------------------- | -------------------------------- | ---------------------------------------------------------------------------- |
| `executive_kpi`      | Management / Executives           | PDF, Excel, charts               | Open vulns by severity, SLA %, MTTR, top-5 risky tags                        |
| `sla_remediation`    | IT / Remediation + Analysts       | Excel (per-sev tabs), PDF, chart | SLA status per vuln, velocity, breach trend                                  |
| `asset_risk`         | Analysts + IT                     | Excel, PDF, chart                | Per-asset weighted risk score                                                |
| `patch_compliance`   | IT / Remediation + Analysts       | Excel, PDF, chart                | Age buckets, % beyond SLA, oldest unpatched                                  |
| `trend_analysis`     | Management + Analysts             | Excel, PDF, charts               | Weekly/monthly snapshots, MTTR trend                                         |
| `plugin_cve`         | Analysts                          | Excel, PDF, charts               | Top plugins/CVEs, exploitable breakdown                                      |
| `ops_remediation`    | Operations / Remediation          | Excel (7 tabs), PDF              | Overdue by plugin, risk acceptances, recurring vulns (legacy bespoke path)   |
| `vuln_export`        | Operations + Analysts             | CSV only                         | Raw open findings, configurable `csv_severities`                             |
| `management_summary` | Senior Management (Directors/VPs) | PDF, HTML email, Excel           | 7 modules on ReportComposer. See `docs/management_summary_calculations.md`   |
| `board_summary`      | Board / Executive Leadership      | PDF, Excel                       | 4 board KPIs; modules-based. See `docs/board_summary_calculations.md`        |
| `unscanned_assets`   | Analysts / IT Ops                 | Excel, CSV                       | Companion to Scan Coverage SLA                                               |
| `composed_report`    | Any (YAML-defined)                | PDF, Excel, email, analyst wb    | Generic module composition — see section above                               |

Per-report details live in each report's module docstring and the `docs/*_calculations.md` auditor runbooks.

---

## Data Fetching (`data/fetchers.py`)

- `tio.exports.vulns()` / `tio.exports.assets()` / `tio.tags.list()`; `fetch_recast_rules()` via `POST /v1/recast/rules/search` (arbitrary AND/OR filter trees — use `_summarize_filter()`; see docstrings)
- **Bounded `last_fixed` lookback:** fixed-finding fetches with no time filter return only ~29 days by API default; real retention is ~15–16 months — always pass a bounded `last_fixed` when history is needed
- Run-scoped parquet cache: `data/cache/<YYYY-MM-DD>/` (local machine date, not UTC); pre-warmed once per batch (`scripts/warm_cache.py` via cron), pruned at batch start; every report hits `[CACHE HIT]`
- `tenacity` exponential backoff; all fetchers return normalized `pd.DataFrame`; `rich` progress bars on long fetches

---

## Code Quality Requirements

- `if __name__ == "__main__":` with `argparse` on every script; type hints and NumPy-style docstrings throughout (see `.planning/codebase/CONVENTIONS.md` for the full conventions with `file:line` references)
- **Timezone policy:** report timestamps UTC (`datetime.now(tz=timezone.utc)`); cache folder names and schedule matching use server local time
- `logging` with rotating file handlers (`logs/app.log`); no silent failures; fail-soft batch semantics
- `requirements.txt` pinned; `.env.example` documents all variables

---

<!-- GSD:project-start source:PROJECT.md -->

## Project

**Vulnerability Management Reporting Suite**

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + inline-chart email — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

The next direction is to make every report **modular and composable** rather than canned: individual KPI/KRI modules render themselves into PDF, Excel, email, and analyst drill-down detail, so each recipient group (Operations, Management, Executive Leadership) gets a tailored bundle assembled from the same shared metric library.

**Core Value:** **Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

### Constraints

- **Tech stack**: Python 3.10+, `pyTenable` SDK, pandas, openpyxl, WeasyPrint, matplotlib + plotly, Jinja2, APScheduler, tenacity — locked. No new SDK adoption in v1.
- **Email-client compatibility**: Outlook / Gmail / Apple Mail must render the per-module email panels. Inline CSS only; no `<style>` blocks; charts via base64 CID. Already established and must be preserved.
- **Backward compatibility**: Existing groups in `delivery_config.yaml` referencing `board_summary`, `management_summary`, `ops_remediation`, `vuln_export`, `unscanned_assets` must continue to deliver during and after v1. Adding the analyst-detail companion to Board Summary cannot regress existing email/PDF for those recipients.
- **Credential handling**: All Tenable + SMTP credentials via `.env` only — never hardcoded, never logged, never committed. Existing pattern is locked.
- **Fail-soft batch semantics**: A module render error must not kill the batch. The empty-data hardening requirement is a hard correctness bar, not a nice-to-have, because filtered-to-zero recipient groups are a regular occurrence (we just hit two on 2026-05-04).
- **Reviewer-in-the-loop for Board Summary delivery**: Board Summary today goes Manager → CISO → IT Metrics team; it is never delivered directly. v1's `analyst_detail: true|false` toggle exists to future-proof this — when Board Summary delivery becomes more direct, recipient groups can opt out of the analyst companion without changing code.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->

## Technology Stack

See `.planning/codebase/STACK.md` for the deep-dive (per-dependency versions, import locations, retry policies, platform requirements).

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

See `.planning/codebase/CONVENTIONS.md` for naming, type hints, docstring style, logging conventions, datetime/timezone rules, pandas patterns, dataclass usage, and comment conventions.

<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

See `.planning/codebase/ARCHITECTURE.md` for the component responsibility table, layer breakdown, data-flow diagrams, key abstractions, entry points, extension points, and anti-patterns.

Quick reference — the load-bearing patterns:

- **Single shared executor:** `run_group()` in `run_all.py` is the sole "run one delivery group" entry point. All CLI modes (daemon, run-due, manual) converge there.
- **Fail-soft batches:** A failure in one report never aborts the rest of the group; a failure in one group never aborts other groups.
- **Run-scoped parquet cache:** Pre-fetch warms `data/cache/<YYYY-MM-DD>/` once per batch; every report in the batch hits `[CACHE HIT]`.
- **Auto-discovery for modules:** Importing `reports.modules` triggers `registry.discover()`, which globs `*_module.py` and lets `@register_module` self-register.
- **Pure compute, deferred render:** `BaseModule.compute()` is contractually side-effect-free; renderers are called later by the composer.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

- **Spike findings for vuln-reporting** (vuln-type classification + trend foundations — proven patterns, constraints, gotchas) → `Skill("spike-findings-vuln-reporting")`

<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.

<!-- GSD:workflow-end -->
