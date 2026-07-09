# CLAUDE.MD — Vulnerability Management Reporting Suite (pyTenable)

## Project Overview

Build a modular Python reporting suite that connects to **Tenable.io / Tenable Vulnerability Management** via the `pyTenable` SDK and produces meaningful, audience-specific vulnerability management reports. Reports are segmented by **Tenable Tags/Labels**, support three distinct audience formats, and are exported as **CSV/Excel, PDF, and matplotlib/plotly charts**.

The suite supports **scheduled and on-demand execution**, with a YAML-driven delivery system that emails the right reports to the right recipients — each group with its own filters, report selection, frequency, and recipient list that can be updated without touching code.

**Vocabulary:** Project-specific terms (chrome, RAG strip, VPR, four-channel render contract, slug, etc.) are defined in [`docs/GLOSSARY.md`](docs/GLOSSARY.md). Read it when a term is unfamiliar; add an entry when introducing a new one.

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

## Technology Stack

Python 3.12+, `pyTenable`, pandas, openpyxl, matplotlib + plotly, weasyprint, python-dotenv, PyYAML, APScheduler, smtplib + email.mime, Jinja2, tenacity, rich.

Full per-dependency notes (versions, where each is imported, retry policies, etc.) live in `.planning/codebase/STACK.md`. Read that when you need the deep version pinning or library-usage detail.

---

## Credential Management

All credentials loaded exclusively from `.env` via `python-dotenv`. Never hardcode credentials.

```
# .env
TVM_ACCESS_KEY=your_access_key_here
TVM_SECRET_KEY=your_secret_key_here
TVM_URL=https://cloud.tenable.com

# SMTP
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=reports@yourcompany.com
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_ADDRESS=reports@yourcompany.com
SMTP_FROM_NAME=Vulnerability Management Reports
```

Validate connection on startup; exit gracefully with a clear error on auth failure. Single chokepoint: `tenable_client.get_client()`.

---

## SLA Definitions

Severity is determined by the **VPR (Vulnerability Priority Rating)** score from Tenable, **not** the native CVSS-based severity. Always derive severity from the `vpr_score` field; fall back to native severity only when VPR is null.

| Severity | VPR Score Range | SLA (Days) |
| -------- | --------------- | ---------- |
| Critical | 9.0 – 10.0      | 15         |
| High     | 7.0 – 8.9       | 30         |
| Medium   | 4.0 – 6.9       | 45         |
| Low      | 0.1 – 3.9       | 120        |

A vulnerability is **overdue** when `today - first_found_date > SLA_days` AND not remediated.

Defined as constants in `config.py` → `SLA_DAYS = {"critical": 15, "high": 30, "medium": 60, "low": 120}`.

---

## Asset Segmentation

All reports must support **filtering and grouping by Tenable Tags/Labels**:

- Fetch tags dynamically at runtime (do not hardcode tag values)
- Support CLI `--tag-category` / `--tag-value` for any report
- Defined per recipient group in `delivery_config.yaml`
- Include as a column/dimension in aggregated outputs
- If no tag filter, run against **all assets**

---

## Project Structure

```
vuln-reporting/
├── .env                          # Credentials (never commit)
├── .env.example
├── config.py                     # SLA constants, severity maps, shared config
├── tenable_client.py             # Authenticated TenableIO client factory
├── delivery_config.yaml          # Recipient groups, schedules, report selections
├── delivery_config.schema.yaml   # JSON Schema for YAML validation
├── scheduler.py                  # APScheduler daemon + cron/manual modes
├── data/
│   ├── fetchers.py               # All pyTenable API fetch functions
│   └── trend/                    # Trend snapshots (management_summary)
├── reports/
│   ├── *.py                      # Per-slug report scripts
│   └── modules/                  # Reusable metric module infrastructure
├── exporters/                    # excel / pdf / chart
├── delivery/                     # email_sender / email_template / delivery_log
├── utils/                        # sla_calculator / tag_helper / formatters
├── templates/report_email.html
├── docs/                         # Calculation runbooks
├── logs/                         # app.log + delivery_log.db
├── output/                       # Timestamped report folders
├── run_all.py                    # Master runner
└── README.md
```

Deeper file-by-file notes live in `.planning/codebase/STRUCTURE.md` and `.planning/codebase/ARCHITECTURE.md`.

---

## Delivery Configuration — `delivery_config.yaml`

Single file controlling who gets what, with what filters, and how often. Editable without touching Python.

```yaml
groups:
  - name: "Executive Team"
    schedule:
      frequency: weekly # weekly | monthly | on_demand
      day_of_week: monday # weekly only
      time: "07:00" # 24hr, server local
    filters:
      tag_category: "Environment"
      tag_value: "Production"
    reports:
      - executive_kpi
      - trend_analysis
    email:
      subject: "Weekly Vuln Management Summary — Production"
      recipients: [ciso@company.com, vp-it@company.com]
      cc: [security-team@company.com]
      reply_to: security@company.com
```

### YAML Schema Rules

- `frequency` ∈ {`weekly`, `monthly`, `on_demand`}
- `day_of_week` required for weekly (`monday`–`sunday`)
- `day_of_month` required for monthly (integer 1–28; 28 max to avoid February edge cases)
- `time` required for weekly/monthly (`HH:MM`, 24-hour, server local)
- `filters` may be `{}` (all assets)
- `reports` must be a list from: `executive_kpi`, `sla_remediation`, `asset_risk`, `patch_compliance`, `trend_analysis`, `plugin_cve`, `ops_remediation`, `management_summary`, `vuln_export`, `board_summary`, `unscanned_assets`, `composed_report`
- When `reports` contains `composed_report`, the group must also declare a non-empty `modules:` array of registered module IDs. Optional `module_options:` is a per-module options dict; optional `report_title:` overrides the cover-page title.
- `recipients` required; `cc` may be empty
- Validate on startup — exit with a clear error if misconfigured
- `delivery_config.schema.yaml` is the JSON-Schema validator (editor/CI use)

---

## Scheduler — `scheduler.py`

Three execution modes, all delegating to the same `run_group(group_config)`:

- **Mode 1 — Daemon:** `python scheduler.py --mode daemon` — APScheduler `CronTrigger` for all weekly/monthly groups; hot-reloads YAML every 5 min; logs to `logs/scheduler.log`. Sample systemd unit at `deploy/vuln-reports.service`.
- **Mode 2 — Run-due (cron / Task Scheduler):** `python scheduler.py --mode run-due` — runs only groups whose schedule matches within a ±10-minute window. Designed to be invoked every 5–10 minutes.
- **Mode 3 — Manual:** `--mode manual --group "<name>"`, `--all-on-demand`, `--recipients <override>`, `--no-email`.

---

## Email Delivery — `delivery/email_sender.py`

Every delivery email must include:

1. **HTML body** (Jinja2): title + timestamp + group name; scope banner; KPI strip (Total Criticals, % Critical/High in SLA, overdue Critical+High, MTTR); up to 3 inline charts via base64 CID; bullet list of attached reports; SLA reference table; footer with reply-to.
2. **PDF attachments** — one per report in the group's list.
3. **Excel attachments** — one per report.

**SMTP rules:**

- STARTTLS (587) default; SSL (465) via env override
- `tenacity` retry: exponential backoff, up to 3 attempts on transient failures
- Validate recipient addresses pre-send
- Enforce `MAX_ATTACHMENT_SIZE_MB` (default 25). If exceeded: log warning, send PDF only, note in body that Excel was omitted.
- Never send to an empty recipient list — log and skip

```python
def send_report_email(group_config: dict, report_outputs: dict) -> bool:
    """Returns True on success, False on failure — logs error, never raises."""
```

---

## Email Template — `templates/report_email.html`

Jinja2 HTML template compatible with Outlook / Gmail / Apple Mail:

- **Inline CSS only.** No external stylesheets, no `<style>` blocks.
- Section order: Header band → Scope banner → KPI tiles (table-based layout) → Inline charts (`<img src="cid:chart_N">`) → Attached reports list → SLA reference table → Footer.
- If `ops_remediation` is in the run, its pre-built `kpi_tiles` from `metrics` take priority over the generic tile logic.

---

## Delivery Log — `delivery/delivery_log.py`

SQLite audit log at `logs/delivery_log.db`:

```sql
CREATE TABLE delivery_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           DATETIME NOT NULL,
    group_name          TEXT NOT NULL,
    trigger_mode        TEXT NOT NULL,      -- 'scheduled' | 'manual' | 'daemon'
    reports_run         TEXT NOT NULL,      -- JSON array
    tag_filter          TEXT,               -- "Category=Value" or "all_assets"
    recipients          TEXT NOT NULL,      -- JSON array
    status              TEXT NOT NULL,      -- 'success' | 'partial' | 'failed'
    error_message       TEXT,
    output_folder       TEXT NOT NULL,
    attachment_size_kb  INTEGER,
    duration_seconds    REAL
);
```

CLI: `--recent N`, `--failures`, `--group "<name>"`, `--from YYYY-MM-DD --to YYYY-MM-DD`.

---

## `run_all.py` — Master Runner

```bash
python run_all.py                                              # All due groups
python run_all.py --group "Finance Remediation Team"           # Specific group
python run_all.py --group "Executive Team" --no-email          # Reports only
python run_all.py --dry-run                                    # Validate config
python run_all.py --group "..." --tag-category X --tag-value Y # Override filter
python run_all.py --group "..." --recipients test@company.com  # Override recipients
```

Outputs land in `output/YYYY-MM-DD_HH-MM_<group-name>/`. Prints a `rich` summary table on completion.

---

## Board-Style Reports — Module Infrastructure

Reports built on `reports/modules/` are composed of independent, testable metric modules assembled by `ReportComposer` into PDF, Excel, and email outputs. Used by `board_summary` and `management_summary`.

### Module anatomy

Every metric module lives in `reports/modules/` and must:

1. Be named `*_module.py` (auto-discovered by `registry.discover()` on package import)
2. Decorate the class with `@register_module`
3. Extend `BaseModule` and implement `compute()`. Override any renderer methods whose channel the module contributes to.

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

| Method                                                                | Channel                               | Default             |
| --------------------------------------------------------------------- | ------------------------------------- | ------------------- |
| `render_pdf_section(data, config) -> str`                             | PDF                                   | `""`                |
| `render_excel_tabs(data, workbook, config) -> list[str]`              | Excel                                 | `[]`                |
| `render_email_kpis(data, config) -> list[dict]`                       | Email KPI tiles (legacy)              | `[]`                |
| `render_email_panel(data, config) -> str`                             | Email body panel (CONTRACT-01)        | `""`                |
| `render_analyst_tabs(data, config) -> list[tuple[str, pd.DataFrame]]` | Analyst-detail workbook (CONTRACT-02) | `[]`                |
| `render_rag_strip_entry(data, config) -> dict`                        | Cover-page RAG strip (CONTRACT-03)    | Gray "No Data" cell |

`ModuleData` (CONTRACT-04) carries the supporting fields:

- `driver_narrative: str` — 1-line "what's driving it" for `render_email_panel`
- `analyst_rows: list[tuple[str, pd.DataFrame]]` — drill-down data for `render_analyst_tabs`
- `rag_strip: dict` — pre-built strip cell `{label, headline_value, rag_color, rag_label}`

### Empty-data guard pattern

Filtered-to-zero recipient groups happen regularly. Render methods MUST not crash on a zero-row `ModuleData`:

1. **Use `safe_pct` / `safe_int` / `safe_format` from `reports.modules.format_utils`** for any value that could be `None`/`NaN`. Inline f-string format specs on possibly-`None` values are forbidden.

   ```python
   from reports.modules import safe_pct, safe_int, safe_format
   panel_html = f"<p>Coverage: {safe_pct(cov_pct)}</p>"   # Good
   panel_html = f"<p>Coverage: {cov_pct:.1f}%</p>"        # Crashes on None
   ```

2. **Return safe defaults instead of raising.** `BaseModule._empty_result()` produces a coherent failed-`ModuleData` (gray strip cell, "No data in scope." driver).

Shared utilities: `reports/modules/rag_utils.py` (`STATUS_COLOR`, `STATUS_LABEL`, `NO_DATA_HEADLINE`, `NO_DATA_DRIVER`, `rag_status_from_value`, `build_rag_strip_entry`) and `reports/modules/format_utils.py` (`safe_pct`, `safe_int`, `safe_format`). Both re-exported at the package level.

### Adding a new module to an existing composed report

1. Create `reports/modules/my_metric_module.py` following the pattern above.
2. Add `ModuleConfig("my_metric")` to the report's module-config list (e.g. `_BOARD_MODULE_CONFIGS` in `board_summary.py`).
3. No registration in `run_all.py` or this file needed for the module itself — only top-level report slugs are registered there.

### PDF assembly note

`ReportComposer.assemble_pdf()` produces a cover/title page followed by one page per module. No trailing footer page (placing metadata there caused an orphaned last page when the final module filled its page exactly).

---

## Adding a New Report — Required Steps

Every new report script **must** be registered in three places or `--dry-run` will reject it:

1. **`run_all.py` — `_VALID_REPORTS`**: add the slug to the `frozenset`.
2. **`run_all.py` — `_REPORT_MODULE_MAP`**: add `"slug": "reports.module_name"`.
3. **`CLAUDE.md` — YAML Schema Rules**: add the slug to the `reports` valid-values list above.

If the report needs group-config parameters beyond the standard set (`tag_category`, `tag_value`, `output_dir`, `generated_at`, `cache_dir`), add a slug-specific block inside `run_group()` in `run_all.py` (see `vuln_export` / `csv_severities` pattern).

Each `run_report()` must return a dict with at minimum: `{"pdf": path_or_none, "excel": path_or_none, "charts": list_of_paths}`. CSV-only reports add `"csv"`. Other keys (`"metrics"`, etc.) are optional.

### Modular reports — bundle-driven routing

Reports on the `reports/modules/` infrastructure can opt into the upgraded email body and analyst workbook by populating these bundle keys in their `run_report()` return dict:

- **`email_body_html: str`** — when non-empty, `delivery/email_sender.py` routes through `build_email_body_modular()` instead of the legacy `build_email_body()` KPI-tile shell. Selection is by a single predicate: "any report's `email_body_html` non-empty?". No slug allowlist.
- **`analyst_excel: Path | None`** — when a real Path, automatically attached alongside the standard PDF and Excel.
- **`email_inline_images: list[{"cid": str, "b64_png": str}]`** — base64 PNG entries decoded into MIMEImage parts with `Content-ID = <{cid}>` so panels can reference them as `<img src="cid:{module_id}_gauge">`.

This pattern is intentional: v2's planned YAML-driven module composition (`groups[].modules: [m1, m2]`) needs zero changes to `delivery/email_sender.py` or `reports/modules/composer.py` because both layers self-describe from the bundle, not from named-report slugs.

### Composed Reports — YAML-driven module composition

`reports/composed_report.py` is the generic slug that realizes the YAML-driven composition pattern. A group opts in with `reports: [composed_report]` plus a `modules:` list of registered module IDs (and optional `module_options:` per-module dicts, optional `report_title:` cover override, optional `analyst_detail:` opt-out). The slug fetches `vulns_df` + `assets_df` (plus `fixed_vulns_df` only when `critical_remediation_sla` is composed), applies the group's tag filter, drives `ReportComposer.run_full_pipeline`, and returns the standard board-shaped four-channel bundle. Adding a new metric module needs no change to `composed_report.py` — module auto-discovery picks it up on next import.

---

## Report Scripts — Slug Index

| Slug                 | Audience                          | Outputs                          | Notes                                                                       |
| -------------------- | --------------------------------- | -------------------------------- | --------------------------------------------------------------------------- |
| `executive_kpi`      | Management / Executives           | PDF, Excel, charts               | Open vulns by severity, SLA %, MTTR, top-5 risky tags                       |
| `sla_remediation`    | IT / Remediation + Analysts       | Excel (per-sev tabs), PDF, chart | SLA status per vuln, velocity, breach trend                                 |
| `asset_risk`         | Analysts + IT                     | Excel, PDF, chart                | Per-asset weighted risk score                                               |
| `patch_compliance`   | IT / Remediation + Analysts       | Excel, PDF, chart                | Age buckets, % beyond SLA, oldest unpatched                                 |
| `trend_analysis`     | Management + Analysts             | Excel, PDF, charts               | Weekly/monthly snapshots, MTTR trend                                        |
| `plugin_cve`         | Analysts                          | Excel, PDF, charts               | Top plugins/CVEs, exploitable breakdown                                     |
| `ops_remediation`    | Operations / Remediation          | Excel (7 tabs), PDF              | Overdue by plugin, risk acceptances, recurring vulns                        |
| `vuln_export`        | Operations + Analysts             | CSV only                         | Raw open findings, configurable `csv_severities`                            |
| `management_summary` | Senior Management (Directors/VPs) | PDF (5pp), HTML email            | 7 RAG metrics; modules-based. See `docs/management_summary_calculations.md` |
| `board_summary`      | Board / Executive Leadership      | PDF, Excel                       | 4 board KPIs; modules-based. See `docs/board_summary_calculations.md`       |
| `unscanned_assets`   | Analysts / IT Ops                 | Excel, CSV                       | Companion to Scan Coverage SLA; on-time / overdue / no-licensed-scan split  |

Per-report details (column lists, exact calculations, data sources) live in each report's module docstring and the `docs/*_calculations.md` runbooks.

---

## Shared Utilities

- **`utils/sla_calculator.py`** — `get_sla_status(severity, first_found, remediated) -> {status, days_open, days_remaining, sla_days}`. UTC-based.
- **`utils/tag_helper.py`** — `get_all_tags(tio)`, `get_assets_by_tag(tio, cat, val)`, `enrich_vulns_with_tags(df, tio)`. CLI: `--list-tags [--category X]`.
- **`utils/formatters.py`** — pure helpers (no I/O); filename/timestamp/value formatting.
- **`exporters/chart_exporter.py`** — color palette: Critical `#d32f2f`, High `#f57c00`, Medium `#fbc02d`, Low `#388e3c`, Info `#1976d2`.

---

## Data Fetching Guidelines (`data/fetchers.py`)

- `tio.exports.vulns()` for bulk vulnerability data — includes `severity_modification_type`, `recast_rule_uuid`, `recast_reason` for risk management tracking
- `tio.exports.assets()` for asset enrichment
- `tio.tags.list()` for tag discovery
- `POST /v1/recast/rules/search` (`fetch_recast_rules()`) — active recast/accept rules with filter trees, expiration dates, original severity, `created_at`; optional enrichment used by `ops_remediation`
- Cache to local `.parquet` per run to avoid redundant API calls across reports in the same group
- **Cache folders are named by local machine date** (`YYYY-MM-DD`), not UTC. Stale prior-day folders pruned at the start of each `run_all.py` batch.
- `tenacity` exponential backoff for rate limiting
- All fetch functions return a normalized `pd.DataFrame`
- `rich` progress bars on long-running fetches

### Recast rules filter structure

The recast rules API returns a `filter` field that can be an arbitrary AND/OR tree. Supported properties: Plugin ID (`definition.id`), Asset ID, IPv4, IPv6, FQDN, Network, CVE, Plugin Output, Protocol, Tags. Use `_summarize_filter()` to convert to a readable string. Plugin ID is only extractable when the filter is flat `{"property": "definition.id", ...}` or a single-item `and/or` wrapping one.

---

## Code Quality Requirements

- `if __name__ == "__main__":` with `argparse` on every script
- Type hints and docstrings throughout
- **Timezone policy:** report timestamps use UTC (`datetime.now(tz=timezone.utc)`); cache folder names and schedule matching use server local time (`datetime.now()` without tzinfo)
- `logging` module with rotating file handlers (`logs/app.log`)
- No silent failures — log all errors; failures in one group must not stop other groups (fail-soft batch semantics)
- `requirements.txt` with pinned versions
- `.env.example` with all variables and inline comments

---

<!-- GSD:project-start source:PROJECT.md -->

## Project

**Vulnerability Management Reporting Suite**

A Python reporting suite that connects to Tenable.io / Tenable Vulnerability Management and produces audience-specific KPI/KRI reports for vulnerability management programs. Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP, and ship as PDF + Excel + inline-chart email — driven by a scheduler that supports daemon, cron-style, and manual on-demand execution.

The next direction is to make every report **modular and composable** rather than canned: individual KPI/KRI modules render themselves into PDF, Excel, email, and analyst drill-down detail, so each recipient group (Operations, Management, Executive Leadership) gets a tailored bundle assembled from the same shared metric library.

**Core Value:** **Right metric, right audience, right channel — without writing a new report each time.** Operations needs remediation detail, Management needs trend and SLA posture, Executive Leadership needs RAG-strip headlines; all three are different cuts of the same underlying data. The framework's job is to make adding, recombining, and routing those cuts a YAML-and-module exercise rather than a code-fork exercise.

### Constraints

- **Tech stack**: Python 3.12+, `pyTenable` SDK, pandas, openpyxl, WeasyPrint, matplotlib + plotly, Jinja2, APScheduler, tenacity — locked. No new SDK adoption in v1.
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
