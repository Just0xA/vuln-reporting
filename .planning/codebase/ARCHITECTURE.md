<!-- refreshed: 2026-05-05 -->
# Architecture

**Analysis Date:** 2026-05-05

## System Overview

The suite is a Python CLI that generates audience-specific vulnerability reports from Tenable.io. A single shared function (`run_group()` in `run_all.py:424`) is invoked by every entry point — direct CLI runs, scheduler daemon, cron-style `run-due`, and manual on-demand mode. Reports are pluggable scripts registered by slug; board / management reports are further composed from independently-registered metric modules under `reports/modules/`.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                              ENTRY POINTS                                │
├──────────────────────┬───────────────────────────┬───────────────────────┤
│   run_all.py (CLI)   │   scheduler.py (daemon /  │   reports/<slug>.py   │
│   `run_all.py:742`   │     run-due / manual)     │   (standalone CLI)    │
│                      │   `scheduler.py:1`        │                       │
└──────────┬───────────┴──────────────┬────────────┴──────────┬────────────┘
           │                          │                       │
           └────── run_group() ───────┘                       │
                       │                                      │
                       ▼                                      │
┌──────────────────────────────────────────────────────────────────────────┐
│                          ORCHESTRATION (run_all)                         │
│  • _load_config()  delivery_config.yaml → list[group]                    │
│  • _is_due()       weekly / monthly schedule match (±10 min)             │
│  • _validate_group / _dry_run                                            │
│  • Pre-fetch: fetch_all_vulnerabilities + fetch_all_assets               │
│  • For each report slug → _import_report() → run_report(tio, run_id, …)  │
│  • send_report_email() unless --no-email                                 │
│  `run_all.py:424` (run_group), `run_all.py:553` (pre-fetch)              │
└──────────┬─────────────────────────────────────────────────┬─────────────┘
           │                                                 │
           ▼                                                 ▼
┌──────────────────────────────┐                ┌─────────────────────────┐
│      DATA + CACHE LAYER      │                │      REPORT LAYER       │
│  data/fetchers.py            │                │  reports/<slug>.py      │
│  • TenableIO export jobs     │                │  • run_report() entry   │
│  • parquet cache per run_id  │  ←──reads──    │  • Composed reports use │
│  • tenacity retry/backoff    │                │    ReportComposer       │
│  data/cache/YYYY-MM-DD/      │                │  reports/modules/       │
└──────────┬───────────────────┘                └────────────┬────────────┘
           │                                                 │
           │     ┌───────────────────────────────────────────┘
           │     │
           ▼     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       MODULE INFRASTRUCTURE                              │
│  reports/modules/                                                        │
│  • base.py      BaseModule ABC + ModuleConfig + ModuleData               │
│  • registry.py  ModuleRegistry + @register_module + auto-discovery       │
│  • composer.py  ReportComposer.run_all / assemble_pdf / assemble_excel   │
│                / collect_email_kpis                                      │
│  Used by: board_summary.py, management_summary.py                        │
└──────────┬───────────────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────┐   ┌──────────────────────────────────────┐
│         EXPORTERS            │   │              DELIVERY                │
│  exporters/                  │   │  delivery/                           │
│  • pdf_exporter (WeasyPrint) │   │  • email_sender.py  SMTP + retries   │
│  • excel_exporter (openpyxl) │   │  • email_template.py  Jinja2 body    │
│  • chart_exporter            │   │  • delivery_log.py   SQLite audit    │
│    (matplotlib + plotly)     │   │  templates/report_email.html         │
└──────────┬───────────────────┘   └──────────────┬───────────────────────┘
           │                                      │
           ▼                                      ▼
┌──────────────────────────────┐   ┌──────────────────────────────────────┐
│   output/<ts>_<group>/<slug> │   │  SMTP server (Office 365 / Gmail)    │
│   PDF + XLSX + PNG + CSV     │   │  + logs/delivery_log.db              │
└──────────────────────────────┘   └──────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Master CLI runner | Parse args, load YAML, schedule-match, drive `run_group()` for each selected group | `run_all.py:742` |
| `run_group()` | Single shared per-group execution: pre-fetch → loop reports → email | `run_all.py:424` |
| Scheduler | APScheduler daemon, run-due trigger, manual mode — all delegate to `run_group()` | `scheduler.py:1` |
| Tenable client factory | Build authenticated `TenableIO` from `.env`, validate connection, exit on failure | `tenable_client.py:40` |
| Shared config | SLA constants, severity / VPR maps, color palette, paths (`ROOT_DIR`, `CACHE_DIR`, `OUTPUT_DIR`, `LOG_DIR`) | `config.py:1` |
| Data fetchers | All `tio.exports.*` calls + parquet caching + tenacity retry | `data/fetchers.py:203,339,451,554` |
| Report scripts | Per-slug `run_report(tio, run_id, **kwargs) -> dict` returning `{pdf, excel, csv, charts, metrics}` | `reports/*.py` |
| Module base / data contracts | `BaseModule` ABC + `ModuleConfig` / `ModuleData` dataclasses | `reports/modules/base.py:43,78,132` |
| Module registry | `@register_module` decorator + filename-based auto-discovery (`*_module.py`, `*_metrics.py`) | `reports/modules/registry.py:228,413` |
| Report composer | Drives `compute()` → `assemble_pdf()` / `assemble_excel()` / `collect_email_kpis()` | `reports/modules/composer.py:320,467,588,664` |
| Excel exporter | openpyxl workbook helpers and styling | `exporters/excel_exporter.py` |
| PDF exporter | WeasyPrint HTML→PDF wrappers (also embedded inside composer for board/management) | `exporters/pdf_exporter.py` |
| Chart exporter | Matplotlib + Plotly chart factories; consistent `SEVERITY_COLORS` palette | `exporters/chart_exporter.py` |
| Email sender | SMTP send (STARTTLS / SSL), tenacity retry, attachment size enforcement, inline CID charts | `delivery/email_sender.py:1` |
| Email template | Jinja2 HTML body builder | `delivery/email_template.py` |
| Delivery log | SQLite audit log of every send attempt + inspection CLI | `delivery/delivery_log.py` |
| SLA / tag / formatter utils | Severity SLA math, tag enrichment, filename / timestamp formatters | `utils/sla_calculator.py`, `utils/tag_helper.py`, `utils/formatters.py` |

## Pattern Overview

**Overall:** Pipeline-driven, plugin-style architecture with two layers of plugins (reports registered by slug in `run_all.py`, metric modules registered by `MODULE_ID` in `reports/modules/registry.py`).

**Key Characteristics:**
- **Single shared executor.** `run_group()` is the sole entry point for "run one delivery group" — all CLI modes converge there (`run_all.py:424`, `scheduler.py:54` imports it).
- **Fail-soft batches.** A failure in one report never aborts the rest of the group; a failure in one group never aborts other groups (`run_all.py:603`, `run_all.py:884`).
- **Run-scoped parquet cache.** Pre-fetch warms `data/cache/<YYYY-MM-DD>/` once per batch; every report in the batch hits `[CACHE HIT]` instead of re-calling Tenable (`run_all.py:553`, `data/fetchers.py:175`).
- **Standard report contract.** Every `reports/<slug>.py` exposes `run_report(tio, run_id, **kwargs) -> dict` returning at minimum `{pdf, excel, charts}`; CSV-only reports add `csv` (`run_all.py:585`).
- **Auto-discovery for modules.** Importing `reports.modules` triggers `registry.discover()`, which globs `*_module.py` / `*_metrics.py`, imports each, and lets `@register_module` self-register the class (`reports/modules/__init__.py:67`, `reports/modules/registry.py:228`).
- **Pure compute, deferred render.** `BaseModule.compute()` is contractually side-effect-free; `render_pdf_section()` / `render_excel_tabs()` / `render_email_kpis()` are called later by the composer (`reports/modules/base.py:180-225`).

## Layers

**Entry / Orchestration (`run_all.py`, `scheduler.py`):**
- Purpose: Resolve which groups run now, supply shared `tio`, `run_id`, `cache_dir`, `generated_at`, and dispatch `run_group()`.
- Depends on: `tenable_client`, `config`, `data.fetchers`, `reports.*`, `delivery.email_sender`.
- Used by: end users (CLI), cron / Task Scheduler (`--mode run-due`), systemd (`--mode daemon`).

**Configuration (`config.py`, `delivery_config.yaml`, `delivery_config.schema.yaml`, `.env`):**
- Purpose: Tunable constants and per-group routing — recipients, schedules, filters, report list.
- Depends on: nothing.
- Used by: every other layer.

**Data Access (`data/fetchers.py`, `data/cache/`, `data/trend/`):**
- Purpose: Single source of truth for Tenable export jobs and their normalized DataFrame outputs.
- Pattern: function-per-dataset; read parquet if present, otherwise call `tio.exports.*`, normalize, write parquet, return DataFrame.
- Depends on: `pyTenable`, `tenacity`, `config.CACHE_DIR`.
- Used by: report scripts (and indirectly modules, via the composer's caller).

**Reports (`reports/*.py`):**
- Purpose: One slug per audience-specific report. Owns its own data assembly, formatting, and output writing.
- Depends on: `data.fetchers`, `exporters/*`, `utils/*`, optionally `reports.modules`.
- Used by: `run_all.run_group()` via dynamic import driven by `_REPORT_MODULE_MAP` (`run_all.py:102`).

**Module Infrastructure (`reports/modules/`):**
- Purpose: Reusable, independently-testable metric modules + the composer that assembles them into PDFs/Excel/email KPIs. Used by `board_summary` and `management_summary`.
- Depends on: `pandas`, `openpyxl`, `WeasyPrint` (via PDF assembly), `chart_utils`, `board_report_utils`.
- Used by: composed reports (`reports/board_summary.py:57`, `reports/management_summary.py`).

**Exporters (`exporters/`):**
- Purpose: Format-conversion helpers (HTML→PDF, dict/df→XLSX, df→PNG/HTML chart).
- Depends on: `weasyprint`, `openpyxl`, `matplotlib`, `plotly`.
- Used by: report scripts and module renderers.

**Delivery (`delivery/`, `templates/`):**
- Purpose: Email assembly, SMTP send with retries, audit logging.
- Depends on: `smtplib`, `email.mime`, `tenacity`, `Jinja2`, `sqlite3`, `config.MAX_ATTACHMENT_SIZE_MB`.
- Used by: `run_group()` after report generation (`run_all.py:631`).

**Utilities (`utils/`):**
- Purpose: SLA calculation (`sla_calculator.py`), tag discovery / asset-by-tag fetch (`tag_helper.py`), filename + timestamp formatting (`formatters.py`).
- Used by: every layer above.

## Data Flow

### Primary "scheduled batch" path

1. CLI invocation `python run_all.py` (or `scheduler.py --mode run-due`) loads `.env`, configures logging, parses args (`run_all.py:802`).
2. `_load_config()` reads `delivery_config.yaml` → `list[group]` (`run_all.py:137`).
3. `_is_due(group, now)` selects groups whose `day_of_week + time` (weekly) or `day_of_month + time` (monthly) match within ±10 min (`run_all.py:175`).
4. `tenable_client.get_client()` builds an authenticated `TenableIO`; stale cache folders are deleted, today's `cache_dir` is created (`run_all.py:848`, `run_all.py:870`).
5. For each selected group, `run_group(group, tio, run_id, cache_dir, …)` is called (`run_all.py:884`).
6. Pre-fetch warms the cache: `fetch_all_vulnerabilities` + `fetch_all_assets` (`run_all.py:553`).
7. For each report slug in `group["reports"]`, `_import_report(slug)` resolves the module via `_REPORT_MODULE_MAP`, then `report_module.run_report(tio, run_id, tag_category, tag_value, output_dir, generated_at, cache_dir, **slug_extras)` is invoked (`run_all.py:575`).
8. Each report writes PDF/XLSX/CSV/PNG into `output/<ts>_<group>/<slug>/` and returns a dict with file paths.
9. `delivery.email_sender.send_report_email(group, report_outputs, trigger_mode)` builds the MIME message: PDF + Excel + CSV attachments, top 3 chart PNGs as inline CID images, KPI tiles + Jinja2 body, then SMTPs with tenacity retries (`run_all.py:631`, `delivery/email_sender.py:75`).
10. `delivery_log.log_delivery(...)` writes one row to `logs/delivery_log.db`.
11. `_print_summary(results)` renders the rich summary table; exit code = 1 if any group failed.

### Composed-report sub-flow (e.g. `board_summary`)

1. `run_report()` calls `fetch_all_assets` + `fetch_all_vulnerabilities` (+ `fetch_fixed_vulnerabilities` for SLA metrics) and applies the optional tag filter (`reports/board_summary.py:48`).
2. A `ReportComposer(vulns_df, assets_df, report_date, module_configs=[...])` is constructed (`reports/board_summary.py:66`).
3. `composer.run_all()` loops `module_configs`, looks up each class via `registry.get(module_id)`, calls `instance.compute(...)`, catches and isolates failures per module (`reports/modules/composer.py:320,355`).
4. `composer.assemble_pdf(results)` calls each module's `render_pdf_section()`, glues them with page-breaks, prepends a cover page, returns a complete HTML document (`reports/modules/composer.py:467`).
5. `composer.assemble_excel(results, workbook)` calls each module's `render_excel_tabs()` and appends a `_Metadata` tab (`reports/modules/composer.py:588`).
6. `composer.collect_email_kpis(results)` merges per-module KPI dicts for the email body (`reports/modules/composer.py:664`).
7. `run_report()` writes the PDF via WeasyPrint, saves the workbook, returns the standard result dict.

**State Management:**
- No long-lived state; the daemon mode keeps APScheduler in-process but each fired job calls the same stateless `run_group()`.
- Trend snapshots persist between runs in `data/trend/management_summary_<scope>.json` for `management_summary`'s month-over-month metric.
- Run-scoped state (`tio`, `run_id`, `cache_dir`, `generated_at`) is created once per batch and passed by argument — no globals are mutated between groups.

## Key Abstractions

**`run_group(group_config, *, tio, run_id, cache_dir, …) -> dict`**
- Purpose: One delivery group, end-to-end — the unit of execution shared by every entry point.
- File: `run_all.py:424`.
- Pattern: Function with rich keyword args; never raises, always returns a result dict (`{group_name, status, output_folder, duration_seconds, reports_generated, email_status, error}`).

**`run_report(tio, run_id, *, tag_category, tag_value, output_dir, generated_at, cache_dir, **extras) -> dict`**
- Purpose: Standard contract every report module must implement.
- Examples: `reports/board_summary.py:82`, `reports/vuln_export.py:357`, `reports/ops_remediation.py:2625`.
- Returns: `{"pdf": path|None, "excel": path|None, "charts": [paths], "csv": path|None (optional), "metrics": dict (optional)}`.

**`BaseModule` (ABC)**
- Purpose: Contract for a single board/management metric — `compute()` (abstract, pure) plus default no-op `render_pdf_section()` / `render_excel_tabs()` / `render_email_kpis()` that subclasses override based on `SUPPORTED_OUTPUTS`.
- File: `reports/modules/base.py:132`.

**`ModuleData` / `ModuleConfig` (dataclasses)**
- Purpose: Typed data contract between `compute()` and renderers — `metrics`, `table_data`, `chart_data`, `summary_text`, `metadata`, `error`.
- File: `reports/modules/base.py:43,78`.

**`ModuleRegistry` (singleton `registry`)**
- Purpose: Module discovery/lookup. Self-registration via `@register_module`, file-glob auto-discovery on package import.
- File: `reports/modules/registry.py:59,410,413`.

**`ReportComposer`**
- Purpose: Orchestrate module execution and assemble outputs. Owns no metric logic.
- File: `reports/modules/composer.py:288`.

## Entry Points

**`run_all.py` (CLI):**
- Location: `run_all.py:742`.
- Triggers: User runs `python run_all.py [--group | --dry-run | --no-email | --tag-category | --tag-value | --recipients]`.
- Responsibilities: Logging setup, arg parsing, `.env` load, config load + validate, group selection, shared `tio` + `cache_dir` setup, loop `run_group()`, print rich summary, set exit code.

**`scheduler.py` (CLI):**
- Location: `scheduler.py:1`.
- Triggers:
  - Daemon: `python scheduler.py --mode daemon` (long-running APScheduler process; reloads YAML every 5 min).
  - Run-due: `python scheduler.py --mode run-due` (one-shot for cron / Windows Task Scheduler).
  - Manual: `python scheduler.py --mode manual --group "<name>"` or `--all-on-demand`.
- Responsibilities: Mode-specific scheduling/argument handling; delegates execution to `run_group()`.

**`reports/<slug>.py` direct execution:**
- Location: each report has `if __name__ == "__main__": argparse + run_report(get_client(), ...)`.
- Triggers: Standalone reproduction / debugging without the YAML config (e.g. `python reports/board_summary.py --tag-category "Environment" --tag-value "Production"`).

**`tenable_client.py` direct execution:**
- Location: `tenable_client.py:140`.
- Triggers: `python tenable_client.py` — connectivity smoke test.

## Extension Points

**Add a new top-level report:**
1. Create `reports/<slug>.py` exposing `run_report(tio, run_id, **kwargs) -> dict`.
2. Add slug to `_VALID_REPORTS` (`run_all.py:75`).
3. Add slug → dotted module path in `_REPORT_MODULE_MAP` (`run_all.py:102`).
4. Add slug to the YAML schema enum in `delivery_config.schema.yaml` and to `CLAUDE.md`'s "YAML Schema Rules" list.
5. If the report needs extra group-config keys, add a slug-specific block at `run_all.py:592` (see `vuln_export` and `unscanned_assets` patterns).

**Add a new metric module to a composed report:**
1. Create `reports/modules/<my_metric>_module.py` (filename must match `*_module.py` to be auto-discovered — `reports/modules/registry.py:47`).
2. Subclass `BaseModule`, set `MODULE_ID`, decorate the class with `@register_module` (`reports/modules/__init__.py:55`).
3. Implement `compute()`; override the renderers whose formats appear in `SUPPORTED_OUTPUTS`.
4. Add `ModuleConfig("<my_metric>")` to the host report's config list (e.g. `_BOARD_MODULE_CONFIGS` at `reports/board_summary.py:66`). No registry edits anywhere else are required.

**Add a new fetcher dataset:**
- Add a new function in `data/fetchers.py` next to existing `fetch_*` functions; reuse `_cache_path` / `_load_cache` / `_save_cache` (`data/fetchers.py:175-200`) and `tenacity` retry decorators.

## Architectural Constraints

- **Threading:** Single-threaded by default. APScheduler daemon mode runs jobs serially in its own background thread; nothing in the report layer is thread-safe and `ModuleRegistry` is explicitly documented as not designed for concurrent mutation (`reports/modules/registry.py:71`).
- **Global state:**
  - `reports.modules.registry.registry` is a process-global singleton populated once at first import.
  - `data/cache/` is a process-shared directory; concurrent runs that share `cache_dir` could race on parquet writes. Caller mitigates by using a single batch `run_id`.
  - No mutable state in `config.py` — module-level constants only.
- **Import-time side effects:** Importing `reports.modules` runs `registry.discover()`, which imports every `*_module.py` in the package. Module files must be importable without external resources.
- **Namespace collision avoidance:** `run_all.py:62-64` deletes any pre-existing `reports`, `data`, `utils` modules from `sys.modules` before adding the project root, so a pip-installed `reports` package on the host can't shadow project-local code. Each project package directory has its own `__init__.py` to guarantee non-namespace-package status.
- **Date / timezone policy:** Cache folder names use **local** machine date (`run_all.py:864`, `run_all.py:870`); report timestamps use **UTC** (`run_all.py:863`). Stale cache folders from prior local-days are pruned at the start of each batch (`run_all.py:870`).

## Anti-Patterns

### Hardcoding new reports outside the three registration sites

**What happens:** A new report module is dropped under `reports/` but `_VALID_REPORTS`, `_REPORT_MODULE_MAP`, and the YAML schema aren't updated.
**Why it's wrong:** `_validate_group()` (`run_all.py:241`) rejects unknown slugs during `--dry-run`, and `_import_report()` returns `None` for unmapped slugs (`run_all.py:402`), so the report silently never runs.
**Do this instead:** Update all three sites; CLAUDE.md documents this as the "Adding a New Report — Required Steps" contract.

### Manual module imports in board/management reports

**What happens:** A composed report `import`s a metric module file directly to "make sure it loads."
**Why it's wrong:** Defeats auto-discovery and creates duplicate registration warnings (`reports/modules/registry.py:115`). It also couples the composed report to the metric module's path.
**Do this instead:** Reference the module by `MODULE_ID` via `ModuleConfig("my_metric")`. Auto-discovery imports the file when `reports.modules` is imported (`reports/modules/__init__.py:67`).

### Side effects in `BaseModule.compute()`

**What happens:** A module writes a chart PNG or mutates `vulns_df` inside `compute()`.
**Why it's wrong:** `compute()` is contractually pure (`reports/modules/base.py:191`). Renderers run later and may be called multiple times per result; chart generation belongs in `render_pdf_section()` / `render_excel_tabs()`, and DataFrame mutation breaks other modules sharing the same input.
**Do this instead:** Use `chart_data` on `ModuleData` to carry raw chart inputs; render lazily in the renderers using helpers from `reports/modules/chart_utils.py`.

### Raising exceptions out of report code

**What happens:** A report's `run_report()` raises on a partial-data condition.
**Why it's wrong:** `run_group()` continues with the next report when one fails (`run_all.py:603`), but a raised exception loses context and aborts that report mid-write. Modules have an even stricter contract (`reports/modules/base.py:198`) — `compute()` must catch all exceptions and populate `ModuleData.error`.
**Do this instead:** Catch internally, log with traceback, return a result dict (or `ModuleData` with `error` set) so the rest of the batch and per-module renderers can handle the failure visually.

## Error Handling

**Strategy:** Catch + log + continue at every batch boundary; never let one unit of work tear down the next.

**Patterns:**
- **`run_group()`** — wraps the Tenable connection, every `run_report()` call, and the email send; returns a status dict instead of raising (`run_all.py:519`, `run_all.py:603`, `run_all.py:634`).
- **`ReportComposer.run_module()`** — catches `validate_config()` and `compute()` exceptions and returns a `ModuleData` with `error` set (`reports/modules/composer.py:355,429`).
- **`registry.discover()`** — broken module file logs a warning, other modules still load (`reports/modules/registry.py:391`).
- **`send_report_email()`** — never raises; tenacity retries SMTP-class errors up to 3 times with exponential backoff; final failure logged and recorded in `delivery_log.db` (`delivery/email_sender.py:91`).
- **`tenable_client.get_client()`** — fatal-only path: missing env vars or bad credentials → `sys.exit(1)` with a clear message; everything downstream assumes the client is valid.

## Cross-Cutting Concerns

**Logging:**
- `run_all.py:742` configures root logging (`StreamHandler` + `FileHandler(LOG_DIR/'app.log')`) with a third-party noise filter for `fontTools` and `weasyprint.progress` (`run_all.py:724`).
- `scheduler.py` uses a `RotatingFileHandler` on `logs/scheduler.log` (`scheduler.py:60`).
- Each module emits via `logger = logging.getLogger(__name__)` so log lines are namespaced by file.

**Validation:**
- `--dry-run` runs `_validate_group()` on every group, checks required `.env` vars, prints a rich validation table, and exits non-zero on any error (`run_all.py:321`).
- `delivery_config.schema.yaml` is a JSON Schema for editor / CI validation of the YAML.
- `BaseModule.validate_config()` is called by the composer before `compute()` (`reports/modules/composer.py:399`).

**Authentication:**
- Single chokepoint: `tenable_client.get_client()` (`tenable_client.py:40`). All keys come from `.env` via `python-dotenv`; never hardcoded.
- SMTP credentials are also `.env`-only (`delivery/email_sender.py:75`).

---

*Architecture analysis: 2026-05-05*
