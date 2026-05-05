# Codebase Structure

**Analysis Date:** 2026-05-05

## Directory Layout

```
vuln-reporting/
├── .env                              # Local credentials (Tenable + SMTP); not committed
├── .env.example                      # Template documenting every required env var
├── .gitignore
├── CLAUDE.md                         # Canonical project spec (architecture, conventions, contracts)
├── RUNBOOK.MD                        # Operational runbook
├── config.py                         # Shared constants: SLA, severity/VPR maps, palette, ROOT/CACHE/OUTPUT/LOG dirs
├── tenable_client.py                 # Authenticated TenableIO factory + connection validator
├── delivery_config.yaml              # Per-group recipients, schedules, filters, report list
├── delivery_config.schema.yaml       # JSON Schema for validating delivery_config.yaml
├── requirements.txt                  # Pinned Python dependencies
├── run_all.py                        # Master CLI runner — owns _VALID_REPORTS, _REPORT_MODULE_MAP, run_group()
├── scheduler.py                      # APScheduler daemon / run-due / manual modes — delegates to run_group()
│
├── data/                             # Tenable data fetch + cache (parquet)
│   ├── __init__.py                   # Marks data/ as a regular package (not namespace package)
│   ├── fetchers.py                   # All tio.exports.* + recast-rules calls; tenacity retry; parquet caching
│   ├── cache/                        # Run-scoped parquet cache; subdirs named YYYY-MM-DD (local time)
│   │   └── 2026-04-30/               # Per-day cache folder (older folders auto-deleted by run_all.py)
│   └── trend/                        # Persisted trend snapshots for management_summary month-over-month metric
│       ├── management_summary_all_assets.json
│       ├── management_summary_Owner_Configuration_Management.json
│       └── management_summary_Owner_Network_Defense.json
│
├── reports/                          # One file per top-level report slug
│   ├── __init__.py                   # Marks reports/ as a regular package
│   ├── asset_risk.py                 # Slug: asset_risk
│   ├── board_summary.py              # Slug: board_summary (composed via reports/modules/)
│   ├── duplicate_assets.py           # (Diagnostic helper — not in _VALID_REPORTS)
│   ├── executive_kpi.py              # Slug: executive_kpi
│   ├── management_summary.py         # Slug: management_summary (composed via reports/modules/)
│   ├── ops_remediation.py            # Slug: ops_remediation (7-tab Excel + PDF + risk modifications)
│   ├── patch_compliance.py           # Slug: patch_compliance
│   ├── plugin_cve.py                 # Slug: plugin_cve
│   ├── sla_remediation.py            # Slug: sla_remediation
│   ├── trend_analysis.py             # Slug: trend_analysis
│   ├── unscanned_assets.py           # Slug: unscanned_assets (Excel+CSV companion to board scan-coverage)
│   ├── vuln_export.py                # Slug: vuln_export (CSV-only raw export)
│   │
│   └── modules/                      # Reusable metric module library + composer infrastructure
│       ├── __init__.py               # Public exports + triggers registry.discover() at import time
│       ├── README.md                 # Internal docs for the module pattern
│       ├── base.py                   # BaseModule ABC + ModuleConfig + ModuleData dataclasses
│       ├── registry.py               # ModuleRegistry singleton + @register_module + auto-discovery
│       ├── composer.py               # ReportComposer: run_all / assemble_pdf / assemble_excel / collect_email_kpis
│       ├── chart_utils.py            # draw_gauge() and shared chart rendering helpers
│       ├── board_report_utils.py     # Shared utilities for the four board metric modules
│       ├── example_module.py         # Reference / template module (auto-discovered)
│       ├── scan_coverage_sla_module.py        # Board metric 1
│       ├── critical_remediation_sla_module.py # Board metric 2
│       ├── high_risk_assets_module.py         # Board metric 3
│       ├── aged_vulns_assets_module.py        # Board metric 4
│       ├── total_vulns_by_severity_module.py  # Used by management_summary
│       ├── mttr_by_severity_module.py         # Used by management_summary
│       └── patch_compliance_rate_module.py    # Used by management_summary
│
├── exporters/                        # Format conversion helpers
│   ├── chart_exporter.py             # Matplotlib + Plotly chart factories with consistent palette
│   ├── excel_exporter.py             # openpyxl workbook + styling helpers
│   └── pdf_exporter.py               # WeasyPrint HTML→PDF wrappers
│
├── delivery/                         # Email delivery + audit logging
│   ├── delivery_log.py               # SQLite audit log (logs/delivery_log.db) + inspection CLI
│   ├── email_sender.py               # SMTP send (STARTTLS/SSL), tenacity retry, attachment size cap, inline CID charts
│   └── email_template.py             # Jinja2 HTML body builder
│
├── utils/                            # Shared utilities used across reports
│   ├── __init__.py
│   ├── formatters.py                 # safe_filename, report_timestamp, etc.
│   ├── sla_calculator.py             # get_sla_status(severity, first_found, remediated) → status/days_open/days_remaining
│   └── tag_helper.py                 # Tag discovery, asset-by-tag fetch, --list-tags CLI
│
├── templates/                        # Jinja2 templates (email only)
│   └── report_email.html             # Inline-CSS email body (Outlook/Gmail compatible)
│
├── docs/                             # Per-report calculation runbooks
│   ├── board_summary_calculations.md
│   └── management_summary_calculations.md
│
├── deploy/                           # Deployment artifacts
│   └── vuln-reports.service          # Sample systemd unit for `scheduler.py --mode daemon`
│
├── tests/                            # Ad-hoc test scripts and diagnostic snapshots (not pytest-organized)
│   ├── analyze_untagged_assets.py
│   ├── diagnose_first_found.py
│   ├── diagnose_high_risk.py
│   ├── diagnose_null_date.py
│   ├── diagnose_raw_vuln.py
│   ├── test_modules_level1.py        # Module-infrastructure smoke tests
│   ├── test_modules_level2.py
│   ├── validate_workstation_rules.py
│   └── debug_*.{json,txt,parquet}    # Captured Tenable payloads for offline reproduction
│
├── logs/                             # Runtime logs and SQLite audit DB
│   ├── app.log                       # run_all.py + report scripts
│   ├── debug_fetch.txt               # Captured fetch debug output
│   └── scheduler.log                 # scheduler.py rotating log (created on first daemon run)
│
├── output/                           # Generated reports — one folder per group run
│   └── YYYY-MM-DD_HH-MM_<group-name>/
│       └── <report-slug>/{*.pdf, *.xlsx, *.csv, *.png}
│
└── .planning/                        # GSD planning artifacts (this directory)
    └── codebase/                     # Codebase maps (ARCHITECTURE.md, STRUCTURE.md, …)
```

## Directory Purposes

**`data/`:**
- Purpose: Single source of truth for Tenable API access and the parquet cache layer.
- Contains: All `fetch_*` functions, cache I/O helpers, normalization utilities.
- Key files: `data/fetchers.py:203` (`fetch_all_vulnerabilities`), `data/fetchers.py:451` (`fetch_all_assets`), `data/fetchers.py:554` (`fetch_recast_rules`).

**`data/cache/`:**
- Purpose: Per-run parquet cache. Subdirectories are named by **local** machine date (`YYYY-MM-DD`). At the start of every `run_all.py` batch, all subdirs except today's are deleted (`run_all.py:870`).
- Generated: Yes (auto-created and auto-pruned).
- Committed: No — cache parquet files are not source.

**`data/trend/`:**
- Purpose: Persisted JSON snapshots for `management_summary`'s month-over-month trend metric. One file per scope (`all_assets`, `Owner_<Tag>`).
- Generated: Yes (appended on each run).
- Committed: Snapshots may or may not be committed depending on policy.

**`reports/`:**
- Purpose: One Python file per top-level report slug. Each exposes `run_report(tio, run_id, **kwargs) -> dict`.
- Contains: 11 registered report scripts plus `duplicate_assets.py` (diagnostic utility, not in `_VALID_REPORTS`).
- Pattern: Standalone CLI block (`if __name__ == "__main__":`) so each report can be exercised in isolation.

**`reports/modules/`:**
- Purpose: Library of reusable metric modules + `ReportComposer` infrastructure. Used by `board_summary` and `management_summary`.
- Auto-discovery: importing this package globs `*_module.py` / `*_metrics.py` and imports each, triggering `@register_module` (`reports/modules/__init__.py:67`, `reports/modules/registry.py:228`).
- Key files: `base.py`, `registry.py`, `composer.py`, `chart_utils.py`, `board_report_utils.py`, plus 8 metric modules.

**`exporters/`:**
- Purpose: Format conversion helpers shared by all reports.
- Contains: WeasyPrint, openpyxl, matplotlib + plotly wrappers using `config.SEVERITY_COLORS` for consistent styling.

**`delivery/`:**
- Purpose: Email build + send + audit. Loaded only when delivery is needed (lazy import in `run_all.py:631`).
- Contains: SMTP sender, Jinja2 body builder, SQLite audit log + CLI.

**`utils/`:**
- Purpose: Small cross-cutting helpers (no I/O beyond logging).
- Contains: SLA math, tag discovery, filename / timestamp formatters.

**`templates/`:**
- Purpose: Jinja2 templates. Currently only the email body template (`report_email.html`) lives here; PDF HTML scaffolding is inlined in `reports/modules/composer.py`.

**`docs/`:**
- Purpose: Per-report calculation runbooks. Updated whenever metric formulas change.
- Files: `board_summary_calculations.md`, `management_summary_calculations.md`.

**`deploy/`:**
- Purpose: Deployment artifacts. Currently a sample `systemd` unit for the scheduler daemon mode.

**`tests/`:**
- Purpose: Ad-hoc diagnostic + smoke-test scripts. Not yet organized as pytest suites.
- Notable: `test_modules_level1.py` / `test_modules_level2.py` exercise the module infrastructure; `diagnose_*.py` files are one-off Tenable payload investigations; `debug_*.{parquet,json,txt}` are captured snapshots for offline reproduction.

**`logs/`:**
- Purpose: Runtime logs and the delivery audit DB.
- Contents: `app.log` (run_all + reports), `scheduler.log` (rotating, created by daemon mode), `delivery_log.db` (SQLite audit; created on first send by `delivery/delivery_log.py`).
- Generated: Yes.
- Committed: No.

**`output/`:**
- Purpose: All generated report artifacts. One folder per group run named `YYYY-MM-DD_HH-MM_<safe-group-name>`, with one subdirectory per report slug.
- Generated: Yes.
- Committed: No.

**`.planning/codebase/`:**
- Purpose: GSD codebase maps consumed by `/gsd-plan-phase` and `/gsd-execute-phase`.
- Contents: `ARCHITECTURE.md`, `STRUCTURE.md` (and others added by additional focus runs).

## Top-Level File Purposes

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Canonical project spec — read first for any new feature work |
| `RUNBOOK.MD` | Operational guidance |
| `config.py` | SLA constants, severity/VPR maps, palette, paths (`ROOT_DIR`, `CACHE_DIR`, `OUTPUT_DIR`, `LOG_DIR`) |
| `tenable_client.py` | `get_client()` factory with `.env`-only credentials and connection validation |
| `delivery_config.yaml` | Single editable file controlling who gets what — recipients, schedules, filters, report list |
| `delivery_config.schema.yaml` | JSON Schema for editor / CI validation of `delivery_config.yaml` |
| `run_all.py` | Master runner — owns `_VALID_REPORTS`, `_REPORT_MODULE_MAP`, `run_group()`, `_is_due()`, `_validate_group()`, `_dry_run()`, `_print_summary()` |
| `scheduler.py` | APScheduler daemon / run-due / manual modes; all paths call `run_group()` from `run_all.py` |
| `requirements.txt` | Pinned dependencies |
| `.env` / `.env.example` | Tenable + SMTP credentials — never committed |

## Registered Reports (slugs)

Authoritative list — `_VALID_REPORTS` (`run_all.py:75`) and `_REPORT_MODULE_MAP` (`run_all.py:102`) must agree:

| Slug | Module Path | File |
|------|-------------|------|
| `executive_kpi` | `reports.executive_kpi` | `reports/executive_kpi.py:599` |
| `sla_remediation` | `reports.sla_remediation` | `reports/sla_remediation.py:697` |
| `asset_risk` | `reports.asset_risk` | `reports/asset_risk.py:685` |
| `patch_compliance` | `reports.patch_compliance` | `reports/patch_compliance.py:737` |
| `trend_analysis` | `reports.trend_analysis` | `reports/trend_analysis.py:860` |
| `plugin_cve` | `reports.plugin_cve` | `reports/plugin_cve.py:771` |
| `ops_remediation` | `reports.ops_remediation` | `reports/ops_remediation.py:2625` |
| `management_summary` | `reports.management_summary` | `reports/management_summary.py:2262` |
| `vuln_export` | `reports.vuln_export` | `reports/vuln_export.py:357` |
| `board_summary` | `reports.board_summary` | `reports/board_summary.py:82` |
| `unscanned_assets` | `reports.unscanned_assets` | `reports/unscanned_assets.py:137` |

## Registered Metric Modules (`reports/modules/`)

Discovered via filename glob `*_module.py` (`reports/modules/registry.py:47`) and self-registered via `@register_module` on import:

- `scan_coverage_sla_module.py` — `MODULE_ID = "scan_coverage_sla"` (board_summary)
- `critical_remediation_sla_module.py` — `MODULE_ID = "critical_remediation_sla"` (board_summary)
- `high_risk_assets_module.py` — `MODULE_ID = "high_risk_assets"` (board_summary)
- `aged_vulns_assets_module.py` — `MODULE_ID = "aged_vulns_assets"` (board_summary)
- `total_vulns_by_severity_module.py` — used by `management_summary`
- `mttr_by_severity_module.py` — used by `management_summary`
- `patch_compliance_rate_module.py` — used by `management_summary`
- `example_module.py` — reference / template

## Naming Conventions

**Files:**
- `snake_case.py` for all Python files.
- Report scripts: `<slug>.py` matching exactly the slug used in `delivery_config.yaml` and `_VALID_REPORTS`.
- Metric modules: `<metric_id>_module.py` (or `*_metrics.py`) — required for auto-discovery.

**Directories:**
- `snake_case` lowercase. Each project package directory ships its own `__init__.py` to prevent namespace-package collisions with installed pip packages (see `run_all.py:62-64`).

**Generated outputs:**
- Output folders: `output/YYYY-MM-DD_HH-MM_<safe-group-name>/` (UTC timestamp, group name passed through `utils.formatters.safe_filename`).
- Cache folders: `data/cache/YYYY-MM-DD/` (local-machine date — see `run_all.py:864`).

## Where to Add New Code

**New top-level report (e.g. `vendor_compliance`):**
- Create: `reports/vendor_compliance.py` exposing `run_report(tio, run_id, **kwargs) -> dict`.
- Register in `run_all.py:75` (`_VALID_REPORTS`) and `run_all.py:102` (`_REPORT_MODULE_MAP`).
- Add slug to `delivery_config.schema.yaml` enum.
- Add slug to the YAML Schema Rules section of `CLAUDE.md`.
- Tests: `tests/test_vendor_compliance.py` (ad-hoc — pytest layout is not yet enforced).

**New metric module for an existing composed report:**
- Create: `reports/modules/<metric_id>_module.py` (filename must match `*_module.py`).
- Subclass `BaseModule`, set `MODULE_ID`, decorate with `@register_module`.
- Add `ModuleConfig("<metric_id>")` to the host report's config list (e.g. `_BOARD_MODULE_CONFIGS` at `reports/board_summary.py:66`).

**New fetcher dataset:**
- Add a `fetch_*` function in `data/fetchers.py`. Reuse `_cache_path`, `_load_cache`, `_save_cache` (`data/fetchers.py:175-200`) and decorate with `tenacity` retry (see existing fetchers for the pattern).

**New shared utility:**
- Cross-cutting helpers → `utils/` (one focused file per concern).
- Format-conversion helpers → `exporters/`.
- Module-only helpers → `reports/modules/board_report_utils.py` or a new `reports/modules/<area>_utils.py`.

**New email template / partial:**
- Add to `templates/` and load via `delivery/email_template.py`.

**Config defaults / shared constants:**
- Add to `config.py`. Never hardcode SLA days, severity ranges, or color hex codes inside reports.

**Tests / diagnostics:**
- `tests/test_*.py` for module-style tests; `tests/diagnose_*.py` for one-off API investigations.

## Special Directories

**`data/cache/<YYYY-MM-DD>/`:**
- Purpose: Run-scoped parquet cache. Hit by every report in the same batch.
- Generated: Yes; auto-pruned each batch (`run_all.py:870`).
- Committed: No.

**`output/<ts>_<group>/`:**
- Purpose: All artifacts produced by one delivery group run, partitioned by report slug.
- Generated: Yes.
- Committed: No.

**`logs/`:**
- Purpose: Application + scheduler logs and the SQLite delivery audit DB.
- Generated: Yes.
- Committed: No (`.gitignore` should exclude `*.log` and `delivery_log.db`).

**`.planning/`:**
- Purpose: GSD planning artifacts (codebase maps, plans, phase outputs).
- Generated: Yes (by GSD commands).
- Committed: Per project convention.

---

*Structure analysis: 2026-05-05*
