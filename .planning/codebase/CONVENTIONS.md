# Coding Conventions

**Analysis Date:** 2026-05-04

This document captures the observed conventions in the Vulnerability Management Reporting Suite. Cite real `file:line` references; when adding new code, follow these patterns rather than inventing alternatives.

---

## Module Header & Imports

Every Python file begins with:

1. A multi-line module docstring describing purpose, audience (where applicable), CLI usage examples, and return contracts.
2. `from __future__ import annotations` (PEP 563 — string-form annotations).
3. Standard library imports.
4. Third-party imports.
5. Local imports from `config`, `data.fetchers`, `utils.*`, `reports.modules.*`.

**Reference:** `reports/board_summary.py:32-58`, `reports/ops_remediation.py:32-66`, `data/fetchers.py:18-40`.

**Standalone-runnable scripts** insert the project root into `sys.path` before importing local packages so they work from any cwd:
```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
```
See `reports/board_summary.py:45`, `reports/vuln_export.py:49`, `data/fetchers.py:28`, `utils/tag_helper.py:27`.

`run_all.py` additionally **purges stale `sys.modules` entries** for `reports`, `data`, `utils` after path injection to avoid namespace collisions when imported from a process that already resolved those names from site-packages — see `run_all.py:53-64`.

---

## Naming Patterns

### Files & Modules

| Kind | Pattern | Example |
|------|---------|---------|
| Report scripts | `reports/<slug>.py` (snake_case slug) | `reports/board_summary.py`, `reports/ops_remediation.py` |
| Metric modules | `reports/modules/<name>_module.py` (auto-discovered by `*_module.py` glob) | `reports/modules/scan_coverage_sla_module.py` |
| Utilities | `utils/<area>.py` | `utils/sla_calculator.py`, `utils/formatters.py` |
| Data fetchers | `data/fetchers.py` (single module) | — |

The `*_module.py` suffix is **load-bearing** — the registry's `_DISCOVERY_PATTERNS` glob (`reports/modules/registry.py:47`) auto-imports any file matching it; renaming a file breaks discovery.

### Identifiers

- **Functions, variables, parameters:** `snake_case` — `run_report`, `vulns_df`, `tag_category`.
- **Classes:** `PascalCase` — `BaseModule`, `ScanCoverageSLAModule`, `ReportComposer`, `ModuleRegistry`.
- **Constants:** `UPPER_SNAKE_CASE` at module top — `SLA_DAYS` (`config.py:28`), `_VALID_REPORTS` (`run_all.py:75`), `DEFAULT_SEVERITIES` (`reports/vuln_export.py:67`).
- **Module-private helpers/constants:** leading underscore — `_extract_plugin_id_from_filter` (`data/fetchers.py:46`), `_BOARD_MODULE_CONFIGS` (`reports/board_summary.py:66`), `_REPORT_MODULE_MAP` (`run_all.py:102`), `_PDF_CSS` (`reports/modules/composer.py:63`).
- **Class constants on `BaseModule` subclasses:** `MODULE_ID`, `DISPLAY_NAME`, `DESCRIPTION`, `REQUIRED_DATA`, `SUPPORTED_OUTPUTS`, `VERSION` — see `reports/modules/base.py:163-174` and `reports/modules/scan_coverage_sla_module.py:97-104`.
- **DataFrame variables:** suffix `_df` — `vulns_df`, `assets_df`, `fixed_vulns_df`. Booleans: prefix `is_` / `has_` — `is_overdue`, `has_plugin_results`.

### Report slugs

Slugs are short, lowercase, snake_case, and **must be globally unique**. They are registered in two places: `run_all.py` (`_VALID_REPORTS` + `_REPORT_MODULE_MAP`) and the `delivery_config.schema.yaml` enum. CLAUDE.md documents but does not register slugs.

### `MODULE_ID` strings

snake_case, globally unique across `reports/modules/`. Convention notes in `reports/modules/base.py:14-25`. Examples: `"scan_coverage_sla"`, `"critical_remediation_sla"`, `"high_risk_assets"`, `"aged_vulns_assets"`.

---

## Type Hints

PEP 604 / 585 modern syntax is used throughout (enabled by `from __future__ import annotations`):

- `list[str]`, `dict[str, int]`, `tuple[int, str]` — never `List[str]`, `Dict[...]`.
- `Optional[X]` from `typing` is still used in function signatures (`utils/sla_calculator.py:19,32-37`, `run_all.py:45`); newer files freely mix `X | None` (`reports/modules/registry.py:136-148`).
- Class attribute annotations use the same modern syntax — `_VALID_REPORTS: frozenset[str]` (`run_all.py:75`), `MODULE_ID: str = ""` (`reports/modules/base.py:163`).
- Function return types are annotated wherever practical; `-> None` is explicit on side-effecting helpers (e.g. `_save_cache` at `data/fetchers.py:188`).

**Keyword-only arguments** are widely used to keep call sites readable: see `run_group(group_config, *, tio=None, run_id=None, ...)` at `run_all.py:424-437` and `run_report(tio, run_id, *, tag_category=None, ...)` at `reports/board_summary.py:82-91`.

---

## Docstring Style

NumPy-style docstrings throughout. Every public function/class includes:

- One-line summary.
- Optional extended description.
- `Parameters` section with name, type, description.
- `Returns` section.
- `Examples` for utility functions where doctests are useful (`config.py:106-114`, `utils/formatters.py:44-49,206-213`).

References: `config.py:79-115` (`vpr_to_severity`), `utils/sla_calculator.py:32-63` (`get_sla_status`), `reports/modules/base.py:43-126` (dataclass docstrings), `reports/modules/registry.py:84-130`.

`BaseModule` docstrings document a **contract** — pure function, no side-effects, always-returns, idempotent — see `reports/modules/base.py:189-225`. Honor that contract in new modules.

---

## Logging

Every module obtains its logger via the standard pattern:

```python
import logging
logger = logging.getLogger(__name__)
```

Examples: `run_all.py:69`, `data/fetchers.py:150`, `utils/sla_calculator.py:25`, `reports/modules/base.py:36`, `reports/modules/composer.py:55`.

### Log message conventions

- **Group/Report-prefixed messages** use bracketed identifiers: `logger.info("[%s] Running report: %s", group_name, slug)` (`run_all.py:583`), `logger.warning("[%s] Pre-fetch failed (%s) — reports will attempt to fetch individually.", ...)` (`run_all.py:563`).
- **Phase markers** for cache and API events: `[CACHE HIT]` (`data/fetchers.py:183`), `[API FETCH]` (`data/fetchers.py:236, 368, 477`).
- **Section dividers** in logs use `===`: `"=== Starting group '%s' (trigger=%s, run_id=%s) ==="` (`run_all.py:502-504`).
- Use `%s` / `%d` lazy formatting — never `f"{...}"` — so the log level filter elides formatting work for suppressed records.
- `logger.exception` is rarely used; instead, `logger.error("[%s] %s\n%s", group_name, msg, traceback.format_exc())` is the prevailing pattern (`run_all.py:521, 605, 636`).
- Module-level helpers expose `_log_prefix(self) -> "[module:<id>]"` (`reports/modules/base.py:424-426`) for use inside metric modules.

### Log configuration

`run_all.py:742-762` sets up `logging.basicConfig` with both stdout and `logs/app.log` handlers, plus a `_ThirdPartyFilter` (`run_all.py:724-739`) that drops sub-WARNING records from `fontTools` and `weasyprint.progress`. `LOG_LEVEL` defaults to `INFO` and is overridable via env var (`config.py:206`).

---

## Error Handling

The codebase deliberately favors **logging-and-continuing** over raising:

1. **Multi-group runs never abort on a single failure.** `run_all.py:884-897` calls `run_group` once per group; failures are caught inside `run_group` and reflected in the returned status dict (`run_all.py:519-530, 603-608, 634-639`).
2. **Reports that fail leave a structured dict** with `status="failed"` / `"partial"` plus `error` text — never an exception (`run_all.py:476-480, 660-668`).
3. **Fetch caches** swallow write errors — `_save_cache` at `data/fetchers.py:188-195` logs a warning rather than raising so a transient disk error doesn't kill a run.
4. **Module `compute()` methods MUST NOT raise.** The contract (`reports/modules/base.py:18-25, 197-201`) requires catching exceptions internally and returning a `ModuleData` with `error` populated. Use the `_empty_result` helper at `reports/modules/base.py:398-422`.
5. **Registry discovery and lookups** log warnings and return `None`/`[]` rather than raising — see `reports/modules/registry.py:391-401, 156`.
6. **`# noqa: BLE001`** is the marker used when intentionally catching `Exception` broadly — `data/fetchers.py:194`, `reports/modules/registry.py:174, 397`.
7. **`SystemExit` is re-raised, not swallowed**, so `tenable_client.get_client()` can hard-exit on auth failure with its own message — `run_all.py:517-518, 851-852`.

When raising **is** appropriate: argparse validation (`utils/tag_helper.py:286 sys.exit(1)`), unrecoverable config issues during `--dry-run`, or programmer errors (assertion-style).

---

## Datetime & Timezone Handling

The codebase distinguishes **two clocks** and uses each consistently:

| Purpose | Clock | Format / Constructor |
|---------|-------|----------------------|
| Report timestamps, SLA math, `generated_at`, `as_of` | UTC | `datetime.now(tz=timezone.utc)` |
| Schedule matching, cache folder names, output folder names | Server local | `datetime.now()` (no tzinfo) |

References:

- UTC for report content: `run_all.py:485, 863`, `reports/board_summary.py:129`, `utils/sla_calculator.py:67`, `utils/formatters.py:319`.
- Local for cache folder names: `run_all.py:487, 489, 864-867`, `reports/board_summary.py:131`. CLAUDE.md explicitly mandates this (cache by local date).
- Local for schedule matching: `run_all.py:830` — `_is_due()` accepts a local `now`, see comment at `run_all.py:188-189`.

**SLA timestamp coercion** in `apply_sla_to_df` at `utils/sla_calculator.py:168-174`: detect non-datetime dtype → `pd.to_datetime(..., utc=True, errors="coerce")`; tz-naive → `dt.tz_localize("UTC")`. Always normalize to UTC-aware before doing date arithmetic.

`utils/formatters.py:307-314` (`fmt_date_utc`) defensively re-applies `tzinfo=timezone.utc` to naive datetimes before formatting.

`run_all.py:758` log format uses `%(asctime)s` (server local time) — that is the chosen convention for log files.

---

## Pandas Patterns

### `.assign()` chains, not in-place mutation

Vectorized column additions use `df.assign(...)` returning a new DataFrame:

```python
df = df.assign(
    first_found=first_found,
    remediated=remediated,
    days_open=days_open,
    sla_days=sla_days,
    days_remaining=days_remaining,
    is_overdue=is_overdue,
)
```
`utils/sla_calculator.py:183-190` and `:204`.

### `np.select` for multi-condition labels

Multi-state categorical assignments use `numpy.select` with explicit `default`:

```python
conditions = [df["remediated"], df["severity"].str.lower() == "info", df["is_overdue"]]
choices    = ["Remediated", "N/A", "Overdue"]
sla_status = pd.Categorical(np.select(conditions, choices, default="Within SLA"), ...)
```
`utils/sla_calculator.py:194-203`, also `reports/vuln_export.py:114-125`.

### `filter_by_*` family

Tag/severity scoping is performed in-memory after the unscoped fetch using helpers in `data/fetchers.py`: `filter_by_tag`, `filter_by_severity` (imported in `reports/vuln_export.py:53-58`, `reports/ops_remediation.py:58-64`). Reports never filter at the API level — the unscoped fetch is cached once per day and reused.

### Empty-DataFrame guards

Helpers check `df.empty` early and return safe defaults rather than raising on missing columns: `utils/sla_calculator.py:163-166, 229-230, 281-282`, `reports/vuln_export.py:199-200`.

### Categorical for ordered enums

Severity and SLA status use `pd.Categorical` with explicit `categories=` to preserve sort order (`utils/sla_calculator.py:200-203`). Severity rank is computed via `{s: i for i, s in enumerate(SEVERITY_ORDER)}` — `utils/formatters.py:87`, `reports/vuln_export.py:71`.

### Caching layer

DataFrames returned by every fetcher are persisted to `<cache_dir>/<dataset>.parquet` (fastparquet engine) so subsequent calls in the same run hit disk, not the API. Helpers `_cache_path`, `_load_cache`, `_save_cache` at `data/fetchers.py:175-195`. `tenacity` retries are applied via the `_retry_policy` decorator dict at `data/fetchers.py:162-168`.

---

## Dataclasses

`@dataclass` is used for **explicit data contracts**, not as a generic struct:

- `ModuleConfig` (`reports/modules/base.py:43-75`) — what the caller hands to a module: `module_id` and an `options: dict` for forward-compatible per-group customization.
- `ModuleData` (`reports/modules/base.py:78-126`) — what `compute()` returns: `module_id`, `display_name`, `metrics`, `table_data`, `chart_data`, `summary_text`, `metadata`, `error`. **Always populate every field on success; on failure, set `error` and leave data fields empty** (use `BaseModule._empty_result`).

`field(default_factory=dict)` is the standard for mutable defaults (`reports/modules/base.py:75`).

---

## The `@register_module` Decorator Pattern

Every metric module subclasses `BaseModule` and is decorated with `@register_module` to self-register on import:

```python
from reports.modules.registry import register_module
from reports.modules.base import BaseModule, ModuleConfig, ModuleData

@register_module
class ScanCoverageSLAModule(BaseModule):
    MODULE_ID    = "scan_coverage_sla"
    DISPLAY_NAME = "Scan Coverage SLA"
    DESCRIPTION  = "..."
    VERSION      = "1.0.0"
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]

    def compute(self, vulns_df, assets_df, report_date, config, **kwargs) -> ModuleData:
        ...
```

References: decorator at `reports/modules/registry.py:413-447`; example usage at `reports/modules/scan_coverage_sla_module.py:87-104`.

**Discovery is automatic.** Importing `reports.modules` triggers `registry.discover()` (`reports/modules/__init__.py:67`), which globs `*_module.py` and `*_metrics.py` files (`reports/modules/registry.py:47`) and imports each. Infrastructure files (`base.py`, `registry.py`, `composer.py`, `__init__.py`) are explicitly excluded (`reports/modules/registry.py:51-56`).

**To add a metric module to an existing composed report (e.g. `board_summary`, `management_summary`):**

1. Create `reports/modules/<name>_module.py` matching the pattern above.
2. Append `ModuleConfig("<MODULE_ID>")` to the report's module list — e.g. `_BOARD_MODULE_CONFIGS` at `reports/board_summary.py:66-71`.
3. No further registration needed — the registry picks it up on next package import.

The renderer methods (`render_pdf_section`, `render_excel_tabs`, `render_email_kpis`) default to no-ops on the base class (`reports/modules/base.py:237-329`) so output-limited modules implement only what they emit. Override `validate_config` (`reports/modules/base.py:331-348`) and `get_audit_info` (`:350-392`) when the module accepts options or has documented calculation formulas.

---

## The Slug → Module Triple-Registration Rule

Adding a new top-level **report** (not a metric module) requires updating three places, enforced by `--dry-run` (`run_all.py:309-311` rejects unknown slugs):

1. **`run_all.py` — `_VALID_REPORTS` frozenset** at `run_all.py:75-87`.
2. **`run_all.py` — `_REPORT_MODULE_MAP` dict** at `run_all.py:102-114` (slug → `"reports.<module_name>"`).
3. **`CLAUDE.md` — YAML Schema Rules** valid-values list for the `reports:` field.

Each report's `run_report()` must accept the standard kwargs `(tio, run_id, *, tag_category, tag_value, output_dir, generated_at, cache_dir)` and return a dict containing at minimum `{"pdf": ..., "excel": ..., "charts": [...]}`. CSV-only reports add `"csv": ...`. See contract at `reports/board_summary.py:82-127` and the call site at `run_all.py:585-601`.

Slug-specific extras (e.g. `csv_severities` for `vuln_export`, `scan_window_days` for `unscanned_assets`) are conditionally injected at `run_all.py:592-597`.

---

## Function Design

- **Keyword-only arguments after `*` for optional/configuration kwargs** — see `run_group` (`run_all.py:424-437`) and `run_report` (`reports/board_summary.py:82-91`).
- **Helpers are module-private (`_leading_underscore`)** when not part of the public API — `_validate_group`, `_dry_run`, `_print_summary`, `_import_report`, `_load_config`, `_is_due`, `_first_str`, `_normalize_vuln_dates`.
- **Public entry points are short and orchestrate** rather than do work inline — `main()` at `run_all.py:742-905` parses args, loads config, dispatches; the heavy lifting lives in `run_group()`.
- **Pure helpers** (no I/O, no API calls) live in `utils/` and are explicitly noted as such — `utils/formatters.py:6` ("All functions are pure (no I/O, no API calls) and safe to import anywhere").

---

## CLI Convention

Every script has an `if __name__ == "__main__":` block with `argparse.ArgumentParser` using `formatter_class=argparse.RawDescriptionHelpFormatter` and a multi-line `epilog` showing real example invocations:

- `run_all.py:764-802`
- `utils/tag_helper.py:228-269`
- `utils/sla_calculator.py:305-328` (smoke-test entry point)

Common arg patterns: `--tag-category`, `--tag-value`, `--output-dir`, `--cache-dir`, `--no-email`, `--dry-run`, `--group`, `--recipients`. Exit codes are documented in module docstrings (e.g. `run_all.py:17-20`).

`rich.console.Console` and `rich.table.Table` are the standard for human-facing terminal output (`run_all.py:50-51, 70`, `utils/tag_helper.py:181-221`).

---

## Module-Level Constants Block

Each large module places a clearly-delimited constants section near the top, separated by `# ===` banners:

```python
# ===========================================================================
# Valid report slugs and frequencies
# ===========================================================================
_VALID_REPORTS: frozenset[str] = frozenset({...})
```

References: `run_all.py:73-130`, `data/fetchers.py:154-168`, `reports/ops_remediation.py:68-100`, `reports/modules/scan_coverage_sla_module.py:45-80`. **`frozenset` is preferred for closed-set membership tests** over `tuple` or `list` — `_VALID_REPORTS`, `_VALID_FREQUENCIES`, `_VALID_DAYS`, `_INFRASTRUCTURE_FILES`, `VALID_SEVERITIES`.

---

## Comments

- **Section banners** use `# ===` lines or `# ---` for nested subsections.
- **`# noqa: PLC0415`** marks intentional in-function imports done to break circular-import chains or defer heavy SDK loading — `run_all.py:515, 554, 631, 849`.
- **`# noqa: BLE001`** marks intentional broad-`Exception` catches.
- Inline TODOs/HACKs are absent from the analyzed sample — when present, prefer adding a `concerns` entry rather than leaving an unannotated comment.

---

*Convention analysis: 2026-05-04*
