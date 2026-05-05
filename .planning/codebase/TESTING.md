# Testing Patterns

**Analysis Date:** 2026-05-04

## Bottom Line

**No automated test framework is configured.** There is no `pytest.ini`, no `pyproject.toml [tool.pytest]`, no `tox.ini`, no `conftest.py`, no `.github/workflows/`, and no CI of any kind in the repository. `pytest` is **not** listed in `requirements.txt` (`requirements.txt:1-43`).

The `tests/` directory exists but contains a mix of two manual smoke-test scripts and several ad-hoc diagnostic / data-analysis utilities. They are run by hand when needed, not as part of an automated pipeline.

Verification before changes is overwhelmingly **manual**, driven by the CLI affordances baked into `run_all.py` and each individual report's `__main__` block.

---

## What's Actually In `tests/`

| File | Type | Lines | Purpose |
|------|------|-------|---------|
| `tests/test_modules_level1.py` | Manual smoke test | 188 | Synthetic-data sanity checks for new metric modules |
| `tests/test_modules_level2.py` | Manual smoke test | 235 | Real-data cross-check of module outputs vs. legacy `_compute_metric_*` functions |
| `tests/analyze_untagged_assets.py` | Diagnostic | 384 | One-off analysis script for assets missing tags |
| `tests/diagnose_first_found.py` | Diagnostic | 61 | Debug script for `first_found` date issues |
| `tests/diagnose_high_risk.py` | Diagnostic | — | Debug script for high-risk asset metric |
| `tests/diagnose_null_date.py` | Diagnostic | — | Debug script for null-date rows |
| `tests/diagnose_raw_vuln.py` | Diagnostic | — | Inspects raw vuln export payload |
| `tests/validate_workstation_rules.py` | Diagnostic | 318 | Validates recast/accept rules against workstation assets |
| `tests/debug_asset_vulns_raw.json` | Fixture | — | Saved API payload for offline inspection |
| `tests/debug_fetch2.txt` | Fixture | — | Captured fetch output |
| `tests/debug_parquet_roundtrip.parquet` | Fixture | — | Cached parquet for roundtrip experiments |

None of these files are imported by any other module — they are all standalone scripts.

---

## How the Two `test_*` Files Work

Both files follow the same homegrown pattern — there is **no test framework** involved.

### `tests/test_modules_level1.py`

- Path injection at `tests/test_modules_level1.py:9-10` so the script can be run directly from anywhere.
- Builds a small synthetic `pd.DataFrame` covering the cases the modules must handle (`tests/test_modules_level1.py:22-31`): open-within-SLA, open-overdue, fixed, reopened.
- Defines a tiny pass/fail counter and a `check(label, condition, got=None)` helper at `tests/test_modules_level1.py:33-44` that prints `PASS  <label>` / `FAIL  <label>  (got: ...)` lines and increments module-level globals.
- Looks up modules through the registry (`registry.get("total_vulns_by_severity")()`), calls `compute()` directly, and asserts on the returned `ModuleData.metrics` dict.

Run command (from a docstring at `tests/test_modules_level1.py:5`):

```bash
python tests/test_modules_level1.py
```

There is no exit code logic — failures print but the script still exits 0. Treat output as advisory.

### `tests/test_modules_level2.py`

- Loads a **specific real-data parquet snapshot** from disk:
  ```python
  CACHE = Path("data/cache/2026-04-09")
  REPORT_DATE = datetime(2026, 4, 9, 7, 0, 0, tzinfo=timezone.utc)
  ```
  (`tests/test_modules_level2.py:30-31`)
- Cross-checks each new module's output against the legacy `_compute_metric_*` functions imported from `reports.management_summary` (`tests/test_modules_level2.py:23-27`).
- Same `check(...)` helper / global PASS/FAIL counter as Level 1.

This file is **environment-dependent** — it only runs cleanly if the named cache folder exists locally with the expected parquet files. It is not portable to a fresh checkout.

### Implications

- These scripts are **migration aids** written when the module infrastructure was being introduced; they verify the new modules match the old per-metric functions on real production data.
- They are **not** continuously maintained — both pre-date current code and reference modules and legacy functions that may evolve.
- A new module added today is **not** automatically covered by either file.

---

## In-File Smoke Tests

A few utility modules expose a small smoke-test under `if __name__ == "__main__":` rather than relying on the `tests/` folder.

`utils/sla_calculator.py:305-328` — runs `get_sla_status` against six hand-crafted cases (Critical overdue, Critical within SLA, High remediated, Medium overdue, Low within SLA, Info N/A) and prints a formatted table. Run it with:

```bash
python utils/sla_calculator.py
```

This is the closest thing to a unit test in the codebase.

`config.py:106-114` includes doctests in the `vpr_to_severity` docstring (`>>> vpr_to_severity(9.5)` ...) but no `doctest` runner is configured anywhere — they serve as documentation only.

---

## Manual Verification Mechanisms (The Real "Test Plan")

In the absence of an automated suite, the codebase relies on these CLI affordances. New code should be validated with these before merge.

### `--dry-run` — Static config validation

```bash
python run_all.py --dry-run
```

Validates `delivery_config.yaml` against:

- Schedule fields (`weekly`/`monthly`/`on_demand` plus required day/time) — `run_all.py:255-303`.
- Recipient list non-empty — `run_all.py:313-316`.
- Report slugs against `_VALID_REPORTS` — `run_all.py:309-311`.
- Required `.env` vars (`TVM_ACCESS_KEY`, `TVM_SECRET_KEY`, SMTP credentials) — `run_all.py:117-124, 330-336`.

Renders a rich-formatted validation table (`run_all.py:338-388`) and exits **1 if any group fails or any env var is missing**, **0 otherwise** (`run_all.py:390-395`).

This is the primary structural guard. If a new report slug is added but not registered in all three required places (see CONVENTIONS.md → "Slug → Module Triple-Registration Rule"), `--dry-run` rejects it.

### `--no-email` — Generate without sending

```bash
python run_all.py --group "Executive Team" --no-email
python reports/board_summary.py --no-email
```

Runs the full report pipeline (API fetch → metric computation → PDF/Excel render) but skips SMTP delivery (`run_all.py:615-616`). Use this to inspect output files locally before letting an email go out.

### `--recipients` — Override delivery list for test sends

```bash
python run_all.py --group "Executive Team" --recipients monroe.justin@gmail.com
```

Replaces the configured recipient list with a comma-separated override and clears CC (`run_all.py:622-628, 858-860`). Use this to send a real test email to yourself.

### Per-report standalone invocation

Every report exposes its own argparse CLI so you can iterate on it without going through the full `run_all` pipeline. Examples:

```bash
python reports/board_summary.py --tag-category "Environment" --tag-value "Production"
python reports/vuln_export.py --severities critical high medium --no-email
python reports/ops_remediation.py --output-dir output/test/ --no-email
python reports/board_summary.py --cache-dir data/cache/2026-04-09/   # offline run from cached parquet
```

References: `reports/board_summary.py:22-29`, `reports/vuln_export.py:18-32`, `reports/ops_remediation.py:23-29`.

The `--cache-dir` flag is particularly important — pointing at a previously captured parquet folder makes the report run **fully offline**, with no API calls, which is the fastest local feedback loop available.

### `python utils/tag_helper.py --list-tags`

Verifies Tenable connectivity and tag discovery without running a full report (`utils/tag_helper.py:228-287`):

```bash
python utils/tag_helper.py --list-tags
python utils/tag_helper.py --list-categories
python utils/tag_helper.py --list-values --category "Environment"
```

### `delivery_log.py` inspection (when implemented)

CLAUDE.md documents `python delivery/delivery_log.py --recent 20` / `--failures` / `--group <name>` / `--from <date> --to <date>` as the audit-log inspection CLI. The file is in the deliverables checklist (CLAUDE.md "Deliverables Checklist") and may not yet exist on disk — confirm before referencing in a phase plan.

### Structural Guards Built Into the Code

Even without tests, several runtime guards catch entire classes of regressions:

- **`_VALID_REPORTS` frozenset** (`run_all.py:75-87`) — adding a slug to YAML without code changes fails dry-run.
- **`_REPORT_MODULE_MAP`** (`run_all.py:102-114`) — missing entries log a warning and skip the report (`run_all.py:411-417`) rather than crashing.
- **`registry.validate_module_list`** (`reports/modules/registry.py:191-222`) — returns `(valid, invalid)` so callers can warn before dispatching.
- **`@register_module` duplicate detection** (`reports/modules/registry.py:110-122`) — re-registration is a logged no-op, not a crash.
- **`tenacity` retry policy** (`data/fetchers.py:162-168`) — masks transient API flakiness so a flaky network doesn't read as a test failure.

---

## Test Data / Fixtures

There are no proper fixture libraries. The closest analogues:

- **Parquet caches under `data/cache/<YYYY-MM-DD>/`** are reused as offline fixtures by `tests/test_modules_level2.py:30` and by reports invoked with `--cache-dir`.
- **`tests/debug_*.json` / `*.parquet`** files are saved API payloads used for ad-hoc inspection.
- The synthetic DataFrame at `tests/test_modules_level1.py:22-31` is the only inline fixture and covers the most common per-row state combinations.

---

## What Coverage Looks Like Today

| Area | Coverage |
|------|----------|
| Top-level orchestrator (`run_all.py`) | None |
| Scheduler (`scheduler.py`) | None |
| Fetchers (`data/fetchers.py`) | None |
| SLA calculator (`utils/sla_calculator.py`) | In-module smoke test only (`:305-328`) |
| Formatters (`utils/formatters.py`) | None |
| Tag helper (`utils/tag_helper.py`) | None |
| Module registry / composer | None |
| Individual `*_module.py` metric modules | Partial — Level 1 (synthetic) and Level 2 (cached real data) cover `total_vulns_by_severity`, `patch_compliance_rate`, `mttr_by_severity` and the four board modules at the time the tests were written |
| Top-level reports | None — exercised manually via `--no-email` and `--dry-run` |
| Email delivery, PDF/Excel exporters | None |

If a phase asks you to add tests, prefer pytest (it would need to be added to `requirements.txt`) and place them in `tests/` mirroring the existing `test_*.py` naming. There is currently no `conftest.py` to extend.

---

*Testing analysis: 2026-05-04*
