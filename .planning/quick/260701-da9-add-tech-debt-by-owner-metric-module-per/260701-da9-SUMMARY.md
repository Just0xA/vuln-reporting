---
status: complete
phase: quick-260701-da9
plan: 01
subsystem: reports/modules
tags: [module, composed_report, rag, tech-debt, owner-segmentation]
dependency-graph:
  requires: [reports/modules/base.py, reports/modules/rag_utils.py, reports/modules/format_utils.py, reports/modules/board_report_utils.py, config.py, utils/sla_calculator.py]
  provides: [tech_debt_by_owner module (auto-discovered, usable via composed_report `modules:`)]
  affects: []
tech-stack:
  added: []
  patterns:
    - "Four-channel render contract (PDF/Excel/email panel/analyst tabs) + cover-page RAG strip"
    - "VPR-primary / native-fallback severity derivation via config.vpr_to_severity"
    - "Owner tag parse/join mirroring board_report_utils.extract_owner semantics"
key-files:
  created:
    - reports/modules/tech_debt_by_owner_module.py
    - tests/test_tech_debt_by_owner_module.py
  modified: []
decisions:
  - "Default owner_category='Owner' delegates to canonical extract_owner() (join separator '; '); non-default categories use an inline parser (join separator ' | ' per CONTEXT.md) — both are correct for their respective code paths, documented in get_audit_info() and tests."
  - "RAG thresholds default green_max=0, amber_max=4 (>4 is red), option-overridable per delivery group."
metrics:
  duration_seconds: 2400
  completed: 2026-07-01
---

# Quick Task 260701-da9: Add Tech Debt by Owner Metric Module Summary

New auto-discovered `tech_debt_by_owner` module quantifying each asset owner's
overdue Critical+High backlog (VPR-primary severity, native fallback), with
full four-channel render contract and cover-page RAG strip.

## What Was Built

`reports/modules/tech_debt_by_owner_module.py` — `TechDebtByOwnerModule`
(`MODULE_ID = "tech_debt_by_owner"`, `REQUIRED_DATA = ["vulns", "assets"]`),
auto-discovered via `@register_module` + the `*_module.py` glob (no edits to
`composed_report.py`, `composer.py`, `run_all.py`, or `CLAUDE.md` — usable
today by adding `tech_debt_by_owner` to a group's `composed_report` `modules:`
list in `delivery_config.yaml`).

**compute()**: filters to open states (`open`/`reopened`), derives severity
per row via `vpr_to_severity(vpr_score, fallback=native_severity)`, computes
overdue vectorized (`days_open > SLA_DAYS[severity]`, mirroring
`utils/sla_calculator.py` semantics), keeps overdue Critical+High rows,
joins each kept row's `asset_uuid` to an owner via `build_owner_map()`
(module-level, importable — delegates to `board_report_utils.extract_owner`
for the default `"Owner"` category, or an inline single-pass parser for any
other configured category), and aggregates per owner into
`{owner, overdue_critical, overdue_high, total, rag_status}` rows sorted
Total desc.

**RAG**: per-owner count `<= green_max` (default 0) → green;
`<= amber_max` (default 4) → yellow; else red — both thresholds
option-overridable. Strip status = worst per-owner status (red > yellow >
green); headline = total overdue Crit+High across owners; `"no_data"` /
`"—"` when zero findings are in scope.

**Four channels**: `render_pdf_section` / `render_excel_tabs` /
`render_email_panel` render an `Owner | Overdue Critical | Overdue High |
Total | RAG` table (Total-desc, footer total row); `render_analyst_tabs`
returns a flat `Tech Debt Detail` drill-down (owner, days_open, severity,
plugin_id/plugin_name when present); `render_rag_strip_entry` uses the
base-class default (honors `data.rag_strip` populated in `compute()`).
All renderers guard `data.error` and use `safe_int`/`STATUS_COLOR`/
`STATUS_LABEL` — no inline f-string format specs on possibly-None values.

`tests/test_tech_debt_by_owner_module.py` — 33 unit tests covering
registration/auto-discovery, owner parse/join (both the default-category
`extract_owner` path and the custom-category inline-parse path), the
`(Unassigned)` bucket (missing Owner tag and no-matching-asset cases),
overdue Crit+High counting (with within-SLA and Medium exclusions), VPR
severity with native fallback, RAG threshold buckets (default and
option-overridden), worst-owner strip status, headline sum, the
zero-in-scope `no_data` case, and the zero-row four-channel empty-data
guard (all four render methods + rag strip, `NaN` absence asserted).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] Test environment had no `pytest` installed**
- **Found during:** Verify step for Task 2
- **Issue:** `.venv/bin/python -m pytest` failed with `No module named pytest`
  — the project venv had no test dependencies installed (pytest is documented
  as a test-only dependency in `requirements-dev.txt`, never in the runtime
  `pyproject.toml`/lockfile per project convention, and the venv was
  provisioned runtime-only).
- **Fix:** Installed the pre-existing, already-committed
  `requirements-dev.txt` (`pytest>=8.3`, `pytest-xdist>=3.6`, `pypdf>=5.0`)
  into `.venv` via `uv pip install --python .venv/bin/python -r
  requirements-dev.txt`. No new dependency was introduced — this file was
  already tracked in the repo and documents itself as the sanctioned
  test-dependency installer (`python -m pip install -r
  requirements-dev.txt`, adapted to `uv pip install` since the venv had no
  `pip` binary either).
- **Files modified:** None (venv-local package install only; no tracked
  files changed).
- **Commit:** N/A (environment-only change, not a code change).

**2. [Rule 1 - Test expectation bug] Initial test asserted the wrong
   multi-value join separator for the default Owner category**
- **Found during:** Task 2 test-run
- **Issue:** My first draft of
  `test_multi_value_owner_joins_with_pipe` asserted `" | "` for the
  *default* `owner_category="Owner"` path, but per the plan's own interface
  spec, the default path delegates to `board_report_utils.extract_owner()`,
  whose canonical join separator is `"; "` (alphabetical, deduped) — `" | "`
  is only used by the module's own inline parser for a *non-default*
  `owner_category`.
- **Fix:** Split into two tests: one for the custom-category inline-parse
  path (`" | "`, via a `Team=` tag) and one for the default `"Owner"`
  category path (`"; "`, via `extract_owner`), plus corrected the
  end-to-end test's expected owner label to `"Alpha; Beta"`.
- **Files modified:** `tests/test_tech_debt_by_owner_module.py` (test-only,
  same file as the task's deliverable — no separate commit).
- **Commit:** Included in `654e042` (Task 2's single commit).

No auth gates encountered.

## Self-Check: PASSED

- FOUND: `reports/modules/tech_debt_by_owner_module.py` (699 lines)
- FOUND: `tests/test_tech_debt_by_owner_module.py` (496 lines)
- FOUND commit `5e38346` (Task 1 — module implementation)
- FOUND commit `654e042` (Task 2 — unit tests)
- `python -c "import reports.modules"` succeeds; `tech_debt_by_owner` is in
  `registry._modules`.
- `.venv/bin/python -m pytest tests/test_tech_debt_by_owner_module.py -q` —
  33 passed, 0 failed.
- `git status --short` shows only the pre-existing `CLAUDE.md` modification
  and the untouched `.planning/quick/.../` docs dir — no edits outside the
  two target files.
