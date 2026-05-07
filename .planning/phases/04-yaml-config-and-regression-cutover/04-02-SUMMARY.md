---
phase: 4
plan: 04-02
subsystem: delivery-config / board_summary plumbing
tags: [analyst_detail, opt-out, kwarg-plumbing, board_summary, run_group, bundle-forward]
requires:
  - 04-01  # jsonschema validation + analyst_detail field in schema
provides:
  - "reports.board_summary.run_report(analyst_detail: bool = True) keyword-only kwarg wired to composer.run_full_pipeline(generate_analyst=...)"
  - "run_all.run_group() slug-specific dispatch reads group_config.get('analyst_detail', True) for board_summary"
  - "reports.board_summary.run_report return dict carries `_bundle` (private) with the full in-memory composer pipeline output (pdf_html, excel_workbook, analyst_workbook_path, email_body_html, email_inline_images, errors, module_results) — unblocks Plan 04-04 structural-snapshot extractor without re-invoking composer or parsing on-disk PDF/Excel"
  - "tests/test_phase4_analyst_detail_toggle.py: composer-level binary contract regression test (False ⇒ analyst_excel is None always)"
affects:
  - reports/board_summary.py
  - run_all.py
  - tests/test_phase4_analyst_detail_toggle.py
tech-stack:
  added: []
  patterns:
    - "Slug-specific kwarg dispatch in run_group() — mirrors existing vuln_export / unscanned_assets pattern; future module-composed reports (e.g. management_summary per D-25) can reuse the same one-line shape"
    - "Underscore-prefixed private key (`_bundle`) on a public return dict to expose internal/diagnostic in-memory state without breaking the public contract"
    - "Default-injection at the Python read site (`dict.get(key, default)`) because jsonschema 4.x does not auto-inject schema defaults"
key-files:
  created:
    - tests/test_phase4_analyst_detail_toggle.py
  modified:
    - reports/board_summary.py
    - run_all.py
decisions:
  - "Default-true semantics preserved: groups omitting analyst_detail (including the existing 'Test Pull') see analyst_detail=True downstream because dict.get('analyst_detail', True) returns the default."
  - "_bundle as a leading-underscore private key (not a public return-dict promotion) — public contract (pdf, excel, charts, metrics, analyst_excel, email_body_html, email_inline_images, email_kpis) unchanged in shape and value. Downstream consumers ignore unknown keys per CLAUDE.md D-22 routing pattern."
  - "Composer-level test (using actual Phase 2 _make_composer / _make_results helpers) over an end-to-end run_report test: empty fixtures suffice because the toggle's effect is binary regardless of data volume; populated data would only add coverage for analyst-rows CONTENT (out of scope here)."
metrics:
  duration: ~22 minutes
  completed: 2026-05-06
---

# Phase 4 Plan 04-02: analyst_detail YAML toggle and _bundle forward — Summary

CONFIG-03 / D-04-03 plumbing: `analyst_detail: false` in `delivery_config.yaml` now opts a group out of the board_summary analyst-detail companion workbook by flipping a single hardcoded literal and adding one slug-specific dispatch line. Additionally, `board_summary.run_report` now exposes the in-memory composer bundle under a private `_bundle` key, unblocking Plan 04-04's structural-snapshot extractor.

## Commits

| Task | Type | Hash | Subject |
|------|------|------|---------|
| 1 | feat | `fdd3b25` | feat(04-02): add analyst_detail kwarg to board_summary.run_report |
| 2 | feat | `9d947ca` | feat(04-02): dispatch analyst_detail from delivery_config to board_summary |
| 3 | test | `c16e4c3` | test(04-02): lock analyst_detail opt-out behavior end-to-end |
| 4 | feat | `0a4fe8c` | feat(04-02): forward composer bundle under _bundle key for cutover smoke script |

All four commits are atomic; each stages only the file(s) cited in its task.

## What changed

### Task 1 — `reports/board_summary.py`
- Added `analyst_detail: bool = True` as the last keyword-only parameter on `run_report`.
- Replaced hardcoded `generate_analyst = True` at the `composer.run_full_pipeline(...)` call site with `generate_analyst = analyst_detail`.
- Updated the docstring `Parameters` block with the new parameter description (default semantics, opt-out behavior, downstream None-path silently handled by `delivery/email_sender.py:148-151`).

### Task 2 — `run_all.py`
- Added a third slug-specific dispatch block in `run_group()` between `vuln_export` and `unscanned_assets`:
  ```python
  if slug == "board_summary":
      report_kwargs["analyst_detail"] = group_config.get("analyst_detail", True)
  ```
- jsonschema 4.x does not auto-inject schema defaults — the Python-side `.get()` with `True` is the canonical default-injection point.

### Task 3 — `tests/test_phase4_analyst_detail_toggle.py` (new)
- Composer-level binary-contract regression. Uses the **actual** Phase 2 fixture helpers `_make_composer` and `_make_results` from `tests/test_phase2_composer_pipeline.py:162-180` (the assumed `_build_synthetic_*` helpers do NOT exist in that file).
- Three checks: (A1) `generate_analyst=False` → `bundle["analyst_excel"]` is None; (A2) no orphan analyst `.xlsx` written to `output_dir` for the False path; (B) `generate_analyst=True` → real Path on disk OR D-20 all-empty fallback None (accepted alternate; the binary contract is "False always None").
- Force-added with `git add -f` because `tests/` is `.gitignore`d (matches Plan 04-01 / Phase 2 / Phase 3 precedent).

### Task 4 — `reports/board_summary.py`
- Refactored the inline `return {...}` literal to `result_dict: dict = {...}` followed by `result_dict["_bundle"] = bundle; return result_dict`.
- Public-contract keys (`pdf`, `excel`, `charts`, `metrics`, `analyst_excel`, `email_body_html`, `email_inline_images`, `email_kpis`) unchanged in shape and value.
- The new `_bundle` key carries the full in-memory composer pipeline output (`pdf_html`, `excel_workbook`, `analyst_workbook_path`, `email_body_html`, `email_inline_images`, `errors`, `module_results`).

## Verification (all gates from PLAN `<verification>`)

| Gate | Status | Evidence |
|------|--------|----------|
| `inspect.signature(run_report)` shows `analyst_detail` keyword-only with default True | PASS | `OK signature` |
| `grep -E "generate_analyst\s*=\s*True" reports/board_summary.py` returns nothing | PASS | (empty grep) |
| `grep -E "generate_analyst\s*=\s*analyst_detail" reports/board_summary.py` returns 1 match | PASS | line 258 |
| `run_all.py` contains `if slug == "board_summary":` and `group_config.get("analyst_detail", True)` | PASS | lines 636 / 642 |
| `python tests/test_phase4_analyst_detail_toggle.py` exits 0 | PASS | 3/3 PASS |
| Test calls `_make_composer(...)` / `_make_results(...)` (NOT `_build_synthetic_*`) | PASS | grep confirmed |
| `python tests/test_phase2_composer_pipeline.py` continues to pass 11/11 | PASS | 11/11 |
| `python tests/test_phase4_schema_validation.py` (Plan 04-01) continues to pass | PASS | All checks passed |
| `python run_all.py --dry-run` against unchanged `delivery_config.yaml` exits 0 | PASS | "All 3 group(s) validated successfully." |
| `grep -cE 'result_dict\["_bundle"\]\s*=\s*bundle' reports/board_summary.py` returns 1 | PASS | 1 |
| Return dict carries `_bundle` with the in-memory composer bundle | PASS | manual import + Task 3 still green after Task 4 refactor |

## Deviations from Plan

None of substance — plan executed exactly as written.

One minor note: `tests/` is `.gitignore`d at the repo root, so Task 3's `git add` required `-f`. This matches the Plan 04-01 precedent and was anticipated by the Phase 4 wave-1 commits (`tests/test_phase4_schema_validation.py` was also force-added in Plan 04-01). Documented in the Task 3 commit body.

## Threat Flags

None. The two threat-model rows (T-04-02-01 information disclosure / T-04-02-02 default drift) are mitigated:

- **T-04-02-01**: When `analyst_detail=False` the composer short-circuits the analyst workbook BEFORE any drill-down rows are written to disk — verified by Task 3 check A2 (no orphan `*analyst*.xlsx` in `output_dir`).
- **T-04-02-02**: Default lives in exactly two places — schema's `default: true` (informational) and Python's `dict.get('analyst_detail', True)` at the read site. The default-true case is exercised implicitly by every existing group in `delivery_config.yaml` (none of which set the field today) and explicitly by Task 3 control case B.

## Self-Check: PASSED

- Files exist:
  - `reports/board_summary.py` — modified (Tasks 1, 4)
  - `run_all.py` — modified (Task 2)
  - `tests/test_phase4_analyst_detail_toggle.py` — created (Task 3)
- Commits exist on `main`: `fdd3b25`, `9d947ca`, `c16e4c3`, `0a4fe8c`
- All four prior-plan tests still pass: Phase 2 (11/11), Phase 4 schema (6/6), Phase 4 analyst-detail (3/3)
- Plan 04-04 prerequisite satisfied: `result['_bundle']` reachable from board_summary.run_report's return value

## Plan 04-04 unblock note

Plan 04-04's regression smoke script (`scripts/smoke_board_summary_cutover.py`) can now exercise both delivery paths:
- `analyst_detail: true` (default) → bundle contains analyst workbook → structural snapshot includes analyst tab data
- `analyst_detail: false` → `bundle["analyst_workbook_path"] is None` → structural snapshot omits the analyst tab section

The `_bundle` private key on the return dict means the smoke script reads `result["_bundle"]["pdf_html"]` / `["excel_workbook"]` / `["module_results"]` directly without re-invoking the composer or parsing on-disk artifacts.
