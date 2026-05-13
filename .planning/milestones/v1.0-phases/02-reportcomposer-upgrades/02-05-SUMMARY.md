---
phase: 02-reportcomposer-upgrades
plan: 05
subsystem: report-composer
tags:
  - testing
  - regression-baseline
  - error-isolation
  - phase-2
requirements:
  - COMPOSER-01
  - COMPOSER-02
  - COMPOSER-03
  - COMPOSER-04
dependency_graph:
  requires:
    - reports/modules/composer.py:run_full_pipeline (Plan 02-04, D-22)
    - reports/modules/composer.py:assemble_pdf with page-2 RAG strip (Plan 02-01, D-02..D-08)
    - reports/modules/composer.py:assemble_email_body (Plan 02-02, D-09..D-15)
    - reports/modules/composer.py:assemble_analyst_workbook + _write_analyst_metadata_tab (Plan 02-03, D-16..D-21)
    - reports/modules/base.py:BaseModule.render_rag_strip_entry / render_email_panel / render_analyst_tabs (Phase 1 four-channel contract)
  provides:
    - tests/test_phase2_composer_pipeline.py (permanent Phase 2 regression bar)
  affects:
    - none — fully additive new test artifact
tech-stack:
  added: []
  patterns:
    - Standalone runnable test script (mirrors `tests/test_modules_level1.py`); no pytest dependency, exits 0 on PASS / 1 on FAIL
    - `@register_module` self-registration for stub modules at import time, namespaced with `_phase2_test_*` prefix to avoid registry collisions with the 8 production modules
    - Two-pronged D-29 hash-stability strategy: content-level hash (Check 4a, always green) AND mtime-normalized byte-level hash (Check 4b, ideal-case green / SKIP on degraded openpyxl)
    - ZIP-entry mtime normalization via in-memory rewrite to defeat openpyxl's per-entry timestamp non-determinism
    - `_SkipCheck` sentinel exception so the test driver can render `[SKIP]` for the optional Check 4b without forcing a `[FAIL]`
key-files:
  created:
    - tests/test_phase2_composer_pipeline.py — Phase 2 regression + isolation bar (492 lines, 1 file, 1 task, 1 commit)
  modified: []
decisions:
  - D-22 honored — Check 1 asserts the bundle dict has EXACTLY {pdf_html, excel_workbook, analyst_workbook_path, email_body_html, email_kpis, metrics, errors}
  - D-27 honored — Check 2 asserts email-panel order AND analyst-workbook tab order both follow `_module_configs` order (B before A when configured B-first)
  - D-28 honored — Check 5 (email panel) and Check 6 (analyst tabs) prove one module's exception does NOT abort assembly of other modules' contributions; the failed module's slot becomes a visible placeholder (email) or a recorded failures row (analyst _Metadata)
  - D-29 honored via two-pronged design — Check 3 covers PDF cover-region hash stability + page-2 strip placement; Check 4a covers main-Excel content-hash stability; Check 4b covers main-Excel mtime-normalized byte-hash stability (the literal "sha256 of the main xlsx" wording)
metrics:
  completed: 2026-05-06
  duration: ~10 minutes
  tasks: 1
  files_created: 1
  commits: 1
---

# Phase 2 Plan 05: Composer Pipeline Regression + Isolation Bar — Summary

Implements the wave-3 verification deliverable for COMPOSER-01..04. Ships a single standalone Python script `tests/test_phase2_composer_pipeline.py` that locks the wave-1 + wave-2 ReportComposer surfaces against future regression. Seven sequential checks cover bundle shape (D-22), per-channel module ordering (D-27), per-module exception isolation across the email-panel and analyst-tabs channels (D-28), and a two-pronged regression-snapshot strategy for D-29: PDF HTML + cover-region hash stability, plus main-Excel content-hash AND mtime-normalized byte-hash stability.

The script exits 0 on success and 1 on any `[FAIL]` / `[ERROR]`; `[SKIP]` (only valid for Check 4b under degraded openpyxl conditions) is non-fatal per the deviation note in the plan's `<must_haves>`.

## What Shipped

### Task 1 — `tests/test_phase2_composer_pipeline.py` (the seven checks)

| Check | Verifies | Decision / Requirement |
|-------|----------|------------------------|
| 1. Bundle-shape regression | `run_full_pipeline()` returns EXACTLY `{pdf_html, excel_workbook, analyst_workbook_path, email_body_html, email_kpis, metrics, errors}` | D-22, COMPOSER-04 |
| 2. Module-configs ordering | When configured `[B, A]`, `email_body_html` has `PANEL_B_BODY` before `PANEL_A_BODY`; analyst workbook has `AnalystTabB` before `AnalystTabA` (skipping `_Metadata`) | D-27 |
| 3. Page-2 strip + cover stability | PDF HTML carries `<div class="rag-strip">` AFTER `<div class="report-cover">`; the cover region between `<div class="report-cover">` and the first `</div>` after it is hash-stable across two equivalent runs | D-29 (PDF intent), COMPOSER-01 |
| 4a. Excel CONTENT hash stability | Hashes per-sheet, per-cell `repr(value)` of the saved main-Excel — defeats openpyxl ZipInfo mtime non-determinism by hashing CONTENT, not bytes | D-29 (intent) |
| 4b. Excel BYTE hash stability (mtime-normalized) | Hashes the .xlsx bytes AFTER rewriting the ZIP container with all internal entry mtimes forced to the ZIP epoch (1980-01-01 00:00:00) — honors D-29's literal "sha256 of the main xlsx" wording | D-29 (literal) |
| 5. Email panel exception isolation | Boom stub raises in `render_email_panel`; placeholder `<div>` containing `phase2-email-boom` and the literal phrase `email panel render failed` appears in body; OTHER modules' panels (`PANEL_A_BODY`, `PANEL_B_BODY`) still render IN ORDER | D-28, COMPOSER-02 |
| 6. Analyst tabs exception isolation | Boom stub raises in `render_analyst_tabs`; failure recorded at `_Metadata!A6=Failures` with rows starting at A8 carrying `_phase2_test_panel_boom` and `phase2-analyst-boom`; surviving modules' tabs (`AnalystTabA`, `AnalystTabB`) still appear in the workbook | D-28, COMPOSER-03 |

- **File:** `tests/test_phase2_composer_pipeline.py` (492 lines)
- **Commit:** `894f5a6`

### Stub-module isolation

Three test stubs are registered at import time via `@register_module`:

| MODULE_ID | render_email_panel | render_analyst_tabs | render_rag_strip_entry |
|-----------|--------------------|---------------------|--------------------------|
| `_phase2_test_panel_a` | returns `<table data-stub="A">PANEL_A_BODY</table>` | returns `[("AnalystTabA", df)]` | green strip cell |
| `_phase2_test_panel_b` | returns `<table data-stub="B">PANEL_B_BODY</table>` | returns `[("AnalystTabB", df)]` | yellow strip cell |
| `_phase2_test_panel_boom` | RAISES `RuntimeError("phase2-email-boom")` | RAISES `RuntimeError("phase2-analyst-boom")` | inherits Phase 1 default |

The `_phase2_test_` namespace prefix prevents collisions with the 8 production modules (`scan_coverage_sla`, `critical_remediation_sla`, `high_risk_assets`, `aged_vulns_assets`, plus the 4 management-summary modules). Production reports run via `python run_all.py` never import `tests/`, so registry pollution is process-local to the test invocation only.

## Two-Pronged D-29 Design

D-29 reads literally as "sha256 hashes of the main pdf and main xlsx". The PDF side is honored as written via Check 3 — `assemble_pdf()` returns a deterministic HTML string, and sha256 of the HTML is byte-stable across runs.

The xlsx side ships **two checks** because openpyxl writes per-ZipInfo `date_time` values from the wall clock when saving, which makes raw `.xlsx` bytes non-deterministic by default:

- **Check 4a (mandatory, always green)** — Content-level sha256 over per-cell `repr(value)` extracted via `iter_rows(values_only=True)`. Defeats mtime non-determinism by definition because the hash never touches the ZIP container. This satisfies D-29's *intent* (content equivalence).
- **Check 4b (mandatory, ideal-case green)** — Byte-level sha256 over the .xlsx file with all internal ZIP entry mtimes normalized to the ZIP epoch (1980-01-01 00:00:00) via a thin in-memory `zipfile.ZipFile` rewrite. Honors D-29's *literal* "sha256 of the main xlsx" wording. The rewrite raises `_SkipCheck` if the openpyxl ZIP layout cannot be losslessly reconstructed (extras / encryption / runtime drift); the driver renders that as `[SKIP]` rather than `[FAIL]`. Check 4a alone still satisfies D-29's intent in that degraded path.

**Local run on this workstation: Check 4b lands `[PASS]`** — openpyxl 3.1.5 + Python 3.14.3 produce ZIP layouts that the mtime-normalization rewrite handles cleanly, so the literal byte-stability claim holds today.

## Verification Evidence

```text
======================================================================
Phase 2 ReportComposer Pipeline — regression + isolation checks
======================================================================
[PASS] D-22 bundle shape
[PASS] D-27 module ordering across channels
[PASS] D-29 page-2 strip + cover stability
[PASS] D-29 main-Excel content hash stability
[PASS] D-29 main-Excel mtime-normalized byte stability
[PASS] D-28 email panel exception isolation
[PASS] D-28 analyst tabs exception isolation
----------------------------------------------------------------------
Result: 7/7 passed, 0 skipped, 0 failed.
```

Determinism verified by running the script back-to-back; both runs print `Result: 7/7 passed, 0 skipped, 0 failed.` Exit codes 0 + 0.

Import as a module without pytest installed: `python -c "import tests.test_phase2_composer_pipeline; print('OK')"` prints `OK`.

Acceptance-criteria grep counts:

| Pattern | File | Expected | Actual |
|---------|------|----------|--------|
| `_phase2_test_` | tests/test_phase2_composer_pipeline.py | ≥ 6 | 25 ✓ |
| `def check_4a_excel_content_hash_stability` / `def check_4b_excel_byte_hash_stability_mtime_normalized` | tests/test_phase2_composer_pipeline.py | 2 | 2 ✓ |
| `def _normalize_xlsx_mtimes` | tests/test_phase2_composer_pipeline.py | 1 | 1 ✓ |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug in plan's verify code] Check 2 read analyst workbook outside `TemporaryDirectory` context**

- **Found during:** First execution of the test script.
- **Issue:** The plan's literal action-block code for Check 2 closed the `with tempfile.TemporaryDirectory() as td:` block BEFORE calling `openpyxl.load_workbook(str(wb_path))`. The temp directory had already been cleaned up, so the load failed with `FileNotFoundError: [Errno 2] No such file or directory: '...phase2_test_2026-05-06_analyst.xlsx'`.
- **Fix:** Moved the analyst-workbook assertions (read + sheet-name comparison) INSIDE the `with` block. Behavior identical, file lifetime now correct. The earlier email-body assertions also moved inside (they didn't strictly need to, but keeping the whole block under one indentation level is cleaner and prevents future drift).
- **Files modified:** `tests/test_phase2_composer_pipeline.py` (Check 2 body indented one level deeper).
- **Commit:** `894f5a6` (bundled with Task 1 — the bug existed only inside the unit-of-work being committed).

**2. [Rule 3 — Blocking: gitignore vs. plan's required deliverable] Force-add past `tests/` gitignore rule**

- **Found during:** Initial `git add tests/test_phase2_composer_pipeline.py` after Task 1.
- **Issue:** The repo's `.gitignore` line 59 (`tests/`) ignores the entire `tests/` directory tree. The plan's `<output>` and `<must_haves>` explicitly require this file as the permanent Phase 2 regression bar deliverable, and the SUMMARY's Self-Check would fail without a tracked artifact. The plan's `<acceptance_criteria>` also implicitly requires the file in git via the post-commit verification in `<verification>`.
- **Fix:** Used `git add -f tests/test_phase2_composer_pipeline.py` to force-track the single file past the directory-level rule. The `.gitignore` itself was NOT modified — leaving it intact preserves project intent for the other untracked dev / scratch test scripts (`tests/test_modules_level1.py`, `tests/diagnose_*.py`, etc., which match the local-only convention seen in pre-Plan baseline).
- **Files modified:** none (only the one force-added artifact).
- **Commit:** `894f5a6`.

No other deviations — D-22, D-27, D-28, D-29 honored; the documented xlsx byte-hash deviation in 02-05-PLAN.md `<must_haves>` did NOT need to fire because Check 4b lands `[PASS]` on this workstation.

## Threat Flags

None. The implementation respects the threat register documented in the plan:

- **T-02-05-01** (stub registration leaks into production process) — mitigated by `_phase2_test_*` namespace prefix + the fact that `run_all.py` / `scheduler.py` / production report scripts never import `tests/`. Verified by reading registry.discover() at registry.py:228+413 — globs `*_module.py` / `*_metrics.py` only, and the test file lives in `tests/` (not `reports/modules/`) so its glob is never matched.
- **T-02-05-02** (information disclosure via tempfile contents) — accepted; temp dirs auto-cleanup, no real Tenable data flows through.
- **T-02-05-03** (test deadlock or runaway loop) — mitigated; `_unique_sheet_name` 100-attempt cap + distinct stub sheet names so the cap is never approached.
- **T-02-05-04** (hash stability false positive over time) — mitigated via the two-pronged D-29 design (Check 4a content hash + Check 4b mtime-normalized byte hash). Either failing surfaces a real regression; both passing locks the surface.

No new security-relevant surface introduced (no new network endpoints, no new auth paths, no schema changes at trust boundaries). The test stubs are project-internal Python code reviewed during PR.

## Confirmation: Byte-Unchanged Surfaces

| Surface | Status |
|---------|--------|
| `reports/modules/composer.py` (all methods) | byte-unchanged — Plan 02-05 only consumes the surfaces, never modifies them |
| `reports/modules/base.py` (all methods, including the four-channel render contract defaults) | byte-unchanged |
| `reports/modules/registry.py` (registry, discover, register_module) | byte-unchanged |
| `reports/modules/rag_utils.py` / `format_utils.py` | byte-unchanged |
| `reports/board_summary.py` / `reports/management_summary.py` | byte-unchanged — Plan 02-05 does NOT exercise the report scripts directly; the test drives `ReportComposer` against stub modules |
| 8 module discovery (board + management board metric modules) | unchanged — `len(registry._modules) == 8` baseline unaffected; the 3 stub modules add to that count IN-PROCESS only when this test script is run |
| `delivery/email_template.py` / `templates/report_email.html` | byte-unchanged |
| `requirements.txt` | byte-unchanged — no new package dependency, the test uses only `pandas` + `openpyxl` (already pinned) and stdlib (`hashlib`, `io`, `tempfile`, `zipfile`, `pathlib`, `argparse`, `traceback`, `sys`) |

## Phase 2 Wave 3 — Final Integration Surface

Plan 02-05 is the verifier integrator that nails down the wave-1 + wave-2 contracts:

| Wave 1 surface | Locked by |
|----------------|-----------|
| `assemble_pdf` page-2 RAG strip | Check 3 (presence + placement + cover-stability) |
| `_build_rag_strip_page` cell-per-module | Check 3 implicitly (the strip render is exercised end-to-end); Check 1 implicitly (bundle's `pdf_html` carries it) |
| `BaseModule.render_rag_strip_entry` Phase 1 default | Stub `render_rag_strip_entry` overrides exercised in Check 3's two-run determinism — proves the override path is byte-stable |
| `assemble_email_body` panels-only fragment | Check 5 (isolation + placeholder + ordering); Check 1 (bundle key) |
| `assemble_analyst_workbook` separate-file companion | Check 6 (isolation + _Metadata Failures); Check 2 (tab ordering); Check 1 (bundle path key) |

| Wave 2 surface | Locked by |
|----------------|-----------|
| `run_full_pipeline` 7-key bundle dict | Check 1 (exact-keys assertion); Check 2 (delegates to per-channel methods in order) |
| `assemble_analyst_workbook` `_Metadata` Failures subsection (D-19 + D-28) | Check 6 (asserts A6=Failures; rows from A8 with module_id + error text) |
| Per-channel error isolation (D-28) | Check 5 (email) + Check 6 (analyst); both prove that boom-stub doesn't abort surviving modules |

After Phase 2 wave 3, any future change to the four channels that breaks any of these properties will surface as a `[FAIL]` here — the test is the permanent regression bar called for in 02-CONTEXT.md decision D-29.

## Self-Check: PASSED

- File `tests/test_phase2_composer_pipeline.py` exists.
- Running `python tests/test_phase2_composer_pipeline.py` exits 0 with `Result: 7/7 passed, 0 skipped, 0 failed.`
- Re-running back-to-back produces identical output (deterministic).
- Importing the file as a module (`python -c "import tests.test_phase2_composer_pipeline"`) succeeds without pytest.
- Stub class names (`_Phase2TestPanelA`, `_Phase2TestPanelB`, `_Phase2TestPanelBoom`) all use the `_phase2_test_*` MODULE_ID namespace.
- `_normalize_xlsx_mtimes` helper present (1 occurrence).
- Both `check_4a_excel_content_hash_stability` and `check_4b_excel_byte_hash_stability_mtime_normalized` defined as separate functions.
- Commit `894f5a6` (Task 1) — present in git log.
