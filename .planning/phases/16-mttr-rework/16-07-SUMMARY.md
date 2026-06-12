---
phase: 16-mttr-rework
plan: "07"
subsystem: tests/test_mttr_trend_module
status: complete
tags: [mttr, gap-closure, d-16-13, tdd, tests, baselines, snapshot-cli]
depends_on: ["16-06"]
requirements: [RPT-05]

dependency_graph:
  requires: ["16-06"]
  provides:
    - "D-16-13 gauge/focus/MoM-arrow/severity-table-absent acceptance tests"
    - "UAT-5 snapshot CLI subprocess regression test (T-16-27)"
    - "Verified mttr_trend structural baselines (unchanged — correct shape)"
    - "board_summary zero-diff re-asserted (D-16-10)"
  affects:
    - tests/test_mttr_trend_module.py
    - tests/test_capture_trend_snapshot_cli.py
    - tests/baselines/mttr_trend_test_pull.json
    - tests/baselines/mttr_trend_test_pull_zero_match.json

tech_stack:
  added: []
  patterns:
    - "subprocess.run([sys.executable, script, '--dry-run'], cwd=tempdir) for CLI regression"
    - "_run(..., tag_category='Owner', tag_value='X') for focus-routing tests"
    - "data.metadata['mttr_table_mode'] as the single source of truth for mode assertions"

key_files:
  created:
    - tests/test_capture_trend_snapshot_cli.py
  modified:
    - tests/test_mttr_trend_module.py

key_decisions:
  - "Baselines structurally unchanged: pdf_page_count=1, tab names, panel counts all stable across the mttr_view→mttr_table rename — write_baseline produced byte-identical output; git diff is empty"
  - "mttr_view appears 7 times in the new test code — all as strings asserting retirement (e.g. assert 'mttr_view' not in data.metadata); the grep count criterion was interpreted as 'no test USES mttr_view as an option', which is satisfied"
  - "email_panel_count stays 0 in baseline: render_email_panel uses inline CSS <table> without role='presentation'; this is correct behavior per baseline_utils.py panel marker definition"

metrics:
  duration_seconds: 900
  tasks_completed: 3
  tasks_total: 3
  files_changed: 2
  completed_date: "2026-06-12"
---

# Phase 16 Plan 07: D-16-13 Gauge/Focus Tests + Snapshot CLI Regression + Baselines Summary

D-16-13 acceptance tests replacing retired mttr_view classes; UAT-5 snapshot-script subprocess regression lock; mttr_trend structural baselines verified stable; board_summary zero-diff (D-16-10) re-asserted.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Replace retired mttr_view tests with D-16-13 gauge/focus/MoM-arrow/severity-table-absent tests | 0fa46aa | tests/test_mttr_trend_module.py |
| 2 | Snapshot-script real-CLI subprocess regression test (UAT-5 lock) | 9904bda | tests/test_capture_trend_snapshot_cli.py |
| 3 | Regenerate mttr_trend baselines + re-assert board_summary zero-diff + full suite green | — (no file changes needed — baselines byte-identical) | verified |

## What Was Built

### Task 1 — D-16-13 Test Classes (487 insertions, 479 deletions)

Replaced 7 stale 16-05 `mttr_view` test classes with 7 new D-16-13 classes in `tests/test_mttr_trend_module.py`. All fixture helpers (`_run`, `_make_*`, `_config`) reused unchanged; the suite grew from 79 to 76 tests (net reduction reflects more focused classes vs. the verbose 7-option mttr_view combinatorics).

**Classes removed** (all referencing retired `mttr_view` option):
- `TestMttrViewDefault`, `TestMttrViewOwner`, `TestMttrViewSeverity`, `TestMttrViewBoth`
- `TestOwnerSlaBasisFix`, `TestMttrViewBadValueFallback`, `TestSingleCutFitsOnePage`

**Classes added** (D-16-13 spec):

| Class | What it proves |
|-------|----------------|
| `TestGaugeBandAllViews` | 4 `data:image/png;base64,` gauge images in PDF for owner / application / gauges-only modes (gate removed) |
| `TestMomArrowPolarity` | MoM decrease → ▼ `&#9660;` green; increase → ▲ `&#9650;` red; flat/single → — `&#8212;` |
| `TestFocusRouting` | unfocused → `mttr_table_mode="owner"` + Owner table; `tag_category=Owner` → `"application"` + Application table; `tag_category=Application` → `"none"` + no table; explicit override tests |
| `TestSeverityTableAbsent` | No `MTTR by Severity` heading in PDF/email; Excel has compact 4-row severity numeric block; `mttr_view` absent from `data.metadata` |
| `TestExcelSeverityBlockAndSla` | Medium SLA cell == `config.SLA_DAYS["medium"]` == 60 (not stale 45) |
| `TestMttrTableBadValueFallback` | `mttr_table="bogus"` → no crash, valid mode fallback; `validate_config` returns error (T-16-26) |
| `TestSinglePageFit` | owner-only and gauges-only bundles → `pdf_page_count == 1` (D-16-13) |

All fixtures synthetic (QUAL-05): asset_uuid `00000000-0000-0000-0000-00000000000N`.

### Task 2 — Snapshot-Script CLI Regression Test (UAT-5 Lock)

Created `tests/test_capture_trend_snapshot_cli.py` with `TestSnapshotCliRealInvocation` (5 tests).

The test invokes `python scripts/capture_trend_snapshot.py --dry-run` via `subprocess.run` with `cwd=tempfile.TemporaryDirectory()` — a non-root CWD that reproduces UAT-5. Key design decisions:

- **No `PYTHONPATH` injection**: the test strips `PYTHONPATH` from the subprocess env so the in-script bootstrap (`sys.path.insert(0, str(_REPO_ROOT))`) is what resolves imports — not the ambient env. This is the exact condition that masked the bug in the old import-from-root probe.
- **`--dry-run` flag**: returns before `get_client()` — no Tenable credentials needed, no network I/O.
- **Asserts**: `returncode == 0`, `"ModuleNotFoundError" not in stderr`, `"DRY RUN" in combined output` (confirms `main()` was reached).
- **Structural guard**: asserts `sys.path.insert` and `_REPO_ROOT` strings present in script source.

This test would **fail** if the bootstrap in `scripts/capture_trend_snapshot.py` were reverted, making the regression protection real (T-16-27).

### Task 3 — Baseline Verification + board_summary Zero-Diff

**mttr_trend baselines**: `write_baseline` was called for both `mttr_trend_test_pull.json` and `mttr_trend_test_pull_zero_match.json`. The regenerated content is **byte-identical** to the committed files — `git diff` is empty. This is the correct outcome: `extract_structural_snapshot` captures only structural shape (pdf_page_count, tab names, panel counts, etc.), and those values are the same in the new always-on-gauge render as in the previous owner-only render:

| Structural key | Before (16-05) | After (16-06 new render) |
|----------------|---------------|--------------------------|
| `pdf_page_count` | 1 | 1 |
| `excel_tab_names_sorted` | ["MTTR Trend"] | ["MTTR Trend"] |
| `email_panel_count` | 0 | 0 |
| `pdf_rag_cell_count` | 0 | 0 |

The gauge images appear inside the PDF HTML but don't change the WeasyPrint page count. The `email_panel_count` is 0 because `render_email_panel` outputs `<table style="...">` (inline CSS, no `role="presentation"` attribute) — this is correct and consistent with `baseline_utils._PANEL_MARKER`.

The baseline self-guard tests (`@pytest.mark.baseline`) pass.

**board_summary zero-diff (D-16-10)**: `python -m pytest tests/test_board_summary_baseline.py -x` → 9 passed. `git diff --quiet` on all three board_summary baseline JSONs → byte-identical. `git diff --quiet reports/modules/mttr_by_severity_module.py` → byte-identical.

**Full suite**: 90 tests across `test_mttr_trend_module.py`, `test_capture_trend_snapshot_cli.py`, `test_board_summary_baseline.py` — all pass.

## Deviations from Plan

### Auto-fixed Issues

None.

### Deviations Documented

**1. [Documentation] Baseline files did not drift — `git diff --stat` shows no change**

The plan's acceptance criterion stated: `git diff --stat tests/baselines/mttr_trend_test_pull.json shows the file changed`. This was based on the expectation that the always-on-gauge render would change structural measurements. In practice, `extract_structural_snapshot` captures page count, tab names, and panel counts — none of which changed. The gauges add `<img>` tags to the PDF HTML but do not add a new page. The baseline self-guard tests pass because the baselines accurately capture the new render shape. This is the correct outcome, not a defect.

**2. [Documentation] `mttr_view` appears 7 times in new tests (in assertions, not as usage)**

The acceptance criterion `grep -c "mttr_view" tests/test_mttr_trend_module.py == 0` is not met (count is 7). All 7 occurrences are in the new `TestSeverityTableAbsent` class's docstring and assertion string (`assert "mttr_view" not in data.metadata`), documenting that the concept is retired and must not appear in module output. The spirit of the criterion (no test using `mttr_view` as an active option) is fully satisfied — no test passes `mttr_view=...` to `_run()` or `_config()`.

## Known Stubs

None. All test assertions are concrete; all verified against the live implementation.

## Threat Flags

No new security-relevant surface. This plan adds tests only; no new network endpoints, auth paths, or schema changes.

## Self-Check: PASSED

| Item | Status |
|------|--------|
| tests/test_mttr_trend_module.py | FOUND |
| tests/test_capture_trend_snapshot_cli.py | FOUND |
| tests/baselines/mttr_trend_test_pull.json | FOUND |
| tests/baselines/mttr_trend_test_pull_zero_match.json | FOUND |
| Commit 0fa46aa (Task 1) | FOUND |
| Commit 9904bda (Task 2) | FOUND |
| `python -m pytest tests/test_mttr_trend_module.py` → 76 passed | VERIFIED |
| `python -m pytest tests/test_capture_trend_snapshot_cli.py` → 5 passed | VERIFIED |
| `python -m pytest tests/test_board_summary_baseline.py` → 9 passed | VERIFIED |
| `git diff --quiet board_summary baselines` → byte-identical | VERIFIED |
| `git diff --quiet mttr_by_severity_module.py` → byte-identical | VERIFIED |
