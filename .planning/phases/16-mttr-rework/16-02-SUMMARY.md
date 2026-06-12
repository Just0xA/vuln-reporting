---
phase: 16-mttr-rework
plan: "02"
subsystem: reporting-modules
status: complete
tags: [mttr, modules, trend, reopened-aware, four-channel, composed-report]
dependency_graph:
  requires: [16-01]
  provides: [mttr_trend module, composed_report frozenset memberships]
  affects: [reports/modules/mttr_trend_module.py, reports/composed_report.py]
tech_stack:
  added: []
  patterns:
    - dual-cold-start (live gauges vs MoM trend independent cold-start paths)
    - reopened-aware COALESCE clock (D-16-02)
    - sample-weighted flat MTTR mean (D-16-02 consequence)
    - frozenset fan-out gate pattern (D-16-01/03)
    - four-channel render contract (CONTRACT-01/02/03/04)
key_files:
  created:
    - reports/modules/mttr_trend_module.py
  modified:
    - reports/composed_report.py
decisions:
  - D-16-01: durably-fixed population — state==FIXED only from fixed_vulns_df; never last_fixed.notna()
  - D-16-02: COALESCE date clock — clipped >=0; flat sample-weighted overall MTTR
  - D-16-03: mttr_trend in _MODULES_NEEDING_TREND_SNAPSHOTS for MoM line
  - D-16-04: rolling window (default 30d) disclosed in all four channels
  - D-16-06/08: Owner cut with absolute MoM delta; partial-month label
  - D-16-07: sparse wording standardized — "Insufficient data (N findings — minimum 5 required)"
  - D-16-10: mttr_by_severity_module.py byte-unchanged
metrics:
  duration: ~20 minutes
  completed: 2026-06-12
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 1
---

# Phase 16 Plan 02: MTTRTrendModule — Reopened-Aware Four-Channel MTTR Summary

New `mttr_trend` module with reopened-aware COALESCE clock, sample-weighted mean, rolling-window disclosure in all four channels, MoM trend from snapshots, and Owner cut — registered in both `composed_report.py` fan-out frozensets so it receives both `fixed_vulns_df` and `trend_snapshots` on every composed run.

## What Was Built

### Task 1: `reports/modules/mttr_trend_module.py` (new, 1156 lines)

`@register_module class MTTRTrendModule(BaseModule)` with `MODULE_ID = "mttr_trend"`, implementing four correctness fixes over `mttr_by_severity_module.py`:

**D-16-01 — Population:** Reads from `kwargs.get("fixed_vulns_df")` gated by `_MODULES_NEEDING_FIXED_VULNS`. Filters `state.astype(str).str.upper() == "FIXED"` only. The old `state=="fixed" OR last_fixed.notna()` clause (which re-includes currently-REOPENED findings via stale `last_fixed`) is absent.

**D-16-02 — Clock:** `(last_fixed - COALESCE(resurfaced_date, first_found)).days.clip(lower=0)`. The old `time_taken_to_fix` preference is completely absent from code. Criterion-3 fixture validated: `first_found=-200d, resurfaced_date=-10d, last_fixed=-2d` → `days_to_fix=8.0` (old module produced 198). Overall MTTR is a flat sample-weighted mean — NOT a mean of per-severity means (D-16-02 consequence).

**D-16-04 — Disclosure:** Rolling window (`default 30, configurable mttr_window_days`) emitted in all four channels: PDF explanatory-text paragraph, Excel row-1 title, email panel footer span, and `metadata["window_days"]`.

**D-16-06/07/08 — Owner cut + sparse wording + partial-month:**
- Per-Owner MTTR via `extract_owner(assets_df)` with absolute MoM delta (curr − prev days, not %)
- Zero-fixed Owners omitted; n < min_sample renders `"Insufficient data (N findings — minimum 5 required)"`
- Partial-month label via `_month_label()` helper (copied verbatim from `new_vs_remediated_module.py`)

**Dual independent cold-start paths (QUAL-01):**
- `fixed_vulns_df` absent/empty → full cold-start (gray RAG, `metrics["cold_start"]=True`)
- `trend_snapshots` absent/insufficient → MoM line cold-starts independently; live per-severity gauges still render

**Four-channel render contract:**
- `render_pdf_section`: overall gauge + per-severity gauges (via `draw_gauge`) + disclosure + Owner/severity table
- `render_excel_tabs`: "MTTR Trend" tab, row-1 title with window disclosure, D-16-05 column order
- `render_email_panel` (CONTRACT-01, not `render_email_kpis`): inline CSS, cold-start branch, footer disclosure
- `render_rag_strip_entry` (CONTRACT-03): overall MTTR / Critical SLA; green ≤1.0, yellow ≤1.25, red >1.25

**Safety:** Entire `compute()` wrapped in `try/except → self._empty_result()`. `safe_format`/`safe_int` used throughout; no inline f-string on None-able values (QUAL-03). CoW-compliant: `.assign(days_to_fix=...)` only.

### Task 2: `reports/composed_report.py` (two frozenset additions only)

Two membership additions — no other change:

**(a) `_MODULES_NEEDING_FIXED_VULNS`** (was `frozenset({"critical_remediation_sla"})`):
- Added `"mttr_trend"` with comment `# D-16-01: MTTR population = durably-fixed findings; fixed_vulns is a hard input, not opportunistic`
- Without this, `need_fixed` evaluates False for mttr_trend-only compositions → `fixed_vulns_df=None` → gray RAG forever

**(b) `_MODULES_NEEDING_TREND_SNAPSHOTS`** (was 4 members):
- Added `"mttr_trend"` with comment `# D-16-03: reads rolling MTTR / MoM line from trend snapshots`

The existing `need_fixed`/`need_trend` intersection gates and `**self._kwargs` fan-out in `composer.py` already deliver both kwargs to any module whose ID is in the respective set — no signature or predicate change was needed.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Create MTTRTrendModule (compute + four-channel renders) | 3f52074 | reports/modules/mttr_trend_module.py |
| 2 | Register mttr_trend in both composed_report fan-out frozensets | e1b3f85 | reports/composed_report.py |

## Verification Results

- `python -c "from reports.modules.mttr_trend_module import MTTRTrendModule as M; assert M.MODULE_ID=='mttr_trend'; assert set(['render_pdf_section','render_excel_tabs','render_email_panel','render_rag_strip_entry']) <= set(dir(M))"` — exits 0
- `import reports.modules; registry.get('mttr_trend')` — returns `MTTRTrendModule` class (auto-discovery confirmed)
- `from reports.composed_report import _MODULES_NEEDING_TREND_SNAPSHOTS as t, _MODULES_NEEDING_FIXED_VULNS as f; assert 'mttr_trend' in t and 'mttr_trend' in f` — exits 0
- `python run_all.py --dry-run` — "All 5 group(s) validated successfully."
- `git diff --quiet -- reports/modules/mttr_by_severity_module.py` — exits 0 (byte-unchanged, D-16-10)
- Criterion-3: `first_found=-200d, resurfaced_date=-10d, last_fixed=-2d` → `overall_mttr=8.0` (not 198) — PASS
- `python -m pytest tests/unit tests/content --override-ini="addopts=" -q` — 177 passed, 0 failed

## Deviations from Plan

None — plan executed exactly as written.

The two `time_taken_to_fix` occurrences in the acceptance-criteria check resolve to docstring and `get_audit_info()` string literal lines (not code); the `["days_to_fix"] =` match resolves to a CoW-compliance comment. Both are false positives in literal `grep -c`; actual code contains zero uses of either pattern.

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns introduced. The module renders aggregate MTTR floats and internal Owner tag name strings only — within the established PII boundary (T-16-06 mitigated). All four render channels output aggregates, not per-finding rows.

T-16-05 (DoS on malformed snapshot/zero-row): mitigated — `compute()` wrapped in `try/except → _empty_result()`; both cold-start guards in place; `(snap.get(...) or {}).get(owner)` access never raises KeyError/TypeError on old snapshots (Pitfall B).

T-16-11 (silent null via missing frozenset membership): mitigated — static acceptance criterion asserts both memberships; `python run_all.py --dry-run` exits 0.

## Self-Check: PASSED

- `reports/modules/mttr_trend_module.py` — created, exists
- `reports/composed_report.py` — modified, exists
- Commit 3f52074 verified in git log (Task 1)
- Commit e1b3f85 verified in git log (Task 2)
- 177 tests pass, 0 fail
- `mttr_by_severity_module.py` — byte-unchanged confirmed
