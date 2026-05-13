---
phase: 03-board-summary-module-migration
fixed_at: 2026-05-06T21:50:00Z
review_path: .planning/phases/03-board-summary-module-migration/03-REVIEW.md
iteration: 1
findings_in_scope: 9
fixed: 9
skipped: 0
status: all_fixed
---

# Phase 3: Code Review Fix Report

**Fixed at:** 2026-05-06T21:50:00Z
**Source review:** `.planning/phases/03-board-summary-module-migration/03-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope (Critical + Warning): 9
- Fixed: 9
- Skipped: 0
- Info findings (out of scope, not addressed): 6

All 9 in-scope findings were fixed. The Phase 2 composer regression
suite (`tests/test_phase2_composer_pipeline.py`, which carries the 3
new Phase 3 checks added in commit `5a7949f`) returns
**10/10 passed, 0 skipped, 0 failed** post-fix. The Phase 3 regression
file referenced in the agent prompt (`tests/test_phase3_regression.py`)
does not exist in the repo — the Phase 3 coverage was extended into
the Phase 2 file.

## Fixed Issues

### CR-01: BLOCKER — `_compute_bu_breakdown` silently mis-counts within-SLA per BU

**Files modified:** `reports/modules/critical_remediation_sla_module.py`
**Commit:** `6782e41` — `fix(03): CR-01 realign within-SLA mask onto fw.index in _compute_bu_breakdown`

**Applied fix:** Added a defensive `within_sla_mask.reindex(fw.index, fill_value=False)`
inside `_compute_bu_breakdown()` so the helper owns its own index alignment. The fix
applied as suggested in REVIEW.md verbatim. Today the indices match (as the reviewer
notes), but a future caller that touches `fixed_in_window` (e.g. `.reset_index(drop=True)`
for downstream display) would have silently turned every `True` into `False`,
producing 0% per-BU SLA without raising. The reindex eliminates that class of
silent data-loss.

**Status:** `fixed` — index-realignment is structurally verifiable (re-read confirms);
the test suite passes; the BU breakdown computation matches the documented contract.

---

### WR-01: Bundle-key drift — `email_kpis` missing from `board_summary.run_report` return dict

**Files modified:** `reports/board_summary.py`
**Commit:** `00c7ab0` — `fix(03): WR-01 surface email_kpis at top level of board_summary return dict`

**Applied fix:** Added `"email_kpis": kpis` to the report return dict (in addition to
the existing `metrics["kpis"]`) so the legacy KPI tile channel (Phase 2 D-23) is
preserved end-to-end. Also updated the docstring's example return shape to include
both `email_inline_images` and `email_kpis`. Fix matches the REVIEW.md suggestion
exactly.

---

### WR-02: Inline-image cumulative budget keeps the first oversize image instead of dropping it

**Files modified:** `delivery/email_sender.py`
**Commit:** `655d973` — `fix(03): WR-02 check inline-image budget before accumulating bytes`

**Applied fix:** Restructured the CID inline-image decode loop so the cumulative
budget check (and a new per-image budget) runs BEFORE `_inline_total` is incremented
and BEFORE `related.attach()` is called. Added a 2 MB per-image upper bound
(`_INLINE_PER_IMAGE_BYTES`) as the reviewer suggested. The previous ordering
admitted a subtle asymmetry: incrementing `_inline_total` before checking the cap
meant a single oversize image bumped the running total without ever being
attached, but the warning message implied the budget was already exceeded.
Fix matches the REVIEW.md suggestion plus the recommended individual-size cap.

---

### WR-03: Analyst-tabs leaks accepted / recasted findings into the Critical Remediation drill-down

**Files modified:** `reports/modules/critical_remediation_sla_module.py`
**Commit:** `3039851` — `fix(03): WR-03 exclude accepted/recasted findings from Critical SLA missed slice`

**Applied fix:** After the `missed = fixed_in_window[...].copy()` slice, drop rows
where `severity_modification_type` is `accepted` or `recasted`. The guard checks
for column presence first to remain backwards-compatible with older fixtures that
lack the field. Fix matches the REVIEW.md suggestion. Both the analyst drill-down
tab AND the email-panel driver narrative (`{missed_count} critical findings missed
SLA.`) benefit since `missed_count` is derived from this slice.

---

### WR-04: `_STATUS_COLOR["yellow"]` (`#f57c00`) drifts from `_GAUGE_THRESHOLDS` yellow band (`#fbc02d`)

**Files modified:**
- `reports/modules/scan_coverage_sla_module.py`
- `reports/modules/critical_remediation_sla_module.py`
- `reports/modules/high_risk_assets_module.py`
- `reports/modules/aged_vulns_assets_module.py`

**Commit:** `6b67c24` — `fix(03): WR-04 align gauge amber color with rag_utils STATUS_COLOR`

**Applied fix:** Changed the gauge yellow threshold color from `#fbc02d` to `#f57c00`
across all four board modules. This aligns the gauge band with `rag_utils.STATUS_COLOR['yellow']`
(the project-wide RAG palette) and the inline status badge / RAG strip cell, so all
three surfaces show the same orange.

**Deviation from suggested fix:** REVIEW.md suggested either (a) rebrand `_STATUS_COLOR['yellow']`
to `#fbc02d` to match the gauge, or (b) rebrand the gauge to `#f57c00` to match the badge.
The reviewer's parenthetical reasoning was self-contradictory ("rebrand the gauge to `#f57c00`
matches chart_exporter.py 'Medium = #fbc02d' convention" — those are different colors). I
picked option (b) because `rag_utils.STATUS_COLOR` is the documented project-wide RAG source
of truth (used by the cover-page strip composer and the email panel) and changing it would
ripple to every consumer; the gauge thresholds are local to four modules and easy to localize.
Both colors are visually amber/orange — the substantive correctness goal (gauge / badge / strip
agreement) is achieved either way.

---

### WR-05: `_unique_sheet_name` API mutates caller's set out-of-band

**Files modified:** `reports/modules/composer.py`
**Commit:** `a9725e5` — `fix(03): WR-05 move set mutation into _unique_sheet_name; fix off-by-one`

**Applied fix:** Moved the `used_names.add()` call into `_unique_sheet_name()` so the
helper owns its own bookkeeping (atomic with the lookup). Removed the now-redundant
`used_names.add(unique)` at the call site in `assemble_analyst_workbook`. Updated
the docstring to reflect the new contract. Also fixed the off-by-one in the
ValueError message — `range(2, 100)` yields suffixes `_2` through `_99` (98 attempts,
not 99). Fix matches the REVIEW.md suggestion.

---

### WR-06: Risk-score scope drift between `compute_bu_risk_scores()` and module-level intent

**Files modified:**
- `reports/modules/aged_vulns_assets_module.py`
- `reports/modules/high_risk_assets_module.py`
- `docs/board_summary_calculations.md`

**Commit:** `9e972ed` — `fix(03): WR-06 document intentional Risk Score broadening in audit_info + runbook`

**Applied fix:** Adopted the spec-confirmation path (no logic change). The `compute_bu_risk_scores()`
docstring already documents the broadening as intentional ("using all open findings on that
asset (not only the aged/filtered findings that caused the asset to qualify)"). I added:
1. Explicit `risk_score` entries to `get_audit_info()` in both modules so the audit
   trail surfaces the broadening at runtime.
2. A new `Risk Score broadening` section in `docs/board_summary_calculations.md`
   (Section 7, after the existing BU breakdown sort-order documentation) that
   states the score is **holistic asset-risk** by design and the headline gauge
   metric is unchanged.

**Deviation from suggested fix:** REVIEW.md offered two paths — narrow `vulns_df` or
document the broadening. I chose documentation rather than narrowing because:
- The headline metric (Aged% / High-Risk%) is correct and narrow; only the BU
  table's Risk Score column is broadened.
- The narrowing path would change a metric column that is already shipping
  in production board reports — that is a behavior change that needs sign-off
  from the board metric owner, not a code-review fix.
- The runbook gap was the genuine defect; closing it makes the existing intent
  explicit and auditable.

**Status:** `fixed: requires human verification` — documentation correctness is
self-verifying via re-read; whether the broadening is the "right" semantic for
the board is a product question that the runbook now surfaces but cannot answer.
The metric owner should confirm at next review.

---

### WR-07: `safe_pct` not used in summary helpers — inline f-string format spec on possibly-None values

**Files modified:**
- `reports/modules/scan_coverage_sla_module.py`
- `reports/modules/critical_remediation_sla_module.py`
- `reports/modules/high_risk_assets_module.py`
- `reports/modules/aged_vulns_assets_module.py`

**Commit:** `5901df5` — `fix(03): WR-07 use safe_pct in summary helpers across all four board modules`

**Applied fix:** Replaced inline `f"{pct:.1f}%"` constructs with `safe_pct(pct)` calls
in every `_build_summary` helper across the four board modules. This makes the
CLAUDE.md "Empty-data guard pattern" rule mechanical — even if a future refactor
breaks the early-return guards, the summary text shows the `NO_DATA_HEADLINE`
sentinel instead of crashing. Fix matches the REVIEW.md suggestion.

---

### WR-08: `_filter_assets_by_tag` returns the unfiltered DataFrame on missing column

**Files modified:** `reports/board_summary.py`
**Commit:** `e84aec5` — `fix(03): WR-08 return empty DataFrame when tags column missing in _filter_assets_by_tag`

**Applied fix:** Changed the fallback path so when the tags column is absent, the
helper returns an empty DataFrame (`assets_df.iloc[0:0].copy().reset_index(drop=True)`)
rather than the full unfiltered frame. Also bumped the log level from `warning` to
`error` so the schema-drift alarm is appropriately loud. The empty frame causes
each module to render its coherent "no data in scope" panel
(`driver_narrative = "No data in scope."`, RAG strip = `—`, etc.) so consumers see
the correct signal instead of a misleadingly-widened scope. Fix matches the
REVIEW.md suggestion.

## Skipped Issues

None — all 9 in-scope findings (CR-01 + WR-01..WR-08) were fixed.

## Info findings (out of scope)

The following 6 Info-level findings from REVIEW.md were NOT addressed as part of
this fix run because `fix_scope = critical_warning`. They remain open for future
clean-up:

- **IN-01:** Dead `_row_bg` / `_xl_fill` helpers in aged_vulns and high_risk modules.
- **IN-02:** Stale `_smtp_cfg()` "read once at module load time" comment.
- **IN-03:** `assemble_pdf` builds `module_list_str` without HTML-escaping at
  construction (escape-at-render is correct today; defensive note).
- **IN-04:** `_extract_owner_tag` only matches exact `"owner"` (case-insensitive),
  misses `"Owner Group"` etc.
- **IN-05:** Unicode RAG icons (`▲ ● ▼ ○`) may render as boxes in older Outlook.
- **IN-06:** Email per-module exception placeholder colour combination.

## Test verification

Phase 2 composer pipeline regression suite (which contains the 3 Phase 3 checks
added in commit `5a7949f`):

```
[PASS] D-22 bundle shape
[PASS] D-27 module ordering across channels
[PASS] D-29 page-2 strip + cover stability
[PASS] D-29 main-Excel content hash stability
[PASS] D-29 main-Excel mtime-normalized byte stability
[PASS] D-28 email panel exception isolation
[PASS] D-28 analyst tabs exception isolation
[PASS] Phase3 QUALITY-02 zero-row render methods
[PASS] Phase3 populated render methods
[PASS] Phase3 bundle email_inline_images key
----------------------------------------------------------------------
Result: 10/10 passed, 0 skipped, 0 failed.
```

All imports succeed (`reports.modules.*`, `reports.board_summary`, `delivery.email_sender`).

---

_Fixed: 2026-05-06T21:50:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
