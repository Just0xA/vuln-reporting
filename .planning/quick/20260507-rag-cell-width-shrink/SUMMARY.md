---
quick_id: 20260507-001
slug: rag-cell-width-shrink
type: quick
status: complete
started: 2026-05-07T05:23:00Z
completed: 2026-05-07T05:48:00Z
gap_source: .planning/phases/03-board-summary-module-migration/03-UAT.md (Test 3, severity major)
files_modified:
  - reports/modules/composer.py
commits:
  - sha: a1584b2
    type: docs
    subject: record Test 3 root cause diagnosis in UAT.md
  - sha: 9b47419
    type: fix(quick)
    subject: shrink Board Summary RAG cell width 62mm→58mm to defeat WeasyPrint flex rounding
diagnosis_source: gsd-debugger agent a405bc3147e4d8c7d
---

# Quick Task SUMMARY — RAG cell width shrink (62mm → 58mm)

## What shipped

Single-file CSS edit in `reports/modules/composer.py:302-303` (`.rag-cell`
flex-basis + width) plus an inline geometry-comment update at lines 298-313
documenting the new math and the historical context.

## Why it works

**Geometry shift.** Old: 4 × 62mm + 3 × 4mm = 260mm in 273mm row = **13mm**
slack. New: 4 × 58mm + 3 × 4mm = 244mm in 273mm row = **29mm** slack. The
new slack dwarfs WeasyPrint's flex rounding error (border subpixels ~2.8mm
+ gap over-allocation), so the 4th cell stays on row 1.

**Coupled fix.** Both UAT-reported symptoms vanish at once because they
were causally linked — the 3+1 wrap doubled strip vertical mass
(~55mm → ~114mm), overflowing A4-landscape page 1's 177mm content area
and triggering `page-break-after: always` to evict the strip to page 2.
With the row not wrapping, the strip stays at ~55mm tall, fits within
page 1, and the unified-cover design (D-01) is restored.

## What was deliberately NOT changed

- `flex-wrap: wrap` stays as-is (NOT switched to `nowrap`).
  `management_summary` uses the same composer with 7 modules and
  intentionally wraps to multi-row. `nowrap` would horizontally overflow
  that report. Leaving `wrap` keeps the >4-cell case working.
- `gap: 4mm` stays as-is. The 29mm slack is comfortable enough that
  trimming the gap would be cosmetic, not load-bearing.
- No changes to `.rag-cell-row`, `.rag-strip-header`, `.report-cover`,
  `.cover-meta`, or any per-metric page CSS — the regression was scoped
  to the 4-cell row and that is the only surface that needed touching.

## Verification

| Check | Result |
|-------|--------|
| `python tests/test_phase2_composer_pipeline.py` | **11/11 passed**, 0 skipped, 0 failed |
| `D-29 page-2 strip + cover stability` (check_3) | passed — fixture compares two runs against each other (stability), not a frozen golden, so the new geometry doesn't break it |
| `Gap 03-07 analyst workbook nullable dtypes` (check_11) | passed — composer chokepoint untouched |
| Per-metric pages 2-5 | unaffected — `.rag-cell*` classes scoped to cover; KPI tiles use `display: table-cell` |
| `management_summary` (7-module wrap path) | unaffected — `flex-wrap: wrap` preserved |

## Risk

None observed. Per-metric pages render unchanged; the 7-module wrap path
is preserved; regression suite is fully green.

## Re-test pointer

Phase 03 UAT Test 3 should now show:
- Cover, sections list, generated timestamp, AND 4-cell RAG strip all on page 1
- 4 cells in a single row with even spacing (~14.5mm gutter each side)
- No orphan cover-only page or strip-only page

User to re-run `python run_all.py --group "Test Pull" --no-email` and visually
confirm the regenerated `board_summary*.pdf`. UAT Test 3 result can then flip
from `issue` to `pass`, taking Phase 03 to **6/6 passed** and clearing the
final UAT gap.
