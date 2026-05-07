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
    subject: "shrink Board Summary RAG cell width 62mm→58mm (initial attempt — INSUFFICIENT)"
  - sha: d7ea6d5
    type: fix(quick)
    subject: "RAG cell width 58mm was insufficient — empirical bisect → 55mm"
diagnosis_source: gsd-debugger agent a405bc3147e4d8c7d
---

# Quick Task SUMMARY — RAG cell width shrink (62mm → 55mm, empirically)

## What shipped

Single-file CSS edit in `reports/modules/composer.py` (`.rag-cell`
flex-basis + width) plus an inline geometry-comment rewrite documenting
the empirical bisect findings.

## Iteration history (the why)

This task closed in two passes — the first one shipped the wrong number.

**Iter 1 (commit 9b47419, 62mm → 58mm)** — based on a theoretical
geometry calculation: 4 × 62 + 3 × 4 = 260mm in 273mm = 13mm slack;
hypothesized ~13mm of slack was eaten by border-subpixel rounding +
flex gap over-allocation; pinned 58mm to give 29mm of slack, which
"should" be plenty. **User UAT showed the layout unchanged at 58mm —
cells still wrapped 3+1 and the strip stayed on page 2.** The
hypothesis was wrong about the magnitude of phantom space WeasyPrint
65.1's flex implementation consumes.

**Iter 2 (commit d7ea6d5, 58mm → 55mm)** — empirical bisect against
the real WeasyPrint 65.1 + `assemble_pdf` path with synthetic
ModuleData:

| Width | Result | Slack on paper |
|------:|--------|---------------:|
| 55mm | **fits in single row** | 41mm |
| 56mm | fits in single row (last value that fits) | 37mm |
| 57mm | wraps to 3+1 | 33mm |
| 58mm | wraps to 3+1 (the failed iter-1 fix) | 29mm |
| 62mm | wraps to 3+1 (original UAT-reported state) | 13mm |

So WeasyPrint actually consumes **~33-37mm of phantom space** beyond
the 4-cell × width + 3-gap × gap-width math. Likely cause: a known
flex `gap` accounting issue in weasyprint 65.x where gap appears to
be either double-counted or treated as having an extra trailing
edge. The pragmatic fix is a width with comfortable empirical
headroom rather than fighting the layout engine — pinned at 55mm
with 1mm safety margin below the 56mm threshold.

## Why this fixes both UAT symptoms at once

The two UAT-reported symptoms (RAG strip on a separate page; cells
wrapping 3+1) are causally linked — the 3+1 wrap doubles strip
vertical mass (~55mm → ~114mm), overflowing A4-landscape page 1's
177mm content area and triggering `page-break-after: always` on
`.report-cover` to evict the strip to page 2. With the row not
wrapping, the strip stays at ~55mm tall, fits within page 1, and the
unified-cover design (D-01) is restored.

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
| `python tests/test_phase2_composer_pipeline.py` | **11/11 passed**, 0 skipped, 0 failed (post iter-2) |
| Synthetic real-render bisect (50/53/55/56/57mm) | confirmed 56mm threshold; 55mm is below it |
| `pdftotext -layout` on 55mm rendered PDF | shows all 4 cell labels on a single line |
| `D-29 page-2 strip + cover stability` (check_3) | passed — fixture compares two runs against each other (stability), not a frozen golden, so the new geometry doesn't break it |
| `Gap 03-07 analyst workbook nullable dtypes` (check_11) | passed — composer chokepoint untouched |
| Per-metric pages 2-5 | unaffected — `.rag-cell*` classes scoped to cover; KPI tiles use `display: table-cell` |
| `management_summary` (multi-module wrap path) | unaffected — `flex-wrap: wrap` preserved; reports with >4 modules can still wrap |

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
