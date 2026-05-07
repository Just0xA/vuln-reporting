---
quick_id: 20260507-001
slug: rag-cell-width-shrink
type: quick
status: in-progress
gap_source: .planning/phases/03-board-summary-module-migration/03-UAT.md (Test 3, severity major)
files_modified:
  - reports/modules/composer.py
diagnosis_source: gsd-debugger agent a405bc3147e4d8c7d
---

# Quick Task: Shrink Board Summary RAG cells 62mm → 58mm

## Why

Phase 03 UAT Test 3 surfaced two coupled defects in the unified PDF cover:

1. **RAG strip on a separate page** (downstream symptom)
2. **4 cells wrap 3+1** instead of fitting a single row (root cause)

Geometry: 4 × 62mm + 3 × 4mm gap = 260mm in a 273mm content row = only 13mm
slack. WeasyPrint's flex implementation rounds aggressively (border subpixel
rounding ~2.8mm cumulative across 8 × 0.5pt borders + flex `gap`
over-allocation) which edges past the 273mm boundary and forces the 4th cell
to row 2. Once wrapped, the strip's vertical mass nearly doubles
(~55mm → ~114mm) and overflows page 1 (177mm content area), so
`page-break-after: always` evicts the strip wholesale to page 2.

## Fix

Single-file CSS edit in `reports/modules/composer.py:302-303`:

- `flex: 0 0 62mm` → `flex: 0 0 58mm`
- `width: 62mm` → `width: 58mm`

Also update the geometry comment at lines 298-301 to reflect new math:
4 × 58mm + 3 × 4mm = 244mm in 273mm = 29mm slack.

## Why NOT change `flex-wrap: wrap → nowrap`

`management_summary` uses the same composer with 7 modules and intentionally
wraps to multi-row. `nowrap` would horizontally overflow that report. Leaving
`wrap` keeps the >4-cell case working.

## Verification

1. `python tests/test_phase2_composer_pipeline.py` → 11/11 GREEN preserved
2. Regenerate Board Summary PDF and visually confirm:
   - Cover, sections list, and 4-cell RAG strip are all on page 1
   - All 4 cells in a single row
   - Per-metric pages (2-5) unchanged

## Risk

None to per-metric pages — `.rag-cell*` classes are scoped to the cover;
`.kpi-tile` uses `display: table-cell` not flex.
