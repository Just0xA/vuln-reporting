---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: 19-11
subsystem: program_health_module
tags: [gap-closure, correctness, pdf-layout, composite-rag, net-velocity]
dependency_graph:
  requires: ["19-10"]
  provides: []
  affects: ["reports/modules/program_health_module.py", "tests/test_program_health_module.py"]
tech_stack:
  added: []
  patterns: [current-sign-status, two-row-pdf-layout, tdd-red-green]
key_files:
  created: []
  modified:
    - reports/modules/program_health_module.py
    - tests/test_program_health_module.py
decisions:
  - "D-7: signal_statuses[1] uses net_velocity_status_current (current-sign) not sig2_status (delta-of-deltas)"
  - "D-8: PDF Net Velocity tile shows net-only headline; caption row carries in/fixed breakdown; mom_arrow='' passed to _render_sparkline_b64 for NV tile"
  - "Email panel keeps intake/fixed inline per spec (email tiles wider than PDF sparkline cells)"
  - "net_velocity_status_current computed before signal_statuses list so it feeds composite, green_count, and narrative"
metrics:
  duration: 900
  completed_date: "2026-06-26"
  tasks: 3
  files: 2
---

# Phase 19 Plan 11: Program Health D-7/D-8 Re-verification Fixes Summary

Re-verification fixes for Plan 19-10's Program Health polish: corrects a composite RAG/count inconsistency (D-7) and PDF Net Velocity tile double-arrow + two-row layout (D-8).

## Tasks Completed

| Task | Commit | Description |
|------|--------|-------------|
| RED: D-7/D-8 regression tests | 10fe4d4 | 13 failing tests covering composite consistency and two-row layout |
| GREEN: D-7 + D-8 implementation | 374ee5e | compute() + render_pdf_section() fixes; all 120 tests pass |
| Task 3: email parity + full suite | (no additional commit — inherits from Task 1 fix) | Email panel inherits D-7 fix from compute(); all 120 tests confirmed green |

## What Was Fixed

### D-7 — Composite RAG consistency (correctness bug)

**Root cause:** `signal_statuses[1]` was `sig2_status` (delta-of-deltas MoM direction), which returns `"missing"` when there is no prior month's net delta to compare against. Meanwhile `net_velocity_status_current` (current-sign) correctly returned `"green"` when `curr_net < 0`. The tile showed green but the composite/count/narrative used the missing status.

**Fix:** Moved the `net_velocity_status_current` computation to before the `signal_statuses` list in `compute()`. Replaced `signal_statuses[1]` from `sig2_status` to `net_velocity_status_current`. `sig2_status` is retained (still computed for the sparkline MoM trend) but no longer drives the composite.

**Result:** With Open Critical red + Net Velocity current-sign green + SLA/MTTR missing:
- `green_count == 1`
- Headline: "1 / 4 On Track"
- Narrative: "worsened on 3 of 4"
- Composite: red (0–1 green rule)
- `data_incomplete=True` (SLA + MTTR still missing)
- Net Velocity NOT listed in `missing_signal_names`

**D-17-06 missing-cap:** Still applies correctly — genuinely absent net delta (`curr_new is None`) now yields `net_velocity_status_current = "missing"` (not "flat") so the cap still fires for truly missing Net Velocity data.

### D-8 — PDF chart-row layout

**Root cause:** `nv_curr_str` embedded the arrow in the string (`...net -7 ▼`) AND `_render_sparkline_b64` appended `mom_arrow` in the PNG title → double arrow. Also the full "in / fixed / net" string made the tile headline font shrink and the tile height non-uniform.

**Fix:**
1. **Single arrow:** Pass `mom_arrow=""` for the Net Velocity tile so `_render_sparkline_b64` title is `"Net Velocity\nnet -7"` (no appended arrow). One arrow appears in the HTML annotation div.
2. **Net-only tile headline:** `nv_tile_str = f"net {net_str}"` — uniform font with the other three tiles.
3. **Two-row layout:** Top row = 4 tile cells (sparkline PNG + arrow annotation only, no definition text). Caption row = 4 caption cells below with definition text and NV breakdown.
4. **Caption row carries breakdown:** `nv_breakdown_str = f"in {new_str} / fixed {fix_str}"` appears in the caption cell below the Net Velocity tile — all three numbers (intake/fixed/net) still shown per D-3.

### Task 3 — Email parity

The email panel's `"N of 4 signals on track"` count reads directly from `metrics["green_count"]`, which is now correct via the D-7 fix. No email code change needed. The email Net Velocity tile keeps the full `"in {new} / fixed {fix} · net {net} {arrow}"` inline value (correct per spec: email tiles are wider than PDF sparkline cells). No double-arrow in email — the arrow is embedded once in `net_vel_val` and no separate arrow span is rendered for the NV tile.

## Test Results

| Metric | Count |
|--------|-------|
| Pre-existing tests (baseline) | 107 |
| New D-7 tests (TestD7CompositeConsistency) | 6 |
| New D-8 tests (TestD8SingleArrow + TestD8TwoRowLayout) | 7 |
| **Total passing** | **120** |
| Failures | 0 |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test fixture used wrong critical delta for `test_d7_net_positive_excludes_from_green_count`**
- **Found during:** GREEN phase implementation
- **Issue:** Test fixture had critical going 10→8 (delta=-2), which falls within `open_crit_flat_band=5` and produces `sig1=amber` not `green`. Comment said "critical improved → green" but flat band absorbed it. Expected `green_count=3` but got `2`.
- **Fix:** Changed critical from 10→8 to 30→10 (delta=-20, well beyond flat_band=5) so `sig1=green` as the test asserts.
- **Files modified:** tests/test_program_health_module.py
- **Commit:** 374ee5e

## Known Stubs

None — all four channels render correctly; no placeholder/TODO values in output paths.

## Human-Check Note (D-8 PDF render verification)

Per the plan's `<human-check>` directive: the two-row tile/caption layout change requires a real WeasyPrint PDF render to confirm visual correctness (WeasyPrint flex/page-break quirks cannot be verified by layout math). Unit tests confirm the HTML structure (caption row after all img tags, single arrow, net-only headline, intake/fixed in caption), but the operator must re-render the composed report (all-assets) to a real PDF to confirm:
- Top row: 4 uniform tiles with single arrows
- Net Velocity tile shows "net -N" with one arrow
- Caption row below with intake/fixed breakdown under Net Velocity
- Page 2 still the Owner table alone

This verification is deferred to operator re-verification after deployment.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check: PASSED

- `reports/modules/program_health_module.py` — modified (verified via git log 374ee5e)
- `tests/test_program_health_module.py` — modified (verified via git log 374ee5e)
- Commit 10fe4d4 exists (RED tests)
- Commit 374ee5e exists (GREEN implementation)
- 120 tests pass, 0 failures
