---
phase: 17-program-health-overview
plan: "03"
subsystem: program-health-module
status: complete
tags: [program-health, render, pdf, excel, email, sparkline, analyst, rag]
requirements: [RPT-07]

dependency_graph:
  requires:
    - reports/modules/program_health_module.py (compute layer from 17-02)
    - reports/modules/base.py (BaseModule, ModuleData, ModuleConfig)
    - reports/modules/rag_utils.py (STATUS_COLOR, build_rag_strip_entry, NO_DATA_HEADLINE)
    - reports/modules/format_utils.py (safe_pct, safe_int, safe_format)
    - matplotlib Agg backend + io.BytesIO + base64 (sparkline rendering)
    - openpyxl.styles (Font, PatternFill) + openpyxl.utils (get_column_letter)
    - html.escape() stdlib (T-17-07 XSS-equivalent guard)
  provides:
    - render_pdf_section — 4-sparkline row + Owner velocity table with outlier flags
    - render_email_panel — 4-tile KPI row + narrative + missing-signal note
    - render_excel_tabs  — ["Program Health", "Owner Velocity"] tabs
    - render_analyst_tabs — [("PH — Owner Detail", df)] aggregate-only
    - render_rag_strip_entry — honors data.rag_strip; falls back to gray
    - _render_sparkline_b64 — matplotlib Agg PNG helper (plt.close mandatory)
  affects:
    - tests/test_program_health_module.py (14 render-side tests appended)

tech_stack:
  added: []
  patterns:
    - _render_sparkline_b64: figsize=(2.0,1.2) @120dpi, plt.close(fig) per call (T-17-08)
    - html.escape() on all owner/tag strings before markup interpolation (T-17-07)
    - safe_pct/safe_int/safe_format throughout — no inline f-string format specs on possibly-None values (QUAL-03)
    - Error guard (data.error → "" / []) at top of every render method
    - Cold-start guard (metrics["cold_start"]) branching in every channel
    - Amber = STATUS_COLOR["yellow"] = #f57c00; #fbc02d banned from all RAG/amber paths
    - test_no_fbc02d_in_module_source: blanket source-file guard catches future regressions

key_files:
  created: []
  modified:
    - reports/modules/program_health_module.py
    - tests/test_program_health_module.py

decisions:
  - "MoM arrow convention: ▼ = improved for lower-is-better signals (Open-Crit, Net Velocity, MTTR); ▲ = improved for SLA Posture (higher-is-better) — per UI-SPEC D-17-06"
  - "Cold-start analyst tabs return [] (no MoM data to show); cold-start Excel still returns 2 tabs (summary tab shows cold-start notice)"
  - "Outlier rendered as &#9650; Outlier (HTML entity) in PDF; plain text 'Outlier' in Excel for openpyxl compatibility"
  - "test_no_fbc02d_in_module_source blanket guard added — required removing #fbc02d from render_rag_strip_entry docstring (was a comment, not code)"

metrics:
  duration_seconds: 1800
  completed_date: "2026-06-12"
  tasks_completed: 3
  files_modified: 2
---

# Phase 17 Plan 03: ProgramHealthModule Render Channels Summary

**One-liner:** Four-channel render contract for `program_health` — matplotlib sparkline row + Owner velocity table (PDF), 4-tile KPI panel + narrative (email), Program Health + Owner Velocity Excel tabs, and aggregate-only analyst detail — all channels empty-data-guard-safe with amber = #f57c00.

## What Was Built

### Task 1: `_render_sparkline_b64` + `render_pdf_section`

**`_render_sparkline_b64(values, signal_label, current_val_str, mom_arrow, arrow_color, line_color) -> str`**

Matplotlib Agg mini-sparkline helper: `figsize=(2.0,1.2)` at 120 dpi, plots value series in `line_color` with `fill_between` shading, titles with `signal_label + current_val_str + mom_arrow` at 7pt in `arrow_color`, saves to BytesIO, calls `plt.close(fig)` unconditionally (T-17-08 figure-leak mitigation), returns base64 string.

**`render_pdf_section`**

- `data.error` → returns `""`
- `metrics["cold_start"]` → cold-start notice replaces sparkline row; Owner table renders current-only (no MoM Delta column)
- Normal: `<h2 class="section-heading">Program Health Overview</h2>`, summary `<p>`, display:table row of 4 sparkline `<img>` cells at 23%/1%, then Owner velocity `<table class="data-table">` with columns Owner / Open Crit+High / MoM Delta / Status
- Outlier rows render `&#9650; Outlier` in `#d32f2f`
- All owner/tag strings escaped via `html.escape()` (T-17-07)

### Task 2: Four remaining channels

**`render_email_panel`**

- `data.error` → `""`
- Cold-start → `#F5F5F5` / `#757575` border header with current-value tiles (Open-Crit safe_int, SLA safe_pct, others `—`); "trend being established" notice
- Normal → `#FFF3E0` / RAG-color border (amber = STATUS_COLOR["yellow"] = `#f57c00`); 4-tile display:table (Open Critical / Net Velocity / SLA Posture (Crit+High) / MTTR (30-day)) each with value + MoM arrow + label; driver_narrative italic #555; missing-signal note #757575 when data_incomplete
- No `#fbc02d` anywhere; safe_pct/safe_int/safe_format on every tile value

**`render_excel_tabs`**

- Returns `["Program Health", "Owner Velocity"]`
- Program Health: A1 "Program Health Overview" bold 13pt; A2 summary/cold-start notice italic #757575; 4-row signal table with headers at row 4
- Owner Velocity: aggregate-only (QUAL-05); headers Owner / Open Crit+High [/ MoM Delta / Status when not suppressed]; outlier rows get "▲ Outlier" text
- Returns `[]` on exception (fail-soft)

**`render_analyst_tabs`**

- Returns `data.analyst_rows` (`[("PH — Owner Detail", df)]`) when valid data
- Returns `[]` on error or cold-start
- QUAL-05: columns are Owner, Open Crit+High (curr), Open Crit+High (prev), MoM Delta, MoM Delta %, Outlier — no asset UUIDs, IPs, hostnames, or plugin IDs

**`render_rag_strip_entry`**

- Returns pre-built `data.rag_strip` when present
- Falls back to gray NO_DATA cell on error or empty strip
- Amber → STATUS_COLOR["yellow"] (#f57c00) via compute()'s rag_key mapping

### Task 3: Render-side tests (14 new tests, 48 total)

| Test class | Tests | What's verified |
|-----------|-------|----------------|
| TestAllChannelsRenderNormal | 1 | All 4 channels return non-empty output without raise |
| TestAllChannelsRenderColdStart | 1 | Cold-start: safe output, no NaN%, amber strip |
| TestAllChannelsRenderZeroRow | 1 | error-state guards: PDF/email → "", Excel → list, analyst → [] |
| TestAnalystTabsAggregateOnly | 1 | QUAL-05: forbidden column substrings (asset_uuid/ip/hostname/plugin) + expected column set |
| TestEmailNoNanPercent | 2 | No "NaN"/"None%" with None values; 4 tile labels present |
| TestAmberUsesYellowColor | 2 | #f57c00 in amber path; blanket #fbc02d source-file guard |
| TestSparklineReturnsBase64 | 3 | PNG magic bytes; None-value tolerance; plt.close() figure-leak guard |
| TestPdfOwnerOutlierMarker | 3 | "Outlier" + #d32f2f in outlier row; missing-signal name in email narrative |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed `#fbc02d` literal from render_rag_strip_entry docstring**

- **Found during:** Task 3 (test_no_fbc02d_in_module_source blanket guard)
- **Issue:** The docstring for `render_rag_strip_entry` contained `#fbc02d` as a "never use this" comment, which caused the blanket source-file guard test to fail.
- **Fix:** Replaced the literal hex with a descriptive phrase ("the Medium-severity color which is reserved for severity tables only"). The color does not appear in any code path — this was purely a docstring mention.
- **Files modified:** `reports/modules/program_health_module.py`
- **Commit:** 0ca94b9 (included with Task 3 commit)

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes. The render boundary introduces two previously-identified threat surfaces, both mitigated:

| Flag | File | Description |
|------|------|-------------|
| T-17-07 mitigated | program_health_module.py | `html.escape()` applied to all owner/tag strings in `render_pdf_section` and `render_email_panel`; no raw f-string interpolation of tag-derived strings into markup |
| T-17-08 mitigated | program_health_module.py | `_render_sparkline_b64` calls `plt.close(fig)` unconditionally in `finally` block; test_sparkline_closes_figure verifies figure count stays flat across 3 calls |

## Self-Check: PASSED

- `reports/modules/program_health_module.py` — exists; contains `_render_sparkline_b64`, `render_pdf_section`, `render_email_panel`, `render_excel_tabs`, `render_analyst_tabs`, `render_rag_strip_entry`; no `#fbc02d` in source
- `tests/test_program_health_module.py` — 48 tests collected, all pass; 8 required render-side test names present
- `run_all.py --dry-run` — exits 0, 5 groups validated (no regression)
- Commits e546b1c, f18cebf, 0ca94b9 — all present in git log
