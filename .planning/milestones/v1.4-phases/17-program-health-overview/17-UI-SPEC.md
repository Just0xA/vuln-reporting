---
phase: 17
slug: program-health-overview
status: draft
shadcn_initialized: false
preset: none
created: 2026-06-12
---

# Phase 17 — UI Design Contract

> Visual and interaction contract for the `program_health` four-channel metric module.
> This phase produces NO web UI, NO JavaScript, NO browser-rendered output.
> All channels are non-interactive static output: WeasyPrint PDF, openpyxl Excel,
> and inline-CSS HTML email (Outlook/Gmail/Apple Mail). Channel constraints are locked.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | none — no component library; inline CSS throughout |
| Preset | not applicable |
| Component library | none — HTML table-based layouts, WeasyPrint-compatible |
| Icon library | Unicode symbols (▲ ▼ —) — no icon font, no SVG library |
| Font — PDF | "Helvetica Neue", Helvetica, Arial, sans-serif (from `_PDF_CSS` in `composer.py`) |
| Font — Email | Arial, sans-serif (from `render_email_panel` in `mttr_trend_module.py`) |
| Font — Charts | DejaVu Sans (from `plt.rcParams` in `chart_exporter.py`) |

Source: `reports/modules/composer.py` `_PDF_CSS`, `exporters/chart_exporter.py` `rcParams`.
No shadcn gate required — this is a Python/WeasyPrint project.

---

## Spacing Scale

All values are CSS pt (PDF) or px (email) units. The existing composer stylesheet
establishes the in-use scale; this phase must match it exactly.

### PDF Channel (pt units — from `composer.py` `_PDF_CSS`)

| Token | Value | Usage |
|-------|-------|-------|
| xs | 2mm (~5.7pt) | Table cell padding (`data-table td`) |
| sm | 3mm (~8.5pt) | Table header padding, section element gap |
| md | 4mm (~11.3pt) | Section element padding, KPI tile padding |
| lg | 5mm (~14.2pt) | KPI row bottom margin |
| xl | 12mm | Module section bottom margin |
| page-margin | 15mm top / 12mm sides / 18mm bottom | A4 landscape page margins |

Sparkline figure: `figsize=(2.0, 1.2)` inches at 120 dpi (per `17-RESEARCH.md` recommendation).
The row of 4 sparklines sits in a `<div style="display:table;width:100%;">` with each sparkline
cell at 23% width and 1% side margins — matching the MTTR per-severity sparkline grid pattern
from `mttr_trend_module.py` line 999.

### Email Channel (px units — from `render_email_panel` patterns)

| Token | Value | Usage |
|-------|-------|-------|
| tile-padding | 8px 12px | KPI tile inner padding |
| tile-gap | 8px | Between tile rows |
| border-left-accent | 4px | Left accent bar on panel header |
| panel-bottom | 8px | Table margin-bottom |

Exceptions: none beyond the channel split above.

---

## Typography

### PDF Channel

| Role | Size | Weight | Line Height | Color |
|------|------|--------|-------------|-------|
| Body / narrative | 9pt | 400 | 1.4 | `#1a1a1a` |
| Explanatory text | 8.5pt | 400 | 1.4 | `#444` |
| Data table cell | 8pt | 400 | — | `#1a1a1a` |
| Data table header | 8pt | bold | — | `#ffffff` on `#1F3864` |
| Section heading (`<h2 class="section-heading">`) | 13pt | bold | — | `#1F3864` |
| Subsection heading (`<h3 class="subsection-heading">`) | 10pt | bold | — | `#2e4a7a` (11pt per `mttr_trend_module.py` for Owner/Application subheadings) |
| KPI tile value | 16pt | bold | — | `#1F3864` |
| KPI tile label | 7.5pt | 400 | — | `#757575` |
| MoM arrow (▲/▼) — improved | 10pt | bold | — | `#388e3c` (green) |
| MoM arrow (▲/▼) — worsened | 10pt | bold | — | `#d32f2f` (red) |
| MoM arrow (—) — flat/missing | 10pt | 400 | — | `#9E9E9E` (grey) |
| Cold-start / missing notice | 9pt | italic | — | `#9E9E9E` |
| Footer (page counter) | 8pt | 400 | — | `#666` |

Source: `reports/modules/composer.py` `_PDF_CSS` (verified lines 86–198).

### Email Channel

| Role | Size | Weight | Color |
|------|------|--------|-------|
| Panel module name | 13px | bold | `#1a1a1a` (via `<strong>`) |
| Panel summary / cold-start notice | 12px | 400 | `#757575` |
| Driver narrative | 11px | italic | `#555` |
| Tile metadata / timestamp | 10px | 400 | `#757575` |

Source: `reports/modules/mttr_trend_module.py` lines 1287–1332, `new_vs_remediated_module.py` lines 675–701.

### Excel Channel

| Role | Size | Bold | Color |
|------|------|------|-------|
| Tab title (A1) | 13pt | yes | default |
| Tab subtitle / cold-start note (A2) | default | italic | `#757575` |
| Column headers | default | yes | default |

Source: `mttr_trend_module.py` lines 1136–1147.

### Chart Channel (matplotlib sparklines)

| Property | Value |
|----------|-------|
| Font family | DejaVu Sans (global `rcParams`) |
| Base font size | 11pt (global `rcParams`) |
| Sparkline title font | 7pt (reduced from base for mini-chart) |
| DPI | 120 for sparklines (vs 150 for full charts) |
| Figure size | (2.0, 1.2) inches per sparkline |

Source: `exporters/chart_exporter.py` lines 76–84; `17-RESEARCH.md` sparkline spec.

---

## Color

### Semantic Palette (from `config.py` and `rag_utils.py` — locked)

| Role | Hex | Usage |
|------|-----|-------|
| Dominant — page surface | `#ffffff` | PDF page background, email table background |
| Secondary — data table stripe | `#f5f7fa` | Even rows in `.data-table` |
| Secondary — table header | `#1F3864` | `.data-table th` background |
| Section heading / KPI value | `#1F3864` | Section headings, KPI tile values |
| Accent — narrative muted | `#444` | Explanatory text |
| Accent — label / disabled | `#757575` | Subtitle, KPI labels, cold-start copy |
| Accent — cold/flat | `#9E9E9E` | Flat MoM arrow, cold-start notice |
| Accent — page footer | `#666` | Footer page counter |
| Chrome header background | `#1a2332` | PDF chrome header band (HEADER_BG_COLOR in `config.py`) |

### RAG Status Colors (from `rag_utils.STATUS_COLOR` — locked)

| Status | Hex | Label |
|--------|-----|-------|
| green (On Target) | `#388e3c` | Composite RAG Green, improved signal arrows |
| yellow / amber (At Risk) | `#f57c00` | Composite RAG Amber, flat/incomplete signal |
| red (Off Target) | `#d32f2f` | Composite RAG Red, worsened signal arrows |
| no_data (No Data) | `#757575` | Empty-data guard fallback strip cell |

Note: the composite RAG key uses `"yellow"` internally (matching `build_rag_strip_entry` API);
the email panel and PDF must use `STATUS_COLOR["yellow"]` = `#f57c00` for amber states.
Do not use `#fbc02d` (Medium severity color) for RAG amber — that color is reserved for severity.

### Per-Signal Sparkline Line Colors (from `17-RESEARCH.md` — locked)

| Signal | Line Color | Rationale |
|--------|-----------|-----------|
| Open-Critical MoM delta | `#d32f2f` | Critical severity color (config.SEVERITY_COLORS) |
| Net velocity (inflow - outflow) | `#1976d2` | Info blue — neutral velocity indicator |
| SLA posture rate | `#388e3c` | Green — posture/health indicator |
| MTTR overall | `#f57c00` | High/orange — time metric |

### Severity Colors (from `config.SEVERITY_COLORS` — locked, for any severity-keyed table column)

| Severity | Hex |
|----------|-----|
| Critical | `#d32f2f` |
| High | `#f57c00` |
| Medium | `#fbc02d` |
| Low | `#388e3c` |
| Info | `#1976d2` |

### Email Panel Background Colors (from existing module patterns)

| State | Background | Left border | Source |
|-------|-----------|-------------|--------|
| Cold-start / no data | `#F5F5F5` | `#757575` (grey) | `new_vs_remediated_module.py` line 677 |
| Normal (data available) | `#FFF3E0` | RAG-color (dynamic) | `mttr_trend_module.py` line 1325 |

Accent reserved for: RAG status indicators on the cover-page RAG strip cell, the left border bar on email panel header, and MoM direction arrows (▲/▼). Not applied to general table rows, body text, or structural layout.

---

## Copywriting Contract

All copy is rendered in non-interactive static output. No CTA labels or destructive confirmations apply. The contract covers state-specific copy for all four channels.

### Module Identity

| Element | Copy |
|---------|------|
| `MODULE_ID` | `program_health` |
| `DISPLAY_NAME` | `Program Health Overview` |

### RAG Strip (Cover Page — CONTRACT-03)

| State | `headline_value_str` | `rag_label` (from STATUS_LABEL) | Notes |
|-------|---------------------|-------------------------------|-------|
| All 4 signals green | Number of green signals, e.g. `"4 / 4 On Track"` | `"On Target"` | `status="green"` |
| 2–3 signals green | E.g. `"3 / 4 On Track"` | `"At Risk"` | `status="yellow"` |
| 0–1 signals green | E.g. `"1 / 4 On Track"` | `"Off Target"` | `status="red"` |
| Missing signal(s), raw=green | E.g. `"3 / 4 On Track"` + `" (incomplete)"` | `"At Risk"` | D-17-06 cap; `status="yellow"` |
| Cold-start (< 2 snapshots) | `"Trend Being Established"` | `"At Risk"` | `status="yellow"` per D-17-08 |
| Zero-row / empty data | `"—"` (`NO_DATA_HEADLINE`) | `"No Data"` | `status="no_data"` via `_empty_result()` |

### Email Panel (CONTRACT-01) — 4-Tile KPI Row

#### Tile Labels (top-line label, 7.5pt / 10px)

| Tile | Label |
|------|-------|
| 1 | `Open Critical` |
| 2 | `Net Velocity` |
| 3 | `SLA Posture (Crit+High)` |
| 4 | `MTTR (30-day)` |

#### Tile Values (current value, display)

| Tile | Format | Cold-start format | Missing format |
|------|--------|-------------------|----------------|
| Open Critical | `{N} open` | `{N} open` (current from live `vulns_df`) | `"—"` |
| Net Velocity | `{+/-N} MoM` | `{N} in / {N} out` | `"—"` |
| SLA Posture | `{safe_pct(rate)}` e.g. `87.3%` | `{safe_pct(current_rate)}` | `"—"` |
| MTTR (30-day) | `{safe_format(days, '.0f')} d` | `"—"` (no `fixed_vulns_df`) | `"—"` |

#### MoM Arrow Convention (consistent with `mttr_trend_module` D-16-13)

| Direction | Symbol | Color |
|-----------|--------|-------|
| Improved | `▼` (U+25BC) | `#388e3c` green |
| Worsened | `▲` (U+25B2) | `#d32f2f` red |
| Flat / no direction | `—` (U+2014 em dash) | `#9E9E9E` grey |

Note: `▼` = improved for Open-Critical (fewer = better), Net Velocity (lower net delta = better), MTTR (lower = better). `▲` = improved for SLA Posture (higher rate = better). The signal `higher_is_better` flag controls the inversion.

#### One-Paragraph Narrative (driver_narrative field — CONTRACT-04)

| Condition | Narrative template |
|-----------|-------------------|
| Normal, composite Green | `"The program improved on {N} of 4 indicators this month. {top signal}: {value} ({arrow} MoM)."` |
| Normal, composite Amber | `"The program held steady on {N} of 4 indicators this month. {lagging signal} warrants attention."` |
| Normal, composite Red | `"The program worsened on {N} of 4 indicators this month. Immediate focus recommended on {bottom signals}."` |
| Missing signal(s) present | Append: `" Note: {signal name(s)} data incomplete this period."` |
| Cold-start | `"Program health trend being established — month-over-month direction available from next snapshot."` |
| Zero-row / empty data | `"No data in scope."` (`NO_DATA_DRIVER` from `rag_utils`) |

The narrative is 1–2 sentences maximum. Signal names to use: "Open Critical count", "Net Velocity", "SLA Posture", "MTTR".

#### Panel Header States

| State | Header background | Left border color | Summary text |
|-------|------------------|------------------|--------------|
| Cold-start / no data | `#F5F5F5` | `#757575` | `"Program health trend being established."` |
| Data available | `#FFF3E0` | RAG color from `STATUS_COLOR` | `data.summary_text` |

### PDF Section (`render_pdf_section`) — Heading and Layout

| Element | Copy |
|---------|------|
| `<h2 class="section-heading">` | `Program Health Overview` |
| Sparkline row label (above row) | `"Month-over-month signal trends"` |
| Sparkline per-chart title | Signal label + current value + MoM arrow, e.g. `"Open Critical\n47 ▼"` |
| Owner table subheading | `"Owner Velocity — Open Critical + High"` |
| Owner outlier column value | `"▲ Outlier"` in `#d32f2f` red when rise > 20% MoM |
| Cold-start notice (replaces sparklines) | `"Month-over-month trend being established — available from next snapshot."` |
| Missing signal notice (inline) | `"[Signal name] data unavailable this period."` |
| Empty data (zero-row) | `"No data in scope for this filter."` |

### Owner Velocity Table — Column Headers

| Column | Header text |
|--------|------------|
| Owner name | `Owner` |
| Current open Crit+High | `Open Crit+High` |
| MoM delta | `MoM Delta` |
| Outlier flag | `Status` |

Column order: Owner | Open Crit+High | MoM Delta | Status.

### Excel Tabs (`render_excel_tabs`)

| Tab | Name |
|-----|------|
| Summary tab | `Program Health` |
| Owner detail tab | `Owner Velocity` |

| Cell | Content |
|------|---------|
| A1 (summary tab) | `Program Health Overview` (bold, 13pt) |
| A2 (summary tab) | Cold-start note or generated timestamp (italic, `#757575`) |

### Analyst Tabs (`render_analyst_tabs` — CONTRACT-02)

| Tab | Name | Columns |
|-----|------|---------|
| Owner MoM detail | `PH — Owner Detail` | Owner, Open Crit+High (curr), Open Crit+High (prev), MoM Delta, MoM Delta %, Outlier |

QUAL-05 hard constraint: no hostnames, IPs, asset UUIDs, or plugin IDs in any analyst tab row. Owner tag name, aggregate open counts, and derived delta only.

### Error / Missing States

| Condition | Copy |
|-----------|------|
| `sla_rate_crit_high` absent from old snapshots (cold-start) | Tile shows `"—"`, narrative appends `" SLA Posture data incomplete this period."` |
| Owner snapshot `insufficient_data=True` | Owner velocity table shows current-snapshot-only owner counts; MoM Delta column shows `"—"`; note below table: `"Owner month-over-month trend being established."` |
| All signals worsened | Composite Red; strip label `"Off Target"` |
| Module compute error (caught) | `_empty_result()` → `"No Data"` strip, grey panel header, `"No data in scope."` narrative |

---

## Channel Constraints (locked — not negotiable)

| Channel | Constraint | Source |
|---------|-----------|--------|
| Email | Inline CSS only — no `<style>` blocks, no external stylesheets | CLAUDE.md |
| Email | Charts via base64 CID: `<img src="cid:{module_id}_sparkline_{n}">` | CLAUDE.md |
| Email | Outlook / Gmail / Apple Mail compatible — table-based layout | CLAUDE.md |
| PDF | WeasyPrint rendered — no JavaScript, no flexbox (use `display:table`) | Existing pattern |
| PDF | A4 landscape, 15mm/12mm/18mm/12mm margins | `composer.py` `_PDF_CSS` |
| PDF | Page counter via `@bottom-center` CSS | `composer.py` `_PDF_CSS` |
| Excel | openpyxl — no xlsxwriter, no pandas `.to_excel()` styling | STACK.md convention |
| All | No web app, no browser rendering, no responsive breakpoints | Phase scope |

---

## Per-Channel Render Contracts

### PDF (`render_pdf_section`) — Layout Specification

```
[<h2 class="section-heading">Program Health Overview</h2>]
[<p class="explanatory-text">summary_text or cold-start notice</p>]

[Sparkline row — display:table, width:100%]
  [Cell 1 — 23% width: Open-Critical sparkline PNG (2.0×1.2in, 120dpi)]
  [Cell 2 — 23% width: Net Velocity sparkline PNG]
  [Cell 3 — 23% width: SLA Posture sparkline PNG]
  [Cell 4 — 23% width: MTTR sparkline PNG]

[<h3 class="subsection-heading">Owner Velocity — Open Critical + High</h3>]
[<table class="data-table">]
  [th: Owner | Open Crit+High | MoM Delta | Status]
  [td rows: one per owner, sorted descending by MoM Delta]
  [Outlier rows: "▲ Outlier" in #d32f2f for >20% MoM rise]
```

Cold-start: replace sparkline row with a single `<p class="explanatory-text">` cold-start notice.
Owner table still renders (current-snapshot counts only, no MoM Delta column).

### Email Panel (`render_email_panel`) — Layout Specification

```
[<table width:100%, border-collapse:collapse, font-family:Arial,sans-serif>]
  [<td padding:8px 12px, background:#FFF3E0 or #F5F5F5, border-left:4px solid {rag_color}>]
    [<strong font-size:13px>Program Health Overview</strong>]
    [<br>]
    [<span font-size:12px> {N} of 4 signals on track — {composite_label} </span>]

[4-tile KPI table — display:table, width:100%]
  [Tile 1: Open Critical  |  Tile 2: Net Velocity]
  [Tile 3: SLA Posture    |  Tile 4: MTTR (30-day)]
  Each tile: value (bold), MoM arrow, label (muted)

[<em font-size:11px color:#555>{driver_narrative}</em>]
[<span font-size:10px color:#757575>{missing signal notice if any}</span>]
```

Sparklines are NOT embedded in the email panel (bandwidth / Outlook compatibility).
The panel is text + table tiles only. Sparkline PNGs are available as separate
`email_inline_images` entries keyed `program_health_sparkline_{0..3}` for
composed report emails that choose to embed them.

### RAG Strip (`render_rag_strip_entry`) — CONTRACT-03

Use `build_rag_strip_entry(display_name, headline_value_str, status)` directly.
Do not construct the dict manually.

| Field | Value |
|-------|-------|
| `display_name` | `"Program Health Overview"` |
| `headline_value_str` | See Copywriting Contract RAG Strip table above |
| `status` | `"green"` / `"yellow"` / `"red"` / `"no_data"` |

---

## Registry Safety

| Registry | Blocks Used | Safety Gate |
|----------|-------------|-------------|
| None — no component registries | n/a | not applicable |

Phase 17 installs no new packages and uses no third-party component registries.
All rendering uses existing `reports/modules/` infrastructure.

---

## Module Options (visual contract for configurable defaults — D-17-05/07)

These ship as `module_options` defaults and affect rendered output. Implementor must
expose all of them via `validate_config()` following `mttr_trend_module` pattern.

| Option key | Default | What it controls |
|-----------|---------|-----------------|
| `green_count_min` | `4` | Signals needed for Green composite (D-17-05) |
| `amber_count_min` | `2` | Signals needed for Amber composite (D-17-05) |
| `open_crit_flat_abs` | `5` | ±N findings = "flat" for Open-Critical signal (D-17-07) |
| `sla_rate_flat_pct` | `2.0` | ±N percentage points = "flat" for SLA Posture signal (D-17-07) |
| `mttr_flat_days` | `1.0` | ±N days = "flat" for MTTR signal (D-17-07) |
| `owner_outlier_pct` | `20.0` | % MoM rise threshold for Owner outlier flag (D-17-09) |

Net velocity has no flat band option — direction is binary (net_delta improved vs worsened),
consistent with `new_vs_remediated_module` directional coloring.

---

## Checker Sign-Off

- [ ] Dimension 1 Copywriting: PASS
- [ ] Dimension 2 Visuals: PASS
- [ ] Dimension 3 Color: PASS
- [ ] Dimension 4 Typography: PASS
- [ ] Dimension 5 Spacing: PASS
- [ ] Dimension 6 Registry Safety: PASS

**Approval:** pending
