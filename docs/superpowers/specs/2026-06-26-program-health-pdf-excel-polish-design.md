# Program Health Overview — PDF / Excel / Email Polish (Phase 19 gap closure)

- **Date:** 2026-06-26
- **Status:** Approved (design)
- **Origin:** Phase 19 Plan 19-08 human-verification checkpoint. Operator UAT against the
  "Custom Composed Report — example" group (scope `filters: {}`, all assets) surfaced
  readability/correctness gaps in the Program Health Overview module. See
  `.planning/phases/19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio/19-08-CHECKPOINT-FINDINGS.md`.
- **Touches:** `reports/modules/program_health_module.py` (PDF + Excel + email render channels)
  and its tests. No composer/email_sender contract changes.

## Context / root cause

Program Health renders 4 velocity signals (Open Critical, Net Velocity, SLA Posture, MTTR)
as a sparkline row + an Owner velocity table, plus an email 4-tile panel and Excel tabs.

UAT root cause (do not re-fix as a bug): the reconstructed historical trend months hold
**severity counts only** — no `mttr_*`, `sla_rate_crit_high`, or `new/fixed` counts. So MoM
arrows / sparklines populate for **Open Critical** (counts exist for all months) but show
"—"/"establishing" for **MTTR / Net Velocity / SLA Posture** (one live month, no prior).
This is correct missing-data behavior. **Decision: forward-fill** — these populate as monthly
snapshots accumulate. No historical reconstruction; `fixed_vulns_df` stays unthreaded
(D-17-01 preserved).

This spec addresses the *readability and current-month correctness* gaps, not the data gap.

## Locked decisions

| # | Decision |
|---|----------|
| D-1 | PDF splits into two pages: page 1 = charts + captions + status line; page 2 = Owner table alone. |
| D-2 | Each chart caption uses the approved definition text (below), verbatim. |
| D-3 | Net Velocity: arrow color from the **current month's net sign** (not delta-of-deltas). Display **intake / fixed / net**. |
| D-4 | MTTR tile stays "—" with caption "establishing from monthly snapshots". No `fixed_vulns_df` threading. |
| D-5 | Owner table columns: Owner \| Open Crit+High \| Share of total % \| Assets \| MoM Delta \| MoM Delta %. |
| D-6 | Excel: fix unreadable row-header fill (match MTTR Trend tab's header style); add definitions block; Owner Velocity tab columns match the new PDF table. |

## Approved caption / definition text (verbatim)

- **Open Critical** — open Critical-VPR findings — *lower is better; ▼ green = falling*
- **Net Velocity** — new findings minus fixed this window (intake − fixed) — *negative is good
  (you fixed more than came in); ▼ green when fixed > intake, ▲ red when intake > fixed*
- **SLA Posture** — % of open Critical + High findings still within SLA — *higher is better;
  ▲ green = rising*
- **MTTR** — average days to remediate (rolling 30-day) — *lower is better; ▼ green = falling*

## Channel-by-channel changes

### PDF (`render_pdf_section`)
1. Restructure into two page sections:
   - **Page 1:** header, "N of 4 signals on track — <RAG label>" status line, the 4-chart
     sparkline row, each chart with its one-line caption (D-2). Narrative summary stays.
   - **Page 2:** Owner velocity table only (D-5), preceded by an explicit page-break so the
     table never straddles a page boundary (today's single overflowing block is the bug).
2. Owner table columns (D-5):
   - **Open Crit+High (curr)** — live from `vulns_df` via `extract_owner()` (existing).
   - **Share of total %** — owner's Open Crit+High ÷ in-scope total Open Crit+High. Computed
     now; guard divide-by-zero with `safe_pct`.
   - **Assets** — per-owner asset count from `assets_df` via `extract_owner()`.
   - **MoM Delta / MoM Delta %** — existing; blank ("—") until history accrues (forward-fill).
3. Net Velocity current-value annotation (D-3): `in {new} / fixed {fixed} · net {net} {arrow}`
   using thousands separators; arrow + color from current net sign.
4. MTTR chart caption (D-4): append "establishing from monthly snapshots" when `mttr_current`
   is None.

### Email (`render_email_panel` / KPI tiles)
- Net Velocity tile: same intake/fixed/net display + current-sign arrow (D-3).
- MTTR tile: keep "—" + the "establishing from monthly snapshots" caption (D-4).
- Definitions: add a compact one-line caption under each tile (or a short legend row) using
  the approved text, kept inline-CSS / Outlook-safe (no `<style>` blocks).
- No layout/tile-count change.

### Excel (`render_excel_tabs`)
- **Program Health tab:** replace the dark-blue-fill/black-text row headers with the MTTR
  Trend tab's readable header style (reuse the same fill + font definition — see
  `mttr_trend_module`'s Excel header). Add a small definitions block (the 4 lines).
- **Owner Velocity tab:** columns match the new PDF table (add Share %, Assets).

### Compute (`compute`)
- Surface `new_current` and `fixed_current` into `metrics` (already read as `curr_new`/
  `curr_fix` for the net delta — just expose them).
- Add `share_pct` and `asset_count` per owner row in `table_data`/`analyst_rows`.
- Net Velocity **current-value status** derives from `sign(net_current)`:
  net < 0 → "green", net > 0 → "red", net == 0 → "flat". The MoM/delta-of-deltas logic that
  drives the *sparkline trend* is unchanged (it still shows when history exists).

## Empty-data / cold-start (QUAL-03 — unchanged contract)
- All new values use `safe_pct`/`safe_int`/`safe_format`; zero-row / zero-total inputs render
  the no-data path, never crash. Share% with a zero denominator → "—".
- Cold-start path keeps rendering; new columns show "—" where data is absent.

## Tests
- New velocity direction: net<0 → green ▼, net>0 → red ▲, net==0 → flat (unit).
- `new_current`/`fixed_current` surfaced; intake/fixed/net string format.
- Owner table: `share_pct` sums to ~100% across owners; divide-by-zero guard; `asset_count`
  present.
- MTTR caption present when `mttr_current` is None.
- Excel: Program Health row-header fill equals the MTTR Trend header fill (assert the style);
  definitions block present; Owner Velocity tab has Share %/Assets columns.
- Cold-start + empty-data guards stay green.

## Verification (human)
- Re-render the composed report (all-assets) and confirm via a **real PDF render** (not layout
  math — WeasyPrint has flex/page-break quirks): page 1 charts+captions, page 2 table alone,
  no mid-table split.
- Excel: row headers readable; definitions present; Owner Velocity has Share %/Assets.
- Email: Net Velocity shows intake/fixed/net with a colored arrow; MTTR caption present.

## Out of scope
- Historical MTTR/velocity/SLA reconstruction.
- Threading `fixed_vulns_df` into program_health (D-17-01 stays).
- Any composer / email_sender / mttr_trend module changes beyond reusing mttr_trend's Excel
  header style.

## Revision 2026-06-26b — re-verification fixes (Plan 19-11)

Operator re-verified the 19-10 build and found two issues. Approved fixes:

- **D-7 — composite consistency (correctness bug).** 19-10 changed the Net Velocity *tile* to
  the current-sign status but left the composite RAG, the "N of 4 On Track" count, and the
  narrative reading the OLD delta-of-deltas status (`sig2_status` = "missing" with no history).
  Result: tile shows green but header says "0 of 4" / "worsened on 4 of 4". Fix: the composite
  RAG / on-track count / narrative consume the **same current-sign Net Velocity status** the
  tile shows. (`signal_statuses[1]` becomes the current-sign status.) The missing-cap (D-17-06)
  still applies to genuinely missing signals (SLA, MTTR with no history). Expected after fix
  with Open Critical red + Net Velocity green + SLA/MTTR missing: "1 of 4 On Track", narrative
  "worsened on 3 of 4", composite stays red.
- **D-8 — PDF chart-row layout (refines D-1/D-2/D-3).**
  - **Single arrow:** today the net string embeds an arrow (`…net {net} {nv_arrow}`) AND
    `_render_sparkline_b64` appends `{mom_arrow}` → two arrows. Pass the arrow once.
  - **Two-row layout:** page-1 chart area = a top row of 4 tiles (uniform height + uniform
    font), each = sparkline + one headline value + one arrow; a small vertical gap; then a
    bottom row of 4 caption cells aligned under each chart. The definition text moves OUT of
    the tiles into the caption row (fixes the cram + per-tile height mismatch).
  - **Net Velocity headline:** the tile shows the **net** value only (e.g. `net −8,272 ▼`) at
    the same font as the other three; the `in {new} / fixed {fixed}` breakdown moves to that
    tile's caption cell below. All three numbers still shown (honors D-3), tiles stay uniform.
