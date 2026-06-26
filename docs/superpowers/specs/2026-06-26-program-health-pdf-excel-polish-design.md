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
