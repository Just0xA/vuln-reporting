---
status: issues_found
phase: 19
plan: 19-08
source: operator UAT (2026-06-25)
scope_run: "Custom Composed Report — example", filters {} (all assets)
---

# Phase 19 — Plan 19-08 Human-Verification Findings

Operator ran `run_all.py --group "Custom Composed Report — example"` (scope flipped to
all-assets) + `capture_trend_snapshot.py`. Checkpoint returned **issues found** — phase
held, NOT marked complete, Wave 5 closeout (19-09) NOT started.

## PASS

- **P16 Test 2 — Excel "MTTR Trend" tab** — window disclosure row present, no "SLA Target"
  column on Owner rows. ✓
- **P16 Test 1 — gauge band renders** with SLA targets (15/30/60/120) in owner-default view.
  The D-16-13 always-visible-band blocker is confirmed fixed. ✓ (arrows: see ROOT CAUSE below)
- **P16 email overall MTTR panel renders** — "Overall MTTR 19.6d (rolling 30 days) — Exceeding
  SLA … Critical SLA target: 15d", partial-month note, defers Owner breakdown to PDF. ✓

## ROOT CAUSE — empty MoM arrows / sparklines (P16 Test 1 arrows, P17 Checks 1 & 3)

Investigated the all-assets trend store. The 12 reconstructed historical months
(2025-06 … 2026-05) contain **severity counts only** (critical/high/medium/low/asset_count).
They do NOT contain the derived metrics: `mttr_*`, `sla_rate_crit_high`, or
`new_findings_count`/`fixed_findings_count`. Only the single live 2026-06 entry has those
slots (and they were `null` at inspection time).

Consequence — for MoM direction / sparklines:
- **Open Critical** → 13 months of counts → arrow + sparkline populate (operator saw ▲). ✓
- **MTTR, Net Velocity, SLA Posture** → only 1 live month, no prior → "—" / "incomplete".
  This is *correct behavior for missing prior data*, not a rendering bug. Switching to
  all-assets fixed Open Critical but could not fix these three.

→ DECISION REQUIRED: accept forward-fill (these populate as monthly snapshots accumulate)
  vs. reconstruct historical MTTR/velocity/SLA (large effort).

## DEFECTS / GAP ITEMS (actionable code work, Phase 17 program_health + renderers)

1. **[P17 PDF] No legend / no explanation.** Sparklines have no "what is this, what's
   good vs bad". No definitions for Net Velocity, SLA Posture, MTTR. Reader can't interpret.
2. **[P17 Net Velocity] direction/semantics.** Value def is already `new - fixed` (intake −
   fixed), which matches operator intent. BUT direction is computed as a month-over-month
   "delta of deltas" (needs prior month → shows "—"). Operator wants direction from the
   CURRENT net: fixed > intake → green ▼ (good); intake > fixed → red ▲ (bad). This also
   removes the history dependency so it works with one month of data.
3. **[P17 PDF] Page splits into two** due to sparkline-row sizing. Operator wants the Owner
   velocity table moved to its own second page for flow.
4. **[P17 Excel] Row-header cell fill unreadable** — dark blue fill with black text. Should
   reuse the MTTR Trend tab's row-header cell formatting.
5. **[P17] MTTR tile inconsistency.** program_health MTTR tile shows "—" (D-17-01: no
   fixed_vulns_df threaded → live tile can't compute; relies on snapshot MoM = None), while
   the mttr_trend module beside it shows 19.6d. Confusing. Consider threading the live value.
6. **[P17 PDF/Excel] More context + more data in the Owner velocity table** + per-metric
   definitions (what Net Velocity / SLA Posture / MTTR mean).

## NOT REGRESSIONS

- `sla_rate_crit_high: null` in the 2026-06 entry — valid fail-soft (no qualifying Crit+High
  open findings, or partial capture). A fresh capture recomputes via the Plan 02 NaT-excluded
  helper.
