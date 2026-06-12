# Phase 17: Program Health Overview - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-12
**Phase:** 17-program-health-overview
**Areas discussed:** Signal sourcing model, SLA signal source, OD-5 composite RAG rule, PDF / Owner table layout

---

## Signal sourcing model

| Option | Description | Selected |
|--------|-------------|----------|
| Re-derive from substrate | program_health reads the same S1 snapshots + current vulns/assets the other modules consume and computes its 4 signals itself. Zero composer change; independent thin-consumer pattern. | ✓ |
| Consume sibling outputs | Change composer/composed_report so source modules compute first, then feed their ModuleData into program_health. Breaks the independent-module contract; ordering/coupling risk. | |
| Extract shared helpers | Pull signal math into shared utils consumed by source modules AND program_health. No composer change but refactors two shipped modules. | |

**User's choice:** Re-derive from substrate (D-17-01).
**Notes:** Confirmed the composer never passes sibling `ModuleData` into `compute()`, so the research's "composer that references other modules" framing does not fit this codebase. Locked correctness consequence (D-17-02): net-velocity and MTTR numbers must use the same definitions as new_vs_remediated / mttr_trend so the one-pager never disagrees with the detail modules.

---

## SLA signal source

| Option | Description | Selected |
|--------|-------------|----------|
| Persist new SLA snapshot field | Extend capture_snapshot() with a forward-accumulating SLA-rate aggregate so "SLA rate delta" is a real MoM signal. Cold-starts until 2 snapshots. | ✓ |
| Current-snapshot SLA, no MoM | Reuse existing SLA breach calc as a current posture signal only; tile shows current rate, no MoM arrow. Simplest, zero snapshot change. | |
| You decide / hybrid | Persist for forward MoM but render current-only until 2 snapshots exist. | |

**User's choice:** Persist new SLA snapshot field (D-17-04).

### Follow-up — SLA metric definition

| Option | Description | Selected |
|--------|-------------|----------|
| % open within SLA (posture) | Of all currently-open findings, % still inside SLA window (not overdue). Point-in-time health posture. | ✓ |
| % fixed within SLA (remediation) | Of findings fixed in rolling-30d, % fixed before SLA expired (critical_remediation_sla logic). Closed-work only. | |
| You decide | Pick whichever fits a management one-pager. | |

**User's choice:** % open within SLA — posture (D-17-03).

### Follow-up — SLA severity scope

| Option | Description | Selected |
|--------|-------------|----------|
| Critical + High only | % of open Crit+High within SLA. Aligns with Open-Crit tile + Owner Crit+High outlier rule; excludes Low/Medium dilution. | ✓ |
| All severities | % of all open within SLA. Truer whole-program number but Low/Medium volume dominates. | |
| You decide | Pick cleanest, most decision-useful scope. | |

**User's choice:** Critical + High only (D-17-03).
**Notes:** User consistently chose the richer path — real MoM (persist a field) over current-only, and posture over remediation-rate — scoped to the severities leadership escalates on.

---

## OD-5 composite RAG rule

| Option | Description | Selected |
|--------|-------------|----------|
| Count green: 4/2-3/0-1 | Green = all 4 green; Amber = 2-3 green; Red = 0-1 green. Roadmap default; configurable via module_options. | ✓ |
| Red-dominates override | Same bands but any single Red forces at least Amber; 2+ Reds forces Red. More conservative. | |
| You decide | Pick the rule that best signals real risk without false alarms. | |

**User's choice:** Count green: 4/2-3/0-1 (D-17-05).

### Follow-up — Missing / cold-start signal folding

| Option | Description | Selected |
|--------|-------------|----------|
| Cap at Amber + note | Any missing signal caps composite at Amber "data incomplete" (never Green) and names the missing signal(s). Available signals still count for Amber-vs-Red. | ✓ |
| Missing = non-green | Missing signal just counts as not-green in the tally; no Amber cap. Edge case: 4 missing = Red misreads "no data" as "off track". | |
| You decide | Whichever honestly represents "can't fully assess" without crying wolf. | |

**User's choice:** Cap at Amber + note (D-17-06).

### Follow-up — Per-signal RAG basis

| Option | Description | Selected |
|--------|-------------|----------|
| MoM direction | Color by month-over-month movement: improved=green, flat=amber, worsened=red. Thresholds for "flat" ship as module_options. | ✓ |
| Absolute level | Color by standing vs target (SLA% ≥95 green, etc.). Reflects standing not momentum; a stuck-but-improving program reads red forever. | |
| Hybrid | Absolute sets band, MoM breaks ties / adds arrow. Richest but most knobs. | |

**User's choice:** MoM direction (D-17-07).
**Notes:** Locked consequence (D-17-08): in cold-start (1 snapshot) no signal has a direction → all 4 missing → composite Amber "data being established" + current-value tiles. Consistent with roadmap criterion 3 and QUAL-01.

---

## PDF / Owner table layout

| Option | Description | Selected |
|--------|-------------|----------|
| Sparkline row + Owner table | Row of 4 mini sparklines (current value + MoM arrow) above the Owner velocity table (>20% MoM Crit+High outlier flag). Matches FEATURES spec. | ✓ |
| Traffic-light table only | Compact 4-row table (signal/current/delta/RAG) + Owner table. Simpler; loses trend shape. | |
| You decide | Pick whichever reads best as a single-page management summary. | |

**User's choice:** Sparkline row + Owner table (D-17-09).

---

## Claude's Discretion

- Exact new snapshot field name + JSON shape for the SLA-posture aggregate; per-Owner SLA persistence is optional (not required by criterion 4).
- Whether D-17-02 parity is via a shared helper or definitionally-identical re-derivation.
- Default numeric "flat" bands (D-17-07) and composite bands (D-17-05) surfaced as module_options.
- Email 4-tile wording, one-paragraph narrative generation, sparkline styling, Excel column order, analyst-tab layout, cold-start / missing-signal disclosure copy.
- Multiple-snapshots-in-one-month tie-break (latest), per D-16-08.

## Deferred Ideas

- GEN-01 / management_summary migration — Phase 18.
- Per-Owner SLA posture in snapshots — optional v1.4 enrichment.
- Absolute-level / hybrid signal RAG — rejected for MoM-direction.
- Red-dominates composite override — rejected for plain green-count.
