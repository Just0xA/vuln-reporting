# Phase 15: Independent New Modules - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-11
**Phase:** 15-independent-new-modules
**Areas discussed:** "New" inflow definition (OD-1), S1 snapshot dimension extension (OD-3), RAG thresholds, Reopen overlap, Partial month handling, Plan decomposition

---

## "New" inflow definition (OD-1)

| Option | Description | Selected |
|--------|-------------|----------|
| `first_found` only | New in M iff first_found in M. Simpler, matches snapshot engine, understates reopen churn. Research's recommendation. | |
| `first_found` OR `resurfaced_date` | New if first_found OR resurfaced in M. More accurate to work-on-queue, more complex, risks double-count vs Reopened module. | ✓ |

**User's choice:** `first_found OR resurfaced_date` — diverged from the research default in favor of accuracy.
**Notes:** Combined with the stacked-display choice below, the intent is for management to see reopen churn explicitly rather than hidden behind a simple first_found inflow.

---

## Reopen overlap (New-vs-Remediated × Reopened relationship)

| Option | Description | Selected |
|--------|-------------|----------|
| Count in both, disclose overlap | Resurfaced counts as inflow AND in Reopened; each internally correct; runbook note; no cross-module subtraction. | |
| Split new vs resurfaced inflow | New-vs-Remediated shows inflow as two stacked components (net-new vs resurfaced); Reopened still counts independently. | ✓ |

**User's choice:** Split new vs resurfaced inflow.
**Notes:** Resurfaced findings still appear in both modules (no subtraction), but New-vs-Remediated makes the net-new/resurfaced split visible in the detailed channels.

---

## S1 snapshot dimension extension (OD-3)

| Option | Description | Selected |
|--------|-------------|----------|
| Extend `capture_snapshot` | Add new aggregate fields to existing S1 record; one file per scope; backward-compatible cold-start. Research's recommendation. | ✓ |
| Module-local snapshot files | Each module writes its own snapshot file; S1 untouched but files proliferate + duplicated cold-start logic. | |

**User's choice:** Extend `capture_snapshot`.
**Notes:** New aggregate dimensions — on-time-scanned count (density denominator, fulfills Phase 14 D-02), reopened count, accepted count, recast count, new-vs-fixed counts. Backward-compatible; new MoM trends cold-start on the new fields.

---

## RAG thresholds

| Option | Description | Selected |
|--------|-------------|----------|
| Research defaults + configurable | Ship research default bands as `module_options`-overridable defaults; tune later without code. | ✓ |
| Set org-specific values now | User supplies exact bands per metric, baked in as defaults. | |

**User's choice:** Research defaults + configurable.
**Notes:** No org-specific bands supplied yet; defaults stand until leadership agrees. Capturing agreed bands later is a config task, not code.

---

## Partial current month

| Option | Description | Selected |
|--------|-------------|----------|
| Show, labeled "Month-to-date (partial)" | Plot in-progress month but label as partial in every channel. Research's recommendation. | ✓ |
| Exclude partial month | Only show completed months; cleaner line but loses most-recent signal until month-end. | |

**User's choice:** Show, labeled "Month-to-date (partial)".
**Notes:** Applies to all MoM trend charts/tables (New-vs-Remediated, Density, Reopened, Accepted/Recast).

---

## Plan decomposition / build order

| Option | Description | Selected |
|--------|-------------|----------|
| Reopened first, then parallel | Build Reopened as pathfinder (no trend dep; exercises state/resurfaced_date + four-channel shape), then four parallel plans. Research's sequencing. | ✓ |
| One plan per module, all parallel | Five independent plans from the start; fastest wall-clock but no pathfinder to copy. | |
| Let the planner decide | Capture modules as scope; planner chooses decomposition. | |

**User's choice:** Reopened first, then parallel.
**Notes:** Reopened plan includes a live-tenant `resurfaced_date`-population spot-check before finalizing its analyst drill-down schema.

---

## Claude's Discretion

- Exact module file/class structure, chart styling, table column ordering.
- `_summarize_filter()` use in the Accepted & Recast analyst tab.
- Fixed-export-absent disclosure wording (degrade to count-only, never silent zero).
- Reopen-lag computation details (`resurfaced_date − last_fixed`, `None` when absent).

## Deferred Ideas

- External Exposure MoM trend (EXT-TREND-01) → v1.5.
- WAS in External Exposure (EXT-WAS-01) → gated on pyTenable upgrade.
- Org-specific RAG band values → future `module_options` config task.
- MTTR rework / Program Health / management_summary migration → Phases 16/17/18.
