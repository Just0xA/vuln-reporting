# Phase 18: management_summary Migration + Docs - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-18
**Phase:** 18-management-summary-migration-docs
**Areas discussed:** OD-8 trend disposition, Retention-fix scope, MTTR 30-day window, Runbook scope (DOC-02), Backfill execution model, Backfill verification gate, Plan sequencing, Legacy JSON disposition

---

## OD-8 — Trend disposition (history at cutover)

| Option | Description | Selected |
|--------|-------------|----------|
| Cold start now, reconstruct later | Migrate on cold start; reconstruction a separate follow-on phase | |
| Migrate legacy JSON | Port management_summary_*.json into the S1 store | |
| Reconstruct-backfill in Phase 18 | Rebuild ~12mo real history from Tenable; ships with history | ✓ |

**User's choice:** Reconstruct-backfill in Phase 18 (→ D-18-01).
**Notes:** Claude flagged the risk of entangling reconstruction with the 2,200-line atomic cutover; resolved by making reconstruction its own pre-cutover plan (decoupled). This choice also resolved the Retention-fix-scope area (fetch rework lands in Phase 18, ahead of cutover).

## OD-8 — Backfill window

| Option | Description | Selected |
|--------|-------------|----------|
| Clean window only (~9-12mo) | Backfill only from where fixed counts stabilize (~Sep 2025) | |
| Full ~16mo, flag the tail | Backfill everything retrievable, mark tapered early months approximate | |
| Fixed 12-month window | Round 12-month boundary regardless of taper | ✓ |

**User's choice:** Fixed 12-month window (2025-06 → now) (→ D-18-02).
**Notes:** Claude carried a caveat — the earliest ~2-3 months (Jun-Aug 2025) sit at the tapered edge and still need a partial/approximate flag; planner verification point, not a reopen.

## OD-8 — Provenance

| Option | Description | Selected |
|--------|-------------|----------|
| Mark provenance, immutable | Source marker reconstructed vs captured; reconstructed months never overwritten | ✓ |
| Treat identically | No marker; simpler but no audit distinction; capture could overwrite | |

**User's choice:** Mark provenance, immutable (→ D-18-03).

## Reconstruction fidelity (per-field)

| Option | Description | Selected |
|--------|-------------|----------|
| Faithful partial backfill | Reconstruct only retrievable fields; null asset_count → Vuln Density cold-starts those months | ✓ |
| Approximate missing inputs | Use current len(assets_df) for historical asset_count | |
| All-or-nothing per month | Only write a month if all fields reconstructable (collapses to cold start) | |

**User's choice:** Faithful partial backfill (→ D-18-04).
**Notes:** Surfaced by Claude — historical asset_count is not reconstructable (Tenable doesn't retain it). No fabricated denominators.

## MTTR 30-day window + fetch-rework regression

| Option | Description | Selected |
|--------|-------------|----------|
| Audit + explicit windows | Audit every fixed-data consumer for implicit-default reliance; each applies its own window; keep rolling-30 | ✓ |
| Keep, assume already explicit | Trust Phase 16; just document | |
| Widen MTTR too | Metric-design change (future phase) | |

**User's choice:** Audit + explicit windows (→ D-18-06).
**Notes:** Claude surfaced the silent-drift risk — widening the fetch changes any metric implicitly relying on the old 30-day default. Audit is a hard gate on the fetch rework.

## Runbook scope (DOC-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Per-module, reproducible | Follow docs/*_calculations.md; exact formula/fields/predicate/edge cases per module | ✓ |
| Single combined runbook | One large doc for all seven | |
| Overview-level | Definitions without full reproduction math | |

**User's choice:** Per-module, auditor-reproducible (→ D-18-07).

## Backfill execution model

| Option | Description | Selected |
|--------|-------------|----------|
| One-time seeding script | Operator-run once before cutover; idempotent; cron continues forward | ✓ |
| Folded into capture cron | Recurring; risks overwrite; conflicts with immutable provenance | |
| Inline at migration | Couples seed to the riskiest step | |

**User's choice:** One-time seeding script (→ D-18-08).

## Backfill verification gate

| Option | Description | Selected |
|--------|-------------|----------|
| Overlap test vs captured | Reconstruct a month with an existing captured snapshot, assert match; fallback reconstruct-today vs live | ✓ |
| Internal consistency only | Coherence checks, no ground-truth anchor | |
| Spot-check + sign-off | Operator eyeballs a few months | |

**User's choice:** Overlap test vs captured (→ D-18-09).

## Plan sequencing

| Option | Description | Selected |
|--------|-------------|----------|
| Full gate chain | fetch+audit → recon+verify → smoke baseline → cutover → runbooks; 1-3 hard gates | ✓ |
| Smoke baseline only | Only smoke baseline gates cutover; recon retrofitted after | |
| Fetch+audit gate, recon after | Gate on fetch+audit+smoke; recon after stable migration | |

**User's choice:** Full gate chain (→ D-18-10).
**Notes:** Roadmap reconciliation captured — smoke baseline remains a hard pre-cutover gate; the gate chain defines what must be green before cutover, not strict commit order of independent prep.

## Legacy JSON disposition

| Option | Description | Selected |
|--------|-------------|----------|
| Archive, don't delete | Stop writing; move legacy files to archive dir for audit/cross-check | ✓ |
| Stop writing, leave in place | Remove writer; leave files | |
| Delete at cutover | Remove writer and files | |

**User's choice:** Archive, don't delete (→ D-18-11).

---

## Claude's Discretion

- Reconstruction predicate mechanics (reuse `open_findings_at()` at past month-boundaries + fixed-data add-back).
- Overlap-test tolerance; provenance field name/shape; archive dir path; partial-month flag mechanics.
- Runbook file grouping within per-module-reproducible.
- Whether the consumer audit extracts a shared explicit-window helper or fixes in place.

## Deferred Ideas

- Widening the MTTR metric window (90-day/all-time) — future phase.
- Reconstructing the tapered Feb–Aug 2025 tail / full ~16mo — set aside for fixed 12mo.
- Persistent finding-mirror + differential-export (`indexed_at`) architecture — v2 strategic option.
- Per-Owner SLA posture in snapshots — optional enrichment (from Phase 17).
- CLOSED (do not re-investigate): `include_unlicensed` and asset-export licensing — ruled out 2026-06-18.
