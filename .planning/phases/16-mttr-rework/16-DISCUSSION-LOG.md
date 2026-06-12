# Phase 16: MTTR Rework - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-12
**Phase:** 16-mttr-rework
**Areas discussed:** Resolved population (OD-4), Duration clock & time_taken_to_fix, Window & MoM bucketing, Channel layout & Owner cut, Trend axis & partial-month semantics, Snapshot schema evolution, board_summary baseline scope

---

## Resolved population (OD-4)

| Option | Description | Selected |
|--------|-------------|----------|
| B — Durably-fixed only | Count only current-state FIXED; drop currently-REOPENED (stale last_fixed). Research + criterion-3 intent. | ✓ |
| A — All fixed (current behavior) | state==FIXED OR last_fixed.notna(); reintroduces the distortion. | |
| C — First-time fixes only | resurfaced_date null only; strictest, smallest sample. | |

**User's choice:** B — Durably-fixed only
**Notes:** Confirmed Option B (also the research recommendation). A reopened-then-re-fixed finding still counts; its clock is corrected by the Duration clock decision. → D-16-01

---

## Duration clock & time_taken_to_fix

| Option | Description | Selected |
|--------|-------------|----------|
| Coalesce resurfaced_date as clock start | days_to_fix = (last_fixed − COALESCE(resurfaced_date, first_found)).days; drop time_taken_to_fix preference. Date-math only; fixture reads ~8d. | ✓ |
| Prefer time_taken_to_fix, fall back to date math | Keeps trusting Tenable's field; risks re-inflation across a reopen. | |
| time_taken_to_fix for never-reopened, date math for reopened | Hybrid. | |

**User's choice:** Coalesce resurfaced_date as clock start (date-math only)
**Notes:** Tenable's time_taken_to_fix likely spans the full first_found→fix window and would re-inflate reopened findings — dropped entirely. Sample-weighted overall mean (criterion 2) falls out for free. → D-16-02

---

## Window & MoM bucketing

| Option | Description | Selected |
|--------|-------------|----------|
| **Trend source:** Persist MTTR into S1 snapshots | Forward-accumulating rolling-30 MTTR in capture_snapshot; cold-start. Only viable path (retention wall). | ✓ |
| **Trend source:** Derive from current export | Blocked — ~29-day fixed retention leaves only ~1 month. | |
| **Trend source:** Hybrid current+snapshot | More moving parts; same-month disagreement. | |
| **Window cfg:** Configurable, default 30 | module_options mttr_window_days; disclosure reflects value. | ✓ |
| **Window cfg:** Hard-coded 30 | Fixed constant. | |

**User's choice:** Persist into S1 snapshots + configurable window (default 30)
**Notes:** Verified `capture_snapshot` persists counts only — no MTTR aggregate existed, so the data-source choice is real. Also extends `scripts/capture_trend_snapshot.py`. → D-16-03, D-16-04

---

## Channel layout & Owner cut

| Option | Description | Selected |
|--------|-------------|----------|
| **Layout:** Overall + per-severity + Owner | Weighted overall + MoM line + per-severity gauges + Owner table. | ✓ |
| **Layout:** Overall + Owner only | Drops per-severity; conflicts with criterion 5. | |
| **Owner scope:** Current-snapshot table only | (Recommended) No per-Owner history; lighter snapshot. | |
| **Owner scope:** Owner MoM too | Persist per-Owner MTTR; cold-start + drift to reconcile. | ✓ |
| **Sparse Owners:** Show 'Insufficient data (N)', omit zero-finding | Criterion-5 treatment extended to Owners. | ✓ |
| **Sparse Owners:** Omit all sub-threshold | Cleaner table, no signal busy small Owners exist. | |

**User's choice:** Overall + per-severity + Owner; **Owner MoM** (diverged from recommended current-only); show "Insufficient data (N)" + omit zero-finding Owners
**Notes:** Deliberate richness choice on Owner MoM (cf. Phase 15 OD-1 divergence). Carries per-Owner snapshot persistence, per-Owner cold-start, Owner-drift reconciliation, and partial-month label on the Owner column. → D-16-05, D-16-06, D-16-07

---

## Trend axis & partial-month semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Snapshot-date axis + 'as-of' disclosure | (Recommended) No partial-month caveat; each rolling-30 point is complete. | |
| Calendar-month axis + partial caveat | Matches new_vs_remediated/density visually; newest month flagged partial. | ✓ |

**User's choice:** Calendar-month axis + partial caveat (diverged from recommended)
**Notes:** Cross-module visual consistency was the explicit goal. The partial flag marks calendar *position*, not an incomplete 30-day window — to clarify in the runbook. Reconciles/keeps the D-16-06 Owner-column partial note. → D-16-08

---

## Snapshot schema evolution

| Option | Description | Selected |
|--------|-------------|----------|
| Implicit optional-field convention | Absent MTTR field → cold-start; no schema_version. Same as D-15-06. | ✓ |
| Add explicit schema_version | Versioned snapshots; new machinery, diverges from Phase 15. | |

**User's choice:** Implicit optional-field convention
**Notes:** Verify with a trend-store smoke check at plan time. → D-16-09

---

## board_summary baseline scope

| Option | Description | Selected |
|--------|-------------|----------|
| Zero-diff safety check + new mttr_trend baseline | Assert board_summary byte-identical; capture new structural baseline for mttr_trend. | ✓ |
| Plan for a legitimate board_summary change | Only if rework touched its render path — it doesn't. | |

**User's choice:** Zero-diff safety check + new mttr_trend baseline
**Notes:** mttr_by_severity is byte-unchanged and the new capture_snapshot params are optional, so a board_summary diff would mean something broke. → D-16-10

---

## Claude's Discretion

- Exact snapshot field names + JSON shape for the new MTTR aggregate
- Chart styling (gauge vs line), Excel column order
- Owner-drift join / missing-month mechanics; multiple-snapshots-in-one-month tie-break
- `min_sample_size` default (existing module defaults to 1; criterion 5 implies 5 — confirm at plan time)
- Exact "as-of" / partial disclosure wording

## Deferred Ideas

- MTTR backfill beyond ~29 days (retention wall — forward-accumulate only)
- Sub-monthly reopen rate (out of scope this milestone)
- WAS MTTR (gated on pyTenable upgrade)
- Program Health (RPT-07, Phase 17) / management_summary migration (GEN-01, Phase 18) — both depend on mttr_trend

---

# Post-UAT Addendum — 2026-06-12 (verify-work, Test 1)

**Trigger:** UAT Test 1 surfaced that the MTTR breakdown renders Severity and Owner rows in a *single combined table* (`table_data` concat at `mttr_trend_module.py:574/595`), which (a) reads as confusing, (b) bleeds onto a 2nd page, and (c) mixes two SLA bases in one column (severity rows use per-sev SLA; owner rows hard-code Critical SLA at `:605`). The right cut is audience-dependent.

## Selection model for the Severity vs Owner breakdown

| Option | Description | Selected |
|--------|-------------|----------|
| Configurable `mttr_view`, split tables | Separate Severity and Owner tables; `module_options.mttr_view ∈ {owner, severity, both}` lets each group render its relevant cut. Fixes confusion + page-bleed + audience fit + the misleading shared SLA column. | ✓ |
| Always split, render both | Two separate tables always; fixes header/SLA confusion but both cuts still print → can still overflow with many owners. | |
| Keep combined, paginate only | Lowest change; keeps the confusing mix and meaningless Owner SLA-target column. | |

**User's choice:** Configurable `mttr_view` (split tables). → D-16-11

## Default `mttr_view` when a group does not set it

| Option | Description | Selected |
|--------|-------------|----------|
| `owner` | By-Owner cut (exec-leadership headline); single table fits a page by default; severity is opt-in. | ✓ |
| `both` | Closest to current behavior; safest backward-compat but a many-owner group can still bleed. | |
| `severity` | Legacy mttr_by_severity framing; Owner opt-in. | |

**User's choice:** `owner`. → D-16-12

## Build path

Tracked as a **Phase 16 gap-closure** (defect in the delivered module). Locked spec captured in `16-UAT.md` Gaps; to be planned via `/gsd-plan-phase 16 --gaps` and executed, then UAT resumes at Test 2.
