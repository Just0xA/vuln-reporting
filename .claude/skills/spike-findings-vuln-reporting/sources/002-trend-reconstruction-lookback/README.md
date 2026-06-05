---
spike: 002
name: trend-reconstruction-lookback
type: standard
validates: "Given the current finding export, when historical open-population is reconstructed from first_found/last_fixed/state, then it is accurate far enough back (months) to replace snapshot-based trend without a cold start."
verdict: PARTIAL
related: [001]
tags: [trend, reconstruction, retention, snapshots, predicate, reopened, substrate]
---

# Spike 002: Trend-Reconstruction Lookback + Predicate Validation

## What This Validates

Can month-over-month vuln history be **reconstructed from the current finding set** (`first_found`/`last_fixed`/`state`/`resurfaced_date`) instead of accumulating snapshots — and **how far back** before retention purges make it lie? Tests the keystone premise of [`../../notes/trend-reconstruction-engine.md`](../../notes/trend-reconstruction-engine.md).

Datasets (real cached export, 2026-06-02): `vulns_all.parquet` (open/reopened, 160,453) + `vulns_fixed.parquet` (fixed, 201,272).

## How to Run

```bash
python .planning/spikes/002-trend-reconstruction-lookback/measure.py
```

## Investigation Trail

1. **Recon of date ranges** surfaced the headline immediately: `vulns_fixed.last_fixed` spans only **2026-05-03 .. 2026-06-02** — fixed findings are retained ~**29 days**.
2. **Confirmed it's a Tenable wall, not ours.** `data/fetchers.py:410` calls `tio.exports.vulns(state=["fixed"])` with **no `since`/date filter** — we already pull everything Tenable returns. The ~29-day horizon is platform-side retention.
3. **Predicate validation at D=today.** Naive single-interval predicate (`first_found<=D AND (last_fixed null OR last_fixed>D)`) gives 129,907 vs actual 160,453 — **undercounts by 30,546, exactly the REOPENED set**. The naive predicate treats a reopened finding's *prior* `last_fixed` as "still fixed."
4. **Fixed the predicate.** A two-interval model (REOPENED is fixed only during `[last_fixed, resurfaced_date)`) reconstructs current open to **160,455 (+2)** — essentially exact. All 30,548 REOPENED carry `resurfaced_date`, so the correction is always computable.
5. **Monthly reconstruction back 18 months** exposes the survivorship problem. `recon_open` reads 4,203 at 2024-12 rising to ~153k now; `remediated(last_fixed)` is ~0 before 2026-05 then 206,240 in 2026-05. The old-month figures are **floors, not truth** — any finding open at D but fixed in `(D, 2026-05-03)` is invisible (purged from fixed, absent from open). Undercount grows monotonically with age.

## Results

**VERDICT: PARTIAL ⚠ — the predicate works; the ambitious premise does not.**

| Claim under test | Result |
| ---------------- | ------ |
| Two-interval predicate computes *current* open state | ✅ VALIDATED (+2 of 160,453; reopened handled) |
| Naive single-interval predicate (as written in the note) | ❌ BUGGY — undercounts by the reopened set (−30,546) |
| Reconstruct *multi-month* MoM history from one current export | ❌ INVALIDATED — ~29-day Tenable retention wall |
| Retire snapshot-based `data/trend/`, no cold start | ❌ INVALIDATED — snapshots remain necessary for real history |

**Answers to the 4 questions:**
1. **Predicate:** validated, but only with the **two-interval (reopened-aware)** form. The note's single-interval predicate is wrong by the entire reopened population — must be fixed before use.
2. **Lookback/retention:** **~29 days.** Net-open reconstruction is complete only for `D >= 2026-05-03`; older dates undercount by everything fixed-then-purged.
3. **New vs Remediated:** **Remediated/outflow has data for ~29 days only** (hard wall). Inflow (`first_found`) extends years back but undercounts older months via survivorship (short-lived findings already purged). Trustworthy window for a true inflow/outflow series: **~1 month.**
4. **Reopened wrinkle:** real and large — 30,548 findings (19% of open). The single-interval predicate miscounts all of them; the two-interval model using `resurfaced_date` resolves it exactly.

### Signal for the build
- **The substrate is NOT a pure reconstruction engine — it's a snapshot-capture engine.** Start persisting monthly snapshots **now** (open-counts by dimension + the fixed export within its retention window). Reconstruction is limited to **current state + the last ~29 days**; everything older must come from accumulated snapshots.
- **VTD-01's cold start is NOT eliminated** (corrects the optimistic 2026-06-05 note). Trend still accrues forward from first snapshot; the only backfill available is ~29 days of fixed data for the first capture.
- **Whatever computes "currently open" MUST use the two-interval predicate.** The naive form silently drops 19% of findings (all reopened). This is a latent-bug warning for any current-state module too, not just trend.
- **What reconstruction DOES enable cheaply:** current-state slices (VTD-01 balance-now, type/severity/owner distributions), ~1-month new/remediated deltas, and `first_found`-based age buckets (already used by `patch_compliance`).
- **Follow-up (out of code):** confirm whether Tenable's fixed-findings retention is extendable by license/setting in this tenant. If it can go to 90+ days, the reconstruction window widens proportionally — but don't bank on it; design for snapshots.
