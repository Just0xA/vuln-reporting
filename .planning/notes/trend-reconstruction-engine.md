---
title: Trend-Reconstruction Engine (history from current findings, not snapshots)
date: 2026-06-05
context: Originated by the requestor during /gsd-explore while scoping post-VTD-01 reports. Instead of accumulating periodic snapshots (current data/trend/ approach), reconstruct the historical open-vulnerability population from the current finding set's lifecycle fields. This is the keystone substrate under ~6 of the 8 batch reports ([[report-requests-batch-2026-06]]).
---

# Trend-Reconstruction Engine

> ⚠ **Spike 002 outcome (2026-06-05): the ambitious premise is INVALIDATED.** Tenable retains fixed findings only **~29 days**, so multi-month history **cannot** be reconstructed from a current export and snapshots **cannot** be retired. What survives: a reopened-aware **current-state** predicate (validated exact) and reconstruction over the **last ~29 days** only. The substrate is therefore a **snapshot-capture engine**, not a backfill engine. The original idea below is retained for context; read it through the spike's lens. See [`../spikes/002-trend-reconstruction-lookback/`](../spikes/002-trend-reconstruction-lookback/).

## The idea

The current trend mechanism (`data/trend/`, used by `management_summary`) stores periodic **snapshots** and accumulates history over time — so any new trend metric has a **cold start** (no history until months pass).

Instead: **reconstruct** the historical open population from today's finding lifecycle fields. A finding was **open on date D** iff:

```
first_found <= D  AND  (last_fixed is null OR last_fixed > D)
```

Run that predicate across the last N month-boundaries and you get the historical open count **retroactively, from a single current export** — no snapshots, no cold start, no accumulation cron. Slice by any dimension (severity, CPE type, `Owner`, tag) for per-bucket trends.

## Why it's the keystone

From the June 2026 batch ([[report-requests-batch-2026-06]]), this engine powers:

- **New vs Remediated (#6)** — it *is* the report: `first_found` in month = new; `last_fixed` in month = remediated.
- **VTD-01 trend** — open Crit+High per App/OS/HW bucket at each month boundary.
- **Vulnerability Density (#5)** — reconstructed open count / asset count per month.
- **Reopened (#7)** — `resurfaced_date` / `state == REOPENED` over time.
- **Program Health velocity (#2)** — inflow vs outflow rates across months.
- **Accepted & Recast (#1)** — current vs previous-month delta.

Build once; six reports become thin `group_by` modules. Also lets `data/trend/` snapshots be retired (or kept only where reconstruction can't serve — see caveats).

## Data availability (verified 2026-06-05)
`vulns_all.parquet` carries `first_found`, `last_found`, `last_fixed`, `state` (OPEN/REOPENED), `resurfaced_date`, `time_taken_to_fix`. A `vulns_fixed.parquet` exists for the remediated population (already fetched; used by `critical_remediation_sla`). So both the open and fixed sides are available without new fetches — **except** that reconstructing *fixed-in-month* counts requires the fixed export to be included in scope (today `vulns_fixed` is fetched only for some reports).

## Caveats (decide per-metric whether reconstruction is valid)

1. **As-of-date severity drift.** Reconstruction applies *today's* VPR/recast severity to past dates. A finding "Critical" today may have been "High" 3 months ago, or been recast since. Fine for a type-distribution or raw-count trend; **not** fine for a historical SLA-breach trend that needs severity-as-it-was. No recast-history source today.
2. **Retention / export window.** Findings aged-out or deleted from Tenable aren't in the export, so **older months undercount**. Quantify the usable lookback before promising N months.
3. **Scope-at-time.** Reconstruction uses *current* tag/asset membership, not historical. An asset that joined `Production`/`Owner=X` last week looks like it was always there. Acceptable for coarse trends; misleading for attribution disputes.
4. **Reopened lifecycle.** `first_found` vs `resurfaced_date` for REOPENED findings — a fixed-then-reappeared finding's "open intervals" aren't a single contiguous span. The predicate above assumes one open interval; multi-interval reconstruction needs `resurfaced_date` handling.

## Design questions for the substrate phase
- Single open-interval predicate vs multi-interval (handles reopened correctly)?
- Which export scope feeds it (open-only vs open+fixed) and how that interacts with the run-scoped parquet cache.
- Output shape: a reusable function `reconstruct_open_counts(df, dates, group_by=...) -> DataFrame` that all trend modules call.
- Coexist with or replace `data/trend/` snapshots — keep snapshots only for as-of-date-severity-sensitive metrics (caveat 1)?
- Measure the real retention/lookback limit (caveat 2) as a spike before committing N-month promises.
