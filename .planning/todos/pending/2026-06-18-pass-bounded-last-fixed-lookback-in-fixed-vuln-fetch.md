---
created: 2026-06-18T11:20:54.137Z
title: Pass bounded last_fixed lookback in fixed-vuln fetch (Phase 18)
area: general
files:
  - data/fetchers.py:410
  - data/fetchers.py:284
  - reports/modules/mttr_trend_module.py
  - ref/Retrieve Vulnerability Data from Vulnerability Management.md:42
---

## Problem

The "~30-day fixed-findings retention wall" documented in spike 002 and earlier
memory is FALSE. The 30-day floor is the Tenable vuln-export **API default** that
applies when no time-based filter (`indexed_at`/`last_fixed`/`last_found`/
`first_found`) is submitted — NOT a platform retention purge. Source:
`ref/Retrieve Vulnerability Data from Vulnerability Management.md` ("Time-based
Filters" limitation, line 42).

`fetch_fixed_vulnerabilities` (`data/fetchers.py:410`) passes only `state` +
`severity`, so the 30-day default silently applies — we were self-limiting by
omission.

**Empirical proof (fresh live pulls, 2026-06-18):**
- No-filter fixed pull: 187,775 rows, `last_fixed` floor 2026-05-19 (~29 days).
- `last_fixed >= 2yr` filter: **1,285,823 rows (6.8x more)**, floor 2025-02-23
  (~16 months). Requested floor was 2024-06-18 but data stopped at 2025-02-23 =
  real retention boundary (~15-16mo, consistent with Tenable license-based
  retention).
- Tail tapers: monthly fixed counts jump ~5x from Aug 2025 (24k) to Sep 2025
  (114k). Conservative clean reconstruction window ~Sep 2025 → now (~9-10mo);
  Feb–Aug 2025 partial (retention edge vs real growth, undistinguished).
  Definitive disambiguation needs a temporal re-run (watch whether the floor
  rolls forward month over month).

This overturns a premise that several v1.4 design decisions rested on, so it must
be weighed during Phase 18 (management_summary Migration + Docs) planning.

## Solution

**Phase 18 action items:**

1. **Fetch rework (warranted):** pass a BOUNDED, CONFIGURABLE `last_fixed` (or
   `indexed_at` as the proper differential cursor) lookback in
   `fetch_fixed_vulnerabilities` (`data/fetchers.py:410`), sized to ~12-13
   months. NOT unbounded — 6.8x volume bloats every run-scoped parquet cache and
   slows every batch run. Consider the same for `fetch_all_vulnerabilities`
   (`data/fetchers.py:284`).
2. **Revisit OD-8 (cold-start decision):** backfilling ~1 year of real
   remediation/outflow history may now be possible on demand, so a hard cold
   start may be unnecessary. Primary input to lock during Phase 18 discuss.
3. **Revisit Phase-16 MTTR "disclosed 30-day window":** likely an artifact of
   this same API default rather than a deliberate design choice; widening the
   lookback changes the MTTR sample ~6.8x.
4. **Spike 002 superseded on the retention point.** Its central conclusion
   ("reconstruction limited to ~29 days, snapshots mandatory, cold start
   unavoidable") no longer holds. BUT the reopened-aware two-interval open
   predicate finding from that spike STILL HOLDS (naive `first_found<=D AND
   (last_fixed null OR last_fixed>D)` drops ~19% reopened; use
   `state`/`resurfaced_date`).

**CLOSED / NO ACTION (investigated and ruled out 2026-06-18, do NOT
re-investigate):**

- `include_unlicensed`: vuln-export-only param; `unscanned_assets` +
  `scan_coverage_sla_module` source their asset universe from the asset export
  (`fetch_all_assets`), so it is structurally irrelevant to them.
- Asset export licensing: verified via membership test that
  `tio.exports.assets()` default pull already includes all unlicensed assets
  (all 378 `is_licensed=False` IDs present in the default 37,459). No coverage
  blind spot.

**Related memory:** `project_tenable_fixed_retention_trend` (rewritten),
`project_asset_export_includes_unlicensed` (new).
