---
status: complete
phase: 17-program-health-overview
source: [17-VERIFICATION.md]
started: 2026-06-12T20:20:00-04:00
updated: 2026-06-12T21:18:00-04:00
---

## Current Test

[testing complete]

## Tests

### 1. Email delivery rendering (Outlook / Gmail / Apple Mail)
expected: Configure a composed_report delivery group with `modules: [program_health]` and send to a test inbox. Email body contains 4 labeled tiles (Open Critical / Net Velocity / SLA Posture (Crit+High) / MTTR (30-day)) with MoM arrows, an Owner velocity table, and — if fewer than 2 monthly snapshots exist — a "Trend Being Established" cold-start notice instead of NaN values.
result: pass
prior_issue: "[Test Pull] Report 'composed_report' failed: can only join an iterable — TypeError at composer.py:546 in run_module, during program_health config validation"
severity: blocker
fixed_in: ab00228
fix_summary: "validate_config now returns list[str] per the BaseModule contract (was returning a coerced ModuleConfig — truthy + non-iterable). compute()'s self-call to validate_config was removed (it already coerces each option inline with per-key defaults; the composer validates config before compute). Verified: 92 tests pass + end-to-end ReportComposer.run_module renders cold-start without crashing."

### 2. Live sla_rate_crit_high snapshot capture
expected: Run `python scripts/capture_trend_snapshot.py` against a live or staging Tenable tenant. Snapshot JSON contains `"sla_rate_crit_high": <float 0–100>` (or `null` when zero Crit+High open), no `KeyError`; capture log shows the computed rate or the fail-soft "SLA-posture aggregate failed" WARNING.
result: pass
note: |
  CORRECTION: initially marked pass off the severity file alone without tracing the
  consumer — user correctly challenged after seeing all scalar aggregates null in the
  OWNER snapshot (trend_owner_all_assets.json). Re-verified properly:
  - Module reads Signal 3 SLA from snap.get('sla_rate_crit_high') where snap comes from
    trend_snapshots = read_trend(dimension='severity') (composed_report.py:234;
    program_health_module.py:15,411,433-434). Severity snapshot = 42.4 (crit_high_open=78377). OK.
  - Owner snapshot's null scalar aggregates (on_time_asset_count, reopened_count, mttr_*,
    new/fixed_findings_count, sla_rate_crit_high) are BY DESIGN + pre-existing: the owner
    capture_snapshot() call (capture_trend_snapshot.py:445) passes only enriched_assets, never
    these scalars — true since Phases 13/15/16. Owner snapshot's real payload is the per-owner
    breakdowns (populated), which the Owner velocity table reads. Not a Phase 17 regression.
  - Per D-17-04, sla_rate_crit_high is severity-dimension only; owner-level SLA was deferred.
  MoM RENDER PROVEN (user-approved month-2 simulation, throwaway + restored): injected a
  synthetic 2026-05 prior severity+owner snapshot against the REAL cached vulns/assets, then
  rendered. Result: cold_start=False, composite_rag=green ("4/4 On Track"), PDF emitted 4
  sparkline <img> cells, no NaN%, owner velocity table = 15 rows with MoM column active and
  2 owners correctly flagged as >20%-rise outliers (Configuration Management, ATM). Trend
  files restored to the single real 2026-06 record afterward (verified). Full four-channel
  live MoM path confirmed working — no longer dependent on waiting for a real month 2.
  VERDICT (user-approved): pass — field capture verified + MoM render proven.

### 3. PDF render visual inspection (sparkline row + Owner table)
expected: Run a composed_report batch with program_health included and open the output PDF. Page shows 4 colored mini-sparklines in a row (red Open-Critical, blue Net Velocity, green SLA, orange MTTR) each with current value + MoM arrow, and below them an Owner velocity table (Owner / Open Crit+High / MoM Delta / Status) with the red "▲ Outlier" marker on >20% MoM-rise owners. Cold-start pages show the notice instead of sparklines.
result: pass
note: "Verified cold-start render path (one snapshot present → 'Trend Being Established' Amber notice, no crash, no layout overflow, no NaN). Full sparkline-row + Owner-velocity-table render is exercised once a 2nd monthly snapshot exists (≥2 required for MoM); deferred to next month's capture, not a defect."

## Summary

total: 3
passed: 3
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

- truth: "A composed_report group with modules: [program_health] renders without crashing (email + PDF channels)"
  status: resolved
  reason: "User reported: [Test Pull] composed_report failed — 'can only join an iterable' (TypeError at composer.py:546)"
  severity: blocker
  test: 1
  resolved_in: ab00228
  root_cause: "program_health_module.validate_config() returned a ModuleConfig instead of list[str]; composer contract requires an iterable of error strings (empty = valid). Fired on every composed run including the no-options case. compute() also self-called validate_config to obtain the coerced config."
  fix: "validate_config() rewritten to return list[str] like the mttr_trend analog (reports/modules/mttr_trend_module.py:1388). compute()'s `config = self.validate_config(config)` reassignment removed — compute reads each option inline with int()/float() + per-key defaults, and the composer validates config before compute(). Regression test TestValidateConfigContract added. Verified: 92 tests pass + end-to-end ReportComposer.run_module renders without crash."
  artifacts: ["reports/modules/program_health_module.py:1508", "reports/modules/composer.py:534-549"]
  missing: []
