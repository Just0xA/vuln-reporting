---
status: partial
phase: 17-program-health-overview
source: [17-VERIFICATION.md]
started: 2026-06-12T20:20:00-04:00
updated: 2026-06-12T20:20:00-04:00
---

## Current Test

[awaiting human testing]

## Tests

### 1. Email delivery rendering (Outlook / Gmail / Apple Mail)
expected: Configure a composed_report delivery group with `modules: [program_health]` and send to a test inbox. Email body contains 4 labeled tiles (Open Critical / Net Velocity / SLA Posture (Crit+High) / MTTR (30-day)) with MoM arrows, an Owner velocity table, and — if fewer than 2 monthly snapshots exist — a "Trend Being Established" cold-start notice instead of NaN values.
result: [pending]

### 2. Live sla_rate_crit_high snapshot capture
expected: Run `python scripts/capture_trend_snapshot.py` against a live or staging Tenable tenant. Snapshot JSON contains `"sla_rate_crit_high": <float 0–100>` (or `null` when zero Crit+High open), no `KeyError`; capture log shows the computed rate or the fail-soft "SLA-posture aggregate failed" WARNING.
result: [pending]

### 3. PDF render visual inspection (sparkline row + Owner table)
expected: Run a composed_report batch with program_health included and open the output PDF. Page shows 4 colored mini-sparklines in a row (red Open-Critical, blue Net Velocity, green SLA, orange MTTR) each with current value + MoM arrow, and below them an Owner velocity table (Owner / Open Crit+High / MoM Delta / Status) with the red "▲ Outlier" marker on >20% MoM-rise owners. Cold-start pages show the notice instead of sparklines.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
