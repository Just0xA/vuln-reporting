---
status: partial
phase: 16-mttr-rework
source: [16-01-SUMMARY.md, 16-02-SUMMARY.md, 16-03-SUMMARY.md]
started: 2026-06-12T13:25:00Z
updated: 2026-06-12T13:33:00Z
paused_reason: "Test 1 surfaced an MTTR table design issue flagged for discussion; UAT paused to lock the design before continuing tests 2-6."
---

## Current Test
<!-- OVERWRITE each test - shows where we are -->

[paused after test 1 — design discussion pending before resuming test 2]
resume_at: 2

## Tests

### 1. MTTR section renders in a composed-report PDF
expected: A composed report including `mttr_trend` produces a "MTTR Trend (Reopened-Aware)" PDF page: overall MTTR gauge vs Critical SLA, per-severity gauges, Owner breakdown table, MoM line (or cold-start notice), and a "Rolling 30-day MTTR …" disclosure line.
result: issue
reported: "Having both Severity and Owner in the same table is confusing. The number of rows also makes the data bleed over to a second page. For something aimed at executive leadership the table by owner works, but for something aimed at lower or middle management that the scope would only be at the owner the severity works. This may need a discussion."
severity: minor
needs_discussion: true

### 2. Excel "MTTR Trend" tab with window disclosure
expected: The same report's Excel file has an "MTTR Trend" tab. Row 1 discloses the window ("MTTR Trend — Rolling 30-day window"), and columns appear in order: Severity/Owner, MTTR (Days), SLA Target, Variance, Status, Sample Size, MoM Delta.
result: [pending]

### 3. Email panel renders with disclosure + sparse-data wording
expected: The rendered delivery email body (Outlook/Gmail-safe, inline CSS) shows an MTTR panel as a table with a footer disclosing the rolling window. Any severity/Owner below the 5-finding threshold reads "Insufficient data (N findings — minimum 5 required)" rather than a number.
result: [pending]

### 4. Reopened-aware MTTR — no reopen inflation (correctness lodestar)
expected: For a finding that was reopened (resurfaced after first-found, then later fixed), MTTR counts from the resurfaced date, not the original first-found. Reopened findings no longer inflate the average toward ~200 days; the overall mean reflects time-since-reopen. (Criterion-3: a finding found -200d, resurfaced -10d, fixed -2d contributes ~8 days, not 198.) If you can't isolate a reopened finding in live data, this is locked by the automated `TestCriterion3ReopenedClock` test — reply "skip".
result: [pending]

### 5. Snapshot persistence — MTTR fields written, cold-start MoM
expected: Run `python scripts/capture_trend_snapshot.py` against your data. The newest entry in `data/trend/trend_severity_all_assets.json` now carries `mttr_overall_days`, `mttr_by_severity`, and `mttr_by_owner` (non-null when ≥5 durable fixes exist in the 30-day window). On the first-ever run the MoM trend cold-starts (single snapshot → trend shows "insufficient data", but the live per-severity gauges still render).
result: [pending]

### 6. board_summary unchanged (D-16-10 regression)
expected: Run an existing board_summary delivery group (`python run_all.py --group "<board group>" --no-email`). The PDF and Excel render exactly as they did before Phase 16 — same page count, same MTTR-by-severity content, no new or missing sections. The Phase 16 work must not have altered board_summary output.
result: [pending]

## Summary

total: 6
passed: 0
issues: 1
pending: 5
skipped: 0

## Gaps

- truth: "MTTR Trend presents an audience-appropriate breakdown that fits on one page"
  status: failed
  reason: "User reported: combining Severity and Owner in a single table is confusing, and the row count bleeds onto a second page. Audience split — exec leadership wants the Owner cut; lower/middle management scoped to a single owner wants the Severity cut. Flagged as needing a design discussion before a fix is planned."
  severity: minor
  test: 1
  needs_discussion: true
  artifacts: []
  missing: []
