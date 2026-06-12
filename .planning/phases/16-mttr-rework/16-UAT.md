---
status: partial
phase: 16-mttr-rework
source: [16-01-SUMMARY.md, 16-02-SUMMARY.md, 16-03-SUMMARY.md]
started: 2026-06-12T13:25:00Z
updated: 2026-06-12T15:52:00Z
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
  reason: "User reported: combining Severity and Owner in a single table is confusing, and the row count bleeds onto a second page. Audience split — exec leadership wants the Owner cut; lower/middle management scoped to a single owner wants the Severity cut."
  severity: minor
  test: 1
  needs_discussion: resolved   # design locked 2026-06-12, see decisions D-16-11 / D-16-12
  decision: |
    LOCKED DESIGN (gap-closure spec for /gsd-plan-phase 16 --gaps):

    Problem (confirmed in code):
    - reports/modules/mttr_trend_module.py builds ONE combined `table_data` list:
      severity rows appended at ~:574-592, Owner rows appended at ~:595-611. That
      single list feeds the PDF table (~:826), the Excel "MTTR Trend" tab (~:954),
      and the analyst tab "MTTR by Severity+Owner" (~:648). 4 severities + N owners
      under one "Severity / Owner" header → confusing + 2nd-page bleed.
    - Latent semantic bug: the shared "SLA Target" column uses per-severity SLA for
      severity rows but HARD-CODES Critical SLA (15) for Owner rows (~:605), so an
      Owner row's SLA Target is meaningless. Splitting tables fixes this.

    Decision D-16-11 — Configurable mttr_view with SPLIT tables:
    - Split the single combined breakdown into two independent tables/sections:
      a Severity table and an Owner table, each with its own header and an
      appropriate SLA basis (Owner table should NOT show the arbitrary Critical-SLA
      anchor as "SLA Target"; relabel or drop that column for the Owner cut).
    - Add module option `mttr_view ∈ {owner, severity, both}` read via
      config.options.get("mttr_view", "owner") — mirrors the existing
      config.options.get pattern already used for mttr_window_days / min_sample_size
      (~:313-314). Settable per group as module_options in delivery_config.yaml.
    - Apply the selected view consistently across PDF + Excel + email panel.
      Analyst-detail tab (CONTRACT-02) may retain full detail (both cuts) since it
      is drill-down, not a headline channel.

    Decision D-16-12 — Default when unset: mttr_view = "owner"
    - Single Owner table renders by default (exec headline; fits one page).
    - Groups wanting the severity cut set module_options.mttr_view: severity (or both).
    - Backward-compat note: any existing composed group already referencing mttr_trend
      will switch from combined→owner-only by default; acceptable per user (owner is
      the headline cut). Call this out in the SUMMARY.

    Out of scope: changing the MTTR math, window, MoM line, or board_summary
    (mttr_by_severity_module.py stays byte-unchanged, D-16-10).

    Tests required:
    - mttr_view=owner → only Owner table/rows render (no severity rows) in PDF/Excel/email.
    - mttr_view=severity → only Severity table renders.
    - mttr_view=both → both render as two distinct tables (not one concat).
    - default (unset) resolves to owner.
    - Owner table no longer emits the hard-coded Critical-SLA "SLA Target" value.
    - Single-cut output fits one PDF page for a representative owner/severity count.
    - board_summary zero-diff still green (D-16-10); existing mttr_trend baselines updated.
  artifacts:
    - reports/modules/mttr_trend_module.py
    - delivery_config.yaml
    - tests/test_mttr_trend_module.py
    - tests/baselines/mttr_trend_test_pull.json
  missing:
    - module_options.mttr_view selector + split Severity/Owner render across PDF/Excel/email
    - Owner-table SLA-basis fix (drop/relabel hard-coded Critical-SLA anchor)
    - tests for each mttr_view value + default + single-page fit
