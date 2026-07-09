---
status: passed
phase: 16-mttr-rework
source: [16-01-SUMMARY.md, 16-02-SUMMARY.md, 16-03-SUMMARY.md, 16-04-SUMMARY.md, 16-05-SUMMARY.md, 16-06-SUMMARY.md, 16-07-SUMMARY.md]
started: 2026-06-12T13:25:00Z
updated: 2026-06-26T12:00:00Z
paused_reason: "Resumed 2026-06-12 after gap closure D-16-11/D-16-12 (plans 16-04/16-05) implemented the mttr_view split tables + owner-default. Test 1 reset to re-test against the new design; render-channel expectations (tests 1-3) updated to match."
closed_reason: "All 4 re-test targets (tests 1,2,3,5) verified passed by operator against the Phase 19 fixed build (D-16-13 + sys.path bootstrap). Confirmed in 19-08-SUMMARY.md (approved 2026-06-26)."
---

## Current Test
<!-- OVERWRITE each test - shows where we are -->

[COMPLETE — all re-test targets passed against the Phase 19 fixed build (D-16-13 + capture_trend_snapshot sys.path fix). Verified operator-confirmed 2026-06-26 via 19-08 checkpoint.]
resume_at: none   # UAT closed — status: passed

## Tests

### 1. MTTR section renders in a composed-report PDF (D-16-13 gauge band + focus-driven table)
expected: A composed report including `mttr_trend` produces a "MTTR Trend (Reopened-Aware)" PDF page with a HEADLINE BAND of 4 per-severity MTTR gauges (Critical/High/Medium/Low, each vs its config.py SLA) each carrying a MoM direction indicator (▼ green = improving/faster, ▲ red = slipping/slower), fixed at the top of page 1. Below: a focus-driven detail table — Owner breakdown when the report is unfocused (all owners), Application breakdown when focused on a single Owner group, and NO table when focused to a single Application (gauges only). Plus a "Rolling 30-day MTTR …" disclosure line. No severity table (gauges replace it).
result: pass
note: "Verified against Phase 19 fixed build (D-16-13) 2026-06-26. 4-gauge severity band confirmed present in owner-default view (D-16-13). Operator confirmed via 19-08 checkpoint (19-08-SUMMARY.md)."
prior_result: "Round 1 issue (combined Severity+Owner table confusing + 2nd-page bleed) → resolved by D-16-11/12. Round 2 re-test surfaced this NEW issue: owner-default view had no gauge at all (per-severity gauges were gated to severity/both, no standalone overall gauge existed). Redesigned as D-16-13 (4-gauge band, all views, focus-driven table)."

### 2. Excel "MTTR Trend" tab with window disclosure (split, owner default)
expected: The same report's Excel file has an "MTTR Trend" tab. Row 1 discloses the window ("MTTR Trend — Rolling 30-day window"). With the default owner view, the tab shows an Owner section whose columns OMIT "SLA Target (Days)" (Owner rows have no SLA anchor). Columns: Owner, MTTR (Days), [no SLA Target], Status, Sample Size, MoM Delta. (mttr_view: both writes a Severity region and an Owner region separated by a blank row, not one concatenated table.)
result: pass
note: "Verified against Phase 19 fixed build 2026-06-26. Excel MTTR Trend tab confirmed: window disclosure present, no SLA Target column on Owner rows. Operator confirmed via 19-08 checkpoint."

### 3. Email panel renders with disclosure + sparse-data wording
expected: The rendered delivery email body (Outlook/Gmail-safe, inline CSS) shows an MTTR panel as a table with a footer disclosing the rolling window AND the active view (e.g. "by Owner"). Any Owner/severity below the 5-finding threshold reads "Insufficient data (N findings — minimum 5 required)" rather than a number.
result: pass
note: "Verified against Phase 19 fixed build 2026-06-26. Email MTTR panel renders confirmed. Operator confirmed via 19-08 checkpoint."

### 4. Reopened-aware MTTR — no reopen inflation (correctness lodestar)
expected: For a finding that was reopened (resurfaced after first-found, then later fixed), MTTR counts from the resurfaced date, not the original first-found. Reopened findings no longer inflate the average toward ~200 days; the overall mean reflects time-since-reopen. (Criterion-3: a finding found -200d, resurfaced -10d, fixed -2d contributes ~8 days, not 198.) If you can't isolate a reopened finding in live data, this is locked by the automated `TestCriterion3ReopenedClock` test — reply "skip".
result: skipped
reason: "Can't isolate a reopened finding in live data; relying on the automated TestCriterion3ReopenedClock test (re-confirmed passing, overall MTTR = 8.0d)."

### 5. Snapshot persistence — MTTR fields written, cold-start MoM
expected: Run `python scripts/capture_trend_snapshot.py` against your data. The newest entry in `data/trend/trend_severity_all_assets.json` now carries `mttr_overall_days`, `mttr_by_severity`, and `mttr_by_owner` (non-null when ≥5 durable fixes exist in the 30-day window). On the first-ever run the MoM trend cold-starts (single snapshot → trend shows "insufficient data", but the live per-severity gauges still render).
result: pass
note: "Verified against Phase 19 fixed build 2026-06-26. sys.path bootstrap added in Phase 19 Plan 16-06 (gap-closure D-16-13); live snapshot capture runs without ModuleNotFoundError and writes MTTR fields. Operator confirmed via 19-08 checkpoint."
prior_result: "ModuleNotFoundError: No module named 'config' — fixed in Phase 19 Plan 16-06 by adding sys.path root bootstrap to scripts/capture_trend_snapshot.py (matching pattern in sibling scripts)."

### 6. board_summary unchanged (D-16-10 regression)
expected: Run an existing board_summary delivery group (`python run_all.py --group "<board group>" --no-email`). The PDF and Excel render exactly as they did before Phase 16 — same page count, same MTTR-by-severity content, no new or missing sections. The Phase 16 work must not have altered board_summary output.
result: pass
note: "User confirmed unchanged (ran the 'Test Pull' group). Matches automated guards: mttr_by_severity_module.py byte-unchanged + 9/9 board_summary structural baselines green."

## Summary

total: 6
passed: 5
issues: 0
pending: 0
skipped: 1
closed: 2026-06-26

## Gaps

- truth: "MTTR Trend presents an audience-appropriate breakdown that fits on one page"
  status: resolved   # implemented (D-16-11/12 plans 16-04/16-05) + superseded by D-16-13 (plans 16-06/16-07) + live re-test passed 2026-06-26 (UAT Test 1 pass).
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

- truth: "The MTTR module's headline is a 4-gauge severity band (with MoM direction) that renders in every view, and the detail table follows the report's focus level"
  status: resolved   # D-16-13 implemented (plans 16-06/16-07) + live re-test passed 2026-06-26 (UAT Test 1 pass).
  reason: "UAT Test 1 round 2: the D-16-11/12 owner-default view rendered NO gauge graphic at all (the only gauges were per-severity, now gated to severity/both; no standalone overall gauge existed). User redesigned the presentation in discussion 2026-06-12."
  severity: major
  test: 1
  needs_discussion: resolved   # D-16-13 locked 2026-06-12, supersedes the D-16-11/12 table-toggle
  decision: |
    LOCKED DESIGN D-16-13 (gap-closure spec) — supersedes D-16-11 / D-16-12 table-toggle:

    HEADLINE BAND (renders in ALL views):
    - 4 per-severity MTTR gauges — Critical / High / Medium / Low — each drawn via the
      existing reports.modules.chart_utils.draw_gauge, each vs its own SLA read from
      config.py SLA_DAYS (NEVER hardcoded; per-install configurable — see memory
      project_sla_days_config_py_authoritative). Un-gate the per-severity gauge block
      currently at mttr_trend_module.py ~:799-852 (remove the `if mttr_view in
      ("severity","both")` guard) so it always renders.
    - Each gauge carries a Month-over-Month DIRECTION indicator from the existing MoM
      delta: ▼ GREEN when this-month MTTR < last-month (improving/faster), ▲ RED when
      it increased (slipping/slower), — when flat / no prior month. (MTTR: lower is
      better — get the arrow polarity right.)
    - Gauge scope follows the report's tag filter automatically: unfocused → averaged
      across ALL owners (exec 30,000-ft view); focused on one Owner group → averaged
      for that group. This is free — compute() already runs on the tag-filtered population.
    - Averaging is SAMPLE-WEIGHTED across all findings of that severity (NOT a mean of
      per-owner means — consistency with D-16-02).
    - Gauges fixed at top of page 1 so leadership always sees them even if the table flows.

    REMOVE the Severity table entirely (redundant with the gauges; ~:913-931 PDF block
    + Excel/email equivalents).

    FOCUS-DRIVEN DETAIL TABLE (replaces the mttr_view {owner,severity,both} toggle):
    - Unfocused (no single Owner= filter) → Owner table (MTTR by owner). Flows to page 2 freely.
    - Focused on a single Owner group (tag_category == "Owner" and tag_value set) →
      Application table (MTTR by application). The `application` column already exists —
      board_report_utils.extract_owner() produces both `owner` and `application` columns
      in one pass.
    - Focused to a single Application (or narrower) → NO table; gauges only.
    - Optional explicit override module option `mttr_table ∈ {auto, owner, application}`
      (default `auto` = focus-driven). RETIRE the `mttr_view` option from 16-04 (and its
      delivery_config.yaml docs + the 16-05 owner/severity/both tests).

    CHANNELS:
    - PDF + email panel render gauges as base64 images + the focus-driven table.
    - Excel cannot show gauge images inline → Excel keeps a compact 4-row severity
      numeric block (Severity | MTTR | SLA | Status | MoM Delta) standing in for the
      gauge band, followed by the focus-driven Owner/Application table.
    - Analyst-detail tab (CONTRACT-02) retains full detail (severity + owner + application).

    OUT OF SCOPE / DEFERRED: MTTR math, window, board_summary (mttr_by_severity_module.py
    byte-unchanged, D-16-10); a 5th "VPR: None" cohort/gauge → backlog (future milestone).
    DOC FIX: CLAUDE.md SLA table Medium 45→60 to match config.py.

    Tests required:
    - 4 severity gauges present in PDF/email for owner (unfocused), application (focused),
      and gauges-only (single-application) cases.
    - MoM arrow polarity: MTTR decrease → ▼ green; increase → ▲ red; flat/no-prior → —.
    - Focus routing: unfocused → Owner table; Owner-focused → Application table;
      Application-focused → no table.
    - Severity table no longer emitted in any channel; mttr_view option removed.
    - Excel severity numeric block + focus-driven table; SLA values come from config.py SLA_DAYS.
    - board_summary zero-diff still green (D-16-10); mttr_trend baselines regenerated.
  artifacts:
    - reports/modules/mttr_trend_module.py
    - reports/modules/board_report_utils.py   # extract_owner already yields `application`
    - delivery_config.yaml
    - tests/test_mttr_trend_module.py
    - tests/baselines/mttr_trend_test_pull.json
    - CLAUDE.md   # Medium SLA doc fix 45→60
  missing:
    - 4-gauge headline band in all views + MoM direction arrows
    - remove severity table; retire mttr_view; add focus-driven Owner/Application table (+ gauges-only at app depth)
    - Excel severity numeric block; tests + baseline regen

- truth: "The scheduled command `python scripts/capture_trend_snapshot.py` runs without error and writes the snapshot (incl. MTTR fields)"
  status: resolved   # sys.path bootstrap added in Phase 19 plan 16-06 (gap-closure D-16-13); live re-test passed 2026-06-26 (UAT Test 5 pass).
  reason: "UAT Test 5: ModuleNotFoundError: No module named 'config' at scripts/capture_trend_snapshot.py:33. The documented/scheduled invocation `python scripts/capture_trend_snapshot.py` fails because the script has no sys.path bootstrap — running it puts scripts/ on sys.path, not the repo root, so root-level `config`/`data`/`tenable_client` imports fail. Without this, the forward-accumulating MTTR trend never populates in production (cannot be backfilled past Tenable's ~29-day fixed-finding retention)."
  severity: blocker
  test: 5
  decision: |
    FIX (no design choice — mechanical): add a project-root sys.path bootstrap at the
    top of scripts/capture_trend_snapshot.py BEFORE the first-party imports, matching the
    pattern already in scripts/smoke_board_summary_cutover.py / scripts/smoke_email_phase2.py
    (insert `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))`). Keep it
    minimal and consistent with the sibling scripts.
    Add a real-invocation regression check so this can't regress under the import-from-root
    probe again — e.g. a test that runs the script as a subprocess with `--dry-run` from a
    NON-root CWD (or asserts it imports cleanly when scripts/ is the only path entry).
    Audit the other scripts/*.py for the same missing-bootstrap footgun while in here.
  artifacts:
    - scripts/capture_trend_snapshot.py
    - tests/   # real-invocation (subprocess --dry-run) regression test
  missing:
    - sys.path root bootstrap so `python scripts/capture_trend_snapshot.py` runs as documented
    - regression test that exercises the real CLI invocation (not just import-from-root)
