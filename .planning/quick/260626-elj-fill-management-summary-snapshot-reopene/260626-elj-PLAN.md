---
phase: quick-260626-elj
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - reports/management_summary.py
  - tests/test_management_summary.py
autonomous: true
requirements: [REAUDIT-WARN-1]

must_haves:
  truths:
    - "management_summary trend snapshot persists a real reopened_count (not None) when vulns_df has REOPENED findings"
    - "management_summary trend snapshot persists a real sla_rate_crit_high (not None) when open Crit+High findings exist"
    - "The 7-module rendered report output (_MGMT_MODULE_CONFIGS) is unchanged — only the snapshot write changes"
    - "Strengthened regression test FAILS against pre-fix code and PASSES after the inline fix"
  artifacts:
    - path: "reports/management_summary.py"
      provides: "Inline reopened_count + sla_rate_crit_high computation in the snapshot-write block"
      contains: "compute_sla_rate_crit_high"
    - path: "tests/test_management_summary.py"
      provides: "Non-None value assertion for reopened_count and sla_rate_crit_high"
      contains: "sla_rate_crit_high"
  key_links:
    - from: "reports/management_summary.py snapshot block"
      to: "utils.sla_calculator.compute_sla_rate_crit_high"
      via: "inline import + call on open_findings_at(vulns_df, generated_at)"
      pattern: "compute_sla_rate_crit_high"
    - from: "reports/management_summary.py snapshot block"
      to: "vulns_df['state']"
      via: "REOPENED state count"
      pattern: "REOPENED"
---

<objective>
Fix REAUDIT-WARN-1: `reports/management_summary.py` forwards `reopened_count` and
`sla_rate_crit_high` to `capture_snapshot()` but both resolve to `None` on every
run, because they are sourced from modules (`reopened_vulns`, `program_health`)
that are NOT in `_MGMT_MODULE_CONFIGS`. The INT-WARN-1 regression test only checks
kwarg KEY presence, so it stays green over the nulls.

Compute both fields INLINE in the snapshot-write block directly from `vulns_df`,
mirroring the canonical cron writer (`scripts/capture_trend_snapshot.py`), so they
are independent of which modules are composed. Strengthen the regression test to
assert NON-None values.

Purpose: Restore correct trend-snapshot persistence for two SLA/reopened fields
without changing the audience-facing report (the 7-module structure must remain
byte-identical).
Output: Two surgical edits (one source, one test); both verified by tests + dry-run.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@./CLAUDE.md

<interfaces>
<!-- Canonical derivations to mirror. Use these directly — no exploration needed. -->

From scripts/capture_trend_snapshot.py (the cron writer — the source of truth):

  reopened_count derivation (L271-273):
    reopened_count = int(
        (df["state"].astype(str).str.upper() == "REOPENED").sum()
    )

  sla_rate_crit_high derivation (L387-407), fail-soft None on error:
    from config import SLA_DAYS                                  # noqa: PLC0415
    from utils.open_count import open_findings_at                # noqa: PLC0415
    from utils.sla_calculator import compute_sla_rate_crit_high  # noqa: PLC0415
    open_df = open_findings_at(df, snapshot_date)
    sla_rate_crit_high = compute_sla_rate_crit_high(open_df, snapshot_date, SLA_DAYS)
    # → None when no SLA-classifiable Crit+High rows; logger.warning + None on exception

From utils/sla_calculator.py:
    def compute_sla_rate_crit_high(open_df, report_date, sla_days) -> Optional[float]
    # returns pct 0–100 (1 decimal) or None; NaT first_found excluded both sides

From utils/open_count.py:
    open_findings_at(df, at_date) -> reopened-aware open findings DataFrame

Current management_summary.py imports (L40-70): does NOT import pandas, SLA_DAYS,
open_findings_at, or compute_sla_rate_crit_high. The snapshot block already has
locals `vulns_df`, `generated_at`, `tag_filter_label`, `fixed_vulns_df` in scope.
Follow the inline-import (`# noqa: PLC0415`) style the cron writer uses — do NOT
add module-level imports for these.
</interfaces>

@reports/management_summary.py
@tests/test_management_summary.py
</context>

<tasks>

<task type="auto">
  <name>Task 1: Replace dead _safe_metric lines with inline reopened_count + sla_rate_crit_high</name>
  <files>reports/management_summary.py</files>
  <action>
In the snapshot-write `try` block of `run_report()` (inside `if vulns_df is not None
and assets_df is not None:`), replace the two dead `_safe_metric(...)` sourcing lines
with inline computations mirroring the cron writer.

(1) Replace line ~492 — `_snap_reopened_count = _safe_metric("reopened_vulns", "reopened_count")`:
    Compute the REOPENED-state count directly from `vulns_df`, guarding for a missing
    "state" column (fail-soft → None). Mirror capture_trend_snapshot.py L271-273 exactly:
    when "state" is present, `int((vulns_df["state"].astype(str).str.upper() == "REOPENED").sum())`;
    when "state" column is absent, set `_snap_reopened_count = None`. Keep the `_snap_reopened_count`
    local name so the `capture_snapshot(... reopened_count=_snap_reopened_count ...)` call (L532)
    is unchanged.

    `vulns_df` is a pandas DataFrame already in scope; `pandas` is NOT imported at module
    level — the `.astype(str)`/`.sum()` chain needs no pandas symbol, so no import is required
    for reopened_count.

(2) Replace line ~522 — `_snap_sla_rate_crit_high = _safe_metric("program_health", "sla_rate_current")`:
    Compute inline with the shared Phase 19 D-05 helper, fail-soft None on error, mirroring
    capture_trend_snapshot.py L387-407. Use inline imports (`# noqa: PLC0415`):
    `from config import SLA_DAYS`, `from utils.open_count import open_findings_at`,
    `from utils.sla_calculator import compute_sla_rate_crit_high`. Then
    `open_df = open_findings_at(vulns_df, generated_at)` and
    `_snap_sla_rate_crit_high = compute_sla_rate_crit_high(open_df, generated_at, SLA_DAYS)`.
    Wrap in a local `try/except Exception` that logs a warning ("management_summary:
    sla_rate_crit_high inline compute failed — field will cold-start: %s") and sets
    `_snap_sla_rate_crit_high = None`, matching the cron writer's fail-soft style. Keep the
    `_snap_sla_rate_crit_high` local name so the `capture_snapshot(... sla_rate_crit_high=... )`
    call (L538) is unchanged.

Surgical only: do NOT modify `_MGMT_MODULE_CONFIGS` (the 7 modules), the `capture_snapshot(...)`
call signature, or any other `_safe_metric(...)` sourcing line. Do NOT add module-level imports.
Update the inline comment on each replaced line from the module name to the inline-compute
rationale (reference REAUDIT-WARN-1).
  </action>
  <verify>
    <automated>python -c "import ast; t=ast.parse(open('reports/management_summary.py',encoding='utf-8').read()); print('parse OK')"</automated>
  </verify>
  <done>
Both `_safe_metric("reopened_vulns", ...)` and `_safe_metric("program_health", ...)` lines are
gone; replaced by inline computations. `_MGMT_MODULE_CONFIGS` unchanged. File parses. The two
`capture_snapshot` kwargs still reference `_snap_reopened_count` / `_snap_sla_rate_crit_high`.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Strengthen INT-WARN-1 regression test to assert non-None values</name>
  <files>tests/test_management_summary.py</files>
  <behavior>
    - Reuse existing `_run_report_capture_snapshot_kwargs(monkeypatch, tmp_path)` — it already
      runs `run_report()` against the frozen parity fixture (which contains 1 REOPENED finding
      and 36 open Crit+High rows) and captures the kwargs forwarded to `capture_snapshot`.
    - New test `test_reopened_and_sla_rate_forwarded_non_none`:
        - `captured["reopened_count"]` is not None and equals 1 (fixture has exactly 1 REOPENED).
        - `captured["sla_rate_crit_high"]` is not None and is a float (fixture yields 27.8).
    - This test FAILS against pre-fix code (both forwarded as None) and PASSES post-Task-1.
    - Do NOT weaken or remove `test_management_summary_forwards_full_field_set` or
      `test_partial_write_regression_guard` (key-presence guards stay).
  </behavior>
  <action>
Add a new test function `test_reopened_and_sla_rate_forwarded_non_none(monkeypatch, tmp_path)`
near the existing INT-WARN-1 guards (after `test_partial_write_regression_guard`, ~L1105).
Reuse `_run_report_capture_snapshot_kwargs(monkeypatch, tmp_path)` to get the captured kwargs.
Assert:
  - `captured["reopened_count"] is not None` AND `captured["reopened_count"] == 1`
    (the frozen fixture `tests/fixtures/management_summary_parity/vulns_df.parquet` has exactly
    one REOPENED-state finding).
  - `captured["sla_rate_crit_high"] is not None` AND `isinstance(captured["sla_rate_crit_high"], float)`
    (the fixture's open Crit+High set yields a real rate, 27.8).
Give the test a docstring citing REAUDIT-WARN-1 and explaining it guards VALUE non-nullness, not
just key presence. Hardcode `== 1` for reopened_count (deterministic frozen fixture); for
sla_rate_crit_high assert `is not None` + float type rather than an exact value to avoid coupling
the test to the SLA-rate arithmetic. No new fixture is needed — the existing frozen parquet already
satisfies both conditions.
  </action>
  <verify>
    <automated>python -m pytest tests/test_management_summary.py::test_reopened_and_sla_rate_forwarded_non_none -x -q</automated>
  </verify>
  <done>
New test passes against the post-Task-1 code. (Pre-fix, the same test fails with reopened_count
and sla_rate_crit_high both None — confirm via the RED step below.)
  </done>
</task>

</tasks>

<verification>
Run these in order (foreground, main branch):

1. RED confirmation (run BEFORE Task 1, AFTER Task 2 — or `git stash` Task 1 to prove RED):
   `python -m pytest tests/test_management_summary.py::test_reopened_and_sla_rate_forwarded_non_none -x -q`
   MUST FAIL with reopened_count / sla_rate_crit_high being None.

2. GREEN (after Task 1 + Task 2):
   `python -m pytest tests/test_management_summary.py::test_reopened_and_sla_rate_forwarded_non_none -x -q`
   MUST PASS.

3. Full management_summary structural + golden-parity suite (output must NOT change):
   `python -m pytest tests/test_management_summary.py -q`
   All tests pass — including the existing INT-WARN-1 key-presence guards and the
   value-golden parity tests (the rendered 7-module report is unchanged).

4. Config validation across all 5 delivery groups:
   `python run_all.py --dry-run`
   Validates all groups with no errors.
</verification>

<success_criteria>
- `reopened_count` and `sla_rate_crit_high` are computed inline from `vulns_df` in the
  management_summary snapshot block, mirroring `scripts/capture_trend_snapshot.py`.
- Both fields persist as real (non-None) values when the data warrants; fail-soft None otherwise.
- `_MGMT_MODULE_CONFIGS` (the 7 rendered modules) is unchanged — report output is byte-identical.
- The strengthened regression test fails pre-fix and passes post-fix.
- Full `tests/test_management_summary.py` suite passes; `run_all.py --dry-run` validates 5 groups.
</success_criteria>

<output>
Create `.planning/quick/260626-elj-fill-management-summary-snapshot-reopene/260626-elj-SUMMARY.md` when done.
</output>
