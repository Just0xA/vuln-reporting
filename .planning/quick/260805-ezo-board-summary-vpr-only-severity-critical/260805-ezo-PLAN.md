---
phase: quick-260805-ezo
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - reports/modules/board_report_utils.py
  - reports/modules/__init__.py
  - reports/modules/high_risk_assets_module.py
  - reports/modules/aged_vulns_assets_module.py
  - reports/modules/critical_remediation_sla_module.py
  - tests/test_board_report_utils.py
  - tests/test_kpi_risk_managed_exclusion.py
  - tests/test_consumer_audit.py
  - scripts/sanity_vpr_severity_cache.py
  - docs/board_summary_calculations.md
autonomous: true
requirements: [QUICK-260805-ezo]

must_haves:
  truths:
    - "vpr_severity_tier() maps VPR score to critical/high/medium/low/none with None/NaN/0.0/unparseable -> 'none'"
    - "add_vpr_severity() returns a new frame via .assign() and tolerates empty frames and a missing vpr_score column"
    - "high_risk_assets, aged_vulns_assets, and critical_remediation_sla tier findings from vpr_severity, never from severity"
    - "config.vpr_to_severity() and data/fetchers.py are byte-unchanged; every non-board module still reads severity"
    - "critical_remediation_sla applies exclude_risk_managed to BOTH the open and the fixed population"
    - "days_to_fix is computed from COALESCE(resurfaced_date, first_found) with no time_taken_to_fix preference"
    - "sla_pct = compliant / (compliant + breached) * 100 where breached = fixed_late + open_past_due; open_not_due is excluded from the denominator"
    - "The FIXED population carries no asset-level on-time gate; the OPEN population carries both the asset-level on-time gate and a finding-level last_found >= report_date - 30d guard"
    - "Excel, PDF, and the email driver narrative disclose all four components plus Total Critical Open"
    - "render_analyst_tabs emits a second tab 'VPR Severity Distribution' with critical/high/medium/low/none rows plus TOTAL"
    - "Green 95 / amber 85 thresholds are unchanged"
    - "No definition-change footnote/disclaimer appears in any rendered channel"
  artifacts:
    - path: "reports/modules/board_report_utils.py"
      provides: "VPR_NONE_LABEL, vpr_severity_tier(), add_vpr_severity()"
      contains: "def add_vpr_severity"
    - path: "reports/modules/critical_remediation_sla_module.py"
      provides: "Reformulated four-component Critical Remediation SLA metric"
      contains: "open_past_due"
    - path: "scripts/sanity_vpr_severity_cache.py"
      provides: "Cache-backed (no live pull) verification of the VPR tiering + open-side populations"
      contains: "argparse"
    - path: "tests/test_board_report_utils.py"
      provides: "Unit tests for vpr_severity_tier / add_vpr_severity"
      contains: "vpr_severity_tier"
  key_links:
    - from: "reports/modules/critical_remediation_sla_module.py"
      to: "reports/modules/board_report_utils.py"
      via: "add_vpr_severity + exclude_risk_managed at compute() entry"
      pattern: "add_vpr_severity"
    - from: "reports/modules/high_risk_assets_module.py"
      to: "vpr_severity column"
      via: "severity_mask built from vpr_severity"
      pattern: "vpr_severity"
    - from: "reports/modules/aged_vulns_assets_module.py"
      to: "vpr_severity column"
      via: "severity_mask + worst_severity aggregation"
      pattern: "vpr_severity"
---

<objective>
Fix the three definitional divergences plus one latent clock bug that made board_summary's
Critical Remediation SLA report 61.6% against an operator console reading of ~74%.

Three parts, all contained to the board modules:

1. **VPR-only severity** — a board-local `vpr_severity` column (no `config.vpr_to_severity()`
   / `data/fetchers.py` edits, no change to the Tenable export severity filter). VPR "none"
   is a distinct concept from native-CVSS "info" and must not be conflated with it.
2. **Critical Remediation SLA reformulation** — reopened-aware clock, risk-managed exclusion
   on both populations, finding-level staleness guard on the open side, asset-level gate
   removed from the fixed side, and a denominator that counts `compliant + breached` while
   excluding findings whose 15-day clock has not yet expired.
3. **Four-component disclosure + a VPR-distribution analyst tab.**

Purpose: the board metric must mean what the console means, and the analyst workbook must
show where findings went under the new definition.
Output: modified board modules + shared helper, a cache-backed sanity script, updated unit
tests, and a rewritten `docs/board_summary_calculations.md` section 7.
</objective>

<execution_context>
@/home/jmonroe/.claude/plugins/cache/gsd-plugin/gsd/4.0.2/workflows/execute-plan.md
@/home/jmonroe/.claude/plugins/cache/gsd-plugin/gsd/4.0.2/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@reports/modules/board_report_utils.py
@reports/modules/critical_remediation_sla_module.py
@docs/board_summary_calculations.md

Reference implementation for the reopened-aware clock (mirror its shape):
`reports/modules/mttr_trend_module.py:420-450` — D-16-02. `pd.to_datetime(..., utc=True,
errors="coerce")` on all three date columns (defensive against a missing column via a NaT
object Series), `resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)` for the
COALESCE, `.dt.days.clip(lower=0)`, then `.assign(days_to_fix=...)`.
Rationale record: `.planning/milestones/v1.4-phases/16-mttr-rework/16-02-SUMMARY.md`.

<interfaces>
<!-- Extracted from the codebase. Use directly — no exploration needed. -->

reports/modules/board_report_utils.py (existing exports):
```python
OWNER_TAG_CATEGORY: str = "Owner"
ON_TIME_WINDOW_DAYS: int = 30
def deduplicate_assets_by_name(assets_df) -> pd.DataFrame
def identify_on_time_assets(assets_df, report_date, window_days=30) -> tuple[pd.DataFrame, pd.DataFrame]
def extract_owner(assets_df, tag_column_name="tags", unassigned_label="Unassigned") -> pd.DataFrame
def exclude_risk_managed(df) -> pd.DataFrame            # drops ACCEPTED/RECASTED
def compute_per_bu_breakdown(df, numerator_mask, denominator_mask, bu_column="owner", higher_is_better=True) -> pd.DataFrame
    # returns columns: owner, numerator, denominator, percentage, affected
def compute_bu_risk_scores(vulns_df, qualifying_uuids, enriched, severities, weights) -> pd.Series
def sla_status_from_thresholds(value, green_threshold, yellow_threshold, direction="higher_is_better") -> str
```

Columns present on both `vulns_df` and `fixed_vulns_df` (verified against
`data/cache/2026-07-01/vulns_all.parquet`, 28 columns):
`asset_uuid, hostname, ipv4, mac_address, operating_system, plugin_id, plugin_name,
plugin_family, vpr_score, severity, severity_native, severity_level, cve_list, cpe,
cvss_base_score, cvss3_score, exploit_available, exploit_code_maturity, first_found,
last_found, last_fixed, state, finding_id, severity_modification_type, recast_rule_uuid,
recast_reason, resurfaced_date, time_taken_to_fix`

Current severity-tiering call sites (the complete set — nothing else in the five board
modules tiers findings):
```
reports/modules/high_risk_assets_module.py:1031   vulns_df["severity"].str.lower().isin(["critical", "high"])
reports/modules/aged_vulns_assets_module.py:1052  vulns_df["severity"].str.lower().isin(_AGED_SEVERITIES)
reports/modules/aged_vulns_assets_module.py:323   worst_severity = ("severity", lambda s: _worst_severity(set(s)))
reports/modules/critical_remediation_sla_module.py:1002  df["severity"].str.lower() == "critical"
reports/modules/board_report_utils.py:516-524     compute_bu_risk_scores severity mask + weight map
```
`scan_coverage_sla_module.py` contains no `severity` reference at all (assets-only) and
`accepted_recast_module.py` only touches `severity_modification_type` /
`original_severity` / `new_severity` (recast-rule fields, not finding tiers). **Neither
gets changed** — recording this so the executor does not invent edits there.
</interfaces>

<locked_decisions>
Every item below is LOCKED by the operator. Do not revisit, do not offer alternatives.

- **D-01** Do not touch `config.vpr_to_severity()` or `data/fetchers.py`. The
  `severity=[critical,high,medium,low]` export filter stays as-is.
- **D-02** VPR "none" is NOT "info". Never conflate them.
- **D-03** Only board modules read `vpr_severity`; every other report keeps reading
  `severity`.
- **D-04** Cohort = `vpr_severity == "critical"` AND not risk-managed, applied to BOTH the
  open and the fixed population.
- **D-05** Clock = `COALESCE(resurfaced_date, first_found)`; `time_taken_to_fix` preference
  is DROPPED entirely.
- **D-06** Open-side staleness guard is FINDING-level (`last_found >= rd - 30d`); the
  asset-level on-time gate is REMOVED from the FIXED side and KEPT on the OPEN side.
- **D-07** `sla_pct = compliant / (compliant + breached) * 100`; `open_not_due` is excluded
  from the denominator.
- **D-08** Thresholds stay 95 green / 85 amber. The metric is EXPECTED to go red. Do not
  "fix" that, do not recalibrate.
- **D-09** NO definition-change footnote, disclaimer, or "methodology changed" note in the
  PDF, Excel, or email. The operator communicates that separately.
- **D-10** The VPR distribution is an analyst-workbook TAB only — not a PDF page, not a new
  module, no change to `_BOARD_MODULE_CONFIGS`.
</locked_decisions>

<plan_decisions>
Two items the operator delegated ("check whether anything else reads that key … keep the
ModuleData.metrics contract coherent"). Resolved here so the executor does not have to
decide mid-task:

- **QT-01 — `total_open_last_month` is removed, not renamed.** A repo-wide grep for
  `total_open_last_month` finds only (a) the module's own `render_pdf_section` /
  `render_excel_tabs` / `_build_summary` / `get_audit_info`, and (b) one comment in
  `tests/test_consumer_audit.py:234`. No composer, `board_pdf_layout`, trend-snapshot,
  baseline JSON, or delivery-config consumer reads it. The new `metrics` contract is:

  ```
  remediation_sla_pct   float | None
  compliant             int      # A where days_to_fix <= 15
  fixed_late            int      # A where days_to_fix > 15
  open_past_due         int      # B
  open_not_due          int      # C  (excluded from denominator)
  breached              int      # fixed_late + open_past_due
  denominator           int      # compliant + breached
  total_critical_open   int      # |B| + |C|
  status                str
  ```
  `total_open_last_month`, `total_fixed_last_month`, and `fixed_within_sla` are removed.
  `remediation_sla_pct` and `status` keep their names (external readers:
  `tests/baseline_extractor`, `tests/test_phase2_composer_pipeline`,
  `scripts/smoke_email_phase2.py`).

- **QT-02 — NaT clock_start on an open finding counts as `open_not_due` (C).** Zero
  occurrences in the 2026-07-01 cache, but the rule must be explicit: a finding whose
  overdue-ness cannot be computed is not counted as a failure, and it still appears in
  Total Critical Open so `|B| + |C|` equals the in-window critical-open count.
</plan_decisions>

<known_consequence>
`aged_vulns_assets` is ALSO composed by `management_summary` (Metric 5) and is available to
any `composed_report` group. Switching it to `vpr_severity` therefore shifts
`management_summary` numbers too — exactly as the 2026-07-22 `exclude_risk_managed` rollout
did. This is an unavoidable consequence of the locked "switch the five board modules"
decision, not a new decision. `high_risk_assets` and `critical_remediation_sla` are
board-only. Record this in the SUMMARY for the operator; do NOT try to scope the change to
board_summary by branching on the calling report.
</known_consequence>

<reference_values>
Measured from `data/cache/2026-07-01/` (36,358 on-time assets) at
`report_date = 2026-07-01T00:00:00Z`. These are the sanity script's expected values:

| Quantity | Value |
|----------|-------|
| on-time assets | 36,358 |
| open findings, on-time, risk-managed excluded | 166,392 |
| vpr_severity critical | 5,723 |
| vpr_severity high | 12,423 |
| vpr_severity medium | 57,196 |
| vpr_severity low | 47,622 |
| vpr_severity none | 43,428 |
| critical open in 30d finding window | 5,723 |
| open_past_due (B) | 3,210 |
| open_not_due (C) | 2,513 |

Also for the record: the naive `first_found`-only clock yields 3,229 past-due vs the
reopened-aware 3,210 — 19 findings the old clock wrongly called overdue.

Definitional impact of VPR-only on the other two board metrics (definitional, NOT
remediation improvement): Metric 3 High-Risk Assets 0.20% -> 0.09%; Metric 4 Aged Vuln
Assets 34.06% -> 7.18%.

There is NO fixed-vulns parquet in cache (`data/cache/2026-07-01/` holds only
`vulns_all.parquet` + `assets_all.parquet`, states OPEN/REOPENED only). The FIXED half of
the metric CANNOT be verified against real data — it is covered by synthetic unit fixtures
only. Hard Rule 1: do not attempt to fetch it.
</reference_values>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: VPR-only severity helper + switch the board severity consumers</name>
  <files>
    reports/modules/board_report_utils.py,
    reports/modules/__init__.py,
    reports/modules/high_risk_assets_module.py,
    reports/modules/aged_vulns_assets_module.py,
    tests/test_board_report_utils.py
  </files>
  <behavior>
    vpr_severity_tier:
    - 9.0 / 9.5 / 10.0 -> "critical"; 8.9 boundary -> "high"; 7.0 -> "high"
    - 6.9 -> "medium"; 4.0 -> "medium"; 3.9 -> "low"; 0.1 -> "low"
    - 0.0 -> "none"; None -> "none"; float("nan") -> "none"; "" -> "none";
      "abc" -> "none"; negative -> "none"
    - numeric strings parse ("9.5" -> "critical") — parquet round-trips can yield object dtype
    add_vpr_severity:
    - frame WITH vpr_score -> new frame with a vpr_severity column, input frame unmodified
      (no vpr_severity column appears on the caller's frame)
    - frame WITHOUT vpr_score -> every row "none", no exception
    - empty frame -> empty frame that still carries the vpr_severity column
    - calling it on a filtered/sliced frame emits no ChainedAssignmentError / CoW warning
    high_risk_assets / aged_vulns_assets:
    - a finding with severity="critical" but vpr_score=None is NOT counted (was counted before)
    - a finding with severity="medium" but vpr_score=9.5 IS counted as critical
  </behavior>
  <action>
Add to `reports/modules/board_report_utils.py`, in a new "VPR severity tiering" section
placed after `exclude_risk_managed` (keep the module docstring's "Shared utilities" bullet
list in sync — it is the file's index):

- `VPR_NONE_LABEL: str = "none"` module constant.
- `vpr_severity_tier(score) -> str` — >=9.0 critical, >=7.0 high, >=4.0 medium, >=0.1 low,
  else `VPR_NONE_LABEL`. Coerce via `float(score)` inside a try/except
  `(TypeError, ValueError)`; `None`, NaN, 0.0, negative, and unparseable all return
  `VPR_NONE_LABEL`. NumPy-style docstring with the boundary table, per project convention.
- `add_vpr_severity(df) -> pd.DataFrame` — returns `df.assign(vpr_severity=...)` per
  Hard Rule 5 (`.assign()` ONLY; never `df["col"] = ...` after a filter/slice). Empty frame:
  return a frame that still has the `vpr_severity` column (assign a same-length empty
  Series so dtype/columns stay stable). Missing `vpr_score` column: log a `logger.warning`
  (mirror `extract_owner`'s fail-soft warning style) and assign `VPR_NONE_LABEL` to every
  row. Prefer a vectorised `pd.to_numeric(df["vpr_score"], errors="coerce")` +
  `pd.cut`/boolean-mask construction over `.map(vpr_severity_tier)` if it stays readable;
  either is acceptable as long as the tier boundaries match `vpr_severity_tier` exactly —
  if you vectorise, the unit tests must assert the two paths agree.

Re-export `vpr_severity_tier`, `add_vpr_severity`, and `VPR_NONE_LABEL` from
`reports/modules/__init__.py` alongside the existing `populate_rag_strip, exclude_risk_managed`
board-helper re-export block.

Switch the severity consumers (D-03 — board modules only):

- `high_risk_assets_module.py`: call `add_vpr_severity(...)` on `vulns_df` at the top of
  `compute()` immediately after the existing `exclude_risk_managed(vulns_df)` call
  (line ~182), and change `_find_high_risk_assets`'s `required` set to
  `{"asset_uuid", "vpr_severity", "first_found"}` and its `severity_mask` (line 1031) to
  read `vulns_df["vpr_severity"]`. Update the two `get_audit_info()` strings at lines
  ~946-948 and the `"severity_scope"` metadata at line ~1062 to say the tier comes from
  the board-local VPR-only tiering (`vpr_severity_tier`), with NO native-CVSS fallback.
- `aged_vulns_assets_module.py`: same pattern — `add_vpr_severity` after the existing
  `exclude_risk_managed` (line ~179); `required` set and `severity_mask` (line 1052) read
  `vpr_severity`; the `worst_severity` groupby aggregation (line ~323) aggregates
  `"vpr_severity"` instead of `"severity"` (the output column name stays `worst_severity` —
  it is a rendered column header); audit strings at ~941-942 and `"severity_scope"` at
  ~1082 updated the same way.
- `board_report_utils.compute_bu_risk_scores`: this helper is called ONLY by those two
  board modules (verified by grep). Switch its severity mask and weight map (lines 516-524)
  to read `vpr_severity`, with a defensive `add_vpr_severity(vulns_df)` call at entry so it
  works regardless of caller ordering. Update its docstring and the `severities` parameter
  description accordingly.

Comment every changed site with `quick-260805-ezo` following the module's existing
decision-ID comment convention (WR-xx / D-xx / T-xx / CR-xx).

Do NOT touch `scan_coverage_sla_module.py` or `accepted_recast_module.py` — neither tiers
findings (see the `<interfaces>` block). Do NOT touch `config.py` or `data/fetchers.py`
(D-01). Do NOT touch any non-board module (`tech_debt_by_owner`, `total_vulns_by_severity`,
`patch_compliance_rate`, `mttr_*`, `program_health`, `external_dmz`, `tag_severity_share`)
— they keep reading `severity` (D-03).

Extend `tests/test_board_report_utils.py` with the behaviors above (synthetic data only,
Hard Rule 2). Include an explicit CoW regression test: filter a frame, call
`add_vpr_severity` on the slice under `warnings.catch_warnings(record=True)`, and assert no
`ChainedAssignmentError`/`FutureWarning` originating from `reports/` (mirror the existing
Phase 16-03 CoW fixture-isolation pattern already used in this suite).
  </action>
  <verify>
    <automated>.venv/bin/python -m pytest tests/test_board_report_utils.py tests/test_kpi_risk_managed_exclusion.py -q -p no:cacheprovider 2>&1 | tail -20</automated>
    <automated>grep -rn 'vpr_to_severity' reports/modules/board_report_utils.py reports/modules/high_risk_assets_module.py reports/modules/aged_vulns_assets_module.py; git diff --stat -- config.py data/fetchers.py | grep -q . && echo "FAIL: D-01 violated" || echo "OK: config.py + fetchers.py untouched"</automated>
    <automated>grep -c 'vpr_severity' reports/modules/high_risk_assets_module.py reports/modules/aged_vulns_assets_module.py</automated>
  </verify>
  <done>
    `vpr_severity_tier` / `add_vpr_severity` / `VPR_NONE_LABEL` exist in
    `board_report_utils.py` and are re-exported from `reports.modules`; the three board
    tiering sites (high_risk, aged_vulns, compute_bu_risk_scores) read `vpr_severity`;
    `config.py` and `data/fetchers.py` show zero diff; new unit tests green.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Reformulate critical_remediation_sla compute() — cohort, clock, four populations, analyst tabs</name>
  <files>
    reports/modules/critical_remediation_sla_module.py,
    tests/test_kpi_risk_managed_exclusion.py,
    tests/test_consumer_audit.py
  </files>
  <behavior>
    Cohort + scoping:
    - a fixed critical finding on an asset whose last_licensed_scan_date is 200 days old
      IS counted (asset-level gate removed from the fixed side, D-06)
    - an open critical finding whose last_found is 45 days old is NOT counted in B or C
      (finding-level staleness guard, D-06)
    - an open critical finding on a not-on-time asset is NOT counted (asset gate kept on
      the open side)
    - a finding with severity_modification_type=ACCEPTED is excluded from BOTH populations
    - a finding with severity="critical" but vpr_score=6.0 is NOT in the cohort
    Clock (D-05):
    - fixed finding first_found=D-100, resurfaced_date=D-10, last_fixed=D-2
      -> days_to_fix = 8 (compliant), NOT 98
    - time_taken_to_fix is present and contradicts the date math -> date math wins
    - last_fixed < clock_start -> days_to_fix clipped to 0 (compliant)
    Metric (D-07):
    - A = 10 fixed (7 within 15d, 3 late), B = 5 open past due, C = 40 not yet due
      -> compliant=7, fixed_late=3, breached=8, denominator=15, sla_pct=46.7,
         total_critical_open=45, status="red"
    - compliant + breached == 0 -> sla_pct is None and status == "no_data"
      (even when C > 0)
    Analyst tabs:
    - returns 2 tabs when missed-SLA rows exist, 1 tab ("VPR Severity Distribution") when
      they do not, [] on data.error
    - the distribution tab has exactly 6 rows: critical/high/medium/low/none + TOTAL, and
      TOTAL equals the sum of the five
  </behavior>
  <action>
Rewrite `compute()` in `reports/modules/critical_remediation_sla_module.py`. Keep the
existing empty-input guard, the `_empty_result` error path, and the `email_gauge_b64`
metadata contract exactly as they are.

**Cohort (D-04):** at compute() entry apply `exclude_risk_managed()` to BOTH `vulns_df` and
`fixed_vulns_df` (today it is fixed-only at line ~194 — inconsistent with
`high_risk_assets_module.py:182` and `aged_vulns_assets_module.py:179`), then
`add_vpr_severity()` to both. Replace `_filter_critical(df, on_time_uuids)` with two
helpers so the two sides can differ:
- `_filter_critical_vpr(df)` — `vpr_severity == "critical"` only, no asset gate. Used by
  the FIXED side.
- the OPEN side additionally applies `asset_uuid.isin(on_time_uuids)`.
Both must keep the current empty-frame / missing-column fail-soft returns.

**Clock (D-05):** delete `_compute_days_to_fix()` entirely (the `time_taken_to_fix`
preference is the bug — it inflates duration across a reopen). Add
`_compute_clock_start(df) -> pd.Series` returning `COALESCE(resurfaced_date, first_found)`
and use it for both sides. Mirror `mttr_trend_module.py:420-450` exactly:
`pd.to_datetime(..., utc=True, errors="coerce")` on each column (falling back to a NaT
object Series when the column is absent), `.where(notna(), other=...)` for the COALESCE,
then `days_to_fix = (last_fixed_ts - clock_start_ts).dt.days.clip(lower=0)` applied with
`.assign()` (Hard Rule 5 — the current code does
`fixed_in_window.loc[:, "days_to_fix"] = ...apply(axis=1)`; that goes away). Cite
`D-16-02` and `quick-260805-ezo` in the comment: both modules ship in the same PDF and must
share one clock.

**Populations** (`rd` = report_date as a UTC-aware `pd.Timestamp`, reusing the existing
tz-coercion block):
```
A  fixed_in_window : state == FIXED AND last_fixed >= rd - 30d
B  open_past_due   : state in (OPEN, REOPENED) AND last_found >= rd - 30d
                     AND asset on-time AND (rd - clock_start).days > 15
C  open_not_due    : state in (OPEN, REOPENED) AND last_found >= rd - 30d
                     AND asset on-time AND (rd - clock_start).days <= 15
```
QT-02: a NaT `clock_start` on an open finding falls into C.

**Metric (D-07/D-08):**
```
compliant  = |A where days_to_fix <= 15|
fixed_late = |A where days_to_fix > 15|
breached   = fixed_late + |B|
denominator = compliant + breached
sla_pct    = round(compliant / denominator * 100, 1)   # None when denominator == 0
total_critical_open = |B| + |C|
```
`denominator == 0` -> `sla_pct = None`, `status = "no_data"` via the existing no_data path.
Thresholds stay `_GREEN_THRESHOLD = 95.0` / `_YELLOW_THRESHOLD = 85.0` (D-08) — do not
touch those constants or `_GAUGE_THRESHOLDS`.

**metrics dict:** emit exactly the QT-01 contract (`remediation_sla_pct`, `compliant`,
`fixed_late`, `open_past_due`, `open_not_due`, `breached`, `denominator`,
`total_critical_open`, `status`). Remove `total_open_last_month`,
`total_fixed_last_month`, and `fixed_within_sla`. Use `safe_int` / `safe_pct` for anything
possibly-None (Hard Rule 6) — no inline f-string format specs on possibly-None values.

**Per-owner breakdown:** `_compute_bu_breakdown` now takes the union of A and B rather than
A alone. Build one combined frame carrying four boolean component flags
(`is_compliant`, `is_fixed_late`, `is_open_past_due`, `is_open_not_due`), map owner from
`extract_owner(assets_df)` (the FULL asset frame, not just on-time — the fixed side no
longer has an asset gate) with `.fillna("Unassigned")`, then call the existing
`compute_per_bu_breakdown(fw, numerator_mask=is_compliant,
denominator_mask=(is_compliant | is_fixed_late | is_open_past_due), higher_is_better=True)`
and merge per-owner sums of the four component flags onto the result. Keep the CR-01
mask-reindex defensiveness that is already in that helper. Rows in C contribute their
component count but must NOT enter the denominator mask. `table_data` = the merged frame's
records; `chart_data["top_5"]` = its head(5).

**Driver narrative (Item 3, verbatim template):**
```
"{compliant} of {denominator} criticals met the 15-day SLA; {fixed_late} fixed late,
 {open_past_due} still overdue, {open_not_due} not yet due."
```
(one line, `safe_int()` on every count). Empty/no-data path keeps `NO_DATA_DRIVER`.

**Analyst tabs (Item 4, D-10):** `render_analyst_tabs()` already returns
`list(data.analyst_rows)`, so build BOTH tabs inside `compute()` and append them to
`analyst_rows_payload`:
1. `"Critical Remediation Detail"` — unchanged shape and column set. It now sources from
   `A where days_to_fix > 15` PLUS the B rows (both are "missed the 15-day SLA"); for a B
   row `days overdue = (rd - clock_start).days - 15` and `remediation due_date` is derived
   from `clock_start + 15d` (not `first_found + 15d` — the clock changed). Keep the
   existing `extract_owner` -> `owner_tag`, plugin concatenation, sort-by-days-overdue-desc,
   and the T-03-03-02 CSV-formula-injection guard on the text columns.
2. `"VPR Severity Distribution"` — NEW. Open findings counted by `vpr_severity`, scope =
   on-time assets + risk-managed excluded (this scope reproduces the operator's reference
   values exactly; do NOT apply the 30-day `last_found` guard here). Columns:
   `VPR Severity` / `Open Findings`. Rows in fixed order
   `critical, high, medium, low, none` (zero-filled when absent) plus a final `TOTAL` row.
   This tab is emitted whenever the module has data, even when tab 1 is empty — the `none`
   row is the entire point of the tab. Values are integers and fixed literal labels, so no
   CSV-injection guard is needed here.

**Docstrings:** update the module docstring header and the `compute()` NumPy docstring to
describe the new cohort, clock, populations, and scoping. Comment each substantive change
with `quick-260805-ezo`.

**Tests:** extend `tests/test_kpi_risk_managed_exclusion.py` with the `<behavior>` cases
above (synthetic fixtures only, Hard Rule 2 — the FIXED half cannot be verified against
cache data, so this is the only coverage it gets). Repoint the three
`tests/test_consumer_audit.py` narrow-vs-wide drift assertions from
`total_fixed_last_month` / `fixed_within_sla` to `denominator` / `compliant` (the intent —
widening the fixed fetch must not change output — is preserved), and fix the stale
`total_open_last_month` comment at line ~234. Check whether
`tests/test_consumer_audit.py::_make_fixed_row` (hardcodes `vpr_score = 9.5` while varying
`severity`) still produces the intended cohort under VPR-only tiering; adjust the fixture
if a case now lands in a different tier, and say so in the SUMMARY.
  </action>
  <verify>
    <automated>.venv/bin/python -m pytest tests/test_kpi_risk_managed_exclusion.py tests/test_consumer_audit.py -q -p no:cacheprovider 2>&1 | tail -20</automated>
    <automated>grep -n 'time_taken_to_fix' reports/modules/critical_remediation_sla_module.py | grep -v '^\s*#' | grep -c . | grep -qx 0 && echo "OK: time_taken_to_fix preference removed" || echo "FAIL: time_taken_to_fix still referenced"</automated>
    <automated>grep -vE '^\s*#' reports/modules/critical_remediation_sla_module.py | grep -c 'total_open_last_month'</automated>
    <automated>grep -c 'VPR Severity Distribution' reports/modules/critical_remediation_sla_module.py</automated>
  </verify>
  <done>
    `compute()` emits the QT-01 metrics contract; `exclude_risk_managed` is applied to both
    populations; `_compute_days_to_fix` is gone and the reopened-aware clock is in place;
    `render_analyst_tabs` returns the distribution tab plus (when non-empty) the detail tab;
    the two touched test files are green.
  </done>
</task>

<task type="auto">
  <name>Task 3: Four-component disclosure across PDF/Excel/email, audit info, docs, and the cache sanity script</name>
  <files>
    reports/modules/critical_remediation_sla_module.py,
    scripts/sanity_vpr_severity_cache.py,
    docs/board_summary_calculations.md
  </files>
  <action>
**PDF (`render_pdf_section`, Item 3):** replace the three support tiles (Open Last Month |
Fixed Last Month | Fixed within SLA) with five: `Compliant (≤15d)` | `Fixed late (>15d)` |
`Still open, overdue` | `Not yet due` | `Total Critical Open`. Keep the
`two_column_metric_section` layout and the existing gauge/status-badge block untouched —
the module docstring records a page-bleed constraint that a stacked explanation already
caused once, so five narrower cells in the SAME single-row table is the shape to use, not
a second row. Shrink the per-cell padding/font if needed to stay inside the column; run
`tests/verify_board_page_bleed.py` to confirm.

Relabel the Top-5 owner table columns to match the new formula:
`Owner | Compliant | Denominator | SLA Compliance %` (still four columns — do not widen the
PDF table; the full component set goes in Excel).

Rewrite the explanatory paragraph at line ~637. The current text claims "Critical
vulnerabilities (VPR 9.0–10.0)" (now TRUE under VPR-only) but still describes the old
fixed-only denominator and the asset-level scope (now wrong). New text must state: cohort =
VPR 9.0–10.0 criticals excluding risk-accepted/recast; the 15-day clock runs from the
resurface date when a finding has reopened; the denominator counts criticals fixed in the
last 30 days PLUS criticals still open past their 15-day SLA; criticals still inside their
15-day clock are excluded; open findings are scoped to assets scanned in the last 30 days
AND findings a scanner has actually seen in the last 30 days. Keep the board-target
sentence with the unchanged ≥95 / ≥85 bands. D-09: NO methodology-change note.

**Excel (`render_excel_tabs`, Item 3):** the KPI block becomes, in this order:
```
SLA Compliance (30d)        <- RAG headline
Status
Compliant (fixed ≤15d)
Fixed late (>15d)
Still open, overdue (>15d)
Not yet due (≤15d)          <- label annotated "(excluded from calculation)"
Total Critical Open
Denominator
```
followed by the existing `Window:` / `SLA Thresholds:` / `Scope:` rows with updated text
(Window = the 30-day fixed window AND the 30-day finding-level staleness guard; Scope = the
asset-level on-time gate applies to the open side only). Shift `header_row` for the owner
table accordingly. The owner breakdown table gains the component columns:
`Owner | Compliant | Fixed late | Still open, overdue | Not yet due | Denominator |
SLA Compliance %`, keeping the existing RAG fill on the percentage cell and setting sensible
`column_dimensions` widths. Keep the D-16 zero-row placeholder path and the `data.error`
path unchanged.

**Email:** `render_email_panel` and the CONTRACT-03 `rag_strip` shape do NOT change (single
percentage + On Target / At Risk / Off Target). Only `render_email_kpis` needs repointing
to the new keys: `"Crit Remediation SLA"` (pct), `"Crit Compliant (30d)"` (compliant),
`"Crit Breached"` (breached).

**`_build_summary`:** update its signature and text to the new components; keep the
`safe_pct()` usage (WR-07) and the two no-data branches.

**`get_audit_info()`:** rewrite every entry in the `calculations` dict to the new formula,
clock, and scoping — one entry per new metric key plus `days_to_fix` (state the
COALESCE and that `time_taken_to_fix` is deliberately NOT used, citing D-16-02 and
quick-260805-ezo), `cohort` (VPR-only + risk-managed exclusion on both populations),
`open_scope` (asset-level on-time gate + finding-level last_found guard), `fixed_scope`
(no asset-level gate — states why: it dropped credit for fixes on assets decommissioned
after remediation), and `owner_breakdown`. Also update the `metadata` dict's `"window"`,
`"on_time_scope"`, and `"days_to_fix_source"` strings.

**Sanity script `scripts/sanity_vpr_severity_cache.py`:** new, cache-backed, NO live pull
(Hard Rule 1 — it reads parquet directly and must not import `data.fetchers` or
`tenable_client`). `argparse` with `--cache-dir` (default `data/cache/2026-07-01`) and
`--report-date` (default `2026-07-01`), `if __name__ == "__main__":`, type hints, NumPy-style
docstrings, `logging` — project convention. It loads `vulns_all.parquet` +
`assets_all.parquet`, applies `identify_on_time_assets` -> `exclude_risk_managed` ->
`add_vpr_severity`, and prints/asserts the `<reference_values>` table: 36,358 on-time
assets; distribution 5,723 / 12,423 / 57,196 / 47,622 / 43,428 / total 166,392; critical
open in window 5,723; open_past_due 3,210; open_not_due 2,513. Exit 1 on any mismatch with a
per-row diff. AGGREGATE COUNTS ONLY — no hostnames, IPs, plugin names, or asset UUIDs in
any output (Hard Rule 2). Note in its docstring that the FIXED half of the metric has no
cache coverage and is verified by synthetic unit fixtures only.

**Docs `docs/board_summary_calculations.md`:** rewrite section 7 (Metric 2) — What it
measures, Formula (show the four components and that C is excluded), Days-to-fix derivation
(COALESCE clock; delete the `time_taken_to_fix` primary-source text at lines 249-254),
Thresholds (values UNCHANGED), Values reported (the QT-01 metric keys), Edge cases (zero
denominator with C > 0 -> No Data; NaT clock_start -> C per QT-02; negative date math clipped
to 0). Update section 2's "Exclusion of risk-managed findings" bullet at line 83 (Metric 2
now excludes from BOTH populations, not just fixed). Update section 3 "Severity
Classification (VPR)" to state that the five board modules tier from a board-local VPR-only
`vpr_severity` with NO native-CVSS fallback (line 102's "falls back to the native Tenable
severity field" is now wrong for board modules — keep the suite-wide fallback statement but
scope it correctly). Update the section 8 and 9 severity-scope lines if they assert a
native fallback. D-09 applies to the rendered channels only — the calculations runbook is an
auditor document and SHOULD record the change.
  </action>
  <verify>
    <automated>.venv/bin/python scripts/sanity_vpr_severity_cache.py && echo "SANITY OK"</automated>
    <automated>.venv/bin/python -m pytest tests/ -q -p no:cacheprovider 2>&1 | tail -25</automated>
    <automated>.venv/bin/python tests/verify_board_page_bleed.py 2>&1 | tail -10</automated>
    <automated>grep -inE 'methodology chang|definition chang|previously reported|note: this metric now' reports/modules/critical_remediation_sla_module.py | grep -c . | grep -qx 0 && echo "OK: D-09 respected" || echo "FAIL: in-report methodology note present"</automated>
  </verify>
  <done>
    All four channels disclose the components per Item 3 with the RAG headline and email
    panel shape unchanged; `get_audit_info()` matches the new formula; the sanity script
    reproduces every reference value from cache; docs section 7 (plus the stale section 2/3
    notes) rewritten; full test suite shows no new failures versus the pre-change baseline.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Tenable export -> parquet cache | Untrusted third-party strings (`plugin_name`, `hostname`, tag values) already in the cache; this change adds no new fetch path |
| Module -> Excel/CSV writer | Analyst workbook cells can be interpreted as formulas by Excel |
| Module -> PDF/email HTML | Module-supplied strings rendered into WeasyPrint HTML and email body |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-ezo-01 | Tampering | New "VPR Severity Distribution" analyst tab | accept | Cells are fixed literal tier labels + integer counts; no third-party string reaches the sheet, so no CSV-formula-injection surface is created |
| T-ezo-02 | Tampering | "Critical Remediation Detail" tab now also carries B (open) rows | mitigate | Keep the existing T-03-03-02 `'`-prefix guard on `asset` / `plugin` / `owner_tag`; the guard must run AFTER the A+B union, not before |
| T-ezo-03 | Information disclosure | `scripts/sanity_vpr_severity_cache.py` output | mitigate | Aggregate counts only — no hostnames, IPs, plugin names, or asset UUIDs printed or written (Hard Rule 2 / D-04-08) |
| T-ezo-04 | Information disclosure | Live Tenable pull during verification | mitigate | Verification is cache-parquet + synthetic fixtures only; the sanity script never imports `data.fetchers` / `tenable_client` (Hard Rule 1, PreToolUse hook enforced) |
| T-ezo-05 | Denial of service | Module render error killing the batch | mitigate | Every new code path stays inside the existing try/except -> `_empty_result()` fail-soft envelope; empty-data guard on all four channels (Hard Rule 6) |
| T-ezo-SC | Tampering | npm/pip/cargo installs | accept | No package installs — zero new dependencies (Hard Rule 8); `requirements.txt` untouched |
</threat_model>

<verification>
1. `.venv/bin/python -m pytest tests/ -q` — no NEW failures versus the pre-change baseline.
   The suite has 5 known pre-existing failures (stub-registry pollution in
   `tests/unit/test_modules.py`, recorded in the 260722-lx9 SUMMARY); capture the baseline
   count BEFORE editing so "no new regressions" is provable.
   Note `pytest.ini` sets `testpaths = tests/unit tests/content tests/e2e`, so a bare
   `pytest` does NOT collect the `tests/*.py` root files — always pass `tests/` explicitly.
2. `.venv/bin/python scripts/sanity_vpr_severity_cache.py` — exit 0, every reference value
   matches.
3. `.venv/bin/python tests/verify_board_page_bleed.py` — the five-tile PDF row does not
   bleed the page.
4. Board structural baselines (`tests/baselines/board_summary_test_pull*.json`) are ALREADY
   stale from the 260722-lx9 accepted_recast rollout (`pdf_page_count = 5`,
   `pdf_rag_cell_count = 4`, `email_panel_count = 4` predate the 5th module) and are
   live-data-origin, so they cannot be regenerated inside Claude Code (Hard Rule 1). If
   `tests/test_board_summary_baseline.py` fails, confirm the failure is that pre-existing
   staleness and NOT new drift, then record it as an operator follow-up — do not edit the
   baseline JSON by hand.
5. Operator-only (outside Claude Code): `python run_all.py --dry-run` and a real
   board_summary run against warmed cache, plus regeneration of the board structural
   baselines via `scripts/smoke_board_summary_cutover.py`.
</verification>

<success_criteria>
- `vpr_severity_tier` / `add_vpr_severity` / `VPR_NONE_LABEL` live in `board_report_utils.py`,
  are re-exported from `reports.modules`, and are empty-frame / missing-column safe.
- `git diff --stat -- config.py data/fetchers.py` is empty (D-01).
- The three board tiering sites read `vpr_severity`; no non-board module was touched (D-03).
- `critical_remediation_sla` applies `exclude_risk_managed` to both populations, uses the
  reopened-aware COALESCE clock with no `time_taken_to_fix` preference, and emits the QT-01
  metrics contract.
- `sla_pct = compliant / (compliant + breached) * 100`; `open_not_due` never enters the
  denominator; thresholds still 95 / 85 (D-08).
- The analyst workbook gains a "VPR Severity Distribution" tab whose `none` row is present
  and non-hidden; no new PDF page, no new module, `_BOARD_MODULE_CONFIGS` unchanged (D-10).
- PDF, Excel, and driver narrative disclose all four components plus Total Critical Open;
  RAG strip and email panel shapes unchanged; no methodology-change note anywhere in the
  rendered channels (D-09).
- `docs/board_summary_calculations.md` section 7 and the stale section 2/3 notes are
  rewritten; `get_audit_info()` matches the shipped formula.
- Sanity script reproduces all reference values from `data/cache/2026-07-01/`.
- No new test regressions; zero new dependencies.
</success_criteria>

<output>
Create `.planning/quick/260805-ezo-board-summary-vpr-only-severity-critical/260805-ezo-SUMMARY.md`
when done. It MUST record:
- the `<known_consequence>` propagation to `management_summary` Metric 5 and any
  `composed_report` group listing `aged_vulns_assets`,
- the removed metric keys (`total_open_last_month`, `total_fixed_last_month`,
  `fixed_within_sla`) and their replacements,
- the expectation that the metric now reports RED under the new formula (D-08 — not a
  defect),
- the operator follow-ups: real `--dry-run`, and regeneration of the
  `tests/baselines/board_summary_test_pull*.json` structural baselines (already stale since
  260722-lx9; Hard Rule 1 blocks doing it here).
</output>
