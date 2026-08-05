---
quick_id: 260805-ezo
subject: Board VPR-only severity + Critical Remediation SLA reformulation
status: complete
completed: 2026-08-05
commits:
  - 702a10f  # Task 1 — VPR-only severity helper + board severity consumers
  - 694cc00  # Task 2 — critical_remediation_sla compute() reformulation
  - f2ed566  # Task 3 — four-channel disclosure, audit info, sanity script, docs
files_created:
  - scripts/sanity_vpr_severity_cache.py
files_modified:
  - reports/modules/board_report_utils.py
  - reports/modules/__init__.py
  - reports/modules/high_risk_assets_module.py
  - reports/modules/aged_vulns_assets_module.py
  - reports/modules/critical_remediation_sla_module.py
  - tests/test_board_report_utils.py
  - tests/test_kpi_risk_managed_exclusion.py
  - tests/test_consumer_audit.py
  - docs/board_summary_calculations.md
---

# Quick Task 260805-ezo — Board VPR-Only Severity + Critical Remediation SLA Reformulation Summary

Fixed the three definitional divergences plus the latent clock bug that made board_summary's Critical Remediation SLA read 61.6% against an operator console reading of ~74%: board modules now tier from a board-local VPR-only `vpr_severity` column, and the Critical Remediation SLA is reformulated onto a reopened-aware clock with a four-component denominator that counts still-open breaches, not just fixed findings.

## What Shipped

### Task 1 — VPR-only severity tiering (`702a10f`)

- `reports/modules/board_report_utils.py` gained `VPR_NONE_LABEL`, `vpr_severity_tier(score)` and `add_vpr_severity(df)`. Tier boundaries are 9.0 critical / 7.0 high / 4.0 medium / 0.1 low, everything else (`0.0`, negative, `None`, `NaN`, `""`, unparseable) → `"none"`. `add_vpr_severity` is vectorised (`pd.to_numeric` + successive `.mask()` coarsest-first) and returns a new frame via `.assign()` (Hard Rule 5). Empty frames still carry the column; a missing `vpr_score` column logs a warning and labels every row `"none"` (fail-soft, mirroring `extract_owner`).
- All three re-exported from `reports.modules`.
- `high_risk_assets`, `aged_vulns_assets` call `add_vpr_severity()` immediately after the existing `exclude_risk_managed()` at `compute()` entry; their `required` sets, `severity_mask`s, `aged_vulns`' `worst_severity` groupby aggregation, `get_audit_info()` strings and `severity_scope` metadata all read/describe `vpr_severity`.
- `compute_bu_risk_scores()` masks and weights on `vpr_severity`, with a defensive `add_vpr_severity()` at entry so it is correct regardless of caller ordering. Verified by grep that it is called only by those two board modules.
- `config.py` and `data/fetchers.py` are byte-unchanged (`git diff --stat` empty against the base) — D-01 respected. `scan_coverage_sla_module.py`, `accepted_recast_module.py`, and every non-board module were not touched — D-03 respected.

### Task 2 — Critical Remediation SLA reformulation (`694cc00`)

- **Cohort (D-04):** `exclude_risk_managed()` now applies to **both** `vulns_df` and `fixed_vulns_df` (it was fixed-only), then `add_vpr_severity()` to both. `_filter_critical(df, on_time_uuids)` was replaced by `_filter_critical_vpr(df)` (cohort only, no asset gate) plus a separate `_filter_open_in_scope()` for the open side.
- **Clock (D-05):** `_compute_days_to_fix()` and its `time_taken_to_fix` preference are deleted. New `_coerce_ts()` / `_compute_clock_start()` implement `COALESCE(resurfaced_date, first_found)` mirroring `mttr_trend_module.py:420-450` (D-16-02), applied with `.assign()`.
- **Populations (D-06):** A = `state == FIXED AND last_fixed >= rd − 30d`, **no asset-level gate**. B/C = open/reopened + asset on-time gate + finding-level `last_found >= rd − 30d` staleness guard, split at `(rd − clock_start).days > 15`. QT-02: NaT `clock_start` falls into C.
- **Metric (D-07/D-08):** `sla_pct = compliant / (compliant + breached) × 100`; `open_not_due` never enters the denominator. `_GREEN_THRESHOLD = 95.0` / `_YELLOW_THRESHOLD = 85.0` / `_GAUGE_THRESHOLDS` untouched.
- **Per-owner breakdown:** now spans A ∪ B ∪ C with four boolean component flags; denominator mask is `is_compliant | is_fixed_late | is_open_past_due`. Owner maps from the **full** asset frame (the fixed side no longer has an asset gate).
- **Analyst tabs:** "Critical Remediation Detail" now unions A-late rows and B rows (`days overdue` and `remediation due_date` both derived from `clock_start`, not `first_found`); new "VPR Severity Distribution" tab with critical/high/medium/low/none + TOTAL.

### Task 3 — Disclosure, audit info, sanity script, docs (`f2ed566`)

- **PDF:** three support tiles → five (`Compliant (≤15d)` | `Fixed late (>15d)` | `Still open, overdue` | `Not yet due` | `Total Critical Open`) in the **same single-row table** with narrower padding and smaller type. Top-5 headers relabelled `Owner | Compliant | Denominator | SLA Compliance %` (still four columns). Explanatory paragraph rewritten. `tests/verify_board_page_bleed.py` → PASS (nominal and worst-case both 2 pages).
- **Excel:** KPI block discloses all four components plus Total Critical Open and Denominator, with `Not yet due` annotated "(excluded from calculation)"; `Window:` / `SLA Thresholds:` / `Scope:` rewritten; `header_row` shifted 12 → 15; owner table gained the component columns with new widths.
- **Email:** `render_email_panel` and the CONTRACT-03 `rag_strip` shape unchanged. `render_email_kpis` repointed to `Crit Remediation SLA` / `Crit Compliant (30d)` / `Crit Breached`.
- **`get_audit_info()`** rewritten end-to-end: one entry per new metric key plus `cohort`, `days_to_fix`, `open_scope`, `fixed_scope`, `owner_breakdown`. Metadata `window` / `on_time_scope` / `days_to_fix_source` updated.
- **`scripts/sanity_vpr_severity_cache.py`** — new, cache-parquet only, never imports `data.fetchers` / `tenable_client`, aggregate counts only.
- **`docs/board_summary_calculations.md`** — section 7 rewritten (four populations, formula, scoping-asymmetry table, COALESCE clock, unchanged thresholds, QT-01 metric keys, analyst tabs, edge cases); section 2 exclusion bullet now says both populations; section 3 rewritten with the `none` tier and a correctly-scoped statement that the suite-wide native fallback still applies to non-board reports; sections 8/9 severity filters scoped; section 11 "Metric 2 shows No Data" note corrected.

## Verification

| Check | Result |
|-------|--------|
| `pytest tests/` baseline (pre-change) | 6 pre-existing failures |
| `pytest tests/` after Task 1 / Task 2 / Task 3 | 6 failures each time — **zero new regressions** |
| `tests/test_board_report_utils.py` + `test_kpi_risk_managed_exclusion.py` | 46 passed (Task 1), 26 passed (Task 2 module tests) |
| `tests/test_kpi_risk_managed_exclusion.py` + `test_consumer_audit.py` | 34 passed |
| `scripts/sanity_vpr_severity_cache.py` | **PASS, exit 0 — all 10 reference values matched exactly** |
| `tests/verify_board_page_bleed.py` | PASS (all three modules, nominal + worst-case) |
| `git diff --stat -- config.py data/fetchers.py` (vs base) | empty (D-01) |
| D-09 methodology-note grep on the module | 0 matches |
| Removed metric keys, non-comment grep | 0 matches |

Sanity-script output (aggregate counts only, Hard Rule 2):

```
on_time_assets            36,358    36,358   +0
open_findings_in_scope   166,392   166,392   +0
vpr_critical               5,723     5,723   +0
vpr_high                  12,423    12,423   +0
vpr_medium                57,196    57,196   +0
vpr_low                   47,622    47,622   +0
vpr_none                  43,428    43,428   +0
critical_open_in_window    5,723     5,723   +0
open_past_due              3,210     3,210   +0
open_not_due               2,513     2,513   +0
RESULT: PASS
```

The 6 pre-existing failures (unchanged, present at the base commit, not caused by this task):

- `tests/unit/test_modules.py` ×5 — stub-registry pollution, recorded in the 260722-lx9 SUMMARY.
- `tests/e2e/test_groups.py::test_group_runs_fail_soft_and_artifacts_valid[Remediation Team]` — `sla_remediation` and `patch_compliance` fail on a missing `'asset_id'` key. This is a **sixth** pre-existing failure not listed in the plan's "5 known" note; it is present in the pre-change baseline and involves two legacy report slugs this task never touched.

`tests/test_board_summary_baseline.py` **passed** (9 tests). The plan anticipated it might fail on the stale `pdf_page_count = 5` / `rag_cell_count = 4` baselines; it did not — this change alters values, not the structural counts those baselines assert.

## Expected Operational Consequences (not defects)

### The metric is expected to report RED (D-08)

Thresholds stay 95 green / 85 amber. Under the new formula the denominator includes 3,210 criticals that are already open past their 15-day SLA, so the reported percentage will drop sharply and the metric will read **Off Target (red)**. This is the agreed outcome of the reformulation, not a regression to fix and not a reason to recalibrate the bands.

### Propagation to `management_summary` (`<known_consequence>`)

`aged_vulns_assets` is composed by **both** `board_summary` (`reports/board_summary.py:92`) **and** `management_summary` (`reports/management_summary.py:91`), and is available to any `composed_report` group that lists it. Switching it to VPR-only therefore shifts `management_summary` Metric 5 numbers too — the same way the 2026-07-22 `exclude_risk_managed` rollout did. Measured definitional impact on the board metrics (definitional shift, **not** remediation improvement):

| Metric | Before | After |
|--------|--------|-------|
| Metric 3 High-Risk Assets | 0.20% | 0.09% |
| Metric 4 Aged Vuln Assets | 34.06% | 7.18% |

`high_risk_assets` and `critical_remediation_sla` are board-only, so they do not propagate.

### Removed metric keys

| Removed | Replacement |
|---------|-------------|
| `total_open_last_month` | `total_critical_open` (in-scope open criticals: B + C) |
| `total_fixed_last_month` | `denominator` (`compliant + breached`) — **not** a like-for-like rename; the old key counted fixed rows only |
| `fixed_within_sla` | `compliant` |

`remediation_sla_pct` and `status` keep their names (external readers: `tests/baseline_extractor`, `tests/test_phase2_composer_pipeline`, `scripts/smoke_email_phase2.py`). New keys added: `compliant`, `fixed_late`, `open_past_due`, `open_not_due`, `breached`, `denominator`, `total_critical_open`.

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 1 - Bug] CSV-injection guard fired a pandas incompatible-dtype `FutureWarning`**

- **Found during:** Task 2 (GREEN run of the new analyst-tab tests).
- **Issue:** `analyst_df.loc[:, _col] = <string dtype>` in `_build_missed_detail` wrote a `string` series into a float64 column whenever the source frame lacked `hostname` (reindex produces an all-NaN float column). pandas emitted "Setting an item of incompatible dtype is deprecated and will raise in a future error of pandas" — a latent Hard Rule 5 violation carried over from the pre-existing code.
- **Fix:** the guard is now built via `.assign()` over a dict comprehension.
- **Files modified:** `reports/modules/critical_remediation_sla_module.py`
- **Commit:** `694cc00`

**2. [Rule 1 - Bug] `pd.concat` all-NA-column deprecation on the A ∪ B union**

- **Found during:** Task 3 (`verify_board_page_bleed.py` run).
- **Issue:** unioning the fixed-late and still-open populations concatenated frames whose irrelevant columns were all-NA on one side (`resurfaced_date` on a never-reopened fixed frame, `last_fixed` on the open frame), triggering "DataFrame concatenation with empty or all-NA entries is deprecated".
- **Fix:** each population is projected to the seven columns the tab actually renders (via a local `_project()` helper) **before** the concat, with `first_found` and `clock_start` coerced to `datetime64[ns, UTC]` and `_days_overdue` to `Float64`.
- **Files modified:** `reports/modules/critical_remediation_sla_module.py`
- **Commit:** `f2ed566`

### Plan-boundary and interpretation notes

**3. `_build_summary` was rewritten in Task 2, not Task 3.** The plan assigned it to Task 3, but its old signature (`total_fixed`, `fixed_within_sla`, `total_open`) referenced locals that Task 2 deletes. Deferring it would have left an uncompilable intermediate commit, so the signature and text were updated alongside the `compute()` rewrite. Task 3's remaining `_build_summary` scope (new components, `safe_pct` retained, two no-data branches) is satisfied.

**4. `_compute_bu_breakdown` frame is A ∪ B ∪ C, not A ∪ B.** The plan says the helper "takes the union of A and B rather than A alone" but also requires that "rows in C contribute their component count". Those are only simultaneously satisfiable if C rows are present in the frame, so the frame is A ∪ B ∪ C and the **denominator mask** excludes C (`is_compliant | is_fixed_late | is_open_past_due`). Consequence worth knowing: `compute_per_bu_breakdown` drops owners with a zero denominator, so an owner whose only rows are in C does not appear in the breakdown table at all.

**5. Fixed-side rows with an uncomputable `days_to_fix` are excluded from both components.** The plan specifies QT-02 for the open side only. For the fixed side the pre-existing documented behaviour was retained: a row with NaT `clock_start` or NaT `last_fixed` counts as neither `compliant` nor `fixed_late`, so it never enters the denominator. This is stated explicitly in `get_audit_info()["calculations"]["fixed_late"]` and in the docs.

**6. Fail-soft handling for a missing `last_found` column.** The plan does not specify what happens when the open frame has no `last_found` column at all. Excluding every row would silently zero the metric, so `_filter_open_in_scope` logs a warning and **skips** the staleness guard in that case (the asset-level on-time gate still applies). A *present* `last_found` that is NaT still excludes the row — its freshness cannot be established.

### Test-fixture adjustments

**7. `tests/test_consumer_audit.py::_make_fixed_row` needed no cohort change.** The plan asked whether its hardcoded `vpr_score = 9.5` alongside a varying `severity` still produces the intended cohort under VPR-only tiering. It does: every row `_narrow_fixed_df` / `_wide_fixed_df` build uses the default `severity="critical"`, and VPR 9.5 tiers to `critical` regardless, so the cohort is unchanged. The fixture was left as-is. The three drift assertions were repointed from `total_fixed_last_month` / `fixed_within_sla` to `denominator` / `compliant` (test names renamed to match), the stale `total_open_last_month` comment at ~line 234 was rewritten, and the `vulns_df` stub columns were updated to `vpr_severity` / `last_found`. A stale "(Step 4)" reference in the `COVERED_FIXED_CONSUMERS` comment block was corrected to "(Step 3)".

**8. `tests/test_kpi_risk_managed_exclusion.py` fixtures gained columns.** `_make_vulns` now carries `vpr_score`, `last_found`, `state`; `_make_fixed_vulns` now carries `vpr_score`, `resurfaced_date`, `time_taken_to_fix`. Without these the modules correctly tier every fixture row as `none` and the existing exclusion tests would assert against an empty cohort. All fixtures remain fully synthetic (Hard Rule 2).

## Known Stubs

None.

## Threat Flags

None. No new network endpoint, auth path, file-access pattern, or schema change at a trust boundary was introduced. The threat register dispositions were honoured:

- **T-ezo-02 (mitigate):** the `'`-prefix CSV-formula guard on `asset` / `plugin` / `owner_tag` runs **after** the A ∪ B union, so the newly-added open rows are guarded.
- **T-ezo-03 (mitigate):** the sanity script prints aggregate counts only.
- **T-ezo-04 (mitigate):** verification was cache-parquet + synthetic fixtures only; the sanity script never imports `data.fetchers` / `tenable_client`.
- **T-ezo-05 (mitigate):** every new path stays inside the existing `try/except → _empty_result()` envelope.
- **T-ezo-SC (accept):** zero package installs; `requirements.txt` untouched.

## Operator Follow-Ups

1. **Run `python run_all.py --dry-run`** outside Claude Code to confirm config validation still passes, then a real `board_summary` run against a warmed cache to eyeball the new PDF page, the five-tile row, and the analyst workbook's VPR Severity Distribution tab.
2. **Regenerate the board structural baselines** — `tests/baselines/board_summary_test_pull*.json` have been stale since quick task 260722-lx9 (`pdf_page_count = 5`, `pdf_rag_cell_count = 4`, `email_panel_count = 4` predate the 5th module). They are live-data-origin and cannot be regenerated inside Claude Code (Hard Rule 1); use `scripts/smoke_board_summary_cutover.py` against warmed parquet. They did **not** fail during this task, but they are still recording pre-260722 structure.
3. **Communicate the definition change to the board audience separately.** Per D-09 no methodology note was added to the PDF, Excel, or email; the runbook (`docs/board_summary_calculations.md`) carries the auditor-facing record.
4. **Expect `management_summary` Metric 5 to move** at the next delivery for the reason recorded above.
5. **Pre-existing e2e failure worth a look:** `tests/e2e/test_groups.py::test_group_runs_fail_soft_and_artifacts_valid[Remediation Team]` fails on a missing `'asset_id'` key in `sla_remediation` and `patch_compliance`. Pre-existing and out of scope here, but it is a real fail-soft path firing in a legacy slug.

## Self-Check: PASSED

All claimed artifacts verified present on disk (`scripts/sanity_vpr_severity_cache.py`, `reports/modules/board_report_utils.py`, `reports/modules/critical_remediation_sla_module.py`, `tests/test_board_report_utils.py`, this SUMMARY) and all three commits verified in `git log` (`702a10f`, `694cc00`, `f2ed566`). `git diff --diff-filter=D` against the base commit reports zero file deletions.
