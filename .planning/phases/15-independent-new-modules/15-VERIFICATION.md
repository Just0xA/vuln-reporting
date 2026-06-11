---
phase: 15-independent-new-modules
verified: 2026-06-11T22:15:00Z
status: passed
score: 9/9 must-haves verified
overrides_applied: 0
---

# Phase 15: Independent New Modules — Verification Report

**Phase Goal:** Five new four-channel metric modules are live and verifiably correct —
New vs Remediated, Vulnerability Density, Reopened Vulnerabilities, Accepted & Recast,
and External/DMZ Exposure Cut — each consuming the S1/S2 substrates (trend store +
owner segmentation) and the Phase-14 gates (external_scope, count_on_time_assets,
composed_report kwargs gates) WITHOUT peer-module dependencies.

**Verified:** 2026-06-11T22:15:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth                                                                                      | Status     | Evidence                                                                                        |
|----|--------------------------------------------------------------------------------------------|------------|-------------------------------------------------------------------------------------------------|
| 1  | All five modules exist, register via auto-discovery, and are present in registry._modules | ✓ VERIFIED | `python -c "import reports.modules; from reports.modules import registry; print(sorted(registry._modules.keys()))"` → `['accepted_recast', ..., 'external_dmz', ..., 'new_vs_remediated', ..., 'reopened_vulns', ..., 'vuln_density', ...]` |
| 2  | Each module implements all five four-channel render methods                                | ✓ VERIFIED | grep confirms `render_pdf_section`, `render_excel_tabs`, `render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry` in all five module files (line numbers confirmed below) |
| 3  | Empty-data guard: all five modules survive zero-row input on all four channels             | ✓ VERIFIED | 241 tests pass under `-W error::FutureWarning`; empty-data guard classes present in every module test file |
| 4  | trend_store.capture_snapshot() backward-compatible extension with six new aggregate fields | ✓ VERIFIED | `data/trend_store.py` lines 337–368: new optional params with `None` defaults; `new_entry` carries `on_time_asset_count`, `reopened_count`, `accepted_count`, `recast_count`, `new_findings_count`, `fixed_findings_count` |
| 5  | composed_report.py frozenset gates: trend/recast modules registered; external_dmz/reopened_vulns absent | ✓ VERIFIED | `composed_report.py` lines 86–99: `_MODULES_NEEDING_TREND_SNAPSHOTS` = `{sc4_kwargs_stub, new_vs_remediated, vuln_density, accepted_recast}`; `_MODULES_NEEDING_RECAST_RULES` = `{sc4_kwargs_stub, accepted_recast}`; grep for `external_dmz` / `reopened_vulns` in composed_report.py produces no output |
| 6  | No peer-module dependencies among the five new modules                                     | ✓ VERIFIED | grep for cross-imports between the five modules produces no output — each imports only from `reports.modules.base`, `board_report_utils`, `rag_utils`, `format_utils`, `registry`, and substrates |
| 7  | Code-review warnings WR-01..05 resolved in commit 81d85c2                                 | ✓ VERIFIED | Commit exists (`git log --oneline 81d85c2` = `fix(15): resolve code-review warnings WR-01..05`); each fix verified by code inspection (detail below) |
| 8  | Phase test suites pass under `-W error::FutureWarning`                                    | ✓ VERIFIED | `241 passed in 4.24s` — all six test files (reopened_vulns, external_dmz, new_vs_remediated, vuln_density, accepted_recast, trend_store) exit 0 |
| 9  | `python run_all.py --dry-run` exits 0 with no regression                                  | ✓ VERIFIED | Output: "All 5 group(s) validated successfully." |

**Score:** 9/9 truths verified

---

### Required Artifacts

| Artifact                                               | Expected                                   | Status     | Details                                    |
|--------------------------------------------------------|--------------------------------------------|------------|--------------------------------------------|
| `reports/modules/reopened_vulns_module.py`             | ReopenedVulnsModule, MODULE_ID=reopened_vulns, @register_module, min 200 lines | ✓ VERIFIED | 573 lines; `@register_module` at line 90; `MODULE_ID = "reopened_vulns"` at line 107 |
| `tests/test_reopened_vulns_module.py`                  | Unit tests, min 120 lines                  | ✓ VERIFIED | 579 lines; 39 tests per SUMMARY              |
| `reports/modules/external_dmz_module.py`               | ExternalDmzModule, MODULE_ID=external_dmz, @register_module, min 180 lines | ✓ VERIFIED | 561 lines; `@register_module` at line 91; `MODULE_ID = "external_dmz"` at line 109 |
| `tests/test_external_dmz_module.py`                    | Unit tests, min 100 lines                  | ✓ VERIFIED | 474 lines; 29 tests per SUMMARY              |
| `reports/modules/new_vs_remediated_module.py`          | NewVsRemediatedModule, MODULE_ID=new_vs_remediated, @register_module, min 200 lines | ✓ VERIFIED | 749 lines; `@register_module` at line 142; `MODULE_ID = "new_vs_remediated"` at line 166 |
| `reports/composed_report.py`                           | frozenset registration for three trend module IDs | ✓ VERIFIED | Lines 86–99 confirmed; all three IDs present |
| `tests/test_new_vs_remediated_module.py`               | Cold-start/stacked inflow/empty-data tests, min 120 lines | ✓ VERIFIED | 858 lines; 49 tests per SUMMARY |
| `reports/modules/vuln_density_module.py`               | VulnDensityModule, MODULE_ID=vuln_density, @register_module, min 180 lines | ✓ VERIFIED | 753 lines; `@register_module` at line 143; `MODULE_ID = "vuln_density"` at line 160 |
| `tests/test_vuln_density_module.py`                    | Per-snapshot denom, drift flag, cold-start tests, min 110 lines | ✓ VERIFIED | 842 lines; 44 tests per SUMMARY |
| `reports/modules/accepted_recast_module.py`            | AcceptedRecastModule, MODULE_ID=accepted_recast, @register_module, min 200 lines | ✓ VERIFIED | 943 lines; `@register_module` at line 137; `MODULE_ID = "accepted_recast"` at line 160 |
| `tests/test_accepted_recast_module.py`                 | Separate counts, expiry, cold-start tests, min 120 lines | ✓ VERIFIED | 911 lines; 55 tests per SUMMARY |
| `data/trend_store.py`                                  | capture_snapshot() with new optional aggregate params | ✓ VERIFIED | Lines 337–368: six new keys; all int/None |
| `scripts/capture_trend_snapshot.py`                    | Wired aggregate counts into severity call  | ✓ VERIFIED | count_on_time_assets, reopened_count, accepted_count, recast_count passed to severity capture_snapshot call |

---

### Key Link Verification

| From                                              | To                                          | Via                               | Status     | Details                                                    |
|---------------------------------------------------|---------------------------------------------|-----------------------------------|------------|------------------------------------------------------------|
| `reopened_vulns_module.py`                        | `board_report_utils.extract_owner`          | Owner cut                         | ✓ WIRED    | Import at line 46; used in compute()                       |
| `reopened_vulns_module.py`                        | `registry.register_module`                  | `@register_module`                | ✓ WIRED    | Decorator at line 90; module in registry confirmed by runtime check |
| `external_dmz_module.py`                          | `utils.external_scope.external_scope`       | Inline scope classification       | ✓ WIRED    | Import at line 57; called inline in compute()              |
| `external_dmz_module.py`                          | `registry.register_module`                  | `@register_module`                | ✓ WIRED    | Decorator at line 91                                       |
| `new_vs_remediated_module.py`                     | `trend_snapshots` kwarg (insufficient_data) | QUAL-01 cold-start branch         | ✓ WIRED    | Lines 248–257: `cold_start = (trend_snapshots is None or insufficient_data)`; `_build_cold_start_result` |
| `composed_report.py`                              | `_MODULES_NEEDING_TREND_SNAPSHOTS`          | gate for new_vs_remediated/vuln_density/accepted_recast | ✓ WIRED | Lines 86–91 confirmed |
| `scripts/capture_trend_snapshot.py`               | `utils.asset_count.count_on_time_assets`    | on_time_asset_count denominator   | ✓ WIRED    | count_on_time_assets imported and passed to severity call  |
| `data/trend_store.py` new_entry                   | vuln_density / new_vs_remediated / accepted_recast modules | MoM trend fields | ✓ WIRED | new_entry dict lines 358–369 stores all six aggregate fields as int/None |
| `accepted_recast_module.py`                       | `recast_rules_df` kwarg                     | Expiry cross-check (Pitfall 6a)   | ✓ WIRED    | `kwargs.get("recast_rules_df")` with None-guard and expired_ids exclusion |
| `accepted_recast_module.py`                       | `data.fetchers._summarize_filter`           | Analyst-tab filter display        | ✓ WIRED    | Confirmed in SUMMARY and module implementation             |

---

### Data-Flow Trace (Level 4)

| Artifact                          | Data Variable         | Source                                          | Produces Real Data | Status      |
|-----------------------------------|-----------------------|-------------------------------------------------|--------------------|-------------|
| `reopened_vulns_module.py`        | `reopened_df`         | `vulns_df["state"].str.upper() == "REOPENED"`   | Yes — filters live vulns_df | ✓ FLOWING |
| `external_dmz_module.py`          | `scoped_assets_df`    | `external_scope(assets_df)` — Phase-14 substrate | Yes                | ✓ FLOWING  |
| `new_vs_remediated_module.py`     | `trend_snapshots`     | `read_trend()` via composed_report kwargs gate  | Yes — from trend JSON files | ✓ FLOWING |
| `vuln_density_module.py`          | `on_time_asset_count` | `snap.get("on_time_asset_count")` per snapshot  | Yes — from captured snapshots | ✓ FLOWING |
| `accepted_recast_module.py`       | `accepted_count`/`recast_count` | `severity_modification_type.isin({"ACCEPTED"/"RECASTED"})` + trend snapshot MoM delta | Yes | ✓ FLOWING |

---

### Behavioral Spot-Checks

| Behavior                                  | Command                                                                                                      | Result           | Status  |
|-------------------------------------------|--------------------------------------------------------------------------------------------------------------|------------------|---------|
| All 5 modules auto-registered             | `python -c "import reports.modules; from reports.modules import registry; print('reopened_vulns' in registry._modules)"` | `True` | ✓ PASS |
| Full phase test suite under FutureWarning | `pytest tests/test_reopened_vulns_module.py tests/test_external_dmz_module.py tests/test_new_vs_remediated_module.py tests/test_vuln_density_module.py tests/test_accepted_recast_module.py tests/content/test_trend_store.py -W error::FutureWarning` | `241 passed in 4.24s` | ✓ PASS |
| --dry-run exits 0                         | `python run_all.py --dry-run`                                                                                | All 5 groups validated | ✓ PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description                                                    | Status       | Evidence                                                             |
|-------------|-------------|----------------------------------------------------------------|--------------|----------------------------------------------------------------------|
| RPT-01      | 15-04       | New vs Remediated monthly trend with Owner cut                | ✓ SATISFIED  | `new_vs_remediated_module.py` — stacked inflow (D-15-01/02), outflow from fixed_findings_count (Option B), cold-start safe |
| RPT-02      | 15-05       | Vulnerability Density MoM, per-snapshot denominator          | ✓ SATISFIED  | `vuln_density_module.py` — per-snapshot on_time_asset_count, >10% drift flag, cold-start |
| RPT-03      | 15-01       | Reopened Vulnerabilities with Owner cut and analyst drill-down | ✓ SATISFIED  | `reopened_vulns_module.py` — state==REOPENED filter, reopen-lag, Owner cut, rate degradation |
| RPT-04      | 15-06       | Accepted & Recast separately tracked, expiry awareness         | ✓ SATISFIED  | `accepted_recast_module.py` — separate accepted/recast, expired-rule exclusion, finding-count headline |
| RPT-06      | 15-03       | External/DMZ exposure cut, current-snapshot only              | ✓ SATISFIED  | `external_dmz_module.py` — external_scope() substrate, locked mismatch schema, no trend branch |
| QUAL-01     | 15-04,05,06 | Cold-start on insufficient_data; never NaN%/crash             | ✓ SATISFIED  | `_build_cold_start_result` in new_vs_remediated and vuln_density; `_safe_delta_arrow` in accepted_recast |
| QUAL-02     | 15-04       | Reopened-aware open-count via open_findings_at()              | ✓ SATISFIED  | `new_vs_remediated_module.py` line 348–350: `from utils.open_count import open_findings_at; open_df = open_findings_at(vulns_df, report_date)` |
| QUAL-03     | 15-01..06   | Zero-row input safe on all four channels                       | ✓ SATISFIED  | Empty-data guard (`vulns_df.empty or column not in`) in every module compute(); 241 tests pass including empty-data suites |
| QUAL-05     | 15-01..06   | Aggregate counts only in snapshots; synthetic fixtures         | ✓ SATISFIED  | trend_store new_entry stores int/None only (no DataFrames verified by code + tests); test fixtures use RFC 6761/5737 addresses; no hostnames/IPs in committed test data |

---

### WR Fix Verification (commit 81d85c2)

| WR    | Issue                                                              | Fix Verified                                                                                                    |
|-------|--------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| WR-01 | UTC/local mismatch in trend_store new_findings_count derivation    | `data/trend_store.py` lines 345–355: `local_tz = datetime.now().astimezone().tzinfo`; `ff.dt.tz_convert(local_tz).dt.strftime("%Y-%m")` — local time used for both ff and lf month comparison |
| WR-02 | tz-aware `.dt.to_period("M")` UserWarning in new_vs_remediated     | `new_vs_remediated_module.py` lines 284–290: `.dt.tz_localize(None)` appended before later `.to_period("M")` calls on both `ff_ts` and `rs_ts` |
| WR-03 | Owner-snapshot failure exits code 3 despite "Non-fatal" comment    | `scripts/capture_trend_snapshot.py` lines 322–329: exception handler now calls `_log_completed(..., "partial", ...)` and `return 0` — no longer exits 3 |
| WR-04 | accepted_recast crashes on missing severity_modification_type column | `accepted_recast_module.py` lines 216–220: empty-data guard extended with `or "severity_modification_type" not in vulns_df.columns` before classification |
| WR-05 | render_excel_tabs sets widths for 5 columns but writes only 4      | `accepted_recast_module.py` line 831: `widths = [28, 14, 14, 14]` — WR-05 comment inline; 4 entries matching 4 data columns |

---

### Anti-Patterns Found

No `TBD`, `FIXME`, or `XXX` markers found in any of the seven phase-15-modified files
(`grep` of all six module files + `data/trend_store.py` + `scripts/capture_trend_snapshot.py`
produced no output).

The `ChainedAssignmentError` warnings emitted during the test run originate from
`pandas.core.frame.py` internals (`com.apply_if_callable` inside `pd.DataFrame.assign`)
and from a test-helper function in `tests/test_new_vs_remediated_module.py:87`
(`df[col] = pd.to_datetime(...)`). Neither is a `FutureWarning` — the pytest gate
`-W error::FutureWarning` does not treat `ChainedAssignmentError` as a failure, and all
241 tests pass. The test-helper CoW violation is a low-severity Info item (test code only,
no production impact).

| File                                     | Line | Pattern               | Severity | Impact      |
|------------------------------------------|------|-----------------------|----------|-------------|
| `tests/test_new_vs_remediated_module.py` | 87   | `df[col] = ...` in test helper (ChainedAssignmentError) | ℹ️ Info | Test code only — does not affect production module or test outcome |

---

### Human Verification Required

None — all phase-15 must-haves are verifiable programmatically. The live-tenant
`resurfaced_date` spot-check (Task 2 of Plan 15-01) was a blocking checkpoint that was
completed during execution (30,010 REOPENED rows, 100% resurfaced_date coverage confirmed
by the operator) and locked before parallel modules were built. No further human UAT is
required for this phase.

---

### Gaps Summary

No gaps. All nine observable truths verified, all required artifacts substantive and wired,
all five code-review warnings resolved with regression coverage, all test suites pass, and
`--dry-run` exits 0.

---

_Verified: 2026-06-11T22:15:00Z_
_Verifier: Claude (gsd-verifier)_
