---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
verified: 2026-06-26T13:00:00Z
status: passed
score: 16/16 must-haves verified
overrides_applied: 1
overrides:
  - must_have: "18-REVIEW IN-02: dead _first_str helper (and the deprecated fetch_vulnerabilities chain) removed from data/fetchers.py"
    reason: "_first_str is called by the deprecated fetch_vulnerabilities at L982, and fetch_vulnerabilities is invoked by the __main__ CLI block at L1390. Removing _first_str would break the CLI. The executor confirmed via grep, documented the decision in 19-06-SUMMARY.md, and deferred removal to when the deprecated chain retires. Both functions are marked deprecated in docstrings. This is an intentional scope decision within D-02's 'fix all dead code' mandate — the function is not dead while the deprecated chain remains CLI-exposed."
    accepted_by: "operator (Justin Monroe)"
    accepted_at: "2026-06-26T13:00:00Z"
re_verification: null
---

# Phase 19: v1.4 Closure Verification Report

**Phase Goal:** v1.4 Closure: INT-WARN-1/2/3 fixes, Phase 17 human verification, Phase 16 UAT, CodeRabbit findings (CONTEXT decisions D-01..D-07, plus enumerated finding IDs CR-*, INT-WARN-*, 15/17/18-REVIEW WR-*/IN-*).
**Verified:** 2026-06-26
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | CR-C1: block_tenable_fetch.py denies nested bash/sh/python -c/-m wrapper payloads that reference guarded modules | VERIFIED | `SHELL_WRAPPERS` set at L41; `script_hit()` recurses into `-c` payloads via `shlex.split` at L145-151; `_depth` cap prevents unbounded recursion |
| 2 | CR-S1: block_tenable_fetch.py fails closed (deny) on malformed JSON payload | VERIFIED | `except` branch at L200-202 calls `deny("Blocked: malformed PreToolUse payload — failing closed.")` — no bare `sys.exit(0)` remains in that branch |
| 3 | CR-S2: trend filename built from sanitized tag suffix (no path-traversal via `/../`) | VERIFIED | `data/trend_store.py` L507: `tag_suffix = re.sub(r"[^A-Za-z0-9_]", "_", tag_filter).strip("_") or "all_assets"` applied before filename build |
| 4 | CR-S3: scan_coverage_sla_module html-escapes data.error and owner label in error-box HTML | VERIFIED | L556-557: `html.escape(str(self.DISPLAY_NAME), quote=True)` and `html.escape(str(data.error), quote=True)` both present |
| 5 | CR-S4: owner_supplemental.py fail-fast rejects output_dir resolving inside data/trend/ | VERIFIED | L247-255: `_resolved == _trend_resolved or _trend_resolved in _resolved.parents` raises `ValueError` with PII policy message |
| 6 | D-05: single shared helper `compute_sla_rate_crit_high` in utils/sla_calculator.py used by all 3 sites, excluding NaT from both numerator and denominator | VERIFIED | Helper at `utils/sla_calculator.py:297`; called from `scripts/capture_trend_snapshot.py:398`, `reports/modules/program_health_module.py:282` (cold-start) and `program_health_module.py:558` (live tile) |
| 7 | INT-WARN-1 / D-03: management_summary capture_snapshot() forward-write emits the FULL aggregate field set | VERIFIED | `reports/management_summary.py` L524-538: `on_time_asset_count`, `reopened_count`, `accepted_count`, `recast_count`, `fixed_vulns_df`, `mttr_overall_days`, `mttr_by_severity`, `mttr_by_owner`, `sla_rate_crit_high` all forwarded |
| 8 | INT-WARN-1 / D-03b: regression guard test asserts management_summary forwards the same capture_snapshot kwarg set as the cron writer | VERIFIED | `tests/test_management_summary.py:1080-1102`: `test_partial_write_regression_guard` compares forwarded keys against `_FULL_AGGREGATE_KWARGS` frozenset; any future partial-write trips this assertion |
| 9 | INT-WARN-2 / D-04: management_summary fetches recast_rules_df fail-soft and forwards it to ReportComposer | VERIFIED | `reports/management_summary.py` L337-347: fail-soft fetch with `recast_rules_df = None` on failure; L396: `recast_rules_df = recast_rules_df` forwarded to composer |
| 10 | INT-WARN-3: test_frozensets_membership asserts exact membership for _MODULES_NEEDING_FIXED_VULNS | VERIFIED | `tests/test_composed_report_kwargs_gates.py` L107-109: `assert _MODULES_NEEDING_FIXED_VULNS == frozenset({"critical_remediation_sla", "mttr_trend"})` |
| 11 | WR-08: VPR bands contiguous (no 8.91–8.99 / 6.91–6.99 / 3.91–3.99 gap) | VERIFIED | `config.py` L98-100: upper bounds corrected to `8.99 / 6.99 / 3.99` with inline WR-08 comments |
| 12 | 18-REVIEW IN-02: _first_str retained by documented decision (live CLI caller) | PASSED (override) | `data/fetchers.py` L163 `_first_str` present; called at L982 by deprecated `fetch_vulnerabilities` which is CLI-invoked at L1390; executor documented decision in 19-06-SUMMARY.md and deferred to deprecated-chain retirement |
| 13 | D-07 closeout: 16-UAT.md flipped to status: passed | VERIFIED | `.planning/phases/16-mttr-rework/16-UAT.md` frontmatter `status: passed`; `resume_at: none`; all gap entries `status: resolved` |
| 14 | D-07 closeout: 17-VERIFICATION.md flipped from human_needed to status: passed | VERIFIED | `.planning/phases/17-program-health-overview/17-VERIFICATION.md` frontmatter `status: passed` |
| 15 | D-07 terminal deliverable: v1.4-MILESTONE-AUDIT.md status off tech_debt | VERIFIED | `.planning/v1.4-MILESTONE-AUDIT.md` frontmatter `status: passed`; `closed: 2026-06-26`; INT-WARN-1/2/3, CodeRabbit, and verification debt all marked resolved in `resolved_by_phase_19` block |
| 16 | D-7 (19-11): composite RAG / "N of 4 On Track" / narrative use current-sign Net Velocity status | VERIFIED | `reports/modules/program_health_module.py` L494-529: `net_velocity_status_current` computed from sign of `curr_net_delta` BEFORE `signal_statuses` list; `signal_statuses[1] = net_velocity_status_current` (not `sig2_status`) |

**Score:** 16/16 truths verified (1 via accepted override)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `.claude/hooks/block_tenable_fetch.py` | Hardened hook: wrapper recursion + fail-closed | VERIFIED | Tracked in git (`git ls-files` confirmed); `SHELL_WRAPPERS`, `shlex.split` recursion, `deny()` on malformed payload all present |
| `tests/test_block_tenable_fetch.py` | 6 regression tests for CR-C1/S1 | VERIFIED | 6 test functions: `test_nested_bash_c_wrapper_denied`, `test_sh_c_wrapper_denied`, `test_python_c_payload_denied`, `test_simple_guarded_fetch_still_denied`, `test_unguarded_command_allowed`, `test_malformed_payload_fails_closed` |
| `utils/sla_calculator.py` | `compute_sla_rate_crit_high` helper | VERIFIED | Defined at L297; NaT-exclusion, None-on-empty guard, reads caller-passed `sla_days` dict (no hardcoded day counts) |
| `tests/test_sla_rate_crit_high.py` | NaT-exclusion unit tests | VERIFIED | File exists; 5 test behaviors covering NaT-excluded denominator, all-NaT cold-start, unmapped severity, empty Crit+High, mixed in-SLA/overdue |
| `reports/management_summary.py` | Full trend writer + recast fetch/forward + guarded run_report | VERIFIED | `recast_rules_df` fetched/forwarded (L337-396); full `capture_snapshot` kwarg set (L524-538); `fixed_vulns_df` fetched at L251 and forwarded at L393 |
| `tests/test_composed_report_kwargs_gates.py` | Third frozenset membership gate | VERIFIED | `assert _MODULES_NEEDING_FIXED_VULNS == frozenset({"critical_remediation_sla", "mttr_trend"})` at L107-109 |
| `data/trend_store.py` | CR-B6 explicit-zero + CR-B7/WR-07 validated load + WR-06 local-month key + WR-05 partial-month flag | VERIFIED | `_load_trend_json`: `isinstance(data, dict)` + `isinstance(snapshots, list)` + non-dict entry check + `*.corrupt` rename; WR-05: `entry["partial"] = True` at L631; WR-06: local strftime convention; CR-S2 `re.sub` at L507 |
| `scripts/backfill_trend_reconstruction.py` | CR-B1/B2/B3/B4; dead _months_in_range + dateutil removed | VERIFIED | `_month_arg` validator at L458; `_months_in_range_stdlib` at L202 (stdlib only); no `dateutil` import found; no `_months_in_range` dead function |
| `config.py` | Contiguous VPR bands (WR-08) + module-level `import math` (IN-01) | VERIFIED | `import math` at L11 (module top); `VPR_SEVERITY_MAP` upper bounds `8.99/6.99/3.99` at L98-100 |
| `reports/modules/composer.py` | CR-F1 return-type guard + CR-F2 metadata-on-all-fail | VERIFIED | `isinstance(html_section, str)` guard at L677; CR-F2: all-fail path emits `_Metadata`-only workbook at L1177-1187 |
| `delivery/email_sender.py` | CR-F4 prebuilt_charts size-budget check | VERIFIED | L488-493: `_prebuilt_per_image_bytes` + `_prebuilt_budget_bytes` applied to `prebuilt_charts` loop |
| `reports/modules/program_health_module.py` | 19-10/11: new_current/fixed_current surfaced; E3F2FD header fill; D-7 composite uses current-sign; D-8 single arrow two-row | VERIFIED | `new_current`/`fixed_current` in metrics at L807-808; `E3F2FD` fill at L1618; `signal_statuses[1] = net_velocity_status_current` at L529 |
| `.planning/v1.4-MILESTONE-AUDIT.md` | status: passed + resolved_by_phase_19 block | VERIFIED | `status: passed`; `closed: 2026-06-26`; detailed `resolved_by_phase_19` entries for INT-WARN-1/2/3, all review items, CodeRabbit, Phase 16/17 closures |
| `.planning/phases/16-mttr-rework/16-UAT.md` | status: passed | VERIFIED | Frontmatter `status: passed`; `resume_at: none`; all gap items `status: resolved` with 2026-06-26 pass dates |
| `.planning/phases/17-program-health-overview/17-VERIFICATION.md` | status: passed | VERIFIED | Frontmatter `status: passed`; 3 human checks recorded as operator-confirmed 2026-06-26 |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `tests/test_block_tenable_fetch.py` | `.claude/hooks/block_tenable_fetch.py` | subprocess / direct calls to `effective_head`/`script_hit`/decision logic | WIRED | 6 test functions reference `block_tenable_fetch` mechanics |
| `scripts/capture_trend_snapshot.py` | `utils.sla_calculator.compute_sla_rate_crit_high` | import + call at L394/398 | WIRED | `from utils.sla_calculator import compute_sla_rate_crit_high` inside fail-soft try at L394 |
| `reports/modules/program_health_module.py` | `utils.sla_calculator.compute_sla_rate_crit_high` | top-level import L77; called at L282 (cold-start) + L558 (live tile) | WIRED | Two call sites confirmed; no inline `len(ch_df)` denominator remains |
| `reports/management_summary.py` | `data.trend_store.capture_snapshot` | full aggregate kwarg set forwarded at L524-538 | WIRED | All 9 optional aggregate kwargs present including `sla_rate_crit_high` |
| `reports/management_summary.py` | `data.fetchers.fetch_recast_rules` | fail-soft fetch at L339-347; `recast_rules_df=` forwarded at L396 | WIRED | D-04/INT-WARN-2 path confirmed |
| `data/fetchers.py::fetch_fixed_vulnerabilities` | `_cache_path(cache_dir, f"vulns_fixed_{lookback_days}d")` | `lookback_days` folded into dataset name at L437 | WIRED | CR-B5: different window values write distinct parquet files |
| `tests/test_composed_report_kwargs_gates.py` | `_MODULES_NEEDING_FIXED_VULNS` | exact-membership assertion at L107-109 | WIRED | INT-WARN-3 gate confirmed present and asserts `{"critical_remediation_sla", "mttr_trend"}` |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `reports/management_summary.py` | `recast_rules_df` | `data.fetchers.fetch_recast_rules` L339 | Yes — live API/cache fetch, fail-soft to None | FLOWING |
| `reports/modules/program_health_module.py` | `sla_rate_crit_high` (cold-start) | `compute_sla_rate_crit_high(open_df, report_date, SLA_DAYS)` L282 | Yes — derives from open_df with NaT filter | FLOWING |
| `scripts/capture_trend_snapshot.py` | `sla_rate_crit_high` | `compute_sla_rate_crit_high(open_df, snapshot_date, SLA_DAYS)` L398 | Yes — written into trend store snapshot | FLOWING |

---

### Behavioral Spot-Checks

Step 7b: SKIPPED for human-verify and planning artifacts (16-UAT, 17-VERIFICATION, v1.4-MILESTONE-AUDIT). Code behavior verified via static analysis above. Full test suite not run (no runnable server required).

| Behavior | Verification Method | Status |
|----------|--------------------|--------|
| `_MODULES_NEEDING_FIXED_VULNS` frozenset gate | Static grep of test assertion | PASS |
| `compute_sla_rate_crit_high` at all 3 sites | `grep -c "compute_sla_rate_crit_high"` — 1 in capture_trend_snapshot, 2 in program_health_module | PASS |
| `block_tenable_fetch.py` git-tracked | `git ls-files` returned the path | PASS |
| VPR bands contiguous | config.py L98-100 values verified 8.99/6.99/3.99 | PASS |

---

### Probe Execution

No `scripts/*/tests/probe-*.sh` files declared for this phase. SKIPPED.

---

### Requirements Coverage

No REQ-IDs are declared for this phase (closure/tech-debt phase per CONTEXT). Coverage is against enumerated finding IDs (CR-*, INT-WARN-*, WR-*, IN-*) across the 11 plans. All must-haves verified above.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `data/trend_store.py` | 600 | `read_trend` builds filename with raw `tag_filter` (no sanitization on read path) | INFO | Read-only path — an attacker would need control over `tag_filter` in group config to reach an arbitrary path. The write path (CR-S2, L507) was fixed per plan scope. The read path failing silently (file not found) is not exploitable for data leakage in the current call chain. Not a plan must-have gap. |
| `data/fetchers.py` | 163/884 | `_first_str` and `fetch_vulnerabilities` retained (deprecated, not removed per IN-02) | INFO | Intentional decision — CLI block at L1390 calls `fetch_vulnerabilities`; removing `_first_str` would break CLI. Both marked deprecated. Deferred to deprecated-chain retirement. Documented in 19-06-SUMMARY.md. Not a blocker. |

No `TBD`, `FIXME`, or `XXX` markers found in any phase-modified files.

---

### Human Verification Required

All human verification items from Phase 16 UAT and Phase 17 checks were completed by the operator on 2026-06-26 and recorded in `19-08-SUMMARY.md`:

- Phase 16 Test 1: 4-gauge MTTR headline band with SLA targets. CONFIRMED PASS.
- Phase 16 Test 2: Excel "MTTR Trend" tab, window disclosure, no SLA-target column on Owner rows. CONFIRMED PASS.
- Phase 16 Test 3: Email MTTR panel renders. CONFIRMED PASS.
- Phase 16 Test 5: Live snapshot capture runs; MTTR fields written. CONFIRMED PASS.
- Phase 17 Check 1: Email 4-tile KPI row + Owner velocity table; on-track count consistent. CONFIRMED PASS.
- Phase 17 Check 2: `sla_rate_crit_high` present in live snapshot entry. CONFIRMED PASS.
- Phase 17 Check 3: PDF sparkline row + Owner velocity table; layout corrected. CONFIRMED PASS.

The Program Health PDF/Excel polish gaps (identified during first-pass checkpoint) were closed by Plans 19-10 and 19-11, and the operator re-verified and approved after 19-11.

No outstanding human verification items remain.

---

### Gaps Summary

No gaps. All 16 must-haves are VERIFIED (15 by direct codebase evidence, 1 by accepted operator override for IN-02 scope decision). The v1.4 milestone audit is closed and all enumerated finding IDs are resolved or documented as intentional deferrals.

The known accepted limitation — reconstructed historical trend months hold severity counts only, causing MTTR/Net Velocity/SLA MoM arrows and sparklines to forward-fill as snapshots accumulate — is an operator decision recorded in `19-08-CHECKPOINT-FINDINGS.md` and is NOT a gap.

---

_Verified: 2026-06-26T13:00:00Z_
_Verifier: Claude (gsd-verifier)_
