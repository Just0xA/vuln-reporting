---
phase: 14-shared-substrates-composed-report-gates
verified: 2026-06-11T18:33:46Z
status: passed
score: 4/4
overrides_applied: 0
---

# Phase 14: Shared Substrates & Composed-Report Gates — Verification Report

**Phase Goal:** The foundational pure-compute helpers and kwargs forwarding gates are in place so every v1.4 module can consume trend history, recast rules, and scope-computation results without I/O inside compute().
**Verified:** 2026-06-11T18:33:46Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #   | Truth | Status | Evidence |
|-----|-------|--------|----------|
| 1 | `utils/external_scope.py` classifies an asset as external when it carries `Location=External` OR `Location=DMZ` tag OR has a public IPv4 (is_global covering CGNAT, loopback, link-local); emits `(scoped_df, mismatches_df)` matching the `extract_owner()` tuple shape; unit-tested against CGNAT, loopback, IPv6 link-local, untagged/mismatched cases | VERIFIED | File exists (248 lines), substantive, implements all branches. `is_public_ipv4` uses `ipaddress.ip_address().is_global`, `try/except (ValueError, TypeError)`. Tag auth via `_has_location_tag` (casefold cat + exact DMZ/External value). WR-03 post-review fix (commit 8b0d466) adds `asset_uuid` to required-column guard. 37 tests in `test_external_scope.py` pass (including `test_missing_asset_uuid_column_failsoft`). `is_public_ipv4("100.64.0.1") is False`, `is_public_ipv4("fe80::1") is False` confirmed via spot-check. |
| 2 | `utils/asset_count.py` returns the licensed asset count from `assets_df` via a pure function; unit-tested including zero-asset guard; `ON_TIME_SCAN_WINDOW_DAYS = 30` in `config.py` as single canonical constant (D-13); returns `None` sentinel (D-14) not `0`; no `datetime.now()` inside (D-12) | VERIFIED | File exists (179 lines). `count_on_time_assets(assets_df, report_date, window_days=ON_TIME_SCAN_WINDOW_DAYS)` signature confirmed. No executable `reports.modules` import. WR-01 post-review fix (commit 69b4684) adds tz-naive column coerce + regression test (`test_tz_naive_column_does_not_raise`). `config.ON_TIME_SCAN_WINDOW_DAYS == 30` confirmed. 15 tests in `test_asset_count.py` pass including: None sentinel (all-stale, empty, missing-column), window-boundary inclusive/exclusive, injected-date purity, default-window config tie, tz-naive coerce. |
| 3 | `composed_report.py` gains `_MODULES_NEEDING_TREND_SNAPSHOTS` and `_MODULES_NEEDING_RECAST_RULES` frozensets with conditional fetch blocks following the existing `_MODULES_NEEDING_FIXED_VULNS` pattern; `run_report()` signature unchanged; existing composed-report groups pass `--dry-run` with no regression | VERIFIED | Lines 85–90: both frozensets `frozenset({"sc4_kwargs_stub"})`. Lines 206–245: `need_trend` and `need_recast` conditional fetch blocks with `try/except` fail-soft wrappers (WR-02, commit bf3dc7e). `run_report()` signature has no `trend_snapshots`/`recast_rules_df` parameters — confirmed via `inspect.signature` check and `test_run_report_signature_unchanged`. `composer.py` and `base.py` byte-unchanged per SUMMARY/Task 4 checkpoint (human-approved). `_sanitise_tag_for_filename` convention used for tag_filter (not raw `_log_scope` space form). |
| 4 | `read_trend()` result and `recast_rules_df` arrive at module `compute()` via `**self._kwargs` fan-out — verified by stub module asserting both kwargs present when listed in the frozensets | VERIFIED | `sc4_kwargs_stub_module.py` (96 lines) auto-discovered via `*_module.py` glob + `@register_module`. `compute(**kwargs)` checks `kwargs.get("trend_snapshots")` and `kwargs.get("recast_rules_df")`; returns `_empty_result` fail-soft when either is missing. `test_stub_compute_receives_both_kwargs` passes with `result.error is None` and `trend_snapshot_count == 2`, `recast_rules_row_count == 2`. Gate intersection logic confirmed: `_MODULES_NEEDING_TREND_SNAPSHOTS.intersection(["some_other_module"])` is falsy. `test_gate_fetch_failure_does_not_propagate` proves WR-02 fail-soft. NOT registered in `run_all.py` (confirmed: `grep sc4_kwargs_stub run_all.py` → not found). |

**Score:** 4/4 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `utils/external_scope.py` | `external_scope()` + `is_public_ipv4()`, min 60 lines | VERIFIED | 248 lines, substantive, all branches implemented |
| `tests/test_external_scope.py` | Unit tests covering all classifier branches | VERIFIED | 37 tests, all pass; monkeypatched positive case (D-18); CoW strict mode enabled |
| `config.py` | `ON_TIME_SCAN_WINDOW_DAYS = 30` constant | VERIFIED | Line 41, between SLA_DAYS and SEVERITY_ORDER, labeled comment block |
| `utils/asset_count.py` | `count_on_time_assets()`, min 40 lines, pure | VERIFIED | 179 lines; no `datetime.now()`, no `reports.modules` import |
| `tests/test_asset_count.py` | 15 tests covering all behavior cases | VERIFIED | 15 tests pass; tz-naive regression test included (WR-01) |
| `reports/composed_report.py` | Two new frozensets + two conditional fetch blocks | VERIFIED | Lines 85–90, 206–245, 346–349; fail-soft try/except on both gates |
| `reports/modules/sc4_kwargs_stub_module.py` | SC#4 stub asserting both kwargs, auto-discovered | VERIFIED | 96 lines; `MODULE_ID = "sc4_kwargs_stub"`; not in `run_all.py` |
| `tests/test_composed_report_kwargs_gates.py` | 9+ tests proving D-15/D-16/D-17/SC#3/SC#4 | VERIFIED | 11 tests; includes WR-02 gate-fetch-failure fail-soft test |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `utils/external_scope.py` | `ipaddress.ip_address().is_global` | `is_public_ipv4` stdlib classifier | WIRED | Line 85: `addr = ipaddress.ip_address(ip_str); return addr.version == 4 and addr.is_global` |
| `utils/external_scope.py` | `assets_df['tags']` + `assets_df['ipv4']` columns | `_has_location_tag` + `is_public_ipv4` per-row | WIRED | Lines 179–183: `assets_df["tags"].apply(_has_location_tag)`, `assets_df["ipv4"].apply(is_public_ipv4)` |
| `utils/asset_count.py` | `config.ON_TIME_SCAN_WINDOW_DAYS` | `from config import ON_TIME_SCAN_WINDOW_DAYS` | WIRED | Line 37: direct import; default arg on line 48 |
| `utils/asset_count.py` | `assets_df['last_licensed_scan_date']` + injected `report_date` | cutoff computation | WIRED | Lines 111–141: licensed filter, tz-normalize, `lsd >= cutoff` |
| `reports/composed_report.py trend gate` | `data.trend_store.read_trend()` | lazy import + call | WIRED | Lines 214–224: `from data.trend_store import read_trend, _sanitise_tag_for_filename`; call with `dimension="severity"`, `months=13`, correct tag_filter |
| `reports/composed_report.py recast gate` | `data.fetchers.fetch_recast_rules()` | lazy import + call | WIRED | Lines 238–240: `from data.fetchers import fetch_recast_rules`; call with `(tio, cache_dir)` |
| `reports/composed_report.py composer_kwargs` | `ReportComposer **self._kwargs -> compute()` | conditional append + fan-out | WIRED | Lines 346–349: `if trend_snapshots is not None: composer_kwargs["trend_snapshots"] = ...`; `if recast_rules_df is not None: composer_kwargs["recast_rules_df"] = ...` |
| `sc4_kwargs_stub_module.py` | `kwargs.get("trend_snapshots")` / `kwargs.get("recast_rules_df")` | `compute()` kwarg assertion | WIRED | Lines 57–58: both kwargs read; lines 61–71: fail-soft on missing |

---

### Data-Flow Trace (Level 4)

These are pure-compute library functions and an acceptance-test stub — not components that render dynamic UI data. Level 4 data-flow is not applicable. The outputs are scalar (`int | None`), DataFrames returned to callers, and kwargs passed through `**self._kwargs`. Data flows verified at Level 3 (wired) via the test suite.

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `is_public_ipv4` negatives (CGNAT, loopback, IPv6, malformed) | `python -c "from utils.external_scope import is_public_ipv4; assert is_public_ipv4('100.64.0.1') is False; assert is_public_ipv4('fe80::1') is False; assert is_public_ipv4('bad') is False; assert is_public_ipv4(None) is False"` | pass | PASS |
| `external_scope` empty-input guard | `python -c "import pandas as pd; from utils.external_scope import external_scope; a,b=external_scope(pd.DataFrame()); assert len(a)==0 and len(b)==0"` | pass | PASS |
| `config.ON_TIME_SCAN_WINDOW_DAYS == 30` | `python -c "import config; assert config.ON_TIME_SCAN_WINDOW_DAYS == 30"` | 30 | PASS |
| Frozensets seeded + signature unchanged | `python -c "import reports.composed_report as c; assert c._MODULES_NEEDING_TREND_SNAPSHOTS == frozenset({'sc4_kwargs_stub'}); import inspect; assert 'trend_snapshots' not in inspect.signature(c.run_report).parameters"` | pass | PASS |
| SC#4 stub auto-discovered | `python -c "import reports.modules; from reports.modules.sc4_kwargs_stub_module import Sc4KwargsStubModule; assert Sc4KwargsStubModule.MODULE_ID == 'sc4_kwargs_stub'"` | pass | PASS |
| stub NOT in run_all.py (D-17) | `grep sc4_kwargs_stub run_all.py` | no output | PASS |

---

### Probe Execution

No probes declared in PLANs. Step 7c: SKIPPED (no `scripts/*/tests/probe-*.sh` for this phase).

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SUB-01 | 14-01-PLAN.md | External-scope helper classifies by tag/IP; emits mismatch list | SATISFIED | `utils/external_scope.py` + `tests/test_external_scope.py`; 37 tests pass |
| SUB-02 | 14-02-PLAN.md | Asset-count denominator helper; on-time-scanned basis; pure function | SATISFIED | `utils/asset_count.py` + `config.ON_TIME_SCAN_WINDOW_DAYS`; 15 tests pass |
| SUB-03 | 14-03-PLAN.md | composed_report.py gains kwargs-forwarding frozensets for trend + recast | SATISFIED | Both frozensets, both fetch blocks, WR-02 fail-soft; 11 tests pass |

All three requirements from REQUIREMENTS.md are marked complete in the traceability table. No orphaned requirements for this phase.

---

### Post-Review Hardening (QUAL-03 "never raises" contract)

Three post-review fixes were applied after the initial TDD GREEN commits. All are confirmed present and covered by regression tests:

| Commit | Fix | Regression Test |
|--------|-----|----------------|
| `69b4684` | WR-01: `last_licensed_scan_date` tz-naive column coerced to UTC before cutoff compare (avoids `TypeError: Cannot compare tz-naive and tz-aware`) | `test_tz_naive_column_does_not_raise` in `test_asset_count.py` |
| `8b0d466` | WR-03: `asset_uuid` added to required-column guard in `external_scope()` (avoids `KeyError` when gap branch runs on a partial export) | `test_missing_asset_uuid_column_failsoft` in `test_external_scope.py` |
| `bf3dc7e` | WR-02: trend + recast gate fetches wrapped in `try/except` so a fetch failure degrades to "kwarg absent" rather than aborting the group bundle | `test_gate_fetch_failure_does_not_propagate` in `test_composed_report_kwargs_gates.py` |

All three regression tests pass in the combined 63-test run. The QUAL-03 "never raises" contract holds for all three fail-soft paths.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `utils/asset_count.py` | 12, 70 | `datetime.now` appears in docstring comments only | Info | Not executable code — D-12 compliance confirmed via import check (`grep -n "^import\|^from" utils/asset_count.py | grep reports.modules` → clean) |
| `utils/external_scope.py` | 36 | `reports.modules` appears in docstring only | Info | Not executable code — confirmed clean via import-only grep |

No `TBD`, `FIXME`, or `XXX` markers in any phase-14 file. No stub returns (`return null`, `return {}`, `return []`) in production paths. No hardcoded empty data in wired paths.

---

### Human Verification Required

None. All success criteria are verifiable programmatically:

- Pure-compute helpers have no UI, no email channel, no visual layout.
- The SC#4 stub's kwarg-forwarding is fully verified by the unit test suite.
- The `--dry-run` no-regression check (Task 4, Plan 03) was approved by the human operator during execution and is recorded in the SUMMARY frontmatter (`key-decisions`).

No items requiring human testing were identified.

---

### Gaps Summary

No gaps. All 4 must-have truths are VERIFIED, all 8 required artifacts exist and are substantive and wired, all 8 key links confirmed present. The three post-review hardening commits are in the git log and their regression tests pass. The 63-test combined suite exits 0.

---

## Final Status

**PASSED** — Phase 14 goal achieved. All three SUB requirements delivered. Foundational substrates are in place for Phase 15 module consumption.

---

_Verified: 2026-06-11T18:33:46Z_
_Verifier: Claude (gsd-verifier)_
