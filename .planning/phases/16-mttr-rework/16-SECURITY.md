# SECURITY AUDIT — Phase 16: mttr-rework

**Audit Date:** 2026-06-12
**Phase:** 16 — mttr-rework (Plans 16-01, 16-02, 16-03)
**ASVS Level:** 1
**Block On:** OPEN_THREATS (high severity)
**Auditor Mode:** VERIFY-MITIGATIONS (threat register provided at plan time)

---

## Threat Verification Summary

**Threats Closed:** 12/12
**Threats Open:** 0/12
**Unregistered Flags:** 0

---

## Threat Register — Full Results

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-16-01 | Information Disclosure | mitigate | CLOSED | `data/trend_store.py:386-391` — new_entry stores only `mttr_overall_days` (float), `mttr_by_severity` (dict of floats), `mttr_by_owner` (dict keyed by Owner tag name). No hostnames, IPs, plugin names, or asset-level rows in any field. Docstring at line 308 explicitly states "Keys are internal Owner tag names only — never hostnames, IPs, or asset-level data (QUAL-05)". `data/trend/` confirmed gitignored at `.gitignore:12`. |
| T-16-02 | Tampering | accept | CLOSED | Rationale present in 16-01-PLAN.md threat model: "Forward-accumulating store, no schema_version, local-disk only. A tampered prior snapshot can skew a MoM delta but cannot crash the reader (cold-start guard). Low-value local target." No `schema_version` field confirmed absent via plan acceptance criterion. |
| T-16-03 | Denial of Service | mitigate | CLOSED | `scripts/capture_trend_snapshot.py:305-382` — entire MTTR aggregate block wrapped in `try/except Exception` at line 379. On except: `logger.warning("MTTR aggregate computation failed — fields will cold-start: %s", exc)` and all three variables reset to None (line 382). The `capture_snapshot()` call at lines 384-395 proceeds unconditionally after the except block. Comment at line 299 explicitly cites T-16-03. |
| T-16-04 | Tampering | accept | CLOSED | Rationale present in 16-01-PLAN.md threat model: "No package installs in this plan — zero new dependencies (stdlib + already-pinned pandas only). No legitimacy gate required." 16-01-SUMMARY.md confirms `tech_stack.added: []`. |
| T-16-05 | Denial of Service | mitigate | CLOSED | `reports/modules/mttr_trend_module.py:279-709` — entire `compute()` body wrapped in `try/except Exception` at line 704 returning `self._empty_result(str(exc), config)`. Cold-start guard on `fixed_vulns_df` absent/empty at lines 303-308 (`_build_cold_start_result`). Cold-start guard on `trend_snapshots` at lines 286-298 (MoM-only cold-start, live gauges unaffected). Pitfall-B safe access `(snap.get("mttr_by_severity") or {}).get(sev)` at line 535; `(snap.get("mttr_by_owner") or {})` at lines 536, 542. |
| T-16-06 | Information Disclosure | mitigate | CLOSED | All four render channels confirmed aggregate-only. `compute()` output at lines 670-701: `metrics` contains only float/int/str/bool values; `table_data` rows contain only MTTR floats, SLA ints, status strings, sample counts, and Owner tag name strings (lines 574-611); `analyst_rows` DataFrames at lines 627-650 are aggregate-level (Severity/Owner label, MTTR days, SLA target, variance, status, sample size, MoM delta — no per-finding rows); `chart_data` at lines 616-622 contains only series of floats and month labels. No `asset_uuid`, `plugin_id`, hostname, or IP field survives into any render output. Owner cut via `extract_owner()` aggregates to owner name only. |
| T-16-07 | Tampering | accept | CLOSED | Rationale present in 16-02-PLAN.md threat model: "No package installs — zero new dependencies. No legitimacy gate required." 16-02-SUMMARY.md confirms `tech_stack.added: []`. |
| T-16-08 | Information Disclosure | mitigate | CLOSED | `tests/test_mttr_trend_module.py:51` — `_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"` (all-zero synthetic UUIDs). `pd.options.mode.copy_on_write = True` at line 42. `tests/baselines/mttr_trend_test_pull.json` confirmed structural-only (12 structural keys, `overall_mttr` key absent, verified by `assert 'overall_mttr' not in d` acceptance criterion). `tests/baselines/mttr_trend_test_pull_zero_match.json` same structural schema. Grep of baselines directory confirms no real IPs (`192.168.`, `10.0.`) — only README.md match was a documentation reference, not data. |
| T-16-09 | Tampering | mitigate | CLOSED | `tests/test_board_summary_baseline.py` — fingerprint-guard approach using hard-coded expected structural constants (`_EXPECTED_TEST_PULL`, `_EXPECTED_ANALYST_OFF`, `_EXPECTED_ZERO_MATCH` at lines 76-99). Any structural drift in board_summary (page count, RAG cell count, panel count, tab names) would fail `TestBoardSummaryBaselineZeroDiff`. Synthetic zero-match path uses `compare_snapshots(actual, load_baseline(...)) == []` as a live gate. `write_baseline()` confirmed absent from the file (per D-16-10). `grep -c "compare_snapshots" tests/test_board_summary_baseline.py` → 13 per SUMMARY verification. |
| T-16-10 | Tampering | accept | CLOSED | Rationale present in 16-03-PLAN.md threat model: "No package installs — zero new dependencies. No legitimacy gate required." 16-03-SUMMARY.md confirms `tech_stack.added: []`. |
| T-16-11 | Tampering | mitigate | CLOSED | `reports/composed_report.py:73-76` — `_MODULES_NEEDING_FIXED_VULNS = frozenset({"critical_remediation_sla", "mttr_trend"})` with inline comment `# D-16-01: MTTR population = durably-fixed findings; fixed_vulns is a hard input, not opportunistic`. `reports/composed_report.py:89-95` — `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset includes `"mttr_trend"` with comment `# D-16-03: reads rolling MTTR / MoM line from trend snapshots`. Test coverage: `tests/test_mttr_trend_module.py` `TestComposedPipelineFixedVulns.test_frozenset_membership_in_composed_report` asserts both memberships via direct import. |
| T-16-12 | Tampering | mitigate | CLOSED | `tests/test_mttr_trend_module.py:756-835` — `TestComposedPipelineFixedVulns` class provides two independent guards: (1) static frozenset membership assertion (lines 819-835) imports `_MODULES_NEEDING_FIXED_VULNS` and `_MODULES_NEEDING_TREND_SNAPSHOTS` and asserts `"mttr_trend" in` both; (2) compute-boundary guard (lines 787-817) drives `MTTRTrendModule.compute()` with 6 fixed findings and asserts `overall_mttr is not None` and `rag_status != "no_data"`. Both guards would fail if mttr_trend were dropped from the frozenset. |

---

## Accepted Risks Log

| Threat ID | Category | Component | Rationale |
|-----------|----------|-----------|-----------|
| T-16-02 | Tampering | snapshot integrity | Forward-accumulating local-disk store. No schema_version by design (D-16-09 implicit-optional convention). Tampered prior snapshot skews MoM delta but cold-start guard prevents crash. Low-value local target with no external attack surface. Documented in 16-01-PLAN.md threat model. |
| T-16-04 | Tampering | package installs (16-01) | Zero new dependencies in Plan 16-01. No package legitimacy gate required. Documented in 16-01-PLAN.md threat model. |
| T-16-07 | Tampering | package installs (16-02) | Zero new dependencies in Plan 16-02. No package legitimacy gate required. Documented in 16-02-PLAN.md threat model. |
| T-16-10 | Tampering | package installs (16-03) | Zero new dependencies in Plan 16-03. No package legitimacy gate required. Documented in 16-03-PLAN.md threat model. |

---

## Unregistered Flags

None. No new attack surface appeared during implementation that lacked a threat mapping.

---

## Audit Notes

**T-16-09 verification detail:** The board_summary zero-diff test uses a fingerprint-guard pattern rather than a live `compare_snapshots` for the populated and analyst_off baselines. This is a documented design deviation (16-03-SUMMARY.md) because those baselines were captured from real Tenable parquet cache and cannot be reproduced synthetically. The fingerprint-guard hard-codes expected values for the five most drift-sensitive structural fields (`pdf_page_count`, `pdf_rag_cell_count`, `email_panel_count`, `analyst_excel_present`, `rag_cells_all_no_data`). A live `compare_snapshots` gate is present for the zero-match variant. This is accepted as equivalent to the declared mitigation.

**T-16-12 verification detail:** The plan specified `run_full_pipeline`-level wiring as the primary path with `compute()` direct call as documented fallback. The implementation uses the compute()-boundary guard (documented fallback path), supplemented by the static frozenset-membership assertion. Both the 16-02 acceptance criterion (static assertion) and the 16-03 defense-in-depth (compute boundary) are present. The threat is CLOSED.
