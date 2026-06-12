---
phase: 16
slug: mttr-rework
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-12
---

# Phase 16 — Validation Strategy

> Reconstructed retroactively (State B — from SUMMARY artifacts) after Nyquist validation
> was enabled post-execution. Phase 16 was planned/executed with Nyquist off, so this
> contract documents the as-built coverage and fills the two regression-suite gaps found
> in the Plan 16-01 data-persistence layer.

Requirement under validation: **RPT-05** (reworked, reopened-aware MTTR).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.x |
| **Config file** | `pytest.ini` |
| **Quick run command** | `python -m pytest tests/content/test_trend_store.py tests/test_mttr_trend_module.py -x` |
| **Full suite command** | `python -m pytest tests/ -x` |
| **Estimated runtime** | ~6 s (MTTR subset); full suite longer |

---

## Sampling Rate

- **After every task commit:** Run the quick run command
- **After every plan wave:** Run the full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~10 seconds (MTTR subset)

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 16-01-01 | 01 | 1 | RPT-05 | T-16-01 | Aggregate-only MTTR floats + internal Owner tag names persisted (PII-safe); fields written explicitly | unit | `pytest tests/content/test_trend_store.py::test_mttr_aggregate_fields_written` · `::test_mttr_params_default_to_none` | ✅ | ✅ green |
| 16-01-02 | 01 | 1 | RPT-05 | T-16-03 | Fail-soft rolling-window reopened-aware compute (D-16-02) — failure writes null, snapshot still completes | smoke | `python scripts/capture_trend_snapshot.py --dry-run` | ✅ | ⚠️ manual-only (see below) |
| 16-01-03 | 01 | 1 | RPT-05 | — | D-16-09 implicit-optional-field: old snapshot lacking MTTR fields reads back cold-start (None/{}) — no KeyError | unit | `pytest tests/content/test_trend_store.py::test_old_snapshot_readable_without_mttr_fields` | ✅ | ✅ green |
| 16-02-01 | 02 | 2 | RPT-05 | T-16-05 / T-16-06 | Four-channel reopened-aware MTTR (D-16-01/02/04/06/07/08); dual cold-start; aggregate-only render | unit | `pytest tests/test_mttr_trend_module.py` | ✅ | ✅ green |
| 16-02-02 | 02 | 2 | RPT-05 | T-16-11 | mttr_trend in BOTH fan-out frozensets — receives non-None fixed_vulns_df + trend_snapshots (no silent gray RAG) | unit | `pytest tests/test_mttr_trend_module.py::TestComposedPipelineFixedVulns` | ✅ | ✅ green |
| 16-03-01 | 03 | 3 | RPT-05 | T-16-08 | Criterion-3 lodestar (reopened clock → ~8d not 198) + cold-start/min_sample/Owner-drift/tie-break/partial-month/four-channel guards | unit | `pytest tests/test_mttr_trend_module.py` | ✅ | ✅ green |
| 16-03-02 | 03 | 3 | RPT-05 | T-16-08 | Structural-only smoke baselines (populated + zero-match), self-guarded; no metric values committed | unit | `pytest tests/test_mttr_trend_module.py -k baseline` | ✅ | ✅ green |
| 16-03-03 | 03 | 3 | RPT-05 | T-16-09 | board_summary structural baselines byte-identical after Phase 16 (D-16-10 zero-diff) | unit | `pytest tests/test_board_summary_baseline.py` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky/manual*

---

## Wave 0 Requirements

Existing infrastructure (pytest + `pytest.ini`) covers all phase requirements. The two
regression-suite gaps found at validation time were filled by appending three tests to the
existing `tests/content/test_trend_store.py`:

- ✅ `test_mttr_aggregate_fields_written` — GAP-1: capture_snapshot writes the three MTTR fields (float + dict round-trip)
- ✅ `test_mttr_params_default_to_none` — GAP-1 companion: omitted kwargs write explicit `None` (D-16-09 convention)
- ✅ `test_old_snapshot_readable_without_mttr_fields` — GAP-2: D-16-09 cold-start read-back promoted from the `__main__` smoke block into the collected suite

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `scripts/capture_trend_snapshot.py` rolling-window reopened-aware MTTR aggregate compute (D-16-02 clock, durably-fixed filter, min_sample, per-Owner) | RPT-05 | The D-16-02 date math is inline in the script's `main()` with no testable seam; extracting it for a unit test would require refactoring an implementation file, which validation may not do. **Compensating automated coverage:** the identical D-16-02 algorithm in the consuming module IS unit-tested by `TestCriterion3ReopenedClock` (reopened finding → ~8d not 198) in `tests/test_mttr_trend_module.py`. This entry is the script-copy's structural gap only — defense-in-depth, not a requirement gap. | `python scripts/capture_trend_snapshot.py --dry-run` exits 0 with an info line reporting the computed MTTR aggregate (keys only, PII-safe). For a behavioral check, run a live snapshot and confirm `data/trend/trend_severity_all_assets.json` newest entry carries non-null `mttr_overall_days` when ≥5 durable fixes exist in the 30-day window. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or are recorded manual-only with compensating coverage
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (GAP-1, GAP-2 filled)
- [x] No watch-mode flags
- [x] Feedback latency < 10s (MTTR subset)
- [x] `nyquist_compliant: true` — RPT-05 has automated verification across the writer (trend_store) and reader (module) layers; the single manual-only entry is a duplicate compute path, not an uncovered requirement

**Approval:** approved 2026-06-12

---

## Validation Audit 2026-06-12

| Metric | Count |
|--------|-------|
| Requirements | 1 (RPT-05) |
| Tasks mapped | 8 |
| Gaps found | 3 |
| Resolved (automated tests added) | 2 (GAP-1, GAP-2) |
| Escalated to manual-only | 1 (GAP-3 — capture-script compute, compensated by module `TestCriterion3`) |
| Tests added | 3 (in `tests/content/test_trend_store.py`) |
| New-test result | 26 passed (23 pre-existing + 3 new), 0 failed |
