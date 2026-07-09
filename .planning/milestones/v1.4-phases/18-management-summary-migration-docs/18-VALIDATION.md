---
phase: 18
slug: management-summary-migration-docs
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-18
---

# Phase 18 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest (existing; see pytest.ini, --strict-markers, pytest.mark.baseline) |
| **Config file** | `pytest.ini` |
| **Quick run command** | `python -m pytest tests/test_consumer_audit.py tests/test_backfill_reconstruction.py tests/test_management_summary.py -x` |
| **Full suite command** | `python -m pytest tests/ -x --ignore=tests/diagnose_*.py` |
| **Estimated runtime** | ~60–120 seconds (phase-scoped quick run ~20s) |

**Note (project_full_suite_test_collection_quirks):** the full suite has known
pre-existing collection crashes (level1/level2 standalone scripts) and 2
`_phase2_test_panel_boom` isolation failures that are NOT regressions. Verify
phase-scoped test files directly; do not gate on the boom failures.

---

## Sampling Rate

- **After every task commit:** Run the phase-scoped quick run command above (latency ~20s).
- **After every plan wave:** Run the relevant new test file(s) for that wave plus the touched module tests (test_mttr_trend_module, test_new_vs_remediated_module, test_board_summary_baseline, test_phase6_run_group_chrome).
- **Before `/gsd:verify-work`:** Phase-scoped files green + `python run_all.py --dry-run` exits 0 + both smoke scripts exit 0.
- **Max feedback latency:** 120 seconds.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 18-01-01 | 01 | 1 | QUAL-04 | T-18-01 | Baseline captures counts/IDs/booleans only, no PII | smoke | `python -c "import ast; ast.parse(open('scripts/smoke_management_summary_cutover.py',encoding='utf-8').read())"` | ❌ W0 | ⬜ pending |
| 18-01-02 | 01 | 1 | QUAL-04 | T-18-01 | Committed baseline PII-free; idempotent re-run | smoke | `python scripts/smoke_management_summary_cutover.py` | ❌ W0 | ⬜ pending |
| 18-02-01 | 02 | 1 | GEN-01 | T-18-04 | No silent metric drift; synthetic PII-free data | unit | `python -m pytest tests/test_consumer_audit.py -x` | ❌ W0 | ⬜ pending |
| 18-02-02 | 02 | 1 | GEN-01 | T-18-04 | Each consumer applies own explicit window; MTTR rolling-30 intact | unit | `python -m pytest tests/test_consumer_audit.py -k "consumer or mttr or new_vs or critical" -x` | ❌ W0 | ⬜ pending |
| 18-02-03 | 02 | 1 | GEN-01 | T-18-03 / T-18-05 | Bounded lookback; no credentials in logs | unit | `python -m pytest tests/test_consumer_audit.py -x` | ❌ W0 | ⬜ pending |
| 18-03-01 | 03 | 2 | GEN-01, QUAL-04 | T-18-07 | Reopened-aware predicate; overlap gate; PII-free synthetic | unit | `python -m pytest tests/test_backfill_reconstruction.py -x` | ❌ W0 | ⬜ pending |
| 18-03-02 | 03 | 2 | GEN-01, QUAL-04 | T-18-06 / T-18-08 | Immutable provenance; null asset_count; partial flag | unit | `python -m pytest tests/test_backfill_reconstruction.py -x` | ❌ W0 | ⬜ pending |
| 18-03-03 | 03 | 2 | GEN-01 | T-18-07 / T-18-09 | Overlap gate passes vs live before seeding | manual | Operator dry-run + seed checkpoint | N/A — checkpoint | ⬜ pending |
| 18-04-01 | 04 | 3 | GEN-01, QUAL-04 | T-18-12 / T-18-13 | Frozenset co-edit; module presence; no PII fixtures | unit | `python -m pytest tests/test_management_summary.py tests/test_phase6_run_group_chrome.py -x` | ❌ W0 | ⬜ pending |
| 18-04-02 | 04 | 3 | GEN-01, QUAL-04 | T-18-10 / T-18-11 / T-18-12 | Atomic removal, fail-soft, modular email | unit | `python -m pytest tests/test_management_summary.py -x && python run_all.py --dry-run` | ❌ W0 | ⬜ pending |
| 18-04-03 | 04 | 3 | QUAL-04 | T-18-12 | Structural smoke parity; legacy archived not deleted | smoke | `python scripts/smoke_management_summary_cutover.py` | ❌ W0 | ⬜ pending |
| 18-04-04 | 04 | 3 | GEN-01, QUAL-04 | T-18-10 | Seven sections + chrome + real-trend MoM + modular email | manual | Operator visual PDF/email UAT | N/A — checkpoint | ⬜ pending |
| 18-05-01 | 05 | 4 | DOC-02 | T-18-14 / T-18-15 | Auditor-reproducible; no PII examples | doc-grep | `python -c "..."` (required-token grep, see plan) | ❌ W0 | ⬜ pending |
| 18-05-02 | 05 | 4 | DOC-02 | T-18-15 | Reproducibility + disclosure accuracy | manual | Operator runbook review | N/A — checkpoint | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

All test files are created as the RED step of the plan that owns them (TDD-first),
so there is no separate Wave 0 plan — each test file is the first task of its plan:

- [ ] `scripts/smoke_management_summary_cutover.py` + `tests/baselines/management_summary_structural_baseline.json` — Plan 01 Task 1/2 (structural smoke baseline)
- [ ] `tests/test_consumer_audit.py` — Plan 02 Task 1 (consumer-audit no-drift + fetch-filter)
- [ ] `tests/test_backfill_reconstruction.py` — Plan 03 Task 1 (overlap, immutability, partial flag, null asset_count, reopened-aware)
- [ ] `tests/test_management_summary.py` — Plan 04 Task 1 (module presence, email_body_html, bespoke-removed, chrome kwargs, trend-forwarded)
- [ ] `tests/test_phase6_run_group_chrome.py` expected-set co-edit — Plan 04 Task 1 (frozenset gate, project_frozenset_gate_test_coupling)

Framework (pytest) already installed — no install needed.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 12mo reconstruction seeded + overlap gate vs live tenant | GEN-01 / D-18-09 | Needs live Tenable credentials + writes the real gitignored trend store | Plan 03 checkpoint: `--dry-run` overlap PASS, then seed once, then re-run writes 0 months |
| All seven sections render in chrome-aware migrated PDF + real-trend MoM + modular email | GEN-01 / QUAL-04 / roadmap criterion 4 | Cannot eyeball a rendered PDF/email programmatically | Plan 04 checkpoint: generate PDF, confirm 7 sections + chrome + non-cold-start MoM + modular email |
| Runbook auditor-reproducibility + disclosure accuracy | DOC-02 | Reproducibility-by-a-third-party is a human judgment | Plan 05 checkpoint: recompute 2 modules from the doc alone; confirm honesty disclosures match what shipped |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or are explicit manual checkpoints with Wave-0 RED tests preceding
- [x] Sampling continuity: no 3 consecutive tasks without automated verify (checkpoints are preceded by automated GREEN tests)
- [x] Wave 0 covers all MISSING references (each test file is the RED first task of its plan)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-18
