---
phase: 20
slug: config-language-loader-matrix
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-09
---

# Phase 20 — Validation Strategy

> Per-phase validation contract. Reconstructed from artifacts (State B) after phase completion; one MISSING gap filled during this audit.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Standalone `main()`/`_check(name, cond, hint)` harnesses (NOT pytest `test_*`). `pytest.ini` sets `testpaths = tests/unit tests/content tests/e2e` (excludes the `tests/` root) and `addopts = -q -n auto ...`, which hangs on single-file invocation — so phase-20 tests are run directly. |
| **Config file** | `pytest.ini` (present, but does not collect these tests by design) |
| **Quick run command** | `.venv/bin/python3 tests/test_config_loader.py` |
| **Full suite command** | `for t in test_config_loader test_generate_delivery_matrix test_effective_config_golden test_dry_run_surfacing; do .venv/bin/python3 tests/$t.py \|\| break; done` |
| **Estimated runtime** | ~5 seconds (all four harnesses) |

---

## Sampling Rate

- **After every task commit:** Run the relevant `tests/test_*.py` harness directly.
- **After every plan wave:** Run all four phase-20 harnesses.
- **Before `/gsd:verify-work`:** All four harnesses must exit 0.
- **Max feedback latency:** ~5 seconds.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 20-01 | 01 | 1 | CONF-01 | T-20-01/02 | Contact-ref + `defaults.analyst_mailbox` resolve into the concrete `email:` block; resolved config passes the unchanged schema | unit | `.venv/bin/python3 tests/test_config_loader.py` | ✅ | ✅ green |
| 20-01 | 01 | 1 | CONF-02 | — | Additive `extra_recipients` merge + defaults application | unit | `.venv/bin/python3 tests/test_config_loader.py` | ✅ | ✅ green |
| 20-01 | 01 | 1 | CONF-03 (loader) | T-20-05 | Global delivery-name uniqueness (dup→error/empty), inline-email rejection, deprecated `groups:` alias warns+loads | unit | `.venv/bin/python3 tests/test_config_loader.py` (G/H/J) | ✅ | ✅ green |
| 20-02 | 02 | 1 | CONF-03 / D-10 (dry-run surfacing) | T-20-06 | `run_all._dry_run` maps loader errors → red + exit 1, warnings → yellow + exit 0 (dup→1, undefined ref→1, inline→1, deprecated alias→0) | integration | `.venv/bin/python3 tests/test_dry_run_surfacing.py` | ✅ | ✅ green |
| 20-03 | 03 | 1 | CONF-05 | T-20-09 | Delivery matrix renders every delivery's name/owner/reports/schedule/filters/contact-NAME; **0** recipient addresses in markdown+html | unit | `.venv/bin/python3 tests/test_generate_delivery_matrix.py` | ✅ | ✅ green |
| 20-04 | 04 | 1 | QUAL-06 | T-20-14 | Two-way equality: legacy resolution == committed golden (byte-identical) AND migrated-twin == same golden; both pass unchanged schema; no `owner`/`contact` in golden group dicts | baseline | `.venv/bin/python3 tests/test_effective_config_golden.py` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. One gap surfaced during this
audit (CONF-03 / D-10 `_dry_run` surfacing) was filled with a new committed harness,
`tests/test_dry_run_surfacing.py`, replicating the existing `main()`/`_check` style.

---

## Manual-Only Verifications

All phase behaviors have automated verification.

*Note (not a gap): the pre-existing `--dry-run` rich Table at `run_all.py:501-535`
renders recipient addresses to the console — legacy single-file behavior outside
Phase 20's scope. The Phase 20 surfacing block it sits beside (`run_all.py:468-485`)
is the layer under automated test.*

---

## Validation Sign-Off

- [x] All tasks have automated verify (no Wave 0 dependencies outstanding)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (the one MISSING gap was filled)
- [x] No watch-mode flags
- [x] Feedback latency < 5s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-09

---

## Validation Audit 2026-07-09

| Metric | Count |
|--------|-------|
| Gaps found | 1 |
| Resolved | 1 |
| Escalated | 0 |

Gap: CONF-03 / D-10 — the `run_all._dry_run` directory-mode surfacing exit-code
contract was verified during execution only by an uncommitted scratchpad harness
(per 20-02-SUMMARY). Filled by `tests/test_dry_run_surfacing.py` (9 checks, green),
which drives the thin `_dry_run` mapping layer directly (monkeypatching module-level
`ROOT_DIR`, `_REQUIRED_ENV_VARS`, and `console`) and asserts all four Plan-20-02
outcomes as observable return codes plus captured console text. Synthetic
`example.invalid` identifiers only; no Tenable fetcher invoked.
