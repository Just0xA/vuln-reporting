---
phase: quick-260813-jaz
plan: 01
subsystem: reporting
tags: [pandas, ops_remediation, risk-acceptance, recast, suppression]

requires: []
provides:
  - "_suppress_risk_accepted() ACCEPTED-only, expiry-aware suppression helper in reports/ops_remediation.py"
  - "vulns_actionable wired through run_report()'s seven actionable-metric surfaces"
  - "Accurate Summary-sheet + Report Info tab wording describing the suppression"
affects: [ops_remediation, board_report_utils, docs/GLOSSARY.md]

tech-stack:
  added: []
  patterns:
    - "ACCEPTED-only suppression (diverges from board's both-types exclude_risk_managed())"
    - "Expiry-aware carve-out: recast_rule_uuid -> recast_rules_df.expires_at cross-check"

key-files:
  created:
    - tests/test_ops_risk_accepted_suppression.py
  modified:
    - reports/ops_remediation.py
    - docs/GLOSSARY.md
    - CLAUDE.md

key-decisions:
  - "D-01: Suppress ACCEPTED only; RECASTED findings stay in the actionable worklist at their recast severity (a recast is still open work, only the tier changed)"
  - "D-02: An ACCEPTED finding whose recast rule has expires_at in the past returns to the actionable population; null/absent/Never/unparseable expires_at never expires"
  - "D-03: Single-variant — no new slug, no include_risk_managed option, no YAML/schema change"
  - "Degrade conservatively: recast_rules_df None/empty/malformed suppresses ALL ACCEPTED rows (never crashes, never loses suppression) with a warning log"

requirements-completed: [QUICK-260813-jaz]

duration: 65min
completed: 2026-08-13
---

# Quick Task 260813-jaz: Suppress risk-accepted findings from ops_remediation Summary

**Added an ACCEPTED-only, expiry-aware `_suppress_risk_accepted()` helper to `reports/ops_remediation.py`, wired it through all seven actionable-metric surfaces in `run_report()`, and corrected the workbook text that had falsely claimed the suppression already happened.**

## Performance

- **Duration:** ~65 min
- **Started:** 2026-08-13T14:05:13-04:00 (Task 1 commit)
- **Completed:** 2026-08-13T18:15:04Z
- **Tasks:** 3 completed
- **Files modified:** 4 (1 new test file, 3 modified)

## Accomplishments

- `_suppress_risk_accepted(vulns_df, recast_rules_df, as_of)` — drops ACCEPTED rows, keeps RECASTED rows (D-01), un-suppresses ACCEPTED rows whose recast rule has expired (D-02), and degrades gracefully (suppresses all ACCEPTED + logs a warning) when `recast_rules_df` is missing/malformed (Hard Rule 6)
- `run_report()` now computes `vulns_actionable` once and routes it to `plugin_df`, the Summary metrics, exploitability counts, top-5 priority plugins, recurring vulnerabilities, `overdue_df`, and `urgent_df` — the seven actionable-metric surfaces
- `_extract_risk_modifications` (Tab 5 "Risk Acceptances & Recasts") and the `count_risk_*` summary tiles still read the FULL unfiltered `vulns_scanned` population — verified both behaviorally and via a source-level `inspect.getsource()` wiring guard
- The `__main__` CLI smoke block was edited to match (never executed, per Hard Rule 1)
- Summary-sheet label and Report Info tab description now accurately state the ACCEPTED-only-unless-expired suppression and that RECASTED findings are never suppressed
- `docs/GLOSSARY.md`'s "Risk-managed finding" entry now documents that ops_remediation deliberately diverges from the board's both-types convention
- `CLAUDE.md`'s slug index row for `ops_remediation` now notes the suppression behavior
- New `tests/test_ops_risk_accepted_suppression.py` — 27 tests covering all 8 required behavior groups

## Task Commits

Each task was committed atomically:

1. **Task 1: Add `_suppress_risk_accepted()` helper + unit tests for behaviors 1-7** - `f226157` (feat)
2. **Task 2: Wire the actionable frame through `run_report()` (+ CLI smoke block) and add the must-not-change regression guard** - `4b92a03` (feat)
3. **Task 3: Make the in-workbook claims accurate + glossary/CLAUDE.md, then run the full suite** - `a99e021` (docs)

_No plan-metadata commit yet — SUMMARY.md/STATE.md docs commit is handled by the orchestrator per the constraints given to this executor run._

## Files Created/Modified

- `reports/ops_remediation.py` — new `_suppress_risk_accepted()` helper (banner-commented section before `_extract_risk_modifications`); `run_report()` and the `__main__` CLI block wired to `vulns_actionable`; Summary-sheet label and Report Info tab text corrected; module docstring updated
- `tests/test_ops_risk_accepted_suppression.py` — new file, 27 tests across 8 behavior groups (accepted-dropped, recast-kept, expiry carve-out x3, findings-frame guards x3, recast_rules_df degradation x4, case-insensitivity + fresh-copy + other-values-kept, and the Task 2 regression guard: behavioral Tab 5 check + source-level wiring guard)
- `docs/GLOSSARY.md` — appended a paragraph to the "Risk-managed finding" entry distinguishing ops' ACCEPTED-only convention from the board's both-types convention
- `CLAUDE.md` — single-cell edit to the `ops_remediation` row's Notes column in the "Report Scripts — Slug Index" table

## Decisions Made

- Followed all three locked decisions (D-01/D-02/D-03) from the plan exactly as specified — ACCEPTED-only suppression, expiry carve-out via `recast_rule_uuid` → `rule_id`/`expires_at` cross-check, single report variant.
- Did not reuse `reports/modules/board_report_utils.py::exclude_risk_managed()` per the plan's explicit instruction; the new helper's docstring references it by file/behavior rather than by the literal function-name string, since Task 1's automated verify (`! grep -q "exclude_risk_managed" reports/ops_remediation.py`) checks the whole file including docstrings/comments, not just import statements. This preserves the plan's intent (explain the divergence for future readers) while satisfying the literal automated check. `docs/GLOSSARY.md` and the plan text itself continue to reference `exclude_risk_managed()` by name where there's no such constraint.

## Deviations from Plan

None — plan executed exactly as written, with the one clarifying interpretation noted above under "Decisions Made" (docstring wording adjusted to satisfy Task 1's literal grep-based verify while preserving the intended documentation content).

**Total deviations:** 0 auto-fixed
**Impact on plan:** None — all three tasks match the plan's action items, must-haves, and verification commands.

## Issues Encountered

- The project's `pytest.ini` forces `-n auto` (pytest-xdist). Running the plan's literal verify commands works but the "bringing up nodes..." worker-spinup adds ~15-20s of apparent latency before test output appears — not a functional issue, just slower to observe. For the full-suite baseline comparison, `-n0` was used instead so the final `N passed, M failed in Xs` summary line was reliably captured (with `-n auto`, that line is written via carriage-return progress updates in this environment and was not reliably visible in captured tool output, though the FAILED test list was always visible either way).
- To establish the pre-change failure baseline without using any destructive git operations on this worktree, a temporary detached `git worktree add` was created at the plan's base commit (`c274c12`) under the scratchpad directory, tests were run there, and the worktree was removed via `git worktree remove --force` afterward. This is a read-only comparison technique, not a modification to the agent's own worktree.

## User Setup Required

None — no external service configuration required.

## Operator Note — Delivered Numbers Will Change

**This changes delivered `ops_remediation` numbers for every group that runs the slug.** Open counts, SLA-state breakdown, Plugins tab, Overdue Detail, Urgent PDF table, exploitability counts, top-5 priority plugins, and recurring-vulnerability counts will all drop by the unexpired-ACCEPTED population (previously these numbers silently included risk-accepted findings, contradicting the workbook's own claimed suppression). Tab 5 "Risk Acceptances & Recasts" and the `count_risk_accepted` / `count_risk_recast` / `count_expiring_soon` / `count_expired` summary tiles are unchanged — they always showed, and still show, the full accepted+recast population.

The exact magnitude cannot be measured inside Claude Code (Hard Rule 1 — no live Tenable pulls). **The operator should run `python reports/ops_remediation.py` against a warmed parquet cache before the next scheduled `ops_remediation` send** and confirm the before/after delta matches the Summary sheet's new "Accepted Findings (suppressed unless expired)" tile value.

## Full Suite Results (Task 3 requirement)

Baseline (pre-change, verified via a temporary detached worktree at commit `c274c12`, the plan's base commit) and after-change (this worktree, commit `a99e021`) full-suite runs, both with `-n0` for a reliable final summary line:

| | Passed | Failed |
|---|---|---|
| Baseline (`c274c12`) | 997 | 6 |
| After (`a99e021`) | 1024 | 6 |

The +27 passed delta is exactly the new `tests/test_ops_risk_accepted_suppression.py` test count. **Identical 6 failing test IDs in both runs — zero new regressions:**

```
FAILED tests/e2e/test_groups.py::test_group_runs_fail_soft_and_artifacts_valid[Remediation Team]
FAILED tests/unit/test_modules.py::test_four_channel_types[_phase2_test_panel_boom]
FAILED tests/unit/test_modules.py::test_four_channel_types[stub_always_fails_f2]
FAILED tests/unit/test_modules.py::test_four_channel_types[stub_non_string_pdf_f1]
FAILED tests/unit/test_modules.py::test_empty_data_guard[_phase2_test_panel_boom]
FAILED tests/unit/test_modules.py::test_empty_data_guard[stub_always_fails_f2]
```

The `tests/unit/test_modules.py` failures are pre-existing stub-registry pollution (documented in the plan as a known, order-dependent issue — they pass when that file runs alone). The `tests/e2e/test_groups.py::test_group_runs_fail_soft_and_artifacts_valid[Remediation Team]` failure is a pre-existing `KeyError: 'asset_id'` inside `reports/sla_remediation.py` / `reports/patch_compliance.py` — neither file was touched by this plan, and the failure reproduces identically at the pre-change baseline. Confirmed NOT a new regression.

## Tab 5 / count_risk_* Unchanged Confirmation

`_extract_risk_modifications` (Tab 5 "Risk Acceptances & Recasts") is still called with the unfiltered `vulns_scanned` frame in both `run_report()` and the `__main__` CLI block — verified by:
1. A behavioral test (`test_extract_risk_modifications_unaffected_by_new_helper`) confirming the full accepted+recast population round-trips through `_extract_risk_modifications` unchanged, and that feeding the suppressed frame instead would yield strictly fewer rows (proving the wiring choice is load-bearing).
2. A structural `inspect.getsource(run_report)` guard (`test_run_report_source_wiring`) that fails if a future edit ever rewires `_extract_risk_modifications` to the suppressed frame, or rewires any of the seven actionable-metric call sites back to `vulns_scanned`.

The four `count_risk_*` summary tiles (`count_risk_accepted`, `count_risk_recast`, `count_expiring_soon`, `count_expired`) derive entirely from `risk_mods_df` (the output of `_extract_risk_modifications`), so they are unaffected by construction — confirmed by inspection; no code in those four lines was touched.

## Next Phase Readiness

This is a standalone quick task with no downstream phase dependency. The helper and its test suite are self-contained within `reports/ops_remediation.py` / `tests/test_ops_risk_accepted_suppression.py` and do not block or require follow-up work, other than the operator verification step noted above.

---
*Quick task: 260813-jaz*
*Completed: 2026-08-13*

## Self-Check: PASSED

All claimed files exist (`reports/ops_remediation.py`, `tests/test_ops_risk_accepted_suppression.py`, `docs/GLOSSARY.md`, `CLAUDE.md`, this SUMMARY.md) and all three task commit hashes (`f226157`, `4b92a03`, `a99e021`) are present in git history.
