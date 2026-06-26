# Retrospective: Vulnerability Management Reporting Suite

Living retrospective. Each milestone appends a section. Cross-milestone trends accumulate at the bottom.

---

## Milestone: v1.0 — Modular Reporting Framework

**Shipped:** 2026-05-08
**Phases:** 4 | **Plans:** 19 | **Quick tasks:** 1
**Timeline:** 4 days

### What Was Built

Extended `BaseModule` with three new render hooks (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) and codified the empty-data guard pattern. Upgraded `ReportComposer` to assemble per-module email bodies, paired analyst-detail companion workbooks, and unified RAG-strip cover pages — all driven from the registered module list. Migrated Board Summary's four metric modules to the new contract end-to-end. Wired `jsonschema` validation into config loading and shipped the `analyst_detail: false` per-group opt-out. Capped with a sub-5-second structural-shape regression smoke that runs against 3 committed PII-redacted baselines.

### What Worked

- **Test-first RED→GREEN structural negative control.** Used twice — Plan 03-07 for the analyst-workbook nullable-dtype BLOCKER, Plan 04-04 for the snapshot extractor. Each time, Task 1 lands the test RED, Task 2 turns it GREEN, and the commit boundary IS the proof the test exercises the implementation. Removed the need for manual revert-and-retest prose.
- **Empirical bisect when geometry math is wrong.** WeasyPrint flex layout's phantom-space consumption was off by ~3× from the theoretical estimate — bisecting cell widths at 50/53/55/56/57mm in a single Python loop found the wrap threshold cleanly. Saved a third UAT round.
- **Locked-decision documents (`<phase>-CONTEXT.md`) before planning.** Phase 4's 8 locked decisions (especially the revised D-04-05 baseline definition) prevented the planner from re-deriving the wrong defaults. The plan-checker iter-1 caught HTML-class-literal mismatches; iter-2 verified PASS in a single revision.
- **D-22 bundle-driven routing.** Every channel selection (email body modular vs. legacy, analyst attach yes/no) is decided by predicates on bundle keys, not by slug allowlists. Extending to v2 (where management_summary and ops_remediation migrate) is a near-zero-code change to `delivery/email_sender.py`.
- **Plan-checker iteration.** Phase 4 went through 2 plan-checker rounds — iter-1 found 2 blockers + 4 warnings localized to one plan (04-04). Iter-2 verified PASS. Catching layout-engine-class-literal mismatches BEFORE execution is dramatically cheaper than the alternative of finding them in the smoke run.
- **Operator-in-the-loop UAT after every phase.** Phase 03 UAT 6/6 caught the BLOCKER and the cover-layout regression that synthetic regression suites couldn't reproduce. Phase 04 UAT 7/7 confirmed real-Tenable behavior end-to-end.

### What Was Inefficient

- **Initial cover-layout fix was based on theoretical math.** Plan-checker iter-1 prescribed 58mm cells based on ~13mm WeasyPrint flex slack consumption. User UAT revealed the layout unchanged. Empirical bisect (iter-2) found the actual phantom-space at 33-37mm — ~3× the estimate. Recorded as a feedback memory: verify CSS/layout fixes with real renders before shipping based on geometry math.
- **Worktree-isolation merge confusion in Wave 2.** Plan 04-02 ran on main directly while Plan 04-03 ran in a worktree. Worktree's base became stale when 04-02 advanced main. Required cherry-pick + manual SUMMARY copy + `worktree remove -f -f` to clean up. Worktree isolation is meant to enable parallelism but cost reconciliation overhead here. Single-plan-per-wave (the default for sequential phases) avoids this.
- **`gsd-sdk` not on PATH for the entire session.** Every workflow that calls `gsd-sdk query ...` had to fall back to inline file reads + manual archive composition. Cost some workflow ergonomics; didn't change outcomes.
- **Schema enum drift caught late.** `delivery_config.schema.yaml:60-69` `reports.items.enum` was missing `board_summary` and `unscanned_assets` — both shipped in earlier phases. If Phase 4 had turned on jsonschema validation BEFORE the enum reconcile, the existing "Test Pull" group would have been rejected on commit. Wave-0 ordering (D-04-01) saved this.
- **Hallucinated background task at one point.** Claimed "the planner is running in the background" when the dispatch never happened (the `/btw` branch interrupted between "dispatching..." and the actual Agent call). User caught it within one turn. Recorded as a feedback memory: trust but verify; never claim work is done without confirmation.

### Patterns Established

- **Test-first commit ordering for ANY structural lock.** RED test commit + GREEN implementation commit. The diff IS the negative control. Used 2× in v1; expect to be the default for v2 module migrations.
- **Locked-decision documents before planning.** Surface 5-10 decisions in a CONTEXT.md before dispatching the planner. Catches drift early; provides traceable rationale; survives re-planning rounds.
- **Plan-checker as a hard gate.** Iterate plans before execution, not during. The cost of a planner round-trip is ~5-10 min; the cost of finding the same issue at the executor level is ~30 min + worktree cleanup.
- **Structural-only baselines for shape regression bars.** Counts, booleans, sorted name lists. NO metric values (drift daily). NO row-level data (PII). The structural smoke complements visual operator confirmation rather than replacing it.
- **`safe_pct`, `safe_int`, `safe_format` formatters everywhere a metric value gets interpolated into a string.** Filtered-to-zero recipient groups are routine; rendering `None` as `—` instead of crashing is correctness, not nice-to-have.
- **Atomic commits per task.** One task = one commit. Dispatchers don't squash. Bisects work cleanly; review-by-commit-message becomes the project documentation.

### Key Lessons

1. **Verify CSS/layout fixes with real renders, not theoretical math.** WeasyPrint flex's phantom-space consumption was 3× the estimate. Always render and inspect (programmatically or visually) before shipping. Saved as a feedback memory.
2. **`.gitignore` of `tests/` and `delivery_config.yaml`** is project convention — test fixtures and the YAML config are intentionally local-by-default. Force-add (`git add -f`) when GSD plans dictate the file is committed-on-purpose. Document why in commit messages.
3. **Plan-checker iter-2 is cheap; execution-level fix-up is expensive.** Two plan-checker passes on Plan 04-04 caught both `module-panel` literal absence and the page-count off-by-1 bug. Either one would have produced silently-wrong baselines and a failed first cutover smoke.
4. **WeasyPrint default `write_pdf()` compresses object headers** via FlateDecode. Regex on the raw byte stream needs `uncompressed_pdf=True`. Surfaced as a Rule 1 deviation during Plan 04-04 Task 2 GREEN.
5. **pandas 3.0 Copy-on-Write changes dtype-replacement semantics.** `.loc[:, col] = ...` may PRESERVE the existing column dtype where the chained `df[col] = ...` setter REPLACED it. F-DTYPE check at the 3 risk_score sites required `.assign()` (the only working pattern).
6. **Trust but verify when claiming work was dispatched.** I claimed the planner was running in the background when I never actually spawned it. User caught immediately; corrected within one turn. Always verify state with a tool call before claiming.

### Cost Observations

- **Model mix:** Primary executor was Opus 4.7 (1M context). All planner / verifier / debugger / executor subagents inherited Opus 4.7. No model downshifts during v1.
- **Sessions:** Single multi-day session bridged 2026-05-05 through 2026-05-08 with intermediate `/clear` between phases.
- **Token efficiency notes:**
  - Spawning subagents (researcher, planner, plan-checker, executor, verifier) kept main-context overhead to ~15% per the workflow's design budget.
  - Reading large source files in full was unavoidable at planning time but compressed by the executor's per-task `<read_first>` blocks.
  - `gsd-sdk` absence forced inline archive composition — cost ~1500-2000 tokens per archive file vs. delegated CLI generation.
- **Notable wins:** structural negative-control via commit boundary (no manual revert/retest); empirical bisect (single Python loop) catching the WeasyPrint phantom-space bug; plan-checker iter-2 catching HTML-class-literal mismatches before execution.

---

## Milestone: v1.3 — Trend & Segmentation Substrate

**Shipped:** 2026-06-11
**Phases:** 2 (12–13) | **Plans:** 8 | **Quick tasks:** 1 (260611-b1x)
**Timeline:** ~3 days (built 2026-06-08 → closed 2026-06-11)

### What Was Built

Two shared substrates so the June-2026 report batch becomes thin v1.4 consumers. **S1:** the reopened-aware two-interval `open_findings_at()` open-count primitive (`utils/open_count.py`) plus `data/trend_store.py` (atomic, idempotent monthly capture/read; cold-start safe; aggregate-only PII) and a `scripts/capture_trend_snapshot.py` cron entry point — extending `data/trend/` without regressing `management_summary`. **S2:** the `extract_owner()` Owner/Application tag helper with a lossless `Unassigned` catch-all, a combined analyst worklist (`reports/owner_supplemental.py`) wired fail-soft into `board_summary`, and owner-dimension trend composition proving S1×S2 end-to-end. Documented in `docs/trend_and_segmentation_calculations.md`.

### What Worked

- **Spike-first settled constraints.** Spikes 001–003 (run in a prior session) had already locked the load-bearing decisions — snapshot-not-reconstruction (~29-day retention wall), the reopened-aware predicate (naive form drops ~19%), WAS-is-heavy — so planning never re-litigated them. The `spike-findings-vuln-reporting` skill carried them forward.
- **TDD RED→GREEN, again the default.** The open-count predicate (12-01), the 13-05 gap-closure (CR-01/WR-05/WR-02 duplicate-uuid cluster), and the closing quick task (260611-b1x) all landed a failing test first.
- **Verify-before-build caught a stale phase.** The milestone-close audit deferred 3 items into a new Phase 14. Reading the live code before planning showed the headline item was already fixed + regression-tested (`71207e6`) and the rest was ~15 lines — so the phase was removed and the work done as a quick task. Avoided a full discuss→plan→execute cycle for a trivial fix.

### What Was Inefficient

- **Audit findings went stale between audit and action.** The v1.3 milestone audit cited `utils/open_count.py:82-88` for a NaT-FIXED over-count that had already been fixed at lines 108-112 in the same milestone; it also mislabeled which `owner_supplemental.py` lines emitted the CoW warning (cited 128/129; the real one was 139). Acting on the audit verbatim would have meant redundant and misdirected work.
- **`audit-open` false-positives on every quick task.** This project's quick SUMMARYs omit a `status:` frontmatter field, so the pre-close audit flagged all 12 historical quick tasks as "missing" — noise at a milestone boundary. Cosmetic follow-up captured.
- **pandas Copy-on-Write resurfaced exactly as the v1.0 watchlist predicted.** The chained-assignment `df[col] = …fillna()…` on the open-count column emitted the pandas-3.0 `ChainedAssignmentError`; fixed with `.assign()` — the same pattern flagged in v1.0's carry-forward watchlist.

### Patterns Established

- **Re-verify audit findings against live code before planning closure work.** An audit is a snapshot; code moves under it. Confirm each cited line/commit before spinning up a phase to "fix" it.
- **Quick task over phase for trivial, well-scoped fixes.** When closure work is a known ~15-line change in one file, `/gsd-quick` (atomic commits + state tracking, no subagent ceremony) beats inserting a roadmap phase.

### Key Lessons

1. **Audit reports can be stale on arrival.** Between writing an audit and acting on it, the cited code may already have changed. Re-read the exact lines/commits before treating a finding as open work — one of three v1.3 "tech-debt" items was already fixed and tested.
2. **The v1.0 CoW watchlist item materialized verbatim.** `.loc[]`/`.assign()` for any int-dtype-critical column is now non-negotiable; the chained setter silently no-ops under CoW. Carry forward.
3. **`-W error::FutureWarning` is a precise diagnostic, but third-party deprecations ride along.** It pinpointed the real production CoW line, but a matplotlib/pyparsing `PyparsingDeprecationWarning` (a FutureWarning subclass) tripped an unrelated e2e test — distinguish your warnings from the dependency tree's.

### Cost Observations

- **Model mix:** Opus orchestrator (main loop); planner on Opus, executor on Sonnet for the closing quick task. No downshifts during substrate build.
- **Sessions:** substrate build across 2026-06-08 → 06-10; milestone close 2026-06-11.
- **Notable:** the verify-before-build check on the Phase 14 premise was the highest-leverage move — a few file reads replaced an entire phase.

---

## Milestone: v1.4 — Management Summary Reporting Improvement

**Shipped:** 2026-06-26
**Phases:** 6 (14–19) | **Plans:** 35 | **Quick tasks:** 1 (260626-elj)
**Timeline:** ~15 days (built 2026-06-11 → closed 2026-06-26)

### What Was Built

The June-2026 management/exec trend-cut report batch as seven thin four-channel modules on the shipped S1/S2 substrates — New vs Remediated, Vulnerability Density, Reopened Vulnerabilities, Accepted & Recast, External/DMZ Exposure (Phase 15); the reworked `mttr_trend` with a disclosed rolling-30-day window, sample-weighted mean, and reopened-aware clock (Phase 16); and the Program Health Overview composite RAG dashboard (Phase 17) — atop Phase 14's shared substrates (`external_scope`, `asset_count`, composed_report kwargs gates). Phase 18 migrated `management_summary` off its ~2,200-line bespoke path onto `ReportComposer` (GEN-01), seeded ~12mo of reconstructed trend history, and shipped auditor runbooks (DOC-02). Phase 19 closed the milestone off `tech_debt`.

### What Worked

- **Substrate-first paid off exactly as v1.3 bet.** The seven v1.4 modules consumed `open_findings_at` + `extract_owner` + `read_trend` directly; none re-invented trend or segmentation. The S1/S2 investment from v1.3 turned report-building into thin module work.
- **The post-close re-audit earned its keep.** Re-running `/gsd-audit-milestone` after closure, with an independent integration checker, caught REAUDIT-WARN-1 — a real data gap the Phase 19 closure had marked "resolved." Phase-level verification (which asserted kwarg key presence) had passed over it.
- **Inline-compute over composing-more-modules.** When the fix surfaced, surfacing the report-content side effect of the "obvious" approach (adding modules to `_MGMT_MODULE_CONFIGS`) led to a cleaner inline fix that left the audience-facing report byte-identical. Asking before changing what VPs see was the right call.

### What Was Inefficient

- **"Forwarded" was mistaken for "populated."** The Phase 19 INT-WARN-1 fix forwarded all 8 snapshot kwargs and its regression test asserted key presence — but 2 fields silently resolved to `None` because their source modules weren't composed. The test passed green over the nulls for a full week until the re-audit's integration checker caught it. A value assertion would have caught it immediately.
- **A documented false-positive explanation was itself wrong.** The v1.3 retro and STATE.md attributed the `audit-open` quick-task noise to "SUMMARYs omit a `status:` field." At v1.4 close the real cause turned out to be a filename mismatch (detector reads `SUMMARY.md`; gsd-quick writes `<id>-SUMMARY.md`) — the status field was already there. The wrong explanation had been inherited across two closes.

### Patterns Established

- **Regression tests assert VALUES, not just shape/key presence.** A kwarg can be present and `None`; a section can render and be empty. When a fix is "field X is now populated," the test must assert X is non-null with realistic data — not that the key exists.
- **Re-run the milestone audit post-closure with an independent integration checker.** It exercises cross-phase wiring against live code and catches what per-phase verification (scoped to one phase's diff) structurally cannot.
- **Verify a documented root cause before inheriting it.** A note that says "false positive because X" can be right about the symptom and wrong about X. Re-test the cause when it next matters.

### Key Lessons

1. **Present ≠ populated.** The highest-value catch of the milestone was a `None` that a green test endorsed. Assert the value.
2. **Surface side effects before applying the "obvious" fix.** The audit's own recommended approach (add modules) would have silently changed the management report; the inline alternative didn't. One clarifying question saved a regression.
3. **Inherited explanations decay like inherited audits.** Same lesson as v1.3 ("audits go stale"), one level up: the *explanation* of a known quirk can be stale too.

### Cost Observations

- **Model mix:** Opus orchestrator (main loop); integration checker on Sonnet; planner on Opus, executor on Sonnet for the closure quick task.
- **Sessions:** Phases 14–18 across 2026-06-11 → 06-21; Phase 19 closure 06-24 → 06-26; re-audit + REAUDIT-WARN-1 + milestone close 06-26.
- **Notable:** the re-audit integration checker (one Sonnet agent, ~137k tokens) found a week-old latent data bug that four phase verifications had each passed — the cheapest high-leverage catch of the milestone.

---

## Cross-Milestone Trends

(This section accumulates patterns across multiple milestones. v1.1 and v1.2 retrospectives were not captured at their close; entries exist for v1.0, v1.3, and v1.4.)

### Velocity

| Milestone | Phases | Plans | Quick Tasks | Days | Commits |
|-----------|--------|-------|-------------|------|---------|
| v1.0 | 4 | 19 | 1 | 4 | 140 |
| v1.3 | 2 | 8 | 1 | 3 | 63 |
| v1.4 | 6 | 35 | 1 | 15 | ~164 |

### UAT Issues Found Per Milestone

| Milestone | UAT BLOCKERs | UAT major/issue | UAT minor/cosmetic |
|-----------|--------------|------------------|--------------------|
| v1.0 | 1 (Phase 03 — pd.NA chokepoint) | 1 (Phase 03 — RAG strip layout) | 0 |
| v1.3 | 0 | 1 (Phase 13 verify gap — CR-01 duplicate-`asset_uuid`, closed via 13-05) | 0 |
| v1.4 | 0 | 1 (Phase 17 PDF/email layout gaps — closed via 19-10/19-11) + REAUDIT-WARN-1 (post-close, inline-compute fix) | 0 |

### Recurring Failure Modes (carry-forward watchlist)

- **WeasyPrint flex layout** — phantom-space consumption beyond cell+gap math. v1 fixed cover; if v2 adds modules, re-test with multi-row wrap.
- **pandas Copy-on-Write dtype shifts** — `.loc[:, col]=` vs `df[col]=` semantics differ post-3.0. v2 module migrations should use `.assign()` for any int-dtype-critical column.
- **Key-presence tests that pass over `None` values** — v1.4's INT-WARN-1 guard asserted kwargs were forwarded but not that they were non-null; 2 fields stayed `None` for a week behind a green test. For any "field is now populated" fix, assert the value with realistic data, not just key/shape presence.
- **`audit-open` quick-task false positives** — fires at every milestone close. Root cause (corrected at v1.4): filename mismatch (detector reads `<dir>/SUMMARY.md`; gsd-quick writes `<dir>/<id>-SUMMARY.md`), NOT a missing `status:` field. Acknowledge & proceed; drop an unprefixed `SUMMARY.md` copy to silence per task.
- **Synthetic regression fixtures don't catch real-data nulls** — Plan 03-07's BLOCKER (StringDtype `pd.NA`, `Int64` `pd.NA`, `datetime64[ns, UTC]` `pd.NaT`) only reproduced against live Tenable. Fixture pattern: include `pd.NA` in StringDtype, `pd.NaT` in datetime, `pd.NA` in Int64 columns by default for any new test fixture.
