# Phase 19: v1.4 Closure — Context

**Gathered:** 2026-06-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Close out the **v1.4 milestone** (currently `tech_debt` per `.planning/v1.4-MILESTONE-AUDIT.md`). This phase has six work-streams, all already enumerated by the milestone audit and the phase code reviews — **no new product capability**:

1. **INT-WARN-1** — `management_summary` forward-writes only a subset of aggregate snapshot fields; if it runs after the cron `capture_trend_snapshot.py` in the same month it overwrites the fully-populated snapshot, nulling `on_time_asset_count` / `reopened/accepted/recast_count` / `mttr_*` / `sla_rate_crit_high` / new+fixed counts. Degrades `new_vs_remediated`, `program_health`, `vuln_density`, `mttr_trend` for that month.
2. **INT-WARN-2** — `management_summary` composes `accepted_recast` but never fetches/forwards `recast_rules_df`, so the recast-expiry cross-check (CLAUDE.md Pitfall 6a) is silently skipped → `pending_reeval` always 0 for this audience.
3. **INT-WARN-3** — `tests/test_composed_report_kwargs_gates.py::test_frozensets_membership` pins exact membership for `_MODULES_NEEDING_TREND_SNAPSHOTS` and `_MODULES_NEEDING_RECAST_RULES` but **not** `_MODULES_NEEDING_FIXED_VULNS`. Missing co-edit gate.
4. **Deferred code-review findings** across three review files (see breadth decision D-04): 18-REVIEW (WR-04..WR-08, IN-01..IN-05), 17-REVIEW (WR-01..WR-05), 15-REVIEW (IN-01..IN-05).
5. **CodeRabbit pass** — run the deferred diff-native review on the Phase 18 work, triage, fold any net-new findings in.
6. **Human verification debt** — Phase 17 (3 live/render checks) and Phase 16 (UAT tests 1, 2, 3, 5 visual re-test) completed against the fixed build, then milestone closeout.

**Already resolved (NOT in scope — confirmed in current code):** 18-REVIEW CR-01 (tag-scoped path now passes real `tio`), WR-01, WR-02, WR-03; Phase 16 code (sys.path bootstrap in `capture_trend_snapshot.py:34`, D-16-13 focus-driven gauge band, CLAUDE.md Medium-SLA doc fix `45→60`). Phase 16 has **no remaining code** — only the operator visual re-test.

</domain>

<decisions>
## Implementation Decisions

### Scope
- **D-01:** Scope = **code fixes + human checks**, all in this single closure phase. Phase 19 both fixes the code and completes the outstanding human verification, then closes the milestone.
- **D-02:** **Fix net = everything, including dead code.** Fix every correctness WARNING *and* every INFO/dead-code item across all three review files (18-REVIEW, 17-REVIEW, 15-REVIEW) plus INT-WARN-1/2/3. Fully clears the v1.4 review backlog. Group risky correctness edits separately from low-value cleanup in the plan waves so a cleanup change never rides on a correctness commit.

### INT-WARN-1 (snapshot overwrite)
- **D-03:** Fix by making `management_summary`'s forward-write emit the **full** aggregate field set (mirror the gated fetch/forward logic in `composed_report.py`), **not** by changing `capture_snapshot()` overwrite semantics. The report becomes a complete writer.
- **D-03b:** Add a regression guard so a future writer cannot silently re-introduce a partial forward-write (e.g. assert the management_summary path forwards the same field set the cron path does). Confirm exact field list against `data/trend_store.py::capture_snapshot` signature during planning.

### INT-WARN-2 (recast expiry)
- **D-04:** Fetch + forward `recast_rules_df` into the `management_summary` path so the `accepted_recast` expiry cross-check runs (mirror `_MODULES_NEEDING_RECAST_RULES` gating from `composed_report.py`). Mechanical; mirrors the existing designed-for path.

### SLA-rate bias
- **D-05:** **Fix the `sla_rate_crit_high` NaT-denominator downward bias BEFORE the Phase 17 human check.** First-found `NaT` rows currently sit in the denominator but can never enter the numerator; the bias is copied across **3 sites** (`utils/open_count.py` / `program_health_module.py` / `capture_trend_snapshot.py` ~lines 396-408 per 17-REVIEW WR-01/WR-06). Fix once via a shared helper so all 3 sites agree, so the live snapshot value the operator inspects in Phase 17 check #2 is actually correct.

### CodeRabbit
- **D-06:** **Operator installs + runs CodeRabbit now, before planning.** `coderabbit review --prompt-only` (free tier; CLI needs one-time install + browser `auth login`; reviews the working tree, ~5 min). Save output to `.planning/phases/19-.../19-CODERABBIT.md` so the planner reads it and folds net-new findings into the plan (deduplicated against the three existing review files). CodeRabbit findings are a planning **input inventory**, not a discussion decision.

### Sequencing & closeout
- **D-07:** **Code first → verify-all at end → close.** Order: (a) all code fixes + tests + dead-code cleanup; (b) then run Phase 16 (UAT tests 1, 2, 3, 5) and Phase 17 (3 checks) human verifications **once** against the fixed build, as `autonomous: false` operator checkpoints; (c) flip `16-UAT.md` and `17-VERIFICATION.md` status to passed and refresh `.planning/v1.4-MILESTONE-AUDIT.md`. Human checks run after code because they exercise the same snapshot/render paths the fixes touch.

### Claude's Discretion
- Exact wave/commit decomposition, shared-helper signatures, and which findings are mechanical enough to batch.
- Whether to add the optional Nyquist `14-VALIDATION.md` / `15-VALIDATION.md` (audit marks them MISSING but **optional** — not a closure blocker). Default: leave out unless trivial; note in closeout that they remain optional.

### Folded Todos
- **`2026-06-18-run-coderabbit-on-phase-18-code-review.md`** — "Run CodeRabbit as a diff-native reviewer on the Phase 18 code review." Folded into D-06 (run before planning). Original problem: CodeRabbit was deferred during `/gsd-review --phase 18` because it reviews a diff, not a prompt; high-value on the actual landed code. Closes this todo.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Master scope source
- `.planning/v1.4-MILESTONE-AUDIT.md` — authoritative enumeration of INT-WARN-1/2/3, deferred findings, and verification/Nyquist debt; the closeout target to refresh.

### Deferred code-review findings (fix-all per D-02)
- `.planning/phases/18-management-summary-migration-docs/18-REVIEW.md` — WR-04 (dead `_months_in_range` + unused `dateutil` import), WR-05 (MTD/partial-month delta), WR-06 (local-vs-UTC month attribution in `capture_snapshot`), WR-07 (destructive corrupt-file rename data-loss path), WR-08 (VPR band gaps drop ~8.95 to native fallback), IN-01..IN-05 (hot-path `import math`, dead `_first_str`, stale runbook sections, stale `_OPEN_STATES` docstring, `LOGO_PATH` default).
- `.planning/phases/17-program-health-overview/17-REVIEW.md` — WR-01/WR-02 (SLA-rate NaT denominator + unmapped-severity NaN drop), WR-03 (`_signal_direction` NaN-as-real), WR-04 (sparkline `s.get(...,0)` masks missing), WR-05 (`analyst_df` NaN guard + int-typed-metadata miscount).
- `.planning/phases/15-independent-new-modules/15-REVIEW.md` — IN-01 (`safe_format` unused in 4/5 new modules), IN-02 (`_rag_fill` unused ×3), IN-03 (`_safe_mom_delta` dead), IN-04 (unused imports in `reopened_vulns_module`), IN-05 (owner `capture_snapshot` omits aggregate counts).
- `.planning/phases/19-.../19-CODERABBIT.md` — **to be produced** by the operator's CodeRabbit run (D-06); planner reads it for net-new findings.

### Human verification debt
- `.planning/phases/17-program-health-overview/17-VERIFICATION.md` (`human_verification:` frontmatter) — the 3 checks: SMTP email render of the 4-tile KPI row + sparklines + Owner velocity table; live-tenant `capture_trend_snapshot.py` `sla_rate_crit_high` round-trip; WeasyPrint PDF sparkline-row/table visual render.
- `.planning/phases/16-mttr-rework/16-UAT.md` (`resume_at: 1`) — UAT tests 1 (gauge-band PDF), 2 (Excel MTTR tab), 3 (email panel), 5 (`capture_trend_snapshot.py` MTTR fields). Tests 4/6 already pass/skip.

### Source files in scope
- `reports/management_summary.py` — INT-WARN-1 forward-write (~L407-427), INT-WARN-2 recast fetch (~L345-361).
- `data/trend_store.py` — `capture_snapshot` field set, WR-06 month attribution (~L390,422-433), WR-07 corrupt-file rename (~L172-192).
- `reports/composed_report.py` — designed-for gated fetch/forward (`_MODULES_NEEDING_FIXED_VULNS` / `_MODULES_NEEDING_RECAST_RULES`) to mirror for WARN-1/2.
- `tests/test_composed_report_kwargs_gates.py` — INT-WARN-3 membership gate (`test_frozensets_membership`).
- `config.py` — WR-08 VPR bands (`VPR_SEVERITY_MAP` L95-100), IN-01 `import math` (L147).
- `utils/open_count.py` + `reports/modules/program_health_module.py` + `scripts/capture_trend_snapshot.py` — D-05 SLA-rate NaT bias (3 sites); IN-04 stale `_OPEN_STATES` docstring.
- `scripts/backfill_trend_reconstruction.py` — WR-04 dead helper.
- `data/fetchers.py` — IN-02 dead `_first_str`/`fetch_vulnerabilities` chain.
- `docs/management_summary_calculations.md` — IN-03 pre-v1.4 sections describing the removed bespoke path.
- `reports/modules/{reopened_vulns,external_dmz,new_vs_remediated,vuln_density}_module.py` — 15-REVIEW IN-01..05 dead imports/symbols.

### Project rules
- `CLAUDE.md` — SLA from `config.py::SLA_DAYS` (authoritative, per-install configurable; see memory `project_sla_days_config_py_authoritative`); no silent failures; UTC report timestamps vs local cache/schedule; locked stack (WR-04 unused `dateutil` violates "no new SDK").

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `reports/composed_report.py` already implements the correct gated fetch/forward for `fixed_vulns_df`, `recast_rules_df`, and `trend_snapshots` via `_MODULES_NEEDING_*` frozensets — INT-WARN-1/2 fixes mirror this rather than invent a new path.
- `scripts/capture_trend_snapshot.py` is the canonical full-field snapshot writer; its `capture_snapshot(...)` call is the field-set reference management_summary must match for D-03.
- Sibling `*_module.py` files and `reports/modules/format_utils.py` (`safe_pct/safe_int/safe_format`) are the convention for the dead-import cleanup.

### Established Patterns
- `test_frozensets_membership` is an **exact co-edit gate** — adding/removing a module from a `_MODULES_NEEDING_*` frozenset breaks the test until its hardcoded expected set is updated (memory `project_frozenset_gate_test_coupling`). The INT-WARN-3 fix extends this pattern to the third frozenset.
- Layout/render fixes need **real renders, not on-paper geometry** (memory `feedback_layout_fixes.md`) — the Phase 16/17 PDF + email human checks exist precisely because WeasyPrint bugs slip past pytest.

### Integration Points
- The management_summary → `capture_snapshot` forward-write shares the trend store with the cron `capture_trend_snapshot.py`; both write the same `(month, tag_filter)` key. The fix must make them agree on the field set.

</code_context>

<specifics>
## Specific Ideas

- D-05 SLA-rate bias: prefer a **single shared helper** that both the live snapshot capture and the module re-derivation call, so the 3 sites cannot drift again.
- D-07 closeout: the phase's terminal deliverable is a refreshed `v1.4-MILESTONE-AUDIT.md` flipping status off `tech_debt` (or documenting precisely what optional items remain), plus `16-UAT.md`/`17-VERIFICATION.md` status updates.

</specifics>

<deferred>
## Deferred Ideas

- **Nyquist `14-VALIDATION.md` / `15-VALIDATION.md`** — audit marks MISSING but explicitly optional; not a closure blocker. Out of scope unless trivial during closeout.
- All v1.4 Backlog items in `ROADMAP.md` (GEN-02/03/04, PERF-01..04, LEGACY-01, VTD-01, SEV-NONE-01, EXT-WAS-01, MTTR window widening, etc.) — future milestones, untouched here.

### Reviewed Todos (not folded)
- None — the single matched todo (CodeRabbit) was folded (D-06).

</deferred>

---

*Phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio*
*Context gathered: 2026-06-24*
