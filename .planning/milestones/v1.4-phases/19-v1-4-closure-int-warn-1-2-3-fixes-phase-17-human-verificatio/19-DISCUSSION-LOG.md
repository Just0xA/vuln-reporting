# Phase 19: v1.4 Closure - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-24
**Phase:** 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
**Areas discussed:** Scope, INT-WARN-1 fix approach, Findings breadth, CodeRabbit timing, SLA-rate bias, Sequencing & closeout

---

## Scope (asked during plan-phase pre-flight, carried into discuss)

| Option | Description | Selected |
|--------|-------------|----------|
| Code fixes only | Fix INT-WARN-1/2/3 + CodeRabbit/review findings; leave human checks to a separate verification step | |
| Code fixes + human checks | Also fold Phase 17 live checks + Phase 16 manual UAT as operator checkpoints in this phase | ✓ |

**User's choice:** Code fixes + human checks.
**Notes:** One closure phase covers everything end-to-end.

---

## INT-WARN-1 fix approach (asked during plan-phase pre-flight, carried into discuss)

| Option | Description | Selected |
|--------|-------------|----------|
| Report writes all fields | management_summary forwards the full aggregate field set, mirroring composed_report.py | ✓ |
| Snapshot save merges | capture_snapshot() merges instead of overwrites, never nulling existing fields | |
| Let the planner decide | Pass both options to the planner | |

**User's choice:** Report writes all fields.
**Notes:** Fixes root cause; the report becomes a complete writer. Snapshot-store semantics stay unchanged.

---

## Findings breadth

| Option | Description | Selected |
|--------|-------------|----------|
| All correctness, defer dead-code | Fix every correctness WARNING across all 3 reviews + INT-WARNs; defer pure dead-code INFO | |
| Everything, including dead code | Fix all WARNINGs AND all INFO/dead-code across 18/17/15 reviews in this phase | ✓ |
| Only phase-title literal scope | Fix only INT-WARN-1/2/3 + 18-REVIEW deferred; leave 17/15 reviews for later | |

**User's choice:** Everything, including dead code.
**Notes:** Fully clears the v1.4 review backlog. Plan should separate risky correctness edits from low-value cleanup in distinct waves/commits.

---

## CodeRabbit timing

| Option | Description | Selected |
|--------|-------------|----------|
| Run now, before planning | Run coderabbit on the branch, merge findings with the 3 review files, planner sees full set | ✓ (then re-confirmed) |
| Run as a task inside the phase | Plan first; run + triage CodeRabbit as an execution task | |
| Skip CodeRabbit entirely | Rely on the 3 existing Claude review files | |

**Follow-up (CLI not installed):**

| Option | Description | Selected |
|--------|-------------|----------|
| I'll install + run it now | Operator installs CodeRabbit, runs `coderabbit review --prompt-only`, shares output; folded before planner runs | ✓ |
| Make it the first phase task | Plan now; first task installs + runs + triages CodeRabbit | |
| Skip CodeRabbit entirely | Drop the pass | |

**User's choice:** Run now (operator installs + runs); fold findings into planning before the planner runs. Save output to `19-CODERABBIT.md`.
**Notes:** CodeRabbit CLI was not on PATH; needs one-time install + browser auth login (free tier).

---

## SLA-rate bias

| Option | Description | Selected |
|--------|-------------|----------|
| Fix bias before human check | Fix NaT-denominator bias at all 3 sites (shared helper) so the live value the operator inspects is correct | ✓ |
| Leave bias, note it | Treat as known directionally-consistent limitation; verify only field round-trip; defer fix | |

**User's choice:** Fix bias before human check.
**Notes:** Phase 17 human check #2 asks the operator to eyeball `sla_rate_crit_high` live — fixing first makes that check meaningful.

---

## Sequencing & closeout

| Option | Description | Selected |
|--------|-------------|----------|
| Code first, verify-all at end, then close | Code fixes/tests → Phase 16 + 17 human checks once against fixed build → flip status + refresh audit | ✓ |
| Code fixes only, close milestone separately | Ship code; human re-tests + audit refresh happen later via separate verify-work pass | |

**User's choice:** Code first, verify-all at end, then close.
**Notes:** Human checks exercise the same snapshot/render paths the fixes touch, so they run after the fixes against one build.

---

## Claude's Discretion

- Wave/commit decomposition, shared-helper signatures, batching of mechanical findings.
- Whether to add optional Nyquist `14-VALIDATION.md` / `15-VALIDATION.md` (audit marks optional, non-blocking).

## Deferred Ideas

- Nyquist 14/15 VALIDATION.md (optional per audit).
- v1.4 ROADMAP backlog items (GEN-02/03/04, PERF-01..04, LEGACY-01, VTD-01, SEV-NONE-01, EXT-WAS-01, MTTR window widening) — future milestones.
