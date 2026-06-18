---
phase: 18
reviewers: [gemini]
reviewed_at: 2026-06-18T13:00:23Z
plans_reviewed: [18-01-PLAN.md, 18-02-PLAN.md, 18-03-PLAN.md, 18-04-PLAN.md, 18-05-PLAN.md]
---

# Cross-AI Plan Review — Phase 18

> **Reviewer availability note:** Of the supported external CLIs, only **gemini** was
> installed and reachable. `claude` was skipped for independence (this review ran
> inside Claude Code). `codex`, `coderabbit`, `opencode`, `qwen`, and `cursor` were
> not installed. This is therefore a **single-reviewer** pass — treat the
> "Consensus Summary" below as one independent perspective, not a multi-AI quorum.
> Re-run `/gsd-review --phase 18 --all` after installing a second CLI (e.g. codex)
> for true adversarial cross-checking.

## Gemini Review

Here is the independent, adversarial review of the Phase 18 migration plans:

### 1. Summary
This is a highly structured, defensively engineered migration plan that effectively isolates the high-risk historical backfill from the atomic pipeline cutover. The sequencing into distinct waves, coupled with hard "gates" (consumer audits, overlap tests), demonstrates a strong grasp of fail-safe operational patterns. However, the explicit decision to omit value-locking from the baseline test, combined with the inherent data limitations of historical Tenable exports (specifically regarding intermediate reopened states), introduces a significant risk of silent calculation drift that visual UAT is ill-equipped to catch.

### 2. Strengths
* **Fail-Safe Gating Architecture:** The use of blocking gates—specifically the consumer audit test that intentionally tries to break existing metrics, and the overlap test before writing reconstructed data—is an exemplary risk mitigation strategy.
* **Immutability and Provenance:** Designing the reconstructed history as immutable, provenance-marked (`source: reconstructed`), and partially flagged (`partial=True`) ensures auditors can explicitly trace the origin of the data and protects captured baselines from corruption.
* **Decoupled Backfill (Plan 03 vs 04):** Separating the complex, error-prone historical reconstruction script from the actual atomic codebase cutover minimizes the blast radius. The migration cutover is simplified to just reading a store that is already populated.
* **Test-Driven Consumer Audit (Plan 02):** Building a test that intentionally feeds a 12-month dataset to a 30-day consumer to force an aggregation failure *before* fixing it is excellent defensive engineering.

### 3. Concerns
* **[HIGH] Value Drift Regression (Plan 01 & 04):** The structural smoke baseline explicitly states "values NOT locked." Relying solely on visual operator UAT (Plan 04, Task 4) to verify that 2,200 lines of bespoke calculation logic map perfectly to 7 new modules is extremely risky. Visual checks easily miss subtle percentage drifts, rounding errors, or edge-case omissions across different recipient groups.
* **[HIGH] Reopened Findings Temporal Paradox (Plan 03 / QUAL-02):** The plan asserts the backfill predicate is "reopened-aware." However, Tenable API exports typically retain only the *most recent* state transition timestamps (e.g., `last_fixed`, `last_found`). If a vulnerability was fixed, reopened, and fixed again over a 6-month period, the intermediate state history is lost. Reconstructing past months perfectly may be mathematically impossible, risking inaccurate historical metrics.
* **[MEDIUM] Consumer Audit Completeness (Plan 02):** The consumer audit explicitly tests `mttr_trend`, `new_vs_remediated`, and `critical_remediation_sla`. If a fourth, unlisted consumer of `fetch_fixed_vulnerabilities` exists in a different report or scheduled task, it will silently ingest 12 months of data, breaking its outputs.
* **[MEDIUM] API Assumption A2 Verification:** Relying purely on documentation for the exact Tenable `last_fixed` filter payload shape (`{"date": "YYYY-MM-DD", "modifier": "date-range"}`) is dangerous. Tenable export API schemas are notoriously finicky, and docs often lag behind strict validation rules.
* **[LOW] Legacy Archive Ingestion (Plan 04):** Moving legacy JSONs to `data/trend/legacy_archive/` is safe, provided `read_trend()` is strictly scoped to not traverse subdirectories; otherwise, the new modular pipeline might accidentally ingest incompatible legacy data shapes and trigger cold-start failures.

### 4. Suggestions
* **Implement a Value-Locked Parity Test:** In Plan 01, run the bespoke report against a *static synthetic dataset* (cached offline parquet) and lock the exact numerical outputs. In Plan 04, run the new modular pipeline against the same synthetic dataset and assert zero value drift automatically. Do not rely entirely on visual UAT for calculation parity.
* **Dynamic Consumer Discovery:** Instead of hardcoding the three known fixed-data consumers in the Plan 02 tests, use a codebase static analysis check (e.g., parsing imports or grep) within the test setup to dynamically discover all callers of `fetch_fixed_vulnerabilities` to ensure they are covered by the explicit window test.
* **Live API Verification Spike (A2):** Preempt Plan 02 with a quick live API spike (via `curl` or an isolated script) against the Tenable API to prove the assumed `last_fixed` payload shape is accepted and filters correctly *before* building the Python logic around it.
* **Acknowledge Reopened Data Limits in Runbooks:** In Plan 05, explicitly disclose the limitations of the "reopened-aware" predicate for historical backfill. State clearly to auditors that reconstructed months represent a best-effort approximation due to the loss of intermediate state transitions in API exports.
* **Assert Strict Directory Scoping:** Add a test in Plan 04 to ensure `read_trend()` explicitly ignores the `legacy_archive` folder and only targets files directly in the active trend directory.

### 5. Risk Assessment
**Overall Risk Level: HIGH**

*Justification:* While the deployment sequencing and structural safeguards are excellent (MEDIUM risk architecturally), the migration replaces 2,200 lines of bespoke calculations without automated numerical parity checks (value locking). When combined with the inherent data-loss limitations of API exports regarding "reopened" vulnerability histories, the probability of introducing silent, auditor-facing metric drift is HIGH. Implementing a static, value-locked regression test before the cutover would immediately downgrade this risk to LOW.

---

## Consensus Summary

Single-reviewer pass (gemini). The review is broadly **positive on the architecture
and sequencing** but raises two HIGH-severity concerns the planner should resolve or
explicitly accept before executing the cutover.

### Agreed Strengths
- The decoupled gate-chain (D-18-10) — consumer-audit gate, overlap-test gate, and
  the reconstruction-before-cutover ordering — is called out as exemplary fail-safe
  engineering.
- Provenance + immutability + partial-flag design for reconstructed history is judged
  sound for auditor trust (the explicit goal of DOC-02).

### Agreed Concerns (highest priority)
1. **[HIGH] No automated numerical parity check across the cutover.** The smoke
   baseline is structure-only ("values NOT locked"), and value-correctness rests on a
   human visual UAT (Plan 04 Task 4). Gemini argues a static-synthetic-dataset,
   value-locked parity test (bespoke vs. modular, asserting zero drift) would catch
   subtle percentage/rounding/edge-case drift that visual review misses — and would
   downgrade the whole phase from HIGH to LOW risk. **This is the single most
   actionable finding.**
   - *Caveat to weigh:* the project deliberately chose "structure locked, values not"
     (D-04-05) because the live values drift daily. A value-locked test is only viable
     against a **frozen synthetic input** run through *both* the bespoke and the
     migrated path. That requires capturing the parity fixture in Plan 01 *while the
     bespoke path still exists* — a real sequencing constraint, not a free add-on.
2. **[HIGH] Reopened temporal-paradox risk in reconstruction.** Gemini questions
   whether a single set of most-recent state timestamps can faithfully reproduce a
   fix→reopen→fix cycle's intermediate months. The planner's existing answer is the
   **overlap-test gate (D-18-09)** plus the validated two-interval `open_findings_at`
   predicate — but the review's point stands that perfect reconstruction of churned
   findings may be impossible, and this limitation should be (a) bounded by the
   overlap tolerance and (b) **disclosed in the Plan 05 runbook** as a best-effort
   approximation, which the current Plan 05 does not explicitly call out.

### Lower-priority concerns worth a cheap mitigation
- **[MEDIUM] Consumer-audit completeness:** the audit hardcodes three known consumers.
  A grep/static sweep for *all* callers of `fetch_fixed_vulnerabilities` would close
  the "unlisted fourth consumer" gap cheaply. (Note: the codebase is small and
  single-maintainer, so the residual risk is modest — but the sweep is ~free.)
- **[MEDIUM] A2 (last_fixed payload shape) is unverified.** Already flagged by the
  planner inside Plan 02; Gemini reinforces doing a live-API spike to confirm the
  filter shape *before* building logic around it, rather than verifying against the
  ref doc alone.
- **[LOW] read_trend() must not traverse `legacy_archive/`.** Add an explicit test in
  Plan 04 Task 3 asserting the archived JSON is not re-ingested.

### Divergent Views
None — single reviewer. The chief tension to adjudicate is **internal**: Gemini's
value-locked-parity recommendation vs. the project's deliberate D-04-05 "structure
locked, values not" decision. These are reconcilable only via a frozen-synthetic
parity fixture; decide whether that extra fixture earns its keep before execution.
