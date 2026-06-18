---
phase: 18
reviewers: [gemini, codex]
reviewed_at: 2026-06-18T13:52:34Z
plans_reviewed: [18-01-PLAN.md, 18-02-PLAN.md, 18-03-PLAN.md, 18-04-PLAN.md, 18-05-PLAN.md]
---

# Cross-AI Plan Review — Phase 18

> **Two-pass review.** **Gemini (pass 1, 2026-06-18T13:00Z)** reviewed the ORIGINAL plans;
> its two HIGH findings (value-locked parity, reopened temporal-paradox) plus three
> lower-severity items were INCORPORATED via `/gsd-plan-phase 18 --reviews` before this pass.
> **Codex (pass 2, 2026-06-18T13:52:34Z)** is the true independent second reviewer — it reviewed the
> REVISED plans. Read Codex's findings as critique of the CURRENT plans (actionable now);
> read Gemini's as historical context for changes already made. Codex surfaced four NEW
> HIGH findings the first pass missed, several of which refine the parity test added in pass 1.

## Gemini Review (pass 1 — original plans, already incorporated)

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

## Codex Review (pass 2 — current revised plans)

# Phase 18 Plan Review

## Summary

These plans are much stronger than a typical high-risk migration plan: they separate fetch widening, reconstruction, baseline capture, atomic cutover, and docs into distinct gates, and they correctly treat both Tenable retention and the bespoke removal as correctness risks rather than implementation chores. The main remaining risks are concentrated in two places: the value-locked parity thread may be too brittle or under-specified for metrics whose semantics intentionally changed, and the reconstruction plan still needs sharper handling of historical truth limits, snapshot dimensions, and real Tenable export behavior. I would not block the phase, but I would tighten several plan details before execution.

## Strengths

- Clear gate sequencing: fetch/consumer audit → reconstruction → baseline → cutover → docs is the right shape for this migration.
- Good recognition that widening `fetch_fixed_vulnerabilities()` is a behavioral change, not just a data-layer improvement.
- Strong dual-writer prevention: removing legacy trend writer/reader in the same cutover as `read_trend()` wiring is appropriate.
- The Plan 01/Plan 04 parity thread is a useful addition if scoped carefully: frozen synthetic inputs can catch rounding, denominator, and edge-case drift that live smoke tests cannot.
- Reconstruction guardrails are audit-minded: provenance, immutable reconstructed months, `asset_count: null`, partial flags, and overlap testing are all necessary.
- Plan 05’s reopened temporal-paradox disclosure is important and should stay. It is the most honest treatment of Tenable’s timestamp limitations.

## Concerns

### HIGH: Value parity may conflict with intentional metric changes

The plans require “zero numerical drift” between the bespoke path and the seven-module path, but the research already notes semantic shifts for at least Metric 5 and Metric 7:

- bespoke Metric 5: age-bucket histogram
- module: `aged_vulns_assets`
- bespoke Metric 7: simple MoM total-open delta
- module: `new_vs_remediated`

If those are intentionally different metrics, exact parity is impossible or misleading. The parity gate should distinguish:

- “same metric, must match exactly”
- “renamed/replaced metric, must satisfy mapped invariants”
- “new richer module, must match only shared subcomponents”

Otherwise Plan 04 may either fail for the right reason or force implementation work that preserves old semantics the milestone is trying to replace.

### HIGH: Plan 01 fixture appears incomplete for fixed-data metrics

Plan 01 commits only:

- `vulns_df.parquet`
- `assets_df.parquet`

But the target seven modules include fixed-data consumers:

- `mttr_trend`
- `new_vs_remediated`
- possibly `critical_remediation_sla` indirectly depending on shared tests

The fixture/golden plan should include `fixed_vulns_df.parquet` and any trend snapshot fixture needed to compute MoM values deterministically. Without that, the value golden may not actually exercise the highest-risk metrics.

### HIGH: Plan 02 live probe has a likely count-comparison error

The probe says filtered count should be less than the unfiltered default count. But if the default Tenable behavior is roughly 30 days and the probe uses `last_fixed >= 60-90 days ago`, the filtered result should usually be greater than the default, not smaller.

Better assertion:

- accepted by API
- sampled rows satisfy `last_fixed >= cutoff`
- 90-day filtered count is greater than or equal to 30-day/default count, or at least differs in the expected direction based on confirmed semantics
- a deliberately narrower cutoff, such as 7 days, returns fewer rows than 90 days

### HIGH: Reconstruction scope may only seed `severity/all_assets`

Plan 03 focuses on `trend_severity_all_assets.json`. If existing `management_summary` groups are tag-scoped, Plan 04’s `read_trend("severity", tag_filter_label, months=13)` may cold-start for tagged groups unless Plan 03 also reconstructs per configured tag filter.

This is a phase-goal risk because success criteria require existing delivery groups to work without YAML changes and MoM modules not to cold-start. The seeding script should either:

- reconstruct every `management_summary` delivery scope from `delivery_config.yaml`, or
- explicitly accept all-assets-only history and document tag-scoped cold starts

The current plans imply the first but only specify the second.

### MEDIUM: Plan 01 structural baseline is not clearly apples-to-apples

The smoke baseline must capture bespoke output using custom structural keys, then Plan 04 switches to `result["_bundle"]`. That can work, but it is fragile unless the key schema is defined as a stable contract.

Risk: the smoke diff fails because the two extractors describe different concepts, not because the migration regressed.

Add a small shared adapter or schema document used by both pre- and post-cutover capture paths.

### MEDIUM: Dynamic caller discovery can become noisy

The Plan 02 static sweep for `fetch_fixed_vulnerabilities` is useful, but it may find:

- tests
- probe scripts
- docs examples
- import-only references
- wrappers that do not consume results directly

The plan allows documenting pass-through callers, but it should define discovery scope precisely. Otherwise the test may become brittle and fail on harmless references.

### MEDIUM: `capture_snapshot()` after cutover may violate reconstructed immutability

Plan 03 says reconstructed months are immutable and never overwritten. Plan 04 says replace `_save_trend_snapshot()` with `capture_snapshot(...)`.

If `capture_snapshot()` overwrites the current month and the current month was seeded as reconstructed, the first migrated run could overwrite a reconstructed snapshot with captured data. That may be acceptable, but it conflicts with “reconstructed months never overwritten” unless explicitly limited.

Clarify intended behavior for the current month:

- captured snapshot supersedes reconstructed current month, or
- reconstructed months are skipped forever, including current month

The docs and tests should match the selected behavior.

### MEDIUM: Reconstruction month-boundary semantics need precision

The plan says month-boundary/month-end but does not require one canonical implementation detail. This matters for:

- `last_fixed > D`
- `first_found <= D`
- timezone conversion
- inclusive/exclusive boundaries
- month key local vs generated UTC

Use a single helper for `month_end_utc(month)` and test boundary cases exactly at `00:00:00` and `23:59:59`.

### MEDIUM: Plan 03 overlap fallback can be weaker than it sounds

Fallback “reconstruct today vs live current-state numbers” validates current open-count logic but does not validate historical fixed add-back very strongly. If no captured month exists, this gate is much less convincing.

Suggestion: require at least one synthetic integration-style overlap test with fixed-after-D add-back, and make the live fallback explicitly “weaker confidence” in the summary.

### LOW: Plan 02 file list omits `config.py`

Plan 02 adds `FIXED_LOOKBACK_DAYS` to `config.py`, but `config.py` is not listed in `files_modified`. That should be corrected.

### LOW: Some verify commands are Unix-flavored in a PowerShell environment

Several commands use `tail -20`. On this Windows/PowerShell workspace, that may work only if Unix tools are installed. Prefer PowerShell-native commands or simple pytest invocations.

### LOW: Plan 05 includes external/vulnerability-density disclosures outside the seven-module set

This may be intentional because v1.4 includes broader modules, but the plan title is management_summary docs. Keep it, but separate clearly:

- “management_summary seven modules”
- “related v1.4 disclosures not rendered in management_summary”

Otherwise auditors may wonder why external exposure and density are documented in the management summary runbook if they are not in the composed report.

## Suggestions

- Add `fixed_vulns_df.parquet` and trend snapshot fixtures to Plan 01’s parity fixture set.
- Change Plan 04 parity from “zero drift for all seven modules” to a mapping table:
  - exact parity metrics
  - tolerance parity metrics
  - invariant-only metrics
  - intentionally changed metrics with documented expected differences
- Fix Plan 02’s live probe count expectation; compare 7-day vs 90-day filtered pulls instead of filtered vs default.
- Expand Plan 03 to reconstruct all configured `management_summary` tag scopes, or explicitly document that only all-assets history is backfilled.
- Add explicit tests for `capture_snapshot()` behavior when a reconstructed current-month snapshot exists.
- Define one shared structural snapshot schema used by both pre-cutover bespoke capture and post-cutover `_bundle` capture.
- Add boundary tests for month-end reconstruction timestamps and timezone handling.
- Make `legacy_archive` scoping a unit test in `data/trend_store` rather than only in `tests/test_management_summary.py`, since it is a store-level contract.
- Add `config.py` to Plan 02’s `files_modified`.
- Replace `tail` in verification commands with PowerShell-safe alternatives.

## Risk Assessment

Overall risk remains **HIGH**, but the plans reduce it substantially. The high rating is justified by the size of the atomic removal, the change in metric execution path, and the fact that reconstructed history depends on Tenable export semantics that are only partially observable. The biggest execution risk is not sequencing anymore; it is correctness drift hidden behind overly broad parity claims or insufficiently scoped reconstruction. Tightening the parity mapping and reconstructing per delivery scope would move this closer to **MEDIUM-HIGH**.

---

## Consensus Summary

Two independent reviewers (Gemini pass 1 on original plans, Codex pass 2 on revised plans).
Both rate the phase **HIGH risk** and both praise the gate sequencing (D-18-10), the
provenance/immutability guardrails, and the decoupled reconstruction-before-cutover design.
Neither blocks the phase. The actionable signal is **Codex's four NEW HIGH findings against
the current plans** — three of which directly refine the value-locked parity test added in
pass 1, meaning the pass-1 fix was directionally right but under-specified.

### Agreed Strengths
- Gate sequencing (fetch/consumer-audit → reconstruction → baseline → cutover → docs) is the
  correct shape — called out by both reviewers.
- Audit-honesty guardrails (provenance, immutable reconstructed months, null `asset_count`,
  partial flags, overlap testing) judged necessary and sound by both.
- Codex independently endorsed the pass-1 additions: the parity thread "is a useful addition
  if scoped carefully" and the reopened temporal-paradox disclosure "is important and should stay."

### Agreed / Highest-Priority Concerns (all from Codex pass 2 — act on these before execution)
1. **[HIGH] Parity gate conflicts with intentional metric changes.** "Zero numerical drift"
   is wrong for metrics whose semantics deliberately changed — bespoke Metric 5 (age-bucket
   histogram) → `aged_vulns_assets`, and bespoke Metric 7 (MoM total-open delta) →
   `new_vs_remediated`. The gate must classify each metric: *exact-match* / *mapped-invariant* /
   *shared-subcomponent-only* / *intentionally-changed-with-documented-diff*. Otherwise Plan 04
   either fails for the wrong reason or forces preserving old semantics the migration is replacing.
   **This refines the pass-1 parity fix — it must not be a blanket zero-drift assertion.**
2. **[HIGH] Plan 01 parity fixture is incomplete.** It commits only `vulns_df.parquet` +
   `assets_df.parquet`, but the fixed-data modules (`mttr_trend`, `new_vs_remediated`,
   indirectly `critical_remediation_sla`) need `fixed_vulns_df.parquet` and a trend-snapshot
   fixture to compute MoM values deterministically. Without these, the golden does not exercise
   the highest-risk metrics — the parity gate would have a false sense of coverage.
3. **[HIGH] Plan 02 live-API probe has a likely count-direction bug.** A `last_fixed >= 60–90d`
   filter should return MORE rows than the ~30-day default, not fewer. Replace "filtered < default"
   with: API accepts the filter; sampled rows satisfy `last_fixed >= cutoff`; a 7-day cutoff
   returns fewer rows than a 90-day cutoff (monotonic-direction check).
4. **[HIGH] Reconstruction may only seed `severity/all_assets`.** If `management_summary`
   delivery groups are tag-scoped, Plan 04's `read_trend("severity", tag_filter_label, …)` will
   cold-start for tagged groups — violating the success criterion that existing groups work
   without YAML changes. Plan 03 must either reconstruct every configured `management_summary`
   scope from `delivery_config.yaml`, OR explicitly document all-assets-only history + accept
   tag-scoped cold starts. Current plans imply the former but specify the latter.

### Lower-priority (cheap to fix during execution)
- **[MED]** Define one shared structural-snapshot schema/adapter used by BOTH the pre-cutover
  bespoke capture and the post-cutover `_bundle` capture, so the smoke diff fails only on real
  regression, not on two extractors describing different shapes.
- **[MED]** Scope the Plan 02 dynamic caller sweep precisely (exclude tests/docs/import-only/
  pass-through) so it isn't brittle.
- **[MED]** Clarify `capture_snapshot()` behavior when the current month was seeded as
  reconstructed — does a captured snapshot supersede it, or are reconstructed months skipped
  forever? Docs + tests must match the chosen rule (immutability contract, D-18-03).
- **[MED]** Pin month-boundary semantics to one `month_end_utc(month)` helper; test exactly at
  `00:00:00` and `23:59:59`; settle inclusive/exclusive + tz.
- **[MED]** Strengthen the Plan 03 overlap fallback — require a synthetic integration test with
  fixed-after-D add-back; mark the live-today fallback as explicitly weaker confidence.
- **[LOW]** Add `config.py` to Plan 02 `files_modified` (it adds `FIXED_LOOKBACK_DAYS`).
- **[LOW]** Make `read_trend()` legacy_archive scoping a `data/trend_store` unit test (store-level
  contract), not only a `test_management_summary.py` test.
- **[LOW]** Replace Unix `tail -20` verify commands with PowerShell-safe / pytest-native ones.
- **[LOW]** In Plan 05, separate "management_summary seven modules" from "related v1.4 disclosures
  not rendered in the composed report" (external exposure, density) to avoid auditor confusion.

### Divergent Views
No direct contradiction. The reviewers reviewed different plan versions, so divergence is
temporal: Gemini's pass-1 HIGHs are resolved; Codex's pass-2 HIGHs are open. The one tension to
adjudicate is **how strict the parity gate should be** — pass 1 pushed toward value-locking;
pass 2 warns that a blanket zero-drift lock is wrong for the intentionally-changed metrics. The
reconciliation is a per-metric parity classification, not a single global assertion.
