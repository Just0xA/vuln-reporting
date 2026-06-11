---
phase: 15
reviewers: [gemini]
reviewed_at: 2026-06-11T19:58:24Z
plans_reviewed: [15-01-PLAN.md, 15-02-PLAN.md, 15-03-PLAN.md, 15-04-PLAN.md, 15-05-PLAN.md, 15-06-PLAN.md]
---

# Cross-AI Plan Review — Phase 15

## Gemini Review

# Phase 15 Plan Review: Independent New Modules

This review covers implementation plans **15-01 through 15-06** for the Vulnerability Management Reporting Suite.

## Summary

The Phase 15 plans are exceptionally well-structured, demonstrating a deep understanding of the established modular framework and the specific requirements of the June 2026 reporting batch. The decomposition into a "Pathfinder" wave (`reopened_vulns` for contract/UI validation and `trend_store` extension for data substrate) followed by parallel module development is a mature architectural strategy. The plans rigorously enforce the mandated quality bars (QUAL-01..05), particularly the transition to "Reopened-aware" logic and pandas 3.0 CoW compliance. The strategy for `new_vs_remediated` (Option B), which sources outflow data from trend snapshots rather than live re-fetches, is a notable efficiency optimization that maintains data consistency while reducing API/compute load.

## Strengths

- **Strategic Build Order:** Using `reopened_vulns` as a pathfinder (15-01) allows for UI/contract validation before the other modules copy the pattern, while the `trend_store` extension (15-02) unblocks all MoM modules.
- **Data Integrity (Pitfall 4/6):** The plans specifically address complex edge cases like "Retroactive Drift" in vulnerability density by using snapshot-local denominators and "Expiry Awareness" in Accepted/Recast logic.
- **Accurate Inflow Model (D-15-01/02):** The decision to stack `net-new` and `resurfaced` components in `new_vs_remediated` provides high-signal visibility into "reopen churn," fulfilling the user's specific request for accuracy over simplicity.
- **PII Discipline:** Rigorous adherence to the aggregate-only boundary for committed fixtures and snapshots (QUAL-05/D-04-08) is consistent across all plans.
- **Efficiency (Option B):** Sourcing outflow/remediated counts from trend snapshots in `new_vs_remediated` avoids redundant fixed-vulnerability exports, which are historically slow/heavy operations.
- **Robust Fail-Softs:** Every plan includes zero-row guards, `safe_*` formatting, and graceful degradation paths (e.g., count-only mode if fixed exports are missing).

## Concerns

- **`resurfaced_date` Population (MEDIUM):** RPT-03 and the `new_vs_remediated` definition rely heavily on `resurfaced_date`. While 15-01 includes a live-tenant spot-check, if population is significantly lower than the ~19% reopen rate cited in spikes, the MTTR and Inflow metrics may appear artificially low.
- **Snapshot Extension Backward Compatibility (LOW):** 15-02 extends the JSON schema. While read-level `.get(..., None)` guards are planned, existing logic in `management_summary` (pre-migration) must be verified to ensure it doesn't choke on unexpected keys if it uses strict dict unpacking (unlikely given current patterns, but worth noting).
- **Chart Complexity (LOW):** The stacked bar chart for `new_vs_remediated` (net-new + resurfaced inflow vs remediated outflow) will be information-dense. Visual clarity in the PDF channel will be critical to ensure management can distinguish "growth" from "churn."

## Suggestions

- **Inflow Disclosure:** In `new_vs_remediated`, add a small tooltip or footnote in the PDF/Excel channels clarifying that "Resurfaced" counts findings that were previously "Fixed" but have re-appeared, to distinguish them from findings that were never fixed.
- **Drift Sensitivity:** For `vuln_density` (15-05), consider making the 10% drift threshold overridable via `module_options`, similar to the RAG bands, to allow for environments with naturally high asset volatility.
- **Analyst Tab Clarity:** In the `reopened_vulns` analyst tab, explicitly label the `reopen_lag_days` as "Days since last fix" to avoid ambiguity for auditors.

## Risk Assessment: LOW

The overall risk is **LOW**. The plans are highly surgical, use proven patterns (copying `mttr_by_severity`), and are backed by a robust TDD approach with strict CoW enforcement. The dependency chain is logical, and the use of Phase 14 substrates ensures that Phase 15 remains focused on business logic and rendering rather than I/O or classification.

**Verdict:** The plans are ready for execution. Proceed with Wave 1 (`15-01` and `15-02`).

---

## Consensus Summary

Single reviewer (Gemini). Verdict: **LOW risk — plans ready for execution.**

### Agreed Strengths
- Strategic build order: `reopened_vulns` (15-01) as pathfinder for contract/UI validation; `trend_store` extension (15-02) unblocks all MoM modules before parallel module work.
- Data-integrity edge cases handled: snapshot-local denominators for density retroactive drift (Pitfall 4); expiry-awareness in Accepted/Recast (Pitfall 6).
- Accurate inflow model honored: stacked net-new + resurfaced (D-15-01/02), not simplified back to first_found-only.
- PII discipline: aggregate-only boundary consistent across fixtures and snapshots (QUAL-05 / D-04-08).
- Option-B outflow sourcing (trend snapshot `fixed_findings_count`) avoids redundant heavy fixed-vuln exports.
- Robust fail-softs: zero-row guards, `safe_*` formatting, graceful count-only degradation.

### Agreed Concerns
- **MEDIUM — `resurfaced_date` population:** RPT-03 and the inflow definition lean on `resurfaced_date`. The 15-01 live-tenant spot-check is the right mitigation, but if population is materially below the ~19% reopen rate, Inflow/MTTR signals could read artificially low. (Already gated by the 15-01 checkpoint task.)
- **LOW — snapshot backward-compat:** verify no strict dict unpacking in pre-migration `management_summary` chokes on new snapshot keys (15-02 plans `.get(..., None)` read guards).
- **LOW — chart density:** the `new_vs_remediated` stacked chart (net-new + resurfaced vs remediated) is information-dense; PDF visual clarity matters for distinguishing growth from churn.

### Divergent Views
None — single reviewer.

### Suggestions (non-blocking, candidates for execution-time polish)
- `new_vs_remediated`: PDF/Excel footnote clarifying "Resurfaced" = previously-fixed findings that re-appeared.
- `vuln_density` (15-05): make the 10% denominator-drift threshold `module_options`-overridable (mirrors the RAG-band pattern in D-15-07).
- `reopened_vulns` (15-01): label `reopen_lag_days` as "Days since last fix" in the analyst tab.
