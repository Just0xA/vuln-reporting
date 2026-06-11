# Phase 13: Owner Segmentation + Composition (S2 + Doc) - Context

**Gathered:** 2026-06-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver **Owner-tag segmentation (S2)** as the stakeholder-routing dimension for the board-style reports, **prove it composes with the trend primitive (S1)** end-to-end, and ship the **auditor runbook (DOC-01)**.

This phase reframes the roadmap's abstract "reusable segmentation helper" into its concrete intent: **start driving the reports to the actual stakeholders.** Today the board "Business Unit" tables are sourced from the `Application` tag (an interim stand-in). This phase **repoints them to the `Owner` tag** (= the Application Support group that owns patching), keeps `Application` as a nested analyst drill-down, and generalizes the shared helper so future ownership tags slot in without a rewrite.

**The ownership model (locked — this is the conceptual anchor):**
- **`Owner` tag = "Application Support"** — the group responsible for maintaining, upgrading, and **patching** the application. **This is where vulnerabilities go**, so it is the grouping/routing dimension for reporting and (eventually) performance metrics. Phase 13 targets this.
- **Business Unit** — owns the application overall; the normal end users. A **future tag** (real `business_unit` tag, not yet populated in Tenable); reference-only for now.
- **Technical Support** — general server/OS engineering & operations (handles OS-type vulns, MS Security Updates for Server 20xx). A **future category**; reference-only for now.

**In scope:** SEG-01..05, DOC-01 —
- Generalize the shared BU helper to be **Owner-primary and tag-category-parameterized**.
- Repoint the **4 board modules** + shared `board_report_utils.py` from `Application` → `Owner`.
- Lossless **`Unassigned`** catch-all (configurable label) so per-Owner totals reconcile to the whole; fail-soft when `Owner` is absent/partial.
- **Combined analyst supplemental** Excel (Owner → Application nesting + Unassigned cleanup worklist).
- **Per-Owner trend composition** (`dimension="owner"`) proving S1×S2.
- **DOC-01** auditor runbook covering the open predicate, ~29-day retention / forward-accumulation, and the Owner/Unassigned model.

**Out of scope (this phase):**
- `management_summary` and `composed_report` Owner wiring (GEN-01; deferred — see Deferred Ideas).
- Building the future **Business Unit** and **Technical Support** tags/dimensions (reference-only now; design must not block them).
- Linking performance-metric *responsibility* to Owner + Business Unit (connections "not as clear yet" — future).
- All v1.4 report modules.

</domain>

<decisions>
## Implementation Decisions

### Ownership model & dimension
- **D-01:** **`Owner` is the active stakeholder dimension** and maps to the **Application Support** group (patching-responsible). Reporting groups by `Owner`. Business Unit and Technical Support are **future/reference** tags — design generally enough to add them later, but do not build them now.
- **D-02:** **Report-facing heading reads `"Owner"`** (per user choice) across PDF tables and Excel tabs — not "Business Unit" (now misleading) and not "Application Support" (raw-tag clarity wins).

### Helper generalization & code shape
- **D-03:** **Generalize the existing shared helper, do not build a parallel one.** `reports/modules/board_report_utils.py` (`BU_TAG_CATEGORY`, `extract_business_unit`, `aggregate_by_business_unit`, BU risk-score) becomes **Owner-primary and tag-category-parameterized**. This satisfies SEG-01/04 with minimal churn and auto-fixes every consumer. SEG-01's "reusable helper" = this generalized utility.
- **D-04:** **Rename the grouping column `business_unit` → `owner`.** Frees the `business_unit` name for the *future real* Business Unit tag (avoids a later collision). Touches the consumer modules' column references.
- **D-05:** **Keep `Application` as a separate parsed column** for the nested analyst drill-down (no longer the source of the primary grouping). The helper must extract **both** `Owner` (primary) and `Application` (nested).

### Catch-all & fail-soft (SEG-02/04)
- **D-06:** **`Unassigned` is the catch-all label (configurable).** Standardize away from the existing `"Untagged"` fillna. Assets with no `Owner` tag (or `Owner` present but empty) fall into a single `Unassigned` bucket so per-Owner totals **always reconcile to the whole**.
- **D-07:** **Fail-soft when `Owner` is absent/partial** → everything `Unassigned`, no crash; empty-data guard per CLAUDE.md (`safe_pct`/`safe_int`/`safe_format`). All 4 consumer modules must continue to deliver.

### Blast radius — repoint to Owner (confirmed complete by grep + user)
- **D-08:** Repoint these and **only** these (full set; no other file references `business_unit`/the BU tag):
  - `reports/modules/board_report_utils.py` — **the shared helper** (where generalization happens)
  - `reports/modules/aged_vulns_assets_module.py`
  - `reports/modules/critical_remediation_sla_module.py`
  - `reports/modules/high_risk_assets_module.py`
  - `reports/modules/scan_coverage_sla_module.py`

### Combined analyst supplemental (SEG-03)
- **D-09:** **One combined supplemental Excel**, **single flat tab**: `Owner` + `Application` + counts columns. `Unassigned` appears as an `Owner` value; **blank-Owner / Unassigned rows double as the "which applications still need an Owner assignment" worklist**, driving tagging cleanup. Sortable/filterable for analysts. Follow the `unscanned_assets.py` analyst-Excel precedent.

### PII rule — reinterpreted (supersedes literal SEG-03 wording)
- **D-10:** **The PII discipline (D-04-08 / SEG-03) is about (a) NOT transmitting row-level asset data to the AI assistant (Claude), and (b) NOT committing it to the repository — it is NOT a ban on internal corporate email.** Therefore:
  - ✅ The combined supplemental (with asset-level Application / Unassigned rows) **may be emailed internally** (server → corporate email group).
  - ❌ Must **not be committed to the repo** and **not be fed into AI/Claude context**.
  - This **explicitly supersedes** the literal SEG-03 phrasing "not attached to any email." DOC-01 must document the *real* rationale (AI/repo exposure, not email).
- **D-11:** **The trend store stays aggregate-only (TREND-06 unchanged).** D-10 is about the analyst supplemental's delivery, not the persisted `data/trend/` payloads — those remain counts-only, no row-level fields.

### Trend composition (SEG-05)
- **D-12:** **`dimension="owner"`, one file, per-Owner counts.** `capture_snapshot(dimension="owner", ...)` writes a single `trend_owner_<tagsuffix>.json` with a count per Owner; `read_trend("owner", ...)` returns the month-over-month series. Matches roadmap SC4 ("`capture_snapshot` accepts an `owner` dimension argument") and the existing Phase-12 `capture_snapshot(df, assets_df, date, dimension, tag_filter, ...)` / `read_trend(dimension, tag_filter, months, ...)` surface — no signature reshape needed.

### Claude's Discretion
- Exact generalized function/parameter names and signatures in `board_report_utils.py` (beyond the agreed Owner-primary + parameterized shape and the `owner` column rename).
- Exact filenames/paths for the combined supplemental and where in the run output it lands (within D-10's not-committed / not-AI constraint).
- Precise `trend_owner_*.json` count-key encoding and tag-suffix convention (follow Phase-12 `trend_<dimension>_<tagsuffix>.json` precedent).
- Whether the configurable `Owner` category name and `Unassigned` label are module constants vs config-driven (follow existing `BU_TAG_CATEGORY` precedent).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements & roadmap
- `.planning/REQUIREMENTS.md` — SEG-01..05, DOC-01 definitions.
- `.planning/ROADMAP.md` — Phase 13 goal + 5 success criteria (reconcile-to-whole, fail-soft, local exception list, owner-dimension snapshot/read, DOC-01 content).

### Phase 12 substrate this phase composes with (S1)
- `.planning/phases/12-trend-snapshot-substrate-s1/12-CONTEXT.md` — S1 decisions (D-03 file-per-dimension shape, D-08 df-injected `capture_snapshot`, D-09 `dimension`+`tag_filter` parameterization forward-compatible with Owner).
- `data/trend_store.py` §§193 (`capture_snapshot(df, assets_df, date, dimension, tag_filter, trend_dir)`), §291 (`read_trend(dimension, tag_filter, months, trend_dir)`) — the surface SEG-05 exercises.
- `utils/open_count.py` §19 (`open_findings_at`) — the reopened-aware two-interval predicate DOC-01 must document.

### Code to generalize / repoint (D-03, D-08)
- `reports/modules/board_report_utils.py` §48 (`BU_TAG_CATEGORY = "Application"`), §206 (`extract_business_unit`), §291 (`aggregate_by_business_unit`), §429+ (BU risk-score) — **the shared helper**; generalize to Owner-primary + parameterized, rename column to `owner`, add Application extraction.
- `reports/modules/aged_vulns_assets_module.py`, `critical_remediation_sla_module.py`, `high_risk_assets_module.py`, `scan_coverage_sla_module.py` — consumers to repoint.
- `reports/modules/critical_remediation_sla_module.py` §978 (`_extract_owner_tag`) — **existing Owner-tag parser**; reuse/promote into the shared helper rather than re-implementing.
- `utils/tag_helper.py` §90 (`enrich_vulns_with_tags`) — tag-category → `tag_<category>` column join (multi-value joined with `" | "`); relevant to how Owner/Application columns are sourced.

### Style & convention precedents
- `reports/unscanned_assets.py` §§431/518/570 (`_write_summary_tab`, `_write_data_tab`, `_write_csv`) — analyst-Excel companion precedent for the combined supplemental (D-09).
- `docs/management_summary_calculations.md` — the `docs/*_calculations.md` runbook style DOC-01 must match.
- `CLAUDE.md` — empty-data guard, fail-soft batch semantics, atomic-write + timezone policy, four-channel module render contract.

### Spike findings (settled constraints DOC-01 documents — do not re-decide)
- `.claude/skills/spike-findings-vuln-reporting/SKILL.md` + `references/vuln-metric-substrate.md` — reopened-aware predicate, snapshot-not-reconstruction, ~29-day retention.
- `.planning/notes/trend-reconstruction-engine.md` — forward-accumulation model, no backfill.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`board_report_utils.py` BU helper** — generalize in place (D-03); `extract_business_unit`/`aggregate_by_business_unit`/`BU_TAG_CATEGORY` already implement the exact group-by-tag + fillna-catch-all pattern, just hardcoded to `Application`.
- **`critical_remediation_sla_module._extract_owner_tag` (§978)** — already parses the `Owner` value from a Tenable `"Cat=Val;Cat=Val"` string; promote to the shared helper (single source of truth).
- **`data/trend_store.py` `capture_snapshot`/`read_trend`** — already `dimension`+`tag_filter`-parameterized (Phase 12 D-09); SEG-05 needs no signature change, only `dimension="owner"` count logic.
- **`reports/unscanned_assets.py`** — analyst-Excel companion template (summary/data tabs, CSV writer) for the combined supplemental.

### Established Patterns
- **Group-by-tag with fillna catch-all** — existing `bu_counts["business_unit"].fillna("Untagged").replace("", "Untagged")`; standardize to `Unassigned` (D-06).
- **Pure compute, deferred I/O** — predicate/segmentation stay pure; capture/render do I/O.
- **File-per-dimension trend store** — `trend_<dimension>_<tagsuffix>.json` (Phase 12); `owner` is a new dimension file, never touches `severity`.

### Integration Points
- 4 consumer modules import the shared helper → repointing the helper + renaming `business_unit`→`owner` flows through all four (D-04, D-08).
- New `trend_owner_*.json` under `data/trend/` (gitignored, aggregate-only).
- Combined supplemental written to run output (not committed, not AI-transmitted; internal email OK — D-10).

</code_context>

<specifics>
## Specific Ideas

- Combined supplemental = one flat tab: `Owner | Application | <counts>`, `Unassigned` as an Owner value; blank-Owner rows = "needs assignment" worklist (D-09).
- `Owner` heading everywhere; `Unassigned` catch-all (D-02, D-06).
- Owner snapshot file e.g. `data/trend/trend_owner_all_assets.json`, per-Owner open counts (D-12).
- Helper extracts both `owner` (primary grouping) and `application` (nested) columns (D-05).

</specifics>

<deferred>
## Deferred Ideas

- **Build the real Business Unit tag/dimension** — future; once populated in Tenable, the generalized helper (D-03) and freed `business_unit` column name (D-04) accommodate it without a rewrite.
- **Technical Support category** (server/OS engineering; OS/MS-update vulns) — future reference dimension.
- **Performance-metric responsibility mapping** to Owner + Business Unit — "connections not as clear yet" (user); future.
- **`management_summary` / `composed_report` Owner wiring** — GEN-01 (v1.4 backlog); out of scope to protect existing delivery and avoid pulling GEN-01 forward.
- **Per-Owner severity breakdown in trend** (vs per-Owner total counts) — D-12 captures per-Owner counts; severity-within-owner trend is a richer future option if needed.

### Reviewed Todos (not folded)
None — no pending todos matched Phase 13.

</deferred>

---

*Phase: 13-owner-segmentation-composition-s2-doc*
*Context gathered: 2026-06-10*
