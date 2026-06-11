# Phase 15: Independent New Modules - Context

**Gathered:** 2026-06-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Five new four-channel metric modules, each a **thin consumer** of the shipped
S1 (trend) + S2 (Owner) substrates and the Phase 14 kwargs gates, with **no
peer-module dependencies**:

1. **New vs Remediated** (`new_vs_remediated`) — monthly inflow vs outflow, net delta, Owner cut
2. **Vulnerability Density** (`vuln_density`) — vulns-per-asset MoM, each month its own denominator
3. **Reopened Vulnerabilities** (`reopened_vulns`) — `state==REOPENED` count + rate, Owner cut, analyst drill-down
4. **Accepted & Recast** (`accepted_recast`) — ACCEPTED vs RECASTED tracked separately, MoM delta, Owner cut
5. **External / DMZ Exposure Cut** (`external_dmz`) — host-vuln findings on externally-scoped assets + mismatch list

Every module implements the **full four-channel render contract** (PDF section,
Excel tabs, email panel, analyst tabs, RAG-strip entry). This phase clarifies
*how* to implement what RPT-01/02/03/04/06 already scope — it does not add new
capabilities. MTTR rework (Phase 16), Program Health (Phase 17), and the
`management_summary` migration (Phase 18) are explicitly out of this phase.

QUAL-01/02/03/05 are **first verified here** and become acceptance bars for
every later v1.4 phase.

Requirements: RPT-01, RPT-02, RPT-03, RPT-04, RPT-06, QUAL-01, QUAL-02,
QUAL-03, QUAL-05.

</domain>

<decisions>
## Implementation Decisions

### "New" inflow definition (OD-1 — locked; user diverged from research default)
- **D-15-01:** "New" inflow = **`first_found` in month M OR `resurfaced_date`
  in month M** — the more accurate definition that reflects all work hitting
  the queue, NOT the simpler `first_found`-only research recommendation. The
  user explicitly chose accuracy over simplicity here.
- **D-15-02:** New-vs-Remediated displays inflow as **two stacked components**:
  **net-new** (`first_found` in M) and **resurfaced** (`resurfaced_date` in M).
  Management sees the split, not a single blended "New" bar. This is required
  in the PDF chart and the supporting table; the email/RAG headline may use the
  combined inflow total but the split must be visible in the detailed channels.

### New-vs-Remediated × Reopened module relationship (OD-1 consequence — locked)
- **D-15-03:** A resurfaced finding is counted in **both** modules by design —
  as the *resurfaced* inflow component in New-vs-Remediated AND as a reopen
  event in `reopened_vulns`. Each module is internally correct for its own
  question. **No cross-module subtraction.** Each module's runbook (DOC-02,
  Phase 18) must carry a one-line note that resurfaced findings appear in both.

### S1 snapshot dimension extension (OD-3 — locked)
- **D-15-04:** **Extend `capture_snapshot`** with new aggregate count fields
  rather than writing module-local snapshot files. Keeps one trend file per
  scope; avoids proliferating files and duplicated cold-start/idempotency
  logic. Follows the trend-store-as-single-source pattern.
- **D-15-05:** New dimensions to add (all **aggregate counts only**, QUAL-05 /
  D-04-08): on-time-scanned asset count (for Density denominator, fulfilling
  the Phase-14 D-02 dependency), reopened count, accepted count, recast count,
  and the new-vs-fixed counts needed for New-vs-Remediated trend context.
- **D-15-06:** **Backward-compatible extension** — existing snapshots lacking
  the new fields are a valid **cold-start** state for the new dimensions
  (absent field → `insufficient_data` branch), never a crash. Existing callers
  and existing trend files must not break; verify with a trend-store smoke
  check during planning. The density / reopened / accepted-recast MoM trends
  **cold-start on the new fields and accumulate forward** (no back-reuse of the
  all-asset `asset_count` history for density — Phase 14 D-02).

### RAG thresholds (locked)
- **D-15-07:** Ship the **research default bands as `module_options`-overridable
  defaults**, not hard-coded constants. Defaults: Density Green ≤2 / Amber ≤4 /
  Red >4 vulns-per-asset; Reopen rate Green <5% / Amber 5–10% / Red >10%;
  Accepted/Recast rate Green <5% / Amber 5–15% / Red >15%; External Crit Green 0
  / Amber 1–5 / Red >5. Tunable per group via `module_options` without code
  changes. (No org-specific values supplied yet — defaults stand until leadership
  agrees bands.)

### Partial current month (locked)
- **D-15-08:** **Show** the in-progress current month in every MoM trend, but
  **label it "Month-to-date (partial)"** explicitly in all four channels so a
  half-month is never read as a real drop. Applies to New-vs-Remediated,
  Density, Reopened, and Accepted/Recast trend charts/tables.

### Plan decomposition / build order (locked)
- **D-15-09:** **Reopened first** as the contract-validation **pathfinder**
  (no trend dependency for its current-month count; exercises `state` /
  `resurfaced_date` and the full four-channel shape), then the other four
  modules as **parallel plans** that copy the proven module shape. Confirm
  `resurfaced_date` population on a live-tenant sample as part of the Reopened
  plan before finalizing its analyst drill-down schema.

### Carried forward from Phase 14 (locked — do NOT re-decide)
- **Density denominator = on-time-scanned licensed assets** (Phase 14 D-01),
  reusing `scan_coverage_sla_module`'s on-time split; flag denominator MoM
  change >10% (success criterion 2).
- **External classification model** (Phase 14 D-04–D-11): tags authoritative
  (`Location=External` OR `Location=DMZ`); `is_public_ipv4()` is a **gap
  detector only** (`public_ip_untagged` mismatch reason), never overrides a
  tag; DMZ-tagged + private IP is **normal, not a mismatch**; empty/unpopulated
  DMZ tag is a valid zero state; CGNAT is a non-issue on real data; classify on
  the single primary `ipv4` column (no fetcher change).
- **External MoM trend deferred to v1.5** (Phase 14 D-03 / EXT-TREND-01) —
  `external_dmz` is **current-snapshot only**.
- **Mismatch-list PII boundary** (D-11 / D-04-08): asset-level mismatch fields
  (`asset_uuid`, `ip_address`, `owner_tag`, `untagged_reason`) allowed in the
  operator-local analyst tab and internally-emailed reports; **never committed
  to repo, never sent to AI**. Committed/aggregate external counts stay
  `finding_count`-only.

### Mandatory QUAL acceptance bars (not gray areas — enforced, first verified here)
- **QUAL-01** cold-start: every MoM module branches on the trend store's
  `insufficient_data` signal; renders a "Trend data being established" notice,
  never `NaN%` or a crash. Every new tag/Owner scope is a valid cold start.
- **QUAL-02** reopened-aware predicate: all open-count logic uses
  `utils/open_count.py` `open_findings_at()` (two-interval) — no ~19% REOPENED
  drop.
- **QUAL-03** empty-data guard: every module survives a zero-row filtered input
  on all four channels; use `safe_pct` / `safe_int` / `safe_format` and
  `_empty_result()`; **no `df["col"]=val` after a filter** anywhere (pandas CoW;
  `.assign()` only — burned in `260611-b1x`).
- **QUAL-05** aggregate-only PII: no committed fixture/baseline contains real
  hostnames, IPs, or plugin names; synthetic data uses RFC 6761/5737 addresses.

### Claude's Discretion
- Exact module file/class structure, chart styling, table column ordering,
  `_summarize_filter()` use in the Accepted & Recast analyst tab, fixed-export
  -absent disclosure wording (degrade to count-only with an explicit note —
  never silent zero), `time_taken_to_fix` vs date-arithmetic derivations, and
  the precise reopen-lag computation (`resurfaced_date − last_fixed`, `None`
  when `resurfaced_date` absent) are implementation details for research/planning.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` § "Phase 15: Independent New Modules" — goal, success
  criteria 1–7, OD-1/OD-3 + `resurfaced_date` verification assignments.
- `.planning/REQUIREMENTS.md` — RPT-01/02/03/04/06; QUAL-01/02/03/05 bars;
  Out-of-Scope (WAS, External MoM); Plan-Time Decisions table (OD-1, OD-3).
- `.planning/research/SUMMARY.md` — OD-1/OD-3 recommendations (note: user
  diverged from OD-1 default), build-order rationale, untouched-files list.
- `.planning/research/FEATURES.md` — per-module feature analysis (Modules 1–4,
  7): data fields, channel content, edge cases, dependencies.
- `.planning/research/PITFALLS.md` — mandatory acceptance bars (cold-start,
  density denominator drift, reopened predicate, MTTR inflation, CoW,
  empty-data, PII).
- `.planning/research/ARCHITECTURE.md` — composed_report integration; module
  file inventory; `**self._kwargs` fan-out.

### Prior phase context (foundation this phase consumes)
- `.planning/phases/14-shared-substrates-composed-report-gates/14-CONTEXT.md` —
  D-01 (density denominator), D-02 (density cold-starts on a NEW on-time-scanned
  snapshot field — Phase 15 creates it), D-03–D-11 (external model), D-15/D-16
  kwargs gates, D-17 (`reopened_vulns` trend-membership decided here).

### Proven patterns to mirror
- `data/trend_store.py` — `read_trend()` `{snapshots, insufficient_data}`;
  `capture_snapshot()` (the function D-15-04/05 extends); `asset_count` field
  (D-04). Extension MUST be backward-compatible (D-15-06).
- `reports/composed_report.py` — `_MODULES_NEEDING_TREND_SNAPSHOTS` /
  `_MODULES_NEEDING_RECAST_RULES` frozensets (Phase 14); add the new modules
  to the appropriate gate when they need trend/recast kwargs.
- `reports/modules/board_report_utils.py:214` `extract_owner()` + `_parse_tags`
  — S2 Owner cut + `Unassigned` catch-all for every module's Owner dimension.
- `reports/modules/scan_coverage_sla_module.py` — on-time split = Density
  denominator basis (D-01); `ON_TIME_SCAN_WINDOW_DAYS` (Phase 14, `config.py`).
- `utils/external_scope.py` — Phase 14 classifier; `(scoped_df, mismatches_df)`
  tuple consumed by `external_dmz`.
- `utils/asset_count.py` — Phase 14 current-run denominator for `vuln_density`.
- `utils/open_count.py` `open_findings_at()` — reopened-aware predicate (QUAL-02).
- `reports/modules/format_utils.py` (`safe_pct`/`safe_int`/`safe_format`) +
  `rag_utils.py` (`build_rag_strip_entry`, `STATUS_COLOR`) — QUAL-03 + RAG strip.
- `reports/modules/base.py` `BaseModule` / `_empty_result()` / four-channel
  contract — the shape every new module implements.
- `reports/modules/mttr_by_severity_module.py` — existing four-channel module
  to copy structure from (note: itself reworked in Phase 16, not here).
- `data/fetchers.py:357-360,470-473` — `severity_modification_type`,
  `resurfaced_date` already fetched (Accepted&Recast + Reopened source fields);
  `fetch_recast_rules()` + `_summarize_filter()` (Accepted&Recast enrichment).

### Spike findings (project skill — auto-loaded)
- `.claude/skills/spike-findings-vuln-reporting/SKILL.md` — VPR-first severity;
  reopened-aware predicate is mandatory (naive drops ~19%); trend =
  forward-accumulating snapshots (Tenable ~29-day fixed retention; cold start
  is real).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **Phase 14 substrates** are ready to consume: `utils/external_scope.py`
  (`external_dmz` scope), `utils/asset_count.py` (`vuln_density` denominator),
  the two composed_report kwargs gates (trend snapshots + recast rules).
- **`extract_owner()`** gives every module its Owner cut + `Unassigned`
  catch-all with one call.
- **`read_trend()` / `capture_snapshot()`** already cold-start-safe and
  idempotent; this phase extends the snapshot record with new aggregate fields.
- **`format_utils` / `rag_utils`** cover the empty-data guard and RAG strip
  with no new code.

### Established Patterns
- Four-channel module contract + auto-discovery: new `*_module.py` files
  self-register via `@register_module`; modules consumed only through
  `composed_report` need **no** `run_all.py` / `_VALID_REPORTS` registration.
- Gate frozenset + `**composer_kwargs` fan-out: adding a module to
  `_MODULES_NEEDING_TREND_SNAPSHOTS` / `_MODULES_NEEDING_RECAST_RULES` is the
  only wiring needed to receive trend/recast kwargs.
- pandas 3.0 CoW — `.assign()` only, never `df["col"]=` after a filter.

### Integration Points
- `data/trend_store.py` `capture_snapshot()` — the one shared file this phase
  modifies (new aggregate dimensions, backward-compatible).
- `reports/composed_report.py` — add new modules to the relevant gate frozenset
  (no signature change).
- Otherwise each module is a self-contained new file under
  `reports/modules/` plus its unit-test + synthetic fixture.

</code_context>

<specifics>
## Specific Ideas

- **OD-1 divergence is deliberate.** The user chose `first_found OR
  resurfaced_date` AND the stacked net-new/resurfaced display — they want
  management to see reopen churn explicitly, not hidden behind a simpler
  first_found-only inflow. Honor both the definition (D-15-01) and the visual
  split (D-15-02); do not "simplify" back to the research default.
- **Reopened is the pathfinder.** Plan it first; use a live-tenant
  `resurfaced_date`-population spot-check inside that plan to finalize the
  Reopened analyst drill-down (plugin_id, resurfaced_date, reopen-lag days)
  before the parallel modules copy the shape.

</specifics>

<deferred>
## Deferred Ideas

- **External Exposure MoM trend (EXT-TREND-01)** — S1 parameterized external
  dimension; deferred to v1.5 (Phase 14 D-03). `external_dmz` is
  current-snapshot only in v1.4.
- **WAS in External Exposure (EXT-WAS-01)** — gated on the pyTenable upgrade;
  out of scope this milestone.
- **Org-specific RAG band values** — defaults ship configurable (D-15-07);
  capturing leadership-agreed bands is a future `module_options` config task,
  not code.
- **MTTR rework, Program Health, management_summary migration** — Phases 16/17/18.

None of the above were scope creep — they are pre-existing roadmap/backlog items
surfaced for traceability.

</deferred>

---

*Phase: 15-independent-new-modules*
*Context gathered: 2026-06-11*
