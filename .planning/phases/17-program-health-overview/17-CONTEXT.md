# Phase 17: Program Health Overview - Context

**Gathered:** 2026-06-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship **one new four-channel metric module**, `program_health`, that stitches
the program's three velocity signals into a single management one-pager:

- **New-vs-Remediated** net velocity (inflow vs outflow)
- **MTTR** trend (rolling-30 overall, from Phase 16 `mttr_trend` substrate)
- **SLA posture** (% of open Critical+High within SLA)
- plus **Open-Critical MoM delta**

…rolled up into **one composite RAG headline** ("on track / at risk / off
track") via the OD-5 rule, a **4-tile email KPI row**, and an **Owner velocity
table**. Cold-start-safe.

`program_health` is a **self-contained, independent module** — like every other
v1.4 module it is a *thin consumer of the shared S1 (trend) + S2 (Owner)
substrates*, NOT a composer that reads sibling modules' computed outputs (the
`ReportComposer` never passes one module's `ModuleData` into another's
`compute()`; see D-17-01). It implements the full four-channel render contract
(PDF section, Excel tabs, email panel, analyst tabs, RAG-strip entry).

This phase clarifies *how* to implement what **RPT-07** already scopes; it adds
no new data sources beyond one new persisted snapshot aggregate (D-17-04).
Program Health does **not** depend on Phase 18 / GEN-01 — the SLA signal is
sourced in-phase (D-17-03/04). The `management_summary` migration (Phase 18) is
explicitly out of scope.

The v1.4 QUAL acceptance bars (cold-start, reopened-aware predicate, empty-data
guard, aggregate-only PII), first verified in Phase 15, are enforced here.

Requirements: **RPT-07** (QUAL-01/02/03/05 carried as acceptance bars).

</domain>

<decisions>
## Implementation Decisions

### Signal sourcing model (locked)
- **D-17-01:** **Re-derive all four signals from the shared substrate.**
  `program_health.compute()` reads the **same S1 `read_trend()` snapshots +
  current `vulns_df`/`assets_df`** the other modules consume and computes its
  signals itself: net velocity from snapshot `new_findings_count` /
  `fixed_findings_count`; Open-Critical MoM delta from the per-severity open
  counts; MTTR from `mttr_overall_days`; SLA posture from the new field
  (D-17-04). **No composer change** — the independent-module contract is
  preserved (compute() never sees sibling `ModuleData`). Chosen over a
  composer-coupling or shared-helper-extraction refactor.
- **D-17-02:** **Definition parity is a correctness bar.** `program_health`'s
  net-velocity and MTTR numbers MUST match the definitions used by
  `new_vs_remediated_module` and `mttr_trend_module` so the one-pager never
  disagrees with the detail modules. (Net velocity uses the D-15-01/02 inflow
  definition incl. resurfaced; MTTR uses the D-16-02 reopened-aware,
  sample-weighted rolling-30 overall mean.) The cleanest realization is likely a
  small shared helper consumed by both source modules **and** `program_health`
  — but extraction is the planner's call; duplicating the exact math is
  acceptable only if it stays definitionally identical.

### SLA signal source (locked — user chose the richer MoM path)
- **D-17-03:** The "SLA rate" signal is **% of open Critical+High findings
  within SLA** (point-in-time **posture**: open & not-overdue ÷ open, over the
  Critical+High population), using the **reopened-aware open predicate**
  (`utils/open_count.py` `open_findings_at()`, QUAL-02) and
  `utils/sla_calculator.py` for the within/over-SLA test. Severity scope is
  **Critical+High only** — aligns with the Open-Crit delta tile and the Owner
  table's Crit+High outlier rule; excludes Low/Medium dilution. (Not the
  "% fixed within SLA" remediation variant — posture, not closed-work, is the
  program-health signal.)
- **D-17-04:** **Persist a new forward-accumulating SLA-posture aggregate into
  the S1 snapshot store** so "SLA rate **delta**" (roadmap criterion 2) is a
  **real MoM** signal — not current-only. Extend `data/trend_store.py`
  `capture_snapshot()` with the new field AND `scripts/capture_trend_snapshot.py`
  to compute + pass it, exactly as Phase 15/16 extended snapshots
  (backward-compatible, **implicit optional-field** convention — absent field →
  cold-start branch, no `schema_version`, no migration; D-15-06 / D-16-09).
  Verify with a trend-store smoke check during planning. The delta is
  cold-start-gated until ≥2 snapshots exist (QUAL-01).

### OD-5 — Composite RAG threshold rule (locked; the phase's must-lock decision)
- **D-17-05:** **Green-count rule:** Green = **all 4** signals green; Amber =
  **2–3** green; Red = **0–1** green. Shipped as a **`module_options`-overridable
  default** (D-15-07 pattern), not a hard-coded constant. (Plain green-count;
  no red-dominates override.)
- **D-17-06:** **Missing-signal folding (criterion 2):** any signal that is
  unavailable — cold-start MoM delta OR an upstream compute error — **caps the
  composite at Amber "data incomplete" (never Green)**, and the email panel +
  PDF **name which signal(s) are missing**. Available signals still count toward
  the green tally to distinguish Amber vs Red. (Honors criterion 2 literally;
  prevents a falsely-Green program when a signal is blind.)

### Per-signal RAG basis (locked)
- **D-17-07:** Each of the 4 signals is colored by **month-over-month
  direction**: improved = green, roughly flat = amber, worsened = red
  (Open-Crit down = green; net velocity backlog-shrinking = green; SLA% up =
  green; MTTR down = green). The "flat" band thresholds ship as
  **`module_options` defaults**, tunable per group without code change.
- **D-17-08 (consequence — cold-start coherence):** With only **1** snapshot,
  **no** signal has an MoM direction → all four are "missing" (D-17-06) →
  composite is **Amber "data being established"** and the 4 email tiles show
  **current values only** with a cold-start notice (roadmap criterion 3,
  QUAL-01). This is a normal first-month state, never a crash or `NaN%`.

### PDF layout (locked — UI hint: yes)
- **D-17-09:** **Sparkline row + Owner velocity table.** Top: a row of **4 mini
  trend sparklines** (one per signal) each annotated with current value + MoM
  arrow (▲/▼/—). Below: the **Owner velocity table** — each Owner's MoM delta on
  open **Critical+High**, with Owners whose open count rose **>20% MoM flagged
  as outliers** (roadmap criterion 4). Sparklines via matplotlib (existing
  `exporters/chart_exporter.py` palette / chart conventions). Chosen over a
  text-only traffic-light table.

### Claude's Discretion (research / planner)
- Exact new snapshot field name + JSON shape for the SLA-posture aggregate
  (overall Crit+High; **per-Owner SLA is NOT required** — criterion 4's Owner
  table is open-count-based, so per-Owner SLA persistence is optional).
- Whether net-velocity/MTTR parity (D-17-02) is achieved via a shared helper or
  definitionally-identical re-derivation.
- The default numeric "flat" bands per signal (D-17-07) and the default
  composite bands surface as `module_options` (D-17-05) — ship sensible
  defaults; no org-specific values supplied.
- Email 4-tile wording, the one-paragraph narrative generation ("the program
  [improved/held/worsened] on N of 4 indicators"), sparkline styling, Excel tab
  column order, analyst-tab per-Owner per-metric MoM layout, and the exact
  cold-start / missing-signal disclosure copy.
- `min`-snapshot tie-break (multiple snapshots in one calendar month → latest),
  consistent with D-16-08.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` § "Phase 17: Program Health Overview" — goal, success
  criteria 1–4, OD-5 lock assignment.
- `.planning/REQUIREMENTS.md` — RPT-07; QUAL-01/02/03/05 acceptance bars;
  Plan-Time Decisions table (OD-5 → Phase 17).
- `.planning/research/SUMMARY.md` — OD-5 recommended resolution (the D-17-05
  default); build-order rationale (Program Health after Modules 1 + 6).
- `.planning/research/FEATURES.md` § "Module 5 — Program Health Overview" — the
  per-channel feature spec (RAG headline, 4-tile email, sparkline PDF, analyst
  drill-down, edge cases). **NOTE the doc's "composer that references other
  modules' outputs" framing is superseded by D-17-01** (re-derive from
  substrate); also note its GEN-01-SLA-module dependency is replaced by the
  in-phase SLA source (D-17-03/04) because GEN-01 is Phase 18.
- `.planning/research/PITFALLS.md` — cold-start, reopened predicate, CoW,
  empty-data, PII acceptance bars.
- `.planning/research/ARCHITECTURE.md` — `**self._kwargs` fan-out; composed_report
  kwargs gates; new-module inventory.

### Prior phase context (foundation this phase consumes)
- `.planning/phases/16-mttr-rework/16-CONTEXT.md` — D-16-02 (reopened-aware,
  sample-weighted MTTR — the definition `program_health` MUST reuse, D-17-02),
  D-16-03 (the `capture_snapshot()` MTTR extension that D-17-04 repeats for SLA),
  D-16-08 (calendar-month axis / partial-month flag — match for sparklines),
  D-16-09 (implicit optional-field snapshot convention).
- `.planning/phases/15-independent-new-modules/15-CONTEXT.md` — D-15-01/02 (net
  velocity inflow definition incl. resurfaced — D-17-02 parity target), D-15-06
  (backward-compatible snapshot extension), D-15-07 (configurable thresholds via
  `module_options` — D-17-05/07 pattern), D-15-08 (partial-month labeling),
  QUAL bars.
- `.planning/phases/14-shared-substrates-composed-report-gates/14-CONTEXT.md` —
  `_MODULES_NEEDING_TREND_SNAPSHOTS` kwargs gate; `program_health` needs the
  `trend_snapshots` kwarg → add it to that frozenset (no signature change).

### Proven patterns to mirror
- `reports/modules/new_vs_remediated_module.py` — calendar-month MoM + Owner cut
  + cold-start reference; net-velocity source definition (D-17-02 parity).
- `reports/modules/mttr_trend_module.py` — rolling-30 MTTR definition + MoM +
  Owner cut (D-17-02 parity); the four-channel shape to copy.
- `reports/modules/critical_remediation_sla_module.py` — existing in-scope SLA
  within/over-SLA logic to reuse/adapt for the D-17-03 posture calc (note: its
  metric is "% fixed within SLA"; D-17-03 wants "% **open** within SLA").
- `data/trend_store.py` — `capture_snapshot()` (the function D-17-04 extends —
  see the Phase 15/16 new-field block ~lines 376–391) and `read_trend()`
  `{snapshots, insufficient_data}`. Snapshot already persists per-severity open
  counts + `new_findings_count` / `fixed_findings_count` / `mttr_overall_days`
  (the re-derive inputs for D-17-01); it does **NOT** yet persist any SLA rate.
- `scripts/capture_trend_snapshot.py` — must compute + pass the new SLA-posture
  aggregate (D-17-04); note the UAT-5 sys.path bootstrap fix already in place.
- `reports/composed_report.py` — `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset;
  add `program_health`.
- `reports/modules/board_report_utils.py` `extract_owner()` + `_parse_tags` —
  Owner velocity table dimension + `Unassigned` catch-all.
- `utils/open_count.py` `open_findings_at()` — reopened-aware open predicate
  (QUAL-02; the open population for D-17-03 SLA posture + Open-Crit delta).
- `utils/sla_calculator.py` `get_sla_status()` — within/over-SLA per finding
  (D-17-03).
- `config.py` `SLA_DAYS` — per-severity SLA targets (authoritative; see
  `[[project_sla_days_config_py_authoritative]]`).
- `reports/modules/format_utils.py` (`safe_pct`/`safe_int`/`safe_format`) +
  `rag_utils.py` (`build_rag_strip_entry`, `STATUS_COLOR`, `rag_status_from_value`)
  — empty-data guard (QUAL-03) + composite RAG strip cell.
- `reports/modules/base.py` `BaseModule` / `_empty_result()` — module shape.
- `exporters/chart_exporter.py` — palette + chart conventions for the D-17-09
  sparklines.

### Spike findings (project skill — auto-loaded)
- `.claude/skills/spike-findings-vuln-reporting/SKILL.md` — VPR-first severity;
  reopened-aware predicate mandatory (~19% drop if naive); trend =
  forward-accumulating snapshots (~29-day fixed-retention wall → SLA-posture MoM
  cold-starts forward, D-17-04).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **S1 snapshots already carry the re-derive inputs** for 3 of 4 signals:
  per-severity open counts (Open-Crit delta), `new_findings_count` /
  `fixed_findings_count` (net velocity), `mttr_overall_days` (MTTR). Only the
  SLA-posture field is new (D-17-04).
- **`new_vs_remediated_module` / `mttr_trend_module`** are the working
  references for calendar-month MoM + cold-start + Owner cut, and the source of
  the definitions `program_health` must match (D-17-02).
- **`open_findings_at()` + `get_sla_status()` + `SLA_DAYS`** give the SLA-posture
  numerator/denominator with no new fetch.
- **`extract_owner()`** supplies the Owner velocity table dimension.
- **`format_utils` / `rag_utils`** cover the empty-data guard + the composite
  RAG strip cell with no new code.

### Established Patterns
- Auto-discovery: a new `program_health_module.py` with `@register_module`
  self-registers; consumed via composed reports / `management_summary`
  (Phase 18) needs **no** `run_all.py` / `_VALID_REPORTS` / schema registration.
- Trend kwargs gate: add `program_health` to `_MODULES_NEEDING_TREND_SNAPSHOTS`
  → `**composer_kwargs` fan-out delivers `trend_snapshots`; no signature change.
- Backward-compatible snapshot extension (D-15-06 → D-16-09 → D-17-04): new
  optional field; absent → cold-start; no `schema_version`.
- pandas 3.0 CoW — `.assign()` only, never `df["col"]=` after a filter (QUAL-03;
  burned in `260611-b1x`).

### Integration Points
- `data/trend_store.py` `capture_snapshot()` — the shared file this phase
  modifies (new SLA-posture aggregate, backward-compatible).
- `scripts/capture_trend_snapshot.py` — compute + pass the new aggregate.
- `reports/composed_report.py` — add `program_health` to the trend-snapshots gate.
- New self-contained `reports/modules/program_health_module.py` + unit tests +
  synthetic fixtures (RFC 5737/6761 — QUAL-05).

</code_context>

<specifics>
## Specific Ideas

- **The "composer" label in research is misleading for this codebase.** Honor
  D-17-01: `program_health` is an independent thin-consumer that re-derives from
  S1/S2, NOT a module that reads other modules' `ModuleData`. The composer does
  not support sibling-output passing and we deliberately keep it that way.
- **User chose the richer SLA path twice over:** real MoM (persist a field,
  D-17-04) over current-only, AND posture ("% open within SLA", D-17-03) over
  remediation-rate — and scoped it to Critical+High. Do not "simplify" back to a
  current-snapshot or all-severity number.
- **Cold-start is structurally Amber here:** because every signal is MoM-direction
  colored (D-17-07), the first-snapshot state has no directions → composite Amber
  "data being established" + current-value tiles (D-17-08). Encode this as an
  explicit acceptance test, not an afterthought.

</specifics>

<deferred>
## Deferred Ideas

- **GEN-01 / `management_summary` migration** — Phase 18; `program_health` is a
  constituent module it will compose, but this phase ships the module standalone
  and does not touch `management_summary`.
- **Per-Owner SLA posture in snapshots** — not required by criterion 4 (Owner
  table is open-count-based); a future enrichment if an Owner-level SLA column is
  ever wanted. Optional in v1.4.
- **Absolute-level / hybrid signal RAG** — considered and rejected in favor of
  MoM-direction (D-17-07); revisit only if leadership wants standing-vs-target
  coloring later.
- **Red-dominates composite override** — considered and rejected for the plain
  green-count rule (D-17-05); the `module_options` surface leaves room to add it
  later without code change to callers.

None of the above were scope creep — they are pre-existing roadmap/backlog items
or explicitly-rejected alternatives surfaced for traceability.

</deferred>

---

*Phase: 17-program-health-overview*
*Context gathered: 2026-06-12*
