# Phase 16: MTTR Rework - Context

**Gathered:** 2026-06-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship a **new** four-channel metric module `mttr_trend` (new `MODULE_ID`) that
fixes the four undisclosed correctness gaps in today's
`reports/modules/mttr_by_severity_module.py`:

1. **Implicit measurement window** → disclose a rolling ~30-day window in all
   four channels.
2. **Unweighted mean-of-means overall MTTR** → a sample-weighted overall mean
   across all in-scope fixed findings.
3. **Reopen-cycle duration inflation** → reopened-aware duration so a
   long-dormant, recently-refixed finding measures its latest cycle, not its
   original discovery.
4. **No MoM trend / no Owner cut** → month-over-month trend + an Owner
   breakdown on the full four-channel contract.

`mttr_by_severity_module.py` is left **byte-unchanged** so `board_summary`
groups that reference it keep delivering. This phase clarifies *how* to
implement what **RPT-05** already scopes; it does not add new data sources.
Program Health (Phase 17), the `management_summary` migration (Phase 18), MTTR
backfill beyond the ~29-day retention wall, and sub-monthly reopen rates are
explicitly out of scope.

The v1.4 QUAL acceptance bars (cold-start, reopened-aware predicate,
empty-data guard, aggregate-only PII), first verified in Phase 15, are
enforced here.

Requirements: **RPT-05** (QUAL-01/02/03/05 carried as acceptance bars).

</domain>

<decisions>
## Implementation Decisions

### Resolved population (OD-4 — locked)
- **D-16-01:** **Option B — durably-fixed only.** The MTTR population is
  findings whose **current `state` is FIXED**. Drop the existing module's
  `state=="fixed" OR last_fixed.notna()` clause — that clause pulls in
  **currently-REOPENED** findings via a stale `last_fixed` and distorts the
  mean. A finding reopened-then-re-fixed (now FIXED) **still counts**, with its
  clock corrected by D-16-02. (Option A keeps the distortion; Option C
  first-time-fixes-only shrinks the sample too far.)

### Duration clock (success-criterion 3 mechanism — locked)
- **D-16-02:** **Date-math only, reopened-aware.**
  `days_to_fix = (last_fixed − COALESCE(resurfaced_date, first_found)).days`,
  clipped to ≥ 0. When `resurfaced_date` is present the clock starts at the
  reopen, not original discovery. **Drop the `time_taken_to_fix` preference
  entirely** — Tenable's field measures the full `first_found → fix` span and
  would silently re-inflate exactly the reopened findings the rework targets.
  Deterministic; makes the criterion-3 fixture (first_found −200d, resurfaced
  −10d, last_fixed −2d) read **~8 days**, not 198.
- **Consequence:** the **sample-weighted overall mean** (criterion 2) falls out
  for free — a flat `mean(days_to_fix)` over all in-scope findings is inherently
  count-weighted (500 Low + 2 Critical → Low-dominated result). No
  mean-of-per-severity-means.

### MoM trend data source (locked)
- **D-16-03:** **Persist MTTR into the S1 snapshot store** — the only viable
  path. The ~29-day Tenable fixed-retention wall (carried v1.3 constraint)
  means MTTR history **cannot** be reconstructed from the current export.
  Extend `data/trend_store.py` `capture_snapshot()` with a
  **forward-accumulating rolling-30-day MTTR aggregate**: **overall +
  per-severity + per-Owner** (see D-16-06), stored as PII-safe floats. Also
  extend `scripts/capture_trend_snapshot.py` to compute and pass it.
  `mttr_trend` reads MoM from `read_trend()` and **cold-starts** (QUAL-01)
  until ≥2 snapshots exist. "Month-over-month" is precisely
  snapshot-over-snapshot rolling-30-day MTTR.

### Measurement window (locked)
- **D-16-04:** **Configurable, default 30.** A `module_options` key (e.g.
  `mttr_window_days`, default `30`) — mirrors the D-15-07 configurable-defaults
  pattern. The disclosure label **reads the actual window value** so it can
  never misstate the window. Disclosure text appears in all four channels
  (PDF gauge/labels, Excel headers, email panel footer, runbook).

### Channel layout (locked)
- **D-16-05:** **Overall + per-severity + Owner.** Headline = sample-weighted
  overall rolling-30 MTTR; MoM trend line; **per-severity breakdown retained**
  (preserves the existing module's per-severity vs-SLA gauges — criterion 5
  already specifies per-severity min-sample behavior, so per-severity stays);
  plus an Owner table.

### Owner cut — Owner MoM (user diverged from current-snapshot-only — locked)
- **D-16-06:** The Owner cut is **month-over-month, not current-snapshot-only**.
  The user deliberately chose the richer option (cf. the Phase 15 OD-1
  divergence). **Consequences the planner MUST handle:**
  - Persist **per-Owner** rolling-30 MTTR into snapshots (D-16-03), alongside
    the existing per-Owner open-count dimension. Owner tag names are already in
    snapshots → within the established PII boundary (aggregate + internal tag
    names OK; see `[[project_pii_rule_is_ai_not_email]]`).
  - **Per-Owner cold-start** — a newly-appearing Owner is a valid cold start,
    never a crash/`NaN%`.
  - **Owner-set drift reconciliation** between snapshots — a new Owner starts a
    fresh series; a vanished Owner drops out. Define the join/missing-month
    behavior at plan time.
  - The partial-month treatment (D-16-08) applies to the Owner MoM column too.

### Sparse-row rendering (locked)
- **D-16-07:** **"Insufficient data (N findings)"**, never a noisy
  single-finding average. Applies to sub-threshold **severities** (criterion 5)
  **and** sub-threshold **Owners** (1–`min_sample`−1 fixed findings). Owners
  with **zero** fixed findings in scope are **omitted** entirely. Zero
  fixed-findings-in-scope overall → `_empty_result()` with gray RAG.

### Trend axis & partial-month semantics (locked)
- **D-16-08:** **Calendar-month X-axis**, consistent with `new_vs_remediated`
  and `vuln_density` (cross-module visual consistency was the explicit goal).
  One trend point per calendar month — each plotted value is the snapshot's
  **complete rolling-30-day** MTTR mapped to its calendar month; the
  newest/current month is flagged **"Month-to-date (partial)"** (D-15-08). Note
  the nuance for the runbook: the rolling-30 value itself is never partial, but
  it is plotted at a partial-calendar-month position, so the partial flag marks
  *position*, not an incomplete window. Same treatment on the Owner MoM column.
  (Multiple snapshots in one month → use the latest in that month; confirm at
  plan time.)

### Snapshot schema evolution (locked)
- **D-16-09:** **Implicit optional-field convention** — same as D-15-06. An
  older snapshot lacking the new MTTR fields is a valid **cold-start** state
  (absent field → `insufficient_data` branch), never a crash. **No
  `schema_version` field**, no migration — consistent with how Phase 15 added
  the reopened/accepted/recast/new/fixed count fields. Verify with a
  trend-store smoke check during planning.

### board_summary baseline scope (OD-7 — locked)
- **D-16-10:** The board_summary baseline re-capture is a **zero-diff safety
  confirmation**: re-run board_summary's structural smoke baseline and assert
  it is **byte-identical** (proves the untouched `mttr_by_severity` + the new
  *optional* `capture_snapshot` params did not regress it). **A diff means
  something broke.** Separately capture a **new structural smoke baseline for
  `mttr_trend`**. The planner should not chase a phantom board_summary diff.

### OD-7 (confirmed locked)
- `MODULE_ID = "mttr_trend"`; `mttr_by_severity_module.py` **byte-unchanged**;
  board_summary smoke baselines re-captured per D-16-10. New module is
  auto-discovered (`@register_module`); consumed via composed reports /
  `management_summary` (Phase 18) — no `run_all.py` / `_VALID_REPORTS`
  registration needed.

### Claude's Discretion (research / planner)
- Exact snapshot field names + JSON shape for the new MTTR aggregate; chart
  styling and gauge-vs-line choices; Excel column order; the precise Owner-drift
  join/missing-month mechanics; multiple-snapshots-in-one-month tie-break;
  `min_sample_size` default (existing module defaults to 1 — criterion 5
  implies a default of 5, confirm at plan time); the exact "as-of"/partial
  disclosure wording.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` § "Phase 16: MTTR Rework" — goal, success criteria 1–5,
  OD-4 / OD-7 lock assignments, the criterion-3 fixture spec.
- `.planning/REQUIREMENTS.md` — RPT-05; QUAL-01/02/03/05 acceptance bars;
  Plan-Time Decisions table (OD-4, OD-7); Out-of-Scope (WAS, MTTR backfill,
  sub-monthly reopen rate).
- `.planning/research/SUMMARY.md` — OD-4 recommendation (Option B; note the user
  **confirmed** B) and OD-7; "no scipy/statsmodels — sample-weighted MTTR mean
  is plain pandas"; build-order; untouched-files list.
- `.planning/research/PITFALLS.md` — Pitfall 2 (MTTR reopened-finding inflation),
  cold-start, CoW, empty-data, PII bars.
- `.planning/research/FEATURES.md` — MTTR Rework feature analysis (fields,
  channel content, edge cases).
- `.planning/research/ARCHITECTURE.md` — `**self._kwargs` fan-out; new-module
  inventory; `composed_report` kwargs gates.

### Prior phase context (foundation this phase consumes)
- `.planning/phases/15-independent-new-modules/15-CONTEXT.md` — D-15-04/05/06
  (the `capture_snapshot` extension pattern this phase repeats: new aggregate
  fields, **backward-compatible**, absent-field → cold-start); D-15-07
  (configurable RAG/threshold defaults via `module_options`); D-15-08
  (partial current-month labeling); the four-channel module shape Modules 1–4/7
  proved.
- `.planning/phases/14-shared-substrates-composed-report-gates/14-CONTEXT.md` —
  D-15/D-16 composed_report kwargs gates (trend snapshots / recast rules);
  `mttr_trend` needs the **trend_snapshots** kwarg → add it to
  `_MODULES_NEEDING_TREND_SNAPSHOTS`.

### Proven patterns to mirror
- `reports/modules/mttr_by_severity_module.py` — the module being reworked;
  copy its four-channel structure (gauges, Excel tab, status/SLA logic) but
  **replace** the `time_taken_to_fix`-preferring `days_to_fix` (lines ~190–222)
  per D-16-02 and the unweighted overall mean (`_build_result` lines ~282–286)
  per D-16-02 consequence. **Do not edit this file** — `mttr_trend` is a new file.
- `data/trend_store.py` — `capture_snapshot()` (the function D-16-03 extends;
  current new-field block ~lines 334–368, owner dimension `_count_by_owner`
  ~171) and `read_trend()` `{snapshots, insufficient_data}` (~line 395).
- `scripts/capture_trend_snapshot.py` — the capture entry point that must
  compute + pass the new MTTR aggregate (note WR-03 exit-code handling for
  owner-snapshot failures).
- `reports/modules/new_vs_remediated_module.py` — the calendar-month MoM +
  cold-start + Owner-cut reference shape (D-16-08 axis consistency target).
- `reports/composed_report.py` — `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset;
  add `mttr_trend` (no signature change).
- `reports/modules/board_report_utils.py` `extract_owner()` + `_parse_tags` —
  S2 Owner cut + `Unassigned` catch-all.
- `utils/open_count.py` `open_findings_at()` — reopened-aware predicate (QUAL-02).
- `reports/modules/format_utils.py` (`safe_pct`/`safe_int`/`safe_format`) +
  `rag_utils.py` (`build_rag_strip_entry`, `STATUS_COLOR`) — QUAL-03 + RAG strip.
- `reports/modules/base.py` `BaseModule` / `_empty_result()` — module shape.
- `data/fetchers.py` — `resurfaced_date`, `state`, `last_fixed`, `first_found`,
  `time_taken_to_fix`, `severity` already fetched (D-16-01/02 source fields).
- `config.py` `SLA_DAYS` — per-severity SLA targets for the status comparison.

### Spike findings (project skill — auto-loaded)
- `.claude/skills/spike-findings-vuln-reporting/SKILL.md` — VPR-first severity;
  reopened-aware predicate mandatory (~19% drop); trend = forward-accumulating
  snapshots (~29-day fixed-retention wall; cold start is real → D-16-03).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`mttr_by_severity_module.py`** is the structural template (four-channel
  contract, gauges, Excel/SLA logic) — copy, then surgically replace the
  `days_to_fix` derivation and overall-mean per D-16-02.
- **`capture_snapshot()` / `read_trend()`** are already cold-start-safe and
  idempotent; D-16-03 extends the snapshot record exactly as Phase 15 did.
- **`extract_owner()`** supplies the Owner dimension + `Unassigned` catch-all.
- **`format_utils` / `rag_utils`** cover the empty-data guard + RAG strip.
- **`new_vs_remediated_module.py`** is the working reference for calendar-month
  MoM + cold-start branch + Owner cut (D-16-08 consistency).

### Established Patterns
- Auto-discovery: a new `mttr_trend_module.py` with `@register_module`
  self-registers; consumed via composed reports needs **no** `run_all.py` /
  schema registration.
- Trend kwargs gate: add `mttr_trend` to `_MODULES_NEEDING_TREND_SNAPSHOTS` →
  `**composer_kwargs` fan-out delivers `trend_snapshots`; no signature change.
- Backward-compatible snapshot extension (D-15-06 → D-16-09): new optional
  fields; absent → cold-start.
- pandas 3.0 CoW — `.assign()` only, never `df["col"]=` after a filter (QUAL-03;
  burned in `260611-b1x`).

### Integration Points
- `data/trend_store.py` `capture_snapshot()` — the shared file this phase
  modifies (new MTTR aggregate dimensions, backward-compatible).
- `scripts/capture_trend_snapshot.py` — compute + pass the new aggregate.
- `reports/composed_report.py` — add `mttr_trend` to the trend-snapshots gate.
- New self-contained `reports/modules/mttr_trend_module.py` + unit tests +
  synthetic fixtures (RFC 5737/6761 — QUAL-05).

</code_context>

<specifics>
## Specific Ideas

- **OD-4 = Option B is confirmed, not just the research default** — durably-fixed
  only; the currently-REOPENED population is dropped from the mean.
- **Two deliberate richness choices** (honor them; do not "simplify" back):
  - **Owner MoM** (D-16-06), not current-snapshot-only — management should see
    Owner remediation velocity over time, with per-Owner cold-start + drift
    handled.
  - **Calendar-month axis with partial flag** (D-16-08), not snapshot-date —
    the user wants the MTTR trend to read the same as `new_vs_remediated` /
    `vuln_density`, accepting that "partial" marks calendar position, not an
    incomplete 30-day window.
- **The criterion-3 fixture is the acceptance lodestar:** first_found −200d,
  `resurfaced_date` −10d, `last_fixed` −2d ⇒ MTTR ≈ 8d. Encode it as a unit test.

</specifics>

<deferred>
## Deferred Ideas

- **MTTR backfill beyond ~29 days** — forbidden by the Tenable fixed-retention
  wall; history accumulates forward from first snapshot (v1.3 constraint).
- **Sub-monthly reopen rate** — out of scope this milestone (research "Deferred").
- **WAS MTTR** — no VPR / no lifecycle fields on pyTenable 1.5.2; gated on an
  SDK upgrade (`[[project_was_no_vpr_no_lifecycle]]`).
- **Program Health composite (RPT-07) / management_summary migration (GEN-01)** —
  Phases 17 / 18; `mttr_trend` is a dependency of both.

None of the above were scope creep — they are pre-existing roadmap/backlog
items surfaced for traceability.

</deferred>

---

*Phase: 16-mttr-rework*
*Context gathered: 2026-06-12*
