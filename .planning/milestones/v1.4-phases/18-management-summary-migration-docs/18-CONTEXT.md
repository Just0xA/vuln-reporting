# Phase 18: management_summary Migration + Docs - Context

**Gathered:** 2026-06-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Migrate `management_summary` from its ~2,200-line bespoke render path onto the
`ReportComposer` pipeline (GEN-01), make it chrome-aware, and write auditor
calculation runbooks for all seven v1.4 modules (DOC-02) — with **zero
regression** to existing recipient-group delivery throughout.

**Expanded this phase (vs the roadmap's original cold-start recommendation):**
a **trend-reconstruction backfill** is now in scope. A 2026-06-18 investigation
overturned the Spike-002 premise that backfill is impossible — the "~30-day
fixed-findings retention wall" is actually the Tenable vuln-export **API default**
when no time-based filter is passed, not a platform purge. Real retention is
~15–16 months and retrievable by passing `last_fixed`. So `management_summary`
will ship its migrated trend with **~12 months of reconstructed real history**
rather than cold-starting (OD-8 → D-18-01).

**Roadmap-locked, not reopened in this discussion:**
- Smoke baseline captured before any migration code; atomic bespoke-path removal
  (no dual-writer window).
- Email routes through `build_email_body_modular()`; `management_summary` added
  to `_CHROME_AWARE_SLUGS`; all seven modules compose via `run_full_pipeline()`.
- Structure locked, values not (D-04-05 smoke parity).

Requirements: **GEN-01, QUAL-04, DOC-02** (QUAL-01/02/03/05 carried as
acceptance bars). This is the **final phase of v1.4** and the roadmap's
**highest-risk** work.

</domain>

<decisions>
## Implementation Decisions

### OD-8 — Trend disposition (the phase's must-lock decision)
- **D-18-01:** **Reconstruct-backfill** (chosen over cold-start and over
  migrating the legacy `management_summary_*.json`). Rebuild real MoM history
  from Tenable's now-retrievable fixed + open exports and seed the S1 trend
  store. **Decoupled from the cutover:** reconstruction is its **own plan that
  runs and is verified BEFORE** the atomic migration cutover — it seeds
  `read_trend()`, the migration then simply reads a store that already has
  history. Two independent commits, never entangled with the 2,200-line removal.
- **D-18-02:** **Fixed 12-month window** (2025-06 → now). Predictable boundary
  chosen over "clean window only" / "full ~16mo." **Caveat for the planner:** a
  12-month boundary puts the earliest ~2–3 months (Jun–Aug 2025) at the tapered
  edge of the fixed export (monthly fixed counts jump ~5× at Sep 2025 — retention
  edge vs real growth, undistinguished). Those specific months MUST carry a
  partial/approximate flag even though the boundary is fixed.
- **D-18-03:** **Provenance-marked, immutable reconstructed snapshots.** Each
  snapshot carries a source marker (`reconstructed` vs `captured`). Reconstructed
  months are **written once and never overwritten** by a later capture run; the
  runbook discloses exactly which months are reconstructed and by what predicate.
  Follows the implicit optional-field snapshot convention (D-15-06 / D-16-09 /
  D-17-04 — absent field → cold-start branch, no `schema_version`).
- **D-18-04:** **Faithful partial backfill.** Reconstruct only fields whose
  inputs are truly retrievable (per-severity open counts, new/fixed counts, MTTR,
  SLA-posture). **`asset_count` is NOT reconstructable** (Tenable doesn't retain
  historical asset population; the asset export is point-in-time) → leave it
  **null on reconstructed months**. Consequence: **Vulnerability Density stays
  cold-start for reconstructed months** (its rule is "each point uses its own
  snapshot's `asset_count`, never current `len(assets_df)`" — D-15) while every
  other metric gets 12mo of history. No fabricated denominators. Runbook
  discloses per-metric which months are reconstructed vs cold-start.

### Retention-fix scope
- **D-18-05:** The **bounded, configurable `last_fixed` lookback** fetch rework
  (the folded todo) lands **in Phase 18**, sequenced ahead of the cutover (the
  reconstruction depends on it). **Bounded, not unbounded** — a 2-year pull
  returned 6.8× the rows (1.29M) and would bloat every run-scoped parquet cache;
  size it to the 12-month window. `data/fetchers.py` `fetch_fixed_vulnerabilities`
  (~L410); consider the same for `fetch_all_vulnerabilities` (~L284).

### MTTR window + fetch-rework regression gate
- **D-18-06:** **Audit every fixed-data consumer for implicit-window reliance
  BEFORE widening the fetch** — hard gate. Any metric that computes over "all
  fixed rows returned" was implicitly relying on the old 30-day API default;
  widening the fetch would silently change it. Each consumer (MTTR rolling-30,
  `new_vs_remediated` outflow, etc.) MUST apply its **own explicit date window**.
  MTTR keeps its **deliberate rolling-30** definition (a "recent velocity" choice,
  not a data limit); the runbook documents it as intentional. No silent metric
  drift is the acceptance bar. (Widening MTTR itself is a metric-design change →
  deferred, see below.)

### Runbooks (DOC-02)
- **D-18-07:** **Per-module, auditor-reproducible runbooks** following the
  existing `docs/*_calculations.md` convention (`management_summary_calculations.md`,
  `board_summary_calculations.md` already exist). One calculations doc per module
  (or tightly grouped). Each: exact formula, real field names, data source, the
  reopened-aware predicate, disclosed window, edge cases — an auditor can recompute
  the value from the doc alone. **Mandatory additions:** disclose the reconstructed
  month range + reconstruction predicate (D-18-01/03), the per-metric
  reconstructed-vs-cold-start split (D-18-04), the rolling-30 MTTR intent (D-18-06),
  and the external-scope rule.

### Backfill execution & verification
- **D-18-08:** **One-time operator-run seeding script** (e.g.
  `scripts/backfill_trend_reconstruction.py`), executed **once before cutover** to
  seed the 12mo of reconstructed snapshots, then never again. **Idempotent** (skips
  months already present — honors immutable provenance). The existing capture cron
  (`scripts/capture_trend_snapshot.py`) continues forward from today. NOT folded
  into the cron; NOT inline at migration.
- **D-18-09:** **Overlap-test verification gate.** Reconstruct the month(s) for
  which a real **captured** snapshot already exists and assert the finding-derived
  fields match within a stated tolerance — proves the predicate reproduces ground
  truth before backfilling months we can't independently check. **Fallback** (if no
  captured month exists yet): reconstruct "today" and compare to the live
  current-state numbers (the spike's +2-of-160,453 check). Must pass before
  reconstructed history is committed.

### Plan sequencing (de-risking the highest-risk phase)
- **D-18-10:** **Full gate chain.** Hard order, each a gate that must be GREEN
  before the cutover begins: **(1)** bounded `last_fixed` fetch rework + consumer
  audit [no metric drift] → **(2)** reconstruction seeding script + overlap-test
  verification → **(3)** smoke baseline captured from the bespoke path → **(4)**
  migration cutover (atomic bespoke-path removal) → **(5)** runbooks. **Roadmap
  reconciliation:** the roadmap names the smoke baseline the "first plan." It is
  read-only of current bespoke output and independent of (1)/(2), so the planner
  MAY still make it plan 01; the gate semantics are "1–3 all green before
  cutover," not a strict commit order of the independent prep work. The roadmap's
  "smoke baseline before any *migration code*" constraint is preserved.

### Legacy JSON disposition
- **D-18-11:** **Archive, don't delete.** Remove `_save_trend_snapshot()` at
  cutover (stop writing), but **move** existing `management_summary_*.json` to an
  archive dir (e.g. `data/trend/legacy_archive/`) rather than deleting. Preserves
  them for auditor comparison and as an independent cross-check against the
  reconstructed history. No live code reads them; reversible.

### Claude's Discretion (research / planner)
- Reconstruction predicate mechanics — reuse `utils/open_count.py`
  `open_findings_at()` at past month-boundaries with the fixed-data add-back
  (findings open at D but fixed in `(D, now]`); the spike validated the
  reopened-aware two-interval form.
- Exact overlap-test tolerance (D-18-09); provenance field name + JSON shape
  (D-18-03); archive dir path (D-18-11); partial-month flag mechanics for the
  earliest reconstructed months (D-18-02).
- Runbook file grouping (strict per-module vs tightly-grouped) within the
  per-module-reproducible decision (D-18-07).
- Whether the consumer audit (D-18-06) extracts a shared explicit-window helper
  or fixes each consumer in place.

### Folded Todos
- **`2026-06-18-pass-bounded-last-fixed-lookback-in-fixed-vuln-fetch.md`** — the
  retention-finding todo captured this session. Folded into D-18-05 (fetch
  rework), D-18-01/02 (reconstruction enabled by it), D-18-06 (the regression
  gate it warned about). Its "CLOSED / NO ACTION" items (`include_unlicensed`,
  asset-export licensing) remain closed — see deferred.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` § "Phase 18: management_summary Migration + Docs" — goal,
  success criteria 1–6, OD-8 lock assignment, smoke-baseline-first constraint.
- `.planning/REQUIREMENTS.md` — GEN-01, QUAL-04, DOC-02; OD-8 in the Plan-Time
  Decisions table; QUAL-01/02/03/05 acceptance bars.
- `.planning/research/SUMMARY.md` — OD-8 row (original cold-start recommendation,
  **now superseded by D-18-01**); GEN-01 flagged **"Highest-risk — elevated
  planning care."**

### The retention finding (origin of the scope expansion)
- `ref/Retrieve Vulnerability Data from Vulnerability Management.md` § "Time-based
  Filters" (line 42) — the API-default-30-day behavior; `include_unlicensed`
  (vuln-export only); deleted/terminated asset filters.
- `.planning/todos/pending/2026-06-18-pass-bounded-last-fixed-lookback-in-fixed-vuln-fetch.md`
  — full empirical evidence (187,775 default vs 1,285,823 at 2yr; floor 2025-02-23;
  taper at Sep 2025), action items, and the CLOSED items.
- `.planning/spikes/002-trend-reconstruction-lookback/README.md` — reconstruction
  mechanics + the **reopened-aware two-interval predicate (STILL HOLDS)**. **NOTE:
  its ~29-day retention conclusion is SUPERSEDED** on the retention point by the
  2026-06-18 finding; the predicate validation is unaffected.

### Prior phase context (foundation this phase consumes)
- `.planning/phases/17-program-health-overview/17-CONTEXT.md` — D-17-01 (re-derive
  from substrate), D-17-04 (the `capture_snapshot()` SLA-posture extension this
  phase's reconstruction must populate), `program_health` is one of the seven
  composed modules.
- `.planning/phases/16-mttr-rework/16-CONTEXT.md` — D-16-02 (reopened-aware,
  sample-weighted rolling-30 MTTR — the definition to preserve, D-18-06), D-16-09
  (implicit optional-field snapshot convention — D-18-03 follows it).
- `.planning/phases/15-independent-new-modules/15-CONTEXT.md` — D-15-01/02 (inflow
  definition incl. resurfaced), D-15-06 (backward-compatible snapshot extension),
  and the **Vulnerability Density own-snapshot-`asset_count` rule** central to
  D-18-04.
- `.planning/phases/14-shared-substrates-composed-report-gates/14-CONTEXT.md` —
  `_MODULES_NEEDING_TREND_SNAPSHOTS` kwargs gate (`management_summary`'s seven
  modules need `trend_snapshots`).

### Runbook convention to follow (DOC-02)
- `docs/management_summary_calculations.md`, `docs/board_summary_calculations.md` —
  the existing `*_calculations.md` per-topic pattern D-18-07 extends.

### Cross-session memory
- `project_tenable_fixed_retention_trend` (rewritten 2026-06-18) — 30-day = API
  default, not retention; real ~15–16mo; bounded `last_fixed` is the fix.
- `project_asset_export_includes_unlicensed` — `include_unlicensed` ruled out (see
  deferred).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/open_count.py` `open_findings_at()` — the reopened-aware two-interval
  open predicate; reused at past month-boundaries for reconstruction (D-18-09).
- `data/trend_store.py` — `capture_snapshot()` / `read_trend()`; the store the
  seeding script writes to (provenance field + immutability, D-18-03) and the
  migrated report reads from.
- `scripts/capture_trend_snapshot.py` — forward capture cron; continues unchanged
  after the one-time backfill (D-18-08).
- `reports/modules/composer.py` `ReportComposer.run_full_pipeline()` — the target
  pipeline; `board_summary` already rides it (the migration analog).
- `scripts/smoke_management_summary_cutover.py` — the structural smoke baseline
  (roadmap criterion 1).

### Established Patterns
- Backward-compatible snapshot extension (D-15-06 → D-16-09 → D-17-04): new
  optional field, absent → cold-start, no `schema_version`. D-18-03 provenance
  field follows this.
- Auto-discovery: the seven modules self-register; `management_summary` composing
  them needs no `run_all.py` re-registration of the modules themselves.
- pandas CoW — `.assign()` only, never `df["col"]=` after a filter (QUAL-03).

### Integration Points
- `data/fetchers.py` `fetch_fixed_vulnerabilities` (~L410) — add bounded
  `last_fixed` (D-18-05); `fetch_all_vulnerabilities` (~L284) consider same.
- `reports/management_summary.py` — `_save_trend_snapshot`, `_load_trend_history`,
  `_compute_metric_*`, `_build_pdf` removed atomically at cutover; reads routed
  through `read_trend()`; added to `_CHROME_AWARE_SLUGS`; email via
  `build_email_body_modular()`.
- `reports/modules/mttr_trend_module.py`, `new_vs_remediated_module.py` — primary
  fixed-data consumers to audit for implicit-window reliance (D-18-06).
- New: `scripts/backfill_trend_reconstruction.py` (D-18-08); `data/trend/legacy_archive/`
  (D-18-11).

</code_context>

<specifics>
## Specific Ideas

- **The user deliberately chose the most ambitious history option** (reconstruct
  over cold-start), and paired it with **audit-honesty guardrails at every turn**:
  provenance-marked immutable snapshots (D-18-03), faithful partial backfill with
  null `asset_count` rather than a fabricated denominator (D-18-04), an overlap
  test against ground truth (D-18-09), and archiving rather than deleting the
  legacy store (D-18-11). Do not "simplify" any of these away — the honesty bar is
  the point, since DOC-02 is fundamentally about auditor trust.
- **Decouple reconstruction from the cutover.** The whole sequencing design
  (D-18-10) exists to keep a real build out of the 2,200-line atomic removal.
  Reconstruction seeds the store; the migration just reads it.
- **The fetch widening is a latent regression vector, not a free win** (D-18-06).
  Treat the consumer audit as a hard gate, not a nice-to-have.

</specifics>

<deferred>
## Deferred Ideas

- **Widening the MTTR metric window** (90-day / all-time MTTR) — a metric-design
  change now that 12mo is available; its own future phase, not Phase 18 (D-18-06
  keeps rolling-30).
- **Reconstructing the tapered Feb–Aug 2025 tail / full ~16mo** — considered and
  set aside for the fixed 12-month window (D-18-02). Revisit if a longer horizon
  is wanted and the taper can be characterized (retention edge vs real growth).
- **Persistent finding-mirror + differential-export architecture** — the larger
  pattern from the Tenable doc (`indexed_at` differential cursor, stateful local
  mirror). A v2 strategic option for trend sourcing; out of scope for v1.4.
- **Per-Owner SLA posture in snapshots** — carried from Phase 17 deferred; optional
  enrichment.

### Reviewed Todos (not folded)
- The folded todo's **CLOSED items remain closed** (not separate todos):
  `include_unlicensed` is vuln-export-only and irrelevant to the
  asset-export-sourced coverage reports; the asset export already includes all
  unlicensed assets (membership-tested 2026-06-18). Do NOT re-investigate — see
  `project_asset_export_includes_unlicensed`.

</deferred>

---

*Phase: 18-management-summary-migration-docs*
*Context gathered: 2026-06-18*
