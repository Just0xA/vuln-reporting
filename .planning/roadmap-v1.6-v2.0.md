# vuln-reporting — Improvement Roadmap: Milestone List (v1.4.x → v2.0, rev. 2026-07-02d — milestones renumbered +1: the v1.5 label was consumed by a release tag pushed to reconcile the dev-machine sync issue; roadmap now starts at v1.6)

> **Intake reconciliation (2026-07-09).** Landed into `.planning/` as a reference doc via quick task `260709-ar2` (the body below is verbatim from the source). Three deltas against current repo state at intake:
> - **HK-01 is already done.** "Apply + commit the 2026-07-02 harness patch" was completed this session as quick task `260709-983` (commits `6862d4d`, `3dfa847`, `ddc0b8d`) — the `block_tenable_fetch` hook is now wired via `.claude/settings.json` and tested. The v1.4.x bucket starts at HK-02.
> - **The v1.5→v1.6 renumbering premise is not yet true.** The header assumes the `v1.5.0` release tag was pushed; as of intake that release is **built locally but HELD/unpushed**. The milestone numbering becomes accurate only once `v1.5.0` actually ships. If v1.5.0 is *not* cut, revisit the numbering.
> - **v2.0 compliance inputs already exist** in the repo: `.planning/seeds/compliance-reporting.md`, `.planning/notes/compliance-data-model-decisions.md`, `docs/tenable_compliance_api_reference.md`. The v1.7 spec referenced below is landed at `.planning/specs/milestone-spec-validation-substrate.md`.

Drafted 2026-07-02 from the post-v1.4 architecture review. Sequenced so each milestone
de-risks the next, existing deliveries never regress, and the module layer — the part
that grows forever — gets thinner with every step. Written to drop into the GSD
workflow: each milestone has a goal, requirement IDs, candidate phases (numbering
continues from Phase 19), exit criteria, and explicit decision gates.

**Ordering rationale in one line each:**

- v1.4.x — clear the cheap known debt so it doesn't ride along into every later diff
- v1.6 — delivery-config scaling is live pain on production *today*; cheap, touches nothing the deep work depends on, stops the bleeding first
- v1.7 — the validation substrate (synthetic cache + offline mode) lands before the deep work so every later parity gate has a committable test bed — Spike 004 is its first consumer
- v1.8 — the history store is the keystone; everything after gets cheaper if it lands
- v1.9 — classification-at-ingest needs the store to have a place to put columns
- v1.10 — the render-layer refactor shrinks modules *once*, so do it before migrating more reports
- v1.11 — GEN-02 and preset consolidation migrate onto the *new* thin model, not twice
- v1.12 — packaging simplification is independent value; deferred because it touches prod delivery
- v2.0 — compliance reporting proves the new substrate on genuinely new value

**Cross-cutting constraints (every milestone, carried from v1.4):** QUAL-02
reopened-aware predicate (until v1.8 replaces it with the history query — then the
*query* becomes the guarded invariant), QUAL-03 empty-data guards (until v1.10 moves
them into the render layer — then renderer tests become the guard), QUAL-05
aggregate-only PII in committed artifacts (never relaxed; the history store is
local-only data, same class as the parquet cache), no live Tenable pulls from Claude
Code (hook coverage test must stay green as new entry points appear), and existing
`delivery_config.yaml` groups must deliver unchanged through every cutover.

---

## v1.4.x — Housekeeping & Harness Debt (quick tasks, no milestone ceremony)

**Goal:** Close the known small items so later milestones start clean. All are
`/gsd-quick` candidates; none warrant a phase.

| ID | Item | Notes |
|----|------|-------|
| HK-01 | Apply + commit the 2026-07-02 harness patch (hook coverage, settings.json, CLAUDE.md rewrite, skill fix, STATE prune) | Already built; needs review + commit |
| HK-02 | `composed_report` output filename disambiguation | Slugified `report_title` (or `output_basename:` YAML field); becomes a live bug the moment a second group composes |
| HK-03 | De-duplicate spike sources | Pick one home (`.claude/skills/.../sources/` recommended since the skill references them); delete `.planning/spikes/00{1,2}` copies, leave a pointer in `spikes/MANIFEST.md` |
| HK-04 | `auto_prune_state: true` in `.planning/config.json` | Keeps STATE.md lean at milestone close automatically |
| HK-05 | Run `/gsd-profile-user` | Fills the Developer Profile placeholder in the GSD-managed CLAUDE.md block |
| HK-06 | Delete `origin/backup/pre-trend-scrub-2026-05-14` | Outstanding since the 2026-05-14 scrub — the backup branch still contains the leaked trend data; the confidence window has long passed |
| HK-07 | Clean `run_all.py` deferred cosmetics | The Phase-3 deprecated aliases (`_PDF_RAG_STRIP_TEMPLATE`, `_build_rag_strip_page`) — bundle with any nearby change |

**Exit:** all seven closed or explicitly re-deferred with reasons.

---

## v1.6 — Delivery Config at Scale

**Goal:** Stop `delivery_config.yaml` from degrading as a shared cross-team surface:
shrink what the file has to say, split ownership, put it under real version control
with review, and make "who gets what, when" answerable without reading YAML.
Slotted immediately after v1.4.x because the pain is live on production now, the
work is cheap, and nothing downstream depends on it.

### Requirements (draft IDs)

| ID | Requirement |
|----|-------------|
| CONF-01 | Recipient membership moves out of the YAML: groups reference Exchange distribution lists (one stable DL address per group) wherever the org allows; residual explicit lists move to a named `recipient_lists:` section referenced by key — membership churn leaves the file entirely |
| CONF-02 | `defaults:` block + optional per-group `extends:` key, resolved by the config loader *before* schema validation (loader-level inheritance, not YAML anchors — anchors are fragile for occasional cross-team editors) |
| CONF-03 | `delivery_config.d/` directory support: one file per team/business domain with an `owner:` metadata field; loader globs, merges, and enforces global group-name uniqueness at load; single-file mode remains supported (CONF-01→03 are load-order sensitive — implement in that order) |
| CONF-04 | Private internal config repo (separate from the public app repo — the PII concern that drove gitignoring applies to the public repo, not to version control itself): restricted access, CODEOWNERS mapped to the `.d/` split so each team reviews its own file, CI gate running schema validation + `run_all.py --dry-run` against the merged result on every PR; production consumes the repo (pull or config artifact), ending untracked hand-edits over SSH |
| CONF-05 | Delivery-matrix generator: `--dry-run` extension or small `config_tool.py` emitting groups × reports × schedule × filters × owner as markdown/HTML, published from CI on every merge — the config made legible |

### Candidate phases (20–21)

1. **Phase 20 — Config language + loader** (CONF-01/02/03; parity gate: every existing production group resolves to an identical effective config under the new loader, asserted by a golden-file test)
2. **Phase 21 — Config repo + CI + matrix** (CONF-04/05; includes the operational cutover — production switches from hand-edited file to repo-sourced config with one dual-source cycle as fallback)

**Exit criteria:** production config sourced from the reviewed repo; recipient churn
handled via DLs/named lists without touching group definitions; delivery matrix
auto-published; effective-config golden test green.

**Risks:** DL adoption depends on Exchange/AD team cooperation (CONF-01 degrades
gracefully to named lists if DLs stall); the private repo needs provisioning through
change management — start that request at milestone open, not at Phase 21.

**Explicitly deferred:** database + admin-UI config management. Revisit only if
non-technical stakeholders need direct self-service and PR review becomes the
bottleneck; the git + `.d/` + CODEOWNERS pattern holds well past current scale and
gives auditors an approval trail they already understand.

---

## v1.7 — Validation Substrate (synthetic cache + offline mode)

**Goal:** A committable, fully synthetic Tenable dataset plus a code-enforced
offline mode, so Claude Code and CI can validate the entire pipeline against a
known data set with zero live pulls and zero real records in version control.

**Full spec:** `milestone-spec-validation-substrate.md` (VAL-01…VAL-10 with
verification gates, PII checklists, and key decisions). This section is the
roadmap summary; the spec is authoritative at `/gsd-new-milestone` time.

**Design decision (record in PROJECT.md):** synthetic generation from an
aggregate profile — NOT anonymization of real records. Record-level anonymized
data still encodes the institution's exposure profile (CVE/plugin distribution
across ~40k assets is threat intel even fully scrubbed), so it could never be
committed. Committed artifacts are limited to a structural schema manifest, an
aggregate-only human-reviewed profile (D-04-08-compliant, fuzzable), and
generator code.

### Requirements (summary — see spec for full text)

| ID | Requirement |
|----|-------------|
| VAL-01 | Structural schema manifest extracted from a real cache (columns/dtypes only) — the fidelity anchor |
| VAL-02 | Profiler (human-run on prod, hook-guarded): aggregate-only statistical profile with `--fuzz`; mandatory PII review before commit |
| VAL-03 | Seeded deterministic generator: full synthetic cache (vulns/assets/tags/fixed_vulns/recast_rules) from manifest + profile + public plugin dictionaries; provenance rule — no code path reads `data/cache/` |
| VAL-04 | Longitudinal lifecycle simulation (open→fix→reopen, ~19% reopened rate, N-month series) — Spike 004's parity dataset; bootstrap profile ships so generator work never blocks on the human profiler run |
| VAL-05 | Offline mode: `--offline` / `VULN_REPORTING_OFFLINE=1`; `get_client()` refuses pre-auth; fetchers raise `CacheMissError`; `--cache-dir` override for tests |
| VAL-06 | Hook allows `run_all.py --offline` (flag form only — env-var form enforces but earns no exemption); CR-C4 adversarial test group |
| VAL-07 | `-m synthetic` integration harness: full suite offline against pinned-seed structural goldens, in CI at reduced scale |
| VAL-08 | Quarterly human-run real-vs-synthetic structural comparison (Phase 18 playbook repurposed); manifest drift fails loudly in the generator |
| VAL-09 | PII gates: profile review checklist, CI denylist test, generator provenance conformance test, RFC 5737/3849 + `.example` identifiers so leaked synthetic data is self-evidently synthetic |
| VAL-10 | Docs: Hard Rule 1 amended for `--offline`; GLOSSARY entries; `docs/synthetic_data.md` (auditor-runbook practice applied to test data) |

### Candidate phases (22–25)

1. **Phase 22 — Manifest + profiler tooling** (VAL-01/02, VAL-09a/b; ends at a human checkpoint: profiler run on prod + PII review + commit)
2. **Phase 23 — Generator + longitudinal model** (VAL-03/04, VAL-09c/d; developed against the bootstrap profile; exit gate: generated cache round-trips every fetcher consumer at CI and full scale)
3. **Phase 24 — Offline mode + hook** (VAL-05/06; exit gate: CR-C4 green + manual zero-egress verification against a cold cache dir)
4. **Phase 25 — Integration harness + CI + docs** (VAL-07/08/10)

Phases 22–23 and Phase 24 are independent and parallelizable; Phase 24 alone is
independently shippable — offline mode is useful *today* with a real warm cache
on the prod-adjacent box, before any synthetic data exists.

**Exit criteria:** Claude Code on a fresh clone (hook active) can generate the
synthetic cache, run the full report suite offline, and run the `-m synthetic`
harness with zero denials and zero egress; VAL-09 checks green with review
sign-off recorded; Spike 004 declares the dataset sufficient or files concrete
generator gaps as VAL follow-ups *before* its verdict.

**Risks (top two):** schema-fidelity drift → false confidence (manifest anchor +
VAL-08 quarterly check); profile judged too revealing even in aggregate (`--fuzz`;
worst case the real profile stays uncommitted on the prod box and only the
bootstrap profile is public — realism degrades, nothing breaks).

---

## v1.8 — Findings History Store (keystone)

**Goal:** Replace "Tenable is the database + aggregate snapshots" with a local,
full-fidelity, append-only findings history in DuckDB over the existing parquet
exports — so "open at date D," MTTR, new-vs-remediated, and reopened counts become
queries over history instead of logic reconstructed inside modules, and so future
questions are answerable for dimensions nobody thought to snapshot.

**Spike-first. Do not commit the milestone until Spike 004 returns a verdict.**

### Spike 004 — DuckDB history viability (1–2 days, decision-grade)

- Ingest N days of existing `data/cache/<date>/` parquet into a DuckDB
  `findings_history` table keyed on (finding_uid, snapshot_date).
- Reimplement `open_findings_at(D)` as a SQL view; assert **zero-drift parity**
  against `utils/open_count.py` across every historical date available.
- Measure: DB size at ~40k assets × daily grain (project 12/24 months), ingest
  wall-time appended to `warm_cache`, and query latency for the three heaviest
  module computations.
- Verdict gates: parity exact; projected 24-month size acceptable for the RHEL
  host; ingest adds < a defined budget to the warm-cache cron window. PARTIAL
  verdicts reshape the milestone (e.g., weekly grain instead of daily); FAIL
  kills v1.8 and the roadmap falls back to extending the snapshot substrate.
- Wrap findings into the `spike-findings-vuln-reporting` skill (new feature-area
  row), same as spikes 001/002.

### Requirements (draft IDs)

| ID | Requirement |
|----|-------------|
| HIST-01 | Daily ingest appends normalized findings + assets from the warm-cache parquet into `data/history/history.duckdb` (local-only, gitignored, PII-equivalent to the cache) |
| HIST-02 | Idempotent ingest: re-running a day's ingest is a no-op (keyed upsert), mirroring `capture_snapshot()` semantics |
| HIST-03 | `open_findings_at(D)` reimplemented as a versioned SQL view with a permanent parity test against the Python predicate on synthetic fixtures |
| HIST-04 | `read_trend()` consumers served from history queries behind a feature flag; JSON snapshots dual-written for ≥ one full delivery cycle as audit fallback |
| HIST-05 | Schema versioning + migration path (`schema_version` table; additive-only columns in v1.8) |
| HIST-06 | Retention & pruning policy (configurable horizon; default ≥ 24 months) with size telemetry in the warm-cache log |
| HIST-07 | Backfill: seed history from the ~12mo reconstruction data + bounded `last_fixed` fetch (human-run; Claude Code blocked per policy) |
| HIST-08 | Cold-start behavior preserved: modules' `insufficient_data` contract unchanged from the consumer side |
| HIST-09 | `duckdb` is the **single** new dependency, pinned; explicit exception to the zero-new-deps rule recorded as a Key Decision |

### Candidate phases (26–29)

1. **Phase 26 — Spike 004 + decision** (gate)
2. **Phase 27 — Ingest pipeline + schema** (HIST-01/02/05/06; wire into `warm_cache.py` post-fetch; hook stays satisfied since ingest reads local parquet only)
3. **Phase 28 — Query layer + parity** (HIST-03; views for open-at-D, MTTR population, new/remediated inflow-outflow, reopened counts; parity harness against Python implementations)
4. **Phase 29 — Trend consumer cutover** (HIST-04/07/08; flag flip after one clean dual-write cycle; management_summary + board_summary outputs byte-identical or documented-difference with operator UAT, reusing the Phase 18 bucketed-parity playbook)

**Exit criteria:** parity gates green on synthetic + live-shape data; one full
scheduled delivery cycle on the flag with zero output drift; snapshots still
captured (not yet retired — retirement is a v1.9+ decision once confidence exists).

**Risks:** DuckDB file locking vs concurrent daemon/cron access (mitigate:
single-writer via warm_cache, readers open read-only); disk growth (HIST-06);
temptation to migrate modules early (explicitly out of scope — v1.8 changes the
*substrate*, not the modules).

---

## v1.9 — Canonical Derived Fields at Ingest

**Goal:** Classification happens once, when data lands — not per call site at
report time. Ends the class of drift where `tag_severity_share` diverged from
`vpr_to_severity` and resolves SEV-NONE-01 globally.

### Requirements (draft IDs)

| ID | Requirement |
|----|-------------|
| DER-01 | Ingest computes and stores: `severity_vpr` (VPR-first), `sla_status`/`days_open`, `owner` (extract_owner), `is_external` (external_scope), `vuln_type` (VTD-01 classifier) as history-store columns |
| DER-02 | SEV-NONE-01 resolved here: single global rule for vpr null/0 → `None` tier, with the tag_severity_share divergence either folded in or documented as the sole sanctioned exception (decision gate) |
| DER-03 | Classifier maps (family override, CPE prefixes, MS-Bulletin routing) move to versioned config; a classifier-version column on each row makes historical rows auditable ("classified under rules v3") |
| DER-04 | All module call sites migrated to read columns; per-field parity gate (column value vs legacy call-site computation) on live-shape fixtures |
| DER-05 | Auditor runbooks updated: each `docs/*_calculations.md` points at the ingest rule + version, not per-report logic |
| DER-06 | Re-derivation path: a human-run script can recompute derived columns over existing history after a classifier-map change, stamping the new version (immutable raw fields; mutable derived fields — record as Key Decision) |

### Candidate phases (30–31)

1. **Phase 30 — Derivation layer + columns + parity** (DER-01/02/03/06)
2. **Phase 31 — Call-site migration + runbook sync** (DER-04/05; mechanical, high-test-coverage work — good parallelization candidate)

**Exit criteria:** zero call sites computing severity/owner/scope/type inline
(enforced by a grep-based conformance test, same pattern as the hook coverage
test); all deliveries unchanged.

**Risk:** DER-02 is a *reporting-content* change if the global rule differs from
any current report's behavior — requires operator sign-off per affected report
before cutover, not after.

---

## v1.10 — MetricResult & Generic Render Layer

**Goal:** Modules stop owning rendering. `compute()` emits a typed `MetricResult`;
a small set of generic renderers produces all channels. Empty-data guarding is
implemented once, in the renderers. Target: a new metric is a compute function +
a declarative presentation spec, ~100–200 lines.

### Requirements (draft IDs)

| ID | Requirement |
|----|-------------|
| REN-01 | `MetricResult` dataclass: headline value+unit, RAG status, trend series, drill-down frame(s), driver narrative, presentation hints — a strict superset of today's `ModuleData` |
| REN-02 | Generic renderer set: KPI tile, trend chart, table, gauge, RAG-strip cell — each rendering to PDF-HTML, Excel, email-panel, and analyst-tab channels |
| REN-03 | Empty-data guard implemented once in the render layer; `safe_pct`/`safe_int` become renderer internals; module-level guard code deleted as modules migrate |
| REN-04 | Typed boundaries rolled in: `DataContext` (replaces the kwargs frozenset gates) and `ReportBundle` (replaces the return-dict contract), with deprecation shims so unmigrated reports keep working |
| REN-05 | Pilot migration: 2 structurally different modules (suggest `total_vulns_by_severity` — simple — and `mttr_trend` — trend-heavy) prove the layer before batch work |
| REN-06 | Batch migration of remaining modules; per-module byte-parity or operator-UAT'd documented differences (Phase 18 playbook) |
| REN-07 | LOC telemetry: median module size before/after recorded in the milestone audit — this is the milestone's success metric |

### Candidate phases (32–35)

1. **Phase 32 — MetricResult + renderer core + pilot** (REN-01/02/03/05)
2. **Phase 33 — Typed boundaries** (REN-04)
3. **Phase 34 — Batch migration A** (board_summary module set)
4. **Phase 35 — Batch migration B** (management_summary module set + stragglers; REN-06/07)

**Exit criteria:** all registered modules on MetricResult; render-layer test suite
owns the empty-data guarantee (the per-phase QUAL-03 re-verification ritual retires);
median module LOC materially down (set the target after Phase 32 pilot data).

**Risk:** biggest refactor in the roadmap. Mitigations: pilots first, per-module
parity gates, shims so a half-migrated tree still ships, and *no other milestone
work concurrent with Phases 34–35*.

---

## v1.11 — Reports-as-Data Consolidation

**Goal:** `composed_report` becomes the only real execution path; the named slugs
become maintained YAML presets. GEN-02 finally lands — onto the thin v1.10 model,
so `ops_remediation` is migrated exactly once.

### Requirements (draft IDs)

| ID | Requirement |
|----|-------------|
| CON-01 | GEN-02: `ops_remediation` decomposed into modules (7 tabs → module set) and migrated to the composer pipeline; bespoke path removed in a single atomic commit behind a parity golden (Phase 18 pattern) |
| CON-02 | Preset mechanism: named slugs (`executive_kpi`, `sla_remediation`, …) defined as shipped YAML module-bundles; `run_all.py` resolves slug → preset → composed pipeline; `_REPORT_MODULE_MAP` shrinks toward one entry |
| CON-03 | LEGACY-01 resolved: each remaining legacy report either becomes a preset, is decomposed (small phase each), or is formally retired with recipient-group sign-off |
| CON-04 | Backward compat: every existing group's YAML works unmodified; presets are internal resolution, not a config migration |
| CON-05 | Docs: RUNBOOK/DEPLOYMENT updated; "Adding a New Report" in CLAUDE.md collapses to "add modules + a preset YAML" |

### Candidate phases (36–38)

1. **Phase 36 — Preset resolution + 2 simplest legacy conversions** (CON-02, start CON-03)
2. **Phase 37 — GEN-02 ops_remediation** (CON-01; the heavy one — its 3,051 lines are the whole phase)
3. **Phase 38 — Remaining conversions + retirements + docs** (CON-03/04/05)

**Exit criteria:** `reports/` contains modules, `composed_report.py`, and presets —
no bespoke render paths; slug count in `_REPORT_MODULE_MAP` ≤ 2 (composed + any
formally-retained exception).

---

## v1.12 — Packaging & Deployment Simplification

**Goal:** Replace the bespoke tarball updater with standard packaging (RPM built in
CI is the RHEL-9/change-management-native answer; wheel + `uv` install is the
fallback), while preserving the operational guarantees v1.2 earned: atomic upgrade,
health check, rollback.

**Decision gate first:** RPM vs wheel+uv, driven by (a) whether the corporate proxy
/ artifact-store constraints that shaped v1.2 still bind, and (b) what change
management will accept fastest. Timebox the evaluation; don't build both.

### Requirements (draft IDs)

| ID | Requirement |
|----|-------------|
| PKG-01 | CI builds the chosen artifact on every `vX.Y.Z` tag (extends `release.yml`); SHA256 + signing per current practice |
| PKG-02 | Install/upgrade path preserves: post-upgrade health check, rollback to prior version, per-release isolation (RPM: `%posttrans` health check + `dnf history undo` documented; wheel: retain the symlink-swap only if uv can't cover it) |
| PKG-03 | systemd unit + hardening carried over unchanged where possible; deviations documented |
| PKG-04 | One full release cycle of dual support (old updater still works) before `update_from_github.sh` is retired; retirement is its own small phase with DEPLOYMENT.md rewrite |
| PKG-05 | Smoke scripts (`deploy/smoke_*.sh`) ported to exercise the new path on the Rocky 9 VM before first production use |

### Candidate phases (39–41)

1. **Phase 39 — Decision spike + CI pipeline** (PKG-01, gate)
2. **Phase 40 — Install path + VM validation** (PKG-02/03/05)
3. **Phase 41 — Cutover + updater retirement** (PKG-04)

**Exit criteria:** one production upgrade and one deliberate rollback executed via
the new path on the real host; bespoke updater deleted; DEPLOYMENT.md smaller than
it is today.

**Note:** independent of v1.8–v1.11 — can be reordered earlier or run between
milestones if a deployment pain spike makes it urgent. It's sequenced late only
because it touches production delivery and the reporting-value milestones don't
depend on it.

---

## v2.0 — Compliance Reporting (new value on the new substrate)

**Goal:** First genuinely new reporting domain, built to prove the platform claim:
a new metric family should now cost "compute + preset," not a milestone of
infrastructure. Seeds already exist: `.planning/seeds/compliance-reporting.md` and
`.planning/notes/compliance-data-model-decisions.md`, plus
`docs/tenable_compliance_api_reference.md`.

### Shape (requirements to be drafted from the seed at milestone time)

- Compliance findings ingest into the history store (new table, same ingest/PII/
  retention discipline — HIST patterns reused, not rebuilt)
- Compliance metric modules as MetricResult compute functions (CIS benchmark pass
  rates, drift-over-time, per-owner compliance posture) rendered entirely by the
  v1.10 generic layer
- Audience presets: operations detail / management trend / executive RAG — the
  original core-value statement, demonstrated on a second domain
- Auditor runbook per metric from day one (keep this practice — it's the most
  valuable convention in the repo)
- **Success metric for the whole roadmap:** LOC and calendar time for v2.0's first
  end-to-end metric, compared against a v1.4-era module. If the redesign worked,
  the difference is dramatic and measurable in the milestone audit.

**Candidate insertions near v2.0** (sequence by appetite, not dependency): the WAS
access path (spike 003 exists), and `threat-intel-tag-migration.md` — both are new
data domains that follow the same ingest-store-compute-preset pattern once v1.8/v1.10
exist.

---

## Dependency graph

```
v1.4.x ──> v1.6 ──> v1.7 ──> v1.8 ──> v1.9 ──> v1.10 ──> v1.11 ──> v2.0
                       (v1.12 independent; slot anywhere after v1.4.x)
```

v1.6 has no downstream dependents — it is sequenced first purely because the pain
is current. Its only interaction with later work: v1.11's preset resolution (CON-02)
builds on the same config loader, so land CONF-02/03 before starting CON-02.

Hard dependencies: v1.8's Spike 004 consumes v1.7's longitudinal dataset (VAL-04), and v1.7's offline mode (Phase 24) is a soft prerequisite for every later parity gate Claude Code runs; v1.9 needs v1.8's store; v1.10 benefits from v1.9 (compute
functions read canonical columns) but only *requires* v1.8; v1.11 requires v1.10
(migrate ops_remediation once, onto the thin model); v2.0 requires v1.8 + v1.10.

## Kill-switches / re-plan triggers

- VAL-02 profile fails PII review even fuzzed → the real profile stays on the prod
  box uncommitted; the generator ships on the bootstrap profile (reduced realism,
  full function); v1.7 proceeds and the quarterly VAL-08 check runs on-box.
- Spike 004 FAIL → cancel v1.8; v1.9 re-scopes derived fields onto the parquet
  cache + snapshot substrate; v1.10/v1.11 proceed unchanged.
- Phase 32 pilot shows the generic renderers can't hit visual parity for the board
  PDF → v1.10 re-scopes to email/Excel/analyst channels only, PDF sections stay
  module-owned (partial win still retires most guard duplication).
- v1.12 decision spike finds change management blocks both RPM and wheel paths →
  keep the bespoke updater, close v1.12 as evaluated-and-declined, record decision.
