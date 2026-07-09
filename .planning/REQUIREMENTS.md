# Requirements: v1.6 Delivery Config at Scale

**Defined:** 2026-07-09
**Core Value:** Right metric, right audience, right channel — without writing a new report each time.

**Milestone goal:** Stop `delivery_config.yaml` from degrading as a shared cross-team surface. Separate the "who" (recipients) from the "what/when" (deliveries), split deliveries into per-team files with clear ownership, put the config under real version control with review, and make "who gets what, when" answerable without reading YAML.

**Source:** Refines the forward roadmap [`roadmap-v1.6-v2.0.md`](roadmap-v1.6-v2.0.md) (CONF-01…05) with the 2026-07-09 operator design discussion. Full scope — both candidate phases (20 + 21).

**Today's pain (the thing being fixed):** One team receiving several reports means several delivery stanzas, each duplicating the same recipient block. Updating a contact means finding and editing every stanza that team appears in. The file grows as (teams × reports) and becomes hard to navigate, own, or review.

---

## v1.6 Requirements

### Config Language & Loader (CONF-01/02/03) — Phase 20

- [x] **CONF-01**: An operator can define recipients once as named **contact groups** in a shared `contacts.yaml` (each entry carrying `recipients` + optional `cc`/`reply_to`), and a delivery references a contact by name (`contact: <key>`) instead of an inline recipient list. An Exchange distribution-list address is a valid contact entry, so membership churn handled in AD never touches this config. Updating a contact is a single edit; recipient churn no longer requires touching any delivery stanza.

- [x] **CONF-02**: The config loader resolves a top-level `defaults:` block **before** schema validation. `defaults.analyst_mailbox` is applied to every delivery as **both** (a) the default `Reply-To` and (b) a standing `Cc` — so the analyst group keeps a record of every report and any recipient reply reaches the analysts, defined once and never repeated. A delivery may add ad-hoc recipients via an additive `extra_recipients:` list (merged + deduped, never overriding the referenced contact) to pull in a manager / CISO / engineer / analyst for temporary attention. A contact may override `reply_to` for its team.

- [x] **CONF-03**: The loader supports a `deliveries.d/` directory — **one file per team**, each with an `owner:` metadata field and a `deliveries:` list — globbing and merging all files at load, and enforcing **global delivery-name uniqueness** across files (today no uniqueness check exists; identically-named groups silently coexist). Single-file mode remains supported. The top-level YAML key is renamed `groups:` → `deliveries:`; the legacy `groups:` key is accepted as a **deprecated alias** (with a load-time warning) for the transition. CONF-01→03 are load-order sensitive and implemented in that order.

### Legibility (CONF-05) — Phase 20

- [x] **CONF-05**: An operator or auditor can generate a **delivery matrix** — deliveries × reports × schedule × filters × owner — as markdown/HTML from the *resolved* config, published from CI on every merge. "Who gets what, when" becomes answerable without reading YAML. (Also serves as the natural acceptance test / first consumer of the resolver.)

### Version Control & Review (CONF-04) — Phase 21

- [ ] **CONF-04**: The delivery configuration lives in a **private internal repository** (separate from the public app repo — the PII concern that drove gitignoring applies to the *public* repo, not to version control itself): restricted access, a **CODEOWNERS** mapping aligned to the `deliveries.d/` split so each team reviews its own file, and a **CI gate** running schema validation + `run_all.py --dry-run` against the *merged effective* config on every PR. Production consumes the reviewed repo (pull or published config artifact), ending untracked hand-edits over SSH. **Long-lead:** provisioning the private repo goes through change management — the request starts at milestone open, not at Phase 21.

### Quality & Compatibility Bars (QUAL) — carried from v1.4

- [x] **QUAL-06**: An **effective-config golden test** asserts that every existing delivery resolves to an identical effective config under the new loader — an un-migrated single file resolves byte-identical, and a migrated file (contacts + defaults + refs) resolves to the *same* effective config. The golden runs against the **synthetic `example.invalid` config only — never production config** (D-04-08). This is the safety gate that makes the cutover reversible in review.

- [ ] **QUAL-07**: Existing `delivery_config.yaml` groups deliver **unchanged during and after** the cutover: the legacy single-file + inline-`email:` + `groups:` form keeps loading and delivering (a deprecated-but-working path), and the production cutover to the repo-sourced config runs with one dual-source fallback cycle before the old path is retired.

---

## Design Decisions (2026-07-09 operator discussion)

- **Resolve-before-validate.** The loader resolves contacts / `defaults` / refs / `extra_recipients` into a concrete `email:` block, *then* the existing `delivery_config.schema.yaml` validates the **resolved effective config** (unchanged in role). So whatever operators write must resolve down to today's group shape — backward compatibility falls out for free and the current schema stays the single gate. New source-level keys (`defaults`, `contacts`, `contact:`, `owner:`, `deliveries.d/`) are validated separately/permissively before resolution.

- **Nothing defined twice (the guardrail).** Contacts + `defaults` live **only** in the shared `contacts.yaml`; per-team `deliveries.d/*.yaml` files hold deliveries only. This is the single rule that stops per-team splitting from re-duplicating the shared "who" one level up — the failure mode that would make the split worse than today (duplicated analyst mailbox / security cc across files, "where is this contact defined?" hunts, cross-file collisions, precedence rules).

- **Analyst mailbox = one knob, universal, no opt-out.** `defaults.analyst_mailbox` drives both the default `Reply-To` and the standing `Cc`. All reporting is internal, so there is no per-delivery archive opt-out — this deletes a config knob and a code branch.

- **Rename scope boundary.** Only the *user-facing* surface (YAML key `groups:`→`deliveries:`, schema, docs, dry-run output) adopts "delivery." Internal Python `group` identifiers — `run_group()`, `output/<date>_<group-name>/` naming, the `delivery_log.db` audit schema — are left untouched (see Out of Scope); an internal rename is churn with no user value and real risk to the fail-soft executor and audit history.

- **Filters stay per-delivery.** A team wanting a stricter-scope report just adds one delivery with a narrower `filters:` block — touching no global setting and no other team's file. A per-file default filter was considered and rejected: filters genuinely vary per delivery, so a shared default would fight more than help.

- **No per-delivery SLA override.** The org SLA is universal. A stricter-turnaround team self-selects operationally; their need is met by the narrower per-delivery filter above, with the report's SLA math unchanged — keeping v1.6 pure config-plumbing and the QUAL-06 "resolves identically" gate clean.

---

## Cross-cutting constraints (carried from v1.4, per the forward roadmap)

- **QUAL-05 (aggregate-only PII, D-04-08):** never relaxed. The effective-config golden and any committed fixtures use synthetic `example.invalid` identifiers only; real recipient config stays gitignored / in the private repo.
- **No live Tenable pulls from Claude Code:** the hook stays green; CI's `run_all.py --dry-run` gate is a pre-auth dry-run (no live fetch).
- **Backward compatibility:** every existing `delivery_config.yaml` group must deliver unchanged through the cutover (QUAL-07).

---

## Future / Deferred (after v1.6)

- **GEN-02** — Migrate `ops_remediation` to the module contract (v1.11 in the forward roadmap).
- **GEN-03/04** — Broader YAML-driven module composition beyond `composed_report`.
- **Database / admin-UI config management** — see Out of Scope.

---

## Out of Scope

| Feature | Reason |
|---------|--------|
| Per-delivery SLA-threshold override | Org SLA is universal; stricter-turnaround teams self-select operationally. Their need is met by a narrower per-delivery filter (already supported) with unchanged report math. Keeps v1.6 pure plumbing and the parity gate clean. |
| Renaming internal Python `group` identifiers | `run_group()`, `output/<date>_<group-name>/` naming, and the `delivery_log.db` audit schema all key on "group"; churn with no user value and real risk to the fail-soft executor + audit history. Only the user-facing YAML/schema/docs adopt "delivery." |
| Database / admin-UI config management | git + `deliveries.d/` + CODEOWNERS holds well past current scale and gives auditors an approval trail they already understand. Revisit only if non-technical self-service is needed and PR review becomes the bottleneck. |
| Per-team `defaults:` for shared filter/schedule (the roadmap's `extends:` idea) | Filters genuinely vary per delivery (operator-confirmed); a per-file default would fight more than help. Deferred as a possible fast-follow. |

---

## Traceability

Populated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| CONF-01 | Phase 20 | Complete |
| CONF-02 | Phase 20 | Complete |
| CONF-03 | Phase 20 | Complete |
| CONF-05 | Phase 20 | Complete |
| QUAL-06 | Phase 20 | Complete |
| CONF-04 | Phase 21 | Pending |
| QUAL-07 | Phase 21 | Pending |

**Coverage:**
- v1.6 requirements: 7 total (CONF-01/02/03/04/05, QUAL-06/07)
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-07-09*
*Last updated: 2026-07-09 after milestone v1.6 opened*
