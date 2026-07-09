# Phase 20: Config Language + Loader + Matrix - Context

**Gathered:** 2026-07-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Introduce a new config **source language** and the loader that resolves it, plus a legibility tool and a parity gate:

- A shared `contacts.yaml` (named contact groups + a top-level `defaults:` block) — the "who".
- Per-team delivery files under `deliveries.d/` (one file per team, each with `owner:` + a `deliveries:` list) — the "what/when".
- A loader that resolves contacts / `defaults` / `contact:` refs / `extra_recipients` into a concrete `email:` block **before** the existing `delivery_config.schema.yaml` validates the resolved effective config.
- A **delivery matrix** generator (deliveries × reports × schedule × filters × owner) from the resolved config.
- An **effective-config golden test** (QUAL-06) proving the new loader resolves every existing config identically to today.

**Requirements:** CONF-01, CONF-02, CONF-03, CONF-05, QUAL-06.

**Out of scope for this phase** (fixed by REQUIREMENTS.md): the private repo / CODEOWNERS / CI gate / production cutover (Phase 21, CONF-04/QUAL-07); renaming internal Python `group` identifiers (`run_group()`, `output/<date>_<group-name>/`, `delivery_log.db`); per-delivery SLA override; per-team default filters. Only the user-facing surface (`groups:`→`deliveries:`, schema, docs, dry-run output) adopts "delivery."

</domain>

<decisions>
## Implementation Decisions

### Config source discovery & mode selection
- **D-01:** **Directory presence is the mode switch.** If a `deliveries.d/` directory exists next to the config, the loader uses directory mode (glob + merge team files + read `contacts.yaml`). Otherwise it falls back to the single `delivery_config.yaml` (legacy or migrated single-file form). No new CLI flag; presence is the switch — simplest for the Phase 21 cutover.
- **D-02:** **`contacts.yaml` is a required sibling in directory mode.** It sits next to `deliveries.d/` in the same config directory and holds contacts + `defaults` **only**. Missing `contacts.yaml` while in directory mode is a clear load error. This enforces the "nothing defined twice" guardrail — the shared "who" lives in exactly one place.
- **D-03:** **Directory-mode deliveries reference recipients via `contact:` only.** A team-file delivery MUST use a `contact: <key>` ref, optionally adding an additive `extra_recipients:` list (merged + deduped, never overriding the contact). An inline `email.recipients` block in directory mode is **rejected**. Forces all "who" into `contacts.yaml`; keeps team files to deliveries only. (Legacy single-file mode still accepts inline `email:` for QUAL-07 backward compat.)

### Delivery matrix generator (CONF-05)
- **D-04:** **Standalone script** — `scripts/generate_delivery_matrix.py` with argparse (`--format`, `--output`), reusing the loader's resolved config. Matches the existing `scripts/` entry-point pattern (`warm_cache.py`, `capture_trend_snapshot.py`) and is trivial for the Phase 21 CI step to invoke. Not folded into `run_all.py`.
- **D-05:** **Matrix shows contact/group NAMES + owner, never expanded recipient addresses.** Columns cover deliveries × reports × schedule × filters × owner at the contact-name granularity the split is organized around. Safe to publish as a CI artifact without leaking real mailboxes — honors Hard Rule 2 / QUAL-05 (aggregate-only PII, D-04-08).
- **D-06:** **Markdown by default, HTML optional** via `--format html`. Markdown renders natively in the private repo / PR view, is greppable and diff-friendly; a styled standalone HTML page is opt-in. Not "both, always."

### Effective-config golden test (QUAL-06)
- **D-07:** **Committed JSON golden + two-way equality.** Resolve → normalize (sorted keys) → serialize to a committed golden JSON file. The test asserts (a) the legacy single-file fixture resolves **byte-identical** to the golden, and (b) the migrated twin resolves to the **same** golden. A reviewable artifact in the diff that also catches silent normalization drift.
- **D-08:** **Fixtures = a migrated twin derived from `delivery_config.example.yaml`.** Author `contacts.example`-style + a `deliveries.d/` twin derived from the existing example config; the golden proves the twin resolves identically to the original single file. Keeps `delivery_config.example.yaml` as the living reference shape and exercises every current key (composed_report `modules`, `cc`, `reply_to`, `on_demand`, empty `filters`). **Synthetic `example.invalid` identifiers only** (D-04-08) — never production config.

### New-key validation & error/warning surfacing
- **D-09:** **Permissive Python checks before resolution** — targeted programmatic validation in the loader (required keys present, every `contact:` ref resolves, delivery names globally unique across files, no inline `email:` in directory mode). No second JSON schema. Matches the requirement's "validated separately/permissively before resolution" wording; the existing `delivery_config.schema.yaml` still gates the **resolved** effective config unchanged.
- **D-10:** **logger + surfaced in `run_all.py --dry-run`.** Deprecated `groups:` alias → `logger.warning` (keeps loading, per CONF-03); duplicate delivery name / undefined `contact:` ref / inline-`email:`-in-directory-mode → `logger.error` + non-zero exit. All echoed in `--dry-run` output so the Phase 21 CI gate and operators see them prominently. Extends the existing fail-loud-at-startup pattern (`run_all.py:166-198`).

### Claude's Discretion
- Exact search path for locating the config directory / `deliveries.d/` relative to the `shared/` symlink layout in prod.
- JSON normalization details for the golden (key ordering, list handling, how `None`/absent keys serialize).
- Matrix Markdown column layout and HTML styling specifics.
- Precise Python module boundary for the new resolver (new `utils/`/`delivery/` module vs. extending `run_all.py._load_config`).

</decisions>

<specifics>
## Specific Ideas

- The loader is **resolve-before-validate**: source keys (`defaults`, `contacts`, `contact:`, `owner:`, `deliveries.d/`) resolve into today's group shape, then the *existing* schema validates the resolved config — backward compatibility falls out for free and the current schema stays the single gate on effective config. (REQUIREMENTS.md Design Decisions.)
- `defaults.analyst_mailbox` is **one knob, universal, no opt-out**: it drives both the default `Reply-To` and a standing `Cc` on every delivery; a contact may override `reply_to`. No per-delivery archive opt-out branch.
- CONF-01→03 are **load-order sensitive** and implemented in that order (contacts → defaults resolution → deliveries.d merge/uniqueness).

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & design (authoritative)
- `.planning/REQUIREMENTS.md` — CONF-01/02/03/05 + QUAL-06/07 full text AND the **"Design Decisions (2026-07-09 operator discussion)"** section, which locks: resolve-before-validate, nothing-defined-twice, analyst-mailbox-no-opt-out, rename scope boundary, filters-stay-per-delivery, no-per-delivery-SLA. Also the **Out of Scope** table.
- `.planning/ROADMAP.md` §"Phase 20: Config Language + Loader + Matrix" — goal + the 5 numbered Success Criteria (what must be TRUE).
- `.planning/roadmap-v1.6-v2.0.md` — forward-roadmap origin of CONF-01…05 and milestone sequencing rationale.

### Existing config surface (what to extend / preserve)
- `delivery_config.schema.yaml` — the JSON Schema that validates the **resolved effective config**; role is unchanged (single gate). Must keep validating today's group shape.
- `delivery_config.example.yaml` — committed reference shape; **source for the migrated-twin golden fixture** (D-08).
- `run_all.py` §`_load_config` (~156-199), `_validate_with_schema`, `_load_schema` (~302) — the single loader to extend; fail-loud-at-startup pattern to mirror (D-10).

### Cross-cutting constraints
- `CLAUDE.md` — Hard Rule 2 (aggregate-only PII, D-04-08) governs the matrix PII treatment (D-05) and golden fixtures (D-08); Hard Rule 1 (no live Tenable pulls — the Phase 21 CI `--dry-run` gate is pre-auth); "Delivery Configuration — `delivery_config.yaml`" section and "Email Delivery — key rules".

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `run_all.py:_load_config()` — current single-file load + schema-validate + return-groups path; the resolver extends this (or a new module it calls). `_validate_with_schema` / `_load_schema` / `_format_error_path` are the existing jsonschema plumbing to reuse for the resolved-config gate.
- `scripts/warm_cache.py`, `scripts/capture_trend_snapshot.py` — the argparse + `if __name__ == "__main__"` standalone-script pattern for `scripts/generate_delivery_matrix.py` (D-04).
- `delivery/email_sender.py` — consumer of the resolved `email:` block (`recipients`/`cc`/`reply_to`); resolution must produce exactly the shape it already expects.

### Established Patterns
- Config path is hardcoded `ROOT_DIR / "delivery_config.yaml"` (`run_all.py:164`), symlinked from `shared/` in prod (`/opt/vuln-reporting/shared/`). Directory-mode discovery (D-01) resolves relative to that same location.
- `scheduler.py` hot-reloads the YAML in daemon mode — directory mode + glob/merge must work under reload, not just one-shot.
- Schema validation fails loud at startup (`run_all.py:166-198`) and via `--dry-run`; new errors extend this (D-10).

### Integration Points
- `run_group()` (the sole executor) consumes each resolved group dict unchanged — internal `group` identifiers are deliberately NOT renamed (Out of Scope).
- Phase 21 depends on this phase's loader, `--dry-run` gate behavior, and matrix script existing before the repo can be gated and consumed.

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. (Per-team default filters / `extends:`, per-delivery SLA override, database/admin-UI config, and the private repo + CI + CODEOWNERS + cutover are already recorded as Out of Scope or Phase 21 in REQUIREMENTS.md.)

</deferred>

---

*Phase: 20-config-language-loader-matrix*
*Context gathered: 2026-07-09*
