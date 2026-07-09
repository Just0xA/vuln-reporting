# Phase 21: Private Config Repo + CI + CODEOWNERS + Production Cutover - Context

**Gathered:** 2026-07-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Move delivery configuration out of the untracked, hand-edited-over-SSH file at
`/opt/vuln-reporting/shared/delivery_config.yaml` and into a **private, reviewed corporate
repository** that is the source of truth and review gate:

- The private repo holds `contacts.yaml` + `deliveries.d/<team>.yaml` (the Phase 20 config language).
- **CODEOWNERS** gates review, mapped 1:1 to the `deliveries.d/` split.
- A **CI gate** runs schema validation + `run_all.py --dry-run` against the *merged effective*
  config on every PR, blocking a bad merge.
- **Production cutover** from server-side hand-edits to the reviewed config, with an
  **automatic dual-source fallback cycle** (new directory-mode config + legacy single file both
  functioning) before the legacy path is retired — with **zero delivery interruption**.

**Requirements:** CONF-04, QUAL-07.

**Out of scope** (fixed by REQUIREMENTS.md / Phase 20): the config language + loader + matrix
(delivered in Phase 20); renaming internal Python `group` identifiers; per-team default filters;
per-delivery SLA override. This phase is the *repository, review-gate, and cutover* layer on top
of the Phase 20 loader.

</domain>

<decisions>
## Implementation Decisions

### Production consumption & transport (CONF-04 SC3)
- **D-01: Private corporate repo is the source of truth + review gate; the reviewed config is
  copied to the prod server manually (same transport as today) — NOT git-pulled by the host, NOT
  a CI-built artifact the host fetches.** The hardened RHEL server gains no outbound-git or
  artifact-fetch machinery. What changes versus today: the file placed on the server is a merged,
  CODEOWNERS-reviewed, CI-passed file from the private repo — this ends *hand-edits on the server*,
  which is the actual intent of CONF-04. (Operator: "the files will be created on the corporate
  side and copied to the server, like current.")
- **D-02: Config never syncs to git on the build/dev (public app repo) side.** The public
  `vuln-reporting` repo keeps gitignoring real delivery config; the private corporate repo is the
  only git home for real config. The release/build path (`release.yml`) carries no config.
  Reaffirms Hard Rule 2 (aggregate-only PII; config never in the public repo). (Operator: "for
  build and dev the files should not sync to git.")
- **D-03: The live server config MUST be traceable to a reviewed repo commit** (no more untracked
  hand-edits). The invariant is: whatever is live on the server equals a merged, reviewed commit
  and that provenance is verifiable. Exact mechanism (stamp the source commit SHA alongside the
  copied config, or a checksum/drift check against repo HEAD) is planner/researcher discretion.

### Dual-source fallback cutover (QUAL-07 SC4)
- **D-04: Automatic loader fallback.** During the cutover window the server holds BOTH the new
  directory-mode config (copied from the reviewed repo: `contacts.yaml` + `deliveries.d/`) AND the
  legacy single `delivery_config.yaml`. The loader prefers directory mode (Phase 20 D-01
  presence-switch); if the directory-mode config is missing or fails to resolve/validate, it falls
  back to the legacy single file and logs a **WARNING naming the active source**. The fallback is a
  natural extension of the Phase 20 directory-presence switch — no new config surface.
- **D-05: "Which source won" is observable every run** and echoed in `run_all.py --dry-run`, so the
  operator can confirm a full dual-source cycle succeeded (repo-sourced path delivering cleanly)
  before retiring the legacy file. Extends the Phase 20 D-10 dry-run surfacing pattern.

### CI gate (CONF-04 SC2)
- **D-06: CI runs in the private config repo and validates against a PINNED app release tarball.**
  On every PR, CI fetches the pinned `vuln-reporting` slim release (the `release.yml` asset),
  installs `requirements.txt`, and runs schema validation + `run_all.py --dry-run` against the
  merged effective config. Version-pinned = reproducible; the pin is bumped when the loader/schema
  changes. (Chosen over pip/git-install-latest and a vendored validator — pinned tarball avoids
  drift from the real loader while staying reproducible.)
- **D-07: Gate scope = schema + full `--dry-run` on the merged config; non-zero exit blocks merge.**
  Reuses Phase 20's error surfacing (duplicate delivery names, undefined `contact:` refs,
  inline-`email:`-in-directory-mode, schema failures). `--dry-run` is **pre-auth** (Hard Rule 1) —
  needs no Tenable/SMTP credentials in CI. The delivery matrix
  (`scripts/generate_delivery_matrix.py`, names+owner only) is published as a PR artifact for
  reviewers.

### CODEOWNERS & governance (CONF-04 SC2)
- **D-08: CODEOWNERS structure is per-file (1:1 with the `deliveries.d/` split), but every owner
  entry points at the Vulnerability Management team — central stewardship, not distributed per-team
  owners.** The VM team controls the server + code and centrally manages/maintains all delivery
  files, so any config PR requires VM-team review. The 1:1 file structure is preserved so per-team
  delegation can be turned on later without restructuring. (Operator: "The Vulnerability Management
  team controls the server and code. They will centrally manage and maintain the delivery files.")
  - **Reconciliation flag for planner:** ROADMAP SC2 literally says a PR "requires *that team's*
    owner as a reviewer." Here review authority is centralized to the VM team now; the 1:1 mapping
    that *enables* per-team ownership exists, but the roster resolves to the VM team. This is
    intentional, not an oversight.
- **D-09: Shared, cross-cutting files (`contacts.yaml`, `defaults`, the schema copy) are owned by
  the VM team** (the default `*` rule → VM team). Consistent with central stewardship; a change to
  the shared "who" is a VM-team-reviewed change.
- **D-10: Actual VCS handles / team names and the repo host are a provisioning input, filled at
  repo creation via change management** (long-lead; the request starts at milestone open, not at
  Phase 21). The CODEOWNERS *structure* and the central-ownership rule are locked now; the concrete
  usernames/teams are filled in when the private repo is provisioned.

### Claude's Discretion
- Exact provenance mechanism for D-03 (source-commit-SHA stamp vs checksum/drift check).
- Directory-mode config layout on the server (e.g. `shared/config/`) and how the copied files are
  placed relative to the existing `shared/` symlink layout.
- CI host (GitHub Actions vs corporate GitLab CI) — follows wherever the private repo is
  provisioned; the gate *logic* (fetch pinned tarball → schema + `--dry-run`) is portable either way.
- Precise runbook step ordering for the cutover and the legacy-path retirement.

</decisions>

<specifics>
## Specific Ideas

- **"Like current" transport** = the existing manual copy (SCP/SSH) from the corporate side to the
  server. The change this phase delivers is **provenance and review** (the copied file is a merged,
  reviewed, CI-passed repo commit), NOT the transport. This is a deliberate scope reduction versus
  the roadmap's literal "pull or published artifact" — the server stays dumb.
- **Dev/build never touches real config** — the public app repo's gitignore of delivery config is
  preserved; `release.yml` and the slim tarball carry no config (Hard Rule 2).
- The **automatic fallback** rides on Phase 20's directory-presence mode switch (D-01): presence of
  `deliveries.d/` selects the new path; absence or resolution failure falls back to the legacy
  single file — the fallback needs no new operator-facing config knob.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & design (authoritative)
- `.planning/REQUIREMENTS.md` — **CONF-04** and **QUAL-07** full text (Phase 21 items), the
  **"Design Decisions (2026-07-09 operator discussion)"** section, and the **Out of Scope** table.
- `.planning/ROADMAP.md` §"Phase 21: Private Config Repo + CI + CODEOWNERS + Production Cutover" —
  goal + the 4 numbered Success Criteria (what must be TRUE). Note the SC2 per-team-owner wording is
  reconciled by D-08 (central VM-team stewardship) and SC3 pull/artifact wording by D-01 (manual
  copy of a reviewed commit).
- `.planning/roadmap-v1.6-v2.0.md` — forward-roadmap origin of CONF-04 / QUAL-07 and milestone
  sequencing rationale.
- `.planning/phases/20-config-language-loader-matrix/20-CONTEXT.md` — the loader decisions this
  phase builds on, especially **D-01** (directory-presence mode switch — the fallback rides on this)
  and **D-10** (`--dry-run` error/warning surfacing — the CI gate's engine).

### Existing config surface (what to extend / preserve)
- `delivery_config.schema.yaml` — the JSON Schema the CI gate validates the resolved effective
  config against (role unchanged from Phase 20).
- `delivery_config.example.yaml` — committed reference shape; `contacts.example.yaml` /
  `deliveries.d/` example twin from Phase 20.
- `run_all.py` §`_load_config` / `--dry-run` — the loader to extend with the automatic dual-source
  fallback (D-04) and source-surfacing (D-05); the CI gate invokes `--dry-run` here.
- `scripts/generate_delivery_matrix.py` — names+owner matrix, published as the CI/PR artifact (D-07).

### Deploy / release / transport patterns to mirror
- `.github/workflows/release.yml` — produces the **slim release tarball** the config-repo CI pins
  and fetches (D-06); also the guarantee that build carries no config (forbidden-path + credential
  scan) that D-02 relies on.
- `scripts/update_from_github.sh` — existing versioned-release + atomic-swap deploy pattern (the
  transport model the server already uses; the manual copy in D-01 sits alongside this).
- `RUNBOOK.md` — deploy layout, `shared/` config location, and the "Files safe to edit without
  developer involvement" table (`shared/delivery_config.yaml`) — this table and the SSH-edit
  guidance MUST be updated by the cutover so the reviewed-repo flow becomes the documented path.

### Cross-cutting constraints
- `CLAUDE.md` — **Hard Rule 1** (no live Tenable pulls; the CI `--dry-run` gate is pre-auth — safe
  in CI without creds, D-07); **Hard Rule 2** (aggregate-only PII / config never in the public repo,
  governs D-02 and the private-vs-public repo split); "Delivery Configuration" and "Execution Model"
  sections.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `run_all.py:_load_config()` (Phase 20 directory-mode loader) — the automatic dual-source fallback
  (D-04) and active-source logging (D-05) extend this; `--dry-run` surfacing (D-10) is the CI engine.
- `.github/workflows/release.yml` — the slim-tarball release the config-repo CI pins and fetches
  (D-06); its forbidden-path + credential-scan steps are the model for "build carries no config."
- `scripts/update_from_github.sh` — versioned release + atomic-swap + health-check transport already
  running on the server; the manual config copy (D-01) coexists with it.
- `scripts/generate_delivery_matrix.py` — the CI/PR review artifact (names+owner, no addresses).

### Established Patterns
- Config path is `ROOT_DIR / "delivery_config.yaml"`, symlinked from `shared/` in prod
  (`/opt/vuln-reporting/shared/`). Directory-mode discovery resolves relative to that same location;
  the copied reviewed config lands there (server layout is Claude's discretion, e.g. `shared/config/`).
- `scheduler.py` hot-reloads config in daemon mode — the fallback + directory mode must work under
  reload, not just one-shot.
- Fail-loud-at-startup + `--dry-run` (Phase 20 D-10) is the surfacing pattern the CI gate and the
  source-selection logging extend.

### Integration Points
- **New (corporate-side, private repo, NOT the public app repo):** CODEOWNERS, the CI workflow, and
  the `contacts.yaml` + `deliveries.d/` config tree live in the private repo. The public app repo is
  unchanged except possibly docs.
- `run_group()` (sole executor) consumes each resolved group dict unchanged — internal identifiers
  are not renamed (Out of Scope, carried from Phase 20).
- Phase 21 depends on Phase 20's loader, `--dry-run` gate, and matrix script already existing.

</code_context>

<deferred>
## Deferred Ideas

- **Distributed per-team CODEOWNERS ownership** — delegating each `deliveries.d/<team>.yaml` to a
  distinct team owner. The 1:1 file structure (D-08) is built to support this, but review authority
  is centralized to the VM team for now; activate delegation later if the VM team chooses. Not this
  phase.
- **Automated server-side pull or published-artifact fetch** — explicitly rejected for this cutover
  (D-01: the operator wants the manual corporate→server copy retained and the server kept dumb).
  Could be revisited in a future milestone if the server is allowed outbound git/artifact access.

</deferred>

---

*Phase: 21-private-config-repo-ci-codeowners-production-cutover*
*Context gathered: 2026-07-09*
