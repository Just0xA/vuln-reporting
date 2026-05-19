# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1-4 (shipped 2026-05-08) — see [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- ✅ **v1.1 PDF Chrome Redesign** — Phases 5-6 (shipped 2026-05-13) — see [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- **v1.2 Server Update and Install** — Phases 7-11 (in progress)

## Phases

<details>
<summary>✅ v1.0 Modular Reporting Framework (Phases 1-4) — SHIPPED 2026-05-08</summary>

- [x] Phase 1: Module Render Contract (3/3 plans) — completed 2026-05-05
- [x] Phase 2: ReportComposer Upgrades (5/5 plans) — completed 2026-05-06
- [x] Phase 3: Board Summary Module Migration (7/7 plans, incl. gap closure 03-07) — completed 2026-05-07
- [x] Phase 4: YAML Config and Regression Cutover (4/4 plans) — completed 2026-05-08

Quick tasks: `rag-cell-width-shrink` (2 iterations) — Phase 03 UAT cover-layout fix.

Full archive: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md). Requirements traceability: [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md). Retrospective: [`RETROSPECTIVE.md`](RETROSPECTIVE.md).

</details>

<details>
<summary>✅ v1.1 PDF Chrome Redesign (Phases 5-6) — SHIPPED 2026-05-13</summary>

- [x] Phase 5: PDF Chrome Foundation (4/4 plans) — completed 2026-05-13
- [x] Phase 6: Cover Redesign + Board Summary Integration (5/5 plans + UAT cycle) — completed 2026-05-13

UAT cycle extended chrome to `composed_report` so any future metric module inherits the chrome with zero per-slug Python.

Full archive: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md). Requirements traceability: [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md). Audit: [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md).

</details>

### v1.2 Server Update and Install (Phases 7-11)

- [ ] **Phase 7: Foundations** — `.gitattributes` export-ignore rules + updated systemd service unit
- [ ] **Phase 8: Warm Cache** — `scripts/warm_cache.py` standalone pre-fetch job with cron-friendly logging
- [ ] **Phase 9: Release Automation** — `.github/workflows/release.yml` producing slim, validated release tarballs
- [ ] **Phase 10: Update Script + Symlink Layout** — `scripts/update_from_github.sh` with full install/update/rollback lifecycle
- [ ] **Phase 11: Documentation** — `README.md`, `DEPLOYMENT.md`, RUNBOOK rewrite, `deploy/crontab.example`

### Deferred to future milestones

From the accumulated backlog (v1.0 + v1.1 + v1.2):

- **GEN-01/02** — Migrate `management_summary` and `ops_remediation` to the module render contract (they would inherit chrome for free once migrated, since chrome is wired through `ReportComposer`).
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04** — Per-batch `enrich_vulns_with_assets` cache, midnight cache crossover, log rotation, tag-typo detection.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **composed_report output filename disambiguation** — per-group basenames (slugified `report_title`, `output_basename:` YAML field, or slugified group name). Captured during v1.1 once multiple composed groups became plausible.
- **Cosmetic janitorial** — `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants (`run_all.py:76,90`); Phase 3 deprecated aliases `_PDF_RAG_STRIP_TEMPLATE` / `_build_rag_strip_page`.
- **pyTenable upgrade + `assets_v2()` migration** — pin is `pyTenable==1.5.2`; latest is `1.9.1` (2026-04-09). See [Backlog section](#backlog) for detail and recommended sequencing.

**Candidate next phase (awaiting milestone assignment):**

- **Phase: Operator Remediation Report v2 — Modular, Priority-Driven**
  Successor to (or replacement for) the current `ops_remediation` slug. Realized as a `composed_report`-style bundle of operator-focused metric modules driven by the priority model captured in [`notes/operator-remediation-priority-model.md`](notes/operator-remediation-priority-model.md). Each module renders into the four-channel contract (PDF section, Excel tab, email panel, analyst drill-down).
  - **External-Facing Priority Queue** — findings on assets where `Location ∈ {External, DMZ}` OR `ipv4` is outside RFC 1918 private space; ranked by VPR × asset count.
  - **Risk-Flag Hot List** — findings where VPR = 10, `vpr_v2.on_cisa_kev = true`, or CVE matches the Threat Intel watchlist (sourced from `config/threat_intel_priority_cves.yaml`; see seed [`threat-intel-tag-migration.md`](seeds/threat-intel-tag-migration.md) for the future Tenable-tag source).
  - **Aged Critical / High** — operator cut of the existing aged-vulns logic, scoped to Critical + High open > 90 days.
  - **Remediation Action Grouping** — group open findings by `plugin.id` (or by patch reference where applicable) so a single fix action shows the full finding-and-host footprint it would resolve.
  - **Fix-Type Breakdown** — counts by patch / configuration change / workaround / disable-service / no-fix-available / vendor-unpatched (Pillar 2 of the operator info model). Depends on research question Q-001 (fix-type reliability) before final classifier shape.
  - **Per-Environment Routing** — operator groups receive only the rows scoped to the environments they own (`Environment ∈ {Dev, Non-Prod, Prod}`), driven by YAML `filters:` and `modules:` per group.
  - **Backlog item this consumes:** GEN-01/02 — migrating `ops_remediation` onto the module contract (would inherit chrome for free).
  - **Cross-references:** `notes/operator-remediation-priority-model.md`, `seeds/threat-intel-tag-migration.md`, `research/questions.md` Q-001.

## Phase Details

### Phase 7: Foundations
**Goal**: The repository correctly defines its release artifact boundary so no future tag can produce a tarball with dev-only content
**Depends on**: Nothing (first phase of v1.2)
**Requirements**: FOOT-01, FOOT-02, FOOT-03, FOOT-04, UPDATE-15
**Success Criteria** (what must be TRUE):
  1. Maintainer runs `git archive --format=tar.gz HEAD | tar -tz` and sees no `.planning/`, `docs/`, `ref/`, `tests/`, `.github/`, `CLAUDE.md`, `RUNBOOK.md`, `CONTRIBUTING.md` paths in the listing
  2. Maintainer runs the same preview and confirms `scripts/warm_cache.py` and `scripts/update_from_github.sh` ARE present while `scripts/setup_github_labels.py` and `scripts/smoke_*` are absent
  3. `deploy/vuln-reports.service` references `/opt/vuln-reporting/current/` as `WorkingDirectory` and `/opt/vuln-reporting/shared/.env` as `EnvironmentFile`; the obsolete `Documentation=` line pointing to `RUNBOOK.md` is removed
  4. Gitignored runtime paths (`data/trend/`, `data/cache/`, `output/`, `logs/`) have belt-and-suspenders `export-ignore` lines so accidentally-staged files cannot enter a tarball
**Plans**: TBD

### Phase 8: Warm Cache
**Goal**: Operators can decouple Tenable fetch latency from report-run wall time by running a pre-fetch job on a cron schedule
**Depends on**: Nothing (independent of release infrastructure; can run against existing live install)
**Requirements**: CACHE-01, CACHE-02, CACHE-03, CACHE-04, CACHE-05, LOG-01, LOG-03
**Success Criteria** (what must be TRUE):
  1. Operator runs `python -m scripts.warm_cache` and finds `data/cache/<YYYY-MM-DD>/*.parquet` files in the same shape `run_all.py` consumes, with no new Python dependencies required
  2. Operator passes `--dry-run` and sees what would be written without any files being created; passes `--verbose` and sees fetch progress; passes `--prune-stale` and prior-day cache folders are removed; passes `--date YYYY-MM-DD` and the target date folder is written
  3. A concurrent daemon + cron invocation cannot observe a partial parquet file (writes go to a temp file and are promoted via `os.replace`)
  4. `logs/warm_cache.log` is written from the first run and rotates automatically; exit code is 0 on success and non-zero on auth or API failure
  5. Every invocation produces at minimum a "started" line (with full argv) and a "completed" line (success or failure) in `logs/warm_cache.log`; usage errors log the real failure reason before exiting non-zero
**Plans**: TBD

### Phase 9: Release Automation
**Goal**: Pushing a version tag produces a clean, validated slim release tarball on GitHub that the update script can download and trust
**Depends on**: Phase 7 (correct `.gitattributes` must exist before any tag is pushed)
**Requirements**: CI-01, CI-02, CI-03, CI-04, CI-05, CI-06, CI-07
**Success Criteria** (what must be TRUE):
  1. Maintainer pushes a `v*` tag and a GitHub Release is created with a `vuln-reporting-vX.Y.Z-slim.tar.gz` asset and a matching `*.sha256` checksum file as a second asset
  2. Maintainer triggers the workflow via `workflow_dispatch` with a version input and the same release assets are produced
  3. A tag with `-rc`, `-beta`, or `-alpha` in the suffix is automatically marked as prerelease on GitHub
  4. The workflow's tarball content assertion step fails the build (no upload occurs) if forbidden paths (`.planning/`, `.env`, `data/trend/`) or non-placeholder credential values appear in the tarball
  5. The workflow file declares `permissions: contents: write` explicitly so the default read-only `GITHUB_TOKEN` is not relied upon
**Plans**: TBD

### Phase 10: Update Script + Symlink Layout
**Goal**: An operator on a fresh or existing server can install, update, and roll back the suite using a single shell script without hand-curating files
**Depends on**: Phase 9 (real release tarball must exist for end-to-end testing)
**Requirements**: UPDATE-01, UPDATE-02, UPDATE-03, UPDATE-04, UPDATE-05, UPDATE-06, UPDATE-07, UPDATE-08, UPDATE-09, UPDATE-10, UPDATE-11, UPDATE-12, UPDATE-13, UPDATE-14, LOG-02
**Success Criteria** (what must be TRUE):
  1. Operator runs `--check` and gets an exit code of 0 (up-to-date), 1 (update available), or 2 (error) without any files being downloaded or changed; operator runs `--list` and sees installed releases with the active one marked
  2. Operator runs `--version vX.Y.Z` and the script downloads the tarball, validates its SHA256, extracts into `releases/vX.Y.Z/`, runs `pip install -r requirements.txt` into a per-release `.venv`, validates via `python run_all.py --dry-run`, atomically swaps the `current` symlink via `ln -sfn`, and restarts the systemd unit
  3. After a successful upgrade the script prints the exact rollback one-liner the operator can paste; operator runs `--rollback` and the `current` symlink re-points to the previous release; the systemd unit restarts cleanly
  4. A failed download, partial extraction, or failed `--dry-run` validation leaves no half-built release directory and does not swap the `current` symlink; if the unit is not active 10 seconds after a swap the script auto-rolls back
  5. `shared/` paths (`.env`, `delivery_config.yaml`, `logs/`, `output/`, `data/cache/`, `data/trend/`) are symlinked into each release directory so configuration and runtime state survive the upgrade; the script refuses to operate when `current` is missing or does not point inside `releases/`
  6. Every invocation writes a "started" line and a "completed/failed-because" line to `logs/update.log`; `GITHUB_TOKEN` env var is respected for authenticated API calls
**Plans**: TBD

### Phase 11: Documentation
**Goal**: A non-author operator can deploy, operate, upgrade, and roll back the suite using only the shipped documentation
**Depends on**: Phases 7-10 (describes final behavior, not provisional behavior)
**Requirements**: DOC-01, DOC-02, DOC-03, DOC-04, DOC-05
**Success Criteria** (what must be TRUE):
  1. Root `README.md` exists and tells a first-time visitor what the suite does, who it is for, and where to find the quickstart (link to `DEPLOYMENT.md`)
  2. `DEPLOYMENT.md` covers system requirements, tarball-only install path, credential configuration, `--dry-run` verification, the update procedure, a prominently-placed rollback one-liner, troubleshooting, an on-disk layout diagram, schema-migration note, and the D-04-08 sensitive-data pre-release checklist
  3. `RUNBOOK.md` is narrowly scoped to day-to-day operations (scheduler management, log locations, common runtime errors); all install/deployment content has moved to `DEPLOYMENT.md`
  4. `RUNBOOK.md` includes an "Operational cron schedule" section with ready-to-use cron lines for `warm_cache.py` and `scheduler.py --mode run-due` with rotation guidance
  5. `deploy/crontab.example` ships a working cron schedule with `warm_cache.py` placed at least 30 minutes before the earliest report group and not near midnight
**Plans**: TBD

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Module Render Contract | v1.0 | 3/3 | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades | v1.0 | 5/5 | Complete | 2026-05-06 |
| 3. Board Summary Module Migration | v1.0 | 7/7 | Complete | 2026-05-07 |
| 4. YAML Config and Regression Cutover | v1.0 | 4/4 | Complete | 2026-05-08 |
| 5. PDF Chrome Foundation | v1.1 | 4/4 | Complete | 2026-05-13 |
| 6. Cover Redesign + Board Summary Integration | v1.1 | 5/5 | Complete | 2026-05-13 |
| 7. Foundations | v1.2 | 0/TBD | Not started | — |
| 8. Warm Cache | v1.2 | 0/TBD | Not started | — |
| 9. Release Automation | v1.2 | 0/TBD | Not started | — |
| 10. Update Script + Symlink Layout | v1.2 | 0/TBD | Not started | — |
| 11. Documentation | v1.2 | 0/TBD | Not started | — |

## Backlog

(Backlog section preserved across milestone closes — accumulates 999.x items if any.)

### pyTenable upgrade + asset export v2 migration

**Captured:** 2026-05-14 (research pass; see `feedback_gsd_artifact_reuse` memory for the explore conversation)
**Status:** Deferred — slot before or as part of the Operator Remediation Report v2 phase, or whenever we need a v2-only asset attribute.

**Context.** Project pins `pyTenable==1.5.2` (`requirements.txt:2`). Asset exports go through `tio.exports.assets()` → v1 endpoint `POST /assets/export`. Tenable shipped a v2 endpoint at `POST /assets/v2/export`, and pyTenable now exposes it as `tio.exports.assets_v2()`. Latest pyTenable is **1.9.1** (released 2026-04-09) — four minor releases ahead of our pin. Both v1 and v2 methods coexist in 1.9.x, so adoption is additive (no forced migration, no Tenable deprecation pressure today).

**Why upgrade.** The v2 endpoint unlocks fields directly relevant to the Operator Remediation Report v2 work (see [`notes/operator-remediation-priority-model.md`](notes/operator-remediation-priority-model.md)):

- `types` filter — first-class include/exclude of Tenable WAS (Web App Scanning) assets in operator reports.
- ACR (Asset Criticality Rating) and AES (Asset Exposure Score) attributes — could replace or supplement the RFC-1918 heuristic for "externally-facing" detection.
- `since` filter — returns assets updated/deleted/terminated since a timestamp regardless of state; enables incremental fetches instead of full exports each run.
- `include_resource_tags` — explicit toggle, cleaner than v1's implicit behavior.

Secondary benefits: Python 3.13 / 3.14 compatibility, Marshmallow → Pydantic refactor of the Exports API (1.7.0 + finalized in 1.9.0), and T1 Export APIs added in 1.8.2 if Tenable One ever scopes in.

**Risk to test.** The upgrade itself is the bigger risk than the v2 swap. The Marshmallow → Pydantic refactor in 1.7.0 / 1.9.0 could shift:

- Parameter validation error shape (low impact — our code doesn't catch SDK validation errors specifically).
- Response-iterator behavior — pyTenable historically yields dicts; verify Pydantic v2 doesn't return model instances that would break the DataFrame construction in `data/fetchers.py` (≈ lines 488, 949, 984, 1113) or anywhere downstream.
- Schema field renames from the 1.8.2 / 1.8.3 schema-correction commits.

Both `tio.exports.vulns()` and `tio.exports.assets()` call sites need end-to-end re-testing on the upgrade, not just assets.

**Recommended sequencing (do not couple).**

1. **Platform upgrade, no behavior change.** Bump `pyTenable` to latest 1.9.x; keep calling `assets()` and `vulns()` as today. Re-run full report suite against real Tenable; confirm no drift. Independently valuable (security, Python compat).
2. **`assets_v2()` adoption.** Swap asset-export call sites in `data/fetchers.py` to `assets_v2()`, surface the new fields into the assets parquet, and update the Operator Remediation priority model to consume ACR/AES where they beat the RFC-1918 heuristic. Add `since`-based incremental fetches if/when the warm-cache story justifies it.

Coupling the platform upgrade with the new-feature adoption couples two distinct risk profiles into one debug surface.

**Sources.**
- [pyTenable on PyPI](https://pypi.org/pypi/pytenable/json)
- [pyTenable Exports API docs (1.9.1)](https://pytenable.readthedocs.io/en/stable/api/io/exports.html) — `assets_v2()` method reference
- [Tenable Export Assets v2 API reference](https://developer.tenable.com/reference/export-assets-v2)
- [pyTenable CHANGELOG.md](https://github.com/tenable/pyTenable/blob/main/CHANGELOG.md)
