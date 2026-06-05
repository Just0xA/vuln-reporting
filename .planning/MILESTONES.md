# Milestones

Living record of shipped versions. Each entry summarizes scope, accomplishments, and key outcomes. Full milestone details live in `.planning/milestones/v[X.Y]-ROADMAP.md` and `.planning/milestones/v[X.Y]-REQUIREMENTS.md`.

---

## v1.3 — Trend & Segmentation Substrate

**Status:** In progress (started 2026-06-05)
**Phases:** 2 (12–13) | **Plans:** TBD
**Requirements:** 13 (TREND-01..07, SEG-01..05, DOC-01)

**Goal:** Build the two shared substrates under the June-2026 report batch — a forward-accumulating monthly snapshot mechanism (S1) and an Owner/BU segmentation helper (S2) — so the v1.4 report modules become thin consumers instead of re-inventing trend and segmentation independently.

**Key design constraints (settled by spikes):**
- S1 is snapshot-capture only — Tenable's ~29-day fixed-retention wall forbids backfill (Spike 002). Cold start is real.
- The open-count primitive must use the reopened-aware two-interval predicate; the naive form silently drops ~19% of findings (all REOPENED).
- Snapshots extend the existing `data/trend/` store; no parallel store; `management_summary` must not regress.
- Snapshot payloads are aggregate counts only (D-04-08 PII discipline).
- SEG-03 analyst exception list is operator-facing local output; never committed or emailed.

**Founding analysis:** [`notes/report-requests-batch-2026-06.md`](notes/report-requests-batch-2026-06.md), [`notes/trend-reconstruction-engine.md`](notes/trend-reconstruction-engine.md), [`spikes/MANIFEST.md`](spikes/MANIFEST.md) (Spikes 001–003).

---

## v1.2 — Deployment & Self-Update Infrastructure

**Shipped:** 2026-05-22 (v1.2.0)
**Phases:** 5 (7–11) | **Plans:** 10
**Timeline:** built 2026-05-19 → 2026-05-20; released and field-hardened 2026-05-22 on a Rocky 9 VM
**Git range:** `5c90d9c` (milestone start) → `v1.2.4` (`ce0bcf3`)
**Files changed:** 65 | **LOC delta:** +11,667 / −1,245
**Requirements:** 39/39 phase-verified satisfied

**Delivered:** A production deployment and self-update story for the suite. A non-author operator can install, upgrade, and roll back on a single Linux server from a signed release tarball — no git clone — driven by `scripts/update_from_github.sh`, with a CI pipeline that publishes those tarballs automatically and authoritative deployment docs.

**Key accomplishments (by phase):**
- **Phase 7 — Foundations:** `/opt/vuln-reporting/{current,releases,shared}` symlink layout; `.gitattributes` `export-ignore` boundary defining the slim release tarball; hardened `deploy/vuln-reports.service` systemd unit (`ProtectSystem=strict` + explicit `ReadWritePaths`, runtime-cache `HOME`/`XDG_CACHE_HOME`/`MPLCONFIGDIR`).
- **Phase 8 — Warm Cache:** `scripts/warm_cache.py` pre-fetch so scheduled batches hit `[CACHE HIT]` instead of redundant Tenable exports.
- **Phase 9 — CI / Release Automation:** `.github/workflows/release.yml` — pushing a `v*` tag builds `vuln-reporting-vX.Y.Z-slim.tar.gz` + `.sha256`, blocks forbidden paths, marks `-rc/-beta/-alpha` as prereleases, and publishes a GitHub Release.
- **Phase 10 — Install / Update / Rollback:** `scripts/update_from_github.sh` with `--check`/`--list`/`--version`/`--rollback`/`--force`/`--skip-restart` — SHA256-verified download, per-release venv, shared-path symlinks, atomic `ln -sfn` swap, `.last` breadcrumb, post-swap health check with auto-rollback, and a printed rollback one-liner.
- **Phase 11 — Documentation:** root `README.md`, authoritative `DEPLOYMENT.md` (tarball install/upgrade/rollback), operations-scoped `RUNBOOK.md`, and `deploy/crontab.example`.

**Releases:**
| Tag | Date | Summary |
|-----|------|---------|
| `v1.2.0` | 2026-05-22 | Initial deployment-infrastructure release (milestone ship). |
| `v1.2.1` | 2026-05-22 | Clean-machine deployment-walkthrough fixes: systemd `StartLimit*` moved `[Service]`→`[Unit]` (restart cap was inert), tracked `delivery_config.example.yaml`, `sudo -u vuln-reports` prefixes + paste-safe one-liners, stale Tenable verify text. |
| `v1.2.2` | 2026-05-22 | Updater resolves a versioned `python3` (≥3.10) on RHEL hosts that ship `python3.9`/`python3.11` but no `/usr/bin/python3`; removed the error-masking `2>/dev/null`. |
| `v1.2.3` | 2026-05-22 | Release retention: `--prune` command + `--keep N` and auto-prune on successful install (keep 3); active + `.last` rollback target always preserved. |
| `v1.2.4` | 2026-05-22 | Fixes `rich.errors.LiveError` when concurrent scheduled groups run in daemon mode — per-call `Console` + disable live display on non-TTY. |

**Verification:**
- 5/5 phase verifications passed (Phases 7–11); 39/39 requirements satisfied.
- Milestone audit `v1.2-MILESTONE-AUDIT.md` status: passed (original `gaps_found` closed by quick task `260520-mp4`).
- v1.2.0 → v1.2.4 each validated end-to-end on a real Rocky 9 VM: install, upgrade, rollback, force-overwrite, real-symlink prune (incl. rollback-target preservation), daemon-mode concurrency (no `LiveError`), and live email delivery.

**Notable surprises (all caught on the real RHEL VM, not the Windows dev box):**
- systemd `ExecStart` pointed at a flat `.venv` while the updater builds per-release `current/.venv` (ship-blocker; quick task `260520-a29`).
- `ProtectSystem=strict` made `ReadWritePaths` load-bearing — `management_summary`'s trend-JSON write was denied until `shared/data/trend` was added (`260520-mp4`).
- A normal RHEL host can have versioned Python only, no `python3` command → updater `command not found` under `sudo` (v1.2.2).
- Per-release venvs accumulate unbounded with no GC → `--prune` (v1.2.3).
- APScheduler runs same-time groups in concurrent threads sharing rich's process-global live-display lock → `LiveError` (v1.2.4).
- Two hand-edited `shared/.env` typos (`GITHUB_RELEASE_REPO`, SMTP) caused a 404 and a connection-refused; reinforced "check the VM's `.env` first."

**Archive:**
- [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md) — full phase + plan detail
- [`milestones/v1.2-REQUIREMENTS.md`](milestones/v1.2-REQUIREMENTS.md) — 39-requirement traceability
- [`v1.2-MILESTONE-AUDIT.md`](v1.2-MILESTONE-AUDIT.md) — milestone audit (status: passed)
- Post-release patches (v1.2.1–v1.2.4) tracked in [`STATE.md`](STATE.md) "Quick Tasks Completed".

---

## v1.1 — PDF Chrome Redesign

**Shipped:** 2026-05-13
**Phases:** 2 | **Plans:** 9
**Timeline:** 1 day (same-day discuss → plan → execute → UAT → close)
**Git range:** `0cda7bc` (Phase 5 context capture) → `c8f521d` (Phase 6 closeout)
**Files changed:** 49 | **LOC delta:** +7,305 / −166

**Delivered:** A shared PDF chrome design system applied to every page of every chrome-aware PDF report. The chrome lives in `reports/modules/pdf_chrome.py` and is wired through `ReportComposer` via an optional `pdf_chrome=` constructor kwarg. Two slugs (`board_summary` and `composed_report`) opt into chrome via the `_CHROME_AWARE_SLUGS` allowlist — meaning every future metric module added to a `composed_report` group inherits chrome with **zero per-slug Python**.

**Key accomplishments:**
- **`PdfChrome` utility** ships a single design-system surface: frozen `PdfChromeConfig` dataclass (`title`, `subtitle`, `generated_at`, `header_bg`, `logo_path`, `privacy_label`) feeds a `PdfChrome` class that emits CSS + header HTML + footer-separator HTML. Silent fallback to title-only when `LOGO_PATH` is unset/missing (CHROME-CFG-03, no log spam).
- **`position: fixed` chrome overlays** paint a full-width 15mm header band and a 1px footer separator edge-to-edge on every page. Replaced the initial margin-box approach after UAT revealed empty `@top-*` margin boxes collapse to zero width in WeasyPrint.
- **Cover body trimmed** to `Scope: <value>` subtitle + RAG strip (now headed "Key Performance Metrics"). Inline title, divider, `.cover-meta`, "Generated:" line, "Sections:" line all removed — those moved to chrome.
- **`_CHROME_AWARE_SLUGS` allowlist** is the single source of truth for chrome-kwarg injection. Legacy `management_summary` + `ops_remediation` byte-unchanged across the milestone — `git diff` returns 0 bytes for both.
- **Modular-framework parity:** `composed_report` inherits chrome on the same seam. Dropping a new `*_module.py` into a `reports: [composed_report]` group + `modules:` list gives it full chrome.
- **YAML knobs:** optional `privacy_label:` and `report_title:` per group; both default-safe (`"Confidential"` and the slug's built-in title respectively).
- **Operator-supplied logo** lives at `assets/logo.png` (`.gitignore`'d); `config.LOGO_PATH` resolves to it; silent-fallback if missing.

**Verification:**
- 2/2 phase verifications PASSED (Phase 5 PASS, Phase 6 PASS WITH NOTES)
- 16/16 requirements satisfied (3-source cross-reference clean)
- 37/37 tests green on the v1.1 surface
- Operator visual UAT approved both `board_summary` and `composed_report` renders
- 0-byte diff on `reports/management_summary.py` + `reports/ops_remediation.py` across the milestone

**Notable surprises:**
- **Empty margin boxes collapse in WeasyPrint.** Initial header design painted backgrounds on `@top-left/-center/-right`; empty boxes rendered zero-width, leaving visible gaps. Pivoted to `position: fixed` overlays with negative side offsets — predictable, pixel-perfect.
- **Latent `pdf_subtitle` double-prefix bug in composed_report.** When the cover template was changed to bake "Scope: " into itself, `composed_report` would have rendered "Scope: Scope: Production". Caught during the chrome-parity extension.
- **`_format_scope_subtitle` circular import.** Both consumers are imported via `importlib` from `run_all`, so they can't import the helper back. Inlined the 3-line helper in both. Defer factoring until > 2 consumers.
- **Same-day end-to-end delivery.** Milestone setup → close in 1 day. v1.0 was 4 days; v1.1 was 1 day because the milestone was scoped tight (chrome + one consumer + framework parity) and the v1.0 module contract did most of the heavy lifting.

**Carried to next milestone (acknowledged backlog):**
- composed_report output filename disambiguation (every group writes `composed_report.{pdf,xlsx}` today; needs per-group basenames).
- All v1.0 backlog still open: GEN-01/02, GEN-03/04, PERF-01..04, LEGACY-01, cosmetic janitorial.

**Archive:**
- [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md) — full phase + plan + UAT-cycle details
- [`milestones/v1.1-REQUIREMENTS.md`](milestones/v1.1-REQUIREMENTS.md) — all 16 requirements traceability
- [`v1.1-MILESTONE-AUDIT.md`](v1.1-MILESTONE-AUDIT.md) — aggregated milestone audit (status: passed)

---

## v1.0 — Modular Reporting Framework

**Shipped:** 2026-05-08
**Phases:** 4 | **Plans:** 19 | **Quick tasks:** 1
**Timeline:** 4 days (2026-05-05 → 2026-05-08)
**Git range:** `ea709a1` (Phase 1 first feat) → `028f188` (Phase 4 UAT close)
**Files changed:** 96 | **LOC delta:** +27,072 / −390

**Delivered:** A modular metric-rendering framework where each `BaseModule` subclass renders itself into 4 channels (PDF section, Excel tabs, email panel, analyst drill-down) — proven end-to-end against the Board Summary report's 4 metric modules with backward-compatible delivery to existing recipient groups.

**Key accomplishments:**
- **Module render contract** extended `BaseModule` with three new abstract methods (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) plus three new `ModuleData` fields (`driver_narrative`, `analyst_rows`, `rag_strip`). Empty-data guard pattern codified in CLAUDE.md and exercised by every render method.
- **`ReportComposer` upgrades** added `assemble_email_body()` (per-module HTML panels), `assemble_analyst_workbook()` (per-module Excel tabs + `_Metadata`), unified RAG-strip cover page, and `run_full_pipeline()` orchestrator that emits a typed bundle. D-22 bundle-driven email/analyst routing — no slug allowlists.
- **Board Summary migration** ported all 4 metric modules (`scan_coverage_sla`, `critical_remediation_sla`, `high_risk_assets`, `aged_vulns_assets`) to the new contract. Real-Tenable UAT-confirmed: PDF + standard Excel + analyst Excel + email panels all render correctly; populated and zero-data paths both clean.
- **YAML schema validation** wired `jsonschema` enforcement into every config load (`run_all.py:_load_config`). `_validate_group()` body REPLACED with a thin schema shim (single source of truth). Misconfigured YAML exits non-zero with offending group + field named.
- **`analyst_detail: false` opt-out** plumbed through `run_all.py:run_group()` → `board_summary.run_report()` → `composer.run_full_pipeline(generate_analyst=)`. No new abstractions; existing kwargs only.
- **Cutover smoke** (`scripts/smoke_board_summary_cutover.py`) is a sub-5-second deterministic structural-shape regression bar against 3 committed baselines. `_NoLiveTenable` sentinel hard-guards against accidental live API calls. Baselines store counts + booleans only — no metric values, no row-level data — per D-04-08 PII guard.

**Verification:**
- 4/4 phase verifications PASSED
- 3/3 phase UATs CLOSED (Phase 1 verifier-only; 2/3/4 with explicit UATs at 6/6 and 7/7)
- 38 tests green across 4 suites at milestone close
- 0 DRIFT against committed structural baselines

**Notable surprises:**
- WeasyPrint flex implementation consumes ~33-37mm of phantom space beyond the visible cell-width math in 65.1 — discovered via empirical bisect during a UAT-driven cover-layout fix. Pinned cells at 55mm with documented inline comment.
- Headline metric values drift daily with vulnerability churn — locking them in baselines would create false-positive alerts. D-04-05 was REVISED before Phase 4 planning to structural-only snapshots; visual operator confirmation remains the value-correctness gate.
- pandas 3.0 Copy-on-Write shifted the dtype-replacement semantics for chained-setter patterns. `.loc[:, col]=` preserved float64 where `df[col]=` had replaced it with int64. `.assign()` was the only pattern preserving int64 dtype AND zero ChainedAssignmentError warnings — documented at 3 risk_score sites.

**Carried to v2 (acknowledged backlog):**
- GEN-01/02: Migrate `management_summary` and `ops_remediation` to the new module contract.
- GEN-03/04: YAML-driven module composition (`modules: [...]` lists; `reports.<slug>.modules` map).
- PERF-01..04: per-batch `enrich_vulns_with_assets` cache, per-day cache midnight handling, log rotation, tag-typo detection.
- LEGACY-01: re-evaluate the 6 unbuilt reports listed in CLAUDE.md as candidate module bundles.
- Cosmetic janitorial: `_VALID_FREQUENCIES` / `_VALID_REPORTS` stale constants in `run_all.py:76,90`.
- Deferred design: cover-page redesign (template-based on Report Title; "Generated" + Data Protection Label to footer).

**Archive:**
- [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md) — full phase + plan details
- [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md) — all 24 requirements traceability
