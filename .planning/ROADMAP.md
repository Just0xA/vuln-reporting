# Roadmap: Vulnerability Management Reporting Suite

## Milestones

- ✅ **v1.0 Modular Reporting Framework** — Phases 1–4 (shipped 2026-05-08) — [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)
- ✅ **v1.1 PDF Chrome Redesign** — Phases 5–6 (shipped 2026-05-13) — [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)
- ✅ **v1.2 Deployment & Self-Update Infrastructure** — Phases 7–11 (shipped 2026-05-22) — [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)
- 📋 **Next milestone** — TBD

## Phases

<details>
<summary>✅ v1.0 Modular Reporting Framework (Phases 1–4) — SHIPPED 2026-05-08</summary>

Full detail: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md)

</details>

<details>
<summary>✅ v1.1 PDF Chrome Redesign (Phases 5–6) — SHIPPED 2026-05-13</summary>

Full detail: [`milestones/v1.1-ROADMAP.md`](milestones/v1.1-ROADMAP.md)

</details>

<details>
<summary>✅ v1.2 Deployment & Self-Update Infrastructure (Phases 7–11) — SHIPPED 2026-05-22</summary>

- [x] Phase 7: Foundations (2/2 plans) — slim-tarball `.gitattributes` boundary + symlink-layout systemd unit
- [x] Phase 8: Warm Cache (2/2 plans) — `scripts/warm_cache.py` atomic pre-fetch
- [x] Phase 9: CI/Release Automation (2/2 plans) — `.github/workflows/release.yml` slim tarball + SHA256
- [x] Phase 10: Install / Update / Rollback (3/3 plans) — `scripts/update_from_github.sh`
- [x] Phase 11: Documentation (2/2 plans) — README, DEPLOYMENT.md, RUNBOOK.md, crontab.example

Full detail: [`milestones/v1.2-ROADMAP.md`](milestones/v1.2-ROADMAP.md)

</details>

## Progress

| Phase                          | Milestone | Plans Complete | Status   | Completed  |
| ------------------------------ | --------- | -------------- | -------- | ---------- |
| 1. Module Render Contract      | v1.0      | 3/3            | Complete | 2026-05-05 |
| 2. ReportComposer Upgrades     | v1.0      | 5/5            | Complete | 2026-05-06 |
| 3. Board Summary Migration     | v1.0      | 7/7            | Complete | 2026-05-07 |
| 4. YAML Opt-out + Regression   | v1.0      | 4/4            | Complete | 2026-05-08 |
| 5. PDF Chrome Foundation       | v1.1      | 4/4            | Complete | 2026-05-13 |
| 6. Cover Redesign + Board Int. | v1.1      | 5/5            | Complete | 2026-05-13 |
| 7. Foundations                 | v1.2      | 2/2            | Complete | 2026-05-19 |
| 8. Warm Cache                  | v1.2      | 2/2            | Complete | 2026-05-19 |
| 9. CI/Release Automation       | v1.2      | 2/2            | Complete | 2026-05-19 |
| 10. Install / Update / Rollback | v1.2     | 3/3            | Complete | 2026-05-19 |
| 11. Documentation              | v1.2      | 2/2            | Complete | 2026-05-20 |

## Backlog

Cross-milestone backlog is tracked in [`PROJECT.md`](PROJECT.md) ("Backlog" / "Deferred to Future Milestones") and [`STATE.md`](STATE.md) ("Deferred Items"). Open items carried past v1.2:

- **GEN-01/02** — Migrate `management_summary` / `ops_remediation` to the module render contract.
- **GEN-03/04** — Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04** — Performance pass (per-batch enrich cache, midnight cache crossover, log rotation, tag-value typo detection).
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports in CLAUDE.md as candidate module bundles.
- **composed_report output filename disambiguation** — per-group basenames for groups using `reports: [composed_report]`.
- **Cosmetic janitorial** — `run_all.py:76,90` stale `_VALID_FREQUENCIES` / `_VALID_REPORTS` constants.
- **Daemon-integrated warm-cache** — fold `scripts/warm_cache.py` into the scheduler daemon as a schedule-derived job (warm ~30 min before the earliest group, computed from `delivery_config.yaml`; warm once before dispatching concurrent same-time groups). Removes the separate cron, the manual ≥30-min timing coupling, the midnight date-rollover footgun, and the cold-cache double-fetch race for same-time groups (`run_all` pre-fetch covers only 2 of the 4 datasets `warm_cache` does). Candidate for v1.3.
- **E2E harness — strengthen Layer 3 module-error detection** — the local E2E suite (`tests/`, added 2026-05-23) asserts `run_group` status + artifact validity but does NOT flag modules that degrade fail-soft. The `aged_vulns_assets` module degrades on the synthetic fixtures because they lack a `business_unit` tag (goal dimension; `Application` is the interim tag while Tenable BU tags are built out). Strengthen by (a) enriching the asset fixtures with the BU/`Application` tag so the module's happy path is exercised, and/or (b) asserting no module-level errors / no ERROR-level logs for groups expected clean.
- **E2E harness — minor follow-ups** — assert the "Excel omitted" email-body note in the oversize-attachment test; reconcile the design spec's SMTP wording (says aiosmtpd; implementation uses a faked `smtplib` transport — RUNBOOK is already correct); migrate the legacy standalone `tests/test_*.py` scripts to pytest discovery (Task 14 of the harness plan, deferred).
- **VTD-01 — Vuln Type Distribution module (App / OS / Hardware)** — candidate phase for the next milestone. New four-channel metric module splitting **open VPR Critical+High** findings into Application / OS / Hardware buckets via the **CPE prefix** (`/a`, `/o`, `/h`) already present in `vulns_df` (`data/fetchers.py:343`). Renders as **three RAG tiles**, one per owning remediation team (App Support+BU, Operations, Data Center), each showing count + % of total + month-over-month delta arrow/color. **Spike 001 done (PARTIAL):** CPE prefix = 99.2% coverage but mis-assigns ~6% of OS-team work, so classifier = **`plugin_family` override → CPE prefix → Unclassified** (config-driven map). Requestor decisions: MS Bulletins → Operations/OS (default), Hardware tile hidden when empty. **Deliverables:** the three-tile module + a `docs/vuln_type_distribution_calculations.md` auditor runbook + a unit-tested classifier (~6% App/OS swing rides on it). **Trend cold-start may be eliminated** by the trend-reconstruction engine (see batch entry below) — reconstruct per-bucket history from `first_found`/`last_fixed` instead of waiting for snapshots. Design record: [`notes/vuln-type-distribution-module.md`](notes/vuln-type-distribution-module.md); spike: [`spikes/001-cpe-coverage-crit-high/`](spikes/001-cpe-coverage-crit-high/).

#### June 2026 report-requests batch + shared substrates

Captured via `/gsd-explore` 2026-06-05. Full landscape, per-report intent, and substrate-first sequencing recommendation: [`notes/report-requests-batch-2026-06.md`](notes/report-requests-batch-2026-06.md). **Recommended: build the substrates (S1/S2) before the report modules** — building any single report first means inventing the trend engine inside it, then refactoring it out from under the others.

Substrates:
- **S1 — Trend substrate (KEYSTONE)** — **Spike 002 reframed this:** Tenable's ~29-day fixed-retention wall means history can't be reconstructed/backfilled, so the substrate is a **snapshot-capture engine** (persist monthly open-counts + in-retention fixed export from now forward); reconstruction serves current-state + last ~29 days only. Cold start is real; must use the reopened-aware two-interval predicate (naive form drops ~19% of findings). Design: [`notes/trend-reconstruction-engine.md`](notes/trend-reconstruction-engine.md); spike: [`spikes/002-trend-reconstruction-lookback/`](spikes/002-trend-reconstruction-lookback/).
- **S2 — Owner/BU segmentation** — group by `Owner` tag category + `Unassigned` catch-all (self-retiring) + analyst alert listing untagged assets. Partially rolled out; same shape as `unscanned_assets` companion.
- **S3 — WAS / External data source** — new `tio.exports.vulns()` Web App Scan fields + public-IP/DMZ scoping; isolated to the External report.

Report modules (thin once S1/S2 exist; #1/#2/#4 entangle **GEN-01** `management_summary` modularization):
- **Accepted & Recast** — current + prev-month ▲▼% infographic; by Owner/BU; uses `severity_modification_type` + `fetch_recast_rules()`. (modularizes a `management_summary` metric)
- **Program Health Overview** — MoM velocity on totals; by Owner/BU. (overlaps `management_summary`)
- **External (Public IP / DMZ)** — external scope = **tagged-external OR computed public IPv4** (dual signal) + analyst flag for mismatches. Needs S3 (WAS) whose **access path is unknown → Spike 003 prerequisite** (unified `tio.exports.vulns()` vs separate `tio.was`). MoM trend (S1). Heaviest/most new-data report.
- **MTTR — REWORK (not review)** — existing `mttr_by_severity_module.py` is a secret rolling ~30-day MTTR (fixed-retention, Spike 002), unweighted mean-of-means, reopened-inflated, no trend, no Owner/BU, legacy email channel. Needs S1 + S2 + honesty fixes + a **resolved-population decision** (exclude reopened/risk-accepted? first-time only?).
- **Vulnerability Density** — open count / total assets, MoM.
- **New vs Remediated** — `first_found`-in-month vs `last_fixed`-in-month; *is* S1 surfaced directly.
- **Reopened Vulnerabilities** — `state==REOPENED` / `resurfaced_date`; build/config regression signal.

> The two 2026-05-14 deploy todos (`deploy-ops-scripts-and-runbook-warm-cache-update-from-github`, `shrink-server-footprint-exclude-dev-only-files`) were **DELIVERED by v1.2** (Phases 7–11). Moved to `.planning/todos/completed/`.
