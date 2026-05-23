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

> The two 2026-05-14 deploy todos (`deploy-ops-scripts-and-runbook-warm-cache-update-from-github`, `shrink-server-footprint-exclude-dev-only-files`) were **DELIVERED by v1.2** (Phases 7–11). Moved to `.planning/todos/completed/`.
