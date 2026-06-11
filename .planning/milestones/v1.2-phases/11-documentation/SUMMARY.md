# Phase 11 — Documentation: Planning Summary

Final phase of the v1.2 milestone. Two documentation plans, sequenced across two waves because RUNBOOK.md's install pointer must link to a DEPLOYMENT.md that already exists.

## Wave table

| Wave | Plan | Deliverables | Reqs | Autonomous |
|------|------|--------------|------|------------|
| 1 | 11-01-PLAN.md | `README.md` + `DEPLOYMENT.md` | DOC-01, DOC-02 | No (human-verify checkpoint) |
| 2 | 11-02-PLAN.md | rewritten `RUNBOOK.md` + `deploy/crontab.example` | DOC-03, DOC-04, DOC-05 | No (human-verify checkpoint) |

11-02 `depends_on: [11-01]` — RUNBOOK's "Installation & Upgrades" pointer links to DEPLOYMENT.md, which 11-01 creates. No `files_modified` overlap between the plans, but the cross-link forces wave 2.

## Requirement → plan → verification matrix

| Req | Plan | Deliverable | Verification |
|-----|------|-------------|--------------|
| DOC-01 | 11-01 | `README.md` | `test -f README.md`; `grep -q DEPLOYMENT.md` (cross-link); human-check orientation-only scope |
| DOC-02 | 11-01 | `DEPLOYMENT.md` | Ten-section `grep -qF` gate; rollback one-liner present; `GITHUB_RELEASE_REPO` present; git-clone documented out-of-scope; human-check prose vs. shipped Phase 7/9/10 behavior |
| DOC-03 | 11-02 | `RUNBOOK.md` | Six-section grep gate; `grep -qF DEPLOYMENT.md`; negative grep proving RHEL-fresh-install + git-clone removed; human-check operations scope |
| DOC-04 | 11-02 | `RUNBOOK.md` cron section | `## Operational Cron Schedule` present; references `crontab.example`; warm_cache + run-due lines + log-rotation guidance |
| DOC-05 | 11-02 | `deploy/crontab.example` | File exists with warm_cache + run-due lines; `midnight` + `30 min` timing comments; `/opt/vuln-reporting/current` path; human-check timing sanity |

All five DOC requirements covered. No unplanned source items; no phase split needed (pure Markdown deliverables, well within context budget).

## Executor notes (handoffs)

1. **DEPLOYMENT.md inherits + modernizes RUNBOOK Section 1 install content; RUNBOOK loses Sections 1–2.** 11-01 pulls the WeasyPrint system-package list and credential/verify content out of the old RUNBOOK Section 1 into DEPLOYMENT.md, but REPLACES the git-clone/scp deploy step with the v1.2 release-tarball workflow. 11-02 then deletes Sections 1 (RHEL fresh install) and 2 (cron-as-install) from RUNBOOK entirely, leaving only a pointer to DEPLOYMENT.md. The two plans must not both try to own install content — DEPLOYMENT.md is the single authoritative install source after wave 1.

2. **Cross-link contract.**
   - README → DEPLOYMENT.md (quickstart pointer) and README → RUNBOOK.md (operations pointer).
   - RUNBOOK → DEPLOYMENT.md (install pointer) and RUNBOOK → deploy/crontab.example (cron section).
   - DEPLOYMENT.md → scripts/update_from_github.sh + GITHUB_RELEASE_REPO.
   Within 11-02, sequence Task 1 (RUNBOOK) and Task 2 (crontab.example) so both link targets exist before the checkpoint; DEPLOYMENT.md already exists from wave 1.

3. **Pre-existing systemd venv-path inconsistency (flag, do not fix here).** `deploy/vuln-reports.service:42` runs `/opt/vuln-reporting/.venv/bin/python`, but `update_from_github.sh` builds a per-release `.venv` under `current/`. The crontab.example uses `/opt/vuln-reporting/current/.venv/bin/python` (the per-release venv the updater actually creates) with a comment noting the older-install fallback. The service-file mismatch is out of scope for this docs phase — surface it for a follow-up, do not block.

4. **No live `delivery_config.yaml` is committed**, so there is no concrete earliest-group time to read. crontab.example assumes a 07:00 earliest group (matching the CLAUDE.md "Executive Team" sample) and schedules warm-cache at 06:15, with a comment instructing the operator to adjust both to their own config. The two encoded hazards: warm-cache ≥30 min before the earliest group, and never near midnight (cache folders are local-date-named).

5. **TDD is OFF; no code to `bash -n`.** Verification is structural: section-presence greps, file-existence checks, cross-link checks, and negative greps (proving removed content is gone), plus a human-verify checkpoint per plan for prose accuracy.

6. **Case-sensitivity RUNBOOK check.** Before the rewrite, confirm only one `RUNBOOK.md` exists (no stale case-variant) so the rewrite doesn't leave a duplicate.
