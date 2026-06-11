---
phase: 11-documentation
verified: 2026-05-20T20:00:00Z
status: passed
score: 5/5
overrides_applied: 0
---

# Phase 11: Documentation — Verification Report

**Phase Goal:** A non-author operator can find everything they need to deploy, upgrade, and run the suite — a root README orients newcomers, DEPLOYMENT.md is the authoritative install/upgrade/rollback guide for the v1.2 tarball workflow, and RUNBOOK.md is rescoped to day-to-day operations with a ready-to-use cron schedule

**Verified:** 2026-05-20T20:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Repo root has a new README.md covering what/who/quickstart/prominent DEPLOYMENT.md link | VERIFIED | README.md exists at repo root; lines 33–47 contain quickstart pointer and documentation map table with DEPLOYMENT.md and RUNBOOK.md links |
| 2 | DEPLOYMENT.md is the authoritative tarball install/upgrade guide with all required elements | VERIFIED | All 11 required elements confirmed present (see DOC-02 detail below) |
| 3 | RUNBOOK.MD rewritten from scratch, scoped to operations only, old install content removed | VERIFIED | Negative grep for "RHEL 9 Server Deployment", "Fresh Install", "git clone", "dnf install" returns no matches; DEPLOYMENT.md pointer at lines 8 and 25–29 |
| 4 | RUNBOOK.MD includes "Operational cron schedule" section with warm_cache.py cron line, run-due cron line, and log-rotation guidance | VERIFIED | Section present at line 363; warm_cache timing rules at lines 395–411; run-due reference at lines 381–387; logrotate config example at lines 422–433 |
| 5 | deploy/crontab.example ships working drop-in cron schedule with warm-cache ≥30 min before earliest group, never near midnight, with cd prefix | VERIFIED | Line 48: `15 6 * * * cd /opt/vuln-reporting/current && /opt/vuln-reporting/current/.venv/bin/python -m scripts.warm_cache …`; both timing rules explained in comments (lines 32–44); run-due every 5 min at line 61 |

**Score:** 5/5 truths verified

---

## DOC-01: README.md

**File:** `README.md` (repo root)
**Status:** PASS

| Check | Evidence |
|-------|----------|
| Exists at repo root | Confirmed |
| States what the suite does | Lines 3–9: tagline + description paragraph |
| States who it's for | Lines 12–27: three-audience breakdown (Operations, Management, Executive Leadership) |
| Quickstart pointer | Lines 32–37: "To install… see DEPLOYMENT.md / For day-to-day… see RUNBOOK.md" |
| Prominent DEPLOYMENT.md link | Lines 33 and 44: linked in quickstart section and documentation map table |
| RUNBOOK link present | Lines 36 and 45: linked in quickstart and documentation map |
| Does NOT duplicate install procedures | Confirmed — no install steps, no CLI commands, no credential config in README |

---

## DOC-02: DEPLOYMENT.md

**File:** `DEPLOYMENT.md` (repo root)
**Status:** PASS

| Required Element | Evidence |
|-----------------|----------|
| System requirements | Lines 45–79: OS, Python 3.10+, WeasyPrint packages, SELinux, disk |
| Install from release tarball (NOT git clone) | Lines 82–164: 8-step tarball procedure; explicit "git clone is NOT a supported production install path" at lines 84–88 |
| `shared/.env` credential config including `GITHUB_RELEASE_REPO` | Lines 170–218: `shared/.env` location; `GITHUB_RELEASE_REPO=owner/repo` at line 202 |
| Verify via `run_all.py --dry-run` | Lines 224–234: dedicated "Validate configuration" sub-section |
| `update_from_github.sh` update procedure | Lines 268–338: `--check`, `--version`, `--rollback`, `--list`, `--force`, `--skip-restart` |
| Prominently placed rollback one-liner | Lines 13–25: blockquote at top of document, before Table of Contents — "Emergency rollback — run this if an upgrade misbehaves" |
| Troubleshooting section | Lines 344–419: 5 named failure scenarios with resolution steps |
| On-disk `/opt/vuln-reporting/{current,releases,shared}` layout diagram | Lines 422–455: ASCII tree showing all three top-level dirs |
| Schema migration note | Lines 463–483: dedicated section explaining operator-managed config and diff procedure |
| D-04-08 sensitive-data checklist | Lines 486–539: 9-item checklist with `example.invalid` at lines 526–528 |
| Uses `current/.venv` interpreter (NOT flat `/opt/vuln-reporting/.venv`) | `${RELEASE_DIR}/.venv` at lines 137–139; `.venv/bin/python` relative to `cd /opt/vuln-reporting/current` at lines 229, 241 |
| GITHUB_RELEASE_REPO in `shared/.env` | Line 202: `GITHUB_RELEASE_REPO=owner/repo` in credential template |

---

## DOC-03: RUNBOOK.MD Rewrite

**File:** `RUNBOOK.MD` (repo root — uppercase extension)
**Status:** PASS

| Check | Evidence |
|-------|----------|
| Scoped to operations only (header/audience) | Lines 1–6: "Scope: Day-to-day operations — how to run and use an already-deployed suite" |
| Old install content GONE: "RHEL 9 Server Deployment (Fresh Install)" | Negative grep confirmed absent |
| Old install content GONE: "git clone" | Negative grep confirmed absent |
| Old install content GONE: "dnf install" | Negative grep confirmed absent |
| "Installation & Upgrades" section points to DEPLOYMENT.md | Lines 22–30: dedicated section with two DEPLOYMENT.md links |
| Day-to-day operations section | Lines 34–278: add/remove recipients, add groups, change schedules, manual triggers, delivery log queries |
| Scheduler management section | Lines 280–360: start/stop/restart, hot-reload behavior, log commands |
| Runtime troubleshooting section | Lines 437–672: 7 named failure scenarios |
| File reference section | Lines 674–773: project layout, editable files, output paths, key log files |
| Paths use `shared/` + `current/` layout | Lines 39, 45–46, 59, 215, 339–340 etc. consistently reference `/opt/vuln-reporting/shared/` and `/opt/vuln-reporting/current/` |

---

## DOC-04: Operational Cron Schedule Section in RUNBOOK.MD

**Status:** PASS

| Check | Evidence |
|-------|----------|
| Section exists | "Operational Cron Schedule" heading at line 363 |
| warm_cache.py cron line reference | Lines 389–411: dedicated "Warm-cache cron line" sub-section with timing rules |
| `scheduler.py --mode run-due` reference | Lines 380–387: "How cron-based scheduling works" sub-section |
| Log rotation guidance | Lines 413–433: logrotate config example for `.cron.log` files |
| References `deploy/crontab.example` | Line 370: linked as `[deploy/crontab.example](deploy/crontab.example)` with install command |

---

## DOC-05: deploy/crontab.example

**File:** `deploy/crontab.example`
**Status:** PASS

| Check | Evidence |
|-------|----------|
| File exists | `ls /d/Projects/vuln-reporting/deploy/crontab.example` confirmed |
| warm-cache line scheduled ≥30 min before earliest group (07:00) | Line 48: `15 6 * * *` (06:15) — 45 minutes before 07:00 earliest group |
| warm-cache line away from midnight | 06:15 satisfies Rule B; comment at lines 37–43 explains the date-rollover hazard |
| Comment explains Rule A (≥30 min) | Lines 32–36: "TIMING RULE A — schedule >=30 minutes before your earliest report group" |
| Comment explains Rule B (never near midnight, cache-folder local-date reason) | Lines 37–43: "TIMING RULE B — NEVER schedule near midnight … Cache folders are named by server LOCAL DATE" |
| warm-cache line has `cd /opt/vuln-reporting/current &&` prefix | Line 48: `cd /opt/vuln-reporting/current &&` present; comment at lines 45–47 explains why (warm_cache imports project-root modules, cron's default CWD is home) |
| warm-cache line uses `current/.venv` interpreter | Line 48: `/opt/vuln-reporting/current/.venv/bin/python` |
| `scheduler.py --mode run-due` runs every 5–10 min | Line 61: `*/5 * * * *` — every 5 minutes |
| run-due line uses `current/.venv` interpreter | Line 61: `/opt/vuln-reporting/current/.venv/bin/python` |

**Checkpoint fix verification:** The `cd /opt/vuln-reporting/current &&` prefix on the warm-cache cron line (commit `daf24bd`) is present and the comment correctly explains it — `warm_cache.py` uses plain `from config import ...` without self-anchoring `sys.path`, so it requires CWD to be the project root. `scheduler.py` self-anchors with `sys.path.insert(0, str(Path(__file__).resolve().parent))` at line 51, so its run-due cron line correctly omits the `cd` prefix.

---

## Cross-Link Integrity

| Link | From | To (linked text) | File on disk | Resolves? |
|------|------|-----------------|-------------|-----------|
| README → DEPLOYMENT.md | README.md:33 | `DEPLOYMENT.md` | `DEPLOYMENT.md` | YES |
| README → RUNBOOK.md | README.md:36 | `RUNBOOK.md` | `RUNBOOK.MD` | WARNING (see below) |
| README → RUNBOOK.md (table) | README.md:45 | `RUNBOOK.md` | `RUNBOOK.MD` | WARNING (see below) |
| DEPLOYMENT.md → RUNBOOK.md | DEPLOYMENT.md:9 | `RUNBOOK.md` | `RUNBOOK.MD` | WARNING (see below) |
| RUNBOOK.MD → DEPLOYMENT.md | RUNBOOK.MD:8 | `DEPLOYMENT.md` | `DEPLOYMENT.md` | YES |
| RUNBOOK.MD → DEPLOYMENT.md (section) | RUNBOOK.MD:28 | `DEPLOYMENT.md` | `DEPLOYMENT.md` | YES |
| RUNBOOK.MD → deploy/crontab.example | RUNBOOK.MD:370 | `deploy/crontab.example` | `deploy/crontab.example` | YES |

**Cross-link case warning:** README.md (×2) and DEPLOYMENT.md (×1) link to `RUNBOOK.md` (lowercase `.md`), but the actual file is `RUNBOOK.MD` (uppercase extension). On Windows NTFS (development environment), both names resolve to the same inode — confirmed by `stat`. On a Linux deployment server with a case-sensitive filesystem, these links would be broken. GitHub's web renderer is also case-sensitive and would render broken links.

This is a cosmetic/documentation quality issue, not an operational blocker — operators on Linux will be reading these files directly from the filesystem or via terminal, not clicking rendered Markdown links. The content itself is complete and correct.

---

## Anti-Pattern Scan

Scanned README.md, DEPLOYMENT.md, RUNBOOK.MD, and deploy/crontab.example for debt markers (TBD, FIXME, XXX) and stub indicators.

| File | Finding | Classification |
|------|---------|---------------|
| All four files | No TBD, FIXME, or XXX markers | Clean |
| DEPLOYMENT.md:495, 519 | "placeholder values" — instructional text in D-04-08 checklist | Not a stub (contextually correct usage) |
| DEPLOYMENT.md:210, 415 | `GITHUB_TOKEN=ghp_xxxx` — example credential placeholder in template | Expected (template placeholder, not code stub) |

No debt markers found.

---

## Human Verification Required

### 1. Linux Cross-Link Case Sensitivity

**Test:** On a Linux server (ext4), render or view the cross-links from README.md and DEPLOYMENT.md to RUNBOOK.md.

**Expected:** `RUNBOOK.md` link fails on a case-sensitive filesystem because the file is named `RUNBOOK.MD`. To fix: either rename `RUNBOOK.MD` to `RUNBOOK.md` or update all three linking files to use `RUNBOOK.MD`.

**Why human:** The verification environment is Windows NTFS where both case variants resolve to the same inode. A Linux render (GitHub web UI, `grip`, or `mdformat`) is needed to confirm whether this manifests as a broken link for end users.

### 2. Cron Smoke Test (Linux box)

**Test:** Install `deploy/crontab.example` as the `vuln-reports` user on a Linux server. Confirm the 06:15 warm-cache job fires and exits cleanly; confirm the `*/5` run-due job fires and exits cleanly.

**Expected:** Both cron lines execute without errors. `warm_cache.cron.log` and `run-due.cron.log` contain expected output.

**Why human:** Cannot execute cron jobs in the verification environment. This is a post-merge operator step, not a gap in the documentation itself.

---

## Gaps Summary

No gaps blocking goal achievement.

The cross-link case mismatch (`RUNBOOK.md` vs `RUNBOOK.MD`) is a quality warning that may produce broken links in GitHub's rendered Markdown or on a Linux filesystem, but does not prevent a non-author operator from using the documentation — the content is complete and all operational instructions are accurate.

The cron smoke test is an expected human step; the crontab content itself is verified correct (timing, interpreter path, `cd` prefix, comments).

---

## Conclusion

**Phase 11 goal: ACHIEVED.**

All five ROADMAP success criteria are satisfied:

1. README.md orients newcomers with what/who/quickstart and prominent links — VERIFIED
2. DEPLOYMENT.md is the authoritative v1.2 tarball install/upgrade/rollback guide with all 11 required elements — VERIFIED
3. RUNBOOK.MD is rewritten and scoped narrowly to operations; old install content is confirmed absent — VERIFIED
4. RUNBOOK.MD includes the "Operational Cron Schedule" section with both cron lines and logrotate guidance — VERIFIED
5. `deploy/crontab.example` is a working drop-in crontab with correct timing, `cd` prefix, `current/.venv` interpreter, and both timing rules explained — VERIFIED

**v1.2 milestone documentation (DOC-01 through DOC-05): COMPLETE.**

The one open item (cross-link case sensitivity) is a cosmetic fix recommended before the v1.2 tag but does not block the milestone.

---

_Verified: 2026-05-20T20:00:00Z_
_Verifier: Claude (gsd-verifier)_
