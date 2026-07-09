# Phase 21: Private Config Repo + CI + CODEOWNERS + Production Cutover - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-09
**Phase:** 21-private-config-repo-ci-codeowners-production-cutover
**Areas discussed:** Prod consumption/transport, Dual-source fallback, CI validator sourcing, CODEOWNERS/shared-file ownership

---

## Production consumption & transport (CONF-04 SC3)

| Option | Description | Selected |
|--------|-------------|----------|
| Git pull on host | Cron/systemd job clones/pulls the private repo into `shared/config/`; loader reads from there. Needs outbound git + deploy key. | |
| Published artifact | CI builds a validated config bundle as a release asset; host fetches it (mirrors `release.yml` + `update_from_github.sh`). | |
| Symlink to checkout | Working checkout on host; config path symlinks into it; cutover = repoint symlink. | |
| **Manual copy (like current), no git sync in build/dev** | Files authored/reviewed in the private corporate repo, then copied to the server as today; build/dev never syncs config to git. | ✓ |

**User's choice:** "like current — the files will be created on the corporate side and copied to the server. For build and dev the files should not sync to git."
**Notes:** Chosen over all three offered mechanisms. The server stays dumb (no git/artifact fetch). CONF-04's intent (end untracked hand-edits) is met because the copied file is a merged, reviewed, CI-passed repo commit. Captured as D-01/D-02/D-03; flagged as an intentional deviation from ROADMAP SC3's literal "pull or published artifact."

---

## Dual-source fallback cutover (QUAL-07 SC4)

| Option | Description | Selected |
|--------|-------------|----------|
| Automatic loader fallback | Loader prefers repo-sourced (directory-mode) config; falls back to legacy single file on missing/invalid, logs which source won. | ✓ |
| Operator-flipped switch | Env var / config-path setting selects source; operator flips, keeps legacy as manual revert. | |
| Parallel dry-run parity | Both sources loaded each run; assert identical effective config before delivering from repo-source. | |

**User's choice:** Automatic loader fallback.
**Notes:** Rides on Phase 20 D-01 directory-presence mode switch. Active source must be observable in logs + `--dry-run` (D-04/D-05).

---

## CI validator sourcing (CONF-04 SC2)

| Option | Description | Selected |
|--------|-------------|----------|
| Pinned release tarball | CI fetches the pinned `vuln-reporting` slim release, installs requirements, runs schema + `--dry-run` against merged config. | ✓ |
| pip/git install of app | CI installs the app from the public repo at a git ref, then validates. | |
| Vendored validator | Config repo vendors just schema + a thin validate entrypoint. | |

**User's choice:** Pinned release tarball.
**Notes:** Reproducible, avoids drift from the real loader; pin bumped when loader/schema changes. Gate = schema + full `--dry-run` (pre-auth, no creds); matrix published as PR artifact (D-06/D-07).

---

## CODEOWNERS & shared-file ownership (CONF-04 SC2)

| Option | Description | Selected |
|--------|-------------|----------|
| Central admin owns shared | Per-team files → team; shared files → central platform/security owner (`*`). | |
| Central + originating team | Shared files require central owner AND the driving team. | |
| Defer ownership roster | Lock structure now; fill handles at provisioning. | (partial) |
| **VM team centrally manages all files** | The Vulnerability Management team controls server+code and manages/maintains all delivery files. | ✓ |

**User's choice:** "The Vulnerability Management team controls the server and code. They will centrally manage and maintain the delivery files."
**Notes:** CODEOWNERS structure stays 1:1 with the `deliveries.d/` split (enables future per-team delegation), but every owner entry resolves to the VM team. Reconciles ROADMAP SC2's per-team-owner wording toward central stewardship (D-08/D-09). Concrete VCS handles deferred to repo provisioning via change management (D-10).

---

## Claude's Discretion

- Provenance mechanism for the server config (source-commit-SHA stamp vs checksum/drift check).
- Directory-mode config layout on the server relative to the `shared/` symlink.
- CI host (GitHub Actions vs corporate GitLab CI) — follows the private repo's provisioning.
- Cutover runbook step ordering and legacy-path retirement sequence.

## Deferred Ideas

- Distributed per-team CODEOWNERS ownership (delegating `deliveries.d/<team>.yaml` to distinct team owners) — structure supports it; centralized to VM team for now.
- Automated server-side pull / published-artifact fetch — explicitly rejected for this cutover; revisit if the server is ever allowed outbound git/artifact access.
