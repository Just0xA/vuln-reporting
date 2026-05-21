---
status: resolved
trigger: "Smoke test on Rocky 9 surfaced real bugs: (1) update_from_github.sh source_env() shell-sources .env and breaks on values with spaces (e.g. SMTP_FROM_NAME), exit 127 — breaks --list/--rollback/--check/--version in production; (2) deploy/vuln-reports.service sets ReadWritePaths but no ProtectSystem, so the write sandbox is a no-op; smoke_test.sh CHECK 1/2 hardcode ProtectSystem=full which does not cover /opt, so the negative control can never fail. Fix the source_env parsing bug; address ProtectSystem hardening with care for matplotlib/WeasyPrint cache dirs."
created: 2026-05-21
updated: 2026-05-21
---

# Debug Session: smoke-deploy-bugs

## Symptoms

- **Expected behavior:**
  - `deploy/smoke_test.sh` on Rocky Linux 9 should pass all 5 checks.
  - CHECK 2 (negative control) should PASS by *correctly blocking* a write to `data/trend` when that path is removed from `ReadWritePaths` (sandbox enforcing).
  - CHECK 3 (`--list`) and CHECK 4 (`--rollback`) should succeed: list both releases with the active marker, and roll back swapping `current` + rewriting `.last`.
- **Actual behavior:**
  - CHECK 2 FAIL: the write SUCCEEDED even with `data/trend` removed from `ReadWritePaths` ("SANDBOX IS NOT ENFORCING").
  - CHECK 3 FAIL: `--list` produced no usable output (both releases reported missing, active marker absent).
  - CHECK 4 FAIL: `--rollback` exit code 127; `current`/`.last` unchanged.
  - CHECK 1 and CHECK 5 PASS.
- **Error messages:**
  - `/opt/vuln-reporting/shared/.env: line 10: Test: command not found` (line 10 = `SMTP_FROM_NAME=Smoke Test`), exit 127.
- **Timeline:** First end-to-end smoke run on a real RHEL-family host (Rocky 9 VirtualBox VM). Never passed on real systemd before — prior validation was Windows-dev-box only.
- **Reproduction:** `sudo bash deploy/smoke_test.sh` (or via `deploy/smoke_bootstrap.sh`) on Rocky 9.

## Root-cause analysis (pre-investigated by orchestrator)

### Bug 1 — `source_env()` shell-sources `.env` (REAL production bug)
`scripts/update_from_github.sh:280-289` `source_env()` runs `. "${INSTALL_ROOT}/shared/.env"`, shell-sourcing the env file. Any value containing a space (e.g. `SMTP_FROM_NAME=Smoke Test`, or production `SMTP_FROM_NAME=Vulnerability Management Reports`) is parsed by bash as `VAR=word command...` → "command not found" → `set -e` aborts before `GITHUB_RELEASE_REPO` is set. Breaks `--list`, `--rollback`, `--check`, `--version` on any realistic install. systemd `EnvironmentFile=` tolerates unquoted spaces; bash `source` does not.
**Fix direction:** parse only the keys the script needs (`GITHUB_RELEASE_REPO`, `GITHUB_TOKEN`) with a safe `KEY=VALUE` reader (split on first `=`, skip comments/blanks, no shell evaluation), instead of sourcing the file.

### Bug 2 — systemd write sandbox is a no-op + smoke negative control can't fail
- `deploy/vuln-reports.service:81-93` sets `NoNewPrivileges`, `PrivateTmp`, `ReadWritePaths` but **no `ProtectSystem`**. Without `ProtectSystem`, `ReadWritePaths` does nothing — the whole FS stays writable; the comment claiming `current/` is read-only is false; the B-01 `data/trend` RWP fix has zero effect.
- `deploy/smoke_test.sh:264,305` CHECK 1/2 hardcode `ProtectSystem=full`, which only protects `/usr`,`/boot`,`/etc` — NOT `/opt`. So the CHECK 2 negative control can never block a `/opt` write.
**Fix direction:** add `ProtectSystem=strict` to the real unit and switch smoke CHECK 1/2 to `strict`. CAUTION: under `strict`, matplotlib (`MPLCONFIGDIR`/`$HOME/.config`) and WeasyPrint (fontconfig `$XDG_CACHE_HOME`/`$HOME/.cache`) cache writes would fail for the `vuln-reports` account (created with `useradd -M`, no home). Must pin `MPLCONFIGDIR`/`XDG_CACHE_HOME`/`HOME` into a writable RWP path (e.g. under `shared/data/cache`) or add those dirs to `ReadWritePaths`. CHECK 1's trivial `json.dump` does NOT exercise this — a real report render does.

## Current Focus

hypothesis: RESOLVED — both root causes confirmed and fixed.
next_action: User to re-run `sudo bash deploy/smoke_test.sh` on the Rocky 9 VM to confirm all 5 checks pass under the new `ProtectSystem=strict` hardening, and to exercise a real report render so matplotlib/WeasyPrint cache writes into `runtime-cache` are validated end-to-end (CHECK 1's json.dump does not cover that path).

## Evidence

- timestamp: 2026-05-21 — Smoke run output: CHECK 1 PASS, CHECK 2 FAIL (sandbox not enforcing), CHECK 3 FAIL (list empty), CHECK 4 FAIL (exit 127, `.env line 10: Test: command not found`), CHECK 5 PASS.
- timestamp: 2026-05-21 — `scripts/update_from_github.sh:282` confirmed `. "${INSTALL_ROOT}/shared/.env"` (shell source).
- timestamp: 2026-05-21 — `deploy/vuln-reports.service` confirmed to have NO `ProtectSystem` directive.
- timestamp: 2026-05-21 — `deploy/smoke_test.sh:264,305` confirmed `ProtectSystem=full` hardcoded in CHECK 1/2 systemd-run.
- timestamp: 2026-05-21 — Fix 1 applied and verified (safe KEY=VALUE env reader replacing shell-source in `update_from_github.sh`).
- timestamp: 2026-05-21 — Fix 2 applied by inspection: `ProtectSystem=strict` + `HOME`/`XDG_CACHE_HOME`/`MPLCONFIGDIR` Environment lines + `runtime-cache` appended to `ReadWritePaths` in the unit; smoke CHECK 1/2 switched `full`→`strict` with runtime-cache + the 3 Environment props (CHECK 2 keeps only `data/trend` out of its RWP so the denial is unambiguous); `runtime-cache` added to smoke `mkdir -p` and DEPLOYMENT.md Step 1 layout + on-disk tree.

## Eliminated

- hypothesis: CRLF line endings in the scripts. ELIMINATED — `git ls-files --eol` shows i/lf w/lf; committed shebang is clean LF.

## Resolution

**root_cause:**
1. **Env parsing (Bug 1):** `source_env()` in `update_from_github.sh` shell-sourced `shared/.env`. Unquoted values with spaces (e.g. `SMTP_FROM_NAME=Smoke Test`) were interpreted by bash as `VAR=word command…`, causing "command not found" + `set -e` abort (exit 127) before `GITHUB_RELEASE_REPO` loaded — breaking `--list`/`--rollback`/`--check`/`--version`. systemd `EnvironmentFile=` tolerates this; bash `source` does not.
2. **Inert sandbox (Bug 2):** the systemd unit set `ReadWritePaths` but no `ProtectSystem`, so the write sandbox was a no-op (whole FS writable). The smoke test hardcoded `ProtectSystem=full`, which does not cover `/opt`, so the CHECK 2 negative control could never block a `/opt` write.

**fix:**
1. **Fix 1 (prior step):** replaced shell-source with a safe `KEY=VALUE` reader that splits on the first `=`, skips comments/blanks, and performs no shell evaluation — reading only the keys the script needs.
2. **Fix 2 (this step):** added `ProtectSystem=strict` to `deploy/vuln-reports.service` and switched smoke CHECK 1/2 from `full` to `strict`. Because `strict` makes `/opt` read-only and the `vuln-reports` account has no home (`useradd -M`), pinned `HOME`, `XDG_CACHE_HOME`, and `MPLCONFIGDIR` to a new writable `shared/data/runtime-cache` path (in `ReadWritePaths`) so matplotlib + WeasyPrint/fontconfig can write their caches. The directory is created at install time (smoke `mkdir -p` and DEPLOYMENT.md Step 1) because a missing `ReadWritePaths` path makes systemd fail namespace setup under `strict`; the `matplotlib/` subdir auto-creates since its parent is writable. CHECK 2 retains runtime-cache + the 3 Environment props so the only denied path is `data/trend` (unambiguous negative control).

**verification:**
- Fix 1 verified earlier in this session (env reader handles spaced values; `--list`/`--rollback` paths reachable).
- Fix 2 verified by inspection at fix time (no systemd on the Windows dev box). Line endings confirmed LF (`git ls-files --eol` → `i/lf w/lf`) so shebangs stay valid on Linux.
- **VM-VERIFIED 2026-05-21 (Rocky 9 VirtualBox):** clean re-run of `sudo bash deploy/smoke_test.sh` → ALL 5 CHECKS PASS, including CHECK 2 negative control now correctly blocking the `data/trend` write under `ProtectSystem=strict`. Real-render probe (matplotlib `savefig` + WeasyPrint `write_pdf`) run via `systemd-run` mirroring the unit's strict sandbox + runtime-cache env → exit 0, "caches written under ProtectSystem=strict", `HOME`/`MPLCONFIGDIR` resolved into `runtime-cache`. Confirms the cache-dir env that CHECK 1's trivial `json.dump` does not exercise. Both bugs fixed and proven in the real target environment.

**files_changed:**
- `scripts/update_from_github.sh` — Fix 1: safe KEY=VALUE env reader (prior step).
- `deploy/vuln-reports.service` — Fix 2: `ProtectSystem=strict`; `HOME`/`XDG_CACHE_HOME`/`MPLCONFIGDIR` Environment lines; `runtime-cache` appended to `ReadWritePaths`.
- `deploy/smoke_test.sh` — Fix 2: `runtime-cache` in `mkdir -p`; CHECK 1/2 `full`→`strict`; runtime-cache + 3 Environment props added to both checks (CHECK 2 keeps `data/trend` out of RWP only).
- `DEPLOYMENT.md` — Fix 2: Step 1 `mkdir -p` adds `data/runtime-cache`; on-disk layout tree shows `runtime-cache/` + `matplotlib/`; added note explaining service-only use, ProtectSystem=strict, and MPLCONFIGDIR auto-creation.
