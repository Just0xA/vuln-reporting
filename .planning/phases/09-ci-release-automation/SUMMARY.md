# Phase 09 — CI/Release Automation: Plan Set Summary

**Wave structure:** Two plans, two waves (09-02 depends on 09-01 placing the insertion marker comment in `release.yml`).

| Plan | Wave | LOC est. | Ships |
|------|------|----------|-------|
| 09-01 | 1 | ~90 | New `.github/workflows/release.yml` — triggers (`push: tags: v*` + `workflow_dispatch.inputs.version`), top-level `permissions: contents: write`, full-history checkout (`fetch-depth: 0`), version resolution + regex validation, prerelease detection (`-rc`/`-beta`/`-alpha`), slim tarball via `git archive --prefix=vuln-reporting-${VERSION}/ -o vuln-reporting-${VERSION}-slim.tar.gz ${VERSION}`, SHA256 sidecar via `sha256sum`, asset upload via `softprops/action-gh-release@v3` with `fail_on_unmatched_files: true`. Pins: `actions/checkout@v6`, `softprops/action-gh-release@v3` (verified 2026-05-19). Leaves a `# Tarball-content assertion step inserted by Plan 09-02` marker between SHA256 and Upload steps. |
| 09-02 | 2 | ~70 | Replaces the marker with an `Assert tarball contents` step that `tar -xzf`s the built tarball into a `mktemp -d`, fails non-zero on any of 12 forbidden paths (`.planning/`, `.env`, `.env.local`, `data/trend/`, `.git/`, `tests/`, `docs/`, `ref/`, `CLAUDE.md`, `RUNBOOK.md`, `CONTRIBUTING.md`, `.github/`), and fails on any `TVM_ACCESS_KEY=` / `TVM_SECRET_KEY=` / `SMTP_PASSWORD=` line whose value is not the literal placeholder from `.env.example` (`your_access_key_here`, `your_secret_key_here`, `your_smtp_password`). Uses `set -euo pipefail`; prints offending paths/lines on failure. |

**Total LOC estimate:** ~160 lines of YAML/bash across one file (`.github/workflows/release.yml`).

**External dependencies:** None — pure GitHub Actions YAML + standard bash + git + tar + sha256sum (all on `ubuntu-latest`).

## Requirement → Verification Traceability

| Req | Description | Plan | Verification |
|-----|-------------|------|--------------|
| CI-01 | `v*` tag push triggers workflow | 09-01 | YAML shape assertion on `on.push.tags`; smoke-tag `v0.0.0-alpha1` runs the workflow end-to-end. |
| CI-02 | `workflow_dispatch` with version input | 09-01 | grep for `workflow_dispatch` + `inputs.version`; manual re-run against existing tag via GitHub UI. |
| CI-03 | Asset named `vuln-reporting-vX.Y.Z-slim.tar.gz` | 09-01 | grep `vuln-reporting-${...}-slim\.tar\.gz`; smoke-tag release page shows the asset. |
| CI-04 | SHA256 sidecar uploaded | 09-01 | grep `.sha256`; smoke-tag release page shows the `.sha256` asset. |
| CI-05 | `-rc`/`-beta`/`-alpha` → prerelease | 09-01 | grep `\-(rc|beta|alpha)`; `softprops/action-gh-release@v3` consumes the boolean step output. |
| CI-06 | Tarball-content assertion gate | 09-02 | Step ordering check (SHA256 < Assert < Upload), all 12 forbidden paths grepped, three credential vars + three placeholder whitelist strings grepped, local `git archive HEAD` extraction sanity check, negative-test human-check with a fake leaked `.env`. |
| CI-07 | Explicit `permissions: contents: write` | 09-01 | Python YAML-shape assertion `d['permissions']['contents'] == 'write'`. |

Every CI-* requirement is covered by at least one automated grep AND at least one runtime check (local-archive dry run or smoke-tag push). No requirement is verified by inspection alone.

## Plan-Checker Outcome (2026-05-19)

**Verdict:** PASS WITH REVISIONS — 0 blockers, 2 warnings, 2 info.

Both warnings fixed in the plan text before commit:

1. **09-01 smoke tag**: Replaced `v0.0.0-test` with `v0.0.0-alpha1`. The `-test` suffix fails the workflow's own version regex `^v[0-9]+\.[0-9]+\.[0-9]+(-(rc|beta|alpha)[0-9.]*)?$`; `-alpha1` matches AND triggers prerelease detection per CI-05.
2. **09-02 credential-scan extraction**: Replaced the underspecified `awk -F: '{print $3}'` directive (which yields `VARNAME=value`, not the bare value) with two unambiguous alternatives — `sed -E 's/^[^:]+:[0-9]+://'` + `cut -d= -f2-`, or a regex-capture approach. Comparison is now explicitly **value-only**.

Info-level observations (no action taken):
- `.github/` in the assertion list is intentional belt-and-suspenders (Phase 7's `.gitattributes` already excludes it).
- The `grep -E "inputs:\s*$|version:"` automated check is weak but passes correctly.

## Executor Notes

- Plan 09-01 leaves a precise marker comment (`# Tarball-content assertion step inserted by Plan 09-02`) so Plan 09-02 has an unambiguous landing site — do not rename or relocate it during 09-01 execution.
- The full `.gitattributes` exclusion list is NOT duplicated inside the workflow YAML. The workflow trusts Phase 7's boundary; Plan 09-02's assertion is the safety net that catches drift.
- Smoke-tag testing (`v0.0.0-alpha1`) is a one-time post-merge verification; the human-check steps document the cleanup (delete release + tag).
- No Python dependencies added in this phase. The workflow is shell + YAML only.
- The configurable GitHub repo slug (originally flagged as a Phase 9 gate) is **not** a Phase 9 concern — `release.yml` uses `$GITHUB_REPOSITORY` automatically. The configurable slug for `update_from_github.sh --check` is a Phase 10 concern, sourced from `.env` via `GITHUB_RELEASE_REPO`.
