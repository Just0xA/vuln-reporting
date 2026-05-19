# Technology Stack — v1.2 Server Update and Install

**Project:** Vulnerability Management Reporting Suite
**Milestone:** v1.2 Server Update and Install
**Researched:** 2026-05-19
**Scope:** NEW infrastructure only. Existing Python stack (pyTenable, pandas, WeasyPrint, etc.) is validated and locked; this file covers only what v1.2 adds or must assume.

> **Verification note:** External web/API tools were unavailable during this research session.
> All GitHub Actions version claims are drawn from training data (cutoff August 2025).
> **The operator MUST verify every pinned version before committing `.github/workflows/release.yml`.**
> Verification method: `gh release list -R actions/checkout` (and equivalents) on any machine with `gh` CLI.

---

## Summary: What v1.2 Adds to the Stack

| Category | Addition | Reason |
|----------|----------|--------|
| GitHub Actions | `actions/checkout` | Workflow needs repo checkout |
| GitHub Actions | `softprops/action-gh-release` | Create release + upload tarball asset |
| Shell tooling | `curl`, `tar` (assumed present) | `update_from_github.sh` asset download + extract |
| Shell tooling | `jq` (conditional) | Parse GitHub API JSON for latest-release detection in `--check` mode |
| Shell tooling | `gh` CLI (optional alternative) | Simpler GitHub API calls in `--check` mode; operator choice |
| Python deps | None new | `warm_cache.py` reuses existing fetchers; no additions to `requirements.txt` |
| Documentation tooling | None | Skip markdown linters for v1.2 |

---

## GitHub Actions

### `actions/checkout`

**Recommended pin:** `actions/checkout@v4`

**Why v4 not v3:**
- v4 uses Node.js 20 (Actions runtime default as of mid-2023). v3 uses Node 16, which GitHub deprecated and began warning on.
- v4 is the current stable major. GitHub's own starter workflows all reference v4.
- Pin by major tag (`@v4`) rather than full SHA for this workflow. Rationale: the release workflow is low-security-impact (it only reads the repo and uploads a tarball to a GitHub Release), so SHA pinning's primary benefit — supply-chain attack protection — is lower-value here than in CI workflows that run untrusted code. If the security team mandates SHA pins across all workflows, pin to the SHA of the v4.x.x release used at commit time.

**Confidence:** MEDIUM — v4 was current and stable at knowledge cutoff (August 2025). Verify `gh release list -R actions/checkout` for any newer major before committing.

---

### `softprops/action-gh-release` vs `actions/create-release` + `actions/upload-release-asset` vs `gh release create`

**Recommendation: `softprops/action-gh-release@v2`**

**Why not `actions/create-release` + `actions/upload-release-asset`:**
- Both are officially archived/unmaintained by GitHub (archived 2022). They still run but receive no updates. Using archived actions in new workflows is an anti-pattern.

**Why not `gh release create` via `run:` step:**
- Viable and shell-portable, but requires constructing the tarball path in a prior step and passing it through as a shell variable — more glue steps, more surface for quoting bugs. `softprops/action-gh-release` handles the asset glob and release-creation in a single declarative step.

**Why `softprops/action-gh-release@v2`:**
- v2 is the current stable major (v1 is Node 16). Community-standard action for this purpose — appears in GitHub Docs examples, star count ~4k+ as of mid-2025.
- Single step: create release + set body + upload one or more asset globs. Supports `workflow_dispatch` inputs and `draft:` / `prerelease:` flags.
- Tag-driven trigger (`on: push: tags: ['v*']`) + `workflow_dispatch` both work with no extra config.

**Recommended step pattern:**
```yaml
- uses: softprops/action-gh-release@v2
  with:
    tag_name: ${{ github.ref_name }}
    name: "${{ github.ref_name }}"
    files: dist/vuln-reporting-${{ github.ref_name }}.tar.gz
    generate_release_notes: true
```

**Confidence:** MEDIUM — v2 was current stable at knowledge cutoff. Verify `gh release list -R softprops/action-gh-release`. If v2 is unavailable for any reason, the `gh release create` shell fallback is always viable.

---

### Workflow trigger design

```yaml
on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:
    inputs:
      tag:
        description: 'Release tag (e.g. v1.2.0)'
        required: true
```

`workflow_dispatch` allows re-running the release workflow against an existing tag without re-pushing it — useful for recovering from a failed upload without creating a new tag.

---

## Shell Tooling Assumptions (`update_from_github.sh`)

The update script runs on the production Linux host. Assumptions about what is present:

| Tool | Assumption | Notes |
|------|------------|-------|
| `curl` | Present on all RHEL/CentOS/Debian targets | Standard; do NOT assume `wget` is a drop-in (flag behavior differs) |
| `tar` | Present | GNU tar with `-xzf` support |
| `jq` | Present OR explicitly required | Needed for `--check` (parse GitHub Releases API JSON to detect latest version). If operator cannot guarantee `jq`, implement `--check` with `python3 -c` one-liner using stdlib `json` instead — Python is always present at `/opt/vuln-reporting/.venv/bin/python`. |
| `gh` CLI | Optional / not assumed | Better ergonomics for GitHub API calls but cannot be assumed on air-gapped or minimal servers. The script MUST NOT require `gh`. |
| `systemctl` | Present | Target is systemd (confirmed by `deploy/vuln-reports.service`). Script uses `systemctl stop/start vuln-reports` around swap. |
| `ln -sfn` | Present | Atomic symlink swap for `/opt/vuln-reporting/current → releases/vX.Y.Z`. |

**Decision: use `python3 -c` for JSON parsing in `--check`** rather than requiring `jq`. The `.venv` Python is always present at `/opt/vuln-reporting/.venv/bin/python3`; calling it for a 3-line stdlib JSON parse avoids adding a system package dependency.

```bash
# Preferred: no jq dependency
LATEST=$(curl -sf "https://api.github.com/repos/ORG/vuln-reporting/releases/latest" \
  | /opt/vuln-reporting/.venv/bin/python3 -c \
    "import sys,json; print(json.load(sys.stdin)['tag_name'])")
```

If `jq` IS present (operator installs it), an alternative `--check` path using `jq -r .tag_name` is fine as a documented option.

---

## `warm_cache.py` — No New Python Dependencies

`scripts/warm_cache.py` reuses existing infrastructure:

- `tenable_client.get_client()` — authentication, already in `tenable_client.py`
- `data.fetchers.fetch_vulnerabilities()` / `fetch_assets()` — parquet caching already implemented at `data/fetchers.py:184,192`
- `rich` — progress bar, already in `requirements.txt`
- `python-dotenv` — `.env` loading, already in `requirements.txt`

**No additions to `requirements.txt`.** The script is a standalone entry point that calls existing functions; it has no unique import requirements.

Entry point pattern:
```python
if __name__ == "__main__":
    import argparse
    # --date, --dry-run flags
```

---

## `.gitattributes` `export-ignore`

No new tooling needed. `.gitattributes` is a plain text file parsed by Git itself during `git archive`. The workflow's tarball build step uses `git archive`:

```bash
git archive --format=tar.gz --prefix=vuln-reporting/ \
  -o dist/vuln-reporting-${TAG}.tar.gz HEAD
```

`export-ignore` paths to include in `.gitattributes`:
- `.planning/` — internal project planning artifacts
- `docs/` — calculation runbooks (operator doesn't need them at runtime)
- `ref/` — reference material
- `tests/` — test suite
- `.github/` — workflows not needed on the server
- `*.md` at root level (README excluded — keep it; DEPLOYMENT.md keep it; exclude `RUNBOOK.MD` only if it's superseded by DEPLOYMENT.md, but keeping it is safer)
- `scripts/smoke_*.py` — dev-only smoke tests

**Note on README and DEPLOYMENT.md:** Keep both in the tarball. The operator benefits from having them on the server for reference. Only exclude dev-specific files.

---

## Documentation Tooling Decision: Skip for v1.2

**Recommendation: No markdown linter added.**

Rationale:
- `README.md` and `DEPLOYMENT.md` are operator-facing prose, not structured data. Linting rules (line length, heading hierarchy) add friction without delivering correctness guarantees that matter for an internal tool.
- No CI pipeline exists (GitHub Actions is being added only for release builds, not PR checks). A linter with no enforcement point is useless.
- The project has no pre-commit hooks, no `.flake8`, no formatter config. Adding a markdown linter would be the first dev-tooling commitment — out of scope for a deployment milestone.
- **If introduced later:** `markdownlint-cli2` (Node, no config file required for basic rules) is the lower-friction option vs `remark` (needs a plugin chain). But defer entirely until a dev-tooling phase is explicitly planned.

---

## GitHub Actions Workflow — Pinning Strategy

**Guidance for `release.yml`:**

```yaml
# Pin by major tag (acceptable for low-risk release workflow)
- uses: actions/checkout@v4
- uses: softprops/action-gh-release@v2

# If SHA pinning is mandated, resolve at commit time:
# actions/checkout SHA for v4.x.x as of ~Aug 2025: check via
#   gh api repos/actions/checkout/releases/latest --jq .tag_name
#   then: gh api repos/actions/checkout/git/refs/tags/<tag>
```

**Permissions block required** (GITHUB_TOKEN must have release-write):
```yaml
permissions:
  contents: write
```

Without `contents: write`, `softprops/action-gh-release` will fail with a 403 when attempting to create the release.

---

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Release action | `softprops/action-gh-release@v2` | `actions/create-release` + `actions/upload-release-asset` | Both archived/unmaintained since 2022 |
| Release action | `softprops/action-gh-release@v2` | `gh release create` in a `run:` step | Works but requires more shell glue; declarative step is cleaner |
| JSON parsing in shell | `python3 -c` stdlib | `jq` | `jq` cannot be assumed on minimal servers; Python is always present |
| Markdown linter | (none) | `markdownlint-cli2`, `remark` | No enforcement point in v1.2; adds friction without value |
| Tarball builder | `git archive` | Custom `tar` exclude list | `git archive` + `.gitattributes` is the idiomatic approach; no separate exclude maintenance |

---

## Confidence Assessment

| Claim | Confidence | Reason |
|-------|------------|--------|
| `actions/checkout@v4` is current stable major | MEDIUM | Known stable at Aug 2025 cutoff; verify before commit |
| `softprops/action-gh-release@v2` is current stable major | MEDIUM | Known stable at Aug 2025 cutoff; verify before commit |
| `actions/create-release` is archived | HIGH | Archived status confirmed in GitHub docs as of early 2023 |
| No new Python deps for `warm_cache.py` | HIGH | Script reuses existing imports; verified against `requirements.txt` |
| `curl`/`tar` present on RHEL/Debian | HIGH | Universal on any standard Linux install |
| `jq` cannot be assumed | HIGH | Minimal RHEL installs omit it; safer to use Python stdlib |
| `gh` CLI cannot be assumed on server | HIGH | Server-side install requires explicit package setup; script must not depend on it |
| `permissions: contents: write` required for release action | HIGH | GitHub Actions GITHUB_TOKEN default is read-only since 2023 |

---

## Operator Verification Checklist

Before committing `release.yml`, run these on any machine with `gh` auth:

```bash
# 1. Confirm actions/checkout latest major
gh release list -R actions/checkout --limit 5

# 2. Confirm softprops/action-gh-release latest major
gh release list -R softprops/action-gh-release --limit 5

# 3. If SHA-pinning required, resolve SHA for chosen tag
gh api repos/actions/checkout/git/refs/tags/v4 --jq .object.sha
gh api repos/softprops/action-gh-release/git/refs/tags/v2 --jq .object.sha
```
