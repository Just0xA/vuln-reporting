---
created: 2026-05-14T13:49:26.447Z
title: Shrink server footprint — exclude dev-only files from deployment
area: tooling
files:
  - .planning/
  - docs/
  - ref/
  - tests/
  - scripts/
related:
  - .planning/todos/pending/2026-05-14-deploy-ops-scripts-and-runbook-warm-cache-update-from-github.md
---

> **Related:** the ops-side companion to this work lives in
> `2026-05-14-deploy-ops-scripts-and-runbook-warm-cache-update-from-github.md` —
> warm-cache job, GitHub update script, and RUNBOOK sections. That todo assumes
> the slim release tarball produced here; pick this one up first.

## Problem

The repo currently mixes runtime code with a large amount of material that is only useful for development: `.planning/` (GSD artifacts, ROADMAP, phases, intel), `ref/` (Tenable API reference dumps — gitignored locally but representative of the pattern), `docs/` calculation runbooks, test scripts/fixtures, contribution templates, and scratch scaffolding. When the suite is deployed to the server/endpoint that actually runs the scheduler, none of this needs to ship.

Goals:
- Server install carries only runtime code + configs (the Python packages, `run_all.py`, `scheduler.py`, `templates/`, `delivery_config*.yaml`, `requirements.txt`, `.env.example`).
- GitHub repo keeps everything (docs, planning, references, tests) so the project stays usable as an open-source artifact.
- Mechanism must be repeatable, not a manual "copy these folders" step at deploy time.

## Solution

Options to evaluate (looking for suggestions — discussed in chat, not yet decided):

1. **GitHub Releases with a built artifact**
   - CI workflow on tag push: build a `vuln-reporting-vX.Y.Z.tar.gz` / `.zip` containing only the runtime tree (driven by an explicit allow-list or a `MANIFEST.in`-style include file).
   - Server pulls the release tarball, not `git clone`.
   - Pros: clean separation, immutable versioned artifacts, plays well with open-source distribution. Cons: requires a release process and a build step.

2. **`.gitattributes` `export-ignore`**
   - Mark `.planning/`, `docs/`, `tests/`, `ref/`, `.github/`, etc. with `export-ignore`.
   - `git archive` (or GitHub's "Download source" zip on a release) automatically excludes them.
   - Pros: simplest, no CI required, integrates naturally with GitHub Releases. Cons: only applies to `git archive`/release tarballs, not to `git clone`.

3. **Packaging as a wheel / pyproject `package-data`**
   - Turn the project into a proper installable package; `pip install` only pulls what's declared in `pyproject.toml`.
   - Server runs from a venv with `pip install vuln-reporting==X.Y.Z`.
   - Pros: most "Pythonic", supports private PyPI / GitHub release asset install. Cons: biggest refactor (entry points, package layout, console_scripts for `run_all`/`scheduler`).

4. **Sparse checkout / shallow clone on the server**
   - `git sparse-checkout` to materialize only runtime paths.
   - Pros: keeps `git pull` as the deploy mechanism. Cons: more brittle, server still needs git, easy to drift.

5. **Deploy script that rsyncs an include-list**
   - `scripts/build_deploy_bundle.py` that copies an allow-listed set of paths into `dist/`, optionally tarballs it.
   - Pros: zero infra dependencies. Cons: yet another script to maintain.

Likely recommendation (to validate with user):
- Combine **#2 (`.gitattributes export-ignore`) + #1 (GitHub Releases)** as v1. Cheapest path: add `export-ignore` lines, tag a release, GitHub auto-generates a slim source tarball that the server pulls. Defer #3 (proper packaging) until/unless the project goes open-source publicly and needs `pip install` ergonomics.

Next steps when picked up:
- Inventory which top-level paths are runtime vs dev (write the allow/deny list explicitly).
- Decide deployment mechanism (release tarball vs sparse clone vs wheel).
- Document the chosen approach in `CONTRIBUTING.md` / `README.md` under a "Deployment" section.
- If going the release route: add a `.github/workflows/release.yml` that builds + attaches the artifact on tag push.

---

## Drafts (ready to apply)

### Top-level path inventory

| Path | Runtime? | Notes |
|---|---|---|
| `config.py` | ✅ | SLA constants, severity maps |
| `tenable_client.py` | ✅ | Authenticated TIO client factory |
| `run_all.py` | ✅ | Master runner |
| `scheduler.py` | ✅ | APScheduler daemon |
| `delivery_config.yaml` | ✅ | Live config (may be server-overridden) |
| `delivery_config.schema.yaml` | ✅ | YAML validator |
| `requirements.txt` | ✅ | Pinned deps |
| `data/` | ✅ | `fetchers.py`, trend snapshots — note: `data/cache/` should be runtime-generated, not shipped |
| `delivery/` | ✅ | email sender, templates, log |
| `exporters/` | ✅ | excel/pdf/chart |
| `reports/` | ✅ | All report slugs + modules |
| `templates/` | ✅ | Jinja2 email template |
| `utils/` | ✅ | sla_calculator, tag_helper, formatters |
| `assets/` | ✅ | Logo/branding used in PDFs (verify before deploy) |
| `deploy/` | ✅ | systemd unit, etc. |
| `.planning/` | ❌ | GSD artifacts, ROADMAP, phases |
| `docs/` | ❌ | Calculation runbooks — dev-only |
| `ref/` | ❌ | Tenable API reference dumps (already `.gitignore`d) |
| `tests/` | ❌ | Pytest suite |
| `scripts/` | ⚠️ | Mixed — `setup_github_labels.py` is dev-only; audit before excluding wholesale |
| `logs/`, `output/`, `__pycache__/` | ❌ | Runtime-generated, never ship |
| `CLAUDE.md`, `RUNBOOK.MD`, `CONTRIBUTING.md` | ❌ | Project docs |
| `.github/` | ❌ | Issue/PR templates |

### `.gitattributes` draft

```gitattributes
# Normalize line endings
* text=auto eol=lf

# Exclude dev-only paths from `git archive` / GitHub release source tarballs.
# These stay in the repo (for open-source consumers and dev work) but never
# ship to the server that runs the scheduler.
.planning/         export-ignore
docs/              export-ignore
ref/               export-ignore
tests/             export-ignore
.github/           export-ignore
CLAUDE.md          export-ignore
RUNBOOK.MD         export-ignore
CONTRIBUTING.md    export-ignore
.gitattributes     export-ignore
.gitignore         export-ignore

# Audit before un-commenting — some scripts/ entries may be runtime utilities.
# scripts/           export-ignore
```

### README "Deployment" section draft

```markdown
## Deployment

The repository contains both runtime code and developer-only material
(planning artifacts, documentation, references, tests). Only the runtime
tree needs to land on the server that executes the reports.

### Install from a GitHub Release (recommended)

1. On GitHub, open the latest entry under **Releases**.
2. Download the **Source code (tar.gz)** asset. `.gitattributes` strips
   `.planning/`, `docs/`, `ref/`, `tests/`, `.github/`, and top-level dev
   docs from this tarball automatically — what you get is the slim
   runtime tree.
3. Extract on the server:
   ```bash
   tar -xzf vuln-reporting-vX.Y.Z.tar.gz -C /opt/
   mv /opt/vuln-reporting-* /opt/vuln-reporting
   cd /opt/vuln-reporting
   ```
4. Create the venv and install pinned deps:
   ```bash
   python3.10 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```
5. Copy `.env.example` → `.env` and fill in Tenable + SMTP credentials.
6. Edit `delivery_config.yaml` for the server's recipient groups.
7. Smoke-test:
   ```bash
   .venv/bin/python run_all.py --dry-run
   ```
8. Install the systemd unit from `deploy/vuln-reports.service` (daemon
   mode) or wire `scheduler.py --mode run-due` into cron / Task Scheduler.

### Cutting a release

Maintainers only. Releases are versioned `vMAJOR.MINOR.PATCH`.

```bash
git tag -a v1.2.0 -m "v1.2.0 — <summary>"
git push origin v1.2.0
```

Then on GitHub: **Releases → Draft a new release** → pick the tag →
publish. The auto-generated source tarball respects `.gitattributes`
`export-ignore` rules, so no manual file filtering is needed.

### Why not `git clone` on the server?

The repo carries ~MB of planning, runbooks, references, and tests that
exist purely for development. Cloning ships all of it. Pulling a release
tarball ships only what the scheduler needs to run, keeps `git` off the
server's dependency surface, and pins every box to an explicit version.

### Verifying a release locally

Before tagging, preview exactly what the tarball will contain:

```bash
git archive --format=tar.gz --prefix=vuln-reporting/ HEAD -o /tmp/preview.tar.gz
tar -tzf /tmp/preview.tar.gz | less
```
```

### Apply checklist (when ready to execute)

- [ ] Audit `scripts/` — decide per-file whether each is runtime or dev.
- [ ] Verify `assets/` is required at runtime (logos in PDF render path).
- [ ] Create `.gitattributes` from the draft above.
- [ ] Add a `## Deployment` section to a new `README.md` (none exists yet) using the draft above.
- [ ] Cut a throwaway pre-release tag (`v0.0.1-rc1`), download the tarball, confirm dev paths are absent.
- [ ] Optional: add `.github/workflows/release.yml` to publish a clean artifact on tag push.
