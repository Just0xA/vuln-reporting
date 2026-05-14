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
---

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
