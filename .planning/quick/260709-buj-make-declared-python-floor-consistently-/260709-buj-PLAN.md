---
quick_id: 260709-buj
title: Make declared Python floor consistently 3.12
date: 2026-07-09
status: complete
---

# Make declared Python floor consistently 3.12 (decision: "3.12 everywhere")

Last doc-consistency fix before tagging v1.5.0. Resolves the contradiction where
pyproject/CONTRIBUTING said 3.12 while CLAUDE.md/PR-templates said 3.10+.

## Edits (5)
1. `CLAUDE.md` — "**Tech stack**: Python 3.10+" → "3.12+".
2. `.planning/PROJECT.md` — same line (the GSD `project-start` source block), so a
   future regen won't revert CLAUDE.md.
3-5. `.github/PULL_REQUEST_TEMPLATE/{fix,feature,enhancement}.md` — delete the
   "- [ ] 3.10" checkbox (keep 3.12 / 3.13+).

## Unchanged (already 3.12)
pyproject.toml (`requires-python = ">=3.12"`), `.python-version`, CONTRIBUTING.md.

## Left as-is (out of scope, not shipped)
Frozen `.planning/research/*`, `.planning/phases/18-*`, and STATE.md history rows
still say "3.10+" (historical records). `.planning/codebase/STACK.md` still cites
3.10+ — stale codebase-map intel, internal/export-ignored; refresh via `/gsd:intel`
when convenient. None ship in the tarball.
