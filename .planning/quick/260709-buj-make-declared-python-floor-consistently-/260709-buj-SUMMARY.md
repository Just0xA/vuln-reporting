---
quick_id: 260709-buj
title: Make declared Python floor consistently 3.12
date: 2026-07-09
status: complete
commits: [b538e09]
---

# Summary — Python floor consistently 3.12

Resolved the split floor claim (pyproject/CONTRIBUTING said 3.12; CLAUDE.md/templates said 3.10+) — decision "3.12 everywhere" — the last doc-consistency fix before v1.5.0.

## Changed (b538e09)
- CLAUDE.md + .planning/PROJECT.md tech-stack line: "Python 3.10+" → "3.12+" (PROJECT.md kept in sync so a GSD regen won't revert CLAUDE.md).
- Dropped the "- [ ] 3.10" checkbox from the 3 PR templates (fix/feature/enhancement); 3.12 / 3.13+ retained.

## Already correct (untouched)
pyproject.toml `requires-python = ">=3.12"`, .python-version 3.12, CONTRIBUTING.md 3.12.

## Verified
All authoritative sources now read 3.12: pyproject / CLAUDE.md / PROJECT.md / CONTRIBUTING / templates.

## Left as-is (out of scope, not shipped)
Frozen `.planning/research/*`, `.planning/phases/18-*`, STATE.md history rows (historical records). `.planning/codebase/STACK.md` still cites 3.10+ — stale codebase-map intel, internal/export-ignored; refresh via `/gsd:intel` when convenient.
