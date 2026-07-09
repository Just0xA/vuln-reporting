---
quick_id: 260709-dux
title: Fix lingering pre-v1.5.0 doc defects (STACK.md 3.12 + ar2 placeholders)
date: 2026-07-09
status: complete
---

# Fix lingering pre-v1.5.0 doc defects

Final cleanup sweep before shipping v1.5.0 — no code, internal `.planning/` docs only.

## Fixes (4)
1. `.planning/codebase/STACK.md:8` — "Python 3.10+ — entire codebase … CLAUDE.md declares 'Python 3.10+'" → 3.12, cite the real floor source (`pyproject requires-python >=3.12`, `.python-version`).
2. `.planning/codebase/STACK.md:79` — Development section "- Python 3.10+." → "3.12+".
3. `.planning/STATE.md` — the 260709-ar2 quick-task row's Commits cell was left as the placeholder `(docs commit)` → real hashes `f4f8b4c, 11e71f5`.
4. `260709-ar2-SUMMARY.md` frontmatter — `commits: [<docs-commit>]` → `[f4f8b4c, 11e71f5]`.

## Left as-is (correctly frozen)
`.planning/research/*`, `.planning/phases/18-*`, and STATE.md history rows that
mention "Python 3.10+" are historical records of past reality — not edited.
`.planning/intel/` is not stood up (intel system disabled); STACK.md is a
`/gsd:map-codebase` prose doc, hand-fixed here.
