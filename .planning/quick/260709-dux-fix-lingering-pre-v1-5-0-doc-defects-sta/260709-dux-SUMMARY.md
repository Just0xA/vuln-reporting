---
quick_id: 260709-dux
title: Fix lingering pre-v1.5.0 doc defects (STACK.md 3.12 + ar2 placeholders)
date: 2026-07-09
status: complete
commits: [f9e71a6]
---

# Summary — final pre-v1.5.0 doc cleanup

Internal `.planning/` docs only, no code. Cleared the last lingering defects before shipping v1.5.0.

## Fixed (f9e71a6)
- `.planning/codebase/STACK.md` (×2): "Python 3.10+" → "3.12+"; line 8 now cites the real floor source (`pyproject requires-python >=3.12`, `.python-version`) instead of the stale "CLAUDE.md declares 3.10+".
- `.planning/STATE.md`: filled the 260709-ar2 row's placeholder `(docs commit)` → `f4f8b4c, 11e71f5`.
- `260709-ar2-SUMMARY.md`: frontmatter `commits: [<docs-commit>]` → `[f4f8b4c, 11e71f5]`.

## Verified
No `Python 3.1[0-1]` floor claim remains in any live doc; zero `(docs commit)`/`<docs-commit>` placeholders in `.planning/`.

## Left as-is (correctly frozen history)
`.planning/research/*`, `phases/18-*`, STATE history rows mentioning "3.10+" — historical records, not rewritten.
