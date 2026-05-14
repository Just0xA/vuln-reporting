---
quick_id: 260514-mlk
title: Stop syncing data/trend to GitHub and scrub history
date: 2026-05-14
status: complete
---

## What changed

- Installed `git filter-repo` (2.47.0) under `%APPDATA%\Python\Python314\Scripts\`.
- Pushed pre-rewrite `origin/main` to `origin/backup/pre-trend-scrub-2026-05-14` as a recovery branch (still contains the 3 sensitive JSON files — by design).
- Added `data/trend/` to `.gitignore` (commit `5bdb866`, post-rewrite SHA).
- Ran `git filter-repo --invert-paths` against the 3 trend JSON paths. 230 commits rewritten in 0.13s; `origin` remote auto-detached by filter-repo.
- Re-added `origin`, force-pushed `main` (29fddd0 → 5bdb866) and tags (v1.0 ccf7c07 → d459cd2, v1.1 678d427 → d9fac11).
- New tag `pre-trend-scrub-2026-05-14` pushed (points to the post-rewrite equivalent of the pre-rewrite HEAD).

## Verification

- `git log origin/main -- data/trend/` → empty.
- `git log v1.0 -- data/trend/` → empty.
- `git log v1.1 -- data/trend/` → empty.
- `git log origin/backup/pre-trend-scrub-2026-05-14 -- data/trend/` → 3 commits (backup intact).
- `git ls-files data/trend/` → empty.
- Working tree: `data/trend/` directory removed by filter-repo. Will be regenerated next time `management_summary` runs; `.gitignore` keeps the regenerated files out.

## Side effects

- All commit SHAs from the first appearance of any trend file forward are now different. Any other clone (none reported) would need to re-clone or hard-reset.
- 230 commits rewritten — every commit message and parent ref is preserved; only the file content was scrubbed.
- `origin/main` is now 1 commit ahead of where it was pre-scrub in terms of *new* work (the `.gitignore` change); the rest is a rewrite of the same logical history.

## Outstanding decision — backup branch

`origin/backup/pre-trend-scrub-2026-05-14` still contains the 3 sensitive JSON files. The branch is on GitHub right now. Options:

1. **Leave indefinitely** — branch stays as a long-term recovery handle. Sensitive data remains on GitHub, defeats the scrub.
2. **Delete after confidence window** — run for a few days, confirm nothing references the old SHAs, then `git push origin --delete backup/pre-trend-scrub-2026-05-14`. Recommended.
3. **Delete now** — accept zero rollback safety net in exchange for immediate full scrub.

Until the backup branch is deleted, the scrub is *incomplete* from a data-exposure standpoint.

## Files touched

- `.gitignore` (added `data/trend/`)
- 3 × `data/trend/*.json` (removed from history via filter-repo, removed from working tree as a side effect)
