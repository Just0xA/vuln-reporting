---
quick_id: 260514-mlk
title: Stop syncing data/trend to GitHub and scrub history
date: 2026-05-14
---

## Goal

Remove `data/trend/*.json` (3 files) from the GitHub repo and from all git history. Aggregate severity counts and internal tag/owner names are sensitive and must not appear on a public-leaning open-source repo.

## Tasks

1. Install `git filter-repo` (`pip install git-filter-repo`).
2. Tag local pre-rewrite HEAD as `pre-trend-scrub-2026-05-14`; push the current `origin/main` to `backup/pre-trend-scrub-2026-05-14` so a recoverable copy exists.
3. Add `data/trend/` to `.gitignore`; commit.
4. Run `git filter-repo --invert-paths --path data/trend/...` for the three JSON files. This will detach `origin`.
5. Re-add `origin`, force-push `main` and the backup ref/tag.
6. Verify `git log --all --full-history -- data/trend/` is empty and that the GitHub mirror no longer contains these paths in any commit.

## Done

- `git ls-files data/trend/` empty.
- `git log --all -- data/trend/` empty.
- `.gitignore` contains `data/trend/`.
- `origin/main` force-pushed; backup ref present.
