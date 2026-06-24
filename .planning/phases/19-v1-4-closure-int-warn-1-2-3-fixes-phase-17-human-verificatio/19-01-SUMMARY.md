---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "01"
subsystem: security-hardening
status: complete
completed: "2026-06-24"
duration_seconds: 900
tasks_completed: 3
files_modified: 5
tags:
  - security
  - hooks
  - fail-closed
  - path-traversal
  - html-injection
  - pii-guard
dependency_graph:
  requires: []
  provides:
    - "CR-C1: block_tenable_fetch wrapper-recursion guard"
    - "CR-S1: fail-closed on malformed PreToolUse payload"
    - "CR-S2: trend filename path-traversal sanitization"
    - "CR-S3: scan_coverage email HTML-escape on error/owner strings"
    - "CR-S4: owner_supplemental PII output-path guard"
  affects:
    - ".claude/hooks/block_tenable_fetch.py"
    - "data/trend_store.py"
    - "reports/modules/scan_coverage_sla_module.py"
    - "reports/owner_supplemental.py"
    - "tests/test_block_tenable_fetch.py"
tech_stack:
  added: []
  patterns:
    - "Recursive effective_head/script_hit with depth cap for shell wrappers"
    - "re.sub sanitization of filesystem-path-facing strings"
    - "html.escape(str(...), quote=True) at all user-data → HTML interpolation sites"
    - "Path.resolve() + parents check for output-path policy guards"
key_files:
  created:
    - tests/test_block_tenable_fetch.py
  modified:
    - .claude/hooks/block_tenable_fetch.py
    - data/trend_store.py
    - reports/modules/scan_coverage_sla_module.py
    - reports/owner_supplemental.py
decisions:
  - "D-02: .claude/hooks/ committed into the repository — block_tenable_fetch.py now version-controlled"
  - "Wrapper recursion depth-capped at 3 (SHELL_WRAPPERS + PY_INTERPRETERS) to guard against unbounded recursion"
  - "CR-S2 applies inline re.sub rather than _sanitise_tag_for_filename (signature takes category+value; tag_filter is already joined)"
metrics:
  duration: 900
  completed_date: "2026-06-24"
---

# Phase 19 Plan 01: Work-stream-A Security / Fail-Closed Findings Summary

**One-liner:** PreToolUse hook hardened against bash/sh/python -c wrapper bypass (CR-C1), fails closed on malformed JSON (CR-S1); trend filename path-traversal sanitized (CR-S2); scan-coverage email HTML-escaped (CR-S3); owner_supplemental PII output-path guard added (CR-S4).

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 (RED) | Failing regression tests for CR-C1 + CR-S1 | a59bf20 | tests/test_block_tenable_fetch.py |
| 1 (GREEN) | Harden block_tenable_fetch.py wrapper recursion + fail-closed | 20c2d64 | .claude/hooks/block_tenable_fetch.py |
| 2 | Path-traversal + HTML-escape + PII output-path guards | fb0713b | data/trend_store.py, reports/modules/scan_coverage_sla_module.py, reports/owner_supplemental.py |
| 3 | Commit .claude/hooks/ into repository | 20c2d64 | (included in Task 1 GREEN commit — file now tracked) |

## What Was Built

### CR-C1: Wrapper recursion in block_tenable_fetch.py

Added `SHELL_WRAPPERS = {"bash", "sh", "zsh", "dash", "ksh"}` and `_MAX_RECURSE_DEPTH = 3`. Extended `script_hit()` to:

1. When `head` is a shell wrapper and a `-c` flag follows: shlex-tokenize the payload string and recurse into `script_hit()` on the sub-tokens (depth-capped at 3).
2. When `head` is a Python interpreter and `-c` follows: scan the inline code string for guarded module/script names via `_scan_inline_code_for_guarded()`.
3. When `head` is a Python interpreter and `-m` follows: existing module-ref check still fires through the recursive path (unchanged, verified by regression test).

Added `import shlex` for payload re-tokenization.

### CR-S1: Fail-closed on malformed payload

Replaced `sys.exit(0)` in the `except Exception` branch of `main()` with `deny("Blocked: malformed PreToolUse payload — failing closed.")`. The `deny()` helper is the single deny emitter; all failure paths now route through it.

### CR-S2: Trend filename path-traversal sanitization (data/trend_store.py)

Replaced the direct `tag_suffix = tag_filter` assignment with:
```python
tag_suffix = re.sub(r"[^A-Za-z0-9_]", "_", tag_filter).strip("_") or "all_assets"
```
The stored `tag_filter` field inside the JSON snapshot entry retains the raw value.

### CR-S3: HTML-escape in scan_coverage error box

At the error-box `render_email_panel()` site (~L553), both `self.DISPLAY_NAME` and `data.error` are now wrapped in `html.escape(str(...), quote=True)` before interpolation. `import html` was already present at module top.

### CR-S4: PII output-path guard in owner_supplemental.py

Added a fail-fast guard before `output_dir.mkdir()`:
```python
_resolved = output_dir.resolve()
_trend_resolved = (Path(__file__).resolve().parent.parent / "data" / "trend").resolve()
if _resolved == _trend_resolved or _trend_resolved in _resolved.parents:
    raise ValueError(...)
```
Raises `ValueError` naming the `project_pii_rule_is_ai_not_email` policy.

## Verification Results

- `pytest tests/test_block_tenable_fetch.py -q -o addopts=""` → 6 passed
- `pytest tests/test_trend_store.py -q -o addopts=""` → 2 passed (no regressions)
- `git ls-files .claude/hooks/block_tenable_fetch.py` → path returned (file tracked)
- `python -c "import data.trend_store, reports.owner_supplemental; import reports.modules.scan_coverage_sla_module"` → IMPORTS OK
- CR-S4 manual verify: `write_owner_supplemental(..., output_dir=str(trend_path))` raises `ValueError` as expected

## Deviations from Plan

### Task 3 completed within Task 1

Task 3 (commit .claude/hooks/ files) was a git hygiene step. The hook file was staged and committed as part of the Task 1 GREEN commit (20c2d64) — `git add .claude/hooks/block_tenable_fetch.py` was included in that commit. A separate Task 3 commit was not needed since the file was already tracked after Task 1.

No other deviations. Plan executed as written.

## Known Stubs

None. All five security mitigations are fully implemented and verified.

## Threat Flags

No new threat surface introduced. All changes are defensive guards on existing code paths — no new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check

- [x] tests/test_block_tenable_fetch.py exists and has 6 tests passing
- [x] .claude/hooks/block_tenable_fetch.py tracked in git (commit 20c2d64)
- [x] data/trend_store.py contains `re.sub(r"[^A-Za-z0-9_]"` in capture_snapshot
- [x] scan_coverage_sla_module.py contains `_error_esc` and `_name_esc` at error-box site
- [x] owner_supplemental.py contains `data/trend` + `ValueError` guard before mkdir
- [x] All 3 task commits exist in git log

## Self-Check: PASSED
