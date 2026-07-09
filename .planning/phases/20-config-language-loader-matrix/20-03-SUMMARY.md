---
phase: 20-config-language-loader-matrix
plan: 03
subsystem: config
tags: [delivery-matrix, cli, markdown, html, pii-safe, config-loader]

# Dependency graph
requires:
  - phase: 20-01
    provides: "delivery/config_loader.py::resolve_config — (groups, errors, warnings, metadata_by_delivery_name)"
provides:
  - "scripts/generate_delivery_matrix.py — standalone CLI rendering the delivery matrix (deliveries x reports x schedule x filters x owner) as Markdown (default) or HTML"
  - "tests/test_generate_delivery_matrix.py — coverage + PII-invariant + side-channel + html-format + all-assets regression harness"
affects: [phase-21-private-repo-cutover]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "standalone-script skeleton reuse: sys.path bootstrap + Flags/Exit-codes docstring + argparse-error-to-logfile subclass + rotating-file logger, copied from scripts/warm_cache.py"
    - "PII-safe published artifact: matrix renders contact/group NAMES + owner sourced only from the resolver's metadata_by_delivery_name side channel, never from email.recipients/cc"

key-files:
  created:
    - scripts/generate_delivery_matrix.py
    - tests/test_generate_delivery_matrix.py
  modified: []

key-decisions:
  - "render_html was written in the same Task 1 commit as render_markdown (both live naturally in one small file); Task 2 wired --format html in main() and added the test coverage — sequencing preserved via what each task's commit adds test/wiring for, no functional deviation"

requirements-completed: [CONF-05]

# Metrics
duration: 3min
completed: 2026-07-09
---

# Phase 20 Plan 03: Delivery Matrix Generator Summary

**Standalone `scripts/generate_delivery_matrix.py` renders "who gets what, when" (deliveries x reports x schedule x filters x owner) as Markdown or HTML, sourcing owner + contact NAME exclusively from the resolver's metadata side channel — zero expanded recipient addresses, safe as a future Phase 21 CI artifact.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-07-09T20:19:00Z (approx, first script write)
- **Completed:** 2026-07-09T20:21:24Z
- **Tasks:** 2
- **Files modified:** 2 (both created)

## Accomplishments
- `scripts/generate_delivery_matrix.py` reuses `delivery.config_loader.resolve_config` (Plan 01) to render the full delivery landscape without opening any YAML — CONF-05 delivered
- Markdown (default) and HTML (`--format html`) renderers share a single row-builder that reads owner + contact NAME exclusively from `metadata_by_delivery_name`, never from `email.recipients`/`cc` (D-05 / Hard Rule 2)
- 14-check regression harness (`tests/test_generate_delivery_matrix.py`) proves matrix coverage, the PII invariant (0 recipient-address occurrences in both formats), the metadata-side-channel sourcing, HTML `<table` output, and `filters: {}` → "All Assets"
- Script imports only the config loader — no `data/fetchers.py`/`tenable_client.py` import (Hard Rule 1)

## Task Commits

Each task was committed atomically:

1. **Task 1: Standalone matrix-generator script skeleton + Markdown renderer (CONF-05, D-04/D-05/D-06)** - `bbc0113` (feat)
2. **Task 2: HTML format + matrix coverage/PII tests** - `bfbf92d` (test)

**Plan metadata:** (recorded in final commit below)

## Files Created/Modified
- `scripts/generate_delivery_matrix.py` - New standalone CLI (285 lines): `_build_parser`/`main`/`_configure_logging`/`_MatrixArgumentParser` skeleton copied from `scripts/warm_cache.py`; `render_markdown`, `render_html`, and the shared `_matrix_rows` helper (schedule/filters formatting + metadata-side-channel join)
- `tests/test_generate_delivery_matrix.py` - New 14-check regression harness (223 lines), `main()`/`_check` style matching `tests/test_config_loader.py` and `tests/test_phase4_schema_validation.py`

## Decisions Made
- Wrote `render_html` alongside `render_markdown` in Task 1's commit since both are small, closely related functions in the same file — Task 1's commit message documents it was included "alongside for Task 2's `--format html` wiring." Task 2 wired `--format html` into `main()`'s dispatch and added all test coverage (markdown, html, PII, side-channel, all-assets). No functional deviation from the plan; task boundaries preserved via what got tested/wired-into-the-CLI-path in each commit rather than a hard split of which function bodies existed.
- Followed `scripts/warm_cache.py` verbatim for the standalone-script skeleton (sys.path bootstrap, Flags/Exit-codes docstring blocks, `_MatrixArgumentParser` argparse-error-to-logfile subclass, rotating-file `_configure_logging`) per the plan's `read_first` instruction.
- Exit codes: 0 success, 2 argparse usage error, 3 loader-returned-errors (config failed to resolve) — mirrors `warm_cache.py`'s exit-code convention, adapted since this script has no auth step.

## Deviations from Plan

None - plan executed exactly as written. Both tasks' acceptance criteria are met; the threat model's five `mitigate` items (T-20-09 PII, T-20-10 loader-reuse-only-YAML-parse, T-20-11 no live Tenable fetch, T-20-12 fail-loud-not-raise on loader errors, T-20-SC no new deps) are all satisfied and exercised by the test suite.

## Issues Encountered
- `python -m pytest tests/test_generate_delivery_matrix.py -x -q` hung/produced no readable output under the repo's default `pytest-xdist` parallel config (this file uses the `main()`/`_check` harness style with no `test_*` functions, matching `tests/test_config_loader.py`'s precedent — `pytest.ini`'s `testpaths` doesn't include it). Resolved by using the plan's documented fallback: `python tests/test_generate_delivery_matrix.py`, which ran all 14 checks green in isolation. No functional issue — same precedent and rationale as Plan 20-01's `tests/test_config_loader.py`.
- The repo's real `delivery_config.yaml` (gitignored, local dev file) is single-file mode with no `deliveries.d/` sibling, so `resolve_config` correctly returns an empty matrix against it. Verified the script's markdown path end-to-end instead against a synthetic directory-mode fixture written to the session scratchpad (not committed) — confirms the acceptance criterion "pointed at a synthetic directory-mode config, prints a Markdown table containing every delivery name, owner, reports, schedule, filters, and contact NAME."

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- CONF-05 complete. `scripts/generate_delivery_matrix.py` is ready for Phase 21's CI step to invoke directly (`python scripts/generate_delivery_matrix.py --format html --output <artifact-path>`) as a published, PII-safe artifact.
- No blockers. Plan 20-04 (effective-config golden test, QUAL-06) can proceed independently — it does not depend on this plan's output.

---
*Phase: 20-config-language-loader-matrix*
*Completed: 2026-07-09*

## Self-Check: PASSED

All created files found on disk (`scripts/generate_delivery_matrix.py`, `tests/test_generate_delivery_matrix.py`, this SUMMARY.md). Both task commits (`bbc0113`, `bfbf92d`) verified present in `git log --oneline --all`.
