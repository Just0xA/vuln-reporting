---
phase: 20-config-language-loader-matrix
plan: 04
subsystem: config
tags: [testing, golden-test, delivery-config, resolve-before-validate, qual-06]

# Dependency graph
requires:
  - "delivery/config_loader.py — resolve_config (Plan 20-01)"
  - "run_all.py — _load_config, _load_schema, _validate_with_schema (Plan 20-01)"
provides:
  - "tests/baselines/effective_config_golden.json — committed normalized effective-config golden"
  - "tests/test_effective_config_golden.py — two-way equality gate (legacy byte-identical + migrated-twin same-golden + schema-passes)"
  - "tests/fixtures/phase20_config_legacy/delivery_config.yaml — legacy single-file twin fixture"
  - "tests/fixtures/phase20_config_twin/ — migrated-twin fixture (contacts.yaml + deliveries.d/*.yaml)"
affects: [phase-21-private-repo-cutover]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "machine-generated golden: golden JSON is written from the resolver's own output (not hand-typed), preventing hand-authored drift"
    - "two-way equality gate: legacy fixture == golden AND migrated-twin fixture == SAME golden, proving new source language resolves identically to today's shape"

key-files:
  created:
    - tests/fixtures/phase20_config_twin/contacts.yaml
    - tests/fixtures/phase20_config_twin/deliveries.d/exec.yaml
    - tests/fixtures/phase20_config_twin/deliveries.d/remediation.yaml
    - tests/fixtures/phase20_config_twin/deliveries.d/tag_profile.yaml
    - tests/fixtures/phase20_config_legacy/delivery_config.yaml
    - tests/baselines/effective_config_golden.json
    - tests/test_effective_config_golden.py
  modified:
    - .gitignore

key-decisions:
  - "Legacy fixture's inline email: blocks were hand-computed to pre-bake analyst-team@example.invalid into cc (and reply_to where the twin's contact has no override), so both fixtures resolve to byte-identical effective configs without any special-casing in the test"
  - "Golden generated via a _REGENERATE flag in the test module (set True, run once, verify, set back False) rather than a separate one-off script — kept the regeneration procedure co-located with the test that consumes it"
  - "Added a scoped .gitignore exception (!tests/fixtures/phase20_config_legacy/delivery_config.yaml) because the existing bare delivery_config.yaml ignore rule (intended to keep the real production config out of git) matched the required synthetic fixture filename at any depth"

requirements-completed: [QUAL-06]

# Metrics
duration: 5min
completed: 2026-07-09
---

# Phase 20 Plan 04: Effective-Config Golden Test Summary

**Committed sorted-key JSON golden + two-way equality test proving the migrated-twin config (contacts.yaml + deliveries.d/) and the legacy single-file delivery_config.yaml resolve to an identical effective config that still passes the unchanged schema — the reversibility gate for the Phase 21 cutover.**

## Performance

- **Duration:** ~5 min
- **Completed:** 2026-07-09
- **Tasks:** 2
- **Files modified:** 7 (6 created, 1 modified)

## Accomplishments
- Authored a legacy single-file fixture (`tests/fixtures/phase20_config_legacy/delivery_config.yaml`) mirroring the three `delivery_config.example.yaml` groups (Executive Team, Remediation Team, Tag Severity & Type Profile) with inline `email:` blocks and the legacy `groups:` key
- Authored the migrated-twin fixture (`tests/fixtures/phase20_config_twin/`) — `contacts.yaml` (3 named contacts + `defaults.analyst_mailbox`) and three `deliveries.d/*.yaml` team files, each with an `owner:` field and a `contact:` ref, exercising `composed_report` + `modules:`, `cc`, `reply_to` (both contact-override and analyst-mailbox-fallback paths), `on_demand`, and empty `filters: {}`
- Generated `tests/baselines/effective_config_golden.json` directly from `resolve_config`'s output (never hand-typed) — a sorted-key, 2-space-indented JSON serialization of `{"groups": [...]}`
- `tests/test_effective_config_golden.py` proves the two-way equality: legacy resolution == committed golden (byte-identical), migrated-twin resolution == the SAME committed golden, both resolved configs pass the unchanged `delivery_config.schema.yaml`, and no golden group dict carries `owner`/`contact` (metadata side-channel keys stay off the schema-gated group dicts)

## Task Commits

Each task was committed atomically:

1. **Task 1: Author legacy + migrated-twin fixtures from delivery_config.example.yaml (D-08)** - `0b627b5` (test)
2. **Task 2: Generate golden + two-way equality + schema-passes test (QUAL-06, D-07)** - `38038c9` (test)

## Files Created/Modified
- `tests/fixtures/phase20_config_twin/contacts.yaml` - 3 contacts (`exec_team`, `remediation_team`, `tag_profile_team`) + `defaults.analyst_mailbox: analyst-team@example.invalid`
- `tests/fixtures/phase20_config_twin/deliveries.d/exec.yaml` - Executive Team delivery, `contact: exec_team`, weekly, tag filter
- `tests/fixtures/phase20_config_twin/deliveries.d/remediation.yaml` - Remediation Team delivery, `contact: remediation_team`, weekly, empty `filters: {}`
- `tests/fixtures/phase20_config_twin/deliveries.d/tag_profile.yaml` - Tag Severity & Type Profile delivery, `contact: tag_profile_team`, on_demand, `composed_report` + `modules:`
- `tests/fixtures/phase20_config_legacy/delivery_config.yaml` - Legacy single-file twin of the same 3 deliveries, inline `email:` blocks pre-baked with the analyst mailbox
- `tests/baselines/effective_config_golden.json` - Machine-generated committed golden (`groups` array, 3 entries, no `owner`/`contact` keys, `example.invalid` addresses only)
- `tests/test_effective_config_golden.py` - `_normalize`/`_check`/`main()` harness (231 lines) implementing the two-way equality + schema-passes gate
- `.gitignore` - Added a scoped exception for the synthetic legacy fixture filename

## Decisions Made
- Followed D-07/D-08 exactly: committed JSON golden, sorted-keys deterministic normalization, machine-generated (not hand-authored) to prevent drift.
- Computed the legacy fixture's `cc`/`reply_to` values by hand-tracing `resolve_delivery_email`'s logic (contact recipients + `extra_recipients` additive; contact `cc` + `analyst_mailbox` standing-Cc; `reply_to` = contact override or `analyst_mailbox` fallback) before writing the fixture, then verified with a live `resolve_config` dry-run against the twin prior to writing the legacy YAML — this produced an exact byte match on the first attempt with no iteration needed.
- Matched the `main()`/`_check` harness style of `test_config_loader.py` and `test_phase4_schema_validation.py` (the closest analogs) rather than pytest `test_*` functions, since `pytest.ini`'s `testpaths` (`tests/unit tests/content tests/e2e`) excludes the `tests/` root — standalone invocation (`python tests/test_effective_config_golden.py`) is the primary verify path, matching the plan's verify command fallback.
- Regeneration procedure lives as a `_REGENERATE` module-level flag inside the test file itself (flip to `True`, run once, verify, flip back), documented in the module docstring, rather than a separate throwaway script — keeps the "how to regenerate" instructions next to the code that consumes the golden.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] `.gitignore`'s bare `delivery_config.yaml` rule silently excluded the required legacy fixture**
- **Found during:** Task 1, staging the legacy fixture file
- **Issue:** `.gitignore` line 14 (`delivery_config.yaml`, no leading slash) matches at any depth, so `git add tests/fixtures/phase20_config_legacy/delivery_config.yaml` reported the file as ignored. This rule exists to keep the real production `delivery_config.yaml` out of git — it was never intended to catch a synthetic test fixture that happens to share the same filename, but the plan's required file path (`tests/fixtures/phase20_config_legacy/delivery_config.yaml`, dictated by frontmatter `files_modified` and the D-08 fixture-directory convention) collided with it.
- **Fix:** Added a scoped negation pattern immediately below the existing rule: `!tests/fixtures/phase20_config_legacy/delivery_config.yaml`, with a comment explaining it is a committed synthetic fixture (`example.invalid` only) for the Phase 20 golden test. Mirrors the existing precedent at `.gitignore:67-68` for `tests/fixtures/management_summary_parity/*.parquet`.
- **Files modified:** `.gitignore`
- **Commit:** `0b627b5`

Or in full: no other deviations — the fixture content and test logic were implemented exactly per plan, and the golden matched the twin fixture on the first resolution attempt (no rework needed).

## Issues Encountered
- `python -m pytest tests/test_effective_config_golden.py -q` hangs/errors under this repo's `pytest.ini` (`addopts = -q -n auto ...`, `testpaths = tests/unit tests/content tests/e2e`) because the file lives outside `testpaths` and pytest-xdist's `-n auto` flag doesn't compose cleanly with an explicit single-file invocation in this environment. This is the same pre-existing condition documented in Plan 20-01's SUMMARY for `test_config_loader.py`. The plan's verify command already anticipates this with a `||` fallback to `python tests/test_effective_config_golden.py`, which runs clean and returns exit code 0 with all 13 checks passing.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- QUAL-06 is satisfied: the effective-config golden test proves the v1.6 config language resolves identically to today's group shape, making the Phase 21 cutover reversible in review.
- All four Phase 20 plans (20-01 loader, 20-02 dry-run + contacts.example.yaml, 20-03 delivery matrix, 20-04 this golden test) are complete. Phase 20 is ready for phase-close verification.
- No blockers for Phase 21 (private repo + CODEOWNERS + CI gate + production cutover, CONF-04/QUAL-07).

---
*Phase: 20-config-language-loader-matrix*
*Completed: 2026-07-09*

## Self-Check: PASSED

All created files found on disk: `tests/fixtures/phase20_config_twin/contacts.yaml`, `tests/fixtures/phase20_config_twin/deliveries.d/exec.yaml`, `tests/fixtures/phase20_config_twin/deliveries.d/remediation.yaml`, `tests/fixtures/phase20_config_twin/deliveries.d/tag_profile.yaml`, `tests/fixtures/phase20_config_legacy/delivery_config.yaml`, `tests/baselines/effective_config_golden.json`, `tests/test_effective_config_golden.py`. Both task commits (`0b627b5`, `38038c9`) verified present in `git log --oneline --all`.
