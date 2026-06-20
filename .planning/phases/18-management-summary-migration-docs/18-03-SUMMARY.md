---
phase: 18-management-summary-migration-docs
plan: "03"
subsystem: data
tags: [trend-store, reconstruction, backfill, overlap-gate, immutability, month-end-utc, pytenable, pandas]

requires:
  - phase: 18-02
    provides: bounded fetch_fixed_vulnerabilities (last_fixed lookback ~15-16mo) that the reconstruction script depends on for fixed-vuln data

provides:
  - month_end_utc(month) shared boundary helper in data/trend_store.py (tz-aware UTC, inclusive/exclusive semantics documented and tested at 00:00:00 / 23:59:59)
  - Reconstructed-month immutability in capture_snapshot() — skips any month already present with source='reconstructed' (incl. current month, D-18-03/review change #7)
  - scripts/backfill_trend_reconstruction.py — one-time idempotent ALL-ASSETS seeding script with embedded overlap-test gate, provenance marking, partial flag, null asset_count
  - ~12 months (2025-06 → 2026-05) of real, overlap-validated ALL-ASSETS history seeded to data/trend/trend_severity_all_assets.json (gitignored, operator-run)
  - Unit test suite tests/test_backfill_reconstruction.py: synthetic-integration overlap gate (primary), weaker live-fallback marker, immutability (captured + reconstructed + current-month), partial flag, null asset_count, reopened-aware predicate, month_end_utc boundaries
  - D-18-10 gate 2 GREEN — trend store ready for Plan 04 cutover

affects:
  - 18-04 (management_summary migration consumes the now-populated all-assets trend store; all-assets modules will NOT cold-start)
  - 18-05 (runbook must document all-assets-only scope + tag-scoped cold-start as explicit decision)

tech-stack:
  added: []
  patterns:
    - "month_end_utc(month) as the single shared boundary helper for all reconstruction math — no inline month-boundary arithmetic anywhere else"
    - "Overlap-test gate: synthetic-integration (fixed-after-D add-back) is the PRIMARY unit gate; live-today fallback is explicitly labeled weaker-confidence"
    - "Immutability-first write: skip months already present (captured OR reconstructed) before touching the JSON; _atomic_write_json for the final write"
    - "Provenance marking: source='reconstructed', asset_count=None, partial=True for months < 2025-09, generated_at UTC"

key-files:
  created:
    - scripts/backfill_trend_reconstruction.py
    - tests/test_backfill_reconstruction.py
  modified:
    - data/trend_store.py (month_end_utc helper + capture_snapshot reconstructed-month immutability)

key-decisions:
  - "D-18-08 (LOCKED): one-time idempotent all-assets seeding script reconstructs ~12mo from Tenable fixed+open exports BEFORE the Plan 04 cutover; immutable, provenance-marked; tag-scoped scopes are explicitly NOT reconstructed (pre-existing cold-start, no active group is tag-scoped on management_summary)"
  - "D-18-03 (LOCKED): reconstructed months are immutable — never overwritten by a later capture_snapshot() call, including the current month (review change #7)"
  - "D-18-04 (LOCKED): asset_count=None on all reconstructed months — Tenable does not retain historical asset population; Vulnerability Density cold-starts for reconstructed months rather than use a fabricated denominator"
  - "D-18-09 (LOCKED): overlap-test gate exits non-zero and writes nothing on divergence; synthetic-integration (fixed-after-D add-back) is the primary unit gate; live-today fallback is explicitly weaker-confidence"
  - "Overlap gate outcome (weaker-confidence path, as designed): live_open=210267, reconstructed_total=210267, abs_diff=0, rel_diff=0.0% — PASS; no captured months existed yet so the primary captured-month comparison ran via the weaker live-today fallback path"
  - "Idempotency confirmed: second run wrote 0 new months (all 13 present); 2026-06 pre-existing snapshot skipped (source=unknown, immutability respected)"

patterns-established:
  - "Boundary math pattern: always call month_end_utc(month) — never compute month boundaries inline"
  - "Reconstruction predicate pattern: open_findings_at(combined_df, month_end_utc(month)) where combined_df = current-open rows + fixed rows with last_fixed > month_end_utc(month); no naive last_fixed null OR last_fixed>D form (QUAL-02)"
  - "Audit-honesty pattern: prefer null over fabricated denominator when historical data is unavailable (D-18-04)"

requirements-completed: [GEN-01, QUAL-04]

duration: operator-gated (code tasks ~45min; operator seed run same-day)
completed: "2026-06-20"
---

# Phase 18 Plan 03: Trend Reconstruction Seeding Summary

**Reconstructed ~12 months of real all-assets MoM severity history from Tenable fixed+open exports with embedded overlap-test gate (PASS: live_open=210267 == reconstructed=210267, 0 diff), provenance-marked immutable snapshots (source='reconstructed', asset_count=null, partial=true for Jun-Aug 2025), and month_end_utc boundary semantics pinned in data/trend_store.py — D-18-10 gate 2 GREEN, store ready for Plan 04 cutover.**

## Performance

- **Duration:** Code tasks ~45 min; operator checkpoint same-day
- **Started:** 2026-06-20 (code tasks)
- **Completed:** 2026-06-20 (operator seed verified, plan closed)
- **Tasks:** 3 (Task 1 RED tests, Task 2 GREEN impl + fix, Task 3 operator seed)
- **Files modified:** 4 code files (data/trend_store.py, scripts/backfill_trend_reconstruction.py, tests/test_backfill_reconstruction.py, tests/test_trend_store.py)

## Accomplishments

- Added `month_end_utc(month)` as the single shared boundary helper to `data/trend_store.py`; extended `capture_snapshot()` to skip any month already present with `source='reconstructed'` (including the current month), enforcing D-18-03 immutability at the forward-capture layer
- Built `scripts/backfill_trend_reconstruction.py`: one-time idempotent ALL-ASSETS seeding script; reconstructs each month via the reopened-aware `open_findings_at()` two-interval predicate with fixed-after-D add-back; embedded overlap-test gate exits non-zero and writes nothing on divergence; provenance-marks every entry (`source='reconstructed'`, `asset_count=None`, `partial=True` for Jun-Aug 2025)
- Operator seeded 12 reconstructed months (2025-06 → 2026-05) into the gitignored `data/trend/trend_severity_all_assets.json`; overlap gate passed on the weaker-confidence fallback path (no prior captured months to use as primary gate) with zero divergence (live_open=210267 == reconstructed_total=210267); idempotency confirmed (second run wrote 0 months); 2026-06 pre-existing snapshot left intact

## Task Commits

1. **Task 1: RED reconstruction/immutability/boundary/partial tests** - `e873f1f` (test)
2. **Task 2: month_end_utc + reconstructed-month immutability + all-assets seeding script** - `f9dab8c` (feat)
3. **Task 2 deviation fix: pass cache_dir to fetchers in backfill live-fetch branch** - `1ee9ce5` (fix)
4. **Task 3: Operator one-time all-assets seed run** - operator-run against live tenant; no repo artifact (data/trend/ is gitignored)

## Files Created/Modified

- `data/trend_store.py` — Added `month_end_utc(month)` shared boundary helper (tz-aware UTC, inclusive/exclusive semantics documented); extended `capture_snapshot()` to skip months with `source='reconstructed'` (D-18-03, review change #7)
- `scripts/backfill_trend_reconstruction.py` — One-time idempotent all-assets reconstruction script: argparse (`--cache-dir`, `--window-start`, `--dry-run`), reopened-aware predicate via `open_findings_at()` + fixed-after-D add-back, embedded overlap-test gate (synthetic-integration primary / live-today weaker fallback), immutable provenance-marked writes via `_atomic_write_json`, partial flag on Jun-Aug 2025, null `asset_count`
- `tests/test_backfill_reconstruction.py` — Created: synthetic-integration overlap pass/fail, weaker-fallback marker, immutability (captured + reconstructed + current-month), capture_snapshot skips reconstructed current month, partial flag, null asset_count, reopened-aware predicate, month_end_utc boundaries at 00:00:00 / 23:59:59 (all RFC-5737/6761 synthetic data, QUAL-05)
- `tests/test_trend_store.py` — Extended with `test_capture_snapshot_skips_reconstructed_current_month` (D-18-03 contract test at the store layer)

## Decisions Made

- **Weaker-confidence overlap gate (by design):** No captured months existed in the tenant's trend store yet, so the embedded gate ran its live-today fallback path rather than the primary synthetic-integration/captured-month comparison path. The plan and tests explicitly document this as weaker confidence. Result: live_open=210267 == reconstructed_total=210267, abs_diff=0, rel_diff=0.0% — PASS. The primary unit gate (synthetic-integration with fixed-after-D add-back) was verified via `test_overlap_synthetic_integration_pass` in the test suite.
- **2026-06 skipped (immutability respected):** A pre-existing 2026-06 snapshot with `source=unknown` was already present; the script left it intact per D-18-03 (never overwrite any existing month, regardless of source).
- **Tag-scoped reconstruction explicitly out of scope:** Confirmed against `delivery_config.yaml` — no active delivery group runs `management_summary` (only a commented example); tag-scoped cold-start is pre-existing and not a regression. Plan 05's runbook will document this as an explicit decision.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] pass cache_dir to fetchers in backfill live-fetch branch**
- **Found during:** Task 2 (backfill script implementation)
- **Issue:** The live-fetch fallback branch in `backfill_trend_reconstruction.py` called `fetch_all_vulnerabilities()` and `fetch_fixed_vulnerabilities()` without forwarding `cache_dir`, causing the live-fetch path to bypass the run-scoped parquet cache and always re-fetch from the API
- **Fix:** Passed `cache_dir` to both fetcher calls in the live-fetch branch; added a regression test asserting `cache_dir` is forwarded
- **Files modified:** `scripts/backfill_trend_reconstruction.py`
- **Committed in:** `1ee9ce5` (separate fix commit after `f9dab8c`)

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug in live-fetch cache_dir forwarding)
**Impact on plan:** Fix was necessary for correctness (caching contract); no scope creep.

## Issues Encountered

None beyond the cache_dir fix above. The operator seed run proceeded cleanly; dry-run confirmed the overlap gate and planned months before the live write.

## User Setup Required

None — the operator already completed the one-time seed run (Task 3 checkpoint). The gitignored `data/trend/trend_severity_all_assets.json` is populated and ready for Plan 04 to consume.

## Threat Surface Scan

No new network endpoints, auth paths, file-access patterns, or schema changes introduced beyond those already in the plan's threat model. `data/trend/` is gitignored; reconstructed entries contain aggregate severity counts only (no hostnames, IPs, plugin names, or asset UUIDs — T-18-06 mitigated). No new threat flags.

## Known Stubs

None — this plan produces a seeding script and its test suite; there are no rendering paths or data-source wirings that could be stubbed.

## Self-Check

- [x] `scripts/backfill_trend_reconstruction.py` exists
- [x] `tests/test_backfill_reconstruction.py` exists
- [x] `data/trend_store.py` contains `month_end_utc`
- [x] Commits e873f1f, f9dab8c, 1ee9ce5 exist in git log
- [x] `data/trend/` NOT committed (gitignored)
- [x] `.claude/hooks/` NOT committed (untracked, out of scope)
- [x] `.planning/todos/pending/2026-06-18-run-coderabbit-on-phase-18-code-review.md` NOT committed (untracked, out of scope)

## Self-Check: PASSED

## Next Phase Readiness

- **Plan 04 (management_summary migration):** The all-assets trend store is populated with ~12 months of real MoM history (2025-06 → 2026-05); `read_trend("severity","all_assets",months=13)` returns `insufficient_data=False`. All-assets modules will NOT cold-start. Tag-scoped groups will still cold-start (pre-existing, documented).
- **Plan 05 (runbook):** Must document: (a) the all-assets-only reconstruction scope and why tag-scoped groups cold-start, (b) the weaker-confidence overlap gate outcome and what it means, (c) the month_end_utc boundary convention, (d) the `backfill_trend_reconstruction.py` idempotency guarantee for future re-runs.
- No blockers.

---
*Phase: 18-management-summary-migration-docs*
*Completed: 2026-06-20*
