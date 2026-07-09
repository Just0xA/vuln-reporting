---
phase: 18-management-summary-migration-docs
plan: "04"
subsystem: reporting
tags: [management_summary, ReportComposer, module-pipeline, trend-store, chrome-pdf, GEN-01]

# Dependency graph
requires:
  - phase: 18-management-summary-migration-docs
    provides: "18-01: structural + value-parity baselines; frozen fixture set; bucketed golden; smoke adapter. 18-02: bounded fixed-vuln fetch. 18-03: 12mo all-assets trend reconstruction seeded in data/trend_store."
provides:
  - "management_summary fully migrated onto ReportComposer.run_full_pipeline() composing all seven metric modules"
  - "Bespoke ~2,200-line render path atomically removed (no dual-writer window) in a single GREEN commit"
  - "management_summary added to _CHROME_AWARE_SLUGS; run_report() accepts chrome kwargs (privacy_label/scope_subtitle/report_title)"
  - "Email body routes through build_email_body_modular() via non-empty email_body_html"
  - "read_trend('severity','all_assets',months=13) wired into ReportComposer so all-assets MoM modules receive 12mo history (no cold-start)"
  - "Legacy management_summary_*.json archived to data/trend/legacy_archive/ (not deleted)"
  - "read_trend store-level directory-scoping confirmed: legacy_archive/ subdir not traversed"
  - "Per-metric value-parity gate: 5 exact-match metrics zero drift vs bespoke golden; 2 documented-difference metrics (M5/M7) excluded from exact assert and confirmed by operator visual UAT"
  - "Structural smoke parity passes via shared adapter on result['_bundle']"
  - "17 migration tests pass; run_all --dry-run validates all 5 groups; operator visual UAT APPROVED"
affects: [Phase 18 plan 05, GEN-01 completion, v1.4 milestone close, future ops_remediation migration (GEN-02)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Atomic bespoke-path removal: new pipeline wired + old functions deleted in a single commit, tested by test_bespoke_functions_removed"
    - "Bucketed value-parity gate: golden JSON carries comparison_policy per metric; test reads the bucket, not hard-coded assignments"
    - "Store-level directory scoping: read_trend globs directly in TREND_DIR, does not traverse subdirs (legacy_archive/)"
    - "Four-channel bundle: management_summary returns _bundle, email_body_html, analyst_excel, email_inline_images matching board_summary shape"

key-files:
  created:
    - tests/test_management_summary.py
    - tests/baselines/management_summary_value_golden.json (Plan 01, consumed here)
    - tests/fixtures/management_summary_parity/ (Plan 01, consumed here)
    - data/trend/legacy_archive/ (move destination for legacy JSON)
  modified:
    - reports/management_summary.py
    - run_all.py
    - tests/test_phase6_run_group_chrome.py
    - tests/test_trend_store.py
    - scripts/smoke_management_summary_cutover.py

key-decisions:
  - "D-18-10 gate 4 GREEN: atomic single-commit removal — bespoke functions deleted in the same commit read_trend()/capture_snapshot wiring lands; no dual-writer window"
  - "Bucketed parity (review HIGH change #1, USER-APPROVED): exact-match metrics (M1/M2/M3/M4/M6) assert zero drift; documented-difference metrics (M5 aged_vulns_assets, M7 new_vs_remediated) excluded from exact assert — their correctness verified by module tests + operator visual UAT"
  - "M5 fixture gap acknowledged: synthetic parity fixture missing 'owner' column causes M5 fail-soft on the fixture run; this is a fixture limitation only — real-data render confirmed correct by operator UAT"
  - "Tag-scoped MoM cold-start is pre-existing, not a regression: no active delivery_config.yaml group is tag-scoped on management_summary (only commented examples)"
  - "Legacy JSON archived not deleted (D-18-11): data/trend/legacy_archive/ created; move, never delete"

patterns-established:
  - "Module pipeline cutover pattern: mirror board_summary wiring exactly — _MGMT_MODULE_CONFIGS, PdfChromeConfig, ReportComposer, run_all(), run_full_pipeline(), _bundle key"
  - "Frozenset co-edit requirement: adding a slug to _CHROME_AWARE_SLUGS requires updating the expected set in test_phase6_run_group_chrome.py on the same commit"
  - "read_trend scoping: active trend dir glob must not recurse into subdirectories; store-level test asserts this contract"

requirements-completed: [GEN-01, QUAL-04, QUAL-02]

# Metrics
duration: multi-session (RED 2026-06-20, GREEN + smoke + UAT 2026-06-21)
completed: 2026-06-21
---

# Phase 18 Plan 04: Atomic Management Summary Cutover (GEN-01) Summary

**management_summary migrated from ~2,200-line bespoke render path to ReportComposer pipeline composing seven registered modules, chrome-aware, with modular email and 12mo all-assets trend history — bespoke path atomically removed, parity gate passes (5 exact-match zero drift, 2 documented-difference confirmed by operator UAT), GEN-01 complete.**

## Performance

- **Duration:** Multi-session (RED phase 2026-06-20; GREEN + smoke + operator UAT 2026-06-21)
- **Started:** 2026-06-20
- **Completed:** 2026-06-21
- **Tasks:** 4 (Tasks 1–3 automated; Task 4 operator visual UAT — APPROVED)
- **Files modified:** 7 key files

## Accomplishments

- Replaced ~2,200 lines of bespoke management_summary render logic with `ReportComposer.run_full_pipeline()` composing the seven pre-existing registered modules in a single atomic GREEN commit — no dual-writer window (QUAL-04)
- Per-metric parity gate (review HIGH change #1): M1 (total_vulns_by_severity), M2 (scan_coverage_sla), M3 (mttr_trend rolling-30), M4 (patch_compliance_rate), M6 (accepted_recast current-period counts/rate) all assert ZERO drift vs the Plan 01 bespoke golden on the frozen synthetic fixture; M5 (aged_vulns_assets) and M7 (new_vs_remediated) documented as intentionally-changed and excluded from exact assert — confirmed correct by operator visual UAT
- Operator visual UAT APPROVED: all seven metric sections render in the chrome-aware PDF; M5 (% of aged on-time-scanned assets, not the old vuln age-bucket histogram) and M7 (inflow/outflow trend, not the old simple total-open delta) render correctly as the new intended metrics; all-assets MoM panels (MTTR trend, New vs Remediated, Accepted & Recast) show real 12mo reconstructed history with no cold-start; modular email body confirmed; all delivery_config.yaml groups run with NO YAML changes

## Task Commits

1. **Task 1: Migration acceptance tests + bucketed value-parity gate + store-level read_trend scoping (RED)** — `678e0bf` (test)
2. **Task 2: Atomic GEN-01 cutover — management_summary onto ReportComposer (GREEN)** — `028f802` (feat)
3. **Task 3: Post-cutover smoke parity + structural rebaseline + archive legacy JSON** — `7ed2699` (chore)
4. **Task 4: Operator visual UAT** — APPROVED (no repo artifact; approval recorded in plan closure context)

## Files Created/Modified

- `reports/management_summary.py` — Migrated: `_MGMT_MODULE_CONFIGS` list of 7 modules; `run_report()` on `ReportComposer.run_full_pipeline()`; chrome kwargs (`privacy_label`/`scope_subtitle`/`report_title`); `read_trend()` wiring; `capture_snapshot()` forward write; `_bundle` return key; `email_body_html` non-empty; all bespoke functions deleted atomically
- `run_all.py` — `management_summary` added to `_CHROME_AWARE_SLUGS`; CHROME-COMPAT-01 exclusion comment removed
- `tests/test_management_summary.py` — Created: 7 tests including `test_value_golden_parity` (bucketed per-metric), `test_bespoke_functions_removed`, `test_run_report_accepts_chrome_kwargs`, `test_trend_forwarded_no_coldstart`, `test_read_trend_ignores_legacy_archive_integration`
- `tests/test_trend_store.py` — Added store-level `test_read_trend_ignores_legacy_archive` contract test (review change #11)
- `tests/test_phase6_run_group_chrome.py` — Expected frozenset updated to include `"management_summary"` (frozenset co-edit)
- `scripts/smoke_management_summary_cutover.py` — Updated to capture from `result["_bundle"]` via shared structural-snapshot adapter
- `data/trend/legacy_archive/` — Created; legacy `management_summary_*.json` moved here (not deleted)

## Decisions Made

- **Bucketed parity approach (USER-APPROVED):** Rather than a blanket zero-drift claim, the parity gate reads per-metric `comparison_policy` from the Plan 01 golden JSON. Exact-match metrics assert zero drift; documented-difference metrics (M5/M7) record the bespoke-vs-modular values for the Summary without asserting exact equality. This avoids a false failure that would force preserving replaced semantics, while still catching subtle rounding/edge-case drift on the five exact-match metrics.
- **M5 and M7 as intentionally-changed metrics:** M5 (`aged_vulns_assets`) in the new module computes % of aged on-time-scanned ASSETS (the roadmap's intended metric), not the old bespoke vuln age-bucket histogram. M7 (`new_vs_remediated`) computes inflow/outflow trend, not the old simple total-open delta. Both are documented differences, not regressions.
- **Atomic removal (QUAL-04):** All bespoke functions — `_save_trend_snapshot`, `_load_trend_history`, `_trend_file_path`, `_sanitise_tag_for_filename`, `_compute_metric_1`–`7`, `compute_all_metrics`, `_build_age_bar_chart`, `_build_trend_line_chart`, `_build_pdf`, `build_email_kpi_tiles`, `build_email_body`, and the orphaned constants — deleted in the same commit as the new pipeline, verified by `test_bespoke_functions_removed`.
- **Legacy JSON archived not deleted (D-18-11):** `data/trend/management_summary_*.json` moved to `data/trend/legacy_archive/` which inherits the `data/trend/` gitignore rule. `read_trend()` directory scoping confirmed not to traverse subdirectories (store-level + integration tests GREEN).

## Deviations from Plan

None — plan executed exactly as written. The M5 fixture gap (missing `'owner'` column in the synthetic parity fixture causes `aged_vulns_assets` to fail-soft on the frozen fixture run) is a known fixture limitation recorded in the plan's acceptance criteria — it does not affect real-data render, which the operator confirmed correct in Task 4 visual UAT.

## Issues Encountered

**M5 synthetic fixture limitation (non-blocking):** The Plan 01 frozen fixture set (`tests/fixtures/management_summary_parity/`) predates the `aged_vulns_assets` module's `'owner'` column requirement. When `test_value_golden_parity` drives the modular pipeline against this fixture, M5 compute hits the empty-data guard and returns a gray "No Data" strip cell. This is the `_empty_result()` fail-soft path working correctly — it is a fixture gap, not a production bug. The module's own unit tests (with correct fixtures) pass, and the operator confirmed M5 renders correctly on real-data. Documented in SUMMARY as a known fixture limitation; resolution deferred to a future fixture-enrichment task if needed.

## User Setup Required

None — no external service configuration required. Operator ran the migrated report against live Tenable data; all seven sections rendered correctly with no YAML changes.

## Parity Gate Outcome

| Metric | Module | Gate | Outcome |
|--------|--------|------|---------|
| M1 Total Vulns by Severity | `total_vulns_by_severity` | Exact-match (zero drift) | PASS |
| M2 Scan Coverage SLA | `scan_coverage_sla` | Exact-match (zero drift) | PASS |
| M3 MTTR Trend (rolling-30) | `mttr_trend` | Exact-match (zero drift) | PASS |
| M4 Patch Compliance Rate | `patch_compliance_rate` | Exact-match (zero drift) | PASS |
| M5 Aged Vulns/Assets | `aged_vulns_assets` | Documented-difference (new metric semantics) | Excluded from exact assert; visual UAT APPROVED |
| M6 Accepted & Recast | `accepted_recast` | Exact-match (zero drift) | PASS |
| M7 New vs Remediated | `new_vs_remediated` | Documented-difference (new metric semantics) | Excluded from exact assert; visual UAT APPROVED |

Structural smoke parity: PASS (shared adapter on `result['_bundle']` vs Plan 01 structural baseline — section count, RAG cell count, module presence all match).

## Next Phase Readiness

GEN-01 is complete. D-18-10 gate 4 GREEN. Phase 18 Plan 05 (documentation, runbooks, and milestone close) is unblocked.

Existing delivery_config.yaml groups continue to deliver with zero YAML changes — backward compatibility confirmed.

## Self-Check

- [x] `reports/management_summary.py` exists and contains `ReportComposer`, `run_full_pipeline`, `read_trend`, `_MGMT_MODULE_CONFIGS`
- [x] `tests/test_management_summary.py` exists with all 7 tests
- [x] `tests/test_trend_store.py` contains `test_read_trend_ignores_legacy_archive`
- [x] Task commits exist: `678e0bf`, `028f802`, `7ed2699`
- [x] Working tree clean (no in-scope tracked changes)

## Self-Check: PASSED

---
*Phase: 18-management-summary-migration-docs*
*Completed: 2026-06-21*
