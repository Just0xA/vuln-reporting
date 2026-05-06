---
phase: 03-board-summary-module-migration
plan: 03-06
subsystem: tests/regression
tags: [regression, test, snapshot, quality-02, smoke-test, phase3-lock]

# Dependency graph
requires:
  - plan: 03-01
    provides: email_inline_images bundle key + ReportComposer.collect_email_inline_images accessor + run_full_pipeline 8-key bundle contract + W3 deprecated symbol aliases
  - plan: 03-02
    provides: ScanCoverageSLAModule with full Phase 3 four-channel contract
  - plan: 03-03
    provides: CriticalRemediationSLAModule with full Phase 3 four-channel contract
  - plan: 03-04
    provides: HighRiskAssetsModule with full Phase 3 four-channel contract (lower_is_better)
  - plan: 03-05
    provides: AgedVulnsAssetsModule with full Phase 3 four-channel contract (lower_is_better, single-tab worst_severity)
provides:
  - tests/test_phase2_composer_pipeline.py extended with 3 Phase 3 checks (10/10 total) — QUALITY-02 zero-row coverage + populated four-channel coverage + bundle-key contract
  - scripts/smoke_email_phase2.py driving real render_email_panel output from the four migrated modules off-network
  - Locked W7 fixture pattern (safe_pct(pct) for headline_value_str in both test and smoke fixtures) modelling CLAUDE.md Empty-data guard pattern rule 1
affects:
  - Phase 3 (closes Phase 3) — Wave 3 final plan; the next gate is Phase 3 verification + Phase 4 v2 work
  - Phase 4 (downstream): the regression suite is the contract guard for any future module migrations or new module additions

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Real-class regression coverage (T-03-06-01 mitigation): zero-row tests instantiate the FOUR REAL migrated module classes (ScanCoverageSLAModule, CriticalRemediationSLAModule, HighRiskAssetsModule, AgedVulnsAssetsModule) — not stubs. Catches real-module empty-data crashes that stub-based tests would miss."
    - "Off-network smoke driving real render_email_panel: scripts/smoke_email_phase2.py replaces the prior stub-panel injection with a populated ModuleData fixture per migrated module (1×1 transparent PNG in metadata['email_gauge_b64']) so each module's render_email_panel is exercised through the actual production code path, with no network calls."
    - "W7 safe_pct(pct) fixture pattern: both check_9 and _build_smoke_module_data use safe_pct(pct) for headline_value_str — never an inline percent-precision f-string spec. Even though pct is a known float in fixture code, fixture code is what new contributors copy when wiring tests for new modules; modelling the wrong pattern would propagate the bug."
    - "Sequential test runner (preserved from Phase 2): standalone-script style with explicit CHECKS list and a sequential pass/skip/fail driver — no test framework dependency."

key-files:
  created: []
  modified:
    - tests/test_phase2_composer_pipeline.py — added Phase 3 module-class imports + safe_pct + NO_DATA_HEADLINE/NO_DATA_DRIVER/STATUS_COLOR sentinels; added check_8_phase3_zero_row_render_methods (QUALITY-02 — 4 modules × 3 renderers); added check_9_phase3_populated_render_methods (4 modules × panel/tabs/strip with W7 safe_pct fixture); added check_10_phase3_bundle_email_inline_images_key (Plan 03-01 bundle contract); appended three new entries to CHECKS list. No existing Phase 2 check function modified.
    - scripts/smoke_email_phase2.py — added Phase 3 module-class imports + ModuleData/ModuleConfig + build_rag_strip_entry + safe_pct; added _build_smoke_module_data helper that constructs a populated ModuleData fixture with 1×1 transparent PNG email_gauge_b64; rewrote _build_synthetic_outputs to drive composer.assemble_email_body and composer.collect_email_inline_images with smoke_results (real render_email_panel) instead of stub-panel injection; retained stub-panels fallback as defensive log-warn-only branch.

key-decisions:
  - "W7 fixture pattern locked: both check_9 and _build_smoke_module_data use safe_pct(pct) for headline_value_str — never an inline percent-precision f-string spec. Modelling the correct pattern in fixture code is essential because new contributors copy fixtures when wiring tests for new modules; an inline f-string format spec on a possibly-None value would crash the moment a new module's compute() returns None for its headline metric."
  - "Real-class coverage over stub-class coverage (T-03-06-01): check_8 instantiates the FOUR REAL migrated module classes against an empty ModuleData fixture rather than re-using the existing _Phase2TestPanelA/B/Boom stubs. Stubs would mask empty-data crashes inside the real modules' render_email_panel / render_analyst_tabs / render_rag_strip_entry implementations. The trade-off is that check_8 imports the migrated module classes at test-import time, which adds ~0.3s of pandas/numpy/openpyxl overhead per run; total test runtime stayed at ~0.9s, well under the 30s T-03-06-02 cap."
  - "check_10 uses inspect.getsource + the public collect_email_inline_images accessor rather than a full run_full_pipeline call. inspect.getsource asserts the bundle key string literal is present in the run_full_pipeline source (the structural contract); the runtime accessor call asserts the empty-results path returns []. A full run_full_pipeline call would have required temp-dir setup + mock module instantiation + slug regex satisfaction + pdf rendering, all to assert one bundle key — disproportionate."
  - "Smoke fixture metadata['email_gauge_b64'] uses a 1×1 transparent PNG (the smallest valid base64 PNG payload). Real gauges from chart_utils.draw_gauge() would require matplotlib import-time cost in the smoke fixture; the 1×1 PNG is sufficient to prove the CID bundle path because composer.collect_email_inline_images only checks isinstance(b64, str) and b64.strip(). The rendered email body is structurally correct (4 cid:{module_id}_gauge references); visual gauge inspection is the job of a live-Tenable run, not a fixture-only smoke."
  - "Stub-panel fallback retained as defensive log-warn branch (not deleted): if a future regression broke render_email_panel for ALL four migrated modules, the smoke would fall through to stub HTML rather than emitting an empty body — and a logger.warning fires on the way through. Defensive belt-and-braces; should never trigger in normal operation."
  - "W7 comment phrasing: the W7 explanatory comments in both files describe the forbidden inline f-string spec without using its literal characters (the regex `f\"\\{pct:\\.1f\\}%\"` returns 0 matches across both files). This avoids a false-positive on the W7 verify regex while keeping the explanation legible to humans."

patterns-established:
  - "Phase 3 contract regression suite as standalone script: tests/test_phase2_composer_pipeline.py is invoked directly via `python tests/test_phase2_composer_pipeline.py`, prints `Result: 10/10 passed`, and exits 0. No pytest dependency. The CHECKS list is the single registration point for new checks; appending a new check is a single-line edit."
  - "Off-network smoke as Phase 3 contract gate: scripts/smoke_email_phase2.py with --dry-run renders the full email body + a synthetic PDF without any network calls (no TenableIO, no SMTP), so the Phase 3 panel-rendering path can be smoke-tested in CI or on a laptop without credentials. The script is the canonical \"does my Phase 3 panel render\" check."

requirements-completed: [QUALITY-02]

# Metrics
duration: ~25min
completed: 2026-05-06
---

# Phase 3 Plan 03-06: Phase 3 Regression Suite Extension Summary

**Phase 3 contract is locked: tests/test_phase2_composer_pipeline.py extended with three new Phase 3 checks (zero-row × 4 real module classes × 3 renderers = 12 zero-input render assertions, all proven non-raising; populated four-channel happy-path × 4 modules; bundle email_inline_images key contract). scripts/smoke_email_phase2.py drives real render_email_panel output from the four migrated modules off-network. Both fixtures use the W7 safe_pct(pct) pattern. Total runtime ~0.9s (well under the 30s T-03-06-02 cap). Phase 2 7/7 baseline continues to pass — no rebaseline required.**

## Performance

- **Duration:** ~25 minutes
- **Started:** 2026-05-06T19:23Z (post Plan 03-05 merge)
- **Completed:** 2026-05-06T20:45Z (approx)
- **Tasks:** 2
- **Files modified:** 2 (tests/test_phase2_composer_pipeline.py, scripts/smoke_email_phase2.py)
- **Test runtime:** ~0.9s wall (well under T-03-06-02's 30s cap)

## Accomplishments

- **QUALITY-02 acceptance gate** — `check_8_phase3_zero_row_render_methods` exercises all FOUR REAL migrated module classes (ScanCoverageSLAModule, CriticalRemediationSLAModule, HighRiskAssetsModule, AgedVulnsAssetsModule) against an empty `ModuleData` fixture (12 zero-input render assertions: 4 modules × {`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`}). Every render method handles the zero-row input without raising and returns the contracted empty/N-A representation.
- **Populated four-channel coverage** — `check_9_phase3_populated_render_methods` asserts each migrated module produces:
  - A non-empty email panel referencing `cid:{module_id}_gauge` with the correct `width:620px` D-02 horizontal-split shape and an interpolated driver narrative;
  - Exactly one `(sheet_name, DataFrame)` tuple from `render_analyst_tabs` with a deterministic round-trip;
  - A non-gray RAG cell from `render_rag_strip_entry` (rag_color != STATUS_COLOR['no_data']).
- **Bundle-key contract** — `check_10_phase3_bundle_email_inline_images_key` asserts `ReportComposer.run_full_pipeline` source references the new `email_inline_images` key (Plan 03-01 D-04) and the public `collect_email_inline_images` accessor returns `[]` for empty results.
- **Smoke script real-render upgrade** — `scripts/smoke_email_phase2.py` replaces the stub-panel injection with `_build_smoke_module_data`-driven populated `ModuleData` fixtures so the four migrated modules render their actual `render_email_panel` output. Smoke runs off-network (no TenableIO, no network calls), produces a 19,654-char rendered email body that contains all four `cid:{module_id}_gauge` references, and writes the synthetic PDF via the existing `composer.assemble_pdf` path.
- **W7 fixture pattern locked** — Both `check_9` and `_build_smoke_module_data` use `safe_pct(pct)` for `headline_value_str` (CLAUDE.md Empty-data guard pattern rule 1). The forbidden inline percent-precision f-string spec literal does not appear in either file (`grep -nE 'f"\{pct:\.1f\}%"'` returns 0 matches across both).
- **Phase 2 baseline preserved** — All 7 existing Phase 2 checks continue to pass without modification. The W3 deprecated aliases shipped by Plan 03-01 (`_PDF_RAG_STRIP_TEMPLATE = _PDF_UNIFIED_COVER_TEMPLATE`, `_build_rag_strip_page = _build_unified_cover_page`) made the cover-hash rebaseline unnecessary — `check_3_page2_strip_and_cover_stability` continues to pass against the unified cover output. The Phase 2 cover-hash rebaseline was NOT required.

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend tests/test_phase2_composer_pipeline.py with Phase 3 zero-row + populated + bundle-key coverage** — `5a7949f` (test)
2. **Task 2: Update scripts/smoke_email_phase2.py to consume real render_email_panel output** — `e024d3e` (test)

## Files Created/Modified

- `tests/test_phase2_composer_pipeline.py` —
  - Added imports for the four real migrated module classes (`ScanCoverageSLAModule`, `CriticalRemediationSLAModule`, `HighRiskAssetsModule`, `AgedVulnsAssetsModule`) plus `NO_DATA_HEADLINE`, `NO_DATA_DRIVER`, `STATUS_COLOR` from `rag_utils`, plus `safe_pct` from `format_utils` (W7).
  - Added `check_8_phase3_zero_row_render_methods` — QUALITY-02 zero-row coverage; 4 modules × 3 renderers = 12 zero-input assertions.
  - Added `check_9_phase3_populated_render_methods` — happy-path coverage with `safe_pct(pct)` fixture (W7).
  - Added `check_10_phase3_bundle_email_inline_images_key` — Plan 03-01 bundle contract via `inspect.getsource` + `collect_email_inline_images([])`.
  - Appended three new `(name, function)` entries to the `CHECKS` list. The existing 7 Phase 2 check functions were not modified.
- `scripts/smoke_email_phase2.py` —
  - Added imports for the four real migrated module classes + `ModuleData`/`ModuleConfig` + `build_rag_strip_entry` + `safe_pct` (W7).
  - Added `_build_smoke_module_data` helper that constructs a populated `ModuleData` fixture per module class (1×1 transparent PNG in `metadata['email_gauge_b64']` so the populated path is exercised).
  - Rewrote `_build_synthetic_outputs` to drive `composer.assemble_email_body(smoke_results)` + `composer.collect_email_inline_images(smoke_results)` instead of injecting stub HTML. The legacy stub-panel fallback is retained as a defensive `logger.warning` branch only.
  - Added `# Phase 3 D-01:` comment block above the `assemble_pdf` call (already present from Plan 03-01; unchanged).

## Decisions Made

- **W7 fixture pattern locked** — both `check_9` and `_build_smoke_module_data` use `safe_pct(pct)` for `headline_value_str`. Even though `pct` is a known float in fixture code, fixture code is what new contributors copy; modelling the wrong pattern (an inline percent-precision f-string spec) would propagate the bug to every module's tests.
- **Real-class coverage over stub-class coverage** — `check_8` instantiates the FOUR REAL migrated module classes (T-03-06-01 mitigation). Stubs would mask empty-data crashes inside the real modules' render methods. The added pandas/numpy/openpyxl import-time overhead is amortized across all 10 checks; total runtime is ~0.9s.
- **`check_10` uses `inspect.getsource` + accessor invocation** rather than a full `run_full_pipeline` call. The structural contract (the bundle key string literal exists in the source) plus an accessor smoke (empty input → empty list) cover the contract without requiring temp-dir setup, mock module instantiation, slug regex satisfaction, and PDF rendering.
- **Smoke fixture uses a 1×1 transparent PNG** for `metadata['email_gauge_b64']` rather than a real `chart_utils.draw_gauge()` output. Real gauges would import matplotlib at fixture-build time; the 1×1 PNG is sufficient because `composer.collect_email_inline_images` only checks `isinstance(b64, str) and b64.strip()`. Visual gauge inspection is the job of a live-Tenable run, not a fixture-only smoke.
- **Stub-panel fallback retained as defensive `logger.warning` branch.** If a future regression broke `render_email_panel` for all four migrated modules, the smoke would fall through to stub HTML rather than emit an empty body — and a `logger.warning` fires on the way through. Defensive belt-and-braces; should never trigger in normal operation.
- **W7 comment phrasing avoids the literal forbidden pattern characters.** The W7 explanatory comments describe the forbidden inline f-string spec in prose ("an inline percent-precision f-string spec") without using its literal characters, so the W7 verify regex `f"\{pct:\.1f\}%"` returns 0 matches across both files. This avoids a false-positive on a regex that scans for the forbidden code shape.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] check_10's runtime accessor instantiation used the wrong constructor signature**
- **Found during:** Task 1 verification (initial test run)
- **Issue:** Plan 03-06 line 338 supplied `ReportComposer(module_configs=[])` for the runtime smoke check. The composer constructor is positional with `vulns_df, assets_df, report_date, module_configs` — keyword-only `module_configs=[]` raises `TypeError: __init__() missing 3 required positional arguments`.
- **Fix:** Use the existing `_make_composer()` factory (which the other 9 checks already use). With no module IDs supplied, it constructs an empty composer — the exact shape needed for the empty-results runtime check.
- **Files modified:** `tests/test_phase2_composer_pipeline.py`
- **Verification:** `python tests/test_phase2_composer_pipeline.py` passes 10/10.
- **Committed in:** `5a7949f` (Task 1 commit; the fix was applied before commit so the commit is clean).

**2. [Rule 1 - Bug] W7 explanatory comments contained the literal forbidden pattern, tripping the W7 verify regex**
- **Found during:** Task 1 acceptance verification (the W7 regex check)
- **Issue:** Three explanatory comments in `tests/test_phase2_composer_pipeline.py` contained the literal `f"{pct:.1f}%"` string (as a "do not do this" example). The plan's acceptance criterion `grep -nE 'f"\{pct:\.1f\}%"'` returns 0 matches treats the literal string as forbidden code regardless of whether it appears in code or comments.
- **Fix:** Rewrote the three comments to describe the forbidden shape in prose ("an inline percent-precision f-string spec") rather than reproducing it verbatim. Meaning preserved; the W7 regex now returns 0 matches.
- **Files modified:** `tests/test_phase2_composer_pipeline.py`
- **Verification:** `grep -nE 'f"\{pct:\.1f\}%"' tests/test_phase2_composer_pipeline.py` returns 0 matches.
- **Committed in:** `5a7949f` (Task 1 commit; same commit as the fix).

---

**Total deviations:** 2 auto-fixed (both Rule 1 bug-class — plan-text typos / oversight; both fixed before the Task 1 commit landed).
**Impact on plan:** None — both fixes were required for Task 1 to satisfy its own acceptance criteria. No scope creep; no Phase 2 regression.

## Issues Encountered

- The plan's `inspect.getsource` assertion in `check_10` would have been more robust as `assert "email_inline_images" in inspect.getsource(...)` rather than asserting structural contracts via string-search; in practice a single-key-literal check is enough for the Plan 03-01 bundle contract because Plan 03-01 ships an exhaustive 8-key bundle test in `check_1_bundle_shape`. `check_10` is the surface area test — it asserts the new key is wired in `run_full_pipeline` and the public accessor is exposed.
- The smoke script's `--save-html` argument cannot be passed as a Windows `$env:TEMP\...` path through PowerShell because Python's argparse receives the literal string `:TEMP\...` (the leading drive letter is consumed as part of the variable expansion). Workaround: use absolute paths or run the script directly from a `cmd.exe` shell. Not a regression — pre-existing behavior of the script.

## Excel Zero-Row Standardisation Regression Diff (D-16) — Consolidated Across 03-02..05

D-16 mandated that every module's `render_excel_tabs` emit a 1-row "No data in scope" sheet on empty data. Pre-Phase-3 some modules skipped their tab on empty data; post-Phase-3 they emit a uniform 1-row tab.

| Module | Pre-Phase-3 empty behavior | Post-Phase-3 empty behavior | Plan |
|--------|----------------------------|-----------------------------|------|
| `scan_coverage_sla` | Sheet present with KPI block (None values) + empty BU breakdown table — structurally non-empty but content-empty | Single "No data in scope" cell at A1 | 03-02 |
| `critical_remediation_sla` | Sheet present with KPI block (None values) + empty BU breakdown table | Single "No data in scope" cell at A1 | 03-03 |
| `high_risk_assets` | Sheet present with KPI block (None values) + empty BU breakdown table | Single "No data in scope" cell at A1 | 03-04 |
| `aged_vulns_assets` | Sheet present with KPI block (None values) + empty BU breakdown table | Single "No data in scope" cell at A1 | 03-05 |

**Live-Tenable Excel diff regression** — when a real Tenable export hits the all-empty path for any of these four modules (e.g. an "Owner=Configuration Mangement" tag-filter typo that filters to zero rows), the Excel tab is now uniform across all four modules. Phase 3 UAT should confirm against a real export that the four tabs render the standardized 1-row "No data in scope" sheet rather than the old structurally-non-empty content-empty layout. Phase 2 UAT test 3 protocol applies.

## Phase 2 Cover-Hash Rebaseline Outcome — NOT NEEDED

Plan 03-06 carried an A5 contingency to rebaseline the Phase 2 `check_3_page2_strip_and_cover_stability` cover-region hash if Plan 03-01's unified-cover rework changed the rendered HTML beyond what the W3 deprecated aliases (`_PDF_RAG_STRIP_TEMPLATE = _PDF_UNIFIED_COVER_TEMPLATE`, `_build_rag_strip_page = _build_unified_cover_page`) absorbed.

**Outcome: rebaseline NOT required.** `check_3` asserts:
1. Both runs render identical HTML (deterministic) — **passes** (W3 alias preservation kept the outer template stable);
2. The literal substring `<div class="rag-strip">` is present — **passes** (Plan 03-01 nested `.rag-strip` inside `.report-cover` for exactly this reason; documented as Deviation #2 in 03-01-SUMMARY);
3. The literal substring `Risk Status Summary` is present — **passes** (Plan 03-01 retained the strip header text);
4. `<div class="rag-strip">` appears AFTER `<div class="report-cover">` — **passes** (the nested-div restructure preserves the textual ordering: `.report-cover` opens first, then the inner `.rag-strip` follows in source order);
5. Cover region hash is byte-stable across runs — **passes** (Plan 02-04 already locked timestamp determinism via the frozen `report_date` string).

The W3 alias preservation strategy worked as designed. Phase 3 is the cleanup window for the W3 deprecated aliases per Plan 03-01's `key-decisions` note, but Plan 03-06 explicitly does NOT remove them — that's a separate cleanup item carried into Phase 4 (or a deferred-items entry). Removing the aliases would force a cover-hash rebaseline; keeping them keeps the regression bar green.

## W7 Fixture Pattern (Locked)

Both `check_9_phase3_populated_render_methods` and `_build_smoke_module_data` use `safe_pct(pct)` for `headline_value_str`:

```python
# tests/test_phase2_composer_pipeline.py — check_9 fixture
rag_strip = build_rag_strip_entry(
    display_name       = instance.DISPLAY_NAME,
    headline_value_str = safe_pct(pct),   # ✓ W7 — None/NaN-safe
    status             = status,
)

# scripts/smoke_email_phase2.py — _build_smoke_module_data fixture
rag_strip = build_rag_strip_entry(
    display_name       = instance.DISPLAY_NAME,
    headline_value_str = safe_pct(pct),   # ✓ W7 — None/NaN-safe
    status             = status,
)
```

The forbidden inline percent-precision f-string spec literal does not appear in either file. Verification:

```bash
grep -nE 'f"\{pct:\.1f\}%"' tests/test_phase2_composer_pipeline.py    # 0 matches
grep -nE 'f"\{pct:\.1f\}%"' scripts/smoke_email_phase2.py             # 0 matches
```

## Smoke Script Status — Off-Network, Real-Panel Rendering Confirmed

`scripts/smoke_email_phase2.py --dry-run --save-html <path>`:

- **Off-network:** No `TenableIO` / `tio.` references. The script imports `from tenable.io import TenableIO` is NOT performed; the only Tenable-adjacent import (the migrated module classes) does not trigger any network call at instantiation.
- **Real-panel rendering:** The 4 migrated module classes' `render_email_panel` methods are called directly via `composer.assemble_email_body(smoke_results)`. The rendered email body is 19,654 chars and contains exactly 4 `cid:{module_id}_gauge` references (one per migrated module).
- **CID inline-image collection:** `composer.collect_email_inline_images(smoke_results)` returns 4 entries, one per module, with the synthetic 1×1 transparent PNG payload.
- **Synthetic PDF:** Rendered via the existing `composer.assemble_pdf` path (Plan 03-01's unified RAG-strip cover); written to `%TEMP%/phase2_smoke.pdf`.
- **Stub-panels fallback:** Retained as a defensive `logger.warning` branch only — never triggers in normal operation now that all four modules implement `render_email_panel`.

## Threat Flags

None — Plan 03-06 introduces no new security-relevant surface beyond what's documented in the plan's `<threat_model>`. T-03-06-01 (test-bypass via stub modules) is mitigated by check_8 instantiating real module classes; T-03-06-02 (DoS via slow tests) is well within budget at ~0.9s actual runtime.

## Phase 2 UAT Test 3 Protocol — Next Step

Per CONTEXT line 239, the next step after Phase 3 ships is a live-Tenable run to confirm:

1. **RAG strip cells show real values** — page 1 of the board PDF carries a unified RAG-strip cover with four cells (one per migrated module), each showing a real percentage headline and the correct RAG color/label/icon.
2. **Email panels render in real clients** — the 4 per-module panels with CID inline gauges render in Outlook desktop (Word render engine), Outlook web, Gmail web, and Apple Mail.
3. **Analyst workbook lands as an attachment** — the analyst companion `.xlsx` arrives alongside the main Excel + PDF + email body.
4. **Excel zero-row standardisation diff** — for any group whose tag filter scopes to zero rows for any of the four migrated modules, the corresponding Excel tab carries the standardized 1-row "No data in scope" cell rather than the prior structurally-non-empty content-empty layout.

The off-network smoke script (`scripts/smoke_email_phase2.py --dry-run`) has confirmed (1) and (2) for HTML structure off-network; live-Tenable UAT closes the loop on real-data rendering.

## Next Phase Readiness

- Phase 3 contract is locked: 10/10 checks pass; both Phase 2 baseline and Phase 3 extensions covered.
- W3 deprecated aliases (`_PDF_RAG_STRIP_TEMPLATE`, `_build_rag_strip_page`) carried forward as Phase 4 cleanup item; their removal would force a cover-hash rebaseline of `check_3`.
- The four migrated board modules (`scan_coverage_sla`, `critical_remediation_sla`, `high_risk_assets`, `aged_vulns_assets`) have full Phase 3 four-channel contract coverage in the regression suite.
- Smoke script is ready for off-network CI invocation and quick laptop-side smoke between live-Tenable runs.
- Phase 4 v2 work (YAML-driven module composition; `management_summary` / `ops_remediation` migrations) inherits the regression suite as a contract guard for any new migrations or new module additions — the `CHECKS` list is the single registration point.

---
*Phase: 03-board-summary-module-migration*
*Completed: 2026-05-06*

## Self-Check: PASSED

- File `03-06-SUMMARY.md` exists at `.planning/phases/03-board-summary-module-migration/`.
- Both task commits exist on `main`:
  - `5a7949f` — test(03-06): extend regression suite with Phase 3 zero-row + populated + bundle-key coverage
  - `e024d3e` — test(03-06): drive smoke script with real render_email_panel output from migrated modules
- Modified files (`tests/test_phase2_composer_pipeline.py`, `scripts/smoke_email_phase2.py`) both exist.
- Phase 2 + Phase 3 regression suite passes 10/10 (`python tests/test_phase2_composer_pipeline.py` exits 0; total runtime ~0.9s, well under T-03-06-02's 30s cap).
- Smoke script runs to completion off-network and emits 4 real CID inline-gauge entries (one per migrated module).
