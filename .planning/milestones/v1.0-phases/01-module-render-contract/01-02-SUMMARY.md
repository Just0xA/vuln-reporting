---
phase: 01-module-render-contract
plan: 02
subsystem: module-infrastructure
tags:
  - module-infrastructure
  - basemodule-contract
  - render-contract

# Dependency graph
requires:
  - phase: 01-module-render-contract
    plan: 01
    provides: "reports/modules/rag_utils.py (STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE, NO_DATA_DRIVER, build_rag_strip_entry, rag_status_from_value); reports/modules/format_utils.py (safe_pct, safe_int, safe_format)"
provides:
  - "BaseModule.render_email_panel(data, config) -> str — concrete no-op default returning ''"
  - "BaseModule.render_analyst_tabs(data, config) -> list[tuple[str, pd.DataFrame]] — concrete no-op default returning []"
  - "BaseModule.render_rag_strip_entry(data, config) -> dict — concrete no-op default returning gray 'No Data' cell"
  - "ModuleData.driver_narrative: str = '' — populated inside compute(), consumed by render_email_panel"
  - "ModuleData.analyst_rows: list[tuple[str, pd.DataFrame]] = field(default_factory=list) — populated inside compute(), consumed by render_analyst_tabs"
  - "ModuleData.rag_strip: dict = field(default_factory=dict) — pre-built strip cell, consumed by composer assemble_pdf cover-page strip"
  - "BaseModule._empty_result() now populates driver_narrative=NO_DATA_DRIVER, analyst_rows=[], rag_strip=gray cell"
  - "reports.modules package re-exports nine new helper symbols (safe_pct, safe_int, safe_format, STATUS_COLOR, STATUS_LABEL, rag_status_from_value, build_rag_strip_entry, NO_DATA_HEADLINE, NO_DATA_DRIVER) BEFORE registry.discover()"
affects:
  - "Phase 02 (composer upgrades — assemble_pdf cover-page strip, assemble_email_body per-module panels, assemble_analyst_workbook per-module tabs all consume the new render methods + ModuleData fields)"
  - "Phase 03 (board metric module migrations override the three new render methods to populate driver_narrative / analyst_rows / rag_strip per CONTRACT-01..03)"
  - "Plan 01-03 (QUALITY-01 / QUALITY-03 audit fixes import safe_pct via the new package re-export)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Deferred-import pattern with `# noqa: PLC0415` for circular-import safety: `from reports.modules.rag_utils import ...` inside method bodies of BaseModule.render_rag_strip_entry and BaseModule._empty_result"
    - "Phase 1 dataclass field-ordering: new fields (with defaults) inserted BEFORE existing `error` field, with `error` itself gaining `= None` default to satisfy Python dataclass ordering rules (every field after the first default-bearing field must also have a default)"
    - "Helper-imports-before-registry-discover pattern in package __init__.py: format_utils + rag_utils imports MUST land before registry.discover() so future metric-module class bodies that reference helpers at decoration time see them already bound"
    - "Concrete-with-no-op-defaults render method pattern: new render methods are NOT @abstractmethod, mirrors existing render_pdf_section / render_excel_tabs at base.py:237-299"

key-files:
  created: []
  modified:
    - "reports/modules/base.py"
    - "reports/modules/__init__.py"

key-decisions:
  - "ModuleData field ordering: new fields placed BEFORE `error` (preserves the existing 'error is the last field' reading order); `error: Optional[str] = None` default added to satisfy dataclass field-ordering rules. Verified non-breaking — all 12 existing ModuleData(...) call sites use kwargs-style construction (D-06)."
  - "render_rag_strip_entry no-op default returns the literal gray 'No Data' dict {label, headline_value: '—', rag_color: '#757575', rag_label: 'No Data'}, NOT a call to build_rag_strip_entry(). The deferred import imports STATUS_COLOR / STATUS_LABEL / NO_DATA_HEADLINE directly per PATTERNS.md section 3 reference implementation. This keeps the no-op default minimal and avoids a second function call in the hot path."
  - "Both deferred imports in base.py are placed inside method bodies tagged `# noqa: PLC0415`. No top-level `from reports.modules.rag_utils import ...` — verified via grep: 0 matches at file-start, 2 matches inside method bodies (pattern-map risk #2)."
  - "Package __init__.py orders helper imports BETWEEN BaseModule (line 58) and ReportComposer (line 61), and BEFORE registry.discover() (line 67). Verified via grep: format_utils import at line 61, rag_utils import at line 64, registry.discover() at line 77 (pattern-map risk #4)."
  - "__all__ uses a single list literal with a `# Phase 1 render helpers` comment delimiter (matches existing in-file comment style)."
  - "Each new helper-import block carries its own `# noqa: F401` comment per the existing __init__.py style (not folded into the existing F401 markers on registry/base lines)."

patterns-established:
  - "Pattern 1: Concrete-no-op render contract extension. New render methods follow the exact shape of existing render_pdf_section / render_excel_tabs: not @abstractmethod, single-line return of a no-op default, full Numpydoc with Default + Contract for overrides + Returns sections."
  - "Pattern 2: Dataclass field-extension with backward-compat. When extending an existing dataclass with new fields, place them BEFORE the no-default fields and give those previously-no-default fields explicit defaults. Verify all call sites use kwargs-style construction first."
  - "Pattern 3: Sibling-helper deferred import. When a base ABC method needs a constant from a sibling helper module that may transitively import from this base file, use a `from sibling import X  # noqa: PLC0415` inside the method body, not at the top of the file."

requirements-completed:
  - CONTRACT-01
  - CONTRACT-02
  - CONTRACT-03
  - CONTRACT-04
  - CONTRACT-05

# Metrics
duration: ~10min
completed: 2026-05-05
---

# Phase 01 Plan 02: BaseModule Contract Extension Summary

**`BaseModule` now exposes the four-channel render contract — three new concrete render methods (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) with no-op defaults; `ModuleData` carries three new typed fields (`driver_narrative`, `analyst_rows`, `rag_strip`) with safe defaults; `_empty_result()` populates them with no-data sentinels; and `reports.modules` re-exports the nine Plan 01-01 helper symbols before `registry.discover()`. All eight existing registered modules continue to instantiate without code changes; the contract is now ready for Phase 2 composer upgrades and Phase 3 board-module migrations to consume in parallel.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-05-05T22:25:00Z (approx)
- **Completed:** 2026-05-05T22:35:00Z
- **Tasks:** 2 / 2 complete
- **Files created:** 0
- **Files modified:** 2

## Accomplishments

- Extended `BaseModule` with three concrete render methods (NOT `@abstractmethod`) following the exact shape of the existing `render_pdf_section` / `render_excel_tabs` no-op defaults at `reports/modules/base.py:237-299`. Each new method has full Numpydoc with `Default` + `Contract for overrides` + `Returns` sections per CONVENTIONS.md.
- Added three typed fields to `ModuleData` (`driver_narrative: str = ""`, `analyst_rows: list[tuple[str, pd.DataFrame]] = field(default_factory=list)`, `rag_strip: dict = field(default_factory=dict)`) with safe defaults so all 12 existing kwargs-style `ModuleData(...)` call sites continue to work unchanged. `error: Optional[str] = None` default added to satisfy Python dataclass field-ordering rules — verified non-breaking by Grep across all `*.py` files.
- Updated `_empty_result()` to populate the three new fields with no-data sentinels: gray 'No Data' strip cell, `NO_DATA_DRIVER = "No data in scope."` narrative, empty analyst rows. The exception path now produces a coherent strip cell instead of crashing the composer.
- Re-exported nine Plan 01-01 helper symbols from `reports/modules/__init__.py`: `safe_pct`, `safe_int`, `safe_format` from `format_utils`; `STATUS_COLOR`, `STATUS_LABEL`, `rag_status_from_value`, `build_rag_strip_entry`, `NO_DATA_HEADLINE`, `NO_DATA_DRIVER` from `rag_utils`. Both helper-import blocks land BEFORE `registry.discover()` so Phase 3+ metric-module class bodies that reference helpers at decoration time see them already bound (pattern-map risk #4).
- All deferred `from reports.modules.rag_utils import ...` imports inside `base.py` are tagged `# noqa: PLC0415` per CONVENTIONS.md (pattern-map risk #2). Zero top-level imports of `rag_utils` from `base.py` — verified via Grep.
- All 8 currently registered metric modules (`aged_vulns_assets`, `critical_remediation_sla`, `example`, `high_risk_assets`, `mttr_by_severity`, `patch_compliance_rate`, `scan_coverage_sla`, `total_vulns_by_severity`) continue to discover without errors; cross-task integration smoke test producing the full kwargs-only ModuleData with new fields populated passes.

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend BaseModule + ModuleData in `reports/modules/base.py`** — `e2e26db` (feat)
2. **Task 2: Re-export new helpers from `reports/modules/__init__.py`** — `903551d` (feat)

**Plan metadata commit:** to be created with this SUMMARY.md (single sequential-mode commit; no separate metadata-only commit needed because gsd-sdk commit routing is not on PATH on this Windows system — see `<sdk_unavailable_note>` in the executor prompt).

## Files Created

None. Plan 01-02 only modifies the two existing module-infrastructure files; the helper sibling files (`rag_utils.py`, `format_utils.py`) were created in Plan 01-01.

## Files Modified

- **`reports/modules/base.py`** (+182 / -16 lines):
  - `ModuleData` dataclass extended with `driver_narrative`, `analyst_rows`, `rag_strip` fields between `metadata` and `error`. `error` gained `= None` default. Numpydoc `Attributes` block updated with three new entries.
  - `BaseModule` class gained three new concrete render methods between `render_excel_tabs` and `render_email_kpis`. Each is a no-op default with full Numpydoc; `render_rag_strip_entry` body uses a deferred `from reports.modules.rag_utils import ...` (`# noqa: PLC0415`).
  - `BaseModule._empty_result()` body extended to populate the three new fields via a second deferred `rag_utils` import.
- **`reports/modules/__init__.py`** (+20 / -0 lines):
  - Two new helper-import blocks inserted between `BaseModule` import (line 58) and `ReportComposer` import (line 61): `from reports.modules.format_utils import safe_pct, safe_int, safe_format` and `from reports.modules.rag_utils import STATUS_COLOR, STATUS_LABEL, rag_status_from_value, build_rag_strip_entry, NO_DATA_HEADLINE, NO_DATA_DRIVER`. Both carry their own `# noqa: F401` comment.
  - `__all__` extended with nine new symbol names under a `# Phase 1 render helpers` delimiter.

## Decisions Made

All decisions were locked in `01-CONTEXT.md` (D-01..D-09, D-12, D-15) and `01-PATTERNS.md` sections 3, 4, 5; the implementation followed them exactly. Notable in-execution clarifications:

- **`render_rag_strip_entry` no-op default uses literal dict construction, not `build_rag_strip_entry()` call.** PATTERNS.md section 3 reference implementation shows the literal four-key dict; mirrored verbatim. The deferred import pulls in `STATUS_COLOR`, `STATUS_LABEL`, `NO_DATA_HEADLINE` directly. This keeps the no-op default minimal (no second function-call frame) and avoids a transitive dependency on `build_rag_strip_entry`'s behavior.
- **Field-ordering safety verified before edit.** Grep across all `.py` files in the repo confirmed every existing `ModuleData(...)` call site uses kwargs-style construction (12 sites: `aged_vulns_assets_module.py:170/248`, `base.py:413`, `composer.py:816`, `critical_remediation_sla_module.py:259`, `example_module.py:80`, `high_risk_assets_module.py:173/253`, `mttr_by_severity_module.py:332`, `patch_compliance_rate_module.py:295`, `scan_coverage_sla_module.py:244`, `total_vulns_by_severity_module.py:158`). The README example at `reports/modules/README.md:91` is documentation only. Therefore inserting new fields with defaults BEFORE `error` and giving `error` a default is non-breaking.
- **`example_module` counts in the discovery total.** Plan truths assert "≥ 7 registered modules"; current registry holds 8 (4 board + 3 management + 1 example). All 8 instantiate post-edit; well above the floor.

## Deviations from Plan

None - plan executed exactly as written.

The executor success-criteria block in the prompt mentioned a smoke test of the form `ModuleData(module_id='x', display_name='X')` with only two positional args. The plan as designed (and as implemented) keeps the original 7 ModuleData fields required (no defaults) — only the 3 new fields and `error` gained defaults per D-06 / pattern-map risk #1. The plan's own Task 1 smoke test (lines 305-309) constructs ModuleData with all 7 original kwargs, which is the canonical construction pattern in every existing call site. The literal 2-arg form would only succeed if defaults were added to all 7 original fields, which is explicitly out of scope (would change the original-field contract). Documenting here for clarity; the plan's own acceptance test passes.

---

**Total deviations:** 0
**Impact on plan:** Plan executed exactly as written; the composer upgrades that consume these contract additions are owned by Phase 2, and the board-module migrations that override the three new render methods are owned by Phase 3.

## Issues Encountered

None.

A line-ending warning (`LF will be replaced by CRLF`) appeared on each `git commit` because the project files are stored with LF line endings but the Windows working tree autocrlf setting normalizes to CRLF on checkout. This is cosmetic only — the commits land with the correct line endings as committed (LF on disk in the git object store).

## Verification Evidence

### Task 1 smoke test (from plan body)

```text
$ python -c "<full Task 1 smoke test from plan>"
OK
```

Asserts:
- `BaseModule.render_email_panel`, `BaseModule.render_analyst_tabs`, `BaseModule.render_rag_strip_entry` exist with `(self, data, config)` signature
- `ModuleData(...)` with the 7 kwargs-only original fields produces an instance whose `driver_narrative == ''`, `analyst_rows == []`, `rag_strip == {}`, `error is None`
- Independent `ModuleData()` instances do NOT share `analyst_rows` or `rag_strip` mutables (`field(default_factory=...)` not the broken `=[]` default)
- A concrete `BaseModule` subclass picks up the three no-op renderer defaults (`render_email_panel == ''`, `render_analyst_tabs == []`, `render_rag_strip_entry == gray cell`)
- `_empty_result('boom', cfg)` populates `error == 'boom'`, `driver_narrative == 'No data in scope.'`, `analyst_rows == []`, `rag_strip == gray cell`

### Task 2 smoke test (from plan body)

```text
$ python -c "<full Task 2 smoke test from plan>"
Discovered MODULE_IDs: ['aged_vulns_assets', 'critical_remediation_sla', 'example', 'high_risk_assets', 'mttr_by_severity', 'patch_compliance_rate', 'scan_coverage_sla', 'total_vulns_by_severity']
OK
```

Asserts:
- All 9 new symbols are accessible via `reports.modules.<name>` AND listed in `__all__`
- All 6 existing symbols still importable AND in `__all__`
- 8 metric modules discovered (≥ 7 floor)
- Functional sanity: `safe_pct(None) == '—'`, `safe_pct(87.4) == '87.4%'`, `STATUS_COLOR['no_data'] == '#757575'`, `NO_DATA_HEADLINE == '—'`

### Cross-task integration smoke test (from plan `<verification>` block)

```text
$ python -c "<full integration smoke test from plan>"
Registered: ['aged_vulns_assets', 'critical_remediation_sla', 'example', 'high_risk_assets', 'mttr_by_severity', 'patch_compliance_rate', 'scan_coverage_sla', 'total_vulns_by_severity']
OK
```

Asserts:
- A subclass `T(BaseModule)` constructs `ModuleData` with `driver_narrative`, `analyst_rows`, `rag_strip=build_rag_strip_entry('Test', safe_pct(87.4), 'yellow')` populated; `data.rag_strip['rag_label'] == 'At Risk'`
- Un-overridden render methods still produce no-op defaults on the populated `data` (proves the render-method overrides don't accidentally interact with `data` shape)
- Existing module discovery still works at full count

### Acceptance criteria gates (Task 1)

| Gate | Result |
|------|--------|
| `grep -c 'def render_email_panel' reports/modules/base.py` | 1 ✓ |
| `grep -c 'def render_analyst_tabs' reports/modules/base.py` | 1 ✓ |
| `grep -c 'def render_rag_strip_entry' reports/modules/base.py` | 1 ✓ |
| `grep -c '@abstractmethod' reports/modules/base.py` | 1 (only `compute()`) ✓ |
| `grep -c 'from reports.modules.rag_utils import' reports/modules/base.py` | 2 (both deferred inside method bodies) ✓ |
| `grep -c '# noqa: PLC0415' reports/modules/base.py` | 2 ✓ |
| `grep -c 'field(default_factory=list)' reports/modules/base.py` | 1 ✓ |
| `grep -c 'field(default_factory=dict)' reports/modules/base.py` | 2 (existing `ModuleConfig.options` + new `ModuleData.rag_strip`) ✓ |
| `grep '^from reports.modules.rag_utils' reports/modules/base.py` | 0 (no top-level imports) ✓ |

### Acceptance criteria gates (Task 2)

| Gate | Result |
|------|--------|
| `from reports.modules.format_utils import` import in `__init__.py` | line 61 ✓ |
| `from reports.modules.rag_utils import` import in `__init__.py` | line 64 ✓ |
| `registry.discover()` line | line 77 (after both helper imports) ✓ |
| All 9 new symbols importable via `from reports.modules import ...` | ✓ |
| All 9 new symbols listed in `__all__` | ✓ |
| 8 modules discovered (≥ 7 floor) | ✓ |

## All `must_haves.truths` verified

| Truth | Verified |
|-------|----------|
| `BaseModule.render_email_panel(data, config) -> str` exists, no-op default `''` | YES — Task 1 smoke test |
| `BaseModule.render_analyst_tabs(data, config) -> list[tuple[str, pd.DataFrame]]` exists, no-op default `[]` | YES — Task 1 smoke test |
| `BaseModule.render_rag_strip_entry(data, config) -> dict` exists, no-op default returns gray 'No Data' cell with literal headline_value `'—'` per D-08 | YES — Task 1 smoke test (`{'label': 'Stub Module', 'headline_value': '—', 'rag_color': '#757575', 'rag_label': 'No Data'}`) |
| `ModuleData` carries `driver_narrative`, `analyst_rows`, `rag_strip` with documented safe defaults | YES — Task 1 smoke test |
| Existing 7+ registered modules continue to instantiate without ModuleData call-site changes | YES — discovery test shows all 8 modules load |
| Existing kwargs-style `ModuleData(...)` call sites at the 12 sites named in the plan still typecheck and run | YES — registry.discover() succeeded with 0 errors |
| `BaseModule._empty_result()` populates the three new fields with safe defaults (gray strip cell, NO_DATA_DRIVER narrative, empty analyst rows) | YES — Task 1 smoke test asserts each field |
| `reports/modules/__init__.py` exposes the new helpers BEFORE `registry.discover()` is called | YES — line numbers 61, 64 both precede 77 |
| All deferred imports in `base.py` tagged `# noqa: PLC0415` | YES — `grep -c '# noqa: PLC0415'` returns 2 |

## Threat Flags

None.

This plan extends an in-process Python ABC contract with concrete no-op-default methods and adds three typed dataclass fields with safe defaults. No new I/O surface, no new network endpoints, no new auth paths, no new credentials, no new file access patterns, no new schema changes at trust boundaries. The deferred imports cross no security boundary. STRIDE register entries T-01-05..T-01-09 from the plan are all dispositioned `mitigate` or `accept` with mitigations explicitly verified by the smoke tests above.

## Self-Check: PASSED

- `reports/modules/base.py` exists and contains the three new render methods + three new ModuleData fields + extended `_empty_result()` — VERIFIED via `grep` and Python smoke test.
- `reports/modules/__init__.py` exists and re-exports the nine new symbols before `registry.discover()` — VERIFIED via line-number `grep` and Python smoke test.
- Commit `e2e26db` (Task 1 — `feat(01-02): extend BaseModule with 3 render methods + 3 ModuleData fields`) exists — VERIFIED via `git log` after commit.
- Commit `903551d` (Task 2 — `feat(01-02): publicize Phase 1 helpers in reports/modules/__init__.py`) exists — VERIFIED via `git log` after commit.
- All `must_haves.truths` from `01-02-PLAN.md` frontmatter verified by smoke test (table above).
- All `acceptance_criteria` blocks in both tasks satisfied (grep counts and Python smoke tests).
- All `<verification>` round-trip tests in the plan body pass.
- No modifications to `STATE.md` or `ROADMAP.md` (orchestrator owns those — sequential mode honors the executor contract).
