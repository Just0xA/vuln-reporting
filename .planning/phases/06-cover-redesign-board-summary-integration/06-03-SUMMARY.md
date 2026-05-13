---
phase: 06-cover-redesign-board-summary-integration
plan: 03
subsystem: reports.board_summary
tags: [chrome, pdf, board_summary, privacy_label, scope_subtitle, phase6]
requires:
  - reports/modules/pdf_chrome.py            # Phase 5 PdfChromeConfig (consumed)
  - reports/modules/composer.py              # Phase 6 plan 01 pdf_chrome wire (consumed)
provides:
  - "board_summary.run_report() privacy_label='Confidential' kwarg"
  - "board_summary.run_report() scope_subtitle=None kwarg"
  - "PdfChromeConfig assembled with all 6 fields and passed via pdf_chrome= to ReportComposer"
affects:
  - reports/board_summary.py
  - reports/modules/composer.py
  - tests/test_phase6_board_summary_chrome.py
  - tests/test_phase6_cover_redesign.py
tech-stack:
  added: []
  patterns:
    - "Inlined _format_scope_subtitle (D-02) — circular import fallback authorized by plan"
    - "Single resolved_subtitle string feeds BOTH cover-body and PdfChromeConfig.subtitle"
    - "_build_unified_cover_page signature pruned to (results, subtitle=...) — completes 06-02 deferred cleanup"
key-files:
  created:
    - tests/test_phase6_board_summary_chrome.py
  modified:
    - reports/board_summary.py
    - reports/modules/composer.py
    - tests/test_phase6_cover_redesign.py
decisions:
  - "D-02 honored: subtitle is value-only; 'All assets' (sentence case) when no tag filter"
  - "CHROME-INT-01 + CHROME-INT-02 satisfied: board_summary is the first production consumer of PdfChrome"
  - "_format_scope_subtitle inlined (NOT imported from run_all) — circular import detected, plan authorized the fallback"
  - "Composer cleanup deferred from plan 06-02 ('Caller Cleanup Deferred') executed here: title/generated_at_str/module_list_str pruned from _build_unified_cover_page"
metrics:
  completed: 2026-05-13
  tasks: 2
  commits: 2
requirements:
  - CHROME-INT-01
  - CHROME-INT-02
---

# Phase 6 Plan 03: board_summary privacy_label + PdfChromeConfig Integration Summary

Wires `board_summary.run_report()` as the first production consumer of the Phase 5 PDF chrome utility. Adds `privacy_label` (default `"Confidential"`) and `scope_subtitle` (default `None`) kwargs, resolves the scope subtitle via a single source of truth (`_format_scope_subtitle`), constructs `PdfChromeConfig` with all six fields, and passes it via `pdf_chrome=` into `ReportComposer(...)`. Cover-page method signature cleanup deferred by plan 06-02 is completed here as part of the rewire (Karpathy §3). `management_summary.py` and `ops_remediation.py` remain untouched per CHROME-COMPAT-01.

## Tasks Completed

| Task | Name                                                          | Commit  | Files                                                                                  |
| ---- | ------------------------------------------------------------- | ------- | -------------------------------------------------------------------------------------- |
| 1    | Wire PdfChromeConfig + prune unused cover params              | 2e668a4 | reports/board_summary.py, reports/modules/composer.py, tests/test_phase6_cover_redesign.py |
| 2    | Unit tests — privacy_label + scope_subtitle propagation       | dc03775 | tests/test_phase6_board_summary_chrome.py                                              |

## Exact Changes — `reports/board_summary.py`

### Imports added

```python
from config import CACHE_DIR, HEADER_BG_COLOR, LOGO_PATH, OUTPUT_DIR
from reports.modules.pdf_chrome import PdfChromeConfig

def _format_scope_subtitle(tc: str | None, tv: str | None) -> str:
    return tv if (tc and tv) else "All assets"
```

`HEADER_BG_COLOR` / `LOGO_PATH` merged into the existing `from config import ...` line; `PdfChromeConfig` added alongside the other `reports.modules` imports.

### Signature change

```python
def run_report(
    tio, run_id, *,
    tag_category:   Optional[str]      = None,
    tag_value:      Optional[str]      = None,
    output_dir:     Optional[Path]     = None,
    generated_at:   Optional[datetime] = None,
    cache_dir:      Optional[Path]     = None,
    analyst_detail: bool               = True,
    privacy_label:  str                = "Confidential",   # NEW
    scope_subtitle: Optional[str]      = None,             # NEW
) -> dict:
```

### Subtitle resolution + PdfChromeConfig construction (replaced lines 220-244)

```python
resolved_subtitle = (
    scope_subtitle
    if scope_subtitle is not None
    else _format_scope_subtitle(tag_category, tag_value)
)

scope_label = (
    f"{tag_category} = {tag_value}"
    if tag_category and tag_value
    else "All Assets"
)   # D-19 — UNCHANGED

pdf_chrome_cfg = PdfChromeConfig(
    title         = _REPORT_TITLE,
    subtitle      = resolved_subtitle,
    generated_at  = generated_at,
    header_bg     = HEADER_BG_COLOR,
    logo_path     = LOGO_PATH,
    privacy_label = privacy_label,
)

composer = ReportComposer(
    vulns_df       = vulns_df,
    assets_df      = assets_df,
    report_date    = generated_at,
    module_configs = _BOARD_MODULE_CONFIGS,
    fixed_vulns_df = fixed_vulns_df,
    pdf_chrome     = pdf_chrome_cfg,    # NEW — CHROME-INT-01
)
```

`pdf_subtitle=resolved_subtitle` is also threaded into `composer.run_full_pipeline(...)` so the cover-body subtitle line and `PdfChromeConfig.subtitle` always agree (D-02 single source of truth — one string, two render channels).

## `_format_scope_subtitle` — Import vs Inline Decision

Plan 06-03 Task 1 step 1 specified:

> The IMPLEMENTOR must verify: try the import first; if `python -c "import reports.board_summary"` raises ImportError, inline the formatter.

**Verification:**

```
$ python -c "import reports.board_summary; print('OK')"
KeyError: 'reports.board_summary'
```

The circular import triggered immediately — `run_all.py`'s top-level imports (`config`, `data.fetchers`, `delivery.*`, etc.) drag the project into a partially-initialized state before `reports.board_summary` can complete its own initialization. Per the plan's authorization, the formatter was inlined as a module-level helper in `reports/board_summary.py` (a verbatim copy of the run_all definition):

```python
def _format_scope_subtitle(tc: str | None, tv: str | None) -> str:
    """Value-only scope subtitle per D-02..."""
    return tv if (tc and tv) else "All assets"
```

Behavior is identical to `run_all._format_scope_subtitle`; one logical formatter, two physical definitions until run_all's top-level imports get slimmed (out of scope here — documented inline).

## Composer Cleanup — Caller Pruning Completed

Plan 06-02 SUMMARY noted under "Caller Cleanup Deferred":

> `_build_unified_cover_page`'s `title`, `generated_at_str`, and `module_list_str` parameters are now unused inside the method body... full signature pruning is plan 06-03's natural scope when board_summary re-wires the call site for chrome opt-in.

Completed here per Karpathy §3 (clean up YOUR mess at the rewire point):

**`assemble_pdf()` (composer.py ~684-708):**
- Removed the `generated_at_str = self._report_date.strftime(...)` computation (now lives in `PdfChromeConfig.generated_at`).
- Removed the `module_list_str = ", ".join(...)` line (was only used for the cover Sections: line, which 06-02 removed).
- Simplified the subtitle fallback from `f"Scope: All Assets  |  Generated {generated_at_str}"` to `"Scope: All Assets"` (the per-page chrome footer now carries the generated timestamp).
- `_build_unified_cover_page(...)` call site reduced from 5 keyword args to 2 (`results`, `subtitle`).

**`_build_unified_cover_page()` (composer.py ~753-770):**
- Signature pruned to `(self, results: list[ModuleData], *, subtitle: str) -> str`.
- Docstring updated to reflect the slimmed contract.
- Class-level alias `_build_rag_strip_page = _build_unified_cover_page` preserved (W3 safety net).

**Test caller fix:** `tests/test_phase6_cover_redesign.py::test_built_cover_renders_scope_subtitle` updated to the new 2-arg signature.

## Tests Added — 6 PASS

`tests/test_phase6_board_summary_chrome.py`:

| Test                                                         | Asserts                                                                                       |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `test_run_report_signature_has_new_kwargs`                   | `privacy_label.default == "Confidential"`, `scope_subtitle.default is None`                   |
| `test_subtitle_defaults_to_all_assets_when_no_filter`        | `cfg.subtitle == "All assets"` when no tag filter (D-02)                                      |
| `test_subtitle_is_value_only_when_filter_set`                | `cfg.subtitle == "Production"` (not "Environment = Production") — D-02 value-only             |
| `test_explicit_scope_subtitle_overrides_fallback`            | Explicit kwarg wins over tag-derived fallback                                                 |
| `test_privacy_label_defaults_to_confidential`                | `cfg.privacy_label == "Confidential"` when kwarg omitted                                      |
| `test_privacy_label_override_propagates`                     | `cfg.privacy_label == "Internal Only"` reaches `PdfChromeConfig` verbatim                     |

Pass evidence:

```
tests/test_phase6_board_summary_chrome.py::test_run_report_signature_has_new_kwargs PASSED
tests/test_phase6_board_summary_chrome.py::test_subtitle_defaults_to_all_assets_when_no_filter PASSED
tests/test_phase6_board_summary_chrome.py::test_subtitle_is_value_only_when_filter_set PASSED
tests/test_phase6_board_summary_chrome.py::test_explicit_scope_subtitle_overrides_fallback PASSED
tests/test_phase6_board_summary_chrome.py::test_privacy_label_defaults_to_confidential PASSED
tests/test_phase6_board_summary_chrome.py::test_privacy_label_override_propagates PASSED
============================== 6 passed in 0.93s ==============================
```

### Cross-plan regression sweep

```
tests/test_phase6_composer_chrome.py    3 passed
tests/test_phase6_cover_redesign.py     6 passed   (1 test updated for slimmed signature)
tests/test_phase6_board_summary_chrome.py  6 passed (NEW)
                                       ---
Total                                    15 passed
```

## Compat Compass — Files Verified Untouched

```
$ git diff --stat reports/management_summary.py reports/ops_remediation.py reports/modules/pdf_chrome.py
(empty — no changes)
```

CHROME-COMPAT-01 satisfied: the two existing report consumers and the Phase 5 utility itself are byte-identical to pre-plan state.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] `from run_all import _format_scope_subtitle` circular**
- **Found during:** Task 1 verification (`python -c "import reports.board_summary"`).
- **Issue:** Plan-recommended import raised `KeyError: 'reports.board_summary'` (circular import via run_all's top-level imports).
- **Fix:** Inlined the one-line formatter per the plan's explicit fallback authorization (Task 1, step 1). Behavior identical to run_all's version.
- **Files:** `reports/board_summary.py`.
- **Commit:** 2e668a4.

**2. [Rule 1 — Bug] `tests/test_phase6_cover_redesign.py` called pruned signature**
- **Found during:** Post-Task 1 regression sweep.
- **Issue:** Plan 06-02's test passed `title=`, `generated_at_str=`, `module_list_str=` to `_build_unified_cover_page` — which this plan prunes. Test raised `TypeError: ... got an unexpected keyword argument 'title'`.
- **Fix:** Updated the test to the new 2-arg signature (`subtitle="Production"` only). All other assertions preserved.
- **Files:** `tests/test_phase6_cover_redesign.py`.
- **Commit:** 2e668a4.

**3. [Rule 3 — Blocking] Empty-DataFrame column-drop in `_filter_assets_by_tag`**
- **Found during:** Task 2 test runs (`test_subtitle_is_value_only_when_filter_set`).
- **Issue:** Pandas drops columns when boolean-masking a zero-row DataFrame, so the test's stub `assets_df = pd.DataFrame(columns=["asset_uuid","tags"])` made `_filter_assets_by_tag` return a column-less frame, which then `KeyError`'d on `filtered_assets["asset_uuid"]`.
- **Fix:** Gave each stub frame one dummy row (`asset_uuid="x"`, `tags=""`) so the filter path returns a properly-shaped (still-empty) result. Inline comment in the test explains the pandas quirk.
- **Files:** `tests/test_phase6_board_summary_chrome.py`.
- **Commit:** dc03775.

**4. [Rule 3 — Blocking] `tests/` is gitignored**
- **Issue:** `.gitignore` excludes `tests/`; first `git add` rejected.
- **Fix:** Used `git add -f` (Phase 5 + plans 06-01/06-02 precedent).
- **Commit:** 2e668a4 + dc03775.

### TDD Gate Note

Task 2 was marked `tdd="true"` but executes AFTER Task 1, so all 6 tests pass green on first run rather than failing RED first. Same pattern as plan 06-01 SUMMARY Task 3 — behavior coverage is achieved regardless of execution order.

## Threat Mitigations Applied

| Threat ID | Mitigation                                                                                                                                                                                                                                                                                              |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-06-04   | Accepted upstream — `PdfChromeConfig.__post_init__` (Phase 5) validates `privacy_label` against the regex; this plan trusts the dataclass. Defense-in-depth at the YAML schema layer is plan 06-04's responsibility.                                                                                       |
| T-06-05   | Accepted — `scope_subtitle` surfaces the operator-supplied tag value in the chrome header. Already visible to recipients via report content; no new disclosure surface.                                                                                                                                  |

## Out-of-Scope / Deferred

- **`run_all.run_group()` wiring `privacy_label` + `scope_subtitle` from `delivery_config.yaml` into the `slug == "board_summary"` kwarg block** — Plan 06-04.
- **YAML schema regex `^[^"]+$` for `privacy_label`** — Plan 06-04.
- **Baseline regen + visual UAT (Outlook/Gmail/Apple Mail render confirmation)** — Plan 06-05.
- **De-duplicating `_format_scope_subtitle` (currently defined in both `run_all.py` and `reports/board_summary.py`)** — blocked on a separate refactor of run_all.py's top-level imports; explicitly out of scope per Karpathy §3.
- **`reports/management_summary.py`, `reports/ops_remediation.py`, `reports/modules/pdf_chrome.py`** — UNTOUCHED (CHROME-COMPAT-01), verified by `git diff --stat`.
- **Pre-existing `tests/test_modules_level1.py` `sys.exit()` at import** — pre-existing, unrelated; not in scope.

## Self-Check

- [x] `reports/board_summary.py` — modified, committed (2e668a4). Two new kwargs, two new imports, PdfChromeConfig constructed and passed via `pdf_chrome=`.
- [x] `reports/modules/composer.py` — modified, committed (2e668a4). `_build_unified_cover_page` signature pruned; `assemble_pdf` caller updated.
- [x] `tests/test_phase6_board_summary_chrome.py` — created, 6 tests pass, committed (dc03775).
- [x] `tests/test_phase6_cover_redesign.py` — updated for pruned signature, 6 tests pass, committed (2e668a4).
- [x] Commits 2e668a4, dc03775 present in `git log --oneline -5`.
- [x] `reports/modules/pdf_chrome.py` — UNTOUCHED.
- [x] `reports/management_summary.py`, `reports/ops_remediation.py` — UNTOUCHED.
- [x] Cross-plan regression: 15/15 Phase 6 tests pass.
- [x] Signature verification (`inspect.signature`) confirms `privacy_label='Confidential'` / `scope_subtitle=None` defaults.

## Self-Check: PASSED
