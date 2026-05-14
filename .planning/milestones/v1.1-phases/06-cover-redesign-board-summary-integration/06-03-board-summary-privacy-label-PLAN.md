---
phase: 06-cover-redesign-board-summary-integration
plan: 03
type: execute
wave: 3
depends_on:
  - 06-01
  - 06-02
files_modified:
  - reports/board_summary.py
  - tests/test_phase6_board_summary_chrome.py
autonomous: true
requirements:
  - CHROME-INT-01
  - CHROME-INT-02
user_setup: []
must_haves:
  truths:
    - "board_summary.run_report() accepts privacy_label (default 'Confidential') and scope_subtitle (default None) kwargs."
    - "board_summary.run_report() builds PdfChromeConfig with title, scope_subtitle (or _format_scope_subtitle fallback), generated_at (UTC), HEADER_BG_COLOR, LOGO_PATH, privacy_label."
    - "board_summary.run_report() passes pdf_chrome=cfg to ReportComposer constructor."
    - "When scope_subtitle is None and no tag filter is set, subtitle resolves to 'All assets'."
  artifacts:
    - path: "reports/board_summary.py"
      provides: "run_report wired with privacy_label + scope_subtitle kwargs; PdfChromeConfig construction"
      contains: "PdfChromeConfig"
    - path: "tests/test_phase6_board_summary_chrome.py"
      provides: "Unit tests for kwarg propagation + PdfChromeConfig field correctness"
      contains: "privacy_label"
  key_links:
    - from: "board_summary.run_report"
      to: "ReportComposer"
      via: "pdf_chrome=PdfChromeConfig(...)"
      pattern: "pdf_chrome="
    - from: "board_summary.run_report"
      to: "config.HEADER_BG_COLOR / config.LOGO_PATH"
      via: "from config import HEADER_BG_COLOR, LOGO_PATH"
      pattern: "HEADER_BG_COLOR"
---

<objective>
Make `board_summary` the first production consumer of the chrome utility (CHROME-INT-02). Add `privacy_label` and `scope_subtitle` kwargs to `run_report()`. Build a `PdfChromeConfig` from the existing inputs + `HEADER_BG_COLOR` / `LOGO_PATH` from `config.py`. Pass it into `ReportComposer(pdf_chrome=cfg)`.

Purpose: D-05 locks board_summary as the v1.1 opt-in. Plan 06-04 wires `run_group()` to pass the kwargs; this plan makes board_summary ready to receive them.

Output: Two new kwargs, one config import, one config construction, one composer-call edit, paired unit tests.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/06-cover-redesign-board-summary-integration/06-CONTEXT.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-RESEARCH.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-01-composer-chrome-wiring-PLAN.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-02-cover-body-redesign-PLAN.md
@reports/board_summary.py
@reports/modules/pdf_chrome.py
@config.py

<interfaces>
<!-- Phase 5 utility contract — consumed only. -->
PdfChromeConfig(
    title: str,
    subtitle: str | None,
    generated_at: datetime,    # MUST be tz-aware UTC
    header_bg: str,
    logo_path: Path | None,
    privacy_label: str = "Confidential",
)

<!-- Phase 6 plan 01 contract — consumed only. -->
ReportComposer(..., pdf_chrome: PdfChromeConfig | None = None)

<!-- Phase 6 plan 02 contract — consumed only. -->
run_all._format_scope_subtitle(tag_category, tag_value) -> str

<!-- This plan's target signature. -->
def run_report(
    tio, run_id,
    tag_category: str | None = None,
    tag_value: str | None = None,
    ...existing kwargs...,
    generated_at: datetime | None = None,
    privacy_label: str = "Confidential",      # NEW
    scope_subtitle: str | None = None,         # NEW
) -> dict: ...
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add privacy_label + scope_subtitle kwargs and wire PdfChromeConfig</name>
  <files>reports/board_summary.py</files>
  <action>
1. **Add imports** to the `from config import ...` line near the top of the file:
   ```python
   from config import (..., HEADER_BG_COLOR, LOGO_PATH)
   ```
   (Merge with existing config imports; do not duplicate lines.)

   Add the Phase 5 chrome import:
   ```python
   from reports.modules.pdf_chrome import PdfChromeConfig
   ```
   Place near other `from reports.modules...` imports.

   Add the run_all helper import for the subtitle fallback:
   ```python
   from run_all import _format_scope_subtitle
   ```
   If this introduces a circular import (board_summary already imported by run_all via the module map), fall back to **inlining a local copy** of the one-line formatter inside board_summary instead. The IMPLEMENTOR must verify: try the import first; if `python -c "import reports.board_summary"` raises ImportError, inline the formatter:
   ```python
   def _format_scope_subtitle(tc, tv): return tv if (tc and tv) else "All assets"
   ```
   placed as a module-level helper at the top of board_summary.py. Document the choice in the SUMMARY.

2. **Add the two new kwargs** to `run_report()` (board_summary.py line 82+) as the LAST kwargs before any `**kwargs` catch-all (if present):
   ```python
   privacy_label: str = "Confidential",
   scope_subtitle: str | None = None,
   ```

3. **Refactor subtitle construction** (board_summary.py lines 234-244):
   - If `scope_subtitle is not None`, use it directly.
   - Else, call `_format_scope_subtitle(tag_category, tag_value)` to derive it.
   - This single string feeds BOTH the cover-body subtitle (via the composer's substitution dict — already plumbed in plan 06-02 as `scope_subtitle`) AND `PdfChromeConfig.subtitle` (D-02 single source of truth).
   - **Preserve `scope_label`** (the analyst _Metadata row string per D-19) UNCHANGED — RESEARCH.md "Files Touched" row "board_summary.py 234-244" calls this out explicitly.

4. **Construct PdfChromeConfig** just before the `ReportComposer(...)` call (board_summary.py around line 220-226):
   ```python
   pdf_chrome_cfg = PdfChromeConfig(
       title=title,                  # existing variable in run_report
       subtitle=resolved_subtitle,   # from step 3
       generated_at=generated_at,    # already UTC per board_summary.py:152-153
       header_bg=HEADER_BG_COLOR,
       logo_path=LOGO_PATH,
       privacy_label=privacy_label,
   )
   ```

5. **Pass to composer**:
   ```python
   composer = ReportComposer(
       ...existing args...,
       pdf_chrome=pdf_chrome_cfg,
   )
   ```

6. DO NOT touch `management_summary.py` or `ops_remediation.py` (CHROME-COMPAT-01). DO NOT change any other board_summary behavior. Karpathy §3 — surgical.
  </action>
  <verify>
    <automated>python -c "import inspect, reports.board_summary as bs; sig = inspect.signature(bs.run_report); assert 'privacy_label' in sig.parameters; assert 'scope_subtitle' in sig.parameters; assert sig.parameters['privacy_label'].default == 'Confidential'; assert sig.parameters['scope_subtitle'].default is None; print('signature OK')"</automated>
  </verify>
  <done>`run_report` signature exposes both new kwargs with the correct defaults. PdfChromeConfig is built with all 6 fields populated and passed via `pdf_chrome=` to `ReportComposer`. `management_summary.py` and `ops_remediation.py` are untouched (verify via `git diff --stat reports/`).</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Unit tests for kwarg propagation and PdfChromeConfig field correctness</name>
  <files>tests/test_phase6_board_summary_chrome.py</files>
  <behavior>
    - Test 1: `run_report()` signature exposes `privacy_label='Confidential'` and `scope_subtitle=None` defaults.
    - Test 2: when called with `tag_category=None, tag_value=None, scope_subtitle=None`, the PdfChromeConfig passed to ReportComposer has `subtitle == "All assets"`.
    - Test 3: when called with `tag_category="Environment", tag_value="Production"` and `scope_subtitle=None`, PdfChromeConfig.subtitle == "Production" (value-only — D-02).
    - Test 4: when `scope_subtitle="Override"` is passed explicitly, it wins over the tag-derived fallback.
    - Test 5: when `privacy_label` is omitted, PdfChromeConfig.privacy_label == "Confidential".
    - Test 6: when `privacy_label="Internal Only"` is passed, PdfChromeConfig.privacy_label == "Internal Only".
  </behavior>
  <action>
Create `tests/test_phase6_board_summary_chrome.py`. Use `unittest.mock.patch` on `reports.board_summary.ReportComposer` to capture the `pdf_chrome` kwarg without actually running the full pipeline.

```python
"""Phase 6 plan 03 — board_summary chrome wiring tests."""
import inspect
from unittest.mock import patch, MagicMock

import pytest

import reports.board_summary as bs


def test_run_report_signature_has_new_kwargs():
    sig = inspect.signature(bs.run_report)
    assert sig.parameters["privacy_label"].default == "Confidential"
    assert sig.parameters["scope_subtitle"].default is None


def _invoke_and_capture_pdf_chrome(**run_kwargs):
    """Call run_report with mocked deps and return the PdfChromeConfig handed to ReportComposer."""
    captured = {}

    class _Spy:
        def __init__(self, *args, **kwargs):
            captured["pdf_chrome"] = kwargs.get("pdf_chrome")
        def run_full_pipeline(self, *a, **kw):
            return {"pdf": None, "excel": None, "charts": [],
                    "email_body_html": "", "analyst_excel": None,
                    "email_inline_images": []}

    # Patch everything board_summary calls so the test exercises ONLY the
    # kwarg-to-PdfChromeConfig wiring path.
    with patch.object(bs, "ReportComposer", _Spy), \
         patch.object(bs, "fetch_vulns", return_value=MagicMock()), \
         patch.object(bs, "fetch_assets", return_value=MagicMock()):
        bs.run_report(tio=MagicMock(), run_id="t", **run_kwargs)
    return captured["pdf_chrome"]


def test_subtitle_defaults_to_all_assets_when_no_filter():
    cfg = _invoke_and_capture_pdf_chrome(tag_category=None, tag_value=None)
    assert cfg.subtitle == "All assets"


def test_subtitle_is_value_only_when_filter_set():
    cfg = _invoke_and_capture_pdf_chrome(tag_category="Environment", tag_value="Production")
    assert cfg.subtitle == "Production"


def test_explicit_scope_subtitle_overrides_fallback():
    cfg = _invoke_and_capture_pdf_chrome(
        tag_category="Environment", tag_value="Production",
        scope_subtitle="Custom Slice",
    )
    assert cfg.subtitle == "Custom Slice"


def test_privacy_label_defaults_to_confidential():
    cfg = _invoke_and_capture_pdf_chrome()
    assert cfg.privacy_label == "Confidential"


def test_privacy_label_override_propagates():
    cfg = _invoke_and_capture_pdf_chrome(privacy_label="Internal Only")
    assert cfg.privacy_label == "Internal Only"
```

The IMPLEMENTOR may need to add a couple more `patch.object()` calls if `run_report` calls additional fetchers/utilities at module top. The intent: stub everything but the kwarg-routing logic, then assert on the captured `PdfChromeConfig`.

If `fetch_vulns` / `fetch_assets` are imported under different names, adjust accordingly.
  </action>
  <verify>
    <automated>python -m pytest tests/test_phase6_board_summary_chrome.py -v</automated>
  </verify>
  <done>All 6 tests pass. `management_summary.py` and `ops_remediation.py` are git-clean (`git status reports/` shows only `board_summary.py` modified).</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| run_group caller → board_summary.run_report | Untrusted kwargs (privacy_label, scope_subtitle) flow through to PdfChromeConfig. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-06-04 | Tampering | privacy_label arriving from delivery_config.yaml | mitigate | Phase 5 schema regex `^[^"]+$` + `PdfChromeConfig.__post_init__` already validate. board_summary trusts the dataclass — defense-in-depth handled upstream. |
| T-06-05 | Information Disclosure | scope_subtitle interpolated into chrome header (every page) | accept | Operator-supplied tag values are already visible to recipients via the report content; surfacing them in the header doesn't change the disclosure surface. |
</threat_model>

<verification>
```powershell
# 1. Signature exposes new kwargs
python -c "import inspect, reports.board_summary as bs; print({k: v.default for k, v in inspect.signature(bs.run_report).parameters.items() if k in ('privacy_label', 'scope_subtitle')})"

# 2. Unit tests
python -m pytest tests/test_phase6_board_summary_chrome.py -v

# 3. Compat compass — these two files MUST be git-clean
git diff --stat reports/management_summary.py reports/ops_remediation.py
# Expected: empty output (no changes)

# 4. Cross-plan regression
python -m pytest tests/test_phase6_composer_chrome.py tests/test_phase6_cover_redesign.py -v
```
</verification>

<success_criteria>
- `run_report()` exposes `privacy_label` (default `"Confidential"`) and `scope_subtitle` (default `None`) kwargs (CHROME-INT-02).
- PdfChromeConfig is constructed with all 6 fields and passed via `pdf_chrome=` to `ReportComposer` (CHROME-INT-01).
- Subtitle resolution: explicit `scope_subtitle` wins; else `_format_scope_subtitle(tag_category, tag_value)` fallback.
- `management_summary.py` and `ops_remediation.py` are git-clean (CHROME-COMPAT-01).
- All 6 new tests pass.
</success_criteria>

<output>
After completion, create `.planning/phases/06-cover-redesign-board-summary-integration/06-03-SUMMARY.md` capturing:
- Exact lines changed in `reports/board_summary.py` (signature, imports, PdfChromeConfig construction, composer call)
- Whether `_format_scope_subtitle` was imported from run_all or inlined locally (and why)
- Test names + pass evidence
- `git diff --stat` proof that management_summary / ops_remediation are untouched.
</output>
