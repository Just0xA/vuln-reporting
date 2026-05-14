---
phase: 06-cover-redesign-board-summary-integration
plan: 02
type: execute
wave: 2
depends_on:
  - 06-01
files_modified:
  - reports/modules/composer.py
  - run_all.py
  - tests/test_phase6_cover_redesign.py
autonomous: true
requirements:
  - CHROME-COV-01
  - CHROME-COV-02
user_setup: []
must_haves:
  truths:
    - "Cover body renders ONLY the scope subtitle line + the unified RAG strip block."
    - "Cover body does NOT contain the legacy title <p>, divider <hr>, .cover-meta wrapper, 'Generated:' line, or 'Sections:' line."
    - "Cover body preserves the 'Risk Status Summary' RAG strip header marker verbatim (R1 from RESEARCH.md)."
    - "_format_scope_subtitle(None, None) returns 'All assets'; _format_scope_subtitle('Environment', 'Production') returns 'Production'."
  artifacts:
    - path: "reports/modules/composer.py"
      provides: "Trimmed _PDF_UNIFIED_COVER_TEMPLATE + matching _build_unified_cover_page() substitution dict"
      contains: "rag-strip"
    - path: "run_all.py"
      provides: "_format_scope_subtitle helper (module-level, above run_group)"
      contains: "_format_scope_subtitle"
    - path: "tests/test_phase6_cover_redesign.py"
      provides: "Unit tests for the trimmed cover and the value-only subtitle formatter"
      contains: "Risk Status Summary"
  key_links:
    - from: "_build_unified_cover_page (composer.py)"
      to: "_PDF_UNIFIED_COVER_TEMPLATE"
      via: "string substitution dict reduced to subtitle + rag strip vars"
      pattern: "rag-strip"
    - from: "_format_scope_subtitle (run_all.py)"
      to: "board_summary.run_report (plan 06-03)"
      via: "scope_subtitle threaded through report_kwargs"
      pattern: "scope_subtitle"
---

<objective>
Strip the cover body to scope subtitle + RAG strip only (D-01). Chrome now carries the title (every page) and the "Generated:" timestamp (footer right corner), so repeating them on page 1 is visual redundancy.

Also land `_format_scope_subtitle()` (D-02) as a module-level helper in `run_all.py` — value-only formatting (`"Production"`, not `"Environment = Production"`; `"All assets"` when no tag filter). Single source of truth feeding both cover body subtitle AND `PdfChromeConfig.subtitle`.

Purpose: D-01 + D-02 are the user-visible deliverables of Phase 6. Plans 06-03/06-04 consume the formatter; plan 06-05 visually validates the trimmed cover.

Output: Smaller cover template, smaller substitution dict, one new helper, paired unit tests.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/06-cover-redesign-board-summary-integration/06-CONTEXT.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-RESEARCH.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-01-composer-chrome-wiring-PLAN.md
@reports/modules/composer.py
@run_all.py
@tests/baseline_utils.py

<interfaces>
<!-- Pre-existing marker the baseline extractor greps for (RESEARCH.md Finding 3, R1). -->
<!-- Confirm exact text via: Select-String -Path tests/baseline_utils.py -Pattern "Risk Status Summary" -->

Baseline extractor marker (must be preserved verbatim in the trimmed template):
```
<h2 class="rag-strip-header">Risk Status Summary</h2>
```

Trimmed _PDF_UNIFIED_COVER_TEMPLATE shape (target after this plan):
```html
<section class="report-cover">
  <p class="cover-subtitle">{scope_subtitle}</p>
  <h2 class="rag-strip-header">Risk Status Summary</h2>
  <div class="rag-strip">
    <div class="rag-cell-row">
      {rag_cells}
    </div>
  </div>
</section>
```

Removed elements (CHROME-COV-02):
- `<p class="cover-title">{title}</p>`
- `<hr class="cover-divider" />`
- `<div class="cover-meta"> ... Generated: {generated_at} ... Sections: {module_list} ... </div>`

_format_scope_subtitle helper (run_all.py, module-level, above run_group):
```python
def _format_scope_subtitle(tag_category: str | None, tag_value: str | None) -> str:
    """Value-only scope label per D-02. Single source of truth for cover body subtitle AND PdfChromeConfig.subtitle."""
    return tag_value if (tag_category and tag_value) else "All assets"
```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Trim _PDF_UNIFIED_COVER_TEMPLATE and update _build_unified_cover_page substitution</name>
  <files>reports/modules/composer.py</files>
  <action>
1. **Edit `_PDF_UNIFIED_COVER_TEMPLATE` (composer.py lines 377-393)** to the shape in the `<interfaces>` block above. Remove:
   - The `<p class="cover-title">{title}</p>` line.
   - The `<hr class="cover-divider" />` line.
   - The entire `<div class="cover-meta"> ... </div>` block (which contains `Generated: {generated_at}` and `Sections: {module_list}`).

   PRESERVE verbatim:
   - The outer `<section class="report-cover">` wrapper.
   - The `<p class="cover-subtitle">{scope_subtitle}</p>` line (rename the substitution key from whatever it is today to `scope_subtitle` — see step 2).
   - The `<h2 class="rag-strip-header">Risk Status Summary</h2>` marker (R1 — baseline extractor depends on this exact string; confirm in Task 3 verify).
   - The full `.rag-strip` / `.rag-cell-row` / per-module rag cell block (CHROME-COV-01).

2. **Update `_build_unified_cover_page()` (composer.py lines ~730+)** substitution dict accordingly:
   - DROP keys: `title`, `generated_at`, `module_list` (and any others tied to removed lines).
   - KEEP key: `scope_subtitle` (rename from `subtitle` / `scope_str` / whatever the current key is — match the trimmed template).
   - KEEP key: `rag_cells` (or whatever drives the per-module RAG cells loop).

3. **Optional cosmetic** (Karpathy §3 — planner's discretion was given in RESEARCH.md "Files Touched" row 1): you MAY trim now-dead CSS rules for `.cover-title`, `.cover-divider`, `.cover-meta` from `_PDF_CSS` (lines 70-374). If touching them is non-trivial or risks merge friction, LEAVE THEM. They are dead but harmless.

4. DO NOT touch the deprecated `_PDF_RAG_STRIP_TEMPLATE` alias on line 401 — R4 says it auto-tracks via Python name binding. DO NOT touch any module-page rendering. DO NOT touch the chrome injection code from plan 06-01.
  </action>
  <verify>
    <automated>python -c "from reports.modules.composer import _PDF_UNIFIED_COVER_TEMPLATE; t = _PDF_UNIFIED_COVER_TEMPLATE; assert 'cover-title' not in t; assert 'cover-divider' not in t; assert 'cover-meta' not in t; assert 'Generated:' not in t; assert 'Sections:' not in t; assert 'Risk Status Summary' in t; assert 'rag-strip' in t; assert '{scope_subtitle}' in t; print('template trimmed OK')"</automated>
  </verify>
  <done>Template contains scope_subtitle placeholder + Risk Status Summary header + rag-strip block. Template does NOT contain any of: cover-title, cover-divider, cover-meta, "Generated:", "Sections:". The substitution dict in `_build_unified_cover_page()` matches the new placeholder set (no KeyError on render).</done>
</task>

<task type="auto">
  <name>Task 2: Add _format_scope_subtitle helper to run_all.py</name>
  <files>run_all.py</files>
  <action>
Add the helper as a module-level function ABOVE `run_group()` (per RESEARCH.md Finding 5 recommendation — single source of truth, future `composed_report` inherits for free):

```python
def _format_scope_subtitle(tag_category: str | None, tag_value: str | None) -> str:
    """Value-only scope subtitle per D-02.

    Single source of truth feeding both the cover-body subtitle line and
    PdfChromeConfig.subtitle (chrome header band). Drops the category prefix
    intentionally — "Production", not "Environment = Production".

    Returns sentence-case "All assets" when no tag filter is set (D-01 case
    normalization — old cover text was "all assets", new is "All assets").
    """
    return tag_value if (tag_category and tag_value) else "All assets"
```

Place it near the other small module-level helpers in `run_all.py` (above `run_group` at line 504). DO NOT call it from `run_group()` in this plan — plan 06-04 wires it into the slug-specific kwarg block.

DO NOT modify any other code in `run_all.py`.
  </action>
  <verify>
    <automated>python -c "from run_all import _format_scope_subtitle as f; assert f(None, None) == 'All assets'; assert f('Environment', 'Production') == 'Production'; assert f('Environment', None) == 'All assets'; assert f(None, 'Production') == 'All assets'; print('formatter OK')"</automated>
  </verify>
  <done>`_format_scope_subtitle` is importable from `run_all`. Returns `"All assets"` for empty/partial input. Returns `tag_value` only when both args are set.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Add unit tests for trimmed cover + scope subtitle formatter</name>
  <files>tests/test_phase6_cover_redesign.py</files>
  <behavior>
    - Test 1: rendered cover HTML (via `_build_unified_cover_page()`) does NOT contain any of `cover-title`, `cover-divider`, `cover-meta`, `Generated:`, `Sections:`.
    - Test 2: rendered cover HTML DOES contain `Risk Status Summary` (baseline marker, R1).
    - Test 3: rendered cover HTML DOES contain the supplied scope subtitle value (e.g. `"Production"`).
    - Test 4: `_format_scope_subtitle(None, None) == "All assets"`.
    - Test 5: `_format_scope_subtitle("Environment", "Production") == "Production"`.
    - Test 6: `_format_scope_subtitle("Environment", None) == "All assets"` (partial input).
  </behavior>
  <action>
Create `tests/test_phase6_cover_redesign.py`.

```python
"""Phase 6 plan 02 — cover body redesign + scope subtitle formatter."""
import pytest

from run_all import _format_scope_subtitle


def test_format_scope_subtitle_no_filter_returns_all_assets():
    assert _format_scope_subtitle(None, None) == "All assets"


def test_format_scope_subtitle_full_filter_returns_value_only():
    assert _format_scope_subtitle("Environment", "Production") == "Production"


def test_format_scope_subtitle_partial_filter_returns_all_assets():
    assert _format_scope_subtitle("Environment", None) == "All assets"
    assert _format_scope_subtitle(None, "Production") == "All assets"


def test_cover_template_removes_legacy_elements():
    """CHROME-COV-02 — cover body no longer carries title/divider/meta/Generated/Sections."""
    from reports.modules.composer import _PDF_UNIFIED_COVER_TEMPLATE as tmpl
    for needle in ("cover-title", "cover-divider", "cover-meta",
                   "Generated:", "Sections:"):
        assert needle not in tmpl, f"legacy element {needle!r} still in cover template"


def test_cover_template_preserves_rag_strip_marker():
    """CHROME-COV-01 + R1 — baseline extractor depends on this exact header text."""
    from reports.modules.composer import _PDF_UNIFIED_COVER_TEMPLATE as tmpl
    assert "Risk Status Summary" in tmpl
    assert "rag-strip" in tmpl


def test_built_cover_renders_scope_subtitle():
    """Rendered cover HTML contains the supplied scope subtitle verbatim."""
    # IMPLEMENTOR: call _build_unified_cover_page() (or its public-facing
    # equivalent) with scope_subtitle="Production" and assert the string
    # appears in the returned HTML. The exact callable signature is in
    # composer.py around line 730 — match what the function expects.
    from reports.modules.composer import _build_unified_cover_page  # adjust if private
    # Minimal inputs — the function may need a stubbed module list; pass [].
    html = _build_unified_cover_page(
        scope_subtitle="Production",
        modules=[],  # adjust per actual signature
    )
    assert "Production" in html
    assert "Risk Status Summary" in html
```

If `_build_unified_cover_page` has a different signature, adapt the call to match. The IMPLEMENTOR is responsible for reading composer.py:730+ and matching the real signature; the test's INTENT (scope_subtitle ends up in the rendered HTML) is the load-bearing assertion.
  </action>
  <verify>
    <automated>python -m pytest tests/test_phase6_cover_redesign.py -v</automated>
  </verify>
  <done>All 6 tests pass. No existing test regresses (run `pytest tests/test_phase2_composer_pipeline.py -v` too).</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| operator → tag_category/tag_value | Free-text inputs that flow into the cover HTML via {scope_subtitle}. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-06-03 | Tampering | scope_subtitle interpolation into cover HTML | mitigate | The same string template engine that handles tag_category/tag_value today escapes HTML — no change in escape semantics. Composer template uses `{scope_subtitle}` via `str.format` / Jinja (whatever it uses today); behavior inherits existing safety. |
</threat_model>

<verification>
```powershell
# 1. Template-shape smoke
python -c "from reports.modules.composer import _PDF_UNIFIED_COVER_TEMPLATE as t; assert 'Generated:' not in t and 'Risk Status Summary' in t; print('OK')"

# 2. Formatter smoke
python -c "from run_all import _format_scope_subtitle as f; print(f(None, None), '|', f('E', 'P'))"

# 3. New unit tests
python -m pytest tests/test_phase6_cover_redesign.py -v

# 4. Regression sweep
python -m pytest tests/test_phase2_composer_pipeline.py tests/test_phase6_composer_chrome.py -v

# 5. RESEARCH Finding 6 sanity check (must return zero matches)
Select-String -Path tests/*.py -Pattern "cover-title|cover-meta|cover-divider"
```
</verification>

<success_criteria>
- `_PDF_UNIFIED_COVER_TEMPLATE` trimmed to subtitle + RAG strip only (CHROME-COV-02).
- `Risk Status Summary` header preserved verbatim — baseline extractor marker intact (CHROME-COV-01, R1).
- `_format_scope_subtitle` helper exposes value-only formatting with `"All assets"` fallback (D-02).
- 6 new unit tests pass; no regression in pre-existing tests.
</success_criteria>

<output>
After completion, create `.planning/phases/06-cover-redesign-board-summary-integration/06-02-SUMMARY.md` capturing:
- Diff summary of the trimmed template (lines removed)
- Confirmation that `Risk Status Summary` marker is still present (verbatim from R1)
- Test names + pass evidence
- RESEARCH.md Finding 6 verified: zero pre-existing tests assert on the removed strings.
</output>

<notes>
**RESEARCH.md Finding 6 verified locally before planning** — `Select-String -Path tests/ -Pattern "cover-title|cover-meta|cover-divider|Generated:|Sections:"` returned zero matches. No test updates beyond the new file in Task 3 are required for the cover redesign.
</notes>
