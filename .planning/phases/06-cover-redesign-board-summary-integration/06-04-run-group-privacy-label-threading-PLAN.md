---
phase: 06-cover-redesign-board-summary-integration
plan: 04
type: execute
wave: 4
depends_on:
  - 06-03
files_modified:
  - run_all.py
  - tests/test_phase6_run_group_chrome.py
autonomous: true
requirements:
  - CHROME-INT-01
  - CHROME-COMPAT-01
user_setup: []
must_haves:
  truths:
    - "run_group() resolves privacy_label from group config with 'Confidential' default."
    - "run_group() resolves scope_subtitle via _format_scope_subtitle(tag_category, tag_value)."
    - "Both kwargs are passed to board_summary.run_report() via the existing slug-specific extras block."
    - "management_summary and ops_remediation slugs do NOT receive privacy_label or scope_subtitle (CHROME-COMPAT-01)."
    - "Existing delivery_config.yaml validates and runs without a privacy_label field (CHROME-COMPAT-02)."
  artifacts:
    - path: "run_all.py"
      provides: "Module-level _CHROME_AWARE_SLUGS frozenset; privacy_label + scope_subtitle resolution in run_group; gated slug-specific kwargs"
      contains: "_CHROME_AWARE_SLUGS"
    - path: "tests/test_phase6_run_group_chrome.py"
      provides: "Compat assertions that legacy slugs do NOT receive privacy_label"
      contains: "management_summary"
  key_links:
    - from: "run_all.py:run_group"
      to: "reports.board_summary.run_report"
      via: "report_kwargs['privacy_label'] / report_kwargs['scope_subtitle']"
      pattern: "_CHROME_AWARE_SLUGS"
    - from: "run_all.py:run_group"
      to: "reports.management_summary.run_report / reports.ops_remediation.run_report"
      via: "NO privacy_label or scope_subtitle in report_kwargs (compat gate)"
      pattern: "slug in _CHROME_AWARE_SLUGS"
---

<objective>
Thread `privacy_label` and `scope_subtitle` from `delivery_config.yaml` through `run_group()` into `board_summary.run_report()` — and ONLY into board_summary (CHROME-COMPAT-01). Per RESEARCH.md Q2, use a slug allowlist over `inspect.signature` (simpler, matches existing per-slug-extras pattern at run_all.py:672-695).

Purpose: D-05 locks the privacy_label flow as YAML → run_group → run_report. This plan is the last code-level wire; plan 06-05 is baseline regen + visual UAT.

Output: One frozenset constant, two resolution lines near the tag filter resolution, two gated kwarg-extras lines in the existing `if slug == "board_summary":` block, paired compat-safety tests.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/06-cover-redesign-board-summary-integration/06-CONTEXT.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-RESEARCH.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-03-board-summary-privacy-label-PLAN.md
@run_all.py
@delivery_config.yaml
@delivery_config.schema.yaml

<interfaces>
<!-- Module-level constant defining which report slugs accept chrome kwargs. -->
_CHROME_AWARE_SLUGS: frozenset[str] = frozenset({"board_summary"})

<!-- Inside run_group(), near tag-filter resolution at run_all.py:589-590. -->
privacy_label = group.get("privacy_label", "Confidential")
scope_subtitle = _format_scope_subtitle(tag_category, tag_value)

<!-- Inside the existing if slug == "board_summary": block (run_all.py:672-682). -->
if slug == "board_summary":
    ...existing kwarg extras...
    if slug in _CHROME_AWARE_SLUGS:
        report_kwargs["privacy_label"]  = privacy_label
        report_kwargs["scope_subtitle"] = scope_subtitle
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add _CHROME_AWARE_SLUGS, resolve kwargs, gate slug-specific extras</name>
  <files>run_all.py</files>
  <action>
1. **Module-level constant** — add near `_VALID_REPORTS` / `_REPORT_MODULE_MAP` (run_all.py:76-110 area):
   ```python
   # Slugs whose run_report() opts in to the Phase 6 chrome utility.
   # Per RESEARCH.md Q2 and D-05: an allowlist beats inspect.signature for
   # a one-consumer rollout. CHROME-COMPAT-01 — management_summary and
   # ops_remediation MUST NOT receive privacy_label / scope_subtitle.
   _CHROME_AWARE_SLUGS: frozenset[str] = frozenset({"board_summary"})
   ```

2. **Resolve at the tag-filter site** (run_all.py:589-590, immediately after the existing `tag_category = ...` / `tag_value = ...` resolution):
   ```python
   privacy_label = group.get("privacy_label", "Confidential")
   scope_subtitle = _format_scope_subtitle(tag_category, tag_value)
   ```
   Variable names match plan 06-03's `board_summary.run_report()` kwargs.

3. **Gate the slug-specific extras** — inside the existing `if slug == "board_summary":` block (run_all.py:672-682), append:
   ```python
   if slug in _CHROME_AWARE_SLUGS:
       report_kwargs["privacy_label"]  = privacy_label
       report_kwargs["scope_subtitle"] = scope_subtitle
   ```
   Yes, the outer `if slug == "board_summary":` already restricts to one slug today. The inner `_CHROME_AWARE_SLUGS` check is **intentionally redundant** — it documents the compat-safety contract at the point of risk and survives future refactors that consolidate the slug-extras blocks. D-05 + CHROME-COMPAT-01 are the load-bearing reasons.

4. DO NOT modify the existing per-slug blocks for `vuln_export`, `unscanned_assets`, `composed_report`. DO NOT add a new slug-specific block for `management_summary` or `ops_remediation` (they are NOT chrome-aware). Karpathy §3.

5. DO NOT modify the delivery_config.yaml schema (privacy_label already landed in Phase 5).
  </action>
  <verify>
    <automated>python -c "from run_all import _CHROME_AWARE_SLUGS, _format_scope_subtitle; assert _CHROME_AWARE_SLUGS == frozenset({'board_summary'}); assert _format_scope_subtitle(None, None) == 'All assets'; print('module constants OK')"</automated>
  </verify>
  <done>`_CHROME_AWARE_SLUGS` is module-level and contains only `"board_summary"`. `privacy_label` + `scope_subtitle` are resolved in `run_group()` near the tag-filter site. The slug-specific kwarg-extras block only injects these two keys when `slug in _CHROME_AWARE_SLUGS`.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Compat-safety tests — legacy slugs do NOT receive privacy_label</name>
  <files>tests/test_phase6_run_group_chrome.py</files>
  <behavior>
    - Test 1: `_CHROME_AWARE_SLUGS == frozenset({"board_summary"})`.
    - Test 2: when `run_group()` dispatches to `board_summary`, the captured `run_report` kwargs CONTAIN `privacy_label` and `scope_subtitle`.
    - Test 3: when `run_group()` dispatches to `management_summary`, the captured kwargs DO NOT contain `privacy_label` (CHROME-COMPAT-01).
    - Test 4: when `run_group()` dispatches to `ops_remediation`, the captured kwargs DO NOT contain `privacy_label`.
    - Test 5: when a group config OMITS `privacy_label`, the default `"Confidential"` is what board_summary receives (CHROME-COMPAT-02).
    - Test 6: when a group config supplies `privacy_label: "Internal Only"`, that value is what board_summary receives.
  </behavior>
  <action>
Create `tests/test_phase6_run_group_chrome.py`. Pattern: patch `importlib.import_module` (or the cached module entries) so each target report is a stub that records the kwargs it was called with, then drive a synthetic group config through `run_group()`.

```python
"""Phase 6 plan 04 — run_group privacy_label threading + compat-safety."""
from unittest.mock import MagicMock, patch

import pytest

import run_all
from run_all import _CHROME_AWARE_SLUGS


def test_chrome_aware_slugs_only_contains_board_summary():
    assert _CHROME_AWARE_SLUGS == frozenset({"board_summary"})


def _run_group_with_slug(slug: str, group_overrides: dict | None = None) -> dict:
    """Dispatch a synthetic group through run_group and return captured run_report kwargs."""
    captured: dict = {}

    fake_module = MagicMock()
    def _spy_run_report(tio, run_id, **kwargs):
        captured.update(kwargs)
        return {"pdf": None, "excel": None, "charts": []}
    fake_module.run_report = _spy_run_report

    group = {
        "name": "Phase6 Test Group",
        "schedule": {"frequency": "on_demand"},
        "reports": [slug],
        "filters": {},
        "email": {"subject": "s", "recipients": ["a@b.c"]},
    }
    if group_overrides:
        group.update(group_overrides)

    # Stub the module-map import so run_group thinks the report module is loaded.
    with patch("run_all.importlib.import_module", return_value=fake_module), \
         patch.object(run_all, "get_client", return_value=MagicMock()):
        run_all.run_group(group, dry_run=False, send_email=False)
    return captured


def test_board_summary_receives_privacy_label_and_scope_subtitle():
    kw = _run_group_with_slug("board_summary")
    assert "privacy_label" in kw
    assert "scope_subtitle" in kw


def test_management_summary_does_not_receive_privacy_label():
    """CHROME-COMPAT-01 — legacy renderer signature is unchanged."""
    kw = _run_group_with_slug("management_summary")
    assert "privacy_label" not in kw
    assert "scope_subtitle" not in kw


def test_ops_remediation_does_not_receive_privacy_label():
    """CHROME-COMPAT-01 — legacy renderer signature is unchanged."""
    kw = _run_group_with_slug("ops_remediation")
    assert "privacy_label" not in kw
    assert "scope_subtitle" not in kw


def test_privacy_label_defaults_to_confidential():
    kw = _run_group_with_slug("board_summary")  # no privacy_label override
    assert kw["privacy_label"] == "Confidential"


def test_privacy_label_override_propagates():
    kw = _run_group_with_slug("board_summary",
                              group_overrides={"privacy_label": "Internal Only"})
    assert kw["privacy_label"] == "Internal Only"
```

If `run_group()`'s actual signature is `run_group(group_config, ...)` and rejects the synthetic group above, adapt the keys (filters, schedule shape) to whatever the live schema requires. Source of truth: `delivery_config.schema.yaml`. The IMPLEMENTOR must match the live signature; the test intent is the load-bearing assertion.

If `get_client` is imported under a different name, patch accordingly.
  </action>
  <verify>
    <automated>python -m pytest tests/test_phase6_run_group_chrome.py -v</automated>
  </verify>
  <done>All 6 tests pass. The compat assertions (tests 3 and 4) are the load-bearing CHROME-COMPAT-01 evidence.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| delivery_config.yaml → run_group | Operator-supplied `privacy_label` flows into report_kwargs. |
| run_group → legacy run_report (management_summary, ops_remediation) | Compat-safety: extra kwargs MUST NOT appear, else TypeError. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-06-06 | Denial of Service | legacy run_report receives unexpected kwarg | mitigate | `_CHROME_AWARE_SLUGS` gate + explicit Task 2 tests 3/4 prevent the regression. Reviewed at every plan touching run_group thereafter. |
| T-06-07 | Tampering | operator-supplied privacy_label | accept | Phase 5 schema regex already enforces no double-quote injection; defense-in-depth in PdfChromeConfig.__post_init__. |
</threat_model>

<verification>
```powershell
# 1. Module constants
python -c "from run_all import _CHROME_AWARE_SLUGS; print(_CHROME_AWARE_SLUGS)"

# 2. New compat tests
python -m pytest tests/test_phase6_run_group_chrome.py -v

# 3. CHROME-COMPAT-02 smoke — existing yaml still validates
python -c "import yaml, jsonschema; jsonschema.validate(yaml.safe_load(open('delivery_config.yaml')), yaml.safe_load(open('delivery_config.schema.yaml'))); print('OK')"

# 4. Dry-run sanity (no email send)
python run_all.py --dry-run

# 5. Full Phase 6 regression
python -m pytest tests/test_phase6_composer_chrome.py tests/test_phase6_cover_redesign.py tests/test_phase6_board_summary_chrome.py tests/test_phase6_run_group_chrome.py -v
```
</verification>

<success_criteria>
- `_CHROME_AWARE_SLUGS = frozenset({"board_summary"})` exists at module level (CHROME-INT-01).
- `run_group()` resolves `privacy_label` (with `"Confidential"` default) and `scope_subtitle` (via `_format_scope_subtitle`).
- `board_summary` receives both kwargs; `management_summary` and `ops_remediation` do NOT (CHROME-COMPAT-01).
- Existing `delivery_config.yaml` validates without `privacy_label` (CHROME-COMPAT-02).
- All 6 new tests pass.
</success_criteria>

<output>
After completion, create `.planning/phases/06-cover-redesign-board-summary-integration/06-04-SUMMARY.md` capturing:
- Exact lines added in `run_all.py` (constant + resolution + gated extras)
- Compat-safety test pass evidence (tests 3 and 4 specifically)
- Confirmation that `python run_all.py --dry-run` succeeds against existing `delivery_config.yaml` (CHROME-COMPAT-02)
- Phase 6 stack is now ready for the baseline regen + UAT in plan 06-05.
</output>
