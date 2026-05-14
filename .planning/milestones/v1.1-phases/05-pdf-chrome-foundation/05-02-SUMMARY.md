---
phase: 05-pdf-chrome-foundation
plan: 02
subsystem: pdf-chrome-utility
tags: [pdf, chrome, design-system, foundation, weasyprint]
requires:
  - "config.HEADER_BG_COLOR (from 05-01)"
  - "delivery_config.schema.yaml: privacy_label regex (from 05-01)"
provides:
  - "reports.modules.pdf_chrome.PdfChromeConfig (frozen dataclass)"
  - "reports.modules.pdf_chrome.PdfChrome (utility class)"
  - "PdfChrome.build_css() — @page rules + .chrome-header styles"
  - "PdfChrome.build_header_html() — body-side running element"
  - "PdfChrome.build_footer_runners() — empty string in v1 (API symmetry)"
affects: []
tech_stack:
  added: []
  patterns:
    - "Frozen-dataclass + utility-class pair parallels base.ModuleConfig + BaseModule"
    - "Render-time logo existence check; no startup FS probe"
    - "Footer corners via literal @bottom-* content strings (no body-side running elements)"
    - "@page :first overrides ONLY @bottom-center for cover-page page-number suppression"
key_files:
  created:
    - reports/modules/pdf_chrome.py
  modified: []
decisions:
  - "Single-file deliverable — no changes to composer.py, run_all.py, or any existing report. Phase 6 owns composer integration."
  - "Defense-in-depth on privacy_label: schema regex rejects \" operator-side (05-01); __post_init__ rejects \" in code (this plan)."
  - "Defense-in-depth on generated_at: __post_init__ rejects naive AND non-UTC datetimes — the literal 'UTC' suffix in the footer is only correct when the source is actually UTC-aware."
  - "Filename omits *_module.py suffix and class is not @register_module-decorated — registry.discover() does not auto-pick it up. PdfChrome is a utility, not a metric module."
metrics:
  tasks_completed: 1
  files_created: 1
  files_modified: 0
  duration_minutes: ~5
  completed_at: "2026-05-13T13:12:00Z"
---

# Phase 5 Plan 02: Shared PDF Chrome Utility Summary

Landed `reports/modules/pdf_chrome.py` — the canonical PDF design-system surface for v1.1+. One new file, 276 lines, zero changes to existing reports or composer. The chrome is provable in isolation; Phase 6 will wire it into `ReportComposer.assemble_pdf()`.

## What Shipped

### `reports/modules/pdf_chrome.py` (276 lines)

Two public names, exactly as the planned `<interfaces>` block specified:

- **`PdfChromeConfig`** — frozen dataclass: `title`, `subtitle`, `generated_at` (UTC-aware), `header_bg` (default `"#1a2332"`), `logo_path` (default `None`), `privacy_label` (default `"Confidential"`).
- **`PdfChrome`** — utility class wrapping a `PdfChromeConfig`; emits CSS, header HTML, footer runners.

#### `__post_init__` validations (defense-in-depth)

1. `generated_at.tzinfo is None` → `ValueError` ("must be timezone-aware (UTC)").
2. `generated_at.utcoffset() != timedelta(0)` → `ValueError` ("must be in UTC").
3. `"` in `privacy_label` → `ValueError` (CSS-content-string safety; mirrors the YAML schema regex from 05-01).

#### `build_css()` output (verified by smoke)

Contains, on a default config with `generated_at = 2026-05-13 08:52 UTC`:
- `@page :first { @bottom-center { content: ""; } }` — cover-page page-number suppression (CHROME-FTR-03)
- `counter(page) " of " counter(pages)` — Page N of M wiring (CHROME-FTR-02)
- `background: #1a2332;` — interpolated header background (CHROME-HDR-01)
- `content: "Confidential";` — interpolated privacy label (CHROME-FTR-01)
- `content: "2026-05-13 08:52 UTC";` — UTC-formatted generated_at (CHROME-FTR-01)
- A4 landscape size, `15mm 12mm 18mm 12mm` margins (matches existing composer)
- `.chrome-header { position: running(chrome-header); ... }` for body-side running element

#### `build_header_html()` branches (CHROME-CFG-03)

- `logo_path is None` → title-only `<div class="chrome-header"><span class="chrome-title">...` (no `<img>` tag)
- `logo_path` points to existing file → emits `<img src="{resolved file:// URI}" alt="">`
- `logo_path` set but file missing → silent fallback to title-only (no exception, no warning log, no reserved width)

Uses `lp.resolve().as_uri()` (in that order) per RESEARCH risk #2 — `as_uri()` on a relative path raises.
Title and subtitle are `html.escape()`'d (XSS-equivalent safety inside `<span>` markup).

#### `build_footer_runners()` — `""` in v1

Footer corners are emitted as literal `content:` strings inside `@bottom-left`/`@bottom-center`/`@bottom-right` margin boxes — no body-side running element for the footer. The method exists for API symmetry with `build_header_html()`.

## Public API Confirmation

```python
from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig
```

Two names. No other public symbols. `logger`, `html`, `Path`, `datetime`, `timezone` are imports, not re-exports.

## Auto-Discovery Exemption

```
>>> from reports.modules import registry
>>> registry.discover()
>>> 'pdf_chrome' in registry
False
>>> len(registry)
8
```

The eight registered metric modules are unchanged: `aged_vulns_assets`, `critical_remediation_sla`, `example_module`, `high_risk_assets`, `mttr_by_severity`, `patch_compliance_rate`, `scan_coverage_sla`, `total_vulns_by_severity`. `pdf_chrome` is correctly absent — file name lacks `*_module.py` suffix, class lacks `@register_module` decorator.

## Verification Sequence

```
$ python -c "from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig; print('import OK')"
import OK

$ python -c "<smoke assertions>"
smoke OK

$ python -c "<naive datetime rejection>"
rejected naive: PdfChromeConfig.generated_at must be timezone-aware (UTC). Got a naive datetime.

$ python -c "<bad-quote rejection>"
rejected quote: PdfChromeConfig.privacy_label must not contain a double-quote character. ...

$ python -c "from reports.modules import registry; registry.discover(); assert 'pdf_chrome' not in registry"
not registered as module - OK
registered count: 8

$ python tests/test_modules_level1.py
  56/56 passed   0 failed
  ALL LEVEL 1 TESTS PASS
```

## Deviations from Plan

None — file shipped exactly as written in the plan's `<action>` block, including the 7 critical implementation notes:

1. `@dataclass(frozen=True)` ✓
2. `__post_init__` validates both UTC-awareness and CSS-safety of `privacy_label` ✓
3. CSS uses doubled `{{`/`}}` to escape inside the f-string ✓
4. `html.escape()` on `title`/`subtitle`; NOT on `privacy_label`/`generated_at_str` (validated upstream) ✓
5. `lp.resolve().as_uri()` order ✓
6. No flexbox — inline-block + `vertical-align: middle` only ✓
7. No `*_module.py` suffix, no `@register_module` ✓

Note on the verify-command spec: the plan's `<verify>` block referenced `from reports.modules.registry import discover, _MODULES`, but the actual registry module exposes a global `registry` instance with `registry.discover()` and `registry._modules`. The verification was adjusted to use the real API (`from reports.modules import registry; registry.discover(); assert 'pdf_chrome' not in registry`) — same intent, correct symbol names. This is a verify-command typo in the plan, not a deviation in the shipped code.

## Commit

- `8548a61` — `feat(05-02): add shared PDF chrome utility module`

## Downstream Hooks

- **Plan 05-03** (unit tests): imports `PdfChrome`, `PdfChromeConfig` from this module; asserts on the string outputs of `build_css()` / `build_header_html()` / `build_footer_runners()`.
- **Plan 05-04** (real-render integration): wraps a minimal `PdfChromeConfig` in a tiny HTML doc, renders via WeasyPrint, extracts per-page text with `pypdf` (pinned by 05-01).
- **Phase 6 composer wiring**: `ReportComposer.assemble_pdf()` will instantiate `PdfChrome(cfg)`, drop `<style>{chrome.build_css()}</style>` into the existing `<head>`, and inject `{chrome.build_header_html()}` as the first body-side element. `build_footer_runners()` returns `""` so it is a safe no-op concatenation in the body template.

## Self-Check: PASSED

- FOUND: `reports/modules/pdf_chrome.py` (276 lines, exceeds 120-line floor in must-haves)
- FOUND: class `PdfChromeConfig` (frozen dataclass with __post_init__)
- FOUND: class `PdfChrome` with three render methods
- FOUND commit: `8548a61` (Task 1)
- VERIFIED: `pdf_chrome` NOT in `registry._modules` after `registry.discover()`
- VERIFIED: `tests/test_modules_level1.py` — 56/56 PASS (no regression)
- VERIFIED: STATE.md, ROADMAP.md, CLAUDE.md, delivery_config.yaml untouched (only `M`-marked pre-existing dirty files on CLAUDE.md and delivery_config.yaml, both unchanged by this plan)
