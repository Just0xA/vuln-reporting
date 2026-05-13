# Phase 1: Module Render Contract — Pattern Map

**Mapped:** 2026-05-05
**Files analyzed:** 8 (2 NEW + 6 EDIT, plus QUALITY-03 audit findings catalogued)
**Analogs found:** 8 / 8

---

## File Classification

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| `reports/modules/rag_utils.py` (NEW) | utility (RAG palette + cell builder) | pure transform | `reports/modules/board_report_utils.py` | exact (sibling helper module) |
| `reports/modules/format_utils.py` (NEW) | utility (None/NaN-safe formatters) | pure transform | `utils/formatters.py` (`fmt_int`, `fmt_pct`, `fmt_days`) | exact (same role, narrower scope) |
| `reports/modules/base.py` (EDIT) | contract (BaseModule ABC + ModuleData) | request-response | self (existing `render_pdf_section`, `render_excel_tabs`, `_empty_result`) | exact |
| `reports/modules/__init__.py` (EDIT) | package exports | static | self (existing `__all__` block) | exact |
| `reports/management_summary.py:1853` (EDIT) | report (QUALITY-01 fix site) | render | `management_summary.py:1830, 1865` (sibling guards on the same tile builder) | exact |
| `reports/management_summary.py:other` (EDIT — QUALITY-03 audit) | report | render | sibling lines in same file already do `if x is not None else "N/A"` | exact |
| QUALITY-03 audit findings across `reports/modules/*.py` | report renderers | render | `reports/modules/scan_coverage_sla_module.py:353, 490, 577` (the established "guard before format" pattern) | exact |
| `CLAUDE.md` (project root) | docs | static | existing "Board-Style Reports — Module Infrastructure" + "Adding a New Report — Required Steps" sections | exact (extend in place) |

---

## Pattern Assignments

### 1. NEW: `reports/modules/rag_utils.py`

**Analog:** `reports/modules/board_report_utils.py` (full file — header, constants block, public function with Numpydoc + Examples).

**Header pattern** (board_report_utils.py:1-40 — copy this shape exactly):

```python
"""
reports/modules/rag_utils.py — Shared RAG (Red/Amber/Green) palette and
cover-page strip helpers for module-based reports.

This module is the neutrally-named home for the RAG status colors, labels,
and the convenience `build_rag_strip_entry()` constructor used by the
cover-page strip in board-style and management-style composed reports.

It is intentionally NOT registered as a BaseModule; these are pure helpers
imported directly by metric modules and by `BaseModule.render_rag_strip_entry()`'s
no-op default.

Public exports
--------------
- ``STATUS_COLOR``         — dict[str, str] of green/yellow/red/no_data hex colors
- ``STATUS_LABEL``         — dict[str, str] of "On Target"/"At Risk"/"Off Target"/"No Data"
- ``rag_status_from_value`` — wrapper around board_report_utils.sla_status_from_thresholds
- ``build_rag_strip_entry`` — convenience constructor for the strip cell dict
- ``NO_DATA_HEADLINE``     — sentinel "—" string for missing values
- ``NO_DATA_DRIVER``       — sentinel "No data in scope." driver-narrative string
"""

from __future__ import annotations

import logging
from typing import Optional

from reports.modules.board_report_utils import sla_status_from_thresholds

logger = logging.getLogger(__name__)
```

**Constants block pattern** (board_report_utils.py:42-50, scan_coverage_sla_module.py:62-75 — directly copies the per-module palette into the new shared module):

```python
# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

#: Hex colors for RAG status keys. Mirrors the per-module _STATUS_COLOR
#: dicts that already exist in scan_coverage_sla_module.py:62-67 and
#: the other three board metric modules. Phase 1 ships this as a shared
#: copy; Phase 3 migrates the four board modules to use it.
STATUS_COLOR: dict[str, str] = {
    "green":   "#388e3c",
    "yellow":  "#f57c00",
    "red":     "#d32f2f",
    "no_data": "#757575",
}

#: Display labels for RAG status keys.
STATUS_LABEL: dict[str, str] = {
    "green":   "On Target",
    "yellow":  "At Risk",
    "red":     "Off Target",
    "no_data": "No Data",
}

#: Sentinel headline value used when a metric has no data in scope.
NO_DATA_HEADLINE: str = "—"

#: Sentinel driver-narrative used when a metric has no data in scope.
NO_DATA_DRIVER: str = "No data in scope."
```

**Wrapper function pattern** (modeled directly on `sla_status_from_thresholds` — board_report_utils.py:477-531). Reproduce the Numpydoc + Examples block:

```python
# ===========================================================================
# RAG status classification
# ===========================================================================

def rag_status_from_value(
    value:            Optional[float],
    green_threshold:  float,
    yellow_threshold: float,
    direction:        str = "higher_is_better",
) -> str:
    """
    Classify a metric value as green / yellow / red / no_data.

    Thin neutrally-named wrapper around
    ``board_report_utils.sla_status_from_thresholds`` so management-summary
    and any future non-board modules can adopt RAG without importing from a
    board-prefixed file. Both call sites coexist until v2 cleanup.

    Parameters
    ----------
    value : float or None
        The metric value to classify.  ``None`` → ``"no_data"``.
    green_threshold : float
        Boundary between green and yellow.
    yellow_threshold : float
        Boundary between yellow and red.
    direction : str
        ``"higher_is_better"`` (default) or ``"lower_is_better"``.

    Returns
    -------
    str
        One of ``"green"``, ``"yellow"``, ``"red"``, ``"no_data"``.
    """
    return sla_status_from_thresholds(
        value=value,
        green_threshold=green_threshold,
        yellow_threshold=yellow_threshold,
        direction=direction,
    )
```

**Constructor function pattern** (CONTEXT.md D-11 reference signature):

```python
# ===========================================================================
# Strip cell construction
# ===========================================================================

def build_rag_strip_entry(
    display_name:       str,
    headline_value_str: str,
    status:             str,
) -> dict:
    """
    Build the cover-page RAG-strip cell dict for a single module.

    Parameters
    ----------
    display_name : str
        Human-readable label (typically ``self.DISPLAY_NAME``).
    headline_value_str : str
        Pre-formatted headline (e.g. ``"87.4%"``, ``"12 assets"``, ``"—"``).
        Module owns its own display formatting; the composer plops this
        string directly into the strip cell.
    status : str
        One of ``"green"``, ``"yellow"``, ``"red"``, ``"no_data"``.
        Unknown values fall back to ``"no_data"``.

    Returns
    -------
    dict
        Strip cell dict with keys ``label``, ``headline_value``,
        ``rag_color``, ``rag_label`` per CONTRACT-03.

    Examples
    --------
    >>> build_rag_strip_entry("Scan Coverage SLA", "97.2%", "green")
    {'label': 'Scan Coverage SLA', 'headline_value': '97.2%',
     'rag_color': '#388e3c', 'rag_label': 'On Target'}
    """
    if status not in STATUS_COLOR:
        status = "no_data"
    return {
        "label":          display_name,
        "headline_value": headline_value_str,
        "rag_color":      STATUS_COLOR[status],
        "rag_label":      STATUS_LABEL[status],
    }
```

**Anti-patterns to avoid:**
- Do NOT register this with `@register_module` — it is a pure helper, not a metric module. (Mirrors `board_report_utils.py` which is also unregistered.)
- Do NOT raise on unknown `status` values — fall back to `"no_data"` and continue. (CONVENTIONS error-handling rule: log-and-continue, never raise.)
- Do NOT add a `STATUS_FILL_COLOR` openpyxl palette in v1 unless Phase 3's exemplar adoption requires it (CONTEXT.md "Claude's Discretion").
- Do NOT use `# noqa: BLE001` — the wrapper has no broad except.

---

### 2. NEW: `reports/modules/format_utils.py`

**Analog:** `utils/formatters.py:255-289` — `fmt_int`, `fmt_pct`, `fmt_days` are the same shape (None/NaN-safe formatters) but use the older `try/except (TypeError, ValueError)` style and a different default (`"N/A"`/`"—"`). The new file establishes a tighter contract: `pd.isna`-safe (handles pandas slices that mix `None` and `NaN`), unified default `"—"`, and `safe_format` for arbitrary format specs.

**Existing `fmt_int` pattern** (utils/formatters.py:255-260) — direct ancestor of `safe_int`:

```python
def fmt_int(value) -> str:
    """Format an integer with thousands separator, or '—' for None/NaN."""
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "—"
```

**Existing `fmt_pct` pattern** (utils/formatters.py:263-279) — direct ancestor of `safe_pct`:

```python
def fmt_pct(value: Optional[float], decimals: int = 1) -> str:
    """
    Format a float fraction (0.0–1.0) as a percentage string.

    Examples
    --------
    >>> fmt_pct(0.857)
    '85.7%'
    >>> fmt_pct(None)
    'N/A'
    """
    if value is None:
        return "N/A"
    try:
        return f"{value * 100:.{decimals}f}%"
    except (TypeError, ValueError):
        return "N/A"
```

**Header pattern for the new file** (mirrors `utils/formatters.py:1-22`):

```python
"""
reports/modules/format_utils.py — None/NaN-safe formatters for metric values
emitted by BaseModule render methods.

These are tighter, pandas-aware siblings of `utils/formatters.py:fmt_int /
fmt_pct / fmt_days`. Three differences:

1. They use `pd.isna()` so a NaN coming out of a pandas slice (mixed None/NaN
   in the same series) is treated identically to a Python `None`.
2. They default to the documented "—" sentinel rather than mixing "N/A" /
   "—" / different per-helper defaults.
3. `safe_format` exposes an arbitrary format-spec escape hatch.

All four render methods on BaseModule MUST use these helpers when
interpolating metric values that could be None or NaN. New modules that
bypass them are caught at code review.

Public exports
--------------
- ``safe_pct``    — None/NaN-safe percent formatter
- ``safe_int``    — None/NaN-safe integer with thousands separator
- ``safe_format`` — None/NaN-safe arbitrary format spec
"""

from __future__ import annotations

from typing import Any

import pandas as pd
```

**`safe_pct` reference signature** (CONTEXT.md D-14, "specifics" section, and 2026-05-04 incident pattern):

```python
# ===========================================================================
# None/NaN-safe formatters
# ===========================================================================

def safe_pct(
    val:       Any,
    default:   str = "—",
    precision: int = 1,
) -> str:
    """
    Format a numeric value as a percentage, returning ``default`` for
    None / NaN inputs.

    The value is interpreted as already-percentage (e.g. ``87.4`` →
    ``"87.4%"``), NOT a fraction. Modules that compute a 0.0-1.0 fraction
    should multiply by 100 before passing.

    Parameters
    ----------
    val : Any
        Numeric value or None / NaN.
    default : str
        Sentinel returned when val is None or NaN. Default ``"—"``.
    precision : int
        Decimal places. Default 1.

    Returns
    -------
    str
        ``f"{val:.{precision}f}%"`` on success; ``default`` on None / NaN /
        un-formattable input.

    Examples
    --------
    >>> safe_pct(87.4)
    '87.4%'
    >>> safe_pct(None)
    '—'
    >>> safe_pct(float('nan'))
    '—'
    >>> safe_pct(95, precision=0)
    '95%'
    """
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return f"{float(val):.{precision}f}%"
    except (TypeError, ValueError):
        return default
```

**`safe_int` reference signature** (mirrors `fmt_int` but with `pd.isna` guard):

```python
def safe_int(
    val:     Any,
    default: str = "—",
) -> str:
    """
    Format a numeric value as an integer with thousands separator,
    returning ``default`` for None / NaN inputs.

    Examples
    --------
    >>> safe_int(12345)
    '12,345'
    >>> safe_int(None)
    '—'
    >>> safe_int(float('nan'))
    '—'
    """
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return f"{int(val):,}"
    except (TypeError, ValueError):
        return default
```

**`safe_format` reference signature** (D-14 escape hatch — covers `mttr_days` etc.):

```python
def safe_format(
    val:     Any,
    fmt:     str,
    default: str = "—",
) -> str:
    """
    Apply an arbitrary format spec to a value, returning ``default`` for
    None / NaN.  The format spec is the part after the colon in an
    f-string — e.g. ``".1f"``, ``",d"``, ``"06.2f"``.

    Examples
    --------
    >>> safe_format(12.345, ".1f")
    '12.3'
    >>> safe_format(None, ".1f")
    '—'
    >>> safe_format(1234, ",d")
    '1,234'
    """
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return format(val, fmt)
    except (TypeError, ValueError):
        return default
```

**Anti-patterns to avoid:**
- Do NOT use `Optional[X]` in new code — modern union syntax (`X | None`) per CONVENTIONS, but `Any` is used here because the input may be int / float / Decimal / numpy scalar.
- Do NOT raise on un-formattable input — return `default` and continue (consistent with the 2026-05-04 incident pattern).
- Do NOT bare-except — `(TypeError, ValueError)` only, mirroring the existing `fmt_int` pattern at `utils/formatters.py:259`.
- Do NOT default to `"N/A"` — the project sentinel decided in CONTEXT.md "specifics" is `"—"`. (`utils/formatters.py` mixes both; the new file standardizes.)
- Do NOT add a `safe_count(val, suffix=, default=)` helper in v1 — explicitly listed as Claude's Discretion in CONTEXT.md "Claude's Discretion" and "Deferred Ideas". Decide at planning time; default to omitting unless a render method needs it.

---

### 3. EDIT: `reports/modules/base.py` — three new render methods

**Analog:** Existing `render_pdf_section()` (lines 237-264) and `render_excel_tabs()` (lines 266-299) on the same class. The new methods follow the same shape exactly: concrete (NOT `@abstractmethod`), no-op default return, Numpydoc with **Default**/**Contract for overrides** sections, override-when-in-`SUPPORTED_OUTPUTS` guidance.

**Existing `render_pdf_section` excerpt** (base.py:237-264 — copy this shape):

```python
def render_pdf_section(
    self,
    data:   ModuleData,
    config: ModuleConfig,
) -> str:
    """
    Render module output as an HTML fragment for WeasyPrint.

    **Default:** returns ``""`` (no PDF output).  Override when
    ``"pdf"`` is in ``self.SUPPORTED_OUTPUTS``.

    Contract for overrides
    ----------------------
    - Return a **self-contained HTML fragment** — no ``<html>``,
      ``<head>``, or ``<body>`` tags.
    - Use **inline CSS only** or CSS class names defined in the
      global report stylesheet.  No ``<link>`` tags, no external
      URLs.
    - Embed charts as ``data:image/png;base64,...`` URIs.
    - If ``data.error`` is set, render an error callout ``<div>``
      with class ``error-box`` — do **not** raise an exception.

    Returns
    -------
    str
        HTML fragment, or ``""`` to produce no PDF section.
    """
    return ""
```

**Existing `render_excel_tabs` excerpt** (base.py:266-299):

```python
def render_excel_tabs(
    self,
    data:     ModuleData,
    workbook: Any,
    config:   ModuleConfig,
) -> list[str]:
    """
    Write one or more tabs into an openpyxl Workbook.

    **Default:** writes nothing and returns ``[]``.  Override when
    ``"excel"`` is in ``self.SUPPORTED_OUTPUTS``.
    ...
    """
    return []
```

**New methods to add** (insert under the existing `render_excel_tabs` at line 299 — same `# ----` subsection banner; D-02, D-03, D-04 from CONTEXT.md):

```python
def render_email_panel(
    self,
    data:   ModuleData,
    config: ModuleConfig,
) -> str:
    """
    Render module output as an inline-CSS HTML fragment for the
    composed email body.

    **Default:** returns ``""`` (no contribution to the email body).
    Override when ``"email"`` is in ``self.SUPPORTED_OUTPUTS`` and the
    module wants to appear as a per-module panel in the assembled
    email body.

    Contract for overrides
    ----------------------
    - Return a **self-contained inline-CSS HTML fragment** — no
      ``<html>``, ``<head>``, ``<body>``, or ``<style>`` blocks.
      Outlook / Gmail / Apple Mail compatibility requires inline
      style attributes only.
    - Embed gauge images as ``cid:`` references (the composer
      provides the CID image map) OR as ``data:image/png;base64,...``
      URIs. Both are tolerated; ``cid:`` is preferred for size.
    - Include a 1-line "what's driving it" string sourced from
      ``data.driver_narrative`` so the panel matches the cover-page
      strip.
    - On ``data.error`` or empty driver narrative, return ``""``
      (the composer concatenates non-empty fragments only).
    - Use ``safe_pct``/``safe_int``/``safe_format`` from
      ``reports.modules.format_utils`` for any numeric interpolation.
      Inline f-string format specs on possibly-``None`` metric values
      are forbidden.

    Returns
    -------
    str
        HTML fragment, or ``""`` to omit this module from the panel
        section.
    """
    return ""

def render_analyst_tabs(
    self,
    data:   ModuleData,
    config: ModuleConfig,
) -> list[tuple[str, pd.DataFrame]]:
    """
    Return one or more (sheet_name, DataFrame) tuples of pivot-friendly
    drill-down rows for the analyst-detail companion workbook.

    **Default:** returns ``[]``.  Un-migrated modules don't appear as
    tabs in the analyst workbook (no empty-tab noise).

    Contract for overrides
    ----------------------
    - Each tuple is one worksheet.  ``sheet_name`` must be unique
      within the module's contribution and <= 31 chars (Excel limit).
    - The DataFrame should be **flat and pivot-table-friendly** —
      one row per finding/asset, no aggregation.  Analysts pivot
      themselves.
    - On ``data.error`` or zero-row data, return ``[]``.  The
      composer produces no tab for an empty contribution.
    - Source data MUST come from ``data.analyst_rows`` (populated
      inside ``compute()``); this method is a pure render path.

    Returns
    -------
    list[tuple[str, pd.DataFrame]]
        ``[]`` if the module emits no analyst detail.
    """
    return []

def render_rag_strip_entry(
    self,
    data:   ModuleData,
    config: ModuleConfig,
) -> dict:
    """
    Return the cover-page RAG-strip cell for this module.

    **Default:** returns a gray "No Data" cell shaped like
    ``{"label": self.DISPLAY_NAME, "headline_value": "—",
        "rag_color": "#757575", "rag_label": "No Data"}``.
    The strip ALWAYS shows one cell per module so missed overrides
    are visually obvious instead of silently disappearing.

    Contract for overrides
    ----------------------
    - Return a dict with exactly four keys: ``label``,
      ``headline_value``, ``rag_color``, ``rag_label``.
      No additional keys in v1 (per CONTRACT-03).
    - ``headline_value`` is a pre-formatted string (e.g.
      ``"87.4%"``, ``"12 assets"``, ``"—"``); the composer
      does not reformat.
    - On ``data.error`` or no-data conditions, return the
      gray default (use ``rag_utils.build_rag_strip_entry``
      with status ``"no_data"`` for consistency).
    - Use ``safe_pct``/``safe_int``/``safe_format`` for the
      headline value when sourcing from possibly-``None``
      metrics.

    Returns
    -------
    dict
        Strip cell dict.  Always non-empty so the cover strip
        is structurally consistent.
    """
    from reports.modules.rag_utils import (
        STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE,
    )
    return {
        "label":          self.DISPLAY_NAME,
        "headline_value": NO_DATA_HEADLINE,
        "rag_color":      STATUS_COLOR["no_data"],
        "rag_label":      STATUS_LABEL["no_data"],
    }
```

**Anti-patterns to avoid:**
- Do NOT decorate the new methods with `@abstractmethod`. Existing 7 registered modules (4 board + 3 management) keep instantiating without code changes — that contract is locked by D-01.
- Do NOT raise from any of the new methods on a zero-row `ModuleData`. Return safe defaults. (Anti-pattern: "Raising exceptions out of report code", ARCHITECTURE.md.)
- Do NOT use a top-of-file `from reports.modules.rag_utils import ...` — that would create an import cycle (`base.py` → `rag_utils.py` → `board_report_utils.py`, and `rag_utils.py` may need to import from `base.py` in the future). Use a deferred import inside `render_rag_strip_entry` (shown above) per the `# noqa: PLC0415` pattern documented in CONVENTIONS.md.

---

### 4. EDIT: `reports/modules/base.py` — three new ModuleData fields + updated `_empty_result`

**Analog:** Existing `ModuleData` dataclass at base.py:78-126 (CONTEXT.md canonical_refs). Existing fields use `dict` / `list[dict]` / `str` with `Optional[str]` for the error sentinel. Existing convention uses `field(default_factory=dict)` per CONVENTIONS.md "Dataclasses" section.

**Existing `ModuleData` excerpt** (base.py:78-126):

```python
@dataclass
class ModuleData:
    """
    Structured output returned by ``BaseModule.compute()``.
    ...
    """

    module_id:    str
    display_name: str
    metrics:      dict
    table_data:   list[dict]
    chart_data:   dict
    summary_text: str
    metadata:     dict
    error:        Optional[str]
```

**Three new fields to add** (D-05, D-06, D-07; insert after `metadata` and before `error` to preserve the "error is the last field" reading order; all with safe defaults so existing `ModuleData(...)` calls continue to work — D-06):

```python
    module_id:        str
    display_name:     str
    metrics:          dict
    table_data:       list[dict]
    chart_data:       dict
    summary_text:     str
    metadata:         dict
    # --- New in Phase 1 (CONTRACT-04) ---
    driver_narrative: str                                       = ""
    analyst_rows:     list[tuple[str, pd.DataFrame]]            = field(default_factory=list)
    rag_strip:        dict                                      = field(default_factory=dict)
    # ------------------------------------
    error:            Optional[str]                             = None
```

**Important:** Because dataclasses require default-bearing fields to come AFTER non-default fields, all three new fields and the existing `error` field need defaults. `error: Optional[str] = None` is consistent with how `_empty_result` is populated. Confirm at planning time that no existing call site constructs `ModuleData` positionally — if any do, this becomes a backward-compat break and the planner needs an alternative ordering or `kw_only=True` on the dataclass.

**Existing `_empty_result` excerpt** (base.py:398-422):

```python
def _empty_result(
    self,
    error_message: str,
    config: ModuleConfig,
) -> ModuleData:
    """
    Convenience method for returning a failed ModuleData from
    inside a caught exception handler.

    Usage::

        except Exception as exc:
            logger.error(...)
            return self._empty_result(str(exc), config)
    """
    return ModuleData(
        module_id    = self.MODULE_ID,
        display_name = self.DISPLAY_NAME,
        metrics      = {},
        table_data   = [],
        chart_data   = {},
        summary_text = "",
        metadata     = {},
        error        = error_message,
    )
```

**Updated `_empty_result` pattern** (Phase 1: populate the three new fields with safe defaults so the exception path produces a coherent strip cell + empty analyst tabs + "No data" driver):

```python
def _empty_result(
    self,
    error_message: str,
    config: ModuleConfig,
) -> ModuleData:
    """
    Convenience method for returning a failed ModuleData from
    inside a caught exception handler.

    Populates the three Phase 1 render fields (driver_narrative,
    analyst_rows, rag_strip) with safe defaults so the cover strip
    shows a gray "No Data" cell and the email panel / analyst tabs
    contribute nothing instead of crashing the assembler.

    Usage::

        except Exception as exc:
            logger.error(...)
            return self._empty_result(str(exc), config)
    """
    from reports.modules.rag_utils import (
        STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE, NO_DATA_DRIVER,
    )
    return ModuleData(
        module_id        = self.MODULE_ID,
        display_name     = self.DISPLAY_NAME,
        metrics          = {},
        table_data       = [],
        chart_data       = {},
        summary_text     = "",
        metadata         = {},
        driver_narrative = NO_DATA_DRIVER,
        analyst_rows     = [],
        rag_strip        = {
            "label":          self.DISPLAY_NAME,
            "headline_value": NO_DATA_HEADLINE,
            "rag_color":      STATUS_COLOR["no_data"],
            "rag_label":      STATUS_LABEL["no_data"],
        },
        error            = error_message,
    )
```

**Anti-patterns to avoid:**
- Do NOT use a single `render_payload: dict` field in place of three discrete fields. Explicitly rejected by D-05.
- Do NOT use a nested dataclass (e.g. `RenderPayload`). Explicitly rejected by D-05.
- Do NOT use mutable default `=[]` / `={}` — use `field(default_factory=...)` per CONVENTIONS.md "Dataclasses" and existing `ModuleConfig.options: dict = field(default_factory=dict)` at base.py:75.
- Do NOT change the order of the existing fields — keep them in their current positions; new fields slot before `error`.
- Do NOT make `_empty_result` import `rag_utils` at module top — keep the import deferred to avoid circular import risk (same pattern as the renderer above).

---

### 5. EDIT: `reports/modules/__init__.py` — export new symbols

**Analog:** Existing `__init__.py` (full file, 76 lines). Pattern is clear:
1. Imports placed in dependency order (registry first, then `BaseModule`/`ModuleConfig`/`ModuleData`, then `ReportComposer`).
2. `registry.discover()` triggered last.
3. `__all__` lists the public API.

**Existing import + `__all__` block** (`__init__.py:51-76`):

```python
from __future__ import annotations

# Registry and decorator first — modules imported below depend on these
# being available when their @register_module decorator executes.
from reports.modules.registry import registry, register_module  # noqa: F401

# Core data contracts
from reports.modules.base import BaseModule, ModuleConfig, ModuleData  # noqa: F401

# Composition utilities
from reports.modules.composer import ReportComposer  # noqa: F401

# Trigger auto-discovery of all *_module.py and *_metrics.py files in
# this directory. Modules self-register via @register_module on import.
# This call is intentionally last so that the registry and base classes
# are fully initialised before any module file is imported.
registry.discover()

__all__ = [
    "registry",
    "register_module",
    "BaseModule",
    "ModuleConfig",
    "ModuleData",
    "ReportComposer",
]
```

**Updated block** (insert two new helper imports BEFORE `registry.discover()`; extend `__all__` per CONTEXT.md Integration Points):

```python
# Core data contracts
from reports.modules.base import BaseModule, ModuleConfig, ModuleData  # noqa: F401

# Render-time helpers (Phase 1)
from reports.modules.format_utils import (  # noqa: F401
    safe_pct, safe_int, safe_format,
)
from reports.modules.rag_utils import (  # noqa: F401
    STATUS_COLOR, STATUS_LABEL,
    rag_status_from_value, build_rag_strip_entry,
    NO_DATA_HEADLINE, NO_DATA_DRIVER,
)

# Composition utilities
from reports.modules.composer import ReportComposer  # noqa: F401

# Trigger auto-discovery ...
registry.discover()

__all__ = [
    "registry",
    "register_module",
    "BaseModule",
    "ModuleConfig",
    "ModuleData",
    "ReportComposer",
    # Phase 1 render helpers
    "safe_pct",
    "safe_int",
    "safe_format",
    "STATUS_COLOR",
    "STATUS_LABEL",
    "rag_status_from_value",
    "build_rag_strip_entry",
    "NO_DATA_HEADLINE",
    "NO_DATA_DRIVER",
]
```

**Anti-patterns to avoid:**
- Do NOT import from `format_utils` / `rag_utils` BEFORE `BaseModule` — `rag_utils` does not import `BaseModule`, but `format_utils` and `rag_utils` must be importable before `registry.discover()` triggers since metric modules may use them at class-body construction time.
- Do NOT include the new helpers in the `# noqa: F401` for the `registry`/`base` lines — give them their own `# noqa: F401` comment per existing style.
- Do NOT split `__all__` into two lists — keep it as one list with a `# Phase 1 render helpers` comment delimiter (matches the in-file comment-banner style).

---

### 6. EDIT: `reports/management_summary.py:1853` — QUALITY-01 fix

**Analog:** The 2026-05-04 `exception_rate` patch (commit `52616a0`). Look at sibling lines on the same `_compute_kpi_tiles` function in `management_summary.py`:
- Line 1830: `comp_str  = f"{comp_rate:.1f}%" if comp_rate is not None else "N/A"`
- Line 1865: `exc_str  = f"{exc_rate:.1f}%" if exc_rate is not None else "N/A"`

The QUALITY-01 site at line 1853 currently reads:

```python
# reports/management_summary.py:1846-1855 (Tile 4 — Scan Coverage)
if m2.get("error"):
    cov_str   = "N/A"
    cov_color = _GREY
    cov_sub   = "data unavailable"
else:
    cov_pct   = m2["coverage_pct"]
    cov_str   = f"{cov_pct:.1f}%"          # ← QUALITY-01 site (line 1853)
    cov_color = _GREEN if cov_pct >= 90 else (_AMBER if cov_pct >= 75 else _RED)
    cov_sub   = f"{m2['scanned']:,} of {m2['total_licensed']:,} assets scanned"
```

**Replacement pattern** (D-16 — use `safe_pct`):

```python
# reports/management_summary.py:1846-1855 (after fix)
if m2.get("error"):
    cov_str   = "N/A"
    cov_color = _GREY
    cov_sub   = "data unavailable"
else:
    cov_pct   = m2["coverage_pct"]
    cov_str   = safe_pct(cov_pct)          # ← Fixed (was f"{cov_pct:.1f}%")
    cov_color = _GREEN if cov_pct is not None and cov_pct >= 90 else (
        _AMBER if cov_pct is not None and cov_pct >= 75 else _RED
    )
    cov_sub   = f"{m2['scanned']:,} of {m2['total_licensed']:,} assets scanned"
```

The bare `cov_pct >= 90` comparison ALSO crashes on `None`; ship the matching guard as part of the fix even though the requirement only names the format string. The intent of QUALITY-01 is "no `TypeError` on a zero-licensed-asset run" (Phase 1 success criterion 4), so fixing only the f-string would still leave the crash path live.

**Import to add at the top of `management_summary.py`** (planner: locate the existing local-imports section; mirror existing `from utils.formatters import ...` if present):

```python
from reports.modules import safe_pct  # Phase 1: None-safe percent formatter
```

**Anti-patterns to avoid:**
- Do NOT keep the inline `f"{cov_pct:.1f}%"` "for now" — the whole point of QUALITY-01 is to remove this pattern.
- Do NOT change the `"N/A"` default in the `m2.get("error")` branch — leave the existing string as-is. (`safe_pct` defaults to `"—"`, but only in the no-data path on the new helper; the legacy branch can continue using `"N/A"` to avoid expanding scope.) Or: pass `default="N/A"` to `safe_pct` if planner prefers symmetry. Either is acceptable; flag as planner discretion.
- Do NOT replace the `>= 90` / `>= 75` numeric comparisons with `safe_*` — they need a real number for color selection; the `is not None` guard is the right tool there.

---

### 7. EDIT: QUALITY-03 audit findings

**Analog (the established pattern):** See `scan_coverage_sla_module.py:353` and the dozens of identical `f"{x:.1f}%" if x is not None else "N/A"` ternaries in `aged_vulns_assets_module`, `critical_remediation_sla_module`, `high_risk_assets_module`, `patch_compliance_rate_module`. Those are ALREADY guarded — they are the "good" reference. The audit's job is to find the few that lack the guard.

**Audit grep targets** (run by the planner; results below are the read-only audit I executed):

Patterns greppped across `reports/`:
- `:\.\df\}%` (any decimal-precision percent)
- `:\,d\}|:\.0%\}|:%\}` (thousands and bare-percent specs)

**Audit results — all `:\d.f}%` matches in `reports/`:**

| File:Line | Snippet | Already guarded? | Action |
|-----------|---------|------------------|--------|
| `reports/asset_risk.py:455` | `f"{int(h):,}\n({pct:.0f}%)"` | `pct` is computed from a non-empty histogram; check if guard needed | INVESTIGATE |
| `reports/unscanned_assets.py:470` | `f"{metrics['on_time'] / total * 100:.1f}%  ← Scan Coverage SLA numerator"` | guarded by `if total ...` block earlier; audit | INVESTIGATE |
| `reports/modules/aged_vulns_assets_module.py:335` | `pct_display = f"{gauge_value:.1f}%"` | `gauge_value` derived in `compute()`, may be 0.0 placeholder for None | INVESTIGATE — check whether `gauge_value` can be None |
| `reports/modules/aged_vulns_assets_module.py:345, 477, 564, 702` | `f"{aged_assets_pct:.1f}%" if aged_assets_pct is not None else "N/A"` | YES (existing pattern) | NO ACTION (already guarded) |
| `reports/modules/aged_vulns_assets_module.py:419-420, 492-494` | `{_GREEN_THRESHOLD:.0f}%` etc. | constant — never None | NO ACTION |
| `reports/management_summary.py:1124` | `pct_str = f"{b['pct']:.1f}%"` (in `_build_age_bar_chart`) | `b['pct']` sourced from `m5_data` list of bucket dicts; check whether bucket pct can be None | INVESTIGATE |
| `reports/management_summary.py:1483` | `val_str = f"{rate:.0f}%" if rate is not None else "N/A"` | YES | NO ACTION |
| `reports/management_summary.py:1542` | `f"{m4['overall_rate']:.1f}%" if m4['overall_rate'] is not None else "N/A"` | YES | NO ACTION |
| `reports/management_summary.py:1568` | `exc_rate_str = f"{exc_rate:.1f}%" if exc_rate is not None else "N/A"` | YES | NO ACTION (mirrors 2026-05-04 fix) |
| `reports/management_summary.py:1830` | `comp_str = f"{comp_rate:.1f}%" if comp_rate is not None else "N/A"` | YES | NO ACTION |
| `reports/management_summary.py:1853` | `cov_str = f"{cov_pct:.1f}%"` | **NO** | **FIX (QUALITY-01)** |
| `reports/management_summary.py:1865` | `exc_str = f"{exc_rate:.1f}%" if exc_rate is not None else "N/A"` | YES | NO ACTION |
| `reports/trend_analysis.py:765` | `f"... {pct_old:.1f}% of current backlog"` | check whether `pct_old` can be None | INVESTIGATE |
| `reports/modules/critical_remediation_sla_module.py:363` | `pct_display = f"{gauge_value:.1f}%"` | same pattern as aged_vulns:335 | INVESTIGATE |
| `reports/modules/critical_remediation_sla_module.py:373, 508, 600, 767` | guarded `if sla_pct is not None else "N/A"` | YES | NO ACTION |
| `reports/modules/critical_remediation_sla_module.py:420, 558` | `f"{bu_pct:.1f}%"` (per-BU loop, value sourced from `compute_per_bu_breakdown` rounded float) | bu_pct cannot be None per the helper's contract (BUs with zero denom excluded) | NO ACTION (guarded by helper contract) |
| `reports/modules/critical_remediation_sla_module.py:452-453, 523-525` | constants | NO ACTION |
| `reports/modules/high_risk_assets_module.py:341` | `pct_display = f"{gauge_value:.1f}%"` | same pattern | INVESTIGATE |
| `reports/modules/high_risk_assets_module.py:351, 483, 570, 723` | guarded `if high_risk_pct is not None else "N/A"` | YES | NO ACTION |
| `reports/modules/high_risk_assets_module.py:426-427, 498-500` | constants | NO ACTION |
| `reports/modules/patch_compliance_rate_module.py:290, 361, 429, 441, 477` | already guarded | YES | NO ACTION |
| `reports/modules/scan_coverage_sla_module.py:231, 343, 353, 397, 490, 534, 577` | mix: lines 343 and 397 / 534 use `gauge_value` / `bu_pct` (helper-guaranteed); rest already guarded | NO ACTION (helper contract) |
| `reports/modules/total_vulns_by_severity_module.py:284` | `ws.cell(row=row_idx, column=3, value=f"{pct:.1f}%")` (per-severity loop) | check whether `pct` can be None | INVESTIGATE |

**Planner action on the audit:** open each `INVESTIGATE` line, trace the producing code, and either:
1. Confirm the value is structurally non-None (annotate with a brief code-comment so the next audit doesn't re-flag), or
2. Wrap with `safe_pct(...)` / `safe_int(...)` and import the helper from `reports.modules`.

**Replacement pattern for any survivor** (mirroring QUALITY-01):

```python
# Before
val_str = f"{my_pct:.1f}%"

# After
val_str = safe_pct(my_pct)
```

**Anti-patterns to avoid:**
- Do NOT add a `noqa` comment to silence the audit. Either fix or annotate.
- Do NOT introduce `safe_pct(my_pct, default="N/A")` everywhere — only when the surrounding code visibly expects `"N/A"`. New code defaults to `"—"`.
- Do NOT add `safe_pct` calls inside `compute()` methods — those return raw numerics; formatting is a render-time concern. (Anti-pattern: "Side effects in `compute()`" is adjacent — this isn't a side effect, but mixing format strings into compute() blurs the layer.)

---

### 8. EDIT: `CLAUDE.md` (project root) — document the four-channel render contract

**Analog:** Existing "Board-Style Reports — Module Infrastructure" section (the existing CLAUDE.md content the user provided in context). The current section already describes:
- Module anatomy (`*_module.py` filename, `@register_module`, `compute()`/`render_pdf_section()`/`render_excel_tabs()`/`render_email_kpis()`)
- Adding a new module to an existing composed report (3-step recipe)
- Key files table

**Phase 1 extends this section with three additions** (CONTRACT-05):

1. A new "Four-channel render contract" subsection listing the four render methods (`render_pdf_section`, `render_excel_tabs`, `render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) and noting that all five are concrete with no-op defaults (NOT `@abstractmethod`).
2. A new "Empty-data guard pattern" subsection requiring that every render method use `safe_pct` / `safe_int` / `safe_format` from `reports.modules.format_utils` when interpolating possibly-None metric values, and return a sensible empty representation rather than raising on a zero-row `ModuleData`.
3. An updated "Adding a new module" subsection (or sibling — Claude's discretion per CONTEXT.md) showing the imports of `safe_pct` / `STATUS_COLOR` etc. and demonstrating the no-op renderer override for `render_rag_strip_entry`.

**Pattern to copy from** (existing CLAUDE.md "Module anatomy" — keep this style):

```markdown
### Module anatomy

Every metric module lives in `reports/modules/` and must:
1. Be named `*_module.py` (auto-discovered by `registry.discover()` on package import)
2. Decorate the class with `@register_module`
3. Extend `BaseModule` and implement `compute()`, `render_pdf_section()`, `render_excel_tabs()`, and `render_email_kpis()`
```

**Updated phrasing should say:** "implement `compute()`; override any of the five renderer methods (`render_pdf_section`, `render_excel_tabs`, `render_email_kpis`, `render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) whose channel the module contributes to. All renderers are concrete with no-op defaults — un-overridden methods produce empty contributions (gray 'No Data' for the RAG strip)."

**Anti-patterns to avoid:**
- Do NOT remove or rewrite the existing "Adding a New Report — Required Steps" section — that's a separate concept (top-level reports vs metric modules).
- Do NOT mark the new render methods as required — D-01 explicitly keeps them concrete with no-op defaults.
- Do NOT add a `CONTRACT_VERSION` discussion — explicitly rejected (CONTEXT.md "Established Patterns").

---

## Shared Patterns

### Logging
**Source:** `reports/modules/scan_coverage_sla_module.py:43, 281-285`
**Apply to:** Both new utility modules (`rag_utils.py`, `format_utils.py`) at the top.
```python
import logging
logger = logging.getLogger(__name__)
```
The new helpers are pure (no logging needed by default), but include the boilerplate so future warnings (e.g. unknown status fall-through in `build_rag_strip_entry`) have a logger ready.

### Module header structure
**Source:** `reports/modules/board_report_utils.py:1-40`, `utils/formatters.py:1-22`
**Apply to:** Both new utility modules.
- Multi-line module docstring with purpose + public exports list
- `from __future__ import annotations` (PEP 563)
- stdlib imports
- third-party imports (`pandas` for `format_utils.py`)
- local imports (only `rag_utils.py` imports `board_report_utils`)
- module-level `logger`

### Section banners
**Source:** `reports/modules/board_report_utils.py` (lines 42, 53, 122, 201, 282, 402, 473)
**Apply to:** All new and edited files.
- Top-level sections: `# ==========...` (75 `=` chars)
- Subsections: `# ----------...`

### Numpydoc docstrings + Examples
**Source:** `reports/modules/board_report_utils.py:477-516` (`sla_status_from_thresholds`); `utils/formatters.py:263-279` (`fmt_pct`)
**Apply to:** Every public function in `rag_utils.py` and `format_utils.py`.
Sections in order: 1-line summary → optional extended description → `Parameters` → `Returns` → `Examples`.

### Error handling — log-and-continue, never raise from helpers
**Source:** CONVENTIONS.md "Error Handling" + `utils/formatters.py:255-260, 282-289`
**Apply to:** All new helpers.
- `try / except (TypeError, ValueError): return default`
- Never bare `except:` and never re-raise.
- For `pd.isna()` calls (which can fail on weird custom types), wrap in `try / except (TypeError, ValueError): pass`.

### Deferred import to avoid circular dependency
**Source:** CONVENTIONS.md "Comments" (`# noqa: PLC0415`); `run_all.py:515, 554, 631, 849`
**Apply to:** `BaseModule.render_rag_strip_entry` and `BaseModule._empty_result` — both need `rag_utils` symbols but cannot top-level import them.
```python
def render_rag_strip_entry(self, data, config):
    from reports.modules.rag_utils import (  # noqa: PLC0415
        STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE,
    )
    return { ... }
```

### Modern type-hint syntax
**Source:** CONVENTIONS.md "Type Hints"
**Apply to:** All new code.
- `list[str]` / `dict[str, int]` / `tuple[str, pd.DataFrame]` — not `List` / `Dict` / `Tuple`.
- `X | None` for new code; `Optional[X]` is tolerated only because `base.py` already uses it (existing field `error: Optional[str]`).

---

## No Analog Found

None. Every file in scope has a clear analog inside the project. The two NEW utility files are direct siblings of well-established existing utilities.

---

## Metadata

**Analog search scope:** `reports/`, `reports/modules/`, `utils/`, `.planning/`, `CLAUDE.md`
**Files scanned:** `base.py`, `__init__.py` (modules), `board_report_utils.py`, `scan_coverage_sla_module.py`, `registry.py`, `composer.py` (referenced not read in detail), `management_summary.py` (lines 630-735, 1100-1145, 1450-1580, 1820-1880), `formatters.py`
**QUALITY-03 grep scope:** `reports/**/*.py` for `:\.\df\}%`, `:\,d\}`, `:\.0%\}`, `:%\}`
**QUALITY-03 findings:** 1 confirmed bug (line 1853, the QUALITY-01 site itself), 6 INVESTIGATE candidates, ~30 already-guarded references serving as the reference pattern
**Pattern extraction date:** 2026-05-05
