# Phase 1: Module Render Contract - Context

**Gathered:** 2026-05-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Extend the module contract in `reports/modules/base.py` so every metric module can describe how it renders into four channels — PDF section, Excel tabs, email panel, and cover-page RAG strip — and codify the empty-data guard pattern across all render methods.

**Concretely, Phase 1 ships:**
1. Three new render methods on `BaseModule` (`render_email_panel`, `render_analyst_tabs`, `render_rag_strip_entry`) — concrete with no-op defaults, NOT `@abstractmethod`.
2. Three new typed fields on `ModuleData` with safe defaults (`driver_narrative`, `analyst_rows`, `rag_strip`).
3. Two new sibling utility files: `reports/modules/rag_utils.py` and `reports/modules/format_utils.py`.
4. Updates to `reports/modules/base.py` docstrings and to the project-root `CLAUDE.md` "Adding a new module" section, including the empty-data guard pattern (CONTRACT-05).
5. The QUALITY-01 `cov_pct` fix at `management_summary.py:1853` and a full QUALITY-03 grep-style audit of `reports/` for format specs that interpolate possibly-`None` metric values.

**Phase 1 does NOT touch:**
- `ReportComposer` (Phase 2 owns the new strip-cover, email-body, and analyst-workbook assembly).
- Any of the 4 board metric modules' implementations (Phase 3 migrates them to override the new render methods).
- Any of the 3 management_summary metric modules — they stay on the no-op defaults indefinitely and are explicitly out of scope until v2.
- `delivery_config.yaml` / `delivery_config.schema.yaml` (Phase 4 owns the `analyst_detail` toggle and `jsonschema` runtime validation).

</domain>

<decisions>
## Implementation Decisions

### Abstract Enforcement
- **D-01: New render methods are concrete with no-op defaults, NOT `@abstractmethod`.** Existing 7 registered modules (4 board + 3 management) keep instantiating without code changes. Mirrors today's `render_pdf_section` / `render_excel_tabs` pattern. Trade-off accepted: a missed override silently produces an empty contribution; mitigated by the gray "No Data" cell visual in the cover-page strip and an optional Phase 4 runtime check.
- **D-02: `render_email_panel` no-op returns `""`.** Phase 2's `assemble_email_body()` concatenates non-empty fragments only — un-migrated modules contribute nothing to the panel section.
- **D-03: `render_analyst_tabs` no-op returns `[]`.** Un-migrated modules don't appear as tabs in the analyst workbook (no empty-tab noise).
- **D-04: `render_rag_strip_entry` no-op returns a gray "No Data" cell.** Shape: `{"label": self.DISPLAY_NAME, "headline_value": "—", "rag_color": "#757575", "rag_label": "No Data"}`. Strip always shows one cell per module so missed overrides are visually obvious instead of silently disappearing.

### ModuleData Shape
- **D-05: Add three discrete typed fields to `ModuleData`** (not a single `render_payload` dict, not a nested dataclass): `driver_narrative: str`, `analyst_rows: list[tuple[str, pd.DataFrame]]`, `rag_strip: dict`.
- **D-06: All three new fields default to safe empties** so existing modules' `ModuleData(...)` construction calls continue to work unchanged. Use `field(default_factory=list)` / `field(default_factory=dict)` for mutables; empty-string default for `driver_narrative`.
- **D-07: `driver_narrative` is populated inside `compute()`,** read by `render_email_panel()`. Each module owns its own driver-line semantics with full DataFrame access. Matches the existing `summary_text` pattern. (No new `compute_driver_narrative()` abstract method.)
- **D-08: `rag_strip["headline_value"]` is a pre-formatted string** (`"87.4%"`, `"12 assets"`, `"—"`). Module owns its own display formatting; composer just plops it into the strip cell. No raw-value-plus-unit indirection.
- **D-09: `rag_strip` keys are exactly `{label, headline_value, rag_color, rag_label}`** per CONTRACT-03 — no extra fields in v1. Resist scope drift toward trend arrows / scope sub-labels / etc.

### Shared RAG Palette
- **D-10: Phase 1 creates `reports/modules/rag_utils.py`** as a new sibling to `base.py`. Neutral name (NOT `board_rag_utils`) so management_summary modules can adopt in v2 without dragging in board-specific semantics.
- **D-11: `rag_utils.py` exports four things in Phase 1:**
  - `STATUS_COLOR: dict[str, str]` — green/yellow/red/no_data hex colors.
  - `STATUS_LABEL: dict[str, str]` — "On Target" / "At Risk" / "Off Target" / "No Data".
  - `rag_status_from_value(value, green_threshold, yellow_threshold, direction)` — wrapper around the existing `board_report_utils.sla_status_from_thresholds()` so modules don't have to import from a board-prefixed file. Both call sites coexist until v2 cleanup.
  - `build_rag_strip_entry(display_name, headline_value_str, status)` — convenience constructor that returns the rag_strip dict (saves Phase 3 modules from hand-building it).
  - Sentinels: `NO_DATA_HEADLINE = "—"`, `NO_DATA_DRIVER = "No data in scope."` — guarantee the gray-cell case is identical wherever it appears.
- **D-12: Opt-in adoption — Phase 1 does NOT refactor the existing 7 modules.** Each module keeps its per-module `_STATUS_COLOR` / `_STATUS_LABEL` copies. Phase 3 migrates the 4 board modules. management_summary's 3 modules stay on per-module copies until v2. The base ABC's no-op `render_rag_strip_entry` uses the `rag_utils.py` constants directly so the strip cell is coherent for un-migrated modules.

### Empty-Data Guard
- **D-13: Phase 1 creates `reports/modules/format_utils.py`** as a sibling to `rag_utils.py`. Separate file from `rag_utils.py` because RAG concerns ≠ value-formatting concerns; in the future `utils/formatters.py` may converge but that's a v2+ exercise.
- **D-14: `format_utils.py` exports three helpers:**
  - `safe_pct(val, default="—", precision=1)` — None/NaN-safe percentage formatter (returns `default` for None / NaN; otherwise `f"{val:.{precision}f}%"`).
  - `safe_int(val, default="—")` — None/NaN-safe integer with thousands separator (returns `default` for None / NaN; otherwise `f"{int(val):,}"`).
  - `safe_format(val, fmt, default="—")` — generic guarded format spec for cases not covered by `safe_pct` / `safe_int` (e.g. `safe_format(mttr_days, ".1f", default="—")`).
- **D-15: All three new render methods MUST use `safe_*` helpers** rather than inline f-string format specs when interpolating any metric value. CLAUDE.md "Adding a new module" section requires this. New modules that bypass the helpers are caught at code review.
- **D-16: QUALITY-01 fix:** Replace the `cov_pct` formatter at `management_summary.py:1853` with `safe_pct(cov_pct)`. Sibling fix to the 2026-05-04 `exception_rate` patch.
- **D-17: QUALITY-03 audit scope:** Full audit of `reports/` (top-level `*.py` plus `reports/modules/*.py`) for f-string format specs interpolating possibly-`None` metric values. Patterns to grep: `:.Xf}%`, `:,d}`, `:.0%}`, `:%}`. Each finding gets the appropriate `safe_*` helper. Audit findings are committed as part of Phase 1 (one commit per fix is fine; all in this phase). Modules in `reports/modules/` belonging to management_summary that are out of scope for migration are still in scope for the formatter audit because the fix is a one-liner, not a contract change.

### Claude's Discretion
- Exact PEP-8 / docstring formatting for `BaseModule` updates and new helper modules — match the established style in `reports/modules/base.py` (Numpydoc-flavored docstrings, `# ===` section banners, `from __future__ import annotations`).
- Whether `rag_utils.py` exports an additional `STATUS_FILL_COLOR` palette for openpyxl PatternFill RGB strings — only add if Phase 3's exemplar adoption needs it; leave out of v1 if unclear at planning time.
- Whether `format_utils.py` adds a `safe_count(val, suffix="", default="—")` helper for headline strings like "12 assets" — propose during planning; small surface area either way.
- Whether the CLAUDE.md update lives in the existing "Adding a New Report — Required Steps" section or in a new sibling "Adding a new module" section. Both work; prefer the latter so the module contract has a clear home.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project Planning
- `.planning/PROJECT.md` — v1 milestone scope, Constraints (tech stack lock, email-client compat, backward-compat, fail-soft batch semantics), Key Decisions table.
- `.planning/REQUIREMENTS.md` §"Module Render Contract" — CONTRACT-01..05; §"Empty-Data Hardening" — QUALITY-01 / QUALITY-03 (QUALITY-02 belongs to Phase 3).
- `.planning/ROADMAP.md` §"Phase 1: Module Render Contract" — goal statement, dependencies, success criteria, parallelization notes (Phases 2 and 3 are independently developable after Phase 1 ships).

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` §"Module Infrastructure", §"Key Abstractions", §"Anti-Patterns" — `BaseModule` / `ModuleData` / `ReportComposer` shape; "Side effects in compute()" anti-pattern; "Raising exceptions out of report code" anti-pattern (both relevant to the new render methods).
- `.planning/codebase/STACK.md` — pinned dependencies; `pyTenable`, `pandas`, `openpyxl`, `WeasyPrint`, `matplotlib`. No new SDKs in v1.
- `.planning/codebase/CONVENTIONS.md` — naming patterns (snake_case modules / files / functions; PascalCase classes; UPPER_SNAKE constants; `_leading_underscore` for module-private), type-hint style (`list[str]` / `dict[str, int]`, modern unions), Numpydoc docstring style.

### Project Documentation
- `CLAUDE.md` (project root) §"Board-Style Reports — Module Infrastructure", §"Adding a New Report — Required Steps" — the existing module-infrastructure section that Phase 1 must update per CONTRACT-05.

### Source Files Phase 1 Touches Directly
- `reports/modules/base.py` — `BaseModule` ABC + `ModuleConfig` / `ModuleData` dataclasses. Primary edit target.
- `reports/modules/registry.py` — `@register_module` decorator + `discover()` auto-discovery. No edits expected; agents need to understand it because it determines what "registered module" means.
- `reports/modules/__init__.py` — module package exports. May need updating to publicize `rag_utils` / `format_utils` and the new `BaseModule` / `ModuleData` extensions.
- `reports/modules/board_report_utils.py` — already exports `sla_status_from_thresholds()` and `ON_TIME_WINDOW_DAYS`; the new `rag_utils.rag_status_from_value()` wraps the former.
- `reports/management_summary.py:1853` — QUALITY-01 fix site (the `cov_pct` formatter).

### Source Files Phase 1 Reads For Context (does NOT edit)
- `reports/modules/scan_coverage_sla_module.py` — exemplar of the existing module pattern; uses `_STATUS_COLOR` / `_STATUS_LABEL` per-module; references `board_report_utils.sla_status_from_thresholds()` and `ON_TIME_WINDOW_DAYS`.
- `reports/modules/composer.py:276-664` — `ReportComposer` consumes `ModuleData` today; Phase 1 must not break the contract it relies on (Phase 2 expands it).
- `reports/modules/chart_utils.py` — `draw_gauge()` returns base64 PNG; the email-panel renderer in Phase 3 will use this. Phase 1 just makes sure the contract permits embedding base64 strings inside the HTML fragment returned by `render_email_panel()`.
- `reports/modules/example_module.py` — keep current behavior; if Phase 1 wants to update the example to demonstrate the new render methods, mark as Claude's Discretion at planning time.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`BaseModule._empty_result()`** (`reports/modules/base.py:398`) — already provides the compute-side failure path. Phase 1 should reuse this for the no-op defaults to keep one source of "empty / N/A" semantics.
- **`board_report_utils.sla_status_from_thresholds()`** — green/yellow/red classifier. New `rag_utils.rag_status_from_value()` is a thin neutrally-named wrapper; both coexist until v2.
- **`board_report_utils.deduplicate_assets_by_name()`** + `compute_per_bu_breakdown()` + `extract_business_unit()` — used by all 4 board modules. Out of scope for Phase 1, but agents should not duplicate them when adding helpers.
- **`reports/modules/chart_utils.draw_gauge()`** — returns base64 PNG. Phase 3's `render_email_panel()` will use this; Phase 1 just sizes the contract for it.

### Established Patterns
- **Pure compute, deferred render.** `BaseModule.compute()` is contractually side-effect-free (`reports/modules/base.py:191-200`). The new `driver_narrative`, `analyst_rows`, and `rag_strip` outputs MUST be produced inside `compute()` (because renderers don't get DataFrames). Same pattern applies; same anti-pattern enforced.
- **Catch-all in `compute()`.** Every existing `compute()` ends with `except Exception as exc: return self._empty_result(str(exc), config)` (`reports/modules/scan_coverage_sla_module.py:281-286`). The new fields' defaults must align with `_empty_result()` so the exception path produces a consistent empty `ModuleData`. Update `_empty_result()` to populate the three new fields with their safe defaults.
- **No-op renderer defaults.** Existing `render_pdf_section()` / `render_excel_tabs()` defaults return `""` / `[]` (`reports/modules/base.py:264, 299`). Phase 1's new methods follow the same shape exactly.
- **Class-level constants for module identity.** `MODULE_ID`, `DISPLAY_NAME`, `DESCRIPTION`, `REQUIRED_DATA`, `SUPPORTED_OUTPUTS`, `VERSION` (`reports/modules/base.py:163-174`). Don't add a new "CONTRACT_VERSION" or similar — it was considered and rejected (Area 1, third option).
- **Numpydoc docstrings + `# ===` section banners + `from __future__ import annotations`.** The new helper modules (`rag_utils.py`, `format_utils.py`) follow this pattern.
- **Module-private helpers prefixed with `_`.** Public constants and helpers in `rag_utils.py` / `format_utils.py` are unprefixed (`STATUS_COLOR`, `safe_pct`); internal helpers (if any) get a leading underscore.

### Integration Points
- **`reports/modules/__init__.py`** — public exports. After Phase 1 the `from reports.modules import …` shorthand should expose `BaseModule`, `ModuleConfig`, `ModuleData`, `register_module`, plus optionally the new `safe_pct` / `safe_int` / `safe_format` / `STATUS_COLOR` / `STATUS_LABEL` symbols. Agents should match the existing export pattern in `__init__.py`.
- **`reports/modules/composer.py:355-664`** — Phase 2 will call the new `render_email_panel()` / `render_analyst_tabs()` / `render_rag_strip_entry()` methods. Phase 1 doesn't edit composer, but the method signatures must be compatible (each takes `(data: ModuleData, config: ModuleConfig)`, same as the existing renderers).
- **`reports/board_summary.py:66`** — `_BOARD_MODULE_CONFIGS` list drives module composition. Out of scope for Phase 1; relevant only as the call site Phase 3 will smoke-test against.
- **`CLAUDE.md` (project root)** — "Adding a new module" content lives in the "Board-Style Reports — Module Infrastructure" section. Phase 1's CLAUDE.md update extends this section (or adds a new subsection) with: the four render methods + their no-op defaults, the empty-data guard requirement, and the `safe_pct` / `safe_int` / `safe_format` import convention.

### Anti-Patterns to Re-Read
- **"Side effects in `BaseModule.compute()`"** (`.planning/codebase/ARCHITECTURE.md`) — the new fields don't change this; renderers still get `ModuleData`-only.
- **"Raising exceptions out of report code"** — applies to the new renderers too. `render_email_panel()` / `render_analyst_tabs()` / `render_rag_strip_entry()` MUST catch internally and return safe defaults on error, never raise.

</code_context>

<specifics>
## Specific Ideas

- **No-op default for `render_rag_strip_entry`** is a gray cell:
  ```python
  {
      "label":          self.DISPLAY_NAME,
      "headline_value": "—",
      "rag_color":      "#757575",
      "rag_label":      "No Data",
  }
  ```
- **`safe_pct` reference signature:** `safe_pct(val: float | None, default: str = "—", precision: int = 1) -> str`. Returns `default` when `val is None` or `pd.isna(val)`; otherwise `f"{val:.{precision}f}%"`.
- **`build_rag_strip_entry` reference signature:** `build_rag_strip_entry(display_name: str, headline_value_str: str, status: str) -> dict` where `status ∈ {"green", "yellow", "red", "no_data"}` and the function looks up `STATUS_COLOR[status]` / `STATUS_LABEL[status]`.
- **2026-05-04 incident pattern** to replicate in `safe_pct` / `safe_int` / `safe_format`: every formatter returns the documented sentinel (`"—"`) instead of raising, and `pd.isna` covers both `None` and `NaN` cases (mixed types from pandas slices).

</specifics>

<deferred>
## Deferred Ideas

- **Phase 4 runtime check that detects modules registered without overriding the new render methods.** Mentioned in Area 1 as a possible mitigation against "missed override silently produces empty contribution." Not in Phase 1's scope; revisit when Phase 4 adds startup validation alongside the `jsonschema` config check (CONFIG-02).
- **Migrate `management_summary` modules to use `rag_utils.py`** — explicitly v2 (GEN-01). Phase 1 only ships the helper; opt-in adoption.
- **Migrate `ops_remediation` to the module contract** — v2 (GEN-02).
- **YAML-driven module composition (`modules: [...]` lists in `delivery_config.yaml`)** — v2 (GEN-03 / GEN-04). Phase 1 keeps module lists hardcoded.
- **`STATUS_FILL_COLOR` openpyxl palette in `rag_utils.py`** — only add if Phase 3 exemplar adoption needs it; otherwise carry forward to v2.
- **`safe_count(val, suffix=)` formatter helper** — propose during planning; small surface area either way.
- **`utils/formatters.py` ↔ `reports/modules/format_utils.py` convergence** — out of scope for v1; revisit during v2 framework polish.
- **Updating `reports/modules/example_module.py`** to demonstrate the new render methods — Claude's discretion at planning time; not blocking.

</deferred>

---

*Phase: 1-Module Render Contract*
*Context gathered: 2026-05-05*
