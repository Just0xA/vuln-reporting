# Phase 1: Module Render Contract - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-05
**Phase:** 1-Module Render Contract
**Areas discussed:** Abstract enforcement, ModuleData shape, Shared RAG palette, Empty-data guard

---

## Abstract Enforcement

### Q1 — How strictly should the three new render hooks be enforced on BaseModule?

| Option | Description | Selected |
|--------|-------------|----------|
| No-op defaults | Concrete methods with safe defaults; mirrors today's `render_pdf_section` / `render_excel_tabs` pattern; existing 7 modules keep working untouched. | ✓ |
| Abstract everywhere | All three as `@abstractmethod`; every registered module must implement in Phase 1, including the 3 management_summary modules whose real migration is owned by v2. | |
| Abstract via opt-in `CONTRACT_VERSION` flag | Per-class flag that toggles abstract-vs-default; introduces a versioning concept that complicates the contract. | |

**User's choice:** No-op defaults.
**Notes:** Backward compat is non-negotiable for management_summary's three modules in v1; the no-op path lets Phase 1 ship without any module-file edits. Phase 3 overrides on the four board modules.

### Q2 — What should `render_rag_strip_entry` return when not overridden?

| Option | Description | Selected |
|--------|-------------|----------|
| Gray "No Data" cell | `{label, headline_value: "—", rag_color: "#757575", rag_label: "No Data"}`; missed override is visually obvious. | ✓ |
| Empty dict `{}` | Composer filters out empties; missed override is invisible (cell disappears). | |
| Raise `NotImplementedError` | Force un-migrated modules to crash; conflicts with no-op-defaults stance. | |

**User's choice:** Gray "No Data" cell.

### Q3 — What should `render_email_panel` return when not overridden?

| Option | Description | Selected |
|--------|-------------|----------|
| Empty string `""` | Composer concatenates non-empty fragments; un-migrated modules contribute nothing. | ✓ |
| Generic placeholder fragment | Visible "not yet migrated" stub; would be noise if ever rendered for management_summary. | |
| Headline-only fragment | Minimal HTML with name + dash; same noise problem; misleading "has data" impression. | |

**User's choice:** Empty string.

### Q4 — What should `render_analyst_tabs` return when not overridden?

| Option | Description | Selected |
|--------|-------------|----------|
| Empty list `[]` | Un-migrated modules absent from the analyst workbook. | ✓ |
| `[(DISPLAY_NAME, empty DataFrame)]` | Always one tab per module; empty tabs are user-visible noise. | |

**User's choice:** Empty list.

---

## ModuleData Shape

### Q1 — How should compute() carry the three new render-time payloads on ModuleData?

| Option | Description | Selected |
|--------|-------------|----------|
| Three discrete typed fields | `driver_narrative: str`, `analyst_rows: list[tuple[str, pd.DataFrame]]`, `rag_strip: dict`. | ✓ |
| Stuff into existing `metadata` / `chart_data` | Convention-only; untyped; easy to forget keys. | |
| Single `render_payload: dict` | One field, three required keys; same untyped failure mode nested deeper. | |
| Nested `RenderPayload` dataclass | Type-safe but adds a second dataclass; option 1 with three top-level fields is simpler and equivalent. | |

**User's choice:** Three discrete typed fields.

### Q2 — Should the three new ModuleData fields default to safe empty values, or be required?

| Option | Description | Selected |
|--------|-------------|----------|
| Default to safe empties | `""` / `[]` / `{}`; existing 7 modules' construction calls keep working unchanged. | ✓ |
| Required | No defaults; touch all 7 modules' compute() return statements in Phase 1; conflicts with no-op-defaults stance. | |

**User's choice:** Default to safe empties.

### Q3 — Where does the "what's driving it" email-panel narrative get produced?

| Option | Description | Selected |
|--------|-------------|----------|
| Inside `compute()`, stored on `driver_narrative` | Module produces the line with full DataFrame access; renderer reads it. Matches existing `summary_text` pattern. | ✓ |
| Inside `render_email_panel()` from existing fields | No new field; renderer composes from `metrics` + `chart_data`; ties renderers to chart_data internal shape. | |
| A second abstract method `compute_driver_narrative()` | Explicit contract for the driver line; over-structured for a single string. | |

**User's choice:** Inside compute().

### Q4 — What's the headline_value type inside the rag_strip dict?

| Option | Description | Selected |
|--------|-------------|----------|
| Pre-formatted string | Module owns its display logic ("87.4%", "12 assets", "—"). | ✓ |
| Raw number + unit | Composer handles formatting consistency; doesn't fit modules whose headline isn't value+unit. | |
| Both — raw + display | Maximum flexibility; redundant for v1; over-engineering. | |

**User's choice:** Pre-formatted string.

---

## Shared RAG Palette

### Q1 — Where do RAG colors and status labels live?

| Option | Description | Selected |
|--------|-------------|----------|
| Shared `rag_utils.py`, opt-in adoption | Phase 1 creates the helper; existing 7 modules keep their copies; Phase 3 migrates the 4 board modules; v2 migrates management. | ✓ |
| Shared `rag_utils.py`, refactor all 7 modules in Phase 1 | Centralize and migrate immediately; scope balloons to 7 module files in a phase that's supposed to define a contract. | |
| Leave per-module, standardize dict keys only | No shared module; drift inevitable across modules' palettes. | |

**User's choice:** Shared rag_utils.py, opt-in adoption.

### Q2 — Where should the shared RAG constants/helpers actually live?

| Option | Description | Selected |
|--------|-------------|----------|
| New `reports/modules/rag_utils.py` | Neutrally-named; v2 management_summary migration won't drag in "board" semantics. | ✓ |
| Extend `reports/modules/board_report_utils.py` | Zero new files; same module already houses `sla_status_from_thresholds()`; "board" prefix becomes confusing in v2. | |
| Add to `reports/modules/base.py` as module-level constants | Co-locate with BaseModule; bloats base.py; couples palette to ABC. | |

**User's choice:** New rag_utils.py.

### Q3 — What goes into the new rag_utils.py in Phase 1?

| Option | Description | Selected |
|--------|-------------|----------|
| `STATUS_COLOR` + `STATUS_LABEL` constants | Four-state palette with hex colors and human-readable labels. | ✓ |
| `rag_status_from_value()` helper | Wrapper around existing `sla_status_from_thresholds()` so modules don't import from a board-prefixed file. | ✓ |
| `build_rag_strip_entry()` helper | Convenience constructor for the rag_strip dict; saves Phase 3 modules from hand-building it. | ✓ |
| Empty-data sentinels (`NO_DATA_HEADLINE`, `NO_DATA_DRIVER`) | Guarantee the gray-cell case is identical wherever it appears. | ✓ |

**User's choice:** All four (multi-select).

---

## Empty-Data Guard

### Q1 — How is the empty-data guard pattern enforced across render methods?

| Option | Description | Selected |
|--------|-------------|----------|
| Shared helpers + documented convention | `safe_pct` / `safe_int` / `safe_format` helpers; CLAUDE.md requires their use; QUALITY-01 + QUALITY-03 audit applies them. | ✓ |
| Doc convention only — inline guards everywhere | No helper; each render method writes its own inline `val if val is not None else dash` guard; drift inevitable. | |
| Decorator wrapping render methods | `@guard_renders` catches errors; silently swallows real bugs; doesn't help inside compute(). | |
| Pydantic-style validation on ModuleData | New dependency; conflicts with PROJECT.md "no new SDKs in v1". | |

**User's choice:** Shared helpers + documented convention.

### Q2 — Where do safe_pct / safe_int / safe_format helpers live?

| Option | Description | Selected |
|--------|-------------|----------|
| New `reports/modules/format_utils.py` | Sibling to rag_utils.py; clean separation between RAG concerns and value-formatting concerns. | ✓ |
| Inside `rag_utils.py` | One new file instead of two; rag_utils name implies RAG concerns; safe_pct isn't RAG. | |
| Extend `utils/formatters.py` | Zero new files; couples module contract to a top-level utility. | |

**User's choice:** New format_utils.py.

### Q3 — How exhaustive is the QUALITY-03 grep audit?

| Option | Description | Selected |
|--------|-------------|----------|
| Audit all f-string format specs across `reports/` (top-level + modules) | Closes the bug class once; largest blast radius for a single phase. | ✓ |
| Audit only `management_summary.py` + `ops_remediation.py` | Bounded scope; survivors elsewhere remain incident-prone. | |
| Audit only the explicit `cov_pct` site (QUALITY-01) | Smallest diff; conflicts with REQUIREMENTS.md QUALITY-03 wording. | |

**User's choice:** Full audit across reports/.

---

## Claude's Discretion

- Exact PEP-8 / docstring formatting for `BaseModule` updates and the new helper modules — match existing style in `reports/modules/base.py`.
- Whether `rag_utils.py` exports an additional `STATUS_FILL_COLOR` palette for openpyxl PatternFill — add only if needed by Phase 3 adoption.
- Whether `format_utils.py` adds a `safe_count(val, suffix="")` helper — propose during planning; small surface area either way.
- Whether the CLAUDE.md update lives in the existing "Adding a New Report — Required Steps" section or a new sibling "Adding a new module" section — both work; new sibling preferred.
- Whether `reports/modules/example_module.py` is updated to demonstrate the new render methods — not blocking; planner's call.

## Deferred Ideas

- **Phase 4 runtime check for missing render-method overrides** — revisit alongside CONFIG-02 jsonschema validation in Phase 4.
- **Migrate management_summary modules to rag_utils.py** — explicitly v2 (GEN-01).
- **Migrate ops_remediation to the module contract** — v2 (GEN-02).
- **YAML-driven module composition (modules: [...] in delivery_config.yaml)** — v2 (GEN-03 / GEN-04).
- **`STATUS_FILL_COLOR` openpyxl palette in rag_utils.py** — only if Phase 3 needs it.
- **`safe_count(val, suffix=)` formatter** — small surface area; planner's call.
- **`utils/formatters.py` ↔ `reports/modules/format_utils.py` convergence** — out of scope for v1; revisit during v2 framework polish.
- **Updating `reports/modules/example_module.py`** — Claude's discretion at planning time.
