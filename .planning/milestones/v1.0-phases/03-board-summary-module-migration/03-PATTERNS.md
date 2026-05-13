# Phase 3: Board Summary Module Migration — Pattern Map

**Mapped:** 2026-05-06
**Files analyzed:** 12 surfaces across 6 plans (03-01..03-06)
**Analogs found:** 12 / 12 (every file has a strong in-repo analog)

---

## Open Questions Resolved

### Q1 — Does `rag_status_from_value()` already accept a `direction` argument?

**YES — already present.** Phase 3 plan 03-01 does NOT need to add it. Cite:

```python
# reports/modules/rag_utils.py:82-117
def rag_status_from_value(
    value:            Optional[float],
    green_threshold:  float,
    yellow_threshold: float,
    direction:        str = "higher_is_better",   # <-- default already locked
) -> str:
    ...
    return sla_status_from_thresholds(
        value=value,
        green_threshold=green_threshold,
        yellow_threshold=yellow_threshold,
        direction=direction,
    )
```

The wrapper forwards the parameter to `sla_status_from_thresholds` at `reports/modules/board_report_utils.py:477-531`, which also already supports both `"higher_is_better"` and `"lower_is_better"`. **The risk-row in `03-CONTEXT.md` ("Plan 03-01 adds the direction parameter") is moot — it already exists.** Plan 03-01 should instead document the existing signature in the helper plan and use it directly.

### Q2 — Are `assemble_pdf()` callers limited to the composer's own `run_full_pipeline`?

**Confirmed (with one caveat).** Cite:

| Caller | Location | Notes |
|--------|----------|-------|
| `ReportComposer.run_full_pipeline` | `reports/modules/composer.py:1468` | Production call — bundle orchestrator |
| `scripts/smoke_email_phase2.py` | `scripts/smoke_email_phase2.py:130` | Off-network smoke test (Phase 2 UAT) — needs adjustment if `assemble_pdf` signature changes |
| `reports/board_summary.py:368` | docstring reference only (`_render_pdf` docstring), not a real call | No code change needed |

**`management_summary.py` is NOT a caller** — it has its own bespoke `_build_pdf()` at `reports/management_summary.py:1205` and its own `build_email_body()` at line 1934, called from `run_report()` at lines 2399 and 2405. Decision: per `03-CONTEXT.md` D-01, the unified RAG-strip cover becomes the only mode in `assemble_pdf()`; `management_summary` is unaffected because it never goes through `assemble_pdf`.

**Caveat for plan 03-01:** the smoke script (`scripts/smoke_email_phase2.py:130`) calls `composer.assemble_pdf(...)` directly. Plan 03-01 should either (a) leave its signature backward compatible (no new args) and just rework the cover/strip composition internally, OR (b) update the smoke script alongside the composer change. Either is fine; the planner picks.

### Q3 — Existing per-module gauge PNG generation pattern (for plan 03-01 D-04 wiring)

All four board modules currently call `chart_utils.draw_gauge()` **inside `render_pdf_section()`** and embed the returned base64 PNG via `data:image/png;base64,{b64}` URI directly into the HTML fragment. **No file is ever written to disk.** Citations:

| Module | Call site | Embed shape |
|--------|-----------|-------------|
| `scan_coverage_sla_module.py:326-340` | `gauge_b64 = draw_gauge(...)` | `<img src="data:image/png;base64,{gauge_b64}" style="width:46%; max-width:320px;">` |
| `critical_remediation_sla_module.py:345-360` | same | same shape, title `"Critical Remediation SLA %"` |
| `high_risk_assets_module.py:323-338` | same | same shape, title `"High-Risk Assets %"` |
| `aged_vulns_assets_module.py:317-332` | same | same shape, title `"Aged Vuln Assets %"` |

**Implication for D-04 wiring (CID gauges in email panels):** the existing PDF gauge path is base64-inline (no PNG file). For the email panel CID requirement (D-04: Outlook desktop strips base64 data URIs), each module's `render_email_panel` must EITHER (i) write the gauge PNG to disk and emit a `{"cid": ..., "path": ...}` entry into the bundle, OR (ii) the composer holds the base64 in memory and `email_sender.py` decodes it into a `MIMEImage` (mirroring the existing `prebuilt_charts` path at `delivery/email_sender.py:401-468`).

**Recommended approach (per CONTEXT D-04 + bundle key `email_inline_images: list[dict]`):** Each module's `render_email_panel` calls `draw_gauge()` AND writes the result to a sibling location alongside `output_dir` (e.g. `output_dir/_email_gauges/{module_id}_gauge.png`), returning panel HTML that references `cid:{module_id}_gauge`. The composer collects entries into `bundle["email_inline_images"]` during `assemble_email_body`. Mirror the existing `_attach_inline_chart` pattern at `delivery/email_sender.py:215-229`.

Alternative (smaller surface, recommended on second look): keep `draw_gauge()` returning base64 inside `render_email_panel`, have the composer decode the base64 into a `MIMEImage` exactly like the `prebuilt_charts` path already does at `delivery/email_sender.py:460-473`. Plan 03-01 picks; the existing `prebuilt_charts` path is a near-exact analog.

---

## File Classification

| Surface (new or modified) | Plan | Role | Data Flow | Closest Analog | Match Quality |
|---------------------------|------|------|-----------|----------------|---------------|
| `reports/modules/board_report_utils.py:populate_rag_strip` (new helper) | 03-01 | utility | transform | `board_report_utils.compute_per_bu_breakdown` (`board_report_utils.py:286`) | exact (sibling helper, same module) |
| `reports/modules/composer.py:assemble_pdf` (cover rework — D-01) | 03-01 | composer | request-response | Phase 2 `_build_rag_strip_page` (`composer.py:702-829`) + `_PDF_COVER_TEMPLATE` (`composer.py:356-366`) | exact (collapsing two existing templates into one) |
| `reports/modules/composer.py:run_full_pipeline` (add `email_inline_images` bundle key) | 03-01 | composer | request-response | Existing bundle assembly at `composer.py:1457-1509` | exact |
| `reports/modules/composer.py:assemble_email_body` (collect inline-image entries) | 03-01 | composer | transform | Existing assemble_email_body iteration at `composer.py:1216-1258` | exact |
| `delivery/email_sender.py:send_report_email` (bundle-driven body selector — D-18) | 03-01 | service | event-driven | Existing `prebuilt_html` selector at `delivery/email_sender.py:400-436` | exact (same shape, slug-agnostic instead of metrics-key based) |
| `delivery/email_sender.py:_attach_analyst_excel` (bundle-driven attachment — D-19) | 03-01 | service | transform | Existing `_attach_file` loop at `delivery/email_sender.py:487-503` | exact |
| `delivery/email_sender.py` (CID inline gauge images — D-04) | 03-01 | service | transform | Existing `prebuilt_charts` decode loop at `delivery/email_sender.py:460-473` | exact |
| `reports/modules/scan_coverage_sla_module.py` (full migration) | 03-02 | metric module | CRUD/transform | itself (extending `compute()` + 3 new render methods + Excel zero-row pattern) | self-analog (extension only) |
| `reports/modules/critical_remediation_sla_module.py` (full migration) | 03-03 | metric module | CRUD/transform | sibling Plan 03-02 (post-migration) | exact |
| `reports/modules/high_risk_assets_module.py` (full migration) | 03-04 | metric module | CRUD/transform | sibling Plan 03-02 (post-migration) — `lower_is_better` direction | role-match |
| `reports/modules/aged_vulns_assets_module.py` (full migration) | 03-05 | metric module | CRUD/transform | sibling Plan 03-04 (post-migration) — `lower_is_better` direction | exact |
| `tests/test_phase2_composer_pipeline.py` (regression extension) | 03-06 | test | request-response | itself (extension only — same test file) | self-analog |

---

## Pattern Assignments

### `populate_rag_strip()` — new helper in `reports/modules/board_report_utils.py` (Plan 03-01)

**Role:** utility (pure helper)
**Data flow:** transform — takes `ModuleData` + thresholds, mutates `data.rag_strip`
**Analog:** `board_report_utils.sla_status_from_thresholds` (`board_report_utils.py:477-531`) for the classifier path; `rag_utils.build_rag_strip_entry` (`rag_utils.py:124-163`) for the cell-dict construction

**Existing module-level constants pattern** (lines 42-50):
```python
#: Tenable tag category that identifies the business unit.
BU_TAG_CATEGORY: str = "Application"

#: Default scan-recency window in days for the on-time filter.
ON_TIME_WINDOW_DAYS: int = 30
```

**Existing pure-helper docstring + signature pattern** (lines 477-531):
```python
def sla_status_from_thresholds(
    value:            Optional[float],
    green_threshold:  float,
    yellow_threshold: float,
    direction:        str = "higher_is_better",
) -> str:
    """
    Classify a metric value as green / yellow / red / no_data.

    Parameters
    ----------
    value : float or None
        The metric value to classify.  ``None`` → ``"no_data"``.
    ...
    """
    if value is None:
        return "no_data"

    if direction == "higher_is_better":
        if value >= green_threshold:
            return "green"
        ...
```

**Reference signature for new helper** (synthesizing from D-05 + analog):
```python
from reports.modules.rag_utils import build_rag_strip_entry, rag_status_from_value
from reports.modules.format_utils import safe_pct

def populate_rag_strip(
    data:              ModuleData,
    *,
    display_name:      str,
    metric_value:      Optional[float],
    threshold_green:   float,
    threshold_yellow:  float,
    direction:         str = "higher_is_better",
) -> None:
    """
    Populate ``data.rag_strip`` in place with a pre-built cell dict.

    Headline value is `safe_pct(metric_value)`. Status is computed via
    `rag_status_from_value(metric_value, threshold_green, threshold_yellow,
    direction=direction)`. None / NaN metric_value → no_data gray cell.
    """
    status = rag_status_from_value(
        metric_value,
        green_threshold=threshold_green,
        yellow_threshold=threshold_yellow,
        direction=direction,
    )
    data.rag_strip = build_rag_strip_entry(
        display_name=display_name,
        headline_value_str=safe_pct(metric_value),
        status=status,
    )
```

---

### `assemble_pdf()` cover rework — `reports/modules/composer.py` (Plan 03-01)

**Role:** composer (HTML assembly)
**Data flow:** request-response (HTML in, PDF-ready HTML out)
**Analog:** existing `assemble_pdf()` at `composer.py:573-696` AND existing `_build_rag_strip_page` at `composer.py:702-829` — D-01 collapses these into a unified cover

**Existing cover template** (`composer.py:356-366`):
```python
_PDF_COVER_TEMPLATE = """
<div class="report-cover">
  <p class="cover-title">{title}</p>
  <p class="cover-subtitle">{subtitle}</p>
  <hr class="cover-divider">
  <div class="cover-meta">
    <p style="margin:0 0 2mm 0;">Generated: {generated_at}</p>
    <p style="margin:0;">Sections: {module_list}</p>
  </div>
</div>
"""
```

**Existing RAG strip template** (`composer.py:368-375`):
```python
_PDF_RAG_STRIP_TEMPLATE = """
<div class="rag-strip">
  <h2 class="rag-strip-header">{header}</h2>
  <div class="rag-cell-row">
{cells_html}
  </div>
</div>
"""
```

**Existing assembly seam** (`composer.py:678-696`):
```python
cover = _PDF_COVER_TEMPLATE.format(
    title        = title,
    subtitle     = subtitle,
    generated_at = generated_at_str,
    module_list  = module_list_str,
)

body = "\n".join(sections) if sections else (...)

rag_strip_page = self._build_rag_strip_page(results)

return "\n".join([
    _PDF_DOCTYPE,
    "<html>",
    "<head>",
    ...,
    "</head>",
    "<body>",
    cover,
    rag_strip_page,    # NEW — Phase 2 D-02
    body,
    "</body>",
    "</html>",
])
```

**Phase 3 D-01 implementation pattern (recommendation):** delete `_PDF_COVER_TEMPLATE` and rework `_PDF_RAG_STRIP_TEMPLATE` to include a header band (title + scope/subtitle + generated_at + sections list) above the cells row. The page-1 cover invariant from Phase 2 D-01 is **explicitly superseded** for board_summary by Phase 3 D-01. Page 1 IS the RAG strip.

**Existing per-module exception-isolation pattern to mirror** (`composer.py:624-644`):
```python
try:
    config   = self._config_for(data.module_id)
    instance = mod_class()
    html_section = instance.render_pdf_section(data, config)
except Exception as exc:  # noqa: BLE001
    logger.error(
        "ReportComposer.assemble_pdf [%s]: render_pdf_section() raised: %s\n%s",
        data.module_id, exc, traceback.format_exc(),
    )
    safe_name = html.escape(str(data.display_name), quote=True)
    safe_exc  = html.escape(str(exc),               quote=True)
    html_section = (
        f'<div class="error-box">'
        f'<strong>{safe_name}</strong>: '
        f'PDF render failed — {safe_exc}'
        f'</div>'
    )
```

---

### `email_inline_images` bundle key — `reports/modules/composer.py` (Plan 03-01)

**Role:** composer (bundle assembly)
**Data flow:** transform — collect per-module gauge images into a list
**Analog:** existing bundle keys `analyst_workbook_path` (`composer.py:1489-1495`) and `email_body_html` (`composer.py:1498`)

**Existing bundle dict shape** (`composer.py:1457-1465`):
```python
bundle: dict[str, Any] = {
    "pdf_html":              "",
    "excel_workbook":        None,
    "analyst_workbook_path": None,
    "email_body_html":       "",
    "email_kpis":            {},
    "metrics":               {},
    "errors":                [],
}
```

**Existing analyst-workbook collection-then-set pattern** (`composer.py:996-1115`) — iterate modules, collect tuples, write file, return path. Mirror this for `email_inline_images`:

**Reference shape for D-04 entry:**
```python
{"cid": "scan_coverage_sla_gauge", "path": Path("output/.../email_gauges/scan_coverage_sla_gauge.png")}
```

**Pattern note:** `cid` stays slug-agnostic per D-20 (no slug allowlist inside composer); the cid string can be derived from `data.module_id` directly.

---

### `delivery/email_sender.py:send_report_email` bundle-driven body selector — Plan 03-01

**Role:** service (email send)
**Data flow:** event-driven (bundle in → email out)
**Analog:** existing `prebuilt_html` selector at `email_sender.py:400-436`

**Existing pattern to copy** (`email_sender.py:400-436`):
```python
prebuilt_html:    str | None       = None
prebuilt_charts:  dict[str, str]   = {}  # {cid_name: base64_str}

for _slug, _output in report_outputs.items():
    if not isinstance(_output, dict):
        continue
    _m = _output.get("metrics") or {}
    if isinstance(_m, dict) and _m.get("email_html"):
        prebuilt_html   = _m["email_html"]
        prebuilt_charts = _m.get("inline_charts") or {}
        logger.debug(
            "[%s] Using pre-built email body from report '%s'.",
            group_name, _slug,
        )
        break  # first pre-built body wins; only one expected per group

try:
    if prebuilt_html is not None:
        reply_to_addr = (group_config.get("email") or {}).get("reply_to", "")
        html_body = prebuilt_html.replace("{reply_to}", reply_to_addr)
    else:
        html_body = build_email_body(
            group_config=group_config,
            report_outputs=report_outputs,
            excel_omitted=excel_omitted,
        )
```

**Phase 3 D-18 reference shape** (verbatim from CONTEXT lines 117-132):
```python
modular_panels = next(
    (
        outputs.get("email_body_html", "")
        for outputs in report_outputs.values()
        if isinstance(outputs.get("email_body_html"), str)
        and outputs["email_body_html"].strip()
    ),
    "",
)
if modular_panels:
    html_body = build_email_body_modular(
        group_config, report_outputs,
        module_panels_html=modular_panels,
        excel_omitted=excel_omitted,
    )
else:
    html_body = build_email_body(group_config, report_outputs, excel_omitted=excel_omitted)
```

**Existing CID-attachment pattern to mirror for D-04** (`email_sender.py:460-473`):
```python
import base64 as _base64
for cid_name, b64_str in prebuilt_charts.items():
    try:
        img_data = _base64.b64decode(b64_str)
        img = MIMEImage(img_data, _subtype="png")
        img.add_header("Content-ID", f"<{cid_name}>")
        img.add_header("Content-Disposition", "inline", filename=f"{cid_name}.png")
        related.attach(img)
        logger.debug("[%s] Embedded pre-built inline chart: %s", group_name, cid_name)
    except Exception as exc:
        logger.warning(
            "[%s] Failed to embed pre-built chart '%s': %s",
            group_name, cid_name, exc,
        )
```

**Existing path-based CID variant (alternative for file-on-disk gauges)** (`email_sender.py:215-229`):
```python
def _attach_inline_chart(msg: MIMEMultipart, path: Path, cid_index: int) -> None:
    with open(path, "rb") as fh:
        img_data = fh.read()
    img = MIMEImage(img_data, _subtype="png")
    img.add_header("Content-ID", f"<chart_{cid_index}>")
    img.add_header("Content-Disposition", "inline", filename=path.name)
    msg.attach(img)
    logger.debug("Embedded chart_%d: %s", cid_index, path.name)
```

**Phase 3 D-19 analyst attachment pattern** — extend `_collect_attachments` at `email_sender.py:121-147`:
```python
def _collect_attachments(report_outputs: dict) -> tuple[list[Path], list[Path], list[Path]]:
    pdfs:   list[Path] = []
    excels: list[Path] = []
    csvs:   list[Path] = []

    for slug, output in report_outputs.items():
        if not isinstance(output, dict):
            continue
        pdf  = output.get("pdf")
        xlsx = output.get("excel")
        csv  = output.get("csv")
        if pdf and Path(pdf).exists():
            pdfs.append(Path(pdf))
        if xlsx and Path(xlsx).exists():
            excels.append(Path(xlsx))
        if csv and Path(csv).exists():
            csvs.append(Path(csv))

    return pdfs, excels, csvs
```

**Phase 3 extension** (per D-19 — bundle-driven, no slug allowlist):
```python
# Add to _collect_attachments; analyst_excel is a Path|None per board_summary.py:300
analyst_excel = output.get("analyst_excel")
if analyst_excel and Path(analyst_excel).exists():
    excels.append(Path(analyst_excel))
```

---

### Module migration pattern — applies identically to plans 03-02..03-05

Each plan migrates ONE board module end-to-end. Below are the shared excerpts; per-plan deltas (direction, narrative template, analyst columns) appear in each module's "Module-Specific" subsection.

**Existing `compute()` return shape pattern** (`scan_coverage_sla_module.py:244-279`):
```python
return ModuleData(
    module_id    = self.MODULE_ID,
    display_name = self.DISPLAY_NAME,
    metrics      = {
        "scan_coverage_pct":   scan_coverage_pct,
        "scanned_on_time":     scanned_on_time,
        "not_scanned_on_time": not_scanned_on_time,
        "total_licensed":      total_licensed,
        "unlicensed_excluded": unlicensed_count,
        "status":              status,
    },
    table_data   = table_data,
    chart_data   = {...},
    summary_text = summary_text,
    metadata     = {...},
    error        = None,
)
```

**Phase 3 extension — populate the three new ModuleData fields inside `compute()` BEFORE the `return ModuleData(...)`**:
```python
from reports.modules.board_report_utils import populate_rag_strip
from reports.modules.rag_utils import NO_DATA_DRIVER

# rag_strip — populate via shared helper (D-05)
populate_rag_strip(
    data,                                       # actually populated later — see note
    display_name      = self.DISPLAY_NAME,
    metric_value      = scan_coverage_pct,
    threshold_green   = _GREEN_THRESHOLD,
    threshold_yellow  = _YELLOW_THRESHOLD,
    direction         = _DIRECTION,
)
```

**Note for executor:** `populate_rag_strip` mutates `data.rag_strip`, so it has to be called AFTER the ModuleData is constructed. Two acceptable shapes: (1) construct ModuleData first, mutate, return; or (2) compute the cell dict before constructing and pass `rag_strip=...` directly. Plan 03-01 picks one and the four module plans copy it. Recommendation: option 2 — pure construction, no post-construction mutation, matches the "pure compute, deferred render" anti-pattern check.

**Driver narrative — hand-coded per D-06** (per-module templates from `03-CONTEXT.md` lines 71-74):

| Module | Narrative shape (illustrative — planner refines exact text) |
|--------|-------------------------------------------------------------|
| `scan_coverage_sla` | `f"{good_bu_name} at {good_bu_pct}; {worst_bu_name} dragging the average down ({overdue_count} of {total_count} licensed assets overdue)."` |
| `critical_remediation_sla` | `f"{fixed_in_window} of {opened_in_window} fixed within {_CRITICAL_SLA_DAYS}-day window; {overdue_count} critical findings still open past SLA."` |
| `high_risk_assets` | `f"{count} assets crossed the high-risk threshold (≥{_HIGH_RISK_COUNT} Crit/High open >{_AGED_DAYS_THRESHOLD}d); worst contributor: {worst_bu} with {worst_bu_count} assets."` |
| `aged_vulns_assets` | `f"{count} assets carry at least one Med+ vuln open >{_AGED_DAYS_THRESHOLD} days; oldest finding: {oldest_age} days; worst BU: {worst_bu}."` |

**Empty-data driver fallback (D-07):** when zero in-scope rows, set `data.driver_narrative = NO_DATA_DRIVER` (`reports/modules/rag_utils.py:75`).

**Existing summary_text builder pattern to copy** (`critical_remediation_sla_module.py:749-775`):
```python
def _build_summary(
    sla_pct:             float | None,
    total_fixed:         int,
    fixed_within_sla:    int,
    total_open:          int,
    status:              str,
) -> str:
    """Build a plain-language narrative sentence for the email body."""
    if sla_pct is None:
        if total_open == 0:
            return (
                "No Critical vulnerabilities were found on on-time-scanned assets — "
                "remediation SLA compliance cannot be computed."
            )
        ...
```

**Phase 3 add `_build_driver_narrative` sibling helper per module** (different angle per D-06).

**`render_email_panel` reference shape (D-02 horizontal split):**
```python
def render_email_panel(self, data: ModuleData, config: ModuleConfig) -> str:
    if data.error or not data.metrics:
        # D-15 empty-row placeholder — no gauge PNG; gray "No Data" band
        return _build_empty_panel(self.DISPLAY_NAME)

    pct = data.metrics.get("scan_coverage_pct")  # per-module key
    headline = safe_pct(pct)
    status = rag_status_from_value(pct, _GREEN_THRESHOLD, _YELLOW_THRESHOLD, _DIRECTION)
    rag_color = STATUS_COLOR[status]
    rag_label = STATUS_LABEL[status]
    icon = STATUS_ICON[status]

    gauge_b64 = draw_gauge(
        value=pct if pct is not None else 0.0,
        thresholds=_GAUGE_THRESHOLDS,
        title=self.DISPLAY_NAME,
        unit="%",
        figsize=(2.4, 1.6),
    )
    cid = f"{self.MODULE_ID}_gauge"

    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'style="width:620px; max-width:620px; margin:8px 0; border:1px solid #e0e0e0; '
        f'border-collapse:separate; background:#ffffff;">'
        f'<tr>'
        f'  <td width="150" style="padding:12px; vertical-align:middle; text-align:center;">'
        f'    <img src="cid:{cid}" alt="" width="120" height="120" '
        f'         style="display:block; margin:0 auto;" />'
        f'  </td>'
        f'  <td width="430" style="padding:12px; vertical-align:middle;">'
        f'    <div style="font-size:11pt; color:#666;">{html.escape(self.DISPLAY_NAME)}</div>'
        f'    <div style="font-size:24pt; font-weight:bold; color:#1a1a1a;">{headline}</div>'
        f'    <div style="font-size:10pt; color:{rag_color}; font-weight:bold;">{icon} {rag_label}</div>'
        f'    <div style="font-size:10pt; color:#444; margin-top:6px;">{html.escape(data.driver_narrative)}</div>'
        f'  </td>'
        f'</tr>'
        f'</table>'
    )
```

**`render_analyst_tabs` reference shape (D-14 single-tab list):**
```python
def render_analyst_tabs(
    self,
    data:   ModuleData,
    config: ModuleConfig,
) -> list[tuple[str, pd.DataFrame]]:
    """Return the module's pre-built analyst rows."""
    if data.error or not data.analyst_rows:
        return []
    return data.analyst_rows
```

**`render_rag_strip_entry` — already concrete in BaseModule** (`base.py:404-459`). Subclass override is needed ONLY when the module wants to bypass the default (which already honors `data.rag_strip` when populated). Plan 03-02..05 can either (a) override explicitly with the same logic for clarity, or (b) rely on the populated `data.rag_strip` and skip the override. Recommendation: skip the override (keep it inherited) so authors don't duplicate the dict-shape-check logic.

**`render_excel_tabs` zero-row standardisation (D-16) reference pattern:**
```python
# At the top of render_excel_tabs, AFTER creating the worksheet:
if data.error:
    ws["A1"] = "Error"
    ws["B1"] = data.error
    return [tab_name]

# NEW per D-16 — uniform empty representation
if not data.table_data and not data.metrics:
    ws["A1"] = "No data in scope"
    return [tab_name]
```

**Existing `_xl_kv` / `_xl_title` helper pattern** that all four modules already share — `scan_coverage_sla_module.py:672-692`, `critical_remediation_sla_module.py:800-812`, etc. No change needed, just preserve.

---

### Module-Specific Deltas (Plans 03-02..03-05)

#### Plan 03-02 — `scan_coverage_sla_module.py` (higher_is_better)

**Direction:** `_DIRECTION = "higher_is_better"` (`scan_coverage_sla_module.py:51`)
**Thresholds:** `_GREEN_THRESHOLD = 95.0`, `_YELLOW_THRESHOLD = 90.0`
**Headline metric:** `data.metrics["scan_coverage_pct"]`
**Analyst tab:** asset-level (D-10/D-13 — apply `deduplicate_assets_by_name`)
**Sheet name:** `"Scan Coverage Detail"` (≤31 chars)
**Columns (per D-10):** `hostname, ipv4, fqdn, last_licensed_scan_date, days_since_licensed_scan, business_unit (Application BU)`
**Sort:** `days_since_licensed_scan` desc (D-11)
**Source data:** the not-on-time licensed slice from existing `compute()` step 2 (`scan_coverage_sla_module.py:178-187`) — `not_on_time = licensed[~on_time_flag]`. This DataFrame is already deduplicated and licensed-only.

**Existing analog for analyst rows:** `unscanned_assets.py` has near-identical data. Reuse the `deduplicate_assets_by_name` enrichment pattern from `scan_coverage_sla_module.py:154` and the BU enrichment pattern from line 211.

#### Plan 03-03 — `critical_remediation_sla_module.py` (higher_is_better)

**Direction:** `_DIRECTION = "higher_is_better"` (`critical_remediation_sla_module.py:68`)
**Thresholds:** `_GREEN_THRESHOLD = 95.0`, `_YELLOW_THRESHOLD = 85.0`
**Headline metric:** `data.metrics["remediation_sla_pct"]`
**Analyst tab:** finding-level (D-10) — **does NOT dedup** (D-13)
**Sheet name:** `"Critical Remediation Detail"` (≤31 chars; truncate if needed)
**Columns (per D-10):** `asset (hostname), plugin (plugin_name + plugin_id), days overdue (max(0, days_to_fix - 15)), first_found, owner_tag (parsed from tags), remediation due_date (first_found + 15d)`
**Sort:** `days overdue` desc (D-11)
**Source data:** `fixed_in_window` from existing `compute()` step 4 + the `_compute_days_to_fix` helper (`critical_remediation_sla_module.py:682-708`). Critical SLA window = `_CRITICAL_SLA_DAYS = SLA_DAYS["critical"] = 15`.

**Critical caveat:** the `not within_sla_mask` rows are the analyst-relevant subset (the missed-SLA ones). Filter `fixed_in_window` to where `days_to_fix > _CRITICAL_SLA_DAYS`.

#### Plan 03-04 — `high_risk_assets_module.py` (lower_is_better)

**Direction:** `_DIRECTION = "lower_is_better"` (`high_risk_assets_module.py:53`) — **inverted thresholds**
**Thresholds:** `_GREEN_THRESHOLD = 0.5`, `_YELLOW_THRESHOLD = 1.0`
**Headline metric:** `data.metrics["high_risk_pct"]`
**Analyst tab:** asset-level (D-10/D-13 — apply dedup)
**Sheet name:** `"High-Risk Assets Detail"` (≤31 chars)
**Columns (per D-10):** `hostname, business_unit, crit_high_open_count (count of Crit/High open >30d), contributing_finding_ids (comma-joined plugin_ids)`
**Sort:** `crit_high_open_count` desc (D-11)
**Source data:** the `high_risk_uuids` set + `aged_counts_per_asset` Series from existing `_find_high_risk_assets` helper (`high_risk_assets_module.py:625-688`). The `aged_counts` Series gives the count column; the `relevant[aged_mask]` slice gives the contributing finding IDs (groupby asset_uuid, agg list).

**Joined-cell column type:** comma-joined string `"19506, 38234, 100123, ..."`. Use `", ".join(map(str, sorted(unique_ids)))` for determinism.

#### Plan 03-05 — `aged_vulns_assets_module.py` (lower_is_better)

**Direction:** `_DIRECTION = "lower_is_better"` (`aged_vulns_assets_module.py:52`)
**Thresholds:** `_GREEN_THRESHOLD = 2.0`, `_YELLOW_THRESHOLD = 5.0`
**Headline metric:** `data.metrics["aged_assets_pct"]`
**Analyst tab:** asset-level (D-10/D-13 — apply dedup) — **single tab with worst_severity column** (D-12)
**Sheet name:** `"Aged Vulns Detail"` (≤31 chars)
**Columns (per D-10):** `hostname, business_unit, oldest_finding_age_days, count_of_aged_findings, contributing_plugins (comma-joined plugin names), worst_severity`
**Sort:** `oldest_finding_age_days` desc (D-11)
**Source data:** the `aged_uuids` set from `_find_aged_assets` (`aged_vulns_assets_module.py:619-667`). To produce per-asset oldest_age + count + plugin list + worst_severity, repeat the filter inside `compute()` and `groupby("asset_uuid")` with multi-agg:
```python
agg_df = (
    aged_findings
    .groupby("asset_uuid")
    .agg(
        oldest_age_days = ("days_open", "max"),
        count_aged      = ("plugin_id", "count"),
        plugins         = ("plugin_name", lambda s: ", ".join(sorted(set(map(str, s))))),
        worst_severity  = ("severity", lambda s: _worst_sev(set(s))),
    )
    .reset_index()
)
```
where `_worst_sev` orders `critical > high > medium`.

**Joined-cell column type:** comma-joined string with deterministic sort (alphabetical) per D-12 caveat.

---

### Plan 03-06 — Regression test extension

**File:** `tests/test_phase2_composer_pipeline.py` (extend in place)
**Role:** test (regression)
**Data flow:** request-response (synthetic ModuleData → bundle assertions)
**Analog:** the existing test file (Phase 2 baseline)

**Existing test patterns to extend:**
- Synthetic ModuleData fixture pattern — extend with populated `rag_strip`, `driver_narrative`, `analyst_rows`
- Bundle key existence assertions — add `email_inline_images` key check
- All-empty / zero-row scenario — extend per QUALITY-02 to assert `render_email_panel` returns gray-no-data placeholder, `render_excel_tabs` emits "No data in scope" row, `render_rag_strip_entry` returns gray cell

**SUMMARY.md flag (per D-16 risk row):** plan 03-06 must explicitly call out the Excel zero-row diff vs pre-Phase-3 baseline.

**Phase 2 UAT smoke pattern to re-run** (per CONTEXT risks line 208): `scripts/smoke_email_phase2.py` with real `render_email_panel` output instead of stub panels.

---

## Shared Patterns

### Module-level constants block (every metric module)

**Source:** `scan_coverage_sla_module.py:46-80` (and identical shape in the other three)
**Apply to:** Plans 03-02..03-05 — re-use existing constants; add no new ones except potentially a private `_CRITICAL_SLA_DAYS` style constant if not already present.
```python
_GREEN_THRESHOLD  = 95.0
_YELLOW_THRESHOLD = 90.0
_DIRECTION        = "higher_is_better"

_GAUGE_THRESHOLDS = [
    (_YELLOW_THRESHOLD, "#d32f2f"),
    (_GREEN_THRESHOLD,  "#fbc02d"),
    (100.0,             "#388e3c"),
]
```

### Per-module exception isolation in `render_email_panel`

**Source:** `composer.py:1232-1251` (Phase 2 D-28 invariant)
**Apply to:** Plans 03-02..03-05 (do not regress this Phase 2 contract — return `""` or a contained placeholder, never raise out of `render_email_panel` / `render_analyst_tabs` / `render_rag_strip_entry`).
```python
try:
    config   = self._config_for(data.module_id)
    instance = mod_class()
    panel_html = instance.render_email_panel(data, config)
except Exception as exc:  # noqa: BLE001
    logger.error(...)
    panel_html = (
        '<div style="border:1px solid #d32f2f; background:#FFF3CD; ...">'
        f'<strong>{safe_name}</strong>: '
        f'email panel render failed — {safe_exc}'
        '</div>'
    )
```

### Empty-data guard pattern (CLAUDE.md "Empty-data guard pattern")

**Source:** `BaseModule._empty_result` at `base.py:558-599` + `format_utils.safe_pct` / `safe_int` / `safe_format`
**Apply to:** every render method in plans 03-02..03-05.
```python
from reports.modules import safe_pct, safe_int, safe_format
from reports.modules.rag_utils import (
    STATUS_COLOR, STATUS_LABEL, STATUS_ICON,
    NO_DATA_HEADLINE, NO_DATA_DRIVER,
    build_rag_strip_entry, rag_status_from_value,
)
```

### Numpydoc docstrings + section banners

**Source:** every module file already follows this — `scan_coverage_sla_module.py:113-142` for `compute()`, `scan_coverage_sla_module.py:292-309` for `render_pdf_section`, etc.
**Apply to:** every new render method in plans 03-02..03-05.

### `# noqa: PLC0415` for deferred imports

**Source:** `base.py:440-442`, `base.py:579-581`, `composer.py:726-728`, `composer.py:992`, `composer.py:1454-1455`, `board_summary.py:380`
**Apply to:** plan 03-01 if any new helper requires deferred imports (e.g. WeasyPrint, openpyxl).

### Inline-CSS only / no `<style>` blocks (CLAUDE.md "Email Template")

**Source:** `templates/report_email.html` and `delivery/email_template.py:425-530`
**Apply to:** plans 03-02..03-05 every `render_email_panel` HTML fragment. **No `<style>` blocks**, only `style="..."` attributes. Width attributes on `<td>` per the existing project convention (D-02).

### HTML-escape every module-supplied string before interpolation (WR-01)

**Source:** `composer.py:790-797`
**Apply to:** plan 03-01 cover rework AND plans 03-02..03-05 `render_email_panel` (display_name, driver_narrative, etc).
```python
import html
label          = html.escape(str(display_name),     quote=False)
driver         = html.escape(str(driver_narrative), quote=False)
```

---

## No Analog Found

None. Every Phase 3 surface has a strong in-repo analog — Phase 3 is dominated by extending existing patterns (pure-helper sibling, render-method overrides, bundle key addition, selector pattern reuse).

---

## Metadata

**Analog search scope:** `reports/modules/`, `reports/`, `delivery/`, `tests/`, `scripts/`, `templates/`
**Files scanned:** ~25 (includes the 4 board modules, composer, base, rag_utils, format_utils, board_report_utils, board_summary, email_sender, email_template, chart_utils, plus management_summary skim for non-caller confirmation)
**Pattern extraction date:** 2026-05-06
**Smoke-test caller note:** `scripts/smoke_email_phase2.py:130` calls `composer.assemble_pdf()` directly — plan 03-01 should keep the signature backward compatible OR update the smoke script in the same commit.
