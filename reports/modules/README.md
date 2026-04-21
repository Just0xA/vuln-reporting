# Report Module Library — Developer Guide

This guide is for engineers adding new metric modules to the vulnerability
management reporting suite. Read it before creating a module file.

---

## 1. Architecture Overview

The module system separates **metric computation** from **report assembly**.
Each module owns one slice of metric logic and knows how to render itself
in every output format. Report scripts compose modules rather than owning
metric logic directly.

```
delivery_config.yaml          run_all.py / report script
┌──────────────────┐          ┌──────────────────────────┐
│ reports:         │          │ ReportComposer(           │
│   - board_summary│  ──────► │   module_configs=[        │
│ modules:         │          │     ModuleConfig("sla"),  │
│   - sla_summary  │          │     ModuleConfig("risk"), │
│   - asset_risk   │          │   ]                       │
│ module_options:  │          │ )                         │
│   asset_risk:    │          │ results = composer        │
│     top_n: 25    │          │           .run_all()      │
└──────────────────┘          └──────────────────────────┘
                                         │
              ┌──────────────────────────┤
              ▼          ▼               ▼
        pdf_html    excel tabs       email kpis
```

**Why this exists:**

1. Different delivery groups want different metric combinations from the
   same base report — changing a group's modules requires a YAML edit, not
   a code change.
2. Board-level and executive reports evolve frequently. Modules let metrics
   be added, removed, or reordered without rewriting report scripts.
3. Each module is independently testable with a simple `python -c` call
   against synthetic DataFrames — no Tenable connection required.

---

## 2. Creating a New Module — Step by Step

### Step 1 — Create the file

Name the file with a `_module.py` or `_metrics.py` suffix so auto-discovery
picks it up:

```
reports/modules/sla_summary_module.py
reports/modules/patch_compliance_metrics.py
```

Files that do not match either pattern are ignored by the discovery system.

### Step 2 — Subclass and decorate

```python
# reports/modules/sla_summary_module.py

from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.registry import register_module
import pandas as pd
import logging

logger = logging.getLogger(__name__)

@register_module
class SLASummaryModule(BaseModule):
    MODULE_ID         = "sla_summary"
    DISPLAY_NAME      = "SLA Summary"
    DESCRIPTION       = "Open finding counts and SLA compliance rate by severity."
    REQUIRED_DATA     = ["vulns"]
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]
    VERSION           = "1.0.0"
```

### Step 3 — Implement `compute()`

```python
    def compute(self, vulns_df, assets_df, report_date, config, **kwargs):
        try:
            open_df  = vulns_df[vulns_df["state"].str.upper() == "OPEN"]
            n_crit   = int((open_df["severity"] == "critical").sum())
            n_high   = int((open_df["severity"] == "high").sum())
            overdue  = int(open_df.get("is_overdue", pd.Series(False)).sum())

            return ModuleData(
                module_id    = self.MODULE_ID,
                display_name = self.DISPLAY_NAME,
                metrics      = {
                    "Open Critical": n_crit,
                    "Open High":     n_high,
                    "Overdue":       overdue,
                },
                table_data   = [],
                chart_data   = {},
                summary_text = (
                    f"{n_crit} critical and {n_high} high findings open; "
                    f"{overdue} are overdue."
                ),
                metadata     = {
                    "computed_at":  str(report_date),
                    "total_rows":   len(vulns_df),
                    "open_rows":    len(open_df),
                },
                error        = None,
            )
        except Exception as exc:
            logger.error("%s compute() failed: %s", self._log_prefix(), exc, exc_info=True)
            return self._empty_result(str(exc), config)
```

### Step 4 — Implement the renderers

See sections 5 and 6 below for format-specific rules.

### Step 5 — Register in `run_all.py` if the module drives a new report slug

If the module is used inside an existing composed report, no changes to
`run_all.py` are needed. If it introduces a new top-level report slug,
follow the **Adding a New Report** steps in `CLAUDE.md`.

### Step 6 — Test in isolation

```bash
python -c "
import pandas as pd
from datetime import datetime, timezone
from reports.modules import registry, ReportComposer
from reports.modules.base import ModuleConfig

composer = ReportComposer(
    vulns_df    = pd.DataFrame({'state': ['open'], 'severity': ['critical'],
                                'is_overdue': [True]}),
    assets_df   = pd.DataFrame(),
    report_date = datetime.now(timezone.utc),
    module_configs = [ModuleConfig('sla_summary')],
)
results = composer.run_all()
print(results[0].metrics)
print(results[0].error)
"
```

---

## 3. ModuleConfig — Per-Group Options

`ModuleConfig` carries an `options` dict sourced from `module_options` in
`delivery_config.yaml`. Use it to make module behaviour configurable without
code changes.

**Declaring options** — document them in the class docstring and
`get_audit_info()`:

```python
@register_module
class AssetRiskModule(BaseModule):
    """
    Supported options
    -----------------
    top_n : int
        Number of highest-risk assets to include in the table.
        Default: 25.
    severity_filter : list[str]
        Severity tiers to include. Default: ["critical", "high"].
    """
    MODULE_ID = "asset_risk"
    ...

    def compute(self, vulns_df, assets_df, report_date, config, **kwargs):
        top_n            = config.options.get("top_n", 25)
        severity_filter  = config.options.get("severity_filter",
                                              ["critical", "high"])
        ...
```

**Validating options** — override `validate_config()` to catch bad values
before `compute()` runs:

```python
    def validate_config(self, config):
        errors = []
        top_n = config.options.get("top_n", 25)
        if not isinstance(top_n, int) or top_n < 1:
            errors.append("top_n must be a positive integer")
        return errors
```

**YAML usage:**

```yaml
modules:
  - asset_risk
module_options:
  asset_risk:
    top_n: 10
    severity_filter: [critical, high]
```

---

## 4. ModuleData Contract

Every field must be set on success. On failure, set `error` and leave the
data fields as empty defaults — callers check `error` first.

| Field          | Type          | Purpose                                              | Empty value  |
|----------------|---------------|------------------------------------------------------|--------------|
| `module_id`    | `str`         | Matches `ModuleConfig.module_id`                     | —            |
| `display_name` | `str`         | Used in headings, logs, error messages               | —            |
| `metrics`      | `dict`        | `{label: value}` for KPI tiles                       | `{}`         |
| `table_data`   | `list[dict]`  | Row dicts for PDF/Excel tables; keys = column names  | `[]`         |
| `chart_data`   | `dict`        | Raw data for chart rendering (structure is yours)    | `{}`         |
| `summary_text` | `str`         | Plain-language narrative for email and PDF           | `""`         |
| `metadata`     | `dict`        | Audit data: timestamps, row counts, filter params    | `{}`         |
| `error`        | `str \| None` | `None` on success; error message string on failure   | `None`       |

**What happens when `error` is set:**

- `render_pdf_section()` should return an error callout `<div>` with class
  `error-box`, not a normal section.
- `render_excel_tabs()` should write a single error tab, not raise.
- `render_email_kpis()` returns `{}` automatically (base class handles this).
- `ReportComposer` logs a warning and includes the result in the output
  list — downstream steps see the error but continue running.

---

## 5. Output Format Rules

### PDF

`render_pdf_section()` must return a **self-contained HTML fragment** — no
`<html>`, `<head>`, or `<body>` tags.

**Available CSS classes** (defined in `composer.py`'s `_PDF_CSS`):

| Class                 | Use for                                      |
|-----------------------|----------------------------------------------|
| `.module-section`     | Outer wrapper for the entire section         |
| `.section-heading`    | `<h2>` section title                         |
| `.subsection-heading` | `<h3>` sub-headings within a section         |
| `.explanatory-text`   | Narrative paragraph below headings           |
| `.error-box`          | Error callout (yellow border, orange stripe) |
| `.data-table`         | `<table>` for tabular data                   |
| `.kpi-row`            | Table-row wrapper for KPI tiles              |
| `.kpi-tile`           | Individual KPI tile cell                     |
| `.kpi-value`          | Large number inside a tile                   |
| `.kpi-label`          | Label below the number                       |
| `.page-break`         | Force a page break before a section          |

**Embedding charts** — convert matplotlib figures to base64 and use a data
URI. Do not write chart files to disk from inside a module:

```python
import io, base64, matplotlib.pyplot as plt

fig, ax = plt.subplots()
ax.bar(["Critical", "High"], [n_crit, n_high])
buf = io.BytesIO()
fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
plt.close(fig)
b64 = base64.b64encode(buf.getvalue()).decode()
img_tag = f'<img src="data:image/png;base64,{b64}" style="max-width:100%;">'
```

**Minimal valid section:**

```python
def render_pdf_section(self, data, config):
    if "pdf" not in self.SUPPORTED_OUTPUTS:
        return ""
    if data.error:
        return (f'<div class="error-box">'
                f'<strong>{self.DISPLAY_NAME}</strong>: {data.error}</div>')
    return f"""
<div class="module-section">
  <h2 class="section-heading">{data.display_name}</h2>
  <p class="explanatory-text">{data.summary_text}</p>
</div>"""
```

### Excel

`render_excel_tabs()` receives an **openpyxl `Workbook`** that the composer
owns. Add sheets to it; do not create a new workbook or call `save()`.

Use shared styling helpers from `exporters/excel_exporter.py` for consistent
column widths, header fills, and conditional formatting:

```python
from exporters.excel_exporter import (
    apply_header_style,
    apply_severity_fill,
    auto_fit_columns,
)

def render_excel_tabs(self, data, workbook, config):
    if "excel" not in self.SUPPORTED_OUTPUTS:
        return []
    ws = workbook.create_sheet("SLA Summary")
    # Write headers
    headers = ["Severity", "Open", "Overdue", "Compliance %"]
    for col, header in enumerate(headers, start=1):
        ws.cell(row=1, column=col, value=header)
    apply_header_style(ws, row=1)
    # Write rows from data.table_data
    for row_idx, row in enumerate(data.table_data, start=2):
        for col_idx, key in enumerate(headers, start=1):
            ws.cell(row=row_idx, column=col_idx, value=row.get(key, ""))
    auto_fit_columns(ws)
    return ["SLA Summary"]
```

Tab names are capped at **31 characters** by Excel. Keep names short or
truncate explicitly — the composer does not truncate automatically.

### Email

The default `render_email_kpis()` implementation returns all `data.metrics`
entries as strings. Override it when you need to:

- Select a subset of metrics for the email (not all metrics belong in
  the email KPI strip)
- Reformat values (e.g. add `%`, round floats, show units)

```python
def render_email_kpis(self, data, config):
    if "email" not in self.SUPPORTED_OUTPUTS or data.error:
        return {}
    return {
        "Open Critical": str(data.metrics.get("Open Critical", 0)),
        "Overdue":       str(data.metrics.get("Overdue", 0)),
        # deliberately omitting "Open High" — too granular for email
    }
```

---

## 6. Error Handling

**The contract: `compute()` must never raise.**

Wrap the entire body in `try/except Exception` and return via
`self._empty_result()` on failure:

```python
def compute(self, vulns_df, assets_df, report_date, config, **kwargs):
    try:
        # ... metric logic ...
        return ModuleData(...)
    except Exception as exc:
        logger.error("%s compute() failed: %s", self._log_prefix(), exc,
                     exc_info=True)
        return self._empty_result(str(exc), config)
```

`_empty_result()` is provided by `BaseModule` and returns a `ModuleData`
with all data fields empty and `error` set to the message string.

The renderers (`render_pdf_section`, `render_excel_tabs`) should also handle
`data.error` gracefully, but they may raise — the composer catches renderer
exceptions and writes an error placeholder.

**Log levels:**

| Situation                           | Level     |
|-------------------------------------|-----------|
| Computation steps / row counts      | `DEBUG`   |
| Missing optional columns, empty subsets, unexpected nulls | `WARNING` |
| Caught exceptions in `compute()`    | `ERROR`   |

---

## 7. Audit Documentation

Override `get_audit_info()` to document calculation formulas and data field
sources. This is written to the `_Metadata` Excel tab and used for runbook
generation.

```python
def get_audit_info(self):
    return {
        **super().get_audit_info(),   # module_id, display_name, version, etc.
        "calculations": {
            "Open Critical": (
                "Count of rows where severity == 'critical' and "
                "state in ('open', 'reopened'). "
                "Source: vulns_df after tag and severity filtering."
            ),
            "Overdue": (
                "Count of rows where is_overdue == True. "
                "is_overdue is set by utils.sla_calculator.apply_sla_to_df() "
                "using SLA_DAYS from config.py: "
                "Critical=15d, High=30d, Medium=90d, Low=180d."
            ),
        },
        "data_sources": [
            "vulns_df — fetch_all_vulnerabilities() + enrich_vulns_with_assets()",
        ],
        "known_limitations": [
            "Findings with no VPR score fall back to native Tenable severity.",
        ],
    }
```

The `super().get_audit_info()` call includes `module_id`, `display_name`,
`description`, `version`, `required_data`, and `supported_outputs` so you
only need to add the calculation-specific keys.

---

## 8. Registry and Auto-Discovery

The registry is a global singleton (`reports.modules.registry`) populated at
import time. Discovery runs once when the package is first imported.

**How discovery works:**

1. `reports/modules/__init__.py` imports and calls `registry.discover()`
2. `discover()` scans the `modules/` directory for files matching
   `*_module.py` or `*_metrics.py`
3. Each matching file is imported via `importlib.import_module()`
4. The `@register_module` decorator on the class calls `registry.register()`
   which stores the class under its `MODULE_ID`

**File naming rules:**

| File name                         | Discovered? |
|-----------------------------------|-------------|
| `sla_summary_module.py`           | Yes         |
| `patch_compliance_metrics.py`     | Yes         |
| `asset_risk_module.py`            | Yes         |
| `my_helpers.py`                   | No          |
| `base.py` / `registry.py`        | No (skipped by infrastructure exclusion list) |

**First-registration-wins:** if two files register the same `MODULE_ID`,
the second registration is silently dropped with a warning. Use unique,
descriptive IDs.

**Checking what is registered:**

```bash
python -c "
from reports.modules import registry
for m in registry.list_all():
    print(m['module_id'], '—', m['display_name'], 'v' + m['version'])
"
```

---

## 9. Testing a Module in Isolation

No Tenable connection is required. Pass synthetic DataFrames:

```bash
# Check registration and audit info
python -c "
from reports.modules import registry
mod = registry.get('your_module_id')()
print(mod.get_audit_info())
"

# Run compute() with synthetic data
python -c "
import pandas as pd
from datetime import datetime, timezone
from reports.modules import registry, ReportComposer
from reports.modules.base import ModuleConfig

composer = ReportComposer(
    vulns_df = pd.DataFrame({
        'severity':   ['critical', 'high', 'medium'],
        'state':      ['open', 'open', 'open'],
        'is_overdue': [True, False, False],
        'days_open':  [20, 15, 45],
    }),
    assets_df   = pd.DataFrame(),
    report_date = datetime.now(timezone.utc),
    module_configs = [ModuleConfig('your_module_id', options={'top_n': 5})],
)
results = composer.run_all()
print('error:',   results[0].error)
print('metrics:', results[0].metrics)
print('summary:', results[0].summary_text)
"

# Test PDF output
python -c "
import pandas as pd
from datetime import datetime, timezone
from reports.modules import registry, ReportComposer
from reports.modules.base import ModuleConfig

composer = ReportComposer(
    vulns_df=pd.DataFrame(), assets_df=pd.DataFrame(),
    report_date=datetime.now(timezone.utc),
    module_configs=[ModuleConfig('your_module_id')],
)
results = composer.run_all()
html = composer.assemble_pdf(results)
print('HTML length:', len(html))
print('Has section:', '<div class=\"module-section\">' in html)
"

# Test Excel output
python -c "
import openpyxl, pandas as pd
from datetime import datetime, timezone
from reports.modules import registry, ReportComposer
from reports.modules.base import ModuleConfig

wb = openpyxl.Workbook()
wb.remove(wb.active)   # remove default sheet

composer = ReportComposer(
    vulns_df=pd.DataFrame(), assets_df=pd.DataFrame(),
    report_date=datetime.now(timezone.utc),
    module_configs=[ModuleConfig('your_module_id')],
)
results = composer.run_all()
tabs = composer.assemble_excel(results, wb)
print('Tabs written:', tabs)
wb.save('/tmp/test_module.xlsx')
"
```
