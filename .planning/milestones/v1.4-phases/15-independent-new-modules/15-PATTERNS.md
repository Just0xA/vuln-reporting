# Phase 15: Independent New Modules — Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 7 (5 new modules + 2 modified files)
**Analogs found:** 7 / 7

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `reports/modules/reopened_vulns_module.py` | module | request-response (current-snapshot) | `reports/modules/mttr_by_severity_module.py` | exact |
| `reports/modules/new_vs_remediated_module.py` | module | trend (read_trend kwarg) | `reports/modules/mttr_by_severity_module.py` | role-match |
| `reports/modules/vuln_density_module.py` | module | trend (read_trend kwarg + asset_count) | `reports/modules/mttr_by_severity_module.py` | role-match |
| `reports/modules/accepted_recast_module.py` | module | CRUD + recast_rules_df kwarg | `reports/modules/mttr_by_severity_module.py` | role-match |
| `reports/modules/external_dmz_module.py` | module | request-response (current-snapshot) | `reports/modules/mttr_by_severity_module.py` | exact |
| `data/trend_store.py` | service | batch (snapshot extend) | `data/trend_store.py` itself | self (backward-compat extension) |
| `reports/composed_report.py` | router | request-response (frozenset gate) | `reports/composed_report.py` itself | self (frozenset gate pattern) |

---

## Pattern Assignments

### `reports/modules/reopened_vulns_module.py` (PATHFINDER — build first)

**Analog:** `reports/modules/mttr_by_severity_module.py` (full read; lines cited below)
**No trend kwarg needed** — current-snapshot `state==REOPENED` filter only. No gate addition to `composed_report.py`.

**Imports pattern** (copy from mttr lines 30-43):
```python
from __future__ import annotations

import logging
from typing import Any, Optional

import pandas as pd
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

from reports.modules import safe_pct, safe_int, safe_format
from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.format_utils import safe_pct, safe_int, safe_format
from reports.modules.rag_utils import (
    STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE, NO_DATA_DRIVER,
    rag_status_from_value, build_rag_strip_entry,
)
from reports.modules.registry import register_module

logger = logging.getLogger(__name__)
```

**Module skeleton** (copy from mttr lines 92-128, adapt constants):
```python
# RAG thresholds — overridable via module_options (D-15-07)
_DEFAULT_GREEN_RATE  = 5.0   # reopen rate % below which is green
_DEFAULT_YELLOW_RATE = 10.0  # reopen rate % below which is yellow

@register_module
class ReopenedVulnsModule(BaseModule):
    """
    Count and rate of findings in state==REOPENED (resurfaced after a fix).

    Primary filter: vulns_df["state"].str.upper() == "REOPENED"
    Rate denominator: reopened_count / (reopened_count + fixed_and_stayed_fixed_count)
      - Requires fixed_vulns_df kwarg when available; degrades to count-only if absent.
    Owner cut: extract_owner(assets_df) joined on asset_uuid.
    Analyst drill-down: plugin_id, resurfaced_date, reopen_lag_days per finding.

    Supported options
    -----------------
    green_rate_threshold  : float  — default 5.0  (reopen rate % for green)
    yellow_rate_threshold : float  — default 10.0 (reopen rate % for yellow)
    """
    MODULE_ID         = "reopened_vulns"
    DISPLAY_NAME      = "Reopened Vulnerabilities"
    DESCRIPTION       = "Count and rate of findings that re-emerged after being marked fixed."
    REQUIRED_DATA     = ["vulns", "assets"]
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]
    VERSION           = "1.0.0"
```

**compute() signature and guard pattern** (copy from mttr lines 130-165, adapt):
```python
def compute(
    self,
    vulns_df:    pd.DataFrame,
    assets_df:   pd.DataFrame,
    report_date: Any,
    config:      ModuleConfig,
    **kwargs:    Any,
) -> ModuleData:
    logger.debug(
        "%s compute() — vulns_df rows: %d",
        self._log_prefix(), len(vulns_df),
    )
    try:
        green_threshold  = float(config.options.get("green_rate_threshold",  _DEFAULT_GREEN_RATE))
        yellow_threshold = float(config.options.get("yellow_rate_threshold", _DEFAULT_YELLOW_RATE))

        # QUAL-03 empty-data guard
        if vulns_df.empty or "state" not in vulns_df.columns:
            return self._empty_result("No vulnerability data in scope.", config)

        # --- Filter to REOPENED (QUAL-02: use state directly for current snapshot) ---
        reopened_df = vulns_df[vulns_df["state"].astype(str).str.upper() == "REOPENED"]

        # --- fixed_vulns_df kwarg (optional; degrade gracefully if absent) ---
        fixed_vulns_df = kwargs.get("fixed_vulns_df")
        has_rate = fixed_vulns_df is not None and not fixed_vulns_df.empty

        reopened_count = len(reopened_df)
        # rate denominator: fixed-and-stayed-fixed count (state==fixed in fixed export)
        # disclose if fixed export absent
        ...

    except Exception as exc:  # noqa: BLE001
        logger.error("%s compute() failed: %s", self._log_prefix(), exc, exc_info=True)
        return self._empty_result(str(exc), config)
```

**Key field accesses** — confirmed in `data/fetchers.py` lines 354-360:
```python
# resurfaced_date and state already present on vulns_df rows:
"state":          vuln.get("state", ""),
"resurfaced_date": vuln.get("resurfaced_date", ""),
"first_found":    vuln.get("first_found", ""),
"last_fixed":     vuln.get("last_fixed", ""),
"plugin_id":      plugin.get("id", ""),
```

**Reopen-lag computation** (Claude's Discretion per CONTEXT.md):
```python
# Use .assign() — never df["col"] = val after a filter (QUAL-03 / Pitfall 9)
reopened_df = reopened_df.assign(
    resurfaced_ts=pd.to_datetime(reopened_df["resurfaced_date"], utc=True, errors="coerce"),
    last_fixed_ts=pd.to_datetime(reopened_df["last_fixed"],      utc=True, errors="coerce"),
)
reopened_df = reopened_df.assign(
    reopen_lag_days=(
        reopened_df["resurfaced_ts"] - reopened_df["last_fixed_ts"]
    ).dt.days
)
# None when resurfaced_date absent — expected, note in analyst tab
```

**Owner cut pattern** (from `board_report_utils.extract_owner`, lines 214-280):
```python
from reports.modules.board_report_utils import extract_owner  # noqa: PLC0415

enriched = extract_owner(assets_df)  # adds "owner" column; Unassigned catch-all
uuid_to_owner = dict(zip(enriched["asset_uuid"], enriched["owner"]))
owner_col = reopened_df["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
owner_counts = owner_col.value_counts().to_dict()
```

**RAG strip build pattern** (from `rag_utils.py` lines 124-163):
```python
# Inside compute(), after computing reopen_rate:
status = rag_status_from_value(
    reopen_rate,
    green_threshold=green_threshold,
    yellow_threshold=yellow_threshold,
    direction="lower_is_better",
)
rag_strip = build_rag_strip_entry(
    display_name       = self.DISPLAY_NAME,
    headline_value_str = f"{reopened_count} ({safe_pct(reopen_rate)})",
    status             = status,
)
```

**render_pdf_section() error guard** (from mttr lines 368-373):
```python
def render_pdf_section(self, data: ModuleData, config: ModuleConfig) -> str:
    if data.error:
        return (
            f'<div class="error-box">'
            f"<strong>{self.DISPLAY_NAME}</strong>: {data.error}"
            f"</div>"
        )
    # ... rest of render
```

**render_excel_tabs() error guard** (from mttr lines 477-483):
```python
def render_excel_tabs(self, data, workbook, config):
    tab_name = "Reopened Vulns"
    try:
        ws = workbook.create_sheet(tab_name)
        if data.error:
            ws["A1"] = "Error"
            ws["B1"] = data.error
            return [tab_name]
        # headers + data rows with Font(bold=True) on row 1
        ...
    except Exception as exc:
        logger.error("%s render_excel_tabs() failed: %s", self._log_prefix(), exc, exc_info=True)
        return []
```

**render_email_panel()** — CONTRACT-01; NOT render_email_kpis (Pitfall, tech debt table):
```python
def render_email_panel(self, data: ModuleData, config: ModuleConfig) -> str:
    """CONTRACT-01: modular email body panel."""
    if data.error or not data.driver_narrative:
        return ""
    m = data.metrics
    # Use safe_pct / safe_int — no inline f"{val:.1f}" on possibly-None metrics
    count_str = safe_int(m.get("reopened_count"))
    rate_str  = safe_pct(m.get("reopen_rate"))
    return f"""
<table style="width:100%;border-collapse:collapse;font-family:Arial,sans-serif;">
  <tr>
    <td style="padding:8px;background:#f5f5f5;">
      <strong>{self.DISPLAY_NAME}</strong><br>
      {count_str} reopened findings ({rate_str} of fixed)<br>
      <em style="font-size:11px;">{data.driver_narrative}</em>
    </td>
  </tr>
</table>"""
```

**render_analyst_tabs()** — CONTRACT-02; returns data.analyst_rows directly:
```python
def render_analyst_tabs(
    self, data: ModuleData, config: ModuleConfig
) -> list[tuple[str, pd.DataFrame]]:
    if data.error or not data.analyst_rows:
        return []
    return data.analyst_rows
    # analyst_rows populated in compute() as:
    # [("Reopened Detail", reopened_detail_df), ("By Owner", owner_df)]
    # Columns per D-11/QUAL-05: plugin_id, resurfaced_date, reopen_lag_days, owner
    # NO hostnames, IPs, asset_uuid visible in committed fixtures
```

**ModuleData construction pattern** (from mttr lines 332-352):
```python
return ModuleData(
    module_id        = self.MODULE_ID,
    display_name     = self.DISPLAY_NAME,
    metrics          = {
        "reopened_count": reopened_count,
        "reopen_rate":    reopen_rate,   # None when fixed export absent
        "has_rate":       has_rate,
        # top-3 owners by count (for email panel narrative)
    },
    table_data       = [...],  # per-owner rows for PDF table
    chart_data       = {...},  # month-labelled bar data
    summary_text     = f"{reopened_count} findings reopened...",
    metadata         = {
        "rate_available": has_rate,
        "rate_disclosure": "Rate omitted — fixed export unavailable." if not has_rate else "",
    },
    driver_narrative = driver_narrative,   # 1-line "what's driving it"
    analyst_rows     = analyst_rows,       # [("Reopened Detail", df), ("By Owner", df)]
    rag_strip        = rag_strip,          # from build_rag_strip_entry()
    error            = None,
)
```

---

### `reports/modules/new_vs_remediated_module.py`

**Analog:** `reports/modules/mttr_by_severity_module.py` + `reports/composed_report.py` (trend gate pattern)
**Needs `trend_snapshots` kwarg** — add `"new_vs_remediated"` to `_MODULES_NEEDING_TREND_SNAPSHOTS` in `composed_report.py`.

**Imports** — same as reopened pattern above, plus:
```python
from data.trend_store import _sanitise_tag_for_filename  # used by composed_report; not by module
# Module itself receives trend_snapshots as a pre-read kwarg — no direct read_trend() call
```

**compute() trend kwarg receipt** (from composed_report.py lines 206-229 — the gate pattern, not the module side):
```python
# Inside compute(**kwargs):
trend_snapshots = kwargs.get("trend_snapshots")  # {"snapshots": [...], "insufficient_data": bool}
cold_start = (
    trend_snapshots is None
    or trend_snapshots.get("insufficient_data", True)
)
if cold_start:
    # QUAL-01 — must render a notice, never NaN% or crash
    # Return a valid ModuleData with cold_start flag in metrics
    return self._build_cold_start_result(config)
```

**Cold-start result pattern** (QUAL-01 — Pitfall 1):
```python
def _build_cold_start_result(self, config: ModuleConfig) -> ModuleData:
    """Return a coherent cold-start ModuleData — not an error, just insufficient history."""
    return ModuleData(
        module_id        = self.MODULE_ID,
        display_name     = self.DISPLAY_NAME,
        metrics          = {"cold_start": True},
        table_data       = [],
        chart_data       = {},
        summary_text     = "Trend data being established — available from next month.",
        metadata         = {"cold_start": True},
        driver_narrative = "Trend data being established.",
        analyst_rows     = [],
        rag_strip        = build_rag_strip_entry(
            self.DISPLAY_NAME, "—", "no_data"
        ),
        error            = None,  # Not an error — a valid cold-start state
    )
```

**Inflow definition — D-15-01/D-15-02 (locked, do not simplify):**
```python
# "New" = first_found in month M  OR  resurfaced_date in month M
# Both components tracked SEPARATELY for the stacked display (D-15-02)
month_period = pd.Period(month_str, "M")

net_new_mask = (
    pd.to_datetime(vulns_df["first_found"], utc=True, errors="coerce")
    .dt.to_period("M") == month_period
)
resurfaced_mask = (
    vulns_df["resurfaced_date"].notna()
    & (
        pd.to_datetime(vulns_df["resurfaced_date"], utc=True, errors="coerce")
        .dt.to_period("M") == month_period
    )
    # Exclude first-time finds to avoid double-counting (first_found==resurfaced_date edge)
    & ~net_new_mask
)
net_new_count    = int(net_new_mask.sum())
resurfaced_count = int(resurfaced_mask.sum())
total_inflow     = net_new_count + resurfaced_count

# "Remediated" = last_fixed in month M AND state=="fixed" (exclude REOPENED from outflow)
fixed_mask = (
    fixed_vulns_df["state"].astype(str).str.upper() == "FIXED"
    if fixed_vulns_df is not None else pd.Series([], dtype=bool)
)
remediated_count = int(
    (
        pd.to_datetime(fixed_vulns_df.loc[fixed_mask, "last_fixed"], utc=True, errors="coerce")
        .dt.to_period("M") == month_period
    ).sum()
) if fixed_vulns_df is not None else 0
```

**Partial-month label — D-15-08:**
```python
# In all render methods, check if the snapshot's month == current month
current_period = pd.Period(report_date, "M")
def _month_label(month_str: str) -> str:
    if pd.Period(month_str, "M") == current_period:
        return f"{month_str} (MTD — partial)"
    return month_str
```

**chart_data structure** (drives stacked bar in PDF):
```python
chart_data = {
    "months":          [_month_label(s["month"]) for s in snapshots],
    "net_new":         [...],       # per-month net-new counts
    "resurfaced":      [...],       # per-month resurfaced counts
    "remediated":      [...],       # per-month outflow counts
    "net_delta":       [...],       # remediated - total_inflow per month
    "fixed_disclosed": has_fixed,   # False triggers disclosure note
}
```

---

### `reports/modules/vuln_density_module.py`

**Analog:** `reports/modules/mttr_by_severity_module.py` + `utils/asset_count.py`
**Needs `trend_snapshots` kwarg** — add `"vuln_density"` to `_MODULES_NEEDING_TREND_SNAPSHOTS`.

**Denominator pattern** (from `utils/asset_count.py` lines 45-160):
```python
from utils.asset_count import count_on_time_assets  # noqa: PLC0415

# Inside compute():
current_denom = count_on_time_assets(assets_df, report_date)
if current_denom is None:
    return self._empty_result("No on-time-scanned licensed assets in scope.", config)
```

**Per-snapshot density** — MUST use each snapshot's own asset_count (Pitfall 4):
```python
# BAD  (retroactive drift):  density = open_count / len(assets_df)
# GOOD (snapshot-local denom):
for snap in snapshots:
    snap_asset_count = snap.get("on_time_asset_count")  # NEW field (D-15-05)
    if not snap_asset_count:
        continue  # cold-start for this snapshot's denominator
    open_count = sum(snap.get(sev, 0) for sev in ("critical", "high", "medium", "low"))
    density = open_count / snap_asset_count
```

**Denominator-drift flag** (success criterion 2):
```python
if len(density_series) >= 2:
    prev_denom = snapshots[-2].get("on_time_asset_count", 0)
    curr_denom = snapshots[-1].get("on_time_asset_count", 0)
    denom_shift_pct = abs(curr_denom - prev_denom) / max(prev_denom, 1) * 100
    flag_denom_drift = denom_shift_pct > 10.0
```

**RAG thresholds** (D-15-07 — defaults, module_options-overridable):
```python
_DEFAULT_GREEN_DENSITY  = 2.0   # vulns/asset
_DEFAULT_YELLOW_DENSITY = 4.0

green_threshold  = float(config.options.get("green_density_threshold",  _DEFAULT_GREEN_DENSITY))
yellow_threshold = float(config.options.get("yellow_density_threshold", _DEFAULT_YELLOW_DENSITY))
status = rag_status_from_value(
    current_density, green_threshold, yellow_threshold, direction="lower_is_better"
)
```

---

### `reports/modules/accepted_recast_module.py`

**Analog:** `reports/modules/mttr_by_severity_module.py` + `data/fetchers.py` recast pattern
**Needs `recast_rules_df` kwarg** — add `"accepted_recast"` to `_MODULES_NEEDING_RECAST_RULES` in `composed_report.py`.
**May also need `trend_snapshots`** — add `"accepted_recast"` to `_MODULES_NEEDING_TREND_SNAPSHOTS` for MoM delta.

**Field access** (from `data/fetchers.py` lines 357-359):
```python
# On vulns_df rows — already fetched, no new API call:
"severity_modification_type": vuln.get("severity_modification_type", "NONE"),
"recast_rule_uuid":           vuln.get("recast_rule_uuid", ""),
```

**Classification filter** (Pitfall 6 — all three sub-traps):
```python
# CORRECT: use .isin(); treat empty string and "NONE" as unmodified (Pitfall 6a-b)
mod_type = vulns_df["severity_modification_type"].astype(str).str.upper()
accepted_mask = mod_type.isin({"ACCEPTED"})
recasted_mask = mod_type.isin({"RECASTED"})

accepted_df = vulns_df[accepted_mask]
recasted_df = vulns_df[recasted_mask]

# Rate denominator: total open findings (state IN {open, reopened})
open_mask = vulns_df["state"].astype(str).str.upper().isin({"OPEN", "REOPENED"})
total_open = int(open_mask.sum())

# exception_rate = (accepted + recasted) / total_open
# NEVER aggregate silently — keep accepted_count and recast_count SEPARATE (Pitfall 6b)
```

**Expiry cross-check** (Pitfall 6a — expired rules):
```python
recast_rules_df = kwargs.get("recast_rules_df")   # may be None — degrade gracefully
if recast_rules_df is not None and not recast_rules_df.empty:
    # fetch_recast_rules() columns: rule_id, action, expires_at, created_at, plugin_id
    # Exclude findings whose rule_uuid links to an expired rule
    today = pd.Timestamp(report_date).tz_convert("UTC")
    expired_ids = set(
        recast_rules_df.loc[
            recast_rules_df["expires_at"].notna()
            & (pd.to_datetime(recast_rules_df["expires_at"], utc=True) < today),
            "rule_id",
        ]
    )
    accepted_df = accepted_df[~accepted_df["recast_rule_uuid"].isin(expired_ids)]
    recasted_df = recasted_df[~recasted_df["recast_rule_uuid"].isin(expired_ids)]
else:
    logger.warning("%s recast_rules_df absent — expiry cross-check skipped.", self._log_prefix())
```

**fetch_recast_rules() columns** (from `data/fetchers.py` lines 584-635):
```python
# Returned columns:
# rule_id, rule_name, plugin_id (int nullable), action (RECAST|ACCEPT),
# new_severity, original_severity, expires_at, created_at
# Use _summarize_filter() for analyst drill-down filter display (not inline parse)
```

**_summarize_filter() usage** (from `data/fetchers.py` lines 117-160):
```python
from data.fetchers import _summarize_filter  # noqa: PLC0415

# In analyst drill-down row construction:
filter_summary = _summarize_filter(rule.get("filter", {}))
# Returns a human-readable <=120-char string; "No filter" for empty
# Do NOT attempt to parse the filter tree inline — accept None plugin_id gracefully
```

**RAG thresholds** (D-15-07 / matches existing management_summary Metric 6):
```python
_DEFAULT_GREEN_EXCEPTION_RATE  = 5.0   # %
_DEFAULT_YELLOW_EXCEPTION_RATE = 15.0  # %
```

---

### `reports/modules/external_dmz_module.py`

**Analog:** `reports/modules/mttr_by_severity_module.py` (module shell) + `utils/external_scope.py` (classifier)
**No new kwargs gate needed** — `external_scope(assets_df)` is pure compute called inline in `compute()`.

**Substrate call pattern** (from `utils/external_scope.py` lines 90-226):
```python
from utils.external_scope import external_scope  # noqa: PLC0415

# Inside compute():
scoped_assets_df, mismatches_df = external_scope(assets_df)
# scoped_assets_df: Location=External/DMZ tagged + public-IP-untagged gap assets
# mismatches_df: columns [asset_uuid, ip_address, owner_tag, untagged_reason]
#   — PII boundary D-11: operator-local only, never committed, never sent to AI

if scoped_assets_df.empty:
    # Valid state for groups scoped to internal-only assets (gray RAG, not error)
    return ModuleData(
        ...,
        summary_text     = "No external-scope assets in scope.",
        rag_strip        = build_rag_strip_entry(self.DISPLAY_NAME, "0", "no_data"),
        error            = None,
    )

# Scope vulns to external assets
scoped_uuids = set(scoped_assets_df["asset_uuid"].dropna())
ext_vulns_df = vulns_df[vulns_df["asset_uuid"].isin(scoped_uuids)]
```

**No MoM trend** (Phase 14 D-03 / EXT-TREND-01 deferred to v1.5):
```python
# external_dmz is CURRENT-SNAPSHOT ONLY — no trend_snapshots kwarg, no cold-start branch
# Do NOT add "external_dmz" to _MODULES_NEEDING_TREND_SNAPSHOTS
```

**RAG thresholds** (D-15-07 — Green=0 Critical, Amber=1-5, Red=>5):
```python
_DEFAULT_GREEN_EXT_CRIT  = 0    # 0 critical = green
_DEFAULT_YELLOW_EXT_CRIT = 5    # 1-5 = yellow; >5 = red
```

**Mismatch analyst tab schema** (Pitfall 11 — lock schema, no scope creep):
```python
# analyst_rows entry for mismatches:
# ("External Scope Mismatches", mismatches_df)
# Columns ONLY: asset_uuid, ip_address, owner_tag, untagged_reason
# EXCLUDED: plugin names, CVE IDs, per-severity breakdowns, recast_rule_uuid
# finding_count is an aggregate total appended per asset — NOT per-finding rows

# Build finding_count per mismatch asset:
ext_counts = (
    ext_vulns_df.groupby("asset_uuid").size().rename("finding_count")
    if not ext_vulns_df.empty else pd.Series(dtype=int)
)
mismatches_df = mismatches_df.assign(
    finding_count=mismatches_df["asset_uuid"].map(ext_counts).fillna(0).astype(int)
)
```

---

### `data/trend_store.py` — backward-compatible extension of `capture_snapshot()`

**Analog:** `data/trend_store.py` itself (lines 222-335)

**Extension approach** (D-15-04/05/06 — new fields in `new_entry` dict, backward-compatible):
```python
# Current new_entry structure (lines 307-313):
new_entry: dict = {
    "month":        month_str,
    "tag_filter":   tag_filter,
    **count_entry,           # critical/high/medium/low counts
    "asset_count":  asset_count,
    "generated_at": generated_at_str,
}

# Phase 15 extension — add new aggregate fields alongside existing ones:
# All new fields are OPTIONAL in existing snapshots (D-15-06 backward compat)
new_entry: dict = {
    "month":              month_str,
    "tag_filter":         tag_filter,
    **count_entry,
    "asset_count":        asset_count,          # existing — all assets
    "on_time_asset_count": on_time_asset_count, # NEW (D-15-05 / OD-3 D-02 dependency)
    "reopened_count":      reopened_count,       # NEW (D-15-05)
    "accepted_count":      accepted_count,       # NEW (D-15-05)
    "recast_count":        recast_count,         # NEW (D-15-05)
    "new_findings_count":  new_findings_count,   # NEW (D-15-05 / for new_vs_remediated)
    "fixed_findings_count": fixed_findings_count, # NEW (D-15-05)
    "generated_at":       generated_at_str,
}
```

**New parameter additions to `capture_snapshot()` signature** (backward-compat — all optional with defaults):
```python
def capture_snapshot(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    date: datetime,
    dimension: str = "severity",
    tag_filter: str = "all_assets",
    trend_dir: Optional[Path] = None,
    enriched_assets: Optional[pd.DataFrame] = None,
    # --- Phase 15 new optional parameters ---
    on_time_asset_count:  Optional[int] = None,   # from count_on_time_assets()
    reopened_count:       Optional[int] = None,   # len(df[state==REOPENED])
    accepted_count:       Optional[int] = None,   # len(df[smt==ACCEPTED])
    recast_count:         Optional[int] = None,   # len(df[smt==RECASTED])
    fixed_vulns_df:       Optional[pd.DataFrame] = None,  # for new/fixed counts
) -> Path:
```

**Backward-compat read guard in consuming modules** (D-15-06):
```python
# Modules reading new fields from snapshots MUST guard against absence:
on_time = snap.get("on_time_asset_count")  # None in older snapshots → cold-start
if on_time is None:
    # Treat as insufficient_data for this snapshot's density computation
    continue
```

**Idempotent write pattern** (unchanged — already correct in trend_store.py lines 320-330):
```python
# Same-month re-run overwrites; new month appends — pattern already proven
snapshots = _load_trend_json(file_path)
updated = False
for idx, snap in enumerate(snapshots):
    if snap.get("month") == month_str and snap.get("tag_filter") == tag_filter:
        snapshots[idx] = new_entry   # overwrite existing month
        updated = True
        break
if not updated:
    snapshots.append(new_entry)
_atomic_write_json(file_path, {"snapshots": snapshots})
```

---

### `reports/composed_report.py` — frozenset gate additions

**Analog:** `reports/composed_report.py` itself (lines 69-91 + 197-249)

**Two new frozensets** (copy pattern from lines 73-90, add after existing gates):
```python
# Existing gates (lines 73-90) — do not modify:
_MODULES_NEEDING_FIXED_VULNS  = frozenset({"critical_remediation_sla"})
_MODULES_NEEDING_ENV_TOTAL    = frozenset({"tag_severity_share"})
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({"sc4_kwargs_stub"})  # Phase 14 seed
_MODULES_NEEDING_RECAST_RULES    = frozenset({"sc4_kwargs_stub"})  # Phase 14 seed

# Phase 15 — extend the existing frozensets (D-17):
# Replace the Phase 14 seeds with expanded sets:
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "sc4_kwargs_stub",
    "new_vs_remediated",    # D-17
    "vuln_density",         # D-17
    "accepted_recast",      # D-17 (for MoM delta)
})
_MODULES_NEEDING_RECAST_RULES = frozenset({
    "sc4_kwargs_stub",
    "accepted_recast",      # D-17
})
```

**Existing gate pattern to mirror** (lines 206-229 / 231-245 — already correct):
```python
# trend gate — already implemented in Phase 14, just extend frozenset:
need_trend = bool(_MODULES_NEEDING_TREND_SNAPSHOTS.intersection(modules))
if need_trend:
    try:
        from data.trend_store import read_trend, _sanitise_tag_for_filename  # noqa
        _trend_tag_filter = _sanitise_tag_for_filename(tag_category, tag_value)
        trend_snapshots = read_trend(
            dimension  = "severity",
            tag_filter = _trend_tag_filter,
            months     = 13,
        )
    except Exception as exc:
        logger.error("composed_report: trend snapshot read failed: %s", exc, exc_info=True)
        trend_snapshots = None   # fail-soft WR-02 — module degrades via _empty_result

# recast gate — already implemented in Phase 14, just extend frozenset:
need_recast = bool(_MODULES_NEEDING_RECAST_RULES.intersection(modules))
if need_recast:
    try:
        from data.fetchers import fetch_recast_rules  # noqa
        recast_rules_df = fetch_recast_rules(tio, cache_dir)
    except Exception as exc:
        logger.error("composed_report: recast rules fetch failed: %s", exc, exc_info=True)
        recast_rules_df = None   # fail-soft WR-02

# composer_kwargs assembly (lines 341-349) — already handles None correctly:
if trend_snapshots is not None:
    composer_kwargs["trend_snapshots"] = trend_snapshots
if recast_rules_df is not None:
    composer_kwargs["recast_rules_df"] = recast_rules_df
```

---

## Shared Patterns

### QUAL-01 — Cold-Start Guard (applies to: new_vs_remediated, vuln_density, accepted_recast)

**Source:** `data/trend_store.py` lines 338-393 (`read_trend()` contract) + pattern described above.

```python
# Every MoM module's compute() MUST start with:
trend_snapshots = kwargs.get("trend_snapshots")
cold_start = trend_snapshots is None or trend_snapshots.get("insufficient_data", True)
if cold_start:
    return self._build_cold_start_result(config)
# Never render NaN% or crash on cold_start — QUAL-01 enforcement
```

Unit-test requirement: fixture with a single-snapshot trend dict (`insufficient_data=True`); assert the module returns a `ModuleData` with `error=None` and `metrics["cold_start"] == True`.

### QUAL-02 — Reopened-Aware Predicate (applies to: new_vs_remediated open-count context)

**Source:** `utils/open_count.py` lines 19-114 (`open_findings_at()`)

```python
# When a module needs "open at point-in-time" counts, use open_findings_at():
from utils.open_count import open_findings_at  # noqa: PLC0415

open_df = open_findings_at(vulns_df, report_date)
# Two-interval model: REOPENED findings correctly counted as open
# Requires date columns already normalized by fetcher's _normalize_vuln_dates
```

Note: `reopened_vulns_module.py` reads `state==REOPENED` DIRECTLY from `vulns_df` for its current count (not via `open_findings_at`) — that is correct for this module's purpose.

### QUAL-03 — Empty-Data Guard (applies to: all 5 modules, all 4 channels)

**Source:** `reports/modules/base.py` lines 558-603 (`_empty_result()`) + `reports/modules/format_utils.py`

```python
# Guard at compute() entry:
if vulns_df.empty or "state" not in vulns_df.columns:
    return self._empty_result("No vulnerability data in scope.", config)

# Guard all numeric render values:
from reports.modules import safe_pct, safe_int, safe_format

# FORBIDDEN: f"{rate:.1f}%"  (crashes on None)
# REQUIRED:  safe_pct(rate)   (returns "—" on None/NaN)

# CoW guard — NEVER after a filter:
# FORBIDDEN: df["col"] = val
# REQUIRED:  df = df.assign(col=val)
```

### QUAL-05 — Aggregate-Only in Snapshots + PII-Clean Fixtures (applies to: trend_store extension, analyst tabs)

**Source:** `CONTEXT.md` D-04-08 + PITFALLS.md Pitfall 10

```python
# Snapshot new fields — aggregate counts ONLY:
new_entry["reopened_count"] = int(len(reopened_df))      # count, not rows
new_entry["accepted_count"] = int(len(accepted_df))      # count, not plugin names

# Test fixtures MUST use synthetic data only:
# Hostnames: "host-001.example.invalid"  (RFC 6761)
# IPs:       "203.0.113.x"              (TEST-NET-3, RFC 5737)
# Plugin IDs: 100001, 100002, ...
# UUIDs:     "00000000-0000-0000-0000-000000000001"
# Owner names: "Engineering", "Operations", "Unassigned"
```

### Four-Channel Contract (applies to: all 5 new modules)

**Source:** `reports/modules/base.py` lines 256-459

| Method | Return on no-data | Return on error |
|---|---|---|
| `render_pdf_section()` | `""` or "No data" HTML block | `<div class="error-box">...</div>` |
| `render_excel_tabs()` | `[]` | Write error row, return `[tab_name]` |
| `render_email_panel()` | `""` | `""` |
| `render_analyst_tabs()` | `[]` | `[]` |
| `render_rag_strip_entry()` | gray "No Data" cell via `build_rag_strip_entry(..., "no_data")` | gray cell |

CONTRACT-01 (`render_email_panel`) is REQUIRED for new modules — NOT `render_email_kpis` (legacy). The predicate in `delivery/email_sender.py` routes through `build_email_body_modular()` when any report's `email_body_html` is non-empty; modules that implement only `render_email_kpis` do NOT participate.

### Owner Cut Pattern (applies to: reopened_vulns, new_vs_remediated, accepted_recast, external_dmz)

**Source:** `reports/modules/board_report_utils.py` lines 214-280 (`extract_owner()`)

```python
from reports.modules.board_report_utils import extract_owner  # noqa: PLC0415

# Inside compute() — call once; result is a copy with "owner" column added:
enriched_assets = extract_owner(assets_df)
# "owner" = value of Owner= tag; "Unassigned" when absent (D-06)
# Build uuid→owner map for joining to vulns_df:
uuid_to_owner = dict(zip(enriched_assets["asset_uuid"], enriched_assets["owner"]))
```

### RAG Strip Entry (applies to: all 5 modules)

**Source:** `reports/modules/rag_utils.py` lines 82-163

```python
from reports.modules.rag_utils import (
    rag_status_from_value, build_rag_strip_entry,
    STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE, NO_DATA_DRIVER,
)

# Classification:
status = rag_status_from_value(
    value=metric_value,
    green_threshold=green_threshold,
    yellow_threshold=yellow_threshold,
    direction="lower_is_better",   # or "higher_is_better"
)

# Strip cell dict (pre-built inside compute(), stored in ModuleData.rag_strip):
rag_strip = build_rag_strip_entry(
    display_name       = self.DISPLAY_NAME,
    headline_value_str = safe_pct(metric_value),   # or safe_int — never raw f-string
    status             = status,
)
```

### Partial-Month Label — D-15-08 (applies to: new_vs_remediated, vuln_density, reopened_vulns MoM, accepted_recast MoM)

```python
# Applied consistently in ALL four render channels wherever month labels appear:
current_period = pd.Period(report_date, "M")
def _label_month(month_str: str) -> str:
    return f"{month_str} (MTD — partial)" if pd.Period(month_str, "M") == current_period else month_str
```

---

## No Analog Found

No files in this phase lack a codebase analog. All patterns are derivable from existing shipped code.

| File | Why no new-territory analog needed |
|---|---|
| All 5 new modules | `mttr_by_severity_module.py` is a complete four-channel analog; patterns for trend kwarg, recast kwarg, and external scope are in the Phase 14 shipped substrates |
| `data/trend_store.py` extension | Self-analog — backward-compat field addition follows the existing `new_entry` dict pattern exactly |
| `reports/composed_report.py` gate addition | Self-analog — `_MODULES_NEEDING_TREND_SNAPSHOTS` / `_MODULES_NEEDING_RECAST_RULES` frozenset extension pattern already present from Phase 14 |

---

## Metadata

**Analog search scope:** `reports/modules/`, `data/`, `utils/`, `reports/`
**Files read:** 12 source files
**Pattern extraction date:** 2026-06-11
