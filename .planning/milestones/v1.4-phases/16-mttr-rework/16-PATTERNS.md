# Phase 16: MTTR Rework — Pattern Map

**Mapped:** 2026-06-12
**Files analyzed:** 6 new/modified files
**Analogs found:** 6 / 6

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `reports/modules/mttr_trend_module.py` | module (new) | request-response + event-driven (snapshot read) | `reports/modules/new_vs_remediated_module.py` (MoM + Owner + cold-start) AND `reports/modules/mttr_by_severity_module.py` (MTTR gauge/Excel/SLA structure) | exact dual-analog |
| `data/trend_store.py` (modify `capture_snapshot`) | data-store | batch / transform | `data/trend_store.py` lines 222–392 (Phase 15 implicit-optional extension pattern) | self-analog / exact |
| `scripts/capture_trend_snapshot.py` (modify `main`) | entry-point / orchestrator | batch | `scripts/capture_trend_snapshot.py` lines 261–329 (Phase 15 aggregate-count compute + fail-soft fetch pattern) | self-analog / exact |
| `reports/composed_report.py` (modify frozenset) | orchestrator / router | request-response | `reports/composed_report.py` lines 86–91 (`_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset) | self-analog / exact |
| `tests/test_mttr_trend_module.py` (new) | test | request-response | `tests/test_new_vs_remediated_module.py` (cold-start, partial-month, owner, four-channel render guard) | exact |
| `tests/baselines/mttr_trend_*.json` (new) | test artifact | — | `tests/baselines/board_summary_test_pull.json` (structural smoke shape) | role-match |

---

## Pattern Assignments

---

### `reports/modules/mttr_trend_module.py` (module, new)

**Primary analog:** `reports/modules/new_vs_remediated_module.py` (MoM + cold-start + Owner + four-channel contract)
**Secondary analog:** `reports/modules/mttr_by_severity_module.py` (MTTR gauge, Excel SLA tab, status/color logic)

---

#### Imports pattern — copy from `new_vs_remediated_module.py` lines 36–56

```python
from __future__ import annotations

import logging
from typing import Any, Optional

import pandas as pd
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

from config import SLA_DAYS
from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.board_report_utils import extract_owner
from reports.modules.chart_utils import draw_gauge
from reports.modules.format_utils import safe_format, safe_int, safe_pct
from reports.modules.rag_utils import (
    NO_DATA_DRIVER,
    NO_DATA_HEADLINE,
    STATUS_COLOR,
    STATUS_LABEL,
    build_rag_strip_entry,
    rag_status_from_value,
)
from reports.modules.registry import register_module
```

**Key difference from `mttr_by_severity`:** that module does NOT import `new_vs_remediated`-style utilities (`format_utils`, `rag_utils`, `board_report_utils`). The new module needs all of them.

---

#### Registration and class constants — copy from `mttr_by_severity_module.py` lines 92–125, change MODULE_ID and REQUIRED_DATA

```python
@register_module
class MTTRTrendModule(BaseModule):
    MODULE_ID         = "mttr_trend"
    DISPLAY_NAME      = "MTTR Trend (Reopened-Aware)"
    DESCRIPTION       = (
        "Rolling-window Mean Time to Remediate — sample-weighted, reopened-aware, "
        "with MoM trend and Owner breakdown."
    )
    REQUIRED_DATA     = ["vulns", "assets", "fixed_vulns", "trend_snapshots"]
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]
    VERSION           = "1.0.0"
```

---

#### Cold-start result builder — copy from `new_vs_remediated_module.py` lines 177–202

```python
def _build_cold_start_result(self, config: ModuleConfig) -> ModuleData:
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
            display_name       = self.DISPLAY_NAME,
            headline_value_str = NO_DATA_HEADLINE,
            status             = "no_data",
        ),
        error            = None,
    )
```

---

#### compute() signature and QUAL-01 cold-start guard — copy from `new_vs_remediated_module.py` lines 208–261

```python
def compute(
    self,
    vulns_df:    pd.DataFrame,
    assets_df:   pd.DataFrame,
    report_date: Any,
    config:      ModuleConfig,
    **kwargs:    Any,
) -> ModuleData:
    try:
        # ---- QUAL-01: cold-start guard (trend_snapshots) ----
        trend_snapshots = kwargs.get("trend_snapshots")
        snapshots_cold = (
            trend_snapshots is None
            or trend_snapshots.get("insufficient_data", True)
        )
        # NOTE: cold_start on snapshots does NOT abort the whole module —
        # per-severity gauges still render from fixed_vulns_df live data.
        # Only the MoM trend line cold-starts independently.

        snapshots: list[dict] = (
            [] if snapshots_cold
            else trend_snapshots.get("snapshots", [])
        )

        fixed_vulns_df: Optional[pd.DataFrame] = kwargs.get("fixed_vulns_df")

        window_days = int(config.options.get("mttr_window_days", 30))
        min_sample  = int(config.options.get("min_sample_size", 5))  # D-16-04, default raised from 1→5
        ...

    except Exception as exc:  # noqa: BLE001
        logger.error("%s compute() failed: %s", self._log_prefix(), exc, exc_info=True)
        return self._empty_result(str(exc), config)
```

**Critical D-16-01 change from `mttr_by_severity` lines 170–177:**
```python
# OLD (mttr_by_severity) — WRONG, pulls in currently-REOPENED via stale last_fixed:
fixed_mask = (
    vulns_df["state"].str.lower().isin({"fixed"}) |
    vulns_df.get("last_fixed", pd.Series(dtype=object)).notna()
)
fixed_df = vulns_df[fixed_mask].copy()

# NEW (mttr_trend) — D-16-01: durably-fixed only
if fixed_vulns_df is None or fixed_vulns_df.empty:
    return self._empty_result_zero_fixed(config)  # or _build_cold_start_result
fixed_df = fixed_vulns_df[
    fixed_vulns_df["state"].astype(str).str.upper() == "FIXED"
].copy()
```

---

#### days_to_fix derivation — D-16-02 replacement for `mttr_by_severity` lines 190–222

This is the critical surgical replacement. The entire `ttf_valid` / `ttf_days` block is dropped and replaced:

```python
# D-16-02: date-math only, reopened-aware COALESCE.
# Both sides coerced to datetime64[ns, UTC] defensively (Pitfall A).
_nat_series = pd.Series([pd.NaT] * len(fixed_df), index=fixed_df.index, dtype="object")

last_fixed_ts = pd.to_datetime(
    fixed_df["last_fixed"] if "last_fixed" in fixed_df.columns else _nat_series,
    utc=True, errors="coerce",
)
first_found_ts = pd.to_datetime(
    fixed_df["first_found"] if "first_found" in fixed_df.columns else _nat_series,
    utc=True, errors="coerce",
)
resurfaced_ts = pd.to_datetime(
    fixed_df["resurfaced_date"] if "resurfaced_date" in fixed_df.columns else _nat_series,
    utc=True, errors="coerce",
)

# COALESCE: use resurfaced_date when present, else first_found
clock_start_ts = resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)

# Both sides are datetime64[ns, UTC]; subtraction is safe
date_diff_days = (last_fixed_ts - clock_start_ts).dt.days.clip(lower=0)

# CoW-compliant: .assign() only — never fixed_df["days_to_fix"] = ... after a filter
fixed_df = fixed_df.assign(days_to_fix=date_diff_days)
fixed_df = fixed_df[
    fixed_df["days_to_fix"].notna() & (fixed_df["days_to_fix"] >= 0)
]
```

**Criterion-3 validation:** `first_found=−200d, resurfaced_date=−10d, last_fixed=−2d` → `clock_start = resurfaced_date` → `days_to_fix = 8`. The old module would return 198.

---

#### Rolling-window filter — apply BEFORE computing MTTR (D-16-04, Pitfall C)

```python
# Apply rolling window to fixed_df for live gauge computation.
# Window is also applied in capture_trend_snapshot.py for stored MTTR aggregate —
# both must use the same window_days value (from config.options).
window_cutoff = pd.Timestamp(report_date) - pd.Timedelta(days=window_days)
window_cutoff = window_cutoff.tz_localize("UTC") if window_cutoff.tzinfo is None else window_cutoff
fixed_df = fixed_df[last_fixed_ts >= window_cutoff]
```

---

#### Overall MTTR — D-16-02 consequence replaces `mttr_by_severity` lines 282–286

```python
# OLD (mttr_by_severity) — WRONG: unweighted mean-of-per-severity-means
valid_mttrs = [v for v in per_sev_mttr.values() if v is not None]
overall_mttr = round(sum(valid_mttrs) / len(valid_mttrs), 1) if valid_mttrs else None

# NEW (mttr_trend) — D-16-02: sample-weighted flat mean across all in-scope findings
overall_mttr: Optional[float] = (
    round(float(fixed_df["days_to_fix"].mean()), 1)
    if len(fixed_df) >= min_sample
    else None
)
```

---

#### MoM trend + Owner-drift join — copy from RESEARCH.md Open Item 2

```python
# D-16-08: deduplicate to latest snapshot per calendar month
by_month: dict[str, dict] = {}
for snap in snapshots:
    m = snap.get("month", "")
    if m not in by_month or snap.get("generated_at", "") > by_month[m].get("generated_at", ""):
        by_month[m] = snap
snapshots_deduped = [by_month[m] for m in sorted(by_month)]

# Build aligned series in one forward pass
months: list[str] = []
overall_mttr_series: list[Optional[float]] = []
sev_series: dict[str, list[Optional[float]]] = {s: [] for s in _SEVERITIES}
owner_set: set[str] = set()

for snap in snapshots_deduped:
    months.append(snap.get("month", ""))
    overall_mttr_series.append(snap.get("mttr_overall_days"))
    for sev in _SEVERITIES:
        sev_series[sev].append((snap.get("mttr_by_severity") or {}).get(sev))
    for owner in (snap.get("mttr_by_owner") or {}):
        owner_set.add(owner)

# Per-owner series with None back-fill (Pitfall B: use (snap.get(...) or {}).get(owner))
owner_series: dict[str, list[Optional[float]]] = {}
for snap_idx, snap in enumerate(snapshots_deduped):
    snap_owners = snap.get("mttr_by_owner") or {}
    for owner in owner_set:
        if owner not in owner_series:
            owner_series[owner] = [None] * snap_idx
        owner_series[owner].append(snap_owners.get(owner))
for owner in owner_set:
    while len(owner_series[owner]) < len(months):
        owner_series[owner].append(None)
```

---

#### Partial-month label — copy `_month_label` from `new_vs_remediated_module.py` lines 109–135 verbatim

```python
def _month_label(month_str: str, current_period: pd.Period) -> str:
    try:
        snap_period = pd.Period(month_str, "M")
        if snap_period == current_period:
            return f"{month_str} (MTD — partial)"
    except Exception:  # noqa: BLE001
        pass
    return month_str
```

Used identically at: `current_period = pd.Period(report_date, "M")`.

---

#### D-16-07 sparse-row rendering — standardised wording

```python
# For any severity or Owner row where n < min_sample (but n > 0):
insufficient_str = f"Insufficient data ({n} findings — minimum {min_sample} required)"
# For Owner rows where n == 0: omit row entirely (do not show "Insufficient data")
# For overall where len(fixed_df) == 0: _empty_result() / _build_cold_start_result()
```

---

#### RAG strip + owner MoM delta helpers

```python
# Overall MTTR RAG — mirror _status_from_ratio from mttr_by_severity_module.py lines 72–78
# Use Critical SLA as anchor (most stringent, consistent with existing module)
def _status_from_ratio(ratio: float) -> tuple[str, str]:
    if ratio <= 1.0:
        return "Within SLA", "#388e3c"
    if ratio <= 1.25:
        return "Near SLA Limit", "#fbc02d"
    return "Exceeding SLA", "#d32f2f"

# RAG strip uses build_rag_strip_entry from rag_utils (CONTRACT-03)
rag_status = "no_data" if overall_mttr is None else (
    "green" if overall_mttr / SLA_DAYS["critical"] <= 1.0 else
    "yellow" if overall_mttr / SLA_DAYS["critical"] <= 1.25 else
    "red"
)
rag_strip = build_rag_strip_entry(
    display_name       = self.DISPLAY_NAME,
    headline_value_str = safe_format(overall_mttr, ".1f") + "d" if overall_mttr is not None else NO_DATA_HEADLINE,
    status             = rag_status,
)

# Owner MoM delta (absolute days, not %) — from RESEARCH.md Open Item 2
def _owner_mom_delta(series: list[Optional[float]]) -> Optional[float]:
    if len(series) < 2:
        return None
    curr, prev = series[-1], series[-2]
    if curr is None or prev is None:
        return None
    return round(curr - prev, 1)
```

---

#### render_pdf_section — copy structure from `mttr_by_severity_module.py` lines 358–458, add disclosures and MoM

```python
def render_pdf_section(self, data: ModuleData, config: ModuleConfig) -> str:
    if data.error:
        return f'<div class="error-box"><strong>{self.DISPLAY_NAME}</strong>: {data.error}</div>'

    if data.metrics.get("cold_start"):
        return f"""
<div class="module-section">
  <h2 class="section-heading">{data.display_name}</h2>
  <p style="color:#757575;">{data.summary_text}</p>
</div>"""

    window_days = data.metadata.get("window_days", 30)
    current_month = data.metadata.get("current_month", "")

    # Gauges: same draw_gauge pattern as mttr_by_severity lines 401–414
    # Window disclosure (D-16-04):
    disclosure = (
        f'<p class="explanatory-text">'
        f'Rolling {window_days}-day MTTR — findings remediated in the last {window_days} days. '
        f'Current month ({current_month}) is month-to-date (partial).'
        f'</p>'
    )
    ...
```

---

#### render_excel_tabs — copy structure from `mttr_by_severity_module.py` lines 464–521, extend with window header and MoM/Owner table

```python
# Row 1: title with window disclosure (D-16-04)
ws["A1"] = f"MTTR Trend — Rolling {window_days}-day window"
ws["A1"].font = Font(bold=True, size=13)

# Headers (D-16-05 column order):
headers = [
    "Severity / Owner", "MTTR (Days)", "SLA Target (Days)",
    "Variance (Days)", "Status", "Sample Size", "MoM Delta (Days)",
]
```

---

#### render_email_panel — copy pattern from `new_vs_remediated_module.py` lines 658–704 (CONTRACT-01, not render_email_kpis)

```python
def render_email_panel(self, data: ModuleData, config: ModuleConfig) -> str:
    if data.error:
        return ""
    if data.metrics.get("cold_start"):
        return f"""
<table style="width:100%;border-collapse:collapse;font-family:Arial,sans-serif;margin-bottom:8px;">
  <tr>
    <td style="padding:8px 12px;background:#F5F5F5;border-left:4px solid #757575;">
      <strong style="font-size:13px;">{self.DISPLAY_NAME}</strong><br>
      <span style="font-size:12px;color:#757575;">{data.summary_text}</span>
    </td>
  </tr>
</table>"""
    if not data.driver_narrative:
        return ""

    rag_status = data.metrics.get("rag_status", "no_data")
    rag_color  = STATUS_COLOR.get(rag_status, STATUS_COLOR["no_data"])
    window_days = data.metadata.get("window_days", 30)
    # Footer disclosure (inline CSS only — Outlook compat):
    # <span style="font-size:10px;color:#757575;">Rolling {window_days}-day MTTR. Current month is partial.</span>
    ...
```

---

#### render_rag_strip_entry — copy from `new_vs_remediated_module.py` lines 732–749 verbatim

```python
def render_rag_strip_entry(self, data: ModuleData, config: ModuleConfig) -> dict:
    if data.error or not data.rag_strip:
        return build_rag_strip_entry(
            display_name       = self.DISPLAY_NAME,
            headline_value_str = NO_DATA_HEADLINE,
            status             = "no_data",
        )
    return data.rag_strip
```

---

### `data/trend_store.py` — modify `capture_snapshot()` (lines 222–392)

**Analog:** self (Phase 15 implicit-optional extension at lines 334–370)

#### Signature extension — append 3 new kwargs after `fixed_vulns_df` (line 234)

```python
def capture_snapshot(
    df: pd.DataFrame,
    assets_df: pd.DataFrame,
    date: datetime,
    dimension: str = "severity",
    tag_filter: str = "all_assets",
    trend_dir: Optional[Path] = None,
    enriched_assets: Optional[pd.DataFrame] = None,
    on_time_asset_count: Optional[int] = None,
    reopened_count: Optional[int] = None,
    accepted_count: Optional[int] = None,
    recast_count: Optional[int] = None,
    fixed_vulns_df: Optional[pd.DataFrame] = None,
    # ---- Phase 16 additions (D-16-03 / D-16-09) ----
    mttr_overall_days: Optional[float] = None,
    mttr_by_severity: Optional[dict] = None,
    mttr_by_owner: Optional[dict] = None,
) -> Path:
```

#### new_entry dict extension — append after line 368 `"fixed_findings_count": fixed_findings_count`

```python
new_entry: dict = {
    "month":               month_str,
    "tag_filter":          tag_filter,
    **count_entry,
    "asset_count":         asset_count,
    "on_time_asset_count": on_time_asset_count,
    "reopened_count":      reopened_count,
    "accepted_count":      accepted_count,
    "recast_count":        recast_count,
    "new_findings_count":  new_findings_count,
    "fixed_findings_count": fixed_findings_count,
    # Phase 16 — explicit null when not supplied so snap.get() returns None
    # consistently (never KeyError) per D-16-09 implicit-optional-field convention.
    "mttr_overall_days":   mttr_overall_days,
    "mttr_by_severity":    mttr_by_severity,
    "mttr_by_owner":       mttr_by_owner,
    "generated_at":        generated_at_str,
}
```

**Pattern proof:** Phase 15 used identical pattern at lines 358–370. `on_time_asset_count`, `reopened_count`, etc. are all stored as explicit `None` when not passed, not omitted. Phase 16 follows exactly the same convention (D-16-09).

---

### `scripts/capture_trend_snapshot.py` — modify `main()` (lines 261–329)

**Analog:** self (Phase 15 aggregate-count pattern, lines 261–309)

#### New MTTR aggregate computation block — insert after `fixed_vulns_df` fetch (after line 294), before the `capture_snapshot` call (line 297)

```python
# ---- Phase 16: compute MTTR aggregate for snapshot persistence (D-16-03) ----
# Window applied here (in the capture script), not inside the module (Pitfall C).
mttr_overall_days: Optional[float] = None
mttr_by_severity: Optional[dict]   = None
mttr_by_owner: Optional[dict]      = None

if fixed_vulns_df is not None and not fixed_vulns_df.empty:
    try:
        window_days = 30  # configurable in future; default per D-16-04
        local_tz = datetime.now().astimezone().tzinfo
        lf = pd.to_datetime(fixed_vulns_df["last_fixed"], utc=True, errors="coerce")
        window_cutoff = pd.Timestamp(snapshot_date, tz="UTC") - pd.Timedelta(days=window_days)

        # D-16-01: durably-fixed only
        state_upper = fixed_vulns_df["state"].astype(str).str.upper()
        window_mask = (state_upper == "FIXED") & (lf >= window_cutoff)
        windowed = fixed_vulns_df[window_mask].copy()

        if not windowed.empty:
            # D-16-02: COALESCE clock start
            _nat = pd.Series([pd.NaT] * len(windowed), index=windowed.index, dtype="object")
            last_fixed_ts  = pd.to_datetime(windowed.get("last_fixed",  _nat), utc=True, errors="coerce")
            first_found_ts = pd.to_datetime(windowed.get("first_found", _nat), utc=True, errors="coerce")
            resurfaced_ts  = pd.to_datetime(windowed.get("resurfaced_date", _nat), utc=True, errors="coerce")
            clock_start    = resurfaced_ts.where(resurfaced_ts.notna(), other=first_found_ts)
            days_col       = (last_fixed_ts - clock_start).dt.days.clip(lower=0)
            windowed       = windowed.assign(days_to_fix=days_col)
            windowed       = windowed[windowed["days_to_fix"].notna() & (windowed["days_to_fix"] >= 0)]

            if not windowed.empty:
                # D-16-02 consequence: flat mean = sample-weighted overall
                mttr_overall_days = round(float(windowed["days_to_fix"].mean()), 2)

                # Per-severity (None when n < min_sample=5)
                MIN_SAMPLE = 5
                mttr_by_severity = {}
                for sev in ("critical", "high", "medium", "low"):
                    sev_df = windowed[windowed["severity"].str.lower() == sev]
                    mttr_by_severity[sev] = (
                        round(float(sev_df["days_to_fix"].mean()), 2)
                        if len(sev_df) >= MIN_SAMPLE else None
                    )

                # Per-Owner (D-16-06): requires enriched assets
                # extract_owner is already imported for the owner snapshot call
                enriched = extract_owner(assets_df)
                uuid_to_owner = dict(zip(
                    enriched.drop_duplicates("asset_uuid")["asset_uuid"],
                    enriched.drop_duplicates("asset_uuid")["owner"],
                ))
                owner_col = windowed["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
                windowed_w_owner = windowed.assign(owner=owner_col)
                mttr_by_owner = {}
                for owner, grp in windowed_w_owner.groupby("owner", dropna=False):
                    mttr_by_owner[str(owner)] = (
                        round(float(grp["days_to_fix"].mean()), 2)
                        if len(grp) >= MIN_SAMPLE else None
                    )

        logger.info(
            "MTTR aggregate — overall=%.1f by_severity=%s by_owner_keys=%s",
            mttr_overall_days or 0.0,
            {k: v for k, v in (mttr_by_severity or {}).items()},
            list((mttr_by_owner or {}).keys()),
        )
    except Exception as exc:  # noqa: BLE001
        # Fail-soft: MTTR aggregate failure must not abort the severity snapshot
        logger.warning("MTTR aggregate computation failed — fields will cold-start: %s", exc)
        mttr_overall_days = mttr_by_severity = mttr_by_owner = None
```

#### Updated `capture_snapshot` call — extend with new kwargs

```python
# Existing call at lines 297–304, extended:
path = capture_snapshot(
    df, assets_df, snapshot_date, "severity", "all_assets",
    on_time_asset_count=on_time_asset_count,
    reopened_count=reopened_count,
    accepted_count=accepted_count,
    recast_count=recast_count,
    fixed_vulns_df=fixed_vulns_df,
    # ---- Phase 16 additions ----
    mttr_overall_days=mttr_overall_days,
    mttr_by_severity=mttr_by_severity,
    mttr_by_owner=mttr_by_owner,
)
```

#### WR-03 fail-soft pattern — Owner MTTR failure must not abort (lines 311–329)

The existing owner snapshot block already has the WR-03 exit-0 pattern (lines 321–329). The MTTR computation above uses the same `except … logger.warning … = None` fail-soft so the severity snapshot succeeds even if MTTR computation fails.

---

### `reports/composed_report.py` — add `"mttr_trend"` to frozenset (lines 86–91)

**Analog:** self (existing frozenset pattern, lines 86–91)

```python
# Current (lines 86–91):
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "sc4_kwargs_stub",
    "new_vs_remediated",
    "vuln_density",
    "accepted_recast",
})

# After Phase 16 change — add one entry:
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "sc4_kwargs_stub",
    "new_vs_remediated",
    "vuln_density",
    "accepted_recast",
    "mttr_trend",          # D-16-03: reads rolling MTTR from trend snapshots
})
```

No other change to `composed_report.py`. The `**self._kwargs` fan-out in `composer.py` already delivers `trend_snapshots` to any module whose ID is in this frozenset — no signature change needed.

---

### `tests/test_mttr_trend_module.py` (new)

**Analog:** `tests/test_new_vs_remediated_module.py` (entire file structure)

#### File header and CoW enforcement — copy from `test_new_vs_remediated_module.py` lines 1–50

```python
"""
tests/test_mttr_trend_module.py — Unit tests for MTTRTrendModule.

Tests cover:
  - Criterion-3 reopened-clock fixture: first_found=−200d, resurfaced_date=−10d,
    last_fixed=−2d → days_to_fix=8, overall_mttr=8.0 (D-16-02)
  - Zero fixed findings → _empty_result() / cold-start (QUAL-01/03)
  - Cold-start MoM: 1 snapshot → cold-start notice, no NaN%, no crash (QUAL-01)
  - min_sample=5 sub-threshold: 3 Critical → "Insufficient data (3 findings...)"
  - Owner cold start: Owner appearing only in snapshot 2 → series=[None, 12.3], MoM=None
  - Owner vanished: Owner in snapshot 1 only → omitted from current Owner table
  - Multiple snapshots same month → latest generated_at wins (D-16-08 tie-break)
  - Partial-month label: current month contains "partial" (D-16-08)
  - pandas CoW strict mode: zero ChainedAssignmentError (QUAL-03)
  - board_summary zero-diff: board_summary baselines byte-identical after Phase 16

All fixtures use synthetic data only (QUAL-05):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - No real hostnames, IPs, CVE IDs, or plugin names
"""

from __future__ import annotations

import datetime
from datetime import timedelta, timezone
from typing import Optional

import pandas as pd
import pytest

# Enforce pandas CoW strict mode
pd.options.mode.copy_on_write = True

from reports.modules.base import ModuleConfig, ModuleData
from reports.modules.mttr_trend_module import MTTRTrendModule
```

#### Fixture helpers — copy `_make_vulns`, `_make_assets`, `_make_snapshot` pattern from `test_new_vs_remediated_module.py` lines 60–128, extend `_make_snapshot` with MTTR fields

```python
REF = datetime.datetime(2026, 6, 12, tzinfo=timezone.utc)
_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"

def _make_fixed_vulns(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal fixed_vulns_df with all required D-16-02 columns."""
    defaults = {
        "state":            "fixed",
        "severity":         "critical",
        "asset_uuid":       f"{_UUID_PREFIX}1",
        "first_found":      REF - timedelta(days=10),
        "resurfaced_date":  None,
        "last_fixed":       REF - timedelta(days=2),
    }
    records = [{**defaults, **r} for r in rows]
    df = pd.DataFrame(records, columns=list(defaults.keys()))
    for col in ("first_found", "resurfaced_date", "last_fixed"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df

def _make_snapshot_mttr(
    month: str,
    mttr_overall_days: Optional[float] = None,
    mttr_by_severity: Optional[dict] = None,
    mttr_by_owner: Optional[dict] = None,
    generated_at: str = "2026-06-01T00:00:00Z",
    **extra,
) -> dict:
    return {
        "month":              month,
        "tag_filter":         "all_assets",
        "critical":           0, "high": 0, "medium": 0, "low": 0,
        "asset_count":        5,
        "on_time_asset_count": None,
        "reopened_count":     None,
        "accepted_count":     None,
        "recast_count":       None,
        "new_findings_count": None,
        "fixed_findings_count": None,
        "mttr_overall_days":  mttr_overall_days,
        "mttr_by_severity":   mttr_by_severity,
        "mttr_by_owner":      mttr_by_owner,
        "generated_at":       generated_at,
        **extra,
    }
```

#### Criterion-3 fixture test — encoding the acceptance lodestar from CONTEXT.md

```python
class TestCriterion3ReopenedClock:
    def test_reopened_clock_days_to_fix_is_8(self):
        """
        D-16-02 criterion-3 fixture:
        first_found=−200d, resurfaced_date=−10d, last_fixed=−2d → days_to_fix=8.
        The old module (time_taken_to_fix preference) would return 198.
        """
        fixed_df = _make_fixed_vulns([{
            "first_found":     REF - timedelta(days=200),
            "resurfaced_date": REF - timedelta(days=10),
            "last_fixed":      REF - timedelta(days=2),
            "state":           "fixed",
            "severity":        "critical",
        }])
        mod = MTTRTrendModule()
        cfg = ModuleConfig("mttr_trend", options={"min_sample_size": 1})
        data = mod.compute(
            pd.DataFrame(),  # vulns_df not used for gauge computation
            _make_assets(),
            REF,
            cfg,
            fixed_vulns_df=fixed_df,
        )
        assert data.error is None
        assert data.metrics.get("overall_mttr") == 8.0, (
            f"Expected 8.0d (reopened-aware), got {data.metrics.get('overall_mttr')}"
        )
```

#### Test class structure to implement — mirrors `test_new_vs_remediated_module.py`

```
TestRegistration         — MODULE_ID, DISPLAY_NAME, auto-discovery
TestCriterion3ReopenedClock — the acceptance lodestar (above)
TestZeroFixedFindings    — empty fixed_vulns_df → _empty_result / cold-start
TestColdStartMoM         — 1 snapshot → cold-start notice, no NaN
TestMinSampleThreshold   — 3 Critical findings, min_sample=5 → "Insufficient data (3 findings — minimum 5 required)"
TestOwnerColdStart       — new Owner in snapshot 2 only → series=[None, 12.3], MoM=None→"N/A"
TestOwnerVanished        — Owner in snapshot 1 only → omitted from current table
TestTieBreak             — 2 snapshots same month, diff generated_at → latest wins
TestPartialMonthLabel    — current month label contains "partial"
TestEmptyDataGuard       — zero-row guard on all four render channels (QUAL-03)
TestPandasCoW            — pd.options.mode.copy_on_write=True; no ChainedAssignmentError
```

---

## Shared Patterns

### 1. `@register_module` auto-discovery
**Source:** `reports/modules/mttr_by_severity_module.py` line 92; `new_vs_remediated_module.py` line 142
**Apply to:** `mttr_trend_module.py`

```python
from reports.modules.registry import register_module

@register_module
class MTTRTrendModule(BaseModule):
    MODULE_ID = "mttr_trend"
```

No registration in `run_all.py` or schema — module-only IDs self-register via `@register_module`.

---

### 2. Empty-data guard — `safe_pct` / `safe_int` / `safe_format`
**Source:** `reports/modules/format_utils.py` (entire file, lines 36–176)
**Apply to:** all four render methods in `mttr_trend_module.py`

Rule: no inline f-string format spec on a value that could be `None` or `NaN`.
```python
# FORBIDDEN:
f"{mttr:.1f}d"          # crashes when mttr is None

# REQUIRED:
safe_format(mttr, ".1f") + "d" if mttr is not None else "Insufficient data"
# or:
safe_format(mttr, ".1f", default="—")
```

---

### 3. `_empty_result()` — failed ModuleData with gray RAG
**Source:** `reports/modules/base.py` lines 558–599
**Apply to:** `except` handler in `compute()`, zero-overall-fixed path

```python
except Exception as exc:  # noqa: BLE001
    logger.error("%s compute() failed: %s", self._log_prefix(), exc, exc_info=True)
    return self._empty_result(str(exc), config)
```

---

### 4. `build_rag_strip_entry` — CONTRACT-03 strip cell
**Source:** `reports/modules/rag_utils.py` lines 124–163
**Apply to:** compute() RAG strip assembly, `render_rag_strip_entry()`

```python
rag_strip = build_rag_strip_entry(
    display_name       = self.DISPLAY_NAME,
    headline_value_str = "14.3d",   # pre-formatted by module
    status             = "green",   # "green"|"yellow"|"red"|"no_data"
)
```

---

### 5. pandas CoW compliance — `.assign()` only after filter
**Source:** CONTEXT.md `Established Patterns` + RESEARCH.md Open Item 3 (Pitfall 9)
**Apply to:** every column mutation in `mttr_trend_module.py` and the new compute block in `capture_trend_snapshot.py`

```python
# COMPLIANT — .assign() returns a new DataFrame:
fixed_df = fixed_df.assign(days_to_fix=date_diff_days)

# FORBIDDEN — direct mutation after filter raises ChainedAssignmentError:
fixed_df["days_to_fix"] = date_diff_days
```

---

### 6. Fail-soft fetch + WR-03 exit pattern
**Source:** `scripts/capture_trend_snapshot.py` lines 286–329
**Apply to:** MTTR aggregate computation block in `capture_trend_snapshot.py`

```python
# Fail-soft: MTTR failure must not abort severity snapshot (mirrors fixed_vulns_df pattern lines 286–294)
mttr_overall_days = mttr_by_severity = mttr_by_owner = None
try:
    # ... compute MTTR aggregate ...
except Exception as exc:  # noqa: BLE001
    logger.warning("MTTR aggregate computation failed — fields will cold-start: %s", exc)
    # mttr_* remain None; capture_snapshot stores explicit nulls per D-16-09
```

---

### 7. Implicit optional-field convention (D-16-09 = D-15-06 repeat)
**Source:** `data/trend_store.py` lines 358–370 (Phase 15 field additions)
**Apply to:** `capture_snapshot()` new kwargs + `new_entry` dict

Store explicit `None` (not omit the key). `snap.get("mttr_overall_days")` then returns `None` unambiguously on both old and new snapshots. Never `snap["mttr_overall_days"]` — raises `KeyError` on old snapshots.

---

### 8. `render_email_panel` (CONTRACT-01) — not `render_email_kpis`
**Source:** `new_vs_remediated_module.py` lines 658–704; `base.py` lines 330–369
**Apply to:** `mttr_trend_module.py` email output

New v1.4 modules implement `render_email_panel`, not `render_email_kpis`. The legacy `render_email_kpis` is still on `mttr_by_severity_module.py` (untouched). The new module follows `new_vs_remediated` — inline CSS only, cold-start branch, no `<style>` blocks.

---

## No Analog Found

All six Phase 16 files have close analogs. No new patterns without precedent in the codebase.

---

## Metadata

**Analog search scope:** `reports/modules/`, `data/`, `scripts/`, `tests/`
**Files read:** `mttr_by_severity_module.py`, `new_vs_remediated_module.py`, `data/trend_store.py`, `scripts/capture_trend_snapshot.py`, `reports/composed_report.py`, `reports/modules/base.py`, `reports/modules/format_utils.py`, `reports/modules/rag_utils.py`, `reports/modules/board_report_utils.py`, `tests/test_new_vs_remediated_module.py`
**Pattern extraction date:** 2026-06-12
