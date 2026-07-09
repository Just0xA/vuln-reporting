# Phase 17: Program Health Overview — Research

**Researched:** 2026-06-12
**Domain:** Four-channel metric module — composite MoM velocity dashboard (trend substrate consumer)
**Confidence:** HIGH — all claims verified from live codebase; no third-party libraries needed

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-17-01:** Re-derive all four signals from the shared substrate. `program_health.compute()` reads the same S1 `read_trend()` snapshots + current `vulns_df`/`assets_df` the other modules consume. **No composer change** — independent-module contract preserved.
- **D-17-02:** Definition parity is a correctness bar. Net-velocity MUST match D-15-01/02 (inflow = first_found OR resurfaced_date in month M, exclusive); MTTR MUST match D-16-02 (COALESCE(resurfaced_date, first_found), sample-weighted rolling-30 flat mean). Shared helper OR definitionally-identical re-derivation — planner's call.
- **D-17-03:** SLA signal = "% of open Critical+High findings within SLA" (posture, not remediation rate). Uses `open_findings_at()` (QUAL-02) + `get_sla_status()`. Critical+High only.
- **D-17-04:** Persist a new forward-accumulating SLA-posture aggregate into S1 snapshot store. Extend `capture_snapshot()` + `capture_trend_snapshot.py`. Backward-compatible implicit-optional-field convention (absent → cold-start, no schema_version).
- **D-17-05:** Green-count OD-5 rule: Green = all 4 signals green; Amber = 2–3 green; Red = 0–1 green. Shipped as `module_options`-overridable default (D-15-07 pattern).
- **D-17-06:** Missing-signal folding: any unavailable signal (cold-start MoM delta OR upstream compute error) caps composite at Amber "data incomplete"; available signals still count toward green tally. Email panel + PDF name missing signals explicitly.
- **D-17-07:** Each signal colored by MoM direction: improved = green, flat = amber, worsened = red. "Flat" band thresholds ship as `module_options` defaults.
- **D-17-08:** Cold-start coherence: 1 snapshot → all 4 signals "missing" → composite Amber "data being established" + current-value tiles. Never a crash or NaN%.
- **D-17-09:** PDF layout = sparkline row (4 mini trend sparklines, current value + MoM arrow) + Owner velocity table (MoM delta on open Crit+High; owners with >20% MoM rise flagged as outliers). Sparklines via matplotlib.

### Claude's Discretion

- Exact new snapshot field name + JSON shape for SLA-posture aggregate (per-Owner SLA persistence is optional — not required by criterion 4).
- Whether D-17-02 parity is via shared helper or definitionally-identical re-derivation.
- Default numeric "flat" bands per signal (D-17-07) and composite bands (D-17-05) surfaced as `module_options`.
- Email 4-tile wording, narrative generation, sparkline styling, Excel tab column order, analyst-tab layout, cold-start/missing-signal disclosure copy.
- Multiple-snapshots-in-one-month tie-break (latest wins, consistent with D-16-08).

### Deferred Ideas (OUT OF SCOPE)

- GEN-01 / `management_summary` migration — Phase 18.
- Per-Owner SLA posture in snapshots — future enrichment.
- Absolute-level / hybrid signal RAG — rejected in favor of MoM-direction.
- Red-dominates composite override — rejected for plain green-count.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RPT-07 | Program Health Overview one-pager composing New-vs-Remediated velocity, MTTR, and SLA posture into a composite RAG with Owner velocity table; cold-start-safe. | All four signals derived from existing S1 substrate + one new persisted field; full four-channel render contract modeled on `new_vs_remediated_module` + `mttr_trend_module`; OD-5 rule locked |
| QUAL-01 | Every MoM module branches on `insufficient_data` cold-start signal — never NaN% or crash. | Cold-start Amber branch (D-17-08): all signals missing → composite Amber + current-value tiles |
| QUAL-02 | Reopened-aware two-interval predicate via `open_findings_at()`. | SLA posture computation uses `open_findings_at()` for numerator/denominator population |
| QUAL-03 | Safe render on zero-row input across all four channels (`safe_pct`/`safe_int`/`safe_format`, `_empty_result()`). | Same pattern as Phase 15/16 modules; empty-data guard mandatory on all branches |
| QUAL-05 | Aggregate counts only — no hostnames, IPs, plugin names, or asset-level fields in committed artifacts. | Test fixtures use RFC 5737/6761 synthetic data; snapshot field stores only a float ratio |

</phase_requirements>

---

## Summary

Phase 17 ships one new four-channel metric module, `program_health`, as a self-contained thin consumer of the existing S1 (trend) + S2 (Owner) substrates. It stitches four MoM velocity signals — Open-Critical MoM delta, net-velocity (inflow − outflow), SLA posture (% open Crit+High within SLA), and MTTR overall — into one composite RAG headline ("on track / at risk / off track") governed by the OD-5 green-count rule.

The module is structurally identical to `new_vs_remediated_module` and `mttr_trend_module` — the proven Phase 15/16 templates — with two additions: (1) a new persisted snapshot field for SLA-posture MoM, and (2) a sparkline PDF row plus Owner velocity table as the PDF layout. Three integration touch-points exist: `data/trend_store.py` (new parameter), `scripts/capture_trend_snapshot.py` (compute + pass), and `reports/composed_report.py` (add to `_MODULES_NEEDING_TREND_SNAPSHOTS`). No new dependencies, no schema version, no `run_all.py` registration.

Cold-start is structurally Amber here: because every signal is MoM-direction-colored (D-17-07), the first-snapshot state has no directions, so all four signals are "missing" (D-17-06) and the composite is Amber "data being established" (D-17-08). This is not a failure path — it is a normal first-month operational state that must be encoded as an explicit acceptance test, not an afterthought.

**Primary recommendation:** Model `program_health_module.py` directly on `mttr_trend_module.py` (the most recent and complete four-channel reference). The snapshot extension follows the exact Phase 16 pattern at `trend_store.py` lines 235–239 and 386–391. The OD-5 composite is a small pure function that takes four signal statuses and returns green/amber/red.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Signal derivation (net velocity, MTTR, open-crit delta) | API / Backend (module compute) | — | Re-derives from S1 snapshots already fetched by composed_report; no new fetch |
| SLA posture computation | API / Backend (module compute) | — | `open_findings_at()` + `get_sla_status()` on live `vulns_df`; pure compute |
| SLA posture MoM persistence | Data / Storage (trend_store) | — | New forward-accumulating snapshot field; written by capture script |
| Composite RAG + per-signal coloring | API / Backend (module compute) | — | OD-5 rule + missing-signal folding is compute-layer logic, not render-layer |
| PDF sparkline row | Frontend Server (render) | — | matplotlib in `render_pdf_section`; base64 embed |
| Owner velocity table | Frontend Server (render) | — | `extract_owner()` + open-count groupby; rendered in PDF + Excel + analyst tab |
| Email 4-tile KPI row | Frontend Server (render) | — | `render_email_panel()` CONTRACT-01 |
| Analyst drill-down tabs | Frontend Server (render) | — | `render_analyst_tabs()` CONTRACT-02; per-Owner MoM aggregate (QUAL-05) |
| Trend-snapshots kwargs gate | API / Backend (composed_report) | — | Add `program_health` to `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset |

---

## Standard Stack

No new packages. All tools are existing project dependencies.

### Core (all `[VERIFIED: live codebase]`)

| Library | Where | Purpose in Phase 17 |
|---------|-------|----------------------|
| `pandas` 2.x (CoW) | `program_health_module.py` | DataFrame operations; `.assign()` only, never `df["col"]=` after filter |
| `matplotlib` (Agg) | `render_pdf_section` sparklines | 4 mini trend sparklines via `reports.modules.chart_utils.draw_gauge` pattern |
| `openpyxl` | `render_excel_tabs` | Excel workbook tab writing |
| `utils.open_count.open_findings_at` | `compute()` | Reopened-aware open predicate for SLA posture numerator/denominator |
| `utils.sla_calculator.get_sla_status` | `compute()` | Within/over-SLA per finding |
| `config.SLA_DAYS` | `compute()` | Authoritative per-severity SLA targets (Critical=15, High=30, Medium=60, Low=120) |
| `data.trend_store.read_trend` | kwargs from `composed_report` | S1 snapshot reader |
| `data.trend_store.capture_snapshot` | `capture_trend_snapshot.py` | S1 snapshot writer (extended with new field) |
| `reports.modules.board_report_utils.extract_owner` | `compute()` | Owner velocity table dimension |
| `reports.modules.format_utils` | all render methods | `safe_pct`, `safe_int`, `safe_format` |
| `reports.modules.rag_utils` | `compute()` + renderers | `build_rag_strip_entry`, `STATUS_COLOR`, `STATUS_LABEL` |
| `reports.modules.base.BaseModule` | class inheritance | Four-channel contract, `_empty_result()` |
| `reports.modules.registry.register_module` | class decorator | Auto-discovery |

**Installation:** None required — no new packages.

---

## Package Legitimacy Audit

Not applicable — Phase 17 installs no external packages. All dependencies are already in `requirements.txt`.

---

## Architecture Patterns

### System Architecture Diagram

```
capture_trend_snapshot.py (cron)
  │  compute sla_rate_crit_high (new)
  │  compute mttr, net velocity, open counts (existing)
  └─► capture_snapshot(df, assets_df, ..., sla_rate_crit_high=X)
           └─► trend_severity_all_assets.json  ← S1 snapshot store

composed_report.py  (run_all.py → run_report)
  │  vulns_df, assets_df   ─────────────────────────────────────────┐
  │  trend_snapshots = read_trend("severity", "all_assets", 13)     │
  │  ("program_health" in _MODULES_NEEDING_TREND_SNAPSHOTS)        │
  │                                                                  │
  └─► ReportComposer(**composer_kwargs)                             │
           └─► ProgramHealthModule.compute(                          │
                 vulns_df, assets_df, report_date, config,          │
                 trend_snapshots=trend_snapshots               ◄─────┘
               )
               │
               ├─ [cold-start: <2 snapshots]
               │    → Amber "data being established" + current-value tiles
               │
               └─ [normal path]
                    ├─ Signal 1: Open-Crit MoM delta  (snapshot critical open counts)
                    ├─ Signal 2: Net velocity          (snapshot new/fixed counts)
                    ├─ Signal 3: SLA rate delta        (snapshot sla_rate_crit_high)
                    ├─ Signal 4: MTTR overall          (snapshot mttr_overall_days)
                    │
                    ├─ Per-signal RAG (MoM direction: improved/flat/worsened)
                    ├─ Missing-signal folding (D-17-06)
                    ├─ OD-5 composite RAG (D-17-05)
                    │
                    ├─ Owner velocity table (extract_owner + open_findings_at)
                    │
                    └─► ModuleData
                          ├─ render_pdf_section       → 4 sparklines + Owner table
                          ├─ render_excel_tabs        → "Program Health" tab
                          ├─ render_email_panel       → 4-tile KPI row + narrative
                          ├─ render_analyst_tabs      → per-Owner MoM aggregate df
                          └─ render_rag_strip_entry   → composite RAG strip cell
```

### Recommended Project Structure

```
reports/modules/
└── program_health_module.py      # NEW — auto-discovered by @register_module

data/
└── trend_store.py                # MODIFIED — new sla_rate_crit_high param

scripts/
└── capture_trend_snapshot.py     # MODIFIED — compute + pass sla_rate_crit_high

reports/
└── composed_report.py            # MODIFIED — add "program_health" to frozenset

tests/
└── test_program_health_module.py # NEW — mirrors test_new_vs_remediated_module.py
```

---

## Research Area 1: trend_store.py Extension Shape (D-17-04)

### Verified existing pattern (Phase 16, lines 235–239 and 386–391)

```python
# capture_snapshot() signature extension (Phase 16 pattern at lines 235-239):
def capture_snapshot(
    ...,
    # ---- Phase 16 additions (D-16-03 / D-16-09) ----
    mttr_overall_days: Optional[float] = None,
    mttr_by_severity: Optional[dict] = None,
    mttr_by_owner: Optional[dict] = None,
) -> Path:
```

```python
# new_entry dict (lines 386-391):
new_entry: dict = {
    ...
    "mttr_overall_days":   mttr_overall_days,
    "mttr_by_severity":    mttr_by_severity,
    "mttr_by_owner":       mttr_by_owner,
    "generated_at":        generated_at_str,
}
```

### Proposed Phase 17 extension

**Field name:** `sla_rate_crit_high`
**Type:** `Optional[float]` — a percentage value 0.0–100.0 (e.g., 87.3 means 87.3% of open Crit+High findings are within SLA)
**JSON shape:** `"sla_rate_crit_high": 87.3` or `null` when computation failed

**Rationale for this shape:**
- Mirrors `mttr_overall_days` (a single float or None) — simplest backward-compatible extension
- Stores the percentage directly (not fraction) to match `safe_pct()` convention
- Absent in old snapshots → `snap.get("sla_rate_crit_high")` returns `None` → cold-start branch, no KeyError
- No per-Owner SLA in snapshot (scoped out by D-17-04; Owner table is open-count-based)

**capture_snapshot() signature addition:**

```python
# ---- Phase 17 addition (D-17-04) ----
sla_rate_crit_high: Optional[float] = None,
```

**new_entry addition (after mttr_by_owner line):**

```python
"sla_rate_crit_high":  sla_rate_crit_high,
```

**Backward-compat smoke check addition in trend_store.py `__main__` block:**

```python
# D-17-04: backward-compat cold-start assertion.
# A snapshot WITHOUT sla_rate_crit_high (pre-Phase-17) must not KeyError.
assert _old_snap.get("sla_rate_crit_high") is None, (
    "Old snapshot must cold-start sla_rate_crit_high to None (no KeyError)"
)
print("Backward-compat sla_rate_crit_high: OK")
```

**Confirmed:** `_old_snap` dict already exists in the `__main__` block (lines 537–543) — just add the assertion.

---

## Research Area 2: Definition Parity (D-17-02)

### Net velocity parity with new_vs_remediated_module

From `new_vs_remediated_module.py` compute(), the inflow definition (D-15-01/02):
- `net_new_mask = ff_ts.dt.to_period("M") == month_period` (first_found in month M)
- `resurfaced_mask = rs_in_month & ~net_new_mask` (resurfaced in M AND NOT first_found in M)
- `total_inflow = nn_count + rs_count`
- outflow = `snap.get("fixed_findings_count")` from snapshot (Option B / D-15-06)
- net delta = `total_inflow - fixed_count`

For `program_health`, net velocity signal is the last month's `net_delta`:
- Read directly from snapshot: `snap.get("new_findings_count")` and `snap.get("fixed_findings_count")`
- `net_delta = new_findings_count - fixed_findings_count` (both already persisted)

**The cleanest parity approach (D-17-02 recommendation):**
`program_health` can read `new_findings_count` and `fixed_findings_count` directly from the S1 snapshots — these are already computed by `capture_trend_snapshot.py` using the same D-15-01 definition. This is definitionally-identical re-derivation without any shared helper extraction, and it is zero-risk because the snapshot field is the canonical stored value.

Net velocity for per-signal coloring:
- `net_delta = snap["new_findings_count"] - snap["fixed_findings_count"]`
- MoM direction: compare last two snapshots' net_delta values

### MTTR parity with mttr_trend_module

From `mttr_trend_module.py` and `capture_trend_snapshot.py`, the overall MTTR is:
- `windowed["days_to_fix"].mean()` (flat sample-weighted mean, NOT mean of means)
- Clock = `COALESCE(resurfaced_date, first_found)` clipped >= 0 (D-16-02)
- Population = `state == "FIXED"` AND `last_fixed >= report_date - 30d` (D-16-01)

For `program_health`, MTTR signal reads `snap.get("mttr_overall_days")` from the snapshot — already computed with the exact D-16-02 definition. No re-derivation needed.

**Conclusion:** Both net-velocity and MTTR are re-derivable from already-persisted snapshot fields, using values that were computed by the Phase 15/16 code with the locked definitions. No shared helper extraction needed; definitionally-identical by virtue of reading the same stored aggregates. [VERIFIED: live codebase]

---

## Research Area 3: OD-5 Composite RAG Mechanics

### Per-signal coloring (D-17-07)

Each signal maps an MoM direction to a RAG status. MoM direction requires ≥2 snapshots.

| Signal | "Improved" (Green) | "Flat" (Amber) | "Worsened" (Red) | Missing |
|--------|-------------------|----------------|-----------------|---------|
| Open-Crit delta | delta < 0 (fewer open) | abs(delta) ≤ flat_band | delta > 0 | cold-start or None |
| Net velocity (net_delta MoM) | curr_delta < prev_delta (improving) | within flat_band | worsening | cold-start or None |
| SLA rate | rate increased | within flat_band % | rate decreased | cold-start or None |
| MTTR overall | MTTR decreased (lower=better) | within flat_band days | MTTR increased | cold-start or None |

**Default "flat" bands (module_options, D-17-07):**
- `open_crit_flat_pct`: 5% change (±5 findings if open count is ~100). Suggest `5` as default.
- `net_velocity_flat_pct`: 10% change in net_delta. Suggest `0` (directional only, matches new_vs_remediated).
- `sla_rate_flat_pct`: 2.0 percentage points. Suggest `2.0`.
- `mttr_flat_days`: 1.0 day. Suggest `1.0`.

These are Claude's Discretion — ship sensible defaults per the spec.

### Missing-signal folding (D-17-06)

```python
def _composite_rag(
    signal_statuses: list[str],   # "green", "amber", "red", or "missing"
    green_min: int = 4,           # module_options: all 4 green = Green
    amber_min: int = 2,           # module_options: 2–3 green = Amber
    # red = 0–1 green
) -> tuple[str, bool]:
    """
    Returns (composite_status, data_incomplete_flag).
    Any "missing" signal → data_incomplete=True → cap at Amber.
    """
    has_missing = any(s == "missing" for s in signal_statuses)
    green_count = sum(1 for s in signal_statuses if s == "green")
    
    if green_count >= green_min:
        raw = "green"
    elif green_count >= amber_min:
        raw = "amber"
    else:
        raw = "red"
    
    # D-17-06: missing caps at Amber, never Green
    if has_missing and raw == "green":
        return "amber", True
    return raw, has_missing
```

**module_options keys (D-17-05/07 pattern):**
```python
green_count_min: int = 4      # default: all 4 green = Green
amber_count_min: int = 2      # default: 2–3 green = Amber
open_crit_flat_abs: int = 5   # ±N findings for "flat" open-crit direction
sla_rate_flat_pct: float = 2.0  # ±N percentage points for "flat" SLA rate
mttr_flat_days: float = 1.0   # ±N days for "flat" MTTR direction
```

### Cold-start Amber (D-17-08)

When `trend_snapshots is None` or `insufficient_data=True` (< 2 snapshots):
- All four signals → "missing"
- `_composite_rag(["missing","missing","missing","missing"])` → ("amber", True)
- Email panel: 4 tiles show current values only (from live `vulns_df`) + cold-start notice
- PDF: current values + "Month-over-month trend being established" notice
- RAG strip: Amber "At Risk" (not "No Data" — the module has data, just no MoM direction yet)

**Critical nuance:** With exactly 1 snapshot, `insufficient_data=True` is returned by `read_trend()` (line 471: `len(recent) < 2`). The module should still display current-snapshot values (critical/high open counts, current MTTR from live `fixed_vulns_df` if available, current SLA rate from live `vulns_df`). The cold-start notice explains why MoM arrows are absent.

---

## Research Area 4: PDF Sparkline Row + Owner Velocity Table (D-17-09)

### Sparkline pattern via chart_utils.draw_gauge

`reports/modules/chart_utils.py` exposes `draw_gauge()` which returns a base64 PNG. For sparklines (mini trend lines, not gauges), the module should use `matplotlib` directly following the `chart_exporter.py` Agg backend pattern.

**Sparkline implementation approach:**

```python
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io, base64

def _render_sparkline_b64(
    values: list[Optional[float]],
    labels: list[str],
    current_val: str,
    mom_arrow: str,   # "▲", "▼", or "—"
    arrow_color: str,
    title: str,
    palette_color: str,
) -> str:
    """Return base64 PNG of a mini trend sparkline."""
    fig, ax = plt.subplots(figsize=(2.0, 1.2))
    xs = list(range(len(values)))
    ys = [v if v is not None else float("nan") for v in values]
    ax.plot(xs, ys, color=palette_color, linewidth=1.5, marker="o", markersize=3)
    ax.set_title(f"{title}\n{current_val} {mom_arrow}", fontsize=7, color=arrow_color)
    ax.axis("off")
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()
```

**Color palette (from config.py SEVERITY_COLORS, canonical):**
- Open-Crit signal: `#d32f2f` (Critical red)
- Net velocity signal: `#1976d2` (Info blue — neutral velocity)
- SLA rate signal: `#388e3c` (Green — posture indicator)
- MTTR signal: `#f57c00` (High orange — time metric)

**MoM arrow convention (consistent with mttr_trend_module D-16-13):**
- `▼` = improved (lower MTTR, lower open count, higher SLA rate, lower net delta) → green
- `▲` = worsened → red
- `—` = flat or missing → grey

### Owner velocity table (D-17-09)

**Source:** `extract_owner(assets_df)` → uuid_to_owner map → groupby on `open_findings_at(vulns_df, report_date)` for current snapshot; then compare with previous month's owner open-count from the S1 owner-dimension snapshot.

**Outlier rule:** Owner whose open count rose >20% MoM flagged as outlier.

```python
# MoM Owner velocity
# curr_owner_counts: dict[str, int] — from live open_findings_at
# prev_owner_counts: dict[str, int] — from S1 owner snapshot (dimension="owner")

def _owner_outlier(curr: int, prev: int, threshold_pct: float = 20.0) -> bool:
    if prev == 0:
        return curr > 0   # any appearance from zero is an outlier
    return (curr - prev) / prev * 100.0 > threshold_pct
```

**Important:** The owner-dimension S1 snapshot (`trend_owner_all_assets.json`) already exists and is already populated by `capture_trend_snapshot.py` (owner snapshot at lines 409–423). `program_health` can read it via `read_trend(dimension="owner", ...)`. This requires a second `read_trend()` call in `composed_report.py` — but only if `program_health` is in the modules list. The planner may choose to:

Option A: Read owner trend inside `compute()` via a direct `read_trend()` call (not via kwargs gate) — simpler, no `composed_report.py` change beyond the frozenset addition.

Option B: Add a second kwargs gate `_MODULES_NEEDING_OWNER_SNAPSHOTS` to `composed_report.py`.

**Recommendation: Option A** — direct `read_trend("owner", ...)` inside `compute()`. The trend_store read is a file read with no side effects; it is acceptable inside compute() since it is not an API call. This avoids a second kwargs gate addition and keeps the integration touch-points minimal.

**QUAL-05 constraint:** The analyst tab must be aggregate-only — per-Owner counts (open Critical+High current + MoM delta + outlier flag), never per-finding rows.

---

## Research Area 5: composed_report.py Integration

### Existing frozenset (lines 89–95)

```python
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "sc4_kwargs_stub",
    "new_vs_remediated",
    "vuln_density",
    "accepted_recast",
    "mttr_trend",          # D-16-03
})
```

**Required change:** Add `"program_health"` to this frozenset. That is the only `composed_report.py` change needed (assuming Option A above for owner snapshot — no new gate required).

**No signature change** — `**composer_kwargs` fan-out already delivers `trend_snapshots` to all modules in the set.

### Tag-category/tag-value injection pattern

`mttr_trend` has a special block at lines 315–319 that injects `tag_category`/`tag_value` into its module options. `program_health` does not need this (no focus-mode table) — no analogous block needed.

---

## Research Area 6: SLA Posture Computation in capture_trend_snapshot.py

### Pattern (mirrors MTTR block lines 301–385)

```python
# ---- Phase 17: compute SLA-posture aggregate for snapshot persistence (D-17-04) ----
# Fail-soft: a computation failure must not abort the severity snapshot.
sla_rate_crit_high: Optional[float] = None

try:
    from utils.open_count import open_findings_at  # already imported at top
    from utils.sla_calculator import get_sla_status
    from config import SLA_DAYS

    open_df = open_findings_at(df, snapshot_date)
    # D-17-03: Critical+High only
    crit_high_mask = open_df["severity"].str.lower().isin({"critical", "high"})
    ch_df = open_df[crit_high_mask]

    if not ch_df.empty:
        # Vectorized within-SLA test:
        # days_open = (snapshot_date - first_found).days, clipped >= 0
        ff_ts = pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
        snap_ts = pd.Timestamp(snapshot_date, tz="UTC") if ... else ...
        days_open = (snap_ts - ff_ts).dt.days.clip(lower=0)
        sla_days_col = ch_df["severity"].str.lower().map(SLA_DAYS)
        within_sla = (days_open <= sla_days_col) & days_open.notna() & sla_days_col.notna()
        sla_rate_crit_high = round(float(within_sla.sum()) / len(ch_df) * 100, 2)

    logger.info("SLA-posture aggregate — sla_rate_crit_high=%s", sla_rate_crit_high)
except Exception as exc:
    logger.warning(
        "SLA-posture aggregate computation failed — field will cold-start: %s", exc
    )
    sla_rate_crit_high = None
```

Then pass to `capture_snapshot(... sla_rate_crit_high=sla_rate_crit_high)`.

**Key detail:** `open_findings_at` is already imported at the top of `capture_trend_snapshot.py` (via `data.trend_store` which imports it). The SLA computation is a vectorized pandas operation — no per-row `get_sla_status()` call needed.

**Timezone note:** `snapshot_date` is tz-naive in `capture_trend_snapshot.py` (line 256/258). The MTTR block wraps it as `pd.Timestamp(snapshot_date, tz="UTC")`. The SLA computation must do the same.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Reopened-aware open count | Custom state filter | `utils.open_count.open_findings_at()` | Drops ~19% of REOPENED findings if done naively |
| Per-finding SLA test | Inline date math | `config.SLA_DAYS` + vectorized pandas | Already tested, handles info/None severity |
| RAG strip cell construction | Custom dict | `rag_utils.build_rag_strip_entry()` | CONTRACT-03 shape must match composer expectations |
| None/NaN-safe formatting | Inline f-string on possibly-None | `safe_pct`, `safe_int`, `safe_format` | f-string format specs on None crash at render time |
| Snapshot atomic write | Direct file write | `capture_snapshot()` / `_atomic_write_json()` | Atomic via temp + os.replace; corrupt-file preservation |
| Owner extraction | Custom tag parser | `board_report_utils.extract_owner()` | Handles Unassigned catch-all, dedup, Application column |
| Matplotlib Agg teardown | Custom cleanup | `plt.close(fig)` + `io.BytesIO` pattern | Memory leak if fig not closed |
| Module auto-discovery | Manual registry | `@register_module` decorator | Glob + decorator handles it; no `run_all.py` registration |

---

## Common Pitfalls

### Pitfall 1: Missing-signal vs. cold-start conflation

**What goes wrong:** Treating "0 snapshots" and "1 snapshot" the same as "signal unavailable during a normal run." Cold-start (< 2 snapshots) is a structural state; a compute error on an individual signal within a normal run (≥ 2 snapshots) is a different case.

**How to avoid:** Two separate branches. `insufficient_data=True` → D-17-08 cold-start Amber (all tiles show current values, notice explains). A per-signal None during a normal run → D-17-06 missing-signal folding (cap at Amber, name the missing signal).

**Warning signs:** The cold-start branch returning "No Data" strip instead of Amber "At Risk"; crash when a single signal is None but snapshots exist.

### Pitfall 2: Composite RAG going Green with a missing signal

**What goes wrong:** `_composite_rag` counts 3 green + 1 missing → raw "green" → returns Green. D-17-06 prohibits this.

**How to avoid:** After computing raw composite, check `has_missing`. If `has_missing and raw == "green"`, return "amber". The email panel and PDF must also name the missing signal(s).

### Pitfall 3: Pandas CoW violation in SLA posture vectorized computation

**What goes wrong:** `ch_df["days_open"] = ...` after filtering from `open_df`. Raises `ChainedAssignmentError` in pandas 3.0 strict CoW mode.

**How to avoid:** All intermediate series assigned to local variables, not back to the DataFrame. Use `.assign()` only if a new column on the filtered frame is needed. The MTTR block in `capture_trend_snapshot.py` (lines 340–344) shows the correct pattern.

### Pitfall 4: Snapshot field absent → KeyError in program_health compute

**What goes wrong:** `snap["sla_rate_crit_high"]` raises KeyError on old snapshots (pre-Phase-17). This breaks the module for any user with existing trend history.

**How to avoid:** Always `snap.get("sla_rate_crit_high")` — returns None on old snapshots → cold-start branch for the SLA signal. This is the D-16-09 / D-15-06 implicit-optional-field convention. Same pattern already in `mttr_trend_module.py`: `snap.get("mttr_overall_days")`.

### Pitfall 5: Owner snapshot not found for velocity table

**What goes wrong:** `read_trend(dimension="owner", tag_filter="all_assets")` returns `insufficient_data=True` if the owner snapshot file doesn't exist yet (e.g., operator running `program_health` before any owner snapshot has been captured).

**How to avoid:** The Owner velocity table must degrade gracefully. If `owner_trend.insufficient_data=True`, fall back to current-snapshot-only owner counts (from live `open_findings_at`), suppress the MoM delta column, and note "Owner MoM trend being established." Do not crash or omit the table entirely.

### Pitfall 6: Multiple snapshots in same calendar month (D-16-08 pattern)

**What goes wrong:** If `capture_trend_snapshot.py` is run twice in the same month, `read_trend()` returns two entries with the same `month` key. The MoM calculation treats them as two separate months.

**How to avoid:** Deduplicate by calendar month before building series — take the latest `generated_at` per month. This is the same pattern as `mttr_trend_module.py` lines 647–651:
```python
by_month: dict[str, dict] = {}
for snap in snapshots:
    m = snap.get("month", "")
    if m not in by_month or snap.get("generated_at", "") > by_month[m].get("generated_at", ""):
        by_month[m] = snap
snapshots_deduped = [by_month[m] for m in sorted(by_month)]
```

### Pitfall 7: tz-naive snapshot_date in SLA vectorized computation

**What goes wrong:** `pd.Timestamp(snapshot_date) - ff_ts` where `ff_ts` is `datetime64[ns, UTC]` and `snapshot_date` is tz-naive raises TypeError in pandas.

**How to avoid:** `snap_ts = pd.Timestamp(snapshot_date, tz="UTC")` — same pattern as MTTR block in `capture_trend_snapshot.py` line 313.

### Pitfall 8: render_email_panel returning 4 tiles with NaN%

**What goes wrong:** A signal that has a current value but no MoM direction renders as `NaN%` because the format spec is applied to None.

**How to avoid:** Mandatory `safe_pct`/`safe_int`/`safe_format` for every value. Current-value tiles in cold-start state must use `safe_pct(current_sla_rate)` not `f"{current_sla_rate:.1f}%"`.

---

## Code Examples

### SLA posture computation (D-17-03) — vectorized pattern

```python
# Source: verified from open_findings_at() + SLA_DAYS usage pattern in codebase
from utils.open_count import open_findings_at
from config import SLA_DAYS

open_df = open_findings_at(vulns_df, report_date)
ch_mask = open_df["severity"].str.lower().isin({"critical", "high"})
ch_df = open_df[ch_mask]

sla_rate_crit_high: Optional[float] = None
if not ch_df.empty:
    report_ts = (
        pd.Timestamp(report_date)
        if pd.Timestamp(report_date).tzinfo is not None
        else pd.Timestamp(report_date, tz="UTC")
    )
    ff_ts = pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
    days_open = (report_ts - ff_ts).dt.days.clip(lower=0)
    sla_days_col = ch_df["severity"].str.lower().map(SLA_DAYS)
    within_sla_mask = (
        days_open.notna() & sla_days_col.notna() & (days_open <= sla_days_col)
    )
    sla_rate_crit_high = round(float(within_sla_mask.sum()) / len(ch_df) * 100, 1)
```

### Cold-start result (D-17-08) — mirrors new_vs_remediated pattern

```python
# Source: new_vs_remediated_module.py _build_cold_start_result() + D-17-08
def _build_cold_start_result(self, config: ModuleConfig) -> ModuleData:
    # Current-value tiles can still be computed from live vulns_df if ≥1 snapshot.
    # For the pure "no snapshots at all" case, all tiles show "—".
    return ModuleData(
        module_id        = self.MODULE_ID,
        display_name     = self.DISPLAY_NAME,
        metrics          = {
            "cold_start": True,
            "composite_rag": "amber",
            "data_incomplete": True,
            # current values populated by caller if available
        },
        table_data       = [],
        chart_data       = {},
        summary_text     = "Program health trend being established — available from next month.",
        metadata         = {"cold_start": True},
        driver_narrative = "Trend data being established.",
        analyst_rows     = [],
        rag_strip        = build_rag_strip_entry(
            display_name       = self.DISPLAY_NAME,
            headline_value_str = "Amber",
            status             = "yellow",   # Amber per D-17-08
        ),
        error            = None,
    )
```

### OD-5 composite RAG (D-17-05/06)

```python
# Source: designed from D-17-05/06 spec; pure function pattern
def _composite_rag_od5(
    signal_statuses: list[str],    # each: "green", "amber", "red", or "missing"
    green_min: int = 4,
    amber_min: int = 2,
) -> tuple[str, bool]:
    """
    Returns (composite_status, data_incomplete).
    composite_status in {"green", "amber", "red"}.
    D-17-06: any missing signal → data_incomplete=True → cap at Amber.
    """
    has_missing = any(s == "missing" for s in signal_statuses)
    green_count = sum(1 for s in signal_statuses if s == "green")
    if green_count >= green_min:
        raw = "green"
    elif green_count >= amber_min:
        raw = "amber"
    else:
        raw = "red"
    if has_missing and raw == "green":
        return "amber", True
    return raw, has_missing
```

### Per-signal MoM direction coloring (D-17-07)

```python
# Source: designed from D-17-07 spec; mirrors mttr_trend _mom_direction pattern
def _signal_direction(
    curr: Optional[float],
    prev: Optional[float],
    higher_is_better: bool,
    flat_band: float = 0.0,  # overridable per signal via module_options
) -> str:
    """Returns "green", "amber", "red", or "missing"."""
    if curr is None or prev is None:
        return "missing"
    delta = curr - prev
    if abs(delta) <= flat_band:
        return "amber"
    improved = delta < 0 if not higher_is_better else delta > 0
    return "green" if improved else "red"
```

### Snapshot deduplication (D-16-08 pattern — required for sparklines)

```python
# Source: mttr_trend_module.py lines 647-651 — copy verbatim
by_month: dict[str, dict] = {}
for snap in snapshots:
    m = snap.get("month", "")
    if m not in by_month or snap.get("generated_at", "") > by_month[m].get("generated_at", ""):
        by_month[m] = snap
snapshots_deduped = [by_month[m] for m in sorted(by_month)]
```

### Reading owner snapshot for Owner velocity table

```python
# Source: data/trend_store.read_trend() signature (verified)
from data.trend_store import read_trend, _sanitise_tag_for_filename

tag_filter = _sanitise_tag_for_filename(
    config.options.get("tag_category"),
    config.options.get("tag_value"),
)
owner_trend = read_trend(dimension="owner", tag_filter=tag_filter, months=13)
owner_insufficient = owner_trend.get("insufficient_data", True)
owner_snapshots = owner_trend.get("snapshots", []) if not owner_insufficient else []
```

---

## State of the Art

| Old Approach | Current Approach | Phase | Impact |
|--------------|------------------|-------|--------|
| Per-module email KPI tiles (legacy) | `render_email_panel` CONTRACT-01 modular panels | Phase 1/2 | `program_health` uses CONTRACT-01 |
| Hardcoded thresholds | `module_options`-overridable defaults (D-15-07) | Phase 15 | OD-5 bands exposed as `module_options` |
| Single snapshot = sufficient | `insufficient_data: len < 2` gate in `read_trend()` | Phase 12 | Cold-start must check `insufficient_data` first |
| Naive MTTR (time_taken_to_fix) | COALESCE(resurfaced_date, first_found) D-16-02 | Phase 16 | MTTR read from snapshot with correct clock |
| Schema version for snapshot evolution | Implicit optional fields (absent → None) | Phase 15/16 | No migration needed for new SLA field |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Owner velocity table reads `trend_owner_all_assets.json` via `read_trend(dimension="owner")` inside `compute()` directly (Option A) | Research Area 4 | If owner snapshot is not being written by all operator deployments, the table degrades to current-only — acceptable |
| A2 | Sparklines use `matplotlib` directly (not `chart_utils.draw_gauge`) since trend lines ≠ gauges | Research Area 4 | If chart_utils is extended with a sparkline helper before Phase 17 ships, use that instead |
| A3 | `sla_rate_crit_high` persisted as a float percentage (0–100) not a fraction (0–1) | Research Area 1 | If convention changes, `safe_pct()` call needs adjustment |

**All three are low-risk; the first two are Claude's Discretion per CONTEXT.md.**

---

## Open Questions

1. **Net velocity "MoM direction" definition**
   - What we know: Net velocity is `new_findings_count - fixed_findings_count` per snapshot. MoM direction should compare the current month's net_delta to the prior month's.
   - What's unclear: Is "improved" defined as "net_delta decreased" (fewer new than last month) or "net_delta went negative" (backlog shrinking)? The former is safer (relative improvement even if backlog is still growing).
   - Recommendation: Use "delta of deltas" — if `curr_net_delta < prev_net_delta`, the trend is improving (green). This is Claude's Discretion per D-17-02; document in the module docstring.

2. **Current-value tiles during cold-start (D-17-08)**
   - What we know: Cold-start shows "current values only + cold-start notice."
   - What's unclear: For MTTR and SLA rate, "current value" requires computing from live `vulns_df`/`fixed_vulns_df`. But `program_health` is NOT in `_MODULES_NEEDING_FIXED_VULNS`, so no `fixed_vulns_df` is available.
   - Recommendation: Current MTTR tile during cold-start shows "—" (cannot compute without fixed_vulns_df). Current SLA rate IS computable from live `vulns_df` via `open_findings_at`. Current open-crit and net-velocity counts are computable from `vulns_df`. Document this explicitly in the module.

---

## Environment Availability

Phase 17 is purely code/config changes. No external dependencies beyond the existing project stack. Skipped.

---

## Validation Architecture

`workflow.nyquist_validation` is `true` in `.planning/config.json` — section included.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (verified: `pytest.ini` present, `test_new_vs_remediated_module.py` and `test_mttr_trend_module.py` exist as templates) |
| Config file | `pytest.ini` (existing) |
| Quick run command | `pytest tests/test_program_health_module.py -x -q` |
| Full suite command | `pytest tests/test_program_health_module.py tests/test_trend_store.py -x -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RPT-07 / QUAL-01 | Cold-start: 0 snapshots → Amber composite, no crash | unit | `pytest tests/test_program_health_module.py::test_cold_start_no_snapshots -x` | ❌ Wave 0 |
| RPT-07 / QUAL-01 | Cold-start: 1 snapshot → Amber composite, current-value tiles | unit | `pytest tests/test_program_health_module.py::test_cold_start_one_snapshot -x` | ❌ Wave 0 |
| RPT-07 / D-17-05 | 4 green signals → Green composite | unit | `pytest tests/test_program_health_module.py::test_composite_all_green -x` | ❌ Wave 0 |
| RPT-07 / D-17-06 | 3 green + 1 missing → Amber, data_incomplete=True | unit | `pytest tests/test_program_health_module.py::test_composite_missing_caps_amber -x` | ❌ Wave 0 |
| RPT-07 / D-17-06 | Missing signal named in email panel + PDF | unit | `pytest tests/test_program_health_module.py::test_missing_signal_named -x` | ❌ Wave 0 |
| QUAL-02 | SLA posture uses open_findings_at (REOPENED not dropped) | unit | `pytest tests/test_program_health_module.py::test_sla_rate_reopened_aware -x` | ❌ Wave 0 |
| QUAL-03 | Zero-row vulns_df → safe render all four channels | unit | `pytest tests/test_program_health_module.py::test_empty_data_guard -x` | ❌ Wave 0 |
| QUAL-05 | Analyst tabs contain only aggregate counts, no hostnames/IPs | unit | `pytest tests/test_program_health_module.py::test_analyst_tabs_aggregate_only -x` | ❌ Wave 0 |
| D-17-04 | Snapshot round-trip: sla_rate_crit_high persisted + read back | unit | `pytest tests/test_trend_store.py::test_sla_rate_crit_high_roundtrip -x` | ❌ Wave 0 |
| D-17-04 | Old snapshot (no sla_rate_crit_high) → None, no KeyError | unit | `pytest tests/test_trend_store.py::test_sla_rate_backward_compat -x` | ❌ Wave 0 |
| D-17-09 | Owner >20% MoM rise → outlier flag in analyst tab | unit | `pytest tests/test_program_health_module.py::test_owner_outlier_flagging -x` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest tests/test_program_health_module.py -x -q`
- **Per wave merge:** `pytest tests/test_program_health_module.py tests/test_trend_store.py -x -q`
- **Phase gate:** Full suite per `pytest.ini` scoped tests green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `tests/test_program_health_module.py` — covers all RPT-07 + QUAL-01/02/03/05 tests above
- [ ] Synthetic fixture helpers — RFC 5737 IPs (192.0.2.x), RFC 6761 hostnames (test.invalid), uuid prefix `00000000-0000-0000-0000-00000000000N`, owner names "Engineering"/"Operations"/"Unassigned" (mirrors `test_new_vs_remediated_module.py` pattern)
- [ ] `tests/test_trend_store.py` additions — `test_sla_rate_crit_high_roundtrip` and `test_sla_rate_backward_compat` (appended to existing file, not new file)

---

## Security Domain

`security_enforcement: true` in `.planning/config.json`, `security_asvs_level: 1`.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Not applicable — no new auth surface |
| V3 Session Management | No | Not applicable |
| V4 Access Control | No | Delivery access controlled by existing SMTP/group config |
| V5 Input Validation | Yes | `module_options` values validated via `validate_config()`; snapshot field values are aggregate floats only |
| V6 Cryptography | No | No new crypto |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| PII in snapshot file (hostnames, IPs, plugin names) | Information Disclosure | QUAL-05: only aggregate float stored (`sla_rate_crit_high`); no per-finding data |
| PII in analyst tabs | Information Disclosure | QUAL-05: analyst tabs contain per-Owner aggregate counts only (owner tag name, open count, MoM delta) — no asset UUIDs, hostnames, or plugin IDs |
| module_options injection (malformed threshold values) | Tampering | `validate_config()` must coerce to int/float and log WARNING on bad values; fallback to defaults (mirrors `mttr_trend_module.validate_config()` pattern) |
| Cold-start bypass (forced Green without data) | Tampering | D-17-06 cap: missing signals → Amber cap enforced in `_composite_rag_od5()`; cannot be bypassed via `module_options` (the cap is structural) |

---

## Sources

### Primary (HIGH confidence — verified from live codebase)

- `reports/modules/new_vs_remediated_module.py` — inflow definition (D-15-01/02), cold-start pattern, four-channel template
- `reports/modules/mttr_trend_module.py` — MTTR definition (D-16-02), MoM direction pattern, validate_config pattern, deduplication pattern (D-16-08)
- `data/trend_store.py` — `capture_snapshot()` extension shape (Phase 16 block lines 235–391), `read_trend()` `insufficient_data` contract
- `scripts/capture_trend_snapshot.py` — MTTR aggregate computation block (lines 301–385) — template for SLA aggregate
- `reports/composed_report.py` — `_MODULES_NEEDING_TREND_SNAPSHOTS` frozenset (lines 89–95), tag injection pattern (lines 315–319)
- `utils/open_count.py` — `open_findings_at()` two-interval reopened-aware predicate
- `utils/sla_calculator.py` — `get_sla_status()` per-finding SLA test; `SLA_DAYS` from `config.py`
- `config.py` — `SLA_DAYS = {"critical": 15, "high": 30, "medium": 60, "low": 120}` (authoritative)
- `reports/modules/base.py` — `_empty_result()`, `ModuleData`, `ModuleConfig`, four-channel contract
- `reports/modules/format_utils.py` — `safe_pct`, `safe_int`, `safe_format`
- `reports/modules/rag_utils.py` — `build_rag_strip_entry`, `STATUS_COLOR`, `STATUS_LABEL`
- `reports/modules/board_report_utils.py` — `extract_owner()` Owner velocity table dimension
- `tests/test_new_vs_remediated_module.py` — synthetic fixture pattern (UUID prefix, RFC names, CoW strict mode)
- `.planning/config.json` — `nyquist_validation: true`, `security_enforcement: true`

### Secondary (MEDIUM confidence)

- `reports/modules/chart_utils.py` — `draw_gauge()` pattern for base64 PNG embedding; sparkline will follow same Agg+BytesIO pattern
- `reports/modules/critical_remediation_sla_module.py` — SLA within/over test pattern (adapted for posture vs. remediation-rate)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all existing dependencies; no new packages
- Architecture: HIGH — all integration points verified from live files
- Pitfalls: HIGH — all based on observed patterns and Phase 15/16 post-mortems (CoW, tz, KeyError)
- OD-5 mechanics: HIGH — locked decisions; pure function; no external dependencies
- Snapshot field shape: HIGH — mirrors Phase 16 extension exactly

**Research date:** 2026-06-12
**Valid until:** 2026-07-12 (stable — no external dependencies; codebase is the authoritative source)
