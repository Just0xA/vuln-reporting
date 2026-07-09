# Phase 17: Program Health Overview - Pattern Map

**Mapped:** 2026-06-12
**Files analyzed:** 5 (2 new, 3 modified)
**Analogs found:** 5 / 5 (every file has an exact or strong analog already in-repo)

> This is a "thin-consumer module + 3-touch-point integration" phase. There is
> nothing structurally novel here — `program_health_module.py` is a near-clone of
> `mttr_trend_module.py`'s four-channel shape, and the three integration edits
> repeat the exact Phase 15/16 snapshot-extension + frozenset-gate pattern. The
> planner should copy aggressively from the cited line ranges, not invent.

---

## File Classification

| New/Modified File | New/Mod | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|---------|------|-----------|----------------|---------------|
| `reports/modules/program_health_module.py` | NEW | metric module (four-channel) | transform / read-aggregate (MoM derive) | `reports/modules/mttr_trend_module.py` | exact (role + data flow) |
| `data/trend_store.py` | MOD | data/storage (snapshot writer) | persistence / CRUD-append | self (Phase 16 block, lines 235–239 / 386–391) | exact (same function, prior precedent) |
| `scripts/capture_trend_snapshot.py` | MOD | batch/cron compute+write | batch / transform→persist | self (MTTR block, lines 300–398) | exact (same script, prior precedent) |
| `reports/composed_report.py` | MOD | orchestrator (kwargs gate) | request-response / fan-out | self (`_MODULES_NEEDING_TREND_SNAPSHOTS`, line 89) | exact (one-line frozenset add) |
| `tests/test_program_health_module.py` | NEW | test | unit | `tests/test_mttr_trend_module.py` | exact (template) |
| `tests/test_trend_store.py` | MOD | test | unit | self (append `sla_rate_crit_high` round-trip + backward-compat) | exact (existing file) |

Note: the secondary analog `new_vs_remediated_module.py` is the canonical
reference for the **cold-start path**, the **net-velocity definition (D-15-01/02)**,
and the **Owner-cut via `open_findings_at` + `extract_owner`** — copy those three
concerns from it, copy everything else (gauges→sparklines, validate_config,
metadata-driven render split) from `mttr_trend_module.py`.

---

## Pattern Assignments

### `reports/modules/program_health_module.py` (NEW — metric module, four-channel)

**Primary analog:** `reports/modules/mttr_trend_module.py` (most complete + recent four-channel reference)
**Secondary analog:** `reports/modules/new_vs_remediated_module.py` (cold-start, net-velocity defn, Owner cut)

#### Imports pattern — copy verbatim from `mttr_trend_module.py` lines 69–93

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
from reports.modules.format_utils import safe_format, safe_int, safe_pct
from reports.modules.rag_utils import (
    NO_DATA_DRIVER,
    NO_DATA_HEADLINE,
    STATUS_COLOR,
    STATUS_LABEL,
    build_rag_strip_entry,
)
from reports.modules.registry import register_module

logger = logging.getLogger(__name__)
```

Add for sparklines (UI-SPEC §Chart Channel; RESEARCH Area 4 / Assumption A2 — use
matplotlib directly, NOT `chart_utils.draw_gauge`, because trend lines ≠ gauges):

```python
import base64
import io
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
```

#### Class declaration + auto-discovery — `mttr_trend_module.py` lines 212–244

```python
@register_module
class ProgramHealthModule(BaseModule):
    MODULE_ID         = "program_health"
    DISPLAY_NAME      = "Program Health Overview"
    DESCRIPTION       = "Composite MoM RAG over 4 velocity signals with Owner velocity table."
    REQUIRED_DATA     = ["vulns", "assets", "trend_snapshots"]
    SUPPORTED_OUTPUTS = ["pdf", "excel", "email"]
    VERSION           = "1.0.0"
```

`@register_module` self-registers on import (CLAUDE.md "Module anatomy"); naming
`*_module.py` makes `registry.discover()` pick it up. **No `run_all.py` /
`_VALID_REPORTS` / schema edit** — it is a module, not a report slug.

#### `compute()` skeleton + cold-start guard — `new_vs_remediated_module.py` lines 208–262 + `mttr_trend_module.py` lines 280–344

The cold-start guard is the load-bearing copy (D-17-08, QUAL-01):

```python
trend_snapshots = kwargs.get("trend_snapshots")
cold_start = (
    trend_snapshots is None
    or trend_snapshots.get("insufficient_data", True)
)
if cold_start:
    return self._build_cold_start_result(config)   # Amber, per D-17-08 (see below)
snapshots: list[dict] = trend_snapshots.get("snapshots", [])
```

Wrap the whole body in `try/except Exception` → `return self._empty_result(str(exc), config)`
(`mttr_trend_module.py` lines 862–867). This is the QUAL-03 / fail-soft bar.

#### Snapshot deduplication (D-17-06 multi-snapshot-per-month) — copy VERBATIM from `mttr_trend_module.py` lines 646–651

```python
by_month: dict[str, dict] = {}
for snap in snapshots:
    m = snap.get("month", "")
    if m not in by_month or snap.get("generated_at", "") > by_month[m].get("generated_at", ""):
        by_month[m] = snap
snapshots_deduped = [by_month[m] for m in sorted(by_month)]
```

#### Signal re-derivation from snapshot fields (D-17-01/02 — definitional parity by reading stored aggregates)

All four signals read persisted snapshot fields with `.get()` (NEVER `[]` — Pitfall 4 / D-16-09):

```python
# last completed vs prior month (snapshots_deduped[-1], [-2])
curr, prev = snapshots_deduped[-1], snapshots_deduped[-2]
# Signal 1 — Open-Critical:    curr.get("critical")  vs prev.get("critical")
# Signal 2 — Net velocity:     curr.get("new_findings_count") - curr.get("fixed_findings_count")
# Signal 3 — SLA posture:      curr.get("sla_rate_crit_high")   (NEW field, D-17-04)
# Signal 4 — MTTR overall:     curr.get("mttr_overall_days")
```

Per-severity open counts live at the top level of the severity snapshot
(`trend_store.py` lines 336–341: `critical`/`high`/`medium`/`low`). `new_findings_count`
/ `fixed_findings_count` / `mttr_overall_days` are at lines 384–388.

#### OD-5 composite + per-signal direction (D-17-05/06/07) — pure functions per RESEARCH Code Examples

These are NEW pure functions (no existing analog — design from RESEARCH §3, lines 637–682).
Mirror the helper-function-at-module-top style of `mttr_trend_module.py` `_mom_direction`
(lines 194–205) and `_owner_mom_delta` (lines 179–191):

```python
def _composite_rag_od5(signal_statuses, green_min=4, amber_min=2):
    has_missing = any(s == "missing" for s in signal_statuses)
    green_count = sum(1 for s in signal_statuses if s == "green")
    raw = "green" if green_count >= green_min else ("amber" if green_count >= amber_min else "red")
    if has_missing and raw == "green":   # D-17-06 cap — structural, cannot be bypassed
        return "amber", True
    return raw, has_missing

def _signal_direction(curr, prev, higher_is_better, flat_band=0.0):
    if curr is None or prev is None:
        return "missing"
    delta = curr - prev
    if abs(delta) <= flat_band:
        return "amber"
    improved = (delta > 0) if higher_is_better else (delta < 0)
    return "green" if improved else "red"
```

`module_options` bands surface via `config.options.get(...)` exactly like
`mttr_trend_module.py` lines 359–360 (`int(config.options.get("mttr_window_days", 30))`).
Default keys per UI-SPEC §Module Options: `green_count_min=4`, `amber_count_min=2`,
`open_crit_flat_abs=5`, `sla_rate_flat_pct=2.0`, `mttr_flat_days=1.0`, `owner_outlier_pct=20.0`.

#### `_build_cold_start_result()` — copy `mttr_trend_module.py` lines 250–274 with ONE change

D-17-08 requires Amber, NOT gray "No Data". Change the strip status:

```python
rag_strip = build_rag_strip_entry(
    display_name       = self.DISPLAY_NAME,
    headline_value_str = "Trend Being Established",   # UI-SPEC RAG-strip table
    status             = "yellow",                    # D-17-08 — NOT "no_data"
)
```

(The MTTR analog returns `status="no_data"` at line 271 — that is the one
intentional divergence. RESEARCH Pitfall 1 + UI-SPEC RAG-strip table call this out.)

#### Owner velocity table (D-17-09) — `new_vs_remediated_module.py` lines 346–360 + 461–471

`extract_owner` + `open_findings_at` + map + `value_counts` is the proven Owner-cut:

```python
from utils.open_count import open_findings_at   # local import, like NvR line 348
open_df = open_findings_at(vulns_df, report_date)
enriched_assets = extract_owner(assets_df)
uuid_to_owner = dict(zip(enriched_assets["asset_uuid"], enriched_assets["owner"]))
owner_col = open_df["asset_uuid"].map(uuid_to_owner).fillna("Unassigned")
```

Scope to Crit+High before the groupby (D-17-09/D-17-03). For the MoM delta + >20%
outlier flag, read the **owner-dimension** snapshot via a direct `read_trend("owner", ...)`
inside `compute()` (RESEARCH Area 4 Option A — recommended; avoids a second kwargs gate):

```python
from data.trend_store import read_trend, _sanitise_tag_for_filename   # RESEARCH lines 700-708
tag_filter = _sanitise_tag_for_filename(
    config.options.get("tag_category"), config.options.get("tag_value"))
owner_trend = read_trend(dimension="owner", tag_filter=tag_filter, months=13)
owner_insufficient = owner_trend.get("insufficient_data", True)
```

Degrade gracefully when `owner_insufficient` (RESEARCH Pitfall 5 / UI-SPEC error table):
current-snapshot counts only, suppress MoM Delta column.

#### Four render methods — copy the channel shells from `mttr_trend_module.py`

| Channel | Copy from | Lines | Phase-17 change |
|---------|-----------|-------|-----------------|
| `render_pdf_section` | `mttr_trend_module.py` | 873–1101 | replace 4-gauge band with 4-sparkline row (UI-SPEC PDF layout); Owner table instead of focus table |
| `render_excel_tabs` | `mttr_trend_module.py` | 1107–1261 | tabs "Program Health" + "Owner Velocity" (UI-SPEC) |
| `render_email_panel` | `mttr_trend_module.py` | 1267–1338 | 4-tile KPI row + narrative; cold-start branch lines 1285–1294 copied as-is |
| `render_analyst_tabs` | `mttr_trend_module.py` | 1344–1359 | identical pass-through of `data.analyst_rows`; QUAL-05 aggregate-only |
| `render_rag_strip_entry` | `mttr_trend_module.py` | 1365–1382 | identical (honor `data.rag_strip`, fall back to gray) |

**Error/cold-start guards at the top of each renderer are mandatory and identical
across both analogs** — `if data.error: return ...` then `if data.metrics.get("cold_start"): return ...`.

#### Sparkline helper (D-17-09) — design from RESEARCH lines 363–388 (no exact analog; matplotlib+BytesIO+plt.close)

Per-signal line colors are locked (UI-SPEC §Per-Signal Sparkline): Open-Crit `#d32f2f`,
Net velocity `#1976d2`, SLA `#388e3c`, MTTR `#f57c00`. MoM arrow convention (UI-SPEC):
`▼`=improved `#388e3c`, `▲`=worsened `#d32f2f`, `—`=flat/missing `#9E9E9E`.
PDF sparkline grid: `display:table` row, 23% cell width, 1% margins — copy the
inline-block cell idiom from `mttr_trend_module.py` lines 997–1003.

#### `validate_config()` — copy `mttr_trend_module.py` lines 1388–1413

Coerce each `module_options` numeric to int/float, log WARNING + fall back to
default on bad values (Security V5 / threshold-injection mitigation). Same try/except
+ `errors.append(...)` shape.

#### `get_audit_info()` — copy `mttr_trend_module.py` lines 1419–1462

Document each signal's definition + the OD-5 rule + the D-17-06 missing cap.

#### Empty-data guard (QUAL-03) — `format_utils.py` (all four channels)

EVERY interpolated possibly-None value uses `safe_pct` / `safe_int` / `safe_format`
(`format_utils.py` lines 36–175). Inline f-string format specs on None are forbidden
(RESEARCH Pitfall 8). E.g. SLA tile: `safe_pct(sla_rate)` NOT `f"{sla_rate:.1f}%"`.

---

### `data/trend_store.py` (MODIFIED — add `sla_rate_crit_high` field)

**Analog:** self — the Phase 16 MTTR extension is the exact precedent (D-17-04 repeats it).

**Signature addition** after `mttr_by_owner` (line 238):

```python
    # ---- Phase 17 addition (D-17-04) ----
    sla_rate_crit_high: Optional[float] = None,
```

**`new_entry` dict addition** after the `mttr_by_owner` line (line 390):

```python
    "sla_rate_crit_high":  sla_rate_crit_high,
```

**Backward-compat smoke assertion** in the `__main__` block (RESEARCH lines 235–244;
`_old_snap` dict already exists at ~lines 537–543):

```python
assert _old_snap.get("sla_rate_crit_high") is None, (
    "Old snapshot must cold-start sla_rate_crit_high to None (no KeyError)"
)
```

This is the implicit-optional-field convention (D-15-06 / D-16-09): no `schema_version`,
no migration, absent → `None` → cold-start. The existing `null`-when-not-supplied pattern
is documented at `trend_store.py` lines 386–391.

---

### `scripts/capture_trend_snapshot.py` (MODIFIED — compute + pass `sla_rate_crit_high`)

**Analog:** self — the MTTR aggregate block (lines 300–385) is the exact template.

Insert a NEW fail-soft block mirroring the MTTR block's structure (RESEARCH Area 6,
lines 459–494), before the `capture_snapshot(...)` call at line 388:

```python
# ---- Phase 17: SLA-posture aggregate (D-17-04) ----
sla_rate_crit_high: Optional[float] = None
try:
    from utils.open_count import open_findings_at
    from config import SLA_DAYS
    open_df = open_findings_at(df, snapshot_date)
    ch_df = open_df[open_df["severity"].str.lower().isin({"critical", "high"})]
    if not ch_df.empty:
        snap_ts = pd.Timestamp(snapshot_date, tz="UTC")        # Pitfall 7 — match MTTR line 313
        ff_ts = pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
        days_open = (snap_ts - ff_ts).dt.days.clip(lower=0)    # local var, NOT ch_df[...]= (Pitfall 3 / CoW)
        sla_days_col = ch_df["severity"].str.lower().map(SLA_DAYS)
        within = days_open.notna() & sla_days_col.notna() & (days_open <= sla_days_col)
        sla_rate_crit_high = round(float(within.sum()) / len(ch_df) * 100, 1)
except Exception as exc:
    logger.warning("SLA-posture aggregate failed — field will cold-start: %s", exc)
    sla_rate_crit_high = None
```

Then add `sla_rate_crit_high=sla_rate_crit_high` to the `capture_snapshot(...)` kwargs
(alongside `mttr_overall_days=...` at lines 395–397). The `snapshot_date` is tz-naive
here — wrap as `pd.Timestamp(snapshot_date, tz="UTC")` exactly as the MTTR block does
at line 313 (RESEARCH Pitfall 7). Float percentage 0–100, NOT a fraction (Assumption A3).

---

### `reports/composed_report.py` (MODIFIED — one-line frozenset add)

**Analog:** self — `_MODULES_NEEDING_TREND_SNAPSHOTS` at lines 89–95.

```python
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({
    "sc4_kwargs_stub",
    "new_vs_remediated",
    "vuln_density",
    "accepted_recast",
    "mttr_trend",
    "program_health",      # Phase 17 (D-17-01) — severity trend_snapshots kwarg
})
```

That is the ONLY edit (RESEARCH Area 5). The `**composer_kwargs` fan-out at lines
219–242 already delivers `trend_snapshots` (severity dimension) to every module in
the set — no signature change. The owner-dimension snapshot for the velocity table is
read INSIDE `compute()` (Option A), so it needs no gate here. `program_health` does NOT
go in `_MODULES_NEEDING_FIXED_VULNS` (lines 73–76) — it has no `fixed_vulns_df` input
(RESEARCH Open Question 2: cold-start MTTR tile shows "—").

---

### `tests/test_program_health_module.py` (NEW) + `tests/test_trend_store.py` (MODIFIED)

**Analog:** `tests/test_mttr_trend_module.py` (lines 1–95 = the fixture template).

Copy the synthetic-fixture scaffold verbatim (QUAL-05 / RFC 5737/6761):

```python
pd.options.mode.copy_on_write = True            # line 42 — strict CoW catches Pitfall 3
_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"   # line 51
REF = datetime.datetime(2026, 6, 12, 0, 0, 0, tzinfo=timezone.utc)   # line 53
def _uuid(n): return f"{_UUID_PREFIX}{n}"       # line 61
def _make_assets(rows=None): ...                # tags="Owner=Engineering" (line 94)
```

Owner names "Engineering"/"Operations"/"Unassigned", IPs 192.0.2.x, hostnames
`*.test.invalid`. Test map (RESEARCH Validation Architecture, lines 772–784):
cold-start 0/1 snapshot → Amber; 4 green → Green; 3 green + 1 missing → Amber +
`data_incomplete`; missing signal named; SLA reopened-aware; zero-row safe-render;
analyst aggregate-only; Owner >20% outlier flag. `test_trend_store.py` gets two
APPENDED tests: `sla_rate_crit_high` round-trip + backward-compat (absent → None).

---

## Shared Patterns

### Cold-start guard (QUAL-01)
**Source:** `new_vs_remediated_module.py` lines 247–257; `mttr_trend_module.py` lines 331–354
**Apply to:** `program_health_module.py` `compute()`
Branch on `trend_snapshots is None or .get("insufficient_data", True)`. Phase-17 twist:
return **Amber** (`status="yellow"`), not gray — the module HAS data, just no MoM direction (D-17-08).

### Empty-data / None-safe formatting (QUAL-03)
**Source:** `reports/modules/format_utils.py` lines 36–175 (`safe_pct`/`safe_int`/`safe_format`)
**Apply to:** all four render methods of `program_health_module.py`
Never inline-format a possibly-None value. Caught at code review per CLAUDE.md.

### RAG strip cell (CONTRACT-03)
**Source:** `reports/modules/rag_utils.py` lines 124–163 (`build_rag_strip_entry`); `STATUS_COLOR`/`STATUS_LABEL` lines 42–55
**Apply to:** `program_health_module.py` compute() + `render_rag_strip_entry`
Composite key uses `"yellow"` internally → `STATUS_COLOR["yellow"] = "#f57c00"`.
Do NOT use `#fbc02d` (that's Medium severity) for amber (UI-SPEC §Color note).

### Reopened-aware open predicate (QUAL-02)
**Source:** `utils/open_count.py` `open_findings_at()` lines 19–114
**Apply to:** SLA-posture numerator/denominator AND Owner velocity counts (both module + capture script)
Naive single-interval filter drops ~19% of REOPENED findings — never hand-roll (RESEARCH Don't-Hand-Roll).

### Owner dimension extraction
**Source:** `reports/modules/board_report_utils.py` `extract_owner()` lines 214–305
**Apply to:** Owner velocity table in `program_health_module.py`
`.map(uuid_to_owner).fillna("Unassigned")` is the catch-all idiom (NvR line 356).

### Authoritative SLA targets
**Source:** `config.py` `SLA_DAYS` lines 28–33 (Critical=15, High=30, Medium=60, Low=120)
**Apply to:** SLA-posture computation (module + capture script)
Read from config — never hardcode (MEMORY: `SLA_DAYS in config.py is authoritative`; CLAUDE.md table is stale).

### pandas CoW compliance (QUAL-03 / Pitfall 3)
**Source:** `mttr_trend_module.py` line 447; `capture_trend_snapshot.py` lines 340–344
**Apply to:** every filtered-frame mutation in module + capture script
Use `.assign()` only; assign intermediate series to LOCAL variables, never `df["col"]=` after a filter.

### `module_options`-overridable defaults (D-15-07 pattern)
**Source:** `mttr_trend_module.py` lines 359–360 (read), 1388–1413 (validate)
**Apply to:** OD-5 bands + per-signal flat bands + owner outlier % in `program_health_module.py`
`int(config.options.get("key", default))` to read; `validate_config()` to guard.

### Implicit optional snapshot field (D-15-06 / D-16-09)
**Source:** `trend_store.py` lines 386–391 (null-when-not-supplied); consumed via `snap.get(...)`
**Apply to:** new `sla_rate_crit_high` field; module reads `snap.get("sla_rate_crit_high")`
No `schema_version`, no migration — absent → None → cold-start (RESEARCH Pitfall 4).

---

## No Analog Found

All files have strong in-repo analogs. Two **sub-components** have no direct
copy-source and are designed from RESEARCH (still low-risk, pure functions):

| Component (within `program_health_module.py`) | Why no analog | Source to use |
|------------------------------------------------|---------------|---------------|
| `_composite_rag_od5()` OD-5 rule | No composite-of-signals helper exists yet | RESEARCH §3 Code Examples (lines 637–662) |
| `_signal_direction()` per-signal MoM coloring | Closest is `_mom_direction` (single metric), not generalized | RESEARCH §3 (lines 664–682); mirror `mttr_trend_module.py` lines 194–205 |
| `_render_sparkline_b64()` matplotlib sparkline | Existing chart helper is `draw_gauge` (gauges ≠ trend lines) | RESEARCH Area 4 (lines 363–388); Agg + BytesIO + `plt.close` |

---

## Metadata

**Analog search scope:** `reports/modules/`, `data/`, `scripts/`, `utils/`, `config.py`, `tests/`
**Files read for extraction:** `mttr_trend_module.py`, `new_vs_remediated_module.py`,
`base.py`, `rag_utils.py`, `format_utils.py`, `open_count.py`, `trend_store.py`
(capture_snapshot + new_entry), `composed_report.py` (frozensets + kwargs fan-out),
`capture_trend_snapshot.py` (MTTR aggregate block), `board_report_utils.py` (extract_owner),
`config.py` (SLA_DAYS + SEVERITY_COLORS), `sla_calculator.py` (get_sla_status signature),
`test_mttr_trend_module.py` (fixture template)
**Pattern extraction date:** 2026-06-12
