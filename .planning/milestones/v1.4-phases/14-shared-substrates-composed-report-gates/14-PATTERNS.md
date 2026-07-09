# Phase 14: Shared Substrates + composed_report Gates — Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 5 (2 new utils, 1 new constant block in config.py, 1 modified composed_report.py, 1 new stub module)
**Analogs found:** 5 / 5

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `utils/external_scope.py` | utility | transform | `reports/modules/board_report_utils.py` `extract_owner()` + `_parse_tags` (lines 214–307) + `identify_on_time_assets()` tuple shape (lines 135–207) | exact |
| `utils/asset_count.py` | utility | transform | `utils/open_count.py` (pure compute, no I/O, injected date, zero-row guard, stdlib only) | exact |
| `config.py` — `ON_TIME_SCAN_WINDOW_DAYS` constant | config | — | `config.py` `SLA_DAYS` block (lines 28–33); `board_report_utils.py` `ON_TIME_WINDOW_DAYS = 30` (line 59) | exact |
| `reports/composed_report.py` — two frozensets + fetch blocks | service | request-response | `reports/composed_report.py` `_MODULES_NEEDING_FIXED_VULNS` / `_MODULES_NEEDING_ENV_TOTAL` gate pattern (lines 73–79, 186–293) | exact |
| `reports/modules/sc4_stub_module.py` (SC#4 test stub) | test/module | request-response | `reports/modules/example_module.py` (minimal `@register_module` class, `compute()` asserting kwargs, `_empty_result` fallback) | exact |

---

## Pattern Assignments

### `utils/external_scope.py` (utility, transform)

**Analogs:**
- `reports/modules/board_report_utils.py` — `_parse_tags` inner function (lines 263–291): case-insensitive category match, exact value extraction, semicolon-delimited `"Category=Value"` token parsing
- `reports/modules/board_report_utils.py` — `extract_owner()` function shape (lines 214–307): takes `assets_df`, returns enriched copy; fail-soft on missing column; `.apply()` over tag string
- `reports/modules/board_report_utils.py` — `identify_on_time_assets()` (lines 135–207): returns a `tuple[pd.DataFrame, pd.DataFrame]`; both sub-DataFrames are `.copy().reset_index(drop=True)`; empty-input guard at top

**Imports pattern** (`board_report_utils.py` lines 35–43):
```python
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)
```

**Tag-parsing pattern — `_parse_tags` inner function** (`board_report_utils.py` lines 263–291):
```python
def _parse_tags(tags_val) -> tuple[str, str]:
    if not isinstance(tags_val, str) or not tags_val.strip():
        return unassigned_label, ""

    owner_values: list[str] = []
    app_values:   list[str] = []

    for token in tags_val.split(";"):
        token = token.strip()
        if not token or "=" not in token:
            continue
        cat, _, val = token.partition("=")
        cat_cf = cat.strip().casefold()
        val_s  = val.strip()
        if not val_s:
            continue
        if cat_cf == OWNER_TAG_CATEGORY.casefold():   # case-insensitive category
            owner_values.append(val_s)                 # exact value retained as-is
```

**Adaptation for `external_scope.py`:** Replace `OWNER_TAG_CATEGORY` with `"location"` (casefold); replace value append with exact membership check: `val_s in {"External", "DMZ"}` (exact, case-sensitive per D-10). Category match is `casefold()`, value match is exact string equality — not casefold.

**Tuple-return shape** (`board_report_utils.py` lines 135–207 `identify_on_time_assets`):
```python
def identify_on_time_assets(
    assets_df:   pd.DataFrame,
    report_date: datetime,
    window_days: int = ON_TIME_WINDOW_DAYS,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if assets_df.empty:
        empty = assets_df.copy()
        return empty, empty           # both sub-frames, same columns

    # ... compute ...
    on_time     = df[on_time_mask].copy().reset_index(drop=True)
    not_on_time = df[~on_time_mask].copy().reset_index(drop=True)
    return on_time, not_on_time
```

**Adaptation for `external_scope.py`:** Return `(scoped_df, mismatches_df)`. `scoped_df` = assets with Location=External OR Location=DMZ tag OR public IPv4 (gap assets appear in BOTH). `mismatches_df` = assets in gap only (public IPv4 but no Location tag). On empty input: `return assets_df.iloc[0:0].copy(), assets_df.iloc[0:0].copy()`.

**`is_public_ipv4` helper — stdlib ipaddress pattern** (no existing analog; stdlib only per D-05/D-18):
```python
import ipaddress

def is_public_ipv4(ip_str: str) -> bool:
    """Return True if ip_str is a globally routable IPv4 address.
    Uses ipaddress.ip_address().is_global — covers RFC1918, CGNAT
    (100.64/10), loopback, link-local, documentation ranges.
    Never raises; returns False on unparseable input.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4 and addr.is_global
    except ValueError:
        return False
```

**CoW rule (Pitfall 9 / `260611-b1x`):** All column additions inside `external_scope.py` must use `.assign()`. Never `df["col"] = val` after a filter. Use:
```python
df = df.assign(is_external_tag=tag_mask, is_public_gap=gap_mask)
```

**`extract_owner` fail-soft column-absent pattern** (`board_report_utils.py` lines 293–306):
```python
if tag_column_name in df.columns:
    parsed = df[tag_column_name].apply(_parse_tags)
    df.loc[:, "owner"]       = [p[0] for p in parsed]
    df.loc[:, "application"] = [p[1] for p in parsed]
else:
    logger.warning(
        "extract_owner: column %r not present in DataFrame — "
        "all assets will be labelled %r.",
        tag_column_name,
        unassigned_label,
    )
    df.loc[:, "owner"]       = unassigned_label
    df.loc[:, "application"] = ""
```

**Adaptation:** Mirror the absent-column guard — if `"tags"` or `"ipv4"` columns are absent, log a warning and return two empty DataFrames (fail-soft, no exception).

---

### `utils/asset_count.py` (utility, transform)

**Analog:** `utils/open_count.py` (lines 1–115) — pure compute, no I/O, no network, accepts a DataFrame + injected reference datetime, zero-row guard at top, `from __future__ import annotations`, stdlib + pandas only.

**Imports pattern** (`utils/open_count.py` lines 1–17):
```python
"""
utils/open_count.py — Point-in-time open-finding predicate.

Pure compute: no file I/O, no network I/O.  ...
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import pandas as pd

logger = logging.getLogger(__name__)
```

**Pure-function signature pattern** (`utils/open_count.py` lines 19–40):
```python
def open_findings_at(df: pd.DataFrame, date: datetime) -> pd.DataFrame:
    """
    ...
    Parameters
    ----------
    df : pd.DataFrame
        ...Must have columns: ...
        All date columns must already be normalized ... before calling this function
        — do NOT call _normalize_vuln_dates inside this predicate.
    date : datetime
        Point-in-time reference (UTC datetime preferred; tz-naive input is
        coerced to UTC).

    Returns
    -------
    pd.DataFrame
        ...Zero-row DataFrames are returned as a zero-row copy; never raises on empty input.
    """
    if df.empty:
        return df.iloc[0:0].copy()
```

**Adaptation for `asset_count.py`:** Signature is `count_on_time_assets(assets_df: pd.DataFrame, report_date: datetime, window_days: int = ...) -> int | None`. No `datetime.now()` inside (D-12). Returns `None` sentinel when no on-time assets found (D-14), not 0. The window constant comes from `config.ON_TIME_SCAN_WINDOW_DAYS` (D-13) — import it, don't hardcode 30.

**On-time split pattern** (`scan_coverage_sla_module.py` lines 262–278 — the per-module implementation this utility extracts):
```python
if hasattr(report_date, "tzinfo") and report_date.tzinfo is not None:
    rd_ts = pd.Timestamp(report_date).tz_convert("UTC")
else:
    rd_ts = pd.Timestamp(report_date, tz="UTC")
cutoff = rd_ts - pd.Timedelta(days=ON_TIME_WINDOW_DAYS)

if not licensed.empty:
    on_time_flag = licensed[_lsd] >= cutoff
    on_time      = licensed[on_time_flag].copy().reset_index(drop=True)
```

**Zero-return sentinel (D-14):** Return `None` (not `0`) when `len(on_time) == 0`. Callers (vuln density module) must `None`-check before dividing. This mirrors `scan_coverage_sla_module.py` lines 281–286 where `scan_coverage_pct = None` is returned for empty licensed pool, then guarded downstream.

**No `datetime.now()` rule (D-12):** `asset_count.py` must accept `report_date` as a parameter. The `scan_coverage_sla_module.py` analog already does this — `report_date` flows from `compute()`'s parameter. The new utility simply makes this an explicit function parameter rather than inheriting it from `self`.

---

### `config.py` — `ON_TIME_SCAN_WINDOW_DAYS` constant (config)

**Analog:** `config.py` `SLA_DAYS` block (lines 28–33) — named dict of related constants grouped under a labeled comment block.

**Pattern** (`config.py` lines 26–33):
```python
# =============================================================================
# SLA Definitions (days to remediate per severity)
# A vulnerability is OVERDUE when:
#   today - first_found_date > SLA_DAYS[severity]  AND  not yet remediated
# =============================================================================
SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 60,
    "low": 120,
}
```

**New constant to add** (place immediately after `SLA_DAYS` block, before `SEVERITY_ORDER`):
```python
# =============================================================================
# On-time scan window — days within which an asset must have received a
# licensed Tenable scan to be counted as "scanned on time".
# Consumed by: utils/asset_count.py, reports/modules/scan_coverage_sla_module.py
# D-13: single canonical source; no drift between substrate and board module.
# =============================================================================
ON_TIME_SCAN_WINDOW_DAYS: int = 30
```

**Migration note for `scan_coverage_sla_module.py`:** After this constant is added to `config.py`, the existing `ON_TIME_WINDOW_DAYS = 30` in `board_report_utils.py` (line 59) becomes a second source of truth. The planner should note that `scan_coverage_sla_module.py` currently imports `ON_TIME_WINDOW_DAYS` from `board_report_utils` — that import chain must be updated to reference `config.ON_TIME_SCAN_WINDOW_DAYS` in a future phase (or kept as a re-export alias in `board_report_utils`). Phase 14 itself only adds the constant; the migration of the board module is deferred to avoid scope creep.

---

### `reports/composed_report.py` — two frozensets + conditional fetch blocks (service, request-response)

**Analog:** `reports/composed_report.py` itself — the existing `_MODULES_NEEDING_FIXED_VULNS` / `_MODULES_NEEDING_ENV_TOTAL` pattern. This is a copy-paste-shaped extension: add two more frozensets and two more conditional blocks in the exact same positions and style.

**Existing frozenset declarations** (`composed_report.py` lines 73–79):
```python
# Modules that need the fixed-vulnerabilities export forwarded via **kwargs.
# CriticalRemediationSLAModule is the only consumer today; conditionally
# fetching avoids an unnecessary export job when this module is not in the
# composition.
_MODULES_NEEDING_FIXED_VULNS = frozenset({"critical_remediation_sla"})

# Modules that need the environment-wide open-finding total (pre-tag-filter)
# forwarded via **kwargs.  TagSeverityShareModule is the only consumer today;
# the total is computed from the unfiltered vulns_df before the tag filter
# narrows it, mirroring the fixed_vulns_df gating pattern.
_MODULES_NEEDING_ENV_TOTAL = frozenset({"tag_severity_share"})
```

**New frozensets to add immediately after line 79** (following the same comment + declaration style):
```python
# Modules that need pre-read trend snapshots forwarded via **kwargs.
# trend_snapshots = read_trend() result dict {"snapshots": [...], "insufficient_data": bool}.
# Phase 14 seeds with the SC#4 stub only; each real v1.4 module adds itself
# in the phase that builds it (D-17).
_MODULES_NEEDING_TREND_SNAPSHOTS = frozenset({"sc4_kwargs_stub"})

# Modules that need the recast-rules DataFrame forwarded via **kwargs.
# recast_rules_df = fetch_recast_rules() result DataFrame.
# Phase 14 seeds with the SC#4 stub only (D-17).
_MODULES_NEEDING_RECAST_RULES = frozenset({"sc4_kwargs_stub"})
```

**Existing conditional fetch block** (`composed_report.py` lines 186–199):
```python
need_fixed = bool(_MODULES_NEEDING_FIXED_VULNS.intersection(modules))
fixed_vulns_df: Optional[pd.DataFrame] = None
if need_fixed:
    logger.info(
        "composed_report: fetching fixed vulnerabilities "
        "(critical_remediation_sla in modules) …"
    )
    fixed_vulns_df = fetch_fixed_vulnerabilities(tio, cache_dir)
```

**New conditional fetch blocks to add** (place in the fetch section after `fixed_vulns_df` block, before the tag-filter section — following same `need_X` / `if need_X:` idiom):
```python
need_trend = bool(_MODULES_NEEDING_TREND_SNAPSHOTS.intersection(modules))
trend_snapshots: Optional[dict] = None
if need_trend:
    from data.trend_store import read_trend  # noqa: PLC0415
    _log_scope = (
        f"{tag_category}={tag_value}" if tag_category and tag_value else "all_assets"
    )
    logger.info(
        "composed_report: reading trend snapshots (scope=%s) …", _log_scope
    )
    trend_snapshots = read_trend(
        dimension  = "severity",
        tag_filter = _log_scope,
        months     = 13,
    )

need_recast = bool(_MODULES_NEEDING_RECAST_RULES.intersection(modules))
recast_rules_df: Optional[pd.DataFrame] = None
if need_recast:
    from data.fetchers import fetch_recast_rules  # noqa: PLC0415
    logger.info("composed_report: fetching recast rules …")
    recast_rules_df = fetch_recast_rules(tio, cache_dir)
```

**Existing `composer_kwargs` build block** (`composed_report.py` lines 289–293):
```python
composer_kwargs: dict = {}
if fixed_vulns_df is not None:
    composer_kwargs["fixed_vulns_df"] = fixed_vulns_df
if _MODULES_NEEDING_ENV_TOTAL.intersection(modules):
    composer_kwargs["env_vuln_total"] = env_vuln_total
```

**New lines to append to `composer_kwargs` block** (add after line 293, before `ReportComposer(` call):
```python
if trend_snapshots is not None:
    composer_kwargs["trend_snapshots"] = trend_snapshots
if recast_rules_df is not None:
    composer_kwargs["recast_rules_df"] = recast_rules_df
```

**`_log_scope` timing note:** `_log_scope` is already computed at line 169 of `composed_report.py` (before the fetch section). The trend fetch block above can reference it directly — no recomputation needed.

**Tag-filter sanitisation note (PITFALLS.md integration gotcha):** `read_trend()` looks up files by `tag_filter` using `_sanitise_tag_for_filename()` at capture time. The value passed to `read_trend(tag_filter=...)` must match what was passed to `capture_snapshot(tag_filter=...)`. The existing `_log_scope` string (`"Category=Value"` or `"all_assets"`) is NOT sanitised. Check `data/trend_store.py:_sanitise_tag_for_filename()` to confirm the caller convention before wiring. Either pass the raw `_log_scope` (if `capture_snapshot` also receives it raw and sanitises internally) or pre-sanitise here.

**`run_report()` signature — unchanged (D-15):** No new parameters. All new kwargs arrive at modules via the existing `**composer_kwargs` → `ReportComposer(**composer_kwargs)` → `**self._kwargs` fan-out. The `ReportComposer` and `base.py` are untouched.

---

### `reports/modules/sc4_kwargs_stub_module.py` (test stub, request-response)

**Analog:** `reports/modules/example_module.py` (lines 1–209) — the minimal `@register_module` class pattern. The SC#4 stub is structurally identical but its `compute()` asserts that `trend_snapshots` and `recast_rules_df` arrive via `**kwargs` (D-17).

**Full skeleton to copy** (`example_module.py` lines 19–102):
```python
from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.registry import register_module

logger = logging.getLogger(__name__)


@register_module
class Sc4KwargsStubModule(BaseModule):
    """
    SC#4 test stub — verifies trend_snapshots and recast_rules_df kwargs
    arrive at compute() when this module ID is in the frozensets.
    NOT for production delivery groups.
    """

    MODULE_ID         = "sc4_kwargs_stub"
    DISPLAY_NAME      = "SC#4 kwargs gate stub"
    DESCRIPTION       = "Phase 14 acceptance test only."
    REQUIRED_DATA     = []
    SUPPORTED_OUTPUTS = []
    VERSION           = "1.0.0"

    def compute(
        self,
        vulns_df:    pd.DataFrame,
        assets_df:   pd.DataFrame,
        report_date: Any,
        config:      ModuleConfig,
        **kwargs:    Any,
    ) -> ModuleData:
        # Assertion: both kwargs must be present when this module is in
        # both frozensets (D-17).
        trend_snapshots  = kwargs.get("trend_snapshots")
        recast_rules_df  = kwargs.get("recast_rules_df")

        errors = []
        if trend_snapshots is None:
            errors.append("trend_snapshots kwarg missing")
        if recast_rules_df is None:
            errors.append("recast_rules_df kwarg missing")

        if errors:
            logger.error("%s compute() kwarg assertions failed: %s",
                         self._log_prefix(), errors)
            return self._empty_result("; ".join(errors), config)

        return ModuleData(
            module_id    = self.MODULE_ID,
            display_name = self.DISPLAY_NAME,
            metrics      = {
                "trend_snapshots_present":  True,
                "recast_rules_df_present":  True,
                "trend_snapshot_count":     len(trend_snapshots.get("snapshots", [])),
                "recast_rules_row_count":   len(recast_rules_df),
            },
            table_data   = [],
            chart_data   = {},
            summary_text = "SC#4 stub: both kwargs arrived at compute().",
            metadata     = {"computed_at": str(report_date)},
            error        = None,
        )
```

**Auto-discovery note:** The stub is named `sc4_kwargs_stub_module.py` (matches `*_module.py` glob). No registration in `run_all.py` or `_VALID_REPORTS` is needed — `registry.discover()` picks it up on import. The stub module ID `"sc4_kwargs_stub"` is already seeded in both frozensets above.

**Empty-data fallback** (`example_module.py` lines 97–102):
```python
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "%s compute() failed: %s", self._log_prefix(), exc,
                exc_info=True,
            )
            return self._empty_result(str(exc), config)
```

**`_empty_result` note:** `BaseModule._empty_result(msg, config)` produces a coherent failed `ModuleData` with gray RAG strip, `"No data in scope."` driver, and empty table/chart data. The stub must use it (not raise) so the batch stays fail-soft.

---

## Shared Patterns

### pandas 3.0 CoW — `.assign()` mandate
**Source:** `reports/modules/board_report_utils.py` lines 496–504; CONVENTIONS.md F-DTYPE; quick task `260611-b1x` post-mortem
**Apply to:** All new files in this phase (`external_scope.py`, `asset_count.py`, stub module)

```python
# CORRECT — always use .assign() after any filter or slice
df = df.assign(days_open=computed_series)

# WRONG — triggers ChainedAssignmentError under pandas 3.0 CoW
df["days_open"] = computed_series    # after a filter
df.loc[:, "days_open"] = computed_series  # after a filter
```

The explicit comment from board_report_utils.py lines 496–504:
```python
# F-DTYPE (Plan 03-07 Task 3): use .assign() rather than chained
# df[col]= or .loc[:, col]= setters — both alternatives either drop
# int dtype (.loc[:, col]= preserves the merge's float64) or fire
# ChainedAssignmentError FutureWarning under pandas 3.0 CoW
# (df[col]= chains through the merge's tracked parent frame).
# .assign() replaces the column on a fresh frame and bypasses both.
bu_asset = bu_asset.assign(
    risk_score=bu_asset["risk_score"].fillna(0).astype(int),
)
```

### Empty-input guard — two-frame tuple variant
**Source:** `board_report_utils.py` `identify_on_time_assets()` lines 174–177
**Apply to:** `utils/external_scope.py`

```python
if assets_df.empty:
    empty = assets_df.copy()
    return empty, empty
```

For `external_scope.py`, prefer `assets_df.iloc[0:0].copy()` (zero-row slice) over `.copy()` of the empty frame to ensure consistent behavior when the caller passes a non-empty frame filtered to zero.

### Empty-input guard — scalar sentinel variant
**Source:** `scan_coverage_sla_module.py` lines 281–286 (None sentinel for division guard)
**Apply to:** `utils/asset_count.py`

```python
if total_on_time == 0:
    return None   # D-14: sentinel distinguishes "no assets" from "no vulns"
```

### Fail-soft `try/except` wrapper
**Source:** `example_module.py` lines 97–102; `scan_coverage_sla_module.py` lines 522–527
**Apply to:** `sc4_kwargs_stub_module.py` `compute()`

```python
try:
    ...
except Exception as exc:  # noqa: BLE001
    logger.error(
        "%s compute() failed: %s", self._log_prefix(), exc,
        exc_info=True,
    )
    return self._empty_result(str(exc), config)
```

### `read_trend()` return contract
**Source:** `data/trend_store.py` lines 338–393
**Apply to:** `composed_report.py` fetch block; downstream modules (Phase 15+) branching on `insufficient_data`

```python
# read_trend() always returns this shape — never raises:
{
    "snapshots":         list[dict],   # sorted ascending by "month" key
    "insufficient_data": bool,         # True when len(snapshots) < 2
}

# Consumers MUST branch on insufficient_data (QUAL-01):
if trend_snapshots["insufficient_data"]:
    return self._empty_result("Insufficient trend history", config)
```

### Module auto-discovery — no `run_all.py` registration needed
**Source:** `reports/composed_report.py` lines 49–50; CLAUDE.md "Adding a new module"
**Apply to:** `sc4_kwargs_stub_module.py`

```python
# Importing reports.modules triggers registry.discover().
from reports.modules import ReportComposer, registry
```

Modules consumed only via `composed_report` or `management_summary` need NO changes to `run_all.py` `_VALID_REPORTS`, `_REPORT_MODULE_MAP`, `delivery_config.schema.yaml`, or `CLAUDE.md` YAML Schema Rules. The `*_module.py` filename glob + `@register_module` decorator is sufficient.

---

## No Analog Found

All five files have strong analogs in the codebase. No "no analog" entries.

---

## Critical Constraints for Planner

These are not optional conventions — they are acceptance bars that burned in prior phases:

| Constraint | Rule | Source |
|---|---|---|
| CoW — no `df["col"]=` after filter | Use `.assign()` exclusively | `260611-b1x`; CONVENTIONS.md F-DTYPE |
| `is_public_ipv4` — use `is_global` not hand-rolled RFC1918 | Covers CGNAT, loopback, link-local, IPv6 | D-05/D-07; PITFALLS.md Pitfall 7 |
| RFC 5737 addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) return `is_global=False` | Cannot serve as positive "external" test fixtures | D-18 |
| `asset_count.py` — no `datetime.now()` inside | Inject `report_date` as parameter | D-12 |
| `asset_count.py` — returns `None` not `0` on empty | Sentinel distinguishes "no assets" from "no vulns" | D-14 |
| `external_scope.py` — DMZ-tagged + private IP is NOT a mismatch | Only `Location=External` on a private IP is anomalous | D-06 |
| `external_scope.py` — gap assets appear in BOTH return DataFrames | `scoped_df` includes gap assets; `mismatches_df` is the gap subset | D-08 |
| `composed_report.py` — `run_report()` signature unchanged | No new parameters; kwargs forwarded via `composer_kwargs` | D-15 |
| `sc4_kwargs_stub_module.py` — no `run_all.py` registration | Auto-discovery only; no slug in `_VALID_REPORTS` | D-17 |
| `ON_TIME_SCAN_WINDOW_DAYS` — single source in `config.py` | No `utils → reports.modules` backwards import | D-13 |

---

## Metadata

**Analog search scope:** `reports/modules/`, `utils/`, `data/`, `config.py`, `reports/composed_report.py`
**Files read for pattern extraction:** `board_report_utils.py`, `scan_coverage_sla_module.py`, `composed_report.py`, `open_count.py`, `config.py`, `trend_store.py` (lines 1–120, 338–437), `example_module.py`
**Pattern extraction date:** 2026-06-11
