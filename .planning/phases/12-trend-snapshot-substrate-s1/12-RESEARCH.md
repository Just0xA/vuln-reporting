# Phase 12: Trend Snapshot Substrate (S1) — Research

**Researched:** 2026-06-06
**Domain:** Pure-compute open-count predicate + forward-accumulating JSON snapshot engine
**Confidence:** HIGH — all findings drawn from direct codebase inspection and the settled spike blueprint

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Build the substrate as a new shared module; leave `management_summary.py`'s private trend helpers (`_save_trend_snapshot`, `_load_trend_history`) exactly as-is. Zero regression risk to TREND-03's byte-for-byte bar. Minor duplication accepted; full `management_summary` migration onto the substrate stays GEN-01 (v1.4 backlog).
- **D-02:** `open_findings_at()` lives in `utils/` (pure compute, no I/O). The snapshot capture/read engine lives in `data/` (does I/O, alongside `data/fetchers.py` and the `data/trend/` store). Planner picks exact filenames.
- **D-03:** File-per-dimension, flat counts. `data/trend/trend_{dimension}_{tagsuffix}.json`. Each snapshot entry keeps the existing flat per-entry shape (`month`, `tag_filter`, `<count keys>`, `generated_at`) so it stays in the same shape *family* as `management_summary`.
- **D-04:** Each snapshot entry also records in-scope `asset_count` (aggregate, PII-safe).
- **D-05:** `read_trend()` reads only the substrate's own files. Merge-reading MS history is rejected (ragged `asset_count` rows). Cold-start begins at the substrate's first snapshot.
- **D-06:** Open-count stays the primitive; no substrate-level de-duplication. Cross-UUID normalization is report-layer, deferred to v1.4.
- **D-07:** Churn is an inherent property of stock-based VM trend metrics. Flow metrics (new-vs-remediated) are the v1.4 answer; substrate enables but does not compute them.
- **D-08:** `capture_snapshot` is df-injected and pure-ish: receives `df` (open+reopened findings) and `assets_df`, computes counts, writes atomically. Entry-point script does the fetching, reusing existing fetchers + date-named `data/cache/` parquet store.
- **D-09:** Standalone cron entry point: `scripts/capture_trend_snapshot.py`, mirroring `scripts/warm_cache.py`. Phase 12 captures the `all_assets` severity snapshot only. `capture_snapshot` stays parameterized by `dimension` + `tag_filter` so Phase 13 can iterate owners without reshaping it.

### Locked by spikes — carried forward, not re-litigated

- Reopened-aware two-interval predicate is mandatory (naive form drops ~19% / all REOPENED).
- Unit tests must cover OPEN / REOPENED / FIXED labelled cases (TREND-01).
- Snapshot-capture, not reconstruction (~29-day Tenable fixed-retention wall; cold start is real).
- Extend `data/trend/`, not a parallel store.
- PII discipline: aggregate counts only — no hostnames, IPs, plugin names, or row-level fields in persisted files.
- Atomic writes (temp-file + `os.replace`) and per-calendar-month idempotency (overwrite the month's cell, never duplicate).

### Claude's Discretion

- Exact new-module filenames, function signatures beyond the agreed shape, and the precise dimension-registration mechanism.
- Cron exit-code conventions (follow `scripts/warm_cache.py` precedent).

### Deferred Ideas (OUT OF SCOPE)

- Flow metrics (new-this-month / remediated-this-month) — v1.4 New-vs-Remediated report.
- Vuln Density (open ÷ asset_count) — v1.4 report.
- Cross-UUID / stable-asset-key de-duplication — report-layer, v1.4.
- Per-tag-filter / per-delivery-group snapshot iteration — Phase 13 (owner dimension) and beyond.
- Full `management_summary` migration onto the substrate — GEN-01 (v1.4).
- Merge-reading MS severity history into `read_trend` — rejected due to ragged `asset_count` rows (D-05).
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TREND-01 | Canonical `open_findings_at(df, date)` with reopened-aware two-interval predicate; unit-tested against OPEN/REOPENED/FIXED labelled cases; matches actual live open count | Predicate algorithm fully specified in spike blueprint (lines 44–54); exact column names confirmed from `data/fetchers.py`; UTC datetime types confirmed from `_normalize_vuln_dates` |
| TREND-02 | `capture_snapshot(date, dimensions)` writes atomic monthly snapshot via temp-file + `os.replace` | Non-atomic pattern identified in MS (lines 244–248); atomic pattern absent from MS but established in project; shape fully specified |
| TREND-03 | Snapshots reuse/extend `data/trend/`; existing trend consumers do not regress | MS JSON shape fully extracted (lines 222–229); D-01 ensures no code change to MS private helpers; substrate writes to separate `trend_severity_*.json` files |
| TREND-04 | `read_trend(dimension, months)` cold-start safe: ≤1 snapshot → available history + flag, never crash | `_compute_metric_7` pattern (lines 740–741) demonstrates the `first_run_notice` pattern to mirror |
| TREND-05 | Idempotent per calendar month (re-run overwrites; never duplicates) | MS `_save_trend_snapshot` lines 232–240 show the (month, tag_filter) keyed overwrite pattern; substrate copies this logic |
| TREND-06 | Aggregate counts only — no row-level PII in persisted files | Payload shape confirmed: `{month, tag_filter, critical, high, medium, low, asset_count, generated_at}` |
| TREND-07 | Cron/daemon-friendly entry point; logged with cron-friendly exit codes | `scripts/warm_cache.py` is the exact template (exit codes 0/2/3, rotating file handler, `_log_started`/`_log_completed`) |
</phase_requirements>

---

## Summary

Phase 12 delivers two tightly scoped new modules. The first is a pure-compute function `open_findings_at(df, date)` that lives in `utils/` alongside `sla_calculator.py` — it implements the reopened-aware two-interval predicate proven in Spike 002 that the naive form silently drops ~19% of findings (the entire REOPENED population). The second is a snapshot engine in `data/` that writes aggregate-only JSON files to the existing `data/trend/` directory, extending the shape already consumed by `management_summary` without touching that module's private helpers. A standalone entry point `scripts/capture_trend_snapshot.py` mirroring `scripts/warm_cache.py` provides the cron integration.

The architectural decisions are fully locked in CONTEXT.md (D-01 through D-09). The research focus here is the exact algorithm, column names, JSON shape, atomic-write convention, and test infrastructure a planner needs to write concrete tasks without ambiguity.

The key implementation risk is getting the reopened-aware predicate exactly right. The spike blueprint is precise and must be followed verbatim — including the `state` column casing, the `resurfaced_date` null-check logic, and the fact that dates from `_normalize_vuln_dates` are already UTC-aware `datetime64[ns, UTC]` timestamps that pandas comparison against a `pd.Timestamp(date, tz=UTC)` handles correctly.

**Primary recommendation:** Implement `open_findings_at` first (unit-tested in isolation), then wire it into `capture_snapshot` (df-injected for testability), then build the entry point. This order matches TREND-01 → TREND-02 → TREND-07 and ensures each piece is verified before the next depends on it.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Open-count predicate | `utils/` (pure compute) | — | No I/O; same layer as `sla_calculator.py`; makes predicate unit-testable without disk |
| Snapshot capture/read engine | `data/` (I/O layer) | — | Writes to `data/trend/`; sits alongside `data/fetchers.py` per D-02 |
| Cron entry point | `scripts/` | — | Mirrors `scripts/warm_cache.py`; handles fetching + cache reuse + exit codes |
| Trend JSON store | `data/trend/` | — | Existing gitignored directory; no new parallel store per D-03 |
| Severity mapping | `config.vpr_to_severity()` | — | VPR-first is a locked project convention; predicate receives already-classified `severity` column |

---

## Standard Stack

No new packages. Phase 12 is pure stdlib + existing project dependencies.

| Library | Already In Project | Role In This Phase |
|---------|-------------------|--------------------|
| `pandas` | Yes | DataFrame operations in predicate and `capture_snapshot` |
| `pathlib.Path` | Yes | File paths for trend JSON and temp-file writes |
| `json` | stdlib | Read/write trend JSON files |
| `os.replace` | stdlib | Atomic rename after temp-file write |
| `datetime` / `timezone` | stdlib | UTC timestamps on `generated_at`; reference date for predicate |
| `logging` / `RotatingFileHandler` | Yes | Logging in entry point (mirror `warm_cache.py`) |
| `pytest` | Yes | Unit tests |

### Package Legitimacy Audit

No new packages. Section not applicable.

---

## Architecture Patterns

### System Architecture Diagram

```
cron / Task Scheduler
        │
        ▼
scripts/capture_trend_snapshot.py
  ├── get_client()  ──► Tenable API (or [CACHE HIT])
  ├── fetch_all_vulnerabilities(tio, cache_dir)  ──► vulns_df (state=open+reopened)
  ├── fetch_all_assets(tio, cache_dir)           ──► assets_df
  │
  └── data/trend_store.capture_snapshot(
            df=vulns_df,
            assets_df=assets_df,
            date=snapshot_date,           ← server local calendar month
            dimension="severity",
            tag_filter=None               ← all_assets for Phase 12
      )
         │
         ├── utils/open_count.open_findings_at(df, date)  ← pure compute
         │         │
         │         └── two-interval predicate
         │               ├── born = first_found <= D
         │               ├── fixed = (FIXED & lf<=D) | (REOPENED & lf<=D & D<rs) | (REOPENED & lf<=D & rs.isna())
         │               └── return df[born & ~fixed]
         │
         ├── .groupby("severity").size()  ──► {critical, high, medium, low}
         ├── len(assets_df)               ──► asset_count
         │
         └── atomic write ──► data/trend/trend_severity_all_assets.json
                                   {snapshots: [..., {month, tag_filter, critical, high, medium, low, asset_count, generated_at}]}

data/trend_store.read_trend(dimension, tag_filter, months)
  └── reads substrate's own trend_severity_*.json (never MS files)
       └── cold-start: len(snapshots) < 2 → {snapshots: [...], insufficient_data: True}
```

### Recommended Project Structure

```
utils/
└── open_count.py           # open_findings_at(df, date) — pure, no I/O

data/
└── trend_store.py          # capture_snapshot(), read_trend()

scripts/
└── capture_trend_snapshot.py   # cron entry point (mirrors warm_cache.py)

tests/unit/
└── test_open_count.py      # TREND-01 labelled-case unit tests

tests/content/
└── test_trend_store.py     # TREND-02..05 snapshot write/read/idempotency tests

data/trend/
├── management_summary_*.json          # MS-owned; NOT touched
└── trend_severity_all_assets.json     # substrate-owned; new
```

### Pattern 1: Reopened-Aware Two-Interval Predicate

**What:** Determines which findings were open at a given point-in-time date `D`. The naive `first_found <= D AND (last_fixed IS NULL OR last_fixed > D)` form is a bug — it drops all REOPENED findings because their `last_fixed` is set (the prior fix) but the finding re-opened later.

**When to use:** Any "open at date D" computation. `open_findings_at(df, date)` is the single call site.

**Exact algorithm** (from spike blueprint, verbatim — do not alter):

```python
# Source: .claude/skills/spike-findings-vuln-reporting/references/vuln-metric-substrate.md lines 44-54
# Column types after _normalize_vuln_dates(): all date cols are datetime64[ns, UTC] or NaT

def open_findings_at(df: pd.DataFrame, date: datetime) -> pd.DataFrame:
    """
    Two-interval model.
    FIXED:    closed permanently at last_fixed.
    REOPENED: closed only during [last_fixed, resurfaced_date); open outside that window.
    OPEN:     never closed (last_fixed is NaT).
    """
    D = pd.Timestamp(date)   # must be tz-aware (UTC) to compare with datetime64[ns, UTC]
    born = df["first_found"] <= D
    st = df["state"]
    lf = df["last_fixed"]
    rs = df["resurfaced_date"]
    fixed = (
        ((st == "FIXED")    & lf.notna() & (lf <= D)) |
        ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.notna() & (D < rs)) |
        ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.isna())
    )
    return df[born & ~fixed]
```

**Column name confirmation** (from `data/fetchers.py` lines 350-361 and `_normalize_vuln_dates` line 1173):

| Column | Type after normalization | Source in API response |
|--------|--------------------------|----------------------|
| `state` | `str` (`"open"`, `"reopened"`, `"fixed"`) | `vuln.get("state", "")` |
| `first_found` | `datetime64[ns, UTC]` | `vuln.get("first_found", "")` → `_parse_iso_utc` |
| `last_fixed` | `datetime64[ns, UTC]` or `NaT` | `vuln.get("last_fixed", "")` → `_parse_iso_utc` |
| `resurfaced_date` | `datetime64[ns, UTC]` or `NaT` | `vuln.get("resurfaced_date", "")` → `_parse_iso_utc` |

**Critical detail on `state` casing:** The fetcher stores raw API values. The spike blueprint uses `"FIXED"` and `"REOPENED"` (uppercase). However, `management_summary.py` line 120 defines `_OPEN_STATES: frozenset[str] = frozenset({"open", "reopened"})` (lowercase). The fetcher at line 354 stores `vuln.get("state", "")` verbatim. **The predicate must use the same casing as whatever the live API returns.** The MS `_OPEN_STATES` uses lowercase, but the spike blueprint uses uppercase in the comparisons. The unit tests (TREND-01) must validate against real field values — use `state.str.upper()` comparison OR match the casing the fetcher receives. The safest approach is `st.str.upper() == "FIXED"` and `st.str.upper() == "REOPENED"` to be casing-insensitive. This is a **planner decision point** — flag in the plan.

### Pattern 2: Snapshot JSON Shape

**Existing MS shape** (from `_save_trend_snapshot`, lines 222–229) — the substrate's shape must stay in this family:

```json
{
  "snapshots": [
    {
      "month":        "2026-06",
      "tag_filter":   "all_assets",
      "critical":     42,
      "high":         183,
      "medium":       751,
      "low":          204,
      "generated_at": "2026-06-06T11:00:00Z"
    }
  ]
}
```

**Substrate severity shape** — adds `asset_count` per D-04:

```json
{
  "snapshots": [
    {
      "month":        "2026-06",
      "tag_filter":   "all_assets",
      "critical":     42,
      "high":         183,
      "medium":       751,
      "low":          204,
      "asset_count":  1247,
      "generated_at": "2026-06-06T11:00:00Z"
    }
  ]
}
```

**Key fields:**
- `month`: ISO year-month string `"YYYY-MM"` — derived from the run's local calendar month (local date convention matches cache folder naming)
- `tag_filter`: `"all_assets"` for Phase 12 (no tag filter). The `_sanitise_tag_for_filename` pattern from MS line 146 can be reused for the Phase 13 parameterized case
- `critical`/`high`/`medium`/`low`: `int` — `value_counts` result cast to int; always present, default 0 if severity absent
- `asset_count`: `int` — `len(assets_df)` after any tag filtering; Phase 12 = total licensed assets
- `generated_at`: ISO 8601 UTC string `"YYYY-MM-DDTHH:MM:SSZ"` — matches MS format exactly

**File naming:**
- MS files: `management_summary_{tagsuffix}.json` — substrate must NOT use this prefix
- Substrate files: `trend_{dimension}_{tagsuffix}.json` → `trend_severity_all_assets.json` for Phase 12
- This naming ensures the substrate's `read_trend()` and MS's `_load_trend_history()` never accidentally cross-read each other's files (D-05)

### Pattern 3: Atomic Write

**Current MS write (NON-atomic)** — `management_summary.py` lines 244–248:

```python
with trend_file.open("w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
```

**Substrate must use atomic write** (temp-file + `os.replace`):

```python
import os
import tempfile

# Source: project convention per CLAUDE.md + D-02/TREND-02 requirement
tmp_fd, tmp_path = tempfile.mkstemp(dir=trend_file.parent, suffix=".tmp")
try:
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp_path, trend_file)   # atomic on POSIX and Windows (same filesystem)
except Exception:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    raise
```

`os.replace` is atomic on POSIX. On Windows it is also atomic when source and destination are on the same filesystem (which they always are here — both in `data/trend/`). The systemd `ReadWritePaths` already includes `data/trend` (added in quick task `close-v12-audit-gaps`).

### Pattern 4: Per-Month Idempotency (TREND-05)

The MS `_save_trend_snapshot` lines 232–240 show the exact keyed-overwrite pattern to replicate:

```python
# Source: reports/management_summary.py lines 232-240
snapshots: list[dict] = data.get("snapshots", [])
updated = False
for idx, snap in enumerate(snapshots):
    if snap.get("month") == month_str and snap.get("tag_filter") == tag_filter_label:
        snapshots[idx] = new_entry
        updated = True
        break
if not updated:
    snapshots.append(new_entry)
```

The substrate copies this logic identically — the key is the `(month, tag_filter)` tuple.

### Pattern 5: Cold-Start-Safe Reader (TREND-04)

The MS `_compute_metric_7` pattern (lines 740–741) demonstrates the flag approach:

```python
has_trend        = len(recent) >= 2
first_run_notice = len(recent) < 2
```

`read_trend()` must return a similar structure: the available snapshots (whatever exists, including 0 or 1) plus an `insufficient_data: bool` flag. It must never raise when the file doesn't exist or contains only one entry. Mirror `_load_trend_history`'s `try/except` that returns `[]` on any parse failure (lines 174–181).

### Pattern 6: Entry Point (`scripts/capture_trend_snapshot.py`)

Mirror `scripts/warm_cache.py` exactly — same structure, same conventions:

| Element | `warm_cache.py` value | `capture_trend_snapshot.py` value |
|---------|----------------------|----------------------------------|
| Log file | `logs/warm_cache.log` | `logs/capture_trend_snapshot.log` |
| Logger name | `"warm_cache"` | `"capture_trend_snapshot"` |
| Exit 0 | success or dry-run | success or dry-run |
| Exit 2 | auth failure or argparse error | auth failure or argparse error |
| Exit 3 | fetcher failed after retries | fetcher or write failed after retries |
| `--dry-run` flag | logs what would happen; writes nothing | same |
| `--verbose` flag | console at DEBUG | same |
| `--date` flag | target date folder (YYYY-MM-DD) | target month (YYYY-MM) for snapshot |
| `_log_started` / `_log_completed` | used | copy verbatim |
| `_WarmCacheArgumentParser` | subclass for argparse error logging | copy or import from warm_cache if needed |
| Rotating file handler | 5 MB, 3 backups | same |

**Key difference:** `warm_cache.py` uses `--date` for the cache folder. `capture_trend_snapshot.py` needs a `--month YYYY-MM` flag (defaults to current local month) for the snapshot target, plus the standard `--date` for the cache folder (defaulting to today). Both default to local time (consistent with cache naming convention per CLAUDE.md timezone policy).

The fetchers to call: `fetch_all_vulnerabilities` + `fetch_all_assets`. Do NOT call `fetch_fixed_vulnerabilities` for Phase 12 — the open-count predicate operates only on the open+reopened export (`state=["open", "reopened"]`).

### Anti-Patterns to Avoid

- **Naive open predicate `first_found <= D AND (last_fixed IS NULL OR last_fixed > D)`:** Drops the entire REOPENED population (~19% in spike data). This is the single most important implementation constraint.
- **Writing directly without temp-file:** MS does this today and it's the identified non-atomic pattern. Substrate must not repeat it.
- **Inline f-string formatting of possibly-None counts:** Use `int(sev_counts.get("critical", 0))` with a default; never `f"{count:.0f}"` on a value that could be None.
- **Reading MS trend files in `read_trend()`:** D-05 explicitly rejects this due to ragged `asset_count` rows. `read_trend()` reads only files matching `trend_{dimension}_{tagsuffix}.json`.
- **Calling `_normalize_vuln_dates` again inside the predicate:** The DataFrame coming from `fetch_all_vulnerabilities` is already normalized. Calling it again is a no-op at best, silently wrong at worst.
- **Using local time in `generated_at`:** UTC for report timestamps per CLAUDE.md timezone policy. `datetime.now(tz=timezone.utc)` not `datetime.now()`.
- **Using UTC in the `month` field:** Local calendar month for snapshot key per cache folder naming convention. `datetime.now().strftime("%Y-%m")` (no `tz=timezone.utc`).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead |
|---------|-------------|-------------|
| Atomic file write | Custom rename logic | `tempfile.mkstemp` + `os.replace` (stdlib) |
| VPR → severity tier | Custom severity bands | `config.vpr_to_severity(vpr_score, fallback=severity_native)` — already on every row |
| Date normalization | Custom ISO parser | Already done by `_normalize_vuln_dates` at fetch time — predicate receives normalized columns |
| Tag suffix sanitization | Custom regex | `_sanitise_tag_for_filename` in `management_summary.py` — extract or copy the pattern |
| Logging / rotating file handler | Custom handler | `logging.handlers.RotatingFileHandler` (copy `warm_cache.py` `_configure_logging`) |
| Cache reuse | Re-fetch from Tenable | Pass `cache_dir` to `fetch_all_vulnerabilities` / `fetch_all_assets` — `[CACHE HIT]` fires automatically |

---

## Common Pitfalls

### Pitfall 1: State Column Casing

**What goes wrong:** The predicate compares `st == "FIXED"` and `st == "REOPENED"` (uppercase as in the spike blueprint). The fetcher stores `vuln.get("state", "")` verbatim from the API. If the API returns lowercase (`"fixed"`, `"reopened"`) or mixed case, the predicate silently counts nothing as fixed, overcounting the open population.

**Why it happens:** The spike blueprint used uppercase to match what was seen in the spiked data. `management_summary.py` uses `_OPEN_STATES = frozenset({"open", "reopened"})` (lowercase), suggesting the API returns lowercase.

**How to avoid:** Use case-insensitive comparison: `st.str.upper() == "FIXED"`. Add a test that explicitly constructs rows with lowercase state values (matching the fetcher's output) and verifies the predicate result.

**Warning signs:** Unit test passes with uppercase-state fixture but live open count doesn't match expected.

### Pitfall 2: Timestamp Timezone Mismatch in Predicate

**What goes wrong:** `df["first_found"] <= D` raises `TypeError: Cannot compare tz-naive and tz-aware datetime-like objects` if `D` is a naive datetime or if `first_found` lost its timezone somewhere.

**Why it happens:** The predicate receives a `date` argument; if it's a naive `datetime.date` object or a naive `datetime.datetime`, the comparison fails at runtime.

**How to avoid:** Always construct `D = pd.Timestamp(date, tz="UTC")` inside `open_findings_at`. The DataFrame's date columns are `datetime64[ns, UTC]` after `_normalize_vuln_dates`. If `date` is already tz-aware UTC, `pd.Timestamp(date)` preserves it.

### Pitfall 3: Empty DataFrame from groupby

**What goes wrong:** `df.groupby("severity").size()` on an empty DataFrame returns an empty Series. `.get("critical", 0)` on a Series raises `AttributeError` — Series has no `.get()`.

**Why it happens:** Empty-data path (a filtered-to-zero recipient group) produces an empty DataFrame after `open_findings_at`. `groupby().size()` returns a Series, not a dict.

**How to avoid:** Convert to dict first: `counts = df.groupby("severity").size().to_dict()`. Then `counts.get("critical", 0)` works correctly on both empty and non-empty cases.

### Pitfall 4: Corrupt Trend File Leaves Partial Write

**What goes wrong:** Process is killed mid-write. Next run finds a truncated JSON file, `json.load` raises, and the snapshot is lost.

**Why it happens:** MS writes directly to the target file (non-atomic). If interrupted between open and close, the file is truncated.

**How to avoid:** The temp-file + `os.replace` atomic write pattern. The temp file is fully written before `os.replace` commits it. On failure, the original file is untouched. The cleanup `except` block unlinks the temp file.

### Pitfall 5: `read_trend()` Accidentally Reads MS Files

**What goes wrong:** `read_trend("severity", "all_assets")` globs `data/trend/*all_assets*.json` and picks up `management_summary_all_assets.json`. The MS file has no `asset_count` field, producing `KeyError` or `NaN` in downstream consumers.

**Why it happens:** Loose glob pattern.

**How to avoid:** `read_trend` must glob specifically for `trend_{dimension}_{tagsuffix}.json` — i.e., `trend_severity_all_assets.json` for Phase 12. The `trend_` prefix distinguishes substrate files from MS files unambiguously.

### Pitfall 6: Month Key Derived from UTC vs. Local Time

**What goes wrong:** Snapshot captured at 2026-07-01T01:30 UTC on a US/Eastern server writes `month = "2026-07"` (UTC), but the operator inspecting the file and the cron schedule both expect `"2026-06"` (local date at run time).

**Why it happens:** CLAUDE.md timezone policy is "report timestamps use UTC; cache folder names and schedule matching use server local time." The `month` field is a schedule-matching key, not a report timestamp.

**How to avoid:** Derive `month_str` from `datetime.now().strftime("%Y-%m")` (no `tz=timezone.utc`), not `datetime.now(tz=timezone.utc)`. Keep `generated_at` as UTC (that IS a report timestamp).

---

## Code Examples

### open_findings_at — complete function signature

```python
# Source: .claude/skills/spike-findings-vuln-reporting/references/vuln-metric-substrate.md
# plus casing fix based on management_summary.py _OPEN_STATES evidence

from __future__ import annotations
from datetime import datetime
import pandas as pd

def open_findings_at(df: pd.DataFrame, date: datetime) -> pd.DataFrame:
    """
    Return the subset of findings that were open at point-in-time `date`.

    Uses the reopened-aware two-interval model: a REOPENED finding is
    considered fixed only during [last_fixed, resurfaced_date).

    Parameters
    ----------
    df : pd.DataFrame
        Vulnerability DataFrame from fetch_all_vulnerabilities().
        Must have columns: first_found, last_fixed, resurfaced_date, state
        (all date columns normalized to datetime64[ns, UTC] by _normalize_vuln_dates).
    date : datetime
        Point-in-time reference (tz-aware UTC datetime).

    Returns
    -------
    pd.DataFrame
        Filtered to rows that were open at `date`.
    """
    D = pd.Timestamp(date, tz="UTC") if getattr(date, "tzinfo", None) is None else pd.Timestamp(date)
    born = df["first_found"] <= D
    st = df["state"].str.upper()    # normalize casing
    lf = df["last_fixed"]
    rs = df["resurfaced_date"]
    fixed = (
        ((st == "FIXED")    & lf.notna() & (lf <= D)) |
        ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.notna() & (D < rs)) |
        ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.isna())
    )
    return df[born & ~fixed]
```

### Severity count extraction (empty-safe)

```python
# Source: project convention — groupby + to_dict() + .get() with default
def _count_by_severity(open_df: pd.DataFrame) -> dict[str, int]:
    counts = open_df.groupby("severity").size().to_dict() if not open_df.empty else {}
    return {
        "critical": int(counts.get("critical", 0)),
        "high":     int(counts.get("high", 0)),
        "medium":   int(counts.get("medium", 0)),
        "low":      int(counts.get("low", 0)),
    }
```

### Atomic JSON write

```python
# Source: stdlib os.replace atomicity guarantee
import json, os, tempfile
from pathlib import Path

def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
```

### read_trend cold-start safe

```python
# Source: _compute_metric_7 pattern — management_summary.py lines 740-741
def read_trend(
    dimension: str,
    tag_filter: str = "all_assets",
    months: int = 6,
) -> dict:
    """
    Returns:
        snapshots: list[dict]   — up to `months` most recent, sorted ascending
        insufficient_data: bool — True when fewer than 2 snapshots exist
    """
    trend_file = TREND_DIR / f"trend_{dimension}_{tag_filter}.json"
    all_snaps = _load_trend_json(trend_file)      # returns [] on missing/corrupt
    relevant = [s for s in all_snaps if s.get("tag_filter") == tag_filter]
    relevant.sort(key=lambda s: s.get("month", ""))
    recent = relevant[-months:]
    return {
        "snapshots":        recent,
        "insufficient_data": len(recent) < 2,
    }
```

---

## `_compute_metric_7` Reader Contract — TREND-03 Protection

`_compute_metric_7` (lines 700–764) is the only existing consumer of the trend store. It must not regress after Phase 12 ships.

**What it reads:** `_trend_file_path(tag_category, tag_value)` → `management_summary_{tagsuffix}.json`. It never reads substrate files.

**What it expects per snapshot entry:** `month`, `tag_filter`, `critical`, `high`, `medium`, `low` — it reads `.get("critical", 0)` etc., so extra keys (`asset_count`) in the same file would be silently ignored even if it did accidentally read one.

**Why TREND-03 is satisfied by D-01:** The substrate writes to `trend_severity_all_assets.json`; MS reads from `management_summary_all_assets.json`. These are different filenames in the same directory. The MS write path (`_save_trend_snapshot`) is unchanged. `_compute_metric_7` will never see substrate files unless someone passes it a substrate path explicitly.

**Byte-for-byte bar:** "Byte-for-byte unchanged" means the content of `management_summary_all_assets.json` after a run with the substrate wired in must be identical to a run without it. Since the substrate writes to a different file and calls none of the MS private helpers, this is structurally guaranteed — no testing needed for the MS file itself, only confirmation that `_save_trend_snapshot` is not modified.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (version from requirements.txt) |
| Config file | `pytest.ini` (root) |
| Quick run command | `pytest tests/unit/test_open_count.py tests/content/test_trend_store.py -q` |
| Full suite command | `pytest -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TREND-01 | `open_findings_at` returns correct rows for OPEN / REOPENED / FIXED labelled inputs | unit | `pytest tests/unit/test_open_count.py -x` | No — Wave 0 |
| TREND-01 | Live open count match (compare `open_findings_at(df, today)` count to `df[df.state.isin(["open","reopened"])]`) | content | `pytest tests/content/test_trend_store.py::test_live_count_match -x` | No — Wave 0 |
| TREND-02 | Atomic write produces valid JSON at target path | content | `pytest tests/content/test_trend_store.py::test_capture_writes_file -x` | No — Wave 0 |
| TREND-03 | MS file `management_summary_all_assets.json` is not modified by substrate capture | content | `pytest tests/content/test_trend_store.py::test_ms_file_untouched -x` | No — Wave 0 |
| TREND-04 | `read_trend` with 0 snapshots returns `{snapshots: [], insufficient_data: True}` without raising | content | `pytest tests/content/test_trend_store.py::test_cold_start_read -x` | No — Wave 0 |
| TREND-05 | Running `capture_snapshot` twice for the same month produces exactly one snapshot entry | content | `pytest tests/content/test_trend_store.py::test_idempotent_overwrite -x` | No — Wave 0 |
| TREND-05 | Running `capture_snapshot` for a second month appends without touching the first | content | `pytest tests/content/test_trend_store.py::test_second_month_appends -x` | No — Wave 0 |
| TREND-06 | Snapshot file contains no hostname, ipv4, plugin_name, asset_uuid fields | content | `pytest tests/content/test_trend_store.py::test_no_pii_in_snapshot -x` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest tests/unit/test_open_count.py -q`
- **Per wave merge:** `pytest -q` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/unit/test_open_count.py` — labelled OPEN/REOPENED/FIXED cases (TREND-01)
- [ ] `tests/content/test_trend_store.py` — snapshot write/read/idempotency/PII/cold-start (TREND-02..06)
- [ ] No new framework install needed — pytest already in project

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| pytest | TREND-01 tests | Yes (in project) | see requirements.txt | — |
| pandas | predicate + capture | Yes | see requirements.txt | — |
| fastparquet | cache round-trip in tests | Yes | see requirements.txt | — |
| `data/trend/` directory | snapshot write | Created at runtime (`mkdir parents=True`) | — | — |

No missing dependencies.

---

## Security Domain

No new attack surface introduced. Phase 12 writes aggregate-count JSON files to a local gitignored directory. No network endpoints, no user input parsed, no credentials added.

ASVS V6 (Cryptography): Not applicable — no cryptographic operations.
ASVS V5 (Input Validation): The `month_str` and `tag_filter` values written to JSON are derived from internal computation (local `datetime.now()` and a locked constant `"all_assets"`), not from user input. No validation needed for Phase 12; Phase 13 tag iteration will need to validate that `tag_filter` is sanitized before use in filename (the `_sanitise_tag_for_filename` pattern already handles this).

PII compliance is enforced by construction: the snapshot payload `{month, tag_filter, critical, high, medium, low, asset_count, generated_at}` contains no row-level fields. TREND-06 unit test confirms this by inspecting the written file for the absence of PII field names.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The Tenable API returns `state` values in lowercase (`"open"`, `"reopened"`, `"fixed"`) based on evidence from `_OPEN_STATES = frozenset({"open", "reopened"})` in MS | Code Examples — state casing | Predicate returns wrong counts; caught immediately by TREND-01 unit tests if fixtures use real casing |
| A2 | `os.replace` on Windows is atomic when source and dest are on the same filesystem | Pattern 3 — Atomic Write | On a network drive or cross-device write, `os.replace` would fail with `OSError`; in practice `data/trend/` is always local |

---

## Open Questions (RESOLVED)

1. **State column casing**
   - What we know: MS uses lowercase `{"open", "reopened"}`; spike blueprint uses uppercase `"FIXED"`/`"REOPENED"` in comparisons
   - What's unclear: Whether the API returns lowercase consistently or mixed-case
   - Recommendation: Use `st.str.upper()` in the predicate for safety; TREND-01 unit tests should use lowercase state values matching the fetcher's actual output (which mirrors MS's `_OPEN_STATES`)

2. **`--date` vs `--month` flag naming in entry point**
   - What we know: `warm_cache.py` uses `--date YYYY-MM-DD` for the cache folder; the snapshot entry point needs a month target (`YYYY-MM`)
   - What's unclear: Whether a single `--date YYYY-MM-DD` flag (inferring month from it) is cleaner than separate `--month YYYY-MM` + `--date YYYY-MM-DD`
   - Recommendation: Use `--month YYYY-MM` (defaults to `datetime.now().strftime("%Y-%m")`) and retain `--date YYYY-MM-DD` for cache folder override, matching `warm_cache.py`'s flag vocabulary

---

## Sources

### Primary (HIGH confidence — direct codebase inspection)

- `reports/management_summary.py` lines 85–250, 700–766 — TREND_DIR, `_trend_file_path`, `_load_trend_history`, `_save_trend_snapshot`, `_compute_metric_7`, `_OPEN_STATES`
- `data/fetchers.py` lines 284–375, 1161–1176 — open+reopened export column names and types, `_normalize_vuln_dates`, `resurfaced_date` field
- `utils/sla_calculator.py` — placement precedent, UTC timezone handling, empty-DataFrame guard pattern
- `scripts/warm_cache.py` — complete entry point template: logging, exit codes, argparse, `_log_started`/`_log_completed`, `RotatingFileHandler`
- `tests/conftest.py`, `tests/fixtures/builders.py`, `tests/unit/test_modules.py`, `tests/content/test_values.py` — test conventions, fixture shape, `pytestmark`, layer taxonomy
- `pytest.ini` — `testpaths`, markers (`unit`, `content`, `e2e`), `addopts`
- `config.py` — `CACHE_DIR`, `vpr_to_severity`, `SLA_DAYS`

### Primary (HIGH confidence — spike artifacts)

- `.claude/skills/spike-findings-vuln-reporting/references/vuln-metric-substrate.md` — two-interval predicate algorithm (lines 44–54), ~29-day retention constraint (line 74), snapshot-not-reconstruction rationale (lines 59–69)

---

## Metadata

**Confidence breakdown:**
- Predicate algorithm: HIGH — spike blueprint is exact, cross-validated against real data (+2 of 160,453)
- Column names and types: HIGH — confirmed by direct codebase inspection of `fetchers.py` and `_normalize_vuln_dates`
- MS JSON shape: HIGH — extracted verbatim from `_save_trend_snapshot` source
- Atomic write pattern: HIGH — stdlib `os.replace` + `tempfile.mkstemp` is the standard approach
- Entry point structure: HIGH — `warm_cache.py` is a complete working template in the repo
- Test layout: HIGH — `pytest.ini` and existing test files establish the exact conventions

**Research date:** 2026-06-06
**Valid until:** 2026-07-06 (stable codebase; only invalidated if MS trend helpers are refactored before Phase 12 ships)
