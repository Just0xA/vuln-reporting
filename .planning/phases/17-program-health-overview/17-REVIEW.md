---
phase: 17-program-health-overview
reviewed: 2026-06-13T00:14:00Z
depth: standard
files_reviewed: 6
files_reviewed_list:
  - data/trend_store.py
  - scripts/capture_trend_snapshot.py
  - reports/modules/program_health_module.py
  - reports/composed_report.py
  - tests/content/test_trend_store.py
  - tests/test_program_health_module.py
findings:
  critical: 0
  warning: 5
  info: 6
  total: 11
status: issues_found
---

# Phase 17: Code Review Report

**Reviewed:** 2026-06-13T00:14:00Z
**Depth:** standard
**Files Reviewed:** 6
**Status:** issues_found

## Summary

Phase 17 adds the `program_health` four-channel module plus a new `sla_rate_crit_high`
trend-snapshot field. The work is high quality: the OD-5 composite RAG logic is correct
and well-tested, the missing-signal Amber cap is structurally enforced and unbypassable,
cold-start paths return coherent `ModuleData` without crashing, HTML escaping is applied
consistently to owner/tag/display strings, and aggregate-only / no-PII discipline is
honored throughout. Empty-data guards and fail-soft try/except wrapping are present at
every required boundary.

No BLOCKER-class defects were found — no injection, no credential exposure, no crash on
empty/cold-start data, no PII leakage. However, there is one **consistent correctness
defect** worth fixing: the SLA-posture rate (computed in three places) silently inflates
its denominator with `first_found=NaT` rows that can never land in the numerator,
biasing the rate downward. This is replicated verbatim across the capture script, the
cold-start path, and the live tile, so it is a single root cause with three sites.
Remaining findings are robustness and consistency improvements.

## Warnings

### WR-01: SLA-posture rate counts `first_found=NaT` rows in the denominator but never the numerator (downward bias)

**Files:**
- `scripts/capture_trend_snapshot.py:396-408`
- `reports/modules/program_health_module.py:255-273` (cold-start)
- `reports/modules/program_health_module.py:519-536` (live tile)

**Issue:** `open_findings_at()` deliberately **includes** findings whose `first_found`
is `NaT` (born = `df["first_found"].isna() | (first_found <= D)` — see
`utils/open_count.py:82` and its WR-02 note). The downstream SLA computation then does:

```python
days_open = (snap_ts - pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")).dt.days
within = days_open <= sla_days_col            # capture script also ANDs days_open.notna()
sla_rate = round(float(within.sum()) / len(ch_df) * 100, 1)
```

For a NaT `first_found`, `days_open` is `NaN`, so `NaN <= sla_days` evaluates `False` —
the row is **excluded from the numerator** (`within.sum()`) but **still counted in the
denominator** (`len(ch_df)`). A Crit+High finding that `open_findings_at` deemed open is
therefore treated as "out of SLA" purely because its `first_found` is missing. This
biases the published SLA rate downward and is inconsistent with `open_count.py`'s
explicit "missing first_found is not grounds to drop a finding" policy.

Note the capture-script site at line 406 adds `days_open.notna()` to the `within` mask,
which makes the *intent* (exclude from numerator) explicit but still leaves the NaT row
in the denominator — so all three sites share the same denominator bias.

**Fix:** Decide a single policy and apply it identically to all three sites. Recommended:
exclude NaT-`first_found` rows from **both** numerator and denominator so the rate is
computed only over findings whose SLA status is actually knowable:

```python
ff = pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
days_open = (snap_ts - ff).dt.days
known = ff.notna()
denom = int(known.sum())
if denom > 0:
    within = known & (days_open <= sla_days_col)
    sla_rate = round(float(within.sum()) / denom * 100, 1)
else:
    sla_rate = None   # no SLA-classifiable findings → cold-start the field
```

This also removes the divide-shape edge where every Crit+High row is NaT (currently
`len(ch_df) > 0` but numerator 0 → a misleading 0.0%).

---

### WR-02: `sla_map`/`sla_days_col` NaN from an unmapped severity silently drops rows from the numerator

**Files:**
- `reports/modules/program_health_module.py:269-270` (cold-start)
- `reports/modules/program_health_module.py:532-533` (live tile)
- `scripts/capture_trend_snapshot.py:405-406` (capture; partly guarded)

**Issue:** `sla_map = ch_df["severity"].str.lower().map(SLA_DAYS)` returns `NaN` for any
severity string not in `SLA_DAYS` ("critical"/"high"/"medium"/"low"). The Crit+High
filter uses `.isin(["critical", "high"])`, so in normal data every row maps. But the
comparison `within = days_open <= sla_map` is not NaN-guarded in the two module sites
(only the capture script at line 406 ANDs `sla_days_col.notna()`). If a severity value
ever carries unexpected casing/whitespace that passes `.isin()` after `.str.lower()` but
fails the `SLA_DAYS` lookup (e.g. a trailing space — `.str.lower()` does not strip), the
row contributes `NaN <= NaN` → `False`, again inflating the denominator without a
matching numerator. The two module sites are inconsistent with the capture script's own
guard.

**Fix:** Mirror the capture script's guard in both module sites:
`within = days_open.notna() & sla_map.notna() & (days_open <= sla_map)`, and pair it
with the WR-01 denominator fix so unmappable rows do not skew the rate.

---

### WR-03: `_signal_direction` treats a snapshot `NaN` value as a real number, not "missing"

**File:** `reports/modules/program_health_module.py:174-180`

**Issue:** The guard is `if curr is None or prev is None: return "missing"`. Snapshot
fields are normally `int`/`float`/`None` after JSON round-trip, so `None` is the expected
absent sentinel and this is correct for JSON-sourced data. However, `curr`/`prev` for
Signals 1 and 4 come straight from `snap.get("critical")` / `snap.get("mttr_overall_days")`,
and the net-velocity path constructs floats. If any upstream ever yields a `float('nan')`
(e.g. a pandas-derived value that was JSON-serialized as `NaN` — Python's `json.dump`
emits bare `NaN`, which `json.load` reads back as `float('nan')`), then `nan is None` is
`False`, `delta = nan - x = nan`, and `abs(nan) <= flat_band` is `False`, so the signal
is silently classified `"red"` (worsened) instead of `"missing"`. That would un-cap the
composite and mislabel a data gap as a regression.

**Fix:** Broaden the guard to cover NaN:

```python
if curr is None or prev is None or pd.isna(curr) or pd.isna(prev):
    return "missing"
```

(`pd` is already imported in this module.) This aligns `_signal_direction` with the
`pd.isna`-based discipline used everywhere else in the suite (`format_utils`).

---

### WR-04: Net-velocity sparkline series silently coerces missing months to 0 via `s.get(..., 0)`

**File:** `reports/modules/program_health_module.py:559-566`

**Issue:** The net-velocity sparkline builder uses
`float(s.get("new_findings_count", 0)) - float(s.get("fixed_findings_count", 0))` inside
a branch already gated on both being non-`None`. The `, 0` defaults are dead for the
`None` case (the `if` guards it), but they are actively wrong if a key is **present with
value `None`** vs **absent** — `s.get("new_findings_count")` returns `None` for a present
null key, the guard catches it, and the point becomes `None` (correct). The concern is
narrower: the `, 0` default is misleading because elsewhere (Signal 2 at lines 451-461)
the same data is treated as `None`-means-missing. A reader could reasonably copy the
sparkline pattern (default-to-0) into a place where it produces a fabricated 0 instead of
a gap. The two representations of "no net-velocity data" diverge.

**Fix:** Drop the `, 0` defaults and rely solely on the `is not None` guard so the
sparkline gap semantics match Signal 2:

```python
(float(s.get("new_findings_count")) - float(s.get("fixed_findings_count")))
if s.get("new_findings_count") is not None and s.get("fixed_findings_count") is not None
else None
```

---

### WR-05: `analyst_df` rounds `mom_delta_pct` without NaN-guarding, and prev-owner extraction can miscount on int-typed metadata

**File:** `reports/modules/program_health_module.py:625-633, 793-796`

**Issue (a):** At lines 793-796 the analyst frame does
`round(r["mom_delta_pct"], 1) if r["mom_delta_pct"] is not None else None`. `mom_delta_pct`
is only ever set to a Python float or `None` in the owner-rows builder (lines 649/653/657),
so this is currently safe — but it relies on the builder never emitting `NaN`. If
`prev_cnt` were ever a float `0.0` reaching line 649, `mom_delta / prev_cnt` would raise
`ZeroDivisionError` only for ints, not floats (floats give `inf`), and `round(inf, 1)` is
`inf` which serializes oddly. The `prev_cnt > 0` guard at line 647 prevents the zero case
for the values currently produced, so this is defensive only.

**Issue (b) — the real concern:** Previous-month owner counts are reconstructed by
iterating `prev_snap.items()` and keeping any key not in a hardcoded metadata-key
blocklist **whose value `isinstance(val, int)`** (lines 625-632). This is fragile in two
ways: (1) the blocklist must be manually kept in sync with every field
`capture_snapshot` writes — it already lists 15 keys and will silently misattribute any
future snapshot field as an "owner" if that field is int-typed; (2) an owner literally
named one of the blocklist tokens (e.g. an Owner tag value `"asset_count"`) would be
dropped from the previous-month map, zeroing its baseline and falsely flagging it as a
new outlier.

**Fix:** Owner snapshots are written by `_count_by_owner` as a flat `{owner: int}` map
merged with metadata. Rather than blocklisting metadata keys, prefer an allowlist driven
by the current-month owner set, or have `capture_snapshot` nest owner counts under a
dedicated `"owner_counts"` sub-dict so the reader needs no blocklist. At minimum, extract
the metadata-key set into a shared module-level constant referenced by both
`capture_snapshot` and this reader so the two cannot drift.

---

## Info

### IN-01: `read_trend` redundant tag_filter re-filter is genuinely dead in the happy path

**File:** `data/trend_store.py:468-476`

**Issue:** The file is already tag-scoped by filename (`trend_{dim}_{tag_filter}.json`), so
the `relevant = [s for s in all_snaps if s.get("tag_filter") == tag_filter]` filter only
ever drops rows when the stored field and filename suffix diverge. The code documents this
and logs a warning, which is the right call — noting only that the filter is otherwise pure
overhead per read. No change required; flagged for awareness.

### IN-02: `_log_completed` "partial" owner-snapshot status is logged but not surfaced to the delivery log

**File:** `scripts/capture_trend_snapshot.py:450-457`

**Issue:** WR-03 (prior phase) correctly returns exit 0 when only the owner snapshot
fails, logging `status=partial`. That partial status lands only in the rotating logfile,
not in any structured channel a scheduler could alert on. Acceptable for a cron job whose
primary deliverable (severity snapshot) succeeded; consider emitting a metric/sentinel if
owner-trend gaps ever need monitoring.

### IN-03: `int(config.options.get("green_count_min", 4))` at compute is redundant after `validate_config`

**File:** `reports/modules/program_health_module.py:384-391`

**Issue:** `validate_config()` (called at line 384) already coerces and defaults all six
numeric options, so the per-option `int(...)`/`float(...)` re-coercion at lines 386-391 is
belt-and-suspenders. Harmless and arguably defensive, but the `.get(key, default)` second
arg can never fire because `validate_config` guarantees the key exists. Could be simplified
to plain reads for clarity.

### IN-04: `_render_sparkline_b64` accepts `arrow_color` parameter that is applied to the title, not an arrow

**File:** `reports/modules/program_health_module.py:842-904`

**Issue:** The parameter is named `arrow_color` but is used as `ax.set_title(..., color=arrow_color)`
(line 895) — it colors the entire title line (label + value + arrow), not just the arrow
glyph. The naming implies finer-grained control than exists. Cosmetic; rename to
`title_color` for accuracy.

### IN-05: Net-velocity "flat band = 0.0" still produces Amber on exact equality, contradicting the "binary; no flat band" docstring

**File:** `reports/modules/program_health_module.py:446-467` and `144-180`

**Issue:** The docstring (lines 447-450, 1581) states net velocity is "binary; no flat
band." But `_signal_direction(flat_band=0.0)` uses `abs(delta) <= flat_band`, so
`curr_net == prev_net` exactly yields `abs(0) <= 0` → `"amber"`, not green/red. So there
IS a degenerate one-point flat band at exact equality. This is defensible behavior (a
genuinely unchanged backlog velocity is neither improving nor worsening) but the
"binary; no flat band" wording overstates. Align the comment with the actual behavior.

### IN-06: Duplicated SLA-tile computation block across cold-start and live paths

**File:** `reports/modules/program_health_module.py:258-273` and `523-536`

**Issue:** The reopened-aware Crit+High SLA-rate computation is copy-pasted nearly
verbatim in `_build_cold_start_result` and the main `compute()` live-tile section (and a
third near-copy in `capture_trend_snapshot.py:396-408`). Any fix to WR-01/WR-02 must be
applied in all three places, and they have already drifted (the capture script has the
`.notna()` guards the module copies lack). Extracting a single
`_sla_rate_crit_high(open_df, snap_ts) -> Optional[float]` helper would collapse the
divergence and make the WR-01/WR-02 fixes single-site. Project convention (CLAUDE.md:
"If you notice unrelated dead code, mention it — don't delete it") supports flagging
rather than refactoring inline.

---

_Reviewed: 2026-06-13T00:14:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
