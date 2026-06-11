---
phase: 12-trend-snapshot-substrate-s1
reviewed: 2026-06-08T21:06:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - utils/open_count.py
  - tests/unit/test_open_count.py
  - data/trend_store.py
  - tests/content/test_trend_store.py
  - scripts/capture_trend_snapshot.py
findings:
  critical: 0
  warning: 5
  info: 6
  total: 11
status: issues_found
---

# Phase 12: Code Review Report

**Reviewed:** 2026-06-08T21:06:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

Reviewed the Phase 12 trend-snapshot substrate: the pure-compute open-finding
predicate (`utils/open_count.py`), the forward-accumulating snapshot engine with
atomic JSON writes (`data/trend_store.py`), the cron entry point
(`scripts/capture_trend_snapshot.py`), and their two test modules.

Overall the substrate is well-structured: the atomic-write fd-close ordering is
correct, the empty-data guard is genuine, PII discipline holds (only aggregate
counts and an asset count are serialized), and the timezone policy (month key
local, `generated_at` UTC) is implemented as specified. The reopened-aware
two-interval predicate matches the documented model and its labelled tests are
sound.

No BLOCKER-class defects were proven. However, several correctness edge cases
escape both the predicate's clauses and its test coverage — chiefly the
treatment of `FIXED`/`REOPENED` rows with a missing `last_fixed` date, which are
silently counted as **open** and would inflate trend counts on real Tenable data.
These are classified WARNING because they degrade count correctness without
crashing or leaking data. There is also a latent timezone-consistency bug in the
cron script's `--month` path and a redundant double-filter in `read_trend`.

## Warnings

### WR-01: FIXED finding with NaT `last_fixed` is counted as OPEN

**File:** `utils/open_count.py:82-86`
**Issue:** The `fixed` mask requires `lf.notna() & (lf <= D)` on every clause.
A row with `state == "fixed"` but `last_fixed == NaT` therefore evaluates
`fixed == False` and — being born before `D` — is returned as **open**. Tenable
exports do occasionally carry a `fixed` state with a missing/empty `last_fixed`
(the fetcher stores `vuln.get("last_fixed", "")` at `data/fetchers.py:352`, which
`_parse_iso_utc` coerces to `NaT`). The result is silent over-counting of open
findings — the exact direction of error this phase exists to *prevent*. No test
exercises a FIXED-with-NaT-last_fixed row; `test_fixed_state_excluded` only covers
the well-formed case.
**Fix:** Treat a `FIXED` state as closed regardless of `last_fixed` presence
(state is authoritative for terminal-fixed), e.g.:
```python
fixed = (
    (st == "FIXED")
    | ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.notna() & (D < rs))
    | ((st == "REOPENED") & lf.notna() & (lf <= D) & rs.isna())
)
```
If the intent is genuinely "only exclude FIXED once its fix date has passed,"
document that decision and add a labelled test for the NaT case so the behavior
is deliberate rather than incidental.

### WR-02: `first_found == NaT` silently drops the finding

**File:** `utils/open_count.py:69`
**Issue:** `born = df["first_found"] <= D` evaluates to `False` for any row whose
`first_found` is `NaT` (comparisons against NaT are always False). Such a row is
excluded from the open set unconditionally — even if it is plainly an `open`
finding. On real data a missing `first_found` is rare but possible, and the
fetcher's `vuln.get("first_found", "")` path can produce `NaT`. The finding is
dropped with no log line, undercounting opens. No test covers a NaT `first_found`.
**Fix:** Decide and document the policy. Either count NaT-`first_found` opens as
present (`born = df["first_found"].isna() | (df["first_found"] <= D)`) or log a
warning with the dropped-row count so the silent loss is observable:
```python
missing = df["first_found"].isna().sum()
if missing:
    logger.warning("open_findings_at: %d rows dropped (first_found is NaT)", missing)
```

### WR-03: `state.str.upper()` raises if the `state` column is non-string dtype

**File:** `utils/open_count.py:72`
**Issue:** `df["state"].str.upper()` assumes an object/string Series. The fetcher
guarantees a string today, but the predicate's docstring advertises it as a
general, reusable pure-compute utility ("safe against any future casing
variation"). If a caller passes a `state` column that pandas has inferred as a
non-object dtype (e.g. all-NaN float, or categorical), `.str.upper()` raises
`AttributeError`/returns all-NaN, and a NaN state silently falls through to
"open". A NaN in `st` makes every `(st == "FIXED")` comparison False, so the row
is treated as open.
**Fix:** Coerce defensively: `st = df["state"].astype("string").str.upper()` and
treat NaN/empty state explicitly (decide open vs. excluded), rather than relying
on the comparison-with-NaN fall-through.

### WR-04: `--month` snapshot path can write the wrong month key vs. the default path (timezone inconsistency)

**File:** `scripts/capture_trend_snapshot.py:239-242`
**Issue:** When `--month` is supplied, `snapshot_date = datetime.strptime(month_str + "-01", "%Y-%m-%d")` — a **tz-naive midnight** on day 01. When `--month` is omitted, `snapshot_date = datetime.now()` — tz-naive *local wall clock*. Both feed `capture_snapshot`, where `date.strftime("%Y-%m")` derives the month key. The two paths therefore disagree on what "now" means: a job that runs at 23:30 local on the last day of a month with no `--month` flag will key the snapshot to the *current* local month, but the documented cron intent ("first day of each month") relies on the operator either trusting local-now or passing `--month`. More concretely, because `snapshot_date` from `--month` is a *naive* datetime while `open_findings_at` coerces naive → **UTC** (`open_count.py:62-66`), the point-in-time `D` for a `--month 2026-06` run becomes `2026-06-01T00:00:00Z`, not local midnight. The month *key* is local-derived but the *open-set cutoff* is UTC-derived from a naive local timestamp — these are silently mixed.
**Fix:** Make the cutoff explicit and consistent. Construct the snapshot reference as an explicit local-or-UTC datetime and document which boundary the open-set uses, e.g. pass a tz-aware `D` and derive the month key from the same instant:
```python
if args.month:
    snapshot_date = datetime.strptime(month_str + "-01", "%Y-%m-%d")
else:
    snapshot_date = datetime.now()
logger.info("Snapshot reference date (naive→UTC in predicate): %s", snapshot_date)
```
At minimum, log the resolved `snapshot_date` so the local-vs-UTC cutoff is auditable, and add a comment that the open-set boundary is UTC midnight for `--month` runs.

### WR-05: `read_trend` filters by `tag_filter` twice but the file is already tag-scoped — masks a real mismatch

**File:** `data/trend_store.py:283-290`
**Issue:** The file path is built from `tag_filter` (`trend_{dimension}_{tag_filter}.json`, line 283), so the file only ever contains entries for that one tag scope. The subsequent `relevant = [s for s in all_snaps if s.get("tag_filter") == tag_filter]` (line 288) is therefore redundant in the happy path — but it is *silently lossy* if the file's entries ever carry a `tag_filter` value that differs from the filename suffix (e.g. a Phase-13 sanitised suffix where `"Environment/Prod"` → filename `Environment_Prod` but the stored `tag_filter` field is the raw `"Environment/Prod"`). In that case `read_trend` returns **zero** snapshots and reports `insufficient_data=True` with no warning, even though the file is fully populated. `capture_snapshot` writes `tag_filter` verbatim into the entry (line 220) while the filename uses the same string only because Phase 12 happens to pass `"all_assets"` for both. The filename/field coupling is an undocumented invariant.
**Fix:** Either drop the redundant filter (trust the filename scoping) or assert the invariant and log when the filter removes rows:
```python
relevant = [s for s in all_snaps if s.get("tag_filter") == tag_filter]
if all_snaps and not relevant:
    logger.warning(
        "read_trend: %d entries in %s but none match tag_filter=%r "
        "(filename/field mismatch?)", len(all_snaps), file_path, tag_filter,
    )
```

## Info

### IN-01: `_atomic_write_json` is not atomic against concurrent same-month captures

**File:** `data/trend_store.py:119-145, 234-245`
**Issue:** `capture_snapshot` does read-modify-write (load list, mutate, write) with no lock. Two near-simultaneous captures for the same `(dimension, tag_filter)` can interleave such that one overwrites the other's appended entry (lost update). The `os.replace` is atomic, but the read-modify-write around it is not. Low risk given the cron-driven once-per-month invocation, but worth a noted assumption.
**Fix:** Document the single-writer assumption in the `capture_snapshot` docstring, or add a sidecar lockfile if concurrent invocation ever becomes possible.

### IN-02: `_load_trend_json` swallows all parse errors as empty → silent data loss on next write

**File:** `data/trend_store.py:100-116, 235`
**Issue:** If a trend file exists but is corrupt/unparseable, `_load_trend_json` logs a warning and returns `[]`. `capture_snapshot` then appends one entry and `_atomic_write_json` **overwrites the corrupt file**, permanently discarding all prior (possibly recoverable) snapshots. The warning is the only trace.
**Fix:** On parse failure, consider preserving the corrupt file (rename to `*.corrupt`) before overwriting, so history is recoverable. At minimum, escalate the log level to ERROR since this path destroys accumulated trend history.

### IN-03: Exit-code contract for `--help` is convoluted

**File:** `scripts/capture_trend_snapshot.py:194-196`
**Issue:** `code = e.code if isinstance(e.code, int) else 2; return code if code != 0 else 0`. The final `if code != 0 else 0` is a no-op for the int branch (returning 0 when code is 0 is identical to returning code). The non-int branch maps `None`→2 correctly, but `--help` exits with `SystemExit(0)` (int), so it returns 0 — fine, but the ternary obscures intent.
**Fix:** Simplify to `return e.code if isinstance(e.code, int) else 2`.

### IN-04: Unused import `pandas as pd` only used in type hints / smoke block

**File:** `utils/open_count.py:14`
**Issue:** Not a defect — `pd` is used in the body and smoke block. Flagging only that the `# noqa: F821` forward-ref hack at lines 99 and 308 (`"pd.Timestamp | pd.NaT"` / `"pd.Timestamp | type(pd.NaT)"`) is fragile: `pd.NaT` is a value, not a type, so the annotation string is not a valid type expression and exists purely to silence linters.
**Fix:** Use a real return annotation (`pd.Timestamp | None`) or drop the annotation on the nested helper; the `noqa` masks a genuinely invalid type string.

### IN-05: Docstring claims `data` is a list but `_load_trend_json` assumes a dict

**File:** `data/trend_store.py:111-113`
**Issue:** `data = json.load(fh); return data.get("snapshots", [])` assumes the top-level JSON is an object. If a trend file's root is a JSON list (legacy/hand-edited), `list.get` raises `AttributeError`, caught by the broad `except` and logged as "Could not load," silently returning `[]` and then overwriting the file (see IN-02). The function's return type annotation (`list[dict]`) is correct, but the implicit "root must be an object" contract is undocumented.
**Fix:** Add a one-line comment that the root must be `{"snapshots": [...]}` and that any other shape is treated as empty.

### IN-06: `asset_count` semantics are scope-ambiguous in Phase 12

**File:** `data/trend_store.py:213`
**Issue:** `asset_count = int(len(assets_df))` records the count of *all* rows in the passed `assets_df`. For Phase 12 (`all_assets`) this is correct, but D-04 says "in-scope asset count." When Phase 13 introduces tag filtering, the contract assumes the caller pre-filters `assets_df` to the tag scope before calling `capture_snapshot`. Nothing in this function enforces or documents that the *vulns* `df` and the *assets* `assets_df` are filtered to the same scope, so a mis-wired Phase 13 caller could record open counts for one scope and an asset count for another with no error.
**Fix:** Note explicitly in the docstring that `df` and `assets_df` must already be filtered to the same tag scope; the function does no scoping of its own.

---

_Reviewed: 2026-06-08T21:06:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
