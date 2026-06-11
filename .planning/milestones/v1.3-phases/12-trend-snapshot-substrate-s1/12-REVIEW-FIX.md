---
phase: 12-trend-snapshot-substrate-s1
fixed_at: 2026-06-10T11:50:00Z
review_path: .planning/phases/12-trend-snapshot-substrate-s1/12-REVIEW.md
iteration: 1
findings_in_scope: 11
fixed: 11
skipped: 0
status: all_fixed
---

# Phase 12: Code Review Fix Report

**Fixed at:** 2026-06-10T11:50:00Z
**Source review:** .planning/phases/12-trend-snapshot-substrate-s1/12-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 11 (5 warning + 6 info, fix_scope=all)
- Fixed: 11
- Skipped: 0

**Test results:** `python -m pytest tests/unit/test_open_count.py tests/content/test_trend_store.py -q` → **22 passed** (run with `.venv/Scripts/python.exe`; the default `C:\Python314` interpreter has no pytest). Both module smoke blocks (`python utils/open_count.py`, `python data/trend_store.py`) also pass.

## Fixed Issues

### WR-01: FIXED finding with NaT `last_fixed` is counted as OPEN

**Files modified:** `utils/open_count.py`, `tests/unit/test_open_count.py`
**Commit:** 71207e6
**Applied fix:** Adopted the review's recommended decision — a terminal `FIXED` state is authoritative for "closed" regardless of `last_fixed` presence. Changed clause 1 of the `fixed` mask from `((st == "FIXED") & lf.notna() & (lf <= D))` to a bare `(st == "FIXED")`, with an inline comment explaining the over-count rationale and the fetcher's `vuln.get("last_fixed", "")` → NaT path. Added a labelled test `test_fixed_state_nat_last_fixed_excluded` covering a FIXED row with `last_fixed=NaT` (now correctly excluded).

### WR-02: `first_found == NaT` silently drops the finding

**Files modified:** `utils/open_count.py`, `tests/unit/test_open_count.py`
**Commit:** 71207e6
**Applied fix:** Made the documented policy decision: a missing `first_found` is not grounds to drop an otherwise-open finding. Changed `born = df["first_found"] <= D` to `born = df["first_found"].isna() | (df["first_found"] <= D)` and added a `logger.warning` reporting the dropped/coerced row count so the data-quality issue is observable. Errs toward inclusion, consistent with WR-01's over-count-prevention intent. Added labelled test `test_nat_first_found_open_included`.

### WR-03: `state.str.upper()` raises if the `state` column is non-string dtype

**Files modified:** `utils/open_count.py`, `tests/unit/test_open_count.py`
**Commit:** 71207e6
**Applied fix:** Coerced defensively with `st = df["state"].astype(str).str.upper()` (per the prior-session-validated approach and the task's explicit guidance), NOT `.astype("string")`. Rationale documented in an inline comment: `.astype(str)` keeps regular Python-str comparisons; a genuine NaN state stringifies to `"NAN"`, matches no terminal-state clause, and falls through to "open" (safe default). `.astype("string")` was deliberately avoided because its nullable-NA semantics would propagate `<NA>` through the `==` comparisons. Added labelled test `test_non_string_state_dtype_does_not_raise` that forces an all-NaN float `state` column and confirms no `AttributeError` and a fall-through-to-open result.

### WR-04: `--month` snapshot path can write the wrong month key vs. the default path (timezone inconsistency)

**Files modified:** `scripts/capture_trend_snapshot.py`
**Commit:** 8f46e44
**Applied fix:** Made the local-vs-UTC cutoff explicit and auditable. Added a block comment documenting that the month KEY is local-derived (`date.strftime("%Y-%m")`) while the open-set CUTOFF `D` is UTC-derived (a `--month 2026-06` run cuts at `2026-06-01T00:00:00Z`), and noting this is acceptable for monthly snapshots. Added a `logger.info` that logs the resolved `snapshot_date` (ISO) and the month key so the cutoff is auditable in the logfile. Kept the existing naive-datetime behavior deliberately (documented), per the review's "at minimum" recommendation.

### WR-05: `read_trend` filters by `tag_filter` twice but the file is already tag-scoped

**Files modified:** `data/trend_store.py`
**Commit:** 92990ae
**Applied fix:** Retained the redundant `tag_filter` filter as a guard but made it observable: when `all_snaps` is non-empty yet `relevant` is empty, log a warning naming the file, entry count, and `tag_filter` (the filename/field-mismatch case from the review). Documented the filename/field coupling invariant in a comment so a Phase-13 caller that diverges the two no longer triggers a silent `insufficient_data=True` on a populated file.

### IN-01: `_atomic_write_json` is not atomic against concurrent same-month captures

**Files modified:** `data/trend_store.py`
**Commit:** 92990ae
**Applied fix:** Documented the SINGLE-WRITER assumption in a new "Concurrency (IN-01)" docstring section on `capture_snapshot`: the read-modify-write around the atomic `os.replace` is not itself locked, so two concurrent captures for the same `(dimension, tag_filter)` could lose an update; safe under once-per-month cron, add a sidecar lockfile if concurrent invocation becomes possible.

### IN-02: `_load_trend_json` swallows all parse errors as empty → silent data loss on next write

**Files modified:** `data/trend_store.py`
**Commit:** 92990ae
**Applied fix:** On parse failure, the corrupt file is now renamed (best-effort) to `*.corrupt` before returning `[]`, so the subsequent read-modify-write in `capture_snapshot` cannot overwrite and permanently discard recoverable history. Escalated the log level from WARNING to ERROR (this path otherwise destroys accumulated trend history). A secondary ERROR is logged if the rename itself fails.

### IN-03: Exit-code contract for `--help` is convoluted

**Files modified:** `scripts/capture_trend_snapshot.py`
**Commit:** 8f46e44
**Applied fix:** Simplified `return code if code != 0 else 0` (preceded by the `code = ...` assignment) to a single `return e.code if isinstance(e.code, int) else 2`, with a clarifying comment. Behavior is identical for all branches (int passes through, None → 2) but intent is now clear.

### IN-04: fragile `# noqa: F821` forward-ref type string

**Files modified:** `utils/open_count.py`
**Commit:** 71207e6
**Applied fix:** Replaced the invalid annotation string `"pd.Timestamp | pd.NaT"  # noqa: F821` on the smoke-block `_ts` helper with a real annotation `pd.Timestamp | None`, removing the lint-silencing hack. (`pd.NaT` is a value, not a type.) The `data/trend_store.py` smoke block carries the same pattern at line 308 but it was not flagged by the finding — left untouched per surgical-change scope; mentioned here for awareness.

### IN-05: Docstring claims `data` is a list but `_load_trend_json` assumes a dict

**Files modified:** `data/trend_store.py`
**Commit:** 92990ae
**Applied fix:** Added a "Contract (IN-05)" docstring paragraph plus an inline comment documenting that the file root must be `{"snapshots": [...]}` and that any other shape (a bare list, scalar, etc.) raises on `.get` and is handled as a parse failure (now via the IN-02 corrupt-file path).

### IN-06: `asset_count` semantics are scope-ambiguous in Phase 12

**Files modified:** `data/trend_store.py`
**Commit:** 92990ae
**Applied fix:** Documented in the `capture_snapshot` docstring (`df` and `assets_df` parameter descriptions) that both arguments MUST already be filtered to the same tag scope by the caller; the function does no scoping of its own and records open counts from `df` and the asset count from `assets_df` verbatim. Pre-empts a mis-wired Phase-13 caller silently recording mismatched-scope counts.

## Skipped Issues

None — all 11 in-scope findings were fixed.

---

## Notes for human verification

- **WR-01, WR-02, WR-03** changed tested predicate behavior. Each has a new labelled test and all 22 tests pass, but the underlying decisions are policy choices (terminal-FIXED authority; NaT-`first_found` counted-as-present-with-warning; NaN-state falls through to open). Confirm these policies match the intended trend-count semantics before the phase proceeds.
- **WR-04** deliberately preserves the existing naive-datetime / UTC-cutoff behavior and only makes it documented and auditable (the review's "at minimum" option). If you want local-midnight cutoffs for `--month` runs instead, that is a behavior change beyond this finding's scope.

---

_Fixed: 2026-06-10T11:50:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
