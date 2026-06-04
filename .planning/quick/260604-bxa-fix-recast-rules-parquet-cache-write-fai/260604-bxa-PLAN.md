---
phase: quick-260604-bxa
plan: 01
type: execute
wave: 1
depends_on: []
files_modified: [data/fetchers.py]
autonomous: true
requirements: [QUICK-260604-bxa]

must_haves:
  truths:
    - "fetch_recast_rules produces a DataFrame whose expires_at/created_at columns are datetime64[ns, UTC] dtype, not object"
    - "A recast-rules-shaped DataFrame containing one real expires_at and one 'Never' writes to parquet via engine='fastparquet' without 'Can't infer object conversion type'"
    - "No pandas 2.2 ChainedAssignmentError warning is emitted during normalization"
  artifacts:
    - path: "data/fetchers.py"
      provides: "fetch_recast_rules date normalization via df.assign"
      contains: "df.assign(**updates)"
  key_links:
    - from: "data/fetchers.py:fetch_recast_rules"
      to: "_parse_iso_utc"
      via: "df.assign update dict"
      pattern: "df\\.assign\\(\\*\\*updates\\)"
---

<objective>
Fix the recast_rules parquet cache write failure. `fetch_recast_rules()` normalizes `expires_at`/`created_at` with an in-place `df.loc[:, col] = <datetime64 Series>` assignment, which preserves the column's existing `object` dtype and casts the Timestamps back into it. The column stays `object` dtype while holding `Timestamp` objects, so fastparquet fails with "Can't infer object conversion type" the moment any rule has a real (non-"Never") `expires_at`. It only worked previously because every rule had `expires_at="Never"` → an all-NaT object column (which serializes fine).

Purpose: Restore the run-scoped parquet cache for recast rules. A failed cache write here breaks `ops_remediation`'s recast-rules enrichment and forces redundant API calls / errors mid-batch.
Output: A surgical edit to the date-normalization block in `fetch_recast_rules` and a local repro asserting correct dtype + clean parquet write.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md

<interfaces>
<!-- The fix mirrors the existing _normalize_* helpers in the SAME file. Use this pattern directly — no exploration needed. -->

data/fetchers.py — existing pattern to copy (lines 1165-1188):

    def _normalize_vuln_dates(df: pd.DataFrame) -> pd.DataFrame:
        """Cast date columns in the vulnerability DataFrame to UTC datetimes."""
        updates = {
            col: _parse_iso_utc(df[col])
            for col in ("first_found", "last_found", "last_fixed", "resurfaced_date")
            if col in df.columns
        }
        return df.assign(**updates) if updates else df

data/fetchers.py — _parse_iso_utc (line ~1162), do NOT modify:

    return pd.to_datetime(series, utc=True, errors="coerce", format="ISO8601")

data/fetchers.py — the buggy block to replace (lines 708-711):

    if not df.empty:
        for col in ("expires_at", "created_at"):
            if col in df.columns:
                df.loc[:, col] = _parse_iso_utc(df[col])
</interfaces>

<background>
Observation 827 (2026-05-19) switched this block from `df[col] = ...` to `df.loc[:, col] = ...` specifically to silence a false-positive pandas 2.2 ChainedAssignmentError warning. That change introduced the dtype bug. `df.assign(**updates)` resolves BOTH: it is warning-free AND yields a true `datetime64[ns, UTC]` dtype.

Empirically verified (pandas 2.2.3, fastparquet):
- `df.loc[:, col] =`   → no warning, dtype=object,            parquet=FAIL (the current bug)
- `df[col] =`          → ChainedAssignment warning, dtype=datetime64[ns,UTC], parquet=OK
- `df.assign(**updates)` → no warning, dtype=datetime64[ns,UTC], parquet=OK  ← chosen fix
</background>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Replace fetch_recast_rules date-normalization loop with df.assign</name>
  <files>data/fetchers.py</files>
  <action>
In `fetch_recast_rules()`, replace the in-place normalization loop (currently lines ~708-711):

    if not df.empty:
        for col in ("expires_at", "created_at"):
            if col in df.columns:
                df.loc[:, col] = _parse_iso_utc(df[col])

with the build-dict-then-assign pattern, matching the existing `_normalize_vuln_dates`/`_normalize_asset_dates` helpers in the same file:

    if not df.empty:
        updates = {
            col: _parse_iso_utc(df[col])
            for col in ("expires_at", "created_at")
            if col in df.columns
        }
        if updates:
            df = df.assign(**updates)

Do NOT touch `_parse_iso_utc`, `_normalize_vuln_dates`, or `_normalize_asset_dates`. Do NOT change the `_EMPTY_COLS` definition, the `_save_cache(df, cache)` call, or any surrounding logic. This is a one-block swap inside `fetch_recast_rules` only.

Why `df.assign` and not `df[col] =`: plain item-assignment triggers a false-positive pandas 2.2 ChainedAssignmentError warning (the reason obs 827 originally moved to `.loc`); `.loc` in turn preserves the column's `object` dtype, which is the parquet-write bug being fixed. `df.assign` produces a fresh `datetime64[ns, UTC]` column with no warning.
  </action>
  <verify>
    <automated>python -c "import pandas as pd; from data.fetchers import _parse_iso_utc; import tempfile, os; df = pd.DataFrame([{'rule_id':'a','expires_at':'2026-12-31T00:00:00Z','created_at':'2026-01-01T00:00:00Z'},{'rule_id':'b','expires_at':'Never','created_at':'2026-02-01T00:00:00Z'}]); updates={c:_parse_iso_utc(df[c]) for c in ('expires_at','created_at') if c in df.columns}; df=df.assign(**updates); assert str(df['expires_at'].dtype)=='datetime64[ns, UTC]', df['expires_at'].dtype; assert str(df['created_at'].dtype)=='datetime64[ns, UTC]', df['created_at'].dtype; p=os.path.join(tempfile.gettempdir(),'recast_repro.parquet'); df.to_parquet(p, engine='fastparquet'); rt=pd.read_parquet(p, engine='fastparquet'); assert str(rt['expires_at'].dtype)=='datetime64[ns, UTC]'; print('PASS: dtype datetime64[ns, UTC], fastparquet round-trip OK')"</automated>
  </verify>
  <done>The normalization block uses `df.assign(**updates)`; the repro asserts both date columns are `datetime64[ns, UTC]` and a recast-rules-shaped DataFrame (one real expires_at + one "Never") writes and round-trips via `engine='fastparquet'` with no error and no ChainedAssignment warning.</done>
</task>

</tasks>

<verification>
- `python -c "import data.fetchers"` imports cleanly (no syntax/regression).
- The repro one-liner in Task 1 verify prints `PASS` (dtype + fastparquet round-trip).
- `git diff data/fetchers.py` shows ONLY the date-normalization block changed inside `fetch_recast_rules` — `_parse_iso_utc` and the `_normalize_*` helpers are byte-unchanged.
</verification>

<success_criteria>
- `fetch_recast_rules` returns `expires_at`/`created_at` as `datetime64[ns, UTC]` (not object).
- A recast-rules DataFrame with at least one real `expires_at` writes to the run-scoped parquet cache without "Can't infer object conversion type".
- No pandas ChainedAssignmentError warning during normalization.
- Change is surgical: only the one block inside `fetch_recast_rules`.
</success_criteria>

<output>
Create `.planning/quick/260604-bxa-fix-recast-rules-parquet-cache-write-fai/260604-bxa-SUMMARY.md` when done.
</output>
