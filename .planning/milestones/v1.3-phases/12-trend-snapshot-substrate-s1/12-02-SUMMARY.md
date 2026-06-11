---
phase: 12-trend-snapshot-substrate-s1
plan: "02"
subsystem: data
tags: [trend, snapshot, atomic-write, idempotency, cold-start, PII, TREND-02, TREND-03, TREND-04, TREND-05, TREND-06]
dependency_graph:
  requires: [utils/open_count.py (Plan 01)]
  provides: [data/trend_store.py, capture_snapshot, read_trend]
  affects: [scripts/capture_trend_snapshot.py (Plan 03)]
tech_stack:
  added: []
  patterns: [atomic-write-mkstemp-os.replace, df-injected-compute, idempotent-overwrite, cold-start-safe-reader]
key_files:
  created:
    - data/trend_store.py
    - tests/content/test_trend_store.py
  modified: []
decisions:
  - "D-Windows-fd: temp fd closed inside with os.fdopen() block BEFORE os.replace call — Windows raises PermissionError if os.replace runs over an open fd (Gemini MEDIUM review)"
  - "D-syspath: sys.path.insert(0, repo_root) at module level mirrors management_summary.py line 58 — required for python data/trend_store.py standalone execution"
  - "D-assign: _open_df() fixture uses .assign() for date column coercion — avoids pandas 3.0 ChainedAssignmentError warnings (Rule 2 auto-fix)"
metrics:
  duration: "~35 minutes"
  completed: "2026-06-08"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 0
---

# Phase 12 Plan 02: Trend Snapshot Engine Summary

**One-liner:** Atomic df-injected monthly snapshot engine with `os.replace` write, `(month, tag_filter)` idempotent overwrite, and cold-start-safe reader — proven by 9 content tests covering TREND-02..06.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Implement data/trend_store.py snapshot engine | 71ae8ef | data/trend_store.py |
| 2 | Write content tests — atomicity, idempotency, cold-start, PII, MS-untouched | c480311 | tests/content/test_trend_store.py |

## What Was Built

### `data/trend_store.py`

Forward-accumulating snapshot engine. No fetching — df-injected (D-08): receives already-fetched `df` + `assets_df`, calls `open_findings_at` (Plan 01 primitive), groups by severity, writes aggregate counts.

Key design points:

**Atomic write (`_atomic_write_json`):** `tempfile.mkstemp` → `with os.fdopen(fd, "w") as fh: json.dump(...)` → `os.replace`. The `with` block closes the fd before `os.replace` runs. On Windows, calling `os.replace` over a still-open fd raises `PermissionError` — the close ordering is the fix (Gemini MEDIUM review). On exception, `os.unlink(tmp_path)` is called best-effort and the original is untouched.

**Idempotent overwrite:** `(month, tag_filter)` key — re-running the same calendar month overwrites the existing entry in-place. A new month appends without touching prior entries. Month key uses server-local time (`date.strftime("%Y-%m")`); `generated_at` uses UTC (`datetime.now(tz=timezone.utc)`).

**Empty-data guard:** `_count_by_severity` calls `.groupby().size().to_dict()` only when `open_df` is non-empty — avoids calling `.get()` directly on a pandas Series (Pitfall 3). Empty df produces all-zero counts without crashing.

**Cold-start reader (`read_trend`):** `_load_trend_json` swallows parse errors and missing-file cases (returns `[]`). `read_trend` returns `{"snapshots": [], "insufficient_data": True}` when the file is absent or has fewer than 2 entries.

**D-01 compliance:** `reports/management_summary.py` is untouched. The substrate writes `trend_{dimension}_{tagsuffix}.json` (distinct `trend_` prefix from `management_summary_*.json`). No MS private helpers are called.

**Overridable `trend_dir`:** Both public functions accept `trend_dir: Optional[Path] = None` — defaults to the module-level `TREND_DIR` constant but can be overridden in tests without monkeypatching.

### `tests/content/test_trend_store.py`

9 content tests marked `pytest.mark.content`, all passing. Every capture/read call passes `trend_dir=tmp_path` (P2 — no real `data/trend/` files touched).

| Test | Requirement | What it proves |
|------|-------------|----------------|
| `test_capture_writes_file` | TREND-02 | Atomic write completes; file exists; 1 snapshot entry |
| `test_live_count_match` | TREND-01 | Written critical count == `open_findings_at` oracle count |
| `test_idempotent_overwrite` | TREND-05 | Same-month re-run → exactly 1 entry |
| `test_second_month_appends` | TREND-05 | New month → 2 entries; prior entry's aggregate fields unchanged |
| `test_cold_start_read` | TREND-04 | Missing file → `{snapshots: [], insufficient_data: True}`, no exception |
| `test_single_snapshot_insufficient_data` | TREND-04 | 1 snapshot → `insufficient_data=True` |
| `test_no_pii_in_snapshot` | TREND-06 | `hostname/ipv4/fqdn/asset_uuid/plugin_name/plugin_id` absent from JSON text |
| `test_ms_file_untouched` | TREND-03 | MS file `st_mtime` unchanged after capture |
| `test_empty_df_writes_zero_counts` | (safety) | Empty df → all counts 0, no crash |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Added sys.path.insert at module level for standalone script execution**
- **Found during:** Task 1 smoke block run (`python data/trend_store.py`)
- **Issue:** `from utils.open_count import open_findings_at` at module top-level fails when `data/trend_store.py` is run directly because the repo root is not on `sys.path`.
- **Fix:** Added `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))` at module level, mirroring the established pattern in `reports/management_summary.py` line 58.
- **Files modified:** data/trend_store.py
- **Commit:** 71ae8ef

**2. [Rule 2 - Convention] Used .assign() for date column coercion in _open_df() fixture**
- **Found during:** Task 2 test run (21 FutureWarning: ChainedAssignmentError from pandas 3.0)
- **Issue:** `df[col] = pd.to_datetime(df[col], ...)` inside a loop emitted pandas 3.0 ChainedAssignment warnings (CLAUDE.md forbids this pattern).
- **Fix:** Replaced loop with `.assign(**{col: pd.to_datetime(df[col], ...) for col in ...})` per CLAUDE.md pandas-3.0-safe convention.
- **Files modified:** tests/content/test_trend_store.py
- **Commit:** c480311

## Verification Results

```
$ python data/trend_store.py
Written to: C:\Users\monro\AppData\Local\Temp\...\trend_severity_all_assets.json
Snapshots  : 1
insufficient_data: True
Idempotent overwrite: OK
Month append: OK
Smoke test passed.

$ python -m pytest tests/content/test_trend_store.py -x -p no:xdist -o "addopts=" -q
.........
9 passed in 0.10s

$ git diff --name-only HEAD~2 HEAD | grep management_summary
(no output — management_summary.py is unmodified)
```

## Known Stubs

None — this plan delivers pure I/O infrastructure with no UI rendering.

## Threat Flags

None — all STRIDE threats addressed per plan threat model:
- T-12-03 (PII leakage): mitigated by fixed key allowlist + `test_no_pii_in_snapshot`
- T-12-04 (partial-file corruption): mitigated by `_atomic_write_json` + fd-close ordering
- T-12-05 (path injection): `_sanitise_tag_for_filename` in place for Phase 13 parameterised case
- T-12-06 (MS file regression): mitigated by `trend_` prefix + D-01 + `test_ms_file_untouched`

## Self-Check: PASSED

- [x] `data/trend_store.py` exists and contains `def capture_snapshot` and `def read_trend`
- [x] `tests/content/test_trend_store.py` exists and contains `pytestmark = pytest.mark.content`
- [x] Commit 71ae8ef exists (Task 1)
- [x] Commit c480311 exists (Task 2)
- [x] `python data/trend_store.py` exits 0 (no PermissionError on Windows os.replace)
- [x] `python -m pytest tests/content/test_trend_store.py` — 9 passed
- [x] `git diff` confirms `reports/management_summary.py` is not in changed files
- [x] Source confirms: `os.replace` present, `with os.fdopen(` present, `os.replace` call OUTSIDE that with-block, `trend_` filename prefix present, month key local / `generated_at` UTC
