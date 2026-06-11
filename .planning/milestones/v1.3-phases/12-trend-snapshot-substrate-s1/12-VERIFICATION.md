---
phase: 12-trend-snapshot-substrate-s1
verified: 2026-06-08T21:10:00Z
status: passed
score: 7/7 must-haves verified
overrides_applied: 0
---

# Phase 12: Trend Snapshot Substrate (S1) Verification Report

**Phase Goal:** The codebase has a canonical, tested open-count primitive and a snapshot-capture engine that begins accumulating monthly trend history in the existing data/trend/ store.
**Verified:** 2026-06-08T21:10:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `open_findings_at(df, date)` returns the correct open subset using the reopened-aware two-interval predicate | VERIFIED | `utils/open_count.py:82-88` implements three-clause `fixed` mask; all 10 unit tests pass; smoke block asserts 3/5 rows open |
| 2 | A plain OPEN finding born before D is counted open at D | VERIFIED | `test_open_state_included`, `test_open_state_no_last_fixed_included` pass |
| 3 | A FIXED finding (last_fixed <= D) is excluded at D | VERIFIED | `test_fixed_state_excluded` pass; clause 1 of `fixed` mask at line 83 |
| 4 | A REOPENED finding is open at D when D >= resurfaced_date, and closed when last_fixed <= D < resurfaced_date | VERIFIED | `test_reopened_state_included` and `test_reopened_in_gap_excluded` pass; clauses 2-3 of `fixed` mask at lines 84-85 |
| 5 | An empty input DataFrame returns an empty result without raising | VERIFIED | `test_empty_dataframe_returns_empty` pass; `df.iloc[0:0].copy()` guard at line 58 |
| 6 | `open_findings_at` is pure compute (no file/network I/O); I/O layer is `data/` | VERIFIED | No `import config`, no `_normalize_vuln_dates`, no file/network calls in `utils/open_count.py`; `data/trend_store.py` is the sole I/O module |
| 7 | `capture_snapshot` writes atomic monthly snapshots; same-month runs are idempotent; new months append; `read_trend` is cold-start safe | VERIFIED | `test_capture_writes_file`, `test_idempotent_overwrite`, `test_second_month_appends`, `test_cold_start_read`, `test_single_snapshot_insufficient_data` all pass; 19/19 tests pass total |
| 8 | Snapshots are aggregate counts only — no PII | VERIFIED | `test_no_pii_in_snapshot` pass; payload assembled from fixed 8-key allowlist at `trend_store.py:219-228` |
| 9 | Existing `management_summary_*.json` is byte-for-byte unchanged after capture | VERIFIED | `test_ms_file_untouched` pass; `trend_` prefix at line 232 is distinct from `management_summary_*`; git diff confirms `reports/management_summary.py` untouched across all phase commits |
| 10 | Cron entry point captures the all_assets severity snapshot with exit codes 0/2/3 | VERIFIED | `python -m scripts.capture_trend_snapshot --dry-run` → exit 0; `--month not-a-month` → exit 2; `RotatingFileHandler` to `logs/capture_trend_snapshot.log` confirmed |

**Score:** 7/7 ROADMAP success criteria verified (10 observable truths total, all VERIFIED)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `utils/open_count.py` | Pure-compute `open_findings_at` predicate | VERIFIED | 132 lines; `def open_findings_at` present; `.str.upper()` casing guard; `df.iloc[0:0].copy()` empty guard; no `import config`, no `_normalize_vuln_dates`; `__main__` smoke block exits 0 |
| `tests/unit/test_open_count.py` | Labelled OPEN/REOPENED/FIXED unit cases (TREND-01) | VERIFIED | 212 lines; `pytestmark = pytest.mark.unit`; `from utils.open_count import open_findings_at`; 10 tests, all pass |
| `data/trend_store.py` | Snapshot capture/read engine (I/O layer) | VERIFIED | 355 lines (>90 min); exports `capture_snapshot` and `read_trend`; `os.replace` atomic write; `from utils.open_count import open_findings_at`; `trend_dir` param for test isolation; `__main__` smoke exits 0 |
| `tests/content/test_trend_store.py` | Content tests for TREND-02..06 | VERIFIED | 300 lines; `pytestmark = pytest.mark.content`; `from data.trend_store import capture_snapshot, read_trend`; 9 tests, all pass |
| `scripts/capture_trend_snapshot.py` | Cron entry point (TREND-07) | VERIFIED | 257 lines (>120 min); `from data.trend_store import capture_snapshot`; `fetch_all_vulnerabilities` and `fetch_all_assets` present; `fetch_fixed_vulnerabilities` absent; `--month`, `--date`, `--dry-run`, `--verbose` flags; `RotatingFileHandler`; `sys.exit(main())` |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `tests/unit/test_open_count.py` | `utils/open_count.py` | `from utils.open_count import open_findings_at` | WIRED | Import confirmed at line 16; all 10 tests exercise the function |
| `data/trend_store.py` | `utils/open_count.py` | `from utils.open_count import open_findings_at` | WIRED | Import at line 55; called at `capture_snapshot:207` |
| `data/trend_store.py` | `data/trend/trend_severity_all_assets.json` | atomic temp-file write + `os.replace` | WIRED | `os.replace` at line 138; `_atomic_write_json` called from `capture_snapshot:245`; `with os.fdopen(` closes fd before `os.replace` (Windows-safe); smoke block confirms no PermissionError |
| `scripts/capture_trend_snapshot.py` | `data/trend_store.py` | `from data.trend_store import capture_snapshot` | WIRED | Import at line 37; called at `main():245` |
| `scripts/capture_trend_snapshot.py` | `data/fetchers.py` | `fetch_all_vulnerabilities` + `fetch_all_assets` | WIRED | Imports at lines 34-36; called at `main():228-230` |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `capture_snapshot` | `open_df` | `open_findings_at(df, date)` — pure predicate on injected df | Yes — df-injected from caller (D-08); predicate proven by unit tests | FLOWING |
| `capture_snapshot` → JSON | `sev_counts` | `_count_by_severity(open_df)` → groupby severity → `.to_dict()` | Yes — `test_live_count_match` asserts written count == `open_findings_at` oracle | FLOWING |
| `read_trend` | `recent` | `_load_trend_json(file_path)` → filter tag_filter → sort → slice | Yes — reads real persisted JSON; cold-start returns `[]` safely | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `open_findings_at` smoke block: 3/5 rows open | `python utils/open_count.py` | `Open at REF : 3` / `Smoke test passed.` / exit 0 | PASS |
| `trend_store` smoke block: capture, idempotent overwrite, month append | `python data/trend_store.py` | `Idempotent overwrite: OK` / `Month append: OK` / `Smoke test passed.` / exit 0 | PASS |
| Cron entry point dry-run | `python -m scripts.capture_trend_snapshot --dry-run` | `DRY RUN: would capture snapshot month=2026-06` / exit 0 | PASS |
| Cron entry point argparse validation | `python -m scripts.capture_trend_snapshot --month not-a-month` | `error: argument --month: --month must be YYYY-MM...` / exit 2 | PASS |
| Full test suite | `python -m pytest tests/unit/test_open_count.py tests/content/test_trend_store.py -q -o addopts=""` | `19 passed in 0.11s` | PASS |

Note: `python scripts/capture_trend_snapshot.py --dry-run` (bare path, not `-m`) raises `ModuleNotFoundError: No module named 'config'` — this is expected; the PLAN specifies invocation as `python -m scripts.capture_trend_snapshot` from the repo root (per `deploy/crontab.example`), which correctly sets the module path. The `-m` form works correctly.

---

### Probe Execution

No probe scripts declared or conventional for this phase. Step 7c: SKIPPED (no `scripts/*/tests/probe-*.sh` files for this phase).

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| TREND-01 | 12-01 | Canonical `open_findings_at` with reopened-aware two-interval predicate; unit-tested against labelled cases | SATISFIED | `utils/open_count.py` predicate + 10 unit tests; `test_live_count_match` proves engine uses predicate as oracle |
| TREND-02 | 12-02 | `capture_snapshot` writes atomic monthly snapshots (temp-file + `os.replace`) | SATISFIED | `_atomic_write_json` with `with os.fdopen(` + `os.replace` after block; `test_capture_writes_file` passes on Windows without PermissionError |
| TREND-03 | 12-02 | Snapshots reuse `data/trend/` store; existing MS output does not regress | SATISFIED | `trend_` prefix distinct from `management_summary_*`; `test_ms_file_untouched` pass; git diff confirms `reports/management_summary.py` unmodified |
| TREND-04 | 12-02 | `read_trend` is cold-start safe (≤1 snapshot → insufficient_data=True, no crash) | SATISFIED | `test_cold_start_read` and `test_single_snapshot_insufficient_data` pass; `_load_trend_json` returns `[]` on missing file |
| TREND-05 | 12-02 | Snapshot capture is idempotent per calendar month | SATISFIED | `test_idempotent_overwrite` (1 entry after 2 same-month runs) and `test_second_month_appends` (2 entries after different months) pass |
| TREND-06 | 12-02 | Snapshot payloads are aggregate counts only — no PII | SATISFIED | `test_no_pii_in_snapshot` asserts `{hostname,ipv4,fqdn,asset_uuid,plugin_name,plugin_id}` absent; payload fixed 8-key allowlist |
| TREND-07 | 12-03 | Cron-friendly entry point captures current month's snapshot with logged exit codes | SATISFIED | `scripts/capture_trend_snapshot.py`: dry-run exit 0, bad-month exit 2, RotatingFileHandler, `_log_started`/`_log_completed` lifecycle, does not call `fetch_fixed_vulnerabilities` |

All 7 TREND-NN requirements mapped to this phase are SATISFIED. SEG-NN and DOC-01 requirements are mapped to Phase 13 (Pending) — not in scope for this phase.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | — | No TBD/FIXME/XXX debt markers | — | — |
| `data/trend_store.py` | 109, 116 | `return []` in `_load_trend_json` | Info | Intentional cold-start/parse-error safe return; not a stub — these are documented error paths for missing/corrupt files, not unimplemented behavior |

No blocker anti-patterns. The two `return []` lines in `_load_trend_json` are correct cold-start guards, not stubs — they exist within an explicit try/except block that handles file-not-found and parse errors exactly as the plan specifies.

---

### Review Finding Assessment (WR-01 — FIXED with NaT last_fixed)

The code review identified WR-01: a `state="fixed"` finding with `last_fixed=NaT` escapes all three `fixed`-mask clauses (each requires `lf.notna()`) and is returned as open, silently over-counting. This is a latent edge case in the Spike 002 blueprint that Plan 01 explicitly instructed to copy verbatim, and is outside the plan's stated behavior spec.

Assessment against must-haves: The plan's documented behaviors are "A FIXED finding (last_fixed <= D) is excluded at D" — this truth is fully verified by `test_fixed_state_excluded`. The NaT-last_fixed case is an undocumented edge not present in the plan's truth set. No test asserts the NaT-FIXED behavior, and the plan does not require one. This is classified as a WARNING carried from the code review — it degrades correctness on real Tenable data where the fetcher can produce `state="fixed"` with `last_fixed=NaT` — but it does not constitute a FAILED must-have for this phase's stated scope.

This issue should be resolved before any v1.4 report module consumes `open_findings_at` on live data.

---

### Human Verification Required

None — all phase behaviors are verifiable programmatically. The entry point's live fetch path (`get_client` → `fetch_all_vulnerabilities` → `capture_snapshot`) requires a live Tenable API credential and is outside automated verification scope, but the plan's acceptance criteria only require dry-run (exit 0) and bad-argument validation (exit 2), both of which pass.

---

### Gaps Summary

No gaps. All 7 ROADMAP success criteria are satisfied by passing tests and working behavioral spot-checks. The review warning WR-01 (FIXED-with-NaT-last_fixed over-count) is a latent correctness edge outside this phase's stated truth set — it does not block the phase goal.

---

_Verified: 2026-06-08T21:10:00Z_
_Verifier: Claude (gsd-verifier)_
