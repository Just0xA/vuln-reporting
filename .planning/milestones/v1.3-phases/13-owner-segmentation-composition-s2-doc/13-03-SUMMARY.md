---
phase: 13-owner-segmentation-composition-s2-doc
plan: "03"
subsystem: trend-store + owner-supplemental
tags: [owner-segmentation, tdd, trend-composition, supplemental-writer, seg-03, seg-05]
dependency_graph:
  requires:
    - reports/modules/board_report_utils.extract_owner (plan 01)
    - data/trend_store.capture_snapshot + read_trend (phase 12)
  provides:
    - data/trend_store._count_by_owner
    - data/trend_store.capture_snapshot(dimension="owner")
    - reports/owner_supplemental.write_owner_supplemental
    - board_summary supplemental_excel / supplemental_csv keys
  affects:
    - scripts/capture_trend_snapshot.py (owner snapshot capture added)
    - reports/board_summary.py (additive supplemental keys)
tech_stack:
  added: []
  patterns:
    - dimension dispatch in capture_snapshot (severity vs owner)
    - caller-pre-enriched owner map (data layer free of reports/modules imports)
    - unscanned_assets _write_data_tab / _write_csv pattern for supplemental
    - CSV injection guard (= + - @ prefix with apostrophe)
    - fail-soft try/except wrapper for supplemental in board run
key_files:
  created:
    - reports/owner_supplemental.py
    - (tests/content/test_trend_store.py extended — not created)
  modified:
    - data/trend_store.py
    - scripts/capture_trend_snapshot.py
    - reports/board_summary.py
    - tests/content/test_trend_store.py
decisions:
  - "Caller pre-enriches assets with extract_owner before passing enriched_assets to capture_snapshot — keeps data/trend_store.py free of reports/modules/ imports (RESEARCH A1 / Pitfall 5)"
  - "dimension dispatch uses count_entry dict unpacked via ** into new_entry — owner dimension gets arbitrary owner-name keys while severity keeps fixed critical/high/medium/low keys"
  - "enriched_assets=None with dimension=owner raises ValueError (loud, testable failure) rather than silently producing all-Unassigned counts (T-13-12)"
  - "owner_supplemental.py placed in reports/ (not reports/modules/) as it is a standalone writer, not a module participant in the four-channel render contract"
  - "CSV injection guard in _safe_cell_value prefixes = + - @ values; openpyxl writes as data so no formula injection risk in Excel path (T-13-09)"
  - "write_owner_supplemental wrapped in fail-soft try/except in board_summary — supplemental error logs but never aborts the board PDF/Excel run (T-13-11)"
metrics:
  duration: "~18 minutes"
  completed: "2026-06-10T19:20:00Z"
  tasks_completed: 3
  files_changed: 4
---

# Phase 13 Plan 03: Trend Composition + Combined Supplemental Summary

Owner-dimension trend capture (`dimension="owner"` + `_count_by_owner`) proven end-to-end via 6 new content tests; combined Owner/Application supplemental Excel+CSV writer shipped under `output/` (gitignored, fail-soft), wired additively into board_summary result dict.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 0 | Write failing SEG-05 owner-dimension trend tests (RED) | 54a2b7d | tests/content/test_trend_store.py (extended) |
| 1 | Add _count_by_owner + dimension=owner dispatch; wire entry point | 919ea1b | data/trend_store.py, scripts/capture_trend_snapshot.py |
| 2 | Combined supplemental writer + board_summary wiring (SEG-03) | 82a4e50 | reports/owner_supplemental.py (created), reports/board_summary.py |

## What Was Built

**`data/trend_store.py`** — extended with owner-dimension support:

1. **`_count_by_owner(open_df, enriched_assets)`**: builds a `uuid→owner` map from `enriched_assets["asset_uuid"]` / `["owner"]`; uses `open_df["asset_uuid"].map(uuid_to_owner).fillna("Unassigned").value_counts().to_dict()` coerced to `{str: int}`. Empty `open_df` guard returns `{}`. Empty `enriched_assets` DataFrame (zero rows, not None) produces all-Unassigned counts. Note: a `None` `enriched_assets` is rejected upstream by `capture_snapshot` with a `ValueError` before reaching this helper (T-13-12).

2. **`capture_snapshot` dispatch**: new `enriched_assets: Optional[pd.DataFrame] = None` param (severity callers unaffected). Dimension dispatch: `"severity"` → `_count_by_severity` (fixed keys, Phase 12 unchanged); `"owner"` → `ValueError` on `enriched_assets=None`, else `_count_by_owner` (arbitrary owner keys); unknown → `ValueError`. Entry built via `**count_entry` unpacking into `new_entry` dict. `read_trend` requires no changes.

**`scripts/capture_trend_snapshot.py`** — after severity capture, pre-enriches `assets_df` via `extract_owner` (local import), then calls `capture_snapshot(..., "owner", "all_assets", enriched_assets=enriched)`. Both captures logged. Owner failure is non-fatal (logged + exits 3).

**`reports/owner_supplemental.py`** (new):

- `write_owner_supplemental(assets_df, vulns_df, output_dir)` — builds flat `(owner, application, open_count, asset_count)` frame; writes single-tab Excel (`Owner Assignment`) + CSV companion; returns `{"supplemental_excel": Path, "supplemental_csv": Path}`.
- Follows `unscanned_assets.py` pattern: navy header fill (`1F3864`), zebra stripe (`F5F5F5`), `freeze_panes="A2"`, `DictWriter QUOTE_ALL utf-8-sig`.
- Empty-df guard: writes "No data for this run." italic cell, no crash.
- CSV injection guard: `_safe_cell_value` prefixes `= + - @` values with `'` (T-13-09).
- Never references `data/trend/` paths (D-11); writes to `output_dir` only (gitignored output/).

**`reports/board_summary.py`** — additive wiring:

- Post-pipeline call to `write_owner_supplemental` wrapped in `try/except` (fail-soft, T-13-11).
- Two new additive keys in `result_dict`: `"supplemental_excel"` and `"supplemental_csv"` (mirroring `"analyst_excel"` pattern). No existing key shapes mutated.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. The supplemental returns real paths backed by openpyxl/csv writes. Owner+Application columns come from `extract_owner` which reads live tag data. No placeholder values flow to rendering.

## Threat Flags

No new network endpoints, auth paths, or schema changes. All STRIDE mitigations in the plan's threat register are implemented:

| Threat ID | Status | Evidence |
|-----------|--------|----------|
| T-13-07 | Mitigated | `test_owner_snapshot_no_pii` asserts no hostname/ipv4/asset_uuid in owner snapshot JSON |
| T-13-08 | Mitigated | Written to `output/` only; `git check-ignore output/` confirmed; no `data/trend` write in owner_supplemental.py |
| T-13-09 | Mitigated | `_safe_cell_value` prefixes `= + - @` values with `'` in both Excel and CSV paths |
| T-13-10 | Mitigated | Reuses existing `_atomic_write_json` (temp+os.replace, Windows-safe) — no new write path |
| T-13-11 | Mitigated | `write_owner_supplemental` call wrapped `try/except` in board_summary; logs + None paths on failure |
| T-13-12 | Mitigated | `ValueError` raised on `capture_snapshot(dimension="owner", enriched_assets=None)`; tested by `test_owner_requires_enriched_assets` |

## Self-Check: PASSED

- `data/trend_store.py` contains `def _count_by_owner`: FOUND (line 171)
- `data/trend_store.py` contains `enriched_assets` in signature: FOUND (line 226)
- `data/trend_store.py` `grep -c "from reports"` returns 0: CONFIRMED
- `scripts/capture_trend_snapshot.py` contains `extract_owner`: FOUND (line 271)
- `reports/owner_supplemental.py` exists and contains `def write_owner_supplemental`: FOUND
- `reports/board_summary.py` contains `write_owner_supplemental`: FOUND (line 323)
- `reports/board_summary.py` contains `supplemental_excel` in result_dict: FOUND (line 390)
- `git check-ignore output/` confirms output/ ignored: CONFIRMED
- 15 content tests pass (6 new owner + 9 existing severity): CONFIRMED
- 131 unit+content tests total, 0 failures: CONFIRMED
- Commits 54a2b7d, 919ea1b, 82a4e50: FOUND
