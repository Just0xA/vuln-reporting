---
phase: 16-mttr-rework
plan: "06"
subsystem: reports/modules/mttr_trend_module
status: complete
tags: [mttr, gap-closure, d-16-13, gauges, focus-driven, bootstrap]
depends_on: ["16-04"]
requirements: [RPT-05]

dependency_graph:
  requires: ["16-04"]
  provides: ["mttr_trend always-on gauge band", "focus-driven detail table", "snapshot bootstrap"]
  affects:
    - reports/modules/mttr_trend_module.py
    - reports/composed_report.py
    - scripts/capture_trend_snapshot.py
    - scripts/warm_cache.py
    - CLAUDE.md

tech_stack:
  added: []
  patterns:
    - "Focus-driven table mode: resolved in compute() from tag_category/tag_value injected by composed_report"
    - "Per-severity MoM direction via _owner_mom_delta(sev_series[sev])"
    - "sys.path bootstrap: _REPO_ROOT = Path(__file__).resolve().parent.parent before first-party imports"

key_files:
  created: []
  modified:
    - reports/modules/mttr_trend_module.py
    - reports/composed_report.py
    - scripts/capture_trend_snapshot.py
    - scripts/warm_cache.py
    - CLAUDE.md

key_decisions:
  - "D-16-13: mttr_view retired; mttr_table {auto,owner,application} is the new override"
  - "Focus depth resolved from tag_category/tag_value in compute(); plumbed from composed_report"
  - "delivery_config.yaml is gitignored (local operational config); changes documented here only"

metrics:
  duration_seconds: 540
  tasks_completed: 3
  tasks_total: 3
  files_changed: 5
  completed_date: "2026-06-12"
---

# Phase 16 Plan 06: D-16-13 MTTR Gauge Band + Focus Table + Snapshot Bootstrap Summary

Always-on 4-gauge per-severity MTTR band with MoM direction arrows; focus-driven Owner/Application/none detail table; mttr_view retired (replaced by mttr_table); snapshot bootstrap fix; CLAUDE.md Medium SLA corrected 45→60.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Snapshot bootstrap fix + sibling audit | 20800d2 | scripts/capture_trend_snapshot.py, scripts/warm_cache.py |
| 2 | compute() + focus plumbing (mttr_table, Application rows, per-sev MoM) | 3349d4d | reports/modules/mttr_trend_module.py, reports/composed_report.py |
| 3 | Render changes + doc fixes | 2e87e87 | CLAUDE.md |

## What Was Built

### Task 1 — Snapshot Bootstrap Fix (UAT Test-5 Blocker)

`scripts/capture_trend_snapshot.py` lacked a `sys.path` bootstrap, so `python scripts/capture_trend_snapshot.py` from any CWD raised `ModuleNotFoundError: No module named 'config'`. Added the project-root bootstrap before first-party imports:

```python
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from config import CACHE_DIR  # noqa: E402
```

`python scripts/capture_trend_snapshot.py --dry-run` now exits 0 from any working directory.

**Sibling script audit:**

| Script | First-party imports? | Already bootstrapped? | Action |
|--------|---------------------|-----------------------|--------|
| `smoke_email_phase2.py` | Yes | Yes (lines 52-53) | No change needed |
| `warm_cache.py` | Yes (`config`, `data.fetchers`, `tenable_client`) | No | Fixed — same pattern added |
| `setup_github_labels.py` | No (stdlib + `urllib` only) | N/A | No change needed |

`warm_cache.py` had the identical footgun and was fixed in the same commit.

### Task 2 — compute() Rewrite + Focus Plumbing (D-16-13)

**mttr_view retired.** The `_valid_views`/`mttr_view` whitelist block is removed from `compute()`. The `mttr_view` validation branch is removed from `validate_config()`. The word `mttr_view` no longer appears anywhere in `mttr_trend_module.py`.

**mttr_table added.** New option `mttr_table ∈ {auto, owner, application}` (default `auto`) with whitelist + warn-and-fallback on unknown values. `validate_config()` rejects bad values at `--dry-run`.

**Focus-signal plumbing.** `composed_report.py` now injects `tag_category` and `tag_value` (from the resolved tag filter) into the `mttr_trend` module's options dict after the tag filter is applied. Only the `mttr_trend` entry is augmented; all other modules' options are untouched. Operator-supplied `mttr_table` is preserved.

**Resolved table mode logic:**
- `mttr_table == "owner"` → mode `"owner"`
- `mttr_table == "application"` → mode `"application"`
- `mttr_table == "auto"`: unfocused → `"owner"`; `tag_category == "owner"` + tag_value → `"application"`; `tag_category == "application"` + tag_value → `"none"`

Mode stashed in `metadata["mttr_table_mode"]` — single source of truth for all three renderers.

**Application detail rows.** `uuid_to_app` built from `extract_owner(assets_df)["application"]` column. Per-application sample-weighted MTTR computed with same shape as Owner rows (`label/mttr_days/sla_days=None/variance=None/status/sample_size/mom_delta=None/insufficient`). Stashed as `metadata["table_data_application"]`.

**Per-severity MoM direction.** For each severity, `sev_mom = _owner_mom_delta(sev_series[sev])` (reuses existing helper). Direction token: `"down"` when delta < 0 (improving, ▼ green), `"up"` when > 0 (slipping, ▲ red), `"flat"` when None or 0. Stashed in `metadata["per_sev_mom_direction"]` and `metadata["per_sev_mom_delta"]`.

**MTTR math unchanged.** `days_to_fix.mean()` calls, COALESCE clock, window filter, RAG strip — all byte-identical. `mttr_by_severity_module.py` is byte-unchanged (`git diff --quiet` verified).

### Task 3 — Render Changes + Doc Fixes (D-16-13)

**render_pdf_section:**
- Removed `if mttr_view in ("severity", "both"):` gate on gauge block — gauges always render
- Added MoM direction marker (▼ green / ▲ red / — grey) below each gauge (HTML entity + inline style)
- Removed the Severity `<table>` section entirely from headline output
- Replaced `mttr_view`-based table branching with `mode = data.metadata.get("mttr_table_mode", "owner")`:
  - `"owner"` → MTTR by Owner table
  - `"application"` → MTTR by Application table (same column shape)
  - `"none"` → gauges only, no detail table

**render_excel_tabs:**
- Removed severity TABLE path entirely
- Always writes compact 4-row severity numeric block: `Severity | MTTR (Days) | SLA Target (Days) | Status | MoM Delta (Days)` (from `table_data_severity` + per-sev direction)
- Below a blank separator row: focus-driven Owner or Application block, or nothing (`mode == "none"`)

**render_email_panel:**
- Removed `_view_labels` dict (mttr_view-keyed)
- Added `_mode_labels` dict: `{"owner": "Owner breakdown", "application": "Application breakdown", "none": "Gauges only"}`
- No severity table emitted; disclosure note reflects resolved mode

**delivery_config.yaml** (gitignored — local config, not committed):
- `mttr_view: owner` example replaced with `mttr_table: auto` + inline comment listing `{auto, owner, application}` with descriptions

**CLAUDE.md:** Medium SLA row corrected 45→60 to match `config.py SLA_DAYS` (authoritative). The CLAUDE.md table was stale — a note observation from May 13, 2026 inadvertently changed it to 45.

## Backward-Compatibility Note

Any existing composed group that set `module_options.mttr_trend.mttr_view` will see that option silently ignored (the key is no longer read). The table auto-resolves by focus via `mttr_table: auto`. Groups can pin behavior by adding `mttr_table: owner` or `mttr_table: application` to their `module_options.mttr_trend` block. No other modules are affected.

## Focus-Signal Plumbing Summary

`composed_report.py` forwards the active `tag_category`/`tag_value` (resolved from the group's `filters:` block) into the `mttr_trend` module's options dict. This happens after the tag filter is applied, so compute() sees the actual scope in use. The focus signal is used only to resolve a mode token (`owner`/`application`/`none`) — the raw tag strings are never written into any HTML or Excel sink.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written. One delivery_config.yaml behavioral note: the file is gitignored (local operational config). The plan artifact lists it in `files_modified`, but the actual git commit does not include it. Changes are documented in this SUMMARY for operator reference.

## Known Stubs

None. All channels (PDF/Excel/email) are fully wired to the resolved table mode.

## Threat Flags

No new security-relevant surface. The change is a config-driven view selector over already-fetched aggregate data, plus a deterministic sys.path bootstrap. See plan's threat register (T-16-19 through T-16-SC) — all dispositioned at plan-time.

## Self-Check: PASSED

All files present. All commits found in git log.

| Item | Status |
|------|--------|
| reports/modules/mttr_trend_module.py | FOUND |
| reports/composed_report.py | FOUND |
| scripts/capture_trend_snapshot.py | FOUND |
| scripts/warm_cache.py | FOUND |
| CLAUDE.md | FOUND |
| .planning/phases/16-mttr-rework/16-06-SUMMARY.md | FOUND |
| Commit 20800d2 (Task 1) | FOUND |
| Commit 3349d4d (Task 2) | FOUND |
| Commit 2e87e87 (Task 3) | FOUND |
