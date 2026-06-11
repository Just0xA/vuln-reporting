---
phase: "15-independent-new-modules"
plan: "06"
subsystem: "reports/modules"
tags: ["module", "accepted-recast", "exception-posture", "risk-management", "four-channel"]
dependency_graph:
  requires: ["15-02", "15-04"]
  provides: ["accepted_recast module (RPT-04)"]
  affects: ["composed_report.py (already gated by 15-04)", "management_summary", "board_summary"]
tech_stack:
  added: []
  patterns:
    - "AcceptedRecastModule four-channel render contract (pdf/excel/email/analyst)"
    - "Expiry cross-check pattern (recast_rules_df kwarg, expired_ids set exclusion)"
    - "Separate accepted/recast tracking (never silently aggregated)"
    - "MoM delta omit-not-zero pattern (safe-delta helper)"
key_files:
  created:
    - reports/modules/accepted_recast_module.py
    - tests/test_accepted_recast_module.py
  modified: []
decisions:
  - "Zero-exception input returns error=None with green RAG (not _empty_result) — filtered-to-zero is a valid operational state for exception posture"
  - "to_period() called on tz-naive copy (tz_localize(None)) to avoid pandas 3.x UserWarning"
  - "pending_reeval tracked as a separate metric alongside accepted_count/recast_count — not merged into the headline"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-11"
  tasks_completed: 1
  tasks_total: 1
  files_changed: 2
---

# Phase 15 Plan 06: Accepted & Recast Module Summary

**One-liner:** AcceptedRecastModule tracks ACCEPTED and RECASTED exception posture separately with expiry cross-check, MoM delta arrows, and Owner cut on all four render channels.

## What Was Built

`reports/modules/accepted_recast_module.py` — full four-channel `BaseModule` implementation:

- `MODULE_ID = "accepted_recast"`, `@register_module` auto-discovery
- Separate `accepted_count` / `recast_count` metrics — never silently aggregated (Pitfall 6b / RPT-04)
- Classification via `.isin({"ACCEPTED"})` / `.isin({"RECASTED"})` on uppercased `severity_modification_type`; `""` and `"NONE"` excluded from both
- Expiry cross-check (Pitfall 6a): `recast_rules_df` kwarg cross-references `expires_at < report_date`; expired findings excluded from current counts and surfaced as `pending_reeval`; `recast_rules_df=None` degrades gracefully with a WARNING log
- Finding counts drive the headline metric; rule-level detail (rule_id, action, plugin_id, filter_summary) lives only in the analyst tab (Pitfall 6c)
- `_summarize_filter()` from `data.fetchers` used for analyst-tab filter column — no inline filter-tree parse
- MoM delta via `_safe_delta_arrow()` helper: prior-month absent / `insufficient_data=True` → `None` (omit arrow entirely, never emit "▲ 0%" or NaN%) — QUAL-01 / Pitfall 5
- Zero-exception scope → coherent green result with `error=None` and `"0 managed exceptions in scope."` driver narrative (QUAL-03)
- Exception rate = `(accepted + recasted) / total_open * 100`; RAG `lower_is_better`; green ≤ 5%, yellow ≤ 15% (D-15-07 defaults, overridable via `config.options`)
- Owner cut via `extract_owner(assets_df)` for both accepted and recasted segments
- All four channels implemented: `render_pdf_section`, `render_excel_tabs`, `render_email_panel` (CONTRACT-01), `render_analyst_tabs` (CONTRACT-02 — "Rule Detail" + "By Owner"), `render_rag_strip_entry` (CONTRACT-03)

`tests/test_accepted_recast_module.py` — 55 tests across 12 test classes:
- Registration, separate counts (Pitfall 6b), expiry cross-check (Pitfall 6a), finding-vs-rule count (Pitfall 6c), MoM delta cold-start (QUAL-01), zero-exception guard (QUAL-03), rate denominator, Owner cut, RAG thresholds, four-channel empty-data, four-channel valid-data, CoW strict mode
- Synthetic UUIDs only (`00000000-0000-0000-0000-00000000000N`) — no real Tenable recast_rule_uuid (QUAL-05)

## Test Results

```
55 passed in 3.81s (exit 0 under -W error::FutureWarning)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] pandas 3.x UserWarning on tz-aware to_period()**
- **Found during:** First test run (MoM delta tests flagging UserWarning)
- **Issue:** `pd.Timestamp(report_date).tz_convert("UTC").to_period("M")` emits `UserWarning: Converting to Period representation will drop timezone information` in pandas 3.x
- **Fix:** Strip timezone before `to_period()` via `ts.tz_localize(None).to_period("M")`
- **Files modified:** `reports/modules/accepted_recast_module.py` (line 329)
- **Commit:** 920c37b (same commit)

None — plan executed with one inline fix before commit.

## Known Stubs

None. All four channels fully implemented and wired.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Module is a pure compute + render unit consuming existing fetcher outputs.

## Self-Check

- [x] `reports/modules/accepted_recast_module.py` exists
- [x] `tests/test_accepted_recast_module.py` exists
- [x] `@register_module` present; `MODULE_ID = "accepted_recast"` confirmed
- [x] `_summarize_filter` imported and used in analyst-tab construction
- [x] No `df["col"] =` chained-assignment patterns (all `.assign()`)
- [x] 55 tests pass, exit 0 under `-W error::FutureWarning`
- [x] Only the two task files touched (plus this SUMMARY)

## Self-Check: PASSED
