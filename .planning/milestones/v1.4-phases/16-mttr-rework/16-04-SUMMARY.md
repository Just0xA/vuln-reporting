---
phase: 16-mttr-rework
plan: "04"
subsystem: reports/modules
tags: [mttr, gap-closure, view-selector, split-table, owner, severity]
dependency_graph:
  requires: ["16-02"]
  provides: ["mttr_view selector", "split Severity/Owner breakdown", "Owner SLA-basis fix"]
  affects: ["reports/modules/mttr_trend_module.py", "delivery_config.yaml"]
tech_stack:
  added: []
  patterns:
    - "config.options.get('mttr_view', 'owner') — mirrors mttr_window_days/min_sample_size pattern"
    - "metadata stash for validated view token; renderers read one source of truth"
    - "two independent table_data lists (table_data_severity, table_data_owner) in metadata"
key_files:
  created: []
  modified:
    - reports/modules/mttr_trend_module.py
    - delivery_config.yaml  # gitignored; on-disk only
decisions:
  - "D-16-11 applied: single combined table_data split into table_data_severity + table_data_owner"
  - "D-16-12 applied: mttr_view defaults to 'owner'; exec default is owner-only, fits one page"
  - "Owner variance dict (owner_variance) removed — was computed against Critical SLA but never meaningful; dropped from data flow entirely"
  - "Owner status label (Within/Near/Exceeding) retained as a velocity reference vs Critical SLA — not emitted as an SLA Target column"
  - "Analyst tab (CONTRACT-02) keeps both cuts regardless of mttr_view — drill-down, not headline channel"
metrics:
  duration_s: 900
  completed: "2026-06-12"
  tasks: 3
  files: 2
---

# Phase 16 Plan 04: MTTR View Selector + Split Table Summary

**One-liner:** `mttr_view ∈ {owner, severity, both}` (default `owner`) splits the MTTR breakdown into independent Severity and Owner tables across PDF, Excel, and email panel, fixing the confusing mixed table and the latent Owner SLA-basis bug (D-16-11/D-16-12).

## What Was Built

### Task 1 — compute(): view-aware split breakdown + Owner SLA-basis fix (commit 8030285)

In `compute()`, added `mttr_view = str(config.options.get("mttr_view", "owner")).lower().strip()` immediately alongside the existing `mttr_window_days`/`min_sample_size` reads (~:313-314). The value is whitelisted to `{"owner", "severity", "both"}`; unknown values log a WARNING and fall back to `"owner"` (the safe default — never interpolated into any HTML/Excel sink).

The single combined `table_data` list (severity rows followed by Owner rows) was replaced with two independent lists:
- `table_data_severity`: severity rows with per-severity `sla_days` and `variance` (meaningful)
- `table_data_owner`: owner rows with `sla_days=None` and `variance=None` (D-16-12 — the Critical-SLA anchor is not a meaningful SLA Target for Owner rows)

Owner status labeling (`Within/Near/Exceeding SLA`) is retained using Critical SLA as a velocity reference, but that value is NOT emitted as a display column.

The `owner_variance` dict was removed (my change made it unused).

Both lists are stashed in `metadata["table_data_severity"]`, `metadata["table_data_owner"]`, and `metadata["mttr_view"]` so all three headline renderers read a single source of truth. The combined `table_data` is kept only to build `analyst_rows` (CONTRACT-02 keeps both cuts regardless of `mttr_view`).

`validate_config` extended to reject `mttr_view` values not in `{owner, severity, both}`.

Module docstring updated with D-16-11/D-16-12 option documentation.

### Task 2 — PDF, Excel, and email-panel render splits (commit 0e4cded)

Each headline renderer reads `mttr_view = data.metadata.get("mttr_view", "owner")` at its top and branches on it.

**PDF (`render_pdf_section`):**
- Per-severity gauges are now gated on `mttr_view in ("severity", "both")` — the `owner` default renders no gauges (single Owner table fits one page, no gauge bloat)
- `severity` view: "MTTR by Severity" table with SLA Target and Variance columns
- `owner` view: "MTTR by Owner" table with no SLA Target column, no Variance column, with MoM Delta
- `both` view: Severity section followed by Owner section as two distinct tables under separate headings
- Explanatory text updated: no longer claims "Owner rows use Critical SLA as the anchor" — now reads "Owner table shows velocity (MTTR + MoM delta) without an SLA anchor"

**Excel (`render_excel_tabs`):**
- `owner` headers: `[Owner, MTTR (Days), Status, Sample Size, MoM Delta (Days)]` — no `SLA Target (Days)`
- `severity` headers: `[Severity, MTTR (Days), SLA Target (Days), Variance (Days), Status, Sample Size]`
- `both`: Severity block then blank separator row then Owner block in the same "MTTR Trend" tab

**Email panel (`render_email_panel`):**
- Overall MTTR headline and driver narrative unchanged
- Disclosure footer now reads `"See attached report for Owner breakdown"` (or `severity`/`Severity & Owner`) so recipients know which view is in the attachment

`render_analyst_tabs` (CONTRACT-02) is untouched — returns both cuts regardless of `mttr_view`.

### Task 3 — delivery_config.yaml documentation (on-disk only, gitignored)

The "Custom Composed Report — example" group's `module_options` block updated from commented placeholder to a live documented example:

```yaml
module_options:
  mttr_trend:
    mttr_view: owner        # {owner, severity, both} — default: owner (D-16-12)
                            # owner    = Owner table only (exec default; fits one page)
                            # severity = Severity table only (with per-severity SLA targets)
                            # both     = two distinct tables: Severity first, then Owner
```

No other group was touched. YAML parses cleanly.

## Backward-Compatibility Note (D-16-12)

**Any existing composed group that references `mttr_trend` without a `module_options.mttr_view` setting will switch from the previous combined Severity+Owner table to owner-only output by default.** This is the intended behavior (owner is the exec headline cut and fits one page). Groups that want the severity cut must explicitly set:

```yaml
module_options:
  mttr_trend:
    mttr_view: severity   # or: both
```

This was the accepted tradeoff when D-16-12 was locked.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Cleanup] Removed unused `owner_variance` dict**
- **Found during:** Task 1
- **Issue:** The Owner MTTR loop computed `owner_variance` as `round(m - critical_sla, 1)`, but after changing `table_data_owner` to carry `variance: None`, the dict was populated but never read
- **Fix:** Removed `owner_variance` dict initialization, population, and the `owner_variance.get(owner_str)` reads from the Owner loop — per CLAUDE.md rule "Remove imports/variables/functions that YOUR changes made unused"
- **Files modified:** `reports/modules/mttr_trend_module.py`
- **Commit:** 8030285

None other — plan executed as written.

## Known Stubs

None. All render paths are wired. The cold-start and error branches were not modified and continue to render safe defaults.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes. The `mttr_view` config value is whitelisted before use and never interpolated into any HTML/Excel sink (T-16-13 mitigation applied). `mttr_by_severity_module.py` byte-unchanged (`git diff --quiet` exits 0, T-16-15).

## Self-Check: PASSED

- `reports/modules/mttr_trend_module.py` — FOUND (modified)
- `delivery_config.yaml` — FOUND (modified, gitignored — on-disk only)
- `.planning/phases/16-mttr-rework/16-04-SUMMARY.md` — FOUND (created)
- Commit `8030285` — FOUND
- Commit `0e4cded` — FOUND
- `git diff --quiet -- reports/modules/mttr_by_severity_module.py` — exits 0 (D-16-10)
