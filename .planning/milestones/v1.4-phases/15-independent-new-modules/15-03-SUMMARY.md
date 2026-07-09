---
phase: 15-independent-new-modules
plan: "03"
subsystem: reports/modules
tags: [module, external-dmz, current-snapshot, four-channel, rpt-06]
status: complete

dependency_graph:
  requires:
    - utils/external_scope.py          # Phase-14 substrate (external_scope())
    - reports/modules/base.py          # BaseModule, ModuleConfig, ModuleData
    - reports/modules/registry.py      # @register_module auto-discovery
    - reports/modules/rag_utils.py     # rag_status_from_value, build_rag_strip_entry
    - reports/modules/format_utils.py  # safe_int, safe_pct, safe_format
    - reports/modules/board_report_utils.py  # extract_owner
  provides:
    - reports/modules/external_dmz_module.py  # MODULE_ID=external_dmz
  affects:
    - reports/modules/registry._modules  # adds external_dmz at import time

tech_stack:
  added: []
  patterns:
    - external_scope() inline substrate call (no new kwargs gate)
    - CoW-safe .assign() + groupby+map for finding_count
    - no_data gray cell branch for zero-external-asset groups (valid state, not error)

key_files:
  created:
    - reports/modules/external_dmz_module.py
    - tests/test_external_dmz_module.py
  modified: []

decisions:
  - "Phase-14 D-03 enforced: external_dmz is current-snapshot only; no trend_snapshots kwarg, no cold_start branch, not in _MODULES_NEEDING_TREND_SNAPSHOTS"
  - "Mismatch analyst tab uses locked schema (asset_uuid, ip_address, owner_tag, untagged_reason, finding_count) per Pitfall 11 / D-11 — no per-finding plugin/CVE columns"
  - "Synthetic gap-detection fixtures use 1.2.3.x (is_global=True) instead of 203.0.113.x TEST-NET-3 (Python 3.14 classifies TEST-NET-3 as is_global=False)"

metrics:
  duration_minutes: 25
  completed_date: "2026-06-11"
  tasks_completed: 1
  tasks_total: 1
  files_created: 2
  files_modified: 0
---

# Phase 15 Plan 03: External DMZ Exposure Module Summary

**One-liner:** Four-channel ExternalDmzModule counting Critical/High/Medium open findings on Location=External/DMZ and public-IP-untagged gap assets, with locked aggregate mismatch analyst tab (RPT-06, current-snapshot only).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Failing tests for ExternalDmzModule | 0b4b539 | tests/test_external_dmz_module.py |
| 1 (GREEN) | Implement ExternalDmzModule | c6e342d | reports/modules/external_dmz_module.py |

## What Was Built

`ExternalDmzModule` is a current-snapshot four-channel module (MODULE_ID=`external_dmz`) that:

1. **Calls `external_scope(assets_df)` inline** in `compute()` — the Phase-14 substrate does tag-authoritative classification (Location=External/DMZ tagged assets + public-IP-untagged gap assets). No new kwargs gate needed.

2. **Scopes vulns** via `asset_uuid.isin(scoped_uuids)` and counts Critical/High/Medium severity.

3. **RAG strip** from external Critical count with `direction="lower_is_better"`: green=0, yellow=1–5, red=>5. Thresholds overridable via `config.options` (`green_ext_crit_threshold`, `yellow_ext_crit_threshold`).

4. **Zero-external-asset groups** return a valid `ModuleData` with gray "no_data" strip cell and `summary_text="No external-scope assets in scope."`, `error=None` — this is a normal state, not an error.

5. **Mismatch analyst tab** `"External Scope Mismatches"` uses the locked schema: `asset_uuid`, `ip_address`, `owner_tag`, `untagged_reason`, `finding_count`. The `finding_count` is a groupby-size aggregate per mismatch asset (CoW-safe `.assign()` + map). No per-finding plugin/CVE/severity columns (Pitfall 11 / D-11).

6. **Four render channels** implemented: `render_pdf_section`, `render_excel_tabs`, `render_email_panel` (CONTRACT-01), `render_analyst_tabs` (CONTRACT-02), `render_rag_strip_entry` (CONTRACT-03).

7. **No trend branch** — `compute()` has no `trend_snapshots` kwarg, no cold-start branch, and `external_dmz` is not added to `_MODULES_NEEDING_TREND_SNAPSHOTS` (Phase-14 D-03 / EXT-TREND-01 deferred to v1.5).

## Test Coverage

29 tests pass under `-W error::FutureWarning` and pandas CoW strict mode:
- Module registration + registry presence
- No trend_snapshots reference in compute() body (Phase-14 D-03 enforcement)
- External scope counts (Location=External, Location=DMZ, mixed, internal exclusion)
- Zero-external-asset gray cell (error=None, summary text, rag_color)
- Mismatch schema lock (exact columns, no plugin/CVE forbidden columns, aggregate finding_count)
- RAG thresholds (green=0, yellow=1–5, red=>5, overridable)
- Empty-data guard × all four render channels + _empty_result path
- CoW strict mode no FutureWarning

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TEST-NET-3 IPs not globally routable in Python 3.14**
- **Found during:** Task 1 (RED → GREEN iteration)
- **Issue:** Plan specified `ip_address "203.0.113.x" TEST-NET-3` for synthetic gap fixtures. Python 3.14's `ipaddress.ip_address("203.0.113.1").is_global` returns `False` — so these IPs do NOT trigger the public-IP-untagged gap detection path in `external_scope()`. Using them in gap-detection test fixtures would produce empty mismatch tabs and failing assertions.
- **Fix:** Changed gap-detection fixture IPs to `1.2.3.x` (genuinely globally-routable, no real operator association, synthetic test values). The `ip_address` display field in committed fixtures still uses the same `1.2.3.x` values — within scope of QUAL-05 (no real customer data from actual scans).
- **Files modified:** `tests/test_external_dmz_module.py`
- **Commit:** 0b4b539

**2. [Rule 1 - Bug] Registry API: REGISTRY is not exported; _modules is the dict**
- **Found during:** Task 1 (RED → GREEN iteration)
- **Issue:** Test initially used `from reports.modules.registry import REGISTRY` following the pathfinder pattern from another test. The actual registry stores modules in `registry._modules` (no `REGISTRY` export).
- **Fix:** Updated test to use `from reports.modules import registry; assert "external_dmz" in registry._modules`.
- **Files modified:** `tests/test_external_dmz_module.py`
- **Commit:** 0b4b539

**3. [Rule 2 - Documentation] trend_snapshots test checked module-level docstring**
- **Found during:** Task 1 (GREEN phase test run)
- **Issue:** The `test_no_trend_snapshots_kwarg_in_module` test checked the entire module source, which included the module docstring mentioning "trend_snapshots" as a documentation note. This caused a false assertion failure on a compliant module.
- **Fix:** Updated test to extract and check only `compute()` method source with docstring lines stripped — precisely what D-03 requires (the kwarg and branch must not exist in code, not in documentation prose).
- **Files modified:** `tests/test_external_dmz_module.py`
- **Commit:** 0b4b539

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced. `mismatches_df` PII boundary is maintained: the mismatch tab only passes through `external_scope()` output columns (operator-local) and the `finding_count` aggregate — no additional asset-level fields are added.

## Self-Check: PASSED

- `reports/modules/external_dmz_module.py` exists: FOUND
- `tests/test_external_dmz_module.py` exists: FOUND
- Commit 0b4b539 (RED): FOUND
- Commit c6e342d (GREEN): FOUND
- `pytest tests/test_external_dmz_module.py -x -q -W error::FutureWarning` exits 0: VERIFIED
- `external_dmz` in registry._modules: VERIFIED
- `external_dmz` NOT in `_MODULES_NEEDING_TREND_SNAPSHOTS`: VERIFIED
- Mismatch analyst columns == locked schema: VERIFIED by test
