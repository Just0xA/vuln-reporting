---
phase: quick-260608-cma
plan: 01
subsystem: reports/modules
tags: [modules, composed_report, vpr, cpe, classifier, tag_severity_share, vuln_type_distribution]
dependency_graph:
  requires: [composed_report slug, ReportComposer, four-channel module contract, registry.discover]
  provides: [tag_severity_share module, vuln_type_distribution module, env_vuln_total forwarding]
  affects: [composed_report.py (additive only), delivery_config.yaml (additive only)]
tech_stack:
  added: []
  patterns: [VTD-01 family-override CPE classifier, env_vuln_total gating mirror of fixed_vulns_df]
key_files:
  created:
    - reports/modules/tag_severity_share_module.py
    - reports/modules/vuln_type_distribution_module.py
    - tests/unit/test_tag_severity_share.py
    - tests/unit/test_vuln_type_distribution.py
    - docs/tag_severity_share_calculations.md
    - docs/vuln_type_distribution_calculations.md
  modified:
    - reports/composed_report.py (gated env_vuln_total forwarding, ~19 lines)
    - delivery_config.yaml (additive example group, untracked/gitignored)
decisions:
  - "D3 honored: _bucket_severity is report-local and never calls config.vpr_to_severity"
  - "D4 fallback label is Other (not Unclassified per spike) — matches spec"
  - "RAG status for both share metrics is yellow (informational) with no threshold — documented in module docstrings and runbooks"
  - "delivery_config.yaml is gitignored by project decision; YAML edit is on disk and validated by dry-run but not committed"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-08"
  tasks_completed: 6
  tasks_total: 6
  files_created: 6
  files_modified: 2
---

# Quick Task 260608-cma: Tag Severity & Type Profile Modules Summary

**One-liner:** Two auto-discovered metric modules delivering VPR-pure severity share vs environment (`tag_severity_share`) and VTD-01 family-override CPE type distribution (`vuln_type_distribution`) via the existing `composed_report` slug with an 8-line gated `env_vuln_total` forwarding addition.

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 | Build tag_severity_share module | `3a13011` | reports/modules/tag_severity_share_module.py |
| 2 | Build vuln_type_distribution module | `8d04320` | reports/modules/vuln_type_distribution_module.py |
| 3 | Forward env_vuln_total from composed_report | `4ad9694` | reports/composed_report.py |
| 4 | Unit tests for mapper, classifier, env-share math | `fde8b60` | tests/unit/test_tag_severity_share.py, tests/unit/test_vuln_type_distribution.py |
| 5 | Auditor runbooks | `1edd9bc` | docs/tag_severity_share_calculations.md, docs/vuln_type_distribution_calculations.md |
| 6 | Additive example YAML group + schema validation | (disk only) | delivery_config.yaml |

## Test Results

```
102 passed, 224 warnings in 3.54s
```

Breakdown:
- `tests/unit/test_tag_severity_share.py` — 28 tests (VPR mapper boundaries, null/NaN/0.0/"" none-bucket, env-share math, /0 guard, pcts-sum-invariant, empty-data guard)
- `tests/unit/test_vuln_type_distribution.py` — 43 tests (VTD-01 labelled samples, family override, a>o>h precedence, Other fallback, Hardware hidden at 0, empty-data guard)
- `tests/unit/test_modules.py` — 31 tests (four-channel contract + empty-data guard now also covering the two new modules via auto-discovery parametrize)

`python run_all.py --dry-run` — All 5 group(s) validated successfully.

## Deviations from Plan

### delivery_config.yaml — not committable (gitignored by project decision)

**Found during:** Task 6

**Issue:** `delivery_config.yaml` was deliberately untracked in commit `fb94c60` ("untrack delivery_config.yaml (already in .gitignore)"). The plan and constraints both ask to commit it, but the project decision to gitignore it takes precedence (CLAUDE.md: surgical changes, don't break existing decisions).

**Fix:** The additive example group is written to disk and validated by `python run_all.py --dry-run` (5 groups, all valid). The file is NOT force-added to git against the project's `.gitignore` rule.

**Impact:** Zero — the YAML content is on disk, validated, and will be picked up by any run. No code correctness impact.

## Decisions Made

1. **D3 honored strictly:** `_bucket_severity` is a report-local pure function — never imports or calls `config.vpr_to_severity`. Documented in module docstring, `get_audit_info()`, and `docs/tag_severity_share_calculations.md` (the "intentional divergence" section auditors need).

2. **D4 fallback label `"Other"` not `"Unclassified"`:** The spike reference uses `"Unclassified"` but the approved spec D4 says `"Other"`. Implemented per spec, test asserts `result != "Unclassified"`.

3. **RAG status for share metrics:** Both modules use `"yellow"` (informational) when data is present — no threshold locked by spec. Documented in module docstrings so it is not misread as a threshold-breach warning.

4. **`delivery_config.yaml` gitignore:** Not force-committed. Validated on disk.

## Known Stubs

None — both modules compute real metrics from the input DataFrame. No hardcoded placeholder values flow to rendered output.

## Threat Flags

No new network endpoints, auth paths, or trust boundary changes introduced. Both modules are pure compute + render; they read from the already-fetched `vulns_df` DataFrame and write HTML/Excel fragments. No new Tenable API calls.

## Self-Check

Files created/exist:
- reports/modules/tag_severity_share_module.py — FOUND
- reports/modules/vuln_type_distribution_module.py — FOUND
- tests/unit/test_tag_severity_share.py — FOUND
- tests/unit/test_vuln_type_distribution.py — FOUND
- docs/tag_severity_share_calculations.md — FOUND
- docs/vuln_type_distribution_calculations.md — FOUND

Commits:
- 3a13011 — FOUND
- 8d04320 — FOUND
- 4ad9694 — FOUND
- fde8b60 — FOUND
- 1edd9bc — FOUND

## Self-Check: PASSED
