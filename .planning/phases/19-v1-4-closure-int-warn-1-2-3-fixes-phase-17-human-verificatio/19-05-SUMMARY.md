---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "05"
status: complete
subsystem: composer / email_sender / module-copy
tags: [fail-soft, hardening, coderabbit, copy-accuracy]
completed: "2026-06-24"
duration_seconds: 900
tasks_completed: 3
files_modified: 5
commits:
  - hash: 4ed1d0e
    message: "feat(19-05): CR-F1 + CR-F2 — composer return-type guard and metadata-on-all-fail"
  - hash: 19247b8
    message: "feat(19-05): CR-F4 — prebuilt_charts size-budget check in email_sender"
  - hash: 3196400
    message: "docs(19-05): CR-D1 + CR-D2 — align module copy/audit metadata to actual risk_score sort"
dependency_graph:
  requires: []
  provides:
    - "CR-F1: composer assemble_pdf isinstance guard before .strip()"
    - "CR-F2: _Metadata tab emitted on all-modules-failed path"
    - "CR-F4: prebuilt_charts inline images respect MAX_ATTACHMENT_SIZE_MB"
    - "CR-D1: aged_vulns_assets_module copy/audit describes risk_score DESC sort"
    - "CR-D2: high_risk_assets_module copy/audit describes risk_score DESC sort + Owner via extract_owner()"
  affects:
    - reports/modules/composer.py
    - delivery/email_sender.py
    - reports/modules/aged_vulns_assets_module.py
    - reports/modules/high_risk_assets_module.py
tech_stack:
  added: []
  patterns:
    - "isinstance guard before method result consumed (CR-F1)"
    - "split not-collected branch on failures-present vs genuinely-empty (CR-F2)"
    - "MAX_ATTACHMENT_SIZE_MB-derived per-image + cumulative budget caps (CR-F4)"
key_files:
  created:
    - tests/test_composer_fail_soft.py
  modified:
    - reports/modules/composer.py
    - delivery/email_sender.py
    - reports/modules/aged_vulns_assets_module.py
    - reports/modules/high_risk_assets_module.py
decisions:
  - "CR-F4 per-image cap set to 20% of MAX_ATTACHMENT_SIZE_MB (mirrors the ratio of the 2MB/10MB default used by the email_inline_images path)"
  - "CR-D1/CR-D2 are text-only corrections; no sort logic was changed"
---

# Phase 19 Plan 05: CR-F1/F2/F4 Fail-soft Hardening + CR-D1/D2 Copy Accuracy Summary

**One-liner:** Composer hardened against non-string PDF sections and all-modules-failed paths; prebuilt_charts budget-capped; aged_vulns and high_risk module copy aligned to actual risk_score DESC sort.

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 | CR-F1 + CR-F2 — composer return-type guard + metadata-on-all-fail | 4ed1d0e | composer.py, tests/test_composer_fail_soft.py |
| 2 | CR-F4 — prebuilt_charts size-budget check | 19247b8 | delivery/email_sender.py |
| 3 | CR-D1 + CR-D2 — module copy/audit metadata accuracy | 3196400 | aged_vulns_assets_module.py, high_risk_assets_module.py |

## What Was Built

### CR-F1 (composer.py assemble_pdf)

Added an `isinstance(html_section, str)` guard immediately after `instance.render_pdf_section(data, config)` and before any `.strip()` call. A module returning `None`, an int, or any non-string now logs a warning and is converted to `""` rather than crashing assembly. The sibling module's output continues to render.

### CR-F2 (composer.py assemble_analyst_workbook)

Split the `if not collected:` branch into two paths:
- **failures is empty** (genuinely no data): return `None` as before (D-20 no-data behavior preserved).
- **failures is non-empty** (every module crashed): log a warning and fall through to workbook creation so `_write_analyst_metadata_tab()` still executes, writing a `_Metadata`-only workbook with the failure audit.

### CR-F4 (email_sender.py prebuilt_charts)

The existing `prebuilt_charts` loop attached base64 PNG data with no size check. Added the same guard pattern as the `email_inline_images` path:
- Per-image cap: 20% of `MAX_ATTACHMENT_SIZE_MB` (5 MB default → 1 MB cap per image)
- Cumulative cap: `MAX_ATTACHMENT_SIZE_MB` in bytes
- On exceed: log warning, skip/break — never attach an oversized payload

### CR-D1 (aged_vulns_assets_module.py)

Text-only corrections:
- Class docstring: "highest percentage at the top" → "highest risk score at the top"
- `get_audit_info()` owner_breakdown: "Primary sort: affected DESC / Secondary sort: percentage DESC" → "Primary sort: risk_score DESC (highest risk score at the top)"

These align with the actual `sort_values("risk_score", ascending=False)` at L272.

### CR-D2 (high_risk_assets_module.py)

Text-only corrections:
- Class docstring: "highest percentage of high-risk assets at the top" → "highest risk score at the top"
- `get_audit_info()` BU_breakdown: "Application tag" → "Owner tag via extract_owner()"; "Primary sort: affected DESC / Secondary sort: percentage DESC" → "Primary sort: risk_score DESC (highest risk score at the top)"

These align with the actual `extract_owner()` call at L246 and `sort_values("risk_score", ascending=False)` at L277.

## Verification Results

```
pytest tests/test_composer_fail_soft.py -q -o addopts=""
→ 3 passed

pytest tests/ -k "composer or email_sender or email or aged_vulns or high_risk" -q -o addopts=""
→ 32 passed

python -c "import reports.modules.composer, delivery.email_sender"
→ IMPORTS OK

grep -ni "highest percentage" reports/modules/aged_vulns_assets_module.py reports/modules/high_risk_assets_module.py
→ (no output — inaccurate phrasing removed)

grep -n "MAX_ATTACHMENT_SIZE_MB" delivery/email_sender.py
→ appears on prebuilt_charts path (L489-493)

grep -n "isinstance" reports/modules/composer.py (assemble_pdf region)
→ isinstance(html_section, str) guard present
```

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None — all changes are internal hardening (type guard, budget cap) or text corrections with no new network endpoints, auth paths, or schema changes.

## Self-Check: PASSED

- `reports/modules/composer.py` — exists and contains `isinstance(html_section, str)` guard and CR-F2 split
- `delivery/email_sender.py` — exists and contains `MAX_ATTACHMENT_SIZE_MB` on prebuilt_charts path
- `tests/test_composer_fail_soft.py` — exists with 3 tests (all pass)
- `reports/modules/aged_vulns_assets_module.py` — "highest percentage" removed; "risk_score" in copy
- `reports/modules/high_risk_assets_module.py` — "highest percentage" removed; "Owner tag via extract_owner()" and "risk_score" in audit
- Commits 4ed1d0e, 19247b8, 3196400 — verified in git log
