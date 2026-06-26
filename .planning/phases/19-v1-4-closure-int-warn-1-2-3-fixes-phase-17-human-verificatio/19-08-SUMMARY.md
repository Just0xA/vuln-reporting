---
phase: 19-v1-4-closure-int-warn-1-2-3-fixes-phase-17-human-verificatio
plan: "08"
subsystem: human-verification (Phase 16 UAT + Phase 17 checks)
tags: [uat, human-verify, checkpoint, program_health, mttr_trend]
dependency_graph:
  requires: ["19-01", "19-02", "19-03", "19-04", "19-05", "19-06", "19-07"]
  provides: ["phase16-uat-confirmed", "phase17-checks-confirmed"]
  affects: ["delivery_config.yaml (local)", "data/trend/trend_severity_all_assets.json"]
tech_stack:
  added: []
  patterns: ["operator render-and-confirm checkpoint", "gap-closure iteration on verification findings"]
key_files:
  created: []
  modified: []
---

# 19-08 — Human Verification (Phase 16 UAT + Phase 17 checks)

Checkpoint plan: Claude prepared the verification artifacts; the operator generated and
visually confirmed the renders against the fully-fixed Wave 1–7 build (per D-07: code first →
verify-all at end). Run scope flipped to all-assets (`filters: {}`) so the 13-month history
populated MoM/sparklines (only Open Critical has full history; MTTR/Net Velocity/SLA forward-fill
— see [[project_tenable_fixed_retention_trend]] and 19-08-CHECKPOINT-FINDINGS.md).

## Outcome: APPROVED (after gap closure)

First pass surfaced issues (captured in `19-08-CHECKPOINT-FINDINGS.md`):
- D-16-13 gauge band confirmed; Excel MTTR Trend tab confirmed.
- Root cause established for empty MTTR/Net Velocity/SLA arrows: reconstructed history holds
  **severity counts only**, no derived metrics → forward-fill (operator decision, not a bug).
- Program Health readability/correctness gaps → fixed via two gap-closure plans:
  - **19-10** — PDF two-page split, per-chart captions, intake/fixed/net velocity display,
    MTTR "establishing" caption, Owner table Share%/Assets, readable Excel header.
  - **19-11** — D-7 composite RAG / "N of 4 On Track" / narrative now use the current-sign
    Net Velocity status (consistent with the tile); D-8 single-arrow + two-row tile/caption
    PDF layout, net-only Net Velocity tile.

Operator re-verified after 19-11 and **approved**. Sparse sparklines (<2 months → lone dot /
blank for Net Velocity, SLA, MTTR) accepted as-is; they fill into lines as monthly snapshots
accumulate.

## Phase 16 UAT — confirmed
- Test 1: 4-gauge MTTR headline band with SLA targets, present in owner-default view (D-16-13). ✓
- Test 2: Excel "MTTR Trend" tab, window disclosure, no SLA-target col on Owner rows. ✓
- Test 3: email MTTR panel renders. ✓
- Test 5: live snapshot capture runs (no `ModuleNotFoundError`); MTTR fields written. ✓

## Phase 17 — confirmed
- Check 1: email 4-tile KPI row + Owner velocity table; on-track count now consistent. ✓
- Check 2: `sla_rate_crit_high` present in the live snapshot entry (float or null fail-soft). ✓
- Check 3: PDF sparkline row + Owner velocity table; layout corrected via 19-10/19-11. ✓

## Self-Check: PASSED
