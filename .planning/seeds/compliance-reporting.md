---
title: Compliance Reporting from Tenable Audit Scans
trigger_condition: When the operational remediation team requests CIS/audit failure tracking as a dedicated report, OR when an executive report needs a compliance-posture roll-up alongside vuln posture. Either trigger is sufficient to start; operational is expected to fire first.
planted_date: 2026-06-01
---

# Compliance Reporting from Tenable Audit Scans

## Background

The reporting suite today consumes vulnerability data via `tio.exports.vulns()` and asset data via `tio.exports.assets()`. Tenable also exposes **compliance/audit scan results** (`tio.exports.compliance()`) — per-asset, per-check pass/fail/warning records driven by CIS, DISA STIG, and custom `.audit` benchmarks. This data is currently unused.

The organization runs CIS as its primary benchmark, plus custom audit files that tailor CIS-derived checks (e.g., security banner language) where local policy requires a variant.

## What this seed triggers

When the trigger condition is met, build a compliance-reporting capability in two staged cuts:

### v1 — Operational, failures grouped by check

Audience: IT remediators (same shape as `ops_remediation`).

- Fetch source: `tio.exports.compliance()` (verify enrichment needs — see [[compliance-data-model-decisions]] and the research-questions entry).
- Output shape: one row per failing check, with affected-asset count and an asset list. Drives a fix-once-deploy-many workflow.
- Unified view: a single workbook/PDF with a `framework` / `audit_file` column rather than per-benchmark splits — CIS and CIS-tailored customs coexist in one view.
- Scope: tag-driven, following the existing `delivery_config.yaml` group model (`tag_category` / `tag_value`). Slots into the existing group-executor contract with no new scoping concept.
- Likely realized as a new top-level report slug (e.g. `compliance_operational`) or, preferably, as one or more metric modules under `reports/modules/` so it can be composed alongside other modules in `composed_report`.

### v2 — Failures grouped by asset (business-unit punch lists)

Audience: business-unit / asset owners.

Same `compliance_df`, different grouping — one row per asset with failing-check counts and a drill-down list. Trigger: once v1 has driven failure volume down enough that an asset-owner punch list is digestible.

### v3 — Executive roll-up

Audience: senior leadership / board.

Same `compliance_df`, rendered as a RAG-strip metric (% compliant across scope, trend) and tied into the existing executive/management-summary reports. Likely a new metric module that lives next to existing board/management modules.

## Why staged this way

Operational first validates the fetch, normalizes the dataframe shape, and gives us a working artifact before the exec roll-up needs to render anything. Each later cut is a different view of the same `compliance_df` — the dataframe is the load-bearing piece, the renders are cheap once it exists.

## Why this is a seed and not a phase

The first audience (operational remediators) hasn't formally requested the report yet; this captures the design direction so when they do, the v1 shape, data-model decisions, and staging are already settled. Once a stakeholder pulls v1 in, promote this to a phase via `/gsd-phase`.
