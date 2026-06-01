---
title: Compliance Reporting — v1 Data Model Decisions
date: 2026-06-01
context: Captured during /gsd-explore conversation on adding Tenable compliance scan data to the reporting suite. Documents the durable shape decisions for v1 so they are not re-litigated when the work is promoted from seed ([[compliance-reporting]]) to a phase.
---

# Compliance Reporting — v1 Data Model Decisions

These decisions apply to the **v1 operational cut** of compliance reporting. v2 (asset-grouped punch lists) and v3 (executive roll-up) reuse the same dataframe and inherit these decisions unless explicitly overridden.

## Decisions

### 1. Failures-only, not pass/fail/warning combined

v1 surfaces only `FAILED` checks. `PASSED` and `WARNING` rows are filtered out at the dataframe level before render.

**Why:** The audience is remediators acting on findings. Including passing checks balloons row count without adding actionable information. Warnings can be revisited if a stakeholder explicitly asks; deferred for v1.

### 2. Grouped by check (not by asset) in v1

One row per failing check, with columns for affected-asset count and an affected-asset list (or a separate detail tab keyed by check ID). Asset-grouped view is explicitly **deferred to v2** and not built in v1.

**Why:** At current asset volume, an asset-grouped view produces unmanageable row counts and obscures the fix-once-deploy-many pattern. Operators reported they prefer to see "this check is failing on N assets — fix the template/policy once" over an asset-by-asset punch list. v2 flips to asset-grouped once v1 has driven failure volume down enough that punch lists are digestible.

### 3. Unified framework view (no per-benchmark split)

CIS, DISA STIG, and custom `.audit` files render together in one workbook/PDF with a `framework` or `audit_file` column distinguishing source. No per-framework report splits in v1.

**Why:** The org runs CIS as its primary benchmark plus custom audit files that tailor CIS-derived checks. Splitting per framework would fragment one logical remediation queue across multiple deliveries. A single column distinguishes source for filtering inside Excel without forcing the report itself to fork.

### 4. Tag-scoped per delivery group (existing pattern)

Compliance reports follow the same `tag_category` / `tag_value` filter contract as every other report in the suite. No new scoping concept (e.g., scoping by benchmark/audit-file at the YAML level) is introduced in v1.

**Why:** The audit-scan results carry asset identity, so they can be filtered by tag exactly like vuln data. Reusing the existing tag-scope pattern means the new report slots into `delivery_config.yaml` groups cleanly and reuses the group-executor in `run_all.py` with no new branching.

### 5. Realize as metric module(s) under `reports/modules/`, not a one-off slug

Prefer building the compliance views as module(s) registered with the module infrastructure so they can be composed into `composed_report` bundles alongside vuln modules. A dedicated top-level slug is acceptable as a stepping stone but should not be the long-term home.

**Why:** The four-channel render contract (PDF / Excel / email panel / analyst tabs) and the RAG-strip cover-page mechanism already give us everything the operational, asset-grouped, and executive cuts need. Building as modules from the start lets v3 (exec roll-up) drop into existing executive/management reports without a second migration.

## Out of scope for v1

- Per-asset pass/fail history / trend over time (deferred; needs a snapshot store similar to `data/trend/`).
- Auditor-grade frozen point-in-time evidence exports (different audience, different format — separate seed if/when requested).
- Compliance-only delivery groups in `delivery_config.yaml` (operational team likely reuses an existing group's tag scope first).

## Open questions

See `.planning/research/questions.md` — primarily whether `tio.exports.compliance()` returns the audit-file identity and check metadata needed for the failures-by-check fan-in, or whether a second fetch is required to enrich.
