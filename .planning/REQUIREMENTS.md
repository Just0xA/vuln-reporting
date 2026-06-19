# Requirements: v1.4 Management Summary Reporting Improvement

**Defined:** 2026-06-11
**Core Value:** Right metric, right audience, right channel — without writing a new report each time.

## v1.4 Requirements

The June-2026 management/exec trend-cut report batch built as thin four-channel modules on the shipped S1 (trend) + S2 (Owner) substrates, plus the GEN-01 `management_summary` migration. All new modules implement the full four-channel render contract (PDF section, Excel tabs, email panel, analyst tabs, RAG-strip entry). WAS findings and the External MoM trend are deferred (no pyTenable upgrade this milestone).

### Shared Substrates (SUB)

- [x] **SUB-01**: A reusable external-scope helper (`utils/external_scope.py`) classifies an asset as external when it is tagged `Location=External/DMZ` **OR** carries a public (non-RFC1918, non-CGNAT/loopback/link-local) IPv4 address, and emits a mismatch/exception list (public-IP-but-untagged / tagged-but-private) mirroring the S2 `Unassigned` catch-all. Pure compute, stdlib `ipaddress` only.
- [x] **SUB-02**: A reusable asset-count denominator helper (`utils/asset_count.py`) returns the current-run asset total for Vulnerability Density; historical denominators are read from the existing S1 snapshot `asset_count` field (D-04), never recomputed from live `assets_df`.
- [x] **SUB-03**: `composed_report.py` forwards trend snapshots and recast rules to modules that need them via gated frozensets (`_MODULES_NEEDING_TREND_SNAPSHOTS`, `_MODULES_NEEDING_RECAST_RULES`), following the existing `_MODULES_NEEDING_FIXED_VULNS` pattern; the S1 snapshot capture is extended (where needed) to carry new-vs-fixed / reopened / exception counts without breaking existing callers.

### Report Modules (RPT)

- [x] **RPT-01**: A reader can see **New vs Remediated** findings per month (incoming vs remediated) trended against prior months, with an Owner cut.
- [x] **RPT-02**: A reader can see **Vulnerability Density** (vulns per asset) trended month-over-month, using each month's own asset-count denominator.
- [x] **RPT-03**: A reader can see **Reopened Vulnerabilities** (build/config regressions: `state==REOPENED` / `resurfaced_date`) with an Owner cut and an analyst drill-down.
- [x] **RPT-04**: A reader can see **Accepted & Recast** posture (ACCEPTED and RECASTED tracked separately) with current vs previous-month ▲▼% change, cut by Owner; sourced from `severity_modification_type` / `recast_rule_uuid` + `fetch_recast_rules()`.
- [x] **RPT-05**: A reader can see a **reworked MTTR** (`mttr_trend`, new MODULE_ID) that discloses its ~30-day measurement window, uses a sample-weighted overall mean, is reopened-aware (no reopen-cycle inflation), and adds month-over-month trend + an Owner cut on the four-channel contract.
- [x] **RPT-06**: A reader can see an **External / DMZ exposure cut** of host-vuln findings (scope from SUB-01) plus the analyst mismatch list; current-snapshot only (WAS and MoM trend deferred).
- [x] **RPT-07**: A reader can see a **Program Health Overview** one-pager composing New-vs-Remediated velocity, MTTR, and SLA posture into a composite RAG with an Owner velocity table; cold-start-safe.

### management_summary Migration (GEN)

- [ ] **GEN-01**: `management_summary` is migrated from its bespoke render path onto the four-channel module contract (becoming chrome-aware via `_CHROME_AWARE_SLUGS`), composing the existing + new modules, with no regression to existing recipient-group delivery.

### Quality & Correctness Bars (QUAL)

- [x] **QUAL-01**: Every month-over-month module branches on the trend store's `insufficient_data` (cold-start) signal and renders a cold-start message instead of `NaN%` or a crash; every new tag/Owner scope is treated as a valid cold start.
- [x] **QUAL-02**: All open-count and MTTR logic uses the reopened-aware two-interval predicate (`open_findings_at`) — no ~19% REOPENED drop, no reopen-cycle MTTR inflation.
- [x] **QUAL-03**: Every new module renders safely on a zero-row / filtered-to-zero input across all four channels (`safe_pct`/`safe_int`/`safe_format`, `_empty_result()`).
- [x] **QUAL-04**: The GEN-01 cutover is guarded by a structural smoke baseline captured **before** any rewrite and visual operator UAT after; the legacy bespoke trend writer is removed in the same change that routes reads through `read_trend()` (no dual-writer window).
- [x] **QUAL-05**: Any new persisted trend snapshot, baseline, or committed artifact contains aggregate counts only — no hostnames, IPs, plugin names, or asset-level fields (D-04-08).

### Documentation (DOC)

- [ ] **DOC-02**: Auditor-facing calculation runbooks document each new v1.4 module (metric definition, data source, edge-case handling, disclosed MTTR window, external-scope rule).

## Future Requirements (deferred)

### Operator Reporting (the deferred "Reading A")

- **GEN-02**: Migrate `ops_remediation` to the module contract as the Operator Remediation Report v2 (layered priority model: exposure → Dev/NonProd/Prod → risk flags → aged → VPR+footprint; fix-type classification; threat-intel YAML intake).

### External / WAS

- **EXT-WAS-01**: Web App Scan (WAS) findings in the External Exposure report — gated on the pyTenable-upgrade decision (1.5.2 `tio.was` has no VPR + no lifecycle fields).
- **EXT-TREND-01**: External Exposure month-over-month trend via an S1 parameterized external dimension.

### Framework / Performance (carried backlog)

- **GEN-03/04**: Broader YAML-driven module composition beyond the `composed_report` slug.
- **PERF-01..04**: per-batch enrich cache, midnight cache crossover, log rotation, tag-value typo detection.
- **LEGACY-01**: re-evaluate the 6 unbuilt canned reports in CLAUDE.md as candidate module bundles.

## Out of Scope

| Feature | Reason |
|---------|--------|
| pyTenable SDK upgrade | Locked constraint this milestone; WAS deferral specifically avoids needing it |
| WAS / `tio.exports.was()` fetcher | 1.5.2 `tio.was` has no VPR + no lifecycle → no WAS trend/SLA; deferred to EXT-WAS-01 |
| External Exposure MoM trend | Needs S1 external-dimension extension; v1.4 ships current-snapshot only (EXT-TREND-01) |
| MTTR history backfill beyond ~29 days | Tenable retains fixed findings only ~29 days (Spike 002); backfill would fabricate data |
| Operator Remediation Report (GEN-02) | The deferred "Reading A"; management trend cuts prioritized first |
| Sub-monthly reopen / new-vs-remediated cadence | Partial-month counts are misleading; monthly snapshot cadence retained |

## Plan-Time Decisions (lock per phase — see `research/SUMMARY.md`)

These are NOT milestone-scoping decisions; each must be locked in the plan context of the phase that implements the affected module. Recommended resolutions are in `research/SUMMARY.md`.

| # | Decision | Affected | Phase |
|---|----------|----------|-------|
| OD-1 | "New" inflow = `first_found` only vs `OR resurfaced_date` | RPT-01 | Phase 15 |
| OD-2 | Density denominator definition (all licensed vs on-time-scanned) | RPT-02, SUB-02 | Phase 14 |
| OD-3 | S1 snapshot dimension extension shape (reopened/exception/new-fixed) | SUB-03, RPT-03, RPT-04 | Phase 15 |
| OD-4 | MTTR resolved-population (exclude reopened? recast? first-fix only?) | RPT-05 | Phase 16 |
| OD-5 | Program Health composite-RAG threshold rule | RPT-07 | Phase 17 |
| OD-6 | External Exposure MoM trend mechanism (deferred vs S1 dimension) | RPT-06 | Phase 14 |
| OD-7 | MTTR rework MODULE_ID (`mttr_trend`, leave `mttr_by_severity` intact) | RPT-05 | Phase 16 |
| OD-8 | `management_summary` legacy trend-JSON migration vs cold start | GEN-01 | Phase 18 |

Plus a Phase 15 verification: confirm `resurfaced_date` is populated on the live tenant before finalizing the Reopened drill-down schema (RPT-03).

## Traceability

Final phase assignments (roadmap created 2026-06-11).

| Requirement | Phase | Status |
|-------------|-------|--------|
| SUB-01 | Phase 14 | Complete |
| SUB-02 | Phase 14 | Complete |
| SUB-03 | Phase 14 | Complete |
| RPT-01 | Phase 15 | Complete |
| RPT-02 | Phase 15 | Complete |
| RPT-03 | Phase 15 | Complete |
| RPT-04 | Phase 15 | Complete |
| RPT-06 | Phase 15 | Complete |
| QUAL-01 | Phase 15 (first verified; enforced Phases 16–18) | Complete |
| QUAL-02 | Phase 15 (first verified; enforced Phases 16–18) | Complete |
| QUAL-03 | Phase 15 (first verified; enforced Phases 16–18) | Complete |
| QUAL-05 | Phase 15 (first verified; enforced Phases 16–18) | Complete |
| RPT-05 | Phase 16 | Complete |
| RPT-07 | Phase 17 | Complete |
| GEN-01 | Phase 18 | Pending |
| QUAL-04 | Phase 18 | Complete |
| DOC-02 | Phase 18 | Pending |

**Coverage:**
- v1.4 requirements: 17 total
- Mapped to phases: 17 ✓
- Unmapped: 0 ✓

---
*Requirements defined: 2026-06-11*
*Last updated: 2026-06-11 — traceability finalized by roadmapper (Phases 14–18)*
