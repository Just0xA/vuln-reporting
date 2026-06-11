---
phase: 15
slug: independent-new-modules
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-11
---

# Phase 15 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> **Auditor verdict: SECURED — 28/28 threats CLOSED.** Register authored at PLAN time (verify-mitigations mode).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| vulns_df → analyst_rows / committed fixtures | Asset-level finding rows could carry PII (hostnames, IPs) if drill-down over-populated | Aggregate counts only; locked drill-down schemas |
| live-tenant cache → conversation (15-01 spot-check) | Task-2 spot-check could leak row-level REOPENED data to the AI | Aggregate counts only (process control) |
| live vulns/assets → persisted trend JSON | Snapshot file is operator-shared; must hold aggregate counts only | int / None scalar counts |
| mismatches_df (asset_uuid/ip/owner) → analyst tab / fixtures | External-scope mismatch fields are operator-local only | Locked 5-col schema, RFC 5737 fixtures |
| trend_snapshots history → MoM delta render | Missing/short history can produce NaN%/crash if cold-start unguarded | Guarded cold-start ModuleData |
| recast_rules_df + vulns_df → accepted/recast counts | Expired rules inflate accepted posture if not cross-checked | Expiry-filtered finding counts |
| recast_reason / rule detail → logs / analyst tab / fixtures | Free-text reason may carry hostnames/IPs; UUIDs may be real | Field never read; synthetic fixture UUIDs |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation (evidence) | Status |
|-----------|----------|-----------|-------------|------------------------|--------|
| T-15-01-PII | Information Disclosure | analyst_rows drill-down + fixtures | mitigate | `reopened_vulns_module.py:285-306` — detail cols restricted to `plugin_id, resurfaced_date, reopen_lag_days, owner`; `asset_uuid` excluded; `test_reopened_vulns_module.py:438-453` asserts schema lock. Synthetic fixtures. | closed |
| T-15-01-SPOT | Information Disclosure | Task-2 live-tenant spot-check | mitigate | `reopened_vulns_module.py` — zero `print()`; all logging `logger.debug/.error` with `len()`/`str(exc)` only. Process control structurally enforced. | closed |
| T-15-01-DOS | Denial of Service | compute() on zero-row/malformed df | mitigate | `reopened_vulns_module.py:156-158` empty-data guard → `_empty_result`; `try/except` at line 353; renderers safe on `data.error`. | closed |
| T-15-01-SC | Tampering | pip/npm installs | accept | Zero new dependencies in Plan 15-01. | closed |
| T-15-02-PII | Information Disclosure | new_entry aggregate fields | mitigate | `trend_store.py:337-370` — six new keys store `int(...)`/`None` only; `.gitignore:12` confirms `data/trend/` ignored. | closed |
| T-15-02-COMPAT | Tampering (data integrity) | snapshots / read_trend | mitigate | `trend_store.py:230-234` — all new params `Optional…=None`; old snapshots read via `snap.get()` (no KeyError); idempotent overwrite unchanged. | closed |
| T-15-02-LOG | Information Disclosure | INFO log of counts | accept | `capture_trend_snapshot.py:279-282` — INFO emits aggregate scalar counts only. | closed |
| T-15-02-SC | Tampering | pip/npm installs | accept | Zero new dependencies in Plan 15-02. | closed |
| T-15-03-PII | Information Disclosure | mismatch analyst tab + fixtures | mitigate | `external_dmz_module.py:315-317` — locked schema `asset_uuid, ip_address, owner_tag, untagged_reason, finding_count`; no plugin/CVE rows. RFC 5737 (`203.0.113.x`) fixtures. | closed |
| T-15-03-SCOPE | Tampering (correctness) | external_scope classification | mitigate | `external_dmz_module.py:57,163` — Phase-14 `external_scope()` imported and called inline; no re-implementation. | closed |
| T-15-03-DOS | Denial of Service | compute() on zero-row input | mitigate | `external_dmz_module.py:168-196` empty `scoped_assets_df` gray-cell branch; `try/except` at line 351 → `_empty_result`. | closed |
| T-15-03-SC | Tampering | pip/npm installs | accept | Zero new dependencies in Plan 15-03. | closed |
| T-15-04-COLDSTART | Denial of Service | MoM delta on <2 snapshots | mitigate | `new_vs_remediated_module.py:247-257` insufficient_data → `_build_cold_start_result`; `_safe_mom_delta()` returns `"N/A"` on prev None/0. | closed |
| T-15-04-OUTFLOW | Tampering (correctness) | absent fixed_findings_count | mitigate | `new_vs_remediated_module.py:334-343` — absent value → `None` outflow + cold flag, never silent zero (D-15-06). | closed |
| T-15-04-PII | Information Disclosure | analyst rows + fixtures | mitigate | `new_vs_remediated_module.py:460-476` — per-month / per-Owner aggregate only; synthetic fixtures. | closed |
| T-15-04-CORRECT | Tampering (correctness) | reopened double-count | mitigate | `new_vs_remediated_module.py:318-343` — resurfaced excludes net_new (`~net_new_mask`); outflow from FIXED-only aggregate (`trend_store.py:354-356`). | closed |
| T-15-04-REGRESS | Tampering | composed_report.py groups | mitigate | `composed_report.py:86-99` — only trend/recast frozensets extended; `_MODULES_NEEDING_FIXED_VULNS` and run_report() signature untouched. | closed |
| T-15-04-SC | Tampering | pip/npm installs | accept | Zero new dependencies in Plan 15-04. | closed |
| T-15-05-DRIFT | Tampering (correctness) | per-snapshot denominator | mitigate | `vuln_density_module.py:306,346-356` — each point divides by its own `on_time_asset_count`; `len(assets_df)` never used for history; >10% drift flagged. | closed |
| T-15-05-DIV0 | Denial of Service | zero/None asset count | mitigate | `vuln_density_module.py:264-271,307-309` — None denom → `_empty_result`; None/0 snapshot denoms skipped; `safe_format`/`safe_int` throughout. | closed |
| T-15-05-COLDSTART | Denial of Service | <2 usable snapshots | mitigate | `vuln_density_module.py:241-255,335-340` — top-level + secondary cold-start branches → `_build_cold_start_result`. | closed |
| T-15-05-PII | Information Disclosure | per-Owner density fixtures | mitigate | `vuln_density_module.py:394-409` — aggregate per-month / per-Owner only; synthetic fixtures. | closed |
| T-15-05-SC | Tampering | pip/npm installs | accept | Zero new dependencies in Plan 15-05. | closed |
| T-15-06-EXPIRY | Tampering (correctness) | accepted/recast classification | mitigate | `accepted_recast_module.py:250-266` — `expired_ids` (expires_at < today) excluded from both frames; accepted/recast kept separate (Pitfall 6b). | closed |
| T-15-06-COLDSTART | Denial of Service | MoM delta on missing prior month | mitigate | `accepted_recast_module.py:325-356` — absent/insufficient/`prior_snap=None` leaves deltas `None`; `_safe_delta_arrow()` returns `None`, never NaN. | closed |
| T-15-06-PII | Information Disclosure | recast_reason logging + fixtures | mitigate | `accepted_recast_module.py` — `recast_reason` never accessed/logged (grep: 0 matches); `test_accepted_recast_module.py:5-9` synthetic UUIDs. | closed |
| T-15-06-DEGRADE | Denial of Service | recast_rules_df None / fetch failure | mitigate | `accepted_recast_module.py:267-271` — None-guard logs warning, skips cross-check; finding-level counts still computed; never crashes batch. | closed |
| T-15-06-SC | Tampering | pip/npm installs | accept | Zero new dependencies in Plan 15-06. | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-15-01 | T-15-01-SC, T-15-02-SC, T-15-03-SC, T-15-04-SC, T-15-05-SC, T-15-06-SC | No new pip/npm dependencies in any Phase-15 plan; zero supply-chain attack surface added. Modules import only pre-pinned project deps (`pandas`, `openpyxl`, `reports.modules.*`). | gsd-security-auditor | 2026-06-11 |
| AR-15-02 | T-15-02-LOG | Trend snapshot INFO log emits only aggregate scalar counts (`on_time_assets`, `reopened`, `accepted`, `recast`) — no row-level data. Consistent with existing trend-logging pattern. | gsd-security-auditor | 2026-06-11 |

*Accepted risks do not resurface in future audit runs.*

---

## Audit Notes

**T-15-01-SPOT (live-tenant spot-check):** Mitigation is a process control (checkpoint instruction), not a code gate. Verified by grep — zero `print()` calls in `reopened_vulns_module.py`; all logging is `logger.debug`/`logger.error` with `len()` counts or exception strings. The constraint is structurally enforced by the module's logging discipline.

**T-15-06-PII (`recast_reason`):** The field is fetched into `vulns_df` by `data/fetchers.py` but `accepted_recast_module.py` never reads it. Satisfying the "not logged at INFO" constraint by omission is stronger than truncating at INFO.

**T-15-03-PII (mismatch analyst schema):** The locked schema `[asset_uuid, ip_address, owner_tag, untagged_reason, finding_count]` is enforced by the substrate `external_scope()` output plus a single `finding_count` aggregate column; the zero-row fallback declares the same five columns explicitly.

**Unregistered flags:** None. All `## Threat Flags` entries in Phase-15 SUMMARY files map to registered threat IDs above.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-11 | 28 | 28 | 0 | gsd-security-auditor (sonnet) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-11
