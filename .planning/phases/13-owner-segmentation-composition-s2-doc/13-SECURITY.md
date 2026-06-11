---
phase: 13
slug: owner-segmentation-composition-s2-doc
status: secured
threats_open: 0
asvs_level: 1
created: 2026-06-11
---

# SECURITY.md — Phase 13 Audit Record

**Phase:** 13 — Owner Segmentation + Composition (S2 + Doc)
**Audit date:** 2026-06-11
**ASVS Level:** 1
**Plans audited:** 13-01, 13-02, 13-03, 13-04, 13-05
**Auditor:** gsd-security-auditor (claude-sonnet-4-6)
**block_on:** open threats
**Verdict:** SECURED — 17/17 threats closed

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Note: Plan 04 (doc-only) and Plan 05 (gap-closure) reused threat IDs `T-13-13`/`T-13-14`
> for different threats — disambiguated below with `(P4)`/`(P5)`.

---

## Threat Verification

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-13-01 | Tampering — tag parser | mitigate | CLOSED | `board_report_utils.py:265` `isinstance(tags_val, str)` guard; split on `";"` at line 271; no eval/exec in function |
| T-13-02 | DoS — missing tags column | mitigate | CLOSED | `board_report_utils.py:293-305` missing-column branch sets all rows to `unassigned_label` without raising; `test_owner_segmentation.py:111` `test_missing_tags_column_fail_soft` |
| T-13-03 | Info Disclosure — owner column values | accept | CLOSED | Internal org names only; `data/trend/` directory empty (no committed JSON); `output/` gitignored at `.gitignore:9` |
| T-13-SC | Tampering — supply chain | mitigate | CLOSED | No subprocess, pip install, or npm install calls in any Phase 13 implementation file |
| T-13-04 | DoS — 4 modules on empty/untagged data | mitigate | CLOSED | All 4 modules import `extract_owner`; `fillna` guards in `board_report_utils.py:285-304`; `safe_pct`/`safe_int` used throughout; empty-data early returns present in all four `compute()` methods |
| T-13-05 | Tampering — "Business Unit" residue | mitigate | CLOSED | Grep of `reports/modules/*.py` for `business_unit`, `Untagged`, `_extract_owner_tag` returns zero matches |
| T-13-06 | Repudiation — `_extract_owner_tag` removal | mitigate | CLOSED | `_extract_owner_tag` grep across all module files returns zero occurrences; no live callers |
| T-13-07 | Info Disclosure — trend_owner_*.json payload | mitigate | CLOSED | `trend_store.py:171-197` `_count_by_owner` produces only `{owner_name: count}`; `new_entry` at lines 307-313 contains only `month`, `tag_filter`, count keys, `asset_count`, `generated_at`; `data/trend/` is empty; `test_trend_store.py:506` `test_owner_snapshot_no_pii` checks `_PII_FIELDS` |
| T-13-08 | Info Disclosure — owner_segmentation.xlsx/csv | mitigate | CLOSED | `owner_supplemental.py:248,253` writes to `output_dir` only; `output/` gitignored at `.gitignore:9`; doc at `docs/trend_and_segmentation_calculations.md:313` confirms repo-commit prohibition |
| T-13-09 | Tampering — CSV/Excel formula injection | mitigate | CLOSED | `owner_supplemental.py:56-78` `_safe_cell_value` prefixes `= + - @` starters with `'`; applied in Excel path (line 169) AND CSV path (line 188) |
| T-13-10 | Tampering — atomic write of trend JSON | mitigate | CLOSED | `trend_store.py:142-168` `_atomic_write_json`: `tempfile.mkstemp` + `os.fdopen` context manager closes fd before `os.replace`; Windows-safe ordering confirmed in docstring |
| T-13-11 | DoS — supplemental error aborting board run | mitigate | CLOSED | `board_summary.py:322-330` `try/except Exception` wraps `write_owner_supplemental`; logs error and sets `_supp_excel/_supp_csv = None`; board PDF/Excel delivery continues |
| T-13-12 | DoS — dimension=owner with no enriched_assets | mitigate | CLOSED | `trend_store.py:299-302` raises `ValueError` immediately; `test_trend_store.py:396` `test_owner_requires_enriched_assets` uses `pytest.raises(ValueError, match="enriched_assets")` |
| T-13-13(P4) | Info Disclosure — example snippets in runbook | mitigate | CLOSED | `docs/trend_and_segmentation_calculations.md` lines 367-395 use synthetic names only ("Network Defense", "Finance Application Support", "Team Alpha", "Team Beta"); no real hostnames, IPs, or asset_uuids present |
| T-13-14(P4) | Repudiation — doc drift | accept | CLOSED | Accepted risk: doc authored after Plans 01/03; future drift is normal maintenance. No enforcement mechanism warranted. |
| T-13-13(P5) | DoS — duplicate asset_uuid in supplemental (CR-01) | mitigate | CLOSED | `owner_supplemental.py:119-123` `drop_duplicates("asset_uuid")` before `set_index`; `test_owner_supplemental.py:155` `test_duplicate_uuid_returns_paths_and_deterministic` verifies first-row-wins attribution |
| T-13-14(P5) | Tampering — non-deterministic owner attribution (WR-05) | mitigate | CLOSED | `trend_store.py:190-192` `enriched_assets.drop_duplicates("asset_uuid")` before `dict(zip(...))`; `test_trend_store.py:450` `test_owner_attribution_deterministic_under_dup_uuid` |
| T-13-15(P5) | Repudiation — supplemental open count disagreeing with trend (WR-02) | mitigate | CLOSED | `owner_supplemental.py:115` `open_findings_at(vulns_df, report_date)` called when `report_date is not None`; `board_summary.py:324` passes `report_date=generated_at`; `test_owner_supplemental.py:208` `test_open_findings_uses_open_set` |
| T-13-16(P5) | Tampering — formula injection after refactor | accept | CLOSED | `_safe_cell_value` at `owner_supplemental.py:56-78` unchanged by refactor; guard present and confirmed |
| T-13-17(P5) | Info Disclosure — open-set refactor leaking row-level data | accept | CLOSED | `_build_owner_app_df` changes remain in-memory; output goes to `output/` (gitignored); trend payload is aggregate-only (verified above) |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| T-13-03 | T-13-03 | Internal org/owner names in Owner column values — not row-level PII; internal email delivery is permitted per project rule. Not committed to repo or fed to AI; `output/` gitignored. | Phase 13 plan threat model (13-01-PLAN.md) | 2026-06-11 |
| T-13-14(P4) | T-13-14(P4) | Documentation drift from implementation — doc authored at plan time; future drift is normal maintenance. No automated enforcement is proportionate for a runbook. | Phase 13 plan threat model (13-04-PLAN.md) | 2026-06-11 |
| T-13-16(P5) | T-13-16(P5) | Formula-injection guard after refactor — accepted because mitigation (`_safe_cell_value`) is confirmed unchanged. Recorded to acknowledge the refactor did not regress the guard. | Phase 13 plan threat model (13-05-PLAN.md) | 2026-06-11 |
| T-13-17(P5) | T-13-17(P5) | Row-level data exposure from open-set refactor — computation stays in-memory; output lands in `output/` (gitignored); trend JSON is aggregate-only. No new persistence surface introduced. | Phase 13 plan threat model (13-05-PLAN.md) | 2026-06-11 |

*Accepted risks do not resurface in future audit runs.*

---

## Unregistered Flags

None. All SUMMARY.md `## Threat Flags` entries from Plans 01-05 map to registered threat IDs in the register above.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-11 | 17 | 17 | 0 | gsd-security-auditor (claude-sonnet-4-6) |

---

## Scope Notes

Files audited:
- `reports/modules/board_report_utils.py`
- `reports/modules/aged_vulns_assets_module.py`
- `reports/modules/high_risk_assets_module.py`
- `reports/modules/scan_coverage_sla_module.py`
- `reports/modules/critical_remediation_sla_module.py`
- `data/trend_store.py`
- `reports/owner_supplemental.py`
- `reports/board_summary.py`
- `docs/trend_and_segmentation_calculations.md`
- `tests/unit/test_owner_segmentation.py`
- `tests/unit/test_owner_supplemental.py`
- `tests/content/test_trend_store.py`
- `.gitignore`

Audit-time observations:
- Implementation files are READ-ONLY. No patches applied.
- `data/trend/` directory was found empty at audit time — no committed JSON files present to scan for PII.
- Grep for `business_unit`, `Untagged`, `_extract_owner_tag` across `reports/modules/*.py` returned zero matches, confirming clean residue removal (T-13-05 / T-13-06).
- Formula-injection guard (`_safe_cell_value`) confirmed present in both the Excel cell path and the CSV DictWriter path (T-13-09 / T-13-16).

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: secured` set in frontmatter

**Approval:** verified 2026-06-11
