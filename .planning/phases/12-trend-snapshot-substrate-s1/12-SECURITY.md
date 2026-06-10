---
phase: 12
slug: trend-snapshot-substrate-s1
status: secured
threats_open: 0
asvs_level: 1
created: 2026-06-10
---

# SECURITY.md — Phase 12 Audit Record

**Phase:** 12 — Trend Snapshot Substrate S1
**Audit date:** 2026-06-10
**ASVS Level:** 1
**Auditor:** gsd-security-auditor (claude-sonnet-4-6)
**block_on:** open threats
**Verdict:** SECURED — 10/10 threats closed

---

## Threat Verification

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-12-01 | Tampering | mitigate | CLOSED | `utils/open_count.py:93` — `st = df["state"].astype(str).str.upper()`; two-interval predicate at lines 108-112; `tests/unit/test_open_count.py` contains `test_reopened_state_included`, `test_reopened_in_gap_excluded`, `test_reopened_null_resurfaced_excluded`, `test_mixed_population` all passing under `pytestmark = pytest.mark.unit` |
| T-12-02 | Information Disclosure | accept | CLOSED | Accepted risk — see Accepted Risks log below |
| T-12-03 | Information Disclosure | mitigate | CLOSED | `data/trend_store.py:257-266` — `new_entry` assembled from exactly 8 keys: `month`, `tag_filter`, `critical`, `high`, `medium`, `low`, `asset_count`, `generated_at`; no `df` or `assets_df` row fields serialised; `tests/content/test_trend_store.py:33,213-226` — `_PII_FIELDS = {"hostname","ipv4","fqdn","asset_uuid","plugin_name","plugin_id"}` asserted absent from written file text |
| T-12-04 | Tampering / DoS | mitigate | CLOSED | `data/trend_store.py:155-168` — `tempfile.mkstemp` → `with os.fdopen(fd,"w",encoding="utf-8") as fh: json.dump(...)` (line 158) → `os.replace(tmp_path, path)` (line 161, outside/after the `with` block — fd closed before rename, Windows-safe); `except Exception` unlinks temp and re-raises (lines 162-168); `_load_trend_json` swallows all parse errors at line 127 and returns `[]` |
| T-12-05 | Tampering | mitigate | CLOSED | `data/trend_store.py:96` — `re.sub(r"[^A-Za-z0-9_]", "_", combined).strip("_")`; Phase 12 only passes the literal `"all_assets"` which bypasses the function entirely; sanitiser present for Phase 13 parameterised case |
| T-12-06 | Tampering | mitigate | CLOSED | `data/trend_store.py:270` — file path uses `f"trend_{dimension}_{tag_suffix}.json"` (`trend_` prefix); no MS private helper calls in `trend_store.py`; `tests/content/test_trend_store.py:234-265` — `test_ms_file_untouched` writes `management_summary_all_assets.json`, records `st_mtime`, runs `capture_snapshot`, asserts mtime unchanged |
| T-12-07 | Tampering / Input Validation | mitigate | CLOSED | `scripts/capture_trend_snapshot.py:123-130` — `_month_type` calls `datetime.strptime(value, "%Y-%m")` and raises `argparse.ArgumentTypeError` on failure; `scripts/capture_trend_snapshot.py:113-120` — `_date_type` validates `%Y-%m-%d`; both bound to `--month` (line 140) and `--date` (line 146) respectively; malformed input exits 2 via the `_SnapshotArgumentParser.error()` override |
| T-12-08 | Information Disclosure | mitigate | CLOSED | `scripts/capture_trend_snapshot.py:165` logs argv/start timestamp; lines 228,230 log cache path; line 257 logs `snapshot_date` and `month_str`; line 261 logs path; no row-level finding or asset field (hostname, ipv4, fqdn, asset_uuid, plugin_name, plugin_id) appears in any log call — grep of `logger.*first_found`, `logger.*asset_uuid`, `logger.*plugin`, `logger.*hostname`, `logger.*fqdn` returns no matches |
| T-12-09 | Denial of Service | mitigate | CLOSED | `scripts/capture_trend_snapshot.py:218-225` — `get_client()` `SystemExit` and `Exception` both caught, log written, `return 2`; lines 232-235 — fetcher exception caught, `return 3`; lines 262-265 — `capture_snapshot` exception caught, `return 3`; no uncaught exception path exists in `main()`; argparse `SystemExit` caught at line 192, mapped to `e.code if isinstance(e.code, int) else 2` |
| T-12-SC | Tampering | accept | CLOSED | Accepted risk — see Accepted Risks log below |

---

## Accepted Risks Log

### T-12-02 — Information Disclosure (predicate output)
- **Accepted by:** Phase 12 plan threat model (12-01-PLAN.md)
- **Rationale:** `open_findings_at` is pure in-memory computation. It receives a DataFrame and returns a filtered DataFrame — no persistence, no logging of row-level fields, no network egress. No PII leaves the function boundary.
- **Residual risk:** None at Phase 12 scope. The caller (Plan 02 `capture_snapshot`) is separately hardened under T-12-03.

### T-12-SC — Supply Chain (npm/pip installs)
- **Accepted by:** Phase 12 plan threat models (12-01, 12-02, 12-03 PLAN.md)
- **Rationale:** Phase 12 introduces zero new packages. All three plans use only stdlib (`json`, `os`, `tempfile`, `re`, `argparse`, `logging`, `datetime`, `pathlib`) plus `pandas` (already pinned in `requirements.txt`) and existing project dependencies (`config`, `data.fetchers`, `tenable_client`). The RESEARCH Package Legitimacy Audit for all three plans is "not applicable."
- **Residual risk:** None introduced by this phase. Existing supply chain risk is inherited, not amplified.

---

## Unregistered Flags

All three SUMMARY.md `## Threat Flags` sections report: **None**.

No unregistered attack surface was introduced during Phase 12 implementation.

---

## Scope

Files audited:
- `utils/open_count.py`
- `data/trend_store.py`
- `scripts/capture_trend_snapshot.py`
- `tests/unit/test_open_count.py`
- `tests/content/test_trend_store.py`
- `.planning/phases/12-trend-snapshot-substrate-s1/12-01-PLAN.md`
- `.planning/phases/12-trend-snapshot-substrate-s1/12-02-PLAN.md`
- `.planning/phases/12-trend-snapshot-substrate-s1/12-03-PLAN.md`
- `.planning/phases/12-trend-snapshot-substrate-s1/12-01-SUMMARY.md`
- `.planning/phases/12-trend-snapshot-substrate-s1/12-02-SUMMARY.md`
- `.planning/phases/12-trend-snapshot-substrate-s1/12-03-SUMMARY.md`
