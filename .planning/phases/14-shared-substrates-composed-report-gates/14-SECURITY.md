---
phase: 14
slug: shared-substrates-composed-report-gates
status: secured
threats_open: 0
threats_closed: 10
asvs_level: 1
created: 2026-06-11
---

# SECURITY.md — Phase 14: Shared Substrates & Composed Report Gates

**Phase:** 14 — shared-substrates-composed-report-gates
**Plans audited:** 14-01, 14-02, 14-03
**ASVS Level:** 1
**Audit date:** 2026-06-11
**Auditor:** gsd-security-auditor (claude-sonnet-4-6)
**Threats closed:** 10 / 10
**Threats open:** 0

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Tenable export → `external_scope()` | Untrusted `ipv4`/`tags` strings cross into stdlib `ipaddress` parser | Untrusted tenant strings |
| `mismatches_df` → output artifacts | Asset-level rows reach only operator-local analyst tabs + internal email, never repo/AI (D-11) | Asset-level PII |
| Tenable assets export → `count_on_time_assets()` | Untrusted `last_licensed_scan_date` crosses into pandas timestamp comparison | Untrusted tenant timestamps |
| YAML `modules` list → frozenset `.intersection()` | Operator-supplied module IDs gate which fetches fire; a typo misses the gate (no fetch), never executes code | Operator config |
| `read_trend()` / `fetch_recast_rules()` → `composer_kwargs` | Pre-read trend dict + recast DataFrame cross into `**self._kwargs` fan-out | Trend dict + recast free-text |

---

## Threat Verification

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-14-01 | Denial of Service | mitigate | CLOSED | `utils/external_scope.py:83-87` — `try/except (ValueError, TypeError)` wraps `ipaddress.ip_address(ip_str)`; returns `False` on malformed/empty/None. Proven by 20 parametrized negatives in `tests/test_external_scope.py:64-93`. |
| T-14-02 | Information Disclosure | mitigate | CLOSED | `utils/external_scope.py:29-35` — module docstring documents D-11 boundary (operator-local, never committed, never sent to AI). Fixtures use `00000000-0000-0000-0000-00000000000N` UUIDs and `*.example.invalid` hostnames; positive external case uses monkeypatched `is_global` (D-18), no real public IP literals committed. |
| T-14-03 | Tampering | accept | CLOSED | Zero new dependencies. `utils/external_scope.py` imports only stdlib (`ipaddress`, `logging`) and pre-existing pinned `pandas==2.2.3`. No new entry in `requirements.txt`. |
| T-14-04 | Denial of Service | mitigate | CLOSED | `utils/asset_count.py:97-99` (empty df), `:102-108` (missing column), `:113-119` (all-NaT), `:143-151` (zero on-time) — all return `None` without raising. Covered by `tests/test_asset_count.py:105,118,125,131,139`. |
| T-14-05 | Tampering | accept | CLOSED | Zero new dependencies. `utils/asset_count.py` imports only stdlib (`argparse`, `logging`, `datetime`) and pre-existing pinned `pandas==2.2.3`. No new entry in `requirements.txt`. |
| T-14-06 | Information Disclosure | mitigate | CLOSED | `count_on_time_assets` returns `int | None` scalar only — no asset-level rows. `tests/test_asset_count.py` fixtures contain no hostnames, IPs, or asset UUIDs; file docstring states "SYNTHETIC-ONLY (QUAL-05)". |
| T-14-07 | Tampering | mitigate | CLOSED | `reports/composed_report.py:97-112` — `run_report()` signature has no `trend_snapshots`/`recast_rules_df` parameters. Asserted at `tests/test_composed_report_kwargs_gates.py:106-118` via `inspect.signature`. |
| T-14-08 | Information Disclosure | mitigate | CLOSED | `reports/composed_report.py:239` — only literal `"fetching recast rules …"` logged (no field values). `reports/modules/sc4_kwargs_stub_module.py:81` — records only `len(recast_rules_df)` scalar; no `recast_reason`/hostnames/IPs accessed or emitted. |
| T-14-09 | Tampering | accept | CLOSED | Zero new dependencies. `reports/composed_report.py:214,238` lazily imports pre-existing `data.trend_store.read_trend` and `data.fetchers.fetch_recast_rules`. No new entry in `requirements.txt`. |
| T-14-10 | Denial of Service | mitigate | CLOSED | `reports/composed_report.py:208-229` (trend gate) and `:231-245` (recast gate) each wrapped in `try/except Exception`, degrading to `None` on failure; `:346-349` None-guards prevent absent kwargs entering `composer_kwargs`; `reports/modules/sc4_kwargs_stub_module.py:61-72` returns `_empty_result` on absent kwargs. End-to-end WR-02 regression test at `tests/test_composed_report_kwargs_gates.py:252-293` raises from both gates and asserts a bundle is still returned. |

---

## Accepted Risks Log

| Threat ID | Risk | Accepted Because |
|-----------|------|-----------------|
| T-14-03 | Supply chain tampering via pip | Zero new packages. `ipaddress` is stdlib; `pandas==2.2.3` pre-existing pinned. No attack surface added vs pre-Phase-14 baseline. |
| T-14-05 | Supply chain tampering via pip | Zero new packages. `datetime` is stdlib; `pandas` pre-existing pinned. No attack surface added. |
| T-14-09 | Supply chain tampering via pip | Zero new packages. `data.trend_store`/`data.fetchers` are pre-existing project modules with no new third-party dependency. |

---

## Unregistered Threat Flags

None. All three SUMMARY.md `## Threat Flags` sections reported no new threat surface beyond the plan register.

---

## Scope

Files audited (read-only):

- `utils/external_scope.py`
- `utils/asset_count.py`
- `config.py`
- `reports/composed_report.py`
- `reports/modules/sc4_kwargs_stub_module.py`
- `tests/test_external_scope.py`
- `tests/test_asset_count.py`
- `tests/test_composed_report_kwargs_gates.py`
- `requirements.txt`

---

## Audit Trail

### Security Audit 2026-06-11

| Metric | Count |
|--------|-------|
| Threats found | 10 |
| Closed | 10 |
| Open | 0 |

Register authored at plan time (all 3 plans carried `<threat_model>` blocks); auditor verified mitigations exist rather than scanning for new threats. Note: post-code-review hardening commits `69b4684`/`bf3dc7e`/`8b0d466` strengthened the fail-soft paths underlying T-14-01/T-14-04/T-14-10 (tz-naive scan-date coercion, gate-fetch `try/except`, missing `asset_uuid` guard), each with a regression test.
