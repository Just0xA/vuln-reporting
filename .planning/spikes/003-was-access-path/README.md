---
spike: 003
name: was-access-path
type: standard
validates: "Given the tenant's WAS license, when web-app findings are fetched, then determine whether they arrive via tio.exports.vulns() (unified, light) or require a separate WAS export (new fetcher, heavy), and which web fields are available."
verdict: PARTIAL
related: []
tags: [was, external, dmz, fetcher, research]
---

# Spike 003: WAS Access Path

## What This Validates

For the External (Public IP / DMZ) report (#3 in [`../../notes/report-requests-batch-2026-06.md`](../../notes/report-requests-batch-2026-06.md)): is Tenable Web App Scanning (WAS) data reachable by projecting more fields off the existing `tio.exports.vulns()` call (light), or does it need a separate fetcher (heavy)? This is a **doc-research spike** — no live tenant call was made here.

## How to Run

Doc findings are below (sourced from pyTenable + developer.tenable.com). To close the tenant-dependent gaps, run the live probe against your own tenant:

```bash
python .planning/spikes/003-was-access-path/probe_live.py   # requires .env Tenable creds
```

## Research Findings (verified against docs, 2026-06-05)

1. **Access path — SEPARATE EXPORT.** WAS findings are **not** in `tio.exports.vulns()`. pyTenable exposes them via **`tio.exports.was(...)`** ("Initiate a WAS vulnerability export") and `tio.was.export()` / `download_scan_report()`. Underlying REST is the **WAS v2 export** (create → poll status → download chunks), same 3-step pattern as VM exports.
   - Sources: pytenable.readthedocs.io/en/stable/api/io/exports.html, .../api/io/was.html, developer.tenable.com/docs/vm-and-was-integrations
2. **Distinguishing WAS in the vuln export — moot.** `exports.vulns()` does accept `source` and `plugin_family` filters, but docs do **not** confirm WAS surfaces there with a documented source value. Treat unified retrieval as unsupported; use `exports.was()`.
3. **WAS fields available.** Export filters: `owasp_2010/2013/2017/2021`, `owasp_api_2019`, `severity`, `state`, `vpr_score`, `vpr_v2_score`, `cvss4_base_score`, `epss_score`, `plugin_ids`, `asset_uuid`. Chunk records carry web-native fields: **`finding_id`, `url`, `http_method`, `input_type`, `input_name`, `output`**, plus `first_found/last_found/last_fixed/indexed_at`, CVSS v2/v3/v4, plugin family/id. (Exact CWE/CVE/request-response field names unconfirmed from docs.)
4. **Recommended approach.** New fetcher `fetch_was_findings()` calling `tio.exports.was(state=['open','reopened'], severity=[...])`, returning a normalized DataFrame parallel to `fetch_vulnerabilities()`. Cache as a new `was_findings.parquet` dataset. Use `first_found`/`since` for MoM trend via the snapshot substrate (S1). Gotchas: separate WAS **license + permissions** (VM-only tenant → empty/403); pagination `num_assets` default 50 / max 5000; export **status polling** (pyTenable iterator handles it); same `tenacity` rate-limit posture as VM exports.

## Live-probe correction — pyTenable 1.5.2 (the pinned version)

The doc research above described `tio.exports.was()`, which **does not exist in the pinned pyTenable 1.5.2.** The first probe run failed (`'ExportsAPI' object has no attribute 'was'`); local source inspection of the installed package revealed the real, version-specific API — and it is **heavier and more fragile** than the unified export the docs described:

- WAS is reached via **`tio.was.export(and_filter=[...], or_filter=[...], single_filter=(...))`** → returns a `WasIterator`.
- It is **scan-config driven**, not findings-driven: it searches WAS scan **configs** (`was/v2/configs/search`), collects parent scan IDs, enumerates **target scan IDs via an UNDOCUMENTED internal endpoint** (source comment: *"has not been publicly documented… in use in the [TVM] UI"*), then **downloads the full report per target scan** (`was/v2/scans/{uuid}/report`) and yields findings.
- **Filters are scan-level only** (`scans_started_at`, `scans_status`) — there is **no finding-level severity/state/VPR filter**. All of that must be done **client-side in pandas**.
- Each yielded record is nested: `{"finding": {…}, "config": {config_id,name,description}, "scan": {…}, "parent_scan": {finalized_at}}`. Actual finding-field schema comes from the scan report and needs the live probe to enumerate.

**Implication — a new decision (see batch note Open Decisions):** build the WAS fetcher on `tio.was.export()` as-is (accept scan-centric model + undocumented-endpoint fragility + per-scan report downloads), **or upgrade pyTenable** to a version exposing the cleaner unified `tio.exports.was()` (findings-level filters) — which collides with the project constraint *"no new SDK adoption / version bump without an explicit decision"* and risks regressing the existing VM fetchers.

## Results

**VERDICT: VALIDATED (with constraints) ✓ — fully answered by docs + live probe.** WAS is licensed and reachable. Access is HEAVY (separate scan-centric export). On the pinned 1.5.2 `tio.was`: no VPR (severity = `risk_factor`/CVSS) and no lifecycle fields (no trend/SLA). Supporting trend/SLA requires a pyTenable upgrade to `tio.exports.was()` — a real decision against the SDK-version constraint. The External report can ship current-posture web findings on 1.5.2 today; trend/SLA on WAS is gated on the upgrade.

- **Bottom line: HEAVY — build a new WAS fetcher.** WAS is a distinct export endpoint with its own schema; cannot be done by projecting more `exports.vulns()` fields. Effort is moderate-within-heavy because `exports.was()` mirrors the existing vulns export pattern (new fetcher + cache dataset + normalization + the external-scope join).

**Live probe results (pyTenable 1.5.2 `tio.was.export()`, 50 findings sampled, 2026-06-05):**
1. **WAS IS licensed and reachable.** (A malformed-filter run returned `400 INVALID_SEARCH_PARAM` — auth/endpoint OK; the configs/search AND group needs ≥2 conditions. Corrected → 50 findings.)
2. **🔴 No VPR, no `severity` field.** `vpr populated: 0/50`. WAS severity is **`risk_factor`** (CVSS-derived: info/low/medium/high/critical). The codebase is VPR-first — so the External/WAS report needs a **`risk_factor`/CVSS-based severity derivation**; VPR SLA bands do not apply to web findings.
3. **🔴 No lifecycle fields via 1.5.2 `tio.was`.** Finding records have **no `state`, `first_found`, `last_found`, or `last_fixed`** — they are per-scan snapshots. This path **cannot support MoM trend or SLA-aging**. The newer unified `tio.exports.was()` (pyTenable upgrade only) *does* carry those — strengthens the upgrade case.
4. **Info noise present.** Sample finding was `risk_factor:'info'` ("Performance Telemetry") — must filter `risk_factor != 'info'`, like Informational on the VM side.
5. **Field schema (confirmed):** `uri, name, family, synopsis, description, solution, see_also, risk_factor, owasp, cwe, wasc, cves, bid, xrefs, cvss, cvss_vector, cvssv3(+_vector), cvssv4(+_vector), input_name, input_type, payload, proof, request_headers, response_headers, output, attachments, plugin_id, plugin_publication_date, plugin_modification_date`.

**The pyTenable-version decision is now the crux** (not just licensing):
- **Stay on 1.5.2 `tio.was`:** current-scan snapshots only — no lifecycle → **no trend/SLA**. Viable only for a current-posture external web list. Plus undocumented endpoint + per-scan downloads + client-side filtering.
- **Upgrade pyTenable for `tio.exports.was()`:** lifecycle fields (`state/first_found/last_found/last_fixed`) + finding-level filters → supports trend/SLA. Cost: SDK bump vs the "no SDK adoption without explicit decision" constraint + VM-fetcher regression risk (needs a regression pass).

### Signal for the build
- Scope the External report as **infra-external (tagged-external OR public IPv4) + a new WAS fetcher**, with WAS gated on the licensing probe AND the pyTenable-version decision.
- **On 1.5.2:** `fetch_was_findings()` wraps `tio.was.export()`, flattens the nested `{"finding","config","scan"}` record, and filters severity/state **client-side**. Budget for per-scan report downloads and the undocumented-endpoint fragility (pin behavior with a thin adapter so a future SDK upgrade is swappable).
- Confirm VPR-on-WAS before assuming standard SLA bands apply to web-app findings.
- **Decision to make:** upgrade pyTenable for the cleaner unified export vs. build on 1.5.2's `tio.was` — weigh against the SDK-version constraint + VM-fetcher regression risk.
