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

**VERDICT: PARTIAL ⚠ — access path RESOLVED but HEAVIER than docs implied (scan-centric `tio.was` in 1.5.2); tenant facts still need the corrected live probe.**

- **Bottom line: HEAVY — build a new WAS fetcher.** WAS is a distinct export endpoint with its own schema; cannot be done by projecting more `exports.vulns()` fields. Effort is moderate-within-heavy because `exports.was()` mirrors the existing vulns export pattern (new fetcher + cache dataset + normalization + the external-scope join).

**Still requires a live tenant probe (run `probe_live.py`):**
1. Is the tenant **WAS-licensed** at all? (VM-only → no data; report degrades to infra-only external.)
2. Is **`vpr_score` populated** on WAS findings? **Critical for this codebase** — severity/SLA logic is VPR-first (`config.vpr_to_severity`). If WAS lacks VPR, it falls back to native severity everywhere; confirm the fallback is acceptable for the External report.
3. Full chunk field schema (CWE, CVE, request/response payload field names) for the report's columns.

### Signal for the build
- Scope the External report as **infra-external (tagged-external OR public IPv4) + a new WAS fetcher**, with WAS gated on the licensing probe AND the pyTenable-version decision.
- **On 1.5.2:** `fetch_was_findings()` wraps `tio.was.export()`, flattens the nested `{"finding","config","scan"}` record, and filters severity/state **client-side**. Budget for per-scan report downloads and the undocumented-endpoint fragility (pin behavior with a thin adapter so a future SDK upgrade is swappable).
- Confirm VPR-on-WAS before assuming standard SLA bands apply to web-app findings.
- **Decision to make:** upgrade pyTenable for the cleaner unified export vs. build on 1.5.2's `tio.was` — weigh against the SDK-version constraint + VM-fetcher regression risk.
