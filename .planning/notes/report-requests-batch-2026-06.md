---
title: Report Requests Batch — June 2026 (landscape + substrate analysis)
date: 2026-06-05
context: Captured during /gsd-explore. The requestor surfaced a batch of new report ideas while scoping the milestone after VTD-01. Laid side-by-side, they share three substrates that should be built once rather than per-report. This note is the "backlog for decision" — it records the landscape and a recommended substrate-first sequencing, NOT a committed milestone.
---

# Report Requests Batch — June 2026

Eight reports are now on the table (VTD-01 + seven new requests). Laid side-by-side they share **three substrates**; building those once turns most of the reports into thin modules. This note exists so the milestone decision is made against the whole batch, not one report at a time.

## The eight reports

| # | Report | Trend MoM | Owner/BU cut | New data source | In mgmt_summary today |
|---|--------|:--:|:--:|:--:|:--:|
| VTD-01 | Vuln Type Distribution (App/OS/HW) | ✓ | tiles = team | — | — |
| 1 | Accepted & Recast findings | ✓ (cur vs prev mo, ▲▼ %) | ✓ | recast rules *(have)* | ✓ partial |
| 2 | Program Health Overview (velocity) | ✓ | ✓ | — | ✓ overlaps |
| 3 | External (Public IP / DMZ) Reporting | ✓ | maybe | **WAS fields (NEW)** | — |
| 4 | Mean Time to Resolution (review pass) | ✓ | ? | — | ✓ exists there |
| 5 | Vulnerability Density (vs total assets) | ✓ | ? | asset totals | — |
| 6 | New vs Remediated (per month) | ✓ | ? | first_found/last_fixed *(have)* | — |
| 7 | Reopened Vulnerabilities (build/config) | ✓ | ? | state / resurfaced_date *(have)* | — |

### Per-report intent (requestor's words, lightly normalized)

1. **Accepted & Recast** — current posture + previous-month infographic (up/down with % change). Exists partially in `management_summary`; wants it modular, plus Accepted/Recast **by Owner/Business Unit** as supporting data. Data: `severity_modification_type`, `recast_rule_uuid` on vulns + `fetch_recast_rules()` (both already in the codebase).
2. **Program Health Overview** — trending month-over-month on totals, showing **velocity across the board**. Owner/BU supporting data.
3. **External (Public IP & DMZ)** — heaviest/most new-data report. **External scope = tagged-external OR computed public IPv4** (non-RFC1918) — dual signal; flag mismatches (public-IP-but-untagged / tagged-but-private) to an analyst like the Owner `Unassigned` catch-all. **Must include Web App Scan (WAS) data — access path RESOLVED (Spike 003): HEAVY.** WAS is a **separate export** (`tio.exports.was()`), NOT unified in `tio.exports.vulns()` — so it needs a new `fetch_was_findings()` + new `was_findings.parquet` cache + normalization (mirror `fetch_fixed_vulnerabilities`'s 3-step export pattern). WAS fields: `url`, `http_method`, `input_type`, `input_name`, `output`, `owasp_*`, CVSS v2/v3/v4, `vpr_score`. **Still needs a live tenant probe** (`spikes/003-was-access-path/probe_live.py`): confirm WAS licensing, and whether `vpr_score` is populated (codebase severity is VPR-first — if absent, WAS falls back to native severity). MoM trend (S1).
4. **Mean Time to Resolution** — **rework, not review-and-keep** (requestor flagged all four gaps). The existing `reports/modules/mttr_by_severity_module.py` is solid but: (a) it's secretly a **rolling ~30-day MTTR** (averages over FIXED findings; fixed are retained only ~29d — Spike 002), never disclosed; (b) `overall_mttr` is an **unweighted mean-of-means** across tiers; (c) reopened findings overstate `days_to_fix` (`last_fixed − first_found` spans the whole reopen cycle); (d) no trend; (e) no Owner/BU; (f) legacy `render_email_kpis` channel, not the four-channel contract. Needs: trend (**S1**), Owner/BU (**S2**), honesty fixes (disclose window, sample-weight, reopened-aware), and a **resolved-population decision** (see Open Decisions).
5. **Vulnerability Density** — change MoM **vs total asset count** (vulns per asset over time). Needs an asset-count denominator.
6. **New vs Remediated** — count incoming vs remediated per month, vs prior months. **This *is* the trend-reconstruction engine surfaced directly** (`first_found` in month = new; `last_fixed` in month = remediated).
7. **Reopened Vulnerabilities** — track build/config regressions where findings reopen. Data: `state == REOPENED`, `resurfaced_date`.

## The three shared substrates

### S1 — Trend substrate (KEYSTONE) — reframed by Spike 002
Nearly every report needs month-over-month. The original idea was to **reconstruct** history from `first_found/last_fixed/state` and retire snapshots. **Spike 002 INVALIDATED that** — Tenable retains fixed findings only ~29 days, so multi-month history can't be backfilled. The real substrate is a **snapshot-capture engine**: persist monthly open-counts (by dimension) + the in-retention fixed export from now forward; reconstruction serves current-state + the last ~29 days only. Still powers VTD-01, #2, #5, #6, #7, #1 — but via accumulated snapshots, with a real cold start. It also **must** use the reopened-aware two-interval predicate (the naive one drops ~19% of findings). Full design + caveats: [[trend-reconstruction-engine]]; spike: [`spikes/002-trend-reconstruction-lookback/`](spikes/002-trend-reconstruction-lookback/).

### S2 — Owner / Business Unit segmentation
Cross-cutting "supporting data" cut (#1, #2 explicit; natural for most). **Status (requestor, 2026-06-05):** partially rolled out via the **`Owner` tag category**; some systems untagged. Required behavior: group by `Owner`, bucket untagged as **`Unassigned`** (catch-all that self-retires as tagging completes), and **emit an analyst alert / exception list of untagged assets** to be defined. Same shape as the existing `unscanned_assets` companion and VTD-01's "Unclassified" bucket. Note: `business_unit` is the *goal* dimension; see [[project_business_unit_interim_application]] for the interim-`Application` history.

### S3 — WAS / External data source (ISOLATED, HEAVY)
Only #3 needs genuinely new data. Spike 003 resolved the access path: WAS is a **separate export** (`tio.exports.was()`), so this is a **new fetcher** (`fetch_was_findings` + `was_findings.parquet`), not a field-projection. External scoping = tagged-external OR computed public IPv4. Least entangled with the other reports, but the most build effort; gated on a live WAS-licensing probe. Sequence independently / last.

## Entanglement: GEN-01 in disguise
Reports #1, #2, #4 extract/extend metrics that live in `management_summary`'s bespoke render path today. Cleanly modularizing them **is** GEN-01 (migrate `management_summary` to the module contract). Treat GEN-01 as in-scope whenever those three are built.

## Recommended sequencing (NOT yet committed)
- **v1.3 — Substrate:** trend-reconstruction engine (S1) + Owner segmentation (S2), likely paired with **GEN-01** `management_summary` modularization. This is the project's "YAML-and-module, not code-fork" core value made real.
- **v1.4+ — Module batch on the substrate:** VTD-01, New-vs-Remediated, Vuln Density, Reopened, Program Health, Accepted/Recast — each a thin module once S1/S2 exist.
- **Independent track:** External/DMZ (#3) — gated on WAS fetcher work, can run parallel.

Rationale: building any single report first (even the spiked-and-ready VTD-01) means inventing S1 inside it, then refactoring it out from under five siblings. Substrate-first avoids that.

## Open decisions for milestone scoping
- Confirm substrate-first vs ship-VTD-01-first.
- Decide whether GEN-01 (`management_summary` migration) is folded into the substrate milestone.
- **WAS access path (#3) — Spike 003 RESOLVED (licensed & probed):** separate export → HEAVY new fetcher. WAS **is licensed & reachable**. Pinned **pyTenable 1.5.2 `tio.was`** yields per-scan snapshots with **no VPR** (severity = `risk_factor`/CVSS — needs its own derivation; VPR SLA bands don't apply) and **no lifecycle fields** (`state/first_found/last_fixed` absent → **no trend/SLA on WAS**). **Decision — pyTenable upgrade:** upgrade to `tio.exports.was()` (gets lifecycle fields → enables WAS trend/SLA, but violates the SDK-version constraint + needs a VM-fetcher regression pass) **vs stay on 1.5.2** (ship current-posture external web list only, no WAS trend). Field schema captured in the spike README.
- **WAS severity model (#3) — settled:** WAS has no VPR; derive severity from `risk_factor`/CVSS and filter `risk_factor != 'info'`. The External report's WAS portion needs a severity path separate from `config.vpr_to_severity`.
- **MTTR resolved-population (#4)**: what counts as "resolved" for the denominator — exclude reopened? exclude risk-accepted/recast? count only first-time fixes? Decide at plan-time; shapes every MTTR number.
- **MTTR is a rework** (settled): all four gaps in scope — trend, honesty, Owner/BU, population.
