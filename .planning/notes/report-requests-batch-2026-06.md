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
3. **External (Public IP & DMZ)** — must include **Web App Scan (WAS)** data; specific WAS fields may not be in the current `fetch_vulns` projection. MoM trend. Needs public-IP/DMZ asset scoping (tags/attributes).
4. **Mean Time to Resolution** — already in `management_summary`; needs a **review pass + requirements discussion** to confirm it meets the ask. Not greenfield.
5. **Vulnerability Density** — change MoM **vs total asset count** (vulns per asset over time). Needs an asset-count denominator.
6. **New vs Remediated** — count incoming vs remediated per month, vs prior months. **This *is* the trend-reconstruction engine surfaced directly** (`first_found` in month = new; `last_fixed` in month = remediated).
7. **Reopened Vulnerabilities** — track build/config regressions where findings reopen. Data: `state == REOPENED`, `resurfaced_date`.

## The three shared substrates

### S1 — Trend-reconstruction engine (KEYSTONE)
Nearly every report needs month-over-month. Instead of accumulating snapshots, **reconstruct the historical open-population from the current finding set** using `first_found / last_fixed / state / severity`. Powers VTD-01 trend, #2, #5, #6, #7 directly and #1's prev-month delta. Retires snapshot-based `data/trend/`. Full design + caveats: [[trend-reconstruction-engine]] (`notes/trend-reconstruction-engine.md`).

### S2 — Owner / Business Unit segmentation
Cross-cutting "supporting data" cut (#1, #2 explicit; natural for most). **Status (requestor, 2026-06-05):** partially rolled out via the **`Owner` tag category**; some systems untagged. Required behavior: group by `Owner`, bucket untagged as **`Unassigned`** (catch-all that self-retires as tagging completes), and **emit an analyst alert / exception list of untagged assets** to be defined. Same shape as the existing `unscanned_assets` companion and VTD-01's "Unclassified" bucket. Note: `business_unit` is the *goal* dimension; see [[project_business_unit_interim_application]] for the interim-`Application` history.

### S3 — WAS / External data source (ISOLATED)
Only #3 needs genuinely new data: Web App Scan fields + public-IP/DMZ scoping. Least entangled, most self-contained — a candidate to sequence independently.

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
- Confirm WAS field gap for #3 (research item — what `tio.exports.vulns()` WAS fields are missing from the current projection).
- MTTR (#4): review-and-keep vs rebuild — needs its own requirements discussion.
