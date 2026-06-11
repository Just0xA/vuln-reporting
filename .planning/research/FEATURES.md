# Feature Research — v1.4 Management Summary Reporting Improvement

**Domain:** Management/exec-facing vulnerability trend-cut report modules (four-channel module contract)
**Researched:** 2026-06-11
**Confidence:** HIGH — all findings grounded in project source files, existing module code, shipped substrates (S1/S2), and founding analysis notes. No external library research required; all frameworks already in use.

---

## Scope Boundary

This document covers ONLY the eight new items in the v1.4 batch:

1. New vs Remediated
2. Vulnerability Density
3. Reopened Vulnerabilities
4. Accepted & Recast
5. Program Health Overview
6. MTTR Rework
7. External / DMZ Exposure Cut
8. GEN-01 — management_summary migration

Already-built items (S1 trend substrate, S2 owner segmentation, VTD-01 type distribution, tag_severity_share, board_summary chrome, composed_report, unscanned_assets) are referenced as dependencies only.

---

## Per-Module Feature Analysis

### Module 1 — New vs Remediated (new_vs_remediated)

**Classification:** TABLE STAKES
**Complexity:** MEDIUM
**Audience:** Senior Management (Directors / VPs)

#### Core metric / definition

Monthly incoming finding count (`first_found` in calendar month M) vs outflow count (`last_fixed` in calendar month M), plotted MoM for the last N captured months. This is the direct surface expression of the S1 trend substrate — it is what the snapshot engine was built to expose.

"New" = count of findings where `first_found` falls within the month boundary.
"Remediated" = count of findings where `last_fixed` falls within the month boundary (fixed export, state == fixed).
Net = Remediated − New (positive = backlog shrinking).

#### Data fields

- `first_found` (open + fixed exports) — new inflow
- `last_fixed` (fixed export / `vulns_fixed.parquet`) — outflow
- `state` (open/reopened/fixed) — population filter
- S1 trend snapshots (`data/trend_store.py`) — month-boundary open counts as denominator context
- S2 `extract_owner()` — Owner-dimension cut for drill-down

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | Net trend over last 2 months: "▼ 47 net new (improving)" or "▲ 23 net new (worsening)"; RAG = Green if net negative (backlog shrinking), Amber if flat ±5%, Red if growing |
| Email panel | 2–3 sentence narrative: inflow count, outflow count, net, direction vs prior month. Owner table (top 3 by inflow) as supporting data. |
| PDF section | Bar chart: grouped bars (New / Remediated) per month for last N months. Delta line overlay. Summary table: month, new, remediated, net, running total. |
| Analyst drill-down | Per-Owner per-month inflow/outflow table. Per-severity breakdown. Findings with `first_found` in current month (new arrivals list — aggregate counts only, no hostnames/IPs per D-04-08). |

#### Edge cases

- **Cold start / insufficient history:** When fewer than 2 months of S1 snapshots exist, show current-month inflow/outflow only with a "Trend data being established" notice. Do not crash; do not show an empty chart. Return cold_start=True in metrics.
- **Zero-data group:** Tag filter matches zero assets → all counts zero → return `_empty_result()` with gray RAG strip cell. Do not divide.
- **Reopened findings double-counted in inflow:** A finding that was fixed and then reopened will have a new `resurfaced_date`. Its `first_found` is historic (not in this month), so it does NOT inflate "New" inflow — it is correctly handled by the reopened-aware `open_findings_at` predicate in S1. However, its `last_fixed` may fall in a prior month and `resurfaced_date` in this month — this counts as inflow-via-reopened only if we track `resurfaced_date`. Decision point: whether "new" means `first_found` only (simpler, understates reopen churn) or `first_found OR resurfaced_date` (accurate but more complex). Flag for plan-time resolution.
- **Fixed export availability:** `vulns_fixed.parquet` must be in the run-scoped cache. New vs Remediated has a hard dependency on the fixed export being fetched. If absent, outflow = 0 and this must be disclosed, not silently shown as zero remediation.
- **Partial month at run time:** If the report runs mid-month, current month's counts are partial. Label current month as "Month-to-date (partial)" in all renderers.

#### Dependencies

- S1 `data/trend_store.py` (read_trend) — for open-count context
- S1 `utils/open_count.py` (open_findings_at) — reopened-aware predicate
- S2 `extract_owner()` — Owner drill-down
- `data/fetchers.py` fixed export (`vulns_fixed.parquet`) — outflow denominator

---

### Module 2 — Vulnerability Density (vuln_density)

**Classification:** DIFFERENTIATOR
**Complexity:** MEDIUM-HIGH
**Audience:** Senior Management (Directors / VPs)

#### Core metric / definition

Open vulnerability count per licensed asset, tracked MoM. Normalizes raw finding counts against fleet size so that a growing estate does not look like a worsening security posture when it is merely growing. Formula: `density(M) = open_findings_at(M) / asset_count(M)`. This introduces the first **asset-count denominator substrate** — total licensed-asset count must be captured monthly alongside the vulnerability count.

#### Data fields

- S1 snapshots with `asset_count` field (already captured per D-04 in `trend_store.py`) — monthly denominator
- `open_findings_at()` — monthly numerator (already in S1)
- `assets_df` (`assets_all.parquet`) — current-month denominator
- S2 `extract_owner()` — per-Owner density

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | Current density value: "3.2 vulns/asset"; RAG thresholds are org-specific (no universal standard) — flag as requiring threshold configuration; default: Green ≤ 2.0, Amber ≤ 4.0, Red > 4.0 (configurable via module options) |
| Email panel | Narrative: current density, MoM delta, whether fleet grew or shrank (context for denominator shift). |
| PDF section | Line chart: density MoM for last N months. Secondary axis: asset count (so readers can see denominator shifts). Summary table: month, open vulns, asset count, density. |
| Analyst drill-down | Per-Owner density table. Assets with highest per-asset finding count (top-N, aggregate — no hostnames per D-04-08). |

#### Edge cases

- **Zero assets (division by zero):** If `asset_count` is zero, density is undefined. Return `_empty_result()` with gray RAG. Never divide. Use `safe_format()` throughout.
- **Asset-count denominator definition:** Three possible definitions — (a) all licensed assets, (b) on-time-scanned licensed assets only (board_summary baseline), (c) all assets including unlicensed. Decision: use (b) on-time-scanned licensed assets for consistency with board metrics. This is an open decision requiring plan-time confirmation.
- **Denominator fluctuation:** A large scan-window miss (monthly scan not run) will cause the on-time denominator to collapse and density to spike artificially. The analyst drill-down should flag when denominator MoM change exceeds 10%.
- **Cold start:** Same as New vs Remediated — less than 2 snapshot months → show current-month density only with cold-start notice. S1 snapshots already capture `asset_count` per D-04 in `trend_store.py`, so no new snapshot infrastructure is needed once the denominator decision is resolved.
- **New substrate needed:** A new helper function `asset_count_at(assets_df, date, tag_filter)` is needed to extract the denominator from S1 snapshots. This is a minor addition to the S1 substrate surface, not a full new substrate.

#### Dependencies

- S1 `data/trend_store.py` (captures `asset_count` per snapshot — already implemented per D-04)
- S1 `utils/open_count.py` (open_findings_at)
- `assets_all.parquet` — current-month denominator
- S2 `extract_owner()` — per-Owner density
- **Open decision:** denominator definition (all licensed vs on-time-scanned)

---

### Module 3 — Reopened Vulnerabilities (reopened_vulns)

**Classification:** TABLE STAKES
**Complexity:** MEDIUM
**Audience:** Senior Management + Analysts

#### Core metric / definition

Count and rate of findings that re-emerged after being marked fixed — proxy for build/config regressions, patching failures, or incomplete remediations. Primary signal: `state == REOPENED` and/or `resurfaced_date IS NOT NULL`. Rate = `reopened_count / (reopened_count + fixed_and_stayed_fixed_count)` for the current period. MoM trend of reopen count.

#### Data fields

- `state` (REOPENED) — primary classification
- `resurfaced_date` — when the finding re-emerged (date it was re-detected)
- `first_found` — original discovery date (to compute reopen lag: `resurfaced_date - last_fixed`)
- `last_fixed` — when it was previously fixed
- `plugin_id`, `plugin_name` — which findings are chronic re-openers
- S2 `extract_owner()` — which Owners have the most reopen activity

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | Reopen count + reopen rate: "42 reopened (8.3% of fixed)"; RAG = Green < 5%, Amber 5–10%, Red > 10% (configurable) |
| Email panel | Narrative: reopen count this month, rate, MoM delta, top-3 contributing Owners. Flag if rate is rising. |
| PDF section | Bar chart: reopened count MoM. Summary table: top plugins/CVEs with most reopens (by plugin ID, not by hostname). Owner breakdown table. |
| Analyst drill-down | Per-finding reopen detail: plugin_id, original first_found, last_fixed, resurfaced_date, Owner, reopen_lag_days. Sorted by reopen_lag_days ascending (quick re-emergences = patching failure; slow = config drift). |

#### Edge cases

- **Reopen double-counting in MTTR:** A reopened finding's `days_to_fix = last_fixed - first_found` spans the entire original + reopen cycle and is artificially large. This module should NOT compute MTTR — that belongs to MTTR Rework. This module counts and trends reopen events only.
- **Zero reopened findings:** `state == REOPENED` returns empty → all counts zero → valid data state, not an error. Return green RAG with "0 reopened findings in scope."
- **`resurfaced_date` population:** Not all reopened findings may have `resurfaced_date` populated (depends on Tenable version and plugin). Use `state == REOPENED` as primary filter; `resurfaced_date` as enrichment when available. If `resurfaced_date` is null for a REOPENED finding, compute reopen lag as `None` and note in analyst drill-down.
- **Rate denominator:** "Reopened as % of fixed" requires the fixed export. If fixed export is absent, show reopen count only (not rate), with a note. Do not crash.
- **Reopened findings in open-count predicate:** The `open_findings_at` predicate in S1 already handles REOPENED correctly via the two-interval model. This module reads `state == REOPENED` from the current snapshot directly (not via `open_findings_at`) for the current-month count.

#### Dependencies

- `vulns_all.parquet` (state, resurfaced_date, first_found, plugin_id)
- `vulns_fixed.parquet` — for rate denominator (optional; degrade gracefully if absent)
- S2 `extract_owner()` — Owner cut
- S1 `data/trend_store.py` — for MoM reopen count trend (reopen counts must be added as a snapshot dimension — new field, not currently in S1 snapshots)
- **New snapshot dimension needed:** S1 currently captures open counts by severity. Reopened counts require either (a) a new `capture_snapshot` dimension parameter or (b) a module-local snapshot alongside `data/trend/`. Decision: prefer (a) extending S1 to avoid proliferating snapshot files.

---

### Module 4 — Accepted & Recast (accepted_recast)

**Classification:** TABLE STAKES
**Complexity:** MEDIUM
**Audience:** Senior Management (Directors / VPs)

#### Core metric / definition

Current count of open findings under active risk management decisions (accepted risk or severity recast), expressed as a rate of total open findings, with a month-over-month delta. Broken down by Owner to show which teams are carrying the most managed exceptions. Sources: `severity_modification_type` field on findings (ACCEPTED / RECASTED) and `fetch_recast_rules()` for rule-level metadata (expiration dates, original severity, created_at).

Note: the existing `management_summary` Metric 6 (Managed Exception Rate) covers this partially but shows only a rate and no Owner breakdown or trend. This module supersedes and expands it.

#### Data fields

- `severity_modification_type` (ACCEPTED / RECASTED) — primary classification
- `recast_rule_uuid` — links to the rule-level metadata
- `fetch_recast_rules()` response: rule expiration date, original severity, created_at, filter tree (summarized via `_summarize_filter()`)
- `first_found` — how long the exception has been in place (exception age)
- S2 `extract_owner()` — Owner breakdown
- S1 `data/trend_store.py` — prior-month exception count snapshot for delta

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | Exception rate + MoM delta: "12.4% (▲ 1.2% vs prior month)"; RAG: Green < 5%, Amber 5–15%, Red > 15% (matches existing `management_summary` thresholds) |
| Email panel | Narrative: total accepted (N), total recast (N), overall rate, MoM delta direction. Top-3 Owners by exception count as supporting data. Flag if exceptions are expiring within 30 days. |
| PDF section | Two KPI tiles: Accepted count, Recast count. Rate gauge. Owner breakdown table (accepted count + recast count + rate per Owner). Expiring-soon alert box if any rules expire within 30 days. |
| Analyst drill-down | Per-rule detail: rule UUID, original severity, current severity (if recast), created_at, expiry_date, Owner, finding count under this rule. Sorted by expiry ascending. |

#### Edge cases

- **Zero exceptions:** Valid state (clean exception posture). Return green RAG, "0 managed exceptions in scope."
- **Prior-month snapshot missing:** If S1 has no prior-month exception count, show current count only; omit delta arrow. Label clearly: "Prior month data not yet available." Do not show "▲ 0%."
- **`fetch_recast_rules()` failure:** The recast rules API is a secondary enrichment. If it fails (auth error, timeout), the module should degrade gracefully: show finding-level exception counts from `severity_modification_type` only, add a note "Rule-level detail unavailable," and not crash the batch.
- **Recast rules filter tree complexity:** `_summarize_filter()` already exists in `data/fetchers.py` to convert the filter tree to a readable string. The analyst drill-down uses this — do not attempt to parse arbitrary filter trees inline.
- **ACCEPTED vs RECASTED distinction:** Both reduce apparent severity. The email panel and PDF must clearly distinguish: "Accepted" = acknowledged residual risk (not fixed); "Recasted" = severity adjusted by analyst. They have different remediation implications. Do not aggregate them silently as "exceptions" in the analyst workbook — keep separate columns.
- **Rate denominator:** Total open findings (state IN {open, reopened}), same as `management_summary` Metric 6. Consistent with existing definitions.

#### Dependencies

- `vulns_all.parquet` (severity_modification_type, recast_rule_uuid, first_found)
- `data/fetchers.py` `fetch_recast_rules()` — rule metadata enrichment (optional degradation if unavailable)
- S2 `extract_owner()` — Owner breakdown
- S1 `data/trend_store.py` — prior-month snapshot for delta (exception_count must be added as a tracked dimension — same new-dimension decision as Module 3)

---

### Module 5 — Program Health Overview (program_health)

**Classification:** TABLE STAKES
**Complexity:** MEDIUM
**Audience:** Senior Management (Directors / VPs)

#### Core metric / definition

A composite MoM velocity dashboard that stitches together the key program signals on one page/panel: total open by severity trend, inflow/outflow rates (from New vs Remediated), SLA compliance rate trend, and MTTR trend. The goal is a single "how is the program doing this month vs last month" view without requiring the reader to flip between five separate pages. This partially overlaps with `management_summary` Metric 7 (MoM Trend) and Metric 4 (SLA Compliance) — GEN-01 migration makes those modules available here.

Note: Program Health is a **composer** module that references the outputs of other modules. It does not compute its own metrics independently; it aggregates from Module 1 (New vs Remediated), existing SLA compliance metrics, and the reworked MTTR module. This makes it the "summary of summaries" for the management audience.

#### Data fields

- S1 `read_trend()` snapshots — MoM open counts by severity
- New vs Remediated module output — inflow/outflow velocity
- SLA compliance data (from `management_summary` Metric 4 logic, to be modularized via GEN-01)
- Reworked MTTR module output — MTTR trend
- S2 `extract_owner()` — Owner velocity table (which Owners improved/worsened)

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | Single composite status: "Program on track / at risk / off track" based on a majority-of-signals rule across open trend + SLA rate + MTTR. |
| Email panel | 4-tile KPI row: Open Critical delta, Net velocity (new-vs-remediated), SLA rate delta, MTTR trend. One-paragraph narrative: "This month the program [improved/held/worsened] on N of 4 key indicators." |
| PDF section | Sparkline row (mini trend line per metric). Owner velocity table: each Owner's MoM delta on open Crit+High. Traffic-light columns per metric. |
| Analyst drill-down | Per-Owner per-metric MoM deltas table. Outlier flag: Owners whose open count increased > 20% MoM. |

#### Edge cases

- **Cold start (fewer than 2 S1 snapshots):** Velocity metrics requiring MoM delta show "—" with cold-start notice. The 4-tile KPI row shows current values only. This is a normal first-month state, not an error.
- **Partial module failures:** Program Health depends on New vs Remediated and MTTR module outputs being available in the same batch run. If either returns an error state, Program Health degrades gracefully: use available signals, note missing signals explicitly. Composite RAG shows Amber (data incomplete) when any signal is missing.
- **Composite RAG definition:** "Majority-of-signals" rule needs precise specification at plan time — if 3 of 4 signals are green, is the composite green or amber? Recommend: Green = all 4 green; Amber = 2–3 green; Red = 0–1 green. Flag as open decision.
- **Overlap with management_summary Metric 7:** GEN-01 migration will extract Metric 7 into a module. Program Health Overview should consume that module's output, not re-implement the MoM trend logic. Sequence dependency: GEN-01 must land before or alongside Program Health.

#### Dependencies

- S1 `data/trend_store.py` (read_trend)
- Module 1 (new_vs_remediated) output — inflow/outflow rates
- Module 6 (mttr_rework) output — MTTR trend
- GEN-01 migrated SLA compliance module output
- S2 `extract_owner()` — Owner velocity
- **Sequence dependency:** Program Health is best built last among the new modules, after Module 1, Module 6, and GEN-01 are available as inputs.

---

### Module 6 — MTTR Rework (mttr_by_severity — replacement)

**Classification:** TABLE STAKES
**Complexity:** HIGH
**Audience:** Senior Management (Directors / VPs) + Analysts

#### Core metric / definition

Mean Time to Remediate, reworked to address four disclosed gaps in the current `mttr_by_severity_module.py`:

**(a) Disclose the ~30-day window:** MTTR is computed from `vulns_fixed.parquet` which Tenable retains only ~29 days. The current module computes a "rolling ~30-day MTTR" but never discloses this. Fix: label all MTTR outputs as "Rolling 30-day MTTR (findings remediated in the last ~30 days)" in PDF, email, Excel, and the calculations runbook. This is a correctness and transparency requirement.

**(b) Sample-weighted overall MTTR:** Current `overall_mttr = mean(per_severity_mttr_values)` is an unweighted mean-of-means. A program that remediates 500 Low and 2 Critical findings looks like it has the average of Critical MTTR and Low MTTR, even though Low dominates the sample. Fix: `overall_mttr = sum(days_to_fix for all findings) / count(all findings)` — a single weighted mean across the full fixed population.

**(c) Reopened-finding exclusion:** A finding that was fixed and then reopened has `last_fixed - first_found` spanning its entire history including reopen cycles, inflating `days_to_fix`. Fix: exclude findings with `state == REOPENED` from the MTTR denominator (they have not been durably fixed), OR include only findings where `last_fixed` is the *most recent* fix event. **This is the resolved-population decision** — see open decisions below.

**(d) Trend + Owner / four-channel contract:** Current module uses `render_email_kpis` (legacy channel). Fix: implement all four channels (`render_pdf_section`, `render_excel_tabs`, `render_email_panel`, `render_rag_strip_entry`, `render_analyst_tabs`). Add MoM MTTR trend per severity. Add per-Owner MTTR breakdown.

#### Data fields

- `vulns_fixed.parquet` (state, severity, first_found, last_fixed, time_taken_to_fix, asset_uuid) — primary MTTR source
- `state` — filter to exclude REOPENED from fixed denominator (per resolved-population decision)
- S2 `extract_owner()` joined via `asset_uuid` → `assets_df` — per-Owner MTTR
- S1 `data/trend_store.py` — MTTR trend requires either (a) monthly MTTR snapshots added as a new S1 dimension, or (b) reconstruction from the ~30-day fixed window (inherently limited to 1 month's look-back). Trend beyond 1 month requires snapshot accumulation forward from first capture.

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | Overall weighted MTTR vs SLA: "Avg 18d (Critical: 11d / High: 22d)"; RAG based on Critical MTTR vs 15-day SLA (most leadership-salient): Green ≤ SLA, Amber ≤ 1.25×SLA, Red > 1.25×SLA |
| Email panel | 4-severity mini-table: severity, MTTR, SLA target, status dot. One-sentence overall: "Critical findings are being resolved in N days on average (SLA: 15 days)." Disclosure footer: "Based on findings remediated in the last ~30 days." |
| PDF section | 4-gauge row (one per severity, same as current render_pdf_section). SLA reference table. Sample size per severity. Disclosure text. MoM sparkline for Critical MTTR. |
| Analyst drill-down | Per-Owner MTTR table (weighted mean per Owner per severity). Sample size per Owner per severity. Findings excluded from MTTR due to resolved-population filter (with reason). |

#### Edge cases

- **Resolved-population decision (open, requires plan-time resolution):** Three candidate definitions for "resolved" in the MTTR denominator:
  - **Option A (simplest):** All findings with `state == fixed` AND `last_fixed` is not null. Includes findings that were previously reopened and are now fixed again. Most inclusive; may overstate MTTR for chronic re-openers.
  - **Option B (reopened-excluded):** Exclude any finding that also appears in the open/reopened export (i.e., currently in REOPENED state). Requires a join between fixed and open exports. Excludes in-progress reopen cycles from the denominator.
  - **Option C (first-time-fixes only):** Only findings where this is the first `last_fixed` event — requires detecting whether `first_found` and `last_fixed` form a contiguous first-time fix. Hard to implement reliably without Tenable exposing a "fix count" field. Not recommended.
  - **Recommendation:** Option B. It excludes the current REOPENED population (which inflates MTTR) without requiring reconstruction of multi-event histories. Document the exclusion explicitly.
- **Sample size below threshold:** Per-severity MTTR with fewer than `min_sample_size` findings (default 5, configurable) should show "Insufficient data (N findings)" rather than a potentially misleading single-finding average.
- **No fixed findings in scope:** Return `_empty_result()` with gray RAG. "No remediated findings in scope for this period."
- **`time_taken_to_fix` vs date arithmetic:** Existing logic (primary: `time_taken_to_fix / 86400`; fallback: `(last_fixed - first_found).days`) is correct and must be preserved. The rework does not change this derivation.
- **Owner join failure:** If `asset_uuid` join between fixed vulns and assets fails (unlicensed/untracked asset), assign Owner = "Unassigned" (consistent with S2 pattern).
- **Backward compatibility:** The existing `mttr_by_severity_module.py` is registered in `board_summary`. The rework replaces it in-place (same MODULE_ID). Smoke baselines for board_summary must be re-captured after the rework lands.

#### Dependencies

- `vulns_fixed.parquet` — primary data source
- `vulns_all.parquet` (state) — for REOPENED exclusion in Option B
- S2 `extract_owner()` + `assets_df` — per-Owner MTTR
- S1 `data/trend_store.py` — MoM MTTR trend (new snapshot dimension needed)
- **Open decision (critical):** Resolved-population definition — Option A, B, or C (see above). Shapes every MTTR number in every channel.
- **Backward compatibility risk:** MODULE_ID collision with existing board_summary registration. Handle via in-place replacement + smoke baseline re-capture.

---

### Module 7 — External / DMZ Exposure Cut (external_exposure)

**Classification:** DIFFERENTIATOR
**Complexity:** MEDIUM-HIGH
**Audience:** Senior Management + Analysts

#### WAS DEFERRED — host-vuln exposure cut only, no new data source

WAS (Web Application Scan) findings are explicitly deferred from this module. The pyTenable version constraint remains in place. This module is a **host-vulnerability exposure cut** using existing `vulns_all.parquet` + `assets_all.parquet`, scoped to externally-facing assets.

#### Core metric / definition

Open vulnerability counts on externally-facing assets, compared to the overall estate. "External" is defined by a dual signal:

- **Tag signal:** asset carries Tenable tag `Location=External` OR `Location=DMZ`
- **IP signal:** asset `ipv4` address is outside RFC 1918 private space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), CGNAT (100.64.0.0/10), loopback (127.0.0.0/8), and link-local (169.254.0.0/16)

An asset is external if EITHER condition is true. An asset is a **mismatch** if the tag signal and IP signal disagree (public IP but no External/DMZ tag, OR External/DMZ tag but private IP). Mismatches go to an analyst exception list — same pattern as S2 "Unassigned" catch-all.

This definition is sourced verbatim from `notes/operator-remediation-priority-model.md` (Tier 1 exposure) and is the project's canonical external-scope definition.

#### Data fields

- `assets_all.parquet` (`ipv4`, `tags`) — external classification
- `vulns_all.parquet` (`asset_uuid`, severity, state) — finding counts on external assets
- `tags` column — Location=External / Location=DMZ detection
- S2 `extract_owner()` — per-Owner external exposure breakdown

#### Audience-appropriate presentation

| Channel | Content |
|---------|---------|
| RAG strip headline | External Critical+High count: "47 Crit+High on external assets (12% of total)"; RAG: threshold configuration needed (org-specific); default: Green = 0 Critical, Amber = 1–5 Critical, Red > 5 Critical |
| Email panel | Narrative: external asset count, Critical/High/Medium finding counts on external scope, % of total findings that are on external assets, MoM delta if S1 has prior snapshots. |
| PDF section | KPI tiles: external asset count, Critical count on external, High count on external. Per-severity bar comparing external vs total. Mismatch count with note directing to analyst workbook. |
| Analyst drill-down | Mismatch table: assets with public IP but no Location tag (tag-gap), assets with Location=External/DMZ tag but private IP (tag-error). Asset UUID + IP + tags only (no full hostnames per D-04-08 — use asset_uuid). Per-Owner external finding counts. |

#### Edge cases

- **Mismatch handling:** Public-IP-but-untagged assets are still included in the external scope (IP signal is sufficient). Tagged-but-private assets are flagged to analyst exception list but still included in scope (tag signal is explicit override). Do not silently exclude either population.
- **IPv6 addresses:** The RFC 1918 / CGNAT / loopback exclusion list is IPv4-only. If `ipv6` is present on the asset, classify as external only if the IPv4 address also qualifies OR the Location tag is present. Do not attempt IPv6 public/private classification — flag as "IPv6 only" in analyst drill-down.
- **Zero external assets:** Valid state for some tag-filtered groups (e.g., a group scoped to internal application servers). Return gray RAG "No external assets in scope" — not an error.
- **No IPv4 field:** Some assets may lack an `ipv4` field (agents, cloud assets). Fall back to tag-only classification. If neither signal available, classify as unknown — do not include in external scope, add to analyst exception list.
- **MoM trend cold start:** External exposure trend via S1 requires the external scope to be a parameterized dimension in `capture_snapshot`. This may not be feasible in S1's current dimension model (which captures by tag filter, not by computed scope). Fallback: current-snapshot-only for first delivery; trend adds over time if a separate snapshot mechanism is implemented. Flag for plan-time decision.

#### Dependencies

- `assets_all.parquet` (ipv4, tags) — scope classification
- `vulns_all.parquet` — findings on external assets
- S2 `extract_owner()` — Owner breakdown
- `operator-remediation-priority-model.md` — canonical external-scope definition (already documented)
- **New helper needed:** `utils/external_scope.py` — `classify_external(assets_df) -> (external_df, mismatch_df)` implementing the dual-signal logic. Reusable by any future module needing external scope.
- **Open decision:** MoM trend mechanism — S1 parameterized dimension vs module-local snapshot.

---

### Module 8 — GEN-01: management_summary Migration (module contract migration)

**Classification:** TABLE STAKES
**Complexity:** HIGH
**Audience:** Internal (engineering) — outcome is invisible to end-users but is required for all other v1.4 modules to compose cleanly into management_summary delivery

#### Core metric / definition

Migrate `reports/management_summary.py` from its bespoke render path onto the four-channel module contract. The existing 7 metrics become individual modules; `ReportComposer.run_full_pipeline()` replaces the bespoke `_build_pdf()` / `build_email_body()` pipeline. The migration must not regress existing management_summary delivery (PDF output, email body, delivery_config.yaml compatibility).

This is the same pattern as the v1.0 board_summary cutover: smoke baselines + visual operator UAT. CHROME-COMPAT-01 analog: `management_summary` byte-unchanged is NOT the constraint here (it's being migrated), but the external observable outputs (PDF shape, email tile layout, SLA reference table) must match pre-migration behavior.

#### Existing metrics that become modules

| Existing metric | Module candidate | Status |
|-----------------|-----------------|--------|
| Metric 1 — Total Open Vulns by Severity | `total_vulns_by_severity` | Already shipped as a module (Phase 12/13 deliverable) |
| Metric 2 — Asset Scan Coverage | `scan_coverage_sla` | Already shipped as a module |
| Metric 3 — MTTR | `mttr_by_severity` | Exists; being reworked as Module 6 above |
| Metric 4 — SLA Compliance Rate | To be extracted | Not yet a standalone module |
| Metric 5 — Vulnerability Age Distribution | To be extracted | Not yet a standalone module |
| Metric 6 — Managed Exception Rate | Superseded by Module 4 (accepted_recast) | Not yet a standalone module |
| Metric 7 — MoM Trend | To be extracted | Not yet a standalone module; consumes S1 read_trend |

#### Audience-appropriate presentation

Not audience-facing — this is an infrastructure migration. Outputs are the same PDF (5pp), same email body structure, same Excel (if added). The chrome framework (`pdf_chrome.py`) is acquired automatically once `management_summary` is added to `_CHROME_AWARE_SLUGS`.

#### Edge cases and migration risks

- **Regression risk:** The existing `management_summary` email body uses the legacy `build_email_body()` KPI-tile shell. After migration it must route through `build_email_body_modular()`. The predicate is "any report's `email_body_html` non-empty" — this is already in `email_sender.py`. No changes to delivery infrastructure needed.
- **Smoke baseline requirement:** Pre-migration baselines must be captured from the current `management_summary` output. Post-migration smoke must match structural shape (page count, section headings, tile counts) — same approach as board_summary cutover (`scripts/smoke_board_summary_cutover.py`). A new `scripts/smoke_management_summary_cutover.py` is needed.
- **Metrics 4, 5, 6 extraction:** Three metrics have no existing standalone modules. They must be extracted and wrapped before GEN-01 can complete. This adds ~3 new module files to the migration scope.
- **Metric 6 → Module 4 supersession:** If Module 4 (Accepted & Recast) ships as a standalone module, the legacy Metric 6 (Managed Exception Rate) can be replaced by Module 4 in the management_summary bundle. This is the intended outcome; confirm at plan time.
- **Delivery config compatibility:** Groups currently configured with `reports: [management_summary]` must continue to work. No YAML changes required from operators.
- **Test synthetic data:** `management_summary.py` has `--test-pdf` and `--test-email` modes with synthetic data. These must remain functional after migration, or equivalent test modes must be added to the new module-based path.

#### Dependencies

- `reports/modules/composer.py` (ReportComposer) — already supports management-report-scale bundles via board_summary proof
- `reports/modules/pdf_chrome.py` — chrome becomes available once slug is in `_CHROME_AWARE_SLUGS`
- All 7 metric modules (3 existing, 3 to extract, 1 reworked) must be complete before GEN-01 assembly
- Module 6 (MTTR Rework) — must land before GEN-01 to avoid immediately re-migrating
- `delivery/email_sender.py` bundle-driven routing — no changes needed (predicate already in place)
- **Sequence dependency:** GEN-01 is a wrapper/assembly task. All constituent modules must be implemented first. It is the last item in the v1.4 build sequence.

---

## Table Stakes vs Differentiator Summary

| Module | Classification | Complexity | Reason |
|--------|---------------|------------|--------|
| New vs Remediated | Table Stakes | MEDIUM | First question management asks: "are we making progress?" |
| Vulnerability Density | Differentiator | MEDIUM-HIGH | Adds fleet-size context most programs don't normalize for |
| Reopened Vulnerabilities | Table Stakes | MEDIUM | Regression signal expected by any mature vuln program |
| Accepted & Recast | Table Stakes | MEDIUM | Exception posture is expected management visibility |
| Program Health Overview | Table Stakes | MEDIUM | The "one pager" summary is the audience's primary ask |
| MTTR Rework | Table Stakes | HIGH | Existing MTTR has 4 correctness gaps; shipping them undisclosed is a trust risk |
| External Exposure Cut | Differentiator | MEDIUM-HIGH | Prioritized exposure context; not universally expected but high value |
| GEN-01 Migration | Table Stakes (infra) | HIGH | Required to compose new modules into management_summary delivery |

---

## Anti-Features

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| WAS findings in External Exposure | Full external attack surface view | Requires pyTenable upgrade (SDK lock constraint); no VPR; no lifecycle fields; WAS needs separate severity model | Defer WAS to a future milestone after SDK decision; ship host-vuln external cut now |
| Backfill N months of MTTR trend from history | Show longer trend at first delivery | Fixed findings retained only ~29 days; any backfill beyond that is fabricated data | Disclose 30-day window; accumulate trend forward from first capture |
| Real-time reopen rate (sub-monthly) | More granular regression detection | Tenable export is not a streaming source; sub-monthly snapshots require scheduler changes and produce misleading partial-month counts | Monthly snapshots + current-state count; label partial months |
| Per-asset MTTR in management email | "Show me which assets are slow" | Management-level report; per-asset detail is PII-adjacent and belongs in analyst drill-down only (D-04-08) | Per-Owner MTTR in email panel; per-asset in analyst Excel only |
| Historical severity-accurate MTTR | MTTR using severity-as-it-was at finding age | Tenable provides no recast history; applying today's VPR to past findings is misleading | Disclose caveat in calculations runbook; use current VPR with explicit note |

---

## Feature Dependencies

```
S1 trend substrate (shipped)
    └──required by──> New vs Remediated (cold-start safe)
    └──required by──> Vulnerability Density (asset_count field in snapshots)
    └──required by──> Reopened Vulns (new snapshot dimension needed)
    └──required by──> Accepted & Recast (prior-month snapshot for delta)
    └──required by──> Program Health Overview (MoM trend data)
    └──required by──> MTTR Rework (MoM MTTR trend)

S2 extract_owner (shipped)
    └──required by──> All 7 new modules (Owner drill-down)

Module 1 (New vs Remediated)
    └──consumed by──> Module 5 (Program Health Overview)

Module 6 (MTTR Rework)
    └──consumed by──> Module 5 (Program Health Overview)
    └──replaces──> existing mttr_by_severity in board_summary (smoke re-capture required)

GEN-01 migrated SLA compliance module
    └──consumed by──> Module 5 (Program Health Overview)

Modules 1–7 (all complete)
    └──required by──> GEN-01 assembly (management_summary migration)

vulns_fixed.parquet (already in cache)
    └──required by──> New vs Remediated (outflow count)
    └──required by──> MTTR Rework (primary MTTR source)
    └──required by──> Reopened Vulns (rate denominator — optional degradation)

utils/external_scope.py (new helper, Module 7)
    └──used by──> external_exposure module
    └──available for──> future operator-remediation-priority-model module
```

---

## Open Decisions for Plan-Time Resolution

These questions are explicitly deferred from research to requirements definition. Each shapes module behavior and must be resolved before implementation begins.

| Decision | Module | Options | Recommendation |
|----------|--------|---------|---------------|
| "New" inflow definition: `first_found` only vs `first_found OR resurfaced_date` | New vs Remediated | (A) `first_found` only — simpler, understates reopen churn; (B) include `resurfaced_date` for REOPENED findings — accurate but requires extra join | Option A for v1.4; document limitation; revisit with Reopened module data |
| Asset-count denominator for density | Vulnerability Density | (A) all licensed assets; (B) on-time-scanned licensed assets; (C) all assets | Option B — consistent with board_summary baseline |
| Reopened snapshot dimension in S1 | Reopened Vulns + Accepted & Recast | (A) extend `capture_snapshot` with new dimensions; (B) module-local snapshot file | Option A — avoid proliferating snapshot files; requires minor S1 extension |
| MTTR resolved-population | MTTR Rework | (A) all fixed findings; (B) exclude current-REOPENED population; (C) first-time fixes only | Option B — excludes in-progress reopen cycles; most accurate for management reporting |
| Program Health composite RAG rule | Program Health Overview | Majority-of-signals vs worst-signal-wins vs weighted | Recommend: Green = all green; Amber = 2–3 of 4 green; Red = 0–1 green |
| External exposure MoM trend mechanism | External Exposure | (A) S1 parameterized external dimension; (B) module-local snapshot | Defer MoM trend to v1.5 if S1 extension is complex; ship current-snapshot-only in v1.4 |
| MTTR rework backward compatibility | MTTR Rework | In-place MODULE_ID replacement vs new MODULE_ID alongside old | In-place replacement; re-capture board_summary smoke baselines |

---

## Build Sequence Implied by Dependencies

1. S1/S2 substrate (already shipped — v1.3 complete)
2. New helper: `utils/external_scope.py` (Module 7 prerequisite, also useful standalone)
3. Module 3 (Reopened Vulns) — establishes reopen-aware snapshot dimension decision
4. Module 4 (Accepted & Recast) — exception snapshot dimension decision (paired with Module 3)
5. Module 1 (New vs Remediated) — direct S1 consumer, no inter-module dependencies
6. Module 2 (Vulnerability Density) — S1 asset_count denominator consumer
7. Module 6 (MTTR Rework) — complex, independent, replaces existing module
8. Module 7 (External Exposure) — independent host-vuln cut
9. Module 5 (Program Health Overview) — depends on Modules 1, 6, and GEN-01 SLA module
10. GEN-01 (management_summary migration) — assembly last, all constituent modules complete

---

## Sources

All findings are HIGH confidence, sourced from:

- `.planning/PROJECT.md` — current milestone scope, substrate status, constraints
- `.planning/notes/report-requests-batch-2026-06.md` — requestor intent per-report, open decisions
- `.planning/notes/trend-reconstruction-engine.md` — S1 design, cold-start constraints, ~29d retention wall
- `.planning/notes/operator-remediation-priority-model.md` — external scope definition (Tier 1)
- `.planning/notes/vuln-type-distribution-module.md` — shipped module pattern to mirror
- `reports/modules/mttr_by_severity_module.py` — existing MTTR code; 4 disclosed gaps verified in source
- `docs/management_summary_calculations.md` — existing metric definitions (Metrics 1–7)
- `docs/board_summary_calculations.md` — existing board metric patterns, edge case handling
- `data/trend_store.py` — S1 snapshot engine; `asset_count` field confirmed per D-04
- `reports/modules/base.py` — four-channel contract, ModuleData fields
- `reports/modules/vuln_type_distribution_module.py` — shipped module pattern reference

---
*Feature research for: v1.4 Management Summary Reporting Improvement*
*Researched: 2026-06-11*
