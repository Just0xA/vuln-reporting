# Pitfalls Research

**Domain:** Vulnerability-management reporting — v1.4 Management Summary Reporting Improvement
**Researched:** 2026-06-11
**Confidence:** HIGH — all pitfalls grounded in this codebase's shipped code, confirmed spike findings, and prior milestone post-mortems

---

## Critical Pitfalls

### Pitfall 1: Cold-Start Mishandling — Promising MoM Metrics Before Two Snapshots Exist

**What goes wrong:**
A module reads `read_trend()` and renders a MoM delta (▲▼%) without checking `insufficient_data`. On first deploy or after a new tag scope is added, only one snapshot exists. Division by the prior-month value is division by zero or by `None`. The rendered output shows a nonsense percentage or raises a `TypeError` inside a render method, crashing the module and (without the `_empty_result` guard) crashing the whole batch.

**Why it happens:**
`read_trend()` already returns `{"snapshots": [...], "insufficient_data": bool}`. Developers focus on the happy-path (N snapshots available) and skip the branch. The issue is invisible in development — it only surfaces when the report runs against a recipient group whose tag scope has fewer than 2 captured months. Every new Owner group added to `delivery_config.yaml` is a cold start.

**How to avoid:**
Every module that renders a MoM delta MUST branch on `insufficient_data` before computing the delta. Return `_empty_result()` or render a "Insufficient history — first snapshot captured, trend available next month" gray RAG cell. The `read_trend()` contract already provides the flag; using it is mandatory, not optional.

Unit-test pattern: inject a single-snapshot trend fixture and assert the module renders the cold-start message rather than crashing or showing `NaN%`.

**Warning signs:**
- A new tag scope (Owner=X or Environment=Y) is added to `delivery_config.yaml` mid-program; the first run for that scope will always be cold.
- A trend JSON file is deleted or renamed during a cache cleanup — next run is cold again for that scope.
- `read_trend()` returns `insufficient_data: True` in logs but the render path has no branch for it.

**Phase to address:** The phase implementing New vs Remediated, Vulnerability Density, and Program Health Overview — all three are the first direct `read_trend()` consumers in v1.4. The cold-start branch must be in each module's `compute()` before those modules are considered shippable.

---

### Pitfall 2: Double-Counting Reopened Findings in New vs Remediated

**What goes wrong:**
New-vs-Remediated counts `first_found` in month as "new" and `last_fixed` in month as "remediated." A REOPENED finding has both a `first_found` (original discovery) and a `last_fixed` (the fix before reopening) and a `resurfaced_date`. If the module naively counts `first_found` without filtering to first-time appearances, a finding that was first found in month M, fixed in M+1, and reopened in M+2 will be counted as "new" in M and "remediated" in M+1 — and then absent from "new" in M+2 even though it reappeared. This silently understates new-finding velocity in months with significant reopened volume.

**Why it happens:**
The `first_found` field is always the original discovery date regardless of reopen cycles. There is no `resurfaced_as_new` flag. Developers write `df[df["first_found"].dt.to_period("M") == period]` and get results that look plausible but miss the reopen dimension.

**How to avoid:**
Define the population contract explicitly at the module level before any code is written:

- "New in month M" = findings where `first_found` falls in month M. Accept that a REOPENED finding's re-appearance is tracked by the Reopened Vulnerabilities module, not here. Document this boundary explicitly in the module docstring.
- "Remediated in month M" = findings where `last_fixed` falls in month M AND `state == 'fixed'`. Exclude REOPENED rows from the remediated count — a fixed-then-reopened finding's `last_fixed` is the fix before resurface, which is ambiguous as a "remediated" signal.

Unit-test on a fixture containing: one plain OPEN finding (first_found in month), one FIXED finding (last_fixed in month), one REOPENED finding with both `first_found` and `resurfaced_date` in different months. Assert the counts match the documented population contract.

**Warning signs:**
- New + Remediated counts drift significantly from the trend-store's open-count deltas — the delta between consecutive open-count snapshots should roughly equal New minus Remediated.
- The Reopened Vulnerabilities module and New vs Remediated show the same findings counted in two places.
- Remediated count in a month matches what was in the REOPENED population for that month.

**Phase to address:** New vs Remediated module implementation phase. The population contract must be in the module docstring and tested before the module is considered shippable.

---

### Pitfall 3: MTTR Reopened-Aware Gap — days_to_fix Overstates Duration for Reopened Findings

**What goes wrong:**
The existing `mttr_by_severity_module.py` falls back to `(last_fixed - first_found).days` when `time_taken_to_fix` is absent. For a REOPENED finding, `first_found` is the original discovery date and `last_fixed` is the most recent fix date. That span includes the dormant period between the first fix and the resurface — potentially months — inflating MTTR. A finding first found 200 days ago, fixed after 10 days, reopened 180 days later, and fixed again after 10 days shows `(last_fixed - first_found).days = 200` instead of the true remediation effort of ~10 days.

The reworked MTTR module must address this. The `time_taken_to_fix` primary path avoids the issue only if Tenable populates it per-fix-event rather than per-original-discovery — this has not been verified on live data for the REOPENED case.

**Why it happens:**
The date-span fallback is a natural approximation that is correct for simple OPEN→FIXED cases and silently wrong for REOPENED cases. The existing module's `get_audit_info()` notes the approximation but does not flag the reopened inflation.

**How to avoid:**
In the MTTR rework:
1. Exclude REOPENED findings from the `(last_fixed - first_found).days` fallback path. For those rows, use `time_taken_to_fix` only; if absent, flag them as `min_sample` deficient rather than computing a misleading duration.
2. Alternatively, compute `(last_fixed - resurfaced_date).days` for REOPENED rows where `resurfaced_date` is not NaT — this gives time-from-resurface-to-fix, the operationally meaningful remediation effort.
3. Lock the resolved-population decision (exclude reopened entirely vs. measure from resurface) in a plan-level context document before implementation begins. This is one of the open decisions flagged in `notes/report-requests-batch-2026-06.md`.

Unit-test: fixture with one REOPENED finding where `first_found` is 200 days ago, `resurfaced_date` is 10 days ago, `last_fixed` is 2 days ago. Assert MTTR is ~8 days, not 198.

**Warning signs:**
- MTTR for any severity tier is substantially higher than intuition suggests for a well-performing program.
- The sample-size footnote shows a mix of OPEN, REOPENED, and FIXED states in the denominator.
- `(last_fixed - first_found).days` produces a value larger than the longest SLA tier by a factor of 2+.

**Phase to address:** MTTR rework phase. The reopened population decision must be locked before any code is written.

---

### Pitfall 4: Vulnerability Density Denominator Drift — Asset Count Changes Month to Month

**What goes wrong:**
Vulnerability Density = open vulns / asset count. The trend-store snapshot already captures `asset_count` at capture time (D-04 in `trend_store.py`). But if a module reads `assets_df` at render time and divides historical open-count snapshots by the current asset count, every historical density point is recalculated against today's denominator. A scope that added 50 assets last month will show a retroactive density drop across all prior months — an artifact, not a real improvement.

**Why it happens:**
It is tempting to compute density as `snapshot["critical"] / len(assets_df)` in a loop over snapshots. The current asset count is readily available; the snapshot's `asset_count` field requires reading from the JSON structure, and developers may miss it.

**How to avoid:**
Always use `snapshot["asset_count"]` from each snapshot entry for that snapshot's density calculation, not the current `assets_df` length. The field is already captured per snapshot by `capture_snapshot()`. Guard against `asset_count == 0` with `safe_int` / a zero-division guard before dividing.

Unit-test: two-snapshot fixture where `asset_count` differs between months. Assert each month's density uses its own snapshot's `asset_count`, not a shared value.

**Warning signs:**
- All historical density points move uniformly when a large number of assets are onboarded — historical points are immutable; uniform movement means the denominator is live.
- The density chart shows a sharp retroactive drop at the current month that was not present in last month's render.

**Phase to address:** Vulnerability Density module implementation phase. The denominator source (snapshot-captured `asset_count`, not live `assets_df`) must be explicit in the module's `compute()` docstring.

---

### Pitfall 5: MoM Delta When Prior Snapshot Is Missing — Division by Zero and None Propagation

**What goes wrong:**
A `▲▼%` calculation of `(current - prior) / prior * 100` fails silently or raises when `prior` is `0` or `None`. This is distinct from the cold-start case: even with 6 months of snapshots, a specific Owner may have had zero findings in one month (new team, new tag scope, genuine zero). Division by zero produces `inf` or raises `ZeroDivisionError`; an f-string format spec applied to `None` raises `TypeError`.

**Why it happens:**
Developers write `pct_change = (curr - prev) / prev * 100` inline without considering the zero-denominator case. The `safe_pct` utility exists for exactly this but is enforced only by convention.

**How to avoid:**
Use `safe_pct`, `safe_int`, and `safe_format` from `reports.modules.format_utils` for every computed percentage entering a render method. The CLAUDE.md prohibition is explicit: inline f-string format specs on possibly-`None` values are forbidden. Additionally, define a standard "prior was zero, now N" label (e.g. `"New"` or `"N/A — prior zero"`) rather than showing `inf%`.

Add a `_safe_mom_delta(curr, prev)` module-level helper that returns `(delta, pct_str)` where `pct_str` is `"N/A"` when `prev` is `None` or `0`. Never compute the percentage inline in a render method.

**Warning signs:**
- Any `ZeroDivisionError` or `TypeError: unsupported format character` in module render logs.
- An Owner bucket that was absent last month appears in the render with an `inf%` delta.
- A recipient group filtered to a new tag scope has zero prior-month findings in its snapshot.

**Phase to address:** All MoM delta modules (New vs Remediated, Vulnerability Density, Accepted & Recast, Program Health Overview). The zero-denominator guard must be present before any percentage is rendered.

---

### Pitfall 6: Recast / Accepted Classification Edge Cases

**What goes wrong:**
Three sub-traps exist:

**a) Expired rules still appear in the findings export.**
A recast rule with an expiration date continues to show `severity_modification_type != "none"` on findings until the next scan re-evaluates them. The Accepted & Recast module must cross-check expiration against `fetch_recast_rules()` data, not rely solely on `severity_modification_type` on the finding row. Counting an expired accepted risk as "currently accepted" overstates the accepted posture.

**b) `severity_modification_type` values beyond "accepted".**
The field can be `"accepted"`, `"recasted"`, `"none"`, or empty string. An empty string is not `"none"`. A module filtering `severity_modification_type == "accepted"` misses the empty-string case (which should map to "not modified"). Additionally, recasted findings are not risk-accepted — they have a distinct operational meaning (severity reclassified vs. risk formally accepted). The module must track accepted and recasted as separate counts.

**c) Rule-count vs. finding-count confusion.**
`fetch_recast_rules()` returns one row per rule; `fetch_all_vulnerabilities()` returns one row per finding. A single recast rule can cover thousands of findings. The Accepted & Recast module's headline metric must be finding count (from `vulns_df`), not rule count. Rule list belongs in the analyst drill-down tab.

**How to avoid:**
- Filter `severity_modification_type` using `.isin({"accepted", "recasted"})` explicitly; treat empty string and `"none"` as unmodified.
- Join `vulns_df` against `fetch_recast_rules()` on `recast_rule_uuid` to cross-check expiration. Flag findings whose rule is expired as "pending re-evaluation" rather than "accepted."
- Keep finding counts in `metrics`, rule counts in `analyst_rows` / `table_data`.

Unit-test: fixture with one accepted finding whose rule is expired; assert it does NOT appear in the current-accepted count.

**Warning signs:**
- Accepted finding count differs significantly from what the operations team expects — check for expired-rule contamination.
- `severity_modification_type` shows unexpected values (empty string, `null`) in a live sample; enumerate them before coding the filter.

**Phase to address:** Accepted & Recast module implementation phase. The classification logic (including all three sub-traps) must be locked in the plan context document before implementation begins.

---

### Pitfall 7: External Scope False Positives — CGNAT, Loopback, Link-Local, and Multi-Homed Assets

**What goes wrong:**
The External / DMZ exposure cut scopes by `Location=External/DMZ` tag OR computed public IPv4 (non-RFC1918). Naively checking "not RFC1918" admits:
- **CGNAT range**: `100.64.0.0/10` — publicly routable but carrier-grade NAT; not internet-facing.
- **Loopback**: `127.0.0.0/8` — never external.
- **Link-local**: `169.254.0.0/16` — APIPA, never external.
- **Documentation/test ranges**: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
- **Multi-homed assets**: an asset with one private IP and one public IP is genuinely external-facing; but an asset with a public IP that is actually behind a NAT boundary is not. Tenable reports the scanned IP, which may be the private side of a NAT pair.

For IPv6, link-local (`fe80::/10`) and unique-local (`fc00::/7`) are not internet-facing and must be excluded.

**How to avoid:**
Use `ipaddress.ip_address(ip).is_global` from the Python standard library rather than a hand-rolled RFC1918 check. `is_global` returns `False` for loopback, link-local, private, CGNAT, and documentation ranges. For IPv6, the same `is_global` check handles `fe80::` and `fc00::` correctly.

The analyst mismatch list (public-IP-but-untagged assets) must include the asset's IP, hostname, and Owner tag so the operations team can validate whether the IP is truly internet-facing or a NAT artifact. Do not auto-classify; surface for human review.

**Warning signs:**
- The external scope includes assets in `10.x.x.x`, `172.16–31.x.x`, or `192.168.x.x` — the RFC1918 check missed a range.
- CGNAT addresses (`100.64.x.x`) appear in the external list.
- A known-internal server appears because it has a link-local IPv6 address that a hand-rolled "not private" check evaluates incorrectly.

**Phase to address:** External / DMZ module implementation phase. The IP classification helper must be unit-tested against CGNAT, loopback, link-local, IPv6 link-local, and documentation ranges before the scope predicate is used in any render.

---

### Pitfall 8: GEN-01 Backward-Compat Regression — management_summary Delivery Breaks During Migration

**What goes wrong:**
`management_summary` currently delivers to real recipient groups on a bespoke render path. During GEN-01 migration to the module render contract, a partial migration state — where the new module path is wired but the new modules are not fully implemented — causes the report to produce an empty PDF, crash in `ReportComposer.assemble_pdf()`, or emit a structurally different email body that breaks Outlook rendering. The v1.4 milestone constraint requires existing delivery to continue throughout migration.

Additionally, `management_summary.py` has a private `_sanitise_tag_for_filename` and `_load_trend_history` / `_save_trend_snapshot` that duplicate `data/trend_store.py`. If GEN-01 migration adds new modules that read from `read_trend()` while the bespoke path continues writing to `management_summary_*.json`, two parallel trend histories accumulate silently.

**Why it happens:**
The migration involves two simultaneous changes: adding the module infrastructure AND removing the bespoke render path. If both happen in the same plan without a smoke baseline, a mid-plan failure leaves the report in a broken in-between state with no regression bar.

**How to avoid:**
Follow the v1.0 board_summary cutover pattern exactly (D-04-05 REVISED):
1. Capture structural baselines from the current bespoke path before any migration code is written — same pattern as `scripts/smoke_board_summary_cutover.py`.
2. Build new modules in parallel with the bespoke path; do not remove the bespoke path until modules are proven.
3. Add a cutover toggle or script that switches the render path atomically.
4. Run the smoke baseline against the new path; fix structural regressions before any delivery.
5. In the same plan that routes reads through `read_trend()`, remove `_save_trend_snapshot()` calls from the bespoke path — never run both writers simultaneously.
6. Operator visual UAT confirms metric values (baselines are structural-only — metric values drift daily and locking them produces false-positive alerts per D-04-05).

**Warning signs:**
- PDF page count changes between bespoke and migrated paths — a missing page indicates a module returned `""` where content was expected.
- Email body switches from the modular `email_body_html` path to the legacy KPI-tile shell because `email_body_html` is empty string — check that all migrated modules implement `render_email_panel`.
- Both `management_summary_*.json` and `trend_*.json` files grow simultaneously — two trend histories are diverging.

**Phase to address:** GEN-01 migration phase. Structural baselines must be captured in the first plan of that phase, before any module code is written.

---

### Pitfall 9: pandas 3.0 Copy-on-Write — In-Place Assignment Silently Changes Dtype or Raises

**What goes wrong:**
pandas 3.0 Copy-on-Write (CoW) means that chained assignment (`df["col"] = value` after a filter or slice) either raises `ChainedAssignmentError` or silently mutates a copy rather than the original. A post-v1.3 bug (quick task `260611-b1x`) was exactly this: `df.loc[:, col] = value` after a boolean mask produced an `object` dtype column that caused a subsequent `.parquet` write to fail. v1.4 modules are entirely new code; the risk is writing any in-place column addition on a filtered DataFrame.

**Why it happens:**
The natural pattern for adding a computed column is `df["new_col"] = computed_series`. Under CoW this is fine on the original DataFrame but wrong after `df = df[mask]` or when the DataFrame was produced by a filter call upstream. New module code defaults to the in-place pattern without realizing the input arrived as a filtered view.

**How to avoid:**
Use `.assign()` for all column additions — the project-blessed pattern (CONVENTIONS.md F-DTYPE):

```python
df = df.assign(days_open=computed_series)
```

Never `df["days_open"] = computed_series` after a filter. Any in-place date normalization must be rewritten as `.assign()`. For module `compute()` methods that receive a tag-filtered `vulns_df`, always treat the input as potentially a view and use `.assign()` exclusively.

Run the full test suite with `pd.options.mode.copy_on_write = True` — in pandas 3.0 strict mode, `ChainedAssignmentError` warnings become errors and are easy to catch before they corrupt data silently.

**Warning signs:**
- `FutureWarning: ChainedAssignmentError` in pytest output — not cosmetic; becomes a hard error in a future patch.
- A parquet write fails with an unexpected dtype (`object` instead of `datetime64[ns, UTC]`) immediately after a column was set via `.loc`.
- A computed column added in `compute()` has `None` values where numeric values were expected — the assignment hit a copy, not the original.

**Phase to address:** Every module implementation phase. CoW compliance must be in the acceptance criteria for each plan; the issue bit v1.3 and must not repeat in v1.4.

---

### Pitfall 10: PII Leakage in New Snapshots and Committed Fixtures

**What goes wrong:**
A new module adds a trend snapshot or analyst drill-down that captures per-asset or per-finding detail (hostnames, IPs, plugin names, CVE IDs with associated asset data) rather than aggregate counts. That data enters a committed test fixture, a baseline file, or a log entry that reaches an AI assistant — violating D-04-08.

Three specific v1.4 risk surfaces:
- **Accepted & Recast analyst tab** — may include plugin names and asset identifiers. These must NOT appear in smoke baselines or committed fixtures.
- **External / DMZ mismatch list** — includes IPs and hostnames of untagged external assets. Output-only artifact; never committed anywhere.
- **Owner-dimension snapshots** — if a new snapshot accidentally captures per-asset breakdowns alongside owner counts, the JSON file becomes PII-bearing.

**Why it happens:**
`ModuleData.analyst_rows` is designed to hold drill-down DataFrames. Populating them with production-sourced rows to create "realistic" test fixtures is tempting because it catches real edge cases. The fixture is then committed.

**How to avoid:**
All test fixtures and committed baselines must use synthetic data only:
- Hostnames: `host-001.example.invalid`, `app-server.example.invalid` (RFC 6761)
- IPs: `203.0.113.x` (TEST-NET-3, RFC 5737 — unambiguously synthetic)
- Plugin IDs: sequential integers starting at `100001`
- Asset UUIDs: `00000000-0000-0000-0000-000000000001` pattern
- Owner names: `"Engineering"`, `"Operations"`, `"Unassigned"` — generic enough to be safe

The structural-only smoke baseline pattern (no row-level content, aggregate counts only) established in v1.0 must be followed for any new smoke script. Never dump a live parquet cache into a test fixture.

**Warning signs:**
- A test fixture file contains IP addresses in private ranges (`10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`) — those came from a real network.
- A baseline file contains plugin names longer than a synthetic stub.
- A committed YAML or JSON file contains `recast_rule_uuid` values that look like real Tenable UUIDs (32-char hex).

**Phase to address:** Every phase that creates modules with analyst drill-down data or new snapshot types. PII discipline must be in the acceptance criteria of each plan, not treated as a post-hoc audit item.

---

### Pitfall 11: Analyst Mismatch List Scope Creep — External Exception List Becomes a Second Vulnerability Report

**What goes wrong:**
The External / DMZ mismatch list (public-IP-but-untagged assets, analogous to the Owner `Unassigned` list from `owner_supplemental.py`) starts as a brief exception list to drive tagging cleanup. Over time it accumulates: vulnerability counts per untagged asset, severity breakdown, CVE identifiers, plugin names. It becomes a full vulnerability report for the external scope, effectively duplicating `sla_remediation` or `vuln_export` for that audience.

This is not a correctness bug but a scope-and-PII risk: the mismatch list's purpose is to drive tagging completion, not remediation tracking. Over-populating it conflates two distinct workflows and increases the risk of row-level data entering inappropriate channels.

**Why it happens:**
`analyst_rows` in `BaseModule` makes it easy to add columns incrementally. Each addition seems justified individually. There is no enforced schema on what goes in the analyst workbook.

**How to avoid:**
Define the mismatch list schema at design time and enforce it in `render_analyst_tabs()`:
- Columns allowed: `asset_uuid`, `ip_address`, `hostname`, `owner_tag`, `untagged_reason` (e.g. "public IP, no Location tag"), `finding_count` (aggregate total only — no per-finding rows).
- Explicitly excluded: plugin names, CVE IDs, per-severity breakdowns below the asset aggregate, `recast_rule_uuid`.

Document the exclusions in the module docstring. The audience for this list is the tagging-completion workflow.

**Warning signs:**
- The analyst tab for the mismatch list has more columns than the Owner supplemental list.
- A stakeholder requests "can we add the CVEs for each of these assets?" — that is `sla_remediation`'s job, not this list's.

**Phase to address:** External / DMZ module design phase (before implementation). The analyst-tab schema must be locked in the plan context document before any code is written.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Reuse `management_summary._load_trend_history()` instead of routing through `data.trend_store.read_trend()` during GEN-01 | Avoids touching the bespoke path | Two diverging trend readers; `management_summary_*.json` and `trend_*.json` grow in parallel; double maintenance surface | Never — GEN-01 must consolidate onto `read_trend()` |
| Compute MTTR from `(last_fixed - first_found).days` without reopened-aware correction | Ships faster; matches existing module behavior | Systematically inflates MTTR for any scope with significant reopened volume; auditors will flag the undisclosed window | Never for the reworked module — the gap is documented and the fix is known |
| Derive density using current `len(assets_df)` rather than each snapshot's `asset_count` | Avoids reading the per-snapshot field | Historical density points retroactively shift with every asset onboard/offboard; MoM comparisons become meaningless | Never — the snapshot already captures `asset_count` for this exact reason |
| Skip cold-start branch for "first month only" since there is no prior data | Avoids one code path | Crashes or renders `NaN%` on the first run for any new tag scope; every new Owner group is a cold start | Never — `insufficient_data` is a one-liner check |
| Use hand-rolled RFC1918 check instead of `ipaddress.ip_address().is_global` | Avoids one import | Misses CGNAT, link-local, IPv6 edge cases — false positives in the external scope | Never for a security-facing scope determination |
| Implement `render_email_kpis` (legacy channel) instead of `render_email_panel` (CONTRACT-01) for new modules | Matches the existing MTTR module's legacy channel | New modules do not participate in the modular email body routing (`email_body_html` predicate); they fall back to the KPI-tile shell | Never for new v1.4 modules — implement the full four-channel contract |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| `data.trend_store.read_trend()` | Pass raw `tag_category`/`tag_value` as `tag_filter` without sanitising; filename lookup fails silently and returns `insufficient_data=True` on a fully populated file | Call `_sanitise_tag_for_filename(tag_category, tag_value)` before passing to `read_trend()` — the same sanitisation used at capture time |
| `capture_snapshot()` scope coupling (IN-06) | Filter `vulns_df` to the tag scope but forget to filter `assets_df` to the same scope; `asset_count` records the full inventory, not the scoped count | Both `df` and `assets_df` must be filtered to the same scope by the caller before passing to `capture_snapshot()` — the function performs no scoping of its own |
| `open_findings_at()` date columns | Pass a `vulns_df` whose date columns have not been normalized by `_normalize_vuln_dates`; comparisons against `datetime64[ns, UTC]` columns fail with `TypeError` | Call `open_findings_at()` only on a DataFrame that has already passed through the fetcher's normalization step |
| `fetch_recast_rules()` filter field | Read the `filter` field as a flat dict; complex AND-OR trees cause `_extract_plugin_id_from_filter` to return `None` silently | Use `_summarize_filter()` for analyst display and `_extract_plugin_id_from_filter()` for plugin ID extraction; accept `None` as a valid "can't extract" result and surface it in the analyst tab rather than crashing |
| GEN-01 dual trend writers | Migration adds new module path reading from `read_trend()` while bespoke path continues writing to `management_summary_*.json`; both paths grow separate histories | In the same plan that routes reads through `read_trend()`, remove `_save_trend_snapshot()` calls from the bespoke path — never run both writers simultaneously |
| `ReportComposer.assemble_pdf()` | A new module's `render_pdf_section()` returns `None` instead of `""` (the no-op default); WeasyPrint fails on `None` concatenation in the page assembler | Every `render_pdf_section()` override must return a `str`; `""` is the correct no-output value; `None` is wrong even if it looks like a no-op |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Per-asset IP classification in a Python loop | External scope determination calls `ipaddress.ip_address(ip)` row-by-row; 10,000 assets takes several seconds | Vectorize using `df["ip"].apply(...)` or build the public-IP mask with a pre-compiled CIDR check | Noticeable above ~5,000 assets; painful above 20,000 |
| Reading the trend JSON file inside `render_pdf_section()` | Trend file re-read on every render call; in a multi-recipient group, read once per recipient | Trend data must be loaded in `compute()` and stored in `ModuleData.metadata` or `chart_data`; render methods receive the already-loaded data | Any multi-recipient group |
| Missing `fixed_vulns_df` in the parquet cache warm step for MTTR | MTTR rework needs the fixed population; if not pre-warmed, the module triggers a fresh Tenable export at render time, blocking the batch | Ensure `fetch_fixed_vulnerabilities()` is in `run_group()`'s pre-fetch warm step for any group whose module list includes the reworked MTTR module | Every MTTR run without pre-warming |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Logging `recast_reason` field verbatim at INFO level | `recast_reason` is free-text and may contain hostnames, IP ranges, or asset names — these appear in `logs/app.log` which may be shared or committed | Log `recast_reason` at DEBUG only; truncate at INFO: `reason[:40] + "..."` |
| Committing a trend snapshot JSON captured from a live tenant as a test fixture | Aggregate counts may be sensitive (e.g. "critical: 47 in Production") alongside the tenant's tag structure | Test fixtures must use synthetic counts (round numbers, no tag values matching real environments) |
| Passing `tag_value` directly into an HTML template without escaping | A tag value containing `<script>` or `&` renders broken HTML or executes in the email body | All dynamic values in `render_email_panel()` and `render_pdf_section()` must pass through `html.escape()` before interpolation |

---

## "Looks Done But Isn't" Checklist

- [ ] **New vs Remediated cold-start:** Module renders a cold-start message (not `NaN%`) when `insufficient_data=True` — verify by running against a fresh trend dir with one snapshot.
- [ ] **Vulnerability Density denominator:** Each historical point uses its own snapshot's `asset_count`, not `len(assets_df)` — verify by asserting density is stable when assets are added between runs.
- [ ] **MTTR reopened-aware:** REOPENED findings do not use `(last_fixed - first_found).days` as `days_to_fix` — verify with the reopened fixture described in Pitfall 3.
- [ ] **Recast expiry check:** An expired accepted-risk rule's findings do NOT appear in the current accepted count — verify with the fixture described in Pitfall 6.
- [ ] **External scope IP classification:** `100.64.1.1` (CGNAT) and `fe80::1` (IPv6 link-local) are NOT in the external scope — verify with unit tests on the IP classifier helper.
- [ ] **GEN-01 smoke baseline captured before migration begins:** Structural smoke passes against the migrated path before `_load_trend_history` / `_save_trend_snapshot` are removed — verify by running the management_summary smoke equivalent.
- [ ] **Four-channel contract completeness:** Every new module implements `render_email_panel` (CONTRACT-01), not only `render_email_kpis` — verify that `email_body_html` in the bundle is non-empty.
- [ ] **Empty-data hardening:** Each module's render methods survive a zero-row `vulns_df` without raising — verify by calling `compute()` on an empty DataFrame and asserting the RAG strip returns a gray "No Data" cell.
- [ ] **PII-clean fixtures:** No committed test fixture or baseline contains real hostnames, IPs, or plugin names — verify with the D-04-08 redaction test suite.
- [ ] **pandas CoW compliance:** No `df["col"] = val` after a filter or slice in any module — verify by running pytest with `pd.options.mode.copy_on_write = True`.

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Cold-start mishandling ships to production | LOW | Deploy a one-line hotfix adding the `insufficient_data` branch; no data loss; next scheduled run renders correctly |
| Double-counted reopened findings in New vs Remediated | MEDIUM | Correct the population filter; re-run the module; issue a corrected report with a note that prior-month counts were adjusted; no snapshot data loss |
| MTTR inflated by reopened findings | MEDIUM | Correct `days_to_fix` logic; re-run; MTTR values will drop; communicate the methodology change as an improvement in `docs/trend_and_segmentation_calculations.md` |
| Density denominator uses current asset count | LOW-MEDIUM | Fix to use snapshot's `asset_count`; historical density points change on next render; document the correction in the calculations runbook |
| GEN-01 regresses management_summary delivery | HIGH | Revert to the bespoke render path immediately (bespoke code must NOT be deleted until smoke baseline passes); diagnose module-by-module; re-run visual UAT before re-attempting cutover |
| PII committed in a test fixture or baseline | HIGH | Immediately: `git rm` the file, scrub from history via interactive rebase, force-push (requires reviewer approval); rotate any API keys if also present; audit all downstream clones |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Cold-start mishandling (P1) | New vs Remediated, Density, Program Health implementation phases | Unit test: single-snapshot fixture renders cold-start message, not `NaN%` |
| Reopened double-count in New vs Remediated (P2) | New vs Remediated implementation phase | Unit test: REOPENED fixture with documented population contract; counts match spec |
| MTTR reopened days_to_fix inflation (P3) | MTTR rework phase | Unit test: REOPENED fixture shows ~8d MTTR, not 198d |
| Density denominator drift (P4) | Vulnerability Density implementation phase | Unit test: two snapshots with different `asset_count`; each uses its own |
| MoM delta zero-denominator (P5) | All MoM delta modules | Unit test: prior=0 fixture produces `"N/A"` not `ZeroDivisionError` |
| Recast / accepted edge cases (P6) | Accepted & Recast implementation phase | Unit test: expired-rule fixture excluded; empty-string `severity_modification_type` treated as unmodified |
| External scope false positives (P7) | External / DMZ module implementation phase | Unit test: CGNAT, loopback, link-local, IPv6 link-local all excluded from scope |
| GEN-01 backward-compat regression (P8) | GEN-01 migration phase — baselines in the first plan, before any module code | Smoke baseline passes structural check; operator visual UAT sign-off before bespoke path removed |
| pandas CoW in-place assignment (P9) | Every module implementation phase | `pytest` with CoW strict mode: zero `ChainedAssignmentError` |
| PII leakage in snapshots / fixtures (P10) | Every phase adding modules with analyst drill-down or new snapshot types | D-04-08 redaction suite passes; `grep` for real IP/hostname patterns in committed files |
| Analyst mismatch list scope creep (P11) | External / DMZ design phase (before implementation) | Schema locked in plan context doc; `render_analyst_tabs()` column list matches spec |

---

## Sources

- `utils/open_count.py` — WR-01, WR-02, WR-03 edge-case comments; reopened-aware two-interval predicate implementation
- `data/trend_store.py` — D-01 through D-08 design constraints; IN-01 (concurrency), IN-06 (scope-coupling) contracts
- `reports/modules/mttr_by_severity_module.py` — existing MTTR gaps: undisclosed rolling ~30d window, unweighted mean-of-means, reopened fallback path
- `reports/management_summary.py` — bespoke trend path (`_load_trend_history`, `_save_trend_snapshot`, `_sanitise_tag_for_filename` duplication)
- `.planning/notes/trend-reconstruction-engine.md` — Spike 002 invalidation; cold-start; reopened lifecycle caveats; as-of-date severity drift caveat
- `.planning/notes/report-requests-batch-2026-06.md` — MTTR open decisions; WAS deferral locked; recast data sources; External scope dual-signal design
- `.planning/PROJECT.md` — Key Decisions D-04-05 (structural-only baselines), D-04-08 (PII discipline), v1.3 substrate decisions, GEN-01 backward-compat constraint
- `.planning/codebase/CONVENTIONS.md` — F-DTYPE (CoW / `.assign()` mandate); datetime/timezone policy; error-handling conventions
- Quick task `260611-b1x` post-v1.3 — CoW chained-assignment bug causing `object` dtype on parquet write; root cause and fix
- v1.0 board_summary cutover — structural-only smoke baseline pattern establishing D-04-05 REVISED

---
*Pitfalls research for: v1.4 Management Summary Reporting Improvement — management/exec trend-cut modules + GEN-01 migration*
*Researched: 2026-06-11*
