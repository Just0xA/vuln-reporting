# Phase 14: Shared Substrates + composed_report Gates - Context

**Gathered:** 2026-06-11
**Status:** Ready for planning

<domain>
## Phase Boundary

The pure-compute foundation layer for v1.4. Delivers two stdlib-only helpers
(`utils/external_scope.py`, `utils/asset_count.py`) and two kwargs-forwarding
gates in `reports/composed_report.py` so every downstream v1.4 module can
consume trend history, recast rules, and scope/denominator computations
**without I/O inside `compute()`**. No new data is fetched, no new dependency
is added, and `run_report()`'s signature is unchanged. The consuming modules
themselves are built in Phases 15–17 — this phase only stands up the substrates
and proves the gate with a stub module.

Requirements: SUB-01, SUB-02, SUB-03 (+ cross-cutting QUAL bars first exercised
here on the substrate code).

</domain>

<decisions>
## Implementation Decisions

### Vulnerability Density Denominator (OD-2 — locked)
- **D-01:** Density denominator = **on-time-scanned licensed assets** (assets
  with `last_licensed_scan_date` within the on-time window, i.e. the
  `scanned_on_time` split that `scan_coverage_sla_module` already computes) —
  **not** all-licensed. Chosen for consistency with the board_summary
  managed-asset baseline; numerator and denominator both reflect
  recently-observed assets.
- **D-02:** Trend coherence — the existing S1 snapshot stores
  `asset_count = len(assets_df)` (all in-scope assets), which is the **wrong
  basis** for an on-time-scanned density trend. That field is **not** reused for
  density. Phase 15 / OD-3 MUST extend the snapshot to store an
  **on-time-scanned count** going forward; the density MoM trend **cold-starts**
  on that new field and accumulates forward (no back-reuse of the all-asset
  history). The Phase-15 ">10% MoM denominator change" flag is the safety net.
  *(This is a dependency Phase 14 creates for Phase 15 — see Deferred.)*

### External Exposure MoM Trend (OD-6 — locked)
- **D-03:** **Defer external MoM trend to v1.5** (backlog EXT-TREND-01).
  `external_scope.py` is **current-snapshot classification only**; no S1
  external-dimension wiring in v1.4. (Already in REQUIREMENTS Out-of-Scope.)

### External Classification Model (SUB-01)
- **D-04:** **Tags are authoritative.** `Location=External` is Tenable's dynamic
  tag defined as *IP is not RFC1918* (the tag already encodes the public-IP
  rule server-side). `Location=DMZ` is a dynamic tag over a **designated
  internal (private) IP range** for DMZ assets — it **exists but is unpopulated**
  in v1.4. External scope = `Location=External` **OR** `Location=DMZ` tag.
- **D-05:** `is_public_ipv4()` is demoted to a **gap detector**. Its only job is
  to flag an asset that has a public IPv4 but is **missing** the External tag
  (tag lag / not-yet-classified) → mismatch reason `public_ip_untagged`. It
  never overrides a tag.
- **D-06:** **DMZ-tagged + private IP is the normal/expected state — NOT a
  mismatch.** The `tagged-but-private` reason from SUB-01 is dropped as a
  routine flag (kept defensive-only for an anomalous External-tag-on-private-IP
  data error). An empty/unpopulated DMZ tag is a valid zero state and must be
  handled gracefully (zero DMZ assets ≠ error).
- **D-07:** **CGNAT is a non-issue on real data.** Tenable never reports CGNAT
  (`100.64.0.0/10`) addresses — agents report the host's DHCP/DNS-assigned local
  IP; CGNAT only exists transiently via ZScaler on workstations and never
  reaches scan/agent data. The `is_global` helper's CGNAT exclusion is harmless
  defensive coverage; **no live-tenant CGNAT verification needed.**

### `external_scope.py` I/O Contract
- **D-08:** Returns `(scoped_df, mismatches_df)` mirroring the shipped S2
  `extract_owner()` tuple shape. `scoped_df` = the **filtered external-only
  subset** (External/DMZ tag OR public IP). Gap/mismatch assets appear in
  **both** `scoped_df` and `mismatches_df`.
- **D-09:** **Multi-IP:** classify on the single **primary `ipv4` column** that
  is already in `assets_df` (the fetcher collapses `ipv4s` → `ipv4[0]`). **No
  fetcher change.** Consistent with the one-assigned-IP-per-host agent model.
- **D-10:** **Tag matching mirrors `extract_owner._parse_tags`:** parse the
  `tags` column tokens (`"Category=Value;…"`), **case-insensitive** category
  match on `Location`, **exact** value `External`/`DMZ`. No Location tag → not
  external (unless caught by the public-IP gap detector).

### Mismatch-List PII Boundary (D-04-08 / SEG-03)
- **D-11:** `mismatches_df` carries asset-level fields (`asset_uuid`,
  `ip_address`, `owner_tag`, `untagged_reason`). Allowed in the
  **operator-local analyst tab AND internally-emailed reports** (local corporate
  domain). **NEVER committed to the repo, NEVER sent to AI/Claude.** The D-04-08
  rule bans repo-commit + AI submission, not internal email. Phase 15's
  committed/aggregate external counts stay `finding_count`-only (no per-finding
  CVE/plugin). See `project_pii_rule_is_ai_not_email`.

### `asset_count.py` Contract (SUB-02)
- **D-12:** Pure function. Accepts a **`report_date` (UTC, the run's
  `generated_at`)** and computes the on-time cutoff = `report_date − window`.
  **No `datetime.now()` inside** — keeps it pure and unit-testable with an
  injected date; honors the UTC-timestamp policy.
- **D-13:** The on-time window (**30 days**) is a **single canonical constant in
  `config.py`** (alongside the SLA constants). Both `asset_count` and
  `scan_coverage_sla` reference it — no `utils → reports.modules` backwards
  import, no drift. The trivial cutoff filter itself lives locally in
  `asset_count`.
- **D-14:** Returns **`None` (sentinel)** when no on-time-scanned assets are in
  scope — distinguishing "no assets" from "no vulns". Consumers must None-check
  before any division; the density module renders cold-start / No-Data via the
  empty-data guard (QUAL-03).

### `composed_report.py` kwargs Gates (SUB-03)
- **D-15:** Add `_MODULES_NEEDING_TREND_SNAPSHOTS` and
  `_MODULES_NEEDING_RECAST_RULES` frozensets + conditional fetch blocks,
  following the existing `_MODULES_NEEDING_FIXED_VULNS` /
  `_MODULES_NEEDING_ENV_TOTAL` pattern exactly. `run_report()` signature
  unchanged; existing composed groups pass `--dry-run` with no regression.
- **D-16:** The trend gate forwards the **full `read_trend()` dict**
  `{"snapshots": [...], "insufficient_data": bool}` under one kwarg
  **`trend_snapshots`**; modules branch on
  `trend_snapshots["insufficient_data"]` for the mandatory QUAL-01 cold-start
  check. The recast gate forwards **`recast_rules_df`** (a DataFrame), matching
  the `fixed_vulns_df` naming convention.
- **D-17:** Phase 14 **seeds the frozensets with the SC#4 test-stub module ID
  only**; each real v1.4 module adds itself to the appropriate frozenset in the
  phase that builds it. Documented intended mapping (not wired until each
  module lands):
  - TREND ⊇ `new_vs_remediated`, `vuln_density`, `accepted_recast`,
    `mttr_trend`, `program_health_overview`
  - RECAST ⊇ `accepted_recast`
  - `reopened_vulns` trend membership is decided in Phase 15 (RPT-03 does not
    mandate MoM).

### Test Strategy (QUAL-05)
- **D-18:** **Monkeypatch `is_global`** for the positive external-classification
  assertion so **no real-looking public IP enters fixtures**. The
  `is_public_ipv4` helper's negative/edge branches (RFC1918, CGNAT `100.64`,
  loopback, IPv6 link-local → all `False`) are tested with genuinely synthetic
  addresses. *Confirmed landmine:* RFC 5737 documentation ranges
  (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) all return `is_global=False` /
  `is_private=True` in Python — they **cannot** serve as a positive "external"
  fixture under the `is_global` rule.

### Claude's Discretion
- Exact frozenset/fetch-block wiring (follows the proven
  `_MODULES_NEEDING_FIXED_VULNS` pattern), `is_public_ipv4` internals (stdlib
  `ipaddress`), file placement, and helper signatures beyond the contracts
  above are implementation details for research/planning.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements
- `.planning/ROADMAP.md` § "Phase 14" — goal, success criteria 1–4, OD-2/OD-6 assignments.
- `.planning/REQUIREMENTS.md` — SUB-01, SUB-02, SUB-03; QUAL-01/02/03/05 bars; Out-of-Scope (WAS, External MoM).
- `.planning/research/SUMMARY.md` — OD recommendations, build-order rationale, "untouched files" list.
- `.planning/research/PITFALLS.md` — mandatory acceptance bars (cold-start, density denominator drift, reopened predicate, CoW, empty-data, PII).
- `.planning/research/ARCHITECTURE.md` — composed_report integration points; `**self._kwargs` fan-out.

### Proven patterns to mirror
- `reports/composed_report.py:73,79,186,289–301` — `_MODULES_NEEDING_FIXED_VULNS` / `_MODULES_NEEDING_ENV_TOTAL` gate + conditional fetch + `composer_kwargs` (the exact pattern D-15/D-16 follow).
- `reports/modules/board_report_utils.py:214` `extract_owner` + `_parse_tags` (case-insensitive category, exact value), and the `on_time` / `not_on_time` split (lines ~176–207) — D-08/D-10.
- `reports/modules/scan_coverage_sla_module.py` — `ON_TIME_WINDOW_DAYS`, `cutoff = report_date − window`, licensed/on-time split (D-01/D-12/D-13).
- `data/trend_store.py` — `read_trend()` `{snapshots, insufficient_data}` (D-16); `capture_snapshot()` + `asset_count = len(assets_df)` D-04 (the field D-02 must extend in Phase 15).
- `data/fetchers.py:519,549` — assets `ipv4s → ipv4[0]` collapse + `tags` column `"Category=Value;…"` format (D-09/D-10); `fetch_recast_rules()` → `recast_rules.parquet` (D-16 recast source).
- `utils/open_count.py` `open_findings_at()` — reopened-aware predicate (QUAL-02; carried-forward constraint).
- `config.py` — SLA constants; the on-time window canonical constant lands here (D-13).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `extract_owner()` tuple shape + `_parse_tags` — `external_scope.py` mirrors both (D-08/D-10).
- `scan_coverage_sla_module`'s on-time split — the denominator basis `asset_count.py` reuses (D-01/D-13).
- `read_trend()` / `capture_snapshot()` — already cold-start-safe and already capturing `asset_count` (D-04); only the on-time count field is missing (D-02).
- `composed_report.py` gate + `composer_kwargs` block — copy-paste-shaped extension point (D-15/D-16).

### Established Patterns
- Gate frozenset + conditional fetch + `**composer_kwargs` fan-out: `composer.py` / `base.py` stay untouched; new kwargs reach every `compute()` automatically.
- Module auto-discovery: the SC#4 stub module needs no `run_all.py`/schema registration.
- pandas 3.0 CoW — `.assign()` only, never `df["col"]=` after a filter (burned in `260611-b1x`).

### Integration Points
- `composed_report.py` is the only file modified in this phase besides the two new `utils/*` files, the new `config.py` constant, and the stub-module test fixture.
- **Untouched (per research):** `composer.py`, `base.py`, `data/trend_store.py` (read path), `utils/open_count.py`, `utils/tag_helper.py`, `delivery_config.schema.yaml`, `_VALID_REPORTS`/`_REPORT_MODULE_MAP`.

</code_context>

<specifics>
## Specific Ideas

Operator-supplied Tenable tag semantics (authoritative for the classifier design):
- `Location=External` is a **dynamic** Tenable tag = "IP is **not** RFC1918". The
  tag and the public-IP signal agree by construction; the IP check only catches
  the lag window before Tenable applies the tag.
- `Location=DMZ` is a **dynamic** tag over a **designated internal (private) IP
  range** for DMZ servers/assets. Exists in Tenable, **not yet populated** in v1.4.
- CGNAT (`100.64/10`) never appears in Tenable scan/agent data — agents report
  the local DHCP/DNS-assigned IP; CGNAT is a ZScaler-only transient on
  workstations.

</specifics>

<deferred>
## Deferred Ideas

- **EXT-TREND-01** — External Exposure month-over-month trend via an S1
  parameterized external dimension. Deferred to v1.5 (D-03). Current-snapshot
  only in v1.4.
- **S1 snapshot on-time-scanned count field** — Phase 14 *creates the
  requirement* (D-02) but the snapshot extension itself is **Phase 15 / OD-3**
  work; density MoM trend cold-starts on it.
- **`reopened_vulns` trend-membership** — whether `reopened_vulns` joins
  `_MODULES_NEEDING_TREND_SNAPSHOTS` is decided in Phase 15 when that module is
  built (D-17).
- **WAS in External Exposure (EXT-WAS-01)** — gated on the pyTenable upgrade;
  out of scope this milestone.

</deferred>

---

*Phase: 14-shared-substrates-composed-report-gates*
*Context gathered: 2026-06-11*
