# Quick Task 260701-da9: Tech Debt by Owner module — Context

**Gathered:** 2026-07-01
**Status:** Ready for planning

<domain>
## Task Boundary

Add a new metric module `tech_debt_by_owner` to `reports/modules/` that quantifies
each owner's "technical debt" (accumulated unfixed vulnerability backlog) and
renders a per-owner RAG rating across the four standard channels. The module plugs
into the existing `composed_report` / `ReportComposer` infrastructure via
auto-discovery — no new top-level report slug.
</domain>

<decisions>
## Implementation Decisions (LOCKED — do not revisit)

### Definition of "Tech Debt" (v1)
- Tech Debt = the **accumulated backlog of overdue, unfixed vulnerabilities** an
  owner is carrying — remediation deferred for short-term speed/budget, compounding
  into exploitable risk.
- v1 population = **overdue open findings** (overdue = `today - first_found > SLA_days`
  AND state in {open, reopened}), using the existing overdue logic in
  `utils/sla_calculator.py::get_sla_status`.
- The user's fuller multi-dimensional framing (missing-patch vs legacy/EOL vs
  misconfiguration) is **explicitly OUT of v1 scope** — noted as future work. Do NOT
  build a debt-dimension classifier.

### Risk scoring per owner
- Per-owner risk metric = **count of overdue Critical + High findings** (VPR-derived
  severity: Critical 9.0–10.0, High 7.0–8.9; fall back to native severity only when
  VPR is null, per project SLA policy).
- This is the "simplest scoring" option the user chose; it ties directly to the KPIs
  already in the email strip.

### Owner grouping (data path — VERIFIED)
- `composed_report.py` does NOT enrich vulns with tag columns; `vulns_df` has NO
  `tag_owner` column. The module must derive owner itself.
- `compute()` receives `assets_df`, which has `asset_uuid` + a semicolon-delimited
  `tags` string of `"Category=Value"` pairs (see `utils/tag_helper.enrich_vulns_with_tags`
  for the exact parse). `vulns_df` has `asset_uuid`.
- Approach: parse the Owner-category value per asset from `assets_df["tags"]`, build an
  `asset_uuid -> owner_value` map, join onto vulns via `asset_uuid`. Assets with no
  Owner tag → bucket labelled `"(Unassigned)"`.
- Owner category name is configurable via a module option `owner_category`
  (default `"Owner"`). Multiple values in the category → join with `" | "` (match
  enrich_vulns_with_tags behaviour) or take first; pick the simplest that is correct.
- This keeps the change surgical: ZERO edits to `composed_report.py` or the composer.

### RAG thresholds (per owner + overall strip)
- Per-owner RAG on overdue Crit+High count, thresholds configurable via options,
  sensible defaults: green = 0, amber = 1–4, red ≥ 5. Use
  `reports/modules/rag_utils.py` (`rag_status_from_value` / `build_rag_strip_entry`,
  `STATUS_COLOR`, `STATUS_LABEL`, `NO_DATA_*`).
- Cover-page RAG strip headline = total overdue Crit+High across all in-scope owners;
  strip status = worst per-owner status (red if any owner red, else amber if any amber,
  else green); `"no_data"` when zero findings in scope.

### Channels (four-channel contract)
- Implement `render_pdf_section`, `render_excel_tabs`, `render_email_panel`,
  `render_analyst_tabs`, `render_rag_strip_entry` (via ModuleData.rag_strip), following
  `vuln_type_distribution_module.py` and `tag_severity_share_module.py` as the pattern
  references (same file, same imports, same empty-data discipline).
- Table shape (PDF/Excel/email): `Owner | Overdue Critical | Overdue High | Total | RAG`,
  sorted by Total desc. Analyst tabs = per-finding drill-down (owner + overdue days +
  severity + plugin), following the existing `analyst_rows` pattern.

### Empty-data guard (HARD requirement)
- Use `safe_pct` / `safe_int` / `safe_format` for any possibly-None value; never inline
  f-string format specs on None. Return `self._empty_result(...)` on zero-row / error.
- Filtered-to-zero owner groups are a regular occurrence and MUST NOT crash.

</decisions>

<specifics>
## Specific Ideas

- Module id: `tech_debt_by_owner`; DISPLAY_NAME: `"Tech Debt by Owner"`; file:
  `reports/modules/tech_debt_by_owner_module.py`; REQUIRED_DATA: `["vulns", "assets"]`.
- Unit tests: `tests/test_tech_debt_by_owner_module.py` (flat tests/ dir convention),
  mirroring `tests/test_accepted_recast_module.py`. Cover: owner parse/join,
  overdue Crit/High counting, RAG threshold buckets, `"(Unassigned)"` bucket, and the
  zero-row empty-data guard.
- No `run_all.py` change and no `CLAUDE.md` slug change — this is a MODULE, not a
  top-level report slug. It becomes usable when a group lists it under
  `composed_report` `modules:` in `delivery_config.yaml`.

</specifics>

<canonical_refs>
## Canonical References

- `reports/modules/vuln_type_distribution_module.py` — closest structural analog
  (classifier + within-tag counts + four channels + empty-data guard).
- `reports/modules/tag_severity_share_module.py` — tag/severity + RAG strip pattern.
- `utils/sla_calculator.py::get_sla_status` — overdue determination.
- `utils/tag_helper.py::enrich_vulns_with_tags` — canonical tag-string parse to copy.
- `config.py` — `SLA_DAYS`, VPR→severity mapping.
- CLAUDE.md → "Board-Style Reports — Module Infrastructure" (four-channel contract,
  empty-data guard) and "Adding a new module to an existing composed report".

</canonical_refs>
