# Design — Tag-vs-Environment Severity Share & Vuln-Type Profile

**Date:** 2026-06-08
**Status:** Approved (brainstorming complete; routes to `/gsd-quick` for build)
**Author:** Justin Monroe (with Claude)

## Problem

For a **selected Tenable tag**, leadership wants two breakdowns in one report:

1. **VPR severity distribution** — Critical / High / Medium / Low / **None** — where each
   severity is expressed as a **percentage of the total number of vulnerabilities in the
   entire environment** (the tag's count at each severity ÷ the environment grand total).
   The rows therefore sum to the tag's overall share of the environment.
2. **CPE type distribution** — Application / Operating System / Hardware / Other — scoped to
   the **same selected tag** (count + % within the tag).

## Confirmed decisions

| # | Decision | Confirmed |
|---|----------|-----------|
| D1 | **Denominator** = tag's count at each severity ÷ **environment grand total** (all severities, all assets). Rows sum to the tag's share of the environment. | ✅ |
| D2 | **"None" severity** = `vpr_score` is null/blank **or** `== 0` (matches Tenable GUI "None"). | ✅ |
| D3 | **No native-severity fallback** in this report. Severity is derived purely from `vpr_score`; a null/0 VPR lands in **None** regardless of native severity. *(Deliberate, documented divergence from the spike's `vpr_to_severity(..., fallback=native)` convention.)* | ✅ |
| D4 | **CPE classifier** = proven VTD-01 family-override rule: `plugin_family` override (Linux distros, MS Bulletins → OS) **first**, then CPE part-letter `a/o/h`, else **Other**. | ✅ |
| D5 | **CPE breakdown is within-tag only** (count + % of the tag), not vs-environment. | ✅ |
| D6 | **Current-snapshot semantics** — `state in {open, reopened}`, no as-of-past-date. The reopened-aware historical predicate is **not** needed here. | ✅ |
| D7 | **No-tag run is degenerate, not an error** — tag = environment ⇒ severity shares become the environment's own distribution (sum to 100%). | ✅ |
| D8 | **Info-native findings are intentionally excluded** (the fetcher already drops them; they are Tenable's internal derivation noise with no bearing on totals). The None bucket therefore contains only **non-info findings lacking a VPR**. No fetcher change. | ✅ |
| D9 | The global change to `config.vpr_to_severity` (0/null → None **everywhere**) is **decoupled** and captured for a separate GSD pass. This report is immune to it (reads raw `vpr_score`). | ✅ |

## Approach

Two new auto-discovered metric modules delivered via the existing generic `composed_report`
slug + a YAML group. No new top-level report slug. The only change outside the modules is a
small, **gated** addition to `composed_report.py` to forward the environment grand total —
mirroring exactly how `fixed_vulns_df` is already threaded to `critical_remediation_sla`.

### Module 1 — `tag_severity_share` ("Tag Severity Share vs Environment")

**File:** `reports/modules/tag_severity_share_module.py`

`compute(vulns_df, assets_df, report_date, config, **kwargs)`:
- `vulns_df` arrives **tag-filtered** (composer applies the tag filter). Restrict to open states
  (`state in {open, reopened}`).
- Derive a **report-local VPR-pure severity** with an explicit None bucket (no native fallback):

  | Bucket | Rule (`vpr_score`) |
  |--------|--------------------|
  | None | null/NaN **or** `== 0` |
  | Low | 0.1 – 3.9 |
  | Medium | 4.0 – 6.9 |
  | High | 7.0 – 8.9 |
  | Critical | 9.0 – 10.0 |

- Read `env_vuln_total: int` from `**kwargs` (the **unfiltered** environment open-finding count).
- For each severity: `pct = tag_count[sev] / env_vuln_total` (guard divide-by-zero → 0.0).
- `metrics`: per-severity count + pct, `tag_total`, `env_vuln_total`, `tag_share_pct`
  (= tag_total / env_vuln_total).
- Populate `driver_narrative`, `rag_strip` (headline = tag's share of env), and `analyst_rows`
  (flat tag findings) per the four-channel contract.

**Renders:** `render_pdf_section` (table: Severity · Tag Count · % of Env Total, + tag-share
footer), `render_excel_tabs` (one tab, same columns), `render_email_panel` (inline-CSS panel),
`render_rag_strip_entry`, `render_analyst_tabs`. All numeric interpolation uses
`safe_pct` / `safe_int` / `safe_format`.

### Module 2 — `vuln_type_distribution` ("Vulnerability Type Distribution")

**File:** `reports/modules/vuln_type_distribution_module.py`

`compute(...)`:
- Operates on the tag-filtered open `vulns_df`.
- Classify each finding via the VTD-01 family-override classifier:
  ```
  classify(plugin_family, cpe):
    if plugin_family matches OS distro/bulletin regex -> "OS"
    elif cpe part 'a' -> "Application"
    elif cpe part 'o' -> "OS"
    elif cpe part 'h' -> "Hardware"
    else -> "Other"
  ```
  Config-driven `OS_FAMILY` regex + Microsoft-Bulletins → OS default.
- `metrics`: count + % **within the tag** for Application / OS / Hardware / Other.

**Renders:** PDF section, Excel tab, email panel, RAG strip, analyst tab.
**Hardware tile/row hidden when its count is 0** (per spike — Hardware ≈ 0 in real data).

### `composed_report.py` change (gated, ~8 lines)

Before the tag filter (currently composed_report.py:199):
```python
_OPEN = vulns_df["state"].str.lower().isin({"open", "reopened"})
env_vuln_total = int(_OPEN.sum())   # environment grand total, pre-filter
```
Add `_MODULES_NEEDING_ENV_TOTAL = frozenset({"tag_severity_share"})`; when intersecting the
requested `modules`, set `composer_kwargs["env_vuln_total"] = env_vuln_total`. `ReportComposer`
already forwards `**self._kwargs` to every `compute()` (composer.py:562), and every `compute()`
absorbs unknown kwargs via `**kwargs` — identical safety profile to `fixed_vulns_df`. No other
module is affected.

### YAML to drive it

```yaml
groups:
  - name: "..."
    schedule: { frequency: on_demand }
    filters: { tag_category: "Environment", tag_value: "Production" }
    reports: [composed_report]
    modules:  [tag_severity_share, vuln_type_distribution]
    email: { ... }
```

CLI smoke test:
```
python reports/composed_report.py \
  --modules tag_severity_share,vuln_type_distribution \
  --tag-category Environment --tag-value Production
```

## Testing

- **Unit — VPR→bucket mapper:** Critical/High/Medium/Low boundaries + None edge cases
  (`None`, `NaN`, `0.0`, `""`). No native fallback path.
- **Unit — family-override classifier:** labelled samples incl. Linux "Local Security Checks"
  (→ OS despite `cpe:/a`), Microsoft Bulletins (→ OS), third-party "Windows" family apps
  (→ Application), missing/unparseable CPE (→ Other). (Spike requires the classifier be tested.)
- **Unit — env-share math:** `tag_count / env_vuln_total`, divide-by-zero guard, rows sum to
  `tag_share_pct`.
- **Empty-data:** zero-row tag scope renders without crashing (gray RAG cell, "No data in
  scope." driver), per the CLAUDE.md empty-data guard.

## Docs (runbooks)

- `docs/vuln_type_distribution_calculations.md` — required by the spike for the VTD-01
  classifier (coverage %, family-override rationale, the ~6% OS/App swing).
- `docs/tag_severity_share_calculations.md` — denominator definition, the None=0/null bucket,
  and the **intentional no-native-fallback divergence** (D3) so auditors don't read it as a bug.

## Out of scope / captured for later

- **Global `vpr_to_severity` change (0/null → None everywhere).** Decoupled per D9. Captured as
  a ROADMAP backlog item. Requires: a `none` tier across `SLA_DAYS` / `SEVERITY_ORDER` /
  `SEVERITY_COLORS` / `SEVERITY_LABELS` / `SEVERITY_FILL_COLORS` / `RISK_WEIGHTS`; a decision on
  the fetcher `severity == "info"` exclusion vs a new None policy; the demotion question
  (native-severe but VPR-less findings → None); coordinated updates across ~8 consuming
  reports/modules; and a `tests/content/test_values.py` rebaseline.
- **Full VTD-01 scope** (Crit+High only, three owning-team RAG tiles, month-over-month delta
  arrows) remains the roadmap VTD-01 item. This report delivers the **classifier** and a
  current-snapshot, all-severity, within-tag distribution — a first realization of the shared
  classifier, not the full trend-aware three-tile module.

## Relationship to existing code

- Reuses the `composed_report` + `ReportComposer` + four-channel module contract verbatim.
- `tag_severity_share` is adjacent to `total_vulns_by_severity_module.py` but differs in two
  ways: (a) denominator = environment grand total (not within-set), (b) VPR-pure severity with a
  None bucket and no native fallback.
- `vuln_type_distribution` is the first shipped consumer of the spike's CPE family-override
  classifier.
