---
phase: 03-board-summary-module-migration
reviewed: 2026-05-06T21:15:00Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - CLAUDE.md
  - delivery/email_sender.py
  - reports/board_summary.py
  - reports/modules/__init__.py
  - reports/modules/aged_vulns_assets_module.py
  - reports/modules/board_report_utils.py
  - reports/modules/composer.py
  - reports/modules/critical_remediation_sla_module.py
  - reports/modules/high_risk_assets_module.py
  - reports/modules/scan_coverage_sla_module.py
  - scripts/smoke_email_phase2.py
  - tests/test_phase2_composer_pipeline.py
findings:
  critical: 1
  warning: 8
  info: 6
  total: 15
status: issues_found
---

# Phase 3: Code Review Report

**Reviewed:** 2026-05-06T21:15:00Z
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

The Phase 3 board-summary module migration looks structurally sound on first pass —
all four metric modules consistently populate the new contract fields
(`driver_narrative`, `analyst_rows`, `metadata['email_gauge_b64']`, `rag_strip`),
the composer's bundle pipeline routes them through the right channels, and the
email sender's bundle-driven dispatch is correctly slug-allowlist-free.

That said, adversarial review surfaced a **BLOCKER**: the within-SLA per-BU
breakdown in `critical_remediation_sla_module._compute_bu_breakdown()` realigns
the index of the mask after a `.copy()` in `compute()`, leaving the BU
breakdown silently miscounted on production data. There are also several
WARNING-level correctness/robustness defects — most notably the BU
within-SLA mask mis-alignment, an analyst-rows leak of accepted/recasted
findings, an inline-image budget that ignores the per-image cap leaving the
first oversize image in, a Phase-3 bundle-key drift between
`board_summary.run_report` and the `email_inline_images` slot, and several
silent fall-throughs around the analyst workbook contract.

## BLOCKER Issues

### CR-01: BLOCKER — `_compute_bu_breakdown` silently mis-counts within-SLA per BU

**File:** `reports/modules/critical_remediation_sla_module.py:1032-1067`

**Issue:** `_compute_bu_breakdown()` is called with `within_sla_mask` computed
against the original `fixed_in_window` index (built at line 257-260). Inside the
helper, `fw = fixed_in_window.copy()` (line 1056) preserves the index — that is
fine. But then `fw.loc[:, "business_unit"] = fw["asset_uuid"].map(...).fillna("Untagged")`
runs after `compute_per_bu_breakdown()` is called with **the unmodified
`within_sla_mask`** that was originally aligned to `fixed_in_window.index`.

That alignment is preserved if and only if `fixed_in_window` is never
reindexed/reset. But upstream, `fixed_in_window = fixed_crit_all[fixed_mask].copy()`
(line 237) — pandas' boolean filter preserves the original index of
`fixed_crit_all`, which itself is `df[mask].copy()` (line 1000 in
`_filter_critical`) — also unreset. By contrast, the BU breakdown's
`compute_per_bu_breakdown()` REQUIRES masks to be re-indexable to
`df_local.index` (board_report_utils.py:351-360). The current call:

```python
return compute_per_bu_breakdown(fw, within_sla_mask, denom_mask, higher_is_better=True)
```

passes `denom_mask = pd.Series(True, index=fw.index)` — but `within_sla_mask`
was constructed against `fixed_in_window.index`, not `fw.index`. Since
`fw = fixed_in_window.copy()`, today the indices match — but **only because nothing reset
the index in between**. Any future caller that touches `fixed_in_window` (e.g.
calling `.reset_index(drop=True)` for downstream display) will silently make the
mask un-alignable, and `compute_per_bu_breakdown.reindex(...).fill_value=False`
will replace every `True` with `False`, producing a `0%` SLA for every BU
without raising.

This is exactly the silent-data-loss class CLAUDE.md flags as a hard correctness
bar (the `compute_per_bu_breakdown` docstring even calls out the
"masks ... re-indexed defensively" pattern). It also conflicts with the
per-finding analyst tab path at lines 298-323, which DOES `.copy()` the
`fixed_in_window` and would be a likely place a future contributor would add
`.reset_index(drop=True)`.

**Fix:** Compute `within_sla_mask` directly from the values inside
`_compute_bu_breakdown` so the helper owns its own index alignment, OR pass
the mask aligned to `fw.index` explicitly:

```python
def _compute_bu_breakdown(fixed_in_window, on_time_assets, within_sla_mask):
    if fixed_in_window.empty:
        return pd.DataFrame(columns=[...])
    fw = fixed_in_window.copy()
    enriched_assets = extract_business_unit(on_time_assets)
    uuid_to_bu      = dict(zip(enriched_assets["asset_uuid"], enriched_assets["business_unit"]))
    fw.loc[:, "business_unit"] = fw["asset_uuid"].map(uuid_to_bu).fillna("Untagged")

    # Realign mask to fw's index — defensive guard against future
    # reset_index() calls on fixed_in_window in compute().
    if within_sla_mask is None:
        within_sla_mask = pd.Series(False, index=fw.index)
    else:
        within_sla_mask = within_sla_mask.reindex(fw.index, fill_value=False)
    denom_mask = pd.Series(True, index=fw.index)
    return compute_per_bu_breakdown(fw, within_sla_mask, denom_mask, higher_is_better=True)
```

---

## WARNING Issues

### WR-01: WARNING — Bundle-key drift: `board_summary.run_report` returns `metrics["kpis"]`, but Phase-2 docs expected `email_kpis` rebrand

**File:** `reports/board_summary.py:289-305`

**Issue:** The bundle returned by `composer.run_full_pipeline()` exposes
`bundle["email_kpis"]` (composer.py:1573, 1616). `run_report` reads it via
`kpis = bundle["email_kpis"]` (line 251) and surfaces it as
`"metrics": {"kpis": kpis, ...}` (line 294). However, the docstring at
line 122-133 advertises the same dict but with a separate `email_kpis`
field at the bundle-shape level. Downstream consumers (e.g. delivery/email_sender.py
which scans `report_outputs[*]["email_kpis"]` via `collect_email_kpis()`) cannot
find this dict. The KPI tile-priority rule documented in CLAUDE.md
("`ops_remediation`'s pre-built `kpi_tiles` from `metrics` are used directly
and take priority over the generic tile logic") is also bypassed — the
`board_summary` bundle never re-publishes `email_kpis` at the report-output
level, so any email_template flow that wants a fallback KPI strip pulls
nothing.

This is a Phase-2-rolled-forward defect (D-23 says legacy KPI channel must be
preserved); the Phase-3 PR did not add the missing top-level key.

**Fix:** Add the legacy KPI field to the report return dict so consumers like
the email template can find it:

```python
return {
    "pdf":              pdf_path,
    "excel":            excel_path,
    "charts":           [],
    "metrics":          {...},
    "analyst_excel":    bundle["analyst_workbook_path"],
    "email_body_html":  bundle["email_body_html"],
    "email_inline_images": bundle.get("email_inline_images", []),
    "email_kpis":       kpis,                 # <-- ADD: surfaces D-23 legacy
}
```

### WR-02: WARNING — Inline-image cumulative budget keeps the first oversize image instead of dropping it

**File:** `delivery/email_sender.py:511-555`

**Issue:** The CID inline-image decode loop accumulates total decoded bytes in
`_inline_total += len(_img_data)` (line 542) **before** checking the budget
(line 543-550). If the first decoded image is larger than `_INLINE_BUDGET_BYTES`
(5 MB), the budget exceeds, the warning fires, the loop breaks — but the
`related.attach(_img)` at line 554 was placed AFTER the break, so this image
is *not* attached, which is good. However the bookkeeping is asymmetric: when
the second image takes total over 5MB, the second image is correctly dropped
but the FIRST image's bytes have already been attached. The budget is meant to
be an upper bound on what gets sent; the first 5MB+ image violates it.

A more subtle issue: the `_inline_total += len(_img_data)` is incremented
**before** the budget check, so a single 10MB image makes `_inline_total=10MB`
and the warning still says "exceeded" — but no image is attached, which fails
silently for the only image the sender expected. This means a single oversize
inline gauge from any future high-resolution module (e.g. Plotly png at print
DPI) silently drops the entire CID strip with no preserved fallback. The PDF
gauge inside the report attachments still works, but the email panel
references `cid:{module_id}_gauge` and the inline image is missing — Outlook
shows a broken-image icon.

**Fix:** Move the budget check before the size accumulation, validate the
size of THIS image first, AND add a `MIMEImage` attach only on success:

```python
candidate_size = len(_img_data)
if _inline_total + candidate_size > _INLINE_BUDGET_BYTES:
    logger.warning(
        "[%s] Inline-image cumulative size would exceed %d bytes — "
        "dropping cid=%s and remaining inline images.",
        group_name, _INLINE_BUDGET_BYTES, _cid,
    )
    _budget_exceeded = True
    break
_inline_total += candidate_size
_img = MIMEImage(_img_data, _subtype="png")
_img.add_header("Content-ID", f"<{_cid}>")
_img.add_header("Content-Disposition", "inline", filename=f"{_cid}.png")
related.attach(_img)
```

Also add a guard for individual-image size (e.g. `> 2 MB`) so a single
pathologically large image doesn't burn the entire budget on its own.

### WR-03: WARNING — Analyst-tabs leaks accepted / recasted findings into the Critical Remediation drill-down

**File:** `reports/modules/critical_remediation_sla_module.py:298-323`

**Issue:** The "Critical Remediation Detail" analyst tab is sourced from
`fixed_in_window[fixed_in_window["days_to_fix"] > _CRITICAL_SLA_DAYS]`. It
projects only severity == critical findings (per `_filter_critical`), but
this slice does NOT filter out findings that were **closed via accepted /
recasted** rules (`severity_modification_type` from the vuln export).
`fetch_fixed_vulnerabilities()` returns the FIXED population — but Tenable
includes accepted/recasted findings in the fixed cohort when the rule's
state changes. These are not "missed SLA" — they are risk-managed
findings, and surfacing them as "missed Critical SLA" misleads operators.

The same defect exists for the email-panel driver narrative
(`{missed_count} critical findings missed SLA.`). The number is inflated by
risk-managed records.

This isn't a regression introduced by Phase 3 directly — but Phase 3 is the
first time the module surfaces a per-finding drill-down, where the issue
becomes operationally visible.

**Fix:** Drop accepted/recasted rows from the missed-SLA slice:

```python
missed = fixed_in_window[fixed_in_window["days_to_fix"] > _CRITICAL_SLA_DAYS].copy()
if "severity_modification_type" in missed.columns:
    smod = missed["severity_modification_type"].astype("string").str.lower()
    missed = missed[~smod.isin(["accepted", "recasted"])].copy()
```

Confirm with the calculations runbook (`docs/board_summary_calculations.md`)
whether risk-managed findings should be included or excluded — this review
assumes the operator-facing drill-down should NOT include them.

### WR-04: WARNING — Per-module `_STATUS_COLOR["yellow"]` is `#f57c00` but the gauge threshold uses `#fbc02d` — drift between status badge and gauge fills

**File:** `reports/modules/scan_coverage_sla_module.py:67-86`,
`reports/modules/critical_remediation_sla_module.py:81-100`,
`reports/modules/high_risk_assets_module.py:77-96`,
`reports/modules/aged_vulns_assets_module.py:77-95`

**Issue:** Each migrated module has TWO yellow hexes:
- `_GAUGE_THRESHOLDS` uses `#fbc02d` (legacy palette from chart_exporter.py).
- `_STATUS_COLOR["yellow"]` uses `#f57c00`.

The composer's RAG strip color whitelist (`_palette_lc` in composer.py:841)
permits only `STATUS_COLOR.values()` from `rag_utils.py`. Since the modules
build their `rag_strip` payload via `build_rag_strip_entry()` which uses
`STATUS_COLOR["yellow"]="#f57c00"`, the strip gets `#f57c00` and passes the
whitelist. But the PDF status badge inside `render_pdf_section()` uses
`_STATUS_COLOR.get(status,...)` which is also `#f57c00`. So the gauge band
and the status badge disagree visibly: the gauge dial points at amber
`#fbc02d` (warm yellow) but the chip below says `#f57c00` (orange). The PDF
will look mismatched — auditable but unprofessional. Email panel uses the
RAG palette `_RAG_STATUS_COLOR["yellow"]="#f57c00"`, so the email and PDF
agree, but the gauge inside the email panel is generated from
`_GAUGE_THRESHOLDS` and shows `#fbc02d`.

**Fix:** Pick one. Either rebrand `_STATUS_COLOR["yellow"]` to `#fbc02d`
across all four modules (matches gauge), or rebrand the gauge thresholds to
`#f57c00` (matches RAG/status badge). The latter is consistent with the
existing `chart_exporter.py` "Medium = `#fbc02d`" convention noted in
CLAUDE.md, so likely the cheapest fix is to pull `_STATUS_COLOR` from
`rag_utils.STATUS_COLOR` everywhere and accept the existing color drift as
a project-wide rebrand decision.

### WR-05: WARNING — `_unique_sheet_name` race window: `used_names` is updated AFTER `collected.append`, but `used` set is mutated inside the call — collision logic correct, but caller mutation pattern is fragile

**File:** `reports/modules/composer.py:1110-1127`

**Issue:** Inside `assemble_analyst_workbook`:

```python
try:
    unique = _unique_sheet_name(sheet_name, used_names)
except ValueError as exc:
    ...
used_names.add(unique)
collected.append((unique, df))
```

The pattern is right, but `_unique_sheet_name` itself does NOT add to
`used_names`. The caller's responsibility to call `used_names.add(unique)`
is documented in the helper docstring. However, if the helper is later
refactored to internally mutate the set (a natural simplification), this
two-step sequence will silently double-count. Convention drift here is
also visible — the docstring says
"caller is expected to add the returned name to used", which is awkward
API design for a helper that already takes a mutable set parameter.

Also, the helper's collision range is `range(2, 100)` — exclusive at 100 —
so the helper actually allows suffixes `_2 ... _99`, and the docstring's
"99 attempts" is correct, but the message
`"after 99 attempts"` is off by one (98 attempts: 2 through 99 inclusive).

**Fix:** Move the mutation into `_unique_sheet_name` so callers cannot get
the order wrong:

```python
def _unique_sheet_name(name: str, used: set[str]) -> str:
    base = name[:31]
    if base not in used:
        used.add(base)
        return base
    for i in range(2, 100):
        ...
        if candidate not in used:
            used.add(candidate)
            return candidate
    raise ValueError(...)
```

And update the docstring + remove the manual `used_names.add(unique)` at
the call site.

### WR-06: WARNING — `aged_vulns_assets_module._find_aged_assets` returns the FILTERED `aged` frame, but the `compute_bu_risk_scores` uses `vulns_df` (UNFILTERED) — risk-score over-counts non-aged findings on aged assets

**File:** `reports/modules/aged_vulns_assets_module.py:248-255` and
`reports/modules/board_report_utils.py:407-471`

**Issue:** In `aged_vulns_assets_module.compute()` step 5a:

```python
bu_risk = compute_bu_risk_scores(
    vulns_df         = vulns_df,           # <-- ALL open findings, not just aged
    qualifying_uuids = aged_uuids,
    ...
    severities       = frozenset({"critical", "high", "medium"}),
    weights          = RISK_WEIGHTS,
)
```

`compute_bu_risk_scores()` then weights `severity` per finding **on every
open finding for the qualifying asset**, not just the aged-finding subset.
The docstring at board_report_utils.py:418-419 calls this out explicitly:
"using all open findings on that asset (not only the aged/filtered
findings that caused the asset to qualify)".

This is intentional per docstring — but the same intent does not match
HighRiskAssetsModule's behavior, where `aged_findings` (the
`relevant[aged_mask]` subset) is also returned but `vulns_df` is passed
to `compute_bu_risk_scores` (high_risk_assets_module.py:253-259).

Both modules use the same `vulns_df` by design — but this is risk
*intent* drift between the helper docstring and the module-level
calculations runbook. If the runbook says "Risk Score = sum of weighted
aged Crit/High findings" then the helper is wrong; if it says "any open
weighted findings on a high-risk asset", the helper is right.

This needs spec confirmation before either side is patched. The
consequence today is that BU sort order and the displayed Risk Score
column include MEDIUM and unaged findings — that may be intentional
(holistic asset risk) or an off-by-population bug.

**Fix:** Verify the intended semantics against
`docs/board_summary_calculations.md` and either narrow the
`vulns_df` argument to the aged subset OR document the intentional
broadening in the module docstring + runbook + audit_info().

### WR-07: WARNING — `safe_pct(scan_coverage_pct)` does not protect the `f"{scan_coverage_pct:.1f}%"` summary text in the same module

**File:** `reports/modules/scan_coverage_sla_module.py:325-332`

**Issue:** `compute()` correctly guards `scan_coverage_pct` with
`if scan_coverage_pct is None:` early return, but in the success branch the
narrative summary still does:

```python
summary_text = (
    f"Scan coverage is {scan_coverage_pct:.1f}% — "  # safe per inline comment
    f"{scanned_on_time:,} of {total_licensed:,} licensed assets ..."
)
```

The CLAUDE.md "Empty-data guard pattern" rule explicitly forbids inline
f-string format specs on **possibly**-None values, even where guarded —
because future refactors break the guard. Identical lint surface exists
in `aged_vulns_assets_module._build_summary` line 1080 and
`high_risk_assets_module._build_summary` line 1061 (both guarded by
`if ... is None: return ...` early returns). The inline comments
`# safe: ...` are documenting the guard, but that is exactly the
maintainability hole CLAUDE.md is designed to close.

**Fix:** Use `safe_pct` everywhere — including in the summary helpers
themselves — to make the rule mechanical rather than conditional:

```python
return (
    f"Scan coverage is {safe_pct(scan_coverage_pct)} — "
    ...
)
```

The diff is two characters per call site and the entire class of
"future refactor breaks guard" is gone.

### WR-08: WARNING — `_filter_assets_by_tag` returns the unfiltered DataFrame on missing column, silently disabling tag scoping

**File:** `reports/board_summary.py:312-361`

**Issue:** When the configured tag column (`tags`) is absent from the
deduplicated assets DataFrame, the helper falls through to "return the
full (unfiltered) DataFrame ... with a warning logged". This means a
caller running `board_summary --tag-category "Environment" --tag-value "Production"`
gets a board for ALL assets if the tags column is missing, with only a
WARNING line in the log. Operationally that is identical to a tag-mismatch
producing a "filtered to zero" report — but with the opposite financial
risk: a board scoped to Production accidentally shows the entire fleet,
which an executive might read as "Production = 12k assets" when production
is actually 800.

This is also incompatible with CLAUDE.md's "Fail-soft batch semantics" —
fail-soft is about NOT crashing the batch; it is NOT about silently
mis-scoping a single report. The batch should fail this report (set
`error` in metrics, render a clear "no data — tag column missing" cell)
instead of silently widening scope.

**Fix:** Return an empty DataFrame instead, OR raise a clearly-typed
`MisconfiguredScope` error caught at `run_group()` and surfaced as the
report's `error`:

```python
if col not in assets_df.columns:
    logger.error(
        "_filter_assets_by_tag: tags column %r absent — "
        "returning EMPTY DataFrame so the report renders 'no data in scope' "
        "rather than silently widening to all assets.",
        col,
    )
    return assets_df.iloc[0:0].copy().reset_index(drop=True)
```

---

## Info

### IN-01: INFO — `aged_vulns_assets_module._row_bg` and `_xl_fill` are dead helpers

**File:** `reports/modules/aged_vulns_assets_module.py:1087-1102`

The `_row_bg` and `_xl_fill` functions are defined but never referenced —
neither `render_pdf_section()` nor `render_excel_tabs()` calls them. The
PDF section uses inline percent + `_STATUS_COLOR.get(...)` instead, and
the Excel tab does NOT use percentage-band fills at all (column 4 is
the integer Risk Score, not a percentage). Same dead-code pattern in
`high_risk_assets_module.py:1069-1084`. This is leftover from the
critical_remediation_sla pattern that was copy-pasted then partially
adapted.

**Fix:** Delete `_row_bg` and `_xl_fill` from both lower-is-better
modules to reduce maintenance surface; or wire them into the BU table
to colour-code the risk score band.

### IN-02: INFO — `_smtp_cfg()` docstring says "read once at module load time" but it's actually invoked per-call

**File:** `delivery/email_sender.py:72-85`

The header comment block says `# SMTP configuration — read once at module load time`,
but `_smtp_cfg()` is a function that re-reads `os.getenv(...)` on every
call inside `send_report_email()` (line 469). This is actually the
desired behavior (test runs `monkeypatch.setenv(...)` between calls and
expect to see the new values), but the comment is stale and misleading
to future readers.

**Fix:** Update the comment to match the function semantics, e.g.
`# SMTP configuration — read on each send_report_email() call so test
# overrides via monkeypatch.setenv work.`

### IN-03: INFO — `assemble_pdf` builds `module_list_str` from `d.display_name` without HTML-escaping, but composer escapes it later — defensive escape happens in only one direction

**File:** `reports/modules/composer.py:674`

The `module_list_str = ", ".join(d.display_name for d in results)` line
joins arbitrary display names without escaping. The composer then
escapes via `html.escape(str(module_list_str), quote=True)` at line 870,
which IS correct. But future refactor that bypasses `_PDF_UNIFIED_COVER_TEMPLATE.format(module_list=...)`
and writes `module_list_str` to HTML directly will inject. Defense in
depth: escape at construction time too, or use a typed wrapper.

**Fix:** Either keep current single-escape pattern (it's correct, just
fragile) and add a comment, or wrap names in `html.escape` at
construction. The current code is correct — this is an architectural
note.

### IN-04: INFO — `_extract_owner_tag` only matches exactly `"owner"` (case-insensitive); does not match `"Owner Group"` or `"Operations Owner"`

**File:** `reports/modules/critical_remediation_sla_module.py:962-977`

The Owner-tag extractor short-circuits on `cat.strip().lower() == "owner"`.
If the org uses tag categories like `"Owner Group"`, `"Operations Owner"`,
or `"Asset Owner"`, the analyst tab will get an empty `owner_tag` for
every row. CLAUDE.md says tag categories are dynamic — this hard-coded
match is a footgun.

**Fix:** Either parameterize via `config.options` (e.g.
`config.options.get("owner_tag_category", "Owner")`), or use a regex
match with priority order so `"Asset Owner"` resolves before `"Owner"`.

### IN-05: INFO — Smoke script log emoji-style header text uses Unicode arrow `▲` `●` `▼` `○` — Outlook may render placeholders

**File:** `reports/modules/rag_utils.py:64-69`

The cover-page strip and email panel emit raw unicode triangles. CLAUDE.md
says "Only use emojis if the user explicitly requests it" — these are
shape glyphs, not emoji, but Outlook (especially older versions on
Windows 10) does not always render `U+25B2` etc. without the system's
DejaVu fonts installed. The visual fallback is correct (color-blind
readers still see the RAG color), but on a corporate fleet running
Outlook 2016 these may show as `□` boxes.

**Fix:** Either accept the risk (shape is decorative), use SVG inline
images, or substitute `↑ ▼ ●` with text-only labels for email and keep
the shapes for PDF only.

### IN-06: INFO — `assemble_email_body` per-module exception placeholder uses `border:1px solid #d32f2f; background:#FFF3CD` — the colour combination is amber-on-red, which fails WCAG AA contrast for the dark amber border on light yellow background

**File:** `reports/modules/composer.py:1298-1306`

Cosmetic but worth noting: the placeholder `<div>` uses red border on a
light yellow background. The text color `#5D4037` (dark brown) on
`#FFF3CD` (cream) is fine, but the `1px solid #d32f2f` border color is
visually disconnected from the body. Also the colour combination is
identical to the PDF `error-box` class but rendered with inline CSS
(no `border-radius`), so the email and PDF error placeholders look
slightly different.

**Fix:** Match the PDF `.error-box` styling exactly (use the same
`border-left: 4pt solid #e65100;` accent), or pick a single error-state
palette and document it in the email template guide.

---

_Reviewed: 2026-05-06T21:15:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
