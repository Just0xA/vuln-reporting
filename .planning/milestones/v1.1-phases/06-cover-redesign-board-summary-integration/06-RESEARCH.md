# Phase 6 — Cover Redesign + Board Summary Integration — RESEARCH

**Researched:** 2026-05-13
**Domain:** WeasyPrint @page CSS integration, Python kwarg compat-routing, structural-baseline impact analysis
**Confidence:** HIGH (all claims sourced from in-tree files)

---

## User Constraints (from CONTEXT.md)

### Locked Decisions

- D-01 — Cover body: scope subtitle + RAG strip only. Strip the inline cover-title p, Generated line, Sections line, cover-divider hr, and cover-meta wrapper. Preserve rag-strip verbatim.
- D-02 — Chrome header subtitle = value-only scope string. Formatter: tag_value if (tag_category and tag_value) else "All assets". Same string in cover body subtitle AND PdfChromeConfig.subtitle.
- D-03 — LOGO_PATH stays None at v1.1 ship. No default logo committed.
- D-04 — Cutover baseline regen = wipe + regenerate + operator visual UAT.
- D-05 — Privacy-label threading: ReportComposer.__init__ gains pdf_chrome PdfChromeConfig kwarg. board_summary.run_report gains privacy_label kwarg defaulting to Confidential. run_all.run_group resolves the default at call site and passes privacy_label only to compat-safe slugs.
- D-06 — Composer wire point: constructor parameter, not assemble_pdf parameter.

### Claude Discretion

- Chrome CSS in same style block vs second style block (Q1).
- Compat-safe kwarg passing: slug allowlist vs inspect.signature (Q2).
- Scope-subtitle formatter location.

### Deferred Ideas (OUT OF SCOPE)

- Committed default brand logo.
- Hero title repeat on cover body.
- Sections enumeration on cover.
- Per-slug capability flag for chrome opt-in (v2 work).
- Header text autoshift for light backgrounds.
- management_summary / ops_remediation migration to module contract (GEN-01/02).
- Extending the baseline-extractor for new chrome fields.
- _PDF_RAG_STRIP_TEMPLATE deprecated alias cleanup.

---

## Phase Requirements

| ID              | Description                                                                          | Research Support                                                                       |
|-----------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| CHROME-COV-01   | Cover preserves rag-strip block verbatim                                             | rag-strip independent of cover-meta wrapper (composer.py:386-391)                      |
| CHROME-COV-02   | Cover removes title/Generated/Sections/divider/cover-meta                            | Old structure at composer.py:377-393                                                   |
| CHROME-INT-01   | ReportComposer accepts pdf_chrome config; emits chrome CSS + header HTML             | _PDF_CSS at composer.py:70-375; assemble_pdf at composer.py:599-724                    |
| CHROME-INT-02   | board_summary.run_report builds PdfChromeConfig and passes to composer               | run_report at board_summary.py:82-151; composer call at board_summary.py:220-226       |
| CHROME-INT-03   | Cutover smoke baselines regenerated; 0 structural drift after re-baseline            | Baselines are structural-only — see Additional Finding 3                               |
| CHROME-COMPAT-01| management_summary / ops_remediation render paths unchanged                          | management_summary.py has own inline cover (line 1334); NOT via composer               |
| CHROME-COMPAT-02| Existing groups validate without privacy_label                                       | Already PASS in Phase 5 (schema field is optional)                                     |


---

## Summary

- Q1 (CSS injection): No @page conflict on @top-left, @bottom-left, @bottom-right (composer _PDF_CSS declares only @bottom-center). Chrome @bottom-center redeclares page-number with identical semantics. Recommendation: emit chrome CSS as a second style block appended after _PDF_CSS.
- Q2 (compat-safe kwargs): _REPORT_MODULE_MAP is dict[str, str] of dotted module paths loaded via importlib; board_summary.run_report is a plain def. Recommendation: one-line slug allowlist matching existing per-slug-extras pattern at run_all.py:672-695.
- Q3 (circular imports): reports/modules/pdf_chrome.py imports zero project modules and has no @register_module. Safe to import from composer.py. PASS.
- Q4 (smoke regen flag): Script has no --regenerate flag. Baselines auto-initialize on first run if missing (smoke_board_summary_cutover.py:248-254). Delete the 3 JSON files and re-run as-is.
- Surprise: Structural baselines capture only counts/keys/CIDs — NOT cover-page text. Cover redesign triggers zero structural drift if pdf_page_count and pdf_rag_cell_count stay constant. Operator visual UAT is the real correctness gate.

---

## Open Question Answers

### Q1 — @page block injection: single vs second style, conflict resolution

Evidence:

- Composer _PDF_CSS @page rule (composer.py:73-81): declares size A4 landscape; margin 15mm 12mm 18mm 12mm and @bottom-center with content Page counter(page) of counter(pages). Only @bottom-center claimed.
- Chrome @page rule (pdf_chrome.py:169-188): same size and margin, plus @top-left (chrome-header running element), @bottom-left (privacy label), @bottom-center (Page N of M — identical content), @bottom-right (generated_at), and @page :first @bottom-center empty.

Conflict map:

| Margin box       | Composer _PDF_CSS       | Chrome build_css             | Conflict? |
|------------------|-------------------------|------------------------------|-----------|
| size             | A4 landscape            | A4 landscape                 | No        |
| margin           | 15mm 12mm 18mm 12mm     | 15mm 12mm 18mm 12mm          | No        |
| @top-left        | unset                   | element(chrome-header)       | No        |
| @bottom-left     | unset                   | privacy_label literal        | No        |
| @bottom-center   | Page N of M             | Page N of M (same)           | Source-order cascade; same content |
| @bottom-right    | unset                   | generated_at literal         | No        |
| @page :first     | absent                  | suppresses @bottom-center    | No        |

Only @bottom-center overlaps, resolving to the same string. CSS Paged Media Level 3 cascade is source order for equal-specificity @page rules. Chrome CSS appended after _PDF_CSS makes chrome declaration win — required so @page :first properly suppresses page 1 counter.

Recommendation: Emit chrome CSS as a second style block appended after _PDF_CSS inside head. Matches design note at pdf_chrome.py:155-157.

Sketch — modify assemble_pdf at composer.py:710-724:

    chrome_style = f"<style>{self._pdf_chrome.build_css()}</style>" if self._pdf_chrome else ""
    # NEW: emit chrome_style after _PDF_CSS in the head, and call self._pdf_chrome.build_header_html() at body-top.
    # Both guarded by "if self._pdf_chrome".

build_footer_runners returns empty string in v1 (pdf_chrome.py:264-276) — inlining OK for API symmetry, no-op.

---

### Q2 — Compat-safe privacy_label kwarg passing

Evidence:

- _REPORT_MODULE_MAP is dict[str, str] — slug to dotted module path (run_all.py:104-110).
- Modules loaded lazily via importlib.import_module(module_path) at run_all.py:489-494.
- Runner calls report_module.run_report(tio, run_id, **report_kwargs) at run_all.py:696. No decorators, no partials.
- Existing slug-specific kwarg-extras pattern at run_all.py:672-695 (4 cases: vuln_export, board_summary, unscanned_assets, composed_report).
- board_summary.run_report is plain def, no decorator (board_summary.py:82).

Trade-offs:

| Approach                                | Pros                                                                 | Cons                                                  |
|-----------------------------------------|----------------------------------------------------------------------|-------------------------------------------------------|
| (a) Slug allowlist                      | One-line; matches existing pattern; explicit; zero overhead         | Hardcoded list; one new line per opt-in report        |
| (b) inspect.signature                   | Auto-generalizes — any report adding the kwarg opts in              | Subtle bugs if anyone wraps run_report later          |

Recommendation: (a) slug allowlist — append to existing block at run_all.py:676-682, adding "report_kwargs[privacy_label] = privacy_label" inside the if slug == board_summary branch. Resolve privacy_label alongside the tag filter at run_all.py:589-590 with "privacy_label = group_config.get(privacy_label, Confidential)".

Symmetric with tag resolution. v2 GEN-01/02 migrations get one more line each.

---

### Q3 — Circular import risk

Evidence:

- reports/modules/pdf_chrome.py imports only: __future__, html, logging, dataclasses.dataclass, datetime.{datetime, timezone}, pathlib.Path. Zero reports. imports.
- Not decorated with @register_module. Filename omits *_module.py suffix that registry.discover globs (pdf_chrome.py:14-17).
- composer.py already imports from reports.modules.base (line 54) and reports.modules.registry (line 55). Adding "from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig" is a sibling import — no new package boundary.

Verdict: PASS. No circular-import risk.

---

### Q4 — Baseline regen smoke script signature

Evidence (scripts/smoke_board_summary_cutover.py):

- Argparse declares only --group, --cache-date, --unredacted (lines 186-201). No --regenerate flag.
- Auto-initializes baselines on first run when file does not exist (lines 248-254): "if not baseline_file.exists(): write_baseline(...); print BASELINE INITIALIZED; continue".
- Header lines 10-15 explicitly: There is NO --update-baseline flag — baselines change ONLY when CODE intentionally changes the structure.

Recommendation: no script changes needed. Phase 6 workflow:

1. rm tests/baselines/board_summary_test_pull.json tests/baselines/board_summary_test_pull_analyst_off.json tests/baselines/board_summary_test_pull_zero_match.json
2. Warm cache: python run_all.py --group "Test Pull" --no-email
3. Run smoke: python scripts/smoke_board_summary_cutover.py — prints BASELINE INITIALIZED per group, exits 0.
4. Inspect the three regenerated JSONs, commit.
5. Operator opens output/.../board_summary.pdf and runs D-04 visual UAT.

A --regenerate flag would be speculative — rm baseline_file && python scripts/... already does that. CLAUDE.md section 2 Simplicity First.

---

## Additional Findings

### 1. WeasyPrint @page :first page-number suppression — verified by Phase 5

Phase 5 verified end-to-end (Phase 5 VERIFICATION row CHROME-FTR-03). The Layer-2 real-render test renders 2 pages via WeasyPrint; pypdf confirms page 1 does not contain "Page 1 of" while page 2 contains "Page 2 of 2". Pattern works because @page :first re-declares only @bottom-center, leaving @bottom-left (privacy_label) and @bottom-right (generated_at) to cascade from base @page (pdf_chrome.py:186-188). Phase 6 inherits this.

### 2. CSS specificity of chrome @page vs composer @page

CSS Paged Media Level 3: @page rules with equal specificity cascade in source order. Both use the bare @page selector → equal specificity. Second-declared wins for any margin box both declare. Chrome CSS must come after _PDF_CSS. Q1 recommendation (second style block, appended after _PDF_CSS) achieves this.

### 3. Baseline JSON shape — cover redesign impact is ZERO structural drift

Reviewed tests/baselines/board_summary_test_pull.json (34 lines). Captured fields:

    analyst_excel_present, bundle_keys_present, email_inline_image_cids_per_module,
    email_panel_count, excel_tab_names_sorted, group_slug, panel_drivers_all_no_data_in_scope,
    pdf_has_risk_status_summary_header, pdf_page_count, pdf_rag_cell_count,
    rag_cells_all_no_data, schema_version

No field captures cover-page text content. Cover-related field is pdf_page_count (currently 5 = cover + 4 module pages). Phase 6 keeps cover as one page → page count stays at 5 → no drift expected.

pdf_has_risk_status_summary_header is an HTML-marker check inside _PDF_UNIFIED_COVER_TEMPLATE. Phase 6 must preserve whatever marker text the extractor greps for. Action for planner: read tests/baseline_utils.py to confirm exact marker string (likely the h2.rag-strip-header "Risk Status Summary" line, based on field name + composer.py:387 template). Preserve verbatim.

D-04 wipe + regenerate is belt-and-braces; structural smoke would likely pass even without wiping. Operator visual UAT is the real correctness gate.

### 4. assemble_pdf injection points

HTML scaffold (composer.py:710-724):

    _PDF_DOCTYPE
    <html><head>
      <meta charset utf-8>
      <title>{title}</title>
      _PDF_CSS                  <-- inject chrome style immediately after
      <style>{page_css}</style> (optional)
    </head><body>
                                <-- inject build_header_html at body-top
      cover                     <-- _build_unified_cover_page output (trimmed)
      body                      <-- module sections
    </body></html>

The chrome-header div from build_header_html must be a body-level element, not inside head or .report-cover. WeasyPrint pulls it into @top-left via the position-running CSS rule emitted by build_css (pdf_chrome.py:189-190).

build_footer_runners returns empty string in v1 — footer corners are pure CSS content strings, no body-side injection needed.

### 5. Subtitle formatter location — recommendation: run_all.run_group

| Location                       | Pro                                                                 | Con                                                            |
|--------------------------------|---------------------------------------------------------------------|----------------------------------------------------------------|
| run_group (single source)      | Computes once, threads same string everywhere; future composed_report inherits | Adds one helper to run_all.py                                  |
| board_summary.run_report       | Co-located with current scope-string code at lines 234-244          | Each new chrome-enabled report duplicates the formatter        |

Recommendation: helper in run_all.py (top-level, above run_group). Compute once, thread via report_kwargs as scope_subtitle. board_summary.run_report accepts the kwarg and uses it for both cover subtitle (replacing lines 234-244 "Scope: tag_category = tag_value") and PdfChromeConfig.subtitle. Single source of truth per D-02.

    # run_all.py, top-level helper:
    def _format_scope_subtitle(tag_category, tag_value):
        return tag_value if (tag_category and tag_value) else "All assets"
    # inside run_group, near privacy_label resolution:
    scope_subtitle = _format_scope_subtitle(tag_category, tag_value)
    # slug-specific block:
    if slug == board_summary:
        report_kwargs[privacy_label]  = privacy_label
        report_kwargs[scope_subtitle] = scope_subtitle

Caveat: "All assets" (D-02) vs "All Assets" (current cover text at board_summary.py:237, 243). D-01 specifies sentence case "All assets". Phase 6 normalizes both. Flag in commit message — intentional case shift.

### 6. Existing tests likely to fail — NONE found

Grep for cover-title|cover-meta|cover-divider|cover-subtitle|Sections|Generated across tests/ returned zero matches. Structural baselines do not assert against any of these strings. No test updates required for cover redesign.

Files referencing those classes/strings outside tests/:
- reports/modules/composer.py — the surgery target itself.
- reports/management_summary.py (lines 1005, 1334, 1338, 2125) — independent inline cover, NOT via composer. DO NOT TOUCH per CHROME-COMPAT-01.
- delivery/email_template.py, exporters/pdf_exporter.py — separate legacy paths; do not share composer cover.

Planner spot-check: tests/test_phase2_composer_pipeline.py is cross-referenced inside composer.py:399 as the reason _PDF_RAG_STRIP_TEMPLATE alias exists. Confirm it does not assert on cover-text strings.

### 7. HEADER_BG_COLOR and LOGO_PATH confirmed in config.py

- config.py:236 — HEADER_BG_COLOR str = #1a2332 (CHROME-CFG-01).
- config.py:237 — LOGO_PATH Path or None = None (CHROME-CFG-02).
- Surrounding docstring (config.py:229-235) notes run_group will construct PdfChromeConfig per group.

### 8. generated_at timestamp is UTC — verified

- board_summary.run_report at board_summary.py:152-153: if generated_at is None: generated_at = datetime.now(tz=timezone.utc).
- run_all.run_group at run_all.py:564-565: same pattern.
- PdfChromeConfig.__post_init__ (pdf_chrome.py:91-104) hard-fails on naive/non-UTC.

No timezone gap. Phase 6 passes generated_at straight into PdfChromeConfig(generated_at=generated_at).

---

## Risk Register

| # | Risk | Likelihood | Mitigation |
|---|------|-----------|-----------|
| R1 | pdf_has_risk_status_summary_header extractor marker text drifts when cover template is trimmed | MEDIUM | Planner: read tests/baseline_utils.py in Wave 0; identify exact marker text; preserve verbatim. |
| R2 | Operator forgets to wipe one of the 3 baselines | LOW | Make 3-file rm explicit in executor task — or include rm -f tests/baselines/board_summary_*.json as preamble. |
| R3 | "All assets" vs "All Assets" case change surprises operator UAT | LOW | D-01 chose "All assets". Note in commit message — intentional. |
| R4 | _PDF_RAG_STRIP_TEMPLATE alias (composer.py:401) tracks the trimmed template via Python name binding | LOW | No action — alias points by reference; auto-tracks. |
| R5 | Future chrome-enabled report duplicates the privacy_label slug-specific block | LOW | Cosmetic. If allowlist grows past 2-3 entries, refactor to inspect.signature then. |
| R6 | WeasyPrint version pin: chrome position-running + @page :first worked under Phase 5 pin; future bump could break this | LOW | Phase 6 inherits the pin per Phase 5 VERIFICATION. |

---

## Files Touched in Phase 6 (verified)

| File | Line range | What changes |
|------|-----------|--------------|
| reports/modules/composer.py | 70-374 (_PDF_CSS) | Optionally trim now-dead .cover-title, .cover-subtitle, .cover-divider, .cover-meta rules. Cosmetic per Karpathy section 3 — planner picks. |
| reports/modules/composer.py | 377-393 (_PDF_UNIFIED_COVER_TEMPLATE) | Trim to: .report-cover wrapper + value-only subtitle line + .rag-strip block. Drop title p, hr, .cover-meta div, Generated line, Sections line. Preserve h2.rag-strip-header marker (R1). |
| reports/modules/composer.py | ~430-446 (__init__) | Add pdf_chrome PdfChromeConfig kwarg defaulting None; store as self._pdf_chrome. |
| reports/modules/composer.py | 599-724 (assemble_pdf) | Inject chrome style after _PDF_CSS; inject build_header_html at body-top. Both guarded if self._pdf_chrome. |
| reports/modules/composer.py | 730-902 (_build_unified_cover_page) | Update template substitution dict — drop title, generated_at, module_list; keep scope subtitle + RAG strip vars. |
| reports/modules/composer.py | top imports | from reports.modules.pdf_chrome import PdfChrome, PdfChromeConfig. |
| reports/board_summary.py | 82-92 (run_report signature) | Add privacy_label str = Confidential and scope_subtitle str or None kwargs. |
| reports/board_summary.py | 220-226 (composer construction) | Build PdfChromeConfig and pass pdf_chrome to ReportComposer. |
| reports/board_summary.py | 234-244 (scope_str / subtitle construction) | Replace Scope tag_category = tag_value with value-only scope_subtitle where it feeds cover/pdf subtitle. Keep scope_label for analyst _Metadata row (D-19) unchanged. |
| reports/board_summary.py | 47 (imports) | Add HEADER_BG_COLOR, LOGO_PATH to from config import. |
| run_all.py | 587-590 (filter resolution) | Add privacy_label = group_config.get(privacy_label, Confidential) and scope_subtitle = _format_scope_subtitle(tag_category, tag_value). |
| run_all.py | 672-682 (slug-specific extras) | Append two report_kwargs lines inside if slug == board_summary block. |
| run_all.py | top-level | Add _format_scope_subtitle helper above run_group. |
| tests/baselines/board_summary_test_pull.json | wipe + regen | Delete; re-generated by smoke auto-init. |
| tests/baselines/board_summary_test_pull_analyst_off.json | wipe + regen | Same. |
| tests/baselines/board_summary_test_pull_zero_match.json | wipe + regen | Same. |
| (operator-only) output/.../board_summary.pdf | visual UAT | D-04 checklist. |

---

## Files NOT to Touch (verified compat-safe)

| File | Why off-limits |
|------|----------------|
| reports/modules/pdf_chrome.py | Phase 5 contract — Phase 6 consumes, does NOT modify. |
| reports/management_summary.py | CHROME-COMPAT-01 — keeps its own inline cover (management_summary.py:1334-1338). Does not use ReportComposer.assemble_pdf. |
| reports/ops_remediation.py | CHROME-COMPAT-01 — legacy renderer untouched. |
| tests/test_pdf_chrome.py | Phase 5 isolation tests; chrome contract unchanged. |
| config.py | HEADER_BG_COLOR, LOGO_PATH already landed (Phase 5). Consume only. |
| delivery_config.schema.yaml | privacy_label field landed in Phase 5; consume via group.get. |
| delivery_config.yaml | Existing groups validate without privacy_label — CHROME-COMPAT-02 already PASS. |
| scripts/smoke_board_summary_cutover.py | Auto-init flow handles regen. No flag needed (Q4). |
| tests/baseline_utils.py | Read but do not modify — confirm pdf_has_risk_status_summary_header marker string (R1). |
| delivery/email_template.py, exporters/pdf_exporter.py | Independent legacy paths; do not share composer cover. |

---

## Sources

### Primary (HIGH confidence — in-tree file:line evidence)

- reports/modules/pdf_chrome.py:1-277 — chrome utility contract (full read).
- reports/modules/composer.py:1-250, 377-401, 430-446, 599-724, 1513-1642 — composer integration target.
- reports/board_summary.py:1-547 — board_summary wiring target.
- run_all.py:76-110, 487-707 — run_group + slug map + slug-specific kwarg pattern.
- scripts/smoke_board_summary_cutover.py:1-272 — smoke script signature; no --regenerate flag.
- tests/baselines/board_summary_test_pull.json — confirmed structural-only shape.
- config.py:229-237 — HEADER_BG_COLOR + LOGO_PATH constants.
- .planning/phases/05-pdf-chrome-foundation/05-VERIFICATION.md — Phase 5 chrome utility PASS evidence.
- .planning/phases/06-cover-redesign-board-summary-integration/06-CONTEXT.md — locked D-01..D-06.

### Secondary (CITED)

- CSS Paged Media Level 3 cascade order — cited indirectly via Phase 5 VERIFICATION row CHROME-FTR-03 (Layer-2 real-render confirmed cascade behaviour on pinned WeasyPrint).

### Tertiary

- None. Every claim verifies against committed files.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The pdf_has_risk_status_summary_header baseline marker greps for the h2.rag-strip-header line (text likely "Risk Status Summary"). Field name + composer.py:387 template strongly suggest this, but tests/baseline_utils.py was not read in this research. | Additional Finding 3, Risk R1 | Trimmed cover loses the marker; smoke regen surfaces pdf_has_risk_status_summary_header false. Planner mitigates by reading tests/baseline_utils.py in Wave 0. |

---

## Metadata

Confidence breakdown:

| Area | Level | Reason |
|------|-------|--------|
| @page conflict map (Q1) | HIGH | Direct grep of both CSS blocks — only @bottom-center overlaps, content identical. |
| Compat-safe kwarg routing (Q2) | HIGH | _REPORT_MODULE_MAP shape confirmed; no decorators on run_report at board_summary.py:82. |
| Circular import risk (Q3) | HIGH | pdf_chrome.py imports verified zero reports. references. |
| Smoke script regen (Q4) | HIGH | Full read of script; auto-init path documented in header lines 10-15. |
| Baseline drift forecast | HIGH | Full read of baseline JSON; no cover-text fields present. |
| Test impact | MEDIUM | Grep across tests/ returned zero matches; planner should spot-check tests/test_phase2_composer_pipeline.py. |
| Baseline-extractor marker text (A1) | MEDIUM | Inferred from field name + template structure; not directly read. |

Research date: 2026-05-13
Valid until: 2026-06-12 (30 days).
