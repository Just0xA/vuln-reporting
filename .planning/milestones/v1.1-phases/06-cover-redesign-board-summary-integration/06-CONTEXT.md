# Phase 06 — Cover Redesign + Board Summary Integration — CONTEXT

**Phase:** 6 — Cover Redesign + Board Summary Integration
**Milestone:** v1.1 — PDF Chrome Redesign (closes the milestone)
**Date:** 2026-05-13
**Status:** Context locked; ready for `/gsd-plan-phase 6`.

---

## Domain

Wire the Phase 5 `PdfChrome` utility into `ReportComposer`, redesign the `_PDF_UNIFIED_COVER_TEMPLATE` body now that header (title) and footer (timestamp + privacy label) take over the repeating chrome surface, thread `privacy_label` from `delivery_config.yaml` through `run_group()` → `board_summary.run_report()` → `ReportComposer` → `PdfChromeConfig`, and regenerate the `scripts/smoke_board_summary_cutover.py` baselines against the new cover-page structure. `management_summary` and `ops_remediation` keep their legacy render paths untouched (CHROME-COMPAT-01).

Phase 6 is the v1.1 milestone-closer. Phase 5 proved the chrome utility in isolation; Phase 6 makes Board Summary the first production consumer and demonstrates that future modular PDF reports inherit the chrome for free.

Requirements (locked in `.planning/REQUIREMENTS.md`): **CHROME-COV-01, CHROME-COV-02, CHROME-INT-01, CHROME-INT-02, CHROME-INT-03, CHROME-COMPAT-01, CHROME-COMPAT-02.**

---

## Canonical Refs

Downstream agents (researcher, planner, executor) MUST read these in addition to ROADMAP.md and this CONTEXT.md:

- `.planning/REQUIREMENTS.md` — milestone v1.1 active requirements (CHROME-COV / INT / COMPAT rows are this phase).
- `.planning/ROADMAP.md` — phase 6 success criteria and milestone scope.
- `.planning/phases/05-pdf-chrome-foundation/05-CONTEXT.md` — locked chrome utility shape (`PdfChrome` + `PdfChromeConfig`), privacy-label flow design, missing-logo fallback rule, WeasyPrint `@page :first` + running-element pattern.
- `.planning/phases/05-pdf-chrome-foundation/05-VERIFICATION.md` — file:line evidence that Phase 5 deliverables exist on disk; Phase 6 starts here.
- `reports/modules/pdf_chrome.py` — the utility being wired. Phase 6 consumes; does NOT modify Phase 5's contract.
- `reports/modules/composer.py` — primary integration target. Lines 70–230 hold `_PDF_CSS`; lines 377–393 hold `_PDF_UNIFIED_COVER_TEMPLATE`; lines 698–902 hold `_build_unified_cover_page()`.
- `reports/board_summary.py` — `run_report()` signature at line 82; subtitle/header-line construction at lines 235–242. Receives the new `privacy_label` kwarg.
- `run_all.py` — `run_group()` at line 504; tag-filter resolution at lines 589–590 (`privacy_label` resolves symmetrically here).
- `scripts/smoke_board_summary_cutover.py` — baseline regen target (CHROME-INT-03).
- `tests/baselines/board_summary_test_pull*.json` — three baselines that will be wiped + regenerated.
- `CLAUDE.md` — Karpathy Guidelines (especially §3 Surgical Changes — Phase 6 must NOT touch `management_summary` / `ops_remediation` paths).
- `docs/GLOSSARY.md` — definitions of *chrome*, *cover page*, *RAG strip*, *four-channel render contract*.

---

## Decisions (locked)

### D-01 — Cover body shape: subtitle + RAG strip only

Once chrome takes the title (header band, every page) and Generated:/privacy label (footer corners, every page), the cover body strips down to two things:

1. **Scope subtitle line** — value-only, NO category prefix
2. **The unified RAG strip** (preserved verbatim from v1.0)

Concretely:

| Input | Old cover body subtitle | New cover body subtitle |
|---|---|---|
| `tag_category="Environment"`, `tag_value="Production"` | `"Environment = Production"` | `"Production"` |
| No tag filter | `"all assets"` | `"All assets"` |

**Removed from cover body (CHROME-COV-02):**
- Inline title `<p class="cover-title">` — chrome header carries the title on every page.
- Inline `<p>Generated: {generated_at}</p>` — moves to footer right corner via `PdfChrome.build_footer_runners()`.
- Inline `<p>Sections: {module_list}</p>` — drop entirely. The reader sees each section on its own page; an explicit enumeration on the cover added clutter without information value.
- The `<hr class="cover-divider">` and the `.cover-meta` wrapper — both retired with the inline blocks they wrapped.

**Preserved on cover body (CHROME-COV-01):**
- The unified `.rag-strip` block — header text, `.rag-cell-row`, and per-module RAG cells render identically to v1.0. No regression in RAG strip rendering or content.

**Rationale:** Chrome header already shows the title on every page (including the cover). Repeating it as a hero block on the cover would be visual redundancy. The scope subtitle anchors the reader to "what slice are we looking at" without re-stating the report's name.

### D-02 — Chrome header subtitle = same value-only scope string

`PdfChromeConfig.subtitle` is populated with the SAME value-only scope string used in the cover body subtitle (D-01). This is single-source-of-truth: `run_group()` (or `board_summary.run_report()`) computes it once, passes it as `subtitle=…` into `PdfChromeConfig`, and the composer renders the same string in two places:

- **Chrome header band** (every page) — small, top-right area beside the title, per `PdfChrome.build_header_html()`.
- **Cover body** (page 1 only) — under the absent title, above the RAG strip.

Both render the same value: `"Production"` / `"Engineering"` / `"All assets"` — never `"Environment = Production"`.

**Formatter contract (lives wherever the scope subtitle is computed — planner picks: `run_group()` vs `board_summary.run_report()`):**

```python
def _format_scope_subtitle(tag_category: str | None, tag_value: str | None) -> str:
    return tag_value if (tag_category and tag_value) else "All assets"
```

The function only needs `tag_value` (and a check that `tag_category` is also set, since the YAML schema requires both-or-neither). The category itself is intentionally dropped.

### D-03 — LOGO_PATH stays None at v1.1 ship

`config.py` keeps `LOGO_PATH: Path | None = None` (Phase 5 default). Phase 6 does NOT introduce a committed default logo. Every operator deployment ships title-only header until the operator points `LOGO_PATH` at their own image.

**Rationale:**
- Phase 5's Layer-1 unit tests already cover the title-only path; the default ship state is the proven-safe path.
- No branding decision needs to be made at the framework level.
- A committed default logo would invite "is this our logo?" confusion in every fresh deploy.
- Operators who want a logo set one line in `config.py` and restart — well documented by the CHROME-CFG-02 acceptance criteria.

**Out of scope for Phase 6:** sourcing or committing a default logo image. If a future deployment wants this, it's a docs/example change in a later milestone.

### D-04 — Cutover baseline regen = wipe + regenerate + operator visual UAT

CHROME-INT-03 requires "0 structural drift after re-baseline." Since the cover structure is changing (cover body now subtitle + RAG strip, no title/timestamp/sections list), the existing three JSON baselines under `tests/baselines/` will diff against the new output. The strategy:

1. **Delete** `tests/baselines/board_summary_test_pull.json`, `…_analyst_off.json`, `…_zero_match.json`.
2. **Run** `scripts/smoke_board_summary_cutover.py` once against the new cover-page structure to regenerate fresh baselines.
3. **Operator visual UAT** — operator opens the actual generated `board_summary.pdf` for at least the test-pull scope and confirms:
   - Header band visible on every page with title + scope subtitle (white text on `#1a2332`).
   - Footer on every page: `"Confidential"` (or per-group override) left, `"2026-MM-DD HH:MM UTC"` right.
   - Footer center: `"Page N of M"` on pages 2+, EMPTY on page 1 (cover).
   - Cover body: scope subtitle + RAG strip, no inline title repeat, no "Generated:" line, no "Sections:" line.
   - RAG strip renders identically to v1.0 (no regression on cell layout, colors, content).
4. **Commit** the regenerated baselines with a clear message tying them to the Phase 6 cover redesign.

**Rejected:** extending the baseline-extractor to gracefully handle the new fields BEFORE regeneration. Reason: cover structure is a one-time shape change; extending the extractor is speculative complexity. The extractor handles the new shape implicitly once baselines are regenerated. If future cover tweaks land, that's when a richer extractor pays for itself.

**Visual UAT is the correctness gate**, not the structural baseline. Per Phase 5 user memory [[feedback_layout_fixes]]: WeasyPrint flex bugs are real; render the PDF and look at it. The structural baseline catches refactor regressions in the NEXT Phase 6+1, not the cover redesign itself.

### D-05 — Privacy-label threading: composer-level config object

`ReportComposer` accepts an optional `pdf_chrome: PdfChromeConfig | None = None` constructor parameter. When provided, the composer instantiates `PdfChrome(pdf_chrome)`, concatenates `PdfChrome.build_css()` into the existing `_PDF_CSS`, and injects `PdfChrome.build_header_html()` + `PdfChrome.build_footer_runners()` into `assemble_pdf()`'s document scaffolding.

`board_summary.run_report()` gains a `privacy_label: str = "Confidential"` kwarg. Builds the `PdfChromeConfig` from its existing inputs (`title`, scope subtitle from D-02, `generated_at` already UTC, `header_bg=HEADER_BG_COLOR`, `logo_path=LOGO_PATH`, `privacy_label`).

`run_all.py:run_group()` resolves the default at the call site (per Phase 5 D-03):

```python
privacy_label = group.get("privacy_label", "Confidential")
# … later …
report_kwargs["privacy_label"] = privacy_label
```

**Compat-safety (CHROME-COMPAT-01):** `management_summary` and `ops_remediation` do NOT accept a `privacy_label` kwarg in v1.1. Their `run_report()` signatures stay exactly as today. `run_group()` MUST only pass `privacy_label` to reports that opt in (slug allowlist or `inspect.signature` check — planner picks). The kwarg is invisible to legacy renderers.

**Open question for the planner:** whether the slug allowlist is hardcoded (`{"board_summary"}`) or derived from a per-slug capability flag in `_REPORT_MODULE_MAP`. Either is acceptable; allowlist is simpler for one consumer; flag generalizes if/when `management_summary`/`ops_remediation` migrate (v2 work, not v1.1).

### D-06 — Composer wire point: constructor parameter, not assemble-time

`ReportComposer.__init__` accepts `pdf_chrome: PdfChromeConfig | None = None`. The composer holds a `PdfChrome` instance for its lifetime; `assemble_pdf()` reads from it. **NOT** a per-call `assemble_pdf(pdf_chrome=…)` parameter.

**Rationale:** chrome is a property of the report run, not of an individual assembly call. The same composer instance assembles PDF + collects email KPIs + builds analyst Excel; all four channels share the same generated_at + scope + privacy label. Putting chrome on the composer makes that single-source-of-truth explicit.

**Backward compatibility:** the parameter is optional with `None` default. Existing direct `ReportComposer(...)` calls (whatever tests or scratch code) keep working with no chrome — they get the legacy `_PDF_CSS` block alone. Only `board_summary.run_report()` opts in for v1.1.

---

## Code Context

- **`reports/modules/composer.py`** — primary surgical target:
  - `_PDF_CSS` (line 70+): chrome `build_css()` output gets concatenated in (added inside the same `<style>` tag, or appended as a second `<style>` block — planner picks).
  - `_PDF_UNIFIED_COVER_TEMPLATE` (line 377+): cover template loses the title `<p>`, the divider `<hr>`, the `.cover-meta` wrapper, and the inline `Generated:` + `Sections:` lines. Keeps the `.rag-strip` block.
  - `_build_unified_cover_page()` (line 730+): updates the template substitution dict to match the simplified template.
  - `assemble_pdf()`: injects `pdf_chrome.build_header_html()` once at body-top (positioned via `running()`) and `pdf_chrome.build_footer_runners()` (running elements pulled into `@bottom-*` margin boxes).
  - `_PDF_RAG_STRIP_TEMPLATE` deprecated alias on line 401: leave as-is (deferred cleanup per STATE.md).
- **`reports/board_summary.py`** — secondary target:
  - `run_report()` signature at line 82: add `privacy_label: str = "Confidential"` kwarg.
  - Scope subtitle construction at lines 235–242: refactor to value-only formatter from D-02.
  - Pass `PdfChromeConfig(...)` to `ReportComposer(..., pdf_chrome=...)`.
- **`run_all.py`** — privacy-label resolution:
  - Line 589–590 (tag filter resolution): add `privacy_label = group.get("privacy_label", "Confidential")` symmetrically.
  - Line 666–667 (run_report kwargs): conditionally pass `privacy_label=` only for compatible slugs.
- **`scripts/smoke_board_summary_cutover.py`** — regen target.
- **`tests/baselines/*.json`** — wipe + regenerate (3 files).
- **`reports/management_summary.py`** + **`reports/ops_remediation.py`** — DO NOT TOUCH. CHROME-COMPAT-01 requires their render paths stay exactly as today.
- **`config.py`** — `HEADER_BG_COLOR` and `LOGO_PATH` already landed in Phase 5; consumed here.

---

## Deferred Ideas

Captured during this discussion or carried from earlier; out of scope for Phase 6 and (mostly) for v1.1.

- **Committed default brand logo** — explicitly rejected for v1.1 ship per D-03. Operators point `LOGO_PATH` at their own image.
- **Hero title repeat on cover body** — rejected per D-01 (visual redundancy with chrome header). Could be revisited if operator UAT feedback says the cover feels too sparse.
- **Sections enumeration on cover** — dropped per D-01. The module pages themselves are the source of truth for what's in the report.
- **Per-slug capability flag for chrome opt-in** — currently a planner-discretion choice (allowlist vs flag). Flag generalizes for v2 when `management_summary` / `ops_remediation` migrate; allowlist is simpler today. Either is acceptable for v1.1.
- **Header text autoshift for light backgrounds** — `REQUIREMENTS.md` "Out of Scope". White-on-dark only; operator picks a dark color.
- **`management_summary` / `ops_remediation` migration to the module contract (GEN-01/02)** — deferred to a future milestone. They keep their legacy render paths in v1.1 (CHROME-COMPAT-01).
- **Extending the baseline-extractor for new chrome fields** — explicitly rejected per D-04 (speculative complexity). If future cover changes land, that's when a richer extractor earns its keep.
- **`_PDF_RAG_STRIP_TEMPLATE` deprecated alias cleanup** — cosmetic-deferred per STATE.md "Deferred Items".

---

## Open Questions for Researcher

- **`@page` block injection** — is it safer to concatenate chrome CSS into the existing `_PDF_CSS` `<style>` block, or to emit a second `<style>` block after it? WeasyPrint should treat both identically (last-declared wins), but confirm the existing `@page` rules in `_PDF_CSS` (page-size, margins, bottom-center page-number) don't conflict with the chrome's `@page` rules — chrome may want to suppress/redefine the existing bottom-center.
- **Compat-safe kwarg passing** — is `inspect.signature()`-based detection of `privacy_label` support on `run_report()` cleaner than a slug allowlist, or is the inspect-based path fragile against partials/decorators? Confirm against the existing `_REPORT_MODULE_MAP` import shape.
- **`pdf_chrome` import from `composer.py`** — is there any circular-import risk between `reports/modules/composer.py` and `reports/modules/pdf_chrome.py`? Both live in the same package; pdf_chrome already doesn't decorate with `@register_module` (it's a utility, not a metric module), so registry discovery doesn't see it. Confirm.
- **Baseline regen smoke run** — the existing smoke script likely re-renders the test-pull, analyst-off, and zero-match scenarios in one pass. Does it accept a `--regenerate` flag today, or do we need to add one? Confirm script signature.

---

## Success Criteria (from ROADMAP.md, restated)

1. `board_summary` PDF renders with new cover (RAG strip + chrome header + footer-without-page-number on page 1) and metric pages (chrome header + footer-with-page-number on pages 2+).
2. Cutover smoke baselines regenerated; 0 structural drift after re-baseline.
3. `management_summary` and `ops_remediation` PDFs deliver unchanged (their existing renderers untouched; existing regression suites pass without modification).
4. Operator visual UAT pass: cover looks professional, header color/logo behavior correct, footer page numbering correct on non-cover pages.

---

## Next Step

```
/clear
/gsd-plan-phase 6
```
