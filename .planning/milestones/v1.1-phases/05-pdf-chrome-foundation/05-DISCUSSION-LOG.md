# Phase 05 — PDF Chrome Foundation — Discussion Log

**Date:** 2026-05-13
**Mode:** default (interactive, single-question per area)
**Companion doc:** `05-CONTEXT.md` (canonical decisions)

This log is human-readable history of the discussion. Downstream agents read `05-CONTEXT.md`, not this file.

---

## Selected gray areas

User chose all four offered areas:

1. Chrome module placement
2. Header/footer rendering mechanism
3. Logo + privacy-label plumbing
4. Isolation test surface

---

## Side-conversation: glossary

Mid-discussion the user asked **"why are we calling this 'chrome'?"** — borrowed from UI/UX vocabulary for framing elements around content (cf. browser chrome). The term is already baked into the v1.1 milestone name and the `CHROME-*` REQ IDs.

User then asked for a definitions file so the vocabulary is referenceable. Created **`docs/GLOSSARY.md`** with 9 initial entries (Chrome, Composed report, Cover page, Four-channel render contract, Module, RAG strip, Recipient group, Slug, SLA, VPR) and added a pointer to it near the top of `CLAUDE.md`. Committed alongside this context.

---

## Area 1 — Chrome module placement

**Initial options presented:** standalone `pdf_chrome.py` (functions only), composer extension methods, CSS-only patch.

**User pushback:** *"I want this to be something that is basically the design of the PDF pages going forward. What are the pros and cons of each or is there a better option based on the vision?"*

**Reformulated** with a fourth option — `PdfChrome` class + `PdfChromeConfig` frozen dataclass — explicitly framed as a design-system surface that parallels the existing `BaseModule` + `ModuleConfig` pattern.

**Decision:** Option D — class + dataclass. Locked in `CONTEXT.md` D-01.

---

## Area 2 — Header/footer rendering mechanism

**Options:**
- α — `@page` margin boxes + `position: running()` elements, with `@page :first` for cover-page-number suppression and `counter(page)/counter(pages)` for "Page N of M."
- β — Per-page HTML blocks emitted by Python.

**Discussion:** I noted the composer already uses `counter(page)/counter(pages)` in its current `@bottom-center` rule, so α is consistent with prior art. β reimplements what CSS gives for free and breaks when modules span multiple pages.

**Decision:** α. Locked in D-02.

---

## Area 3 — Logo + privacy-label plumbing

**Recommended shape presented:**

- Logo: `<img src="file:///…">` inside the running element. Reject base64.
- Logo missing-file fallback detected at render time inside `PdfChrome.build_header_html()`, not at startup.
- Privacy-label `"Confidential"` default resolved at the `run_group()` call site (operator-visible); dataclass also keeps a defensive default for direct test instantiation.

Contrast option offered: resolve default *only* in `PdfChromeConfig`.

**Decision:** Recommended shape as written. Locked in D-03.

---

## Area 4 — Isolation test surface

**Options:** two-layer pyramid (recommended), string asserts only, two-layer + pixel snapshots.

**Reasoning surfaced:** Project memory [[feedback_layout_fixes]] requires real renders, not theoretical math. String-only fails that bar. Pixel snapshots belong to Phase 6 cutover regen (CHROME-INT-03), not chrome-in-isolation.

**Decision:** Two-layer pyramid. Locked in D-04.

---

## Deferred ideas captured

- Header text autoshift for light backgrounds (explicitly out of scope per REQUIREMENTS.md).
- Pixel/byte-diff visual snapshots of chrome (Phase 6 territory).
- Legacy report migration to module render contract (GEN-01/02, deferred milestone).
- CSS custom properties vs running elements for footer corner content — implementation detail; planner picks.

---

## Open questions queued for the researcher

Listed in `05-CONTEXT.md`. Highlights:
- WeasyPrint `@page :first` margin-box override behavior.
- Footer three-corner layout at A4 landscape with current margins.
- `pypdf` per-page text-extraction stability vs alternatives (PyMuPDF, pdfplumber).
- WeasyPrint `position: running()` interactions with `<img>` content.

---

## Files created or modified during the discussion

- **Created** `docs/GLOSSARY.md` — project vocabulary glossary.
- **Modified** `CLAUDE.md` — added pointer to `docs/GLOSSARY.md` under Project Overview.
- **Created** `.planning/phases/05-pdf-chrome-foundation/05-CONTEXT.md`
- **Created** `.planning/phases/05-pdf-chrome-foundation/05-DISCUSSION-LOG.md` (this file)
