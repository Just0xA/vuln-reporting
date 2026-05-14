# Phase 06 — Discussion Log

**Phase:** 6 — Cover Redesign + Board Summary Integration
**Date:** 2026-05-13
**Format:** One row per question asked, options presented, user's selection, follow-up notes.

This log is for human reference only (audits, retrospectives). Downstream agents (researcher, planner, executor) read CONTEXT.md, not this file.

---

## Q1 — Cover body shape

**Question:** Once chrome takes the title (header) and Generated:/privacy label (footer), what stays in the cover body itself?

**Options presented:**
1. Hero title + subtitle + RAG strip
2. Subtitle + RAG strip (no title repeat)
3. RAG strip only
4. Hero title + RAG strip + Sections list

**User selection:** **Option 2** — Subtitle + RAG strip (no title repeat)

**User follow-up:** "I want to also drop the 'Category =' part of the subtitle, so that the scope just reads the Value of the key not the category."

**Captured as:** CONTEXT.md D-01 (cover body shape) + D-02 (value-only scope formatter applies to both cover body and chrome header subtitle).

---

## Q2 — Chrome header subtitle content

**Question:** `PdfChromeConfig.subtitle` is a free field. What should it contain for `board_summary`?

**Options presented:**
1. Per-group scope (e.g. 'Tag: Production' or 'All assets')
2. Static descriptor (e.g. 'Vulnerability Metrics')
3. Omit subtitle — title only

**User selection:** **Option 1** — Per-group scope

**Reconciled with Q1 follow-up:** The example label said "Tag: Production" but the user explicitly asked (in Q1) for value-only, no category prefix. Resolved as: subtitle = `"Production"` / `"All assets"` (no "Tag:" prefix, no "Environment =" prefix). Same string in both chrome header and cover body (single source of truth).

**Captured as:** CONTEXT.md D-02.

---

## Q3 — Default LOGO_PATH for v1.1 ship

**Question:** `config.py` has `LOGO_PATH = None` today. What should the milestone ship?

**Options presented:**
1. Stay None — operator points at their own logo
2. Commit a default placeholder logo to the repo

**User selection:** **Option 1** — Stay None

**Captured as:** CONTEXT.md D-03 (LOGO_PATH stays None; no default logo committed in v1.1).

---

## Q4 — Cutover baseline regeneration strategy (CHROME-INT-03)

**Question:** Cover structure is changing, so the existing JSON baselines will drift. How should that be handled?

**Options presented:**
1. Wipe + regenerate + operator visual UAT gate
2. Extend baseline-extractor for new cover shape, then regen
3. Two-phase: regen with old extractor, then extend extractor

**User selection:** **Option 1** — Wipe + regenerate + operator visual UAT gate

**Captured as:** CONTEXT.md D-04 (delete 3 existing baselines, regen fresh, operator opens the PDF and confirms; extractor extension explicitly rejected as speculative).

---

## Items Not Asked (locked from upstream)

The following were NOT presented as gray areas because they are already locked:

- **`PdfChrome` + `PdfChromeConfig` shape** — locked in Phase 5 CONTEXT.md D-01.
- **WeasyPrint `@page :first` cover suppression mechanism** — locked in Phase 5 CONTEXT.md D-02 and verified in Phase 5 Layer-2 integration test.
- **Logo missing-file fallback location (inside `PdfChrome.build_header_html()`)** — locked in Phase 5 CONTEXT.md D-03.
- **Privacy-label default resolution at `run_group()` call site** — locked in Phase 5 CONTEXT.md D-03; Phase 6 wires it (D-05).
- **`management_summary` / `ops_remediation` stay on legacy render path** — locked by REQUIREMENTS.md CHROME-COMPAT-01.

## Claude's Discretion (left for the planner)

- **Composer chrome wire point: constructor vs assemble-time** — closed by CONTEXT.md D-06 (constructor). Listed here for traceability since it wasn't explicitly asked.
- **Slug allowlist vs `inspect.signature()`-based opt-in for `privacy_label` kwarg passing** — explicitly noted as planner-discretion in CONTEXT.md D-05; flagged as a researcher question.
- **Whether chrome CSS lives in the same `<style>` block as `_PDF_CSS` or a second block** — flagged as a researcher question.
