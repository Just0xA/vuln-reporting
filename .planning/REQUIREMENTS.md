# Milestone v1.1 Requirements — PDF Chrome Redesign

**Goal:** Redesign the PDF cover and apply a consistent, configurable header/footer to every page of every PDF report.

**Status:** Active (defined 2026-05-13)
**Count:** 16 REQs across 6 categories

---

## Active Requirements

### Configuration (CHROME-CFG)
- [ ] **CHROME-CFG-01**: Operator can configure PDF header background color globally in `config.py` (default: dark navy `#1a2332`).
- [ ] **CHROME-CFG-02**: Operator can configure an optional company logo file path globally in `config.py`.
- [ ] **CHROME-CFG-03**: When `LOGO_PATH` is unset or the file is missing, PDFs render with title-only header (no reserved logo space, no crash, no warning spam).
- [ ] **CHROME-CFG-04**: Operator can override the privacy label (default `"Confidential"`) per delivery group in `delivery_config.yaml` via an optional `privacy_label:` field; schema enforces type (string).

### Header (CHROME-HDR)
- [ ] **CHROME-HDR-01**: Every PDF page renders a header band with configured background color, optional logo on the left, and Report Title on the right.
- [ ] **CHROME-HDR-02**: Report Title text remains legible against the configured background color (white-text default; no autoshift in v1.1).

### Footer (CHROME-FTR)
- [ ] **CHROME-FTR-01**: Every PDF page renders a footer with privacy label on the left and Date Generated (UTC) on the right.
- [ ] **CHROME-FTR-02**: On every page EXCEPT the cover, the footer also renders the current page number centered between the corners (format `Page N of M` or equivalent).
- [ ] **CHROME-FTR-03**: Cover page footer omits the page number (only privacy label + date).

### Cover Page (CHROME-COV)
- [ ] **CHROME-COV-01**: Cover page body shows the unified RAG strip from v1.0 (no regression in RAG strip rendering or content).
- [ ] **CHROME-COV-02**: Cover page no longer renders the standalone "Generated:" timestamp or "Data Protection Label" inline — both are now in the footer.

### Integration (CHROME-INT)
- [ ] **CHROME-INT-01**: `board_summary` PDF renders with the new cover, header, and footer end-to-end (real-Tenable smoke + operator visual UAT pass).
- [ ] **CHROME-INT-02**: PDF chrome lives in a shared utility (e.g. `reports/modules/pdf_chrome.py` or composer extension) so future PDF reports inherit it without copying CSS.
- [ ] **CHROME-INT-03**: Cutover smoke baselines (`scripts/smoke_board_summary_cutover.py`) regenerate cleanly against the new cover-page structure; structural drift count = 0 after re-baseline.

### Backward Compatibility (CHROME-COMPAT)
- [ ] **CHROME-COMPAT-01**: `management_summary` and `ops_remediation` PDFs continue to deliver as today (no regression; their legacy render path is untouched in v1.1).
- [ ] **CHROME-COMPAT-02**: Existing `delivery_config.yaml` groups continue to validate without specifying `privacy_label:` (field is optional, defaults to "Confidential").

---

## Out of Scope (v1.1)

Carried forward to a later milestone; explicitly NOT this milestone:

- **GEN-01/02** — Migrate `management_summary` / `ops_remediation` to module render contract. Their legacy render path stays as-is; they will inherit the chrome only after migration.
- **GEN-03/04** — Broader YAML-driven module composition beyond the existing `composed_report` slug.
- **PERF-01..04** — Performance pass.
- **LEGACY-01** — Re-evaluate the 6 unbuilt reports as candidate module bundles.
- **Janitorial** — Stale `_VALID_FREQUENCIES` / `_VALID_REPORTS` constants in `run_all.py`.
- **Header text autoshift** — Light backgrounds requiring dark title text. v1.1 ships white-on-dark only; operator picks a dark color.

---

## Traceability

| REQ-ID | Phase |
|--------|-------|
| CHROME-CFG-01 | 5 — PDF Chrome Foundation |
| CHROME-CFG-02 | 5 — PDF Chrome Foundation |
| CHROME-CFG-03 | 5 — PDF Chrome Foundation |
| CHROME-CFG-04 | 5 — PDF Chrome Foundation |
| CHROME-HDR-01 | 5 — PDF Chrome Foundation |
| CHROME-HDR-02 | 5 — PDF Chrome Foundation |
| CHROME-FTR-01 | 5 — PDF Chrome Foundation |
| CHROME-FTR-02 | 5 — PDF Chrome Foundation |
| CHROME-FTR-03 | 5 — PDF Chrome Foundation |
| CHROME-COV-01 | 6 — Cover Redesign + Board Summary Integration |
| CHROME-COV-02 | 6 — Cover Redesign + Board Summary Integration |
| CHROME-INT-01 | 6 — Cover Redesign + Board Summary Integration |
| CHROME-INT-02 | 6 — Cover Redesign + Board Summary Integration |
| CHROME-INT-03 | 6 — Cover Redesign + Board Summary Integration |
| CHROME-COMPAT-01 | 6 — Cover Redesign + Board Summary Integration |
| CHROME-COMPAT-02 | 6 — Cover Redesign + Board Summary Integration |

Coverage: 16/16 REQs mapped (100%).

---

*Created: 2026-05-13 — milestone v1.1 kickoff*
