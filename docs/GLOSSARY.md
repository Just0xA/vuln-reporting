# Glossary — Vulnerability Management Reporting Suite

Project-specific vocabulary that may not be obvious from the code alone. Add a term here when it first shows up in a planning doc, REQ ID, module name, or commit message and is not self-explanatory.

---

## Chrome (PDF chrome)

The framing elements around PDF page content — the header band (logo + report title) and footer band (privacy label + page number + generation timestamp) — as distinct from the *content* (cover RAG strip, module metric pages, analyst tables).

Borrowed from UI/UX vocabulary ("browser chrome" = the toolbar/tabs/address bar around the webpage). Used in milestone v1.1 and the `CHROME-*` REQ IDs in `.planning/REQUIREMENTS.md`.

## Composed report

The generic top-level report slug (`composed_report`) that lets `delivery_config.yaml` assemble an arbitrary list of registered modules into one bundle, without authoring a new Python report script per combination. Opt in with `reports: [composed_report]` plus a `modules:` array. Added 2026-05-13. See the "Composed Reports" section in `CLAUDE.md`.

## Cover page

The first page of every modular PDF report. Currently renders the report title, scope subtitle, generation timestamp, section list, and the unified RAG strip cells. In v1.1, the timestamp and privacy label move from the cover body to the footer band.

## Four-channel render contract

Each metric module renders into four output channels via concrete (non-abstract) methods on `BaseModule`:

| Channel               | Method                       |
| --------------------- | ---------------------------- |
| PDF                   | `render_pdf_section()`       |
| Excel                 | `render_excel_tabs()`        |
| Email body panel      | `render_email_panel()`       |
| Analyst-detail tabs   | `render_analyst_tabs()`      |

Plus `render_rag_strip_entry()` for the cover-page RAG strip and `render_email_kpis()` for the legacy KPI-tile path. All defaults are no-ops so a module can opt into only the channels it has data for.

## Module (metric module)

A self-contained KPI/KRI implementation under `reports/modules/`, named `*_module.py`, decorated with `@register_module`, extending `BaseModule`. Auto-discovered at import time. Implements one `compute()` (pure, side-effect-free) plus whichever renderer methods its channels need. The unit of composability for board/management/composed reports.

## RAG / RAG strip

**RAG** = Red / Amber / Green status indicator, the conventional management-reporting color scheme for "off track / at risk / on track." The **RAG strip** is the horizontal row of colored cells on the cover page of board-style reports, one cell per module, showing each metric's headline value and status at a glance. Defined in `reports/modules/rag_utils.py`.

## Recipient group

One entry under `groups:` in `delivery_config.yaml`. Bundles together: a schedule (weekly/monthly/on-demand), a tag filter, a list of reports (or modules for `composed_report`), and an email destination list. The unit a scheduler iterates over.

## Slug

A short, lowercase, underscore-separated identifier used in code and YAML to refer to a top-level report — e.g. `board_summary`, `executive_kpi`, `composed_report`. Listed in `run_all.py:_VALID_REPORTS` and the YAML schema's `reports` enum.

## SLA (Severity-based SLA)

The remediation deadline in days from `first_found_date`, derived from the vulnerability's **VPR** score (not native CVSS severity):

| Severity | VPR Range  | SLA (days) |
| -------- | ---------- | ---------- |
| Critical | 9.0 – 10.0 | 15         |
| High     | 7.0 – 8.9  | 30         |
| Medium   | 4.0 – 6.9  | 45         |
| Low      | 0.1 – 3.9  | 120        |

Defined as constants in `config.py`. A vulnerability is **overdue** when `today - first_found_date > SLA_days` and not remediated.

## VPR (Vulnerability Priority Rating)

Tenable's proprietary risk score (0.0 – 10.0) combining CVSS, threat intel, and exploit-availability signals. **The project's authoritative severity input** — always derived from the `vpr_score` field; native severity is only the fallback when VPR is null. Drives SLA bucket assignment.

---

*Add a term:* lowercase, alphabetical, lead with the canonical name, give the why and the where (file path or REQ ID), keep it under ~5 lines unless the concept genuinely needs more.