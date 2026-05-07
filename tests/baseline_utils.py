"""
tests/baseline_utils.py — Phase 4 STRUCTURAL-ONLY baseline snapshot extractor.

Public API:
  extract_structural_snapshot(bundle, group_slug) -> dict   # 12 keys, structural only
  compare_snapshots(actual, baseline) -> list[str]          # diff lines or []
  load_baseline(path) -> dict
  write_baseline(path, snapshot) -> None

Per revised D-04-05 (2026-05-07): snapshots contain ONLY deterministic
structural shape — counts, booleans, sorted name lists. They do NOT
contain metric values (which drift daily with vulnerability churn) or
row-level data (which D-04-08 forbids). The schema is fixed; adding a
key requires editing this file AND the test file together.

Per D-04-08: defensive PII guard rejects DataFrames whose columns match
the exact-match list or narrow substring backstop. The snapshot itself
never reads cell values, only column names — the guard is belt-and-
braces against future contributors who add row-level fields by mistake.

HTML markers VERIFIED against actual source (plan-checker 2026-05-07):
  - email panels: each `render_email_panel` emits exactly ONE
    `<table role="presentation" ...>` per panel. The composer's
    `assemble_email_body` just `\\n.join(panels)` with no wrapping div.
    The legacy `class="module-panel"` literal does NOT exist in
    production HTML.
  - pdf page count: cover page is separated from module 1 by the CSS
    rule `page-break-after` on `.report-cover`, NOT by an HTML
    `<div class="page-break">` element (verified at composer.py:677).
    HTML page-break count is therefore off by one. Use the
    WeasyPrint byte stream as the authoritative source.

Run-time: zero Tenable I/O, zero filesystem I/O outside tests/baselines/.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

# --- PII guard ----------------------------------------------------------

_PII_EXACT: frozenset[str] = frozenset({
    "hostname", "ipv4", "ipv6", "fqdn", "plugin_name",
    "recast_reason", "recipient_email", "business_unit_name",
})

# Narrow substring backstop. Deliberately specific — substrings like 'name'
# alone produce too many false positives (tag_name, email_panel_count).
_PII_SUBSTRING: tuple[str, ...] = ("asset_name", "host_name", "ip_address")


def _is_pii_column(col: str) -> bool:
    low = str(col).lower()
    if low in _PII_EXACT:
        return True
    return any(s in low for s in _PII_SUBSTRING)


def _assert_no_pii(df: pd.DataFrame) -> None:
    for c in df.columns:
        if _is_pii_column(c):
            raise ValueError(
                f"PII guard: refusing to walk DataFrame with column {c!r} "
                f"(matches PII_EXACT or PII_SUBSTRING). Snapshots are "
                f"structural-only per revised D-04-05; row-level data is "
                f"forbidden per D-04-08."
            )

# --- Snapshot extractor -------------------------------------------------

def _no_data_color() -> str:
    """RAG cell color sentinel for the no-data state. Imported lazily."""
    try:
        from reports.modules.rag_utils import STATUS_COLOR  # noqa: PLC0415
        return STATUS_COLOR.get("no_data", "#cccccc")
    except Exception:
        return "#cccccc"


# Class / role literals — VERIFIED against actual source (plan-checker
# 2026-05-07). If a future panel layout introduces a nested
# `role="presentation"` table inside its outer panel table, the panel
# heuristic over-counts; the alternate would be the per-module gauge CID
# substring `f'cid:{module_id}_gauge"'`. Update both this file AND the
# test fixture together if the production marker changes.
_RAG_CELL_CLASS = 'class="rag-cell"'
_PANEL_MARKER = 'role="presentation"'
_RISK_STATUS_HEADER = "Risk Status Summary"
_NO_DATA_DRIVER = "No data in scope."


def _pdf_page_count_from_html(pdf_html: str) -> int:
    """Authoritative PDF page count via WeasyPrint byte stream.

    Renders pdf_html to uncompressed bytes (so PDF object headers are
    visible to the regex) and counts `/Type /Page` objects. The regex's
    trailing `\\b` word boundary excludes `/Type /Pages` (the catalog
    object that lists all pages, where `s` would not be a word boundary),
    so no subtraction is needed — each match IS one rendered page.

    `uncompressed_pdf=True` is required because WeasyPrint's default
    output runs object streams through FlateDecode, which would hide
    the `/Type /Page` markers from a regex over the raw bytes.

    Falls back to the HTML page-break count + 2 (cover + final implicit
    page) ONLY if WeasyPrint is not importable — should never happen in
    this project (WeasyPrint is a pinned dependency in requirements.txt).
    """
    try:
        from weasyprint import HTML  # noqa: PLC0415
    except Exception:
        return pdf_html.count('class="page-break"') + 2
    try:
        pdf_bytes = HTML(string=pdf_html).write_pdf(uncompressed_pdf=True)
    except TypeError:
        # Older WeasyPrint without uncompressed_pdf kwarg — fall back to
        # default and accept that compressed output may yield 0 matches;
        # callers can detect this via the fallback HTML heuristic.
        try:
            pdf_bytes = HTML(string=pdf_html).write_pdf()
        except Exception:
            return pdf_html.count('class="page-break"') + 2
    except Exception:
        return pdf_html.count('class="page-break"') + 2
    return len(re.findall(rb'/Type\s*/Page\b', pdf_bytes))


def extract_structural_snapshot(bundle: dict, group_slug: str) -> dict:
    # PII guard: walk every analyst_rows DataFrame for forbidden columns.
    for md in bundle.get("module_results", []):
        for _sheet, df in (getattr(md, "analyst_rows", []) or []):
            if isinstance(df, pd.DataFrame):
                _assert_no_pii(df)

    pdf_html = bundle.get("pdf_html") or ""
    email_body = bundle.get("email_body_html") or ""

    # PDF page count: byte-stream authoritative (revised heuristic)
    pdf_page_count = _pdf_page_count_from_html(pdf_html)

    pdf_has_risk_status_summary_header = _RISK_STATUS_HEADER in pdf_html
    pdf_rag_cell_count = pdf_html.count(_RAG_CELL_CLASS)

    # Excel tab name set
    wb = bundle.get("excel_workbook")
    excel_tab_names_sorted = sorted([ws.title for ws in wb.worksheets]) if wb else []

    # Email panel count: role="presentation" per panel (verified marker)
    email_panel_count = email_body.count(_PANEL_MARKER)

    inline_cids = sorted({
        img.get("cid", "")
        for img in bundle.get("email_inline_images", [])
        if img.get("cid")
    })

    bundle_keys_present = sorted(bundle.keys())

    analyst_excel = (
        bundle.get("analyst_excel")
        if bundle.get("analyst_excel") is not None
        else bundle.get("analyst_workbook_path")
    )
    analyst_excel_present = analyst_excel is not None

    # rag_cells_all_no_data: every RAG cell band uses STATUS_COLOR['no_data']
    no_data_color = _no_data_color().lower()
    rag_cells_all_no_data = (
        pdf_rag_cell_count > 0
        and pdf_html.lower().count(no_data_color) >= pdf_rag_cell_count
    )

    # panel_drivers_all_no_data_in_scope: count of "No data in scope." occurrences
    # equals panel count
    nd_count = email_body.count(_NO_DATA_DRIVER)
    panel_drivers_all_no_data_in_scope = (
        email_panel_count > 0 and nd_count >= email_panel_count
    )

    return {
        "schema_version": 1,
        "group_slug": group_slug,
        "pdf_page_count": pdf_page_count,
        "pdf_has_risk_status_summary_header": pdf_has_risk_status_summary_header,
        "pdf_rag_cell_count": pdf_rag_cell_count,
        "excel_tab_names_sorted": excel_tab_names_sorted,
        "email_panel_count": email_panel_count,
        "email_inline_image_cids_per_module": inline_cids,
        "bundle_keys_present": bundle_keys_present,
        "analyst_excel_present": analyst_excel_present,
        "rag_cells_all_no_data": rag_cells_all_no_data,
        "panel_drivers_all_no_data_in_scope": panel_drivers_all_no_data_in_scope,
    }


def compare_snapshots(actual: dict, baseline: dict) -> list[str]:
    diffs: list[str] = []
    for k in sorted(baseline.keys()):
        a, b = actual.get(k), baseline[k]
        if a != b:
            diffs.append(f"{k}: actual={a!r} baseline={b!r}")
    for k in sorted(set(actual.keys()) - set(baseline.keys())):
        diffs.append(
            f"{k}: present in actual, missing from baseline "
            f"(was structural-snapshot updated? See tests/baselines/README.md)"
        )
    return diffs


def load_baseline(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_baseline(path: Path, snapshot: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8"
    )
