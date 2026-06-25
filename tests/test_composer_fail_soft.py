"""
Regression tests for composer fail-soft hardening (CR-F1 / CR-F2).

CR-F1: assemble_pdf() must not crash when a module's render_pdf_section()
       returns a non-string value (None, int, …).  The bad return is
       silently converted to "" and the rest of the PDF assembles normally.

CR-F2: assemble_analyst_workbook() must still emit a workbook containing a
       _Metadata tab when every module FAILED (collected is empty but failures
       is non-empty).

Baseline: when collected is empty AND failures is empty (genuinely no data),
          assemble_analyst_workbook() returns None — original behaviour preserved.

All fixtures are synthetic (QUAL-05 — no real hostnames, IPs, or plugin names).
"""

from __future__ import annotations

import datetime
import pathlib

import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Helpers to build a minimal ReportComposer without touching real data
# ---------------------------------------------------------------------------

from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules import register_module, registry
from reports.modules.composer import ReportComposer


_UTC = datetime.timezone.utc
_REPORT_DATE = datetime.datetime(2026, 1, 15, 0, 0, 0, tzinfo=_UTC)


def _make_composer(module_configs: list[ModuleConfig]) -> ReportComposer:
    """Return a ReportComposer wired with synthetic config (empty DataFrames)."""
    return ReportComposer(
        vulns_df=pd.DataFrame(),
        assets_df=pd.DataFrame(),
        report_date=_REPORT_DATE,
        module_configs=module_configs,
    )


def _stub_data(module_id: str, display_name: str = "Stub") -> ModuleData:
    """Return a minimal ModuleData for a stub module."""
    return ModuleData(
        module_id=module_id,
        display_name=display_name,
        metrics={},
        table_data=[],
        chart_data={},
        summary_text="stub",
        metadata={},
    )


# ---------------------------------------------------------------------------
# CR-F1 — non-string return from render_pdf_section()
# ---------------------------------------------------------------------------

# Use a unique module_id so repeated test collection doesn't re-register.
_NON_STRING_ID = "stub_non_string_pdf_f1"


@register_module
class _NonStringPdfModule(BaseModule):
    """Stub that returns None from render_pdf_section() — triggers CR-F1."""

    MODULE_ID    = _NON_STRING_ID
    DISPLAY_NAME = "Stub Non-String PDF"

    def compute(self, *args, **kwargs) -> ModuleData:  # type: ignore[override]
        return _stub_data(self.MODULE_ID, self.DISPLAY_NAME)

    def render_pdf_section(self, data: ModuleData, config: ModuleConfig) -> None:  # type: ignore[return]
        return None  # intentionally wrong return type


_GOOD_PDF_ID = "stub_good_pdf_f1"


@register_module
class _GoodPdfModule(BaseModule):
    """Stub that returns a valid HTML string from render_pdf_section()."""

    MODULE_ID    = _GOOD_PDF_ID
    DISPLAY_NAME = "Stub Good PDF"

    def compute(self, *args, **kwargs) -> ModuleData:  # type: ignore[override]
        return _stub_data(self.MODULE_ID, self.DISPLAY_NAME)

    def render_pdf_section(self, data: ModuleData, config: ModuleConfig) -> str:
        return "<p>Good module output</p>"


def test_non_string_pdf_section_safe(tmp_path: pathlib.Path) -> None:
    """
    CR-F1: a module returning None from render_pdf_section() must not raise.
    The other (good) module's section must still appear in the assembled PDF.
    """
    configs = [
        ModuleConfig(_NON_STRING_ID),
        ModuleConfig(_GOOD_PDF_ID),
    ]
    composer = _make_composer(configs)

    # Build synthetic results directly (no real compute() call needed).
    results = [
        _stub_data(_NON_STRING_ID, "Stub Non-String PDF"),
        _stub_data(_GOOD_PDF_ID,   "Stub Good PDF"),
    ]

    # assemble_pdf returns an HTML string — must not raise.
    html = composer.assemble_pdf(
        results=results,
        subtitle="Test subtitle",
    )

    assert isinstance(html, str), "assemble_pdf must return a string"
    assert "Good module output" in html, (
        "The good module's output must still appear in the assembled PDF "
        "even when the sibling module returned a non-string section."
    )


# ---------------------------------------------------------------------------
# CR-F2 — all modules failed → _Metadata tab still written
# ---------------------------------------------------------------------------

_ALWAYS_FAILS_ID = "stub_always_fails_f2"


@register_module
class _AlwaysFailsModule(BaseModule):
    """Stub whose render_analyst_tabs() always raises — simulates a crash."""

    MODULE_ID    = _ALWAYS_FAILS_ID
    DISPLAY_NAME = "Stub Always Fails"

    def compute(self, *args, **kwargs) -> ModuleData:  # type: ignore[override]
        return _stub_data(self.MODULE_ID, self.DISPLAY_NAME)

    def render_analyst_tabs(
        self, data: ModuleData, config: ModuleConfig
    ) -> list:
        raise RuntimeError("Intentional render_analyst_tabs failure (CR-F2 test)")


def test_metadata_tab_on_all_modules_failed(tmp_path: pathlib.Path) -> None:
    """
    CR-F2: when every module's render_analyst_tabs() raises, assemble_analyst_workbook()
    must still write a workbook containing a _Metadata sheet (failure audit).
    """
    import openpyxl  # noqa: PLC0415 — deferred import mirrors composer convention

    configs  = [ModuleConfig(_ALWAYS_FAILS_ID)]
    composer = _make_composer(configs)
    results  = [_stub_data(_ALWAYS_FAILS_ID, "Stub Always Fails")]

    output_path = tmp_path / "all_failed_analyst.xlsx"
    returned_path = composer.assemble_analyst_workbook(
        results=results,
        output_path=output_path,
        slug="test_slug",
        scope_label="Test Scope",
    )

    assert returned_path is not None, (
        "assemble_analyst_workbook must return a Path (not None) when all modules "
        "failed, so the _Metadata tab with the failure audit is written."
    )
    assert output_path.exists(), "Workbook file must exist on disk."

    wb = openpyxl.load_workbook(str(output_path))
    assert "_Metadata" in wb.sheetnames, (
        "_Metadata tab must be present in the workbook even when all modules failed."
    )


# ---------------------------------------------------------------------------
# Baseline: genuinely empty (no failures) → returns None
# ---------------------------------------------------------------------------

_EMPTY_TABS_ID = "stub_empty_tabs_f2_baseline"


@register_module
class _EmptyTabsModule(BaseModule):
    """Stub that returns an empty list from render_analyst_tabs() — no data, no failure."""

    MODULE_ID    = _EMPTY_TABS_ID
    DISPLAY_NAME = "Stub Empty Tabs"

    def compute(self, *args, **kwargs) -> ModuleData:  # type: ignore[override]
        return _stub_data(self.MODULE_ID, self.DISPLAY_NAME)

    def render_analyst_tabs(
        self, data: ModuleData, config: ModuleConfig
    ) -> list:
        return []  # no tabs, no error — genuinely empty


def test_no_data_still_returns_none(tmp_path: pathlib.Path) -> None:
    """
    Baseline: when collected is empty AND failures is empty, assemble_analyst_workbook()
    must return None (no file written) — original D-20 no-data behaviour preserved.
    """
    configs  = [ModuleConfig(_EMPTY_TABS_ID)]
    composer = _make_composer(configs)
    results  = [_stub_data(_EMPTY_TABS_ID, "Stub Empty Tabs")]

    output_path = tmp_path / "no_data_analyst.xlsx"
    returned_path = composer.assemble_analyst_workbook(
        results=results,
        output_path=output_path,
        slug="test_slug",
        scope_label="Test Scope",
    )

    assert returned_path is None, (
        "assemble_analyst_workbook must return None when there are no data tabs "
        "and no failures — original D-20 no-data behaviour must be preserved."
    )
    assert not output_path.exists(), "No workbook file should be written for no-data path."
