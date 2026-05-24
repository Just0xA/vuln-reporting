"""
tests/unit/test_modules.py — Layer 1 four-channel contract per registered module.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from openpyxl import Workbook

from reports.modules import registry
from reports.modules.base import ModuleConfig, ModuleData

pytestmark = pytest.mark.unit

_NOW = datetime.now(tz=timezone.utc)
MODULE_IDS = [m["module_id"] for m in registry.list_all()]


def _compute(module_id, vulns_df, assets_df):
    inst = registry.get(module_id)()
    return inst, inst.compute(vulns_df, assets_df, _NOW, ModuleConfig(module_id))


def test_registry_is_not_empty():
    assert MODULE_IDS, "registry.discover() found no modules"


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_compute_returns_moduledata(module_id, synthetic_vulns_df, synthetic_assets_df):
    _, data = _compute(module_id, synthetic_vulns_df, synthetic_assets_df)
    assert isinstance(data, ModuleData)


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_four_channel_types(module_id, synthetic_vulns_df, synthetic_assets_df):
    inst, data = _compute(module_id, synthetic_vulns_df, synthetic_assets_df)
    cfg = ModuleConfig(module_id)
    assert isinstance(inst.render_pdf_section(data, cfg), str)
    assert isinstance(inst.render_excel_tabs(data, Workbook(), cfg), list)
    assert isinstance(inst.render_email_panel(data, cfg), str)
    assert isinstance(inst.render_analyst_tabs(data, cfg), list)
    strip = inst.render_rag_strip_entry(data, cfg)
    assert isinstance(strip, dict)
    assert {"label", "headline_value", "rag_color", "rag_label"} <= set(strip)


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_empty_data_guard(module_id, empty_vulns_df, empty_assets_df):
    """Zero-row input must not raise in compute() or any renderer."""
    inst, data = _compute(module_id, empty_vulns_df, empty_assets_df)
    cfg = ModuleConfig(module_id)
    assert isinstance(data, ModuleData)
    inst.render_pdf_section(data, cfg)
    inst.render_excel_tabs(data, Workbook(), cfg)
    inst.render_email_panel(data, cfg)
    inst.render_analyst_tabs(data, cfg)
    inst.render_rag_strip_entry(data, cfg)
