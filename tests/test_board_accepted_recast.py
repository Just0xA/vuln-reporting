"""
tests/test_board_accepted_recast.py — accepted_recast wired into board_summary.

All fixtures use synthetic data only (QUAL-05 / D-04-08):
  - asset_uuid: "00000000-0000-0000-0000-00000000000N"
  - recast_rule_uuid: "00000000-0000-0000-0000-00000000000N"
  - plugin_id: 100001, 100002, ...
  - owner names: "Engineering", "Operations"
  - No real hostnames, IPs, CVE IDs, plugin names, or real Tenable UUIDs

Key requirement coverage
-------------------------
- accepted_recast is present in board_summary._board_module_configs() output
- Running accepted_recast's compute() with synthetic board-style fixtures
  produces all four channels: a non-empty render_pdf_section, at least one
  analyst/excel tab, and a populated (non "No Data") rag_strip entry

Pandas CoW strict mode enforced at module level.
"""

from __future__ import annotations

import datetime

import pandas as pd
import pytest

# Enforce pandas CoW strict mode — catches ChainedAssignmentError / FutureWarning
pd.options.mode.copy_on_write = True

import openpyxl

import reports.board_summary as bs
from reports.modules.base import ModuleConfig
from reports.modules.accepted_recast_module import AcceptedRecastModule

_UUID_PREFIX = "00000000-0000-0000-0000-00000000000"
_REPORT_DATE = datetime.datetime(2026, 6, 11, tzinfo=datetime.timezone.utc)


def _uuid(n: int) -> str:
    return f"{_UUID_PREFIX}{n}"


def _make_vulns(rows: list[dict]) -> pd.DataFrame:
    defaults = {
        "state":                       "OPEN",
        "first_found":                 "2026-01-01T00:00:00Z",
        "plugin_id":                   100001,
        "asset_uuid":                  _uuid(1),
        "severity":                    "high",
        "severity_modification_type":  "NONE",
        "recast_rule_uuid":            "",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_assets(rows: list[dict]) -> pd.DataFrame:
    defaults = {"asset_uuid": _uuid(1), "tags": ""}
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


def _make_recast_rules(rows: list[dict]) -> pd.DataFrame:
    defaults = {
        "rule_id":           _uuid(1),
        "rule_name":         "Test Rule",
        "plugin_id":         None,
        "action":            "ACCEPT",
        "new_severity":      None,
        "original_severity": "high",
        "expires_at":        None,
        "created_at":        "2026-01-01T00:00:00Z",
    }
    records = [{**defaults, **r} for r in rows]
    return pd.DataFrame(records, columns=list(defaults.keys()))


class TestBoardModuleConfigs:
    def test_accepted_recast_present_in_board_module_configs(self):
        # quick-260813-ga2 — _BOARD_MODULE_CONFIGS became a per-call factory
        # (_board_module_configs) so options never leak across runs.
        for include_risk_managed in (False, True):
            module_ids = [
                cfg.module_id
                for cfg in bs._board_module_configs(include_risk_managed)
            ]
            assert "accepted_recast" in module_ids


class TestAcceptedRecastFourChannelInBoardContext:
    """
    Run accepted_recast's compute() with synthetic board-style fixtures
    (vulns_df + assets_df + recast_rules_df + trend_snapshots — the same
    shape board_summary.py forwards via ReportComposer kwargs fan-out) and
    verify it produces all four channels.
    """

    def _compute(self) -> "pd.Series":
        vulns_df = _make_vulns([
            {"plugin_id": 100001, "asset_uuid": _uuid(1),
             "severity_modification_type": "ACCEPTED", "recast_rule_uuid": _uuid(1)},
            {"plugin_id": 100002, "asset_uuid": _uuid(1),
             "severity_modification_type": "ACCEPTED", "recast_rule_uuid": _uuid(1)},
            {"plugin_id": 100003, "asset_uuid": _uuid(2),
             "severity_modification_type": "RECASTED", "recast_rule_uuid": _uuid(2)},
            {"plugin_id": 100004, "asset_uuid": _uuid(1),
             "severity_modification_type": "NONE"},
        ])
        assets_df = _make_assets([
            {"asset_uuid": _uuid(1), "tags": "Owner=Engineering"},
            {"asset_uuid": _uuid(2), "tags": "Owner=Operations"},
        ])
        recast_rules_df = _make_recast_rules([
            {"rule_id": _uuid(1), "action": "ACCEPT"},
            {"rule_id": _uuid(2), "action": "RECAST"},
        ])
        trend_snapshots = {"snapshots": [], "insufficient_data": True}

        mod = AcceptedRecastModule()
        cfg = ModuleConfig("accepted_recast")
        return mod.compute(
            vulns_df, assets_df, _REPORT_DATE, cfg,
            recast_rules_df=recast_rules_df,
            trend_snapshots=trend_snapshots,
        )

    def test_pdf_section_non_empty(self):
        data   = self._compute()
        result = AcceptedRecastModule().render_pdf_section(data, ModuleConfig("accepted_recast"))
        assert isinstance(result, str)
        assert len(result) > 0

    def test_at_least_one_analyst_or_excel_tab(self):
        data = self._compute()
        cfg  = ModuleConfig("accepted_recast")

        analyst_tabs = AcceptedRecastModule().render_analyst_tabs(data, cfg)
        workbook     = openpyxl.Workbook()
        excel_tabs   = AcceptedRecastModule().render_excel_tabs(data, workbook, cfg)

        assert len(analyst_tabs) > 0 or len(excel_tabs) > 0

    def test_rag_strip_populated_not_no_data(self):
        data = self._compute()
        rag  = data.rag_strip
        assert rag.get("label")
        assert rag.get("rag_color")
        assert rag.get("rag_label") != "No Data"
