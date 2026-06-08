"""
tests/unit/test_tag_severity_share.py — Unit tests for TagSeverityShareModule.

Covers:
- VPR -> bucket mapper (_bucket_severity): boundary values + None/NaN/0.0/"" edge cases.
- env-share math: per-severity pct = tag_count / env_vuln_total * 100; /0 guard;
  five severity pcts sum to tag_share_pct.
- No native-severity fallback path (D3).
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

import pandas as pd
import pytest

from reports.modules.tag_severity_share_module import _bucket_severity, TagSeverityShareModule
from reports.modules.base import ModuleConfig, ModuleData

pytestmark = pytest.mark.unit

_NOW = datetime.now(tz=timezone.utc)


# ===========================================================================
# VPR -> bucket mapper
# ===========================================================================

@pytest.mark.parametrize("vpr_score,expected_bucket", [
    # Critical boundary values
    (9.0,  "critical"),
    (9.5,  "critical"),
    (10.0, "critical"),
    # High boundary values
    (7.0,  "high"),
    (8.0,  "high"),
    (8.9,  "high"),
    # Medium boundary values
    (4.0,  "medium"),
    (5.5,  "medium"),
    (6.9,  "medium"),
    # Low boundary values
    (0.1,  "low"),
    (2.0,  "low"),
    (3.9,  "low"),
    # None bucket — null/NaN/0.0/"" (D2, D3 — no native fallback)
    (None,        "none"),
    (float("nan"), "none"),
    (0.0,         "none"),
    ("",          "none"),
    # Non-numeric string — no native fallback
    ("critical",  "none"),
    ("high",      "none"),
    # pd.NA
    (pd.NA,       "none"),
    # pd.NaT-like
    (pd.NaT,      "none"),
])
def test_bucket_severity(vpr_score, expected_bucket):
    assert _bucket_severity(vpr_score) == expected_bucket, (
        f"_bucket_severity({vpr_score!r}) expected {expected_bucket!r}"
    )


def test_no_native_fallback_for_string_severity():
    """Native severity strings must never produce a non-none bucket."""
    for native in ("critical", "high", "medium", "low", "Critical", "HIGH"):
        assert _bucket_severity(native) == "none", (
            f"_bucket_severity({native!r}) should be 'none' — no native fallback (D3)"
        )


# ===========================================================================
# env-share math
# ===========================================================================

def _make_vulns_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal vulns DataFrame for testing."""
    return pd.DataFrame(rows)


def _run_compute(vulns_df: pd.DataFrame, env_vuln_total: int) -> ModuleData:
    inst = TagSeverityShareModule()
    return inst.compute(
        vulns_df,
        pd.DataFrame(),
        _NOW,
        ModuleConfig("tag_severity_share"),
        env_vuln_total=env_vuln_total,
    )


class TestEnvShareMath:

    def test_per_severity_pct_math(self):
        """Each severity pct = tag_count[sev] / env_vuln_total * 100."""
        df = _make_vulns_df([
            {"state": "open",     "vpr_score": 9.5},   # critical
            {"state": "open",     "vpr_score": 7.5},   # high
            {"state": "open",     "vpr_score": 5.0},   # medium
            {"state": "open",     "vpr_score": 2.0},   # low
            {"state": "open",     "vpr_score": None},  # none
            {"state": "fixed",    "vpr_score": 9.0},   # excluded
        ])
        env_total = 100
        data = _run_compute(df, env_total)

        assert data.error is None
        m = data.metrics

        assert m["critical_count"] == 1
        assert m["high_count"]     == 1
        assert m["medium_count"]   == 1
        assert m["low_count"]      == 1
        assert m["none_count"]     == 1
        assert m["tag_total"]      == 5

        assert pytest.approx(m["critical_pct"], rel=1e-5) == 1.0
        assert pytest.approx(m["high_pct"],     rel=1e-5) == 1.0
        assert pytest.approx(m["medium_pct"],   rel=1e-5) == 1.0
        assert pytest.approx(m["low_pct"],      rel=1e-5) == 1.0
        assert pytest.approx(m["none_pct"],     rel=1e-5) == 1.0

    def test_divide_by_zero_guard(self):
        """env_vuln_total == 0 must not raise and must yield 0.0 pcts."""
        df = _make_vulns_df([
            {"state": "open", "vpr_score": 9.5},
        ])
        data = _run_compute(df, env_vuln_total=0)
        assert data.error is None
        for sev in ("critical", "high", "medium", "low", "none"):
            assert data.metrics[f"{sev}_pct"] == 0.0
        assert data.metrics["tag_share_pct"] == 0.0

    def test_pcts_sum_to_tag_share_pct(self):
        """Sum of the five per-severity pcts must equal tag_share_pct."""
        df = _make_vulns_df([
            {"state": "open",     "vpr_score": 9.0},   # critical
            {"state": "open",     "vpr_score": 7.0},   # high
            {"state": "reopened", "vpr_score": 5.5},   # medium
            {"state": "open",     "vpr_score": 1.5},   # low
            {"state": "open",     "vpr_score": 0.0},   # none
        ])
        env_total = 200
        data = _run_compute(df, env_total)
        assert data.error is None

        m          = data.metrics
        pct_sum    = sum(m[f"{s}_pct"] for s in ("critical", "high", "medium", "low", "none"))
        tag_share  = m["tag_share_pct"]
        assert pytest.approx(pct_sum, rel=1e-9) == tag_share

    def test_reopened_included_in_tag_total(self):
        """'reopened' state findings must be included, 'fixed' excluded."""
        df = _make_vulns_df([
            {"state": "open",     "vpr_score": 9.5},
            {"state": "reopened", "vpr_score": 9.5},
            {"state": "fixed",    "vpr_score": 9.5},
        ])
        data = _run_compute(df, env_vuln_total=50)
        assert data.metrics["tag_total"] == 2
        assert data.metrics["critical_count"] == 2

    def test_empty_vulns_df_no_raise(self):
        """Zero-row input must not raise; metrics must be all-zero."""
        data = _run_compute(pd.DataFrame(columns=["state", "vpr_score"]), env_vuln_total=0)
        assert data.error is None
        assert data.metrics["tag_total"] == 0
        assert data.metrics["tag_share_pct"] == 0.0

    def test_env_vuln_total_forwarded_in_metrics(self):
        """env_vuln_total passed via kwargs must appear in returned metrics."""
        df = _make_vulns_df([{"state": "open", "vpr_score": 9.0}])
        data = _run_compute(df, env_vuln_total=999)
        assert data.metrics["env_vuln_total"] == 999

    def test_nan_vpr_bucketed_to_none_no_native_fallback(self):
        """NaN vpr_score must land in none bucket — NOT promoted via native severity."""
        df = _make_vulns_df([
            {"state": "open", "vpr_score": float("nan")},
        ])
        data = _run_compute(df, env_vuln_total=10)
        assert data.error is None
        assert data.metrics["none_count"] == 1
        assert data.metrics["critical_count"] == 0

    def test_zero_vpr_bucketed_to_none(self):
        """vpr_score == 0.0 must land in none bucket (D2)."""
        df = _make_vulns_df([
            {"state": "open", "vpr_score": 0.0},
        ])
        data = _run_compute(df, env_vuln_total=10)
        assert data.metrics["none_count"] == 1
        assert data.metrics["low_count"] == 0


# ===========================================================================
# Four-channel contract — zero-row empty-data guard
# ===========================================================================

class TestEmptyDataGuard:

    def test_empty_df_all_channels_no_raise(self):
        """Zero-row tag scope must render all four channels without raising."""
        from openpyxl import Workbook

        inst = TagSeverityShareModule()
        empty_df = pd.DataFrame(columns=["state", "vpr_score"])
        data = inst.compute(empty_df, pd.DataFrame(), _NOW, ModuleConfig("tag_severity_share"))
        cfg  = ModuleConfig("tag_severity_share")

        pdf   = inst.render_pdf_section(data, cfg)
        tabs  = inst.render_excel_tabs(data, Workbook(), cfg)
        panel = inst.render_email_panel(data, cfg)
        atabs = inst.render_analyst_tabs(data, cfg)
        strip = inst.render_rag_strip_entry(data, cfg)

        assert isinstance(pdf,   str)
        assert isinstance(tabs,  list)
        assert isinstance(panel, str)
        assert isinstance(atabs, list)
        assert isinstance(strip, dict)
        assert {"label", "headline_value", "rag_color", "rag_label"} <= set(strip)

    def test_empty_df_strip_is_no_data(self):
        """Zero-row tag scope must produce a gray 'No Data' RAG strip cell."""
        inst = TagSeverityShareModule()
        empty_df = pd.DataFrame(columns=["state", "vpr_score"])
        data  = inst.compute(empty_df, pd.DataFrame(), _NOW, ModuleConfig("tag_severity_share"))
        strip = inst.render_rag_strip_entry(data, ModuleConfig("tag_severity_share"))
        assert strip["rag_label"] == "No Data"
        assert strip["headline_value"] == "—"
