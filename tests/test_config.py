"""
tests/test_config.py — Unit tests for config.py constants and helpers.

Covers:
  - WR-08: VPR_SEVERITY_MAP band contiguity (no gap drops score to fallback)
  - IN-01: import math must be at module-level, not inside vpr_to_severity
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import config
from config import vpr_to_severity


# ---------------------------------------------------------------------------
# WR-08: Band contiguity — scores in the former gap must resolve correctly
# ---------------------------------------------------------------------------

class TestVprBandContiguity:
    """VPR_SEVERITY_MAP must be gap-free: every score in [0.1, 10.0] maps
    to exactly one named tier without falling to the native fallback."""

    def test_vpr_score_8_95_is_high(self):
        """8.95 was in the old (8.9, 9.0) gap — must map to 'high', not fallback."""
        assert vpr_to_severity(8.95) == "high"

    def test_vpr_score_8_91_is_high(self):
        """8.91 is squarely in the old gap — must map to 'high'."""
        assert vpr_to_severity(8.91) == "high"

    def test_vpr_boundary_9_0_is_critical(self):
        """9.0 is exactly on the critical lower bound — must map to 'critical'."""
        assert vpr_to_severity(9.0) == "critical"

    def test_vpr_score_10_0_is_critical(self):
        """10.0 is the maximum VPR — must map to 'critical'."""
        assert vpr_to_severity(10.0) == "critical"

    def test_vpr_score_7_0_is_high(self):
        """7.0 is the high lower bound — must map to 'high'."""
        assert vpr_to_severity(7.0) == "high"

    def test_vpr_score_8_9_is_high(self):
        """8.9 was the old upper bound — must still map to 'high'."""
        assert vpr_to_severity(8.9) == "high"

    def test_vpr_score_6_95_is_medium(self):
        """6.95 was in the old (6.9, 7.0) gap — must map to 'medium', not fallback."""
        assert vpr_to_severity(6.95) == "medium"

    def test_vpr_score_6_91_is_medium(self):
        """6.91 is squarely in the old gap — must map to 'medium'."""
        assert vpr_to_severity(6.91) == "medium"

    def test_vpr_score_7_0_boundary_is_high_not_medium(self):
        """7.0 must be 'high' (start of high), not 'medium'."""
        assert vpr_to_severity(7.0) == "high"

    def test_vpr_score_4_0_is_medium(self):
        """4.0 is the medium lower bound — must map to 'medium'."""
        assert vpr_to_severity(4.0) == "medium"

    def test_vpr_score_6_9_is_medium(self):
        """6.9 was the old medium upper bound — must still map to 'medium'."""
        assert vpr_to_severity(6.9) == "medium"

    def test_vpr_score_3_95_is_low(self):
        """3.95 was in the old (3.9, 4.0) gap — must map to 'low', not fallback."""
        assert vpr_to_severity(3.95) == "low"

    def test_vpr_score_3_91_is_low(self):
        """3.91 is squarely in the old gap — must map to 'low'."""
        assert vpr_to_severity(3.91) == "low"

    def test_vpr_score_0_1_is_low(self):
        """0.1 is the low lower bound — must map to 'low'."""
        assert vpr_to_severity(0.1) == "low"

    def test_vpr_score_3_9_is_low(self):
        """3.9 was the old low upper bound — must still map to 'low'."""
        assert vpr_to_severity(3.9) == "low"

    def test_vpr_score_0_0_falls_to_fallback(self):
        """0.0 is below all bands — should return the fallback, not a tier name."""
        result = vpr_to_severity(0.0, fallback="info")
        assert result == "info"

    def test_vpr_score_below_low_falls_to_fallback(self):
        """A score below 0.1 (e.g. 0.05) must still fall through to fallback."""
        result = vpr_to_severity(0.05, fallback="info")
        assert result == "info"

    def test_vpr_none_returns_fallback(self):
        """None score must return the fallback."""
        assert vpr_to_severity(None, fallback="medium") == "medium"

    def test_vpr_nan_returns_fallback(self):
        """NaN score must return the fallback."""
        import math
        assert vpr_to_severity(math.nan, fallback="low") == "low"

    def test_vpr_string_score_returns_fallback(self):
        """Non-numeric string must return the fallback."""
        assert vpr_to_severity("not-a-number", fallback="info") == "info"


# ---------------------------------------------------------------------------
# IN-01: math import must be at module level, not inside vpr_to_severity
# ---------------------------------------------------------------------------

class TestMathImportHoisted:
    """import math must live at module-level in config.py, not inside the
    vpr_to_severity function body (IN-01 — hot-path inline import)."""

    def test_math_import_at_module_level(self):
        """config.py must have 'import math' in its module-level imports."""
        config_path = Path(inspect.getfile(config))
        src = config_path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        # Collect all top-level import statements
        top_level_imports = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_level_imports.add(alias.name)
        assert "math" in top_level_imports, (
            "'import math' not found at module top-level in config.py. "
            "It must be hoisted out of vpr_to_severity (IN-01)."
        )

    def test_math_not_imported_inside_vpr_to_severity(self):
        """import math must NOT appear inside the vpr_to_severity function body."""
        config_path = Path(inspect.getfile(config))
        src = config_path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "vpr_to_severity":
                for child in ast.walk(node):
                    if isinstance(child, ast.Import):
                        for alias in child.names:
                            assert alias.name != "math", (
                                "'import math' found inside vpr_to_severity — "
                                "must be hoisted to module level (IN-01)."
                            )
