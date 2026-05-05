"""
reports/modules/rag_utils.py — Shared RAG (Red/Amber/Green) palette and
cover-page strip helpers for module-based reports.

This module is the neutrally-named home for the RAG status colors, labels,
and the convenience `build_rag_strip_entry()` constructor used by the
cover-page strip in board-style and management-style composed reports.

It is intentionally NOT registered as a BaseModule; these are pure helpers
imported directly by metric modules and by `BaseModule.render_rag_strip_entry()`'s
no-op default.

Public exports
--------------
- ``STATUS_COLOR``         — dict[str, str] of green/yellow/red/no_data hex colors
- ``STATUS_LABEL``         — dict[str, str] of "On Target"/"At Risk"/"Off Target"/"No Data"
- ``rag_status_from_value`` — wrapper around board_report_utils.sla_status_from_thresholds
- ``build_rag_strip_entry`` — convenience constructor for the strip cell dict
- ``NO_DATA_HEADLINE``     — sentinel "—" string for missing values
- ``NO_DATA_DRIVER``       — sentinel "No data in scope." driver-narrative string
"""

from __future__ import annotations

import logging
from typing import Optional

from reports.modules.board_report_utils import sla_status_from_thresholds

logger = logging.getLogger(__name__)


# ===========================================================================
# Module-level constants
# ===========================================================================

#: Hex colors for RAG status keys. Mirrors the per-module _STATUS_COLOR
#: dicts that already exist in scan_coverage_sla_module.py and the other
#: three board metric modules. Phase 1 ships this as a shared copy;
#: Phase 3 migrates the four board modules to use it.
STATUS_COLOR: dict[str, str] = {
    "green":   "#388e3c",
    "yellow":  "#f57c00",
    "red":     "#d32f2f",
    "no_data": "#757575",
}

#: Display labels for RAG status keys.
STATUS_LABEL: dict[str, str] = {
    "green":   "On Target",
    "yellow":  "At Risk",
    "red":     "Off Target",
    "no_data": "No Data",
}

#: Sentinel headline value used when a metric has no data in scope.
NO_DATA_HEADLINE: str = "—"

#: Sentinel driver-narrative used when a metric has no data in scope.
NO_DATA_DRIVER: str = "No data in scope."


# ===========================================================================
# RAG status classification
# ===========================================================================

def rag_status_from_value(
    value:            Optional[float],
    green_threshold:  float,
    yellow_threshold: float,
    direction:        str = "higher_is_better",
) -> str:
    """
    Classify a metric value as green / yellow / red / no_data.

    Thin neutrally-named wrapper around
    ``board_report_utils.sla_status_from_thresholds`` so management-summary
    and any future non-board modules can adopt RAG without importing from a
    board-prefixed file. Both call sites coexist until v2 cleanup.

    Parameters
    ----------
    value : float or None
        The metric value to classify.  ``None`` → ``"no_data"``.
    green_threshold : float
        Boundary between green and yellow.
    yellow_threshold : float
        Boundary between yellow and red.
    direction : str
        ``"higher_is_better"`` (default) or ``"lower_is_better"``.

    Returns
    -------
    str
        One of ``"green"``, ``"yellow"``, ``"red"``, ``"no_data"``.
    """
    return sla_status_from_thresholds(
        value=value,
        green_threshold=green_threshold,
        yellow_threshold=yellow_threshold,
        direction=direction,
    )


# ===========================================================================
# Strip cell construction
# ===========================================================================

def build_rag_strip_entry(
    display_name:       str,
    headline_value_str: str,
    status:             str,
) -> dict:
    """
    Build the cover-page RAG-strip cell dict for a single module.

    Parameters
    ----------
    display_name : str
        Human-readable label (typically ``self.DISPLAY_NAME``).
    headline_value_str : str
        Pre-formatted headline (e.g. ``"87.4%"``, ``"12 assets"``, ``"—"``).
        Module owns its own display formatting; the composer plops this
        string directly into the strip cell.
    status : str
        One of ``"green"``, ``"yellow"``, ``"red"``, ``"no_data"``.
        Unknown values fall back to ``"no_data"``.

    Returns
    -------
    dict
        Strip cell dict with keys ``label``, ``headline_value``,
        ``rag_color``, ``rag_label`` per CONTRACT-03.

    Examples
    --------
    >>> build_rag_strip_entry("Scan Coverage SLA", "97.2%", "green")
    {'label': 'Scan Coverage SLA', 'headline_value': '97.2%',
     'rag_color': '#388e3c', 'rag_label': 'On Target'}
    """
    if status not in STATUS_COLOR:
        status = "no_data"
    return {
        "label":          display_name,
        "headline_value": headline_value_str,
        "rag_color":      STATUS_COLOR[status],
        "rag_label":      STATUS_LABEL[status],
    }
