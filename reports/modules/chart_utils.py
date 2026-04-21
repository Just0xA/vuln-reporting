"""
reports/modules/chart_utils.py — Shared Matplotlib chart utilities for report modules.

Provides the ``draw_gauge()`` semicircular gauge function and its supporting
helpers.  Any report module that renders a gauge should import from here
rather than duplicating the implementation.

Usage
-----
::

    from reports.modules.chart_utils import draw_gauge

    b64_png = draw_gauge(
        value=87.3,
        min_val=0,
        max_val=100,
        thresholds=[(75, "#d32f2f"), (90, "#fbc02d"), (100, "#388e3c")],
        title="Patch Compliance",
        unit="%",
    )
    # Embed in HTML:
    # <img src="data:image/png;base64,{b64_png}" style="width:100%;max-width:500px;">

Notes
-----
- This module applies the matplotlib.path deepcopy compatibility patch at
  import time.  It is safe to import chart_utils in any report module
  regardless of whether the caller also imports matplotlib directly.
- All gauge rendering is done with a non-interactive Agg backend.
  ``matplotlib.use("Agg")`` is called once at module level.
"""

from __future__ import annotations

import base64
import io
import math
from typing import Optional

import matplotlib
matplotlib.use("Agg")   # Non-interactive backend — must precede pyplot import
import matplotlib.pyplot as plt
import matplotlib.path as _mpath
from matplotlib.patches import Wedge

# ---------------------------------------------------------------------------
# Python 3.14 / matplotlib compatibility patch
# matplotlib.path.Path.__deepcopy__ calls copy.deepcopy(super(), memo) which
# recurses infinitely in Python 3.14.  Replace it with a direct constructor
# copy that only copies the data arrays — no deepcopy chain involved.
# Applying the patch more than once is harmless (idempotent reassignment).
# ---------------------------------------------------------------------------

def _safe_path_deepcopy(self, memo):  # type: ignore[override]
    return _mpath.Path(
        self.vertices.copy(),
        self.codes.copy() if self.codes is not None else None,
        self._interpolation_steps,
        self.should_simplify,
        self.simplify_threshold,
    )


_mpath.Path.__deepcopy__ = _safe_path_deepcopy  # type: ignore[method-assign]


# ===========================================================================
# Private helpers
# ===========================================================================

def _val_to_angle(v: float, min_val: float, max_val: float) -> float:
    """
    Map a gauge value to a matplotlib angle in degrees.

    The gauge arc spans the upper semicircle:
        180°  = left  = min_val
         90°  = top   = midpoint
          0°  = right = max_val

    The returned angle is clamped so the needle never escapes the arc.
    """
    if max_val == min_val:
        return 90.0
    fraction = max(0.0, min(1.0, (v - min_val) / (max_val - min_val)))
    return 180.0 - fraction * 180.0


def _fmt_gauge_label(v: float) -> str:
    """Format a gauge range-end label (e.g. 0 → '0', 100 → '100', 37.5 → '37.5')."""
    return str(int(v)) if v == int(v) else f"{v:.1f}"


# ===========================================================================
# Public API
# ===========================================================================

def draw_gauge(
    value: float,
    min_val: float = 0,
    max_val: float = 100,
    thresholds: Optional[list[tuple[float, str]]] = None,
    title: str = "",
    unit: str = "%",
    reference_line: Optional[float] = None,
    reference_label: Optional[str] = None,
    figsize: tuple = (3, 2),
) -> str:
    """
    Draw a semicircular gauge using Matplotlib and return a base64 PNG string.

    Parameters
    ----------
    value : float
        Current value to display.  Clamped to [min_val, max_val].
    min_val, max_val : float
        Gauge range.  Defaults 0–100.
    thresholds : list of (threshold_value, hex_color), optional
        Defines colour zones from min to max.  Each tuple means
        "from the previous threshold up to threshold_value, use this colour."
        Example: [(75, '#d32f2f'), (90, '#fbc02d'), (100, '#388e3c')]
        → 0–75 red, 75–90 amber, 90–100 green.
        If None, the arc is drawn in a neutral grey.
    title : str
        Label displayed below the gauge value.
    unit : str
        Suffix appended to the displayed value (default ``"%"``).
        Pass ``"d"`` for day-based MTTR gauges.
    reference_line : float, optional
        Draw a prominent tick mark at this value on the arc.
        Used to show the SLA target on MTTR gauges.
    reference_label : str, optional
        Short label for the reference tick (e.g. ``"SLA"``).
    figsize : tuple
        Matplotlib figure size in inches.  Default ``(3, 2)``.

    Returns
    -------
    str
        Base64-encoded PNG for inline embedding::

            <img src="data:image/png;base64,{result}"
                 style="width:100%; max-width:500px;">

    Notes
    -----
    - White background (``facecolor='white'``).
    - Rendered at 150 dpi for PDF clarity.
    - Figure is closed with ``plt.close(fig)`` immediately after encoding
      to prevent memory accumulation during batch runs.
    """
    value_clamped = max(float(min_val), min(float(max_val), float(value)))

    # ---- Determine the zone colour the current value falls in ---------------
    value_color = "#2E75B6"   # default: project navy
    if thresholds:
        lo = float(min_val)
        for thresh_val, color in thresholds:
            if lo <= value_clamped <= float(thresh_val):
                value_color = color
                break
            lo = float(thresh_val)
        else:
            # value is above all defined threshold upper-bounds — use last color
            value_color = thresholds[-1][1]

    # ---- Figure setup -------------------------------------------------------
    fig, ax = plt.subplots(figsize=figsize, facecolor="white")
    ax.set_aspect("equal")
    # Data coordinates chosen so the semicircle fits cleanly with room for
    # value text (below center) and title text (bottom).
    ax.set_xlim(-0.62, 0.62)
    ax.set_ylim(-0.30, 0.60)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    center  = (0.0, 0.0)
    r_outer = 0.50
    r_inner = 0.32
    arc_w   = r_outer - r_inner
    arc_mid = (r_inner + r_outer) / 2.0   # midpoint radius for needle length

    # ---- Background (full grey arc) -----------------------------------------
    ax.add_patch(
        Wedge(center, r_outer, 0, 180, width=arc_w,
              facecolor="#E0E0E0", edgecolor="none")
    )

    # ---- Coloured zone arcs -------------------------------------------------
    if thresholds:
        lo_val = float(min_val)
        zones: list[tuple[float, float, str]] = []
        for thresh_val, color in thresholds:
            hi_val = min(float(thresh_val), float(max_val))
            if hi_val > lo_val:
                zones.append((lo_val, hi_val, color))
            lo_val = float(thresh_val)
        # Any gap between last threshold and max_val gets the last color
        if lo_val < float(max_val):
            zones.append((lo_val, float(max_val), thresholds[-1][1]))

        for lo_v, hi_v, color in zones:
            # Angles: higher angle (left) corresponds to lower value
            a_left  = _val_to_angle(lo_v, min_val, max_val)
            a_right = _val_to_angle(hi_v, min_val, max_val)
            if a_left > a_right:          # always true for a left-to-right gauge
                ax.add_patch(
                    Wedge(center, r_outer, a_right, a_left,
                          width=arc_w, facecolor=color,
                          edgecolor="none", linewidth=0)
                )

    # ---- Thin boundary rings (visual polish) --------------------------------
    for r, w in ((r_outer, 0.007), (r_inner, 0.007)):
        ax.add_patch(
            Wedge(center, r, 0, 180, width=w,
                  facecolor="#BDBDBD", edgecolor="none")
        )

    # ---- Reference line (e.g. SLA target tick) ------------------------------
    if reference_line is not None and min_val <= reference_line <= max_val:
        ref_rad = math.radians(_val_to_angle(reference_line, min_val, max_val))
        # Draw tick that extends slightly inside and outside the arc band
        rx1 = center[0] + (r_inner - 0.03) * math.cos(ref_rad)
        ry1 = center[1] + (r_inner - 0.03) * math.sin(ref_rad)
        rx2 = center[0] + (r_outer + 0.03) * math.cos(ref_rad)
        ry2 = center[1] + (r_outer + 0.03) * math.sin(ref_rad)
        ax.plot([rx1, rx2], [ry1, ry2],
                color="#212121", linewidth=2.5,
                solid_capstyle="round", zorder=7)
        if reference_label:
            lx = center[0] + (r_outer + 0.12) * math.cos(ref_rad)
            ly = center[1] + (r_outer + 0.12) * math.sin(ref_rad)
            ax.text(lx, ly, reference_label,
                    ha="center", va="center",
                    fontsize=6, color="#212121", fontweight="bold")

    # ---- Needle -------------------------------------------------------------
    needle_rad = math.radians(_val_to_angle(value_clamped, min_val, max_val))
    nx = center[0] + arc_mid * math.cos(needle_rad)
    ny = center[1] + arc_mid * math.sin(needle_rad)
    ax.plot([center[0], nx], [center[1], ny],
            color="#212121", linewidth=2.0,
            solid_capstyle="round", zorder=8)

    # Pivot: dark ring + light centre dot for a clean rivet look
    ax.add_patch(plt.Circle(center, 0.032, color="#212121", zorder=9))
    ax.add_patch(plt.Circle(center, 0.018, color="#F5F5F5", zorder=10))

    # ---- Arc endpoint labels (min / max) ------------------------------------
    ax.text(center[0] - r_outer - 0.07, center[1] - 0.04,
            _fmt_gauge_label(min_val),
            ha="center", va="center", fontsize=6.5, color="#757575")
    ax.text(center[0] + r_outer + 0.07, center[1] - 0.04,
            _fmt_gauge_label(max_val),
            ha="center", va="center", fontsize=6.5, color="#757575")

    # ---- Value text (large, bold, zone-coloured) ----------------------------
    val_rounded = round(value, 1)
    if unit:
        disp_val = (
            f"{int(round(value))}{unit}"
            if val_rounded == int(val_rounded)
            else f"{val_rounded:.1f}{unit}"
        )
    else:
        disp_val = (
            str(int(round(value)))
            if val_rounded == int(val_rounded)
            else f"{val_rounded:.1f}"
        )
    ax.text(center[0], center[1] - 0.11,
            disp_val,
            ha="center", va="center",
            fontsize=13, fontweight="bold", color=value_color, zorder=11)

    # ---- Title label --------------------------------------------------------
    if title:
        ax.text(center[0], -0.25,
                title,
                ha="center", va="center",
                fontsize=6.5, color="#1A1A1A")

    # ---- Encode to base64 PNG -----------------------------------------------
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150,
                bbox_inches="tight", facecolor="white", edgecolor="none")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("utf-8")
    fig.clf()
    plt.close(fig)
    return b64
