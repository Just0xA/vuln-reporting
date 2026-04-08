"""
exporters/chart_exporter.py — Reusable chart generation for all report scripts.

Every public function:
  - Accepts a pd.DataFrame, a title string, and an output_path (str or Path,
    without extension — the function appends .png / .html itself)
  - Saves a Matplotlib .png (for PDF embedding and email CID inline images)
  - Saves a Plotly .html (interactive) and Plotly .png (static, via kaleido)
  - Returns (png_path: Path, html_path: Path)
    kpi_gauge() is the sole exception — it returns (png_path, None) because
    a gauge is already built as a Plotly figure and the html is also returned.

Color palette (from config.py — do not override locally):
    Critical = #d32f2f | High = #f57c00 | Medium = #fbc02d
    Low = #388e3c     | Info = #1976d2

Exported functions
------------------
bar_chart_by_severity()   — vertical bar per severity tier
horizontal_bar_chart()    — horizontal bar, e.g. Top 25 assets
stacked_bar_chart()       — stacked bar, e.g. age buckets per severity
line_chart()              — multi-series line, e.g. trend over time
donut_chart()             — donut / pie, e.g. plugin family distribution
kpi_gauge()               — semi-circular gauge for SLA compliance %
"""

from __future__ import annotations

import base64
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

_KALEIDO_TIMEOUT = 30  # seconds before giving up on a Plotly PNG export

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — must be set before pyplot import
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ---------------------------------------------------------------------------
# Patch matplotlib.path.Path.__deepcopy__ — broken in matplotlib 3.8–3.9.x.
# The stock implementation calls copy.deepcopy(super(), memo) which triggers
# infinite recursion when ax.set_yticks() / tick rendering copies path objects.
# Fixed upstream in matplotlib 3.10+; this patch is a no-op on fixed versions.
# ---------------------------------------------------------------------------
import copy as _copy
import matplotlib.path as _mpath

def _patched_path_deepcopy(self, memo):
    cls = type(self)
    new = cls.__new__(cls)
    memo[id(self)] = new
    for k, v in self.__dict__.items():
        object.__setattr__(new, k, _copy.deepcopy(v, memo))
    return new

if not getattr(_mpath.Path.__deepcopy__, "_patched", False):
    _mpath.Path.__deepcopy__ = _patched_path_deepcopy
    _mpath.Path.__deepcopy__._patched = True
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio

from config import SEVERITY_COLORS, SEVERITY_ORDER, SEVERITY_LABELS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global Matplotlib style — applied once at import time
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "savefig.facecolor": "white",
})

# Plotly default renderer (static images via kaleido)
pio.kaleido.scope.default_format = "png"

# Default figure size (inches) — wide-format for reports
_FIG_W, _FIG_H = 10, 5

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sev_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.lower(), "#9e9e9e")


def _sev_colors_for(severities: list[str]) -> list[str]:
    return [_sev_color(s) for s in severities]


def _ordered_present(severities_in_data: list[str]) -> list[str]:
    """Return only the severity tiers that appear in the data, in canonical order."""
    present = set(s.lower() for s in severities_in_data)
    return [s for s in SEVERITY_ORDER if s in present]


def _save_png(fig: plt.Figure, base_path: Path) -> Path:
    """Save a Matplotlib figure as PNG and close it. Returns the PNG path."""
    path = base_path.with_suffix(".png")
    fig.savefig(path)
    plt.close(fig)
    logger.debug("Saved Matplotlib PNG: %s", path)
    return path


def _write_plotly_png(fig: go.Figure, png_path: Path) -> None:
    """
    Write a Plotly figure as PNG by running kaleido inside an isolated subprocess.

    Isolation prevents kaleido from hanging the main process or corrupting
    matplotlib's global state — a known issue with kaleido 0.2.x on Windows
    where the Chromium subprocess never responds.

    If the subprocess times out or fails the warning is logged and execution
    continues; the PNG file will simply be absent.
    """
    tmp_json: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            tf.write(fig.to_json())
            tmp_json = Path(tf.name)

        script = (
            "import plotly.io as pio, pathlib;"
            f"fig=pio.from_json(pathlib.Path(r'{tmp_json}').read_text(encoding='utf-8'));"
            f"fig.write_image(r'{png_path}')"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            timeout=_KALEIDO_TIMEOUT,
            capture_output=True,
        )
        if result.returncode != 0:
            err = result.stderr.decode(errors="replace").strip()
            logger.warning("Plotly PNG subprocess exited non-zero: %s", err or "(no stderr)")
        else:
            logger.debug("Saved Plotly PNG: %s", png_path)
    except subprocess.TimeoutExpired:
        logger.warning(
            "Plotly PNG export timed out after %ds (kaleido not responding) — skipping: %s",
            _KALEIDO_TIMEOUT, png_path,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Plotly PNG export failed: %s", exc)
    finally:
        if tmp_json and tmp_json.exists():
            tmp_json.unlink(missing_ok=True)


def _save_plotly(fig: go.Figure, base_path: Path) -> tuple[Path, Path]:
    """
    Save a Plotly figure as both .html and .png.

    Returns
    -------
    tuple[Path, Path]
        (png_path, html_path)
    """
    png_path = base_path.with_suffix(".png")
    html_path = base_path.with_suffix(".html")

    _write_plotly_png(fig, png_path)

    fig.write_html(str(html_path), include_plotlyjs="cdn", full_html=True)
    logger.debug("Saved Plotly HTML: %s", html_path)
    return png_path, html_path


def _base_plotly_layout(title: str) -> dict:
    return {
        "title": {"text": title, "font": {"size": 16, "family": "Arial, sans-serif"}},
        "font": {"family": "Arial, sans-serif", "size": 13, "color": "#212121"},
        "paper_bgcolor": "#ffffff",
        "plot_bgcolor": "#ffffff",
        "margin": {"l": 60, "r": 40, "t": 70, "b": 60},
        "legend": {
            "orientation": "h",
            "yanchor": "bottom",
            "y": -0.3,
            "xanchor": "center",
            "x": 0.5,
        },
    }


def png_to_base64(png_path: Path) -> str:
    """
    Encode a PNG file as a base64 data URI string.

    Used by email_sender to embed charts as CID images.

    Parameters
    ----------
    png_path : Path

    Returns
    -------
    str
        Data URI: ``data:image/png;base64,<encoded>``
    """
    with open(png_path, "rb") as fh:
        encoded = base64.b64encode(fh.read()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# ===========================================================================
# Public chart functions
# ===========================================================================

def bar_chart_by_severity(
    df: pd.DataFrame,
    title: str,
    output_path: str | Path,
    value_col: str,
    severity_col: str = "severity",
    xlabel: str = "Severity",
    ylabel: str = "Count",
) -> tuple[Path, Path]:
    """
    Vertical bar chart showing one numeric value per severity tier.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain *severity_col* and *value_col*.
    title : str
    output_path : str or Path
        Base path without extension.
    value_col : str
        Column with the bar heights.
    severity_col : str
        Column containing severity strings.
    xlabel, ylabel : str

    Returns
    -------
    (png_path, html_path)
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    # Order severities canonically
    ordered = _ordered_present(df[severity_col].tolist())
    plot_df = (
        df.groupby(severity_col)[value_col]
        .sum()
        .reindex(ordered, fill_value=0)
        .reset_index()
    )
    plot_df.columns = ["severity", "value"]
    labels = [SEVERITY_LABELS.get(s, s.title()) for s in plot_df["severity"]]
    colors = _sev_colors_for(plot_df["severity"].tolist())

    # --- Matplotlib ---
    fig, ax = plt.subplots(figsize=(_FIG_W, _FIG_H))
    bars = ax.bar(labels, plot_df["value"], color=colors, width=0.55, zorder=2)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=1)
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + max(plot_df["value"].max() * 0.01, 0.5),
                f"{int(h):,}",
                ha="center",
                va="bottom",
                fontsize=10,
            )
    png_path = _save_png(fig, base)

    # --- Plotly ---
    pfig = go.Figure(
        go.Bar(
            x=labels,
            y=plot_df["value"],
            marker_color=colors,
            text=[f"{int(v):,}" for v in plot_df["value"]],
            textposition="outside",
        )
    )
    pfig.update_layout(
        **_base_plotly_layout(title),
        xaxis_title=xlabel,
        yaxis_title=ylabel,
        bargap=0.35,
    )
    _, html_path = _save_plotly(pfig, base)

    return png_path, html_path


def horizontal_bar_chart(
    df: pd.DataFrame,
    title: str,
    output_path: str | Path,
    label_col: str,
    value_col: str,
    color_col: Optional[str] = None,
    xlabel: str = "Value",
    max_rows: int = 25,
) -> tuple[Path, Path]:
    """
    Horizontal bar chart — typically used for Top-N asset risk rankings.

    Parameters
    ----------
    df : pd.DataFrame
    title : str
    output_path : str or Path
    label_col : str
        Column used as bar labels (Y axis).
    value_col : str
        Column used as bar lengths (X axis).
    color_col : str, optional
        Column containing severity strings for per-bar coloring.
        If None, uses a single brand color (#1976d2).
    xlabel : str
    max_rows : int
        Cap displayed rows (default 25).
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    plot_df = df.head(max_rows).copy()
    labels = plot_df[label_col].astype(str).tolist()
    values = plot_df[value_col].tolist()

    if color_col and color_col in plot_df.columns:
        colors = _sev_colors_for(plot_df[color_col].tolist())
    else:
        colors = ["#1976d2"] * len(plot_df)

    fig_h = max(4, len(labels) * 0.35)

    # --- Matplotlib ---
    fig, ax = plt.subplots(figsize=(_FIG_W, fig_h))
    y_pos = range(len(labels))
    bars = ax.barh(list(y_pos), values, color=colors, height=0.6, zorder=2)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.xaxis.grid(True, linestyle="--", alpha=0.5, zorder=1)
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_width() + max(max(values) * 0.005, 0.1),
            bar.get_y() + bar.get_height() / 2,
            f"{val:,}" if isinstance(val, int) else f"{val:.1f}",
            va="center",
            fontsize=8,
        )
    png_path = _save_png(fig, base)

    # --- Plotly ---
    pfig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker_color=colors,
            text=[f"{v:,}" if isinstance(v, int) else f"{v:.1f}" for v in values],
            textposition="outside",
        )
    )
    pfig.update_layout(
        **_base_plotly_layout(title),
        xaxis_title=xlabel,
        yaxis={"autorange": "reversed"},
        height=max(400, len(labels) * 28 + 120),
    )
    _, html_path = _save_plotly(pfig, base)

    return png_path, html_path


def stacked_bar_chart(
    df: pd.DataFrame,
    title: str,
    output_path: str | Path,
    x_col: str,
    stack_cols: list[str],
    colors: Optional[list[str]] = None,
    xlabel: str = "",
    ylabel: str = "Count",
) -> tuple[Path, Path]:
    """
    Stacked bar chart — e.g. vulnerability age buckets broken down per severity.

    Parameters
    ----------
    df : pd.DataFrame
        Each row is one X-axis category; *stack_cols* are the stacked series.
    title : str
    output_path : str or Path
    x_col : str
        Column for X-axis categories.
    stack_cols : list[str]
        Columns to stack (in order, bottom to top).
    colors : list[str], optional
        Per-series colors.  Defaults to severity palette in SEVERITY_ORDER.
    xlabel, ylabel : str
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    if colors is None:
        colors = [_sev_color(c) for c in stack_cols]

    x_labels = df[x_col].astype(str).tolist()

    # --- Matplotlib ---
    fig, ax = plt.subplots(figsize=(_FIG_W, _FIG_H))
    bottoms = np.zeros(len(df))
    for col, color in zip(stack_cols, colors):
        vals = df[col].fillna(0).to_numpy(dtype=float)
        ax.bar(x_labels, vals, bottom=bottoms, color=color, label=col, width=0.6, zorder=2)
        bottoms += vals
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=1)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.15),
        ncol=len(stack_cols),
        frameon=False,
        fontsize=9,
    )
    png_path = _save_png(fig, base)

    # --- Plotly ---
    traces = [
        go.Bar(
            name=col,
            x=x_labels,
            y=df[col].fillna(0).tolist(),
            marker_color=color,
        )
        for col, color in zip(stack_cols, colors)
    ]
    pfig = go.Figure(data=traces)
    pfig.update_layout(
        **_base_plotly_layout(title),
        barmode="stack",
        xaxis_title=xlabel,
        yaxis_title=ylabel,
    )
    _, html_path = _save_plotly(pfig, base)

    return png_path, html_path


def line_chart(
    df: pd.DataFrame,
    title: str,
    output_path: str | Path,
    x_col: str,
    y_cols: list[str],
    colors: Optional[list[str]] = None,
    xlabel: str = "",
    ylabel: str = "Count",
    y_pct: bool = False,
) -> tuple[Path, Path]:
    """
    Multi-series line chart — e.g. open vuln trend or SLA compliance over time.

    Parameters
    ----------
    df : pd.DataFrame
    title : str
    output_path : str or Path
    x_col : str
        Column used as the X axis (dates or period labels).
    y_cols : list[str]
        One line per column.
    colors : list[str], optional
        Per-line colors.  Defaults to severity palette.
    xlabel, ylabel : str
    y_pct : bool
        If True, format Y-axis as percentage (0–100).
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    if colors is None:
        colors = [_sev_color(c) for c in y_cols]

    x_vals = df[x_col].astype(str).tolist()

    # --- Matplotlib ---
    fig, ax = plt.subplots(figsize=(_FIG_W, _FIG_H))
    for col, color in zip(y_cols, colors):
        label = SEVERITY_LABELS.get(col.lower(), col)
        ax.plot(x_vals, df[col].fillna(0), marker="o", color=color, label=label, linewidth=2, markersize=5)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel + (" (%)" if y_pct else ""))
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    if len(x_vals) > 8:
        plt.xticks(rotation=35, ha="right", fontsize=8)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=len(y_cols), frameon=False, fontsize=9)
    png_path = _save_png(fig, base)

    # --- Plotly ---
    traces = [
        go.Scatter(
            name=SEVERITY_LABELS.get(col.lower(), col),
            x=x_vals,
            y=df[col].fillna(0).tolist(),
            mode="lines+markers",
            line={"color": color, "width": 2},
            marker={"size": 6},
        )
        for col, color in zip(y_cols, colors)
    ]
    pfig = go.Figure(data=traces)
    pfig.update_layout(
        **_base_plotly_layout(title),
        xaxis_title=xlabel,
        yaxis_title=ylabel + (" (%)" if y_pct else ""),
        hovermode="x unified",
    )
    _, html_path = _save_plotly(pfig, base)

    return png_path, html_path


def donut_chart(
    df: pd.DataFrame,
    title: str,
    output_path: str | Path,
    labels_col: str,
    values_col: str,
    colors: Optional[list[str]] = None,
    max_slices: int = 10,
) -> tuple[Path, Path]:
    """
    Donut chart — e.g. plugin family distribution.

    Slices beyond *max_slices* are collapsed into an "Other" segment.

    Parameters
    ----------
    df : pd.DataFrame
    title : str
    output_path : str or Path
    labels_col : str
    values_col : str
    colors : list[str], optional
        Explicit slice colors.  If None, uses severity palette then Plotly default.
    max_slices : int
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    plot_df = df[[labels_col, values_col]].copy().sort_values(values_col, ascending=False)
    if len(plot_df) > max_slices:
        top = plot_df.head(max_slices - 1)
        other_val = plot_df.iloc[max_slices - 1:][values_col].sum()
        other_row = pd.DataFrame([{labels_col: "Other", values_col: other_val}])
        plot_df = pd.concat([top, other_row], ignore_index=True)

    labels = plot_df[labels_col].astype(str).tolist()
    values = plot_df[values_col].tolist()

    if colors is None:
        # Use severity colors where label matches, else cycle a neutral palette
        _neutral = ["#42a5f5", "#66bb6a", "#ffa726", "#ab47bc", "#26a69a",
                    "#ef5350", "#8d6e63", "#78909c", "#d4e157", "#26c6da"]
        colors = []
        for lbl in labels:
            if lbl.lower() in SEVERITY_COLORS:
                colors.append(SEVERITY_COLORS[lbl.lower()])
            else:
                colors.append(_neutral[len(colors) % len(_neutral)])

    # --- Matplotlib ---
    fig, ax = plt.subplots(figsize=(7, 6))
    wedges, texts, autotexts = ax.pie(
        values,
        labels=None,
        colors=colors,
        autopct=lambda p: f"{p:.1f}%" if p >= 3 else "",
        startangle=90,
        pctdistance=0.75,
        wedgeprops={"width": 0.55},
    )
    for at in autotexts:
        at.set_fontsize(8)
    ax.legend(
        wedges,
        [f"{l} ({v:,})" for l, v in zip(labels, values)],
        loc="lower center",
        bbox_to_anchor=(0.5, -0.15),
        ncol=2,
        fontsize=8,
        frameon=False,
    )
    ax.set_title(title, pad=12)
    png_path = _save_png(fig, base)

    # --- Plotly ---
    pfig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.45,
            marker={"colors": colors},
            textinfo="percent",
            hovertemplate="%{label}: %{value:,}<extra></extra>",
        )
    )
    pfig.update_layout(**_base_plotly_layout(title))
    _, html_path = _save_plotly(pfig, base)

    return png_path, html_path


def kpi_gauge(
    value: float,
    title: str,
    output_path: str | Path,
    min_val: float = 0.0,
    max_val: float = 100.0,
    thresholds: Optional[dict] = None,
) -> tuple[Path, Path]:
    """
    Semi-circular KPI gauge — used for SLA compliance percentages.

    Colors the arc green above the healthy threshold, yellow in caution zone,
    and red below the critical threshold.

    Parameters
    ----------
    value : float
        Current value to display (0–100 for percentages).
    title : str
    output_path : str or Path
    min_val, max_val : float
    thresholds : dict, optional
        ``{"red": 60, "yellow": 80}`` — defaults shown.
        Sectors: < red = red, red–yellow = yellow, >= yellow = green.

    Returns
    -------
    (png_path, html_path) — both generated via Plotly.
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    if thresholds is None:
        thresholds = {"red": 60, "yellow": 80}

    red_thresh = thresholds.get("red", 60)
    yel_thresh = thresholds.get("yellow", 80)

    if value >= yel_thresh:
        bar_color = "#388e3c"
    elif value >= red_thresh:
        bar_color = "#fbc02d"
    else:
        bar_color = "#d32f2f"

    pfig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=value,
            number={"suffix": "%", "font": {"size": 32}},
            title={"text": title, "font": {"size": 14}},
            gauge={
                "axis": {"range": [min_val, max_val], "tickwidth": 1},
                "bar": {"color": bar_color, "thickness": 0.3},
                "bgcolor": "white",
                "borderwidth": 1,
                "bordercolor": "#cccccc",
                "steps": [
                    {"range": [min_val, red_thresh], "color": "#FFCDD2"},
                    {"range": [red_thresh, yel_thresh], "color": "#FFF9C4"},
                    {"range": [yel_thresh, max_val], "color": "#C8E6C9"},
                ],
                "threshold": {
                    "line": {"color": "#212121", "width": 2},
                    "thickness": 0.75,
                    "value": value,
                },
            },
        )
    )
    pfig.update_layout(
        paper_bgcolor="#ffffff",
        font={"family": "Arial, sans-serif", "color": "#212121"},
        margin={"l": 30, "r": 30, "t": 60, "b": 30},
        height=280,
        width=320,
    )

    png_path, html_path = _save_plotly(pfig, base)
    return png_path, html_path


# ===========================================================================
# Convenience: save a Matplotlib figure the caller built themselves
# ===========================================================================

def save_matplotlib_figure(
    fig: plt.Figure,
    output_path: str | Path,
) -> Path:
    """
    Persist a caller-built Matplotlib figure as PNG and return the path.

    Useful when a report script builds a bespoke chart that doesn't map
    cleanly onto the standard helpers above.
    """
    base = Path(output_path)
    base.parent.mkdir(parents=True, exist_ok=True)
    return _save_png(fig, base)


if __name__ == "__main__":
    # Smoke test — generates sample charts in output/chart_test/
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from config import OUTPUT_DIR

    out = OUTPUT_DIR / "chart_test"
    out.mkdir(parents=True, exist_ok=True)

    # bar_chart_by_severity
    sample = pd.DataFrame({
        "severity": ["critical", "high", "medium", "low"],
        "count": [12, 45, 120, 30],
    })
    p, h = bar_chart_by_severity(sample, "Open Vulnerabilities by Severity", out / "bar_sev", "count")
    print(f"bar:        {p}\n            {h}")

    # horizontal_bar_chart
    assets = pd.DataFrame({
        "asset": [f"host-{i:02d}.corp" for i in range(10)],
        "score": [200 - i * 18 for i in range(10)],
    })
    p, h = horizontal_bar_chart(assets, "Top 10 Riskiest Assets", out / "hbar", "asset", "score")
    print(f"hbar:       {p}\n            {h}")

    # stacked_bar_chart
    age = pd.DataFrame({
        "severity": ["Critical", "High", "Medium", "Low"],
        "0–15d": [2, 10, 30, 5],
        "16–30d": [3, 12, 20, 8],
        "31–60d": [5, 8, 25, 10],
        "61–90d": [2, 5, 15, 7],
    })
    p, h = stacked_bar_chart(age, "Vuln Age Buckets by Severity", out / "stacked",
                             "severity", ["0–15d", "16–30d", "31–60d", "61–90d"])
    print(f"stacked:    {p}\n            {h}")

    # line_chart
    trend = pd.DataFrame({
        "month": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        "critical": [10, 12, 8, 15, 9, 7],
        "high": [40, 38, 42, 35, 33, 30],
    })
    p, h = line_chart(trend, "Open Vuln Trend", out / "line", "month", ["critical", "high"])
    print(f"line:       {p}\n            {h}")

    # donut_chart
    families = pd.DataFrame({
        "family": ["Windows", "Web Servers", "Databases", "Network", "Other"],
        "count": [80, 55, 30, 20, 15],
    })
    p, h = donut_chart(families, "Plugin Family Distribution", out / "donut", "family", "count")
    print(f"donut:      {p}\n            {h}")

    # kpi_gauge
    p, h = kpi_gauge(73.5, "Critical SLA Compliance", out / "gauge")
    print(f"gauge:      {p}\n            {h}")

    print("\nAll smoke-test charts written to", out)
