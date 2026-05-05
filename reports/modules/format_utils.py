"""
reports/modules/format_utils.py — None/NaN-safe formatters for metric values
emitted by BaseModule render methods.

These are tighter, pandas-aware siblings of `utils/formatters.py:fmt_int /
fmt_pct / fmt_days`. Three differences:

1. They use `pd.isna()` so a NaN coming out of a pandas slice (mixed None/NaN
   in the same series) is treated identically to a Python `None`.
2. They default to the documented "—" sentinel rather than mixing the
   legacy N-slash-A string, "—", and different per-helper defaults.
3. `safe_format` exposes an arbitrary format-spec escape hatch.

All four render methods on BaseModule MUST use these helpers when
interpolating metric values that could be None or NaN. New modules that
bypass them are caught at code review.

Public exports
--------------
- ``safe_pct``    — None/NaN-safe percent formatter
- ``safe_int``    — None/NaN-safe integer with thousands separator
- ``safe_format`` — None/NaN-safe arbitrary format spec
"""

from __future__ import annotations

from typing import Any

import pandas as pd


# ===========================================================================
# None/NaN-safe formatters
# ===========================================================================

def safe_pct(
    val:       Any,
    default:   str = "—",
    precision: int = 1,
) -> str:
    """
    Format a numeric value as a percentage, returning ``default`` for
    None / NaN inputs.

    The value is interpreted as already-percentage (e.g. ``87.4`` →
    ``"87.4%"``), NOT a fraction. Modules that compute a 0.0-1.0 fraction
    should multiply by 100 before passing.

    Parameters
    ----------
    val : Any
        Numeric value or None / NaN.
    default : str
        Sentinel returned when val is None or NaN. Default ``"—"``.
    precision : int
        Decimal places. Default 1.

    Returns
    -------
    str
        ``f"{val:.{precision}f}%"`` on success; ``default`` on None / NaN /
        un-formattable input.

    Examples
    --------
    >>> safe_pct(87.4)
    '87.4%'
    >>> safe_pct(None)
    '—'
    >>> safe_pct(float('nan'))
    '—'
    >>> safe_pct(95, precision=0)
    '95%'
    """
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return f"{float(val):.{precision}f}%"
    except (TypeError, ValueError):
        return default


def safe_int(
    val:     Any,
    default: str = "—",
) -> str:
    """
    Format a numeric value as an integer with thousands separator,
    returning ``default`` for None / NaN inputs.

    Parameters
    ----------
    val : Any
        Numeric value or None / NaN.
    default : str
        Sentinel returned when val is None or NaN. Default ``"—"``.

    Returns
    -------
    str
        ``f"{int(val):,}"`` on success; ``default`` on None / NaN /
        un-formattable input.

    Examples
    --------
    >>> safe_int(12345)
    '12,345'
    >>> safe_int(None)
    '—'
    >>> safe_int(float('nan'))
    '—'
    """
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return f"{int(val):,}"
    except (TypeError, ValueError):
        return default


def safe_format(
    val:     Any,
    fmt:     str,
    default: str = "—",
) -> str:
    """
    Apply an arbitrary format spec to a value, returning ``default`` for
    None / NaN.  The format spec is the part after the colon in an
    f-string — e.g. ``".1f"``, ``",d"``, ``"06.2f"``.

    Parameters
    ----------
    val : Any
        Numeric value or None / NaN.
    fmt : str
        Python format-spec string, e.g. ``".1f"``, ``",d"``.
    default : str
        Sentinel returned when val is None or NaN. Default ``"—"``.

    Returns
    -------
    str
        ``format(val, fmt)`` on success; ``default`` on None / NaN /
        un-formattable input.

    Examples
    --------
    >>> safe_format(12.345, ".1f")
    '12.3'
    >>> safe_format(None, ".1f")
    '—'
    >>> safe_format(1234, ",d")
    '1,234'
    """
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return format(val, fmt)
    except (TypeError, ValueError):
        return default
