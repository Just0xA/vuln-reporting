"""
reports/modules/board_pdf_layout.py — shared two-column PDF section layout for
board metric modules.

Fixes the board-metric PDF page bleed: board modules previously stacked the
measurement explanation as the LAST block below an already-tall vertical column
(gauge image + status badge + support numbers + 5-row BU table). Under the
production PDF chrome's reduced content height, a measurement explanation
longer than ~2 lines pushed the section past one page, bleeding its trailing
lines onto a second page.

``two_column_metric_section`` lays the section out as:

    +---------------------------------------------------------------+
    |  Section heading (full width)                                 |
    +------------------------------+--------------------------------+
    |  gauge + status + support    |  measurement explanation       |
    |  (LEFT)                      |  (RIGHT, left-aligned)         |
    +------------------------------+--------------------------------+
    |  Top-5 Worst BU table (full width, below)                     |
    +---------------------------------------------------------------+

The explanation now shares vertical space with the gauge column rather than
stacking below it, so the section height shrinks and stays on one page. A CSS
``display:table`` layout is used deliberately — WeasyPrint 65.x has documented
flex quirks in this repo (see composer.py .rag-cell notes), and table layout is
the reliable two-column primitive.
"""
from __future__ import annotations


def two_column_metric_section(
    *,
    heading_html: str,
    left_html: str,
    explanation_html: str,
    full_width_html: str = "",
) -> str:
    """
    Assemble a board metric PDF section with the metric graphic on the left and
    the measurement explanation on the right.

    Parameters
    ----------
    heading_html : str
        The ``<h2 class="section-heading">`` element (rendered full width).
    left_html : str
        Left-column content — typically gauge + status badge + support numbers.
    explanation_html : str
        The measurement-explanation block (an ``.explanatory-text`` paragraph).
        Rendered in the right column, left-aligned.
    full_width_html : str
        Optional content rendered full width BELOW the two-column row —
        typically the Top-5 Worst-Performing Business Units table.

    Returns
    -------
    str
        Complete ``module-section`` HTML string.
    """
    return f"""
<div class="module-section">
  {heading_html}
  <div style="display:table; width:100%; table-layout:fixed; margin-bottom:4mm;">
    <div style="display:table-cell; box-sizing:border-box; width:50%; vertical-align:middle; padding-right:5mm;">
      {left_html}
    </div>
    <div style="display:table-cell; box-sizing:border-box; width:50%; vertical-align:middle; text-align:left;">
      {explanation_html}
    </div>
  </div>
  {full_width_html}
</div>"""
