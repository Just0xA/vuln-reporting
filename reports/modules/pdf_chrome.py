"""
reports/modules/pdf_chrome.py — Shared PDF chrome design-system utility.

This module defines the canonical PDF header band + footer band surface for
every PDF report from v1.1 onward. Reports hold a ``PdfChromeConfig`` and
render through ``PdfChrome``; no report should hand-roll @page CSS or
running-element markup ever again.

Design notes
------------
- ``PdfChromeConfig`` is a *frozen* dataclass: chrome config is immutable
  per render. Future global knobs (header height, font, etc.) are added
  here as new fields with defaults — no signature churn for callers.
- ``PdfChrome`` is a plain utility class, NOT a ``BaseModule`` subclass.
  It is not a metric module, has no ``MODULE_ID``, and is not registered
  via ``@register_module``. The filename intentionally omits the
  ``*_module.py`` suffix so ``registry.discover()`` does not pick it up.
- The missing-logo fallback (CHROME-CFG-03) is owned here, at render
  time. No startup-time FS check — config can name a logo that lands on
  disk later.
- Footer corners are emitted as literal ``content:`` strings inside
  ``@bottom-left``/``@bottom-center``/``@bottom-right`` margin boxes
  (verified by RESEARCH Q2). ``build_footer_runners()`` therefore
  returns ``""`` in v1 and exists only for API symmetry with
  ``build_header_html()``.
- Phase 5 ships the utility in isolation. Phase 6 wires it into
  ``ReportComposer.assemble_pdf()``.

References
----------
- ``.planning/phases/05-pdf-chrome-foundation/05-CONTEXT.md`` D-01..D-04
- ``.planning/phases/05-pdf-chrome-foundation/05-RESEARCH.md`` Q1..Q4
"""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


# ===========================================================================
# Configuration dataclass
# ===========================================================================

@dataclass(frozen=True)
class PdfChromeConfig:
    """
    Immutable per-render chrome configuration.

    Attributes
    ----------
    title : str
        Report title shown in the header band on every page.
    subtitle : str
        Secondary line in the header band (e.g. scope/tag filter
        descriptor). May be empty.
    generated_at : datetime
        Report run timestamp. **MUST be timezone-aware UTC**;
        ``__post_init__`` raises ``ValueError`` otherwise. The footer
        bottom-right prints this as ``YYYY-MM-DD HH:MM UTC``.
    header_bg : str
        Header band background color (CSS color string). Default
        ``"#1a2332"`` matches ``config.HEADER_BG_COLOR``. White text is
        applied unconditionally per CHROME-HDR-02 (no autoshift in
        v1.1).
    logo_path : Path | None
        Optional absolute path to a company logo image. ``None`` means
        title-only header. A non-existent path silently falls back to
        title-only at render time (CHROME-CFG-03).
    privacy_label : str
        Footer bottom-left label (e.g. ``"Confidential"``). MUST NOT
        contain a double-quote because the value is interpolated into a
        CSS ``content: "..."`` string; ``__post_init__`` raises
        ``ValueError`` otherwise. Defense in depth — the YAML schema
        regex in ``delivery_config.schema.yaml`` rejects the same
        characters operator-side.
    """

    title:         str
    subtitle:      str
    generated_at:  datetime
    header_bg:     str          = "#1a2332"
    logo_path:     Path | None  = None
    privacy_label: str          = "Confidential"

    def __post_init__(self) -> None:
        # CHROME-FTR-01: footer right corner advertises UTC; the literal
        # "UTC" suffix is only correct when the source datetime is
        # actually UTC-aware.
        if self.generated_at.tzinfo is None:
            raise ValueError(
                "PdfChromeConfig.generated_at must be timezone-aware "
                "(UTC). Got a naive datetime."
            )
        if self.generated_at.utcoffset() != timezone.utc.utcoffset(None):
            raise ValueError(
                "PdfChromeConfig.generated_at must be in UTC. Convert "
                "with .astimezone(timezone.utc) before passing in."
            )
        # CHROME-CFG-04: privacy_label is interpolated into a CSS
        # `content: "..."` string. A stray " would break the CSS. The
        # YAML schema regex enforces this operator-side; this check
        # protects direct Python construction (tests, future callers).
        if '"' in self.privacy_label:
            raise ValueError(
                "PdfChromeConfig.privacy_label must not contain a "
                "double-quote character. Use a single-quote or smart "
                "quote inside the label if quoting is needed."
            )


# ===========================================================================
# Chrome utility
# ===========================================================================

class PdfChrome:
    """
    Render the shared PDF header band + footer band from a
    ``PdfChromeConfig``.

    Usage (Phase 6 composer wiring sketch — NOT this phase's work)::

        chrome = PdfChrome(cfg)
        html_doc = f'''<!doctype html>
        <html>
          <head><style>{chrome.build_css()}</style></head>
          <body>
            {chrome.build_header_html()}
            {chrome.build_footer_runners()}
            ... body content ...
          </body>
        </html>'''
    """

    def __init__(self, cfg: PdfChromeConfig) -> None:
        self.cfg = cfg

    # -------------------------------------------------------------------
    # CSS — @page rules + chrome class styles
    # -------------------------------------------------------------------

    def build_css(self) -> str:
        """
        Emit the chrome CSS: ``@page`` margin-box rules (with
        ``@page :first`` cover-page page-number suppression) plus the
        ``.chrome-header`` class styles consumed by the body-side
        running element from ``build_header_html()``.

        The CSS is intended to live in its own ``<style>`` block,
        separate from the composer's existing module/table/cover-body
        CSS (Phase 6 keeps them as two blocks for testability).
        """
        cfg = self.cfg
        generated_at_str = cfg.generated_at.strftime("%Y-%m-%d %H:%M UTC")

        # Footer corners are literal `content:` strings (RESEARCH Q2).
        # Header band is a `position: running()` element so it can
        # carry an <img> (RESEARCH Q4). Cover page-number suppression
        # uses `@page :first` overriding ONLY @bottom-center; the other
        # two corners cascade from the base @page rule (RESEARCH Q1).
        #
        # Order matters: base @page MUST come before @page :first.
        return f"""
        @page {{
          size: A4 landscape;
          margin: 15mm 12mm 18mm 12mm;
          @top-left-corner  {{ content: ""; background: {cfg.header_bg}; }}
          @top-left         {{ content: element(chrome-header); background: {cfg.header_bg}; }}
          @top-center       {{ content: ""; background: {cfg.header_bg}; }}
          @top-right        {{ content: ""; background: {cfg.header_bg}; }}
          @top-right-corner {{ content: ""; background: {cfg.header_bg}; }}
          @bottom-left-corner {{
            content: "";
            border-top: 1px solid #999;
          }}
          @bottom-left   {{
            content: "{cfg.privacy_label}";
            font-size: 8pt; color: #666;
            border-top: 1px solid #999;
            padding-top: 2mm;
          }}
          @bottom-center {{
            content: "Page " counter(page) " of " counter(pages);
            font-size: 8pt; color: #666;
            border-top: 1px solid #999;
            padding-top: 2mm;
          }}
          @bottom-right  {{
            content: "Generated On: {generated_at_str}";
            font-size: 8pt; color: #666;
            border-top: 1px solid #999;
            padding-top: 2mm;
          }}
          @bottom-right-corner {{
            content: "";
            border-top: 1px solid #999;
          }}
        }}
        @page :first {{
          @bottom-center {{ content: ""; }}
        }}
        .chrome-header {{
          position: running(chrome-header);
          background: {cfg.header_bg};
          color: #ffffff;
          padding: 3mm 4mm;
        }}
        .chrome-header img {{
          height: 8mm;
          vertical-align: middle;
          margin-right: 4mm;
        }}
        .chrome-header .chrome-title {{
          vertical-align: middle;
          font-weight: bold;
          font-size: 12pt;
        }}
        """

    # -------------------------------------------------------------------
    # Header HTML — body-side running element
    # -------------------------------------------------------------------

    def build_header_html(self) -> str:
        """
        Emit the body-side ``<div class="chrome-header">`` carrying
        ``position: running(chrome-header)``. WeasyPrint pulls this
        div into the ``@top-left`` margin box on every page.

        Logo handling per CHROME-CFG-03:
          - ``logo_path is None``        → title-only (no <img>)
          - ``logo_path`` exists on disk → ``<img src="file://...">``
          - ``logo_path`` missing        → title-only, no exception,
            no warning log (filtered-to-zero recipient groups must not
            spam logs).
        """
        cfg = self.cfg

        # Logo branch — render-time existence check (no startup probe).
        logo_html = ""
        if cfg.logo_path is not None:
            lp = Path(cfg.logo_path)
            if lp.exists():
                # .resolve() is required before .as_uri() — relative
                # paths raise ValueError otherwise (RESEARCH risk #2).
                logo_uri = lp.resolve().as_uri()
                logo_html = f'<img src="{logo_uri}" alt="">'
            # Missing-file fallback: silent. No log, no exception, no
            # reserved width. CHROME-CFG-03 acceptance.

        title = html.escape(cfg.title)

        return (
            f'<div class="chrome-header">'
            f'{logo_html}'
            f'<span class="chrome-title">{title}</span>'
            f'</div>'
        )

    # -------------------------------------------------------------------
    # Footer runners — no-op in v1 (CSS-only footer)
    # -------------------------------------------------------------------

    def build_footer_runners(self) -> str:
        """
        Return an empty string in v1.

        Footer corners are emitted as literal ``content:`` strings
        inside the margin boxes defined by ``build_css()``. There is
        no body-side running element for the footer. This method
        exists for API symmetry with ``build_header_html()`` and to
        future-proof for cases where the footer eventually needs HTML
        markup (e.g. clickable links, mixed-color text spans, a QR
        code).
        """
        return ""
