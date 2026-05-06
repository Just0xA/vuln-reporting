---
phase: 02-reportcomposer-upgrades
reviewed: 2026-05-06T07:58:00Z
status: issues_found
depth: standard
total_findings: 7
critical_count: 0
warning_count: 4
info_count: 3
---

# Phase 2: ReportComposer Upgrades — Code Review

Standard-depth adversarial review of the 10 source files changed since Phase 1 close (commit `a296987`). No security blockers and no correctness defects in the happy path; four warnings centered on un-escaped HTML/CSS interpolation from module-supplied strings into the new RAG strip + email panel placeholders, one fail-soft semantic gap in `_unique_sheet_name`, plus three info items (stale import, public-API path-traversal hardening, smoke-script ergonomics).

---

## Critical Issues

_None._

---

## Warnings

### WR-01: RAG-strip cell HTML interpolation does not escape module-supplied strings (BLOCKER on adversarial input)

**Files:**
- `D:\Projects\vuln-reporting\reports\modules\composer.py:771-787`
- `D:\Projects\vuln-reporting\reports\modules\base.py:454-459` (default cell builder)

**Issue:**
`_build_rag_strip_page` builds each strip cell by string-interpolating four values from the module-returned dict directly into the HTML output:

```python
label          = str(cell_dict["label"])
headline_value = str(cell_dict["headline_value"])
rag_color      = str(cell_dict["rag_color"])
rag_label      = str(cell_dict["rag_label"])
icon           = _icon_for(rag_color)

cells.append(
    '    <div class="rag-cell">\n'
    f'      <div class="rag-cell-label">{label}</div>\n'
    f'      <div class="rag-cell-value">{headline_value}</div>\n'
    f'      <div class="rag-cell-band" '
    f'style="background-color: {rag_color};">\n'
    f'        <span class="rag-cell-icon">{icon}</span>'
    f'<span class="rag-cell-rag-label">{rag_label}</span>\n'
    '      </div>\n'
    '    </div>'
)
```

Three concrete failure modes:

1. **HTML breakage from `&` / `<` / `>`** — a future module DISPLAY_NAME like `"Patch & Compliance"` (or `"R&D Assets"`) is fed verbatim into `<div class="rag-cell-label">...</div>`. The `&` does not produce visible breakage in WeasyPrint, but a label like `"Coverage <30 days"` becomes a malformed open tag and silently corrupts the cover page. Same risk on `headline_value` and `rag_label`.

2. **CSS injection in `rag_color`** — the value flows straight into `style="background-color: {rag_color};"`. A module that returns `rag_color: "red; }--></style><script>..."` would inject CSS or break out of the style attribute. Not exploitable today (modules are first-party code in this repo), but the `rag_color` is documented as a contract field — once Phase 3 modules and v2's analyst-driven module additions land, an analyst typo like `"#388e3c; border:50pt solid red"` breaks the page silently.

3. **No defensive normalization on rag_color** — `_icon_for(rag_color_hex)` does case-insensitive match against `STATUS_COLOR.values()` and falls back to `STATUS_ICON["no_data"]` on miss. That fallback is silent; if a Phase 3 module accidentally writes `rag_color: "#fbc02d"` (yellow from `_GAUGE_THRESHOLDS`) instead of the canonical `STATUS_COLOR["yellow"]` value `"#f57c00"`, the cell renders the *yellow band color* but the "no_data" `○` icon — a misleading mixed signal that contradicts D-08's "shape carries the signal independent of color" guarantee.

**Severity rationale:** Warning, not Critical, because all three failure modes require a module producing a malformed dict; today no Phase 1 module does. But the contract documents `headline_value`, `rag_label`, and `rag_color` as module-supplied strings, and PROJECT.md explicitly anticipates analyst-driven new modules in v2. This needs to be hardened before Phase 3 board modules start populating real values.

**Fix:**

```python
import html  # noqa: PLC0415  (deferred — the helper is used only inside this method)

label          = html.escape(str(cell_dict["label"]),          quote=False)
headline_value = html.escape(str(cell_dict["headline_value"]), quote=False)
rag_label      = html.escape(str(cell_dict["rag_label"]),      quote=False)
# rag_color is a CSS color — validate strictly against the known palette
rag_color_raw = str(cell_dict["rag_color"]).strip()
if rag_color_raw.lower() not in {v.lower() for v in STATUS_COLOR.values()}:
    logger.warning(
        "ReportComposer._build_rag_strip_page [%s]: rag_color %r is not in "
        "STATUS_COLOR — substituting no_data gray.",
        data.module_id, rag_color_raw,
    )
    rag_color_raw = STATUS_COLOR["no_data"]
rag_color = rag_color_raw
icon      = _icon_for(rag_color)
```

Also worth tightening `_icon_for` so a non-canonical color logs a warning rather than silently degrading to the no_data icon (so Phase 3 module developers see the contract drift in logs immediately).

---

### WR-02: Email-panel error placeholder injects exception message into HTML without escaping

**File:** `D:\Projects\vuln-reporting\reports\modules\composer.py:1169-1183`

**Issue:**
When `render_email_panel()` raises, `assemble_email_body()` catches and substitutes a placeholder `<div>`:

```python
except Exception as exc:  # noqa: BLE001
    logger.error(...)
    html = (
        '<div style="border:1px solid #d32f2f; ...">'
        f'<strong>{data.display_name}</strong>: '
        f'email panel render failed — {exc}'
        '</div>'
    )
```

`{exc}` renders the exception message verbatim. Exception strings can contain arbitrary content sourced from user-controlled paths:

- `KeyError` raises with the missing key in `repr()` form — if a module reads `config.options['<some/path>']` and the key contains `<` or `>`, the error message will too.
- A buggy module that includes raw API response text in an error message could surface untrusted Tenable-side data.
- The placeholder HTML is then routed through the email template's `{{ module_panels_html | safe }}` (`templates/report_email.html:102`), which deliberately disables Jinja2 autoescape — so any HTML in `exc` reaches the email client.

The legacy `assemble_pdf` placeholder at composer.py:627-632 has the identical pattern; this warning calls out both. The PDF path is somewhat insulated because WeasyPrint's HTML parser tolerates malformed input, but the email path renders inside Outlook/Gmail/Apple Mail which is the constraint surface the project takes seriously (CLAUDE.md "Email-client compatibility").

**Severity rationale:** Warning. `data.display_name` comes from a registered class constant (controlled), but `exc` is not. The realistic exploitation surface is small (no internet-facing input flows here), but it violates the "inline CSS only, predictable HTML" guarantee for email clients.

**Fix:**

```python
import html  # noqa: PLC0415

except Exception as exc:  # noqa: BLE001
    logger.error(...)
    safe_name = html.escape(str(data.display_name), quote=True)
    safe_exc  = html.escape(str(exc),               quote=True)
    html = (
        '<div style="border:1px solid #d32f2f; '
        'background:#FFF3CD; color:#5D4037; '
        'padding:8px 12px; margin:6px 0; '
        'font-family:Arial,Helvetica,sans-serif; font-size:10pt;">'
        f'<strong>{safe_name}</strong>: '
        f'email panel render failed — {safe_exc}'
        '</div>'
    )
```

Apply the equivalent escape to the PDF placeholder at composer.py:627-632.

---

### WR-03: `_unique_sheet_name` raises `ValueError` from inside `assemble_analyst_workbook`, breaking the D-28 fail-soft contract

**Files:**
- `D:\Projects\vuln-reporting\reports\modules\composer.py:1535-1586` (helper)
- `D:\Projects\vuln-reporting\reports\modules\composer.py:1007-1009` (call site)

**Issue:**
The helper is documented to raise after 99 collision attempts:

```python
def _unique_sheet_name(name: str, used: set[str]) -> str:
    ...
    for i in range(2, 100):
        ...
    raise ValueError(
        f"_unique_sheet_name: could not generate unique sheet name "
        f"from {name!r} after 99 attempts."
    )
```

The call site does not handle that exception:

```python
for entry in tabs:
    ...
    sheet_name, df = entry
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        continue
    unique = _unique_sheet_name(sheet_name, used_names)   # ← may raise
    used_names.add(unique)
    collected.append((unique, df))
```

Because this iteration runs *after* the per-module `try/except` wrapping `instance.render_analyst_tabs()` (composer.py:964-987), a `ValueError` raised here propagates out through `assemble_analyst_workbook` and ultimately out of `run_full_pipeline` — directly contradicting D-28 ("module render error must not kill the batch") and PROJECT.md's "Fail-soft batch semantics" hard correctness bar.

The probability of hitting 99 collisions is low (Phase 2 modules return short, distinct sheet names), but the design intent of "every catastrophic case becomes a `_Metadata` Failures row" is broken.

**Severity rationale:** Warning. Today no module collides 99 times so this is dormant. But the helper's docstring documents the ValueError as expected behavior and the call site quietly assumes it cannot happen — exactly the kind of drift PROJECT.md's fail-soft constraint exists to prevent.

**Fix:**

Wrap the per-entry sheet-name resolution in the same try/except that already records into `failures`:

```python
for entry in tabs:
    if (
        not isinstance(entry, tuple)
        or len(entry) != 2
        or not isinstance(entry[0], str)
    ):
        logger.warning(...)
        continue

    sheet_name, df = entry
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        continue

    try:
        unique = _unique_sheet_name(sheet_name, used_names)
    except ValueError as exc:
        logger.error(
            "ReportComposer.assemble_analyst_workbook [%s]: "
            "could not allocate unique sheet name for %r — recording failure.",
            data.module_id, sheet_name,
        )
        failures.append((data.module_id, f"sheet-name allocation failed: {exc}"))
        continue
    used_names.add(unique)
    collected.append((unique, df))
```

That preserves the audit trail (failure recorded in `_Metadata` Failures) and lets every other module's tabs still land.

---

### WR-04: `run_full_pipeline` slug interpolation is a public-API path-traversal surface

**File:** `D:\Projects\vuln-reporting\reports\modules\composer.py:1409-1416`

**Issue:**
The analyst filename is computed as:

```python
analyst_filename = f"{slug}_{date_str}_analyst.xlsx"   # D-16
bundle["analyst_workbook_path"] = self.assemble_analyst_workbook(
    results,
    Path(output_dir) / analyst_filename,
    ...
)
```

`slug` is a public, non-keyword-only string parameter on `run_full_pipeline()` and is documented as "the report slug used for the analyst filename" — no constraints. A caller passing `slug="../../escape"` produces `Path(output_dir) / "../../escape_2026-05-06_analyst.xlsx"` and the analyst workbook lands outside `output_dir`. Same hazard if `slug` contains `/` or `\` on Windows.

In Phase 2, `run_full_pipeline` is called only from `board_summary.py:239-248` with the hardcoded literal `slug="board_summary"`, so the surface is contained today. But:

1. CLAUDE.md and the canonical-references in 02-CONTEXT.md document `run_full_pipeline()` as a public API building block (D-23).
2. v2's promised YAML-driven module composition (PROJECT.md "Out of Scope: Migrating board_summary.py's hardcoded `_BOARD_MODULE_CONFIGS` to be YAML-driven") will eventually have `slug` flow from `delivery_config.yaml` — at which point this becomes user-supplied.
3. `_write_analyst_metadata_tab` writes `slug` into the workbook's `_Metadata` cell (composer.py:1648-1649) without sanitization; same path-traversal-style argument applies to writing user-influenced strings into Excel cells when v2 lands.

**Severity rationale:** Warning. No exploitation today, but the typing (`str`) and docstring guarantee no validation. Easier to harden now than after the API surface widens.

**Fix:**

Add a slug whitelist check at the top of `run_full_pipeline` (and document it):

```python
import re  # noqa: PLC0415

_SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

def run_full_pipeline(self, results, output_dir, *, slug, ...):
    if not _SAFE_SLUG_RE.match(slug):
        raise ValueError(
            f"run_full_pipeline: slug {slug!r} must match {_SAFE_SLUG_RE.pattern} "
            "(letters, digits, underscore, hyphen only — no path separators)."
        )
    ...
```

Same check should ideally apply at `assemble_analyst_workbook(slug=...)` since it's also documented as public-callable.

---

## Info

### IN-01: `import openpyxl` at module top of `board_summary.py` is now unused

**File:** `D:\Projects\vuln-reporting\reports\board_summary.py:42`

**Issue:**
```python
import openpyxl
```

The previous `run_report` flow built its own `openpyxl.Workbook` directly. Phase 2 rewires that path through `bundle["excel_workbook"]` (`board_summary.py:279`), so the only Excel handling left in this file is `wb.save(str(excel_file))` on the workbook the composer already constructed. There is no remaining `openpyxl.*` reference in the file (verified via grep — the only matches are line 42 and a comment at line 274).

This is a dead import and would be flagged by `ruff` / `flake8 F401` if the project had a linter wired in. Doesn't break anything, but per CONVENTIONS.md "no unused imports."

**Fix:** Delete line 42.

---

### IN-02: `tag_filter_label` field is set but never reaches the cover page subtitle when scope_label and subtitle diverge in future callers

**File:** `D:\Projects\vuln-reporting\reports\board_summary.py:220-230`

**Issue:**
The current code computes two parallel string forms:

```python
scope_str = (
    f"Scope: {tag_category} = {tag_value}"
    if tag_category and tag_value
    else "Scope: All Assets"
)
subtitle    = scope_str
scope_label = (
    f"{tag_category} = {tag_value}"
    if tag_category and tag_value
    else "All Assets"
)   # used for analyst workbook _Metadata Scope row (D-19)
```

`subtitle` and `scope_label` agree today (one is the `"Scope: " +` prefix of the other), but they're computed twice with hand-rolled identical conditionals. The subtle bug surface: if a future change adds a new filter dimension to one path but not the other, the analyst workbook's `_Metadata!Scope` cell and the PDF's cover-subtitle line silently drift apart.

**Severity rationale:** Info — code-quality nit, no current bug. Low cost to factor out and consolidate.

**Fix:**

```python
scope_label = (
    f"{tag_category} = {tag_value}"
    if tag_category and tag_value
    else "All Assets"
)
subtitle = f"Scope: {scope_label}"
```

Single source of truth, drift impossible.

---

### IN-03: `scripts/smoke_email_phase2.py` `--no-stub-panels` doc references `{%% else %%}` correctly but argparse will not unescape on Windows

**File:** `D:\Projects\vuln-reporting\scripts\smoke_email_phase2.py:247-249`

**Issue:**
The `--no-stub-panels` help text reads:

```python
help="Skip the synthetic Phase 3-style panels and let the legacy "
     "KPI-tile fallback render (use to confirm the {%% else %%} path).",
```

The `{%% else %%}` is a defensive-`%`-escape (so argparse's `%(prog)s`-style interpolation doesn't mangle it on display), but the resulting rendered help text shows `{% else %}` which is the actual Jinja2 syntax. That's fine for argparse, but on a Windows shell this string is also a `for /F` token in batch contexts — running this in `cmd.exe` with a wrapper script that pipes `--help` through `for` (or any shell that interprets `%`) will get scrambled output. PowerShell handles it correctly.

This is a minor ergonomics issue — the script already documents `.venv\\Scripts\\python.exe` as the invocation idiom, which sidesteps the issue. Worth a single-line comment so future maintainers don't "fix" the `%%` thinking it's a typo.

Also: the smoke script's `_smtp_send` uses `smtp.login(user, pwd)` directly without context-managing the password (composes the variable into the SMTPLib call only). The `pwd` variable lives in the function's frame and is not redacted. Acceptable for an off-network UAT helper, but worth noting that any traceback printed during the SMTP send (if `smtp.login` raises something like `SMTPAuthenticationError`) may surface the password in the exception args depending on the SMTP server. Standard library `smtplib` does not embed the password in `SMTPAuthenticationError` args, so this is theoretical. Not a finding to action.

**Fix:** Add a one-line comment above the help string:

```python
# %% is an argparse double-percent escape — renders as a single % in help output.
```

---

## Notes On Items Confirmed Clean

For the record, the following adversarial concerns were checked and found clean:

- **Logging discipline (`%s`/`%d` lazy formatting, no f-strings inside `logger.*`)** — verified via grep across all 10 in-scope files; no offending sites.
- **`# noqa: PLC0415` on deferred imports** — every in-function import in the new code (`composer.py:714`, `composer.py:945`, `composer.py:1375-1376`, `base.py:440`, `base.py:579`, `smoke_email_phase2.py:113`, `136`, `145`, etc.) carries the noqa.
- **`management_summary.py` Option-2 deferral** — bespoke `_build_pdf` (line 2399) and `build_email_body` (line 2405) flows untouched; only additive `analyst_excel: None` + `email_body_html: ""` keys added at lines 2465-2466.
- **Legacy `build_email_body()`** — byte-unchanged at `email_template.py:347-418`; the new `build_email_body_modular()` is a sibling at lines 425-530.
- **Email template `{% else %}` legacy path** — preserves the legacy KPI-tiles block when `module_panels_html` is empty/absent; backward-compat for `ops_remediation`, `vuln_export`, `unscanned_assets` recipients.
- **Empty-data guard discipline** — `_build_rag_strip_page` has explicit `_gray_placeholder()` fallback paths for registry miss, exception, and malformed dict (composer.py:738-769); `assemble_analyst_workbook` has D-20 all-empty short-circuit (composer.py:1011-1019); `_write_analyst_metadata_tab` succeeds with empty failures list. No render-method crashes on zero-row `ModuleData`.
- **Email-client compatibility** — `assemble_email_body()` emits inline-style `<table>`/`<div>` only; no `<style>` blocks, no JS, no flexbox; verified by inspecting the panel HTML and the error placeholder.
- **Bundle-dict mutable-default avoidance** — `run_full_pipeline` constructs the bundle as a fresh `{}` literal per call (composer.py:1378-1386); no `def f(bundle: dict = {})` anti-pattern.
- **Module ordering across all four channels** — every channel iterates `for data in results:` where `results` was built by `run_all()` iterating `self._module_configs`; D-07/D-27 invariant holds.
- **SMTP credentials in smoke script** — pulled from `.env` via `python-dotenv`; never logged (the `logger.info` lines log host/port/use_ssl only); never written to disk; `smtp.login()` is the only call site.

---

_Reviewed: 2026-05-06T07:58:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
