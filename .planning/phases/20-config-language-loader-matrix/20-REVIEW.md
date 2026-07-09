---
phase: 20-config-language-loader-matrix
reviewed: 2026-07-09T00:00:00Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - delivery/config_loader.py
  - run_all.py
  - scripts/generate_delivery_matrix.py
  - contacts.example.yaml
  - tests/test_config_loader.py
  - tests/test_effective_config_golden.py
  - tests/test_generate_delivery_matrix.py
  - tests/fixtures/phase20_config_legacy/delivery_config.yaml
  - tests/fixtures/phase20_config_twin/contacts.yaml
  - tests/fixtures/phase20_config_twin/deliveries.d/exec.yaml
  - tests/fixtures/phase20_config_twin/deliveries.d/remediation.yaml
  - tests/fixtures/phase20_config_twin/deliveries.d/tag_profile.yaml
  - tests/baselines/effective_config_golden.json
  - .gitignore
findings:
  critical: 0
  warning: 4
  info: 5
  total: 9
status: issues_found
---

# Phase 20: Code Review Report

**Reviewed:** 2026-07-09
**Depth:** standard
**Files Reviewed:** 14
**Status:** issues_found

## Summary

Phase 20 adds a resolve-before-validate config loader (`delivery/config_loader.py`)
for the v1.6 config language (`contacts.yaml` + `deliveries.d/*.yaml`), a delivery-matrix
generator (`scripts/generate_delivery_matrix.py`), directory-mode delegation in
`run_all._load_config`, and a two-way effective-config golden test. I ran all three
Phase 20 test files in the project venv — **all checks pass**, including the byte-identical
two-way golden equality (legacy single-file twin ≡ migrated directory twin ≡ committed
golden) and both fixtures passing the unchanged schema.

The core Hard-Rule-2 (PII) invariant holds for the design under review: the schema-gated
group dict carries no `owner`/`contact` key (`_PASSTHROUGH_GROUP_KEYS` deliberately excludes
them), the metadata side channel supplies names only, and the matrix generator never routes
`recipients`/`cc`/`reply_to` into its output — the generator test asserts zero `@example.invalid`
leaks in both markdown and HTML. The `_PASSTHROUGH_GROUP_KEYS` allowlist is correctly aligned
with the schema's group-level `additionalProperties: false` allowed keys (verified against
`delivery_config.schema.yaml`), so the side-channel isolation is sound.

Key concerns are all in the matrix generator and the loader's silent-drop behavior — none
rise to a security/data-loss BLOCKER, but the unescaped HTML/markdown rendering of
operator-controlled config strings and the silent discard of inline `email.cc`/`email.reply_to`
in directory mode are real robustness/correctness gaps worth fixing.

## Warnings

### WR-01: `render_html` interpolates config values without HTML-escaping

**File:** `scripts/generate_delivery_matrix.py:206-209`
**Issue:** Cell values (delivery `name`, `owner`, `reports`, `filters`, `contact`) are
interpolated raw into `<th>`/`<td>` via f-strings with no escaping:
```python
header_html = "".join(f"<th>{col}</th>" for col in _MATRIX_COLUMNS)
body_html = "\n".join(
    "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
)
```
These values come from operator-authored YAML, but a group name / owner / `report_title`
containing `&`, `<`, or `>` (e.g. `Team A & B`, `filters` values, a `contact` like
`ops<->sec`) will corrupt or inject markup into a document the module docstring explicitly
labels "Safe to publish as a CI artifact." The codebase already has an established escaping
helper (`exporters/pdf_exporter.py:73 _html_escape`) and uses `autoescape` in
`delivery/email_template.py:58`; this new HTML renderer bypasses that convention.
**Fix:** Escape every interpolated cell before rendering:
```python
import html
# ...
header_html = "".join(f"<th>{html.escape(col)}</th>" for col in _MATRIX_COLUMNS)
body_html = "\n".join(
    "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
    for row in rows
)
```

### WR-02: `render_markdown` does not escape the `|` cell delimiter

**File:** `scripts/generate_delivery_matrix.py:191-192`
**Issue:** Rows are joined with `" | "` with no escaping of a literal `|` inside a cell:
```python
for row in rows:
    lines.append("| " + " | ".join(row) + " |")
```
Any delivery `name`, `owner`, `report_title`, `contact`, or filter value containing a pipe
(legal in YAML strings) silently breaks the Markdown table structure, shifting or splitting
columns in the published matrix. This is the same "published artifact integrity" concern as
WR-01, in the default (`markdown`) output path.
**Fix:** Escape pipes (and ideally newlines) per cell, e.g.
`cell.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")` applied in `_matrix_rows`
or at join time.

### WR-03: Inline `email.cc` / `email.reply_to` silently dropped in directory mode

**File:** `delivery/config_loader.py:276-283, 292` (and `resolve_delivery_email:138-143`)
**Issue:** Directory mode rejects an inline `email:` block only when it carries `recipients`:
```python
inline_email = delivery.get("email")
if isinstance(inline_email, dict) and inline_email.get("recipients"):
    errors.append(... "inline email.recipients ...")
    continue
```
`resolve_delivery_email` then reads only `email.subject` from that stub and builds its own
`cc`/`reply_to` from the contact + defaults. An operator who writes
`email: {cc: [...], reply_to: ...}` (no `recipients`) in a `deliveries.d/*.yaml` file gets
those values **silently discarded** with no error and no warning — the D-03 "all who flows
through contact:" intent is enforced only for `recipients`, not the other addressing keys.
This is a fail-silent surprise on a channel the whole phase is trying to make loud.
**Fix:** In the inline-email guard, also reject (or at minimum warn on) an inline `email`
block that carries any addressing key other than `subject`:
```python
if isinstance(inline_email, dict):
    stray = set(inline_email) - {"subject"}
    if stray:
        errors.append(
            f"{team_file.name}: delivery '{name}' has inline email keys {sorted(stray)} — "
            "directory mode routes cc/recipients/reply_to through contact: only"
        )
        continue
```

### WR-04: `--config` flag ignored for directory-mode / dry-run detection in `run_all._dry_run`

**File:** `run_all.py:452, 473`
**Issue:** `_dry_run` hardcodes `config_path = ROOT_DIR / "delivery_config.yaml"` and keys
directory-mode resolution off `(config_path.parent / "deliveries.d").is_dir()`. `_load_config`
correctly honors an injected `config_path` (used by the tests), but the `--dry-run` UX path
always inspects `ROOT_DIR`, so a `deliveries.d/` located anywhere other than `ROOT_DIR`
(e.g. the prod `shared/` symlink layout referenced in the `resolve_config` docstring, or a
`--config` override if one is later wired in) will have its resolution errors/warnings
skipped in the dry-run report even while `_load_config` resolves them. The two code paths
disagree on where config lives.
**Fix:** Thread the same `config_path` used by `_load_config` (resolved from any `--config`
override / the `shared/` layout) into `_dry_run`, and drive both the schema re-read and the
`deliveries.d/` check from that single resolved path instead of a second hardcoded
`ROOT_DIR / "delivery_config.yaml"`.

## Info

### IN-01: Nameless deliveries collide as "duplicate delivery name: None"

**File:** `delivery/config_loader.py:272, 284-290`
**Issue:** `name = delivery.get("name")` may be `None`. Two deliveries that both omit `name:`
hit `if name in seen_names` on the second one and are reported as
`duplicate delivery name: None` rather than a clearer "delivery missing required name:".
The schema is the eventual safety net (group `name` is required, `minLength: 1`), so this
still fails loud — only the error message is misleading.
**Fix:** Special-case a missing/blank `name` with a dedicated error before the duplicate
check, e.g. `if not name: errors.append(f"{team_file.name}: delivery missing 'name'"); continue`.

### IN-02: Inline-email check ordered before duplicate-name check obscures the real error

**File:** `delivery/config_loader.py:276-290`
**Issue:** The inline-`email.recipients` guard (line 277) runs before the duplicate-name
guard (line 284). A delivery that is BOTH a duplicate name AND carries inline
`email.recipients` reports only the inline-email error, masking the duplicate. Both paths
`continue` and both ultimately zero out `groups`, so behavior is correct; only diagnostic
completeness suffers.
**Fix:** Optional — validate name/duplicate first so the most structural error surfaces, or
accumulate both errors instead of `continue`-ing on the first.

### IN-03: `_matrix_rows` assumes every metadata/report cell is a string

**File:** `scripts/generate_delivery_matrix.py:174, 192`
**Issue:** `reports = ", ".join(group.get("reports") or [])` and the later
`" | ".join(row)` (markdown) / `str(cell)` absence (html) assume list-of-str and str cells.
The matrix generator calls `resolve_config` directly and renders **before** any schema
validation, so a malformed `owner:` (YAML list/int), `contact:`, or a non-string entry in
`reports:` raises `TypeError` at join time instead of producing a clean config error.
In normal operation the schema-valid config makes this unreachable, but the generator's
pre-schema position removes that guarantee.
**Fix:** Coerce with `str(...)` at row construction (pairs naturally with the WR-01/WR-02
escaping fix), and/or guard `reports` entries with `str`.

### IN-04: `main()` SystemExit handler collapses distinct exit codes

**File:** `scripts/generate_delivery_matrix.py:242-244`
**Issue:**
```python
except SystemExit as e:
    code = e.code if isinstance(e.code, int) else 2
    return code if code != 0 else 0
```
The `code if code != 0 else 0` branch is a no-op (returns `0` when `code == 0`, i.e. the
identity), and a non-int non-None `e.code` (a string message) is mapped to `2` which is
correct for argparse but conflates argparse-usage exits with any other `SystemExit`. Harmless
today because only `_MatrixArgumentParser.error` (exit 2) and `--help` (exit 0) raise here,
but the redundant ternary reads as if it intends something it doesn't.
**Fix:** Simplify to `return e.code if isinstance(e.code, int) else 2`.

### IN-05: `resolve_config` returns partial metadata on the error path

**File:** `delivery/config_loader.py:309-310`
**Issue:** On any collected error the function returns `([], errors, warnings,
metadata_by_delivery_name)` — `groups` is emptied (correct) but `metadata_by_delivery_name`
still contains entries for the deliveries processed before the failure. Callers under review
discard metadata on the error path (`_load_config` unpacks `_metadata`, the matrix generator
returns exit 3 before rendering), so this is currently benign. Flagging because the docstring
(lines 204-205) says "On any error ... `groups` is `[]`" without noting the fourth return is
NOT correspondingly cleared — a future consumer that reads metadata regardless of `errors`
could surface owner/contact names for a config that failed to resolve.
**Fix:** Either clear `metadata_by_delivery_name` on the error return for symmetry with
`groups`, or document explicitly that metadata may be partially populated when `errors` is
non-empty.

---

_Reviewed: 2026-07-09_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
