---
phase: 05-pdf-chrome-foundation
plan: 01
subsystem: pdf-chrome-config-surface
tags: [config, schema, dependencies, foundation]
requires: []
provides:
  - "config.HEADER_BG_COLOR (str = '#1a2332')"
  - "config.LOGO_PATH (Path | None = None)"
  - "delivery_config.schema.yaml: groups[].privacy_label (optional, regex ^[^\"]+$)"
  - "requirements.txt: pypdf~=6.0"
affects: []
tech_stack:
  added:
    - pypdf~=6.0 (test/dev only)
  patterns:
    - "Operator-overridable config constants live at end of config.py with banner comment"
    - "Optional cosmetic per-group fields cluster after report_title in schema"
key_files:
  created: []
  modified:
    - config.py
    - delivery_config.schema.yaml
    - requirements.txt
decisions:
  - "privacy_label safety: schema-validate (regex `^[^\"]+$`) over silent-escape — surface operator typos at --dry-run time rather than ship a quietly-mangled CSS footer string. PdfChromeConfig.__post_init__ in plan 05-02 will re-enforce in code (defense in depth)."
  - "pypdf pinned ~=6.0 (compatible-release, major-version locked) — installed version is 6.11.0. Matches dev/test-only role; major-version pin guards against future breaking API changes."
metrics:
  tasks_completed: 3
  files_modified: 3
  duration_minutes: ~5
  completed_at: "2026-05-13T13:09:00Z"
---

# Phase 5 Plan 01: PDF Chrome Foundation — Config Surface Summary

Landed the three-knob config surface for the upcoming shared PDF chrome utility: two `config.py` constants, one optional YAML schema field, and one test-only `requirements.txt` pin. Zero behavior change to existing reports.

## What Shipped

### 1. `config.py` — HEADER_BG_COLOR + LOGO_PATH (CHROME-CFG-01, CHROME-CFG-02)

Appended a new banner-style section at the end of `config.py`:

```python
HEADER_BG_COLOR: str       = "#1a2332"   # CHROME-CFG-01
LOGO_PATH:       Path | None = None      # CHROME-CFG-02
```

Verified: `from config import HEADER_BG_COLOR, LOGO_PATH` resolves to `'#1a2332'` and `None`.

Commit: `35523ac` — `feat(05-01): add HEADER_BG_COLOR and LOGO_PATH constants to config.py`

### 2. `delivery_config.schema.yaml` — optional privacy_label (CHROME-CFG-04, CHROME-COMPAT-02)

Inserted under `definitions.group.properties` immediately after `report_title`:

```yaml
privacy_label:
  type: string
  description: |
    Optional per-group override for the PDF footer privacy label ...
  minLength: 1
  pattern: '^[^"]+$'
```

Field is NOT added to `required:` — stays optional. Default `"Confidential"` resolves at the `run_group()` call site (Phase 6).

Three verifications all pass:
- Existing `delivery_config.yaml` still validates (CHROME-COMPAT-02 evidence — no regression for deployed groups).
- A group with `privacy_label: "Internal Only"` validates.
- A group with a double-quote inside `privacy_label` is rejected by `jsonschema.validators.validator_for(schema).iter_errors(...)`.

Commit: `393e269` — `feat(05-01): add optional privacy_label field to delivery_config schema`

### 3. `requirements.txt` — pypdf~=6.0

Appended:

```
# Testing — PDF text extraction for chrome integration tests (plan 05-04)
pypdf~=6.0
```

`pip install -r requirements.txt` completed without conflicts. Installed version: **`pypdf 6.11.0`**.

Commit: `90aaedf` — `chore(05-01): pin pypdf~=6.0 as test-only dependency`

## CHROME-COMPAT-02 Evidence

The deployed `delivery_config.yaml` validates against the updated schema unchanged. No group currently declares `privacy_label`, and that remains valid (the field is optional, no default injected by the schema). The `run_group()` default-resolution wiring is Phase 6 work, not this plan.

```
$ python -c "import yaml, jsonschema; jsonschema.validate(yaml.safe_load(open('delivery_config.yaml')), yaml.safe_load(open('delivery_config.schema.yaml'))); print('OK')"
OK
```

## Privacy Label Safety Choice — schema-validate vs silent-escape

**Chose:** schema-level rejection via `pattern: '^[^"]+$'`.

**Rationale:** The privacy label is interpolated into a CSS `content: "..."` string by `reports/modules/pdf_chrome.py` (plan 05-02). A stray double-quote would either:
1. Break the CSS silently and leave the footer empty / malformed (silent-escape route).
2. Be caught at `--dry-run` time with a clear `jsonschema.ValidationError` naming the offending field (schema-validate route).

Operators run `--dry-run` before delivery; surfacing the typo at validation time is strictly better than shipping a mangled footer to a CISO. Plan 05-02 will add a defense-in-depth `__post_init__` check on `PdfChromeConfig` for direct Python construction paths that bypass YAML validation.

## Deviations from Plan

None — plan executed exactly as written. All three tasks completed first-try with all verification commands passing.

## Verification Sequence

Final smoke (per plan `<verification>` block):

```
$ python -c "from config import HEADER_BG_COLOR, LOGO_PATH; print(HEADER_BG_COLOR, LOGO_PATH)"
#1a2332 None
$ python -c "import yaml, jsonschema; jsonschema.validate(yaml.safe_load(open('delivery_config.yaml')), yaml.safe_load(open('delivery_config.schema.yaml'))); print('OK')"
OK
$ python -c "import pypdf; print(pypdf.__version__)"
6.11.0
$ .venv/Scripts/python.exe tests/test_phase4_schema_validation.py
PASS  A_current_yaml_clean
PASS  B_frequency_typo_rejected
PASS  C_analyst_detail_non_boolean_rejected
PASS  D_unknown_report_slug_rejected
PASS  E_malformed_email_rejected
PASS  F_additional_properties_rejected
All checks passed.
```

Note: `tests/test_phase4_schema_validation.py` is a script-style runner (not pytest collection-compatible); invoked directly via `python tests/test_phase4_schema_validation.py` per its docstring. All 6 schema-validation regression checks PASS — no regression.

## Downstream Hooks

- Plan 05-02 (`PdfChromeConfig` dataclass + `PdfChrome` class) imports `HEADER_BG_COLOR` and `LOGO_PATH` from `config.py` for defaults.
- Plan 05-04 integration test imports `pypdf` for per-page text extraction.
- Phase 6 wires `group.get("privacy_label", "Confidential")` at the `run_group()` call site (CHROME-COMPAT-02 default resolution).

## Self-Check: PASSED

- FOUND: `config.py` (HEADER_BG_COLOR + LOGO_PATH block present)
- FOUND: `delivery_config.schema.yaml` (privacy_label property present)
- FOUND: `requirements.txt` (pypdf~=6.0 line present)
- FOUND commit: `35523ac` (Task 1)
- FOUND commit: `393e269` (Task 2)
- FOUND commit: `90aaedf` (Task 3)
