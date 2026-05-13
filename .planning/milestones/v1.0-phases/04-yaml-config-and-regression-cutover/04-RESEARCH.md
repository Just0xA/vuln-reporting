# Phase 4: YAML Config and Regression Cutover - Research

**Researched:** 2026-05-07
**Domain:** YAML schema validation, runtime config validation, opt-out plumbing, regression cutover
**Confidence:** HIGH (entire surface is in-repo; no external API uncertainty)

## Summary

Phase 4 is almost entirely a wiring exercise — the upstream pieces (composer kwarg, bundle-driven email attachment, schema file) are already in place from Phases 1-3. There are exactly four moves:

1. Add an optional `analyst_detail: boolean` property to `delivery_config.schema.yaml` under the `group` definition.
2. Wire `jsonschema.validate()` into `run_all.py:_load_config()` and ensure `scheduler.py` uses the same validated load path.
3. In `run_all.py:run_group()`, read `group_config.get("analyst_detail", True)` and forward it to `board_summary`'s `run_report()` as a new kwarg, which in turn flips `composer.run_full_pipeline(generate_analyst=...)` (currently hardcoded `True` at `reports/board_summary.py:247`).
4. Add a sample group to `delivery_config.yaml` that demonstrates `analyst_detail: false`, then run a regression-cutover comparison against the pre-v1 baseline for every currently-configured `board_summary` group.

**Primary recommendation:** Replace the hand-rolled `_validate_group()` (run_all.py:241-318) with a `jsonschema`-driven validator while keeping a thin wrapper for the `_dry_run()` rich-table summary. The schema is already richer than the hand-rolled checks (`format: email`, `pattern: HH:MM`, conditional `if/then/else` for weekly/monthly required fields, `dependencies` between `tag_category`/`tag_value`).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Schema definition | Config (`delivery_config.schema.yaml`) | — | Single source of truth for valid config shape |
| Runtime validation | CLI loader (`run_all.py:_load_config`) | Scheduler (`scheduler.py` reuses `_load_config`) | Validation must run on every load path before any group executes |
| `analyst_detail` toggle read | Orchestrator (`run_all.py:run_group`) | Report script (`reports/board_summary.py:run_report`) | YAML field → kwarg lives at the orchestrator boundary |
| Analyst workbook generation switch | Composer (`reports/modules/composer.py:run_full_pipeline`) | — | Already in place via `generate_analyst=` kwarg; Phase 4 only flips the value |
| Analyst attachment routing | Email sender (`delivery/email_sender.py:_collect_attachments`) | — | Already bundle-driven (`analyst_excel` Path → attach) — no Phase 4 change |
| Regression cutover | Test harness / manual diff | — | End-to-end equivalence check on real Tenable data, not unit test |

## Existing Surface Inventory

### `delivery_config.schema.yaml` (already exists — 212 lines)

JSON Schema draft-07 expressed as YAML. Top-level shape:
- `groups: array` (required, `minItems: 0`)
- Each group has `$ref: "#/definitions/group"` requiring `name`, `schedule`, `reports`, `email`; optional `description`, `filters`, `csv_severities`, `modules`, `module_options`.
- `schedule` uses conditional validation: `if frequency == weekly then require day_of_week + time; else if monthly then require day_of_month + time` (lines 141-157).
- `email` requires `subject` + `recipients` (`minItems: 1`, `format: email`); `cc` defaults `[]`; `reply_to` is `format: email`.
- `filters` allows empty `{}` and uses `dependencies` to require `tag_category`/`tag_value` together.
- `additionalProperties: false` on `group`, `schedule`, `filters`, `email` — adding `analyst_detail` requires a schema edit.
- **Schema gap for Phase 4:** `reports.items.enum` (lines 60-69) is missing `board_summary`, `unscanned_assets` — both are in `run_all.py:_VALID_REPORTS` but not in the schema. This is a latent bug: a config using `board_summary` would fail schema validation today. Phase 4 must reconcile both lists.

### `delivery_config.yaml` (current state)

Single group only:
- `"Test Pull"` — `frequency: on_demand`, `reports: [board_summary]`, `filters: {}`, recipients `monroe.justin@gmail.com`. This is the only currently-configured `board_summary` group, which simplifies the regression cutover.

### `run_all.py:_load_config()` (lines 137-168)

- Reads `delivery_config.yaml` via `yaml.safe_load`.
- Returns `[]` (empty list) on missing file, parse error, non-dict root, or non-list `groups` — does **not** raise. Errors are logged.
- No call to `jsonschema.validate()` anywhere in the file (verified by grep).

### `run_all.py:_validate_group()` (lines 241-318)

Hand-rolled checks, called only from `_dry_run()` (line 353):
- `name` non-empty
- `schedule.frequency` in `_VALID_FREQUENCIES`
- For weekly: `day_of_week` in `_VALID_DAYS`, `time` parseable HH:MM
- For monthly: `day_of_month` int in 1-28, `time` parseable
- `reports` non-empty list, each slug in `_VALID_REPORTS`
- `email.recipients` non-empty list

**What it misses vs. the schema:**
- `format: email` on recipients/cc/reply_to (the schema validates email format; the hand-rolled does not)
- `pattern: ^([01][0-9]|2[0-3]):[0-5][0-9]$` for `time` (hand-rolled only checks two integer parts split on `:`)
- `additionalProperties: false` (hand-rolled silently ignores unknown keys — a typo like `recipeints` is invisible today)
- `dependencies: tag_category requires tag_value` (hand-rolled does not check)
- `csv_severities`, `modules`, `module_options` not validated by hand-rolled at all

### `scheduler.py`

Imports `_load_config, _is_due, run_group` from `run_all` (line 54). It does **not** independently validate — it relies entirely on `_load_config()` returning a list of groups. Wiring `jsonschema` into `_load_config()` automatically covers daemon, run-due, and manual modes.

### `jsonschema` package

- Pinned at `jsonschema==4.23.0` in `requirements.txt:39`
- Confirmed via Grep: not imported anywhere in the source tree today
- Standard usage pattern: `from jsonschema import validate, ValidationError; validate(instance, schema)` raises `ValidationError` with `.absolute_path` (a `deque`), `.message`, `.validator`, `.validator_value`, `.instance`

### Composer + email plumbing already in place (NO Phase 4 changes needed here)

| Site | State | Phase 4 action |
|------|-------|----------------|
| `reports/modules/composer.py:run_full_pipeline(... generate_analyst=True ...)` | ✅ kwarg exists since Phase 2 (D-25) | None |
| `reports/board_summary.py:247` calls `composer.run_full_pipeline(... generate_analyst=True ...)` | ⚠️ hardcoded `True` | Replace with kwarg from `run_report` signature |
| `reports/board_summary.py:82-91` `run_report(..., cache_dir)` signature | ⚠️ no `analyst_detail` kwarg yet | Add `analyst_detail: bool = True` |
| `run_all.py:584-597` builds `report_kwargs` dict | ⚠️ does not pass `analyst_detail` | Add `report_kwargs["analyst_detail"] = group_config.get("analyst_detail", True)` for `board_summary` (and any other future analyst-producing slug) |
| `delivery/email_sender.py:149-151` attaches `analyst_excel` when path exists | ✅ bundle-driven, no allowlist | None — when `generate_analyst=False`, bundle returns `analyst_workbook_path=None`, attach is silently skipped |

## `analyst_detail` Opt-Out Plumbing Path

End-to-end trace (top-down):

1. `delivery_config.yaml` → optional `analyst_detail: false` per group (default `true` when absent)
2. `run_all.py:_load_config()` → schema-validated; field passed through verbatim
3. `run_all.py:run_group()` (line 575 loop) → for `slug == "board_summary"`, read `group_config.get("analyst_detail", True)`, add to `report_kwargs`
4. `reports/board_summary.py:run_report()` → accepts new kwarg `analyst_detail: bool = True`
5. `reports/board_summary.py:247` → `composer.run_full_pipeline(..., generate_analyst=analyst_detail, ...)`
6. `composer.run_full_pipeline()` → forwards to `assemble_analyst_workbook(generate=...)`, which short-circuits and returns `None` when `generate=False`
7. Bundle returned with `analyst_workbook_path=None`
8. `board_summary.run_report()` returns `analyst_excel=None`
9. `delivery/email_sender.py:_collect_attachments()` skips the analyst attachment (Path is None)
10. Email goes out with PDF + standard Excel + email panels — no analyst workbook

**Default semantics (CONFIG-01):** When `analyst_detail` is absent, downstream sees `True` because `dict.get(key, True)` returns the default. `jsonschema` does not auto-inject defaults from the schema (see Risks); Python's `.get(key, True)` is the canonical injection point.

## `jsonschema` Integration Pattern

### Loading

```python
import yaml
from jsonschema import Draft7Validator, ValidationError

def _load_schema(schema_path: Path) -> dict:
    with open(schema_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)

def _validate_config(raw: dict, schema: dict) -> list[str]:
    """Returns list of human-readable error strings; empty = valid."""
    validator = Draft7Validator(schema)
    errors = []
    for err in sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path)):
        # Build a path like "groups[0].schedule.frequency"
        path_parts = []
        for p in err.absolute_path:
            if isinstance(p, int):
                path_parts.append(f"[{p}]")
            else:
                path_parts.append(f".{p}" if path_parts else str(p))
        path = "".join(path_parts) or "<root>"
        # Try to surface the offending group name for the error UX
        group_name = ""
        if len(err.absolute_path) >= 2 and err.absolute_path[0] == "groups":
            try:
                group_name = raw["groups"][err.absolute_path[1]].get("name", "")
            except (KeyError, IndexError, TypeError):
                pass
        prefix = f"[{group_name}] " if group_name else ""
        errors.append(f"{prefix}{path}: {err.message}")
    return errors
```

`Draft7Validator.iter_errors()` is preferred over `validate()` because it yields **all** errors instead of raising on the first one — better for the rich-table dry-run UX and CI logs.

### Plug-in points

| File | Function | Action |
|------|----------|--------|
| `run_all.py` | `_load_config` (line 137) | After `yaml.safe_load`, load schema, run validator, log errors and return `[]` on validation failure |
| `run_all.py` | `_dry_run` (line 321) | Replace per-group `_validate_group()` call with reuse of `_validate_config()` results — group rows show validation errors from the schema, not the hand-rolled checks |
| `run_all.py` | `main()` (line 742+) | When `_load_config` returns `[]` due to validation, exit non-zero with a CLI-friendly summary (CONFIG-02 acceptance criterion) |
| `scheduler.py` | inherits via `from run_all import _load_config` | No change needed — schema validation propagates automatically |

### Error UX

Acceptance criterion (CONFIG-02): "a misconfigured group exits non-zero with an error naming the offending group and field (e.g. `frequency: weeky` is caught at startup, not at run time)".

Sample output:
```
[Test Pull] groups[0].schedule.frequency: 'weeky' is not one of ['weekly', 'monthly', 'on_demand']
```

The `[group_name]` prefix is built by indexing `raw["groups"][err.absolute_path[1]]["name"]` whenever the error path starts with `groups[N]`. For top-level errors (e.g. missing `groups` key), no prefix is added.

## Schema Edits Required (CONFIG-01, CONFIG-04)

Add to `delivery_config.schema.yaml` under `definitions.group.properties`:

```yaml
analyst_detail:
  type: boolean
  description: |
    Optional opt-out for the analyst-detail companion workbook on
    module-composed reports (board_summary, management_summary).
    Defaults to true when omitted. Set to false when the recipient
    group should receive only the PDF, standard Excel, and email
    panels — no analyst drill-down workbook.
  default: true
```

`additionalProperties: false` on `group` already permits this addition once declared. **The `default: true` value in the schema is informational only** — JSON Schema draft-07 does not require validators to populate defaults. Python code reads via `group_config.get("analyst_detail", True)`.

Also reconcile the `reports` enum (CONFIG-04 ancillary fix — out-of-spec but required for any working schema-validated config):
- Add to enum: `board_summary`, `unscanned_assets`
- These exist in `run_all.py:_VALID_REPORTS` (lines 75-87) but are missing from `delivery_config.schema.yaml:60-69`.

## Sample YAML Showing Opt-Out (CONFIG-04)

```yaml
- name: "Board — Direct Delivery (no analyst pack)"
  description: |
    Demonstrates the analyst_detail opt-out. When this delivery becomes
    direct (CISO inbox) rather than reviewer-mediated, set analyst_detail:
    false to suppress the drill-down workbook. PDF + standard Excel +
    email panels still ship.
  schedule:
    frequency: on_demand
  filters: {}
  reports:
    - board_summary
  analyst_detail: false      # opt-out — default is true
  email:
    subject: "Board Vulnerability Metrics — Executive Snapshot"
    recipients:
      - ciso@company.com
    reply_to: security@company.com
```

## Regression Cutover Plan (BOARD-08, success criterion #4)

### Currently-configured `board_summary` recipient groups

Searched `delivery_config.yaml` — exactly **one** group runs `board_summary`:
- `"Test Pull"` — on_demand, no tag filter, single recipient

This is a developer/test config, not a production-deployed config. The regression cutover bar is therefore "this one group renders correctly with the v1 deltas" rather than a multi-group matrix.

### What "pre-v1 baseline" means

There is no committed snapshot of pre-v1 PDF/Excel binaries. The practical interpretation:

- **PDF metric values** (Scan Coverage SLA %, Critical Remediation SLA %, High-Risk Assets %, Aged Vulnerability Assets %) — must match the values produced by the same report against the same Tenable data before any Phase 1-4 changes. Compare numerically, not byte-wise (timestamps, font hinting, and PDF object ordering can vary).
- **Excel rows** — `_Metadata` row count and the four metric-tab row counts must match the pre-v1 baseline. The board metric module Excel tabs are defined by `reports/modules/*_module.py:render_excel_tabs()`; their row counts are deterministic for a given vuln/asset DataFrame.
- **Recipient list** — taken verbatim from `delivery_config.yaml`; must be unchanged.

### Intentional deltas (success criterion calls these out as expected)

1. **Added analyst Excel attachment** (when `analyst_detail: true`, default) — separate `.xlsx` file `board_summary_analyst.xlsx` (Phase 2 D-19/D-20).
2. **Upgraded email body** — modular per-module panels via `build_email_body_modular()` instead of legacy KPI-tile shell (Phase 2 D-22, Phase 3 routing).
3. **RAG-strip cover page** — page 1 of PDF now shows the four-cell RAG strip (Phase 2 Plan 02-01).

### Practical cutover procedure

1. Run `python run_all.py --group "Test Pull" --no-email` against current `main` (post-Phase 3) — this is "v1 in flight."
2. Capture: `output/<ts>_Test_Pull/board_summary/board_summary.pdf`, `board_summary.xlsx`, `board_summary_analyst.xlsx`.
3. Compare to a pre-v1 reference run (re-run from a checkout of the pre-Phase-1 commit, or accept the four metric percentages from the Phase 3 UAT report at `.planning/phases/03-board-summary-module-migration/03-UAT.md`).
4. Repeat with `analyst_detail: false` added to the YAML — confirm `board_summary_analyst.xlsx` is **not** produced and not attached.
5. Confirm a deliberate config error (`frequency: weeky`) causes non-zero exit at startup with `[Test Pull] groups[0].schedule.frequency: 'weeky' is not one of ...`.

The Phase 2 composer pipeline test (`tests/test_phase2_composer_pipeline.py`, 11/11 green per Phase 3 UAT) covers the structural regression. The cutover is the end-to-end-on-real-Tenable-data check on top of that.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Per-field config validation | Extending `_validate_group()` line by line | `jsonschema.Draft7Validator.iter_errors()` against the existing schema | The schema already encodes `format: email`, HH:MM regex, conditional weekly/monthly required fields, `additionalProperties: false`, `dependencies`. Hand-rolled checks miss all of those. |
| Default value injection | A second pass that walks the schema looking for `default:` keys | `dict.get("analyst_detail", True)` at the read site | jsonschema 4 does not apply defaults by design. The standard idiom is to inject at the access boundary. |
| Email format validation | Regex like `r"[^@]+@[^@]+\.[^@]+"` | `format: email` in schema (already present at lines 198, 205, 211) + `Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)` | Built-in format checkers cover the RFC-relevant edge cases; rolling our own is a known anti-pattern. |
| Pre-v1 binary regression diff | `cmp` on PDF bytes | Compare metric values + row counts | PDF byte stability is not contractual — fonts, timestamps, object ordering all drift. |

## Common Pitfalls

### Pitfall 1: `Draft7Validator` `format_checker` is opt-in

**What goes wrong:** `format: email` in the schema is silently ignored unless you pass a `format_checker` to the validator. Misconfigured emails sail through.

**How to avoid:** Instantiate as `Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)`. Test the failure path with a known-bad email like `not-an-email`.

### Pitfall 2: `additionalProperties: false` will reject `analyst_detail` until the schema is edited

**What goes wrong:** The current schema declares `additionalProperties: false` on the `group` definition (line 36). Adding `analyst_detail: false` to a YAML group **without first editing the schema** causes validation to fail: `Additional properties are not allowed ('analyst_detail' was unexpected)`.

**How to avoid:** Schema edit must land in the same commit (or earlier) as any YAML edit that uses `analyst_detail`. The plan ordering matters: schema first, then YAML, then code.

### Pitfall 3: `_validate_group()` and `jsonschema` may diverge

**What goes wrong:** If the hand-rolled `_validate_group()` is left in place "as defense in depth," the rich-table dry-run output and the actual validation rules can drift. Future schema additions won't show up in `--dry-run` until the hand-rolled is updated.

**How to avoid:** Replace `_validate_group()` with a thin wrapper that calls `_validate_config()` once and bins errors by group index, so the rich table still renders per-group rows but the validation logic is single-sourced from the schema.

### Pitfall 4: `reports` enum drift

**What goes wrong:** The schema's `reports.items.enum` (lines 60-69) is missing `board_summary` and `unscanned_assets`, so any config that uses them will fail schema validation today. Phase 4 cannot land schema enforcement without first reconciling this list.

**How to avoid:** Phase 4's first task should align `delivery_config.schema.yaml` `reports` enum with `run_all.py:_VALID_REPORTS`. CLAUDE.md's "Adding a New Report — Required Steps" already lists three sites; the schema is implicitly a fourth that has been falling out of sync.

### Pitfall 5: ValidationError path for nested errors is tricky

**What goes wrong:** `ValidationError.absolute_path` is a `collections.deque` of mixed strings (key names) and ints (array indices). Naively printing it gives `deque(['groups', 0, 'schedule', 'frequency'])` — useless for users.

**How to avoid:** Walk the deque manually, formatting ints as `[N]` and strings with `.` separators (see code in "Loading" section above).

## Code Examples

### Schema validation entry point

```python
# run_all.py — replace _load_config body (illustrative)
from jsonschema import Draft7Validator

_SCHEMA_PATH = ROOT_DIR / "delivery_config.schema.yaml"

def _load_config(config_path: Optional[Path] = None) -> list[dict]:
    if config_path is None:
        config_path = ROOT_DIR / "delivery_config.yaml"
    if not config_path.exists():
        logger.error("delivery_config.yaml not found at %s", config_path)
        return []
    try:
        with open(config_path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        with open(_SCHEMA_PATH, encoding="utf-8") as fh:
            schema = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("YAML parse error: %s", exc)
        return []
    if not isinstance(raw, dict):
        logger.error("delivery_config.yaml: root must be a mapping")
        return []
    errors = _validate_config(raw, schema)
    if errors:
        for e in errors:
            logger.error("config validation: %s", e)
        return []
    groups = raw.get("groups") or []
    return groups
```

### Threading the toggle through `run_group`

```python
# run_all.py:run_group, inside the report loop near line 592
if slug == "board_summary":
    report_kwargs["analyst_detail"] = group_config.get("analyst_detail", True)
```

### `board_summary.run_report()` signature update

```python
def run_report(
    tio,
    run_id: str,
    *,
    tag_category: Optional[str] = None,
    tag_value:    Optional[str] = None,
    output_dir:   Optional[Path] = None,
    generated_at: Optional[datetime] = None,
    cache_dir:    Optional[Path] = None,
    analyst_detail: bool = True,    # NEW Phase 4 (CONFIG-03, D-25)
) -> dict:
    ...
    bundle = composer.run_full_pipeline(
        results,
        output_dir,
        slug             = "board_summary",
        report_date      = generated_at,
        generate_analyst = analyst_detail,   # was hardcoded True at line 247
        pdf_title        = _REPORT_TITLE,
        pdf_subtitle     = subtitle,
        scope_label      = scope_label,
    )
```

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | None declared in `requirements.txt` (Phase 2/3 used `tests/test_phase2_composer_pipeline.py` invoked directly) |
| Config file | None |
| Quick run command | `python tests/test_phase2_composer_pipeline.py` (existing structural regression — 11/11 per Phase 3 UAT) |
| Full suite command | `python -m unittest discover tests/` (would discover any `test_*.py` if needed) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| CONFIG-01 | Schema accepts `analyst_detail: true/false`; rejects non-boolean | unit | `python -c "import yaml,jsonschema;s=yaml.safe_load(open('delivery_config.schema.yaml'));jsonschema.Draft7Validator(s).validate({'groups':[{'name':'x','schedule':{'frequency':'on_demand'},'reports':['board_summary'],'analyst_detail':False,'email':{'subject':'s','recipients':['a@b.c']}}]})"` | manual smoke (no test file yet) |
| CONFIG-02 | Misconfigured group exits non-zero at startup | smoke | `python run_all.py --dry-run` against a YAML with `frequency: weeky` — expect exit code 1 | manual |
| CONFIG-03 | `analyst_detail: false` group has no analyst attachment | integration (manual) | Run group; inspect `output/.../` for absence of `board_summary_analyst.xlsx` | manual |
| CONFIG-04 | Sample group in `delivery_config.yaml` shows the toggle | static | `grep -n "analyst_detail" delivery_config.yaml` returns at least one match | manual |
| BOARD-08 | Existing `board_summary` recipient group produces non-regressing PDF/Excel | end-to-end | Run `--no-email` against current and pre-v1 commit, diff metric values + row counts | manual |

### Sampling Rate

- **Per task commit:** `python tests/test_phase2_composer_pipeline.py` (Phase 2/3 structural regression must stay green throughout)
- **Per wave merge:** Above + manual `python run_all.py --dry-run` smoke
- **Phase gate:** Full end-to-end cutover run for the single configured `board_summary` group, with both `analyst_detail: true` (default) and `false` paths exercised

### Wave 0 Gaps

- [ ] `tests/test_phase4_schema_validation.py` — covers CONFIG-01, CONFIG-02 (schema accept/reject cases, error message format with group name + field path)
- [ ] `tests/test_phase4_analyst_detail_toggle.py` — covers CONFIG-03 (run `board_summary` with `analyst_detail=False` against fixture data, assert `bundle["analyst_workbook_path"] is None` and the return dict's `analyst_excel is None`)

Framework install: none — both can run as `python tests/test_*.py` scripts following the Phase 2 pattern.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hand-rolled `_validate_group()` | `jsonschema.Draft7Validator` against `delivery_config.schema.yaml` | Phase 4 | Single source of truth; richer validation (email format, time pattern, additionalProperties, conditional required fields) |
| Hardcoded `generate_analyst=True` at `board_summary.py:247` | `generate_analyst=analyst_detail` from kwarg | Phase 4 | YAML-driven opt-out; no code changes for future groups to toggle |
| Schema file present but never read | Loaded and enforced at every config load | Phase 4 | Misconfiguration fails loud, not at run time |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Pre-v1 baseline = the metric values currently produced by the post-Phase-3 codebase, not a separate snapshot in git history | Regression Cutover Plan | If a pre-Phase-1 reference snapshot exists somewhere (e.g. an exported PDF in a private location), the cutover should diff against it instead. Confirm with user. |
| A2 | The single `"Test Pull"` group is the only currently-configured `board_summary` consumer (all other recipient groups envisioned in CLAUDE.md are templates, not deployed) | Regression Cutover Plan | If production already deploys multiple `board_summary` groups not committed to the repo, those need to be enumerated separately. |
| A3 | `Draft7Validator` is the right schema version (the schema declares `$schema: "http://json-schema.org/draft-07/schema#"`) | Integration pattern | Verified by reading the schema file (line 8) — confidence HIGH. |
| A4 | Reconciling the `reports` enum (adding `board_summary`, `unscanned_assets`) is in-scope as a prerequisite for schema enforcement | Schema Edits Required | If the user wants strict scope adherence (CONFIG-01..04 only), this becomes a deferred item — but enforcement cannot land without it. |

## Open Questions

1. **Should `_validate_group()` be removed or kept as a thin wrapper?**
   - What we know: It is only called from `_dry_run()` and provides a per-group error list for the rich table.
   - What's unclear: Whether the user wants the rich-table UX preserved (yes implies wrap) or simplified (no implies remove).
   - Recommendation: Wrap. Replace its body with a call into the per-group bucket of `_validate_config()` results, keep the function signature so `_dry_run()` is unaffected.

2. **Should `management_summary` also receive the `analyst_detail` toggle?**
   - What we know: `management_summary.py:run_report()` returns `analyst_excel: None` always (line 2317, 2465) — it does not produce an analyst workbook today.
   - What's unclear: Whether Phase 4 should pre-wire the kwarg there too for forward-compat, or wait until management_summary actually grows analyst tabs.
   - Recommendation: Wire it for consistency (both module-composed reports follow the same plumbing pattern). The kwarg is a no-op until management_summary's modules return analyst tabs.

3. **Is `reports` enum reconciliation a Phase 4 task or should it be split out?**
   - What we know: The schema is broken today w.r.t. `board_summary`/`unscanned_assets`. Schema enforcement requires fixing it.
   - Recommendation: Include in Phase 4 as a prerequisite micro-task in Wave 0 (alongside the `analyst_detail` schema addition).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `jsonschema` | CONFIG-02 runtime validation | ✓ (declared) | 4.23.0 | — |
| `PyYAML` | Schema file load | ✓ | 6.0.2 | — |
| Real Tenable.io creds | BOARD-08 cutover run | ✓ (per `.env`, used by Phase 3 UAT) | — | Mock fixtures in `tests/test_phase2_composer_pipeline.py` cover structural regression |

No missing dependencies.

## Project Constraints (from CLAUDE.md)

- **Adding/modifying a report slug** requires three-site update: `_VALID_REPORTS`, `_REPORT_MODULE_MAP`, schema's `reports.items.enum`. Phase 4's enum reconciliation honors this rule.
- **Backward compatibility:** Existing groups must continue to deliver. Adding `analyst_detail: true` as default preserves Phase 3 behavior exactly.
- **Fail-soft batch semantics:** A bad config must NOT silently skip groups — it must exit non-zero loud. This is encoded in the CONFIG-02 acceptance criterion.
- **Credential handling:** No new env vars in Phase 4. Validation runs against the YAML file only; no secrets touched.
- **Email-client compatibility:** No email template changes in Phase 4 — the modular email body is already locked from Phase 3.

## Recommended Plan Structure (input to gsd-planner)

Suggested **3 plans** for Phase 4:

### Plan 04-01 — Schema + Runtime Validation (CONFIG-01, CONFIG-02, prerequisite enum reconciliation)
- Wave 0: Add `tests/test_phase4_schema_validation.py` skeleton with passing-and-failing config fixtures
- Wave 1: Edit `delivery_config.schema.yaml`:
  - Add `analyst_detail: boolean (default: true)` under `group.properties`
  - Add `board_summary`, `unscanned_assets` to `reports.items.enum`
- Wave 2: Implement `_validate_config()` and rewire `_load_config()` in `run_all.py`; update `_validate_group()`/`_dry_run()` to consume the schema-derived errors
- Wave 3: CONFIG-02 smoke — verify a `frequency: weeky` config exits non-zero with the named-group-and-field error message

### Plan 04-02 — `analyst_detail` Opt-Out Plumbing (CONFIG-03, CONFIG-04)
- Wave 0: Add `tests/test_phase4_analyst_detail_toggle.py` skeleton
- Wave 1: Add `analyst_detail: bool = True` kwarg to `reports/board_summary.py:run_report()`; change line 247 from hardcoded `True` to the kwarg
- Wave 2: In `run_all.py:run_group()` report loop, add the slug-specific `report_kwargs["analyst_detail"] = group_config.get("analyst_detail", True)` block (mirror of `vuln_export`/`unscanned_assets` pattern at lines 592-597). Optionally extend to `management_summary` for forward-compat.
- Wave 3: Add the demonstration group to `delivery_config.yaml` with `analyst_detail: false` (CONFIG-04)
- Wave 4: Manual validation — run the demo group, confirm no `*_analyst.xlsx` produced or attached

### Plan 04-03 — Regression Cutover (BOARD-08)
- Wave 0: Document the cutover procedure in `.planning/phases/04-yaml-config-and-regression-cutover/CUTOVER.md`
- Wave 1: Run `python run_all.py --group "Test Pull" --no-email` on current `main`; capture output artifacts and metric values
- Wave 2: Compare metric values + Excel row counts to Phase 3 UAT reference numbers (`.planning/phases/03-board-summary-module-migration/03-UAT.md`); document any deviation
- Wave 3: Run again with `analyst_detail: false` on a temp YAML; confirm absence of analyst workbook
- Wave 4: Sign-off in `04-UAT.md`; mark CONFIG-01..04, BOARD-08 closed in `REQUIREMENTS.md`

**Dependencies:** Plan 04-01 must land before 04-02 (schema must accept `analyst_detail` before YAML can use it). Plan 04-03 depends on both. 04-01 and 04-02 can be developed in parallel branches but must merge in order.

## Sources

### Primary (HIGH confidence)
- `delivery_config.schema.yaml` (read in full)
- `delivery_config.yaml` (read in full)
- `run_all.py:1-170, 240-360, 420-640` (read directly)
- `scheduler.py:1-200` (read directly)
- `reports/board_summary.py:1-380` (read directly)
- `delivery/email_sender.py:130-170` (read directly)
- `requirements.txt:39` — `jsonschema==4.23.0` declared
- `.planning/REQUIREMENTS.md` — CONFIG-01..04, BOARD-08 acceptance criteria
- `.planning/ROADMAP.md:89-99` — Phase 4 goal verbatim
- `.planning/phases/02-reportcomposer-upgrades/02-CONTEXT.md` — D-22, D-24, D-25 already document the Phase 4 hooks

### Secondary (MEDIUM confidence)
- `.planning/phases/03-board-summary-module-migration/03-UAT.md` — Phase 3 UAT reference numbers (used as cutover baseline)

### Tertiary (LOW confidence)
- None — all claims trace to in-repo files

## Metadata

**Confidence breakdown:**
- Schema integration: HIGH — schema file is concrete; jsonschema usage pattern is the package's documented entry point
- Plumbing path: HIGH — every kwarg from composer to email_sender already exists; Phase 4 only flips one default and adds one `.get()`
- Regression scope: MEDIUM — assumes `"Test Pull"` is the only `board_summary` consumer (A2). User confirmation requested.
- Cutover baseline: MEDIUM — relies on Phase 3 UAT numbers as the reference (A1). If a pre-Phase-1 binary snapshot exists, it should be the reference instead.

**Research date:** 2026-05-07
**Valid until:** 2026-06-06 (30 days — surface is internal and stable)
