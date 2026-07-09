# Phase 20: Config Language + Loader + Matrix - Pattern Map

**Mapped:** 2026-07-09
**Files analyzed:** 8 (4 new, 4 modified/preserved)
**Analogs found:** 8 / 8

This phase adds a new config **source language** (shared `contacts.yaml` + per-team
`deliveries.d/*.yaml`) plus a **resolve-before-validate** loader, a standalone
**delivery-matrix** generator, and an **effective-config golden test**. No RESEARCH.md
(research disabled) — all patterns are drawn directly from the live codebase.

The governing design invariant (CONTEXT D-01/D-09, REQUIREMENTS "resolve-before-validate"):
source keys resolve into **today's group shape**, then the *existing*
`delivery_config.schema.yaml` validates the resolved effective config **unchanged**. Every
analog below serves that invariant.

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| resolver/loader (new module `delivery/config_loader.py` **or** extend `run_all.py._load_config`) | config-loader | transform (source→effective) | `run_all.py._load_config` + `_validate_with_schema`/`_load_schema`/`_format_error_path` | exact (role + flow) |
| `scripts/generate_delivery_matrix.py` | script (CLI) | transform / file-I/O | `scripts/warm_cache.py`, `scripts/capture_trend_snapshot.py` | exact (standalone argparse script) |
| `contacts.example.yaml` (fixture + committed reference) | config-fixture | — (static) | `delivery_config.example.yaml` | role-match (new source shape) |
| `deliveries.d/` twin fixture + golden JSON | test-fixture / golden | file-I/O | `tests/baselines/*.json` + `tests/fixtures/management_summary_parity/` | role-match |
| effective-config golden test | test | file-I/O / transform-compare | `tests/test_management_summary.py::test_value_golden_parity`, `tests/test_phase4_schema_validation.py` | exact (golden-parity gate) |
| `delivery_config.schema.yaml` (preserve) | config-schema | validation | itself — role unchanged | preserve |
| `delivery_config.example.yaml` (preserve as living reference) | config-fixture | — | itself | preserve |
| `run_all.py` (extend `_load_config` + `--dry-run` surfacing) | config-loader | transform | `run_all.py._dry_run`, `_load_config` | exact (self) |

---

## Pattern Assignments

### Resolver / Loader — new `delivery/config_loader.py` OR extension of `run_all.py._load_config` (config-loader, transform)

**Analog:** `run_all.py._load_config()` (`run_all.py:156-200`) plus the jsonschema
plumbing at `run_all.py:302-321`.

The loader is the heart of the phase. Directory-mode discovery (D-01), permissive Python
pre-checks (D-09), then hand off the **resolved effective config** to the *existing*
schema gate. Whether it lives in a new module or extends `_load_config`, it must preserve
the current return contract: **`list[dict]` of groups**, empty list on failure, everything
logged (never raised) so `run_group()` consumes each resolved group dict unchanged.

**Return contract + fail-soft-empty pattern to preserve** (`run_all.py:156-200`):
```python
def _load_config(config_path: Optional[Path] = None) -> list[dict]:
    if config_path is None:
        config_path = ROOT_DIR / "delivery_config.yaml"
    if not config_path.exists():
        logger.error("delivery_config.yaml not found at %s", config_path)
        return []
    try:
        with open(config_path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("delivery_config.yaml parse error: %s", exc)
        return []
    if not isinstance(raw, dict):
        logger.error("delivery_config.yaml: root must be a mapping")
        return []
    # single-source-of-truth schema validation — fail loud at startup
    try:
        schema = _load_schema()
    except (FileNotFoundError, yaml.YAMLError) as exc:
        logger.error("delivery_config.schema.yaml load failed: %s", exc)
        return []
    errors = _validate_with_schema(raw, schema)
    if errors:
        for err in errors:
            logger.error("config validation: %s", err)
        return []
    groups = raw.get("groups")
    if not isinstance(groups, list):
        logger.error("delivery_config.yaml: 'groups' key must be a list")
        return []
    logger.debug("Loaded %d group(s) from delivery_config.yaml", len(groups))
    return groups
```

**Where the new logic slots in (resolve-before-validate):** the directory-mode branch and
`_validate_with_schema(raw, schema)` call bracket the new resolver. Read `deliveries.d/` +
`contacts.yaml` → resolve `contact:`/`defaults`/`extra_recipients` into the concrete
`email:` block → assemble `{"groups": [...]}` → then run the **unchanged**
`_validate_with_schema` on that resolved dict.

**Directory-mode switch (D-01) — sibling-presence probe** — mirror the `config_path`
resolution at `run_all.py:163-168` and `scheduler.py:271`. Config path is
`ROOT_DIR / "delivery_config.yaml"` (`run_all.py:164`), symlinked from `shared/` in prod.
Resolve `deliveries.d/` and `contacts.yaml` relative to `config_path.parent` so the
`shared/` symlink layout (Claude's-Discretion item) is honored:
```python
config_dir = config_path.parent
deliveries_dir = config_dir / "deliveries.d"
if deliveries_dir.is_dir():
    # directory mode: glob team files + require contacts.yaml sibling
    contacts_path = config_dir / "contacts.yaml"
    if not contacts_path.exists():
        logger.error("directory mode: contacts.yaml missing next to deliveries.d/")
        return []
    ...
else:
    # legacy / migrated single-file fallback (existing path above)
```

**jsonschema plumbing to REUSE verbatim for the resolved-config gate** (`run_all.py:302-321`):
```python
_SCHEMA_PATH: Path = ROOT_DIR / "delivery_config.schema.yaml"   # run_all.py:149

def _load_schema() -> dict:
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)

def _validate_with_schema(raw: dict, schema: dict) -> list[str]:
    validator = Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)
    return [
        _format_error_path(err, raw)
        for err in sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path))
    ]
```
Do NOT add a second schema (D-09). The permissive Python pre-checks are targeted
programmatic checks (required keys, every `contact:` ref resolves, globally-unique delivery
names, no inline `email:` in directory mode), then hand off to this existing gate.

**Error-path formatting to reuse for consistent messages** (`run_all.py:273-299`) —
`_format_error_path(err, raw)` renders `[group_name] groups[N].<path>: <message>`. New
loader errors (D-10) should follow the same human-readable `logger.error` shape so
`--dry-run` output stays uniform.

**Hot-reload compatibility (D-01 must survive reload):** `scheduler.py` re-invokes
`_load_config()` on mtime change (`scheduler.py:269-285`). The reload closure watches a
single path's mtime:
```python
def _reload_check() -> None:
    global _config_mtime
    config_path = ROOT_DIR / "delivery_config.yaml"
    current_mtime = config_path.stat().st_mtime
    if current_mtime == _config_mtime:
        return
    logger.info("delivery_config.yaml changed — reloading and rescheduling...")
    _config_mtime = current_mtime
    groups = _load_config()
    _schedule_groups(scheduler, groups)
```
**Gap the planner must close:** directory mode has N+1 files (`deliveries.d/*.yaml` +
`contacts.yaml`), but the reload probe watches ONE mtime. The loader/reschedule path must
either be reachable through `_load_config()` unchanged (so no scheduler edit is needed) or
the mtime probe must cover the directory. Keep the reschedule entry point as
`_load_config()` returning `list[dict]` to avoid touching `scheduler.py`.

---

### `scripts/generate_delivery_matrix.py` (script, transform / file-I/O)

**Analog:** `scripts/warm_cache.py` (full file) and `scripts/capture_trend_snapshot.py`
(header + argparse). Use `warm_cache.py` as the structural template.

**Module-docstring + Flags + Exit-codes header convention** (`scripts/warm_cache.py:1-21`):
```python
#!/usr/bin/env python
"""Warm the Tenable parquet cache for the day ...

Flags
-----
--date YYYY-MM-DD   ...
--dry-run           Log what would happen; write no files.

Exit codes
----------
0   success or dry-run
2   ... argparse usage error
3   ... failure
"""
```
For the matrix script the flags are `--format {markdown,html}` (default markdown, D-06),
`--output <path>` (D-04). Keep the same `Flags` / `Exit codes` docstring blocks.

**Repo-root sys.path bootstrap** (`scripts/warm_cache.py:23-43`) — every `scripts/` entry
point does this before importing project modules:
```python
from __future__ import annotations
import argparse, logging, sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from config import ...          # noqa: E402
```
The matrix script imports the **loader** here (the resolved-config source, D-04) — e.g.
`from run_all import _load_config` or the new `delivery.config_loader`.

**argparse-error-logs-to-file subclass** (`scripts/warm_cache.py:121-130`) — reproduce for
LOG-01 parity:
```python
class _WarmCacheArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        started = datetime.now(tz=timezone.utc).isoformat()
        _log_to_file_only(
            f"Started at {started} UTC; argv={sys.argv}; "
            f"failed because argparse usage error: {message}"
        )
        super().error(message)
```

**`_build_parser` / `main(argv=None)` / `if __name__ == "__main__": sys.exit(main())`
skeleton** (`scripts/warm_cache.py:143-275`):
```python
def _build_parser() -> _WarmCacheArgumentParser:
    parser = _WarmCacheArgumentParser(
        prog="python -m scripts.generate_delivery_matrix",
        description="Render the delivery matrix from the resolved config.",
    )
    parser.add_argument("--format", choices=("markdown", "html"), default="markdown", ...)
    parser.add_argument("--output", type=Path, default=None, ...)
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
        return code if code != 0 else 0
    logger = _configure_logging(args.verbose)
    ...
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

**Rotating-file-handler logging setup** (`scripts/warm_cache.py:64-99`) — copy
`_configure_logging` / `_ensure_log_dir`; use `logs/generate_delivery_matrix.log` +
`_LOGGER_NAME = "generate_delivery_matrix"`.

**PII constraint (D-05 / Hard Rule 2):** matrix columns show contact/group **NAMES + owner**,
never expanded recipient addresses. The script consumes the resolved config but must render
at the `contact:`-key granularity (pre-expansion), so it is safe to publish as a CI artifact.
Do NOT emit `email.recipients` values into the matrix.

---

### `contacts.example.yaml` — new committed reference + golden source (config-fixture, static)

**Analog:** `delivery_config.example.yaml` (full file).

**Conventions to mirror** (`delivery_config.example.yaml:1-13`): a header comment block
explaining copy-to-`shared/` usage, and the **RFC 6761 reserved `example.invalid` domain on
every address** so the template never delivers mail and never leaks PII (Hard Rule 2 /
D-04-08 / D-08):
```yaml
# All recipients below use the RFC 6761 reserved example.invalid domain so this
# template never delivers mail. Replace every placeholder before going live.
```
`contacts.example.yaml` holds `contacts:` (named groups mapping to `example.invalid`
addresses) + a top-level `defaults:` block (`defaults.analyst_mailbox`, D-02, one universal
knob driving both default `Reply-To` and standing `Cc`). It holds contacts + defaults
**only** — no deliveries.

**Source `email:` shape the resolution must reproduce** (`delivery_config.example.yaml:27-34,
72-76`) — the resolved effective config's `email:` block must match exactly what the schema
and `email_sender.py` already expect:
```yaml
    email:
      subject: "Weekly Vuln Management Summary — Production"
      recipients:
        - ciso@example.invalid
        - vp-it@example.invalid
      cc:
        - security-team@example.invalid
      reply_to: security@example.invalid
```
The `deliveries.d/` twin (D-08) must exercise every current key the example uses:
`composed_report` + `modules:` (`delivery_config.example.yaml:63-68`), `cc`, `reply_to`,
`on_demand`, and empty `filters: {}` (line 42).

---

### `deliveries.d/` twin fixture + committed golden JSON (test-fixture / golden, file-I/O)

**Analog:** `tests/baselines/*.json` (committed JSON goldens) + directory-fixture layout
`tests/fixtures/management_summary_parity/` (a named subdir holding a fixture set).

**Fixture-directory layout convention** (`tests/fixtures/management_summary_parity/`): a
named subdirectory under `tests/fixtures/` holds a coherent fixture bundle
(`vulns_df.parquet`, `trend_snapshots.json`, etc.). Put the migrated-twin
(`contacts.example`-style file + `deliveries.d/` team files) under a comparable
`tests/fixtures/<phase20-twin>/` directory, and the golden under `tests/baselines/`
alongside the other committed JSON goldens.

**Golden-path constant convention** (`tests/test_management_summary.py:59`,
`tests/test_board_summary_baseline.py:68-71`):
```python
_BASELINES_DIR = Path(__file__).parent / "baselines"
_GOLDEN_PATH   = _BASELINES_DIR / "management_summary_value_golden.json"
```

**PII (D-08 / Hard Rule 2):** twin + golden use synthetic `example.invalid` identifiers only
— never production config.

---

### Effective-config golden test (test, transform-compare)

**Analog:** `tests/test_management_summary.py::test_value_golden_parity`
(`test_management_summary.py:398-449`) for the resolve→compare-to-committed-golden pattern,
and `tests/test_phase4_schema_validation.py` for the plain `_load_schema` /
`_validate_with_schema` harness style.

**Two-way equality assertion (D-07):** resolve → normalize (sorted keys) → serialize to a
committed golden JSON, then assert (a) legacy single-file fixture resolves **byte-identical**
to the golden and (b) the migrated twin resolves to the **same** golden. The golden-parity
harness pattern (`test_management_summary.py:426-449`):
```python
def test_value_golden_parity(tmp_path: Path) -> None:
    vulns_df, assets_df, fixed_vulns_df, trend_snapshots = _load_fixtures()
    golden = _load_golden()
    out = _run_modular_pipeline(...)
    results = out["results"]
    failures: list[str] = []
    for metric_key, gentry in golden["metrics"].items():
        ...   # compare actual vs golden, collect failures
```
For Phase 20, "actual" = `_load_config()` (or the resolver) run against each fixture,
normalized with `json.dumps(..., sort_keys=True, indent=...)` (JSON normalization details are
Claude's Discretion, D-07) and compared to the committed golden string.

**JSON golden load convention** (`test_management_summary.py:111,118`):
```python
with open(path, encoding="utf-8") as fh:
    return json.load(fh)
```

**Schema-harness style for the resolved-config gate check**
(`tests/test_phase4_schema_validation.py:21,50-58`):
```python
from run_all import _load_schema, _validate_with_schema
...
schema = _load_schema()
errs = _validate_with_schema(raw, schema)
_check("A_current_yaml_clean", errs == [], hint=str(errs))
```
Use this to prove the **resolved** twin still passes the unchanged schema (the phase's
correctness bar: schema role unchanged).

**Test runner convention:** repo tests use a `_check`/`FAILED` self-contained
`main() -> int` + `sys.exit(main())` harness (`test_phase4_schema_validation.py:26-119`) OR
pytest `test_*` functions (`test_management_summary.py`). Match whichever the neighboring
config tests use — `test_phase4_schema_validation.py` (the closest analog by subject) uses
the `main()/_check` style.

---

### `delivery_config.schema.yaml` (config-schema — PRESERVE)

**Role unchanged (single gate on the resolved effective config).** Do NOT relax it to
accept source keys (`contacts`, `defaults`, `contact:`, `owner:`). Those are resolved away
*before* validation. `additionalProperties: false` at both root
(`delivery_config.schema.yaml:14`) and `group` (line 36) means any un-resolved source key
would be correctly rejected — that is the desired safety net, not a bug to work around.

The resolved effective config must satisfy the existing `group` required set
(`delivery_config.schema.yaml:31-35`): `name`, `schedule`, `reports`, `email`; and the
`email` required set (lines 233-236): `subject`, `recipients`. The resolver's job is to
produce exactly that shape.

---

### `run_all.py` — `--dry-run` surfacing (config-loader, transform — EXTEND)

**Analog:** `run_all.py._dry_run` (`run_all.py:394-489`).

**D-10 surfacing pattern:** deprecated `groups:` alias → `logger.warning` (keeps loading,
CONF-03); duplicate delivery name / undefined `contact:` ref / inline-`email:`-in-directory-
mode → `logger.error` + non-zero exit. All echoed prominently in `--dry-run`. The existing
whole-config schema-error surfacing block is the exact pattern to extend
(`run_all.py:413-430`):
```python
config_path = ROOT_DIR / "delivery_config.yaml"
if config_path.exists():
    try:
        with open(config_path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if isinstance(raw, dict):
            schema_errors = _validate_with_schema(raw, schema)
            if schema_errors:
                any_errors = True
                console.print("\n[bold red]Schema validation errors:[/bold red]")
                for err in schema_errors:
                    console.print(f"  [red]x {err}[/red]")
    except yaml.YAMLError as exc:
        any_errors = True
        console.print(f"\n[bold red]YAML parse error:[/bold red] {exc}")
```
New loader-level errors (undefined `contact:` ref, dup delivery name, inline email in dir
mode) should be printed in a comparable `console.print("[bold red]...[/bold red]")` block and
flip `any_errors = True` so `_dry_run` returns exit code 1 (`run_all.py:484-486`). This is
the Phase 21 CI gate's signal.

**Exit-code contract to preserve** (`run_all.py:394-399,484-489`): `0` all valid, `1` any
error. Phase 21's pre-auth `--dry-run` CI gate depends on this.

---

## Shared Patterns

### Resolve-before-validate (the phase's spine)
**Source:** `run_all.py._load_config` (`:181-192`) — schema validation slot.
**Apply to:** loader + golden test + schema preservation.
Source keys resolve into today's group shape; then the *unchanged* `_validate_with_schema`
gates the effective config. Backward compat falls out for free.

### Fail-loud-at-startup, never-raise
**Source:** `run_all.py._load_config` (`:166-197`), `_dry_run` (`:394-489`).
**Apply to:** loader, `--dry-run` extension, matrix script.
Every failure is `logger.error(...)` + `return []` (loader) or `+ non-zero exit` (dry-run);
callers handle the empty/error case gracefully. Never raise out of the load path.

### Standalone-script skeleton
**Source:** `scripts/warm_cache.py` (`:23-43` bootstrap, `:143-275` parser/main/entrypoint).
**Apply to:** `scripts/generate_delivery_matrix.py`.
Repo-root `sys.path.insert`, `Flags`/`Exit codes` docstring, argparse-error-to-logfile
subclass, `main(argv=None) -> int`, `sys.exit(main())`.

### Aggregate-only PII (Hard Rule 2 / D-04-08)
**Source:** `delivery_config.example.yaml:9-11` (`example.invalid` domain).
**Apply to:** matrix output (D-05, names+owner not addresses), all fixtures + golden (D-08).
Synthetic `example.invalid` identifiers only in anything committed.

### jsonschema gate reuse
**Source:** `run_all.py:302-321` (`_load_schema`, `_validate_with_schema`, `_format_error_path`).
**Apply to:** loader resolved-config gate + golden test.
Single Draft7 validator with `FORMAT_CHECKER`; one schema, no second.

---

## No Analog Found

None. Every new file maps to a strong existing analog. The genuinely new *behavior* — glob +
merge of `deliveries.d/`, contact-ref resolution, `defaults` expansion, cross-file uniqueness
— has no drop-in analog (it is the phase's novel logic), but its **structure, return
contract, error surfacing, and PII handling** all reuse the patterns above. The
Claude's-Discretion items (module boundary, JSON normalization details, matrix column layout,
`shared/` symlink search path) are deliberately unconstrained by CONTEXT.

---

## Conventions

Automated convention derivation was **skipped** (`gsd-tools verify conventions --derive`
returned `{"skipped": true, "reason": "no-readable-files"}` for both `--scope scripts` and
repo-wide — the deterministic module targets JS/TS ecosystems, not this Python repo).
The following axes are derived by manual majority-vote over the read analogs and CLAUDE.md
"Code Quality Requirements" / `.planning/codebase/CONVENTIONS.md`:

| Axis | Dominant | Share | Entropy | Status |
|------|----------|-------|---------|--------|
| File-name casing | `snake_case.py` (`run_all.py`, `warm_cache.py`, `capture_trend_snapshot.py`, `config_loader.py`) | high (~100%) | low | named contract |
| Identifier casing | `snake_case` funcs/vars, `_leading_underscore` for module-private, `UPPER_SNAKE` module constants (`_VALID_REPORTS`, `_SCHEMA_PATH`, `CACHE_DIR`) | high (~95%) | low | named contract |
| Export style | Python module-level `def`/constants; module-private via `_` prefix; no `__all__` — import by name (`from run_all import _load_config`) | high | low | named contract |
| Import style | stdlib → third-party → first-party grouped; `from __future__ import annotations` first line of every module; scripts do `sys.path.insert(0, str(_REPO_ROOT))` then `# noqa: E402` first-party imports | high | low | named contract |

At `share >= 70%` these are **named contracts** — match them exactly. New Phase 20 files
(`config_loader.py`, `generate_delivery_matrix.py`, the golden test) MUST follow all four.

**Contested hotspots (author's choice):** none observed in the read scope. This Python repo
has no CJS↔ESM dual-resolver split; the module system is uniformly CPython import. Where a
directory-local style exists (e.g. `scripts/` entry points all carry the
`Flags`/`Exit codes` docstring + argparse-error-to-logfile subclass), match the directory's
local style — for Phase 20 that means `scripts/generate_delivery_matrix.py` copies the
`scripts/warm_cache.py` shape, not `run_all.py`'s rich-table shape.

---

## Metadata

**Analog search scope:** `run_all.py`, `scheduler.py`, `scripts/`, `delivery_config.schema.yaml`,
`delivery_config.example.yaml`, `config.py`, `tests/` (config/golden tests + fixture layout).
**Files scanned:** ~14 read/greped.
**Pattern extraction date:** 2026-07-09
