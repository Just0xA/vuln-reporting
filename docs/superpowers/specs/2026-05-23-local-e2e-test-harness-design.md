# Local E2E Test Harness — Design Spec

**Date:** 2026-05-23
**Status:** Approved (design); pending implementation plan
**Author:** Justin Monroe (with Claude)

## Purpose

Provide a **robust, repeatable, offline** end-to-end test suite that validates the
vulnerability-reporting pipeline locally — without the `vuln-dev` VM and without
hitting Tenable — and gates it on `git commit` so reports are proven functional
before any commit or push.

"Functioning" is validated at three depths:

1. **Artifacts** are produced and structurally valid (PDF opens, Excel has the
   expected tabs, email HTML is well-formed).
2. **Content/values** are correct — known synthetic inputs produce known KPI
   numbers (catches calculation regressions, not just "it ran").
3. **Delivery** works — the real MIME email (attachments, inline CID charts) is
   built and delivered through a local in-process SMTP catcher, asserted
   programmatically, and dumped to `.eml` for optional manual eyeballing.

## Decisions (locked during brainstorming)

| # | Decision | Choice |
|---|----------|--------|
| 1 | E2E boundary | All three layers (artifacts + content assertions + SMTP delivery) |
| 2 | Test data source | Hybrid — hand-built fixtures (exact values) + seeded generator (volume/edge/fail-soft) |
| 3 | Trigger/gate | Everything on `git commit` (pre-commit hook), with a documented escape hatch + xdist parallelism for speed |
| 4 | Test runner | Adopt `pytest` (migrate existing standalone scripts) |
| 5 | SMTP layer | In-process `aiosmtpd`: capture + programmatic assert + dump `.eml` to `output/` |
| 6 | Coverage | Config-driven (every real `delivery_config.yaml` group) **plus** a per-module unit layer (every registered module) |
| 7 | Fixture injection | **A** (seed parquet cache → real `run_group`) for config-driven E2E; **B** (monkey-patch / direct call) for per-module units |

## Key codebase facts the design relies on

- Fetchers are **cache-first**: `fetch_all_vulnerabilities(tio, cache_dir)` calls
  `_load_cache()` and returns immediately if `<cache_dir>/vulns_all.parquet`
  exists (`data/fetchers.py:276–278`). `tio` is never touched on a cache hit.
  → Seeding `cache_dir` with fixture parquets injects data through the **real**
  `run_group` path with no monkey-patching (injection A).
- Cache files are written/read with `engine="fastparquet"` (`data/fetchers.py:219, 230`).
  Fixtures MUST write with the same engine.
- `run_group()` is the single shared executor (`run_all.py:523`); all CLI modes
  converge there. It accepts `cache_dir` and creates it if `None`
  (`run_all.py:587–590`).
- Fetch datasets and their cache filenames: `vulns_all`, `vulns_fixed`,
  `assets_all`, `recast_rules` (`data/fetchers.py` + `scripts/warm_cache.py:52`).
- `fetch_fixed_vulnerabilities` is only called when `critical_remediation_sla`
  is composed — fixtures provide `vulns_fixed` only for those scenarios.
- Modules self-register on import via `registry.discover()` globbing `*_module.py`.
- Four-channel render contract + empty-data guard are defined in CLAUDE.md and
  `reports/modules/base.py`.

## Architecture — three test layers

```
Layer 1  Module unit tests    injection B   fast   every registered *_module.py
Layer 2  Content/value tests  hand fixtures fast   exact KPI numbers from known inputs
Layer 3  Config-driven E2E    injection A   slow   each delivery_config.yaml group, real run_group + SMTP
```

All three run under one `pytest` invocation. `pytest-xdist` (`-n auto`)
parallelizes across cores so Layer 3's WeasyPrint renders do not serialize.

## Layout

```
pytest.ini                       # testpaths, addopts = -n auto -q, markers (unit, content, e2e)
tests/
  conftest.py                    # shared fixtures (below)
  fixtures/
    builders.py                  # hand-built dfs — exact known contents
    generator.py                 # seeded generator — make_scenario(seed, n_assets, sev_mix, overdue_ratio) -> (dfs, expected)
    scenarios.py                 # named scenarios: THREE_OVERDUE_CRIT, ZERO_MATCH, OVERSIZED, NULL_VPR, NULL_FIRST_FOUND
  validators.py                  # assert_valid_pdf / assert_valid_xlsx / assert_well_formed_html / assert_email_cids_resolve
  smtp_catcher.py                # in-process aiosmtpd wrapper (capture + .eml dump)
  unit/    test_modules.py       # Layer 1 (parametrized over registry)
  content/ test_values.py        # Layer 2
  e2e/     test_groups.py        # Layer 3 (parametrized over real groups)
requirements-dev.txt             # pytest, pytest-xdist, aiosmtpd, pypdf  (test-only, never shipped to VM)
.githooks/pre-commit             # runs pytest; installed via: git config core.hooksPath .githooks
```

## Shared fixtures (`conftest.py`)

- `synthetic_vulns_df`, `synthetic_assets_df`, `synthetic_fixed_df` — from builders/generator.
- `seeded_cache(tmp_path)` — writes fixture parquets (`vulns_all`, `assets_all`,
  `vulns_fixed`, `recast_rules`) into a temp `cache_dir` using
  `engine="fastparquet"`; returns the path. **This is injection A.**
- `dummy_tio` — stub passed where `run_group` expects a client; never called on a
  cache hit (asserted — proves the short-circuit).
- `smtp_catcher` — starts in-process `aiosmtpd` on a random localhost port, yields
  a handle exposing `.messages`, tears down on exit. SMTP env vars
  (`SMTP_HOST`/`SMTP_PORT`) monkey-patched to point at it.
- `temp_output_dir(tmp_path)` — isolated `output/` per test.

## Fixtures — hybrid

- **Hand-built (`builders.py`)** — DataFrames with deliberately exact contents.
  Example: `THREE_OVERDUE_CRIT` = 5 vulns, exactly 3 critical past SLA, 2 within
  SLA. Drives Layer 2 exact-value assertions.
- **Seeded generator (`generator.py`)** — `make_scenario(seed=42, n_assets=200,
  sev_mix=..., overdue_ratio=0.3)` returns `(dfs, expected)` where `expected` is
  derived from the same params so assertions stay in sync. Drives volume, edge
  cases, fail-soft.
- **Named scenarios (`scenarios.py`)**, including failure modes:
  - `ZERO_MATCH` — filtered-to-zero recipient group (empty-data guard).
  - `OVERSIZED` — attachments exceed `MAX_ATTACHMENT_SIZE_MB`.
  - `NULL_VPR` — VPR null → native CVSS severity fallback.
  - `NULL_FIRST_FOUND` — null first-found date handling.

## Test-case catalogue — what each layer asserts

### Layer 1 — per module (parametrized over `registry.discover()`)

- `compute()` on a populated df returns a `ModuleData` without raising.
- **Empty-data guard:** `compute()` on a zero-row df returns a coherent
  `_empty_result` (gray "No Data" strip, `"No data in scope."` driver) — never
  raises, never an inline-f-string crash on `None`.
- Four-channel contract:
  - `render_pdf_section` → `str`
  - `render_excel_tabs` → `list`
  - `render_email_panel` → `str`
  - `render_analyst_tabs` → `list[tuple]`
  - `render_rag_strip_entry` → `dict` with required keys (`label`,
    `headline_value`, `rag_color`, `rag_label`).

### Layer 2 — content/value (hand fixtures, exact)

- `THREE_OVERDUE_CRIT` → overdue-critical metric `== 3`; in-SLA% matches hand math.
- `utils/sla_calculator.get_sla_status` correctness across the VPR severity bands
  and the overdue boundary (`days_open == SLA_days` within SLA vs
  `> SLA_days` overdue).
- `NULL_VPR` → severity derived from native CVSS fallback per CLAUDE.md.
- MTTR computed correctly from known `fixed` dates.

### Layer 3 — config-driven E2E (real `run_group` per group)

- `run_group(cfg, cache_dir=seeded_cache, tio=dummy_tio)` returns success;
  `dummy_tio` is never called (proves cache short-circuit).
- PDF exists and opens (`pypdf`, ≥1 page); Excel exists and `openpyxl` loads the
  expected tabs; `email_body_html` is non-empty and well-formed.
- `analyst_excel` is a Path when the group's `analyst_detail` ≠ false, and `None`
  when false; no analyst `.xlsx` is written in the off case.
- **SMTP (via catcher):**
  - exactly one message per group;
  - recipients / cc / subject match the group config;
  - PDF + Excel (+ analyst when applicable) attached;
  - every `<img src="cid:X">` resolves to a `MIMEImage` `Content-ID`;
  - total size respected; `OVERSIZED` → PDF-only fallback + body note;
  - empty recipient list → skipped, not sent;
  - raw `.eml` dumped to `output/test-eml/<group>.eml`.
- `ZERO_MATCH` group → batch completes fail-soft (no exception kills the run).

## SMTP catcher (`smtp_catcher.py`)

Thin wrapper over `aiosmtpd.controller.Controller` with a custom handler that
appends each received message to an in-memory list and writes the raw `.eml` to
the dump dir. Pure Python, pip-installed, no Docker, Windows-friendly. Binds a
random localhost port to avoid collisions under xdist.

## Pre-commit gate + escape hatch

- `.githooks/pre-commit` runs `python -m pytest -n auto -q`. Installed once with
  `git config core.hooksPath .githooks` (works on Windows via Git's bundled bash).
  Documented in RUNBOOK.md.
- **Escape hatch:** if env `VULN_E2E_SKIP=1`, the hook prints a loud warning and
  exits 0 — so genuine emergencies do not force `git commit --no-verify` (which
  would skip *all* hooks). The normal path runs the full suite.
- Wall-clock is measured after build. If Layer 3 makes commits painful, the
  fallback is to mark Layer 3 `@pytest.mark.e2e` and move only that mark to a
  pre-push hook. Per decision #3 we start with everything on pre-commit.

## Existing tests

Per decision #4 ("adopt pytest"), the ~10 standalone `tests/test_*.py` scripts are
migrated to pytest discovery (their `main()`/`_check` bodies become `test_`
functions with `assert`s). This migration is a **separate, clearly-bounded slice**
in the implementation plan: the new harness lands first and works standalone;
migration of legacy scripts follows so the two efforts do not entangle.

## New dependencies (test-only — `requirements-dev.txt`)

`pytest`, `pytest-xdist`, `aiosmtpd`, `pypdf`. `openpyxl` is already shipped. None
are added to production `requirements.txt`; the VM never installs these.

## Risks / open notes

- **WeasyPrint speed** dominates Layer 3 — mitigated by xdist; measured post-build.
- **fastparquet engine** — fixtures must write with `engine="fastparquet"` to
  match `_load_cache` (`data/fetchers.py:230`). Builders pin that.
- **Schema drift** — if a fetcher's columns change, fixtures must change too. The
  per-module empty-df fixtures encode the column contract, so drift breaks loudly
  rather than silently.

## Out of scope

- Hitting the real Tenable API or the `vuln-dev` VM (this suite is fully offline).
- Visual/pixel regression of rendered PDFs (structural validity only).
- Production `requirements.txt` changes.
- GitHub Actions / remote CI (local pre-commit only, per the request).
