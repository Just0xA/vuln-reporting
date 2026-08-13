---
phase: quick-260813-ga2
plan: 01
subsystem: reports/board_summary + reports/modules
tags: [board-summary, risk-managed, variant-report, module-option]
dependency-graph:
  requires: []
  provides: [BOARD-VARIANT-01]
  affects: [run_all.py, delivery_config.schema.yaml, delivery/email_template.py, reports/board_summary.py]
tech-stack:
  added: []
  patterns:
    - "Per-call ModuleConfig factory instead of a shared mutable module-level list (prevents daemon-process option leakage across successive runs)"
    - "Frozen dataclass variant record (_BoardVariant) selecting slug/title/filenames/behavior by a single boolean"
    - "Two-slugs-one-module mapping in _REPORT_MODULE_MAP"
key-files:
  created:
    - tests/test_board_summary_variants.py
  modified:
    - reports/modules/critical_remediation_sla_module.py
    - reports/modules/high_risk_assets_module.py
    - reports/modules/aged_vulns_assets_module.py
    - reports/board_summary.py
    - run_all.py
    - delivery_config.schema.yaml
    - delivery/email_template.py
    - tests/test_kpi_risk_managed_exclusion.py
    - tests/test_phase6_run_group_chrome.py
    - tests/test_phase6_board_summary_chrome.py
    - tests/test_board_accepted_recast.py
    - docs/board_summary_calculations.md
    - docs/GLOSSARY.md
    - CLAUDE.md
    - RUNBOOK.md
decisions:
  - "Owner supplemental skipped entirely for the inclusive variant (not written twice) — it reads the unfiltered frames so both variants would produce identical output, and it is never emailed"
  - "Inclusive variant returns empty email_body_html/email_inline_images by construction; excluded variant's body carries a one-line cross-reference pointer to the inclusive PDF"
  - "_board_module_configs() is a per-call factory, not a module-level list, to prevent ModuleConfig.options leaking across successive board_summary runs in a long-lived scheduler daemon process"
metrics:
  duration_seconds: 2700
  completed: "2026-08-13"
  tasks: 3
  files: 16
---

# Phase quick-260813-ga2 Plan 01: Split board_summary into risk-managed-excluded and risk-managed-included variants Summary

Added an `include_risk_managed` module option (default `False`, today's behavior unchanged) to the three board KPI modules that call `exclude_risk_managed()`, then variant-parameterized `reports/board_summary.py` so the same module drives two report slugs — `board_summary` (excluding, unchanged numbers) and the new `board_summary_incl_risk_managed` (including ACCEPTED/RECASTED findings in Metrics 2-4) — both listed in every board delivery group so one email carries both PDFs.

## What Was Built

**Task 1 — module option:** `critical_remediation_sla_module.py`, `high_risk_assets_module.py`, and `aged_vulns_assets_module.py` each read `config.options.get("include_risk_managed", False)` once at the top of `compute()`'s try block and skip `exclude_risk_managed()` when truthy (Critical Remediation SLA guards *both* the open and fixed populations behind the single flag so they never diverge). `add_vpr_severity()` stays unconditional, immediately after the guard (Hard Rule 4). The PDF explanatory paragraph and Excel `Scope:` row in `critical_remediation_sla_module.py` now select between "excluding" / "including risk-accepted and recast findings" via a precomputed local variable (no inline conditional in the f-string, per Hard Rule 6). `get_audit_info()` — which has no `config` parameter and is invoked on a bare `cls()` by the registry — documents the conditional statically rather than asserting one branch. All three modules gained a `risk_managed_scope` metadata key (two literal strings, identical across modules) so the Excel `_Metadata` tab discloses which population produced the numbers; `_build_metadata()` in `high_risk_assets_module.py` and `aged_vulns_assets_module.py` gained a second `include_risk_managed: bool` parameter, threaded through both call sites in each file including the no-data early returns.

**Task 2 — variant-parameterize board_summary.py + register the slug:** Replaced the module-level `_BOARD_MODULE_CONFIGS` list and `_PDF_FILENAME`/`_EXCEL_FILENAME` constants with a frozen `_BoardVariant` dataclass record (slug, title_suffix, pdf_filename, excel_filename, include_risk_managed, write_supplemental, email_panels) and two instances (`_VARIANT_EXCLUDED`, `_VARIANT_INCLUDED`), selected via `_resolve_variant(include_risk_managed)`. `_board_module_configs(include_risk_managed)` is now a factory building fresh `ModuleConfig` objects on every call — load-bearing, not stylistic, since the old shared mutable list would have leaked the inclusive variant's options into every subsequent `board_summary` run inside a long-lived `scheduler.py --mode daemon` process. `run_report()` gained a keyword-only `include_risk_managed: bool = False` parameter; the owner/application supplemental writer now runs only when `variant.write_supplemental` (skipped for the inclusive variant); PDF/Excel filenames and the `run_full_pipeline(slug=...)` kwarg follow the variant; `email_body_html`/`email_inline_images` are emptied for the inclusive variant, and the excluded variant's body gets an appended one-line inline-CSS pointer to the attached inclusive PDF. Added `--include-risk-managed` to the CLI argparse block. `run_all.py` registers the new slug in `_VALID_REPORTS`, `_REPORT_MODULE_MAP` (mapped to the same `reports.board_summary` module, with an explanatory comment), and `_CHROME_AWARE_SLUGS`; a new `_BOARD_SUMMARY_SLUGS` frozenset widens the `run_group()` kwarg-injection block from `if slug == "board_summary":` to `if slug in _BOARD_SUMMARY_SLUGS:`, keying `include_risk_managed` off which slug is dispatched while keeping `analyst_detail` honored for both. `delivery_config.schema.yaml` gained the slug in the `reports` enum and a corrected `report_title` description; `delivery/email_template.py` gained `_REPORT_DESCRIPTIONS` entries for both board slugs (neither existed before). The three tests coupled to the old shape were co-edited in this same commit: `test_phase6_run_group_chrome.py` (4-element `_CHROME_AWARE_SLUGS`), `test_phase6_board_summary_chrome.py` (title assertions now include the variant suffix), `test_board_accepted_recast.py` (switched from reading `bs._BOARD_MODULE_CONFIGS` to calling `bs._board_module_configs()`).

**Task 3 — variant test suite + docs:** New `tests/test_board_summary_variants.py` (26 tests) covers slug registration in all four places plus schema-enum/`_VALID_REPORTS` set-equality enforcement, title-suffix composition (including with an explicit `report_title` override), per-variant module options reaching the composer, distinct filenames, the `run_full_pipeline(slug=...)` kwarg, the owner-supplemental skip, empty email panels for the inclusive variant, and the no-state-leak property (mutate one call's configs, verify the next call's fresh configs are unaffected; run inclusive-then-excluded in one process and verify no cross-contamination). `docs/board_summary_calculations.md` gained a new "Two Report Variants" section (TOC and all following section numbers renumbered from 3-11 to 4-12) with the measured-impact table and the three misreading caveats from the approved plan, plus `include_risk_managed` notes on the Metrics 2/3/4 Edge cases sections, the Metric 5 tie-out gap note, and the per-owner BU re-rank note. `docs/GLOSSARY.md` gained a "Risk-managed finding" entry. `CLAUDE.md`'s slug index table and `RUNBOOK.md`'s valid-slug list both list the new slug.

## Deviations from Plan

None — plan executed exactly as written, including both corrections folded into the approved spec (no composer `cid_namespace` work; new slug maps to the existing `reports/board_summary.py`, no new file under `reports/`).

## Cache-Backed Impact Check (Task 1, verify step)

Written as a throwaway scratchpad script (never committed) that loads `data/cache/2026-08-05/{vulns_all,assets_all,vulns_fixed_365d}.parquet` directly via `pd.read_parquet` and calls each module's `compute()` twice (bare `ModuleConfig` vs. `options={"include_risk_managed": True}`) at `report_date = 2026-08-05`, all-assets scope. Observed values match the approved plan's expected numbers exactly:

| Metric | Excluding (today) | Including | Delta |
|---|---|---|---|
| Critical Remediation SLA | 81.8% (open criticals 3,308, denominator 18,931, compliant 15,479) | **78.9%** (open criticals **4,019**, denominator 19,627, compliant 15,479) | −2.9 pp; numerator unchanged |
| High-Risk Assets | 52 / 0.1% | **52 / 0.1%** | none on this snapshot |
| Aged Vulnerability Assets | 5,585 / 15.4% | **6,279 / 17.4%** | +694 assets / +2.0 pp |

No divergence from the plan's expected values — no STOP condition triggered.

## Full-Suite Failure Counts (Task 3)

`tests/unit/test_modules.py` in isolation and combined with `tests/unit tests/content`: **0 failures before and after** this change in this environment. The plan flagged "5 order-dependent stub-registry failures" as a known pre-existing condition to record rather than fix; they did not reproduce in either the isolated `tests/unit/test_modules.py -q` run or the combined `tests/unit tests/content -q` run (both exit 0). Recorded here per the plan's instruction rather than investigated further, since they are out of this task's scope regardless of whether they reproduce.

All named verification runs passed with exit 0:
- `run_all.py --dry-run` — exit 0, all 6 board deliveries (5 in `board.yaml` + `board_test.yaml`'s on-demand group) list two reports; the "Board Summary — Live Test" entry in `adhoc.yaml` also lists two.
- `pytest tests/unit tests/content -q` — exit 0.
- `pytest tests/test_kpi_risk_managed_exclusion.py tests/test_board_report_utils.py tests/test_phase6_board_summary_chrome.py tests/test_phase6_run_group_chrome.py tests/test_board_accepted_recast.py tests/test_phase4_schema_validation.py tests/test_phase4_analyst_detail_toggle.py tests/test_consumer_audit.py tests/test_board_summary_baseline.py tests/test_board_summary_variants.py -q` — exit 0.
- Schema-enum ↔ `_VALID_REPORTS` symmetric difference: empty (13 entries each), verified both via a scratchpad one-liner and enforced going forward by `tests/test_board_summary_variants.py::TestSlugRegistration::test_schema_enum_reconciled_with_valid_reports`.

## Operator-Only Follow-Ups (not attempted — need a warm cache + real run)

Per the plan's `<verification>` section, these require a live/manual run outside Claude Code and were not attempted:

1. `python run_all.py --group "Board Summary - test" --no-email` — verify 2 PDFs, 2 main + 2 analyst Excels with distinct filenames; `owner_segmentation.*` present under `board_summary/` and **absent** under `board_summary_incl_risk_managed/`; `[CACHE HIT]` on the second slug's fetches; cover titles carry the right qualifiers; Metrics 1 and 5 identical, 2 and 4 moved.
2. Capture the MIME structure: exactly 5 `Content-ID` parts, every `cid:` in the body resolving to one of them with no orphans; 6 attachments with 6 distinct filenames.
3. Render in Outlook + Gmail + Apple Mail — a CID regression shows as a wrong image, not an error.
4. The cover title is 22pt; if the `" (Excluding Risk-Accepted & Recast)"` / `" (Including Risk-Accepted & Recast)"` suffix wraps badly in the real WeasyPrint render, shorten to `" (Excl. …)"` / `" (Incl. …)"` — operator judgment, no code change beyond the two literals in `reports/board_summary.py`.
5. Regenerate the stale `tests/baselines/board_summary_test_pull*.json` structural baselines via `scripts/smoke_board_summary_cutover.py` (stale since quick-260722-lx9; unrelated to this task, noted per the plan).

## Local Operator Config Note

`deliveries.d/board.yaml` (all 5 deliveries), `deliveries.d/board_test.yaml`, and the "Board Summary — Live Test" entry in `deliveries.d/adhoc.yaml` were edited to add `board_summary_incl_risk_managed` alongside `board_summary` and to update `subject:` lines noting both views are attached. This worktree did not have `deliveries.d/`, `contacts.yaml`, or `delivery_config.yaml` present (gitignored local operator config, not shared across git worktrees) — they were copied in from the main checkout before editing, edited here, and are correctly **not** staged or committed (confirmed via `git status --short` before every commit). The operator's main checkout at `/home/jmonroe/projects/vuln-reporting/deliveries.d/board.yaml` etc. was **not** modified — the operator should apply the same edit there (or copy this worktree's edited files back) before the next scheduled board delivery.

## Self-Check: PASSED

All files listed in `files_modified` (plus the new `tests/test_board_summary_variants.py`) confirmed present on disk. All three task commits confirmed in `git log`:
- `517637c` — Task 1 (module option)
- `cd9747c` — Task 2 (variant-parameterize + slug registration)
- `1c72950` — Task 3 (variant test suite + docs)
