# Phase 19 — CodeRabbit Findings Triage

**Source:** `19-CODERABBIT.md` (raw JSONL stream — `coderabbit review --agent --base-commit f3f1c4f`, free CLI tier, 2026-06-24)
**Review scope:** `f3f1c4f..HEAD` (all Phase 18 work + uncommitted tree)
**Total findings:** 41 — 1 critical, 22 major, 18 minor
**Net-new after dedup:** 39 (2 exact duplicates of existing review findings; 1 partial overlap tracked as an extension)

Per **D-06**, CodeRabbit is an additive second-opinion inventory; per **D-02**, *everything* here is in fix-all scope. This file is the deduplicated, planner-ready cut. IDs (`CR-*`) are assigned here for plan/commit traceability.

---

## Dedup against existing v1.4 review backlog

| CodeRabbit finding | Maps to | Disposition |
| --- | --- | --- |
| `data/trend_store.py` L389-390 — month key UTC vs server-local | **18-REVIEW WR-06** (local-vs-UTC month attribution) | **Duplicate — already in scope.** Do not double-track. |
| `docs/management_summary_calculations.md` L137-148 — pre-v1.4 stale SLA/MTTR/M5/M7 sections | **18-REVIEW IN-03** (stale runbook describing removed bespoke path) | **Duplicate — already in scope.** |
| `data/trend_store.py` L153-193 — `_load_trend_json` no shape/type validation | **18-REVIEW WR-07** (corrupt-file rename, same ~L172-192 block) | **Partial overlap — extends WR-07.** Tracked as **CR-B7**: WR-07 adds the destructive-rename fix; CR-B7 adds root-dict + snapshots-list-of-dicts validation on top. Fix together. |

---

## Net-new findings (39) — grouped for plan waves

Grouping mirrors the existing D-02 guidance: keep risky correctness/security edits in their own waves; batch low-value doc/comment cleanup separately.

### A. Security / fail-closed — highest priority (5)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-C1 | **critical** | `.claude/hooks/block_tenable_fetch.py` L82-90 | `effective_head` bypass only strips simple wrappers/`VAR=val`; guarded fetches slip through nested `bash -lc`/`sh -c` payloads and `python -c`/`-m` module refs. Recurse into wrapper payloads + inspect `-c`/`-m`; add regression coverage for those shapes. |
| CR-S1 | major | `.claude/hooks/block_tenable_fetch.py` L127-131 | Malformed `PreToolUse` payload path `sys.exit(0)` → **fails open** (allows). Emit the generic deny instead — fail closed. |
| CR-S2 | major | `data/trend_store.py` L456-458 | Trend filename built directly from `tag_filter`; `/../` escapes the trend dir (path traversal). Sanitize the filename suffix only; keep stored `tag_filter` field unchanged. |
| CR-S3 | major | `reports/modules/scan_coverage_sla_module.py` L555-557 | `data.error` + owner label strings interpolated unescaped into email error-box HTML. Escape both sites with the existing HTML-escape helper. |
| CR-S4 | major | `reports/owner_supplemental.py` L246-248 | `output_dir` accepts any path incl. `data/trend`; violates PII output-path policy ([[project_pii_rule_is_ai_not_email]]). Add fail-fast guard rejecting paths under `data/trend/` before `mkdir`. |

### B. Trend / backfill correctness (7)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-B1 | major | `scripts/backfill_trend_reconstruction.py` L133-149 | Add-back rows fixed *after* the boundary are dropped by `open_findings_at()` (treats `state=fixed` as terminal) — historical counts undercount. Flip add-back rows to `open` for the boundary check only; preserve original fixed metadata. |
| CR-B2 | major | `scripts/backfill_trend_reconstruction.py` L503-511 | Cached branch returns `vulns_all.parquet` without the OPEN/REOPENED filter `fetch_all_vulnerabilities()` applies → cached vs live runs diverge ([[project_tenable_fixed_retention_trend]]). Apply same status filter on the cached path. |
| CR-B3 | minor | `scripts/backfill_trend_reconstruction.py` L216-218 | Reconstruction window + fallback-month logic uses local-naive time; misclassifies current month at rollover. Use UTC consistently (same class as WR-06, new site). |
| CR-B4 | minor | `scripts/backfill_trend_reconstruction.py` L477-482 | `--window-start` not validated in argparse; malformed `YYYY-MM` fails late after Tenable/cache work. Add a `_month_arg` type validator up front. |
| CR-B5 | major | `data/fetchers.py` L379-435 | `fetch_fixed_vulnerabilities` omits `lookback_days` from cache identity → different windows reuse the same parquet ([[project_tenable_fixed_retention_trend]]). Include `lookback_days` in the cache key (`vulns_fixed_{N}d`). |
| CR-B6 | major | `data/trend_store.py` L427-433 | `fixed_findings_count` stays `None` when `fixed_vulns_df` is present-but-empty; should be explicit `0` (empty ≠ missing). |
| CR-B7 | major | `data/trend_store.py` L153-193 | `_load_trend_json` returns `data.get("snapshots", [])` unchecked. Validate root is dict, snapshots is list, each item is dict; else treat as parse failure. **Extends WR-07** (same block) — fix together. |

### C. Fail-soft / module rendering (4)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-F1 | major | `reports/modules/composer.py` L653-681 | Fail-soft PDF path still assumes `render_pdf_section()` returns a string; non-string/invalid result breaks assembly at `.strip()`. Validate return shape before use; skip/convert to safe fallback. |
| CR-F2 | major | `reports/modules/composer.py` L1158-1166 | `assemble_analyst_workbook` treats no-data and all-modules-failed identically → drops the `_Metadata` tab on failure-only runs. Split the paths; emit `_Metadata` from `failures` when every module fails. |
| CR-F3 | minor | `reports/management_summary.py` L202-240 | `run_report` "never raises" contract violated — fetch/compose path unguarded. Wrap fetch/compose and reflect failure in status dict (like PDF/Excel fallbacks) **or** soften the docstring. Touches the same path as INT-WARN-1/2 — fold into that wave. |
| CR-F4 | major | `delivery/email_sender.py` L487-501 | `prebuilt_charts` (management_summary) path decodes + attaches inline images with no 2 MB/5 MB budget check, unlike `email_inline_images`. Apply the same size-budget helper. |

### D. Module copy / audit-metadata accuracy (2)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-D1 | major | `reports/modules/aged_vulns_assets_module.py` L115-116 | Docstring/PDF copy/audit metadata still say "highest percentage / affected DESC, percentage DESC"; actual `table_data`/`top_5` sort by `risk_score`. Update copy to match (M5 redesign). |
| CR-D2 | major | `reports/modules/high_risk_assets_module.py` L117-119 | Copy/`get_audit_info()` say "highest percentage" + Application-tag grouping; actual is `risk_score` ordering + Owner via `extract_owner()` ([[project_business_unit_interim_application]]). Align text + audit messaging. |

### E. Test rigor / portability (7)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-T1 | major | `tests/e2e/test_groups.py` L103 | `_GROUPS[0]` indexed unconditionally at import → collection breaks when `_load_groups()` is empty ([[project_full_suite_test_collection_quirks]]). Guard/skip when no groups. |
| CR-T2 | major | `tests/test_consumer_audit.py` L552-555 | `_PASS_THROUGH_CALLERS` matches any `run_report` scope (too broad). Use module-qualified `file::function` identifiers for the exemption. |
| CR-T3 | major | `tests/test_backfill_reconstruction.py` L247-264 | Add-back test tolerance is too loose — passes even if rows 3/4 are dropped. Require exact/zero-tolerance match. **Pairs with CR-B1** (the test that should catch it). |
| CR-T4 | minor | `tests/test_backfill_reconstruction.py` L565-588 | Partial-flag checks are conditional → pass even if taper months were never produced. Assert the expected taper/non-taper month set exists first. |
| CR-T5 | minor | `tests/test_management_summary.py` L550-595 | `_check_float_tolerance`/`_check_mixed` or-chains treat valid `0`/`0.0` as missing. Use explicit key-existence checks (empty-data 0-vs-absent). |
| CR-T6 | minor | `tests/baselines/management_summary_structural_schema.py` L81-102 | `pdf_page_count` drift is env-dependent (WeasyPrint vs fallback heuristic). Don't treat fallback-derived counts as drift, or require WeasyPrint. |
| CR-T7 | minor | `tests/baselines/management_summary_value_golden.json` L4 | `_meta.fixture_dir` hardcodes a machine-specific absolute Windows path. Emit repo-relative. |

### F. Deploy script — `scripts/update_from_github.sh` (2)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-U1 | major | L327-331 | Relative symlink target normalization is inconsistent; legacy `releases/v1.2.0` duplicates to `INSTALL_ROOT/releases/releases/...`. Anchor non-absolute targets against `INSTALL_ROOT` only; share a resolver helper. |
| CR-U2 | major | L904-916 | `--force` re-extraction can delete the active release dir before a replacement is staged → breaks rollback (`PREV` points at a rebuilt tree). Refuse `--force` on the active release, or stage-then-swap. |

### G. Doc / comment staleness — cleanup wave (12)

| ID | Sev | File · lines | Issue |
| --- | --- | --- | --- |
| CR-G1 | minor | `scripts/smoke_management_summary_cutover.py` L1-7 | Docstring/run wording still describes the old bespoke path; now returns `result["_bundle"]`. |
| CR-G2 | minor | `run_all.py` L94-102 | Stale CHROME-COMPAT-01 comment says management_summary must not receive chrome kwargs (no longer true post-GEN-01). |
| CR-G3 | minor | `scripts/smoke_email_phase2.py` L332-346 | `--no-stub-panels` help text misdescribes behavior (only disables empty-panels stub, not the legacy KPI path). |
| CR-G4 | major | `scripts/smoke_email_phase2.py` L133-139 | Smoke generates cid-gauge panel HTML but never attaches the inline images → cids don't resolve in the sent message. |
| CR-G5 | major | `docs/trend_and_segmentation_calculations.md` L182-191 | "No backfill" guidance is outdated vs the supported `backfill_trend_reconstruction.py` workflow. Separate unsupported ad-hoc backfill from the sanctioned reconstruction path. |
| CR-G6 | minor | `.planning/ROADMAP.md` L9 | v1.4 milestone badge ("in progress") inconsistent with the completed progress table. |
| CR-G7 | minor | `.planning/STATE.md` L24-31 | Current-focus summary contradicts the detailed phase/status fields + Phase 19 resume target ([[project_decision_coverage_gate_searches_frontmatter_only]] context: STATE schema). |
| CR-G8 | minor | `19-CONTEXT.md` L66-67 | Ambiguous `19-.../19-CODERABBIT.md` placeholder ref. **Fixed as part of this fold** (now concrete + points at this triage). |
| CR-G9 | minor | `.planning/phases/18-management-summary-migration-docs/18-VALIDATION.md` L4-7 | Status fields + Wave 0 checklist inconsistent with the approved sign-off section. |
| CR-G10 | minor | `.planning/milestones/v1.3-phases/13-owner-segmentation-composition-s2-doc/13-03-SUMMARY.md` L65-67 | `enriched_assets` empty-vs-`None` handling doc is self-contradictory. |
| CR-G11 | minor | `.planning/phases/15-independent-new-modules/15-02-SUMMARY.md` L88-89 | Invalid set notation in the ACCEPTED/RECASTED example. |
| CR-G12 | minor | `.planning/phases/14-shared-substrates-composed-report-gates/14-03-PLAN.md` L139-146 | Malformed inline shell check in stub-discovery acceptance criteria; should assert `sc4_kwargs_stub` is actually in the registry ([[project_frozenset_gate_test_coupling]]). |

---

## Notes for the planner

- **Severity ≠ wave priority.** CR-C1 (hook bypass) is the only critical and is a genuine guard-bypass — sequence it early in a security wave with CR-S1..S4.
- **Pairs to land together:** CR-B1 + CR-T3 (fix + the test that proves it); CR-B7 + WR-07 (same block); CR-F3 + INT-WARN-1/2 (same management_summary fetch/compose path).
- **`.claude/hooks/` is currently untracked** (`?? .claude/hooks/` in git status) — CR-C1/CR-S1 land on files not yet committed; confirm they're committed as part of this phase.
- **Several G-items are GSD planning docs** (ROADMAP/STATE/SUMMARY/PLAN/VALIDATION). They're trivially fixable but touch milestone-audit artifacts — the D-07 closeout already refreshes ROADMAP/STATE, so fold CR-G6/G7 into that final step rather than an early wave.
- **All 39 are in scope under D-02** ("fix net = everything"). None justify a re-litigation of scope; this triage only assigns IDs and grouping for the plan.
