# Phase 19: v1.4 Closure — Pattern Map

**Mapped:** 2026-06-24
**Files analyzed:** 28 (modify-dominated; 0 creates)
**Analogs found:** 28 / 28 (every file is its own primary analog or has a named sibling)

---

## Overview

This is a **correctness-and-cleanup phase** — no new files, only targeted edits to existing ones. The pattern map is therefore organized around *what pattern to mirror or remove* rather than *what structure to copy wholesale*. For each work-stream bucket the executor needs: (a) the file and line range being touched, (b) the existing pattern that is authoritative, and (c) the concrete excerpt to replicate or the symbol to delete.

---

## File Classification

| File | Role | Data Flow | Closest Analog / Source of Truth | Work-stream |
|------|------|-----------|----------------------------------|-------------|
| `reports/management_summary.py` | report (composer wrapper) | request-response | `reports/composed_report.py` gated fetch block (L245-259) | INT-WARN-1, INT-WARN-2, CR-F3 |
| `tests/test_composed_report_kwargs_gates.py` | test | — | itself: `test_frozensets_membership` (L92-108) | INT-WARN-3 |
| `.claude/hooks/block_tenable_fetch.py` | security hook | request-response | itself: `effective_head` / `script_hit` / `deny` pattern (L82-155) | CR-C1, CR-S1 |
| `data/trend_store.py` | data / I-O | file-I/O | itself: `capture_snapshot` new_entry dict (L435-453); `_load_trend_json` (L153-193) | CR-S2, CR-B6, CR-B7, WR-06, WR-07 |
| `reports/modules/scan_coverage_sla_module.py` | module | request-response | itself: `html.escape` pattern (L851-903) | CR-S3 |
| `reports/owner_supplemental.py` | report | file-I/O | itself: output-path guard pattern (add fail-fast) | CR-S4 |
| `scripts/backfill_trend_reconstruction.py` | script | batch | itself: `_months_in_range_stdlib` (L211-228); `fetch_all_vulnerabilities` open-filter | CR-B1, CR-B2, CR-B3, CR-B4, WR-04 |
| `data/fetchers.py` | data | request-response | itself: `_cache_path(cache_dir, "vulns_fixed")` pattern (L432); `_first_str` (L163) | CR-B5, IN-02 |
| `reports/modules/composer.py` | composer | request-response | itself: `render_pdf_section` call + fail-soft (L653-681); `assemble_analyst_workbook` (L1073-1165) | CR-F1, CR-F2 |
| `delivery/email_sender.py` | delivery | request-response | itself: `email_inline_images` size-budget check (existing) | CR-F4 |
| `reports/modules/aged_vulns_assets_module.py` | module | CRUD | `reports/modules/high_risk_assets_module.py` (sibling with same risk_score sort) | CR-D1 |
| `reports/modules/high_risk_assets_module.py` | module | CRUD | itself: `extract_owner()` call site + `get_audit_info()` | CR-D2 |
| `tests/e2e/test_groups.py` | test | — | itself + sibling tests: guard `_GROUPS[0]` access | CR-T1 |
| `tests/test_consumer_audit.py` | test | — | itself: `_PASS_THROUGH_CALLERS` set (L552-555) | CR-T2 |
| `tests/test_backfill_reconstruction.py` | test | — | itself: add-back tolerance (L247-264); partial-flag (L565-588) | CR-T3, CR-T4 |
| `tests/test_management_summary.py` | test | — | itself: `_check_float_tolerance`/`_check_mixed` (L550-595) | CR-T5 |
| `tests/baselines/management_summary_structural_schema.py` | test baseline | — | itself: `pdf_page_count` check (L81-102) | CR-T6 |
| `tests/baselines/management_summary_value_golden.json` | test fixture | — | itself: `_meta.fixture_dir` (L4) | CR-T7 |
| `scripts/update_from_github.sh` | deploy | batch | itself: symlink resolver (L327-331); `--force` re-extraction (L904-916) | CR-U1, CR-U2 |
| `scripts/smoke_management_summary_cutover.py` | script/doc | — | itself: docstring (L1-7) | CR-G1 |
| `run_all.py` | entry point | — | itself: stale comment (L94-102) | CR-G2 |
| `scripts/smoke_email_phase2.py` | script | — | itself + `delivery/email_sender.py` CID-attach pattern | CR-G3, CR-G4 |
| `docs/trend_and_segmentation_calculations.md` | doc | — | itself: "No backfill" section (L182-191) | CR-G5 |
| `.planning/ROADMAP.md` | planning doc | — | itself: v1.4 badge (L9) | CR-G6 (fold into D-07 closeout) |
| `.planning/STATE.md` | planning doc | — | itself: current-focus section (L24-31) | CR-G7 (fold into D-07 closeout) |
| `utils/open_count.py` | utility | transform | itself: `open_findings_at` (L19-114); `scripts/capture_trend_snapshot.py` SLA block (L390-418) | D-05 SLA-rate bias (site 1 of 3) |
| `reports/modules/program_health_module.py` | module | transform | `scripts/capture_trend_snapshot.py` SLA block (L390-418) — shared helper target | D-05 SLA-rate bias (site 2 of 3) |
| `config.py` | config | — | itself: `VPR_SEVERITY_MAP` (L95-100); `vpr_to_severity` hot-path `import math` (L147) | WR-08, IN-01 |
| `docs/management_summary_calculations.md` | doc | — | itself: pre-v1.4 stale sections (already in scope as 18-REVIEW IN-03) | IN-03 |
| `reports/modules/{reopened_vulns,external_dmz,new_vs_remediated,vuln_density}_module.py` | modules | transform | sibling modules with clean import blocks (e.g. `external_dmz_module.py` L36-57) | 15-REVIEW IN-01..05 |

---

## Pattern Assignments by Work-stream

---

### INT-WARN-1 — `reports/management_summary.py`: partial forward-write

**Problem:** `capture_snapshot()` call at ~L420-427 passes only `df`, `assets_df`, `date`, `dimension`, `tag_filter`, `fixed_vulns_df`. The full `capture_snapshot` signature (confirmed at `data/trend_store.py` L275-294) also accepts `on_time_asset_count`, `reopened_count`, `accepted_count`, `recast_count`, `mttr_overall_days`, `mttr_by_severity`, `mttr_by_owner`, `sla_rate_crit_high`.

**Decision D-03:** Make management_summary a *complete* writer — forward the full field set, matching what `scripts/capture_trend_snapshot.py` emits at L420-432.

**Source of truth — complete `capture_snapshot` call** (`scripts/capture_trend_snapshot.py` L420-432):
```python
path = capture_snapshot(
    df, assets_df, snapshot_date, "severity", "all_assets",
    on_time_asset_count=on_time_asset_count,
    reopened_count=reopened_count,
    accepted_count=accepted_count,
    recast_count=recast_count,
    fixed_vulns_df=fixed_vulns_df,
    mttr_overall_days=mttr_overall_days,
    mttr_by_severity=mttr_by_severity,
    mttr_by_owner=mttr_by_owner,
    sla_rate_crit_high=sla_rate_crit_high,
)
```

**Current management_summary call** (`reports/management_summary.py` L420-427) — the incomplete writer to replace:
```python
capture_snapshot(
    df             = vulns_df,
    assets_df      = assets_df,
    date           = generated_at,
    dimension      = "severity",
    tag_filter     = tag_filter_label,
    fixed_vulns_df = fixed_vulns_df,
)
```

**What to derive from the composer bundle:** The aggregate counts (`reopened_count`, `accepted_count`, `recast_count`, `on_time_asset_count`, `mttr_*`, `sla_rate_crit_high`) must be extracted from the module results already computed by `composer.run_all()`. Pattern for extracting from `results` list: iterate `results` for the module that produces each metric (e.g. `accepted_recast` module for accepted/recast counts; `scan_coverage_sla` for `on_time_asset_count`; `mttr_trend` for mttr values; `program_health` for `sla_rate_crit_high`) and read from `result.metrics`. Use `None` as the safe default when a module's result has `error is not None`.

**D-03b regression guard:** Assert that the kwargs set forwarded by management_summary matches the `capture_snapshot` parameter set (minus `df`/`assets_df`/`date`/`dimension`/`tag_filter`/`trend_dir`/`enriched_assets`). A unit test comparing the two keyword sets catches future partial-write regressions without a live run.

---

### INT-WARN-2 — `reports/management_summary.py`: missing `recast_rules_df` fetch

**Problem:** `accepted_recast` module is in `_MGMT_MODULE_CONFIGS` but `recast_rules_df` is never fetched and never forwarded to the `ReportComposer`, so the expiry cross-check inside `accepted_recast.compute()` is silently skipped.

**Decision D-04:** Mirror the `_MODULES_NEEDING_RECAST_RULES` gated fetch pattern from `reports/composed_report.py`.

**Source of truth — gated recast fetch** (`reports/composed_report.py` L245-259):
```python
need_recast = bool(_MODULES_NEEDING_RECAST_RULES.intersection(modules))
recast_rules_df: Optional[pd.DataFrame] = None
if need_recast:
    # Fail-soft (WR-02): a recast fetch failure (transient API/network error
    # after tenacity exhausts, parquet write error) degrades to "kwarg
    # absent" rather than aborting the batch.
    try:
        from data.fetchers import fetch_recast_rules  # noqa: PLC0415
        logger.info("composed_report: fetching recast rules …")
        recast_rules_df = fetch_recast_rules(tio, cache_dir)
    except Exception as exc:
        logger.error(
            "composed_report: recast rules fetch failed: %s", exc, exc_info=True
        )
        recast_rules_df = None
```

**Adaptation for management_summary:** `accepted_recast` is always in `_MGMT_MODULE_CONFIGS`, so the `need_recast` intersection check is not required — fetch unconditionally (but still fail-soft). Forward `recast_rules_df=recast_rules_df` into the `ReportComposer(...)` constructor alongside the existing `trend_snapshots=` kwarg (L353-361).

---

### INT-WARN-3 — `tests/test_composed_report_kwargs_gates.py`: missing `_MODULES_NEEDING_FIXED_VULNS` gate

**Problem:** `test_frozensets_membership` (L92-108) asserts membership for `_MODULES_NEEDING_TREND_SNAPSHOTS` and `_MODULES_NEEDING_RECAST_RULES` but has no assertion for `_MODULES_NEEDING_FIXED_VULNS`.

**Source of truth — existing gate assertions** (`tests/test_composed_report_kwargs_gates.py` L100-108):
```python
assert _MODULES_NEEDING_TREND_SNAPSHOTS == frozenset(
    {"sc4_kwargs_stub", "new_vs_remediated", "vuln_density", "accepted_recast", "mttr_trend", "program_health"}
), "_MODULES_NEEDING_TREND_SNAPSHOTS membership drifted (D-17 / Phase 15 / Phase 16 / Phase 17)"
assert _MODULES_NEEDING_RECAST_RULES == frozenset(
    {"sc4_kwargs_stub", "accepted_recast"}
), "_MODULES_NEEDING_RECAST_RULES membership drifted (D-17 / Phase 15)"
```

**Pattern to add:** Add a third `assert` block using the same exact-membership pattern. Import `_MODULES_NEEDING_FIXED_VULNS` alongside the existing imports (L44-47). Current membership at `reports/composed_report.py` L73-76: `{"critical_remediation_sla", "mttr_trend"}`. The assertion message must follow the same "(D-NN / Phase NN)" citation format.

---

### Work-stream A — Security / fail-closed

#### CR-C1 + CR-S1: `.claude/hooks/block_tenable_fetch.py`

**CR-C1 problem:** `effective_head` (L82-90) strips simple wrappers but misses `bash -lc '...'` / `sh -c '...'` payloads and `python -c` / `python -m` module refs inside those payloads.

**Existing `effective_head` pattern** (L82-90):
```python
def effective_head(tokens):
    """Basename of the real command, skipping wrappers and VAR=val prefixes."""
    i = 0
    while i < len(tokens):
        if basename(tokens[i]) in WRAPPERS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
            i += 1
            continue
        return basename(tokens[i]), tokens[i + 1:]
    return None, []
```

**Fix pattern:** When `effective_head` resolves to a shell wrapper (`bash`, `sh`, `zsh`) and a `-c` flag follows, recursively tokenize the `-c` payload and call `script_hit` on the resulting sub-tokens. Similarly, when the head is a Python interpreter and `-c` follows, check the inline code string for guarded module/script names.

**CR-S1 problem:** Malformed `PreToolUse` payload → `sys.exit(0)` at L127-131 / L131 (the `except Exception` block) allows instead of denies.

**Existing deny pattern** (L119-125):
```python
def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)
```

**Fix:** Replace bare `sys.exit(0)` in the malformed-payload `except` branch with `deny("Blocked: malformed PreToolUse payload — failing closed.")`.

#### CR-S2: `data/trend_store.py` — path traversal in filename

**Problem (L456-458):** `tag_suffix = tag_filter` is used directly in `f"trend_{dimension}_{tag_suffix}.json"` — a `/../` in `tag_filter` escapes `TREND_DIR`.

**Fix pattern:** Sanitize via the existing `_sanitise_tag_for_filename` helper (L126-150) before building the file path. The stored `tag_filter` field in the JSON entry stays unchanged — only the filesystem suffix is sanitized.

```python
# Fix: sanitize the suffix only
tag_suffix = re.sub(r"[^A-Za-z0-9_]", "_", tag_filter).strip("_") or "all_assets"
file_path = trend_dir / f"trend_{dimension}_{tag_suffix}.json"
```

Note: `_sanitise_tag_for_filename` takes `(category, value)` not a pre-joined string. Either call it with parsed components or apply the identical regex inline.

#### CR-S3: `reports/modules/scan_coverage_sla_module.py` — unescaped HTML in error box

**Problem (L555-557):** `data.error` and owner label interpolated unescaped into email error-box HTML.

**Existing HTML-escape pattern in the same file** (L851-852, L885-886):
```python
label_esc  = html.escape(str(self.DISPLAY_NAME), quote=True)
driver_esc = html.escape(str(data.driver_narrative or ""), quote=True)
```

**Fix:** Apply the same `html.escape(..., quote=True)` to `data.error` and the owner label string at the two L555-557 sites. `html` is already imported in `composer.py`; confirm it is also imported in `scan_coverage_sla_module.py` or add `import html`.

#### CR-S4: `reports/owner_supplemental.py` — output-path PII guard

**Problem (L246-248):** `output_dir` accepts arbitrary paths including `data/trend/`.

**Fix pattern:** Add a fail-fast guard before `mkdir`:
```python
_resolved = Path(output_dir).resolve()
_trend_resolved = (Path(__file__).resolve().parent.parent / "data" / "trend").resolve()
if _resolved == _trend_resolved or _trend_resolved in _resolved.parents:
    raise ValueError(
        f"owner_supplemental: output_dir {output_dir!r} resolves inside "
        "data/trend/ — PII output-path policy violation (project_pii_rule_is_ai_not_email)."
    )
```

---

### Work-stream B — Trend / backfill correctness

#### CR-B1: `scripts/backfill_trend_reconstruction.py` L133-149 — add-back rows dropped

**Problem:** `open_findings_at()` treats `state=fixed` as terminal, so add-back rows (findings fixed after the boundary) are dropped from the historical open count.

**Fix pattern:** For the boundary check only, flip add-back rows' state to `"open"` in a local copy before calling `open_findings_at`. Do not mutate the original DataFrame (CoW rule from CONVENTIONS.md).
```python
# Flip add-back rows to "open" for the boundary predicate only
_df_boundary = df.copy()
_df_boundary.loc[add_back_mask, "state"] = "open"
open_at_boundary = open_findings_at(_df_boundary, boundary_date)
```

#### CR-B2: `scripts/backfill_trend_reconstruction.py` L503-511 — cached path skips open/reopened filter

**Problem:** Cached branch returns `vulns_all.parquet` without applying the `state in {open, reopened}` filter that the live `fetch_all_vulnerabilities()` applies.

**Fix pattern:** After loading from cache, apply the same status filter the live fetcher applies. The existing pattern in `data/fetchers.py` uses `state` column lower-case values `{"open", "reopened"}`:
```python
if cached is not None:
    open_mask = cached["state"].str.lower().isin({"open", "reopened"})
    return cached[open_mask].reset_index(drop=True)
```

#### CR-B3: `scripts/backfill_trend_reconstruction.py` L216-218 — local-naive time at rollover

**Problem:** `_months_in_range` and `_months_in_range_stdlib` call `datetime.now()` (local-naive). Consistent with WR-06 class of bug — use `datetime.now()` (local, no tzinfo) for month-key attribution per CLAUDE.md timezone policy (month keys = server local), but confirm the *current-month* boundary check uses the same convention. If the function is computing the reconstruction window boundary (not a snapshot month-key), UTC is appropriate here.

**Fix pattern:** Match the timezone policy already used for month keys in `capture_snapshot` (L390: `month_str = date.strftime("%Y-%m")`). For the reconstruction window boundary, use `datetime.now()` consistently (local-naive) so rollover attribution agrees with the snapshot store.

#### CR-B4: `scripts/backfill_trend_reconstruction.py` L477-482 — `--window-start` not validated

**Fix pattern:** Add an `argparse` type validator. Mirror the pattern used in `scripts/capture_trend_snapshot.py` for date validation:
```python
def _month_arg(value: str) -> str:
    import re
    if not re.fullmatch(r"\d{4}-\d{2}", value):
        raise argparse.ArgumentTypeError(
            f"--window-start must be YYYY-MM, got {value!r}"
        )
    return value
# In argparse:
parser.add_argument("--window-start", type=_month_arg, ...)
```

#### CR-B5: `data/fetchers.py` L379-435 — `lookback_days` missing from cache key

**Problem:** `_cache_path(cache_dir, "vulns_fixed")` always produces `vulns_fixed.parquet` regardless of `lookback_days`. Different lookback windows reuse the same file.

**Existing `_cache_path` pattern** (`data/fetchers.py` L203-204):
```python
def _cache_path(cache_dir: Path, dataset: str) -> Path:
    return cache_dir / f"{dataset}.parquet"
```

**Fix:** Include `lookback_days` in the dataset name:
```python
cache = _cache_path(cache_dir, f"vulns_fixed_{lookback_days}d")
```

This is a one-line change at L432. No other callers pass `lookback_days` != default, so no cascading changes are needed.

#### CR-B6: `data/trend_store.py` L427-433 — `fixed_findings_count` stays `None` for empty-but-present df

**Problem:** The guard `if not fixed_vulns_df.empty:` at L427 leaves `fixed_findings_count = None` when `fixed_vulns_df` is present but empty. Empty ≠ missing.

**Fix pattern:** Set `fixed_findings_count = 0` when `fixed_vulns_df` is present-but-empty:
```python
if fixed_vulns_df is not None:
    # ... existing new_findings_count derivation ...
    if fixed_vulns_df.empty:
        fixed_findings_count = 0   # present but empty → explicit zero
    else:
        # existing lf_month logic
        lf = pd.to_datetime(fixed_vulns_df["last_fixed"], utc=True, errors="coerce")
        ...
```

#### CR-B7 + WR-07: `data/trend_store.py` L153-193 — `_load_trend_json` validation + corrupt rename

**CR-B7 problem:** `data.get("snapshots", [])` at L179 is called without checking that `data` is a dict, and each element of the returned list is not validated to be a dict.

**WR-07 problem (existing in scope):** Corrupt file is renamed `*.corrupt` (best-effort) but the rename code (L172-192) may lose recoverable data.

**Fix pattern — extend the existing corrupt-file block** to add root-dict and snapshots-list-of-dicts validation:
```python
try:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    # CR-B7: validate root is dict
    if not isinstance(data, dict):
        raise ValueError(f"_load_trend_json: root is {type(data).__name__}, expected dict")
    snapshots = data.get("snapshots", [])
    # CR-B7: validate snapshots is a list of dicts
    if not isinstance(snapshots, list):
        raise ValueError(f"_load_trend_json: 'snapshots' is {type(snapshots).__name__}, expected list")
    bad = [i for i, s in enumerate(snapshots) if not isinstance(s, dict)]
    if bad:
        raise ValueError(f"_load_trend_json: non-dict snapshot entries at indices {bad}")
    return snapshots
except (json.JSONDecodeError, ValueError, AttributeError) as exc:
    # WR-07 + CR-B7: rename corrupt file before returning []
    logger.error("_load_trend_json: parse/validation failure for %s: %s", path, exc)
    _corrupt = path.with_suffix(".corrupt")
    try:
        path.rename(_corrupt)
        logger.error("_load_trend_json: renamed corrupt file to %s", _corrupt)
    except OSError as rename_exc:
        logger.error("_load_trend_json: could not rename corrupt file: %s", rename_exc)
    return []
```

---

### Work-stream C — Fail-soft / module rendering

#### CR-F1: `reports/modules/composer.py` L653-681 — `render_pdf_section` non-string return

**Problem:** Line 675 calls `.strip()` on `html_section` without verifying it is a string. A module returning `None` or an int crashes assembly.

**Existing fail-soft pattern in the same block** (L657-673): the `except Exception` block already builds a safe fallback string. Extend it:
```python
html_section = instance.render_pdf_section(data, config)
# CR-F1: validate return type before .strip()
if not isinstance(html_section, str):
    logger.warning(
        "ReportComposer.assemble_pdf [%s]: render_pdf_section() returned "
        "%r (not str) — converting to safe fallback.",
        data.module_id, type(html_section).__name__,
    )
    html_section = ""
if not html_section or not html_section.strip():
    continue
```

#### CR-F2: `reports/modules/composer.py` L1158-1166 — `assemble_analyst_workbook` drops `_Metadata` on all-fail

**Problem:** When `collected` is empty *and* `failures` is non-empty (every module failed), the code falls into the "all-empty workbook → no file written" branch and drops the `_Metadata` tab entirely.

**Existing `_Metadata` write pattern** (after L1158): the `_Metadata` tab is written after all module tabs. The fix is to split the all-empty path: if `failures` is non-empty, still write a workbook containing only `_Metadata`.

**Pattern to mirror:** The existing `_Metadata` + `failures` writing code that runs when `collected` is non-empty. Move the `_Metadata`-only write into the `if not collected` branch when `failures`:
```python
if not collected:
    if not failures:
        logger.info("...every module returned [] or empty DataFrames — skipping analyst workbook")
        return None
    # CR-F2: failures present but no data tabs → still emit _Metadata
    logger.warning(
        "ReportComposer.assemble_analyst_workbook: all %d module(s) failed; "
        "writing _Metadata-only workbook with failure audit.", len(failures)
    )
    # fall through to workbook creation with empty collected
```

#### CR-F3: `reports/management_summary.py` L202-240 — "never raises" contract

**Problem:** The fetch + compose block (L225-374) is unguarded. A fetch failure raises out of `run_report()`, violating the "never raises" docstring contract.

**Decision:** Fold into the INT-WARN-1/2 wave (same code path). Wrap the entire fetch/compose block in a try/except and reflect failure in the return dict, matching the existing PDF/Excel fallback pattern (L387-411):
```python
# Existing PDF fallback pattern to mirror:
try:
    pdf_file = output_dir / _PDF_FILENAME
    _render_pdf(bundle["pdf_html"], pdf_file)
    pdf_path = pdf_file
except Exception as exc:
    logger.error("management_summary: PDF generation failed: %s", exc, exc_info=True)
```

#### CR-F4: `delivery/email_sender.py` L487-501 — `prebuilt_charts` no size budget

**Problem:** `prebuilt_charts` (management_summary inline images) attach base64 PNG data with no per-image size check, unlike `email_inline_images`.

**Fix pattern:** Find the existing size-budget helper used for `email_inline_images` in the same file and apply the same check to each `prebuilt_charts` entry before attaching. The cap should respect `MAX_ATTACHMENT_SIZE_MB` (default 25 MB) converted to bytes per image, consistent with the existing helper.

---

### Work-stream D — Module copy / audit-metadata accuracy

#### CR-D1: `reports/modules/aged_vulns_assets_module.py` L115-116

**Problem:** Docstring/PDF copy says "highest percentage / affected DESC, percentage DESC"; actual sort is by `risk_score`.

**Fix:** Update the docstring and any PDF copy at L115-116 to say "highest risk score" / "sorted by risk_score DESC". No logic change.

#### CR-D2: `reports/modules/high_risk_assets_module.py` L117-119

**Problem:** Copy + `get_audit_info()` says "highest percentage" + "Application-tag grouping"; actual is `risk_score` ordering + `Owner` via `extract_owner()`.

**Fix:** Update copy to "highest risk score" and audit info to reference "Owner" grouping via `extract_owner()`. No logic change.

---

### Work-stream E — Test rigor / portability

#### CR-T1: `tests/e2e/test_groups.py` L103

**Fix pattern:** Guard the `_GROUPS[0]` access:
```python
_GROUPS = _load_groups()
if not _GROUPS:
    pytest.skip("No delivery groups configured — skipping e2e group tests")
_first_group = _GROUPS[0]
```

#### CR-T2: `tests/test_consumer_audit.py` L552-555

**Fix pattern:** Change `_PASS_THROUGH_CALLERS` to use `file::function` qualified identifiers instead of bare function names, matching the more specific pattern:
```python
_PASS_THROUGH_CALLERS = {
    "reports/management_summary.py::run_report",
    "reports/board_summary.py::run_report",
    # etc.
}
```

#### CR-T3 + CR-B1 pair: `tests/test_backfill_reconstruction.py` L247-264

**Fix:** Require exact/zero-tolerance match for the add-back row counts. Remove the tolerance slack and assert exact equality:
```python
assert result_count == expected_count, (
    f"open_findings_at add-back: expected {expected_count} rows, got {result_count}. "
    "CR-B1: add-back rows must not be dropped."
)
```

#### CR-T4: `tests/test_backfill_reconstruction.py` L565-588

**Fix:** Assert the expected taper/non-taper month set exists before checking the partial flag:
```python
assert set(produced_months) >= expected_months, (
    f"Taper months not produced: {expected_months - set(produced_months)}"
)
# Then check the flag
```

#### CR-T5: `tests/test_management_summary.py` L550-595

**Fix pattern:** Replace `or`-chain idiom `val or default` with explicit key-existence checks:
```python
# Bad (treats 0 as missing):
result = data.get("count") or 0
# Good:
assert "count" in data, "key 'count' must be present"
result = data["count"]
assert result == 0  # or whatever the expected value is
```

#### CR-T6: `tests/baselines/management_summary_structural_schema.py` L81-102

**Fix:** Make `pdf_page_count` check conditional on WeasyPrint being available and producing a real count (not a heuristic fallback). Pattern: skip or soft-assert when the count comes from the fallback path.

#### CR-T7: `tests/baselines/management_summary_value_golden.json` L4

**Fix:** Replace the hardcoded absolute Windows path in `_meta.fixture_dir` with a repo-relative path (e.g. `"tests/baselines/fixtures"` or `"."`).

---

### Work-stream F — Deploy script

#### CR-U1: `scripts/update_from_github.sh` L327-331 — symlink resolver

**Fix pattern:** Anchor non-absolute symlink targets against `INSTALL_ROOT` only. Extract a resolver helper:
```bash
_resolve_target() {
  local target="$1"
  if [[ "$target" = /* ]]; then
    echo "$target"
  else
    echo "${INSTALL_ROOT}/${target}"
  fi
}
```

#### CR-U2: `scripts/update_from_github.sh` L904-916 — `--force` re-extraction

**Fix pattern:** Refuse `--force` on the active release directory (the one `current` symlink points to), or stage to a temp dir then swap:
```bash
_active=$(readlink -f "${INSTALL_ROOT}/current" 2>/dev/null || true)
if [[ "$_active" == "$_release_dir" ]]; then
  echo "ERROR: --force re-extraction refused on active release ${_active}; rollback would be broken." >&2
  exit 1
fi
```

---

### Work-stream G — Doc / comment cleanup

All G-items are one-line or paragraph text fixes. No pattern extraction needed beyond knowing the file and line.

| ID | File | Lines | Action |
|----|------|-------|--------|
| CR-G1 | `scripts/smoke_management_summary_cutover.py` | L1-7 | Update docstring: remove "old bespoke path"; describe current `result["_bundle"]` shape |
| CR-G2 | `run_all.py` | L94-102 | Delete or update CHROME-COMPAT-01 stale comment (management_summary now accepts chrome kwargs) |
| CR-G3 | `scripts/smoke_email_phase2.py` | L332-346 | Fix `--no-stub-panels` help text: "disables empty-panels stub only, not the legacy KPI path" |
| CR-G4 | `scripts/smoke_email_phase2.py` | L133-139 | Attach inline images that the script already generates as CID panels (same attach pattern as `delivery/email_sender.py` `email_inline_images`) |
| CR-G5 | `docs/trend_and_segmentation_calculations.md` | L182-191 | Separate "unsupported ad-hoc backfill" from "sanctioned `backfill_trend_reconstruction.py` workflow" |
| CR-G6 | `.planning/ROADMAP.md` | L9 | Fold into D-07 closeout: update v1.4 badge from "in progress" to reflect completion |
| CR-G7 | `.planning/STATE.md` | L24-31 | Fold into D-07 closeout: align current-focus summary with phase/status fields |
| CR-G8 | `19-CONTEXT.md` | L66-67 | Already resolved during triage fold (per triage note) |
| CR-G9 | `.planning/phases/18-.../18-VALIDATION.md` | L4-7 | Align status fields + Wave 0 checklist with approved sign-off section |
| CR-G10 | `.planning/milestones/.../13-03-SUMMARY.md` | L65-67 | Fix self-contradictory `enriched_assets` empty-vs-None doc |
| CR-G11 | `.planning/phases/15-.../15-02-SUMMARY.md` | L88-89 | Fix invalid set notation in ACCEPTED/RECASTED example |
| CR-G12 | `.planning/phases/14-.../14-03-PLAN.md` | L139-146 | Fix malformed inline shell check; assert `sc4_kwargs_stub` is in registry |

---

### Work-stream: Deferred review findings (18/17/15-REVIEW)

#### 18-REVIEW WR-04 — `scripts/backfill_trend_reconstruction.py`: dead `_months_in_range` + unused `dateutil`

**Dead symbol:** `_months_in_range` at L189-208 uses `from dateutil.relativedelta import relativedelta` and is superseded by `_months_in_range_stdlib` at L211-228.

**Fix:** Delete `_months_in_range` (L189-208) and remove the `dateutil` import. Replace all call sites with `_months_in_range_stdlib`. This aligns with CLAUDE.md "locked stack" (no new SDK adoption — `dateutil` is not in requirements; its presence is the WR-04 violation).

**Confirm no other callers of `_months_in_range`:**
```
Grep("_months_in_range[^_]", path="D:/Projects/vuln-reporting")
```

#### 18-REVIEW WR-05 — MTD/partial-month delta (in-scope per D-02, location TBD during planning)

**Scope:** The delta computation that attributes partial-month changes should use the same local-time month key convention used by `capture_snapshot`. Exact file/line to be confirmed by the executor reading the relevant delta function.

#### 18-REVIEW WR-06 — `data/trend_store.py` L389-390: local-vs-UTC month attribution

**Already in scope from 18-REVIEW.** The `month_str = date.strftime("%Y-%m")` at L390 is correct (local, per CLAUDE.md). The audit finding is that `date` may arrive as a UTC-aware datetime, causing month-boundary misattribution on non-UTC servers. Fix: convert `date` to local time before strftime:
```python
# WR-06 fix: use local time for month key (CLAUDE.md timezone policy)
_local_date = date.astimezone()  # converts UTC-aware to server-local
month_str = _local_date.strftime("%Y-%m")
```

#### 18-REVIEW WR-07 — corrupt-file rename (fold with CR-B7, same block)

Already covered above under CR-B7.

#### 18-REVIEW WR-08 — `config.py` L95-100: VPR band gap drops ~8.95 to native fallback

**Problem:** `VPR_SEVERITY_MAP` has `(7.0, 8.9, "high")` — the upper bound is 8.9, so scores 8.91–8.99 fall through to `fallback` (native severity) rather than "high".

**Fix:** Close the gap. Change the high-band upper bound from `8.9` to `8.99` (or `< 9.0` logic), matching the intent that Critical starts at 9.0:
```python
VPR_SEVERITY_MAP: list[tuple[float, float, str]] = [
    (9.0, 10.0, "critical"),
    (7.0,  8.99, "high"),    # WR-08: was 8.9; closes the 8.91-8.99 gap
    (4.0,  6.9,  "medium"),
    (0.1,  3.9,  "low"),
]
```

#### 18-REVIEW IN-01 — `config.py` L147: hot-path `import math` inside `vpr_to_severity`

**Fix:** Move `import math` to module-level imports (already present at top of file or add there). Remove the inline `import math` at L147.

#### 18-REVIEW IN-02 — `data/fetchers.py` L163: dead `_first_str`

**`_first_str` definition** (L163): used nowhere else per Grep. Delete it.

#### 18-REVIEW IN-03 — `docs/management_summary_calculations.md`: stale pre-v1.4 sections

**Fix:** Delete or replace sections describing the removed bespoke `_compute_metric_1.._7` / `compute_all_metrics` path. Update to describe the current `ReportComposer.run_full_pipeline()` path.

#### 18-REVIEW IN-04 — `utils/open_count.py`: stale `_OPEN_STATES` docstring reference

**Fix:** The docstring at L49-50 references `management_summary._OPEN_STATES` which no longer exists post-GEN-01 cutover. Update to remove the reference or replace with the current state values `{"open", "reopened"}`.

#### 18-REVIEW IN-05 — `data/trend_store.py`: `capture_snapshot` docstring for owner dimension omits aggregate counts

**Fix:** Extend the docstring to note that `dimension="owner"` does not populate `reopened_count`, `accepted_count`, `recast_count`, etc. (those are severity-dimension fields populated by the caller). No code change.

#### 17-REVIEW WR-01/WR-06 — D-05 SLA-rate NaT denominator bias (3 sites)

**Problem:** `sla_rate_crit_high` computation at all 3 sites divides by `len(ch_df)` where `ch_df` may contain rows with `first_found=NaT`. NaT rows can never enter the numerator (days_open is NaT → `days_open <= sla_days` is False) but they DO inflate the denominator, biasing the rate downward.

**Authoritative computation site** (`scripts/capture_trend_snapshot.py` L390-418):
```python
open_df = open_findings_at(df, snapshot_date)
ch_df = open_df[open_df["severity"].str.lower().isin({"critical", "high"})]

if not ch_df.empty:
    snap_ts = pd.Timestamp(snapshot_date, tz="UTC")
    ff_ts = pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
    days_open = (snap_ts - ff_ts).dt.days.clip(lower=0)
    sla_days_col = ch_df["severity"].str.lower().map(SLA_DAYS)
    within = days_open.notna() & sla_days_col.notna() & (days_open <= sla_days_col)
    sla_rate_crit_high = round(float(within.sum()) / len(ch_df) * 100, 1)
```

**Fix (D-05 shared helper):** Extract a `compute_sla_rate_crit_high(open_df, report_date, sla_days) -> Optional[float]` helper into `utils/sla_calculator.py` (already exists for SLA utilities). The helper must exclude NaT-`first_found` rows from both numerator AND denominator:
```python
def compute_sla_rate_crit_high(
    open_df: pd.DataFrame,
    report_date: datetime,
    sla_days: dict,
) -> Optional[float]:
    """Return % of open Crit+High findings within SLA, NaT-first_found excluded from both."""
    ch_df = open_df[open_df["severity"].str.lower().isin({"critical", "high"})]
    if ch_df.empty:
        return None
    snap_ts = pd.Timestamp(report_date, tz="UTC")
    ff_ts = pd.to_datetime(ch_df["first_found"], utc=True, errors="coerce")
    valid_mask = ff_ts.notna()          # exclude NaT from denominator
    ch_valid = ch_df[valid_mask]
    if ch_valid.empty:
        return None
    days_open = (snap_ts - ff_ts[valid_mask]).dt.days.clip(lower=0)
    sla_days_col = ch_valid["severity"].str.lower().map(sla_days)
    within = days_open.notna() & sla_days_col.notna() & (days_open <= sla_days_col)
    return round(float(within.sum()) / len(ch_valid) * 100, 1)
```

All 3 sites replace their inline SLA-rate logic with a call to this helper.

#### 17-REVIEW WR-02 — `reports/modules/program_health_module.py`: unmapped-severity NaN drop

**Fix:** When building `sla_days_col = ch_df["severity"].str.lower().map(SLA_DAYS)`, unmapped severities produce NaN. The `within` mask already guards with `sla_days_col.notna()` in the shared helper above, so this is automatically fixed once the helper is adopted.

#### 17-REVIEW WR-03 — `reports/modules/program_health_module.py`: `_signal_direction` NaN-as-real

**Fix:** Add `pd.isna()` guard before computing signal direction:
```python
if pd.isna(curr_val) or pd.isna(prev_val):
    direction = "neutral"
else:
    direction = _signal_direction(curr_val, prev_val)
```

#### 17-REVIEW WR-04 — `reports/modules/program_health_module.py`: sparkline `s.get(...,0)` masks missing

**Fix:** Use `s.get(key)` with explicit `None` check instead of `s.get(key, 0)`, so truly-absent data is distinguishable from a legitimate zero.

#### 17-REVIEW WR-05 — `reports/modules/program_health_module.py`: `analyst_df` NaN guard + int-typed metadata miscount

**Fix:** Add `.dropna(subset=[...])` before count operations on the analyst DataFrame, and ensure count fields are cast to `int` not left as numpy int64.

#### 15-REVIEW IN-01 — dead `safe_format` imports in 4 of 5 new modules

**Affected files:** `reopened_vulns_module.py`, `external_dmz_module.py`, `new_vs_remediated_module.py`, `vuln_density_module.py` — all import `safe_format` from `format_utils` but do not call it.

**Pattern to verify:** Read each module's usage of `safe_format` (Grep). If zero call sites, remove from the import line.

**Example clean import block** (from `external_dmz_module.py` L47, which already shows the full import):
```python
from reports.modules.format_utils import safe_format, safe_int, safe_pct
```

If `safe_format` is unused, trim to:
```python
from reports.modules.format_utils import safe_int, safe_pct
```

#### 15-REVIEW IN-02 — dead `_rag_fill` in `reopened_vulns_module.py` and `external_dmz_module.py`

Both files define `_rag_fill` at L76 but do not call it (confirmed by Grep showing the def but no call sites referencing it in the same file). Delete the function body in each affected module.

#### 15-REVIEW IN-03 — dead `_safe_mom_delta` (not found in scan — confirm location during planning)

**Action:** Confirm with `Grep("_safe_mom_delta")` which file(s) define but never call it, then delete.

#### 15-REVIEW IN-04 — unused imports in `reopened_vulns_module.py`

**Confirmed unused** (from Grep showing the import block): verify each import is exercised via a call site Grep. The typical dead imports in Phase 15 modules are module-level `Optional`/`Any` type hints that were replaced by `|` union syntax.

#### 15-REVIEW IN-05 — `capture_snapshot` omits aggregate counts for owner dimension

Already covered by 18-REVIEW IN-05 above (same finding, same fix).

---

## Shared Patterns (cross-cutting)

### Fail-soft pattern
**Source:** `reports/composed_report.py` L239-243 / L255-259; `reports/management_summary.py` L393-411
**Apply to:** All new try/except blocks in this phase (CR-F3, INT-WARN-2, CR-B1, CR-B2)
```python
try:
    ...
except Exception as exc:
    logger.error("context: operation failed: %s", exc, exc_info=True)
    result_var = None   # or safe default
```

### HTML-escape pattern for user/module-supplied strings
**Source:** `reports/modules/scan_coverage_sla_module.py` L851-852; `reports/modules/composer.py` L666-667
**Apply to:** CR-S3 (scan_coverage error box), CR-F1 (composer PDF fallback)
```python
import html
safe_name = html.escape(str(value), quote=True)
```

### Dead-import removal convention
**Source:** `reports/modules/external_dmz_module.py` L36-57 (clean reference import block)
**Apply to:** All 15-REVIEW IN-01..04 dead-import removals
- Remove the specific name from the `from X import A, B, C` line; keep the rest
- If the entire `from X import ...` line becomes unused, remove the line
- Remove any dead function def that is confirmed zero-call-sites

### `capture_snapshot` full-field-set convention
**Source:** `scripts/capture_trend_snapshot.py` L420-432
**Apply to:** INT-WARN-1 fix (management_summary forward-write)
- All optional aggregate fields must be passed by keyword, not positional
- `None` is the correct default for any field the caller cannot supply (explicit null per D-16-09 pattern)

### UTC import pattern
**Source:** `reports/management_summary.py` L45; `reports/composed_report.py` L33
**Apply to:** Any new datetime usage introduced by this phase
```python
from datetime import datetime, timezone
generated_at = datetime.now(tz=timezone.utc)
```

---

## No Analog Found

All 28 files have analogs. This phase has no net-new files — all entries are targeted edits to existing source.

---

## Metadata

**Analog search scope:** `reports/`, `data/`, `utils/`, `tests/`, `scripts/`, `.claude/hooks/`, `config.py`, `run_all.py`, `delivery/`
**Files read for pattern extraction:** 14 source files, targeted sections
**Pattern extraction date:** 2026-06-24
