# Codebase Concerns

**Analysis Date:** 2026-05-04

This document catalogs known and inferred concerns across security, robustness, performance,
operational and deliverables-checklist dimensions for the Vulnerability Management
Reporting Suite. Each entry is structured: **what / where / severity / one-line mitigation**.

---

## Security

### Recast/Accept rules — direct REST call bypasses SDK retry hooks

**What:** `fetch_recast_rules()` builds an `X-ApiKeys` header inline using
`os.getenv("TVM_ACCESS_KEY")` / `TVM_SECRET_KEY`, posts to `/v1/recast/rules/search`
via plain `requests.post`. The SDK's retry/backoff is bypassed and there is no
TLS verification override or timeout-budget logging.
**Where:** `data/fetchers.py:585-636`
**Severity:** low
**Mitigation:** Wrap with the same `tenacity` retry policy used elsewhere or move into a
shared helper that re-uses `tio._session` for consistent auth handling.

### SMTP password loaded at import time, kept in memory for full process lifetime

**What:** `_smtp_cfg()` (called per-send) re-reads env, but `load_dotenv()` runs at module
import. The password sits in `os.environ` for the whole `run_all.py` invocation, accessible
to any imported third-party library that reads env vars. There is no scrub on shutdown.
**Where:** `delivery/email_sender.py:61, 75-85`
**Severity:** low
**Mitigation:** Read SMTP creds via a function and overwrite the env var slot after the
SMTP client logs in, or move to a key vault/credential manager for production.

### `delivery_log.db` contains recipient addresses but `.gitignore` rule is ambiguous

**What:** SQLite audit log stores every recipient list as JSON. `.gitignore` excludes
`*.db / *.sqlite*` globally — fine — but a stray copy under `output/` would also be
caught. Worth confirming. Bigger concern: there is no row-purge schedule, so the
`recipients` column accumulates PII indefinitely.
**Where:** `delivery/delivery_log.py` (full file), `.gitignore:65-67`
**Severity:** low
**Mitigation:** Add a retention policy CLI (e.g. `--purge-older-than 365d`) and document
the file's PII content in README troubleshooting.

### `tenable_client.get_client()` calls `sys.exit(1)` from a library-level function

**What:** Authentication failure aborts the process via `sys.exit(1)` (lines 74, 87, 100,
105, 110). Anything that imports `tenable_client` for testing or UI integration cannot
recover from a transient network blip without restarting.
**Where:** `tenable_client.py:74, 87, 100, 105, 110`
**Severity:** low
**Mitigation:** Raise a typed exception (e.g. `TenableAuthError`) and let `run_all.main()`
catch it — keep `sys.exit` only at the CLI entry point.

### `.env.example` documents real credential variable names but no secret-rotation guidance

**What:** Template shows `TVM_ACCESS_KEY=your_access_key_here` and SMTP password but does
not warn against committing `.env`, document API-key scoping (least-privilege), or note
that the actual `.env` exists at the repo root and contains real keys (we can see it on disk).
**Where:** `.env.example:1-37`, `.env` (present, not read)
**Severity:** med
**Mitigation:** Add a "DO NOT COMMIT" banner and instructions to scope the Tenable API key
to `Vuln View / Asset View / Tag List / Recast Rules Read` only.

### No validation that uploaded SMTP credentials use TLS-required auth

**What:** `_smtp_send` uses `smtp.login()` after `starttls()` but does not verify the TLS
handshake succeeded (no `smtp.has_extn("starttls")` check) and does not pin a server cert.
On a misconfigured firewall a downgrade to plaintext is possible.
**Where:** `delivery/email_sender.py:254-265`
**Severity:** low
**Mitigation:** Add `if not smtp.has_extn("STARTTLS"): raise` between `ehlo` and
`starttls`, and consider explicit `ssl.create_default_context()` for the SSL path.

---

## Robustness — Empty / Filtered Data Handling

### `f"{cov_pct:.1f}%"` will raise on missing scan-coverage data

**What:** Tile 4 builder formats `cov_pct = m2["coverage_pct"]` without a `None` guard.
The `m2` block does have an `error` early-out, but if `_compute_metric_2` returns a dict
with `error` absent and `coverage_pct=None` (e.g. zero licensed assets) this raises
`TypeError: unsupported format string passed to NoneType`.
**Where:** `reports/management_summary.py:1853`
**Severity:** med
**Mitigation:** Mirror the `comp_str` pattern at line 1830 — use the `if v is not None`
guard before `:.1f` formatting.

### `m1["critical"]`, `m1["high"]`, `m1["total"]` formatted with `:,` assume ints

**What:** `f"{crit:,}"` / `f"{high:,}"` / `f"{m1['total']:,}"` and similar across the
email-tile and rich-table renderers will raise on `None`. `_compute_metric_1` is
implemented to always return ints, but if a future edit returns `None` for "no data
matched", the tile renderer will crash mid-email-build (after PDF is already written).
**Where:** `reports/management_summary.py:1816, 1824, 2167-2171, 1843, 1855, 1870`
**Severity:** med
**Mitigation:** Centralise the metric→tile conversion through a `_safe_int_fmt(v)` helper
that falls back to "N/A".

### `_compute_metric_3` (MTTR) divides by `len(valid_mttrs)` only — but other modules guard differently

**What:** `mttr_by_severity_module.py:285` returns `None` when `valid_mttrs` is empty,
but `_compute_metric_3` in `management_summary.py` does not — both code paths exist.
A drift bug.
**Where:** `reports/modules/mttr_by_severity_module.py:285`,
`reports/management_summary.py:_compute_metric_3` (around line 440-450)
**Severity:** low
**Mitigation:** Pick one implementation as canonical and import it from the module rather
than duplicating.

### `[col == value]` filters assume column existence after enrichment

**What:** Several reports do `open_df[open_df["severity"] == sev]` /
`vulns_df[vulns_df["state"].str.lower().isin(...)]` without checking whether the column
exists post-enrichment. If `enrich_vulns_with_assets` ever drops a column due to a
schema mismatch from a future Tenable API change, these raise `KeyError` mid-report.
**Where:**
- `reports/sla_remediation.py:192, 524`
- `reports/executive_kpi.py:196`
- `reports/trend_analysis.py:508`
- `reports/management_summary.py:285, 445, 505, 587, 659`
- `reports/modules/mttr_by_severity_module.py:234`
- `reports/modules/total_vulns_by_severity_module.py:120`
- `reports/patch_compliance.py:231, 255`
**Severity:** low
**Mitigation:** Add a one-time `_assert_columns(df, [...])` helper at the top of each
`_compute_*` function so schema drift surfaces with a clear error.

### `.str.lower()` on `severity_modification_type` will fail on a non-string column

**What:** `open_df["severity_modification_type"].fillna("none").str.upper()` assumes
the column exists and is dtype object. If `vulns_all.parquet` is generated by an older
fetcher (column missing) or pyarrow casts to category, `.str` fails.
**Where:** `reports/management_summary.py:675-678`,
`reports/ops_remediation.py:585`
**Severity:** low
**Mitigation:** Use `if "severity_modification_type" not in df.columns: return zero-result`
guard at the top of these helpers (already done in ops_remediation:585, missing in
management_summary).

### `unscanned_assets._write_summary_tab` total fallback `or 1` masks empty-data state

**What:** `total = metrics["total_assets"] or 1` is used to avoid `ZeroDivisionError`
in the percentage formula, but produces a misleading "0 / 1 = 0.0%" instead of "N/A"
when the deduplication output is empty.
**Where:** `reports/unscanned_assets.py:464, 470`
**Severity:** low
**Mitigation:** Branch on `total == 0` and write "N/A — no licensed assets in scope".

### `vulns_df["resurfaced_date"].notna()` assumes column exists

**What:** Recurring-findings filter checks `vulns_df.empty or "resurfaced_date" not in
vulns_df.columns` (line 792) — good. But the assignment one line later uses
`vulns_df[vulns_df["resurfaced_date"].notna()]` without the guard. Acceptable because
of the early return, but fragile under refactor.
**Where:** `reports/ops_remediation.py:792, 795`
**Severity:** low
**Mitigation:** Combine the guard and filter into one helper to prevent a future
refactor splitting them.

### Recently fixed: `ops_remediation` early return previously skipped `_compute_sla_status`

**What:** Historical bug — empty filter result skipped the SLA-state column creation,
causing downstream Excel/PDF tabs to fail on missing column. Fix is in place
(`reports/ops_remediation.py:216-224`) — empty `df` falls through to
`apply_sla_to_df()` and `_compute_sla_status()`. `_compute_sla_status` itself now
correctly returns an empty DataFrame with the column added (lines 263-266).
**Where:** `reports/ops_remediation.py:216-224, 263-266`
**Severity:** low (resolved — flagged for awareness)
**Mitigation:** Add a regression test that runs the full report against a
no-match tag filter and asserts every output file is produced.

### Recently fixed: `management_summary._compute_metric_6` ZeroDivisionError on `exception_rate`

**What:** Historical bug — `exception_rate = open_exceptions / total_open * 100` raised
when `total_open == 0`. Fix is in place (lines 662-669 short-circuit and return
`exception_rate=None`).
**Where:** `reports/management_summary.py:662-669`
**Severity:** low (resolved — flagged for awareness)
**Mitigation:** Same regression-test recommendation as above.

---

## Performance

### `enrich_vulns_with_assets` runs once per report, not once per group

**What:** Every report in a group (`executive_kpi`, `sla_remediation`, `asset_risk`,
`patch_compliance`, `trend_analysis`, `plugin_cve`, `ops_remediation`, `vuln_export`,
`management_summary`) re-runs the left-join independently. For a 180k-row vuln frame
× 9 reports that's 9 left-joins per group. Logs (`enrich_vulns_with_assets:
180000/180000 vuln rows matched...`) confirm the repeated work.
**Where:**
`reports/executive_kpi.py:122`, `reports/sla_remediation.py:149`,
`reports/asset_risk.py:139`, `reports/patch_compliance.py:149`,
`reports/trend_analysis.py:179`, `reports/plugin_cve.py:133`,
`reports/ops_remediation.py:209`, `reports/vuln_export.py:437`,
`reports/management_summary.py:2336, 2340, 2578, 2582`
**Severity:** med
**Mitigation:** Cache the enriched frame in the run-scoped `cache_dir` (e.g.
`vulns_all_enriched.parquet`) on first call, or pass it as a kwarg from
`run_group()` so each report receives the already-joined frame.

### `management_summary` runs `enrich_vulns_with_assets` four times in one report

**What:** Lines 2336, 2340, 2578, 2582 each call `enrich_vulns_with_assets` — twice
on `vulns_raw` and twice on `fixed_raw`. Two of those four calls are inside the
`__main__` block (review CLI), but the report's normal path still does it twice
per run.
**Where:** `reports/management_summary.py:2336, 2340, 2578, 2582`
**Severity:** med
**Mitigation:** Compute once at top of `run_report()` and pass the enriched frames
through to all `_compute_metric_N` helpers.

### Per-day cache scheme deletes prior days unconditionally on every batch

**What:** `run_all.main()` iterates `CACHE_DIR.iterdir()` and `shutil.rmtree`s every
folder that isn't today's local-time folder, on every invocation. A run started just
before midnight followed by a run after midnight will pay the full Tenable export cost
twice (the first run's cache is wiped). On a cron-driven setup with `*/10` cadence
crossing midnight, this hits the API ~6× harder than necessary.
**Where:** `run_all.py:870-877`
**Severity:** med
**Mitigation:** Keep the last 24 hours' worth of caches (compare folder mtime, not
just name) or skip the wipe when the only stale folder is < 6h old.

### Cache key uses local-machine date instead of UTC

**What:** `cache_dir = CACHE_DIR / datetime.now().strftime("%Y-%m-%d")` (local time)
while `generated_at` uses `datetime.now(tz=timezone.utc)`. A scheduled run at 23:30 EDT
writes to one folder; the next run at 04:00 UTC the same calendar day in UTC writes
to a different folder. Reports that depend on a stable cache across the boundary will
re-fetch.
**Where:** `run_all.py:486-487, 864-867`
**Severity:** low
**Mitigation:** Standardise on UTC for the cache directory (or document that local
time is intentional and matches the operator's timezone).

### `fetch_all_vulnerabilities` builds the full row list in memory before parquet write

**What:** The export streams via `tio.exports.vulns()` but every record is appended
to a single `rows: list[dict]` and converted to a DataFrame at the end (line 329).
For 180k+ rows × ~30 fields including string CVE lists, peak memory > 1.5 GB.
**Where:** `data/fetchers.py:243, 329`, `data/fetchers.py:374, 443`
**Severity:** low
**Mitigation:** Stream-write to parquet in 50k-row chunks via `fastparquet.write` with
`append=True`.

### `exports.vulns(severity=...)` always re-pulls Critical/High/Medium/Low even when only one needed

**What:** Both `fetch_all_vulnerabilities` and `fetch_fixed_vulnerabilities` pass the
full severity list even though the most common consumer (`vuln_export`) only uses three
of those four. The savings are small but the pattern means a future "Critical-only" use
case can't shortcut the export.
**Where:** `data/fetchers.py:240, 372`
**Severity:** low
**Mitigation:** Push severity filter into `filter_by_severity()` only — leave the export
unscoped so the cache is reusable across all report severities.

---

## Operational

### Tag value typos break filters silently

**What:** `filter_by_tag` does case-insensitive substring match on `Category=Value`. A
typo like `Configuration Mangement` vs `Configuration Management` matches no rows; the
report runs to completion with empty data and no "tag value not found" error. Operators
have already encountered this in production.
**Where:** `data/fetchers.py:694-750`
**Severity:** med
**Mitigation:** Cross-check the tag against `fetch_tags(tio).value` once at startup and
raise a clear "tag X=Y not present in this Tenable instance — closest matches: …" error.

### Single-config-file failure mode

**What:** `delivery_config.yaml` is a single file with no schema validation at
runtime — `delivery_config.schema.yaml` exists but `jsonschema` is in `requirements.txt`
and never imported anywhere. A typo in `frequency: weeky` is caught only by
`_validate_group()`, which runs only under `--dry-run`. A scheduled run with a malformed
group skips that group with a logged error but the operator is not alerted.
**Where:** `run_all.py:241-318`, `delivery_config.schema.yaml`, `requirements.txt:39`
**Severity:** med
**Mitigation:** Wire `jsonschema.validate(raw_yaml, schema)` into `_load_config()` so
every invocation validates and exits non-zero on malformed input.

### `delivery_config.yaml` has no atomic-update strategy

**What:** Daemon mode hot-reloads `delivery_config.yaml` every 5 minutes. A partial
write by an editor (open + save in two steps) can be parsed mid-write, leaving the
daemon with a stale or malformed config until the next reload.
**Where:** `scheduler.py` (daemon mode reload logic)
**Severity:** low
**Mitigation:** Read with `os.replace`-style atomicity check — verify file mtime
stable for ≥ 1 reload cycle before applying changes.

### `delivery_config.yaml` is `.gitignored`

**What:** `.gitignore:13` excludes the active config file. Operators editing on the
production host have no version control. Combined with the hot-reload behavior, an
edit-and-save mistake has no rollback.
**Where:** `.gitignore:13`, `delivery_config.yaml`
**Severity:** low
**Mitigation:** Track a sanitized `delivery_config.yaml.example` in git and document a
`config-versioned/` folder under operator control for actual-config history.

### Timezone mismatch — UTC report timestamps vs local cache folder names

**What:** `generated_at = datetime.now(tz=timezone.utc)` for report metadata but
cache folder uses `datetime.now()` (local). On 11pm-EDT runs the report is dated
03:00 UTC the next day while the cache is in yesterday's folder.
**Where:** `run_all.py:486-489, 864-867`
**Severity:** low
**Mitigation:** Pick one timezone and document the choice in CLAUDE.md (already
mentions this — but the reasoning isn't reflected back into code paths that mix the two).

### App log rotation is missing for the main `app.log`

**What:** `scheduler.py` uses `RotatingFileHandler` (10 MB × 5) but `run_all.py:746`
uses a plain `FileHandler` writing to `logs/app.log` indefinitely. Long-lived
deployments will grow the file without bound.
**Where:** `run_all.py:744-762`, `tenable_client.py:29-36`
**Severity:** med
**Mitigation:** Use `RotatingFileHandler` everywhere (or have all entry points share
one logging-setup helper).

### Diagnostic logs leak filtered tag samples

**What:** `filter_by_tag` logs `Sample values: %s` (line 740) — the first 5
`Category=Value` strings. If sensitive tag values exist (e.g. project codenames,
customer IDs in tags), they end up in `logs/app.log`. Low risk but worth flagging.
**Where:** `data/fetchers.py:735-741`
**Severity:** low
**Mitigation:** Move that diagnostic to DEBUG-level only or redact the values.

### `run_all.py` re-instantiates `TenableIO` once per group via `tenable_client.get_client`

**What:** `run_all.main()` creates one client and passes it through (line 850) — good.
But each `run_group()` re-checks for `tio is None` and could create a fresh one if
called from another path (`scheduler.py daemon mode`), so the connection isn't
guaranteed to be reused. Each `get_client()` call also performs a `server.status()`
validation request — adds ~500ms per group.
**Where:** `run_all.py:512-518`, `tenable_client.py:116-137`
**Severity:** low
**Mitigation:** Make `get_client()` cache its result on the module level
(simple `_singleton_client` pattern) so all callers share the same authenticated client.

### Stale `sys.modules` cleanup in `run_all.py` is fragile

**What:** Lines 62-64 unconditionally `del sys.modules[k]` for any cached entry
matching `reports.*` / `data.*` / `utils.*`. If `run_all` is imported multiple times
(e.g. tests), this clobbers any test-only mocks installed in those namespaces.
**Where:** `run_all.py:62-64`
**Severity:** low
**Mitigation:** Gate this behind a "first-import" sentinel or move it to a function
that only runs from the `__main__` entry path.

---

## Deliverables Checklist — Reality Check

Cross-checking the CLAUDE.md "Deliverables Checklist" against what actually exists on disk
as of 2026-05-04:

### Items the checklist marks unchecked but **DO exist**

| Checklist item | Status on disk |
|---|---|
| `tenable_client.py` | EXISTS — `tenable_client.py` (4.5KB) |
| `utils/sla_calculator.py` | EXISTS — `utils/sla_calculator.py` |
| `utils/tag_helper.py` | EXISTS — `utils/tag_helper.py` |
| `utils/formatters.py` | EXISTS — `utils/formatters.py` |
| `exporters/excel_exporter.py` | EXISTS — `exporters/excel_exporter.py` |
| `exporters/pdf_exporter.py` | EXISTS — `exporters/pdf_exporter.py` |
| `exporters/chart_exporter.py` | EXISTS — `exporters/chart_exporter.py` |
| `reports/executive_kpi.py` | EXISTS |
| `reports/sla_remediation.py` | EXISTS |
| `reports/asset_risk.py` | EXISTS |
| `reports/patch_compliance.py` | EXISTS |
| `reports/trend_analysis.py` | EXISTS |
| `reports/plugin_cve.py` | EXISTS |
| `delivery/email_sender.py` | EXISTS |
| `delivery/email_template.py` | EXISTS |
| `templates/report_email.html` | EXISTS |
| `delivery/delivery_log.py` | EXISTS |
| `scheduler.py` | EXISTS — daemon + run-due + manual |
| `deploy/vuln-reports.service` | EXISTS |
| `requirements.txt` | EXISTS |
| `.env.example` | EXISTS |

**Severity:** med
**What:** The checklist in `CLAUDE.md` is materially out of date — it advertises ~21
"unbuilt" items that are in fact built. Future contributors using the checklist as a
roadmap waste time re-implementing existing modules.
**Where:** `CLAUDE.md` "Deliverables Checklist" section
**Mitigation:** Tick off the existing items, or replace the checklist with a "live
component map" that is generated/checked by CI.

### Items still legitimately missing

| Checklist item | Notes |
|---|---|
| `README.md` | Not present at repo root — only `CLAUDE.md` and `RUNBOOK.MD` |

**Severity:** low
**Mitigation:** Add a slim `README.md` pointing to `CLAUDE.md` / `RUNBOOK.MD` for
onboarding.

### Items present but not on the checklist

These exist on disk and are referenced by the runtime, but were never added to the
"Deliverables Checklist":

- `reports/duplicate_assets.py` — companion analysis report (not in `_VALID_REPORTS`)
- `reports/modules/example_module.py` — appears to be a dev scaffold
- `reports/modules/total_vulns_by_severity_module.py`,
  `patch_compliance_rate_module.py`, `mttr_by_severity_module.py` — used by
  `management_summary` but not listed as separate deliverables
- `tests/` directory contains diagnostic scripts (`analyze_untagged_assets.py`,
  `diagnose_*.py`, `validate_workstation_rules.py`, `test_modules_level1.py`,
  `test_modules_level2.py`) — but `.gitignore:60` excludes `tests/`, so any pytest
  CI integration using these will be silently dropped from version control.

**Severity:** low
**Mitigation:** Decide whether `tests/` should be committed; if yes, remove from
`.gitignore`. Document `duplicate_assets.py` and `example_module.py`.

### Logs / debug artefacts present in working tree

- `logs/debug_fetch.txt` (untracked, fine)
- `tests/debug_asset_vulns_raw.json`, `tests/debug_fetch2.txt`,
  `tests/debug_parquet_roundtrip.parquet` — debug artefacts in the tests folder

**Severity:** low
**Mitigation:** Move debug captures to a `scratch/` folder that's `.gitignored`, or
delete on next cleanup pass.

---

*Concerns audit: 2026-05-04*
