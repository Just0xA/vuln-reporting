---
phase: quick-260813-jaz
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - reports/ops_remediation.py
  - tests/test_ops_risk_accepted_suppression.py
  - docs/GLOSSARY.md
  - CLAUDE.md
autonomous: true
requirements: [QUICK-260813-jaz]

must_haves:
  truths:
    - "ops_remediation actionable metrics (open counts, SLA states, Plugins, Overdue/Urgent, exploitability, top-5 priority, recurring) exclude ACCEPTED findings"
    - "RECASTED findings REMAIN in the ops actionable worklist at their recast severity"
    - "An ACCEPTED finding whose recast rule expires_at < report date flows BACK into the actionable metrics"
    - "ACCEPTED findings on rules with null/absent/'Never' expires_at stay suppressed"
    - "When recast_rules_df is None/empty/malformed, all ACCEPTED rows are suppressed and a warning is logged (never crash, never lose the suppression)"
    - "Tab 5 'Risk Acceptances & Recasts' and the count_risk_* summary tiles still read the FULL unsuppressed population"
    - "The Summary-sheet label and Report Info tab text accurately describe ACCEPTED-only suppression plus the expiry carve-out"
  artifacts:
    - path: "reports/ops_remediation.py"
      provides: "_suppress_risk_accepted() helper + single application point in run_report()"
      contains: "def _suppress_risk_accepted"
    - path: "tests/test_ops_risk_accepted_suppression.py"
      provides: "8 behavior groups incl. the must-not-change regression guard"
      contains: "_suppress_risk_accepted"
  key_links:
    - from: "reports/ops_remediation.py::run_report"
      to: "_suppress_risk_accepted"
      via: "vulns_actionable = _suppress_risk_accepted(vulns_scanned, recast_rules_df, generated_at)"
      pattern: "vulns_actionable = _suppress_risk_accepted"
    - from: "reports/ops_remediation.py::run_report"
      to: "_extract_risk_modifications"
      via: "still passed the UNFILTERED vulns_scanned"
      pattern: "_extract_risk_modifications"
---

<objective>
Operations reported that risk-accepted vulnerabilities still appear in `ops_remediation` metrics. They do: `reports/ops_remediation.py` applies no risk-managed filter anywhere, yet the workbook already *claims* the suppression happens (Summary row label L1407, Report Info tab text L1497) — which is why the numbers were trusted.

Fix: add ONE ACCEPTED-only, expiry-aware suppression helper inside `reports/ops_remediation.py`, apply it ONCE in `run_report()` to produce an actionable frame, feed that frame to every actionable metric, and keep the unfiltered frame for the "Risk Acceptances & Recasts" surface. Then make the two false claims true.

Purpose: correctness — Operations' worklist must not contain work they formally accepted, while still containing recasts (still their work, only the tier changed) and re-surfacing acceptances whose rule has expired.
Output: helper + wiring + new test file + accurate in-workbook wording + glossary/CLAUDE.md notes.

The approach is DECIDED (see `<locked_decisions>` below) — do not re-investigate, do not offer alternatives, do not reuse `exclude_risk_managed()` as-is.
</objective>

<execution_context>
@/home/jmonroe/.claude/plugins/cache/gsd-plugin/gsd/4.0.2/workflows/execute-plan.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md

<locked_decisions>
D-01 — **ACCEPTED only, NOT RECASTED.** Suppress only `severity_modification_type == "ACCEPTED"`. RECASTED findings STAY in the actionable worklist at their recast severity: a recast is still open work Operations owns, only the tier changed. This deliberately DIVERGES from `reports/modules/board_report_utils.py::exclude_risk_managed()`, which drops BOTH. Rationale to preserve in the docstring: the Summary sheet already lists "Accepted Findings (suppressed from counts)" and "Recast Findings (severity changed)" as two distinct lines — ACCEPTED-only matches the report's original design intent.

D-02 — **Expired acceptances return to the actionable metrics.** An ACCEPTED finding whose Tenable recast rule has `expires_at < report date` is NO LONGER suppressed. Join `recast_rule_uuid` (findings) against `rule_id` / `expires_at` (`fetch_recast_rules()` output, already fetched in `run_report()` as `recast_rules_df`). Rules with null / absent / `"Never"` / unparseable `expires_at` never expire and stay suppressed. Graceful degradation REQUIRED: if `recast_rules_df` is None/empty/malformed, suppress ALL ACCEPTED rows and log a warning — never crash, never silently drop the suppression entirely.

D-03 — **Single-variant.** No second report slug, no `include_risk_managed` option, no new YAML field. Unlike `board_summary` (quick-260813-ga2), ops gets one behavior.
</locked_decisions>

<interfaces>
Extracted from the codebase — use directly, no exploration needed.

`reports/ops_remediation.py::run_report()` — the sole application point. Current shape (line numbers as of HEAD):
```
2694    recast_rules_df = fetch_recast_rules(tio, cache_dir)
2696    scanned_df, unscanned_df = _identify_unscanned_assets(assets_df, as_of=generated_at)
2698    scanned_ids   = set(scanned_df["asset_uuid"])
2699    vulns_scanned = vulns_df[vulns_df["asset_uuid"].isin(scanned_ids)]
2701    plugin_df = _group_by_plugin(vulns_scanned)
2703-2711  _compute_summary_metrics(vulns_df=vulns_scanned, ...)
2713    _compute_exploitability_metrics(vulns_scanned)
2718    _get_top_priority_plugins(vulns_scanned)
2721-2727  _extract_risk_modifications(vulns_df=vulns_scanned, assets_df, recast_rules_df, as_of, cache_dir)
2728-2731  _extract_recurring_vulnerabilities(vulns_df=vulns_scanned, assets_df)
2772    overdue_df = _enrich_with_assets(vulns_scanned[vulns_scanned["ops_sla_status"] == OPS_SLA_OVERDUE])
2798    urgent_df  = _enrich_with_assets(vulns_scanned[vulns_scanned["ops_sla_status"] == OPS_SLA_URGENT])
```
`generated_at` is tz-aware UTC (`datetime.now(tz=timezone.utc)`).

`data/fetchers.py::fetch_recast_rules()` return schema (NO `asset_uuid`):
    rule_id, rule_name, plugin_id, action, new_severity, original_severity, expires_at, created_at

Existing expiry cross-check to mirror — `reports/modules/accepted_recast_module.py` L245-269 ("Pitfall 6a"):
```python
expired_mask = (
    recast_rules_df["expires_at"].notna()
    & (pd.to_datetime(recast_rules_df["expires_at"], utc=True) < today)
)
expired_ids = set(recast_rules_df.loc[expired_mask, "rule_id"])
if expired_ids and "recast_rule_uuid" in accepted_df.columns:
    accepted_df = accepted_df[~accepted_df["recast_rule_uuid"].isin(expired_ids)]
```

Existing "Never" sentinel handling already in `reports/ops_remediation.py` (L682, L693) — `expires_at` can arrive as `None`, `""`, or the literal string `"Never"`.

The shared helper you must NOT reuse — `reports/modules/board_report_utils.py:322`:
```python
def exclude_risk_managed(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "severity_modification_type" not in df.columns:
        return df
    mod = df["severity_modification_type"].astype(str).str.upper()
    return df[~mod.isin(["ACCEPTED", "RECASTED"])].copy()
```
It drops BOTH types and has no expiry awareness. D-01/D-02 require different behavior.

`reports/ops_remediation.py` module conventions: `from __future__ import annotations`, module-level `logger = logging.getLogger(__name__)` (L145), NumPy-style docstrings, full type hints, private helpers prefixed `_`.

Test convention (`tests/test_kpi_risk_managed_exclusion.py` header): module docstring listing synthetic-data guarantees, `pd.options.mode.copy_on_write = True` before importing report modules, UUIDs of the form `00000000-0000-0000-0000-00000000000N`, plugin_ids `100001+`.
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Add _suppress_risk_accepted() helper + unit tests for behaviors 1-7</name>
  <files>reports/ops_remediation.py, tests/test_ops_risk_accepted_suppression.py</files>
  <behavior>
    1. ACCEPTED rows are dropped from the returned frame
    2. RECASTED rows are KEPT (D-01)
    3. ACCEPTED row whose recast_rule_uuid matches a rule with expires_at in the past is KEPT (D-02)
    4. ACCEPTED row whose rule has expires_at in the future is DROPPED
    5. ACCEPTED row whose rule has expires_at of None / NaT / "" / "Never" / unparseable is DROPPED (never expires)
    6. Empty frame -> returned unchanged, no raise. Frame missing "severity_modification_type" -> returned unchanged, no raise. Frame missing "recast_rule_uuid" -> all ACCEPTED dropped, no raise, warning logged
    7. recast_rules_df is None / empty DataFrame / DataFrame missing rule_id or expires_at -> all ACCEPTED dropped, warning logged, no raise
    Plus: rows with "NONE" / "" / None / other modification values are always KEPT; the returned frame is a fresh .copy(); matching is case-insensitive ("accepted", "Accepted", "ACCEPTED")
  </behavior>
  <action>
Add a new private helper to `reports/ops_remediation.py`. Place it immediately BEFORE `_extract_risk_modifications` (currently L547) under a new banner comment block matching the file's existing `# ====` section-header style, titled to make the divergence obvious, e.g. `# Risk-accepted suppression (ACCEPTED only — NOT recast; see quick-260813-jaz)`.

Signature: `def _suppress_risk_accepted(vulns_df: pd.DataFrame, recast_rules_df: Optional[pd.DataFrame], as_of: datetime) -> pd.DataFrame:`

Naming is load-bearing: the name must say ACCEPTED, not "risk-managed", so no future reader assumes parity with `exclude_risk_managed()`. Write a NumPy-style docstring (Parameters / Returns / Notes) that states, in this order: (a) it suppresses ONLY `ACCEPTED`, and RECASTED findings deliberately REMAIN because a recast is still open work Operations owns — only the tier changed (D-01); (b) it deliberately does NOT reuse `reports.modules.board_report_utils.exclude_risk_managed`, which drops both types and has no expiry awareness; (c) expired acceptances return to the actionable population (D-02); (d) degradation behavior when rules are unavailable.

Body, in order:

1. Guard (Hard Rule 6): `if vulns_df.empty or "severity_modification_type" not in vulns_df.columns:` -> `logger.debug(...)` and `return vulns_df` unchanged.
2. `mod = vulns_df["severity_modification_type"].astype(str).str.upper()`; `accepted_mask = mod == "ACCEPTED"`. If `not accepted_mask.any()` -> log at debug and `return vulns_df` unchanged.
3. Normalise `as_of`: `as_of_utc = as_of if as_of.tzinfo is not None else as_of.replace(tzinfo=timezone.utc)`; compare against `pd.Timestamp(as_of_utc)`.
4. Build `expired_ids: set[str]`:
   - If `recast_rules_df is None or recast_rules_df.empty or not {"rule_id", "expires_at"}.issubset(recast_rules_df.columns)`: `expired_ids = set()` and `logger.warning("[%s] Recast rules unavailable or malformed — suppressing ALL %d ACCEPTED findings without an expiry cross-check.", REPORT_NAME, int(accepted_mask.sum()))`.
   - Else: `_exp = pd.to_datetime(recast_rules_df["expires_at"], utc=True, errors="coerce")` (this is what turns `None` / `""` / `"Never"` / unparseable into `NaT` == never expires, satisfying behavior 5); `_expired = _exp.notna() & (_exp < pd.Timestamp(as_of_utc))`; `expired_ids = {str(v).strip() for v in recast_rules_df.loc[_expired, "rule_id"] if str(v).strip() and str(v).strip().lower() != "nan"}`.
5. Compute `suppress_mask`:
   - Start `suppress_mask = accepted_mask`.
   - If `expired_ids`: if `"recast_rule_uuid" in vulns_df.columns`, build `_uuid = vulns_df["recast_rule_uuid"].fillna("").astype(str).str.strip()` and set `suppress_mask = accepted_mask & ~_uuid.isin(expired_ids)`; else `logger.warning(...)` that the findings frame has no `recast_rule_uuid` column so the expiry carve-out cannot be applied, and leave `suppress_mask = accepted_mask`.
6. `logger.info("[%s] Risk-accepted suppression | accepted=%d | suppressed=%d | returned_by_expiry=%d | recast_kept=%d", REPORT_NAME, int(accepted_mask.sum()), int(suppress_mask.sum()), int(accepted_mask.sum() - suppress_mask.sum()), int((mod == "RECASTED").sum()))`.
7. `return vulns_df[~suppress_mask].copy()` — boolean-mask filter then `.copy()`, never `df["col"] = ...` (Hard Rule 5).

Do NOT import `exclude_risk_managed`. Do NOT change `_extract_risk_modifications` or any other existing function in this task.

Create `tests/test_ops_risk_accepted_suppression.py`. Module docstring lists the synthetic-data guarantee (Hard Rule 2: `00000000-0000-0000-0000-00000000000N` asset UUIDs, `11111111-...-00000000000N` rule UUIDs, plugin_ids `100001+`, plugin names like `"Synthetic Plugin A"` — NO real hostnames/IPs/CVEs/plugin names/Tenable UUIDs). Set `pd.options.mode.copy_on_write = True` at module top BEFORE `from reports.ops_remediation import _suppress_risk_accepted`. Add a small fixture builder returning a findings frame with columns `asset_uuid, plugin_id, plugin_name, severity, severity_modification_type, recast_rule_uuid, state, first_found` and a rules-frame builder with `rule_id, expires_at`. Cover behaviors 1-7 above plus the case-insensitivity, "other value kept", and fresh-`.copy()` assertions. Use `caplog` (pytest builtin) to assert the warning fires for behavior 7 and for the missing-`recast_rule_uuid` path. Assert no `ChainedAssignmentError` / CoW warning is emitted (`pytest.warns(None)` is removed in modern pytest — instead use `warnings.catch_warnings(record=True)` filtered to the `reports.ops_remediation` source path, mirroring the fixture-isolation approach noted in STATE.md Phase 16-03).
  </action>
  <verify>
    <automated>python -m pytest tests/test_ops_risk_accepted_suppression.py -x -q && grep -q "def _suppress_risk_accepted" reports/ops_remediation.py && ! grep -q "exclude_risk_managed" reports/ops_remediation.py</automated>
  </verify>
  <done>`_suppress_risk_accepted` exists in `reports/ops_remediation.py` with an ACCEPTED-only + expiry-aware body; all 7 behavior groups pass; `exclude_risk_managed` is NOT imported; no CoW warnings.</done>
</task>

<task type="auto">
  <name>Task 2: Wire the actionable frame through run_report() (+ CLI smoke block) and add the must-not-change regression guard</name>
  <files>reports/ops_remediation.py, tests/test_ops_risk_accepted_suppression.py</files>
  <action>
In `run_report()` (`reports/ops_remediation.py`), immediately after `vulns_scanned = vulns_df[vulns_df["asset_uuid"].isin(scanned_ids)]` (L2699) insert a new binding `vulns_actionable = _suppress_risk_accepted(vulns_scanned, recast_rules_df, generated_at)`, preceded by a short comment block stating: the actionable worklist is the scanned findings minus UNEXPIRED risk acceptances (ACCEPTED only — recasts stay; cross-reference `_suppress_risk_accepted` / quick-260813-jaz), and that `vulns_scanned` stays UNFILTERED for `_extract_risk_modifications` (Tab 5), which must keep reporting the full accepted+recast population.

Then swap `vulns_scanned` -> `vulns_actionable` at EXACTLY these call sites:
  - L2701 `_group_by_plugin(vulns_scanned)`
  - L2704 `_compute_summary_metrics(vulns_df=vulns_scanned, ...)`
  - L2713 `_compute_exploitability_metrics(vulns_scanned)`
  - L2718 `_get_top_priority_plugins(vulns_scanned)`
  - L2729 `_extract_recurring_vulnerabilities(vulns_df=vulns_scanned, ...)`
  - L2772 `overdue_df` slice — both occurrences on the line
  - L2798 `urgent_df` slice — both occurrences on the line

LEAVE UNCHANGED (must-not-change surface):
  - L2722 `_extract_risk_modifications(vulns_df=vulns_scanned, ...)` — keeps the FULL population so Tab 5 "Risk Acceptances & Recasts" still shows what was suppressed and why.
  - The `summary["count_risk_accepted"] / count_risk_recast / count_expiring_soon / count_expired` tiles (L2733-2745) — they derive from `risk_mods_df`, so they are unaffected by construction. Verify this rather than assume it; do not touch those lines.
  - `_identify_unscanned_assets` / `unscanned_df` (assets-only, no findings involved).

`plugin_df`, `summary`, the PDF, and the email-summary body all derive from the above call sites, so the PDF/email numbers follow automatically — no separate edits in `_build_pdf` / `_build_email_summary` / `_kpi_html`.

Apply the SAME edit to the `if __name__ == "__main__":` smoke block so a manual operator run does not diverge from the scheduled run: after `_vulns_scanned = _vulns_df[...]` (L2908) add `_vulns_actionable = _suppress_risk_accepted(_vulns_scanned, _recast_rules_df, _as_of)`, and swap `_vulns_scanned` -> `_vulns_actionable` at L2910, L2913, L2922, L2927, L2938, L2993 (both occurrences), L3020 (both occurrences), leaving L2931 `_extract_risk_modifications(vulns_df=_vulns_scanned, ...)` unchanged. `_recast_rules_df` is already fetched at L2903. Do NOT run this block (Hard Rule 1 — live pull, blocked by the PreToolUse hook); it is edited for consistency only.

Extend `tests/test_ops_risk_accepted_suppression.py` with behavior 8 — the regression guard on the must-not-change surface. Two complementary checks:

  (a) Behavioral: call `_extract_risk_modifications(vulns_df=<full synthetic frame containing both ACCEPTED and RECASTED rows>, assets_df=..., recast_rules_df=..., as_of=...)` and assert the returned frame still contains BOTH an `"Accepted"` and a `"Recast"` row for the suppressed plugins — i.e. it is unaffected by the new helper. Additionally assert that feeding it the `_suppress_risk_accepted()` output would yield strictly fewer rows, proving the wiring choice is load-bearing.

  (b) Structural (source-level wiring guard, since a live `run_report()` call is impossible under Hard Rule 1): use `inspect.getsource(reports.ops_remediation.run_report)` and assert — `"vulns_actionable = _suppress_risk_accepted(vulns_scanned, recast_rules_df, generated_at)"` appears exactly once; `"_extract_risk_modifications("` is followed (within the next few lines of the sliced source) by `vulns_df        = vulns_scanned`; and each of `_group_by_plugin(`, `_compute_exploitability_metrics(`, `_get_top_priority_plugins(`, `_extract_recurring_vulnerabilities(` is called with `vulns_actionable` and never with `vulns_scanned`. Keep the assertions tolerant of whitespace (normalise runs of spaces) so cosmetic reformatting does not break the test, but strict about which identifier reaches which callee. Mirror the structural-guard style already used in `tests/test_consumer_audit.py`.
  </action>
  <verify>
    <automated>cd /home/jmonroe/projects/vuln-reporting && python -m pytest tests/test_ops_risk_accepted_suppression.py -x -q && python - <<'PY'
import inspect, re
import reports.ops_remediation as m
s = inspect.getsource(m.run_report)
assert s.count("vulns_actionable = _suppress_risk_accepted(") == 1, "helper not applied once"
assert re.search(r"_extract_risk_modifications\([^)]*vulns_scanned", s, re.S), "Tab 5 must keep the unfiltered frame"
for fn in ("_group_by_plugin(", "_compute_exploitability_metrics(", "_get_top_priority_plugins("):
    assert fn + "vulns_actionable" in s.replace(" ", "").replace(fn.replace(" ",""), fn), fn
print("wiring ok")
PY</automated>
  </verify>
  <done>`run_report()` computes `vulns_actionable` once and feeds it to all seven actionable-metric surfaces; `_extract_risk_modifications` and the `count_risk_*` tiles still read the full population; the CLI smoke block matches; behavior-8 regression guard passes.</done>
</task>

<task type="auto">
  <name>Task 3: Make the in-workbook claims accurate + glossary/CLAUDE.md, then run the full suite</name>
  <files>reports/ops_remediation.py, docs/GLOSSARY.md, CLAUDE.md</files>
  <action>
1. `reports/ops_remediation.py` L1407 (`_build_summary_sheet`, Risk Management section) — the label `"Accepted Findings (suppressed from counts)"` is now true but incomplete. Change it to `"Accepted Findings (suppressed unless expired)"`. Leave the adjacent `"Recast Findings (severity changed)"` row untouched — it correctly signals that recasts are NOT suppressed. Do not change the values, fills, or row ordering.

2. `reports/ops_remediation.py` L1497 (`_extend_metadata_tab`, Report Info tab -> "Risk Acceptances & Recasts" description) — replace the sentence `"Accepted findings are suppressed from open vuln counts."` with wording that states the exact population an auditor is looking at, covering all three facts: ACCEPTED findings are suppressed from the actionable counts (Summary, Plugins, Overdue Detail, exploitability, priority plugins, recurring); RECAST findings are NOT suppressed and remain in those counts at their recast severity; and an acceptance whose rule has EXPIRED is no longer suppressed and returns to the actionable counts. Note that this tab itself reports the FULL accepted+recast population regardless of suppression. Keep the surrounding sentences about expiration dates / red+orange highlighting intact and keep the tuple's prose style.

3. Update the `ops_remediation` module docstring at the top of `reports/ops_remediation.py` with a one-line note on the ACCEPTED-only suppression rule and the expiry carve-out, matching the docstring's existing bullet/section style.

4. `docs/GLOSSARY.md` — the existing "## Risk-managed finding" entry (L46-48) already describes the board's both-types `exclude_risk_managed()` convention. Append to that entry (do NOT create a competing term) a sentence stating that `ops_remediation` deliberately diverges: it suppresses ONLY `ACCEPTED` (via `_suppress_risk_accepted()` in `reports/ops_remediation.py`), keeps `RECASTED` in the actionable worklist because a recast is still open work at a changed tier, and un-suppresses acceptances whose rule `expires_at` has passed — so "risk-managed" (board) and "risk-accepted" (ops) are NOT interchangeable populations. Reference quick-260813-jaz.

5. `CLAUDE.md` — in the "Report Scripts — Slug Index" table, `ops_remediation` row, Notes cell: append `Suppresses unexpired ACCEPTED findings from actionable metrics (recasts kept).` to the existing `Overdue by plugin, risk acceptances, recurring vulns (legacy bespoke path)` text. Surgical single-cell edit — do not touch any other row or column.

6. Run the full suite and compare against the pre-change baseline. Known pre-existing, order-dependent failures live in `tests/unit/test_modules.py` (stub-registry pollution — they pass when that file runs alone) and are NOT regressions. Any NEW failure must be fixed before the task is done. Record the before/after failure counts and the exact failing test IDs in the SUMMARY.
  </action>
  <verify>
    <automated>cd /home/jmonroe/projects/vuln-reporting && grep -q "suppressed unless expired" reports/ops_remediation.py && grep -q -i "recast findings are not suppressed\|recast findings remain" reports/ops_remediation.py && grep -q "_suppress_risk_accepted" docs/GLOSSARY.md && grep -q -i "unexpired ACCEPTED" CLAUDE.md && python -m pytest tests/ -q</automated>
  </verify>
  <done>Summary-sheet label and Report Info tab text accurately describe ACCEPTED-only suppression + the expiry carve-out; module docstring, GLOSSARY entry, and the CLAUDE.md slug row are updated; full suite shows zero new failures vs the pre-change baseline.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Tenable rules API -> `recast_rules_df` | External data (`rule_id`, `expires_at`) drives whether a finding is suppressed from an operational worklist |
| Report workbook -> Operations reader | The Report Info / Summary text is the auditor's only statement of what population the numbers cover |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-jaz-01 | Information Disclosure | Suppressed findings vanish from all ops surfaces | mitigate | Tab 5 "Risk Acceptances & Recasts" and the `count_risk_*` tiles keep reading the FULL unfiltered `vulns_scanned` — Task 2 leaves `_extract_risk_modifications` wired to it and Task 2(b) adds a source-level guard that fails if a future edit rewires it |
| T-jaz-02 | Tampering | Malformed / hostile `expires_at` or `rule_id` values from the rules API | mitigate | `pd.to_datetime(..., errors="coerce")` maps unparseable values to `NaT` (never expires -> stays suppressed, the conservative direction); `rule_id` normalised via `str().strip()` with empty/`nan` dropped; schema presence checked before use |
| T-jaz-03 | Denial of Service | Rules API failure kills the report | mitigate | D-02 graceful degradation: `recast_rules_df` None/empty/malformed -> suppress all ACCEPTED, log a warning, never raise. Behavior 7 test covers it |
| T-jaz-04 | Repudiation | Numbers change with no audit trail of why | mitigate | `logger.info` line emits accepted / suppressed / returned_by_expiry / recast_kept counts per run; workbook text updated (Task 3) so the reader knows the population |
| T-jaz-SC | Tampering | npm/pip/cargo installs | n/a | Zero new dependencies (Hard Rule 8) — no install tasks in this plan, so no legitimacy gate applies |
</threat_model>

<verification>
- `python -m pytest tests/test_ops_risk_accepted_suppression.py -x -q` — all 8 behavior groups green
- `python -m pytest tests/ -q` — zero NEW failures vs the pre-change baseline (the `tests/unit/test_modules.py` order-dependent stub-registry failures are pre-existing)
- **Hard Rule 1** — no live Tenable pulls. Every check is an offline unit test over synthetic frames plus `inspect.getsource` structural assertions. The plan runs NO fetcher, NO `reports/ops_remediation.py` standalone invocation, and NO `run_all.py`. The `__main__` smoke block is edited but never executed.
- **Hard Rule 2** — synthetic fixtures only: `00000000-...` asset UUIDs, `11111111-...` rule UUIDs, plugin_ids `100001+`, plugin names `"Synthetic Plugin A"`. No real hostnames/IPs/MACs/CVEs/plugin names in any committed file.
- **Hard Rule 3** — no new open predicate introduced. The helper filters rows by `severity_modification_type` only; existing open/SLA logic is untouched.
- **Hard Rule 4** — no severity tiering touched; the helper filters rows, never re-tiers.
- **Hard Rule 5** — `_suppress_risk_accepted` returns a boolean-mask slice plus `.copy()`; no `df["col"] = ...` anywhere in new code.
- **Hard Rule 6** — empty frame, missing `severity_modification_type`, missing `recast_rule_uuid`, and None/empty/malformed `recast_rules_df` all return without raising (behaviors 6 and 7).
- **Hard Rule 8** — zero new dependencies; `requirements.txt` untouched.
- **D-03** — no new slug, no `include_risk_managed` option, no schema/YAML change: `run_all.py` and `delivery_config.schema.yaml` are NOT in `files_modified`.
</verification>

<success_criteria>
- `_suppress_risk_accepted(vulns_df, recast_rules_df, as_of)` exists in `reports/ops_remediation.py`, suppresses ACCEPTED only, keeps RECASTED, un-suppresses expired acceptances, and degrades gracefully with a warning (Task 1).
- `run_report()` applies it exactly once and routes `vulns_actionable` to all seven actionable-metric surfaces (Task 2).
- `_extract_risk_modifications` and the four `count_risk_*` tiles verifiably still read the full unsuppressed population, protected by a regression guard (Task 2).
- The `__main__` smoke block matches `run_report()` behavior (Task 2).
- Summary-sheet label and Report Info tab text are accurate; module docstring, GLOSSARY, and CLAUDE.md updated (Task 3).
- `tests/test_ops_risk_accepted_suppression.py` covers all 8 required behavior groups and passes.
- Full `python -m pytest tests/ -q` shows zero new failures.
</success_criteria>

<output>
Create `.planning/quick/260813-jaz-suppress-risk-accepted-findings-from-ops/260813-jaz-SUMMARY.md` when done.

Record in the SUMMARY:
- The before/after full-suite failure counts and exact failing test IDs (to prove zero new regressions).
- An OPERATOR NOTE: this changes delivered `ops_remediation` numbers for every group that runs the slug — open counts, SLA-state breakdown, Plugins, Overdue Detail, Urgent PDF table, exploitability, top-5 priority plugins, and recurring will all drop by the unexpired-ACCEPTED population. The magnitude cannot be measured inside Claude Code (Hard Rule 1); the operator should run `ops_remediation` against the warmed parquet cache before the next scheduled send and confirm the delta matches the Summary sheet's "Accepted Findings (suppressed unless expired)" tile.
- Confirmation that Tab 5 and the `count_risk_*` tiles are byte-unchanged in behavior.
</output>
