---
phase: quick-260608-cma
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - reports/modules/tag_severity_share_module.py
  - reports/modules/vuln_type_distribution_module.py
  - reports/composed_report.py
  - tests/unit/test_tag_severity_share.py
  - tests/unit/test_vuln_type_distribution.py
  - docs/tag_severity_share_calculations.md
  - docs/vuln_type_distribution_calculations.md
  - delivery_config.yaml
autonomous: true
requirements: [SEV-NONE-01]
must_haves:
  truths:
    - "A composed_report group with modules:[tag_severity_share, vuln_type_distribution] renders PDF + Excel + email without crashing."
    - "tag_severity_share buckets a null/NaN/0.0 vpr_score into None with NO native-severity fallback."
    - "tag_severity_share expresses each severity as tag_count[sev] / env_vuln_total (env grand total), guarding /0."
    - "vuln_type_distribution classifies findings via plugin_family OS-override -> CPE part-letter a/o/h -> Other, hiding Hardware when count==0."
    - "Zero-row tag scope renders a gray No-Data RAG cell and 'No data in scope.' driver instead of raising."
  artifacts:
    - path: "reports/modules/tag_severity_share_module.py"
      provides: "tag_severity_share module — VPR-pure severity-vs-environment share"
      contains: "MODULE_ID         = \"tag_severity_share\""
    - path: "reports/modules/vuln_type_distribution_module.py"
      provides: "vuln_type_distribution module — VTD-01 family-override CPE classifier"
      contains: "MODULE_ID         = \"vuln_type_distribution\""
    - path: "reports/composed_report.py"
      provides: "gated env_vuln_total forwarding"
      contains: "_MODULES_NEEDING_ENV_TOTAL"
    - path: "tests/unit/test_tag_severity_share.py"
      provides: "VPR->bucket mapper + env-share math tests"
    - path: "tests/unit/test_vuln_type_distribution.py"
      provides: "family-override classifier tests"
    - path: "docs/tag_severity_share_calculations.md"
      provides: "auditor runbook documenting the no-native-fallback / None=0-or-null divergence"
    - path: "docs/vuln_type_distribution_calculations.md"
      provides: "auditor runbook for the VTD-01 classifier"
  key_links:
    - from: "reports/composed_report.py"
      to: "tag_severity_share_module.compute(**kwargs)"
      via: "composer_kwargs['env_vuln_total']"
      pattern: "env_vuln_total"
    - from: "delivery_config.yaml"
      to: "composed_report"
      via: "reports:[composed_report] + modules:[tag_severity_share, vuln_type_distribution]"
      pattern: "tag_severity_share"
---

<objective>
Build the Tag-vs-Environment Severity Share & Vuln-Type Profile report as two new
auto-discovered metric modules delivered through the existing `composed_report` slug.

Purpose: Give leadership, for a selected Tenable tag, (1) a VPR severity distribution
expressed as a share of the entire environment's open-finding total, and (2) a within-tag
CPE type distribution (Application / OS / Hardware / Other) using the proven VTD-01
family-override classifier.

Output:
- `reports/modules/tag_severity_share_module.py` (MODULE_ID `tag_severity_share`)
- `reports/modules/vuln_type_distribution_module.py` (MODULE_ID `vuln_type_distribution`)
- Gated `env_vuln_total` forwarding in `reports/composed_report.py`
- Unit tests for the VPR->bucket mapper, the family-override classifier, and the env-share math
- Two auditor runbooks under `docs/`
- One additive example group in `delivery_config.yaml`

The design is locked (spec D1-D9). Do NOT re-litigate any decision. Implement exactly as specified.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
</execution_context>

<context>
@docs/superpowers/specs/2026-06-08-tag-severity-env-share-and-vuln-type-design.md
@CLAUDE.md
@.claude/skills/spike-findings-vuln-reporting/references/vuln-metric-substrate.md

<read_first>
- reports/modules/total_vulns_by_severity_module.py — closest analog. Match its docstring
  style, compute()/render structure, try-except -> _empty_result pattern, and get_audit_info().
- reports/modules/base.py — BaseModule contract; ModuleData fields (driver_narrative,
  analyst_rows, rag_strip); _empty_result(); the four concrete-default renderers
  (render_pdf_section, render_excel_tabs, render_email_panel, render_analyst_tabs,
  render_rag_strip_entry).
- reports/composed_report.py:69-100 — `_MODULES_NEEDING_FIXED_VULNS` gating; :180-219 the
  fetch/filter; :199-219 the tag filter; :272-283 `composer_kwargs` forwarding.
- config.py:71-167 — VPR_SEVERITY_MAP, vpr_to_severity (DO NOT use for this report — it
  applies a native fallback; D3 forbids that), SEVERITY_COLORS, SEVERITY_FILL_COLORS.
- tests/unit/test_modules.py — parametrized four-channel contract; new modules are picked up
  automatically by registry.list_all(). conftest provides synthetic_vulns_df / empty_vulns_df.
- delivery_config.yaml:69-95 — the existing "Custom Composed Report — example" group; mirror
  its shape for the new additive group.
</read_first>

<interfaces>
<!-- Contracts the executor uses directly — no codebase exploration needed. -->

ModuleData (reports/modules/base.py) — populate inside compute():
  module_id, display_name, metrics(dict), table_data(list[dict]), chart_data(dict),
  summary_text(str), metadata(dict), driver_narrative(str), analyst_rows(list[(str,DataFrame)]),
  rag_strip(dict {label, headline_value, rag_color, rag_label}), error(str|None).
  On failure: return self._empty_result(str(exc), config).

Re-exported at reports.modules package level (import from `reports.modules`):
  register_module, safe_pct, safe_int, safe_format,
  STATUS_COLOR, STATUS_LABEL, NO_DATA_HEADLINE, NO_DATA_DRIVER,
  rag_status_from_value, build_rag_strip_entry.

safe_pct(val) interprets val as ALREADY-percentage (87.4 -> "87.4%"). Multiply a 0.0-1.0
fraction by 100 before passing. safe_int(val) -> thousands-separated. Both return "—" on None/NaN.

build_rag_strip_entry(display_name, headline_value_str, status) -> strip cell dict;
status in {"green","yellow","red","no_data"}.

Open states (frozenset): {"open", "reopened"} — filter via
  vulns_df["state"].str.lower().isin({"open","reopened"}).

VTD-01 classifier (from vuln-metric-substrate.md — config-driven regex in the module):
  _CPE_PART = re.compile(r"cpe:(?:2\.3:|/)([aoh])[:/]", re.IGNORECASE)
  PART_TO_BUCKET = {"a": "Application", "o": "OS", "h": "Hardware"}
  OS_FAMILY = re.compile(r"local security checks|red hat|centos|oracle linux|ubuntu|debian|"
                         r"suse|amazon linux|rocky|alma|fedora|microsoft bulletin", re.IGNORECASE)
  classify(plugin_family, cpe): OS_FAMILY override first -> CPE part-letter a>o>h -> "Other".
  (Spec D4 uses "Other" as the fallback label, NOT the spike's "Unclassified".)

composed_report.run_report fetches vulns_df via fetch_all_vulnerabilities BEFORE the tag
filter (composed_report.py:175). vulns_df has columns including: state, vpr_score,
asset_uuid, plugin_family, cpe (comma-joined string per data/fetchers.py:343).
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Build the tag_severity_share module</name>
  <files>reports/modules/tag_severity_share_module.py</files>
  <behavior>
    - vpr_score null/NaN -> None bucket (no native fallback per D3).
    - vpr_score == 0.0 -> None bucket (D2).
    - 0.1..3.9 -> low; 4.0..6.9 -> medium; 7.0..8.9 -> high; 9.0..10.0 -> critical.
    - Each severity pct = tag_count[sev] / env_vuln_total; env_vuln_total==0 -> pct 0.0 (no /0 crash).
    - tag_share_pct == sum of the five severity pcts (rows sum to the tag's share of env).
    - Empty/zero-row tag scope: compute() returns ModuleData with all counts 0, env_vuln_total
      honored from kwargs, and renders without raising.
  </behavior>
  <action>
    Create `reports/modules/tag_severity_share_module.py` following the structure of
    `total_vulns_by_severity_module.py`. Implements MODULE_ID="tag_severity_share",
    DISPLAY_NAME="Tag Severity Share vs Environment", SUPPORTED_OUTPUTS=["pdf","excel","email"]
    (implements SEV-NONE-01).

    Severity buckets here are VPR-PURE with an explicit None bucket and NO native-severity
    fallback (D3) — do NOT call config.vpr_to_severity. Define a report-local
    `_bucket_severity(vpr_score) -> str` helper returning one of
    {"none","low","medium","high","critical"}: pd.isna(vpr_score) OR float(vpr_score)==0.0 ->
    "none"; otherwise map by VPR range (mirror VPR_SEVERITY_MAP ranges). The five-tier display
    order is ("critical","high","medium","low","none").

    compute(vulns_df, assets_df, report_date, config, **kwargs): read
    `env_vuln_total = int(kwargs.get("env_vuln_total", 0) or 0)`. Restrict vulns_df to open
    states {open, reopened}. Bucket each open row; build per-severity counts. For each severity
    `pct = (count / env_vuln_total * 100.0) if env_vuln_total > 0 else 0.0`. metrics carries
    per-severity count + pct, `tag_total`, `env_vuln_total`, and `tag_share_pct`
    (= tag_total/env_vuln_total*100 guarded). Use the empty-data guard pattern from CLAUDE.md;
    wrap the body in try/except returning self._empty_result(str(exc), config).

    Populate the four-channel contract:
    - driver_narrative: 1-line "what's driving it" (e.g. tag share of env + top severity).
    - rag_strip: build via build_rag_strip_entry(self.DISPLAY_NAME, safe_pct(tag_share_pct),
      status). Headline = tag's share of env. Choose status reasonably (this is a share metric,
      not an SLA gate — use "no_data" when tag_total==0, otherwise a neutral non-red status such
      as rag_status_from_value or a fixed informational color; document the chosen rule in the
      module docstring). Do NOT invent thresholds the spec didn't lock — keep it informational.
    - analyst_rows: a flat per-finding DataFrame of the tag's open findings (the tag-filtered
      open rows with their bucketed severity column added).
    render_pdf_section: table with columns Severity | Tag Count | % of Env Total + a tag-share
      footer line. render_excel_tabs: one tab, same columns. render_email_panel: inline-CSS
      panel (no <style>), include driver_narrative; return "" on data.error. render_analyst_tabs:
      return data.analyst_rows (or [] on error/zero rows). render_rag_strip_entry: inherit the
      base default (it honors compute()-populated data.rag_strip).

    ALL numeric interpolation in every renderer uses safe_pct/safe_int/safe_format — no inline
    f-string format specs on possibly-None values. Add get_audit_info() documenting the
    denominator (env grand total), the None=null-or-0 bucket, and the intentional
    no-native-fallback divergence. Add an `if __name__ == "__main__":` argparse smoke block
    matching the analog if the analog has one (total_vulns_by_severity has none — so this module
    needs none; do not add speculative CLI).

    Type hints + docstrings throughout. Surgical: create only this file.
  </action>
  <verify>
    <automated>python -c "from reports.modules import registry; m=registry.get('tag_severity_share')(); print(m.MODULE_ID)"</automated>
  </verify>
  <done>Module registers as `tag_severity_share`; _bucket_severity maps null/NaN/0.0 -> "none" with no native fallback; per-severity pct uses env_vuln_total with /0 guard; four channels implemented with safe_* formatters.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Build the vuln_type_distribution module</name>
  <files>reports/modules/vuln_type_distribution_module.py</files>
  <behavior>
    - Linux "Local Security Checks" family with cpe:/a:... -> "OS" (family override wins).
    - Microsoft Bulletin family -> "OS".
    - "Windows" third-party family with cpe:/a:... -> "Application" (NOT overridden).
    - cpe:2.3:o:... -> "OS"; cpe:/h:... -> "Hardware"; missing/unparseable CPE + non-OS family -> "Other".
    - Mixed CPE precedence a>o>h.
    - Hardware row/tile omitted from rendered output when its count == 0.
    - Within-tag count + % (denominator = tag_total, NOT environment).
  </behavior>
  <action>
    Create `reports/modules/vuln_type_distribution_module.py`. MODULE_ID="vuln_type_distribution",
    DISPLAY_NAME="Vulnerability Type Distribution", SUPPORTED_OUTPUTS=["pdf","excel","email"].

    Define the VTD-01 config-driven classifier at module level exactly per the
    vuln-metric-substrate.md blueprint (see <interfaces>): module-level `_CPE_PART`,
    `PART_TO_BUCKET`, `OS_FAMILY` (include the Microsoft Bulletins -> OS default), and a pure
    `classify(plugin_family: str, cpe: str) -> str` returning one of
    {"Application","OS","Hardware","Other"} ("Other" is the D4 fallback label). Keep classify
    importable for tests.

    compute(...): operate on tag-filtered open vulns_df ({open, reopened}). Apply classify row-wise
    over (plugin_family, cpe). metrics: count + within-tag pct for Application / OS / Hardware /
    Other (pct = count/tag_total*100, guard /0). Set a `hide_hardware` flag in metrics/metadata
    when Hardware count == 0. driver_narrative, analyst_rows (flat per-finding DataFrame with the
    classified type column), and rag_strip (informational headline — e.g. dominant type or
    Application share; use "no_data" when tag_total==0). Empty-data guard + try/except ->
    _empty_result.

    Renderers: render_pdf_section (table Type | Count | % within Tag, omit the Hardware row when
    hidden), render_excel_tabs (one tab, same columns, omit Hardware row when hidden),
    render_email_panel (inline-CSS, includes driver_narrative, "" on error), render_analyst_tabs
    (data.analyst_rows). All numeric interpolation via safe_pct/safe_int/safe_format. Add
    get_audit_info() documenting the family-override-first rule, the a>o>h precedence, the
    "Other" fallback, and the Hardware-hidden-when-zero behavior.

    Type hints + docstrings. Surgical: create only this file.
  </action>
  <verify>
    <automated>python -c "from reports.modules.vuln_type_distribution_module import classify; assert classify('Red Hat Local Security Checks','cpe:/a:redhat:foo')=='OS'; assert classify('Windows','cpe:/a:adobe:reader')=='Application'; assert classify('',None)=='Other'; print('ok')"</automated>
  </verify>
  <done>Module registers as `vuln_type_distribution`; classify implements family-override-first then a>o>h then "Other"; Hardware hidden when 0; within-tag pct; four channels with safe_* formatters.</done>
</task>

<task type="auto">
  <name>Task 3: Forward env_vuln_total from composed_report (gated)</name>
  <files>reports/composed_report.py</files>
  <action>
    Mirror the `_MODULES_NEEDING_FIXED_VULNS` pattern exactly (composed_report.py:73, :180, :272).

    1. Add near line 73: `_MODULES_NEEDING_ENV_TOTAL = frozenset({"tag_severity_share"})`.
    2. After vulns_df is fetched but BEFORE the tag filter (the `if tag_category and tag_value:`
       block at :199), compute the environment grand total from the UNFILTERED open vulns_df:
       `_open_mask = vulns_df["state"].str.lower().isin({"open", "reopened"})` then
       `env_vuln_total = int(_open_mask.sum())`. Guard for an absent/empty "state" column
       (set env_vuln_total = 0 if the column is missing) so a degenerate fetch does not raise.
    3. In the composer_kwargs assembly block (:272-274), add gating identical to fixed_vulns_df:
       `if _MODULES_NEEDING_ENV_TOTAL.intersection(modules): composer_kwargs["env_vuln_total"] = env_vuln_total`.

    Surgical change (~8 lines). Do NOT alter the fixed_vulns_df logic or any other behavior.
    ReportComposer already forwards **self._kwargs to every compute() (composer.py:562), and every
    compute() absorbs unknown kwargs via **kwargs — same safety profile as fixed_vulns_df.
  </action>
  <verify>
    <automated>python -c "import ast,inspect,reports.composed_report as c; src=inspect.getsource(c); assert '_MODULES_NEEDING_ENV_TOTAL' in src and 'env_vuln_total' in src; ast.parse(src); print('ok')"</automated>
  </verify>
  <done>`_MODULES_NEEDING_ENV_TOTAL` exists; env_vuln_total computed from unfiltered open vulns_df pre-filter; forwarded via composer_kwargs only when tag_severity_share is in modules; fixed_vulns_df logic untouched.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 4: Unit tests for the mapper, classifier, and env-share math</name>
  <files>tests/unit/test_tag_severity_share.py, tests/unit/test_vuln_type_distribution.py</files>
  <behavior>
    - VPR->bucket: critical/high/medium/low boundary values land in the right tier;
      None, float('nan'), 0.0, and "" all land in "none"; NO native-fallback path is taken.
    - env-share math: tag_count/env_vuln_total*100 is correct; env_vuln_total==0 yields 0.0
      (no ZeroDivisionError); the five severity pcts sum to tag_share_pct.
    - classifier: Linux Local Security Checks (cpe:/a) -> OS; Microsoft Bulletin -> OS;
      "Windows" family third-party app (cpe:/a) -> Application; missing/unparseable CPE -> Other;
      cpe:2.3:o -> OS; cpe:/h -> Hardware; mixed CPE a>o>h precedence.
  </behavior>
  <action>
    Create two pytest files under tests/unit/ matching the existing layout (from __future__ import
    annotations; `pytestmark = pytest.mark.unit`; import targets from the new modules).

    test_vuln_type_distribution.py: import `classify` from
    reports.modules.vuln_type_distribution_module and parametrize the labelled samples in
    <behavior> (include the spec's exact cases: Linux distro family with app CPE, Microsoft
    Bulletins, third-party "Windows" family, missing/unparseable CPE, 2.3 and 2.2 CPE forms,
    mixed-CPE precedence).

    test_tag_severity_share.py: import the report-local severity bucket helper
    (`_bucket_severity`) from reports.modules.tag_severity_share_module and parametrize the VPR
    boundary + None/NaN/0.0/"" edge cases. Then build a tiny synthetic tag-filtered vulns_df and
    drive compute() with env_vuln_total via the ModuleConfig + kwargs path
    (`inst.compute(df, assets_df, _NOW, ModuleConfig('tag_severity_share'), env_vuln_total=N)`),
    asserting: per-severity pct math, the /0 guard at env_vuln_total==0, and that the five
    severity pcts sum to metrics['tag_share_pct'] (within float tolerance).

    Use pandas DataFrames with the minimal columns the modules read (state, vpr_score for
    severity; state, plugin_family, cpe for type). Match conftest fixture style where convenient
    but the targeted unit tests can build their own small frames.
  </action>
  <verify>
    <automated>python -m pytest tests/unit/test_tag_severity_share.py tests/unit/test_vuln_type_distribution.py -q</automated>
  </verify>
  <done>Both test files pass; cover VPR boundaries + None/NaN/0.0/"" with no native fallback, the family-override classifier labelled samples, and env-share math incl. the /0 guard and rows-sum-to-tag-share invariant.</done>
</task>

<task type="auto">
  <name>Task 5: Auditor runbooks</name>
  <files>docs/tag_severity_share_calculations.md, docs/vuln_type_distribution_calculations.md</files>
  <action>
    Create two calculation runbooks following the style of docs/board_summary_calculations.md /
    docs/management_summary_calculations.md (skim one to match heading structure and tone).

    docs/tag_severity_share_calculations.md MUST document:
    - Denominator definition: each severity pct = tag's count at that severity ÷ the environment
      grand total (all severities, all assets, open states {open, reopened}); rows sum to the
      tag's share of the environment (D1).
    - The None bucket = vpr_score null/blank OR == 0 (D2), matching the Tenable GUI "None".
    - The INTENTIONAL divergence (D3): severity is derived purely from vpr_score with NO
      native-severity fallback — call this out explicitly so an auditor does not read it as a bug.
      Note it diverges from the spike's vpr_to_severity(..., fallback=native) convention and from
      config.vpr_to_severity used elsewhere.
    - Open-state and Informational-exclusion notes (D8: Info-native dropped upstream by fetcher).
    - The no-tag degenerate case (D7): tag == environment ⇒ shares sum to ~100%.

    docs/vuln_type_distribution_calculations.md MUST document:
    - The VTD-01 family-override classifier: plugin_family OS/distro/Microsoft-Bulletin override
      first, then CPE part-letter a/o/h, else "Other" (D4); a>o>h precedence.
    - Within-tag denominator (D5): count + % within the tag, not vs environment.
    - Coverage rationale (~99.2% Crit+High classify per spike) and the ~6% OS/App swing the
      family override prevents.
    - Hardware row hidden when count == 0.
  </action>
  <verify>
    <automated>python -c "import pathlib; a=pathlib.Path('docs/tag_severity_share_calculations.md').read_text(encoding='utf-8'); b=pathlib.Path('docs/vuln_type_distribution_calculations.md').read_text(encoding='utf-8'); assert 'fallback' in a.lower() and 'environment' in a.lower(); assert 'family' in b.lower(); print('ok')"</automated>
  </verify>
  <done>Both runbooks exist; tag_severity_share doc explicitly documents the no-native-fallback / None=0-or-null divergence and the env-grand-total denominator; vuln_type doc documents the family-override classifier and within-tag denominator.</done>
</task>

<task type="auto">
  <name>Task 6: Additive example YAML group + schema validation</name>
  <files>delivery_config.yaml</files>
  <action>
    Append ONE new group to delivery_config.yaml mirroring the existing "Custom Composed Report —
    example" group (delivery_config.yaml:69-95). The new group:
    - name: a distinct descriptive name (e.g. "Tag Severity & Type Profile — example").
    - schedule: { frequency: on_demand }.
    - reports: [composed_report].
    - modules: [tag_severity_share, vuln_type_distribution].
    - filters: a tag filter (tag_category: "Environment", tag_value: "Production").
    - email: subject + recipients (use the test recipient already in the file) + reply_to.

    ADDITIVE ONLY — do not modify or remove any existing group. Match indentation/style exactly.
  </action>
  <verify>
    <automated>python -c "import yaml; yaml.safe_load(open('delivery_config.yaml',encoding='utf-8')); print('yaml ok')" && python run_all.py --dry-run</automated>
  </verify>
  <done>New group parses; `python run_all.py --dry-run` validates the full config (incl. the new group against delivery_config.schema.yaml) with no errors; existing groups unchanged.</done>
</task>

</tasks>

<verification>
- All new modules auto-discover: `python -m pytest tests/unit/test_modules.py -q` (parametrized
  four-channel + empty-data contract now also covers the two new modules).
- Targeted unit tests pass: `python -m pytest tests/unit/test_tag_severity_share.py tests/unit/test_vuln_type_distribution.py -q`.
- `python run_all.py --dry-run` passes (new YAML group valid; composed_report slug already
  registered; no _VALID_REPORTS / _REPORT_MODULE_MAP / CLAUDE.md changes needed for modules).
- Empty-data guard: a zero-row tag scope renders a gray No-Data RAG cell and "No data in scope."
  driver without raising (covered by test_modules.py::test_empty_data_guard).
</verification>

<success_criteria>
- `tag_severity_share` and `vuln_type_distribution` modules exist, register, and implement the
  four-channel render contract with safe_pct/safe_int/safe_format throughout.
- tag_severity_share: None bucket = vpr_score null/NaN/0.0 with NO native fallback (D3);
  per-severity pct = tag_count / env_vuln_total with /0 guard; rows sum to tag_share_pct.
- vuln_type_distribution: family-override-first classifier (a>o>h, "Other" fallback), within-tag
  pct, Hardware hidden at 0.
- composed_report forwards env_vuln_total only when tag_severity_share is composed, computed from
  the UNFILTERED open vulns_df, mirroring the fixed_vulns_df gate.
- Unit tests cover the mapper edge cases, classifier labelled samples, and env-share math (/0 guard).
- Two auditor runbooks exist; tag_severity_share doc documents the intentional divergence.
- Additive YAML group validates via `run_all.py --dry-run`; existing groups untouched.
- Karpathy: surgical, minimum code, no speculative CLI/abstractions; matches analog style.
</success_criteria>

<output>
This is a `/gsd-quick` task — no SUMMARY.md required. On completion, ensure the spec and the
ROADMAP.md SEV-NONE-01 entry already staged on this branch are included in the commit alongside
the code (they are pre-written, not code work).
</output>
