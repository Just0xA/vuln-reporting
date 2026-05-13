---
phase: 06-cover-redesign-board-summary-integration
plan: 05
type: execute
wave: 5
depends_on:
  - 06-01
  - 06-02
  - 06-03
  - 06-04
files_modified:
  - tests/baselines/board_summary_test_pull.json
  - tests/baselines/board_summary_test_pull_analyst_off.json
  - tests/baselines/board_summary_test_pull_zero_match.json
autonomous: false
requirements:
  - CHROME-INT-03
  - CHROME-COMPAT-02
user_setup: []
must_haves:
  truths:
    - "The 3 board_summary smoke baselines are regenerated against the Phase 6 cover redesign."
    - "Re-running scripts/smoke_board_summary_cutover.py after regeneration shows 0 structural drift."
    - "Operator visual UAT passes: header band, footer corners, page-1 footer-center suppression, trimmed cover body, RAG strip parity with v1.0."
    - "Existing delivery_config.yaml continues to run end-to-end without a privacy_label field (CHROME-COMPAT-02)."
  artifacts:
    - path: "tests/baselines/board_summary_test_pull.json"
      provides: "Regenerated structural baseline for the standard Test Pull scope"
      contains: "schema_version"
    - path: "tests/baselines/board_summary_test_pull_analyst_off.json"
      provides: "Regenerated baseline for analyst_detail: false variant"
      contains: "schema_version"
    - path: "tests/baselines/board_summary_test_pull_zero_match.json"
      provides: "Regenerated baseline for zero-match (filtered-to-empty) variant"
      contains: "schema_version"
  key_links:
    - from: "tests/baselines/*.json"
      to: "scripts/smoke_board_summary_cutover.py"
      via: "auto-init on missing baseline (script lines 248-254)"
      pattern: "BASELINE INITIALIZED"
    - from: "Operator visual UAT"
      to: "output/<run>/board_summary.pdf"
      via: "manual open + check against D-04 checklist"
      pattern: "Risk Status Summary"
---

<objective>
Wipe the 3 board_summary smoke baselines, warm the cache, regenerate them via the auto-init path of `scripts/smoke_board_summary_cutover.py` (per RESEARCH.md Q4 — no `--regenerate` flag needed), commit, run an **operator visual UAT** on the rendered PDF (D-04 — this is the correctness gate, not the structural baseline), and re-run the smoke script to confirm 0 drift.

Purpose: CHROME-INT-03 requires "0 structural drift after re-baseline." But since structural baselines capture only counts/keys/CIDs and NOT cover-page text (RESEARCH.md Finding 3), structural drift is expected to be near-zero even before regeneration — **the operator visual UAT is what actually validates the Phase 6 cover redesign and the chrome header/footer rendering correctness** (D-04, and user memory `feedback_layout_fixes` — WeasyPrint flex bugs are real; render the PDF and look at it).

Output: 3 regenerated baseline JSONs, 1 visual-UAT pass confirmation captured in the SUMMARY, 1 zero-drift smoke re-run.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/06-cover-redesign-board-summary-integration/06-CONTEXT.md
@.planning/phases/06-cover-redesign-board-summary-integration/06-RESEARCH.md
@scripts/smoke_board_summary_cutover.py
@tests/baselines/board_summary_test_pull.json
@tests/baselines/board_summary_test_pull_analyst_off.json
@tests/baselines/board_summary_test_pull_zero_match.json
@delivery_config.yaml

<interfaces>
<!-- scripts/smoke_board_summary_cutover.py auto-init path (RESEARCH.md Q4). -->
# If baseline_file does not exist:
#   write_baseline(baseline_file, observed)
#   print(f"BASELINE INITIALIZED: {baseline_file.name}")
#   continue
# Header docstring lines 10-15 explicitly: NO --update-baseline flag.

<!-- IMPLEMENTOR: confirm the exact group name in delivery_config.yaml. -->
# The CONTEXT.md references "Test Pull" / "<Test Pull group>"; the SMOKE
# script likely targets specific groups via --group or iterates a list.
# Confirm by:
#   Select-String -Path delivery_config.yaml -Pattern "Test Pull"
#   Select-String -Path scripts/smoke_board_summary_cutover.py -Pattern "test_pull|--group"
</interfaces>
</context>

<tasks>

<task type="checkpoint:human-action" gate="blocking">
  <name>Task 1: Confirm the Test Pull group name in delivery_config.yaml</name>
  <what-built>Operator needs to read `delivery_config.yaml` and confirm the exact group name(s) that the 3 baselines correspond to (`board_summary_test_pull`, `…_analyst_off`, `…_zero_match`).</what-built>
  <how-to-verify>
    Run in PowerShell:
    ```powershell
    Select-String -Path delivery_config.yaml -Pattern "Test Pull"
    Select-String -Path scripts/smoke_board_summary_cutover.py -Pattern "test_pull|--group|GROUPS"
    ```
    Confirm the group name string that `run_all.py --group "<name>"` should receive for the cache warm-up step in Task 3.
  </how-to-verify>
  <resume-signal>Reply with the exact group name (e.g. `Test Pull` or `Board Summary Test Pull`), or `proceed` if the smoke script does not require a `--group` arg.</resume-signal>
</task>

<task type="auto">
  <name>Task 2: Wipe the 3 existing baselines</name>
  <files>tests/baselines/board_summary_test_pull.json, tests/baselines/board_summary_test_pull_analyst_off.json, tests/baselines/board_summary_test_pull_zero_match.json</files>
  <action>
Delete the 3 baseline files. RESEARCH.md Q4: the smoke script auto-initializes a missing baseline on the next run.

PowerShell:
```powershell
Remove-Item tests/baselines/board_summary_test_pull.json
Remove-Item tests/baselines/board_summary_test_pull_analyst_off.json
Remove-Item tests/baselines/board_summary_test_pull_zero_match.json
```

Verify the deletions via `git status tests/baselines/`.

DO NOT modify any other baselines or smoke artifacts.
  </action>
  <verify>
    <automated>python -c "from pathlib import Path; missing = [p for p in ['tests/baselines/board_summary_test_pull.json', 'tests/baselines/board_summary_test_pull_analyst_off.json', 'tests/baselines/board_summary_test_pull_zero_match.json'] if not Path(p).exists()]; assert len(missing) == 3, f'Expected 3 missing, got {missing}'; print('all 3 wiped')"</automated>
  </verify>
  <done>All 3 baseline files are absent from disk. `git status` shows them as deleted (not yet committed).</done>
</task>

<task type="auto">
  <name>Task 3: Warm the cache and regenerate baselines via smoke auto-init</name>
  <files>(no source edits — runs scripts)</files>
  <action>
1. **Warm the cache** (one fetch from Tenable → local parquet under `data/cache/<today>/`). Use the group name confirmed in Task 1. PowerShell:
   ```powershell
   python run_all.py --group "<TEST_PULL_GROUP_NAME>" --no-email
   ```
   `--no-email` keeps this purely a render run.

2. **Run the smoke script** — auto-init writes fresh baselines per RESEARCH.md Q4. PowerShell:
   ```powershell
   python scripts/smoke_board_summary_cutover.py
   ```
   Expected stdout: 3 lines containing `BASELINE INITIALIZED: board_summary_test_pull*.json`. Exit code 0.

3. **Inspect the 3 regenerated JSONs** for sanity. PowerShell:
   ```powershell
   Get-Content tests/baselines/board_summary_test_pull.json
   Get-Content tests/baselines/board_summary_test_pull_analyst_off.json
   Get-Content tests/baselines/board_summary_test_pull_zero_match.json
   ```
   Confirm each contains `schema_version`, `pdf_page_count`, `pdf_rag_cell_count`, `pdf_has_risk_status_summary_header: true` (R1 — the trimmed cover MUST still satisfy this marker check).

If `pdf_has_risk_status_summary_header` is `false` in any of the 3 outputs, STOP — that means plan 06-02's template trim accidentally dropped the marker the extractor greps for. Fix via re-running plan 06-02 verify tests; the marker MUST be `Risk Status Summary` per the extractor in `tests/baseline_utils.py:92`.
  </action>
  <verify>
    <automated>python -c "import json; from pathlib import Path; files = ['tests/baselines/board_summary_test_pull.json', 'tests/baselines/board_summary_test_pull_analyst_off.json', 'tests/baselines/board_summary_test_pull_zero_match.json']; [json.loads(Path(f).read_text()) for f in files]; print('all 3 regenerated and parseable')"</automated>
    <automated>python -c "import json; b = json.loads(open('tests/baselines/board_summary_test_pull.json').read()); assert b.get('pdf_has_risk_status_summary_header') is True, f'marker missing: {b}'; print('R1 marker preserved')"</automated>
  </verify>
  <done>All 3 baseline JSONs exist, are valid JSON, and have `pdf_has_risk_status_summary_header: true` (R1 marker preserved through the cover trim).</done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <name>Task 4: Operator visual UAT — the correctness gate (D-04)</name>
  <what-built>
    A regenerated `output/<YYYY-MM-DD_HH-MM_Test-Pull>/board_summary.pdf` produced by Task 3's cache-warm + smoke-render. **This visual check is the actual correctness gate for Phase 6** (per D-04 and user memory `feedback_layout_fixes` — WeasyPrint flex bugs are real; the structural baseline does NOT catch chrome rendering bugs because the JSON only captures counts/keys/CIDs, not pixels or layout).
  </what-built>
  <how-to-verify>
    Open the generated `board_summary.pdf` (the run from Task 3's `run_all.py --group …`). Run through D-04 checklist:

    1. **Header band visible on EVERY page** with title + scope subtitle. White text on `#1a2332` dark navy. Title-only header is the expected default (no logo, per D-03).

    2. **Footer corners on EVERY page:**
       - Bottom-left: `Confidential` (or your group's override).
       - Bottom-right: UTC timestamp matching `2026-MM-DD HH:MM UTC` format.

    3. **Footer center:**
       - Page 1 (cover): EMPTY (no `Page 1 of N`).
       - Pages 2+: `Page N of M`.

    4. **Cover body (page 1 only):**
       - Scope subtitle (value-only — `Production` / `All assets`).
       - "Risk Status Summary" header.
       - RAG strip — cells render identically to v1.0 (colors, layout, content).
       - NO inline title repeat, NO `Generated:` line, NO `Sections:` line, NO `<hr>` divider, NO `.cover-meta` wrapper.

    5. **RAG strip parity vs v1.0:**
       - Compare against an archived v1.0 board_summary.pdf if available, or against the most recent pre-Phase-6 baseline screenshot. Cell count, cell colors, cell labels, and headline values MUST match.

    6. **Sanity sweep:** flip through every page. No orphaned blank pages. Page numbering on pages 2+ is monotonic. The header band does not bleed into module content.
  </how-to-verify>
  <resume-signal>Type `approved` if all 6 checks pass. Otherwise describe the visual regression (e.g. "header bleeds into RAG strip on page 1", "footer-right timestamp missing on page 3", "RAG cell colors changed") and which earlier plan needs revisiting (typically 06-01 for chrome injection bugs, 06-02 for cover body bugs, 06-03 for PdfChromeConfig field bugs).</resume-signal>
</task>

<task type="auto">
  <name>Task 5: Commit regenerated baselines</name>
  <files>tests/baselines/board_summary_test_pull.json, tests/baselines/board_summary_test_pull_analyst_off.json, tests/baselines/board_summary_test_pull_zero_match.json</files>
  <action>
Commit ONLY the 3 regenerated baseline JSONs. Commit message (HEREDOC pattern, exact text):

```
chore(06-05): regenerate board_summary smoke baselines for cover redesign

Phase 6 trims the unified cover template to scope subtitle + RAG strip
only (D-01, CHROME-COV-02). Structural baselines capture counts/keys/CIDs
and not cover text, so most fields are unchanged; "All assets" case
normalization (D-01) is the only operator-visible cover shift. Visual UAT
passed against D-04 checklist.
```

Use `git add tests/baselines/board_summary_test_pull*.json` (3 explicit paths if globbing is risky on PowerShell — use the explicit list from `files` above).

DO NOT amend or force-push.
  </action>
  <verify>
    <automated>git log -1 --stat tests/baselines/board_summary_test_pull.json | Select-String -Pattern "06-05|board_summary"</automated>
  </verify>
  <done>HEAD commit contains the 3 regenerated baselines and a message starting with `chore(06-05):`. Working tree is otherwise clean for `tests/baselines/`.</done>
</task>

<task type="auto">
  <name>Task 6: Re-run smoke script — confirm 0 drift</name>
  <files>(no edits — verification only)</files>
  <action>
Re-run the smoke script. With the baselines now on disk and matching the just-rendered output, the script must print `PASS` (or its equivalent — RESEARCH.md Q4 noted exit code 0 on success) for all 3 scenarios and exit 0.

PowerShell:
```powershell
python scripts/smoke_board_summary_cutover.py
```

If any drift surfaces here, it means the smoke render between Task 3 and Task 6 is non-deterministic — investigate before proceeding. Common causes: timestamp leakage into a captured field (shouldn't be — generated_at is excluded from the structural baseline; RESEARCH.md Finding 3), tag-data shift between runs, ordering instability in `excel_tab_names_sorted` (which IS sorted, so should be stable).
  </action>
  <verify>
    <automated>python scripts/smoke_board_summary_cutover.py; if ($LASTEXITCODE -ne 0) { throw "smoke script returned $LASTEXITCODE — drift detected" } else { Write-Output "0 drift" }</automated>
  </verify>
  <done>`scripts/smoke_board_summary_cutover.py` exits 0; stdout shows PASS for all 3 scenarios. CHROME-INT-03 satisfied.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Phase 6 code state → operator visual UAT | Visual UAT is the *only* path that catches WeasyPrint layout/CSS bugs in the new chrome injection. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-06-08 | Repudiation | "we re-baselined and shipped" without visual UAT | mitigate | Task 4 is a blocking `checkpoint:human-verify`. SUMMARY MUST capture the operator's `approved` signal — no implicit pass. |
| T-06-09 | Tampering | baseline regen masks a real regression in chrome rendering | mitigate | RESEARCH.md Finding 3 already establishes structural baselines do NOT capture cover text — Task 4 visual UAT is the gate, not Task 6's diff. Documented explicitly in this plan's `<objective>`. |
</threat_model>

<verification>
```powershell
# 1. Baselines exist, parseable, marker preserved
python -c "import json; b = json.loads(open('tests/baselines/board_summary_test_pull.json').read()); assert b['pdf_has_risk_status_summary_header'] is True; print('OK')"

# 2. Smoke script — 0 drift
python scripts/smoke_board_summary_cutover.py

# 3. CHROME-COMPAT-02 — existing yaml still validates and runs (no privacy_label required)
python -c "import yaml, jsonschema; jsonschema.validate(yaml.safe_load(open('delivery_config.yaml')), yaml.safe_load(open('delivery_config.schema.yaml'))); print('OK')"

# 4. End-to-end regression — every Phase 6 test file
python -m pytest tests/test_phase6_composer_chrome.py tests/test_phase6_cover_redesign.py tests/test_phase6_board_summary_chrome.py tests/test_phase6_run_group_chrome.py -v

# 5. Commit landed
git log -1 --stat -- tests/baselines/
```
</verification>

<success_criteria>
- 3 baselines regenerated and committed (CHROME-INT-03).
- `pdf_has_risk_status_summary_header: true` in all 3 — R1 marker survived the cover trim.
- Operator visual UAT pass captured in SUMMARY (D-04 — the correctness gate).
- `python scripts/smoke_board_summary_cutover.py` exits 0 — 0 structural drift after regen (CHROME-INT-03).
- Existing `delivery_config.yaml` continues to validate and run without a `privacy_label` field (CHROME-COMPAT-02).
- v1.1 milestone closed.
</success_criteria>

<output>
After completion, create `.planning/phases/06-cover-redesign-board-summary-integration/06-05-SUMMARY.md` capturing:
- The exact group name used for cache warm-up (resolved in Task 1)
- `BASELINE INITIALIZED` stdout from Task 3
- Operator's `approved` signal from Task 4 — quote the exact reply if there were caveats
- Final smoke script output (zero-drift confirmation from Task 6)
- Commit SHA from Task 5
- Note: this closes Phase 6 and the v1.1 PDF Chrome Redesign milestone.
</output>

<notes>
**Why visual UAT is the correctness gate (not the structural baseline):**
RESEARCH.md Finding 3 confirms the baseline JSON captures only:
- analyst_excel_present, bundle_keys_present, email_inline_image_cids_per_module,
- email_panel_count, excel_tab_names_sorted, group_slug,
- panel_drivers_all_no_data_in_scope, pdf_has_risk_status_summary_header,
- pdf_page_count, pdf_rag_cell_count, rag_cells_all_no_data, schema_version.

NONE of these capture: header band color, footer corner contents, footer-center suppression on page 1, scope subtitle text rendering, logo placement, "All assets" vs "all assets" case shift. Per user memory `feedback_layout_fixes` and D-04, only the operator opening the PDF can validate these. Task 4 is a blocking checkpoint specifically because automation cannot replace it.
</notes>
