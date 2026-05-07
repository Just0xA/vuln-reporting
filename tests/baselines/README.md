# tests/baselines/

Locked **structural-shape** baselines for the Phase 4 Board Summary
regression cutover smoke (`scripts/smoke_board_summary_cutover.py`).

## Hard rule: baselines change with CODE, not DATA

**Per revised CONTEXT.md D-04-05 (2026-05-07), these baselines are
STRUCTURAL ONLY.** They contain:

- PDF page count (byte-stream authoritative — counted from the rendered
  PDF, not from HTML page-break divs, because the cover page relies on
  CSS `page-break-after` rather than an explicit page-break element)
- "Risk Status Summary" header presence (boolean)
- RAG cell count
- Excel tab name set (sorted)
- Email body per-module panel count (counted from `role="presentation"`
  per panel — verified marker against composer.py + the four board
  metric module renders)
- Email inline-image CID set (sorted)
- Bundle keys present (sorted)
- `analyst_excel_present` (boolean)
- `rag_cells_all_no_data` (boolean)
- `panel_drivers_all_no_data_in_scope` (boolean)

They do NOT contain:

- **Headline metric values** (scan_coverage_pct, critical_remediation_sla_pct, etc.).
  These drift day-to-day with vulnerability churn. Locking them creates
  false-positive drift alerts on every Tenable update.
- **Per-tab Excel row counts.** Same reason as above — daily data churn.
- **Any per-row data** (hostnames, IPs, plugin names, BU tags, etc.) — forbidden by D-04-08.

### What this means in practice

The structural snapshot catches **refactor-driven regressions**:

- A composer change accidentally drops an Excel tab.
- A module renamer breaks the email panel HTML structure (e.g. removes
  the `role="presentation"` table or wraps it in a different element).
- A boolean toggle stops short-circuiting the analyst workbook.
- A no-data path stops painting RAG cells gray.
- A cover-page redesign accidentally adds or removes a rendered page.

The structural snapshot does NOT catch **data regressions** (a metric
went up because a remediation push closed findings; a metric went down
because new vulns were discovered). Those are caught by the operator
visually verifying values against Tenable production during the same
cutover run.

The two layers are complementary: the smoke script is automatic and
deterministic; the human is responsible for value correctness. Neither
can replace the other.

## No --update-baseline flag

There is no flag to overwrite a baseline. **Baselines change only when
CODE intentionally changes the structure** — adding a panel, renaming
an Excel tab, etc. — which is a code-review event documented in the
commit message that touches both `tests/baseline_utils.py` (new key in
the schema) and `tests/baselines/<group>.json` (new value).

To intentionally update a baseline:

1. Make the structural code change (e.g. add a 5th board module).
2. Update `tests/baseline_utils.py:extract_structural_snapshot` to
   include any new key.
3. Update `tests/test_baseline_extractor.py:EXPECTED_KEYS` to match.
4. Run `python tests/test_baseline_extractor.py` and confirm GREEN.
5. Run the smoke script. The first run after the schema change writes
   a fresh baseline automatically (capture-on-first-run; see below)
   OR drifts loudly if you forgot step 4.
6. Hand-edit the baseline JSON if needed. Commit with a clear message
   explaining the structural change.

**Do NOT** silently hand-edit a baseline to silence a drift you did not
cause. The drift is the test telling you something changed.

## Capture-on-first-run

When a baseline file does not exist, the smoke script writes it and
prints:

```
[smoke] BASELINE INITIALIZED for <group>: tests/baselines/<file>.json — review and commit.
```

Exit code is **0** (capture is not a failure; it's the documented bootstrap
path). Subsequent runs always diff against the committed file.

Operator workflow on a new tenant or after a schema change:

```bash
# 1. Warm the cache once per dev session
python run_all.py --group "Test Pull" --no-email

# 2. First run — captures all three baselines and exits 0
python scripts/smoke_board_summary_cutover.py

# 3. Visually inspect each JSON for sanity
ls -la tests/baselines/

# 4. Commit
git add tests/baselines/*.json
git commit -m "chore(04-04): initial structural baselines for board_summary"
```

## --unredacted is local-only

The default mode of `smoke_board_summary_cutover.py` redacts IPs and
emails in error/diagnostic output (the snapshot itself is structural
and contains no row-level data either way; the flag controls verbosity
of error messages, not the snapshot content).

`--unredacted` bypasses the redaction. **It is for the operator's local
terminal ONLY.** Do NOT:

- Paste `--unredacted` output into a PR description, an issue comment, or any chat.
- Copy it into a screenshot, an email, or a shared document.
- Commit any file produced by `--unredacted` to git.

If you need to share a drift report:

1. Run the script in default (redacted) mode.
2. Describe the failure in your own words: "pdf_page_count drifted
   from 5 to 4; one Excel tab name disappeared".
3. Do not paste raw diff lines unless your environment treats hashed
   identifiers as non-sensitive.

## Why structural-only?

> Headline metric values change daily with vulnerability churn. Locking
> them creates false-positive alerts on every Tenable update. The
> structural snapshot catches refactor-driven regressions (lost tab,
> broken toggle, dropped panel) without false positives on data movement.
> Visual operator confirmation against Tenable production remains the
> human gate for value correctness.

(Quoted from revised D-04-05.)

## Cross-references

- `tests/baseline_utils.py` — the extractor + PII guard
- `scripts/smoke_board_summary_cutover.py` — the runner
- `.planning/phases/04-yaml-config-and-regression-cutover/04-CONTEXT.md`
  — D-04-05 (revised), D-04-06, D-04-08
