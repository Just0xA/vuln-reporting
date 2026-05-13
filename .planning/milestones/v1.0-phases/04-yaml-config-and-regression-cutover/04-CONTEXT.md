---
phase: 4
phase_name: YAML Config and Regression Cutover
status: locked
captured: 2026-05-07
locked_decisions: 8
---

# Phase 4 — Locked Decisions

These decisions were settled in conversation between the operator and Claude
on 2026-05-07 before planning. The planner treats them as non-negotiable
inputs; deviations require returning to the user.

## D-04-01 — Schema enum reconciliation is Wave 0

The current `delivery_config.schema.yaml:60-69` `reports.items.enum` is
missing `board_summary` and `unscanned_assets` (both shipped in Phases 1-3
and present in `run_all.py:_VALID_REPORTS`). Schema enforcement cannot
land without reconciling this list FIRST.

**Why:** turning on `jsonschema.validate()` against the current schema
would immediately reject the only currently-deployed `board_summary`
group ("Test Pull"), bricking production on commit. Wave 0 of Plan 04-01
fixes the enum before validation is enforced.

**How to apply:** Plan 04-01 lands the enum fix as its first task; the
jsonschema integration only runs after the enum is reconciled.

## D-04-02 — Replace `_validate_group()`, do not coexist

The hand-rolled `_validate_group()` at `run_all.py:241-318` will be
**replaced** by a thin wrapper around `jsonschema` errors, not kept
alongside as defense in depth.

**Why:** two validators will inevitably drift; the hand-rolled one already
misses checks the schema can express (`format: email`,
`additionalProperties: false`, `dependencies` between
`tag_category`/`tag_value`). Single source of truth wins. The wrapper
preserves the existing rich-table dry-run UX.

**How to apply:** Plan 04-01 deletes the body of `_validate_group()` and
replaces it with a call to `_validate_with_schema(group, schema_dict)`
that returns the same error-list shape the existing dry-run already
consumes. Test coverage adds: malformed YAML triggers exit non-zero with
the offending group + field named in the error.

## D-04-03 — `analyst_detail` opt-out plumbed via existing kwargs

The composer kwarg (`generate_analyst=`) and the bundle-driven analyst
attach (`delivery/email_sender.py`) already exist. Phase 4 wires
`group_config.get("analyst_detail", True)` from YAML through
`run_all.py:run_group()` → `run_report(... analyst_detail=...)` →
`composer.run_full_pipeline(generate_analyst=...)`.

**Why:** the plumbing is fully built; only `reports/board_summary.py:247`
hardcodes `True` today. Replacing one literal with a kwarg-driven value
is the entire fix — no new abstractions needed.

**How to apply:** Plan 04-02 adds an `analyst_detail` parameter to
`board_summary.run_report()` (default `True`) and threads the YAML field
through `run_all.py:run_group()`. Schema marks it as optional boolean
with `default: true`; the Python load path injects the default if
missing because jsonschema 4 doesn't apply defaults.

## D-04-04 — Three test groups in `delivery_config.yaml`

Single "Test Pull" group doesn't exercise the new code paths. Phase 4
extends `delivery_config.yaml` with two additional test groups:

1. **"Test Pull"** — existing, default `analyst_detail: true` → baseline
2. **"Test Pull — Analyst Off"** (new) — `analyst_detail: false` →
   exercises CONFIG-03 opt-out (no analyst workbook in delivery)
3. **"Test Pull — Zero Match"** (new) — tag filter that yields 0 assets
   → exercises empty-data path (gray "No Data" cells, em-dash headlines,
   "No data in scope." panels)

Production rollout (UC Engineering / Workstation / Enterprise
Virtualization, etc.) is **deferred** — not Phase 4's job. Operators
add their real groups in their own deployment config later.

**Why:** Phase 4 ships three new YAML-driven behaviors (schema
validation / analyst-detail opt-out / regression cutover); each needs a
test group exercising it. Deferring real prod groups keeps the committed
config focused on dev/test.

**How to apply:** Plan 04-03 adds the two new groups with these
LOCKED literal values (operator-confirmed 2026-05-07):
- "Test Pull — Zero Match": `tag_category: "Application"`,
  `tag_value: "DoesNotExist"` (Application is a known tag category in
  the operator's tenant; "DoesNotExist" is a literal value that does
  not exist).

## D-04-05 — Baselining = visual (data) + structural snapshot (shape)

**Revised 2026-05-07** after operator clarified that headline metric
values drift day-to-day with vulnerability churn. Locking metric values
would create false-positive alerts on every Tenable update.

Operator continues to visually verify metric VALUES against Tenable
production — that remains the human gate for data correctness.
Underneath that gate, a **structural-shape snapshot** locks in only
properties that are deterministic across runs regardless of data volume.

**Snapshot fields per group (DETERMINISTIC across runs):**
- PDF page count (e.g. board_summary = 5: 1 cover + 4 metric pages)
- "Risk Status Summary" header presence on the cover page
- RAG cell count on page 1 (board_summary = 4)
- Excel tab NAMES, sorted alphabetically (e.g.
  `["Aged Vulns Detail", "Critical Remediation Detail",
   "High-Risk Detail", "Scan Coverage Detail", "_Metadata"]`)
- Email body per-module panel count (board_summary = 4)
- Email inline-image CID presence per module (board_summary = 4 gauges,
  one cid per module_id matching `<img src="cid:{module_id}_gauge">`)
- Bundle keys present in `bundle = run_full_pipeline(...)`:
  `pdf_html`, `excel_workbook`, `analyst_excel`, `email_body_html`,
  `email_inline_images`, `email_kpis`, `metrics`, `errors`
- For `analyst_detail: false` groups → `bundle["analyst_excel"] is None`
- For zero-match groups → every RAG cell color is `STATUS_COLOR["no_data"]`
  AND every panel driver narrative equals `"No data in scope."`

**Snapshot fields EXCLUDED (DATA-DEPENDENT, would create false alerts):**
- Headline metric percentages (drift daily with vuln churn)
- Per-tab Excel row counts (depend on which assets/findings exist today)
- Per-row asset/finding detail (also forbidden by D-04-08 PII rule)
- Specific RAG cell colors per metric on populated groups (depend on
  whether today's coverage is above or below threshold)

**No `--update-baseline` flag.** Baselines change only when CODE
intentionally changes the structure (rare, code-review event,
documented in the commit). They do NOT change when DATA changes (every
day). This makes the smoke script a deterministic regression bar with
zero day-to-day maintenance.

**Storage:** `tests/baselines/board_summary_<group_slug>.json`. One
baseline per test group, committed to the repo. Initial values are
written by the operator after the first verified run of each group.

**Why this is better than the original D-04-05:** the structural shape
is exactly what a "regression cutover" should protect — it answers "did
this refactor accidentally drop a tab / break the toggle / lose a
panel?" — without false positives on data churn. Visual data
verification stays the human gate for value correctness. The two layers
are complementary: smoke script catches shape regressions automatically,
operator catches value regressions visually during the production run.

**How to apply:** Plan 04-04 ships:
- `tests/baseline_utils.py:extract_structural_snapshot(bundle, group_slug) -> dict`
  that produces ONLY the deterministic fields above (refuses to write
  metric values or row-level data even if asked — defensive)
- `tests/baseline_utils.py:compare_snapshots(actual, baseline) -> list[str]`
  returning human-readable diff lines, empty list on match
- `scripts/smoke_board_summary_cutover.py` that runs all 3 test groups
  against the cached parquet and diffs structural snapshots
- `tests/baselines/board_summary_test_pull.json` (initial committed
  baseline for the populated path)
- `tests/baselines/board_summary_test_pull_analyst_off.json` (initial
  baseline for analyst_detail: false)
- `tests/baselines/board_summary_test_pull_zero_match.json` (initial
  baseline for empty-data path)
- `tests/baselines/README.md` documenting the no-row-level rule + the
  "baselines change with CODE, not with DATA" convention

## D-04-06 — Cutover smoke runs against cached parquet, not live API

The cutover smoke script (`scripts/smoke_board_summary_cutover.py`)
runs against the cached parquet in `data/cache/<YYYY-MM-DD>/` rather
than calling Tenable. Operator pre-warms the cache once at the start
of a Phase 4 dev session; subsequent script invocations are <5s and
free.

**Why:** Tenable API calls are slow (minutes) and rate-limited. Cached
parquet runs in seconds. Cache freshness is the operator's choice —
script doesn't enforce age.

**How to apply:** Plan 04-04 documents the workflow in the script
docstring + README section. Script aborts cleanly if no cache exists
with a helpful message ("run `python run_all.py --group 'Test Pull' --no-email`
once to warm the cache").

## D-04-07 — Plan structure: 4 plans

Confirmed structure for Phase 4:

| Plan  | Wave | Subject |
|-------|------|---------|
| 04-01 | 1    | Schema enum fix + `analyst_detail` schema field + `jsonschema.validate()` integration replacing `_validate_group()` |
| 04-02 | 2    | Thread `analyst_detail` from group config through `run_all.py:run_group()` → `board_summary.run_report()` → `composer.run_full_pipeline(generate_analyst=)` |
| 04-03 | 2    | Add "Test Pull — Analyst Off" and "Test Pull — Zero Match" test groups to `delivery_config.yaml` |
| 04-04 | 3    | `tests/baseline_utils.py` snapshot extractor + `scripts/smoke_board_summary_cutover.py` runner + sample baselines for all 3 test groups |

**Wave order rationale:** Plan 04-01 unblocks 04-02 (schema must accept
`analyst_detail` before YAML can use it) and 04-03 (schema must accept
the new groups before they can be added). Plan 04-02 and 04-03 are
independent in Wave 2. Plan 04-04 depends on both 04-02 (kwarg threaded)
and 04-03 (test groups exist) — Wave 3.

**Why:** dependencies dictate order; each wave is verifiable
independently.

**How to apply:** Planner produces 4 PLAN.md files matching this
structure; gsd-plan-checker verifies dependency graph + acceptance
criteria coverage.

## D-04-08 — Sensitive data MUST NOT enter conversation context

Test outputs, smoke-script logs, baseline files, and committed YAML
snippets MUST NOT contain row-level Tenable data that maps individual
assets / findings to identifiable values. Specifically forbidden in
ANY artifact that could be pasted into a conversation, copied to a
PR description, or committed to git:

- Hostnames / asset names (real values)
- IPv4 / IPv6 / FQDNs
- Plugin / finding names + descriptions
- Asset-to-CVE pairings (CVE IDs alone are public; the pairing is not)
- Application / Business Unit tag values that map to internal team or
  org structure
- Real recipient email addresses on test groups
- Free-text from Tenable comments / recast_reason fields

What IS safe to share / log / commit:
- Aggregate counts (total assets, total findings, % within SLA)
- Structural shape (PDF page count, generic Excel tab names like
  "Scan Coverage Detail", "Risk Status Summary" header presence)
- Schema / code-level info (line numbers, function names, error class
  names, jsonschema ValidationError messages with field paths)
- Synthetic / fabricated test data (e.g. `host-a`, `10.0.0.1` in
  unit-test fixtures)

**Why:** the operator works in environments where production
vulnerability data is sensitive; even partial leakage of asset+finding
pairings is a security concern. Default-redact is cheaper than
remediating after a leak.

**How to apply:**

1. **Plan 04-04 — smoke script defaults to redacted output.**
   `scripts/smoke_board_summary_cutover.py` emits hashed hostnames
   (`asset-<sha256[:8]>`), masked IPs (`10.x.x.x`), and anonymized tag
   values (`bu-A`, `bu-B`) when printing diff output or per-row
   summaries. A `--unredacted` flag bypasses for operator local-only
   inspection. Default is redacted.

2. **Plan 04-04 — baselines store counts + headline metrics only.**
   `tests/baselines/board_summary_<group>.json` contains structural
   shape (page counts, tab row counts) and headline metric values
   (`scan_coverage_pct: 95.2`). NO row-level data. The snapshot
   extractor refuses to write row-level fields even if asked.

3. **Plan 04-03 — test recipient addresses are non-real.**
   New "Test Pull — Analyst Off" and "Test Pull — Zero Match" groups
   use a non-existent test domain (e.g.
   `reports-test@example.invalid`) so a YAML leak doesn't expose the
   operator's real address. Existing "Test Pull" recipient stays as-is
   — operator's call.

4. **Plan 04-04 — tests/baselines/README.md documents the
   no-row-level rule.** Codifies the convention so future contributors
   inherit it. References this CONTEXT.md decision.

5. **Plan 04-04 — defensive PII detector in baseline_utils.py.**
   The snapshot extractor explicitly DROPS columns named
   `hostname`, `ipv4`, `ipv6`, `fqdn`, `plugin_name`, `recast_reason`
   (and any column containing the substring `name`, `address`, or
   `email`) when serializing diagnostic output. Belt-and-braces: if a
   future contributor adds a row-level field by accident, the
   extractor still won't leak it.

**Out of scope for Phase 4** (carried forward, not blocking):

- Auditing existing log lines (`run_all.py`, `data/fetchers.py`,
  `delivery/email_sender.py`) for PII leakage — separate quick task.
- Adding a `LOG_REDACT=true` env var that swaps log lines globally —
  larger refactor.

---

## Open questions resolved

The researcher's RESEARCH.md flagged Assumptions A1 + A2 as needing user
confirmation. Both were resolved by the operator on 2026-05-07:

- **A1 (pre-v1 baseline definition)** → resolved as D-04-05 (visual +
  structural snapshot, with operator-locked metric values).
- **A2 (single-group scope)** → resolved as D-04-04 (extend committed
  config to 3 test groups; defer prod group rollout to operator).

## Cross-references

- `.planning/phases/04-yaml-config-and-regression-cutover/04-RESEARCH.md`
- `.planning/ROADMAP.md` Phase 4 success criteria (lines 89-99)
- `delivery_config.schema.yaml:60-69` (enum reconciliation needed)
- `run_all.py:_validate_group` (lines 241-318) — to be replaced
- `run_all.py:_load_config` (line 137 area) — jsonschema integration point
- `reports/board_summary.py:247` — `generate_analyst=True` to become kwarg-driven
- `delivery/email_sender.py:149-151` — bundle-driven analyst attach (no edits needed)
