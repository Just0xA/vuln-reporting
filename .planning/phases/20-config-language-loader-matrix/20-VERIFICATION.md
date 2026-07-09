---
phase: 20-config-language-loader-matrix
verified: 2026-07-09T20:40:58Z
status: passed
score: 5/5 must-haves verified
has_blocking_gaps: false
overrides_applied: 0
---

# Phase 20: Config Language & Loader Matrix Verification Report

**Phase Goal:** An operator can define recipients once in a shared `contacts.yaml`, split deliveries into one file per team under `deliveries.d/`, and see the whole delivery landscape in one generated matrix — with a golden test proving the new loader resolves every existing config identically to today.
**Verified:** 2026-07-09T20:40:58Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Editing one contact in `contacts.yaml` propagates to every delivery referencing it, with no delivery file edited | VERIFIED | Live test (fresh, non-committed fixture): built a `contacts.yaml` + `deliveries.d/team_a.yaml`, resolved via `resolve_config`, edited only `contacts.yaml` (`old@example.invalid` → `new@example.invalid`), re-resolved — delivery's `recipients` changed with zero edits to the delivery file. Also exercised via the committed 20-check `tests/test_config_loader.py` harness (`A_contact_ref_resolves_recipients`, etc.) — all pass. |
| 2 | `defaults.analyst_mailbox` appears as standing Cc + default Reply-To (unless contact overrides) on every delivery, never inside a team's delivery file | VERIFIED | Live resolution of `tests/fixtures/phase20_config_twin/` shows `analyst-team@example.invalid` present in `cc` on all 3 deliveries; `reply_to` falls back to it for Remediation Team but is overridden by the contact's own `reply_to` for Executive Team and Tag Profile. `grep` confirms `analyst_mailbox` never appears inside any `deliveries.d/*.yaml` team file — only in `contacts.yaml`'s `defaults:` block. |
| 3 | An operator adds a report by editing only `deliveries.d/<team>.yaml`; loader globs+merges all team files and rejects same-name duplicates with a clear error | VERIFIED | Live test: two team files (`team_a.yaml`, `team_b.yaml`) each declaring a delivery named "Dup Delivery" → `resolve_config` returns `errors=['duplicate delivery name: Dup Delivery (in team_b.yaml, already defined in team_a.yaml)']` and `groups=[]`. Also confirmed live through the real `run_all.py --dry-run` CLI entry point (see Key Link Verification) — prints the error in red and exits 1. |
| 4 | A single un-migrated legacy `delivery_config.yaml` still loads/resolves; golden test asserts byte-identical resolution; a migrated equivalent resolves to the same golden | VERIFIED | `tests/test_effective_config_golden.py` (13/13 checks green): `legacy_matches_committed_golden`, `twin_matches_committed_golden`, and the direct `twin_matches_legacy_directly` all pass via strict Python string equality (`==`) on `json.dumps(..., sort_keys=True)` normalized output — not a fuzzy/subset comparison. Both resolutions independently pass the unchanged `delivery_config.schema.yaml` (`legacy_passes_schema`, `twin_passes_schema`). |
| 5 | One command produces a published delivery matrix (deliveries × reports × schedule × filters × owner) covering every delivery, without opening any YAML | VERIFIED | `python scripts/generate_delivery_matrix.py --config tests/fixtures/phase20_config_twin/contacts.yaml` (live run) produced a Markdown table with all 3 deliveries, each row showing Delivery/Owner/Reports/Schedule/Filters/Contact — no recipient addresses. `--format html` and `--help` also exercised live. 14/14 checks in `tests/test_generate_delivery_matrix.py` pass, including the PII invariant (0 `@example.invalid` occurrences in either output format). |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `delivery/config_loader.py` | `resolve_config`/`resolve_contacts`/`resolve_delivery_email`, ≥120 lines | VERIFIED | 312 lines. All three functions present, exported, exercised by 20 passing checks. No bare `yaml.load(` (only `yaml.safe_load`). |
| `tests/test_config_loader.py` | ≥80 lines, unit tests for CONF-01/02/03 | VERIFIED | 449 lines, 20/20 checks pass (run live: `.venv/bin/python tests/test_config_loader.py`). |
| `contacts.example.yaml` | Contacts+defaults only, `example.invalid` | VERIFIED | 40 lines. Contains `contacts:` + `defaults.analyst_mailbox`; no `deliveries:`/`groups:` key; one contact overrides `reply_to` (exec_team), one doesn't (remediation_team). |
| `run_all.py` (`_dry_run` extension) | Surfaces loader errors/warnings, exit code flip | VERIFIED | Live-tested against the real `ROOT_DIR` config path with a temporary `deliveries.d/` + duplicate name: prints red error, exits 1 (confirmed via captured exit code, not just piped output). Repo state confirmed clean/unchanged afterward. |
| `scripts/generate_delivery_matrix.py` | Standalone CLI, ≥90 lines, `--format`/`--output` | VERIFIED | 285 lines. `--help` shows `--format {markdown,html}`, `--output`, `--config`, `--verbose`. Imports only the config loader — no fetcher import (grep confirms no `fetchers`/`tenable_client` import). |
| `tests/test_generate_delivery_matrix.py` | ≥40 lines, coverage+PII+side-channel+format tests | VERIFIED | 223 lines, 14/14 checks pass live. |
| `tests/baselines/effective_config_golden.json` | Committed normalized golden, `groups` key | VERIFIED | Valid JSON, 3 groups, no `owner`/`contact` keys on any group dict, only `@example.invalid` addresses. |
| `tests/test_effective_config_golden.py` | ≥60 lines, two-way equality gate | VERIFIED | 147 lines, 13/13 checks pass live. `_REGENERATE = False` confirmed (not left in write-mode). |
| `tests/fixtures/phase20_config_twin/contacts.yaml` | Migrated-twin contacts+defaults source | VERIFIED | Present, parses, contains `defaults`, referenced correctly by the golden test. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `run_all.py::_load_config` | `delivery/config_loader.py::resolve_config` | Directory-mode delegation | WIRED | `run_all.py:179-180` calls `resolve_config(config_path)` when `deliveries.d/` exists next to `config_path`; unpacks 4-tuple, discards metadata. Confirmed by reading the source and by `tests/test_config_loader.py` checks K/L/M. |
| `delivery/config_loader.py::resolve_config` | `run_all.py::_validate_with_schema` | Resolved config gated by unchanged schema | WIRED | `run_all.py:189-196` runs `{"groups": groups}` through `_load_schema()` + `_validate_with_schema` before returning. `delivery_config.schema.yaml` confirmed byte-unchanged across the entire Phase 20 commit range (`git log 90966df..HEAD -- delivery_config.schema.yaml` returns empty). |
| `run_all.py::_dry_run` | `delivery/config_loader.py::resolve_config` | Directory-mode error/warning surfacing | WIRED | `run_all.py:473-483`. Live-exercised against `ROOT_DIR`: duplicate-name error printed in red, exit code 1 captured directly (not inferred). |
| `scripts/generate_delivery_matrix.py` | `delivery/config_loader.py::resolve_config` | Loader reuse for resolved config + metadata side channel | WIRED | Script imports `from delivery.config_loader import resolve_config` and sources owner/contact exclusively from `metadata_by_delivery_name`, confirmed by live run showing owner/contact values that only exist in the metadata side channel (group dicts carry no such keys, confirmed by golden + config_loader tests). |
| `tests/test_effective_config_golden.py` | `delivery/config_loader.py` + `run_all.py::_load_config` | Resolve both fixtures, normalize to JSON | WIRED | Test imports `resolve_config`, `_load_config`, `_load_schema`, `_validate_with_schema` and exercises all of them; 13/13 checks pass. |
| `scheduler.py` | `run_all.py::_load_config` | Hot-reload entry point, unchanged | WIRED (unmodified) | `git diff --stat scheduler.py` shows no changes; last commit touching it (`ef0f509`) predates Phase 20. `_load_config` preserves its `list[dict]` return contract in both modes. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| CONF-01 | 20-01 | Named contact groups in `contacts.yaml`, referenced by `contact: <key>` | SATISFIED | `resolve_delivery_email` looks up `contacts_by_name`; live-tested contact-name resolution and single-point-of-edit propagation. |
| CONF-02 | 20-01 | `defaults.analyst_mailbox` resolved pre-schema as standing Cc + default Reply-To; `extra_recipients` additive | SATISFIED | Live resolution confirms Cc/Reply-To behavior + override; `D_extra_recipients_merge_dedupe` check passes. |
| CONF-03 | 20-01, 20-02 | `deliveries.d/` directory, one file per team, global uniqueness, `groups:`→`deliveries:` deprecated alias | SATISFIED | Live duplicate-name rejection via both `resolve_config` directly and the real `run_all.py --dry-run` CLI; `J_deprecated_groups_alias_warns_and_loads` check passes. |
| CONF-05 | 20-03 | Delivery matrix (deliveries × reports × schedule × filters × owner), markdown default / HTML optional | SATISFIED | Live run of `scripts/generate_delivery_matrix.py` produces the full matrix; PII invariant enforced and tested. |
| QUAL-06 | 20-04 | Effective-config golden test, two-way equality (legacy ≡ golden ≡ migrated twin) | SATISFIED | `tests/test_effective_config_golden.py` 13/13 checks pass, strict string-equality comparison, both fixtures independently pass the unchanged schema. |

No orphaned requirements — REQUIREMENTS.md maps exactly CONF-01/02/03/05 and QUAL-06 to Phase 20, and all five appear in plan frontmatter `requirements:` fields. CONF-04 and QUAL-07 are correctly scoped to Phase 21 (not claimed by any Phase 20 plan).

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `scripts/generate_delivery_matrix.py` | 206-209 | `render_html` interpolates cell values without `html.escape()` | ⚠️ Warning | Operator-controlled strings (delivery name, owner, filters, contact) containing `&`/`<`/`>` could corrupt or inject markup into the published matrix artifact. Flagged in 20-REVIEW.md (WR-01), confirmed still present in code at verification time. Non-blocking: does not affect the stated roadmap success criteria; matrix content and PII invariants still hold in the common case. |
| `scripts/generate_delivery_matrix.py` | 191-192 | `render_markdown` does not escape literal `\|` in cell values | ⚠️ Warning | A delivery name/owner/filter value containing a pipe character would silently break the Markdown table structure. Flagged in 20-REVIEW.md (WR-02), confirmed still present. Non-blocking for the same reason as above. |
| `delivery/config_loader.py` | 276-283 | Inline `email.cc`/`email.reply_to` (without `recipients`) silently dropped in directory mode with no error or warning | ⚠️ Warning | Violates the phase's "surface everything loudly" intent for a narrow edge case (an operator who writes `email: {cc: [...]}` with no `recipients` gets no feedback). Flagged in 20-REVIEW.md (WR-03), confirmed still present. Does not affect any of the 5 roadmap success criteria as stated. |
| `run_all.py` | 452, 473 | `_dry_run` hardcodes `ROOT_DIR / "delivery_config.yaml"`; no `--config` CLI flag exists on `run_all.py` | ⚠️ Warning | Confirmed live: `run_all.py --dry-run --config <path>` errors with "unrecognized arguments." The dry-run surfacing (Plan 20-02's deliverable) only inspects the fixed prod-adjacent path; it cannot be pointed at an arbitrary `deliveries.d/` location via CLI (only via direct Python `config_path=` kwarg, which is how the plan's own tests validate it). Flagged in 20-REVIEW.md (WR-04), confirmed still present. Functionally verified working correctly against the real `ROOT_DIR` path in this verification (duplicate-name error → exit 1, cleanly reverted). Non-blocking: SC3's actual observable claim ("adds a new report... loader globs and merges... rejects with a clear error") is satisfied at the `resolve_config`/`_load_config` layer, which is config-path-agnostic; the CLI ergonomics gap only affects testing convenience against non-standard config locations, which Phase 21 (CODEOWNERS/CI cutover) will need to address when it wires the `shared/` symlink layout. |

No 🛑 Blocker anti-patterns and no unreferenced debt markers (`TBD`/`FIXME`/`XXX`) found in any file touched by this phase.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Contact edit propagates without delivery-file edit | Fresh scratchpad fixture, edit `contacts.yaml`, re-resolve | `recipients` changed from `old@example.invalid` to `new@example.invalid` with zero delivery-file edits | ✓ PASS |
| Duplicate delivery name rejected at `resolve_config` layer | Fresh scratchpad fixture, two team files, same delivery name | `errors=['duplicate delivery name: ...']`, `groups=[]` | ✓ PASS |
| Duplicate delivery name rejected via real CLI (`run_all.py --dry-run`) | Temporary `deliveries.d/` + `contacts.yaml` next to the real `delivery_config.yaml`, then removed | Red error printed, captured exit code = 1, repo state confirmed clean afterward | ✓ PASS |
| Matrix generator produces full matrix from one command | `python scripts/generate_delivery_matrix.py --config tests/fixtures/phase20_config_twin/contacts.yaml` | Markdown table, 3 rows, all columns populated, exit 0 | ✓ PASS |
| `test_config_loader.py` (20 checks) | `.venv/bin/python tests/test_config_loader.py` | All 20 PASS | ✓ PASS |
| `test_generate_delivery_matrix.py` (14 checks) | `.venv/bin/python tests/test_generate_delivery_matrix.py` | All 14 PASS | ✓ PASS |
| `test_effective_config_golden.py` (13 checks) | `.venv/bin/python tests/test_effective_config_golden.py` | All 13 PASS | ✓ PASS |
| `delivery_config.schema.yaml` unchanged across Phase 20 | `git log 90966df..HEAD -- delivery_config.schema.yaml` | Empty (no commits) | ✓ PASS |
| `scheduler.py` unchanged | `git diff --stat scheduler.py` | Empty | ✓ PASS |

Note: `pytest` collection intentionally excludes these three test files (`pytest.ini` `testpaths = tests/unit tests/content tests/e2e`), matching the pre-existing precedent for config-tests (`test_phase4_schema_validation.py`). Standalone invocation is the documented and correct verify path, and was used above.

### Human Verification Required

None. All five observable truths were independently reproduced with live commands against both the committed fixtures and freshly constructed scratch fixtures — no visual, real-time, or external-service behavior in this phase requires human judgment.

### Gaps Summary

No gaps. All 5 roadmap success criteria are verified with live evidence (not merely SUMMARY claims), all required artifacts exist/are substantive/are wired, all key links are wired, and all 47 automated checks across the three phase test harnesses pass in the project venv. The code review's 4 warnings (WR-01 through WR-04) were independently re-confirmed as still present in the code at verification time — they are legitimate robustness/UX gaps but none of them break any of the phase's 5 stated success criteria, so they do not block phase completion. They are appropriate candidates for a backlog item ahead of the Phase 21 CI-gate/cutover work, since WR-04 in particular (`--dry-run` has no `--config` override) will matter once Phase 21 wires CI against the `shared/` symlink layout.

---

*Verified: 2026-07-09T20:40:58Z*
*Verifier: Claude (gsd-verifier)*
