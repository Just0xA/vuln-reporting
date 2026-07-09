# Milestone Spec — Validation Substrate (VAL)

**Slot (settled 2026-07-02, renumbered rev-d):** **v1.7**, between v1.6 (Delivery Config
at Scale) and v1.8 (Findings History Store) — integrated into `roadmap-milestones-v1.6-v2.0.md`
rev. 2026-07-02c, which owns numbering and sequencing; this spec is authoritative
for requirement detail. Sequenced before the history store because Spike 004 is
this milestone's first major consumer — the longitudinal synthetic dataset is
exactly the parity test bed the spike needs. Candidate phases 22–25.

**Drafted:** 2026-07-02, from the anonymized-cache viability discussion.

---

## Goal

Give the project a committable, realistic, fully synthetic Tenable dataset and a
mechanically enforced offline mode, so that Claude Code (and CI) can validate the
entire pipeline — fetcher consumers, modules, composers, exporters, delivery dry
paths — against a known data set with **zero** live Tenable pulls and **zero** real
records anywhere in version control.

**Core value:** Full-pipeline validation without live data — the no-live-pull policy
enforced in code, not just in the hook.

## Design decision (record in PROJECT.md Key Decisions)

**Synthetic generation from an aggregate profile — NOT anonymization of real
records.** Record-level anonymized data still encodes the institution's actual
exposure profile (CVE/plugin distribution across ~40k assets is threat intelligence
even with every identifier scrubbed), so it could never be committed, which defeats
the purpose. The committed artifacts are limited to: (a) a structural schema
manifest, (b) an aggregate-only statistical profile (D-04-08-compliant, human-
reviewed, optionally fuzzed), and (c) generator code. All synthetic records are
fabricated at build/test time from those inputs plus public Tenable plugin
dictionary data.

## Non-goals / out of scope

- Anonymized copies of real cache data, in any form, committed or "temporarily" shared (explicitly rejected — see decision above)
- Synthetic SMTP/delivery endpoints beyond what `tests/smtp_catcher.py` already provides
- Load/performance testing at full 40k-asset scale in CI (generator must *support* full scale for local use; CI runs a reduced-scale profile)
- Compliance-findings synthesis (belongs to the v2.0 milestone; the generator should be structured so a second dataset family can be added, but building it now is scope creep)

---

## Requirements

| ID | Requirement |
|----|-------------|
| VAL-01 | **Schema manifest.** Profiler extracts a structural manifest from a real cache — per-dataset column names, dtypes, nullability, and categorical value *domains only where non-sensitive* (e.g., severity labels, state enums; never hostnames/plugin sets). Committed as `tests/synthetic/schema_manifest.json`. Structural metadata only; this is the fidelity anchor. |
| VAL-02 | **Profiler (human-run, prod only).** `scripts/profile_cache.py` reads `data/cache/<date>/` parquet and emits an aggregate-only statistical profile: severity/VPR distributions, findings-per-asset shape, plugin-family frequencies, tag-taxonomy structure (category/value counts, not values where values are sensitive), first_found age spread, reopened rate, fixed/open ratios, asset OS/type mix. Includes `--fuzz` (rounding + noise) for anything deemed too revealing. Output goes through a **mandatory human PII review** (checklist in the script's docstring) before commit. The profiler is a live-data-adjacent script: added to the hook's GUARDED_ALWAYS set even though it reads local parquet only — Claude Code never runs it; defense in depth. |
| VAL-03 | **Generator.** `tests/synthetic/generate.py` — seeded, deterministic — consumes manifest + profile and fabricates a complete synthetic cache (`vulns`, `assets`, `tags`, `fixed_vulns`, `recast_rules` parquet) that validates against the manifest exactly. Plugin IDs/names/families/CPEs drawn from public Tenable plugin dictionary data (committed subset, provenance documented). Generator provenance rule: its only inputs are manifest, profile, public dictionaries, and the seed — it must have no code path that reads `data/cache/`. Scale is a parameter (CI profile ~2k assets; local full-scale supported). |
| VAL-04 | **Longitudinal simulation.** The generator models finding lifecycles as events (open → fix → reopen) across a configurable N-month window, matching the profiled reopened rate (~19%) and age distributions, and can emit (a) a point-in-time cache "as of date D" and (b) a daily/weekly series of caches. This is what exercises `open_findings_at()`, MoM modules, cold-start branches — and is Spike 004's parity dataset. A bootstrap hand-authored profile ships with the milestone so generator development is not blocked waiting on the human profiler run (VAL-02); the real profile replaces it when reviewed. |
| VAL-05 | **Offline mode.** `--offline` flag on `run_all.py`/`scheduler.py` plus `VULN_REPORTING_OFFLINE=1` env equivalent. Two enforcement layers: `tenable_client.get_client()` refuses and exits non-zero when offline is set (the existing credential chokepoint becomes the offline chokepoint too); fetchers raise a clean `CacheMissError` on cache miss instead of falling through to the API. A `--cache-dir` override lets tests point at a synthetic cache directory without touching `data/cache/`. |
| VAL-06 | **Hook allowance.** `.claude/hooks/block_tenable_fetch.py` allows `run_all.py --offline` (same per-segment flag detection as `--dry-run`), verified the same way the dry-run exemptions were: by reading the code path and confirming the refusal executes pre-auth. New CR-C4 test group extends `tests/test_block_tenable_fetch.py`: offline allowed; offline + a second guarded segment still denied; `--offline` on scripts without a verified offline path still denied; env-var form does NOT exempt (the hook can't see the child environment reliably — flag form only). |
| VAL-07 | **Integration harness.** Pytest marker (`-m synthetic`) suite that generates (or reuses a cached build of) the synthetic dataset, runs the full report suite offline for representative groups (one legacy slug, one modular slug, one composed group, one filtered-to-zero group), and asserts **structural** goldens: bundle keys present, sheet/tab inventories, PDF page counts, email-panel presence, RAG strip shape — not pixel or byte parity (synthetic content differs run-to-run only if the seed changes; goldens pin the seed). Wired into CI at the reduced scale. |
| VAL-08 | **Fidelity maintenance.** Quarterly human-run check: regenerate the manifest + profile from current prod cache, diff against committed versions, and run the structural-comparison suite against both real and synthetic caches on the prod-adjacent box (Phase 18 structural-baseline playbook, repurposed). Documented in RUNBOOK.md with a calendar owner. Manifest drift (Tenable adds/renames export fields) fails loudly in the generator, not silently in reports. |
| VAL-09 | **PII gates.** (a) Profiler output review checklist committed alongside the script; (b) a CI test asserting the committed profile contains no record-level arrays and no fields from a denylist of identifier column names; (c) generator provenance rule from VAL-03 enforced by a conformance test (no `data/cache` literals or path derivations in `tests/synthetic/`); (d) synthetic hostnames/IPs drawn from reserved ranges (RFC 5737/3849 addresses, `.example`/`.test` domains) so a leak of synthetic data is self-evidently synthetic. |
| VAL-10 | **Docs + Hard Rules.** CLAUDE.md Hard Rule 1 amended: `run_all.py --offline` joins the permitted invocations, with the enforcement rationale (get_client refusal is pre-auth, code-verified). GLOSSARY entries: *synthetic cache*, *schema manifest*, *offline mode*, *profile*. RUNBOOK gains the profiler procedure and quarterly fidelity check. `docs/synthetic_data.md` documents the profile fields and what each drives in the generator — the auditor-runbook practice applied to test data. |

---

## Phases (candidate; numbering assigned at plan time)

1. **Phase A — Manifest + profiler tooling** (VAL-01, VAL-02, VAL-09a/b)
   Builds the tools; ends at a **human checkpoint**: operator runs the profiler on
   prod, completes PII review, commits manifest + profile. Not a blocker for
   Phase B thanks to the bootstrap profile.
2. **Phase B — Generator + longitudinal model** (VAL-03, VAL-04, VAL-09c/d)
   Developed against the bootstrap profile; re-validated against the real profile
   when it lands. Exit gate: generated cache round-trips through every fetcher
   consumer's load path without error at CI scale and full scale.
3. **Phase C — Offline mode + hook** (VAL-05, VAL-06)
   The code-enforcement phase. Exit gate: CR-C4 suite green; manual verification
   that `run_all.py --offline --group X` against a deliberately cold cache dir
   exits via `CacheMissError` with zero network egress (verify on the dev box with
   the proxy logs or an egress-denied environment).
4. **Phase D — Integration harness + CI + docs** (VAL-07, VAL-08, VAL-10)
   Exit gate: `-m synthetic` suite green in CI; docs merged; quarterly check
   scheduled with an owner.

**Dependency note:** Phases A/B and Phase C are independent and parallelizable;
Phase D needs both. If the milestone must ship value early, Phase C alone
(offline mode + hook) is independently useful — it upgrades what Claude Code can
do with a *real* warm cache on the prod-adjacent box, today.

## Verification / exit criteria (milestone)

- Claude Code, on a fresh clone with the hook active, can: generate the synthetic
  cache, run the full report suite offline, and run the `-m synthetic` harness —
  with zero hook denials and zero network egress.
- No committed artifact contains a real hostname, IP, MAC, UUID, plugin-to-asset
  association, or record-level data of any kind (VAL-09 checks green + human
  review sign-off recorded in the milestone audit).
- Spike 004 (history store) declares this dataset sufficient for its parity work,
  or files concrete generator gaps as requirements — the spike is the acceptance
  test for VAL-04.
- Structural goldens stable across two consecutive CI runs at pinned seed.

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Schema fidelity drift → false confidence (the worst failure mode) | VAL-01 manifest as hard anchor; generator fails loudly on mismatch; VAL-08 quarterly real-vs-synthetic structural comparison |
| Profile judged too revealing even in aggregate | `--fuzz` (VAL-02); worst case the profile stays uncommitted on the prod box and only the bootstrap profile is public — generator realism degrades but nothing else breaks |
| Generator over-fits to current reports (only produces data shapes today's modules read) | Round-trip gate in Phase B runs *fetcher consumers*, not report expectations; manifest covers all exported columns, not just consumed ones |
| Offline flag detection gap in the hook (env-var form, wrapper nesting) | Flag-form-only exemption (VAL-06); CR-C4 adversarial cases; the get_client() refusal is the real enforcement — the hook is defense in depth |
| Longitudinal model too naive for Spike 004 | Spike 004 is named the acceptance test; gaps become VAL follow-ups before the spike verdict, not after |

## Key decisions to record at milestone open

1. Synthetic-from-profile over anonymized-real (rationale above).
2. `--offline` exemption added to the hook: the enforcement moves into
   `get_client()`; the hook's role for this path is belt-and-braces.
3. Public Tenable plugin dictionary subset committed to the repo (provenance +
   license note in `docs/synthetic_data.md`).

## Interaction with the existing roadmap

- **v1.8 History Store:** Spike 004 consumes VAL-04's longitudinal series; the
  parity harness (HIST-03) reuses the synthetic fixtures. This is why VAL slots
  first.
- **v1.10 Render Layer:** REN-05/06 per-module parity migrations get a stable
  offline test bed instead of hand-built fixtures.
- **Hook/harness:** VAL-02's profiler joins GUARDED_ALWAYS; the CR-C3 coverage
  test's exemption table gains `generate.py` (never touches tenable_client at
  all — should not even import it; conformance-checked).
