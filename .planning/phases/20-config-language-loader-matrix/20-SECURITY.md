---
phase: 20
slug: config-language-loader-matrix
status: verified
threats_open: 0
asvs_level: 1
created: 2026-07-09
---

# Phase 20 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

**Verdict:** SECURED — 16/16 threats CLOSED, 0 open, 0 unregistered flags.
**Auditor stance:** FORCE (every mitigation assumed absent until proven present in code).
Threat register was authored at plan time and is treated as COMPLETE. This audit
VERIFIES each declared mitigation exists in implemented code; it does not scan for
new vulnerabilities. Implementation files were not modified.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| operator-authored YAML → loader | `contacts.yaml` + `deliveries.d/*.yaml` parsed at startup | malformed/hostile YAML |
| filesystem directory discovery → glob | `deliveries.d/` contents globbed and read | path-traversal / unexpected files |
| resolved config → schema gate | resolved effective config into the Draft7 validator | recipient/group config |
| resolved error/warning strings → console (`--dry-run`, CI artifact) | dry-run output consumed by operators + future Phase 21 CI gate | error/warning text |
| matrix output → published CI artifact | delivery matrix published on merge (Phase 21) | contact/group names + owner (no addresses) |
| fixture YAML → resolver under test / golden JSON → committed artifact | synthetic fixtures resolved through the real loader; golden is a reviewable diff | synthetic (`example.invalid`) config |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-20-01 | Tampering | YAML deserialization in `config_loader.py` | mitigate | `yaml.safe_load` at `config_loader.py:226,243`; grep confirms zero `yaml.load(` in module | closed |
| T-20-02 | Tampering | `deliveries.d/` glob discovery | mitigate | Glob restricted to `deliveries_dir.glob("*.yaml")` (`:240`); dir = `config_path.parent / "deliveries.d"` (`:207-208`) — no `..`/absolute path accepted | closed |
| T-20-03 | Denial of Service | malformed team file / missing `contacts.yaml` | mitigate | Fail-loud-never-raise: `errors.append(...)` + `return []` throughout; `yaml.YAMLError` caught (`:227,244`); verified inert on nonexistent path, no exception | closed |
| T-20-04 | Information disclosure | resolved `email:` recipients in logs/errors | accept | Error strings reference contact-key / delivery / file / path only, never addresses (`:219-220,260,264,269,279-294`); see Accepted Risks Log | closed |
| T-20-05 | Repudiation | silent duplicate delivery names | mitigate | Global uniqueness across files; collision error names delivery + both files (`:284-290`); exercised by `tests/test_config_loader.py` | closed |
| T-20-06 | Information disclosure | error strings printed by `--dry-run` | mitigate | Directory-mode block prints only loader error/warning strings (`run_all.py:474-485`); no `email.recipients` emitted | closed |
| T-20-07 | Tampering | `contacts.example.yaml` copy-to-prod template | mitigate | `@example.invalid` sole domain; header (`:1-16`) instructs replacement before going live | closed |
| T-20-08 | Elevation of privilege | `--dry-run` triggering live Tenable fetch | mitigate | Block calls only `resolve_config` (`run_all.py:474`); no fetcher/`tenable_client` invoked (Hard Rule 1) | closed |
| T-20-09 | Information disclosure | matrix artifact leaking real mailboxes | mitigate | `_matrix_rows` sources owner+contact from `metadata_by_delivery_name` only (`generate_delivery_matrix.py:162-178`); test asserts 0 addresses in md+html (`test_generate_delivery_matrix.py:158-179`, 14/14 pass) | closed |
| T-20-10 | Tampering | YAML parse in loader the script reuses | mitigate | Script reuses Plan-01 loader (`:40`); no independent YAML parsing | closed |
| T-20-11 | Elevation of privilege | script triggering live Tenable fetch | mitigate | Only first-party import is `resolve_config` (`:40`); no `data.fetchers`/`tenable_client` (Hard Rule 1) | closed |
| T-20-12 | Denial of Service | malformed config crashing script | mitigate | Loader errors surfaced to log + `return 3`, never raised (`generate_delivery_matrix.py:257-261`) | closed |
| T-20-13 | Information disclosure | golden JSON / fixtures leaking real recipient config | mitigate | Golden + all fixtures use `@example.invalid` exclusively; golden carries no `owner`/`contact` keys (HIGH priority given two prior scrubs — clean) | closed |
| T-20-14 | Tampering | hand-authored golden drifting from resolver output | mitigate | Golden machine-generated via `_REGENERATE` (`test_effective_config_golden.py:58-61,100-102`); two-way equality legacy==golden AND twin==golden (`:106-119`) + schema pass (`:134-135`) | closed |
| T-20-15 | Tampering | YAML parse of fixtures | mitigate | Golden test resolves via `_load_config`/`resolve_config` (`:45-46,82,87`); no bare `yaml.load(` in any phase-20 test | closed |
| T-20-SC | Tampering | npm/pip/cargo installs | mitigate | `requirements.txt` unchanged in phase 20 (last edit phase 05); no new dependency (Hard Rule 8) | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-20-01 | T-20-04 | Config is internal and pre-auth; residual disclosure surface is nil in practice — loader error/warning strings reference contact-key names, delivery names, source filenames, and filesystem paths only, never expanded recipient addresses (verified `config_loader.py:219-220,260,264,269,279-294` and `run_all.py:474-485`). No address is logged. | gsd-security-auditor (per plan disposition) | 2026-07-09 |

*Accepted risks do not resurface in future audit runs.*

---

## Unregistered Flags

None. No `## Threat Flags` section appeared in any of the four phase-20 SUMMARY
files — no new attack surface was flagged during implementation.

---

## Notes

- Implementation files were READ-ONLY throughout this audit; none were modified.
- Mitigations were exercised, not just grepped: `tests/test_config_loader.py`,
  `tests/test_generate_delivery_matrix.py`, and `tests/test_effective_config_golden.py`
  all pass through the project venv, covering duplicate-name uniqueness, the PII
  invariant, side-channel sourcing, and two-way golden equality.
- The `--dry-run` legacy rich Table (`run_all.py:501-535`) does render recipient
  addresses to the console, but that is pre-existing single-file behavior outside
  Phase 20's threat scope; T-20-06 is scoped to the loader error/warning strings
  printed by the directory-mode surfacing block, which carry no addresses.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-09 | 16 | 16 | 0 | gsd-security-auditor (verify mitigations; register authored at plan time) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-09
