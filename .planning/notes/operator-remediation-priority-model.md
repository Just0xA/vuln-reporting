---
title: Operator Remediation Priority Model
date: 2026-05-14
context: Captured during /gsd-explore conversation on the modular Operator Remediation Report (successor to ops_remediation). Documents the durable prioritization logic and data-sourcing decisions independent of implementation.
---

# Operator Remediation Priority Model

The IT Operators responsible for vulnerability remediation work from a layered priority model. This note records the model itself so any future module, report, or filter that needs to mirror operator priorities has a single source of truth — independent of how the modular framework eventually realizes it.

## Three pillars of operator information need

An operator looking at a remediation queue needs to answer three questions, in this order:

1. **What needs priority?** — which finding/asset should I work on first?
2. **How do I resolve it?** — is this a patch, a configuration change, a workaround, or unfixable?
3. **Which systems need it?** — what is the affected-asset footprint of the fix I'm about to apply?

Every operator-facing module should map cleanly to one (or more) of these three pillars.

## Priority hierarchy

Priorities are evaluated **top-down**. Higher tiers always outrank lower tiers regardless of count.

### Tier 1 — Exposure: externally-facing first

Externally-facing assets jump the queue. An asset is considered external when **either** of the following is true:

- The asset carries the Tenable tag `Location=External` or `Location=DMZ`.
- The asset's `ipv4` address is **outside** the RFC 1918 private space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). For completeness, CGNAT (`100.64.0.0/10`), loopback (`127.0.0.0/8`), and link-local (`169.254.0.0/16`) are also treated as non-external.

The org's network policy disallows dual-homed systems (no host is both directly internet-attached and on the internal network), so the public-IP heuristic is reliable on its own. The tag is the explicit override and the public-IP check is the safety net.

### Tier 2 — Environment ordering for change management

Within the same priority bracket, change management dictates the rollout order:

> **Dev → Non-Prod → Prod**

This is a remediation **sequencing** rule, not a deprioritization of Prod. Prod findings still drive priority — operators just patch Dev first to validate the change before promoting it.

The environment is derived from the Tenable `Environment` tag.

### Tier 3 — Risk flags (top-of-list within an environment)

Findings carrying any of the following risk flags are top-priority within their environment:

- **VPR score = 10** — Tenable's maximum priority signal.
- **CISA Known Exploited Vulnerabilities (KEV)** — `plugin.vpr_v2.on_cisa_kev = true`.
- **Threat Intel watchlist** — CVEs the internal Threat Intel team has flagged as priority. See [Threat-intel intake](#threat-intel-intake) below for sourcing.

### Tier 4 — Aged Critical / High

Critical or High findings (VPR ≥ 7.0) open for **more than 90 days**. These exceed every SLA the program tracks and represent accumulated risk that has aged past acceptable tolerance.

### Tier 5 — Fallback ordering

Everything else is ranked by:

1. **VPR score**, descending.
2. **Affected asset count**, descending — a finding affecting 200 hosts outranks one affecting 5.

## Fix-type classification (Pillar 2)

The "How do I resolve it" pillar uses Tenable plugin fields to bucket each finding:

| Bucket | Derivation |
|--------|------------|
| Patch available | `plugin.has_patch = true` and `plugin.vendor_unpatched = false` |
| Workaround only | `plugin.has_workaround = true` and `plugin.has_patch = false` |
| Configuration change | `plugin.has_workaround = true` and `plugin.workaround_type = "Configuration Change"` |
| Disable service | `plugin.has_workaround = true` and `plugin.workaround_type = "Disable Service"` |
| No fix available | `plugin.vendor_unpatched = true` and no workaround |

> ⚠️ Reliability of these fields across plugin families is an **open research question** — see `.planning/research/questions.md`. For some families the `solution` text may need regex inspection as a fallback.

## Threat-intel intake

### Today (email-driven)

The Threat Intel team sends an email to the Vulnerability Management team identifying CVEs that need elevated priority. The Vuln Team then generates one-off reports and distributes them to the responsible operator groups.

**Reporting-pipeline implication:** until the migration described below ships, the operator report needs an operator-maintained intake file (e.g. `config/threat_intel_priority_cves.yaml`) that the Vuln Team updates whenever a new email arrives. The priority module reads this file at run time and ORs its CVE list into the Tier-3 risk flags.

### Future (Teams + Tenable tags)

The target state is for Threat Intel signals to flow through a Teams channel and to be reflected as Tenable tags on the affected findings/assets. When that ships, the operator report swaps its data source from the local YAML to a Tenable tag query — the module's prioritization logic is unchanged. See the seed [`threat-intel-tag-migration.md`](../seeds/threat-intel-tag-migration.md) for the trigger conditions.

## Field references

All field names above match the Tenable Vulnerability Export schema. Field definitions are in [`docs/tenable_vuln_api_reference.md`](../../docs/tenable_vuln_api_reference.md).

## Related artifacts

- Seed: [`threat-intel-tag-migration.md`](../seeds/threat-intel-tag-migration.md)
- Research question: fix-type classification reliability (see `.planning/research/questions.md`)
- Phase: Operator Remediation Report v2 (see `ROADMAP.md`)
- Current implementation being replaced: `reports/ops_remediation.py`
