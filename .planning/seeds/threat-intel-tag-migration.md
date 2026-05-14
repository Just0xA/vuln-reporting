---
title: Migrate Threat-Intel CVE Source from Local YAML to Tenable Tag
trigger_condition: When the Vulnerability Management / Threat Intel teams roll out the Teams-channel + Tenable-tag workflow for flagging priority CVEs, and assets/findings begin carrying the agreed tag (e.g. `Priority=ThreatIntel` or `ThreatIntel=Priority`) reliably enough to be authoritative.
planted_date: 2026-05-14
---

# Migrate Threat-Intel CVE Source to Tenable Tag

## Background

The Operator Remediation Report's priority model (see [`../notes/operator-remediation-priority-model.md`](../notes/operator-remediation-priority-model.md)) includes a Tier-3 "Threat Intel watchlist" signal alongside VPR=10 and CISA KEV.

Today this list lives in operator emails curated by the Vuln Team. The interim intake is an operator-maintained file (`config/threat_intel_priority_cves.yaml`) updated when emails arrive.

The Vuln Team's target state is to route Threat Intel callouts through a Teams channel and reflect them as **Tenable tags** on the affected assets or findings. Once that workflow is in place and the tags become the system of record, the operator report should switch its data source to read from Tenable directly.

## What this seed triggers

When the trigger condition is met:

1. Confirm the agreed tag key/value (likely `Priority=ThreatIntel` or `ThreatIntel=true` — final naming owned by the Vuln Team).
2. Update the threat-intel module's lookup to source CVEs from the Tenable tag query instead of `config/threat_intel_priority_cves.yaml`.
3. Either deprecate the YAML intake or keep it as a manual-override fallback (decision deferred — depends on how trusted the tag workflow turns out to be in practice).
4. Update [`operator-remediation-priority-model.md`](../notes/operator-remediation-priority-model.md) "Threat-intel intake" section to reflect the new state.

The **priority logic itself does not change** — only the data source. This is why the intake was abstracted out from the start.

## Why this is a seed and not a phase

The trigger depends on an external team's roadmap, not ours. The implementation is small (swap a data source). Capturing it as a seed prevents the work from getting lost when the migration finally happens, without committing scope before the upstream signal exists.
