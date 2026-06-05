# Spike Manifest

## Idea

A CPE-based **Vuln Type Distribution** report module that splits open vulnerabilities into **Application / Operating System / Hardware** buckets for executive leadership. The buckets map 1:1 onto remediation teams (App Support + BU, Operations, Data Center), so the metric exposes where serious risk concentrates and — via month-over-month trend — where remediation is keeping pace vs slipping. Headline volume = VPR Critical+High open count per bucket, rendered as three RAG tiles. Design record: [`../notes/vuln-type-distribution-module.md`](../notes/vuln-type-distribution-module.md).

## Requirements

Design decisions that emerged during spiking. Non-negotiable for the real build.

- **Classifier is `plugin_family` override → CPE prefix → Unclassified**, NOT CPE alone. CPE-prefix gives 99.2% coverage but mis-assigns ~6% of OS-team work (Linux distro Local Security Checks carry `cpe:/a:`).
- **Volume unit = VPR Critical+High open count** per bucket (mirrors `config.vpr_to_severity`).
- **Classifier must be unit-tested** against a labelled sample of family/CPE combinations — a ~6% volume swing between App and OS tiles rides on it.
- **Open human decision (requestor/team leads):** do Microsoft patch-Tuesday Bulletins (~2,500 Crit+High `{a,o}` findings) belong to App Support or Operations? This is policy, not code.
- **Hardware tile is ~0 today** — confirm hardware/firmware scan scope before promising a 3-tile design; consider hiding the Hardware tile when empty.
- **Trend has a cold start** — ship balance-now; monthly per-bucket snapshots accumulate the MoM axis over subsequent months.

## Spikes

| # | Name | Type | Validates | Verdict | Tags |
|---|------|------|-----------|---------|------|
| 001 | cpe-coverage-crit-high | standard | CPE-prefix classification of Crit+High is high-coverage AND team-ownership-accurate enough to drive the exec metric | ⚠ PARTIAL — CPE backbone validated (99.2% coverage), pure-CPE rejected; plugin_family override required | cpe, classification, vpr, plugin-family, exec-metric |
