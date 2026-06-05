---
title: Vuln Type Distribution Module (Application / OS / Hardware)
date: 2026-06-05
context: Captured during /gsd-explore conversation on a CPE-based report module that splits open vulnerabilities into Application / Operating System / Hardware buckets for executive leadership. Documents the durable design decisions and open questions independent of implementation.
---

# Vuln Type Distribution Module (Application / OS / Hardware)

A requestor wants an executive-facing metric showing how vulnerabilities distribute across **Application**, **Operating System**, and **Hardware**, derived from **CPE data**. The split is meaningful because it maps 1:1 onto the remediation teams:

| Bucket | CPE prefix | Owning team(s) |
| ------ | ---------- | -------------- |
| Application | `cpe:/a:` | App Support + Business Unit groups |
| Operating System | `cpe:/o:` | Operations |
| Hardware | `cpe:/h:` | Data Center support |

The goal is to help leadership **see gaps in remediation efforts** by exposing where serious risk concentrates and whether each team's share is moving in the right direction.

## Decisions reached in exploration

1. **Primary story = volume imbalance.** The headline is *where the risk concentration lives* across the three buckets — not (initially) SLA velocity or accountability framing, though the per-team tile layout delivers accountability as a side effect.

2. **Volume unit = VPR Critical+High open count.** Count only VPR Critical/High findings per bucket. Raw open count was rejected as misleading (one app server with hundreds of low-severity library findings would swamp a handful of critical OS holes and give execs the wrong impression). Severity follows the project's VPR-first policy (see `config.py` SLA bands).

3. **Visual = three RAG tiles, one per team.** Each tile names its owning team and shows: count, % of total, and a month-over-month delta arrow + RAG color. Fits the existing board/management RAG-strip idiom (`render_rag_strip_entry` / `render_email_panel`, four-channel contract). Rejected alternatives: 100% stacked bar, stacked trend area chart, tiles+sparklines.

4. **Classification source is already in the data.** `data/fetchers.py:343` already pulls `plugin.cpe` into `vulns_df` as a comma-joined string. No new fetch is required. The classifier is the CPE part letter (`a` / `o` / `h`) in CPE 2.2 form (`cpe:/a:vendor:product`).

5. **Trend ships in two stages (cold start).** No App/OS/Hardware history exists today, so the month-over-month delta produces nothing until monthly snapshots accumulate. Ship **balance-now** first; the trend axis fills in over subsequent months. Leadership must not be promised a trend line on day one.

## Open questions (resolve before/while building)

- **Empty-CPE / mixed-CPE handling — pending real-data measurement.** A meaningful share of findings carry `"cpe": []` (info/web/config plugins; the example response has a CSP-header web finding with no CPE). Decision deferred to a measurement spike: how much of the **Critical+High** set classifies cleanly by CPE prefix, and how big is the residual. Candidate fallback: a `plugin_family` → bucket map (e.g. "Red Hat Local Security Checks" is unambiguously OS even with empty CPE — often a *cleaner* OS/App signal than CPE). A visible "Unclassified" bucket is the honest floor if coverage is poor.
- **Multi-CPE precedence.** A single finding's CPE list can mix types. Need a fixed precedence (e.g. `a > o > h`) so each finding lands in exactly one team's bucket — buckets are mutually exclusive because teams are.
- **Snapshot persistence mechanism.** The trend axis needs a monthly snapshot of per-bucket Crit+High counts. Open: write the module's own snapshot, or piggyback the existing trend-snapshot infrastructure (`data/trend/`, used by `management_summary`)?

## Data reality (verified 2026-06-05)

- `vulns_df.cpe` exists (comma-joined CPE list per finding). CPE 2.2 form confirmed in `docs/example_vulnerability_api_response_200.json` (`cpe:/a:microsoft:sharepoint_server`).
- `vulns_df.plugin_family` exists — fallback-classifier candidate.
- VPR severity fields present (`vpr` / `vpr_v2`) — drives the Crit+High filter.
- Empty CPE arrays confirmed present in real plugin output.

## Realization path

New `reports/modules/*_module.py` following the four-channel contract (auto-discovered via `@register_module`), surfaced through `composed_report` and/or the board/management bundles. No change to `run_all.py` or `email_sender.py` needed for the module itself. See CLAUDE.md "Adding a new module to an existing composed report."
