---
name: spike-findings-vuln-reporting
description: Implementation blueprint from spike experiments. Requirements, proven patterns, and verified knowledge for building the vuln-reporting metric substrate (vuln-type classification + trend foundations). Auto-loaded during implementation work on VTD-01, trend, or the June-2026 report batch.
---

<context>
## Project: vuln-reporting

Shared foundations under the June-2026 report batch — a CPE-based Vuln Type Distribution module (VTD-01) plus seven trend-oriented reports. Two spikes validated the classification rule and the trend-feasibility limits before committing a milestone, both producing decision-grade PARTIAL verdicts that reshaped the plan.

Spike sessions wrapped: 2026-06-05
</context>

<requirements>
## Requirements

Non-negotiable design decisions from spiking. Every feature area reference must honor these.

- **Severity is VPR-first** via `config.vpr_to_severity(vpr_score, fallback=native)` (Critical 9.0–10.0, High 7.0–8.9).
- **Vuln-type classifier = `plugin_family` override → CPE prefix → Unclassified**, config-driven map. Pure CPE-only is rejected (99.2% CPE coverage but mis-assigns ~6% of OS-team work).
- **Volume unit = VPR Critical+High open count** per bucket.
- **Microsoft Bulletins → Operations/OS** (default, config-changeable); **hide Hardware tile when empty** (~0 in real data).
- **Any "currently open" computation MUST use the reopened-aware two-interval predicate** — the naive form silently drops ~19% of findings (all REOPENED).
- **Trend = forward-accumulating snapshots, not backfilled reconstruction** — Tenable retains fixed findings only ~29 days. Cold start is real.
- **Classifier + predicate must be unit-tested** against labelled samples.
- **Ship `docs/vuln_type_distribution_calculations.md`** auditor runbook with VTD-01.
</requirements>

<findings_index>
## Feature Areas

| Area | Reference | Key Finding |
|------|-----------|-------------|
| Vuln Metric Substrate | references/vuln-metric-substrate.md | CPE+family classifier (99.2%) and reopened-aware open predicate work; multi-month trend reconstruction does NOT (~29d retention) — snapshots required |

## Source Files

Original spike source files are preserved in `sources/` for complete reference (READMEs + runnable `measure.py`/`probe.py`).
</findings_index>

<metadata>
## Processed Spikes

- 001-cpe-coverage-crit-high
- 002-trend-reconstruction-lookback
</metadata>
