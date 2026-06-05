# Spike Wrap-Up Summary

**Date:** 2026-06-05
**Spikes processed:** 2
**Feature areas:** Vuln Metric Substrate (classification + trend foundations)
**Skill output:** `./.claude/skills/spike-findings-vuln-reporting/`

## Processed Spikes
| # | Name | Type | Verdict | Feature Area |
|---|------|------|---------|--------------|
| 001 | cpe-coverage-crit-high | standard | ⚠ PARTIAL | Vuln Metric Substrate |
| 002 | trend-reconstruction-lookback | standard | ⚠ PARTIAL | Vuln Metric Substrate |

## Key Findings

- **Classification (001):** CPE prefix classifies 99.2% of VPR Crit+High findings, but CPE-prefix ≠ team ownership. Rule must be `plugin_family` override → CPE prefix → Unclassified (config-driven). "Windows" plugin_family is third-party apps (Adobe/Chrome/Java) — correctly Application; Linux distro "Local Security Checks" carry `cpe:/a:` but are OS-team work. Hardware ~0. ~6% App/OS swing rides on the family map → must be unit-tested.
- **Trend (002):** Tenable retains fixed findings only ~29 days (platform-side), so multi-month history cannot be reconstructed from a current export and snapshots cannot be retired. The substrate is a snapshot-capture engine; reconstruction serves current-state + last ~29 days. Cold start is real.
- **Predicate bug (002):** the naive "open at D" predicate drops all REOPENED findings (~19%, 30,546/160,453). The reopened-aware two-interval form (using `resurfaced_date`) validates exact (+2). Applies to any current-state module, not just trend.

## Impact on planning
Both verdicts reshaped the v1.3 substrate scope: S1 is snapshot-capture (known quantity, extends existing `data/trend/`), not reconstruction. VTD-01 cold-start confirmed real. Notes and ROADMAP corrected accordingly. Saved cross-session memory `project_tenable_fixed_retention_trend`.
