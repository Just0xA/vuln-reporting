# Phase 14: Shared Substrates + composed_report Gates - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-11
**Phase:** 14-shared-substrates-composed-report-gates
**Areas discussed:** Density denominator (OD-2), External MoM trend (OD-6), External classification precedence, Multi-IP handling, Tag-match semantics, On-time cutoff DRY, Frozenset membership, scoped_df shape, Mismatch-list PII, Test fixtures, Trend kwarg contract, Cutoff "now" source, Zero-guard return

---

## Density Denominator (OD-2)

| Option | Description | Selected |
|--------|-------------|----------|
| On-time-scanned | Divide by assets scanned in last 30d; consistent with board_summary baseline | ✓ |
| All-licensed | Divide by every licensed asset; more stable but counts stale assets | |
| You decide | Take the research recommendation | |

**User's choice:** On-time-scanned.
**Notes:** Follow-up surfaced a coherence gap — existing S1 snapshot stores `len(assets_df)` (all in-scope), wrong basis for an on-time-scanned trend.

| Option | Description | Selected |
|--------|-------------|----------|
| Add on-time field, cold-start | Extend S1 snapshot with on-time count going forward; density trend cold-starts on it | ✓ |
| Keep all-asset basis for density | Reverse to all-asset to match existing field | |
| You decide | — | |

**User's choice:** Add on-time field, cold-start (Phase 15 / OD-3 dependency flagged from here).

---

## External MoM Trend (OD-6)

| Option | Description | Selected |
|--------|-------------|----------|
| Defer MoM to v1.5 | Current-snapshot only; EXT-TREND-01 backlog | ✓ |
| Build S1 external dimension now | Expand snapshot schema + PII surface this milestone | |

**User's choice:** Defer to v1.5.

---

## External Classification Precedence

| Option | Description | Selected |
|--------|-------------|----------|
| Any external signal wins | Union: public IP OR External/DMZ tag → external; conflicts flagged | ✓ (then refined) |
| Explicit tag authoritative | Location=Internal suppresses IP signal | |
| You decide | — | |

**User's choice / refinement:** The `Location=External` tag is itself Tenable's "IP not RFC1918" dynamic rule, and `Location=DMZ` is a dynamic tag over a designated internal IP range (exists, unpopulated). **Tag always wins.** Net model: tags authoritative; `is_public_ipv4()` demoted to a gap detector that only flags `public_ip_untagged`. DMZ + private IP is normal, not a mismatch. CGNAT never appears in Tenable data (agents report the local DHCP/DNS IP; CGNAT is a ZScaler-only transient).

---

## Substrate sub-decisions (batched)

| Area | Selected |
|------|----------|
| Multi-IP handling | Primary `ipv4` column only; no fetcher change |
| Tag match semantics | Mirror `extract_owner._parse_tags` (Location category, case-insensitive, exact value) |
| On-time cutoff DRY | Canonical window constant in `config.py`; cutoff filter local to asset_count |
| Frozenset membership | Stub now; modules self-add in their build phase; documented intended mapping |
| scoped_df shape | Filtered external-only subset; gap assets in both scoped_df and mismatches_df |
| Mismatch-list PII | Operator-local analyst tab + internal-domain email OK; never committed, never to AI |
| Test fixtures | Monkeypatch `is_global` for the positive case (RFC 5737 ranges fail is_global) |
| Trend kwarg | Full `read_trend()` dict under `trend_snapshots`; recast as `recast_rules_df` |
| Cutoff "now" | `report_date` param (UTC generated_at); pure function |
| Zero-guard return | `None` sentinel — distinguishes "no assets" from "no vulns" |

**Notes:** Mismatch-PII clarification — D-04-08 bans repo-commit + AI submission, not internal corporate email (per `project_pii_rule_is_ai_not_email`). Test-fixture choice verified empirically: `192.0.2.1`/`198.51.100.1`/`203.0.113.1` all return `is_global=False`.

---

## Claude's Discretion

- Exact gate/fetch-block wiring (follows `_MODULES_NEEDING_FIXED_VULNS`), `is_public_ipv4` internals, helper signatures beyond the locked contracts.

## Deferred Ideas

- EXT-TREND-01 (external MoM trend) → v1.5.
- S1 snapshot on-time-scanned count field → Phase 15 / OD-3.
- `reopened_vulns` trend membership → decided Phase 15.
- EXT-WAS-01 (WAS in External Exposure) → gated on pyTenable upgrade.
