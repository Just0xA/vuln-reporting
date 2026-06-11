# Phase 12: Trend Snapshot Substrate (S1) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-06
**Phase:** 12-trend-snapshot-substrate-s1
**Areas discussed:** Module placement & MS refactor, Store shape for dimensions, Asset-churn / metric validity, Snapshot data source, Entry point

---

## Module placement & MS refactor

| Option | Description | Selected |
|--------|-------------|----------|
| New module, MS untouched | New shared module; leave MS private helpers as-is. Zero regression risk; full migration → GEN-01. | ✓ |
| Extract & rewire MS | Move MS helpers into substrate; prove byte-for-byte unchanged in this phase. | |
| Predicate shared, store new | Only the pure predicate becomes shared; store separate; MS keeps its writer. | |

**User's choice:** New module, MS untouched
**Notes:** Protects TREND-03's byte-for-byte bar; MS migration is already the v1.4 GEN-01 backlog item.

## Placement

| Option | Description | Selected |
|--------|-------------|----------|
| utils/ predicate + data/ store | `open_findings_at` in utils/ (pure); snapshot engine in data/ (I/O). | ✓ |
| Single new data/ module | Both predicate + engine in one data/ module. | |
| Single new utils/ module | Both in one utils/ module. | |

**User's choice:** utils/ predicate + data/ store
**Notes:** Matches existing layer conventions (`utils/sla_calculator.py` pure; `data/fetchers.py` I/O).

---

## Store shape for dimensions

| Option | Description | Selected |
|--------|-------------|----------|
| File-per-dimension, flat counts | `trend_{dimension}_{tagsuffix}.json`; severity keys identical to MS; new dims get own files. | ✓ |
| Nested dimensions, one file | One file/tag_filter with nested dimensions object; diverges from MS flat shape. | |
| Generic counts map | Uniform {dimension, buckets:{label:count}}; severity no longer matches MS keys. | |

**User's choice:** File-per-dimension, flat counts
**Notes:** Preserves MS reader contract; substrate owns its own files (consistent with "MS untouched").

## Cold-start / merge-read MS history

| Option | Description | Selected |
|--------|-------------|----------|
| Substrate's own files only | read_trend reads only substrate-written files. Clean ownership. | ✓ (derived) |
| Merge-read MS severity history | Also ingest MS's management_summary_*.json for a longer day-one series. | |

**User's choice:** Superseded by the asset-churn discussion; resolved by derivation — adding `asset_count` to the substrate shape (D-04) makes MS rows ragged, so read_trend reads substrate files only (D-05).
**Notes:** Revisit only if a longer day-one series is later required.

---

## Asset-churn / metric validity (user-raised)

User raised: vulns are tied to assets; a purged asset removes its vulns (looks like remediation), and a rebuilt asset gets a new UUID (duplicate findings). Questioned whether snapshot open-count is the right trend approach.

| Question | Option | Description | Selected |
|----------|--------|-------------|----------|
| Churn handling | Snapshot open + asset count | Keep open-count primitive; also record in-scope asset_count; document churn caveat in DOC-01; flow → v1.4. | ✓ |
| Churn handling | Open count only, document caveat | Open counts only; no asset_count; strict TREND-02 scope. | |
| Churn handling | Rethink — capture finding flow now | Pull v1.4 New-vs-Remediated flow into Phase 12. | |
| Dedup | No dedup — open is open | Re-detected findings are genuinely open; cross-UUID reconciliation deferred. | ✓ |
| Dedup | Note as v1.4 concern | Same, but log dedup explicitly as v1.4 backlog. | |

**User's choice:** Snapshot open + asset_count; No dedup
**Notes:** Established that churn distorts stock-deltas but not flow metrics; flow = deferred v1.4 New-vs-Remediated report (substrate feeds it). asset_count is the cheap, non-reconstructable denominator worth capturing now (enables Vuln Density, makes churn visible). Cross-UUID dedup still recorded in CONTEXT Deferred Ideas as future-relevant.

---

## Snapshot data source

| Option | Description | Selected |
|--------|-------------|----------|
| Function takes df; script fetches | capture_snapshot(df, assets_df, date, ...) pure/testable; entry-point script fetches via fetchers + parquet cache. | ✓ |
| Function fetches internally | capture_snapshot calls fetchers; simpler call, harder to unit-test. | |

**User's choice:** Function takes df; script fetches
**Notes:** Keeps the open-count primitive unit-testable (TREND-01); follows pure-compute/deferred-I/O convention.

---

## Entry point

| Option | Description | Selected |
|--------|-------------|----------|
| Standalone script, all_assets severity | `scripts/capture_trend_snapshot.py` (warm_cache-style); Phase 12 = all_assets severity; parameterized for Phase 13. | ✓ |
| Subcommand on existing tooling | Flag on run_all.py or scheduler mode. | |
| Standalone script, iterate tag filters | Iterate all delivery_config tag filters now. | |

**User's choice:** Standalone script, all_assets severity
**Notes:** Mirrors `scripts/warm_cache.py`; capture_snapshot stays parameterized by dimension+tag_filter so Phase 13 owner iteration needs no reshape.

---

## Claude's Discretion

- Exact new-module filenames and function signatures beyond the agreed shape.
- The dimension-registration mechanism.
- Cron exit-code conventions (follow `scripts/warm_cache.py`).

## Deferred Ideas

- Flow metrics (new/remediated this month) → v1.4 New-vs-Remediated report.
- Vuln Density (open ÷ asset_count) → v1.4 (denominator captured now).
- Cross-UUID / stable-asset-key dedup → v1.4 report layer.
- Per-tag-filter / per-group snapshot iteration → Phase 13+.
- Full management_summary migration onto the substrate → GEN-01 (v1.4).
- Merge-reading MS severity history into read_trend → rejected for now; revisit if longer day-one series needed.
