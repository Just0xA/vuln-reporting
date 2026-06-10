# Milestone v1.3 Requirements — Trend & Segmentation Substrate

**Milestone goal:** Build the two shared substrates under the June-2026 report batch — a forward-accumulating trend-snapshot mechanism and an Owner/BU segmentation helper — so the v1.4 report modules become thin consumers instead of each re-inventing trend and segmentation.

**Status:** 🟡 PLANNING (started 2026-06-05)
**Count:** 13 REQs across 3 categories

**Founding analysis:** [`notes/report-requests-batch-2026-06.md`](notes/report-requests-batch-2026-06.md), [`notes/trend-reconstruction-engine.md`](notes/trend-reconstruction-engine.md), spikes 001–003 ([`spikes/MANIFEST.md`](spikes/MANIFEST.md)), and the `spike-findings-vuln-reporting` skill.

**REQ-ID conventions:**
- `TREND-NN` — Trend snapshot substrate (S1)
- `SEG-NN` — Owner/BU segmentation (S2)
- `DOC-NN` — Documentation deliverables

**Out of scope (deferred to v1.4+):** All report modules (VTD-01, New-vs-Remediated, Vuln Density, Reopened, Program Health, Accepted/Recast); External/DMZ+WAS report (gated on the pyTenable-upgrade decision — Spike 003); GEN-01 `management_summary` four-channel migration.

---

## v1.3 Requirements

### Trend Snapshot Substrate (S1)

- [x] **TREND-01**: A canonical `open_findings_at(df, date)` primitive computes the open population using the **reopened-aware two-interval predicate** (OPEN = never fixed; REOPENED = fixed only during `[last_fixed, resurfaced_date)`; FIXED = fixed at `last_fixed`), is **unit-tested against labelled cases including reopened findings**, and matches the actual current open count exactly.
- [x] **TREND-02**: A `capture_snapshot(date, dimensions)` function writes a monthly snapshot of open counts grouped by each registered dimension (severity at minimum; pluggable for type/owner); writes are **atomic** (temp-file + `os.replace`).
- [x] **TREND-03**: Snapshots **reuse/extend the existing `data/trend/` store** and the JSON shape consumed by `management_summary` — no parallel store; existing trend consumers do not regress.
- [x] **TREND-04**: A `read_trend(dimension, months)` function returns a month-over-month series from accumulated snapshots and is **cold-start safe** (≤1 snapshot → returns available history and flags insufficient data, never crashes).
- [x] **TREND-05**: Snapshot capture is **idempotent per calendar month** (re-running for the same month overwrites that month's cell; never duplicates).
- [x] **TREND-06**: Snapshot payloads are **aggregate counts only — no row-level PII** (D-04-08); safe to persist under the existing `data/trend/` rules.
- [x] **TREND-07**: An operator/scheduled **entry point captures the current month's snapshot** (cron/daemon-friendly, logged with cron-friendly exit codes) so history accrues without manual action.

### Owner / BU Segmentation (S2)

- [x] **SEG-01**: A reusable helper **groups findings/assets by the `Owner` tag category**, returning per-Owner buckets.
- [x] **SEG-02**: Assets without an `Owner` tag fall into a single **`Unassigned` catch-all** (label configurable) so per-Owner totals always reconcile to the whole.
- [x] **SEG-03**: The substrate produces an **analyst exception list of `Unassigned` assets** as operator-facing detail output (Excel/local), never committed or emailed in violation of D-04-08, to drive tagging cleanup.
- [x] **SEG-04**: Segmentation is **fail-soft** when the `Owner` category is absent or partially applied (→ everything `Unassigned`, no crash; empty-data guard per CLAUDE.md).
- [x] **SEG-05**: Owner segmentation **composes with the trend primitive** — per-Owner open counts can be snapshotted and trended (proves S1×S2 combine end-to-end).

### Documentation

- [x] **DOC-01**: A substrate calculations/runbook doc (`docs/trend_and_segmentation_calculations.md` or equivalent) records the open-predicate definition, the **~29-day Tenable fixed-retention / forward-accumulation** limitation (no backfill), and the `Owner`/`Unassigned` segmentation model — auditor-facing, matching the `docs/*_calculations.md` pattern.

---

## Future Requirements (deferred)

- **v1.4 report batch** (consumers of S1/S2): VTD-01 (Vuln Type Distribution), New-vs-Remediated, Vuln Density, Reopened, Program Health, Accepted/Recast.
- **GEN-01** — migrate `management_summary` to the four-channel module contract (entangled with reports #1/#2/#4).
- **External/DMZ + WAS report** — gated on the pyTenable-upgrade decision (Spike 003: 1.5.2 `tio.was` has no VPR + no lifecycle fields).
- **GEN-03/04** — broader YAML-driven module composition beyond `composed_report`.
- **PERF-01..04**, **LEGACY-01** — carried from prior backlog.

## Out of Scope

- **Trend reconstruction / history backfill** — explicitly rejected (Spike 002: ~29-day fixed-retention wall). The substrate is snapshot-capture only.
- **WAS data fetching** — deferred with the External report.

## Traceability

| Requirement | Phase | Status  |
|-------------|-------|---------|
| TREND-01    | 12    | Complete |
| TREND-02    | 12    | Complete |
| TREND-03    | 12    | Complete |
| TREND-04    | 12    | Complete |
| TREND-05    | 12    | Complete |
| TREND-06    | 12    | Complete |
| TREND-07    | 12    | Complete |
| SEG-01      | 13    | Complete |
| SEG-02      | 13    | Complete |
| SEG-03      | 13    | Complete |
| SEG-04      | 13    | Complete |
| SEG-05      | 13    | Complete |
| DOC-01      | 13    | Complete |
