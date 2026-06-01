# Research Questions

Open questions surfaced during exploration that warrant a focused research pass before they become commitments.

---

## Q-001 — Reliability of Tenable fix-type fields across plugin families

**Surfaced:** 2026-05-14 (via `/gsd-explore` — Operator Remediation Report v2)
**Owner:** TBD
**Status:** Open

### Question

How reliably can we classify each finding's **fix type** (patch / configuration change / workaround / disable-service / no-fix-available / vendor-unpatched) from the Tenable plugin fields:

- `plugin.has_patch`
- `plugin.vendor_unpatched`
- `plugin.has_workaround`
- `plugin.workaround_type` (enum: `Configuration Change` | `Disable Service`)
- `plugin.solution` (free text)
- `plugin.workaround` (free text)

Are there plugin families where these booleans/enums are **unreliable** — e.g. `has_patch=true` but `solution` text actually requires a configuration change, or `has_workaround=false` but the `solution` text describes one — and where we'd need to regex/heuristic the free-text `solution` / `workaround` fields as a backup classifier?

### Why this matters

The Operator Remediation Report v2 (see ROADMAP) needs a reliable fix-type bucketing so operators can answer Pillar 2 ("How do I resolve this?") at a glance and group remediation work by action type. If the structured fields are reliable, the classifier is a 6-line function. If they aren't, the module needs a heuristic layer plus a confidence flag — and the team needs to know which plugin families to manually review.

### How to investigate

1. Pull a recent live (or cached) vulnerability export covering Critical + High findings.
2. Tabulate counts by `(has_patch, vendor_unpatched, has_workaround, workaround_type)`.
3. Spot-check ~25 findings across a spread of `plugin.family` values — sample at least Windows MS Bulletins, Ubuntu USN, RHEL, CGI/web, network device, and SSL/TLS families.
4. For each sample, compare the structured-field classification against the prose `solution` / `workaround` text.
5. Flag any family where the structured fields disagree with the prose **> 10%** of the time. Those families become the heuristic-backup target list.

### Acceptance / handoff

Output a short table mapping `plugin.family` → reliability verdict (`Reliable` / `Needs heuristic backup` / `Unknown — too few samples`) plus the proposed classifier logic. Attach the table to the Operator Remediation Report v2 phase context when planning starts.

---

## Q-002 — `tio.exports.compliance()` schema sufficiency for failures-by-check fan-in

**Surfaced:** 2026-06-01 (via `/gsd-explore` — Compliance Reporting seed)
**Owner:** TBD
**Status:** Open

### Question

Does `tio.exports.compliance()` return enough check metadata in a single fetch to render a failures-grouped-by-check view, or do we need a second fetch (or a join against scan/audit-policy metadata) to enrich?

Specifically, per row, do we get:

- **Audit-file / framework identity** — name and/or ID of the source `.audit` file (CIS Windows Server 2022, CIS-tailored custom, DISA STIG, etc.) so a `framework` column is populated without a lookup.
- **Check identity and description** — stable check ID, check name, rationale/description text, and CIS-section reference for grouping and for the analyst-tab drill-down.
- **Result status** — `PASSED` / `FAILED` / `WARNING` (and any other states) so we can filter to failures-only.
- **Asset identity** — UUID / hostname / IP for tag enrichment via the existing `utils/tag_helper.py` path.
- **Per-instance evidence** — actual-vs-expected values, or output snippet, for analyst drill-down.

### Why this matters

The v1 operational cut (see [[compliance-reporting]] seed and [[compliance-data-model-decisions]] note) is a one-row-per-failing-check fan-in with affected-asset counts. If the export already carries the check + audit-file identity inline, the module is a straightforward `groupby`. If not, we need to either (a) call a second endpoint to enrich check metadata, or (b) pre-load a check-catalog from the audit-policy definitions and join in-process.

### How to investigate

1. Trigger a one-off `tio.exports.compliance()` against a small known-compliance-enabled scope and dump a sample (~100 rows) to parquet.
2. Inspect the column set and per-row payload — note which of the fields above are present, which are null, which require enrichment.
3. Cross-check against the pyTenable docs and the `/compliance` v3 API spec for documented schema vs. observed.
4. If enrichment is needed, identify the cheapest source (scan metadata, audit-policy endpoint, or a manually exported audit-catalog).

### Acceptance / handoff

Output a short table mapping each required field → `Present in export` / `Needs enrichment (source: X)` / `Not available`. If enrichment is required, propose the join strategy and estimate added fetch cost. Attach to the Compliance Reporting phase context when planning starts.
