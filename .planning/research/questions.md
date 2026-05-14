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
