# Phase 13: Owner Segmentation + Composition (S2 + Doc) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-10
**Phase:** 13-owner-segmentation-composition-s2-doc
**Areas discussed:** Ownership model, Wiring scope, Supplemental relationship, Heading label, Column name, Trend shape, PII/delivery, Catch-all label, Supplemental layout, Blast radius

---

## Reframing (opening exchange)

User rejected the initial generic gray-area set and clarified intent: "Owner Segmentation" is really about changing the board_summary "Business Unit" tables and the Excel supplemental **from the `Application` tag to the `Owner` tag**, to start driving reports to actual stakeholders. The `Application` breakdown is still needed — demoted to a nested analyst drill-down. This reframed the entire discussion away from an abstract substrate toward concrete consumer rewiring.

---

## Ownership model (Owner ↔ business_unit ↔ Application)

| Option | Description | Selected |
|--------|-------------|----------|
| Owner replaces Application as BU source | Flip BU_TAG_CATEGORY; generalize helper | (basis of free-text) |
| Add Owner as a new distinct dimension | Parallel grouping system | |
| Let me explain the tag relationship | User describes the real nesting | ✓ |

**User's choice:** Free-text — full ownership model.
**Notes:** Asset ownership is layered. **Business Unit** owns the app overall (end users). **Application Support** maintains/upgrades/**patches** the app — *this is where vulnerabilities go*. **Technical Support** (e.g., Server Engineering & Ops) owns the server/OS itself and OS-type vulns (MS Server updates). Reporting should target/group by **Application Support** = the **`Owner`** tag. A real Business Unit tag and a Technical Support category are future/reference. Performance-metric responsibility to Owner+BU is future ("connections not as clear yet").

## Wiring scope

| Option | Description | Selected |
|--------|-------------|----------|
| Substrate + repoint board modules + supplemental | Full wiring this phase | ✓ |
| Substrate + composition + doc only | Rewiring deferred | |
| Repoint board modules only | Composition deferred | |

**User's choice:** Substrate + repoint board modules + supplemental.

## Supplemental relationship

| Option | Description | Selected |
|--------|-------------|----------|
| Two outputs: Owner→App focus + Unassigned cleanup | Distinct artifacts | |
| One combined supplemental | Unassigned as an Owner bucket; App nested | ✓ |
| Unassigned list only (literal SEG-03) | Defer nested breakdown | |

**User's choice:** Combined supplemental.
**Notes:** Combined view also helps analysts identify which Applications still need an Owner assignment.

## Heading label

| Option | Description | Selected |
|--------|-------------|----------|
| Rename heading to 'Owner' | Audience-facing 'Owner' | ✓ |
| Keep 'Business Unit' heading | Source tag only changes | |
| Make the label configurable | Config-driven heading | |

**User's choice:** Rename heading to 'Owner'.

## Column name

| Option | Description | Selected |
|--------|-------------|----------|
| Rename column to 'owner' | Free 'business_unit' for future real BU tag | ✓ |
| Keep 'business_unit', fill with Owner | Least churn | |
| Parameterized grouping column | Most flexible | |

**User's choice:** Rename column to 'owner'.

## Trend shape (SEG-05)

| Option | Description | Selected |
|--------|-------------|----------|
| dimension='owner', one file, per-Owner counts | Matches roadmap SC4 | ✓ |
| Per-Owner tag_filter iteration | Severity-within-owner, many files | |
| You decide | | |

**User's choice:** dimension='owner', one file, per-Owner counts.

## PII / delivery

| Option | Description | Selected |
|--------|-------------|----------|
| Local-only, never emailed | Strict literal SEG-03 | |
| Emailed aggregate, local-only detail | Split artifact | |
| You decide | | (free-text reinterpretation) |

**User's choice:** Free-text — reinterpreted the rule.
**Notes:** The PII rule is about **not transmitting data to the AI (Claude)** and not committing to the repo — **not** a ban on internal corporate email. Server → internal corporate email group is OK. This supersedes the literal SEG-03 "not attached to any email." Trend store stays aggregate-only (separate constraint).

## Catch-all label

| Option | Description | Selected |
|--------|-------------|----------|
| 'Unassigned' bucket, heading 'Owner' | Standardize catch-all | ✓ |
| 'Unassigned' bucket, heading 'Application Support' | | |
| Keep 'Untagged' | | |

**User's choice:** 'Unassigned' bucket, heading 'Owner'.

## Supplemental layout

| Option | Description | Selected |
|--------|-------------|----------|
| One tab: Owner + Application + counts | Flat, sortable | ✓ |
| Tab per Owner | More navigable, more tabs | |
| You decide | | |

**User's choice:** One tab: Owner + Application + counts.

## Blast radius

| Option | Description | Selected |
|--------|-------------|----------|
| board_summary only (both BU modules) | | |
| board_summary + management_summary | Pulls GEN-01 forward | |
| Ready for context — you decide scope | | (free-text expansion) |

**User's choice:** Free-text — named the modules to repoint.
**Notes:** User named high_risk_assets, critical_remediation_sla, scan_coverage_sla, aged_vulns_assets and asked Claude to find any others. Grep confirmed those four + the shared `board_report_utils.py` are the **complete** set referencing `business_unit`/the BU tag — nothing else to chase.

---

## Claude's Discretion

- Generalized function/parameter names in `board_report_utils.py` (beyond Owner-primary + parameterized + `owner` column rename).
- Combined-supplemental filename/output location (within not-committed / not-AI-transmitted constraint).
- `trend_owner_*.json` count-key encoding and tag-suffix convention.
- Whether Owner category name / Unassigned label are module constants vs config-driven.

## Deferred Ideas

- Build the real Business Unit tag/dimension (future).
- Technical Support category (future reference dimension).
- Performance-metric responsibility mapping to Owner + Business Unit (future).
- `management_summary` / `composed_report` Owner wiring (GEN-01, v1.4).
- Per-Owner severity breakdown in trend (richer future option).
