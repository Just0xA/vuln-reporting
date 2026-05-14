---
slug: tenable-assets-compliance-reference-docs
date: 2026-05-14
type: quick
status: complete
---

# Summary

Created two field reference documents in `docs/`, mirroring the structure of the existing `tenable_vuln_api_reference.md`, using the raw schema files captured in `ref/`.

## Outputs

- `docs/tenable_assets_api_reference.md` — covers **both** v1 (currently used via `tio.exports.assets()`) and v2 (future migration target via `tio.exports.assets_v2()`) asset export schemas. Each field row carries an explicit version marker:
  - **[v1]** — present only in v1; gone or renamed in v2
  - **[v2]** — present only in v2 (not in our current data)
  - **[v1+v2]** — present in both; row shows both paths when they differ
  - Sections grouped by concept (Identity & Lifecycle, Timestamps, Network, Cloud, Third-Party IDs, Sources, Tags, Open Ports, Software, Ratings, Resource Tags), with a closing v1→v2 migration summary listing new fields, restructured paths, dropped fields, and unchanged shape.
- `docs/tenable_compliance_api_reference.md` — single-version reference for `POST /compliance/export`. Sections: Identity & State, Check Definition & Evaluation, Benchmark & Framework Identifiers, Timing, embedded `assets` sub-object, field-to-metric cheat sheet. Includes explicit callout that the embedded tag shape (`category` + `values[]`) differs from the assets export tag shape (`key` + `value`).

Both docs cross-link to each other, to `tenable_vuln_api_reference.md`, to `GLOSSARY.md`, and to the existing backlog entry "pyTenable upgrade + asset export v2 migration" in `.planning/ROADMAP.md`.

## Notable observations during build

- **ACR and AES are already in v1.** The legacy `acr_score` / `exposure_score` strings AND the modern `ratings.acr.score` / `ratings.aes.score` floats both exist in v1 today. We don't have to wait for v2 to start using them for the Operator Remediation priority model.
- **v2 adds `is_public` (boolean).** Structured "internet-facing" flag — direct replacement candidate for the RFC-1918 IP heuristic in the priority model. Captured in the migration summary section.
- **v2 adds `types` (array).** First-class asset type distinguishes hosts / WAS / cloud resources — relevant when scoping operator reports.
- **Compliance embedded-tag shape is lossy.** `{category, values[]}` vs assets-export `{uuid, key, value, added_by, added_at}`. Joining back to the assets export is the path for full tag fidelity. Documented as a callout.

## No code changes

Documentation only. No call sites touched.
