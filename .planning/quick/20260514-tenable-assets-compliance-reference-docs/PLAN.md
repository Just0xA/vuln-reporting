---
slug: tenable-assets-compliance-reference-docs
date: 2026-05-14
type: quick
---

# Tenable Assets + Compliance API Reference Docs

Mirror `docs/tenable_vuln_api_reference.md` for the Assets and Compliance Tenable exports using the raw field definitions captured in `ref/`.

## Scope

1. `docs/tenable_assets_api_reference.md` — field dictionary covering **both** the v1 (`POST /assets/export`, currently used via `tio.exports.assets()`) and v2 (`POST /assets/v2/export`, future target via `assets_v2()`) export schemas, with per-field indicators showing where each field lives in each version.
2. `docs/tenable_compliance_api_reference.md` — single field dictionary for the compliance export.

Both docs follow the structure and section style of the existing vuln reference: top-of-doc project conventions block, then field tables grouped by sub-object, then a closing cheat sheet / extension note.

## Source files

- `ref/assets_v1_api_response_fields.txt` + `ref/assets_v1_api_response.json`
- `ref/assets_v2_api_response_fields.txt` + `ref/assets_v2_api_response.json`
- `ref/compliance_api_response_fields.txt` + `ref/compliance_api_response.json`

## Out of scope

- No code changes — documentation only.
- No SDK migration plan beyond cross-linking to the existing ROADMAP backlog entry for the pyTenable 1.9.x upgrade.
