# Tenable Compliance API — Field Reference

A user- and AI-friendly dictionary of the fields returned by the Tenable Vulnerability Management (Tenable.io) **Compliance Export** API. Each record is one (compliance check × asset) result, equivalent to one row in the compliance findings view in the Tenable UI.

- Endpoint: `POST /compliance/export`.
- pyTenable surface: `tio.exports.compliance(...)`.
- **Current use in this project:** Not consumed today. This reference is groundwork for adding compliance modules to the modular framework (candidate fit for the Operator Remediation Report v2 phase and potential Board-level "Compliance Coverage" metric).
- Source: official Tenable API documentation (compliance export response schema).
- Example payload: [`ref/compliance_api_response.json`](../ref/compliance_api_response.json).
- For project terminology: [`GLOSSARY.md`](GLOSSARY.md).
- Sister references: [`tenable_vuln_api_reference.md`](tenable_vuln_api_reference.md), [`tenable_assets_api_reference.md`](tenable_assets_api_reference.md).

> **Project conventions you should know before reading**
>
> - **States mirror the vuln export.** `OPEN` / `REOPENED` / `FIXED` follow the same UI-vs-API naming rule (`new`/`active` → `OPEN`; `resurfaced` → `REOPENED`).
> - **No VPR / CVSS / SLA** concepts apply here. Compliance findings are categorical (`PASSED` / `FAILED` / `WARNING` / `SKIPPED` / `UNKNOWN`), not risk-scored.
> - **The `assets` sub-object is a snapshot** of the asset at the time the compliance check ran. For richer asset attributes (tags, ACR/AES, last-licensed-scan dates), join against the assets export by `asset_uuid` → `assets.id`.
> - **`state` is null** for findings last seen before December 2021.

---

## Top-Level Compliance Object — Identity & State

| Field | Type | Description | Notes |
| ----- | ---- | ----------- | ----- |
| `asset_uuid` | string | UUID of the asset on which the check was executed. | **Join key** to the assets export (`asset_uuid` → `assets.id`). |
| `check_id` | string | Unique identifier for the compliance finding. Derived from `compliance_full_id`, `compliance_functional_id`, `compliance_informational_id`. **Regenerated** when any of those change. | Primary key when stable identity is needed. |
| `plugin_id` | int | Unique ID of the compliance plugin. | Use for grouping checks that share the same plugin definition. |
| `plugin_name` | string | Name of the compliance check. | Often equivalent to `check_name`. |
| `metadata_id` | string | Internal identifier used in Tenable VM's pipeline ingestion. | Generally not used by downstream consumers. |
| `state` | string | Lifecycle state: `OPEN` / `REOPENED` / `FIXED`. **Null** for findings last seen before December 2021. | See state table below. |
| `status` | string | Compliance evaluation result: `PASSED` / `FAILED` / `WARNING` / `SKIPPED` / `UNKNOWN`. | The "is this asset compliant?" answer. See status table below. |
| `check_error` | string | Error message if the compliance evaluation itself failed (distinct from a failed check). | Surface in analyst tabs only; not summary metrics. |

### `state` values

| API value | UI equivalent | Meaning |
| --------- | ------------- | ------- |
| `OPEN` | "New" / "Active" | Compliance finding is currently present on the asset. |
| `REOPENED` | "Resurfaced" | Previously `FIXED`, then re-detected on a new scan. |
| `FIXED` | "Fixed" | No longer detected. |

### `status` values

| Value | Meaning |
| ----- | ------- |
| `PASSED` | The asset passed the compliance check. |
| `FAILED` | The asset failed the compliance check. |
| `WARNING` | No definable passing criteria — manual review required (e.g. "verify admin group membership is appropriate"). |
| `SKIPPED` | The check is not applicable to this asset (wrong OS, offline device, etc.). |
| `UNKNOWN` | The OVAL engine could not determine a status. |

---

## Check Definition & Evaluation

What the check actually evaluated, what it expected, and what it found.

| Field | Type | Description |
| ----- | ---- | ----------- |
| `check_name` | string | Descriptive name of the compliance check. |
| `check_info` | string | Full prose description of the check. |
| `description` | string | Detailed description of the compliance check. May overlap with `check_info`. |
| `synopsis` | string | Short summary of the compliance audit. |
| `expected_value` | string | Desired value for the check. For manual checks, this is the **command** that was meant to run. Example: a password-length check with required length 8 has `expected_value = "8"`. |
| `actual_value` | string | Value evaluated from the check. For manual checks, this is the **command output**. Example: same password-length check finds length 7 → `actual_value = "7"`. May be a long string or table-formatted text. |
| `audit_file` | string | Name of the audit file (`.audit`) containing the check. |
| `profile_name` | string | Profile name for the benchmark standard (e.g. `Level 1 - Server`). |
| `db_type` | string | Type of database, if the check evaluated a database (e.g. `MSSQL`, `Oracle`, `MySQL`). |
| `uname_output` | string | Output of the `uname` command on the asset — typically OS type and kernel version. |
| `solution` | string | Remediation guidance for the check. |

---

## Benchmark & Framework Identifiers

The fields that locate this check inside a standard benchmark (CIS, DISA STIG, custom audits).

| Field | Type | Description |
| ----- | ---- | ----------- |
| `compliance_benchmark_name` | string | Name of the benchmark (e.g. `CIS SQL Server 2019`). |
| `compliance_benchmark_version` | string | Version of the benchmark (e.g. `1.2.0`). |
| `compliance_control_id` | string | Hashed identifier that aggregates multiple results to a single CIS/DISA recommendation — lets consumers match checks that evaluate the same recommendation within a benchmark. |
| `compliance_full_id` | string | Hash of the full check (excluding external references). **Changes** if any field in the check changes. |
| `compliance_functional_id` | string | Hash of the **functional logic** inside the audit (what the check actually does). Changes only when the evaluation changes — useful for tracking the same check across cosmetic edits. |
| `compliance_informational_id` | string | Hash of the **descriptive fields** (info + solution text). Changes only when documentation changes. |
| `reference[]` | array<object> | Industry references for the check — see [Reference Sub-Object](#reference-sub-object). |
| `see_also` | string | Links to external websites with additional context on the check. |

### Reference Sub-Object

Maps the check to specific controls in external compliance frameworks (e.g. NIST 800-53, ISO 27001, PCI-DSS).

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `framework` | string | Name of the compliance framework (e.g. `CIS`, `NIST 800-53`, `PCI-DSS`, `HIPAA`). |
| `control` | string | Specific control inside that framework (e.g. `AC-2`, `1.1.5`, `5.5.3`). |

---

## Timing Fields

| Field | Type | Description |
| ----- | ---- | ----------- |
| `first_seen` | ISO timestamp | When a compliance scan first assessed this asset with this check. |
| `last_seen` | ISO timestamp | When a compliance scan most recently assessed this asset with this check. |
| `last_fixed` | ISO timestamp | When the failure was last fixed on this asset (only meaningful for previously-failed checks). |
| `last_observed` | ISO timestamp | When the check result was last observed (whether active or fixed). |
| `indexed_at` | ISO timestamp | When the audit result was indexed into Tenable VM. Useful for "since last run" filters. |

---

## Embedded `assets` Sub-Object

A **snapshot** of the asset at the time the check ran. For full asset attributes (tags, ACR/AES, last-licensed-scan dates, sources, etc.) join against the assets export by `asset_uuid` → `assets.id`.

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `id` | string | Asset UUID. Equal to the top-level `asset_uuid`. |
| `name` | string | Asset name. |
| `ipv4_addresses` | array<string> | IPv4 addresses associated with the asset at scan time. |
| `ipv6_addresses` | array<string> | IPv6 addresses associated with the asset at scan time. |
| `fqdns` | array<string> | FQDNs associated with the asset at scan time. |
| `netbios_name` | string | NetBIOS name. |
| `mac_addresses` | array<string> | MAC addresses associated with the asset at scan time. |
| `operating_systems` | array<string> | Operating system strings. |
| `system_type` | string | Reported by Plugin ID 54615: `router`, `general-purpose`, `scan-host`, `embedded`. |
| `network_id` | string | UUID of the network that produced this scan. Default: `00000000-0000-0000-0000-000000000000`. |
| `agent_name` | string | Name of the Nessus Agent that scanned the asset, if applicable. |
| `agent_uuid` | string | UUID of the Nessus Agent that identified the asset, if applicable. |
| `tags[]` | array<object> | Tenable tags assigned to the asset. **Note:** unlike the assets export, each tag entry here uses `category` + `values[]` (plural) instead of `key` + `value`. |

### Embedded tag shape

The compliance-export embedded tag schema differs from the assets export. Be aware when joining or normalizing.

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `category` | string | Tag category (e.g. `Environment`, `Application`). |
| `values` | array<string> | Tag values for that category (plural — an asset can carry multiple values for the same category). |

> **Compare with the assets-export tag shape** (`{uuid, key, value, added_by, added_at}` per entry) — the compliance export is **lossy** by comparison (no UUIDs, no who/when). For full tag fidelity, always join to the assets export by `asset_uuid`.

---

## Field-to-Metric Cheat Sheet

Starter map for common compliance-reporting questions, mirroring the cheat sheet style in the vuln reference.

| Question | Fields to use |
| -------- | ------------- |
| **Currently-failing checks** | `state in ('OPEN','REOPENED')` AND `status = 'FAILED'` |
| **Currently-warning checks** | `state in ('OPEN','REOPENED')` AND `status = 'WARNING'` |
| **Pass rate by asset** | Group by `asset_uuid`; `count(status='PASSED') / count(status in ('PASSED','FAILED'))` |
| **Pass rate by control / framework** | Explode `reference[]`; group by `(framework, control)` |
| **Pass rate by benchmark** | Group by `(compliance_benchmark_name, compliance_benchmark_version)` |
| **How long has it been failing?** | `today - first_seen` for rows where `status='FAILED'` and `state in ('OPEN','REOPENED')` |
| **When was a previously-failing check fixed?** | `last_fixed` (only meaningful where `state='FIXED'`) |
| **Remediation guidance** | `solution` |
| **What was actually wrong?** | `actual_value` (observed) vs `expected_value` (desired) |
| **Tag-scoped reports** | Use embedded `assets.tags[]` for quick filtering, or join to the assets export by `asset_uuid` for full tag fidelity. |
| **Group asset by environment / BU** | Join `asset_uuid` to assets export; filter on `tags[]` (e.g. `category=Environment`, `category=Application`). |

---

## Adding to This Document

When a new field, derived attribute, or framework mapping is introduced:

1. Add the field with type and description in the matching section.
2. If introducing a project-specific use (e.g. a new compliance metric module), cross-link to the runbook that consumes it.
3. Keep the cheat sheet in sync — it's the section AI assistants will key off when composing new compliance modules.
