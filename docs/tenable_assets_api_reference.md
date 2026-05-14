# Tenable Assets API — Field Reference

A user- and AI-friendly dictionary of the fields returned by the Tenable Vulnerability Management (Tenable.io) **Assets Export** API. This document covers **both** versions of the asset export endpoint so the team can reason about what we use today and what we'd inherit from a future migration.

| Version | Endpoint | pyTenable method | Current use in this project |
| ------- | -------- | ---------------- | --------------------------- |
| **v1** | `POST /assets/export` | `tio.exports.assets()` | **In use today** — `data/fetchers.py` |
| **v2** | `POST /assets/v2/export` | `tio.exports.assets_v2()` | **Not yet adopted** — future migration target |

- Source: official Tenable API documentation (assets export response schemas).
- Example payloads: [`ref/assets_v1_api_response.json`](../ref/assets_v1_api_response.json) and [`ref/assets_v2_api_response.json`](../ref/assets_v2_api_response.json).
- Migration plan: see the backlog entry "pyTenable upgrade + asset export v2 migration" in [`.planning/ROADMAP.md`](../.planning/ROADMAP.md).
- For project terminology: [`GLOSSARY.md`](GLOSSARY.md). For the vulnerability-export schema: [`tenable_vuln_api_reference.md`](tenable_vuln_api_reference.md).

> **How to read this document**
>
> Each field row carries one of three version markers:
>
> - **[v1]** — Present only in the v1 schema. If we migrate, this field is **gone or renamed** in v2 (a v2 equivalent, if any, is named in the row).
> - **[v2]** — Present only in the v2 schema. **Not** in our current data. Surfaces only after the migration.
> - **[v1+v2]** — Present in both schemas. May live at a **different nesting path** in v2 — the row gives both paths when they differ.
>
> Where v2 introduces a sub-object (e.g. `scan`, `cloud`, `timestamps`, `network`, `third_party_ids`, `ratings`), the v2 path is given as `parent.field`. v1 paths are always flat.

> **Project conventions you should know**
>
> - **Severity / VPR** are vulnerability concepts and do not appear on assets. The asset export contributes **exposure scoring** (`acr_score` / `ratings.acr.score`, `exposure_score` / `ratings.aes.score`) but not VPR.
> - **Tag enrichment** of vulnerability findings happens via this asset export — the `tags` array on each asset is joined onto the vulns DataFrame post-fetch (see [`utils/tag_helper.py`](../utils/tag_helper.py)). Asset tags are the **only** source of tag data; the vulnerability export does not carry tags.
> - **`last_licensed_scan_date`** is the load-bearing field for the project's Scan Coverage SLA and the on-time-asset baseline used across the Board and Management summaries. Same field name in both v1 and v2, but in v2 it lives under `scan.last_licensed_scan_date`.
> - **Timezone policy** (project): timestamps in the API are ISO-8601 UTC; cache folder names use local-machine date.

---

## Top-Level Asset Object — Identity & Lifecycle

Each row in the export is one **asset** — a tracked host, network device, or cloud resource. The top-level fields cover identity, lifecycle state, and the "who reported it" pointers.

| Field | Type | Description | Version |
| ----- | ---- | ----------- | ------- |
| `id` | string | Unique asset identifier in Tenable VM. **Join key** for tag enrichment, trend snapshots, and vuln→asset lookups. | **[v1+v2]** |
| `has_agent` | boolean | A Nessus Agent scan identified this asset. | **[v1+v2]** |
| `has_plugin_results` | boolean | This asset has plugin (vulnerability) results associated with it. | **[v1+v2]** |
| `is_licensed` | boolean | Asset is currently counted against the Tenable license. | **[v2]** *(in v1, infer from `last_licensed_scan_date != null`)* |
| `agent_uuid` | string | Tenable UUID assigned by agent or credentialed scan. Null for unauthenticated non-agent scans. | **[v1+v2]** |
| `bios_uuid` | string | BIOS UUID of the asset. **v2 path:** `network.bios_uuid`. | **[v1+v2]** |
| `network_device_serial_identifier` | string | Network-device serial number used for identification. | **[v2]** |
| `serial_number` | string | Manufacturer-assigned serial (network devices only). | **[v1]** *(v2 partially replaces with `network_device_serial_identifier`)* |
| `terminated_by` | string | Username that terminated the cloud-platform instance. | **[v1+v2]** |
| `deleted_by` | string | Username that deleted the asset record. | **[v1+v2]** |
| `types` | array<string> | Asset type(s) — used to distinguish host, Web App Scanning (WAS), and cloud-resource assets. | **[v2]** *(v1 has no equivalent — type was implicit per source)* |
| `is_public` | boolean | Asset is internet-facing / externally accessible. | **[v2]** *(unlocks structured external-facing detection; v1 requires the RFC-1918 IP heuristic — see [`.planning/notes/operator-remediation-priority-model.md`](../.planning/notes/operator-remediation-priority-model.md))* |
| `custom_attributes` | array<{id, value}> | Org-defined custom attributes attached to the asset. | **[v2]** |

---

## Timestamps

In v1, all timestamps sit at the top level. In v2, they are split: **lifecycle** timestamps live under `timestamps.*`; **scan** timestamps live under `scan.*` (see [Scan Timestamps](#scan-timestamps) below).

| Field | Type | Description | v1 path | v2 path |
| ----- | ---- | ----------- | ------- | ------- |
| `created_at` | ISO timestamp | When Tenable VM created the asset record. | `created_at` | `timestamps.created_at` |
| `updated_at` | ISO timestamp | When the asset record was last updated. | `updated_at` | `timestamps.updated_at` |
| `deleted_at` | ISO timestamp | When a user deleted the record (retained until it ages out of the license). | `deleted_at` | `timestamps.deleted_at` |
| `terminated_at` | ISO timestamp | When the cloud-platform instance was terminated. | `terminated_at` | `timestamps.terminated_at` |
| `first_seen` | ISO timestamp | First scan detection of the asset. | `first_seen` | `timestamps.first_seen` |
| `last_seen` | ISO timestamp | Most recent scan detection. **Drives hostname-dedup tiebreak** in `board_report_utils.deduplicate_assets_by_name()`. | `last_seen` | `timestamps.last_seen` |
| `tenable_agent_days_since_active` | int | Days since the Nessus Agent last observed the asset (only when `sources` includes `NESSUS_AGENT`). | top-level | top-level (unchanged) |

### Scan Timestamps

These are the timestamps for the scan that produced the asset record. **`last_licensed_scan_date` is the load-bearing field for Scan Coverage SLA / on-time-asset baseline.**

| Field | Type | Description | v1 path | v2 path |
| ----- | ---- | ----------- | ------- | ------- |
| `first_scan_time` | ISO timestamp | Date and time of the first scan run against this asset. | `first_scan_time` | `scan.first_scan_time` |
| `last_scan_time` | ISO timestamp | Date and time of the last scan run against this asset. | `last_scan_time` | `scan.last_scan_time` |
| `last_authenticated_scan_date` | ISO timestamp | Most recent credentialed scan of this asset. | `last_authenticated_scan_date` | `scan.last_authenticated_scan_date` |
| `last_licensed_scan_date` | ISO timestamp | Last scan that identified the asset as licensed (returned results from a non-discovery plugin in the last 90 days). **Drives Scan Coverage SLA.** | `last_licensed_scan_date` | `scan.last_licensed_scan_date` |
| `last_scan_id` | string / uuid | Unique identifier of the scan configuration used for the most recent scan. | `last_scan_id` | `scan.last_scan_id` |
| `last_schedule_id` | string | `schedule_uuid` of the scan schedule used for the most recent scan. | `last_schedule_id` | `scan.last_schedule_id` |
| `last_authentication_attempt_date` | ISO timestamp | Last time a scan attempted SSH (Unix) or SMB (Windows) authentication. | `last_authentication_attempt_date` | `scan.last_authentication_attempt_date` |
| `last_authentication_success_date` | ISO timestamp | Last successful authentication. **Not updated by Agent scans.** | `last_authentication_success_date` | `scan.last_authentication_success_date` |
| `last_authentication_scan_status` | string | `Success` / `Failure` / `N/A`. Not updated by Agent scans. | `last_authentication_scan_status` | `scan.last_authentication_scan_status` |
| `last_scan_target` | string | IP or FQDN that was actually probed in the last scan. | `last_scan_target` | `scan.last_scan_target` |

---

## Network Identity

In v1, network identifiers live at the top level. In v2, they're under `network.*`.

| Field | Type | Description | v1 path | v2 path |
| ----- | ---- | ----------- | ------- | ------- |
| `network_id` | string | UUID of the network assigned to the scanners. Default network is `00000000-0000-0000-0000-000000000000`. | `network_id` | `network.network_id` |
| `network_name` | string | Name of the network object (default name is `Default`). | `network_name` | `network.network_name` |
| `ipv4s` | array<string> | All IPv4 addresses associated with the asset. | `ipv4s` | `network.ipv4s` |
| `ipv6s` | array<string> | All IPv6 addresses associated with the asset. | `ipv6s` | `network.ipv6s` |
| `fqdns` | array<string> | All fully-qualified domain names. | `fqdns` | `network.fqdns` |
| `mac_addresses` | array<string> | All MAC addresses. | `mac_addresses` | `network.mac_addresses` |
| `netbios_names` | array<string> | All NetBIOS names. | `netbios_names` | `network.netbios_names` |
| `hostnames` | array<string> | All hostnames. **Used for hostname-based dedup** in the on-time-asset baseline. | `hostnames` | `network.hostnames` |
| `operating_systems` | array<string> | Operating system strings. | `operating_systems` | top-level (unchanged) |
| `system_types` | array<string> | Reported by Plugin ID 54615. Values: `router`, `general-purpose`, `scan-host`, `embedded` (v2 also includes `firewall`). | `system_types` | top-level (unchanged) |
| `ssh_fingerprints` | array<string> | SSH key fingerprints. | `ssh_fingerprints` | `network.ssh_fingerprints` |

### Network Interfaces

Both versions ship a `network_interfaces` array. v2 adds two additional booleans on each interface.

| Sub-field | Type | Description | Version |
| --------- | ---- | ----------- | ------- |
| `name` | string | Interface name. | **[v1+v2]** |
| `mac_addresses` | array<string> | MAC addresses on this interface. | **[v1+v2]** |
| `ipv4s` | array<string> | IPv4 addresses on this interface. | **[v1+v2]** |
| `ipv6s` | array<string> | IPv6 addresses on this interface. | **[v1+v2]** |
| `fqdns` | array<string> | FQDNs on this interface. | **[v1+v2]** |
| `virtual` | boolean | Interface is a virtual interface. | **[v2]** |
| `aliased` | boolean | Interface is aliased. | **[v2]** |

---

## Cloud Provider Attributes

In v1, the AWS / Azure / GCP fields are flat with a prefix (`aws_*`, `azure_*`, `gcp_*`). In v2, they're nested under `cloud.{provider}.*`.

### AWS

| Field | v1 path | v2 path |
| ----- | ------- | ------- |
| EC2 AMI ID | `aws_ec2_instance_ami_id` | `cloud.aws.ec2_instance_ami_id` |
| EC2 instance ID | `aws_ec2_instance_id` | `cloud.aws.ec2_instance_id` |
| AWS account owner ID | `aws_owner_id` | `cloud.aws.owner_id` |
| Availability zone | `aws_availability_zone` | `cloud.aws.availability_zone` |
| Region | `aws_region` | `cloud.aws.region` |
| VPC ID | `aws_vpc_id` | `cloud.aws.vpc_id` |
| EC2 instance group name | `aws_ec2_instance_group_name` | `cloud.aws.ec2_instance_group_name` |
| EC2 instance state | `aws_ec2_instance_state_name` | `cloud.aws.ec2_instance_state_name` |
| EC2 instance type | `aws_ec2_instance_type` | `cloud.aws.ec2_instance_type` |
| Subnet ID | `aws_subnet_id` | `cloud.aws.subnet_id` |
| EC2 product code | `aws_ec2_product_code` | `cloud.aws.ec2_product_code` |
| EC2 instance name | `aws_ec2_name` | `cloud.aws.ec2_name` |

### Azure

| Field | v1 path | v2 path |
| ----- | ------- | ------- |
| VM ID | `azure_vm_id` | `cloud.azure.vm_id` |
| Resource ID | `azure_resource_id` | `cloud.azure.resource_id` |

### GCP

| Field | v1 path | v2 path |
| ----- | ------- | ------- |
| Project ID | `gcp_project_id` | `cloud.gcp.project_id` |
| Zone | `gcp_zone` | `cloud.gcp.zone` |
| Instance ID | `gcp_instance_id` | `cloud.gcp.instance_id` |

---

## Third-Party Asset IDs

In v1, these are flat; in v2, they live under `third_party_ids.*`.

| Field | Type | v1 path | v2 path |
| ----- | ---- | ------- | ------- |
| McAfee ePO asset GUID | string | `mcafee_epo_guid` | `third_party_ids.mcafee_epo_guid` |
| McAfee ePO agent GUID | string | `mcafee_epo_agent_guid` | `third_party_ids.mcafee_epo_agent_guid` |
| ServiceNow sys_id | string | `servicenow_sysid` | `third_party_ids.servicenow_sysid` |
| BigFix asset ID | string | `bigfix_asset_id` | `third_party_ids.bigfix_asset_id` |
| Qualys asset IDs | array<string> | `qualys_asset_ids` | `third_party_ids.qualys_asset_ids` |
| Qualys host IDs | array<string> | `qualys_host_ids` | `third_party_ids.qualys_host_ids` |
| Symantec EP hardware keys | array<string> | `symantec_ep_hardware_keys` | `third_party_ids.symantec_ep_hardware_keys` |

---

## Sources

`sources` is an array of objects describing every scanner / connector / API import that has reported this asset. Schema is **unchanged** between v1 and v2.

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `name` | string | Source name. Common values: `NESSUS_SCAN`, `NESSUS_AGENT`, `PVS` (NNM), `AWS`, `WAS`, plus any custom names defined for your tenant. |
| `first_seen` | ISO timestamp | When this source first reported the asset. |
| `last_seen` | ISO timestamp | When this source most recently reported the asset. |

### Common source names

| Source | Meaning |
| ------ | ------- |
| `NESSUS_SCAN` | Tenable Nessus scan |
| `NESSUS_AGENT` | Tenable Nessus Agent scan |
| `PVS` | Tenable Nessus Network Monitor (NNM) — historical name "PVS" is preserved |
| `AWS` | Amazon Web Services connector |
| `WAS` | Tenable Web App Scanning |

---

## Tags

`tags` is an array of `category=value` pairs assigned to the asset in Tenable VM. Schema is **unchanged** between v1 and v2. These tags drive the project's filter/segmentation contract (see `delivery_config.yaml` and [`utils/tag_helper.py`](../utils/tag_helper.py)).

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `uuid` | string | Tag UUID. |
| `key` | string | The category portion of the `category=value` pair (e.g. `Environment`, `Application`, `Location`). |
| `value` | string | The value portion (e.g. `Production`, `Finance`, `DMZ`). |
| `added_by` | string | UUID of the user who assigned the tag. |
| `added_at` | ISO timestamp | When the tag was assigned. |

---

## Open Ports

`open_ports` is an array of info-level plugin findings carrying port + service detail. Schema is **unchanged** between v1 and v2.

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `port` | int | Open port number. |
| `protocol` | string | Communication protocol. |
| `service_names` | array<string> | Service names associated with the port. |
| `first_seen` | ISO timestamp | When this open port was first detected. |
| `last_seen` | ISO timestamp | When this open port was most recently detected. |

---

## Software Inventory

| Field | Type | Description | Version |
| ----- | ---- | ----------- | ------- |
| `installed_software` | array<string> | CPE 2.2 strings for software detected by plugin 45590. Software entries **expire after 30 days** without a fresh detection. | **[v1+v2]** |
| `agent_names` | array<string> | Names of any Tenable Agents that scanned the asset. | **[v1+v2]** |
| `manufacturer_tpm_ids` | array<string> | TPM identifiers. | **[v1+v2]** |

---

## Ratings — ACR & AES (Lumin Metrics)

Both versions expose `ratings.acr.score` and `ratings.aes.score` at the same path. v1 also carries **legacy duplicates** at the top level as strings; v2 drops the legacy fields.

| Concept | Type | v1 path(s) | v2 path | Notes |
| ------- | ---- | ---------- | ------- | ----- |
| **ACR** — Asset Criticality Rating (1 – 10) | float (`ratings.acr.score`) and string (`acr_score`) | `ratings.acr.score` **+** `acr_score` (legacy, string-typed) | `ratings.acr.score` only | Reflects business importance of the asset to the organization. Higher = more critical. Use `ratings.acr.score` for new integrations — Tenable has marked `acr_score` as a **legacy** field. |
| **AES** — Asset Exposure Score (1 – 1000) | float (`ratings.aes.score`) and string (`exposure_score`) | `ratings.aes.score` **+** `exposure_score` (legacy, string-typed) | `ratings.aes.score` only | Weighted combination of VPR and ACR. Higher = more exposed. Use `ratings.aes.score` for new integrations. |

> **Why this matters for us:** ACR and AES are the two strongest candidate signals for replacing the project's RFC-1918 "externally-facing" heuristic and for sharpening the Operator Remediation priority model. Both fields exist in v1 today (under `ratings.*`) — so we **don't need to wait for v2 to start using them**.

---

## Resource Tags (Cloud-Imported)

`resource_tags` is a flat array of `{key, value}` pairs imported from a Cloud Discovery Connector. **Distinct from `tags`** — these are the native AWS / Azure / GCP resource tags, not Tenable VM tags.

| Sub-field | Type | Description |
| --------- | ---- | ----------- |
| `key` | string | Resource tag key as defined in the cloud provider. |
| `value` | string | Resource tag value. |

Both versions ship this array. v2 adds the explicit `include_resource_tags` request parameter for finer payload control.

---

## v1 → v2 Migration Summary

A condensed reference for what changes structurally when we move from `assets()` to `assets_v2()`. See the [pyTenable upgrade + asset export v2 migration](../.planning/ROADMAP.md) backlog entry for the recommended sequencing.

### New in v2

- `is_licensed` (boolean) — replaces inference from `last_licensed_scan_date`.
- `types` (array<string>) — first-class asset type (host / WAS / cloud-resource).
- `is_public` (boolean) — **structured external-facing flag**, candidate replacement for the RFC-1918 heuristic.
- `network_device_serial_identifier` — explicit field for network device serials.
- `custom_attributes` — org-defined custom attributes.
- `network_interfaces[].virtual` and `network_interfaces[].aliased`.

### Restructured in v2 (same data, new path)

- All `created_at` / `updated_at` / `deleted_at` / `terminated_at` / `first_seen` / `last_seen` → moved under `timestamps.*`.
- All scan-related timestamps (`last_scan_*`, `last_authenticated_scan_date`, `last_licensed_scan_date`, `last_authentication_*`) → moved under `scan.*`.
- All `aws_*` / `azure_*` / `gcp_*` → moved under `cloud.{aws|azure|gcp}.*` (with the prefix stripped).
- All `mcafee_epo_*` / `servicenow_sysid` / `bigfix_asset_id` / `qualys_*` / `symantec_ep_*` → moved under `third_party_ids.*`.
- `network_id` / `network_name` / `bios_uuid` / `ipv4s` / `ipv6s` / `fqdns` / `mac_addresses` / `netbios_names` / `hostnames` / `ssh_fingerprints` → moved under `network.*`.

### Dropped or replaced in v2

- `acr_score` (string) → use `ratings.acr.score` (float).
- `exposure_score` (string) → use `ratings.aes.score` (float).
- `serial_number` → use `network_device_serial_identifier` for network-device-specific cases.

### Unchanged shape (no path change)

- `sources[]`, `tags[]`, `open_ports[]`, `resource_tags[]`, `installed_software[]`, `agent_names[]`, `manufacturer_tpm_ids[]`, `operating_systems[]`, `system_types[]`.
- `id`, `has_agent`, `has_plugin_results`, `agent_uuid`, `terminated_by`, `deleted_by`, `tenable_agent_days_since_active`.

---

## Adding to This Document

When a new field, derived attribute, or version delta is introduced:

1. Add the field with type, description, and the appropriate version marker (**[v1]**, **[v2]**, or **[v1+v2]**).
2. If the field's path differs between versions, show both paths in the row.
3. If introducing a project-specific use, cross-link to the runbook or note that consumes it.
4. Keep the migration summary at the bottom in sync — that's the section the team will check when planning the v1→v2 cutover.
