# Tenable Vulnerability API — Field Reference

A user- and AI-friendly dictionary of the fields returned by the Tenable Vulnerability Management (Tenable.io) **Vulnerability Export** API and surfaced through `pyTenable`'s `tio.exports.vulns()`. Use this when designing metrics, writing fetchers, or interpreting cached parquet rows.

- Source: official Tenable API documentation (vuln export response schema).
- Example payload: [`docs/example_vulnerability_api_response_200.json`](example_vulnerability_api_response_200.json).
- For project-specific terminology (chrome, RAG strip, four-channel render contract, slug, etc.) see [`GLOSSARY.md`](GLOSSARY.md).

> **Project conventions you should know before reading**
>
> - **Severity is derived from `plugin.vpr.score`** (VPR), not from the CVSS-based `severity` / `severity_id` fields. See [CLAUDE.md → SLA Definitions](../CLAUDE.md). The CVSS-derived `severity`/`severity_id` are used as a fallback only when VPR is null.
> - **SLA windows are keyed to severity** (Critical 15d, High 30d, Medium 45d, Low 120d).
> - **A vulnerability is "open"** when `state` is `OPEN` or `REOPENED`. `FIXED` rows are used for MTTR / velocity calcs via `time_taken_to_fix` and `last_fixed`.
> - **Timezone policy** (project): timestamps in the API are ISO-8601 UTC. The reporting code stores UTC for metric calcs.
> - **Tag enrichment** is layered on after fetch via [`utils/tag_helper.py`](../utils/tag_helper.py). Tag fields are **not** part of the Vulnerability Export response — they come from the Assets export.

---

## Top-Level Vulnerability Object

Each row in the export is one **finding** — a (plugin × asset) detection. The top-level fields describe state, timing, source, and link out to nested `asset`, `plugin`, `port`, and `scan` sub-objects.

| Field                        | Type            | Description                                                                                     | Notes / project use                                                               |
| ---------------------------- | --------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `finding_id`                 | uuid (string)   | Unique identifier for the finding.                                                              | Primary key for a (plugin × asset) row.                                           |
| `severity`                   | string          | CVSS-derived label: `info`, `low`, `medium`, `high`, `critical`.                                | **Not** the field reports key off — see VPR note above.                           |
| `severity_id`                | int (0-4)       | Current numeric severity: `0=info, 1=low, 2=medium, 3=high, 4=critical`. Reflects user recasts. |                                                                                   |
| `severity_default_id`        | int (0-4)       | Original numeric severity **before** any recast. Same scale as `severity_id`.                   | Use to detect recast deltas (`severity_id != severity_default_id`).               |
| `severity_modification_type` | string          | `NONE` \| `RECASTED` \| `ACCEPTED`.                                                             | Drives risk-acceptance and recast reporting in `ops_remediation`.                 |
| `state`                      | string          | Finding state.                                                                                  | See state table below.                                                            |
| `first_found`                | ISO timestamp   | When a scan first detected this finding on this asset.                                          | Anchor for **SLA aging** — `today - first_found` vs SLA window.                   |
| `last_found`                 | ISO timestamp   | Most recent scan detection.                                                                     | Used in freshness/staleness checks.                                               |
| `last_fixed`                 | ISO timestamp   | When the finding stopped being detected (only for `FIXED`).                                     | Pair with `first_found` to compute MTTR.                                          |
| `time_taken_to_fix`          | int64 (seconds) | Server-side MTTR in seconds. **Only present for `FIXED`.**                                      | Prefer this over computing `last_fixed - first_found` to match Tenable's numbers. |
| `indexed`                    | int64 / ISO     | When the row was indexed into Tenable VM.                                                       | Useful for "since last run" filters.                                              |
| `source`                     | string          | Scan source. Common: `NESSUS`, `AGENT`, `NNM`.                                                  | Driver of Scan Coverage / unscanned-asset reporting.                              |
| `resurfaced_date`            | ISO timestamp   | When the finding most recently transitioned `FIXED → REOPENED`.                                 | Surface in trend & recurring-vuln modules.                                        |
| `output`                     | string          | Free-text scanner output explaining the detection.                                              | Asset evidence — surface in analyst tabs, not summaries.                          |

### `state` values

| API value  | UI equivalent     | Meaning                                                                  |
| ---------- | ----------------- | ------------------------------------------------------------------------ |
| `OPEN`     | "New" or "Active" | Currently detected on the asset.                                         |
| `REOPENED` | "Resurfaced"      | Previously marked `FIXED`, then re-detected. Treated as open for SLA.    |
| `FIXED`    | "Fixed"           | No longer detected. Use for MTTR / velocity, not for open-count metrics. |

---

## `asset` Object

Identifying information about the host where the finding lives. Reports join here to apply **Tag/Label segmentation** (after enrichment from the assets export).

| Field                          | Type          | Description                                                                                                                                    |
| ------------------------------ | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `uuid`                         | string        | Stable Tenable asset UUID. **Join key** for tag enrichment and trend snapshots.                                                                |
| `tracked`                      | boolean       | Whether Tenable persistently tracks this asset. Untracked assets get fresh identifiers each scan and **do not** appear in workbenches/reports. |
| `agent_uuid`                   | string        | UUID of the Nessus Agent that scanned, if applicable.                                                                                          |
| `bios_uuid`                    | string        | BIOS UUID.                                                                                                                                     |
| `device_type`                  | string        | E.g. `general-purpose`, `hypervisor`, `network`.                                                                                               |
| `fqdn`                         | string        | Fully-qualified domain name.                                                                                                                   |
| `hostname`                     | string        | Short hostname.                                                                                                                                |
| `netbios_name`                 | string        | NetBIOS name.                                                                                                                                  |
| `netbios_workgroup`            | string        | NetBIOS workgroup.                                                                                                                             |
| `ipv4`                         | string        | IPv4 address.                                                                                                                                  |
| `ipv6`                         | string        | IPv6 address.                                                                                                                                  |
| `mac_address`                  | string        | MAC address.                                                                                                                                   |
| `operating_system`             | array<string> | One or more OS strings.                                                                                                                        |
| `serial_number`                | string        | Manufacturer-assigned serial (network devices only).                                                                                           |
| `network_id`                   | uuid          | ID of the network the scanner saw the asset on. Default network is `00000000-0000-0000-0000-000000000000`.                                     |
| `last_authenticated_results`   | ISO timestamp | Last successful **credentialed** scan. Drives Scan Coverage SLA.                                                                               |
| `last_unauthenticated_results` | ISO timestamp | Last successful **unauthenticated** scan.                                                                                                      |

> Tag fields (e.g. `Environment=Production`) are **not** in this object — they're attached post-fetch by `utils/tag_helper.enrich_vulns_with_tags()` using the assets export.

---

## `plugin` Object

The detection definition: what was checked, why it's risky, and how Tenable scores it. Most metric logic lives here.

### Identification & description

| Field         | Type          | Description                                                                     |
| ------------- | ------------- | ------------------------------------------------------------------------------- |
| `id`          | int           | Plugin ID. Stable identifier — use as a join key for "vulns by plugin" rollups. |
| `name`        | string        | Plugin name (often the patch/bulletin name).                                    |
| `family`      | string        | Plugin family (`Windows : Microsoft Bulletins`, `CGI abuses`, etc.).            |
| `family_id`   | int           | Numeric family ID.                                                              |
| `type`        | string        | General check type, e.g. `local` or `remote`.                                   |
| `version`     | string        | Plugin version used at scan time.                                               |
| `synopsis`    | string        | One-line summary of the issue.                                                  |
| `description` | string        | Full prose description.                                                         |
| `solution`    | string        | Remediation guidance.                                                           |
| `see_also`    | array<string> | Reference links.                                                                |

### Risk & severity (CVSS-style)

| Field                  | Type        | Description                                                                                                    |
| ---------------------- | ----------- | -------------------------------------------------------------------------------------------------------------- |
| `risk_factor`          | string      | `low` / `medium` / `high` / `critical` based on CVSS. (Project keys off VPR instead.)                          |
| `vendor_severity`      | string      | Severity assigned by the CVE Numbering Authority (CNA), accounting for vendor mitigations.                     |
| `stig_severity`        | string      | STIG severity code (Cat I / II / III).                                                                         |
| `cvss_base_score`      | float 0-10  | **CVSSv2** base score.                                                                                         |
| `cvss_temporal_score`  | float       | CVSSv2 temporal score.                                                                                         |
| `cvss3_base_score`     | float 0-10  | **CVSSv3** base score.                                                                                         |
| `cvss3_temporal_score` | float       | CVSSv3 temporal score.                                                                                         |
| `cvss4_base_score`     | float 0-10  | **CVSSv4** base score.                                                                                         |
| `epss_score`           | float 0-100 | EPSS — probability (as a percent) the vuln is exploited in the wild in the next 30 days. Higher = more likely. |

CVSS **vector** sub-objects (`cvss_vector`, `cvss3_vector`, `cvss4_vector`) carry the metric breakdown (Attack Vector, Complexity, Privileges Required, Impact, etc.) plus a `raw` field with the standard string form (e.g. `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`). The temporal/threat vector variants (`cvss_temporal_vector`, `cvss3_temporal_vector`, `cvss4_threat_vector`) add Exploit Maturity, Remediation Level, and Report Confidence. See the original spec for the full enum values.

### Patch & vendor state

| Field                    | Type          | Description                                                          |
| ------------------------ | ------------- | -------------------------------------------------------------------- |
| `has_patch`              | boolean       | Vendor has published a patch.                                        |
| `vendor_unpatched`       | boolean       | Vendor has **not** released a patch yet. (Compare with `has_patch`.) |
| `patch_publication_date` | ISO timestamp | When the patch was released.                                         |
| `publication_date`       | ISO timestamp | When the plugin was first published.                                 |
| `vuln_publication_date`  | ISO timestamp | When the underlying vulnerability was first publicly disclosed.      |
| `modification_date`      | ISO timestamp | When the plugin was last updated.                                    |
| `unsupported_by_vendor`  | boolean       | The affected software is end-of-life.                                |
| `ms_bulletin`            | string        | Microsoft security bulletin reference.                               |
| `usn`                    | string        | Ubuntu Security Notice.                                              |

### Workarounds

| Field                  | Type          | Description                                  |
| ---------------------- | ------------- | -------------------------------------------- |
| `has_workaround`       | boolean       | A documented workaround exists.              |
| `workaround`           | string        | Free-text workaround description.            |
| `workaround_type`      | string        | `Configuration Change` or `Disable Service`. |
| `workaround_published` | ISO timestamp | When the workaround was published.           |

### Exploitability & threat-actor signals

| Field                          | Type    | Description                                             |
| ------------------------------ | ------- | ------------------------------------------------------- |
| `exploit_available`            | boolean | A public exploit exists.                                |
| `exploitability_ease`          | string  | Free-text description of exploitation difficulty.       |
| `exploited_by_malware`         | boolean | Known to be exploited by malware.                       |
| `exploited_by_nessus`          | boolean | Nessus actively confirmed exploitation during scanning. |
| `in_the_news`                  | boolean | Media-prominent (Shellshock, Meltdown, etc.).           |
| `checks_for_default_account`   | boolean | Plugin checks for default-credential exposure.          |
| `checks_for_malware`           | boolean | Plugin checks for malware.                              |
| `exploit_framework_canvas`     | boolean | Exploit available in Immunity CANVAS.                   |
| `exploit_framework_core`       | boolean | Exploit available in CORE Impact.                       |
| `exploit_framework_d2_elliot`  | boolean | Exploit available in D2 Elliot Web Exploitation.        |
| `exploit_framework_exploithub` | boolean | Exploit available in ExploitHub.                        |
| `exploit_framework_metasploit` | boolean | Exploit available in Metasploit.                        |
| `canvas_package`               | string  | CANVAS exploit-pack name.                               |
| `d2_elliot_name`               | string  | D2 Elliot exploit name.                                 |
| `exploithub_sku`               | string  | ExploitHub SKU.                                         |
| `metasploit_name`              | string  | Metasploit module name.                                 |

### Cross-references

| Field   | Type              | Description                                                                          |
| ------- | ----------------- | ------------------------------------------------------------------------------------ |
| `cve`   | array<string>     | CVE IDs the plugin covers.                                                           |
| `bid`   | array<int>        | Bugtraq IDs.                                                                         |
| `cpe`   | array<string>     | CPE identifiers.                                                                     |
| `xrefs` | array<{type, id}> | Third-party references — each item has `type` (e.g. `CVE`, `MSKB`, `IAVA`) and `id`. |

### Recast / risk-acceptance pointers

These fields live at the **top level** of the finding (not under `plugin`), but they reference plugin-scoped rules defined in Tenable VM:

| Field              | Type   | Description                                           |
| ------------------ | ------ | ----------------------------------------------------- |
| `recast_rule_uuid` | string | UUID of the recast/accept rule that applies.          |
| `recast_reason`    | string | The reason text from the recast rule's Comment field. |

Active recast/accept rules can be pulled via `fetch_recast_rules()` (`data/fetchers.py`), which calls `POST /v1/recast/rules/search`. The rule body includes the filter tree (Plugin ID, Asset ID, IPv4/6, FQDN, Network, CVE, Plugin Output, Protocol, Tags), expiration date, original severity, and `created_at`. `ops_remediation` enriches with these.

---

## `plugin.vpr` — Vulnerability Priority Rating (current)

> ⚠️ **VPR is the project's primary severity signal.** All SLA windows, RAG colors, and "what should we fix first" metrics derive from `plugin.vpr.score`, falling back to `severity` only when `vpr.score` is null. See [CLAUDE.md → SLA Definitions](../CLAUDE.md).

| Field     | Type          | Description                                                                                              |
| --------- | ------------- | -------------------------------------------------------------------------------------------------------- |
| `score`   | float 0-10    | Tenable's VPR for this vulnerability. If a plugin covers multiple CVEs, this is the **max** across them. |
| `updated` | ISO timestamp | When Tenable last imported VPR for this vuln (refreshed daily).                                          |
| `drivers` | object        | Breakdown of inputs that produced the score (see below).                                                 |

### `plugin.vpr.drivers`

| Driver                        | Type                         | Meaning                                                                                                                                                              |
| ----------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `age_of_vuln`                 | `{lower_bound, upper_bound}` | Bucketed days since NVD published. Ranges: 0-7, 7-30, 30-60, 60-180, 180-365, 365-730, 731+. For the top bucket, `upper_bound` is `0` (sentinel meaning "no upper"). |
| `threat_recency`              | `{lower_bound, upper_bound}` | Bucketed days since last threat event. Ranges: 0-7, 7-30, 30-120, 120-365, 366+. Same `0`-as-sentinel rule for the top bucket.                                       |
| `threat_intensity_last28`     | string                       | `Very Low` / `Low` / `Medium` / `High` / `Very High` — frequency of threat events in the last 28 days.                                                               |
| `threat_sources_last28`       | array<string>                | Where the threat events came from (social media, dark web, etc.).                                                                                                    |
| `exploit_code_maturity`       | string                       | `High` / `Functional` / `PoC` / `Unproven` — parallels the CVSS Exploit Code Maturity categories.                                                                    |
| `product_coverage`            | string                       | `Low` / `Medium` / `High` / `Very High` — how many distinct products are affected.                                                                                   |
| `cvss3_impact_score`          | float                        | NVD's CVSSv3 impact score (or Tenable's prediction).                                                                                                                 |
| `cvss_impact_score_predicted` | boolean                      | `true` if `cvss3_impact_score` was predicted by Tenable (NVD didn't supply one).                                                                                     |

---

## `plugin.vpr_v2` — VPR Version 2 (Beta)

> ⚠️ **Scheduled deprecation: 2026-07-01.** On that date, `plugin.vpr` will start being populated by the v2 model and `plugin.vpr_v2` will be retired. Migrate consumers to read from `plugin.vpr` before then.

| Field                                   | Type          | Description                                                                                                                                                                                        |
| --------------------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `score`                                 | float 0.1-10  | VPR v2 score.                                                                                                                                                                                      |
| `vpr_percentile`                        | float         | Percentile vs all scored vulns.                                                                                                                                                                    |
| `vpr_severity`                          | enum          | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE`.                                                                                                                                                   |
| `exploit_probability`                   | float 0-1     | Likelihood of in-the-wild exploitation.                                                                                                                                                            |
| `cve_id`                                | string        | The CVE the v2 score is anchored to.                                                                                                                                                               |
| `exploit_code_maturity`                 | string        | Same axis as the v1 driver.                                                                                                                                                                        |
| `on_cisa_kev`                           | boolean       | Whether the CVE is on CISA's Known Exploited Vulnerabilities list.                                                                                                                                 |
| `exploit_chain`                         | array<string> | CVEs that form an exploit chain with this vuln.                                                                                                                                                    |
| `in_the_news_intensity_last30`          | enum          | `VERY_HIGH` / `HIGH` / `MEDIUM` / `LOW` / `VERY_LOW`.                                                                                                                                              |
| `in_the_news_recency`                   | enum          | `0_7_DAYS` / `7_14_DAYS` / `14_30_DAYS` / `30_60_DAYS` / `60_180_DAYS` / `NO_RECORDED_EVENTS`.                                                                                                     |
| `in_the_news_sources_last30`            | array<enum>   | Source categories (Academic, Blogs, Code Repositories, Cyber News, Cybersecurity Vendors, Forums, Government, Mainstream News, Other, Security Research, Technology Companies, Tools & Resources). |
| `malware_observations_intensity_last30` | enum          | Same scale as `in_the_news_intensity_last30`.                                                                                                                                                      |
| `malware_observations_recency`          | enum          | Same buckets as `in_the_news_recency`.                                                                                                                                                             |
| `targeted_industries`                   | array<enum>   | Industries observed to be targeted (Banking, Healthcare, Government, …).                                                                                                                           |
| `targeted_regions`                      | array<enum>   | Geographic regions observed to be targeted.                                                                                                                                                        |
| `threat_summary`                        | object        | Additional summary fields.                                                                                                                                                                         |
| `remediation`                           | object        | Patch / config / workaround recommendations.                                                                                                                                                       |

---

## `port` Object

| Field      | Type   | Description                                    |
| ---------- | ------ | ---------------------------------------------- |
| `port`     | int    | Network port the scanner reached the asset on. |
| `protocol` | string | `TCP` / `UDP` / `ICMP`.                        |
| `service`  | string | Detected service (`www`, `cifs`, `ssh`, etc.). |

---

## `scan` Object

| Field              | Type          | Description                          |
| ------------------ | ------------- | ------------------------------------ |
| `uuid`             | string        | Scan UUID.                           |
| `schedule_uuid`    | string        | Scan schedule UUID.                  |
| `started_at`       | ISO timestamp | Scan start time.                     |
| `last_scan_target` | string        | IP/FQDN the scanner actually probed. |

---

## CVSS Vector Enum Quick-Reference

The CVSS vector sub-objects each expose `raw` plus named axes. Allowed values per axis:

| Axis                                              | CVSSv2                                      | CVSSv3                                                                  | CVSSv4                                                                                    |
| ------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Attack Vector                                     | `Network` / `Adjacent Network` / `Local`    | `Network` / `Adjacent` / `Local` / `Physical`                           | `Network` / `Adjacent` / `Local` / `Physical`                                             |
| Attack Complexity                                 | `H` / `M` / `L`                             | `H` / `M` / `L`                                                         | `Low` / `High`                                                                            |
| Attack Requirements                               | —                                           | —                                                                       | `None` / `Present`                                                                        |
| Privileges Required                               | —                                           | —                                                                       | `None` / `Low` / `High`                                                                   |
| User Interaction                                  | —                                           | —                                                                       | `None` / `Passive` / `Active`                                                             |
| Authentication                                    | `N` / `S` / `M` (None / Single / Multiple)  | —                                                                       | —                                                                                         |
| Confidentiality / Integrity / Availability impact | `N` / `P` / `C` (None / Partial / Complete) | `H` / `L` / `N`                                                         | `High` / `Low` / `None` (vulnerable system) + `High` / `Low` / `None` (subsequent system) |
| Exploit Maturity (temporal/threat)                | `U` / `POC` / `F` / `H` / `ND`              | `Unproven` / `Proof-of-concept` / `Functional` / `High` / `Not-defined` | `Not Defined` / `Attacked` / `Proof-of-Concept` / `Unreported`                            |
| Remediation Level (temporal)                      | `OF` / `TF` / `W` / `U` / `ND`              | `O` / `T` / `W` / `U` / `X`                                             | —                                                                                         |
| Report Confidence (temporal)                      | `UC` / `UR` / `C` / `ND`                    | `U` / `R` / `C` / `X`                                                   | —                                                                                         |

The `raw` strings follow standard CVSS notation, e.g.:

- CVSSv2: `AV:N/AC:L/Au:S/C:C/I:C/A:C`
- CVSSv3: `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- CVSSv4 base + threat: `AV:N/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H` + `CVSS:4.0/E:U`

---

## Field-to-Metric Cheat Sheet

A starter map for common reporting questions. Specific report contracts live in [`docs/board_summary_calculations.md`](board_summary_calculations.md) and [`docs/management_summary_calculations.md`](management_summary_calculations.md).

| Question                             | Fields to use                                                                                                                       |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| **What's open right now?**           | `state in ('OPEN','REOPENED')`                                                                                                      |
| **Severity bucket** (project policy) | `plugin.vpr.score` → bucket via `SLA_DAYS` map; fall back to `severity` when `vpr.score` is null                                    |
| **Is it overdue?**                   | `today - first_found > SLA_DAYS[severity_bucket]` AND `state != 'FIXED'`                                                            |
| **Age of an open finding**           | `today - first_found`                                                                                                               |
| **MTTR per fix**                     | `time_taken_to_fix` (preferred); else `last_fixed - first_found`                                                                    |
| **Was it ever resurfaced?**          | `state == 'REOPENED'` OR `resurfaced_date` is not null                                                                              |
| **Exploitability flag**              | `plugin.exploit_available` OR any `plugin.exploit_framework_*` true OR `plugin.exploited_by_malware` OR `plugin.vpr_v2.on_cisa_kev` |
| **Risk-accepted?**                   | `severity_modification_type == 'ACCEPTED'` (cross-check `recast_rule_uuid`)                                                         |
| **Recasted severity?**               | `severity_modification_type == 'RECASTED'` OR `severity_id != severity_default_id`                                                  |
| **Authenticated coverage**           | `asset.last_authenticated_results` recency                                                                                          |
| **Patch available**                  | `plugin.has_patch` true / `plugin.vendor_unpatched` false                                                                           |
| **Workaround available**             | `plugin.has_workaround`                                                                                                             |
| **CVE rollups**                      | `plugin.cve` (array) — explode to one row per CVE                                                                                   |
| **Group by plugin**                  | `plugin.id`                                                                                                                         |
| **Group by asset**                   | `asset.uuid`                                                                                                                        |
| **Tag-scoped reports**               | Apply after fetch via `utils/tag_helper.enrich_vulns_with_tags()`                                                                   |

---

## Adding to This Document

When you introduce a new field, derived attribute, or interpretation rule:

1. Add the field with type, description, and (if applicable) a note about how the project uses it.
2. If it's a project-specific convention (not in the Tenable spec), cross-link to the runbook or code that defines it.
3. Keep the cheat sheet in sync — that's the section most AI assistants will key off when designing metrics.
