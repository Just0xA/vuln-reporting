# Stack Research

**Domain:** Python vulnerability-reporting suite — v1.4 Management Summary Reporting Improvement
**Researched:** 2026-06-11
**Confidence:** HIGH (all claims grounded in direct codebase inspection: requirements.txt,
data/fetchers.py, data/trend_store.py, reports/modules/mttr_by_severity_module.py,
reports/modules/chart_utils.py, utils/open_count.py, and the founding analysis notes)

---

## Verdict: Zero New Dependencies

Every capability required by v1.4 is satisfied by the locked stack. `requirements.txt` is
unchanged. No new pip packages. No pyTenable upgrade.

---

## Locked Stack (do not modify)

| Technology | Pinned Version | Role in v1.4 |
|------------|---------------|--------------|
| `pyTenable` | 1.5.2 | `tio.exports.vulns()`, `tio.exports.assets()`, `tio.tags.list()` — all existing call sites; no new endpoints needed |
| `pandas` | 2.2.3 | All DataFrame compute in every new module; CoW-safe patterns already enforced (quick task `260611-b1x`) |
| `numpy` | 2.2.4 | Aggregations via pandas; no direct calls needed in new modules |
| `matplotlib` | 3.10.1 | MoM trend line charts, ▲▼% bar charts, velocity charts — all within existing `chart_utils.py` patterns |
| `plotly` + `kaleido` | 6.0.1 + 0.2.1 | Optional interactive variants; kaleido handles static PNG export for email CID embeds |
| `openpyxl` | 3.1.5 | Excel tab rendering in every module's `render_excel_tabs()` |
| `weasyprint` | 65.1 | PDF section rendering via `render_pdf_section()` → `ReportComposer.assemble_pdf()` |
| `Jinja2` | 3.1.6 | Email panel HTML in `render_email_panel()` |
| `fastparquet` | unpinned | Run-scoped parquet cache read/write — unchanged |
| `jsonschema` | 4.23.0 | delivery_config.schema.yaml validation — unchanged |
| `rich` | 14.0.0 | Progress bars in any new fetch helpers |
| `tenacity` | 9.1.2 | Retry policy on API calls — unchanged |
| `python-dotenv` | 1.1.0 | Credential loading — unchanged |
| `PyYAML` | 6.0.2 | YAML config parsing — unchanged |
| `APScheduler` | 3.11.0 | Scheduling daemon — unchanged |
| `tzdata` | 2025.2 | UTC datetime handling — unchanged |
| `pypdf` | ~6.0 | PDF smoke-test extraction — unchanged |
| `requests` | transitive via pyTenable | Already used directly in `fetch_recast_rules()` (fetchers.py:616) — unchanged |
| `ipaddress` | stdlib (Python 3.10+) | Public-IPv4 classification for External/DMZ scope — zero new install |

---

## Per-Question Analysis

### Q1 — External/public-IPv4 classification: stdlib `ipaddress`, no new dep

**Answer: YES, fully doable with the Python 3.10+ stdlib `ipaddress` module. No new package.**

The operator-remediation-priority-model note specifies exactly which ranges are non-external:

- RFC 1918 private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- CGNAT: `100.64.0.0/10`
- Loopback: `127.0.0.0/8`
- Link-local: `169.254.0.0/16`

`ipaddress.ip_address(ip).is_private` covers RFC 1918, loopback, and link-local in Python 3.10.
CGNAT (`100.64.0.0/10`) requires one explicit `ip_network` check because `is_private` does not
cover it in Python 3.10 (it was added to `is_private` only in Python 3.11). The classifier
belongs in a new `utils/external_scope.py` helper — one file, no install:

```python
import ipaddress

_CGNAT = ipaddress.ip_network("100.64.0.0/10")

def is_public_ipv4(ip_str: str) -> bool:
    """True if ip_str is a routable public IPv4 (not RFC1918/CGNAT/loopback/link-local)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr in _CGNAT)
```

The External/DMZ scope predicate is: `Location=External/DMZ tag OR is_public_ipv4(asset.ipv4)`.
Both signals are already present in `assets_all.parquet`:

- `tags` column: built by `fetch_all_assets()` as a `"Category=Value;..."` semicolon string
  (fetchers.py:565), directly usable with the existing `filter_by_tag()` pattern.
- `ipv4` column: first IPv4 from the asset export (fetchers.py:549).

No API change, no new data source, no new library. The mismatch/exception list
(public-IP-but-untagged, tagged-but-private) is a boolean cross-join on those two signals,
emitted as an analyst tab — the same pattern as `owner_supplemental.py`'s untagged-asset list.

**Integration point:** `utils/external_scope.py` (new file, stdlib only) → consumed by the
External/DMZ module's `compute()`. Vectorised via `pd.Series.apply(is_public_ipv4)` on
`assets_df["ipv4"]` after joining to `vulns_df` via `asset_uuid`.

---

### Q2 — Vulnerability Density asset-count denominator: `tio.exports.assets()`, no new dep

**Answer: Already fetched. `fetch_all_assets()` → `assets_all.parquet` is the denominator
source. No new data source, no new endpoint.**

`fetch_all_assets()` (fetchers.py:486) returns one row per licensed Tenable asset and is already
called in the standard run pipeline. The denominator for vulns/asset in a given month/scope is
`len(assets_df)` after applying the same tag filter used for the vuln numerator.

Critically, `data/trend_store.py` already stores this denominator. Design constraint D-04 in
`trend_store.py` reads: "Each snapshot entry records aggregate in-scope `asset_count` alongside
counts." `capture_snapshot()` receives `assets_df` as a parameter for exactly this reason. So:

- **Historical denominator (MoM trend):** read from `trend_store.read_trend()` → each snapshot
  entry's `asset_count` field. This is free — it accumulated alongside every prior snapshot
  capture since v1.3 shipped.
- **Current-month denominator:** `len(assets_df)` after tag-scoping, same as every other module
  that needs an asset count.

No new fetch, no new endpoint, no new column. `assets_all.parquet` is already warmed by the
first report in any `run_all.py` batch.

**Integration point:** `data/trend_store.read_trend()` → `snapshots[i]["asset_count"]` for
historical denominator. Current-run `assets_df` for the current-month denominator.

---

### Q3 — MoM infographics and velocity charts: matplotlib already sufficient, no new dep

**Answer: matplotlib 3.10.1 + plotly 6.0.1 + kaleido 0.2.1 cover every chart type needed.
No new charting library.**

The v1.4 chart requirements map cleanly to existing matplotlib primitives already used in the
codebase:

| Chart need | Primitive | Already used? |
|------------|-----------|--------------|
| MoM trend line (New vs Remediated, Program Health velocity) | `ax.plot()` / `ax.fill_between()` | Yes — `chart_utils.py` |
| ▲▼% month-delta bar with RAG colouring | `ax.bar()` with conditional colour map | Yes — existing module bar patterns |
| Velocity dual-axis (inflow vs outflow) | `ax.plot()` dual-axis (`twinx`) | Yes — trend_analysis pattern |
| MTTR trend by severity (one line per severity tier) | `ax.plot()` multi-series | Yes — `draw_gauge` + line patterns in `chart_utils.py` |
| Accepted/Recast ▲▼% infographic tile | `matplotlib.figure` with text annotation | Yes — KPI tile pattern in existing modules |
| Reopened count bar/trend | `ax.bar()` | Yes |

All charts render to base64 PNG via `io.BytesIO` + `fig.savefig()` for CID email embedding —
the established pattern in `reports/modules/chart_utils.py`. The `render_email_panel()` contract
returns HTML with `<img src="cid:{module_id}_chart">` and the module populates
`ModuleData.email_inline_images` with the base64 PNG entry.

**Integration point:** New modules call helpers in or add helpers to
`reports/modules/chart_utils.py`. The `draw_gauge` helper is already imported by
`mttr_by_severity_module.py` and reusable for the MTTR rework.

---

## Existing Substrates Each New Module Builds On

Every v1.4 module is a thin consumer. It calls existing infrastructure rather than building new
I/O or data paths.

| New Module | Data inputs | Existing substrates consumed | New code required |
|------------|-------------|------------------------------|-------------------|
| New vs Remediated | `vulns_df` (open+fixed), `trend_store` | `open_findings_at()` (utils/open_count.py), `trend_store.read_trend()`, `fetch_fixed_vulnerabilities()` | Module class + chart helper |
| Vulnerability Density | `vulns_df`, `assets_df`, `trend_store` | `trend_store.read_trend()` (`asset_count` field), `open_findings_at()` | Module class + density calc |
| Reopened Vulnerabilities | `vulns_df` (`state==REOPENED`, `resurfaced_date`) | `fetch_all_vulnerabilities()` — already includes `state` + `resurfaced_date` columns (fetchers.py:354,360) | Module class + bar/trend chart |
| Accepted & Recast | `recast_rules_df`, `vulns_df` | `fetch_recast_rules()` (fetchers.py:584), `extract_owner()` (utils/); join on `recast_rule_uuid` column (fetchers.py:357) | Module class + MoM delta logic |
| Program Health Overview | `vulns_df`, `trend_store` | `open_findings_at()`, `trend_store.read_trend()`, `extract_owner()` | Module class + velocity chart |
| MTTR rework | `fixed_vulns_df`, `vulns_df` | `fetch_fixed_vulnerabilities()`, `extract_owner()`, `trend_store` (for trend slice) | Replace or extend `mttr_by_severity_module.py`; full four-channel wiring |
| External/DMZ exposure | `vulns_df`, `assets_df` | `fetch_all_assets()` (`ipv4` + `tags` columns), new `utils/external_scope.py` (stdlib only) | `utils/external_scope.py` + module class |
| GEN-01: management_summary migration | All existing mgmt_summary data paths | All above modules + `ReportComposer` | Wiring + smoke baselines (same pattern as board_summary cutover) |

---

## What NOT to Add

| Do not add | Reason |
|------------|--------|
| Any pyTenable version > 1.5.2 | WAS is explicitly deferred this milestone; the SDK-version constraint is locked. `tio.exports.was()` is out of scope. |
| `fetch_was_findings()` or `was_findings.parquet` | WAS data source is deferred. The External report uses host-vuln data only (tag + public-IP filter on existing exports). |
| Any new charting library (bokeh, altair, seaborn, vega-altair) | matplotlib + plotly cover all v1.4 chart types. A third renderer adds maintenance surface with no benefit. |
| `geopandas` or any IP-geolocation library | Public-IP classification needs only RFC-range checks, not geolocation. The stdlib `ipaddress` module is exact and sufficient. |
| `scipy` or `statsmodels` | No statistical inference in v1.4. Sample-weighted MTTR mean is plain pandas arithmetic (`np.average` via pandas `groupby`). |
| `pyarrow` | `fastparquet` is the explicit, intentional engine choice (`engine="fastparquet"` at fetchers.py:219). pyarrow is excluded by design. |
| `pytest` or any test runner in `requirements.txt` | Tests are local-only by project decision (memory: `project_tests_local_only`). Test deps are never committed to requirements.txt. |
| `numba` or `cython` | No performance pass in v1.4 (PERF-01..04 explicitly deferred to backlog). |

---

## MTTR Rework — Implementation Note

The existing `mttr_by_severity_module.py` implements only the legacy `render_email_kpis()`
channel. The rework must add all four-channel methods:

- `render_pdf_section()` — currently absent
- `render_excel_tabs()` — currently absent
- `render_email_panel()` — currently absent (only legacy `render_email_kpis` present)
- `render_analyst_tabs()` — currently absent
- `render_rag_strip_entry()` — currently absent

Correctness changes (no new libraries, all inputs already in `fixed_vulns_df`):

1. **Disclose the ~30-day window.** Fixed findings are retained only ~29 days (Spike 002 /
   memory `project_tenable_fixed_retention_trend`). The PDF/email panel must state this.
2. **Sample-weighted mean.** Current code is unweighted mean-of-means across severity tiers.
   Replace with `sum(days_to_fix) / count(findings)` per tier — plain pandas `groupby`.
3. **Reopened-aware.** For REOPENED findings, `last_fixed - first_found` spans the full reopen
   cycle and overstates days-to-fix. Decision on treatment (exclude reopened / use
   `resurfaced_date` for interval) is deferred to plan-time per founding analysis open decisions;
   the `resurfaced_date` column is already present in `vulns_df` (fetchers.py:360).
4. **MoM trend.** Requires `trend_store.read_trend()` — already shipped in v1.3.
5. **Owner/BU cut.** Requires `extract_owner()` — already shipped in v1.3.

No new library. All inputs are already fetched and cached in the standard run pipeline.

---

## Accepted & Recast — Owner Join Note

`fetch_recast_rules()` returns a DataFrame of rules (not findings). To produce "Accepted &
Recast by Owner," join `recast_rules_df` to `vulns_df` on `recast_rule_uuid`
(present in `fetch_all_vulnerabilities()` output at fetchers.py:357), then apply
`extract_owner()` to the enriched vuln rows. The join is in-memory on already-cached parquet —
no extra API call.

For the MoM ▲▼% delta: the current-month rule count comes from `recast_rules_df`
(`fetch_recast_rules()` returns rules with `created_at` timestamps); the prior-month count
is read from `trend_store.read_trend()` snapshot entries (the trend snapshot captures recast
counts alongside open counts if the snapshot script is extended to include them, or the module
computes a point-in-time delta from `created_at` dates in the rules DataFrame itself).

---

## Python 3.10 `ipaddress` Compatibility Note

`ipaddress.IPv4Address.is_private` in Python 3.10 covers RFC 1918, loopback, and link-local.
It does NOT cover CGNAT `100.64.0.0/10` in 3.10 (that was added in 3.11 per the changelog).
The explicit `addr in _CGNAT` check in `utils/external_scope.py` is therefore required for
correctness on the project's Python 3.10 minimum. On 3.11+ the check is redundant but harmless.

**Confidence:** HIGH — verified against the Python 3.10 docs for `ipaddress.ip_address` and the
3.11 changelog entry that extended `is_private` to cover additional reserved ranges.

---

## Sources

All findings are HIGH confidence — grounded in direct codebase inspection, not training-data
assumptions.

- `requirements.txt` (project root) — all pinned versions confirmed
- `data/fetchers.py` lines 248–721 — `fetch_all_vulnerabilities`, `fetch_all_assets`,
  `fetch_recast_rules` signatures, column schemas, and cache paths confirmed
- `data/trend_store.py` docstring + design constraints D-01..D-08 — `asset_count` field
  confirmed present in snapshot entries
- `reports/modules/mttr_by_severity_module.py` lines 1–60 — legacy `render_email_kpis` channel
  confirmed; four-channel methods absent confirmed
- `reports/modules/chart_utils.py` (glob confirmed present) — existing chart helper surface
- `.planning/notes/operator-remediation-priority-model.md` — RFC range list for
  `is_public_ipv4` confirmed; CGNAT `100.64.0.0/10` explicitly listed
- `.planning/notes/report-requests-batch-2026-06.md` — WAS deferral decision, pyTenable
  upgrade constraint, `recast_rule_uuid` join path confirmed
- `.planning/notes/trend-reconstruction-engine.md` — Spike 002 outcome (snapshot not
  reconstruction), `asset_count` denominator pattern confirmed
- `.planning/PROJECT.md` — locked constraints, v1.3 shipped substrates (S1 + S2) confirmed
- Python 3.10 stdlib `ipaddress` docs — `is_private` coverage in 3.10 vs 3.11 confirmed

---

*Stack research for: v1.4 Management Summary Reporting Improvement*
*Researched: 2026-06-11*
