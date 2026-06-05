# Vuln Metric Substrate — Classification & Trend Foundations

Implementation blueprint for the shared foundations under the June-2026 report batch (VTD-01 + 7 reports). Two spikes proved what works and — more importantly — what silently doesn't. Follow this and you won't re-learn the landmines.

## Requirements (non-negotiable)

- **Severity is VPR-first.** Derive every severity via `config.vpr_to_severity(vpr_score, fallback=native_severity)` (Critical 9.0–10.0, High 7.0–8.9). Never read a raw severity string directly for tiering.
- **Vuln-type classifier = `plugin_family` override → CPE prefix → Unclassified**, config-driven map. Pure CPE-only is rejected.
- **Any "currently open" computation MUST use the reopened-aware two-interval predicate.** The naive single-interval form is a bug.
- **Trend = forward-accumulating snapshots, not backfilled reconstruction.** Reconstruction serves current-state + the last ~29 days only.
- **Classifier and predicate must be unit-tested** against labelled samples — both carry large silent-error surfaces (~6% App/OS swing; ~19% reopened drop).

## How to Build It

### 1. Vuln-type classification (App / OS / Hardware) — from Spike 001

CPE is already in `vulns_df` (`data/fetchers.py:343`, comma-joined string). Classify with a **family override first**, then CPE prefix:

```python
import re
# CPE part letter, both 2.2 (cpe:/a:...) and 2.3 (cpe:2.3:a:...)
_CPE_PART = re.compile(r"cpe:(?:2\.3:|/)([aoh])[:/]", re.IGNORECASE)
PART_TO_BUCKET = {"a": "Application", "o": "OS", "h": "Hardware"}

# Config-driven: families that are OS-team work despite carrying an app CPE.
OS_FAMILY = re.compile(r"local security checks|red hat|centos|oracle linux|ubuntu|"
                       r"debian|suse|amazon linux|rocky|alma|fedora", re.IGNORECASE)
# DECISION (requestor): Microsoft Bulletins default to OS/Operations — add to OS_FAMILY map.

def classify(plugin_family: str, cpe: str) -> str:
    if plugin_family and OS_FAMILY.search(plugin_family):
        return "OS"
    parts = {m.lower() for m in _CPE_PART.findall(cpe or "")}
    for p in ("a", "o", "h"):          # precedence a>o>h for mixed CPE
        if p in parts:
            return PART_TO_BUCKET[p]
    return "Unclassified"
```

Coverage on real data: **99.2%** of Crit+High classify; 0.8% Unclassified (negligible). Hide the Hardware tile when its count is 0.

### 2. Reopened-aware "open at date D" predicate — from Spike 002

```python
def open_at(df, D):
    """Two-interval model. REOPENED is fixed only during [last_fixed, resurfaced_date)."""
    born = df["first_found"] <= D
    st, lf, rs = df["state"], df["last_fixed"], df["resurfaced_date"]
    fixed = (
        ((st == "FIXED")     & lf.notna() & (lf <= D)) |
        ((st == "REOPENED")  & lf.notna() & (lf <= D) & rs.notna() & (D < rs)) |
        ((st == "REOPENED")  & lf.notna() & (lf <= D) & rs.isna())
    )
    return df[born & ~fixed]
```

Validates to **+2 of the actual current open count** (160,453). All REOPENED findings carry `resurfaced_date`, so the correction is always computable.

### 3. Trend — snapshot capture, not reconstruction

- Persist a **monthly snapshot** of per-dimension open counts (extend the existing `data/trend/` mechanism that `management_summary` uses).
- For the **first** snapshot only, you can backfill ~29 days of new/remediated deltas from the live `first_found` / `last_fixed` data.
- Everything older than ~29 days must come from accumulated snapshots. Design for cold start.

## What to Avoid

- **❌ Naive open predicate** `first_found<=D AND (last_fixed null OR last_fixed>D)` — drops every REOPENED finding (30,546 / 19% on real data) because their prior `last_fixed` is in the past. Looks correct, undercounts badly.
- **❌ Pure CPE-only classification** — Linux distro "Local Security Checks" carry `cpe:/a:<package>` but are OS-team work. Without the family override, ~6% of OS volume lands on the App tile. (Conversely, don't over-correct: "Windows" plugin_family is third-party apps — Adobe/Chrome/Java/Office — and `cpe:/a` is *correct* there. Override only on distro/bulletin families.)
- **❌ Reconstructing multi-month history from a current export** — survivorship undercount that grows with age (showed 4,203 "open" at 2024-12, a floor not reality). Don't promise backfilled trend lines.
- **❌ Inline f-string formatting of possibly-None metric values** — use `safe_pct`/`safe_int`/`safe_format` (CLAUDE.md empty-data guard).

## Constraints

- **Tenable retains fixed findings only ~29 days.** Platform-side (the fetcher already pulls `state=["fixed"]` with no `since`). Caps remediation/outflow data and net-open reconstruction at ~1 month. Confirm per-tenant whether retention is license-extendable before assuming wider.
- **Severity is as-of-today**, not as-of-date — reconstruction can't recover historical recast severity. Fine for type/count trends; not for historical SLA-breach trends.
- **Scope-at-time** — reconstruction uses current tag/asset membership, not historical.
- Stack: pandas (3.0-safe; prefer `.assign()` over chained `df[col]=` to avoid ChainedAssignment warnings + dtype surprises), `pyarrow`/`fastparquet` for cache.

## Origin

Synthesized from spikes: 001 (cpe-coverage-crit-high), 002 (trend-reconstruction-lookback).
Source files in: `sources/001-cpe-coverage-crit-high/`, `sources/002-trend-reconstruction-lookback/`.
Design records: `.planning/notes/vuln-type-distribution-module.md`, `.planning/notes/trend-reconstruction-engine.md`, `.planning/notes/report-requests-batch-2026-06.md`.
