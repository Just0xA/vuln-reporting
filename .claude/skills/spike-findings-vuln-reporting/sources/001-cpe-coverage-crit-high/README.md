---
spike: 001
name: cpe-coverage-crit-high
type: standard
validates: "Given the real cached vulns export, when open VPR Critical+High findings are classified by CPE prefix (a/o/h), then a high enough share classifies cleanly (and correctly by team ownership) to drive an exec App/OS/Hardware metric without a plugin_family fallback."
verdict: PARTIAL
related: []
tags: [cpe, classification, vuln-type-distribution, vpr, plugin-family, exec-metric]
---

# Spike 001: CPE Coverage of VPR Critical+High Findings

## What This Validates

Given the most recent real cached vulns export (`data/cache/2026-06-02/vulns_all.parquet`, 160,453 findings), when open VPR Critical+High findings are bucketed into Application/OS/Hardware by CPE prefix, then is coverage high enough — **and team-ownership-accurate enough** — to drive the planned exec metric, or is a `plugin_family` fallback/override required?

Mirrors production severity via `config.vpr_to_severity` (VPR-first, native-severity fallback). All export rows are open (state ∈ {OPEN, REOPENED}).

## How to Run

```bash
python .planning/spikes/001-cpe-coverage-crit-high/measure.py   # headline coverage numbers
python .planning/spikes/001-cpe-coverage-crit-high/probe.py     # team-ownership depth probe
```

## What to Expect

`measure.py` prints coverage %, a/o/h split, residual size, residual plugin_family domination, and mixed-type frequency. `probe.py` breaks the Application bucket down by plugin_family and compares CPE-only vs family-first classification.

## Investigation Trail

1. **Headline (`measure.py`).** 61,120 Crit+High findings (38.1% of export). CPE prefix classifies **99.2%** cleanly; only **0.8% (491)** residual, all truly-empty CPE. Mechanical coverage is excellent.
2. **Surprise A — Hardware is empty.** Zero pure-`h` Crit+High findings; only 9 `{a,h}` mixed. The Data Center tile would read ~0. Either hardware/appliance scanning is out of scope for this instance, or hardware findings aren't CPE-tagged.
3. **Surprise B — 6.4% mixed `{a,o}` (3,903).** `a>o>h` precedence routes all of them to Application. Drilled in: 64.6% are "Windows : Microsoft Bulletins", 31.3% "Red Hat Local Security Checks" — i.e. **OS/platform patching work**, not app work. Precedence silently hands OS-team findings to the App tile.
4. **Hypothesis — does `cpe:/a` == App Support ownership?** Feared Linux distro package CVEs (cpe:/a:openssl…) would pollute Application. `probe.py` family breakdown of the 54,081 Application bucket: **74.6% "Windows", 5.9% "Windows : Microsoft Bulletins", 4.2% CGI abuses, 2.8% Databases, 2.3% Red Hat Local Security Checks.**
5. **Confirmation — sampled "Windows"-family plugin_names.** Adobe Reader (8,483), Office Macro Execution (6,982), Intel BHI spec-exec (3,559), Google Chrome (1,162+1,025), Windows Defender sigs, MSXML, Oracle Java (many), MS Edge. **These are genuine third-party applications** — correctly App Support / BU territory. "Windows" plugin_family is a *detection-platform* label, not an ownership label. CPE `/a` is semantically right here.
6. **Net.** CPE prefix is both high-coverage AND mostly correct on ownership, with **two precise exceptions** that need a `plugin_family` override:
   - **Linux distro "Local Security Checks" families** carry `cpe:/a:<package>` but are OS/Operations work (~1,229 inside Application + the mixed ones).
   - **`{a,o}` Microsoft Bulletins (2,522)** — genuinely ambiguous; an **org policy decision** (App Support vs Operations) that moves ~2,500 Crit+High findings between two tiles.

## Results

**VERDICT: PARTIAL ⚠** — CPE prefix is the right *backbone* (99.2% coverage, third-party apps classify correctly), but **pure CPE-only is rejected** for a team-ownership metric. A thin `plugin_family` override layer is required.

Distribution under the two rules (Crit+High, n=61,120):

| Bucket | CPE-only (a>o>h) | Family-first override |
| ------ | ---------------- | --------------------- |
| Application | 54,081 (88.5%) | 52,852 (86.5%) |
| OS | 6,548 (10.7%) | 7,777 (12.7%) |
| Hardware | 0 (0%) | 0 (0%) |
| Unclassified | 491 (0.8%) | 491 (0.8%) |

**Answers to the spike's 5 questions:**
1. **Clean CPE-prefix coverage:** 99.2% of Crit+High.
2. **a/o/h split:** ~88% Application, ~11% OS, ~0% Hardware.
3. **Residual:** 0.8% (491), 100% truly-empty CPE — negligible; a tiny "Unclassified" tile or a 3-family map absorbs it (residual families: General, Service detection, Windows).
4. **plugin_family fallback worth building?** YES — but not mainly for the empty residual. It's needed as an **override** for OS distro families that carry app CPEs, and to resolve the Microsoft-Bulletin ambiguity. A pure CPE-only + Unclassified rule would mis-assign ~6% of OS-team work to App Support.
5. **Mixed-type frequency:** 6.4% are `{a,o}`; `a>o>h` is **too naive** for them — for the OS-patch families among them, `o` should win. Recommend: family-aware precedence (OS "Local Security Checks"/"Bulletins" families → OS even when an app CPE is present).

### Signal for the build
- **Classifier = plugin_family override → CPE prefix → Unclassified**, not CPE alone. Build a small, auditable `OS_FAMILY` set (Linux distro "Local Security Checks", and a decision on MS Bulletins).
- **Surface a required human decision to the requestor:** do Microsoft patch-Tuesday bulletins belong to App Support or Operations? ~2,500 Crit+High findings hinge on it.
- **Confirm Hardware scan scope.** Today the Hardware/Data Center tile is ~0. Either confirm hardware/firmware scanning is out of scope (and consider a 2-tile App/OS design with Hardware shown only when non-zero), or investigate why hardware findings lack CPE.
- The classifier should be **unit-tested against a labelled sample** of these family/CPE combinations, not trusted blind — the 6% swing rides on it.
