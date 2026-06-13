---
phase: 17-program-health-overview
verified: 2026-06-12T20:19:00-04:00
status: human_needed
score: 10/10 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Deliver a composed_report group that includes program_health to a real (or sandbox) SMTP endpoint and confirm the email body contains the 4-tile KPI row, sparkline images, and Owner velocity table"
    expected: "Email arrives with 4 labeled tiles (Open Critical / Net Velocity / SLA Posture (Crit+High) / MTTR (30-day)), MoM arrows, and an Owner velocity table. Cold-start groups show 'Trend Being Established' instead of NaN."
    why_human: "render_email_panel returns correct HTML in unit tests but full MIME encoding, CID attachment, and Outlook/Gmail rendering cannot be verified by grep or pytest alone."
  - test: "Run capture_trend_snapshot.py against a live or staging Tenable tenant and inspect the written snapshot JSON for the sla_rate_crit_high field"
    expected: "Snapshot file contains a numeric sla_rate_crit_high value (float 0–100) or null (when zero Crit+High open), not a missing key."
    why_human: "The fail-soft block and field round-trip are tested with synthetic data; a live tenant exercises the full open_findings_at + SLA_DAYS path against real VPR-derived severity strings."
  - test: "Generate a composed_report PDF with program_health included and visually inspect the sparkline row and Owner velocity table"
    expected: "Four colored sparklines (red/blue/green/orange) appear above the Owner velocity table. Outlier owners show the red '▲ Outlier' marker. Cold-start renders a notice instead of sparklines."
    why_human: "WeasyPrint layout of the display:table sparkline row and table column widths requires a real PDF render to verify — WeasyPrint flex bugs have previously passed on-paper geometry checks but failed in real renders (see project memory: feedback_layout_fixes.md)."
---

# Phase 17: Program Health Overview Verification Report

**Phase Goal:** The Program Health Overview module is live — a single-page composite MoM velocity dashboard that stitches New vs Remediated, MTTR trend, and SLA posture into one composite RAG with an Owner velocity table, cold-start-safe.
**Verified:** 2026-06-12T20:19:00-04:00
**Status:** human_needed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | S1 severity snapshot persists sla_rate_crit_high (forward-accumulating, OD-5/D-17-04) | VERIFIED | `data/trend_store.py` contains `sla_rate_crit_high: Optional[float] = None` parameter; `new_entry` dict persists it; `__main__` smoke prints "Backward-compat cold-start (sla_rate_crit_high): OK" |
| 2 | SLA posture computed reopened-aware (open_findings_at) over Crit+High using config.SLA_DAYS — never hardcoded (D-17-03) | VERIFIED | `scripts/capture_trend_snapshot.py` imports `open_findings_at` and `SLA_DAYS`; uses both at lines 393–408; grep confirms no hardcoded day counts |
| 3 | Old snapshots lacking sla_rate_crit_high read back as None, no KeyError (D-17-04/D-16-09, QUAL-01) | VERIFIED | `__main__` backward-compat assertion in `data/trend_store.py`; `test_sla_rate_backward_compat` passes; `test_sla_rate_params_default_to_none` passes |
| 4 | Only aggregate float persisted — no hostnames, IPs, plugin names, or asset-level fields (QUAL-05) | VERIFIED | Capture script stores only `round(float(within.sum()) / len(ch_df) * 100, 1)`; test_analyst_tabs_aggregate_only passes; forbidden column substrings assert clean |
| 5 | SLA-posture computation fail-soft — errors set field None, do not abort severity snapshot (QUAL-03) | VERIFIED | `try/except Exception` at lines 391–418 in capture script logs WARNING and sets `sla_rate_crit_high = None`; severity snapshot call at line 420 is outside the failing block |
| 6 | program_health is an auto-discovered four-channel module (@register_module, MODULE_ID program_health) — RPT-07 | VERIFIED | `registry.discover()` finds it; `registry.get('program_health').MODULE_ID == 'program_health'`; all 48 tests pass |
| 7 | OD-5 composite RAG correct with structural missing-signal Amber cap (D-17-05/D-17-06); cold-start yields Amber "Trend Being Established" rag_strip status="yellow" (D-17-08) | VERIFIED | `_composite_rag_od5(['green']*4) == ('green', False)`; `_composite_rag_od5(['green','green','green','missing']) == ('amber', True)`; cold-start live probe: rag_strip color=#f57c00, headline="Trend Being Established" |
| 8 | Four render channels implemented (PDF sparkline+owner table, email 4-tile+narrative, Excel 2 tabs, analyst aggregate-only) with safe_pct/safe_int/safe_format throughout — no #fbc02d (QUAL-03, QUAL-05) | VERIFIED | All five render methods confirmed present; all 14 render-side tests pass; `test_no_fbc02d_in_module_source` passes; `test_email_no_nan_percent` passes; analyst tab QUAL-05 assertion passes |
| 9 | program_health added to _MODULES_NEEDING_TREND_SNAPSHOTS, NOT _MODULES_NEEDING_FIXED_VULNS; no run_all.py slug entry (D-17-01) | VERIFIED | `'program_health' in _MODULES_NEEDING_TREND_SNAPSHOTS == True`; `'program_health' in _MODULES_NEEDING_FIXED_VULNS == False`; `grep program_health run_all.py` exits 1 (no match) |
| 10 | Owner velocity reopened-aware over Crit+High, >20% outlier flag, degrades gracefully on insufficient owner trend (D-17-09, QUAL-01) | VERIFIED | `test_owner_outlier_flagged_on_rise` passes; `test_owner_outlier_pct_option_respected` passes; `test_owner_outlier_flagging_no_trend` passes (graceful degrade) |

**Score: 10/10 truths verified**

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `data/trend_store.py` | capture_snapshot() sla_rate_crit_high param + new_entry + backward-compat smoke | VERIFIED | Contains `sla_rate_crit_high: Optional[float] = None`; persisted in new_entry; __main__ prints backward-compat OK |
| `scripts/capture_trend_snapshot.py` | fail-soft SLA aggregate block + sla_rate_crit_high= on severity call only | VERIFIED | AST-parseable; `sla_rate_crit_high=sla_rate_crit_high` appears exactly once; try/except fail-soft present |
| `tests/content/test_trend_store.py` | Round-trip + default-None + backward-compat tests for sla_rate_crit_high | VERIFIED | 3 tests collected, 3 pass; full 29-test suite green |
| `reports/modules/program_health_module.py` | ProgramHealthModule with @register_module, compute(), 4 render channels, helpers | VERIFIED | All methods confirmed present; 48 tests pass |
| `reports/composed_report.py` | program_health in _MODULES_NEEDING_TREND_SNAPSHOTS | VERIFIED | Confirmed in frozenset; not in _MODULES_NEEDING_FIXED_VULNS |
| `tests/test_program_health_module.py` | 8 compute + 8 render test names; 48 total | VERIFIED | 48 tests collected and pass; all required test names present |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `scripts/capture_trend_snapshot.py` | `data.trend_store.capture_snapshot` | `sla_rate_crit_high=sla_rate_crit_high` keyword arg on severity call | WIRED | Confirmed — exactly 1 occurrence, severity call only |
| `scripts/capture_trend_snapshot.py` | `utils.open_count.open_findings_at` + `config.SLA_DAYS` | reopened-aware open population + authoritative SLA targets | WIRED | Both imported and used in the SLA block at lines 393–408 |
| `reports/composed_report.py` | `ProgramHealthModule.compute` | `_MODULES_NEEDING_TREND_SNAPSHOTS` → `**composer_kwargs` fan-out | WIRED | `program_health` confirmed in frozenset; existing fan-out delivers `trend_snapshots` kwarg |
| `reports/modules/program_health_module.py` | `data.trend_store.read_trend` + `utils.open_count.open_findings_at` | owner-dimension snapshot read + reopened-aware SLA/Owner population | WIRED | Both imported and called within `compute()` at lines 248, 518, 590 |
| `reports/modules/program_health_module.py` | snapshot `sla_rate_crit_high` field (Plan 17-01) | `snap.get('sla_rate_crit_high')` signal re-derivation | WIRED | Lines 467–476; uses `.get()` (never `[]`) — T-17-06 |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `program_health_module.py` | `trend_snapshots` (Signal 1–4) | `_MODULES_NEEDING_TREND_SNAPSHOTS` gate → `read_trend()` in `composed_report.py` | Yes — reads live JSON snapshot store | FLOWING |
| `program_health_module.py` | `sla_rate_crit_high` (Signal 3) | `snap.get("sla_rate_crit_high")` from forward-accumulating S1 snapshot (Plan 17-01) | Yes — captured by `capture_trend_snapshot.py` with real vulns data | FLOWING |
| `program_health_module.py` | Owner velocity | `open_findings_at(vulns_df)` + `read_trend(dimension="owner")` inside `compute()` | Yes — live vulns_df + owner snapshot | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Module auto-discovers and registers | `registry.discover(); registry.get('program_health').MODULE_ID` | `program_health` | PASS |
| OD-5 composite all-green | `_composite_rag_od5(['green']*4)` | `('green', False)` | PASS |
| OD-5 missing-signal caps amber | `_composite_rag_od5(['green','green','green','missing'])` | `('amber', True)` | PASS |
| OD-5 1-green = red | `_composite_rag_od5(['green','red','red','red'])` | `('red', False)` | PASS |
| Cold-start rag_strip status | `compute(vulns_df, ..., trend_snapshots=None).rag_strip` | `{color: #f57c00, headline: "Trend Being Established"}` | PASS |
| trend_store backward-compat | `python data/trend_store.py` | prints "Backward-compat cold-start (sla_rate_crit_high): OK" | PASS |
| --dry-run no regression | `python run_all.py --dry-run` | "All 5 group(s) validated successfully" | PASS |
| Full test suite | `pytest tests/test_program_health_module.py -q -o addopts=""` | 48 passed | PASS |
| trend_store suite | `pytest tests/content/test_trend_store.py -q -o addopts=""` | 29 passed | PASS |

---

### Probe Execution

Step 7c: No `scripts/*/tests/probe-*.sh` files found for this phase. Phase is a module/library phase, not a standalone runnable. Skipped.

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| RPT-07 | 17-01, 17-02, 17-03 | Program Health Overview one-pager composing New-vs-Remediated velocity, MTTR, and SLA posture into composite RAG with Owner velocity table, cold-start-safe | SATISFIED | Module registered, all 10 truths verified, 48 tests pass, REQUIREMENTS.md traceability table marks "Complete" |

No orphaned requirements found. Only RPT-07 is mapped to Phase 17 in REQUIREMENTS.md. GEN-01, QUAL-04, DOC-02 are mapped to Phase 18 (Pending).

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `reports/modules/program_health_module.py` | 174 | `_signal_direction` guards `None` but not `float('nan')` | WARNING (WR-03 from REVIEW) | A JSON-serialized NaN could be misclassified as "red" instead of "missing"; uncommon path (JSON spec disallows bare NaN but Python's `json.dump` emits it) |
| `scripts/capture_trend_snapshot.py` + `program_health_module.py` (3 sites) | 396–408, 255–273, 519–536 | `sla_rate_crit_high` denominator includes `first_found=NaT` rows that can never enter the numerator | WARNING (WR-01 from REVIEW) | Downward bias in published SLA rate; all three sites replicate the same root cause; does NOT affect any must-have truth (the posture signal is directionally correct; bias is consistent across periods) |
| `reports/modules/program_health_module.py` | 625–632 | Previous-month owner counts use blocklist to exclude metadata keys; fragile against future snapshot field additions | WARNING (WR-05 from REVIEW) | An owner literally named a blocklist token would be dropped; a future int-typed snapshot field would be misread as an owner count |
| `reports/modules/program_health_module.py` | 559–566 | Net-velocity sparkline uses `, 0` defaults in `s.get(...)` — diverges from Signal 2's "None = missing" semantics | INFO (WR-04 from REVIEW) | Misleading to future readers; not a runtime defect given the `is not None` guard |

No `TBD`, `FIXME`, or `XXX` markers found in any Phase 17 modified files. No unresolved debt markers.

**Anti-pattern classification:** All four items from the code review are WARNING or INFO. None are blockers: WR-01/WR-02 are correctness edge cases that affect the SLA rate value but not goal-level behavior (module registers, renders, cold-starts safely); WR-03/WR-05 are robustness gaps in uncommon paths. No must-have truth fails because of these.

---

### Human Verification Required

#### 1. Email delivery rendering (Outlook / Gmail / Apple Mail)

**Test:** Configure a composed_report delivery group with `modules: [program_health]` and send to a test inbox. Inspect the received email.
**Expected:** Email body contains 4 labeled tiles (Open Critical / Net Velocity / SLA Posture (Crit+High) / MTTR (30-day)) with MoM arrows, an Owner velocity table, and — if fewer than 2 monthly snapshots exist — a "Trend Being Established" cold-start notice instead of NaN values.
**Why human:** Full MIME encoding, CID image attachment, and multi-client rendering cannot be verified by grep or pytest. Prior project memory (feedback_layout_fixes.md) documents WeasyPrint layout failures that only manifested in real renders.

#### 2. Live sla_rate_crit_high snapshot capture

**Test:** Run `python scripts/capture_trend_snapshot.py` against a live or staging Tenable tenant. Inspect the written snapshot JSON.
**Expected:** Snapshot contains `"sla_rate_crit_high": <float>` (or `null` when zero Crit+High open findings). No `KeyError`. The capture script log shows either the computed rate or the "SLA-posture aggregate failed" WARNING (fail-soft path).
**Why human:** Fail-soft block and field round-trip are proven with synthetic data; only a live tenant exercises the full `open_findings_at` + VPR-derived severity path and the actual rate value can be sanity-checked.

#### 3. PDF render visual inspection (sparkline row + Owner table)

**Test:** Run a composed_report batch with program_health included and open the output PDF.
**Expected:** Page contains 4 colored mini-sparklines in a row (red for Open-Critical, blue for Net Velocity, green for SLA, orange for MTTR), each annotated with current value and MoM arrow. Below the sparklines: an Owner velocity table with Owner / Open Crit+High / MoM Delta / Status columns. Outlier owners show the red "▲ Outlier" indicator. Cold-start pages show the notice text instead of sparklines.
**Why human:** WeasyPrint `display:table` layout of the sparkline row requires a real PDF render per project memory (feedback_layout_fixes.md). The sparkline base64 round-trip is test-proven but the WeasyPrint render of the `<img>` cells in a table layout is not.

---

### Gaps Summary

No gaps. All 10 must-have truths are VERIFIED. The three warnings (WR-01 NaT denominator bias, WR-03 NaN guard, WR-05 blocklist fragility) are correctness improvements identified by the code review but do not fail any must-have and do not prevent goal achievement. They are tracked in `17-REVIEW.md` for the next planning cycle.

---

_Verified: 2026-06-12T20:19:00-04:00_
_Verifier: Claude (gsd-verifier)_
