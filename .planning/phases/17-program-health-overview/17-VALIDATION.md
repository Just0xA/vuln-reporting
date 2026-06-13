---
phase: 17
slug: program-health-overview
status: validated
nyquist_compliant: partial
wave_0_complete: true
created: 2026-06-12
---

# Phase 17 — Validation Strategy

> Per-phase validation contract. Reconstructed from artifacts (State B). Requirement: **RPT-07** (Program Health Overview four-channel module); must-haves are the D-17-xx / OD-5 / QUAL-xx decisions locked at plan time.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest |
| **Config file** | `pytest.ini` |
| **Quick run command** | `python -m pytest tests/test_program_health_module.py -q` |
| **Full suite command** | `python -m pytest tests/test_program_health_module.py tests/content/test_trend_store.py tests/test_composed_report_kwargs_gates.py -q` |
| **Estimated runtime** | ~2 seconds (phase-scoped) |

**Result at audit (2026-06-12):** `92 passed, 0 failed` across the three phase-relevant files (53 module + 35 trend_store + gate tests).

---

## Sampling Rate

- **After every task commit:** Run quick command (`test_program_health_module.py`)
- **After every plan wave:** Run full phase-scoped command (all three files)
- **Before `/gsd:verify-work`:** Full suite green — confirmed
- **Max feedback latency:** ~2 seconds

---

## Per-Requirement Verification Map

| Decision / Req | Plan | Wave | Behavior | Test(s) | Type | Status |
|----------------|------|------|----------|---------|------|--------|
| RPT-07 four-channel module (auto-discovered) | 02/03 | 2/3 | PDF/Excel/email/RAG channels all render | `test_all_channels_render_normal`, `test_all_channels_render_cold_start`, `test_all_channels_render_zero_row` | unit | ✅ green |
| D-17-01 added to `_MODULES_NEEDING_TREND_SNAPSHOTS` (not FIXED_VULNS) | 02 | 2 | frozenset membership gate | `test_composed_report_kwargs_gates.py` (frozenset assert, lines 100–108) | unit | ✅ green |
| D-17-02 definition parity (reads canonical snapshot fields) | 02 | 2 | net-velocity / MTTR derived from `new_findings_count`/`fixed_findings_count`/`mttr_overall_days` | composite tests build + consume canonical fields (`test_composite_*`) | unit (behavioral) | ✅ green |
| OD-5 / D-17-05 composite RAG (4/2-3/0-1 green) | 02 | 2 | Green/Amber/Red folding | `test_composite_all_green`, `test_composite_two_green_is_amber`, `test_composite_one_green_is_red`, `test_composite_rag_*` (12 total) | unit | ✅ green |
| D-17-06 missing signal caps Amber, named, structural | 02 | 2 | missing → Amber cap unbypassable | `test_composite_missing_caps_amber`, `test_missing_signal_named`, `test_missing_cap_is_structural_not_bypassable` | unit | ✅ green |
| D-17-07 per-signal MoM direction + flat bands | 02 | 2 | improved/flat/worsened coloring | `test_signal_direction_*` (11 tests incl. flat-band boundary) | unit | ✅ green |
| D-17-08 / QUAL-01 cold-start <2 snapshots → Amber, no NaN/crash | 02 | 2 | "Trend Being Established", current-value tiles | `test_cold_start_no_snapshots`, `test_cold_start_one_snapshot`, `test_cold_start_insufficient_data_false_but_one_snap` | unit | ✅ green |
| D-17-03 / QUAL-02 SLA posture reopened-aware (Crit+High, config.SLA_DAYS) | 01/02 | 1/2 | `open_findings_at` over Crit+High | `test_sla_rate_reopened_aware`, `test_reopened_finding_in_sla_denominator` | unit | ✅ green |
| D-17-09 owner velocity + >20% MoM-rise outlier | 02/03 | 2/3 | outlier flag + PDF marker | `test_owner_outlier_flagging_no_trend`, `test_owner_outlier_flagged_on_rise`, `test_owner_outlier_pct_option_respected`, `test_pdf_owner_outlier_marker`, `test_pdf_non_outlier_has_no_outlier_marker` | unit | ✅ green |
| OD-5 / D-17-04 `sla_rate_crit_high` persisted (forward-accumulating float) | 01 | 1 | round-trip + default None | `test_sla_rate_crit_high_roundtrip`, `test_sla_rate_params_default_to_none` | unit | ✅ green |
| D-17-04 / D-16-09 old snapshots read back None (cold-start, no migration) | 01 | 1 | backward-compat read | `test_sla_rate_backward_compat` | unit | ✅ green |
| QUAL-05 aggregate-only persistence + analyst tabs (no PII) | 01/03 | 1/3 | no asset_uuid/ip/hostname/plugin | `test_analyst_tabs_aggregate_only` (forbidden-substring + exact column set) | unit | ✅ green |
| D-17-09 PDF sparkline row | 03 | 3 | base64 sparklines, None-safe, figure-leak-safe | `test_sparkline_returns_base64`, `test_sparkline_handles_none_values`, `test_sparkline_closes_figure` | unit | ✅ green |
| D-17-06 email 4-tile KPI row + narrative names missing signal | 03 | 3 | tile labels + missing-signal note | `test_email_panel_contains_tile_labels`, `test_pdf_missing_signal_note` | unit | ✅ green |
| QUAL-03 render channels safe_pct/safe_int — no NaN% | 03 | 3 | no NaN% in email panel | `test_email_no_nan_percent` | unit | ✅ green |
| QUAL-03 module zero-row → `_empty_result()` (no raise) | 02 | 2 | empty-data guard | `test_empty_data_guard`, `test_empty_data_guard_with_snapshots` | unit | ✅ green |
| Amber color = `#f57c00`, no `#fbc02d` in source | 03 | 3 | RAG color contract | `test_amber_uses_yellow_color`, `test_no_fbc02d_in_module_source` | unit | ✅ green |
| `validate_config()` returns `list[str]` (UAT blocker ab00228) | 02 | 2 | contract — `.join()` never raises | `test_returns_list_not_moduleconfig`, `test_join_does_not_raise`, `test_valid_options_pass`, `test_bad_int_option_reports_error`, `test_bad_float_option_reports_error` | unit | ✅ green |
| **QUAL-03 capture-script SLA-posture fail-soft** | 01 | 1 | error → field None, snapshot proceeds | — none — | manual | ⚠️ manual-only |

*Status: ✅ green · ⚠️ manual-only · ❌ red*

---

## Wave 0 Requirements

Existing infrastructure (pytest + `tests/test_program_health_module.py`, `tests/content/test_trend_store.py`, `tests/test_composed_report_kwargs_gates.py`) covers all automatable phase requirements. No Wave 0 stubs required.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Capture-script SLA-posture fail-soft: a computation error in the SLA block sets `sla_rate_crit_high=None` and does not abort the severity snapshot | QUAL-03 / T-17-02 (Plan 01) | Block is inline in `main()` at `scripts/capture_trend_snapshot.py:391–418`, downstream of the live fetch pipeline (Tenable exports → vulns_df/assets_df). A unit test would have to mock the whole fetch/assets path plus `open_findings_at` to raise. The sibling MTTR fail-soft (T-16-03, identical inline structure) was left code-inspection-verified in Phase 16 — same precedent applied here. Verified CLOSED by the Phase 17 security audit (`17-SECURITY.md`, T-17-02) via code inspection. | Temporarily raise inside the `try` block (e.g. force `open_findings_at` to throw), run `python scripts/capture_trend_snapshot.py --month <YYYY-MM>`, confirm: (1) a `WARNING "SLA-posture aggregate failed — field will cold-start"` is logged, (2) the severity `capture_snapshot()` still writes with `sla_rate_crit_high: null`, (3) script exits 0. Revert the change. |

---

## Validation Sign-Off

- [x] All tasks have automated verify or are documented manual-only
- [x] Sampling continuity: no 3 consecutive requirements without automated verify
- [x] Wave 0 covers all MISSING references (none required)
- [x] No watch-mode flags
- [x] Feedback latency < 5s (~2s phase-scoped)
- [ ] `nyquist_compliant: true` — **partial** (1 manual-only, 16 automated areas)

**Approval:** validated (partial) 2026-06-12 — 16 requirement areas automated (92 passing tests), 1 manual-only (capture-script fail-soft, per Phase 16 precedent).

---

## Validation Audit 2026-06-12

| Metric | Count |
|--------|-------|
| Requirement areas | 17 |
| COVERED (automated) | 16 |
| MISSING → manual-only | 1 |
| Resolved by new tests | 0 |
| Phase-scoped tests passing | 92 |
