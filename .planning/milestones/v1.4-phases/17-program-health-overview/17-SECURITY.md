---
phase: 17
slug: program-health-overview
status: verified
threats_open: 0
asvs_level: none
created: 2026-06-12
---

# Phase 17 — Security: Program Health Overview

> Per-phase security contract: threat register, accepted risks, and audit trail.

**Auditor:** gsd-security-auditor · **block_on:** high · **Threats closed:** 8 / 8 · **Threats open:** 0

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| live vulns_df → persisted snapshot JSON | Aggregate-only float crosses into a committed/persisted file | `sla_rate_crit_high` scalar (0–100) |
| operator module_options (YAML) → composite RAG thresholds | Untrusted numeric thresholds influence the headline status | int/float threshold keys |
| snapshot JSON → compute() | Optional fields may be absent (old snapshots) | nullable aggregate floats |
| owner/tag strings (Tenable tags) → HTML/PDF/Excel markup | Untrusted tag-derived strings cross into rendered output | owner tag display strings |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-17-01 | Information Disclosure | `sla_rate_crit_high` persisted in trend snapshot | mitigate | Aggregate float only; no host/IP/UUID/plugin fields in snapshot schema — `data/trend_store.py:382–401`; owner snapshot call excludes the field. | closed |
| T-17-02 | Tampering / DoS | SLA-posture compute aborting capture batch | mitigate | Bare `try/except Exception` sets field `None`; severity capture proceeds unconditionally — `scripts/capture_trend_snapshot.py:391–421`. | closed |
| T-17-03 | Tampering | tz-naive `snapshot_date` → wrong SLA math | mitigate | `pd.Timestamp(snapshot_date, tz="UTC")` and `pd.to_datetime(..., utc=True)` — both operands tz-aware — `scripts/capture_trend_snapshot.py:401–402`. | closed |
| T-17-04 | Tampering | `module_options` threshold injection | mitigate | `validate_config()` coerces 6 keys, returns `list[str]`; D-17-06 missing-signal Amber cap structural at `_composite_rag_od5:137–139`, unreachable via options — `program_health_module.py:1522–1547`. | closed |
| T-17-05 | Information Disclosure | analyst_rows / Excel tab PII leak | mitigate | `analyst_df` columns are owner name + aggregate Crit+High + MoM delta only; forbidden-substring test blocks asset_uuid/ip/hostname/plugin — `program_health_module.py:788–807`. | closed |
| T-17-06 | Denial of Service | KeyError on absent snapshot field | mitigate | All reads via `.get()`; `None → "missing" → Amber`; whole `compute()` `try/except → _empty_result` — `program_health_module.py:439,452–455,832`. | closed |
| T-17-07 | Tampering / XSS-equivalent | owner/tag strings into HTML/PDF markup | mitigate | `html.escape()` on every owner/tag string in `render_pdf_section` (973,1069,1099,1137) and `render_email_panel` (1225–1329); Excel/analyst tabs produce no markup. | closed |
| T-17-08 | Denial of Service | matplotlib figure leak across sparklines | mitigate | `plt.close(fig)` in `finally:` block, `BytesIO` scoped per call — `program_health_module.py:904–905`; `test_sparkline_closes_figure` asserts flat figure count. | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Threat Verification Evidence

| Threat ID | Evidence (file:line) |
|-----------|----------------------|
| T-17-01 | `data/trend_store.py:239–240,382–401` — `sla_rate_crit_high` declared `Optional[float]`, stored as a plain scalar in `new_entry`; no hostnames/IPs/UUIDs/plugin IDs in snapshot schema. Owner snapshot call (`capture_trend_snapshot.py:445–449`) does not receive `sla_rate_crit_high`. |
| T-17-02 | `scripts/capture_trend_snapshot.py:391–418` — SLA block wrapped in bare `try/except Exception`; on failure `sla_rate_crit_high = None` (line 418) and severity `capture_snapshot()` (line 421) proceeds unconditionally. |
| T-17-03 | `scripts/capture_trend_snapshot.py:401–402` — `snap_ts = pd.Timestamp(snapshot_date, tz="UTC")`; `ff_ts = pd.to_datetime(..., utc=True, errors="coerce")`. Both operands tz-aware before subtraction. |
| T-17-04 | `reports/modules/program_health_module.py:1522–1547` — `validate_config()` coerces all six threshold keys (3 int, 3 float); non-coercible values append to `errors` list (returns `list[str]`). D-17-06 missing-signal Amber cap structural in `_composite_rag_od5:137–139` (`if has_missing and raw == "green": return ("amber", True)`) — executes before threshold comparison, unreachable via `module_options`. Verified by `tests/test_program_health_module.py:343–364` (`test_missing_cap_is_structural_not_bypassable`). |
| T-17-05 | `reports/modules/program_health_module.py:788–807` — `analyst_df` columns: `Owner`, `Open Crit+High (curr)`, `Open Crit+High (prev)`, `MoM Delta`, `MoM Delta %`, `Outlier`. No `asset_uuid`/`ip`/`hostname`/`plugin` column; `owner_rows` built from aggregates only (645–668). Verified by `tests/test_program_health_module.py:939–976` (`test_analyst_tabs_aggregate_only`). |
| T-17-06 | `reports/modules/program_health_module.py:439,452–455,474,485` — all snapshot reads use `.get()`; `_signal_direction()` returns `"missing"` on `None` (174–175); whole `compute()` wrapped `try/except:832 → _empty_result()`. `data/trend_store.py:399` writes explicit null per entry. |
| T-17-07 | `render_pdf_section`: `html.escape()` on `summary_text` (973) + every owner string across three table branches (1069,1099,1137) + fallback label (1034). `render_email_panel`: `html.escape()` on DISPLAY_NAME (1225,1327), `driver_narrative` (1230,1321), four tile values (1287,1292,1297,1302), each missing signal (1312), `composite_label`/`green_count` (1329). `render_excel_tabs`/`render_analyst_tabs` produce no HTML markup. |
| T-17-08 | `reports/modules/program_health_module.py:882–905` — `plt.close(fig)` in `finally:` block (905); `BytesIO` scoped per call (900). Verified by `tests/test_program_health_module.py:1112–1135` (`test_sparkline_closes_figure`) — figure count unchanged after 3 calls. |

---

## Accepted Risks Log

No accepted risks. All eight threats are `mitigate` disposition with verified in-code controls.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-12 | 8 | 8 | 0 | gsd-security-auditor |

---

## Notes

- The D-17-06 missing-signal Amber cap bypass concern (T-17-04) is structurally correct: the cap in `_composite_rag_od5` fires on `has_missing` before the green-count threshold is applied, so even `green_count_min=1` with a missing signal cannot produce a Green composite.
- `validate_config` return type (`list[str]`) was the UAT blocker (ab00228); the regression test `test_returns_list_not_moduleconfig` covers this contract.
- `render_excel_tabs` writes owner strings as plain openpyxl cell values — no markup context, escape not required.
- T-17-05 analyst-row protection is enforced at both the compute boundary (aggregate-only columns in `analyst_df`) and the render boundary (forbidden-substring test on rendered DataFrame columns).
- Register authored at plan time (`register_authored_at_plan_time: true`) across all three PLAN files — audit verified mitigations rather than retroactive-STRIDE construction.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-12
