"""
scripts/capture_management_summary_parity_golden.py
— One-shot synthetic fixture builder + bespoke-path golden emitter.

PURPOSE
-------
Builds a FROZEN deterministic synthetic dataset and runs the CURRENT
BESPOKE ``compute_all_metrics`` path against it to emit a BUCKETED golden
JSON classifying each of the seven metrics into one of two parity buckets:

    exact_match         — semantics preserved across the migration; Plan 04
                          must assert zero drift (EXACT for int counts or
                          TOLERANCE+abs_delta for float ratios)

    documented_difference — semantics intentionally changed; EXCLUDED from
                            the exact assert; the golden records the bespoke
                            value + a written difference_rationale + any
                            shared_invariant Plan 04 can still assert (or
                            the literal "none")

BUCKET ASSIGNMENTS (derived from 18-RESEARCH.md Seven Module Definitions +
module docstrings — NOT assumed):

    M1 total_vulns_by_severity     → exact_match
        Module: total_vulns_by_severity_module.py
        Semantics identical: per-severity open counts.
        Comparison policy: EXACT (integer counts).

    M2 scan_coverage_sla           → exact_match
        Module: scan_coverage_sla_module.py
        Semantics identical: % of licensed assets scanned in last 30 days.
        Comparison policy: TOLERANCE abs_delta <= 1e-6 (float ratio).

    M3 mttr_trend (rolling-30 current-window MTTR value) → exact_match
        Module: mttr_trend_module.py  (D-18-06 preserves rolling-30)
        Semantics preserved for the CURRENT-WINDOW value; MoM trend line
        is an additive enrichment, not a semantic change.
        Comparison policy: TOLERANCE abs_delta <= 0.5 (float, days).
        Note: bespoke uses time_taken_to_fix preference + last_fixed−first_found
        fallback; module uses last_fixed−COALESCE(resurfaced_date,first_found)
        (D-16-02). The REOPENED row will produce a different per-finding
        days_to_fix; tolerance accommodates this intentional clock change.

    M4 patch_compliance_rate       → exact_match
        Module: patch_compliance_rate_module.py
        Semantics identical: % of open findings still within SLA window.
        Comparison policy: TOLERANCE abs_delta <= 1e-6 (float ratio).

    M5 aged_vulns_assets           → documented_difference
        Bespoke: age-bucket HISTOGRAM OF VULNS (six buckets, count+%).
        Module: aged_vulns_assets_module.py → % of ON-TIME-SCANNED ASSETS
                with >= 1 Med/High/Crit finding open > 90 days.
        Different unit (assets ≠ vulns) AND different denominator.
        Shared invariant: none (relies on module's own tests + visual UAT).

    M6 accepted_recast             → exact_match
        Module: accepted_recast_module.py
        Semantics preserved: current-period ACCEPTED/RECASTED finding counts
        and exception rate. MoM delta is trend-sourced and excluded from the
        frozen-fixture exact assert (trend_snapshots carry two prior months
        but the delta itself is NOT part of this exact bucket).
        Comparison policy: EXACT (integer counts), TOLERANCE abs_delta <= 1e-6
        for exception_rate (float).

    M7 new_vs_remediated           → documented_difference
        Bespoke: simple MoM delta of TOTAL OPEN findings
                 (curr.critical+high+medium+low − prev.same).
        Module: new_vs_remediated_module.py → richer inflow (net-new +
                resurfaced) / outflow (snapshot fixed_findings_count) trend
                with net-delta.  Outflow is SNAPSHOT-SOURCED, not derivable
                from the frozen fixed_vulns_df fixture directly.
        Different metric entirely.
        Shared invariant: none (relies on module's own tests + visual UAT).

D-04-05 RECONCILIATION (review-approved):
    D-04-05 ("structure locked, values NOT") governs LIVE-DRIFTING values.
    This golden is locked against a FROZEN SYNTHETIC INPUT — deterministic
    and reproducible.  It is a standard regression check, NOT a live-value
    lock.  No conflict with D-04-05.

PER-METRIC GATE (NOT blanket zero-drift):
    Plan 04 ONLY asserts the five EXACT-MATCH metrics (M1/M2/M3/M4/M6).
    M5 and M7 are EXCLUDED from the exact assert; they carry a recorded
    bespoke reference value + difference_rationale for auditor context.

QUAL-05 / D-04-08:
    Fixture uses ONLY RFC-5737 addresses (198.51.100.x, 203.0.113.x) and
    RFC-6761 hostnames (.invalid / .example.*). No real hostnames, IPs,
    plugin names, or asset UUIDs in any committed artifact.

RETIRED — SUPERSEDED BY THE MODULAR PIPELINE (Phase 18 Plan 04 cutover):
    This was a ONE-TIME capture script.  The bespoke ``compute_all_metrics``
    path it ran against was ATOMICALLY REMOVED at the Plan 04 cutover (proven
    by ``test_bespoke_functions_removed`` in tests/test_management_summary.py),
    so ``--emit-golden`` can no longer regenerate the golden.

    The golden it produced — ``tests/baselines/management_summary_value_golden.json``
    — is now FROZEN and is consumed by ``test_value_golden_parity``.  Do not
    attempt to regenerate it; the modular pipeline is the source of truth and
    the frozen golden locks parity against the captured bespoke values.

    ``--emit-golden`` is intentionally guarded to exit with a clear message
    rather than crashing with an ImportError on the deleted bespoke import.
    ``--rebuild-fixture`` (synthetic fixture parquets) still works.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fixture / golden paths
# ---------------------------------------------------------------------------

FIXTURE_DIR  = REPO_ROOT / "tests" / "fixtures" / "management_summary_parity"
GOLDEN_PATH  = REPO_ROOT / "tests" / "baselines" / "management_summary_value_golden.json"

VULNS_PARQUET  = FIXTURE_DIR / "vulns_df.parquet"
ASSETS_PARQUET = FIXTURE_DIR / "assets_df.parquet"
FIXED_PARQUET  = FIXTURE_DIR / "fixed_vulns_df.parquet"
TREND_JSON     = FIXTURE_DIR / "trend_snapshots.json"

# Deterministic reference date — fixed, not datetime.now(), so the golden
# values do not drift across runs (QUAL-02 / D-04-05 reconciliation).
_REPORT_DATE = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

# Deterministic random seed
_SEED = 12345


# ---------------------------------------------------------------------------
# Synthetic fixture builders
# ---------------------------------------------------------------------------

def _build_vulns_df() -> pd.DataFrame:
    """Build a deterministic synthetic open-vulnerabilities DataFrame.

    QUAL-05: all IPs are RFC-5737 (198.51.100.x / 203.0.113.x); all
    hostnames are RFC-6761 (.invalid / .example.*).

    Covers all branches exercised by M1..M6:
    - 4 severities, both open + reopened states
    - ACCEPTED + RECASTED modification types (for M6)
    - aged findings (>90 days open) across Med/High/Crit (for M5 bucket)
    - at least one REOPENED finding with resurfaced_date set (QUAL-02)
    """
    import random
    rng = random.Random(_SEED)

    rows: list[dict] = []

    # --- Fixed sets for determinism ---
    severities   = ["critical", "high", "medium", "low"]
    vpr_map      = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}

    # Group A: 10 critical — all open, within SLA (<15 days)
    for i in range(10):
        ip  = f"198.51.100.{i}"
        host = f"host-{i:03d}.invalid"
        rows.append({
            "asset_uuid":                 f"uuid-crit-{i:03d}",
            "hostname":                   host,
            "ipv4":                       ip,
            "fqdn":                       host,
            "plugin_id":                  10000 + i,
            "plugin_name":                f"Critical Plugin {i}",
            "plugin_family":              "General",
            "vpr_score":                  vpr_map["critical"],
            "severity":                   "critical",
            "severity_native":            "critical",
            "severity_modification_type": "NONE",
            "recast_rule_uuid":           None,
            "state":                      "open",
            "first_found":                _REPORT_DATE - timedelta(days=10),
            "last_seen":                  _REPORT_DATE - timedelta(days=1),
            "last_fixed":                 None,
            "resurfaced_date":            None,
            "cve_list":                   "CVE-2024-0001",
            "cvss_base_score":            9.8,
            "exploit_available":          True,
        })

    # Group B: 10 critical — open, OVERDUE (>15 days)
    for i in range(10):
        ip  = f"198.51.100.{20 + i}"
        host = f"host-{20+i:03d}.invalid"
        rows.append({
            "asset_uuid":                 f"uuid-crit-od-{i:03d}",
            "hostname":                   host,
            "ipv4":                       ip,
            "fqdn":                       host,
            "plugin_id":                  10100 + i,
            "plugin_name":                f"Critical OD Plugin {i}",
            "plugin_family":              "General",
            "vpr_score":                  vpr_map["critical"],
            "severity":                   "critical",
            "severity_native":            "critical",
            "severity_modification_type": "NONE",
            "recast_rule_uuid":           None,
            "state":                      "open",
            "first_found":                _REPORT_DATE - timedelta(days=20),
            "last_seen":                  _REPORT_DATE - timedelta(days=1),
            "last_fixed":                 None,
            "resurfaced_date":            None,
            "cve_list":                   "CVE-2024-0002",
            "cvss_base_score":            9.0,
            "exploit_available":          False,
        })

    # Group C: 15 high — open, OVERDUE (>30 days)
    for i in range(15):
        ip  = f"198.51.100.{40 + i}"
        host = f"host-h{i:03d}.example.invalid"
        rows.append({
            "asset_uuid":                 f"uuid-high-{i:03d}",
            "hostname":                   host,
            "ipv4":                       ip,
            "fqdn":                       host,
            "plugin_id":                  10200 + i,
            "plugin_name":                f"High Plugin {i}",
            "plugin_family":              "Windows",
            "vpr_score":                  vpr_map["high"],
            "severity":                   "high",
            "severity_native":            "high",
            "severity_modification_type": "NONE",
            "recast_rule_uuid":           None,
            "state":                      "open",
            "first_found":                _REPORT_DATE - timedelta(days=35),
            "last_seen":                  _REPORT_DATE - timedelta(days=1),
            "last_fixed":                 None,
            "resurfaced_date":            None,
            "cve_list":                   "CVE-2024-0003",
            "cvss_base_score":            7.5,
            "exploit_available":          False,
        })

    # Group D: 20 medium — within SLA (<60 days), ACCEPTED (for M6)
    for i in range(20):
        ip  = f"203.0.113.{i}"
        host = f"host-m{i:03d}.example.invalid"
        mod_type = "ACCEPTED" if i % 4 == 0 else "NONE"
        rows.append({
            "asset_uuid":                 f"uuid-med-{i:03d}",
            "hostname":                   host,
            "ipv4":                       ip,
            "fqdn":                       host,
            "plugin_id":                  10300 + i,
            "plugin_name":                f"Medium Plugin {i}",
            "plugin_family":              "CGI",
            "vpr_score":                  vpr_map["medium"],
            "severity":                   "medium",
            "severity_native":            "medium",
            "severity_modification_type": mod_type,
            "recast_rule_uuid":           None,
            "state":                      "open",
            "first_found":                _REPORT_DATE - timedelta(days=30),
            "last_seen":                  _REPORT_DATE - timedelta(days=1),
            "last_fixed":                 None,
            "resurfaced_date":            None,
            "cve_list":                   "CVE-2024-0004",
            "cvss_base_score":            5.5,
            "exploit_available":          False,
        })

    # Group E: 5 medium — OVERDUE (>60 days), RECASTED (for M6)
    for i in range(5):
        ip  = f"203.0.113.{30 + i}"
        host = f"host-mr{i:03d}.example.invalid"
        rows.append({
            "asset_uuid":                 f"uuid-med-rc-{i:03d}",
            "hostname":                   host,
            "ipv4":                       ip,
            "fqdn":                       host,
            "plugin_id":                  10400 + i,
            "plugin_name":                f"Medium Recast {i}",
            "plugin_family":              "CGI",
            "vpr_score":                  vpr_map["medium"],
            "severity":                   "medium",
            "severity_native":            "medium",
            "severity_modification_type": "RECASTED",
            "recast_rule_uuid":           f"rule-{i:03d}",
            "state":                      "open",
            "first_found":                _REPORT_DATE - timedelta(days=70),
            "last_seen":                  _REPORT_DATE - timedelta(days=1),
            "last_fixed":                 None,
            "resurfaced_date":            None,
            "cve_list":                   "CVE-2024-0005",
            "cvss_base_score":            5.0,
            "exploit_available":          False,
        })

    # Group F: 10 low — within SLA (<120 days)
    for i in range(10):
        ip  = f"203.0.113.{50 + i}"
        host = f"host-l{i:03d}.example.invalid"
        rows.append({
            "asset_uuid":                 f"uuid-low-{i:03d}",
            "hostname":                   host,
            "ipv4":                       ip,
            "fqdn":                       host,
            "plugin_id":                  10500 + i,
            "plugin_name":                f"Low Plugin {i}",
            "plugin_family":              "Settings",
            "vpr_score":                  vpr_map["low"],
            "severity":                   "low",
            "severity_native":            "low",
            "severity_modification_type": "NONE",
            "recast_rule_uuid":           None,
            "state":                      "open",
            "first_found":                _REPORT_DATE - timedelta(days=60),
            "last_seen":                  _REPORT_DATE - timedelta(days=1),
            "last_fixed":                 None,
            "resurfaced_date":            None,
            "cve_list":                   None,
            "cvss_base_score":            2.0,
            "exploit_available":          False,
        })

    # Group G: 1 REOPENED critical finding with resurfaced_date (QUAL-02)
    # first_found ~200d ago, resurfaced ~10d ago, last_fixed ~2d ago (NOT yet fixed)
    rows.append({
        "asset_uuid":                 "uuid-reopened-001",
        "hostname":                   "host-reopened.invalid",
        "ipv4":                       "198.51.100.200",
        "fqdn":                       "host-reopened.invalid",
        "plugin_id":                  19999,
        "plugin_name":                "Reopened Critical Plugin",
        "plugin_family":              "General",
        "vpr_score":                  vpr_map["critical"],
        "severity":                   "critical",
        "severity_native":            "critical",
        "severity_modification_type": "NONE",
        "recast_rule_uuid":           None,
        "state":                      "reopened",
        "first_found":                _REPORT_DATE - timedelta(days=200),
        "last_seen":                  _REPORT_DATE - timedelta(days=1),
        "last_fixed":                 _REPORT_DATE - timedelta(days=15),  # previously fixed
        "resurfaced_date":            _REPORT_DATE - timedelta(days=10),
        "cve_list":                   "CVE-2024-0099",
        "cvss_base_score":            9.5,
        "exploit_available":          True,
    })

    df = pd.DataFrame(rows)

    # Ensure correct dtypes
    for col in ("first_found", "last_seen", "last_fixed", "resurfaced_date"):
        df = df.assign(**{col: pd.to_datetime(df[col], utc=True, errors="coerce")})

    return df


def _build_assets_df() -> pd.DataFrame:
    """Build a deterministic synthetic assets DataFrame.

    Contains 30 licensed assets, all on-time-scanned (within 30 days).
    A known subset (10) host the aged Med/High/Crit vulns (Group C/E) —
    for M5's asset-denominator context.

    QUAL-05: RFC-5737/6761 addresses only.
    """
    rows: list[dict] = []
    scan_date = _REPORT_DATE - timedelta(days=15)

    for i in range(30):
        ip   = f"198.51.100.{i}" if i < 15 else f"203.0.113.{i - 15}"
        host = f"asset-{i:03d}.invalid"
        rows.append({
            "asset_uuid":              f"asset-uuid-{i:03d}",
            "hostname":                host,
            "ipv4":                    ip,
            "fqdn":                    host,
            "operating_system":        "Linux",
            "network_name":            "Default",
            "last_seen":               _REPORT_DATE - timedelta(days=1),
            "last_licensed_scan_date": scan_date,
            "tags":                    "Environment=Production",
            "tags_str":                "Environment: Production",
            "source_name":             "NESSUS_SCAN",
        })

    df = pd.DataFrame(rows)
    for col in ("last_seen", "last_licensed_scan_date"):
        df = df.assign(**{col: pd.to_datetime(df[col], utc=True, errors="coerce")})
    return df


def _build_fixed_vulns_df() -> pd.DataFrame:
    """Build a deterministic synthetic fixed-vulnerabilities DataFrame.

    Covers the inputs for M3 (MTTR) — fixed findings with both within-SLA
    and outside-SLA remediation times, spanning all four severity tiers.

    Also includes the REOPENED-pattern finding: first_found ~200d ago,
    resurfaced ~10d ago, last_fixed ~2d ago — days_to_fix per D-16-02 clock
    is (last_fixed - resurfaced_date) = 8 days.

    QUAL-05: RFC-5737/6761 addresses only.
    """
    rows: list[dict] = []
    vpr_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}

    # 5 critical fixed within SLA (<=15 days)
    for i in range(5):
        fixed_at = _REPORT_DATE - timedelta(days=i)
        found_at = fixed_at - timedelta(days=10)
        rows.append({
            "asset_uuid":      f"fix-uuid-crit-{i:03d}",
            "hostname":        f"fix-host-c{i:03d}.invalid",
            "ipv4":            f"198.51.100.{100 + i}",
            "fqdn":            f"fix-host-c{i:03d}.invalid",
            "plugin_id":       20000 + i,
            "plugin_name":     f"Fixed Critical {i}",
            "plugin_family":   "General",
            "vpr_score":       vpr_map["critical"],
            "severity":        "critical",
            "severity_native": "critical",
            "state":           "fixed",
            "first_found":     found_at,
            "last_fixed":      fixed_at,
            "resurfaced_date": None,
            "time_taken_to_fix": int((fixed_at - found_at).total_seconds()),
            "cve_list":        "CVE-2024-1001",
            "cvss_base_score": 9.0,
        })

    # 5 critical fixed OVERDUE (>15 days)
    for i in range(5):
        found_at = _REPORT_DATE - timedelta(days=40 + i)
        fixed_at = _REPORT_DATE - timedelta(days=i)
        rows.append({
            "asset_uuid":      f"fix-uuid-crit-od-{i:03d}",
            "hostname":        f"fix-host-cod{i:03d}.invalid",
            "ipv4":            f"198.51.100.{110 + i}",
            "fqdn":            f"fix-host-cod{i:03d}.invalid",
            "plugin_id":       20100 + i,
            "plugin_name":     f"Fixed Critical OD {i}",
            "plugin_family":   "General",
            "vpr_score":       vpr_map["critical"],
            "severity":        "critical",
            "severity_native": "critical",
            "state":           "fixed",
            "first_found":     found_at,
            "last_fixed":      fixed_at,
            "resurfaced_date": None,
            "time_taken_to_fix": int((fixed_at - found_at).total_seconds()),
            "cve_list":        "CVE-2024-1002",
            "cvss_base_score": 9.0,
        })

    # 8 high fixed — varied MTTR
    for i in range(8):
        found_at = _REPORT_DATE - timedelta(days=20 + i * 3)
        fixed_at = _REPORT_DATE - timedelta(days=i)
        rows.append({
            "asset_uuid":      f"fix-uuid-high-{i:03d}",
            "hostname":        f"fix-host-h{i:03d}.invalid",
            "ipv4":            f"203.0.113.{100 + i}",
            "fqdn":            f"fix-host-h{i:03d}.invalid",
            "plugin_id":       20200 + i,
            "plugin_name":     f"Fixed High {i}",
            "plugin_family":   "Windows",
            "vpr_score":       vpr_map["high"],
            "severity":        "high",
            "severity_native": "high",
            "state":           "fixed",
            "first_found":     found_at,
            "last_fixed":      fixed_at,
            "resurfaced_date": None,
            "time_taken_to_fix": int((fixed_at - found_at).total_seconds()),
            "cve_list":        "CVE-2024-1003",
            "cvss_base_score": 7.5,
        })

    # 6 medium fixed
    for i in range(6):
        found_at = _REPORT_DATE - timedelta(days=50 + i)
        fixed_at = _REPORT_DATE - timedelta(days=i)
        rows.append({
            "asset_uuid":      f"fix-uuid-med-{i:03d}",
            "hostname":        f"fix-host-m{i:03d}.example.invalid",
            "ipv4":            f"203.0.113.{110 + i}",
            "fqdn":            f"fix-host-m{i:03d}.example.invalid",
            "plugin_id":       20300 + i,
            "plugin_name":     f"Fixed Medium {i}",
            "plugin_family":   "CGI",
            "vpr_score":       vpr_map["medium"],
            "severity":        "medium",
            "severity_native": "medium",
            "state":           "fixed",
            "first_found":     found_at,
            "last_fixed":      fixed_at,
            "resurfaced_date": None,
            "time_taken_to_fix": int((fixed_at - found_at).total_seconds()),
            "cve_list":        "CVE-2024-1004",
            "cvss_base_score": 5.5,
        })

    # 4 low fixed
    for i in range(4):
        found_at = _REPORT_DATE - timedelta(days=80 + i)
        fixed_at = _REPORT_DATE - timedelta(days=i)
        rows.append({
            "asset_uuid":      f"fix-uuid-low-{i:03d}",
            "hostname":        f"fix-host-l{i:03d}.example.invalid",
            "ipv4":            f"203.0.113.{120 + i}",
            "fqdn":            f"fix-host-l{i:03d}.example.invalid",
            "plugin_id":       20400 + i,
            "plugin_name":     f"Fixed Low {i}",
            "plugin_family":   "Settings",
            "vpr_score":       vpr_map["low"],
            "severity":        "low",
            "severity_native": "low",
            "state":           "fixed",
            "first_found":     found_at,
            "last_fixed":      fixed_at,
            "resurfaced_date": None,
            "time_taken_to_fix": int((fixed_at - found_at).total_seconds()),
            "cve_list":        None,
            "cvss_base_score": 2.0,
        })

    # REOPENED finding: first_found ~200d ago, resurfaced ~10d ago, last_fixed ~2d ago
    # D-16-02 clock: days_to_fix = (last_fixed - resurfaced_date) = 8 days
    rows.append({
        "asset_uuid":      "fix-uuid-reopened-001",
        "hostname":        "fix-reopened.invalid",
        "ipv4":            "198.51.100.200",
        "fqdn":            "fix-reopened.invalid",
        "plugin_id":       29999,
        "plugin_name":     "Fixed Reopened Critical",
        "plugin_family":   "General",
        "vpr_score":       9.5,
        "severity":        "critical",
        "severity_native": "critical",
        "state":           "fixed",
        "first_found":     _REPORT_DATE - timedelta(days=200),
        "last_fixed":      _REPORT_DATE - timedelta(days=2),
        "resurfaced_date": _REPORT_DATE - timedelta(days=10),
        "time_taken_to_fix": int(timedelta(days=8).total_seconds()),  # 8 days
        "cve_list":        "CVE-2024-0099",
        "cvss_base_score": 9.5,
    })

    df = pd.DataFrame(rows)
    for col in ("first_found", "last_fixed", "resurfaced_date"):
        df = df.assign(**{col: pd.to_datetime(df[col], utc=True, errors="coerce")})
    return df


def _build_trend_snapshots_json() -> dict:
    """Build a deterministic synthetic trend_snapshots fixture.

    Returns the JSON structure that ``_compute_metric_7`` (bespoke) and the
    modular trend readers expect:
        {"snapshots": [...], "insufficient_data": bool}

    Contains 3 prior months so MoM-dependent values (M7 bespoke delta,
    M6 accepted_recast MoM delta, mttr_trend MoM) compute deterministically.

    Each snapshot entry matches the bespoke ``_save_trend_snapshot`` shape:
        month, tag_filter, critical, high, medium, low, generated_at
    """
    tag_filter = "all_assets"
    snapshots = [
        {
            "month":          "2026-03",
            "tag_filter":     tag_filter,
            "critical":       15,
            "high":           22,
            "medium":         30,
            "low":            12,
            "generated_at":   "2026-03-01T10:00:00Z",
            # Additional fields used by trend_store-based modules
            "fixed_findings_count": 18,
            "accepted_count":       3,
            "recast_count":         2,
            "asset_count":          30,
            "mttr_critical":        12.0,
            "mttr_high":            25.0,
            "mttr_medium":          45.0,
            "mttr_low":             80.0,
        },
        {
            "month":          "2026-04",
            "tag_filter":     tag_filter,
            "critical":       13,
            "high":           20,
            "medium":         28,
            "low":            11,
            "generated_at":   "2026-04-01T10:00:00Z",
            "fixed_findings_count": 20,
            "accepted_count":       4,
            "recast_count":         2,
            "asset_count":          30,
            "mttr_critical":        11.0,
            "mttr_high":            22.0,
            "mttr_medium":          42.0,
            "mttr_low":             75.0,
        },
        {
            "month":          "2026-05",
            "tag_filter":     tag_filter,
            "critical":       12,
            "high":           18,
            "medium":         26,
            "low":            10,
            "generated_at":   "2026-05-01T10:00:00Z",
            "fixed_findings_count": 22,
            "accepted_count":       5,
            "recast_count":         3,
            "asset_count":          30,
            "mttr_critical":        10.5,
            "mttr_high":            21.0,
            "mttr_medium":          40.0,
            "mttr_low":             72.0,
        },
    ]
    return {"snapshots": snapshots, "insufficient_data": False}


# ---------------------------------------------------------------------------
# Fixture I/O
# ---------------------------------------------------------------------------

def rebuild_fixture() -> None:
    """Write the deterministic synthetic fixture set to disk.

    Overwrites existing fixtures — deterministic, so re-running produces
    value-identical parquets.
    """
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    vulns_df  = _build_vulns_df()
    assets_df = _build_assets_df()
    fixed_df  = _build_fixed_vulns_df()
    trend_d   = _build_trend_snapshots_json()

    vulns_df.to_parquet(VULNS_PARQUET,  index=False)
    assets_df.to_parquet(ASSETS_PARQUET, index=False)
    fixed_df.to_parquet(FIXED_PARQUET,  index=False)

    TREND_JSON.write_text(
        json.dumps(trend_d, indent=2), encoding="utf-8"
    )

    logger.info("Fixture set written to %s", FIXTURE_DIR)
    print(f"[capture] Fixture set written: {FIXTURE_DIR}")


def load_fixture() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """Read the committed fixture parquets + trend_snapshots.json."""
    for p in (VULNS_PARQUET, ASSETS_PARQUET, FIXED_PARQUET, TREND_JSON):
        if not p.exists():
            raise FileNotFoundError(
                f"Fixture missing: {p}\n"
                f"Run with --rebuild-fixture to generate the fixture set first."
            )
    vulns_df  = pd.read_parquet(VULNS_PARQUET)
    assets_df = pd.read_parquet(ASSETS_PARQUET)
    fixed_df  = pd.read_parquet(FIXED_PARQUET)
    trend_d   = json.loads(TREND_JSON.read_text(encoding="utf-8"))
    return vulns_df, assets_df, fixed_df, trend_d


# ---------------------------------------------------------------------------
# Bespoke compute path runner
# ---------------------------------------------------------------------------

def _run_bespoke_compute(
    vulns_df:     pd.DataFrame,
    assets_df:    pd.DataFrame,
    fixed_df:     pd.DataFrame,
    trend_d:      dict,
) -> dict:
    """Run the BESPOKE ``compute_all_metrics`` path against the fixture.

    Constructs an in-memory trend file that ``_compute_metric_7`` reads
    via ``_load_trend_history`` (the bespoke path reads from a Path, not
    a dict — we write a temp file to satisfy it).

    Returns the raw metrics dict with keys metric_1 .. metric_7.
    """
    import tempfile
    import os
    from reports.management_summary import compute_all_metrics  # noqa: PLC0415

    # Write the trend_snapshots fixture to a temp JSON file so the bespoke
    # _compute_metric_7 can load it via _load_trend_history(trend_file).
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(trend_d, tf)
        temp_trend_path = Path(tf.name)

    try:
        metrics = compute_all_metrics(
            vulns_df         = vulns_df,
            assets_df        = assets_df,
            fixed_vulns_df   = fixed_df,
            trend_file       = temp_trend_path,
            tag_filter_label = "all_assets",
            report_date      = _REPORT_DATE,
        )
    finally:
        try:
            os.unlink(temp_trend_path)
        except OSError:
            pass

    return metrics


# ---------------------------------------------------------------------------
# Golden builder
# ---------------------------------------------------------------------------

def _serialize_value(v: Any) -> Any:
    """Convert pandas/numpy types to JSON-serialisable Python types."""
    if v is None:
        return None
    if isinstance(v, float):
        return round(float(v), 6)
    if isinstance(v, (int,)):
        return int(v)
    if isinstance(v, dict):
        return {k: _serialize_value(vv) for k, vv in v.items()}
    if isinstance(v, list):
        return [_serialize_value(x) for x in v]
    return v


def build_bucketed_golden(metrics: dict) -> dict:
    """Construct the bucketed golden from the bespoke metrics dict.

    Returns a golden JSON structure with per-metric bucket classification,
    bespoke values, and (for EXACT-MATCH) comparison policy, or (for
    DOCUMENTED-DIFFERENCE) difference_rationale + shared_invariant.
    """
    m1 = metrics["metric_1"]
    m2 = metrics["metric_2"]
    m3 = metrics["metric_3"]
    m4 = metrics["metric_4"]
    m5 = metrics["metric_5"]
    m6 = metrics["metric_6"]
    m7 = metrics["metric_7"]

    golden: dict = {
        "_meta": {
            "description": (
                "Bucketed bespoke-path golden values for the frozen synthetic fixture. "
                "D-04-05 reconciliation: this is a FROZEN-SYNTHETIC-INPUT parity lock, "
                "NOT a live-value lock. D-04-05 governs live-drifting values; this is a "
                "deterministic regression check. The gate is PER-METRIC (NOT blanket "
                "zero-drift) — only EXACT-MATCH metrics are asserted by Plan 04. "
                "Bucket assignments derived from 18-RESEARCH.md Seven Module Definitions "
                "+ module docstrings (NOT assumed)."
            ),
            "fixture_dir": str(FIXTURE_DIR),
            "report_date": _REPORT_DATE.isoformat(),
            "captured_by": "bespoke compute_all_metrics path",
        },
        "metrics": {
            "M1_total_vulns_by_severity": {
                "metric_id":         "total_vulns_by_severity",
                "bucket":            "exact_match",
                "bucket_source":     "18-RESEARCH.md + total_vulns_by_severity_module.py docstring: semantics identical (per-severity open counts)",
                "bespoke_values": {
                    "critical": _serialize_value(m1.get("critical")),
                    "high":     _serialize_value(m1.get("high")),
                    "medium":   _serialize_value(m1.get("medium")),
                    "low":      _serialize_value(m1.get("low")),
                    "total":    _serialize_value(m1.get("total")),
                },
                "comparison_policy": "EXACT",
                "comparison_note":   "Integer counts must match exactly; open+reopened states.",
            },
            "M2_scan_coverage_sla": {
                "metric_id":         "scan_coverage_sla",
                "bucket":            "exact_match",
                "bucket_source":     "18-RESEARCH.md + scan_coverage_sla_module.py: semantics identical (% licensed assets scanned in last 30d)",
                "bespoke_values": {
                    "coverage_pct":   _serialize_value(m2.get("coverage_pct")),
                    "scanned":        _serialize_value(m2.get("scanned")),
                    "not_scanned":    _serialize_value(m2.get("not_scanned")),
                    "total_licensed": _serialize_value(m2.get("total_licensed")),
                },
                "comparison_policy": "TOLERANCE",
                "tolerance":         1e-6,
                "tolerance_note":    "Float ratio; abs(actual - bespoke) <= 1e-6 for coverage_pct.",
            },
            "M3_mttr_trend": {
                "metric_id":         "mttr_trend",
                "bucket":            "exact_match",
                "bucket_source":     "18-RESEARCH.md + mttr_trend_module.py: D-18-06 preserves rolling-30 window; current-window value semantics preserved",
                "bespoke_values": {
                    "mttr":        _serialize_value(m3.get("mttr")),
                    "total_fixed": _serialize_value(m3.get("total_fixed")),
                },
                "comparison_policy": "TOLERANCE",
                "tolerance":         0.5,
                "tolerance_note": (
                    "Float, days. abs(actual - bespoke) <= 0.5 per severity. "
                    "Note: bespoke uses time_taken_to_fix preference + date-diff fallback; "
                    "module uses D-16-02 clock (last_fixed - COALESCE(resurfaced_date, first_found)). "
                    "The REOPENED row will differ; tolerance accommodates this intentional clock change."
                ),
            },
            "M4_patch_compliance_rate": {
                "metric_id":         "patch_compliance_rate",
                "bucket":            "exact_match",
                "bucket_source":     "18-RESEARCH.md + patch_compliance_rate_module.py: semantics identical (% open findings within SLA)",
                "bespoke_values": {
                    "overall_rate": _serialize_value(m4.get("overall_rate")),
                    "within_sla":   _serialize_value(m4.get("within_sla")),
                    "total_open":   _serialize_value(m4.get("total_open")),
                },
                "comparison_policy": "TOLERANCE",
                "tolerance":         1e-6,
                "tolerance_note":    "Float ratio; abs(actual - bespoke) <= 1e-6 for overall_rate.",
            },
            "M5_aged_vulns_assets": {
                "metric_id":          "aged_vulns_assets",
                "bucket":             "documented_difference",
                "bucket_source":      "18-RESEARCH.md + aged_vulns_assets_module.py docstring: bespoke is age-bucket histogram of vulns; module is % of on-time-scanned ASSETS with a >90d Med/High/Crit finding — different unit+denominator",
                "bespoke_values": {
                    "age_buckets": _serialize_value(m5),
                },
                "difference_rationale": (
                    "M5 bespoke: age-bucket histogram of OPEN VULNS (six buckets: 0-30, "
                    "31-60, 61-90, 91-180, 181-365, 365+ days; count + pct of total open). "
                    "M5 module (aged_vulns_assets): % of ON-TIME-SCANNED ASSETS with >= 1 "
                    "Medium/High/Critical finding open > 90 days. "
                    "Different unit (vulns vs assets), different denominator (total open vulns "
                    "vs on-time-scanned licensed assets), different threshold (age bucket boundaries "
                    "vs single 90-day cutoff). Exact parity is impossible and meaningless."
                ),
                "shared_invariant":     "none",
                "shared_invariant_note": "No common quantity Plan 04 can assert. Relies on the module's own tests + visual UAT.",
            },
            "M6_accepted_recast": {
                "metric_id":         "accepted_recast",
                "bucket":            "exact_match",
                "bucket_source":     "18-RESEARCH.md + accepted_recast_module.py: current-period ACCEPTED/RECASTED counts and exception rate semantics preserved",
                "bespoke_values": {
                    "open_exceptions": _serialize_value(m6.get("open_exceptions")),
                    "total_open":      _serialize_value(m6.get("total_open")),
                    "exception_rate":  _serialize_value(m6.get("exception_rate")),
                },
                "comparison_policy": "MIXED",
                "comparison_note": (
                    "open_exceptions, total_open: EXACT (integer counts). "
                    "exception_rate: TOLERANCE abs_delta <= 1e-6 (float, %). "
                    "MoM delta is trend-sourced and NOT part of this frozen-fixture exact assert."
                ),
            },
            "M7_new_vs_remediated": {
                "metric_id":          "new_vs_remediated",
                "bucket":             "documented_difference",
                "bucket_source":      "18-RESEARCH.md + new_vs_remediated_module.py docstring: bespoke is simple MoM total-open delta; module is richer inflow/outflow trend with snapshot-sourced outflow",
                "bespoke_values": {
                    "snapshots":           _serialize_value(m7.get("snapshots")),
                    "delta_critical_high": _serialize_value(m7.get("delta_critical_high")),
                    "delta_medium_low":    _serialize_value(m7.get("delta_medium_low")),
                    "has_trend":           _serialize_value(m7.get("has_trend")),
                    "first_run_notice":    _serialize_value(m7.get("first_run_notice")),
                },
                "difference_rationale": (
                    "M7 bespoke: simple MoM delta of TOTAL OPEN findings "
                    "(curr.critical+high - prev.critical+high, curr.medium+low - prev.medium+low). "
                    "M7 module (new_vs_remediated): richer inflow (net-new via first_found + "
                    "resurfaced via resurfaced_date) / outflow (snapshot fixed_findings_count) "
                    "trend with net-delta per month. Outflow is SNAPSHOT-SOURCED, not derivable "
                    "from fixed_vulns_df directly. Different metric entirely."
                ),
                "shared_invariant":     "none",
                "shared_invariant_note": "No common quantity Plan 04 can assert. Relies on the module's own tests + visual UAT.",
            },
        },
    }
    return golden


def emit_golden(metrics: dict) -> None:
    """Write the bucketed golden JSON to disk."""
    golden = build_bucketed_golden(metrics)
    GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_text(
        json.dumps(golden, indent=2, sort_keys=False), encoding="utf-8"
    )
    logger.info("Bucketed golden written to %s", GOLDEN_PATH)
    print(f"[capture] Golden written: {GOLDEN_PATH}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--rebuild-fixture", action="store_true",
        help="Rebuild the synthetic fixture parquets + trend_snapshots.json.",
    )
    parser.add_argument(
        "--emit-golden", action="store_true",
        help="Run the bespoke compute path against the fixture and emit the golden JSON.",
    )
    args = parser.parse_args()

    if not args.rebuild_fixture and not args.emit_golden:
        parser.print_help()
        return 1

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    if args.rebuild_fixture:
        rebuild_fixture()

    if args.emit_golden:
        # The bespoke compute_all_metrics path was atomically removed at the
        # Phase 18 Plan 04 cutover, so this one-time capture is RETIRED. Guard
        # here so the operator gets a clear message instead of an ImportError.
        import reports.management_summary as _ms  # noqa: PLC0415
        if not hasattr(_ms, "compute_all_metrics"):
            print(
                "[capture] RETIRED: the bespoke compute_all_metrics path was "
                "removed at the Phase 18 Plan 04 cutover. This one-time golden "
                "capture script is retired; the golden "
                "(tests/baselines/management_summary_value_golden.json) is frozen "
                "and the modular pipeline is now the source of truth. Nothing to emit."
            )
            return 1

        print("[capture] Loading fixture set ...")
        vulns_df, assets_df, fixed_df, trend_d = load_fixture()
        print(f"[capture] vulns_df: {len(vulns_df)} rows, assets_df: {len(assets_df)} rows, "
              f"fixed_df: {len(fixed_df)} rows, trend snapshots: {len(trend_d.get('snapshots', []))}")
        print("[capture] Running bespoke compute_all_metrics ...")
        metrics = _run_bespoke_compute(vulns_df, assets_df, fixed_df, trend_d)
        emit_golden(metrics)
        print("[capture] Done.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
