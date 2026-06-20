"""Phase 6 plan 04 — run_group privacy_label + scope_subtitle threading.

Covers CHROME-INT-01 + CHROME-COMPAT-01.

These tests stub the dynamically-imported report module and the Tenable
client so they exercise ONLY the kwarg-routing path in run_group(). No
Tenable API calls, no parquet I/O, no PDF/Excel rendering.

The load-bearing assertions are tests 3 and 4 — they prove that legacy
slugs (management_summary, ops_remediation) never receive privacy_label
or scope_subtitle, which is the compat-safety contract for the Phase 6
chrome rollout (Plan 06-04, threat T-06-06).
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_all  # noqa: E402
from run_all import _CHROME_AWARE_SLUGS  # noqa: E402


def test_chrome_aware_slugs_includes_both_modular_consumers():
    """CHROME-COMPAT-01 — the allowlist is the single source of truth for
    which slugs may receive chrome kwargs. board_summary, composed_report,
    and management_summary (migrated in Phase 18 GEN-01) opt into the chrome
    design system; ops_remediation stays out so its run_report() signature
    remains untouched.

    Phase 18 Plan 04 co-edit (project_frozenset_gate_test_coupling):
    management_summary is added to _CHROME_AWARE_SLUGS in the same atomic
    commit that migrates run_report() onto ReportComposer and adds the chrome
    kwargs to its signature (Pitfall 3 / T-18-13). This test is updated in
    the same Plan 04 Task 1 commit so it does not block the GREEN run."""
    assert _CHROME_AWARE_SLUGS == frozenset({
        "board_summary",
        "composed_report",
        "management_summary",
    })


def _run_group_with_slug(slug: str, group_overrides: dict | None = None) -> dict:
    """Dispatch a synthetic group through run_group() and return the kwargs
    that the dynamically-imported report module's run_report() received."""
    captured: dict = {}

    def _spy_run_report(tio, run_id, **kwargs):
        captured.update(kwargs)
        return {"pdf": None, "excel": None, "charts": []}

    fake_module = MagicMock()
    fake_module.run_report = _spy_run_report

    group = {
        "name": "Phase6 Test Group",
        "schedule": {"frequency": "on_demand"},
        "reports": [slug],
        "filters": {},
        "email": {"subject": "s", "recipients": ["a@b.c"]},
    }
    if group_overrides:
        group.update(group_overrides)

    # Stub importlib so _import_report(slug) returns our spy module
    # regardless of slug. Also stub the pre-fetch helpers and email send
    # path so run_group() never touches Tenable or SMTP.
    with patch("run_all.importlib.import_module", return_value=fake_module), \
         patch("data.fetchers.fetch_all_assets", return_value=MagicMock()), \
         patch("data.fetchers.fetch_all_vulnerabilities", return_value=MagicMock()):
        run_all.run_group(
            group,
            tio=MagicMock(),
            run_id="t",
            no_email=True,
        )
    return captured


def test_board_summary_receives_privacy_label_and_scope_subtitle():
    """CHROME-INT-01 — chrome-aware slug gets BOTH new kwargs plus report_title."""
    kw = _run_group_with_slug("board_summary")
    assert "privacy_label" in kw
    assert "scope_subtitle" in kw
    # YAML-driven cover-title override flows through with the other
    # chrome kwargs; group without `report_title:` passes None and the
    # slug falls back to its built-in default.
    assert "report_title" in kw
    assert kw["report_title"] is None


def test_board_summary_report_title_override_forwarded():
    """YAML `report_title:` on a board_summary group propagates verbatim."""
    kw = _run_group_with_slug(
        "board_summary",
        group_overrides={"report_title": "Q2 Posture"},
    )
    assert kw["report_title"] == "Q2 Posture"


def test_composed_report_receives_chrome_kwargs():
    """CHROME-INT-01 — the YAML-driven module-composition slug is the
    other chrome-aware consumer. Adding new metric modules and dropping
    them into a `reports: [composed_report]` group must inherit the
    chrome design (header band, footer, cover layout) without any
    per-slug wiring."""
    kw = _run_group_with_slug(
        "composed_report",
        group_overrides={
            "modules": ["scan_coverage_sla"],
            "report_title": "Custom Composed Report",
        },
    )
    assert "privacy_label"  in kw
    assert "scope_subtitle" in kw
    assert kw["report_title"] == "Custom Composed Report"


def test_management_summary_receives_chrome_kwargs():
    """Phase 18 GEN-01 — management_summary is now chrome-aware.

    After the atomic cutover onto ReportComposer (Plan 04 Task 2), the
    run_report() signature accepts privacy_label / scope_subtitle /
    report_title and management_summary is added to _CHROME_AWARE_SLUGS.
    This test replaces the old CHROME-COMPAT-01 compat-safety guard which
    asserted the opposite (legacy renderer signature unchanged).

    The load-bearing assertion is now that management_summary DOES receive
    the chrome kwargs — mirroring the board_summary and composed_report
    tests above.
    """
    kw = _run_group_with_slug("management_summary")
    assert "privacy_label"  in kw
    assert "scope_subtitle" in kw
    assert "report_title"   in kw


def test_ops_remediation_does_not_receive_chrome_kwargs():
    """CHROME-COMPAT-01 — legacy renderer signature is unchanged."""
    kw = _run_group_with_slug("ops_remediation")
    assert "privacy_label"  not in kw
    assert "scope_subtitle" not in kw
    assert "report_title"   not in kw


def test_privacy_label_defaults_to_confidential():
    """CHROME-COMPAT-02 — groups without privacy_label still work; the
    default flows through as 'Confidential'."""
    kw = _run_group_with_slug("board_summary")
    assert kw["privacy_label"] == "Confidential"


def test_privacy_label_override_propagates():
    """Operator-supplied privacy_label reaches board_summary verbatim."""
    kw = _run_group_with_slug(
        "board_summary",
        group_overrides={"privacy_label": "Internal Only"},
    )
    assert kw["privacy_label"] == "Internal Only"
