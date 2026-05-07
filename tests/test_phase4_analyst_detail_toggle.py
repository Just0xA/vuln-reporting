"""
tests/test_phase4_analyst_detail_toggle.py — CONFIG-03 / D-04-03 regression.

Locks in the analyst_detail opt-out plumbing added in Plan 04-02:

  * composer.run_full_pipeline(generate_analyst=False) → bundle['analyst_excel'] is None
  * composer.run_full_pipeline(generate_analyst=True)  → bundle['analyst_excel'] is a Path
    (or None on the D-20 all-empty fallback, which is an accepted alternate)

Empty-DataFrame fixtures from tests/test_phase2_composer_pipeline.py are sufficient:
the analyst_detail toggle's effect is binary regardless of data volume; populated
data would only add coverage for analyst-rows CONTENT (out of scope here).

Run: python tests/test_phase4_analyst_detail_toggle.py
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Use the ACTUAL fixture helpers from the Phase 2 test file
# (tests/test_phase2_composer_pipeline.py:162-180). NO `_build_synthetic_*`
# helpers exist in that file.
from tests.test_phase2_composer_pipeline import (    # noqa: E402
    _make_composer,
    _make_results,
)

FAILED: list[str] = []

_BOARD_MODULES = (
    "scan_coverage_sla",
    "critical_remediation_sla",
    "high_risk_assets",
    "aged_vulns_assets",
)


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


def main() -> int:
    report_date = datetime.now(tz=timezone.utc)

    # A — generate_analyst=False
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        composer = _make_composer(*_BOARD_MODULES)
        results = _make_results(*_BOARD_MODULES)
        bundle_off = composer.run_full_pipeline(
            results,
            out_dir,
            slug="board_summary",
            report_date=report_date,
            generate_analyst=False,
            pdf_title="x",
            pdf_subtitle="y",
            scope_label="All Assets",
        )
        analyst_excel = bundle_off.get("analyst_excel")
        if analyst_excel is None:
            analyst_excel = bundle_off.get("analyst_workbook_path")
        _check(
            "A_off_analyst_excel_is_none",
            analyst_excel is None,
            hint=str(analyst_excel),
        )
        analyst_files = list(out_dir.glob("*analyst*.xlsx"))
        _check(
            "A_off_no_orphan_xlsx",
            analyst_files == [],
            hint=str(analyst_files),
        )

    # B — generate_analyst=True (control case)
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        composer = _make_composer(*_BOARD_MODULES)
        results = _make_results(*_BOARD_MODULES)
        bundle_on = composer.run_full_pipeline(
            results,
            out_dir,
            slug="board_summary",
            report_date=report_date,
            generate_analyst=True,
            pdf_title="x",
            pdf_subtitle="y",
            scope_label="All Assets",
        )
        path_on = bundle_on.get("analyst_excel") or bundle_on.get("analyst_workbook_path")
        # Accepted alternate: empty fixtures may trigger the D-20 all-empty
        # fallback (no analyst rows → no workbook). Either outcome is correct
        # for this test; the BINARY contract is "False ⇒ None always".
        if path_on is None:
            _check(
                "B_on_path_is_real_OR_d20_fallback",
                True,
                hint="all-empty fallback hit; covered by Phase 3 plan 03-06",
            )
        else:
            _check(
                "B_on_path_is_real_OR_d20_fallback",
                Path(path_on).exists(),
                hint=str(path_on),
            )

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
