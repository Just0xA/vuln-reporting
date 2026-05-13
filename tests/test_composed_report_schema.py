"""
tests/test_composed_report_schema.py — composed_report schema + registry tests.

Covers the 5 dry-run validation behaviors introduced by the
composed_report slug:

  A — valid: reports=[composed_report], modules=[scan_coverage_sla]
      passes schema and registry validation (zero errors).
  B — invalid: modules=[] is rejected at schema level (empty array).
  C — invalid: modules key omitted is rejected at schema level
      (modules required when composed_report in reports).
  D — invalid at runtime: modules=[nonexistent_xyz] passes schema but
      _validate_group returns an error naming the bad ID.
  E — regression: a group without composed_report in reports is
      unaffected by the new rules.

Run: python tests/test_composed_report_schema.py
Exit code: 0 = all checks passed, non-zero = failure.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from run_all import _load_schema, _validate_group, _validate_with_schema  # noqa: E402

FAILED: list[str] = []


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


def _base_group(**overrides) -> dict:
    g = {
        "name": "Composed Test",
        "schedule": {"frequency": "on_demand"},
        "reports": ["composed_report"],
        "modules": ["scan_coverage_sla"],
        "filters": {},
        "email": {
            "subject": "x",
            "recipients": ["a@b.co"],
            "reply_to": "a@b.co",
        },
    }
    g.update(overrides)
    return g


def main() -> int:
    schema = _load_schema()

    # A — valid composed_report with one registered module
    g = _base_group()
    errs_schema  = _validate_with_schema({"groups": [g]}, schema)
    errs_runtime = _validate_group(g, _schema=schema)
    _check(
        "A_valid_composed_report_passes",
        errs_schema == [] and errs_runtime == [],
        hint=f"schema={errs_schema}, runtime={errs_runtime}",
    )

    # B — modules: [] rejected at schema level
    g = _base_group(modules=[])
    errs = _validate_with_schema({"groups": [g]}, schema)
    _check(
        "B_empty_modules_rejected",
        any("modules" in e for e in errs),
        hint=str(errs),
    )

    # C — modules key omitted rejected at schema level
    g = _base_group()
    del g["modules"]
    errs = _validate_with_schema({"groups": [g]}, schema)
    _check(
        "C_missing_modules_rejected",
        any("modules" in e for e in errs),
        hint=str(errs),
    )

    # D — unknown module ID: schema passes, _validate_group rejects
    g = _base_group(modules=["nonexistent_xyz"])
    errs_schema  = _validate_with_schema({"groups": [g]}, schema)
    errs_runtime = _validate_group(g, _schema=schema)
    _check(
        "D_unknown_module_id_schema_passes",
        errs_schema == [],
        hint=str(errs_schema),
    )
    _check(
        "D_unknown_module_id_runtime_rejects",
        any("nonexistent_xyz" in e for e in errs_runtime),
        hint=str(errs_runtime),
    )

    # E — regression: board_summary group without composed_report
    # remains unaffected by the new rules (no modules key, no errors).
    g = {
        "name": "Regression Board",
        "schedule": {"frequency": "on_demand"},
        "reports": ["board_summary"],
        "filters": {},
        "email": {
            "subject": "x",
            "recipients": ["a@b.co"],
            "reply_to": "a@b.co",
        },
    }
    errs_schema  = _validate_with_schema({"groups": [g]}, schema)
    errs_runtime = _validate_group(g, _schema=schema)
    _check(
        "E_board_summary_unaffected",
        errs_schema == [] and errs_runtime == [],
        hint=f"schema={errs_schema}, runtime={errs_runtime}",
    )

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
