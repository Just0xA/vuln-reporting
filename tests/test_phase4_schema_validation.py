"""
tests/test_phase4_schema_validation.py — Phase 4 CONFIG-01/CONFIG-02 regression.

Locks in the jsonschema-backed validator behavior added in Plan 04-01:
  * Reconciled `reports` enum accepts board_summary + unscanned_assets.
  * `analyst_detail` is an optional boolean.
  * Misconfigured groups produce errors naming the group + field path.
  * format_checker=FORMAT_CHECKER catches malformed emails.
  * additionalProperties=false catches typo'd field names.

Run: python tests/test_phase4_schema_validation.py
Exit code: 0 = all checks passed, non-zero = failure.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from run_all import _load_schema, _validate_with_schema  # noqa: E402

FAILED: list[str] = []


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


def _base_group(**overrides) -> dict:
    g = {
        "name": "Test Pull",
        "schedule": {"frequency": "on_demand"},
        "reports": ["board_summary"],
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

    # A — current file on disk validates clean
    import yaml
    with open(Path(__file__).resolve().parent.parent / "delivery_config.yaml", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    errs = _validate_with_schema(raw, schema)
    _check("A_current_yaml_clean", errs == [], hint=str(errs))

    # B — frequency typo
    bad = {"groups": [_base_group(schedule={"frequency": "weeky"})]}
    errs = _validate_with_schema(bad, schema)
    _check(
        "B_frequency_typo_rejected",
        any("Test Pull" in e and "frequency" in e and "weeky" in e for e in errs),
        hint=str(errs),
    )

    # C — analyst_detail non-boolean
    bad = {"groups": [_base_group(analyst_detail="yes")]}
    errs = _validate_with_schema(bad, schema)
    _check(
        "C_analyst_detail_non_boolean_rejected",
        any("analyst_detail" in e and ("boolean" in e or "type" in e) for e in errs),
        hint=str(errs),
    )

    # D — unknown report slug
    bad = {"groups": [_base_group(reports=["nonsense_report"])]}
    errs = _validate_with_schema(bad, schema)
    _check(
        "D_unknown_report_slug_rejected",
        any("nonsense_report" in e for e in errs),
        hint=str(errs),
    )

    # E — malformed email (proves format_checker is active)
    bad_email = {
        "subject": "x",
        "recipients": ["not-an-email"],
    }
    bad = {"groups": [_base_group(email=bad_email)]}
    errs = _validate_with_schema(bad, schema)
    _check(
        "E_malformed_email_rejected",
        any("email" in e or "format" in e or "not-an-email" in e for e in errs),
        hint=str(errs),
    )

    # F — additionalProperties:false catches typo'd top-level group key
    g = _base_group()
    g["recipeints"] = ["x@y.co"]    # noqa: typo intentional
    bad = {"groups": [g]}
    errs = _validate_with_schema(bad, schema)
    _check(
        "F_additional_properties_rejected",
        any("recipeints" in e or "Additional properties" in e for e in errs),
        hint=str(errs),
    )

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
