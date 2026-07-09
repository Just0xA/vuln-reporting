"""
tests/test_effective_config_golden.py — Phase 20 QUAL-06 effective-config
golden regression.

Proves the v1.6 config language resolves to today's group shape
identically (D-07 two-way equality), so the Phase 21 cutover is
reversible in review:

  * The LEGACY single-file fixture (tests/fixtures/phase20_config_legacy/
    delivery_config.yaml — inline `email:` blocks, `groups:` key) resolves
    byte-identical to the committed golden
    (tests/baselines/effective_config_golden.json).
  * The MIGRATED-TWIN fixture (tests/fixtures/phase20_config_twin/ —
    contacts.yaml + deliveries.d/*.yaml, `contact:` refs, `deliveries:`
    key) resolves to the SAME committed golden.
  * Both resolved effective configs pass the unchanged
    delivery_config.schema.yaml.

Normalization (Claude's Discretion, D-07): the resolved `list[dict]` of
groups is wrapped as ``{"groups": groups}`` and serialized with
``json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False)`` — a
deterministic, sorted-key, human-diffable form. Both fixtures are run
through this same normalization before comparison.

Regenerating the golden (only when resolution intentionally changes):
run this file's ``main()`` with ``_REGENERATE = True`` set below, or
manually write ``_normalize(legacy_groups)`` to
``tests/baselines/effective_config_golden.json`` via a one-off script,
then review the diff carefully before committing.

All fixtures + the golden use the RFC 6761 reserved example.invalid
domain (Hard Rule 2 / D-04-08) — no real recipient addresses anywhere.

Run: python -m pytest tests/test_effective_config_golden.py -q
     (or) python tests/test_effective_config_golden.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from delivery.config_loader import resolve_config  # noqa: E402
from run_all import _load_config, _load_schema, _validate_with_schema  # noqa: E402

FAILED: list[str] = []

_TESTS_DIR = Path(__file__).resolve().parent
_FIXTURES_DIR = _TESTS_DIR / "fixtures"
_BASELINES_DIR = _TESTS_DIR / "baselines"
_GOLDEN_PATH = _BASELINES_DIR / "effective_config_golden.json"

_LEGACY_CONFIG_PATH = _FIXTURES_DIR / "phase20_config_legacy" / "delivery_config.yaml"
_TWIN_CONTACTS_PATH = _FIXTURES_DIR / "phase20_config_twin" / "contacts.yaml"

# Set to True and re-run to regenerate the committed golden from the
# legacy fixture's resolution. Leave False for normal test runs — the
# golden should only change deliberately, with the diff reviewed.
_REGENERATE = False


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


def _normalize(groups: list[dict]) -> str:
    """
    Serialize a resolved ``groups`` list into a deterministic, sorted-key
    JSON string for byte-identical comparison (D-07).
    """
    return json.dumps({"groups": groups}, sort_keys=True, indent=2, ensure_ascii=False)


def _resolve_legacy() -> list[dict]:
    """Resolve the legacy single-file fixture via _load_config (single-file mode)."""
    return _load_config(config_path=_LEGACY_CONFIG_PATH)


def _resolve_twin() -> list[dict]:
    """Resolve the migrated-twin fixture via _load_config (directory mode)."""
    return _load_config(config_path=_TWIN_CONTACTS_PATH)


def main() -> int:
    legacy_groups = _resolve_legacy()
    twin_groups = _resolve_twin()

    _check("legacy_resolves_nonempty", len(legacy_groups) > 0, hint=str(legacy_groups))
    _check("twin_resolves_nonempty", len(twin_groups) > 0, hint=str(twin_groups))

    legacy_normalized = _normalize(legacy_groups)
    twin_normalized = _normalize(twin_groups)

    if _REGENERATE:
        _GOLDEN_PATH.write_text(legacy_normalized + "\n", encoding="utf-8")
        print(f"REGENERATED golden at {_GOLDEN_PATH}")

    golden_text = _GOLDEN_PATH.read_text(encoding="utf-8").rstrip("\n")

    _check(
        "legacy_matches_committed_golden",
        legacy_normalized == golden_text,
        hint="legacy fixture resolution drifted from tests/baselines/effective_config_golden.json",
    )
    _check(
        "twin_matches_committed_golden",
        twin_normalized == golden_text,
        hint="migrated twin resolution does not equal the committed golden — QUAL-06 two-way equality broken",
    )
    _check(
        "twin_matches_legacy_directly",
        twin_normalized == legacy_normalized,
        hint="migrated twin and legacy fixture resolve to different effective configs",
    )

    # Golden group dicts must never carry the owner/contact metadata
    # side-channel keys (D-09) — schema additionalProperties:false at
    # the group level is the safety net.
    for g in legacy_groups + twin_groups:
        _check(
            f"no_owner_or_contact_key[{g.get('name')}]",
            "owner" not in g and "contact" not in g,
            hint=str(g),
        )

    # Both resolved effective configs must pass the unchanged schema.
    schema = _load_schema()
    legacy_schema_errors = _validate_with_schema({"groups": legacy_groups}, schema)
    twin_schema_errors = _validate_with_schema({"groups": twin_groups}, schema)
    _check("legacy_passes_schema", legacy_schema_errors == [], hint=str(legacy_schema_errors))
    _check("twin_passes_schema", twin_schema_errors == [], hint=str(twin_schema_errors))

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
