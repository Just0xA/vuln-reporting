"""tests/test_stamp_config_provenance.py — Phase 21 D-03 provenance stamp/verify.

Covers the round-trip (stamp then verify passes) and the drift case
(mutating a config byte makes verify exit non-zero) for
``scripts/stamp_config_provenance.py``, using synthetic temp files only
(Hard Rule 2 — no real recipient content anywhere in this file).

Run: .venv/bin/python3 -m pytest tests/test_stamp_config_provenance.py -x -q
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.stamp_config_provenance import (  # noqa: E402
    _SIDECAR_NAME,
    stamp,
    verify,
)

_LOGGER = logging.getLogger("test_stamp_config_provenance")
_LOGGER.addHandler(logging.NullHandler())

_SYNTHETIC_COMMIT_SHA = "abc1234def5678900000000000000000000000"


def _write_synthetic_config(config_dir: Path) -> None:
    """Write a synthetic directory-mode config tree (example.invalid only)."""
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "contacts.yaml").write_text(
        "contacts:\n"
        "  synthetic_team:\n"
        "    recipients: [synthetic@example.invalid]\n",
        encoding="utf-8",
    )
    deliveries_dir = config_dir / "deliveries.d"
    deliveries_dir.mkdir(exist_ok=True)
    (deliveries_dir / "synthetic.yaml").write_text(
        "owner: synthetic-team\n"
        "deliveries:\n"
        "  - name: Synthetic Delivery\n"
        "    contact: synthetic_team\n",
        encoding="utf-8",
    )


def test_stamp_then_verify_round_trip(tmp_path: Path) -> None:
    """stamp() writes a sidecar; verify() on the unmodified config exits 0."""
    config_dir = tmp_path / "config"
    _write_synthetic_config(config_dir)

    stamp_code = stamp(config_dir, _SYNTHETIC_COMMIT_SHA, _LOGGER)
    assert stamp_code == 0

    sidecar_path = config_dir / _SIDECAR_NAME
    assert sidecar_path.is_file()

    record = json.loads(sidecar_path.read_text(encoding="utf-8"))
    assert record["commit_sha"] == _SYNTHETIC_COMMIT_SHA
    assert "sha256" in record
    assert "stamped_at" in record

    verify_code = verify(config_dir, _LOGGER)
    assert verify_code == 0


def test_verify_detects_drift_on_mutated_byte(tmp_path: Path) -> None:
    """Mutating a config byte after stamping makes verify() exit non-zero."""
    config_dir = tmp_path / "config"
    _write_synthetic_config(config_dir)

    assert stamp(config_dir, _SYNTHETIC_COMMIT_SHA, _LOGGER) == 0

    # Mutate one byte in a stamped config file (simulates an untracked hand-edit).
    contacts_path = config_dir / "contacts.yaml"
    original = contacts_path.read_text(encoding="utf-8")
    contacts_path.write_text(original + "# tampered\n", encoding="utf-8")

    assert verify(config_dir, _LOGGER) != 0


def test_verify_fails_on_missing_sidecar(tmp_path: Path) -> None:
    """verify() on a config directory with no prior stamp exits non-zero."""
    config_dir = tmp_path / "config"
    _write_synthetic_config(config_dir)

    assert verify(config_dir, _LOGGER) != 0


def test_stamp_fails_on_missing_config_dir(tmp_path: Path) -> None:
    """stamp() on a nonexistent config directory exits non-zero."""
    missing_dir = tmp_path / "does-not-exist"
    assert stamp(missing_dir, _SYNTHETIC_COMMIT_SHA, _LOGGER) != 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
