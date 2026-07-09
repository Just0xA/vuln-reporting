"""
tests/test_dry_run_surfacing.py — Phase 20 CONF-03 / D-10 dry-run surfacing.

Locks in the THIN `run_all._dry_run` directory-mode surfacing block
(run_all.py:468-485) — the layer that MAPS loader-level errors/warnings
returned by ``delivery.config_loader.resolve_config`` onto the ``--dry-run``
exit code and console output:

  * loader ERRORS  -> printed in red   -> ``any_errors = True`` -> exit 1
  * loader WARNINGS -> printed in yellow -> exit code UNCHANGED   -> exit 0

The four Plan 20-02 acceptance outcomes are asserted through ``_dry_run``
itself (not through ``resolve_config``, which is already covered by
tests/test_config_loader.py checks G/H/J):

  1. duplicate delivery name   -> error   -> exit 1
  2. undefined ``contact:`` ref -> error   -> exit 1
  3. inline ``email:`` in dir mode -> error -> exit 1
  4. deprecated top-level ``groups:`` alias -> warning -> exit 0

Per 20-02-SUMMARY this mapping was previously verified only by an
uncommitted scratchpad harness; this file is the committed cover.

TESTABILITY / global-state handling
------------------------------------
``_dry_run`` is entangled with process/module globals. Each case:
  * monkeypatches ``run_all.ROOT_DIR`` to a synthetic tmp dir holding a
    ``deliveries.d/`` + ``contacts.yaml`` sibling (there is NO
    ``delivery_config.yaml`` file there, so the legacy single-file
    schema-error block is skipped — only the directory-mode block runs);
  * neutralizes the env-var masking path by setting
    ``run_all._REQUIRED_ENV_VARS = []`` so the ONLY driver of the exit
    code is the directory-mode resolution block under test;
  * swaps ``run_all.console`` for a ``rich`` Console writing to a
    ``StringIO`` so console output can be asserted without noise.
All patched globals are restored in a ``finally`` block.

``_dry_run`` only reads/resolves YAML — no Tenable fetcher entry point is
invoked (Hard Rule 1 permits pre-auth dry-run YAML resolution).

All addresses use the RFC 6761 reserved example.invalid domain (Hard
Rule 2 / D-04-08) — no real recipient addresses anywhere in this file.

Run: python tests/test_dry_run_surfacing.py
     (or) .venv/bin/python3 tests/test_dry_run_surfacing.py
     (NOT `python -m pytest` — see tests/test_config_loader.py infra note)
"""
from __future__ import annotations

import io
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console  # noqa: E402

import run_all  # noqa: E402

FAILED: list[str] = []


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


_CONTACTS_YAML = """
contacts:
  exec_team:
    recipients:
      - ciso@example.invalid
      - vp-it@example.invalid
    cc:
      - board-liaison@example.invalid
  remediation_team:
    recipients:
      - remediation@example.invalid
defaults:
  analyst_mailbox: analyst-team@example.invalid
"""


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run_dry_run_against(base_dir: Path) -> tuple[int, str]:
    """
    Invoke ``run_all._dry_run([])`` with ``run_all.ROOT_DIR`` pointed at a
    synthetic directory-mode config tree under *base_dir*.

    Returns ``(exit_code, console_output)``. Passes an EMPTY groups list so
    the rich per-group table loop is a no-op and the directory-mode
    surfacing block is the ONLY driver of the exit code.

    Restores every patched module global in a ``finally`` block.
    """
    orig_root = run_all.ROOT_DIR
    orig_console = run_all.console
    orig_required_env = run_all._REQUIRED_ENV_VARS

    buf = io.StringIO()
    try:
        run_all.ROOT_DIR = base_dir
        run_all.console = Console(file=buf, width=200, force_terminal=False)
        run_all._REQUIRED_ENV_VARS = []
        code = run_all._dry_run([])
        return code, buf.getvalue()
    finally:
        run_all.ROOT_DIR = orig_root
        run_all.console = orig_console
        run_all._REQUIRED_ENV_VARS = orig_required_env


def _make_base(tmp_root: Path, name: str) -> Path:
    base = tmp_root / name
    _write(base / "contacts.yaml", _CONTACTS_YAML)
    return base


def _dup_name_case(tmp_root: Path) -> None:
    """Duplicate delivery name across two team files -> error -> exit 1."""
    base = _make_base(tmp_root, "duplicate_name")
    _write(
        base / "deliveries.d" / "team_a.yaml",
        """
owner: "Team A"
deliveries:
  - name: "Shared Name"
    contact: exec_team
    subject: "A"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    _write(
        base / "deliveries.d" / "team_b.yaml",
        """
owner: "Team B"
deliveries:
  - name: "Shared Name"
    contact: remediation_team
    subject: "B"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    code, out = _run_dry_run_against(base)
    _check(
        "dup_name_exit_1",
        code == 1,
        hint=f"expected exit 1, got {code}; out={out!r}",
    )
    _check(
        "dup_name_error_surfaced",
        "duplicate delivery name" in out and "Config errors" in out,
        hint=f"out={out!r}",
    )


def _undefined_ref_case(tmp_root: Path) -> None:
    """Undefined contact: ref -> error -> exit 1."""
    base = _make_base(tmp_root, "undefined_ref")
    _write(
        base / "deliveries.d" / "team.yaml",
        """
owner: "Team X"
deliveries:
  - name: "Broken Ref Delivery"
    contact: nonexistent_team
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    code, out = _run_dry_run_against(base)
    _check(
        "undefined_ref_exit_1",
        code == 1,
        hint=f"expected exit 1, got {code}; out={out!r}",
    )
    _check(
        "undefined_ref_error_surfaced",
        "nonexistent_team" in out and "Config errors" in out,
        hint=f"out={out!r}",
    )


def _inline_email_case(tmp_root: Path) -> None:
    """Inline email.recipients in directory mode -> error -> exit 1."""
    base = _make_base(tmp_root, "inline_email")
    _write(
        base / "deliveries.d" / "team.yaml",
        """
owner: "Team Inline"
deliveries:
  - name: "Inline Email Delivery"
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
    email:
      recipients:
        - inline@example.invalid
""",
    )
    code, out = _run_dry_run_against(base)
    _check(
        "inline_email_exit_1",
        code == 1,
        hint=f"expected exit 1, got {code}; out={out!r}",
    )
    _check(
        "inline_email_error_surfaced",
        "inline" in out.lower() and "Config errors" in out,
        hint=f"out={out!r}",
    )


def _deprecated_alias_case(tmp_root: Path) -> None:
    """Deprecated top-level groups: alias, otherwise valid -> warning -> exit 0."""
    base = _make_base(tmp_root, "deprecated_alias")
    _write(
        base / "deliveries.d" / "team.yaml",
        """
owner: "Team Alias"
groups:
  - name: "Alias Delivery"
    contact: exec_team
    subject: "x"
    schedule:
      frequency: on_demand
    filters: {}
    reports:
      - executive_kpi
""",
    )
    code, out = _run_dry_run_against(base)
    _check(
        "deprecated_alias_exit_0",
        code == 0,
        hint=f"expected exit 0 (warning must NOT flip exit code), got {code}; out={out!r}",
    )
    _check(
        "deprecated_alias_warning_surfaced",
        "Config warnings" in out and "deprecated" in out.lower(),
        hint=f"out={out!r}",
    )
    _check(
        "deprecated_alias_no_error_block",
        "Config errors" not in out,
        hint=f"warning case must not emit an error block; out={out!r}",
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        _dup_name_case(tmp_root)
        _undefined_ref_case(tmp_root)
        _inline_email_case(tmp_root)
        _deprecated_alias_case(tmp_root)

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
