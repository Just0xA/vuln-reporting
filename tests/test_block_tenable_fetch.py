"""
tests/test_block_tenable_fetch.py — Regression tests for the PreToolUse
block_tenable_fetch.py hook.

Covers:
  - CR-C1: nested shell-wrapper bypass (bash -lc / sh -c / python -c / python -m)
  - CR-S1: malformed PreToolUse payload fails CLOSED (deny, not allow)
  - Regression: existing direct fetch still denied; safe command still allowed.

Tests drive the hook as a subprocess feeding a JSON PreToolUse payload on
stdin and asserting the parsed decision JSON.  This exercises the full entry
point (main()) including the JSON serialiser and sys.exit(0) path.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK_PATH = REPO_ROOT / ".claude" / "hooks" / "block_tenable_fetch.py"


def _run_hook(payload_str: str) -> dict:
    """Run the hook subprocess, feeding payload_str on stdin.

    Returns the parsed JSON output dict, or {} on empty stdout (allow path
    that exits without printing).
    """
    result = subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=payload_str,
        capture_output=True,
        text=True,
        timeout=10,
    )
    stdout = result.stdout.strip()
    if not stdout:
        return {}
    return json.loads(stdout)


def _make_payload(command: str) -> str:
    """Build a minimal PreToolUse Bash-tool JSON payload."""
    return json.dumps({"tool_input": {"command": command}})


def _decision(out: dict) -> str:
    """Extract permissionDecision from hook output, defaulting to 'allow'."""
    return (
        out.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
    )


# ---------------------------------------------------------------------------
# CR-C1 tests: nested wrapper bypass
# ---------------------------------------------------------------------------


def test_nested_bash_c_wrapper_denied():
    """bash -lc 'python -m data.fetchers ...' must be DENIED (CR-C1)."""
    cmd = "bash -lc 'python -m data.fetchers --export vulns'"
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "deny", (
        f"Expected deny for bash -lc wrapped guarded fetch, got: {out}"
    )


def test_sh_c_wrapper_denied():
    """sh -c 'python data/fetchers.py' must be DENIED (CR-C1)."""
    cmd = "sh -c 'python data/fetchers.py'"
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "deny", (
        f"Expected deny for sh -c wrapped guarded fetch, got: {out}"
    )


def test_python_c_payload_denied():
    """python -c 'import data.fetchers' must be DENIED (CR-C1)."""
    cmd = "python -c 'import data.fetchers'"
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "deny", (
        f"Expected deny for python -c guarded module import, got: {out}"
    )


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------


def test_simple_guarded_fetch_still_denied():
    """Direct python data/fetchers.py must remain DENIED (no regression)."""
    cmd = "python data/fetchers.py"
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "deny", (
        f"Expected deny for direct guarded fetch, got: {out}"
    )


def test_unguarded_command_allowed():
    """An unrelated command (ls -la) must be ALLOWED."""
    cmd = "ls -la"
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "allow", (
        f"Expected allow for unguarded command, got: {out}"
    )


# ---------------------------------------------------------------------------
# CR-S1 test: fail-closed on malformed payload
# ---------------------------------------------------------------------------


def test_malformed_payload_fails_closed():
    """Malformed/non-JSON stdin must produce a DENY, not allow or silent exit (CR-S1)."""
    out = _run_hook("this is not json {{{")
    assert _decision(out) == "deny", (
        f"Expected deny (fail-closed) for malformed payload, got: {out}"
    )

# ---------------------------------------------------------------------------
# CR-C2: expanded entry-point coverage (2026-07 harness review)
# ---------------------------------------------------------------------------


import pytest


@pytest.mark.parametrize("cmd", [
    "python scripts/warm_cache.py",
    "python scripts/capture_trend_snapshot.py",
    "python scripts/backfill_trend_reconstruction.py --dry-run",  # gate fetches live
    "python scripts/probe_last_fixed_filter.py",
    "python utils/tag_helper.py --list-tags",
    "python reports/board_summary.py",
    "python reports/ops_remediation.py --tag-category Env",
    "python -m reports.board_summary",
])
def test_live_pull_scripts_denied(cmd):
    """Every standalone live-pull entry point must be DENIED (CR-C2)."""
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "deny", f"Expected deny for {cmd!r}, got: {out}"


@pytest.mark.parametrize("cmd", [
    "python scripts/warm_cache.py --dry-run",
    "python scripts/capture_trend_snapshot.py --dry-run",
    "python run_all.py --dry-run",
])
def test_verified_dryrun_scripts_allowed(cmd):
    """Scripts with a verified pre-auth --dry-run exit are ALLOWED with the flag."""
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "allow", f"Expected allow for {cmd!r}, got: {out}"


@pytest.mark.parametrize("cmd", [
    "uv run python run_all.py --group X",
    "uv run --frozen python scripts/warm_cache.py",
    "uv run run_all.py",
    "poetry run python reports/board_summary.py",
    "./run_all.py --group X",
    "xargs python reports/board_summary.py",
    "bash -lc 'uv run python run_all.py'",
])
def test_launcher_and_direct_exec_bypasses_denied(cmd):
    """uv/poetry run, direct ./script.py, and xargs forms must be DENIED (CR-C2)."""
    out = _run_hook(_make_payload(cmd))
    assert _decision(out) == "deny", f"Expected deny for {cmd!r}, got: {out}"


def test_uv_run_dryrun_allowed():
    """uv run python run_all.py --dry-run is ALLOWED (parity with bare python)."""
    out = _run_hook(_make_payload("uv run python run_all.py --dry-run"))
    assert _decision(out) == "allow", f"Expected allow, got: {out}"


# ---------------------------------------------------------------------------
# CR-C3: self-maintaining coverage — any file importing tenable_client must be
# in the hook's guarded sets. A new live-pull entry point that isn't guarded
# fails THIS test the day it lands, instead of silently widening access.
# ---------------------------------------------------------------------------


def _hook_guarded_sets():
    """Import the hook as a module and return (GUARDED_ALWAYS | GUARDED_DRYRUN)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("block_tenable_fetch", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return set(mod.GUARDED_ALWAYS) | set(mod.GUARDED_DRYRUN)


# Files that import tenable_client but are NOT standalone live-pull entry
# points, with the reason each is exempt. Anything new must be justified here
# or added to the hook's guarded sets.
_COVERAGE_EXEMPT: dict[str, str] = {
    "run_all.py": "guarded via GUARDED_DRYRUN (real --dry-run mode)",
    "smoke_board_summary_cutover.py": "cache-only by design; never calls get_client()",
    "smoke_management_summary_cutover.py": "cache-only by design; never calls get_client()",
    "conftest.py": "test scaffolding; no live client construction",
}

_IMPORT_PATTERN = re.compile(
    r"^\s*(from\s+tenable_client\s+import|import\s+tenable_client)\b", re.MULTILINE
)


def test_every_tenable_client_importer_is_guarded():
    """CR-C3: grep the repo for tenable_client importers; each must be guarded."""
    guarded = _hook_guarded_sets()
    unguarded: list[str] = []
    for py in REPO_ROOT.rglob("*.py"):
        rel = py.relative_to(REPO_ROOT)
        parts = rel.parts
        if parts[0] in {".git", ".venv", "tests", ".planning", ".claude"}:
            continue
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _IMPORT_PATTERN.search(text):
            continue
        if py.name in guarded or py.name in _COVERAGE_EXEMPT:
            continue
        unguarded.append(str(rel))
    assert not unguarded, (
        "Files import tenable_client but are neither in the hook's guarded "
        f"sets nor in _COVERAGE_EXEMPT: {unguarded}. Add them to "
        ".claude/hooks/block_tenable_fetch.py (GUARDED_ALWAYS unless they "
        "have a verified pre-auth --dry-run exit) or justify an exemption."
    )
