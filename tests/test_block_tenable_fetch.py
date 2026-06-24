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
