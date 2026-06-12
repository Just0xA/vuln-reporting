"""
tests/test_capture_trend_snapshot_cli.py — Subprocess regression test for the
capture_trend_snapshot.py sys.path bootstrap fix (UAT-5 lock).

UAT-5 uncovered that `python scripts/capture_trend_snapshot.py` raised
ModuleNotFoundError: No module named 'config' when invoked from any CWD
that was NOT the repo root — because the script had no sys.path bootstrap
and relied on the ambient CWD to resolve first-party imports.

16-06 Task 1 fixed this by inserting:
    _REPO_ROOT = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_REPO_ROOT))
before the first-party imports in the script.

This test locks that fix against regression by:
  1. Computing repo_root from THIS test file's resolved location (not CWD).
  2. Invoking the script via subprocess with cwd=<non-root dir> (a tempdir).
  3. NOT setting PYTHONPATH to repo_root in the subprocess env — the in-script
     bootstrap must be what resolves imports, not the ambient env. Setting
     PYTHONPATH would re-mask the bug (the exact issue that the old
     import-from-root probe had).
  4. Asserting returncode == 0 and no ModuleNotFoundError in stderr.

The --dry-run flag is used so no Tenable credentials are needed and no files
are written — the script returns 0 before get_client() is called.

No real data, no network I/O, no Tenable credentials required.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Script path — derived from this test file's resolved location, not CWD.
# repo_root = tests/../ = project root
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "capture_trend_snapshot.py"


class TestSnapshotCliRealInvocation:
    """
    Real-invocation subprocess regression test for the snapshot-script
    sys.path bootstrap (UAT-5 lock — D-16-27).

    The test MUST run from a non-root CWD to reproduce the original bug.
    Using a TemporaryDirectory guarantees the ambient CWD cannot put the
    repo root on sys.path; it is the script's own bootstrap that resolves
    imports.

    DO NOT set PYTHONPATH=repo_root in the subprocess environment — that
    would re-mask the bug exactly as the old import-from-root probe did.
    """

    def test_script_exists(self):
        """Sanity: the script file exists at the expected path."""
        assert _SCRIPT_PATH.exists(), (
            f"Script not found at {_SCRIPT_PATH} — check repo layout"
        )

    def test_dry_run_from_non_root_cwd_exits_0(self):
        """
        `python scripts/capture_trend_snapshot.py --dry-run` from a non-root
        CWD exits 0 with no ModuleNotFoundError.

        This is the exact invocation that UAT-5 caught: the script raised
        ModuleNotFoundError when the ambient CWD was not the repo root and
        no sys.path bootstrap was present. The 16-06 bootstrap fix resolves
        imports from Path(__file__).resolve().parent.parent regardless of CWD.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [sys.executable, str(_SCRIPT_PATH), "--dry-run"],
                cwd=tmpdir,  # NOT the repo root — this is the regression trigger
                capture_output=True,
                text=True,
                env={
                    # Pass through minimal env (PATH, TEMP, etc.) but
                    # do NOT add repo_root to PYTHONPATH — the script's
                    # own bootstrap must handle it.
                    k: v for k, v in os.environ.items()
                    if k != "PYTHONPATH"  # exclude any ambient PYTHONPATH that would mask the bug
                },
            )

        assert result.returncode == 0, (
            f"Script exited {result.returncode} from non-root CWD.\n"
            f"stdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}\n"
            f"If returncode==1 with ModuleNotFoundError, the sys.path bootstrap "
            f"in scripts/capture_trend_snapshot.py was reverted."
        )
        assert "ModuleNotFoundError" not in result.stderr, (
            f"ModuleNotFoundError found in stderr — bootstrap failed:\n{result.stderr}"
        )
        assert "No module named 'config'" not in result.stderr, (
            f"'No module named config' in stderr — bootstrap failed:\n{result.stderr}"
        )

    def test_dry_run_stderr_has_no_module_not_found_error(self):
        """
        Explicit assert on ModuleNotFoundError absence (belt-and-suspenders).
        The --dry-run path returns before get_client(), so no Tenable credentials needed.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [sys.executable, str(_SCRIPT_PATH), "--dry-run"],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
            )
        assert "ModuleNotFoundError" not in result.stderr, (
            f"ModuleNotFoundError in stderr:\n{result.stderr}"
        )
        assert "No module named" not in result.stderr, (
            f"'No module named' in stderr — some import failed:\n{result.stderr}"
        )

    def test_dry_run_output_confirms_reached_main(self):
        """
        --dry-run outputs a DRY RUN log line, confirming the script reached
        main() and was not short-circuited by an import error.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [sys.executable, str(_SCRIPT_PATH), "--dry-run"],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
            )
        # The script logs "DRY RUN: would capture snapshot ..."
        combined = result.stdout + result.stderr
        assert "DRY RUN" in combined, (
            f"Expected 'DRY RUN' in output to confirm script reached main(), got:\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_bootstrap_would_fail_without_it(self):
        """
        Documentation test: confirms the bug this regression guards against.

        If the bootstrap (_REPO_ROOT insertion) were removed from the script,
        running from a non-root CWD with no PYTHONPATH would raise:
            ModuleNotFoundError: No module named 'config'
        This test does NOT reproduce the failure (to avoid breaking the test);
        it records the bug class and links to UAT-5 so the regression test
        purpose is clear to future maintainers.

        The actual guard is test_dry_run_from_non_root_cwd_exits_0.
        """
        # The bootstrap line in capture_trend_snapshot.py is:
        #   _REPO_ROOT = Path(__file__).resolve().parent.parent
        #   sys.path.insert(0, str(_REPO_ROOT))
        # Verify it is present:
        script_text = _SCRIPT_PATH.read_text(encoding="utf-8")
        assert "sys.path.insert" in script_text, (
            "Bootstrap 'sys.path.insert' not found in capture_trend_snapshot.py — "
            "the UAT-5 fix was reverted. Running from a non-root CWD will raise "
            "ModuleNotFoundError: No module named 'config'."
        )
        assert "_REPO_ROOT" in script_text, (
            "_REPO_ROOT anchor not found in capture_trend_snapshot.py — "
            "the UAT-5 bootstrap fix may have been removed or renamed."
        )
