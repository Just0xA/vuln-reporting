#!/usr/bin/env python3
"""PreToolUse hook: gate Tenable data pulls. Two independent checks, deny-only.

  Check 1 (script rule): deny any subcommand that runs fetchers.py,
    tenable_client.py, or run_all.py through a Python interpreter UNLESS
    --dry-run is present in that same subcommand.

  Check 2 (host rule): deny any subcommand that is a network tool (curl, wget,
    Invoke-WebRequest/-RestMethod, etc.) OR a Python interpreter AND mentions a
    Tenable API host. This catches ad-hoc egress regardless of script name.
    No --dry-run exception: a call to the API is a call to the API.

Design:
  * Deny-only. Never returns "allow", so a parser bug can't widen access.
  * Per-subcommand. Compound commands (&&, ||, ;, |, newline, &) are split and
    judged independently, so a --dry-run in a later segment can't launder a run.
  * Reads are untouched. `cat run_all.py`, `grep cloud.tenable.com cfg.py`, and
    the Read tool aren't interpreter/network invocations, so they pass through.
  * Wrapper recursion (CR-C1): bash/sh/zsh -c payloads and python -c/-m refs
    are re-checked against the guarded-name set (depth-capped at 3).
  * Fail-closed (CR-S1): malformed PreToolUse payloads produce a deny, not an
    allow or a silent exit.
"""
import sys, json, re, shlex
from pathlib import Path

# GUARDED_DRYRUN: scripts with a VERIFIED pre-auth --dry-run exit (the dry-run
# branch returns before get_client() is ever called). Exempt only when
# --dry-run appears in the same subcommand.
#   run_all.py               — config validation; no API touch under --dry-run
#   warm_cache.py            — dry-run exits at arg parse, before get_client()
#   capture_trend_snapshot.py — same pattern as warm_cache
# fetchers.py / tenable_client.py / probe_last_fixed_filter.py /
# utils/tag_helper.py have no such mode, so they are ALWAYS denied; a
# --dry-run argument on them is meaningless and must not act as an escape
# hatch. backfill_trend_reconstruction.py is ALWAYS denied because its
# --dry-run still runs the overlap-test gate, which fetches live data.
GUARDED_DRYRUN         = {"run_all.py", "warm_cache.py", "capture_trend_snapshot.py"}
GUARDED_DRYRUN_MODULES = {"run_all", "warm_cache", "capture_trend_snapshot"}
GUARDED_ALWAYS         = {"fetchers.py", "tenable_client.py",
                          "backfill_trend_reconstruction.py",
                          "probe_last_fixed_filter.py", "tag_helper.py"}
GUARDED_ALWAYS_MODULES = {"fetchers", "tenable_client",
                          "backfill_trend_reconstruction",
                          "probe_last_fixed_filter", "tag_helper"}

def _discover_report_scripts():
    """Every reports/*.py is a standalone live-pull entry point (its
    ``__main__`` calls ``get_client()``) with no pre-auth dry-run, so all of
    them are ALWAYS-denied. Discovered dynamically so a new report script is
    guarded the day it lands. Failure degrades to the static sets only —
    the hook stays deny-only either way; tests/test_block_tenable_fetch.py
    coverage test catches any get_client importer that slips both nets.
    """
    try:
        repo_root = Path(__file__).resolve().parents[2]
        scripts = {p.name for p in (repo_root / "reports").glob("*.py")
                   if p.name != "__init__.py"}
        modules = {p[:-3] for p in scripts}
        return scripts, modules
    except Exception:
        return set(), set()

_rep_scripts, _rep_modules = _discover_report_scripts()
GUARDED_ALWAYS         |= _rep_scripts
GUARDED_ALWAYS_MODULES |= _rep_modules
# cloud.tenable.com also matches sensor.cloud.tenable.com and fedcloud.tenable.com
TENABLE_HOSTS   = ("cloud.tenable.com",)
PY_INTERPRETERS = {"python", "python3", "pythonw", "py",
                   "python.exe", "python3.exe", "pythonw.exe"}
NET_TOOLS = {"curl", "curl.exe", "wget", "wget.exe",
             "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
             "start-bitstransfer"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "env", "sudo", "xargs"}
# Launchers whose `run` subcommand executes an arbitrary command line
# (`uv run python run_all.py`). The launcher AND its `run` token are both
# skipped so the real head is judged. `uv run run_all.py` (script form,
# no interpreter token) is also covered because run_all.py then becomes
# the head and heads are re-checked against the guarded sets below.
RUN_LAUNCHERS = {"uv", "poetry", "pdm", "pipenv", "hatch"}
SHELL_WRAPPERS = {"bash", "sh", "zsh", "dash", "ksh"}
_MAX_RECURSE_DEPTH = 3

def split_segments(cmd):
    """Split on shell operators (&& || ; | & newline) but NOT inside quotes,
    so a `python -c "a;b"` string stays a single segment."""
    segs, cur, quote, i, n = [], "", None, 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if quote:
            cur += ch
            if ch == quote:
                quote = None
            i += 1
        elif ch in ("'", '"'):
            quote = ch; cur += ch; i += 1
        elif cmd[i:i + 2] in ("&&", "||"):
            segs.append(cur); cur = ""; i += 2
        elif ch in (";", "|", "&", "\n"):
            segs.append(cur); cur = ""; i += 1
        else:
            cur += ch; i += 1
    segs.append(cur)
    return segs

def basename(tok):
    return re.split(r"[\\/]", tok)[-1].lower()

def tokenize(segment):
    out, cur, quote = [], "", None
    for ch in segment:
        if quote:
            if ch == quote:
                quote = None
            else:
                cur += ch
        elif ch in ("'", '"'):
            quote = ch
        elif ch.isspace():
            if cur:
                out.append(cur); cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out

def effective_head(tokens):
    """Basename of the real command, skipping wrappers, VAR=val prefixes,
    and run-launcher prefixes (`uv run`, `poetry run`, ...)."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        b = basename(tok)
        if b in WRAPPERS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            i += 1
            continue
        if b in RUN_LAUNCHERS:
            # Skip the launcher, its option flags, and the `run` subcommand,
            # then keep unwrapping (handles `uv run --frozen python x.py`).
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            if i < len(tokens) and tokens[i] == "run":
                i += 1
                while i < len(tokens) and tokens[i].startswith("-"):
                    i += 1
                continue
            # Launcher without `run` (e.g. `uv pip ...`) — judge next token.
            continue
        return b, tokens[i + 1:]
    return None, []

def is_dry_run(tokens):
    return any(t == "--dry-run" or t.startswith("--dry-run=") for t in tokens)

def _scan_inline_code_for_guarded(code_str):
    """Scan an inline code string (from python -c '...') for guarded module refs.

    Returns 'always', 'dryrun', or None.
    """
    # Check for 'import X' or 'from X import ...' referencing guarded modules.
    for mod in GUARDED_ALWAYS_MODULES:
        if re.search(r'\b' + re.escape(mod) + r'\b', code_str):
            return "always"
    for mod in GUARDED_DRYRUN_MODULES:
        if re.search(r'\b' + re.escape(mod) + r'\b', code_str):
            return "dryrun"
    # Also check for guarded script filenames referenced inline.
    for script in GUARDED_ALWAYS:
        if script in code_str:
            return "always"
    for script in GUARDED_DRYRUN:
        if script in code_str:
            return "dryrun"
    return None


def script_hit(head, rest, _depth=0):
    """Return 'always', 'dryrun', or None for the guarded script in this segment.

    CR-C1: when head is a shell wrapper (bash/sh/zsh) followed by -c, the
    inline payload is re-tokenized and script_hit is called recursively.
    When head is a Python interpreter followed by -c, the inline code is
    scanned for guarded module/script names.  Depth-capped at _MAX_RECURSE_DEPTH.
    """
    if _depth >= _MAX_RECURSE_DEPTH:
        return None

    # --- Direct execution: the head IS the guarded script ---
    # Catches `./run_all.py`, `uv run run_all.py`, and any shebang-style
    # invocation where no interpreter token precedes the script name.
    if head in GUARDED_ALWAYS:
        return "always"
    if head in GUARDED_DRYRUN:
        return "dryrun"

    # --- Shell wrapper recursion (bash -lc '...', sh -c '...', etc.) ---
    if head in SHELL_WRAPPERS:
        # Find the -c flag (may be combined: -lc, -c, etc.)
        c_payload = None
        for j, t in enumerate(rest):
            if t == "-c" or (t.startswith("-") and "c" in t and t[1] != "-"):
                if j + 1 < len(rest):
                    c_payload = rest[j + 1]
                    break
        if c_payload is not None:
            try:
                sub_tokens = shlex.split(c_payload)
            except ValueError:
                sub_tokens = tokenize(c_payload)
            if sub_tokens:
                # Re-run effective_head so wrapper/launcher prefixes inside
                # the payload (`bash -lc 'uv run python ...'`, `sh -c
                # 'sudo python ...'`) are stripped the same way as at top
                # level.
                sub_head, sub_rest = effective_head(sub_tokens)
                if sub_head is not None:
                    return script_hit(sub_head, sub_rest, _depth + 1)
        return None

    if head not in PY_INTERPRETERS:
        return None

    # --- Python interpreter: check -m module ref ---
    for j, t in enumerate(rest):
        if t == "-m" and j + 1 < len(rest):
            mod = rest[j + 1].split(".")[-1]
            if mod in GUARDED_ALWAYS_MODULES:
                return "always"
            if mod in GUARDED_DRYRUN_MODULES:
                return "dryrun"

    # --- Python interpreter: check -c inline code ---
    for j, t in enumerate(rest):
        if t == "-c" and j + 1 < len(rest):
            return _scan_inline_code_for_guarded(rest[j + 1])
        # Also handle: python -c'import ...' (no space, token starts with -c)
        if t.startswith("-c") and len(t) > 2 and not t.startswith("-c-"):
            return _scan_inline_code_for_guarded(t[2:])

    # --- Standard script-name check ---
    for t in rest:
        b = basename(t)
        if b in GUARDED_ALWAYS:
            return "always"
        if b in GUARDED_DRYRUN:
            return "dryrun"
    return None

def hits_host_rule(head, segment_lower):
    if head not in PY_INTERPRETERS and head not in NET_TOOLS:
        return False
    return any(host in segment_lower for host in TENABLE_HOSTS)

def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        # CR-S1: fail closed — a malformed PreToolUse payload denies rather
        # than silently allowing the tool call through.
        deny("Blocked: malformed PreToolUse payload — failing closed.")
    ti = data.get("tool_input") or {}
    cmd = ti.get("command") or " ".join(str(v) for v in ti.values() if isinstance(v, str))
    if not cmd:
        sys.exit(0)
    for segment in split_segments(cmd):
        tokens = tokenize(segment)
        if not tokens:
            continue
        head, rest = effective_head(tokens)
        if head is None:
            continue
        hit = script_hit(head, rest)
        if hit == "always":
            deny("Blocked by local policy: fetchers.py / tenable_client.py pull "
                 "live Tenable data and have no dry-run mode, so they are always "
                 "blocked here. Run it yourself outside Claude Code.")
        if hit == "dryrun" and not is_dry_run(tokens):
            deny("Blocked by local policy: runs run_all.py without --dry-run. "
                 "Add --dry-run, or run it yourself outside Claude Code.")
        if hits_host_rule(head, segment.lower()):
            deny("Blocked by local policy: this command reaches the Tenable API "
                 "host (cloud.tenable.com). Pulling live Tenable data from Claude "
                 "Code is disabled. Run it yourself outside Claude Code.")
    sys.exit(0)

if __name__ == "__main__":
    main()