---
slug: rich-liveerror-concurrent
status: resolved
trigger: "rich.errors.LiveError 'Only one live display may be active at once' when two scheduled reports run at the same time"
created: 2026-05-22
updated: 2026-05-22
---

# Debug Session: rich LiveError on concurrent scheduled reports

## Symptoms

- **Expected:** Two delivery groups scheduled at the same time both run and deliver successfully.
- **Actual:** One group fails with `rich.errors.LiveError: Only one live display may be active at once`. (Fail-soft batch semantics mean the other group/report likely proceeds, but the affected report is lost.)
- **Error / trace (Rocky 9 VM, v1.2.3):**
  ```
  [ERROR] run_all — [Test Pull — Analyst Off] Report 'board_summary' failed: Only one live display may be active at once
  run_all.run_group (run_all.py:729)
    -> board_summary.run_report (board_summary.py:201)
      -> data/fetchers.py fetch_fixed_vulnerabilities (fetchers.py:395): `with Progress(...)`
        -> rich/progress.py start -> rich/live.py start -> rich/console.py set_live
          -> rich.errors.LiveError: Only one live display may be active at once
  ```
- **Timeline:** Surfaced 2026-05-22 when testing two reports scheduled at the same time on the VM (v1.2.3). Not previously hit because groups were run one at a time / manually.
- **Reproduction:** Schedule two groups (e.g. "Test Pull" + "Test Pull — Analyst Off") at the same `time:` so they fire concurrently.

## Initial Hypothesis (to verify, not assume)

APScheduler fires overlapping jobs in separate threads; each report opens a `rich` `Progress` live display on a **shared module-level `Console`**, and `rich` permits only one live display per `Console` at a time → `LiveError`. Secondary observation: under the systemd service there is no TTY, so live progress bars serve no purpose there anyway.

## Investigation scope

- How `rich` `Console` / `Progress` is instantiated and shared across `data/fetchers.py` and the report modules (module-level singleton vs per-call).
- How `run_all` / `scheduler.py` execute groups concurrently: APScheduler executor type, thread pool size, `max_instances`, `coalesce`, whether daemon vs run-due mode overlaps jobs.
- Whether `fetch_fixed_vulnerabilities` (and other fetchers) wrap network calls in `Progress`, and whether they guard on `console.is_terminal`.
- Candidate fixes to evaluate: (a) suppress live `Progress` when not a TTY, (b) per-run/per-thread `Console` instances, (c) serialize execution (APScheduler `max_instances=1` / single worker / lock around `run_group`), (d) a lock guarding live-display creation.

## Current Focus

- hypothesis: CONFIRMED (with refinement) — concurrent daemon-mode threads + rich's process-global live-display lock collide; non-TTY service gains nothing from live bars regardless.
- next_action: ROOT CAUSE FOUND — present fix options at checkpoint.

## Evidence

- timestamp: 2026-05-22 — `data/fetchers.py:32` imports `Progress` from rich. Five fetchers open `with Progress(SpinnerColumn(), TextColumn(...), TimeElapsedColumn(), transient=True)` at lines 264, 395, 499, 893, 995. NONE pass an explicit `console=` argument. With no console, rich uses its **process-global default console** (`rich.get_console()`), and the live-display lock lives on that shared console instance. Two threads entering any two of these blocks at once → `LiveError`.
- timestamp: 2026-05-22 — `scheduler.py` daemon mode (line 300+) uses `BlockingScheduler()` with **default executor (ThreadPoolExecutor, 10 workers)**. Each group is added as a separate `add_job(..., id="group_<name>", ...)` (line 248) with `replace_existing=True`, `misfire_grace_time=600`. `max_instances` is left at the APScheduler default of 1 — but that only prevents the SAME job_id overlapping. Two DIFFERENT groups scheduled at the same `time:` get distinct job_ids and **fire concurrently in two pool threads**. This is the concurrency vector that triggers the collision. `coalesce` is also default.
- timestamp: 2026-05-22 — `scheduler.py` run-due mode (line 414): groups run in a **sequential `for group in due:` loop**. No concurrency in this mode, so run-due would NOT hit the LiveError. The bug is specific to daemon mode (matches the VM repro, which uses the daemon service).
- timestamp: 2026-05-22 — The systemd service runs `scheduler.py --mode daemon`/`--mode run-due` non-interactively (no TTY). rich `Progress` live bars produce no useful output on a non-terminal but still acquire the global live lock. So the live display is pure liability under the service: zero value, real failure mode.
- timestamp: 2026-05-22 — Other module-level `Console()` singletons exist (`run_all.py:71`, `delivery/delivery_log.py:42`, `utils/tag_helper.py:32`, `reports/management_summary.py:104`) but these are used for static `console.print(...)`/tables, NOT live displays, so they do not contribute to the LiveError. Only the `Progress` blocks in `data/fetchers.py` take the live lock.

## Root Cause

Two compounding facets:

1. **(Primary, concurrency)** In daemon mode, APScheduler's default ThreadPoolExecutor runs two distinct groups scheduled at the same time concurrently. Both groups call into `data/fetchers.py`, where every `Progress(...)` is created without an explicit `Console` and therefore shares rich's process-global default console. rich enforces a single active live display per console process-wide, so the second thread to enter a `Progress` block raises `rich.errors.LiveError`.

2. **(Secondary, correctness)** Under the systemd service there is no TTY, so these `transient=True` live progress bars render nothing useful but still take the live lock — making them all cost, no benefit, in exactly the environment where the failure occurs.

`specialist_hint: python`

## Fix Direction (candidates, with tradeoffs)

**Option A — TTY-gate the live Progress (recommended primary).** Replace the bare `Progress(...)` usage with a small helper that passes `disable=not console.is_terminal` (or wraps a no-op when `not sys.stdout.isatty()`). On the non-TTY service this turns off the live display entirely (no lock taken), which both fixes the service crash AND removes a pointless render. Surgical: one helper + swap five call sites. Honors "no value under systemd" + fail-soft.
  - Tradeoff: does NOT fix the interactive case where a user runs two concurrent groups in a real terminal (rare, but possible).

**Option B — Per-call / per-thread Console.** Construct a fresh `Console()` inside each `Progress(console=...)` (or thread-local). Each console has its own live lock, so concurrent threads never collide regardless of TTY.
  - Tradeoff: multiple live displays writing to the same real terminal interleave/garble output; fine on non-TTY. More moving parts than A.

**Option C — Serialize daemon execution.** Wrap `run_group` (or the live-display creation) in a process-wide `threading.Lock`, OR cap the daemon executor to 1 worker / coalesce. Removes concurrency entirely.
  - Tradeoff: serializes ALL group deliveries in daemon mode (slower batches); arguably acceptable since this is a low-frequency scheduled service, but it's a behavior change beyond the bug.

**Recommended:** Option A as the correctness fix for the service (the environment where the bug actually fires), optionally combined with a lightweight guard (B or C) only if interactive concurrency is a real concern. Needs live-concurrency confirmation on the Rocky 9 VM after the fix (per the "verify on real RHEL VM" practice).

## Eliminated

- run-due mode as a trigger — it runs groups sequentially (scheduler.py:414), cannot produce overlapping live displays.
- The static `Console()` singletons in run_all/delivery_log/tag_helper/management_summary — used for non-live `print`/tables only; they do not take the live lock.

## Resolution

**Fix applied:** Option A + B in `data/fetchers.py` (2026-05-22).

- Added `_make_fetch_progress()` helper that constructs a `Progress` with **its own `Console`** (B — per-call console, so concurrent threads never share rich's process-global live-display lock) **and** `disable=not console.is_terminal` (A — live display fully off when stdout is not a terminal, i.e. under the systemd service).
- Imported `rich.console.Console`.
- Replaced all 5 identical `with Progress(SpinnerColumn(), TextColumn(...), TimeElapsedColumn(), transient=True) as progress:` blocks (lines 264/395/499/893/995) with `with _make_fetch_progress() as progress:`.

**Verification (dev box, .venv Python):**
- `py_compile data/fetchers.py` → OK.
- Concurrency test, non-TTY stdout: two threads entering `_make_fetch_progress()` simultaneously → no error; `disable` resolved to `True` (A confirmed for the service path).
- Concurrency test, live ENABLED (`force_terminal=True`, in-memory file): per-call console (B) → **PASS, no error**; control using a single shared console under the same concurrency → **collided with `LiveError`**, proving the test reproduces the original bug and the fix prevents it.

**Files changed:** `data/fetchers.py`.

**Confirmed on the VM (2026-05-22, v1.2.4):** the original repro — two groups (`Test Pull` + `Test Pull — Analyst Off`) scheduled at the same `time:` — ran concurrently under the daemon (interleaved log lines prove true thread concurrency). Both completed `board_summary` incl. `fetch_fixed_vulnerabilities`, wrote PDF + Excel, and reached the email stage. **No `LiveError`.** Fully resolved. Shipped in v1.2.4.
