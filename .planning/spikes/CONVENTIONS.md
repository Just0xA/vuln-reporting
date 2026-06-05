# Spike Conventions

Patterns and stack choices established across spike sessions. New spikes follow these unless the question requires otherwise.

## Stack

- **Python + pandas** measurement scripts run against the **real cached parquet** in `data/cache/<YYYY-MM-DD>/` (`vulns_all`, `vulns_fixed`, `assets_all`). No live Tenable API call needed — the cache is real exported data, so spikes are fast, deterministic, and offline.
- **Reuse production logic** rather than reimplementing: import `config.vpr_to_severity` (and other `config`/`utils` helpers) via `sys.path.insert(0, <project root>)` so spike measurements mirror what the real modules will compute.
- Stdout verification is acceptable for these spikes because they answer **facts/measurements** (coverage %, retention horizon, predicate correctness), not feelings.

## Structure

- One spike per `.planning/spikes/NNN-descriptive-name/`.
- `measure.py` = the headline measurement; add `probe.py` for a depth/second-angle investigation (see 001). Keep scripts runnable standalone with a `PARQUET`/`CACHE` constant near the top.
- README.md carries full frontmatter + Investigation Trail + Results with a verdict table and an explicit "answers to the N questions" section.

## Patterns

- **Mirror production severity:** always derive Crit/High via `vpr_to_severity(score, fallback=native)`, never raw strings.
- **Don't stop at the happy path.** Both spikes flipped on the second look — 001's "Windows = OS" fear reversed (it's third-party apps); 002's optimistic reconstruction premise collapsed on retention. Probe surprises before writing a verdict.
- **Quantify the silent-error surface** (e.g. ~6% App/OS swing, ~19% reopened drop) so the build knows what to unit-test.
- **ASCII only in script output** — the Windows console is cp1252; non-ASCII chars (`≈`, `→`) raise `UnicodeEncodeError` mid-run. Use `~`, `->`, `==>`.

## Tools & Libraries

- `pandas` (3.0-safe): prefer `.assign()` over chained `df[col] = ...` to avoid `ChainedAssignmentError` warnings and dtype surprises.
- Parquet via the project's existing `pyarrow`/`fastparquet` setup.
- When filtering console noise, grep out the pandas FutureWarning/ChainedAssignment block rather than suppressing warnings in the script.
