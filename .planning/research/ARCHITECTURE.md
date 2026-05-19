# Architecture Patterns

**Domain:** Deployment infrastructure for Python reporting suite (v1.2 Server Update and Install)
**Researched:** 2026-05-19
**Scope:** Integration analysis for `warm_cache.py`, `update_from_github.sh`, `.github/workflows/release.yml`, `.gitattributes` — new components integrating with existing v1.1 system.

---

## Integration Point Analysis

### 1. `scripts/warm_cache.py` — Where It Plugs In

**The seam is `data/fetchers.py`, not `run_all.py`.**

`run_all.py`'s pre-fetch block (lines 658–671) is a thin wrapper that calls exactly two functions:

```python
fetch_all_vulnerabilities(tio, cache_dir)
fetch_all_assets(tio, cache_dir)
```

Both functions already implement the full cache contract: `_cache_path()` → `_load_cache()` → (if miss) API call → `_save_cache()`. This logic lives entirely in `data/fetchers.py` (lines 175–200 for helpers; `fetch_all_vulnerabilities` at line 203, `fetch_all_assets` at line 451).

`warm_cache.py` should **import and call `fetch_all_vulnerabilities` and `fetch_all_assets` directly from `data.fetchers`** — no shared helper needs to be extracted from `run_all.py`. The pre-fetch block in `run_all.py` is already the minimum seam: two fetcher calls. `warm_cache.py` replicates that exact call pattern as a standalone script.

**Cache directory convention:** `run_all.py` derives `cache_dir` as `CACHE_DIR / datetime.now().strftime("%Y-%m-%d")` (local time). `warm_cache.py` must use the identical derivation (`datetime.now()`, not UTC) so the paths match when `run_all.py` looks up the pre-warmed files. `config.CACHE_DIR` is the shared root — import it, don't hardcode `/opt/...`.

**What `warm_cache.py` needs to import:**
- `tenable_client.get_client` — identical to every other entry point
- `data.fetchers.fetch_all_vulnerabilities`
- `data.fetchers.fetch_all_assets`
- `config.CACHE_DIR` — for default `cache_dir` derivation
- `config.LOG_DIR` — for `logs/warm_cache.log` rotating handler

**What it does NOT need:**
- Any import from `run_all.py` — no shared helper extraction required
- Any report module imports
- `delivery_config.yaml` — cache warming is scope-agnostic (fetches all assets / all vulns; tag filtering happens in-memory inside each report)

**Stale-folder pruning:** `run_all.py` prunes prior-day cache folders at startup (line 870). `warm_cache.py` implements the same pruning under `--prune-stale`, keeping the behavior opt-in for the scheduled warm job. Both must agree on "local machine date" as the folder name, not UTC.

**Idempotency:** The existing `_load_cache` / `_save_cache` pattern does not prevent re-fetch on re-run — `_load_cache` returns the cached file if present, which means a re-run of `warm_cache.py` for the same date will immediately return cached data without hitting Tenable again. This is the correct behavior for idempotency. The `--force` flag (if desired) would need to delete the parquet files before calling the fetchers.

---

### 2. Symlink Layout vs. Existing systemd Unit

**The existing unit uses hardcoded `/opt/vuln-reporting/` paths — it must change.**

Current `deploy/vuln-reports.service` has:

```ini
WorkingDirectory=/opt/vuln-reporting
EnvironmentFile=/opt/vuln-reporting/.env
ExecStart=/opt/vuln-reporting/.venv/bin/python scheduler.py --mode daemon
ReadWritePaths=/opt/vuln-reporting/output /opt/vuln-reporting/logs /opt/vuln-reporting/data/cache
```

After the symlink layout is introduced:

```
/opt/vuln-reporting/
├── current -> releases/v1.2.0/    # symlink — active code
├── releases/
│   └── v1.2.0/                    # extracted slim tarball
│       ├── run_all.py
│       ├── scheduler.py
│       ├── .venv/                 # venv lives per-release
│       ├── .env -> ../../shared/.env
│       ├── delivery_config.yaml -> ../../shared/delivery_config.yaml
│       ├── logs -> ../../shared/logs/
│       ├── output -> ../../shared/output/
│       └── data/cache -> ../../shared/data/cache/
└── shared/
    ├── .env
    ├── delivery_config.yaml
    ├── logs/
    ├── output/
    └── data/cache/
```

**Required changes to `deploy/vuln-reports.service`:**

```ini
WorkingDirectory=/opt/vuln-reporting/current
EnvironmentFile=/opt/vuln-reporting/shared/.env
ExecStart=/opt/vuln-reporting/current/.venv/bin/python scheduler.py --mode daemon
ReadWritePaths=/opt/vuln-reporting/shared/output /opt/vuln-reporting/shared/logs /opt/vuln-reporting/shared/data/cache
```

Key decisions:
- `WorkingDirectory` points at `current` (the symlink). systemd resolves symlinks for `WorkingDirectory`, so after a `current` swap + `systemctl restart`, the new release directory is used.
- `EnvironmentFile` points at `shared/.env` directly — not through `current` — because the env file must survive upgrades and the path must be stable for `systemctl daemon-reload`-free restarts.
- `ReadWritePaths` points at `shared/` subtrees because those are the real filesystem locations. The symlinks inside the release directory point back to `shared/`, but `ReadWritePaths` operates on real paths.
- The `.venv` lives inside each release directory (not shared) so dependency upgrades between versions are isolated. The update script creates the venv and installs `requirements.txt` as part of the release extraction step.

**`Documentation=` line** currently references `file:///opt/vuln-reporting/RUNBOOK.MD`. After layout change, this becomes `file:///opt/vuln-reporting/current/RUNBOOK.MD` or is simply removed (RUNBOOK.MD is `export-ignore`d from the tarball, so it won't be in the release directory).

---

### 3. `data/cache/` in the Symlink Scheme

**The correct granularity is `data/cache/` as the symlinked subpath — not `data/` itself.**

The reason: `data/` contains `data/fetchers.py` and `data/trend/`, which are **code and persistent state** respectively. `data/fetchers.py` is runtime code from the release tarball. `data/trend/` holds month-over-month JSON snapshots for `management_summary` that must survive upgrades (same as `logs/` and `output/`).

Breaking this down:

| Path | Where it lives | Survives upgrade? |
|------|---------------|-------------------|
| `data/fetchers.py` | Inside release tarball | No — replaced on upgrade (correct) |
| `data/__init__.py` | Inside release tarball | No — replaced on upgrade (correct) |
| `data/cache/` | `shared/data/cache/` symlinked in | Yes — pre-warmed parquet files valid all day |
| `data/trend/` | `shared/data/trend/` symlinked in | Yes — historical trend snapshots |

**Symlink structure inside each release directory:**

```
releases/v1.2.0/data/
├── __init__.py          # from tarball
├── fetchers.py          # from tarball
├── cache -> ../../../shared/data/cache/    # symlink
└── trend -> ../../../shared/data/trend/   # symlink
```

**`update_from_github.sh` must create these symlinks** after extracting the tarball:

```bash
ln -sfn /opt/vuln-reporting/shared/data/cache  /opt/vuln-reporting/releases/vX.Y.Z/data/cache
ln -sfn /opt/vuln-reporting/shared/data/trend  /opt/vuln-reporting/releases/vX.Y.Z/data/trend
```

**`config.py` path derivation:** `CACHE_DIR` in `config.py` is currently derived relative to the project root. After the symlink layout, `data/cache` resolves through the symlink to `shared/data/cache/`. Python's `Path(__file__).resolve().parent` in `config.py` resolves the real path, but the symlinked `data/cache` subdir will resolve correctly because Python path traversal follows symlinks at each component. No change to `config.py` is required.

**The `warm_cache.py` implication:** `warm_cache.py` running from `/opt/vuln-reporting/current/` will derive `cache_dir` using `config.CACHE_DIR`, which resolves through the `data/cache` symlink to `shared/data/cache/YYYY-MM-DD/`. When `run_all.py` subsequently runs from the same `current/`, it derives the identical path. Cache sharing works transparently.

---

### 4. Dependency Graph Between New Components

```
.gitattributes
    └── must be correct BEFORE first tag is pushed
            └── .github/workflows/release.yml
                    └── produces release tarball assets on GitHub
                            └── update_from_github.sh --version vX.Y.Z
                                    └── (consumes tarball, extracts, symlinks shared/, validates, swaps current)
                                            └── deploy/vuln-reports.service (updated to use current/)
                                                    └── scripts/warm_cache.py (runs from current/, writes to shared/data/cache/)
```

Linear dependency chain with one branch:

**Hard sequential dependencies:**
1. `.gitattributes` must exist and be correct before any tag is pushed. A tag pushed without `export-ignore` rules bakes the wrong file list into the release artifact permanently.
2. `.github/workflows/release.yml` depends on `.gitattributes` being correct (the workflow uses `git archive` or relies on GitHub's auto-generated tarball which respects `export-ignore`).
3. A working release tarball on GitHub must exist before `update_from_github.sh --version` can be tested end-to-end.
4. `deploy/vuln-reports.service` must be updated before the first real deployment using the symlink layout — the old hardcoded paths will break as soon as `current/` is introduced.

**Independent (can be built in parallel once `.gitattributes` exists):**
- `scripts/warm_cache.py` depends only on `data/fetchers.py` and `tenable_client.py` — both exist now. It can be built and tested locally without the release/symlink infrastructure.
- `update_from_github.sh` can be written and dry-run tested on a scratch directory before a real release exists.

**`scripts/` export-ignore decision is a blocker:** The footprint todo flags `scripts/` as "mixed — audit before excluding wholesale". `warm_cache.py` is a runtime utility (needed on the server); `setup_github_labels.py` is dev-only. The `.gitattributes` decision for `scripts/` must be made before cutting the first real release tarball. Options: exclude `scripts/setup_github_labels.py` individually, or keep all of `scripts/` in the tarball (it's small). Recommend: keep `scripts/` in the tarball (the warm cache job needs to ship to the server), exclude `scripts/setup_github_labels.py` individually.

---

### 5. Recommended Build Order

**Phase 1 — Foundations (unblocks everything downstream)**

Build `.gitattributes` first. Every subsequent component depends on the tarball being correct. Audit `scripts/` per-file before writing the file. Also update `deploy/vuln-reports.service` to use `current/` paths in this phase — it ships in the tarball and must be correct from the first real release.

Files in this phase:
- `.gitattributes` (new)
- `deploy/vuln-reports.service` (edit — `WorkingDirectory`, `EnvironmentFile`, `ExecStart`, `ReadWritePaths`, `Documentation`)

**Phase 2 — `scripts/warm_cache.py` (independent, immediate server value)**

Can be built and tested now against the existing live install without any symlink layout changes. The fetcher seam is already correct. This is the highest-value deliverable for reducing report run latency and can be validated immediately.

Files in this phase:
- `scripts/warm_cache.py` (new)
- `scripts/__init__.py` (new — makes `scripts/` a package for `python -m scripts.warm_cache`)

**Phase 3 — Release workflow**

`.github/workflows/release.yml` + verification pass (local `git archive` preview to confirm excluded paths).

Files in this phase:
- `.github/workflows/release.yml` (new)

**Phase 4 — `update_from_github.sh` + symlink layout**

Requires a real release artifact on GitHub to test the download path end-to-end. Introduce the `/opt/vuln-reporting/{current, releases/, shared/}` layout. The script performs: download → verify checksum → extract → create venv → install deps → symlink `shared/` entries → `python run_all.py --dry-run` → swap `current` → write `.last` breadcrumb → restart unit.

Files in this phase:
- `scripts/update_from_github.sh` (new)
- `deploy/crontab.example` (new)

**Phase 5 — Documentation**

RUNBOOK additions, user-facing README, DEPLOYMENT.md.

Files in this phase:
- `RUNBOOK.MD` (edit — add "Operational cron schedule" + "Updating from GitHub" sections)
- `README.md` (new — user-facing what/who/quickstart + deployment section)
- `DEPLOYMENT.md` (new — operator-focused, references `update_from_github.sh` and on-disk layout)

---

## Complete New vs. Modified File List

### New files

| Path | Description |
|------|-------------|
| `.gitattributes` | Line-ending normalization + `export-ignore` for dev-only paths |
| `scripts/warm_cache.py` | Standalone cache warm entry point; calls `fetch_all_vulnerabilities` + `fetch_all_assets` directly |
| `scripts/__init__.py` | Makes `scripts/` a Python package for `-m scripts.warm_cache` invocation |
| `.github/workflows/release.yml` | Triggered on `v*` tag push and `workflow_dispatch`; builds slim tarball via `git archive`, uploads as release asset |
| `scripts/update_from_github.sh` | POSIX shell; `--check` / `--version` / `--rollback` / `--list` modes; manages `/opt/vuln-reporting/{current,releases/,shared/}` layout |
| `deploy/crontab.example` | Example cron lines: warm cache pre-run, `scheduler.py --mode run-due` every 5 min, log rotation |
| `README.md` | User-facing root README (what/who/quickstart/deployment) — none exists yet |
| `DEPLOYMENT.md` | Operator-focused install + update guide; on-disk layout diagram; references `update_from_github.sh` |

### Modified files

| Path | What changes |
|------|-------------|
| `deploy/vuln-reports.service` | `WorkingDirectory` → `current/`, `EnvironmentFile` → `shared/.env`, `ExecStart` → `current/.venv/...`, `ReadWritePaths` → `shared/` subtrees, `Documentation` line updated |
| `RUNBOOK.MD` | Add "Operational cron schedule" section + "Updating from GitHub" section with on-disk layout diagram |

### No changes needed

| Path | Reason |
|------|--------|
| `run_all.py` | Pre-fetch block already calls `fetch_all_vulnerabilities` / `fetch_all_assets` directly; warm cache populates the same parquet files; no change required |
| `data/fetchers.py` | Cache contract (`_cache_path` / `_load_cache` / `_save_cache`) is the correct seam; `warm_cache.py` imports these functions, not the other way around |
| `config.py` | `CACHE_DIR` / `LOG_DIR` path derivation works correctly through symlinks; no change needed |
| `scheduler.py` | No changes; delegates to `run_group()` in `run_all.py` unchanged |
| All report scripts | No changes; symlink layout is transparent to Python code above the `data/cache/` level |

---

## Architectural Constraints for New Components

### `warm_cache.py` must follow existing patterns

- Use `logging.getLogger(__name__)` with a `RotatingFileHandler` on `LOG_DIR / "warm_cache.log"` — identical pattern to `scheduler.py`'s `logs/scheduler.log`.
- `tenable_client.get_client()` is the only path to a Tenable connection — do not construct `TenableIO` directly.
- Exit code 0 on success, non-zero on auth failure or API error (cron emits mail on non-zero exit).
- `if __name__ == "__main__": argparse` block required per project convention.
- Type hints and docstrings throughout per `.planning/codebase/CONVENTIONS.md`.

### `update_from_github.sh` atomicity requirement

The `current` symlink swap must be atomic. POSIX `ln -sfn target linkname` is not atomic. Use `ln -s target /opt/vuln-reporting/current.tmp && mv -T /opt/vuln-reporting/current.tmp /opt/vuln-reporting/current` (two-step via `mv -T` on Linux) to ensure the live symlink is never in a broken intermediate state. The systemd unit reads `WorkingDirectory=/opt/vuln-reporting/current` at job start, so a swap between a job firing and it starting could pick up the wrong version — `systemctl restart` after the swap is the correct serialization point.

### `.gitattributes` `scripts/` decision

`scripts/warm_cache.py` must ship in the release tarball (it runs on the server). `scripts/setup_github_labels.py` (dev-only) should be excluded individually. Recommended `.gitattributes` entry:

```gitattributes
scripts/setup_github_labels.py  export-ignore
```

Do not blanket-exclude `scripts/` — that would omit `warm_cache.py` and `update_from_github.sh` from the release.

### `update_from_github.sh` must not symlink `.env` into the release

`.env` must live only in `shared/` and be symlinked from there. The script symlinks `shared/.env` into each release directory. It must never write or create `.env` itself — credential handling is operator-only.

---

## Data Flow: Post-v1.2 Operational Sequence

```
06:15 UTC    cron: python -m scripts.warm_cache --prune-stale
                   → GET /v1/exports/vulns + /v1/exports/assets (Tenable API)
                   → writes shared/data/cache/YYYY-MM-DD/vulns_all.parquet
                   → writes shared/data/cache/YYYY-MM-DD/assets_all.parquet
                   → exit 0

07:00 UTC    cron: python scheduler.py --mode run-due
                   → run_group("Executive Team")
                     → pre-fetch: fetch_all_vulnerabilities() → [CACHE HIT]
                     → pre-fetch: fetch_all_assets()          → [CACHE HIT]
                     → run board_summary, trend_analysis ...
                     → send_report_email(...)

(operator, on demand)
             update_from_github.sh --check
             → prints "latest: v1.3.0  installed: v1.2.0"

             update_from_github.sh --version v1.3.0
             → download + verify tarball
             → extract to releases/v1.3.0/
             → create .venv, pip install -r requirements.txt
             → ln -s shared/.env, shared/delivery_config.yaml, shared/logs, shared/output, shared/data/cache, shared/data/trend
             → python run_all.py --dry-run   (validation gate)
             → mv -T current.tmp current      (atomic symlink swap)
             → echo "releases/v1.2.0" > releases/.last
             → systemctl restart vuln-reports
             → prints rollback one-liner
```

---

## Anti-Patterns to Avoid

### Extracting a `_warm_cache()` helper from `run_all.py`

Do not create a shared helper in `run_all.py` that both the main script and `warm_cache.py` call. `run_all.py`'s pre-fetch block is two function calls to `data.fetchers` — the fetcher module is already the shared library. Adding a helper to `run_all.py` would create an import dependency from `scripts/warm_cache.py` into `run_all.py`, which imports `delivery`, `reports.*`, and the full module registry on import. `warm_cache.py` has no need for any of that.

### Symlinking `data/` wholesale

Do not symlink the entire `data/` directory into `shared/`. `data/fetchers.py` is release code — it should be replaced on upgrade, not persisted. Only `data/cache/` and `data/trend/` are persistent state. Symlinking `data/` wholesale would freeze `fetchers.py` at the version of the last release that created the `shared/data/` directory, defeating the purpose of upgrades.

### Hardcoding `/opt/vuln-reporting/` in `warm_cache.py`

Use `config.CACHE_DIR` and `config.LOG_DIR`. These are derived from `Path(__file__).resolve().parent` in `config.py`, which resolves to the actual release directory. This keeps the script relocatable (useful for local dev and staging runs) and avoids embedding deployment-specific paths in source code.

### Pushing a tag before verifying `.gitattributes`

Run `git archive --format=tar.gz --prefix=vuln-reporting/ HEAD -o /tmp/preview.tar.gz && tar -tzf /tmp/preview.tar.gz | sort` and confirm `.planning/`, `docs/`, `tests/`, `CLAUDE.md`, `RUNBOOK.MD` are absent before pushing the first `v*` tag. A wrong tarball is immutable on GitHub and cannot be corrected without deleting and re-creating the release.

---

*Architecture analysis: 2026-05-19*
