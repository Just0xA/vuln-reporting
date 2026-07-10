# Repository Restructuring Proposal

**Status:** Draft proposal (read-only — no moves performed)
**Drafted:** 2026-07-10
**Trigger:** Loose config files at the repo root surfaced during Phase 21; broader question of whether the layout needs a restructuring pass.
**Intended consumer:** A future GSD phase/milestone. This document seeds planning; it does not authorize any move.

---

## 1. TL;DR

The project is **more organized than it feels**. Core packages already live in `delivery/`, `exporters/`, `reports/`, `utils/`, `scripts/`, `docs/`, `deploy/`, `tests/`. The genuine clutter is narrow:

1. **Config files loose at root** (5 files) — the thing that triggered this.
2. **Docs split** between root and `docs/`.

A codebase-wide "big-bang" restructure is **the wrong shape for this repo** because an unusual amount of behavior is coupled to concrete file paths (security hook, module auto-discovery, deploy symlinks, `config.py` path anchors). Recommendation: **two contained, surgical passes** (config, then docs) executed as their own GSD phase(s), and **leave the core packages where they are**.

---

## 2. Current state

### Already well-placed (do NOT touch)
- Packages: `delivery/`, `exporters/`, `reports/` (+ `reports/modules/`), `utils/`
- `scripts/`, `docs/`, `deploy/`, `templates/`, `tests/`, `data/`
- Root entry points / core modules: `config.py`, `run_all.py`, `scheduler.py`, `tenable_client.py` — top-level is a normal home for these.

### Actual clutter
- **Config at root (5):** `contacts.yaml`, `contacts.example.yaml`, `delivery_config.yaml`, `delivery_config.example.yaml`, `delivery_config.schema.yaml`
- **Docs split:** root holds `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `DEPLOYMENT.md`, `RUNBOOK.md`; `docs/` holds calculation runbooks + API references. `README`/`CLAUDE`/`CONTRIBUTING` conventionally stay at root; `DEPLOYMENT`/`RUNBOOK` are the ambiguous ones.

---

## 3. Guiding principles

1. **Incremental, never big-bang.** Each pass is independently shippable, testable, and revertible.
2. **`git mv` only** — preserve blame/history (the team has already done two history scrubs; history is sensitive).
3. **Move + update-coupling in one atomic change.** A move and the path references it breaks land in the same commit, never separately.
4. **Leave path-coupled core alone unless the payoff is large.** Navigability gains do not justify a 130-import-site rewrite.
5. **Do it under GSD**, not ad hoc — this is precisely the high-blast-radius work the planning workflow de-risks.

---

## 4. Landmine register (why this repo punishes moves)

| Coupling point | Location | What breaks if you move naively |
|---|---|---|
| **Security hook path match** | `.claude/hooks/block_tenable_fetch.py` (+ `tests/test_block_tenable_fetch.py`) | Guards by path/basename: `run_all.py`, `tenable_client.py`, `utils/tag_helper.py`, `data/fetchers.py`, `scripts/warm_cache.py`, `capture_trend_snapshot.py`, `backfill_trend_reconstruction.py`, `probe_last_fixed_filter.py`. Moving any = hook fails open (dangerous) or blocks wrong target. |
| **Module auto-discovery** | `reports/modules/registry.py` | Globs `*_module.py` / `*_metrics.py` inside `reports/modules/`. Location + filename suffix both load-bearing. |
| **Package-root imports** | repo-wide | `reports.` (69 files), `utils.` (47), `delivery.` (11), `exporters.` (8), `import config` (7), `import tenable_client` (2). Relocating a package under a new root touches all of these. |
| **`config.py` path anchors** | `config.py` | `ROOT_DIR = Path(__file__).parent`; `LOG_DIR`, `OUTPUT_DIR`, `CACHE_DIR`, `LOGO_PATH` all derive from it. Move `config.py` and every derived path silently shifts. |
| **Deploy symlinks** | `scripts/update_from_github.sh` `symlink_shared()` | Names files: `.env`, `delivery_config.yaml`, `logs`, `output`, `data/cache`, `data/trend` (+ planned `shared/config/`). |
| **Release scan / tarball** | `.github/workflows/release.yml` | Forbidden-path + credential scans keyed on paths; slim-tarball contents. |
| **Ops surface** | systemd unit, `crontab.example`, `RUNBOOK.md` layout diagrams | Reference concrete paths. |
| **`.gitignore`** | `.gitignore` | Path-specific rules (`delivery_config.yaml`, `/contacts.yaml`, `/deliveries.d/`, `output/`, `logs/`, `data/cache/`). |

---

## 5. Proposed target structure

```
vuln-reporting/
├── config/                       # NEW — all delivery config lives here
│   ├── delivery_config.schema.yaml
│   ├── delivery_config.example.yaml
│   ├── contacts.example.yaml
│   ├── contacts.yaml             # gitignored (real/local)
│   ├── delivery_config.yaml      # gitignored (legacy fallback)
│   └── deliveries.d/             # gitignored (real/local team files)
├── docs/
│   ├── operations/               # NEW — DEPLOYMENT.md, RUNBOOK.md move here
│   └── … (existing calculation runbooks + API refs)
├── config.py  run_all.py  scheduler.py  tenable_client.py   # UNCHANGED at root
├── delivery/ exporters/ reports/ utils/ scripts/ deploy/ templates/ tests/ data/
├── README.md  CLAUDE.md  CONTRIBUTING.md                    # stay at root (convention)
└── …
```

Deliberately **not** proposing a `src/` package root — see §7.

---

## 6. Risk-ranked move map

### Tier 1 — Config consolidation → `config/`  (contained, high value)
**Why safe-ish:** the loader core is *already directory-agnostic* — `resolve_config()` derives `config_dir = config_path.parent`, and `tests/fixtures/phase20_config_twin/` proves config resolves from a subdirectory **today**. Only the CLI entry points hardcode root.

**Moves:** the 5 config files + a `config/deliveries.d/` home.

**Must update in the same change:**
- `run_all.py`: `main()` calls `_load_config()` with no arg (defaults to `ROOT_DIR/delivery_config.yaml`); `_dry_run` and `_SCHEMA_PATH` hardcode `ROOT_DIR/…`. Add a `--config-dir` flag (default `config/`) threaded into `_load_config`, `_select_config_source`, `_dry_run`, and the schema path. **This is the enabling change — do it first.**
- `.gitignore`: repoint `/contacts.yaml`, `/deliveries.d/`, `delivery_config.yaml` → `config/…` (keep root-anchored so `tests/fixtures/` twins stay tracked).
- `scripts/update_from_github.sh`: `symlink_shared()` — repoint the `delivery_config.yaml` symlink and the planned `shared/config/` entry.
- `RUNBOOK.md`: layout diagram + the Phase 21 cutover section (`shared/config/` already referenced there — reconcile).
- `delivery_config.example.yaml` / `.schema.yaml` references in docs + `_VALID_REPORTS`-adjacent comments.

**Verify:** `python run_all.py --dry-run` reports directory-mode and validates; `tests/test_config_loader.py`, `tests/test_dry_run_surfacing.py`, and the QUAL-06 golden test all pass; hook test unaffected.

**Interlocks with Phase 21:** the 21-04 RUNBOOK already targets a server-side `shared/config/`. Landing the `--config-dir` flag makes local layout match prod instead of relying on the root symlink trick. Sequence this **after Phase 21 closes** to avoid churning the open cutover.

### Tier 2 — Docs convention → `docs/operations/`  (low coupling, mechanical)
**Moves:** `DEPLOYMENT.md`, `RUNBOOK.md` → `docs/operations/`. Keep `README`/`CLAUDE`/`CONTRIBUTING` at root.
**Must update:** cross-links in `CLAUDE.md` (it names `DEPLOYMENT.md`/`RUNBOOK.md`), `README.md`, `deploy/` references, and any `docs/*` indexes. `git grep -n 'RUNBOOK.md\|DEPLOYMENT.md'` to enumerate.
**Verify:** no dead relative links (`git grep` + a link check); GSD `.planning` references are cosmetic (stale line refs), fix opportunistically.

### Tier 3 — Core package relocation (e.g., `src/`)  — RECOMMEND: DO NOT
**Cost:** ~130+ import-site edits, `config.py` `ROOT_DIR` re-anchoring, the full security-hook guarded list + its test, module auto-discovery base path, deploy symlinks, release scan, systemd/cron. **Reward:** marginal.
**Verdict:** out of scope. If ever revisited, it is its own milestone with a dedicated risk plan — not part of a "tidy the root" pass.

---

## 7. Non-goals
- No `src/` layout / core-package relocation (Tier 3 rejected above).
- No renaming of internal `group` identifiers (already Out-of-Scope from Phase 20/21).
- No change to module filename conventions (`*_module.py` is load-bearing).
- No history rewrite; `git mv` preserves lineage.

---

## 8. Recommended sequencing
1. **Close Phase 21 first** (it owns the config/cutover surface; don't churn it mid-flight).
2. **GSD phase: "Config consolidation"** — Tier 1. Ship the `--config-dir` flag + move + coupling updates atomically.
3. **GSD phase (or quick): "Docs convention"** — Tier 2. Mechanical, low risk.
4. Tier 3 stays parked unless a concrete driver appears.

**Backlog one-liner:** *RESTRUCTURE-01 — Consolidate delivery config into `config/` (add `run_all.py --config-dir`, repoint gitignore/deploy-symlinks/RUNBOOK); then move DEPLOYMENT/RUNBOOK under `docs/operations/`. Core packages stay put. See `.planning/restructuring-proposal.md`.*
