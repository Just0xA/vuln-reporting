# Phase 21: Private Config Repo + CI + CODEOWNERS + Production Cutover - Pattern Map

**Mapped:** 2026-07-09
**Files analyzed:** 6 (1 modified in public repo, 4 new in a SEPARATE private corporate repo, 1 doc update)
**Analogs found:** 6 / 6

> **Repo-boundary note (read first).** Only ONE file in this phase is edited in the public
> `vuln-reporting` app repo: `run_all.py` (D-04 fallback + D-05 source logging) — plus a doc
> touch (`RUNBOOK.md`). Every other artifact (CI workflow, CODEOWNERS, `contacts.yaml` +
> `deliveries.d/` config tree) is a **new file that lives in the private corporate config repo**,
> NOT in this repo. For those, the analog below supplies the *shape to copy*; the planner must
> emit them as private-repo deliverables (or as committed `*.example` templates), never as real
> config committed here (Hard Rule 2, D-02).

---

## File Classification

| New/Modified File | Repo | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|------|-----------|----------------|---------------|
| `run_all.py` (`_load_config`, `_dry_run`) | public (modify) | config-loader | transform / request-response | itself (Phase 20 loader) — in-place extension | exact (self) |
| `.github/workflows/ci.yml` (config-repo CI gate) | **private (new)** | config / CI | batch / request-response | `.github/workflows/release.yml` | role-match (CI) |
| `CODEOWNERS` (config-repo governance) | **private (new)** | config / governance | event-driven (PR review) | none in repo | no analog |
| `contacts.yaml` + `deliveries.d/<team>.yaml` (config tree) | **private (new)** | config | transform | `contacts.example.yaml` + `tests/fixtures/phase20_config_twin/deliveries.d/*.yaml` | exact (shape) |
| CI matrix-artifact publish step | **private (new)**, in ci.yml | config / CI | batch | `scripts/generate_delivery_matrix.py` (invoked as-is) | exact (reuse) |
| `RUNBOOK.md` (cutover runbook + safe-to-edit table) | public (modify) | docs | n/a | `RUNBOOK.md` §"Project layout" + §"Files safe to edit" | exact (self) |

---

## Pattern Assignments

### `run_all.py` — `_load_config()` D-04 automatic dual-source fallback (config-loader, transform)

**Analog:** `run_all.py:157-236` (the Phase 20 loader — extend in place, do not rewrite).

**Current structure (what exists, `run_all.py:176-204`):** directory presence is the mode switch;
on ANY directory-mode error the function currently `return []` (hard fail — no fallback yet):

```python
if config_path is None:
    config_path = ROOT_DIR / "delivery_config.yaml"

if (config_path.parent / "deliveries.d").is_dir():
    groups, load_errors, load_warnings, _metadata = resolve_config(config_path)
    for warning in load_warnings:
        logger.warning("delivery config: %s", warning)
    if load_errors:
        for err in load_errors:
            logger.error("delivery config: %s", err)
        return []          # <-- D-04 changes THIS: fall back to legacy instead of returning []
    # ... schema gate ...
    logger.debug("Loaded %d delivery(ies) from deliveries.d/", len(groups))
    return groups          # <-- directory-mode success

if not config_path.exists():
    logger.error("delivery_config.yaml not found at %s", config_path)
    return []
# ... legacy single-file parse + schema gate (lines 206-236) ...
```

**D-04 change to copy:** when directory mode is present but `resolve_config` returns `load_errors`
OR the resolved config fails the schema gate, the loader must **fall through to the legacy
single-file branch** (lines 202-236) instead of `return []`, and emit a `logger.warning` naming the
active source. The legacy-parse code block already exists below — the change is to reach it, not
to duplicate it. Preserve the existing directory-mode success path unchanged.

**Active-source logging pattern to copy (D-05).** Use the existing `logger.warning`/`logger.debug`
idiom already in this function (`run_all.py:182, 199`). Emit exactly one line naming the winning
source, e.g. `logger.warning("delivery config: directory-mode config failed to resolve; falling back to legacy single file %s", config_path)` on fallback, and an INFO/DEBUG line naming the active
source on the success paths. **Return-shape contract is unchanged** — still `list[dict]`; the
metadata 4th tuple element stays discarded (docstring `run_all.py:170-174`).

**Guard note (must not regress):** the current code short-circuits `return []` on directory-mode
error *before* checking `config_path.exists()`. The fallback must handle the case where the legacy
file is ALSO absent (true dual-source retirement) — then the existing `logger.error(... not
found ...)` + `return []` at lines 202-204 is the correct terminal state. Scheduler daemon
hot-reload calls `_load_config()` on every reload cycle (`code_context`), so the fallback must be
idempotent and side-effect-free — matches the existing pure-load contract.

---

### `run_all.py` — `_dry_run()` D-05 active-source surfacing (config-loader, request-response)

**Analog:** `run_all.py:430-544` (the Phase 20 `--dry-run`; this is the CI gate's engine, D-07).

**Directory-mode surfacing already present (`run_all.py:473-485`)** — copy this rich-console
idiom for the new active-source echo:

```python
if (config_path.parent / "deliveries.d").is_dir():
    _groups, errors, warnings, _meta = resolve_config(config_path)
    if warnings:
        console.print("\n[bold yellow]Config warnings:[/bold yellow]")
        for w in warnings:
            console.print(f"  [yellow]! {w}[/yellow]")
    if errors:
        any_errors = True
        console.print("\n[bold red]Config errors:[/bold red]")
        for e in errors:
            console.print(f"  [red]x {e}[/red]")
```

**D-05 change to copy:** add a single console line stating which source `_load_config()` actually
selected (directory-mode vs legacy-fallback), so the operator can confirm the repo-sourced path
delivered cleanly across a full dual-source cycle before retiring the legacy file. Follow the
existing `console.print("[bold ...]...[/...]")` rich-markup style. The dry-run already re-reads
config independently (`run_all.py:452-485`); the active-source line should reflect the SAME
selection logic `_load_config` used — factor the "which source won" decision so both call sites
agree (avoid divergent duplicate detection).

**Exit-code contract (unchanged, copy as-is):** `_dry_run` returns `0` all-valid / `1` any error
(`run_all.py:434, 541, 544`). D-07 depends on this: CI treats non-zero as merge-blocking.

---

### `.github/workflows/ci.yml` — config-repo CI gate (config/CI, batch) — **PRIVATE REPO, NEW**

**Analog for shape:** `.github/workflows/release.yml` (this public repo). Copy the workflow
skeleton, the `set -euo pipefail` step discipline, and the multi-step assert-then-fail pattern.
The config-repo CI does the INVERSE flow of release.yml: release.yml *builds+asserts+publishes* the
slim tarball; the config CI *fetches that pinned tarball, installs, and validates config against it*.

**Workflow skeleton to copy (`release.yml:1-28`):**

```yaml
name: Release
on:
  push:
    tags: [ 'v[0-9]*.[0-9]*.[0-9]*' ]
  workflow_dispatch:
    inputs: { version: { ... } }
permissions:
  contents: write        # config CI needs only: contents: read
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
```

For the config CI, `on:` becomes `pull_request:` (gate every PR, D-06/D-07), and permissions drop
to read.

**Pinned-tarball fetch (D-06) — mirror release.yml's asset naming.** release.yml publishes
`vuln-reporting-${VERSION}-slim.tar.gz` + a `.sha256` sidecar (`release.yml:56-70, 153-162`). The
config CI must fetch a PINNED `${VERSION}` of that asset (not `latest`), verify the sha256 sidecar
(the sidecar exists precisely so a downstream consumer can verify — reuse it), extract, and
`pip install -r requirements.txt`. Pin lives in a config-repo variable; bump when loader/schema
change (D-06).

**Assert-then-fail step discipline to copy (`release.yml:72-151`).** release.yml runs each check,
accumulates failures into arrays, and does a single final non-zero exit. Copy that structure for
the config gate's two checks:

```bash
set -euo pipefail
# 1. schema validation + 2. run_all.py --dry-run against the MERGED effective config
python run_all.py --dry-run    # exit non-zero blocks merge (D-07)
```

`--dry-run` is **pre-auth (Hard Rule 1)** — no Tenable/SMTP creds in CI. The dry-run's own
`_REQUIRED_ENV_VARS` check (`run_all.py:135-142, 441-447`) will flag missing env; the CI gate
targets **config** validity, so the planner must decide whether to stub those env vars or scope the
gate to config-only errors. Note: `_dry_run` currently returns `1` on missing env
(`run_all.py:442`), so CI must supply placeholder env or the gate fails on env, not config —
flag for planner.

**"Build carries no config" model (D-02) — copy the forbidden-path + credential-scan idea**
(`release.yml:92-151`). release.yml proves the tarball has no `.env`, no `.planning`, no config
leak. This is the guarantee D-02 leans on (the fetched tarball the config CI installs carries no
config, so CI validates the private repo's config against a clean loader). No change needed to
release.yml — cite it as the existing guarantee.

---

### `CODEOWNERS` — config-repo governance (config/governance, event-driven) — **PRIVATE REPO, NEW**

**Analog:** none in this codebase (no CODEOWNERS exists — confirmed by `find`). This is a
net-new artifact; use GitHub/GitLab CODEOWNERS syntax directly.

**Structure locked by D-08/D-09 (no code excerpt — spec):**
- Per-file entries, 1:1 with the `deliveries.d/<team>.yaml` split (D-08) — one line per team file,
  so per-team delegation can be turned on later without restructuring.
- **Every** owner entry currently resolves to the Vulnerability Management team (central
  stewardship, D-08) — the 1:1 structure is present but the roster is centralized now.
- The default `*` rule → VM team, covering the shared cross-cutting files `contacts.yaml`,
  `defaults`, and the schema copy (D-09).
- Concrete VCS handles / team names are a **provisioning input (D-10)** — the structure is locked
  now; usernames are filled at private-repo creation. Planner should emit CODEOWNERS with a clearly
  marked placeholder team handle (e.g. `@ORG/vuln-management-team`) and a comment noting D-10.

**Reconciliation flag (carry into plan):** ROADMAP SC2 literally says a PR "requires *that team's*
owner as a reviewer"; D-08 centralizes review to the VM team now. This is intentional — the 1:1
mapping that *enables* per-team ownership exists, but the roster resolves to VM. Document this in
the plan so the SC2 wording isn't read as unmet.

---

### `contacts.yaml` + `deliveries.d/<team>.yaml` — config tree (config, transform) — **PRIVATE REPO, NEW**

**Analog (exact shape):** `contacts.example.yaml` (this repo) for the `contacts.yaml` shape, and
`tests/fixtures/phase20_config_twin/deliveries.d/exec.yaml` + `contacts.yaml` for the team-file +
contacts shapes. These are the Phase 20 config language — the private repo holds the REAL twins of
these example/fixture files.

**`contacts.yaml` shape to copy (`contacts.example.yaml:18-41`):**

```yaml
contacts:
  exec_team:
    recipients: [ ciso@example.invalid, vp-it@example.invalid ]
    cc: [ security-team@example.invalid ]
    reply_to: security@example.invalid
  remediation_team:
    recipients: [ remediation@example.invalid ]
defaults:
  analyst_mailbox: analyst-team@example.invalid   # default Reply-To + standing Cc
```

**`deliveries.d/<team>.yaml` shape to copy (`tests/fixtures/phase20_config_twin/deliveries.d/exec.yaml`):**

```yaml
owner: exec-reporting-team          # feeds the matrix + (later) per-team CODEOWNERS delegation
deliveries:
  - name: "Executive Team"
    subject: "Weekly Vuln Management Summary — Production"
    contact: exec_team              # references contacts.yaml by name (never inline email:)
    schedule: { frequency: weekly, day_of_week: monday, time: "07:00" }
    filters: { tag_category: "Environment", tag_value: "Production" }
    reports: [ executive_kpi, trend_analysis ]
```

**Resolver contract the config tree must satisfy (`delivery/config_loader.py:176-233`).**
`resolve_config` returns errors on: missing `contacts.yaml` next to `deliveries.d/`; duplicate
delivery `name` across files; undefined `contact:` ref; inline `email:` in directory mode. The CI
gate (D-07) surfaces exactly these — so the private config tree is only valid when it resolves
cleanly and passes the unchanged `delivery_config.schema.yaml` gate.

**Hard Rule 2 (D-02):** these files hold REAL recipient addresses and live ONLY in the private
repo. The examples/fixtures above use `example.invalid` — the real files must never land in the
public repo. Any committed reference in THIS repo stays as `*.example`/fixture with
`example.invalid` domains.

---

### CI matrix-artifact publish step (config/CI, batch) — **PRIVATE REPO, in ci.yml, reuses this repo's script**

**Analog (reuse as-is):** `scripts/generate_delivery_matrix.py` (this repo, shipped in the slim
tarball). D-07 publishes the matrix as a PR review artifact.

**Invocation to copy (`generate_delivery_matrix.py:112-140, 250-273`):**

```bash
python scripts/generate_delivery_matrix.py --config <merged-config-path> \
    --format markdown --output delivery-matrix.md
# exit 0 success / 2 usage / 3 loader errors
```

Then upload `delivery-matrix.md` as a CI artifact. **PII invariant (D-07 / Hard Rule 2):** the
matrix emits contact/group NAMES + owner ONLY — never expanded recipient addresses
(`generate_delivery_matrix.py:5-10, 162-178`), sourced from the resolver's
`metadata_by_delivery_name` side channel. Safe to publish. No change to the script needed; the CI
step just invokes it against the merged config and uploads the output.

---

### `RUNBOOK.md` — cutover runbook + updated safe-to-edit table (docs)

**Analog:** `RUNBOOK.md` itself — §"Project layout (v1.2 symlink structure)" (`RUNBOOK.md:682-717`)
and §"Files safe to edit without developer involvement" (`RUNBOOK.md:721-729`).

**Table to update (`RUNBOOK.md:723-729`), current rows:**

```markdown
| File | What you can change |
| ---- | ------------------- |
| `shared/.env` | Add or rotate credentials; adjust `MAX_ATTACHMENT_SIZE_MB` |
| `shared/delivery_config.yaml` | Add/remove groups, change recipients, adjust schedules |
```

**Cutover change (D-01/D-03):** the `shared/delivery_config.yaml` row's "hand-edit over SSH"
guidance (`RUNBOOK.md:52, 62`: `sudo -u vuln-reports nano .../delivery_config.yaml`) must be
REPLACED by the reviewed-repo flow: edits happen in the private corporate repo → PR → CODEOWNERS
review → CI gate → merge → manual copy of the merged commit to the server. The table must reflect
that server-side hand-edits are no longer the documented path.

**Layout diagram to extend (`RUNBOOK.md:703-713`):** add the directory-mode config location under
`shared/` (`contacts.yaml` + `deliveries.d/`; exact server layout is Claude's discretion, e.g.
`shared/config/`, D-04-context). Note the dual-source coexistence during the cutover window (both
the new tree AND legacy `shared/delivery_config.yaml` present) and the provenance stamp / drift
check (D-03, mechanism at planner discretion).

**Transport model to keep (`scripts/update_from_github.sh:541-558`).** `symlink_shared()` links
`shared/delivery_config.yaml` into each release (`update_from_github.sh:551`). The cutover keeps
the manual corporate→server copy (D-01: server stays dumb, no outbound git/artifact fetch). If a
new `shared/config/` (or `contacts.yaml` + `deliveries.d/`) location is introduced, the planner
must decide whether `symlink_shared()` gains a symlink for it — flag this as a possible small
transport touch, consistent with the existing 6-symlink pattern.

---

## Shared Patterns

### Rich-console surfacing (fail-loud + `--dry-run`)
**Source:** `run_all.py:444-485` (`console.print("[bold red]...[/bold red]")` idiom).
**Apply to:** the D-05 active-source echo in `_dry_run`. Match the existing yellow-warning /
red-error markup; do not introduce a new logging style.

### Logger-line source naming
**Source:** `run_all.py:181-185, 199` (`logger.warning`/`logger.error`/`logger.debug` with a
`"delivery config: %s"` prefix).
**Apply to:** the D-04/D-05 active-source WARNING/INFO in `_load_config`. One line, names the source.

### Assert-then-single-exit CI discipline
**Source:** `release.yml:72-151` (accumulate failures, single final `exit 1`).
**Apply to:** the private-repo `ci.yml` schema + `--dry-run` gate. `set -euo pipefail` on every
`run:` step (`release.yml:33, 48, 58, 68, 74`).

### PII-safe published artifact
**Source:** `generate_delivery_matrix.py:5-10, 162-178` (names+owner from
`metadata_by_delivery_name`, never `email.recipients`).
**Apply to:** the CI PR matrix artifact. Hard Rule 2 — no addresses in any CI output.

### `example.invalid` synthetic-data convention
**Source:** `contacts.example.yaml:10-11`, all Phase 20 fixtures.
**Apply to:** any config sample committed to THIS repo. Real addresses live only in the private repo (D-02).

---

## No Analog Found

| File | Repo | Role | Data Flow | Reason |
|------|------|------|-----------|--------|
| `CODEOWNERS` | private (new) | governance | event-driven | No CODEOWNERS exists in this repo; net-new. Use GitHub/GitLab CODEOWNERS syntax; VM-team placeholder handle per D-10. |

The config-repo `ci.yml` and the `contacts.yaml`/`deliveries.d/` tree DO have analogs
(`release.yml` for CI shape; `contacts.example.yaml` + Phase 20 fixtures for config shape) — they
are "no analog" only in the sense that they live in a different (private) repo. Planner should
treat those analogs as the authoritative shape to copy.

---

## Conventions

Convention derivation via the shared `gsd-tools.cjs verify conventions --derive` module was
**skipped** (`reason: no-readable-files`) under both `--scope scripts` and repo-wide — the tool
could not read files in this sandbox. Falling back to the repo's documented conventions
(`.planning/codebase/CONVENTIONS.md`, `CLAUDE.md`):

| Axis | Dominant | Source of truth |
|------|----------|-----------------|
| Python file-name casing | `snake_case` (`generate_delivery_matrix.py`, `config_loader.py`) | observed across `scripts/`, `delivery/` |
| Python identifier casing | `snake_case` funcs/vars, `_leading_underscore` module-private, `UPPER_SNAKE` consts (`_REQUIRED_ENV_VARS`, `_VALID_REPORTS`) | `run_all.py`, `generate_delivery_matrix.py` |
| Config file-name casing | `snake_case.yaml` (`delivery_config.yaml`, `contacts.yaml`); team files under `deliveries.d/` are `<team>.yaml` | Phase 20 loader + fixtures |
| Docstring style | NumPy-style (Parameters/Returns) with type hints throughout | CLAUDE.md "Code Quality"; `resolve_config`, `_is_due` |
| Datetime | `datetime.now(tz=timezone.utc)` for report/log timestamps; server-local for schedule/cache | CLAUDE.md "Timezone policy"; `generate_delivery_matrix.py:104, 247` |
| Logging | `logging` + `RotatingFileHandler`, no silent failures, fail-soft batch | CLAUDE.md; `generate_delivery_matrix.py:52-77` |

**Contested hotspots (author's choice):** none derived (tool skipped). The one cross-language
split to respect is repo-boundary, not casing: the **public app repo** (Python, `snake_case`, NumPy
docstrings) versus the **private config repo** (YAML config + CI YAML + CODEOWNERS). Files authored
for the private repo follow YAML/CI conventions and this repo's config-language shape; they must
never carry real config into the public repo (Hard Rule 2 / D-02). Match each artifact's target-repo
local style: Python edits (`run_all.py`) follow the `snake_case`/NumPy-docstring norm; the new
config tree follows the Phase 20 `contacts.yaml` + `deliveries.d/<team>.yaml` shape.

---

## Metadata

**Analog search scope:** `run_all.py`, `delivery/config_loader.py`, `.github/workflows/`,
`scripts/generate_delivery_matrix.py`, `scripts/update_from_github.sh`, `delivery_config.schema.yaml`,
`contacts.example.yaml`, `tests/fixtures/phase20_config_twin/`, `RUNBOOK.md`.
**Files scanned:** 9.
**Convention derivation:** skipped (no-readable-files) — documented conventions used instead.
**Pattern extraction date:** 2026-07-09.
