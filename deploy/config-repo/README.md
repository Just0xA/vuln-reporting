# Config Repo — Reference Templates

**These files are REFERENCE templates for the PRIVATE corporate delivery-config
repository. They are NOT active in this public `vuln-reporting` app repo** — no
real recipient addresses, team handles, or delivery config live here (Hard Rule
2 / D-02). The `.example` suffix on `ci.yml.example` marks it as a template to
be copied and adapted, not a live workflow.

## What's in this directory

| File | Purpose |
| ---- | ------- |
| `ci.yml.example` | Reference GitHub Actions workflow: gates every PR against the private config repo with schema validation + a config-only `run_all.py --dry-run`. |
| `CODEOWNERS.example` | Reference CODEOWNERS mapping (added by Plan 21-03) — 1:1 with the `deliveries.d/` split, centrally owned by the Vulnerability Management team. |

## Placement

At private-repo provisioning, copy these into the repo root:

- `ci.yml.example` → `.github/workflows/ci.yml` (or the equivalent GitLab CI
  file, if the private repo is hosted on GitLab instead — the CI host is an
  operator/D-10 provisioning choice; the gate logic in `ci.yml.example` is
  portable either way).
- `CODEOWNERS.example` → `CODEOWNERS` at the repo root.

The private repo itself then holds the real `contacts.yaml` +
`deliveries.d/<team>.yaml` config tree (the Phase 20 config language) — those
files never exist in this public repo, only their `*.example`/fixture twins
(`contacts.example.yaml`, `tests/fixtures/phase20_config_twin/`).

## The `PINNED_VERSION` pin

`ci.yml.example` fetches a **pinned** `vuln-reporting` slim release tarball —
never `latest` — and verifies its `.sha256` sidecar before extracting
(T-21-05). Set `PINNED_VERSION` to the release tag currently deployed to
production.

**Bump `PINNED_VERSION` whenever the config loader or schema changes** (D-06):
a new `delivery_config.schema.yaml` field, a new `resolve_config` validation
rule, or any change to `run_all.py`'s `--dry-run` behavior. Leaving the pin
stale means the gate validates PRs against an outdated loader that may accept
config the real deployed app would reject (or vice versa).

## Why the gate exports placeholder env

The gate is **pre-auth** (Hard Rule 1): it must never carry real Tenable or
SMTP credentials, and `run_all.py --dry-run` performs no live API call. But
`_dry_run()` fails closed if any of the six `_REQUIRED_ENV_VARS`
(`TVM_ACCESS_KEY`, `TVM_SECRET_KEY`, `SMTP_HOST`, `SMTP_USERNAME`,
`SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`) are unset — so without a stub, every PR
would fail on **missing credentials**, not on the config problem a reviewer
actually needs to see. `ci.yml.example` exports obviously-fake placeholder
values (e.g. `ci-placeholder`, `ci@example.invalid`) for exactly these six
vars so the env-presence check passes and the gate's non-zero exit means the
**config** is wrong.

## What the gate blocks

A non-zero `run_all.py --dry-run` exit blocks the merge. The gate catches:

- Duplicate delivery `name` values across `deliveries.d/*.yaml` files
- A `contact:` reference in a delivery file with no matching entry in
  `contacts.yaml`
- An inline `email:` block in a delivery file (directory mode requires a
  `contact:` reference instead — inline recipients are a legacy single-file
  pattern only)
- Any `delivery_config.schema.yaml` validation failure on the merged,
  resolved config

## The PR artifact

The gate's final step runs `scripts/generate_delivery_matrix.py --format
markdown` and uploads the result as a PR artifact named `delivery-matrix`.
This matrix lists **delivery names + owner only** — never expanded recipient
email addresses — so it is safe to attach to a PR for reviewer visibility
without leaking PII (Hard Rule 2).

## See also

Plan 21-04's cutover runbook documents the end-to-end flow this gate is part
of: edit in the private repo → open a PR → CODEOWNERS review → this CI gate
→ merge → manual copy of the merged commit to the production server (the
server itself stays dumb — no outbound git or artifact fetch, per D-01).
