# Phase 20: Config Language + Loader + Matrix - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-09
**Phase:** 20-config-language-loader-matrix
**Areas discussed:** Config source discovery, Matrix surface & PII, Golden parity test, New-key validation & warnings

**Framing note:** REQUIREMENTS.md already locks the resolve-before-validate architecture, the nothing-defined-twice guardrail, analyst_mailbox behavior (one knob, no opt-out), the rename scope boundary, and per-delivery filters. Discussion deliberately skipped those and focused only on genuinely-open HOW gaps.

---

## Config source discovery

### Mode selection
| Option | Description | Selected |
|--------|-------------|----------|
| Directory presence wins | deliveries.d/ exists → dir mode; else single-file fallback. No new flag. | ✓ |
| Explicit --config-dir flag | Operator/CI opts in via flag; default single-file. | |
| Error if both present | Refuse to load if single file AND deliveries.d/ both exist. | |

### contacts.yaml location
| Option | Description | Selected |
|--------|-------------|----------|
| Sibling, required in dir mode | contacts.yaml next to deliveries.d/, required in dir mode; missing → error. | ✓ |
| Sibling, optional | Optional; inline email: still allowed. | |
| You decide | Defer to planning. | |

### Delivery recipient refs (dir mode)
| Option | Description | Selected |
|--------|-------------|----------|
| contact: only (+ extra_recipients) | MUST use contact: ref; inline email.recipients rejected in dir mode. | ✓ |
| contact: or inline email: | Either form allowed (not both). | |
| You decide | Defer to planning. | |

**User's choice:** Directory presence wins; contacts.yaml required sibling; dir-mode deliveries use contact: only.
**Notes:** Enforces nothing-defined-twice at the loader level; legacy single-file mode retains inline email: for QUAL-07 backward compat.

---

## Matrix surface & PII

### Command surface
| Option | Description | Selected |
|--------|-------------|----------|
| Standalone script | scripts/generate_delivery_matrix.py (argparse), reuses resolver. | ✓ |
| run_all.py --matrix flag | Fold into master runner. | |
| You decide | Defer to planning. | |

### PII treatment
| Option | Description | Selected |
|--------|-------------|----------|
| Contact names + owner only | No expanded addresses; safe to publish as CI artifact. | ✓ |
| Expanded addresses, gitignored | Full recipient lists; treated as sensitive. | |
| You decide | Defer to planning. | |

### Output format
| Option | Description | Selected |
|--------|-------------|----------|
| Markdown default, HTML optional | md by default; --format html opt-in. | ✓ |
| Markdown only | Defer HTML. | |
| Both, always | Emit .md + .html every run. | |

**User's choice:** Standalone script; contact names + owner only; Markdown default with optional HTML.
**Notes:** PII choice aligns with Hard Rule 2 / QUAL-05 and the Phase 21 "published from CI on every merge" step.

---

## Golden parity test

### Comparison mechanism
| Option | Description | Selected |
|--------|-------------|----------|
| Committed JSON golden + equality | Normalize → committed golden JSON; legacy fixture byte-identical + migrated twin equal. | ✓ |
| In-memory equality only | Assert resolved legacy == resolved migrated; no committed file. | |
| You decide | Defer to planning. | |

### Fixtures
| Option | Description | Selected |
|--------|-------------|----------|
| Migrated twin of example config | Twin derived from delivery_config.example.yaml; proves identical resolution. | ✓ |
| Fresh minimal synthetic pair | Purpose-built fixture pair independent of example config. | |
| You decide | Defer to planning. | |

**User's choice:** Committed JSON golden with two-way equality; fixtures = migrated twin of delivery_config.example.yaml.
**Notes:** Synthetic example.invalid identifiers only (D-04-08). Twin keeps the example file as the living reference and exercises all current keys.

---

## New-key validation & warnings

### Pre-resolution validation mechanism
| Option | Description | Selected |
|--------|-------------|----------|
| Permissive Python checks | Programmatic checks in loader; no second schema. | ✓ |
| Dedicated source JSON schema | Second Draft7 schema for source keys. | |
| You decide | Defer to planning. | |

### Error/warning surfacing
| Option | Description | Selected |
|--------|-------------|----------|
| logger + surfaced in --dry-run | Deprecation → warning (keeps loading); hard errors → logger.error + non-zero exit; echoed in --dry-run. | ✓ |
| logger only | Everything to logs/app.log, no dry-run echo. | |
| You decide | Defer to planning. | |

**User's choice:** Permissive Python checks; logger + surfaced in --dry-run.
**Notes:** Matches the requirement's "validated separately/permissively before resolution" wording; existing schema still gates the resolved config. Surfacing extends run_all.py:166-198 fail-loud pattern and feeds the Phase 21 CI gate.

---

## Claude's Discretion

- Config-directory search path relative to the shared/ symlink layout in prod.
- JSON normalization details for the golden (key ordering, None/absent handling).
- Matrix Markdown column layout and HTML styling.
- Python module boundary for the new resolver (new module vs. extending run_all.py._load_config).

## Deferred Ideas

None — discussion stayed within phase scope. Per-team default filters / extends:, per-delivery SLA override, database/admin-UI config, and the Phase 21 private-repo/CI/CODEOWNERS/cutover work are already recorded as Out of Scope or Phase 21 in REQUIREMENTS.md.
