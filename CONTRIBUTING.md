# Contributing to vuln-reporting

Thanks for considering a contribution. This project follows an **issue-first** workflow with explicit approval gates so reviewer time and operator stability stay protected. Please read this document end-to-end before opening an issue or PR.

---

## The issue-first rule

**Every PR must reference an approved issue.** No exceptions. PRs without a linked issue, or with an issue that has not yet passed its approval gate, are auto-flagged by the triage workflow and may be closed.

The flow looks like this:

```
Idea / problem
    ↓
Open an issue (using the right template)
    ↓
Maintainer triage → gate label applied
    ↓
Open a PR (using the matching PR template, with `Closes #N` / `Fixes #N`)
    ↓
Review → CI → merge
```

The four issue types and their gate labels:

| Issue type | Template | Default labels | Gate label (required before PR) |
| ---------- | -------- | -------------- | ------------------------------- |
| Feature request | `feature_request.yml` | `feature-request`, `needs-review` | `approved-feature` |
| Enhancement | `enhancement.yml` | `enhancement`, `needs-review` | `approved-enhancement` |
| Bug report | `bug_report.yml` | `bug`, `needs-triage` | `confirmed-bug` |
| Chore | `chore.yml` | `type: chore`, `needs-triage` | `approved` (informal; chores often skip strict gating) |

**Why this gate exists:** small repos burn out fast when speculative PRs accumulate. Filing an issue first lets the maintainer say "yes, this is in scope" *before* anyone writes code. A PR closed for being out-of-scope is wasted effort for both sides.

---

## Picking the right issue template

Choose by **what the work changes**, not by how big it is:

- **Net-new capability** (a new report slug, a new metric module, a new delivery channel) → **Feature Request**.
- **Change to behavior of something that already exists** (different output, schema tweak, refactored CLI) → **Enhancement**.
- **Defect / crash / wrong output / regression** → **Bug Report**.
- **No user-visible change at all** (refactor, dep upgrade, doc edit, CI fix, dead-code cleanup) → **Chore**.

If you're not sure, default to Enhancement and let the maintainer reclassify during triage.

---

## PII and data-sensitivity rules

This project handles vulnerability and asset data. **Real data must never appear in issues, PRs, commits, tests, fixtures, or screenshots.** Specifically:

- **No real hostnames, FQDNs, IP addresses, MAC addresses, asset UUIDs, or finding IDs.** Use the example payloads in `docs/example_vulnerability_api_response_200.json` and `ref/` as a redaction style guide.
- **No real CVE-specific plugin output text** that could identify a particular customer environment.
- **No SMTP credentials, Tenable access/secret keys, or cloud connector credentials** — even partial.
- **No real `delivery_config.yaml`, no real cache parquet files, no real generated PDF/XLSX.**

The bug-report template's PII checklist is enforced — incomplete confirmations are auto-closed.

---

## Pull request requirements

### Template

Every PR must use a typed template (`feature.md`, `enhancement.md`, or `fix.md`) — **not** the default. Templates live in `.github/PULL_REQUEST_TEMPLATE/`. When opening a PR, append `?template=feature.md` (or `enhancement.md` / `fix.md`) to the new-PR URL, or use `gh pr create` with the appropriate template.

### Linkage

Use the GitHub keyword form so the issue closes on merge:

- Feature PR: `Closes #NN`
- Enhancement PR: `Closes #NN`
- Fix PR: `Fixes #NN`

### Scope

One concern per PR. Don't bundle a feature with a refactor, or a bug fix with an unrelated cleanup. Split into separate PRs and link them.

### Tested platforms

The project supports Windows, Linux, and macOS for development and Linux for production scheduling. Test on whichever platform you have available and **check only the boxes you actually tested** in the PR checklist. Honest gaps are fine; false claims are not.

### Title style

```
<type>(<area>): <one-line summary in imperative mood>
```

Examples:

- `feat(board_summary): add external-facing priority module`
- `fix(scheduler): handle midnight cache crossover correctly`
- `docs(roadmap): add pyTenable upgrade backlog entry`
- `chore(deps): bump pandas to 2.3.0`

`<type>` matches the PR template: `feat` / `enhancement` / `fix` / `chore` / `docs` / `refactor` / `test` / `ci`.

### Commit style

- Commit messages should explain **why**, not what — the diff already shows what.
- Atomic commits are preferred: one logical change per commit so `git revert` is surgical.
- Never use `--no-verify`, `--no-gpg-sign`, or skip pre-commit hooks. Fix the underlying problem instead.
- Co-author trailer for AI-assisted commits should be honest — credit the actual tool involved.

### CHANGELOG

Update `CHANGELOG.md` for every user-visible change (features, enhancements, fixes, breaking changes). Chores and pure-docs PRs may skip the CHANGELOG.

---

## What `/gsd-inbox` does on your contributions

This project uses the `/gsd-inbox` skill to triage incoming issues and PRs against the templates and gates documented here. When the maintainer runs it:

1. Every open issue is **scored** against its template's required fields (completeness percentage).
2. Every open PR is **checked** for: matching template, linked issue, correct gate label on the linked issue, completed PR checklist, CI status.
3. **Gate violations** (PR with no linked issue, or with an unapproved issue) are flagged prominently.
4. Issues scoring under 50% completeness, and PRs with gate violations, **may be auto-closed** with a comment pointing at this file.

If your issue or PR was auto-closed, fix the missing fields and open a new submission — auto-closed items are not reopened.

---

## Local development

Prerequisites:

- Python 3.10+ (currently tested on 3.10, 3.11, 3.12).
- A Tenable Vulnerability Management tenant with API keys for end-to-end validation. Many tests can run without it (smoke harness uses recorded fixtures).
- WeasyPrint requires platform-specific GTK / Pango libraries on Windows. See WeasyPrint docs for setup.

Setup:

```bash
python -m venv .venv
.venv/Scripts/activate    # Windows
# or
source .venv/bin/activate # macOS / Linux
pip install -r requirements.txt
cp .env.example .env       # then fill in your own credentials — never commit .env
```

Run the smoke suite before opening a PR:

```bash
python -m pytest -q
python scripts/smoke_board_summary_cutover.py
```

---

## Where to find context

- **What we're building and why:** [`README.md`](README.md), [`CLAUDE.md`](CLAUDE.md), `.planning/PROJECT.md`.
- **Project conventions** (naming, type hints, logging, datetime, pandas patterns): `.planning/codebase/CONVENTIONS.md`.
- **Architecture overview:** `.planning/codebase/ARCHITECTURE.md`.
- **Tenable field reference:** `docs/tenable_vuln_api_reference.md`, `docs/tenable_assets_api_reference.md`, `docs/tenable_compliance_api_reference.md`.
- **Glossary:** `docs/GLOSSARY.md`.

---

## Questions

For general help, setup questions, or "is this in scope?" conversations *before* filing an issue, use [Discussions](https://github.com/Just0xA/vuln-reporting/discussions).
