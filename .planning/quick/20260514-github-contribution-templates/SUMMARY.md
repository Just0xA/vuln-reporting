---
slug: github-contribution-templates
date: 2026-05-14
type: quick
status: complete
---

# Summary

Scaffolded the `.github/` issue + PR templates and `CONTRIBUTING.md` required by the `/gsd-inbox` triage workflow.

## Files created

- `.github/ISSUE_TEMPLATE/config.yml` — disables blank issues, routes generic questions to Discussions.
- `.github/ISSUE_TEMPLATE/feature_request.yml` — net-new capability. 12 required fields including pre-submission checklist (no real customer data), feature name, addition type dropdown (report slug / metric module / delivery channel / fetcher / utility), problem, what-is-added, scope, ≥ 2 user stories, acceptance criteria, runtime / platform matrix (Windows/Linux/macOS × Python 3.10–3.13+), breaking changes, maintenance burden, alternatives. Auto-labels: `feature-request`, `needs-review`.
- `.github/ISSUE_TEMPLATE/enhancement.yml` — modifies existing behavior. Required: pre-submission, target name, current vs proposed behavior with concrete examples, reason/benefit, scope, breaking changes, alternatives, area-affected dropdown (12 options covering reports / modules / fetcher / cache / delivery / scheduler / chrome / Excel / config / docs / tests / other). Auto-labels: `enhancement`, `needs-review`.
- `.github/ISSUE_TEMPLATE/bug_report.yml` — defect / crash / wrong output. Captures project commit/version, Python version, pyTenable version, OS, what-happened, expected, steps to reproduce, frequency, severity, **4-item PII checklist** (no real hostnames/IPs/UUIDs, no credentials, no real config / cache / output attachments). Auto-labels: `bug`, `needs-triage`.
- `.github/ISSUE_TEMPLATE/chore.yml` — maintenance-only. Required pre-submission checklist with **explicit no-user-facing-change gate**, type-of-maintenance dropdown (refactor / dep / test / docs / CI / janitorial), current state with line citations, proposed work, acceptance criteria, area affected. Auto-labels: `type: chore`, `needs-triage`.
- `.github/PULL_REQUEST_TEMPLATE/feature.md` — Feature PR. Top-of-template gate notice requiring `approved-feature` label on linked issue. `Closes #N` linkage, files-changed tables, implementation notes, acceptance-criteria checklist (copied from issue), test coverage, platforms tested, Python versions tested, scope confirmation, breaking changes section.
- `.github/PULL_REQUEST_TEMPLATE/enhancement.md` — Enhancement PR. Gate: `approved-enhancement`. Before/after sections, implementation approach, verification method, platforms/versions tested, scope confirmation, breaking changes.
- `.github/PULL_REQUEST_TEMPLATE/fix.md` — Fix PR. Gate: `confirmed-bug`. What-was-broken + what-fix-does + **root cause** + verification + **regression test (required or justified)** + platforms/versions tested + scope + breaking changes.
- `CONTRIBUTING.md` — the issue-first rule and approval-gate flow, four issue-type table with gate labels, PII rules section, PR requirements (template / linkage / scope / title style / commit style / CHANGELOG), `/gsd-inbox` triage explanation, local development setup notes, cross-references to project context docs.

## Labels referenced (operator-managed in GitHub UI)

CONTRIBUTING.md documents which labels are expected. The operator needs to create these in the repo's Issues settings:

- Classification: `feature-request`, `enhancement`, `bug`, `type: chore`
- Pending attention: `needs-review`, `needs-triage`
- Gate-passed: `approved-feature`, `approved-enhancement`, `confirmed-bug`
- Auto-flag: `gate-violation` (applied by `/gsd-inbox --label`)

## Notable design decisions

- **Tailored to this project's stack** instead of copying GSD's example field names. Bug template asks for Python version + pyTenable version (not Node.js); feature template uses report slug / metric module / fetcher as the addition-type taxonomy.
- **PII gate is hard, not advisory.** The bug template's 4-item checklist is `required: true` on every item. Operators handling Tenable data cannot ship a bug report without confirming redaction.
- **Chore template enforces no-user-facing-change** as the very first gate. Misclassified work (a chore that's actually an enhancement) gets caught before review.
- **PR templates include explicit gate-violation notice at the top** so contributors are reminded of the issue-first rule before they fill in the PR body.

## Operator follow-up (not in this task)

To actually use `/gsd-inbox` after this task lands:

1. Create the labels listed above in the GitHub Issues settings UI.
2. Enable Discussions on the repo (CONTRIBUTING.md points to it for generic questions).
3. Optionally: add a GitHub Action that comments on PRs missing a linked issue (belt-and-suspenders against the gate).
