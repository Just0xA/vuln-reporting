---
slug: github-contribution-templates
date: 2026-05-14
type: quick
---

# Scaffold GitHub Contribution Templates

Create the `.github/` issue + PR templates and `CONTRIBUTING.md` needed for `/gsd-inbox` to triage incoming contributions against a documented standard. Tailor field names and runtime questions to this project's Python + pyTenable + WeasyPrint stack rather than copying GSD's example field names verbatim.

## Files

1. `.github/ISSUE_TEMPLATE/config.yml` — disable blank issues, route generic questions elsewhere.
2. `.github/ISSUE_TEMPLATE/feature_request.yml` — pre-submission checklist, problem statement, scope, user stories, acceptance criteria, runtime / platform matrix, breaking-change + alternatives.
3. `.github/ISSUE_TEMPLATE/enhancement.yml` — current vs proposed behavior, reason + benefit, scope, area-affected dropdown.
4. `.github/ISSUE_TEMPLATE/bug_report.yml` — project version, Python version, pyTenable version, OS, repro steps, severity, **PII checklist** (no real customer / vuln / asset data).
5. `.github/ISSUE_TEMPLATE/chore.yml` — maintenance task definition with explicit "no user-facing changes" gate.
6. `.github/PULL_REQUEST_TEMPLATE/feature.md` — feature PR template enforcing issue link, files-changed table, spec compliance, platforms tested.
7. `.github/PULL_REQUEST_TEMPLATE/enhancement.md` — same gate, before/after focus.
8. `.github/PULL_REQUEST_TEMPLATE/fix.md` — same gate, root-cause + regression-test focus.
9. `CONTRIBUTING.md` — issue-first rule, label gate flow per type, PII rules, PR-title style, commit style, `/gsd-inbox` triage rule.

## Labels created in CONTRIBUTING (operator-managed in GitHub UI)

- `feature-request`, `enhancement`, `bug`, `type: chore` — classification
- `needs-review`, `needs-triage` — pending operator attention
- `approved-feature`, `approved-enhancement`, `confirmed-bug` — gate-passed
- `gate-violation` — auto-applied by `/gsd-inbox --label`

## Out of scope

- Actually creating the labels in GitHub (operator does that in the Issues UI; CONTRIBUTING documents them).
- Wiring CODEOWNERS, branch protection, or required-status-checks (those are GitHub repo settings, not templates).
- Auto-PR-comment GitHub Actions (a possible follow-up but not needed for `/gsd-inbox` itself).
