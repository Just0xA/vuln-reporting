# Vulnerability Management Reporting Suite

> **Right metric, right audience, right channel — without writing a new report each time.**

A modular Python reporting suite that connects to **Tenable.io / Tenable Vulnerability Management**
via the `pyTenable` SDK and produces audience-specific vulnerability management reports.
Reports are scoped by Tenable tags, delivered to YAML-configured recipient groups via SMTP,
and shipped as PDF + Excel + inline-chart email — driven by a scheduler that supports
daemon, cron-style, and manual on-demand execution.

---

## Who it's for

Vulnerability management programs that need to communicate risk to different audiences
without maintaining a separate report script for each one:

- **Operations teams** need remediation detail: overdue findings, plugin breakdowns,
  recurring vulnerabilities, and per-asset risk scores.
- **Management** needs trend and SLA posture: are we getting better or worse,
  and are we meeting our remediation windows?
- **Executive Leadership** needs RAG-strip headlines: a one-page read on Critical/High
  exposure, breach rate, and MTTR — without raw finding lists.

Each recipient group is defined in `delivery_config.yaml` with its own tag filter,
report selection, schedule, and recipient list. No code changes required to add or
reconfigure a group.

---

## Quickstart

To install, upgrade, or roll back on a Linux server, see [DEPLOYMENT.md](DEPLOYMENT.md).

For day-to-day operation — managing recipients, schedules, triggering reports manually,
and troubleshooting — see [RUNBOOK.md](RUNBOOK.md).

---

## Documentation map

| Document | What it covers |
|----------|----------------|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Install from a release tarball, configure credentials, verify, update procedure, rollback, on-disk layout, troubleshooting |
| [RUNBOOK.md](RUNBOOK.md) | Run and operate the suite: recipients, schedules, manual triggers, log locations, runtime troubleshooting |
| [CLAUDE.md](CLAUDE.md) | Architecture, report slug index, module infrastructure, calculation conventions, coding guidelines |
| [docs/](docs/) | Per-report calculation runbooks (`board_summary_calculations.md`, `management_summary_calculations.md`, etc.) |
