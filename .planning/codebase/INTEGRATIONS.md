# External Integrations

**Analysis Date:** 2026-05-04

## APIs & External Services

**Tenable Vulnerability Management (Tenable.io):**
- Service: Tenable.io cloud vulnerability platform.
- Base URL: `https://cloud.tenable.com` (configurable via `TVM_URL`; default at `tenable_client.py:57`).
- Auth: API key pair `accessKey` + `secretKey`, sourced from `TVM_ACCESS_KEY` / `TVM_SECRET_KEY` env vars.
- SDK/Client:
  - Primary: `pyTenable.tenable.io.TenableIO` instantiated at `tenable_client.py:80-84`. Connection validated against `tio.server.status()` at `tenable_client.py:136`.
  - Direct REST: `requests` (lazy import at `data/fetchers.py:586`) for the one endpoint pyTenable does not wrap.
- Endpoints used:
  - `tio.exports.vulns(state=["open","reopened"], severity=[critical,high,medium,low])` — open findings stream; called in `data/fetchers.py:253`.
  - `tio.exports.vulns(state=["fixed"], severity=[...])` — remediated findings for MTTR; called in `data/fetchers.py:384`.
  - `tio.exports.vulns(tags=[(category, value)], ...)` — tag-scoped variant in deprecated `fetch_vulnerabilities()`, `data/fetchers.py:882`.
  - `tio.exports.assets()` — asset enumeration; called in `data/fetchers.py:488` and `data/fetchers.py:984`.
  - `tio.exports.assets(tags=[(category, value)])` — tag-scoped asset enumeration in deprecated `fetch_assets_by_tag()`, `data/fetchers.py:1113`.
  - `tio.tags.list()` — tag-category/value catalogue; called in `data/fetchers.py:1059`.
  - `tio.server.status()` — health-check used during connection validation, `tenable_client.py:136`.
  - `POST /v1/recast/rules/search` — direct HTTP POST (not in pyTenable). Issued in `data/fetchers.py:620-625`; auth header `X-ApiKeys: accessKey=<...>;secretKey=<...>` built at `data/fetchers.py:610`. Pagination via `payload["next"]` cursor (`data/fetchers.py:633-636`). 30-second timeout (`data/fetchers.py:624`).
- Retry policy: tenacity exponential backoff on `tenable.errors.APIError`, `ConnectionError`, `TimeoutError`. Multiplier 2, min 4s, max 60s, max 5 attempts (`data/fetchers.py:156-168`).

## Data Storage

**Databases:**
- SQLite — local audit log only.
  - File: `logs/delivery_log.db`, defined at `delivery/delivery_log.py:47` (`DB_PATH = LOG_DIR / "delivery_log.db"`).
  - Schema: single `delivery_log` table with columns `id, timestamp, group_name, trigger_mode, reports_run, tag_filter, recipients, status, error_message, output_folder, attachment_size_kb, duration_seconds` (`delivery/delivery_log.py:49-64`).
  - Connection: `sqlite3.connect(...)` with `PRAGMA journal_mode=WAL` and `Row` factory (`delivery/delivery_log.py:80-85`).

**File Storage (local filesystem only — no cloud storage):**
- Parquet cache at `data/cache/<YYYY-MM-DD>/<dataset>.parquet` (folder pattern declared in `CLAUDE.md` Data Fetching Guidelines; cache root from `config.py:220-221`). Files: `vulns_all.parquet`, `vulns_fixed.parquet`, `assets_all.parquet`, `recast_rules.parquet`, plus `tags.parquet` and per-tag-scoped variants.
- Engine pinned to `fastparquet` at `data/fetchers.py:184` and `data/fetchers.py:192`.
- Trend snapshots (JSON) at `data/trend/management_summary_*.json`; persisted by `reports/management_summary.py` for rolling month-over-month metrics.
- Report outputs at `output/YYYY-MM-DD_HH-MM_<group-name>/` (`config.py:214-215` defines the root; `run_all.py` builds per-group subfolders).
- Logs at `logs/app.log` (`tenable_client.py:34`) and `logs/scheduler.log` (`scheduler.py:60`); the scheduler log uses `RotatingFileHandler(maxBytes=10MB, backupCount=5)` at `scheduler.py:75-80`.

**Caching:**
- Per-run parquet cache only (see above). No Redis / Memcached / external cache.
- Cache deduplication: all reports inside one `run_all.py` batch share a single `cache_dir`, so each Tenable export endpoint is hit once per run; subsequent reports get `[CACHE HIT]` (`data/fetchers.py:183`).

## Authentication & Identity

**Auth Provider:**
- None — this codebase has no inbound auth surface. It is a one-way batch reporting tool.
- Outbound auth to Tenable: API-key pair (`X-ApiKeys` header for direct REST at `data/fetchers.py:610`; SDK constructor params at `tenable_client.py:80-84`).
- Outbound auth to SMTP: username/password basic auth via `smtp.login()` (`delivery/email_sender.py:248`, `:260`).

## Monitoring & Observability

**Error Tracking:**
- None (no Sentry, Rollbar, Datadog SDK installed). Errors are written to local rotating logs and surfaced through the SQLite delivery audit log (`status='failed'`, `error_message=...` at `delivery/email_sender.py:549-560`).

**Logs:**
- stdlib `logging` configured in two places:
  - `tenable_client.py:29-37` — base config: stdout `StreamHandler` + plain `FileHandler(logs/app.log)`.
  - `scheduler.py:63-96` — overrides root logger with stdout + `RotatingFileHandler(logs/scheduler.log, 10MB × 5)`. Strips third-party noisy loggers via `_ThirdPartyFilter` imported from `run_all.py` (`scheduler.py:90`).
- Rich progress bars during long-running exports (`data/fetchers.py:245-251`, `:376-382`, `:480-486`).

## CI/CD & Deployment

**Hosting:**
- Self-hosted Linux host running systemd. Reference unit file: `deploy/vuln-reports.service`.
- Working directory pinned to `/opt/vuln-reporting` (`deploy/vuln-reports.service:33`).
- Service account: `vuln-reports:vuln-reports` (non-login, dedicated) (`deploy/vuln-reports.service:27-28`).
- Restart policy: `Restart=on-failure`, `RestartSec=30`, max 5 restarts in 300s window (`deploy/vuln-reports.service:54-57`).
- Graceful shutdown: `KillSignal=SIGTERM`, `TimeoutStopSec=120`; `scheduler.py:342-369` catches SIGTERM/SIGINT and waits for in-flight jobs before calling `scheduler.shutdown(wait=True)`.

**CI Pipeline:**
- None committed. No `.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile`, etc. present.

## Environment Configuration

**Required env vars (loaded via `python-dotenv` from `.env`):**
- `TVM_ACCESS_KEY` — Tenable API access key (`tenable_client.py:55`).
- `TVM_SECRET_KEY` — Tenable API secret key (`tenable_client.py:56`).
- `SMTP_HOST` — SMTP relay hostname (`delivery/email_sender.py:78`; default `smtp.office365.com`).
- `SMTP_USERNAME` — SMTP login (`delivery/email_sender.py:80`).
- `SMTP_PASSWORD` — SMTP password / app-password (`delivery/email_sender.py:81`).
- `SMTP_FROM_ADDRESS` — From-header address (`delivery/email_sender.py:82`).
- `--dry-run` enforces all six of the above (`run_all.py:117-124`).

**Optional env vars:**
- `TVM_URL` — Tenable base URL; default `https://cloud.tenable.com` (`tenable_client.py:57`).
- `SMTP_PORT` — default `587` (`delivery/email_sender.py:79`).
- `SMTP_USE_SSL` — string `"true"` selects `SMTP_SSL` instead of STARTTLS (`delivery/email_sender.py:84`, switch at `delivery/email_sender.py:245`).
- `SMTP_FROM_NAME` — display name; default `"Vulnerability Management Reports"` (`delivery/email_sender.py:83`).
- `MAX_ATTACHMENT_SIZE_MB` — default `25` (`config.py:201`).
- `LOG_LEVEL` — default `INFO` (`config.py:206`).

**Secrets location:**
- `.env` at project root — never committed. `.env.example` (committed) is the contract. On the systemd host, `EnvironmentFile=/opt/vuln-reporting/.env` injects the values directly into the service process environment (`deploy/vuln-reports.service:38`).

## Outbound Email (SMTP)

**Service:**
- Generic SMTP relay; defaults target Office 365 (`smtp.office365.com:587`, `delivery/email_sender.py:78-79` and `.env.example:15-16`).
- STARTTLS on port 587 (default, `delivery/email_sender.py:256-264`); SSL on port 465 when `SMTP_USE_SSL=true` (`delivery/email_sender.py:246-253`).
- Login via `smtp.login(username, password)` (`delivery/email_sender.py:248`, `:260`).
- 30-second connection timeout on both paths (`delivery/email_sender.py:247`, `:256`).

**Reliability:**
- tenacity retry on `smtplib.SMTPException`, `ConnectionError`, `TimeoutError`, `OSError`. Multiplier 2, min 4s, max 30s, max 3 attempts (`delivery/email_sender.py:91-97`). Decorator applied at `delivery/email_sender.py:232`.

**Payload:**
- Multipart MIME: `MIMEMultipart("mixed")` at `delivery/email_sender.py:447`, with a nested `MIMEMultipart("related")` (`:456`) carrying the HTML body and CID-embedded chart PNGs (`:476-478`).
- Attachments: PDFs (`octet-stream`, `:488-494`), Excel (`octet-stream`, `:497-503`), CSV (`text/csv` via `_attach_csv()`, `:150-163` and `:506-512`).
- Total attachment size enforced at `MAX_ATTACHMENT_SIZE_MB`; on overflow, Excel files are dropped and a `partial` status is recorded (`delivery/email_sender.py:378-389`, `:567`).

## Scheduler Integrations

**APScheduler (in-process daemon):**
- `BlockingScheduler` + `IntervalTrigger` imported at `scheduler.py:300-301`; `CronTrigger` at `scheduler.py:155`.
- Weekly groups → `CronTrigger(day_of_week=mon|tue|...|sun, hour, minute)` (`scheduler.py:192-196`).
- Monthly groups → `CronTrigger(day=1..28, hour, minute)` (`scheduler.py:232-236`).
- 10-minute misfire grace window (`scheduler.py:254`).
- Hot-reload of `delivery_config.yaml` via 5-minute `IntervalTrigger` job `_reload_check` (`scheduler.py:262-287`, `:325-331`); detects mtime change and reschedules without restart.

**Cron / Windows Task Scheduler (external trigger):**
- `python scheduler.py --mode run-due` reads the config and runs only groups inside ±10 minute window of `datetime.now()` (server local time) (`scheduler.py:376-419`, schedule match logic in `run_all.py:175-234`).
- Designed to be invoked every 5–10 minutes by an external scheduler. Sample crontab:`*/10 * * * * /usr/bin/python3 /opt/vuln-reporting/scheduler.py --mode run-due` (per CLAUDE.md Mode 2).

**Manual / on-demand:**
- `python scheduler.py --mode manual --group "<name>"` or `--all-on-demand`; supports `--no-email` and `--recipients` overrides (`scheduler.py:426-503`).

## Webhooks & Callbacks

**Incoming:** None. The service exposes no HTTP endpoints, sockets, or queue consumers.

**Outgoing:**
- Tenable HTTPS calls only (via pyTenable + one direct `requests.post` to `/v1/recast/rules/search`).
- SMTP submission to the configured relay.
- No webhooks, no message-queue producers, no third-party callbacks.

## Filesystem Touchpoints (summary)

| Path | Role | Created at |
|------|------|------------|
| `data/cache/<YYYY-MM-DD>/*.parquet` | Per-day Tenable export cache | `data/fetchers.py:188-195` |
| `data/trend/management_summary_*.json` | Trend snapshots for management report | `reports/management_summary.py` |
| `output/<run-id>/*.{pdf,xlsx,csv,png,html}` | Generated report artefacts | `config.py:214-215` |
| `logs/app.log` | Base application log | `tenable_client.py:34` |
| `logs/scheduler.log` (rotated, 10MB×5) | Scheduler / daemon log | `scheduler.py:75-80` |
| `logs/delivery_log.db` | SQLite audit log of every send attempt | `delivery/delivery_log.py:47` |
| `.env` | Secrets (Tenable + SMTP) — read-only | loaded via `load_dotenv()` in multiple modules |

---

*Integration audit: 2026-05-04*
