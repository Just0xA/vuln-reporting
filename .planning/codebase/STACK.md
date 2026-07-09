# Technology Stack

**Analysis Date:** 2026-05-04

## Languages

**Primary:**
- Python 3.12+ — declared floor (`pyproject.toml` `requires-python = ">=3.12"`, `.python-version` 3.12). `from __future__ import annotations` used pervasively (e.g. `tenable_client.py:13`, `data/fetchers.py:18`); project documentation in `CLAUDE.md` declares "Python 3.12+".

**Secondary:**
- HTML/Jinja2 templates — `templates/report_email.html` and inline HTML built by `delivery/email_template.py:47-57` (Jinja2 `Environment` + `FileSystemLoader`).
- YAML — declarative delivery config (`delivery_config.yaml`) plus JSON-Schema-format validator at `delivery_config.schema.yaml`.
- SQL (SQLite dialect) — embedded delivery audit log; see `delivery/delivery_log.py:49-64` for the `delivery_log` `CREATE TABLE` statement.

## Runtime

**Environment:**
- CPython, expected to be invoked from a project-local virtualenv. The systemd unit at `deploy/vuln-reports.service:42` hard-codes the interpreter path `ExecStart=/opt/vuln-reporting/current/.venv/bin/python scheduler.py --mode daemon` (the per-release venv built by `update_from_github.sh`, reached via the `current` symlink), and the dev workstation copy of `.venv/` lives at the repo root.

**Package Manager:**
- pip with a flat, fully-pinned `requirements.txt` (no Poetry/PDM/uv lockfile present).
- No `pyproject.toml`, `setup.py`, `Pipfile`, or `Pipfile.lock` in the repo root. `requirements.txt` is the single source of truth for dependencies.

## Frameworks

**Core:**
- `pyTenable` 1.5.2 (`requirements.txt:2`) — Tenable Vulnerability Management SDK; instantiated in `tenable_client.py:80-84` (`TenableIO(access_key=..., secret_key=..., url=...)`); errors caught from the bundled `tenable.errors.APIError` (`tenable_client.py:21`) and from `restfly.errors.UnauthorizedError` re-aliased as `AuthenticationError` (`tenable_client.py:22`). `restfly` is a transitive dependency pulled in by pyTenable.
- `pandas` 2.2.3 (`requirements.txt:5`) + `numpy` 2.2.4 (`requirements.txt:6`) — every fetcher in `data/fetchers.py` returns a normalized `pd.DataFrame`; date normalization helpers `_parse_iso_utc` / `_normalize_vuln_dates` / `_normalize_asset_dates` at `data/fetchers.py:1132-1168`.
- `APScheduler` 3.11.0 (`requirements.txt:24`) — used in daemon mode only. `BlockingScheduler` and `IntervalTrigger` imported at `scheduler.py:300-301`; `CronTrigger` imported at `scheduler.py:155`. Misfire grace time set to 600s in `scheduler.py:254`.

**Testing:**
- No test framework declared in `requirements.txt`. A `tests/` directory exists at the repo root but is not wired into a runner. Pytest, unittest, etc. are not installed by `requirements.txt` (verified via grep — `pytest`, `unittest`, `nose` absent).

**Build/Dev:**
- No linter, formatter, or pre-commit configuration committed. No `.flake8`, `pyproject.toml`, `ruff.toml`, `mypy.ini`, `.pre-commit-config.yaml` present at the repo root (only the files listed in the directory listing are tracked).

## Key Dependencies

**Critical (runtime):**
- `pyTenable==1.5.2` — Tenable API SDK (`requirements.txt:2`). Used directly via `tio.exports.vulns()`, `tio.exports.assets()`, `tio.tags.list()`, `tio.server.status()`.
- `pandas==2.2.3` — DataFrame substrate for every report (`requirements.txt:5`).
- `numpy==2.2.4` — pandas dep, used directly in math/aggregations across reports (`requirements.txt:6`).
- `openpyxl==3.1.5` — Excel writer for all `.xlsx` outputs and conditional formatting (`requirements.txt:9`); imported in `exporters/excel_exporter.py` and per-module Excel renderers under `reports/modules/`.
- `matplotlib==3.10.1` — static PNG charts embedded in PDFs and emails (`requirements.txt:12`).
- `plotly==6.0.1` + `kaleido==0.2.1` — interactive `.html` charts plus static PNG export via Kaleido (`requirements.txt:13-14`). Kaleido is the static-image renderer required by Plotly's `write_image()`.
- `weasyprint==65.1` — HTML → PDF rendering (`requirements.txt:17`); imported lazily inside `exporters/pdf_exporter.py:515`, `reports/board_summary.py:350`, and `reports/management_summary.py:1236` to keep import-time cost down.
- `python-dotenv==1.1.0` — `.env` loader (`requirements.txt:20`); called in `tenable_client.py:53`, `config.py:16`, `delivery/email_sender.py:61`, `scheduler.py:49`, `run_all.py:48`.
- `PyYAML==6.0.2` — `delivery_config.yaml` parser (`requirements.txt:21`); used in `run_all.py:47` (`yaml.safe_load` at `run_all.py:153`).
- `Jinja2==3.1.6` — email body templating (`requirements.txt:27`); `Environment(loader=FileSystemLoader(...), autoescape=select_autoescape(...))` at `delivery/email_template.py:56-57`.
- `tenacity==9.1.2` — exponential backoff for both Tenable API fetches and SMTP sends (`requirements.txt:30`). Tenable retry policy: `data/fetchers.py:162-168` (`wait_exponential(multiplier=2, min=4, max=60)`, `stop_after_attempt(5)`). SMTP retry policy: `delivery/email_sender.py:91-97` (`wait_exponential(multiplier=2, min=4, max=30)`, `stop_after_attempt(3)`).
- `rich==14.0.0` — CLI tables and progress bars (`requirements.txt:33`); `Console`, `Table`, `box` used by `run_all.py`, `delivery/delivery_log.py`, `utils/tag_helper.py`; `Progress`/`SpinnerColumn` used during exports in `data/fetchers.py:245-251` and `data/fetchers.py:376-382`.
- `fastparquet` (unpinned, `requirements.txt:36`) — explicitly selected via `engine="fastparquet"` in `data/fetchers.py:184` (`pd.read_parquet`) and `data/fetchers.py:192` (`df.to_parquet`). pyarrow is intentionally not used.
- `jsonschema==4.23.0` — declared in `requirements.txt:39` for delivery-config schema validation (`delivery_config.schema.yaml`), but not actually imported anywhere in the project source. Validation is currently performed by hand-rolled checks in `run_all.py:241-318` (`_validate_group()`).
- `tzdata==2025.2` — timezone database (`requirements.txt:42`); required on Windows hosts where IANA tz data is otherwise unavailable. UTC handling in `data/fetchers.py:1142` (`pd.to_datetime(..., utc=True, errors="coerce", format="ISO8601")`).

**Infrastructure (runtime, transitive but used directly):**
- `requests` — pulled in transitively by pyTenable; imported lazily inside `data/fetchers.py:586` (`import requests as _requests`) for the direct `POST /v1/recast/rules/search` call that pyTenable does not wrap.
- `restfly` — transitive dep of pyTenable; `restfly.errors.UnauthorizedError` aliased to `AuthenticationError` at `tenable_client.py:22`.
- `smtplib` (stdlib) — SMTP transport in `delivery/email_sender.py:33`. Both `smtplib.SMTP` (STARTTLS) and `smtplib.SMTP_SSL` paths implemented at `delivery/email_sender.py:245-265`.
- `email.mime.*` (stdlib) — `MIMEMultipart`, `MIMEText`, `MIMEImage`, `MIMEBase`, `encoders` imported at `delivery/email_sender.py:38-42`.
- `sqlite3` (stdlib) — delivery audit log at `delivery/delivery_log.py:28`; WAL journal mode set at `delivery/delivery_log.py:84`.

## Configuration

**Environment:**
- All secrets and connection settings are loaded from a single `.env` file at the repo root via `python-dotenv`. `.env.example` is committed as the onboarding template.
- Tenable creds (required): `TVM_ACCESS_KEY`, `TVM_SECRET_KEY` (`tenable_client.py:55-67`). Optional: `TVM_URL` (defaults to `https://cloud.tenable.com` at `tenable_client.py:57`).
- SMTP creds (required for delivery): `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, `SMTP_FROM_NAME` (read at `delivery/email_sender.py:75-85`). Optional: `SMTP_USE_SSL` (string `"true"` flips port-465 SSL path).
- Optional overrides: `MAX_ATTACHMENT_SIZE_MB` (`config.py:201`, default 25), `LOG_LEVEL` (`config.py:206`, default `INFO`).
- `--dry-run` enforces presence of `TVM_ACCESS_KEY`, `TVM_SECRET_KEY`, `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS` (`run_all.py:117-124`).

**Build:**
- No build step. The project ships as a directory of `.py` source files plus the `.venv/` virtualenv on the deploy host.
- `delivery_config.schema.yaml` is the JSON-Schema-format validator for `delivery_config.yaml` (intended for editor / CI use; not currently enforced at runtime — see `jsonschema` note above).

## Platform Requirements

**Development:**
- Python 3.12+.
- Local virtualenv (`.venv/`) populated by `pip install -r requirements.txt`.
- WeasyPrint requires GTK/Pango/Cairo native libs on Windows; on Linux/RHEL these are typically installed via `pango`, `cairo`, `gdk-pixbuf2` system packages.

**Production:**
- Linux host running systemd is the documented deployment target. Sample unit at `deploy/vuln-reports.service` expects:
  - Working dir: `/opt/vuln-reporting` (`deploy/vuln-reports.service:33`).
  - Service account: `vuln-reports:vuln-reports` (`deploy/vuln-reports.service:27-28`).
  - `EnvironmentFile=/opt/vuln-reporting/.env` (`deploy/vuln-reports.service:38`).
  - Hardening: `NoNewPrivileges=true`, `PrivateTmp=true`, `ReadWritePaths=output logs data/cache` (`deploy/vuln-reports.service:70-80`).
- Cron / Windows Task Scheduler also supported via `python scheduler.py --mode run-due` invoked every 5–10 minutes (CLAUDE.md `Mode 2`).
- Outbound network access required to Tenable.io (`https://cloud.tenable.com`) and the configured SMTP relay.

---

*Stack analysis: 2026-05-04*
