# Local E2E Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline, three-layer pytest suite (module-unit, content/value, config-driven E2E with an in-process SMTP catcher) that proves reports work before every commit.

**Architecture:** Layer 1 drives each registered module's `compute()` + five renderers directly with synthetic DataFrames. Layer 2 asserts exact KPI numbers from hand-built fixtures via `utils/sla_calculator`. Layer 3 seeds a temp parquet `cache_dir` with fixture data, then runs the real `run_group()` per `delivery_config.yaml` group — the fetchers' cache-first short-circuit (`data/fetchers.py:276`) means no Tenable call — and asserts artifacts + the real MIME email captured by an in-process `aiosmtpd`. A pre-commit hook runs the whole suite under `pytest-xdist`.

**Tech Stack:** pytest, pytest-xdist, aiosmtpd, pypdf, openpyxl (already shipped), pandas, fastparquet (already shipped).

Spec: `docs/superpowers/specs/2026-05-23-local-e2e-test-harness-design.md`

---

## File structure

| File | Responsibility |
|------|----------------|
| `requirements-dev.txt` | Test-only deps (pytest, pytest-xdist, aiosmtpd, pypdf). Never installed on the VM. |
| `pytest.ini` | testpaths, markers, `-n auto`, `--import-mode=importlib`. |
| `tests/conftest.py` | sys.path bootstrap + shared fixtures (`temp_output_dir`, `synthetic_*_df`, `empty_*_df`, `seeded_cache`, `dummy_tio`, `smtp_catcher`). |
| `tests/fixtures/builders.py` | Hand-built DataFrames with exact known contents. |
| `tests/fixtures/generator.py` | Seeded scenario generator → `(dfs, expected)`. |
| `tests/fixtures/scenarios.py` | Named scenarios (`ZERO_MATCH`, `OVERSIZED`, `NULL_VPR`, `NULL_FIRST_FOUND`). |
| `tests/validators.py` | `assert_valid_pdf` / `assert_valid_xlsx` / `assert_well_formed_html` / `assert_email_cids_resolve`. |
| `tests/smtp_catcher.py` | In-process aiosmtpd controller wrapper (capture + `.eml` dump). |
| `tests/unit/test_modules.py` | Layer 1 — parametrized over registry. |
| `tests/content/test_values.py` | Layer 2 — exact-value assertions. |
| `tests/e2e/test_groups.py` | Layer 3 — real `run_group` + SMTP capture + failure-mode tests. |
| `.githooks/pre-commit` | Runs `pytest -n auto -q`; honors `VULN_E2E_SKIP=1`. |

---

## Task 1: Dev dependencies + pytest skeleton

**Files:**
- Create: `requirements-dev.txt`
- Create: `pytest.ini`
- Create: `tests/fixtures/__init__.py` (empty)

- [ ] **Step 1: Write `requirements-dev.txt`**

```
# Test-only dependencies. NOT installed on the production VM.
# Install locally with:  pip install -r requirements-dev.txt
pytest==8.3.4
pytest-xdist==3.6.1
aiosmtpd==1.4.6
pypdf==5.1.0
```

- [ ] **Step 2: Write `pytest.ini`**

```ini
[pytest]
testpaths = tests/unit tests/content tests/e2e
addopts = -q -n auto --import-mode=importlib --strict-markers
markers =
    unit: Layer 1 — per-module contract tests
    content: Layer 2 — exact KPI value assertions
    e2e: Layer 3 — config-driven run_group + SMTP delivery
```

- [ ] **Step 3: Create the empty fixtures package marker**

Create `tests/fixtures/__init__.py` with a single line:

```python
"""Test fixture builders, generators, and named scenarios."""
```

- [ ] **Step 4: Install dev deps and verify collection works**

Run: `pip install -r requirements-dev.txt; python -m pytest --collect-only`
Expected: exit 0, "no tests ran" / "collected 0 items" (the test dirs don't exist yet — that's fine; the key check is pytest + xdist import cleanly).

- [ ] **Step 5: Commit**

```bash
git add requirements-dev.txt pytest.ini tests/fixtures/__init__.py
git commit -m "test: add pytest harness skeleton + dev dependencies"
```

---

## Task 2: Fixture builders (hand-built exact data)

**Files:**
- Create: `tests/fixtures/builders.py`

Column names mirror `data/fetchers.py` vuln rows (`:325`) and asset rows (`:544`). `first_found` is UTC-aware so `apply_sla_to_df` works without coercion.

- [ ] **Step 1: Write `tests/fixtures/builders.py`**

```python
"""
tests/fixtures/builders.py — hand-built DataFrames with EXACT known contents.

These power Layer 2 value assertions. Every value is deliberate so the
expected KPI numbers are hand-verifiable. Columns mirror the normalized
output of data/fetchers.py (vuln rows at fetchers.py:325, asset rows at :544).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

# Fixed reference point so "days_open" is deterministic regardless of wall clock.
AS_OF = datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc)

# Full vuln column set the suite relies on.
_VULN_COLUMNS = [
    "asset_uuid", "hostname", "ipv4", "plugin_id", "plugin_name",
    "plugin_family", "vpr_score", "severity", "severity_native",
    "cve_list", "cvss_base_score", "exploit_available",
    "first_found", "last_found", "last_fixed", "state", "finding_id",
]

_ASSET_COLUMNS = [
    "asset_uuid", "hostname", "ipv4", "fqdn", "operating_system",
    "network_name", "last_seen", "last_licensed_scan_date",
    "tags", "tags_str", "source_name",
]


def _vuln(asset_uuid, severity, vpr, days_ago, state="open", **over):
    """One vuln row; first_found is `days_ago` before AS_OF."""
    ff = AS_OF - timedelta(days=days_ago) if days_ago is not None else None
    row = {
        "asset_uuid": asset_uuid,
        "hostname": f"host-{asset_uuid}",
        "ipv4": "10.0.0.1",
        "plugin_id": 19506,
        "plugin_name": "Test Plugin",
        "plugin_family": "General",
        "vpr_score": vpr,
        "severity": severity,
        "severity_native": severity,
        "cve_list": "CVE-2024-0001",
        "cvss_base_score": 7.5,
        "exploit_available": False,
        "first_found": ff,
        "last_found": AS_OF,
        "last_fixed": None,
        "state": state,
        "finding_id": f"f-{asset_uuid}-{severity}",
    }
    row.update(over)
    return row


def build_vulns_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=_VULN_COLUMNS)
    df["first_found"] = pd.to_datetime(df["first_found"], utc=True, errors="coerce")
    return df


def build_assets_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=_ASSET_COLUMNS)
    for col in ("last_seen", "last_licensed_scan_date"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df


def three_overdue_crit() -> pd.DataFrame:
    """
    5 open vulns: exactly 3 critical past the 15-day SLA, 2 critical within it.
    Expected: is_overdue.sum() == 3.
    """
    return build_vulns_df([
        _vuln("a1", "critical", 9.5, days_ago=20),  # overdue (20 > 15)
        _vuln("a2", "critical", 9.1, days_ago=30),  # overdue
        _vuln("a3", "critical", 9.8, days_ago=16),  # overdue
        _vuln("a4", "critical", 9.2, days_ago=10),  # within SLA
        _vuln("a5", "critical", 9.0, days_ago=5),   # within SLA
    ])


def one_asset() -> pd.DataFrame:
    return build_assets_df([{
        "asset_uuid": "a1", "hostname": "host-a1", "ipv4": "10.0.0.1",
        "fqdn": "host-a1.test", "operating_system": "Linux",
        "network_name": "Default", "last_seen": AS_OF,
        "last_licensed_scan_date": AS_OF, "tags": "Environment=Production",
        "tags_str": "Environment: Production", "source_name": "NESSUS_SCAN",
    }])
```

- [ ] **Step 2: Verify the builders produce the expected counts**

Run:
```bash
python -c "from tests.fixtures.builders import three_overdue_crit, AS_OF; from utils.sla_calculator import apply_sla_to_df; df=apply_sla_to_df(three_overdue_crit(), as_of=AS_OF); print(int(df['is_overdue'].sum()))"
```
Expected: prints `3`

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/builders.py
git commit -m "test: add hand-built fixture builders with exact known data"
```

---

## Task 3: Seeded scenario generator

**Files:**
- Create: `tests/fixtures/generator.py`

- [ ] **Step 1: Write `tests/fixtures/generator.py`**

```python
"""
tests/fixtures/generator.py — seeded synthetic data generator.

make_scenario() returns (vulns_df, assets_df, expected) where `expected`
is derived from the SAME params so value assertions stay in sync with the
generated data. Deterministic for a fixed seed.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pandas as pd

from config import SLA_DAYS as _SLA  # source of truth — avoid drift
from tests.fixtures.builders import build_assets_df, build_vulns_df

_SEVERITIES = ["critical", "high", "medium", "low"]
_VPR = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.0}


def make_scenario(
    seed: int = 42,
    n_assets: int = 50,
    vulns_per_asset: int = 4,
    overdue_ratio: float = 0.3,
    as_of: datetime | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Generate vulns + assets and the expected overdue count."""
    if as_of is None:
        as_of = datetime(2026, 5, 23, 12, 0, 0, tzinfo=timezone.utc)
    rng = random.Random(seed)

    asset_rows, vuln_rows = [], []
    expected_overdue = 0

    for i in range(n_assets):
        uuid = f"gen-{i:04d}"
        asset_rows.append({
            "asset_uuid": uuid, "hostname": f"gen-host-{i}",
            "ipv4": f"10.1.{i // 256}.{i % 256}", "fqdn": f"gen-host-{i}.test",
            "operating_system": "Linux", "network_name": "Default",
            "last_seen": as_of, "last_licensed_scan_date": as_of,
            "tags": "Environment=Staging", "tags_str": "Environment: Staging",
            "source_name": "NESSUS_SCAN",
        })
        for j in range(vulns_per_asset):
            sev = rng.choice(_SEVERITIES)
            is_overdue = rng.random() < overdue_ratio
            days_ago = _SLA[sev] + 5 if is_overdue else max(1, _SLA[sev] - 5)
            if is_overdue:
                expected_overdue += 1
            vuln_rows.append({
                "asset_uuid": uuid, "hostname": f"gen-host-{i}", "ipv4": "10.1.0.1",
                "plugin_id": 10000 + j, "plugin_name": f"Gen Plugin {j}",
                "plugin_family": "General", "vpr_score": _VPR[sev],
                "severity": sev, "severity_native": sev,
                "cve_list": "CVE-2024-9999", "cvss_base_score": 7.0,
                "exploit_available": False,
                "first_found": as_of - timedelta(days=days_ago),
                "last_found": as_of, "last_fixed": None, "state": "open",
                "finding_id": f"gen-{i}-{j}",
            })

    return (
        build_vulns_df(vuln_rows),
        build_assets_df(asset_rows),
        {"overdue_count": expected_overdue, "n_assets": n_assets},
    )
```

- [ ] **Step 2: Verify determinism + expected sync**

Run:
```bash
python -c "from tests.fixtures.generator import make_scenario; from tests.fixtures.builders import AS_OF; from utils.sla_calculator import apply_sla_to_df; v,a,e=make_scenario(seed=42, as_of=AS_OF); df=apply_sla_to_df(v, as_of=AS_OF); print(int(df['is_overdue'].sum())==e['overdue_count'])"
```
Expected: prints `True`

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/generator.py
git commit -m "test: add seeded scenario generator with synced expected values"
```

---

## Task 4: Named scenarios (incl. failure modes)

**Files:**
- Create: `tests/fixtures/scenarios.py`

- [ ] **Step 1: Write `tests/fixtures/scenarios.py`**

```python
"""
tests/fixtures/scenarios.py — named scenarios, including failure modes.

Each scenario returns (vulns_df, assets_df). Used by Layer 3 to exercise
empty-data, null-VPR, and null-date code paths deterministically.
"""
from __future__ import annotations

import pandas as pd

from tests.fixtures.builders import (
    AS_OF, build_assets_df, build_vulns_df, one_asset, three_overdue_crit, _vuln,
)


def zero_match() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Assets exist but carry a tag no group filters on → filtered-to-zero."""
    assets = build_assets_df([{
        "asset_uuid": "z1", "hostname": "z-host", "ipv4": "10.9.9.9",
        "fqdn": "z.test", "operating_system": "Linux", "network_name": "Default",
        "last_seen": AS_OF, "last_licensed_scan_date": AS_OF,
        "tags": "Environment=NoSuchValue", "tags_str": "Environment: NoSuchValue",
        "source_name": "NESSUS_SCAN",
    }])
    return three_overdue_crit(), assets


def null_vpr() -> tuple[pd.DataFrame, pd.DataFrame]:
    """VPR null → severity must come from native fallback."""
    df = build_vulns_df([
        _vuln("n1", "high", vpr=None, days_ago=40, severity_native="high"),
        _vuln("n2", "medium", vpr=None, days_ago=10, severity_native="medium"),
    ])
    return df, one_asset()


def null_first_found() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Null first_found must not crash SLA math."""
    df = build_vulns_df([_vuln("nf1", "critical", 9.5, days_ago=None)])
    return df, one_asset()
```

- [ ] **Step 2: Verify each scenario builds + survives SLA math**

Run:
```bash
python -c "from tests.fixtures.scenarios import zero_match, null_vpr, null_first_found; from tests.fixtures.builders import AS_OF; from utils.sla_calculator import apply_sla_to_df; [apply_sla_to_df(s()[0], as_of=AS_OF) for s in (zero_match, null_vpr, null_first_found)]; print('ok')"
```
Expected: prints `ok` (no exception on null VPR / null date)

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/scenarios.py
git commit -m "test: add named scenarios for empty/null-VPR/null-date paths"
```

---

## Task 5: Validators

**Files:**
- Create: `tests/validators.py`

- [ ] **Step 1: Write `tests/validators.py`**

```python
"""
tests/validators.py — structural assertions for produced artifacts.

assert_valid_pdf      — pypdf opens it and it has >=1 page.
assert_valid_xlsx     — openpyxl loads it; optional expected-tab check.
assert_well_formed_html — html.parser consumes it without raising.
assert_email_cids_resolve — every <img src="cid:X"> has a matching
                            Content-ID part in the MIME message.
"""
from __future__ import annotations

import re
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path

from openpyxl import load_workbook
from pypdf import PdfReader


def assert_valid_pdf(path: Path) -> None:
    assert Path(path).exists(), f"PDF missing: {path}"
    reader = PdfReader(str(path))
    assert len(reader.pages) >= 1, f"PDF has no pages: {path}"


def assert_valid_xlsx(path: Path, expected_tabs: list[str] | None = None) -> None:
    assert Path(path).exists(), f"Excel missing: {path}"
    wb = load_workbook(str(path), read_only=True)
    if expected_tabs:
        missing = [t for t in expected_tabs if t not in wb.sheetnames]
        assert not missing, f"Excel {path} missing tabs: {missing}"


class _StrictHTML(HTMLParser):
    def error(self, message):  # pragma: no cover - parser rarely calls this
        raise ValueError(message)


def assert_well_formed_html(html: str) -> None:
    assert html and html.strip(), "HTML body is empty"
    _StrictHTML().feed(html)  # raises on malformed markup


def assert_email_cids_resolve(msg: Message) -> None:
    """Every cid: referenced in the HTML body must have a matching part."""
    html_parts = [
        p.get_payload(decode=True).decode("utf-8", "replace")
        for p in msg.walk()
        if p.get_content_type() == "text/html"
    ]
    referenced = set()
    for body in html_parts:
        referenced.update(re.findall(r'src=["\']cid:([^"\']+)["\']', body))

    available = set()
    for part in msg.walk():
        cid = part.get("Content-ID", "")
        if cid:
            available.add(cid.strip("<>"))

    missing = referenced - available
    assert not missing, f"Unresolved inline CIDs: {missing} (have: {available})"
```

- [ ] **Step 2: Verify validators import + reject bad input**

Run:
```bash
python -c "from tests.validators import assert_well_formed_html; assert_well_formed_html('<p>ok</p>'); print('ok')"
```
Expected: prints `ok`

- [ ] **Step 3: Commit**

```bash
git add tests/validators.py
git commit -m "test: add PDF/Excel/HTML/email-CID structural validators"
```

---

## Task 6: In-process SMTP catcher

**Files:**
- Create: `tests/smtp_catcher.py`

- [ ] **Step 1: Write `tests/smtp_catcher.py`**

```python
"""
tests/smtp_catcher.py — in-process aiosmtpd that captures messages.

Pure Python, no Docker. Binds 127.0.0.1 on an OS-assigned free port so
parallel xdist workers don't collide. Captured messages are parsed into
email.message.Message objects and (optionally) dumped as .eml for manual
eyeballing.
"""
from __future__ import annotations

from email import message_from_bytes
from email.message import Message
from pathlib import Path

from aiosmtpd.controller import Controller


class _CaptureHandler:
    def __init__(self, dump_dir: Path | None) -> None:
        self.messages: list[Message] = []
        self.dump_dir = dump_dir
        if dump_dir:
            dump_dir.mkdir(parents=True, exist_ok=True)

    async def handle_DATA(self, server, session, envelope):
        msg = message_from_bytes(envelope.content)
        self.messages.append(msg)
        if self.dump_dir:
            idx = len(self.messages)
            (self.dump_dir / f"message_{idx:03d}.eml").write_bytes(envelope.content)
        return "250 Message accepted for delivery"


class SmtpCatcher:
    """Context manager around an aiosmtpd Controller on a free local port."""

    def __init__(self, dump_dir: Path | None = None) -> None:
        self._handler = _CaptureHandler(dump_dir)
        # port=0 → OS assigns a free port, read back after start().
        self._controller = Controller(self._handler, hostname="127.0.0.1", port=0)

    def __enter__(self) -> "SmtpCatcher":
        self._controller.start()
        return self

    def __exit__(self, *exc) -> None:
        self._controller.stop()

    @property
    def host(self) -> str:
        return self._controller.hostname

    @property
    def port(self) -> int:
        return self._controller.server.sockets[0].getsockname()[1]

    @property
    def messages(self) -> list[Message]:
        return self._handler.messages
```

- [ ] **Step 2: Verify the catcher starts, receives, and stops**

Run:
```bash
python -c "import smtplib; from email.mime.text import MIMEText; from tests.smtp_catcher import SmtpCatcher; c=SmtpCatcher();
with c:
 m=MIMEText('hi'); m['Subject']='t'; m['From']='a@x'; m['To']='b@y'
 s=smtplib.SMTP(c.host, c.port, timeout=5); s.sendmail('a@x',['b@y'], m.as_string()); s.quit()
 print(len(c.messages))"
```
Expected: prints `1`

- [ ] **Step 3: Commit**

```bash
git add tests/smtp_catcher.py
git commit -m "test: add in-process aiosmtpd capture catcher"
```

---

## Task 7: conftest.py — sys.path + shared fixtures

**Files:**
- Create: `tests/conftest.py`

The `seeded_cache` fixture writes all four datasets (`vulns_all`, `assets_all`, `vulns_fixed`, `recast_rules`) with `engine="fastparquet"` to match `_load_cache` (`data/fetchers.py:230`) so `run_group`'s pre-fetch and every report hit `[CACHE HIT]` and never touch `tio`.

- [ ] **Step 1: Write `tests/conftest.py`**

```python
"""
tests/conftest.py — shared pytest fixtures for the local E2E harness.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

# Make the project root importable (run_all, data, reports, utils, ...).
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.fixtures.builders import three_overdue_crit, one_asset  # noqa: E402
from tests.fixtures.generator import make_scenario  # noqa: E402
from tests.smtp_catcher import SmtpCatcher  # noqa: E402

_EML_DUMP_DIR = _ROOT / "output" / "test-eml"


class DummyTio:
    """Stand-in Tenable client. Never called on a cache hit; raises if it is."""
    def __getattr__(self, name):
        raise AssertionError(
            f"DummyTio.{name} accessed — cache short-circuit failed; "
            "a fetcher tried to hit Tenable."
        )


@pytest.fixture
def dummy_tio() -> DummyTio:
    return DummyTio()


@pytest.fixture
def synthetic_vulns_df() -> pd.DataFrame:
    return make_scenario(seed=42)[0]


@pytest.fixture
def synthetic_assets_df() -> pd.DataFrame:
    return make_scenario(seed=42)[1]


@pytest.fixture
def empty_vulns_df() -> pd.DataFrame:
    return three_overdue_crit().iloc[0:0].copy()


@pytest.fixture
def empty_assets_df() -> pd.DataFrame:
    return one_asset().iloc[0:0].copy()


@pytest.fixture
def temp_output_dir(tmp_path) -> Path:
    d = tmp_path / "output"
    d.mkdir()
    return d


@pytest.fixture
def seeded_cache(tmp_path) -> Path:
    """Write fixture parquets so fetchers load from cache (no Tenable I/O)."""
    cache = tmp_path / "cache"
    cache.mkdir()
    vulns, assets, _ = make_scenario(seed=7)
    datasets = {
        "vulns_all": vulns,
        "assets_all": assets,
        "vulns_fixed": vulns.iloc[0:0].copy(),     # no fixed vulns in fixture
        "recast_rules": pd.DataFrame(),            # no recast rules
    }
    for name, df in datasets.items():
        df.to_parquet(cache / f"{name}.parquet", index=False, engine="fastparquet")
    return cache


@pytest.fixture
def smtp_catcher(monkeypatch):
    """Start an in-process SMTP catcher and point the email sender at it."""
    with SmtpCatcher(dump_dir=_EML_DUMP_DIR) as catcher:
        monkeypatch.setenv("SMTP_HOST", catcher.host)
        monkeypatch.setenv("SMTP_PORT", str(catcher.port))
        monkeypatch.setenv("SMTP_USERNAME", "")
        monkeypatch.setenv("SMTP_PASSWORD", "")
        monkeypatch.setenv("SMTP_USE_SSL", "false")
        monkeypatch.setenv("SMTP_FROM_ADDRESS", "reports@test.local")
        yield catcher
```

- [ ] **Step 2: Verify fixtures resolve via a throwaway test**

Run:
```bash
python -m pytest tests/conftest.py --collect-only 2>&1 | tail -3
```
Expected: exit 0, no import errors (conftest imports cleanly).

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "test: add conftest with seeded-cache, dummy-tio, smtp fixtures"
```

---

## Task 8: Layer 1 — per-module contract tests

**Files:**
- Create: `tests/unit/test_modules.py`

Module IDs come from `registry.list_all()` (`reports/modules/registry.py:158`). `compute()` signature is `(vulns_df, assets_df, report_date, config, **kwargs)` (`base.py:200`). Renderers: `render_pdf_section(data, config)`, `render_excel_tabs(data, workbook, config)`, `render_email_panel(data, config)`, `render_analyst_tabs(data, config)`, `render_rag_strip_entry(data, config)`.

- [ ] **Step 1: Write `tests/unit/test_modules.py`**

```python
"""
tests/unit/test_modules.py — Layer 1 four-channel contract per registered module.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from openpyxl import Workbook

from reports.modules import registry
from reports.modules.base import ModuleConfig, ModuleData

pytestmark = pytest.mark.unit

_NOW = datetime.now(tz=timezone.utc)
MODULE_IDS = [m["module_id"] for m in registry.list_all()]


def _compute(module_id, vulns_df, assets_df):
    inst = registry.get(module_id)()
    return inst, inst.compute(vulns_df, assets_df, _NOW, ModuleConfig(module_id))


def test_registry_is_not_empty():
    assert MODULE_IDS, "registry.discover() found no modules"


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_compute_returns_moduledata(module_id, synthetic_vulns_df, synthetic_assets_df):
    _, data = _compute(module_id, synthetic_vulns_df, synthetic_assets_df)
    assert isinstance(data, ModuleData)


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_four_channel_types(module_id, synthetic_vulns_df, synthetic_assets_df):
    inst, data = _compute(module_id, synthetic_vulns_df, synthetic_assets_df)
    cfg = ModuleConfig(module_id)
    assert isinstance(inst.render_pdf_section(data, cfg), str)
    assert isinstance(inst.render_excel_tabs(data, Workbook(), cfg), list)
    assert isinstance(inst.render_email_panel(data, cfg), str)
    assert isinstance(inst.render_analyst_tabs(data, cfg), list)
    strip = inst.render_rag_strip_entry(data, cfg)
    assert isinstance(strip, dict)
    assert {"label", "headline_value", "rag_color", "rag_label"} <= set(strip)


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_empty_data_guard(module_id, empty_vulns_df, empty_assets_df):
    """Zero-row input must not raise in compute() or any renderer."""
    inst, data = _compute(module_id, empty_vulns_df, empty_assets_df)
    cfg = ModuleConfig(module_id)
    assert isinstance(data, ModuleData)
    inst.render_pdf_section(data, cfg)
    inst.render_excel_tabs(data, Workbook(), cfg)
    inst.render_email_panel(data, cfg)
    inst.render_analyst_tabs(data, cfg)
    inst.render_rag_strip_entry(data, cfg)
```

- [ ] **Step 2: Run Layer 1**

Run: `python -m pytest tests/unit/test_modules.py -v`
Expected: PASS for every parametrized module across all four tests. If a module raises on empty data, that's a real empty-data-guard bug — fix the module per CLAUDE.md's `safe_pct`/`_empty_result` pattern, do not weaken the test.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_modules.py
git commit -m "test: Layer 1 four-channel + empty-data contract per module"
```

---

## Task 9: Layer 2 — exact value assertions

**Files:**
- Create: `tests/content/test_values.py`

- [ ] **Step 1: Write `tests/content/test_values.py`**

```python
"""
tests/content/test_values.py — Layer 2 exact-value assertions on known fixtures.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from config import vpr_to_severity
from tests.fixtures.builders import AS_OF, three_overdue_crit
from tests.fixtures.generator import make_scenario
from utils.sla_calculator import apply_sla_to_df, get_sla_status

pytestmark = pytest.mark.content


def test_three_overdue_criticals_counts_exactly_three():
    df = apply_sla_to_df(three_overdue_crit(), as_of=AS_OF)
    assert int(df["is_overdue"].sum()) == 3


def test_null_vpr_falls_back_to_native_severity():
    """vpr_to_severity (config.py:79): None score → fallback; real score → VPR band."""
    assert vpr_to_severity(None, fallback="high") == "high"
    assert vpr_to_severity(9.5, fallback="low") == "critical"


def test_overdue_boundary_is_strict_greater_than():
    """days_open == sla_days is Within SLA; days_open > sla_days is Overdue."""
    at_limit = get_sla_status("critical", AS_OF - timedelta(days=15), False, as_of=AS_OF)
    over = get_sla_status("critical", AS_OF - timedelta(days=16), False, as_of=AS_OF)
    assert at_limit["status"] == "Within SLA"
    assert at_limit["is_overdue"] is False
    assert over["status"] == "Overdue"
    assert over["is_overdue"] is True


def test_generator_overdue_matches_expected():
    vulns, _, expected = make_scenario(seed=42, as_of=AS_OF)
    df = apply_sla_to_df(vulns, as_of=AS_OF)
    assert int(df["is_overdue"].sum()) == expected["overdue_count"]


def test_remediated_is_never_overdue():
    res = get_sla_status("critical", AS_OF - timedelta(days=99), True, as_of=AS_OF)
    assert res["status"] == "Remediated"
    assert res["is_overdue"] is False
```

- [ ] **Step 2: Run Layer 2**

Run: `python -m pytest tests/content/test_values.py -v`
Expected: 5 PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/content/test_values.py
git commit -m "test: Layer 2 exact SLA value + boundary assertions"
```

---

## Task 10: Layer 3 — config-driven artifacts

**Files:**
- Create: `tests/e2e/test_groups.py`

`run_group` signature (`run_all.py:523`): keyword-only `tio`, `cache_dir`, `base_output_dir`, `no_email`, `recipient_override`. It always returns a dict with `status` in `{success, partial, failed}` and never raises.

- [ ] **Step 1: Write the artifact half of `tests/e2e/test_groups.py`**

```python
"""
tests/e2e/test_groups.py — Layer 3 config-driven E2E.

Seeds a temp parquet cache, runs the REAL run_group per delivery_config.yaml
group with a DummyTio (cache short-circuit means it's never called), then
validates artifacts and the captured MIME email.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from run_all import run_group
from tests.validators import assert_valid_pdf, assert_valid_xlsx

pytestmark = pytest.mark.e2e

_ROOT = Path(__file__).resolve().parent.parent.parent
_GROUPS = yaml.safe_load((_ROOT / "delivery_config.yaml").read_text())["groups"]
_GROUP_IDS = [g["name"] for g in _GROUPS]


@pytest.mark.parametrize("group", _GROUPS, ids=_GROUP_IDS)
def test_group_runs_fail_soft_and_artifacts_valid(
    group, seeded_cache, temp_output_dir, dummy_tio
):
    result = run_group(
        group,
        tio=dummy_tio,
        cache_dir=seeded_cache,
        base_output_dir=temp_output_dir,
        no_email=True,
        recipient_override=["test@example.com"],
    )
    assert result["status"] in ("success", "partial"), result.get("error")

    out = Path(result["output_folder"])
    for pdf in out.rglob("*.pdf"):
        assert_valid_pdf(pdf)
    for xlsx in out.rglob("*.xlsx"):
        assert_valid_xlsx(xlsx)


# --- Failure-mode scenarios driven through the real pipeline -----------

import pandas as pd  # noqa: E402

from tests.fixtures.scenarios import (  # noqa: E402
    null_first_found, null_vpr, zero_match,
)

_SCENARIOS = {
    "zero_match": zero_match,
    "null_vpr": null_vpr,
    "null_first_found": null_first_found,
}


def _cache_from(cache_dir: Path, vulns: pd.DataFrame, assets: pd.DataFrame) -> Path:
    """Write a scenario's dfs into a cache dir (fastparquet, all 4 datasets)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    datasets = {
        "vulns_all": vulns,
        "assets_all": assets,
        "vulns_fixed": vulns.iloc[0:0].copy(),
        "recast_rules": pd.DataFrame(),
    }
    for name, df in datasets.items():
        df.to_parquet(cache_dir / f"{name}.parquet", index=False, engine="fastparquet")
    return cache_dir


@pytest.mark.parametrize("scenario_name", list(_SCENARIOS))
def test_failure_mode_scenarios_run_fail_soft(
    scenario_name, tmp_path, temp_output_dir, dummy_tio
):
    """ZERO_MATCH / null-VPR / null-first-found must not crash run_group."""
    vulns, assets = _SCENARIOS[scenario_name]()
    cache = _cache_from(tmp_path / "scenario-cache", vulns, assets)
    result = run_group(
        _GROUPS[0],
        tio=dummy_tio,
        cache_dir=cache,
        base_output_dir=temp_output_dir,
        no_email=True,
        recipient_override=["test@example.com"],
    )
    assert result["status"] in ("success", "partial"), result.get("error")
```

- [ ] **Step 2: Run the artifact + scenario tests**

Run: `python -m pytest tests/e2e/test_groups.py -v`
Expected: every group PASS with status success/partial; the 3 failure-mode scenarios PASS (no crash); any produced PDF/Excel validates. A `DummyTio.<attr> accessed` AssertionError means a fetcher escaped the cache — seed that dataset in the `seeded_cache` fixture.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_groups.py
git commit -m "test: Layer 3 config-driven artifact validation via run_group"
```

---

## Task 11: Layer 3 — SMTP delivery + failure modes

**Files:**
- Modify: `tests/e2e/test_groups.py` (append)

`send_report_email` reads SMTP_* env (`email_sender.py:78`) and enforces `MAX_ATTACHMENT_SIZE_MB`. To force the oversize fallback deterministically we monkeypatch that constant on the module to `0`.

- [ ] **Step 1: Append the delivery + failure-mode tests to `tests/e2e/test_groups.py`**

```python
# --- SMTP delivery + failure modes -------------------------------------

from email import message_from_bytes  # noqa: E402

from tests.validators import (  # noqa: E402
    assert_email_cids_resolve, assert_well_formed_html,
)

_FIRST_GROUP = _GROUPS[0]


def _attachment_filenames(msg) -> list[str]:
    return [
        p.get_filename()
        for p in msg.walk()
        if p.get_filename()
    ]


def test_group_email_is_captured_and_well_formed(
    seeded_cache, temp_output_dir, dummy_tio, smtp_catcher
):
    run_group(
        _FIRST_GROUP,
        tio=dummy_tio,
        cache_dir=seeded_cache,
        base_output_dir=temp_output_dir,
        no_email=False,
        recipient_override=["test@example.com"],
    )
    assert len(smtp_catcher.messages) == 1
    msg = smtp_catcher.messages[0]

    html = "".join(
        p.get_payload(decode=True).decode("utf-8", "replace")
        for p in msg.walk()
        if p.get_content_type() == "text/html"
    )
    assert_well_formed_html(html)
    assert_email_cids_resolve(msg)
    # At least one PDF attachment present.
    assert any(str(f).lower().endswith(".pdf") for f in _attachment_filenames(msg))


def test_oversize_attachments_fall_back_to_pdf_only(
    seeded_cache, temp_output_dir, dummy_tio, smtp_catcher, monkeypatch
):
    import delivery.email_sender as es
    monkeypatch.setattr(es, "MAX_ATTACHMENT_SIZE_MB", 0)

    run_group(
        _FIRST_GROUP,
        tio=dummy_tio,
        cache_dir=seeded_cache,
        base_output_dir=temp_output_dir,
        no_email=False,
        recipient_override=["test@example.com"],
    )
    assert len(smtp_catcher.messages) == 1
    files = [str(f).lower() for f in _attachment_filenames(smtp_catcher.messages[0])]
    assert not any(f.endswith(".xlsx") for f in files), "Excel should be omitted when oversize"


def test_empty_recipient_list_is_skipped_not_sent(
    seeded_cache, temp_output_dir, dummy_tio, smtp_catcher
):
    group = dict(_FIRST_GROUP)
    group["email"] = dict(group.get("email", {}))
    group["email"]["recipients"] = []
    group["email"]["cc"] = []

    result = run_group(
        group,
        tio=dummy_tio,
        cache_dir=seeded_cache,
        base_output_dir=temp_output_dir,
        no_email=False,
    )
    assert len(smtp_catcher.messages) == 0
    assert result["status"] in ("success", "partial", "failed")
```

- [ ] **Step 2: Run the delivery + failure-mode tests**

Run: `python -m pytest tests/e2e/test_groups.py -k "email or oversize or recipient" -v`
Expected: 3 PASS. The `.eml` files appear under `output/test-eml/`. Open one in Outlook/browser to eyeball.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_groups.py
git commit -m "test: Layer 3 SMTP delivery, oversize fallback, empty-recipient skip"
```

---

## Task 12: Full-suite run + timing baseline

**Files:**
- None (verification + measurement only)

- [ ] **Step 1: Run the whole suite in parallel**

Run: `python -m pytest`
Expected: all layers green.

- [ ] **Step 2: Measure wall-clock**

Run (PowerShell): `Measure-Command { python -m pytest } | Select-Object TotalSeconds`
Record the number. If it's painfully slow on commit (subjective; note it in the PR/commit), the documented fallback is to move `@pytest.mark.e2e` to a pre-push hook — but per the design we keep everything on pre-commit for now.

- [ ] **Step 3: Add `.eml` dump dir to `.gitignore`**

Add this line to `.gitignore`:

```
output/test-eml/
```

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "test: ignore captured .eml dump dir"
```

---

## Task 13: Pre-commit hook + escape hatch + docs

**Files:**
- Create: `.githooks/pre-commit`
- Modify: `RUNBOOK.md` (append a "Local E2E test suite" section)

- [ ] **Step 1: Write `.githooks/pre-commit`**

```sh
#!/bin/sh
# Pre-commit gate: runs the local E2E test suite.
# Emergency bypass:  VULN_E2E_SKIP=1 git commit ...
if [ "$VULN_E2E_SKIP" = "1" ]; then
    echo "!!! VULN_E2E_SKIP=1 set — SKIPPING the E2E test suite. Use only in emergencies. !!!"
    exit 0
fi

echo "Running local E2E test suite (set VULN_E2E_SKIP=1 to bypass in emergencies)..."
python -m pytest -n auto -q
status=$?
if [ "$status" -ne 0 ]; then
    echo "E2E suite FAILED — commit aborted. Fix the tests or set VULN_E2E_SKIP=1 to bypass."
fi
exit "$status"
```

- [ ] **Step 2: Make it executable and register the hooks path**

Run:
```bash
git update-index --chmod=+x .githooks/pre-commit
git config core.hooksPath .githooks
```
Expected: no output (success). `git config core.hooksPath` now returns `.githooks`.

- [ ] **Step 3: Append the docs section to `RUNBOOK.md`**

Add this section at the end of `RUNBOOK.md`:

```markdown
## Local E2E Test Suite

Offline pytest suite that validates reports before every commit (no Tenable, no VM).

**One-time setup:**

    pip install -r requirements-dev.txt
    git config core.hooksPath .githooks

**Run manually:**

    python -m pytest            # whole suite, parallel
    python -m pytest -m unit    # Layer 1 only (per-module contract)
    python -m pytest -m content # Layer 2 only (exact values)
    python -m pytest -m e2e     # Layer 3 only (run_group + SMTP)

**Pre-commit gate:** the `.githooks/pre-commit` hook runs the full suite on
every `git commit`. Emergency bypass (use sparingly):

    VULN_E2E_SKIP=1 git commit -m "..."

**Eyeball a delivered email:** captured messages are written to
`output/test-eml/message_NNN.eml` — open in Outlook / a browser.
```

- [ ] **Step 4: Verify the hook fires**

Run: `git commit --allow-empty -m "chore: verify pre-commit hook fires"`
Expected: the suite runs before the commit completes; commit succeeds only if green.

- [ ] **Step 5: Commit the hook + docs**

```bash
git add .githooks/pre-commit RUNBOOK.md
git commit -m "test: add pre-commit E2E gate with emergency bypass + RUNBOOK docs"
```

---

## Task 14 (follow-on slice): Migrate legacy standalone tests

**Files:**
- Modify: existing `tests/test_*.py` (one per commit)

This is the bounded migration slice from the spec — kept separate so the new harness lands first and works standalone. Do this only after Tasks 1–13 are green.

- [ ] **Step 1: Inventory legacy scripts**

Run: `python -m pytest tests/ --collect-only -q 2>&1 | tail -20`
Note which `tests/test_*.py` define no `test_` functions (they use `main()`/`_check`).

- [ ] **Step 2: Migrate one script to pytest functions**

For one legacy file, convert its `_check(name, cond)` calls into `assert cond, name` inside `test_*` functions, and drop its `main()`/`sys.argv` block. Keep the existing fixtures it built inline or move them to `conftest.py` if shared.

- [ ] **Step 3: Add the migrated file's dir to `testpaths`**

If the migrated file lives directly in `tests/`, extend `pytest.ini` `testpaths` to include `tests` (or move the file under `tests/unit|content|e2e`). Prefer moving it under the matching layer dir to keep `testpaths` tight.

- [ ] **Step 4: Run and commit per migrated file**

Run: `python -m pytest <migrated file> -v`
Expected: PASS. Then:

```bash
git add <migrated file> pytest.ini
git commit -m "test: migrate <name> to pytest"
```

Repeat Steps 2–4 for each remaining legacy script.

---

## Notes for the implementer

- **fastparquet is mandatory** for fixture parquets — `_load_cache` reads with `engine="fastparquet"` (`data/fetchers.py:230`). A pyarrow-written file may not round-trip identically.
- **DummyTio is a tripwire**, not a stub: any attribute access raises, proving the cache short-circuit held. If a test trips it, seed the missing dataset in `seeded_cache` rather than fleshing out the dummy.
- **Empty-data guard failures are real bugs.** If Task 8's `test_empty_data_guard` fails for a module, fix the module (`safe_pct`/`safe_int`/`_empty_result` per CLAUDE.md) — never weaken the test.
- **xdist + random SMTP port**: each worker gets its own catcher on an OS-assigned port, so parallel runs don't collide.
```
