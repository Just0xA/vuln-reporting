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
        "recast_rules": pd.DataFrame({"_": pd.Series([], dtype="object")}),  # fastparquet requires >=1 column
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
