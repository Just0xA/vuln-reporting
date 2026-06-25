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


def _load_groups() -> list[dict]:
    """Prefer the operator's real config; fall back to the tracked example.

    delivery_config.yaml is gitignored (operator-managed) so it may be absent
    on a fresh checkout. The example is always tracked. If neither exists,
    return [] and the parametrized tests simply collect nothing.
    """
    for name in ("delivery_config.yaml", "delivery_config.example.yaml"):
        path = _ROOT / name
        if path.exists():
            return yaml.safe_load(path.read_text()).get("groups", []) or []
    return []


_GROUPS = _load_groups()
_GROUP_IDS = [g["name"] for g in _GROUPS]

# CR-T1: guard the module-level _GROUPS[0] access — when _load_groups() returns
# empty, pytest.skip at collection time so an empty-groups env does not break
# collection with an IndexError.
if not _GROUPS:
    pytest.skip(
        "No delivery groups configured — skipping e2e group tests",
        allow_module_level=True,
    )

_FIRST_GROUP = _GROUPS[0]


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
    # Don't let a regression-to-zero-artifacts pass silently: every real group
    # here is expected to emit at least one PDF.
    pdfs = list(out.rglob("*.pdf"))
    assert pdfs, f"group '{group['name']}' produced no PDF in {out}"
    for pdf in pdfs:
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
    import config as _config  # noqa: PLC0415
    cache_dir.mkdir(parents=True, exist_ok=True)
    # CR-B5: fixed-vuln cache file is keyed by lookback window; seed the default.
    fixed_key = f"vulns_fixed_{_config.FIXED_LOOKBACK_DAYS}d"
    datasets = {
        "vulns_all": vulns,
        "assets_all": assets,
        fixed_key: vulns.iloc[0:0].copy(),
        "recast_rules": pd.DataFrame({"_": pd.Series([], dtype="object")}),
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
        _FIRST_GROUP,
        tio=dummy_tio,
        cache_dir=cache,
        base_output_dir=temp_output_dir,
        no_email=True,
        recipient_override=["test@example.com"],
    )
    assert result["status"] in ("success", "partial"), result.get("error")


# --- SMTP delivery + failure modes -------------------------------------

from tests.validators import (  # noqa: E402
    assert_email_cids_resolve, assert_well_formed_html,
)


def _attachment_filenames(msg) -> list:
    return [p.get_filename() for p in msg.walk() if p.get_filename()]


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
