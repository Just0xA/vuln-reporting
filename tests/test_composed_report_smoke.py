"""
tests/test_composed_report_smoke.py — composed_report four-channel smoke.

Drives ``composed_report.run_report`` end-to-end with monkey-patched
fetchers (no Tenable round trip), asserting the four-channel bundle
contract:

  A — modules=[scan_coverage_sla] returns a dict whose pdf is a real
      Path on disk, excel is a real Path on disk, email_body_html is a
      non-empty str, and analyst_excel is a Path or None.
  B — analyst_detail=False forces analyst_excel to None and writes no
      analyst .xlsx to the output directory.
  C — modules=[critical_remediation_sla] triggers
      fetch_fixed_vulnerabilities (other module compositions must
      not).

Run: python tests/test_composed_report_smoke.py
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Importing composed_report transitively triggers registry.discover().
from reports import composed_report  # noqa: E402
from data import fetchers as _fetchers  # noqa: E402

FAILED: list[str] = []


def _check(name: str, cond: bool, hint: str = "") -> None:
    if cond:
        print(f"PASS  {name}")
    else:
        FAILED.append(name)
        print(f"FAIL  {name}{(': ' + hint) if hint else ''}")


def _empty_vulns_df() -> pd.DataFrame:
    """Empty open-vulns DataFrame with the columns scan_coverage_sla touches."""
    return pd.DataFrame({
        "asset_uuid": pd.Series([], dtype="string"),
        "severity":   pd.Series([], dtype="string"),
    })


def _empty_assets_df() -> pd.DataFrame:
    """Empty assets DataFrame with the columns _filter_assets_by_tag + modules touch."""
    return pd.DataFrame({
        "asset_uuid":               pd.Series([], dtype="string"),
        "hostname":                 pd.Series([], dtype="string"),
        "ipv4":                     pd.Series([], dtype="string"),
        "fqdn":                     pd.Series([], dtype="string"),
        "tags":                     pd.Series([], dtype="string"),
        "last_licensed_scan_date":  pd.to_datetime([], utc=True, errors="coerce"),
    })


def _empty_fixed_df() -> pd.DataFrame:
    return pd.DataFrame({
        "asset_uuid":            pd.Series([], dtype="string"),
        "severity":              pd.Series([], dtype="string"),
    })


class _FixedCallCounter:
    """Tracks invocations of fetch_fixed_vulnerabilities."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, tio, cache_dir):
        self.calls += 1
        return _empty_fixed_df()


def _install_fetcher_patches(fixed_counter: _FixedCallCounter) -> None:
    """Replace the three fetch_* functions on both ``data.fetchers`` and
    the names already imported into ``reports.composed_report``."""
    def _vulns(tio, cache_dir):
        return _empty_vulns_df()

    def _assets(tio, cache_dir):
        return _empty_assets_df()

    _fetchers.fetch_all_vulnerabilities = _vulns
    _fetchers.fetch_all_assets          = _assets
    _fetchers.fetch_fixed_vulnerabilities = fixed_counter

    composed_report.fetch_all_vulnerabilities    = _vulns
    composed_report.fetch_all_assets             = _assets
    composed_report.fetch_fixed_vulnerabilities  = fixed_counter


def _run_smoke(
    modules: list[str],
    *,
    analyst_detail: bool = True,
    fixed_counter: _FixedCallCounter | None = None,
) -> tuple[dict, Path]:
    """Call composed_report.run_report in an isolated temp dir."""
    fc = fixed_counter or _FixedCallCounter()
    _install_fetcher_patches(fc)

    tmp = Path(tempfile.mkdtemp(prefix="composed_smoke_"))
    out = tmp / "out"
    cache = tmp / "cache"
    out.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)

    result = composed_report.run_report(
        tio          = None,
        run_id       = "smoke",
        output_dir   = out,
        cache_dir    = cache,
        generated_at = datetime.now(tz=timezone.utc),
        modules      = modules,
        analyst_detail = analyst_detail,
    )
    return result, out


def main() -> int:
    # ----------------------------------------------------------------
    # A — single-module composition, analyst_detail=True
    # ----------------------------------------------------------------
    result_a, out_a = _run_smoke(["scan_coverage_sla"])

    pdf = result_a.get("pdf")
    _check(
        "A_pdf_is_existing_path",
        isinstance(pdf, Path) and pdf.exists(),
        hint=f"pdf={pdf!r}",
    )

    excel = result_a.get("excel")
    _check(
        "A_excel_is_existing_path",
        isinstance(excel, Path) and excel.exists(),
        hint=f"excel={excel!r}",
    )

    body = result_a.get("email_body_html", "")
    _check(
        "A_email_body_html_nonempty_str",
        isinstance(body, str) and bool(body.strip()),
        hint=f"len={len(body) if isinstance(body, str) else '?'}",
    )

    analyst = result_a.get("analyst_excel")
    _check(
        "A_analyst_excel_path_or_none",
        analyst is None or (isinstance(analyst, Path) and analyst.exists()),
        hint=f"analyst={analyst!r}",
    )

    # ----------------------------------------------------------------
    # B — analyst_detail=False -> analyst_excel is None, no analyst file
    # ----------------------------------------------------------------
    result_b, out_b = _run_smoke(["scan_coverage_sla"], analyst_detail=False)
    analyst_off = result_b.get("analyst_excel")
    _check(
        "B_analyst_off_returns_none",
        analyst_off is None,
        hint=f"analyst={analyst_off!r}",
    )
    leftover = list(out_b.glob("**/*analyst*.xlsx"))
    _check(
        "B_analyst_off_no_orphan_file",
        leftover == [],
        hint=f"leftover={leftover}",
    )

    # ----------------------------------------------------------------
    # C — critical_remediation_sla triggers fixed-vulns fetch;
    #     scan_coverage_sla alone does not.
    # ----------------------------------------------------------------
    counter_crit = _FixedCallCounter()
    _run_smoke(
        ["critical_remediation_sla"],
        fixed_counter=counter_crit,
    )
    _check(
        "C_critical_remediation_sla_triggers_fixed_fetch",
        counter_crit.calls == 1,
        hint=f"calls={counter_crit.calls}",
    )

    counter_scan = _FixedCallCounter()
    _run_smoke(
        ["scan_coverage_sla"],
        fixed_counter=counter_scan,
    )
    _check(
        "C_scan_coverage_sla_does_not_fetch_fixed",
        counter_scan.calls == 0,
        hint=f"calls={counter_scan.calls}",
    )

    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed: {FAILED}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
