"""
reports/modules — Report module library for the vulnerability management suite.

This package provides the infrastructure for composing reports from reusable,
independently testable metric modules.

Quick start
-----------
Using an existing module in a report script::

    from reports.modules import registry, ReportComposer
    from reports.modules.base import ModuleConfig

    composer = ReportComposer(
        vulns_df=vulns_df,
        assets_df=assets_df,
        report_date=generated_at,
        module_configs=[
            ModuleConfig("sla_summary"),
            ModuleConfig("asset_risk", options={"top_n": 25}),
        ],
    )
    results  = composer.run_all()
    pdf_html = composer.assemble_pdf(results)
    kpis     = composer.collect_email_kpis(results)

Creating a new module::

    # reports/modules/my_metric_module.py
    from reports.modules import register_module
    from reports.modules.base import BaseModule, ModuleConfig, ModuleData

    @register_module
    class MyMetricModule(BaseModule):
        MODULE_ID    = "my_metric"
        DISPLAY_NAME = "My Metric"
        ...

    # That's it — the module is auto-discovered on next import.

Exports
-------
registry          — Global ModuleRegistry instance
register_module   — @register_module class decorator
BaseModule        — Abstract base class for all modules
ModuleConfig      — Configuration dataclass (sourced from delivery_config.yaml)
ModuleData        — Structured output dataclass returned by compute()
ReportComposer    — Orchestration and assembly utilities
"""

from __future__ import annotations

# Registry and decorator first — modules imported below depend on these
# being available when their @register_module decorator executes.
from reports.modules.registry import registry, register_module  # noqa: F401

# Core data contracts
from reports.modules.base import BaseModule, ModuleConfig, ModuleData  # noqa: F401

# Composition utilities
from reports.modules.composer import ReportComposer  # noqa: F401

# Trigger auto-discovery of all *_module.py and *_metrics.py files in
# this directory. Modules self-register via @register_module on import.
# This call is intentionally last so that the registry and base classes
# are fully initialised before any module file is imported.
registry.discover()

__all__ = [
    "registry",
    "register_module",
    "BaseModule",
    "ModuleConfig",
    "ModuleData",
    "ReportComposer",
]
