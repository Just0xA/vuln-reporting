"""
reports/modules/sc4_kwargs_stub_module.py — Phase 14 SC#4 acceptance-test stub.

Verifies that ``trend_snapshots`` and ``recast_rules_df`` kwargs arrive at
``compute()`` when this module ID is seeded in the
``_MODULES_NEEDING_TREND_SNAPSHOTS`` and ``_MODULES_NEEDING_RECAST_RULES``
frozensets in ``reports/composed_report.py``.

NOT for production delivery groups.  Include it in a composed-report group
only for acceptance testing the kwargs-forwarding gates (SC#4, D-16, D-17).
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from reports.modules.base import BaseModule, ModuleConfig, ModuleData
from reports.modules.registry import register_module

logger = logging.getLogger(__name__)


@register_module
class Sc4KwargsStubModule(BaseModule):
    """
    SC#4 test stub — verifies trend_snapshots and recast_rules_df kwargs
    arrive at compute() when this module ID is in the frozensets.
    NOT for production delivery groups.
    """

    MODULE_ID         = "sc4_kwargs_stub"
    DISPLAY_NAME      = "SC#4 kwargs gate stub"
    DESCRIPTION       = "Phase 14 acceptance test only — not for production delivery groups."
    REQUIRED_DATA     = []
    SUPPORTED_OUTPUTS = []
    VERSION           = "1.0.0"

    def compute(
        self,
        vulns_df:    pd.DataFrame,
        assets_df:   pd.DataFrame,
        report_date: Any,
        config:      ModuleConfig,
        **kwargs:    Any,
    ) -> ModuleData:
        """
        Assert that both kwargs forwarded by the composed_report gates are present.

        Returns a ``ModuleData`` with metrics recording presence and counts when
        both arrive, or ``_empty_result`` (fail-soft, never raises) when either
        is missing.
        """
        try:
            trend_snapshots = kwargs.get("trend_snapshots")
            recast_rules_df = kwargs.get("recast_rules_df")

            errors = []
            if trend_snapshots is None:
                errors.append("trend_snapshots kwarg missing")
            if recast_rules_df is None:
                errors.append("recast_rules_df kwarg missing")

            if errors:
                logger.error(
                    "%s compute() kwarg assertions failed: %s",
                    self._log_prefix(),
                    errors,
                )
                return self._empty_result("; ".join(errors), config)

            return ModuleData(
                module_id    = self.MODULE_ID,
                display_name = self.DISPLAY_NAME,
                metrics      = {
                    "trend_snapshots_present": True,
                    "recast_rules_df_present": True,
                    "trend_snapshot_count":    len(trend_snapshots.get("snapshots", [])),
                    "recast_rules_row_count":  len(recast_rules_df),
                },
                table_data   = [],
                chart_data   = {},
                summary_text = "SC#4 stub: both kwargs arrived at compute().",
                metadata     = {"computed_at": str(report_date)},
                error        = None,
            )

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "%s compute() failed: %s", self._log_prefix(), exc,
                exc_info=True,
            )
            return self._empty_result(str(exc), config)
