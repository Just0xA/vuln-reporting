"""
reports/modules/registry.py — Module registry and auto-discovery.

Modules register themselves using the ``@register_module`` decorator.
The registry auto-discovers all files matching ``*_module.py`` or
``*_metrics.py`` in the modules/ directory when ``registry.discover()``
is called (triggered automatically by importing the package).

Usage
-----
Registering a new module::

    from reports.modules.registry import register_module
    from reports.modules.base import BaseModule, ModuleConfig, ModuleData

    @register_module
    class MySLAModule(BaseModule):
        MODULE_ID    = "sla_summary"
        DISPLAY_NAME = "SLA Summary"
        ...

Accessing the registry::

    from reports.modules import registry

    mod_class = registry.get("sla_summary")
    instance  = mod_class()

    all_modules = registry.list_all()
    valid, invalid = registry.validate_module_list(["sla_summary", "bad_id"])
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reports.modules.base import BaseModule

logger = logging.getLogger(__name__)

# Filename patterns that trigger auto-discovery
_DISCOVERY_PATTERNS: tuple[str, ...] = ("*_module.py", "*_metrics.py")

# Files in the modules/ directory that are infrastructure — never treated
# as metric modules during discovery.
_INFRASTRUCTURE_FILES: frozenset[str] = frozenset({
    "__init__.py",
    "base.py",
    "registry.py",
    "composer.py",
})


class ModuleRegistry:
    """
    Central registry for all available report modules.

    Modules self-register by being imported via the ``@register_module``
    decorator.  The registry discovers modules automatically from the
    ``modules/`` package directory — no manual listing required.

    A single global instance (``registry``) is created at the bottom of
    this file and re-exported from ``reports/modules/__init__.py``.

    Thread safety
    -------------
    Registration and discovery are expected to happen at import time
    (single-threaded startup).  The registry is not designed for
    concurrent mutation at runtime.
    """

    def __init__(self) -> None:
        self._modules: dict[str, type[BaseModule]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, module_class: type[BaseModule]) -> None:
        """
        Register a module class by its ``MODULE_ID``.

        Called automatically by the ``@register_module`` decorator.
        Logs a warning and skips if:
        - ``MODULE_ID`` is empty or not a string
        - A module with the same ID is already registered (the first
          registration wins; re-registration is a no-op with a warning)

        Parameters
        ----------
        module_class : type[BaseModule]
            The module class to register.  Must have a non-empty
            ``MODULE_ID`` class attribute.
        """
        module_id = getattr(module_class, "MODULE_ID", "")

        if not module_id or not isinstance(module_id, str):
            logger.warning(
                "ModuleRegistry.register: skipping %r — MODULE_ID is "
                "empty or not a string.",
                module_class,
            )
            return

        if module_id in self._modules:
            existing = self._modules[module_id]
            if existing is module_class:
                # Exact same class re-imported (e.g. during reload) — silent no-op
                return
            logger.warning(
                "ModuleRegistry.register: MODULE_ID %r is already registered "
                "by %r. Keeping the original; ignoring %r.",
                module_id,
                existing.__qualname__,
                module_class.__qualname__,
            )
            return

        self._modules[module_id] = module_class
        logger.debug(
            "ModuleRegistry: registered '%s' → %s v%s",
            module_id,
            module_class.__qualname__,
            getattr(module_class, "VERSION", "?"),
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, module_id: str) -> type[BaseModule] | None:
        """
        Return the module class for ``module_id``, or ``None`` if not found.

        Parameters
        ----------
        module_id : str
            The ``MODULE_ID`` string to look up.

        Returns
        -------
        type[BaseModule] or None
        """
        result = self._modules.get(module_id)
        if result is None:
            logger.debug(
                "ModuleRegistry.get: '%s' not found. Registered: %s",
                module_id,
                sorted(self._modules.keys()),
            )
        return result

    def list_all(self) -> list[dict]:
        """
        Return metadata for all registered modules, sorted by MODULE_ID.

        Each entry is a dict with the keys returned by
        ``BaseModule.get_audit_info()`` plus ``class_name``.

        Returns
        -------
        list[dict]
            One dict per registered module, sorted by ``module_id``.
        """
        results = []
        for module_id, cls in sorted(self._modules.items()):
            try:
                info = cls().get_audit_info()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ModuleRegistry.list_all: get_audit_info() failed for "
                    "'%s': %s",
                    module_id, exc,
                )
                info = {"module_id": module_id}

            info["class_name"] = cls.__qualname__
            results.append(info)

        return results

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_module_list(
        self,
        module_ids: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        Validate a list of module IDs against the registry.

        Parameters
        ----------
        module_ids : list[str]
            Module IDs to validate (e.g. from delivery_config.yaml).

        Returns
        -------
        tuple[list[str], list[str]]
            ``(valid_ids, invalid_ids)`` — preserving input order.
        """
        valid:   list[str] = []
        invalid: list[str] = []

        for mid in module_ids:
            if mid in self._modules:
                valid.append(mid)
            else:
                invalid.append(mid)
                logger.warning(
                    "ModuleRegistry.validate_module_list: unknown module "
                    "id %r. Registered ids: %s",
                    mid, sorted(self._modules.keys()),
                )

        return valid, invalid

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def discover(self, modules_dir: Path | None = None) -> None:
        """
        Auto-discover and import all module files in the ``modules/``
        directory.

        Any file matching ``*_module.py`` or ``*_metrics.py`` (see
        ``_DISCOVERY_PATTERNS``) is imported.  Modules register
        themselves on import via the ``@register_module`` decorator.

        Infrastructure files (``base.py``, ``registry.py``, etc.) are
        explicitly skipped so they are never mistakenly imported as
        metric modules.

        Parameters
        ----------
        modules_dir : Path, optional
            Directory to scan.  Defaults to the ``modules/`` package
            directory (i.e. the directory containing this file).

        Notes
        -----
        - Discovery is idempotent: importing an already-registered
          module class is a safe no-op (registry.register() handles it).
        - Import errors in individual files are caught and logged as
          warnings — a broken module file will not prevent other modules
          from loading.
        - The example_module.py is discovered automatically because it
          matches the ``*_module.py`` pattern.
        """
        if modules_dir is None:
            modules_dir = Path(__file__).resolve().parent

        candidates: list[Path] = []
        for pattern in _DISCOVERY_PATTERNS:
            candidates.extend(modules_dir.glob(pattern))

        # Deduplicate (a file could match both patterns in theory) and sort
        seen: set[Path] = set()
        unique_candidates: list[Path] = []
        for path in sorted(candidates):
            if path not in seen:
                seen.add(path)
                unique_candidates.append(path)

        if not unique_candidates:
            logger.debug(
                "ModuleRegistry.discover: no module files found in %s "
                "matching %s",
                modules_dir, _DISCOVERY_PATTERNS,
            )
            return

        # Determine the Python package prefix for importlib
        # (e.g. "reports.modules" when modules_dir is reports/modules/).
        # Prefer deriving from this module's own __name__ (already resolved
        # correctly by Python's import system, handles namespace packages).
        # Falls back to the file-walk approach when run outside a package
        # context (e.g. direct script execution).
        package_prefix = _package_prefix_from_name(__name__) or _resolve_package_prefix(modules_dir)

        before_count = len(self._modules)

        for path in unique_candidates:
            if path.name in _INFRASTRUCTURE_FILES:
                logger.debug(
                    "ModuleRegistry.discover: skipping infrastructure "
                    "file %s",
                    path.name,
                )
                continue

            _import_module_file(path, package_prefix)

        after_count = len(self._modules)
        newly_registered = after_count - before_count

        logger.info(
            "ModuleRegistry.discover: scanned %d file(s) in %s — "
            "%d module(s) newly registered (%d total).",
            len(unique_candidates),
            modules_dir,
            newly_registered,
            after_count,
        )

    def __repr__(self) -> str:
        return (
            f"ModuleRegistry("
            f"{len(self._modules)} modules: "
            f"{sorted(self._modules.keys())})"
        )

    def __len__(self) -> int:
        return len(self._modules)

    def __contains__(self, module_id: str) -> bool:
        return module_id in self._modules


# ===========================================================================
# Internal helpers
# ===========================================================================

def _package_prefix_from_name(module_name: str) -> str:
    """
    Derive the package prefix from a fully-qualified module name.

    ``"reports.modules.registry"`` → ``"reports.modules"``
    ``"__main__"``                 → ``""``  (caller should fall back)

    Parameters
    ----------
    module_name : str
        Typically ``__name__`` of this registry module.
    """
    if not module_name or module_name == "__main__":
        return ""
    parts = module_name.split(".")
    # Drop the last component ("registry") to get the package ("reports.modules")
    return ".".join(parts[:-1]) if len(parts) > 1 else ""


def _resolve_package_prefix(modules_dir: Path) -> str:
    """
    Walk up from ``modules_dir`` to find the nearest ancestor that is
    NOT a Python package (i.e. has no ``__init__.py``), then build the
    dotted package name from the remaining path components.

    Example
    -------
    ``/project/reports/modules/`` → ``"reports.modules"``
    (assuming ``/project/`` has no ``__init__.py`` but
    ``/project/reports/`` and ``/project/reports/modules/`` both do)
    """
    parts: list[str] = []
    current = modules_dir.resolve()

    while (current / "__init__.py").exists():
        parts.append(current.name)
        current = current.parent

    return ".".join(reversed(parts))


def _import_module_file(path: Path, package_prefix: str) -> None:
    """
    Import a single module file, catching and logging any errors.

    Parameters
    ----------
    path : Path
        Absolute path to the ``.py`` file.
    package_prefix : str
        Dotted package prefix (e.g. ``"reports.modules"``).
    """
    stem        = path.stem
    module_name = f"{package_prefix}.{stem}" if package_prefix else stem

    try:
        # If the module is already in sys.modules, re-importing is a no-op
        # (modules that are already registered won't re-register).
        importlib.import_module(module_name)
        logger.debug("ModuleRegistry.discover: imported %s", module_name)
    except ImportError as exc:
        logger.warning(
            "ModuleRegistry.discover: failed to import %s — %s. "
            "Check that all dependencies are installed.",
            module_name, exc,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "ModuleRegistry.discover: unexpected error importing %s — %s.",
            module_name, exc,
        )


# ===========================================================================
# Global registry instance + registration decorator
# ===========================================================================

#: The global module registry.  Imported by ``reports/modules/__init__.py``
#: and available throughout the suite as ``from reports.modules import registry``.
registry = ModuleRegistry()


def register_module(cls: type[BaseModule]) -> type[BaseModule]:
    """
    Class decorator that registers a module with the global registry.

    Apply this decorator to any ``BaseModule`` subclass to make it
    available for use in delivery groups and composed reports.

    Usage
    -----
    ::

        from reports.modules.registry import register_module
        from reports.modules.base import BaseModule, ModuleConfig, ModuleData

        @register_module
        class SLASummaryModule(BaseModule):
            MODULE_ID    = "sla_summary"
            DISPLAY_NAME = "SLA Summary"
            ...

    The decorator is a pass-through — it registers the class and
    returns it unchanged so normal inheritance and introspection work.

    Parameters
    ----------
    cls : type[BaseModule]
        The module class to register.

    Returns
    -------
    type[BaseModule]
        The same class, unmodified.
    """
    registry.register(cls)
    return cls
