"""Module registry for forensic-analyze (docs/dev/contract.md section 8a).

Every ``modules/<name>.py`` that defines ``MODULE`` (an ``api.Module`` instance) is a module.
The registry works with zero, some, or all modules present: a file that fails to import is
reported by ``load_errors()`` and left out, so one broken module never stops a run.

Test-only hook: ``AIRLOCK_EXTRA_MODULES`` is a ``:``-separated list of extra ``.py`` files
(absolute paths) that each define ``MODULE``. The functional tests use it to register a small
test module when the real module of that name is not installed; a real module always wins. It
is never set on the image.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import pkgutil
import sys
from pathlib import Path

from forensic_analyze.api import Module

EXTRA_ENV = "AIRLOCK_EXTRA_MODULES"

# Fixed names and run order from the contract. Modules that exist must use these orders.
KNOWN_ORDER: dict[str, int] = {
    "inventory": 10,
    "recycle_bin": 20,
    "deletion_history": 30,
    "users": 40,
    "malware": 50,
    "images": 60,
    "video": 70,
    "audio": 80,
    "documents": 90,
    "timeline": 100,
    "carve": 110,
}

KNOWN_TITLES: dict[str, str] = {
    "inventory": "File inventory",
    "recycle_bin": "Recycle bin",
    "deletion_history": "Deletion history",
    "users": "Users and accounts",
    "malware": "Malware and hash triage",
    "images": "Images",
    "video": "Video",
    "audio": "Audio",
    "documents": "Documents",
    "timeline": "Timeline",
    "carve": "Carving unallocated space",
}

_errors: dict[str, str] = {}


def _load_extra(path: Path) -> Module | None:
    name = f"forensic_analyze_extra_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        _errors[str(path)] = "cannot load file"
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # a broken test module must not stop the registry
        _errors[str(path)] = f"{type(exc).__name__}: {exc}"
        return None
    found = getattr(mod, "MODULE", None)
    return found if isinstance(found, Module) else None


def _discover() -> list[Module]:
    _errors.clear()
    found: dict[str, Module] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"{__name__}.{info.name}")
        except Exception as exc:  # report and continue: other modules still run
            _errors[info.name] = f"{type(exc).__name__}: {exc}"
            continue
        candidate = getattr(mod, "MODULE", None)
        if isinstance(candidate, Module) and candidate.name:
            found[candidate.name] = candidate
    for raw in (os.environ.get(EXTRA_ENV) or "").split(":"):
        if not raw.strip():
            continue
        extra = _load_extra(Path(raw.strip()))
        if extra is None or not extra.name:
            continue
        if extra.name in found:
            _errors[raw.strip()] = f"{extra.name}: a real module has this name; test module unused"
            continue
        found[extra.name] = extra
    return sorted(found.values(), key=lambda m: (m.order, m.name))


def all_modules() -> list[Module]:
    """Every importable module, sorted by ``order`` (then name)."""
    return _discover()


def by_name() -> dict[str, Module]:
    return {m.name: m for m in all_modules()}


def load_errors() -> dict[str, str]:
    """Modules that failed to import during the last discovery: name -> reason."""
    return dict(_errors)


def order_of(name: str) -> int:
    return KNOWN_ORDER.get(name, 1000)


def title_of(name: str) -> str:
    return KNOWN_TITLES.get(name, name.replace("_", " ").capitalize())
