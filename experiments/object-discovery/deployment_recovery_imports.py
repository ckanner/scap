"""Load this fixture's siblings by path, independent of service module names."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys

DIRECTORY = Path(__file__).resolve().parent
NAMESPACE = "_scap_deployment_recovery_" + hashlib.sha256(str(DIRECTORY).encode()).hexdigest()[:16]


def local(stem):
    if not isinstance(stem, str) or not stem.isidentifier():
        raise ImportError("fixture module must be a local Python identifier")
    name = NAMESPACE + "_" + stem
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    specification = importlib.util.spec_from_file_location(name, DIRECTORY / (stem + ".py"))
    value = importlib.util.module_from_spec(specification)
    sys.modules[name] = value
    try:
        specification.loader.exec_module(value)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return value
