"""Static dependency adapters for unchanged experiment observers and readers.

Only sibling import names are resolved here, once at module initialization.
There is no production import, monkey-patched algorithm or live rebinding.
"""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import sys

import spec

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


@contextmanager
def siblings(**bindings):
    previous = {name: sys.modules.get(name) for name in bindings}
    sys.modules.update(bindings)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    definition.loader.exec_module(value)
    return value


with siblings(spec=spec):
    support = module('equal_seed_raw_observer', ROOT / 'experiments/object-load/support.py')
    resources = module('equal_seed_owned_observer', ROOT / 'experiments/object-load/resources.py')
diagnostics = module('equal_seed_http_diagnostics', ROOT / 'experiments/group-commit-load/diagnostics.py')


def observers():
    return support, resources


def reader():
    # Load before running any cell. The returned reader keeps its own module
    # dependencies; restoring import names does not change those references.
    with siblings(spec=spec, shared=sys.modules[__name__], diagnostics=diagnostics):
        return module('equal_seed_original_byte_reader', ROOT / 'experiments/group-commit-load/oracle.py')


DEPENDENCIES = (
    'docs/architecture/admission-lifecycle-diagnostics.md',
    'experiments/group-commit-load/spec.py', 'experiments/group-commit-load/oracle.py',
    'experiments/group-commit-load/diagnostics.py', 'experiments/group-commit-load/record.mjs',
    'experiments/object-load/spec.py', 'experiments/object-load/support.py',
    'experiments/object-load/resources.py', 'experiments/object-load/launcher.py',
    'experiments/object-overload/schedule.mjs', 'experiments/object-network/run.py',
    'experiments/object-service/build.py', 'experiments/object-service/audit_wire.py',
    'experiments/object-network/head5_audit.py')


def fixture_files():
    return sorted([*(path for path in HERE.iterdir()
                     if path.is_file() and path.suffix in ('.py', '.mjs', '.md')),
                   *(ROOT / name for name in DEPENDENCIES)])
