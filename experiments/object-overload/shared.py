"""Load the unchanged bounded observation helpers with their original spec.

No source is patched and no product behavior is intercepted. The temporary
module binding only resolves the legacy helpers' sibling import correctly.
"""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
LOAD = ROOT / 'experiments/object-load'
DEPENDENCIES = (
    'experiments/object-load/spec.py', 'experiments/object-load/support.py',
    'experiments/object-load/resources.py', 'experiments/object-load/launcher.py',
    'experiments/object-service/audit_wire.py', 'experiments/object-network/head5_audit.py')


def module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    definition.loader.exec_module(value)
    return value


@contextmanager
def original_spec():
    old = sys.modules.get('spec')
    sys.modules['spec'] = module('overload_original_load_spec', LOAD / 'spec.py')
    try:
        yield
    finally:
        if old is None:
            sys.modules.pop('spec', None)
        else:
            sys.modules['spec'] = old


def observers():
    with original_spec():
        support = module('overload_byte_capture', LOAD / 'support.py')
        resources = module('overload_owned_resources', LOAD / 'resources.py')
    return support, resources


def fixture_files():
    here = Path(__file__).resolve().parent
    paths = [path for path in here.iterdir()
             if path.is_file() and path.suffix in ('.py', '.mjs', '.md')]
    return sorted([*paths, *(ROOT / name for name in DEPENDENCIES)])
