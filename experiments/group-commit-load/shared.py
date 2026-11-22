"""Reuse bounded byte/resource observers without changing their source or gates."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def module(name, path):
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    definition.loader.exec_module(value)
    return value


legacy = module('group_load_observer_loader', ROOT / 'experiments/object-overload/shared.py')


def observers():
    return legacy.observers()


def fixture_files():
    dependencies = (*legacy.DEPENDENCIES, 'experiments/object-overload/shared.py',
                    'experiments/object-overload/schedule.mjs',
                    'experiments/object-network/run.py', 'experiments/object-service/build.py')
    return sorted([*(path for path in HERE.iterdir() if path.is_file() and path.suffix in ('.py', '.mjs', '.md')),
                   *(ROOT / name for name in dependencies)])
