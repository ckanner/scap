"""Initialize independent fixed-cap imports, never change a running module.

The original observer, runner, SDK probe and independent byte readers remain
unchanged. Auditors do not load runners; only the runtime entry point asks for
the two runners before starting any owned process.
"""
from contextlib import contextmanager
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from types import MappingProxyType, ModuleType

import spec

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
_ABSENT = object()


@contextmanager
def siblings(**bindings):
    previous = {name: sys.modules.get(name, _ABSENT) for name in bindings}
    sys.modules.update(bindings)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is _ABSENT:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def module(name, path):
    name = 'group_width_' + name
    if name in sys.modules:
        value = sys.modules[name]
        if Path(value.__file__).resolve() != Path(path).resolve():
            raise ValueError('static module name reused for a different source')
        return value
    definition = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(definition)
    sys.modules[name] = value
    try:
        definition.loader.exec_module(value)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return value


DEPENDENCIES = (
    'docs/architecture/group-width-comparison.md',
    'docs/architecture/admission-lifecycle-diagnostics.md',
    'experiments/object-load/spec.py', 'experiments/object-load/support.py',
    'experiments/object-load/resources.py', 'experiments/object-load/launcher.py',
    'experiments/object-overload/schedule.mjs', 'experiments/object-network/run.py',
    'experiments/object-network/build_evidence.py', 'experiments/object-service/build.py',
    'experiments/object-service/audit_wire.py', 'experiments/object-network/head5_audit.py')


def fixture_files():
    directories = (HERE, ROOT / 'experiments/equal-seed-load',
                   ROOT / 'experiments/group-commit-load')
    return sorted({*(path for directory in directories for path in directory.iterdir()
                     if path.is_file() and path.suffix in ('.py', '.mjs', '.md')),
                   *(ROOT / name for name in DEPENDENCIES)})


with siblings(spec=spec):
    support = module('raw_observer', ROOT / 'experiments/object-load/support.py')
    resources = module('owned_observer', ROOT / 'experiments/object-load/resources.py')
    lifecycle = module('lifecycle', ROOT / 'experiments/equal-seed-load/lifecycle.py')
with siblings(spec=spec, shared=sys.modules[__name__]):
    observer = module('observer', ROOT / 'experiments/equal-seed-load/observer.py')
diagnostics = module('http_diagnostics', ROOT / 'experiments/group-commit-load/diagnostics.py')


def observers():
    return support, resources


def _spec_binding(cap):
    value = ModuleType(f'group_width_cap{cap}_spec')
    value.__dict__.update({name: item for name, item in vars(spec).items() if not name.startswith('_')})
    value.PROFILE = {**spec.PROFILE, 'max_members': cap}
    value.CONTRACTS = {rate: spec.CONTRACTS[rate, cap] for rate in spec.RATES}
    value.SHORT = value.CONTRACTS[12]
    # Copy mutable ceilings once so accidental edits cannot cross cap contexts.
    for name in ('BOUNDS', 'DEADLINES', 'PROCESS_LIMITS'):
        setattr(value, name, deepcopy(getattr(spec, name)))
    return value


def _shared_binding(cap, original):
    value = ModuleType(f'group_width_cap{cap}_shared')
    for name in ('ROOT', 'HERE', 'module', 'fixture_files', 'observers', 'support', 'resources'):
        setattr(value, name, globals()[name])
    value.reader = lambda: original
    return value


_specs = {cap: _spec_binding(cap) for cap in spec.CAPS}
_readers, _shared, _auditors = {}, {}, {}
for _cap in spec.CAPS:
    with siblings(spec=_specs[_cap], shared=sys.modules[__name__], diagnostics=diagnostics):
        _readers[_cap] = module(f'cap{_cap}_byte_reader', ROOT / 'experiments/group-commit-load/oracle.py')
    _shared[_cap] = _shared_binding(_cap, _readers[_cap])
    with siblings(spec=_specs[_cap], shared=_shared[_cap], lifecycle=lifecycle):
        _auditors[_cap] = module(f'cap{_cap}_auditor', ROOT / 'experiments/equal-seed-load/oracle.py')


def reader(cap):
    return _readers[spec.member_cap(cap)]


def auditor(cap):
    return _auditors[spec.member_cap(cap)]


_runtimes = None


def runtimes():
    """Called once by run.py initialization, never by the audit entry point."""
    global _runtimes
    if _runtimes is None:
        result = {}
        for cap in spec.CAPS:
            with siblings(spec=_specs[cap], shared=_shared[cap],
                          lifecycle=lifecycle, observer=observer):
                result[cap] = module(f'cap{cap}_runner', ROOT / 'experiments/equal-seed-load/run.py')
        _runtimes = MappingProxyType(result)
    return _runtimes
