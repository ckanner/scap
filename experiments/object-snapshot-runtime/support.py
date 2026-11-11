"""Reuse the committed owner runtime's transport/process observers only."""
from pathlib import Path
import importlib.util
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    description = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(description)
    sys.modules[name] = value
    description.loader.exec_module(value)
    return value


observer = load('snapshot_owner_observer', HERE.parent / 'object-owner-plan-runtime/support.py')
Child, Trace, Proxy = observer.Child, observer.Trace, observer.Proxy
network, signing = observer.network, observer.signing
service_build, seed_build = observer.service_build, observer.seed_build
sha, encoded, save, module = observer.sha, observer.encoded, observer.save, observer.module
MAX_RAW = observer.MAX_RAW
