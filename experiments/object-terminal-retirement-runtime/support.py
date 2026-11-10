"""Reuse only the raw owned-process/SigV4 transport observer, not its runner or oracle."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_spec = importlib.util.spec_from_file_location('terminal_raw_transport',
    HERE.parent / 'object-reclamation-runtime/support.py')
shared = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = shared
_spec.loader.exec_module(shared)

Trace, Proxy, Child = shared.Trace, shared.Proxy, shared.Child
network, signing, service_build = shared.network, shared.signing, shared.service_build
sha, encoded, save, module = shared.sha, shared.encoded, shared.save, shared.module
