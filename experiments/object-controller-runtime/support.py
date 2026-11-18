"""Reuse existing raw observers; no database or controller decisions live here."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


shared = load('controller_runtime_raw', HERE.parent / 'object-owner-plan-runtime/support.py')
http = load('controller_runtime_http', HERE.parent / 'object-owner-plan-runtime/http_proxy.py')
configuration = load('controller_runtime_config', HERE.parent / 'object-reclamation-runtime/spec.py').configuration
Trace, Child, Proxy, HTTPProxy = shared.Trace, shared.Child, shared.Proxy, http.HTTPProxy
network, build = shared.network, shared.service_build
save, encoded, sha = shared.save, shared.encoded, shared.sha
