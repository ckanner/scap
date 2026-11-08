"""Load independent byte readers under unambiguous module identities.

The service and network directories both contain a catalogue_oracle.py. A
combined model test process must never select one by incidental sys.path order.
No controller, builder or production transition module is imported here.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for relative in ("experiments/object-service", "experiments/object-network"):
    directory = str(ROOT / relative)
    if directory not in sys.path:
        sys.path.append(directory)


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


catalogue = load("discovery_catalogue_byte_reader", "experiments/object-network/catalogue_oracle.py")
segmented = load("discovery_segmented_byte_reader", "experiments/object-service/segmented_tree_audit.py")
build = load("discovery_seed_build_reader", "experiments/object-network/audit_build.py")
wire = load("discovery_wire_byte_reader", "experiments/object-service/audit_wire.py")
