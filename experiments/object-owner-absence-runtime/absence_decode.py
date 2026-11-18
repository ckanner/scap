"""Load shared independent audit code without runner or product imports."""
import importlib.util
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent.parent / 'object-owner-plan-runtime'
sys.path.insert(0, str(BASE))
import audit_evidence as evidence
import audit_model as model

spec = importlib.util.spec_from_file_location('absence_owner_audit', BASE / 'oracle.py')
base_oracle = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base_oracle
spec.loader.exec_module(base_oracle)


def controls():
    spec = importlib.util.spec_from_file_location('absence_owner_controls', BASE / 'controls.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
