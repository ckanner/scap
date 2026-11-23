"""Frozen max-members 8/4 experiment; all other equal-seed inputs are reused."""
from copy import deepcopy
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
_definition = importlib.util.spec_from_file_location(
    'group_width_equal_contract', ROOT / 'experiments/equal-seed-load/spec.py')
_equal = importlib.util.module_from_spec(_definition)
sys.modules[_definition.name] = _equal
_definition.loader.exec_module(_equal)

for _name in ('SCOPE', 'WORKER', 'PROFILE', 'ADMISSION', 'CACHE', 'TRANSPORT',
              'OUTPUT', 'RETENTION', 'SEED_ROWS', 'SEED_RATE', 'LOAD_SECONDS',
              'WINDOW_MS', 'RATES', 'DEADLINES', 'BOUNDS', 'PROCESS_LIMITS',
              'LANES', 'INTERVALS', 'BUCKETS_US'):
    globals()[_name] = deepcopy(getattr(_equal, _name))
DDL, INSERT, ALL_ROWS, payload = _equal.DDL, _equal.INSERT, _equal.ALL_ROWS, _equal.payload
NAME = 'group-width-v1'
CAPS = (8, 4)
ABBA = (('cap8-1', 8), ('cap4-1', 4), ('cap4-2', 4), ('cap8-2', 8))
ROUNDS = tuple((f'rate-{rate}-{name}', cap) for rate in RATES for name, cap in ABBA)


def member_cap(value):
    if type(value) is not int or value not in CAPS:
        raise ValueError('unfrozen group-width member cap')
    return value


@dataclass(frozen=True)
class Contract(_equal.Contract):
    max_members: int

    def __post_init__(self):
        super().__post_init__()
        member_cap(self.max_members)

    @property
    def name(self):
        return f'{NAME}-rate-{self.rate}-cap{self.max_members}'

    @property
    def plan(self):
        # The old plan supplies every unchanged ceiling and arrival parameter.
        result = super().plan
        result.update(name=NAME, profile=self.name, max_members=self.max_members)
        result['group_profile'] = {**PROFILE, 'max_members': self.max_members}
        return result


CONTRACTS = {(rate, cap): Contract(rate, cap) for rate in RATES for cap in CAPS}
SHORT = CONTRACTS[12, 8]


def cells():
    return [{'name': f'rate-{rate}-{name}', 'group_commit': True,
             'rate': rate, 'max_members': cap, 'contract': CONTRACTS[rate, cap].name}
            for rate in RATES for name, cap in ABBA]


def matrix_plan():
    return {'schema': 1, 'profile': NAME, 'cells': cells(),
            'contracts': {contract.name: contract.plan for contract in CONTRACTS.values()},
            'measured_inserts': sum(rate * LOAD_SECONDS * 4 for rate in RATES),
            'seed_inserts': SEED_ROWS * len(ROUNDS), 'schema_executions': len(ROUNDS),
            'deadlines': dict(DEADLINES), 'bounds': dict(BOUNDS),
            'process_limits': deepcopy(PROCESS_LIMITS), 'automatic_rerun': False}


def calls(contract=SHORT):
    return _equal.calls(contract)


def configuration(endpoint, cache, s3_endpoint, token_digest, enabled, contract=SHORT,
                  diagnostic_digest=None):
    if enabled is not True:
        raise ValueError('both group-width arms require group commit enabled')
    if type(contract) is not Contract:
        raise ValueError('explicit group-width contract required')
    result = deepcopy(_equal.configuration(endpoint, cache, s3_endpoint, token_digest,
                                           True, contract, diagnostic_digest))
    result['admission']['group_commit']['max_members'] = contract.max_members
    return result
