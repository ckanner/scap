"""Frozen equal-seed-v1 inputs and experiment ceilings, not product algorithms.

Admission and per-request deadlines are unchanged. A ceiling is a stop/fail
condition; none is a theorem that every failure path completes within it.
"""
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
_definition = importlib.util.spec_from_file_location(
    'equal_seed_original_contract', ROOT / 'experiments/group-commit-load/spec.py')
_original = importlib.util.module_from_spec(_definition)
sys.modules[_definition.name] = _original
_definition.loader.exec_module(_original)

SCOPE, WORKER = dict(_original.SCOPE), _original.WORKER
PROFILE, ADMISSION = dict(_original.PROFILE), dict(_original.ADMISSION)
CACHE, TRANSPORT = dict(_original.CACHE), dict(_original.TRANSPORT)
OUTPUT, RETENTION = dict(_original.OUTPUT), dict(_original.RETENTION)
DDL, INSERT, ALL_ROWS, payload = _original.DDL, _original.INSERT, _original.ALL_ROWS, _original.payload
MIB, GIB = 1024 ** 2, 1024 ** 3
NAME = 'equal-seed-v1'
SEED_ROWS, SEED_RATE, LOAD_SECONDS, WINDOW_MS = 256, 4, 32, 4000
ABBA = (('off-1', False), ('on-1', True), ('on-2', True), ('off-2', False))
RATES = (12, 32)
ROUNDS = tuple((f'rate-{rate}-{name}', enabled) for rate in RATES for name, enabled in ABBA)
DEADLINES = {'client_ms': 65000, 'client_recovery_ms': 70000, 's3_ms': 15000,
             'startup_seconds': 60, 'seed_seconds': 100, 'load_seconds': 90,
             'settlement_seconds': 600, 'audit_seconds': 90, 'matrix_audit_seconds': 120,
             'shutdown_seconds': 30, 'cell_seconds': 900, 'run_seconds': 7200}
# The legacy observers import these at module initialization. Their fixed input
# module is adapted once, before any process starts; no live globals are changed.
BOUNDS = {'raw_bytes': 2 * GIB, 's3_requests': 60000, 'handlers': 32,
          'trace_rows': 240000, 'trace_bytes': 384 * MIB, 'body_bytes': 64 * MIB,
          'samples': 15000, 'sample_interval_ms': 100, 'sample_bytes': 64 * MIB,
          'sdk_rows': 22000, 'sdk_bytes': 32 * MIB, 'intent_rows': 1281,
          'intent_bytes': 2 * MIB, 'http_posts': 5139,
          'diagnostic_gets': 16, 'diagnostic_response_bytes': 65536,
          'diagnostic_bytes': MIB, 'diagnostic_ledger_bytes': 64 * 1024,
          'backend_bytes': 2 * GIB, 'matrix_bytes': 24 * GIB, 'matrix_inodes': 200000,
          'startup_free_bytes': 26 * GIB, 'minimum_free_bytes': 2 * GIB,
          'startup_free_inodes': 220000, 'events_bytes': 2 * MIB,
          'events_rows': 4096, 'child_log_bytes': MIB}
PROCESS_LIMITS = {
    'service': {'rss_bytes': 2 * GIB, 'fds': 2048, 'tasks': 256},
    'node': {'rss_bytes': GIB, 'fds': 1024, 'tasks': 64},
    'backend': {'rss_bytes': 2 * GIB, 'fds': 2048, 'tasks': 512},
    'observer': {'rss_bytes': GIB, 'fds': 1024, 'tasks': 128},
}
LANES = ('data', 'control', 'recovery', 'catalogue', 'restore')
INTERVALS = ('body', 'pre_enqueue', 'queue', 'invocation', 'encoding',
             'post_work_hold', 'post_http_hold', 'total_hold')
BUCKETS_US = (100, 500, 1000, 5000, 10000, 50000, 100000, 500000,
              1000000, 2500000, 5000000, 10000000, 30000000, 60000000,
              300000000, 1800000000, 86400000000, 604800000000, (1 << 64) - 1)


@dataclass(frozen=True)
class Contract:
    rate: int

    def __post_init__(self):
        if type(self.rate) is not int or self.rate not in RATES:
            raise ValueError('unfrozen equal-seed rate')

    @property
    def name(self):
        return f'{NAME}-rate-{self.rate}'

    @property
    def phases(self):
        return {'seed_rows': {'count': SEED_ROWS, 'rate': SEED_RATE, 'duration_ms': 64000},
                'load': {'count': self.rate * LOAD_SECONDS, 'rate': self.rate,
                         'duration_ms': LOAD_SECONDS * 1000}}

    @property
    def deadlines(self):
        return dict(DEADLINES)

    @property
    def retained_entries(self):
        return 1 + SEED_ROWS + self.rate * LOAD_SECONDS

    image_pages = 128
    window_ms = WINDOW_MS

    @property
    def plan(self):
        return {'schema': 1, 'name': NAME, 'profile': self.name, 'rate': self.rate,
                'scope': dict(SCOPE), 'worker': WORKER, 'phases': self.phases,
                'group_profile': dict(PROFILE), 'admission': dict(ADMISSION),
                'cache': dict(CACHE), 'transport': dict(TRANSPORT), 'output': dict(OUTPUT),
                'retention': dict(RETENTION), 'resource_diagnostics': True,
                'lifecycle_diagnostics': {'version': 1, 'path': '/diagnostics/lifecycle'},
                'client_inflight_limit': 192, 'max_offer_lag_ms': 1000,
                'bounds': dict(BOUNDS), 'process_limits': PROCESS_LIMITS,
                'deadlines': self.deadlines, 'window_ms': self.window_ms,
                'oracle_bounds': {'image_pages': self.image_pages,
                    'retained_entries': self.retained_entries, 'data_chunk_pages': 32,
                    'data_tree_max_level': 0, 'request_tree_max_level': 1,
                    'request_tree_max_nodes': self.retained_entries // 64 + 1},
                'seed_original_ack_required': SEED_ROWS, 'generator_rejections_allowed': 0,
                'same_database_cumulative_phases': False, 'finite_growth': True,
                'performance_improvement_required': False, 'artificial_queue_gate': False,
                'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


CONTRACTS = {rate: Contract(rate) for rate in RATES}
# Only supplies a default to reused generic readers; every actual audit passes
# the explicit cell contract, and no old profile is registered here.
SHORT = CONTRACTS[12]


def cells():
    return [{'name': name, 'group_commit': enabled, 'rate': rate,
             'contract': CONTRACTS[rate].name}
            for rate in RATES for name, enabled in ROUNDS if name.startswith(f'rate-{rate}-')]


def matrix_plan():
    return {'schema': 1, 'profile': NAME, 'cells': cells(),
            'contracts': {str(rate): contract.plan for rate, contract in CONTRACTS.items()},
            'measured_inserts': sum(rate * LOAD_SECONDS * 4 for rate in RATES),
            'seed_inserts': SEED_ROWS * len(ROUNDS), 'schema_executions': len(ROUNDS),
            'deadlines': dict(DEADLINES), 'bounds': dict(BOUNDS),
            'process_limits': PROCESS_LIMITS, 'automatic_rerun': False}


def calls(contract=SHORT):
    result = [{'id': 'create', 'phase': 'seed', 'operation': 'create', 'nonce': '1'},
              {'id': 'activate', 'phase': 'seed', 'operation': 'activate', 'nonce': '2'},
              {'id': 'schema', 'phase': 'seed', 'operation': 'execute', 'request_id': '1',
               'statements': [{'sql': DDL, 'params': []}]}]
    number = 0
    for phase, settings in contract.phases.items():
        arrivals = []
        for index in range(settings['count']):
            arrivals.append({'id': f'{phase}-{index}', 'phase': phase, 'operation': 'execute',
                'row': number, 'request_id': str(number + 2),
                'offset_ns': index * 1_000_000_000 // settings['rate'],
                'statements': [{'sql': INSERT, 'params': [{'integer': str(number)},
                                                         {'payload_row': number}]}]})
            number += 1
        controls = 4 if phase == 'seed_rows' else 8
        for index in range(controls):
            arrivals.append({'id': f'{phase}-control-{index}', 'phase': phase,
                'operation': 'status',
                'offset_ns': index * settings['duration_ms'] * 1_000_000 // controls})
        result.extend(sorted(arrivals, key=lambda item: (item['offset_ns'], item['id'])))
    return result


def configuration(endpoint, cache, s3_endpoint, token_digest, enabled, contract=SHORT,
                  diagnostic_digest=None):
    if diagnostic_digest is None:
        raise ValueError('independent diagnostic credential digest required')
    result = _original.configuration(endpoint, cache, s3_endpoint, token_digest, enabled, contract)
    result['lifecycle_diagnostics'] = {'version': 1, 'token_sha256': diagnostic_digest}
    return result
