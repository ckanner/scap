"""Frozen input and accounting contract; contains no database implementation."""
from __future__ import annotations

import hashlib

SCOPES = {name: {'deployment': '1', 'tenant': tenant, 'database': database,
                 'incarnation': '1', 'generation': '1'}
          for name, tenant, database in (
              ('single', '7', '1101'), ('batch', '7', '1102'),
              ('hot', '7', '1103'), ('quiet', '8', '1201'))}
WORKER = 6101
PHASES = ('seed', 'single', 'batch', 'overload', 'verify', 'recovered')
MEASURED = ('single', 'batch', 'overload')
DURATION_MS = 30000
ARRIVALS = {'hot': 32, 'quiet': 4, 'control': 2}
CLIENT_INFLIGHT = 64
MAX_OFFER_LAG_MS = 1000
PROGRESS_WINDOW_MS = 5000
BATCH_SIZE = 8
LOGICAL_ROWS = 64
DEADLINES = {'ordinary_ms': 60000, 'recovery_ms': 60000, 's3_ms': 15000,
             'client_ms': 65000, 'client_recovery_ms': 70000,
             'phase_seconds': 600, 'run_seconds': 1200, 'gate_hold_ms': 12000}
ADMISSION = {'active_database_actors': 4, 'active_database_actors_per_tenant': 3,
             'actor_idle_timeout_ms': 600000, 'control_workers': 2,
             'queued_total': 32, 'queued_per_tenant': 16, 'queued_per_database': 8,
             'reserved_controls': 4, 'data_intake': 16, 'control_intake': 8,
             'recovery_intake': 4, 'max_body_bytes': 4194304,
             'timeout_ms': 60000, 'recovery_timeout_ms': 60000, 'read_pool': None}
CACHE = {'pages_per_actor': 16384, 'parallel_recoveries': 1}
TRANSPORT = {'version': 1, 'max_connections': 64, 'max_headers': 64,
             'max_header_bytes': 16384, 'max_buffer_bytes': 32768,
             'header_timeout_ms': 5000, 'response_timeout_ms': 30000,
             'shutdown_timeout_ms': 30000}
OUTPUT = {'version': 1, 'bytes': 536870912, 'bytes_per_tenant': 201326592,
          'control_bytes': 8388608, 'control_bytes_per_tenant': 1048576}
# Keep the pre-existing byte collector's declared bounds. Its independent source
# is archived together with this contract; these are collector limits, not SLOs.
BOUNDS = {'raw_bytes': 2 * 1024**3, 's3_requests': 30000, 'handlers': 32,
          'trace_rows': 200000, 'trace_bytes': 128 * 1024**2, 'samples': 15000,
          'sample_interval_ms': 100, 'body_bytes': 64 * 1024**2,
          'startup_free_bytes': 2 * 1024**3, 'minimum_free_bytes': 1024**3}
DDL = 'CREATE TABLE overload(id INTEGER PRIMARY KEY,payload BLOB NOT NULL)'
INSERT = 'INSERT INTO overload(id,payload) VALUES(?,?) RETURNING id,payload,random() AS witness'
COUNTS = 'SELECT count(*) AS n,coalesce(sum(id),0) AS total FROM overload'
ALL_ROWS = 'SELECT id,payload FROM overload ORDER BY id'


def payload(row, size=256):
    """Identical deterministic logical input in single and batch comparisons."""
    seed = hashlib.sha256(('scap-overload-input-v1:' + str(row)).encode()).digest()
    return bytes(seed[index % len(seed)] ^ (index // len(seed) & 255) for index in range(size))


def calls():
    result = []

    def add(identifier, phase, scope, operation, **fields):
        result.append({'id': identifier, 'phase': phase, 'scope': scope,
                       'operation': operation, **fields})

    for name, scope in SCOPES.items():
        nonce = int(scope['database']) * 10
        add('seed-' + name + '-create', 'seed', name, 'create', nonce=str(nonce + 1))
        add('seed-' + name + '-activate', 'seed', name, 'activate',
            nonce=str(nonce + 2), expected_revision='1')
        add('seed-' + name + '-schema', 'seed', name, 'execute', request_id='1', kind='schema')
    for phase, size in (('single', 1), ('batch', BATCH_SIZE)):
        for first in range(0, LOGICAL_ROWS, size):
            add(f'{phase}-{first // size}', phase, phase, 'execute',
                request_id=str(first // size + 2), kind='insert',
                rows=list(range(first, first + size)))
    offered = []
    for lane, rate in ARRIVALS.items():
        for number in range(rate * DURATION_MS // 1000):
            base = {'id': f'overload-{lane}-{number}', 'phase': 'overload',
                    'scope': 'hot' if lane in ('hot', 'control') else 'quiet',
                    'lane': lane, 'offset_ns': number * 1_000_000_000 // rate}
            if lane == 'hot':
                base.update(operation='execute', request_id=str(number + 2),
                            kind='insert', rows=[number])
            elif lane == 'quiet':
                base.update(operation='query', kind='counts')
            else:
                base.update(operation='status')
            offered.append(base)
    result.extend(sorted(offered, key=lambda call: (call['offset_ns'], call['lane'])))
    originals = [item for item in result if item['operation'] == 'execute']
    for item in originals:
        for step, operation in enumerate(('lookup', 'cancel', 'lookup')):
            add(f"verify-{item['id']}-{step}", 'verify', item['scope'], operation,
                original=item['id'])
    for name in SCOPES:
        add('rows-' + name, 'verify', name, 'query', kind='all_rows')
        # After all in-flight tasks and the original identity resolution have
        # drained, each tenant must still acquire and return ordinary resources.
        add('recovered-' + name, 'recovered', name, 'query', kind='counts')
    return result


def statements(item):
    kind = item.get('kind')
    if kind == 'schema':
        return [{'sql': DDL, 'params': []}]
    if kind == 'insert':
        return [{'sql': INSERT, 'params': [{'integer': str(row)},
                  {'payload_row': row}]} for row in item['rows']]
    if kind == 'counts':
        return [{'sql': COUNTS, 'params': []}]
    if kind == 'all_rows':
        return [{'sql': ALL_ROWS, 'params': []}]
    return None


PLAN = {'schema': 1, 'name': 'object-overload-v1', 'scopes': SCOPES,
        'worker_instance': WORKER, 'phases': PHASES, 'measured': MEASURED,
        'duration_ms': DURATION_MS, 'arrivals_per_second': ARRIVALS,
        'client_inflight_limit': CLIENT_INFLIGHT, 'max_offer_lag_ms': MAX_OFFER_LAG_MS,
        'progress_window_ms': PROGRESS_WINDOW_MS,
        'logical_rows_per_comparison': LOGICAL_ROWS, 'batch_statements': BATCH_SIZE,
        'admission': ADMISSION, 'cache': CACHE, 'transport': TRANSPORT,
        'output': OUTPUT, 'deadlines': DEADLINES, 'bounds': BOUNDS,
        'aws_standard': 'NOT_RUN', 'production_slo_passed': False,
        'sampled_resource_peak_is_hard_bound': False}
