"""Frozen paired workload. No product implementation or performance threshold."""
import hashlib

ROUNDS = (('off-1', False), ('on-1', True), ('on-2', True), ('off-2', False))
SCOPE = {'deployment': '1', 'tenant': '7', 'database': '1301',
         'incarnation': '1', 'generation': '1'}
WORKER = 6301
PHASES = {'low': {'count': 32, 'rate': 4, 'duration_ms': 8000},
          'contended': {'count': 128, 'rate': 64, 'duration_ms': 2000}}
PROFILE = {'version': 1, 'max_members': 8, 'max_input_bytes': 1048576,
           'max_changed_pages': 1024, 'max_result_bytes': 1048576}
ADMISSION = {'active_database_actors': 2, 'active_database_actors_per_tenant': 1,
             'actor_idle_timeout_ms': 600000, 'control_workers': 2,
             'queued_total': 96, 'queued_per_tenant': 80, 'queued_per_database': 72,
             'reserved_controls': 8, 'data_intake': 80, 'control_intake': 8,
             'recovery_intake': 4, 'max_body_bytes': 65536,
             'timeout_ms': 60000, 'recovery_timeout_ms': 60000}
CACHE = {'pages_per_actor': 16384, 'parallel_recoveries': 1}
TRANSPORT = {'version': 1, 'max_connections': 192, 'max_headers': 64,
             'max_header_bytes': 16384, 'max_buffer_bytes': 32768,
             'header_timeout_ms': 5000, 'response_timeout_ms': 30000,
             'shutdown_timeout_ms': 30000}
OUTPUT = {'version': 1, 'bytes': 536870912, 'bytes_per_tenant': 402653184,
          'control_bytes': 8388608, 'control_bytes_per_tenant': 1048576}
DEADLINES = {'client_ms': 65000, 'client_recovery_ms': 70000, 's3_ms': 15000,
             'phase_seconds': 180, 'run_seconds': 720}
# These exactly match the reused, unmodified object-load capture helpers.
BOUNDS = {'raw_bytes': 2 * 1024**3, 's3_requests': 30000, 'handlers': 32,
          'trace_rows': 200000, 'trace_bytes': 128 * 1024**2, 'samples': 15000,
          'sample_interval_ms': 100, 'body_bytes': 64 * 1024**2,
          'startup_free_bytes': 2 * 1024**3, 'minimum_free_bytes': 1024**3}
DDL = 'CREATE TABLE paired(id INTEGER PRIMARY KEY,payload BLOB NOT NULL,witness INTEGER NOT NULL)'
INSERT = 'INSERT INTO paired(id,payload,witness) VALUES(?,?,random()) RETURNING id,payload,witness'
ALL_ROWS = 'SELECT id,payload,witness FROM paired ORDER BY id'
PLAN = {'schema': 1, 'name': 'independent-group-commit-load-v1',
        'rounds': [list(value) for value in ROUNDS], 'scope': SCOPE, 'worker': WORKER,
        'phases': PHASES, 'group_profile': PROFILE, 'client_inflight_limit': 192,
        'max_offer_lag_ms': 1000, 'admission': ADMISSION, 'cache': CACHE,
        'transport': TRANSPORT, 'output': OUTPUT, 'deadlines': DEADLINES,
        'bounds': BOUNDS, 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN',
        'performance_improvement_required': False, 'artificial_queue_gate': False}


def payload(number):
    return hashlib.sha256(('scap-group-load-v1:' + str(number)).encode()).digest() * 8


def calls():
    result = [{'id': 'create', 'phase': 'seed', 'operation': 'create', 'nonce': '1'},
              {'id': 'activate', 'phase': 'seed', 'operation': 'activate', 'nonce': '2'},
              {'id': 'schema', 'phase': 'seed', 'operation': 'execute', 'request_id': '1',
               'statements': [{'sql': DDL, 'params': []}]}]
    number = 0
    for phase, settings in PHASES.items():
        arrivals = []
        for index in range(settings['count']):
            arrivals.append({'id': f'{phase}-{index}', 'phase': phase, 'operation': 'execute',
                'row': number, 'request_id': str(number + 2),
                'offset_ns': index * 1_000_000_000 // settings['rate'],
                'statements': [{'sql': INSERT, 'params': [{'integer': str(number)},
                                                        {'payload_row': number}]}]})
            number += 1
        for index in range(4):
            arrivals.append({'id': f'{phase}-control-{index}', 'phase': phase,
                             'operation': 'status', 'offset_ns': index * settings['duration_ms'] * 250000})
        result.extend(sorted(arrivals, key=lambda item: (item['offset_ns'], item['id'])))
    return result


def configuration(endpoint, cache, s3_endpoint, token_digest, enabled):
    return {'version': 1, 'listen': endpoint, 'worker_instance': str(WORKER),
        'cache_directory': str(cache),
        'admission': {**ADMISSION, 'group_commit': PROFILE if enabled else None},
        'cache': CACHE, 'transport': TRANSPORT, 'output': OUTPUT,
        'execution': {'result_memory_bytes': 134217728},
        's3': {'endpoint': s3_endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_TEST_ACCESS', 'secret_key_env': 'SCAP_TEST_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': DEADLINES['s3_ms']},
        'credentials': [{'sha256': token_digest, 'deployment': '1', 'tenant': '7',
                         'principal': '11', 'provision': True}]}
