"""Frozen workload and input denominator; no database or scheduling implementation."""
SCOPES = {
    name: {'deployment': '1', 'tenant': tenant, 'database': database,
           'incarnation': '1', 'generation': '1'}
    for name, tenant, database in (
        ('seq', '7', '101'), ('same', '7', '102'), ('m0', '7', '201'), ('m1', '7', '202'),
        ('m2', '8', '301'), ('m3', '8', '302'), ('hot', '8', '401'), ('cold', '7', '501'))}
MEASURED = {'write_seq': (32, 1), 'write_same': (64, 4), 'write_multi': (64, 4),
            'read_same': (64, 4), 'read_multi': (64, 4)}
PHASES = ('seed', *MEASURED, 'hot-open', 'cold-open', 'cold-probes', 'cold-warm', 'verify')
DEADLINES = {'ordinary_ms': 60000, 'recovery_ms': 60000, 's3_ms': 15000,
             'client_ms': 65000, 'client_recovery_ms': 70000, 'gate_hold_ms': 12000,
             'probe_ms': 4000, 'phase_seconds': 180, 'run_seconds': 1200}
ADMISSION = {'active_database_actors': 8, 'active_database_actors_per_tenant': 5,
             'actor_idle_timeout_ms': 600000, 'control_workers': 2, 'queued_total': 64,
             'queued_per_tenant': 32, 'queued_per_database': 8, 'reserved_controls': 4,
             'data_intake': 16, 'control_intake': 8, 'recovery_intake': 4,
             'max_body_bytes': 4194304, 'timeout_ms': 60000, 'recovery_timeout_ms': 60000}
CACHE = {'pages_per_actor': 16384, 'parallel_recoveries': 1}
TRANSPORT = {'version': 1, 'max_connections': 64, 'max_headers': 64,
             'max_header_bytes': 16384, 'max_buffer_bytes': 32768, 'header_timeout_ms': 5000,
             'response_timeout_ms': 30000, 'shutdown_timeout_ms': 30000}
OUTPUT = {'version': 1, 'bytes': 268435456, 'bytes_per_tenant': 201326592,
          'control_bytes': 8388608, 'control_bytes_per_tenant': 1048576}
BOUNDS = {'raw_bytes': 2 * 1024**3, 's3_requests': 30000, 'handlers': 32,
          'trace_rows': 200000, 'trace_bytes': 128 * 1024**2, 'samples': 15000,
          'sample_interval_ms': 100, 'body_bytes': 64 * 1024**2,
          'startup_free_bytes': 2 * 1024**3, 'minimum_free_bytes': 1024**3}
DDL = 'CREATE TABLE loads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)'
COUNTS = 'SELECT count(*) AS n, coalesce(sum(id),0) AS total FROM loads'
ALL_ROWS = 'SELECT id,payload FROM loads ORDER BY id'


def calls():
    result = []
    def add(identifier, phase, scope, operation, **fields):
        result.append({'id': identifier, 'phase': phase, 'scope': scope,
                       'operation': operation, **fields})
    for name, scope in SCOPES.items():
        nonce = int(scope['database']) * 10
        add('seed-' + name + '-create', 'seed', name, 'create', nonce=str(nonce + 1))
        add('seed-' + name + '-activate', 'seed', name, 'activate', nonce=str(nonce + 2), expected_revision='1')
        add('seed-' + name + '-schema', 'seed', name, 'execute', request_id='1', kind='schema')
    add('seed-hot-row', 'seed', 'hot', 'execute', request_id='2', kind='insert', rows=[0], blob_bytes=4096)
    for number in range(16):
        add(f'seed-cold-{number}', 'seed', 'cold', 'execute', request_id=str(number + 2),
            kind='bulk', rows=list(range(number * 32, (number + 1) * 32)), blob_bytes=65536)
    for phase, (count, _) in MEASURED.items():
        for number in range(count):
            name = ('m' + str(number % 4)) if phase.endswith('multi') else ('seq' if phase == 'write_seq' else 'same')
            if phase.startswith('write'):
                row = number // 4 if phase.endswith('multi') else number
                add(f'{phase}-{number}', phase, name, 'execute', request_id=str(row + 2),
                    kind='insert', rows=[row], blob_bytes=4096)
            else:
                add(f'{phase}-{number}', phase, name, 'query', kind='counts')
    add('hot-open', 'hot-open', 'hot', 'open')
    add('cold-open', 'cold-open', 'cold', 'open')
    for number in range(8):
        add(f'hot-probe-{number}', 'cold-probes', 'hot', 'query', kind='counts')
    for number in range(2):
        add(f'cold-status-{number}', 'cold-probes', 'cold', 'status')
    add('recovery-busy', 'cold-probes', 'seq', 'open', expected_error='RECOVERY_BUSY')
    add('cold-warm', 'cold-warm', 'cold', 'query', kind='counts')
    originals = [item for item in result if item['operation'] == 'execute']
    for item in originals:
        steps = ('lookup',) if item['phase'] == 'seed' else ('lookup', 'cancel', 'lookup')
        for step, operation in enumerate(steps):
            add(f"verify-{item['id']}-{step}", 'verify', item['scope'], operation, original=item['id'])
    for name in SCOPES:
        if name != 'cold':
            add('rows-' + name, 'verify', name, 'query', kind='all_rows')
    for number in range(16):
        add(f'rows-cold-{number}', 'verify', 'cold', 'query', kind='row_range',
            first=number * 32, last=(number + 1) * 32)
    return result


def statements(item, payloads):
    """Input construction only. Blob descriptors are materialized by the SDK probe."""
    kind = item.get('kind')
    if kind == 'schema':
        return [{'sql': DDL, 'params': []}]
    if kind in ('insert', 'bulk'):
        values, parameters = [], []
        for row in item['rows']:
            values.append('(?,?)')
            parameters.extend([{'integer': str(row)}, {'blob': payloads[str(row)]}])
        suffix = ' RETURNING id,payload,random() AS witness' if kind == 'insert' else ' RETURNING id'
        output = [{'sql': 'INSERT INTO loads(id,payload) VALUES' + ','.join(values) + suffix, 'params': parameters}]
        if kind == 'bulk':
            output.append({'sql': 'SELECT random() AS witness', 'params': []})
        return output
    if kind == 'counts':
        return [{'sql': COUNTS, 'params': []}]
    if kind == 'all_rows':
        return [{'sql': ALL_ROWS, 'params': []}]
    if kind == 'row_range':
        return [{'sql': 'SELECT id,payload FROM loads WHERE id>=? AND id<? ORDER BY id',
                 'params': [{'integer': str(item['first'])}, {'integer': str(item['last'])}]}]
    return None


PLAN = {'schema': 1, 'name': 'object-load-local-v1', 'scopes': SCOPES, 'measured': MEASURED,
        'phases': PHASES, 'deadlines': DEADLINES, 'admission': ADMISSION, 'cache': CACHE,
        'transport': TRANSPORT, 'output': OUTPUT, 'bounds': BOUNDS, 'http_posts': 871,
        'original_executes': 185, 'measured_calls': 288, 'cold_user_bytes': 33554432,
        'aws_standard': 'NOT_RUN', 'production_slo_passed': False}
