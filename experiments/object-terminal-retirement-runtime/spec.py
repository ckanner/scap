"""Fixed public inputs; no authority decision or product implementation."""
import hashlib
import struct


def direct(database, incarnation=1):
    return dict(zip(('deployment', 'tenant', 'database', 'incarnation', 'generation'),
                    map(str, (1, 7, database, incarnation, 1))))


NAMED = {
    'before': (7101, 'terminal-before-release', None),
    'before_successor': (7102, 'terminal-before-release', '3'),
    'after': (7103, 'terminal-after-reuse', None),
    'after_successor': (7104, 'terminal-after-reuse', '3'),
    'proof_present': (7105, 'terminal-proof-present', None),
    'proof_absent': (7106, 'terminal-proof-absent', None),
    'fence_absent': (7107, 'terminal-fence-absent', None),
    'foreign_loser': (7108, 'terminal-foreign-occupied', None),
}


def creation(name):
    operation, spelling, expected = NAMED[name]
    digest = hashlib.sha256(b'SCAP-NAMED-ID-v1\0' + struct.pack('>QQQQ', 1, 7, 11, operation)).digest()
    database, incarnation = struct.unpack('>QQ', digest[:16])
    return {'creator': '11', 'operation': str(operation), 'name': spelling,
            'scope': direct(database, incarnation), 'expected_name_revision': expected}


SCOPES = {name: direct(number) for name, number in (
    ('late', 6101), ('race', 6102), ('receipt', 6103), ('stale', 6191), ('bad_sweep', 6192))}
SCOPES.update({name: creation(name)['scope'] for name in NAMED})
SCOPES['foreign'] = {**SCOPES['foreign_loser'],
                     'incarnation': str(int(SCOPES['foreign_loser']['incarnation']) + 1)}
SEEDED = ('late', 'race', 'receipt', 'before', 'before_successor', 'after',
          'after_successor', 'foreign', 'stale', 'bad_sweep')
SURVIVORS = ('before_successor', 'after_successor', 'foreign')
ROLES = ('A', 'B', 'C', 'R')
MAX_SWEEP_PAGES = 32
TIMEOUTS = {'sdk_ms': 90000, 'recovery_ms': 300000, 'http_ms': 120000,
            's3_ms': 120000, 'original_unknown_ms': 1500, 'hold_seconds': 180,
            'old_reader_observation_ms': 30000, 'receipt_observation_ms': 30000,
            'whole_seconds': 1200}


def statements(counter, create=False):
    initial = ([{'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)',
                 'params': []}] if create else [])
    sql = (f'INSERT INTO witness VALUES(1,{counter},randomblob(64))' if create else
           f'UPDATE witness SET counter={counter},payload=randomblob(64) WHERE id=1')
    return initial + [{'sql': sql + ' RETURNING counter,payload,random() AS nonce', 'params': []}]


def inputs():
    result = [{'name': f'{name}-{counter}', 'scope_name': name, 'epoch': '1',
               'request_id': str(counter), 'statements': statements(counter, counter == 1),
               'purpose': 'seed', 'counter': counter}
              for name in SEEDED for counter in (1, 2)]
    for name, purpose in (('late', 'late_put'), ('race', 'old_cas'), ('receipt', 'committed_reply')):
        result.append({'name': name + '-3', 'scope_name': name, 'epoch': '1', 'request_id': '3',
                       'statements': statements(3), 'purpose': purpose, 'counter': 3})
    return result


def head_path(name):
    return f'/scap-test/scap-object/v1/1/7/{SCOPES[name]["database"]}/head'


def prefix(name, generation):
    value = SCOPES[name]
    return (f'/scap-test/scap-object/v1/1/7/{value["database"]}/inc/{value["incarnation"]}'
            f'/gen/{value["generation"]}/storage/{generation}/objects/')


def catalogue_path(kind, name):
    value = creation(name)
    base = '/scap-test/scap-object/v1/1/7/catalogue/v1/'
    if kind == 'name':
        return base + 'name/' + hashlib.sha256(value['name'].encode()).hexdigest()
    if kind in ('create', 'abort-proof'):
        return base + kind + '/11/' + value['operation']
    raise ValueError('unplanned catalogue key')


def configuration(port, cache, endpoint, tokens, worker, role):
    return {
        'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': str(worker),
        'cache_directory': str(cache),
        'transport': {'version': 1, 'max_connections': 64, 'max_headers': 64,
            'max_header_bytes': 16384, 'max_buffer_bytes': 32768, 'header_timeout_ms': 5000,
            'response_timeout_ms': 120000, 'shutdown_timeout_ms': 30000},
        's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_TERMINAL_ACCESS', 'secret_key_env': 'SCAP_TERMINAL_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': TIMEOUTS['s3_ms']},
        'admission': {'active_database_actors': 16, 'active_database_actors_per_tenant': 16,
            'actor_idle_timeout_ms': 60000, 'control_workers': 4,
            'queued_total': 32, 'queued_per_tenant': 32, 'queued_per_database': 8,
            'reserved_controls': 2, 'data_intake': 16, 'control_intake': 8,
            'recovery_intake': 2, 'max_body_bytes': 1048576,
            'timeout_ms': TIMEOUTS['http_ms'], 'recovery_timeout_ms': TIMEOUTS['recovery_ms']},
        'catalogue': {'workers': 4, 'queued_total': 16, 'queued_per_tenant': 16,
            'queued_per_name': 4, 'intake': 8, 'max_body_bytes': 65536, 'timeout_ms': 120000},
        'output': {'version': 1, 'bytes': 268435456, 'bytes_per_tenant': 201326592,
                   'control_bytes': 8388608, 'control_bytes_per_tenant': 1048576},
        'cache': {'pages_per_actor': 4096, 'parallel_recoveries': 2},
        'execution': {'result_memory_bytes': 134217728},
        'credentials': [{'sha256': tokens[principal], 'deployment': '1', 'tenant': '7',
                         'principal': principal, 'provision': role in ('A', 'B') and principal == '11'}
                        for principal in ('11', '12')],
        'gc': ({'deployment': '1', 'access_key_env': 'SCAP_TERMINAL_GC_ACCESS',
                'secret_key_env': 'SCAP_TERMINAL_GC_SECRET', 'session_token_env': None}
               if role == 'B' else None),
    }
