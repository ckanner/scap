"""Frozen logical inputs. This module contains no product or audit algorithm."""
SCOPES = {name: {'deployment': '1', 'tenant': '7', 'database': str(database),
                 'incarnation': '1', 'generation': '1'}
          for name, database in (('main', 4101), ('fence', 4102), ('aborted', 4103))}
LIMITS = {'quota_bytes': 67108864, 'retention_entries': 129,
          'retention_result_bytes': 268435456}
MAX_SWEEP_PAGES = 128


def statements(counter, create=False):
    result = []
    if create:
        result.append({'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)', 'params': []})
        sql = f'INSERT INTO witness VALUES(1,{counter},randomblob(64))'
    else:
        sql = f'UPDATE witness SET counter={counter},payload=randomblob(64) WHERE id=1'
    result.append({'sql': sql + ' RETURNING counter,payload,random() AS nonce', 'params': []})
    return result


def inputs():
    result = []
    for name in SCOPES:
        count = 260 if name == 'main' else 2
        for counter in range(1, count + 1):
            epoch = (counter - 1) // 129 + 1 if name == 'main' else 1
            request = (counter - 1) % 129 + 1
            result.append({'name': f'{name}-{counter:03d}', 'scope_name': name,
                           'epoch': str(epoch), 'request_id': str(request),
                           'statements': statements(counter, create=counter == 1),
                           'purpose': 'seed', 'counter': counter})
    result.append({'name': 'main-cancel', 'scope_name': 'main', 'epoch': '3',
                   'request_id': '3', 'statements': statements(777777), 'purpose': 'cancel'})
    result.append({'name': 'main-late-put', 'scope_name': 'main', 'epoch': '3',
                   'request_id': '4', 'statements': statements(999999), 'purpose': 'late_put'})
    result.append({'name': 'fence-old-cas', 'scope_name': 'fence', 'epoch': '1',
                   'request_id': '3', 'statements': statements(888888), 'purpose': 'old_cas'})
    return result


def prefix(name, generation):
    scope = SCOPES[name]
    return (f'/scap-test/scap-object/v1/1/7/{scope["database"]}/inc/1/gen/1/'
            f'storage/{generation}/objects/')


def head_path(name):
    return f'/scap-test/scap-object/v1/1/7/{SCOPES[name]["database"]}/head'


def configuration(port, cache, endpoint, token_hash, worker, gc):
    result = {
        'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': str(worker),
        'cache_directory': str(cache),
        'transport': {'version': 1, 'max_connections': 64, 'max_headers': 64,
            'max_header_bytes': 16384, 'max_buffer_bytes': 32768, 'header_timeout_ms': 5000,
            'response_timeout_ms': 120000, 'shutdown_timeout_ms': 30000},
        's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_RECLAIM_ACCESS', 'secret_key_env': 'SCAP_RECLAIM_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': 120000},
        'admission': {'active_database_actors': 4, 'active_database_actors_per_tenant': 4,
            'actor_idle_timeout_ms': 60000, 'control_workers': 2,
            'queued_total': 32, 'queued_per_tenant': 32, 'queued_per_database': 8,
            'reserved_controls': 2, 'data_intake': 16, 'control_intake': 8,
            'recovery_intake': 2, 'max_body_bytes': 1048576,
            'timeout_ms': 120000, 'recovery_timeout_ms': 300000},
        'cache': {'pages_per_actor': 16384, 'parallel_recoveries': 2},
        'execution': {'result_memory_bytes': 134217728},
        'credentials': [{'sha256': token_hash, 'deployment': '1', 'tenant': '7',
                         'principal': '11', 'provision': True}],
        'gc': None,
    }
    if gc:
        result['gc'] = {'deployment': '1', 'access_key_env': 'SCAP_RECLAIM_GC_ACCESS',
                       'secret_key_env': 'SCAP_RECLAIM_GC_SECRET', 'session_token_env': None}
    return result
