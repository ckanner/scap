"""Fixed inputs for the actual owner-plan contract; no product implementation."""
from __future__ import annotations

import hashlib
import struct

SCOPE_FIELDS = ('deployment', 'tenant', 'database', 'incarnation', 'generation')


def direct(database, incarnation=1):
    return dict(zip(SCOPE_FIELDS, map(str, (1, 7, database, incarnation, 1))))


NAMED = {
    'named_old': (7601, 'owner-head8-history', None),
    'named_successor': (7602, 'owner-head8-history', '3'),
}


def creation(name):
    operation, spelling, revision = NAMED[name]
    digest = hashlib.sha256(b'SCAP-NAMED-ID-v1\0' + struct.pack('>QQQQ', 1, 7, 11, operation)).digest()
    database, incarnation = struct.unpack('>QQ', digest[:16])
    return {'creator': '11', 'operation': str(operation), 'name': spelling,
            'scope': direct(database, incarnation), 'expected_name_revision': revision}


SCOPES = {name: direct(database) for name, database in (
    ('bulk', 7201), ('late_prepare', 7202), ('claim_cancel', 7203),
    ('claim_wins', 7204), ('resume_cancel', 7205), ('resume_wins', 7206),
    ('acl', 7207), ('target_death', 7208), ('resume_death', 7209),
    ('legacy', 7210), ('proof_claim', 7211), ('proof_cancel', 7212))}
SCOPES.update({name: creation(name)['scope'] for name in NAMED})
SCOPES.update({name: direct(database) for name, database in (
    ('missing_descriptor', 7214), ('budget_gets', 7215), ('budget_bytes', 7216))})

ROLES = ('A', 'B', 'C', 'R', 'G', 'Z')
WORKERS = {'A': (9101,), 'B': (9102, 9202), 'C': (9103, 9203),
           'R': (9104, 9204, 9304), 'G': (9105,), 'Z': (9106,)}
NATIVE_WORKER = 9000
SURVIVORS = tuple(name for name in SCOPES if name != 'named_old')
EXTRA_SQL = ('resume_wins', 'proof_claim', 'named_old')
LIMITS = {'quota_bytes': 67108864, 'retention_entries': 129,
          'retention_result_bytes': 268435456}
TIMEOUTS = {'sdk_ms': 90000, 'recovery_ms': 300000, 'http_ms': 120000,
            's3_ms': 120000, 'original_unknown_ms': 1500,
            'hold_seconds': 180, 'whole_seconds': 1200}
MAX_SWEEP_PAGES = 32

# Counts are original owner POSTs, including deliberate errors and lost ACKs.
# All other SQL/catalogue/status calls have a separately closed raw denominator.
OWNER_RPC = dict(zip(SCOPES, (
    (5, 4, 3, 0, 5), (2, 2, 2, 0, 2), (4, 3, 3, 2, 2),
    (4, 3, 2, 2, 1), (3, 3, 3, 1, 1), (2, 2, 3, 2, 1),
    (3, 2, 5, 0, 2), (3, 4, 3, 1, 2), (3, 3, 4, 1, 2),
    (3, 3, 2, 1, 1), (3, 5, 3, 0, 5), (4, 3, 2, 4, 2),
    (2, 2, 2, 0, 5), (1, 1, 1, 0, 0), (5, 3, 3, 0, 2),
    (3, 3, 3, 1, 1), (3, 3, 3, 1, 1))))
OWNER_METHODS = ('prepare', 'claim', 'resume', 'abort', 'inspect')

# One fixed original descriptor per entry. "cold" always uses creator 12 and
# the new C incarnation. Repeated calls restore this input; they do not rebase.
WARM_PLANS = {
    'bulk': (('takeover', 9102, 'fenced'), ('takeover', 9102, 'active')),
    'late_prepare': (('takeover', 9102, 'active'),),
    'claim_cancel': (('takeover', 9102, 'aborted'), ('takeover', 9102, 'active')),
    'claim_wins': (('takeover', 9102, 'aborted'), ('activate', 9102, 'active')),
    'resume_cancel': (('takeover', 9102, 'aborted'), ('activate', 9102, 'active')),
    'resume_wins': (('takeover', 9102, 'active'),),
    'acl': (('takeover', 9102, 'active'),),
    'target_death': (('takeover', 9102, 'aborted'), ('takeover', 9204, 'active')),
    'resume_death': (('takeover', 9204, 'active'), ('takeover', 9103, 'active')),
    'legacy': (('takeover', 9102, 'aborted'), ('activate', 9102, 'active')),
    'proof_claim': (('takeover', 9102, 'active'), ('takeover', 9102, 'active')),
    'proof_cancel': (('takeover', 9102, 'aborted'), ('activate', 9102, 'aborted'),
                     ('activate', 9102, 'active')),
    'named_old': (('takeover', 9102, 'active'), ('takeover', 9102, 'active')),
    'named_successor': (),
    'missing_descriptor': (('takeover', 9102, 'active'), ('takeover', 9102, 'active')),
    'budget_gets': (('takeover', 9105, 'aborted'), ('takeover', 9102, 'active')),
    'budget_bytes': (('takeover', 9106, 'aborted'), ('takeover', 9102, 'active')),
}


def plans():
    result = []
    for index, name in enumerate(SCOPES, 1):
        for ordinal, (mode, worker, terminal) in enumerate(WARM_PLANS[name], 1):
            result.append(plan(name, ordinal, mode, worker, terminal, 11, index))
        if name in SURVIVORS:
            result.append(plan(name, len(WARM_PLANS[name]) + 1, 'takeover', 9203,
                               'active', 12, index, cold=True))
    return result


def plan(name, ordinal, mode, worker, terminal, creator, index=None, cold=False):
    if index is None:
        index = tuple(SCOPES).index(name) + 1
    operation = 800000 + index * 100 + ordinal
    return {'name': f'{name}-p{ordinal}', 'scope_name': name, 'creator': str(creator),
            'operation': str(operation), 'mode': mode, 'target_worker': str(worker),
            'nonces': {key: str(operation * 10 + offset)
                       for offset, key in enumerate(('claim', 'cancel', 'activate', 'abort'), 1)},
            'terminal': terminal, 'cold': cold}


def exceptional_plans():
    """Saved inputs which never produce a new accepted descriptor."""
    result = [plan('claim_cancel', 90, 'takeover', 9102, 'pending', 12),
              plan('claim_wins', 91, 'activate', 9101, 'invalid', 11)]
    result.extend({'name': name + '-changed-base', 'alias': name}
                  for name in ('bulk-p1', 'missing_descriptor-p1'))
    return result


def statements(counter, create=False):
    first = ([{'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)',
               'params': []}] if create else [])
    sql = (f'INSERT INTO witness VALUES(1,{counter},randomblob(64))' if create else
           f'UPDATE witness SET counter={counter},payload=randomblob(64) WHERE id=1')
    return first + [{'sql': sql + ' RETURNING counter,payload,random() AS nonce', 'params': []}]


def inputs():
    result = []
    for name in SCOPES:
        for counter in range(1, (260 if name == 'bulk' else 2) + 1):
            result.append({'name': f'{name}-{counter:03d}', 'scope_name': name,
                'epoch': str((counter - 1) // 129 + 1 if name == 'bulk' else 1),
                'request_id': str((counter - 1) % 129 + 1),
                'statements': statements(counter, counter == 1), 'purpose': 'seed', 'counter': counter})
    for name in EXTRA_SQL:
        result.append({'name': name + '-003', 'scope_name': name, 'epoch': '1', 'request_id': '3',
                       'statements': statements(3), 'purpose': 'after_owner', 'counter': 3})
    for request, purpose, counter in ((3, 'cancel', 777777), (4, 'blocked', 888888)):
        result.append({'name': 'bulk-' + purpose, 'scope_name': 'bulk', 'epoch': '3',
                       'request_id': str(request), 'statements': statements(counter), 'purpose': purpose})
    return result


FAULTS = (
    ('bulk-prepare-ack', 'http', 'drop', 'after_response'),
    ('bulk-claim-ack', 'http', 'drop', 'after_response'),
    ('bulk-resume-ack', 'http', 'drop', 'after_response'),
    ('cancelling-ack', 'http', 'drop', 'after_response'),
    ('legacy-activation-delayed', 'http', 'hold', 'before_forward'),
    ('late-descriptor-put', 's3', 'hold', 'before_forward'),
    ('claim-cancel-old-claim', 's3', 'hold', 'before_forward'),
    ('claim-wins-claim', 's3', 'hold', 'before_forward'),
    ('claim-wins-cancel', 's3', 'hold', 'before_forward'),
    ('resume-cancel-active', 's3', 'hold', 'before_forward'),
    ('resume-wins-active', 's3', 'hold', 'before_forward'),
    ('resume-wins-abort', 's3', 'hold', 'before_forward'),
    ('acl-change-payload', 's3', 'hold', 'before_forward'),
    ('acl-revoke-payload', 's3', 'hold', 'before_forward'),
    ('acl-prepare-descriptor', 's3', 'hold', 'before_forward'),
    ('dead-worker-claim', 's3', 'hold', 'before_forward'),
    ('dead-worker-resume', 's3', 'hold', 'before_forward'),
    ('legacy-takeover', 's3', 'hold', 'before_forward'),
    ('claim-proof-put-ack', 's3', 'drop', 'after_response'),
    ('claim-proof-read-ack', 's3', 'drop', 'after_response'),
    ('old-proof-missing', 's3', 'no_such_key', 'before_forward'),
    ('old-proof-not-before-admission', 's3', 'replace_body', 'after_response'),
    ('cancel-proof-read-ack', 's3', 'drop', 'after_response'),
    ('current-descriptor-missing', 's3', 'no_such_key', 'before_forward'),
    ('historical-descriptor-missing', 's3', 'no_such_key', 'before_forward'),
    ('same-id-different-hash', 's3', 'replace_body', 'after_response'),
    ('gets-budget-descriptor', 's3', 'hold', 'before_forward'),
    ('bytes-budget-descriptor', 's3', 'hold', 'before_forward'),
)

EXPECTED = {'scopes': 17, 'sql_originals': 297, 'sql_committed': 295,
    'native_sql_committed': 260, 'cold_sql_committed': 292, 'cold_cancelled': 1,
    'cold_unknown': 1, 'cold_business_queries': 16, 'saved_owner_inputs': 50,
    'descriptors': 46, 'admissions': 45, 'claimed': 43, 'cancelling': 2,
    'active': 36, 'aborted': 9, 'proofs': 28,
    'owner_posts': 200, 'prepare_posts': 53, 'claim_posts': 49, 'resume_posts': 47,
    'abort_posts': 16, 'inspect_posts': 35, 'faults': 28, 's3_faults': 23,
    'http_faults': 5, 'service_incarnations': 10, 'sdk_incarnations': 10,
    'owned_wait4': 27, 'warm_service_cache_losses': 9}


def head_path(name):
    return f'/scap-test/scap-object/v1/1/7/{SCOPES[name]["database"]}/head'


def prefix(name, generation):
    value = SCOPES[name]
    return (f'/scap-test/scap-object/v1/1/7/{value["database"]}/inc/{value["incarnation"]}'
            f'/gen/{value["generation"]}/storage/{generation}/objects/')


def owner_path(name, kind, creator, operation):
    assert kind in ('descriptor', 'proof')
    value = SCOPES[name]
    return (f'/scap-test/scap-object/v1/1/7/{value["database"]}/inc/{value["incarnation"]}'
            f'/gen/{value["generation"]}/owner/v1/{kind}/{creator}/{operation}')


def configuration(port, cache, endpoint, tokens, worker, role):
    return {
        'version': 1, 'listen': f'127.0.0.1:{port}', 'worker_instance': str(worker),
        'cache_directory': str(cache),
        'transport': {'version': 1, 'max_connections': 64, 'max_headers': 64,
            'max_header_bytes': 16384, 'max_buffer_bytes': 32768, 'header_timeout_ms': 5000,
            'response_timeout_ms': 120000, 'shutdown_timeout_ms': 30000},
        's3': {'endpoint': endpoint, 'region': 'us-east-1', 'bucket': 'scap-test',
            'access_key_env': 'SCAP_OWNER_ACCESS', 'secret_key_env': 'SCAP_OWNER_SECRET',
            'session_token_env': None, 'allow_http': True, 'timeout_ms': TIMEOUTS['s3_ms']},
        'admission': {'active_database_actors': 32, 'active_database_actors_per_tenant': 32,
            'actor_idle_timeout_ms': 120000, 'control_workers': 4,
            'queued_total': 64, 'queued_per_tenant': 64, 'queued_per_database': 16,
            'reserved_controls': 4, 'data_intake': 32, 'control_intake': 16,
            'recovery_intake': 4, 'max_body_bytes': 1048576,
            'timeout_ms': TIMEOUTS['http_ms'], 'recovery_timeout_ms': TIMEOUTS['recovery_ms']},
        'catalogue': {'workers': 4, 'queued_total': 16, 'queued_per_tenant': 16,
            'queued_per_name': 4, 'intake': 8, 'max_body_bytes': 65536, 'timeout_ms': 120000},
        'output': {'version': 1, 'bytes': 268435456, 'bytes_per_tenant': 201326592,
            'control_bytes': 8388608, 'control_bytes_per_tenant': 1048576},
        'cache': {'pages_per_actor': 4096, 'parallel_recoveries': 2},
        'execution': {'result_memory_bytes': 134217728},
        'owner_recovery': {'payload_gets': 0 if role == 'G' else 1048576,
                           'payload_bytes': 1 if role == 'Z' else 68719476736},
        'credentials': [{'sha256': tokens[principal], 'deployment': '1', 'tenant': '7',
            'principal': principal, 'provision': principal == '11' and role in ('A', 'C')}
            for principal in ('11', '12')],
        'gc': ({'deployment': '1', 'access_key_env': 'SCAP_OWNER_GC_ACCESS',
            'secret_key_env': 'SCAP_OWNER_GC_SECRET', 'session_token_env': None}
            if role == 'C' else None),
    }


def validate():
    assert len(SCOPES) == EXPECTED['scopes']
    assert len({tuple(value.values()) for value in SCOPES.values()}) == len(SCOPES)
    assert len(inputs()) == EXPECTED['sql_originals']
    committed = [row for row in inputs() if row['purpose'] not in ('cancel', 'blocked')]
    assert len(committed) == EXPECTED['sql_committed']
    assert len([row for row in committed if row['scope_name'] in SURVIVORS]) == EXPECTED['cold_sql_committed']
    assert len(plans()) == EXPECTED['descriptors']
    assert len(plans()) + len(exceptional_plans()) == EXPECTED['saved_owner_inputs']
    assert len([row for row in plans() if row['terminal'] != 'fenced']) == EXPECTED['admissions']
    for terminal in ('active', 'aborted'):
        assert len([row for row in plans() if row['terminal'] == terminal]) == EXPECTED[terminal]
    assert EXPECTED['admissions'] - len(SCOPES) == EXPECTED['proofs']
    for index, method in enumerate(OWNER_METHODS):
        assert sum(row[index] for row in OWNER_RPC.values()) == EXPECTED[method + '_posts']
    assert sum(map(sum, OWNER_RPC.values())) == EXPECTED['owner_posts']
    assert len(FAULTS) == EXPECTED['faults']
    for layer in ('s3', 'http'):
        assert sum(row[1] == layer for row in FAULTS) == EXPECTED[layer + '_faults']
    workers = [worker for values in WORKERS.values() for worker in values] + [NATIVE_WORKER]
    assert len(workers) == len(set(workers)) == EXPECTED['service_incarnations'] + 1
    return dict(EXPECTED)


if __name__ == '__main__':
    import json
    print(json.dumps(validate(), sort_keys=True, indent=2))
