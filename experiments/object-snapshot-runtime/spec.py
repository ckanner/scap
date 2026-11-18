"""Fixed native SQL, point identities, workers and original fault denominator."""
from pathlib import Path
import importlib.util

SCOPE = dict(zip(('deployment', 'tenant', 'database', 'incarnation', 'generation'),
                 ('1', '7', '8201', '1', '1')))
SCOPES = {'bulk': SCOPE}
NAMED = {}
ROLES = ('A', 'C')
WORKERS = {'A': (9401,), 'C': (9403, 9503)}
NATIVE_WORKER = 9300
LIMITS = {'quota_bytes': 67108864, 'retention_entries': 2, 'retention_result_bytes': 268435456}
SNAPSHOT_LIMITS = {'max_points': 2, 'max_logical_bytes': '4194304'}
TIMEOUTS = {'sdk_ms': 90000, 'recovery_ms': 300000, 'http_ms': 120000,
            's3_ms': 120000, 'original_unknown_ms': 1500, 'hold_seconds': 180, 'whole_seconds': 600}
MAX_SWEEP_PAGES = 32
POINTS = ({'name': 'point-one', 'creator': '11', 'operation': '880001', 'label': 'after-original-2', 'counter': 2},
          {'name': 'point-two', 'creator': '11', 'operation': '880002', 'label': 'after-original-4', 'counter': 4})
FAULTS = (('capture-original-ack', 'http', 'drop', 'after_response'),
          ('release-original-ack', 'http', 'drop', 'after_response'))
EXPECTED = {'scopes': 1, 'sql_originals': 6, 'sql_committed': 6, 'native_sql_committed': 2,
            'public_sql_committed': 4, 'cold_sql_committed': 6, 'retained_windows': 3,
            'saved_owner_inputs': 2, 'owner_descriptors': 2, 'owner_posts': 6,
            'saved_snapshot_inputs': 2, 'snapshot_descriptors': 2, 'snapshot_proofs': 2,
            'captures': 2, 'releases': 2, 'snapshot_limits_posts': 1,
            'copy_plans': 1, 'promotions': 1, 'sweep_rounds': 2, 'terminal_seals': 1,
            'terminal_rejections': 1, 'faults': 2, 'http_faults': 2, 's3_faults': 0,
            'service_incarnations': 3, 'sdk_incarnations': 3, 'owned_wait4': 13,
            'warm_service_cache_losses': 2, 'native_cache_losses': 1}
OWNER_RPC = {'bulk': (2, 2, 2, 0, 0)}


def plans():
    return [{'name': f'bulk-p{index}', 'scope_name': 'bulk', 'creator': '11',
             'operation': str(890000 + index), 'mode': 'takeover', 'target_worker': str(worker),
             'nonces': dict(zip(('claim', 'cancel', 'activate', 'abort'),
                               (str(8900000 + index * 10 + offset) for offset in range(1, 5)))),
             'terminal': 'active', 'cold': index == 2}
            for index, worker in ((1, 9401), (2, 9503))]


def exceptional_plans():
    return []


def statements(counter):
    create = [{'sql': 'CREATE TABLE witness(id INTEGER PRIMARY KEY, counter INTEGER NOT NULL, payload BLOB NOT NULL)',
               'params': []}] if counter == 1 else []
    size = 64 if counter <= 2 else 196608
    expression = (f'INSERT INTO witness VALUES(1,{counter},randomblob({size}))' if counter == 1 else
                  f'UPDATE witness SET counter={counter},payload=randomblob({size}) WHERE id=1')
    return create + [{'sql': expression + ' RETURNING counter,payload,random() AS nonce', 'params': []}]


def inputs():
    return [{'name': f'original-{counter}', 'scope_name': 'bulk',
             'epoch': str((counter - 1) // 2 + 1), 'request_id': str((counter - 1) % 2 + 1),
             'counter': counter, 'purpose': 'seed' if counter <= 2 else 'public',
             'statements': statements(counter)} for counter in range(1, 7)]


def configuration(port, cache, endpoint, tokens, worker, role):
    description = importlib.util.spec_from_file_location('snapshot_owner_configuration',
        Path(__file__).resolve().parent.parent / 'object-owner-plan-runtime/spec.py')
    value = importlib.util.module_from_spec(description)
    description.loader.exec_module(value)
    return value.configuration(port, cache, endpoint, tokens, worker, role)


def prefix(generation):
    return f'/scap-test/scap-object/v1/1/7/8201/inc/1/gen/1/storage/{generation}/objects/'


def snapshot_path(kind, operation):
    assert kind in ('descriptor', 'proof')
    return f'/scap-test/scap-object/v1/1/7/8201/inc/1/gen/1/snapshot/v1/{kind}/11/{operation}'


def validate():
    assert len(inputs()) == EXPECTED['sql_originals']
    assert len(POINTS) == EXPECTED['saved_snapshot_inputs']
    assert len(plans()) == EXPECTED['saved_owner_inputs']
    assert sum(map(sum, OWNER_RPC.values())) == EXPECTED['owner_posts']
    assert len(FAULTS) == EXPECTED['faults']
    assert len(set([NATIVE_WORKER] + [worker for values in WORKERS.values() for worker in values])) == 4
    assert EXPECTED['owned_wait4'] == 4 + 2 + 1 + EXPECTED['service_incarnations'] + EXPECTED['sdk_incarnations']
    return dict(EXPECTED)
