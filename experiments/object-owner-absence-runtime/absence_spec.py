"""Predeclared inputs for three actual absence races."""
from absence_support import base_spec

SCOPES = {name: base_spec.direct(number) for name, number in
          (('current', 7301), ('superseded', 7302), ('proof', 7303))}
ROLES = ('A', 'B', 'C')
WORKERS = {'A': (9401,), 'B': (9402,), 'C': (9403,)}
NATIVE_WORKER = 9400  # Native assembler receipt is bound; this profile uses scapd's native engine.
NAMED = {}
LIMITS = dict(base_spec.LIMITS)
TIMEOUTS = dict(base_spec.TIMEOUTS)
MAX_SWEEP_PAGES = 0
OWNER_RPC = {'current': (2, 1, 1, 0, 1), 'superseded': (4, 2, 1, 3, 1), 'proof': (4, 2, 1, 3, 1)}
EXPECTED = {'scopes': 3, 'sql_originals': 6, 'sql_committed': 6, 'lookups': 6,
            'business_queries': 3, 'saved_owner_inputs': 7, 'descriptors': 7, 'proofs': 4,
            'owner_posts': 27, 'claimed': 5, 'cancelling': 2, 'active': 3, 'aborted': 4,
            's3_faults': 4, 'service_incarnations': 3, 'sdk_incarnations': 3, 'owned_wait4': 12}
FAULTS = ((name + '-real-404', 's3', 'hold', 'after_response') for name in SCOPES)
FAULTS = tuple(FAULTS) + (('proof-stable-head2', 's3', 'hold', 'after_response'),)
configuration = base_spec.configuration


def inputs():
    return [{'name': f'{name}-{counter:03d}', 'scope_name': name, 'epoch': '1',
             'request_id': str(counter), 'statements': base_spec.statements(counter, counter == 1),
             'purpose': 'seed', 'counter': counter} for name in SCOPES for counter in (1, 2)]


def plans():
    result = []
    for index, name in enumerate(SCOPES, 1):
        for ordinal in range(1, 2 if name == 'current' else 4):
            operation = 810000 + index * 100 + ordinal
            result.append({'name': f'{name}-p{ordinal}', 'scope_name': name, 'creator': '11',
                'operation': str(operation), 'mode': 'takeover' if ordinal == 1 else 'activate',
                'target_worker': '9402', 'nonces': {key: str(operation * 10 + offset)
                    for offset, key in enumerate(('claim', 'cancel', 'activate', 'abort'), 1)}})
    return result


def exceptional_plans():
    return []


def head_path(name):
    return f'/scap-test/scap-object/v1/1/7/{SCOPES[name]["database"]}/head'


def owner_path(name, kind, creator, operation):
    return (f'/scap-test/scap-object/v1/1/7/{SCOPES[name]["database"]}'
            f'/inc/1/gen/1/owner/v1/{kind}/{creator}/{operation}')


def validate():
    assert len(inputs()) == 6 and len(plans()) == 7 and sum(map(sum, OWNER_RPC.values())) == 27
    assert len(FAULTS) == 4 and len({tuple(value.values()) for value in SCOPES.values()}) == 3
    assert len({worker for workers in WORKERS.values() for worker in workers}) == 3
    return EXPECTED
