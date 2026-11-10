"""Frozen owner SDK inputs and offered-operation denominator; no product logic."""

WORKERS = {'a': '7101', 'b': '7202', 'c': '7303', 'd': '7404'}
NAMES = ('route', 'guard', 'race', 'late', 'lost_claim', 'lost_activation', 'corrupt',
         'acl', 'lifecycle', 'deadline', 'cold', 'recovery', 'rejects')
SCOPES = {name: {'deployment': '1', 'tenant': '7', 'database': str(1001 + index),
                 'incarnation': '1', 'generation': '1'} for index, name in enumerate(NAMES)}
PRINCIPALS = {'writer': '11', 'manager': '12', 'reader': '13', 'blind_admin': '14', 'rescue': '15'}
POLICY = [
    {'principal': '11', 'read': True, 'write': True, 'admin': False},
    {'principal': '12', 'read': True, 'write': False, 'admin': True},
    {'principal': '13', 'read': True, 'write': False, 'admin': False},
    {'principal': '14', 'read': False, 'write': False, 'admin': True},
    {'principal': '15', 'read': True, 'write': False, 'admin': True},
]
SEED_SQL = ('CREATE TABLE witness(n INTEGER PRIMARY KEY)', 'INSERT INTO witness(n) VALUES(1) RETURNING n')
WRITE_SQL = 'INSERT INTO witness(n) VALUES(2) RETURNING n'
QUERY_SQL = 'SELECT n FROM witness ORDER BY n'
DEADLINES = {'ordinary_ms': 15000, 'recovery_ms': 30000, 's3_ms': 10000,
             'client_ms': 20000, 'owner_ms': 35000, 'short_ms': 250,
             'gate_seconds': 10, 'child_seconds': 40, 'ready_seconds': 20, 'actor_idle_ms': 5000}

COMMANDS = {}


def command(name, operation, scope, http=(), **fields):
    assert name not in COMMANDS
    COMMANDS[name] = {'id': name, 'operation': operation, 'scope': scope, 'phase': fields.pop('phase', scope),
                      'http': [list(value) for value in http], **fields}


def prepare(name, scope, target='b', nonces=(101, 102), **fields):
    command(name, 'prepare', scope, [('a', 'status', 200)], target=target,
            takeover_nonce=str(nonces[0]), activate_nonce=str(nonces[1]), **fields)


def reconcile(name, scope, intent, target='b', *, code=200, activate=True, bootstrap='a', **fields):
    calls = [(bootstrap, 'status', 200), (target, 'takeover', code)]
    if activate:
        calls.append((target, 'activate', 200))
    command(name, 'reconcile', scope, calls, intent=intent, bootstrap=bootstrap, **fields)


command('seed', 'seed', None, phase='seed')
prepare('route_prepare', 'route')
reconcile('route_reconcile', 'route', 'route_prepare')
command('route_write', 'routed_execute', 'route', [('a', 'status', 200), ('b', 'execute', 200)], request_id='2')
command('route_lookup', 'lookup', 'route', [('a', 'lookup', 200)], request='route_write')
command('route_query', 'routed_query', 'route', [('a', 'status', 200), ('b', 'query', 200)])

prepare('guard_prepare', 'guard', nonces=(201, 202), registry='misbound')
reconcile('guard_reconcile', 'guard', 'guard_prepare', target='c', code=409, activate=False, registry='misbound')
command('guard_inspect', 'inspect', 'guard', [('a', 'status', 200)], intent='guard_prepare', registry='misbound')

prepare('race_prepare_b', 'race', 'b', (301, 302))
prepare('race_prepare_c', 'race', 'c', (303, 304))
reconcile('race_b', 'race', 'race_prepare_b')
reconcile('race_c', 'race', 'race_prepare_c', target='c', code=409, activate=False)
command('race_inspect_c', 'inspect', 'race', [('a', 'status', 200)], intent='race_prepare_c')

prepare('late_prepare', 'late', nonces=(401, 402))
command('late_write', 'routed_execute', 'late', [('a', 'status', 200), ('a', 'execute', 409)], request_id='2')
reconcile('late_reconcile', 'late', 'late_prepare', bootstrap='c')
command('late_lookup', 'lookup', 'late', [('a', 'lookup', 200)], request='late_write')
command('late_cancel', 'cancel', 'late', [('a', 'cancel', 200)], request='late_write')
command('late_cancelled', 'lookup', 'late', [('a', 'lookup', 200)], request='late_write')
command('late_query', 'routed_query', 'late', [('a', 'status', 200), ('b', 'query', 200)])

prepare('claim_prepare', 'lost_claim', nonces=(501, 502))
reconcile('claim_lost', 'lost_claim', 'claim_prepare', code='dropped', activate=False)
command('claim_inspect', 'inspect', 'lost_claim', [('a', 'status', 200)], intent='claim_prepare')
command('claim_reuse', 'reuse', 'lost_claim', intent='claim_prepare')
command('claim_restored_reuse', 'restore_reuse', 'lost_claim', intent='claim_prepare')
command('claim_activation_prepare', 'prepare_activation', 'lost_claim', [('a', 'status', 200)], activate_nonce='503')
command('claim_activation', 'reconcile', 'lost_claim', [('a', 'status', 200), ('b', 'activate', 200)],
        intent='claim_activation_prepare')

prepare('activation_prepare', 'lost_activation', nonces=(601, 602))
command('activation_lost', 'reconcile', 'lost_activation',
        [('a', 'status', 200), ('b', 'takeover', 200), ('b', 'activate', 'dropped')], intent='activation_prepare')
command('activation_advance', 'quota', 'lost_activation', [('a', 'quota', 200)], revision='6', nonce='603')
command('activation_inspect', 'inspect', 'lost_activation', [('a', 'status', 200)], intent='activation_prepare')

prepare('corrupt_prepare', 'corrupt', nonces=(701, 702))
command('corrupt_reconcile', 'reconcile', 'corrupt',
        [('a', 'status', 200), ('b', 'takeover', 200), ('b', 'activate', 409)], intent='corrupt_prepare')
command('corrupt_inspect', 'inspect', 'corrupt', [('a', 'status', 200)], intent='corrupt_prepare')
command('corrupt_activation_prepare', 'prepare_activation', 'corrupt', [('a', 'status', 200)], activate_nonce='703')
command('corrupt_activation', 'reconcile', 'corrupt', [('a', 'status', 200), ('b', 'activate', 200)],
        intent='corrupt_activation_prepare')
command('corrupt_query', 'routed_query', 'corrupt', [('a', 'status', 200), ('b', 'query', 200)])

prepare('acl_prepare', 'acl', nonces=(801, 802))
reconcile('acl_reconcile', 'acl', 'acl_prepare', code=403, activate=False)
command('acl_revoke', 'revoke_admin', 'acl', [('a', 'policy', 200)], revision='4', nonce='803', caller='rescue')
command('acl_reuse', 'reuse', 'acl', intent='acl_prepare')

prepare('lifecycle_prepare', 'lifecycle', nonces=(901, 902))
command('lifecycle_change', 'lifecycle', 'lifecycle', [('a', 'lifecycle', 200)], revision='4', nonce='903')
command('lifecycle_reconcile', 'reconcile', 'lifecycle', [('a', 'status', 200)], intent='lifecycle_prepare')
command('lifecycle_inspect', 'inspect', 'lifecycle', [('a', 'status', 200)], intent='lifecycle_prepare')
command('lifecycle_write', 'routed_execute', 'lifecycle', [('a', 'status', 200)], request_id='2')

command('recovery_warm', 'routed_query', 'route', [('a', 'status', 200), ('b', 'query', 200)], phase='recovery')
prepare('recovery_prepare', 'recovery', nonces=(1001, 1002))
reconcile('recovery_reconcile', 'recovery', 'recovery_prepare')
command('recovery_hot', 'routed_query', 'route', [('a', 'status', 200), ('b', 'query', 200)], phase='recovery')
command('recovery_control', 'status', 'recovery', [('a', 'status', 200)], caller='manager')

command('reject_unknown_route', 'routed_execute', 'rejects', [('a', 'status', 200)], request_id='2', registry='unknown')
command('reject_auth', 'routed_execute', 'rejects', [('a', 'status', 401)], request_id='3', caller='invalid')
command('reject_read', 'routed_execute', 'rejects', [('a', 'status', 403)], request_id='4', caller='blind_admin')
command('busy_held', 'status', 'rejects', [('a', 'status', 200)], caller='manager')
command('reject_busy', 'routed_execute', 'rejects', [('a', 'status', 429)], request_id='5')
command('reject_redirect', 'routed_execute', 'rejects', [('a', 'status', 'redirect')], request_id='6')
command('reject_authority', 'routed_execute', 'rejects', [('a', 'status', 503)], request_id='7')
command('deadline_write', 'routed_execute', 'deadline', [('a', 'status', 'deadline')], request_id='2', timeout_ms=250)
command('cold_write', 'routed_execute', 'cold', [('a', 'status', 200), ('a', 'execute', 200)], request_id='2')

# These commands run in a second actual Node process after a real kill/wait4 of
# worker A. Only the metadata bootstrap changes; mutation routes stay fixed.
command('bootstrap_inspect', 'restore_inspect', 'lost_activation', [('c', 'status', 200)],
        intent='activation_prepare', bootstrap='c', node=2)
command('bootstrap_reuse', 'restore_reuse', 'lost_activation', intent='activation_prepare', bootstrap='c', node=2)
command('bootstrap_changed_route', 'restore_invalid_route', 'lost_activation', intent='activation_prepare', bootstrap='c', node=2)
command('bootstrap_wrong_scope', 'restore_wrong_scope', 'lost_activation', intent='activation_prepare', bootstrap='c', node=2)
command('cold_prepare', 'prepare', 'cold', [('c', 'status', 200)], target='d', takeover_nonce='1101',
        activate_nonce='1102', bootstrap='c', node=2)
reconcile('cold_reconcile', 'cold', 'cold_prepare', target='d', bootstrap='c', node=2)
command('cold_lookup_seed', 'lookup', 'cold', [('c', 'lookup', 200)], request='seed_cold', bootstrap='c', node=2)
command('cold_lookup_write', 'lookup', 'cold', [('c', 'lookup', 200)], request='cold_write', bootstrap='c', node=2)
command('cold_query', 'routed_query', 'cold', [('c', 'status', 200), ('d', 'query', 200)], bootstrap='c', node=2)

PLAN = {'schema': 1, 'profile': 'explicit-owner-real-transport-v1', 'workers': WORKERS,
        'scopes': SCOPES, 'seed_scopes': list(NAMES), 'principals': PRINCIPALS, 'policy': POLICY,
        'seed_sql': list(SEED_SQL), 'write_sql': WRITE_SQL, 'query_sql': QUERY_SQL,
        'deadlines': DEADLINES, 'commands': list(COMMANDS.values()), 'seed_nonce_base': 10000,
        'automatic_failure_detector': 'NOT_IMPLEMENTED', 'automatic_controller': 'NOT_IMPLEMENTED',
        'automatic_registry_roll_forward': 'NOT_IMPLEMENTED', 'aws_standard': 'NOT_RUN', 'production_slo': 'NOT_RUN'}


def head_path(name):
    scope = SCOPES[name]
    return '/scap-test/scap-object/v1/1/7/' + scope['database'] + '/head'
