"""Independent HEAD6/7/8, owner Descriptor/Proof and immutable closure decoder.

Only pure SQL/result/frame witnesses are shared with earlier audits. This
module does not import the product, SDK, runner, or a product state machine.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

_spec = importlib.util.spec_from_file_location('owner_pure_graph',
    Path(__file__).resolve().parent.parent / 'object-reclamation-runtime/audit_model.py')
graph = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(graph)
wire, Rejected, need = graph.wire, graph.Rejected, graph.need
sha, uint, digest = graph.sha, graph.uint, graph.digest
BASIS, HEAD = graph.BASIS, graph.HEAD
SCOPE = ('deployment', 'tenant', 'database', 'incarnation', 'generation')
OWNER = ('reference', 'admission', 'phase')
REFERENCE = ('creator', 'operation', 'descriptor_hash')
ADMISSION = ('kind', 'revision', 'head_serial')
PHASE = ('kind', 'revision', 'head_serial', 'nonce', 'owner_epoch', 'owner_instance')
OWNER_INPUT = ('creator', 'operation', 'expected_revision', 'expected_head_serial', 'mode', 'target_worker', 'nonces')
NONCES = ('claim', 'cancel', 'activate', 'abort')
BASE = ('head_hash', 'etag', 'revision', 'head_serial', 'owner_epoch', 'owner_instance', 'active', 'previous_marker')
HEAD_ORDER = ('format', 'scope', 'head_serial', 'storage', 'revision', 'transition', 'sequence',
              'owner_epoch', 'owner_instance', 'owner_plan', 'active', 'auth_epoch', 'policy',
              'lifecycle', 'creation', 'deletion', 'data_root', 'quota', 'retention', 'request_epoch', 'windows')


def shape(value, keys, rule):
    need(isinstance(value, dict) and set(value) == set(keys), rule)
    return value


def ordered(value, keys):
    return {key: value[key] for key in keys if key in value}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def canonical_marker(value):
    return {'reference': ordered(value['reference'], REFERENCE),
            'admission': ordered(value['admission'], ADMISSION),
            'phase': ordered(value['phase'], PHASE)}


def canonical_input(value):
    return {**ordered(value, OWNER_INPUT[:-1]), 'nonces': ordered(value['nonces'], NONCES)}


def canonical_head(value):
    """Typed field order is independent of JSON source whitespace/object order."""
    result = ordered(value, HEAD_ORDER)
    result['scope'] = ordered(value['scope'], SCOPE)
    storage = ordered(value['storage'], ('active_generation', 'allocated_through', 'plan', 'sweep', 'terminal'))
    if storage['plan'] is not None:
        plan = ordered(storage['plan'], ('serial', 'source', 'target', 'phase', 'basis'))
        basis = ordered(plan['basis'], ('data_root', 'windows', 'sequence', 'revision', 'quota', 'retention', 'request_epoch'))
        basis['windows'] = [ordered(window, ('epoch', 'root', 'count', 'result_bytes')) for window in basis['windows']]
        basis['quota'] = ordered(basis['quota'], ('max_bytes',))
        basis['retention'] = ordered(basis['retention'], ('max_entries', 'max_result_bytes'))
        plan['basis'], storage['plan'] = basis, plan
    if storage['sweep'] is not None:
        sweep = ordered(storage['sweep'], ('serial', 'generation', 'next_after', 'exhausted', 'entries'))
        sweep['entries'] = [ordered(entry, ('key', 'hash', 'etag', 'disposition')) for entry in sweep['entries']]
        storage['sweep'] = sweep
    result['storage'] = storage
    result['transition'] = ordered(value['transition'], ('revision', 'nonce'))
    if 'owner_plan' in value:
        result['owner_plan'] = canonical_marker(value['owner_plan'])
    result['policy'] = [ordered(permission, ('principal', 'read', 'write', 'admin')) for permission in value['policy']]
    if value['creation'] is not None:
        result['creation'] = ordered(value['creation'], ('creator', 'operation', 'name_hash', 'descriptor_hash'))
    if value['deletion'] is not None:
        result['deletion'] = ordered(value['deletion'], ('kind', 'principal', 'operation', 'expected_name_revision',
                                                       'expected_head_revision', 'nonce', 'descriptor_hash'))
    result['quota'] = ordered(value['quota'], ('max_bytes',))
    result['retention'] = ordered(value['retention'], ('max_entries', 'max_result_bytes'))
    result['windows'] = [ordered(window, ('epoch', 'root', 'count', 'result_bytes')) for window in value['windows']]
    return encoded(result)


def owner_input(value):
    shape(value, OWNER_INPUT, 'owner-input-shape')
    for key in OWNER_INPUT[:4] + ('target_worker',):
        uint(value[key], minimum=1)
    need(value['expected_revision'] <= value['expected_head_serial'], 'owner-original-counter-order')
    need(value['mode'] in ('takeover', 'activate'), 'owner-mode')
    shape(value['nonces'], NONCES, 'owner-nonces-shape')
    for nonce in value['nonces'].values():
        uint(nonce, minimum=1)
    need(len(set(value['nonces'].values())) == 4, 'owner-distinct-nonces')
    return value


def owner_reference(value):
    shape(value, REFERENCE, 'owner-reference-shape')
    uint(value['creator'], minimum=1)
    uint(value['operation'], minimum=1)
    digest(value['descriptor_hash'])
    return value


def owner_marker(value):
    shape(value, OWNER, 'owner-marker-shape')
    owner_reference(value['reference'])
    admission = shape(value['admission'], ADMISSION, 'owner-admission-shape')
    phase = shape(value['phase'], PHASE, 'owner-phase-shape')
    need(admission['kind'] in ('claim', 'cancel'), 'owner-admission-kind')
    need(phase['kind'] in ('claimed', 'cancelling', 'active', 'aborted'), 'owner-phase-kind')
    for key in ('revision', 'head_serial'):
        uint(admission[key], minimum=2)
        uint(phase[key], minimum=2)
    for key in ('nonce', 'owner_epoch', 'owner_instance'):
        uint(phase[key], minimum=1)
    need(admission['revision'] <= admission['head_serial'] and phase['revision'] <= phase['head_serial'], 'owner-marker-counter-order')
    expected_kind = {'claimed': 'claim', 'cancelling': 'cancel', 'active': 'claim', 'aborted': admission['kind']}[phase['kind']]
    need(admission['kind'] == expected_kind, 'owner-phase-admission-kind')
    if phase['kind'] in ('claimed', 'cancelling'):
        need(all(phase[key] == admission[key] for key in ('revision', 'head_serial')), 'owner-pending-original-admission')
    else:
        need(all(phase[key] > admission[key] for key in ('revision', 'head_serial')), 'owner-terminal-after-admission')
    need(phase['revision'] - admission['revision'] == phase['head_serial'] - admission['head_serial'], 'owner-no-technical-gap')
    need(len(encoded(canonical_marker(value))) <= 4096, 'owner-marker-budget')
    return value


def marker_in_head(value):
    marker = owner_marker(value['owner_plan'])
    phase = marker['phase']
    need(phase['revision'] <= value['revision'] and phase['head_serial'] <= value['head_serial']
         and value['lifecycle'] != 'provisioning', 'owner-head-history-order')
    need(value['revision'] != phase['revision'] or value['transition']['nonce'] == phase['nonce'], 'owner-same-revision-nonce')
    if phase['kind'] != 'active':
        need(value['active'] is False, 'owner-non-active-inactive')
    if phase['kind'] in ('claimed', 'cancelling'):
        storage = value['storage']
        need(value['lifecycle'] == 'ready' and storage['plan'] is None and storage['sweep'] is None
             and storage.get('terminal') is None, 'owner-pending-no-maintenance')
        need(value['owner_epoch'] == phase['owner_epoch'] and value['owner_instance'] == phase['owner_instance'], 'owner-pending-current-tuple')
        need(value['revision'] < 2**64 - 1 and value['head_serial'] < 2**64 - 1, 'owner-pending-final-reserve')
        need(value['revision'] - phase['revision'] == value['head_serial'] - phase['head_serial'], 'owner-pending-business-only')


def owner_key(path):
    match = re.fullmatch(r'/scap-test/scap-object/v1/1/7/([1-9][0-9]*)/inc/([1-9][0-9]*)/gen/([1-9][0-9]*)'
                        r'/owner/v1/(descriptor|proof)/([1-9][0-9]*)/([1-9][0-9]*)', path)
    need(match is not None and len(path.removeprefix('/scap-test/').encode()) <= 512, 'owner-permanent-key')
    database, incarnation, generation, kind, creator, operation = match.groups()
    logical = dict(zip(SCOPE, (1, 7, int(database), int(incarnation), int(generation))))
    scope(logical)
    return logical, kind, uint(int(creator), minimum=1), uint(int(operation), minimum=1)


def canonical_descriptor(value):
    return {'version': value['version'], 'scope': ordered(value['scope'], SCOPE),
            'input': canonical_input(value['input']), 'base': ordered(value['base'], BASE),
            'input_digest': value['input_digest']}


def descriptor(raw, path=None):
    need(len(raw) <= 16384, 'owner-descriptor-budget')
    value = wire.parse(raw)
    shape(value, ('version', 'scope', 'input', 'base', 'input_digest'), 'owner-descriptor-shape')
    need(type(value['version']) is int and value['version'] == 1, 'owner-descriptor-version')
    scope(value['scope'])
    original = owner_input(value['input'])
    base = shape(value['base'], BASE, 'owner-base-shape')
    for key in ('revision', 'head_serial'):
        uint(base[key], 2**64 - 3, 1)
    for key in ('owner_epoch', 'owner_instance'):
        uint(base[key], minimum=1)
    need(type(base['active']) is bool, 'owner-base-active')
    digest(base['head_hash'])
    need(isinstance(base['etag'], str) and re.fullmatch(r'"[!#-~]{0,1022}"', base['etag']), 'owner-original-etag')
    if base['previous_marker'] is not None:
        digest(base['previous_marker'])
    need(base['revision'] == original['expected_revision'] and base['head_serial'] == original['expected_head_serial'], 'owner-original-base-counters')
    if original['mode'] == 'takeover':
        need(base['owner_epoch'] < 2**64 - 1, 'owner-takeover-epoch-reserve')
    else:
        need(base['active'] is False and base['owner_instance'] == original['target_worker'], 'owner-activate-original-inactive-target')
    canonical = canonical_descriptor(value)
    preimage = [1, canonical['scope'], canonical['input'], canonical['base']]
    need(value['input_digest'] == sha(encoded(preimage)), 'owner-original-input-digest')
    if path is not None:
        logical, kind, creator, operation = owner_key(path)
        need(kind == 'descriptor' and logical == value['scope'] and creator == original['creator']
             and operation == original['operation'], 'owner-descriptor-full-key')
    return value


def reference(value):
    original = value['input']
    return {'creator': original['creator'], 'operation': original['operation'],
            'descriptor_hash': sha(encoded(canonical_descriptor(value)))}


def descriptor_base(value, snapshot, etag):
    base = value['base']
    need(snapshot['scope'] == value['scope'] and etag == base['etag']
         and sha(canonical_head(snapshot)) == base['head_hash'], 'owner-exact-original-head')
    need(all(snapshot[key] == base[key] for key in ('revision', 'head_serial', 'owner_epoch', 'owner_instance', 'active')),
         'owner-original-base-fields')
    previous = snapshot.get('owner_plan')
    need(base['previous_marker'] == (None if previous is None else sha(encoded(canonical_marker(previous)))), 'owner-original-marker-hash')


def descriptor_marker(value, marker):
    owner_marker(marker)
    base, original = value['base'], value['input']
    admission, phase = marker['admission'], marker['phase']
    need(marker['reference'] == reference(value), 'owner-accepted-descriptor-reference')
    need(admission['revision'] == base['revision'] + 1 and admission['head_serial'] == base['head_serial'] + 1, 'owner-accepted-original-admission')
    if admission['kind'] == 'cancel':
        epoch, worker = base['owner_epoch'], base['owner_instance']
    else:
        epoch = base['owner_epoch'] + (original['mode'] == 'takeover')
        worker = original['target_worker']
    need((phase['owner_epoch'], phase['owner_instance']) == (epoch, worker), 'owner-accepted-original-target')
    key = {'claimed': 'claim', 'cancelling': 'cancel', 'active': 'activate', 'aborted': 'abort'}[phase['kind']]
    need(phase['nonce'] == original['nonces'][key], 'owner-original-phase-nonce')


def proof(raw, path=None):
    need(len(raw) <= 8192, 'owner-proof-budget')
    value = wire.parse(raw)
    shape(value, ('version', 'scope', 'marker'), 'owner-proof-shape')
    need(type(value['version']) is int and value['version'] == 1, 'owner-proof-version')
    scope(value['scope'])
    owner_marker(value['marker'])
    need(value['marker']['phase']['kind'] in ('active', 'aborted'), 'owner-proof-terminal-only')
    if path is not None:
        logical, kind, creator, operation = owner_key(path)
        ref = value['marker']['reference']
        need(kind == 'proof' and logical == value['scope'] and creator == ref['creator']
             and operation == ref['operation'], 'owner-proof-full-key')
    return value


def proof_before(value, original, current):
    need(value['scope'] == original['scope'] == current['scope'], 'owner-proof-scope-context')
    descriptor_marker(original, value['marker'])
    marker = current.get('owner_plan')
    need(marker is not None and marker['reference'] != value['marker']['reference'], 'owner-proof-superseded-marker')
    need(all(value['marker']['phase'][key] < marker['admission'][key]
             for key in ('revision', 'head_serial')), 'owner-proof-before-current-admission')


def scope(value):
    need(isinstance(value, dict) and set(value) == set(SCOPE), 'full-scope-shape')
    for key in SCOPE:
        uint(value[key], minimum=1)
    need(value['deployment'] == 1 and value['tenant'] == 7, 'fixed-namespace')
    return value


def scope_key(value):
    return tuple(scope(value)[key] for key in SCOPE)


def prefix(value, generation):
    scope(value)
    return (f'/scap-test/scap-object/v1/1/7/{value["database"]}/inc/{value["incarnation"]}'
            f'/gen/{value["generation"]}/storage/{generation}/objects/')


def object_path(path):
    match = re.fullmatch(r'/scap-test/scap-object/v1/1/7/([1-9][0-9]*)/inc/([1-9][0-9]*)'
                        r'/gen/([1-9][0-9]*)/storage/([1-9][0-9]*)/objects/([0-9a-f]{64})', path)
    need(match is not None, 'payload-key-only')
    database, incarnation, generation, storage, digest_value = match.groups()
    value = dict(zip(SCOPE, (1, 7, int(database), int(incarnation), int(generation))))
    scope(value)
    uint(int(storage), minimum=1)
    return value, int(storage), digest_value


def head_path(path):
    match = re.fullmatch(r'/scap-test/scap-object/v1/1/7/([1-9][0-9]*)/head', path)
    return None if match is None else uint(int(match.group(1)), minimum=1)


def transition(value):
    need(isinstance(value, dict) and set(value) == {'revision', 'nonce'}, 'business-transition-shape')
    uint(value['revision'], minimum=1)
    uint(value['nonce'], minimum=1)


def origin(value):
    need(isinstance(value, dict) and set(value) == {'creator', 'operation', 'name_hash', 'descriptor_hash'}, 'creation-origin-shape')
    uint(value['creator'], minimum=1)
    uint(value['operation'], minimum=1)
    digest(value['name_hash'])
    digest(value['descriptor_hash'])


def deletion(value):
    need(isinstance(value, dict) and set(value) == {'kind', 'principal', 'operation',
        'expected_name_revision', 'expected_head_revision', 'nonce', 'descriptor_hash'}, 'deletion-origin-shape')
    need(value['kind'] in ('abort', 'delete'), 'deletion-kind')
    for key in ('principal', 'operation', 'expected_name_revision', 'nonce'):
        uint(value[key], minimum=1)
    digest(value['descriptor_hash'])
    if value['kind'] == 'abort':
        need(value['expected_head_revision'] is None, 'abort-no-head-rebase')
    else:
        uint(value['expected_head_revision'], minimum=1)


def retired(storage, generation):
    return (1 <= generation <= storage['allocated_through'] and
            (storage.get('terminal') is not None or generation != storage['active_generation']
             and (storage['plan'] is None or generation != storage['plan']['target'])))


def terminal_rules(value):
    storage, serial = value['storage'], value['head_serial']
    terminal = storage['terminal']
    need(isinstance(terminal, dict) and set(terminal) == {'serial'}, 'terminal-seal-shape')
    uint(terminal['serial'], serial, 1)
    need(storage['allocated_through'] < terminal['serial'], 'terminal-after-allocation')
    need(value['revision'] < terminal['serial'], 'terminal-after-business-revision')
    need(value['lifecycle'] == 'deleted' and value['active'] is False and storage['plan'] is None,
         'terminal-deleted-inactive')
    if storage['sweep'] is not None:
        need(storage['sweep']['serial'] > terminal['serial'], 'checkpoint-after-terminal')


def head(raw, known_scopes):
    need(len(raw) <= 262144, 'bounded-head-record')
    value = wire.parse(raw)
    need(isinstance(value, dict) and type(value.get('format')) is int and value['format'] in (6, 7, 8), 'strict-head-format')
    need(set(value) == HEAD | ({'owner_plan'} if value['format'] == 8 else set()), 'head-owner-format-shape')
    need(scope_key(value['scope']) in known_scopes, 'allocated-full-scope')
    for key in ('head_serial', 'revision', 'owner_epoch', 'owner_instance', 'auth_epoch', 'request_epoch'):
        uint(value[key], minimum=1)
    uint(value['sequence'])
    need(value['head_serial'] >= value['revision'], 'head-business-serial-order')
    need(type(value['active']) is bool and value['lifecycle'] in ('provisioning', 'ready', 'maintenance', 'deleted'),
         'head-lifecycle')
    transition(value['transition'])
    need(value['transition']['revision'] == value['revision'], 'head-transition-revision')
    if value['creation'] is not None:
        origin(value['creation'])
    if value['deletion'] is not None:
        deletion(value['deletion'])
        need(value['creation'] is not None and value['lifecycle'] == 'deleted', 'named-deletion-lifecycle')
    # HEAD6 direct lifecycle transitions preserve the historical activation bit.
    # Only the explicit HEAD7 seal promises inactive storage authority.
    digest(value['data_root'])
    need(set(value['quota']) == {'max_bytes'}, 'quota-shape')
    if value['quota']['max_bytes'] is not None:
        uint(value['quota']['max_bytes'], minimum=4096)
    retention = value['retention']
    need(set(retention) == {'max_entries', 'max_result_bytes'}, 'retention-shape')
    uint(retention['max_entries'], 65536, 1)
    uint(retention['max_result_bytes'], minimum=1)
    policies = value['policy']
    need(isinstance(policies, list) and 1 <= len(policies) <= 1024, 'policy-shape')
    principals = []
    for permission in policies:
        need(set(permission) == {'principal', 'read', 'write', 'admin'}
             and all(type(permission[key]) is bool for key in ('read', 'write', 'admin')), 'permission-shape')
        principals.append(uint(permission['principal'], minimum=1))
    need(len(set(principals)) == len(principals) and any(p['admin'] for p in policies), 'current-admin')
    windows = value['windows']
    need(isinstance(windows, list) and len(windows) == min(value['request_epoch'], 3), 'window-count')
    for offset, window in enumerate(windows):
        need(set(window) == {'epoch', 'root', 'count', 'result_bytes'}
             and window['epoch'] == value['request_epoch'] - offset, 'window-order')
        digest(window['root'])
        uint(window['count'], retention['max_entries'])
        uint(window['result_bytes'], min(retention['max_result_bytes'], window['count'] * 67108864))
        if offset:
            need(window['count'] == retention['max_entries'] or
                 window['result_bytes'] > max(0, retention['max_result_bytes'] - 67108864), 'closed-window-complete')
    if value['lifecycle'] == 'provisioning':
        need(value['creation'] is not None and not value['active'] and value['sequence'] == 0
             and value['request_epoch'] == 1 and windows[0]['count'] == windows[0]['result_bytes'] == 0,
             'named-provisioning-has-no-business')
    if value['creation'] is not None and value['lifecycle'] == 'deleted':
        barrier = value['deletion']
        need(barrier is not None and not value['active'] and value['transition']['nonce'] == barrier['nonce']
             and any(permission['principal'] == barrier['principal'] and permission['admin'] for permission in policies),
             'named-deletion-current-authority')
        if barrier['kind'] == 'abort':
            need(barrier['principal'] == value['creation']['creator'] and value['revision'] <= 2
                 and value['sequence'] == 0 and value['request_epoch'] == 1
                 and windows[0]['count'] == windows[0]['result_bytes'] == 0, 'named-abort-has-no-business')
        else:
            need(barrier['expected_head_revision'] + 1 == value['revision'], 'named-original-deletion-revision')
    storage = value['storage']
    terminal = isinstance(storage, dict) and 'terminal' in storage
    need(set(storage) == {'active_generation', 'allocated_through', 'plan', 'sweep'} |
         ({'terminal'} if terminal else set()) and
         (value['format'] == 8 or terminal == (value['format'] == 7)), 'exact-storage-version-shape')
    active = uint(storage['active_generation'], minimum=1)
    allocated = uint(storage['allocated_through'], value['head_serial'], active)
    plan, sweep = storage['plan'], storage['sweep']
    need(plan is None or sweep is None, 'plan-checkpoint-exclusive')
    if plan is not None:
        need(set(plan) == {'serial', 'source', 'target', 'phase', 'basis'} and not value['active'], 'copy-plan-shape')
        uint(plan['serial'], value['head_serial'], 1)
        need(plan['source'] == active and plan['target'] == allocated > active and plan['phase'] in ('copying', 'sealed'), 'copy-plan-generations')
        basis = plan['basis']
        need(set(basis) == BASIS and all(basis[key] == value[key] for key in BASIS - {'revision'})
             and 1 <= basis['revision'] <= value['revision'], 'copy-original-basis')
    if sweep is not None:
        need(set(sweep) == {'serial', 'generation', 'next_after', 'exhausted', 'entries'}, 'checkpoint-shape')
        uint(sweep['serial'], value['head_serial'], 1)
        uint(sweep['generation'], minimum=1)
        need(retired(storage, sweep['generation']), 'checkpoint-retired-generation')
        need(type(sweep['exhausted']) is bool and sweep['exhausted'] == (sweep['next_after'] is None), 'checkpoint-frontier')
        if sweep['next_after'] is not None:
            digest(sweep['next_after'])
        need(isinstance(sweep['entries'], list) and 1 <= len(sweep['entries']) <= 32, 'checkpoint-bound')
        previous = ''
        for entry in sweep['entries']:
            need(set(entry) == {'key', 'hash', 'etag', 'disposition'}, 'checkpoint-entry')
            name = digest(entry['hash'])
            need(name > previous and '/scap-test/' + entry['key'] == prefix(value['scope'], sweep['generation']) + name,
                 'checkpoint-full-scope-key')
            previous = name
            need(isinstance(entry['etag'], str) and re.fullmatch(r'"[!#-~]{0,1022}"', entry['etag']), 'original-etag-shape')
            need(entry['disposition'] in ('pending', 'applied', 'observed_absent', 'condition_mismatch'), 'checkpoint-disposition')
    if terminal:
        terminal_rules(value)
    if value['format'] == 8:
        marker_in_head(value)
    return value


def advance(previous, current):
    need(current['scope'] == previous['scope'], 'head-full-scope-immutable')
    need(current['head_serial'] == previous['head_serial'] + 1, 'physical-serial-step')
    before, after = previous['storage'], current['storage']
    old_owner, new_owner = previous.get('owner_plan'), current.get('owner_plan')
    fields = HEAD | ({'owner_plan'} if old_owner is not None or new_owner is not None else set())
    if old_owner != new_owner:
        need(current['format'] == 8 and new_owner is not None and before == after,
             'owner-format-one-way-adoption')
        need(current['revision'] == previous['revision'] + 1 and current['lifecycle'] == 'ready',
             'owner-phase-single-business-step')
        phase = new_owner['phase']
        need(phase['revision'] == current['revision'] and phase['head_serial'] == current['head_serial']
             and phase['nonce'] == current['transition']['nonce'], 'owner-phase-current-transition')
        need((current['owner_epoch'], current['owner_instance']) == (phase['owner_epoch'], phase['owner_instance']),
             'owner-phase-published-tuple')
        need(all(current.get(key) == previous.get(key) for key in fields -
                 {'format', 'owner_plan', 'revision', 'head_serial', 'transition', 'owner_epoch', 'owner_instance', 'active'}),
             'owner-phase-preserves-business')
        if old_owner is None or old_owner['reference'] != new_owner['reference']:
            need(old_owner is None or old_owner['phase']['kind'] in ('active', 'aborted'), 'owner-no-pending-replacement')
            need(phase['kind'] in ('claimed', 'cancelling') and not current['active'], 'owner-admission-inactive')
            if phase['kind'] == 'cancelling':
                need((current['owner_epoch'], current['owner_instance']) ==
                     (previous['owner_epoch'], previous['owner_instance']), 'owner-cancelling-keeps-original-tuple')
            return 'owner_claim' if phase['kind'] == 'claimed' else 'owner_cancel'
        need(old_owner['admission'] == new_owner['admission'] and old_owner['reference'] == new_owner['reference'],
             'owner-terminal-original-admission')
        need(old_owner['phase']['kind'] in ('claimed', 'cancelling') and phase['kind'] in ('active', 'aborted')
             and (phase['kind'] != 'active' or old_owner['phase']['kind'] == 'claimed'), 'owner-terminal-legal-phase')
        need((phase['owner_epoch'], phase['owner_instance']) ==
             (old_owner['phase']['owner_epoch'], old_owner['phase']['owner_instance']), 'owner-terminal-keeps-tuple')
        need(current['active'] == (phase['kind'] == 'active'), 'owner-terminal-activation')
        return 'owner_active' if phase['kind'] == 'active' else 'owner_abort'
    if before.get('terminal') is None and after.get('terminal') is not None:
        need(previous['lifecycle'] == 'deleted' and before['plan'] is None and before['sweep'] is None,
             'seal-original-deleted-quiescent')
        need(current['format'] == (8 if previous['format'] == 8 else 7)
             and previous['format'] in (6, 8), 'seal-original-format')
        need(all(current[key] == previous[key] for key in fields - {'format', 'head_serial', 'storage', 'active'}),
             'seal-business-preservation')
        need(after == {**before, 'terminal': {'serial': current['head_serial']}} and not current['active'], 'one-way-terminal-seal')
        return 'terminal'
    need(current['format'] == previous['format'], 'terminal-format-irreversible')
    if before.get('terminal') is not None:
        need(after['terminal'] == before['terminal'] and after['active_generation'] == before['active_generation']
             and after['allocated_through'] == before['allocated_through'], 'terminal-allocation-frozen')
        need(all(current[key] == previous[key] for key in fields - {'head_serial', 'storage'}), 'terminal-business-frozen')
    if current['revision'] != previous['revision']:
        need(before.get('terminal') is None and previous['lifecycle'] != 'deleted'
             and current['revision'] == previous['revision'] + 1 and before == after, 'business-one-step')
        if old_owner is not None and old_owner['phase']['kind'] in ('claimed', 'cancelling'):
            need(all(current[key] == previous[key] for key in fields -
                     {'head_serial', 'revision', 'transition', 'policy', 'auth_epoch', 'quota'}), 'owner-pending-metadata-only')
        return 'business'
    need(all(current[key] == previous[key] for key in fields - {'head_serial', 'storage', 'active'}), 'technical-business-preservation')
    old_plan, new_plan, old_sweep, new_sweep = before['plan'], after['plan'], before['sweep'], after['sweep']
    if old_plan is None and new_plan is not None:
        need(old_sweep is None and new_sweep is None and new_plan['serial'] == current['head_serial']
             and after['active_generation'] == before['active_generation']
             and after['allocated_through'] == before['allocated_through'] + 1
             and new_plan['phase'] == 'copying' and new_plan['basis'] == {key: previous[key] for key in BASIS}
             and not current['active'], 'copy-freeze-original')
        return 'begin'
    if old_plan is not None:
        need(old_sweep is None and new_sweep is None and after['allocated_through'] == before['allocated_through']
             and not current['active'], 'copy-transition')
        if new_plan is not None:
            need(new_plan == {**old_plan, 'phase': 'sealed'} and old_plan['phase'] == 'copying'
                 and after['active_generation'] == before['active_generation'], 'copy-complete-before-seal')
            return 'copy_seal'
        if after['active_generation'] == old_plan['target']:
            need(old_plan['phase'] == 'sealed', 'promote-after-complete-copy')
            return 'promote'
        need(after['active_generation'] == before['active_generation'], 'only-planned-abort')
        return 'abort'
    need(new_plan is None and after['active_generation'] == before['active_generation']
         and after['allocated_through'] == before['allocated_through'] and current['active'] == previous['active'],
         'gc-keeps-authority')
    if old_sweep is None:
        need(new_sweep is not None and new_sweep['serial'] == current['head_serial']
             and all(entry['disposition'] == 'pending' for entry in new_sweep['entries']), 'checkpoint-install')
        return 'prepare'
    if new_sweep is None:
        need(all(entry['disposition'] != 'pending' for entry in old_sweep['entries']), 'pending-checkpoint-cleared')
        return 'clear'
    need(all(new_sweep[key] == old_sweep[key] for key in set(old_sweep) - {'entries'})
         and len(new_sweep['entries']) == len(old_sweep['entries']), 'checkpoint-identity')
    changed = False
    for old, new in zip(old_sweep['entries'], new_sweep['entries']):
        need(all(old[key] == new[key] for key in ('key', 'hash', 'etag')), 'checkpoint-original-etag')
        if old['disposition'] != new['disposition']:
            need(old['disposition'] == 'pending' and new['disposition'] != 'pending', 'disposition-monotonic')
            changed = True
    need(changed, 'nonempty-checkpoint-progress')
    return 'progress'


def native_creation(value):
    need(set(value) == {'creator', 'operation', 'name', 'scope', 'expected_name_revision'}, 'creation-fields')
    uint(value['creator'], minimum=1)
    uint(value['operation'], minimum=1)
    scope(value['scope'])
    need(isinstance(value['name'], str) and 1 <= len(value['name'].encode()) <= 255, 'name-spelling')
    if value['expected_name_revision'] is not None:
        uint(value['expected_name_revision'], 2**64 - 4, 1)
    hashed = hashlib.sha256(b'SCAP-NAMED-ID-v1\0' + struct.pack('>QQQQ', 1, 7, value['creator'], value['operation'])).digest()
    need((value['scope']['database'], value['scope']['incarnation']) == struct.unpack('>QQ', hashed[:16])
         and value['scope']['generation'] == 1, 'named-derived-full-scope')


def control(value):
    need(set(value) == {'format', 'creation', 'origin', 'kind', 'principal', 'operation',
        'expected_name_revision', 'expected_head_revision', 'nonce'} and value['format'] == 1, 'control-fields')
    native_creation(value['creation'])
    origin(value['origin'])
    need(value['origin']['creator'] == value['creation']['creator']
         and value['origin']['operation'] == value['creation']['operation']
         and value['origin']['name_hash'] == sha(value['creation']['name'].encode()), 'control-original-creation')
    deletion({key: value[key] for key in ('kind', 'principal', 'operation', 'expected_name_revision',
        'expected_head_revision', 'nonce')} | {'descriptor_hash': '0' * 64})
    if value['kind'] == 'abort':
        need(value['principal'] == value['creation']['creator'], 'abort-original-creator')


def catalogue(raw, path):
    value = wire.parse(raw)
    need(isinstance(value, dict) and json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode() == raw,
         'canonical-catalogue-record')
    base = '/scap-test/scap-object/v1/1/7/catalogue/v1/'
    need(path.startswith(base), 'catalogue-key')
    suffix = path[len(base):]
    if suffix.startswith('create/'):
        need(set(value) == {'format', 'creation', 'options', 'initial_quota', 'retention'} and value['format'] == 1,
             'descriptor-fields')
        native_creation(value['creation'])
        need(suffix == f'create/{value["creation"]["creator"]}/{value["creation"]["operation"]}', 'descriptor-key')
        need(value['options'] == {'quota': {'kind': 'limited', 'max_bytes': 67108864}}
             and value['initial_quota'] == {'max_bytes': 67108864}, 'named-initial-quota')
        need(set(value['retention']) == {'max_entries', 'max_result_bytes'}, 'descriptor-retention-shape')
        uint(value['retention']['max_entries'], 65536, 1)
        uint(value['retention']['max_result_bytes'], minimum=1)
        return 'descriptor', value
    if suffix.startswith('control/'):
        control(value)
        need(suffix == f'control/{value["principal"]}/{value["kind"]}/{value["operation"]}', 'control-key')
        return 'control', value
    if suffix.startswith('abort-proof/'):
        need(set(value) == {'format', 'control', 'barrier'} and value['format'] == 1, 'proof-fields')
        control(value['control'])
        need(value['control']['kind'] == 'abort', 'proof-abort-source')
        original, barrier = value['control']['creation'], value['barrier']
        need(suffix == f'abort-proof/{original["creator"]}/{original["operation"]}', 'proof-key')
        if barrier['kind'] == 'own_deleted':
            need(set(barrier) == {'kind', 'transition'}, 'own-proof-fields')
            transition(barrier['transition'])
            need(barrier['transition']['revision'] in (1, 2)
                 and barrier['transition']['nonce'] == value['control']['nonce'], 'own-proof-business-barrier')
        else:
            need(set(barrier) == {'kind', 'scope', 'creation'} and barrier['kind'] == 'foreign_occupied', 'foreign-proof-fields')
            scope(barrier['scope'])
            if barrier['creation'] is not None:
                origin(barrier['creation'])
            need(all(barrier['scope'][key] == original['scope'][key] for key in ('deployment', 'tenant', 'database'))
                 and (barrier['scope'] != original['scope'] or barrier['creation'] != value['control']['origin']), 'foreign-proof-distinction')
        return 'proof', value
    need(suffix.startswith('name/') and set(value) == {'format', 'creation', 'origin', 'revision', 'state', 'control', 'proof'}
         and value['format'] == 1, 'name-fields')
    native_creation(value['creation'])
    origin(value['origin'])
    need(suffix == 'name/' + sha(value['creation']['name'].encode()), 'name-key')
    reserved = (value['creation']['expected_name_revision'] or 0) + 1
    need(value['state'] in ('reserved', 'bound', 'aborting', 'tombstone'), 'name-state')
    need(value['revision'] == reserved + {'reserved': 0, 'bound': 1, 'aborting': 1, 'tombstone': 2}[value['state']], 'name-revision')
    if value['state'] in ('reserved', 'bound'):
        need(value['control'] is None and value['proof'] is None, 'live-name-no-barrier')
    else:
        control(value['control'])
        need(value['control']['creation'] == value['creation'] and value['control']['origin'] == value['origin'], 'name-original-control')
        if value['state'] == 'aborting' or value['control']['kind'] == 'delete':
            need(value['proof'] is None, 'no-unplanned-proof')
        else:
            digest(value['proof'])
    return 'name', value


def envelope(raw, path):
    logical, generation, name = object_path(path)
    need(len(raw) >= 20 and raw[:8] == b'SCAPOBJ2' and sha(raw) == name, 'immutable-content-key')
    metadata_bytes, payload_bytes = struct.unpack_from('<IQ', raw, 8)
    need(metadata_bytes <= 65516 and payload_bytes <= 67108864 and len(raw) == 20 + metadata_bytes + payload_bytes,
         'immutable-frame-extent')
    metadata = wire.parse(raw[20:20 + metadata_bytes])
    need(set(metadata) == {'format', 'scope', 'payload'} and metadata['format'] == 2
         and metadata['scope'] == logical, 'immutable-full-scope')
    need(set(metadata['payload']) == {'kind', 'value'}, 'immutable-payload-shape')
    return metadata['payload']['kind'], metadata['payload']['value'], raw[20 + metadata_bytes:]


class Graph(graph.Graph):
    """Reuse only the independent pure closure traversal with full-scope loading."""
    def __init__(self, objects, logical, generation):
        self.objects, self.logical, self.generation = objects, logical, generation
        self.prefix = prefix(logical, generation)
        self.dependencies, self.results, self.index_levels = set(), {}, []

    def load(self, name, kind):
        path = self.prefix + digest(name)
        need(path in self.objects, 'complete-durable-dependency')
        actual, value, raw = envelope(self.objects[path], path)
        need(actual == kind, 'typed-dependency-edge')
        self.dependencies.add(path)
        return value, raw
