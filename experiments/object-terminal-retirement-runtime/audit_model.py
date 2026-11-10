"""Independent strict HEAD6/HEAD7 and catalogue records; no product verifier."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

_spec = importlib.util.spec_from_file_location('terminal_pure_graph',
    Path(__file__).resolve().parent.parent / 'object-reclamation-runtime/audit_model.py')
graph = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(graph)
wire, Rejected, need = graph.wire, graph.Rejected, graph.need
sha, uint, digest = graph.sha, graph.uint, graph.digest
BASIS, HEAD = graph.BASIS, graph.HEAD
SCOPE = ('deployment', 'tenant', 'database', 'incarnation', 'generation')


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
    value = wire.parse(raw)
    need(isinstance(value, dict) and set(value) == HEAD and value['format'] in (6, 7), 'strict-head-format')
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
    need(principals == sorted(set(principals)) and any(p['principal'] == 11 and p['admin'] for p in policies), 'current-admin')
    windows = value['windows']
    need(isinstance(windows, list) and len(windows) == min(value['request_epoch'], 3), 'window-count')
    for offset, window in enumerate(windows):
        need(set(window) == {'epoch', 'root', 'count', 'result_bytes'}
             and window['epoch'] == value['request_epoch'] - offset, 'window-order')
        digest(window['root'])
        uint(window['count'], retention['max_entries'])
        uint(window['result_bytes'], retention['max_result_bytes'])
        if offset:
            need(window['count'] == retention['max_entries'], 'closed-window-complete')
    storage = value['storage']
    need(set(storage) == {'active_generation', 'allocated_through', 'plan', 'sweep'} |
         ({'terminal'} if value['format'] == 7 else set()), 'exact-storage-version-shape')
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
    if value['format'] == 7:
        terminal_rules(value)
    return value


def advance(previous, current):
    need(current['scope'] == previous['scope'], 'head-full-scope-immutable')
    need(current['head_serial'] == previous['head_serial'] + 1, 'physical-serial-step')
    before, after = previous['storage'], current['storage']
    if previous['format'] == 6 and current['format'] == 7:
        need(previous['lifecycle'] == 'deleted' and before['plan'] is None and before['sweep'] is None,
             'seal-original-deleted-quiescent')
        need(all(current[key] == previous[key] for key in HEAD - {'format', 'head_serial', 'storage', 'active'}),
             'seal-business-preservation')
        need(after == {**before, 'terminal': {'serial': current['head_serial']}} and not current['active'], 'one-way-terminal-seal')
        return 'terminal'
    need(current['format'] == previous['format'], 'terminal-format-irreversible')
    if previous['format'] == 7:
        need(after['terminal'] == before['terminal'] and after['active_generation'] == before['active_generation']
             and after['allocated_through'] == before['allocated_through'], 'terminal-allocation-frozen')
        need(all(current[key] == previous[key] for key in HEAD - {'head_serial', 'storage'}), 'terminal-business-frozen')
    if current['revision'] != previous['revision']:
        need(previous['format'] == 6 and previous['lifecycle'] != 'deleted'
             and current['revision'] == previous['revision'] + 1 and before == after, 'business-one-step')
        return 'business'
    need(all(current[key] == previous[key] for key in HEAD - {'head_serial', 'storage', 'active'}), 'technical-business-preservation')
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
