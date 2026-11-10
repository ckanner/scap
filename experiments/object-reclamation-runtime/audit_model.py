"""Independent HEAD6 state and complete immutable graph checks.

No production/controller/runner code is imported. Result decoding and SQL
fingerprints are pure wire witnesses shared with earlier independent audits.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import struct

_spec = importlib.util.spec_from_file_location('reclamation_pure_wire',
    Path(__file__).resolve().parent.parent / 'object-service/audit_wire.py')
wire = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wire)


class Rejected(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(rule)


def need(condition, rule):
    if not condition:
        raise Rejected(rule)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uint(value, maximum=2**64 - 1, minimum=0):
    need(type(value) is int and minimum <= value <= maximum, 'integer-shape')
    return value


def digest(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'hash-shape')
    return value


def scope(database):
    need(database in (4101, 4102, 4103), 'logical-database-scope')
    return {'deployment': 1, 'tenant': 7, 'database': database, 'incarnation': 1, 'generation': 1}


def prefix(database, generation):
    return f'/scap-test/scap-object/v1/1/7/{database}/inc/1/gen/1/storage/{generation}/objects/'


def object_path(path):
    match = re.fullmatch(r'/scap-test/scap-object/v1/1/7/(410[123])/inc/1/gen/1/storage/([1-9][0-9]*)/objects/([0-9a-f]{64})', path)
    need(match is not None, 'object-key-scope')
    database, generation, name = match.groups()
    return int(database), int(generation), name


def head_path(path):
    match = re.fullmatch(r'/scap-test/scap-object/v1/1/7/(410[123])/head', path)
    return None if match is None else int(match.group(1))


def retired(storage, generation):
    return (1 <= generation <= storage['allocated_through'] and generation != storage['active_generation']
            and (storage['plan'] is None or generation != storage['plan']['target']))


BASIS = {'data_root', 'windows', 'sequence', 'revision', 'quota', 'retention', 'request_epoch'}
HEAD = {'format', 'scope', 'head_serial', 'storage', 'revision', 'transition', 'sequence',
        'owner_epoch', 'owner_instance', 'active', 'auth_epoch', 'policy', 'lifecycle',
        'creation', 'deletion', 'data_root', 'quota', 'retention', 'request_epoch', 'windows'}


def head(raw, database):
    value = wire.parse(raw)
    need(set(value) == HEAD and value['format'] == 6 and value['scope'] == scope(database), 'head6-shape')
    need(all(type(v) is int for v in value['scope'].values()), 'scope-integer-shape')
    for field in ('head_serial', 'revision', 'owner_epoch', 'owner_instance', 'auth_epoch', 'request_epoch'):
        uint(value[field], minimum=1)
    uint(value['sequence'])
    need(value['head_serial'] >= value['revision'], 'head-serial')
    need(type(value['active']) is bool and value['lifecycle'] == 'ready', 'head-lifecycle')
    need(value['creation'] is None and value['deletion'] is None, 'unnamed-logical-scope')
    transition(value['transition'])
    need(value['transition']['revision'] == value['revision'], 'head-transition')
    digest(value['data_root'])
    need(value['quota'] == {'max_bytes': 67108864}
         and value['retention'] == {'max_entries': 129, 'max_result_bytes': 268435456}, 'durable-retention-profile')
    permissions = value['policy']
    need(isinstance(permissions, list) and 1 <= len(permissions) <= 2, 'acl-shape')
    seen = set()
    for permission in permissions:
        need(set(permission) == {'principal', 'read', 'write', 'admin'}, 'acl-shape')
        uint(permission['principal'], minimum=1)
        need(permission['principal'] not in seen, 'acl-duplicate')
        seen.add(permission['principal'])
        need(all(type(permission[k]) is bool for k in ('read', 'write', 'admin')), 'acl-shape')
    need(any(p['principal'] == 11 and p['admin'] for p in permissions), 'admin-preserved')
    windows = value['windows']
    need(isinstance(windows, list) and len(windows) == min(value['request_epoch'], 3), 'retained-window-count')
    for index, window in enumerate(windows):
        need(set(window) == {'epoch', 'root', 'count', 'result_bytes'}, 'window-shape')
        uint(window['epoch'], minimum=1)
        need(window['epoch'] == value['request_epoch'] - index, 'window-order')
        digest(window['root'])
        uint(window['count'], 129)
        uint(window['result_bytes'], min(268435456, window['count'] * 67108864))
        if index:
            need(window['count'] == 129, 'closed-window-full')
    storage = value['storage']
    need(set(storage) == {'active_generation', 'allocated_through', 'plan', 'sweep'}, 'storage-shape')
    active = uint(storage['active_generation'], minimum=1)
    allocated = uint(storage['allocated_through'], value['head_serial'], active)
    plan, sweep = storage['plan'], storage['sweep']
    need(plan is None or sweep is None, 'plan-sweep-exclusive')
    if plan is not None:
        need(set(plan) == {'serial', 'source', 'target', 'phase', 'basis'}, 'plan-shape')
        uint(plan['serial'], value['head_serial'], 1)
        uint(plan['source'], minimum=1)
        uint(plan['target'], minimum=1)
        need(plan['source'] == active and plan['target'] == allocated > active
             and plan['phase'] in ('copying', 'sealed') and not value['active'], 'plan-generations')
        basis = plan['basis']
        need(set(basis) == BASIS and all(basis[k] == value[k] for k in BASIS - {'revision'})
             and 1 <= basis['revision'] <= value['revision'] and basis['revision'] <= plan['serial'], 'copy-basis')
    if sweep is not None:
        need(set(sweep) == {'serial', 'generation', 'next_after', 'exhausted', 'entries'}, 'checkpoint-shape')
        uint(sweep['serial'], value['head_serial'], 1)
        uint(sweep['generation'], minimum=1)
        need(retired(storage, sweep['generation']), 'checkpoint-retirement')
        need(type(sweep['exhausted']) is bool and sweep['exhausted'] == (sweep['next_after'] is None), 'checkpoint-frontier')
        if sweep['next_after'] is not None:
            digest(sweep['next_after'])
        need(isinstance(sweep['entries'], list) and 1 <= len(sweep['entries']) <= 32, 'checkpoint-bound')
        prior = ''
        for entry in sweep['entries']:
            need(set(entry) == {'key', 'hash', 'etag', 'disposition'}, 'checkpoint-entry')
            name = digest(entry['hash'])
            need(name > prior and '/' + 'scap-test/' + entry['key'] == prefix(database, sweep['generation']) + name,
                 'checkpoint-original-key')
            prior = name
            need(isinstance(entry['etag'], str) and re.fullmatch(r'"[!#-~]{0,1022}"', entry['etag']), 'checkpoint-etag')
            need(entry['disposition'] in ('pending', 'applied', 'observed_absent', 'condition_mismatch'), 'checkpoint-disposition')
    return value


def transition(value):
    need(set(value) == {'revision', 'nonce'}, 'transition-shape')
    uint(value['revision'], minimum=1)
    uint(value['nonce'], minimum=1)


def advance(previous, current):
    need(current['head_serial'] == previous['head_serial'] + 1, 'head-serial-step')
    before, after = previous['storage'], current['storage']
    if current['revision'] != previous['revision']:
        need(current['revision'] == previous['revision'] + 1 and before == after, 'business-storage-fence')
        if before['plan'] is not None:
            need(all(current[k] == previous[k] for k in HEAD - {'head_serial', 'revision', 'transition', 'policy', 'auth_epoch'})
                 and current['auth_epoch'] == previous['auth_epoch'] + 1, 'copy-policy-only')
        return 'business'
    need(all(current[k] == previous[k] for k in HEAD - {'head_serial', 'storage', 'active'}), 'technical-business-preservation')
    old_plan, new_plan = before['plan'], after['plan']
    old_sweep, new_sweep = before['sweep'], after['sweep']
    if old_plan is None and new_plan is not None:
        need(old_sweep is None and new_sweep is None and new_plan['serial'] == current['head_serial']
             and after['active_generation'] == before['active_generation']
             and after['allocated_through'] == before['allocated_through'] + 1
             and new_plan['source'] == before['active_generation']
             and new_plan['target'] == after['allocated_through'] and new_plan['phase'] == 'copying'
             and new_plan['basis'] == {k: previous[k] for k in BASIS} and not current['active'], 'freeze-original-basis')
        return 'begin'
    if old_plan is not None:
        need(old_sweep is None and new_sweep is None and after['allocated_through'] == before['allocated_through']
             and not current['active'], 'copy-transition-shape')
        if new_plan is not None:
            need(new_plan == {**old_plan, 'phase': 'sealed'} and old_plan['phase'] == 'copying'
                 and after['active_generation'] == before['active_generation'], 'seal-transition')
            return 'seal'
        if after['active_generation'] == old_plan['target']:
            need(old_plan['phase'] == 'sealed', 'promote-before-seal')
            return 'promote'
        need(after['active_generation'] == before['active_generation'], 'aborted-generation-reuse')
        return 'abort'
    need(new_plan is None and after['active_generation'] == before['active_generation']
         and after['allocated_through'] == before['allocated_through']
         and current['active'] == previous['active'], 'sweep-preserves-authority')
    if old_sweep is None:
        need(new_sweep is not None and new_sweep['serial'] == current['head_serial']
             and all(e['disposition'] == 'pending' for e in new_sweep['entries']), 'checkpoint-install')
        return 'prepare'
    if new_sweep is None:
        need(all(e['disposition'] != 'pending' for e in old_sweep['entries']), 'pending-checkpoint-cleared')
        return 'clear'
    need(all(new_sweep[k] == old_sweep[k] for k in set(old_sweep) - {'entries'})
         and len(new_sweep['entries']) == len(old_sweep['entries']), 'checkpoint-identity')
    changed = False
    for old, new in zip(old_sweep['entries'], new_sweep['entries']):
        need(all(new[k] == old[k] for k in ('key', 'hash', 'etag')), 'checkpoint-etag-refreshed')
        if new['disposition'] != old['disposition']:
            need(old['disposition'] == 'pending' and new['disposition'] != 'pending', 'checkpoint-disposition-regressed')
            changed = True
    need(changed, 'empty-technical-transition')
    return 'progress'


def envelope(raw, path):
    database, _generation, name = object_path(path)
    need(len(raw) >= 20 and raw[:8] == b'SCAPOBJ2' and sha(raw) == name, 'immutable-bytes-key')
    metadata_bytes, raw_bytes = struct.unpack_from('<IQ', raw, 8)
    need(metadata_bytes <= 65516 and raw_bytes <= 67108864 and len(raw) == 20 + metadata_bytes + raw_bytes, 'frame-extent')
    metadata = wire.parse(raw[20:20 + metadata_bytes])
    need(set(metadata) == {'format', 'scope', 'payload'} and metadata['format'] == 2
         and metadata['scope'] == scope(database), 'frame-logical-scope')
    payload = metadata['payload']
    need(set(payload) == {'kind', 'value'}, 'frame-payload')
    return payload['kind'], payload['value'], raw[20 + metadata_bytes:]


class Graph:
    def __init__(self, objects, database, generation):
        self.objects, self.database, self.generation = objects, database, generation
        self.prefix = prefix(database, generation)
        self.dependencies, self.results, self.index_levels = set(), {}, []

    def load(self, name, kind):
        path = self.prefix + digest(name)
        need(path in self.objects, 'complete-copy-dependency')
        actual, value, raw = envelope(self.objects[path], path)
        need(actual == kind, 'typed-graph-edge')
        self.dependencies.add(path)
        return value, raw

    def data(self, root):
        manifest, raw = self.load(root, 'manifest')
        need(not raw and set(manifest) == {'page_count', 'root'}, 'manifest-shape')
        pages = uint(manifest['page_count'], 16384)
        if pages == 0:
            need(manifest['root'] is None, 'empty-manifest-root')
            return b''

        def node(name, expected_level, first_chunk):
            value, raw = self.load(name, 'node')
            need(not raw and set(value) == {'level', 'first_chunk', 'children'}, 'data-node-shape')
            level = uint(value['level'], 4)
            need((expected_level is None or level == expected_level) and value['first_chunk'] == first_chunk,
                 'data-node-position')
            children = value['children']
            remaining = (pages + 31) // 32 - first_chunk
            span = 256 ** level
            need(isinstance(children, list) and len(children) == min(256, (remaining + span - 1) // span)
                 and children, 'data-node-extent')
            result = []
            for index, child in enumerate(children):
                chunk = first_chunk + index * span
                if level:
                    result.extend(node(child, level - 1, chunk))
                else:
                    metadata, blob = self.load(child, 'chunk')
                    need(metadata == {'first_page': chunk * 32 + 1, 'bytes': []}
                         and len(blob) == min(32, pages - chunk * 32) * 4096, 'chunk-extent')
                    result.append(blob)
            return result

        image = b''.join(node(manifest['root'], None, 0))
        need(len(image) == pages * 4096 and image[:16] == b'SQLite format 3\0'
             and image[16:18] == b'\x10\0', 'native-sqlite-image')
        return image

    def index(self, name, epoch, expected_level=None, nonroot=False):
        value, raw = self.load(name, 'index')
        need(not raw and value['epoch'] == epoch, 'index-epoch')
        if value['kind'] == 'leaf':
            need(set(value) == {'kind', 'epoch', 'entries'} and expected_level in (None, 0), 'leaf-shape')
            entries = value['entries']
            need(isinstance(entries, list) and (64 if nonroot else 0) <= len(entries) <= 128, 'leaf-width')
            previous = 0
            for entry in entries:
                need(set(entry) == {'request', 'outcome', 'result_bytes'}, 'index-entry')
                request = entry['request']
                need(set(request) == {'epoch', 'id', 'principal', 'fingerprint'} and request['epoch'] == epoch
                     and request['principal'] == 11, 'retained-request-identity')
                uint(request['id'], minimum=previous + 1)
                digest(request['fingerprint'])
                previous = request['id']
                uint(entry['result_bytes'], 67108864)
            level = 0
        else:
            need(set(value) == {'kind', 'epoch', 'level', 'children'} and value['kind'] == 'branch', 'branch-shape')
            level = uint(value['level'], 3, 1)
            need(expected_level is None or level == expected_level, 'index-decreasing-level')
            children = value['children']
            need(isinstance(children, list) and (16 if nonroot else 2) <= len(children) <= 32, 'branch-width')
            entries, previous = [], 0
            for child in children:
                need(set(child) == {'hash', 'summary'}, 'branch-child')
                observed, aggregate = self.index(child['hash'], epoch, level - 1, True)
                need(aggregate == child['summary'] and aggregate['first'] > previous, 'complete-index-aggregate')
                previous = aggregate['last']
                entries.extend(observed)
        self.index_levels.append(level)
        aggregate = {'first': entries[0]['request']['id'] if entries else 0,
                     'last': entries[-1]['request']['id'] if entries else 0,
                     'count': len(entries), 'result_bytes': sum(e['result_bytes'] for e in entries)}
        return entries, aggregate

    def closure(self, basis):
        image = self.data(basis['data_root'])
        data_dependencies = set(self.dependencies)
        all_entries = []
        for window in basis['windows']:
            entries, aggregate = self.index(window['root'], window['epoch'])
            need(aggregate['count'] == window['count'] and aggregate['result_bytes'] == window['result_bytes'], 'window-complete-aggregate')
            all_entries.extend(entries)
            for entry in entries:
                outcome, request = entry['outcome'], entry['request']
                if outcome['state'] == 'committed':
                    need(set(outcome) == {'state', 'result'}, 'committed-index-shape')
                    value, raw = self.load(outcome['result'], 'result')
                    need(set(value) == {'request', 'sequence', 'transition', 'data_root', 'bytes'}
                         and value['bytes'] == [] and value['request'] == request, 'original-result-identity')
                    need(len(raw) == entry['result_bytes'] and 1 <= value['sequence'] <= basis['sequence'], 'original-result-bound')
                    transition(value['transition'])
                    need(value['transition']['nonce'] == request['id'] and value['transition']['revision'] <= basis['revision'], 'original-result-transition')
                    digest(value['data_root'])  # Receipt metadata, intentionally not a graph edge.
                    wire.result(raw)
                    self.results[(request['epoch'], request['id'])] = (outcome['result'], value, raw)
                else:
                    need(set(outcome) == {'state', 'transition'} and outcome['state'] == 'cancelled'
                         and entry['result_bytes'] == 0, 'cancelled-index-shape')
                    transition(outcome['transition'])
                    need(outcome['transition']['nonce'] == request['id'] and outcome['transition']['revision'] <= basis['revision'], 'cancelled-index-barrier')
        return {'dependencies': set(self.dependencies), 'data_dependencies': data_dependencies,
                'results': self.results, 'entries': all_entries, 'index_levels': self.index_levels, 'image': image}
