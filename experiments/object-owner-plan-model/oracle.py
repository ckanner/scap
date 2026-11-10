#!/usr/bin/env python3
"""Independent raw-history checker. Does not import the model or its constructors.

It reconstructs the exact object service, delivered observations, fixed attempts,
caller knowledge and process ownership from raw events. The controller summary is
ignored. This is a finite protocol oracle, not a production HEAD8 decoder.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re


HEAD_KEY = 'scap-object/v1/1/7/91/head'
SCOPE_VALUE = {'deployment': 1, 'tenant': 7, 'database': 91, 'incarnation': 1, 'generation': 1}
ROOT = 'scap-object/v1/1/7/91/inc/1/gen/1/'
MAX_U64 = 18446744073709551615
HASH = re.compile(r'[0-9a-f]{64}\Z')
PENDING_PHASES = {'claimed', 'cancelling'}
FINAL_PHASES = {'active', 'aborted'}
PENDING_DENY = {'execute', 'commit', 'cancel_unknown', 'close_full', 'epoch', 'set_lifecycle',
                'named_delete', 'catalogue_recovery_publish', 'compact_begin', 'compact_copy',
                'compact_promote', 'compact_abort', 'gc_prepare', 'gc_resume', 'storage_seal'}
READ_ONLY = {'status', 'query', 'lookup', 'open_readonly', 'cancel_known'}


class Violation(AssertionError):
    def __init__(self, rule, detail=''):
        self.rule, self.detail = rule, detail
        super().__init__(f'{rule}: {detail}')


def require(value, rule, detail=''):
    if not value:
        raise Violation(rule, detail)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def sha(value):
    raw = value if isinstance(value, str) else canonical(value)
    return hashlib.sha256(raw.encode()).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'strict-json', 'duplicate field')
        result[key] = value
    return result


def raw_json(raw, maximum):
    require(isinstance(raw, str) and len(raw.encode()) <= maximum, 'wire-size')
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError('constant')))
    except (ValueError, TypeError) as error:
        raise Violation('strict-json', str(error)) from error
    require(canonical(value) == raw, 'canonical-bytes')
    return value


def fields(value, expected, rule='strict-schema'):
    require(type(value) is dict and set(value) == set(expected), rule, str(expected))


def integer(value, maximum=MAX_U64, minimum=1):
    require(type(value) is int and minimum <= value <= maximum, 'canonical-u64')


def hash_value(value):
    require(type(value) is str and HASH.fullmatch(value) is not None, 'canonical-hash')


def owner(value, maximum):
    fields(value, ('instance', 'epoch'))
    integer(value['instance'])
    integer(value['epoch'], maximum)


def ident(value):
    fields(value, ('creator', 'operation'))
    integer(value['creator'])
    integer(value['operation'])


def scope(value):
    require(value == SCOPE_VALUE, 'full-scope')
    for item in value.values():
        integer(item)


def quoted_etag(value):
    require(type(value) is str and 2 <= len(value.encode()) <= 1024 and
            value[0] == value[-1] == '"' and all(ord(c) >= 32 and ord(c) != 127 for c in value[1:-1]) and
            '"' not in value[1:-1], 'opaque-etag')


def key_for(kind, identity):
    ident(identity)
    value = ROOT + f'owner/v1/{kind}/{identity["creator"]}/{identity["operation"]}'
    require(len(value.encode()) <= 512, 'control-key-size')
    return value


def owner_marker(value, maximum):
    fields(value, ('identity', 'descriptor_hash', 'admission', 'phase'))
    require(len(canonical(value).encode()) <= 4096, 'marker-size')
    ident(value['identity'])
    hash_value(value['descriptor_hash'])
    accepted, phase = value['admission'], value['phase']
    fields(accepted, ('kind', 'revision', 'head_serial'))
    fields(phase, ('kind', 'revision', 'head_serial', 'nonce', 'owner'))
    require(accepted['kind'] in ('claim', 'cancel'), 'admission-kind')
    require(phase['kind'] in PENDING_PHASES | FINAL_PHASES, 'phase-kind')
    for row in (accepted, phase):
        integer(row['revision'], maximum)
        integer(row['head_serial'], maximum)
        require(row['revision'] <= row['head_serial'], 'serial-order')
    integer(phase['nonce'])
    owner(phase['owner'], maximum)
    if phase['kind'] in PENDING_PHASES:
        require((phase['revision'], phase['head_serial']) ==
                (accepted['revision'], accepted['head_serial']), 'pending-stable-counters')
        require((accepted['kind'], phase['kind']) in (('claim', 'claimed'), ('cancel', 'cancelling')),
                'pending-kind')
    else:
        require(phase['revision'] > accepted['revision'] and
                phase['head_serial'] > accepted['head_serial'], 'two-stage-terminal')
        require(phase['kind'] != 'active' or accepted['kind'] == 'claim', 'cancel-never-activates')
    return value


def parse_head(raw, maximum):
    value = raw_json(raw, 262144)
    expected = {'format', 'scope', 'revision', 'head_serial', 'transition_nonce', 'owner', 'active', 'lifecycle',
                'auth_epoch', 'admins', 'readers', 'quota', 'data_root', 'windows', 'requests', 'storage'}
    require(value.get('format') in (6, 7, 8), 'head-version')
    if value['format'] == 8:
        expected.add('owner_plan')
    fields(value, expected, 'head-version-schema')
    scope(value['scope'])
    for name in ('revision', 'head_serial', 'auth_epoch'):
        integer(value[name], maximum)
    require(value['revision'] <= value['head_serial'], 'serial-order')
    integer(value['transition_nonce'])
    owner(value['owner'], maximum)
    require(type(value['active']) is bool, 'strict-schema')
    require(value['lifecycle'] in ('ready', 'maintenance', 'deleted'), 'lifecycle')
    for name in ('admins', 'readers'):
        require(type(value[name]) is list and value[name] == sorted(set(value[name])), 'policy-schema')
        for principal in value[name]:
            integer(principal)
    integer(value['quota'])
    hash_value(value['data_root'])
    require(type(value['requests']) is list and type(value['windows']) is list, 'closure-schema')
    require(value['windows'] == [entry['id'] for entry in value['requests']], 'closure-schema')
    require(len(value['windows']) == len(set(value['windows'])), 'request-identity')
    for entry in value['requests']:
        fields(entry, ('id', 'fingerprint', 'result'))
        require(type(entry['id']) is str and type(entry['fingerprint']) is str, 'request-identity')
        hash_value(entry['result'])
    store = value['storage']
    fields(store, ('active', 'allocated', 'copy', 'sweep', 'terminal'))
    integer(store['active'])
    integer(store['allocated'])
    require(store['active'] <= store['allocated'] <= value['head_serial'], 'storage-counters')
    require(all(type(store[name]) is bool for name in ('copy', 'sweep', 'terminal')), 'storage-schema')
    require(not (store['copy'] and store['sweep']), 'storage-exclusion')
    require(not store['terminal'] or (not store['copy'] and not store['sweep'] and
            value['lifecycle'] == 'deleted' and not value['active']), 'terminal-storage')
    require(value['format'] != 6 or not store['terminal'], 'head-version-schema')
    require(value['format'] != 7 or store['terminal'], 'head-version-schema')
    if value['format'] == 8:
        plan = owner_marker(value['owner_plan'], maximum)
        phase = plan['phase']
        require(phase['revision'] <= value['revision'] and phase['head_serial'] <= value['head_serial'],
                'phase-not-in-future')
        require(phase['revision'] != value['revision'] or phase['nonce'] == value['transition_nonce'],
                'current-owner-transition-nonce')
        if phase['kind'] != 'active':
            require(not value['active'], 'inactive-phase')
        if phase['kind'] in PENDING_PHASES:
            require(value['lifecycle'] == 'ready' and not any(store[n] for n in ('copy', 'sweep', 'terminal')),
                    'pending-storage-exclusion')
            require(phase['owner'] == value['owner'], 'pending-owner')
            require(value['revision'] < maximum and value['head_serial'] < maximum,
                    'pending-counter-reserve')
    return value


def parse_descriptor(raw, maximum):
    value = raw_json(raw, 16384)
    fields(value, ('version', 'scope', 'identity', 'target', 'mode', 'nonces',
                   'expected_revision', 'expected_head_serial', 'base', 'input_digest'))
    require(value['version'] == 1, 'descriptor-version')
    scope(value['scope'])
    ident(value['identity'])
    integer(value['target'])
    integer(value['expected_revision'], maximum)
    integer(value['expected_head_serial'], maximum)
    require(value['mode'] in ('takeover', 'activate'), 'descriptor-mode')
    fields(value['nonces'], ('claim', 'cancel', 'activate', 'abort'))
    for nonce in value['nonces'].values():
        integer(nonce)
    require(len(set(value['nonces'].values())) == 4, 'distinct-nonces')
    base = value['base']
    fields(base, ('head_hash', 'etag', 'revision', 'head_serial', 'owner', 'marker_hash'))
    hash_value(base['head_hash'])
    quoted_etag(base['etag'])
    integer(base['revision'], maximum)
    integer(base['head_serial'], maximum)
    require(base['revision'] <= base['head_serial'], 'serial-order')
    require((base['revision'], base['head_serial']) ==
            (value['expected_revision'], value['expected_head_serial']), 'saved-prepare-counters')
    owner(base['owner'], maximum)
    if base['marker_hash'] is not None:
        hash_value(base['marker_hash'])
    hash_value(value['input_digest'])
    content = {key: item for key, item in value.items() if key != 'input_digest'}
    require(sha(content) == value['input_digest'], 'descriptor-input-digest')
    return value


def parse_proof(raw, maximum):
    value = raw_json(raw, 8192)
    fields(value, ('version', 'scope', 'marker'))
    require(value['version'] == 1, 'proof-version')
    scope(value['scope'])
    owner_marker(value['marker'], maximum)
    require(value['marker']['phase']['kind'] in FINAL_PHASES, 'terminal-proof-only')
    return value


class Audit:
    def __init__(self):
        self.objects, self.calls, self.reads, self.writes = {}, {}, {}, {}
        self.processes, self.routes, self.workers = {}, {}, set()
        self.etags, self.executed, self.accepted_markers = set(), set(), {}
        self.maximum, self.original_ack, self.closed = None, None, False
        self.sequence = 0
        self.stats = {'calls': 0, 'writes': 0, 'applied': 0, 'conflicts': 0,
                      'caller_unknowns': 0, 'recoveries': 0, 'proof_readbacks': 0,
                      'late_effects': 0, 'guards': 0, 'native_sql': 0}

    def run(self, trace, strict_scenario=False):
        require(type(trace) is dict and trace.get('schema') == 1, 'trace-schema')
        for number, event in enumerate(trace.get('events', []), 1):
            require(not self.closed, 'closed-history')
            require(event.get('sequence') == number, 'event-sequence')
            self.sequence = number
            method = getattr(self, 'event_' + event.get('event', ''), None)
            require(method is not None, 'known-event', event.get('event', ''))
            method(event)
        require(self.closed, 'closed-history', 'missing final observer denominator')
        require(self.original_ack['result'] == self.objects[
            ROOT + 'storage/1/objects/' + sha(self.original_ack['result'])]['body'], 'original-result-preserved')
        if strict_scenario:
            self.planned_scenario(trace)
        return {'status': 'PASSED', 'name': trace.get('name'), **self.stats,
                'final_head': json.loads(self.objects[HEAD_KEY]['body']),
                'original_result_sha256': sha(self.original_ack['result']),
                'unknowns_remain_unknown': True, 'production_or_controller': 'NOT_IMPLEMENTED'}

    def planned_scenario(self, trace):
        name, events = trace['name'], trace['events']
        require(self.stats['calls'] > 0, 'scenario-nonvacuous')
        match = re.fullmatch(r'(claim_cancel|two_resume|resume_abort)-(\d{3})-lost([01])', name)
        if match:
            family, number, lost = match.group(1), int(match.group(2)), int(match.group(3))
            if family == 'claim_cancel':
                actors = {'c2': 'left', 'c3': 'right'}
                chains = (('admit', 'invoke', 'effect', 'respond'),) * 2
                require(self.calls['c2']['input']['operation'] == 'claim' and
                        self.calls['c3']['input']['operation'] == 'abort', 'planned-racing-inputs')
            else:
                actors = {'c3': 'left', 'c4': 'right'}
                recovery = ('admit', 'recover', 'invoke', 'effect', 'respond')
                chains = (recovery, recovery if family == 'two_resume' else ('admit', 'invoke', 'effect', 'respond'))
                require(self.calls['c3']['input']['operation'] == 'resume' and
                        self.calls['c4']['input']['operation'] == ('resume' if family == 'two_resume' else 'abort'),
                        'planned-racing-inputs')
            def extensions(left, right, sequence=()):
                if not left and not right:
                    yield sequence
                if left:
                    yield from extensions(left[1:], right, sequence + (('left', left[0]),))
                if right:
                    yield from extensions(left, right[1:], sequence + (('right', right[0]),))
            possibilities = list(extensions(*chains))
            require(number < len(possibilities), 'planned-schedule-index')
            actual, active_actions = [], set()
            for event in events:
                event_call = event.get('call')
                if event['event'] in ('s3_put_effect', 's3_put_response'):
                    row = self.writes[event['io']]['request']
                    event_call = row['call'] if row['purpose'] == 'candidate' else None
                if event_call not in actors:
                    continue
                action = {'http_admitted': 'admit', 'recovery_verified': 'recover',
                          's3_put_invoked': 'invoke', 's3_put_effect': 'effect',
                          's3_put_response': 'respond'}.get(event['event'])
                if action is not None:
                    pair = (actors[event_call], action)
                    actual.append(pair)
                    active_actions.add(pair)
                if event['event'] == 's3_put_response':
                    require(event['delivered'] == (not lost), 'planned-response-loss')
            expected = [pair for pair in possibilities[number] if pair in active_actions]
            require(actual == expected, 'planned-macro-schedule')
            head = parse_head(self.objects[HEAD_KEY]['body'], self.maximum)
            require(head['revision'] == 3 and head['head_serial'] == 3 and
                    head['owner_plan']['phase']['kind'] in
                    ({'aborted'} if family == 'claim_cancel' else
                     {'active'} if family == 'two_resume' else FINAL_PHASES), 'planned-terminal-result')
        elif name.startswith('preparelost-'):
            require(self.calls['c1']['outcome']['kind'] == 'unknown' and
                    sum(event['event'] == 'client_ref_restored' for event in events) == 2,
                    'lost-prepare-restored-original')
            original = self.calls['c1']['input']['args']['input']
            restores = [event for event in events if event['event'] == 'client_ref_restored']
            require(all(event['saved_input'] == original for event in restores) and
                    restores[0]['reference'] == restores[1]['reference'], 'lost-prepare-stable-ref')
        elif name.startswith('guards-'):
            attempted = [row for row in self.calls.values() if row['input']['operation'] == 'guard']
            require({row['input']['args']['entry'] for row in attempted} == PENDING_DENY | READ_ONLY,
                    'all-pending-entries')
            require(all(row['outcome'] == {'kind': 'error', 'value': {'code': 'PENDING'}}
                        for row in attempted if row['input']['args']['entry'] in PENDING_DENY), 'all-pending-entries')
        elif name.startswith('damage-owner-binding-'):
            require(name in {'damage-owner-binding-0', 'damage-owner-binding-1'}, 'declared-owner-binding-scenario')
            faults = [row for row in events if row['event'] == 'explicit_owner_binding_fault']
            inspections = [row for row in self.calls.values() if row['input']['operation'] == 'inspect']
            require(len(faults) == len(inspections) == 1, 'planned-owner-binding-damage')
            call = inspections[0]
            expected = 'CONFLICT' if name.endswith('-1') else 'CORRUPT'
            require(call['outcome'] == {'kind': 'error', 'value': {'code': expected}}, 'planned-owner-binding-outcome')
            proof_reads = [io for io in call['reads'] if '/owner/v1/proof/' in self.reads[io]['request']['key']]
            require(len(proof_reads) == 1 and self.read(proof_reads[0], call) is None, 'planned-owner-binding-missing-proof')
        elif name.startswith('transition-'):
            require(name in {'transition-technical', 'transition-business'}, 'declared-transition-scenario')
            head = parse_head(self.objects[HEAD_KEY]['body'], self.maximum)
            phase = head['owner_plan']['phase']
            require(head['head_serial'] == phase['head_serial'] + 1, 'planned-transition-serial')
            if name == 'transition-technical':
                require(head['revision'] == phase['revision'] and head['transition_nonce'] == phase['nonce'],
                        'planned-technical-transition')
            else:
                require(head['revision'] == phase['revision'] + 1 and head['transition_nonce'] == 9001 and
                        head['transition_nonce'] != phase['nonce'], 'planned-business-transition')
        else:
            require(name.split('-')[0] in {'descriptor', 'crash', 'cancelling', 'metadata', 'reserve',
                    'counter', 'activate', 'sameworker', 'replacement', 'legacy', 'latehttp', 'proof',
                    'deleted', 'inspect', 'storage', 'limits', 'sql', 'damage'}, 'declared-scenario-family')

    def event_initial(self, event):
        require(self.sequence == 1, 'initial-once')
        require(3 <= event['maximum'] <= MAX_U64, 'counter-bound')
        self.maximum = event['maximum']
        scope(event['scope'])
        require(event['limits'] == {'descriptor': 16384, 'proof': 8192, 'marker': 4096,
            'head': 262144, 'etag': 1024, 'key': 512, 'metadata_io': 8}, 'fixed-model-limits')
        self.objects = deepcopy(event['objects'])
        head = parse_head(self.objects[HEAD_KEY]['body'], self.maximum)
        require(head['format'] in (6, 7), 'initial-legacy-authority')
        for key, value in self.objects.items():
            quoted_etag(value['etag'])
            require(value['etag'] not in self.etags, 'etag-aba')
            self.etags.add(value['etag'])
            if key != HEAD_KEY:
                require(key == ROOT + 'storage/1/objects/' + sha(value['body']), 'payload-address')
                raw_json(value['body'], 8192)
        self.original_ack = deepcopy(event['original_ack'])
        require(self.original_ack['request'] == 'seed' and len(head['requests']) == 1 and
                head['requests'][0]['result'] == sha(self.original_ack['result']), 'initial-original-result')

    def event_process_started(self, event):
        process = event['process']
        require(process not in self.processes, 'process-identity-reuse')
        require(event['kind'] in ('server', 'client'), 'process-kind')
        if event['kind'] == 'server':
            integer(event['worker'])
            require(event['worker'] not in self.workers, 'worker-identity-assumption')
            self.workers.add(event['worker'])
            require(type(event['route']) is str, 'trusted-route')
            self.routes[event['route']] = process
        else:
            require(event['worker'] is None and event['route'] is None, 'process-kind')
        self.processes[process] = {**deepcopy(event), 'live': True}

    def event_explicit_metadata_fault(self, event):
        require(event['key'] == key_for('descriptor', {'creator': 11, 'operation': 101}) and
                event['purpose'] == 'test missing permanent descriptor; no legal DELETE API' and
                event['value'] is None and self.objects.get(event['key']) == event['previous'],
                'declared-metadata-damage-only')
        require(event['previous'] is not None, 'damage-existing-permanent-record')
        del self.objects[event['key']]

    def event_explicit_proof_fault(self, event):
        require(event['key'] == key_for('proof', {'creator': 11, 'operation': 101}) and
                event['purpose'] == 'test stable superseded proof counter contradiction' and
                self.objects.get(event['key']) == event['previous'], 'declared-proof-damage-only')
        old = parse_proof(event['previous']['body'], self.maximum)
        changed = parse_proof(event['value']['body'], self.maximum)
        expected = deepcopy(old)
        head = parse_head(self.objects[HEAD_KEY]['body'], self.maximum)
        expected['marker']['phase']['revision'] = head['owner_plan']['admission']['revision']
        expected['marker']['phase']['head_serial'] = head['owner_plan']['admission']['head_serial']
        require(changed == expected, 'declared-proof-damage-only')
        quoted_etag(event['value']['etag'])
        require(event['value']['etag'] not in self.etags, 'etag-aba')
        self.etags.add(event['value']['etag'])
        self.objects[event['key']] = deepcopy(event['value'])

    def event_explicit_owner_binding_fault(self, event):
        require(event['key'] == HEAD_KEY and self.objects[HEAD_KEY] == event['previous'] and
                event['purpose'] == 'test same immutable operation identity with another HEAD descriptor hash',
                'declared-owner-binding-damage-only')
        original = parse_head(event['previous']['body'], self.maximum)
        damaged = parse_head(event['value']['body'], self.maximum)
        require(original['format'] == 8, 'declared-owner-binding-damage-only')
        expected = deepcopy(original)
        expected['owner_plan']['descriptor_hash'] = damaged['owner_plan']['descriptor_hash']
        require(damaged == expected and damaged['owner_plan']['descriptor_hash'] !=
                original['owner_plan']['descriptor_hash'], 'declared-owner-binding-damage-only')
        descriptor = self.objects.get(key_for('descriptor', original['owner_plan']['identity']))
        require(descriptor is not None and sha(descriptor['body']) == original['owner_plan']['descriptor_hash'],
                'damage-existing-owner-dependency')
        quoted_etag(event['value']['etag'])
        require(event['value']['etag'] not in self.etags, 'etag-aba')
        self.etags.add(event['value']['etag'])
        self.objects[HEAD_KEY] = deepcopy(event['value'])

    def event_process_exited(self, event):
        require(event['process'] in self.processes and self.processes[event['process']]['live'], 'process-exit')
        self.processes[event['process']]['live'] = False
        # No pending write is deleted here. Its invocation remains an obligation.

    def event_http_dispatched(self, event):
        require(event['call'] not in self.calls, 'call-identity')
        client = self.processes.get(event['client'])
        require(client is not None and client['kind'] == 'client' and client['live'], 'live-client')
        scope(event['scope'])
        require(type(event['deadline']) is int and type(event['io_limit']) is int and
                0 <= event['io_limit'] <= 8, 'request-budget')
        self.calls[event['call']] = {'input': deepcopy(event), 'process': None, 'candidate': None,
            'metadata_ios': 0, 'outcome': None, 'server_result': None, 'recovery': None,
            'verified': None, 'barrier': None, 'native': None, 'readbacks': [], 'reads': [], 'writes': []}
        self.stats['calls'] += 1

    def event_http_admitted(self, event):
        call = self.calls[event['call']]
        require(call['process'] is None, 'admission-once')
        process = self.processes[event['process']]
        require(process['live'] and process['kind'] == 'server' and
                event['process'] == self.routes[call['input']['route']], 'actual-server')
        require(event['actual_worker'] == process['worker'], 'actual-worker')
        call['process'], call['actual_worker'] = event['process'], event['actual_worker']

    def call_io(self, event):
        call = self.calls[event['call']]
        require(call['process'] is not None and self.processes[call['process']]['live'], 'io-live-admission')
        source = call['input']
        require(event['deadline'] == source['deadline'], 'fixed-deadline')
        require(self.sequence - 1 < source['deadline'], 'invoke-within-deadline')
        require(source['expected_worker'] is None or source['expected_worker'] == call['actual_worker'],
                'actual-target-guard')
        require(len(event['key'].encode()) <= 512 and (event['key'] == HEAD_KEY or event['key'].startswith(ROOT)),
                'scoped-key')
        if '/storage/' not in event['key']:
            call['metadata_ios'] += 1
            require(call['metadata_ios'] <= source['io_limit'], 'metadata-io-budget')
        return call

    def event_s3_get_invoked(self, event):
        call = self.call_io(event)
        require(event['io'] not in self.reads and event['io'] not in self.writes, 'io-identity')
        self.reads[event['io']] = {'request': deepcopy(event), 'effected': False, 'responded': False}
        call['reads'].append(event['io'])

    def event_s3_get_effect(self, event):
        row = self.reads[event['io']]
        require(not row['effected'], 'read-effect-once')
        require(event['value'] == self.objects.get(row['request']['key']), 'exact-get-pair')
        row.update(effected=True, value=deepcopy(event['value']))

    def event_s3_get_response(self, event):
        row = self.reads[event['io']]
        require(row['effected'] and not row['responded'], 'read-response-order')
        call = self.calls[row['request']['call']]
        require(event['delivered'] and self.processes[call['process']]['live'] and
                event['value'] == row['value'], 'same-get-response')
        row['responded'] = True
        row['response_sequence'] = self.sequence

    def read(self, identifier, call, key=None):
        row = self.reads.get(identifier)
        require(row is not None and row['responded'] and row['request']['call'] == call['input']['call'],
                'delivered-observation')
        if key is not None:
            require(row['request']['key'] == key, 'observation-key')
        return row['value']

    def head_read(self, identifier, call):
        value = self.read(identifier, call, HEAD_KEY)
        require(value is not None, 'head-exists')
        return parse_head(value['body'], self.maximum), value['etag']

    def desc_read(self, identifier, call, identity=None):
        if identity is None:
            identity = call['input']['args']['identity']
        value = self.read(identifier, call, key_for('descriptor', identity))
        require(value is not None, 'descriptor-authority')
        desc = parse_descriptor(value['body'], self.maximum)
        require(desc['identity'] == identity, 'descriptor-identity')
        if call['input']['operation'] in ('claim', 'resume', 'abort'):
            require(call['input']['args'].get('descriptor_hash') == sha(desc), 'hash-required-plan-ref')
        return desc

    @staticmethod
    def authorized(call, head, read=False):
        require(call['input']['principal'] in head['readers' if read else 'admins'], 'fresh-acl')

    def available(self, head):
        require(head['lifecycle'] == 'ready' and not any(head['storage'][key]
                for key in ('copy', 'sweep', 'terminal')), 'owner-storage-admission')

    def reserve(self, head, count, takeover=False):
        require(head['revision'] <= self.maximum - count and head['head_serial'] <= self.maximum - count,
                'terminal-counter-reserve')
        require(not takeover or head['owner']['epoch'] < self.maximum, 'owner-epoch-overflow')

    def original_base(self, head, etag, desc):
        old = desc['base']
        require(old['head_hash'] == sha(head) and old['etag'] == etag and
                old['revision'] == head['revision'] and old['head_serial'] == head['head_serial'] and
                old['owner'] == head['owner'] and old['marker_hash'] ==
                (sha(head['owner_plan']) if 'owner_plan' in head else None), 'original-descriptor-base')

    def old_proof(self, event, call, head):
        if 'owner_plan' not in head:
            require(event['proof_io'] is None, 'unexpected-proof')
            return
        current = head['owner_plan']
        require(current['phase']['kind'] in FINAL_PHASES, 'pending-admission-exclusion')
        require(event['proof_io'] in self.reads, 'proof-before-replace')
        value = self.read(event['proof_io'], call, key_for('proof', current['identity']))
        require(value is not None, 'proof-before-replace')
        proof = parse_proof(value['body'], self.maximum)
        require(proof == {'version': 1, 'scope': head['scope'], 'marker': current}, 'proof-before-replace')
        self.stats['proof_readbacks'] += 1

    def phase_binding(self, plan, desc):
        require(plan['identity'] == desc['identity'] and plan['descriptor_hash'] == sha(desc), 'plan-descriptor-binding')
        phase = plan['phase']
        nonce = {'claimed': 'claim', 'cancelling': 'cancel', 'active': 'activate', 'aborted': 'abort'}[phase['kind']]
        require(phase['nonce'] == desc['nonces'][nonce], 'phase-nonce')
        expected_owner = deepcopy(desc['base']['owner'])
        if plan['admission']['kind'] == 'claim' and desc['mode'] == 'takeover':
            expected_owner['epoch'] += 1
            expected_owner['instance'] = desc['target']
        require(phase['owner'] == expected_owner, 'historical-phase-owner')
        require(plan['admission']['revision'] == desc['base']['revision'] + 1 and
                plan['admission']['head_serial'] == desc['base']['head_serial'] + 1, 'fixed-admission-counters')

    def event_candidate_fixed(self, event):
        call = self.calls[event['call']]
        require(call['candidate'] is None and call['process'] is not None and
                self.processes[call['process']]['live'], 'candidate-once')
        require(event['deadline'] == call['input']['deadline'], 'fixed-deadline')
        head, etag = self.head_read(event['basis_io'], call)
        self.authorized(call, head, call['input']['operation'] == 'sql')
        operation, args = call['input']['operation'], call['input']['args']
        if event['key'] == HEAD_KEY:
            require(event['condition'] == {'if_match': etag}, 'original-etag')
            proposed = parse_head(event['body'], self.maximum)
            self.head_candidate(event, call, head, etag, proposed)
        elif operation == 'prepare':
            require(event['condition'] == {'if_none_match': True}, 'immutable-condition')
            proposed = parse_descriptor(event['body'], self.maximum)
            require(event['key'] == key_for('descriptor', args['input']['identity']), 'descriptor-key')
            require(proposed['identity']['creator'] == call['input']['principal'], 'prepare-creator')
            require({key: proposed[key] for key in ('identity', 'target', 'mode', 'nonces',
                    'expected_revision', 'expected_head_serial')} == args['input'],
                    'fixed-plan-input')
            require(self.read(event['descriptor_io'], call, event['key']) is None, 'prepare-first-exact-lookup')
            require(head.get('owner_plan', {}).get('identity') != proposed['identity'],
                    'referenced-descriptor-must-exist')
            require(event.get('prepare_proof_io') in self.reads and
                    self.read(event['prepare_proof_io'], call, key_for('proof', proposed['identity'])) is None,
                    'referenced-descriptor-must-exist')
            require('owner_plan' not in head or head['owner_plan']['phase']['kind'] in FINAL_PHASES,
                    'pending-admission-exclusion')
            self.available(head)
            self.reserve(head, 2, proposed['mode'] == 'takeover')
            if proposed['mode'] == 'activate':
                require(proposed['target'] == head['owner']['instance'] and not head['active'], 'activate-only-base')
            self.original_base(head, etag, proposed)
        elif operation == 'preserve':
            require(event['condition'] == {'if_none_match': True}, 'immutable-condition')
            current = head.get('owner_plan')
            require(current is not None and current['phase']['kind'] in FINAL_PHASES, 'terminal-proof-only')
            desc = self.desc_read(event['descriptor_io'], call, current['identity'])
            self.phase_binding(current, desc)
            proposed = parse_proof(event['body'], self.maximum)
            require(event['key'] == key_for('proof', current['identity']), 'proof-key')
            require(proposed == {'version': 1, 'scope': head['scope'], 'marker': current}, 'stable-terminal-proof')
        else:
            raise Violation('candidate-operation')
        call['candidate'] = deepcopy(event)

    def head_candidate(self, event, call, before, etag, after):
        operation, args = call['input']['operation'], call['input']['args']
        require(after['scope'] == before['scope'], 'full-scope')
        expected = deepcopy(before)
        expected['head_serial'] += 1
        if operation != 'storage':
            expected['revision'] += 1
        plan = before.get('owner_plan')
        is_pending = plan is not None and plan['phase']['kind'] in PENDING_PHASES
        if operation in ('claim', 'abort', 'resume'):
            desc = self.desc_read(event['descriptor_io'], call)
            same = plan is not None and plan['identity'] == desc['identity'] and plan['descriptor_hash'] == sha(desc)
            self.available(before)
            if operation == 'claim' or (operation == 'abort' and not same):
                require(not is_pending, 'pending-admission-exclusion')
                self.original_base(before, etag, desc)
                self.reserve(before, 2, operation == 'claim' and desc['mode'] == 'takeover')
                self.old_proof(event, call, before)
                if desc['mode'] == 'activate':
                    require(desc['target'] == before['owner']['instance'] and not before['active'], 'activate-only-base')
                expected['format'], expected['active'] = 8, False
                admission = 'claim' if operation == 'claim' else 'cancel'
                phase = 'claimed' if operation == 'claim' else 'cancelling'
                if operation == 'claim':
                    require(call['actual_worker'] == desc['target'] == call['input']['expected_worker'],
                            'actual-target-guard')
                    if desc['mode'] == 'takeover':
                        expected['owner']['epoch'] += 1
                        expected['owner']['instance'] = desc['target']
                expected['owner_plan'] = {'identity': desc['identity'], 'descriptor_hash': sha(desc),
                    'admission': {'kind': admission, 'revision': expected['revision'],
                                  'head_serial': expected['head_serial']},
                    'phase': {'kind': phase, 'revision': expected['revision'],
                              'head_serial': expected['head_serial'], 'nonce': desc['nonces'][admission],
                              'owner': deepcopy(expected['owner'])}}
                expected['transition_nonce'] = desc['nonces'][admission]
            else:
                require(same and is_pending, 'monotonic-accepted-phase')
                self.reserve(before, 1)
                self.phase_binding(plan, desc)
                kind, nonce = ('active', 'activate') if operation == 'resume' else ('aborted', 'abort')
                if operation == 'resume':
                    require(plan['phase']['kind'] == 'claimed', 'cancel-never-activates')
                    require(call['actual_worker'] == desc['target'] == call['input']['expected_worker'] and
                            before['owner']['instance'] == desc['target'], 'actual-target-guard')
                    require(call['verified'] is not None and call['barrier'] is not None, 'complete-recovery-barrier')
                expected['active'] = kind == 'active'
                expected['owner_plan']['phase'] = {'kind': kind, 'revision': expected['revision'],
                    'head_serial': expected['head_serial'], 'nonce': desc['nonces'][nonce],
                    'owner': deepcopy(expected['owner'])}
                expected['transition_nonce'] = desc['nonces'][nonce]
        elif operation in ('acl', 'quota'):
            require(before['lifecycle'] == 'ready' and not before['storage']['terminal'], 'metadata-lifecycle')
            self.reserve(before, 2 if is_pending else 1)
            expected['transition_nonce'] = args.get('transition_nonce', before['transition_nonce'])
            if operation == 'acl':
                require(before['auth_epoch'] < self.maximum, 'auth-epoch-overflow')
                expected['auth_epoch'] += 1
                expected['admins'] = args['admins']
            else:
                require(call.get('quota_manifest') == event['basis_io'], 'quota-snapshot')
                expected['quota'] = args['quota']
        elif operation in ('legacy_takeover', 'legacy_activate'):
            require(before['format'] != 8, 'legacy-permanent-disabled')
            self.available(before)
            require(before['revision'] == args['expected_revision'], 'legacy-original-revision')
            self.reserve(before, 1, operation == 'legacy_takeover')
            if operation == 'legacy_takeover':
                expected['owner']['epoch'] += 1
                expected['owner']['instance'] = call['actual_worker']
                expected['active'] = False
            else:
                require(before['owner']['instance'] == call['actual_worker'], 'actual-target-guard')
                expected['active'] = True
        elif operation == 'storage':
            require(not is_pending, 'pending-mutator-guard')
            require(before['head_serial'] < self.maximum, 'counter-overflow')
            value = args['value']
            if value in ('copy', 'sweep'):
                require(not any(before['storage'][key] for key in ('copy', 'sweep', 'terminal')), 'storage-exclusion')
                expected['storage'][value], expected['active'] = True, False
            elif value == 'finish':
                expected['storage']['copy'] = expected['storage']['sweep'] = False
            elif value == 'deleted':
                self.reserve(before, 1)
                require(before['owner']['epoch'] < self.maximum, 'owner-epoch-overflow')
                expected['revision'] += 1
                expected['owner']['epoch'] += 1
                expected['lifecycle'], expected['active'] = 'deleted', False
            elif value == 'terminal':
                require(before['lifecycle'] == 'deleted' and not before['storage']['copy'] and
                        not before['storage']['sweep'], 'terminal-storage')
                expected['storage']['terminal'] = True
                expected['format'] = 8 if plan is not None else 7
            else:
                require(value == 'technical', 'storage-projection')
        elif operation == 'sql':
            require(not is_pending, 'pending-mutator-guard')
            self.available(before)
            require(before['active'] and before['owner']['instance'] == call['actual_worker'], 'sql-owner')
            self.reserve(before, 1)
            require(call.get('sql') is not None, 'original-sql-only')
            result = json.loads(call['sql']['result'])
            expected['data_root'] = sha({'kind': 'data', 'counter': 1})
            expected['windows'].append(args['request'])
            expected['requests'].append({'id': args['request'], 'fingerprint': result['fingerprint'], 'result': sha(result)})
            for value in (expected['data_root'], sha(result)):
                require(ROOT + 'storage/1/objects/' + value in self.objects, 'dependencies-before-head')
        else:
            raise Violation('head-operation')
        if operation != 'sql':
            require((after['data_root'], after['requests'], after['windows']) ==
                    (before['data_root'], before['requests'], before['windows']), 'original-closure-preserved')
        require(after == expected, 'head-exact-delta', operation)

    def event_s3_put_invoked(self, event):
        call = self.call_io(event)
        require(event['io'] not in self.writes and event['io'] not in self.reads, 'io-identity')
        if event['purpose'] == 'candidate':
            candidate = call['candidate']
            require(candidate is not None and all(event[key] == candidate[key]
                    for key in ('key', 'body', 'condition', 'deadline')), 'fixed-candidate')
            require(not any(self.writes[io]['request']['purpose'] == 'candidate' for io in call['writes']),
                    'one-attempt-no-rebase')
        else:
            require(event['purpose'] == 'sql_dependency' and call.get('sql') is not None, 'original-sql-only')
            require(event['condition'] == {'if_none_match': True} and
                    event['key'] == ROOT + 'storage/1/objects/' + sha(event['body']), 'immutable-condition')
        self.writes[event['io']] = {'request': deepcopy(event), 'effected': False, 'responded': False}
        call['writes'].append(event['io'])
        self.stats['writes'] += 1

    def event_s3_put_effect(self, event):
        row = self.writes[event['io']]
        require(not row['effected'], 'write-effect-once')
        request, result = row['request'], event['result']
        prior = self.objects.get(request['key'])
        condition = request['condition']
        allowed = ((condition == {'if_none_match': True} and prior is None) or
                   (set(condition) == {'if_match'} and prior is not None and prior['etag'] == condition['if_match']))
        require(result['status'] == (200 if allowed else 412), 'conditional-effect')
        if allowed:
            require(result['value']['body'] == request['body'], 'effect-fixed-bytes')
            quoted_etag(result['value']['etag'])
            require(result['value']['etag'] not in self.etags, 'etag-aba')
            self.etags.add(result['value']['etag'])
            self.objects[request['key']] = deepcopy(result['value'])
            self.stats['applied'] += 1
            if request['key'] == HEAD_KEY:
                head = parse_head(request['body'], self.maximum)
                if 'owner_plan' in head:
                    current = head['owner_plan']
                    key = (current['identity']['creator'], current['identity']['operation'])
                    previous = self.accepted_markers.get(key)
                    if previous is not None and previous['phase']['kind'] in FINAL_PHASES:
                        require(previous == current, 'stable-terminal-marker')
                    self.accepted_markers[key] = deepcopy(current)
            call = self.calls[request['call']]
            if not self.processes[call['process']]['live'] or call['outcome'] is not None:
                self.stats['late_effects'] += 1
        else:
            require(result['value'] == prior, 'conflict-no-write')
            self.stats['conflicts'] += 1
        row.update(effected=True, result=deepcopy(result))

    def event_s3_put_response(self, event):
        row = self.writes[event['io']]
        require(row['effected'] and not row['responded'], 'write-response-order')
        call = self.calls[row['request']['call']]
        if event['delivered']:
            require(self.processes[call['process']]['live'] and event['result'] == row['result'], 'write-response-pair')
        else:
            require(event['result'] is None, 'lost-response-no-knowledge')
        row['responded'], row['delivered'] = True, event['delivered']

    def event_immutable_readback_verified(self, event):
        call = self.calls[event['call']]
        write = self.writes[event['write']]
        require(write['request']['call'] == event['call'] and write['responded'] and write['delivered'],
                'immutable-write-observation')
        value = self.read(event['read'], call, write['request']['key'])
        require(value is not None and value['body'] == write['request']['body'], 'immutable-first-input')
        call['readbacks'].append(event['read'])

    def event_prepared_descriptor_verified(self, event):
        call = self.calls[event['call']]
        require(call['input']['operation'] == 'prepare' and call['candidate'] is None,
                'existing-prepare-is-observation')
        args = call['input']['args']['input']
        stored = self.read(event['descriptor_io'], call, key_for('descriptor', args['identity']))
        require(stored is not None and stored['body'] == event['body'], 'existing-descriptor-actual-bytes')
        desc = parse_descriptor(stored['body'], self.maximum)
        head, _etag = self.head_read(event['basis_io'], call)
        self.authorized(call, head)
        require(self.reads[event['basis_io']]['request']['sequence'] >
                self.reads[event['descriptor_io']]['response_sequence'], 'prepare-current-admin-after-history')
        require({key: desc[key] for key in args} == args, 'same-fixed-prepare-input')
        call['existing_prepared'] = event['body']

    def event_recovery_started(self, event):
        call = self.calls[event['call']]
        require(call['input']['operation'] == 'resume' and call['recovery'] is None, 'recovery-call')
        head, _etag = self.head_read(event['basis_io'], call)
        desc = self.desc_read(event['descriptor_io'], call)
        self.authorized(call, head)
        require(head.get('owner_plan', {}).get('phase', {}).get('kind') == 'claimed', 'recovery-claimed-only')
        self.phase_binding(head['owner_plan'], desc)
        require(call['actual_worker'] == call['input']['expected_worker'] == desc['target'] == head['owner']['instance'],
                'actual-target-guard')
        require(event['deadline'] == call['input']['deadline'], 'fixed-deadline')
        self.available(head)
        self.reserve(head, 1)
        call['recovery'] = deepcopy(event)

    def event_recovery_verified(self, event):
        call = self.calls[event['call']]
        require(call['recovery'] is not None and call['verified'] is None, 'complete-recovery-once')
        head, _etag = self.head_read(call['recovery']['basis_io'], call)
        hashes = [head['data_root']] + [row['result'] for row in head['requests']]
        require(len(event['reads']) == len(hashes), 'complete-retained-closure')
        for io, value_hash in zip(event['reads'], hashes):
            value = self.read(io, call, ROOT + 'storage/1/objects/' + value_hash)
            require(value is not None and sha(value['body']) == value_hash, 'recovery-content-hash')
        require(all(event[key] == head[key] for key in ('data_root', 'requests', 'windows')), 'complete-retained-closure')
        call['verified'] = deepcopy(event)
        call['verified_sequence'] = self.sequence
        self.stats['recoveries'] += 1

    def event_recovery_barrier(self, event):
        call = self.calls[event['call']]
        require(call['verified'] is not None and call['barrier'] is None, 'recovery-barrier-order')
        require(event['basis_io'] == call['recovery']['basis_io'], 'original-recovery-base')
        require(event['final_io'] != event['basis_io'] and
                self.reads[event['final_io']]['request']['sequence'] > call['verified_sequence'],
                'fresh-recovery-barrier-order')
        original = self.read(event['basis_io'], call, HEAD_KEY)
        final = self.read(event['final_io'], call, HEAD_KEY)
        require(original == final, 'fresh-recovery-barrier')
        self.authorized(call, parse_head(final['body'], self.maximum))
        call['barrier'] = deepcopy(event)

    def event_quota_manifest_verified(self, event):
        call = self.calls[event['call']]
        head, _etag = self.head_read(event['basis_io'], call)
        value = self.read(event['read'], call, ROOT + 'storage/1/objects/' + head['data_root'])
        require(value is not None and sha(value['body']) == head['data_root'], 'quota-snapshot')
        call['quota_manifest'] = event['basis_io']

    def event_inspect_barrier(self, event):
        call = self.calls[event['call']]
        require(call['input']['operation'] == 'inspect' and 'inspect_barrier' not in call,
                'inspect-barrier-order')
        original = self.read(event['basis_io'], call, HEAD_KEY)
        final = self.read(event['final_io'], call, HEAD_KEY)
        require(original == final, 'stable-history-observation')
        desc = self.desc_read(call['reads'][0], call)
        proof = self.read(event['proof_io'], call, key_for('proof', desc['identity']))
        require(self.reads[event['proof_io']]['request']['sequence'] >
                self.reads[event['basis_io']]['response_sequence'] and
                self.reads[event['final_io']]['request']['sequence'] >
                self.reads[event['proof_io']]['response_sequence'], 'history-barrier-order')
        head = parse_head(final['body'], self.maximum)
        self.authorized(call, head)
        current = head.get('owner_plan')
        require(current is None or current['identity'] != desc['identity'] or current['descriptor_hash'] == sha(desc),
                'same-identity-descriptor-binding')
        if proof is not None:
            value = parse_proof(proof['body'], self.maximum)
            self.phase_binding(value['marker'], desc)
            head = parse_head(final['body'], self.maximum)
            require(head['format'] == 8 and value['marker']['phase']['revision'] <
                    head['owner_plan']['admission']['revision'] and value['marker']['phase']['head_serial'] <
                    head['owner_plan']['admission']['head_serial'], 'historical-proof-before-current-admission')
        call['inspect_barrier'] = deepcopy(event)

    def event_native_sql_executed(self, event):
        call = self.calls[event['call']]
        require(call['input']['operation'] == 'sql' and event['request'] == call['input']['args']['request'] and
                event['request'] not in self.executed, 'sql-never-replayed')
        head_reads = [io for io in call['reads'] if self.reads[io]['request']['key'] == HEAD_KEY]
        head, _etag = self.head_read(head_reads[-1], call)
        require(head.get('owner_plan', {}).get('phase', {}).get('kind') not in PENDING_PHASES, 'pending-mutator-guard')
        require(head['active'] and head['owner']['instance'] == call['actual_worker'], 'sql-owner')
        self.executed.add(event['request'])
        call['sql'] = deepcopy(event)
        self.stats['native_sql'] += 1

    def event_native_publication(self, event):
        call = self.calls[event['call']]
        write = self.writes[event['write']]
        require(call['input']['operation'] == 'resume' and call['verified'] is not None and
                call['barrier'] is not None and write['responded'] and write['delivered'] and
                write['result']['status'] == 200, 'native-after-authoritative-phase')
        require(write['request']['call'] == event['call'] and call['native'] is None, 'native-once')
        require(event['descriptor_hash'] == json.loads(write['request']['body'])['owner_plan']['descriptor_hash'],
                'native-plan-binding')
        call['native'] = deepcopy(event)

    def event_server_finished(self, event):
        call = self.calls[event['call']]
        require(call['server_result'] is None and call['process'] is not None and
                self.processes[call['process']]['live'], 'server-result-once')
        kind, value, operation = event['kind'], event['value'], call['input']['operation']
        if operation == 'inspect':
            heads = [self.read(io, call, HEAD_KEY) for io in call['reads']
                     if self.reads[io]['request']['key'] == HEAD_KEY]
            if heads:
                first = parse_head(heads[0]['body'], self.maximum)
                current = first.get('owner_plan')
                desc = self.desc_read(call['reads'][0], call)
                if (call['input']['principal'] in first['admins'] and current is not None and current['identity'] == desc['identity'] and
                        current['descriptor_hash'] != sha(desc)):
                    require(len(heads) == 2, 'owner-binding-final-barrier')
                    changed = heads[0] != heads[-1]
                    require(kind == 'error' and value == {'code': 'CONFLICT' if changed else 'CORRUPT'},
                            'changed-head-before-corruption' if changed else 'same-identity-descriptor-binding')
        if operation == 'prepare':
            observed = [io for io in call['reads'] if self.reads[io]['request']['key'] == HEAD_KEY]
            if observed:
                current, _etag = self.head_read(observed[-1], call)
                if call['input']['principal'] not in current['admins']:
                    require(kind == 'error' and value == {'code': 'DENIED'}, 'prepare-authorize-before-history')
        if kind == 'accepted':
            writes = [self.writes[io] for io in call['writes'] if self.writes[io]['request']['purpose'] == 'candidate']
            require(len(writes) == 1 and writes[0]['responded'] and writes[0]['delivered'] and
                    writes[0]['result']['status'] == 200 and value == {'head': json.loads(writes[0]['request']['body'])},
                    'ack-after-accepted-original')
            require(operation != 'resume' or call['native'] is not None, 'ack-after-native')
        elif kind in ('prepared', 'preserved'):
            if 'existing_prepared' in call:
                require(kind == 'prepared' and value == {'body': call['existing_prepared']}, 'same-fixed-prepare-input')
            else:
                require(call['readbacks'] and value == {'body': call['candidate']['body']}, 'ack-after-immutable-readback')
            require((kind, operation) in (('prepared', 'prepare'), ('preserved', 'preserve')), 'result-operation')
        elif kind == 'pending':
            require(operation == 'prepare' and call['candidate'] is None, 'pending-no-alternate-descriptor')
            require(value['marker']['phase']['kind'] in PENDING_PHASES, 'pending-observation')
        elif kind in ('read_only', 'guard_only'):
            require(operation == 'guard' and call['candidate'] is None and not call['writes'], 'read-only-authority')
            entry = call['input']['args']['entry']
            head, _etag = self.head_read(call['reads'][-1], call)
            if kind == 'read_only':
                self.authorized(call, head, read=True)
                require(entry in READ_ONLY and value == {'entry': entry, 'writer': False, 'native_session': False},
                        'readonly-not-writer')
            else:
                require(entry in PENDING_DENY and head.get('owner_plan', {}).get('phase', {}).get('kind')
                        not in PENDING_PHASES, 'pending-mutator-guard')
                require(value == {'entry': entry, 'production_effect': 'NOT_MODELLED'}, 'bounded-projection')
            self.stats['guards'] += 1
        elif kind == 'observed':
            require(value.get('native_session') is False and value.get('historical_ack') is False,
                    'observation-not-old-ack')
            read_heads = [io for io in call['reads'] if self.reads[io]['request']['key'] == HEAD_KEY]
            current, _etag = self.head_read(read_heads[-1], call)
            self.authorized(call, current)
            desc = self.desc_read(call['reads'][0], call)
            require(value.get('prepared') == {'body': canonical(desc), 'descriptor_hash': sha(desc)},
                    'observed-actual-descriptor')
            require(value['current_head'] == current, 'observed-head-snapshot')
            if 'marker' in value:
                require(value['marker'] == current.get('owner_plan'), 'observed-marker')
            elif 'proof' in value:
                require('inspect_barrier' in call, 'stable-history-observation')
                proof_reads = [io for io in call['reads'] if '/owner/v1/proof/' in self.reads[io]['request']['key']]
                require(proof_reads, 'observed-proof-read')
                stored = self.read(proof_reads[-1], call)
                require(stored is not None and parse_proof(stored['body'], self.maximum) == value['proof'], 'observed-proof')
            else:
                require('inspect_barrier' in call, 'stable-history-observation')
                require(value.get('past_effect') == 'unknown' and value.get('phase') == 'unaccepted_or_fenced',
                        'fence-not-not-applied')
        elif kind == 'unknown':
            require(value == {'reason': 's3_response_lost'} and any(self.writes[io]['responded'] and
                    not self.writes[io]['delivered'] for io in call['writes']), 'unknown-response-evidence')
        else:
            require(kind == 'error' and set(value) == {'code'}, 'result-kind')
        call['server_result'] = {'kind': kind, 'value': deepcopy(value)}

    def restored_record(self, event):
        source = self.calls[event['source']]['outcome']
        require(source is not None and source['kind'] in ('prepared', 'observed'), 'restore-from-observed-record')
        raw = source['value']['body'] if source['kind'] == 'prepared' else source['value']['prepared']['body']
        desc = parse_descriptor(raw, self.maximum)
        fixed = {key: desc[key] for key in ('identity', 'target', 'mode', 'nonces',
                                          'expected_revision', 'expected_head_serial')}
        return raw, desc, fixed

    def event_client_ref_restored(self, event):
        raw, desc, fixed = self.restored_record(event)
        require(event['saved_input'] == fixed, 'restore-saved-input-match')
        require(event['reference'] == {**desc['identity'], 'descriptor_hash': sha(raw)}, 'restored-hash-ref')

    def event_client_ref_restore_rejected(self, event):
        _raw, _desc, fixed = self.restored_record(event)
        require(event['saved_input'] != fixed, 'restore-real-input-mismatch')

    def event_caller_observed(self, event):
        call = self.calls[event['call']]
        require(call['outcome'] is None, 'unknown-not-rewritten')
        result = {'kind': event['kind'], 'value': event['value']}
        if result != call['server_result']:
            require(event['kind'] == 'unknown' and event['value'] in
                    ({'reason': 'client_timeout'}, {'reason': 'client_exit'}), 'caller-knowledge')
            if event['value']['reason'] == 'client_exit':
                require(not self.processes[call['input']['client']]['live'], 'client-exit-knowledge')
        call['outcome'] = deepcopy(result)
        self.stats['caller_unknowns'] += (event['kind'] == 'unknown' or
            (event['kind'] == 'error' and event['value'] == {'code': 'UNKNOWN'}))

    def event_observation_closed(self, event):
        require(event['calls'] == sorted(self.calls) and event['reads'] == sorted(self.reads) and
                event['writes'] == sorted(self.writes), 'observer-denominator')
        require(event['pending_effects'] == sorted(io for io, value in self.writes.items() if not value['effected']),
                'invoked-survives-crash')
        require(event['pending_responses'] == sorted(io for io, value in self.writes.items() if not value['responded']),
                'response-denominator')
        require(event['caller_unknowns'] == sorted(name for name, value in self.calls.items()
                if value['outcome'] is not None and (value['outcome']['kind'] == 'unknown' or
                   value['outcome'] == {'kind': 'error', 'value': {'code': 'UNKNOWN'}})), 'unknown-history-ledger')
        require(event['objects_sha256'] == sha(self.objects), 'final-object-history')
        self.closed = True


def audit(trace, strict_scenario=False):
    return Audit().run(trace, strict_scenario)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    value = json.loads(args.trace.read_text(), object_pairs_hook=unique_pairs)
    print(json.dumps(audit(value), sort_keys=True))


if __name__ == '__main__':
    main()
