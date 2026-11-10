"""Finite owner-plan protocol projection, never a service/controller implementation.

S3 GETs have explicit invoke/effect/response events but one macro scheduling cut.
Conditional writes have three independently schedulable cuts. A caller timeout or
process exit never removes an invoked request from the object service.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json


U64 = (1 << 64) - 1
SCOPE = dict(zip(('deployment', 'tenant', 'database', 'incarnation', 'generation'),
                 (1, 7, 91, 1, 1)))
PREFIX = 'scap-object/v1/1/7/91/inc/1/gen/1/'
HEAD = 'scap-object/v1/1/7/91/head'
PENDING = ('claimed', 'cancelling')
TERMINAL = ('active', 'aborted')
MUTATORS = ('execute', 'commit', 'cancel_unknown', 'close_full', 'epoch',
            'set_lifecycle', 'named_delete', 'catalogue_recovery_publish',
            'compact_begin', 'compact_copy', 'compact_promote', 'compact_abort',
            'gc_prepare', 'gc_resume', 'storage_seal')
READERS = ('status', 'query', 'lookup', 'open_readonly', 'cancel_known')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256((value if isinstance(value, str) else encoded(value)).encode()).hexdigest()


def control_key(kind, creator, operation, descriptor_hash=None):
    return PREFIX + f'owner/v1/{kind}/{creator}/{operation}'


def payload_key(value):
    return PREFIX + 'storage/1/objects/' + value


def identity(creator=11, operation=101):
    return {'creator': creator, 'operation': operation}


def plan_input(operation=101, target=2, mode='takeover', creator=11,
               expected_revision=1, expected_head_serial=1):
    return {'identity': identity(creator, operation), 'target': target, 'mode': mode,
            'expected_revision': expected_revision, 'expected_head_serial': expected_head_serial,
            'nonces': {'claim': operation * 10 + 1, 'cancel': operation * 10 + 2,
                       'activate': operation * 10 + 3, 'abort': operation * 10 + 4}}


def marker(head):
    return head.get('owner_plan')


def pending(head):
    return marker(head) is not None and marker(head)['phase']['kind'] in PENDING


def available(head):
    storage = head['storage']
    return (head['lifecycle'] == 'ready' and not storage['copy'] and
            not storage['sweep'] and not storage['terminal'])


def base_fields(head, etag):
    return {'head_hash': digest(head), 'etag': etag, 'revision': head['revision'],
            'head_serial': head['head_serial'], 'owner': deepcopy(head['owner']),
            'marker_hash': digest(marker(head)) if marker(head) is not None else None}


def descriptor(head, etag, value):
    body = {'version': 1, 'scope': deepcopy(head['scope']), **deepcopy(value),
            'base': base_fields(head, etag)}
    body['input_digest'] = digest(body)
    return body


def terminal_proof(head):
    return {'version': 1, 'scope': deepcopy(head['scope']), 'marker': deepcopy(marker(head))}


class Rejected(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass
class Call:
    identifier: str
    operation: str
    args: dict
    principal: int
    route: str
    client: str
    expected_worker: int | None
    deadline: int
    io_limit: int
    stage: str = 'queued'
    process: str | None = None
    basis: dict | None = None
    basis_io: str | None = None
    desc: dict | None = None
    desc_io: str | None = None
    proof_io: str | None = None
    body: str | None = None
    key: str | None = None
    condition: dict | None = None
    io: str | None = None
    metadata_ios: int = 0
    outcome: dict | None = None
    recovery: bool = False
    inspected_proof: dict | None = None
    prepare_proof_io: str | None = None


@dataclass
class Exchange:
    identifier: str
    call: str
    key: str
    body: str
    condition: dict
    purpose: str
    result: dict | None = None
    responded: bool = False


class World:
    """One Scope, bounded counters, opaque complete native data/result closure."""
    def __init__(self, maximum=15, revision=1, serial=1, epoch=1, active=True,
                 storage=None, lifecycle='ready'):
        assert 3 <= maximum <= U64
        self.maximum = maximum
        self.events, self.calls, self.exchanges, self.processes, self.routes = [], {}, {}, {}, {}
        self.objects, self.etags, self.executed = {}, 0, set()
        data = {'kind': 'data', 'counter': 0}
        result = {'kind': 'result', 'request': 'seed', 'fingerprint': 'seed-fingerprint',
                  'rows': [[0, 'original-random-result']]}
        self.seed_result = encoded(result)
        self._install(payload_key(digest(data)), encoded(data))
        self._install(payload_key(digest(result)), encoded(result))
        head = {'format': 6, 'scope': deepcopy(SCOPE), 'revision': revision,
                'head_serial': serial, 'transition_nonce': 1, 'owner': {'instance': 1, 'epoch': epoch},
                'active': active, 'lifecycle': lifecycle, 'auth_epoch': 1,
                'admins': [11, 12], 'readers': [11, 12], 'quota': 100,
                'data_root': digest(data), 'windows': ['seed'], 'requests': [
                    {'id': 'seed', 'fingerprint': 'seed-fingerprint', 'result': digest(result)}],
                'storage': storage or {'active': 1, 'allocated': 1, 'copy': False,
                                      'sweep': False, 'terminal': False}}
        if head['storage']['terminal']:
            head['format'], head['lifecycle'], head['active'] = 7, 'deleted', False
        self._install(HEAD, encoded(head))
        self.emit('initial', maximum=maximum, scope=SCOPE, objects=deepcopy(self.objects),
                  original_ack={'request': 'seed', 'result': self.seed_result},
                  limits={'descriptor': 16384, 'proof': 8192, 'marker': 4096,
                          'head': 262144, 'etag': 1024, 'key': 512, 'metadata_io': 8},
                  assumptions=['strong exact GET and conditional PUT', 'no ETag ABA',
                               'process worker identities never reused',
                               'opaque finite complete native recovery closure'])
        for name, kind, worker, route in (
            ('client-1', 'client', None, None), ('client-2', 'client', None, None),
            ('worker-1', 'server', 1, 'owner'), ('worker-2', 'server', 2, 'target'),
            ('worker-3', 'server', 3, 'other')):
            self.spawn(name, kind, worker, route)

    @property
    def clock(self):
        return len(self.events)

    def emit(self, event, **fields):
        self.events.append({'sequence': len(self.events) + 1, 'event': event, **deepcopy(fields)})

    def _install(self, key, body):
        self.etags += 1
        self.objects[key] = {'body': body, 'etag': f'"opaque-{self.etags:06d}"'}

    def head(self):
        return json.loads(self.objects[HEAD]['body'])

    def spawn(self, process, kind, worker=None, route=None):
        assert process not in self.processes
        assert worker is None or all(row['worker'] != worker for row in self.processes.values())
        self.processes[process] = {'kind': kind, 'worker': worker, 'live': True}
        if route is not None:
            self.routes[route] = process
        self.emit('process_started', process=process, kind=kind, worker=worker, route=route)

    def crash(self, process):
        assert self.processes[process]['live']
        self.processes[process]['live'] = False
        self.emit('process_exited', process=process)
        for call in self.calls.values():
            if call.client == process and call.outcome is None:
                self._observe(call, 'unknown', {'reason': 'client_exit'})
        # Deliberately leave all Exchange objects in place, including uneffected PUTs.

    def begin(self, operation, args=None, principal=11, route='target', client='client-1',
              expected_worker=None, deadline=None, io_limit=8):
        assert self.processes[client]['live']
        assert 0 <= io_limit <= 8
        identifier = f'c{len(self.calls) + 1}'
        args = deepcopy(args or {})
        if 'identity' in args and 'descriptor_hash' in args['identity']:
            args['descriptor_hash'] = args['identity'].pop('descriptor_hash')
        if operation in ('claim', 'resume', 'legacy_takeover', 'legacy_activate') and expected_worker is None:
            expected_worker = self.processes[self.routes[route]]['worker']
        call = Call(identifier, operation, args, principal, route, client,
                    expected_worker, self.clock + 4096 if deadline is None else deadline, io_limit)
        self.calls[identifier] = call
        self.emit('http_dispatched', call=identifier, operation=operation, args=call.args,
                  principal=principal, route=route, client=client, expected_worker=expected_worker,
                  scope=SCOPE, deadline=call.deadline, io_limit=io_limit)
        return identifier

    def _observe(self, call, kind, value):
        if call.outcome is None:
            call.outcome = {'kind': kind, 'value': deepcopy(value)}
            self.emit('caller_observed', call=call.identifier, kind=kind, value=value)

    def timeout(self, identifier):
        call = self.calls[identifier]
        assert call.outcome is None
        self._observe(call, 'unknown', {'reason': 'client_timeout'})

    def _finish(self, call, kind, value):
        call.stage = 'done'
        self.emit('server_finished', call=call.identifier, kind=kind, value=value)
        if self.processes[call.client]['live']:
            self._observe(call, kind, value)

    def _error(self, call, code):
        self._finish(call, 'error', {'code': code})

    def _budget(self, call, key):
        if self.clock >= call.deadline:
            raise Rejected('UNKNOWN')
        if '/storage/' not in key:
            if call.metadata_ios >= call.io_limit:
                raise Rejected('LIMIT')
            call.metadata_ios += 1

    def _read(self, call, key):
        self._budget(call, key)
        identifier = f'g{self.clock + 1}'
        self.emit('s3_get_invoked', io=identifier, call=call.identifier, key=key,
                  deadline=call.deadline)
        stored = deepcopy(self.objects.get(key))
        self.emit('s3_get_effect', io=identifier, value=stored)
        self.emit('s3_get_response', io=identifier, delivered=True, value=stored)
        return identifier, stored

    def _head(self, call):
        identifier, stored = self._read(call, HEAD)
        assert stored is not None
        return identifier, json.loads(stored['body']), stored['etag']

    @staticmethod
    def _authorize(head, principal, read=False):
        if principal not in head['readers' if read else 'admins']:
            raise Rejected('DENIED')

    def _space(self, head, count=1, takeover=False):
        if head['revision'] > self.maximum - count or head['head_serial'] > self.maximum - count:
            raise Rejected('LIMIT')
        if takeover and head['owner']['epoch'] == self.maximum:
            raise Rejected('LIMIT')

    def _read_descriptor(self, call):
        if call.operation in ('claim', 'resume', 'abort') and not isinstance(call.args.get('descriptor_hash'), str):
            raise Rejected('INVALID')
        ident = call.args['identity']
        identifier, stored = self._read(call, control_key('descriptor', **ident))
        if stored is None:
            raise Rejected('MISSING_DESCRIPTOR')
        call.desc_io, call.desc = identifier, json.loads(stored['body'])
        if call.operation in ('claim', 'resume', 'abort') and digest(call.desc) != call.args['descriptor_hash']:
            raise Rejected('CONFLICT')
        return call.desc

    def _old_proof(self, call, head):
        old = marker(head)
        if old is None:
            return
        if old['phase']['kind'] not in TERMINAL:
            raise Rejected('PENDING')
        identifier, stored = self._read(call, control_key('proof', **old['identity']))
        if stored is None or stored['body'] != encoded(terminal_proof(head)):
            raise Rejected('PROOF_REQUIRED')
        call.proof_io = identifier

    def _ready(self, call, key, body, condition, basis_io=None):
        call.key, call.body, call.condition = key, encoded(body), condition
        call.basis_io, call.stage = basis_io, 'ready'
        self.emit('candidate_fixed', call=call.identifier, key=key, body=call.body,
                  condition=condition, basis_io=basis_io, descriptor_io=call.desc_io,
                  proof_io=call.proof_io, prepare_proof_io=call.prepare_proof_io, deadline=call.deadline)

    @staticmethod
    def _same_plan(head, desc):
        current = marker(head)
        return (current is not None and current['identity'] == desc['identity'] and
                current['descriptor_hash'] == digest(desc))

    def _terminal_observation(self, call, head):
        value = {'marker': deepcopy(marker(head)), 'current_head': deepcopy(head),
                 'prepared': {'body': encoded(call.desc), 'descriptor_hash': digest(call.desc)},
                 'native_session': False, 'historical_ack': False}
        self._finish(call, 'observed', value)

    def admit(self, identifier):
        call = self.calls[identifier]
        assert call.stage == 'queued'
        process = self.routes[call.route]
        assert self.processes[process]['live']
        call.process = process
        call.stage = 'admitted'
        actual = self.processes[process]['worker']
        self.emit('http_admitted', call=identifier, process=process, actual_worker=actual)
        try:
            if self.clock >= call.deadline:
                raise Rejected('UNKNOWN')
            if call.expected_worker is not None and call.expected_worker != actual:
                raise Rejected('TARGET')
            method = getattr(self, '_admit_' + call.operation, None)
            if method is None:
                raise Rejected('INVALID')
            method(call, actual)
        except Rejected as error:
            self._error(call, error.code)
        return call.stage

    def _admit_prepare(self, call, _actual):
        value = call.args['input']
        lookup, stored = self._read(call, control_key('descriptor', **value['identity']))
        call.desc_io = lookup
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if stored is not None:
            existing = json.loads(stored['body'])
            fixed = {key: existing[key] for key in value}
            if fixed != value:
                raise Rejected('CONFLICT')
            self.emit('prepared_descriptor_verified', call=call.identifier, descriptor_io=lookup,
                      basis_io=basis, body=stored['body'])
            self._finish(call, 'prepared', {'body': stored['body']})
            return
        if marker(head) is not None and marker(head)['identity'] == value['identity']:
            raise Rejected('CORRUPT')
        proof_io, proof = self._read(call, control_key('proof', **value['identity']))
        call.prepare_proof_io = proof_io
        if proof is not None:
            raise Rejected('CORRUPT')
        if pending(head):
            self._finish(call, 'pending', {'marker': marker(head)})
            return
        if not available(head):
            raise Rejected('LIFECYCLE')
        if value['identity']['creator'] != call.principal:
            raise Rejected('DENIED')
        if value['mode'] not in ('takeover', 'activate'):
            raise Rejected('INVALID')
        if len(set(value['nonces'].values())) != 4 or any(not 0 < n <= U64 for n in value['nonces'].values()):
            raise Rejected('INVALID')
        if value['mode'] == 'activate' and (value['target'] != head['owner']['instance'] or head['active']):
            raise Rejected('TARGET')
        if (head['revision'], head['head_serial']) != (value['expected_revision'], value['expected_head_serial']):
            raise Rejected('CONFLICT')
        self._space(head, 2, value['mode'] == 'takeover')
        body = descriptor(head, etag, value)
        self._ready(call, control_key('descriptor', **value['identity']), body,
                    {'if_none_match': True}, basis)

    def _admit_claim(self, call, actual):
        desc = self._read_descriptor(call)
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if actual != desc['target']:
            raise Rejected('TARGET')
        if self._same_plan(head, desc):
            self._terminal_observation(call, head)
            return
        if not available(head) or pending(head):
            raise Rejected('PENDING' if pending(head) else 'LIFECYCLE')
        if base_fields(head, etag) != desc['base']:
            raise Rejected('FENCED')
        if desc['mode'] == 'activate' and (desc['target'] != head['owner']['instance'] or head['active']):
            raise Rejected('TARGET')
        self._space(head, 2, desc['mode'] == 'takeover')
        self._old_proof(call, head)
        next_head = deepcopy(head)
        next_head['revision'] += 1
        next_head['head_serial'] += 1
        next_head['active'], next_head['format'] = False, 8
        if desc['mode'] == 'takeover':
            next_head['owner']['epoch'] += 1
            next_head['owner']['instance'] = desc['target']
        next_head['owner_plan'] = self._new_marker(desc, next_head, 'claim', 'claimed')
        next_head['transition_nonce'] = desc['nonces']['claim']
        self._ready(call, HEAD, next_head, {'if_match': etag}, basis)

    @staticmethod
    def _new_marker(desc, head, admission, phase):
        return {'identity': deepcopy(desc['identity']), 'descriptor_hash': digest(desc),
                'admission': {'kind': admission, 'revision': head['revision'],
                              'head_serial': head['head_serial']},
                'phase': {'kind': phase, 'revision': head['revision'],
                          'head_serial': head['head_serial'],
                          'nonce': desc['nonces'][admission], 'owner': deepcopy(head['owner'])}}

    def _admit_abort(self, call, _actual):
        desc = self._read_descriptor(call)
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if self._same_plan(head, desc):
            if marker(head)['phase']['kind'] in TERMINAL:
                self._terminal_observation(call, head)
                return
            self._space(head)
            next_head = deepcopy(head)
            next_head['revision'] += 1
            next_head['head_serial'] += 1
            self._phase(next_head, desc, 'aborted', 'abort')
        else:
            if not available(head) or pending(head):
                raise Rejected('PENDING' if pending(head) else 'LIFECYCLE')
            if base_fields(head, etag) != desc['base']:
                raise Rejected('FENCED')
            self._space(head, 2)
            self._old_proof(call, head)
            next_head = deepcopy(head)
            next_head['revision'] += 1
            next_head['head_serial'] += 1
            next_head['format'], next_head['active'] = 8, False
            next_head['owner_plan'] = self._new_marker(desc, next_head, 'cancel', 'cancelling')
            next_head['transition_nonce'] = desc['nonces']['cancel']
        self._ready(call, HEAD, next_head, {'if_match': etag}, basis)

    @staticmethod
    def _phase(head, desc, kind, nonce):
        head['active'] = kind == 'active'
        head['transition_nonce'] = desc['nonces'][nonce]
        head['owner_plan']['phase'] = {'kind': kind, 'revision': head['revision'],
            'head_serial': head['head_serial'], 'nonce': desc['nonces'][nonce],
            'owner': deepcopy(head['owner'])}

    def _admit_resume(self, call, actual):
        desc = self._read_descriptor(call)
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if actual != desc['target']:
            raise Rejected('TARGET')
        if not self._same_plan(head, desc):
            raise Rejected('FENCED')
        if marker(head)['phase']['kind'] in TERMINAL:
            self._terminal_observation(call, head)
            return
        if marker(head)['phase']['kind'] != 'claimed':
            raise Rejected('CANCELLED')
        if not available(head) or head['owner']['instance'] != actual:
            raise Rejected('LIFECYCLE')
        self._space(head)
        call.basis = {'head': deepcopy(head), 'etag': etag}
        call.basis_io, call.stage = basis, 'recover'
        self.emit('recovery_started', call=call.identifier, basis_io=basis,
                  descriptor_io=call.desc_io, deadline=call.deadline)

    def recover(self, identifier, corrupt=False):
        call = self.calls[identifier]
        assert call.stage == 'recover' and self.processes[call.process]['live']
        head = call.basis['head']
        try:
            inputs = [head['data_root']] + [entry['result'] for entry in head['requests']]
            reads = []
            for value in inputs:
                io, stored = self._read(call, payload_key(value))
                if stored is None or digest(stored['body']) != value or corrupt:
                    raise Rejected('CORRUPT')
                reads.append(io)
            self.emit('recovery_verified', call=identifier, reads=reads,
                      data_root=head['data_root'], requests=head['requests'], windows=head['windows'])
            barrier, current, etag = self._head(call)
            if current != head or etag != call.basis['etag']:
                raise Rejected('CONFLICT')
            self._authorize(current, call.principal)
            self.emit('recovery_barrier', call=identifier, basis_io=call.basis_io, final_io=barrier)
            next_head = deepcopy(head)
            next_head['revision'] += 1
            next_head['head_serial'] += 1
            self._phase(next_head, call.desc, 'active', 'activate')
            call.recovery = True
            self._ready(call, HEAD, next_head, {'if_match': etag}, call.basis_io)
        except Rejected as error:
            self._error(call, error.code)
        return call.stage

    def _admit_preserve(self, call, _actual):
        basis, head, _etag = self._head(call)
        self._authorize(head, call.principal)
        old = marker(head)
        if old is None or old['phase']['kind'] not in TERMINAL:
            raise Rejected('PENDING')
        call.args['identity'] = deepcopy(old['identity'])
        desc = self._read_descriptor(call)
        if digest(desc) != old['descriptor_hash']:
            raise Rejected('CORRUPT')
        self._ready(call, control_key('proof', **old['identity']), terminal_proof(head),
                    {'if_none_match': True}, basis)

    def _admit_inspect(self, call, _actual):
        desc = self._read_descriptor(call)
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if self._same_plan(head, desc):
            self._terminal_observation(call, head)
            return
        call.basis_io, call.basis = basis, {'head': head, 'etag': etag}
        call.stage = 'inspect_proof'

    def inspect_proof(self, identifier):
        call = self.calls[identifier]
        assert call.stage == 'inspect_proof' and self.processes[call.process]['live']
        try:
            io, proof = self._read(call, control_key('proof', **call.desc['identity']))
            call.proof_io, call.inspected_proof = io, proof
            call.stage = 'inspect_barrier'
        except Rejected as error:
            self._error(call, error.code)

    def inspect_finish(self, identifier):
        call = self.calls[identifier]
        assert call.stage == 'inspect_barrier' and self.processes[call.process]['live']
        try:
            final, head, etag = self._head(call)
            if head != call.basis['head'] or etag != call.basis['etag']:
                raise Rejected('CONFLICT')
            self._authorize(head, call.principal)
            current = marker(head)
            if (current is not None and current['identity'] == call.desc['identity'] and
                    current['descriptor_hash'] != digest(call.desc)):
                raise Rejected('CORRUPT')
            proof = call.inspected_proof
            if proof is not None:
                old = json.loads(proof['body'])['marker']
                if (head['format'] != 8 or marker(head) is None or
                    old['phase']['revision'] >= marker(head)['admission']['revision'] or
                    old['phase']['head_serial'] >= marker(head)['admission']['head_serial']):
                    raise Rejected('CORRUPT')
            self.emit('inspect_barrier', call=identifier, basis_io=call.basis_io,
                      proof_io=call.proof_io, final_io=final)
            if proof is not None:
                self._finish(call, 'observed', {'proof': json.loads(proof['body']),
                    'prepared': {'body': encoded(call.desc), 'descriptor_hash': digest(call.desc)},
                    'current_head': head, 'native_session': False, 'historical_ack': False})
            else:
                self._finish(call, 'observed', {'phase': 'unaccepted_or_fenced',
                    'prepared': {'body': encoded(call.desc), 'descriptor_hash': digest(call.desc)},
                    'current_head': head, 'past_effect': 'unknown', 'native_session': False,
                    'historical_ack': False})
        except Rejected as error:
            self._error(call, error.code)

    def _admit_acl(self, call, _actual):
        self._metadata(call, 'acl')

    def _admit_quota(self, call, _actual):
        self._metadata(call, 'quota')

    def _metadata(self, call, kind):
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if head['storage']['terminal'] or head['lifecycle'] != 'ready':
            raise Rejected('LIFECYCLE')
        self._space(head, 2 if pending(head) else 1)
        next_head = deepcopy(head)
        next_head['revision'] += 1
        next_head['head_serial'] += 1
        next_head['transition_nonce'] = call.args.get('transition_nonce', head['transition_nonce'])
        if kind == 'acl':
            if head['auth_epoch'] == self.maximum:
                raise Rejected('LIMIT')
            next_head['auth_epoch'] += 1
            next_head['admins'] = list(call.args['admins'])
        else:
            manifest, stored = self._read(call, payload_key(head['data_root']))
            if stored is None or digest(stored['body']) != head['data_root']:
                raise Rejected('CORRUPT')
            self.emit('quota_manifest_verified', call=call.identifier, read=manifest, basis_io=basis)
            next_head['quota'] = call.args['quota']
        self._ready(call, HEAD, next_head, {'if_match': etag}, basis)

    def _admit_guard(self, call, _actual):
        _basis, head, _etag = self._head(call)
        name = call.args['entry']
        if name in READERS:
            self._authorize(head, call.principal, read=True)
            self._finish(call, 'read_only', {'entry': name, 'writer': False, 'native_session': False})
            return
        if name not in MUTATORS:
            raise Rejected('INVALID')
        self._authorize(head, call.principal)
        if pending(head):
            raise Rejected('PENDING')
        self._finish(call, 'guard_only', {'entry': name, 'production_effect': 'NOT_MODELLED'})

    def _admit_storage(self, call, _actual):
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if pending(head):
            raise Rejected('PENDING')
        if head['head_serial'] == self.maximum:
            raise Rejected('LIMIT')
        next_head = deepcopy(head)
        next_head['head_serial'] += 1
        value = call.args['value']
        if value == 'technical':
            pass
        elif value in ('copy', 'sweep'):
            if head['storage']['copy'] or head['storage']['sweep'] or head['storage']['terminal']:
                raise Rejected('LIFECYCLE')
            next_head['storage'][value] = True
            next_head['active'] = False
        elif value == 'finish':
            next_head['storage']['copy'] = next_head['storage']['sweep'] = False
        elif value == 'deleted':
            self._space(head, 1, True)
            next_head['revision'] += 1
            next_head['owner']['epoch'] += 1
            next_head['lifecycle'], next_head['active'] = 'deleted', False
        elif value == 'terminal':
            if head['lifecycle'] != 'deleted' or head['storage']['copy'] or head['storage']['sweep']:
                raise Rejected('LIFECYCLE')
            next_head['storage']['terminal'] = True
            next_head['format'] = 8 if marker(head) else 7
        else:
            raise Rejected('INVALID')
        self._ready(call, HEAD, next_head, {'if_match': etag}, basis)

    def _admit_legacy_takeover(self, call, actual):
        self._legacy(call, actual, True)

    def _admit_legacy_activate(self, call, actual):
        self._legacy(call, actual, False)

    def _legacy(self, call, actual, takeover):
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal)
        if head['format'] == 8:
            raise Rejected('LEGACY_DISABLED')
        if not available(head):
            raise Rejected('LIFECYCLE')
        if head['revision'] != call.args['expected_revision']:
            raise Rejected('CONFLICT')
        self._space(head, 1, takeover)
        next_head = deepcopy(head)
        next_head['revision'] += 1
        next_head['head_serial'] += 1
        if takeover:
            next_head['owner'] = {'instance': actual, 'epoch': head['owner']['epoch'] + 1}
            next_head['active'] = False
        else:
            if head['owner']['instance'] != actual:
                raise Rejected('TARGET')
            next_head['active'] = True
        self._ready(call, HEAD, next_head, {'if_match': etag}, basis)

    def _admit_sql(self, call, actual):
        basis, head, etag = self._head(call)
        self._authorize(head, call.principal, read=True)
        if pending(head):
            raise Rejected('PENDING')
        if not available(head) or not head['active'] or head['owner']['instance'] != actual:
            raise Rejected('INACTIVE')
        self._space(head)
        request = call.args['request']
        if request in self.executed:
            raise Rejected('NO_SQL_REPLAY')
        self.executed.add(request)
        result = {'kind': 'result', 'request': request, 'fingerprint': 'input-' + request,
                  'rows': [[1, 'fixed-model-random-' + request]]}
        data = {'kind': 'data', 'counter': 1}
        self.emit('native_sql_executed', call=call.identifier, request=request,
                  input='explicit-original-' + request, result=encoded(result))
        for value in (data, result):
            key = payload_key(digest(value))
            self._budget(call, key)
            io = f'w{len(self.exchanges) + 1}'
            exchange = Exchange(io, call.identifier, key, encoded(value), {'if_none_match': True}, 'sql_dependency')
            self.exchanges[io] = exchange
            self.emit('s3_put_invoked', io=io, call=call.identifier, key=key, body=exchange.body,
                      condition=exchange.condition, deadline=call.deadline, purpose=exchange.purpose)
            self.effect(io)
            self.respond(io)
        next_head = deepcopy(head)
        next_head['revision'] += 1
        next_head['head_serial'] += 1
        next_head['data_root'] = digest(data)
        next_head['windows'].append(request)
        next_head['requests'].append({'id': request, 'fingerprint': result['fingerprint'], 'result': digest(result)})
        self._ready(call, HEAD, next_head, {'if_match': etag}, basis)

    def invoke(self, identifier):
        call = self.calls[identifier]
        assert call.stage == 'ready' and self.processes[call.process]['live']
        try:
            self._budget(call, call.key)
        except Rejected as error:
            self._error(call, error.code)
            return None
        io = f'w{len(self.exchanges) + 1}'
        self.exchanges[io] = Exchange(io, identifier, call.key, call.body, deepcopy(call.condition), 'candidate')
        call.io, call.stage = io, 'invoked'
        self.emit('s3_put_invoked', io=io, call=identifier, key=call.key, body=call.body,
                  condition=call.condition, deadline=call.deadline, purpose='candidate')
        return io

    def effect(self, identifier):
        exchange = self.exchanges[identifier]
        assert exchange.result is None
        prior = self.objects.get(exchange.key)
        allowed = ((exchange.condition == {'if_none_match': True} and prior is None) or
                   (set(exchange.condition) == {'if_match'} and prior is not None and
                    prior['etag'] == exchange.condition['if_match']))
        if allowed:
            self._install(exchange.key, exchange.body)
        exchange.result = {'status': 200 if allowed else 412,
                           'value': deepcopy(self.objects.get(exchange.key))}
        self.emit('s3_put_effect', io=identifier, result=exchange.result)
        return exchange.result['status']

    def respond(self, identifier, delivered=True):
        exchange = self.exchanges[identifier]
        assert exchange.result is not None and not exchange.responded
        exchange.responded = True
        call = self.calls[exchange.call]
        live = self.processes[call.process]['live']
        delivered = bool(delivered and live)
        self.emit('s3_put_response', io=identifier, delivered=delivered,
                  result=exchange.result if delivered else None)
        if not live:
            return
        if not delivered:
            self._finish(call, 'unknown', {'reason': 's3_response_lost'})
            return
        if exchange.purpose == 'sql_dependency':
            return
        try:
            if call.operation in ('prepare', 'preserve'):
                read, value = self._read(call, exchange.key)
                if value is None or value['body'] != exchange.body:
                    raise Rejected('CONFLICT')
                self.emit('immutable_readback_verified', call=call.identifier, write=identifier, read=read)
                self._finish(call, 'prepared' if call.operation == 'prepare' else 'preserved',
                             {'body': exchange.body})
            elif exchange.result['status'] == 412:
                raise Rejected('CONFLICT')
            else:
                if call.operation == 'resume':
                    self.emit('native_publication', call=call.identifier, write=identifier,
                              descriptor_hash=digest(call.desc))
                self._finish(call, 'accepted', {'head': json.loads(exchange.body)})
        except Rejected as error:
            self._error(call, error.code)

    def complete(self, identifier, delivered=True):
        call = self.calls[identifier]
        if call.stage == 'queued':
            self.admit(identifier)
        if call.stage == 'recover':
            self.recover(identifier)
        if call.stage == 'inspect_proof':
            self.inspect_proof(identifier)
        if call.stage == 'inspect_barrier':
            self.inspect_finish(identifier)
        if call.stage == 'ready':
            self.invoke(identifier)
        if call.stage == 'invoked':
            self.effect(call.io)
            self.respond(call.io, delivered)
        return deepcopy(call.outcome)

    def request(self, operation, args=None, **kwargs):
        identifier = self.begin(operation, args, **kwargs)
        self.complete(identifier)
        return identifier

    def prepare(self, operation=101, target=2, mode='takeover', **kwargs):
        head = self.head()
        value = plan_input(operation, target, mode, kwargs.get('principal', 11), head['revision'], head['head_serial'])
        identifier = self.request('prepare', {'input': value}, **kwargs)
        return value['identity'], identifier

    def restore_ref(self, saved_input, observation):
        source = self.calls[observation].outcome
        assert source is not None and source['kind'] in ('prepared', 'observed')
        raw = source['value']['body'] if source['kind'] == 'prepared' else source['value']['prepared']['body']
        desc = json.loads(raw)
        if {key: desc[key] for key in saved_input} != saved_input:
            self.emit('client_ref_restore_rejected', source=observation, saved_input=saved_input)
            raise Rejected('CONFLICT')
        reference = {**desc['identity'], 'descriptor_hash': digest(raw)}
        self.emit('client_ref_restored', source=observation, saved_input=saved_input, reference=reference)
        return reference

    def fault_remove_descriptor(self, reference):
        key = control_key('descriptor', **reference)
        previous = self.objects.pop(key)
        self.emit('explicit_metadata_fault', key=key, previous=previous, value=None,
                  purpose='test missing permanent descriptor; no legal DELETE API')

    def fault_future_proof(self, reference):
        key = control_key('proof', **reference)
        previous = deepcopy(self.objects[key])
        value = json.loads(previous['body'])
        value['marker']['phase']['revision'] = marker(self.head())['admission']['revision']
        value['marker']['phase']['head_serial'] = marker(self.head())['admission']['head_serial']
        self._install(key, encoded(value))
        self.emit('explicit_proof_fault', key=key, previous=previous, value=self.objects[key],
                  purpose='test stable superseded proof counter contradiction')

    def fault_owner_binding(self):
        previous = deepcopy(self.objects[HEAD])
        value = self.head()
        original = value['owner_plan']['descriptor_hash']
        value['owner_plan']['descriptor_hash'] = ('0' if original[0] != '0' else '1') + original[1:]
        self._install(HEAD, encoded(value))
        self.emit('explicit_owner_binding_fault', key=HEAD, previous=previous, value=self.objects[HEAD],
                  purpose='test same immutable operation identity with another HEAD descriptor hash')

    def snapshot(self):
        return {'objects': deepcopy(self.objects), 'processes': deepcopy(self.processes),
                'calls': {name: {'stage': value.stage, 'outcome': value.outcome}
                          for name, value in self.calls.items()},
                'pending': {name: {'effected': value.result is not None, 'responded': value.responded}
                            for name, value in self.exchanges.items()}}

    def trace(self, name):
        events = deepcopy(self.events)
        events.append({'sequence': len(events) + 1, 'event': 'observation_closed',
            'calls': sorted(self.calls),
            'reads': sorted(row['io'] for row in self.events if row['event'] == 's3_get_invoked'),
            'writes': sorted(self.exchanges),
            'pending_effects': sorted(name for name, value in self.exchanges.items() if value.result is None),
            'pending_responses': sorted(name for name, value in self.exchanges.items() if not value.responded),
            'caller_unknowns': sorted(name for name, value in self.calls.items()
                if value.outcome is not None and (value.outcome['kind'] == 'unknown' or
                   value.outcome == {'kind': 'error', 'value': {'code': 'UNKNOWN'}})),
            'objects_sha256': digest(self.objects)})
        return {'schema': 1, 'name': name, 'events': events,
                'summary': {'not_trusted_by_oracle': True, 'final': self.snapshot()}}
