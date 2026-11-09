"""Finite SCAP reclamation protocol model. No production imports or real I/O.

The store evaluates an already-issued request using its original bytes and
condition. Client admission and network application are deliberately separate.
Only the independent oracle is an acceptance authority for the emitted graph.
"""

import copy
import hashlib
import json


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def etag(raw):
    return hashlib.sha256(bytes.fromhex(raw)).hexdigest()


def snapshot(head):
    return {'body': copy.deepcopy(head), 'etag': digest(head)}


class Blocked(Exception):
    pass


class Model:
    def __init__(self, spec, profile):
        self.spec, self.profile = spec, profile
        self.graph, self.bounds = spec['objects'], spec['bounds']

    def closure(self, roots):
        result, remaining = set(), list(roots)
        while remaining:
            item = remaining.pop()
            if item not in result:
                result.add(item)
                remaining.extend(self.graph[item]['edges'])
        return sorted(result)

    def present(self, state, generation, names):
        return all(state['objects'].get(str(generation), {}).get(self.graph[name]['hash']) == self.graph[name]['raw'] for name in names)

    def check(self, condition, reason):
        if not condition:
            raise Blocked(reason)

    def retired(self, head, generation):
        return 1 <= generation <= head['M'] and generation != head['A'] and (
            head['T'] is None or generation != head['T']['target']) and all(pin['generation'] != generation for pin in head['pins'])

    def actions(self, state):
        result = []
        for actor, local in state['actors'].items():
            program = self.profile['programs'][actor]
            if local['stopped'] is not None or local['pc'] == len(program):
                continue
            instruction = program[local['pc']]
            if instruction['op'] == 'observe':
                token = state['tokens'].get(local['last_token'])
                if token is None:
                    result.append({'actor': actor, 'choice': 'step'})
                else:
                    if token['stage'] == 'applied':
                        result.append({'actor': actor, 'choice': 'known'})
                    if token['uncertain'] or token['stage'] == 'discarded':
                        result.append({'actor': actor, 'choice': 'unknown'})
            elif instruction['op'] == 'native_publish':
                token = state['tokens'].get(local['last_token'])
                if token is not None and token['observed'] == 'known' and token['response']['outcome'] == 'APPLIED':
                    result.extend({'actor': actor, 'choice': choice} for choice in ('commit', 'fail'))
                else:
                    result.append({'actor': actor, 'choice': 'step'})
            elif instruction['op'] == 'drain':
                if all(token['stage'] != 'pending' for token in state['tokens'].values() if
                       instruction.get('actor') is None or token['actor'] == instruction['actor']):
                    result.append({'actor': actor, 'choice': 'step'})
            else:
                result.append({'actor': actor, 'choice': 'step'})
        for identifier, token in state['tokens'].items():
            if token['stage'] == 'pending':
                result.append({'network': identifier, 'choice': 'apply'})
                if token['uncertain']:
                    result.append({'network': identifier, 'choice': 'discard'})
        return sorted(result, key=encoded)

    def successor(self, old, action):
        state = copy.deepcopy(old)
        if 'network' in action:
            self.network(state, action['network'], action['choice'])
        else:
            actor = action['actor']
            local = state['actors'][actor]
            instruction = self.profile['programs'][actor][local['pc']]
            try:
                self.client(state, actor, instruction, action['choice'])
            except Blocked as error:
                # Rejection is observable, not an omitted transition or retry.
                state = copy.deepcopy(old)
                state['actors'][actor]['stopped'] = str(error)
            else:
                local['pc'] += 1
        return state

    def request(self, state, actor, kind, body, instruction):
        local = state['actors'][actor]
        identifier = actor + ':' + str(local['pc'])
        self.check(len(state['tokens']) < self.bounds['tokens'], 'TOKEN_LIMIT')
        self.check(identifier not in state['tokens'], 'TOKEN_REUSE')
        state['tokens'][identifier] = {'actor': actor, 'kind': kind, 'request': copy.deepcopy(body),
                                     'uncertain': instruction.get('uncertain', False), 'stage': 'pending',
                                     'response': None, 'observed': None}
        local['last_token'] = identifier
        local['last_result'] = None

    def fresh(self, state, actor):
        view = state['actors'][actor]['view']
        self.check(view is not None, 'HEAD_NOT_OBSERVED')
        self.check(view['etag'] == digest(view['body']), 'HEAD_BODY_ETAG_MISMATCH')
        return view, copy.deepcopy(view['body'])

    def broker(self, state, actor):
        name = self.profile['actors'][actor]['broker']
        self.check(name is not None, 'BROKER_REQUIRED')
        return name, state['brokers'][name]

    def advance(self, head, *, business=False, transition=None):
        self.check(head['serial'] < self.bounds['serial'], 'SERIAL_EXHAUSTED')
        head['serial'] += 1
        if business:
            self.check(head['revision'] < self.bounds['revision'], 'REVISION_EXHAUSTED')
            head['revision'] += 1
            head['transition'] = transition

    def cas(self, state, actor, instruction, kind, view, head):
        self.request(state, actor, 'head_cas', {'kind': kind, 'base': view, 'candidate': head}, instruction)

    def client(self, state, actor, instruction, choice):
        local, role = state['actors'][actor], self.profile['actors'][actor]['role']
        op = instruction['op']
        if op == 'head_get':
            local['view'] = snapshot(state['head'])
            local['head_reads'] += 1
            return
        if op == 'observe':
            self.check(local['last_token'] in state['tokens'], 'NO_ORIGINAL_REQUEST')
            token = state['tokens'][local['last_token']]
            self.check(token['observed'] is None, 'REPEATED_OBSERVATION')
            token['observed'] = choice
            if choice == 'unknown':
                local['last_result'] = {'outcome': 'UNKNOWN'}
                local['caller_unknown'] = True
                return
            response = copy.deepcopy(token['response'])
            local['last_result'] = response
            if token['kind'] == 'head_cas' and token['request']['kind'] in ('pin_add', 'pin_release'):
                _, broker = self.broker(state, actor)
                if response['outcome'] == 'APPLIED':
                    broker['phase'] = 'granted' if token['request']['kind'] == 'pin_add' else 'released'
                    if token['request']['kind'] == 'pin_release':
                        broker['gate'] = False
            if token['kind'] == 'object_get' and response['outcome'] == 'FOUND':
                body = token['request']
                self.check(response['raw'] == self.graph[body['object']]['raw'], 'OBJECT_BYTES_INVALID')
                if body['purpose'] == 'read':
                    _, broker = self.broker(state, actor)
                    self.check(not local['ended'] and actor in broker['guards'] and
                               local['sealed'] is not None and body['protection'] == local['sealed']['pin'] and
                               body['generation'] == local['sealed']['generation'], 'LATE_READ_RESPONSE')
                    local['verified'] = sorted(set(local['verified']) | {body['object']})
                elif body['purpose'] == 'copy_source':
                    self.check(body['protection'] == local['plan'], 'STALE_COPY_RESPONSE')
                    local['copied'][body['object']] = response['raw']
                elif body['purpose'] == 'copy_verify':
                    self.check(body['protection'] == local['plan'], 'STALE_COPY_RESPONSE')
                    local['copy_verified'] = sorted(set(local['copy_verified']) | {body['object']})
            return
        if op in ('pin_add', 'pin_release'):
            view, head = self.fresh(state, actor)
            name, broker = self.broker(state, actor)
            if op == 'pin_add':
                self.check(head['life'] == 'Ready' and head['T'] is None, 'PIN_ADMISSION_BLOCKED')
                self.check(head['acl'] == 'allow', 'READ_DENIED')
                self.check(broker['phase'] == 'new' and broker['gate'], 'ACQUISITION_ALREADY_USED')
                self.check(len(head['pins']) < self.bounds['pins'], 'PIN_LIMIT')
                token = {'grant_serial': head['serial'] + 1, 'generation': head['A'], 'scope': self.spec['scope'],
                         **self.profile['brokers'][name]}
                self.advance(head)
                head['pins'] = sorted(head['pins'] + [token], key=encoded)
                broker['token'], broker['base_serial'], broker['phase'] = token, view['body']['serial'], 'pending'
            else:
                self.check(broker['token'] is not None, 'ORIGINAL_ACQUISITION_REQUIRED')
                self.check(not broker['gate'] and not broker['guards'], 'RELEASE_NOT_QUIESCENT')
                self.check(head['life'] in ('Ready', 'Deleted'), 'RELEASE_LIFECYCLE')
                # An absent pending Add is fenced, never declared settled at its
                # unchanged base serial. This path performs no object read.
                self.advance(head)
                head['pins'] = [pin for pin in head['pins'] if pin != broker['token']]
            self.cas(state, actor, instruction, op, view, head)
            return
        if op == 'inspect_pin':
            view, head = self.fresh(state, actor)
            _, broker = self.broker(state, actor)
            self.check(broker['token'] is not None, 'ORIGINAL_ACQUISITION_REQUIRED')
            if broker['token'] in head['pins']:
                broker['phase'] = 'granted'
            elif head['serial'] > broker['base_serial']:
                self.check(not broker['guards'], 'GUARD_WITHOUT_PIN')
                broker['phase'], broker['gate'] = 'released', False
            else:
                broker['phase'] = 'pending_absent'
            return
        if op == 'guard_begin':
            view, head = self.fresh(state, actor)
            _, broker = self.broker(state, actor)
            self.check(broker['gate'] and broker['phase'] == 'granted', 'LOCAL_GATE_CLOSED')
            self.check(not local['quarantined'], 'QUARANTINED')
            self.check(head['life'] == 'Ready' and head['T'] is None and head['acl'] == 'allow', 'PROTECTED_ADMISSION_BLOCKED')
            self.check(broker['token'] in head['pins'] and broker['token']['generation'] == head['A'], 'FULL_PIN_NOT_OBSERVED')
            self.check(head['serial'] > broker['base_serial'], 'PIN_ADD_REQUIRES_NEW_EXACT_GET')
            self.check(local['sealed'] is None and actor not in broker['guards'], 'SEALED_ATTEMPT_REUSED')
            self.check(len(broker['guards']) < self.bounds['guards'], 'GUARD_LIMIT')
            broker['guards'] = sorted(broker['guards'] + [actor])
            local['sealed'] = {'snapshot': view, 'generation': head['A'], 'pin': copy.deepcopy(broker['token'])}
            return
        if op == 'gate_close':
            _, broker = self.broker(state, actor)
            broker['gate'] = False
            return
        if op == 'guard_end':
            _, broker = self.broker(state, actor)
            self.check(actor in broker['guards'], 'NO_LIVE_GUARD')
            broker['guards'].remove(actor)
            local['ended'] = True
            return
        if op == 'caller_timeout':
            # The caller has stopped waiting. This is deliberately not a model
            # of the worker's absolute deadline or proof of native quiescence.
            local['caller_unknown'] = True
            return
        if op == 'quarantine':
            local['quarantined'] = True
            return
        if op == 'pause':
            local['stopped'] = 'PAUSED'
            return
        if op in ('tick', 'drain'):
            if op == 'tick':
                state['ticks'] += 1
            return
        if op in ('object_get', 'object_put'):
            _, broker = self.broker(state, actor)
            sealed = local['sealed']
            self.check(sealed is not None and actor in broker['guards'] and not local['ended'], 'UNPROTECTED_REMOTE_IO')
            item = instruction['object']
            body = {'generation': sealed['generation'], 'object': item, 'key': self.graph[item]['hash'],
                    'purpose': 'read', 'protection': copy.deepcopy(sealed['pin'])}
            if op == 'object_put':
                body['raw'] = self.graph[item]['raw']
            self.request(state, actor, op, body, instruction)
            return
        if op == 'write':
            _, broker = self.broker(state, actor)
            sealed = local['sealed']
            self.check(role == 'writer' and sealed is not None and actor in broker['guards'] and not local['ended'], 'WRITE_WITHOUT_ORIGINAL_GUARD')
            self.check(not local['quarantined'], 'QUARANTINED')
            self.check(not local['write_dispatched'], 'SQL_REPLAY')
            view, head = sealed['snapshot'], copy.deepcopy(sealed['snapshot']['body'])
            self.check(head['owner'] == self.profile['actors'][actor]['worker'], 'WRONG_OWNER')
            roots = instruction['roots']
            self.check(set(self.closure(roots)) <= set(local['verified']), 'UNVERIFIED_WRITE_CLOSURE')
            self.advance(head, business=True, transition=actor + ':write')
            head['roots'] = roots
            local['write_dispatched'] = True
            self.cas(state, actor, instruction, op, view, head)
            return
        if op == 'native_publish':
            self.check(local['native'] == 'not_started', 'NATIVE_PUBLICATION_REUSED')
            token = state['tokens'][local['last_token']]
            self.check(token['kind'] == 'head_cas' and token['request']['kind'] == 'write' and not local['ended'], 'NATIVE_WITHOUT_ORIGINAL_ATTEMPT')
            if token['observed'] != 'known' or token['response']['outcome'] != 'APPLIED':
                local['native'] = 'aborted'
                local['completion'] = 'UNKNOWN' if token['observed'] == 'unknown' else 'CONFLICT'
            else:
                head = token['request']['candidate']
                local['commit_reference'] = {'token': local['last_token'], 'revision': head['revision'], 'transition': head['transition'],
                                             'roots': copy.deepcopy(head['roots']), 'etag': token['response']['etag']}
                local['native'] = 'committed' if choice == 'commit' else 'failed_after_commit'
                local['completion'] = 'COMMITTED' if choice == 'commit' else 'COMMITTED_BUT_UNAVAILABLE'
            return
        if op == 'ack':
            token = state['tokens'][local['last_token']]
            if local['caller_unknown'] or token['observed'] != 'known' or token['response']['outcome'] != 'APPLIED' or local['native'] != 'committed':
                local['ack'] = 'WITHHELD'
            else:
                self.check(token['kind'] == 'head_cas' and token['request']['kind'] == 'write' and not local['ended'], 'ACK_BEFORE_NATIVE_PUBLICATION')
                local['ack'] = local['last_token']
            return
        if op == 'materialize':
            _, broker = self.broker(state, actor)
            sealed = local['sealed']
            self.check(role == 'reader' and sealed is not None and actor in broker['guards'] and not local['ended'], 'MATERIALIZE_WITHOUT_LIVE_GUARD')
            needed = self.closure(sealed['snapshot']['body']['roots'])
            frames = {}
            for token in state['tokens'].values():
                body, response = token['request'], token['response']
                if (token['actor'] == actor and token['kind'] == 'object_get' and token['observed'] == 'known' and response['outcome'] == 'FOUND' and
                    body['purpose'] == 'read' and body['generation'] == sealed['generation'] and body['protection'] == sealed['pin'] and body['object'] in needed):
                    frames[body['key']] = response['raw']
            self.check(set(frames) == {self.graph[name]['hash'] for name in needed}, 'READ_CLOSURE_NOT_MATERIALIZED')
            local['materialized'] = {'snapshot': copy.deepcopy(sealed['snapshot']), 'generation': sealed['generation'], 'frames': frames}
            return
        if op == 'read_return':
            self.check(role == 'reader' and local['materialized'] is not None, 'READ_RETURN_UNMATERIALIZED')
            local['read_result'] = {'outcome': 'WITHHELD'} if local['caller_unknown'] else {
                'outcome': 'SUCCESS', 'snapshot_etag': local['materialized']['snapshot']['etag'],
                'object_hashes': sorted(local['materialized']['frames'])}
            return
        if op in ('acl', 'takeover', 'quota', 'delete', 'complete'):
            self.check(role == 'admin', 'ADMIN_REQUIRED')
            view, head = self.fresh(state, actor)
            if op == 'complete':
                self.check(head['life'] == 'Provisioning' and head['revision'] == 1 and head['serial'] == 1, 'PROVISIONING_ORIGINAL_BARRIER')
                head['life'] = 'Ready'
            else:
                self.check(head['life'] == 'Ready', 'ADMIN_LIFECYCLE')
                if op in ('takeover', 'quota'):
                    self.check(head['T'] is None, 'ROOT_CONTROL_FROZEN')
                if op == 'acl': head['acl'] = instruction['value']
                if op == 'takeover': head['owner'] = instruction['value']
                if op == 'quota': head['quota'] = instruction['value']
                if op == 'delete': head['life'], head['T'] = 'Deleted', None
            self.advance(head, business=True, transition=actor + ':' + str(local['pc']))
            self.cas(state, actor, instruction, op, view, head)
            return
        if op in ('freeze', 'abort', 'seal', 'promote'):
            self.check(role == 'gc', 'GC_CAPABILITY_REQUIRED')
            view, head = self.fresh(state, actor)
            self.check(head['life'] == 'Ready', 'GC_LIFECYCLE')
            if op == 'freeze':
                self.check(head['T'] is None and not head['pins'], 'GC_BLOCKED')
                self.check(head['M'] < self.bounds['generation'], 'GENERATION_EXHAUSTED')
                head['M'] += 1
                head['T'] = {'id': instruction['plan'], 'source': head['A'], 'target': head['M'],
                             'roots': copy.deepcopy(head['roots']), 'phase': 'copying'}
            else:
                self.check(head['T'] is not None and head['T']['id'] == instruction['plan'], 'STALE_PLAN')
                if op == 'abort':
                    head['T'] = None
                else:
                    plan = local['plan']
                    self.check(plan is not None and plan['id'] == head['T']['id'] and
                               plan['source'] == head['A'] and plan['target'] == head['T']['target'] and
                               plan['roots'] == head['roots'] == head['T']['roots'], 'STALE_PLAN')
                    self.check(not head['pins'], 'GC_BLOCKED')
                    self.check(set(self.closure(plan['roots'])) <= set(local['copy_verified']), 'INCOMPLETE_COPY')
                    if op == 'seal':
                        self.check(head['T']['phase'] == 'copying', 'WRONG_COPY_PHASE')
                        head['T']['phase'] = 'sealed'
                    else:
                        self.check(head['T']['phase'] == 'sealed', 'WRONG_COPY_PHASE')
                        head['A'], head['T'] = head['T']['target'], None
            self.advance(head)
            self.cas(state, actor, instruction, op, view, head)
            return
        if op == 'capture_plan':
            _, head = self.fresh(state, actor)
            self.check(role == 'gc' and head['life'] == 'Ready' and head['T'] is not None and head['T']['id'] == instruction['plan'], 'STALE_PLAN')
            local['plan'] = copy.deepcopy(head['T'])
            local['copied'], local['copy_verified'] = {}, []
            return
        if op in ('copy_get', 'copy_put', 'copy_verify'):
            plan = local['plan']
            self.check(role == 'gc' and plan is not None, 'PLAN_NOT_CAPTURED')
            item = instruction['object']
            self.check(item in self.closure(plan['roots']), 'COPY_OUTSIDE_CLOSURE')
            body = {'generation': plan['source'] if op == 'copy_get' else plan['target'], 'object': item,
                    'key': self.graph[item]['hash'], 'purpose': 'copy_source' if op == 'copy_get' else 'copy_verify',
                    'protection': copy.deepcopy(plan)}
            if op == 'copy_put':
                self.check(item in local['copied'], 'COPY_SOURCE_NOT_OBSERVED')
                body['raw'] = local['copied'][item]
            self.request(state, actor, 'object_put' if op == 'copy_put' else 'object_get', body, instruction)
            return
        if op in ('sweep_open', 'sweep_resume'):
            _, head = self.fresh(state, actor)
            self.check(role == 'gc' and head['life'] == 'Ready', 'GC_LIFECYCLE')
            generation, identity = instruction['generation'], instruction['plan']
            self.check(self.retired(head, generation), 'NOT_PERMANENTLY_RETIRED')
            if op == 'sweep_open':
                self.check(identity not in state['checkpoints'] and len(state['checkpoints']) < self.bounds['checkpoints'], 'CHECKPOINT_LIMIT_OR_REUSE')
                # Abstract atomic, durable create of a bounded descriptor. The
                # model does not claim a production checkpoint wire format.
                state['checkpoints'][identity] = {'scope': self.spec['scope'], 'generation': generation,
                                                 'plan': identity, 'cursor': 0, 'batch': None, 'round': 'open'}
            checkpoint = state['checkpoints'].get(identity)
            self.check(checkpoint is not None and checkpoint['scope'] == self.spec['scope'] and
                       checkpoint['generation'] == generation and checkpoint['plan'] == identity, 'STALE_CURSOR')
            local['sweep'] = copy.deepcopy(checkpoint)
            return
        if op == 'list':
            self.check(local['sweep'] is not None, 'SWEEP_NOT_CAPTURED')
            self.request(state, actor, 'list', {'generation': local['sweep']['generation'], 'plan': local['sweep']['plan']}, instruction)
            return
        if op == 'candidate_get':
            self.check(local['sweep'] is not None, 'SWEEP_NOT_CAPTURED')
            result = local['last_result']
            self.check(result is not None and result['outcome'] == 'LIST' and self.graph[instruction['object']]['hash'] in result['objects'], 'CANDIDATE_NOT_LISTED')
            item = instruction['object']
            self.request(state, actor, 'object_get', {'generation': local['sweep']['generation'], 'object': item,
                         'key': self.graph[item]['hash'], 'purpose': 'delete_candidate', 'protection': local['sweep']['plan']}, instruction)
            return
        if op == 'persist_batch':
            sweep = local['sweep']
            self.check(sweep is not None and sweep == state['checkpoints'].get(sweep['plan']), 'STALE_CURSOR')
            original = state['tokens'][local['last_token']]
            self.check(original['kind'] == 'object_get' and original['request']['purpose'] == 'delete_candidate' and
                       original['observed'] == 'known' and original['response']['outcome'] == 'FOUND', 'CANDIDATE_NOT_EXACT_GET')
            batch = {'object': original['request']['object'], 'key': original['request']['key'], 'etag': original['response']['etag']}
            checkpoint = copy.deepcopy(sweep); checkpoint['batch'] = batch; checkpoint['cursor'] += 1
            self.check(checkpoint['cursor'] <= self.bounds['cursor'], 'CURSOR_EXHAUSTED')
            state['checkpoints'][sweep['plan']] = checkpoint
            local['sweep'] = copy.deepcopy(checkpoint)
            return
        if op == 'delete_object':
            _, head = self.fresh(state, actor)
            sweep = local['sweep']
            self.check(role == 'gc' and head['life'] == 'Ready', 'GC_LIFECYCLE')
            self.check(sweep is not None and sweep == state['checkpoints'].get(sweep['plan']) and sweep['batch'] is not None, 'STALE_CURSOR')
            self.check(self.retired(head, sweep['generation']), 'NOT_PERMANENTLY_RETIRED')
            self.request(state, actor, 'object_delete', {'generation': sweep['generation'], 'plan': sweep['plan'],
                         'scope': self.spec['scope'], 'cursor': sweep['cursor'], **sweep['batch']}, instruction)
            return
        if op == 'record_round':
            sweep, result = local['sweep'], local['last_result']
            self.check(sweep is not None and sweep == state['checkpoints'].get(sweep['plan']), 'STALE_CURSOR')
            self.check(result is not None and result['outcome'] == 'LIST', 'ROUND_NOT_OBSERVED')
            checkpoint = copy.deepcopy(sweep)
            checkpoint['round'] = 'observed_empty' if not result['objects'] else 'observed_nonempty'
            state['checkpoints'][sweep['plan']] = checkpoint; local['sweep'] = copy.deepcopy(checkpoint)
            return
        raise AssertionError('unknown frozen instruction ' + op)

    def network(self, state, identifier, choice):
        token = state['tokens'][identifier]
        if choice == 'discard':
            token['stage'] = 'discarded'
            return
        request, kind = token['request'], token['kind']
        if kind == 'head_cas':
            # This is the entire backend condition. ACL/phase/guard checks do
            # not run again after the request was already dispatched.
            if request['base']['etag'] == digest(state['head']):
                old = state['head']
                state['head'] = copy.deepcopy(request['candidate'])
                before = set(range(1, old['M'] + 1)) - {old['A']} - ({old['T']['target']} if old['T'] else set())
                new = state['head']
                after = set(range(1, new['M'] + 1)) - {new['A']} - ({new['T']['target']} if new['T'] else set())
                state['retired'] = sorted(set(state['retired']) | before | after)
                response = {'outcome': 'APPLIED', 'etag': digest(state['head'])}
            else:
                response = {'outcome': 'CONFLICT'}
        elif kind == 'list':
            response = {'outcome': 'LIST', 'objects': sorted(state['objects'].get(str(request['generation']), {}))}
        else:
            generation, item = str(request['generation']), request['key']
            objects = state['objects'].get(generation, {})
            old = objects.get(item)
            if kind == 'object_get':
                response = {'outcome': 'MISSING'} if old is None else {'outcome': 'FOUND', 'raw': old, 'etag': etag(old)}
            elif kind == 'object_put':
                if old is None:
                    state['objects'].setdefault(generation, {})[item] = request['raw']
                    response = {'outcome': 'CREATED', 'etag': etag(request['raw'])}
                else:
                    response = {'outcome': 'EXISTS', 'etag': etag(old)}
            elif kind == 'object_delete':
                if old is None:
                    response = {'outcome': 'MISSING'}
                elif etag(old) != request['etag']:
                    response = {'outcome': 'CONFLICT'}
                else:
                    del objects[item]
                    if not objects:
                        state['objects'].pop(generation, None)
                    response = {'outcome': 'APPLIED'}
            else:
                raise AssertionError('unknown network request ' + kind)
        token['stage'], token['response'] = 'applied', response
