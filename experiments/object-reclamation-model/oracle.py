"""Independent transition/closure oracle for the frozen finite model inputs.

This file imports neither model.py nor run.py nor production code. It checks
original actions and complete state deltas, not the producer's verdict/counts.
"""

import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import tarfile


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def body_tag(head):
    return sha(canonical(head))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def same(actual, expected, reason):
    if type(actual) is type(expected) and isinstance(actual, (set, bytes)):
        require(actual == expected, reason)
    else:
        require(type(actual) is type(expected) and canonical(actual) == canonical(expected), reason)


def parse(raw):
    def pairs(values):
        result = {}
        for name, value in values:
            require(name not in result, 'duplicate JSON field')
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


class Refusal(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


class Rules:
    def __init__(self, inputs, profile):
        self.inputs, self.profile = inputs, profile
        self.objects, self.limits = inputs['objects'], inputs['bounds']

    def reachable_objects(self, roots):
        visited = set()
        def visit(name):
            require(name in self.objects, 'unknown content graph reference')
            if name not in visited:
                visited.add(name)
                for child in self.objects[name]['edges']:
                    visit(child)
        for name in roots:
            visit(name)
        return visited

    def complete_at(self, state, generation, roots):
        values = state['objects'].get(str(generation), {})
        return all(values.get(self.objects[name]['hash']) == self.objects[name]['raw'] for name in self.reachable_objects(roots))

    def retired(self, head, generation):
        return generation in range(1, head['M'] + 1) and generation != head['A'] and (
            head['T'] is None or generation != head['T']['target']) and not any(pin['generation'] == generation for pin in head['pins'])

    def check_state(self, state):
        same(set(state), {'head', 'objects', 'brokers', 'actors', 'tokens', 'checkpoints', 'retired', 'ticks'}, 'state fields changed')
        h = state['head']
        same(set(h), {'serial', 'revision', 'transition', 'A', 'M', 'T', 'roots', 'acl', 'owner', 'quota', 'life', 'pins'}, 'HEAD fields changed')
        for field, maximum in (('serial', self.limits['serial']), ('revision', self.limits['revision']), ('M', self.limits['generation'])):
            require(type(h[field]) is int and 1 <= h[field] <= maximum, 'bounded HEAD counter invalid: ' + field)
        require(h['serial'] >= h['revision'] and type(h['A']) is int and 1 <= h['A'] <= h['M'], 'serial/business or generation order')
        require(h['life'] in ('Provisioning', 'Ready', 'Deleted') and h['acl'] in ('allow', 'deny'), 'lifecycle/ACL invalid')
        require(type(h['quota']) is int and h['quota'] >= 0 and isinstance(h['owner'], str), 'business metadata invalid')
        require(isinstance(h['transition'], str) and h['transition'], 'missing original business transition')
        require(h['roots'] and len(set(h['roots'])) == len(h['roots']), 'root identity invalid')
        require(self.complete_at(state, h['A'], h['roots']), 'active root complete raw-byte closure missing')
        staging = h['T']
        if staging is not None:
            same(set(staging), {'id', 'source', 'target', 'roots', 'phase'}, 'staging fields changed')
            require(h['life'] == 'Ready' and not h['pins'] and staging['source'] == h['A'] and
                    1 <= staging['target'] <= h['M'] and staging['target'] != h['A'] and
                    staging['roots'] == h['roots'] and staging['phase'] in ('copying', 'sealed'), 'invalid freeze/pin/lifecycle combination')
            if staging['phase'] == 'sealed':
                require(self.complete_at(state, staging['target'], staging['roots']), 'sealed target complete raw-byte closure missing')
        retired = sorted(set(range(1, h['M'] + 1)) - {h['A']} - ({staging['target']} if staging else set()))
        same(state['retired'], retired, 'retirement was reused or lost')
        require(len(h['pins']) <= self.limits['pins'] and h['pins'] == sorted(h['pins'], key=canonical), 'pin bound/order invalid')
        require(len({canonical(pin) for pin in h['pins']}) == len(h['pins']), 'duplicate full pin token')
        require(len({pin['grant_serial'] for pin in h['pins']}) == len(h['pins']), 'two accepted pins share grant serial')
        for pin in h['pins']:
            same(set(pin), {'grant_serial', 'generation', 'scope', 'worker', 'process', 'broker', 'acquisition'}, 'pin identity fields changed')
            require(pin['scope'] == self.inputs['scope'] and pin['generation'] == h['A'] and
                    1 < pin['grant_serial'] <= h['serial'] and h['life'] != 'Provisioning', 'pin scope/generation/admission invalid')
        by_key = {value['hash']: value['raw'] for value in self.objects.values()}
        for generation, values in state['objects'].items():
            require(re.fullmatch(r'[1-9][0-9]*', generation) and int(generation) <= h['M'] and values, 'physical object generation invalid')
            for key, raw in values.items():
                require(key in by_key and raw == by_key[key] and sha(bytes.fromhex(raw)) == key, 'physical key/raw hash identity changed')
        same(set(state['actors']), set(self.profile['actors']), 'actor inventory changed')
        same(set(state['brokers']), set(self.profile['brokers']), 'broker inventory changed')
        for broker_name, broker in state['brokers'].items():
            require(broker['phase'] in ('new', 'pending', 'pending_absent', 'granted', 'released') and type(broker['gate']) is bool, 'broker phase invalid')
            guards = broker['guards']
            require(guards == sorted(set(guards)) and len(guards) <= self.limits['guards'], 'guard bound/order invalid')
            if broker['token'] is not None:
                token = broker['token']
                same({key: token[key] for key in ('worker', 'process', 'broker', 'acquisition')}, self.profile['brokers'][broker_name], 'broker full acquisition identity changed')
                require(token['scope'] == self.inputs['scope'] and token['grant_serial'] == broker['base_serial'] + 1, 'grant original base changed')
            for actor in guards:
                require(self.profile['actors'][actor]['broker'] == broker_name, 'guard joined another broker')
                local = state['actors'][actor]
                require(not local['ended'] and local['sealed'] is not None and local['sealed']['pin'] == broker['token'] and
                        broker['token'] in h['pins'], 'live guard lost its nonrevokable full pin')
                require(self.complete_at(state, local['sealed']['generation'], local['sealed']['snapshot']['body']['roots']), 'pinned reader closure deleted')
        for name, local in state['actors'].items():
            require(type(local['pc']) is int and 0 <= local['pc'] <= len(self.profile['programs'][name]), 'actor program counter invalid')
            if local['view'] is not None:
                same(local['view']['etag'], body_tag(local['view']['body']), 'exact HEAD body/ETag mismatch')
            if local['sealed'] is not None:
                sealed = local['sealed']
                same(sealed['snapshot']['etag'], body_tag(sealed['snapshot']['body']), 'sealed exact body/ETag mismatch')
                require(sealed['generation'] == sealed['snapshot']['body']['A'] and sealed['pin'] in sealed['snapshot']['body']['pins'], 'sealed generation/pin context changed')
            require(local['verified'] == sorted(set(local['verified'])) and local['copy_verified'] == sorted(set(local['copy_verified'])), 'verification set invalid')
            if local['plan'] is None:
                require(not local['copied'] and not local['copy_verified'], 'copy evidence without captured plan')
            else:
                require(set(local['copied']) <= self.reachable_objects(local['plan']['roots']) and
                        set(local['copy_verified']) <= self.reachable_objects(local['plan']['roots']), 'copy evidence outside captured root set')
                for item, raw in local['copied'].items():
                    same(raw, self.objects[item]['raw'], 'raw copy was re-encoded')
                if staging is not None and all(local['plan'][field] == staging[field] for field in ('id', 'source', 'target', 'roots')):
                    values = state['objects'].get(str(staging['target']), {})
                    require(all(values.get(self.objects[item]['hash']) == self.objects[item]['raw'] for item in local['copy_verified']), 'verification reused across target generations')
            if local['ack'] not in (None, 'WITHHELD'):
                token = state['tokens'][local['ack']]
                require(not local['caller_unknown'] and token['observed'] == 'known' and token['stage'] == 'applied' and
                        token['kind'] == 'head_cas' and token['request']['kind'] == 'write' and token['response']['outcome'] == 'APPLIED' and
                        local['native'] == 'committed', 'false SQL ACK after UNKNOWN or failed native publication')
            require(local['native'] in ('not_started', 'aborted', 'committed', 'failed_after_commit'), 'native outcome invalid')
            if local['commit_reference'] is not None:
                reference = local['commit_reference']; original = state['tokens'][reference['token']]
                require(original['kind'] == 'head_cas' and original['request']['kind'] == 'write' and original['observed'] == 'known' and
                        original['response']['outcome'] == 'APPLIED', 'committed reference lacks original known CAS')
                candidate = original['request']['candidate']
                same(reference, {'token': reference['token'], 'revision': candidate['revision'], 'transition': candidate['transition'],
                                 'roots': candidate['roots'], 'etag': original['response']['etag']}, 'original committed reference changed')
            if local['native'] == 'failed_after_commit':
                require(local['completion'] == 'COMMITTED_BUT_UNAVAILABLE' and local['commit_reference'] is not None and local['ack'] in (None, 'WITHHELD'), 'native failure erased durable commitment')
            materialized = local['materialized']
            if materialized is not None:
                require(local['sealed'] is not None, 'materialization has no original admission')
                same(materialized['snapshot'], local['sealed']['snapshot'], 'materialized read rebound original authorized snapshot')
                same(materialized['generation'], local['sealed']['generation'], 'materialized read rebound physical generation')
                required = {self.objects[item]['hash']: self.objects[item]['raw'] for item in self.reachable_objects(materialized['snapshot']['body']['roots'])}
                same(materialized['frames'], required, 'materialized read lacks complete original raw bytes')
                observed = {}
                for token in state['tokens'].values():
                    request, response = token['request'], token['response']
                    if (token['actor'] == name and token['kind'] == 'object_get' and token['observed'] == 'known' and response['outcome'] == 'FOUND' and
                        request['purpose'] == 'read' and request['generation'] == materialized['generation'] and request['protection'] == local['sealed']['pin']):
                        observed[request['key']] = response['raw']
                require(all(observed.get(key) == raw for key, raw in required.items()), 'read materialization invented unobserved bytes')
            if local['read_result'] is not None:
                require(materialized is not None, 'reader returned before complete materialization')
                expected = {'outcome': 'WITHHELD'} if local['caller_unknown'] else {
                    'outcome': 'SUCCESS', 'snapshot_etag': materialized['snapshot']['etag'], 'object_hashes': sorted(materialized['frames'])}
                same(local['read_result'], expected, 'reader success outlived caller or changed materialized bytes')
        require(len(state['tokens']) <= self.limits['tokens'] and len(state['checkpoints']) <= self.limits['checkpoints'], 'token/checkpoint bound exceeded')
        for token in state['tokens'].values():
            require(token['stage'] in ('pending', 'applied', 'discarded') and token['observed'] in (None, 'known', 'unknown'), 'network/client knowledge invalid')
            require((token['response'] is not None) == (token['stage'] == 'applied'), 'response invented before application')
            require(token['observed'] != 'known' or token['stage'] == 'applied', 'UNKNOWN represented as known backend outcome')
            request = token['request']
            if token['kind'] == 'head_cas':
                same(request['base']['etag'], body_tag(request['base']['body']), 'original candidate body/ETag mismatch')
            elif token['kind'] != 'list':
                require(request['object'] in self.objects and request['key'] == self.objects[request['object']]['hash'], 'original immutable key changed')
        for name, checkpoint in state['checkpoints'].items():
            require(name == checkpoint['plan'] and checkpoint['scope'] == self.inputs['scope'] and
                    checkpoint['generation'] in state['retired'] and checkpoint['round'] in ('open', 'observed_empty', 'observed_nonempty') and
                    type(checkpoint['cursor']) is int and 0 <= checkpoint['cursor'] <= self.limits['cursor'], 'checkpoint/cursor/permanent-absence claim invalid')
        require(type(state['ticks']) is int and state['ticks'] >= 0, 'model clock invalid')

    def enabled(self, state):
        actions = []
        for actor in sorted(self.profile['programs']):
            local, program = state['actors'][actor], self.profile['programs'][actor]
            if local['stopped'] is not None or local['pc'] >= len(program):
                continue
            instruction = program[local['pc']]
            if instruction['op'] == 'native_publish':
                token = state['tokens'].get(local['last_token'])
                choices = ('commit', 'fail') if token is not None and token['observed'] == 'known' and token['response']['outcome'] == 'APPLIED' else ('step',)
                actions.extend({'actor': actor, 'choice': choice} for choice in choices)
                continue
            if instruction['op'] != 'observe':
                pending = instruction['op'] == 'drain' and any(token['stage'] == 'pending' and
                          (instruction.get('actor') is None or token['actor'] == instruction['actor']) for token in state['tokens'].values())
                if not pending:
                    actions.append({'actor': actor, 'choice': 'step'})
                continue
            token = state['tokens'].get(local['last_token'])
            if token is None:
                actions.append({'actor': actor, 'choice': 'step'})
            else:
                if token['stage'] == 'applied': actions.append({'actor': actor, 'choice': 'known'})
                if token['uncertain'] or token['stage'] == 'discarded': actions.append({'actor': actor, 'choice': 'unknown'})
        for identifier, token in state['tokens'].items():
            if token['stage'] == 'pending':
                actions.append({'network': identifier, 'choice': 'apply'})
                if token['uncertain']: actions.append({'network': identifier, 'choice': 'discard'})
        return {canonical(value) for value in actions}

    def original_view(self, local):
        need(local['view'] is not None, 'HEAD_NOT_OBSERVED')
        need(local['view']['etag'] == body_tag(local['view']['body']), 'HEAD_BODY_ETAG_MISMATCH')
        return local['view']

    def owned_broker(self, state, actor):
        name = self.profile['actors'][actor]['broker']
        need(name is not None, 'BROKER_REQUIRED')
        return name, state['brokers'][name]

    def issue(self, state, actor, instruction, kind, request):
        local = state['actors'][actor]; identity = actor + ':' + str(local['pc'])
        need(len(state['tokens']) < self.limits['tokens'], 'TOKEN_LIMIT')
        need(identity not in state['tokens'], 'TOKEN_REUSE')
        state['tokens'][identity] = {'actor': actor, 'kind': kind, 'request': copy.deepcopy(request),
                                    'uncertain': instruction.get('uncertain', False), 'stage': 'pending', 'response': None, 'observed': None}
        local['last_token'], local['last_result'] = identity, None

    def increment(self, h, business, identity):
        need(h['serial'] != self.limits['serial'], 'SERIAL_EXHAUSTED')
        h['serial'] += 1
        if business:
            need(h['revision'] != self.limits['revision'], 'REVISION_EXHAUSTED')
            h['revision'] += 1; h['transition'] = identity

    def head_dispatch(self, state, actor, instruction):
        local = state['actors'][actor]; op = instruction['op']; role = self.profile['actors'][actor]['role']
        view = self.original_view(local) if op != 'write' else None
        if op == 'write':
            _, broker = self.owned_broker(state, actor)
            sealed = local['sealed']
            need(role == 'writer' and sealed is not None and actor in broker['guards'] and not local['ended'], 'WRITE_WITHOUT_ORIGINAL_GUARD')
            need(not local['quarantined'], 'QUARANTINED')
            need(not local['write_dispatched'], 'SQL_REPLAY')
            view = sealed['snapshot']
        h = copy.deepcopy(view['body']); business = op in ('write', 'acl', 'takeover', 'quota', 'delete', 'complete')
        identity = actor + (':write' if op == 'write' else ':' + str(local['pc']))
        if op == 'pin_add':
            name, broker = self.owned_broker(state, actor)
            need(h['life'] == 'Ready' and h['T'] is None, 'PIN_ADMISSION_BLOCKED')
            need(h['acl'] == 'allow', 'READ_DENIED')
            need(broker['phase'] == 'new' and broker['gate'], 'ACQUISITION_ALREADY_USED')
            need(len(h['pins']) < self.limits['pins'], 'PIN_LIMIT')
            pin = dict(self.profile['brokers'][name], grant_serial=h['serial'] + 1, generation=h['A'], scope=self.inputs['scope'])
            h['pins'] = sorted(h['pins'] + [pin], key=canonical)
            broker.update(token=pin, base_serial=view['body']['serial'], phase='pending')
        elif op == 'pin_release':
            _, broker = self.owned_broker(state, actor)
            need(broker['token'] is not None, 'ORIGINAL_ACQUISITION_REQUIRED')
            need(not broker['gate'] and not broker['guards'], 'RELEASE_NOT_QUIESCENT')
            need(h['life'] in ('Ready', 'Deleted'), 'RELEASE_LIFECYCLE')
            h['pins'] = [pin for pin in h['pins'] if pin != broker['token']]
        elif op == 'write':
            need(h['owner'] == self.profile['actors'][actor]['worker'], 'WRONG_OWNER')
            need(self.reachable_objects(instruction['roots']) <= set(local['verified']), 'UNVERIFIED_WRITE_CLOSURE')
            h['roots'] = instruction['roots']; local['write_dispatched'] = True
        elif op in ('acl', 'takeover', 'quota', 'delete', 'complete'):
            need(role == 'admin', 'ADMIN_REQUIRED')
            if op == 'complete':
                need(h['life'] == 'Provisioning' and (h['serial'], h['revision']) == (1, 1), 'PROVISIONING_ORIGINAL_BARRIER')
                h['life'] = 'Ready'
            else:
                need(h['life'] == 'Ready', 'ADMIN_LIFECYCLE')
                if op in ('takeover', 'quota'): need(h['T'] is None, 'ROOT_CONTROL_FROZEN')
                if op == 'acl': h['acl'] = instruction['value']
                elif op == 'quota': h['quota'] = instruction['value']
                elif op == 'takeover': h['owner'] = instruction['value']
                else: h.update(life='Deleted', T=None)
        else:
            need(role == 'gc', 'GC_CAPABILITY_REQUIRED')
            need(h['life'] == 'Ready', 'GC_LIFECYCLE')
            if op == 'freeze':
                need(h['T'] is None and not h['pins'], 'GC_BLOCKED')
                need(h['M'] < self.limits['generation'], 'GENERATION_EXHAUSTED')
                h['M'] += 1
                h['T'] = {'id': instruction['plan'], 'source': h['A'], 'target': h['M'], 'roots': copy.deepcopy(h['roots']), 'phase': 'copying'}
            else:
                need(h['T'] is not None and h['T']['id'] == instruction['plan'], 'STALE_PLAN')
                if op == 'abort': h['T'] = None
                else:
                    p = local['plan']
                    need(p is not None and p['id'] == h['T']['id'] and p['source'] == h['A'] and
                         p['target'] == h['T']['target'] and p['roots'] == h['roots'] == h['T']['roots'], 'STALE_PLAN')
                    need(not h['pins'], 'GC_BLOCKED')
                    need(self.reachable_objects(p['roots']) <= set(local['copy_verified']), 'INCOMPLETE_COPY')
                    need(h['T']['phase'] == ('copying' if op == 'seal' else 'sealed'), 'WRONG_COPY_PHASE')
                    if op == 'seal': h['T']['phase'] = 'sealed'
                    else: h.update(A=h['T']['target'], T=None)
        self.increment(h, business, identity)
        self.issue(state, actor, instruction, 'head_cas', {'kind': op, 'base': view, 'candidate': h})

    def observe(self, state, actor, choice):
        local = state['actors'][actor]
        need(local['last_token'] in state['tokens'], 'NO_ORIGINAL_REQUEST')
        token = state['tokens'][local['last_token']]
        need(token['observed'] is None, 'REPEATED_OBSERVATION')
        token['observed'] = choice
        if choice == 'unknown':
            local['last_result'], local['caller_unknown'] = {'outcome': 'UNKNOWN'}, True
            return
        response, request = token['response'], token['request']
        local['last_result'] = copy.deepcopy(response)
        if token['kind'] == 'head_cas' and request['kind'] in ('pin_add', 'pin_release') and response['outcome'] == 'APPLIED':
            _, broker = self.owned_broker(state, actor)
            broker['phase'] = 'granted' if request['kind'] == 'pin_add' else 'released'
            if request['kind'] == 'pin_release': broker['gate'] = False
        if token['kind'] != 'object_get' or response['outcome'] != 'FOUND': return
        need(response['raw'] == self.objects[request['object']]['raw'], 'OBJECT_BYTES_INVALID')
        purpose = request['purpose']
        if purpose == 'read':
            _, broker = self.owned_broker(state, actor)
            need(not local['ended'] and actor in broker['guards'] and local['sealed'] is not None and
                 request['protection'] == local['sealed']['pin'] and request['generation'] == local['sealed']['generation'], 'LATE_READ_RESPONSE')
            local['verified'] = sorted(set(local['verified']) | {request['object']})
        elif purpose in ('copy_source', 'copy_verify'):
            need(request['protection'] == local['plan'], 'STALE_COPY_RESPONSE')
            if purpose == 'copy_source': local['copied'][request['object']] = response['raw']
            else: local['copy_verified'] = sorted(set(local['copy_verified']) | {request['object']})

    def local_step(self, state, actor, instruction, choice):
        local = state['actors'][actor]; op = instruction['op']; role = self.profile['actors'][actor]['role']
        if op in ('pin_add', 'pin_release', 'write', 'acl', 'takeover', 'quota', 'delete', 'complete', 'freeze', 'abort', 'seal', 'promote'):
            self.head_dispatch(state, actor, instruction); return
        if op == 'head_get':
            local['view'] = {'body': copy.deepcopy(state['head']), 'etag': body_tag(state['head'])}; local['head_reads'] += 1; return
        if op == 'observe': self.observe(state, actor, choice); return
        if op == 'inspect_pin':
            h = self.original_view(local)['body']; _, broker = self.owned_broker(state, actor)
            need(broker['token'] is not None, 'ORIGINAL_ACQUISITION_REQUIRED')
            if broker['token'] in h['pins']: broker['phase'] = 'granted'
            elif h['serial'] > broker['base_serial']:
                need(not broker['guards'], 'GUARD_WITHOUT_PIN'); broker.update(phase='released', gate=False)
            else: broker['phase'] = 'pending_absent'
            return
        if op == 'guard_begin':
            view = self.original_view(local); h = view['body']; _, broker = self.owned_broker(state, actor)
            need(broker['gate'] and broker['phase'] == 'granted', 'LOCAL_GATE_CLOSED')
            need(not local['quarantined'], 'QUARANTINED')
            need(h['life'] == 'Ready' and h['T'] is None and h['acl'] == 'allow', 'PROTECTED_ADMISSION_BLOCKED')
            need(broker['token'] in h['pins'] and broker['token']['generation'] == h['A'], 'FULL_PIN_NOT_OBSERVED')
            need(h['serial'] > broker['base_serial'], 'PIN_ADD_REQUIRES_NEW_EXACT_GET')
            need(local['sealed'] is None and actor not in broker['guards'], 'SEALED_ATTEMPT_REUSED')
            need(len(broker['guards']) < self.limits['guards'], 'GUARD_LIMIT')
            broker['guards'] = sorted(broker['guards'] + [actor])
            local['sealed'] = {'snapshot': view, 'generation': h['A'], 'pin': copy.deepcopy(broker['token'])}; return
        if op in ('gate_close', 'guard_end'):
            _, broker = self.owned_broker(state, actor)
            if op == 'gate_close': broker['gate'] = False
            else:
                need(actor in broker['guards'], 'NO_LIVE_GUARD'); broker['guards'].remove(actor); local['ended'] = True
            return
        if op in ('caller_timeout', 'quarantine', 'pause', 'tick', 'drain'):
            if op == 'caller_timeout': local['caller_unknown'] = True
            elif op == 'quarantine': local['quarantined'] = True
            elif op == 'pause': local['stopped'] = 'PAUSED'
            elif op == 'tick': state['ticks'] += 1
            return
        if op in ('object_get', 'object_put'):
            _, broker = self.owned_broker(state, actor); sealed = local['sealed']
            need(sealed is not None and actor in broker['guards'] and not local['ended'], 'UNPROTECTED_REMOTE_IO')
            item = instruction['object']
            request = {'generation': sealed['generation'], 'object': item, 'key': self.objects[item]['hash'],
                       'purpose': 'read', 'protection': copy.deepcopy(sealed['pin'])}
            if op == 'object_put': request['raw'] = self.objects[item]['raw']
            self.issue(state, actor, instruction, op, request); return
        if op == 'ack':
            token = state['tokens'][local['last_token']]
            if local['caller_unknown'] or token['observed'] != 'known' or token['response']['outcome'] != 'APPLIED' or local['native'] != 'committed': local['ack'] = 'WITHHELD'
            else:
                need(token['kind'] == 'head_cas' and token['request']['kind'] == 'write' and not local['ended'], 'ACK_BEFORE_NATIVE_PUBLICATION')
                local['ack'] = local['last_token']
            return
        if op == 'native_publish':
            need(local['native'] == 'not_started', 'NATIVE_PUBLICATION_REUSED')
            token = state['tokens'][local['last_token']]
            need(token['kind'] == 'head_cas' and token['request']['kind'] == 'write' and not local['ended'], 'NATIVE_WITHOUT_ORIGINAL_ATTEMPT')
            if token['observed'] != 'known' or token['response']['outcome'] != 'APPLIED':
                local['native'] = 'aborted'; local['completion'] = 'UNKNOWN' if token['observed'] == 'unknown' else 'CONFLICT'
            else:
                candidate = token['request']['candidate']
                local['commit_reference'] = {'token': local['last_token'], 'revision': candidate['revision'], 'transition': candidate['transition'],
                                             'roots': copy.deepcopy(candidate['roots']), 'etag': token['response']['etag']}
                local.update(native='committed' if choice == 'commit' else 'failed_after_commit',
                             completion='COMMITTED' if choice == 'commit' else 'COMMITTED_BUT_UNAVAILABLE')
            return
        if op == 'materialize':
            _, broker = self.owned_broker(state, actor); sealed = local['sealed']
            need(role == 'reader' and sealed is not None and actor in broker['guards'] and not local['ended'], 'MATERIALIZE_WITHOUT_LIVE_GUARD')
            required = self.reachable_objects(sealed['snapshot']['body']['roots']); frames = {}
            for token in state['tokens'].values():
                request, response = token['request'], token['response']
                if (token['actor'] == actor and token['kind'] == 'object_get' and token['observed'] == 'known' and response['outcome'] == 'FOUND' and
                    request['purpose'] == 'read' and request['generation'] == sealed['generation'] and request['protection'] == sealed['pin'] and request['object'] in required):
                    frames[request['key']] = response['raw']
            need(set(frames) == {self.objects[item]['hash'] for item in required}, 'READ_CLOSURE_NOT_MATERIALIZED')
            local['materialized'] = {'snapshot': copy.deepcopy(sealed['snapshot']), 'generation': sealed['generation'], 'frames': frames}; return
        if op == 'read_return':
            need(role == 'reader' and local['materialized'] is not None, 'READ_RETURN_UNMATERIALIZED')
            local['read_result'] = {'outcome': 'WITHHELD'} if local['caller_unknown'] else {
                'outcome': 'SUCCESS', 'snapshot_etag': local['materialized']['snapshot']['etag'], 'object_hashes': sorted(local['materialized']['frames'])}
            return
        if op == 'capture_plan':
            h = self.original_view(local)['body']
            need(role == 'gc' and h['life'] == 'Ready' and h['T'] is not None and h['T']['id'] == instruction['plan'], 'STALE_PLAN')
            local.update(plan=copy.deepcopy(h['T']), copied={}, copy_verified=[]); return
        if op in ('copy_get', 'copy_put', 'copy_verify'):
            p, item = local['plan'], instruction['object']
            need(role == 'gc' and p is not None, 'PLAN_NOT_CAPTURED')
            need(item in self.reachable_objects(p['roots']), 'COPY_OUTSIDE_CLOSURE')
            request = {'generation': p['source'] if op == 'copy_get' else p['target'], 'object': item, 'key': self.objects[item]['hash'],
                       'purpose': 'copy_source' if op == 'copy_get' else 'copy_verify', 'protection': copy.deepcopy(p)}
            if op == 'copy_put':
                need(item in local['copied'], 'COPY_SOURCE_NOT_OBSERVED'); request['raw'] = local['copied'][item]
            self.issue(state, actor, instruction, 'object_put' if op == 'copy_put' else 'object_get', request); return
        if op in ('sweep_open', 'sweep_resume'):
            h = self.original_view(local)['body']; generation, identity = instruction['generation'], instruction['plan']
            need(role == 'gc' and h['life'] == 'Ready', 'GC_LIFECYCLE')
            need(self.retired(h, generation), 'NOT_PERMANENTLY_RETIRED')
            if op == 'sweep_open':
                need(identity not in state['checkpoints'] and len(state['checkpoints']) < self.limits['checkpoints'], 'CHECKPOINT_LIMIT_OR_REUSE')
                state['checkpoints'][identity] = {'scope': self.inputs['scope'], 'generation': generation, 'plan': identity, 'cursor': 0, 'batch': None, 'round': 'open'}
            checkpoint = state['checkpoints'].get(identity)
            need(checkpoint is not None and checkpoint['scope'] == self.inputs['scope'] and checkpoint['generation'] == generation and checkpoint['plan'] == identity, 'STALE_CURSOR')
            local['sweep'] = copy.deepcopy(checkpoint); return
        if op == 'list':
            need(local['sweep'] is not None, 'SWEEP_NOT_CAPTURED')
            self.issue(state, actor, instruction, 'list', {key: local['sweep'][key] for key in ('generation', 'plan')}); return
        if op == 'candidate_get':
            need(local['sweep'] is not None, 'SWEEP_NOT_CAPTURED')
            result, item = local['last_result'], instruction['object']
            need(result is not None and result['outcome'] == 'LIST' and self.objects[item]['hash'] in result['objects'], 'CANDIDATE_NOT_LISTED')
            self.issue(state, actor, instruction, 'object_get', {'generation': local['sweep']['generation'], 'object': item,
                       'key': self.objects[item]['hash'], 'purpose': 'delete_candidate', 'protection': local['sweep']['plan']}); return
        if op == 'persist_batch':
            sweep = local['sweep']
            need(sweep is not None and sweep == state['checkpoints'].get(sweep['plan']), 'STALE_CURSOR')
            token = state['tokens'][local['last_token']]
            need(token['kind'] == 'object_get' and token['request']['purpose'] == 'delete_candidate' and token['observed'] == 'known' and token['response']['outcome'] == 'FOUND', 'CANDIDATE_NOT_EXACT_GET')
            checkpoint = copy.deepcopy(sweep)
            checkpoint['batch'] = {'object': token['request']['object'], 'key': token['request']['key'], 'etag': token['response']['etag']}
            checkpoint['cursor'] += 1; need(checkpoint['cursor'] <= self.limits['cursor'], 'CURSOR_EXHAUSTED')
            state['checkpoints'][sweep['plan']] = checkpoint; local['sweep'] = copy.deepcopy(checkpoint); return
        if op == 'delete_object':
            h = self.original_view(local)['body']; sweep = local['sweep']
            need(role == 'gc' and h['life'] == 'Ready', 'GC_LIFECYCLE')
            need(sweep is not None and sweep == state['checkpoints'].get(sweep['plan']) and sweep['batch'] is not None, 'STALE_CURSOR')
            need(self.retired(h, sweep['generation']), 'NOT_PERMANENTLY_RETIRED')
            request = dict(sweep['batch'], generation=sweep['generation'], plan=sweep['plan'], scope=self.inputs['scope'], cursor=sweep['cursor'])
            self.issue(state, actor, instruction, 'object_delete', request); return
        if op == 'record_round':
            sweep, result = local['sweep'], local['last_result']
            need(sweep is not None and sweep == state['checkpoints'].get(sweep['plan']), 'STALE_CURSOR')
            need(result is not None and result['outcome'] == 'LIST', 'ROUND_NOT_OBSERVED')
            checkpoint = copy.deepcopy(sweep); checkpoint['round'] = 'observed_empty' if not result['objects'] else 'observed_nonempty'
            state['checkpoints'][sweep['plan']] = checkpoint; local['sweep'] = copy.deepcopy(checkpoint); return
        raise ValueError('unreviewed finite program instruction ' + op)

    def network_relation(self, before, action):
        result = copy.deepcopy(before); token = result['tokens'][action['network']]
        if action['choice'] == 'discard': token['stage'] = 'discarded'; return result
        request, kind = token['request'], token['kind']
        if kind == 'head_cas':
            # S3 sees original bytes + original If-Match, not today's local
            # permission, deadline, owner, lifecycle or broker state.
            matched = body_tag(before['head']) == request['base']['etag']
            if matched:
                result['head'] = copy.deepcopy(request['candidate'])
                h = result['head']
                result['retired'] = sorted(set(before['retired']) | (set(range(1, h['M'] + 1)) - {h['A']} - ({h['T']['target']} if h['T'] else set())))
            response = {'outcome': 'APPLIED', 'etag': body_tag(result['head'])} if matched else {'outcome': 'CONFLICT'}
        elif kind == 'list':
            response = {'outcome': 'LIST', 'objects': sorted(before['objects'].get(str(request['generation']), {}))}
        else:
            generation, key = str(request['generation']), request['key']
            previous = before['objects'].get(generation, {}).get(key)
            if kind == 'object_get':
                response = {'outcome': 'MISSING'} if previous is None else {'outcome': 'FOUND', 'raw': previous, 'etag': sha(bytes.fromhex(previous))}
            elif kind == 'object_put':
                response = {'outcome': 'EXISTS' if previous is not None else 'CREATED', 'etag': sha(bytes.fromhex(previous if previous is not None else request['raw']))}
                if previous is None: result['objects'].setdefault(generation, {})[key] = request['raw']
            elif kind == 'object_delete':
                status = 'MISSING' if previous is None else 'CONFLICT' if sha(bytes.fromhex(previous)) != request['etag'] else 'APPLIED'
                response = {'outcome': status}
                if status == 'APPLIED':
                    del result['objects'][generation][key]
                    if not result['objects'][generation]: del result['objects'][generation]
            else: raise ValueError('unreviewed network operation')
        token.update(stage='applied', response=response)
        return result

    def edge(self, before, action, after):
        require(canonical(action) in self.enabled(before), 'edge is not an enabled original action')
        if 'network' in action:
            expected = self.network_relation(before, action)
            reason = 'original backend key/condition/effect changed'
        else:
            expected = copy.deepcopy(before); actor = action['actor']; local = expected['actors'][actor]
            instruction = self.profile['programs'][actor][local['pc']]
            try:
                self.local_step(expected, actor, instruction, action['choice'])
            except Refusal as refusal:
                expected = copy.deepcopy(before); expected['actors'][actor]['stopped'] = str(refusal)
            else:
                local['pc'] += 1
            reason = 'client protocol delta changed: ' + instruction['op']
        same(after, expected, reason)
        self.check_state(after)


FROZEN_INPUT_SHA256 = '06a5eec502e2ca9f367715d107b4c10407f3b22200065b0ae2d0e6e3e8518a76'


def validate_inputs(raw):
    same(sha(raw), FROZEN_INPUT_SHA256, 'frozen actor programs/bounds/content graph changed')
    value = parse(raw)
    same(value['schema'], 1, 'input schema changed')
    same(value['bounds'], {'serial': 16, 'revision': 8, 'generation': 4, 'pins': 2, 'guards': 2,
                          'tokens': 64, 'checkpoints': 2, 'cursor': 8}, 'finite protocol bounds changed')
    same(value['execution_limits'], {'states_per_profile': 200000, 'edges_per_profile': 1200000, 'seconds_per_profile': 120}, 'execution resource bounds changed')
    require(len(value['profiles']) == 26 and len(value['objects']) == 8, 'finite profile/object denominator changed')
    require(sum(len(program) for profile in value['profiles'] for program in profile['programs'].values()) == 629,
            'finite actor instruction denominator changed')
    hashes = {item['hash']: name for name, item in value['objects'].items()}
    require(len(hashes) == 8, 'duplicate content object identity')
    for name, item in value['objects'].items():
        raw_object = bytes.fromhex(item['raw'])
        require(raw_object.startswith(b'SCAP-MODEL-OBJECT-1\n') and sha(raw_object) == item['hash'], 'abstract raw frame/hash changed')
        decoded = parse(raw_object.split(b'\n', 1)[1])
        same(decoded['kind'], item['kind'], 'content type graph mismatch')
        same(decoded['children'], [value['objects'][child]['hash'] for child in item['edges']], 'content graph differs from raw object references')
        if 'receipt_data_root' in decoded:
            require(re.fullmatch('[0-9a-f]{64}', decoded['receipt_data_root']) is not None, 'receipt identity invalid')
        require(raw_object != b'SCAP-MODEL-OBJECT-1\n' + canonical(decoded), 'noncanonical raw-copy profile lost')
    for profile in value['profiles']:
        require(set(profile['actors']) == set(profile['programs']) and 1 <= len(profile['actors']) <= 4, 'finite actor inventory invalid')
        Rules(value, profile).check_state(profile['initial'])
    return value


def witnesses(name, rules, before, action, state):
    h, locals_, brokers = state['head'], state['actors'], state['brokers']
    tokens = list(state['tokens'].values())
    def head_tokens(kind):
        return [token for token in tokens if token['kind'] == 'head_cas' and token['request']['kind'] == kind]
    def applied(token):
        return token['stage'] == 'applied' and token['response']['outcome'] == 'APPLIED'
    def stopped(code):
        return any(local['stopped'] == code for local in locals_.values())
    network = state['tokens'].get(action.get('network'))
    if name == 'unknown_other_broker_not_granted':
        return any(b['phase'] == 'released' and b['token'] is not None and any(pin['grant_serial'] == b['token']['grant_serial'] and pin != b['token'] for pin in h['pins'])
                   and any(token['observed'] == 'unknown' and token['request']['candidate']['pins'][-1] == b['token'] for token in head_tokens('pin_add')) for b in brokers.values())
    if name == 'add_absent_at_original_serial_pending':
        return any(b['phase'] == 'pending_absent' and b['base_serial'] == h['serial'] and b['token'] not in h['pins'] for b in brokers.values())
    if name == 'add_absent_after_new_serial_settled':
        return any(b['phase'] == 'released' and b['token'] is not None and h['serial'] > b['base_serial'] and b['token'] not in h['pins'] for b in brokers.values())
    if name == 'pin_blocks_freeze': return stopped('GC_BLOCKED') and bool(h['pins'])
    if name == 'get_captured_with_guard':
        return any(token['kind'] == 'object_get' and token['request']['purpose'] == 'read' and token['request']['protection'] in h['pins'] for token in tokens)
    if name == 'paused_guard_remains_protected':
        return state['ticks'] == 2 and any(local['stopped'] == 'PAUSED' and local['caller_unknown'] for local in locals_.values()) and bool(h['pins']) and any(b['guards'] for b in brokers.values())
    if name == 'two_actual_guards': return any(len(b['guards']) == 2 for b in brokers.values())
    if name == 'release_rejected_live_guard': return stopped('RELEASE_NOT_QUIESCENT') and any(b['guards'] for b in brokers.values())
    if name == 'join_rejected_closed_gate': return stopped('LOCAL_GATE_CLOSED')
    if name == 'unknown_write_applied': return any(applied(t) and t['observed'] == 'unknown' for t in head_tokens('write')) and locals_['w']['ack'] == 'WITHHELD'
    if name == 'unknown_write_original_conflict':
        return any(t['stage'] == 'applied' and t['response']['outcome'] == 'CONFLICT' and t['observed'] == 'unknown' for t in head_tokens('write')) and locals_['w']['ack'] == 'WITHHELD'
    if name == 'release_preserves_new_business_roots': return any(applied(t) and t['request']['candidate']['roots'] == ['data1', 'index1'] for t in head_tokens('pin_release'))
    if name == 'old_write_conflicts_after_technical_cas':
        return any(t['stage'] == 'applied' and t['response']['outcome'] == 'CONFLICT' for t in head_tokens('write')) and any(applied(t) for t in head_tokens('pin_add'))
    if name == 'promoted_with_latest_acl': return any(applied(t) and t['request']['candidate']['acl'] == 'deny' for t in head_tokens('promote'))
    if name == 'raw_copy_identity_preserved': return any(applied(t) for t in head_tokens('promote')) and rules.complete_at(state, h['A'], h['roots'])
    if name == 'deleted_staging_retired': return h['life'] == 'Deleted' and h['A'] == 1 and h['M'] == 2 and 2 in state['retired'] and h['T'] is None
    if name == 'late_copy_after_delete':
        return network is not None and action['choice'] == 'apply' and before['head']['life'] == 'Deleted' and network['kind'] == 'object_put' and network['response']['outcome'] == 'CREATED'
    if name == 'late_promote_cannot_revive':
        return network is not None and action['choice'] == 'apply' and before['head']['life'] == 'Deleted' and network['kind'] == 'head_cas' and network['request']['kind'] == 'promote' and network['response']['outcome'] == 'CONFLICT'
    if name == 'delete_preserves_live_pin': return h['life'] == 'Deleted' and bool(h['pins']) and any(b['guards'] for b in brokers.values())
    if name == 'narrow_release_in_deleted_quarantine':
        return locals_['p']['quarantined'] and any(applied(t) and t['request']['base']['body']['life'] == 'Deleted' for t in head_tokens('pin_release'))
    if name == 'abandoned_two_next_is_three': return h['A'] == 1 and h['M'] == 3 and h['T'] is not None and h['T']['target'] == 3 and 2 in state['retired']
    if name == 'late_put_stays_in_abandoned_two':
        return network is not None and action['choice'] == 'apply' and network['kind'] == 'object_put' and network['request']['generation'] == 2 and before['head']['T'] is not None and before['head']['T']['target'] == 3 and network['response']['outcome'] == 'CREATED'
    if name == 'unknown_delete_applied': return any(t['kind'] == 'object_delete' and t['observed'] == 'unknown' and applied(t) for t in tokens)
    if name == 'unknown_delete_not_applied': return any(t['kind'] == 'object_delete' and t['observed'] == 'unknown' and t['stage'] == 'discarded' for t in tokens)
    if name == 'old_delete_cannot_target_new_active':
        return network is not None and action['choice'] == 'apply' and network['kind'] == 'object_delete' and network['request']['generation'] == 1 and before['head']['A'] == 3 and network['response']['outcome'] == 'APPLIED' and rules.complete_at(state, 3, h['roots'])
    if name == 'stale_cursor_rejected': return stopped('STALE_CURSOR')
    if name == 'provisioning_technical_admission_rejected': return h['life'] == 'Provisioning' and (stopped('PIN_ADMISSION_BLOCKED') or stopped('GC_LIFECYCLE'))
    if name == 'named_complete_revision_two': return any(applied(t) and t['request']['candidate']['revision'] == 2 and t['request']['candidate']['life'] == 'Ready' for t in head_tokens('complete'))
    if name == 'serial_exhaustion_rejected': return stopped('SERIAL_EXHAUSTED')
    if name == 'generation_exhaustion_rejected': return stopped('GENERATION_EXHAUSTED')
    if name == 'pin_capacity_rejected': return stopped('PIN_LIMIT')
    if name == 'empty_round_is_not_permanent_absence':
        return (network is not None and action['choice'] == 'apply' and network['kind'] == 'object_put' and network['request']['generation'] == 1 and
                network['request']['object'] == 'data1' and before['checkpoints'].get('old-one', {}).get('round') == 'observed_empty' and not before['objects'].get('1') and bool(state['objects'].get('1')))
    if name == 'finite_drained_sweep_empty':
        program = rules.profile['programs']['g']; barrier = next(index for index, item in enumerate(program) if item['op'] == 'drain')
        return h['A'] == 2 and locals_['g']['pc'] > barrier and not state['objects'].get('1') and state['checkpoints'].get('old-one', {}).get('round') == 'observed_empty' and all(t['stage'] != 'pending' for t in tokens)
    if name in ('incomplete_copy_rejected', 'new_plan_incomplete_copy_rejected'): return stopped('INCOMPLETE_COPY')
    if name == 'frozen_root_controls_rejected': return h['T'] is not None and stopped('ROOT_CONTROL_FROZEN')
    if name == 'root_controls_after_explicit_abort': return h['T'] is None and any(applied(t) for kind in ('quota', 'takeover') for t in head_tokens(kind))
    if name == 'new_plan_has_no_old_verification': return any(local['plan'] is not None and local['plan']['target'] == 3 and not local['copy_verified'] and not local['copied'] for local in locals_.values())
    if name == 'late_old_plan_verification_rejected': return stopped('STALE_COPY_RESPONSE')
    if name == 'native_commit_before_ack': return any(local['native'] == 'committed' and local['ack'] not in (None, 'WITHHELD') and local['commit_reference'] is not None for local in locals_.values())
    if name == 'native_failure_preserves_committed_reference':
        return any(local['native'] == 'failed_after_commit' and local['completion'] == 'COMMITTED_BUT_UNAVAILABLE' and local['commit_reference'] is not None and local['ack'] == 'WITHHELD' for local in locals_.values())
    if name == 'reader_returns_materialized_bytes_after_sweep':
        return (action.get('actor') == 'p' and rules.profile['programs']['p'][before['actors']['p']['pc']]['op'] == 'read_return' and
                not before['objects'].get('1') and before['head']['A'] == 2 and locals_['p']['ended'] and
                locals_['p']['read_result'] is not None and locals_['p']['read_result']['outcome'] == 'SUCCESS')
    if name == 'reader_early_exit_rejected': return stopped('READ_RETURN_UNMATERIALIZED')
    if name == 'reader_detached_caller_no_success':
        return locals_['timeout']['materialized'] is not None and locals_['timeout']['read_result'] == {'outcome': 'WITHHELD'} and locals_['timeout']['caller_unknown']
    if name == 'ended_worker_cannot_consume_late_get': return stopped('LATE_READ_RESPONSE') and locals_['p']['ended'] and not h['pins']
    raise ValueError('unreviewed required witness ' + name)


def records(path):
    with gzip.open(path, 'rb') as stream:
        for line in stream:
            require(len(line) < 1024 * 1024, 'raw graph record exceeds finite bound')
            yield parse(line)


def trace_for(profile, states, parents, edge):
    sequence, cursor = [], edge['source']
    while cursor:
        previous = parents[cursor]
        require(previous is not None, 'witness has no reachable prefix')
        sequence.append(previous); cursor = previous['source']
    sequence.reverse(); sequence.append(edge)
    return {'schema': 1, 'profile': profile['name'], 'inputs_sha256': FROZEN_INPUT_SHA256,
            'states': [states[0]] + [states[item['target']] for item in sequence], 'actions': [item['action'] for item in sequence]}


def audit_trace(inputs, profile, trace):
    same(trace['schema'], 1, 'trace schema changed')
    same(trace['inputs_sha256'], FROZEN_INPUT_SHA256, 'trace frozen input identity changed')
    same(trace['profile'], profile['name'], 'trace profile changed')
    same(trace['states'][0], profile['initial'], 'trace does not start at frozen initial state')
    require(len(trace['states']) == len(trace['actions']) + 1, 'trace action/state denominator changed')
    rules = Rules(inputs, profile); rules.check_state(trace['states'][0])
    for before, action, after in zip(trace['states'], trace['actions'], trace['states'][1:]): rules.edge(before, action, after)


def audit_profile(inputs, profile, directory, output=None):
    rules = Rules(inputs, profile); states, hashes = [], set()
    for row in records(directory / 'states.jsonl.gz'):
        same(row['id'], len(states), 'state id inventory has gaps/repeats')
        require(len(states) < inputs['execution_limits']['states_per_profile'], 'state resource bound exceeded')
        key = sha(canonical(row['value'])); same(key, row['sha256'], 'complete state bytes/hash changed')
        require(key not in hashes, 'duplicate state was counted twice'); hashes.add(key)
        rules.check_state(row['value']); states.append(row['value'])
    require(states, 'no initial state')
    same(states[0], profile['initial'], 'initial state differs from frozen profile')
    outgoing, edges, parents = [dict() for _ in states], [], [None] * len(states)
    found = {}
    for edge in records(directory / 'edges.jsonl.gz'):
        require(len(edges) < inputs['execution_limits']['edges_per_profile'], 'edge resource bound exceeded')
        require(type(edge['source']) is int and type(edge['target']) is int and 0 <= edge['source'] < len(states) and 0 <= edge['target'] < len(states), 'edge has unknown source/target')
        key = canonical(edge['action']); require(key not in outgoing[edge['source']], 'duplicate successor for original action')
        before, after = states[edge['source']], states[edge['target']]
        rules.edge(before, edge['action'], after)
        outgoing[edge['source']][key] = edge; edges.append(edge)
        if edge['target'] and parents[edge['target']] is None: parents[edge['target']] = edge
        for name in profile['witnesses']:
            if name not in found and witnesses(name, rules, before, edge['action'], after): found[name] = edge
    terminal_ids = []
    for identity, state in enumerate(states):
        expected = rules.enabled(state)
        same(set(outgoing[identity]), expected, 'BFS closure omitted/added enabled successor')
        if not expected: terminal_ids.append(identity)
    seen, frontier = {0}, [0]
    while frontier:
        source = frontier.pop()
        for edge in outgoing[source].values():
            if edge['target'] not in seen: seen.add(edge['target']); frontier.append(edge['target'])
    same(len(seen), len(states), 'reported graph contains unreachable states')
    require(set(found) == set(profile['witnesses']), 'required finite interleaving witness missing: ' + str(sorted(set(profile['witnesses']) - set(found))))
    report = parse((directory / 'enumeration.json').read_bytes())
    require(report['complete'] is True and report['status'] == 'ENUMERATED' and report['reason'] is None, 'truncated exploration cannot count as complete')
    for field, expected in (('profile', profile['name']), ('states', len(states)), ('edges', len(edges)), ('expanded_states', len(states)), ('terminals', len(terminal_ids))):
        same(report[field], expected, 'producer graph denominator differs: ' + field)
    for name in ('states.jsonl.gz', 'edges.jsonl.gz'):
        same(report['files'][name], sha((directory / name).read_bytes()), 'original graph file hash changed')
    selected = []
    for name, edge in found.items():
        trace = trace_for(profile, states, parents, edge); audit_trace(inputs, profile, trace)
        raw = canonical(trace) + b'\n'
        if output is not None: (output / (profile['name'] + '--' + name + '.json')).write_bytes(raw)
        selected.append({'witness': name, 'steps': len(trace['actions']), 'sha256': sha(raw)})
    conditional = None
    if profile['name'] == '19_conditional_drain_convergence':
        program = profile['programs']['g']; barrier = next(index for index, item in enumerate(program) if item['op'] == 'drain')
        qualified = [states[index] for index in terminal_ids if states[index]['head']['A'] == 2 and states[index]['actors']['g']['pc'] > barrier]
        require(qualified and all(not state['objects'].get('1') for state in qualified), 'finite drained fair sweep failed conditional empty-space result')
        conditional = {'qualified_terminal_states': len(qualified), 'retired_generation_empty': True,
                       'assumptions': 'successful migration; actual old request drain; fixed finite old key set; full offered sweep; all enabled network steps terminate'}
    blocked = {}
    for index in terminal_ids:
        for local in states[index]['actors'].values():
            if local['stopped'] is not None: blocked[local['stopped']] = blocked.get(local['stopped'], 0) + 1
    return {'profile': profile['name'], 'states': len(states), 'edges': len(edges), 'terminals': len(terminal_ids),
            'complete_closure': True, 'safety': 'PASS_WITHIN_FROZEN_PROGRAMS', 'terminal_stops': blocked,
            'witnesses': selected, 'conditional_cost_result': conditional}


def audit(directory, *, output=None, allow_partial=False, verify_source=True):
    raw = (directory / 'inputs.json').read_bytes(); inputs = validate_inputs(raw)
    run = parse((directory / 'run.json').read_bytes())
    same(run['input_sha256'], sha(raw), 'producer input hash changed')
    require(run['producer_safety_authority'] is False and run['source_unchanged'] is True and run['status'] == 'ENUMERATED' and run['error'] is None,
            'producer source/termination receipt incomplete')
    profiles = [profile for profile in inputs['profiles'] if profile['name'] in run['selected_profiles']]
    same([profile['name'] for profile in profiles], run['selected_profiles'], 'profile selection unknown/reordered')
    if not allow_partial:
        require(run['all_frozen_profiles_selected'] is True and len(profiles) == len(inputs['profiles']), 'partial profile selection is not full acceptance')
    same([entry['profile'] for entry in run['profiles']], run['selected_profiles'], 'enumerated profile denominator incomplete')
    with tarfile.open(directory / 'source.tar', 'r') as archive:
        members = archive.getmembers()
        same(sorted(member.name for member in members), sorted(run['source']), 'source input inventory changed')
        require(all(member.isfile() and '/' not in member.name and not member.name.startswith('.') for member in members), 'source archive contains non-file/foreign paths')
        for member in members:
            body = archive.extractfile(member).read()
            same({'sha256': sha(body), 'bytes': len(body)}, run['source'][member.name], 'source bytes/hash changed')
            if member.name == 'inputs.json': same(body, raw, 'archived program inputs differ')
        require({'model.py', 'oracle.py', 'run.py', 'inputs.json'} <= set(run['source']), 'required model source omitted')
    if verify_source:
        same(run['source']['oracle.py']['sha256'], sha(Path(__file__).read_bytes()), 'acceptance oracle differs from frozen source')
    if output is not None: output.mkdir(parents=True, exist_ok=False)
    results, files = [], {}
    for name in ('inputs.json', 'run.json', 'source.tar'): files[name] = sha((directory / name).read_bytes())
    for profile in profiles:
        result = audit_profile(inputs, profile, directory / profile['name'], output); results.append(result)
        for name in ('states.jsonl.gz', 'edges.jsonl.gz', 'enumeration.json'):
            files[profile['name'] + '/' + name] = sha((directory / profile['name'] / name).read_bytes())
    report = {'schema': 1, 'status': 'PASS', 'scope': 'all_frozen_profiles' if len(profiles) == len(inputs['profiles']) else 'EXPLICIT_PARTIAL_DEVELOPMENT_ONLY',
              'bounds': inputs['bounds'], 'execution_limits': inputs['execution_limits'], 'claims': inputs['claims'],
              'profiles': results, 'states': sum(item['states'] for item in results), 'edges': sum(item['edges'] for item in results),
              'input_files': files, 'evidence_sha256': sha(canonical(files))}
    if output is not None: (output / 'oracle.json').write_bytes(json.dumps(report, sort_keys=True, indent=2).encode() + b'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory for independent report and original witness traces')
    args = parser.parse_args()
    value = audit(args.evidence, output=args.output)
    print(json.dumps({key: value[key] for key in ('status', 'scope', 'states', 'edges', 'evidence_sha256')}, sort_keys=True))
