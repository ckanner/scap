"""Finite controller policy projection composed with the existing HEAD8 model.

This is neither the JavaScript controller nor native/HTTP/S3 acceptance. Core
events remain byte-for-byte in their own ledger; controller events reference
exact core cuts and never manufacture authoritative responses or old ACKs.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def load_core():
    name = '_controller_core_model'
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'object-owner-plan-model/model.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


core = load_core()
ROUTES = {1: 'owner', 2: 'target', 3: 'other'}
MUTATIONS = {'prepare', 'claim', 'resume', 'abort'}
FAILURES = {'TRANSPORT', 'DEADLINE'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def policy(principal=11, domain='authority-a', **modes):
    value = {'version': 1, 'scope': deepcopy(core.SCOPE), 'authority': domain, 'principal': principal,
             'workers': [[1, 0, 'owner'], [2, 1, 'target'], [3, 2, 'other']],
             'modes': {'takeover': True, 'activate': True, 'cancel': True} | modes,
             'limits': {'calls': 8, 'mutations': 1, 'timeout': 30000, 'recovery': 1800000,
                        'failures': 3, 'interval': 1000, 'span': 5000}}
    digest = hashlib.sha256(b'SCAPOWNERPOLICYMODEL1\0' + canonical(value).encode()).digest()
    words = [int.from_bytes(digest[i:i+8], 'big') for i in range(0, 32, 8)]
    assert len(set(words)) == 4 and all(words)
    return value | {'digest': digest.hex(), 'nonces': dict(zip(('claim', 'cancel', 'activate', 'abort'), words))}


@dataclass
class Actor:
    name: str
    client: str
    policy: dict
    base: dict | None = None
    windows: dict = field(default_factory=dict)
    prepared: dict | None = None
    recovery: bool = False
    unknowns: set = field(default_factory=set)
    tick: dict | None = None
    incarnation: int = 0


class Halt(Exception):
    pass


class World:
    def __init__(self, policies=None, **kwargs):
        self.core = core.World(maximum=40, **kwargs)
        values = policies or [policy(), policy()]
        self.actors = {name: Actor(name, 'client-' + str(i + 1), deepcopy(p))
                       for i, (name, p) in enumerate(zip(('a', 'b'), values))}
        self.now, self.events, self.tick_number = 0, [], 0
        self.emit('initial', policies={k: a.policy for k, a in self.actors.items()},
                  clients={k: a.client for k, a in self.actors.items()},
                  assumptions=['three fixed nonreused worker incarnations',
                               'a classified probe failure is an external finite-model input',
                               'the existing core model supplies exact GET/conditional PUT semantics'])

    def emit(self, kind, **value):
        self.events.append({'sequence': len(self.events)+1, 'at': self.core.clock, 'time': self.now,
                            'event': kind, **deepcopy(value)})

    def begin(self, who, timeout=None):
        a = self.actors[who]
        if a.tick is not None:
            raise Halt('OVERLAP')
        self.tick_number += 1
        maximum = a.policy['limits']['recovery' if a.recovery else 'timeout']
        duration = maximum if timeout is None else timeout
        if not 0 < duration <= maximum:
            raise Halt('DEADLINE')
        a.tick = {'id': self.tick_number, 'deadline': self.now+duration, 'recovery': a.recovery,
                  'calls': 0, 'mutations': 0, 'head': None, 'health': {}, 'inspected': None}
        self.emit('tick', actor=who, tick=a.tick['id'], deadline=a.tick['deadline'], recovery=a.recovery)

    def rpc(self, who, method, args=None, route='other', guard=None, deferred=False):
        a = self.actors[who]
        t = a.tick
        if self.now >= t['deadline']:
            raise Halt('DEADLINE')
        if t['calls'] >= 8 or (method in MUTATIONS and t['mutations'] >= 1):
            raise Halt('LIMIT')
        t['calls'] += 1
        t['mutations'] += int(method in MUTATIONS)
        call = self.core.begin(method, args, principal=a.policy['principal'], route=route,
                               client=a.client, expected_worker=guard)
        self.emit('rpc', actor=who, tick=t['id'], call=call, method=method)
        if not deferred:
            self.core.complete(call)
            self.observe(who, call)
        return call

    def observe(self, who, call):
        a = self.actors[who]
        outcome = self.core.calls[call].outcome
        self.emit('response', actor=who, call=call, outcome=outcome)
        if outcome and outcome['kind'] == 'unknown':
            a.unknowns.add(call)
        if outcome and (outcome['kind'] == 'unknown' or
                        (outcome['kind'] == 'error' and outcome['value']['code'] != 'MISSING_DESCRIPTOR')):
            a.windows.clear()
        if outcome and outcome['kind'] == 'prepared':
            a.prepared = json.loads(outcome['value']['body'])
        return outcome

    def status(self, who, route='other', role='authority', guard=None):
        a = self.actors[who]
        call = self.rpc(who, 'guard', {'entry': 'status'}, route, guard)
        outcome = self.core.calls[call].outcome
        if outcome['kind'] != 'read_only':
            raise Halt(outcome['value']['code'])
        read = next(e for e in reversed(self.core.events)
                    if e['event'] == 's3_get_response' and e['io'] in
                    [x['io'] for x in self.core.events if x['event'] == 's3_get_invoked' and x['call'] == call])
        snapshot = deepcopy(read['value'])
        h = json.loads(snapshot['body'])
        self.emit('head', actor=who, call=call, read=read['io'], role=role, snapshot=snapshot)
        if role == 'authority':
            if a.base != snapshot:
                a.windows.clear(); a.prepared = None
            a.base = snapshot
            a.tick['head'] = h
            a.recovery = h.get('owner_plan', {}).get('phase', {}).get('kind') == 'claimed'
        elif snapshot != a.base:
            a.windows.clear()
            raise Halt('STALE')
        return h

    def probe(self, who, worker, code='OK', slot='owner'):
        a, t = self.actors[who], self.actors[who].tick
        if code == 'OK':
            self.status(who, ROUTES[worker], 'probe', worker)
            a.windows.pop(slot, None)
            result = {'healthy': True, 'mature': False}
            self.emit('probe', actor=who, worker=worker, slot=slot, code=code, result=result)
        else:
            if self.now >= t['deadline'] or t['calls'] >= 8:
                raise Halt('LIMIT')
            t['calls'] += 1
            self.emit('network_failure', actor=who, worker=worker, slot=slot, code=code)
            if code not in FAILURES:
                a.windows.clear()
                raise Halt(code)
            route = next(v for k, v in ROUTES.items() if k != worker)
            self.status(who, route, 'confirmation')
            old = a.windows.get(slot)
            if old is None or old['worker'] != worker:
                old = {'worker': worker, 'first': self.now, 'last': self.now, 'count': 1}
            elif self.now-old['last'] >= 1000:
                old = old | {'last': self.now, 'count': min(3, old['count']+1)}
            a.windows[slot] = old
            result = {'healthy': False, 'mature': old['count'] >= 3 and self.now-old['first'] >= 5000}
            self.emit('probe', actor=who, worker=worker, slot=slot, code=code, result=result)
        t['health'][slot] = result
        return result

    def inspect(self, who, identity):
        call = self.rpc(who, 'inspect', {'identity': identity})
        outcome = self.core.calls[call].outcome
        if outcome['kind'] == 'error':
            if outcome['value']['code'] == 'MISSING_DESCRIPTOR':
                self.emit('descriptor_missing', actor=who, call=call)
                self.actors[who].tick['inspected'] = None
                return None
            raise Halt(outcome['value']['code'])
        value = outcome['value']
        desc = json.loads(value['prepared']['body'])
        self.emit('descriptor', actor=who, call=call, body=desc)
        a = self.actors[who]
        a.tick['inspected'] = desc
        if value['current_head'] != a.tick['head']:
            a.windows.clear()
            raise Halt('STALE')
        return desc

    def own(self, who, desc):
        p = self.actors[who].policy
        return (desc['scope'] == p['scope'] and desc['identity']['creator'] == p['principal'] and
                desc['identity']['operation'] == desc['expected_head_serial'] and desc['nonces'] == p['nonces'] and
                p['modes'][desc['mode']] and desc['target'] in ROUTES)

    def new_input(self, who, target, mode):
        a = self.actors[who]
        h = a.tick['head']
        return {'identity': {'creator': a.policy['principal'], 'operation': h['head_serial']},
                'target': target, 'mode': mode, 'expected_revision': h['revision'],
                'expected_head_serial': h['head_serial'], 'nonces': deepcopy(a.policy['nonces'])}

    def dispatch(self, who, method, value, deferred=False):
        a, t = self.actors[who], self.actors[who].tick
        self.emit('decision', actor=who, method=method, value=value)
        if method == 'prepare':
            args, route, guard = {'input': value}, 'other', None
        else:
            args = {'identity': value['identity'] | {'descriptor_hash': core.digest(value)}}
            route = ROUTES[value['target']] if method in ('claim', 'resume') else 'other'
            guard = value['target'] if method in ('claim', 'resume') else None
        call = self.rpc(who, method, args, route, guard, deferred)
        if not deferred:
            outcome = self.core.calls[call].outcome
            if outcome['kind'] == 'accepted':
                a.recovery = outcome['value']['head']['owner_plan']['phase']['kind'] == 'claimed'
            if outcome['kind'] == 'error':
                raise Halt(outcome['value']['code'])
        return call

    def finish(self, who, reason='WAITING'):
        a, t = self.actors[who], self.actors[who].tick
        self.emit('report', actor=who, tick=t['id'], reason=reason,
                  calls=t['calls'], mutations=t['mutations'], unknowns=sorted(a.unknowns),
                  native_session=False, historical_ack=False)
        a.tick = None

    def crash(self, who):
        a = self.actors[who]
        old = a.client
        self.core.crash(old)
        if a.tick is not None:
            for call in self.core.calls.values():
                if call.client == old and call.outcome is not None and call.outcome['kind'] == 'unknown':
                    a.unknowns.add(call.identifier)
            self.finish(who, 'PROCESS_EXIT')
        a.incarnation += 1
        a.client = f'controller-{who}-{a.incarnation}'
        self.core.spawn(a.client, 'client')
        a.base, a.prepared, a.recovery = None, None, False
        a.windows.clear(); a.unknowns.clear()
        self.emit('restart', actor=who, previous=old, client=a.client)

    def warm(self, who, times=(0, 5000), code='TRANSPORT'):
        for time in times:
            assert time >= self.now, 'finite-model time must not go backwards'
            self.now = time
            self.tick(who, owner_code=code)

    def ready(self, who, target=2):
        """Same-policy controllers may observe different healthy higher candidates."""
        self.begin(who)
        h = self.status(who)
        health = self.probe(who, h['owner']['instance'], 'TRANSPORT')
        assert health['mature']
        assert self.inspect(who, {'creator': self.actors[who].policy['principal'],
                                  'operation': h['head_serial']}) is None
        assert self.probe(who, target, slot='target')['healthy']
        return self.new_input(who, target, 'takeover')

    def tick(self, who, owner_code='OK', target_code='OK', preferred=2, timeout=None):
        a = self.actors[who]
        self.begin(who, timeout)
        reason = 'WAITING'
        try:
            h = self.status(who)
            if h['lifecycle'] != 'ready' or any(h['storage'][k] for k in ('copy', 'sweep', 'terminal')):
                raise Halt('MAINTENANCE')
            marker = h.get('owner_plan')
            if marker:
                if marker['identity']['creator'] != a.policy['principal']:
                    raise Halt('FOREIGN')
                desc = self.inspect(who, marker['identity'])
                if not self.own(who, desc):
                    raise Halt('FOREIGN')
                phase = marker['phase']['kind']
                if phase in ('claimed', 'cancelling'):
                    self.inspect(who, desc['identity'])
                    if phase == 'cancelling':
                        if not a.policy['modes']['cancel']: raise Halt('CANCEL_DISABLED')
                        self.dispatch(who, 'abort', desc); reason = 'ABORTED'
                    else:
                        health = self.probe(who, desc['target'], target_code, 'target')
                        if health['healthy']:
                            if not a.tick['recovery']: raise Halt('NEXT_RECOVERY_TICK')
                            self.dispatch(who, 'resume', desc); reason = 'ACTIVE_OBSERVED'
                        elif health['mature']:
                            if not a.policy['modes']['cancel']: raise Halt('CANCEL_DISABLED')
                            self.dispatch(who, 'abort', desc); reason = 'ABORTED'
                        else: raise Halt('TARGET_WINDOW')
                    return reason
            owner = h['owner']['instance']
            health = self.probe(who, owner, owner_code)
            if h['active'] and health['healthy']:
                raise Halt('HEALTHY')
            if not health['healthy'] and not health['mature']:
                raise Halt('OWNER_WINDOW')
            mode = 'activate' if health['healthy'] else 'takeover'
            if not a.policy['modes'][mode]: raise Halt('MODE_DISABLED')
            if h['revision'] > 38 or h['head_serial'] > 38 or (mode == 'takeover' and h['owner']['epoch'] == 40):
                raise Halt('COUNTER')
            desc = self.inspect(who, {'creator': a.policy['principal'], 'operation': h['head_serial']})
            if desc:
                if not self.own(who, desc): raise Halt('FOREIGN')
                if desc['base']['head_hash'] != core.digest(h) or desc['base']['etag'] != a.base['etag']:
                    raise Halt('FENCED')
                if desc['mode'] == 'activate':
                    if h['active'] or desc['target'] != owner: raise Halt('RANK')
                elif desc['target'] <= owner: raise Halt('RANK')
                cancel_inactive = desc['mode'] == 'takeover' and health['healthy']
                target = health if desc['target'] == owner else (
                    None if cancel_inactive else self.probe(who, desc['target'], target_code, 'target'))
                cancel = cancel_inactive or not target['healthy']
                if cancel and not cancel_inactive and not (health['mature'] and target['mature']):
                    raise Halt('TARGET_WINDOW')
                if cancel and not a.policy['modes']['cancel']: raise Halt('CANCEL_DISABLED')
                if a.prepared is None:
                    self.dispatch(who, 'prepare', {k: deepcopy(desc[k]) for k in
                        ('identity', 'target', 'mode', 'expected_revision', 'expected_head_serial', 'nonces')})
                    reason = 'REPREPARED'
                else:
                    self.inspect(who, desc['identity'])
                    self.dispatch(who, 'abort' if cancel else 'claim', desc)
                    reason = 'CANCELLING' if cancel else 'CLAIMED'
            else:
                target = owner if health['healthy'] else preferred
                if mode == 'takeover':
                    if target <= owner or target not in ROUTES: raise Halt('RANK')
                    if not self.probe(who, target, target_code, 'target')['healthy']:
                        raise Halt('CANDIDATE')
                self.dispatch(who, 'prepare', self.new_input(who, target, mode)); reason = 'PREPARED'
            return reason
        except Halt as error:
            reason = str(error)
            if reason in ('FOREIGN', 'FENCED'):
                a.windows.clear()
            return reason
        finally:
            self.finish(who, reason)

    def trace(self, name):
        assert all(a.tick is None for a in self.actors.values())
        return {'schema': 1, 'name': name, 'protocol': self.core.trace(name), 'controller': deepcopy(self.events),
                'witness': deepcopy(getattr(self, 'witness', {})),
                'summary': {'untrusted': True, 'production_controller': 'NOT_EXECUTED'}}
