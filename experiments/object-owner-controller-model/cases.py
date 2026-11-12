"""Declared finite histories; assertions prevent vacuous scenario witnesses.

Schedules enumerate macro cuts only. Native storage, TLS, fleet scheduling and
real request cancellation remain outside this policy projection.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from itertools import product

from model import World, Halt, policy, core, ROUTES


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    build: object


def schedule(left, right, prefix=()):
    if not left and not right:
        yield prefix
    if left:
        yield from schedule(left[1:], right, prefix + (('a', left[0]),))
    if right:
        yield from schedule(left, right[1:], prefix + (('b', right[0]),))


def operator(w, method, args=None, **kwargs):
    if 'operator' not in w.core.processes:
        w.core.spawn('operator', 'client')
    call = w.core.request(method, args, client='operator', **kwargs)
    assert w.core.calls[call].outcome['kind'] != 'error', w.core.calls[call].outcome
    return call


def advance(w, who='a', **kwargs):
    w.now += 5000
    return w.tick(who, **kwargs)


def prepared(w=None):
    w = w or World()
    w.warm('a')
    assert advance(w, owner_code='TRANSPORT') == 'PREPARED'
    return w


def claimed(w=None):
    w = prepared(w)
    assert advance(w, owner_code='TRANSPORT') == 'CLAIMED'
    return w


def ref(desc):
    return desc['identity'] | {'descriptor_hash': core.digest(desc)}


def claim_ready(w, who):
    a = w.actors[who]
    w.begin(who)
    h = w.status(who)
    assert w.probe(who, h['owner']['instance'], 'TRANSPORT')['mature']
    d = w.inspect(who, {'creator': a.policy['principal'], 'operation': h['head_serial']})
    assert d is not None and w.own(who, d) and a.prepared == d
    assert w.probe(who, d['target'], slot='target')['healthy']
    assert w.inspect(who, d['identity']) == d
    return w.dispatch(who, 'claim', d, deferred=True)


def prepare_race(config, lost, order):
    policies = [policy(), policy() if config == 'same' else
                policy(domain='authority-b') if config == 'other-policy' else policy(principal=12)]
    w = World(policies)
    for time in (0, 5000):
        w.now = time
        for who in ('a', 'b'):
            assert w.tick(who, owner_code='TRANSPORT') == 'OWNER_WINDOW'
    w.now = 10000
    inputs = {who: w.ready(who, target) for who, target in (('a', 2), ('b', 3))}
    calls = {who: w.dispatch(who, 'prepare', value, deferred=True) for who, value in inputs.items()}
    first_effect = None
    for who, step in order:
        c = w.core.calls[calls[who]]
        if step == 'admit':
            w.core.admit(c.identifier)
        elif step == 'invoke' and c.stage == 'ready':
            w.core.invoke(c.identifier)
        elif step == 'effect' and c.io is not None:
            if w.core.effect(c.io) == 200 and first_effect is None:
                first_effect = who
        elif step == 'respond':
            if c.io is not None:
                w.core.respond(c.io, delivered=not (lost and who == first_effect))
            w.observe(who, c.identifier)
            w.finish(who)
    assert first_effect is not None
    original_unknown = {c.identifier: deepcopy(c.outcome) for c in w.core.calls.values()
                        if c.outcome and c.outcome['kind'] == 'unknown'}
    assert bool(original_unknown) == bool(lost)
    stored = json_descriptor(w, inputs[first_effect]['identity'])
    assert stored['target'] == inputs[first_effect]['target']
    for who in ('a', 'b'):
        w.crash(who)
    for time in (15000, 20000, 25000):
        w.now = time
        for who in ('a', 'b'):
            w.tick(who, owner_code='TRANSPORT')
    eligible = [who for who in ('a', 'b') if w.actors[who].prepared is not None]
    assert len(eligible) == (1 if config == 'other-policy' else 2)
    w.now = 30000
    pending = {who: claim_ready(w, who) for who in eligible}
    for call in pending.values():
        w.core.admit(call)
        assert w.core.calls[call].stage == 'ready'
        w.core.invoke(call)
    # Both admitted original candidates remain live; the prepare winner chooses
    # only the fixed order of this second CAS race, not a new authority base.
    effect_order = [who for who in (first_effect, 'b' if first_effect == 'a' else 'a') if who in pending]
    for who in effect_order:
        w.core.effect(w.core.calls[pending[who]].io)
    for who, call in pending.items():
        w.core.respond(w.core.calls[call].io)
        w.observe(who, call)
        w.finish(who)
    accepted = [who for who, call in pending.items() if w.core.calls[call].outcome['kind'] == 'accepted']
    assert len(accepted) == 1
    for who in ('a', 'b'):
        w.crash(who)
    for time in (35000, 40000):
        w.now = time
        for who in ('a', 'b'):
            w.tick(who)
    h = w.core.head()
    assert h['active'] and h['owner_plan']['phase']['kind'] == 'active'
    assert h['owner']['instance'] == json_descriptor(w, h['owner_plan']['identity'])['target']
    for call, outcome in original_unknown.items():
        assert w.core.calls[call].outcome == outcome
    w.witness = {'family': 'prepare-race', 'config': config, 'lost': lost,
                 'schedule': [list(x) for x in order]}
    return w


def json_descriptor(w, identity):
    import json
    return json.loads(w.core.objects[core.control_key('descriptor', **identity)]['body'])


def healthy():
    w = World()
    for time in (0, 5000, 10000):
        w.now = time
        assert w.tick('a') == 'HEALTHY'
    return w


def activation():
    w = World(active=False)
    assert w.tick('a') == 'PREPARED'
    assert advance(w) == 'CLAIMED'
    assert advance(w) == 'ACTIVE_OBSERVED'
    assert w.core.head()['active'] and w.core.head()['owner'] == {'instance': 1, 'epoch': 1}
    return w


def restart_pending(phase):
    w = claimed() if phase == 'claimed' else prepared(World(active=False))
    if phase == 'cancelling':
        assert advance(w) == 'CANCELLING'
    assert w.core.head()['owner_plan']['phase']['kind'] == phase
    w.crash('a')
    if phase == 'claimed':
        assert advance(w) == 'NEXT_RECOVERY_TICK'
        assert advance(w) == 'ACTIVE_OBSERVED'
    else:
        assert advance(w) == 'ABORTED'
    return w


def cancel_then_activate():
    w = restart_pending('cancelling')
    assert not w.core.head()['active']
    # The existing core projection exposes proof preservation as an explicit
    # operator action. This is not evidence of a controller HTTP implementation.
    operator(w, 'preserve', route='other')
    assert advance(w) == 'PREPARED'
    assert advance(w) == 'CLAIMED'
    assert advance(w) == 'ACTIVE_OBSERVED'
    assert w.core.head()['owner'] == {'instance': 1, 'epoch': 1}
    return w


def late_prepare():
    w = World()
    w.warm('a'); w.now = 10000
    original = w.ready('a', 3)
    old = w.dispatch('a', 'prepare', original, deferred=True)
    w.core.admit(old); old_io = w.core.invoke(old)
    w.crash('a')
    for time in (15000, 20000):
        w.now = time
        assert w.tick('a', owner_code='TRANSPORT') == 'OWNER_WINDOW'
    w.now = 25000
    new_input = w.ready('a', 2)
    new = w.dispatch('a', 'prepare', new_input, deferred=True)
    w.core.admit(new); new_io = w.core.invoke(new)
    assert w.core.effect(old_io) == 200
    w.core.respond(old_io)
    assert w.core.effect(new_io) == 412
    w.core.respond(new_io)
    w.observe('a', new); w.finish('a')
    assert w.core.calls[new].outcome == {'kind': 'error', 'value': {'code': 'CONFLICT'}}
    assert advance(w, owner_code='TRANSPORT') == 'OWNER_WINDOW'
    assert advance(w, owner_code='TRANSPORT') == 'OWNER_WINDOW'
    assert advance(w, owner_code='TRANSPORT') == 'REPREPARED'
    assert advance(w, owner_code='TRANSPORT') == 'CLAIMED'
    assert advance(w) == 'ACTIVE_OBSERVED'
    assert w.core.head()['owner']['instance'] == 3
    assert w.core.calls[old].outcome['kind'] == 'unknown'
    return w


def late_claim(effect_before):
    w = prepared()
    w.now = 15000
    old = claim_ready(w, 'a')
    w.core.admit(old); old_io = w.core.invoke(old)
    if effect_before:
        assert w.core.effect(old_io) == 200
    w.core.timeout(old)
    w.observe('a', old); w.finish('a', 'DEADLINE')
    for _ in range(10):
        advance(w, 'b', owner_code='TRANSPORT', target_code='TRANSPORT')
        if w.core.head().get('owner_plan', {}).get('phase', {}).get('kind') == 'aborted':
            break
    assert w.core.head()['owner_plan']['phase']['kind'] == 'aborted'
    if not effect_before:
        assert w.core.effect(old_io) == 412
    w.core.respond(old_io)
    assert w.core.calls[old].outcome['kind'] == 'unknown'
    return w


def foreign(creator, terminal):
    w = World()
    value = core.plan_input(operation=99, creator=creator)
    p = operator(w, 'prepare', {'input': value}, principal=creator)
    import json
    d = json.loads(w.core.calls[p].outcome['value']['body'])
    operator(w, 'claim', {'identity': ref(d)}, route='target', principal=creator)
    if terminal:
        operator(w, 'resume', {'identity': ref(d)}, route='target', principal=creator)
    for _ in range(3):
        assert advance(w) == 'FOREIGN'
    return w


def no_suspicion(code):
    w = World()
    for time in (0, 5000, 10000, 15000):
        w.now = time
        assert w.tick('a', owner_code=code) == code
    assert not w.actors['a'].windows
    return w


def intervals():
    w = World()
    for time in (0, 500, 999, 1000, 1999, 2000, 4999):
        w.now = time
        assert w.tick('a', owner_code='TRANSPORT') == 'OWNER_WINDOW'
    w.now = 5000
    assert w.tick('a', owner_code='TRANSPORT') == 'PREPARED'
    return w


def reset_window(kind):
    w = World(); w.warm('a')
    if kind == 'head':
        operator(w, 'storage', {'value': 'technical'}, route='other')
        assert w.core.head()['revision'] == 1 and w.core.head()['head_serial'] == 2
    elif kind == 'success':
        assert advance(w) == 'HEALTHY'
    elif kind == 'invalid':
        assert advance(w, owner_code='INVALID') == 'INVALID'
    else:
        w.crash('a')
    assert advance(w, owner_code='TRANSPORT') == 'OWNER_WINDOW'
    assert w.actors['a'].windows['owner']['count'] == 1
    return w


def bounded(kind):
    w = World()
    if kind == 'calls':
        w.begin('a')
        w.status('a')
        for _ in range(7):
            w.rpc('a', 'guard', {'entry': 'status'})
        try:
            w.rpc('a', 'guard', {'entry': 'status'})
        except Halt as e:
            assert str(e) == 'LIMIT'
        else:
            raise AssertionError('ninth request dispatched')
        w.finish('a', 'LIMIT')
    elif kind == 'deadline':
        w.begin('a', timeout=1); w.status('a'); w.now = 1
        try:
            w.rpc('a', 'guard', {'entry': 'status'})
        except Halt as e:
            assert str(e) == 'DEADLINE'
        else:
            raise AssertionError('request dispatched after original deadline')
        w.finish('a', 'DEADLINE')
    elif kind == 'mutations':
        w.warm('a'); w.now = 10000
        value = w.ready('a'); w.dispatch('a', 'prepare', value)
        try:
            w.dispatch('a', 'prepare', value)
        except Halt as e:
            assert str(e) == 'LIMIT'
        else:
            raise AssertionError('second mutation dispatched')
        w.finish('a', 'LIMIT')
    return w


def maintenance(kind):
    w = World(lifecycle='deleted') if kind == 'deleted' else World(
        storage={'active': 1, 'allocated': 1, 'copy': kind == 'copy',
                 'sweep': kind == 'sweep', 'terminal': kind == 'terminal'})
    assert w.tick('a', owner_code='TRANSPORT') == 'MAINTENANCE'
    return w


def counter(kind):
    w = World(**({'revision': 39, 'serial': 39} if kind == 'revision' else {kind: 39 if kind != 'epoch' else 40}))
    w.warm('a')
    assert advance(w, owner_code='TRANSPORT') == 'COUNTER'
    return w


def mode_off(kind):
    values = [policy(**{kind: False}), policy()]
    w = World(values, active=kind != 'activate')
    if kind == 'activate':
        assert w.tick('a') == 'MODE_DISABLED'
    elif kind == 'takeover':
        w.warm('a')
        assert advance(w, owner_code='TRANSPORT') == 'MODE_DISABLED'
    else:
        w = prepared(w)
        for _ in range(3):
            reason = advance(w, owner_code='TRANSPORT', target_code='TRANSPORT')
        assert reason == 'CANCEL_DISABLED'
    return w


def rank_exhausted():
    w = World()
    operator(w, 'legacy_takeover', {'expected_revision': 1}, route='other')
    operator(w, 'legacy_activate', {'expected_revision': 2}, route='other')
    w.warm('a')
    assert advance(w, owner_code='TRANSPORT', preferred=2) == 'RANK'
    assert w.core.head()['owner']['instance'] == 3
    return w


def sql_unknown():
    w = World(); w.core.spawn('operator', 'client')
    call = w.core.begin('sql', {'request': 'original'}, client='operator', route='owner')
    w.core.complete(call, delivered=False)
    original = deepcopy(w.core.calls[call].outcome)
    assert original['kind'] == 'unknown'
    w = claimed(w)
    assert advance(w) == 'ACTIVE_OBSERVED'
    operator(w, 'guard', {'entry': 'lookup'}, route='target')
    assert w.core.calls[call].outcome == original
    assert len([e for e in w.core.events if e['event'] == 'native_sql_executed']) == 1
    assert w.core.head()['windows'] == ['seed', 'original']
    return w


def authority_change(kind):
    w = claimed() if kind != 'stale-inspection' else prepared()
    if kind == 'stale-inspection':
        w.now += 5000; w.begin('a'); w.status('a')
        identity = deepcopy(w.actors['a'].prepared['identity'])
        operator(w, 'quota', {'quota': 77}, route='other')
        try:
            w.inspect('a', identity)
        except Halt as error:
            assert str(error) == 'STALE'
        else:
            raise AssertionError('changed authority accepted')
        w.finish('a', 'STALE')
    elif kind == 'revoked-admin':
        operator(w, 'acl', {'admins': [12]}, route='other', principal=12)
        assert advance(w) == 'DENIED'
    else:
        w.core.crash('worker-2')
        w.core.spawn('worker-4', 'server', 4, 'target')
        assert advance(w) == 'TARGET'
    return w


def cases():
    rows = []
    steps = ('admit', 'invoke', 'effect', 'respond')
    all_orders = list(schedule(steps, steps))
    # Ten serial extensions let an admission return an existing descriptor
    # without a PUT. Their remaining three no-op cuts can duplicate histories;
    # do not count those as independent racing traces.
    orders = [order for order in all_orders
              if max(order.index((who, 'admit')) for who in ('a', 'b')) <
                 min(order.index((who, 'effect')) for who in ('a', 'b'))]
    assert len(all_orders) == 70 and len(orders) == 60
    for config, lost in product(('same', 'other-policy', 'other-creator'), (False, True)):
        for number, order in enumerate(orders):
            rows.append(Case(f'race-{config}-{int(lost)}-{number:02d}', 'prepare-race',
                             lambda c=config, l=lost, o=order: prepare_race(c, l, o)))
    for name, fn in [('healthy', healthy), ('activate-current', activation),
                     ('cancel-then-activate', cancel_then_activate), ('late-prepare', late_prepare),
                     ('intervals', intervals), ('rank-exhausted', rank_exhausted), ('sql-unknown', sql_unknown)]:
        rows.append(Case(name, name, fn))
    for phase in ('claimed', 'cancelling'):
        rows.append(Case('restart-'+phase, 'restart-pending', lambda p=phase: restart_pending(p)))
    for before in (False, True):
        rows.append(Case('late-claim-'+str(int(before)), 'late-claim', lambda b=before: late_claim(b)))
    for creator, terminal in product((11, 12), (False, True)):
        rows.append(Case(f'foreign-{creator}-{int(terminal)}', 'foreign', lambda c=creator, t=terminal: foreign(c, t)))
    for code in ('INVALID', 'DENIED', 'BUSY', 'LIMIT', 'TARGET', 'LIFECYCLE', 'CORRUPT'):
        rows.append(Case('nondeath-'+code.lower(), 'nondeath', lambda c=code: no_suspicion(c)))
    for kind in ('head', 'success', 'invalid', 'restart'):
        rows.append(Case('reset-'+kind, 'window-reset', lambda k=kind: reset_window(k)))
    for kind in ('calls', 'deadline', 'mutations'):
        rows.append(Case('bound-'+kind, 'bounds', lambda k=kind: bounded(k)))
    for kind in ('copy', 'sweep', 'deleted', 'terminal'):
        rows.append(Case('maintenance-'+kind, 'maintenance', lambda k=kind: maintenance(k)))
    for kind in ('revision', 'serial', 'epoch'):
        rows.append(Case('counter-'+kind, 'counter', lambda k=kind: counter(k)))
    for kind in ('takeover', 'activate', 'cancel'):
        rows.append(Case('mode-off-'+kind, 'mode-off', lambda k=kind: mode_off(k)))
    for kind in ('stale-inspection', 'revoked-admin', 'replacement-worker'):
        rows.append(Case(kind, 'authority-change', lambda k=kind: authority_change(k)))
    assert len(rows) == 402 and len({row.name for row in rows}) == len(rows)
    return rows
