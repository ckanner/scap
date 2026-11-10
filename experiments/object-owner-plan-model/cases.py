"""Finite, named workloads and complete interleavings of their stated macro cuts.

Assertions here require each intended scenario to occur. The separate oracle
does not import this module and independently decides whether its raw history is
legal. A guard-only result explicitly does not implement the guarded operation.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from itertools import product

from model import World, MUTATORS, READERS, HEAD, control_key, marker, plan_input, digest


def result(world, identifier, kind=None, code=None):
    value = world.calls[identifier].outcome
    assert value is not None, identifier
    if kind is not None:
        assert value['kind'] == kind, (identifier, value, kind)
    if code is not None:
        assert value == {'kind': 'error', 'value': {'code': code}}, (identifier, value, code)
    return value


def accepted(world, operation, args=None, **kwargs):
    call = world.request(operation, args, **kwargs)
    result(world, call, 'accepted')
    return call


def prepared(world, operation=101, target=2, mode='takeover', **kwargs):
    identity, call = world.prepare(operation, target, mode, **kwargs)
    result(world, call, 'prepared')
    return {**identity, 'descriptor_hash': digest(result(world, call)['value']['body'])}


def active(world=None, operation=101, target=2, mode='takeover', route='target'):
    world = world or World()
    identity = prepared(world, operation, target, mode)
    accepted(world, 'claim', {'identity': identity}, route=route)
    accepted(world, 'resume', {'identity': identity}, route=route)
    return world, identity


def schedule(left, right, prefix=()):
    """Every linear extension of two fixed per-call action orders, exactly once."""
    if not left and not right:
        yield prefix
    if left:
        yield from schedule(left[1:], right, prefix + (('left', left[0]),))
    if right:
        yield from schedule(left, right[1:], prefix + (('right', right[0]),))


def play(world, calls, order, lose=()):
    for actor, action in order:
        identifier = calls[actor]
        call = world.calls[identifier]
        if action == 'admit':
            world.admit(identifier)
        elif action == 'recover':
            if call.stage == 'recover':
                world.recover(identifier)
        elif action == 'invoke':
            if call.stage == 'ready':
                world.invoke(identifier)
        elif action == 'effect':
            if call.io is not None:
                world.effect(call.io)
        elif action == 'respond':
            if call.io is not None:
                world.respond(call.io, delivered=actor not in lose)
        else:
            raise AssertionError(action)


def claim_cancel(order, lose=()):
    world = World()
    identity = prepared(world)
    calls = {'left': world.begin('claim', {'identity': identity}),
             'right': world.begin('abort', {'identity': identity}, route='other', client='client-2')}
    play(world, calls, order, lose)
    current = marker(world.head())['phase']['kind']
    if current in ('claimed', 'cancelling'):
        accepted(world, 'abort', {'identity': identity}, route='other', principal=12, client='client-2')
    assert marker(world.head())['phase']['kind'] == 'aborted'
    assert world.head()['revision'] == 3 and not world.head()['active']
    seen = world.request('claim', {'identity': identity}, client='client-2')
    result(world, seen, 'observed')
    return world


def recovery_race(order, lose=(), other='resume'):
    world = World()
    identity = prepared(world)
    accepted(world, 'claim', {'identity': identity})
    calls = {'left': world.begin('resume', {'identity': identity}),
             'right': world.begin(other, {'identity': identity},
                                  route='target' if other == 'resume' else 'other', client='client-2')}
    play(world, calls, order, lose)
    phase = marker(world.head())['phase']['kind']
    assert phase in ('active', 'aborted')
    assert phase == 'active' or other == 'abort'
    assert world.head()['revision'] == 3 and world.head()['owner']['epoch'] == 2
    observed = world.request('resume', {'identity': identity}, client='client-2')
    result(world, observed, 'observed')
    assert result(world, observed)['value']['native_session'] is False
    return world


def descriptor_race(same, reverse, lost):
    world = World()
    first = plan_input()
    second = deepcopy(first)
    if not same:
        second['target'] = 3
    calls = [world.begin('prepare', {'input': first}),
             world.begin('prepare', {'input': second}, client='client-2')]
    for call in calls:
        world.admit(call)
        world.invoke(call)
    order = list(reversed(calls)) if reverse else calls
    for call in order:
        world.effect(world.calls[call].io)
        world.respond(world.calls[call].io, delivered=not (lost and call == order[0]))
    stored = world.objects[control_key('descriptor', 11, 101)]['body']
    assert stored == world.calls[order[0]].body
    if not same:
        result(world, order[1], code='CONFLICT')
    else:
        result(world, order[1], 'prepared')
    if lost:
        result(world, order[0], 'unknown')
    return world


def late_after_crash(stage, role, effect_first=False):
    world = World()
    if stage == 'prepare':
        call = world.begin('prepare', {'input': plan_input()})
        identity = {'creator': 11, 'operation': 101}
    else:
        identity = prepared(world)
        if stage in ('resume', 'preserve'):
            accepted(world, 'claim', {'identity': identity})
        if stage == 'preserve':
            accepted(world, 'resume', {'identity': identity})
            call = world.begin('preserve')
        else:
            call = world.begin(stage, {'identity': identity})
    world.admit(call)
    if world.calls[call].stage == 'recover':
        world.recover(call)
    io = world.invoke(call)
    assert io is not None
    if effect_first:
        assert world.effect(io) == 200
    world.crash('client-1' if role == 'client' else 'worker-2')
    if not effect_first:
        assert world.effect(io) == 200
    world.respond(io)
    if role == 'server':
        world.timeout(call)
        world.spawn('worker-4', 'server', 4, 'target')
    observed = world.request('inspect', {'identity': identity}, route='other', client='client-2', principal=12)
    result(world, observed, 'observed')
    result(world, call, 'unknown')
    return world


def cancelling_crash():
    world = World()
    identity = prepared(world)
    call = world.begin('abort', {'identity': identity}, route='other')
    world.admit(call)
    io = world.invoke(call)
    world.crash('worker-3')
    assert world.effect(io) == 200
    world.respond(io)
    world.timeout(call)
    assert marker(world.head())['phase']['kind'] == 'cancelling'
    world.spawn('worker-4', 'server', 4, 'other')
    accepted(world, 'abort', {'identity': identity}, route='other', principal=12, client='client-2')
    assert marker(world.head())['admission']['kind'] == 'cancel'
    assert world.head()['owner'] == {'instance': 1, 'epoch': 1}
    return world


def recovery_metadata(kind, point, revoke):
    world = World()
    identity = prepared(world)
    accepted(world, 'claim', {'identity': identity})
    call = world.begin('resume', {'identity': identity})
    world.admit(call)
    if point == 'after_barrier':
        world.recover(call)
    args = {'admins': [12] if revoke else [11, 12, 13]} if kind == 'acl' else {'quota': 77}
    accepted(world, kind, args, route='other', principal=12, client='client-2')
    if point == 'during_recovery':
        world.recover(call)
    else:
        world.complete(call)
    result(world, call, code='CONFLICT')
    if revoke:
        denied = world.request('resume', {'identity': identity})
        result(world, denied, code='DENIED')
    accepted(world, 'resume', {'identity': identity}, principal=12, client='client-2')
    assert world.head()['admins'] == args.get('admins', [11, 12])
    assert world.head()['quota'] == args.get('quota', 100)
    assert marker(world.head())['admission']['revision'] == 2
    return world


def metadata_reserve(kind, serial_gap):
    world = World(maximum=5, serial=1 + serial_gap)
    identity = prepared(world)
    accepted(world, 'claim', {'identity': identity})
    while world.head()['revision'] < 4 and world.head()['head_serial'] < 4:
        accepted(world, kind, {'admins': [11, 12]} if kind == 'acl' else {'quota': 99})
    call = world.request(kind, {'admins': [11, 12]} if kind == 'acl' else {'quota': 98})
    result(world, call, code='LIMIT')
    accepted(world, 'abort', {'identity': identity}, route='other')
    assert max(world.head()['revision'], world.head()['head_serial']) == 5
    return world


def counters(kind):
    if kind == 'revision':
        world = World(maximum=5, revision=4, serial=4)
    elif kind == 'serial':
        world = World(maximum=5, serial=4)
    else:
        world = World(maximum=5, epoch=5, active=kind != 'activate_epoch')
    if kind == 'activate_epoch':
        identity = prepared(world, target=1, mode='activate')
        accepted(world, 'claim', {'identity': identity}, route='owner')
        accepted(world, 'resume', {'identity': identity}, route='owner')
        assert world.head()['owner']['epoch'] == 5
    else:
        _identity, call = world.prepare()
        result(world, call, code='LIMIT')
    return world


def activate_only(kind):
    world = World(active=kind == 'already_active')
    target = 2 if kind == 'wrong_target' else 1
    identity, call = world.prepare(target=target, mode='activate')
    if kind == 'valid':
        result(world, call, 'prepared')
        identity = {**identity, 'descriptor_hash': digest(result(world, call)['value']['body'])}
        accepted(world, 'claim', {'identity': identity}, route='owner')
        accepted(world, 'resume', {'identity': identity}, route='owner')
        assert world.head()['owner'] == {'instance': 1, 'epoch': 1}
    else:
        result(world, call, code='TARGET')
    return world


def same_worker_takeover():
    world, _identity = active(World(), target=1, route='owner')
    assert world.head()['owner'] == {'instance': 1, 'epoch': 2}
    return world


def replacement(claimed, guard):
    world = World()
    identity = prepared(world)
    if claimed:
        accepted(world, 'claim', {'identity': identity})
    call = world.begin('resume' if claimed else 'claim', {'identity': identity}, expected_worker=guard)
    world.crash('worker-2')
    world.spawn('worker-4', 'server', 4, 'target')
    world.complete(call)
    result(world, call, code='TARGET')
    if claimed:
        accepted(world, 'abort', {'identity': identity}, route='other', principal=12)
    else:
        accepted(world, 'abort', {'identity': identity}, route='other', principal=12)
        accepted(world, 'abort', {'identity': identity}, route='other', principal=12)
    preserved = world.request('preserve', route='other')
    result(world, preserved, 'preserved')
    second = prepared(world, operation=102, target=4)
    accepted(world, 'claim', {'identity': second}, expected_worker=4)
    accepted(world, 'resume', {'identity': second}, expected_worker=4)
    assert world.head()['owner']['instance'] == 4
    return world


def legacy_pending(terminal):
    world = World()
    identity = prepared(world)
    accepted(world, 'claim', {'identity': identity})
    # A legacy SDK can invent this new intent while pending. The server gate,
    # not a client-memory restriction or only the old R+2 rule, must close it.
    expected = world.head()['revision'] + 1
    call = world.begin('legacy_activate', {'expected_revision': expected})
    accepted(world, 'resume' if terminal == 'active' else 'abort', {'identity': identity})
    assert world.head()['revision'] == expected
    world.complete(call)
    result(world, call, code='LEGACY_DISABLED')
    return world


def legacy_old_cas():
    world = World()
    identity = prepared(world)
    call = world.begin('legacy_takeover', {'expected_revision': 1}, route='other')
    world.admit(call)
    io = world.invoke(call)
    accepted(world, 'claim', {'identity': identity})
    accepted(world, 'abort', {'identity': identity})
    assert world.effect(io) == 412
    world.respond(io)
    result(world, call, code='CONFLICT')
    return world


def late_http():
    world = World()
    identity = prepared(world)
    old = world.begin('claim', {'identity': identity})
    world.timeout(old)
    accepted(world, 'abort', {'identity': identity}, client='client-2', route='other')
    accepted(world, 'abort', {'identity': identity}, client='client-2', route='other')
    world.complete(old)
    assert world.calls[old].stage == 'done' and world.calls[old].io is None
    result(world, old, 'unknown')
    assert marker(world.head())['phase']['kind'] == 'aborted'
    return world


def proof_history(lost, admission):
    world, first = active(World(maximum=20))
    historical = deepcopy(marker(world.head()))
    accepted(world, 'sql', {'request': 'q1'})
    accepted(world, 'acl', {'admins': [11, 12, 13]}, route='other')
    accepted(world, 'quota', {'quota': 88}, route='other')
    second = prepared(world, operation=102, target=3)
    blocked = world.request(admission, {'identity': second}, route='other')
    result(world, blocked, code='PROOF_REQUIRED')
    save = world.begin('preserve')
    world.admit(save)
    io = world.invoke(save)
    if lost:
        world.timeout(save)
    world.effect(io)
    world.respond(io, delivered=not lost)
    accepted(world, admission, {'identity': second}, route='other')
    if admission == 'abort':
        accepted(world, 'abort', {'identity': second}, route='other')
    proof = world.objects[control_key('proof', **first)]['body']
    import json
    assert json.loads(proof)['marker'] == historical
    observed = world.request('inspect', {'identity': first}, route='other')
    result(world, observed, 'observed')
    assert result(world, observed)['value']['proof']['marker'] == historical
    if lost:
        result(world, save, 'unknown')
    return world


def historical_deleted():
    world, first = active()
    preserved = world.request('preserve')
    result(world, preserved, 'preserved')
    old = world.objects[control_key('proof', **first)]['body']
    historical = deepcopy(marker(world.head()))
    accepted(world, 'storage', {'value': 'deleted'}, route='other')
    assert world.head()['owner']['epoch'] > historical['phase']['owner']['epoch']
    preserved = world.request('preserve', route='other')
    result(world, preserved, 'preserved')
    assert world.objects[control_key('proof', **first)]['body'] == old
    accepted(world, 'storage', {'value': 'terminal'}, route='other')
    observed = world.request('inspect', {'identity': first}, route='owner', principal=12)
    result(world, observed, 'observed')
    _identity, call = world.prepare(operation=102)
    result(world, call, code='LIFECYCLE')
    assert not world.head()['active']
    return world


def historical_inspect_race(change, point):
    world, first = active(World(maximum=20))
    result(world, world.request('preserve'), 'preserved')
    second = prepared(world, operation=102, target=3)
    accepted(world, 'claim', {'identity': second}, route='other')
    accepted(world, 'abort', {'identity': second}, route='other')
    call = world.begin('inspect', {'identity': first}, route='owner')
    world.admit(call)
    assert world.calls[call].stage == 'inspect_proof'
    if point == 'after_proof':
        world.inspect_proof(call)
    if change == 'acl':
        accepted(world, 'acl', {'admins': [12]}, route='other', principal=12)
    else:
        result(world, world.request('preserve', route='other'), 'preserved')
        third = prepared(world, operation=103, target=1)
        accepted(world, 'claim', {'identity': third}, route='owner')
    world.complete(call)
    result(world, call, code='CONFLICT')
    observed = world.request('inspect', {'identity': first}, principal=12, route='owner')
    result(world, observed, 'observed')
    return world


def pending_guards(phase):
    world = World()
    identity = prepared(world)
    accepted(world, 'claim' if phase == 'claimed' else 'abort', {'identity': identity})
    for entry in MUTATORS:
        call = world.request('guard', {'entry': entry})
        result(world, call, code='PENDING')
    for entry in READERS:
        result(world, world.request('guard', {'entry': entry}), 'read_only')
    result(world, world.request('sql', {'request': 'forbidden'}), code='PENDING')
    result(world, world.request('storage', {'value': 'terminal'}), code='PENDING')
    _identity, call = world.prepare(operation=102)
    result(world, call, 'pending')
    assert control_key('descriptor', 11, 102) not in world.objects
    accepted(world, 'abort', {'identity': identity})
    return world


def incompatible_storage(value, prepared_before):
    world = World()
    identity = prepared(world) if prepared_before else None
    if value == 'terminal':
        accepted(world, 'storage', {'value': 'deleted'})
    accepted(world, 'storage', {'value': value})
    if prepared_before:
        call = world.request('claim', {'identity': identity})
        result(world, call, code='FENCED' if value == 'technical' else 'LIFECYCLE')
    else:
        _identity, call = world.prepare()
        if value == 'technical':
            result(world, call, 'prepared')
        else:
            result(world, call, code='LIFECYCLE')
    return world


def limits(kind):
    world = World()
    if kind == 'metadata':
        call = world.request('prepare', {'input': plan_input()}, io_limit=4)
        result(world, call, code='LIMIT')
        assert control_key('descriptor', 11, 101) in world.objects
        identity = prepared(world)
    elif kind == 'deadline':
        call = world.begin('prepare', {'input': plan_input()}, deadline=world.clock + 14)
        world.admit(call)
        io = world.invoke(call)
        assert io is not None
        world.timeout(call)
        world.effect(io)
        world.respond(io)
        result(world, call, 'unknown')
        assert world.calls[call].stage == 'done'
        identity = prepared(world)
    else:
        call = world.request('prepare', {'input': plan_input()}, deadline=0)
        result(world, call, code='UNKNOWN')
        identity = prepared(world)
    accepted(world, 'claim', {'identity': identity})
    accepted(world, 'abort', {'identity': identity})
    return world


def sql_unknown():
    world = World()
    call = world.begin('sql', {'request': 'q1'}, route='owner')
    world.admit(call)
    io = world.invoke(call)
    world.timeout(call)
    world.effect(io)
    world.respond(io, delivered=False)
    identity = prepared(world)
    accepted(world, 'claim', {'identity': identity})
    accepted(world, 'resume', {'identity': identity})
    replay = world.request('sql', {'request': 'q1'})
    result(world, replay, code='NO_SQL_REPLAY')
    assert len(world.executed) == 1 and world.head()['requests'][-1]['id'] == 'q1'
    result(world, call, 'unknown')
    return world


def lost_prepare_restore(change, effect_before_crash):
    world = World(maximum=20)
    original = plan_input()
    call = world.begin('prepare', {'input': original})
    world.admit(call)
    io = world.invoke(call)
    if effect_before_crash:
        world.effect(io)
    world.crash('client-1')
    if not effect_before_crash:
        world.effect(io)
    world.respond(io, delivered=False)
    result(world, call, 'unknown')
    inspect = world.request('inspect', {'identity': original['identity']}, client='client-2', route='other', principal=12)
    result(world, inspect, 'observed')
    ref = world.restore_ref(original, inspect)
    if change == 'accepted':
        accepted(world, 'claim', {'identity': ref}, client='client-2', principal=12)
    elif change == 'metadata':
        accepted(world, 'quota', {'quota': 77}, client='client-2', principal=12)
    elif change == 'deleted':
        accepted(world, 'storage', {'value': 'deleted'}, client='client-2', principal=12)
        accepted(world, 'storage', {'value': 'terminal'}, client='client-2', principal=12)
    if change != 'none':
        altered = deepcopy(original)
        altered['expected_revision'] = world.head()['revision']
        altered['expected_head_serial'] = world.head()['head_serial']
        conflict = world.request('prepare', {'input': altered}, client='client-2', route='other', principal=12)
        result(world, conflict, code='CONFLICT')
    again = world.request('prepare', {'input': original}, client='client-2', route='other', principal=12)
    result(world, again, 'prepared')
    assert world.restore_ref(original, again) == ref
    # Current ADMIN is checked before even returning an input mismatch/history.
    bad = deepcopy(original)
    bad['target'] = 3
    denied = world.request('prepare', {'input': bad}, client='client-2', principal=99)
    result(world, denied, code='DENIED')
    if change == 'none':
        accepted(world, 'claim', {'identity': ref}, client='client-2', principal=12)
    if change in ('none', 'accepted'):
        accepted(world, 'resume', {'identity': ref}, client='client-2', principal=12)
        assert marker(world.head())['phase']['kind'] == 'active'
    else:
        fenced = world.request('claim', {'identity': ref}, client='client-2', principal=12)
        result(world, fenced, code='FENCED' if change == 'metadata' else 'LIFECYCLE')
    return world


def missing_permanent_descriptor(kind):
    world = World(maximum=20)
    reference = prepared(world)
    accepted(world, 'claim', {'identity': reference})
    if kind in ('terminal', 'superseded'):
        accepted(world, 'resume', {'identity': reference})
    if kind == 'superseded':
        result(world, world.request('preserve'), 'preserved')
        newer = prepared(world, operation=102, target=3)
        accepted(world, 'claim', {'identity': newer}, route='other')
        accepted(world, 'abort', {'identity': newer}, route='other')
    world.fault_remove_descriptor(reference)
    _identity, call = world.prepare(operation=101)
    result(world, call, code='CORRUPT')
    assert control_key('descriptor', **reference) not in world.objects
    return world


def future_proof(changed_head):
    world, first = active(World(maximum=20))
    result(world, world.request('preserve'), 'preserved')
    second = prepared(world, operation=102, target=3)
    accepted(world, 'claim', {'identity': second}, route='other')
    accepted(world, 'abort', {'identity': second}, route='other')
    world.fault_future_proof(first)
    call = world.begin('inspect', {'identity': first}, route='owner')
    world.admit(call)
    world.inspect_proof(call)
    if changed_head:
        accepted(world, 'quota', {'quota': 77}, route='other')
    world.inspect_finish(call)
    result(world, call, code='CONFLICT' if changed_head else 'CORRUPT')
    return world


def owner_binding_fault(changed_head):
    world = World(maximum=20)
    reference = prepared(world)
    accepted(world, 'claim', {'identity': reference})
    descriptor_before = deepcopy(world.objects[control_key('descriptor', **reference)])
    world.fault_owner_binding()
    call = world.begin('inspect', {'identity': reference}, route='owner')
    world.admit(call)
    world.inspect_proof(call)
    if changed_head:
        accepted(world, 'quota', {'quota': 77}, route='other')
    world.inspect_finish(call)
    result(world, call, code='CONFLICT' if changed_head else 'CORRUPT')
    assert world.objects[control_key('descriptor', **reference)] == descriptor_before
    assert control_key('proof', **reference) not in world.objects
    return world


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    build: object


def cases():
    """Fixed finite denominator; no random seeds, adaptive workloads or retries."""
    result = []
    put_chain = ('admit', 'invoke', 'effect', 'respond')
    recovery_chain = ('admit', 'recover', 'invoke', 'effect', 'respond')
    for family, left, right, builder in (
        ('claim_cancel', put_chain, put_chain, lambda order, lose: claim_cancel(order, lose)),
        ('two_resume', recovery_chain, recovery_chain, lambda order, lose: recovery_race(order, lose)),
        ('resume_abort', recovery_chain, put_chain, lambda order, lose: recovery_race(order, lose, 'abort'))):
        for index, order in enumerate(schedule(left, right)):
            for lost in (False, True):
                lose = ('left', 'right') if lost else ()
                result.append(Case(f'{family}-{index:03d}-lost{int(lost)}', family,
                    lambda order=order, lose=lose, builder=builder: builder(order, lose)))
    def add(name, function, *args):
        family = name.split('-')[0]
        result.append(Case(name, family, lambda function=function, args=args: function(*args)))
    for values in product((False, True), repeat=3):
        add('descriptor-' + ''.join(str(int(v)) for v in values), descriptor_race, *values)
    for stage, role, effected in product(('prepare', 'claim', 'resume', 'preserve'), ('client', 'server'), (False, True)):
        add(f'crash-{stage}-{role}-{int(effected)}', late_after_crash, stage, role, effected)
    add('cancelling-restart', cancelling_crash)
    for kind, point in product(('acl', 'quota'), ('during_recovery', 'after_barrier')):
        for revoke in ((False, True) if kind == 'acl' else (False,)):
            add(f'metadata-{kind}-{point}-{int(revoke)}', recovery_metadata, kind, point, revoke)
    for kind, gap in product(('acl', 'quota'), (0, 1)):
        add(f'reserve-{kind}-{gap}', metadata_reserve, kind, gap)
    for kind in ('revision', 'serial', 'epoch', 'activate_epoch'):
        add('counter-' + kind, counters, kind)
    for kind in ('valid', 'already_active', 'wrong_target'):
        add('activate-' + kind, activate_only, kind)
    add('sameworker-takeover', same_worker_takeover)
    for claimed, guard in product((False, True), (2, 4)):
        add(f'replacement-{int(claimed)}-{guard}', replacement, claimed, guard)
    for terminal in ('active', 'aborted'):
        add('legacy-' + terminal, legacy_pending, terminal)
    add('legacy-original-cas', legacy_old_cas)
    add('latehttp-after-abort', late_http)
    for lost, admission in product((False, True), ('claim', 'abort')):
        add(f'proof-{int(lost)}-{admission}', proof_history, lost, admission)
    add('deleted-historical-owner', historical_deleted)
    for change, point in product(('acl', 'marker'), ('before_proof', 'after_proof')):
        add(f'inspect-{change}-{point}', historical_inspect_race, change, point)
    for phase in ('claimed', 'cancelling'):
        add('guards-' + phase, pending_guards, phase)
    for value, before in product(('technical', 'copy', 'sweep', 'deleted', 'terminal'), (False, True)):
        add(f'storage-{value}-{int(before)}', incompatible_storage, value, before)
    for kind in ('metadata', 'deadline', 'expired'):
        add('limits-' + kind, limits, kind)
    add('sql-unknown-not-replayed', sql_unknown)
    for change, before in product(('none', 'accepted', 'metadata', 'deleted'), (False, True)):
        add(f'preparelost-{change}-{int(before)}', lost_prepare_restore, change, before)
    for kind in ('pending', 'terminal', 'superseded'):
        add('damage-' + kind, missing_permanent_descriptor, kind)
    for changed in (False, True):
        add(f'damage-future-proof-{int(changed)}', future_proof, changed)
        add(f'damage-owner-binding-{int(changed)}', owner_binding_fault, changed)
    return result
