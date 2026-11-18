"""Semantic corruptions. Success requires the exact independent rule named here."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib

from model import World, policy, core, canonical
from cases import (prepared, claimed, healthy, restart_pending, late_prepare, foreign,
                   bounded, counter, authority_change, claim_ready, reset_window)


@dataclass(frozen=True)
class Control:
    name: str
    rule: str
    build: object


def events(trace, kind):
    return [e for e in trace['controller'] if e['event'] == kind]


def rehash(p):
    value = {k: v for k, v in p.items() if k not in ('digest', 'nonces')}
    digest = hashlib.sha256(b'SCAPOWNERPOLICYMODEL1\0' + canonical(value).encode()).digest()
    p['digest'] = digest.hex()
    p['nonces'] = dict(zip(('claim', 'cancel', 'activate', 'abort'),
                          [int.from_bytes(digest[i:i+8], 'big') for i in range(0, 32, 8)]))


def insert(trace, anchor, value):
    row = {'sequence': 0, 'at': anchor['at'], 'time': anchor['time'], 'actor': anchor['actor'], **value}
    trace['controller'].insert(trace['controller'].index(anchor), row)


def mutate(base, change, name):
    trace = base().trace('negative-' + name)
    change(trace)
    for i, event in enumerate(trace['controller'], 1):
        event['sequence'] = i
    return trace


def decision(trace, target=2, mode='takeover', report=-1):
    anchor = events(trace, 'report')[report]
    prior = [e for e in events(trace, 'head') if e['sequence'] < anchor['sequence'] and e['role'] == 'authority'][-1]
    import json
    h = json.loads(prior['snapshot']['body'])
    p = trace['controller'][0]['policies'][anchor['actor']]
    value = {'identity': {'creator': p['principal'], 'operation': h['head_serial']},
             'target': target, 'mode': mode, 'expected_revision': h['revision'],
             'expected_head_serial': h['head_serial'], 'nonces': deepcopy(p['nonces'])}
    insert(trace, anchor, {'event': 'decision', 'method': 'prepare', 'value': value})


def raw_rpc(w, method, args, route='other', guard=None):
    a, t = w.actors['a'], w.actors['a'].tick
    call = w.core.begin(method, args, client=a.client, principal=a.policy['principal'],
                        route=route, expected_worker=guard)
    t['calls'] += 1
    t['mutations'] += int(method in ('prepare', 'claim', 'resume', 'abort'))
    w.emit('rpc', actor='a', tick=t['id'], call=call, method=method)
    w.core.complete(call); w.observe('a', call)
    return call


def ninth_call():
    w = World(); w.begin('a'); w.status('a')
    for _ in range(7):
        w.rpc('a', 'guard', {'entry': 'status'})
    raw_rpc(w, 'guard', {'entry': 'status'})
    w.finish('a')
    return w


def second_mutation():
    w = World(); w.warm('a'); w.now = 10000
    value = w.ready('a'); w.dispatch('a', 'prepare', value)
    w.emit('decision', actor='a', method='prepare', value=value)
    raw_rpc(w, 'prepare', {'input': value}); w.finish('a')
    return w


def business_sql():
    w = World(); w.begin('a'); w.status('a')
    raw_rpc(w, 'sql', {'request': 'controller-must-not-execute'}, route='owner')
    w.finish('a')
    return w


def wrong_target_guard():
    w = prepared(); w.now = 15000
    # Build exactly the original legal decision, then deliberately choose the
    # wrong guarded endpoint. The core correctly rejects TARGET; policy still
    # must reject that outbound call before relying on a safe server rejection.
    w.begin('a'); h = w.status('a')
    w.probe('a', h['owner']['instance'], 'TRANSPORT')
    d = w.inspect('a', w.actors['a'].prepared['identity'])
    w.probe('a', d['target'], slot='target'); w.inspect('a', d['identity'])
    w.emit('decision', actor='a', method='claim', value=d)
    raw_rpc(w, 'claim', {'identity': d['identity'] | {'descriptor_hash': core.digest(d)}}, route='other', guard=3)
    w.finish('a')
    return w


def controls():
    rows = []
    def add(name, rule, base, change=lambda _t: None):
        rows.append(Control(name, rule, lambda b=base, c=change, n=name: mutate(b, c, n)))
    def change_policy(t, key, value, repair=True):
        p = t['controller'][0]['policies']['a']; p[key] = value
        if repair: rehash(p)
    add('alter-policy-without-hash', 'full-policy-digest', healthy,
        lambda t: change_policy(t, 'authority', 'unbound', False))
    add('inflate-fixed-call-limit', 'fixed-limits', healthy,
        lambda t: change_policy(t, 'limits', policy()['limits'] | {'calls': 9}))
    add('wrong-full-scope', 'fixed-scope-and-rank', healthy,
        lambda t: change_policy(t, 'scope', core.SCOPE | {'generation': 2}))
    add('extend-original-deadline', 'original-deadline', healthy,
        lambda t: events(t, 'tick')[0].update(deadline=30001))
    add('retrofit-recovery-budget', 'recovery-budget-fixed-at-start', lambda: restart_pending('claimed'),
        lambda t: next(e for e in events(t, 'tick') if e['recovery']).update(recovery=False))
    def late(t):
        tick = events(t, 'tick')[0]; tick['deadline'] = 1
        for e in t['controller']:
            if e['sequence'] > tick['sequence']: e['time'] = max(1, e['time'])
    add('request-after-deadline', 'no-late-dispatch', healthy, late)
    add('actual-ninth-request', 'http-cap', ninth_call)
    add('actual-second-mutation', 'single-mutation', second_mutation)
    add('hide-request-denominator', 'full-call-denominator', healthy,
        lambda t: events(t, 'report')[0].update(calls=1))
    add('controller-executes-sql', 'no-business-sql', business_sql)
    add('call-uses-other-principal', 'call-policy-binding', healthy,
        lambda t: change_policy(t, 'principal', 12))
    add('invent-head-etag', 'exact-head-observation', healthy,
        lambda t: events(t, 'head')[0]['snapshot'].update(etag='"invented"'))
    add('probe-another-worker', 'guarded-probe', healthy,
        lambda t: events(t, 'probe')[0].update(worker=2))
    def nondeath(t):
        events(t, 'network_failure')[0]['code'] = 'INVALID'
        events(t, 'probe')[0]['code'] = 'INVALID'
    add('count-invalid-as-death', 'only-unreachable-counts', prepared, nondeath)
    add('reuse-nonconfirmation-read', 'fresh-independent-confirmation', prepared,
        lambda t: next(e for e in events(t, 'head') if e['role'] == 'confirmation').update(role='probe'))
    add('one-failure-is-mature', 'failure-window', prepared,
        lambda t: events(t, 'probe')[0]['result'].update(mature=True))
    add('invent-policy-nonce', 'policy-and-operation', prepared,
        lambda t: events(t, 'decision')[0]['value']['nonces'].update(claim=1))
    add('unconfigured-target', 'policy-mode-and-target', prepared,
        lambda t: events(t, 'decision')[0]['value'].update(target=4))
    add('ignore-counter-reserve', 'prepare-counter-and-phase', lambda: counter('serial'), decision)
    add('rebase-expected-revision', 'original-base', prepared,
        lambda t: events(t, 'decision')[0]['value'].update(expected_revision=2))
    def first_winner(t):
        next(e for e in events(t, 'decision') if e['method'] == 'prepare' and
             e['value']['target'] == 3 and e['time'] > 25000)['value']['target'] = 2
    add('replace-actual-first-winner', 'fixed-first-winner', late_prepare, first_winner)
    def one_failure():
        w = World(); w.tick('a', owner_code='TRANSPORT'); return w
    add('prepare-before-window', 'mature-owner-required', one_failure, decision)
    add('takeover-healthy-active', 'healthy-active-readonly', healthy,
        lambda t: decision(t, report=0))
    add('automatic-same-rank', 'increasing-rank', prepared,
        lambda t: events(t, 'decision')[0]['value'].update(target=1))
    def no_target(t):
        row = next(e for e in events(t, 'probe') if e['slot'] == 'target')
        t['controller'].remove(row)
    add('prepare-without-target-probe', 'target-health-required', prepared, no_target)
    def no_second_inspect(t):
        row = events(t, 'descriptor')[-1]
        t['controller'].remove(row)
    add('claim-without-final-inspect', 'inspect-before-mutation', claimed, no_second_inspect)
    def forget_prepared(t):
        row = next(e for e in events(t, 'response') if e['outcome']['kind'] == 'prepared')
        t['controller'].remove(row)
    add('claim-without-verified-reprepare', 'prepared-original-base', claimed, forget_prepared)
    add('override-foreign-marker', 'foreign-marker', lambda: foreign(12, False),
        lambda t: decision(t, report=0))
    add('erase-original-unknown', 'unknown-not-backfilled', late_prepare,
        lambda t: next(e for e in events(t, 'report') if e['unknowns']).update(unknowns=[]))
    add('observation-claims-historical-ack', 'observation-not-ack', healthy,
        lambda t: events(t, 'report')[0].update(historical_ack=True))
    add('observation-claims-native-session', 'observation-not-ack', healthy,
        lambda t: events(t, 'report')[0].update(native_session=True))
    add('actual-wrong-target-guard', 'target-guard', wrong_target_guard)
    def omit_tick(t):
        cutoff = events(t, 'tick')[-1]['sequence']
        t['controller'] = [e for e in t['controller'] if e['sequence'] < cutoff]
    add('omit-real-controller-calls', 'all-controller-calls', healthy, omit_tick)
    def changed_authority(t):
        anchor = events(t, 'report')[-1]
        d = events(t, 'descriptor')[-1]['body']
        insert(t, anchor, {'event': 'decision', 'method': 'prepare', 'value':
            {k: deepcopy(d[k]) for k in ('identity', 'target', 'mode', 'expected_revision', 'expected_head_serial', 'nonces')}})
    add('mutate-after-authority-change', 'descriptor-current-authority',
        lambda: authority_change('stale-inspection'), changed_authority)
    add('invent-response-value', 'actual-response', healthy,
        lambda t: events(t, 'response')[0]['outcome']['value'].update(native_session=True))
    add('invent-descriptor-target', 'actual-descriptor', claimed,
        lambda t: events(t, 'descriptor')[0]['body'].update(target=3))
    def old_head(t):
        rows = [e for e in events(t, 'head') if e['role'] == 'authority']
        rows[1].update(**{k: deepcopy(rows[0][k]) for k in ('call', 'read', 'snapshot')})
    add('reuse-prior-tick-authority', 'current-tick-observation', healthy, old_head)
    def confirmation_before_failure(t):
        fail = events(t, 'network_failure')[0]
        head = next(e for e in events(t, 'head') if e['role'] == 'confirmation')
        t['controller'].remove(fail)
        index = t['controller'].index(head)+1
        fail['at'] = head['at']
        t['controller'].insert(index, fail)
    add('confirmation-predates-failure', 'fresh-independent-confirmation', prepared, confirmation_before_failure)
    def duplicate_inspect(t):
        rows = events(t, 'descriptor')
        rows[-1]['call'] = rows[-2]['call']
    add('same-inspect-counted-twice', 'inspect-before-mutation', claimed, duplicate_inspect)
    def forged_reason(t):
        next(e for e in events(t, 'report') if e['reason'] == 'INVALID')['reason'] = 'WAITING'
        events(t, 'probe')[-1]['result']['mature'] = True
    add('report-cannot-preserve-failed-window', 'failure-window', lambda: reset_window('invalid'), forged_reason)
    assert len(rows) == 40 and len({row.name for row in rows}) == len(rows)
    return rows
