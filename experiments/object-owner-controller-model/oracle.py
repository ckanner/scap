"""Independent controller policy checker over authoritative core event references.

Imports only the existing independent HEAD8 oracle, never this model, cases or
production modules. Controller summaries do not decide acceptance.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


class Violation(AssertionError):
    def __init__(self, rule, detail=''):
        self.rule = rule
        super().__init__(f'{rule}: {detail}')


def require(value, rule, detail=''):
    if not value:
        raise Violation(rule, detail)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def core_checker():
    name = '_controller_independent_core_oracle'
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'object-owner-plan-model/oracle.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CORE = core_checker()
HEAD = 'scap-object/v1/1/7/91/head'
METHODS = {'guard', 'inspect', 'prepare', 'claim', 'resume', 'abort'}
MUTATIONS = {'prepare', 'claim', 'resume', 'abort'}


def audit(trace, strict=False):
    require(type(trace) is dict and trace.get('schema') == 1, 'schema')
    raw = trace['protocol']['events']
    # Native/object/caller knowledge is checked from the raw core trace, not
    # the policy sidecar or its producer's final state.
    core_result = CORE.audit(trace['protocol'])
    calls = {e['call']: e for e in raw if e['event'] == 'http_dispatched'}
    responses = {e['call']: e for e in raw if e['event'] == 'caller_observed'}
    get_requests = {e['io']: e for e in raw if e['event'] == 's3_get_invoked'}
    gets = {e['io']: e for e in raw if e['event'] == 's3_get_response'}
    starts = {e['process']: e for e in raw if e['event'] == 'process_started'}
    exits = {e['process']: e for e in raw if e['event'] == 'process_exited'}
    actors, owners, observed_calls, clients = {}, {}, set(), set()
    previous_at = previous_time = 0
    totals = {'ticks': 0, 'mutations': 0, 'restarts': 0, 'probe_failures': 0}
    for number, event in enumerate(trace['controller'], 1):
        require(event['sequence'] == number, 'event-order')
        at, now, kind = event['at'], event['time'], event['event']
        require(type(at) is int and previous_at <= at < len(raw) and
                type(now) is int and now >= previous_time, 'original-cut-and-clock')
        previous_at, previous_time = at, now
        if kind == 'initial':
            require(number == 1 and set(event['policies']) == {'a', 'b'}, 'finite-actors')
            for name, p in event['policies'].items():
                q = {k: deepcopy(v) for k, v in p.items() if k not in ('digest', 'nonces')}
                full = hashlib.sha256(b'SCAPOWNERPOLICYMODEL1\0' + canonical(q).encode()).digest()
                words = dict(zip(('claim', 'cancel', 'activate', 'abort'),
                                 [int.from_bytes(full[i:i+8], 'big') for i in range(0, 32, 8)]))
                require(p['digest'] == full.hex() and p['nonces'] == words and
                        len(set(words.values())) == 4 and all(words.values()), 'full-policy-digest')
                require(p['scope'] == CORE.SCOPE_VALUE and p['workers'] == [[1, 0, 'owner'], [2, 1, 'target'], [3, 2, 'other']], 'fixed-scope-and-rank')
                require(p['limits'] == {'calls': 8, 'mutations': 1, 'timeout': 30000, 'recovery': 1800000,
                                        'failures': 3, 'interval': 1000, 'span': 5000}, 'fixed-limits')
                client = event['clients'][name]
                require(client in starts and starts[client]['sequence'] <= at, 'controller-incarnation')
                actors[name] = {'policy': p, 'client': client, 'base': None, 'windows': {}, 'prepared': None,
                                'recovery': False, 'tick': None}
                clients.add(client)
            continue
        require(event.get('actor') in actors, 'actor')
        a = actors[event['actor']]
        p, t = a['policy'], a['tick']
        if kind == 'restart':
            require(t is None and event['previous'] == a['client'] and a['client'] in exits and
                    exits[a['client']]['sequence'] <= at and event['client'] in starts and
                    starts[event['client']]['sequence'] <= at and event['client'] not in clients, 'restart-incarnation')
            clients.add(event['client'])
            a.update(client=event['client'], base=None, windows={}, prepared=None, recovery=False)
            totals['restarts'] += 1
            continue
        if kind == 'tick':
            require(t is None, 'single-tick')
            require(event['recovery'] == a['recovery'], 'recovery-budget-fixed-at-start')
            maximum = p['limits']['recovery' if event['recovery'] else 'timeout']
            require(now < event['deadline'] <= now+maximum, 'original-deadline')
            a['tick'] = {'id': event['tick'], 'deadline': event['deadline'], 'recovery': event['recovery'],
                         'calls': 0, 'mutations': 0, 'head': None, 'health': {}, 'inspected': None,
                         'marker_descriptor': None, 'inspection_count': 0, 'last_read': None,
                         'descriptor_head': None, 'failed_probe': None, 'decision': None,
                         'rpc_ids': set(), 'inspection_calls': {}, 'used_health_reads': set()}
            totals['ticks'] += 1
            continue
        require(t is not None, 'active-tick')
        if kind == 'rpc':
            require(event['tick'] == t['id'], 'tick-call-binding')
            require(now < t['deadline'], 'no-late-dispatch')
            require(t['calls'] < 8, 'http-cap')
            method, call = event['method'], event['call']
            require(method in METHODS, 'no-business-sql')
            require(call not in observed_calls and call in calls and calls[call]['sequence'] <= at,
                    'actual-call-once')
            c = calls[call]
            require(c['operation'] == method and c['client'] == a['client'] and
                    c['principal'] == p['principal'] and c['scope'] == p['scope'], 'call-policy-binding')
            if method in MUTATIONS:
                require(t['mutations'] == 0, 'single-mutation')
                require(t['decision'] is not None and t['decision']['method'] == method, 'verified-decision')
                value = t['decision']['value']
                if method == 'prepare':
                    require(c['args'] == {'input': value}, 'original-input')
                else:
                    require(c['args'] == {'identity': value['identity'], 'descriptor_hash': digest(value)}, 'original-reference')
                    if method in ('claim', 'resume'):
                        require(c['expected_worker'] == value['target'] and
                                c['route'] == p['workers'][value['target']-1][2], 'target-guard')
                t['decision'] = None; t['mutations'] += 1; totals['mutations'] += 1
            elif method == 'guard':
                require(c['args'] == {'entry': 'status'}, 'no-business-sql')
            observed_calls.add(call); owners[call] = event['actor']; t['calls'] += 1
            t['rpc_ids'].add(call)
        elif kind == 'response':
            call = event['call']
            require(call in t['rpc_ids'], 'current-tick-observation')
            require(owners.get(call) == event['actor'] and call in responses and
                    calls[call]['client'] == a['client'] and
                    responses[call]['sequence'] <= at and event['outcome'] ==
                    {'kind': responses[call]['kind'], 'value': responses[call]['value']}, 'actual-response')
            if event['outcome']['kind'] == 'prepared':
                a['prepared'] = json.loads(event['outcome']['value']['body'])
            if event['outcome']['kind'] == 'accepted':
                a['recovery'] = event['outcome']['value']['head']['owner_plan']['phase']['kind'] == 'claimed'
            if event['outcome']['kind'] == 'unknown' or (event['outcome']['kind'] == 'error' and
                    event['outcome']['value']['code'] != 'MISSING_DESCRIPTOR'):
                a['windows'] = {}
        elif kind == 'head':
            io, call = event['read'], event['call']
            require(call in t['rpc_ids'], 'current-tick-observation')
            require(owners.get(call) == event['actor'] and io in gets and
                    get_requests[io]['call'] == call and get_requests[io]['key'] == HEAD and
                    gets[io]['sequence'] <= at and gets[io]['delivered'] and
                    event['snapshot'] == gets[io]['value'], 'exact-head-observation')
            snap, role = event['snapshot'], event['role']
            h = json.loads(snap['body'])
            require(h['scope'] == p['scope'], 'full-scope')
            if role == 'authority':
                require(t['head'] is None, 'one-original-authority')
                if a['base'] != snap:
                    a['windows'] = {}; a['prepared'] = None
                a['base'], t['head'] = snap, h
                a['recovery'] = h.get('owner_plan', {}).get('phase', {}).get('kind') == 'claimed'
            else:
                require(role in ('probe', 'confirmation'), 'head-role')
                if snap != a['base']:
                    a['windows'] = {}
            t['last_read'] = {'role': role, 'snapshot': snap, 'call': call, 'sequence': number}
        elif kind == 'network_failure':
            require(now < t['deadline'] and t['calls'] < 8, 'probe-budget')
            t['calls'] += 1; totals['probe_failures'] += 1
            t['failed_probe'] = event
            if event['code'] not in ('TRANSPORT', 'DEADLINE'):
                a['windows'] = {}
        elif kind == 'probe':
            last, worker, slot, code = t['last_read'], event['worker'], event['slot'], event['code']
            require(slot in ('owner', 'target') and worker in (1, 2, 3), 'probe-identity')
            require(last is not None and last['snapshot'] == a['base'], 'fresh-independent-confirmation')
            require(last['call'] not in t['used_health_reads'], 'fresh-probe-read')
            if code == 'OK':
                c = calls[last['call']]
                require(last['role'] == 'probe' and c['expected_worker'] == worker and
                        c['route'] == p['workers'][worker-1][2], 'guarded-probe')
                a['windows'].pop(slot, None)
                expected = {'healthy': True, 'mature': False}
            else:
                failure = t['failed_probe']
                require(code in ('TRANSPORT', 'DEADLINE') and failure is not None and
                        all(failure[k] == event[k] for k in ('worker', 'slot', 'code')),
                        'only-unreachable-counts')
                require(last['role'] == 'confirmation' and
                        last['sequence'] > failure['sequence'] and
                        calls[last['call']]['route'] != p['workers'][worker-1][2], 'fresh-independent-confirmation')
                old = a['windows'].get(slot)
                if old is None or old['worker'] != worker:
                    old = {'worker': worker, 'first': now, 'last': now, 'count': 1}
                elif now-old['last'] >= 1000:
                    old = old | {'last': now, 'count': min(3, old['count']+1)}
                a['windows'][slot] = old
                expected = {'healthy': False, 'mature': old['count'] >= 3 and now-old['first'] >= 5000}
            require(event['result'] == expected, 'failure-window')
            t['used_health_reads'].add(last['call'])
            t['health'][slot] = expected
        elif kind in ('descriptor', 'descriptor_missing'):
            call = event['call']
            require(call in t['rpc_ids'], 'current-tick-observation')
            require(owners.get(call) == event['actor'] and calls[call]['operation'] == 'inspect' and
                    call in responses and responses[call]['sequence'] <= at, 'actual-descriptor-observation')
            value = responses[call]
            if kind == 'descriptor_missing':
                require(value['kind'] == 'error' and value['value']['code'] == 'MISSING_DESCRIPTOR', 'actual-missing')
                t['inspected'] = None
            else:
                require(value['kind'] == 'observed' and event['body'] == json.loads(value['value']['prepared']['body']), 'actual-descriptor')
                t['descriptor_head'] = value['value']['current_head']
                d = event['body']
                if (t['descriptor_head'] != t['head'] or d['identity']['creator'] != p['principal'] or
                        d['nonces'] != p['nonces'] or not p['modes'][d['mode']] or
                        (d['identity']['operation'] == t['head']['head_serial'] and
                         (d['base']['head_hash'] != digest(t['head']) or d['base']['etag'] != a['base']['etag']))):
                    a['windows'] = {}
                t['inspected'] = event['body']; t['inspection_count'] += 1
                t['inspection_calls'].setdefault(digest(event['body']), set()).add(call)
                if t['head'].get('owner_plan', {}).get('identity') == event['body']['identity']:
                    t['marker_descriptor'] = event['body']
        elif kind == 'decision':
            require(t['decision'] is None and now < t['deadline'], 'decision-budget')
            decide(a, event['method'], event['value'])
            t['decision'] = event
        elif kind == 'report':
            require(event['tick'] == t['id'] and event['calls'] == t['calls'] and
                    event['mutations'] == t['mutations'], 'full-call-denominator')
            expected = sorted(c for c, r in responses.items() if calls[c]['client'] == a['client'] and
                              r['sequence'] <= at and r['kind'] == 'unknown')
            require(event['unknowns'] == expected, 'unknown-not-backfilled')
            require(event['native_session'] is False and event['historical_ack'] is False, 'observation-not-ack')
            # A human-readable report reason never changes policy knowledge.
            # Failure resets above come only from bound observations/inputs.
            a['tick'] = None
        else:
            raise Violation('known-event', kind)
    require(actors and all(a['tick'] is None for a in actors.values()), 'closed-controller-history')
    require({c for c, v in calls.items() if v['client'] in clients} == observed_calls, 'all-controller-calls')
    if trace['name'].startswith('race-'):
        race_witness(trace, raw, calls, responses)
    if strict:
        named_witness(trace, raw, calls, responses)
    return {'status': 'PASSED', **totals, 'core_calls': core_result['calls'],
            'core_unknowns': core_result['caller_unknowns'], 'native_http_s3': 'NOT_RUN'}


def race_witness(trace, raw, calls, responses):
    """Require actual two-PUT races and recovery, independent of case assertions."""
    name = re.fullmatch(r'race-(same|other-policy|other-creator)-([01])-([0-5][0-9])', trace['name'])
    require(name is not None, 'race-inventory-name')
    config, lost, _ = name.groups()
    witness = trace.get('witness', {})
    require(witness.get('family') == 'prepare-race' and witness.get('config') == config and
            witness.get('lost') is bool(int(lost)), 'race-declared-input')
    first = [e for e in trace['controller'] if e['event'] == 'rpc' and e['method'] == 'prepare'][:2]
    require(len(first) == 2 and {e['actor'] for e in first} == {'a', 'b'}, 'race-two-controllers')
    selected = {e['call']: e['actor'] for e in first}
    require({calls[c]['args']['input']['target'] for c in selected} == {2, 3} and
            all(calls[c]['args']['input']['expected_revision'] == 1 and
                calls[c]['args']['input']['expected_head_serial'] == 1 for c in selected), 'race-same-base-candidates')
    put_calls = {e['io']: e['call'] for e in raw if e['event'] == 's3_put_invoked' and e['call'] in selected}
    require(len(put_calls) == 2, 'race-two-real-puts')
    order, first_effect, successes = [], None, []
    for e in raw:
        if e['event'] == 'http_admitted' and e['call'] in selected:
            order.append([selected[e['call']], 'admit'])
        elif e['event'] == 's3_put_invoked' and e['call'] in selected:
            order.append([selected[e['call']], 'invoke'])
        elif e['event'] in ('s3_put_effect', 's3_put_response') and e['io'] in put_calls:
            action = 'effect' if e['event'] == 's3_put_effect' else 'respond'
            call = put_calls[e['io']]
            order.append([selected[call], action])
            if action == 'effect' and e['result']['status'] == 200:
                first_effect = first_effect or call
                successes.append(call)
    require(order == witness['schedule'] and len(order) == 8 and
            max(order.index([a, 'admit']) for a in ('a', 'b')) <
            min(order.index([a, 'effect']) for a in ('a', 'b')), 'race-actual-schedule')
    require(len(successes) == (2 if config == 'other-creator' else 1), 'race-first-winner')
    require(responses[first_effect]['kind'] == ('unknown' if lost == '1' else 'prepared'), 'race-actual-loss')
    require(len([e for e in trace['controller'] if e['event'] == 'restart']) == 4, 'race-loss-of-local-state')
    claim_puts = {e['io']: e['call'] for e in raw if e['event'] == 's3_put_invoked' and
                  calls[e['call']]['operation'] == 'claim'}
    require(len(claim_puts) == (1 if config == 'other-policy' else 2), 'race-claim-candidates')
    effects = [e for e in raw if e['event'] == 's3_put_effect' and e['io'] in claim_puts]
    require(len([e for e in effects if e['result']['status'] == 200]) == 1, 'race-single-claim-winner')
    writes = {e['io']: e for e in raw if e['event'] == 's3_put_invoked'}
    heads = [json.loads(e['result']['value']['body']) for e in raw if e['event'] == 's3_put_effect' and
             e['result']['status'] == 200 and writes[e['io']]['key'] == HEAD]
    require(heads and heads[-1]['active'] and heads[-1]['owner_plan']['phase']['kind'] == 'active', 'race-active-recovery')
    if config != 'other-creator':
        require(heads[-1]['owner']['instance'] == calls[first_effect]['args']['input']['target'], 'race-actual-target-adopted')


def expected_names():
    """Independent frozen inventory; do not import the generator's cases list."""
    names = {f'race-{config}-{lost}-{n:02d}' for config in ('same', 'other-policy', 'other-creator')
             for lost in (0, 1) for n in range(60)}
    names.update(('healthy', 'activate-current', 'cancel-then-activate', 'late-prepare', 'intervals',
                  'rank-exhausted', 'sql-unknown', 'restart-claimed', 'restart-cancelling',
                  'late-claim-0', 'late-claim-1', 'stale-inspection', 'revoked-admin', 'replacement-worker'))
    names.update(f'foreign-{creator}-{terminal}' for creator in (11, 12) for terminal in (0, 1))
    for prefix, suffixes in (
        ('nondeath-', ('invalid', 'denied', 'busy', 'limit', 'target', 'lifecycle', 'corrupt')),
        ('reset-', ('head', 'success', 'invalid', 'restart')),
        ('bound-', ('calls', 'deadline', 'mutations')),
        ('maintenance-', ('copy', 'sweep', 'deleted', 'terminal')),
        ('counter-', ('revision', 'serial', 'epoch')),
        ('mode-off-', ('takeover', 'activate', 'cancel'))):
        names.update(prefix + suffix for suffix in suffixes)
    require(len(names) == 402, 'independent-inventory-definition')
    return names


def named_witness(trace, raw, calls, responses):
    name, side = trace['name'], trace['controller']
    require(name in expected_names(), 'declared-positive-scenario')
    if name.startswith('race-'):
        return  # Detailed two-PUT/first-winner/restart witness checked above.
    writes = {e['io']: e for e in raw if e['event'] == 's3_put_invoked'}
    effects = [e for e in raw if e['event'] == 's3_put_effect']
    heads = [json.loads(raw[0]['objects'][HEAD]['body'])] + [json.loads(e['result']['value']['body'])
             for e in effects if e['result']['status'] == 200 and writes[e['io']]['key'] == HEAD]
    phases = [h['owner_plan']['phase']['kind'] for h in heads if 'owner_plan' in h]
    controlled = {e['call'] for e in side if e['event'] == 'rpc'}
    mutations = [calls[c]['operation'] for c in controlled if calls[c]['operation'] in MUTATIONS]
    ticks = [e for e in side if e['event'] == 'tick']
    restarts = [e for e in side if e['event'] == 'restart']
    failures = [e for e in side if e['event'] == 'network_failure']
    probes = [e for e in side if e['event'] == 'probe']
    errors = [responses[c]['value']['code'] for c in controlled if c in responses and responses[c]['kind'] == 'error']
    check = lambda value: require(value, 'mandatory-' + name)
    if name == 'healthy':
        check(len(ticks) == 3 and not mutations and len(probes) == 3 and all(p['code'] == 'OK' for p in probes))
    elif name == 'activate-current':
        check(not heads[0]['active'] and phases == ['claimed', 'active'] and
              heads[-1]['owner'] == heads[0]['owner'] and sorted(mutations) == ['claim', 'prepare', 'resume'])
    elif name == 'cancel-then-activate':
        check(phases == ['cancelling', 'aborted', 'claimed', 'active'] and
              heads[-1]['owner'] == heads[0]['owner'] and any(c['operation'] == 'preserve' for c in calls.values()))
    elif name == 'late-prepare':
        check(len(restarts) == 1 and heads[-1]['active'] and heads[-1]['owner']['instance'] == 3 and
              any(calls[c]['operation'] == 'prepare' and r['kind'] == 'unknown' for c, r in responses.items()) and
              any(e['result']['status'] == 412 and calls[writes[e['io']]['call']]['operation'] == 'prepare' for e in effects))
    elif name == 'intervals':
        check([e['time'] for e in ticks] == [0, 500, 999, 1000, 1999, 2000, 4999, 5000] and
              mutations == ['prepare'] and [p['result']['mature'] for p in probes if p['slot'] == 'owner'] == [False]*7 + [True])
    elif name == 'rank-exhausted':
        check(heads[-1]['owner']['instance'] == 3 and not mutations and probes[-1]['result']['mature'])
    elif name == 'sql-unknown':
        sql = [e for e in raw if e['event'] == 'native_sql_executed']
        check(len(sql) == 1 and responses[sql[0]['call']]['kind'] == 'unknown' and heads[-1]['active'] and
              heads[-1]['windows'] == ['seed', 'original'] and
              any(c['operation'] == 'guard' and c['args'] == {'entry': 'lookup'} for c in calls.values()))
    elif name.startswith('restart-'):
        phase = name[len('restart-'):]
        check(len(restarts) == 1 and phases == ([phase, 'active'] if phase == 'claimed' else [phase, 'aborted']))
        if phase == 'claimed':
            later = [t for t in ticks if t['sequence'] > restarts[0]['sequence']]
            check([t['recovery'] for t in later] == [False, True])
    elif name.startswith('late-claim-'):
        claims = {c for c, r in responses.items() if calls[c]['operation'] == 'claim' and r['kind'] == 'unknown'}
        selected = [e for e in effects if writes[e['io']]['call'] in claims]
        check(len(claims) == len(selected) == 1 and phases[-1] == 'aborted' and
              selected[0]['result']['status'] == (200 if name.endswith('1') else 412))
    elif name.startswith('foreign-'):
        _, creator, terminal = name.split('-')
        check(not mutations and len(ticks) == 3 and heads[-1]['owner_plan']['identity']['creator'] == int(creator) and
              phases[-1] == ('active' if terminal == '1' else 'claimed'))
    elif name.startswith('nondeath-'):
        check(not mutations and not probes and len(failures) == 4 and
              all(e['code'] == name[len('nondeath-'):].upper() for e in failures))
    elif name.startswith('reset-'):
        check(not mutations and probes[-1]['slot'] == 'owner' and probes[-1]['result'] == {'healthy': False, 'mature': False})
        if name == 'reset-head': check(heads[-1]['revision'] == 1 and heads[-1]['head_serial'] == 2)
        if name == 'reset-success': check(any(p['result']['healthy'] for p in probes))
        if name == 'reset-invalid': check(any(e['code'] == 'INVALID' for e in failures))
        if name == 'reset-restart': check(len(restarts) == 1)
    elif name.startswith('bound-'):
        reports = [e for e in side if e['event'] == 'report']
        if name == 'bound-calls': check(len(controlled) == 8 and not mutations and len(ticks) == 1)
        if name == 'bound-deadline': check(len(controlled) == 1 and reports[-1]['time'] == ticks[0]['deadline'])
        if name == 'bound-mutations': check(mutations == ['prepare'] and len([e for e in side if e['event'] == 'decision']) == 2)
    elif name.startswith('maintenance-'):
        kind = name[len('maintenance-'):]
        check(not mutations and len(controlled) == 1 and
              (heads[0]['lifecycle'] == 'deleted' if kind == 'deleted' else heads[0]['storage'][kind]))
    elif name.startswith('counter-'):
        key = name[len('counter-'):]
        value = heads[0]['owner']['epoch'] if key == 'epoch' else heads[0]['head_serial' if key == 'serial' else key]
        check(not mutations and value == (40 if key == 'epoch' else 39) and probes[-1]['result']['mature'])
    elif name.startswith('mode-off-'):
        mode = name[len('mode-off-'):]
        check(side[0]['policies']['a']['modes'][mode] is False and
              (mutations == ['prepare'] if mode == 'cancel' else not mutations))
    elif name == 'stale-inspection':
        inspections = [responses[c]['value'] for c in controlled if calls[c]['operation'] == 'inspect' and
                       c in responses and responses[c]['kind'] == 'observed']
        observations = [e for e in side if e['event'] == 'head' and e['role'] == 'authority']
        check(mutations == ['prepare'] and inspections[-1]['current_head'] != json.loads(observations[-1]['snapshot']['body']))
    elif name == 'revoked-admin':
        check(heads[-1]['admins'] == [12] and 'DENIED' in errors and phases[-1] == 'claimed')
    elif name == 'replacement-worker':
        check(any(e['event'] == 'process_started' and e['worker'] == 4 for e in raw) and
              'TARGET' in errors and phases[-1] == 'claimed')
    else:
        raise Violation('missing-mandatory-witness', name)


def decide(a, method, value):
    p, t = a['policy'], a['tick']
    h = t['head']
    require(method in MUTATIONS and h is not None, 'controller-method')
    require(h['lifecycle'] == 'ready' and not any(h['storage'][k] for k in ('copy', 'sweep', 'terminal')), 'lifecycle-guard')
    require(value['identity']['creator'] == p['principal'] and value['nonces'] == p['nonces'] and
            value['identity']['operation'] == value['expected_head_serial'], 'policy-and-operation')
    require(value['target'] in (1, 2, 3) and p['modes'][value['mode']], 'policy-mode-and-target')
    marker = h.get('owner_plan')
    if t['inspected'] is not None:
        require(t['descriptor_head'] == h, 'descriptor-current-authority')
    if marker:
        inspected = t['marker_descriptor']
        require(inspected is not None and inspected['scope'] == p['scope'] and
                inspected['identity'] == marker['identity'] and digest(inspected) == marker['descriptor_hash'] and
                inspected['identity']['creator'] == p['principal'] and inspected['nonces'] == p['nonces'], 'foreign-marker')
    owner_health, target_health = t['health'].get('owner'), t['health'].get('target')
    pending = marker is not None and marker['phase']['kind'] in ('claimed', 'cancelling')
    if method == 'prepare':
        require(not pending and h['revision'] <= 38 and h['head_serial'] <= 38 and
                (value['mode'] != 'takeover' or h['owner']['epoch'] < 40), 'prepare-counter-and-phase')
        require(value['expected_revision'] == h['revision'] and value['expected_head_serial'] == h['head_serial'], 'original-base')
        if t['inspected']:
            d = t['inspected']
            require(all(value[k] == d[k] for k in value) and d['base']['head_hash'] == digest(h) and
                    d['base']['etag'] == a['base']['etag'], 'fixed-first-winner')
        require(owner_health is not None, 'owner-health-required')
        if owner_health['healthy']:
            require(not h['active'], 'healthy-active-readonly')
            require((value['mode'] == 'activate' and value['target'] == h['owner']['instance']) or
                    (value['mode'] == 'takeover' and t['inspected'] is not None and p['modes']['cancel']), 'inactive-cleanup')
        else:
            require(owner_health['mature'], 'mature-owner-required')
            require(value['mode'] == 'takeover' and value['target'] > h['owner']['instance'], 'increasing-rank')
            require(target_health is not None and (target_health['healthy'] or
                    (target_health['mature'] and t['inspected'] is not None and p['modes']['cancel'])), 'target-health-required')
        return
    require(t['inspected'] == value and value['scope'] == p['scope'] and
            len(t['inspection_calls'].get(digest(value), ())) >= 2, 'inspect-before-mutation')
    if method == 'resume':
        require(pending and marker['phase']['kind'] == 'claimed' and
                h['owner']['instance'] == value['target'], 'resume-accepted-target')
        require(t['recovery'], 'recovery-budget-fixed-at-start')
        require(target_health and target_health['healthy'], 'resume-healthy-target')
        return
    if method == 'abort':
        require(p['modes']['cancel'], 'cancel-enabled')
        if pending:
            require(marker['phase']['kind'] == 'cancelling' or (target_health and target_health['mature']), 'abort-own-failure-window')
            return
    require(a['prepared'] == value and value['base']['head_hash'] == digest(h) and
            value['base']['etag'] == a['base']['etag'], 'prepared-original-base')
    require(owner_health is not None, 'owner-health-required')
    if method == 'claim':
        if value['mode'] == 'activate':
            require(not h['active'] and owner_health['healthy'] and value['target'] == h['owner']['instance'], 'activate-current-owner')
        else:
            require(owner_health['mature'] and target_health and target_health['healthy'] and
                    value['target'] > h['owner']['instance'], 'claim-mature-increasing-target')
    else:
        require((not h['active'] and owner_health['healthy'] and value['mode'] == 'takeover') or
                (owner_health['mature'] and target_health and target_health['mature']), 'abort-own-failure-window')


def run_directory(directory, controls=False):
    """Read persisted traces in a fresh process without loading any generator."""
    import math
    import platform
    import signal
    import subprocess
    import time
    import traceback
    from collections import Counter
    root = Path(__file__).resolve().parents[2]
    path = directory.resolve()
    label = 'controls' if controls else 'oracle'
    started = time.time()
    report = {'status': 'FAILED', 'phase': label, 'production_controller': 'NOT_EXECUTED',
              'native_sqlite_http_s3': 'NOT_RUN', 'aws': 'NOT_RUN', 'throughput_slo': 'NOT_RUN'}
    def append(name, value):
        encoded = (canonical(value)+'\n').encode()
        require(sum(p.stat().st_size for p in path.rglob('*') if p.is_file()) + len(encoded) <= 512*1024*1024,
                'fixed-evidence-byte-budget')
        with (path / name).open('xb') as stream: stream.write(encoded)
    def expire(_signal, _frame):
        raise TimeoutError('original 180-second execution deadline')
    previous = signal.signal(signal.SIGALRM, expire)
    try:
        inputs = json.loads((path/'inputs.json').read_text())
        require(time.time() < inputs['deadline_epoch'], 'original-execution-deadline')
        signal.alarm(math.ceil(inputs['deadline_epoch']-time.time()))
        report['diagnostic'] = inputs['diagnostic']
        binary = Path(sys.executable).resolve()
        require(inputs['python'] == {'path': str(binary), 'version': platform.python_version(),
                'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}, 'frozen-python')
        def check_source():
            for name, expected in inputs['source']['files'].items():
                file = (root/name).resolve()
                require(file.is_relative_to(root) and hashlib.sha256(file.read_bytes()).hexdigest() == expected,
                        'frozen-source', name)
            if not inputs['diagnostic']:
                head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, check=True,
                                      capture_output=True, text=True, timeout=10).stdout.strip()
                changed = subprocess.run(['git', 'status', '--porcelain', '--', *inputs['source']['files']],
                                         cwd=root, check=True, capture_output=True, text=True, timeout=10).stdout
                require(head == inputs['source']['repository_head'] and not changed, 'frozen-repository')
        check_source()
        require(json.loads((path/'source-after.json').read_text()) == inputs['source'], 'source-generation-stability')
        exploration = json.loads((path/'exploration.json').read_text())
        require(exploration['status'] == 'GENERATED' and exploration['positive_cases'] == 402 and
                exploration['unique_raw_histories'] == 402 and exploration['negative_controls'] == 40,
                'complete-generated-inventory')
        manifest = json.loads((path/'traces.json').read_text())
        positive = [row for row in manifest if row['kind'] == 'positive']
        negative = [row for row in manifest if row['kind'] == 'negative']
        require(len(positive) == 402 and {row['name'] for row in positive} == expected_names(), 'complete-positive-inventory')
        require(len(negative) == 40 and len({row['name'] for row in negative}) == 40, 'complete-negative-inventory')
        inventory = json.loads((path/'inventory.json').read_text())
        require({row['name']: row['rule'] for row in negative} ==
                {row['name']: row['rule'] for row in inventory['negative']}, 'frozen-negative-specification')
        def read(row):
            file = (path/row['file']).resolve()
            require(file.is_relative_to(path), 'evidence-path')
            data = file.read_bytes()
            require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'persisted-trace-hash')
            return json.loads(data)
        if controls:
            prior = json.loads((path/'oracle.json').read_text())
            require(prior['status'] == 'PASSED' and prior['positive_cases'] == 402, 'positive-oracle-first')
            row = next(r for r in positive if r['name'] == 'cancel-then-activate')
            original = read(row)
            original_bytes = canonical(original)
            expected = audit(original, strict=True)
            positive_controls = [{'name': 'original-history', 'passed': expected['status'] == 'PASSED'}]
            altered = deepcopy(original)
            altered['summary'] = {'passed': False, 'historical_ack': True, 'native_session': True}
            positive_controls.append({'name': 'fabricated-summary-ignored', 'passed': audit(altered, strict=True) == expected})
            results = []
            for row in negative:
                value = read(row)
                try:
                    audit(value)
                except (Violation, CORE.Violation) as error:
                    actual = error.rule
                else:
                    actual = 'FALSE_PASS'
                result = {'name': row['name'], 'expected': row['rule'], 'actual': actual,
                          'passed': actual == row['rule'], 'trace_sha256': row['sha256']}
                results.append(result)
                if not result['passed']:
                    append('negative-failure.json', result)
                    raise Violation('negative-exact-rule', canonical(result))
            positive_controls.append({'name': 'original-unchanged-after-negatives',
                'passed': canonical(original) == original_bytes and audit(original, strict=True) == expected})
            require(all(row['passed'] for row in positive_controls), 'positive-controls')
            report.update(negative_controls=len(results), positive_controls=3,
                          negative_results=results, positive_results=positive_controls)
        else:
            totals, results, fingerprints = Counter(), [], set()
            for row in positive:
                value = read(row)
                require(value['name'] == row['name'], 'manifest-trace-name')
                raw = {'protocol': value['protocol']['events'], 'controller': value['controller']}
                fingerprint = hashlib.sha256(canonical(raw).encode()).hexdigest()
                require(fingerprint == row['raw_history_sha256'] and fingerprint not in fingerprints,
                        'unique-independent-history')
                fingerprints.add(fingerprint)
                checked = audit(value, strict=True)
                totals.update({k: v for k, v in checked.items() if type(v) is int})
                results.append({'name': row['name'], 'trace_sha256': row['sha256'], 'checked': checked})
            report.update(positive_cases=402, unique_raw_histories=len(fingerprints),
                          aggregate=dict(sorted(totals.items())), results=results)
        check_source()
        report.update(status='PASSED', source_sha256=inputs['source']['sha256'])
    except BaseException as error:
        report.update(error=type(error).__name__, message=str(error))
        append(label+'-failure.json', {'error': type(error).__name__, 'message': str(error),
                                      'traceback': traceback.format_exc()})
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = time.time()-started
        append(label+'.json', report)
    print(canonical({k: v for k, v in report.items() if k not in ('results', 'negative_results', 'positive_results')}))
    return report['status'] == 'PASSED'


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run_directory(args.directory, args.controls) else 1)
