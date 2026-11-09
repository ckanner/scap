"""Independent adversarial controls over complete enumerated histories.

Each protocol mutation starts with a separately accepted original prefix, changes
the last effect, and must fail at its named semantic boundary. Graph controls
separately falsify successor completeness and truncated-run reporting.
"""

import argparse
import copy
import gzip
import json
import os
from pathlib import Path
import shutil

import oracle


def save(path, raw):
    temporary = path.with_name(path.name + '.replacement')
    temporary.write_bytes(raw)
    temporary.replace(path)


def document(path, value):
    save(path, json.dumps(value, sort_keys=True, indent=2).encode() + b'\n')


def compressed(path, rows):
    raw = b''.join(oracle.canonical(row) + b'\n' for row in rows)
    save(path, gzip.compress(raw, mtime=0))


class Original:
    def __init__(self, evidence, inputs):
        self.evidence, self.inputs, self.cache = evidence, inputs, {}

    def graph(self, prefix):
        profile = next(profile for profile in self.inputs['profiles'] if profile['name'].startswith(prefix + '_'))
        if prefix not in self.cache:
            path = self.evidence / profile['name']
            states = [row['value'] for row in oracle.records(path / 'states.jsonl.gz')]
            edges = list(oracle.records(path / 'edges.jsonl.gz')); parents = [None] * len(states)
            for edge in edges:
                if edge['target'] and parents[edge['target']] is None: parents[edge['target']] = edge
            self.cache[prefix] = profile, states, edges, parents
        return self.cache[prefix]

    def select(self, prefix, predicate):
        profile, states, edges, parents = self.graph(prefix)
        for edge in edges:
            before, after, action = states[edge['source']], states[edge['target']], edge['action']
            actor = action.get('actor')
            op = profile['programs'][actor][before['actors'][actor]['pc']]['op'] if actor is not None else None
            context = {'before': before, 'after': after, 'action': action, 'actor': actor, 'op': op, 'profile': profile}
            if predicate(context):
                return profile, oracle.trace_for(profile, states, parents, edge), context
        raise ValueError('negative control has no original eligible witness in ' + prefix)


def added(context):
    names = set(context['after']['tokens']) - set(context['before']['tokens'])
    return next(iter(names)) if len(names) == 1 else None


def client(op, predicate=lambda context: True, *, issued=False):
    return lambda context: context['op'] == op and (not issued or added(context) is not None) and predicate(context)


def network(kind, predicate=lambda context: True):
    return lambda context: context['action'].get('choice') == 'apply' and 'network' in context['action'] and context['before']['tokens'][context['action']['network']]['kind'] == kind and predicate(context)


def candidate(after, context):
    return after['tokens'][added(context)]['request']['candidate']


def request(after, context):
    return after['tokens'][added(context)]['request']


def broker(after, context):
    return after['brokers'][context['profile']['actors'][context['actor']]['broker']]


def local(after, context):
    return after['actors'][context['actor']]


def forge_head(after, context, change):
    actor = context['actor']; previous = context['before']['actors'][actor]
    view = previous['view']; head = copy.deepcopy(view['body']); head['serial'] += 1
    change(head)
    local(after, context).update(stopped=None, pc=previous['pc'] + 1)
    identifier = actor + ':' + str(previous['pc'])
    after['tokens'][identifier] = {'actor': actor, 'kind': 'head_cas', 'request': {'kind': context['op'], 'base': view, 'candidate': head},
                                  'uncertain': False, 'stage': 'pending', 'response': None, 'observed': None}
    local(after, context).update(last_token=identifier, last_result=None)


def reencode_copy(after, context):
    value = request(after, context)
    raw = bytes.fromhex(value['raw']); decoded = oracle.parse(raw.split(b'\n', 1)[1])
    changed = b'SCAP-MODEL-OBJECT-1\n' + oracle.canonical(decoded)
    oracle.require(changed != raw, 'raw-copy control made no byte change')
    value['raw'] = changed.hex()


def foreign_grant(after, context):
    b = broker(after, context)
    other = next(pin for pin in context['before']['head']['pins'] if pin['grant_serial'] == b['token']['grant_serial'] and pin != b['token'])
    b.update(token=copy.deepcopy(other), phase='granted', gate=True)


def overwrite_active_delete(after, context):
    token = context['before']['tokens'][context['action']['network']]
    old = token['request']; key = old['key']; active = str(context['before']['head']['A'])
    # Preserve the original immutable request, but pretend its backend effect
    # used today's generation. This catches an alias-based store simulator.
    after['objects'] = copy.deepcopy(context['before']['objects'])
    del after['objects'][active][key]
    if not after['objects'][active]: del after['objects'][active]


def unregistered_get(after, context):
    actor, previous = context['actor'], context['before']['actors'][context['actor']]
    identifier = actor + ':unregistered'
    after['tokens'][identifier] = {'actor': actor, 'kind': 'object_get', 'request': {'generation': after['head']['A'], 'object': 'page0',
        'key': next(key for key, raw in after['objects'][str(after['head']['A'])].items() if b'"kind": "page"' in bytes.fromhex(raw)),
        'purpose': 'read', 'protection': None}, 'uncertain': False, 'stage': 'pending', 'response': None, 'observed': None}
    local(after, context)['last_token'] = identifier


def admitted_provisioning(after, context):
    identity = context['profile']['actors'][context['actor']]['broker']
    b = after['brokers'][identity]; h = context['before']['actors'][context['actor']]['view']['body']
    pin = dict(context['profile']['brokers'][identity], generation=h['A'], grant_serial=h['serial'] + 1,
               scope={'deployment': 1, 'tenant': 7, 'database': 1001, 'incarnation': 1, 'generation': 1})
    b.update(token=pin, base_serial=h['serial'], phase='pending')
    forge_head(after, context, lambda next_head: next_head.update(pins=[pin]))


def late_verification(after, context):
    actor = context['actor']; before = context['before']['actors'][actor]
    identity = before['last_token']; token = after['tokens'][identity]
    token['observed'] = 'known'
    local(after, context).update(stopped=None, pc=before['pc'] + 1, last_result=copy.deepcopy(token['response']), copy_verified=['page0'])


def late_read(after, context):
    previous = context['before']['actors'][context['actor']]
    token = after['tokens'][previous['last_token']]; token['observed'] = 'known'
    local(after, context).update(stopped=None, pc=previous['pc'] + 1, last_result=copy.deepcopy(token['response']), verified=['page0'])


def cases():
    # name: profile-prefix, original-edge predicate, final-effect mutation,
    # exact semantic rejection fragment. The denominator is frozen in tests.
    return {
        'pin_add_without_serial_fence': ('01', client('pin_add', issued=True), lambda a, c: candidate(a, c).update(serial=request(a, c)['base']['body']['serial']), 'client protocol delta changed: pin_add'),
        'pin_release_returns_aba_body': ('07', client('pin_release', issued=True), lambda a, c: candidate(a, c).update(serial=broker(a, c)['base_serial']), 'client protocol delta changed: pin_release'),
        'abandoned_generation_reallocated_as_a_plus_one': ('11', client('freeze', lambda c: c['before']['actors'][c['actor']]['view']['body']['M'] == 2, issued=True), lambda a, c: (candidate(a, c).update(M=2), candidate(a, c)['T'].update(target=2)), 'client protocol delta changed: freeze'),
        'head_observation_allows_unregistered_get': ('03', client('head_get', lambda c: not c['before']['head']['pins'] and c['actor'] == 'p'), unregistered_get, 'client protocol delta changed: head_get'),
        'ttl_revokes_paused_pin': ('04', client('tick', lambda c: c['before']['actors']['p']['stopped'] == 'PAUSED'), lambda a, c: a['head'].update(pins=[]), 'client protocol delta changed: tick'),
        'http_timeout_drops_actual_guard': ('04', client('caller_timeout'), lambda a, c: broker(a, c).update(guards=[]), 'client protocol delta changed: caller_timeout'),
        'old_write_rebound_to_fresh_etag': ('07', client('write', lambda c: c['before']['head']['serial'] > c['before']['actors']['w']['sealed']['snapshot']['body']['serial'], issued=True), lambda a, c: request(a, c).update(base={'body': copy.deepcopy(c['before']['head']), 'etag': oracle.body_tag(c['before']['head'])}), 'client protocol delta changed: write'),
        'old_put_rebound_to_new_generation': ('18', client('object_put', issued=True), lambda a, c: request(a, c).update(generation=2), 'client protocol delta changed: object_put'),
        'promote_restores_revoked_acl': ('08', client('promote', lambda c: c['before']['actors'][c['actor']]['view']['body']['acl'] == 'deny', issued=True), lambda a, c: candidate(a, c).update(acl='allow'), 'client protocol delta changed: promote'),
        'release_restores_old_business_roots': ('06', client('pin_release', lambda c: c['before']['actors'][c['actor']]['view']['body']['roots'] == ['data1', 'index1'], issued=True), lambda a, c: candidate(a, c).update(roots=['data0', 'index0']), 'client protocol delta changed: pin_release'),
        'deleted_release_restores_old_acl': ('10', client('pin_release', lambda c: c['before']['actors'][c['actor']]['view']['body']['life'] == 'Deleted', issued=True), lambda a, c: candidate(a, c).update(acl='allow'), 'client protocol delta changed: pin_release'),
        'raw_copy_reencoded_equal_payload': ('08', client('copy_put', issued=True), reencode_copy, 'client protocol delta changed: copy_put'),
        'seal_without_complete_target_closure': ('20', client('seal', lambda c: c['after']['actors'][c['actor']]['stopped'] == 'INCOMPLETE_COPY'), lambda a, c: forge_head(a, c, lambda h: h['T'].update(phase='sealed')), 'client protocol delta changed: seal'),
        'verified_t2_cache_reused_for_t3': ('22', client('capture_plan', lambda c: c['after']['actors'][c['actor']]['plan'] is not None and c['after']['actors'][c['actor']]['plan']['target'] == 3), lambda a, c: local(a, c).update(copied=copy.deepcopy(c['before']['actors'][c['actor']]['copied']), copy_verified=c['before']['actors'][c['actor']]['copy_verified']), 'client protocol delta changed: capture_plan'),
        'late_verify_accredited_to_new_plan': ('23', client('observe', lambda c: c['after']['actors'][c['actor']]['stopped'] == 'STALE_COPY_RESPONSE'), late_verification, 'client protocol delta changed: observe'),
        'logical_delete_keeps_staging_plan': ('09', client('delete', lambda c: c['before']['actors'][c['actor']]['view']['body']['T'] is not None, issued=True), lambda a, c: candidate(a, c).update(T=copy.deepcopy(request(a, c)['base']['body']['T'])), 'client protocol delta changed: delete'),
        'logical_delete_revokes_live_pin': ('10', client('delete', lambda c: bool(c['before']['head']['pins']), issued=True), lambda a, c: candidate(a, c).update(pins=[]), 'client protocol delta changed: delete'),
        'late_promote_revives_deleted_head': ('09', network('head_cas', lambda c: c['before']['head']['life'] == 'Deleted' and c['before']['tokens'][c['action']['network']]['request']['kind'] == 'promote'), lambda a, c: a.update(head=copy.deepcopy(a['tokens'][c['action']['network']]['request']['candidate'])), 'original backend key/condition/effect changed'),
        'delete_active_generation': ('12', client('delete_object', issued=True), lambda a, c: request(a, c).update(generation=c['before']['head']['A']), 'client protocol delta changed: delete_object'),
        'delete_staging_generation': ('12', client('delete_object', lambda c: c['before']['head']['T'] is not None, issued=True), lambda a, c: request(a, c).update(generation=c['before']['head']['T']['target']), 'client protocol delta changed: delete_object'),
        'delete_head_identity_slot': ('12', client('delete_object', issued=True), lambda a, c: request(a, c).update(key='head'), 'client protocol delta changed: delete_object'),
        'delete_catalogue_barrier': ('12', client('delete_object', issued=True), lambda a, c: request(a, c).update(key='catalogue/name/barrier'), 'client protocol delta changed: delete_object'),
        'old_delete_hits_new_active_generation': ('12', network('object_delete', lambda c: c['before']['head']['A'] == 3 and c['after']['tokens'][c['action']['network']]['response']['outcome'] == 'APPLIED'), overwrite_active_delete, 'original backend key/condition/effect changed'),
        'stale_cursor_retargets_another_retired_generation': ('13', client('sweep_resume'), lambda a, c: (local(a, c).update(stopped=None, pc=c['before']['actors'][c['actor']]['pc'] + 1), local(a, c)['sweep'].update(generation=3)), 'client protocol delta changed: sweep_resume'),
        'pin_technical_transition_enters_provisioning': ('14', client('pin_add', lambda c: c['before']['actors'][c['actor']]['view']['body']['life'] == 'Provisioning'), admitted_provisioning, 'client protocol delta changed: pin_add'),
        'technical_pin_changes_business_revision': ('01', client('pin_add', issued=True), lambda a, c: candidate(a, c).update(revision=candidate(a, c)['revision'] + 1), 'client protocol delta changed: pin_add'),
        'empty_scan_claims_permanent_absence': ('18', client('record_round', lambda c: c['after']['checkpoints']['old-one']['round'] == 'observed_empty'), lambda a, c: (a['checkpoints']['old-one'].update(round='permanently_empty'), local(a, c)['sweep'].update(round='permanently_empty')), 'client protocol delta changed: record_round'),
        'unknown_delete_claims_not_applied': ('12', client('observe', lambda c: c['action']['choice'] == 'unknown' and c['before']['tokens'][c['before']['actors'][c['actor']]['last_token']]['kind'] == 'object_delete' and c['before']['tokens'][c['before']['actors'][c['actor']]['last_token']]['response'] == {'outcome': 'APPLIED'}), lambda a, c: local(a, c).update(last_result={'outcome': 'NOT_APPLIED'}), 'client protocol delta changed: observe'),
        'unknown_add_absence_at_original_serial_claims_cleanup': ('02', client('inspect_pin', lambda c: c['after']['brokers']['b']['phase'] == 'pending_absent'), lambda a, c: broker(a, c).update(phase='released', gate=False), 'client protocol delta changed: inspect_pin'),
        'same_process_foreign_broker_token_adopted': ('01', client('inspect_pin', lambda c: c['after']['brokers'][c['profile']['actors'][c['actor']]['broker']]['phase'] == 'released' and any(pin['grant_serial'] == c['before']['brokers'][c['profile']['actors'][c['actor']]['broker']]['token']['grant_serial'] for pin in c['before']['head']['pins'])), foreign_grant, 'client protocol delta changed: inspect_pin'),
        'gate_close_keeps_join_gate_open': ('05', client('gate_close'), lambda a, c: broker(a, c).update(gate=True), 'client protocol delta changed: gate_close'),
        'release_while_actual_guard_still_running': ('05', client('pin_release', lambda c: c['after']['actors'][c['actor']]['stopped'] == 'RELEASE_NOT_QUIESCENT'), lambda a, c: forge_head(a, c, lambda h: h.update(pins=[])), 'client protocol delta changed: pin_release'),
        'unknown_original_write_gets_sql_ack': ('06', client('ack', lambda c: c['before']['actors']['w']['caller_unknown'] and c['after']['actors']['w']['ack'] == 'WITHHELD'), lambda a, c: local(a, c).update(ack=c['before']['actors']['w']['last_token']), 'client protocol delta changed: ack'),
        'backend_invents_current_acl_recheck': ('08', network('head_cas', lambda c: c['before']['head']['acl'] == 'deny' and c['after']['tokens'][c['action']['network']]['response']['outcome'] == 'APPLIED'), lambda a, c: (a.update(head=copy.deepcopy(c['before']['head']), retired=copy.deepcopy(c['before']['retired'])), a['tokens'][c['action']['network']].update(response={'outcome': 'DENIED'})), 'original backend key/condition/effect changed'),
        'native_failure_gets_success_ack': ('06', client('ack', lambda c: c['before']['actors']['w']['native'] == 'failed_after_commit'), lambda a, c: local(a, c).update(ack=c['before']['actors']['w']['last_token']), 'client protocol delta changed: ack'),
        'native_failure_rolls_back_durable_head': ('06', client('native_publish', lambda c: c['action']['choice'] == 'fail'), lambda a, c: a.update(head=copy.deepcopy(c['before']['tokens'][c['before']['actors']['w']['last_token']]['request']['base']['body'])), 'client protocol delta changed: native_publish'),
        'reader_returns_before_materializing': ('25', client('read_return', lambda c: c['actor'] == 'early'), lambda a, c: local(a, c).update(stopped=None, pc=c['before']['actors'][c['actor']]['pc'] + 1, read_result={'outcome': 'SUCCESS', 'object_hashes': []}), 'client protocol delta changed: read_return'),
        'detached_reader_claims_success': ('25', client('read_return', lambda c: c['actor'] == 'timeout'), lambda a, c: local(a, c).update(read_result={'outcome': 'SUCCESS', 'snapshot_etag': local(a, c)['materialized']['snapshot']['etag'], 'object_hashes': sorted(local(a, c)['materialized']['frames'])}), 'client protocol delta changed: read_return'),
        'ended_worker_consumes_late_read_bytes': ('26', client('observe', lambda c: c['after']['actors'][c['actor']]['stopped'] == 'LATE_READ_RESPONSE'), late_read, 'client protocol delta changed: observe'),
    }


def rejection(call, expected):
    try:
        call()
    except ValueError as error:
        oracle.require(expected in str(error), 'negative control rejected at unrelated boundary: ' + str(error))
        return str(error)
    raise ValueError('invalid independent evidence was accepted')


def main(args):
    baseline = oracle.audit(args.evidence)
    inputs = oracle.validate_inputs((args.evidence / 'inputs.json').read_bytes())
    source = Original(args.evidence, inputs)
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'status': 'FAILED', 'baseline_evidence_sha256': baseline['evidence_sha256'],
              'control_source_sha256': oracle.sha(Path(__file__).read_bytes()), 'denominator': len(cases()) + 3,
              'negative_controls': [], 'positive_controls': []}
    try:
        for name, (prefix, predicate, mutate, expected) in cases().items():
            profile, original, context = source.select(prefix, predicate)
            oracle.audit_trace(inputs, profile, original)
            changed = copy.deepcopy(original); mutate(changed['states'][-1], context)
            raw_original, raw_changed = oracle.canonical(original) + b'\n', oracle.canonical(changed) + b'\n'
            oracle.require(raw_original != raw_changed, 'control did not change original evidence')
            (args.output / (name + '.original.json')).write_bytes(raw_original)
            (args.output / (name + '.mutated.json')).write_bytes(raw_changed)
            reason = rejection(lambda: oracle.audit_trace(inputs, profile, changed), expected)
            report['negative_controls'].append({'case': name, 'profile': profile['name'], 'reason': reason,
                                                'original_sha256': oracle.sha(raw_original), 'mutated_sha256': oracle.sha(raw_changed)})
        profile = next(profile for profile in inputs['profiles'] if profile['name'].startswith('15_'))
        for name in ('missing_enabled_successor', 'truncated_run_reported_as_accepted'):
            directory = args.output / name
            shutil.copytree(args.evidence / profile['name'], directory, copy_function=os.link)
            enumeration = oracle.parse((directory / 'enumeration.json').read_bytes())
            if name == 'missing_enabled_successor':
                edges = list(oracle.records(directory / 'edges.jsonl.gz')); edges.pop(0)
                compressed(directory / 'edges.jsonl.gz', edges)
                enumeration['edges'] -= 1; enumeration['files']['edges.jsonl.gz'] = oracle.sha((directory / 'edges.jsonl.gz').read_bytes())
                expected = 'BFS closure omitted/added enabled successor'
            else:
                enumeration.update(complete=False, status='INCOMPLETE', reason='STATE_RESOURCE_LIMIT')
                expected = 'truncated exploration cannot count as complete'
            document(directory / 'enumeration.json', enumeration)
            reason = rejection(lambda: oracle.audit_profile(inputs, profile, directory), expected)
            report['negative_controls'].append({'case': name, 'profile': profile['name'], 'reason': reason,
                                                'input_files': {path.name: oracle.sha(path.read_bytes()) for path in directory.iterdir() if path.is_file()}})
        directory = args.output / 'summary_not_authority'
        shutil.copytree(args.evidence, directory, copy_function=os.link)
        document(directory / 'summary.json', {'status': 'invented', 'complete': False, 'states': 0, 'production_gc': True})
        verified = oracle.audit(directory)
        oracle.same(verified['evidence_sha256'], baseline['evidence_sha256'], 'convenience summary changed acceptance authority')
        report['positive_controls'].append({'case': 'summary_not_authority', 'evidence_sha256': verified['evidence_sha256']})
        oracle.same(len(report['negative_controls']) + len(report['positive_controls']), report['denominator'], 'control denominator incomplete')
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        document(args.output / 'controls.json', report)
        print(json.dumps({key: report.get(key) for key in ('status', 'denominator', 'error')}, sort_keys=True), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory for original/mutated full history prefixes and controls.json')
    main(parser.parse_args())
