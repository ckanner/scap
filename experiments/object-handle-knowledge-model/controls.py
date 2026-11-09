"""Mutations of reachable raw graph edges; never import or call the producer.

Every negative retains the original source state, original event and connected
prefix. It changes a semantic target fact, calls the frozen independent rule,
and requires the declared rejection boundary. Graph controls use the same
enabled-choice function as the complete audit. No acceptance overlay exists.
"""

import argparse
import copy
import json
from pathlib import Path

from oracle import States, bound_file, identity, records, witness_path, write_json
from oracle_protocol import (Violation, choice_closure, edge_checks, fingerprint,
                             must, physical_key, state_checks, wire)


def actor(after, event):
    return after['actors'][event['actor']]


def outcome(value):
    return (value.get('outcome') or {}).get('kind')


def replace_body(after, event, update):
    candidate = actor(after, event)['candidate']
    body = json.loads(bytes.fromhex(candidate['raw']))
    update(body)
    candidate['raw'] = wire(body).hex()


def replace_management_verb(before, event, after, spec, profile):
    candidate = actor(after, event)['candidate']
    body = copy.deepcopy(candidate['base'])
    body['serial'] += 1
    body['revision'] += 1
    body['auth_epoch'] += 1
    body['acl']['8']['read'] = not body['acl']['8']['read']
    candidate.update(kind='policy', raw=wire(body).hex())


def replace_technical_verb(before, event, after, spec, profile):
    candidate = actor(after, event)['candidate']
    body = copy.deepcopy(candidate['base'])
    body['serial'] += 1
    body['plan'] = None
    candidate.update(kind='abort_plan', raw=wire(body).hex())


def rebind_technical_generation(before, event, after, spec, profile):
    changed = actor(after, event)
    generation = changed['context']['head']['plan']['target']
    changed['context']['generation'] = generation
    changed['candidate']['generation'] = generation


def reject_failure_probe(before, event, after, spec, profile):
    for identifier in set(after['tokens']) - set(before['tokens']):
        del after['tokens'][identifier]
    who = event['actor']
    after['actors'][who] = copy.deepcopy(before['actors'][who])
    after['actors'][who].update(pc=len(profile['actors'][who]['program']), stopped='failed_attempt_closed',
                               outcome={'kind': 'Rejected', 'reason': 'failed_attempt_closed'})


def falsely_reject_retired_removal(before, event, after, spec, profile):
    who = event['actor']
    after['world'] = copy.deepcopy(before['world'])
    after['actors'][who] = copy.deepcopy(before['actors'][who])
    after['actors'][who].update(
        pc=len(profile['actors'][who]['program']), stopped='fixture_remove_live_generation',
        outcome={'kind': 'Rejected', 'reason': 'fixture_remove_live_generation'})


def rejected_removal_deletes_live_object(before, event, after, spec, profile):
    command = profile['actors'][event['actor']]['program'][event['pc']]
    scope = spec['scope']
    key = ('scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}'
           .format(**scope) + '/storage/' + str(command['generation']) + '/objects/'
           + spec['frames'][command['name']]['hash'])
    del after['world']['objects']['D0'][key]


def rejected_removal_changes_foreign_authority(before, event, after, spec, profile):
    scope = spec['scope']
    key = 'scap-object/v1/{deployment}/{tenant}/{database}/head'.format(**scope)
    after['world']['heads']['D1'][key]['serial'] += 1


def replace_with_guard_rejection(before, event, after, profile, reason):
    who = event['actor']
    after['tokens'] = copy.deepcopy(before['tokens'])
    after['actors'][who] = copy.deepcopy(before['actors'][who])
    after['actors'][who].update(pc=len(profile['actors'][who]['program']), stopped=reason,
                               outcome={'kind': 'Rejected', 'reason': reason})


def falsely_reject_freeze(before, event, after, spec, profile):
    replace_with_guard_rejection(before, event, after, profile, 'freeze_not_available')


def falsely_reject_held_read(before, event, after, spec, profile):
    replace_with_guard_rejection(before, event, after, profile, 'no_retained_hold')


def falsely_reject_closure_get(before, event, after, spec, profile):
    replace_with_guard_rejection(before, event, after, profile, 'get_not_in_original_closure')


def rejected_freeze_recaptures_context(before, event, after, spec, profile):
    changed = actor(after, event)
    changed['context']['view_token'] = before['actors'][event['actor']]['view_token']


def rejected_hold_grants_current_context(before, event, after, spec, profile):
    who = event['actor']
    original = before['actors'][who]
    view, head = original['view'], original['view']['head']
    actor(after, event)['context'] = {
        'domain': view['domain'], 'scope': copy.deepcopy(head['scope']),
        'lineage': profile['actors'][who]['lineage'], 'generation': head['A'],
        'roots': {'data': head['data'], 'index': head['index']}, 'mode': 'read', 'plan': None,
        'head': copy.deepcopy(head), 'etag': view['etag'], 'key': view['key'],
        'view_token': original['view_token'],
    }


def rejected_nonmember_dispatches_get(before, event, after, spec, profile):
    who = event['actor']
    original = before['actors'][who]
    context = original['context']
    command = profile['actors'][who]['program'][event['pc']]
    frame = spec['frames'][command['name']]
    identifier = f'{who}:{original["pc"]}'
    actor(after, event).update(last=identifier, last_result=None, no_work=False)
    after['tokens'][identifier] = {
        'actor': who, 'lineage': profile['actors'][who]['lineage'], 'effect': None, 'observation': None,
        'request': {'method': 'GET', 'domain': context['domain'], 'scope': copy.deepcopy(context['scope']),
                    'generation': context['generation'],
                    'key': physical_key(context['scope'], context['generation'], frame['hash']),
                    'hash': frame['hash'], 'purpose': 'read', 'expected_kind': frame['kind'],
                    'context_token': context['view_token'], 'uncertain': False},
    }


def false_block(before, event, after, spec, profile):
    who = event['actor']
    after['actors'][who] = copy.deepcopy(before['actors'][who])
    after['actors'][who].update(pc=len(profile['actors'][who]['program']), stopped='publication_latched',
                               outcome={'kind': 'Rejected', 'reason': 'publication_latched'})


def forge_permit(before, event, after, spec, profile):
    a, old = actor(after, event), before['actors'][event['actor']]
    a.update(pc=old['pc'] + 1, stopped=None, outcome=None)
    candidate = old['candidate']
    a['permit'] = {'candidate_hash': fingerprint(candidate), 'lineage': candidate['lineage'],
                   'generation': candidate['generation'], 'check_pc': old['pc']}


def revoke_enabled_permit(before, event, after, spec, profile):
    for identifier in set(after['tokens']) - set(before['tokens']):
        del after['tokens'][identifier]
    false_block(before, event, after, spec, profile)


def dispatch_after_stop(before, event, after, spec, profile):
    who = event['actor']
    a = copy.deepcopy(before['actors'][who])
    candidate, permit = a['candidate'], a['permit']
    identifier = f'{who}:{a["pc"]}'
    command = profile['actors'][who]['program'][a['pc']]
    a.update(pc=a['pc'] + 1, stopped=None, outcome=None, cas=identifier, last=identifier,
             permit=None, last_result=None, no_work=False)
    after['actors'][who] = a
    after['tokens'][identifier] = {
        'actor': who, 'lineage': profile['actors'][who]['lineage'], 'effect': None, 'observation': None,
        'request': {'method': 'HEAD_CAS', 'domain': candidate['domain'], 'scope': candidate['scope'],
                    'key': candidate['key'], 'etag': candidate['etag'], 'raw': candidate['raw'],
                    'generation': candidate['generation'], 'purpose': candidate['kind'],
                    'candidate_hash': fingerprint(candidate), 'permit': permit,
                    'context_token': candidate['view_token'], 'uncertain': command['uncertain']},
    }


def expire_without_proof(before, event, after, spec, profile):
    a = actor(after, event)
    a['failure']['classification'] = 'expired'
    known = after['lineages'][profile['actors'][event['actor']]['lineage']]
    known['physical'][str(a['failure']['generation'])]['status'] = 'expired'
    a['outcome'] = {'kind': 'SnapshotExpired', 'failure': a['failure']['token']}


def physicalize_semantic(before, event, after, spec, profile):
    who = event['actor']
    a = actor(after, event)
    identifier = a['last']
    request = after['tokens'][identifier]['request']
    a['failure'] = {'kind': 'physical', 'fault': 'hash', 'token': identifier,
                    'generation': request['generation'], 'domain': request['domain'],
                    'scope': request['scope'], 'key': request['key'], 'hash': request['hash'],
                    'classification': 'unresolved'}
    known = after['lineages'][profile['actors'][who]['lineage']]
    known['semantic'] = False
    known['physical'][str(request['generation'])] = {'status': 'unresolved', 'origin': identifier, 'proof': None}


def normalize_materialized(before, event, after, spec, profile):
    frames = actor(after, event)['materialized']['frames']
    frame = next(iter(frames.values()))
    value = json.loads(bytes.fromhex(frame['raw']).partition(b'\n')[2])
    frame['raw'] = (b'MODELKNOWLEDGE1\n' + wire(value)).hex()


def other_frame(before, event, after):
    who = event['actor']
    current = after['actors'][who]
    if current['failure'] or not current['last']:
        return None
    request = after['tokens'][current['last']]['request']
    if request['method'] != 'GET' or request['purpose'] != 'read':
        return None
    for name, value in before['actors'].items():
        if name != who and request['hash'] in value['frames']:
            return request['hash'], value['frames'][request['hash']]['token']
    return None


def borrow_frame(before, event, after, spec, profile):
    key, identifier = other_frame(before, event, after)
    actor(after, event)['frames'][key]['token'] = identifier


def late_original(before, event, after):
    if event['kind'] != 'network':
        return False
    token = before['tokens'][event['token']]
    return (token['request']['method'] == 'HEAD_CAS' and token['observation'] == {'kind': 'Unknown'}
            and after['tokens'][event['token']]['effect']['kind'] == 'Applied')


def candidates():
    cases = []

    def add(name, profile, op, who, predicate, mutate, boundary, network=False):
        cases.append({'name': name, 'profile': profile, 'op': op, 'actor': who,
                      'predicate': predicate, 'mutate': mutate, 'boundary': boundary, 'network': network})

    yes = lambda before, event, after: True
    add('nonfixture_authority_fault', 'K02_missing', 'mark', 'a', yes,
        lambda b, e, a, s, p: a['world']['head_fault'].__setitem__('D1', 'unavailable'), 'nonfixture')
    add('nonfixture_semantic_fault', 'K02_missing', 'mark', 'a', yes,
        lambda b, e, a, s, p: a['world']['semantic_bad_roots'].append(s['frames']['M0']['hash']), 'nonfixture')
    add('cross_lineage_authority_poison', 'K02_missing', 'begin', 'a', yes,
        lambda b, e, a, s, p: a['lineages']['H2'].__setitem__('authority', True), 'crossed knowledge lineage')
    add('cross_lineage_physical_poison', 'K02_missing', 'observe', 'a',
        lambda b, e, a: bool(a['lineages']['H1']['physical']),
        lambda b, e, a, s, p: a['lineages']['H2'].__setitem__('physical', copy.deepcopy(a['lineages']['H1']['physical'])),
        'crossed knowledge lineage')
    add('independent_read_cannot_clear_old_incident', 'K02_missing', 'return_read', 'b', yes,
        lambda b, e, a, s, p: a['lineages']['H1'].__setitem__('physical', {}), 'crossed knowledge lineage')
    add('same_lineage_read_cannot_clear_incident', 'K01_missing_takeover', 'return_read', 'b', yes,
        lambda b, e, a, s, p: a['lineages']['H1'].__setitem__('physical', {}), 'unrelated lineage knowledge')
    add('same_lineage_read_cannot_clear_authority', 'K08_malformed', 'return_read', 'c', yes,
        lambda b, e, a, s, p: a['lineages']['H1'].__setitem__('authority', False), 'unrelated lineage knowledge')
    add('independent_read_not_blocked_by_global_health', 'K02_missing', 'admit', 'b', yes, false_block,
        'read falsely blocked by publication-only latch')
    add('nonobserve_cannot_replace_view', 'K02_missing', 'mark', 'a',
        lambda b, e, a: a['actors']['a']['view'] is not None,
        lambda b, e, a, s, p: a['actors']['a']['view']['head'].__setitem__('serial', 99), 'unrelated actor state: view')
    add('nonobserve_cannot_rebind_token_label', 'K02_missing', 'mark', 'a', yes,
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('last', 'forged:token'), 'unrelated actor state: last')
    add('unknown_observation_not_rewritten_by_delivery', 'K16_independent_lookup', None, None, late_original,
        lambda b, e, a, s, p: a['tokens'][e['token']].__setitem__('observation', copy.deepcopy(a['tokens'][e['token']]['effect'])),
        'immutable request/observation: observation', network=True)
    add('late_delivery_cannot_rewrite_original_public_unknown', 'K16_independent_lookup', None, None, late_original,
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('outcome', {'kind': 'Ack', 'token': e['token']}),
        'backend changed client knowledge: actors', network=True)
    add('permit_cannot_be_rebound_to_new_condition', 'K12_takeover', 'send_head', 'a',
        lambda b, e, a: a['actors']['a']['cas'] is not None,
        lambda b, e, a, s, p: a['tokens'][a['actors']['a']['cas']]['request'].__setitem__('etag', '"new-condition"'),
        'publication rebound after final check')
    add('permit_cannot_be_minted_through_prior_latch', 'K12_takeover', 'final_check', 'a',
        lambda b, e, a: a['actors']['a']['stopped'] == 'publication_latched', forge_permit,
        'permit minted through own known latch')
    add('later_latch_cannot_revoke_enabled_original_permit', 'K12_takeover', 'send_head', 'a',
        lambda b, e, a: bool(b['lineages']['H1']['physical']) and a['actors']['a']['cas'] is not None,
        revoke_enabled_permit, 'read falsely blocked by publication-only latch')
    add('stop_still_blocks_new_dispatch_with_old_permit', 'K17_before_dispatch_takeover', 'send_head', 'a', yes,
        dispatch_after_stop, 'ordinary step continued an ended attempt')
    add('native_finish_cannot_reopen_local_gate', 'K17_after_dispatch_writer', 'native_publish', 'a', yes,
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('local_stop', False), 'unrelated actor state: local_stop')
    add('stopped_known_commit_cannot_gain_public_ack', 'K17_after_dispatch_writer', 'ack', 'a',
        lambda b, e, a: b['actors']['a']['known_commit'] is not None and b['actors']['a']['native'] == 'committed',
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('outcome', {'kind': 'Ack', 'token': a['actors']['a']['cas']}),
        'public ACK/UNKNOWN/withheld classification')
    add('unknown_cannot_become_native_committed', 'K16_independent_lookup', 'native_publish', 'a',
        lambda b, e, a: b['actors']['a']['known_commit'] is None,
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('native', 'committed'), 'native outcome without own known original CAS')
    add('independent_lookup_cannot_execute_native', 'K16_independent_lookup', 'return_lookup', 'b',
        lambda b, e, a: outcome(a['actors']['b']) == 'Lookup',
        lambda b, e, a, s, p: a['actors']['b'].__setitem__('native', 'executed'), 'unrelated actor state: native')
    add('same_bytes_from_other_actor_not_own_read_proof', 'K08_malformed', 'observe', 'b',
        lambda b, e, a: other_frame(b, e, a) is not None, borrow_frame,
        'successful response did not retain exact original bytes')
    add('materialized_frame_cannot_be_reencoded', 'K02_missing', 'materialize', 'b', yes,
        normalize_materialized, 'image moved between attempts')
    add('materialization_cannot_omit_original_frame', 'K02_missing', 'materialize', 'b', yes,
        lambda b, e, a, s, p: a['actors']['b']['materialized']['frames'].popitem(), 'image moved between attempts')
    add('foreign_scope_probe_cannot_expire', 'K09_probe_wrong_scope', 'classify', 'a',
        lambda b, e, a: a['lineages']['H1']['authority'], expire_without_proof, 'exact original evidence')
    add('malformed_probe_cannot_expire', 'K09_probe_malformed', 'classify', 'a',
        lambda b, e, a: a['lineages']['H1']['authority'], expire_without_proof, 'exact original evidence')
    add('held_generation_cannot_expire', 'K06_held_missing', 'classify', 'a',
        lambda b, e, a: a['actors']['a']['failure']['classification'] == 'corrupt', expire_without_proof, 'exact original evidence')
    add('active_generation_cannot_expire', 'K04_missing', 'classify', 'b',
        lambda b, e, a: a['actors']['b']['failure']['classification'] == 'corrupt', expire_without_proof, 'exact original evidence')
    add('probe_must_use_original_authority_domain', 'K09_probe_wrong_scope', 'probe', 'a', yes,
        lambda b, e, a, s, p: a['tokens'][a['actors']['a']['last']]['request'].__setitem__('domain', 'D1'), 'failure probe rebound')
    add('probe_capability_is_consumed_once', 'K09_probe_wrong_scope', 'probe', 'a', yes,
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('probe_used', False), 'probe capability not consumed')
    add('classify_cannot_change_unrelated_incident', 'K04_missing', 'classify', 'b', yes,
        lambda b, e, a, s, p: a['lineages']['H2']['physical'].__setitem__('2', copy.deepcopy(a['lineages']['H2']['physical']['1'])),
        'exact original evidence')
    add('hash_valid_semantic_failure_is_not_physical_expiry', 'K15_typed_edge', 'observe', 'a',
        lambda b, e, a: (a['actors']['a']['failure'] or {}).get('kind') == 'semantic', physicalize_semantic,
        'hash-valid semantic error downgraded to physical expiry')
    add('metadata_constructor_cannot_change_data_root', 'K12_takeover', 'prepare_manage', 'a', yes,
        lambda b, e, a, s, p: replace_body(a, e, lambda body: body.__setitem__('data', s['frames']['M1']['hash'])),
        'candidate changed fields outside closed constructor')
    add('management_constructor_cannot_substitute_another_valid_verb', 'K12_takeover', 'prepare_manage', 'a',
        lambda b, e, a: a['actors']['a']['stopped'] is None, replace_management_verb,
        'candidate constructor kind differs from original operation')
    add('technical_constructor_cannot_substitute_another_valid_verb', 'K05_retired_missing', 'prepare_tech', 'm',
        lambda b, e, a: (a['actors']['m']['candidate'] or {}).get('kind') == 'promote', replace_technical_verb,
        'candidate constructor kind differs from original operation')
    add('technical_context_cannot_rebind_generation_with_candidate', 'K05_retired_missing', 'prepare_tech', 'm',
        lambda b, e, a: (a['actors']['m']['candidate'] or {}).get('kind') == 'promote', rebind_technical_generation,
        'technical context differs from original fresh authority')
    add('failed_attempt_cannot_suppress_its_enabled_failure_probe', 'K05_retired_missing', 'probe', 'a', yes,
        reject_failure_probe, 'failed-attempt rejection outside ordinary guard')
    add('new_plan_cannot_rehold_retired_target', 'K06_aborted_target', 'prepare_tech', 'm',
        lambda b, e, a: (a['actors']['m']['candidate'] or {}).get('kind') == 'freeze',
        lambda b, e, a, s, p: replace_body(a, e, lambda body: body.__setitem__('hold', {
            'id': 'HOLD-REUSE', 'scope': s['scope'], 'generation': 2,
            'roots': {'data': body['data'], 'index': body['index']}})),
        'candidate changed fields outside closed constructor')
    add('later_stop_cannot_revoke_historical_ack', 'K14_takeover', 'stop_local', 'a',
        lambda b, e, a: outcome(b['actors']['a']) == 'Ack',
        lambda b, e, a, s, p: a['actors']['a'].__setitem__('outcome', {'kind': 'Withheld', 'token': a['actors']['a']['cas']}),
        'historical public outcome rewritten')
    add('retired_generation_cannot_be_falsely_rejected_as_live', 'K05_materialized_return',
        'remove_retired', 'm', lambda b, e, a: a['actors']['m']['stopped'] is None,
        falsely_reject_retired_removal, 'fixture rejected already retired generation')
    add('rejected_fixture_cannot_remove_active_source', 'K05_materialized_return',
        'remove_retired', 'm',
        lambda b, e, a: a['actors']['m']['stopped'] == 'fixture_remove_live_generation',
        rejected_removal_deletes_live_object, 'fixture rejection changed backend state')
    add('rejected_fixture_cannot_change_foreign_authority', 'K05_materialized_return',
        'remove_retired', 'm',
        lambda b, e, a: a['actors']['m']['stopped'] == 'fixture_remove_live_generation',
        rejected_removal_changes_foreign_authority, 'fixture rejection changed backend state')
    add('available_freeze_cannot_borrow_old_occupied_plan', 'K06_aborted_target', 'prepare_tech', 'm',
        lambda b, e, a: a['actors']['m']['stopped'] is None
        and (a['actors']['m']['candidate'] or {}).get('kind') == 'freeze',
        falsely_reject_freeze, 'freeze rejection lacks original occupied plan')
    add('rejected_freeze_cannot_capture_another_context', 'K06_aborted_target', 'prepare_tech', 'm',
        lambda b, e, a: a['actors']['m']['stopped'] == 'freeze_not_available',
        rejected_freeze_recaptures_context, 'guard rejection changed original attempt')
    add('retained_read_cannot_borrow_foreign_absent_hold', 'K06_held_missing', 'admit', 'a',
        lambda b, e, a: a['actors']['a']['stopped'] is None,
        falsely_reject_held_read, 'retained rejection ignored original observed hold')
    add('rejected_hold_cannot_grant_current_generation_read', 'K06_held_missing', 'admit', 'a',
        lambda b, e, a: a['actors']['a']['stopped'] == 'no_retained_hold',
        rejected_hold_grants_current_context, 'guard rejection changed original attempt')
    add('original_closure_get_cannot_be_suppressed', 'K14_writer', 'get', 'b',
        lambda b, e, a: a['actors']['b']['stopped'] is None,
        falsely_reject_closure_get, 'closure rejection names an authorized original dependency')
    add('rejected_nonmember_cannot_issue_an_object_get', 'K14_writer', 'get', 'b',
        lambda b, e, a: a['actors']['b']['stopped'] == 'get_not_in_original_closure',
        rejected_nonmember_dispatches_get, 'guard rejection changed original tokens')
    return cases


def execute_case(case, before, event, honest, spec, profile, preserve):
    edge_checks(before, honest, spec, profile, event)
    state_checks(honest, spec, profile)
    changed = copy.deepcopy(honest)
    case['mutate'](before, event, changed, spec, profile)
    must(changed != honest, 'negative mutation did not change target')
    preserve(changed, 'MUTATION_SAVED_BEFORE_CHECK', None)
    try:
        edge_checks(before, changed, spec, profile, event)
        state_checks(changed, spec, profile)
    except Violation as error:
        preserve(changed, 'REJECTED_AT_REQUIRED_BOUNDARY' if case['boundary'] in str(error)
                 else 'FAILED_WRONG_REJECTION_BOUNDARY', str(error))
        must(case['boundary'] in str(error), 'negative rejected at wrong boundary: ' + case['name'] + ': ' + str(error))
        return changed, str(error)
    except Exception as error:
        preserve(changed, 'FAILED_CHECKER_EXCEPTION', type(error).__name__ + ': ' + str(error))
        raise
    preserve(changed, 'FAILED_NEGATIVE_ACCEPTED', None)
    raise Violation('negative accepted: ' + case['name'])


def run(graph, audit, output, inputs):
    spec = json.loads(inputs.read_text())
    profiles = {profile['id']: profile for profile in spec['profiles']}
    baseline = json.loads(audit.read_text())
    manifest_path = graph / 'manifest.json'
    must(baseline['status'] == 'PASS_WITHIN_DECLARED_MODEL_SCOPE' and baseline['whole_inventory'], 'complete baseline oracle required')
    must(bound_file(baseline['graph_manifest']) == manifest_path.read_bytes(), 'baseline graph identity changed')
    must(bound_file(baseline['inputs']) == inputs.read_bytes(), 'baseline input identity changed')
    manifest = json.loads(manifest_path.read_text())
    source = json.loads(bound_file(manifest['source_before']))
    for item in source:
        bound_file(item)
    output.mkdir(exist_ok=False)
    cases = candidates()
    results = []
    found = set()
    graph_controls_done = False
    for item in manifest['profiles']:
        report = json.loads(bound_file(item))
        selected = [case for case in cases if case['profile'] == report['profile']]
        graph_scope = report['profile'] == 'K17_after_dispatch_takeover'
        if not selected and not graph_scope:
            continue
        bound_file(report['states_file']); bound_file(report['edges_file'])
        states = States()
        for record in records(report['states_file']['path']):
            states.append(record)
        profile = profiles[report['profile']]
        for edge in records(report['edges_file']['path']):
            before, honest = states[edge['from']], states[edge['to']]
            event = edge['event']
            for case in selected:
                if case['name'] in found or (event['kind'] == 'network') != case['network']:
                    continue
                if not case['network'] and (event['op'] != case['op'] or event['actor'] != case['actor']):
                    continue
                if not case['predicate'](before, event, honest):
                    continue
                name = case['name']
                record = {'schema': 1, 'name': name,
                          'profile': profile['id'], 'profile_sha256': fingerprint(profile),
                          'states_file': report['states_file'], 'edges_file': report['edges_file'],
                          'original_edge': edge, 'connected_original_prefix': witness_path(states, edge),
                          'expected_boundary': case['boundary'],
                          'original_edge_positive': 'PASS'}
                path = output / (name + '.json')
                def preserve(changed, status, rejection):
                    write_json(path, {**record, 'status': status, 'changed_target': changed,
                                      'changed_target_sha256': fingerprint(changed), 'observed_rejection': rejection})
                execute_case(case, before, event, honest, spec, profile, preserve)
                found.add(name)
                results.append(identity(path))
            if graph_scope and not graph_controls_done:
                a = before['actors']['a']
                original = before['tokens'].get(a['cas'])
                if (not a['handle_open'] and a['local_stop'] and original and original['effect'] is None
                        and original['observation'] == {'kind': 'Unknown'}):
                    from oracle_protocol import expected_labels
                    labels = expected_labels(before, profile)
                    choice_closure(before, profile, labels)
                    altered = [label for label in labels if not (label.get('token') == a['cas'] and label.get('delivery') == 'apply')]
                    for name, values, boundary in [
                            ('omit_delivery_after_closed_caller', altered, 'enabled choice closure differs'),
                            ('duplicate_enabled_delivery', labels + [labels[0]], 'enabled choice repeated')]:
                        try:
                            choice_closure(before, profile, values)
                        except Violation as error:
                            must(boundary in str(error), 'wrong graph rejection boundary')
                            path = output / (name + '.json')
                            write_json(path, {'schema': 1, 'name': name, 'status': 'REJECTED_AT_REQUIRED_BOUNDARY',
                                              'profile': profile['id'], 'source_state': edge['from'],
                                              'source_sha256': states.hashes[edge['from']],
                                              'connected_original_prefix': witness_path(states, edge)[:-1],
                                              'original_choices': labels, 'mutated_choices': values,
                                              'expected_boundary': boundary, 'observed_rejection': str(error)})
                            results.append(identity(path))
                        else:
                            raise Violation('graph negative accepted: ' + name)
                    graph_controls_done = True
        if all(case['name'] in found for case in selected):
            print('CONTROLS', profile['id'], len(selected), flush=True)
    must(found == {case['name'] for case in cases}, 'negative control source edge unreachable: ' + ', '.join(sorted({case['name'] for case in cases} - found)))
    must(graph_controls_done, 'closed-caller pending delivery source unreachable')
    for item in source:
        bound_file(item)
    receipt = {'schema': 1, 'status': 'PASS_WITHIN_CONTROL_SCOPE', 'baseline': identity(audit),
               'graph_manifest': identity(manifest_path), 'inputs': identity(inputs),
               'semantic_negative_controls': len(cases), 'graph_negative_controls': 2,
               'positive_original_edges': len(cases), 'positive_original_choice_sets': 1,
               'results': results, 'source_unchanged': True,
               'limitations': 'Reachable original edge/prefix mutations against exact frozen independent rules; no new BFS or altered acceptance mode.'}
    write_json(output / 'receipt.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--graph', type=Path, required=True)
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, default=Path(__file__).with_name('inputs.json'))
    args = parser.parse_args()
    try:
        receipt = run(args.graph, args.audit, args.output, args.inputs)
        print(json.dumps({key: receipt[key] for key in ('status', 'semantic_negative_controls', 'graph_negative_controls')}), flush=True)
    except Exception as error:
        args.output.mkdir(exist_ok=True)
        write_json(args.output / 'failure.json', {'schema': 1, 'status': 'FAILED',
                                                 'error_type': type(error).__name__, 'error': str(error)})
        raise


if __name__ == '__main__':
    main()
