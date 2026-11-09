"""Independent proof obligations for recorded graphs; imports no producer code.

This checks evidence and allowed changes, not a second call to the reducer. The
finite input determines the enabled labels; concrete original tokens determine
backend effects and client knowledge. A rejection is checked at its actual edge.
"""

import copy
import hashlib
import json


class Violation(Exception):
    pass


def must(value, message):
    if not value:
        raise Violation(message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def fingerprint(value):
    return hashlib.sha256(wire(value)).hexdigest()


def authority_slot(scope):
    return 'scap-object/v1/{deployment}/{tenant}/{database}/head'.format(**scope)


def physical_key(scope, generation, name):
    return ('scap-object/v1/{deployment}/{tenant}/{database}/inc/{incarnation}/gen/{generation}'
            .format(**scope) + '/storage/' + str(generation) + '/objects/' + name)


def version(head):
    return '"head:' + fingerprint(head) + '"'


def permanent(head, generation):
    excluded = {head['A']}
    if head['plan'] is not None:
        excluded.add(head['plan']['target'])
    if head['hold'] is not None:
        excluded.add(head['hold']['generation'])
    return generation in range(1, head['M'] + 1) and generation not in excluded


def valid_authority(value, scope, maximum):
    if not isinstance(value, dict) or value.get('format') != 'MODELHEAD-KNOWLEDGE1' or value.get('scope') != scope:
        return False
    for field in ('serial', 'revision', 'A', 'M'):
        if type(value.get(field)) is not int:
            return False
    if not 1 <= value['revision'] <= value['serial'] or not 1 <= value['A'] <= value['M'] <= maximum:
        return False
    plan, hold = value.get('plan'), value.get('hold')
    if plan is not None and (not isinstance(plan, dict) or plan.get('scope') != scope
                            or plan.get('source') != value['A']
                            or not value['A'] < plan.get('target', 0) <= value['M']
                            or plan.get('roots') != {'data': value.get('data'), 'index': value.get('index')}
                            or plan.get('phase') not in ('copying', 'sealed')):
        return False
    if hold is not None and (not isinstance(hold, dict) or hold.get('scope') != scope
                            or not 1 <= hold.get('generation', 0) <= value['M']):
        return False
    return value.get('life') in ('ready', 'maintenance', 'deleted')


def decoded_head(result):
    if not result or result.get('kind') != 'Found':
        return None
    try:
        return json.loads(bytes.fromhex(result['raw']))
    except (ValueError, UnicodeDecodeError, KeyError):
        return None


def read_frame(raw):
    value = bytes.fromhex(raw)
    must(value.startswith(b'MODELKNOWLEDGE1\n'), 'raw frame prefix')
    try:
        metadata = json.loads(value.partition(b'\n')[2])
    except (ValueError, UnicodeDecodeError) as error:
        raise Violation('raw frame metadata') from error
    must(metadata.get('format') == 'MODELKNOWLEDGE1', 'raw frame version')
    return metadata


def knowledge(state, profile, actor):
    return state['lineages'][profile['actors'][actor]['lineage']]


def local_healthy(known, generation):
    return not (known['authority'] or known['semantic'] or str(generation) in known['physical'])


def permitted(head, principal, rights):
    grant = head['acl'].get(str(principal), {})
    return all(grant.get(item) is True for item in rights)


def same_except(before, after, allowed, message):
    must(set(before) == set(after), message + ' schema')
    for key in before:
        if key not in allowed:
            must(before[key] == after[key], message + ': ' + key)


def expected_labels(state, profile):
    labels = []
    for identifier, token in sorted(state['tokens'].items()):
        if token['effect'] is None:
            for disposition in ('apply', 'discard'):
                labels.append({'kind': 'network', 'token': identifier, 'delivery': disposition})
    for who, actor in sorted(state['actors'].items()):
        program = profile['actors'][who]['program']
        if actor['stopped'] is not None or actor['pc'] >= len(program):
            continue
        instruction = program[actor['pc']]
        options = ['run']
        if instruction['op'] == 'await':
            other, marker = instruction['condition']['mark']
            if state['actors'][other]['marks'].get(marker) is not True:
                continue
        if instruction['op'] == 'observe' and not actor['no_work']:
            request = state['tokens'].get(actor['last'])
            if request and request['observation'] is None:
                options = []
                if request['effect'] is not None:
                    options.append('known')
                if request['request']['uncertain']:
                    options.append('unknown')
                if not options:
                    continue
        if instruction['op'] == 'native_publish':
            options = ['commit', 'fail'] if actor['known_commit'] else ['abort']
        labels += [{'kind': 'client', 'actor': who, 'pc': actor['pc'], 'op': instruction['op'], 'choice': option}
                   for option in options]
    return labels


def choice_closure(state, profile, labels):
    actual = [wire(label) if isinstance(label, dict) else label for label in labels]
    wanted = {wire(label) for label in expected_labels(state, profile)}
    must(len(actual) == len(set(actual)), 'enabled choice repeated')
    must(set(actual) == wanted, 'enabled choice closure differs')


def observed_authority(state, who, token_id):
    token = state['tokens'].get(token_id)
    must(token is not None and token['actor'] == who, 'authority token not original actor')
    must(token['request']['method'] == 'HEAD_GET' and token['request']['purpose'] == 'admit',
         'authority token is not fresh admission')
    result = token['observation']
    must(result and result['kind'] == 'Found', 'authority not actually observed')
    return token, decoded_head(result)


def closure(actor):
    context = actor['context']
    must(context is not None, 'closure lacks original context')
    roots = [(context['roots']['index'], 'index')]
    if context['mode'] != 'lookup':
        roots.append((context['roots']['data'], 'manifest'))
    required = {}
    queue = list(roots)
    while queue:
        key, kind = queue.pop()
        if key in required:
            must(required[key] == kind, 'closure aliases different incoming types')
            continue
        required[key] = kind
        if key not in actor['frames']:
            continue
        frame = read_frame(actor['frames'][key]['raw'])
        must(frame['kind'] == kind, 'observed prefix contains wrong child type')
        if kind == 'manifest':
            queue += [(child, 'chunk') for child in frame['children']]
        elif kind == 'index':
            queue += [(entry['result'], 'result') for entry in frame['entries']]
    return required


def frame_provenance(state, profile, who, frame_hash, frame, purpose):
    actor = state['actors'][who]
    context = actor['context']
    token = state['tokens'].get(frame['token'])
    must(token is not None and token['actor'] == who and token['lineage'] == context['lineage'],
         'frame adopted from another attempt')
    request, response = token['request'], token['observation']
    must(request['method'] == 'GET' and request['purpose'] == purpose, 'frame not actual original GET')
    must(request['domain'] == context['domain'] and request['scope'] == context['scope']
         and request['generation'] == context['generation'] and request['hash'] == frame_hash
         and request['context_token'] == context['view_token'], 'frame original context changed')
    must(request['key'] == physical_key(context['scope'], context['generation'], frame_hash), 'frame physical key changed')
    must(response and response['kind'] == 'Found' and response['raw'] == frame['raw'], 'frame bytes not original observation')
    must(hashlib.sha256(bytes.fromhex(frame['raw'])).hexdigest() == frame_hash, 'frame digest mismatch')
    metadata = read_frame(frame['raw'])
    must(metadata['scope'] == context['scope'] and metadata['kind'] == frame['kind'] == request['expected_kind'],
         'frame scope/type mismatch')


def semantic_bad_response(request, result):
    try:
        value = read_frame(result['raw'])
        if value['scope'] != request['scope'] or value['kind'] != request['expected_kind']:
            return True
        return value['kind'] == 'result' and (value['request'] != 'Q1' or value['principal'] != 7
                                             or value['sequence'] != 1 or value['revision'] != 2)
    except (Violation, KeyError, TypeError):
        return True


def incident_provenance(state, line_id, generation, incident):
    token = state['tokens'].get(incident['origin'])
    must(token is not None and token['lineage'] == line_id, 'incident crossed lineage')
    request, observed = token['request'], token['observation']
    must(request['method'] == 'GET' and request['generation'] == int(generation) and observed is not None,
         'incident without original source GET')
    must(observed['kind'] == 'NoSuchKey' or (observed['kind'] == 'Found'
         and hashlib.sha256(bytes.fromhex(observed['raw'])).hexdigest() != request['hash']),
         'physical incident without physical evidence')
    if incident['proof'] is None:
        must(incident['status'] == 'unresolved', 'incident changed without original probe')
        return
    probe = state['tokens'].get(incident['proof'])
    must(probe and probe['actor'] == token['actor'] and probe['lineage'] == line_id, 'probe borrowed from another actor')
    p = probe['request']
    must(p['method'] == 'HEAD_GET' and p['purpose'] == 'probe' and p['failure_token'] == incident['origin']
         and p['domain'] == request['domain'] and p['scope'] == request['scope']
         and p['key'] == authority_slot(request['scope']), 'probe domain/scope/purpose changed')
    must(probe['observation'] is not None, 'probe not actually observed')


def state_checks(state, spec, profile):
    must(set(state) == {'world', 'lineages', 'actors', 'tokens'}, 'state schema')
    must(set(state['actors']) == set(profile['actors']), 'actor inventory changed')
    must(set(state['lineages']) == set(profile['initial']['lineages']), 'lineage inventory changed')
    must(len(state['tokens']) <= spec['bounds']['tokens'], 'network token bound')
    for domain, heads in state['world']['heads'].items():
        for key, head in heads.items():
            must(key == authority_slot(head['scope']) and valid_authority(head, spec['scope'], spec['bounds']['generations']),
                 'authoritative state invalid')
    for line_id, known in state['lineages'].items():
        original = profile['initial']['lineages'][line_id]
        for field in ('domain', 'scope', 'worker'):
            must(known[field] == original[field], 'lineage identity rebound')
        for generation, incident in known['physical'].items():
            must(incident['status'] in ('unresolved', 'expired', 'corrupt'), 'unknown incident status')
            incident_provenance(state, line_id, generation, incident)
            if incident['proof'] is not None:
                proof = decoded_head(state['tokens'][incident['proof']]['observation'])
                if valid_authority(proof, known['scope'], spec['bounds']['generations']):
                    wanted = 'expired' if permanent(proof, int(generation)) else 'corrupt'
                else:
                    wanted = 'unresolved'
                must(incident['status'] == wanted, 'incident classification differs from own authority')
    for who, actor in state['actors'].items():
        must(0 <= actor['pc'] <= len(profile['actors'][who]['program']), 'program counter outside bound')
        if actor['view'] is not None:
            token, head = observed_authority(state, who, actor['view_token'])
            must(head == actor['view']['head'] and token['observation']['etag'] == actor['view']['etag']
                 and token['request']['domain'] == actor['view']['domain']
                 and token['request']['key'] == actor['view']['key'], 'view not original observed body/ETag')
            must(valid_authority(head, knowledge(state, profile, who)['scope'], spec['bounds']['generations']),
                 'invalid authority became a usable view')
        context = actor['context']
        if context is not None:
            token, original = observed_authority(state, who, context['view_token'])
            must(context['head'] == original and context['etag'] == token['observation']['etag']
                 and context['domain'] == token['request']['domain'] and context['scope'] == token['request']['scope']
                 and context['key'] == token['request']['key']
                 and context['lineage'] == profile['actors'][who]['lineage'], 'captured context rebound')
            for name, frame in actor['frames'].items():
                frame_provenance(state, profile, who, name, frame, 'read')
            for name, frame in actor['readbacks'].items():
                frame_provenance(state, profile, who, name, frame, 'readback')
            closure(actor)
        if actor['materialized'] is not None:
            image = actor['materialized']
            must(context is not None and image['lineage'] == context['lineage']
                 and image['context_token'] == context['view_token'] and image['generation'] == context['generation']
                 and image['mode'] == context['mode'] and image['frames'] == actor['frames'], 'image moved between attempts')
            must(set(closure(actor)) == set(image['frames']), 'image is not complete observed closure')
        if actor['known_commit'] is not None:
            token = state['tokens'].get(actor['known_commit'])
            must(token and token['actor'] == who and token['request']['method'] == 'HEAD_CAS'
                 and token['observation'] and token['observation']['kind'] == 'Applied', 'invented known durable publication')
        if actor['permit'] is not None:
            must(actor['candidate'] is not None and actor['permit']['candidate_hash'] == fingerprint(actor['candidate'])
                 and actor['permit']['lineage'] == profile['actors'][who]['lineage'], 'permit rebound')
        if actor['outcome'] and actor['outcome']['kind'] == 'Ack':
            must(actor['known_commit'] == actor['outcome']['token'], 'ACK not original known CAS')
            if actor['candidate']['kind'] == 'writer':
                must(actor['native'] == 'committed', 'writer ACK before native publication')
        if actor['failure'] and actor['failure']['kind'] == 'physical':
            origin = state['tokens'][actor['failure']['token']]
            must(origin['actor'] == who and origin['request']['domain'] == actor['failure']['domain']
                 and origin['request']['scope'] == actor['failure']['scope'], 'failure capsule rebound')


def backend_check(before, after, spec, event):
    identifier = event['token']
    token = before['tokens'][identifier]
    must(token['effect'] is None, 'backend replay')
    same_except(before, after, {'world', 'tokens'}, 'backend changed client knowledge')
    must(set(before['tokens']) == set(after['tokens']), 'backend changed token inventory')
    for name, old in before['tokens'].items():
        if name != identifier:
            must(old == after['tokens'][name], 'backend changed another token')
    same_except(token, after['tokens'][identifier], {'effect'}, 'backend changed immutable request/observation')
    request = token['request']
    world = copy.deepcopy(before['world'])
    domain, key = request['domain'], request['key']
    if event['delivery'] == 'discard':
        expected = {'kind': 'Unavailable', 'delivered': False}
    elif request['method'] == 'HEAD_GET':
        fault = world['head_fault'][domain]
        value = world['heads'][domain].get(key)
        if fault == 'unavailable':
            expected = {'kind': 'Unavailable', 'delivered': True}
        elif value is None:
            expected = {'kind': 'NoSuchKey', 'delivered': True}
        else:
            value = copy.deepcopy(value)
            if fault == 'wrong_scope':
                value['scope'] = copy.deepcopy(spec['foreign_scope'])
            raw = b'broken HEAD' if fault == 'malformed' else wire(value)
            expected = {'kind': 'Found', 'raw': raw.hex(), 'etag': version(value), 'delivered': True}
    elif request['method'] == 'GET':
        found = world['objects'][domain].get(key)
        expected = {'kind': 'Found', **found, 'delivered': True} if found else {'kind': 'NoSuchKey', 'delivered': True}
    elif request['method'] == 'PUT_ABSENT':
        if key in world['objects'][domain]:
            expected = {'kind': 'Conflict', 'delivered': True}
        else:
            tag = '"object:' + str(world['object_version']) + '"'
            world['object_version'] += 1
            world['objects'][domain][key] = {'raw': request['raw'], 'etag': tag}
            expected = {'kind': 'Applied', 'etag': tag, 'delivered': True}
    else:
        must(request['method'] == 'HEAD_CAS', 'unknown network method')
        current = world['heads'][domain].get(key)
        if current is not None and version(current) == request['etag']:
            value = json.loads(bytes.fromhex(request['raw']))
            world['heads'][domain][key] = value
            expected = {'kind': 'Applied', 'etag': version(value), 'delivered': True}
        else:
            expected = {'kind': 'Conflict', 'delivered': True}
    must(after['tokens'][identifier]['effect'] == expected, 'backend original-condition effect')
    must(after['world'] == world, 'backend changed world beyond original request')


ACTOR_CHANGES = {
    'await': set(), 'mark': {'marks'}, 'begin': {'handle_open'},
    'fault_head': set(), 'fault_object': set(), 'fault_captured': set(), 'remove_retired': set(),
    'release_handle': {'handle_open', 'marks'}, 'stop_local': {'local_stop'}, 'detach': {'detached'},
    'attempt_adopt': set(), 'attempt_expire_semantic': set(),
    'head_get': {'last', 'last_result', 'no_work'},
    'get': {'last', 'last_result', 'no_work'}, 'get_root': {'last', 'last_result', 'no_work'},
    'load_next': {'last', 'last_result', 'no_work'}, 'put': {'last', 'last_result', 'no_work'},
    'probe': {'probe_used', 'last', 'last_result', 'no_work'},
    'observe': {'no_work', 'last_result', 'view', 'view_token', 'known_commit', 'failure', 'frames', 'readbacks'},
    'admit': {'context'}, 'materialize': {'materialized'}, 'materialize_lookup': {'materialized'},
    'validate_content': {'content_validated', 'failure'},
    'return_read': {'outcome'}, 'return_lookup': {'outcome'},
    'native_execute': {'native'}, 'native_publish': {'native'}, 'begin_commit': {'commit_started'},
    'prepare_write': {'candidate', 'permit', 'cas', 'known_commit'},
    'prepare_manage': {'candidate', 'permit', 'cas', 'known_commit'},
    'prepare_tech': {'candidate', 'permit', 'cas', 'known_commit', 'context'},
    'final_check': {'permit'}, 'send_head': {'permit', 'cas', 'last', 'last_result', 'no_work'},
    'classify': {'failure', 'outcome'}, 'ack': {'outcome'},
}
ISSUE_OPS = {'head_get', 'get', 'get_root', 'load_next', 'put', 'probe', 'send_head'}
FIXTURE_OPS = {'fault_head', 'fault_object', 'fault_captured', 'remove_retired'}
ORDINARY_OPS = {'head_get', 'get', 'get_root', 'load_next', 'put', 'admit', 'materialize',
                'materialize_lookup', 'validate_content', 'return_read', 'return_lookup',
                'native_execute', 'begin_commit', 'prepare_write', 'prepare_manage', 'prepare_tech',
                'final_check', 'send_head'}


def allowed_changes(before, after, profile, event):
    who, op = event['actor'], event['op']
    must(op in ACTOR_CHANGES, 'unregistered client operation')
    must(set(before['tokens']) <= set(after['tokens']), 'client removed old token')
    must(set(before['actors']) == set(after['actors']), 'client changed actor inventory')
    for other, old in before['actors'].items():
        if other != who:
            must(old == after['actors'][other], 'client changed another actor')
    same_except(before['actors'][who], after['actors'][who], ACTOR_CHANGES[op] | {'pc', 'stopped', 'outcome'},
                'client changed unrelated actor state')
    for identifier, old in before['tokens'].items():
        allowed = {'observation'} if op == 'observe' and identifier == before['actors'][who]['last'] else set()
        same_except(old, after['tokens'][identifier], allowed, 'client changed old token')
    added = set(after['tokens']) - set(before['tokens'])
    must(not added or op in ISSUE_OPS, 'client created token outside dispatch')
    must(len(added) <= 1, 'client issued multiple unaccounted requests')
    line_id = profile['actors'][who]['lineage']
    for other, old in before['lineages'].items():
        new = after['lineages'][other]
        if other != line_id:
            must(old == new, 'client crossed knowledge lineage')
        else:
            fields = ({'created'} if op == 'begin' else
                      {'physical', 'authority', 'semantic'} if op in ('observe', 'classify', 'validate_content') else set())
            same_except(old, new, fields, 'client changed unrelated lineage knowledge')
            must(not old['created'] or new['created'], 'lineage creation undone')
            must(not old['authority'] or new['authority'], 'authority latch cleared')
            must(not old['semantic'] or new['semantic'], 'semantic latch cleared')
            must(set(old['physical']) <= set(new['physical']), 'physical incident cleared')
            for generation, incident in old['physical'].items():
                changed = incident != new['physical'][generation]
                if changed:
                    must(op == 'classify' and before['actors'][who]['failure']
                         and incident['origin'] == before['actors'][who]['failure']['token'], 'unrelated incident altered')
                    must(incident['origin'] == new['physical'][generation]['origin'], 'incident origin rebound')
    if op not in FIXTURE_OPS:
        must(before['world'] == after['world'], 'nonfixture client changed backend/fault injection')


def justified_rejection(before, after, spec, profile, event):
    who, op = event['actor'], event['op']
    actor = before['actors'][who]
    reason = after['actors'][who]['stopped']
    command = profile['actors'][who]['program'][actor['pc']]
    if reason == 'local_gate_closed':
        must(op not in ('observe', 'native_publish', 'ack', 'mark', 'await', 'release_handle')
             and (actor['local_stop'] or actor['detached']), 'invented local gate rejection')
    elif reason == 'failed_attempt_closed':
        reads_response = (op == 'observe' and not actor['no_work'] and actor['last'] is not None
                          and before['tokens'][actor['last']]['request']['method'] == 'GET')
        must(actor['failure'] is not None and (op in ORDINARY_OPS or reads_response),
             'failed-attempt rejection outside ordinary guard')
    elif reason == 'publication_latched':
        must(op in ('begin_commit', 'prepare_write', 'prepare_manage', 'prepare_tech', 'final_check'),
             'read falsely blocked by publication-only latch')
        generation = (actor['candidate']['generation'] if op == 'final_check' else
                      actor['view']['head']['A'] if op == 'prepare_tech' else actor['context']['generation'])
        must(not local_healthy(knowledge(before, profile, who), generation), 'false global/foreign publication block')
    elif reason.startswith('foreign_') and reason.endswith('_rejected'):
        must(op == 'attempt_adopt' and reason == 'foreign_' + command['kind'] + '_rejected'
             and profile['actors'][who]['lineage'] != profile['actors'][command['source']]['lineage'], 'invented adoption rejection')
    elif reason == 'semantic_failure_cannot_expire':
        must(op == 'attempt_expire_semantic' and actor['failure']['kind'] == 'semantic', 'wrong semantic-expiry rejection')
    elif reason in ('head_unavailable', 'object_get_unavailable', 'object_put_unavailable'):
        must(op == 'observe', 'transport rejection outside observation')
        request = before['tokens'][actor['last']]['request']
        result = after['tokens'][actor['last']]['observation']
        method = {'head_unavailable': 'HEAD_GET', 'object_get_unavailable': 'GET', 'object_put_unavailable': 'PUT_ABSENT'}[reason]
        must(request['method'] == method and result['kind'] in ('Unavailable', 'Unknown', 'NoSuchKey'), 'transport rejection without evidence')
    elif reason in ('authority_corrupt', 'source_missing', 'source_hash', 'source_semantic'):
        must(op == 'observe' and not command.get('allow_failure'), 'unexpected corruption rejection')
        failure = after['actors'][who]['failure']
        expected = {'authority_corrupt': 'authority', 'source_missing': 'physical',
                    'source_hash': 'physical', 'source_semantic': 'semantic'}[reason]
        must(failure and failure['kind'] == expected and failure['token'] == actor['last'], 'corruption rejection without own observation')
    elif reason == 'content_invalid':
        must(op == 'validate_content' and not command.get('allow_failure')
             and actor['context']['roots']['data'] in before['world']['semantic_bad_roots'], 'invented content rejection')
    else:
        # No generic "safe error" acceptance. A new guard outcome in a program
        # requires an explicit independently reviewed obligation here.
        raise Violation('unaccounted rejection boundary: ' + str(reason))


def request_creation(before, after, spec, profile, event, token_id):
    who, op = event['actor'], event['op']
    actor, next_actor = before['actors'][who], after['actors'][who]
    command = profile['actors'][who]['program'][actor['pc']]
    token = after['tokens'][token_id]
    must(token_id == f'{who}:{actor["pc"]}' and token['actor'] == who
         and token['lineage'] == profile['actors'][who]['lineage'], 'new token identity')
    must(token['effect'] is None and token['observation'] is None, 'new token already delivered/observed')
    must(next_actor['last'] == token_id and next_actor['last_result'] is None and not next_actor['no_work'], 'new request not original pending token')
    request = token['request']
    must(actor['handle_open'] and not actor['local_stop'] and not actor['detached'], 'new dispatch after local gate closure')
    if op == 'probe':
        failure = actor['failure']
        must(failure and failure['kind'] == 'physical' and not actor['probe_used'], 'failure probe not once')
        must(request == {'method': 'HEAD_GET', 'domain': failure['domain'], 'scope': failure['scope'],
                         'key': authority_slot(failure['scope']), 'purpose': 'probe',
                         'failure_token': failure['token'], 'uncertain': command['uncertain']}, 'failure probe rebound')
        must(next_actor['probe_used'], 'probe capability not consumed')
        return
    must(actor['failure'] is None, 'new dispatch revived failed prefix')
    line = knowledge(before, profile, who)
    if op == 'head_get':
        must(request == {'method': 'HEAD_GET', 'domain': line['domain'], 'scope': line['scope'],
                         'key': authority_slot(line['scope']), 'purpose': command['purpose'],
                         'uncertain': command['uncertain']}, 'fresh HEAD request not own lineage')
        return
    if op == 'send_head':
        candidate, permit = actor['candidate'], actor['permit']
        must(candidate and permit and permit['candidate_hash'] == fingerprint(candidate), 'dispatch without last-check capability')
        must(request == {'method': 'HEAD_CAS', 'domain': candidate['domain'], 'scope': candidate['scope'],
                         'key': candidate['key'], 'etag': candidate['etag'], 'raw': candidate['raw'],
                         'generation': candidate['generation'], 'purpose': candidate['kind'],
                         'candidate_hash': fingerprint(candidate), 'permit': permit,
                         'context_token': candidate['view_token'], 'uncertain': command.get('uncertain', False)}, 'publication rebound after final check')
        must(next_actor['permit'] is None and next_actor['cas'] == token_id, 'publication permit not consumed exactly once')
        return  # A later lineage latch is deliberately not a dispatch precondition.
    context = actor['context']
    must(context is not None and request['domain'] == context['domain'] and request['scope'] == context['scope']
         and request['generation'] == context['generation'] and request['context_token'] == context['view_token'], 'object request moved from captured context')
    must(request['key'] == physical_key(context['scope'], context['generation'], request['hash'])
         and request['uncertain'] is False, 'object physical key changed')
    if op == 'put':
        frame = spec['frames'][command['name']]
        must(request['method'] == 'PUT_ABSENT' and request['purpose'] == 'write_dependency'
             and request['hash'] == frame['hash'] and request['raw'] == frame['raw']
             and context['mode'] == 'write' and actor['native'] == 'executed' and actor['commit_started'],
             'object PUT without original execution/dependency bytes')
    else:
        must(request['method'] == 'GET', 'object read changed method')
        if request['purpose'] == 'readback':
            frame = spec['frames'][command['name']]
            must(context['mode'] == 'write' and actor['native'] == 'executed'
                 and request['hash'] == frame['hash'] and request['expected_kind'] == frame['kind'], 'readback not own dependency')
        else:
            wanted = closure(actor)
            must(request['purpose'] == 'read' and request['hash'] in wanted
                 and request['expected_kind'] == wanted[request['hash']], 'GET bypassed original typed frontier')
            if op == 'get':
                must(request['hash'] == spec['frames'][command['name']]['hash'], 'GET changed explicit candidate')
            if op == 'get_root':
                must(request['hash'] == context['roots']['data'], 'GET changed captured root')


def candidate_check(before, after, spec, profile, event):
    who, op = event['actor'], event['op']
    actor, updated = before['actors'][who], after['actors'][who]
    command = profile['actors'][who]['program'][actor['pc']]
    candidate = updated['candidate']
    expected_kind = 'writer' if op == 'prepare_write' else command['kind']
    must(candidate['kind'] == expected_kind, 'candidate constructor kind differs from original operation')
    context = updated['context'] if op == 'prepare_tech' else actor['context']
    if op == 'prepare_tech':
        view = actor['view']
        must(view is not None, 'technical step without original fresh view')
        original = view['head']
        must(context == {'domain': view['domain'], 'scope': original['scope'],
                         'lineage': profile['actors'][who]['lineage'], 'generation': original['A'],
                         'roots': {'data': original['data'], 'index': original['index']},
                         'mode': 'technical', 'plan': original['plan'], 'head': original,
                         'etag': view['etag'], 'key': view['key'], 'view_token': actor['view_token']},
             'technical context differs from original fresh authority')
    base = context['head']
    value = json.loads(bytes.fromhex(candidate['raw']))
    must(candidate['domain'] == context['domain'] and candidate['scope'] == context['scope']
         and candidate['lineage'] == context['lineage'] and candidate['generation'] == context['generation']
         and candidate['key'] == context['key'] and candidate['etag'] == context['etag']
         and candidate['base'] == base and candidate['view_token'] == context['view_token'], 'candidate not original authority')
    must(value['scope'] == base['scope'] and value['serial'] == base['serial'] + 1, 'candidate serial/scope')
    must(local_healthy(knowledge(before, profile, who), context['generation']), 'candidate prepared despite own latch')
    kind = candidate['kind']
    expected = copy.deepcopy(base)
    expected['serial'] += 1
    if kind in ('writer', 'takeover', 'policy'):
        expected['revision'] += 1
    if kind == 'writer':
        must(op == 'prepare_write' and context['mode'] == 'write' and actor['native'] == 'executed'
             and actor['commit_started'] and actor['content_validated'], 'writer candidate without original execution')
        must(set(actor['readbacks']) == {spec['frames'][x]['hash'] for x in ('C1', 'M1', 'R1', 'I1')}, 'writer lacks complete own durable readbacks')
        expected.update(sequence=base['sequence'] + 1, data=spec['frames']['M1']['hash'], index=spec['frames']['I1']['hash'])
    elif kind == 'takeover':
        must(op == 'prepare_manage' and context['mode'] == 'manage', 'takeover bypassed admission')
        expected.update(owner=knowledge(before, profile, who)['worker'], owner_epoch=base['owner_epoch'] + 1, active=False)
    elif kind == 'policy':
        must(op == 'prepare_manage' and context['mode'] == 'manage', 'policy bypassed admission')
        expected['auth_epoch'] += 1
        expected['acl']['8']['read'] = not base['acl']['8']['read']
    else:
        must(op == 'prepare_tech' and permitted(base, profile['actors'][who]['principal'], ('admin',))
             and base['life'] != 'deleted', 'new technical step lacks its current ADMIN')
        must(context['view_token'] == actor['view_token'] and context['head'] == actor['view']['head'], 'technical step reused stale view')
        if kind == 'hold_add':
            must(base['hold'] is None, 'hold replacement')
            expected['hold'] = {'id': 'HOLD1', 'scope': base['scope'], 'generation': base['A'],
                                'roots': {'data': base['data'], 'index': base['index']}}
        elif kind == 'promote':
            must(base['plan'] and base['plan']['phase'] == 'sealed', 'promotion without exact sealed initial plan')
            expected.update(A=base['plan']['target'], plan=None, active=False)
        elif kind == 'abort_plan':
            must(base['plan'] is not None, 'abandon without original plan')
            expected['plan'] = None
        elif kind == 'freeze':
            must(base['plan'] is None and base['M'] < spec['bounds']['generations'], 'new target not freshly allocated')
            expected['M'] += 1
            expected['active'] = False
            expected['plan'] = {'id': 'P' + str(expected['M']), 'scope': base['scope'], 'source': base['A'],
                                'target': expected['M'], 'started_serial': expected['serial'], 'phase': 'copying',
                                'roots': {'data': base['data'], 'index': base['index']}}
        else:
            must(kind == 'fence', 'unexpected technical verb')
            expected['revision'] += 1
            expected['auth_epoch'] += 1
    must(value == expected and candidate['raw'] == wire(expected).hex(), 'candidate changed fields outside closed constructor')
    must(updated['permit'] is None and updated['cas'] is None and updated['known_commit'] is None,
         'candidate inherited prior permit/knowledge')


def observation_check(before, after, spec, profile, event):
    who = event['actor']
    actor, updated = before['actors'][who], after['actors'][who]
    if actor['no_work']:
        must(not updated['no_work'] and updated['last_result'] == {'kind': 'NoWork'}, 'no-work observation forged')
        return
    identifier = actor['last']
    token, changed = before['tokens'][identifier], after['tokens'][identifier]
    must(token['actor'] == who and token['observation'] is None, 'observation not own single response')
    if event['choice'] == 'unknown':
        must(token['request']['uncertain'], 'UNKNOWN branch not declared')
        result = {'kind': 'Unknown'}
    else:
        must(token['effect'] is not None, 'known observation before delivery')
        result = token['effect']
    must(changed['observation'] == result and updated['last_result'] == result, 'observation does not retain actual result')
    request = token['request']
    method = request['method']
    if method == 'HEAD_CAS':
        must(updated['known_commit'] == (identifier if result['kind'] == 'Applied' else None), 'UNKNOWN/Conflict promoted to known commit')
    elif method == 'HEAD_GET' and request['purpose'] != 'probe':
        head = decoded_head(result)
        usable = valid_authority(head, request['scope'], spec['bounds']['generations'])
        if usable:
            must(updated['view'] == {'head': head, 'etag': result['etag'], 'domain': request['domain'], 'key': request['key']}
                 and updated['view_token'] == identifier, 'fresh view not original body/ETag')
        else:
            must(updated['view'] == actor['view'] and updated['view_token'] == actor['view_token'], 'bad authority became new view')
            if result['kind'] == 'Found':
                must(updated['failure'] == {'kind': 'authority', 'token': identifier, 'classification': 'corrupt'}
                     and knowledge(after, profile, who)['authority'], 'bad authority not locally latched')
    elif method == 'GET' and result['kind'] in ('Found', 'NoSuchKey'):
        physical = result['kind'] == 'NoSuchKey' or hashlib.sha256(bytes.fromhex(result['raw'])).hexdigest() != request['hash']
        if physical:
            failure = updated['failure']
            must(failure and failure['kind'] == 'physical' and failure['token'] == identifier
                 and failure['classification'] == 'unresolved' and failure['generation'] == request['generation']
                 and failure['domain'] == request['domain'] and failure['scope'] == request['scope']
                 and failure['key'] == request['key'] and failure['hash'] == request['hash'], 'physical failure provenance')
            must(updated['frames'] == actor['frames'] and updated['readbacks'] == actor['readbacks'], 'failed response extended prefix')
        elif semantic_bad_response(request, result):
            must(updated['failure'] and updated['failure']['kind'] == 'semantic' and updated['failure']['token'] == identifier,
                 'hash-valid semantic error downgraded to physical expiry')
            must(knowledge(after, profile, who)['semantic'], 'semantic failure not latched')
        else:
            must(updated['failure'] is None, 'valid source response invented a semantic failure')
            which = 'readbacks' if request['purpose'] == 'readback' else 'frames'
            expected = copy.deepcopy(actor[which])
            metadata = read_frame(result['raw'])
            expected[request['hash']] = {'token': identifier, 'raw': result['raw'], 'kind': metadata['kind']}
            must(updated[which] == expected, 'successful response did not retain exact original bytes')
            other = 'frames' if which == 'readbacks' else 'readbacks'
            must(updated[other] == actor[other], 'response modified unrelated prefix')


def knowledge_changes(before, after, spec, profile, event):
    """A permitted field is not permission to invent knowledge in that field."""
    who, op = event['actor'], event['op']
    line_id = profile['actors'][who]['lineage']
    if line_id is None:
        return
    expected = copy.deepcopy(before['lineages'][line_id])
    actor = before['actors'][who]
    if op == 'begin' and after['actors'][who]['stopped'] is None:
        if profile['actors'][who]['program'][actor['pc']]['new']:
            expected['created'] = True
    elif op == 'observe' and not actor['no_work']:
        identifier = actor['last']
        request = before['tokens'][identifier]['request']
        result = after['tokens'][identifier]['observation']
        if request['method'] == 'HEAD_GET' and request['purpose'] != 'probe' and result['kind'] == 'Found':
            if not valid_authority(decoded_head(result), request['scope'], spec['bounds']['generations']):
                expected['authority'] = True
        elif request['method'] == 'GET' and result['kind'] in ('Found', 'NoSuchKey'):
            physical = result['kind'] == 'NoSuchKey' or hashlib.sha256(bytes.fromhex(result['raw'])).hexdigest() != request['hash']
            if physical:
                expected['physical'].setdefault(str(request['generation']),
                                                {'status': 'unresolved', 'origin': identifier, 'proof': None})
            elif semantic_bad_response(request, result):
                expected['semantic'] = True
    elif op == 'classify' and after['actors'][who]['stopped'] is None:
        failure = actor['failure']
        result = before['tokens'][actor['last']]['observation']
        value = decoded_head(result)
        valid = valid_authority(value, failure['scope'], spec['bounds']['generations'])
        status = ('expired' if permanent(value, failure['generation']) else 'corrupt') if valid else 'unresolved'
        if result['kind'] == 'Found' and not valid:
            expected['authority'] = True
        incident = expected['physical'][str(failure['generation'])]
        if incident['origin'] == failure['token']:
            incident.update(status=status, proof=actor['last'])
    elif op == 'validate_content' and actor['materialized'] is not None and actor['failure'] is None:
        if actor['context']['roots']['data'] in before['world']['semantic_bad_roots']:
            expected['semantic'] = True
    must(after['lineages'][line_id] == expected, 'knowledge update lacks this operation\'s exact original evidence')


def fixture_check(before, after, spec, profile, event):
    who = event['actor']
    must(profile['actors'][who]['role'] == 'fixture', 'unprivileged fault injection')
    command = profile['actors'][who]['program'][event['pc']]
    world = copy.deepcopy(before['world'])
    if command['op'] == 'fault_head':
        world['head_fault']['D0'] = command['mode']
    else:
        if command['op'] == 'fault_captured':
            context = before['actors'][command['actor']]['context']
            domain, scope, generation = context['domain'], context['scope'], context['generation']
            frame = next(item for item in spec['frames'].values() if item['hash'] == context['roots']['data'])
        else:
            domain, scope, generation = 'D0', spec['scope'], command['generation']
            frame = spec['frames'][command['name']]
        key = physical_key(scope, generation, frame['hash'])
        if command['op'] == 'remove_retired':
            must(permanent(world['heads'][domain][authority_slot(scope)], generation), 'fixture GC removed protected generation')
            world['objects'][domain].pop(key, None)
        elif command['mode'] == 'missing':
            world['objects'][domain].pop(key, None)
        else:
            must(command['mode'] in ('hash', 'restore'), 'unknown explicit fixture fault')
            raw = frame['raw'] + (b'bad-tail'.hex() if command['mode'] == 'hash' else '')
            world['objects'][domain][key] = {'raw': raw, 'etag': f'"fixture:{generation}:{command["mode"]}"'}
    must(after['world'] == world, 'fixture changed more than declared injection')


def client_check(before, after, spec, profile, event):
    who, op = event['actor'], event['op']
    actor, updated = before['actors'][who], after['actors'][who]
    command = profile['actors'][who]['program'][actor['pc']]
    allowed_changes(before, after, profile, event)
    must(event['pc'] == actor['pc'] and event['op'] == command['op'], 'edge skipped original program step')
    if actor['outcome'] is not None:
        must(updated['outcome'] == actor['outcome'], 'historical public outcome rewritten')
    if actor['failure'] is not None:
        must(updated['failure'] is not None, 'failed attempt resurrected')
        if op != 'classify':
            must(updated['failure'] == actor['failure'], 'original failure capsule rewritten')
        else:
            same_except(actor['failure'], updated['failure'], {'classification'}, 'classify changed original failure')
    if actor['local_stop']:
        must(updated['local_stop'], 'local gate reopened')
    if actor['detached']:
        must(updated['detached'], 'detached caller revived')
    rejected = updated['stopped'] is not None
    if rejected:
        must(actor['stopped'] is None and updated['pc'] == len(profile['actors'][who]['program']), 'rejected program counter')
        justified_rejection(before, after, spec, profile, event)
        if actor['outcome'] is None:
            must(updated['outcome'] == {'kind': 'Rejected', 'reason': updated['stopped']}, 'rejection invented success')
    else:
        must(updated['pc'] == actor['pc'] + 1, 'client program progress')
        if op not in ('return_read', 'return_lookup', 'ack', 'classify'):
            must(updated['outcome'] == actor['outcome'], 'nonexit operation fabricated a public outcome')
        if op in ORDINARY_OPS:
            must(actor['handle_open'] and actor['failure'] is None and not actor['local_stop']
                 and not actor['detached'], 'ordinary step continued an ended attempt')
    for identifier in set(after['tokens']) - set(before['tokens']):
        request_creation(before, after, spec, profile, event, identifier)
    if op == 'observe':
        observation_check(before, after, spec, profile, event)
    knowledge_changes(before, after, spec, profile, event)
    if op in FIXTURE_OPS and not rejected:
        fixture_check(before, after, spec, profile, event)
    if rejected:
        return
    if op == 'begin':
        known = knowledge(before, profile, who)
        must(not actor['handle_open'] and updated['handle_open'], 'handle creation')
        if command['new']:
            must(not known['created'] and knowledge(after, profile, who)['created'], 'reused lineage identity')
        else:
            must(known['created'] and any(other['handle_open'] and profile['actors'][name]['lineage'] == profile['actors'][who]['lineage']
                                        for name, other in before['actors'].items()), 'clone lacks live lineage')
            must(knowledge(after, profile, who) == known, 'clone reset knowledge')
    elif op == 'mark':
        expected = {**actor['marks'], command['name']: True}
        must(updated['marks'] == expected, 'mark changed unrelated fixture barrier')
    elif op == 'release_handle':
        must(not updated['handle_open'] and updated['marks'] == {**actor['marks'], 'closed': True}, 'handle close changed knowledge')
    elif op in ('stop_local', 'detach'):
        must(updated['local_stop' if op == 'stop_local' else 'detached'] is True, 'local close not recorded')
    elif op == 'admit':
        head, context = actor['view']['head'], updated['context']
        must(actor['context'] is None and actor['failure'] is None and actor['handle_open']
             and not actor['local_stop'] and not actor['detached'], 'admission reused ended attempt')
        mode = command['mode']
        needed = ('read', 'write') if mode == 'write' else ('admin',) if mode in ('manage', 'copy') else ('read',)
        must(head['life'] == 'ready' and permitted(head, profile['actors'][who]['principal'], needed), 'admission lacks original fresh permission')
        generation, roots, plan = head['A'], {'data': head['data'], 'index': head['index']}, None
        if command.get('retained'):
            must(head['hold'] is not None, 'retained admission without persistent hold')
            generation, roots = head['hold']['generation'], head['hold']['roots']
        if mode == 'copy':
            must(head['plan'] is not None, 'copy admission without current plan')
            plan = head['plan']; generation, roots = plan[command['copy_role']], plan['roots']
        if mode == 'write':
            must(head['active'] and head['owner'] == knowledge(before, profile, who)['worker'] and head['plan'] is None,
                 'write admission lacks owner/freeze permission')
        must(context['generation'] == generation and context['roots'] == roots and context['plan'] == plan
             and context['mode'] == mode and context['view_token'] == actor['view_token'], 'admission changed captured roots/plan')
    elif op in ('prepare_write', 'prepare_manage', 'prepare_tech'):
        candidate_check(before, after, spec, profile, event)
    elif op == 'final_check':
        candidate = actor['candidate']
        must(actor['permit'] is None and candidate is not None and actor['failure'] is None
             and not actor['local_stop'] and not actor['detached'], 'permit minted for ended attempt')
        must(local_healthy(knowledge(before, profile, who), candidate['generation']), 'permit minted through own known latch')
        must(updated['permit'] == {'candidate_hash': fingerprint(candidate), 'lineage': candidate['lineage'],
                                   'generation': candidate['generation'], 'check_pc': actor['pc']}, 'permit not exact original candidate')
    elif op == 'native_execute':
        must(actor['native'] is None and updated['native'] == 'executed' and actor['content_validated']
             and actor['materialized'] is not None and actor['context']['mode'] == 'write', 'native replay or foreign image execution')
    elif op == 'begin_commit':
        must(actor['native'] == 'executed' and not actor['commit_started'] and updated['commit_started']
             and local_healthy(knowledge(before, profile, who), actor['context']['generation']), 'early commit health gate bypass')
    elif op == 'native_publish':
        must(actor['native'] == 'executed', 'native finish repeated or no original execution')
        if actor['known_commit']:
            wanted = 'committed' if event['choice'] == 'commit' else 'commit_failed'
        else:
            wanted = 'aborted'
        must(updated['native'] == wanted, 'native outcome without own known original CAS')
    elif op == 'validate_content':
        must(actor['materialized'] is not None and actor['failure'] is None, 'content validated without live complete image')
        bad = actor['context']['roots']['data'] in before['world']['semantic_bad_roots']
        if bad:
            must(updated['failure'] and updated['failure']['kind'] == 'semantic'
                 and knowledge(after, profile, who)['semantic'] and not updated['content_validated'], 'semantic content failure became healthy/expired')
        else:
            must(updated['content_validated'] and updated['failure'] is None, 'good independent content falsely blocked')
    elif op == 'classify':
        failure = actor['failure']
        token = before['tokens'][actor['last']]
        must(failure and failure['kind'] == 'physical' and actor['probe_used']
             and token['request']['purpose'] == 'probe' and token['request']['failure_token'] == failure['token'],
             'failure classification borrowed authority')
        head = decoded_head(token['observation'])
        valid = valid_authority(head, failure['scope'], spec['bounds']['generations'])
        status = ('expired' if permanent(head, failure['generation']) else 'corrupt') if valid else 'unresolved'
        must(updated['failure']['classification'] == status, 'failure incorrectly scoped')
        expected = {'expired': 'SnapshotExpired', 'corrupt': 'Corrupt', 'unresolved': 'AuthorityUnavailable'}[status]
        must(updated['outcome'] == {'kind': expected, 'failure': failure['token']}, 'failure public result differs from evidence')
    elif op in ('return_read', 'return_lookup', 'ack'):
        public_exit(before, after, spec, profile, event)
    elif op in ('get', 'get_root', 'put', 'head_get', 'send_head', 'probe'):
        must(len(set(after['tokens']) - set(before['tokens'])) == 1, 'successful dispatch omitted original request')
    elif op == 'load_next' and set(after['tokens']) == set(before['tokens']):
        must(set(closure(actor)) == set(actor['frames']) and updated['no_work'] and updated['last'] is None,
             'frontier ended before complete original graph')


def public_exit(before, after, spec, profile, event):
    who, op = event['actor'], event['op']
    actor, updated = before['actors'][who], after['actors'][who]
    must(actor['outcome'] is None, 'second public result')
    if op == 'ack':
        token = before['tokens'][actor['cas']]
        must(token['actor'] == who and token['observation'] is not None, 'ACK without own original response')
        if actor['local_stop'] or actor['detached'] or actor['failure'] is not None:
            expected = 'Withheld'
        elif actor['known_commit']:
            if actor['candidate']['kind'] == 'writer':
                must(actor['native'] in ('committed', 'commit_failed'), 'ACK before native settlement')
                expected = 'Ack' if actor['native'] == 'committed' else 'CommittedUnavailable'
            else:
                expected = 'Ack'
        else:
            expected = 'Conflict' if token['observation']['kind'] == 'Conflict' else 'Unknown'
        must(updated['outcome'] == {'kind': expected, 'token': actor['cas']}, 'public ACK/UNKNOWN/withheld classification')
        return
    must(actor['handle_open'] and actor['failure'] is None and not actor['local_stop'] and not actor['detached'],
         'public read succeeded after original local gate closed')
    must(actor['materialized'] is not None and set(closure(actor)) == set(actor['frames']), 'public read not complete own original bytes')
    if op == 'return_read':
        must(actor['content_validated'] and updated['outcome'] == {'kind': 'Read', 'context_token': actor['context']['view_token']},
             'read not original validated materialization')
    else:
        must(actor['context']['mode'] == 'lookup' and actor['native'] is None, 'lookup replayed SQL/native')
        index = read_frame(actor['frames'][actor['context']['roots']['index']]['raw'])
        entry = next((entry for entry in index['entries'] if entry['request'] == 'Q1'), None)
        receipt = entry['result'] if entry else None
        if receipt:
            value = read_frame(actor['frames'][receipt]['raw'])
            must(value['request'] == 'Q1' and value['principal'] == profile['actors'][who]['principal']
                 and value['sequence'] <= actor['context']['head']['sequence']
                 and value['revision'] <= actor['context']['head']['revision'], 'lookup did not prove exact retained identity')
        must(updated['outcome'] == {'kind': 'Lookup' if receipt else 'LookupUnknown', 'receipt': receipt,
                                    'context_token': actor['context']['view_token']}, 'lookup forged receipt or original ACK')


def edge_checks(before, after, spec, profile, event):
    must(event in expected_labels(before, profile), 'recorded edge was not enabled')
    if event['kind'] == 'network':
        backend_check(before, after, spec, event)
    else:
        client_check(before, after, spec, profile, event)
    for domain, heads in before['world']['heads'].items():
        for key, head in heads.items():
            newer = after['world']['heads'][domain][key]
            must(newer['serial'] >= head['serial'] and newer['M'] >= head['M'], 'authority serial/allocation regressed')
            for generation in range(1, spec['bounds']['generations'] + 1):
                if permanent(head, generation):
                    must(permanent(newer, generation), 'retired generation revived or held anew')
