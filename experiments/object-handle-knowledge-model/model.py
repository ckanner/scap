"""Finite producer for handle-local knowledge. The oracle must not import this file.

The input fixes programs, raw frames and bounds. Backend delivery is independent of
client progress; no transition cancels an already created network token.
"""

import copy
import hashlib
import json


class Rejected(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def head_key(scope):
    return f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"


def object_key(scope, generation, object_hash):
    return (f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}"
            f"/inc/{scope['incarnation']}/gen/{scope['generation']}/storage/{generation}/objects/{object_hash}")


def head_etag(value):
    return '"head:' + digest(value) + '"'


def retired(head, generation):
    target = head['plan']['target'] if head['plan'] else None
    held = head['hold']['generation'] if head['hold'] else None
    return 1 <= generation <= head['M'] and generation not in (head['A'], target, held)


def lineage(state, profile, name):
    return state['lineages'][profile['actors'][name]['lineage']]


def live(actor):
    require(actor['handle_open'], 'handle_closed')
    require(not actor['local_stop'] and not actor['detached'], 'local_gate_closed')
    require(actor['failure'] is None, 'failed_attempt_closed')


def healthy(knowledge, generation):
    return (not knowledge['authority'] and not knowledge['semantic']
            and str(generation) not in knowledge['physical'])


def head_valid(value, scope, bounds):
    try:
        if (value['format'] != 'MODELHEAD-KNOWLEDGE1' or value['scope'] != scope
                or not 1 <= value['revision'] <= value['serial']
                or not 1 <= value['A'] <= value['M'] <= bounds['generations']):
            return False
        if value['plan']:
            plan = value['plan']
            if (plan['scope'] != scope or plan['source'] != value['A']
                    or not value['A'] < plan['target'] <= value['M']
                    or plan['roots'] != {'data': value['data'], 'index': value['index']}
                    or plan['phase'] not in ('copying', 'sealed')):
                return False
        if value['hold']:
            held = value['hold']
            if held['scope'] != scope or not 1 <= held['generation'] <= value['M']:
                return False
        return value['life'] in ('ready', 'maintenance', 'deleted')
    except (KeyError, TypeError):
        return False


def rights(head, principal, *needed):
    permission = head['acl'].get(str(principal), {})
    return all(permission.get(right, False) is True for right in needed)


def parse_frame(raw_hex):
    raw = bytes.fromhex(raw_hex)
    require(raw.startswith(b'MODELKNOWLEDGE1\n'), 'frame_header_semantic')
    try:
        value = json.loads(raw.split(b'\n', 1)[1])
    except (ValueError, IndexError) as error:
        raise Rejected('frame_metadata_semantic') from error
    require(value.get('format') == 'MODELKNOWLEDGE1', 'frame_format_semantic')
    return value


def required_frames(actor):
    """Only original roots and references from already observed raw frames."""
    context = actor['context']
    require(context is not None, 'no_original_context')
    pending = [(context['roots']['index'], 'index')]
    if context['mode'] != 'lookup':
        pending.insert(0, (context['roots']['data'], 'manifest'))
    wanted = {}
    while pending:
        object_hash, kind = pending.pop(0)
        require(object_hash not in wanted or wanted[object_hash] == kind, 'edge_kind_alias')
        if object_hash in wanted:
            continue
        wanted[object_hash] = kind
        frame = actor['frames'].get(object_hash)
        if frame is None:
            continue
        value = parse_frame(frame['raw'])
        require(value['kind'] == kind, 'typed_edge_semantic')
        if kind == 'manifest':
            pending.extend((child, 'chunk') for child in value['children'])
        elif kind == 'index':
            pending.extend((entry['result'], 'result') for entry in value['entries'])
        # Result.data_root is identity metadata, deliberately not an edge.
    return wanted


def known_frame(spec, object_hash):
    return next(value for value in spec['frames'].values() if value['hash'] == object_hash)


def issue(state, spec, profile, name, request):
    actor = state['actors'][name]
    token_id = f"{name}:{actor['pc']}"
    require(token_id not in state['tokens'], 'token_replay')
    require(len(state['tokens']) < spec['bounds']['tokens'], 'token_bound')
    state['tokens'][token_id] = {
        'actor': name, 'lineage': profile['actors'][name]['lineage'],
        'request': copy.deepcopy(request), 'effect': None, 'observation': None,
    }
    actor['last'] = token_id
    actor['last_result'] = None
    actor['no_work'] = False
    return token_id


def physical_failure(state, profile, name, token_id, kind):
    actor = state['actors'][name]
    token = state['tokens'][token_id]
    request = token['request']
    actor['failure'] = {
        'kind': 'physical', 'fault': kind, 'token': token_id,
        'domain': request['domain'], 'scope': copy.deepcopy(request['scope']),
        'generation': request['generation'], 'key': request['key'],
        'hash': request['hash'], 'classification': 'unresolved',
    }
    knowledge = lineage(state, profile, name)
    key = str(request['generation'])
    previous = knowledge['physical'].get(key)
    if previous is None:
        knowledge['physical'][key] = {'status': 'unresolved', 'origin': token_id, 'proof': None}


def semantic_failure(state, profile, name, token_id, reason):
    actor = state['actors'][name]
    actor['failure'] = {'kind': 'semantic', 'reason': reason, 'token': token_id,
                        'classification': 'corrupt'}
    lineage(state, profile, name)['semantic'] = True


def authority_failure(state, profile, name, token_id):
    actor = state['actors'][name]
    actor['failure'] = {'kind': 'authority', 'token': token_id, 'classification': 'corrupt'}
    lineage(state, profile, name)['authority'] = True


def backend_effect(state, spec, token, delivery):
    request = token['request']
    if delivery == 'discard':
        return {'kind': 'Unavailable', 'delivered': False}
    domain, key = request['domain'], request['key']
    if request['method'] == 'HEAD_GET':
        fault = state['world']['head_fault'][domain]
        if fault == 'unavailable':
            return {'kind': 'Unavailable', 'delivered': True}
        head = state['world']['heads'][domain].get(key)
        if head is None:
            return {'kind': 'NoSuchKey', 'delivered': True}
        value = copy.deepcopy(head)
        if fault == 'wrong_scope':
            value['scope'] = copy.deepcopy(spec['foreign_scope'])
        raw = canonical(value).hex() if fault != 'malformed' else b'broken HEAD'.hex()
        return {'kind': 'Found', 'raw': raw, 'etag': head_etag(value), 'delivered': True}
    if request['method'] == 'GET':
        obj = state['world']['objects'][domain].get(key)
        return ({'kind': 'Found', **copy.deepcopy(obj), 'delivered': True} if obj else
                {'kind': 'NoSuchKey', 'delivered': True})
    if request['method'] == 'PUT_ABSENT':
        objects = state['world']['objects'][domain]
        if key in objects:
            return {'kind': 'Conflict', 'delivered': True}
        version = state['world']['object_version']
        state['world']['object_version'] += 1
        value = {'raw': request['raw'], 'etag': f'"object:{version}"'}
        objects[key] = value
        return {'kind': 'Applied', 'etag': value['etag'], 'delivered': True}
    require(request['method'] == 'HEAD_CAS', 'unknown_backend_method')
    current = state['world']['heads'][domain].get(key)
    # The backend knows only the originally sent condition. It does not inspect
    # client health, current permissions, native status or the caller's outcome.
    if current is None or head_etag(current) != request['etag']:
        return {'kind': 'Conflict', 'delivered': True}
    replacement = json.loads(bytes.fromhex(request['raw']))
    state['world']['heads'][domain][key] = replacement
    return {'kind': 'Applied', 'etag': head_etag(replacement), 'delivered': True}


def observe(state, spec, profile, name, command, choice):
    actor = state['actors'][name]
    if actor['no_work']:
        actor['no_work'] = False
        actor['last_result'] = {'kind': 'NoWork'}
        return
    token_id = actor['last']
    require(token_id is not None, 'observe_without_token')
    token = state['tokens'][token_id]
    require(token['actor'] == name and token['observation'] is None, 'observe_not_owned_once')
    request = token['request']
    if choice == 'unknown':
        require(request['uncertain'], 'unknown_not_enabled')
        result = {'kind': 'Unknown'}
    else:
        require(token['effect'] is not None, 'response_not_delivered')
        result = copy.deepcopy(token['effect'])
    token['observation'] = copy.deepcopy(result)
    actor['last_result'] = copy.deepcopy(result)
    method = request['method']
    if method == 'HEAD_CAS':
        if result['kind'] == 'Applied':
            actor['known_commit'] = token_id
        elif result['kind'] in ('Unavailable', 'Unknown'):
            # Original UNKNOWN remains a historical observation even if the
            # original token later applies at the backend.
            actor['known_commit'] = None
        elif result['kind'] == 'Conflict':
            actor['known_commit'] = None
        return
    if method == 'PUT_ABSENT':
        require(result['kind'] in ('Applied', 'Conflict'), 'object_put_unavailable')
        return
    if method == 'HEAD_GET' and request['purpose'] == 'probe':
        return  # Only classify can use this dedicated failure-authority response.
    if method == 'HEAD_GET':
        if result['kind'] != 'Found':
            raise Rejected('head_unavailable')
        try:
            value = json.loads(bytes.fromhex(result['raw']))
        except (ValueError, UnicodeDecodeError):
            value = None
        if not head_valid(value, request['scope'], spec['bounds']):
            authority_failure(state, profile, name, token_id)
            if not command.get('allow_failure'):
                raise Rejected('authority_corrupt')
            return
        actor['view'] = {'head': value, 'etag': result['etag'], 'domain': request['domain'],
                         'key': request['key']}
        actor['view_token'] = token_id
        return
    require(method == 'GET', 'unknown_observation_method')
    live(actor)
    if result['kind'] == 'NoSuchKey':
        physical_failure(state, profile, name, token_id, 'missing')
        if not command.get('allow_failure'):
            raise Rejected('source_missing')
        return
    require(result['kind'] == 'Found', 'object_get_unavailable')
    if hashlib.sha256(bytes.fromhex(result['raw'])).hexdigest() != request['hash']:
        physical_failure(state, profile, name, token_id, 'hash')
        if not command.get('allow_failure'):
            raise Rejected('source_hash')
        return
    try:
        value = parse_frame(result['raw'])
        require(value['scope'] == request['scope'], 'frame_scope_semantic')
        require(value['kind'] == request['expected_kind'], 'typed_edge_semantic')
        if value['kind'] == 'result':
            require(value['request'] == 'Q1' and value['principal'] == 7
                    and value['sequence'] == 1 and value['revision'] == 2,
                    'result_identity_semantic')
    except (Rejected, KeyError) as error:
        semantic_failure(state, profile, name, token_id, str(error))
        if not command.get('allow_failure'):
            raise Rejected('source_semantic') from error
        return
    frame = {'token': token_id, 'raw': result['raw'], 'kind': value['kind']}
    actor['readbacks' if request['purpose'] == 'readback' else 'frames'][request['hash']] = frame


def capture(actor, profile, name, generation, roots, mode, plan=None):
    return {'domain': actor['view']['domain'], 'scope': copy.deepcopy(actor['view']['head']['scope']),
            'lineage': profile['actors'][name]['lineage'], 'generation': generation,
            'roots': copy.deepcopy(roots), 'mode': mode, 'plan': copy.deepcopy(plan),
            'head': copy.deepcopy(actor['view']['head']), 'etag': actor['view']['etag'],
            'key': actor['view']['key'], 'view_token': actor['view_token']}


def prepare(actor, context, next_head, kind):
    actor['candidate'] = {
        'kind': kind, 'domain': context['domain'], 'scope': copy.deepcopy(context['scope']),
        'lineage': context['lineage'], 'generation': context['generation'],
        'key': context['key'], 'etag': context['etag'], 'base': copy.deepcopy(context['head']),
        'raw': canonical(next_head).hex(), 'view_token': context['view_token'],
    }
    actor['permit'] = None
    actor['cas'] = None
    actor['known_commit'] = None


def fixture_step(state, spec, profile, name, command):
    require(profile['actors'][name]['role'] == 'fixture', 'fixture_right_required')
    world = state['world']
    if command['op'] == 'fault_head':
        world['head_fault']['D0'] = command['mode']
        return
    if command['op'] == 'fault_captured':
        context = state['actors'][command['actor']]['context']
        require(context is not None, 'fault_without_capture')
        generation = context['generation']
        item = known_frame(spec, context['roots']['data'])
        domain, scope = context['domain'], context['scope']
    else:
        generation = command['generation']
        item = spec['frames'][command['name']]
        domain, scope = 'D0', spec['scope']
    key = object_key(scope, generation, item['hash'])
    if command['op'] == 'remove_retired':
        require(retired(world['heads'][domain][head_key(scope)], generation), 'fixture_remove_live_generation')
        world['objects'][domain].pop(key, None)
    elif command['mode'] == 'missing':
        world['objects'][domain].pop(key, None)
    else:
        raw = item['raw'] if command['mode'] == 'restore' else item['raw'] + b'bad-tail'.hex()
        require(command['mode'] in ('hash', 'restore'), 'unknown_fixture_fault')
        world['objects'][domain][key] = {'raw': raw, 'etag': f'"fixture:{generation}:{command["mode"]}"'}


def client_step(state, spec, profile, name, command, choice):
    actor = state['actors'][name]
    op = command['op']
    if op == 'await':
        return
    if op == 'mark':
        actor['marks'][command['name']] = True
        return
    if op == 'begin':
        knowledge = lineage(state, profile, name)
        require(not actor['handle_open'], 'handle_already_open')
        if command['new']:
            require(not knowledge['created'], 'lineage_identity_reuse')
            knowledge['created'] = True
        else:
            require(knowledge['created'] and any(other['handle_open']
                    and profile['actors'][other_name]['lineage'] == profile['actors'][name]['lineage']
                    for other_name, other in state['actors'].items()), 'clone_without_live_handle')
        actor['handle_open'] = True
        return
    if op in ('fault_head', 'fault_object', 'fault_captured', 'remove_retired'):
        fixture_step(state, spec, profile, name, command)
        return
    if op == 'release_handle':
        actor['handle_open'] = False
        actor['marks']['closed'] = True
        return
    if op == 'stop_local':
        actor['local_stop'] = True
        return
    if op == 'detach':
        actor['detached'] = True
        return
    if op == 'attempt_adopt':
        require(profile['actors'][command['source']]['lineage'] != profile['actors'][name]['lineage'],
                'invalid_adoption_fixture')
        raise Rejected('foreign_' + command['kind'] + '_rejected')
    if op == 'attempt_expire_semantic':
        require(actor['failure'] and actor['failure']['kind'] == 'semantic', 'no_semantic_failure')
        raise Rejected('semantic_failure_cannot_expire')
    if op == 'observe':
        observe(state, spec, profile, name, command, choice)
        return
    if op == 'probe':
        require(actor['handle_open'] and not actor['local_stop'] and not actor['detached'], 'probe_gate_closed')
        failure = actor['failure']
        require(failure and failure['kind'] == 'physical' and not actor['probe_used'], 'probe_not_once_physical')
        actor['probe_used'] = True
        issue(state, spec, profile, name, {
            'method': 'HEAD_GET', 'domain': failure['domain'], 'scope': copy.deepcopy(failure['scope']),
            'key': head_key(failure['scope']), 'purpose': 'probe', 'failure_token': failure['token'],
            'uncertain': command['uncertain'],
        })
        return
    if op == 'classify':
        failure = actor['failure']
        require(failure and failure['kind'] == 'physical' and actor['probe_used'], 'classify_without_probe')
        token = state['tokens'][actor['last']]
        require(token['actor'] == name and token['request']['purpose'] == 'probe'
                and token['request']['failure_token'] == failure['token']
                and token['observation'] is not None, 'classify_not_original_probe')
        result = token['observation']
        status = 'unresolved'
        if result['kind'] == 'Found':
            try:
                head = json.loads(bytes.fromhex(result['raw']))
            except (ValueError, UnicodeDecodeError):
                head = None
            if head_valid(head, failure['scope'], spec['bounds']):
                status = 'expired' if retired(head, failure['generation']) else 'corrupt'
            else:
                lineage(state, profile, name)['authority'] = True
        failure['classification'] = status
        key = str(failure['generation'])
        incident = lineage(state, profile, name)['physical'][key]
        # An independent successful read never clears this incident. Only the
        # original incident's one probe can refine its own unresolved knowledge.
        if incident['origin'] == failure['token']:
            incident['status'] = status
            incident['proof'] = actor['last']
        actor['outcome'] = {'kind': {'expired': 'SnapshotExpired', 'corrupt': 'Corrupt',
                                    'unresolved': 'AuthorityUnavailable'}[status],
                            'failure': failure['token']}
        return
    if op == 'native_publish':
        require(actor['native'] == 'executed', 'native_publish_without_execution')
        actor['native'] = ('committed' if choice == 'commit' else 'commit_failed') if actor['known_commit'] else 'aborted'
        return
    if op == 'ack':
        require(actor['candidate'] is not None and actor['cas'] is not None, 'ack_without_original_candidate')
        require(actor['outcome'] is None, 'public_outcome_rewrite')
        token = state['tokens'][actor['cas']]
        observed = token['observation']
        require(observed is not None, 'ack_without_observation')
        if actor['local_stop'] or actor['detached'] or actor['failure'] is not None:
            actor['outcome'] = {'kind': 'Withheld', 'token': actor['cas']}
        elif actor['known_commit']:
            if actor['candidate']['kind'] == 'writer':
                require(actor['native'] in ('committed', 'commit_failed'), 'ack_before_native_finish')
                kind = 'Ack' if actor['native'] == 'committed' else 'CommittedUnavailable'
            else:
                kind = 'Ack'
            actor['outcome'] = {'kind': kind, 'token': actor['cas']}
        else:
            actor['outcome'] = {'kind': 'Conflict' if observed['kind'] == 'Conflict' else 'Unknown',
                                'token': actor['cas']}
        return
    live(actor)
    knowledge = lineage(state, profile, name)
    if op == 'head_get':
        issue(state, spec, profile, name, {
            'method': 'HEAD_GET', 'domain': knowledge['domain'], 'scope': copy.deepcopy(knowledge['scope']),
            'key': head_key(knowledge['scope']), 'purpose': command['purpose'],
            'uncertain': command['uncertain'],
        })
        return
    if op == 'admit':
        require(actor['context'] is None and actor['view'] is not None, 'admit_requires_fresh_own_view')
        head = actor['view']['head']
        mode, principal = command['mode'], profile['actors'][name]['principal']
        require(head['life'] == 'ready', 'lifecycle_not_ready')
        needed = ('read', 'write') if mode == 'write' else (('admin',) if mode in ('manage', 'copy') else ('read',))
        require(rights(head, principal, *needed), 'permission_denied')
        if mode == 'write':
            require(head['active'] and head['owner'] == knowledge['worker'] and head['plan'] is None,
                    'writer_owner_or_freeze')
        generation, roots, plan = head['A'], {'data': head['data'], 'index': head['index']}, None
        if command.get('retained'):
            require(head['hold'] is not None, 'no_retained_hold')
            generation, roots = head['hold']['generation'], head['hold']['roots']
        if mode == 'copy':
            require(head['plan'] is not None, 'no_current_copy_plan')
            plan = head['plan']
            generation, roots = plan[command['copy_role']], plan['roots']
        actor['context'] = capture(actor, profile, name, generation, roots, mode, plan)
        return
    if op in ('get', 'get_root', 'load_next'):
        context = actor['context']
        require(context is not None, 'get_without_context')
        purpose = command.get('purpose', 'read')
        wanted = required_frames(actor)
        if op == 'load_next':
            missing = [item for item in wanted if item not in actor['frames']]
            if not missing:
                actor['last'] = None
                actor['last_result'] = None
                actor['no_work'] = True
                return
            object_hash = missing[0]
        elif op == 'get_root':
            object_hash = context['roots']['data']
        else:
            object_hash = spec['frames'][command['name']]['hash']
        if purpose == 'readback':
            require(context['mode'] == 'write' and actor['native'] == 'executed', 'readback_without_writer')
            require(object_hash in [spec['frames'][key]['hash'] for key in ('C1', 'M1', 'R1', 'I1')],
                    'readback_not_original_dependency')
            expected_kind = known_frame(spec, object_hash)['kind']
        else:
            require(object_hash in wanted, 'get_not_in_original_closure')
            expected_kind = wanted[object_hash]
        issue(state, spec, profile, name, {
            'method': 'GET', 'domain': context['domain'], 'scope': copy.deepcopy(context['scope']),
            'generation': context['generation'], 'key': object_key(context['scope'], context['generation'], object_hash),
            'hash': object_hash, 'purpose': purpose, 'expected_kind': expected_kind,
            'context_token': context['view_token'], 'uncertain': False,
        })
        return
    if op in ('materialize', 'materialize_lookup'):
        wanted = required_frames(actor)
        require(set(wanted) == set(actor['frames']), 'incomplete_original_materialization')
        actor['materialized'] = {
            'lineage': profile['actors'][name]['lineage'], 'context_token': actor['context']['view_token'],
            'generation': actor['context']['generation'], 'frames': copy.deepcopy(actor['frames']),
            'mode': actor['context']['mode'],
        }
        if op == 'materialize_lookup':
            require(actor['context']['mode'] == 'lookup', 'lookup_materialization_wrong_mode')
        return
    if op == 'validate_content':
        require(actor['materialized'] is not None and actor['context']['mode'] != 'lookup', 'no_data_materialization')
        if actor['context']['roots']['data'] in state['world']['semantic_bad_roots']:
            semantic_failure(state, profile, name, actor['context']['view_token'], 'abstract_content_invalid')
            if not command.get('allow_failure'):
                raise Rejected('content_invalid')
        else:
            actor['content_validated'] = True
        return
    if op in ('return_read', 'return_lookup'):
        require(actor['outcome'] is None and actor['materialized'] is not None, 'return_without_own_materialization')
        if op == 'return_read':
            require(actor['content_validated'], 'read_before_content_validation')
            actor['outcome'] = {'kind': 'Read', 'context_token': actor['context']['view_token']}
        else:
            require(actor['context']['mode'] == 'lookup' and actor['native'] is None, 'lookup_is_not_execution')
            index = parse_frame(actor['frames'][actor['context']['roots']['index']]['raw'])
            entry = next((entry for entry in index['entries'] if entry['request'] == 'Q1'), None)
            receipt = None
            if entry:
                value = parse_frame(actor['frames'][entry['result']]['raw'])
                require(value['principal'] == profile['actors'][name]['principal']
                        and value['sequence'] <= actor['context']['head']['sequence']
                        and value['revision'] <= actor['context']['head']['revision'], 'lookup_receipt_identity')
                receipt = entry['result']
            actor['outcome'] = {'kind': 'Lookup' if receipt else 'LookupUnknown', 'receipt': receipt,
                                'context_token': actor['context']['view_token']}
        return
    if op == 'native_execute':
        require(actor['context']['mode'] == 'write' and actor['content_validated']
                and actor['materialized'] is not None and actor['native'] is None, 'native_execute_once_own_image')
        actor['native'] = 'executed'
        return
    if op == 'begin_commit':
        require(actor['native'] == 'executed' and not actor['commit_started'], 'commit_start_once')
        require(healthy(knowledge, actor['context']['generation']), 'publication_latched')
        actor['commit_started'] = True
        return
    if op == 'put':
        context = actor['context']
        require(context['mode'] == 'write' and actor['commit_started'] and actor['native'] == 'executed',
                'put_without_original_write')
        item = spec['frames'][command['name']]
        require(command['name'] in ('C1', 'M1', 'R1', 'I1'), 'not_original_write_dependency')
        issue(state, spec, profile, name, {
            'method': 'PUT_ABSENT', 'domain': context['domain'], 'scope': copy.deepcopy(context['scope']),
            'generation': context['generation'], 'key': object_key(context['scope'], context['generation'], item['hash']),
            'hash': item['hash'], 'raw': item['raw'], 'purpose': 'write_dependency',
            'context_token': context['view_token'], 'uncertain': False,
        })
        return
    if op in ('prepare_write', 'prepare_manage'):
        context = actor['context']
        require(context is not None and actor['candidate'] is None, 'candidate_once_from_original_context')
        require(healthy(knowledge, context['generation']), 'publication_latched')
        value = copy.deepcopy(context['head'])
        value['serial'] += 1
        value['revision'] += 1
        if op == 'prepare_write':
            require(context['mode'] == 'write' and actor['native'] == 'executed'
                    and actor['commit_started'], 'prepare_without_original_execution')
            require(set(actor['readbacks']) == {spec['frames'][key]['hash'] for key in ('C1', 'M1', 'R1', 'I1')},
                    'write_dependency_readback_incomplete')
            value.update(sequence=value['sequence'] + 1, data=spec['frames']['M1']['hash'], index=spec['frames']['I1']['hash'])
            kind = 'writer'
        else:
            require(context['mode'] == 'manage', 'manage_without_original_authority')
            kind = command['kind']
            if kind == 'takeover':
                value.update(owner=knowledge['worker'], owner_epoch=value['owner_epoch'] + 1, active=False)
            else:
                require(kind == 'policy', 'closed_management_algebra')
                value['auth_epoch'] += 1
                value['acl']['8']['read'] = not value['acl']['8']['read']
        prepare(actor, context, value, kind)
        return
    if op == 'prepare_tech':
        require(actor['view'] is not None, 'technical_without_fresh_authority')
        head = actor['view']['head']
        require(rights(head, profile['actors'][name]['principal'], 'admin'), 'technical_admin_denied')
        require(head['life'] != 'deleted', 'technical_deleted')
        context = capture(actor, profile, name, head['A'], {'data': head['data'], 'index': head['index']}, 'technical', head['plan'])
        require(healthy(knowledge, head['A']), 'publication_latched')
        value = copy.deepcopy(head)
        value['serial'] += 1
        kind = command['kind']
        if kind == 'hold_add':
            require(head['hold'] is None, 'hold_already_present')
            value['hold'] = {'id': 'HOLD1', 'scope': copy.deepcopy(head['scope']), 'generation': head['A'],
                             'roots': {'data': head['data'], 'index': head['index']}}
        elif kind == 'promote':
            require(head['plan'] and head['plan']['phase'] == 'sealed', 'promote_without_sealed_plan')
            value.update(A=head['plan']['target'], plan=None, active=False)
        elif kind == 'abort_plan':
            require(head['plan'] is not None, 'abort_without_plan')
            value['plan'] = None
        elif kind == 'freeze':
            require(head['plan'] is None and head['M'] < spec['bounds']['generations'], 'freeze_not_available')
            value['M'] += 1
            value['active'] = False
            value['plan'] = {'id': f"P{value['M']}", 'scope': copy.deepcopy(head['scope']), 'source': head['A'],
                             'target': value['M'], 'started_serial': value['serial'], 'phase': 'copying',
                             'roots': {'data': head['data'], 'index': head['index']}}
        else:
            require(kind == 'fence', 'unknown_technical_transition')
            value['revision'] += 1
            value['auth_epoch'] += 1
        actor['context'] = context
        prepare(actor, context, value, kind)
        return
    if op == 'final_check':
        candidate = actor['candidate']
        require(candidate is not None and actor['permit'] is None, 'final_check_without_new_candidate')
        require(healthy(knowledge, candidate['generation']), 'publication_latched')
        actor['permit'] = {'candidate_hash': digest(candidate), 'lineage': candidate['lineage'],
                            'generation': candidate['generation'], 'check_pc': actor['pc']}
        return
    if op == 'send_head':
        candidate, permit = actor['candidate'], actor['permit']
        require(candidate is not None and permit is not None and permit['candidate_hash'] == digest(candidate),
                'no_original_publication_permit')
        actor['permit'] = None
        actor['cas'] = issue(state, spec, profile, name, {
            'method': 'HEAD_CAS', 'domain': candidate['domain'], 'scope': copy.deepcopy(candidate['scope']),
            'key': candidate['key'], 'etag': candidate['etag'], 'raw': candidate['raw'],
            'generation': candidate['generation'], 'purpose': candidate['kind'],
            'candidate_hash': digest(candidate), 'permit': copy.deepcopy(permit),
            'context_token': candidate['view_token'],
            'uncertain': command.get('uncertain', False),
        })
        return
    raise Rejected('unknown_client_step')


def choices(state, profile):
    """All enabled labels, including every pending delivery after client exit."""
    result = []
    for token_id, token in sorted(state['tokens'].items()):
        if token['effect'] is None:
            result.extend({'kind': 'network', 'token': token_id, 'delivery': delivery}
                          for delivery in ('apply', 'discard'))
    for name, actor in sorted(state['actors'].items()):
        program = profile['actors'][name]['program']
        if actor['stopped'] is not None or actor['pc'] == len(program):
            continue
        command = program[actor['pc']]
        values = ['run']
        if command['op'] == 'await':
            target, marker = command['condition']['mark']
            if not state['actors'][target]['marks'].get(marker):
                continue
        elif command['op'] == 'observe' and not actor['no_work']:
            token = state['tokens'].get(actor['last'])
            if token and token['observation'] is None:
                values = (['known'] if token['effect'] is not None else [])
                if token['request']['uncertain']:
                    values.append('unknown')
                if not values:
                    continue
        elif command['op'] == 'native_publish':
            values = ['commit', 'fail'] if actor['known_commit'] else ['abort']
        result.extend({'kind': 'client', 'actor': name, 'pc': actor['pc'], 'op': command['op'], 'choice': choice}
                      for choice in values)
    return result


def transition(state, spec, profile, event):
    result = copy.deepcopy(state)
    if event['kind'] == 'network':
        token = result['tokens'][event['token']]
        require(token['effect'] is None, 'delivery_replay')
        token['effect'] = backend_effect(result, spec, token, event['delivery'])
        return result
    name = event['actor']
    actor = result['actors'][name]
    command = profile['actors'][name]['program'][actor['pc']]
    try:
        client_step(result, spec, profile, name, command, event['choice'])
        actor['pc'] += 1
    except Rejected as error:
        actor['stopped'] = str(error)
        actor['pc'] = len(profile['actors'][name]['program'])
        if actor['outcome'] is None:
            actor['outcome'] = {'kind': 'Rejected', 'reason': str(error)}
    return result
