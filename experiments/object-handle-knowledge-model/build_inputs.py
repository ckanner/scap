"""Expand finite programs only. This module never explores or evaluates transitions."""

from pathlib import Path
import copy
import hashlib
import json


HERE = Path(__file__).resolve().parent
SCOPE = {'deployment': 1, 'tenant': 2, 'database': 3, 'incarnation': 4, 'generation': 5}
FOREIGN_SCOPE = {**SCOPE, 'incarnation': 6}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def step(op, **arguments):
    return {'op': op, **arguments}


def mark(name):
    return step('mark', name=name)


def wait(actor, name):
    return step('await', condition={'mark': [actor, name]})


def head(purpose='admit', **options):
    return [step('head_get', purpose=purpose, uncertain=options.get('uncertain', False)),
            step('observe', allow_failure=options.get('allow_failure', False),
                 allow_unknown=options.get('allow_unknown', False))]


def get(name, purpose='read', allow_failure=False):
    return [step('get', name=name, purpose=purpose), step('observe', allow_failure=allow_failure)]


def load_all():
    return [command for _ in range(8) for command in [step('load_next'), step('observe')]]


def read_body(*, return_value=True):
    return [*load_all(), step('materialize'), step('validate_content'),
            *([step('return_read')] if return_value else [])]


def enter(mode='read', *, new=True, retained=False, copy_role=None):
    return [step('begin', new=new), *head(),
            step('admit', mode=mode, retained=retained, copy_role=copy_role)]


def publication_body(verb, *, uncertain=False, acknowledge=True):
    if verb == 'writer':
        commands = [*load_all(), step('materialize'), step('validate_content'),
                    step('native_execute'), step('begin_commit')]
        for name in ('C1', 'M1', 'R1', 'I1'):
            commands += [step('put', name=name), step('observe'), *get(name, 'readback')]
        commands += [step('prepare_write'), *get('M1', 'readback')]
    else:
        commands = [step('prepare_manage', kind=verb)]
    commands += [step('final_check'), step('send_head', uncertain=uncertain),
                 step('observe', allow_failure=True, allow_unknown=uncertain)]
    if verb == 'writer':
        commands += [step('native_publish')]
    if acknowledge:
        commands += [step('ack')]
    return commands


def publish(verb, *, new=True, uncertain=False):
    return [*enter('write' if verb == 'writer' else 'manage', new=new),
            *publication_body(verb, uncertain=uncertain)]


def technical(kind, **arguments):
    return [*head(), step('prepare_tech', kind=kind, **arguments), step('final_check'),
            step('send_head'), step('observe')]


def probe():
    return [step('probe', uncertain=True), step('observe', allow_failure=True, allow_unknown=True),
            step('classify')]


def actor(program, lineage='H1', *, role='client', principal=7):
    return {'lineage': lineage, 'principal': principal, 'role': role, 'program': program}


def initial_actor():
    return {'pc': 0, 'stopped': None, 'handle_open': False, 'view': None, 'view_token': None,
            'context': None, 'frames': {}, 'readbacks': {}, 'failure': None, 'probe_used': False,
            'materialized': None, 'content_validated': False, 'native': None, 'commit_started': False,
            'candidate': None, 'permit': None, 'last': None, 'last_result': None, 'no_work': False,
            'cas': None, 'known_commit': None, 'outcome': None, 'local_stop': False,
            'detached': False, 'marks': {}}


def make_frames():
    frames = {}

    def add(name, kind, **body):
        value = {'format': 'MODELKNOWLEDGE1', 'scope': SCOPE, 'kind': kind, **body}
        # Deliberately noncanonical whitespace is part of the original bytes.
        raw = (b'MODELKNOWLEDGE1\n' + json.dumps(value, ensure_ascii=True, indent=1).encode())
        frames[name] = {'name': name, 'kind': kind, 'raw': raw.hex(),
                        'hash': hashlib.sha256(raw).hexdigest()}

    add('C0', 'chunk', value='original-data')
    add('M0', 'manifest', children=[frames['C0']['hash']])
    add('C1', 'chunk', value='new-data')
    add('M1', 'manifest', children=[frames['C1']['hash']])
    add('R1', 'result', request='Q1', principal=7, sequence=1, revision=2,
        data_root=frames['M1']['hash'], result='original-result-bytes')
    add('I0', 'index', entries=[])
    add('I1', 'index', entries=[{'request': 'Q1', 'result': frames['R1']['hash']}])
    add('BAD', 'manifest', children=[frames['R1']['hash']])
    return frames


def head_key(scope=SCOPE):
    return f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}/head"


def object_key(generation, digest, scope=SCOPE):
    return (f"scap-object/v1/{scope['deployment']}/{scope['tenant']}/{scope['database']}"
            f"/inc/{scope['incarnation']}/gen/{scope['generation']}/storage/{generation}/objects/{digest}")


def initial_head(frames, *, sealed=False, bad_data=False):
    head_value = {
        'format': 'MODELHEAD-KNOWLEDGE1', 'scope': copy.deepcopy(SCOPE),
        'serial': 1, 'revision': 1, 'sequence': 0, 'A': 1, 'M': 1,
        'owner': 'W0', 'owner_epoch': 1, 'active': True, 'auth_epoch': 1,
        'acl': {'7': {'read': True, 'write': True, 'admin': True},
                '8': {'read': True, 'write': False, 'admin': False}},
        'life': 'ready', 'data': frames['BAD' if bad_data else 'M0']['hash'],
        'index': frames['I0']['hash'], 'plan': None, 'hold': None,
    }
    if sealed:
        head_value.update(serial=2, M=2, active=False)
        head_value['plan'] = {'id': 'P0', 'source': 1, 'target': 2, 'started_serial': 2,
                              'scope': copy.deepcopy(SCOPE), 'phase': 'sealed',
                              'roots': {'data': head_value['data'], 'index': head_value['index']}}
    return head_value


def main():
    frames = make_frames()
    spec = {
        'schema': 1, 'name': 'handle-scoped-knowledge', 'scope': SCOPE, 'foreign_scope': FOREIGN_SCOPE,
        'frames': frames, 'domains': ['D0', 'D1'],
        'bounds': {'actors': 4, 'lineages': 3, 'workers': 2, 'domains': 2, 'scopes': 2,
                   'generations': 3, 'holds': 1, 'plans': 1, 'frames': 8, 'tokens': 48,
                   'steps_per_actor': 96, 'states_per_profile': 50000,
                   'edges_per_profile': 150000, 'seconds_per_profile': 120},
        'claims': {
            'production_change': False, 'absolute_deadline_timing': 'NOT_MODELED',
            'native_validation': 'ABSTRACT_CONTENT_OUTCOME_ONLY',
            'retained_lookup': 'ABSTRACT_INDEX_RESULT_IDENTITY_ONLY_NOT_BTREE_OR_SCAPRES1',
            'ordinary_operation_durable_pins': False, 'durable_global_health': False,
            'generation_registry_memory_bound': 'NOT_PROVED',
            'lineage_history_reclamation': 'NOT_MODELED',
        },
        'required_current_rights': {
            'read': 'fresh READ; Ready', 'lookup': 'fresh READ for original principal; Ready',
            'write': 'fresh READ+WRITE; Ready; active owner; no plan',
            'takeover': 'fresh ADMIN; Ready', 'policy': 'fresh ADMIN; Ready or Maintenance',
            'copy_read': 'fresh ADMIN; exact current plan',
            'technical': 'fresh ADMIN; exact original current plan/hold predicate',
            'failure_probe': 'original authenticated context; no new data/admin grant',
        },
        'profile_assumptions': [
            'Every await/mark is an explicit finite fixture/program scheduling assumption.',
            'Pending dispatched requests always retain independent apply/discard choices after client exit.',
            'Original deadline exhaustion is an explicit local-stop event, not a real clock proof.',
            'A sealed initial copy plan assumes exact original raw closure was already validated at target.',
            'Fixture removal of a retired object assumes correct GC admission; checkpoint/DELETE protocol is not re-proved.',
            'Fixture corruption/restoration is an explicitly declared external fault, never automatic client repair.',
            'Closed lineage knowledge remains in model history; this is not an implementation of unbounded runtime storage.',
            'A new handle cannot clear or reuse an old lineage identity; clones require a live handle of that lineage.',
        ],
        'profiles': [],
    }

    def add(identifier, group, description, actors, witnesses, *, sealed=False, bad_data=False,
            semantic_bad=False, other_worker=False, other_domain=False, assumptions=()):
        h0 = initial_head(frames, sealed=sealed, bad_data=bad_data)
        h1 = initial_head(frames)
        h1.update(serial=3, A=2, M=2)
        lineages = {
            'H1': {'domain': 'D0', 'scope': copy.deepcopy(SCOPE), 'worker': 'W0', 'created': False,
                   'physical': {}, 'authority': False, 'semantic': False},
            'H2': {'domain': 'D1' if other_domain else 'D0', 'scope': copy.deepcopy(SCOPE),
                   'worker': 'W1' if other_worker else 'W0', 'created': False,
                   'physical': {}, 'authority': False, 'semantic': False},
            'H3': {'domain': 'D0', 'scope': copy.deepcopy(SCOPE), 'worker': 'W1', 'created': False,
                   'physical': {}, 'authority': False, 'semantic': False},
        }
        generations = [1, 2] if sealed else [1]
        objects = {'D0': {}, 'D1': {}}
        for domain, generation_set in [('D0', generations), ('D1', [2])]:
            for generation in generation_set:
                for name in ('M0', 'C0', 'I0', *(['BAD', 'R1'] if bad_data else [])):
                    item = frames[name]
                    objects[domain][object_key(generation, item['hash'])] = {
                        'raw': item['raw'], 'etag': f'"initial:{domain}:{generation}:{name}"'}
        used = {value['lineage'] for value in actors.values() if value['lineage'] is not None}
        initial = {
            'world': {'heads': {'D0': {head_key(): h0}, 'D1': {head_key(): h1}},
                      'objects': objects, 'head_fault': {'D0': None, 'D1': None},
                      'semantic_bad_roots': [frames['M0']['hash']] if semantic_bad else [],
                      'object_version': 1},
            'lineages': {name: value for name, value in lineages.items() if name in used},
            'actors': {name: initial_actor() for name in actors}, 'tokens': {},
        }
        profile = {'id': identifier, 'group': group, 'description': description,
                   'actors': actors, 'initial': initial, 'required_witnesses': witnesses,
                   'program_assumptions': list(assumptions)}
        assert len(actors) <= spec['bounds']['actors']
        assert max(len(value['program']) for value in actors.values()) <= spec['bounds']['steps_per_actor']
        assert len(initial['lineages']) <= spec['bounds']['lineages']
        spec['profiles'].append(profile)

    # Shared-lineage publication rejection and a separately complete read.
    for failure in ('missing', 'hash'):
        for verb in ('writer', 'takeover', 'policy'):
            a = [*enter(), mark('admitted'), wait('f', 'faulted'),
                 *get('M0', allow_failure=True), *probe(), mark('failed')]
            f = [wait('a', 'admitted'), step('fault_object', generation=1, name='M0', mode=failure),
                 step('fault_head', mode='unavailable'), mark('faulted'), wait('a', 'failed'),
                 step('fault_object', generation=1, name='M0', mode='restore'),
                 step('fault_head', mode=None), mark('restored')]
            b = [wait('f', 'restored'), *enter(new=False), *read_body()]
            c = [wait('f', 'restored'), *publish(verb, new=False)]
            add(f'K01_{failure}_{verb}', 'K01', 'Clone publication is blocked; own complete new read preserves latch',
                {'a': actor(a), 'b': actor(b), 'c': actor(c), 'f': actor(f, None, role='fixture')},
                ['original_unknown_incident', 'same_lineage_read_success_preserves_latch',
                 'same_lineage_publication_denied', 'failed_attempt_never_returns_data'])

    for group, other_worker in [('K02', False), ('K03', True)]:
        for failure in ('missing', 'hash'):
            a = [*enter(), mark('admitted'), wait('f', 'faulted'), *get('M0', allow_failure=True),
                 *probe(), mark('failed')]
            f = [wait('a', 'admitted'), step('fault_object', generation=1, name='M0', mode=failure),
                 step('fault_head', mode='unavailable'), mark('faulted'), wait('a', 'failed'),
                 step('fault_object', generation=1, name='M0', mode='restore'),
                 step('fault_head', mode=None), mark('restored')]
            b = [wait('f', 'restored'), *enter(), *read_body()]
            add(f'{group}_{failure}', group, 'Independent new handle reads using its own complete evidence',
                {'a': actor(a), 'b': actor(b, 'H2'), 'f': actor(f, None, role='fixture')},
                ['original_unknown_incident', 'independent_read_success_preserves_old_latch'],
                other_worker=other_worker)

    for failure in ('missing', 'hash'):
        a = [*enter(), mark('admitted'), wait('f', 'faulted'), *get('M0', allow_failure=True),
             *probe(), mark('failed')]
        f = [wait('a', 'admitted'), step('fault_object', generation=1, name='M0', mode=failure),
             step('fault_head', mode='unavailable'), mark('faulted'), wait('a', 'failed'),
             step('fault_head', mode=None), mark('ready')]
        b = [wait('f', 'ready'), *enter(), *get('M0', allow_failure=True), *probe()]
        add(f'K04_{failure}', 'K04', 'Independent handle must fail on its own persistent bad source',
            {'a': actor(a), 'b': actor(b, 'H2'), 'f': actor(f, None, role='fixture')},
            ['independent_failure_has_own_token', 'old_unknown_not_cleared'])

    for failure in ('missing', 'hash'):
        a = [*enter(), mark('admitted'), wait('m', 'retired'), *get('M0', allow_failure=True),
             *probe()]
        m = [step('begin', new=True), wait('a', 'admitted'), *technical('promote'),
             step('fault_object', generation=1, name='M0', mode=failure), mark('retired')]
        b = [wait('m', 'retired'), *enter(), *read_body()]
        add(f'K05_retired_{failure}', 'K05', 'Original failure expires only from its own retirement probe',
            {'a': actor(a), 'm': actor(m, 'H2', role='fixture'), 'b': actor(b, 'H3')},
            ['original_generation_expired', 'new_generation_read_success', 'other_lineage_not_poisoned'], sealed=True)
    a = [*enter(), *read_body(return_value=False), mark('materialized'), wait('m', 'retired'), step('return_read')]
    m = [step('begin', new=True), wait('a', 'materialized'), *technical('promote'),
         step('remove_retired', generation=1, name='M0'), mark('retired')]
    add('K05_materialized_return', 'K05', 'Original complete value can return after retirement without closing GET',
        {'a': actor(a), 'm': actor(m, 'H2', role='fixture')}, ['materialized_read_returns_after_fence'], sealed=True)

    a = [*enter('copy', copy_role='target'), mark('captured'), wait('m', 'replaced'),
         *get('M0', allow_failure=True), *probe()]
    m = [step('begin', new=True), wait('a', 'captured'), *technical('abort_plan'),
         *technical('freeze'), step('remove_retired', generation=2, name='M0'), mark('replaced')]
    add('K06_aborted_target', 'K06', 'G2 is retired under active G1 and new target G3',
        {'a': actor(a), 'm': actor(m, 'H2', role='fixture')},
        ['aborted_target_expires_with_lower_active_generation'], sealed=True)
    for failure in ('missing', 'hash'):
        m = [step('begin', new=True), *technical('hold_add'), *technical('promote'), mark('held'),
             wait('a', 'admitted'), step('fault_object', generation=1, name='M0', mode=failure), mark('faulted')]
        a = [wait('m', 'held'), *enter(retained=True), mark('admitted'), wait('m', 'faulted'),
             *get('M0', allow_failure=True), *probe()]
        add(f'K06_held_{failure}', 'K06', 'A legal active-G1 hold remains protected after Promote to G2',
            {'m': actor(m, 'H2', role='fixture'), 'a': actor(a)},
            ['hold_added_before_promotion', 'held_generation_cannot_expire'], sealed=True,
            assumptions=['Held-object fault is external corruption, not an allowed GC deletion.'])

    a = [*enter('copy', copy_role='source'), mark('captured'), wait('m', 'replaced'),
         *get('M0', allow_failure=True), *probe()]
    m = [step('begin', new=True), wait('a', 'captured'), *technical('abort_plan'), *technical('freeze'),
         step('fault_object', generation=1, name='M0', mode='missing'), mark('replaced')]
    add('K07_active_source', 'K07', 'Replacing the plan does not excuse corruption of its still-active source',
        {'a': actor(a), 'm': actor(m, 'H2', role='fixture')}, ['old_plan_active_source_is_corrupt'], sealed=True)

    for fault in ('malformed', 'wrong_scope'):
        a = [step('begin', new=True), mark('opened'), wait('f', 'faulted'),
             *head(allow_failure=True), mark('latched')]
        f = [wait('a', 'opened'), step('begin', new=False), step('fault_head', mode=fault), mark('faulted'),
             wait('a', 'latched'), step('fault_head', mode=None), mark('restored'), *head(),
             step('admit', mode='manage'), step('prepare_manage', kind='policy'),
             step('final_check'), step('send_head'), step('observe'), step('ack')]
        b = [wait('f', 'restored'), *enter(), *read_body()]
        c = [wait('f', 'restored'), *enter(new=False), *read_body()]
        add(f'K08_{fault}', 'K08', 'Malformed authority is known only to its lineage and is never cleared by a good read',
            {'a': actor(a), 'b': actor(b, 'H2'), 'c': actor(c), 'f': actor(f, role='fixture')},
            ['authority_latch_is_local', 'independent_read_success_preserves_old_latch',
             'same_lineage_read_success_preserves_latch', 'authority_latch_still_blocks_publication'])

    a = [*enter(), mark('admitted'), wait('f', 'faulted'), *get('M0', allow_failure=True),
         mark('failed'), wait('b', 'observed'), step('attempt_adopt', source='b', kind='authority')]
    b = [wait('a', 'failed'), step('begin', new=True), *head(), mark('observed')]
    f = [wait('a', 'admitted'), step('fault_object', generation=1, name='M0', mode='missing'), mark('faulted')]
    add('K09_foreign_domain', 'K09', 'Another trusted backend with matching Scope cannot prove original retirement',
        {'a': actor(a), 'b': actor(b, 'H2'), 'f': actor(f, None, role='fixture')},
        ['foreign_domain_retirement_proof_rejected'], other_domain=True)

    for fault in ('wrong_scope', 'malformed'):
        a = [*enter(), mark('admitted'), wait('m', 'faulted'), *get('M0', allow_failure=True),
             *probe()]
        m = [step('begin', new=True), wait('a', 'admitted'), *technical('promote'),
             step('fault_object', generation=1, name='M0', mode='missing'),
             step('fault_head', mode=fault), mark('faulted')]
        add(f'K09_probe_{fault}', 'K09', 'Only the original full-Scope failure probe may establish retirement',
            {'a': actor(a), 'm': actor(m, 'H2', role='fixture')},
            ['failure_probe_keeps_original_domain_scope', f'{fault}_probe_cannot_expire',
             'invalid_probe_latches_only_its_lineage'], sealed=True)

    # Both known and UNKNOWN observations remain enabled. Required witnesses select
    # the UNKNOWN histories; this program does not condition away network choices.
    w = [*publish('writer', uncertain=True), mark('answered'), step('release_handle')]
    b = [wait('a', 'closed'), step('begin', new=True), *head(),
         step('attempt_adopt', source='a', kind='context')]
    m = [step('begin', new=True), wait('a', 'answered'), *technical('fence'), mark('fenced')]
    add('K10_old_conditional', 'K10', 'A new handle cannot revive old state while every old conditional remains deliverable',
        {'a': actor(w), 'b': actor(b, 'H2'), 'm': actor(m, 'H3')},
        ['unknown_old_cas_applies_before_fence', 'unknown_old_cas_conflicts_after_fence',
         'new_handle_cannot_adopt_old_attempt', 'old_unknown_is_immutable'])

    for complete in (False, True):
        a = [*enter(), *(read_body(return_value=False) if complete else get('M0')),
             mark('ready'), wait('b', 'attempted'), *([] if complete else read_body(return_value=False)),
             step('return_read')]
        b = [wait('a', 'ready'), *enter(), mark('attempted'),
             step('attempt_adopt', source='a', kind='image' if complete else 'frames')]
        add('K11_' + ('image' if complete else 'prefix'), 'K11', 'Image and prefix provenance cannot move to a new handle',
            {'a': actor(a), 'b': actor(b, 'H2')},
            ['foreign_local_evidence_rejected', 'original_lineage_read_remains_usable'])

    for verb in ('writer', 'takeover', 'policy'):
        body = publication_body(verb)
        cut = next(i for i, item in enumerate(body) if item['op'] == 'final_check')
        a = [*enter('write' if verb == 'writer' else 'manage'), *body[:cut], mark('prepared'),
             step('final_check'), mark('checked'), wait('b', 'failed'), *body[cut + 1:]]
        b = [wait('a', 'prepared'), *enter(new=False), mark('admitted'), wait('f', 'faulted'),
             *get('M0', allow_failure=True), mark('failed')]
        f = [wait('b', 'admitted'), step('fault_object', generation=1, name='M0', mode='missing'), mark('faulted')]
        add(f'K12_{verb}', 'K12', 'A latch before final check blocks; a latch after it does not revoke the permit',
            {'a': actor(a), 'b': actor(b), 'f': actor(f, None, role='fixture')},
            ['latch_before_final_check_denies_permit', 'latch_after_final_check_allows_original_dispatch'])

    for verb in ('writer', 'takeover', 'policy'):
        body = publication_body(verb, uncertain=True)
        cut = next(i for i, item in enumerate(body) if item['op'] == 'send_head')
        a = [*enter('write' if verb == 'writer' else 'manage'), *body[:cut + 1], mark('dispatched'),
             wait('b', 'failed'), *body[cut + 1:]]
        b = [wait('a', 'dispatched'), *enter(new=False), mark('admitted'), wait('m', 'faulted'),
             step('get_root'), step('observe', allow_failure=True), mark('failed')]
        m = [step('begin', new=True), wait('b', 'admitted'),
             step('fault_captured', actor='b', mode='missing'), mark('faulted'),
             wait('b', 'failed'), *technical('fence')]
        witnesses = ['inflight_cas_known_after_latch', 'inflight_cas_conflict_after_latch',
                     'inflight_cas_unknown_after_latch', 'latch_does_not_revoke_original_ack']
        if verb == 'writer':
            witnesses += ['known_commit_native_failure_preserves_receipt']
        add(f'K13_{verb}', 'K13', 'Post-dispatch health cannot change original effect or caller knowledge',
            {'a': actor(a), 'b': actor(b), 'm': actor(m, 'H2', role='fixture')}, witnesses)

    for verb in ('read', 'writer', 'takeover', 'policy'):
        original = [*enter(), *read_body()] if verb == 'read' else publish(verb)
        a = [*original, mark('answered'), wait('b', 'failed'), step('stop_local'), step('detach')]
        failed_root = 'M1' if verb == 'writer' else 'M0'
        b = [wait('a', 'answered'), *enter(new=False), mark('admitted'), wait('f', 'faulted'),
             *get(failed_root, allow_failure=True), mark('failed')]
        f = [wait('b', 'admitted'), step('fault_object', generation=1, name=failed_root, mode='missing'), mark('faulted')]
        add(f'K14_{verb}', 'K14', 'Later latch and stop cannot rewrite earlier public success',
            {'a': actor(a), 'b': actor(b), 'f': actor(f, None, role='fixture')}, ['historical_success_survives_later_events'])

    a = [*enter(), *get('BAD'), *get('R1', allow_failure=True), mark('semantic')]
    b = [wait('a', 'semantic'), *enter(), *get('BAD'), *get('R1', allow_failure=True)]
    add('K15_typed_edge', 'K15', 'Hash-valid typed-edge corruption is independently detected, not called expiry',
        {'a': actor(a), 'b': actor(b, 'H2')}, ['typed_semantic_failure_is_not_expiry', 'semantic_detection_is_per_lineage'],
        bad_data=True, assumptions=['This externally corrupt input remains active; it is not claimed to be legally sealed/copied.'])
    a = [*enter(), *load_all(), step('materialize'), step('validate_content', allow_failure=True),
         mark('semantic'), wait('m', 'retired'), step('attempt_expire_semantic')]
    m = [step('begin', new=True), wait('a', 'semantic'), *technical('promote'), mark('retired')]
    b = [wait('m', 'retired'), *enter(), *load_all(), step('materialize'), step('validate_content', allow_failure=True)]
    add('K15_abstract_content', 'K15', 'Raw-valid but semantically invalid content is not repaired by generation promotion',
        {'a': actor(a), 'm': actor(m, 'H2'), 'b': actor(b, 'H3')},
        ['semantic_latch_survives_physical_retirement', 'same_content_new_generation_is_still_invalid'],
        sealed=True, semantic_bad=True,
        assumptions=['Content validation is a declared abstract outcome after complete raw closure, not a SQLite proof.'])

    a = [*publish('writer', uncertain=True), mark('answered'), step('release_handle')]
    b = [wait('a', 'closed'), *enter('lookup'), *load_all(), step('materialize_lookup'), step('return_lookup')]
    add('K16_independent_lookup', 'K16', 'A new handle independently proves a durable receipt without rewriting original UNKNOWN',
        {'a': actor(a), 'b': actor(b, 'H2')},
        ['independent_lookup_proves_old_unknown_commit', 'lookup_does_not_replay_native', 'old_unknown_is_immutable'],
        assumptions=['The abstract index/result binding is not the real B+ tree or SCAPRES1 codec.'])

    for verb in ('writer', 'takeover', 'policy'):
        body = publication_body(verb, uncertain=True)
        cut = next(i for i, item in enumerate(body) if item['op'] == 'send_head')
        a = [*enter('write' if verb == 'writer' else 'manage'), *body[:cut],
             step('stop_local'), *body[cut:]]
        add(f'K17_before_dispatch_{verb}', 'K17', 'A last-health permit does not override a subsequently closed local gate',
            {'a': actor(a)}, ['stopped_permit_cannot_dispatch'],
            assumptions=['The explicit stop is after the final healthy step and before the next send_head step.'])
        a = [*enter('write' if verb == 'writer' else 'manage'), *body[:cut + 1],
             step('stop_local'), *body[cut + 1:], step('release_handle')]
        witnesses = ['stopped_dispatched_cas_still_applies', 'stopped_dispatched_cas_still_discards',
                     'stopped_original_public_ack_is_withheld', 'stopped_unknown_token_not_rewritten']
        if verb == 'writer':
            witnesses += ['stopped_known_durable_native_commit', 'stopped_known_durable_native_failure']
        add(f'K17_after_dispatch_{verb}', 'K17', 'Closing the local gate cannot cancel an already dispatched original conditional',
            {'a': actor(a)}, witnesses,
            assumptions=['The explicit stop precedes observe, not backend delivery; all pending deliveries remain enabled.'])

    ids = [profile['id'] for profile in spec['profiles']]
    assert len(ids) == len(set(ids))
    spec['expanded_counts'] = {
        'profiles': len(ids),
        'steps': sum(len(value['program']) for profile in spec['profiles'] for value in profile['actors'].values()),
        'mandatory_witnesses': sum(len(profile['required_witnesses']) for profile in spec['profiles']),
        'maximum_actor_steps': max(len(value['program']) for profile in spec['profiles'] for value in profile['actors'].values()),
    }
    target = HERE / 'inputs.json'
    target.write_text(json.dumps(spec, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'PROGRAMS_EXPANDED_NOT_EXPLORED', **spec['expanded_counts'],
                      'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
