"""Named semantic bad histories. Each must fail at its declared independent rule.

Most are a minimal raw prefix ending at the first illegal candidate/observation;
they do not need a fabricated later success to demonstrate an unsafe admission.
If the intended check is removed, a later generic failure is NOT a passing test.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json

import cases
from model import World, HEAD, encoded, digest, plan_input, descriptor, control_key


def trace(world, name='negative-source'):
    return world.trace(name)


def index(value, event, operation=None, last=True, predicate=lambda _row: True):
    calls = {row['call']: row['operation'] for row in value['events'] if row['event'] == 'http_dispatched'}
    found = [i for i, row in enumerate(value['events']) if row['event'] == event and
             (operation is None or calls.get(row.get('call')) == operation) and predicate(row)]
    assert found, (event, operation)
    return found[-1] if last else found[0]


def prefix(value, end):
    result = deepcopy(value)
    result['events'] = result['events'][:end + 1]
    for number, row in enumerate(result['events'], 1):
        row['sequence'] = number
    return result


def candidate(world, operation, mutate, last=True):
    value = trace(world)
    at = index(value, 'candidate_fixed', operation, last)
    row = value['events'][at]
    body = json.loads(row['body'])
    mutate(body, row)
    row['body'] = encoded(body)
    return prefix(value, at)


def append_before_error(world, identifier, event):
    value = trace(world)
    at = index(value, 'server_finished', predicate=lambda row: row['call'] == identifier)
    value['events'][at] = {'sequence': at + 1, **event}
    return prefix(value, at)


def observed_read(world, identifier, kind):
    reads = {row['io']: row for row in world.events if row['event'] == 's3_get_invoked'
             and row['call'] == identifier and kind(row['key'])}
    return [(row['io'], row['value']) for row in world.events
            if row['event'] == 's3_get_response' and row['io'] in reads]


def failed_head_candidate(world, identifier, mutate):
    call = world.calls[identifier]
    basis, stored = observed_read(world, identifier, lambda key: key == HEAD)[-1]
    body = json.loads(stored['body'])
    mutate(body, call)
    return append_before_error(world, identifier, {'event': 'candidate_fixed', 'call': identifier,
        'key': HEAD, 'body': encoded(body), 'condition': {'if_match': stored['etag']},
        'basis_io': basis, 'descriptor_io': call.desc_io, 'proof_io': call.proof_io,
        'prepare_proof_io': call.prepare_proof_io, 'deadline': call.deadline})


def pending_world(kind='claimed'):
    world = World()
    ident = cases.prepared(world)
    cases.accepted(world, 'claim' if kind == 'claimed' else 'abort', {'identity': ident})
    return world, ident


def no_crash_cancellation():
    world = World()
    ident = cases.prepared(world)
    call = world.begin('claim', {'identity': ident})
    world.admit(call)
    io = world.invoke(call)
    world.crash('worker-2')
    world.timeout(call)
    value = trace(world)
    value['events'][-1]['pending_effects'].remove(io)
    return value


def cas_rebase():
    world, ident = pending_world()
    call = world.begin('resume', {'identity': ident})
    world.admit(call)
    world.recover(call)
    cases.accepted(world, 'quota', {'quota': 77}, route='other')
    world.invoke(call)
    value = trace(world)
    at = index(value, 's3_put_invoked', predicate=lambda row: row['call'] == call)
    value['events'][at]['condition'] = {'if_match': world.objects[HEAD]['etag']}
    return prefix(value, at)


def claim_rebase():
    world = World()
    ident = cases.prepared(world)
    cases.accepted(world, 'quota', {'quota': 77}, route='other')
    call = world.request('claim', {'identity': ident})
    cases.result(world, call, code='FENCED')
    def mutate(head, current):
        head['revision'] += 1
        head['head_serial'] += 1
        head['owner']['epoch'] += 1
        head['owner']['instance'] = 2
        head['format'], head['active'] = 8, False
        head['transition_nonce'] = current.desc['nonces']['claim']
        head['owner_plan'] = {'identity': current.desc['identity'], 'descriptor_hash': digest(current.desc),
            'admission': {'kind': 'claim', 'revision': head['revision'], 'head_serial': head['head_serial']},
            'phase': {'kind': 'claimed', 'revision': head['revision'], 'head_serial': head['head_serial'],
                      'nonce': current.desc['nonces']['claim'], 'owner': deepcopy(head['owner'])}}
    return failed_head_candidate(world, call, mutate)


def first_wins_readback():
    world = cases.descriptor_race(False, False, False)
    loser = 'c2'
    call = world.calls[loser]
    read = observed_read(world, loser, lambda key: '/descriptor/' in key)[-1][0]
    return append_before_error(world, loser, {'event': 'immutable_readback_verified', 'call': loser,
                                            'write': call.io, 'read': read})


def immediate_unclaimed_abort():
    world, _ident = pending_world('cancelling')
    def mutate(head, _row):
        head['owner_plan']['phase']['kind'] = 'aborted'
        head['owner_plan']['phase']['nonce'] = 1014
    return candidate(world, 'abort', mutate)


def cancel_activation():
    world, ident = pending_world('cancelling')
    call = world.request('resume', {'identity': ident})
    cases.result(world, call, code='CANCELLED')
    def mutate(head, current):
        head['revision'] += 1
        head['head_serial'] += 1
        head['active'] = True
        head['owner_plan']['phase'].update(kind='active', revision=head['revision'],
            head_serial=head['head_serial'], nonce=current.desc['nonces']['activate'])
    return failed_head_candidate(world, call, mutate)


def exhausted_pending_metadata():
    world = cases.metadata_reserve('acl', 0)
    def mutate(head, _row):
        head['revision'] = head['head_serial'] = 5
    return candidate(world, 'acl', mutate)


def reserve_bound(epoch=False):
    world = World(maximum=5, revision=1 if epoch else 3, serial=1 if epoch else 3,
                  epoch=4 if epoch else 1)
    cases.prepared(world)
    value = trace(world)
    value['events'][0]['maximum'] = 4
    return prefix(value, index(value, 'candidate_fixed', 'prepare'))


def legacy_late():
    world = cases.legacy_pending('active')
    call = next(name for name, row in world.calls.items() if row.operation == 'legacy_activate')
    def mutate(head, _current):
        head['revision'] += 1
        head['head_serial'] += 1
        head['active'] = True
    return failed_head_candidate(world, call, mutate)


def stale_recovery_barrier():
    world = cases.recovery_metadata('acl', 'during_recovery', True)
    call = next(name for name, row in world.calls.items() if row.operation == 'resume')
    heads = observed_read(world, call, lambda key: key == HEAD)
    return append_before_error(world, call, {'event': 'recovery_barrier', 'call': call,
        'basis_io': heads[0][0], 'final_io': heads[-1][0]})


def reused_recovery_read():
    world, _ident = cases.active()
    value = trace(world)
    at = index(value, 'recovery_barrier')
    value['events'][at]['final_io'] = value['events'][at]['basis_io']
    return prefix(value, at)


def cached_acl_recovery():
    world = cases.recovery_metadata('acl', 'during_recovery', True)
    call = next(name for name, row in world.calls.items() if row.operation == 'resume' and
                row.outcome == {'kind': 'error', 'value': {'code': 'DENIED'}})
    head_io = observed_read(world, call, lambda key: key == HEAD)[-1][0]
    return append_before_error(world, call, {'event': 'recovery_started', 'call': call,
        'basis_io': head_io, 'descriptor_io': world.calls[call].desc_io, 'deadline': world.calls[call].deadline})


def wrong_worker():
    world, _ident = cases.active()
    value = trace(world)
    at = index(value, 'http_dispatched', 'claim')
    value['events'][at]['expected_worker'] = 3
    return prefix(value, index(value, 's3_get_invoked', 'claim', False))


def missing_retained_result():
    world, _ident = cases.active()
    value = trace(world)
    at = index(value, 'recovery_verified')
    value['events'][at]['reads'].pop()
    return prefix(value, at)


def activate_wrong_target():
    world = cases.activate_only('valid')
    value = trace(world)
    at = index(value, 'http_dispatched', 'prepare')
    value['events'][at]['args']['input']['target'] = 2
    end = index(value, 'candidate_fixed', 'prepare')
    body = json.loads(value['events'][end]['body'])
    body['target'] = 2
    body['input_digest'] = digest({key: item for key, item in body.items() if key != 'input_digest'})
    value['events'][end]['body'] = encoded(body)
    return prefix(value, end)


def activate_active_base():
    world = cases.activate_only('valid')
    value = trace(world)
    end = index(value, 'candidate_fixed', 'prepare')
    initial = value['events'][0]['objects'][HEAD]
    head = json.loads(initial['body'])
    head['active'] = True
    initial['body'] = encoded(head)
    for row in value['events'][:end]:
        if (row['event'] in ('s3_get_effect', 's3_get_response') and row['value'] is not None and
                row['value']['etag'] == initial['etag']):
            row['value']['body'] = initial['body']
    return prefix(value, end)


def proof_late_counters():
    world = cases.proof_history(False, 'claim')
    def mutate(body, row):
        read = next(e for e in world.events if e['event'] == 's3_get_response' and e['io'] == row['basis_io'])
        head = json.loads(read['value']['body'])
        body['marker']['phase']['revision'] = head['revision']
        body['marker']['phase']['head_serial'] = head['head_serial']
    return candidate(world, 'preserve', mutate)


def proof_missing_read(admission='claim'):
    world = cases.proof_history(False, admission)
    value = trace(world)
    at = index(value, 'candidate_fixed', admission,
               predicate=lambda row: row['proof_io'] is not None)
    value['events'][at]['proof_io'] = None
    return prefix(value, at)


def old_marker_changed():
    world = cases.proof_history(False, 'claim')
    return candidate(world, 'acl', lambda head, _row: head['owner_plan']['phase'].update(nonce=90909))


def pending_mutator_success():
    world = cases.pending_guards('claimed')
    value = trace(world)
    call = next(name for name, row in world.calls.items() if row.operation == 'guard')
    at = index(value, 'server_finished', predicate=lambda row: row['call'] == call)
    value['events'][at].update(kind='guard_only', value={'entry': 'execute', 'production_effect': 'NOT_MODELLED'})
    return prefix(value, at)


def readonly_writer():
    world = cases.pending_guards('cancelling')
    value = trace(world)
    at = index(value, 'server_finished', predicate=lambda row: row['kind'] == 'read_only')
    value['events'][at]['value']['writer'] = True
    return prefix(value, at)


def owner_root_changed():
    world, _ident = cases.active()
    return candidate(world, 'claim', lambda head, _row: head.update(data_root=head['requests'][0]['result']))


def sql_replay():
    world = cases.sql_unknown()
    value = trace(world)
    at = index(value, 'native_sql_executed')
    value['events'].insert(at + 1, deepcopy(value['events'][at]))
    return prefix(value, at + 1)


def extended_deadline():
    world = cases.limits('deadline')
    value = trace(world)
    at = index(value, 's3_put_invoked', 'prepare', False)
    value['events'][at]['deadline'] += 1000
    return prefix(value, at)


def reset_metadata_budget():
    world = World()
    cases.prepared(world)
    value = trace(world)
    at = index(value, 'http_dispatched', 'prepare')
    value['events'][at]['io_limit'] = 1
    return prefix(value, index(value, 's3_put_invoked', 'prepare'))


def missing_not_applied():
    world = World()
    ident = cases.prepared(world)
    world.request('inspect', {'identity': ident})
    value = trace(world)
    at = index(value, 'server_finished', 'inspect')
    value['events'][at]['value']['past_effect'] = 'not_applied'
    return prefix(value, at)


def historical_ack():
    world, ident = cases.active()
    world.request('inspect', {'identity': ident})
    value = trace(world)
    at = index(value, 'server_finished', 'inspect')
    value['events'][at]['value']['native_session'] = True
    value['events'][at]['value']['historical_ack'] = True
    return prefix(value, at)


def unstable_inspect():
    world = cases.historical_inspect_race('acl', 'after_proof')
    call = next(name for name, row in world.calls.items() if row.operation == 'inspect' and
                row.outcome == {'kind': 'error', 'value': {'code': 'CONFLICT'}})
    heads = observed_read(world, call, lambda key: key == HEAD)
    proof = observed_read(world, call, lambda key: '/proof/' in key)[0][0]
    return append_before_error(world, call, {'event': 'inspect_barrier', 'call': call,
        'basis_io': heads[0][0], 'proof_io': proof, 'final_io': heads[-1][0]})


def changed_historical_owner():
    world = cases.historical_deleted()
    def mutate(body, _row):
        body['marker']['phase']['owner']['epoch'] += 1
    return candidate(world, 'preserve', mutate)


def cross_scope():
    world = World()
    cases.prepared(world)
    def mutate(body, _row):
        body['scope']['incarnation'] = 2
        body['input_digest'] = digest({key: value for key, value in body.items() if key != 'input_digest'})
    return candidate(world, 'prepare', mutate)


def unknown_rewritten():
    world = cases.late_http()
    value = trace(world)
    at = index(value, 'caller_observed', predicate=lambda row: row['kind'] == 'unknown')
    changed = deepcopy(value['events'][at])
    changed.update(kind='accepted', value={'claimed_old_ack': True})
    value['events'].insert(at + 1, changed)
    return prefix(value, at + 1)


def mixed_get_pair():
    world = World()
    cases.prepared(world)
    value = trace(world)
    at = index(value, 's3_get_response', last=False, predicate=lambda row: row['value'] is not None)
    value['events'][at]['value']['etag'] = '"another-opaque-value"'
    return prefix(value, at)


def duplicate_field():
    world = World()
    cases.prepared(world)
    value = trace(world)
    at = index(value, 'candidate_fixed', 'prepare')
    value['events'][at]['body'] = value['events'][at]['body'].replace('"version":1', '"version":1,"version":1')
    return prefix(value, at)


def before_immutable_readback():
    world = World()
    cases.prepared(world)
    value = trace(world)
    value['events'] = [row for row in value['events'] if row['event'] != 'immutable_readback_verified']
    return prefix(value, index(value, 'server_finished', 'prepare'))


def native_before_effect():
    world, _ident = cases.active()
    value = trace(world)
    native = value['events'][index(value, 'native_publication')]
    at = index(value, 's3_put_invoked', 'resume')
    value['events'].insert(at + 1, deepcopy(native))
    return prefix(value, at + 1)


def complete_exchange_omitted():
    world = World()
    ident = cases.prepared(world)
    call = cases.accepted(world, 'claim', {'identity': ident})
    value = trace(world)
    write = world.calls[call].io
    value['events'] = [row for row in value['events'] if row.get('io') != write and
                      not (row.get('call') == call and row['event'] in ('server_finished', 'caller_observed'))]
    # Removing a complete final exchange cannot shrink the observer's independent ledger.
    return prefix(value, len(value['events']) - 1)


def hashless_mutation():
    world, _ident = cases.active()
    value = trace(world)
    at = index(value, 'http_dispatched', 'claim')
    del value['events'][at]['args']['descriptor_hash']
    return prefix(value, index(value, 'candidate_fixed', 'claim'))


def altered_restore_input():
    world = cases.lost_prepare_restore('accepted', False)
    value = trace(world)
    at = index(value, 'client_ref_restored', last=False)
    value['events'][at]['saved_input']['target'] = 3
    return prefix(value, at)


def existing_prepare_rebased():
    world = cases.lost_prepare_restore('metadata', False)
    value = trace(world)
    at = index(value, 'server_finished', 'prepare', predicate=lambda row: row['kind'] == 'prepared')
    body = json.loads(value['events'][at]['value']['body'])
    body['base']['head_hash'] = digest(world.head())
    body['base']['etag'] = world.objects[HEAD]['etag']
    value['events'][at]['value']['body'] = encoded(body)
    return prefix(value, at)


def unauthorized_input_oracle():
    world = cases.lost_prepare_restore('none', False)
    value = trace(world)
    at = index(value, 'server_finished', 'prepare', predicate=lambda row: row['kind'] == 'error' and
               row['value']['code'] == 'DENIED')
    value['events'][at]['value']['code'] = 'CONFLICT'
    return prefix(value, at)


def rebuild_missing_descriptor(kind):
    world = cases.missing_permanent_descriptor(kind)
    call_id = next(name for name, current in reversed(list(world.calls.items())) if current.operation == 'prepare')
    call = world.calls[call_id]
    basis, stored = observed_read(world, call_id, lambda key: key == HEAD)[-1]
    body = descriptor(json.loads(stored['body']), stored['etag'], call.args['input'])
    return append_before_error(world, call_id, {'event': 'candidate_fixed', 'call': call_id,
        'key': control_key('descriptor', **call.args['input']['identity']), 'body': encoded(body),
        'condition': {'if_none_match': True}, 'basis_io': basis, 'descriptor_io': call.desc_io,
        'proof_io': None, 'prepare_proof_io': call.prepare_proof_io, 'deadline': call.deadline})


def future_historical_proof():
    world = cases.future_proof(False)
    identifier = next(name for name, call in world.calls.items() if call.operation == 'inspect')
    heads = observed_read(world, identifier, lambda key: key == HEAD)
    proof = observed_read(world, identifier, lambda key: '/proof/' in key)[0][0]
    return append_before_error(world, identifier, {'event': 'inspect_barrier', 'call': identifier,
        'basis_io': heads[0][0], 'proof_io': proof, 'final_io': heads[-1][0]})


def incorrect_owner_binding_outcome(changed_head):
    world = cases.owner_binding_fault(changed_head)
    identifier = next(name for name, call in world.calls.items() if call.operation == 'inspect')
    value = trace(world)
    at = index(value, 'server_finished', predicate=lambda row: row['call'] == identifier)
    if changed_head:
        value['events'][at]['value']['code'] = 'CORRUPT'
    else:
        desc = world.calls[identifier].desc
        value['events'][at].update(kind='observed', value={'phase': 'unaccepted_or_fenced',
            'prepared': {'body': encoded(desc), 'descriptor_hash': digest(desc)},
            'current_head': world.head(), 'past_effect': 'unknown', 'native_session': False,
            'historical_ack': False})
    return prefix(value, at)


def wrong_current_owner_nonce():
    world = cases.phase_nonce_successor('technical')
    return candidate(world, 'storage', lambda head, _row: head.update(transition_nonce=9001))


@dataclass(frozen=True)
class Negative:
    name: str
    rule: str
    build: object


def negatives():
    rows = (
        ('original-attempt-rebased', 'fixed-candidate', cas_rebase),
        ('descriptor-claim-rebased', 'original-descriptor-base', claim_rebase),
        ('crash-deletes-invoked-request', 'invoked-survives-crash', no_crash_cancellation),
        ('same-id-different-input-readback', 'immutable-first-input', first_wins_readback),
        ('unclaimed-abort-skips-cancelling', 'two-stage-terminal', immediate_unclaimed_abort),
        ('cancelling-can-activate', 'cancel-never-activates', cancel_activation),
        ('metadata-spends-terminal-counter', 'pending-counter-reserve', exhausted_pending_metadata),
        ('prepare-insufficient-two-slots', 'terminal-counter-reserve', lambda: reserve_bound(False)),
        ('takeover-epoch-overflow', 'owner-epoch-overflow', lambda: reserve_bound(True)),
        ('legacy-new-input-during-pending', 'legacy-permanent-disabled', legacy_late),
        ('recovery-ignores-new-acl-head', 'fresh-recovery-barrier', stale_recovery_barrier),
        ('recovery-reuses-initial-get', 'fresh-recovery-barrier-order', reused_recovery_read),
        ('fresh-resume-uses-cached-admin', 'fresh-acl', cached_acl_recovery),
        ('wrong-actual-worker-guard', 'actual-target-guard', wrong_worker),
        ('retained-result-not-recovered', 'complete-retained-closure', missing_retained_result),
        ('activate-only-wrong-owner', 'activate-only-base', activate_wrong_target),
        ('activate-only-starts-active', 'activate-only-base', activate_active_base),
        ('proof-rebuilt-from-later-counters', 'stable-terminal-proof', proof_late_counters),
        ('claim-overwrites-without-proof-read', 'proof-before-replace', lambda: proof_missing_read('claim')),
        ('cancel-overwrites-without-proof-read', 'proof-before-replace', lambda: proof_missing_read('abort')),
        ('acl-rewrites-terminal-marker', 'head-exact-delta', old_marker_changed),
        ('pending-write-entry-allowed', 'pending-mutator-guard', pending_mutator_success),
        ('readonly-grants-writer', 'readonly-not-writer', readonly_writer),
        ('owner-change-replaces-data-root', 'original-closure-preserved', owner_root_changed),
        ('unknown-sql-is-replayed', 'sql-never-replayed', sql_replay),
        ('request-extends-original-deadline', 'fixed-deadline', extended_deadline),
        ('request-resets-metadata-budget', 'metadata-io-budget', reset_metadata_budget),
        ('missing-proof-means-not-applied', 'fence-not-not-applied', missing_not_applied),
        ('history-means-ack-and-session', 'observation-not-old-ack', historical_ack),
        ('proof-read-crosses-acl-change', 'stable-history-observation', unstable_inspect),
        ('named-delete-rewrites-proof-owner', 'stable-terminal-proof', changed_historical_owner),
        ('descriptor-cross-scope', 'full-scope', cross_scope),
        ('unknown-rewritten-after-observation', 'unknown-not-rewritten', unknown_rewritten),
        ('get-body-and-etag-mixed', 'same-get-response', mixed_get_pair),
        ('descriptor-duplicate-json-field', 'strict-json', duplicate_field),
        ('immutable-ack-before-exact-readback', 'ack-after-immutable-readback', before_immutable_readback),
        ('native-before-head-response', 'native-after-authoritative-phase', native_before_effect),
        ('whole-exchange-omitted', 'observer-denominator', complete_exchange_omitted),
        ('hashless-ref-can-mutate', 'hash-required-plan-ref', hashless_mutation),
        ('restored-descriptor-ignores-saved-input', 'restore-saved-input-match', altered_restore_input),
        ('existing-prepare-returns-new-base', 'same-fixed-prepare-input', existing_prepare_rebased),
        ('prepare-conflict-leaks-before-admin', 'prepare-authorize-before-history', unauthorized_input_oracle),
        ('rebuild-descriptor-still-in-marker', 'referenced-descriptor-must-exist', lambda: rebuild_missing_descriptor('terminal')),
        ('rebuild-descriptor-retained-by-proof', 'referenced-descriptor-must-exist', lambda: rebuild_missing_descriptor('superseded')),
        ('old-proof-not-before-new-admission', 'historical-proof-before-current-admission', future_historical_proof),
        ('same-operation-wrong-hash-reported-fenced', 'same-identity-descriptor-binding', lambda: incorrect_owner_binding_outcome(False)),
        ('changing-head-latched-as-owner-corruption', 'changed-head-before-corruption', lambda: incorrect_owner_binding_outcome(True)),
        ('technical-head-changes-current-owner-nonce', 'current-owner-transition-nonce', wrong_current_owner_nonce),
    )
    return [Negative(*row) for row in rows]
