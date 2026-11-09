"""Required reachable observations, separate from universal edge obligations."""

from oracle_protocol import decoded_head, permanent, valid_authority


def hits(before, after, event, spec, profile):
    result = set()
    actors = after['actors']
    a, b = actors.get('a', {}), actors.get('b', {})
    h1 = after['lineages'].get('H1', {})
    current = next(iter(after['world']['heads']['D0'].values()))

    def outcome(actor):
        return (actor.get('outcome') or {}).get('kind')

    def failed(actor, kind=None, classification=None):
        value = actor.get('failure')
        return bool(value and (kind is None or value['kind'] == kind)
                    and (classification is None or value['classification'] == classification))

    def latched(known):
        return bool(known.get('physical') or known.get('authority') or known.get('semantic'))

    def own_cas(actor_name='a'):
        actor = actors.get(actor_name, {})
        return after['tokens'].get(actor.get('cas'))

    def observation(token, name):
        return bool(token and token['observation'] and token['observation']['kind'] == name)

    def effect(token, name):
        return bool(token and token['effect'] and token['effect']['kind'] == name)

    def client(op, actor='a'):
        return event['kind'] == 'client' and event['actor'] == actor and event['op'] == op

    def add(name, condition):
        if condition:
            result.add(name)

    unresolved = failed(a, 'physical', 'unresolved') and outcome(a) == 'AuthorityUnavailable' and a.get('probe_used')
    add('original_unknown_incident', unresolved)
    add('failed_attempt_never_returns_data', unresolved and outcome(a) not in ('Read', 'Ack'))
    add('old_unknown_not_cleared', unresolved and failed(b, 'physical'))
    same_read = any(value.get('outcome') and value['outcome']['kind'] == 'Read'
                    and profile['actors'][name]['lineage'] == 'H1'
                    and name != 'a' for name, value in actors.items())
    add('same_lineage_read_success_preserves_latch', same_read and latched(h1))
    add('same_lineage_publication_denied', any(value['stopped'] == 'publication_latched'
                                               and profile['actors'][name]['lineage'] == 'H1'
                                               for name, value in actors.items()) and latched(h1))
    add('independent_read_success_preserves_old_latch', outcome(b) == 'Read'
        and profile['actors']['b']['lineage'] != 'H1' and latched(h1))
    add('independent_failure_has_own_token', failed(b, 'physical') and b['failure']['token'] != (a.get('failure') or {}).get('token')
        and after['tokens'][b['failure']['token']]['actor'] == 'b')
    add('original_generation_expired', failed(a, 'physical', 'expired') and outcome(a) == 'SnapshotExpired')
    add('new_generation_read_success', outcome(b) == 'Read' and b['context']['generation'] == 2)
    add('other_lineage_not_poisoned', failed(a, 'physical', 'expired') and outcome(b) == 'Read'
        and not latched(after['lineages'][profile['actors']['b']['lineage']]))
    add('materialized_read_returns_after_fence', client('return_read') and outcome(a) == 'Read'
        and a['context']['generation'] == 1 and current['A'] == 2)
    add('aborted_target_expires_with_lower_active_generation', failed(a, 'physical', 'expired')
        and a['failure']['generation'] == 2 and current['A'] == 1 and current['plan'] is not None
        and current['plan']['target'] == 3)
    add('hold_added_before_promotion', current['A'] == 2 and current['hold'] is not None
        and current['hold']['generation'] == 1
        and any(token['request'].get('purpose') == 'hold_add' and effect(token, 'Applied') for token in after['tokens'].values())
        and any(token['request'].get('purpose') == 'promote' and effect(token, 'Applied') for token in after['tokens'].values()))
    add('held_generation_cannot_expire', failed(a, 'physical', 'corrupt') and a['failure']['generation'] == 1
        and current['A'] == 2 and current['hold'] is not None and current['hold']['generation'] == 1)
    add('old_plan_active_source_is_corrupt', failed(a, 'physical', 'corrupt') and a['context']['mode'] == 'copy'
        and a['failure']['generation'] == current['A'] == 1 and current['plan'] is not None
        and current['plan']['target'] == 3)
    add('authority_latch_is_local', h1.get('authority') and not after['lineages'].get('H2', {}).get('authority'))
    add('authority_latch_still_blocks_publication', h1.get('authority')
        and any(value['stopped'] == 'publication_latched' for value in actors.values()))
    add('foreign_domain_retirement_proof_rejected', a.get('stopped') == 'foreign_authority_rejected'
        and a['failure']['domain'] == 'D0' and b['view']['domain'] == 'D1')
    if a.get('probe_used') and a.get('last') in after['tokens']:
        token = after['tokens'][a['last']]
        request = token['request']
        if request.get('purpose') == 'probe' and a.get('failure'):
            own = request['domain'] == a['failure']['domain'] and request['scope'] == a['failure']['scope']
            add('failure_probe_keeps_original_domain_scope', own and token['observation'] is not None)
            invalid = observation(token, 'Found') and not valid_authority(decoded_head(token['observation']), request['scope'], spec['bounds']['generations'])
            add('invalid_probe_latches_only_its_lineage', invalid and h1.get('authority')
                and not after['lineages'].get('H2', {}).get('authority') and failed(a, 'physical', 'unresolved'))
            for fault in ('wrong_scope', 'malformed'):
                add(f'{fault}_probe_cannot_expire', profile['id'] == f'K09_probe_{fault}' and invalid
                    and outcome(a) == 'AuthorityUnavailable' and failed(a, 'physical', 'unresolved'))
    original = own_cas()
    fence = own_cas('m')
    old_unknown = observation(original, 'Unknown') and outcome(a) == 'Unknown'
    add('unknown_old_cas_applies_before_fence', old_unknown and effect(original, 'Applied') and effect(fence, 'Applied')
        and current['revision'] == 3 and current['data'] == spec['frames']['M1']['hash'])
    add('unknown_old_cas_conflicts_after_fence', old_unknown and effect(original, 'Conflict') and effect(fence, 'Applied'))
    add('old_unknown_is_immutable', old_unknown and original['effect'] is not None)
    add('new_handle_cannot_adopt_old_attempt', b.get('stopped') == 'foreign_context_rejected'
        and not a.get('handle_open', True) and b.get('handle_open') and old_unknown)
    add('foreign_local_evidence_rejected', b.get('stopped') in ('foreign_frames_rejected', 'foreign_image_rejected'))
    add('original_lineage_read_remains_usable', outcome(a) == 'Read'
        and b.get('stopped') in ('foreign_frames_rejected', 'foreign_image_rejected'))
    add('latch_before_final_check_denies_permit', client('final_check') and a['stopped'] == 'publication_latched'
        and latched(h1) and a['candidate'] is not None and a['permit'] is None)
    if client('send_head'):
        prior = before['actors']['a']
        add('latch_after_final_check_allows_original_dispatch', latched(before['lineages']['H1'])
            and prior['permit'] is not None and a['cas'] is not None and a['stopped'] is None)
    if client('observe') and latched(before['lineages'].get('H1', {})):
        add('inflight_cas_known_after_latch', observation(original, 'Applied') and a['known_commit'] == a['cas'])
        add('inflight_cas_conflict_after_latch', observation(original, 'Conflict'))
        add('inflight_cas_unknown_after_latch', observation(original, 'Unknown'))
    add('latch_does_not_revoke_original_ack', client('ack') and outcome(a) == 'Ack' and latched(h1))
    add('known_commit_native_failure_preserves_receipt', outcome(a) == 'CommittedUnavailable'
        and a['native'] == 'commit_failed' and observation(original, 'Applied') and latched(h1))
    add('historical_success_survives_later_events', event['kind'] == 'client' and event.get('actor') == 'a'
        and event['op'] in ('stop_local', 'detach') and outcome(before['actors']['a']) in ('Read', 'Ack')
        and a['outcome'] == before['actors']['a']['outcome'] and latched(h1))
    add('typed_semantic_failure_is_not_expiry', profile['group'] == 'K15' and failed(a, 'semantic')
        and a['failure'].get('reason') == 'typed_edge_semantic')
    add('semantic_detection_is_per_lineage', failed(a, 'semantic') and failed(b, 'semantic')
        and a['failure']['token'] != b['failure']['token'] and h1.get('semantic')
        and after['lineages'].get('H2', {}).get('semantic'))
    add('semantic_latch_survives_physical_retirement', a.get('stopped') == 'semantic_failure_cannot_expire'
        and failed(a, 'semantic') and permanent(current, 1) and h1.get('semantic'))
    add('same_content_new_generation_is_still_invalid', failed(a, 'semantic') and failed(b, 'semantic')
        and b['context']['generation'] == 2 and a['context']['roots'] == b['context']['roots'])
    add('independent_lookup_proves_old_unknown_commit', old_unknown and effect(original, 'Applied') and outcome(b) == 'Lookup'
        and b['outcome']['receipt'] == spec['frames']['R1']['hash'] and b['native'] is None)
    add('lookup_does_not_replay_native', outcome(b) == 'Lookup' and b['native'] is None
        and profile['actors']['b']['lineage'] != 'H1')
    add('stopped_permit_cannot_dispatch', client('send_head') and a['stopped'] == 'local_gate_closed'
        and before['actors']['a']['permit'] is not None and a['cas'] is None)
    if event['kind'] == 'network':
        token = after['tokens'][event['token']]
        stopped = before['actors'][token['actor']]['local_stop']
        if token['request']['method'] == 'HEAD_CAS' and stopped:
            add('stopped_dispatched_cas_still_applies', effect(token, 'Applied'))
            add('stopped_dispatched_cas_still_discards', event['delivery'] == 'discard')
            add('stopped_unknown_token_not_rewritten', observation(token, 'Unknown')
                and token['observation'] == before['tokens'][event['token']]['observation'])
    add('stopped_original_public_ack_is_withheld', client('ack') and before['actors']['a']['local_stop']
        and outcome(a) == 'Withheld')
    add('stopped_known_durable_native_commit', client('native_publish') and before['actors']['a']['local_stop']
        and a['known_commit'] is not None and a['native'] == 'committed')
    add('stopped_known_durable_native_failure', client('native_publish') and before['actors']['a']['local_stop']
        and a['known_commit'] is not None and a['native'] == 'commit_failed')
    return result & set(profile['required_witnesses'])
