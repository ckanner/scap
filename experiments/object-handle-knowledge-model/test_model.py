"""Focused concrete paths and oracle boundaries. This is not full BFS evidence."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

import model
from controls import (falsely_reject_closure_get, falsely_reject_freeze, falsely_reject_held_read,
                      falsely_reject_retired_removal, rebind_technical_generation,
                      reject_failure_probe, rejected_freeze_recaptures_context,
                      rejected_hold_grants_current_context, rejected_nonmember_dispatches_get,
                      rejected_removal_changes_foreign_authority,
                      rejected_removal_deletes_live_object, replace_management_verb,
                      replace_technical_verb)
from oracle_protocol import Violation, authority_slot, edge_checks, justified_rejection, state_checks
from run import select_profiles


HERE = Path(__file__).resolve().parent
SPEC = json.loads((HERE / 'inputs.json').read_text())
PROFILES = {profile['id']: profile for profile in SPEC['profiles']}


class Trace:
    def __init__(self, identifier):
        self.profile = PROFILES[identifier]
        self.state = copy.deepcopy(self.profile['initial'])
        self.steps = []
        state_checks(self.state, SPEC, self.profile)

    def act(self, event):
        before = self.state
        after = model.transition(before, SPEC, self.profile, event)
        edge_checks(before, after, SPEC, self.profile, event)
        state_checks(after, SPEC, self.profile)
        self.steps.append((before, event, after))
        self.state = after

    def delivery(self, identifier, kind='apply'):
        self.act({'kind': 'network', 'token': identifier, 'delivery': kind})

    def step(self, who, *, choice=None, auto_delivery=True):
        actor = self.state['actors'][who]
        instruction = self.profile['actors'][who]['program'][actor['pc']]
        choices = [event for event in model.choices(self.state, self.profile)
                   if event['kind'] == 'client' and event['actor'] == who]
        if instruction['op'] == 'observe' and auto_delivery and actor['last']:
            token = self.state['tokens'][actor['last']]
            if token['effect'] is None and choice != 'unknown':
                self.delivery(actor['last'])
                choices = [event for event in model.choices(self.state, self.profile)
                           if event['kind'] == 'client' and event['actor'] == who]
        if choice is not None:
            choices = [event for event in choices if event['choice'] == choice]
        self.assert_choices(choices, who, instruction)
        self.act(choices[0])

    @staticmethod
    def assert_choices(choices, who, instruction):
        if not choices:
            raise AssertionError('fixture requested disabled step: ' + who + ' ' + str(instruction))

    def until_mark(self, who, marker):
        while not self.state['actors'][who]['marks'].get(marker):
            self.step(who)

    def until_op(self, who, operation):
        while self.profile['actors'][who]['program'][self.state['actors'][who]['pc']]['op'] != operation:
            self.step(who)

    def finish(self, who):
        program = self.profile['actors'][who]['program']
        while self.state['actors'][who]['stopped'] is None and self.state['actors'][who]['pc'] < len(program):
            self.step(who)

    def fault_then_probe(self):
        self.until_mark('a', 'admitted')
        self.until_mark('f', 'faulted')
        self.until_mark('a', 'failed')


class KnowledgeTests(unittest.TestCase):
    def test_expanded_inventory_keeps_original_program_objects_and_declared_bounds(self):
        history = json.loads((HERE / 'program-history.json').read_text())
        self.assertEqual(hashlib.sha256((HERE / 'inputs.json').read_bytes()).hexdigest(),
                         history['expanded_programs']['inputs_sha256'])
        self.assertEqual(SPEC['expanded_counts'], {'profiles': 46, 'steps': 1899,
                                                  'mandatory_witnesses': 119, 'maximum_actor_steps': 52})
        for original in history['original_programs']['profiles']:
            self.assertEqual(model.digest(PROFILES[original['id']]), original['sha256'])
        for profile in PROFILES.values():
            self.assertLessEqual(len(profile['actors']), SPEC['bounds']['actors'])
            self.assertTrue(all(len(actor['program']) <= SPEC['bounds']['steps_per_actor']
                                for actor in profile['actors'].values()))

    def test_same_lineage_complete_new_read_preserves_latch_and_blocks_new_management(self):
        trace = Trace('K01_missing_takeover')
        trace.fault_then_probe()
        trace.until_mark('f', 'restored')
        incident = copy.deepcopy(trace.state['lineages']['H1'])
        trace.finish('b')
        self.assertEqual(trace.state['actors']['b']['outcome']['kind'], 'Read')
        self.assertEqual(trace.state['lineages']['H1'], incident)
        trace.finish('c')
        self.assertEqual(trace.state['actors']['c']['stopped'], 'publication_latched')

    def test_same_worker_new_lineage_complete_read_does_not_clear_original_incident(self):
        trace = Trace('K02_hash')
        trace.fault_then_probe()
        trace.until_mark('f', 'restored')
        original = copy.deepcopy(trace.state['lineages']['H1'])
        trace.finish('b')
        self.assertEqual(trace.state['actors']['b']['outcome']['kind'], 'Read')
        self.assertEqual(trace.state['lineages']['H1'], original)
        self.assertFalse(trace.state['lineages']['H2']['physical'])

    def test_persistent_bad_source_requires_independent_second_failure(self):
        trace = Trace('K04_missing')
        trace.fault_then_probe()
        trace.until_mark('f', 'ready')
        trace.finish('b')
        a, b = (trace.state['actors'][who] for who in ('a', 'b'))
        self.assertEqual(a['failure']['classification'], 'unresolved')
        self.assertEqual(b['failure']['classification'], 'corrupt')
        self.assertNotEqual(a['failure']['token'], b['failure']['token'])

    def test_held_source_has_legal_history_and_cannot_expire_after_promotion(self):
        trace = Trace('K06_held_missing')
        trace.until_mark('m', 'held')
        head = next(iter(trace.state['world']['heads']['D0'].values()))
        self.assertEqual((head['A'], head['hold']['generation']), (2, 1))
        trace.until_mark('a', 'admitted')
        trace.until_mark('m', 'faulted')
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Corrupt')

    def test_bad_original_domain_probe_never_grants_expiry_or_a_rebase_view(self):
        for kind in ('wrong_scope', 'malformed'):
            with self.subTest(kind=kind):
                trace = Trace('K09_probe_' + kind)
                trace.until_mark('a', 'admitted')
                original_view = copy.deepcopy(trace.state['actors']['a']['view'])
                trace.until_mark('m', 'faulted')
                trace.finish('a')
                actor = trace.state['actors']['a']
                self.assertEqual(actor['outcome']['kind'], 'AuthorityUnavailable')
                self.assertEqual(actor['view'], original_view)
                self.assertTrue(trace.state['lineages']['H1']['authority'])
                self.assertFalse(trace.state['lineages']['H2']['authority'])

    def test_latch_before_final_check_blocks_but_after_check_does_not_revoke_original_permit(self):
        for late in (False, True):
            with self.subTest(late=late):
                trace = Trace('K12_takeover')
                trace.until_mark('a', 'prepared')
                if late:
                    trace.until_mark('a', 'checked')
                trace.until_mark('b', 'admitted')
                trace.until_mark('f', 'faulted')
                trace.until_mark('b', 'failed')
                trace.finish('a')
                actor = trace.state['actors']['a']
                self.assertEqual(actor['outcome']['kind'], 'Ack' if late else 'Rejected')
                self.assertEqual(actor['stopped'], None if late else 'publication_latched')

    def test_stop_after_permit_prevents_each_new_publication_dispatch(self):
        for verb in ('writer', 'takeover', 'policy'):
            with self.subTest(verb=verb):
                trace = Trace('K17_before_dispatch_' + verb)
                trace.finish('a')
                actor = trace.state['actors']['a']
                self.assertEqual(actor['stopped'], 'local_gate_closed')
                self.assertIsNotNone(actor['permit'])
                self.assertFalse(any(token['request']['method'] == 'HEAD_CAS' for token in trace.state['tokens'].values()))

    def test_unknown_original_conditional_still_delivers_after_stop_and_handle_close(self):
        for verb in ('writer', 'takeover', 'policy'):
            with self.subTest(verb=verb):
                trace = Trace('K17_after_dispatch_' + verb)
                trace.until_op('a', 'stop_local')
                trace.step('a')
                original = trace.state['actors']['a']['cas']
                trace.step('a', choice='unknown', auto_delivery=False)
                trace.finish('a')
                self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Withheld')
                self.assertFalse(trace.state['actors']['a']['handle_open'])
                trace.delivery(original)
                self.assertEqual(trace.state['tokens'][original]['observation'], {'kind': 'Unknown'})
                self.assertEqual(trace.state['tokens'][original]['effect']['kind'], 'Applied')
                self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Withheld')

    def test_abstract_known_durable_native_finish_is_separate_from_closed_public_exit(self):
        for choice, expected in [('commit', 'committed'), ('fail', 'commit_failed')]:
            with self.subTest(choice=choice):
                trace = Trace('K17_after_dispatch_writer')
                trace.until_op('a', 'stop_local')
                trace.step('a')
                trace.step('a')  # Original CAS delivers and is observed while local gate is closed.
                trace.step('a', choice=choice)
                self.assertEqual(trace.state['actors']['a']['native'], expected)
                trace.finish('a')
                self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Withheld')

    def test_foreign_local_image_is_rejected_without_harming_original_read(self):
        trace = Trace('K11_image')
        trace.until_mark('a', 'ready')
        trace.finish('b')
        self.assertEqual(trace.state['actors']['b']['stopped'], 'foreign_image_rejected')
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Read')

    def test_new_lookup_proves_receipt_without_adopting_unknown_or_executing_native(self):
        trace = Trace('K16_independent_lookup')
        trace.until_op('a', 'send_head')
        trace.step('a')
        original = trace.state['actors']['a']['cas']
        trace.step('a', choice='unknown', auto_delivery=False)
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Unknown')
        trace.delivery(original)
        trace.finish('b')
        self.assertEqual(trace.state['actors']['b']['outcome']['kind'], 'Lookup')
        self.assertIsNone(trace.state['actors']['b']['native'])
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Unknown')
        actual = {token['request']['hash'] for token in trace.state['tokens'].values()
                  if token['actor'] == 'b' and token['request']['method'] == 'GET'}
        self.assertEqual(actual, {SPEC['frames']['I1']['hash'], SPEC['frames']['R1']['hash']})

    def test_history_success_is_not_retroactively_revoked_by_latch_stop_or_detach(self):
        trace = Trace('K14_takeover')
        trace.until_mark('a', 'answered')
        original = copy.deepcopy(trace.state['actors']['a']['outcome'])
        trace.until_mark('b', 'admitted')
        trace.until_mark('f', 'faulted')
        trace.until_mark('b', 'failed')
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome'], original)
        self.assertTrue(trace.state['actors']['a']['local_stop'])
        self.assertTrue(trace.state['actors']['a']['detached'])

    def test_oracle_rejects_nonfixture_fault_mutation_and_knowledge_injection(self):
        trace = Trace('K02_missing')
        trace.step('a')
        before, event, honest = trace.steps[-1]
        changed = copy.deepcopy(honest)
        changed['world']['head_fault']['D0'] = 'unavailable'
        with self.assertRaisesRegex(Violation, 'nonfixture'):
            edge_checks(before, changed, SPEC, trace.profile, event)
        changed = copy.deepcopy(honest)
        changed['lineages']['H2']['authority'] = True
        with self.assertRaisesRegex(Violation, 'crossed knowledge'):
            edge_checks(before, changed, SPEC, trace.profile, event)


    def test_bare_technical_send_defaults_to_known_response_without_changing_program(self):
        trace = Trace('K05_retired_missing')
        trace.until_mark('a', 'admitted')
        trace.until_op('m', 'send_head')
        command = trace.profile['actors']['m']['program'][trace.state['actors']['m']['pc']]
        self.assertNotIn('uncertain', command)
        trace.step('m')
        identifier = trace.state['actors']['m']['cas']
        self.assertIs(trace.state['tokens'][identifier]['request']['uncertain'], False)
        self.assertFalse(any(event.get('actor') == 'm' and event.get('choice') == 'unknown'
                             for event in model.choices(trace.state, trace.profile)))
        trace.step('m')
        self.assertEqual(trace.state['actors']['m']['known_commit'], identifier)

    def test_oracle_binds_valid_alternative_constructors_to_original_command(self):
        management = Trace('K12_takeover')
        management.until_op('a', 'prepare_manage')
        management.step('a')
        technical = Trace('K05_retired_missing')
        technical.until_mark('a', 'admitted')
        technical.until_op('m', 'prepare_tech')
        technical.step('m')
        for trace, mutation in [(management, replace_management_verb), (technical, replace_technical_verb)]:
            with self.subTest(profile=trace.profile['id']):
                before, event, honest = trace.steps[-1]
                changed = copy.deepcopy(honest)
                mutation(before, event, changed, SPEC, trace.profile)
                with self.assertRaisesRegex(Violation, 'constructor kind differs from original operation'):
                    edge_checks(before, changed, SPEC, trace.profile, event)

    def test_technical_capture_is_exact_even_when_candidate_generation_moves_with_it(self):
        trace = Trace('K05_retired_missing')
        trace.until_mark('a', 'admitted')
        trace.until_op('m', 'prepare_tech')
        trace.step('m')
        before, event, honest = trace.steps[-1]
        changed = copy.deepcopy(honest)
        rebind_technical_generation(before, event, changed, SPEC, trace.profile)
        with self.assertRaisesRegex(Violation, 'technical context differs from original fresh authority'):
            edge_checks(before, changed, SPEC, trace.profile, event)
        for field, value in [('mode', 'copy'), ('plan', None),
                             ('roots', {'data': SPEC['frames']['M1']['hash'], 'index': SPEC['frames']['I1']['hash']})]:
            with self.subTest(field=field):
                changed = copy.deepcopy(honest)
                changed['actors']['m']['context'][field] = value
                with self.assertRaisesRegex(Violation, 'technical context differs from original fresh authority'):
                    edge_checks(before, changed, SPEC, trace.profile, event)

    def test_failure_does_not_allow_oracle_to_remove_a_legal_probe_edge(self):
        trace = Trace('K05_retired_missing')
        trace.until_mark('a', 'admitted')
        trace.until_mark('m', 'retired')
        trace.until_op('a', 'probe')
        trace.step('a')
        before, event, honest = trace.steps[-1]
        self.assertEqual(before['actors']['a']['failure']['kind'], 'physical')
        self.assertEqual(len(set(honest['tokens']) - set(before['tokens'])), 1)
        changed = copy.deepcopy(honest)
        reject_failure_probe(before, event, changed, SPEC, trace.profile)
        with self.assertRaisesRegex(Violation, 'failed-attempt rejection outside ordinary guard'):
            edge_checks(before, changed, SPEC, trace.profile, event)

    def test_profile_selection_rejects_duplicate_or_unknown_without_starting_exploration(self):
        identifier = SPEC['profiles'][0]['id']
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            select_profiles(SPEC, [identifier, identifier])
        with self.assertRaisesRegex(ValueError, 'unknown'):
            select_profiles(SPEC, ['NOT_A_PROFILE'])
        self.assertEqual(select_profiles(SPEC, [identifier]), [SPEC['profiles'][0]])
        self.assertEqual(select_profiles(SPEC, []), SPEC['profiles'])

    @staticmethod
    def materialized_remove_trace(delivery):
        trace = Trace('K05_materialized_return')
        trace.until_mark('a', 'materialized')
        trace.until_op('m', 'send_head')
        trace.step('m')
        original = trace.state['actors']['m']['cas']
        trace.delivery(original, delivery)
        trace.step('m', choice='known', auto_delivery=False)
        trace.step('m')
        return trace

    def test_nonapplied_promotion_rejects_live_removal_without_any_fixture_effect(self):
        trace = self.materialized_remove_trace('discard')
        before, event, after = trace.steps[-1]
        self.assertEqual(event['op'], 'remove_retired')
        self.assertEqual(before['world']['heads']['D0'][authority_slot(SPEC['scope'])]['A'], 1)
        self.assertEqual(after['actors']['m']['stopped'], 'fixture_remove_live_generation')
        self.assertEqual(before['tokens'][before['actors']['m']['cas']]['effect'],
                         {'kind': 'Unavailable', 'delivered': False})
        self.assertEqual(before['world'], after['world'])
        self.assertEqual(before['tokens'], after['tokens'])
        self.assertEqual(before['lineages'], after['lineages'])
        self.assertNotIn('retired', after['actors']['m']['marks'])

    def test_applied_promotion_keeps_retired_remove_and_original_materialized_return(self):
        trace = self.materialized_remove_trace('apply')
        before, event, after = trace.steps[-1]
        self.assertIsNone(after['actors']['m']['stopped'])
        self.assertEqual(before['world']['heads']['D0'][authority_slot(SPEC['scope'])]['A'], 2)
        self.assertEqual(len(set(before['world']['objects']['D0']) - set(after['world']['objects']['D0'])), 1)
        original = copy.deepcopy(after['actors']['a']['materialized'])
        trace.finish('m')
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Read')
        self.assertEqual(trace.state['actors']['a']['materialized'], original)

    def test_oracle_cannot_use_foreign_live_authority_to_reject_retired_original_generation(self):
        trace = self.freeze_after_abort_trace('K06_aborted_target', 'apply')
        trace.until_op('m', 'remove_retired')
        trace.step('m')
        before, event, honest = trace.steps[-1]
        key = authority_slot(SPEC['scope'])
        command = trace.profile['actors']['m']['program'][event['pc']]
        self.assertEqual(command, {'op': 'remove_retired', 'generation': 2, 'name': 'M0'})
        original, foreign = (before['world']['heads'][domain][key] for domain in ('D0', 'D1'))
        self.assertEqual((original['A'], original['M'], original['plan']['target']), (1, 3, 3))
        self.assertIsNone(original['hold'])
        self.assertEqual(foreign['A'], command['generation'])
        self.assertIsNone(honest['actors']['m']['stopped'])
        for token, purpose, view in (('m:6', 'abort_plan', 'm:2'), ('m:12', 'freeze', 'm:8')):
            self.assertEqual(before['tokens'][token]['request']['purpose'], purpose)
            self.assertEqual(before['tokens'][token]['request']['etag'], before['tokens'][view]['observation']['etag'])
            self.assertEqual(before['tokens'][token]['observation']['kind'], 'Applied')
        changed = copy.deepcopy(honest)
        falsely_reject_retired_removal(before, event, changed, SPEC, trace.profile)
        with self.assertRaisesRegex(Violation, 'fixture rejected already retired generation'):
            edge_checks(before, changed, SPEC, trace.profile, event)

    def test_rejected_fixture_cannot_remove_live_bytes_or_change_another_authority(self):
        trace = self.materialized_remove_trace('discard')
        before, event, honest = trace.steps[-1]
        for mutation in (rejected_removal_deletes_live_object, rejected_removal_changes_foreign_authority):
            with self.subTest(mutation=mutation.__name__):
                changed = copy.deepcopy(honest)
                mutation(before, event, changed, SPEC, trace.profile)
                with self.assertRaisesRegex(Violation, 'fixture rejection changed backend state'):
                    edge_checks(before, changed, SPEC, trace.profile, event)

    def test_rejected_fixture_requires_declared_role_and_valid_original_scope_authority(self):
        trace = self.materialized_remove_trace('discard')
        before, event, honest = trace.steps[-1]
        wrong_role = copy.deepcopy(trace.profile)
        wrong_role['actors']['m']['role'] = 'client'
        with self.assertRaisesRegex(Violation, 'fixture rejection lacks original fixture command'):
            justified_rejection(before, honest, SPEC, wrong_role, event)
        key = authority_slot(SPEC['scope'])
        for mutation in ('missing_authority', 'wrong_scope'):
            with self.subTest(mutation=mutation):
                bad_before, bad_after = copy.deepcopy(before), copy.deepcopy(honest)
                for state in (bad_before, bad_after):
                    if mutation == 'missing_authority':
                        del state['world']['heads']['D0'][key]
                    else:
                        state['world']['heads']['D0'][key]['scope'] = copy.deepcopy(SPEC['foreign_scope'])
                with self.assertRaisesRegex(Violation, 'fixture rejection lacks valid original authority'):
                    justified_rejection(bad_before, bad_after, SPEC, trace.profile, event)

    def test_fixture_rejection_rule_itself_preserves_original_tokens_and_lineage_knowledge(self):
        trace = self.materialized_remove_trace('discard')
        before, event, honest = trace.steps[-1]
        changed = copy.deepcopy(honest)
        changed['tokens'][before['actors']['m']['cas']]['observation'] = {'kind': 'Unknown'}
        with self.assertRaisesRegex(Violation, 'fixture rejection changed original tokens'):
            justified_rejection(before, changed, SPEC, trace.profile, event)
        changed = copy.deepcopy(honest)
        changed['lineages']['H2']['authority'] = True
        with self.assertRaisesRegex(Violation, 'fixture rejection changed knowledge'):
            justified_rejection(before, changed, SPEC, trace.profile, event)


    @staticmethod
    def freeze_after_abort_trace(identifier, delivery):
        trace = Trace(identifier)
        trace.until_mark('a', 'captured')
        trace.until_op('m', 'send_head')
        trace.step('m')
        trace.delivery(trace.state['actors']['m']['cas'], delivery)
        trace.step('m', choice='known', auto_delivery=False)
        trace.until_op('m', 'prepare_tech')
        trace.step('m')
        return trace

    @staticmethod
    def retained_admission_trace(identifier, hold_delivery, promote_delivery):
        trace = Trace(identifier)
        trace.until_op('m', 'send_head')
        trace.step('m')
        trace.delivery(trace.state['actors']['m']['cas'], hold_delivery)
        trace.step('m', choice='known', auto_delivery=False)
        trace.until_op('m', 'send_head')
        trace.step('m')
        trace.delivery(trace.state['actors']['m']['cas'], promote_delivery)
        trace.step('m', choice='known', auto_delivery=False)
        trace.until_mark('m', 'held')
        trace.until_op('a', 'admit')
        trace.step('a')
        return trace

    @staticmethod
    def writer_then_explicit_get_trace(delivery):
        trace = Trace('K14_writer')
        trace.until_op('a', 'send_head')
        trace.step('a')
        trace.delivery(trace.state['actors']['a']['cas'], delivery)
        trace.step('a', choice='known', auto_delivery=False)
        trace.step('a', choice='commit' if delivery == 'apply' else 'abort')
        trace.step('a')
        trace.until_mark('a', 'answered')
        trace.until_mark('b', 'admitted')
        trace.until_mark('f', 'faulted')
        trace.until_op('b', 'get')
        trace.step('b')
        return trace


    def test_nonapplied_abort_rejects_freeze_against_its_new_original_view(self):
        for identifier in ('K06_aborted_target', 'K07_active_source'):
            with self.subTest(profile=identifier):
                trace = self.freeze_after_abort_trace(identifier, 'discard')
                before, event, after = trace.steps[-1]
                actor = before['actors']['m']
                self.assertEqual((event['op'], event['pc']), ('prepare_tech', 10))
                self.assertEqual(actor['view_token'], 'm:8')
                self.assertEqual(actor['context']['view_token'], 'm:2')
                self.assertEqual(actor['view']['head']['plan']['id'], 'P0')
                self.assertEqual(before['tokens']['m:6']['observation'],
                                 {'kind': 'Unavailable', 'delivered': False})
                self.assertEqual(after['actors']['m']['stopped'], 'freeze_not_available')
                for field in ('world', 'tokens', 'lineages'):
                    self.assertEqual(before[field], after[field])
                self.assertEqual(actor['context'], after['actors']['m']['context'])

    def test_applied_abort_keeps_freeze_enabled_despite_older_context_plan(self):
        trace = self.freeze_after_abort_trace('K06_aborted_target', 'apply')
        before, event, honest = trace.steps[-1]
        self.assertIsNotNone(before['actors']['m']['context']['head']['plan'])
        self.assertIsNone(before['actors']['m']['view']['head']['plan'])
        self.assertEqual(honest['actors']['m']['candidate']['kind'], 'freeze')
        self.assertEqual(honest['actors']['m']['context']['view_token'], 'm:8')
        changed = copy.deepcopy(honest)
        falsely_reject_freeze(before, event, changed, SPEC, trace.profile)
        with self.assertRaisesRegex(Violation, 'freeze rejection lacks original occupied plan'):
            edge_checks(before, changed, SPEC, trace.profile, event)

    def test_nonapplied_hold_is_absent_from_original_retained_admission_in_both_promotion_outcomes(self):
        for identifier in ('K06_held_missing', 'K06_held_hash'):
            for delivery in ('apply', 'discard'):
                with self.subTest(profile=identifier, promotion=delivery):
                    trace = self.retained_admission_trace(identifier, 'discard', delivery)
                    before, event, after = trace.steps[-1]
                    original = before['actors']['a']
                    self.assertEqual(original['view_token'], 'a:2')
                    self.assertIsNone(original['view']['head']['hold'])
                    self.assertEqual(original['view']['head']['A'], 2 if delivery == 'apply' else 1)
                    self.assertEqual(before['tokens']['m:5']['observation'],
                                     {'kind': 'Unavailable', 'delivered': False})
                    self.assertEqual(after['actors']['a']['stopped'], 'no_retained_hold')
                    self.assertIsNone(after['actors']['a']['context'])
                    for field in ('world', 'tokens', 'lineages'):
                        self.assertEqual(before[field], after[field])

    def test_observed_hold_keeps_retained_read_and_later_source_failure_valid(self):
        trace = self.retained_admission_trace('K06_held_missing', 'apply', 'apply')
        before, event, honest = trace.steps[-1]
        self.assertEqual(before['actors']['a']['view']['head']['hold']['generation'], 1)
        self.assertIsNone(before['world']['heads']['D1'][authority_slot(SPEC['scope'])]['hold'])
        self.assertEqual(honest['actors']['a']['context']['generation'], 1)
        changed = copy.deepcopy(honest)
        falsely_reject_held_read(before, event, changed, SPEC, trace.profile)
        with self.assertRaisesRegex(Violation, 'retained rejection ignored original observed hold'):
            edge_checks(before, changed, SPEC, trace.profile, event)
        trace.until_mark('a', 'admitted')
        trace.until_mark('m', 'faulted')
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Corrupt')
        self.assertEqual(trace.state['actors']['a']['failure']['kind'], 'physical')


    def test_unapplied_writer_rejects_only_nonmember_before_any_get_or_failure(self):
        trace = self.writer_then_explicit_get_trace('discard')
        before, event, after = trace.steps[-1]
        original = before['actors']['b']
        self.assertEqual(original['context']['view_token'], 'b:2')
        self.assertEqual(original['context']['roots'],
                         {'data': SPEC['frames']['M0']['hash'], 'index': SPEC['frames']['I0']['hash']})
        self.assertEqual(original['frames'], {})
        self.assertEqual(after['actors']['b']['stopped'], 'get_not_in_original_closure')
        self.assertEqual(after['actors']['a']['outcome']['kind'], 'Unknown')
        self.assertIsNone(after['actors']['b']['failure'])
        for field in ('world', 'tokens', 'lineages'):
            self.assertEqual(before[field], after[field])
        self.assertNotIn('b:7', after['tokens'])

    def test_applied_writer_keeps_authorized_get_missing_and_historical_ack(self):
        trace = self.writer_then_explicit_get_trace('apply')
        before, event, honest = trace.steps[-1]
        self.assertEqual(before['actors']['b']['context']['roots']['data'], SPEC['frames']['M1']['hash'])
        self.assertEqual(honest['tokens']['b:7']['request']['hash'], SPEC['frames']['M1']['hash'])
        changed = copy.deepcopy(honest)
        falsely_reject_closure_get(before, event, changed, SPEC, trace.profile)
        with self.assertRaisesRegex(Violation, 'closure rejection names an authorized original dependency'):
            edge_checks(before, changed, SPEC, trace.profile, event)
        trace.finish('b')
        self.assertEqual(trace.state['tokens']['b:7']['observation']['kind'], 'NoSuchKey')
        self.assertEqual(trace.state['actors']['b']['failure']['kind'], 'physical')
        self.assertEqual(trace.state['actors']['b']['failure']['token'], 'b:7')
        self.assertIn('1', trace.state['lineages']['H1']['physical'])
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Ack')
        trace.finish('a')
        self.assertEqual(trace.state['actors']['a']['outcome']['kind'], 'Ack')

    def test_rejected_guards_cannot_recapture_grant_or_dispatch(self):
        cases = (
            (self.freeze_after_abort_trace('K06_aborted_target', 'discard'),
             rejected_freeze_recaptures_context, 'guard rejection changed original attempt'),
            (self.retained_admission_trace('K06_held_missing', 'discard', 'apply'),
             rejected_hold_grants_current_context, 'guard rejection changed original attempt'),
            (self.writer_then_explicit_get_trace('discard'),
             rejected_nonmember_dispatches_get, 'guard rejection changed original tokens'),
        )
        for trace, mutation, boundary in cases:
            with self.subTest(mutation=mutation.__name__):
                before, event, honest = trace.steps[-1]
                changed = copy.deepcopy(honest)
                mutation(before, event, changed, SPEC, trace.profile)
                with self.assertRaisesRegex(Violation, boundary):
                    edge_checks(before, changed, SPEC, trace.profile, event)


    def test_new_guard_rules_bind_own_authority_scope_command_role_and_permission(self):
        traces = (
            self.freeze_after_abort_trace('K06_aborted_target', 'discard'),
            self.retained_admission_trace('K06_held_missing', 'discard', 'apply'),
            self.writer_then_explicit_get_trace('discard'),
        )
        for trace in traces:
            before, event, honest = trace.steps[-1]
            who = event['actor']
            original = before['actors'][who]
            token_id = (original['context']['view_token'] if event['op'] == 'get'
                        else original['view_token'])
            for changed_field, changed_value in (('domain', 'D1'), ('scope', SPEC['foreign_scope'])):
                with self.subTest(reason=honest['actors'][who]['stopped'], identity=changed_field):
                    bad_before, bad_after = copy.deepcopy(before), copy.deepcopy(honest)
                    for state in (bad_before, bad_after):
                        state['tokens'][token_id]['request'][changed_field] = copy.deepcopy(changed_value)
                    with self.assertRaisesRegex(Violation, 'guard rejection borrowed another authority'):
                        justified_rejection(bad_before, bad_after, SPEC, trace.profile, event)
            other_token = next(identifier for identifier, token in before['tokens'].items()
                               if token['actor'] != who and token['request']['method'] == 'HEAD_GET'
                               and token['request']['purpose'] == 'admit'
                               and token['observation'] and token['observation']['kind'] == 'Found')
            bad_before, bad_after = copy.deepcopy(before), copy.deepcopy(honest)
            for state in (bad_before, bad_after):
                holder = state['actors'][who]['context'] if event['op'] == 'get' else state['actors'][who]
                holder['view_token'] = other_token
            with self.assertRaisesRegex(Violation, 'authority token not original actor'):
                justified_rejection(bad_before, bad_after, SPEC, trace.profile, event)
            denied = copy.deepcopy(trace.profile)
            denied['actors'][who]['principal'] = 999
            with self.assertRaisesRegex(Violation, 'admission guard|read permission|authorized roots'):
                justified_rejection(before, honest, SPEC, denied, event)
            wrong_role = copy.deepcopy(trace.profile)
            wrong_role['actors'][who]['role'] = ('client' if wrong_role['actors'][who]['role'] == 'fixture'
                                                else 'fixture')
            with self.assertRaisesRegex(Violation, 'changed original'):
                justified_rejection(before, honest, SPEC, wrong_role, event)
            different = copy.deepcopy(trace.profile)
            command = different['actors'][who]['program'][event['pc']]
            if event['op'] == 'prepare_tech':
                command['kind'] = 'abort_plan'
            elif event['op'] == 'admit':
                command['retained'] = False
            else:
                command['purpose'] = 'readback'
            with self.assertRaisesRegex(Violation, 'changed original'):
                justified_rejection(before, honest, SPEC, different, event)

    def test_new_guard_rules_preserve_all_backend_tokens_and_knowledge(self):
        traces = (
            self.freeze_after_abort_trace('K06_aborted_target', 'discard'),
            self.retained_admission_trace('K06_held_missing', 'discard', 'apply'),
            self.writer_then_explicit_get_trace('discard'),
        )
        for trace in traces:
            before, event, honest = trace.steps[-1]
            who = event['actor']
            for changed_field in ('world', 'tokens', 'lineages'):
                with self.subTest(reason=honest['actors'][who]['stopped'], changed=changed_field):
                    changed = copy.deepcopy(honest)
                    if changed_field == 'world':
                        changed['world']['heads']['D1'][authority_slot(SPEC['scope'])]['serial'] += 1
                        boundary = 'guard rejection changed backend state'
                    elif changed_field == 'tokens':
                        changed['tokens'][next(iter(changed['tokens']))]['observation'] = {'kind': 'Unknown'}
                        boundary = 'guard rejection changed original tokens'
                    else:
                        changed['lineages'][trace.profile['actors'][who]['lineage']]['authority'] = True
                        boundary = 'guard rejection changed knowledge'
                    with self.assertRaisesRegex(Violation, boundary):
                        justified_rejection(before, changed, SPEC, trace.profile, event)

    def test_guard_evidence_does_not_read_a_later_global_head(self):
        # Isolated oracle-source tests, not added reachable-profile claims:
        # a later backend HEAD cannot rewrite an already observed guard basis.
        traces = (
            self.freeze_after_abort_trace('K06_aborted_target', 'discard'),
            self.retained_admission_trace('K06_held_missing', 'discard', 'apply'),
            self.writer_then_explicit_get_trace('discard'),
        )
        for trace in traces:
            before, event, honest = trace.steps[-1]
            changed_before, changed_after = copy.deepcopy(before), copy.deepcopy(honest)
            for state in (changed_before, changed_after):
                head = state['world']['heads']['D0'][authority_slot(SPEC['scope'])]
                head['serial'] += 1
                if event['op'] == 'prepare_tech':
                    head['plan'] = None
                elif event['op'] == 'admit':
                    head['hold'] = {'id': 'HOLD-LATER', 'scope': copy.deepcopy(SPEC['scope']),
                                    'generation': head['A'],
                                    'roots': {'data': head['data'], 'index': head['index']}}
                else:
                    head['data'], head['index'] = SPEC['frames']['M1']['hash'], SPEC['frames']['I1']['hash']
                    head['revision'] += 1
                    head['sequence'] += 1
            justified_rejection(changed_before, changed_after, SPEC, trace.profile, event)


if __name__ == '__main__':
    unittest.main()
