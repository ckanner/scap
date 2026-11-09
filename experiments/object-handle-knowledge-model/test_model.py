"""Focused concrete paths and oracle boundaries. This is not full BFS evidence."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

import model
from controls import (rebind_technical_generation, reject_failure_probe,
                      replace_management_verb, replace_technical_verb)
from oracle_protocol import Violation, edge_checks, state_checks
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


if __name__ == '__main__':
    unittest.main()
