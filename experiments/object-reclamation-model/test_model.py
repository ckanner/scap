"""Harness/boundary regressions; full interleaving evidence is a separate gate."""

import ast
from collections import deque
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import controls
import model
import oracle
import run as producer


ROOT = Path(__file__).resolve().parent
INPUTS = oracle.validate_inputs((ROOT / 'inputs.json').read_bytes())


def profile(prefix):
    return next(value for value in INPUTS['profiles'] if value['name'].startswith(prefix + '_'))


def find_edge(prefix, predicate):
    definition = profile(prefix); reducer = model.Model(INPUTS, definition)
    queue = deque([definition['initial']]); seen = {model.digest(definition['initial'])}
    while queue:
        before = queue.popleft()
        for action in reducer.actions(before):
            after = reducer.successor(before, action)
            if predicate(before, action, after):
                oracle.Rules(INPUTS, definition).edge(before, action, after)
                return before, action, after
            key = model.digest(after)
            if key not in seen:
                if len(seen) >= 5000: raise AssertionError('focused unit search incomplete')
                seen.add(key); queue.append(after)
    raise AssertionError('required focused boundary was not reachable')


class FrozenInputsTests(unittest.TestCase):
    def test_explicit_profile_program_and_object_denominators(self):
        self.assertEqual(len(INPUTS['profiles']), 26)
        self.assertEqual(sum(len(program) for item in INPUTS['profiles'] for program in item['programs'].values()), 629)
        self.assertEqual(len(INPUTS['objects']), 8)
        self.assertEqual(len({value['name'] for value in INPUTS['profiles']}), 26)

    def test_changing_any_protocol_bound_requires_a_new_input_freeze(self):
        changed = copy.deepcopy(INPUTS); changed['bounds']['pins'] += 1
        with self.assertRaisesRegex(ValueError, 'frozen actor programs'):
            oracle.validate_inputs(oracle.canonical(changed))

    def test_receipt_data_root_is_identity_not_an_implicit_copy_edge(self):
        rules = oracle.Rules(INPUTS, profile('08'))
        self.assertEqual(rules.reachable_objects(['data0', 'index0']), {'data0', 'page0', 'index0', 'result0'})
        result = oracle.parse(bytes.fromhex(INPUTS['objects']['result0']['raw']).split(b'\n', 1)[1])
        self.assertEqual(result['receipt_data_root'], '0' * 64)
        self.assertNotIn(result['receipt_data_root'], {value['hash'] for value in INPUTS['objects'].values()})

    def test_equal_decoded_objects_do_not_replace_exact_raw_bytes(self):
        raw = bytes.fromhex(INPUTS['objects']['result0']['raw'])
        normalized = b'SCAP-MODEL-OBJECT-1\n' + oracle.canonical(oracle.parse(raw.split(b'\n', 1)[1]))
        self.assertNotEqual(raw, normalized)
        self.assertNotEqual(oracle.sha(raw), oracle.sha(normalized))

    def test_head_tag_repeats_when_body_repeats_and_serial_prevents_aba(self):
        initial = copy.deepcopy(profile('01')['initial']['head'])
        changed = copy.deepcopy(initial); changed['pins'] = [{'test': 'temporary'}]
        changed['pins'] = []
        self.assertEqual(model.digest(initial), model.digest(changed))
        changed['serial'] += 2
        self.assertNotEqual(model.digest(initial), model.digest(changed))
        self.assertEqual(model.digest(initial), oracle.body_tag(initial))

    def test_oracle_imports_no_reducer_runner_or_production_modules(self):
        tree = ast.parse((ROOT / 'oracle.py').read_text())
        imports = {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports |= {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse(imports & {'model', 'run', 'scap', 'controls'})
        self.assertTrue(imports <= {'argparse', 'copy', 'gzip', 'hashlib', 'json', 'pathlib', 're', 'tarfile'})


class ProtocolBoundaryTests(unittest.TestCase):
    def test_metadata_pin_add_does_not_read_an_object_or_manufacture_a_snapshot(self):
        definition = profile('03'); reducer = model.Model(INPUTS, definition)
        initial = definition['initial']
        observed = reducer.successor(initial, {'actor': 'p', 'choice': 'step'})
        issued = reducer.successor(observed, {'actor': 'p', 'choice': 'step'})
        self.assertEqual(issued['actors']['p']['view'], observed['actors']['p']['view'])
        self.assertEqual(len(issued['tokens']), 1)
        self.assertEqual(next(iter(issued['tokens'].values()))['kind'], 'head_cas')
        self.assertEqual(issued['objects'], initial['objects'])
        self.assertEqual(issued['brokers']['b']['guards'], [])

    def test_caller_timeout_does_not_destroy_a_live_native_guard(self):
        definition = profile('04'); before = definition['initial']
        action = {'actor': 'p', 'choice': 'step'}
        after = model.Model(INPUTS, definition).successor(before, action)
        self.assertTrue(after['actors']['p']['caller_unknown'])
        self.assertEqual(after['brokers'], before['brokers'])
        self.assertEqual(after['head'], before['head'])
        oracle.Rules(INPUTS, definition).edge(before, action, after)

    def test_refused_serial_allocation_rolls_back_all_client_side_effects(self):
        definition = profile('15'); reducer = model.Model(INPUTS, definition)
        before = reducer.successor(definition['initial'], {'actor': 'p', 'choice': 'step'})
        after = reducer.successor(before, {'actor': 'p', 'choice': 'step'})
        self.assertEqual(after['actors']['p']['stopped'], 'SERIAL_EXHAUSTED')
        self.assertEqual(after['brokers'], before['brokers'])
        self.assertEqual(after['tokens'], before['tokens'])
        self.assertEqual(after['head'], before['head'])

    def test_unknown_add_absence_at_unchanged_serial_remains_pending(self):
        before, action, after = find_edge('02', lambda b, a, c: c['brokers']['b']['phase'] == 'pending_absent')
        self.assertEqual(after['head']['serial'], after['brokers']['b']['base_serial'])
        forged = copy.deepcopy(after); forged['brokers']['b'].update(phase='released', gate=False)
        with self.assertRaisesRegex(ValueError, 'client protocol delta changed: inspect_pin'):
            oracle.Rules(INPUTS, profile('02')).edge(before, action, forged)

    def test_new_plan_capture_cannot_keep_previous_target_verification(self):
        before, action, after = find_edge('22', lambda b, a, c: a.get('actor') == 'g' and
            c['actors']['g']['plan'] is not None and c['actors']['g']['plan']['target'] == 3 and
            b['actors']['g']['plan'] is not None and b['actors']['g']['plan']['target'] == 2)
        self.assertTrue(before['actors']['g']['copy_verified'])
        self.assertEqual(after['actors']['g']['copy_verified'], [])
        self.assertEqual(after['actors']['g']['copied'], {})

    def test_late_old_plan_verification_cannot_repopulate_new_plan(self):
        before, action, after = find_edge('23', lambda b, a, c: c['actors']['copy']['stopped'] == 'STALE_COPY_RESPONSE')
        self.assertEqual(after['actors']['copy']['plan']['target'], 3)
        self.assertEqual(after['actors']['copy']['copy_verified'], [])
        token = before['tokens'][before['actors']['copy']['last_token']]
        self.assertEqual(token['request']['generation'], 2)

    def test_native_failure_preserves_durable_reference_and_withholds_ack(self):
        before, action, after = find_edge('06', lambda b, a, c: c['actors']['w']['native'] == 'failed_after_commit' and c['actors']['w']['ack'] == 'WITHHELD')
        local = after['actors']['w']; reference = local['commit_reference']
        self.assertEqual(local['completion'], 'COMMITTED_BUT_UNAVAILABLE')
        self.assertEqual(after['tokens'][reference['token']]['response']['outcome'], 'APPLIED')
        self.assertEqual(after['head']['roots'], ['data1', 'index1'])

    def test_reader_materialization_uses_observed_original_raw_frames(self):
        before, action, after = find_edge('25', lambda b, a, c: c['actors']['timeout']['materialized'] is not None and c['actors']['timeout']['read_result'] == {'outcome': 'WITHHELD'})
        local = after['actors']['timeout']
        self.assertTrue(local['caller_unknown'])
        self.assertEqual(len(local['materialized']['frames']), 4)
        self.assertTrue(local['ended'])

    def test_ended_worker_does_not_accept_late_original_get(self):
        before, action, after = find_edge('26', lambda b, a, c: c['actors']['p']['stopped'] == 'LATE_READ_RESPONSE')
        self.assertTrue(after['actors']['p']['ended'])
        self.assertIsNone(after['actors']['p']['materialized'])
        self.assertEqual(after['actors']['p']['verified'], [])

    def backend_identity(self, kind):
        definition = profile('12'); before = copy.deepcopy(definition['initial'])
        request = {'generation': 1, 'object': 'page0', 'key': INPUTS['objects']['data0']['hash'],
                   'etag': INPUTS['objects']['page0']['hash'], 'purpose': 'delete_candidate'}
        before['tokens']['probe'] = {'actor': 's', 'kind': kind, 'request': request, 'uncertain': False,
                                    'stage': 'pending', 'response': None, 'observed': None}
        # Deliberately invalid client token, passed only to the isolated backend
        # relation: the store must use key, not the diagnostic object label.
        after = copy.deepcopy(before); model.Model(INPUTS, definition).network(after, 'probe', 'apply')
        expected = oracle.Rules(INPUTS, definition).network_relation(before, {'network': 'probe', 'choice': 'apply'})
        self.assertEqual(after, expected)
        self.assertEqual(after['tokens']['probe']['response'], {'outcome': 'MISSING'})
        self.assertEqual(after['objects'], before['objects'])

    def test_backend_get_uses_original_key_not_diagnostic_object_label(self):
        self.backend_identity('object_get')

    def test_backend_delete_uses_original_key_not_diagnostic_object_label(self):
        self.backend_identity('object_delete')


class EvidenceHarnessTests(unittest.TestCase):
    def test_resource_cap_is_explicitly_incomplete(self):
        limited = copy.deepcopy(INPUTS); limited['execution_limits']['states_per_profile'] = 1
        with tempfile.TemporaryDirectory() as temp:
            result = producer.explore(limited, profile('15'), Path(temp) / 'limited')
            self.assertFalse(result['complete'])
            self.assertEqual(result['status'], 'INCOMPLETE')
            self.assertEqual(result['reason'], 'STATE_RESOURCE_LIMIT')
            self.assertEqual(result['expanded_states'], 0)

    def test_time_cap_crossed_in_final_expansion_is_still_a_failed_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(producer.time, 'monotonic', side_effect=[0, 0, 0, 0, 121]):
                result = producer.explore(INPUTS, profile('16'), Path(temp) / 'late-completion')
            self.assertFalse(result['complete'])
            self.assertEqual(result['reason'], 'ELAPSED_RESOURCE_LIMIT')
            self.assertEqual(result['expanded_states'], result['states'])
            self.assertEqual(result['elapsed_seconds'], 121)

    def test_controls_have_fixed_protocol_and_graph_denominators(self):
        self.assertEqual(len(controls.cases()), 39)
        self.assertEqual(len(set(controls.cases())), 39)
        for name, (prefix, predicate, mutate, reason) in controls.cases().items():
            self.assertTrue(name and prefix and callable(predicate) and callable(mutate) and reason)

    def test_mutation_replacement_does_not_truncate_hardlinked_original(self):
        with tempfile.TemporaryDirectory() as temp:
            original, target = Path(temp) / 'original', Path(temp) / 'copy'
            original.write_bytes(b'original'); os.link(original, target)
            controls.save(target, b'mutated')
            self.assertEqual(original.read_bytes(), b'original')
            self.assertEqual(target.read_bytes(), b'mutated')

    def test_nested_boolean_does_not_equal_integer_and_duplicate_json_is_rejected(self):
        with self.assertRaises(ValueError): oracle.same({'serial': True}, {'serial': 1}, 'typed identity')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON field'): oracle.parse(b'{"x":1,"x":1}')


if __name__ == '__main__':
    unittest.main()
