import ast
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import cases
import counterexamples
import explore
from model import World, encoded, plan_input, control_key
from oracle import audit, parse_descriptor, parse_head, parse_proof, Violation


class ProtocolTests(unittest.TestCase):
    def test_fixed_scenario_families(self):
        passed = 0
        for case in cases.cases():
            if case.family in explore.EXPECTED_FAMILIES and not case.name.endswith('000-lost0'):
                continue
            with self.subTest(case=case.name):
                observed = audit(case.build().trace(case.name), strict_scenario=True)
                self.assertEqual(observed['status'], 'PASSED')
                passed += 1
        self.assertEqual(passed, 94)

    def test_all_semantic_negative_boundaries(self):
        for control in counterexamples.negatives():
            with self.subTest(control=control.name):
                with self.assertRaises(Violation) as rejected:
                    audit(control.build())
                self.assertEqual(rejected.exception.rule, control.rule)

    def test_complete_declared_interleaving_counts(self):
        four = ('admit', 'invoke', 'effect', 'respond')
        five = ('admit', 'recover', 'invoke', 'effect', 'respond')
        for left, right, count in ((four, four, 70), (five, five, 252), (five, four, 126)):
            histories = list(cases.schedule(left, right))
            self.assertEqual(len(histories), count)
            self.assertEqual(len(set(histories)), count)
            for history in histories:
                self.assertEqual(tuple(action for side, action in history if side == 'left'), left)
                self.assertEqual(tuple(action for side, action in history if side == 'right'), right)

    def test_exact_registered_denominators(self):
        counts = explore.check_inventory(cases.cases(), counterexamples.negatives())
        self.assertEqual(sum(counts.values()), 987)
        self.assertEqual(counts['preparelost'], 8)
        self.assertEqual(counts['damage'], 7)

    def test_same_operation_wrong_hash_is_corrupt_only_after_a_stable_final_head(self):
        for changed in (False, True):
            world = cases.owner_binding_fault(changed)
            observed = [row for row in world.calls.values() if row.operation == 'inspect']
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0].outcome, {'kind': 'error',
                'value': {'code': 'CONFLICT' if changed else 'CORRUPT'}})
            audit(world.trace(f'damage-owner-binding-{int(changed)}'), strict_scenario=True)

    def test_oracle_does_not_import_candidate_or_runner(self):
        parsed = ast.parse((Path(__file__).parent / 'oracle.py').read_text())
        imported = set()
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                imported.update(item.name.split('.')[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split('.')[0])
        self.assertTrue(imported.isdisjoint({'model', 'cases', 'counterexamples', 'explore'}))

    def test_oracle_standalone_isolated_interpreter(self):
        world, _reference = cases.active()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'history.json'
            path.write_text(json.dumps(world.trace('standalone')))
            process = subprocess.run([sys.executable, '-I', str(Path(__file__).parent / 'oracle.py'), str(path)],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)['status'], 'PASSED')

    def test_controller_summary_has_no_authority(self):
        original = cases.proof_history(False, 'claim').trace('proof-0-claim')
        expected = audit(original, strict_scenario=True)
        modified = deepcopy(original)
        modified['summary'] = {'owner': 'forged', 'calls': 0, 'status': 'FAILED'}
        self.assertEqual(audit(modified, strict_scenario=True), expected)
        del modified['summary']
        self.assertEqual(audit(modified, strict_scenario=True), expected)

    def test_schedule_name_cannot_claim_a_different_order(self):
        case = cases.cases()[0]
        value = case.build().trace(case.name)
        value['name'] = 'claim_cancel-001-lost0'
        with self.assertRaises(Violation) as rejected:
            audit(value, strict_scenario=True)
        self.assertEqual(rejected.exception.rule, 'planned-macro-schedule')

    def test_server_exit_does_not_revoke_invocation(self):
        world = World()
        reference = cases.prepared(world)
        identifier = world.begin('claim', {'identity': reference})
        world.admit(identifier)
        io = world.invoke(identifier)
        world.crash('worker-2')
        self.assertIsNone(world.exchanges[io].result)
        self.assertEqual(world.effect(io), 200)
        world.respond(io)
        self.assertEqual(world.head()['owner_plan']['phase']['kind'], 'claimed')
        audit(world.trace('late-storage-effect'))

    def test_hashless_mutations_reject_before_descriptor_io(self):
        world = World()
        reference = cases.prepared(world)
        for operation in ('claim', 'resume', 'abort'):
            identifier = world.request(operation, {'identity': {'creator': reference['creator'], 'operation': reference['operation']}})
            cases.result(world, identifier, code='INVALID')
            self.assertFalse([event for event in world.events if event.get('call') == identifier and
                              event['event'].startswith('s3_')])
        audit(world.trace('hashless'))

    def test_restored_input_must_match_actual_record(self):
        world = cases.lost_prepare_restore('accepted', False)
        observation = next(name for name, call in world.calls.items() if call.operation == 'inspect')
        altered = plan_input(target=3)
        from model import Rejected
        with self.assertRaises(Rejected):
            world.restore_ref(altered, observation)
        audit(world.trace('restore-mismatch'))

    def test_input_digest_scope_and_distinct_nonces(self):
        world = World()
        cases.prepared(world)
        body = json.loads(world.objects[control_key('descriptor', 11, 101)]['body'])
        for mutation, rule in (
            (lambda value: value['nonces'].update(cancel=value['nonces']['claim']), 'distinct-nonces'),
            (lambda value: value.update(extra=1), 'strict-schema'),
            (lambda value: value.update(base=None), 'strict-schema'),
            (lambda value: value['base'].update(etag='not-quoted'), 'opaque-etag'),
            (lambda value: value['scope'].update(incarnation=2), 'full-scope'),
            (lambda value: value.update(input_digest='0' * 64), 'descriptor-input-digest'),
        ):
            with self.subTest(rule=rule):
                changed = deepcopy(body)
                mutation(changed)
                with self.assertRaises(Violation) as rejected:
                    parse_descriptor(encoded(changed), 15)
                self.assertEqual(rejected.exception.rule, rule)

    def test_head8_nonnull_and_legacy_field_absence(self):
        world, _ref = cases.active()
        value = world.head()
        for mutation in (lambda head: head.update(owner_plan=None),
                         lambda head: head.pop('owner_plan'),
                         lambda head: head.update(format=6)):
            changed = deepcopy(value)
            mutation(changed)
            with self.assertRaises(Violation):
                parse_head(encoded(changed), 15)

    def test_terminal_marker_owner_is_historical(self):
        world = cases.historical_deleted()
        head = world.head()
        self.assertGreater(head['owner']['epoch'], head['owner_plan']['phase']['owner']['epoch'])
        parsed = parse_head(encoded(head), 15)
        self.assertEqual(parsed, head)
        proof = parse_proof(world.objects[control_key('proof', 11, 101)]['body'], 15)
        self.assertEqual(proof['marker'], head['owner_plan'])

    def test_size_limits_are_checked_before_normalization(self):
        world = World()
        cases.prepared(world)
        raw = world.objects[control_key('descriptor', 11, 101)]['body']
        with self.assertRaises(Violation) as rejected:
            parse_descriptor(raw + ' ' * 16384, 15)
        self.assertEqual(rejected.exception.rule, 'wire-size')

    def test_output_directory_is_never_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'evidence'
            writer = explore.Output(directory)
            receipt = writer.save('failure.json', {'kept': True})
            with self.assertRaises(FileExistsError):
                explore.Output(directory)
            self.assertEqual((directory / receipt['file']).read_text().strip(), '{"kept":true}')

    def test_evidence_files_are_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = explore.Output(Path(temporary) / 'evidence')
            output.save('trace.json', {'first': True})
            with self.assertRaises(FileExistsError):
                output.save('trace.json', {'later': True})


if __name__ == '__main__':
    unittest.main()
