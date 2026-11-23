"""Synthetic input and import-binding checks, never actual service evidence."""
import copy
from pathlib import Path
import subprocess
import sys
import unittest

import shared
import spec


class ContractTests(unittest.TestCase):
    def test_matrix_is_cap_abba_with_both_arms_enabled(self):
        plan = spec.matrix_plan()
        self.assertEqual((plan['measured_inserts'], plan['seed_inserts'], plan['schema_executions']),
                         (5632, 2048, 8))
        self.assertEqual([cell['max_members'] for cell in plan['cells']], [8, 4, 4, 8] * 2)
        self.assertEqual([cell['rate'] for cell in plan['cells']], [12] * 4 + [32] * 4)
        self.assertTrue(all(cell['group_commit'] is True for cell in plan['cells']))
        self.assertEqual([cell['name'] for cell in plan['cells']], [
            f'rate-{rate}-{name}' for rate in (12, 32)
            for name in ('cap8-1', 'cap4-1', 'cap4-2', 'cap8-2')])
        for cell in plan['cells']:
            contract = spec.CONTRACTS[cell['rate'], cell['max_members']]
            self.assertEqual(cell['contract'], contract.name)
            self.assertEqual(plan['contracts'][contract.name], contract.plan)
        self.assertIs(plan['automatic_rerun'], False)

    def test_original_workload_and_limits_are_identical(self):
        for rate in spec.RATES:
            original = spec._equal.CONTRACTS[rate]
            for cap in spec.CAPS:
                contract = spec.CONTRACTS[rate, cap]
                self.assertEqual(spec.calls(contract), spec._equal.calls(original))
                plan = copy.deepcopy(contract.plan)
                plan.pop('max_members')
                plan['name'] = original.plan['name']
                plan['profile'] = original.name
                plan['group_profile']['max_members'] = 8
                self.assertEqual(plan, original.plan)
        for name in ('BOUNDS', 'DEADLINES', 'PROCESS_LIMITS', 'ADMISSION', 'TRANSPORT', 'OUTPUT'):
            self.assertEqual(getattr(spec, name), getattr(spec._equal, name))

    def test_only_service_configuration_difference_is_member_cap(self):
        for rate in spec.RATES:
            inputs = ('127.0.0.1:1234', Path('/private/cache'), 'http://127.0.0.1:1235', 'a' * 64)
            configs = [spec.configuration(*inputs, True, spec.CONTRACTS[rate, cap], 'b' * 64)
                       for cap in spec.CAPS]
            original = spec._equal.configuration(*inputs, True, spec._equal.CONTRACTS[rate], 'b' * 64)
            self.assertEqual(configs[0], original)
            self.assertEqual(configs[1]['admission']['group_commit']['max_members'], 4)
            configs[1]['admission']['group_commit']['max_members'] = 8
            self.assertEqual(configs[1], configs[0])
        self.assertEqual(spec._equal.PROFILE['max_members'], 8)
        self.assertEqual(spec._equal._original.PROFILE['max_members'], 8)

    def test_unfrozen_inputs_and_disabled_arm_are_rejected(self):
        for rate in (True, 4, 16, 32.0, '32'):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                spec.Contract(rate, 4)
        for cap in (True, False, 0, 1, 5, 16, 4.0, '4'):
            for operation in (lambda: spec.Contract(12, cap),
                              lambda: shared.reader(cap), lambda: shared.auditor(cap)):
                with self.subTest(cap=cap), self.assertRaises(ValueError):
                    operation()
        for enabled in (False, None, 1, 'true'):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                spec.configuration('a', 'b', 'c', 'd' * 64, enabled, spec.SHORT, 'e' * 64)
        with self.assertRaises(ValueError):
            spec.configuration('a', 'b', 'c', 'd' * 64, True, spec._equal.SHORT, 'e' * 64)
        with self.assertRaises(ValueError):
            spec.configuration('a', 'b', 'c', 'd' * 64, True)


class BindingTests(unittest.TestCase):
    def test_independent_reader_and_auditor_keep_their_cap(self):
        for cap in (4, 8, 4, 8):
            reader, auditor = shared.reader(cap), shared.auditor(cap)
            self.assertIs(auditor.base, reader)
            self.assertEqual(reader.spec.PROFILE['max_members'], cap)
            self.assertEqual(auditor.spec.SHORT.max_members, cap)
            self.assertEqual({value.max_members for value in auditor.spec.CONTRACTS.values()}, {cap})
            self.assertIs(auditor.spec, reader.spec)
            self.assertIs(auditor.lifecycle, shared.lifecycle)
        self.assertIsNot(shared.reader(4).spec, shared.reader(8).spec)
        self.assertIsNot(shared.reader(4).spec.PROFILE, shared.reader(8).spec.PROFILE)
        self.assertIs(sys.modules['spec'], spec)
        self.assertIs(sys.modules['shared'], shared)

    def test_audit_import_does_not_import_runtime(self):
        command = ('import sys, shared; '
                   'assert all("group_width_cap" not in name or not name.endswith("_runner") '
                   'for name in sys.modules); '
                   'assert shared._runtimes is None; '
                   'assert shared.auditor(4).base is shared.reader(4)')
        result = subprocess.run([sys.executable, '-B', '-c', command], cwd=shared.HERE,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_reuses_original_cells_with_static_cap_specs(self):
        import run
        self.assertIs(run.RUNTIMES, shared.runtimes())
        for cap, runtime in run.RUNTIMES.items():
            self.assertEqual(Path(runtime.Cell.__init__.__code__.co_filename).resolve(),
                             shared.ROOT / 'experiments/equal-seed-load/run.py')
            self.assertEqual(runtime.Cell.__init__.__globals__['spec'].PROFILE['max_members'], cap)
            self.assertIs(runtime.spec, shared.reader(cap).spec)
            self.assertEqual({contract.max_members for contract in runtime.spec.CONTRACTS.values()}, {cap})
            self.assertIs(runtime.observer, shared.observer)
            self.assertEqual(runtime.shared.HERE, shared.HERE)
        self.assertIs(sys.modules['spec'], spec)
        self.assertIs(sys.modules['shared'], shared)

    def test_fixture_inventory_covers_transitive_sources(self):
        files = shared.fixture_files()
        self.assertEqual(files, sorted(set(files)))
        names = {path.relative_to(shared.ROOT).as_posix() for path in files}
        for name in ('experiments/equal-seed-load/run.py', 'experiments/equal-seed-load/probe.mjs',
                     'experiments/equal-seed-load/record.mjs', 'experiments/equal-seed-load/oracle.py',
                     'experiments/equal-seed-load/observer.py', 'experiments/equal-seed-load/lifecycle.py',
                     'experiments/group-commit-load/record.mjs', 'experiments/group-commit-load/oracle.py',
                     'experiments/object-load/launcher.py', 'experiments/object-network/build_evidence.py',
                     'docs/architecture/group-width-comparison.md'):
            self.assertIn(name, names)
        self.assertEqual((shared.HERE / 'probe.mjs').read_text().splitlines()[-1],
                         "import '../equal-seed-load/probe.mjs';")

    def test_sibling_import_names_restore_after_failure(self):
        before = sys.modules['spec']
        with self.assertRaisesRegex(ValueError, 'intentional'):
            with shared.siblings(spec=shared.reader(4).spec, group_width_missing_test=None):
                self.assertIs(sys.modules['spec'], shared.reader(4).spec)
                raise ValueError('intentional')
        self.assertIs(sys.modules['spec'], before)
        self.assertNotIn('group_width_missing_test', sys.modules)


if __name__ == '__main__':
    unittest.main()
