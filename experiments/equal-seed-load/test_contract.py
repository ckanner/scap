"""Synthetic parser/contract controls. These are never actual service evidence."""
import copy
import errno
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import lifecycle
import observer
import oracle
import spec


def synthetic_snapshot(data=0, control=0, recovery=0):
    def distribution(count, complete=True):
        return {'completed': str(count if complete else 0), 'censored': '0',
                'not_reached': str(0 if complete else count), 'total_us': str(count * 5 if complete else 0),
                'buckets': [str(count if complete else 0)] + ['0'] * 18}
    lanes = []
    for name in spec.LANES:
        count = {'data': data, 'control': control, 'recovery': recovery}.get(name, 0)
        lanes.append({'lane': name, 'acquired': str(count), 'released': str(count), 'active': '0',
                      'intervals': [{'interval': interval, **distribution(count)} for interval in spec.INTERVALS]})
    return {'version': 1, 'valid': True, 'unit': 'microseconds',
            'histogram_upper_bounds_us': [str(value) for value in spec.BUCKETS_US], 'lanes': lanes,
            'groups': {**{name: '0' for name in ('attempts', 'active', 'selected', 'consumed',
                                               'declined', 'completed', 'incomplete')},
                       'duration': distribution(0), 'selected_sizes': ['0'] * 64, 'consumed_sizes': ['0'] * 64}}


class ContractTests(unittest.TestCase):
    def test_fixed_counts_and_original_profiles(self):
        plan = spec.matrix_plan()
        self.assertEqual((plan['measured_inserts'], plan['seed_inserts'], len(plan['cells'])), (5632, 2048, 8))
        self.assertEqual([row['group_commit'] for row in plan['cells']], [False, True, True, False] * 2)
        for rate, contract in spec.CONTRACTS.items():
            calls = spec.calls(contract)
            executes = [row for row in calls if row['operation'] == 'execute']
            self.assertEqual(len(executes), 257 + 32 * rate)
            self.assertEqual([int(row['request_id']) for row in executes], list(range(1, len(executes) + 1)))
            controls = [row for row in calls if row['operation'] == 'status' and row['phase'] == 'load']
            self.assertEqual([row['offset_ns'] for row in controls], [index * 4_000_000_000 for index in range(8)])
            self.assertEqual(contract.image_pages, 128)
        self.assertEqual(list(spec._original.CONTRACTS), ['short-v1', 'admission-curve-v1'])
        self.assertEqual(spec._original.ADMISSION['data_intake'], 80)
        self.assertEqual(4 * spec.CONTRACTS[32].retained_entries + 15, spec.BOUNDS['http_posts'])

    def test_no_unfrozen_rate_or_shared_diagnostic_credential_default(self):
        for value in (True, 4, 16, 32.0, '32'):
            with self.assertRaises(ValueError):
                spec.Contract(value)
        with self.assertRaises(ValueError):
            spec.configuration('x', 'y', 'z', 'a' * 64, False)

    def test_binary_result_geometry(self):
        import struct
        columns = (b'id', b'payload', b'witness')
        raw = b'SCAPRES1' + struct.pack('<II', 1, 3)
        raw += b''.join(struct.pack('<I', len(value)) + value for value in columns)
        raw += struct.pack('<I', 1)
        # Independent wire tags are taken from the protocol reader, not product
        # encoder logic; length arithmetic does not need to choose their values.
        row_size = (1 + 8) + (1 + 4 + 256) + (1 + 8)
        self.assertEqual(len(raw) + row_size + 16, 343)
        self.assertEqual(36 + 1280 * 343, 439076)
        self.assertEqual(64 + 1280 * row_size, 357184)


class LifecycleTests(unittest.TestCase):
    def reject(self, rule, value):
        with self.assertRaises(lifecycle.Invalid) as caught:
            lifecycle.parse(value)
        self.assertEqual(caught.exception.rule, rule)

    def test_positive_parse_and_delta(self):
        before = lifecycle.parse(synthetic_snapshot(256, 4))
        after = lifecycle.parse(synthetic_snapshot(640, 12))
        expected = dict.fromkeys(spec.LANES, 0)
        expected.update(data=384, control=8)
        delta = lifecycle.cohort(before, after, expected)
        self.assertEqual(delta['lanes']['data']['intervals']['body']['completed'], 384)
        self.assertEqual(delta['lanes']['control']['released'], 8)

    def test_strict_shapes_canonical_integers_and_bounds(self):
        for bad in ('00', '+1', '-1', '1.0', 1, True, str(1 << 64), '١'):
            with self.subTest(bad=bad):
                value = synthetic_snapshot()
                value['lanes'][0]['acquired'] = bad
                self.reject('lifecycle-integer', value)
        for key, value, rule in (
            ('valid', False, 'lifecycle-invalid'), ('version', True, 'lifecycle-version'),
            ('unit', 'nanoseconds', 'lifecycle-version'), ('lanes', [], 'lifecycle-lanes'),
            ('histogram_upper_bounds_us', ['1'], 'lifecycle-bounds')):
            changed = synthetic_snapshot()
            changed[key] = value
            self.reject(rule, changed)
        changed = synthetic_snapshot()
        changed['tenant'] = '7'
        self.reject('lifecycle-shape', changed)

    def test_conservation_and_duration(self):
        changed = synthetic_snapshot(1)
        changed['lanes'][0]['active'] = '1'
        self.reject('lifecycle-lane-conservation', changed)
        changed = synthetic_snapshot(1)
        changed['lanes'][0]['intervals'][0]['not_reached'] = '1'
        self.reject('lifecycle-interval-conservation', changed)
        changed = synthetic_snapshot(1)
        changed['lanes'][0]['intervals'][0]['buckets'][0] = '0'
        self.reject('lifecycle-histogram-denominator', changed)
        changed = synthetic_snapshot(1)
        changed['lanes'][0]['intervals'][0]['total_us'] = '101'
        self.reject('lifecycle-duration-range', changed)

    def test_group_completed_declined_and_incomplete(self):
        value = synthetic_snapshot()
        group = value['groups']
        group.update(attempts='3', selected='12', consumed='4', completed='1', declined='1', incomplete='1')
        group['selected_sizes'][3] = '3'
        group['consumed_sizes'][3] = '1'
        group['duration'].update(completed='2', censored='1', total_us='10')
        group['duration']['buckets'][0] = '2'
        self.assertEqual(lifecycle.parse(value)['groups']['consumed'], 4)
        changed = copy.deepcopy(value)
        changed['groups']['consumed_sizes'][3] = '2'
        self.reject('lifecycle-group-sizes', changed)
        changed = copy.deepcopy(value)
        changed['groups']['duration']['not_reached'] = '1'
        self.reject('lifecycle-group-duration', changed)

    def test_quiescence_and_regression(self):
        before = lifecycle.parse(synthetic_snapshot(1))
        after = lifecycle.parse(synthetic_snapshot(2))
        wrong = dict.fromkeys(spec.LANES, 0)
        with self.assertRaisesRegex(lifecycle.Invalid, 'lifecycle-cohort-denominator'):
            lifecycle.cohort(before, after, wrong)
        with self.assertRaisesRegex(lifecycle.Invalid, 'lifecycle-counter-regression'):
            lifecycle.cohort(after, before, wrong)
        active = synthetic_snapshot(2)
        active['lanes'][0].update(acquired='3', active='1')
        with self.assertRaisesRegex(lifecycle.Invalid, 'lifecycle-nonquiescent'):
            lifecycle.cohort(before, lifecycle.parse(active), wrong)

    def test_total_hold_and_missing_success_hook_cannot_hide_in_not_reached(self):
        before = lifecycle.parse(synthetic_snapshot())
        expected = dict.fromkeys(spec.LANES, 0)
        expected['data'] = 1
        for interval, rule in ((7, 'lifecycle-total-hold-complete'), (0, 'lifecycle-success-interval-complete')):
            changed = synthetic_snapshot(1)
            item = changed['lanes'][0]['intervals'][interval]
            item.update(completed='0', not_reached='1', total_us='0', buckets=['0'] * 19)
            after = lifecycle.parse(changed)
            with self.assertRaises((lifecycle.Invalid, oracle.Rejected)) as caught:
                delta = lifecycle.cohort(before, after, expected)
                oracle.complete_intervals(delta, {'load-0': {'phase': 'load', 'operation': 'execute'}},
                    {'load-0': {'finish': {'ok': True}, 'reply': {'ok': True}}})
            self.assertEqual(caught.exception.rule, rule)

    def test_absolute_seed_cohort_cannot_be_removed_from_both_snapshots(self):
        planned = {row['id']: row for row in spec.calls(spec.CONTRACTS[12])}
        calls = {key: {'finish': {'ok': True}, 'reply': {'ok': True}} for key in planned}
        valid = lifecycle.parse(synthetic_snapshot(258, 4, 1))
        self.assertEqual(oracle.seed_baseline(valid, planned, calls),
                         {'data': 258, 'control': 4, 'recovery': 1, 'catalogue': 0, 'restore': 0})
        before = lifecycle.parse(synthetic_snapshot(257, 4, 1))
        after = lifecycle.parse(synthetic_snapshot(257 + 384, 12, 1))
        expected = dict.fromkeys(spec.LANES, 0)
        expected.update(data=384, control=8)
        lifecycle.cohort(before, after, expected)
        with self.assertRaisesRegex(oracle.Rejected, 'lifecycle-seed-cohort-denominator'):
            oracle.seed_baseline(before, planned, calls)

    def test_every_diagnostic_poll_obeys_its_boundary_and_eight_get_budget(self):
        original = [{'boundary': 'baseline', 'request_ns': 10, 'response_ns': 11},
                    {'boundary': 'end', 'request_ns': 30, 'response_ns': 31}]
        oracle.diagnostic_windows(original, 9, 20, 29, 40)
        wrong = copy.deepcopy(original)
        wrong[0].update(request_ns=21, response_ns=22)
        with self.assertRaisesRegex(oracle.Rejected, 'diagnostic-poll-window'):
            oracle.diagnostic_windows(wrong, 9, 20, 29, 40)
        excessive = [dict(original[0])] * 9 + [original[1]]
        with self.assertRaisesRegex(oracle.Rejected, 'diagnostic-boundary-budget'):
            oracle.diagnostic_windows(excessive, 9, 20, 29, 40)


class GeometryAndEnvelopeTests(unittest.TestCase):
    def test_eight_cell_order_and_live_process_denominator(self):
        good = [(10 * index + 1, 10 * index + 2) for index in range(8)]
        oracle.validate_round_order(good)
        for bad in (good[:4], [good[3], *good[1:3], good[0], *good[4:]]):
            with self.assertRaisesRegex(oracle.Rejected, 'round-run-order'):
                oracle.validate_round_order(bad)
        starts = {7: {'monotonic_ns': 1}}
        ends = {7: {'monotonic_ns': 9}}
        sample = {'monotonic_ns': 2, 'locked_ns': 3, 'completed_ns': 7, 'processes': [
            {'role': 'observer', 'started_ns': 3, 'completed_ns': 4},
            {'role': 'backend', 'identity': {'pid': 7}, 'started_ns': 5, 'completed_ns': 6}]}
        oracle.process_presence(sample, starts, ends)
        for removed in (0, 1):
            changed = copy.deepcopy(sample)
            del changed['processes'][removed]
            with self.assertRaisesRegex(oracle.Rejected, 'resource-live-process-denominator'):
                oracle.process_presence(changed, starts, ends)
        rows = [{'event': event, 'identity': {'pid': pid}} for pid in range(9)
                for event in ('envelope_process_started', 'envelope_process_reaped')]
        oracle.owned_inventory(rows)
        with self.assertRaisesRegex(oracle.Rejected, 'resource-process-denominator'):
            oracle.owned_inventory([*rows, rows[0]])
        changed = copy.deepcopy(rows)
        changed[2]['identity']['pid'] = 0
        with self.assertRaisesRegex(oracle.Rejected, 'resource-process-denominator'):
            oracle.owned_inventory(changed)

    def test_backend_order_uses_spawn_to_reap_not_readiness(self):
        with tempfile.TemporaryDirectory(prefix='equal-seed-unit-') as directory:
            root = Path(directory)
            for index, cell in enumerate(spec.cells()):
                path = root / cell['name']
                path.mkdir()
                events = []
                for process in range(4):
                    events += [
                        {'event': 'envelope_process_started', 'role': 'backend',
                         'spawn_requested_ns': index * 100 + process + 1},
                        {'event': 'envelope_process_reaped', 'role': 'backend',
                         'monotonic_ns': index * 100 + 90 + process}]
                events += [{'event': 'backend_started', 'monotonic_ns': index * 100 + 10},
                           {'event': 'backend_stopped', 'monotonic_ns': index * 100 + 95}]
                (path / 'events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in events))
            oracle.validate_round_order(oracle.round_boundaries(root))
            path = root / spec.cells()[1]['name'] / 'events.jsonl'
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows[0]['spawn_requested_ns'] = 50
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.assertRaisesRegex(oracle.Rejected, 'round-run-order'):
                oracle.validate_round_order(oracle.round_boundaries(root))

    def test_exit_race_requires_same_owned_identity_and_zombie(self):
        descriptor = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
        try:
            stat = observer.resources.read_at(descriptor, 'stat')
            identity = observer.resources.stat_identity(stat)
        finally:
            os.close(descriptor)
        tail = stat.rfind(')') + 2
        zombie = stat[:tail] + 'Z' + stat[tail + 1:]
        with mock.patch.object(observer.resources, 'read_at', side_effect=[stat, 'Pid: 1\n', zombie]):
            row = observer.process_sample(-1, identity)
        self.assertEqual(row['state'], 'Z')
        self.assertTrue(row['exit_raced'])
        self.assertNotIn('metrics', row)
        with mock.patch.object(observer.resources, 'read_at', side_effect=[stat, 'Pid: 1\n', stat]):
            with self.assertRaises(ValueError):
                observer.process_sample(-1, identity)

    def test_independent_sqlite_geometry_rejects_extra_table_and_freelist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unit.sqlite'
            connection = sqlite3.connect(path)
            connection.execute(spec.DDL)
            connection.execute('INSERT INTO paired VALUES(?,?,?)', (0, spec.payload(0), 3))
            connection.commit()
            image = path.read_bytes()
            result = oracle.sqlite_geometry(image, [[0, spec.payload(0), 3]])
            self.assertEqual(result['rows'], 1)
            connection.execute('CREATE TABLE other(v)')
            connection.commit()
            with self.assertRaisesRegex(oracle.Rejected, 'fixed-image-schema'):
                oracle.sqlite_geometry(path.read_bytes(), [[0, spec.payload(0), 3]])
            connection.close()
            changed = bytearray(image)
            changed[36:40] = (1).to_bytes(4, 'big')
            with self.assertRaisesRegex(oracle.Rejected, 'image-freelist'):
                oracle.sqlite_geometry(bytes(changed), [[0, spec.payload(0), 3]])

    def test_current_owned_proc_read_and_aggregate_backend_ceiling(self):
        descriptor = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
        try:
            identity = observer.resources.stat_identity(observer.resources.read_at(descriptor, 'stat'))
            value = observer.process_sample(descriptor, identity)
            self.assertEqual(oracle.process_fields(value['status_raw']), value['metrics'])
            observer.accept_processes([{**value, 'role': 'observer'}])
        finally:
            os.close(descriptor)
        example = {'role': 'backend', 'metrics': {'VmRSS': spec.GIB + 1}, 'fd_names': ['1'], 'task_names': ['1']}
        with self.assertRaisesRegex(ValueError, 'backend'):
            observer.accept_processes([example, example])

    def test_filesystem_sealed_prefix_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'one').write_bytes(b'original')
            (root / 'cell').mkdir()
            (root / 'cell' / 'two').write_bytes(b'active')
            whole = observer.tree(root)
            first, second = observer.entry_tree(root / 'one'), observer.entry_tree(root / 'cell')
            self.assertEqual(whole['allocated_bytes'], first['allocated_bytes'] + second['allocated_bytes'])
            self.assertEqual(whole['inodes'], first['inodes'] + second['inodes'])
            (root / 'bad').symlink_to(root / 'one')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                observer.tree(root)

    def test_original_failure_and_primary_ack_gate(self):
        planned = {'load-0': {'phase': 'load', 'operation': 'execute'},
                   'load-control-0': {'phase': 'load', 'operation': 'status'}}
        calls = {'load-0': {'reply': {'ok': False}, 'rejection': {'reason': 'intake_data_requests_tenant'}},
                 'load-control-0': {'reply': {'ok': True}, 'rejection': None}}
        self.assertEqual(oracle.expected_cohort(planned, calls),
                         {'data': 0, 'control': 1, 'recovery': 0, 'catalogue': 0, 'restore': 0})
        calls['load-0']['reply'] = None
        with self.assertRaisesRegex(oracle.Rejected, 'cohort-acquire-unresolved'):
            oracle.expected_cohort(planned, calls)


class ObserverRaceTests(unittest.TestCase):
    def test_enumerated_child_directory_disappearance_is_a_counted_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / 'temporary-lock'
            child.mkdir()
            (root / 'retained').write_bytes(b'original')
            original_scandir = os.scandir
            def disappear(path):
                if Path(path) == child:
                    child.rmdir()
                return original_scandir(path)
            with mock.patch.object(observer.os, 'scandir', side_effect=disappear):
                observed = observer.tree(root)
            self.assertEqual(observed['races'], 1)
            self.assertEqual(observed['files'], 1)
            self.assertEqual(observed['file_bytes'], len(b'original'))
            # The directory already observed remains charged to this sample.
            self.assertEqual(observed['inodes'], 2)

    def test_missing_root_is_never_an_empty_successful_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'owned'
            with self.assertRaises(FileNotFoundError):
                observer.tree(root)
            root.mkdir()
            child = root / 'temporary'
            child.mkdir()
            original_scandir = os.scandir
            def remove_root(path):
                if Path(path) == child:
                    child.rmdir()
                    root.rmdir()
                return original_scandir(path)
            with mock.patch.object(observer.os, 'scandir', side_effect=remove_root):
                with self.assertRaises(FileNotFoundError) as caught:
                    observer.tree(root)
            self.assertEqual(caught.exception.filename, str(root))

    def test_replaced_root_and_other_io_errors_still_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'owned'
            root.mkdir()
            child = root / 'temporary'
            child.mkdir()
            original_scandir = os.scandir
            for failure in (PermissionError(errno.EACCES, 'denied', str(child)),
                            OSError(errno.EIO, 'I/O failure', str(child))):
                def fail_child(path):
                    if Path(path) == child:
                        raise failure
                    return original_scandir(path)
                with self.subTest(error=type(failure).__name__):
                    with mock.patch.object(observer.os, 'scandir', side_effect=fail_child):
                        with self.assertRaises(type(failure)) as caught:
                            observer.tree(root)
                    self.assertIs(caught.exception, failure)
            def replace_root(path):
                if Path(path) == child:
                    root.rename(root.with_name('original-owned'))
                    root.mkdir()
                return original_scandir(path)
            with mock.patch.object(observer.os, 'scandir', side_effect=replace_root):
                with self.assertRaisesRegex(ValueError, 'root was replaced'):
                    observer.tree(root)

    def test_root_disappearance_after_opening_scan_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'owned'
            root.mkdir()
            original_scandir = os.scandir
            def disappear(path):
                entries = original_scandir(path)
                root.rmdir()
                return entries
            with mock.patch.object(observer.os, 'scandir', side_effect=disappear):
                with self.assertRaises(FileNotFoundError):
                    observer.tree(root)

    def test_missing_proc_directory_requires_same_owned_identity_and_zombie(self):
        descriptor = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
        try:
            original_stat = observer.resources.read_at(descriptor, 'stat')
            status = observer.resources.read_at(descriptor, 'status')
            identity = observer.resources.stat_identity(original_stat)
        finally:
            os.close(descriptor)
        offset = original_stat.rfind(')') + 2
        zombie = original_stat[:offset] + 'Z' + original_stat[offset + 1:]
        for final_stat in (original_stat, zombie):
            with self.subTest(zombie=final_stat == zombie):
                with mock.patch.object(observer.resources, 'read_at', side_effect=[original_stat, status, final_stat]):
                    with mock.patch.object(observer.resources, 'names_at',
                                           side_effect=FileNotFoundError(errno.ENOENT, 'missing', 'fd')):
                        if final_stat == zombie:
                            row = observer.process_sample(-1, identity)
                            self.assertTrue(row['exit_raced'])
                            self.assertNotIn('metrics', row)
                        else:
                            with self.assertRaises(FileNotFoundError):
                                observer.process_sample(-1, identity)

    def test_failure_provenance_has_path_context_and_actual_stack(self):
        def owned_scan_failure():
            raise FileNotFoundError(errno.ENOENT, 'missing original', '/owned/temporary')
        try:
            owned_scan_failure()
        except FileNotFoundError as error:
            result = observer.error_evidence(error, {'operation': 'filesystem_aggregate',
                'root': '/owned', 'phase': 'seed_rows', 'sample': 545, 'unrecorded': 'private-value'})
        self.assertEqual(result['error_type'], 'FileNotFoundError')
        self.assertEqual((result['errno'], result['filename']), (errno.ENOENT, '/owned/temporary'))
        self.assertEqual(result['context']['sample'], 545)
        self.assertNotIn('unrecorded', result['context'])
        self.assertIn('owned_scan_failure', result['traceback'])
        self.assertIn('/owned/temporary', result['traceback'])
        self.assertFalse(result['truncated'])

    def test_failure_provenance_is_bounded_after_json_escaping(self):
        large = ('\x00\n\t' + '\U0001f600') * 10000
        def deep_failure(depth):
            if depth:
                return deep_failure(depth - 1)
            raise FileNotFoundError(errno.ENOENT, large, large)
        try:
            deep_failure(20)
        except FileNotFoundError as error:
            result = observer.error_evidence(error, {
                **dict.fromkeys(('operation', 'role', 'root', 'path', 'phase'), large),
                'sample': (1 << 64) - 1, 'pid': (1 << 64) - 1, 'proc_pid': 1 << 1000})
        self.assertLessEqual(len(observer.encoded(result)), 16384)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['traceback_frame_limit_per_exception'], 12)
        self.assertNotIn('proc_pid', result['context'])
        self.assertEqual(result['errno'], errno.ENOENT)

    def test_monitor_failure_stops_and_retains_bounded_provenance(self):
        for recording_error in (None, PermissionError(errno.EACCES, 'cannot record event')):
            with self.subTest(recording_error=recording_error is not None):
                monitor = observer.Monitor.__new__(observer.Monitor)
                monitor.stop = mock.Mock()
                monitor.stop.is_set.return_value = False
                monitor.errors, monitor.count = [], 544
                monitor.sampling_context = {'operation': 'filesystem_aggregate', 'root': '/owned'}
                monitor.phase = lambda: 'seed_rows'
                monitor.sample = mock.Mock(side_effect=FileNotFoundError(errno.ENOENT, 'missing', '/owned'))
                monitor.events = mock.Mock()
                monitor.events.emit.side_effect = recording_error
                monitor.run()
                monitor.sample.assert_called_once()
                self.assertEqual(len(monitor.errors), 1 if recording_error is None else 2)
                failure = monitor.errors[0]
                self.assertEqual(failure['context']['sample'], 545)
                self.assertIn('traceback', failure)
                self.assertLessEqual(len(observer.encoded(failure)), 16384)
                monitor.events.emit.assert_called_once_with('monitor_failed', failure=failure)
                if recording_error is not None:
                    self.assertEqual(monitor.errors[1]['context']['operation'], 'monitor_failure_record')
                with self.assertRaisesRegex(RuntimeError, 'monitor_errors'):
                    monitor.check()


if __name__ == '__main__':
    unittest.main()
