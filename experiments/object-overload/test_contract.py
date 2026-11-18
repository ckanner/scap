"""Observer counterexamples only; these synthetic fixtures are not actual runs."""
from __future__ import annotations

from collections import Counter
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

import controls
import oracle as o
import resource_audit
import shared
import spec
import wire_audit


def arrivals_fixture():
    origin = 1_000_000_000
    calls, history = {}, [{'event': 'phase_started', 'phase': 'overload',
                            'origin_ns': str(origin), 'monotonic_ns': str(origin + 1)}]
    for item in spec.calls():
        if item['phase'] != 'overload':
            continue
        scheduled = origin + item['offset_ns']
        rejected = item['lane'] == 'hot' and int(item['id'].rsplit('-', 1)[1]) % 16 == 15
        begin = {'scheduled_ns': str(scheduled), 'monotonic_ns': str(scheduled + 2_000_000)}
        finish = {'ok': not rejected, 'monotonic_ns': str(scheduled + 20_000_000),
                  'state': 'committed' if item['lane'] == 'hot' and not rejected else None,
                  'error': {'code': 'BACKPRESSURE', 'name': 'RemoteError'} if rejected else None}
        calls[item['id']] = {'item': item, 'begin': begin, 'finish': finish,
                             'category': 'rejected' if rejected else 'success'}
        history.append({'event': 'call_offered', 'id': item['id'], 'monotonic_ns': str(scheduled + 1_000_000),
                        'scheduled_ns': str(scheduled), 'active': 1})
    history.append({'event': 'arrivals_finished', 'monotonic_ns': str(origin + spec.DURATION_MS * 1_000_000),
                    'planned': len(calls)})
    return calls, history


def closure_fixture():
    scope = {key: int(value) for key, value in spec.SCOPES['single'].items()}
    prefix = '/scap-test/scap-object/v1/1/7/1101/inc/1/gen/1/storage/1/objects/'
    head = '/scap-test/scap-object/v1/1/7/1101/head'
    accepted, requests, responses = [], {}, {}

    def save(kind, value, data=b''):
        meta = json.dumps({'format': 2, 'scope': scope, 'payload': {'kind': kind, 'value': value}},
                          separators=(',', ':')).encode()
        body = b'SCAPOBJ2' + struct.pack('<IQ', len(meta), len(data)) + meta + data
        path = prefix + o.digest(body)
        tick = 100 + len(accepted) * 100
        put, response = {'path': path, 'monotonic_ns': tick}, {'monotonic_ns': tick + 10}
        accepted.append((put, response, body))
        serial = len(requests) + 1
        requests[serial] = {'method': 'GET', 'path': path}
        responses[serial] = {'path': path, 'status': 200, 'response_sha256': o.digest(body), 'monotonic_ns': tick + 30}
        return o.digest(body)

    chunk = save('chunk', {'first_page': 1, 'bytes': []}, b'\x00' * 4096)
    node = save('node', {'level': 0, 'children': [chunk]})
    manifest = save('manifest', {'page_count': 1, 'root': node})
    index = save('index', {'kind': 'leaf', 'epoch': 1, 'entries': []})
    accepted.append(({'path': head, 'monotonic_ns': 1000}, {'monotonic_ns': 1010},
                     json.dumps({'windows': [{'root': index}], 'data_root': manifest}).encode()))
    return accepted, requests, responses, {'single': head}, {'single': prefix}


class PlanTests(unittest.TestCase):
    def test_complete_denominator_and_original_identities(self):
        calls = spec.calls()
        self.assertEqual(len(calls), 4340)
        self.assertEqual(len({item['id'] for item in calls}), len(calls))
        self.assertEqual(Counter(item['phase'] for item in calls), {
            'seed': 12, 'single': 64, 'batch': 8, 'overload': 1140, 'verify': 3112, 'recovered': 4})
        originals = {item['id']: item for item in calls if item['operation'] == 'execute'}
        self.assertEqual(len(originals), 1036)
        self.assertEqual(len({(item['scope'], item['request_id']) for item in originals.values()}), 1036)
        for identifier in originals:
            self.assertEqual([item['operation'] for item in calls if item.get('original') == identifier],
                             ['lookup', 'cancel', 'lookup'])

    def test_batch_means_eight_transactions_and_same_sixty_four_logical_inputs(self):
        calls = spec.calls()
        single = [spec.statements(item) for item in calls if item['phase'] == 'single']
        batch = [spec.statements(item) for item in calls if item['phase'] == 'batch']
        self.assertEqual([statement for group in single for statement in group],
                         [statement for group in batch for statement in group])
        self.assertEqual((len(single), len(batch)), (64, 8))
        self.assertTrue(all(len(group) == 8 for group in batch))

    def test_original_open_loop_offsets_and_lane_counts(self):
        offered = [item for item in spec.calls() if item['phase'] == 'overload']
        self.assertEqual(Counter(item['lane'] for item in offered), {'hot': 960, 'quiet': 120, 'control': 60})
        self.assertEqual([item['offset_ns'] for item in offered], sorted(item['offset_ns'] for item in offered))
        self.assertLess(max(item['offset_ns'] for item in offered), 30_000_000_000)

    def test_payloads_are_equal_when_reused_but_distinct_across_rows(self):
        values = [spec.payload(number) for number in range(960)]
        self.assertEqual(len(set(values)), 960)
        self.assertTrue(all(len(value) == 256 for value in values))
        self.assertEqual(values[0], spec.payload(0))

    def test_observer_import_restores_original_spec_binding_even_on_error(self):
        before = sys.modules['spec']
        with self.assertRaises(RuntimeError):
            with shared.original_spec():
                self.assertIsNot(sys.modules['spec'], before)
                self.assertEqual(sys.modules['spec'].BOUNDS, spec.BOUNDS)
                raise RuntimeError('exercise restoration')
        self.assertIs(sys.modules['spec'], before)


class ArrivalTests(unittest.TestCase):
    def rejected(self, rule, change):
        calls, history = arrivals_fixture()
        change(calls, history)
        with self.assertRaises(o.Rejected) as raised:
            o.arrivals(calls, history)
        self.assertEqual(raised.exception.rule, rule)

    def test_complete_schedule_has_six_windows_and_all_lanes(self):
        calls, history = arrivals_fixture()
        result = o.arrivals(calls, history)
        self.assertEqual(result['offered'], 1140)
        self.assertEqual(len(result['progress_windows']), 6)
        self.assertEqual(result['scheduled_per_second'], 38)

    def test_missing_offer_cannot_disappear_from_denominator(self):
        self.rejected('offered-denominator', lambda _calls, history: history.pop(10))

    def test_arrival_time_cannot_move_after_a_slow_response(self):
        self.rejected('fixed-arrival-schedule', lambda _calls, history: history[2].update(scheduled_ns='1'))

    def test_generation_delay_is_bounded_against_original_time(self):
        self.rejected('offered-rate-not-reached', lambda calls, _history:
                      calls['overload-hot-0']['begin'].update(monotonic_ns=str(2_000_000_001)))

    def test_no_backpressure_does_not_claim_overload_was_tested(self):
        def change(calls, _history):
            for call in calls.values():
                call['finish'].update(ok=True, error=None)
        self.rejected('overload-not-observed', change)

    def test_late_success_cannot_fill_an_empty_progress_window(self):
        def change(calls, _history):
            for call in calls.values():
                if call['item']['lane'] == 'quiet' and call['item']['offset_ns'] < 5_000_000_000:
                    call['finish']['monotonic_ns'] = '7000000000'
        self.rejected('tenant-window-progress', change)

    def test_valid_cancellation_is_not_a_successfully_committed_transaction(self):
        def change(calls, _history):
            for call in calls.values():
                if call['item']['lane'] == 'hot':
                    call['finish']['state'] = 'cancelled'
        self.rejected('tenant-window-progress', change)

    def test_counter_cannot_claim_extra_generator_capacity(self):
        self.rejected('client-inflight-bound', lambda _calls, history: history[1].update(active=64))

    def test_original_window_must_actually_finish(self):
        self.rejected('original-arrival-window', lambda _calls, history: history[-1].update(monotonic_ns='2'))


class ByteAndClockTests(unittest.TestCase):
    def test_raw_digest_and_length_are_both_checked(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name); (directory / 'raw').mkdir()
            (directory / 'raw-budget').write_text('0\n')
            value = controls.store(directory, b'original bytes')
            self.assertEqual(o.raw(directory, value), b'original bytes')
            path = directory / value['file']
            path.write_bytes(b'altered! bytes')
            with self.assertRaises(o.Rejected) as raised:
                o.raw(directory, value)
            self.assertEqual(raised.exception.rule, 'raw-integrity')

    def test_path_escape_rejected_without_reading_it(self):
        with self.assertRaises(o.Rejected) as raised:
            o.raw(Path('/'), {'file': '../../secret', 'bytes': 0, 'sha256': '0' * 64})
        self.assertEqual(raised.exception.rule, 'raw-path')

    def test_empty_or_nonfinite_percentiles_do_not_fill_zero(self):
        for values in ([], [float('nan')], [float('inf')], [-1]):
            with self.assertRaises(o.Rejected):
                o.percentiles(values)
        self.assertEqual(o.percentiles([1, 2, 3, 4])['p95'], 4)

    def test_concurrency_uses_complete_intervals(self):
        self.assertEqual(o.concurrent([(1, 3), (2, 4), (4, 6)]), 2)
        with self.assertRaises(o.Rejected):
            o.concurrent([(3, 1)])

    def test_clock_rejects_boolean_zero_and_nondecimal(self):
        for value in (True, 0, '-1', 'x'):
            with self.assertRaises(o.Rejected):
                o.moment({'monotonic_ns': value})
        self.assertEqual(o.moment({'monotonic_ns': '12'}), 12)

    def test_archive_rejects_link_or_missing_member(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'source.tar'
            with tarfile.open(path, 'w') as archive:
                info = tarfile.TarInfo('source.py'); info.size = 4
                archive.addfile(info, io.BytesIO(b'code'))
            o.archive_inputs(path, {'source.py': o.digest(b'code')}, 'source')
            with self.assertRaises(o.Rejected):
                o.archive_inputs(path, {'missing.py': o.digest(b'code')}, 'source')
            with tarfile.open(path, 'w') as archive:
                info = tarfile.TarInfo('source.py'); info.type = tarfile.SYMTYPE; info.linkname = '/tmp/escape'
                archive.addfile(info)
            with self.assertRaises(o.Rejected):
                o.archive_inputs(path, {'source.py': o.digest(b'code')}, 'source')

    def test_hardlinked_counterexample_never_changes_source(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            original, changed = root / 'original', root / 'changed'
            original.write_bytes(b'original')
            os.link(original, changed)
            controls.replace(changed, b'counterexample')
            self.assertEqual(original.read_bytes(), b'original')
            self.assertEqual(changed.read_bytes(), b'counterexample')
            self.assertNotEqual(original.stat().st_ino, changed.stat().st_ino)


class ClosureTests(unittest.TestCase):
    def test_complete_data_and_request_closures_precede_head(self):
        result = wire_audit.closures(*closure_fixture())
        self.assertEqual(result['head_publications'], 1)
        self.assertEqual(result['distinct_dependencies'], 4)

    def test_missing_child_is_not_treated_as_empty_data(self):
        args = list(closure_fixture()); args[0].pop(0)
        with self.assertRaises(o.Rejected) as raised:
            wire_audit.closures(*args)
        self.assertEqual(raised.exception.rule, 'publication-closure')

    def test_dependency_without_complete_readback_cannot_publish(self):
        args = list(closure_fixture()); args[2].pop(1)
        with self.assertRaises(o.Rejected) as raised:
            wire_audit.closures(*args)
        self.assertEqual(raised.exception.rule, 'dependency-readback')

    def test_readback_after_head_is_not_accepted(self):
        args = list(closure_fixture()); args[2][1]['monotonic_ns'] = 2000
        with self.assertRaises(o.Rejected) as raised:
            wire_audit.closures(*args)
        self.assertEqual(raised.exception.rule, 'closure-before-head')

    def test_truncated_or_changed_immutable_frame_rejected(self):
        args = closure_fixture()
        request, _, data = args[0][0]
        scope = {k: int(v) for k, v in spec.SCOPES['single'].items()}
        for altered in (data[:-1], data[:19], b'badmagic' + data[8:]):
            with self.assertRaises(o.Rejected):
                wire_audit.frame(altered, request['path'], scope)


class MutationTests(unittest.TestCase):
    def test_fabricated_success_skips_none_errors_and_preserves_original_source(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            rows = [{'event': 'call_finished', 'id': 'ok', 'error': None, 'ok': True},
                    {'event': 'call_finished', 'id': 'bad', 'error': {'code': 'BACKPRESSURE'}, 'ok': False}]
            path = directory / 'sdk.jsonl'
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            controls.mutate(directory, 'fabricated_success')
            changed = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(changed[0], rows[0])
            self.assertEqual(changed[1]['error'], None)
            self.assertTrue(changed[1]['ok'])

    def test_counterexample_catalogue_is_complete(self):
        self.assertEqual(len(controls.CASES), 18)
        self.assertIn('closure-before-head', controls.CASES.values())
        self.assertIn('tenant-window-progress', controls.CASES.values())

    def test_proc_identity_uses_original_start_ticks(self):
        raw = '77 (thread with spaces) S ' + ' '.join(['0'] * 18 + ['12345'])
        self.assertEqual(resource_audit.process_stat(raw), (77, 12345))
        for invalid in ('', '77 no parentheses', '77 (x) S 0'):
            with self.assertRaises(o.Rejected):
                resource_audit.process_stat(invalid)


if __name__ == '__main__':
    unittest.main()
