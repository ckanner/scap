"""Independent observer tests, separate from Rust or Node production coverage."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import oracle
import spec


class Contract(unittest.TestCase):
    def reject(self, rule, function):
        with self.assertRaises(oracle.Rejected) as raised:
            function()
        self.assertEqual(raised.exception.rule, rule)

    def publication(self, count=3):
        previous = {'revision': 5, 'sequence': 3, 'head_serial': 5,
                    'data_root': 'old', 'transition': {'revision': 5, 'nonce': 3},
                    'windows': ['old'], 'active': True, 'owner_instance': 77}
        entries, stored = {}, {}
        for offset in range(1, count + 1):
            identifier = offset + 9
            entries[identifier] = {'outcome': {'state': 'committed'}}
            stored[identifier] = {'metadata': {'sequence': 3 + offset,
                'transition': {'revision': 5 + offset, 'nonce': identifier},
                'request': {'id': identifier}, 'data_root': 'root-' + str(offset)}}
        after = {'entries': entries, 'stored': stored}
        before = {'entries': {}, 'stored': {}}
        last = stored[9 + count]['metadata']
        current = dict(previous, revision=5 + count, sequence=3 + count, head_serial=5 + count,
                       data_root=last['data_root'], transition=last['transition'], windows=['new'])
        return previous, current, before, after

    def test_fixed_workload_has_two_rates_and_identical_round_inputs(self):
        calls = spec.calls()
        self.assertEqual(spec.ROUNDS, (('off-1', False), ('on-1', True), ('on-2', True), ('off-2', False)))
        for phase, settings in spec.PHASES.items():
            writes = [item for item in calls if item['phase'] == phase and item['operation'] == 'execute']
            self.assertEqual(len(writes), settings['count'])
            self.assertEqual([item['offset_ns'] for item in writes],
                             [n * 1000000000 // settings['rate'] for n in range(settings['count'])])
            self.assertTrue(all(len(item['statements']) == 1 for item in writes))
        writes = [item for item in calls if 'row' in item]
        self.assertEqual(len({item['request_id'] for item in writes}), 160)
        self.assertEqual(len({item['row'] for item in writes}), 160)
        self.assertEqual(sum(len(spec.payload(item['row'])) for item in writes), 40960)

    def test_configuration_only_changes_the_group_profile(self):
        off = spec.configuration('127.0.0.1:1', '/cache', 'http://127.0.0.1:2', 'digest', False)
        on = spec.configuration('127.0.0.1:1', '/cache', 'http://127.0.0.1:2', 'digest', True)
        self.assertIsNone(off['admission'].pop('group_commit'))
        self.assertEqual(on['admission'].pop('group_commit'), spec.PROFILE)
        self.assertEqual(off, on)

    def test_group_requires_the_actual_number_of_independent_records(self):
        args = self.publication()
        self.assertEqual(oracle.publication(*args, True), 3)
        changed = copy.deepcopy(args)
        changed[3]['entries'].pop(10)
        self.reject('group-fresh-identities', lambda: oracle.publication(*changed, True))

    def test_off_profile_cannot_claim_a_group(self):
        self.reject('group-width', lambda: oracle.publication(*self.publication(2), False))
        self.assertEqual(oracle.publication(*self.publication(1), False), 1)

    def test_group_cannot_launder_old_entries_or_a_cancelled_member(self):
        args = self.publication()
        args[2]['entries'][1] = {'outcome': {'state': 'cancelled'}}
        self.reject('retained-unchanged', lambda: oracle.publication(*args, True))
        args = self.publication()
        args[3]['entries'][10]['outcome']['state'] = 'cancelled'
        self.reject('group-fresh-identities', lambda: oracle.publication(*args, True))

    def test_group_checks_member_sequence_and_final_root(self):
        args = self.publication()
        args[3]['stored'][10]['metadata']['sequence'] += 1
        self.reject('group-member-sequence', lambda: oracle.publication(*args, True))
        args = self.publication()
        args[1]['data_root'] = 'unrelated'
        self.reject('protected-head-fields', lambda: oracle.publication(*args, True))

    def test_group_cannot_change_owner_or_widen_to_nine(self):
        args = self.publication()
        args[1]['owner_instance'] += 1
        self.reject('protected-head-fields', lambda: oracle.publication(*args, True))
        self.reject('group-width', lambda: oracle.publication(*self.publication(9), True))

    def test_ordinary_activation_keeps_single_step_and_authority(self):
        previous = {'revision': 1, 'sequence': 0, 'head_serial': 1, 'active': False,
                    'transition': {'revision': 1, 'nonce': 1}}
        current = dict(previous, revision=2, head_serial=2, active=True, transition={'revision': 2, 'nonce': 2})
        empty = {'entries': {}, 'stored': {}}
        self.assertEqual(oracle.publication(previous, current, empty, empty, True), 0)
        current['head_serial'] = 3
        self.reject('protected-head-fields', lambda: oracle.publication(previous, current, empty, empty, True))

    def test_nearest_rank_does_not_invent_empty_tail_or_smoothed_p99(self):
        self.assertEqual(oracle.percentiles([]), {'samples': 0, 'p50': None, 'p95': None, 'p99': None, 'maximum': None})
        self.assertEqual(oracle.percentiles([1, 2, 100])['p99'], 100)
        self.assertEqual(oracle.percentiles(list(range(1, 129)))['p99'], 127)
        for values in ([-1], [float('nan')], [float('inf')]):
            self.reject('latency-values', lambda: oracle.percentiles(values))

    def test_original_raw_bytes_are_hashed_and_path_confined(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'raw').mkdir()
            data = b'original result'
            digest = hashlib.sha256(data).hexdigest()
            value = {'file': 'raw/' + digest, 'sha256': digest, 'bytes': len(data)}
            (directory / value['file']).write_bytes(data)
            self.assertEqual(oracle.raw(directory, value), data)
            self.reject('raw-path', lambda: oracle.raw(directory, dict(value, file='../escape')))
            (directory / value['file']).write_bytes(b'changed result!')
            self.reject('raw-integrity', lambda: oracle.raw(directory, value))

    def test_trace_requires_complete_records_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'trace.jsonl'
            path.write_text('{"event":"complete"}\n')
            self.assertEqual(oracle.rows(path), [{'event': 'complete'}])
            path.write_text('{"event":"truncated"}')
            self.reject('ledger-framing', lambda: oracle.rows(path))

    def test_outcomes_keep_unknown_rejections_and_local_failures_separate(self):
        def outcome(ok=False, **error):
            return oracle.observed_outcome({'finish': {'ok': ok, 'error': error}})
        self.assertEqual(outcome(True), 'success')
        self.assertEqual(outcome(outcome='committed'), 'committed_unavailable')
        self.assertEqual(outcome(code='DEADLINE'), 'unknown')
        self.assertEqual(outcome(name='RemoteError', code='QUEUE_FULL'), 'rejected')
        self.assertEqual(outcome(name='TypeError'), 'transport_error')

    def test_raw_success_cannot_be_relabelled_as_a_transport_failure(self):
        start = {'monotonic_ns': '1'}
        terminal = {'monotonic_ns': '3', 'status': 200, 'event': 'http_response'}
        finish = {'monotonic_ns': '4', 'ok': False, 'state': None,
                  'sdk_terminal_ns': '4',
                  'error': {'name': 'TypeError', 'code': None, 'outcome': None}}
        self.reject('sdk-http-outcome', lambda: oracle.validate_terminal(
            start, finish, terminal, {'ok': True, 'value': {'state': 'committed'}}))

    def test_error_latency_cannot_end_before_original_http_terminal(self):
        start = {'monotonic_ns': '1'}
        terminal = {'monotonic_ns': '5', 'status': 429, 'event': 'http_response'}
        finish = {'monotonic_ns': '4', 'ok': False, 'state': None,
                  'error': {'name': 'RemoteError', 'code': 'BACKPRESSURE', 'outcome': 'unresolved'}}
        self.reject('http-terminal-before-finish', lambda: oracle.validate_terminal(
            start, finish, terminal, {'ok': False, 'error': {'code': 'BACKPRESSURE'}}))

    def test_actual_sdk_outcomes_are_bound_to_raw_http(self):
        start = {'monotonic_ns': '1'}
        response = {'monotonic_ns': '3', 'status': 200, 'event': 'http_response'}
        finish = {'monotonic_ns': '5', 'sdk_terminal_ns': '4', 'ok': True,
                  'state': 'committed', 'error': None}
        oracle.validate_terminal(start, finish, response, {'ok': True, 'value': {'state': 'committed'}})
        finish.update(ok=False, state=None, error={'name': 'RemoteError', 'code': 'BACKPRESSURE', 'outcome': 'unresolved'})
        oracle.validate_terminal(start, finish, dict(response, status=429),
                                 {'ok': False, 'error': {'code': 'BACKPRESSURE'}})
        finish['error']['name'] = 'TypeError'
        self.reject('sdk-http-outcome', lambda: oracle.validate_terminal(start, finish, dict(response, status=429),
                                 {'ok': False, 'error': {'code': 'BACKPRESSURE'}}))

    def test_committed_decode_deadline_needs_original_time_and_receipt(self):
        start = {'monotonic_ns': '1'}
        response = {'monotonic_ns': '3', 'status': 200, 'event': 'http_response'}
        finish = {'monotonic_ns': '65000000005', 'sdk_terminal_ns': '65000000004', 'ok': False,
                  'state': None, 'error': {'name': 'CommittedResultError', 'code': 'DEADLINE',
                  'outcome': 'committed', 'receipt': {'identity': 7}, 'raw_result': {}}}
        reply = {'ok': True, 'value': {'state': 'committed', 'receipt': {'identity': 7}}}
        oracle.validate_terminal(start, finish, response, reply)
        finish['sdk_terminal_ns'] = '4'
        self.reject('sdk-committed-deadline', lambda: oracle.validate_terminal(start, finish, response, reply))
        finish['sdk_terminal_ns'] = '65000000004'
        finish['error']['receipt']['identity'] = 8
        self.reject('sdk-committed-receipt', lambda: oracle.validate_terminal(start, finish, response, reply))

    def test_offer_window_is_included_even_when_last_write_finishes_early(self):
        self.assertEqual(oracle.measured_elapsed(100, 8100, [500, 7900]), 8000)
        self.assertEqual(oracle.measured_elapsed(100, 8100, [500, 9100]), 9000)

    def test_original_deadline_can_win_before_the_raw_response_drains(self):
        start = {'monotonic_ns': 1}
        terminal = {'monotonic_ns': 65000000006, 'status': 200, 'event': 'http_response'}
        finish = {'monotonic_ns': 65000000008, 'sdk_terminal_ns': 65000000004,
                  'ok': False, 'state': None, 'error': {'name': 'UnknownError', 'code': 'UNKNOWN',
                  'outcome': 'unknown', 'cause_code': 'DEADLINE'}}
        for reply in ({'ok': True, 'value': {'state': 'committed'}},
                      {'ok': False, 'error': {'code': 'BACKPRESSURE'}}):
            oracle.validate_terminal(start, finish, terminal, reply)
        finish['error']['cause_code'] = None
        self.reject('sdk-response-before-terminal', lambda: oracle.validate_terminal(
            start, finish, terminal, {'ok': True, 'value': {'state': 'committed'}}))
        finish['error']['cause_code'] = 'DEADLINE'
        finish['sdk_terminal_ns'] = 4
        self.reject('sdk-transport-deadline', lambda: oracle.validate_terminal(
            start, finish, terminal, {'ok': True, 'value': {'state': 'committed'}}))

    def test_read_or_noncommitted_decode_can_exceed_the_original_deadline(self):
        start = {'monotonic_ns': 1}
        terminal = {'monotonic_ns': 3, 'status': 200, 'event': 'http_response'}
        finish = {'monotonic_ns': 65000000008, 'sdk_terminal_ns': 65000000004,
                  'ok': False, 'state': None, 'error': {'name': 'ClientError', 'code': 'DEADLINE',
                  'outcome': None, 'cause_code': 'DEADLINE'}}
        for operation in ('status', 'query'):
            oracle.validate_terminal(start, finish, terminal, {'ok': True, 'value': {}}, operation)
        finish['error'].update(name='UnknownError', code='UNKNOWN', outcome='unknown')
        oracle.validate_terminal(start, finish, terminal, {'ok': True, 'value': {'state': 'cancelled'}}, 'cancel')
        self.reject('sdk-http-outcome', lambda: oracle.validate_terminal(
            start, finish, terminal, {'ok': True, 'value': {}}, 'status'))

    def test_actual_round_order_cannot_be_replaced_by_the_reported_abba_list(self):
        boundaries = [(1, 2), (3, 4), (5, 6), (7, 8)]
        oracle.validate_round_order(boundaries)
        boundaries[0], boundaries[3] = boundaries[3], boundaries[0]
        self.reject('round-run-order', lambda: oracle.validate_round_order(boundaries))

    def test_active_count_allows_finished_promise_tail_but_not_fabricated_capacity(self):
        calls = [{'start': {'monotonic_ns': 1}, 'finish': {'monotonic_ns': 3}},
                 {'start': {'monotonic_ns': 2}, 'finish': {'monotonic_ns': 9}},
                 {'start': {'monotonic_ns': 7}, 'finish': {'monotonic_ns': 10}}]
        oracle.active_bounds({'monotonic_ns': 5, 'active': 1}, calls)
        oracle.active_bounds({'monotonic_ns': 5, 'active': 2}, calls)
        for count in (0, 3, 192):
            self.reject('generator-active-count', lambda: oracle.active_bounds({'monotonic_ns': 5, 'active': count}, calls))

    def test_a_never_dispatched_identity_cannot_appear_committed(self):
        item = next(item for item in spec.calls() if item['id'] == 'low-0')
        calls = {'lookup-low-0': {'finish': {'ok': True},
                 'body': {'version': 1, 'scope': spec.SCOPE, 'operation': 'lookup', 'request': oracle.intent(item)},
                 'reply': {'value': {'state': 'committed'}}}}
        self.reject('never-dispatched-commit', lambda: oracle.settlement({'low-0': item}, calls))

    def test_phase_intervals_require_the_frozen_nonoverlapping_order(self):
        events = [{'event': 'service_start_requested', 'monotonic_ns': 1},
                  {'event': 'service_started', 'monotonic_ns': 2}]
        for index, phase in enumerate(('seed', *spec.PHASES, 'verify')):
            events.extend([{'event': 'phase_started', 'phase': phase, 'monotonic_ns': 10 + index * 10},
                           {'event': 'phase_finished', 'phase': phase, 'monotonic_ns': 19 + index * 10}])
        self.assertEqual(oracle.phase_intervals(events)['low'], (20, 29))
        events[-1]['monotonic_ns'] = 3
        self.reject('runner-phase-clock', lambda: oracle.phase_intervals(events))


if __name__ == '__main__':
    unittest.main()
